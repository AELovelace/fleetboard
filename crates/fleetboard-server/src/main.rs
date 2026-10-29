//! The `fleetboard-server` binary: load the config, open SQLite, start the poller and the hourly
//! pruner, serve the dashboard until Ctrl-C or SIGTERM, then flush the open windows.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use fleetboard_server::api::{router, AppState};
use fleetboard_server::config::ServerConfig;
use fleetboard_server::db::Db;
use fleetboard_server::poller::Poller;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "fleetboard-server",
    version,
    about = "Fleetboard: polls the clients, keeps 24 h of history and serves the dashboard"
)]
struct Cli {
    /// Path of server.toml (default: /etc/fleetboard/server.toml, or %ProgramData%\Fleetboard\server.toml on Windows)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Poll and serve until stopped (the default)
    Run,
    /// Print a fresh shared token to put in the server's config and every client.toml
    GenToken,
    /// Read the config and report what's wrong with it, if anything
    CheckConfig,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let path = cli
        .config
        .clone()
        .unwrap_or_else(ServerConfig::default_path);
    match cli.command.as_ref().unwrap_or(&Command::Run) {
        Command::GenToken => {
            println!("{}", gen_token());
            Ok(())
        }
        Command::CheckConfig => {
            let cfg = ServerConfig::load(&path)?;
            println!(
                "{} is fine: bind {}, db {}, token {}",
                path.display(),
                cfg.bind,
                cfg.db.display(),
                if cfg.token_set() { "set" } else { "NOT SET" }
            );
            Ok(())
        }
        Command::Run => {
            let cfg = ServerConfig::load(&path)?;
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log));
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();
            if !cfg.token_set() {
                tracing::warn!("no shared token configured (FLEETBOARD_TOKEN or `token` in {}); every poll will be rejected", path.display());
            }
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(serve(cfg))
        }
    }
}

/// 32 unambiguous characters, the same alphabet the client uses.
fn gen_token() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

async fn serve(cfg: ServerConfig) -> anyhow::Result<()> {
    let addr = cfg.bind_addr()?;
    let db = Db::open(&cfg.db)?;
    let hosts = db.list_hosts()?;
    tracing::info!(
        "database {} ready, {} host(s)",
        cfg.db.display(),
        hosts.len()
    );
    let poller = Poller::new(db.clone(), cfg.token.trim().to_string(), hosts);
    let poll_task = tokio::spawn(poller.clone().run());
    let prune_task = tokio::spawn(prune_hourly(db.clone()));

    let state = AppState {
        db: db.clone(),
        poller: poller.clone(),
        token_set: cfg.token_set(),
    };
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("can't listen on {addr}"))?;
    tracing::info!(
        "fleetboard-server {} listening on http://{addr}/",
        fleetboard_server::VERSION
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    poll_task.abort();
    prune_task.abort();
    poller.flush(); // the open 10 s windows go to disk
    tracing::info!("stopped");
    Ok(())
}

/// Once an hour: drop rows older than 24 h and shrink the WAL.
async fn prune_hourly(db: Db) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        let db = db.clone();
        match tokio::task::spawn_blocking(move || db.prune(fleetboard_server::now_unix())).await {
            Ok(Ok(n)) if n > 0 => tracing::info!("pruned {n} old sample row(s)"),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!("prune failed: {e}"),
            Err(e) => tracing::warn!("prune task failed: {e}"),
        }
    }
}

/// Ctrl-C everywhere, plus SIGTERM on Unix.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("stop requested");
}
