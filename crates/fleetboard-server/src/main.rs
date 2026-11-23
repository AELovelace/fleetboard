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
    /// Service tokens for the /api/v1 API (Mnemerynne): add, list, revoke
    #[command(subcommand)]
    Token(TokenCommand),
    /// The newest /api/v1 calls: when, which token, what, the status and how long it took
    Calls {
        /// How many to show
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
}

#[derive(Subcommand, Debug)]
enum TokenCommand {
    /// Make a token and print it once (only its hash is kept)
    Add {
        /// Who holds it, e.g. mnemerynne-read
        name: String,
        /// read (the default: reads only) or act (reads and the audited actions)
        #[arg(long, default_value = "read")]
        scope: String,
    },
    /// Every token: name, scope, first characters, made, last used, revoked
    List,
    /// Revoke a token by name; it is refused from its next request on
    Revoke { name: String },
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
                "{} is fine: bind {}, db {}, token {}, {}",
                path.display(),
                cfg.bind,
                cfg.db.display(),
                if cfg.token_set() { "set" } else { "NOT SET" },
                cfg.wazuh.summary()
            );
            Ok(())
        }
        Command::Token(cmd) => {
            let cfg = ServerConfig::load(&path)?;
            let db = Db::open(&cfg.db)?; // the same database the running server uses (WAL: safe side by side)
            token_command(&db, cmd)
        }
        Command::Calls { limit } => {
            let cfg = ServerConfig::load(&path)?;
            let db = Db::open(&cfg.db)?;
            for c in db.recent_calls((*limit).clamp(1, 1000))? {
                println!(
                    "{}  {:<20} {:>3} {:>5} ms  {} {}",
                    fleetboard_server::time::iso(c.ts),
                    c.token,
                    c.status,
                    c.ms,
                    c.method,
                    c.path
                );
            }
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

/// `token add | list | revoke` against the server's database.
fn token_command(db: &Db, cmd: &TokenCommand) -> anyhow::Result<()> {
    use fleetboard_server::time::iso;
    use fleetboard_server::tokens;
    let now = fleetboard_server::now_unix();
    match cmd {
        TokenCommand::Add { name, scope } => {
            let (token, row) = tokens::create(db, name, scope, now).map_err(anyhow::Error::msg)?;
            println!("{token}");
            eprintln!(
                "Token {:?} ({}) made. It is shown only now: paste it into Mnemerynne as the API's credential (Bearer).",
                row.name, row.scopes
            );
        }
        TokenCommand::List => {
            for t in db.list_tokens()? {
                println!(
                    "{:<24} {:<9} {}…  made {}  last used {}  {}",
                    t.name,
                    t.scopes,
                    t.prefix,
                    iso(t.created_at),
                    t.last_used_at.map(iso).unwrap_or_else(|| "never".into()),
                    t.revoked_at
                        .map(|r| format!("REVOKED {}", iso(r)))
                        .unwrap_or_default()
                );
            }
        }
        TokenCommand::Revoke { name } => {
            if db.revoke_token(name, now)? {
                db.audit(now, "local", "token.revoke", name, "")?;
                println!("Revoked {name}; it is refused from its next request on.");
            } else {
                anyhow::bail!("no live token called {name:?} (`token list` shows them)");
            }
        }
    }
    Ok(())
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
    if cfg.wazuh.enabled {
        tracing::info!("{}", cfg.wazuh.summary());
    }
    let poller = Poller::with_wazuh(
        db.clone(),
        cfg.token.trim().to_string(),
        hosts,
        cfg.wazuh.clone(),
    );
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
        match tokio::task::spawn_blocking(move || {
            let now = fleetboard_server::now_unix();
            if let Err(e) = db.prune_long(now) {
                tracing::warn!("pruning rollups and API calls failed: {e}"); // hourly 7 d, daily 90 d, calls 90 d
            }
            db.prune(now)
        })
        .await
        {
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
