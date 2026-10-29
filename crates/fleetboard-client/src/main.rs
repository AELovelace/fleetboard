//! The `fleetboard-client` binary: parse the command line, load the config, start the sampler
//! thread and the HTTP server, and stop both cleanly on Ctrl-C or SIGTERM.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use fleetboard_client::cli::{Cli, Command};
use fleetboard_client::config::{generate_token, ClientConfig};
use fleetboard_client::http::{router, AppState};
use fleetboard_client::{gpu, sampler};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command.as_ref().unwrap_or(&Command::Run) {
        Command::GenToken => {
            println!("{}", generate_token()); // no config needed for this one
            Ok(())
        }
        Command::CheckConfig => {
            let path = cli.config_path();
            let cfg = ClientConfig::load(&path)?;
            println!(
                "{} is fine: bind {}, name {}, gpu {}",
                path.display(),
                cfg.bind,
                cfg.display_name().unwrap_or_else(|| "(hostname)".into()),
                cfg.gpu
            );
            Ok(())
        }
        Command::Once => {
            let cfg = load_or_default(&cli)?;
            init_logging(&cfg.log);
            let mut s = sampler::Sampler::new(&cfg, gpu::detect(cfg.gpu));
            let _ = s.tick(); // prime the deltas
            std::thread::sleep(Duration::from_secs(1));
            println!("{}", serde_json::to_string_pretty(&s.tick())?);
            Ok(())
        }
        Command::Run => {
            let cfg = ClientConfig::load(&cli.config_path())?;
            init_logging(&cfg.log);
            serve(cfg)
        }
    }
}

/// `once` is allowed to run without a config (a brand-new box has none yet).
fn load_or_default(cli: &Cli) -> anyhow::Result<ClientConfig> {
    let path = cli.config_path();
    if path.exists() {
        ClientConfig::load(&path)
    } else {
        Ok(ClientConfig {
            token: "x".repeat(16),
            ..Default::default()
        }) // placeholder token: never served
    }
}

/// Logs to stderr (the journal under systemd); the level comes from the config, RUST_LOG wins.
fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// Start the sampler thread, then serve until a stop signal arrives.
fn serve(cfg: ClientConfig) -> anyhow::Result<()> {
    let addr = cfg.bind_addr()?;
    let latest: sampler::Latest = Arc::new(RwLock::new(None));
    let stop = Arc::new(AtomicBool::new(false));
    let collectors = gpu::detect(cfg.gpu);
    let state = AppState {
        latest: latest.clone(),
        token: cfg.token.trim().into(),
        allowed_hosts: Arc::new(cfg.allowed_hosts.clone()),
        hostname: sysinfo::System::host_name().unwrap_or_else(|| "unknown".into()),
    };
    let sampler = sampler::Sampler::new(&cfg, collectors);
    let sampler_thread = {
        let (latest, stop) = (latest.clone(), stop.clone());
        std::thread::Builder::new()
            .name("sampler".into())
            .spawn(move || sampler::run(sampler, latest, stop))?
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("can't listen on {addr}"))?;
        tracing::info!(
            "fleetboard-client {} listening on {addr}",
            fleetboard_client::VERSION
        );
        axum::serve(listener, router(state))
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        anyhow::Ok(())
    })?;

    stop.store(true, Ordering::Relaxed); // tell the sampler to finish its nap
    let _ = sampler_thread.join();
    tracing::info!("stopped");
    Ok(())
}

/// Ctrl-C everywhere, plus SIGTERM on Unix (what systemd sends).
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
