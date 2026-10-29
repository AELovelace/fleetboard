//! The `fleetboard-client` binary: parse the command line, load the config, and hand over to
//! `run::serve` (console) or the Windows service plumbing.

use std::time::Duration;

use clap::Parser;
use fleetboard_client::cli::{Cli, Command};
use fleetboard_client::config::{generate_token, ClientConfig};
use fleetboard_client::{gpu, run, sampler};
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
            run::serve(cfg, run::shutdown_signal())
        }
        #[cfg(windows)]
        Command::Service(cmd) => {
            use fleetboard_client::cli::ServiceCmd;
            use fleetboard_client::service_windows as svc;
            match cmd {
                ServiceCmd::Install => svc::install(&std::env::current_exe()?, &cli.config_path()),
                ServiceCmd::Uninstall => svc::uninstall(),
                ServiceCmd::Start => svc::start(),
                ServiceCmd::Stop => svc::stop(),
                ServiceCmd::Run => svc::run(),
            }
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
