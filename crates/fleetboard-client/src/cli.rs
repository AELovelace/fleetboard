//! Command line: `run` (the service), `once` (print one snapshot), `gen-token`, `check-config`,
//! and on Windows `service install|uninstall|start|stop` (plus the hidden `service run` the SCM uses).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "fleetboard-client",
    version,
    about = "Fleetboard's agent: answers /healthz and /stats with this machine's stats"
)]
pub struct Cli {
    /// Path of client.toml (default: /etc/fleetboard/client.toml, or %ProgramData%\Fleetboard\client.toml on Windows)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Serve /healthz and /stats until stopped (the default)
    Run,
    /// Measure once and print the Snapshot as JSON; the first thing to run on a new box
    Once,
    /// Print a fresh shared token to put in every client.toml and the server's config
    GenToken,
    /// Read the config and report what's wrong with it, if anything
    CheckConfig,
    /// Windows service: install, uninstall, start or stop the "Fleetboard client" service
    #[cfg(windows)]
    #[command(subcommand)]
    Service(ServiceCmd),
}

#[cfg(windows)]
#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// Register the service (auto-start, LocalService, restart on failure) using --config
    Install,
    /// Stop and remove the service
    Uninstall,
    /// Start the installed service
    Start,
    /// Stop the installed service
    Stop,
    /// What the Service Control Manager launches; not for people
    #[command(hide = true)]
    Run,
}

impl Cli {
    /// The config path to use: `--config`, or the OS default.
    pub fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(crate::config::ClientConfig::default_path)
    }
}
