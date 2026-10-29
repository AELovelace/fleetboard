//! Command line: `run` (the service), `once` (print one snapshot), `gen-token`, `check-config`.
//! Windows adds `service install|uninstall|start|stop` in milestone M5.

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
}

impl Cli {
    /// The config path to use: `--config`, or the OS default.
    pub fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(crate::config::ClientConfig::default_path)
    }
}
