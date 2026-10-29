//! `server.toml` and its environment overrides.
//!
//! ```toml
//! bind = "127.0.0.1:9281"                       # only Mnemerynne on this box should reach it
//! db = "/var/lib/fleetboard/fleetboard.db"      # Windows default: %ProgramData%\Fleetboard\fleetboard.db
//! token = "…"                                   # the same shared token every client has
//! log = "info"
//! ```
//! `FLEETBOARD_TOKEN`, `FLEETBOARD_BIND` and `FLEETBOARD_DB` win over the file, so the systemd unit
//! can keep the token in a 0640 env file.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The default port of the server.
pub const DEFAULT_PORT: u16 = 9281;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub db: PathBuf,
    pub token: String,
    pub log: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: format!("127.0.0.1:{DEFAULT_PORT}"),
            db: default_db_path(),
            token: String::new(),
            log: "info".into(),
        }
    }
}

/// Where the database goes when the config doesn't say.
fn default_db_path() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Fleetboard").join("fleetboard.db")
    } else {
        PathBuf::from("/var/lib/fleetboard/fleetboard.db")
    }
}

impl ServerConfig {
    /// `/etc/fleetboard/server.toml`, or `%ProgramData%\Fleetboard\server.toml` on Windows.
    pub fn default_path() -> PathBuf {
        if cfg!(windows) {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            base.join("Fleetboard").join("server.toml")
        } else {
            PathBuf::from("/etc/fleetboard/server.toml")
        }
    }

    /// Read the file if it exists (a missing file means "all defaults"), then apply the environment.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut cfg = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("can't read {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("{} isn't valid", path.display()))?
        } else {
            Self::default()
        };
        cfg.apply_env();
        cfg.bind_addr()?;
        Ok(cfg)
    }

    /// Environment variables override the file.
    pub fn apply_env(&mut self) {
        if let Some(v) = env_non_empty("FLEETBOARD_TOKEN") {
            self.token = v;
        }
        if let Some(v) = env_non_empty("FLEETBOARD_BIND") {
            self.bind = v;
        }
        if let Some(v) = env_non_empty("FLEETBOARD_DB") {
            self.db = PathBuf::from(v);
        }
    }

    pub fn bind_addr(&self) -> anyhow::Result<SocketAddr> {
        self.bind.parse().with_context(|| {
            format!(
                "`bind` = {:?} isn't an address like 127.0.0.1:{DEFAULT_PORT}",
                self.bind
            )
        })
    }

    /// Whether a usable token is configured; the dashboard shows "NOT SET" otherwise.
    pub fn token_set(&self) -> bool {
        self.token.trim().len() >= 16
    }
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_means_defaults() {
        let cfg = ServerConfig::load(Path::new("Z:/definitely/not/here.toml")).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:9281");
        assert!(!cfg.token_set());
    }

    #[test]
    fn the_file_is_read_and_a_bad_bind_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("server.toml");
        std::fs::write(
            &p,
            "token = \"abcdefghijklmnopqrstuvwxyz\"\nbind = \"127.0.0.1:1\"\n",
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert!(cfg.token_set() && cfg.bind == "127.0.0.1:1");
        std::fs::write(&p, "bind = \"nope\"\n").unwrap();
        assert!(ServerConfig::load(&p)
            .unwrap_err()
            .to_string()
            .contains("nope"));
    }
}
