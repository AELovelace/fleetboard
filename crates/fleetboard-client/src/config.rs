//! `client.toml`: where it lives on each OS, what it holds, and the rules it must pass.
//!
//! ```toml
//! token = "…"              # the one shared token; `fleetboard-client gen-token` prints one
//! bind = "0.0.0.0:9280"    # on the Mnemerynne box itself use "127.0.0.1:9280"
//! name = ""                # display name; empty = hostname
//! allowed_hosts = []       # Host-header allow-list; empty = any (the token is the real guard)
//! gpu = true               # try the GPU collectors at all
//! skip_mounts = []         # mount points to leave out of the disks list
//! log = "info"             # tracing filter: error, warn, info, debug, trace
//! ```
//!
//! `FLEETBOARD_TOKEN` in the environment overrides `token` (handy for a test shell).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

/// The default port every client listens on; the server appends it when an address has none.
pub const DEFAULT_PORT: u16 = 9280;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct ClientConfig {
    pub token: String,
    pub bind: String,
    pub name: String,
    pub allowed_hosts: Vec<String>,
    pub gpu: bool,
    pub skip_mounts: Vec<String>,
    pub log: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            bind: format!("0.0.0.0:{DEFAULT_PORT}"),
            name: String::new(),
            allowed_hosts: Vec::new(),
            gpu: true,
            skip_mounts: Vec::new(),
            log: "info".into(),
        }
    }
}

impl ClientConfig {
    /// Where the config lives when `--config` isn't given: `/etc/fleetboard/client.toml` on Unix,
    /// `%ProgramData%\Fleetboard\client.toml` on Windows.
    pub fn default_path() -> PathBuf {
        if cfg!(windows) {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            base.join("Fleetboard").join("client.toml")
        } else {
            PathBuf::from("/etc/fleetboard/client.toml")
        }
    }

    /// Read and check the file; the environment's `FLEETBOARD_TOKEN` wins over the file's token.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("can't read {}", path.display()))?;
        let mut cfg: Self =
            toml::from_str(&text).with_context(|| format!("{} isn't valid", path.display()))?;
        if let Ok(env_token) = std::env::var("FLEETBOARD_TOKEN") {
            if !env_token.trim().is_empty() {
                cfg.token = env_token.trim().to_string(); // the environment overrides the file
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// The rules: a token at least 16 characters long, and a bind address that parses.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.token.trim().len() < 16 {
            bail!("`token` is missing or shorter than 16 characters; run `fleetboard-client gen-token` and put the result in the config");
        }
        self.bind_addr()?;
        Ok(())
    }

    /// `bind` as a socket address, with a readable error when it isn't one.
    pub fn bind_addr(&self) -> anyhow::Result<SocketAddr> {
        self.bind.parse().with_context(|| {
            format!(
                "`bind` = {:?} isn't an address like 0.0.0.0:{DEFAULT_PORT}",
                self.bind
            )
        })
    }

    /// The display name for the server: the config's `name`, or None to let the hostname stand.
    pub fn display_name(&self) -> Option<String> {
        let name = self.name.trim();
        (!name.is_empty()).then(|| name.to_string())
    }
}

/// A fresh random token: 32 URL-safe characters, enough for a shared secret on a LAN.
pub fn generate_token() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"; // no 0/O/1/l/I lookalikes
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(text: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f
    }

    #[test]
    fn defaults_fill_in_everything_but_the_token() {
        let f = write("token = \"abcdefghijklmnop\"\n");
        let cfg = ClientConfig::load(f.path()).unwrap();
        assert_eq!(cfg.bind, "0.0.0.0:9280");
        assert!(cfg.gpu && cfg.allowed_hosts.is_empty() && cfg.display_name().is_none());
    }

    #[test]
    fn a_short_or_missing_token_is_refused() {
        let f = write("bind = \"127.0.0.1:9280\"\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("gen-token"), "{err}");
        let f = write("token = \"short\"\n");
        assert!(ClientConfig::load(f.path()).is_err());
    }

    #[test]
    fn a_bad_bind_address_is_refused_with_the_value_in_the_message() {
        let f = write("token = \"abcdefghijklmnop\"\nbind = \"nonsense\"\n");
        let err = ClientConfig::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("nonsense"), "{err}");
    }

    #[test]
    fn generated_tokens_are_long_random_and_unambiguous() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(!a.contains(['0', 'O', '1', 'l', 'I']));
    }
}
