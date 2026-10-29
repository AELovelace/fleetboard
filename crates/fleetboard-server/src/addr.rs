//! Parsing the `address` an admin types for a host: `name`, `name:port`, `10.0.5.9`, `[fe80::1]:9280`.
//! No scheme (it's always plain http on the LAN), the default port when none is given, and a
//! lower-cased hostname so duplicates can't hide behind capital letters.

use std::fmt;

/// The port every client listens on unless told otherwise (same as the client's DEFAULT_PORT).
pub const CLIENT_PORT: u16 = 9280;

/// A checked `host:port`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAddr {
    pub host: String, // lower-case; IPv6 without brackets
    pub port: u16,
}

impl HostAddr {
    /// Turn what the admin typed into a HostAddr, or say what's wrong in a sentence.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("The address is empty.".into());
        }
        if text.contains("://") || text.contains('/') {
            return Err("Give just host or host:port, without http:// or a path.".into());
        }
        if text.len() > 253 {
            return Err("The address is too long.".into());
        }
        let (host, port) = if let Some(rest) = text.strip_prefix('[') {
            // [v6]:port or [v6]
            let (inner, after) = rest
                .split_once(']')
                .ok_or("An IPv6 address needs a closing ].")?;
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => return Err("After ] only :port may follow.".into()),
            };
            (inner.to_string(), port)
        } else if text.matches(':').count() > 1 {
            (text.to_string(), None) // bare IPv6 without a port
        } else {
            match text.split_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (text.to_string(), None),
            }
        };
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
        {
            return Err(format!("{host:?} isn't a hostname or IP address."));
        }
        let port = match port {
            None => CLIENT_PORT,
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(|| format!("{p:?} isn't a port number (1-65535)."))?,
        };
        Ok(Self { host, port })
    }

    /// The base URL the poller uses.
    pub fn url(&self) -> String {
        if self.host.contains(':') {
            format!("http://[{}]:{}", self.host, self.port)
        } else {
            format!("http://{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for HostAddr {
    /// How it's stored and shown: `host:port`, IPv6 in brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_usual_shapes_and_fills_the_default_port() {
        assert_eq!(HostAddr::parse("RDS1").unwrap().to_string(), "rds1:9280");
        assert_eq!(
            HostAddr::parse(" 10.0.5.9:9999 ").unwrap().to_string(),
            "10.0.5.9:9999"
        );
        assert_eq!(
            HostAddr::parse("[fe80::1]:9280").unwrap().to_string(),
            "[fe80::1]:9280"
        );
        assert_eq!(
            HostAddr::parse("fe80::1").unwrap().url(),
            "http://[fe80::1]:9280"
        );
        assert_eq!(
            HostAddr::parse("nas.lan").unwrap().url(),
            "http://nas.lan:9280"
        );
    }

    #[test]
    fn refuses_schemes_paths_and_bad_ports() {
        for bad in [
            "",
            "http://rds1:9280",
            "rds1/stats",
            "rds1:0",
            "rds1:70000",
            "rds1:abc",
            "bad host",
            "[fe80::1",
        ] {
            assert!(HostAddr::parse(bad).is_err(), "{bad:?} should be refused");
        }
    }
}
