//! Service tokens for the `/api/v1` API (the one Mnemerynne calls for Claude).
//!
//! A token is `fbt_` plus 40 random characters. Only its SHA-256 hash is stored, so a copy of the
//! database can't be used to call the API. Each token has a name (who holds it) and scopes:
//!
//! - `read`: list hosts, one host's details and health, its history, recent activity;
//! - `act`: also the actions (add, rename, pause and resume monitoring of a host). Mnemerynne
//!   only calls these after a person presses *Run it* on Claude's proposal.
//!
//! Tokens are made, listed and revoked with `fleetboard-server token …` on the box; a revoked
//! token is refused on its very next request (every request looks the hash up afresh).

use sha2::{Digest, Sha256};

/// What a token may do. `Act` always includes reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Read,
    Act,
}

impl Scope {
    /// The `scopes` column for a token made with this scope.
    pub fn column(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Act => "read,act",
        }
    }

    /// `read` or `act` (as typed on the command line).
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "read" => Ok(Scope::Read),
            "act" | "read,act" => Ok(Scope::Act),
            other => Err(format!("unknown scope {other:?}: use read or act")),
        }
    }
}

/// Whether a token's `scopes` column grants `wanted`.
pub fn grants(scopes: &str, wanted: Scope) -> bool {
    let has = |s: &str| scopes.split(',').any(|x| x.trim() == s); // one comma-separated word at a time
    match wanted {
        Scope::Read => has("read") || has("act"),
        Scope::Act => has("act"),
    }
}

/// The prefix every token starts with, so a leaked one is easy to recognise in logs and scanners.
pub const TOKEN_PREFIX: &str = "fbt_";

/// A fresh token: `fbt_` + 40 characters from an unambiguous alphabet (about 235 bits).
pub fn generate() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng(); // the OS-seeded CSPRNG
    let body: String = (0..40)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("{TOKEN_PREFIX}{body}")
}

/// SHA-256 of the token as lowercase hex: what the database keeps and looks up.
pub fn hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The first 8 characters, shown by `token list` so a person can tell which token is which.
pub fn display_prefix(token: &str) -> String {
    token.chars().take(8).collect()
}

/// A token's name: 1-64 characters of letters, digits, `-`, `_` and `.`.
pub fn clean_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(name.to_string())
    } else {
        Err("a token name is 1-64 letters, digits, '-', '_' or '.'".into())
    }
}

/// Make a token: check the name and scope, store the hash (and an audit line), and hand back
/// the token itself, which is never seen again.
pub fn create(
    db: &crate::db::Db,
    name: &str,
    scope: &str,
    now: u64,
) -> Result<(String, crate::db::ApiToken), String> {
    let name = clean_name(name)?;
    let scope = Scope::parse(scope)?;
    let token = generate();
    let row = db
        .insert_token(
            &name,
            &hash(&token),
            &display_prefix(&token),
            scope.column(),
            now,
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                format!("a token called {name:?} already exists; revoke it or pick another name")
            } else {
                format!("couldn't save the token: {e}")
            }
        })?;
    db.audit(now, "local", "token.add", &name, scope.column())
        .map_err(|e| e.to_string())?;
    Ok((token, row))
}

/// The token from an `Authorization: Bearer …` header, if it looks like one of ours.
pub fn from_header(value: Option<&str>) -> Option<&str> {
    let (scheme, token) = value?.trim().split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && token.starts_with(TOKEN_PREFIX) && token.len() <= 128)
        .then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_long_prefixed_and_different() {
        let a = generate();
        let b = generate();
        assert!(a.starts_with("fbt_") && a.len() == 44);
        assert_ne!(a, b);
        assert_eq!(display_prefix(&a).len(), 8);
    }

    #[test]
    fn the_hash_is_sha256_hex() {
        // The well-known SHA-256 of "abc".
        assert_eq!(
            hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn scopes_parse_and_grant() {
        assert_eq!(Scope::parse("READ").unwrap(), Scope::Read);
        assert_eq!(Scope::parse("act").unwrap(), Scope::Act);
        assert!(Scope::parse("admin").is_err());
        assert!(grants("read", Scope::Read) && !grants("read", Scope::Act));
        assert!(grants("read,act", Scope::Read) && grants("read,act", Scope::Act));
        assert!(!grants("reader", Scope::Read)); // whole words only
    }

    #[test]
    fn the_header_must_be_a_bearer_fbt_token() {
        assert_eq!(from_header(Some("Bearer fbt_x")), Some("fbt_x"));
        assert_eq!(from_header(Some("bearer  fbt_x ")), Some("fbt_x"));
        assert_eq!(from_header(Some("Basic fbt_x")), None);
        assert_eq!(from_header(Some("Bearer someone-elses-token")), None);
        assert_eq!(from_header(None), None);
    }

    #[test]
    fn names_are_plain() {
        assert_eq!(clean_name(" mnemerynne-read ").unwrap(), "mnemerynne-read");
        assert!(
            clean_name("").is_err() && clean_name("a b").is_err() && clean_name("x;y").is_err()
        );
    }
}
