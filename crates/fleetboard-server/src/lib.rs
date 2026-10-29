//! The Fleetboard server: polls every client, keeps a short in-memory trail and 24 hours of
//! 10-second averages in SQLite, and serves the dashboard and its live stream.
//!
//! It is reached only through Mnemerynne's Remote proxy, which handles sign-in and groups, so there
//! is no authentication of its own: it binds to 127.0.0.1 and trusts whatever reaches it. The proxy
//! strips `/remote/<slug>` and sends no user identity, so every URL the dashboard uses is relative
//! and the audit log can only record `X-Forwarded-For`.
//!
//! Module map: `config` (server.toml), `db` (SQLite), `poller` (the 2-second loop, modelled on
//! Mnemerynne's balancer poller), `ring` (the last 10 minutes per host), `bucket` (10-second
//! averages), `api` (routes), `addr` (host:port parsing).

pub mod addr;
pub mod api;
pub mod bucket;
pub mod config;
pub mod db;
pub mod poller;
pub mod ring;

/// The server's own version, shown in the dashboard footer and `/healthz`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Unix seconds now, as every timestamp in the system is the server's clock.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
