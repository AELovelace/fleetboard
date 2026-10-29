//! The Fleetboard client: a passive agent that measures this machine once a second and answers
//! two HTTP routes for the Fleetboard server to poll.
//!
//! * `GET /healthz`: who this is, no token needed (liveness checks, installers).
//! * `GET /stats`: the latest [`fleetboard_proto::Snapshot`]; needs `Authorization: Bearer <token>`.
//!
//! The binary (`main.rs`) is a thin shell around this library so the integration tests in the
//! server crate can mount [`http::router`] on an ephemeral port and poll a real client.
//!
//! Module map: `config` (client.toml), `auth` (the token check), `sampler` (the 1 Hz measuring
//! thread), `gpu` (collectors for each vendor), `http` (routes and hardening headers), `cli`.

pub mod auth;
pub mod cli;
pub mod config;
pub mod gpu;
pub mod http;
pub mod sampler;

/// The client's own version, reported in `Health.agent` and `HostFacts.agent`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
