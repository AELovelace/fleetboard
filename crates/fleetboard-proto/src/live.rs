//! What the server sends the dashboard: one [`LiveEvent`] per poll tick on the `GET /api/live`
//! stream, the short in-memory trail ([`RingPoint`]) and the 24-hour history ([`HistoryPoint`]).

use serde::{Deserialize, Serialize};

use crate::snapshot::Snapshot;

/// One host as the dashboard sees it: the row the admin added plus what the last poll found.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HostLive {
    pub id: i64,
    pub name: String,
    pub address: String, // "host:port" as stored; no scheme
    pub enabled: bool,
    pub reachable: Option<bool>, // None: not asked yet (just added, or disabled)
    pub error: String,           // readable reason when reachable is false, else ""
    pub polled_s_ago: Option<u64>, // seconds since the last answer (good or bad)
    pub latency_ms: Option<u32>, // how long the last successful poll took
    pub snapshot: Option<Snapshot>, // the latest answer; kept while the host is down so the card still shows facts
}

/// One tick of the live stream: every host at once, stamped with the server's clock.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LiveEvent {
    pub ts: u64, // server unix seconds
    pub hosts: Vec<HostLive>,
}

/// One point of the in-memory trail behind the sparklines (one per poll, 10 minutes kept).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct RingPoint {
    pub ts: u64,
    pub cpu: f32,
    pub mem_used: u64,
    pub gpu_util: Option<f32>, // GPU 0, when the host has one
    pub net_rx: u64,           // bytes/s summed over interfaces
    pub net_tx: u64,
}

/// One averaged point from the history table (10 s rows, or coarser when the API downsamples).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct HistoryPoint {
    pub ts: u64, // start of the window, unix seconds
    pub cpu: Option<f32>,
    pub load1: Option<f32>,
    pub mem_used: Option<u64>,
    pub mem_total: Option<u64>,
    pub net_rx: Option<u64>,
    pub net_tx: Option<u64>,
    pub gpu_util: Option<f32>,
    pub vram_used: Option<u64>,
    pub gpu_temp: Option<f32>,
}
