//! Wire types shared by the Fleetboard client and server.
//!
//! The client answers `GET /stats` with a [`Snapshot`] and `GET /healthz` with a [`Health`].
//! The server turns many snapshots into a [`LiveEvent`] for the dashboard's live stream, and
//! answers history questions with [`HistoryPoint`]s. Keeping every type here, in one crate with
//! no I/O, means the two binaries can never disagree about field names or units.
//!
//! Units everywhere: bytes, bytes per second (`_bps`), percent 0–100 as `f32`, degrees Celsius,
//! watts, megahertz and seconds. An `Option` means "this platform or driver doesn't expose it".
//!
//! Versioning: [`SCHEMA`] is bumped only for a breaking change. New fields are added with
//! `#[serde(default)]` so an older server still reads a newer client, and unknown fields are
//! ignored on purpose (no `deny_unknown_fields`).

pub mod live;
pub mod snapshot;

pub use live::{HistoryPoint, HostLive, LiveEvent, RingPoint};
pub use snapshot::{
    Cpu, Disk, Gpu, GpuVendor, Health, HostFacts, Memory, NetIf, Snapshot, Temperature,
};

/// The wire format version this crate speaks; see the module docs for the bump rule.
pub const SCHEMA: u32 = 1;
