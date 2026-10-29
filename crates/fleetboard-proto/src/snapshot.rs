//! What one machine reports about itself: the [`Snapshot`] the client returns from `GET /stats`,
//! and the tiny [`Health`] it returns from `GET /healthz` without a token.

use serde::{Deserialize, Serialize};

/// Everything the client measured in its latest one-second tick.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub schema: u32,   // always crate::SCHEMA when the client built it
    pub taken_at: u64, // the client's unix seconds; display only, the server stamps its own clock
    pub host: HostFacts,
    pub cpu: Cpu,
    pub memory: Memory,
    #[serde(default)]
    pub disks: Vec<Disk>, // real filesystems only (no tmpfs, overlay, snaps…)
    #[serde(default)]
    pub network: Vec<NetIf>, // rates are worked out by the client from two samples
    #[serde(default)]
    pub gpus: Vec<Gpu>, // empty when no collector found a card
    #[serde(default)]
    pub temperatures: Vec<Temperature>, // hwmon on Linux; usually empty on Windows
}

/// Facts about the machine that rarely change.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct HostFacts {
    pub hostname: String,
    #[serde(default)]
    pub name: Option<String>, // display name from the client's config, when set
    pub os: String, // "Fedora Linux 42", "Windows Server 2022"
    #[serde(default)]
    pub kernel: Option<String>,
    pub arch: String, // "x86_64"
    pub uptime_s: u64,
    pub agent: String, // the client crate's version, e.g. "0.1.0"
}

/// Processor load.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Cpu {
    pub percent: f32, // whole-machine utilisation 0–100
    #[serde(default)]
    pub per_core: Vec<f32>, // one entry per logical core
    pub cores: u16,   // logical cores
    pub model: String, // "AMD Ryzen 7 5800X 8-Core Processor"
    #[serde(default)]
    pub load1: Option<f32>, // Unix load averages; None on Windows
    #[serde(default)]
    pub load5: Option<f32>,
    #[serde(default)]
    pub load15: Option<f32>,
    #[serde(default)]
    pub freq_mhz: Option<u32>, // current frequency of the first core
}

/// RAM and swap, in bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Memory {
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub available_bytes: u64, // what new programs could still get (counts cache as free)
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
}

/// One mounted filesystem worth showing.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Disk {
    pub mount: String, // "/" or "C:\"
    #[serde(default)]
    pub device: Option<String>, // "/dev/nvme0n1p2" when known
    pub fs: String,    // "ext4", "NTFS"
    pub used_bytes: u64,
    pub total_bytes: u64,
}

/// One network interface with its current rates.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct NetIf {
    pub name: String,
    pub rx_bps: u64,   // bytes received per second over the last tick
    pub tx_bps: u64,   // bytes sent per second over the last tick
    pub rx_total: u64, // bytes since the interface came up
    pub tx_total: u64,
}

/// Who made the graphics card.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Other,
}

/// One graphics card. Every measurement is optional because each source exposes a different set:
/// NVML gives all of them, AMD's sysfs most of them, Windows performance counters only utilisation
/// and memory.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Gpu {
    pub index: u8,
    pub vendor: GpuVendor,
    pub name: String,   // "NVIDIA GeForce GTX 1050 Ti", "Radeon RX 580"
    pub source: String, // "nvml", "amdgpu-sysfs" or "pdh": which collector produced it
    #[serde(default)]
    pub util_percent: Option<f32>,
    #[serde(default)]
    pub vram_used_bytes: Option<u64>,
    #[serde(default)]
    pub vram_total_bytes: Option<u64>,
    #[serde(default)]
    pub temp_c: Option<f32>,
    #[serde(default)]
    pub power_w: Option<f32>,
    #[serde(default)]
    pub fan_percent: Option<f32>,
    #[serde(default)]
    pub fan_rpm: Option<u32>,
    #[serde(default)]
    pub clock_mhz: Option<u32>, // graphics clock
}

/// A temperature sensor that isn't part of a GPU (CPU package, NVMe, board).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Temperature {
    pub label: String,
    pub celsius: f32,
    #[serde(default)]
    pub max_c: Option<f32>, // the sensor's own limit, when it reports one
}

/// The answer to `GET /healthz`: cheap, never needs the token, says who this is.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Health {
    pub status: String, // "ok"
    pub schema: u32,
    pub agent: String, // client version
    pub hostname: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot with every optional field filled in.
    fn full() -> Snapshot {
        Snapshot {
            schema: crate::SCHEMA,
            taken_at: 1_761_600_000,
            host: HostFacts {
                hostname: "rds1".into(),
                name: Some("RDS 1".into()),
                os: "Windows Server 2022".into(),
                kernel: Some("10.0.20348".into()),
                arch: "x86_64".into(),
                uptime_s: 86_400,
                agent: "0.1.0".into(),
            },
            cpu: Cpu {
                percent: 43.5,
                per_core: vec![40.0, 47.0],
                cores: 2,
                model: "Test CPU".into(),
                load1: Some(1.2),
                load5: Some(0.9),
                load15: Some(0.8),
                freq_mhz: Some(3400),
            },
            memory: Memory {
                used_bytes: 6 << 30,
                total_bytes: 16 << 30,
                available_bytes: 9 << 30,
                swap_used_bytes: 0,
                swap_total_bytes: 4 << 30,
            },
            disks: vec![Disk {
                mount: "C:\\".into(),
                device: None,
                fs: "NTFS".into(),
                used_bytes: 100 << 30,
                total_bytes: 500 << 30,
            }],
            network: vec![NetIf {
                name: "Ethernet".into(),
                rx_bps: 1200,
                tx_bps: 300,
                rx_total: 1 << 40,
                tx_total: 1 << 38,
            }],
            gpus: vec![Gpu {
                index: 0,
                vendor: GpuVendor::Nvidia,
                name: "GTX 1050 Ti".into(),
                source: "nvml".into(),
                util_percent: Some(12.0),
                vram_used_bytes: Some(1 << 30),
                vram_total_bytes: Some(4 << 30),
                temp_c: Some(41.0),
                power_w: Some(18.5),
                fan_percent: Some(30.0),
                fan_rpm: Some(1200),
                clock_mhz: Some(1290),
            }],
            temperatures: vec![Temperature {
                label: "CPU".into(),
                celsius: 55.0,
                max_c: Some(95.0),
            }],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let snap = full();
        let text = serde_json::to_string(&snap).unwrap();
        assert_eq!(serde_json::from_str::<Snapshot>(&text).unwrap(), snap);
        assert!(text.contains("\"vendor\":\"nvidia\"")); // the enum is lowercase on the wire
    }

    #[test]
    fn missing_optional_fields_read_as_none_and_unknown_fields_are_ignored() {
        // A minimal client (no GPUs, no load averages) and a newer one that added a field.
        let text = r#"{"schema":1,"taken_at":1,"host":{"hostname":"h","os":"o","arch":"x86_64","uptime_s":1,"agent":"0.1.0"},
                       "cpu":{"percent":1.0,"cores":1,"model":"m","brand_new_field":true},
                       "memory":{"used_bytes":1,"total_bytes":2,"available_bytes":1,"swap_used_bytes":0,"swap_total_bytes":0}}"#;
        let snap: Snapshot = serde_json::from_str(text).unwrap();
        assert_eq!(snap.cpu.load1, None);
        assert!(snap.gpus.is_empty() && snap.disks.is_empty() && snap.network.is_empty());
        assert_eq!(snap.host.name, None);
    }
}
