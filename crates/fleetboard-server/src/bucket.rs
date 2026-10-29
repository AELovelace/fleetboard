//! Ten-second averages. Each poll's snapshot is added to the bucket for its window (`ts / 10`);
//! when a poll lands in a new window the finished bucket becomes one [`SampleRow`] for SQLite.
//! A host that was down for a whole window leaves a gap: no row, so the chart shows the hole.

use fleetboard_proto::Snapshot;

/// Window length in seconds.
pub const WINDOW: u64 = 10;

/// One finished window, averaged: what `samples_10s` stores.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleRow {
    pub host_id: i64,
    pub ts: u64, // window start (a multiple of WINDOW)
    pub n: u32,  // polls averaged
    pub cpu: f32,
    pub load1: Option<f32>,
    pub mem_used: u64,
    pub mem_total: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub disk_used: u64,
    pub disk_total: u64,
    pub gpu_util: Option<f32>,
    pub vram_used: Option<u64>,
    pub vram_total: Option<u64>,
    pub gpu_temp: Option<f32>,
    pub gpus: String, // JSON: every GPU's util/vram/temp/power, averaged
}

/// Running sums for the window in progress.
#[derive(Debug, Default, Clone)]
pub struct Bucket {
    host_id: i64,
    window: Option<u64>,
    n: u32,
    cpu: f64,
    load1: Option<f64>,
    mem_used: u128,
    mem_total: u64,
    net_rx: u128,
    net_tx: u128,
    disk_used: u64,
    disk_total: u64,
    gpus: Vec<GpuSum>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
struct GpuSum {
    #[serde(rename = "i")]
    index: u8,
    #[serde(skip)]
    n_util: u32,
    util: Option<f64>,
    vram_used: Option<u128>,
    vram_total: Option<u64>,
    temp: Option<f64>,
    power: Option<f64>,
}

impl Bucket {
    pub fn new(host_id: i64) -> Self {
        Self {
            host_id,
            ..Default::default()
        }
    }

    /// Add one poll. Returns the previous window's row when this poll opened a new window.
    pub fn push(&mut self, ts: u64, snap: &Snapshot) -> Option<SampleRow> {
        let window = ts / WINDOW * WINDOW;
        let finished = match self.window {
            Some(w) if w != window => self.finish(),
            _ => None,
        };
        if self.window != Some(window) {
            self.reset(window);
        }
        self.n += 1;
        self.cpu += snap.cpu.percent as f64;
        if let Some(l) = snap.cpu.load1 {
            self.load1 = Some(self.load1.unwrap_or(0.0) + l as f64);
        }
        self.mem_used += snap.memory.used_bytes as u128;
        self.mem_total = snap.memory.total_bytes; // a size, not an average
        self.net_rx += snap.network.iter().map(|n| n.rx_bps as u128).sum::<u128>();
        self.net_tx += snap.network.iter().map(|n| n.tx_bps as u128).sum::<u128>();
        self.disk_used = snap.disks.iter().map(|d| d.used_bytes).sum(); // latest value stands for the window
        self.disk_total = snap.disks.iter().map(|d| d.total_bytes).sum();
        for g in &snap.gpus {
            let sum = match self.gpus.iter_mut().find(|s| s.index == g.index) {
                Some(s) => s,
                None => {
                    self.gpus.push(GpuSum {
                        index: g.index,
                        ..Default::default()
                    });
                    self.gpus.last_mut().unwrap()
                }
            };
            if let Some(u) = g.util_percent {
                sum.util = Some(sum.util.unwrap_or(0.0) + u as f64);
                sum.n_util += 1;
            }
            if let Some(v) = g.vram_used_bytes {
                sum.vram_used = Some(sum.vram_used.unwrap_or(0) + v as u128);
            }
            sum.vram_total = g.vram_total_bytes.or(sum.vram_total);
            if let Some(t) = g.temp_c {
                sum.temp = Some(sum.temp.unwrap_or(0.0) + t as f64);
            }
            if let Some(p) = g.power_w {
                sum.power = Some(sum.power.unwrap_or(0.0) + p as f64);
            }
        }
        finished
    }

    /// Close the current window without a new poll (used when a host is removed or at shutdown).
    pub fn finish(&mut self) -> Option<SampleRow> {
        let window = self.window?;
        if self.n == 0 {
            return None;
        }
        let n = self.n as f64;
        let gpus: Vec<serde_json::Value> = self
            .gpus
            .iter()
            .map(|g| {
                serde_json::json!({
                    "i": g.index,
                    "util": g.util.map(|u| u / g.n_util.max(1) as f64),
                    "vram_used": g.vram_used.map(|v| (v / self.n as u128) as u64),
                    "vram_total": g.vram_total,
                    "temp": g.temp.map(|t| t / n),
                    "power": g.power.map(|p| p / n),
                })
            })
            .collect();
        let first = self.gpus.first();
        let row = SampleRow {
            host_id: self.host_id,
            ts: window,
            n: self.n,
            cpu: (self.cpu / n) as f32,
            load1: self.load1.map(|l| (l / n) as f32),
            mem_used: (self.mem_used / self.n as u128) as u64,
            mem_total: self.mem_total,
            net_rx: (self.net_rx / self.n as u128) as u64,
            net_tx: (self.net_tx / self.n as u128) as u64,
            disk_used: self.disk_used,
            disk_total: self.disk_total,
            gpu_util: first.and_then(|g| g.util.map(|u| (u / g.n_util.max(1) as f64) as f32)),
            vram_used: first.and_then(|g| g.vram_used.map(|v| (v / self.n as u128) as u64)),
            vram_total: first.and_then(|g| g.vram_total),
            gpu_temp: first.and_then(|g| g.temp.map(|t| (t / n) as f32)),
            gpus: serde_json::to_string(&gpus).unwrap_or_else(|_| "[]".into()),
        };
        self.window = None;
        Some(row)
    }

    fn reset(&mut self, window: u64) {
        let host_id = self.host_id;
        *self = Self {
            host_id,
            window: Some(window),
            ..Default::default()
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetboard_proto::{Cpu, Gpu, GpuVendor, HostFacts, Memory, NetIf, SCHEMA};

    fn snap(cpu: f32, rx: u64, gpu: Option<f32>) -> Snapshot {
        Snapshot {
            schema: SCHEMA,
            taken_at: 0,
            host: HostFacts::default(),
            cpu: Cpu {
                percent: cpu,
                load1: Some(1.0),
                ..Default::default()
            },
            memory: Memory {
                used_bytes: 100,
                total_bytes: 1000,
                ..Default::default()
            },
            disks: vec![],
            network: vec![NetIf {
                name: "eth0".into(),
                rx_bps: rx,
                tx_bps: 0,
                rx_total: 0,
                tx_total: 0,
            }],
            gpus: gpu
                .map(|u| {
                    vec![Gpu {
                        index: 0,
                        vendor: GpuVendor::Amd,
                        name: "RX".into(),
                        source: "test".into(),
                        util_percent: Some(u),
                        vram_used_bytes: Some(10),
                        vram_total_bytes: Some(100),
                        temp_c: Some(60.0),
                        power_w: None,
                        fan_percent: None,
                        fan_rpm: None,
                        clock_mhz: None,
                    }]
                })
                .unwrap_or_default(),
            temperatures: vec![],
        }
    }

    #[test]
    fn five_polls_in_one_window_make_one_averaged_row() {
        let mut b = Bucket::new(7);
        for (i, cpu) in [10.0, 20.0, 30.0, 40.0, 50.0].into_iter().enumerate() {
            assert!(b
                .push(100 + i as u64 * 2, &snap(cpu, 1000, Some(cpu)))
                .is_none()); // 100..108 all in window 100
        }
        let row = b
            .push(110, &snap(0.0, 0, None))
            .expect("window 100 is finished by the poll at 110");
        assert_eq!((row.host_id, row.ts, row.n), (7, 100, 5));
        assert_eq!(row.cpu, 30.0);
        assert_eq!(row.load1, Some(1.0));
        assert_eq!(row.net_rx, 1000);
        assert_eq!(row.mem_total, 1000);
        assert_eq!(row.gpu_util, Some(30.0));
        assert_eq!(row.gpu_temp, Some(60.0));
        assert!(row.gpus.contains("\"vram_total\":100"));
    }

    #[test]
    fn a_gap_makes_no_row_and_finish_closes_the_last_window() {
        let mut b = Bucket::new(1);
        assert!(b.push(100, &snap(50.0, 0, None)).is_none());
        // The host was down from 102 to 138; the next poll at 140 finishes window 100 only.
        let row = b.push(140, &snap(10.0, 0, None)).unwrap();
        assert_eq!((row.ts, row.n), (100, 1));
        let last = b.finish().unwrap();
        assert_eq!((last.ts, last.n, last.cpu), (140, 1, 10.0));
        assert!(b.finish().is_none());
    }
}
