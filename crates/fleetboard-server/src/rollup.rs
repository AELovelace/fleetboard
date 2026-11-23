//! Longer, lighter history: per host and metric, the min, max, average, first and last value of
//! every hour (kept 7 days) and every UTC day (kept 90 days), next to the 24 hours of 10-second
//! rows. That's what capacity questions need ("when will rsync-box's disk be full?") and it is
//! tiny: a few dozen numbers per host per hour.
//!
//! Metric names (also what the API's `metric` parameter resolves to):
//!
//! | metric | value | `cap` |
//! |---|---|---|
//! | `cpu` | CPU % | |
//! | `mem` | memory used % | |
//! | `load` | 1-minute load average (Unix) | |
//! | `temp` | the hottest sensor or GPU, °C | |
//! | `disk:<mount>` | bytes used | bytes total |
//! | `net:<interface>:rx` / `:tx` | bytes per second | |
//! | `gpu:<n>` | GPU utilisation % | |
//! | `gpu:<n>:temp` | GPU °C | |
//! | `gpu:<n>:vram` | VRAM bytes used | VRAM bytes total |
//!
//! The poller feeds every successful snapshot into the host's [`Rollups`]. An hour or day that ends
//! comes back as finished rows; every few minutes the open ones are drained too, and the database
//! merges each part into the row it already has (min of mins, sum of sums…), so a restart loses
//! at most a few minutes.

use std::collections::HashMap;

use fleetboard_proto::Snapshot;

pub const HOUR: u64 = 3600;
pub const DAY: u64 = 86_400;
pub const KEEP_HOURLY: u64 = 7 * DAY; // hourly rows are pruned after a week
pub const KEEP_DAILY: u64 = 90 * DAY; // daily rows after 90 days
pub const MAX_NET_IFS: usize = 16; // interfaces with traffic kept per host (Windows lists many virtual ones)

/// What one metric did inside one hour or day.
#[derive(Debug, Clone, PartialEq)]
pub struct Acc {
    pub min: f64,
    pub max: f64,
    pub sum: f64,
    pub n: u32,
    pub cap: Option<f64>, // the latest capacity (disk or VRAM total)
    pub first: f64,
    pub first_ts: u64,
    pub last: f64,
    pub last_ts: u64,
}

impl Acc {
    fn new(ts: u64, v: f64, cap: Option<f64>) -> Self {
        Self {
            min: v,
            max: v,
            sum: v,
            n: 1,
            cap,
            first: v,
            first_ts: ts,
            last: v,
            last_ts: ts,
        }
    }

    fn push(&mut self, ts: u64, v: f64, cap: Option<f64>) {
        self.min = self.min.min(v);
        self.max = self.max.max(v);
        self.sum += v;
        self.n += 1;
        self.last = v;
        self.last_ts = ts;
        if cap.is_some() {
            self.cap = cap;
        }
    }
}

/// One finished (or partly finished) hour or day of one metric, ready for the database.
#[derive(Debug, Clone, PartialEq)]
pub struct RollupRow {
    pub host_id: i64,
    pub span: u64,  // HOUR or DAY
    pub start: u64, // the hour's or UTC day's first second
    pub metric: String,
    pub acc: Acc,
}

/// Every metric a snapshot carries, as (name, value, capacity).
pub fn metrics(snap: &Snapshot) -> Vec<(String, f64, Option<f64>)> {
    let mut out = vec![("cpu".to_string(), f64::from(snap.cpu.percent), None)];
    if snap.memory.total_bytes > 0 {
        let pct = snap.memory.used_bytes as f64 * 100.0 / snap.memory.total_bytes as f64;
        out.push(("mem".into(), pct, None));
    }
    if let Some(l) = snap.cpu.load1 {
        out.push(("load".into(), f64::from(l), None));
    }
    let hottest = crate::wazuh::readings(snap)
        .iter()
        .map(|r| f64::from(r.celsius))
        .fold(None, |m: Option<f64>, c| Some(m.map_or(c, |m| m.max(c))));
    if let Some(c) = hottest {
        out.push(("temp".into(), c, None));
    }
    for d in &snap.disks {
        out.push((
            format!("disk:{}", d.mount),
            d.used_bytes as f64,
            Some(d.total_bytes as f64),
        ));
    }
    for n in snap
        .network
        .iter()
        .filter(|n| n.rx_total + n.tx_total > 0) // skip interfaces that never carried a byte
        .take(MAX_NET_IFS)
    {
        out.push((format!("net:{}:rx", n.name), n.rx_bps as f64, None));
        out.push((format!("net:{}:tx", n.name), n.tx_bps as f64, None));
    }
    for g in &snap.gpus {
        if let Some(u) = g.util_percent {
            out.push((format!("gpu:{}", g.index), f64::from(u), None));
        }
        if let Some(t) = g.temp_c {
            out.push((format!("gpu:{}:temp", g.index), f64::from(t), None));
        }
        if let Some(v) = g.vram_used_bytes {
            out.push((
                format!("gpu:{}:vram", g.index),
                v as f64,
                g.vram_total_bytes.map(|t| t as f64),
            ));
        }
    }
    out.retain(|(_, v, _)| v.is_finite());
    out
}

/// The open hour and day of one host.
#[derive(Debug)]
pub struct Rollups {
    host_id: i64,
    open: [(u64, u64, HashMap<String, Acc>); 2], // (span, start, metrics) for HOUR and DAY
}

impl Rollups {
    pub fn new(host_id: i64) -> Self {
        Self {
            host_id,
            open: [(HOUR, 0, HashMap::new()), (DAY, 0, HashMap::new())],
        }
    }

    /// Add one snapshot taken at server time `now`; returns the rows of any hour or day it closed.
    pub fn push(&mut self, now: u64, snap: &Snapshot) -> Vec<RollupRow> {
        let mut done = Vec::new();
        let values = metrics(snap);
        for i in 0..self.open.len() {
            let span = self.open[i].0;
            let start = now - now % span; // UTC hours and days both start on a multiple
            if self.open[i].1 != start {
                done.extend(self.take(i)); // a new hour or day: hand the old one over
                self.open[i].1 = start;
            }
            let map = &mut self.open[i].2;
            for (name, v, cap) in &values {
                match map.get_mut(name) {
                    Some(acc) => acc.push(now, *v, *cap),
                    None => {
                        map.insert(name.clone(), Acc::new(now, *v, *cap));
                    }
                }
            }
        }
        done
    }

    /// Everything gathered so far in the open hour and day; they stay open and start empty.
    pub fn drain(&mut self) -> Vec<RollupRow> {
        (0..self.open.len()).flat_map(|i| self.take(i)).collect()
    }

    fn take(&mut self, i: usize) -> Vec<RollupRow> {
        let (span, start, map) = &mut self.open[i];
        let (span, start) = (*span, *start);
        map.drain()
            .map(|(metric, acc)| RollupRow {
                host_id: self.host_id,
                span,
                start,
                metric,
                acc,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetboard_proto::{Cpu, Disk, HostFacts, Memory, NetIf};

    fn snap(cpu: f32, used: u64) -> Snapshot {
        Snapshot {
            schema: fleetboard_proto::SCHEMA,
            taken_at: 0,
            host: HostFacts::default(),
            cpu: Cpu {
                percent: cpu,
                ..Default::default()
            },
            memory: Memory {
                used_bytes: 1,
                total_bytes: 4,
                ..Default::default()
            },
            disks: vec![Disk {
                mount: "/".into(),
                device: None,
                fs: "xfs".into(),
                used_bytes: used,
                total_bytes: 100,
            }],
            network: vec![NetIf {
                name: "idle0".into(),
                rx_bps: 0,
                tx_bps: 0,
                rx_total: 0,
                tx_total: 0,
            }],
            gpus: vec![],
            temperatures: vec![],
        }
    }

    #[test]
    fn metrics_have_units_and_skip_idle_interfaces() {
        let m = metrics(&snap(50.0, 40));
        let names: Vec<&str> = m.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, vec!["cpu", "mem", "disk:/"]);
        assert_eq!(m[1].1, 25.0); // 1 of 4 bytes
        assert_eq!(m[2].2, Some(100.0)); // the disk's capacity rides along
    }

    #[test]
    fn an_hour_closes_when_the_next_one_starts_and_drain_keeps_it_open() {
        let mut r = Rollups::new(7);
        assert!(r.push(3600 * 10 + 5, &snap(10.0, 40)).is_empty());
        assert!(r.push(3600 * 10 + 7, &snap(30.0, 42)).is_empty());
        let closed = r.push(3600 * 11, &snap(90.0, 43)); // a new hour, same day
        let cpu = closed.iter().find(|row| row.metric == "cpu").unwrap();
        assert_eq!((cpu.span, cpu.start, cpu.host_id), (HOUR, 36_000, 7));
        assert_eq!(
            (cpu.acc.min, cpu.acc.max, cpu.acc.sum, cpu.acc.n),
            (10.0, 30.0, 40.0, 2)
        );
        let disk = closed.iter().find(|row| row.metric == "disk:/").unwrap();
        assert_eq!((disk.acc.first, disk.acc.last), (40.0, 42.0));
        assert!(closed.iter().all(|row| row.span == HOUR)); // the day is still open
        let drained = r.drain();
        assert_eq!(
            drained.iter().filter(|row| row.span == DAY).count(),
            3, // cpu, mem and disk for the day so far
        );
        let day_cpu = drained
            .iter()
            .find(|row| row.span == DAY && row.metric == "cpu")
            .unwrap();
        assert_eq!(day_cpu.acc.n, 3);
        assert!(r.drain().is_empty()); // drained rows aren't handed over twice
    }
}
