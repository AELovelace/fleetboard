//! The last ten minutes of one host, one point per poll, for the sparklines. Lives in memory only;
//! the dashboard fetches it once on load and then appends from the live stream.

use std::collections::VecDeque;

use fleetboard_proto::{RingPoint, Snapshot};

/// 300 polls at one every 2 s = 10 minutes.
pub const RING_CAPACITY: usize = 300;

#[derive(Debug, Default, Clone)]
pub struct Ring {
    points: VecDeque<RingPoint>,
}

impl Ring {
    /// Reduce a snapshot to the few numbers the sparklines draw and remember it.
    pub fn push(&mut self, ts: u64, snap: &Snapshot) {
        if self.points.len() == RING_CAPACITY {
            self.points.pop_front();
        }
        self.points.push_back(RingPoint {
            ts,
            cpu: snap.cpu.percent,
            mem_used: snap.memory.used_bytes,
            gpu_util: snap.gpus.first().and_then(|g| g.util_percent),
            net_rx: snap.network.iter().map(|n| n.rx_bps).sum(),
            net_tx: snap.network.iter().map(|n| n.tx_bps).sum(),
        });
    }

    /// Oldest first.
    pub fn points(&self) -> Vec<RingPoint> {
        self.points.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetboard_proto::{Cpu, HostFacts, Memory, SCHEMA};

    fn snap(cpu: f32) -> Snapshot {
        Snapshot {
            schema: SCHEMA,
            taken_at: 0,
            host: HostFacts::default(),
            cpu: Cpu {
                percent: cpu,
                ..Default::default()
            },
            memory: Memory::default(),
            disks: vec![],
            network: vec![],
            gpus: vec![],
            temperatures: vec![],
        }
    }

    #[test]
    fn keeps_the_newest_300_points() {
        let mut r = Ring::default();
        for i in 0..(RING_CAPACITY as u64 + 5) {
            r.push(i, &snap(i as f32));
        }
        let pts = r.points();
        assert_eq!(pts.len(), RING_CAPACITY);
        assert_eq!(pts.first().unwrap().ts, 5);
        assert_eq!(pts.last().unwrap().cpu, (RING_CAPACITY as f32) + 4.0);
    }
}
