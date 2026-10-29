//! The measuring loop. `sysinfo` calls block, so the sampler lives on a plain thread, ticks once a
//! second and publishes the newest [`Snapshot`] into a shared slot the HTTP handlers read.
//!
//! Network rates need two samples, so the very first tick is measured but not published.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fleetboard_proto::{Cpu, Disk, HostFacts, Memory, NetIf, Snapshot, Temperature, SCHEMA};
use sysinfo::{
    Components, CpuRefreshKind, Disks, MemoryRefreshKind, Networks, RefreshKind, System,
};

use crate::config::ClientConfig;
use crate::gpu::GpuCollector;

/// The slot the HTTP side reads: `None` until the second tick has happened.
pub type Latest = Arc<RwLock<Option<Snapshot>>>;

/// Filesystems that are never worth a bar: memory-backed, overlay layers and kernel views.
const PSEUDO_FS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "overlay",
    "squashfs",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "efivarfs",
    "autofs",
    "ramfs",
    "fuse.portal",
    "fusectl",
    "debugfs",
    "tracefs",
    "configfs",
    "pstore",
    "bpf",
    "hugetlbfs",
    "mqueue",
    "securityfs",
    "binfmt_misc",
    "nsfs",
    "devpts",
];
/// Mount prefixes that are housekeeping, not storage anyone cares about.
const PSEUDO_MOUNTS: &[&str] = &[
    "/snap/",
    "/run/",
    "/sys/",
    "/proc/",
    "/dev/",
    "/boot/efi",
    "/var/lib/snapd",
];

/// Bytes per second from a byte delta and the time it took; the one piece of arithmetic in here.
pub fn rate(delta_bytes: u64, elapsed: Duration) -> u64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0;
    }
    (delta_bytes as f64 / secs).round() as u64
}

/// Whether a mounted filesystem belongs in the disks list.
pub fn is_real_disk(fs: &str, mount: &str, removable: bool, skip: &[String]) -> bool {
    if removable || PSEUDO_FS.contains(&fs.to_ascii_lowercase().as_str()) {
        return false;
    }
    if PSEUDO_MOUNTS
        .iter()
        .any(|p| mount.starts_with(p) || mount == p.trim_end_matches('/'))
    {
        return false;
    }
    !skip.iter().any(|s| s == mount)
}

/// Owns the sysinfo handles between ticks (they keep the previous reading for deltas).
pub struct Sampler {
    sys: System,
    disks: Disks,
    nets: Networks,
    comps: Components,
    gpus: Vec<Box<dyn GpuCollector>>,
    last_tick: Instant,
    display_name: Option<String>,
    skip_mounts: Vec<String>,
    model: String,
    cores: u16,
}

impl Sampler {
    /// Set up the handles and take the first (unpublished) reading.
    pub fn new(cfg: &ClientConfig, gpus: Vec<Box<dyn GpuCollector>>) -> Self {
        let refresh = RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage().with_frequency())
            .with_memory(MemoryRefreshKind::everything());
        let sys = System::new_with_specifics(refresh);
        let model = sys
            .cpus()
            .first()
            .map(|c| c.brand().trim().to_string())
            .unwrap_or_default();
        let cores = sys.cpus().len() as u16;
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            nets: Networks::new_with_refreshed_list(),
            comps: Components::new_with_refreshed_list(),
            gpus,
            last_tick: Instant::now(),
            display_name: cfg.display_name(),
            skip_mounts: cfg.skip_mounts.clone(),
            model,
            cores,
        }
    }

    /// Measure everything once and build the snapshot. Call it at a steady 1 Hz.
    pub fn tick(&mut self) -> Snapshot {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(true); // true: forget disks that vanished (an unplugged USB stick)
        self.nets.refresh(true);
        self.comps.refresh(true);
        let elapsed = self.last_tick.elapsed(); // measured right after the network refresh, for the rates
        self.last_tick = Instant::now();

        let cpu = Cpu {
            percent: self.sys.global_cpu_usage(),
            per_core: self.sys.cpus().iter().map(|c| c.cpu_usage()).collect(),
            cores: self.cores,
            model: self.model.clone(),
            load1: load_average().map(|l| l.0),
            load5: load_average().map(|l| l.1),
            load15: load_average().map(|l| l.2),
            freq_mhz: self
                .sys
                .cpus()
                .first()
                .map(|c| c.frequency() as u32)
                .filter(|f| *f > 0),
        };
        let memory = Memory {
            used_bytes: self.sys.used_memory(),
            total_bytes: self.sys.total_memory(),
            available_bytes: self.sys.available_memory(),
            swap_used_bytes: self.sys.used_swap(),
            swap_total_bytes: self.sys.total_swap(),
        };
        let disks = self
            .disks
            .iter()
            .filter(|d| {
                let fs = d.file_system().to_string_lossy();
                let mount = d.mount_point().to_string_lossy();
                is_real_disk(&fs, &mount, d.is_removable(), &self.skip_mounts)
                    && d.total_space() > 0
            })
            .map(|d| Disk {
                mount: d.mount_point().to_string_lossy().into_owned(),
                device: Some(d.name().to_string_lossy().into_owned()).filter(|n| !n.is_empty()),
                fs: d.file_system().to_string_lossy().into_owned(),
                used_bytes: d.total_space().saturating_sub(d.available_space()),
                total_bytes: d.total_space(),
            })
            .collect();
        let network = self
            .nets
            .iter()
            .filter(|(name, _)| !name.starts_with("lo")) // loopback traffic is noise
            .map(|(name, data)| NetIf {
                name: name.clone(),
                rx_bps: rate(data.received(), elapsed),
                tx_bps: rate(data.transmitted(), elapsed),
                rx_total: data.total_received(),
                tx_total: data.total_transmitted(),
            })
            .collect();
        let temperatures = self
            .comps
            .iter()
            .filter_map(|c| {
                c.temperature().map(|t| Temperature {
                    label: c.label().to_string(),
                    celsius: t,
                    max_c: c.max(),
                })
            })
            .collect();
        let gpus = self.gpus.iter_mut().flat_map(|g| g.collect()).collect();

        Snapshot {
            schema: SCHEMA,
            taken_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            host: HostFacts {
                hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
                name: self.display_name.clone(),
                os: System::long_os_version()
                    .unwrap_or_else(|| System::name().unwrap_or_else(|| "unknown".into())),
                kernel: System::kernel_version(),
                arch: System::cpu_arch(),
                uptime_s: System::uptime(),
                agent: crate::VERSION.to_string(),
            },
            cpu,
            memory,
            disks,
            network,
            gpus,
            temperatures,
        }
    }
}

/// Unix load averages; sysinfo returns zeros on Windows, which we report as "not available".
fn load_average() -> Option<(f32, f32, f32)> {
    if cfg!(windows) {
        return None;
    }
    let l = System::load_average();
    Some((l.one as f32, l.five as f32, l.fifteen as f32))
}

/// Run the loop until `stop` is set: the first tick primes the deltas, every later one is published.
pub fn run(mut sampler: Sampler, latest: Latest, stop: Arc<AtomicBool>) {
    let _ = sampler.tick(); // prime: no rates yet, so nothing to publish
    let period = Duration::from_secs(1);
    let mut next = Instant::now() + period;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now < next {
            std::thread::sleep((next - now).min(Duration::from_millis(200))); // short naps so stop is noticed quickly
            continue;
        }
        next += period; // fixed cadence, no drift
        let snap = sampler.tick();
        if let Ok(mut slot) = latest.write() {
            *slot = Some(snap);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_is_bytes_over_seconds_rounded() {
        assert_eq!(rate(1000, Duration::from_secs(1)), 1000);
        assert_eq!(rate(1000, Duration::from_millis(500)), 2000);
        assert_eq!(rate(1, Duration::from_millis(3000)), 0); // 0.33 rounds to 0
        assert_eq!(rate(500, Duration::ZERO), 0); // never divide by zero
    }

    #[test]
    fn pseudo_filesystems_and_skipped_mounts_are_left_out() {
        let skip = vec!["/mnt/scratch".to_string()];
        assert!(is_real_disk("ext4", "/", false, &skip));
        assert!(is_real_disk("NTFS", "C:\\", false, &skip));
        assert!(!is_real_disk("tmpfs", "/tmp", false, &skip));
        assert!(!is_real_disk("squashfs", "/snap/core/1", false, &skip));
        assert!(!is_real_disk("vfat", "/boot/efi", false, &skip));
        assert!(!is_real_disk("exfat", "D:\\", true, &skip)); // removable
        assert!(!is_real_disk("xfs", "/mnt/scratch", false, &skip)); // skipped by config
    }

    #[test]
    fn a_tick_produces_a_sane_snapshot_on_this_machine() {
        let cfg = ClientConfig {
            token: "x".repeat(16),
            ..Default::default()
        };
        let mut s = Sampler::new(&cfg, Vec::new());
        let _ = s.tick();
        std::thread::sleep(Duration::from_millis(250));
        let snap = s.tick();
        assert_eq!(snap.schema, SCHEMA);
        assert!(snap.memory.total_bytes > 0 && snap.cpu.cores > 0);
        assert!(!snap.host.hostname.is_empty() && snap.host.agent == crate::VERSION);
    }
}
