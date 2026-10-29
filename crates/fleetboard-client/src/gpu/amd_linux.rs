//! AMD cards on Linux through the amdgpu driver's sysfs files under `/sys/class/drm/card*/device/`.
//! Everything here is world-readable, so the client needs no root and no udev rule:
//!
//! * `vendor` (`0x1002` is AMD) and `device` (the PCI id, for the name)
//! * `gpu_busy_percent`, `mem_info_vram_used`, `mem_info_vram_total`
//! * `hwmon/hwmon*/temp1_input` (millidegrees), `power1_average` or `power1_input` (microwatts),
//!   `fan1_input` (rpm), `pwm1` / `pwm1_max` (fan duty)
//!
//! `parse_card` works on any directory with those files, which is how the unit test feeds it a
//! fake card.

use std::fs;
use std::path::{Path, PathBuf};

use fleetboard_proto::{Gpu, GpuVendor};

use super::GpuCollector;

const DRM: &str = "/sys/class/drm";
const AMD_VENDOR: &str = "0x1002";

/// A few common chips, so the card has a friendly name without a full PCI database.
const NAMES: &[(&str, &str)] = &[
    ("0x67df", "Radeon RX 580 (Polaris 10)"),
    ("0x67ef", "Radeon RX 560 (Polaris 11)"),
    ("0x699f", "Radeon RX 550 (Polaris 12)"),
    ("0x731f", "Radeon RX 5700 (Navi 10)"),
    ("0x73bf", "Radeon RX 6900 XT (Navi 21)"),
    ("0x73df", "Radeon RX 6700 XT (Navi 22)"),
    ("0x73ff", "Radeon RX 6600 (Navi 23)"),
    ("0x744c", "Radeon RX 7900 (Navi 31)"),
    ("0x747e", "Radeon RX 7800 XT (Navi 32)"),
    ("0x7480", "Radeon RX 7600 (Navi 33)"),
    ("0x1636", "Radeon Graphics (Renoir)"),
    ("0x164c", "Radeon Graphics (Lucienne)"),
    ("0x15bf", "Radeon 780M (Phoenix)"),
];

pub struct AmdCollector {
    cards: Vec<PathBuf>, // the `device` directories found at start
}

impl AmdCollector {
    /// Look for AMD cards; `None` when there are none.
    pub fn new() -> Option<Self> {
        let cards = find_cards(Path::new(DRM));
        (!cards.is_empty()).then_some(Self { cards })
    }

    pub fn card_count(&self) -> usize {
        self.cards.len()
    }
}

impl GpuCollector for AmdCollector {
    fn name(&self) -> &'static str {
        "amdgpu sysfs"
    }

    fn collect(&mut self) -> Vec<Gpu> {
        self.cards
            .iter()
            .enumerate()
            .filter_map(|(i, dir)| parse_card(dir, i as u8))
            .collect()
    }
}

/// Every `cardN/device` whose vendor is AMD, in card order (`card0`, `card1`, …; render nodes skipped).
pub fn find_cards(drm: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(drm) else {
        return Vec::new();
    };
    let mut cards: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("card") && !name.contains('-') // "card1", not "card1-HDMI-A-1"
        })
        .map(|p| p.join("device"))
        .filter(|d| read_trim(&d.join("vendor")).as_deref() == Some(AMD_VENDOR))
        .collect();
    cards.sort();
    cards
}

/// One card from its `device` directory; `None` when it isn't an AMD card.
pub fn parse_card(dir: &Path, index: u8) -> Option<Gpu> {
    if read_trim(&dir.join("vendor")).as_deref() != Some(AMD_VENDOR) {
        return None;
    }
    let device_id = read_trim(&dir.join("device"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let name = NAMES
        .iter()
        .find(|(id, _)| *id == device_id)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("AMD GPU {}", device_id.trim_start_matches("0x")));
    let hwmon = fs::read_dir(dir.join("hwmon")).ok().and_then(|rd| {
        rd.flatten().map(|e| e.path()).find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("hwmon"))
        })
    });
    let hw = |file: &str| hwmon.as_ref().and_then(|h| read_num(&h.join(file)));
    let fan_percent = match (hw("pwm1"), hw("pwm1_max")) {
        (Some(pwm), Some(max)) if max > 0.0 => Some((pwm / max * 100.0) as f32),
        (Some(pwm), None) => Some((pwm / 255.0 * 100.0) as f32), // pwm1 is 0-255 when there's no max file
        _ => None,
    };
    Some(Gpu {
        index,
        vendor: GpuVendor::Amd,
        name,
        source: "amdgpu-sysfs".into(),
        util_percent: read_num(&dir.join("gpu_busy_percent")).map(|v| v as f32),
        vram_used_bytes: read_num(&dir.join("mem_info_vram_used")).map(|v| v as u64),
        vram_total_bytes: read_num(&dir.join("mem_info_vram_total")).map(|v| v as u64),
        temp_c: hw("temp1_input").map(|v| (v / 1000.0) as f32),
        power_w: hw("power1_average")
            .or_else(|| hw("power1_input"))
            .map(|v| (v / 1_000_000.0) as f32),
        fan_percent,
        fan_rpm: hw("fan1_input").map(|v| v as u32),
        clock_mhz: None, // pp_dpm_sclk needs parsing; later if wanted
    })
}

fn read_trim(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_num(path: &Path) -> Option<f64> {
    read_trim(path)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake RX 580 as sysfs would show it.
    fn fake_card(dir: &Path) {
        fs::create_dir_all(dir.join("hwmon/hwmon3")).unwrap();
        for (f, v) in [
            ("vendor", "0x1002\n"),
            ("device", "0x67DF\n"),
            ("gpu_busy_percent", "37\n"),
            ("mem_info_vram_used", "1073741824\n"),
            ("mem_info_vram_total", "8589934592\n"),
        ] {
            fs::write(dir.join(f), v).unwrap();
        }
        for (f, v) in [
            ("temp1_input", "61000\n"),
            ("power1_average", "84500000\n"),
            ("fan1_input", "1450\n"),
            ("pwm1", "128\n"),
            ("pwm1_max", "255\n"),
        ] {
            fs::write(dir.join("hwmon/hwmon3").join(f), v).unwrap();
        }
    }

    #[test]
    fn reads_a_fake_rx_580() {
        let tmp = tempfile::tempdir().unwrap();
        let dev = tmp.path().join("card1/device");
        fake_card(&dev);
        let g = parse_card(&dev, 0).unwrap();
        assert_eq!(g.name, "Radeon RX 580 (Polaris 10)");
        assert_eq!(g.util_percent, Some(37.0));
        assert_eq!(
            (g.vram_used_bytes, g.vram_total_bytes),
            (Some(1 << 30), Some(8 << 30))
        );
        assert_eq!(g.temp_c, Some(61.0));
        assert_eq!(g.power_w, Some(84.5));
        assert_eq!(g.fan_rpm, Some(1450));
        assert!((g.fan_percent.unwrap() - 50.2).abs() < 0.1);
    }

    #[test]
    fn other_vendors_and_connectors_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        fake_card(&tmp.path().join("card1/device"));
        fs::create_dir_all(tmp.path().join("card0/device")).unwrap();
        fs::write(tmp.path().join("card0/device/vendor"), "0x10de\n").unwrap(); // NVIDIA: NVML's job
        fs::create_dir_all(tmp.path().join("card1-HDMI-A-1")).unwrap(); // a connector, not a card
        fs::create_dir_all(tmp.path().join("renderD128")).unwrap();
        let cards = find_cards(tmp.path());
        assert_eq!(cards, vec![tmp.path().join("card1/device")]);
        assert!(parse_card(&tmp.path().join("card0/device"), 0).is_none());
    }
}
