//! Graphics cards. Each vendor has its own collector behind one trait; `detect` tries them all at
//! start-up and logs one line per outcome, so "why is my GPU missing" is answered by the journal.
//!
//! * `nvidia`: NVML on both OSes (utilisation, VRAM, temperature, power, fan, clock).
//! * `amd_linux`: the amdgpu driver's sysfs files (no root needed).
//! * Windows performance counters for AMD and Intel: milestone M4, part three.

use fleetboard_proto::Gpu;

pub mod nvidia;

#[cfg(target_os = "linux")]
pub mod amd_linux;

#[cfg(windows)]
pub mod windows_pdh;

/// One source of GPU readings.
pub trait GpuCollector: Send {
    /// A short name for the log line, e.g. "NVML".
    fn name(&self) -> &'static str;
    /// Read every card this collector knows; failures become `None` fields, never a panic.
    fn collect(&mut self) -> Vec<Gpu>;
}

/// Try every collector this build knows and keep the ones that found a card.
pub fn detect(enabled: bool) -> Vec<Box<dyn GpuCollector>> {
    if !enabled {
        tracing::info!("GPU collection is off in the config");
        return Vec::new();
    }
    let mut found: Vec<Box<dyn GpuCollector>> = Vec::new();
    let mut have_nvml = false;
    match nvidia::NvidiaCollector::new() {
        Ok(c) => {
            tracing::info!("NVIDIA: {} device(s) via NVML", c.device_count());
            found.push(Box::new(c));
            have_nvml = true;
        }
        Err(why) => tracing::info!("NVIDIA: {why}"),
    }
    #[cfg(windows)]
    match windows_pdh::PdhCollector::new(have_nvml) {
        Ok(c) => {
            tracing::info!(
                "Windows counters: {} adapter(s) via PDH/DXGI",
                c.adapter_count()
            );
            found.push(Box::new(c));
        }
        Err(why) => tracing::info!("Windows counters: {why}"),
    }
    #[cfg(not(windows))]
    let _ = have_nvml;
    #[cfg(target_os = "linux")]
    match amd_linux::AmdCollector::new() {
        Some(c) => {
            tracing::info!("AMD: {} card(s) via amdgpu sysfs", c.card_count());
            found.push(Box::new(c));
        }
        None => tracing::info!("AMD: no amdgpu cards in /sys/class/drm"),
    }
    if found.is_empty() {
        tracing::info!("no GPU collectors found a card");
    }
    found
}

/// Give every card a unique index across collectors (NVML cards first, then AMD).
pub fn renumber(gpus: &mut [Gpu]) {
    for (i, g) in gpus.iter_mut().enumerate() {
        g.index = i as u8;
    }
}
