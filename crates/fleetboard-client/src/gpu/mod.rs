//! Graphics cards. Each vendor has its own collector behind one trait; `detect` tries them all at
//! start-up and logs one line per outcome, so "why is my GPU missing" is answered by the journal.
//!
//! Collectors (added in milestone M4):
//! * `nvidia`: NVML on both OSes (utilisation, VRAM, temperature, power, fan, clock).
//! * `amd_linux`: the amdgpu driver's sysfs files (no root needed).
//! * `windows_pdh`: Windows performance counters for any vendor (utilisation and VRAM only).

use fleetboard_proto::Gpu;

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
    let found: Vec<Box<dyn GpuCollector>> = Vec::new(); // M4 fills this in vendor by vendor
    if found.is_empty() {
        tracing::info!("no GPU collectors found a card");
    }
    found
}
