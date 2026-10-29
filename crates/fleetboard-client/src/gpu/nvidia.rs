//! NVIDIA cards through NVML (the library behind nvidia-smi), on Windows and Linux alike. The
//! driver ships `nvml.dll` / `libnvidia-ml.so.1`; when it isn't there `Nvml::init` fails and this
//! collector simply isn't used. Every reading is taken separately so one unsupported query (a card
//! without a fan, say) leaves only that field empty.

use fleetboard_proto::{Gpu, GpuVendor};
use nvml_wrapper::enum_wrappers::device::{Clock, TemperatureSensor};
use nvml_wrapper::Nvml;

use super::GpuCollector;

pub struct NvidiaCollector {
    nvml: Nvml,
    count: u32,
}

impl NvidiaCollector {
    /// Load the driver library; `None` (with the reason logged by the caller) when there is none.
    pub fn new() -> Result<Self, String> {
        let nvml = Nvml::init().map_err(|e| format!("NVML not available ({e})"))?;
        let count = nvml
            .device_count()
            .map_err(|e| format!("NVML: can't count devices ({e})"))?;
        if count == 0 {
            return Err("NVML: no devices".into());
        }
        Ok(Self { nvml, count })
    }

    pub fn device_count(&self) -> u32 {
        self.count
    }
}

impl GpuCollector for NvidiaCollector {
    fn name(&self) -> &'static str {
        "NVML"
    }

    fn collect(&mut self) -> Vec<Gpu> {
        (0..self.count)
            .filter_map(|i| {
                let d = self.nvml.device_by_index(i).ok()?; // a card that vanished is skipped this tick
                let mem = d.memory_info().ok();
                Some(Gpu {
                    index: i as u8,
                    vendor: GpuVendor::Nvidia,
                    name: d.name().unwrap_or_else(|_| "NVIDIA GPU".into()),
                    source: "nvml".into(),
                    util_percent: d.utilization_rates().ok().map(|u| u.gpu as f32),
                    vram_used_bytes: mem.as_ref().map(|m| m.used),
                    vram_total_bytes: mem.as_ref().map(|m| m.total),
                    temp_c: d.temperature(TemperatureSensor::Gpu).ok().map(|t| t as f32),
                    power_w: d.power_usage().ok().map(|mw| mw as f32 / 1000.0), // NVML reports milliwatts
                    fan_percent: d.fan_speed(0).ok().map(|f| f as f32),
                    fan_rpm: None, // NVML gives percent, not rpm
                    clock_mhz: d.clock_info(Clock::Graphics).ok(),
                })
            })
            .collect()
    }
}
