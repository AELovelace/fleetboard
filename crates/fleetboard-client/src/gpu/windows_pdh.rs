//! Any GPU on Windows through the system's own performance counters, the same numbers Task
//! Manager shows: `\GPU Engine(*)\Utilization Percentage` and `\GPU Adapter Memory(*)\Dedicated
//! Usage`. DXGI supplies each adapter's name, vendor, total VRAM and LUID, which is how counter
//! instances (`pid_1234_luid_0x00000000_0x0000C3A1_phys_0_eng_0_engtype_3D`) are matched to cards.
//!
//! This is the AMD and Intel path on Windows (no temperature, power or fan: those need vendor SDKs).
//! NVIDIA adapters are skipped when NVML already reported them, so a card is never listed twice.

use std::collections::HashMap;

use fleetboard_proto::{Gpu, GpuVendor};
use windows::core::{w, PCWSTR};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE,
};
use windows::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW,
    PdhOpenQueryW, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_MORE_DATA,
};

use super::GpuCollector;

const VENDOR_AMD: u32 = 0x1002;
const VENDOR_NVIDIA: u32 = 0x10de;
const VENDOR_INTEL: u32 = 0x8086;
const VENDOR_MICROSOFT: u32 = 0x1414; // the Basic Render Driver (WARP)

/// One adapter as DXGI describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Adapter {
    pub luid: (i32, u32), // (HighPart, LowPart), the key the counters use
    pub name: String,
    pub vendor_id: u32,
    pub vram_total: u64,
}

/// What one counter instance name says: which adapter, which engine type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub luid: (i32, u32),
    pub engtype: String,
}

/// `pid_1234_luid_0x00000000_0x0000C3A1_phys_0_eng_0_engtype_3D` -> luid (0, 0xC3A1), "3D".
/// Memory counters have no `engtype` part; they end with `_phys_0`.
pub fn parse_instance(name: &str) -> Option<Instance> {
    // Engine instances read "pid_…_luid_…", memory instances start with "luid_…" directly.
    let at = name.find("luid_")?;
    let rest = &name[at + "luid_".len()..];
    let mut parts = rest.split('_');
    let high = parts.next()?.trim_start_matches("0x");
    let low = parts.next()?.trim_start_matches("0x");
    let high = i32::from_str_radix(high, 16).ok()?;
    let low = u32::from_str_radix(low, 16).ok()?;
    let engtype = name.split("_engtype_").nth(1).unwrap_or("").to_string();
    Some(Instance {
        luid: (high, low),
        engtype,
    })
}

/// Sum 3D-engine utilisation per adapter (capped at 100), and memory per adapter.
pub fn fold(
    util: &[(Instance, f64)],
    memory: &[(Instance, f64)],
) -> HashMap<(i32, u32), (Option<f32>, Option<u64>)> {
    let mut out: HashMap<(i32, u32), (Option<f32>, Option<u64>)> = HashMap::new();
    for (inst, v) in util {
        if inst.engtype != "3D" {
            continue; // copy/video engines would double count
        }
        let e = out.entry(inst.luid).or_default();
        e.0 = Some((e.0.unwrap_or(0.0) + *v as f32).min(100.0));
    }
    for (inst, v) in memory {
        let e = out.entry(inst.luid).or_default();
        e.1 = Some(e.1.unwrap_or(0) + *v as u64);
    }
    out
}

/// The adapters DXGI knows, minus software renderers.
pub fn adapters() -> Vec<Adapter> {
    let mut out = Vec::new();
    // SAFETY: plain COM calls; every handle is owned by the returned smart pointers.
    unsafe {
        let Ok(factory) = CreateDXGIFactory1::<IDXGIFactory1>() else {
            return out;
        };
        let mut i = 0;
        while let Ok(adapter) = factory.EnumAdapters1(i) {
            i += 1;
            let Ok(desc) = adapter.GetDesc1() else {
                continue;
            };
            let len = desc
                .Description
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(desc.Description.len());
            let name = String::from_utf16_lossy(&desc.Description[..len])
                .trim()
                .to_string();
            // Microsoft's software renderer: flagged on most machines, but a headless server can list
            // "Microsoft Basic Render Driver" without the flag, so the vendor id and name are checked too.
            if desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 != 0
                || desc.VendorId == VENDOR_MICROSOFT
                || name.contains("Basic Render")
            {
                continue;
            }
            out.push(Adapter {
                luid: (desc.AdapterLuid.HighPart, desc.AdapterLuid.LowPart),
                name,
                vendor_id: desc.VendorId,
                vram_total: desc.DedicatedVideoMemory as u64,
            });
        }
    }
    out
}

pub struct PdhCollector {
    query: isize,
    util: isize,
    memory: isize,
    adapters: Vec<Adapter>,
}

// SAFETY: PDH handles may be used from any one thread at a time; the sampler owns this collector.
unsafe impl Send for PdhCollector {}

impl PdhCollector {
    /// Open the query. `skip_nvidia` when NVML already covers those cards.
    pub fn new(skip_nvidia: bool) -> Result<Self, String> {
        let adapters: Vec<Adapter> = adapters()
            .into_iter()
            .filter(|a| !(skip_nvidia && a.vendor_id == VENDOR_NVIDIA))
            .collect();
        if adapters.is_empty() {
            return Err("no adapters left for the performance counters".into());
        }
        let mut query = 0isize;
        let mut util = 0isize;
        let mut memory = 0isize;
        // SAFETY: documented PDH calls with valid out-pointers; the query is closed in Drop.
        unsafe {
            if PdhOpenQueryW(PCWSTR::null(), 0, &mut query) != 0 {
                return Err("PdhOpenQuery failed".into());
            }
            if PdhAddEnglishCounterW(
                query,
                w!("\\GPU Engine(*)\\Utilization Percentage"),
                0,
                &mut util,
            ) != 0
            {
                PdhCloseQuery(query);
                return Err("the GPU Engine counter isn't available".into());
            }
            if PdhAddEnglishCounterW(
                query,
                w!("\\GPU Adapter Memory(*)\\Dedicated Usage"),
                0,
                &mut memory,
            ) != 0
            {
                PdhCloseQuery(query);
                return Err("the GPU Adapter Memory counter isn't available".into());
            }
            PdhCollectQueryData(query); // utilisation is a rate: it needs a first sample to compare with
        }
        Ok(Self {
            query,
            util,
            memory,
            adapters,
        })
    }

    pub fn adapter_count(&self) -> usize {
        self.adapters.len()
    }

    /// Every instance of one counter as (parsed name, value).
    fn read(&self, counter: isize) -> Vec<(Instance, f64)> {
        let mut size = 0u32;
        let mut count = 0u32;
        // SAFETY: the two-call pattern PDH documents: ask for the size, then fill a buffer of it.
        unsafe {
            let status =
                PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &mut size, &mut count, None);
            if status != PDH_MORE_DATA || size == 0 {
                return Vec::new();
            }
            let mut buf = vec![0u8; size as usize];
            let items = buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;
            if PdhGetFormattedCounterArrayW(
                counter,
                PDH_FMT_DOUBLE,
                &mut size,
                &mut count,
                Some(items),
            ) != 0
            {
                return Vec::new();
            }
            (0..count as usize)
                .filter_map(|i| {
                    let item = &*items.add(i);
                    let name = item.szName.to_string().ok()?;
                    let inst = parse_instance(&name)?;
                    Some((inst, item.FmtValue.Anonymous.doubleValue))
                })
                .collect()
        }
    }
}

impl Drop for PdhCollector {
    fn drop(&mut self) {
        // SAFETY: closing the query we opened; the handle is not used afterwards.
        unsafe {
            PdhCloseQuery(self.query);
        }
    }
}

impl GpuCollector for PdhCollector {
    fn name(&self) -> &'static str {
        "Windows performance counters"
    }

    fn collect(&mut self) -> Vec<Gpu> {
        // SAFETY: a documented PDH call on our open query.
        unsafe {
            PdhCollectQueryData(self.query);
        }
        let folded = fold(&self.read(self.util), &self.read(self.memory));
        self.adapters
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let (util, used) = folded.get(&a.luid).copied().unwrap_or((Some(0.0), None));
                Gpu {
                    index: i as u8,
                    vendor: match a.vendor_id {
                        VENDOR_AMD => GpuVendor::Amd,
                        VENDOR_NVIDIA => GpuVendor::Nvidia,
                        VENDOR_INTEL => GpuVendor::Intel,
                        _ => GpuVendor::Other,
                    },
                    name: a.name.clone(),
                    source: "pdh".into(),
                    util_percent: util,
                    vram_used_bytes: used,
                    vram_total_bytes: (a.vram_total > 0).then_some(a.vram_total),
                    temp_c: None,
                    power_w: None,
                    fan_percent: None,
                    fan_rpm: None,
                    clock_mhz: None,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_are_parsed() {
        let i =
            parse_instance("pid_1234_luid_0x00000000_0x0000C3A1_phys_0_eng_0_engtype_3D").unwrap();
        assert_eq!(
            i,
            Instance {
                luid: (0, 0xC3A1),
                engtype: "3D".into()
            }
        );
        let m = parse_instance("luid_0x00000000_0x0000C3A1_phys_0").unwrap();
        assert_eq!((m.luid, m.engtype.as_str()), ((0, 0xC3A1), ""));
        assert!(parse_instance("nonsense").is_none());
    }

    #[test]
    fn utilisation_sums_3d_engines_per_adapter_and_caps_at_100() {
        let inst = |e: &str| Instance {
            luid: (0, 1),
            engtype: e.into(),
        };
        let util = vec![(inst("3D"), 60.0), (inst("3D"), 55.0), (inst("Copy"), 90.0)];
        let mem = vec![
            (
                Instance {
                    luid: (0, 1),
                    engtype: "".into(),
                },
                1024.0,
            ),
            (
                Instance {
                    luid: (0, 1),
                    engtype: "".into(),
                },
                1024.0,
            ),
        ];
        let f = fold(&util, &mem);
        assert_eq!(f[&(0, 1)], (Some(100.0), Some(2048)));
    }

    #[test]
    fn the_counters_read_every_adapter_on_this_machine() {
        // A CI runner has only the software renderer, so "no adapters" is a fine outcome too.
        let Ok(mut c) = PdhCollector::new(false) else {
            return;
        };
        std::thread::sleep(std::time::Duration::from_millis(600)); // rates need two samples a moment apart
        let gpus = c.collect();
        assert_eq!(gpus.len(), c.adapter_count());
        for g in &gpus {
            assert_eq!(g.source, "pdh");
            assert!(
                g.util_percent.is_none_or(|u| (0.0..=100.0).contains(&u)),
                "{g:?}"
            );
        }
    }

    #[test]
    fn this_machine_lists_its_adapters() {
        // Runs on any Windows box with a display adapter; software renderers are skipped.
        let list = adapters();
        assert!(list.iter().all(|a| !a.name.contains("Basic Render")));
    }
}
