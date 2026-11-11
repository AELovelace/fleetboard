//! Temperature alerts for Wazuh.
//!
//! Every poll, each temperature a host reports (its sensors and its GPUs) is checked against the
//! `[[wazuh.temperature]]` rules in `server.toml`. Each rule says which sensors and hosts it covers
//! and which temperature is which Wazuh alert level. Whenever a sensor's level changes, the server
//! appends one JSON line to `wazuh.log`. The Wazuh agent on this box reads that file
//! (`<log_format>json</log_format>`), and `deploy/wazuh/fleetboard_rules.xml` on the manager turns
//! the line's `fleetboard.level` into an alert of that level.
//!
//! ```toml
//! [wazuh]
//! enabled = true
//! log = "/var/log/fleetboard/wazuh-alerts.json"
//! hysteresis_c = 3        # cool this far below a threshold before the level drops
//! repeat_minutes = 30     # say it again while a sensor stays hot (0 = only on changes)
//! recovered_level = 3     # level of the "back to normal" line (0 = don't send one)
//!
//! [[wazuh.temperature]]   # the first rule that matches a sensor decides its level
//! name = "GPUs"
//! sensors = ["gpu"]       # case-insensitive pieces of the sensor's label; empty = every sensor
//! hosts = []              # names from the Hosts tab or hostnames; empty = every host
//! thresholds = [ { at_c = 85, level = 7 }, { at_c = 95, level = 12 } ]
//!
//! [[wazuh.temperature]]
//! name = "Everything else"
//! thresholds = [ { at_c = 80, level = 5 }, { at_c = 90, level = 10 }, { at_c = 100, level = 12 } ]
//! ```

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::bail;
use fleetboard_proto::Snapshot;
use serde::{Deserialize, Serialize};

use crate::db::Host;

/// The highest level Wazuh knows.
pub const MAX_LEVEL: u8 = 15;

/// The `[wazuh]` section of `server.toml`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WazuhConfig {
    pub enabled: bool,
    pub log: PathBuf,
    pub hysteresis_c: f32,
    pub repeat_minutes: u64,
    pub recovered_level: u8,
    pub max_log_mb: u64, // the file is moved to `<log>.1` past this size; 0 = never
    pub temperature: Vec<TempRule>,
}

/// One set of thresholds and the sensors and hosts it applies to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TempRule {
    pub name: String,
    pub sensors: Vec<String>,
    pub hosts: Vec<String>,
    pub thresholds: Vec<Threshold>,
}

/// From `at_c` degrees up, the sensor is at Wazuh level `level`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    pub at_c: f32,
    pub level: u8,
}

impl Default for WazuhConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log: default_log_path(),
            hysteresis_c: 3.0,
            repeat_minutes: 30,
            recovered_level: 3,
            max_log_mb: 50,
            temperature: vec![TempRule {
                name: "Any sensor".into(),
                sensors: vec![],
                hosts: vec![],
                thresholds: vec![
                    Threshold {
                        at_c: 80.0,
                        level: 5,
                    },
                    Threshold {
                        at_c: 90.0,
                        level: 10,
                    },
                    Threshold {
                        at_c: 100.0,
                        level: 12,
                    },
                ],
            }],
        }
    }
}

fn default_log_path() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Fleetboard")
            .join("logs")
            .join("wazuh-alerts.json")
    } else {
        PathBuf::from("/var/log/fleetboard/wazuh-alerts.json")
    }
}

impl WazuhConfig {
    /// Sort every rule's thresholds, name unnamed rules, and refuse what can't work.
    pub fn normalize(&mut self) -> anyhow::Result<()> {
        if !self.hysteresis_c.is_finite() || self.hysteresis_c < 0.0 {
            bail!("[wazuh] hysteresis_c must be 0 or more");
        }
        if self.recovered_level > MAX_LEVEL {
            bail!("[wazuh] recovered_level must be 0–{MAX_LEVEL}");
        }
        if self.enabled && self.log.as_os_str().is_empty() {
            bail!("[wazuh] log must name a file");
        }
        if self.enabled && self.temperature.is_empty() {
            bail!("[wazuh] is enabled but has no [[wazuh.temperature]] rules");
        }
        for (i, rule) in self.temperature.iter_mut().enumerate() {
            if rule.name.trim().is_empty() {
                rule.name = format!("rule {}", i + 1);
            }
            let name = rule.name.clone();
            if rule.thresholds.is_empty() {
                bail!("[[wazuh.temperature]] {name:?} has no thresholds");
            }
            for t in &rule.thresholds {
                if !t.at_c.is_finite() {
                    bail!("[[wazuh.temperature]] {name:?}: at_c must be a number");
                }
                if t.level == 0 || t.level > MAX_LEVEL {
                    bail!(
                        "[[wazuh.temperature]] {name:?}: level {} isn't 1–{MAX_LEVEL}",
                        t.level
                    );
                }
            }
            rule.thresholds.sort_by(|a, b| a.at_c.total_cmp(&b.at_c));
            if rule.thresholds.windows(2).any(|w| w[0].at_c == w[1].at_c) {
                bail!("[[wazuh.temperature]] {name:?} has two thresholds at the same temperature");
            }
            for s in rule.sensors.iter_mut().chain(rule.hosts.iter_mut()) {
                *s = s.trim().to_lowercase();
            }
            rule.sensors.retain(|s| !s.is_empty());
            rule.hosts.retain(|s| !s.is_empty());
        }
        Ok(())
    }

    /// One line for `check-config`.
    pub fn summary(&self) -> String {
        if !self.enabled {
            return "wazuh alerts off".into();
        }
        let rules: Vec<String> = self
            .temperature
            .iter()
            .map(|r| {
                let t: Vec<String> = r
                    .thresholds
                    .iter()
                    .map(|t| format!("{}°C→{}", t.at_c, t.level))
                    .collect();
                format!("{} [{}]", r.name, t.join(", "))
            })
            .collect();
        format!(
            "wazuh alerts to {}: {}",
            self.log.display(),
            rules.join("; ")
        )
    }
}

/// One temperature from a snapshot, with the label the rules match against.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub sensor: String,
    pub celsius: f32,
}

/// Every temperature in a snapshot: the sensors, then each GPU as "GPU <index> <name>".
pub fn readings(snap: &Snapshot) -> Vec<Reading> {
    let sensors = snap.temperatures.iter().map(|t| Reading {
        sensor: t.label.clone(),
        celsius: t.celsius,
    });
    let gpus = snap.gpus.iter().filter_map(|g| {
        g.temp_c.map(|c| Reading {
            sensor: format!("GPU {} {}", g.index, g.name),
            celsius: c,
        })
    });
    sensors
        .chain(gpus)
        .filter(|r| r.celsius.is_finite())
        .collect()
}

/// What the server remembers about one sensor of one host.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SensorState {
    step: Option<usize>, // index into the rule's thresholds; None = below them all
    rule: usize,
    last_sent: u64,
}

/// A host's sensors, keyed by label.
pub type HostAlerts = HashMap<String, SensorState>;

/// One line of the alert file.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct AlertLine {
    pub fleetboard: AlertBody,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct AlertBody {
    pub event: &'static str, // "temperature"
    pub state: &'static str, // "raised", "lowered", "ongoing" or "recovered"
    pub level: u8,           // the Wazuh level the manager's rules give this line
    pub previous_level: u8,  // 0 = it wasn't alerting
    pub host: String,
    pub address: String,
    pub hostname: String,
    pub sensor: String,
    pub celsius: f32,
    pub threshold_c: Option<f32>, // the threshold now reached; None once recovered
    pub rule: String,
    pub ts: u64, // the server's unix seconds
}

impl WazuhConfig {
    /// The first rule that covers this sensor on this host.
    fn rule_for(&self, host: &Host, hostname: &str, sensor: &str) -> Option<usize> {
        let sensor = sensor.to_lowercase();
        let (name, hostname) = (host.name.to_lowercase(), hostname.to_lowercase());
        self.temperature.iter().position(|r| {
            (r.hosts.is_empty() || r.hosts.iter().any(|h| *h == name || *h == hostname))
                && (r.sensors.is_empty() || r.sensors.iter().any(|s| sensor.contains(s)))
        })
    }

    /// Check one snapshot against the rules and say what changed. `alerts` is this host's memory.
    pub fn evaluate(
        &self,
        host: &Host,
        snap: &Snapshot,
        alerts: &mut HostAlerts,
        now: u64,
    ) -> Vec<AlertLine> {
        let mut out = Vec::new();
        for r in readings(snap) {
            let Some(rule_i) = self.rule_for(host, &snap.host.hostname, &r.sensor) else {
                alerts.remove(&r.sensor);
                continue;
            };
            let rule = &self.temperature[rule_i];
            let st = alerts.entry(r.sensor.clone()).or_default();
            let cur = if st.rule == rule_i { st.step } else { None };
            // At or below the current step a level holds until the sensor has cooled by the
            // hysteresis; above it the plain threshold applies.
            let new = (0..rule.thresholds.len()).rev().find(|&i| {
                let slack = if cur.is_some_and(|c| i <= c) {
                    self.hysteresis_c
                } else {
                    0.0
                };
                r.celsius >= rule.thresholds[i].at_c - slack
            });
            let level_of = |s: Option<usize>| s.map_or(0, |i| rule.thresholds[i].level);
            let state = match (cur, new) {
                (c, n) if c == n => {
                    let repeat = self.repeat_minutes.saturating_mul(60);
                    if n.is_some() && repeat > 0 && now.saturating_sub(st.last_sent) >= repeat {
                        Some("ongoing")
                    } else {
                        None
                    }
                }
                (_, None) => Some("recovered"),
                (c, n) if n > c => Some("raised"),
                _ => Some("lowered"),
            };
            let previous_level = level_of(cur);
            st.step = new;
            st.rule = rule_i;
            let Some(state) = state else { continue };
            st.last_sent = now;
            let level = if new.is_some() {
                level_of(new)
            } else {
                self.recovered_level
            };
            if level == 0 {
                continue;
            }
            out.push(AlertLine {
                fleetboard: AlertBody {
                    event: "temperature",
                    state,
                    level,
                    previous_level,
                    host: host.name.clone(),
                    address: host.address.clone(),
                    hostname: snap.host.hostname.clone(),
                    sensor: r.sensor,
                    celsius: (r.celsius * 10.0).round() / 10.0,
                    threshold_c: new.map(|i| rule.thresholds[i].at_c),
                    rule: rule.name.clone(),
                    ts: now,
                },
            });
        }
        out
    }
}

/// Appends alert lines to the file the Wazuh agent reads.
pub struct AlertLog {
    path: PathBuf,
    max_bytes: u64,
    failing: AtomicBool, // so a broken path is logged once, not every poll
    write_lock: Mutex<()>,
}

impl AlertLog {
    pub fn new(cfg: &WazuhConfig) -> Self {
        Self {
            path: cfg.log.clone(),
            max_bytes: cfg.max_log_mb.saturating_mul(1024 * 1024),
            failing: AtomicBool::new(false),
            write_lock: Mutex::new(()),
        }
    }

    /// Write the lines (and log each one); errors are logged, never returned.
    pub fn write(&self, lines: &[AlertLine]) {
        if lines.is_empty() {
            return;
        }
        for l in lines {
            let b = &l.fleetboard;
            tracing::info!(
                "Wazuh level {} ({}): {} {} at {}°C",
                b.level,
                b.state,
                b.host,
                b.sensor,
                b.celsius
            );
        }
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        match self.append(lines) {
            Ok(()) => {
                if self.failing.swap(false, Ordering::Relaxed) {
                    tracing::info!("Wazuh alert file {} is writable again", self.path.display());
                }
            }
            Err(e) => {
                if !self.failing.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "can't write the Wazuh alert file {}: {e}",
                        self.path.display()
                    );
                }
            }
        }
    }

    fn append(&self, lines: &[AlertLine]) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        if self.max_bytes > 0 {
            if let Ok(meta) = std::fs::metadata(&self.path) {
                if meta.len() >= self.max_bytes {
                    let mut old = self.path.clone().into_os_string();
                    old.push(".1");
                    std::fs::rename(&self.path, old)?; // the agent notices and reopens
                }
            }
        }
        let mut text = String::new();
        for l in lines {
            text.push_str(&serde_json::to_string(l).map_err(std::io::Error::other)?);
            text.push('\n');
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetboard_proto::{Gpu, GpuVendor, Temperature};

    fn host() -> Host {
        Host {
            id: 1,
            name: "RDS 1".into(),
            address: "10.0.0.5".into(),
            enabled: true,
        }
    }

    fn snap(cpu: f32, gpu: Option<f32>) -> Snapshot {
        Snapshot {
            schema: fleetboard_proto::SCHEMA,
            taken_at: 0,
            host: fleetboard_proto::HostFacts {
                hostname: "rds1".into(),
                ..Default::default()
            },
            cpu: Default::default(),
            memory: Default::default(),
            disks: vec![],
            network: vec![],
            gpus: gpu
                .map(|t| Gpu {
                    index: 0,
                    vendor: GpuVendor::Nvidia,
                    name: "GTX 1050 Ti".into(),
                    source: "nvml".into(),
                    util_percent: None,
                    vram_used_bytes: None,
                    vram_total_bytes: None,
                    temp_c: Some(t),
                    power_w: None,
                    fan_percent: None,
                    fan_rpm: None,
                    clock_mhz: None,
                })
                .into_iter()
                .collect(),
            temperatures: vec![Temperature {
                label: "k10temp Tctl".into(),
                celsius: cpu,
                max_c: None,
            }],
        }
    }

    fn cfg(text: &str) -> WazuhConfig {
        let mut c: WazuhConfig = toml::from_str(text).unwrap();
        c.normalize().unwrap();
        c
    }

    const TWO_RULES: &str = r#"
        enabled = true
        repeat_minutes = 0
        [[temperature]]
        name = "GPUs"
        sensors = ["GPU"]
        thresholds = [ { at_c = 95, level = 12 }, { at_c = 85, level = 7 } ]
        [[temperature]]
        name = "rest"
        thresholds = [ { at_c = 70, level = 5 }, { at_c = 85, level = 10 } ]
    "#;

    /// (sensor, state, level) of each line.
    fn short(lines: &[AlertLine]) -> Vec<(String, &'static str, u8)> {
        lines
            .iter()
            .map(|l| {
                (
                    l.fleetboard.sensor.clone(),
                    l.fleetboard.state,
                    l.fleetboard.level,
                )
            })
            .collect()
    }

    #[test]
    fn each_sensor_takes_the_level_of_the_first_matching_rule() {
        let c = cfg(TWO_RULES);
        let mut a = HostAlerts::new();
        // CPU 86 → "rest" 85 → 10; GPU 86 → "GPUs" 85 → 7 (the GPU rule wins over "rest").
        let out = c.evaluate(&host(), &snap(86.0, Some(86.0)), &mut a, 100);
        assert_eq!(
            short(&out),
            vec![
                ("k10temp Tctl".into(), "raised", 10),
                ("GPU 0 GTX 1050 Ti".into(), "raised", 7)
            ]
        );
        assert_eq!(out[1].fleetboard.rule, "GPUs");
        assert_eq!(out[1].fleetboard.threshold_c, Some(85.0));
        // Nothing changed: nothing is said again.
        assert!(c
            .evaluate(&host(), &snap(86.5, Some(87.0)), &mut a, 102)
            .is_empty());
    }

    #[test]
    fn levels_drop_only_after_cooling_by_the_hysteresis_and_recovery_is_reported() {
        let c = cfg(TWO_RULES); // hysteresis 3 by default, recovered_level 3
        let mut a = HostAlerts::new();
        let h = host();
        assert_eq!(
            short(&c.evaluate(&h, &snap(88.0, None), &mut a, 0))[0].2,
            10
        );
        assert!(c.evaluate(&h, &snap(83.0, None), &mut a, 2).is_empty()); // 85 - 3 = 82 still holds
        let out = c.evaluate(&h, &snap(81.0, None), &mut a, 4);
        assert_eq!(short(&out), vec![("k10temp Tctl".into(), "lowered", 5)]);
        assert_eq!(out[0].fleetboard.previous_level, 10);
        assert!(c.evaluate(&h, &snap(68.0, None), &mut a, 6).is_empty()); // 70 - 3 = 67
        let out = c.evaluate(&h, &snap(66.0, None), &mut a, 8);
        assert_eq!(short(&out), vec![("k10temp Tctl".into(), "recovered", 3)]);
        assert_eq!(out[0].fleetboard.threshold_c, None);
        // Rising again uses the plain threshold, not the lowered one.
        assert!(c.evaluate(&h, &snap(69.0, None), &mut a, 10).is_empty());
        assert_eq!(
            short(&c.evaluate(&h, &snap(70.0, None), &mut a, 12))[0].1,
            "raised"
        );
    }

    #[test]
    fn a_jump_past_several_thresholds_is_one_line_and_hot_sensors_repeat() {
        let mut c = cfg(TWO_RULES);
        c.repeat_minutes = 1;
        c.recovered_level = 0;
        let mut a = HostAlerts::new();
        let h = host();
        assert_eq!(short(&c.evaluate(&h, &snap(20.0, None), &mut a, 0)), vec![]);
        assert_eq!(
            short(&c.evaluate(&h, &snap(99.0, None), &mut a, 1)),
            vec![("k10temp Tctl".into(), "raised", 10)]
        );
        assert!(c.evaluate(&h, &snap(99.0, None), &mut a, 60).is_empty());
        assert_eq!(
            short(&c.evaluate(&h, &snap(99.0, None), &mut a, 61))[0].1,
            "ongoing"
        );
        // recovered_level = 0: cooling down says nothing.
        assert!(c.evaluate(&h, &snap(20.0, None), &mut a, 62).is_empty());
    }

    #[test]
    fn rules_can_be_limited_to_hosts_by_name_or_hostname() {
        let c = cfg(r#"
            enabled = true
            [[temperature]]
            hosts = ["NAS"]
            thresholds = [ { at_c = 40, level = 9 } ]
            [[temperature]]
            hosts = ["RDS1"]
            thresholds = [ { at_c = 50, level = 4 } ]
        "#);
        let mut a = HostAlerts::new();
        let out = c.evaluate(&host(), &snap(55.0, None), &mut a, 0);
        assert_eq!(short(&out), vec![("k10temp Tctl".into(), "raised", 4)]);
        assert_eq!(out[0].fleetboard.rule, "rule 2");
        let mut other = host();
        other.name = "Desk".into();
        let mut s = snap(99.0, None);
        s.host.hostname = "desk".into();
        assert!(c.evaluate(&other, &s, &mut HostAlerts::new(), 0).is_empty()); // no rule covers it
    }

    #[test]
    fn bad_rules_are_refused_in_words() {
        for (text, needle) in [
            ("[[temperature]]\nthresholds = []", "no thresholds"),
            ("[[temperature]]\nthresholds = [{ at_c = 80, level = 16 }]", "level 16"),
            ("[[temperature]]\nthresholds = [{ at_c = 80, level = 0 }]", "level 0"),
            (
                "[[temperature]]\nthresholds = [{ at_c = 80, level = 3 }, { at_c = 80, level = 5 }]",
                "same temperature",
            ),
            ("hysteresis_c = -1", "hysteresis"),
        ] {
            let mut c: WazuhConfig = toml::from_str(text).unwrap();
            let err = c.normalize().unwrap_err().to_string();
            assert!(err.contains(needle), "{text}: {err}");
        }
        // A typo is an error, not a silently ignored key.
        assert!(toml::from_str::<WazuhConfig>("[[temperature]]\nlevels = []").is_err());
    }

    #[test]
    fn the_file_gets_one_json_line_per_alert_and_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(TWO_RULES);
        c.log = dir.path().join("sub").join("alerts.json");
        c.max_log_mb = 0;
        let log = AlertLog::new(&c);
        let lines = c.evaluate(&host(), &snap(90.0, Some(96.0)), &mut HostAlerts::new(), 7);
        log.write(&lines);
        let text = std::fs::read_to_string(&c.log).unwrap();
        let parsed: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1]["fleetboard"]["level"], 12);
        assert_eq!(parsed[1]["fleetboard"]["event"], "temperature");
        assert_eq!(parsed[1]["fleetboard"]["host"], "RDS 1");

        let log = AlertLog {
            max_bytes: 1,
            ..AlertLog::new(&c)
        };
        log.write(&lines[..1]);
        assert_eq!(std::fs::read_to_string(&c.log).unwrap().lines().count(), 1);
        assert!(dir.path().join("sub").join("alerts.json.1").exists());
    }
}
