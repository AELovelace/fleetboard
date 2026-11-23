//! The limits the audit operations and the Wazuh disk and offline alerts share. They live in the
//! database (`meta`, keys `threshold.<name>`), so the API's *Set threshold* action (a change a
//! person approves in Mnemerynne) can move them without editing files; every change is audited.

use serde::Serialize;

use crate::db::Db;

/// The current limits; `Default` gives the values used until one is set.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Thresholds {
    pub disk_pct: u32,          // a disk this full is "over" (and Wazuh disk_level)
    pub disk_critical_pct: u32, // and this full is critical (Wazuh disk_critical_level)
    pub mem_pct: u32,           // memory used
    pub temp_c: u32,            // the hottest sensor or GPU
    pub offline_minutes: u32,   // silent this long = offline (and Wazuh offline_level)
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            disk_pct: 90,
            disk_critical_pct: 97,
            mem_pct: 90,
            temp_c: 85,
            offline_minutes: 10,
        }
    }
}

/// Every threshold's name and allowed range (inclusive).
pub const RANGES: [(&str, u32, u32); 5] = [
    ("disk_pct", 50, 99),
    ("disk_critical_pct", 50, 100),
    ("mem_pct", 50, 100),
    ("temp_c", 40, 120),
    ("offline_minutes", 1, 1440),
];

impl Thresholds {
    /// The stored values, defaults for any never set (or unreadable).
    pub fn load(db: &Db) -> Self {
        let mut t = Self::default();
        for (name, lo, hi) in RANGES {
            let stored = db
                .get_setting(&format!("threshold.{name}"))
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|v| (lo..=hi).contains(v)); // a hand-edited bad value falls back to the default
            if let Some(v) = stored {
                *t.field(name).expect("a known name") = v;
            }
        }
        t
    }

    fn field(&mut self, name: &str) -> Option<&mut u32> {
        Some(match name {
            "disk_pct" => &mut self.disk_pct,
            "disk_critical_pct" => &mut self.disk_critical_pct,
            "mem_pct" => &mut self.mem_pct,
            "temp_c" => &mut self.temp_c,
            "offline_minutes" => &mut self.offline_minutes,
            _ => return None,
        })
    }

    /// Check a new value: a known name, inside its range, and disk_pct below disk_critical_pct.
    /// Returns the old value and the thresholds with the change made.
    pub fn with(&self, name: &str, value: u32) -> Result<(u32, Self), String> {
        let (_, lo, hi) = RANGES
            .iter()
            .find(|(n, _, _)| *n == name)
            .ok_or_else(|| format!("There's no threshold called {name:?}."))?;
        if !(*lo..=*hi).contains(&value) {
            return Err(format!("{name} must be {lo} to {hi}."));
        }
        let mut next = *self;
        let slot = next.field(name).expect("checked above");
        let old = *slot;
        *slot = value;
        if next.disk_pct >= next.disk_critical_pct {
            return Err(format!(
                "disk_pct ({}) must stay below disk_critical_pct ({}).",
                next.disk_pct, next.disk_critical_pct
            ));
        }
        Ok((old, next))
    }

    /// Store one value (after `with` accepted it).
    pub fn save(db: &Db, name: &str, value: u32) -> rusqlite::Result<()> {
        db.set_setting(&format!("threshold.{name}"), &value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_until_set_then_the_stored_value() {
        let db = Db::in_memory().unwrap();
        assert_eq!(Thresholds::load(&db), Thresholds::default());
        let (old, next) = Thresholds::default().with("disk_pct", 85).unwrap();
        assert_eq!((old, next.disk_pct), (90, 85));
        Thresholds::save(&db, "disk_pct", 85).unwrap();
        assert_eq!(Thresholds::load(&db).disk_pct, 85);
        db.set_setting("threshold.mem_pct", "7000").unwrap(); // out of range: ignored
        assert_eq!(Thresholds::load(&db).mem_pct, 90);
    }

    #[test]
    fn bad_changes_are_refused_in_words() {
        let t = Thresholds::default();
        assert!(t.with("nope", 1).unwrap_err().contains("no threshold"));
        assert!(t.with("temp_c", 500).unwrap_err().contains("40 to 120"));
        assert!(t
            .with("disk_pct", 98)
            .unwrap_err()
            .contains("below disk_critical_pct"));
    }
}
