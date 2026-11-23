//! UTC dates without a date library: unix seconds to `2026-11-23T14:05:00Z` and back to a day.
//! The civil-date conversion is Howard Hinnant's `civil_from_days`, exact for the proleptic
//! Gregorian calendar.

/// (year, month 1-12, day 1-31) for a count of days since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468; // shift the epoch to 0000-03-01
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of the 400-year era
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of the era
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of the March-based year
    let mp = (5 * doy + 2) / 153; // March-based month
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `2026-11-23T14:05:00Z` (UTC, whole seconds).
pub fn iso(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// `2026-11-23`, the UTC day a timestamp falls in.
pub fn day(ts: u64) -> String {
    let (y, m, d) = civil_from_days((ts / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z"); // a leap day in a century leap year
        assert_eq!(iso(1_795_446_300), "2026-11-23T15:05:00Z");
        assert_eq!(day(1_795_446_300), "2026-11-23");
        assert_eq!(day(4_107_542_399), "2100-02-28"); // 2100 isn't a leap year
    }
}
