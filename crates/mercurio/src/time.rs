//! Unix time and the UTC date formats services send (RFC 3339, RFC 2822, AWS and syslog stamps), without a date crate.

/// Unix time in seconds.
pub fn unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Unix time in milliseconds.
pub fn unix_time_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

const SECS_PER_DAY: u64 = 86_400;
/// Days in a 400-year Gregorian cycle.
const DAYS_PER_ERA: i64 = 146_097;
/// Days from 0000-03-01 to 1970-01-01: the dates below count from March, so leap days end a year.
const EPOCH_FROM_MARCH: i64 = 719_468;

/// Unix seconds at midnight UTC of `year-month-day` (Howard Hinnant's `days_from_civil`).
pub fn unix_secs(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * DAYS_PER_ERA + doe - EPOCH_FROM_MARCH) * SECS_PER_DAY as i64
}

/// UTC timestamp parts `(year, month, day, hour, minute, second)` for `secs` (Howard Hinnant's `civil_from_days`).
pub fn utc_parts(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / SECS_PER_DAY) as i64;
    let rem = secs % SECS_PER_DAY;
    let z = days + EPOCH_FROM_MARCH;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z.rem_euclid(DAYS_PER_ERA);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
}

/// RFC 3339 / ISO 8601 UTC timestamp, e.g. `2026-10-16T12:00:00Z`.
pub fn iso8601_utc(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// RFC 2822 date, e.g. `Fri, 16 Oct 2026 12:00:00 +0000`.
pub fn rfc2822_utc(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(secs);
    let days = (secs / SECS_PER_DAY) as i64;
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(mo - 1) as usize];
    format!("{wd}, {d:02} {mon} {y:04} {h:02}:{mi:02}:{s:02} +0000")
}

/// Unix seconds of an RFC 3339 time (`2026-10-20T17:00:00.000Z`, `...+02:00`); `None` when it is not one.
pub fn parse_rfc3339(s: &str) -> Option<f64> {
    let c = crate::regex!(
        r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:([Zz])|([+-])(\d{2}):?(\d{2}))$"
    )
    .captures(s.trim())?;
    let n = |i: usize| c.get(i).and_then(|m| m.as_str().parse::<i64>().ok());
    let (month, day, hour, min, sec) = (n(2)?, n(3)?, n(4)?, n(5)?, n(6)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let frac = c.get(7).and_then(|m| m.as_str().parse::<f64>().ok()).unwrap_or(0.0);
    let offset = match c.get(9).map(|m| m.as_str()) {
        Some(sign) => {
            let o = n(10)? * 3600 + n(11)? * 60;
            if sign == "-" { -o } else { o }
        }
        None => 0,
    };
    let secs = unix_secs(n(1)?, month, day) + hour * 3600 + min * 60 + sec - offset;
    Some(secs as f64 + frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0.0));
        assert_eq!(parse_rfc3339("2026-10-16T12:00:00.500Z"), Some(1_792_152_000.5));
        assert_eq!(parse_rfc3339("2026-10-16T14:00:00+02:00"), Some(1_792_152_000.0));
        assert_eq!(parse_rfc3339("300"), None);
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn dates() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_792_152_000), "2026-10-16T12:00:00Z");
        assert_eq!(iso8601_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc2822_utc(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn unix_secs_round_trips_utc_parts() {
        let secs = unix_secs(2026, 10, 16);
        assert_eq!(utc_parts(secs as u64), (2026, 10, 16, 0, 0, 0));
    }
}
