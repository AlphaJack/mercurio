//! Gregorian calendar arithmetic shared by the time formats and `Retry-After` dates.

pub(crate) const SECS_PER_DAY: u64 = 86_400;
/// Days in a 400-year Gregorian cycle.
pub(crate) const DAYS_PER_ERA: i64 = 146_097;
/// Days from 0000-03-01 to 1970-01-01: the dates below count from March, so leap days end a year.
pub(crate) const EPOCH_FROM_MARCH: i64 = 719_468;

/// Unix seconds at midnight UTC of `year-month-day` (Howard Hinnant's `days_from_civil`).
pub(crate) fn unix_secs(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * DAYS_PER_ERA + doe - EPOCH_FROM_MARCH) * SECS_PER_DAY as i64
}
