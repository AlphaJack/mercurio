//! Helpers shared by SMS services (Twilio, Vonage, Plivo, ...).

use crate::Plan;
use crate::http::Response;
use crate::parse::{PhoneNo, is_phone_no, parse_phone_no};
use crate::url::ParsedUrl;

/// Phone numbers from `?to=` (unquoted) when it is set and non-empty.
pub(crate) fn to_param(u: &ParsedUrl) -> Vec<String> {
    match u.param_nonempty("to") {
        Some(to) => crate::parse::parse_phone_no_unquoted([to], false),
        None => Vec::new(),
    }
}

/// `[is_phone_no(t) for t in parse_phone_no(targets)]`, keeping only valid numbers, paired with the entry they came from.
pub(crate) fn valid_phones(targets: &[String], prefix: bool, min_len: usize) -> Vec<(String, PhoneNo)> {
    parse_phone_no(targets, true, prefix).into_iter().filter_map(|t| is_phone_no(&t, min_len).map(|p| (t, p))).collect()
}

/// `[full ...]` for every valid number in `targets`.
pub(crate) fn full_numbers(targets: &[String]) -> Vec<String> {
    valid_phones(targets, false, 10).into_iter().map(|(_, p)| p.full).collect()
}

/// One plan per target, labelled with the target, all attempted.
pub(crate) fn per_target<T, F>(targets: impl IntoIterator<Item = T>, label: impl Fn(&T) -> String, f: F) -> Plan
where
    F: Fn(&T) -> Plan,
{
    Plan::all(targets.into_iter().map(|t| f(&t).target(label(&t))))
}

/// Success when the status is one of `statuses`.
pub(crate) fn expect(r: &Response, statuses: &[u16]) -> crate::Result<()> {
    if statuses.contains(&r.status) { Ok(()) } else { Err(r.http_error()) }
}

/// A plan that fails without sending anything.
pub(crate) fn no_targets(service: &str) -> Plan {
    Plan::Fail(crate::Error::Message(format!("there are no valid {service} targets to notify")))
}
