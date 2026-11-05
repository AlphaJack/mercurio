//! Helpers shared by SMS services (Twilio, Vonage, Plivo, ...).

use crate::Plan;
use crate::service::Param;
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

/// The `{targets}` path token of SMS services: phone numbers separated by `/`.
pub(crate) const PHONE_TARGETS: Param = Param::new("targets", "Targets").list("/").required().group(&["target_phone"]);

/// `[+full ...]` for every valid number in `targets`.
pub(crate) fn plus_numbers(targets: &[String]) -> Vec<String> {
    full_numbers(targets).into_iter().map(|n| format!("+{n}")).collect()
}

/// The valid numbers in `targets`, each keeping the `+` it was written with.
pub(crate) fn numbers_keeping_plus(targets: &[String]) -> Vec<String> {
    parse_phone_no(targets, true, false)
        .into_iter()
        .filter_map(|t| {
            let p = is_phone_no(&t, 10)?;
            Some(if t.trim_start().starts_with('+') { format!("+{}", p.full) } else { p.full })
        })
        .collect()
}

/// `targets` in groups of `size` (one each without `?batch=yes`).
pub(crate) fn batches(targets: &[String], size: usize) -> Vec<Vec<String>> {
    targets.chunks(size).map(<[String]>::to_vec).collect()
}

/// One plan per target, labelled with the target, all attempted.
pub(crate) fn per_target<T, F>(targets: impl IntoIterator<Item = T>, label: impl Fn(&T) -> String, f: F) -> Plan
where
    F: Fn(&T) -> Plan,
{
    Plan::all(targets.into_iter().map(|t| f(&t).target(label(&t))))
}

/// A plan that fails without sending anything.
pub(crate) fn no_targets(service: &str) -> Plan {
    Plan::Fail(crate::Error::Message(format!("there are no valid {service} targets to notify")))
}
