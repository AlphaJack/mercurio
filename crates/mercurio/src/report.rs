//! [`Report`]: what a `notify` call did, per URL and per attempt.

use std::fmt;
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::plan::{Delivery, Outcome};

/// Overall outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// Everything was delivered.
    Success,
    /// Some deliveries worked, others failed.
    Partial,
    /// Nothing was delivered.
    Failure,
    /// There was nothing to notify.
    NoMatch,
    /// Nothing was delivered and every failure was a timeout.
    Timeout,
}

impl Status {
    /// Lower-case name: `success`, `partial`, `failure`, `nomatch` or `timeout`.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Success => "success",
            Status::Partial => "partial",
            Status::Failure => "failure",
            Status::NoMatch => "nomatch",
            Status::Timeout => "timeout",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One delivery attempt of one URL.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Attempt {
    /// What happened to each target in this attempt.
    pub delivery: Delivery,
    /// Time the attempt took.
    pub elapsed: Duration,
}

impl Attempt {
    pub(crate) fn new(delivery: Delivery, started: Instant) -> Self {
        Self { delivery, elapsed: started.elapsed() }
    }

    /// `Success`, `Partial` (some targets delivered), `Timeout` (every failure timed out) or `Failure`.
    pub fn status(&self) -> Status {
        if self.delivery.is_success() {
            Status::Success
        } else if self.delivery.outcomes.iter().any(|o| o.result.is_ok()) {
            Status::Partial
        } else if self.delivery.errors().all(Error::is_timeout) {
            Status::Timeout
        } else {
            Status::Failure
        }
    }
}

/// Result of [`crate::Mercurio::notify`]: one entry per URL.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Report {
    /// One entry per URL notified, in the order they were added.
    pub entries: Vec<ReportEntry>,
}

/// What happened to one URL.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReportEntry {
    /// Redacted label like `tgram:// (Telegram)`.
    pub label: String,
    /// Service id ([`crate::ServiceDef::id`]), e.g. `"telegram"`.
    pub service: &'static str,
    /// Outcome of the last attempt.
    pub delivery: Delivery,
    /// Every attempt, in order (more than one with `?retry=`).
    pub attempts: Vec<Attempt>,
    /// The URL id naming this target's persistent store.
    pub url_id: Option<String>,
    /// This entry failed, but a later priority group of its tag chain delivered, so the call still succeeds (Apprise's escalation; see [`crate::TagFilter`]).
    pub escalated: bool,
}

impl ReportEntry {
    /// `Success` when the last attempt delivered everything, `Timeout` when attempts only timed out, `Failure` otherwise.
    pub fn status(&self) -> Status {
        if self.delivery.is_success() {
            return Status::Success;
        }
        let timed_out = |a: &Attempt| a.status() == Status::Timeout;
        if self.attempts.last().is_some_and(timed_out) && self.attempts.iter().all(timed_out) {
            Status::Timeout
        } else {
            Status::Failure
        }
    }
}

impl Report {
    /// `true` when every URL delivered (and there was at least one).
    pub fn is_success(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|e| e.delivery.is_success() || e.escalated)
    }

    /// Aggregate status: `Partial` when not everything worked but some attempt delivered something.
    pub fn status(&self) -> Status {
        if self.entries.is_empty() {
            return Status::NoMatch;
        }
        if self.is_success() {
            return Status::Success;
        }
        let some = self
            .entries
            .iter()
            .flat_map(|e| &e.attempts)
            .any(|a| matches!(a.status(), Status::Success | Status::Partial));
        if some {
            Status::Partial
        } else if self.entries.iter().all(|e| e.status() == Status::Timeout) {
            Status::Timeout
        } else {
            Status::Failure
        }
    }

    /// Every failed outcome, with the entry it belongs to.
    pub fn failures(&self) -> impl Iterator<Item = (&ReportEntry, &Outcome)> {
        self.entries.iter().flat_map(|e| e.delivery.outcomes.iter().filter(|o| o.result.is_err()).map(move |o| (e, o)))
    }
}
