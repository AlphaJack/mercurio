//! Event recording for non-HTTP services.
//!
//! A [`Comparator`] scripts the fake peer for a case ([`Comparator::setup`]) and maps what mercurio did on a socket, a local program or a datagram to a list of events ([`Comparator::events`]).
//!
//! - `normalise`: `[[regex, replacement], ...]` at fixture or case level is applied to every string (random nicks, versions, pids).
//! - `ignore: ["events:/0/send", "events:/*/payload"]` masks values at a JSON pointer (`*` = any index/key).

use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::testing::FakeTransport;

/// Events collected by a scripted peer.
pub type Recorder = Arc<Mutex<Vec<Value>>>;
/// Lines or chunks written on one scripted connection.
pub type Log = Arc<Mutex<Vec<String>>>;

/// Everything one case run shares between `setup` and `events`.
#[derive(Debug, Default)]
pub struct Session {
    /// The fake transport the case runs on.
    pub fake: Arc<FakeTransport>,
    /// Events pushed by scripted peers while mercurio talks to them.
    pub events: Recorder,
    /// Per-connection logs (stream services).
    pub logs: Vec<Log>,
    /// Raw bytes written on the scripted connection (binary protocols).
    pub written: Option<Arc<Mutex<Vec<u8>>>>,
}

/// How to replay one family of event fixtures.
#[derive(Debug, Clone, Copy)]
pub struct Comparator {
    /// Fixture `service` ids handled by this comparator.
    pub services: &'static [&'static str],
    /// Script the fake transport (connections, command outputs) for a case.
    pub setup: fn(&mut Session, &Value),
    /// What mercurio did, as events.
    pub events: fn(&Session, &Value) -> Vec<Value>,
    /// Applied to the events (drops values that change between runs).
    pub normalise: fn(Vec<Value>) -> Vec<Value>,
    /// Record events of cases whose delivery fails.
    pub events_on_failure: bool,
}

impl Comparator {
    /// A comparator that records nothing; start from it with `..Comparator::DEFAULT`.
    pub const DEFAULT: Comparator = Comparator {
        services: &[],
        setup: |_, _| {},
        events: |_, _| Vec::new(),
        normalise: |v| v,
        events_on_failure: true,
    };
}

/// Whether a scripted response says `"error": true`.
pub(crate) fn scripted_error(r: &Value) -> bool {
    r.get("error").and_then(Value::as_bool).unwrap_or(false)
}
