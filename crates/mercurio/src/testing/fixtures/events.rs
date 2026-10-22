//! Event recording for non-HTTP services.
//!
//! A [`Comparator`] scripts the fake peer for a case ([`Comparator::setup`]) and maps what mercurio did on a socket, a local program or a datagram to a list of events ([`Comparator::events`]).
//!
//! - `normalise`: `[[regex, replacement], ...]` at fixture or case level is applied to every string (random nicks, versions, pids).
//! - `ignore: ["events:/0/send", "events:/*/payload"]` masks values at a JSON pointer (`*` = any index/key).

use std::sync::{Arc, Mutex};

use regex::Regex;
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

const BUILTIN: &[Comparator] = &[
    super::socket::SMTP,
    super::socket::SMPP,
    super::stream::LINES,
    super::stream::MQTT,
    super::stream::SYSLOG,
    super::stream::RSYSLOG,
    super::desktop::MACOSX,
    super::desktop::DBUS,
    super::desktop::GNOME,
    super::desktop::WINDOWS,
    super::desktop::BLINK1,
    super::desktop::XMPP,
];

/// The comparator for a fixture's `service`, if it records events.
pub fn comparator(service: &str) -> Option<&'static Comparator> {
    BUILTIN.iter().find(|c| c.services.contains(&service))
}

fn rules_of(v: Option<&Value>) -> Vec<(Regex, String)> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|r| Some((Regex::new(r[0].as_str()?).ok()?, r[1].as_str().unwrap_or("").to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn normalise_strings(v: &mut Value, rules: &[(Regex, String)]) {
    match v {
        Value::String(s) => {
            for (re, rep) in rules {
                *s = re.replace_all(s, rep.as_str()).into_owned();
            }
        }
        Value::Array(a) => {
            for x in a {
                normalise_strings(x, rules);
            }
        }
        Value::Object(m) => {
            for x in m.values_mut() {
                normalise_strings(x, rules);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Run one valid case through `c` and record what mercurio did.
pub(super) fn record(
    c: &Comparator,
    doc: &Value,
    case: &Value,
    target: crate::Target,
    ignore: &[String],
    front: super::Front,
) -> Value {
    let mut s = Session::default();
    (c.setup)(&mut s, case);
    let msgs = [super::case_message(case)];
    let (mut attempts, _) =
        super::runner::run_sends(front, target, &msgs, &s.fake, &super::fixture_asset(doc), false).remove(0);
    let delivery = attempts.pop().map(|a| a.delivery).unwrap_or_default();
    let ok = delivery.is_success();
    let mut out = super::outcome(ok, delivery.errors().map(ToString::to_string).collect());
    let http = s.fake.requests();
    if !http.is_empty() {
        out["requests"] = super::requests(&http, ignore);
    }
    if !ok && !c.events_on_failure {
        return out;
    }
    let mut rules = rules_of(doc.get("normalise"));
    rules.extend(rules_of(case.get("normalise")));
    let mut events = Value::Array((c.normalise)((c.events)(&s, case)));
    normalise_strings(&mut events, &rules);
    for ptr in ignore.iter().filter_map(|i| i.strip_prefix("events:")) {
        super::runner::blank(&mut events, ptr);
    }
    out["events"] = events;
    out
}
