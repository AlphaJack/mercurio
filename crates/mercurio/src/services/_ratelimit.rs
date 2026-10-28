//! A server-advertised request budget (`X-RateLimit-Remaining` / `X-RateLimit-Reset`) kept between the sends of one target, as Apprise keeps `ratelimit_remaining` and `ratelimit_reset` on the plugin object.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::env::Env;
use crate::http::{Request, Response};
use crate::plan::Plan;
use crate::Result;

/// How a service writes `X-RateLimit-Reset`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Reset {
    /// Seconds until the window ends (Reddit).
    SecondsLeft,
    /// An RFC 3339 time (Mastodon).
    Rfc3339,
}

#[derive(Debug)]
pub(crate) struct RateLimit {
    reset: Reset,
    /// Added to the wait, for clock skew.
    grace: Duration,
    /// `(remaining, reset as Unix seconds)`.
    state: Mutex<(f64, f64)>,
}

impl RateLimit {
    pub(crate) fn new(reset: Reset, grace: Duration) -> Arc<Self> {
        Arc::new(RateLimit { reset, grace, state: Mutex::new((1.0, 0.0)) })
    }

    /// How long to wait before the next request: until the reset (plus the grace) when nothing is left.
    fn wait(&self, env: &dyn Env) -> Option<Duration> {
        let (remaining, reset) = *self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = env.unix_time_ms() as f64 / 1000.0;
        (remaining <= 0.0 && now < reset).then(|| Duration::from_secs_f64(reset - now) + self.grace)
    }

    /// Keep the budget a successful response advertises; a header that does not parse leaves its value.
    fn record(&self, r: &Response, env: &dyn Env) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(remaining) = r.header("x-ratelimit-remaining").and_then(|v| v.trim().parse::<f64>().ok()) else {
            return;
        };
        state.0 = remaining;
        let reset = r.header("x-ratelimit-reset").map(str::trim);
        let reset = match self.reset {
            Reset::SecondsLeft => reset
                .and_then(|v| v.parse::<f64>().ok())
                .map(|s| env.unix_time_ms() as f64 / 1000.0 + s),
            Reset::Rfc3339 => reset.and_then(crate::time::parse_rfc3339),
        };
        if let Some(reset) = reset.filter(|r| r.is_finite()) {
            state.1 = reset;
        }
    }

    /// Send `req` once the budget allows it (the wait is worked out when execution reaches it), recording the budget of responses whose status is in `ok`.
    pub(crate) fn send(
        self: &Arc<Self>,
        req: Request,
        ok: &'static [u16],
        env: &Arc<dyn Env>,
        then: impl FnOnce(Result<Response>) -> Plan + Send + 'static,
    ) -> Plan {
        let (me, env) = (self.clone(), env.clone());
        Plan::defer(move || {
            let wait = me.wait(env.as_ref());
            let send = Plan::http(req, move |res| {
                if let Ok(r) = &res
                    && ok.contains(&r.status)
                {
                    me.record(r, env.as_ref());
                }
                then(res)
            });
            match wait {
                Some(d) => Plan::chain([Plan::Sleep(d), send]),
                None => send,
            }
        })
    }
}

/// The frozen clock of [`second_send_waits`], in Unix seconds.
#[cfg(test)]
pub(crate) const NOW: u64 = 1_700_000_000;

/// Tests of the services that keep a budget: the one sleep of a second send of `url`, after the `first` responses left no budget.
#[cfg(test)]
pub(crate) fn second_send_waits(url: &str, first: Vec<Response>, second: Response) -> Duration {
    let t = crate::parse(url).unwrap();
    let fake = crate::testing::FakeTransport::new().with_env(crate::testing::FixedEnv::new(NOW));
    for r in first {
        fake.respond_with(r);
    }
    let asset = crate::Asset::default();
    assert!(t.send(&crate::Message::new("one"), &fake, &asset).is_success(), "first send");
    assert!(fake.sleeps().is_empty(), "the first send never waits");
    fake.respond_with(second);
    assert!(t.send(&crate::Message::new("two"), &fake, &asset).is_success(), "second send");
    let sleeps = fake.sleeps();
    assert_eq!(sleeps.len(), 1, "{sleeps:?}");
    sleeps[0]
}
