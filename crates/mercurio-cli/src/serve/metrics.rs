//! `/metrics`: request counters in the Prometheus text format, named like the compatible `django_prometheus` metrics.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

/// `django_prometheus` default latency buckets (seconds).
const BUCKETS: [f64; 16] = [0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0, 25.0, 50.0, 75.0];

/// Append one line (writing to a `String` can not fail).
macro_rules! w {
    ($o:expr, $($arg:tt)*) => {{
        $o.push_str(&format!($($arg)*));
        $o.push('\n');
    }};
}

#[derive(Default)]
struct Counters {
    requests: u64,
    responses: u64,
    by_method: BTreeMap<String, u64>,
    by_view: BTreeMap<(String, String), u64>,
    by_status: BTreeMap<u16, u64>,
    by_status_view: BTreeMap<(u16, String, String), u64>,
    latency: Vec<u64>,
    latency_sum: f64,
    notifications: BTreeMap<&'static str, u64>,
}

#[derive(Default)]
pub struct Metrics {
    inner: Mutex<Counters>,
}

impl Metrics {
    /// Count one answered request. `view` is the route name.
    pub fn record(&self, method: &str, view: &str, status: u16, elapsed: Duration) {
        let Ok(mut c) = self.inner.lock() else { return };
        c.requests += 1;
        c.responses += 1;
        *c.by_method.entry(method.to_string()).or_default() += 1;
        *c.by_view.entry((view.to_string(), method.to_string())).or_default() += 1;
        *c.by_status.entry(status).or_default() += 1;
        *c.by_status_view.entry((status, view.to_string(), method.to_string())).or_default() += 1;
        if c.latency.is_empty() {
            c.latency = vec![0; BUCKETS.len()];
        }
        let secs = elapsed.as_secs_f64();
        for (i, b) in BUCKETS.iter().enumerate() {
            if secs <= *b
                && let Some(n) = c.latency.get_mut(i)
            {
                *n += 1;
            }
        }
        c.latency_sum += secs;
    }

    /// Count one notification call by its outcome (`success`, `failure`, ...).
    pub fn notified(&self, status: &'static str) {
        if let Ok(mut c) = self.inner.lock() {
            *c.notifications.entry(status).or_default() += 1;
        }
    }

    pub fn render(&self) -> String {
        let Ok(c) = self.inner.lock() else { return String::new() };
        let mut o = String::new();
        let counter = |o: &mut String, name: &str, help: &str| {
            w!(o, "# HELP {name} {help}\n# TYPE {name} counter");
        };
        counter(
            &mut o,
            "apprise_django_http_requests_before_middlewares_total",
            "Total count of requests before middlewares run.",
        );
        w!(o, "apprise_django_http_requests_before_middlewares_total {}.0", c.requests);
        counter(
            &mut o,
            "apprise_django_http_responses_before_middlewares_total",
            "Total count of responses before middlewares run.",
        );
        w!(o, "apprise_django_http_responses_before_middlewares_total {}.0", c.responses);
        counter(&mut o, "apprise_django_http_requests_total_by_method_total", "Count of requests by method.");
        for (m, n) in &c.by_method {
            w!(o, "apprise_django_http_requests_total_by_method_total{{method=\"{m}\"}} {n}.0");
        }
        counter(&mut o, "apprise_django_http_requests_total_by_transport_total", "Count of requests by transport.");
        w!(o, "apprise_django_http_requests_total_by_transport_total{{transport=\"http\"}} {}.0", c.requests);
        counter(
            &mut o,
            "apprise_django_http_requests_total_by_view_transport_method_total",
            "Count of requests by view, transport, method.",
        );
        for ((v, m), n) in &c.by_view {
            w!(
                o,
                "apprise_django_http_requests_total_by_view_transport_method_total{{method=\"{m}\",transport=\"http\",view=\"{v}\"}} {n}.0"
            );
        }
        counter(&mut o, "apprise_django_http_responses_total_by_status_total", "Count of responses by status.");
        for (s, n) in &c.by_status {
            w!(o, "apprise_django_http_responses_total_by_status_total{{status=\"{s}\"}} {n}.0");
        }
        counter(
            &mut o,
            "apprise_django_http_responses_total_by_status_view_method_total",
            "Count of responses by status, view, method.",
        );
        for ((s, v), n) in c.by_status_view.iter().map(|((s, v, m), n)| ((s, (v, m)), n)) {
            w!(
                o,
                "apprise_django_http_responses_total_by_status_view_method_total{{method=\"{}\",status=\"{s}\",view=\"{}\"}} {n}.0",
                v.1,
                v.0
            );
        }
        let name = "apprise_django_http_requests_latency_including_middlewares_seconds";
        w!(o, "# HELP {name} Histogram of requests processing time (including middleware processing time).");
        w!(o, "# TYPE {name} histogram");
        for (i, b) in BUCKETS.iter().enumerate() {
            w!(o, "{name}_bucket{{le=\"{b:?}\"}} {}.0", c.latency.get(i).copied().unwrap_or(0));
        }
        w!(o, "{name}_bucket{{le=\"+Inf\"}} {}.0", c.requests);
        w!(o, "{name}_count {}.0", c.requests);
        w!(o, "{name}_sum {}", c.latency_sum);
        counter(&mut o, "apprise_notifications_total", "Notification calls by result (mercurio).");
        for (s, n) in &c.notifications {
            w!(o, "apprise_notifications_total{{status=\"{s}\"}} {n}.0");
        }
        o
    }
}
