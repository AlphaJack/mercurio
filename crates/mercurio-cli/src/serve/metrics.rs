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

/// `django_prometheus`'s body size buckets, `PowersOf(2, 30)`: 0, then 1 to 2^29 bytes.
fn byte_buckets() -> Vec<f64> {
    std::iter::once(0.0).chain((0..30).map(|i| f64::from(1u32 << i))).collect()
}

/// One Prometheus histogram.
#[derive(Debug, Clone, Default)]
struct Hist {
    buckets: Vec<f64>,
    counts: Vec<u64>,
    count: u64,
    sum: f64,
}

impl Hist {
    fn new(buckets: Vec<f64>) -> Self {
        Hist { counts: vec![0; buckets.len()], buckets, count: 0, sum: 0.0 }
    }

    fn observe(&mut self, v: f64) {
        for (b, n) in self.buckets.iter().zip(self.counts.iter_mut()) {
            if v <= *b {
                *n += 1;
            }
        }
        self.count += 1;
        self.sum += v;
    }

    /// The `_bucket`, `_count` and `_sum` lines; `labels` like `method="GET",` (trailing comma) or empty.
    fn render(&self, o: &mut String, name: &str, labels: &str) {
        for (b, n) in self.buckets.iter().zip(&self.counts) {
            w!(o, "{name}_bucket{{{labels}le=\"{b:?}\"}} {n}.0");
        }
        w!(o, "{name}_bucket{{{labels}le=\"+Inf\"}} {}.0", self.count);
        let plain = labels.trim_end_matches(',');
        let labels = if plain.is_empty() { String::new() } else { format!("{{{plain}}}") };
        w!(o, "{name}_count{labels} {}.0", self.count);
        w!(o, "{name}_sum{labels} {}", self.sum);
    }
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
    latency_by_view: BTreeMap<(String, String), Hist>,
    request_bytes: Option<Hist>,
    response_bytes: Option<Hist>,
    streaming: u64,
    notifications: BTreeMap<&'static str, u64>,
}

#[derive(Default)]
pub struct Metrics {
    inner: Mutex<Counters>,
}

impl Metrics {
    /// Count one answered request. `view` is the route name; `bytes_in` the request body; `bytes_out` the response body, `None` when it is streamed.
    pub fn record(
        &self,
        method: &str,
        view: &str,
        status: u16,
        elapsed: Duration,
        bytes_in: u64,
        bytes_out: Option<u64>,
    ) {
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
        c.latency_by_view
            .entry((view.to_string(), method.to_string()))
            .or_insert_with(|| Hist::new(BUCKETS.to_vec()))
            .observe(secs);
        c.request_bytes.get_or_insert_with(|| Hist::new(byte_buckets())).observe(bytes_in as f64);
        match bytes_out {
            Some(n) => c.response_bytes.get_or_insert_with(|| Hist::new(byte_buckets())).observe(n as f64),
            None => c.streaming += 1,
        }
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
        let name = "apprise_django_http_requests_latency_seconds_by_view_method";
        w!(o, "# HELP {name} Histogram of request processing time labelled by view.");
        w!(o, "# TYPE {name} histogram");
        for ((v, m), h) in &c.latency_by_view {
            h.render(&mut o, name, &format!("method=\"{m}\",view=\"{v}\","));
        }
        let bodies = [
            ("apprise_django_http_requests_body_total_bytes", "Histogram of requests by body size.", &c.request_bytes),
            (
                "apprise_django_http_responses_body_total_bytes",
                "Histogram of responses by body size.",
                &c.response_bytes,
            ),
        ];
        for (name, help, h) in bodies {
            w!(o, "# HELP {name} {help}");
            w!(o, "# TYPE {name} histogram");
            h.clone().unwrap_or_else(|| Hist::new(byte_buckets())).render(&mut o, name, "");
        }
        counter(&mut o, "apprise_django_http_responses_streaming_total", "Count of streaming responses.");
        w!(o, "apprise_django_http_responses_streaming_total {}.0", c.streaming);
        process(&mut o);
        counter(&mut o, "apprise_notifications_total", "Notification calls by result (mercurio).");
        for (s, n) in &c.notifications {
            w!(o, "apprise_notifications_total{{status=\"{s}\"}} {n}.0");
        }
        o
    }
}

/// `prometheus_client`'s process metrics, read from `/proc` as it does (Linux only, as there).
#[cfg(target_os = "linux")]
fn process(o: &mut String) {
    // `sysconf(_SC_CLK_TCK)` needs `unsafe`; it is 100 on every Linux build Prometheus targets.
    const TICKS: f64 = 100.0;
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let status = read("/proc/self/status");
    let kib = |key: &str| {
        status.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| v.split_whitespace().next()?.parse::<f64>().ok())
    };
    let stat = read("/proc/self/stat");
    // Numbered as in proc(5): state is field 3, utime 14, stime 15, starttime 22.
    let fields: Vec<&str> = stat.rsplit_once(')').map(|(_, r)| r.split_whitespace().collect()).unwrap_or_default();
    let field = |n: usize| fields.get(n - 3).and_then(|v| v.parse::<f64>().ok());
    let boot = read("/proc/stat").lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse::<f64>().ok());
    let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count() as f64).ok();
    let max_fds = read("/proc/self/limits")
        .lines()
        .find(|l| l.starts_with("Max open files"))
        .and_then(|l| l.split_whitespace().nth(3)?.parse::<f64>().ok());
    let metrics = [
        ("process_virtual_memory_bytes", "Virtual memory size in bytes.", "gauge", kib("VmSize:").map(|k| k * 1024.0)),
        ("process_resident_memory_bytes", "Resident memory size in bytes.", "gauge", kib("VmRSS:").map(|k| k * 1024.0)),
        (
            "process_start_time_seconds",
            "Start time of the process since unix epoch in seconds.",
            "gauge",
            boot.zip(field(22)).map(|(b, t)| b + t / TICKS),
        ),
        (
            "process_cpu_seconds_total",
            "Total user and system CPU time spent in seconds.",
            "counter",
            field(14).zip(field(15)).map(|(u, s)| (u + s) / TICKS),
        ),
        ("process_open_fds", "Number of open file descriptors.", "gauge", fds),
        ("process_max_fds", "Maximum number of open file descriptors.", "gauge", max_fds),
    ];
    for (name, help, kind, value) in metrics {
        if let Some(v) = value {
            w!(o, "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {v:?}");
        }
    }
}

/// `prometheus_client` exports process metrics on Linux only.
#[cfg(not(target_os = "linux"))]
fn process(_: &mut String) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_latency_body_sizes_and_streams() {
        let m = Metrics::default();
        m.record("POST", "s_notify", 200, Duration::from_millis(30), 100, Some(3000));
        m.record("POST", "s_notify", 200, Duration::from_millis(5), 0, None);
        let out = m.render();
        let has = |line: &str| assert!(out.lines().any(|l| l == line), "{line}\n{out}");
        has(
            r#"apprise_django_http_requests_latency_seconds_by_view_method_bucket{method="POST",view="s_notify",le="0.01"} 1.0"#,
        );
        has(r#"apprise_django_http_requests_latency_seconds_by_view_method_count{method="POST",view="s_notify"} 2.0"#);
        has(r#"apprise_django_http_requests_body_total_bytes_bucket{le="0.0"} 1.0"#);
        has(r#"apprise_django_http_requests_body_total_bytes_bucket{le="128.0"} 2.0"#);
        has("apprise_django_http_requests_body_total_bytes_sum 100");
        has(r#"apprise_django_http_responses_body_total_bytes_bucket{le="2048.0"} 0.0"#);
        has(r#"apprise_django_http_responses_body_total_bytes_bucket{le="4096.0"} 1.0"#);
        has("apprise_django_http_responses_body_total_bytes_count 1.0");
        has("apprise_django_http_responses_streaming_total 1.0");
        assert_eq!(byte_buckets().len(), 31);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_metrics_on_linux() {
        let out = Metrics::default().render();
        for name in
            ["process_resident_memory_bytes", "process_cpu_seconds_total", "process_open_fds", "process_max_fds"]
        {
            let value =
                out.lines().find_map(|l| l.strip_prefix(&format!("{name} "))).and_then(|v| v.parse::<f64>().ok());
            assert!(value.is_some_and(|v| v > 0.0), "{name}\n{out}");
        }
    }
}
