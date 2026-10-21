//! Sending a notification and rendering its result: the logs of the call as text, HTML or `{"error", "details"}`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use mercurio::{AsyncMercurio, BoxFuture, Message, Report, TagFilter, TemplateVars};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::http::{Body, Reply, Req};

/// One log line of a notification call.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: &'static str,
    pub time: SystemTime,
    pub message: String,
    pub service: Option<String>,
}

impl LogEntry {
    pub fn new(level: &'static str, message: String, service: Option<String>) -> Self {
        LogEntry { level, time: SystemTime::now(), message, service }
    }

    /// `YYYY-MM-DD HH:MM:SS,mmm` (UTC).
    pub fn asctime(&self) -> String {
        let d = self.time.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
        let (y, mo, da, h, mi, s) = mercurio::__private::utc_parts(d.as_secs());
        format!("{y:04}-{mo:02}-{da:02} {h:02}:{mi:02}:{s:02},{:03}", d.subsec_millis())
    }

    pub fn line(&self) -> String {
        format!("{} - {} - {}", self.asctime(), self.level, self.message)
    }
}

/// Log entries for a finished call: one per service notified.
pub fn report_logs(report: &Report) -> Vec<LogEntry> {
    let mut logs = Vec::new();
    for e in &report.entries {
        let service = Some(e.service.to_string());
        if e.delivery.is_success() {
            logs.push(LogEntry::new("INFO", format!("Sent {} notification.", e.label), service));
        } else {
            for o in e.delivery.outcomes.iter().filter(|o| o.result.is_err()) {
                let why = o.result.as_ref().err().map(ToString::to_string).unwrap_or_default();
                logs.push(LogEntry::new(
                    "ERROR",
                    format!("Failed to send {} notification: {why}", e.label),
                    service.clone(),
                ));
            }
        }
    }
    logs
}

pub fn render(req: &Req, status: u16, logs: &[LogEntry], error: Option<&str>) -> Reply {
    if req.wants_json() {
        let details: Vec<Value> = logs.iter().map(|l| json!([l.level, l.asctime(), l.message])).collect();
        return Reply::json(status, &json!({"error": error, "details": details}));
    }
    if req.wants_html_logs() {
        let mut html = String::from("<ul class=\"logs\">");
        for l in logs {
            html.push_str(&format!(
                "<li class=\"log_{lvl}\"><div class=\"log_time\">{t}</div><div class=\"log_level\">{lvl}</div><div class=\"log_msg\">{m}</div></li>",
                lvl = l.level,
                t = l.asctime(),
                m = html_escape(&l.message)
            ));
        }
        html.push_str("</ul>");
        return Reply::new(status, "text/html; charset=utf-8", html.into_bytes());
    }
    let mut text = logs.iter().map(LogEntry::line).collect::<Vec<_>>().join("\n");
    if text.is_empty() {
        text = error.unwrap_or_default().to_string();
    }
    Reply::new(status, "text/plain; charset=utf-8", text.into_bytes())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#x27;")
}

/// What to send.
pub struct Job {
    pub notifier: AsyncMercurio,
    pub message: Message,
    pub filter: TagFilter,
    pub vars: TemplateVars,
    /// `Some(key)` for a stored configuration.
    pub key: Option<String>,
}

impl Job {
    /// Send, with every log line of the call (the library's own and one per finished service) going to `on_log` as it happens.
    pub async fn run(&self, on_log: Arc<dyn Fn(LogEntry) + Send + Sync>) -> Report {
        let sink: crate::logging::Sink = {
            let on_log = on_log.clone();
            Arc::new(move |level, message| on_log(LogEntry::new(level_name(level), message, None)))
        };
        let on_entry = |entry: &mercurio::ReportEntry| entry_logs(entry).into_iter().for_each(|l| on_log(l));
        let send = self.notifier.notify_with(
            &self.message,
            mercurio::NotifyOptions::new().tags(&self.filter).vars(&self.vars).on_entry(&on_entry),
        );
        crate::logging::capture(sink, send).await
    }

    /// The 424 message for this kind of call.
    pub fn failure_message(&self) -> &'static str {
        if self.key.is_some() {
            "One or more notification could not be sent"
        } else {
            "One or more notifications could not be sent"
        }
    }
}

pub async fn deliver(req: &Req, job: &Job, level: u8) -> (Reply, Report, Vec<LogEntry>) {
    let collected = Arc::new(std::sync::Mutex::new(Vec::new()));
    let report = {
        let collected = collected.clone();
        job.run(Arc::new(move |l| collected.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(l))).await
    };
    let all = std::mem::take(&mut *collected.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
    let logs = filter_level(all.clone(), level);
    req.note(|ev| {
        ev.services = Some(report.entries.len());
        ev.failed = Some(report.entries.iter().filter(|e| !e.delivery.is_success()).count());
    });
    let reply = if report.is_success() {
        render(req, 200, &logs, None)
    } else {
        req.note(|ev| ev.error = Some(job.failure_message().to_string()));
        render(req, 424, &logs, Some(job.failure_message()))
    };
    (reply, report, all)
}

/// The name of a `tracing` level, as the logs show it.
fn level_name(level: tracing::Level) -> &'static str {
    match level {
        tracing::Level::ERROR => "ERROR",
        tracing::Level::WARN => "WARNING",
        tracing::Level::INFO => "INFO",
        tracing::Level::DEBUG => "DEBUG",
        tracing::Level::TRACE => "TRACE",
    }
}

/// Numeric log level of a level name (`TRACE` 5 ... `CRITICAL` 50).
pub fn level_value(name: &str) -> Option<u8> {
    match name.trim().to_ascii_uppercase().as_str() {
        "TRACE" => Some(5),
        "DEBUG" => Some(10),
        "INFO" => Some(20),
        "WARNING" => Some(30),
        "ERROR" => Some(40),
        "CRITICAL" => Some(50),
        _ => None,
    }
}

/// Keep the entries at or above `level`.
pub fn filter_level(logs: Vec<LogEntry>, level: u8) -> Vec<LogEntry> {
    logs.into_iter().filter(|l| level_value(l.level).unwrap_or(20) >= level).collect()
}

fn entry_logs(e: &mercurio::ReportEntry) -> Vec<LogEntry> {
    report_logs(&Report { entries: vec![e.clone()] })
}

/// One Server-Sent Event.
pub fn sse(event: &str, data: &Value) -> Event {
    Event::default().event(event).data(data.to_string())
}

fn log_event(l: &LogEntry) -> Event {
    sse("log", &json!({"level": l.level, "asctime": l.asctime(), "message": l.message, "service": l.service}))
}

/// Live streams currently admitted (`APPRISE_STREAM_WORKER_COUNT` + `APPRISE_STREAM_QUEUE_SIZE`).
pub struct StreamSlots {
    active: AtomicUsize,
    capacity: usize,
}

impl StreamSlots {
    pub fn new(capacity: usize) -> Arc<StreamSlots> {
        Arc::new(StreamSlots { active: AtomicUsize::new(0), capacity })
    }

    pub fn try_admit(self: &Arc<Self>) -> Option<StreamSlot> {
        let prev = self.active.fetch_add(1, Ordering::SeqCst);
        if prev >= self.capacity {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(StreamSlot(self.clone()))
    }
}

/// Releases its admission when the response is done.
pub struct StreamSlot(Arc<StreamSlots>);

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Called once a streamed job has finished, with its report and logs.
pub type OnDone = Box<dyn FnOnce(Report, Vec<LogEntry>) -> BoxFuture<'static, ()> + Send>;

/// Runs the job in a task, sending a `log` event as each service finishes and a final `result` event; `done` gets the report and logs. While idle the stream sends a heartbeat comment.
pub fn stream(job: Job, level: u8, slot: StreamSlot, heartbeat: Duration, done: OnDone) -> Reply {
    let (tx, rx) = mpsc::unbounded_channel::<Event>();
    let send = move |tx: &mpsc::UnboundedSender<Event>, event: Event| {
        if tx.send(event).is_err() {
            log::debug!("stream client went away");
        }
    };
    send(&tx, Event::default().comment("connected"));
    tokio::spawn(async move {
        let collected = Arc::new(std::sync::Mutex::new(Vec::new()));
        let report = {
            let (collected, tx) = (collected.clone(), tx.clone());
            job.run(Arc::new(move |l: LogEntry| {
                if level_value(l.level).unwrap_or(20) >= level {
                    send(&tx, log_event(&l));
                }
                collected.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(l);
            }))
            .await
        };
        let status = report.status().as_str().to_ascii_uppercase();
        send(&tx, sse("result", &json!({"status": status})));
        drop(tx);
        let logs = std::mem::take(&mut *collected.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        done(report, logs).await;
    });
    // The stream holds `slot` until the client has the last event.
    let events = futures_util::stream::unfold((rx, slot), |(mut rx, slot)| async move {
        rx.recv().await.map(|event| (Ok::<_, std::convert::Infallible>(event), (rx, slot)))
    });
    let sse = Sse::new(events).keep_alive(KeepAlive::new().interval(heartbeat).text("heartbeat"));
    let response = ([("X-Accel-Buffering", "no")], sse).into_response();
    Reply { status: 200, ctype: String::new(), body: Body::Response(Box::new(response)), headers: Vec::new() }
}
