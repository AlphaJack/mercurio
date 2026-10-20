//! Alertmanager and Grafana webhooks: a JSON payload with an `alerts` array and a `status`, and no `body`, becomes a notification, so `/notify/{key}` and `/notify` work as their webhook receivers.
//!
//! Grafana's `title` and `message` are used as they are. For Alertmanager the title follows its default subject (`[FIRING:2] HighCPU web (prod)`) and the body lists each alert. The type comes from the status and the `severity` label; a `type` in the payload, the query or a header still wins.

use serde_json::{Map, Value};

/// `true` for an Alertmanager or Grafana webhook payload that carries no notification body of its own.
pub fn is_alert_payload(data: &Map<String, Value>) -> bool {
    !data.contains_key("body")
        && data.get("alerts").is_some_and(Value::is_array)
        && data.get("status").is_some_and(Value::is_string)
}

/// Fill `title`, `body`, `type` and `format` from the webhook fields; fields already set are kept.
pub fn convert(data: &mut Map<String, Value>) {
    let status = data.get("status").and_then(Value::as_str).unwrap_or("").to_lowercase();
    let alerts: Vec<Value> = data.get("alerts").and_then(Value::as_array).cloned().unwrap_or_default();
    let title = text(data, "title").unwrap_or_else(|| subject(data, &status, &alerts));
    let body = text(data, "message").unwrap_or_else(|| alert_lines(&alerts).join("\n"));
    let kind = kind(data, &status, &alerts);
    for (k, v) in [("title", title), ("body", body), ("type", kind.to_string()), ("format", "text".to_string())] {
        if !data.get(k).is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty())) {
            data.insert(k.into(), Value::String(v));
        }
    }
}

fn text(data: &Map<String, Value>, key: &str) -> Option<String> {
    data.get(key).and_then(Value::as_str).filter(|s| !s.trim().is_empty()).map(str::to_string)
}

/// The values of a label set, sorted by label name.
fn values(labels: Option<&Value>, skip: &Map<String, Value>) -> Vec<String> {
    let Some(Value::Object(m)) = labels else { return Vec::new() };
    let mut pairs: Vec<(&String, &Value)> = m.iter().filter(|(k, _)| !skip.contains_key(*k)).collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs.into_iter().map(|(_, v)| v.as_str().map_or_else(|| v.to_string(), str::to_string)).collect()
}

/// Alertmanager's default `__subject`: `[STATUS:firing count] group label values (other common label values)`.
fn subject(data: &Map<String, Value>, status: &str, alerts: &[Value]) -> String {
    let firing = alerts.iter().filter(|a| a.get("status").and_then(Value::as_str) == Some("firing")).count();
    let mut out =
        if status == "firing" { format!("[FIRING:{firing}]") } else { format!("[{}]", status.to_uppercase()) };
    let empty = Map::new();
    let group = values(data.get("groupLabels"), &empty);
    if !group.is_empty() {
        out = format!("{out} {}", group.join(" "));
    }
    let group_labels = data.get("groupLabels").and_then(Value::as_object).unwrap_or(&empty);
    let rest = values(data.get("commonLabels"), group_labels);
    if !rest.is_empty() {
        out = format!("{out} ({})", rest.join(" "));
    }
    out
}

/// One line per alert, `[FIRING] name: summary`, with the description on the next line.
fn alert_lines(alerts: &[Value]) -> Vec<String> {
    let field = |a: &Value, set: &str, key: &str| {
        a.get(set).and_then(|s| s.get(key)).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
    };
    let mut lines = Vec::new();
    for a in alerts {
        let status = a.get("status").and_then(Value::as_str).unwrap_or("unknown").to_uppercase();
        let name = field(a, "labels", "alertname").unwrap_or_else(|| "alert".into());
        lines.push(match field(a, "annotations", "summary") {
            Some(summary) => format!("[{status}] {name}: {summary}"),
            None => format!("[{status}] {name}"),
        });
        if let Some(d) = field(a, "annotations", "description") {
            lines.push(d);
        }
    }
    lines
}

/// `success` once resolved; while firing, the highest `severity` among the common labels and the alerts.
fn kind(data: &Map<String, Value>, status: &str, alerts: &[Value]) -> &'static str {
    if status == "resolved" {
        return "success";
    }
    let severity = |labels: Option<&Value>| {
        labels.and_then(|l| l.get("severity")).and_then(Value::as_str).map(|s| match s.to_lowercase().as_str() {
            "critical" | "error" | "page" | "emergency" | "high" => 2,
            "info" | "informational" | "none" | "low" => 0,
            _ => 1,
        })
    };
    let levels =
        std::iter::once(severity(data.get("commonLabels"))).chain(alerts.iter().map(|a| severity(a.get("labels"))));
    match levels.flatten().max() {
        Some(2) => "failure",
        Some(0) => "info",
        _ => "warning",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn alertmanager() -> Map<String, Value> {
        obj(json!({
            "version": "4",
            "status": "firing",
            "groupLabels": {"alertname": "HighCPU"},
            "commonLabels": {"alertname": "HighCPU", "env": "prod", "severity": "critical"},
            "alerts": [
                {"status": "firing", "labels": {"alertname": "HighCPU", "severity": "critical"},
                 "annotations": {"summary": "CPU above 90% on web-1", "description": "for 5 minutes"}},
                {"status": "firing", "labels": {"alertname": "HighCPU"}, "annotations": {}},
            ],
        }))
    }

    #[test]
    fn alertmanager_payload() {
        let mut d = alertmanager();
        assert!(is_alert_payload(&d));
        convert(&mut d);
        assert_eq!(d["title"], "[FIRING:2] HighCPU (prod critical)");
        assert_eq!(d["body"], "[FIRING] HighCPU: CPU above 90% on web-1\nfor 5 minutes\n[FIRING] HighCPU");
        assert_eq!((d["type"].as_str(), d["format"].as_str()), (Some("failure"), Some("text")));
    }

    #[test]
    fn grafana_payload_and_overrides() {
        let mut d = obj(json!({
            "status": "resolved", "title": "[RESOLVED] Disk", "message": "Disk is fine", "alerts": [], "type": "info",
        }));
        convert(&mut d);
        assert_eq!(
            (d["title"].as_str(), d["body"].as_str(), d["type"].as_str()),
            (Some("[RESOLVED] Disk"), Some("Disk is fine"), Some("info"))
        );
        let mut d = obj(json!({"status": "resolved", "alerts": [], "groupLabels": {}}));
        convert(&mut d);
        assert_eq!((d["title"].as_str(), d["type"].as_str()), (Some("[RESOLVED]"), Some("success")));
    }

    #[test]
    fn severities() {
        let firing = |sev: Value| {
            let mut d = obj(json!({"status": "firing", "alerts": [{"status": "firing", "labels": {"severity": sev}}]}));
            convert(&mut d);
            d["type"].as_str().unwrap().to_string()
        };
        assert_eq!(firing(json!("warning")), "warning");
        assert_eq!(firing(json!("info")), "info");
        assert_eq!(firing(json!("page")), "failure");
        assert_eq!(firing(Value::Null), "warning");
    }

    #[test]
    fn not_alerts() {
        assert!(!is_alert_payload(&obj(json!({"body": "x", "alerts": [], "status": "firing"}))));
        assert!(!is_alert_payload(&obj(json!({"alerts": {}, "status": "firing"}))));
        assert!(!is_alert_payload(&obj(json!({"title": "t"}))));
    }
}
