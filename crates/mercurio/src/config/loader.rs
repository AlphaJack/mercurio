//! Configuration sources (files, HTTP, memory) and `include` handling.

use std::path::{Path, PathBuf};

use super::model::{Config, ConfigFormat, ConfigOptions, MAX_BUFFER_SIZE, cfg_err};
use super::pending::build;
use super::text::{get_schema, parse_text};
use super::yaml_doc::parse_yaml;
use crate::error::Result;
use crate::transport::{AsyncTransport, BoxFuture, FileOp, FileOutput};
use crate::url::{ParseOptions, parse_url_with, quote, unquote};

#[derive(Debug, Clone)]
pub(super) enum SourceKind {
    File(PathBuf),
    Http { url: String, headers: Vec<(String, String)>, user: Option<String>, password: Option<String>, verify: bool },
    Memory(String),
}

#[derive(Debug, Clone)]
pub(super) struct Source {
    pub(super) kind: SourceKind,
    /// Forced format (`?format=`), else detected per source type.
    pub(super) format: Option<ConfigFormat>,
}

impl Source {
    /// The source for a configuration URL or plain path (no scheme means a local file).
    pub(super) fn instantiate(url: &str, format: Option<ConfigFormat>) -> Result<Source> {
        let url = match get_schema(url) {
            None => format!("file://{}", quote(url, "/")),
            Some(s) if matches!(s.as_str(), "file" | "http" | "https") => url.to_string(),
            Some(s) => return Err(cfg_err(format!("unsupported configuration schema {s}://"))),
        };
        Source::parse(&url, format)
    }

    /// `C_MGR[schema].parse_url(url)`.
    fn parse(url: &str, format: Option<ConfigFormat>) -> Result<Source> {
        let scheme = get_schema(url).unwrap_or_default();
        let unparseable = || cfg_err(format!("unparseable configuration URL {}", crate::plan::redact_url(url)));
        let verify_host = scheme != "file";
        let u = parse_url_with(url, ParseOptions { verify_host, ..Default::default() }).ok_or_else(unparseable)?;
        let format = u.param("format").and_then(ConfigFormat::parse).or(format);
        let kind = match scheme.as_str() {
            "file" => {
                let re = crate::regex!(r"(?i)^[a-z0-9]+://(?P<path>[^?]+)(\?.*)?");
                let path = re.captures(url).ok_or_else(unparseable)?["path"].to_string();
                SourceKind::File(path_decode(&unquote(&path)))
            }
            "http" | "https" => {
                let mut headers: Vec<(String, String)> =
                    u.query_minus.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                for (k, v) in u.query_plus.iter() {
                    headers.retain(|(n, _)| n != k);
                    headers.push((k.to_string(), v.to_string()));
                }
                let mut target = format!("{}://{}", scheme, u.host());
                if let Some(p) = u.port {
                    target.push_str(&format!(":{p}"));
                }
                target.push_str(u.fullpath.as_deref().unwrap_or("/"));
                SourceKind::Http { url: target, headers, user: u.user(), password: u.password(), verify: u.verify }
            }
            _ => return Err(unparseable()),
        };
        Ok(Source { kind, format })
    }

    /// `schemas()` of the including source, for the cross-include rule.
    fn schemas(&self) -> &'static [&'static str] {
        match self.kind {
            SourceKind::File(_) => &["file"],
            SourceKind::Http { .. } => &["http", "https"],
            SourceKind::Memory(_) => &["memory"],
        }
    }

    /// Directory relative includes resolve against.
    fn config_path(&self) -> PathBuf {
        match &self.kind {
            SourceKind::File(p) => p.parent().map(Path::to_path_buf).unwrap_or_default(),
            SourceKind::Http { .. } | SourceKind::Memory(_) => std::env::current_dir().unwrap_or_default(),
        }
    }

    fn describe(&self) -> String {
        match &self.kind {
            SourceKind::File(p) => format!("file://{}", p.display()),
            SourceKind::Http { url, .. } => crate::plan::redact_url(url),
            SourceKind::Memory(_) => "memory://".into(),
        }
    }
}

/// `path_decode`: expand `~` (Windows: `%VAR%`, `$VAR`, `${VAR}`), make absolute.
pub(super) fn path_decode(path: &str) -> PathBuf {
    let expanded = if cfg!(windows) {
        PathBuf::from(expand_vars(path, |name| std::env::var(name).ok()))
    } else if path == "~" || path.starts_with("~/") {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(path.trim_start_matches('~').trim_start_matches('/')),
            None => PathBuf::from(path),
        }
    } else {
        PathBuf::from(path)
    };
    if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir().map(|d| d.join(&expanded)).unwrap_or(expanded)
    }
}

pub(super) struct Loader<'a> {
    pub(super) transport: &'a dyn AsyncTransport,
    pub(super) opts: &'a ConfigOptions,
}

impl Loader<'_> {
    /// `read()`: the content and the format to parse it with.
    async fn read(&self, src: &Source, warnings: &mut Vec<String>) -> Option<(String, ConfigFormat)> {
        match &src.kind {
            SourceKind::Memory(text) => Some((text.clone(), src.format.unwrap_or(ConfigFormat::Text))),
            SourceKind::File(path) => {
                let meta = match self.transport.file(&FileOp::Stat { path: path.clone() }).await {
                    Ok(FileOutput::Meta(Some(m))) => m,
                    _ => {
                        warnings.push(format!("File is not accessible: {}", path.display()));
                        return None;
                    }
                };
                if meta.len as usize > MAX_BUFFER_SIZE {
                    warnings.push(format!(
                        "File size exceeds maximum allowable buffer length ({}KB).",
                        MAX_BUFFER_SIZE / 1024
                    ));
                    return None;
                }
                let bytes = match self.transport.file(&FileOp::Read { path: path.clone(), max: 0 }).await {
                    Ok(FileOutput::Bytes(b)) => b,
                    _ => {
                        warnings.push(format!("File can not be opened for read: {}", path.display()));
                        return None;
                    }
                };
                let Ok(text) = String::from_utf8(bytes) else {
                    warnings.push(format!("File not using expected encoding (utf-8) : {}", path.display()));
                    return None;
                };
                let yaml_ext = crate::regex!(r"(?i)^.*\.ya?ml\s*$").is_match(&path.to_string_lossy());
                let format = src.format.unwrap_or(if yaml_ext { ConfigFormat::Yaml } else { ConfigFormat::Text });
                Some((text, format))
            }
            SourceKind::Http { url, headers, user, password, verify } => {
                let mut req = crate::http::Request::post(url.clone()).header("User-Agent", "Mercurio");
                for (k, v) in headers {
                    req = req.set_header(k.clone(), v.clone());
                }
                if user.is_some() || password.is_some() {
                    req = req.basic_auth(user.as_deref().unwrap_or(""), password.as_deref());
                }
                req = req.verify(*verify);
                let res = match self.transport.http(&req).await {
                    Ok(r) => r,
                    Err(e) => {
                        warnings.push(format!("A Connection error occurred retrieving HTTP configuration: {e}"));
                        return None;
                    }
                };
                if !res.is_success() {
                    warnings.push(format!("HTTP configuration request failed: HTTP {}", res.status));
                    return None;
                }
                let declared: usize = res.header("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                if declared > MAX_BUFFER_SIZE || res.body.len() > MAX_BUFFER_SIZE {
                    warnings.push(format!(
                        "HTTP config response exceeds maximum buffer length ({}KB);",
                        MAX_BUFFER_SIZE / 1024
                    ));
                    return None;
                }
                let text = String::from_utf8_lossy(&res.body).into_owned();
                let ctype = res.header("content-type").unwrap_or("application/octet-stream");
                let format = src.format.unwrap_or_else(|| {
                    if crate::regex!(r"(?i)^(text|application)/(x-)?yaml").is_match(ctype) {
                        ConfigFormat::Yaml
                    } else {
                        ConfigFormat::Text
                    }
                });
                Some((text, format))
            }
        }
    }

    /// `ConfigBase.services()`: parse `src`, then follow its includes.
    pub(super) fn services<'s>(&'s self, src: &'s Source, recursion: u32, cfg: &'s mut Config) -> BoxFuture<'s, ()> {
        Box::pin(async move {
            let Some((content, format)) = self.read(src, &mut cfg.warnings).await else { return };
            let before = cfg.services.len();
            let parsed = match format {
                ConfigFormat::Text => parse_text(&content),
                ConfigFormat::Yaml => parse_yaml(&content, self.opts),
            };
            let includes = parsed.includes.clone();
            build(parsed, cfg);
            for inc in includes {
                if recursion == 0 {
                    log::debug!("Recursion limit reached; ignoring Include URL: {}", crate::plan::redact_url(&inc));
                    continue;
                }
                let (url, schema) = match get_schema(&inc) {
                    None => {
                        let mut path = PathBuf::from(&inc);
                        if !path.is_absolute() {
                            path = src.config_path().join(path);
                        }
                        (format!("file://{}", quote(&path.to_string_lossy(), "/")), "file".to_string())
                    }
                    Some(s) => {
                        if !matches!(s.as_str(), "file" | "http" | "https" | "memory") {
                            cfg.warnings.push(format!("Unsupported include schema {s}."));
                            continue;
                        }
                        (inc.clone(), s)
                    }
                };
                let child = match Source::parse(&url, None) {
                    Ok(c) => c,
                    Err(_) => {
                        cfg.warnings.push(format!("Unparseable include URL {}", crate::plan::redact_url(&url)));
                        continue;
                    }
                };
                if schema == "file" && !src.schemas().contains(&"file") && !self.opts.insecure_includes {
                    cfg.warnings.push(format!(
                        "Including {schema}:// based configuration is prohibited. Ignoring URL {}",
                        crate::plan::redact_url(&url)
                    ));
                    continue;
                }
                self.services(&child, recursion - 1, cfg).await;
            }
            if cfg.services.len() == before {
                log::warn!("Failed to load configuration from {}", src.describe());
            }
        })
    }
}

/// Windows-style variable expansion: `%name%`, `$name` and `${name}` are replaced by `var(name)`; unknown names, unclosed forms and text inside `'...'` stay as written; `%%` and `$$` become `%` and `$`.
fn expand_vars(path: &str, var: impl Fn(&str) -> Option<String>) -> String {
    let is_name = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-';
    let put = |out: &mut String, name: &str, form: String| match var(name).filter(|_| !name.is_empty()) {
        Some(v) => out.push_str(&v),
        None => out.push_str(&form),
    };
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(at) = rest.find(['\'', '%', '$']) {
        let (text, tail) = rest.split_at(at);
        out.push_str(text);
        rest = tail;
        if let Some(after) = rest.strip_prefix("%%").or_else(|| rest.strip_prefix("$$")) {
            out.push_str(rest.split_at(1).0);
            rest = after;
            continue;
        }
        if let Some(after) = rest.strip_prefix('\'') {
            let Some((quoted, tail)) = after.split_once('\'') else { break };
            out.push_str(&format!("'{quoted}'"));
            rest = tail;
            continue;
        }
        let (name, form, tail) = if let Some(after) = rest.strip_prefix('%') {
            let Some((name, tail)) = after.split_once('%') else { break };
            (name, format!("%{name}%"), tail)
        } else if let Some(after) = rest.strip_prefix("${") {
            let Some((name, tail)) = after.split_once('}') else { break };
            (name, format!("${{{name}}}"), tail)
        } else {
            let after = rest.strip_prefix('$').unwrap_or(rest);
            let (name, tail) = after.split_at(after.bytes().take_while(is_name).count());
            (name, format!("${name}"), tail)
        };
        put(&mut out, name, form);
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Default configuration locations searched by the CLI, in search order.
pub fn default_paths() -> Vec<String> {
    let mut out = Vec::new();
    if cfg!(windows) {
        for base in ["%APPDATA%", "%LOCALAPPDATA%", "%ALLUSERSPROFILE%", "%PROGRAMFILES%", "%COMMONPROGRAMFILES%"] {
            for ext in ["", ".conf", ".yml", ".yaml"] {
                out.push(format!("{base}\\Apprise\\apprise{ext}"));
            }
        }
        return out;
    }
    for base in ["~/.apprise", "~/.config/apprise", "~/.apprise/apprise", "~/.config/apprise/apprise"] {
        for ext in ["", ".conf", ".yml", ".yaml"] {
            out.push(format!("{base}{ext}"));
        }
    }
    out.extend(["/etc/apprise", "/etc/apprise.yml", "/etc/apprise.yaml"].map(String::from));
    for ext in ["", ".conf", ".yml", ".yaml"] {
        out.push(format!("/etc/apprise/apprise{ext}"));
    }
    out
}

/// Expand `~` (Windows: environment variables) in a configured path.
pub fn expand_path(path: &str) -> PathBuf {
    path_decode(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expansion with `APPDATA`, `A_B` and `X-Y` set.
    #[test]
    fn expand_vars_cases() {
        let env = |name: &str| match name {
            "APPDATA" => Some(r"C:\Users\u\AppData\Roaming".to_string()),
            "A_B" => Some("x".into()),
            "X-Y" => Some("dash".into()),
            _ => None,
        };
        let cases = [
            (r"%APPDATA%\Apprise\apprise", r"C:\Users\u\AppData\Roaming\Apprise\apprise"),
            (r"%UNSET_VAR%\x", r"%UNSET_VAR%\x"),
            ("%%APPDATA%%", "%APPDATA%"),
            ("%APPDATA", "%APPDATA"),
            ("50%", "50%"),
            ("$A_B/${A_B}/${UNSET_VAR}", "x/x/${UNSET_VAR}"),
            ("$$A_B", "$A_B"),
            ("${A_B", "${A_B"),
            ("$X-Y", "dash"),
            ("$", "$"),
            ("a$/b", "a$/b"),
            ("'%APPDATA%'", "'%APPDATA%'"),
            ("it's %APPDATA%", "it's %APPDATA%"),
            ("%%", "%"),
            ("%", "%"),
            ("${}", "${}"),
            ("%A_B%%A_B%", "xx"),
            ("plain", "plain"),
            ("~/x", "~/x"),
        ];
        for (input, want) in cases {
            assert_eq!(expand_vars(input, env), want, "{input}");
        }
    }
}
