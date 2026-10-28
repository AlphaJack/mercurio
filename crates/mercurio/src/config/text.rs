//! TEXT configuration and format detection.

use super::groups::{apply_groups, normalize_groups};
use super::model::{ConfigFormat, Parsed, RawEntry};
use crate::tag::Tag;

/// `ConfigBase.detect_config_format`.
pub fn detect_format(content: &str) -> Option<ConfigFormat> {
    let re = crate::regex!(
        r"(?i)^\s*(?P<line>([;#]+(?P<comment>.*))|(?P<text>((?P<tag>[ \t,a-z0-9_:-]+)=)?[a-z0-9]+://.*)|((?P<yaml>[a-z0-9]+):.*)|(?P<assign>[ \t,a-z0-9_:-]+=[a-z0-9, \t_-]+))?$"
    );
    let mut format = None;
    for line in split_lines(content) {
        let caps = re.captures(line)?;
        if caps.name("yaml").is_some() {
            return Some(ConfigFormat::Yaml);
        }
        if caps.name("text").is_some() || caps.name("assign").is_some() {
            return Some(ConfigFormat::Text);
        }
        format = Some(ConfigFormat::Text);
    }
    format
}

/// `re.split(r"\r*\n", content)`.
pub(super) fn split_lines(content: &str) -> Vec<&str> {
    crate::regex!(r"\r*\n").split(content).collect()
}

/// `ConfigBase.config_parse_text`.
pub(super) fn parse_text(content: &str) -> Parsed {
    let re = crate::regex!(
        r"(?i)^\s*(?P<line>([;#]+(?P<comment>.*))|(\s*(?P<tags>[a-z0-9, \t_:-]+)\s*=|=)?\s*((?P<url>[a-z0-9]{1,32}://.*)|(?P<assign>[a-z0-9, \t_-]+))|include\s+(?P<config>.+))?\s*$"
    );
    let mut out = Parsed::default();
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for (no, line) in split_lines(content).into_iter().enumerate() {
        let no = no + 1;
        let Some(c) = re.captures(line) else {
            log::error!("Invalid TEXT configuration format found on line {no}.");
            return Parsed::default();
        };
        let (url, assign, include) = (c.name("url"), c.name("assign"), c.name("config"));
        if let Some(inc) = include {
            out.includes.push(inc.as_str().trim().to_owned());
            continue;
        }
        let tags_raw = c.name("tags").map(|m| m.as_str());
        if let Some(assign) = assign {
            let gs = crate::parse::parse_list(tags_raw);
            if gs.is_empty() {
                out.warnings.push(format!("Unparseable tag assignment - no group(s) on line {no}"));
                continue;
            }
            let tags = crate::parse::parse_list([assign.as_str()]);
            if tags.is_empty() {
                out.warnings.push(format!("Unparseable tag assignment - no tag(s) to assign on line {no}"));
                continue;
            }
            for g in gs {
                let i = match groups.iter().position(|(n, _)| *n == g) {
                    Some(i) => i,
                    None => {
                        groups.push((g.clone(), Vec::new()));
                        groups.len() - 1
                    }
                };
                for t in &tags {
                    if *t != g && !groups[i].1.contains(t) {
                        groups[i].1.push(t.clone());
                    }
                }
            }
            continue;
        }
        let Some(url) = url else { continue };
        let tags = crate::parse::parse_list(tags_raw);
        if tags.iter().any(|t| Tag::parse(t).retry.is_some()) {
            out.warnings.push(format!(
                "You can not specify a retry count as part of a service tag on line {no}; use ?retry=N in the URL instead."
            ));
            continue;
        }
        out.entries.push(RawEntry { url: url.as_str().trim().to_owned(), tags, location: format!("line {no}") });
    }
    normalize_groups(&mut groups);
    apply_groups(&mut out.entries, &groups);
    out
}

/// `GET_SCHEMA_RE.match`.
pub(super) fn get_schema(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^\s*(?P<schema>[a-z0-9]{1,32})://.*\n?\z");
    re.captures(url).map(|c| c["schema"].to_lowercase())
}
