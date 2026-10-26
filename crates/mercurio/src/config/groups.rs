//! Tag groups: `groups:` / `name=tags` assignments and their expansion.

use super::model::RawEntry;
use super::yaml::Yaml;
use super::yaml_doc::{yaml_list, yaml_set};

/// `__normalize_tag_groups`: expand groups of groups.
pub(super) fn normalize_groups(groups: &mut Vec<(String, Vec<String>)>) {
    fn get<'a>(g: &'a [(String, Vec<String>)], k: &str) -> Option<&'a Vec<String>> {
        g.iter().find(|(n, _)| n == k).map(|(_, v)| v)
    }
    fn set_of(g: &mut Vec<(String, Vec<String>)>, k: &str) -> usize {
        match g.iter().position(|(n, _)| n == k) {
            Some(i) => i,
            None => {
                g.push((k.to_string(), Vec::new()));
                g.len() - 1
            }
        }
    }
    fn union(a: &mut Vec<String>, b: impl IntoIterator<Item = String>) {
        for x in b {
            if !a.contains(&x) {
                a.push(x);
            }
        }
    }
    fn expand(
        g: &mut Vec<(String, Vec<String>)>,
        names: &[String],
        tags: &[String],
        ignore: &mut Vec<String>,
    ) -> Vec<String> {
        let mut results = Vec::new();
        for tag in tags {
            if ignore.contains(tag) {
                continue;
            }
            let i = set_of(g, tag);
            let members = g[i].1.clone();
            union(&mut results, members.iter().filter(|m| !names.contains(m)).cloned());
            let mut found: Vec<String> = members.into_iter().filter(|m| names.contains(m)).collect();
            found.sort();
            for gtag in found {
                if ignore.contains(&gtag) {
                    continue;
                }
                ignore.push(tag.clone());
                let expanded = expand(g, names, std::slice::from_ref(&gtag), ignore);
                let j = set_of(g, &gtag);
                g[j].1 = expanded.clone();
                union(&mut results, expanded);
                ignore.retain(|x| x != tag);
            }
        }
        results
    }
    let mut names: Vec<String> = groups.iter().map(|(n, _)| n.clone()).collect();
    names.sort();
    for tag in names.clone() {
        let exp = expand(groups, &names, std::slice::from_ref(&tag), &mut Vec::new());
        let i = set_of(groups, &tag);
        union(&mut groups[i].1, exp);
        if get(groups, &tag).is_some_and(|v| v.is_empty()) {
            crate::warning!("The group {tag} has no tags assigned to it");
            groups.retain(|(n, _)| n != &tag);
        }
    }
}

pub(super) fn apply_groups(entries: &mut [RawEntry], groups: &[(String, Vec<String>)]) {
    for e in entries {
        for (group, tags) in groups {
            if e.tags.iter().any(|t| tags.contains(t)) && !e.tags.contains(group) {
                e.tags.push(group.clone());
            }
        }
    }
}

pub(super) fn parse_groups(groups: &Yaml, into: &mut Vec<(String, Vec<String>)>) {
    let mut add = |key: &Yaml, tags: &Yaml| {
        let mut names = Vec::new();
        yaml_list(key, &mut names);
        names.sort();
        names.dedup();
        for group in names {
            let set: Vec<String> = if let Yaml::Seq(items) = tags {
                let mut s = Vec::new();
                for e in items {
                    if let Yaml::Map(m) = e {
                        s.extend(m.iter().map(|(k, _)| k.to_text()));
                    } else {
                        yaml_list(e, &mut s);
                    }
                }
                s
            } else {
                yaml_set(tags)
            };
            match into.iter_mut().find(|(n, _)| *n == group) {
                Some((_, existing)) => {
                    for t in set {
                        if !existing.contains(&t) {
                            existing.push(t);
                        }
                    }
                }
                None => {
                    let mut s = set;
                    s.sort();
                    s.dedup();
                    into.push((group, s));
                }
            }
        }
    };
    match groups {
        Yaml::Map(m) => {
            for (k, v) in m {
                add(k, v);
            }
        }
        Yaml::Seq(list) => {
            for e in list {
                if let Yaml::Map(m) = e {
                    for (k, v) in m {
                        add(k, v);
                    }
                }
            }
        }
        Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Str(_) => {}
    }
}
