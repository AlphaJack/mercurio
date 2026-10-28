//! Tags and tag filters.
//!
//! A [`TagFilter`] is a list of alternatives (OR); each alternative is a group of tags that must all be present (AND). The reserved tag `all` matches everything and services tagged `always` are selected by any filter. With no filter at all ([`TagFilter::untagged`]) only services without tags match.

use std::fmt;

use crate::parse::parse_list;

/// `MATCH_ALL_TAG`: a filter token matching every service.
pub(crate) const MATCH_ALL: &str = "all";
/// `MATCH_ALWAYS_TAG`: services carrying it are notified by every filter.
pub(crate) const MATCH_ALWAYS: &str = "always";

/// One tag with optional dispatch priority (`2:endpoint`) and retry (`endpoint:3`).
#[derive(Debug, Clone, Default)]
pub struct Tag {
    /// Lower-cased name; the identity of the tag.
    pub name: String,
    /// Dispatch priority from `2:name`; `0` when not written.
    pub priority: u64,
    /// The priority was written explicitly (`0:endpoint`).
    pub has_priority: bool,
    /// Call-level retry suffix; only valid in filters.
    pub retry: Option<u64>,
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Tag {}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl Tag {
    /// Parse `[priority:]name[:retry]`; anything else is a plain name (lower-cased, trimmed).
    pub fn parse(value: &str) -> Tag {
        let v = value.trim_matches(|c: char| c.is_whitespace());
        let re = crate::regex!(r"(?i)^(?:(?P<priority>[0-9]+):)?(?P<tag>[a-z0-9][a-z0-9_-]*)(?::(?P<retry>[0-9]+))?$");
        if let Some(c) = re.captures(v) {
            let priority = c.name("priority").map(|m| m.as_str().parse::<u64>());
            let (priority, has_priority) = match priority {
                Some(Ok(p)) => (p, true),
                _ => (0, false),
            };
            return Tag {
                name: c["tag"].to_lowercase(),
                priority,
                has_priority,
                retry: c.name("retry").and_then(|m| m.as_str().parse().ok()),
            };
        }
        Tag { name: v.to_lowercase(), ..Tag::default() }
    }
}

/// Parse a tag list (`"a, b c"`) into unique tags, keeping the first spelling of each name, sorted by name.
pub(crate) fn parse_tags<I, S>(values: I) -> Vec<Tag>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out: Vec<Tag> = Vec::new();
    for raw in parse_list(values) {
        let t = Tag::parse(&raw);
        if !t.name.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Which services to notify.
///
/// The three tag syntaxes in use read `"a,b"` differently, so there is one constructor for each:
///
/// | Constructor | Syntax | `"a,b"` means |
/// |---|---|---|
/// | [`TagFilter::parse`] | library strings | `a` or `b` |
/// | [`TagFilter::from_cli`] | CLI `-g`: each value is an AND group, values are alternatives | `a` and `b` |
/// | [`TagFilter::from_api`] | server `tag=`: commas separate alternatives, spaces join; blank means all | `a` or `b` |
///
/// ```
/// use mercurio::{Tag, TagFilter};
///
/// let devops = [Tag::parse("devops"), Tag::parse("critical")];
/// let always = [Tag::parse("always")];
///
/// // Library strings: every token is an alternative.
/// assert!(TagFilter::parse("devops, billing").matches(&devops));
/// // CLI: one `-g` value is an AND group, several values are alternatives.
/// assert!(TagFilter::from_cli(&["devops,critical"]).matches(&devops));
/// assert!(!TagFilter::from_cli(&["devops,billing"]).matches(&devops));
/// // `always` joins every tagged run, but not an untagged one.
/// assert!(TagFilter::parse("billing").matches(&always));
/// assert!(!TagFilter::untagged().matches(&always));
/// assert!(TagFilter::untagged().matches(&[]));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagFilter {
    /// `None`: untagged services only.
    groups: Option<Vec<Vec<String>>>,
    match_always: bool,
}

impl Default for TagFilter {
    /// Every service (`all`).
    fn default() -> Self {
        TagFilter::all()
    }
}

impl TagFilter {
    /// Match everything (`MATCH_ALL_TAG`).
    pub fn all() -> Self {
        TagFilter { groups: Some(vec![vec![MATCH_ALL.into()]]), match_always: true }
    }

    /// No filter: only services without tags (the CLI default without `--tag`).
    pub fn untagged() -> Self {
        TagFilter { groups: None, match_always: true }
    }

    /// Library string semantics (`notify(tag="a, b")`): every comma or space separated token is an alternative.
    pub fn parse(expr: &str) -> Self {
        let groups: Vec<Vec<String>> = parse_list([expr]).into_iter().map(|t| vec![t]).collect();
        TagFilter { groups: Some(groups), match_always: true }
    }

    /// Alternatives of AND groups: `[["a", "b"], ["c"]]` is `(a AND b) OR c`. Each inner string may itself hold several comma/space separated tags.
    pub fn any_of<I, G, S>(groups: I) -> Self
    where
        I: IntoIterator<Item = G>,
        G: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let groups = groups.into_iter().map(|g| parse_list(g)).collect();
        TagFilter { groups: Some(groups), match_always: true }
    }

    /// CLI semantics: each `--tag` value is an AND group (`-g "a,b"` requires both); several `--tag` values are alternatives. An empty list is [`TagFilter::untagged`].
    pub fn from_cli<S: AsRef<str>>(values: &[S]) -> Self {
        if values.is_empty() {
            return TagFilter::untagged();
        }
        TagFilter::any_of(values.iter().map(|v| [v.as_ref()]))
    }

    /// The `tag=` form of the API server: commas separate alternatives, spaces join tags that must all match. Blank means everything.
    pub fn from_api(expr: &str) -> Self {
        let expr = expr.trim();
        if expr.is_empty() {
            return TagFilter::all();
        }
        let groups = expr
            .split(',')
            .map(|g| g.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .filter(|g| !g.is_empty())
            .collect::<Vec<_>>();
        if groups.is_empty() {
            return TagFilter::all();
        }
        TagFilter { groups: Some(groups), match_always: true }
    }

    /// Disable the `always` rule: services tagged `always` are no longer selected by every filter.
    #[must_use]
    pub fn without_always(mut self) -> Self {
        self.match_always = false;
        self
    }

    /// The alternatives; `None` for an untagged-only filter.
    pub fn groups(&self) -> Option<&[Vec<String>]> {
        self.groups.as_deref()
    }

    /// Whether a filter token carries an explicit priority (`2:endpoint`).
    pub fn has_explicit_priority(&self) -> bool {
        self.groups.iter().flatten().flatten().any(|t| Tag::parse(t).has_priority)
    }

    /// The escalation chain and priority of a service with `tags` (Apprise's `_build_tag_chains`): the first single-tag alternative the service carries names its chain, at that tag's priority; anything else (AND groups, `always`) goes to the `""` chain at the most urgent priority among its tags that the filter names. A match-all or untagged filter has one chain at priority 0.
    pub(crate) fn chain_of(&self, tags: &[Tag]) -> (String, u64) {
        let Some(groups) = &self.groups else { return (String::new(), 0) };
        if groups.iter().all(|g| g.iter().all(|t| Tag::parse(t).name == MATCH_ALL)) {
            return (String::new(), 0);
        }
        for group in groups.iter().filter(|g| g.len() == 1) {
            let name = Tag::parse(&group[0]).name;
            if let Some(t) = tags.iter().find(|t| t.name == name) {
                return (name, t.priority);
            }
        }
        let named: Vec<String> = groups.iter().flatten().map(|t| Tag::parse(t).name).collect();
        let priority = tags.iter().filter(|t| named.contains(&t.name)).map(|t| t.priority).min().unwrap_or(0);
        (String::new(), priority)
    }

    /// The retry count of the first `tag:N` token that matches a service with `tags` (an exact `P:tag:N` also needs priority `P`), in the order the filter was written.
    pub(crate) fn retry_for(&self, tags: &[Tag]) -> Option<u64> {
        self.groups.iter().flatten().flatten().map(|t| Tag::parse(t)).filter(|ft| ft.retry.is_some()).find_map(|ft| {
            let hit = tags.iter().any(|t| t.name == ft.name && (!ft.has_priority || t.priority == ft.priority));
            if hit { ft.retry } else { None }
        })
    }

    /// `is_exclusive_match(logic, data)`.
    pub fn matches(&self, tags: &[Tag]) -> bool {
        let Some(groups) = &self.groups else { return tags.is_empty() };
        if groups.is_empty() {
            return tags.is_empty();
        }
        let always = [vec![MATCH_ALWAYS.to_owned()]];
        let extra: &[Vec<String>] = if self.match_always { &always } else { &[] };
        for group in groups.iter().chain(extra) {
            if group.is_empty() {
                return tags.is_empty();
            }
            if group.iter().all(|tok| token_matches(tok, tags)) {
                return true;
            }
        }
        false
    }
}

impl From<&str> for TagFilter {
    fn from(s: &str) -> Self {
        TagFilter::parse(s)
    }
}

fn token_matches(tok: &str, tags: &[Tag]) -> bool {
    let ft = Tag::parse(tok);
    if ft.name == MATCH_ALL {
        return true;
    }
    if !ft.has_priority {
        return tags.iter().any(|t| t.name == ft.name);
    }
    tags.iter().any(|t| t.name == ft.name && t.priority == ft.priority)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(s: &str) -> Vec<Tag> {
        parse_tags([s])
    }

    #[test]
    fn library_string_is_or() {
        let f = TagFilter::parse("a, b");
        assert!(f.matches(&tags("a")));
        assert!(f.matches(&tags("b")));
        assert!(!f.matches(&tags("c")));
        assert!(TagFilter::parse("a b").matches(&tags("b")));
    }

    #[test]
    fn groups_are_and() {
        let f = TagFilter::any_of([vec!["a", "b"], vec!["c"]]);
        assert!(f.matches(&tags("a,b")));
        assert!(!f.matches(&tags("a")));
        assert!(f.matches(&tags("c")));
        assert!(TagFilter::from_cli(&["a, b"]).matches(&tags("a b x")));
        assert!(!TagFilter::from_cli(&["a, b"]).matches(&tags("a")));
    }

    #[test]
    fn all_always_untagged() {
        assert!(TagFilter::all().matches(&tags("x")));
        assert!(TagFilter::all().matches(&[]));
        assert!(TagFilter::parse("x").matches(&tags("always")));
        assert!(!TagFilter::parse("x").without_always().matches(&tags("always")));
        assert!(TagFilter::untagged().matches(&[]));
        assert!(!TagFilter::untagged().matches(&tags("always")));
    }

    #[test]
    fn priority() {
        let t = Tag::parse("2:Endpoint");
        assert_eq!((t.name.as_str(), t.priority, t.has_priority), ("endpoint", 2, true));
        assert_eq!(Tag::parse("a:3").retry, Some(3));
        let data = vec![t];
        assert!(TagFilter::parse("endpoint").matches(&data));
        assert!(TagFilter::parse("2:endpoint").matches(&data));
        assert!(!TagFilter::parse("1:endpoint").matches(&data));
    }

    #[test]
    fn api() {
        let f = TagFilter::from_api("dev ops, prod");
        assert!(f.matches(&tags("dev,ops")));
        assert!(!f.matches(&tags("dev")));
        assert!(f.matches(&tags("prod")));
        assert!(TagFilter::from_api("").matches(&tags("x")));
    }
}
