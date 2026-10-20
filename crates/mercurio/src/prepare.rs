//! The message pipeline between [`Message`] and a service's `plan`: payload cap, escapes, format conversion, title merging and overflow.

use crate::convert;
use crate::error::{Error, Result};
use crate::message::{Message, NotifyFormat, OverflowMode};
use crate::service::{Context, Limits, Notify, ServiceDef};

/// One piece of a message after the pipeline, ready for `plan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// Title, converted to the service's format.
    pub title: String,
    /// Body, converted to the service's format.
    pub body: String,
    /// This piece carries the message's attachments.
    pub attach: bool,
}

/// All pieces of one message for one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMessage {
    /// The pieces to send, in order (more than one when the body was split).
    pub pieces: Vec<Piece>,
    /// Resolved format the service renders.
    pub format: NotifyFormat,
    /// The caller's declared input format (`None`: passthrough).
    pub input_format: Option<NotifyFormat>,
    /// Truncate mode keeps only the first attachment.
    pub first_attachment_only: bool,
}

/// URL-level options feeding the pipeline.
#[derive(Debug, Clone, Copy)]
pub struct PipelineOptions {
    pub format_override: Option<NotifyFormat>,
    pub overflow: OverflowMode,
    /// Replace `:shortcode:` emoji in the title and body before anything else.
    pub emojis: bool,
}

/// The format a service receives: the override when the service accepts it, else the body format when accepted, else the service's first format. A service with one format takes the override as is.
pub fn resolve_format(
    formats: &[NotifyFormat],
    override_: Option<NotifyFormat>,
    body: Option<NotifyFormat>,
) -> NotifyFormat {
    let first = formats.first().copied().unwrap_or_default();
    if formats.len() <= 1 {
        return override_.unwrap_or(first);
    }
    if let Some(o) = override_
        && formats.contains(&o)
    {
        return o;
    }
    if let Some(b) = body
        && formats.contains(&b)
    {
        return b;
    }
    first
}

/// Run the whole pipeline for one service.
pub fn prepare(
    def: &ServiceDef,
    service: &dyn Notify,
    opts: PipelineOptions,
    msg: &Message,
    ctx: &Context<'_>,
) -> Result<PreparedMessage> {
    let asset = ctx.asset;
    let input_format = msg.format.or(asset.body_format);
    let format = resolve_format(def.formats, opts.format_override, input_format);

    if msg.body.is_empty() && msg.attachments.is_empty() {
        return Err(Error::Message("no message body or attachment was specified".into()));
    }
    if msg.body.is_empty() && !def.attachments {
        return Err(Error::Message(format!("{} does not support attachments", def.name)));
    }

    // The body stays borrowed until a conversion changes it: it can be megabytes.
    let (mut title, mut body) = (msg.title.clone(), std::borrow::Cow::Borrowed(msg.body.as_str()));
    if opts.emojis {
        title = convert::emoji::apply(&title);
        body = convert::emoji::apply(&body).into();
    }
    if let Some(input) = input_format {
        body = convert::convert_between(input, format, &body).into();
        if !title.is_empty() && def.limits.title_maxlen == 0 {
            title = convert::convert_between(input, format, &title);
        }
    }

    let limits = service.limits(&title, &body, format, ctx).unwrap_or(def.limits);
    let passthrough = input_format.is_none();
    let overflow = opts.overflow;
    let chunks = apply_overflow(&title, &body, limits, overflow, format, passthrough);
    let dialect = !passthrough && service.convert("", format).is_some();
    let mut pieces: Vec<Piece> = Vec::new();
    for chunk in chunks {
        if !dialect {
            pieces.push(Piece { title: chunk.title, body: chunk.body, attach: false });
            continue;
        }
        let convert_fn = |b: &str| service.convert(b, format).unwrap_or_else(|| b.to_string());
        let bodies = match overflow {
            OverflowMode::Split if service.split_converted() => {
                convert::dialect::split_html(&convert_fn(&chunk.body), limits.body_maxlen, usize::MAX)
            }
            OverflowMode::Truncate if service.split_converted() => {
                convert::dialect::split_html(&convert_fn(&chunk.body), limits.body_maxlen, 1)
            }
            OverflowMode::Split => {
                convert::split_dialect_chunk(&chunk.body, limits.body_maxlen, &convert_fn, Some(format))
            }
            OverflowMode::Truncate => {
                vec![convert::truncate_dialect_chunk(&chunk.body, limits.body_maxlen, &convert_fn, Some(format))]
            }
            OverflowMode::Upstream => vec![convert_fn(&chunk.body)],
        };
        for (i, b) in bodies.into_iter().enumerate() {
            let title = if i == 0 { chunk.title.clone() } else { String::new() };
            pieces.push(Piece { title, body: b, attach: false });
        }
    }
    if let Some(p) = pieces.first_mut() {
        p.attach = !msg.attachments.is_empty();
    }
    Ok(PreparedMessage {
        pieces,
        format,
        input_format,
        first_attachment_only: overflow == OverflowMode::Truncate && msg.attachments.len() > 1,
    })
}

/// A chunk produced by [`apply_overflow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub title: String,
    pub body: String,
}

/// Drop leading line breaks (`\r`, `\n`, `\x0b`, `\x0c`) and trailing whitespace.
fn tidy_chunk(s: &str) -> String {
    s.trim_start_matches(['\r', '\n', '\x0b', '\x0c']).trim_end().to_string()
}

fn chunk(title: impl Into<String>, body: impl Into<String>) -> Chunk {
    Chunk { title: title.into(), body: body.into() }
}

/// Fit a message into `limits`: a service without a title gets it merged into the body, the title is cut to `title_maxlen`, the body to `body_max_line_count` lines, then truncated or split into pieces of at most `body_maxlen` characters (`0`: unlimited). Only the first piece carries the title.
pub fn apply_overflow(
    title: &str,
    body: &str,
    limits: Limits,
    overflow: OverflowMode,
    format: NotifyFormat,
    passthrough: bool,
) -> Vec<Chunk> {
    let mut title = title.trim().to_string();
    let mut body = body.trim_end().to_string();
    if limits.title_maxlen == 0 && !title.is_empty() {
        body = match format {
            NotifyFormat::Html => format!("<b>{title}</b><br />\r\n{body}"),
            NotifyFormat::Markdown if !passthrough => {
                format!("# {}\n{body}", title.trim_start_matches(['#', '-', ' ']))
            }
            NotifyFormat::Text | NotifyFormat::Markdown => format!("{title}\r\n{body}"),
        };
        title.clear();
    }
    if limits.body_max_line_count > 0 {
        let re = crate::regex!(r"\r*\n");
        body = re.split(&body).take(limits.body_max_line_count).collect::<Vec<_>>().join("\r\n");
    }
    if overflow == OverflowMode::Upstream {
        return vec![chunk(title, body)];
    }
    if limits.title_maxlen > 0 && title.chars().count() > limits.title_maxlen {
        title = title.chars().take(limits.title_maxlen).collect::<String>().trim_end().to_string();
    }
    let max = limits.body_maxlen;
    if max == 0 || body.chars().count() <= max {
        return vec![chunk(title, body)];
    }
    let pieces = convert::smart_split(&body, max as isize, format);
    if overflow == OverflowMode::Truncate {
        let mut first = tidy_chunk(pieces.first().map(String::as_str).unwrap_or(""));
        // A dangling backslash would escape whatever the service appends.
        if format == NotifyFormat::Markdown && first.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1 {
            first.pop();
        }
        return vec![chunk(title, first)];
    }
    // A piece that was only line breaks would go out as an empty message.
    let mut out: Vec<Chunk> =
        pieces.iter().map(|p| tidy_chunk(p)).filter(|p| !p.is_empty()).map(|p| chunk("", p)).collect();
    match out.first_mut() {
        Some(first) => first.title = title,
        None => out.push(chunk(title, "")),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Asset;

    fn bodies(c: &[Chunk]) -> Vec<(&str, &str)> {
        c.iter().map(|c| (c.title.as_str(), c.body.as_str())).collect()
    }

    #[test]
    fn title_merges_when_service_has_no_title() {
        let limits = Limits { title_maxlen: 0, ..Limits::DEFAULT };
        let p = apply_overflow("T", "B", limits, OverflowMode::Upstream, NotifyFormat::Text, true);
        assert_eq!(bodies(&p), vec![("", "T\r\nB")]);
        let p = apply_overflow("T", "B", limits, OverflowMode::Upstream, NotifyFormat::Html, true);
        assert_eq!(p[0].body, "<b>T</b><br />\r\nB");
    }

    #[test]
    fn truncate() {
        let limits = Limits { title_maxlen: 5, body_maxlen: 10, body_max_line_count: 0 };
        let p = apply_overflow("Title long", "0123456789ABC", limits, OverflowMode::Truncate, NotifyFormat::Text, true);
        assert_eq!(bodies(&p), vec![("Title", "0123456789")]);
    }

    #[test]
    fn split_drops_empty_pieces() {
        let limits = Limits { title_maxlen: 5, body_maxlen: 10, body_max_line_count: 0 };
        // A window that opens with a line break or a space yields no empty piece.
        for body in
            [format!("{}\r\n{}", "a".repeat(9), "b".repeat(15)), format!("{} {}", "a".repeat(10), "b".repeat(15))]
        {
            let p = apply_overflow("T", &body, limits, OverflowMode::Split, NotifyFormat::Text, true);
            assert!(p.iter().all(|c| !c.body.is_empty()), "{:?}", bodies(&p));
            assert_eq!(p[0].title, "T");
            assert_eq!(p.len(), 3, "{:?}", bodies(&p));
        }
    }

    #[test]
    fn formats() {
        use NotifyFormat::*;
        assert_eq!(resolve_format(&[Text], Some(Html), None), Html);
        assert_eq!(resolve_format(&[Text, Markdown], None, Some(Markdown)), Markdown);
        assert_eq!(resolve_format(&[Text, Markdown], Some(Html), Some(Html)), Text);
    }

    #[test]
    fn pipeline_conversion() {
        let msg = Message::new("**hi** :smile:").title(":rocket: Up");
        let asset = Asset::default();
        let body = |url: &str, msg: &Message, asset: &Asset| {
            let p = crate::parse(url).unwrap().prepare(msg, asset).unwrap();
            (p.pieces[0].title.clone(), p.pieces[0].body.clone())
        };
        assert_eq!(body("json://localhost", &msg, &asset), (":rocket: Up".into(), "**hi** :smile:".into()));

        // Declared Markdown is converted for an HTML service (title kept apart).
        let md = msg.clone().format(NotifyFormat::Markdown);
        assert_eq!(body("json://localhost?format=html", &md, &asset).1, "<p><strong>hi</strong> :smile:</p>");
    }
}
