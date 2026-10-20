//! `:shortcode:` emoji (`?emojis=yes`, `-j`, [`crate::Asset::interpret_emojis`]): GitHub's gemoji names from the `emojis` crate, applied the way Apprise's `apply_emojis` applies its own table.

/// Replace every known `:name:` (case-insensitive) with its emoji. Names never contain `:`, so at each colon the text up to the next one is the only candidate; an unknown one is left as written and its closing colon may open the next.
pub fn apply(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once(':') {
        out.push_str(before);
        match after.split_once(':').and_then(|(name, tail)| lookup(name).map(|e| (e, tail))) {
            Some((emoji, tail)) => {
                out.push_str(emoji);
                rest = tail;
            }
            None => {
                out.push(':');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The emoji of gemoji shortcode `name`, ignoring case.
fn lookup(name: &str) -> Option<&'static str> {
    if name.is_empty() || !name.is_ascii() {
        return None;
    }
    emojis::get_by_shortcode(&name.to_ascii_lowercase()).map(emojis::Emoji::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcodes() {
        assert_eq!(apply(":smile: :+1: :ThumbsUp: :-1:"), "😄 👍 👍 👎");
        // Expanded patterns: `:(raised_)?hand:`, `:runn(er|ing):`.
        assert_eq!(apply(":hand: :raised_hand: :runner: :running:"), "✋ ✋ 🏃 🏃");
        // Unknown names stay; their closing colon can open a known one.
        assert_eq!(apply("x:nope:smile: 10:30 :"), "x:nope😄 10:30 :");
        assert_eq!(apply("::smile::"), ":😄:");
        assert_eq!(apply("no colons"), "no colons");
    }

    /// Apprise's rule between the asset's `interpret_emojis` and a URL's `?emojis=`.
    #[test]
    fn asset_and_url_decide() {
        for (asset, query, on) in [
            (None, "", false),
            (Some(true), "", true),
            (Some(true), "?emojis=no", false),
            (None, "?emojis=yes", true),
            (Some(false), "?emojis=yes", false),
        ] {
            let t = crate::parse(&format!("json://localhost/x{query}")).unwrap();
            let asset = crate::Asset { interpret_emojis: asset, ..crate::Asset::default() };
            let prepared = t.prepare(&crate::Message::new(":rocket:"), &asset).unwrap();
            assert_eq!(prepared.pieces[0].body == "🚀", on, "{asset:?} {query}");
        }
    }
}
