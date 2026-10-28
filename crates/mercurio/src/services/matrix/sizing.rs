//! Matrix event size accounting. [`body_char_limit`] sizes direct sends (`Notify::message_limits`); the flat limits (65000, 40000 with E2EE) apply to webhooks.

/// Matrix's hard event-size ceiling.
pub(crate) const MATRIX_EVENT_BYTE_LIMIT: usize = 65536;
/// Room for homeserver-added event metadata.
pub(crate) const MATRIX_EVENT_SAFETY_MARGIN: usize = 4000;
/// JSON fields around plaintext or encrypted message content.
pub(crate) const MATRIX_CONTENT_JSON_OVERHEAD: usize = 200;
/// Unpadded base64 of a 32-byte key.
pub(crate) const MATRIX_E2EE_KEY_LEN: usize = 43;
/// Fallback device-id cost before the device id is known.
pub(crate) const MATRIX_DEVICE_ID_FALLBACK_BYTES: usize = 512;

/// Serialised size of a Megolm envelope with empty ciphertext and device id.
pub(crate) fn e2ee_envelope_structural_bytes() -> usize {
    let x = "x".repeat(MATRIX_E2EE_KEY_LEN);
    let v = serde_json::json!({
        "algorithm": "m.megolm.v1.aes-sha2",
        "ciphertext": "",
        "sender_key": x,
        "session_id": x,
        "device_id": "",
    });
    v.to_string().len()
}

#[cfg(test)]
pub(crate) fn utf8_char_len(ch: char) -> usize {
    ch.len_utf8()
}

/// A character's UTF-8 cost after JSON string escaping.
pub(crate) fn json_char_bytes(ch: char) -> usize {
    match ch {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// Largest input accepted by a non-decreasing cost function.
pub(crate) fn max_byte_budget(cost: impl Fn(usize) -> usize, byte_budget: usize, ceiling: usize) -> usize {
    if cost(0) > byte_budget {
        return 0;
    }
    let (mut low, mut high) = (0, ceiling);
    while low < high {
        let middle = (low + high).div_ceil(2);
        if cost(middle) <= byte_budget {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
}

/// Character limit safe for every chunk of `body` (sliding window).
pub(crate) fn fit_char_limit(body: &str, byte_budget: usize, cost: impl Fn(usize) -> usize) -> usize {
    let chars: Vec<char> = body.chars().collect();
    if chars.is_empty() {
        return 1;
    }
    let ceiling = byte_budget * 16 + 1024;
    let target = max_byte_budget(cost, byte_budget, ceiling);
    let mut window = 0usize;
    let mut left = 0usize;
    let mut shortest_over: Option<usize> = None;
    for (right, ch) in chars.iter().enumerate() {
        window += json_char_bytes(*ch);
        while window > target {
            let len = right - left + 1;
            if shortest_over.is_none_or(|s| len < s) {
                shortest_over = Some(len);
            }
            window -= json_char_bytes(chars[left]);
            left += 1;
        }
    }
    match shortest_over {
        None => chars.len(),
        Some(s) => s.saturating_sub(1).max(1),
    }
}

pub(crate) fn device_id_overhead_bytes(device_id: Option<&str>) -> usize {
    match device_id {
        None | Some("") => MATRIX_DEVICE_ID_FALLBACK_BYTES,
        Some(d) => d.chars().map(json_char_bytes).sum(),
    }
}

/// JSON bytes added by Matrix title wrappers.
pub(crate) fn title_overhead_bytes(title: &str, rich: bool) -> usize {
    if title.is_empty() {
        return 0;
    }
    let plain: usize = format!("# {title}\r\n").chars().map(json_char_bytes).sum();
    if !rich {
        return plain;
    }
    let html = crate::util::escape_html(title, false, false);
    plain + format!("<h1>{html}</h1><br/>").chars().map(json_char_bytes).sum::<usize>()
}

/// Unpadded base64 length of `n` bytes.
pub(crate) fn b64_unpadded_len(n: usize) -> usize {
    let (full, rem) = (n / 3, n % 3);
    if rem == 0 { full * 4 } else { full * 4 + rem + 1 }
}

fn varint_len(n: usize) -> usize {
    if n == 0 { 1 } else { (usize::BITS - n.leading_zeros()).div_ceil(7) as usize }
}

/// Predicted base64 Megolm ciphertext length.
pub(crate) fn predict_megolm_ciphertext_len(plaintext_len: usize, counter: usize) -> usize {
    let padded = (plaintext_len / 16 + 1) * 16;
    let counter_field = 1 + varint_len(counter);
    let ct_field = 1 + varint_len(padded) + padded;
    let body = 1 + counter_field + ct_field;
    b64_unpadded_len(body + 8 + 64)
}

/// Estimated final event size of a chunk.
pub(crate) fn wire_cost(content_bytes: usize, rich: bool, e2ee: bool, title_bytes: usize, device_id: Option<&str>) -> usize {
    let mult = if rich { 2 } else { 1 };
    let inner = content_bytes * mult + title_bytes + MATRIX_CONTENT_JSON_OVERHEAD;
    if !e2ee {
        return inner;
    }
    predict_megolm_ciphertext_len(inner, 0) + e2ee_envelope_structural_bytes() + device_id_overhead_bytes(device_id)
}

/// Safe Matrix body limit (characters) for one notification.
pub(crate) fn body_char_limit(body: &str, title: &str, rich: bool, e2ee: bool, device_id: Option<&str>) -> usize {
    let title_bytes = title_overhead_bytes(title, rich);
    let budget = MATRIX_EVENT_BYTE_LIMIT - MATRIX_EVENT_SAFETY_MARGIN;
    fit_char_limit(body, budget, |c| wire_cost(c, rich, e2ee, title_bytes, device_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jb(s: &str) -> usize {
        s.chars().map(json_char_bytes).sum()
    }

    #[test]
    fn char_costs() {
        assert_eq!(utf8_char_len('a'), 1);
        assert_eq!(utf8_char_len('é'), 2);
        assert_eq!(utf8_char_len('中'), 3);
        assert_eq!(utf8_char_len('😀'), 4);
        assert_eq!(json_char_bytes('"'), 2);
        assert_eq!(json_char_bytes('\\'), 2);
        for c in ['\u{8}', '\u{c}', '\n', '\r', '\t'] {
            assert_eq!(json_char_bytes(c), 2);
        }
        assert_eq!(json_char_bytes('\0'), 6);
        assert_eq!(json_char_bytes('\u{1f}'), 6);
        assert_eq!(json_char_bytes('中'), 3);
    }

    #[test]
    fn budgets() {
        assert_eq!(max_byte_budget(|v| v + 10, 110, 1000), 100);
        assert_eq!(max_byte_budget(|v| v + 1000, 10, 1000), 0);
    }

    #[test]
    fn title_and_device_overhead() {
        assert_eq!(title_overhead_bytes("", false), 0);
        assert_eq!(title_overhead_bytes("hi", false), jb("# hi\r\n"));
        assert_eq!(title_overhead_bytes("hi", true), jb("# hi\r\n") + jb("<h1>hi</h1><br/>"));
        assert_eq!(title_overhead_bytes("<b>", true), jb("# <b>\r\n") + jb("<h1>&lt;b&gt;</h1><br/>"));
        assert_eq!(title_overhead_bytes(&"\u{1}".repeat(10), false), jb("# \r\n") + 60);
        assert_eq!(device_id_overhead_bytes(None), MATRIX_DEVICE_ID_FALLBACK_BYTES);
        assert_eq!(device_id_overhead_bytes(Some("ABCDEFGHIJ")), 10);
    }

    #[test]
    fn envelope_and_prediction() {
        assert_eq!(e2ee_envelope_structural_bytes(), 185);
        // Reference value.
        assert_eq!(predict_megolm_ciphertext_len(100, 0), 252);
        assert_eq!(b64_unpadded_len(32), 43);
        assert_eq!(b64_unpadded_len(3), 4);
        // 100 bytes -> padded 112 -> body 1 + 2 + (1 + 1 + 112) = 117 -> + 72 = 189 bytes.
        assert_eq!(predict_megolm_ciphertext_len(100, 0), b64_unpadded_len(189));
    }

    #[test]
    fn limits() {
        assert_eq!(fit_char_limit("", 100, |c| c), 1);
        let small = body_char_limit("hello", "title", false, false, None);
        assert_eq!(small, 5);
        let big = "a".repeat(100_000);
        let lim = body_char_limit(&big, "", false, false, None);
        assert_eq!(lim, MATRIX_EVENT_BYTE_LIMIT - MATRIX_EVENT_SAFETY_MARGIN - MATRIX_CONTENT_JSON_OVERHEAD);
        assert_eq!(lim, 61336);
        assert_eq!(body_char_limit(&big, "", false, true, Some("DEV")), 45719);
        let rich = body_char_limit(&big, "", true, false, None);
        assert_eq!(rich, lim / 2);
        // Escape-heavy bodies get a lower limit.
        let quotes = "\"".repeat(100_000);
        assert_eq!(body_char_limit(&quotes, "", false, false, None), 30668);
    }

    #[test]
    fn fit_limit_is_linear() {
        let body = "a".repeat(1_000_000);
        assert!(fit_char_limit(&body, 61536, |w| w + 200) > 0);
    }
}
