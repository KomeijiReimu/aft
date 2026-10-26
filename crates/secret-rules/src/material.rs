//! P3: what a key may be, and how it is encoded at each location.
//!
//! A key that cannot be transported safely refuses the request (the caller
//! never sees partial material). Refusals name the rule that rejected the key,
//! never the key.

use crate::location::Location;

/// Shortest admissible key, in bytes. The scrubber derives base64 patterns
/// from a key's whole-byte alignment, and 16 bytes keeps every pattern
/// non-empty (S1, P3).
pub const MIN_KEY_LEN: usize = 16;

/// Why a key cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialRefusal {
    /// Zero-length key material.
    Empty,
    /// Fewer than [`MIN_KEY_LEN`] bytes.
    TooShort,
    /// The key text appears inside its own label's placeholder.
    SubstringOfPlaceholder,
    /// A header value cannot carry this byte (CTL, or a byte above 0x7E).
    NonVisibleHeaderByte,
}

/// Check that `key` may be used for `label`.
pub fn check_admissible(
    key: &[u8],
    label: &str,
    location: &Location,
) -> Result<(), MaterialRefusal> {
    if key.is_empty() {
        return Err(MaterialRefusal::Empty);
    }
    // The placeholder check runs before the length floor: a key that is part
    // of its own placeholder is refused for that reason, whatever its length,
    // because the length floor alone would describe it wrongly.
    if key_is_substring_of_placeholder(key, label) {
        return Err(MaterialRefusal::SubstringOfPlaceholder);
    }
    if key.len() < MIN_KEY_LEN {
        return Err(MaterialRefusal::TooShort);
    }
    match location {
        // A header value is a byte string on the wire; anything outside the
        // visible ASCII range cannot be sent as one, and a control byte would
        // let a key forge header structure.
        Location::Bearer | Location::Header(_) => {
            if !key.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
                return Err(MaterialRefusal::NonVisibleHeaderByte);
            }
        }
        Location::Query(_) | Location::Json(_) => {}
    }
    Ok(())
}

/// True when the key text appears inside the label's own placeholder text, or
/// the placeholder appears inside the key.
///
/// Either direction exposes the key: a key that is a fragment of its label's
/// placeholder would appear in every substituted request, and a key that
/// contains the whole placeholder would be rewritten by the scrubber.
pub fn key_is_substring_of_placeholder(key: &[u8], label: &str) -> bool {
    let placeholder = crate::placeholder::placeholder_text(label);
    let placeholder = placeholder.as_bytes();
    bytes_contain(placeholder, key) || bytes_contain(key, placeholder)
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Encode `key` for `location`, or explain why the location cannot carry it.
///
/// `json_escape` marks the S1 JSON form used by the scrubber; callers that
/// substitute into a JSON body use [`Location::Json`] instead.
pub fn encode_for_location(
    key: &[u8],
    label: &str,
    location: &Location,
) -> Result<Vec<u8>, MaterialRefusal> {
    check_admissible(key, label, location)?;
    Ok(match location {
        Location::Bearer => {
            let mut out = b"Bearer ".to_vec();
            out.extend_from_slice(key);
            out
        }
        Location::Header(_) => key.to_vec(),
        Location::Query(_) => percent_encode_form(key, false),
        Location::Json(_) => json_escape(key).into_bytes(),
    })
}

/// Percent-encode every byte outside the RFC 3986 unreserved set, uppercase
/// hex.
///
/// `keep_spaces_literal` leaves `0x20` alone, which the scrubber needs to
/// catch the common variant of form encoding.
pub(crate) fn percent_encode_form(key: &[u8], keep_spaces_literal: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() * 3);
    for byte in key {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if unreserved || (keep_spaces_literal && *byte == b' ') {
            out.push(*byte);
        } else {
            out.extend_from_slice(format!("%{byte:02X}").as_bytes());
        }
    }
    out
}

/// RFC 8259 string escaping of arbitrary key bytes.
///
/// Valid UTF-8 is kept as characters; invalid bytes are written as `\ufffd`
/// so the escaped text is always a legal JSON string body.
pub fn json_escape(key: &[u8]) -> String {
    let mut out = String::with_capacity(key.len());
    let mut rest = key;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                escape_str(text, &mut out);
                break;
            }
            Err(err) => {
                let (valid, after) = rest.split_at(err.valid_up_to());
                escape_str(std::str::from_utf8(valid).unwrap_or_default(), &mut out);
                out.push_str("\\ufffd");
                let skip = err.error_len().unwrap_or(after.len());
                rest = after.get(skip..).unwrap_or_default();
            }
        }
    }
    out
}

fn escape_str(text: &str, out: &mut String) {
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
}

/// RFC 3986 path normalization helper shared with the scrubber: `true` when
/// `byte` may stay literal inside a normalized path's encoded form.
pub(crate) fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}
