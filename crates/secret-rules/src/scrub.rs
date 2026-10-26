//! S1 and S2: representations of a key, and a streaming scrubber.
//!
//! A key shorter than [`crate::material::MIN_KEY_LEN`] never reaches this
//! module (P3 refuses it), which is what keeps every derived pattern non-empty.
//!
//! Two properties shape the design:
//!
//! * **Release never depends on the secret.** The scrubber always holds back
//!   the tail of the stream that is shorter than the longest pattern, whatever
//!   its content. A response that continues a secret prefix is therefore not
//!   treated differently from one that does not, and the release pattern cannot
//!   be used to guess the key one byte at a time.
//! * **A complete match is never split.** Matching runs on the whole window
//!   first, so a key that ends exactly at the holdback boundary is replaced
//!   before any part of it is released.
//!
//! Encodings are matched by decoding rather than by spelling them out: the
//! window is percent-decoded (and form-decoded, JSON-unescaped, hex-decoded or
//! base64-decoded where the bytes look like one of those) and compared with the
//! key. That covers every escape-case and selective-escaping choice inside one
//! family without ever enumerating them.

pub use crate::material::json_escape;
use crate::material::percent_encode_form;
use crate::placeholder::PLACEHOLDER_PREFIX;
use crate::work::Counted;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// Why a key cannot be turned into scrub patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubError {
    /// Zero-length key.
    Empty,
    /// Fewer than the P3 minimum.
    TooShort,
}

/// The encoding family a decoded match was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// The key bytes themselves.
    Raw,
    /// `%XX` escapes, with either hex case and any selection of escapes.
    Percent,
    /// `+`-for-space form encoding around a key that contains a space.
    Form,
    /// A JSON string body with `\/`, `\"`, `\\` and `\uXXXX` escapes.
    Json,
    /// Hex digits in any case.
    Hex,
}

/// Every literal a response may use for one key (S1).
///
/// `Debug` reports only the shape: the patterns themselves are the key in
/// several encodings, so printing them would print the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPatterns {
    /// Sorted longest first, so a longer spelling is tried before a shorter
    /// one that sits inside it.
    patterns: Vec<Zeroizing<Vec<u8>>>,
    /// Length of the key itself; decoded matches never shrink below it.
    key_len: usize,
    /// Longest representation a match can consume. An escape family can spell
    /// one key byte with six source bytes (`\u00e9` in JSON), so this is larger
    /// than the longest literal pattern.
    longest_consumed: usize,
}

impl std::fmt::Debug for KeyPatterns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPatterns")
            .field("count", &self.patterns.len())
            .field("key_len", &self.key_len)
            .field("longest", &self.longest())
            .finish()
    }
}

impl KeyPatterns {
    /// Derive the S1 representations of `key`.
    pub fn derive(key: &[u8]) -> Result<Self, ScrubError> {
        if key.is_empty() {
            return Err(ScrubError::Empty);
        }
        if key.len() < crate::material::MIN_KEY_LEN {
            return Err(ScrubError::TooShort);
        }
        let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();
        set.insert(key.to_vec());
        set.extend(base64_patterns(key));
        set.extend(percent_patterns(key));
        set.extend(hex_patterns(key));
        let json = json_escape(key);
        if !json.is_empty() {
            set.insert(json.into_bytes());
        }
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = set.into_iter().map(Zeroizing::new).collect();
        patterns.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        Ok(Self {
            patterns,
            key_len: key.len(),
            // The widest source span any family can produce for this key.
            longest_consumed: max_consumed_len(key.len()),
        })
    }

    /// The literal spellings, longest first.
    pub fn patterns(&self) -> impl Iterator<Item = &[u8]> {
        self.patterns.iter().map(|pattern| pattern.as_slice())
    }

    /// Number of distinct representations.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// True when no pattern was derived; impossible for an admissible key.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Longest pattern, which sets the holdback window (S2).
    pub fn longest(&self) -> usize {
        self.patterns.first().map_or(0, |pattern| pattern.len())
    }

    /// The key length the decoded families must reproduce.
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// Longest source span a completed match can consume.
    pub fn longest_consumed(&self) -> usize {
        self.longest_consumed
    }
}

/// Base64 forms: standard and URL-safe alphabets, padded and unpadded, matched
/// on the stable core of all three byte alignments plus the whole key.
///
/// A key inside a larger base64 payload is matched by decoding (see
/// [`MatcherSet::scrub_window`]), so the literals here only need to catch the
/// key standing alone.
pub fn base64_patterns(key: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for offset in 0..3 {
        let Some(tail) = key.get(offset..) else {
            continue;
        };
        let core_end = tail.len() - tail.len() % 3;
        let core = &tail[..core_end];
        if core.is_empty() {
            continue;
        }
        for alphabet in [BASE64_STANDARD, BASE64_URL_SAFE] {
            let encoded = base64_encode(core, alphabet, false);
            if !encoded.is_empty() {
                out.push(encoded);
            }
        }
    }
    for alphabet in [BASE64_STANDARD, BASE64_URL_SAFE] {
        let unpadded = base64_encode(key, alphabet, false);
        if !unpadded.is_empty() {
            out.push(unpadded);
        }
        let padded = base64_encode(key, alphabet, true);
        if !padded.is_empty() {
            out.push(padded);
        }
    }
    out
}

/// The RFC 4648 standard alphabet, exposed for tests and callers that build
/// padded forms themselves.
pub fn base64_standard() -> &'static [u8; 64] {
    BASE64_STANDARD
}

/// The RFC 4648 URL-safe alphabet.
pub fn base64_url_safe() -> &'static [u8; 64] {
    BASE64_URL_SAFE
}

const BASE64_STANDARD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Minimal base64 encoder over one RFC 4648 alphabet.
pub fn base64_encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[((triple >> 18) & 0x3f) as usize]);
        out.push(alphabet[((triple >> 12) & 0x3f) as usize]);
        if chunk.len() > 1 {
            out.push(alphabet[((triple >> 6) & 0x3f) as usize]);
        } else if pad {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[(triple & 0x3f) as usize]);
        } else if pad {
            out.push(b'=');
        }
    }
    out
}

/// Percent-encoded forms: every byte as `%XX`, and RFC 3986 with unreserved
/// bytes literal, plus the form variant that leaves spaces literal.
pub fn percent_patterns(key: &[u8]) -> Vec<Vec<u8>> {
    let mut all = Vec::with_capacity(key.len() * 3);
    for byte in key {
        all.extend_from_slice(format!("%{byte:02X}").as_bytes());
    }
    vec![
        all,
        percent_encode_form(key, false),
        percent_encode_form(key, true),
    ]
}

/// Hex forms: the whole key lower- and upper-case. Mixed case is caught by the
/// hex decoder, not by the spellings.
pub fn hex_patterns(key: &[u8]) -> Vec<Vec<u8>> {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut lower = Vec::with_capacity(key.len() * 2);
    let mut upper = Vec::with_capacity(key.len() * 2);
    for b in key {
        lower.push(LOWER[(b >> 4) as usize]);
        lower.push(LOWER[(b & 0x0f) as usize]);
        upper.push(UPPER[(b >> 4) as usize]);
        upper.push(UPPER[(b & 0x0f) as usize]);
    }
    vec![lower, upper]
}

/// The replacement for a scrubbed key, per label.
pub fn placeholder_for(label: &str) -> Vec<u8> {
    (format!("{}{label}", PLACEHOLDER_PREFIX) + "}}").into_bytes()
}

/// One installed matcher set with the text it is replaced by.
pub struct MatcherSet {
    /// The key itself, kept zeroizing for the lifetime of the matcher.
    key: Zeroizing<Vec<u8>>,
    patterns: KeyPatterns,
    replacement: Vec<u8>,
}

impl std::fmt::Debug for MatcherSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatcherSet")
            .field("label_replacement", &self.replacement)
            .field("patterns", &self.patterns.len())
            .finish()
    }
}

impl MatcherSet {
    /// Derive matchers for `key` and the placeholder they are replaced with.
    pub fn new(label: &str, key: &[u8]) -> Result<Self, ScrubError> {
        Ok(Self {
            key: Zeroizing::new(key.to_vec()),
            patterns: KeyPatterns::derive(key)?,
            replacement: placeholder_for(label),
        })
    }

    /// The replacement text.
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }

    /// The literal spellings, longest first.
    pub fn patterns(&self) -> impl Iterator<Item = &[u8]> {
        self.patterns.patterns()
    }

    /// Longest pattern.
    pub fn longest(&self) -> usize {
        self.patterns.longest()
    }

    /// Longest representation this matcher can consume.
    pub fn longest_consumed(&self) -> usize {
        self.patterns.longest_consumed()
    }

    /// The key length a decoded family must reproduce.
    pub fn key_len(&self) -> usize {
        self.patterns.key_len()
    }

    /// The key bytes, for the decoded comparisons.
    fn key(&self) -> &[u8] {
        &self.key
    }

    /// Every span of `window` that holds this matcher's key, sorted by start
    /// and free of overlaps.
    ///
    /// The spans index the input only; the replacement text is never part of
    /// the window, so the caller applies them to a copy of the original bytes
    /// without ever rescanning generated text. The scan is one pass: base64
    /// tokens are decoded once each, and every other byte is tried once.
    fn find_spans(&self, window: &[u8]) -> Vec<(usize, usize)> {
        let tokens = self.find_base64_spans(window);
        let mut spans: Vec<(usize, usize)> = Vec::with_capacity(tokens.len());
        let mut next_token = 0;
        let mut index = 0;
        while index < window.len() {
            // A base64 token that decodes to the key is replaced whole, and its
            // bytes are not tried again one by one.
            if let Some(&(start, end)) = tokens.get(next_token) {
                if start <= index {
                    push_merged(&mut spans, (start, end));
                    next_token += 1;
                    index = index.max(end);
                    continue;
                }
            }
            // Cheap pre-filter: every family's match starts with an escape
            // introducer (`%`, `\`), a base64 or hex character or the key's
            // own first byte.
            if !self.can_start_match(window[index]) {
                index += 1;
                continue;
            }
            match self.try_match_at(window, index) {
                Some((end, _family)) => {
                    push_merged(&mut spans, (index, end));
                    index = end;
                }
                None => index += 1,
            }
        }
        // A match can end past the start of the last tokens; they still count.
        for &(start, end) in tokens.get(next_token..).unwrap_or_default() {
            push_merged(&mut spans, (start, end));
        }
        spans
    }

    /// True when one representation of the key can begin with `byte`.
    fn can_start_match(&self, byte: u8) -> bool {
        byte == b'%'
            || byte == b'\\'
            || is_base64_byte(byte)
            || self.key().first().is_some_and(|first| *first == byte)
    }

    /// Every base64 token in `window` that decodes to the key, once per token.
    ///
    /// A token is the maximal run of base64 characters around the key. Decoding
    /// it once per alignment and replacing it whole keeps the work linear in the
    /// window, and covers the token's edge bytes too.
    fn find_base64_spans(&self, window: &[u8]) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let mut index = 0;
        while index < window.len() {
            if !is_base64_byte(window[index]) {
                index += 1;
                continue;
            }
            let start = index;
            while index < window.len() && is_base64_byte(window[index]) {
                index += 1;
            }
            let run = &window[start..index];
            // A key may begin inside the token; every offset of the token is a
            // possible alignment, and `base64_run_contains` tries four of them
            // per start, so test the whole token once.
            if base64_run_contains(run, self.key()) {
                spans.push((start, index));
            }
        }
        spans
    }

    /// The end of a key representation starting at `index`, if one starts
    /// there.
    fn try_match_at(&self, window: &[u8], index: usize) -> Option<(usize, Family)> {
        let key = self.key();
        // Base64 is handled by `find_base64_spans` over whole tokens, before
        // this per-byte pass: a literal spelling of part of the key is a prefix
        // of the token that contains the whole key, and replacing the token
        // covers the key's edge bytes as well.
        // Literal spellings next: they are exact and cheapest.
        for pattern in self.patterns() {
            if window.len() >= index + pattern.len()
                && &window[index..index + pattern.len()] == pattern
            {
                return Some((index + pattern.len(), Family::Raw));
            }
        }
        // Then the decoded escape families.
        if let Some(end) = match_percent(window, index, key) {
            return Some((end, Family::Percent));
        }
        if let Some(end) = match_form(window, index, key) {
            return Some((end, Family::Form));
        }
        if let Some(end) = match_json(window, index, key) {
            return Some((end, Family::Json));
        }
        if let Some(end) = match_hex(window, index, key) {
            return Some((end, Family::Hex));
        }
        None
    }
}

/// Append `span` to `spans`, which are sorted by start, merging it with the
/// last span when the two overlap.
///
/// Two overlapping matches of one key are replaced as one: keeping only the
/// first would leave the second's leading bytes, which spell part of the key.
fn push_merged(spans: &mut Vec<(usize, usize)>, span: (usize, usize)) {
    match spans.last_mut() {
        Some(last) if span.0 < last.1 => last.1 = last.1.max(span.1),
        _ => spans.push(span),
    }
}

/// A `%XX` run at `index` that decodes to the key, with either hex case and any
/// selection of escapes.
fn match_percent(window: &[u8], index: usize, key: &[u8]) -> Option<usize> {
    let mut cursor = index;
    let mut decoded = Zeroizing::new(Vec::new());
    while cursor < window.len() && decoded.len() < key.len() {
        let byte = window[cursor];
        if byte == b'%' {
            let (value, len) = decode_percent(window, cursor)?;
            decoded.push(value);
            cursor += len;
        } else {
            decoded.push(byte);
            cursor += 1;
        }
    }

    // The holdback keeps the window's last byte beyond any match that ends in
    // the released part, so a match that ends at the very end of the window is
    // still complete here; it is simply re-checked on the next call.
    if decoded.as_slice() == key {
        return Some(cursor);
    }
    None
}

/// A form-encoded run: like percent, but `+` decodes to a space when the key
/// itself contains a space.
fn match_form(window: &[u8], index: usize, key: &[u8]) -> Option<usize> {
    if !key.contains(&b' ') {
        return None;
    }
    let mut cursor = index;
    let mut decoded = Zeroizing::new(Vec::new());
    while cursor < window.len() && decoded.len() < key.len() {
        let byte = window[cursor];
        if byte == b'%' {
            let (value, len) = decode_percent(window, cursor)?;
            decoded.push(value);
            cursor += len;
        } else if byte == b'+' {
            decoded.push(b' ');
            cursor += 1;
        } else {
            decoded.push(byte);
            cursor += 1;
        }
    }
    (decoded.as_slice() == key).then_some(cursor)
}

/// A JSON string body starting at `index` that unescapes to the key.
fn match_json(window: &[u8], index: usize, key: &[u8]) -> Option<usize> {
    let mut cursor = index;
    let mut decoded = Zeroizing::new(Vec::new());
    while cursor < window.len() && decoded.len() < key.len() {
        let byte = window[cursor];
        if byte == b'\\' {
            let (value, len) = decode_json_escape(window, cursor)?;
            decoded.extend_from_slice(&value);
            cursor += len;
        } else {
            decoded.push(byte);
            cursor += 1;
        }
    }
    (decoded.as_slice() == key).then_some(cursor)
}

/// A hex run at `index` in any case that decodes to the key.
fn match_hex(window: &[u8], index: usize, key: &[u8]) -> Option<usize> {
    let needed = key.len() * 2;
    let end = index.checked_add(needed)?;
    let run = window.get(index..end)?;
    let mut decoded = Zeroizing::new(Vec::with_capacity(key.len()));
    for pair in run.chunks(2) {
        let high = crate::placeholder::hex_value(pair[0])?;
        let low = crate::placeholder::hex_value(pair[1])?;
        decoded.push((high << 4) | low);
    }
    (decoded.as_slice() == key).then_some(end)
}

/// True when decoding the whole `run` (with either alphabet, `+`/`/` and
/// `-`/`_` mixed) yields the key anywhere inside.
///
/// The run is decoded **once per starting offset** rather than per position
/// and per alphabet. That keeps a long base64 body linear: four alignments of
/// one pass each, instead of a fresh decode from every byte.
fn base64_run_contains(run: &[u8], key: &[u8]) -> bool {
    if run.len() < key.len() + 4 {
        return false;
    }
    // The key can start at any character, but always within the first three
    // characters of a group; four alignments cover every possible group phase.
    for offset in 0..4 {
        let Some(slice) = run.get(offset..) else {
            continue;
        };
        let mut decoded = Vec::with_capacity(slice.len());
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for byte in slice {
            let Some(value) = base64_value(*byte) else {
                // A byte outside the alphabet ends the token: reset and keep
                // scanning, so the run's cells past padding still decode.
                buffer = 0;
                bits = 0;
                continue;
            };
            buffer = (buffer << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                decoded.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }
        if decoded.len() >= key.len() && decoded.windows(key.len()).any(|c| c == key) {
            return true;
        }
    }
    false
}

/// Index of one base64 character in the RFC 4648 alphabet, accepting both the
/// standard `+`/`/` pair and its URL-safe `-`/`_` spelling.
fn base64_value(byte: u8) -> Option<u32> {
    match byte {
        b'=' => None,
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => BASE64_STANDARD
            .iter()
            .position(|candidate| *candidate == byte)
            .map(|index| index as u32),
    }
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
}

fn decode_percent(window: &[u8], index: usize) -> Option<(u8, usize)> {
    let high = window
        .get(index + 1)
        .copied()
        .and_then(crate::placeholder::hex_value);
    let low = window
        .get(index + 2)
        .copied()
        .and_then(crate::placeholder::hex_value);
    match (high, low) {
        (Some(high), Some(low)) => Some(((high << 4) | low, 3)),
        _ => None,
    }
}

/// One escaped byte of the JSON/percent family at `index`.
///
/// The families differ only in which sequences are escapes, so one decoder
/// serves both the streaming matcher and the audit record's key check.
fn decode_either(text: &[u8], index: usize) -> Option<(u8, usize)> {
    let byte = *text.get(index)?;
    if byte == b'%' {
        return decode_percent(text, index);
    }
    if byte != b'\\' {
        return None;
    }
    match *text.get(index + 1)? {
        b'u' => {
            let hex = std::str::from_utf8(text.get(index + 2..index + 6)?).ok()?;
            let code = u32::from_str_radix(hex, 16).ok()?;
            let ch = char::from_u32(code)?;
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            if encoded.len() == 1 {
                Some((encoded.as_bytes()[0], 6))
            } else {
                // A multi-byte character is not one key byte; refuse so the
                // caller treats the text as literal.
                None
            }
        }
        b'"' => Some((b'"', 2)),
        b'/' => Some((b'/', 2)),
        b'\\' => Some((b'\\', 2)),
        b'b' => Some((0x08, 2)),
        b'f' => Some((0x0c, 2)),
        b'n' => Some((b'\n', 2)),
        b'r' => Some((b'\r', 2)),
        b't' => Some((b'\t', 2)),
        _ => None,
    }
}

/// True when decoding `text` anywhere yields the key.
pub(crate) fn text_decodes_to_key(text: &str, key: &[u8]) -> bool {
    if key.is_empty() {
        return false;
    }
    // Hex, in either case, contiguous.
    let bytes = text.as_bytes();
    let mut candidate = Zeroizing::new(Vec::with_capacity(key.len()));
    for (index, byte) in bytes.iter().enumerate() {
        if let Some(value) = crate::placeholder::hex_value(*byte) {
            if index % 2 == 0 {
                candidate.push(value << 4);
            } else {
                if let Some(last) = candidate.last_mut() {
                    *last |= value;
                }
                if candidate.len() == key.len() && candidate.as_slice() == key {
                    return true;
                }
                if candidate.len() >= key.len() {
                    candidate.clear();
                }
            }
        } else {
            candidate.clear();
        }
    }
    for start in 0..bytes.len() {
        let mut cursor = start;
        let mut decoded = Zeroizing::new(Vec::with_capacity(key.len()));
        while cursor < bytes.len() && decoded.len() < key.len() {
            match decode_either(bytes, cursor) {
                Some((value, len)) => {
                    decoded.push(value);
                    cursor += len;
                }
                None => {
                    decoded.push(bytes[cursor]);
                    cursor += 1;
                }
            }
        }
        if decoded.as_slice() == key {
            return true;
        }
    }
    false
}

/// Replace every decoded spelling of `key` in `text` with `replacement`.
pub(crate) fn scrub_encodings(text: &str, key: &[u8], replacement: &str) -> String {
    if key.is_empty() {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        let mut probe = cursor;
        let mut decoded = Zeroizing::new(Vec::with_capacity(key.len()));
        while probe < bytes.len() && decoded.len() < key.len() {
            match decode_either(bytes, probe) {
                Some((value, len)) => {
                    decoded.push(value);
                    probe += len;
                }
                None => {
                    decoded.push(bytes[probe]);
                    probe += 1;
                }
            }
        }
        if decoded.as_slice() == key {
            out.push_str(replacement);
            cursor = probe;
            continue;
        }
        let ch = text[cursor..].chars().next().unwrap_or_default();
        out.push(ch);
        cursor += ch.len_utf8();
    }
    out
}

fn decode_json_escape(window: &[u8], index: usize) -> Option<(Vec<u8>, usize)> {
    match *window.get(index + 1)? {
        b'"' => Some((vec![b'"'], 2)),
        b'\\' => Some((vec![b'\\'], 2)),
        b'/' => Some((vec![b'/'], 2)),
        b'b' => Some((vec![0x08], 2)),
        b'f' => Some((vec![0x0c], 2)),
        b'n' => Some((vec![b'\n'], 2)),
        b'r' => Some((vec![b'\r'], 2)),
        b't' => Some((vec![b'\t'], 2)),
        b'u' => {
            let hex = std::str::from_utf8(window.get(index + 2..index + 6)?).ok()?;
            let code = u32::from_str_radix(hex, 16).ok()?;
            Some((char::from_u32(code)?.to_string().into_bytes(), 6))
        }
        _ => None,
    }
}

/// How many bytes a scrubber withholds from the caller: one less than the
/// longest pattern.
///
/// The holdback is a constant for the stream and does not depend on the
/// content, which is what keeps the release pattern from revealing whether a
/// chunk continued the secret. It never splits a complete match, because
/// matching runs on the whole buffered window before anything is released.
pub fn overlap_for(longest_consumed: usize) -> usize {
    longest_consumed.saturating_sub(1)
}

/// The widest source span the match families produce for a key of `key_len`
/// bytes.
///
/// JSON can spell every byte as `\u00XX` (six bytes each), percent-encoding
/// three, hex two and base64 four per three bytes; the escaped JSON form is
/// always the widest. Streaming keeps space for it plus one byte, so a match
/// never starts in released bytes.
pub fn max_consumed_len(key_len: usize) -> usize {
    key_len.saturating_mul(6).max(key_len).max(1)
}

/// A streaming scrubber state (S2).
///
/// Feed arbitrary chunks in order; each call returns bytes that are safe to
/// forward immediately. The caller must not observe how many bytes each call
/// returns: output is released in fixed-size steps, so the step at which a byte
/// appears says nothing about the secret. [`Scrubber::finish`] releases what is
/// left once the stream ends.
pub struct Scrubber {
    matchers: Vec<MatcherSet>,
    /// Bytes held back across calls.
    pending: Zeroizing<Vec<u8>>,
    longest: usize,
}

impl std::fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scrubber")
            .field("matchers", &self.matchers)
            .field("longest", &self.longest)
            .finish()
    }
}

impl Scrubber {
    /// Build a scrubber over every installed matcher.
    pub fn new(matchers: Vec<MatcherSet>) -> Self {
        let longest = matchers
            .iter()
            .map(MatcherSet::longest_consumed)
            .max()
            .unwrap_or(0);
        Self {
            matchers,
            pending: Zeroizing::new(Vec::new()),
            longest,
        }
    }

    /// Install a matcher that became known mid-stream (a rotated key). Bytes
    /// already released cannot be rechecked, so the caller installs matchers
    /// before forwarding the response they must cover.
    pub fn install(&mut self, matcher: MatcherSet) {
        self.longest = self.longest.max(matcher.longest_consumed());
        self.matchers.push(matcher);
    }

    /// Holdback window in bytes.
    pub fn overlap(&self) -> usize {
        overlap_for(self.longest)
    }

    /// True when no matcher is installed, so bytes pass through untouched.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    /// Number of installed matchers.
    pub fn matcher_count(&self) -> usize {
        self.matchers.len()
    }

    /// Bytes currently held back from the caller.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Scrub `chunk`, returning bytes safe to forward now.
    ///
    /// The number of bytes returned in one call says nothing about the secret:
    /// a fixed `overlap()` bytes of the input are held back, independent of
    /// what the response contains. A caller that needs the whole response
    /// scrubbed must call [`Scrubber::finish`] at the end of the stream.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.matchers.is_empty() {
            return chunk.to_vec();
        }
        let mut buffer = std::mem::take(&mut self.pending).to_vec();
        buffer.extend_from_slice(chunk);
        let (out, held) = self.scrub_buffer(&buffer);
        self.pending = Zeroizing::new(held);
        out
    }

    /// Release the retained tail at end of stream.
    pub fn finish(&mut self) -> Vec<u8> {
        let tail = std::mem::take(&mut self.pending).to_vec();
        if self.matchers.is_empty() {
            return tail;
        }
        // End of stream: nothing can complete a match any more, so whatever is
        // left is scrubbed once and released.
        self.scrub_all(&tail)
    }

    /// Every replacement the installed matchers make in `buffer`, sorted and
    /// free of overlaps.
    ///
    /// Each matcher sees only `buffer`, never another matcher's generated text,
    /// so generated placeholders can never be rewritten in the same pass. When
    /// two matchers claim overlapping bytes, the matcher installed first keeps
    /// its span and the later one is dropped.
    ///
    /// Accepted spans are kept in an ordered map keyed by start. They never
    /// overlap, so the only one a new span can collide with is the last one
    /// that starts before the new span ends: one lookup per candidate, and
    /// `O(m log m)` work for `m` matches instead of comparing every pair.
    fn find_edits(&self, buffer: &[u8]) -> Vec<(usize, usize, Vec<u8>)> {
        let mut accepted: BTreeMap<Counted<usize>, (usize, usize)> = BTreeMap::new();
        for (which, matcher) in self.matchers.iter().enumerate() {
            for (start, end) in matcher.find_spans(buffer) {
                let overlaps = accepted
                    .range(..Counted(end))
                    .next_back()
                    .is_some_and(|(_, (previous_end, _))| *previous_end > start);
                if !overlaps {
                    accepted.insert(Counted(start), (end, which));
                }
            }
        }
        accepted
            .into_iter()
            .map(|(Counted(start), (end, which))| {
                (start, end, self.matchers[which].replacement.clone())
            })
            .collect()
    }

    /// Rewrite `buffer` with `edits`.
    fn apply_edits(buffer: &[u8], edits: &[(usize, usize, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(buffer.len());
        let mut cursor = 0;
        for (start, end, replacement) in edits {
            out.extend_from_slice(&buffer[cursor..*start]);
            out.extend_from_slice(replacement);
            cursor = *end;
        }
        out.extend_from_slice(&buffer[cursor..]);
        out
    }

    fn scrub_all(&self, buffer: &[u8]) -> Vec<u8> {
        let edits = self.find_edits(buffer);
        Self::apply_edits(buffer, &edits)
    }

    /// Scrub the window, then release what may leave.
    ///
    /// Release is split on the **input** window, never on the rewritten text.
    /// Everything the scrubber matches that starts inside `buffer[..split]`
    /// ends at or before `split`, because no pattern is longer than the overlap
    /// plus one candidate byte. The replacement for such a match may be longer
    /// than the bytes it stands for, so it is released whole with the head and
    /// never held back: holding generated text would emit it again later.
    /// Matches that start after `split` stay in the window and are matched
    /// again once more bytes arrive. The holdback is a fixed length that does
    /// not depend on what the window contains.
    /// Scrub the window, then release what may leave.
    ///
    /// Release is decided on the **input** window and the rewritten text is cut
    /// at the same offsets: the scrubber works out which input ranges it
    /// replaced, releases the input up to the holdback, and writes every
    /// replacement for a range that ends inside that part. Holding back the
    /// bytes a replacement would occupy would emit generated text twice; cutting
    /// the rewritten text at an input offset would split an escape.
    fn scrub_buffer(&self, buffer: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let hold = overlap_for(self.longest).min(buffer.len());
        let split = buffer.len() - hold;
        let edits = self.find_edits(buffer);
        let mut out = Vec::with_capacity(buffer.len());
        let mut cursor = 0;
        for (start, end, replacement) in &edits {
            if *start >= split {
                break;
            }
            // A replacement that starts in the released part is written in
            // full, even when it runs past the split; the bytes it covers are
            // consumed in the input, so nothing of it is left to re-emit.
            out.extend_from_slice(&buffer[cursor..*start]);
            out.extend_from_slice(replacement);
            cursor = (*end).min(buffer.len());
        }
        // Input up to the split is released; the rest is held back for the next
        // call and matched again with more bytes behind it.
        if cursor < split {
            out.extend_from_slice(&buffer[cursor..split]);
        }
        // A replacement that ran past the split consumed those bytes already,
        // so the held tail starts no earlier than the end of the split.
        let tail_start = split.max(cursor);
        let tail = buffer[tail_start..].to_vec();
        (out, tail)
    }
}

/// Scrub a complete buffer with one key (convenience for tests and fetch).
pub fn scrub_bytes(key: &[u8], label: &str, input: &[u8]) -> Result<Vec<u8>, ScrubError> {
    let mut scrubber = Scrubber::new(vec![MatcherSet::new(label, key)?]);
    let mut out = scrubber.push(input);
    out.extend_from_slice(&scrubber.finish());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_matches_are_aggregated_in_n_log_n_comparisons() {
        // The closure check's shape: thousands of disjoint key tokens in one
        // push. Two matchers make the cross-matcher overlap check run on every
        // candidate. `MDEyMzQ1Njc4OWFiY2RlZg` is the unpadded base64 of
        // `0123456789abcdef`; the second key appears raw.
        let tokens = 10_000usize;
        let unit = "MDEyMzQ1Njc4OWFiY2RlZg!fedcba9876543210!";
        let input = unit.repeat(tokens);
        let mut scrubber = Scrubber::new(vec![
            MatcherSet::new("a", b"0123456789abcdef").unwrap(),
            MatcherSet::new("b", b"fedcba9876543210").unwrap(),
        ]);
        crate::work::take();
        let mut out = scrubber.push(input.as_bytes());
        out.extend_from_slice(&scrubber.finish());
        let comparisons = crate::work::take();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{{ck-secret:a}}!{{ck-secret:b}}!".repeat(tokens)
        );
        let matches = 2 * tokens as u64;
        let log2 = u64::from(u64::BITS - matches.leading_zeros());
        // One range lookup and one insert per candidate, each a B-tree search
        // of at most eleven keys per level.
        let ceiling = 2 * 12 * matches * log2;
        assert!(comparisons > 0, "the accepted-span map was never consulted");
        assert!(
            comparisons <= ceiling,
            "{comparisons} comparisons for {matches} matches (ceiling {ceiling})"
        );
    }

    #[test]
    fn overlapping_matches_of_one_key_are_replaced_as_one() {
        let mut spans = vec![(0, 4)];
        push_merged(&mut spans, (2, 9));
        push_merged(&mut spans, (9, 12));
        assert_eq!(spans, vec![(0, 9), (9, 12)]);
    }
}
