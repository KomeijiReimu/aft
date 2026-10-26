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
use std::collections::BTreeSet;
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
    /// Standard or URL-safe base64, padded or not.
    Base64,
}

/// Every literal a response may use for one key (S1).
#[derive(Debug)]
pub struct KeyPatterns {
    /// Sorted longest first, so a longer spelling is tried before a shorter
    /// one that sits inside it.
    patterns: Vec<Zeroizing<Vec<u8>>>,
    /// Length of the key itself; decoded matches never shrink below it.
    key_len: usize,
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

    /// The key length a decoded family must reproduce.
    pub fn key_len(&self) -> usize {
        self.patterns.key_len()
    }

    /// The key bytes, for the decoded comparisons.
    fn key(&self) -> &[u8] {
        &self.key
    }

    /// Test hook: the edits this matcher finds in `window`.
    /// Every match of the key in `window`, as `(start, end, replacement)`.
    ///
    /// Matches never overlap each other, and the replacement text is not part
    /// of the window, so the caller can apply the edits to a copy of the
    /// original bytes without ever rescanning generated text.
    fn find_edits(&self, window: &[u8]) -> Vec<(usize, usize, Vec<u8>)> {
        let mut edits = Vec::new();
        let mut index = 0;
        while index < window.len() {
            // A repeated byte (the self-overlapping case) is the worst thing
            // this matcher sees: literal spellings are checked first, then each
            // decoded family in turn.
            match self.try_match_at(window, index) {
                Some((end, _family)) => {
                    edits.push((index, end, self.replacement.clone()));
                    index = end;
                }
                None => index += 1,
            }
        }
        edits
    }

    /// The end of a key representation starting at `index`, if one starts
    /// there.
    fn try_match_at(&self, window: &[u8], index: usize) -> Option<(usize, Family)> {
        let key = self.key();
        // Literal spellings first: they are exact and cheapest.
        for pattern in self.patterns() {
            if window.len() >= index + pattern.len()
                && &window[index..index + pattern.len()] == pattern
            {
                return Some((index + pattern.len(), Family::Raw));
            }
        }
        // Then the decoded families, each of which may be longer than the key
        // or the same length.
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
        if let Some(end) = match_base64(window, index, key) {
            return Some((end, Family::Base64));
        }
        None
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

/// A base64 run at `index`, in either alphabet, padded or not, that decodes to
/// a string containing the key.
///
/// The run is extended while it stays inside the alphabet, so the match covers
/// the whole encoded token that overlaps the key rather than only its aligned
/// middle. Bytes outside the key are replaced with it as well: leaving them
/// would let a reader decode the edge key bytes from the surviving groups.
fn match_base64(window: &[u8], index: usize, key: &[u8]) -> Option<usize> {
    let mut end = index;
    while end < window.len() && is_base64_byte(window[end]) {
        end += 1;
    }
    if end == index {
        return None;
    }
    let run = &window[index..end];
    // A token with a single trailing character decodes to complete groups only
    // once that character is padding; try it with and without.
    for trim in 0..=1.min(run.len().saturating_sub(1)) {
        let run = &run[..run.len() - trim];
        if base64_matches(run, key) {
            return Some(end);
        }
    }
    None
}

fn base64_matches(run: &[u8], key: &[u8]) -> bool {
    for alphabet in [BASE64_STANDARD, BASE64_URL_SAFE] {
        let Some(decoded) = base64_decode(run, alphabet) else {
            continue;
        };
        if decoded.windows(key.len()).any(|candidate| candidate == key) {
            return true;
        }
    }
    false
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
}

fn base64_decode(input: &[u8], alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input {
        if *byte == b'=' {
            continue;
        }
        let value = alphabet.iter().position(|candidate| candidate == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
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
pub fn overlap_for(longest_pattern: usize) -> usize {
    longest_pattern.saturating_sub(1)
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
        let longest = matchers.iter().map(MatcherSet::longest).max().unwrap_or(0);
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
        self.longest = self.longest.max(matcher.longest());
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

    /// Run every matcher once over the window.
    ///
    /// A matcher sees only the bytes `buffer` holds, never the text another
    /// matcher wrote: the output is built from the input side while the
    /// inserted replacements are copied through untouched.
    /// Every replacement the installed matchers make in `buffer`, sorted and
    /// free of overlaps.
    ///
    /// Each matcher sees only `buffer`, never another matcher's generated text,
    /// so generated placeholders can never be rewritten in the same pass.
    fn find_edits(&self, buffer: &[u8]) -> Vec<(usize, usize, Vec<u8>)> {
        let mut edits: Vec<(usize, usize, Vec<u8>)> = Vec::new();
        for matcher in &self.matchers {
            for edit in matcher.find_edits(buffer) {
                let overlaps = edits
                    .iter()
                    .any(|(start, end, _)| edit.0 < *end && *start < edit.1);
                if !overlaps {
                    edits.push(edit);
                }
            }
        }
        edits.sort_by_key(|(start, end, _)| (*start, *end));
        edits
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
