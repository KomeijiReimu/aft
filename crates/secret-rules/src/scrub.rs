//! S1 and S2: representations of a key, and a streaming scrubber.
//!
//! A key shorter than [`crate::material::MIN_KEY_LEN`] never reaches here (P3
//! refuses it), which is what keeps every derived pattern non-empty. Patterns
//! are plain byte strings, so scrubbing is a byte scan with a bounded overlap
//! window rather than a regular expression.

use crate::material::{json_escape, percent_encode_form};
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

/// Every literal a response may use for one key (S1).
#[derive(Debug)]
pub struct KeyPatterns {
    /// `(pattern, case_insensitive)` sorted longest first.
    patterns: Vec<(Zeroizing<Vec<u8>>, bool)>,
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
        let mut patterns: Vec<(Zeroizing<Vec<u8>>, bool)> = set
            .into_iter()
            .map(|pattern| {
                let case_insensitive = is_hex_shaped(&pattern);
                (Zeroizing::new(pattern), case_insensitive)
            })
            .collect();
        // Longest first: a shorter pattern inside a longer one must never be
        // replaced before the longer one is tried.
        patterns.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        Ok(Self { patterns })
    }

    /// The patterns, longest first, with their case-sensitivity.
    pub fn patterns(&self) -> impl Iterator<Item = (&[u8], bool)> {
        self.patterns
            .iter()
            .map(|(pattern, insensitive)| (pattern.as_slice(), *insensitive))
    }

    /// Number of distinct representations.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// True when no pattern was derived; impossible for an admissible key.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Longest pattern, which sets the overlap window (S2).
    pub fn longest(&self) -> usize {
        self.patterns
            .first()
            .map_or(0, |(pattern, _)| pattern.len())
    }
}

/// True when a pattern is hexadecimal (optionally with `%` signs), so a case
/// variant is the same value and may be matched case-insensitively.
fn is_hex_shaped(pattern: &[u8]) -> bool {
    let mut saw_digit = false;
    for byte in pattern {
        if *byte == b'%' {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return false;
        }
        if byte.is_ascii_digit() {
            saw_digit = true;
        }
    }
    saw_digit
}

/// Base64 forms: standard and URL-safe alphabets, padded and unpadded, matched
/// on the stable core of all three byte alignments.
///
/// A key inside a larger base64 payload begins at an arbitrary offset relative
/// to the payload's first character. Every whole 3-byte group of `key[offset..]`
/// encodes to the same 4 characters in every alignment, so the core of
/// `offset` is the group-aligned middle of `key[offset..]`. A 16-byte key's
/// core is 4 characters, which keeps even the smallest case long enough not to
/// occur by chance.
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
/// bytes literal, plus the common form-encoding variant that leaves spaces
/// literal.
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

/// Hex forms: the whole key lower- and upper-case. Mixed case is covered by
/// case-insensitive matching of these patterns.
pub fn hex_patterns(key: &[u8]) -> Vec<Vec<u8>> {
    let mut lower = Vec::with_capacity(key.len() * 2);
    let mut upper = Vec::with_capacity(key.len() * 2);
    for byte in key {
        lower.extend_from_slice(format!("{byte:02x}").as_bytes());
        upper.extend_from_slice(format!("{byte:02X}").as_bytes());
    }
    vec![lower, upper]
}

/// The replacement for a scrubbed key, per label.
///
/// The placeholder is pure ASCII by grammar, so it can stand in for a
/// truncated encoding inside a response body without breaking quoting.
pub fn placeholder_for(label: &str) -> Vec<u8> {
    format!("{PLACEHOLDER_PREFIX}{label}}}").into_bytes()
}

/// One installed matcher set with the text it is replaced by.
pub struct MatcherSet {
    patterns: KeyPatterns,
    replacement: Vec<u8>,
}

impl MatcherSet {
    /// Derive matchers for `key` and the placeholder they are replaced with.
    pub fn new(label: &str, key: &[u8]) -> Result<Self, ScrubError> {
        Ok(Self {
            patterns: KeyPatterns::derive(key)?,
            replacement: placeholder_for(label),
        })
    }

    /// The replacement text.
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }

    /// The patterns, longest first.
    pub fn patterns(&self) -> impl Iterator<Item = (&[u8], bool)> {
        self.patterns.patterns()
    }

    /// Longest pattern.
    pub fn longest(&self) -> usize {
        self.patterns.longest()
    }
}

/// Number of trailing bytes a streaming scrubber must keep to catch a match
/// split across reads: strictly less than the longest pattern, because a full
/// length that did not match can never begin a later match.
pub fn overlap_for(longest_pattern: usize) -> usize {
    longest_pattern.saturating_sub(1)
}

/// A streaming scrubber state (S2).
///
/// Feed arbitrary chunks in order; each call returns bytes that are safe to
/// forward immediately. The retained tail is at most `longest - 1` bytes, and
/// [`Scrubber::finish`] releases it once the stream ends.
pub struct Scrubber {
    matchers: Vec<MatcherSet>,
    /// Bytes held back across calls.
    pending: Zeroizing<Vec<u8>>,
    longest: usize,
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

    /// The larger window needed by a newly installed matcher, so the caller
    /// can re-check already held bytes after a rotation (V4).
    pub fn install(&mut self, matcher: MatcherSet) {
        self.longest = self.longest.max(matcher.longest());
        self.matchers.push(matcher);
    }

    /// Overlap window in bytes.
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

    /// Scrub `chunk`, returning bytes safe to forward now.
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
        let (out, _) = self.scrub_buffer(&tail);
        out
    }

    /// Run the whole buffer through every matcher, then hold back the longest
    /// possible partial match suffix.
    fn scrub_buffer(&self, buffer: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let scrubbed = self.scrub_all(buffer);
        let hold = self.partial_suffix_len(&scrubbed);
        let split = scrubbed.len() - hold;
        let (out, held) = scrubbed.split_at(split);
        (out.to_vec(), held.to_vec())
    }

    fn scrub_all(&self, buffer: &[u8]) -> Vec<u8> {
        let mut current = buffer.to_vec();
        loop {
            let mut changed = false;
            for matcher in &self.matchers {
                let (next, hit) = replace_patterns(&current, matcher);
                if hit {
                    current = next;
                    changed = true;
                }
            }
            if !changed {
                return current;
            }
        }
    }

    /// Length of the longest suffix that is a proper prefix of some pattern.
    fn partial_suffix_len(&self, buffer: &[u8]) -> usize {
        if self.longest <= 1 {
            return 0;
        }
        let max = self.longest.min(buffer.len() + 1);
        for length in (1..max).rev() {
            let start = buffer.len() - length;
            let tail = &buffer[start..];
            for matcher in &self.matchers {
                for (pattern, insensitive) in matcher.patterns() {
                    if length < pattern.len() && eq_prefix(tail, &pattern[..length], insensitive) {
                        return length;
                    }
                }
            }
        }
        0
    }
}

fn eq_prefix(candidate: &[u8], pattern: &[u8], insensitive: bool) -> bool {
    candidate.len() == pattern.len()
        && candidate
            .iter()
            .zip(pattern)
            .all(|(left, right)| byte_eq(*left, *right, insensitive))
}

fn byte_eq(left: u8, right: u8, insensitive: bool) -> bool {
    left == right || (insensitive && left.eq_ignore_ascii_case(&right))
}

/// Replace every pattern occurrence in `input` (longest first).
fn replace_patterns(input: &[u8], matcher: &MatcherSet) -> (Vec<u8>, bool) {
    let mut current = input.to_vec();
    let mut hit = false;
    for (pattern, insensitive) in matcher.patterns() {
        let mut out = Vec::with_capacity(current.len());
        let mut index = 0;
        let mut local_hit = false;
        while index < current.len() {
            if let Some(end) = match_at(&current, index, pattern, insensitive) {
                out.extend_from_slice(&matcher.replacement);
                index = end;
                local_hit = true;
            } else {
                out.push(current[index]);
                index += 1;
            }
        }
        if local_hit {
            current = out;
            hit = true;
        }
    }
    (current, hit)
}

/// End offset of a pattern occurrence starting at `start`, if any.
fn match_at(haystack: &[u8], start: usize, pattern: &[u8], insensitive: bool) -> Option<usize> {
    let end = start.checked_add(pattern.len())?;
    let window = haystack.get(start..end)?;
    if window
        .iter()
        .zip(pattern)
        .all(|(left, right)| byte_eq(*left, *right, insensitive))
    {
        Some(end)
    } else {
        None
    }
}

/// Scrub a complete buffer with one key (convenience for tests and fetch).
pub fn scrub_bytes(key: &[u8], label: &str, input: &[u8]) -> Result<Vec<u8>, ScrubError> {
    let mut scrubber = Scrubber::new(vec![MatcherSet::new(label, key)?]);
    let mut out = scrubber.push(input);
    out.extend_from_slice(&scrubber.finish());
    Ok(out)
}
