//! Helpers shared by the vector-driven tests.

use serde_json::Value;

/// Groups every vector file must carry.
pub const REQUIRED_GROUPS: &[&str] = &[
    "P1", "P2", "P3", "P4", "M1", "M2", "M3", "M4", "S1", "S2", "A1",
];

/// The cases of `group` in `file`.
///
/// A missing or empty group is an error, never a skip: a vector file that lost
/// its group must fail the run, or a whole area of the rule set could stop
/// being exercised without any test going red.
pub fn require_group(file: &str, group: &str) -> Result<Vec<Value>, String> {
    let vectors = load(file);
    let cases = vectors
        .pointer(&format!("/groups/{group}"))
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| format!("vector group {group} is missing from {file}"))?;
    if cases.is_empty() {
        return Err(format!("vector group {group} in {file} is empty"));
    }
    Ok(cases)
}

/// Run every case of one `group` from `file` and collect failures.
///
/// `run` is the case interpreter of the calling test binary; the shared helpers
/// never reach back into a test crate themselves.
#[allow(dead_code)]
pub type CaseRunner<'a> = dyn FnMut(&Value) -> Result<Value, String> + 'a;
pub type Decoder = fn(&str) -> Vec<Vec<u8>>;

#[allow(dead_code)]
pub fn run_group(
    file: &str,
    group: &str,
    run: &mut CaseRunner<'_>,
    failures: &mut Vec<String>,
    total: &mut usize,
) {
    let cases = require_group(file, group).unwrap_or_else(|err| panic!("{err}"));
    for case in cases {
        *total += 1;
        let case_name = name(&case);
        let actual = match run(&case) {
            Ok(actual) => actual,
            Err(err) => {
                failures.push(format!("{group}/{case_name}: harness error: {err}"));
                continue;
            }
        };
        let expected = case.get("expect").expect("every case carries expect");
        if &actual != expected {
            failures.push(format!(
                "{group}/{case_name}: expected {} got {}",
                compact(expected),
                compact(&actual)
            ));
        }
    }
}

/// Every file named here must carry exactly the groups it is responsible for.
///
/// Naming the group per file, instead of accepting a group from anywhere, is
/// what stops a group from being "present" somewhere the runner never loads.
pub const FILE_GROUPS: &[(&str, &[&str])] = &[
    ("secret_rules_v1.json", &["P1", "P2", "P4"]),
    ("secret_rules_p3.json", &["P3"]),
    ("secret_rules_m1.json", &["M1"]),
    ("secret_rules_m2.json", &["M2"]),
    ("secret_rules_m3.json", &["M3"]),
    ("secret_rules_m4.json", &["M4"]),
    ("secret_rules_s1.json", &["S1"]),
    ("secret_rules_s2.json", &["S2"]),
    ("secret_rules_a1.json", &["A1"]),
];

/// Check that each file carries its groups and that every required group has a
/// home.
pub fn check_groups_present() {
    let mut covered: Vec<String> = Vec::new();
    for (file, groups) in FILE_GROUPS {
        for group in *groups {
            require_group(file, group).unwrap_or_else(|err| panic!("{err}"));
            covered.push((*group).to_string());
        }
    }
    for group in REQUIRED_GROUPS {
        assert!(
            covered.iter().any(|name| name == group),
            "no vector file is responsible for {group}"
        );
    }
}

/// The independent ``oracle``: decode the common encodings of a response and
/// look for the key. It shares no code with the production matchers, so a
/// missing representation cannot be missing from the detector too.
pub fn discloses(key: &[u8], output: &[u8]) -> bool {
    if key.is_empty() {
        return false;
    }
    // The raw bytes, not a lossy string: lossy conversion collapses every
    // invalid sequence to U+FFFD, which can make unrelated bytes look absent or
    // present. Key material never survives that check unless the bytes are
    // literally there.
    let raw = output;
    let text = String::from_utf8_lossy(output).into_owned();
    if !key.is_empty() && raw.windows(key.len()).any(|window| window == key) {
        return true;
    }
    let mut unescaped = text.replace("\\/", "/");
    unescaped = unescaped.replace("\\\"", "\"");
    unescaped = unescaped.replace("\\\\", "\\");
    unescaped = unescaped.replace('+', " ");
    if !key.is_empty()
        && unescaped
            .as_bytes()
            .windows(key.len())
            .any(|window| window == key)
    {
        return true;
    }
    let decoders: [Decoder; 3] = [percent_decodes, hex_decodes, base64_decodes];
    for decode in decoders {
        for decoded in decode(&text) {
            if decoded.len() >= key.len() && decoded.windows(key.len()).any(|window| window == key)
            {
                return true;
            }
        }
    }
    false
}

pub fn percent_decodes(text: &str) -> Vec<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(byte) = pair.and_then(|pair| u8::from_str_radix(pair, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    vec![out]
}

pub fn hex_decodes(text: &str) -> Vec<Vec<u8>> {
    let mut runs = Vec::new();
    for start in 0..text.len().min(2) {
        let bytes = text.as_bytes();
        let mut index = start;
        let mut run = Vec::new();
        let mut decoded = Vec::new();
        while index + 1 < bytes.len() {
            let pair = &bytes[index..index + 2];
            match std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            {
                Some(byte) => {
                    decoded.push(byte);
                    index += 2;
                }
                None => {
                    if decoded.len() >= secret_rules::MIN_KEY_LEN {
                        run.push(std::mem::take(&mut decoded));
                    }
                    decoded.clear();
                    index += 1;
                }
            }
        }
        // Only a run at least as long as the shortest key can be key material;
        // a couple of accidental hex letters (the `de` in `secret`) are not.
        if decoded.len() >= secret_rules::MIN_KEY_LEN {
            run.push(decoded);
        }
        runs.extend(run);
    }
    runs
}

pub fn base64_decodes(text: &str) -> Vec<Vec<u8>> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_";
    let mut out = Vec::new();
    for offset in 0..4 {
        let mut buffer = 0u32;
        let mut bits = 0u32;
        let mut decoded = Vec::new();
        for byte in text.bytes().skip(offset) {
            let Some(value) = ALPHA.iter().position(|candidate| *candidate == byte) else {
                // A decoded run only counts once it is long enough to hold a key.
                if decoded.len() >= secret_rules::MIN_KEY_LEN {
                    out.push(std::mem::take(&mut decoded));
                }
                decoded.clear();
                buffer = 0;
                bits = 0;
                continue;
            };
            buffer = (buffer << 6) | value as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                decoded.push((buffer >> bits) as u8);
                // Keep only the bits that are still waiting for a byte.
                buffer &= (1 << bits) - 1;
            }
        }
        if decoded.len() >= secret_rules::MIN_KEY_LEN {
            out.push(decoded);
        }
    }
    out
}

/// Load a committed vector file.
pub fn load(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("{} is not valid JSON: {err}", path.display()))
}

/// The case's `name` field.
#[allow(dead_code)]
pub fn name(case: &Value) -> String {
    case.get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
        .to_string()
}

/// A JSON string interpreted as bytes; a `\uXXXX` escape therefore arrives as
/// UTF-8, which is what a request may carry.
#[allow(dead_code)]
pub fn bytes(value: &Value) -> Vec<u8> {
    value.as_str().unwrap_or_default().as_bytes().to_vec()
}

/// Key bytes of a case: either literal text in `key` or raw bytes in hex in
/// `key_hex`, because a key may be any byte string.
#[allow(dead_code)]
pub fn key_bytes(case: &Value) -> Vec<u8> {
    if let Some(hex) = case.get("key_hex").and_then(Value::as_str) {
        let digits: Vec<u8> = hex.as_bytes().to_vec();
        let mut out = Vec::with_capacity(digits.len() / 2);
        for pair in digits.chunks(2) {
            let text = std::str::from_utf8(pair).expect("hex digits are ASCII");
            out.push(u8::from_str_radix(text, 16).expect("valid hex pair"));
        }
        return out;
    }
    bytes(case.get("key").unwrap_or(&Value::Null))
}

/// A JSON string field.
#[allow(dead_code)]
pub fn string(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_string()
}

/// Bytes rendered back into a JSON-safe string for comparison.
#[allow(dead_code)]
pub fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Compact one-line rendering for failure messages.
#[allow(dead_code)]
pub fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}
