//! Helpers shared by the vector-driven tests.

use serde_json::Value;

/// Groups every vector file must carry; the acceptance matrix names each one.
pub const REQUIRED_GROUPS: &[&str] = &[
    "P1", "P2", "P3", "P4", "M1", "M2", "M3", "M4", "S1", "S2", "A1",
];

/// Skip a case whose group the file does not define yet; the group's own test
/// reports a missing or empty group, so this never hides a case.
pub fn skip_missing_group(file: &str, group: &str) {
    let vectors = load(file);
    if vectors.pointer(&format!("/groups/{group}")).is_none() {
        eprintln!("{group}: no vectors in {file} yet");
    }
}

/// Run every case of one `group` from `file` and collect failures.
pub fn run_group(file: &str, group: &str, failures: &mut Vec<String>, total: &mut usize) {
    let vectors = load(file);
    let cases = vectors
        .pointer(&format!("/groups/{group}"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("vector group {group} is missing from {file}"));
    assert!(!cases.is_empty(), "vector group {group} in {file} is empty");
    for case in cases {
        *total += 1;
        let case_name = name(case);
        let actual = match super::run(case) {
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

/// Every required group is present in at least one of the files.
pub fn check_groups_present(files: &[&str]) {
    let mut seen: Vec<String> = Vec::new();
    for file in files {
        let vectors = load(file);
        if let Some(groups) = vectors.get("groups").and_then(Value::as_object) {
            seen.extend(groups.keys().cloned());
        }
    }
    for group in REQUIRED_GROUPS {
        assert!(
            seen.iter().any(|name| name == group),
            "no vectors for {group}"
        );
    }
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
pub fn name(case: &Value) -> String {
    case.get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
        .to_string()
}

/// A JSON string interpreted as bytes; a `\uXXXX` escape therefore arrives as
/// UTF-8, which is what a request may carry.
pub fn bytes(value: &Value) -> Vec<u8> {
    value.as_str().unwrap_or_default().as_bytes().to_vec()
}

/// Key bytes of a case: either literal text in `key` or raw bytes in hex in
/// `key_hex`, because a key may be any byte string.
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
pub fn string(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_string()
}

/// Bytes rendered back into a JSON-safe string for comparison.
pub fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Compact one-line rendering for failure messages.
pub fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Case-sensitive or ASCII case-insensitive containment.
pub fn contains(haystack: &str, needle: &[u8], insensitive: bool) -> bool {
    let needle = String::from_utf8_lossy(needle).into_owned();
    if needle.is_empty() {
        return false;
    }
    if insensitive {
        haystack
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    } else {
        haystack.contains(&needle)
    }
}
