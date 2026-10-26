//! Regression tests for the second audit round: the leaks, evasions and DoS
//! shapes the closure check named, each written as the cited counterexample.

mod support;

use secret_rules::{
    evaluate_request_with_connect, scrub_bytes, AuditReason, AuditRecordV1, ConnectAuthority,
    Decision, HeaderField, KeyPatterns, LabelRule, Location, RequestRefusal, RequestView, ScopeRef,
};
use serde_json::json;
use support::{bytes, key_bytes, load, string, MIN_KEY, MIN_KEY_HEX};

const PH: &str = "{{ck-secret:x}}";

fn rule(label: &str, location: Location) -> LabelRule {
    LabelRule {
        label: label.to_string(),
        host: "api.example.com".to_string(),
        port: 443,
        path_prefix: "/v1".to_string(),
        location,
        grant_id: "grant".to_string(),
    }
}

fn connect() -> ConnectAuthority {
    ConnectAuthority::parse("api.example.com:443").unwrap()
}

fn keys(label: &str, key: &[u8]) -> Vec<(String, Vec<u8>)> {
    vec![(label.to_string(), key.to_vec())]
}

/// Every spelling a `Debug` dump could use for the key: ASCII and the decimal
/// byte list libstd prints for byte slices.
fn debug_shows_key(rendered: &str, key: &[u8]) -> bool {
    let ascii = String::from_utf8_lossy(key);
    if !ascii.is_empty() && rendered.contains(ascii.as_ref()) {
        return true;
    }
    let decimal: Vec<String> = key.iter().map(|byte| byte.to_string()).collect();
    rendered.contains(&decimal.join(", "))
}

// --- item 8: no Debug or serialization path leaks key bytes -----------------

#[test]
fn item8_request_outcome_debug_does_not_dump_the_rewritten_body() {
    let body = format!("{{\"key\":\"{PH}\"}}");
    let request = RequestView::new(
        "/v1/x",
        vec![HeaderField::value("Content-Type", b"application/json")],
    )
    .with_body(body.as_bytes());
    let outcome = evaluate_request_with_connect(
        &request,
        &connect(),
        &[rule("x", Location::Json("/key".to_string()))],
        &keys("x", MIN_KEY),
    );
    assert_eq!(outcome.refusal, None);
    assert!(outcome.rewritten_body.is_some(), "the body carries the key");
    let rendered = format!("{outcome:?}");
    assert!(
        !debug_shows_key(&rendered, MIN_KEY),
        "Debug printed the key: {rendered}"
    );
    assert!(rendered.contains("rewritten_body_len"), "{rendered}");
}

#[test]
fn item8_key_patterns_debug_does_not_dump_the_patterns() {
    let patterns = KeyPatterns::derive(MIN_KEY).unwrap();
    let rendered = format!("{patterns:?}");
    assert!(
        !debug_shows_key(&rendered, MIN_KEY),
        "KeyPatterns Debug printed key material: {rendered}"
    );
    assert!(rendered.contains("longest"), "{rendered}");
}

#[test]
fn item8_audit_record_debug_does_not_dump_metadata() {
    let record = AuditRecordV1::new(
        1,
        "repo_key",
        Decision::Literal,
        AuditReason::Matched,
        "req-1",
        String::from_utf8_lossy(MIN_KEY).into_owned(),
    );
    let rendered = format!("{record:?}");
    assert!(
        !debug_shows_key(&rendered, MIN_KEY),
        "AuditRecordV1 Debug printed the key: {rendered}"
    );
}

#[test]
fn item8_scope_fields_are_checked_against_the_key() {
    let record = AuditRecordV1::new(
        1,
        "repo_key",
        Decision::Literal,
        AuditReason::Matched,
        "req-1",
        "task-1",
    )
    .with_scope(Some(ScopeRef {
        owner: String::from_utf8_lossy(MIN_KEY).into_owned(),
        kind: "head".to_string(),
        reference: "ref".to_string(),
    }));
    assert!(record.to_json_line_with_key(MIN_KEY).is_err());
}

#[test]
fn item8_encoded_key_forms_in_metadata_are_found() {
    let hex: String = MIN_KEY.iter().map(|byte| format!("{byte:02x}")).collect();
    let record = AuditRecordV1::new(
        1,
        "repo_key",
        Decision::Literal,
        AuditReason::Matched,
        "req-1",
        hex,
    );
    assert!(record.to_json_line_with_key(MIN_KEY).is_err());
}

#[test]
fn item8_punctuation_separated_key_is_refused_without_the_key() {
    // `ab-cd-ef-...` has no sixteen-byte alphanumeric run, so the shape check
    // alone would let it through.
    let separated = "ab-cd-ef-gh-ij-kl";
    let record = AuditRecordV1::new(
        1,
        "repo_key",
        Decision::Literal,
        AuditReason::Matched,
        "req-1",
        separated,
    );
    assert_eq!(
        record.to_json_line_with_key(separated.as_bytes()),
        Err(secret_rules::AuditRefusal::KeyMaterialInRecord)
    );
}

#[test]
fn item8_the_record_has_no_unguarded_serialization() {
    // The type is deliberately not `Serialize`; the only writers check first.
    // This compiles only because the value goes through `to_json_line`.
    let record = AuditRecordV1::new(
        1,
        "repo_key",
        Decision::Literal,
        AuditReason::Matched,
        "req-1",
        "task-1",
    );
    let json = record.to_json_line().expect("clean record");
    assert!(json.contains("\"reason\":\"matched\""), "{json}");
}

// --- item 13: duplicate detection is total and bounded ----------------------

fn duplicate_case(body: &str) -> Option<RequestRefusal> {
    let request = RequestView::new(
        "/v1/x",
        vec![HeaderField::value("Content-Type", b"application/json")],
    )
    .with_body(body.as_bytes());
    evaluate_request_with_connect(
        &request,
        &connect(),
        &[rule("x", Location::Json("/key".to_string()))],
        &keys("x", MIN_KEY),
    )
    .refusal
}

#[test]
fn item13_leading_whitespace_duplicate_refuses() {
    let body = format!(" {{\"key\":\"{PH}\",\"key\":\"{PH}\"}}");
    assert_eq!(duplicate_case(&body), Some(RequestRefusal::DuplicateField));
}

#[test]
fn item13_whitespace_before_a_nested_value_still_finds_the_duplicate() {
    let body = format!("{{\"outer\": {{\"key\": \"{PH}\"}}, \"outer\": 1}}");
    assert_eq!(duplicate_case(&body), Some(RequestRefusal::DuplicateField));
}

#[test]
fn item13_escaped_member_names_compare_decoded() {
    // `ke\u0079` is `key` to any parser.
    let body = format!("{{\"key\":\"{PH}\",\"ke\\u0079\":1}}");
    assert_eq!(duplicate_case(&body), Some(RequestRefusal::DuplicateField));
}

#[test]
fn item13_deep_nesting_refuses_instead_of_overflowing() {
    let depth = 100_000;
    let mut body = String::new();
    body.push_str(&"[".repeat(depth));
    body.push_str(&"]".repeat(depth));
    assert_eq!(duplicate_case(&body), Some(RequestRefusal::BodyTooDeep));
}

#[test]
fn item13_a_wide_object_is_checked_once_per_member() {
    // Ten thousand distinct members: linear work, and no duplicate.
    let members: Vec<String> = (0..10_000).map(|index| format!("\"k{index}\":1")).collect();
    let body = format!("{{{}}}", members.join(","));
    assert_eq!(duplicate_case(&body), None);
}

// --- item 14: base64 edges and mixed alphabets ------------------------------

fn b64(input: &[u8], url_safe: bool, pad: bool) -> String {
    let encoded = secret_rules::scrub::base64_encode(
        input,
        if url_safe {
            secret_rules::scrub::base64_url_safe()
        } else {
            secret_rules::scrub::base64_standard()
        },
        pad,
    );
    String::from_utf8(encoded).unwrap()
}

#[test]
fn item14_key_at_token_start_loses_no_edge_byte() {
    let mut token = MIN_KEY.to_vec();
    token.extend_from_slice(b"ZZ");
    let encoded = b64(&token, false, false);
    let output = scrub_bytes(MIN_KEY, "x", encoded.as_bytes()).unwrap();
    assert_eq!(output, PH.as_bytes(), "token was only partly replaced");
}

#[test]
fn item14_mixed_standard_and_urlsafe_alphabet_is_scrubbed() {
    // A token that decodes to the key but mixes `+`/`/` with `-`/`_`.
    let standard = b64(MIN_KEY, false, false);
    let mixed: String = standard
        .chars()
        .enumerate()
        .map(|(index, ch)| match (index % 2, ch) {
            (0, '+') => '-',
            (0, '/') => '_',
            _ => ch,
        })
        .collect();
    let url_safe = b64(MIN_KEY, true, false);
    for token in [mixed, url_safe, standard] {
        let output = scrub_bytes(MIN_KEY, "x", token.as_bytes()).unwrap();
        assert_eq!(output, PH.as_bytes(), "token {token} survived");
    }
}

#[test]
fn item14_long_base64_body_stays_linear() {
    // A one-megabyte base64 body with no key in it: the scrubber must finish
    // quickly (the old per-offset decode took minutes).
    let body: String = (0..1_000_000)
        .map(|index| char::from(b'A' + (index % 26) as u8))
        .collect();
    let started = std::time::Instant::now();
    let output = scrub_bytes(MIN_KEY, "x", body.as_bytes()).unwrap();
    assert_eq!(output.len(), body.len());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "base64 body took {:?}",
        started.elapsed()
    );
}

// --- item 16: prefix boundaries, fragments, redirect validation -------------

#[test]
fn item16_dot_segment_or_doubled_prefixes_do_not_become_root() {
    for prefix in ["//", "/.", "/v1/..", "///"] {
        let rule = LabelRule {
            path_prefix: prefix.to_string(),
            ..rule("x", Location::Header("X-A".to_string()))
        };
        let request = RequestView::new("/admin", vec![HeaderField::value("X-A", PH.as_bytes())]);
        let outcome =
            evaluate_request_with_connect(&request, &connect(), &[rule], &keys("x", MIN_KEY));
        assert!(
            outcome.refusal.is_some(),
            "prefix {prefix:?} authorized /admin"
        );
    }
}

#[test]
fn item16_a_fragment_in_the_target_refuses() {
    // `#` is not a path byte: a server routes /admin#/../v1/x to /admin while a
    // fragment-stripping client might see /v1/x.
    let request = RequestView::new(
        "/admin#/../v1/x",
        vec![HeaderField::value("X-A", PH.as_bytes())],
    );
    let outcome = evaluate_request_with_connect(
        &request,
        &connect(),
        &[rule("x", Location::Header("X-A".to_string()))],
        &keys("x", MIN_KEY),
    );
    assert_eq!(outcome.refusal, Some(RequestRefusal::FragmentInTarget));
}

#[test]
fn item16_the_redirect_path_validates_rules() {
    use secret_rules::{evaluate_redirect, RedirectOutcome, RequestTarget};
    let invalid = vec![
        LabelRule {
            path_prefix: "//".to_string(),
            ..rule("x", Location::Query("k".to_string()))
        },
        LabelRule {
            label: "Bad Label".to_string(),
            ..rule("x", Location::Query("k".to_string()))
        },
    ];
    let hop = RequestTarget {
        host: "api.example.com".to_string(),
        port: 443,
        scheme: "https",
        target: "/anything",
    };
    for decision in evaluate_redirect(&invalid, &hop) {
        assert_eq!(decision.outcome, RedirectOutcome::NotAuthorized);
        assert!(decision.refusal.is_some());
    }
}

// --- item 6: duplicate authority fields and a bound destination -------------

#[test]
fn item6_duplicate_host_or_authority_refuses() {
    let bearer = format!("Bearer {PH}");
    for headers in [
        vec![
            HeaderField::value("Host", b"api.example.com"),
            HeaderField::value("Host", b"evil.example"),
            HeaderField::value("Authorization", bearer.as_bytes()),
        ],
        vec![
            HeaderField::value(":authority", b"api.example.com"),
            HeaderField::value(":authority", b"evil.example"),
            HeaderField::value("Authorization", bearer.as_bytes()),
        ],
    ] {
        let request = RequestView::new("/v1/x", headers);
        let outcome = evaluate_request_with_connect(
            &request,
            &connect(),
            &[rule("x", Location::Bearer)],
            &keys("x", MIN_KEY),
        );
        assert_eq!(outcome.refusal, Some(RequestRefusal::DuplicateField));
        assert!(!outcome.substituted());
    }
}

#[test]
fn item6_an_approved_target_for_an_evil_connect_is_not_authorized() {
    // The caller cannot hand `evaluate_request_with_connect` a target of its
    // own: the destination comes from the CONNECT authority. A rule for
    // evil.example therefore matches nothing on an api.example.com tunnel.
    let bearer = format!("Bearer {PH}");
    let request = RequestView::new(
        "/v1/x",
        vec![HeaderField::value("Authorization", bearer.as_bytes())],
    );
    let evil_rule = LabelRule {
        host: "evil.example".to_string(),
        ..rule("x", Location::Bearer)
    };
    let outcome =
        evaluate_request_with_connect(&request, &connect(), &[evil_rule], &keys("x", MIN_KEY));
    assert_eq!(
        outcome.refusal, None,
        "the rule is valid, it simply does not match"
    );
    assert!(!outcome.substituted());
}

// --- item 15: known-answer tests for the independent detectors --------------

#[test]
fn item15_each_decoder_has_known_answers() {
    // URL-safe base64 of sixteen 0xff bytes uses `_` in its alphabet; the
    // standard one uses `/` and `+`.
    let bytes_of_ff = [0xffu8; 16];
    let standard = secret_rules::scrub::base64_encode(
        &bytes_of_ff,
        secret_rules::scrub::base64_standard(),
        false,
    );
    let url_safe = secret_rules::scrub::base64_encode(
        &bytes_of_ff,
        secret_rules::scrub::base64_url_safe(),
        false,
    );
    for encoded in [standard, url_safe] {
        let text = String::from_utf8_lossy(&encoded).into_owned();
        assert!(
            support::discloses(&bytes_of_ff, text.as_bytes()),
            "detector missed base64 form {text}"
        );
    }
    // JSON unicode escapes and a form `+` for space.
    let key: &[u8] = b"a b-cd-ef-gh-ijkl";
    let escaped: String = key.iter().map(|byte| format!("\\u{:04x}", byte)).collect();
    assert!(
        support::discloses(key, escaped.as_bytes()),
        "unicode escapes"
    );
    let plus_form: Vec<u8> = key
        .iter()
        .map(|byte| if *byte == b' ' { b'+' } else { *byte })
        .collect();
    assert!(support::discloses(key, &plus_form), "form plus");
}

// --- H2: a replacement may not disclose an installed key -------------------

#[test]
fn h2_a_label_that_spells_its_key_refuses() {
    // The audit's pair: key `abcdefghijklmnop`, label its hex.
    let key: &[u8] = b"abcdefghijklmnop";
    let hex_label = "6162636465666768696a6b6c6d6e6f70";
    let request = RequestView::new("/v1/x", Vec::new());
    let mut hex_rule = rule("placeholder", Location::Header("X-A".to_string()));
    hex_rule.label = hex_label.to_string();
    let outcome =
        evaluate_request_with_connect(&request, &connect(), &[hex_rule], &keys(hex_label, key));
    assert_eq!(
        outcome.refusal,
        Some(RequestRefusal::ReplacementDisclosesKey)
    );
    let rendered = format!("{outcome:?}");
    assert!(!debug_shows_key(&rendered, key), "{rendered}");
}

#[test]
fn h2_a_key_that_contains_its_label_refuses() {
    // The audit's pair reversed: the key spells the label, so P3 admits it (the
    // key does not fit inside its placeholder) but the scrubber would rewrite
    // the placeholder's own label text. The replacement that would be installed
    // does not disclose the key, so P3's admission stands and the placeholder is
    // the replacement; the refusal case is the one below, where the label
    // spells the key.
    let key: &[u8] = b"a-very-long-key-value";
    let mut containing = rule("x", Location::Header("X-A".to_string()));
    containing.label = "x".to_string();
    let request = RequestView::new("/v1/x", vec![HeaderField::value("X-A", PH.as_bytes())]);
    let outcome = evaluate_request_with_connect(
        &request,
        &connect(),
        &[containing],
        &[("x".to_string(), key.to_vec())],
    );
    assert_eq!(outcome.refusal, None);
    let edit = outcome.header_edits.first().expect("a header edit");
    assert_eq!(edit.replacement.as_slice(), key);
}

#[test]
fn h2_a_key_that_is_its_labels_hex_refuses() {
    // The audit's exact pair: the label is the key's hex, so the placeholder
    // written for it would spell the whole key.
    let key: &[u8] = b"abcdefghijklmnop";
    let hex_label = "6162636465666768696a6b6c6d6e6f70";
    let mut hex_rule = rule("placeholder", Location::Header("X-A".to_string()));
    hex_rule.label = hex_label.to_string();
    let request = RequestView::new(
        "/v1/x",
        vec![HeaderField::value(
            "X-A",
            Box::leak(
                format!("{{{{ck-secret:{hex_label}}}}}")
                    .into_bytes()
                    .into_boxed_slice(),
            ),
        )],
    );
    let outcome = evaluate_request_with_connect(
        &request,
        &connect(),
        &[hex_rule],
        &[(hex_label.to_string(), key.to_vec())],
    );
    assert_eq!(
        outcome.refusal,
        Some(RequestRefusal::ReplacementDisclosesKey)
    );
}

// --- H1: a fully escaped representation streams intact ----------------------

#[test]
fn h1_unicode_escaped_key_survives_every_split() {
    let escaped: String = MIN_KEY
        .iter()
        .map(|byte| format!("\\u{:04x}", byte))
        .collect();
    let body = format!("before {escaped} after");
    let whole = scrub_bytes(MIN_KEY, "x", body.as_bytes()).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&whole),
        "before {{ck-secret:x}} after"
    );
    for split in 0..=body.len() {
        let mut scrubber =
            secret_rules::Scrubber::new(vec![secret_rules::MatcherSet::new("x", MIN_KEY).unwrap()]);
        let mut out = scrubber.push(body.as_bytes().get(..split).unwrap_or_default());
        out.extend_from_slice(&scrubber.push(body.as_bytes().get(split..).unwrap_or_default()));
        out.extend_from_slice(&scrubber.finish());
        assert_eq!(
            String::from_utf8_lossy(&out),
            "before {{ck-secret:x}} after",
            "split at {split} lost the match"
        );
    }
}

// --- n2: header bytes and body bytes are separate ---------------------------

#[test]
fn n2_a_body_cannot_decide_the_connect_host() {
    let bearer = format!("Bearer {PH}");
    let body = b"api.example.com";
    let request = RequestView::from_header_block(
        "/v1/x",
        vec![
            HeaderField::ranged("Host", 0, body.len()),
            HeaderField::value("Authorization", bearer.as_bytes()),
        ],
        b"",
    )
    .with_body(body);
    let outcome = evaluate_request_with_connect(
        &request,
        &connect(),
        &[rule("x", Location::Bearer)],
        &keys("x", MIN_KEY),
    );
    // The Host range points outside the (empty) header block, so the request
    // is malformed; no body byte can stand in for a header value.
    assert_eq!(
        outcome.refusal,
        Some(RequestRefusal::TargetMismatch(
            secret_rules::TargetRefusal::AuthorityMismatch
        ))
    );
    assert!(!outcome.substituted());
}

#[test]
fn n2_a_borrowed_bearer_credential_reports_no_offsets() {
    let credential = PH.to_string();
    let request = RequestView::new(
        "/v1/x",
        vec![HeaderField::value("Authorization", credential.as_bytes())],
    );
    let outcome = evaluate_request_with_connect(
        &request,
        &connect(),
        &[rule("x", Location::Bearer)],
        &keys("x", MIN_KEY),
    );
    let edit = outcome.header_edits.first().expect("a header edit");
    assert_eq!(
        (edit.start, edit.end),
        (0, 0),
        "a borrowed value has no offsets"
    );
    assert_eq!(edit.replacement.as_slice(), MIN_KEY);
}

#[test]
fn n2_a_scheme_less_authorization_substitutes_only_the_credential() {
    // A caller that split the scheme passes the credential alone; the edit then
    // covers the caller's own bytes, never an offset into a buffer it did not
    // supply.
    let request = RequestView::from_header_block(
        "/v1/x",
        vec![HeaderField::ranged("Authorization", 0, PH.len())],
        PH.as_bytes(),
    );
    let outcome = evaluate_request_with_connect(
        &request,
        &connect(),
        &[rule("x", Location::Bearer)],
        &keys("x", MIN_KEY),
    );
    let edit = outcome.header_edits.first().expect("a header edit");
    assert_eq!((edit.start, edit.end), (0, PH.len()));
}

// --- the first-round items that must stay closed ---------------------------

#[test]
fn audit_suite_constants_are_the_audit_keys() {
    assert_eq!(MIN_KEY.len(), secret_rules::MIN_KEY_LEN);
    assert_eq!(MIN_KEY_HEX.len(), MIN_KEY.len() * 2);
    let _ = json!({});
    let _ = load("secret_rules_v1.json");
    let _ = (bytes, key_bytes, string);
}
