//! P2 and P4: where a key may go in a request, and when to refuse instead of
//! guess.
//!
//! A label's rule comes only from the vault, so [`LabelRule`] is the request
//! authority this crate is allowed to trust. Evaluation is a pure function of a
//! parsed request plus the rules: it returns the byte edits a proxy applies, or
//! a refusal. Edits are collected before anything is applied, and any refusal
//! empties the edit list, which is what makes substitution atomic per request.

mod json;

pub use json::is_json_content_type;

use crate::material::{check_admissible, encode_for_location, MaterialRefusal};
use crate::placeholder::{parse_exact, PLACEHOLDER_PREFIX};
use crate::target::{RequestTarget, RuleTarget, TargetRefusal};

/// Where a key is substituted (P2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// The `Authorization` value is exactly `Bearer <placeholder>`, with the
    /// scheme matched case-insensitively.
    Bearer,
    /// The whole value of the named header.
    Header(String),
    /// The whole value of the named query parameter, after percent-decoding.
    Query(String),
    /// An RFC 6901 pointer to a JSON string whose whole value is the
    /// placeholder.
    Json(String),
}

/// Short name of a location kind, used in audit records.
pub fn location_kind_token(location: &Location) -> String {
    match location {
        Location::Bearer => "bearer".to_string(),
        Location::Header(name) => format!("header:{}", name.to_ascii_lowercase()),
        Location::Query(name) => format!("query:{name}"),
        Location::Json(pointer) => format!("json:{pointer}"),
    }
}

/// A label's rule, as resolved by the vault (V1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelRule {
    pub label: String,
    pub host: String,
    pub port: u16,
    pub path_prefix: String,
    pub location: Location,
    /// Opaque grant identifier; the vault compares it, the crate never parses
    /// it.
    pub grant_id: String,
}

/// Why a request is refused (P2, P4, and the target rules it depends on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRefusal {
    /// A duplicate of a declared header or query parameter exists (P4).
    DuplicateField,
    /// A declared header name is not a valid HTTP field name (P2).
    InvalidHeaderName,
    /// A declared header name may not carry a key (P2).
    ReservedHeaderName,
    /// A JSON pointer is malformed (P2, P4).
    InvalidJsonPointer,
    /// A pointer names something other than a single string (P4).
    NonStringJsonTarget,
    /// The JSON body cannot be parsed (P4).
    MalformedJsonBody,
    /// The body is over the 1 MiB cap (P4).
    BodyTooLarge,
    /// The request body carries a Content-Encoding (P4).
    ContentEncodingPresent,
    /// A JSON body's Content-Type is not `application/json` or `+json` (P4).
    JsonContentTypeMissing,
    /// The request target and the rule disagree on host, scheme, port or path
    /// (M1, M2).
    TargetMismatch(TargetRefusal),
    /// The request's own authority is not the connection's CONNECT authority
    /// (M4).
    AuthorityMismatch,
    /// A key cannot be used at its location (P3).
    Material(MaterialRefusal),
}

impl From<MaterialRefusal> for RequestRefusal {
    fn from(value: MaterialRefusal) -> Self {
        RequestRefusal::Material(value)
    }
}

impl RequestRefusal {
    /// Stable reason tag for audit records.
    pub fn reason(&self) -> &'static str {
        match self {
            RequestRefusal::DuplicateField => "duplicate_field",
            RequestRefusal::InvalidHeaderName => "invalid_header_name",
            RequestRefusal::ReservedHeaderName => "reserved_header_name",
            RequestRefusal::InvalidJsonPointer => "invalid_json_pointer",
            RequestRefusal::NonStringJsonTarget => "non_string_json_target",
            RequestRefusal::MalformedJsonBody => "malformed_json_body",
            RequestRefusal::BodyTooLarge => "body_too_large",
            RequestRefusal::ContentEncodingPresent => "content_encoding",
            RequestRefusal::JsonContentTypeMissing => "not_json",
            RequestRefusal::TargetMismatch(TargetRefusal::SchemeNotHttps) => "scheme_not_https",
            RequestRefusal::TargetMismatch(TargetRefusal::HostMismatch) => "host_mismatch",
            RequestRefusal::TargetMismatch(TargetRefusal::PortMismatch) => "port_mismatch",
            RequestRefusal::TargetMismatch(TargetRefusal::PathOutsidePrefix) => {
                "path_outside_prefix"
            }
            RequestRefusal::TargetMismatch(TargetRefusal::AmbiguousPathSeparator) => {
                "ambiguous_separator"
            }
            RequestRefusal::TargetMismatch(TargetRefusal::EmptySegment) => "empty_segment",
            RequestRefusal::TargetMismatch(TargetRefusal::NotOriginForm) => "not_origin_form",
            RequestRefusal::TargetMismatch(TargetRefusal::MalformedPath) => "malformed_path",
            RequestRefusal::TargetMismatch(TargetRefusal::MalformedAuthority) => {
                "malformed_authority"
            }
            RequestRefusal::AuthorityMismatch => "authority_mismatch",
            RequestRefusal::Material(MaterialRefusal::Empty) => "material_empty",
            RequestRefusal::Material(MaterialRefusal::TooShort) => "material_too_short",
            RequestRefusal::Material(MaterialRefusal::SubstringOfPlaceholder) => {
                "material_in_placeholder"
            }
            RequestRefusal::TargetMismatch(TargetRefusal::AuthorityMismatch) => {
                "authority_mismatch"
            }
            RequestRefusal::Material(MaterialRefusal::NonVisibleHeaderByte) => {
                "material_not_visible"
            }
        }
    }
}

/// How one label was decided for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelOutcome {
    /// The rule matched and the placeholder was substituted.
    Substituted {
        byte_start: usize,
        byte_end: usize,
        replacement: Vec<u8>,
    },
    /// The rule matched but the placeholder is not the whole value (P2): it
    /// goes upstream literally.
    NotWholeValue,
    /// The rule did not match; the placeholder goes upstream literally.
    OutOfScope,
    /// The label was refused; the request is not sent.
    Refused(RequestRefusal),
}

/// One byte edit: replace `[start, end)` with `replacement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub replacement: Vec<u8>,
}

/// The result of evaluating every rule against one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOutcome {
    /// One entry per rule, in the caller's rule order.
    pub labels: Vec<LabelOutcome>,
    /// Edits to the query inside the request target, sorted by offset.
    pub target_edits: Vec<Edit>,
    /// The body to send when a JSON pointer changed it.
    pub rewritten_body: Option<Vec<u8>>,
    /// Set when any label refused: nothing is sent upstream and any material
    /// fetched for the request is zeroized.
    pub refusal: Option<RequestRefusal>,
}

impl RequestOutcome {
    /// True when at least one location was substituted.
    pub fn substituted(&self) -> bool {
        !self.target_edits.is_empty() || self.rewritten_body.is_some()
    }
}

/// A header field of a request under evaluation.
#[derive(Debug, Clone)]
pub struct HeaderField<'a> {
    pub name: &'a str,
    /// Byte range of the value inside the request buffer, when the caller has
    /// one contiguous buffer.
    pub value_range: Option<(usize, usize)>,
    /// The value bytes, for callers that evaluate a decision and rewrite it
    /// elsewhere (fetch).
    pub borrowed: Option<&'a [u8]>,
}

impl<'a> HeaderField<'a> {
    /// A header whose value bytes are known but whose position is not.
    pub fn value(name: &'a str, value: &'a [u8]) -> Self {
        Self {
            name,
            value_range: None,
            borrowed: Some(value),
        }
    }

    /// A header whose value is a range inside the request buffer.
    pub fn ranged(name: &'a str, start: usize, end: usize) -> Self {
        Self {
            name,
            value_range: Some((start, end)),
            borrowed: None,
        }
    }

    fn bytes<'b>(&'b self, buffer: &'b [u8]) -> &'b [u8] {
        if let Some((start, end)) = self.value_range {
            return buffer.get(start..end).unwrap_or_default();
        }
        self.borrowed.unwrap_or_default()
    }
}

/// A request to evaluate.
#[derive(Debug, Clone)]
pub struct RequestView<'a> {
    /// The request target, exactly as received.
    pub target: &'a str,
    pub headers: Vec<HeaderField<'a>>,
    pub body: &'a [u8],
}

impl<'a> RequestView<'a> {
    /// A bodyless request.
    pub fn new(target: &'a str, headers: Vec<HeaderField<'a>>) -> Self {
        Self {
            target,
            headers,
            body: &[],
        }
    }

    /// Attach a request body.
    pub fn with_body(mut self, body: &'a [u8]) -> Self {
        self.body = body;
        self
    }

    fn header_values<'b>(&'b self, name: &'b str) -> Vec<&'b [u8]> {
        self.headers
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.bytes(self.body))
            .collect()
    }
}

/// Largest request body a JSON location may be declared against (P4).
pub const MAX_SUBSTITUTABLE_BODY: usize = 1024 * 1024;

/// Header names that may never carry a key (P2).
pub const RESERVED_HEADER_NAMES: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "upgrade",
    "te",
    "trailer",
    "accept-encoding",
    "cookie",
];

/// True when `name` is reserved, a `Sec-WebSocket-*` name, or a pseudo-header.
pub fn header_name_is_reserved(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered.starts_with(':')
        || lowered.starts_with("sec-websocket-")
        || RESERVED_HEADER_NAMES.contains(&lowered.as_str())
}

/// Validate a rule's header name for P2.
pub fn validate_header_name(name: &str) -> Result<(), RequestRefusal> {
    let bytes = name.as_bytes();
    // A reserved name is reported as reserved even when it is also a
    // pseudo-header (`:authority`), because the rule that matters is P2's.
    if header_name_is_reserved(name) {
        return Err(RequestRefusal::ReservedHeaderName);
    }
    if bytes.is_empty() || !bytes.iter().all(|byte| is_token_byte(*byte)) {
        return Err(RequestRefusal::InvalidHeaderName);
    }
    Ok(())
}

/// RFC 7230 `tchar`.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// What `evaluate_location` decided for one non-JSON rule.
enum Decision {
    /// A substitute decision with the value span inside the request buffer,
    /// or the replacement bytes for a query parameter.
    Substituted {
        start: usize,
        end: usize,
        replacement: Vec<u8>,
    },
    NotWhole,
    OutOfScope,
}

/// Evaluate every rule against one request for `key`.
pub fn evaluate_request(
    request: &RequestView<'_>,
    target: &RequestTarget<'_>,
    rules: &[LabelRule],
    key: &[u8],
) -> RequestOutcome {
    let mut outcomes: Vec<LabelOutcome> = Vec::with_capacity(rules.len());
    let mut refusal: Option<RequestRefusal> = None;

    let mut query = QueryIndex::parse(request.target);
    // JSON locations are evaluated as one pass over the body, so their slots
    // are recorded as (rule index, outcome) and merged after that pass.
    let mut json_rules: Vec<(usize, &LabelRule)> = Vec::new();

    for rule in rules {
        let rule_target = RuleTarget {
            host: &rule.host,
            port: rule.port,
            path_prefix: &rule.path_prefix,
        };
        if let Err(err) = target.matches(&rule_target) {
            outcomes.push(LabelOutcome::OutOfScope);
            // A target miss is the label's own business; it never refuses the
            // request, because the placeholder then simply goes upstream
            // literally (P2).
            let _ = err;
            continue;
        }
        if let Location::Json(_) = rule.location {
            json_rules.push((outcomes.len(), rule));
            outcomes.push(LabelOutcome::OutOfScope);
            continue;
        }
        match decide_location(rule, request, &mut query, key) {
            Ok(Decision::Substituted {
                start,
                end,
                replacement,
            }) => outcomes.push(LabelOutcome::Substituted {
                byte_start: start,
                byte_end: end,
                replacement,
            }),
            Ok(Decision::NotWhole) => outcomes.push(LabelOutcome::NotWholeValue),
            Ok(Decision::OutOfScope) => outcomes.push(LabelOutcome::OutOfScope),
            Err(err) => {
                refusal = refusal.or(Some(err));
                outcomes.push(LabelOutcome::Refused(err));
            }
        }
    }
    let mut rewritten_body = None;
    if !json_rules.is_empty() {
        let rules_only: Vec<&LabelRule> = json_rules.iter().map(|(_, rule)| *rule).collect();
        match json::evaluate(request, &rules_only, key) {
            Ok(result) => {
                for ((slot, _), outcome) in json_rules.iter().zip(result.outcomes) {
                    outcomes[*slot] = outcome;
                }
                rewritten_body = result.rewritten_body;
            }
            Err(err) => {
                refusal = refusal.or(Some(err));
                outcomes = rules.iter().map(|_| LabelOutcome::Refused(err)).collect();
                rewritten_body = None;
            }
        }
    }

    let target_edits: Vec<Edit> = if refusal.is_some() {
        Vec::new()
    } else {
        // Only query substitutions carry offsets into the request target; a
        // header value's offsets belong to the header block, which the caller
        // rewrites itself.
        let mut edits: Vec<Edit> = outcomes
            .iter()
            .zip(rules.iter())
            .filter_map(|(outcome, rule)| match (outcome, &rule.location) {
                (
                    LabelOutcome::Substituted {
                        byte_start,
                        byte_end,
                        replacement,
                    },
                    Location::Query(_),
                ) => Some(Edit {
                    start: *byte_start,
                    end: *byte_end,
                    replacement: replacement.clone(),
                }),
                _ => None,
            })
            .collect();
        edits.sort_by_key(|edit| edit.start);
        edits
    };

    if refusal.is_some() {
        rewritten_body = None;
    }

    RequestOutcome {
        labels: outcomes,
        target_edits,
        rewritten_body,
        refusal,
    }
}

fn decide_location<'q>(
    rule: &'q LabelRule,
    request: &RequestView<'_>,
    query: &mut QueryIndex<'q>,
    key: &[u8],
) -> Result<Decision, RequestRefusal> {
    // Two literal closing braces; write them without format braces so the
    // target is unambiguous.
    let placeholder = format!("{}{}", PLACEHOLDER_PREFIX, rule.label) + "}}";
    match &rule.location {
        Location::Bearer => {
            let values = request.header_values("authorization");
            if values.len() > 1 {
                return Err(RequestRefusal::DuplicateField);
            }
            let Some(value) = values.first() else {
                return Ok(Decision::OutOfScope);
            };
            match bearer_form(value, &rule.label) {
                WholeValue::Whole => {
                    check_admissible(key, &rule.label, &rule.location)?;
                    let (start, end) = value_range(request, "authorization")?;
                    // The credential starts after the `Bearer ` scheme, which
                    // is six bytes plus one space.
                    Ok(Decision::Substituted {
                        start: start + b"Bearer ".len(),
                        end,
                        replacement: key.to_vec(),
                    })
                }
                WholeValue::NotWhole => Ok(Decision::NotWhole),
                WholeValue::Absent => Ok(Decision::OutOfScope),
            }
        }
        Location::Header(name) => {
            validate_header_name(name)?;
            let values = request.header_values(name);
            if values.len() > 1 {
                return Err(RequestRefusal::DuplicateField);
            }
            let Some(value) = values.first() else {
                return Ok(Decision::OutOfScope);
            };
            if *value == placeholder.as_bytes() {
                check_admissible(key, &rule.label, &rule.location)?;
                let (start, end) = value_range(request, name)?;
                Ok(Decision::Substituted {
                    start,
                    end,
                    replacement: key.to_vec(),
                })
            } else if mentions_placeholder(value) {
                Ok(Decision::NotWhole)
            } else {
                Ok(Decision::OutOfScope)
            }
        }
        Location::Query(name) => {
            if query.claimed(name) {
                return Err(RequestRefusal::DuplicateField);
            }
            query.claim(name);
            let mut fields = query.fields_named(name);
            let first = fields.next();
            if fields.next().is_some() {
                return Err(RequestRefusal::DuplicateField);
            }
            let Some((start, end, decoded)) = first else {
                return Ok(Decision::OutOfScope);
            };
            if decoded == placeholder.as_bytes() {
                let replacement = encode_for_location(key, &rule.label, &rule.location)?;
                Ok(Decision::Substituted {
                    start,
                    end,
                    replacement,
                })
            } else if mentions_placeholder(&decoded) {
                Ok(Decision::NotWhole)
            } else {
                Ok(Decision::OutOfScope)
            }
        }
        Location::Json(_) => Ok(Decision::OutOfScope),
    }
}

/// The byte range of a header value inside the request buffer.
///
/// A caller that only asks for a decision (fetch) passes no buffer, and then
/// the decision is still made: the caller rewrites its own header block and
/// does not need offsets.
fn value_range(request: &RequestView<'_>, name: &str) -> Result<(usize, usize), RequestRefusal> {
    Ok(request
        .headers
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case(name))
        .and_then(|field| field.value_range)
        .unwrap_or((0, 0)))
}

enum WholeValue {
    Whole,
    NotWhole,
    Absent,
}

fn bearer_form(value: &[u8], label: &str) -> WholeValue {
    let has_scheme = value.len() >= 6 && value[..6].eq_ignore_ascii_case(b"Bearer");
    if !has_scheme {
        return if mentions_placeholder(value) {
            WholeValue::NotWhole
        } else {
            WholeValue::Absent
        };
    }
    let credential = match value.get(6..) {
        Some(rest) if rest.first() == Some(&b' ') => &rest[1..],
        _ => {
            return if mentions_placeholder(value) {
                WholeValue::NotWhole
            } else {
                WholeValue::Absent
            }
        }
    };
    // The label is part of the placeholder grammar. Where a credential is not a
    // well-formed placeholder at all, there is nothing here for the label to
    // substitute, so the rule does not apply to it.
    match std::str::from_utf8(credential).ok().and_then(parse_exact) {
        Some(parsed) if parsed.label == label => WholeValue::Whole,
        Some(_) => WholeValue::NotWhole,
        None if mentions_placeholder(credential) => WholeValue::NotWhole,
        None => WholeValue::Absent,
    }
}

fn mentions_placeholder(value: &[u8]) -> bool {
    value
        .windows(PLACEHOLDER_PREFIX.len())
        .any(|window| window == PLACEHOLDER_PREFIX.as_bytes())
}

/// Query parameters with their byte ranges in the request target.
struct QueryIndex<'a> {
    text: &'a str,
    /// `(name, value start, value end)` in target order.
    fields: Vec<(&'a str, usize, usize)>,
    claimed: Vec<&'a str>,
}

impl<'a> QueryIndex<'a> {
    fn parse(target: &'a str) -> Self {
        let mut fields = Vec::new();
        if let Some(query_start) = target.find('?') {
            let query = &target[query_start + 1..];
            let mut offset = query_start + 1;
            for pair in query.split('&') {
                let pair_start = offset;
                offset += pair.len() + 1;
                if pair.is_empty() {
                    continue;
                }
                match pair.find('=') {
                    Some(eq) => {
                        fields.push((&pair[..eq], pair_start + eq + 1, pair_start + pair.len()))
                    }
                    None => fields.push((pair, pair_start + pair.len(), pair_start + pair.len())),
                }
            }
        }
        Self {
            text: target,
            fields,
            claimed: Vec::new(),
        }
    }

    fn claimed(&self, name: &str) -> bool {
        self.claimed.contains(&name)
    }

    fn claim(&mut self, name: &'a str) {
        self.claimed.push(name);
    }

    fn fields_named<'b>(
        &'b self,
        name: &'b str,
    ) -> impl Iterator<Item = (usize, usize, Vec<u8>)> + 'b {
        self.fields
            .iter()
            .filter(move |(field, _, _)| *field == name)
            .map(|(_, start, end)| {
                let raw = &self.text.as_bytes()[*start..*end];
                (*start, *end, crate::placeholder::percent_decode_lossy(raw))
            })
    }
}

/// Apply target-query edits to a request target.
pub fn apply_target_edits(target: &str, edits: &[Edit]) -> String {
    let bytes = target.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    for edit in edits {
        out.extend_from_slice(&bytes[cursor..edit.start]);
        out.extend_from_slice(&edit.replacement);
        cursor = edit.end;
    }
    out.extend_from_slice(&bytes[cursor..]);
    String::from_utf8_lossy(&out).into_owned()
}
