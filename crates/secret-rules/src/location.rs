//! P2 and P4: where a key may go in a request, and when to refuse instead of
//! guess.
//!
//! A label's rule comes only from the vault, so [`LabelRule`] is the request
//! authority this crate is allowed to trust. Evaluation is a pure function of a
//! parsed request, the connection's CONNECT authority and a key per label: it
//! returns the byte edits a proxy applies, or a refusal.
//!
//! Each key belongs to exactly one label. A request naming label A never
//! receives B's key, and a label with no key refuses the request rather than
//! borrowing another one. Edits are collected before anything is applied, and
//! any refusal empties them all, which is what makes substitution atomic per
//! request.

mod json;

pub use json::is_json_content_type;

use crate::material::{check_admissible, encode_for_location, MaterialRefusal};
use crate::placeholder::{is_label, parse_exact, PLACEHOLDER_PREFIX};
use crate::target::{
    authority_matches_connect, ConnectAuthority, RequestTarget, RuleTarget, TargetRefusal,
};
use zeroize::Zeroizing;

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
    /// No key is held for a label the request names.
    MissingMaterial,
    /// A rule label does not satisfy the placeholder grammar (P1).
    InvalidLabel,
    /// The request target carries a fragment, which a server never sees.
    FragmentInTarget,
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
            RequestRefusal::MissingMaterial => "missing_material",
            RequestRefusal::InvalidLabel => "invalid_label",
            RequestRefusal::FragmentInTarget => "fragment_in_target",
        }
    }
}

/// How one label was decided for one request.
///
/// The variant is reported in full, but `Debug` never prints replacement bytes:
/// an outcome can be logged while the request is still being assembled.
#[derive(Clone, PartialEq, Eq)]
pub enum LabelOutcome {
    /// The rule matched and the placeholder was substituted.
    Substituted {
        byte_start: usize,
        byte_end: usize,
        replacement: Zeroizing<Vec<u8>>,
    },
    /// The rule matched but the placeholder is not the whole value (P2): it
    /// goes upstream literally.
    NotWholeValue,
    /// The rule did not match; the placeholder goes upstream literally.
    OutOfScope,
    /// The label was refused; the request is not sent.
    Refused(RequestRefusal),
}

impl std::fmt::Debug for LabelOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LabelOutcome::Substituted {
                byte_start,
                byte_end,
                replacement,
            } => f
                .debug_struct("Substituted")
                .field("byte_start", byte_start)
                .field("byte_end", byte_end)
                .field("replacement_len", &replacement.len())
                .finish(),
            LabelOutcome::NotWholeValue => f.write_str("NotWholeValue"),
            LabelOutcome::OutOfScope => f.write_str("OutOfScope"),
            LabelOutcome::Refused(refusal) => f.debug_tuple("Refused").field(refusal).finish(),
        }
    }
}

impl LabelOutcome {
    /// True when this label was substituted.
    pub fn is_substituted(&self) -> bool {
        matches!(self, LabelOutcome::Substituted { .. })
    }
}

/// One byte edit: replace `[start, end)` with `replacement`.
#[derive(Clone, PartialEq, Eq)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub replacement: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Edit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Edit")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("replacement_len", &self.replacement.len())
            .finish()
    }
}

/// One header value to replace, and what it becomes.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderEdit {
    pub name: String,
    pub start: usize,
    pub end: usize,
    pub replacement: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for HeaderEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderEdit")
            .field("name", &self.name)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("replacement_len", &self.replacement.len())
            .finish()
    }
}

/// The result of evaluating every rule against one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOutcome {
    /// One entry per rule, in the caller's rule order.
    pub labels: Vec<LabelOutcome>,
    /// Edits to the query inside the request target, sorted by offset.
    pub target_edits: Vec<Edit>,
    /// Edits to header values inside the request buffer, in rule order.
    pub header_edits: Vec<HeaderEdit>,
    /// The body to send when a JSON pointer changed it.
    pub rewritten_body: Option<Zeroizing<Vec<u8>>>,
    /// Set when any label refused: nothing is sent upstream, every
    /// key-bearing edit is dropped, and any material fetched for the request is
    /// zeroized.
    pub refusal: Option<RequestRefusal>,
}

impl RequestOutcome {
    /// True when at least one location was substituted.
    ///
    /// Derived from the label outcomes, so a header or bearer substitution
    /// counts exactly like a query or body one, and a refused request never
    /// reports a substitution.
    pub fn substituted(&self) -> bool {
        self.refusal.is_none() && self.labels.iter().any(LabelOutcome::is_substituted)
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

    /// The values of every header called `name`, in wire order.
    ///
    /// A ranged value is read from the request buffer the caller supplied; a
    /// borrowed value is used as-is. Keeping those two paths apart matters:
    /// reading a ranged field from the wrong slice silently replaces the value
    /// with an unrelated one.
    fn header_values<'b>(&'b self, name: &'b str) -> Vec<&'b [u8]> {
        self.headers
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| match field.value_range {
                Some((start, end)) => self.body.get(start..end).unwrap_or_default(),
                None => field.borrowed.unwrap_or_default(),
            })
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
    /// A substitute decision with the value span inside the request buffer
    /// and the location token the audit record needs.
    Substituted {
        start: usize,
        end: usize,
        replacement: Vec<u8>,
        location: String,
    },
    NotWhole,
    OutOfScope,
}

/// Decide one non-JSON location. The key is already known to belong to the
/// rule's label.
fn decide_location<'q>(
    rule: &'q LabelRule,
    request: &RequestView<'_>,
    query: &mut QueryIndex<'q>,
    key: &[u8],
) -> Result<Decision, RequestRefusal> {
    let placeholder = crate::placeholder::placeholder_text(&rule.label);
    match &rule.location {
        Location::Bearer => {
            let values = request.header_values("authorization");
            if values.len() > 1 {
                return Err(RequestRefusal::DuplicateField);
            }
            let Some(value) = values.first() else {
                return Ok(Decision::OutOfScope);
            };
            // A ranged field holds the whole value, `Bearer <credential>`; a
            // borrowed one may hold only the credential.
            let range = value_range(request, "authorization")?;
            // The range covers the whole field value; the credential may sit
            // after the scheme inside it.
            let whole_value = value
                .get(..6)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Bearer"));
            match bearer_form(value, &rule.label, whole_value) {
                WholeValue::Whole => {
                    check_admissible(key, &rule.label, &rule.location)?;
                    let start = if whole_value {
                        range.0 + b"Bearer ".len()
                    } else {
                        range.0
                    };
                    Ok(Decision::Substituted {
                        start,
                        end: range.1,
                        replacement: key.to_vec(),
                        location: "bearer".to_string(),
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
                    location: location_kind_token(&rule.location),
                })
            } else if mentions_placeholder(value) {
                Ok(Decision::NotWhole)
            } else {
                Ok(Decision::OutOfScope)
            }
        }
        Location::Query(name) => {
            if query.is_claimed(name) {
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
                    location: location_kind_token(&rule.location),
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

/// Evaluate every rule against one request.
///
/// `keys` holds one key per label; a rule whose label has no key refuses the
/// request rather than reusing another label's key. The connection's CONNECT
/// authority is a required input: a request whose own authority disagrees with
/// it is refused before any location is considered (M4).
pub fn evaluate_request_with_connect(
    request: &RequestView<'_>,
    target: &RequestTarget<'_>,
    connect: &ConnectAuthority,
    rules: &[LabelRule],
    keys: &[(String, Vec<u8>)],
) -> RequestOutcome {
    let mut refusal = check_authority(request, connect);
    let mut outcomes: Vec<LabelOutcome> = Vec::with_capacity(rules.len());

    let mut query = QueryIndex::parse(request.target);
    // JSON locations are evaluated as one pass over the body, so their slots
    // are recorded as (rule index, outcome) and merged after that pass.
    let mut json_rules: Vec<(usize, &LabelRule)> = Vec::new();
    let mut header_edits: Vec<HeaderEdit> = Vec::new();

    for rule in rules {
        if refusal.is_none() {
            refusal = validate_rule(rule);
        }
        if let Some(err) = refusal {
            outcomes.push(LabelOutcome::Refused(err));
            continue;
        }
        let rule_target = RuleTarget {
            host: &rule.host,
            port: rule.port,
            path_prefix: &rule.path_prefix,
        };
        if target.matches(&rule_target).is_err() {
            // A target miss is the label's own business; it never refuses the
            // request, because the placeholder then goes upstream literally.
            outcomes.push(LabelOutcome::OutOfScope);
            continue;
        }
        let Some(key) = key_for(keys, &rule.label) else {
            refusal = Some(RequestRefusal::MissingMaterial);
            outcomes.push(LabelOutcome::Refused(RequestRefusal::MissingMaterial));
            continue;
        };
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
                location,
            }) => {
                let kind = &rule.location;
                // A query or body edit is reported in its own place; only a
                // header value becomes a header edit.
                let header_name = match kind {
                    Location::Bearer => Some("Authorization".to_string()),
                    Location::Header(name) => Some(name.to_ascii_lowercase()),
                    Location::Query(_) | Location::Json(_) => None,
                };
                if let Some(name) = header_name {
                    header_edits.push(HeaderEdit {
                        name,
                        start,
                        end,
                        replacement: Zeroizing::new(replacement.clone()),
                    });
                }
                let _ = location;
                outcomes.push(LabelOutcome::Substituted {
                    byte_start: start,
                    byte_end: end,
                    replacement: Zeroizing::new(replacement),
                });
            }
            Ok(Decision::NotWhole) => outcomes.push(LabelOutcome::NotWholeValue),
            Ok(Decision::OutOfScope) => outcomes.push(LabelOutcome::OutOfScope),
            Err(err) => {
                refusal = refusal.or(Some(err));
                outcomes.push(LabelOutcome::Refused(err));
            }
        }
    }

    let mut rewritten_body = None;
    if !json_rules.is_empty() && refusal.is_none() {
        let rules_only: Vec<&LabelRule> = json_rules.iter().map(|(_, rule)| *rule).collect();
        let keys_only: Vec<(String, Vec<u8>)> = rules_only
            .iter()
            .filter_map(|rule| {
                key_for(keys, &rule.label).map(|key| (rule.label.clone(), key.to_vec()))
            })
            .collect();
        match json::evaluate(request, &rules_only, &keys_only) {
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
    } else if let Some(err) = refusal {
        for (slot, _) in &json_rules {
            outcomes[*slot] = LabelOutcome::Refused(err);
        }
    }

    // Query edits carry offsets into the request target; header edits carry
    // offsets into the header buffer and are reported separately.
    let mut target_edits: Vec<Edit> = outcomes
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
    target_edits.sort_by_key(|edit| edit.start);

    finish(
        outcomes,
        target_edits,
        header_edits,
        rewritten_body,
        refusal,
    )
}

/// A refused request carries no edits at all: every key-bearing edit is dropped
/// so a caller that applies edits without checking the refusal cannot send a
/// key.
fn finish(
    labels: Vec<LabelOutcome>,
    target_edits: Vec<Edit>,
    header_edits: Vec<HeaderEdit>,
    rewritten_body: Option<Zeroizing<Vec<u8>>>,
    refusal: Option<RequestRefusal>,
) -> RequestOutcome {
    if let Some(err) = refusal {
        let labels = labels
            .into_iter()
            .map(|outcome| match outcome {
                LabelOutcome::Substituted { .. } => LabelOutcome::Refused(err),
                other => other,
            })
            .collect();
        return RequestOutcome {
            labels,
            target_edits: Vec::new(),
            header_edits: Vec::new(),
            rewritten_body: None,
            refusal: Some(err),
        };
    }
    RequestOutcome {
        labels,
        target_edits,
        header_edits,
        rewritten_body,
        refusal,
    }
}

fn key_for<'k>(keys: &'k [(String, Vec<u8>)], label: &str) -> Option<&'k [u8]> {
    keys.iter()
        .find(|(key_label, _)| key_label == label)
        .map(|(_, key)| key.as_slice())
}

/// M4: the request's own authority must match the connection's.
fn check_authority(
    request: &RequestView<'_>,
    connect: &ConnectAuthority,
) -> Option<RequestRefusal> {
    // A header value may be borrowed, or a range inside the request buffer.
    let header = |name: &str| -> Option<String> {
        request.headers.iter().find_map(|field| {
            if !field.name.eq_ignore_ascii_case(name) {
                return None;
            }
            let bytes = match field.value_range {
                Some((start, end)) => request.body.get(start..end).unwrap_or_default(),
                None => field.borrowed.unwrap_or_default(),
            };
            Some(String::from_utf8_lossy(bytes).into_owned())
        })
    };
    let host = header("host");
    let authority = header(":authority");
    authority_matches_connect(
        connect,
        host.as_deref(),
        authority.as_deref(),
        request.target,
    )
    .err()
    .map(RequestRefusal::TargetMismatch)
}

/// Rules whose fields the vault must never be able to smuggle past the grammar.
fn validate_rule(rule: &LabelRule) -> Option<RequestRefusal> {
    if !is_label(&rule.label) {
        return Some(RequestRefusal::InvalidLabel);
    }
    if let Location::Header(name) = &rule.location {
        if let Err(err) = validate_header_name(name) {
            return Some(err);
        }
    }
    if !rule.path_prefix.starts_with('/') {
        return Some(RequestRefusal::TargetMismatch(TargetRefusal::MalformedPath));
    }
    None
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

#[derive(Debug)]
enum WholeValue {
    Whole,
    NotWhole,
    Absent,
}

/// Decide how a bearer value relates to `label`.
///
/// `whole_value` says whether `value` is the complete field value (starting
/// with the `Bearer` scheme) or only the credential: a proxy passes the whole
/// value, while a caller that already split the scheme passes the credential.
fn bearer_form(value: &[u8], label: &str, whole_value: bool) -> WholeValue {
    let credential = if whole_value {
        let has_scheme = value.len() >= 6 && value[..6].eq_ignore_ascii_case(b"Bearer");
        if !has_scheme {
            return if mentions_placeholder(value) {
                WholeValue::NotWhole
            } else {
                WholeValue::Absent
            };
        }
        match value.get(6..) {
            Some(rest) if rest.first() == Some(&b' ') => &rest[1..],
            _ => {
                return if mentions_placeholder(value) {
                    WholeValue::NotWhole
                } else {
                    WholeValue::Absent
                }
            }
        }
    } else {
        value
    };
    // The credential must be exactly this label's placeholder. Anything else
    // that looks like a placeholder goes upstream literally rather than being
    // guessed at.
    let parsed_mark = std::str::from_utf8(credential).ok().and_then(parse_exact);
    match parsed_mark {
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
///
/// Names are compared **decoded**, because a server decodes them: `k%65y` and
/// `key` are the same parameter to every form and query parser, and treating
/// them as different would let a second value shadow the authorised one.
struct QueryIndex<'a> {
    text: &'a str,
    /// `(decoded name, value start, value end)` in target order.
    fields: Vec<(String, usize, usize)>,
    claimed: Vec<String>,
}

impl<'a> QueryIndex<'a> {
    fn parse(target: &'a str) -> Self {
        let mut fields = Vec::new();
        // A fragment is never sent to a server; when a target carries one, it
        // is not part of the query at all.
        let without_fragment = match target.find('#') {
            Some(at) => &target[..at],
            None => target,
        };
        if let Some(query_start) = without_fragment.find('?') {
            let query = &without_fragment[query_start + 1..];
            let mut offset = query_start + 1;
            for pair in query.split('&') {
                let pair_start = offset;
                offset += pair.len() + 1;
                if pair.is_empty() {
                    continue;
                }
                let (raw_name, value_start, value_end) = match pair.find('=') {
                    Some(eq) => (&pair[..eq], pair_start + eq + 1, pair_start + pair.len()),
                    None => (pair, pair_start + pair.len(), pair_start + pair.len()),
                };
                let name = String::from_utf8_lossy(&crate::placeholder::percent_decode_lossy(
                    raw_name.as_bytes(),
                ))
                .into_owned();
                fields.push((name, value_start, value_end));
            }
        }
        Self {
            text: target,
            fields,
            claimed: Vec::new(),
        }
    }

    fn is_claimed(&self, name: &str) -> bool {
        self.claimed.iter().any(|claimed| claimed == name)
    }

    fn claim(&mut self, name: &str) {
        if !self.is_claimed(name) {
            self.claimed.push(name.to_string());
        }
    }

    fn fields_named<'b>(
        &'b self,
        name: &'b str,
    ) -> impl Iterator<Item = (usize, usize, Vec<u8>)> + 'b {
        self.fields
            .iter()
            .filter(move |(field, _, _)| field == name)
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
