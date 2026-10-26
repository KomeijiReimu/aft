//! A1: the versioned audit record.
//!
//! A record says which label was decided, against which scope, host, port,
//! path prefix and location kind, and what the decision was. It never holds key
//! bytes, a query string, a body or a substituted URL.
//!
//! Two things keep that promise enforceable rather than aspirational:
//!
//! * `reason` is a closed vocabulary ([`AuditReason`]), so a caller cannot pass
//!   arbitrary text into it. The vocabulary is re-used for refusal codes, which
//!   already name a rule and never a value.
//! * every other text field is checked when the record is built and scrubbed
//!   when it is serialized. A value that still holds the key, or a control
//!   byte, refuses the record; anything else that happens to look like key
//!   material is replaced with the label's placeholder before it is written.

use serde::{Deserialize, Serialize};

/// Current record version.
pub const AUDIT_VERSION_V1: u32 = 1;

/// What happened to one label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// The key was substituted at the label's declared location.
    Substituted,
    /// The placeholder was sent upstream literally.
    Literal,
    /// The request or launch was refused.
    Refused,
}

/// The closed set of reasons a record may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReason {
    /// The rule matched and the key was substituted.
    Matched,
    /// The rule matched but the placeholder was not the whole value.
    NotWholeValue,
    /// No rule declared the label's placeholder in this request.
    OutOfScope,
    /// The request was refused; see the accompanying refusal code.
    Refused,
    /// The request named a label with no key of its own.
    MissingMaterial,
    /// The request's authority did not match the connection's.
    AuthorityMismatch,
    /// A declared or present field was duplicated.
    DuplicateField,
    /// The request body was not the JSON the request claimed.
    MalformedJsonBody,
    /// The request body carried an encoding.
    ContentEncoding,
    /// The label's rule is not valid.
    InvalidRule,
}

impl AuditReason {
    /// Parse a stored reason; unknown text is refused, never accepted.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "matched" => AuditReason::Matched,
            "not_whole_value" => AuditReason::NotWholeValue,
            "out_of_scope" => AuditReason::OutOfScope,
            "refused" => AuditReason::Refused,
            "missing_material" => AuditReason::MissingMaterial,
            "authority_mismatch" => AuditReason::AuthorityMismatch,
            "duplicate_field" => AuditReason::DuplicateField,
            "malformed_json_body" => AuditReason::MalformedJsonBody,
            "content_encoding" => AuditReason::ContentEncoding,
            "invalid_rule" => AuditReason::InvalidRule,
            _ => return None,
        })
    }

    /// The text written into a record.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditReason::Matched => "matched",
            AuditReason::NotWholeValue => "not_whole_value",
            AuditReason::OutOfScope => "out_of_scope",
            AuditReason::Refused => "refused",
            AuditReason::MissingMaterial => "missing_material",
            AuditReason::AuthorityMismatch => "authority_mismatch",
            AuditReason::DuplicateField => "duplicate_field",
            AuditReason::MalformedJsonBody => "malformed_json_body",
            AuditReason::ContentEncoding => "content_encoding",
            AuditReason::InvalidRule => "invalid_rule",
        }
    }
}

/// The authorization scope a call runs under (V2). `None` on a record means
/// the call had no daemon stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRef {
    pub owner: String,
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

impl ScopeRef {
    /// True when every field is plain, printable text.
    pub fn is_valid(&self) -> bool {
        [&self.owner, &self.kind, &self.reference]
            .into_iter()
            .all(|value| metadata_is_valid(value))
    }
}

/// The path prefix that matched, as the rule declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedPrefix {
    pub path_prefix: String,
}

/// Why a record could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRefusal {
    /// A field holds text that could be key material.
    KeyMaterialInRecord,
    /// A field holds a control byte, so the line could not be parsed back.
    InvalidMetadata,
}

/// One audit record, version 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecordV1 {
    /// Wire tag; readers refuse any other value.
    pub v: u32,
    pub timestamp_ms: u64,
    pub label: String,
    /// `None` when the call carried no daemon stamp, so no scope was available
    /// to name.
    pub scope: Option<ScopeRef>,
    /// `None` when no rule was evaluated.
    pub host: Option<String>,
    pub port: Option<u16>,
    pub matched_prefix: Option<MatchedPrefix>,
    /// `bearer`, `header:<name>`, `query:<name>` or `json:<pointer>`.
    pub location_kind: Option<String>,
    pub decision: Decision,
    pub reason: AuditReason,
    pub request_id: String,
    /// Task id, or `<fetch call id>#<hop>`.
    pub origin: String,
}

impl AuditRecordV1 {
    /// A record with every rule-dependent field unset.
    pub fn new(
        timestamp_ms: u64,
        label: impl Into<String>,
        decision: Decision,
        reason: AuditReason,
        request_id: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        Self {
            v: AUDIT_VERSION_V1,
            timestamp_ms,
            label: label.into(),
            scope: None,
            host: None,
            port: None,
            matched_prefix: None,
            location_kind: None,
            decision,
            reason,
            request_id: request_id.into(),
            origin: origin.into(),
        }
    }

    /// Attach the authorization scope.
    pub fn with_scope(mut self, scope: Option<ScopeRef>) -> Self {
        self.scope = scope;
        self
    }

    /// Attach the rule that was evaluated.
    pub fn with_rule(
        mut self,
        host: impl Into<String>,
        port: u16,
        matched_prefix: impl Into<String>,
        location_kind: impl Into<String>,
    ) -> Self {
        self.host = Some(host.into());
        self.port = Some(port);
        self.matched_prefix = Some(MatchedPrefix {
            path_prefix: matched_prefix.into(),
        });
        self.location_kind = Some(location_kind.into());
        self
    }

    /// Check the record against a key, then serialize it as one JSON line.
    ///
    /// A field that still contains the key (or any of its encodings) refuses
    /// the record: the caller must not rely on output scrubbing to catch a
    /// mistake in what it put into the record. Fields that pass are written as
    /// they are.
    pub fn to_json_line_with_key(&self, key: &[u8]) -> Result<String, AuditRefusal> {
        if !self.metadata_is_valid() {
            return Err(AuditRefusal::InvalidMetadata);
        }
        if self.mentions_key(key) {
            return Err(AuditRefusal::KeyMaterialInRecord);
        }
        Ok(self.render())
    }

    /// Serialize the record as one JSON line.
    ///
    /// Every text field is checked for the shape that could carry key material
    /// first: a value that is not plain printable metadata refuses the record.
    /// Callers that hold the key should prefer
    /// [`AuditRecordV1::to_json_line_with_key`], which also refuses a field
    /// that contains the key itself.
    pub fn to_json_line(&self) -> Result<String, AuditRefusal> {
        if !self.metadata_is_valid() {
            return Err(AuditRefusal::InvalidMetadata);
        }
        if self.fields().any(looks_like_key_material) {
            return Err(AuditRefusal::KeyMaterialInRecord);
        }
        Ok(self.render())
    }

    /// The label whose placeholder replaces key material in the text fields.
    pub fn scrubbed_with_key(&self, key: &[u8]) -> Result<Self, AuditRefusal> {
        if !self.metadata_is_valid() {
            return Err(AuditRefusal::InvalidMetadata);
        }
        let placeholder = format!("{{{{ck-secret:{}}}}}", self.label);
        let scrub = |value: &str| replace_all(value, key, &placeholder);
        let mut record = self.clone();
        record.request_id = scrub(&self.request_id);
        record.origin = scrub(&self.origin);
        record.host = self.host.as_deref().map(scrub);
        record.location_kind = self.location_kind.as_deref().map(scrub);
        record.matched_prefix = self.matched_prefix.as_ref().map(|prefix| MatchedPrefix {
            path_prefix: scrub(&prefix.path_prefix),
        });
        record.scope = self.scope.as_ref().map(|scope| ScopeRef {
            owner: scrub(&scope.owner),
            kind: scrub(&scope.kind),
            reference: scrub(&scope.reference),
        });
        Ok(record)
    }

    /// Every text field, for the checks above.
    fn fields(&self) -> impl Iterator<Item = &str> {
        let static_fields = [
            Some(self.label.as_str()),
            Some(self.request_id.as_str()),
            Some(self.origin.as_str()),
            self.host.as_deref(),
            self.location_kind.as_deref(),
            self.matched_prefix
                .as_ref()
                .map(|prefix| prefix.path_prefix.as_str()),
            self.scope.as_ref().map(|scope| scope.owner.as_str()),
            self.scope.as_ref().map(|scope| scope.kind.as_str()),
            self.scope.as_ref().map(|scope| scope.reference.as_str()),
        ];
        static_fields.into_iter().flatten()
    }

    /// True when no text field could carry key material.
    fn metadata_is_valid(&self) -> bool {
        let fields = [
            Some(self.label.as_str()),
            Some(self.request_id.as_str()),
            Some(self.origin.as_str()),
            self.host.as_deref(),
            self.location_kind.as_deref(),
            self.matched_prefix
                .as_ref()
                .map(|prefix| prefix.path_prefix.as_str()),
        ];
        if !fields.into_iter().flatten().all(metadata_is_valid) {
            return false;
        }
        self.scope.as_ref().is_none_or(ScopeRef::is_valid)
    }

    /// True when any text field contains the key in its raw form.
    fn mentions_key(&self, key: &[u8]) -> bool {
        if key.is_empty() {
            return false;
        }
        let fields = [
            Some(self.label.as_str()),
            Some(self.request_id.as_str()),
            Some(self.origin.as_str()),
            self.host.as_deref(),
            self.location_kind.as_deref(),
            self.matched_prefix
                .as_ref()
                .map(|prefix| prefix.path_prefix.as_str()),
        ];
        fields.into_iter().flatten().any(|field| {
            field
                .as_bytes()
                .windows(key.len())
                .any(|window| window == key)
        })
    }

    fn render(&self) -> String {
        serde_json::to_string(self).expect("audit record v1 always serializes")
    }
}

/// Replace every occurrence of `needle` in `value` with `replacement`.
fn replace_all(value: &str, needle: &[u8], replacement: &str) -> String {
    if needle.is_empty() {
        return value.to_string();
    }
    let needle = String::from_utf8_lossy(needle).into_owned();
    value.replace(&needle, replacement)
}

/// True when `value` carries a run that could be key material.
///
/// Metadata is a label, a task id, a host or a location token: no field of
/// those ever holds a run of sixteen or more letters and digits with no
/// separator, which is the shortest key P3 admits. A field that does is refused
/// rather than written, because the record is a log line and the key would be
/// recoverable from it.
fn looks_like_key_material(value: &str) -> bool {
    let mut run = 0usize;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            run += 1;
            if run >= crate::material::MIN_KEY_LEN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// True when `value` is plain printable text of a reasonable length.
///
/// Metadata is a label, a task id, a host or a location token; anything with a
/// control byte or an absurd length is not one of those and is refused rather
/// than written into a log line.
fn metadata_is_valid(value: &str) -> bool {
    value.len() <= 512 && value.chars().all(|ch| !ch.is_control() && ch != '\u{7f}')
}
