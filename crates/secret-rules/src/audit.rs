//! A1: the versioned audit record.
//!
//! A record says which label was decided, against which scope, host, port,
//! path prefix and location kind, and what the decision was. It never holds key
//! bytes, a query string, a body or a substituted URL: `origin` is rendered by
//! the caller as a task id or `<fetch call id>#<hop>`, and the crate keeps it
//! opaque.

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

/// The authorization scope a call runs under (V2). `None` on a record means
/// the call had no daemon stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRef {
    pub owner: String,
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

/// The path prefix that matched, as the rule declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedPrefix {
    pub path_prefix: String,
}

/// One audit record, version 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecordV1 {
    /// Wire tag; readers refuse any other value.
    pub v: u32,
    pub timestamp_ms: u64,
    pub label: String,
    /// `None` when the call had no stamp (B2 precedence, V2).
    pub scope: Option<ScopeRef>,
    /// `None` when no rule was evaluated.
    pub host: Option<String>,
    pub port: Option<u16>,
    pub matched_prefix: Option<MatchedPrefix>,
    /// `bearer`, `header:<name>`, `query:<name>` or `json:<pointer>`.
    pub location_kind: Option<String>,
    pub decision: Decision,
    pub reason: String,
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
        reason: impl Into<String>,
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
            reason: reason.into(),
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

    /// Serialize as one JSON line.
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).expect("audit record v1 always serializes")
    }
}
