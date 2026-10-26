//! Entorhinal's registered ref is opaque. Resolve it to the exact AFT native
//! root/harness/session key without minting another container identity.

use super::participant::{NotBindable, RefResolver, ResolvedSession};
use cortexkit_role_agent_data::refs::Ref;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredSession {
    pub agent_id: String,
    pub ref_kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub harness: String,
    pub session_id: String,
    pub project_root: Option<String>,
}

pub trait SessionLookup: Send + Sync {
    fn session_for_ref(&self, reference: &Ref) -> Result<RegisteredSession, NotBindable>;
}

#[derive(Debug, Clone)]
pub struct NativeIdentity {
    pub root: PathBuf,
    pub harness: String,
    pub session: String,
    pub storage_harness: crate::harness::Harness,
}

/// A read of AFT's retained identities, not a new registration surface. The
/// resolver verifies the returned identity again instead of trusting aliases.
pub trait NativeIdentityLookup: Send + Sync {
    fn lookup(
        &self,
        root: &std::path::Path,
        harness: &str,
        session: &str,
    ) -> Result<NativeIdentity, NotBindable>;
}

pub struct EntorhinalRefs {
    pub registry: Arc<dyn SessionLookup>,
    pub native: Arc<dyn NativeIdentityLookup>,
}

pub fn matches_native(registered: &RegisteredSession, native: &NativeIdentity) -> bool {
    let Some(root) = &registered.project_root else {
        return false;
    };
    let Ok(expected) = cortexkit_paths::ProjectRootId::from_path(root) else {
        return false;
    };
    let Ok(actual) = cortexkit_paths::ProjectRootId::from_path(&native.root) else {
        return false;
    };
    expected == actual
        && registered.harness == native.harness
        && registered.session_id == native.session
}

impl RefResolver for EntorhinalRefs {
    fn resolve(&self, reference: &Ref) -> Result<ResolvedSession, NotBindable> {
        let registered = self.registry.session_for_ref(reference)?;
        if registered.reference != reference.r#ref
            || registered.ref_kind != reference.ref_kind
            || !matches!(
                (registered.ref_kind.as_str(), registered.harness.as_str()),
                ("opencode-session", "opencode") | ("pi-session", "pi")
            )
        {
            return Err(NotBindable);
        }
        let root = registered.project_root.as_ref().ok_or(NotBindable)?;
        let native = self.native.lookup(
            std::path::Path::new(root),
            &registered.harness,
            &registered.session_id,
        )?;
        if !matches_native(&registered, &native) {
            return Err(NotBindable);
        }
        Ok(ResolvedSession {
            registered_ref: registered.reference,
            project_root: native.root,
            harness: registered.harness,
            session: registered.session_id,
            storage_harness: native.storage_harness,
        })
    }
}
