//! M3: every redirect is a new request, evaluated from scratch.
//!
//! A redirect is not a continuation of the request that caused it. The new
//! location gets its own scheme, host, port and path check, so a hop to
//! another host, another scheme or another port never receives the key.

use crate::location::RequestRefusal;
use crate::placeholder::mentions_label_loose;
use crate::target::{
    canonical_host, normalize_request_target, path_covers, RequestTarget, RuleTarget, TargetRefusal,
};
use crate::LabelRule;

/// How a redirect hop was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOutcome {
    /// At least one rule covers the hop; substitute as for a fresh request.
    Authorized,
    /// No rule covers the hop; send the placeholder literally.
    NotAuthorized,
}

/// Resolve a `Location` header value against `current`, then parse it.
///
/// A relative reference inherits the current request's scheme, host and port,
/// but is still a new request under M3.
pub fn resolve_location(
    location: &str,
    current: &RequestTarget<'_>,
) -> Result<String, TargetRefusal> {
    let location = location.trim();
    if location.is_empty() {
        return Err(TargetRefusal::MalformedAuthority);
    }
    if location.starts_with("https://") || location.starts_with("HTTPS://") {
        return Ok(location.to_string());
    }
    if location.contains("://") {
        // A non-HTTPS scheme resolves as-is; evaluation refuses it later.
        return Ok(location.to_string());
    }
    if let Some(authority_and_path) = location.strip_prefix("//") {
        return Ok(format!("https://{authority_and_path}"));
    }
    let port = if current.port == 443 {
        String::new()
    } else {
        format!(":{}", current.port)
    };
    let path = if location.starts_with('/') {
        location.to_string()
    } else {
        let base = current.target.split('?').next().unwrap_or("/");
        let directory = match base.rfind('/') {
            Some(at) => &base[..=at],
            None => "/",
        };
        format!("{directory}{location}")
    };
    Ok(format!("https://{}{port}{path}", current.host))
}

/// Split an absolute URL into the request target it implies.
///
/// Returns `(scheme, host, port, origin_form_target)`.
pub fn split_absolute(url: &str) -> Result<(String, String, u16, String), TargetRefusal> {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return Err(TargetRefusal::NotOriginForm),
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    let (host, port) = split_host_port(authority)?;
    let target = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Ok((scheme, host, port, target))
}

fn split_host_port(authority: &str) -> Result<(String, u16), TargetRefusal> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((inner, tail)) = rest.split_once(']') else {
            return Err(TargetRefusal::MalformedAuthority);
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse()
                .map_err(|_| TargetRefusal::MalformedAuthority)?,
            None => 443,
        };
        return Ok((canonical_host(&format!("[{inner}]"))?, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| TargetRefusal::MalformedAuthority)?;
            Ok((canonical_host(host)?, port))
        }
        None => Ok((canonical_host(authority)?, 443)),
    }
}

/// Decide whether a redirect hop may receive `rules`' keys.
///
/// The second element names, per rule, why it was not authorized.
pub fn evaluate_redirect(
    rules: &[LabelRule],
    hop: &RequestTarget<'_>,
) -> (RedirectOutcome, Vec<RequestRefusal>) {
    let mut authorized = false;
    let mut refusals = Vec::new();
    for rule in rules {
        let target = RuleTarget {
            host: &rule.host,
            port: rule.port,
            path_prefix: &rule.path_prefix,
        };
        match hop.matches(&target) {
            Ok(_) => authorized = true,
            Err(err) => refusals.push(RequestRefusal::TargetMismatch(err)),
        }
    }
    let outcome = if authorized {
        RedirectOutcome::Authorized
    } else {
        RedirectOutcome::NotAuthorized
    };
    (outcome, refusals)
}

/// True when a `Location` value still mentions the label's placeholder, so a
/// redirect to an authorized path is substituted exactly like a client
/// request.
pub fn location_mentions(location: &str, label: &str) -> bool {
    mentions_label_loose(location, label)
}

/// True when `path` stays under `prefix` after normalization.
pub fn path_is_covered(path: &str, prefix: &str) -> bool {
    normalize_request_target(path)
        .map(|normalized| path_covers(&normalized.value, prefix.trim_end_matches('/')))
        .unwrap_or(false)
}
