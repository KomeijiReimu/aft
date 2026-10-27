//! Shared local-path and remote-document resolution for read-only commands.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::context::AppContext;
use crate::protocol::{RawRequest, Response};
use crate::secret::SecretVault;
use crate::url_fetch::{
    fetch_url_to_cache, is_http_url, SecretFetch, UrlFetchError, UrlFetchOptions, URL_REPLY_MARGIN,
};

/// Refusal for a placeholder fetch made outside an outline or zoom call, which
/// would have no call end to delete its private document at.
const SECRET_FETCH_NEEDS_CALL: &str =
    "Secret placeholder URLs can only be fetched by outline or zoom; nothing was fetched.";

pub(super) fn resolve_file_or_url(
    req: &RawRequest,
    ctx: &AppContext,
    file: &str,
) -> Result<PathBuf, Response> {
    resolve_with_fetch(req, ctx, file, fetch_url_to_cache)
}

/// Trusted configuration sets the private-network ceiling; a request can
/// narrow that permission but cannot grant it.
fn fetch_options(req: &RawRequest, ctx: &AppContext) -> UrlFetchOptions {
    let allow_private = ctx.config().url_fetch_allow_private
        && req
            .params
            .get("allow_private")
            .and_then(|value| value.as_bool())
            .unwrap_or(true);
    UrlFetchOptions {
        allow_private,
        ..Default::default()
    }
}

fn resolve_with_fetch(
    req: &RawRequest,
    ctx: &AppContext,
    file: &str,
    fetch: impl FnOnce(&str, &Path, UrlFetchOptions) -> Result<PathBuf, UrlFetchError>,
) -> Result<PathBuf, Response> {
    if is_http_url(file) {
        // A URL that mentions a secret placeholder never touches the URL
        // cache: not even while the cache location is unavailable.
        if let Some(labels) = crate::url_fetch::secret_labels_in_url(file) {
            return resolve_secret_fetch(req, ctx, file, &labels);
        }
        let storage_dir = ctx.cache_dir();
        let options = fetch_options(req, ctx);
        // While the cache location is unavailable (its volume is missing, or
        // the user config that names it is unreadable), `cache_dir()` falls
        // back to durable storage, which caches must not fill. Serve a fresh
        // copy already cached there, and refuse to download anything new.
        let fetched = match ctx.cache_unavailable_reason() {
            Some(reason) => {
                match crate::url_fetch::cached_url_document(file, &storage_dir, &options) {
                    Ok(Some(cached)) => Ok(cached),
                    Ok(None) => {
                        return Err(Response::error(
                            &req.id,
                            crate::root_cache::CACHE_DIR_UNAVAILABLE,
                            format!(
                                "URL download refused while the cache location is unavailable: {reason}"
                            ),
                        ))
                    }
                    Err(error) => Err(error),
                }
            }
            None => fetch(file, &storage_dir, options),
        };
        return fetched
            .map(|path| {
                // The download stopped early enough to leave time for reading the
                // document back. Those reads must not use the reply margin too: a
                // stalled read then fails while the reply still reaches the caller
                // before the call's deadline.
                crate::bounded_io::keep_reply_margin(URL_REPLY_MARGIN);
                path
            })
            .map_err(|error| url_fetch_error_response(&req.id, &error));
    }
    ctx.validate_read_path(&req.id, req.session(), Path::new(file))
}

/// A failed fetch keeps its typed code; a timeout also names its phase, and
/// a failure repeated from memory says so and when a new fetch is possible.
fn url_fetch_error_response(id: &str, error: &UrlFetchError) -> Response {
    let mut data = serde_json::Map::new();
    if let Some(phase) = error.phase() {
        data.insert("phase".into(), phase.as_str().into());
    }
    if let Some(retry_after) = error.retry_after() {
        data.insert("cached".into(), true.into());
        data.insert(
            "retry_after_ms".into(),
            (retry_after.as_millis() as u64).into(),
        );
    }
    if data.is_empty() {
        return Response::error(id, error.code(), error.to_string());
    }
    Response::error_with_data(
        id,
        error.code(),
        error.to_string(),
        serde_json::Value::Object(data),
    )
}

/// Resolve a URL that mentions a secret placeholder (`labels` are the
/// well-formed ones it holds).
///
/// The order matters. A cache location that is unavailable refuses first, as
/// a plain fetch's would, but without serving a cached copy. Then every label
/// is resolved under the call's daemon-stamped authorization scope: an
/// ineligible scope refuses before the vault is asked, and the first label
/// that is pending consent or refused ends the call before anything is
/// fetched. Only then is the document fetched into a private folder outside
/// the URL cache, which the enclosing [`FetchTempScope`] deletes when the
/// call returns.
fn resolve_secret_fetch(
    req: &RawRequest,
    ctx: &AppContext,
    file: &str,
    labels: &[String],
) -> Result<PathBuf, Response> {
    let vault = fetch_vault();
    if let Some(reason) = ctx.cache_unavailable_reason() {
        return Err(secret_fetch_refusal(
            &req.id,
            vault.as_ref(),
            labels,
            crate::root_cache::CACHE_DIR_UNAVAILABLE,
            &format!("URL download refused while the cache location is unavailable: {reason}"),
        ));
    }
    if !FetchTempScope::active() {
        return Err(secret_fetch_refusal(
            &req.id,
            vault.as_ref(),
            labels,
            "url_fetch_failed",
            SECRET_FETCH_NEEDS_CALL,
        ));
    }
    #[allow(unused_mut)]
    let mut options = fetch_options(req, ctx);
    #[cfg(test)]
    TEST_FETCH_OPTIONS.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(&mut options);
        }
    });

    let mut authorization = None;
    let mut rules = Vec::with_capacity(labels.len());
    if let Some(first) = labels.first() {
        let scopes = match crate::subc::current_call_scopes() {
            Ok((scopes, _)) => scopes,
            Err(reason) => {
                let outcome = crate::secret::refuse_ineligible(first, reason);
                return Err(secret_outcome_refusal(
                    &req.id,
                    vault.as_ref(),
                    labels,
                    outcome,
                ));
            }
        };
        for label in labels {
            match crate::subc::resolve_current_secret_label(vault.as_ref(), label) {
                crate::subc::LaunchDecision::Proceed {
                    mut rule, grant_id, ..
                } => {
                    rule.grant_id = grant_id;
                    rules.push(rule);
                }
                crate::subc::LaunchDecision::Refuse(outcome) => {
                    return Err(secret_outcome_refusal(
                        &req.id,
                        vault.as_ref(),
                        labels,
                        outcome,
                    ));
                }
                crate::subc::LaunchDecision::Pending(pending) => {
                    return Err(secret_fetch_refusal(
                        &req.id,
                        vault.as_ref(),
                        labels,
                        crate::secret::SECRET_ACCESS_PENDING,
                        pending.message,
                    ));
                }
            }
        }
        authorization = Some(scopes.authorization);
    }

    let document_dir = crate::url_fetch::create_secret_fetch_dir(&ctx.cache_dir())
        .map_err(|error| url_fetch_error_response(&req.id, &error))?;
    // Owned by the enclosing call from here on, so every return below,
    // failures included, leaves the folder to be deleted at the call's end.
    FetchTempScope::adopt(document_dir.clone());
    let secrets = SecretFetch {
        vault: vault.as_ref(),
        authorization,
        labels: labels.to_vec(),
        rules,
        call_id: req.id.clone(),
    };
    let document = crate::url_fetch::fetch_url_with_secrets(file, &document_dir, options, &secrets)
        .map_err(|error| url_fetch_error_response(&req.id, &error))?;
    #[cfg(test)]
    TEST_DOCUMENT_OBSERVER.with(|observer| {
        if let Some(observer) = observer.borrow().as_ref() {
            observer(&document);
        }
    });
    crate::bounded_io::keep_reply_margin(URL_REPLY_MARGIN);
    Ok(document)
}

/// The vault a placeholder fetch resolves through: the one bash uses, which in
/// production answers `Unavailable` to everything. Tests may install their own.
fn fetch_vault() -> Arc<dyn SecretVault> {
    #[cfg(test)]
    if let Some(vault) = TEST_FETCH_VAULT.with(|slot| slot.borrow().clone()) {
        return vault;
    }
    crate::bash_background::secrets::vault()
}

fn secret_outcome_refusal(
    id: &str,
    vault: &dyn SecretVault,
    labels: &[String],
    outcome: crate::secret::LabelOutcome,
) -> Response {
    match outcome {
        crate::secret::LabelOutcome::Refuse { code, message } => {
            secret_fetch_refusal(id, vault, labels, code, &message)
        }
        // Only a refusal ends a launch here; anything else reaching this point
        // is still not a grant.
        _ => secret_fetch_refusal(
            id,
            vault,
            labels,
            crate::secret::SECRET_REFUSED,
            crate::url_fetch::SECRET_FETCH_REFUSED,
        ),
    }
}

/// Refuse a placeholder fetch before any request is sent, with one audit
/// record per scanned label naming the call's scope.
fn secret_fetch_refusal(
    id: &str,
    vault: &dyn SecretVault,
    labels: &[String],
    code: &str,
    message: &str,
) -> Response {
    let scope = crate::subc::current_secret_audit_scope().map(|scope| scope.to_scope_ref());
    for label in labels {
        let record = secret_rules::audit::AuditRecordV1::new(
            crate::secret::now_ms(),
            label,
            secret_rules::audit::Decision::Refused,
            secret_rules::audit::AuditReason::Refused,
            id,
            id,
        )
        .with_scope(scope.clone());
        let _ = vault.audit(&record);
    }
    Response::error(id, code, message)
}

thread_local! {
    /// Private documents placeholder fetches wrote during the current outline
    /// or zoom call, and how many [`FetchTempScope`]s are open on this thread.
    static FETCH_TEMP: RefCell<(usize, Vec<PathBuf>)> = const { RefCell::new((0, Vec::new())) };
}

/// Keeps the private documents of placeholder fetches for exactly one outline
/// or zoom call.
///
/// A placeholder fetch hands its caller the path of a scrubbed document in a
/// private folder, which the caller reads until it builds its reply. The
/// command handler opens one of these scopes first; when it drops, on every
/// return path, the folders registered while it was open are deleted. Scopes
/// nest: an inner one leaves the documents to the outermost, because the
/// outer call may still be reading them. A placeholder fetch with no scope
/// open is refused, so no document is ever left for a later call to clean up.
pub(super) struct FetchTempScope {
    /// Thread-local state: the scope must drop on the thread that opened it.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl FetchTempScope {
    pub(super) fn enter() -> Self {
        FETCH_TEMP.with(|state| state.borrow_mut().0 += 1);
        Self {
            _not_send: std::marker::PhantomData,
        }
    }

    fn active() -> bool {
        FETCH_TEMP.with(|state| state.borrow().0 > 0)
    }

    /// Hand `dir` to the open scope. Callers check [`Self::active`] first; a
    /// folder adopted with no scope open is deleted at once.
    fn adopt(dir: PathBuf) {
        let orphan = FETCH_TEMP.with(|state| {
            let mut state = state.borrow_mut();
            if state.0 == 0 {
                return Some(dir);
            }
            state.1.push(dir);
            None
        });
        if let Some(dir) = orphan {
            remove_fetch_dir(&dir);
        }
    }
}

impl Drop for FetchTempScope {
    fn drop(&mut self) {
        let finished = FETCH_TEMP.with(|state| {
            let mut state = state.borrow_mut();
            state.0 = state.0.saturating_sub(1);
            if state.0 == 0 {
                std::mem::take(&mut state.1)
            } else {
                Vec::new()
            }
        });
        for dir in finished {
            remove_fetch_dir(&dir);
        }
    }
}

fn remove_fetch_dir(dir: &Path) {
    if let Err(error) = std::fs::remove_dir_all(dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            log::warn!(
                "failed to delete a placeholder fetch's private folder {}: {error}",
                dir.display()
            );
        }
    }
}

#[cfg(test)]
thread_local! {
    static TEST_FETCH_VAULT: RefCell<Option<Arc<dyn SecretVault>>> = const { RefCell::new(None) };
    /// Adjusts a placeholder fetch's options (host overrides, test TLS roots).
    static TEST_FETCH_OPTIONS: RefCell<Option<Box<dyn Fn(&mut UrlFetchOptions)>>> = const { RefCell::new(None) };
    /// Sees each placeholder fetch's document path while the call still runs.
    static TEST_DOCUMENT_OBSERVER: RefCell<Option<Box<dyn Fn(&Path)>>> = const { RefCell::new(None) };
}

#[cfg(test)]
mod url_tests {
    use super::*;

    /// A context whose cache location is unknown because the user config was
    /// unreadable; `cache_dir()` then names the durable storage root.
    fn cache_unavailable_ctx(storage: &Path) -> AppContext {
        AppContext::new(
            Box::new(crate::parser::TreeSitterProvider::new()),
            crate::config::Config {
                storage_dir: Some(storage.to_path_buf()),
                cache_config_unknown: Some("user config is not valid JSONC".into()),
                ..Default::default()
            },
        )
    }

    fn outline_request(url: &str) -> RawRequest {
        serde_json::from_value(serde_json::json!({
            "id": "cache-off-url",
            "command": "outline",
            "file": url,
        }))
        .unwrap()
    }

    /// With `storage.cache_dir` set, every URL cache access goes through the
    /// cache root: the download, the fresh-cache lookup and the remembered
    /// failure check all run on the folder handed to the fetch, and a
    /// remembered failure is keyed by it. None may read or write under the
    /// durable storage root.
    #[test]
    fn url_fetches_and_their_cache_checks_use_the_cache_root() {
        let temp = tempfile::tempdir().unwrap();
        let storage = temp.path().join("storage");
        let cache_parent = temp.path().join("cache-volume");
        std::fs::create_dir(&cache_parent).unwrap();
        let mut config = crate::config::Config {
            storage_dir: Some(storage.clone()),
            cache_dir: Some(cache_parent),
            ..Default::default()
        };
        assert!(crate::root_cache::prepare_cache_root_for_test(&mut config).is_none());
        let ctx = AppContext::new(Box::new(crate::parser::TreeSitterProvider::new()), config);
        assert!(ctx.cache_unavailable_reason().is_none());
        let cache_root = ctx.cache_dir();
        assert_ne!(cache_root, storage);
        let url = "https://93.184.216.34/docs.md";
        let document = cache_root.join("url_cache").join("fetched.md");
        let resolved = resolve_with_fetch(&outline_request(url), &ctx, url, |_, folder, _| {
            assert_eq!(
                folder,
                cache_root.as_path(),
                "URL cache outside the cache root"
            );
            Ok(document.clone())
        })
        .expect("the fetch succeeded");
        assert_eq!(resolved, document);
    }

    #[test]
    fn url_download_is_refused_without_writing_while_the_cache_location_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let storage = temp.path().join("storage");
        let ctx = cache_unavailable_ctx(&storage);
        assert!(ctx.cache_unavailable_reason().is_some());
        // An address literal keeps the check off the network.
        let url = "https://93.184.216.34/docs.md";
        let refused = resolve_with_fetch(&outline_request(url), &ctx, url, |_, _, _| {
            panic!("a download started while the cache location is unavailable")
        })
        .expect_err("a fresh download must be refused");
        assert_eq!(
            refused.data["code"],
            crate::root_cache::CACHE_DIR_UNAVAILABLE
        );
        let message = refused.data["message"].as_str().unwrap();
        assert!(message.contains("cache_dir_config_unknown"), "{message}");
        assert_eq!(ctx.cache_dir(), storage);
        assert!(
            !storage.join("url_cache").exists(),
            "the refusal wrote a URL cache under durable storage"
        );
    }

    #[test]
    fn url_already_cached_still_serves_while_the_cache_location_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let storage = temp.path().join("storage");
        let ctx = cache_unavailable_ctx(&storage);
        let url = "https://93.184.216.34/docs.md";
        let cache = ctx.cache_dir();
        let content = crate::url_fetch::cache_content_path_for_url(&cache, url, ".md");
        std::fs::create_dir_all(content.parent().unwrap()).unwrap();
        std::fs::write(&content, "# cached").unwrap();
        let fetched_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        std::fs::write(
            crate::url_fetch::cache_meta_path_for_url(&cache, url),
            serde_json::json!({
                "url": url,
                "contentType": "text/markdown",
                "extension": ".md",
                "fetchedAt": fetched_at,
                "downloaded_bytes": 8,
            })
            .to_string(),
        )
        .unwrap();
        let served = resolve_with_fetch(&outline_request(url), &ctx, url, |_, _, _| {
            panic!("a download started while the cache location is unavailable")
        })
        .expect("the cached copy must still serve");
        assert_eq!(served, content);
    }

    #[test]
    fn private_fetch_permission_cannot_widen_trusted_ceiling() {
        for trusted in [false, true] {
            let ctx = AppContext::new(
                Box::new(crate::parser::TreeSitterProvider::new()),
                crate::config::Config {
                    url_fetch_allow_private: trusted,
                    ..Default::default()
                },
            );
            for requested in [None, Some(false), Some(true)] {
                let mut value = serde_json::json!({"id": "ceiling", "command": "outline"});
                if let Some(requested) = requested {
                    value["allow_private"] = requested.into();
                }
                let req = serde_json::from_value(value).unwrap();
                let resolved = resolve_with_fetch(
                    &req,
                    &ctx,
                    "https://example.com/doc.md",
                    |_, _, options| {
                        assert_eq!(options.allow_private, trusted && requested.unwrap_or(true));
                        Ok(PathBuf::from("cached.md"))
                    },
                );
                assert!(resolved.is_ok());
            }
        }
    }

    #[test]
    fn a_fetched_document_is_read_back_without_using_the_reply_margin() {
        let storage = tempfile::tempdir().unwrap();
        let document = storage.path().join("fetched.md");
        let ctx = AppContext::new(
            Box::new(crate::parser::TreeSitterProvider::new()),
            crate::config::Config {
                storage_dir: Some(storage.path().to_path_buf()),
                ..Default::default()
            },
        );
        let req =
            serde_json::from_value(serde_json::json!({"id": "slow-fetch", "command": "outline"}))
                .unwrap();
        let budget = crate::bounded_io::Budget::after(std::time::Duration::from_secs(10));
        let call_deadline = budget.deadline;
        let _call = crate::bounded_io::enter(Some(budget));
        let fetched = || {
            resolve_with_fetch(&req, &ctx, "https://example.com/doc.md", |_, _, _| {
                std::fs::write(&document, "# Title\n").unwrap();
                Ok(document.clone())
            })
            .expect("the fetch succeeded")
        };
        let path = fetched();
        assert_eq!(
            crate::bounded_io::read_to_string(&path).unwrap(),
            "# Title\n"
        );
        let read_back_deadline = |budget: Option<crate::bounded_io::Budget>| {
            budget.expect("the call budget is still in force").deadline
        };
        assert_eq!(
            read_back_deadline(crate::bounded_io::current()),
            call_deadline - URL_REPLY_MARGIN
        );
        // A second document in the same call keeps the one margin.
        fetched();
        assert_eq!(
            read_back_deadline(crate::bounded_io::current()),
            call_deadline - URL_REPLY_MARGIN
        );
    }

    #[test]
    fn untrusted_private_flag_is_refused_by_outline_and_zoom() {
        for (trusted, requested) in [(false, true), (true, false)] {
            let ctx = AppContext::new(
                Box::new(crate::parser::TreeSitterProvider::new()),
                crate::config::Config {
                    url_fetch_allow_private: trusted,
                    ..Default::default()
                },
            );
            for command in ["outline", "zoom"] {
                let req = serde_json::from_value(serde_json::json!({"id": "private-denied", "command": command, "file": "http://127.0.0.1:0/doc.md", "symbol": "Heading", "allow_private": requested})).unwrap();
                let response = if command == "outline" {
                    super::super::outline::handle_outline(&req, &ctx)
                } else {
                    super::super::zoom::handle_zoom(&req, &ctx)
                };
                assert!(!response.success);
                assert_eq!(response.data["code"], "url_fetch_failed");
                assert!(
                    response.data["message"]
                        .as_str()
                        .unwrap()
                        .to_ascii_lowercase()
                        .contains("private"),
                    "refusal must be the network policy, not a failed connection: {:?}",
                    response.data
                );
            }
        }
    }

    mod secret_fetch {
        use super::super::*;
        use crate::secret::{FakeVault, Resolution};
        use secret_rules::location::{LabelRule, Location};
        use std::io::{Read as _, Write as _};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
        use std::rc::Rc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;

        /// Key bytes with `/` and `+`, so the query copy is percent-encoded.
        const KEY: &[u8] = b"fetch-secret-key/0123456789+abc";
        const ENCODED_KEY: &str = "fetch-secret-key%2F0123456789%2Babc";
        const PLACEHOLDER: &str = "{{ck-secret:test}}";
        /// Hosts the test certificate covers and the overrides route locally.
        const HOSTS: [&str; 5] = [
            "api.secret.test",
            "other.secret.test",
            "github.com",
            "gitlab.com",
            "raw.githubusercontent.com",
        ];

        type Handler = dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync;

        /// A local HTTPS/1.1 server that records each request head and answers
        /// with what `handler` returns for the request target (`None` closes
        /// the connection without an answer).
        struct TlsServer {
            addr: SocketAddr,
            heads: Arc<Mutex<Vec<String>>>,
            connections: Arc<AtomicUsize>,
        }

        impl TlsServer {
            fn heads(&self) -> Vec<String> {
                self.heads.lock().unwrap().clone()
            }
            fn targets(&self) -> Vec<String> {
                self.heads()
                    .iter()
                    .map(|head| head.split(' ').nth(1).unwrap_or_default().to_string())
                    .collect()
            }
        }

        struct Tls {
            server: Arc<rustls::ServerConfig>,
            client: rustls::ClientConfig,
        }

        fn tls() -> Tls {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let ca = params.self_signed(&ca_key).unwrap();
            let mut names: Vec<String> = HOSTS.iter().map(|host| host.to_string()).collect();
            names.push("127.0.0.1".into());
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let leaf = rcgen::CertificateParams::new(names)
                .unwrap()
                .signed_by(&leaf_key, &ca, &ca_key)
                .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.der().clone()).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
                )
                .unwrap();
            Tls {
                server: Arc::new(server),
                client,
            }
        }

        fn serve(
            tls: &Tls,
            handler: impl Fn(&str) -> Option<Vec<u8>> + Send + Sync + 'static,
        ) -> TlsServer {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let heads = Arc::new(Mutex::new(Vec::new()));
            let connections = Arc::new(AtomicUsize::new(0));
            let handler: Arc<Handler> = Arc::new(handler);
            let config = Arc::clone(&tls.server);
            let (seen, count) = (Arc::clone(&heads), Arc::clone(&connections));
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    count.fetch_add(1, Ordering::SeqCst);
                    let (config, seen, handler) =
                        (Arc::clone(&config), Arc::clone(&seen), Arc::clone(&handler));
                    std::thread::spawn(move || {
                        let connection = rustls::ServerConnection::new(config).unwrap();
                        let mut tls = rustls::StreamOwned::new(connection, stream);
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") && head.len() < 64 * 1024 {
                            match tls.read(&mut byte) {
                                Ok(1) => head.push(byte[0]),
                                _ => return,
                            }
                        }
                        let head = String::from_utf8_lossy(&head).into_owned();
                        let target = head.split(' ').nth(1).unwrap_or_default().to_string();
                        seen.lock().unwrap().push(head);
                        if let Some(reply) = handler(&target) {
                            let _ = tls.write_all(&reply);
                            let _ = tls.flush();
                        }
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                    });
                }
            });
            TlsServer {
                addr,
                heads,
                connections,
            }
        }

        fn http(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
            let mut reply = format!(
                "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n",
                body.len()
            );
            for (name, value) in headers {
                reply.push_str(&format!("{name}: {value}\r\n"));
            }
            reply.push_str("\r\n");
            let mut bytes = reply.into_bytes();
            bytes.extend_from_slice(body);
            bytes
        }

        fn markdown(body: &[u8]) -> Vec<u8> {
            http("200 OK", &[("Content-Type", "text/markdown")], body)
        }

        /// A document that echoes the key in a heading and in body text.
        fn echo_document() -> Vec<u8> {
            let key = String::from_utf8_lossy(KEY);
            format!(
                "# Title\n\nThe server saw {key} and {ENCODED_KEY}.\n\n## Echo {key}\n\nMore.\n"
            )
            .into_bytes()
        }

        fn rule(host: &str, port: u16, prefix: &str) -> LabelRule {
            LabelRule {
                label: "test".into(),
                host: host.into(),
                port,
                path_prefix: prefix.into(),
                location: Location::Query("key".into()),
                grant_id: String::new(),
            }
        }

        fn granted_vault(rule: LabelRule) -> FakeVault {
            let vault = FakeVault::new();
            vault.set_resolution("test", crate::secret::granted(rule, "grant-1"));
            vault.set_material("test", vec![KEY.to_vec()]);
            vault
        }

        fn stamp() -> subc_protocol::scope::ScopeStamp {
            serde_json::from_value(serde_json::json!({"owner":{"kind":"reserved","module_id":"prefrontal-core"},"ref":"secret-fetch","kind":"head","scope_epoch":1,"owner_authorized":true})).unwrap()
        }

        struct Fixture {
            _temp: tempfile::TempDir,
            root: PathBuf,
            ctx: AppContext,
            tls: Tls,
        }

        fn fixture(config: crate::config::Config) -> Fixture {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("project");
            std::fs::create_dir_all(&root).unwrap();
            let config = crate::config::Config {
                storage_dir: Some(temp.path().join("storage")),
                ..config
            };
            Fixture {
                ctx: AppContext::new(Box::new(crate::parser::TreeSitterProvider::new()), config),
                root,
                _temp: temp,
                tls: tls(),
            }
        }

        /// Everything a fetch saw: the response, and each private document
        /// path the call handed to outline or zoom, with whether it existed
        /// at that moment.
        struct Run {
            response: Response,
            documents: Vec<(PathBuf, bool)>,
        }

        impl Run {
            fn text(&self) -> String {
                self.response.data.to_string()
            }
            fn code(&self) -> Option<&str> {
                self.response.data["code"].as_str()
            }
        }

        fn request(command: &str, url: &str, extra: serde_json::Value) -> RawRequest {
            let mut value = serde_json::json!({"id": format!("secret-{command}"), "command": command, "file": url});
            if let serde_json::Value::Object(extra) = extra {
                for (key, item) in extra {
                    value[key] = item;
                }
            }
            serde_json::from_value(value).unwrap()
        }

        /// Run one command with the fake vault, local host routing, and
        /// (when `scoped`) a stamped prefrontal head identity.
        fn run(
            fixture: &Fixture,
            vault: &FakeVault,
            servers: &[(&str, SocketAddr)],
            req: &RawRequest,
            scoped: bool,
        ) -> Run {
            struct Restore;
            impl Drop for Restore {
                fn drop(&mut self) {
                    TEST_FETCH_VAULT.with(|slot| slot.replace(None));
                    TEST_FETCH_OPTIONS.with(|slot| slot.replace(None));
                    TEST_DOCUMENT_OBSERVER.with(|slot| slot.replace(None));
                }
            }
            let _restore = Restore;
            let vault: Arc<dyn SecretVault> = Arc::new(vault.clone());
            TEST_FETCH_VAULT.with(|slot| slot.replace(Some(vault)));
            let client = fixture.tls.client.clone();
            let routes: Vec<(String, SocketAddr)> = servers
                .iter()
                .map(|(host, addr)| (host.to_string(), *addr))
                .collect();
            TEST_FETCH_OPTIONS.with(|slot| {
                slot.replace(Some(Box::new(move |options: &mut UrlFetchOptions| {
                    options.tls_config = Some(client.clone());
                    for (host, addr) in &routes {
                        options.public_host_overrides.push((
                            host.clone(),
                            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                        ));
                        options.connect_overrides.push((host.clone(), *addr));
                    }
                })))
            });
            let documents = Rc::new(RefCell::new(Vec::new()));
            let seen = Rc::clone(&documents);
            TEST_DOCUMENT_OBSERVER.with(|slot| {
                slot.replace(Some(Box::new(move |path: &Path| {
                    seen.borrow_mut().push((path.to_path_buf(), path.exists()));
                })))
            });
            let call = || match req.command.as_str() {
                "outline" => super::super::super::outline::handle_outline(req, &fixture.ctx),
                _ => super::super::super::zoom::handle_zoom(req, &fixture.ctx),
            };
            let response = if scoped {
                crate::subc::with_secret_identity_for_test(&fixture.root, stamp(), call)
            } else {
                call()
            };
            let documents = documents.borrow().clone();
            Run {
                response,
                documents,
            }
        }

        fn assert_no_key(text: &str) {
            let raw = String::from_utf8_lossy(KEY);
            assert!(!text.contains(raw.as_ref()), "raw key leaked: {text}");
            assert!(!text.contains(ENCODED_KEY), "encoded key leaked: {text}");
        }

        fn assert_documents_removed(run: &Run, cache: &Path) {
            assert!(
                !run.documents.is_empty(),
                "no private document was produced"
            );
            for (path, existed) in &run.documents {
                assert!(existed, "the document must exist while the call reads it");
                assert!(
                    path.starts_with(cache.join(crate::url_fetch::SECRET_FETCH_DIR)),
                    "{}",
                    path.display()
                );
                assert!(!path.exists(), "document left behind: {}", path.display());
                assert!(
                    !path.parent().unwrap().exists(),
                    "private folder left behind"
                );
            }
        }

        /// A fresh cached copy of `url` whose content must never be served.
        fn plant_sentinel(cache: &Path, url: &str) {
            let content = crate::url_fetch::cache_content_path_for_url(cache, url, ".md");
            std::fs::create_dir_all(content.parent().unwrap()).unwrap();
            std::fs::write(&content, "# SENTINEL cached copy\n").unwrap();
            std::fs::write(
                crate::url_fetch::cache_meta_path_for_url(cache, url),
                serde_json::json!({
                    "url": url,
                    "contentType": "text/markdown",
                    "extension": ".md",
                    "fetchedAt": crate::secret::now_ms(),
                    "downloaded_bytes": 22,
                })
                .to_string(),
            )
            .unwrap();
        }

        fn cache_entries(cache: &Path) -> usize {
            std::fs::read_dir(cache.join("url_cache"))
                .map(|entries| entries.count())
                .unwrap_or(0)
        }

        #[test]
        fn outline_and_zoom_substitute_a_query_placeholder_and_scrub_the_echo() {
            for command in ["outline", "zoom"] {
                let fixture = fixture(Default::default());
                let server = serve(&fixture.tls, |_| Some(markdown(&echo_document())));
                let port = server.addr.port();
                let url = format!("https://api.secret.test:{port}/v1/doc.md?key={PLACEHOLDER}");
                let cache = fixture.ctx.cache_dir();
                plant_sentinel(&cache, &url);
                let before = cache_entries(&cache);
                let vault = granted_vault(rule("api.secret.test", port, "/v1"));
                let req = request(command, &url, serde_json::json!({"symbol": "Title"}));
                let run = run(
                    &fixture,
                    &vault,
                    &[("api.secret.test", server.addr)],
                    &req,
                    true,
                );

                assert!(run.response.success, "{command}: {:?}", run.response.data);
                assert_eq!(
                    server.targets(),
                    vec![format!("/v1/doc.md?key={ENCODED_KEY}")],
                    "{command}: the key reaches the server in the query"
                );
                let head = server.heads()[0].to_ascii_lowercase();
                assert!(head.contains("accept-encoding: identity"), "{head}");
                let text = run.text();
                assert_no_key(&text);
                assert!(text.contains(PLACEHOLDER), "{command}: {text}");
                assert!(
                    !text.contains("SENTINEL"),
                    "{command}: served the cached copy"
                );
                assert_eq!(
                    cache_entries(&cache),
                    before,
                    "{command}: URL cache changed"
                );
                assert_documents_removed(&run, &cache);

                assert_eq!(vault.resolve_calls(), 1);
                assert_eq!(vault.material_calls(), 1);
                let records = vault.audit_records();
                assert_eq!(records.len(), 1, "{records:?}");
                let record = &records[0];
                assert_eq!(record.decision, secret_rules::audit::Decision::Substituted);
                assert_eq!(record.origin, format!("secret-{command}#0"));
                assert_eq!(record.location_kind.as_deref(), Some("query:key"));
                assert_eq!(record.host.as_deref(), Some("api.secret.test"));
                assert_eq!(record.scope.as_ref().unwrap().reference, "secret-fetch");
                assert!(record.to_json_line_with_key(KEY).is_ok());
            }
        }

        #[test]
        fn a_gzip_answer_to_an_identity_request_is_decoded_and_scrubbed() {
            use tokio::io::AsyncReadExt;
            let fixture = fixture(Default::default());
            let plain = echo_document();
            let mut gzipped = Vec::new();
            {
                use std::future::Future;
                let mut encoder =
                    async_compression::tokio::bufread::GzipEncoder::new(plain.as_slice());
                let mut reading = std::pin::pin!(encoder.read_to_end(&mut gzipped));
                let mut context = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(reading.as_mut().poll(&mut context).is_ready());
            }
            let server = serve(&fixture.tls, move |_| {
                Some(http(
                    "200 OK",
                    &[
                        ("Content-Type", "text/markdown"),
                        ("Content-Encoding", "gzip"),
                    ],
                    &gzipped,
                ))
            });
            let port = server.addr.port();
            let url = format!("https://api.secret.test:{port}/v1/doc.md?key={PLACEHOLDER}");
            let vault = granted_vault(rule("api.secret.test", port, "/v1"));
            let req = request("zoom", &url, serde_json::json!({"symbol": "Title"}));
            let run = run(
                &fixture,
                &vault,
                &[("api.secret.test", server.addr)],
                &req,
                true,
            );
            assert!(run.response.success, "{:?}", run.response.data);
            let text = run.text();
            assert_no_key(&text);
            assert!(text.contains("The server saw"), "not decoded: {text}");
        }

        #[test]
        fn redirects_off_the_rule_and_bad_locations_never_carry_the_key() {
            let fixture = fixture(Default::default());
            let key = String::from_utf8_lossy(KEY).into_owned();
            let other = serve(&fixture.tls, |_| Some(markdown(b"# Other\n")));
            let other_port = other.addr.port();
            let api = serve(&fixture.tls, move |target| {
                let location = if target.starts_with("/v1/cross") {
                    // The redirect itself echoes the key; it must be scrubbed
                    // before it is followed or quoted.
                    format!("https://other.secret.test:{other_port}/v1/doc.md?key={key}&k={PLACEHOLDER}")
                } else if target.starts_with("/v1/out") {
                    format!("/admin/doc.md?key={PLACEHOLDER}")
                } else if target.starts_with("/v1/bad") {
                    format!("https://[{key}")
                } else {
                    return Some(markdown(b"# Admin\n"));
                };
                Some(http("302 Found", &[("Location", &location)], b""))
            });
            let port = api.addr.port();
            let routes = [
                ("api.secret.test", api.addr),
                ("other.secret.test", other.addr),
            ];
            let vault = granted_vault(rule("api.secret.test", port, "/v1"));
            for case in ["cross", "out", "bad"] {
                let url = format!("https://api.secret.test:{port}/v1/{case}.md?key={PLACEHOLDER}");
                let req = request("outline", &url, serde_json::json!({}));
                let run = run(&fixture, &vault, &routes, &req, true);
                let text = run.text();
                assert_no_key(&text);
                match case {
                    "bad" => {
                        assert!(!run.response.success);
                        assert!(text.contains("Invalid redirect Location"), "{text}");
                        assert!(text.contains(PLACEHOLDER), "{text}");
                    }
                    _ => assert!(run.response.success, "{case}: {text}"),
                }
            }
            // Only the first hop of each fetch, on the approved prefix, got
            // the key; the off-rule hops got the placeholder.
            let mut api_targets = api.targets();
            api_targets.sort();
            assert_eq!(
                api_targets,
                vec![
                    format!("/admin/doc.md?key={PLACEHOLDER}"),
                    format!("/v1/bad.md?key={ENCODED_KEY}"),
                    format!("/v1/cross.md?key={ENCODED_KEY}"),
                    format!("/v1/out.md?key={ENCODED_KEY}"),
                ]
            );
            assert_eq!(
                other.targets(),
                vec![format!("/v1/doc.md?key={PLACEHOLDER}&k={PLACEHOLDER}")]
            );
            for head in api.heads().iter().chain(other.heads().iter()) {
                let raw = String::from_utf8_lossy(KEY);
                assert!(!head.contains(raw.as_ref()), "{head}");
            }
            for record in vault.audit_records() {
                assert!(record.to_json_line_with_key(KEY).is_ok());
            }
        }

        #[test]
        fn a_transport_error_names_only_the_placeholder_url() {
            let fixture = fixture(Default::default());
            let server = serve(&fixture.tls, |_| None);
            let port = server.addr.port();
            let url = format!("https://api.secret.test:{port}/v1/doc.md?key={PLACEHOLDER}");
            let vault = granted_vault(rule("api.secret.test", port, "/v1"));
            let req = request("outline", &url, serde_json::json!({}));
            let run = run(
                &fixture,
                &vault,
                &[("api.secret.test", server.addr)],
                &req,
                true,
            );
            assert!(!run.response.success);
            let text = run.text();
            assert_no_key(&text);
            assert!(text.contains(&url), "{text}");
            assert!(server.targets().iter().all(|t| t.contains(ENCODED_KEY)));
            assert_eq!(
                vault.material_calls(),
                1,
                "retries reuse the hop's material"
            );
        }

        #[test]
        fn web_view_urls_with_a_placeholder_are_fetched_unrewritten() {
            let fixture = fixture(Default::default());
            let server = serve(&fixture.tls, |_| Some(markdown(b"# Page\n")));
            let port = server.addr.port();
            let routes = [
                ("github.com", server.addr),
                ("gitlab.com", server.addr),
                ("raw.githubusercontent.com", server.addr),
            ];
            let github =
                format!("https://github.com:{port}/o/r/blob/main/doc.md?key={PLACEHOLDER}");
            let vault = granted_vault(rule("raw.githubusercontent.com", port, "/o"));
            let run_github = run(
                &fixture,
                &vault,
                &routes,
                &request("outline", &github, serde_json::json!({})),
                true,
            );
            assert!(
                run_github.response.success,
                "{:?}",
                run_github.response.data
            );
            let gitlab =
                format!("https://gitlab.com:{port}/g/p/-/blob/main/doc.md?key={PLACEHOLDER}");
            let vault_gitlab = granted_vault(rule("gitlab.com", port, "/g/p/-/raw"));
            let run_gitlab = run(
                &fixture,
                &vault_gitlab,
                &routes,
                &request("outline", &gitlab, serde_json::json!({})),
                true,
            );
            assert!(
                run_gitlab.response.success,
                "{:?}",
                run_gitlab.response.data
            );
            assert_eq!(
                server.targets(),
                vec![
                    format!("/o/r/blob/main/doc.md?key={PLACEHOLDER}"),
                    format!("/g/p/-/blob/main/doc.md?key={PLACEHOLDER}"),
                ]
            );
            let hosts: Vec<String> = server
                .heads()
                .iter()
                .filter_map(|head| {
                    head.lines()
                        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                        .map(str::to_string)
                })
                .collect();
            assert!(
                hosts[0].contains("github.com") && !hosts[0].contains("raw."),
                "{hosts:?}"
            );
            assert_eq!(
                vault.material_calls(),
                0,
                "the raw host's rule never received the key"
            );
            assert_eq!(vault_gitlab.material_calls(), 0);
        }

        #[test]
        fn cache_unavailable_refuses_without_serving_or_writing() {
            let fixture = fixture(crate::config::Config {
                cache_config_unknown: Some("user config is not valid JSONC".into()),
                ..Default::default()
            });
            assert!(fixture.ctx.cache_unavailable_reason().is_some());
            let server = serve(&fixture.tls, |_| Some(markdown(&echo_document())));
            let port = server.addr.port();
            let url = format!("https://api.secret.test:{port}/v1/doc.md?key={PLACEHOLDER}");
            let cache = fixture.ctx.cache_dir();
            plant_sentinel(&cache, &url);
            let before = cache_entries(&cache);
            for command in ["outline", "zoom"] {
                let vault = granted_vault(rule("api.secret.test", port, "/v1"));
                let req = request(command, &url, serde_json::json!({"symbol": "Title"}));
                let run = run(
                    &fixture,
                    &vault,
                    &[("api.secret.test", server.addr)],
                    &req,
                    true,
                );
                assert_eq!(
                    run.code(),
                    Some(crate::root_cache::CACHE_DIR_UNAVAILABLE),
                    "{command}"
                );
                assert!(!run.text().contains("SENTINEL"), "{command}");
                assert_eq!(vault.resolve_calls(), 0, "{command}");
                assert!(run.documents.is_empty());
            }
            assert_eq!(cache_entries(&cache), before);
            assert!(!cache.join(crate::url_fetch::SECRET_FETCH_DIR).exists());
            assert_eq!(server.connections.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn the_private_address_ceiling_holds_for_placeholder_fetches() {
            for (trusted, requested) in [(false, true), (true, false)] {
                let fixture = fixture(crate::config::Config {
                    url_fetch_allow_private: trusted,
                    ..Default::default()
                });
                let private = serve(&fixture.tls, |_| Some(markdown(b"# Private\n")));
                let private_port = private.addr.port();
                let api = serve(&fixture.tls, move |_| {
                    let location =
                        format!("https://127.0.0.1:{private_port}/v1/doc.md?key={PLACEHOLDER}");
                    Some(http("302 Found", &[("Location", &location)], b""))
                });
                let port = api.addr.port();
                let extra = serde_json::json!({"allow_private": requested});
                // Directly at a private address: refused before any request.
                let direct =
                    format!("https://127.0.0.1:{private_port}/v1/doc.md?key={PLACEHOLDER}");
                let vault = granted_vault(rule("127.0.0.1", private_port, "/v1"));
                let run_direct = run(
                    &fixture,
                    &vault,
                    &[],
                    &request("outline", &direct, extra.clone()),
                    true,
                );
                assert!(!run_direct.response.success);
                assert!(
                    run_direct.text().contains("Blocked private URL host"),
                    "{}",
                    run_direct.text()
                );
                assert_eq!(vault.material_calls(), 0);
                // Redirected to a private address: refused before that hop.
                let url = format!("https://api.secret.test:{port}/v1/doc.md?key={PLACEHOLDER}");
                let vault = granted_vault(rule("api.secret.test", port, "/v1"));
                let run_redirect = run(
                    &fixture,
                    &vault,
                    &[("api.secret.test", api.addr)],
                    &request("outline", &url, extra),
                    true,
                );
                assert!(!run_redirect.response.success);
                assert!(
                    run_redirect.text().contains("Blocked private URL host"),
                    "{}",
                    run_redirect.text()
                );
                assert_no_key(&run_redirect.text());
                assert_eq!(
                    private.connections.load(Ordering::SeqCst),
                    0,
                    "trusted={trusted}"
                );
            }
        }

        #[test]
        fn ineligible_or_refused_labels_fetch_nothing() {
            let fixture = fixture(Default::default());
            let server = serve(&fixture.tls, |_| Some(markdown(&echo_document())));
            let port = server.addr.port();
            let url = format!("https://api.secret.test:{port}/v1/doc.md?key={PLACEHOLDER}");
            let routes = [("api.secret.test", server.addr)];
            let req = request("outline", &url, serde_json::json!({}));

            let vault = granted_vault(rule("api.secret.test", port, "/v1"));
            let unscoped = run(&fixture, &vault, &routes, &req, false);
            assert_eq!(unscoped.code(), Some(crate::secret::SECRET_REFUSED));
            assert_eq!(vault.resolve_calls(), 0);

            let denied = FakeVault::new();
            denied.set_resolution(
                "test",
                Resolution::Denied {
                    reason: "no".into(),
                },
            );
            let run_denied = run(&fixture, &denied, &routes, &req, true);
            assert_eq!(run_denied.code(), Some(crate::secret::SECRET_REFUSED));

            let unavailable = FakeVault::new();
            let run_unavailable = run(&fixture, &unavailable, &routes, &req, true);
            assert_eq!(
                run_unavailable.code(),
                Some(crate::secret::SECRETS_UNAVAILABLE)
            );
            assert_eq!(unavailable.resolve_calls(), 1);

            assert_eq!(server.connections.load(Ordering::SeqCst), 0);
            for vault in [&vault, &denied, &unavailable] {
                let summary = vault.audit_summary();
                assert_eq!(
                    summary,
                    vec![("test".to_string(), secret_rules::audit::Decision::Refused)]
                );
            }
        }

        #[test]
        fn the_private_document_is_deleted_when_zoom_fails_after_reading_it() {
            let fixture = fixture(Default::default());
            let server = serve(&fixture.tls, |_| Some(markdown(&echo_document())));
            let port = server.addr.port();
            let url = format!("https://api.secret.test:{port}/v1/doc.md?key={PLACEHOLDER}");
            let vault = granted_vault(rule("api.secret.test", port, "/v1"));
            let req = request("zoom", &url, serde_json::json!({"symbol": "NoSuchHeading"}));
            let run = run(
                &fixture,
                &vault,
                &[("api.secret.test", server.addr)],
                &req,
                true,
            );
            assert!(!run.response.success, "{:?}", run.response.data);
            assert_no_key(&run.text());
            assert_documents_removed(&run, &fixture.ctx.cache_dir());
        }

        #[test]
        fn a_placeholder_fetch_outside_an_outline_or_zoom_call_is_refused() {
            let fixture = fixture(Default::default());
            let url = "https://93.184.216.34/v1/doc.md?key={{ck-secret:test}}";
            let req = request("outline", url, serde_json::json!({}));
            let refused = resolve_with_fetch(&req, &fixture.ctx, url, |_, _, _| {
                panic!("a placeholder URL reached the cached fetch")
            })
            .expect_err("no call scope is open");
            assert_eq!(refused.data["message"], SECRET_FETCH_NEEDS_CALL);
            assert!(!fixture
                .ctx
                .cache_dir()
                .join(crate::url_fetch::SECRET_FETCH_DIR)
                .exists());
        }

        #[test]
        fn nested_scopes_keep_documents_until_the_outermost_drops() {
            let temp = tempfile::tempdir().unwrap();
            let dir = temp.path().join("doc");
            std::fs::create_dir(&dir).unwrap();
            let outer = FetchTempScope::enter();
            {
                let _inner = FetchTempScope::enter();
                FetchTempScope::adopt(dir.clone());
            }
            assert!(
                dir.exists(),
                "an inner scope deleted a document the outer call uses"
            );
            drop(outer);
            assert!(!dir.exists());
            let orphan = temp.path().join("orphan");
            std::fs::create_dir(&orphan).unwrap();
            FetchTempScope::adopt(orphan.clone());
            assert!(
                !orphan.exists(),
                "a folder adopted with no scope must not be kept"
            );
        }
    }
}
