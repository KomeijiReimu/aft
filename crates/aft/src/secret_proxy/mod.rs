//! A command-private CONNECT proxy. The launcher supplies only scanned, resolved
//! labels and arms the new command session before releasing the child. The job
//! owner retains the handle and reports process-tree end or the end of the
//! configured lifetime SecretScope, either of which stops the proxy.
//!
//! # Memory boundary
//!
//! Vault material, matcher patterns, overlap windows, and all proxy-created
//! material-bearing request staging use zeroizing owners. This includes the Bytes owners behind
//! substituted header values, query-bearing URIs, and JSON bodies. The rules
//! evaluator plans locations with public dummy bytes, never real material.
//!
//! Third-party codec buffers are outside that ownership guarantee: rustls owns
//! TLS plaintext/record buffers; h2 owns HTTP/2 stream and HPACK buffers; Hyper
//! owns its HTTP/1 encoder write buffer; async-compression and its codec crates
//! own decompression workspaces. These codecs allocate and manage their own
//! buffers rather than accepting AFT's zeroizing owners. The proxy does not
//! persist or log any of them, or format key-bearing requests or responses with
//! `Debug` or `Display`. Zeroization is defence in depth in the daemon, not a claim
//! that third-party protocol implementations erase every transient copy.

mod peer;
mod request;
mod response;
mod websocket;

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use secret_rules::location::{validate_header_name, LabelRule, Location};
use secret_rules::scrub::{MatcherSet, Scrubber};
use secret_rules::target::{canonical_host, ConnectAuthority};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::secret::vault::SecretVault;
use crate::secret::SecretScope;

pub(crate) type Body = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

/// Constant agent-visible wording; labels and hosts are appended as data.
pub const PROXY_REFUSAL: &str = "Secret proxy refused the request";

/// A launch-time resolution, not a request-time material cache.
#[derive(Clone, Debug)]
pub struct GrantedLabel {
    pub rule: LabelRule,
    pub expires_at_ms: u64,
}

pub struct ProxyConfig {
    pub vault: Arc<dyn SecretVault>,
    pub authorization_scope: SecretScope,
    pub lifetime_scope: SecretScope,
    pub scanned_labels: Vec<String>,
    pub grants: Vec<GrantedLabel>,
    pub origin: String,
}

/// Errors contain no transport diagnostics, URLs, credentials or vault text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    UnsupportedPlatform,
    InvalidRules,
    Initialization,
    InvalidSession,
    Stopped,
}

pub(crate) struct State {
    config: ProxyConfig,
    session: AtomicI32,
    stopped: AtomicBool,
    token: Zeroizing<String>,
    ca: rcgen::Certificate,
    ca_key: KeyPair,
    upstream: rustls::ClientConfig,
    material_gate: Mutex<()>,
    // Keep each installed key as an exact-byte matcher for response scrubbers.
    // Rotation adds a matcher instead of replacing earlier key values.
    patterns: Mutex<Vec<(String, Zeroizing<Vec<u8>>)>>,
    #[cfg(test)]
    headers_sensitive: AtomicBool,
}

impl State {
    fn mark_stopped(&self) {
        let _gate = self.material_gate.lock();
        self.stopped.store(true, Ordering::Release);
    }

    fn scrubber(&self) -> Result<Scrubber, ()> {
        let patterns = self.patterns.lock();
        let sets = patterns
            .iter()
            .map(|(label, key)| MatcherSet::new(label, key).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        Scrubber::new(sets).map_err(|_| ())
    }

    fn refresh(&self, scrubber: &mut Scrubber) -> Result<(), ()> {
        let patterns = self.patterns.lock();
        for (label, key) in &patterns[scrubber.matcher_count()..] {
            scrubber
                .install(MatcherSet::new(label, key).map_err(|_| ())?)
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn install(&self, label: &str, key: &[u8]) -> Result<(), ()> {
        let mut patterns = self.patterns.lock();
        if self.stopped.load(Ordering::Acquire) {
            return Err(());
        }
        if patterns
            .iter()
            .any(|(l, k)| l == label && k.as_slice() == key)
        {
            return Ok(());
        }
        let mut sets = patterns
            .iter()
            .map(|(l, k)| MatcherSet::new(l, k).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        sets.push(MatcherSet::new(label, key).map_err(|_| ())?);
        Scrubber::new(sets).map_err(|_| ())?;
        patterns.push((label.to_owned(), Zeroizing::new(key.to_vec())));
        Ok(())
    }

    fn scrub(&self, bytes: &[u8]) -> Result<Vec<u8>, ()> {
        let mut scrubber = self.scrubber()?;
        let mut out = scrubber.push(bytes);
        out.extend(scrubber.finish());
        Ok(out)
    }

    fn tls_for(&self, host: &str) -> Result<rustls::ServerConfig, ()> {
        let key = KeyPair::generate().map_err(|_| ())?;
        let cert = CertificateParams::new(vec![host.to_owned()])
            .map_err(|_| ())?
            .signed_by(&key, &self.ca, &self.ca_key)
            .map_err(|_| ())?;
        let der = Zeroizing::new(key.serialize_der());
        let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(der.to_vec()).into();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], private_key)
            .map_err(|_| ())?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Dropping or stopping the handle closes the listener and all connections.
/// Keep it in the background job, not in the launching tool call's stack frame.
pub struct SecretProxy {
    address: SocketAddr,
    ca_pem: String,
    state: Arc<State>,
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl SecretProxy {
    pub fn start(config: ProxyConfig) -> Result<Self, ProxyError> {
        let upstream =
            crate::platform_tls::client_config().map_err(|_| ProxyError::Initialization)?;
        Self::start_with_tls(config, upstream)
    }

    fn start_with_tls(
        config: ProxyConfig,
        upstream: rustls::ClientConfig,
    ) -> Result<Self, ProxyError> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err(ProxyError::UnsupportedPlatform);
        }
        let scanned: BTreeSet<_> = config.scanned_labels.iter().collect();
        let resolved: BTreeSet<_> = config.grants.iter().map(|g| &g.rule.label).collect();
        if scanned.is_empty()
            || scanned != resolved
            || resolved.len() != config.grants.len()
            || config.grants.iter().any(|g| {
                let r = &g.rule;
                !secret_rules::placeholder::is_label(&r.label)
                    || canonical_host(&r.host).is_err()
                    || secret_rules::target::normalize_path_prefix(&r.path_prefix).map_or(true, |p| p != r.path_prefix)
                    || matches!(&r.location, Location::Header(name) if validate_header_name(name).is_err())
            })
        {
            return Err(ProxyError::InvalidRules);
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut params =
            CertificateParams::new(Vec::new()).map_err(|_| ProxyError::Initialization)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().map_err(|_| ProxyError::Initialization)?;
        let ca = params
            .self_signed(&ca_key)
            .map_err(|_| ProxyError::Initialization)?;
        let ca_pem = ca.pem();
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| ProxyError::Initialization)?;
        let token = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random));
        let state = Arc::new(State {
            config,
            session: AtomicI32::new(0),
            stopped: AtomicBool::new(false),
            token,
            ca,
            ca_key,
            upstream,
            material_gate: Mutex::new(()),
            patterns: Mutex::new(Vec::new()),
            #[cfg(test)]
            headers_sensitive: AtomicBool::new(false),
        });
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| ProxyError::Initialization)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ProxyError::Initialization)?;
        let address = listener
            .local_addr()
            .map_err(|_| ProxyError::Initialization)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| ProxyError::Initialization)?;
        let (stop, receiver) = watch::channel(false);
        let shared = state.clone();
        let thread = std::thread::Builder::new()
            .name("secret-proxy".into())
            .spawn(move || {
                runtime.block_on(serve(listener, shared.clone(), receiver));
                shared.mark_stopped();
                runtime.shutdown_timeout(Duration::from_secs(1));
                shared.patterns.lock().clear();
            })
            .map_err(|_| ProxyError::Initialization)?;
        Ok(Self {
            address,
            ca_pem,
            state,
            stop,
            thread: Some(thread),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Exec-time only: never persist the returned credential with a task request.
    pub fn proxy_url(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "http://{}:@{}",
            self.state.token.as_str(),
            self.address
        ))
    }

    /// Public CA certificate only; the signer stays in daemon memory.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Arm only a newly created session leader, while the child is held at its
    /// exec barrier. Connections handled while no session is armed are refused.
    pub fn arm_command(&self, pid: u32) -> Result<(), ProxyError> {
        let pid = i32::try_from(pid).map_err(|_| ProxyError::InvalidSession)?;
        if self.state.stopped.load(Ordering::Acquire) {
            return Err(ProxyError::Stopped);
        }
        if !peer::is_session_leader(pid) {
            return Err(ProxyError::InvalidSession);
        }
        self.state
            .session
            .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ProxyError::InvalidSession)?;
        Ok(())
    }

    pub fn stop_if_scope_ended(&mut self, scope: &SecretScope) {
        if &self.state.config.lifetime_scope == scope {
            self.stop();
        }
    }

    /// The job's process-tree owner calls this even if a descendant escaped its
    /// original session; session disappearance is also watched defensively.
    pub fn process_tree_ended(&mut self) {
        self.stop();
    }

    pub fn stop(&mut self) {
        self.state.mark_stopped();
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.state.patterns.lock().clear();
    }
}

impl Drop for SecretProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn serve(
    listener: std::net::TcpListener,
    state: Arc<State>,
    mut stop: watch::Receiver<bool>,
) {
    let Ok(listener) = TcpListener::from_std(listener) else {
        return;
    };
    let mut connections = tokio::task::JoinSet::new();
    let mut monitor = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = monitor.tick() => {
                let session = state.session.load(Ordering::Acquire);
                if session > 0 && !peer::session_alive(session) { break; }
            }
            accepted = listener.accept() => {
                let Ok((socket, _)) = accepted else { break; };
                let state = state.clone();
                connections.spawn(async move {
                    let session = state.session.load(Ordering::Acquire);
                    if session <= 0 || !peer::authorized(&socket, session) { return; }
                    let service = service_fn(move |request| connect(request, state.clone()));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service).with_upgrades().await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    state.mark_stopped();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn connect(
    mut request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let refused = || refusal("", "");
    if request.method() != Method::CONNECT || state.stopped.load(Ordering::Acquire) {
        return Ok(refused());
    }
    let mut credentials = request.headers().get_all("proxy-authorization").iter();
    let expected = Zeroizing::new(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:", state.token.as_str()))
    ));
    if credentials.next().map(|v| v.as_bytes()) != Some(expected.as_bytes())
        || credentials.next().is_some()
    {
        return Ok(refused());
    }
    let Some(authority) = request.uri().authority() else {
        return Ok(refused());
    };
    let Ok(authority) = ConnectAuthority::parse(authority.as_str()) else {
        return Ok(refused());
    };
    if request.headers().get_all("host").iter().any(|h| {
        h.to_str().ok().is_none_or(|h| {
            secret_rules::target::authority_matches_connect(&authority, Some(h), None, "/").is_err()
        })
    }) {
        return Ok(refused());
    }
    let intercepted = state
        .config
        .grants
        .iter()
        .any(|g| canonical_host(&g.rule.host).ok().as_ref() == Some(&authority.host));
    let tls = if intercepted {
        match state.tls_for(&authority.host) {
            Ok(tls) => Some(tls),
            Err(()) => return Ok(refused()),
        }
    } else {
        None
    };
    let upstream = if intercepted {
        None
    } else {
        match TcpStream::connect((authority.host.as_str(), authority.port)).await {
            Ok(socket) => Some(socket),
            Err(_) => return Ok(refused()),
        }
    };
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(&mut request).await else {
            return;
        };
        let mut io = TokioIo::new(upgraded);
        if let Some(mut upstream) = upstream {
            let _ = tokio::io::copy_bidirectional(&mut io, &mut upstream).await;
        } else if let Some(tls) = tls {
            let Ok(tls) = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                .accept(io)
                .await
            else {
                return;
            };
            let service = service_fn(move |request| {
                request::forward(request, authority.clone(), state.clone())
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tls), service)
                .await;
        }
    });
    Ok(Response::new(full(Bytes::new())))
}

pub(crate) fn full(bytes: Bytes) -> Body {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

struct SecretBytes(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn secret_bytes(bytes: Zeroizing<Vec<u8>>) -> Bytes {
    Bytes::from_owner(SecretBytes(bytes))
}

pub(crate) fn refusal(label: &str, host: &str) -> Response<Body> {
    let mut response = Response::new(full(Bytes::from(format!(
        "{PROXY_REFUSAL}: {label} ({host})\n"
    ))));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(all(test, unix))]
mod tests;
