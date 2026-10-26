use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use secret_rules::location::{
    evaluate_request_with_connect, HeaderField, LabelOutcome, Location, RequestView,
};
use secret_rules::material::{check_admissible, encode_for_location};
use secret_rules::target::{
    authority_matches_connect, normalize_request_target, ConnectAuthority, RequestTarget,
    RuleTarget,
};
use zeroize::Zeroizing;

use super::{full, refusal, Body, State};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(super) async fn forward(
    request: Request<Incoming>,
    authority: ConnectAuthority,
    state: Arc<State>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let websocket = request
        .headers()
        .get("upgrade")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let fallback = state
        .config
        .grants
        .first()
        .map(|g| g.rule.label.as_str())
        .unwrap_or("");
    let result = prepare_and_send(request, &authority, &state).await;
    Ok(result.unwrap_or_else(|label| {
        let label = if label.is_empty() { fallback } else { &label };
        let bytes = Zeroizing::new(format!(
            "{}: {label} ({})\n",
            super::PROXY_REFUSAL,
            authority.host
        ));
        let mut response = refusal("", "");
        *response.body_mut() =
            full(Bytes::from(state.scrub(bytes.as_bytes()).unwrap_or_else(
                |_| super::PROXY_REFUSAL.as_bytes().to_vec(),
            )));
        if websocket {
            response.headers_mut().insert(
                "connection",
                hyper::header::HeaderValue::from_static("close"),
            );
        }
        response
    }))
}

async fn prepare_and_send(
    mut request: Request<Incoming>,
    authority: &ConnectAuthority,
    state: &Arc<State>,
) -> Result<Response<Body>, String> {
    let fail = || String::new();
    if state.stopped.load(Ordering::Acquire) {
        return Err(fail());
    }
    let target = request
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/")
        .to_owned();
    // HTTP/2 carries :authority in the URI, not in HeaderMap. Inspect both it
    // and every Host value before reducing the URI to an origin-form target.
    if request.headers().get_all("host").iter().any(|h| {
        h.to_str()
            .ok()
            .is_none_or(|h| authority_matches_connect(authority, Some(h), None, &target).is_err())
    }) || authority_matches_connect(
        authority,
        None,
        request.uri().authority().map(|a| a.as_str()),
        &target,
    )
    .is_err()
        || request.uri().scheme_str().is_some_and(|s| s != "https")
        || (request.version() != Version::HTTP_2 && request.uri().authority().is_some())
    {
        return Err(fail());
    }
    let ws = request
        .headers()
        .get("upgrade")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let client_upgrade = ws.then(|| hyper::upgrade::on(&mut request));
    let (mut parts, mut incoming) = request.into_parts();
    let rules: Vec<_> = state.config.grants.iter().map(|g| g.rule.clone()).collect();
    let target_view = RequestTarget {
        host: authority.host.clone(),
        port: authority.port,
        scheme: "https",
        target: &target,
    };
    let matches: Vec<_> = rules
        .iter()
        .map(|r| {
            target_view
                .matches(&RuleTarget {
                    host: &r.host,
                    port: r.port,
                    path_prefix: &r.path_prefix,
                })
                .is_ok()
        })
        .collect();
    let has_json = rules
        .iter()
        .zip(&matches)
        .any(|(r, m)| *m && matches!(r.location, Location::Json(_)));
    // Only JSON substitution needs a buffered body. Other uploads remain
    // streaming; they are never searched for placeholders outside their rule.
    let mut body = body_buffer(has_json);
    if has_json {
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| fail())?;
            if let Some(data) = frame.data_ref() {
                if body.len().saturating_add(data.len()) > 1024 * 1024 {
                    return Err(fail());
                }
                body.extend_from_slice(data);
            }
            if frame.trailers_ref().is_some() {
                return Err(fail());
            }
        }
    }
    let headers = parts
        .headers
        .iter()
        .map(|(n, v)| HeaderField::value(n.as_str(), v.as_bytes()))
        .collect();
    let view = RequestView::new(&target, headers).with_body(&body);
    // Use public dummy material only to plan and validate locations. Real vault
    // bytes never enter the rules evaluator's ordinary Vec key copies.
    let dummy: Vec<_> = rules
        .iter()
        .map(|r| (r.label.clone(), b"proxy-planning-value-0000".to_vec()))
        .collect();
    let plan = evaluate_request_with_connect(&view, authority, &rules, &dummy);
    if plan.refusal.is_some() {
        return Err(fail());
    }
    if has_json {
        let json: serde_json::Value = serde_json::from_slice(&body).map_err(|_| fail())?;
        for (rule, matched) in rules.iter().zip(&matches) {
            if let Location::Json(pointer) = &rule.location {
                if *matched && json.pointer(pointer).is_some_and(|v| !v.is_string()) {
                    return Err(rule.label.clone());
                }
            }
        }
    }
    let mut materials = Vec::new();
    for ((rule, matched), grant) in rules.iter().zip(&matches).zip(&state.config.grants) {
        if !matched {
            materials.push(None);
            continue;
        }
        let _gate = state.material_gate.lock();
        if state.stopped.load(Ordering::Acquire)
            || crate::secret::vault::now_ms() >= grant.expires_at_ms
        {
            return Err(rule.label.clone());
        }
        let material = state
            .config
            .vault
            .material(
                &state.config.authorization_scope,
                &rule.label,
                &rule.grant_id,
            )
            .map_err(|_| rule.label.clone())?;
        check_admissible(material.expose(), &rule.label, &rule.location)
            .map_err(|_| rule.label.clone())?;
        state
            .install(&rule.label, material.expose())
            .map_err(|_| rule.label.clone())?;
        materials.push(Some(material));
    }
    let mut query_edits = Vec::new();
    let mut body_edits = Vec::new();
    let mut header_edits = Vec::new();
    for ((rule, outcome), material) in rules.iter().zip(&plan.labels).zip(&materials) {
        if let LabelOutcome::Substituted {
            byte_start,
            byte_end,
            ..
        } = outcome
        {
            let material = material.as_ref().ok_or_else(fail)?;
            let encoded = Zeroizing::new(
                encode_for_location(material.expose(), &rule.label, &rule.location)
                    .map_err(|_| rule.label.clone())?,
            );
            match &rule.location {
                Location::Query(_) => query_edits.push((*byte_start, *byte_end, encoded)),
                Location::Json(_) => body_edits.push((*byte_start, *byte_end, encoded)),
                Location::Header(name) => header_edits.push((name.clone(), encoded)),
                Location::Bearer => header_edits.push(("authorization".to_owned(), encoded)),
            }
        }
    }
    drop(view);
    for (name, bytes) in header_edits {
        let name = hyper::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| fail())?;
        let mut value = hyper::header::HeaderValue::from_maybe_shared(super::secret_bytes(bytes))
            .map_err(|_| fail())?;
        value.set_sensitive(true);
        parts.headers.insert(name, value);
    }
    let mut wire_target = apply_edits(target.as_bytes(), &mut query_edits)?;
    if let Ok(normalized) = normalize_request_target(target.split('?').next().unwrap_or(&target)) {
        let query = wire_target
            .iter()
            .position(|c| *c == b'?')
            .map(|i| Zeroizing::new(wire_target[i..].to_vec()));
        wire_target = Zeroizing::new(normalized.wire);
        if let Some(query) = query {
            wire_target.extend_from_slice(&query);
        }
    }
    parts.uri =
        hyper::Uri::from_maybe_shared(super::secret_bytes(Zeroizing::new(wire_target.to_vec())))
            .map_err(|_| fail())?;
    parts.headers.remove("proxy-authorization");
    parts.headers.insert(
        "accept-encoding",
        hyper::header::HeaderValue::from_static("identity"),
    );
    parts.headers.remove("sec-websocket-extensions");
    super::response::strip_hop_headers(&mut parts.headers, ws);
    // Routing belongs to CONNECT, never to a client-nominated hop header or
    // the presence of a Host field on the downstream HTTP version.
    parts.headers.insert(
        "host",
        hyper::header::HeaderValue::from_str(&authority.authority()).map_err(|_| fail())?,
    );
    let outbound_body: Body = if has_json {
        let rewritten = apply_edits(&body, &mut body_edits)?;
        parts.headers.insert(
            "content-length",
            hyper::header::HeaderValue::from_str(&rewritten.len().to_string())
                .map_err(|_| fail())?,
        );
        full(super::secret_bytes(rewritten))
    } else {
        incoming
            .map_err(|_| super::response::io_error())
            .boxed_unsync()
    };
    // Validate the request and fetch and check material for every matching rule
    // before opening upstream. TLS uses a direct socket, ignoring proxy env.
    let socket = tokio::net::TcpStream::connect((authority.host.as_str(), authority.port))
        .await
        .map_err(|_| fail())?;
    let mut tls_config = state.upstream.clone();
    tls_config.alpn_protocols = if ws {
        vec![b"http/1.1".to_vec()]
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    let server_name =
        rustls::pki_types::ServerName::try_from(authority.host.clone()).map_err(|_| fail())?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_config))
        .connect(server_name, socket)
        .await
        .map_err(|_| fail())?;
    if state.stopped.load(Ordering::Acquire) {
        return Err(fail());
    }
    let http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let mut outbound = Request::from_parts(parts, outbound_body);
    if http2 {
        let host = authority.authority();
        let mut uri = Zeroizing::new(Vec::with_capacity(8 + host.len() + wire_target.len()));
        uri.extend_from_slice(b"https://");
        uri.extend_from_slice(host.as_bytes());
        uri.extend_from_slice(&wire_target);
        *outbound.uri_mut() =
            hyper::Uri::from_maybe_shared(super::secret_bytes(uri)).map_err(|_| fail())?;
        *outbound.version_mut() = Version::HTTP_2;
    } else {
        *outbound.version_mut() = Version::HTTP_11;
    }
    #[cfg(test)]
    state.headers_sensitive.store(
        plan.header_edits.iter().all(|edit| {
            outbound
                .headers()
                .get(edit.name.as_str())
                .is_some_and(|value| value.is_sensitive())
        }),
        Ordering::Release,
    );
    let response = if http2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|_| fail())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = {
            let _gate = state.material_gate.lock();
            if state.stopped.load(Ordering::Acquire) {
                return Err(fail());
            }
            sender.send_request(outbound)
        };
        drop(materials);
        response.await.map_err(|_| fail())?
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| fail())?;
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        let response = {
            let _gate = state.material_gate.lock();
            if state.stopped.load(Ordering::Acquire) {
                return Err(fail());
            }
            sender.send_request(outbound)
        };
        drop(materials);
        response.await.map_err(|_| fail())?
    };
    let _request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    super::response::forward(response, state.clone(), client_upgrade)
        .await
        .map_err(|_| fail())
}

pub(super) fn body_buffer(has_json: bool) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(if has_json { 1024 * 1024 } else { 0 }))
}

fn apply_edits(
    input: &[u8],
    edits: &mut [(usize, usize, Zeroizing<Vec<u8>>)],
) -> Result<Zeroizing<Vec<u8>>, String> {
    edits.sort_by_key(|e| e.0);
    let capacity = input.len() + edits.iter().map(|e| e.2.len()).sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    let mut cursor = 0;
    for (start, end, value) in edits {
        if *start < cursor || *start > *end || *end > input.len() {
            return Err(String::new());
        }
        out.extend_from_slice(&input[cursor..*start]);
        out.extend_from_slice(value);
        cursor = *end;
    }
    out.extend_from_slice(&input[cursor..]);
    Ok(out)
}
