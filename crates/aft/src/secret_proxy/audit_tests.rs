use super::*;

fn launch(server: &Server, vault: Arc<Vault>) -> (SecretProxy, Client) {
    let proxy = SecretProxy::start_with_tls(
        config(vault, server.address.port(), &[("test", Location::Bearer)]),
        server.client_tls.clone(),
    )
    .unwrap();
    let client = Client::spawn(&proxy, server);
    proxy.arm_command(client.process.id()).unwrap();
    (proxy, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_host_authority() {
    let server = Server::new("echo-request-h1").await;
    let (proxy, mut client) = launch(&server, Vault::new());
    let authority = format!("localhost:{}", server.address.port());
    assert_eq!(
        client.command(json!({"op":"connect","raw":true}))["ok"],
        true
    );
    let wire = format!("GET /approved HTTP/1.1\r\nHost: {authority}\r\nConnection: host, close\r\nAuthorization: Bearer {MARKER}\r\n\r\n");
    client.command(json!({"op":"raw","wire":wire}));
    assert_eq!(
        server.seen.lock()[0]["headers"]["host"],
        authority,
        "client-nominated hop header deleted the routing authority"
    );
    client.connect(true);
    let reply = client.command(json!({"op":"request","omit_host":true,"path":"/approved","headers":{"authorization":format!("Bearer {MARKER}")}}));
    assert_eq!(reply["status"], 200, "{reply}");
    assert_eq!(server.seen.lock()[1]["headers"]["host"], authority);
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_transfer_coding() {
    let server = Server::new("raw-transfer-h1").await;
    let (_proxy, mut client) = launch(&server, Vault::new());
    client.connect(false);
    let reply = client.request(
        "/approved",
        json!({"authorization":format!("Bearer {MARKER}")}),
        "",
    );
    if reply["status"] == 403 || reply["error"] == true {
        return;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(reply["bytes"].as_str().unwrap())
        .unwrap();
    let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(bytes.as_slice());
    let mut decoded = Vec::new();
    if decoder.read_to_end(&mut decoded).await.is_ok() {
        assert!(
            !decoded.windows(K1.len()).any(|w| w == K1),
            "encoded transfer body escaped the scrubber"
        );
    }
    assert!(!bytes.windows(K1.len()).any(|w| w == K1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_expiry_revocation_at_send() {
    for revoke in [false, true] {
        let server = Server::new("delay-h1").await;
        let vault = Vault::new();
        let mut cfg = config(
            vault.clone(),
            server.address.port(),
            &[("test", Location::Bearer)],
        );
        let expiry = crate::secret::vault::now_ms() + 2000;
        if !revoke {
            cfg.grants[0].expires_at_ms = expiry;
        }
        let proxy = SecretProxy::start_with_tls(cfg, server.client_tls.clone()).unwrap();
        let mut client = Client::spawn(&proxy, &server);
        proxy.arm_command(client.process.id()).unwrap();
        client.connect(false);
        let worker = std::thread::spawn(move || {
            let reply = client.request(
                "/approved",
                json!({"authorization":format!("Bearer {MARKER}")}),
                "",
            );
            (reply, client)
        });
        tokio::time::timeout(Duration::from_secs(5), server.handshake_seen.notified())
            .await
            .unwrap();
        if revoke {
            vault.denied.store(true, Ordering::SeqCst);
        } else {
            tokio::time::sleep(Duration::from_millis(
                expiry.saturating_sub(crate::secret::vault::now_ms()) + 20,
            ))
            .await;
        }
        server.tls_release.notify_one();
        let (reply, _client) = worker.join().unwrap();
        assert_eq!(
            reply["status"], 403,
            "authorization lapsed during upstream TLS: {reply}"
        );
        assert!(server.seen.lock().is_empty());
        assert_eq!(
            vault.calls.load(Ordering::SeqCst),
            if revoke { 1 } else { 0 }
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_peer_generation() {
    let server = Server::new("plain").await;
    let vault = Vault::new();
    let (proxy, mut client) = launch(&server, vault.clone());
    proxy
        .state
        .test_identity_generation
        .store(1, Ordering::SeqCst);
    assert_eq!(
        client.command(json!({"op":"connect"}))["error"],
        true,
        "a recycled session generation inherited the token"
    );
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_resource_limits() {
    assert_eq!(
        request::body_buffer(true).capacity(),
        0,
        "JSON reserved its full budget before any body bytes arrived"
    );
    let server = Server::new("plain").await;
    let (proxy, mut client) = launch(&server, Vault::new());
    assert_eq!(
        client.command(json!({"op":"cap_connections"}))["accepted"],
        16
    );
    drop(client);
    drop(proxy);
    let server = Server::new("hold").await;
    let (proxy, mut client) = launch(&server, Vault::new());
    client.connect(true);
    let reply = client.command(json!({"op":"many"}));
    let statuses = reply["statuses"]
        .as_array()
        .expect("bounded streams completed");
    assert_eq!(statuses.iter().filter(|v| **v == 200).count(), 32);
    assert_eq!(statuses.iter().filter(|v| **v == 403).count(), 4);
    drop(client);
    drop(proxy);
    let server = Server::new("plain").await;
    let (proxy, mut client) = launch(&server, Vault::new());
    proxy.state.test_idle_timeout_ms.store(25, Ordering::SeqCst);
    assert_eq!(
        client.command(json!({"op":"connect","raw":true}))["ok"],
        true
    );
    assert_eq!(client.command(json!({"op":"idle"}))["closed"], true);
    for index in 0..32 {
        proxy
            .state
            .install("test", format!("bounded-secret-{index:04}").as_bytes())
            .unwrap();
    }
    assert!(proxy.state.install("test", b"bounded-secret-0032").is_err());
    assert_eq!(proxy.state.patterns.lock().len(), 32);
}

#[test]
fn audit_zeroizing_encoding_classification() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("content-encoding", HeaderValue::from_bytes(K1).unwrap());
    let (result, bytes) =
        crate::test_allocations::count_bytes(|| response::content_codings(&headers));
    assert!(result.is_err());
    assert_eq!(
        bytes, 0,
        "unsupported content coding was copied into allocated storage"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_request_decisions() {
    let server = Server::new("plain").await;
    let vault = Vault::new();
    let (_proxy, mut client) = launch(&server, vault.clone());
    client.connect(false);
    for path in ["/approved", "/outside"] {
        assert_eq!(
            client.request(
                path,
                json!({"authorization":format!("Bearer {MARKER}")}),
                ""
            )["status"],
            200
        );
    }
    vault.denied.store(true, Ordering::SeqCst);
    assert_eq!(
        client.request(
            "/approved",
            json!({"authorization":format!("Bearer {MARKER}")}),
            ""
        )["status"],
        403
    );
    let records = vault.audits.lock();
    assert_eq!(
        records.len(),
        3,
        "each request must emit exactly one decision"
    );
    for (record, decision) in records.iter().zip(["substituted", "literal", "refused"]) {
        let line = record.to_json_line_with_keys(&[K1]).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["decision"], decision);
        assert_eq!(value["host"], "localhost");
        assert_eq!(value["port"], server.address.port());
        assert_eq!(value["origin"], "test-task");
        assert!(!line.contains(std::str::from_utf8(K1).unwrap()));
        assert_eq!(value["scope"]["ref"], "head");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_raw_parser_cases() {
    let server = Server::new("echo-request-h1").await;
    let (_proxy, mut client) = launch(&server, Vault::new());
    let authority = format!("localhost:{}", server.address.port());
    let cases = [
        "Content-Length: 0\r\nContent-Length: 4\r\n",
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: host\r\n",
        "Host: other.invalid\r\n",
        "X-Note: one\r\n folded\r\n",
        "X-Note : value\r\n",
    ];
    for fields in cases {
        assert_eq!(
            client.command(json!({"op":"connect","raw":true}))["ok"],
            true
        );
        let body = if fields.contains("Transfer-Encoding") {
            "0\r\n\r\n"
        } else {
            ""
        };
        let wire=format!("POST /approved HTTP/1.1\r\nHost: {authority}\r\n{fields}Authorization: Bearer {MARKER}\r\nConnection: close\r\n\r\n{body}");
        client.command(json!({"op":"raw","wire":wire}));
        for seen in server.seen.lock().iter() {
            assert_eq!(
                seen["headers"]["host"], authority,
                "parser normalization lost the bound virtual host"
            );
            assert!(
                !(seen["headers"].get("content-length").is_some()
                    && seen["headers"].get("transfer-encoding").is_some())
            );
            assert_eq!(seen["body"], "");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_unscanned_header_refusal() {
    let server = Server::new("plain").await;
    let vault = Vault::new();
    let (_proxy, mut client) = launch(&server, vault.clone());
    client.connect(false);
    let reply = client.request(
        "/approved",
        json!({"authorization":"Bearer {{ck-secret:new}}"}),
        "",
    );
    assert_eq!(reply["status"], 403);
    assert_eq!(
        reply["body"],
        "Secret proxy refused the request: new (localhost)\n"
    );
    assert_eq!(vault.calls.load(Ordering::SeqCst), 0);
    assert!(server.seen.lock().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_ipv6_literal() {
    let server = Server::new("ipv6-h1").await;
    let vault = Vault::new();
    let mut cfg = config(
        vault.clone(),
        server.address.port(),
        &[("test", Location::Bearer)],
    );
    cfg.grants[0].rule.host = "[::1]".into();
    let proxy = SecretProxy::start_with_tls(cfg, server.client_tls.clone()).unwrap();
    let mut client = Client::spawn(&proxy, &server);
    proxy.arm_command(client.process.id()).unwrap();
    let authority = server.address.to_string();
    assert_eq!(
        client.command(json!({"op":"connect","authority":authority}))["ok"],
        true,
        "IPv6 CONNECT failed before inner TLS"
    );
    let reply=client.command(json!({"op":"request","authority":authority,"path":"/approved","headers":{"authorization":format!("Bearer {MARKER}")}}));
    assert_eq!(reply["status"], 200, "{reply}");
    assert_eq!(vault.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        server.seen.lock()[0]["headers"]["authorization"],
        "Bearer test-key-12345678"
    );
}
