use super::*;

const SOURCE: &str =
    "pub fn session_marker() -> u32 { session_leaf() }\npub fn session_leaf() -> u32 { 42 }\n";

fn dispatch(request: RawRequest, ctx: &AppContext) -> Response {
    assert!(matches!(
        crate::sandbox_spawn::current_authenticated_principal(),
        AuthenticatedPrincipal::RouteBind {
            trust: PrincipalTrust::Untrusted,
            route_channel: 41,
            route_epoch: 9,
            ..
        }
    ));
    match request.command.as_str() {
        "read" => crate::commands::read::handle_read(&request, ctx),
        "outline" => crate::commands::outline::handle_outline(&request, ctx),
        "zoom" => crate::commands::zoom::handle_zoom(&request, ctx),
        "semantic_search" => {
            crate::commands::semantic_search::handle_semantic_search(&request, ctx)
        }
        "grep" => crate::commands::grep::handle_grep(&request, ctx),
        "glob" => crate::commands::glob::handle_glob(&request, ctx),
        "callers" => crate::commands::callers::handle_callers(&request, ctx),
        other => panic!("unexpected session-read command: {other}"),
    }
}

async fn query_with(f: &Fixture, name: &str, args: Value, dispatch: DispatchFn) -> Value {
    let mut args = args;
    args["rich_ui_op"] = json!(format!("{name}@1"));
    let operation = super::super::super::admission::prepare(name, &args).unwrap();
    let executor = Arc::new(Executor::new());
    assert!(executor.register_actor(f.carrier.root.clone(), f.ctx.clone()));
    let routes = HashMap::from([
        (route_key(41, 9), f.carrier.clone()),
        (route_key(43, 9), f.policy.clone()),
    ]);
    let reply = tool_provider::route_tests::exchange_decoded_with_capabilities(
        decoded_request(name, args, "reader", None, 71),
        &routes,
        &executor,
        &Arc::new(DispatchPathMetrics::new()),
        dispatch,
        PROOFS,
    )
    .await;
    assert_eq!(reply.frame.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&reply.frame.body).unwrap();
    super::super::super::carrier::validate_body(Some(&operation.entry), &body).unwrap();
    body
}

fn indexed_fixture(shape: &str) -> Fixture {
    let mut f = Fixture::new(if shape == "worker" { "worker" } else { "head" });
    std::fs::write(f.dir.path().join("main.rs"), SOURCE).unwrap();
    let request: RawRequest = serde_json::from_value(json!({
        "id":"configure-session-reads", "command":"configure", "harness":"runner",
        "project_root":f.policy.project_root, "storage_dir":f.dir.path().join("storage"),
        "config":[{"tier":"user", "source":f.dir.path().join("aft.jsonc"),
            "doc":json!({"indexes":{"trigram":true,"semantic":false,"callgraph":true}}).to_string()}]
    }))
    .unwrap();
    let response = crate::commands::configure::handle_configure(&request, &f.ctx);
    assert!(response.success, "configure: {response:?}");
    crate::runtime_drain::drain_deferred_configure_maintenance(&f.ctx);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        crate::runtime_drain::drain_search_index_events(&f.ctx);
        crate::runtime_drain::drain_callgraph_store_events(&f.ctx);
        let search_ready = f
            .ctx
            .search_index()
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|i| i.ready);
        let graph_ready = matches!(
            f.ctx.callgraph_store_for_ops(),
            crate::context::CallgraphStoreAccess::Ready(_)
        );
        if search_ready && graph_ready {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "session-read indexes did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    if shape == "non-core-head" {
        for route in [&mut f.carrier, &mut f.policy] {
            Arc::get_mut(&mut route.0)
                .unwrap()
                .scope
                .as_mut()
                .unwrap()
                .owner =
                serde_json::from_value(json!({"kind":"reserved", "module_id":"thalamus"})).unwrap();
        }
        if let AuthenticatedPrincipal::RouteBind { principal_id, .. } =
            &mut Arc::get_mut(&mut f.policy.0).unwrap().spawn_principal
        {
            *principal_id = Some("reserved:thalamus".into());
        }
    } else if shape == "flow-head" {
        for route in [&mut f.carrier, &mut f.policy] {
            Arc::get_mut(&mut route.0)
                .unwrap()
                .scope
                .as_mut()
                .unwrap()
                .attributes
                .flow_id = Some("flow".into());
        }
    }
    if shape == "worker" {
        f.record(&f.policy, "worker");
    }
    access_grants::register(&f.policy, &f.ctx).unwrap();
    f
}

#[tokio::test]
async fn session_reads_serve_all_seven_from_heads_workers_and_flow_heads() {
    let _manifest =
        super::super::super::chunks::set_test_manifest_for_test(Some(MANIFEST.to_vec()));
    for shape in ["head", "non-core-head", "worker", "flow-head"] {
        let f = indexed_fixture(shape);
        for (name, args, expected) in [
            (
                "read",
                json!({"path":"main.rs", "startLine":1, "endLine":2}),
                "session_marker",
            ),
            ("outline", json!({"target":"main.rs"}), "session_marker"),
            (
                "zoom",
                json!({"batch":[{"target":"main.rs", "symbols":["session_marker", "session_leaf"]}]}),
                "session_marker",
            ),
            (
                "search",
                json!({"pattern":"session_marker", "topK":3}),
                "session_marker",
            ),
            (
                "grep",
                json!({"pattern":"session_marker", "include":"*.rs"}),
                "session_marker",
            ),
            ("glob", json!({"pattern":"**/*.rs"}), "main.rs"),
            (
                "callgraph",
                json!({"op":"callers", "path":"main.rs", "symbol":"session_leaf"}),
                "session_marker",
            ),
        ] {
            let body = query_with(&f, name, args, dispatch).await;
            assert_eq!(body["isError"], false, "{shape} {name}: {body}");
            assert_eq!(body["content"], json!([{"type":"text", "text":""}]));
            assert_eq!(body["structuredContent"].as_object().unwrap().len(), 1);
            assert!(
                body["structuredContent"]["text"]
                    .as_str()
                    .unwrap()
                    .contains(expected),
                "{shape} {name}: {body}"
            );
        }
    }
}

#[tokio::test]
async fn session_reads_media_refused_before_native_handlers() {
    let _manifest =
        super::super::super::chunks::set_test_manifest_for_test(Some(MANIFEST.to_vec()));
    let f = Fixture::new("head");
    access_grants::register(&f.policy, &f.ctx).unwrap();
    std::fs::write(f.dir.path().join("main.rs"), SOURCE).unwrap();
    // Misleading extensions ensure admission inspects bytes, not file names.
    for (file, bytes) in [
        ("image.txt", b"GIF89a".as_slice()),
        ("pdf.txt", b"%PDF-1.7\n".as_slice()),
        ("binary.txt", b"binary\0data".as_slice()),
    ] {
        std::fs::write(f.dir.path().join(file), bytes).unwrap();
        for (name, args) in [
            ("read", json!({"path":file, "startLine":1, "endLine":1})),
            ("outline", json!({"target":file})),
            (
                "zoom",
                json!({"batch":[{"target":"main.rs", "symbols":["session_marker"]}, {"target":file, "symbols":["one"]}]}),
            ),
        ] {
            let body = query_with(&f, name, args, |_, _| {
                panic!("media reached native handler")
            })
            .await;
            assert_eq!(
                body,
                super::super::super::carrier::error_body("unsupported_media"),
                "{name} {file}"
            );
        }
    }
}
