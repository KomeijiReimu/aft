use super::*;
use serde_json::json;

fn manifest() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/rich_ui/manifest.jcs.json"
    ))
    .unwrap()
}

fn prepare(name: &str, arguments: Value) -> Result<Operation, ErrorBody> {
    prepare_with_manifest(name, &arguments, Some(&manifest()))
}

#[test]
fn operation_admission_precedence_and_bound_fields() {
    for args in [
        json!({}),
        json!({"rich_ui_op":null}),
        json!({"rich_ui_op":"read"}),
        json!({"rich_ui_op":"read@x"}),
        json!({"rich_ui_op":"read@1@2"}),
    ] {
        assert_eq!(
            prepare("read", args).unwrap_err().code,
            "rich_ui_op_malformed"
        );
    }
    for encoded in ["read@2", "unpublished@1"] {
        assert_eq!(
            prepare("grep", json!({"rich_ui_op":encoded,"session":"canary"}))
                .unwrap_err()
                .code,
            "operation_version_unsupported"
        );
    }
    assert_eq!(
        prepare("grep", json!({"rich_ui_op":"read@1","session":"canary"}))
            .unwrap_err()
            .code,
        "operation_target_mismatch"
    );
    for key in ["session", "session_id", "sessionId"] {
        let mut args = json!({"rich_ui_op":"read@1","path":"x".repeat(8193)});
        args[key] = json!("canary");
        assert_eq!(
            prepare("read", args).unwrap_err().code,
            "bound_field_supplied"
        );
    }
    for (name, args) in [
        ("bash_status", json!({"rich_ui_op":"bash_status@1"})),
        (
            "bash_status",
            json!({"rich_ui_op":"bash_status@1","task":4}),
        ),
        (
            "read",
            json!({"rich_ui_op":"read@1","task":"key","path":"x"}),
        ),
        (
            "bash_status",
            json!({"rich_ui_op":"bash_status@1","task":"key","taskId":"id"}),
        ),
    ] {
        assert_eq!(prepare(name, args).unwrap_err().code, "args_invalid");
    }
    let op = prepare(
        "bash_status",
        json!({"rich_ui_op":"bash_status@1","task":"viewed-key"}),
    )
    .unwrap();
    assert_eq!(op.task.as_deref(), Some("viewed-key"));
    assert_eq!(op.arguments, json!({}));
    assert_eq!(
        prepare(
            "aft_outline",
            json!({"rich_ui_op":"outline@1","target":"x"})
        )
        .unwrap()
        .entry["id"],
        "outline"
    );
}

#[test]
fn operation_arguments_caps_closed_fields_and_remote_targets() {
    let overhead = serde_json::to_vec(&json!({"path":""})).unwrap().len();
    assert!(prepare(
        "read",
        json!({"rich_ui_op":"read@1","path":"x".repeat(8192-overhead)})
    )
    .is_ok());
    assert_eq!(
        prepare(
            "read",
            json!({"rich_ui_op":"read@1","path":"x".repeat(8193-overhead)})
        )
        .unwrap_err()
        .code,
        "args_invalid"
    );
    for extra in [
        json!({"ref":"HEAD"}),
        json!({"output_offset":0}),
        json!({"outputMode":"raw"}),
        json!({"background":true}),
        json!({"once":true}),
    ] {
        let mut args = json!({"rich_ui_op":"bash_status@1","task":"key"});
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(
            prepare("bash_status", args).unwrap_err().code,
            "args_invalid"
        );
    }
    for regex in [false, true] {
        assert!(prepare("bash_watch", json!({"rich_ui_op":"bash_watch@1","task":"key","pattern":"needle","regex":regex,"timeoutMs":20_000})).is_ok());
    }
    assert_eq!(
        prepare(
            "bash_watch",
            json!({"rich_ui_op":"bash_watch@1","task":"key","pattern":"needle","timeoutMs":20_001})
        )
        .unwrap_err()
        .code,
        "args_invalid"
    );
    for remote in [
        "https://example.com",
        "http://example.com",
        "issue://123",
        "pr://123",
    ] {
        for (name, args) in [
            ("read", json!({"path":remote})),
            ("outline", json!({"target":remote})),
            ("outline", json!({"target":[remote]})),
            ("zoom", json!({"batch":[{"target":remote,"symbols":["x"]}]})),
            ("grep", json!({"path":remote,"pattern":"x"})),
            (
                "callgraph",
                json!({"op":"callers","path":"x","toPath":remote,"symbol":"x"}),
            ),
        ] {
            let mut args = args;
            args["rich_ui_op"] = json!(format!("{name}@1"));
            assert_eq!(
                prepare(name, args).unwrap_err().code,
                "args_invalid",
                "{name} {remote}"
            );
        }
    }
}

#[test]
fn operation_requires_publication_and_non_carrier_rejects_even_null_marker() {
    for name in ["read", "bash_status"] {
        assert_eq!(
            prepare_with_manifest(name, &json!({"rich_ui_op":format!("{name}@1")}), None)
                .unwrap_err()
                .code,
            "operation_version_unsupported"
        );
    }
    assert_eq!(
        reject_non_carrier(&json!({"rich_ui_op":null}))
            .unwrap_err()
            .code,
        "rich_ui_op_not_allowed"
    );
    assert!(reject_non_carrier(&json!({"path":"x"})).is_ok());
}

#[test]
fn operation_query_translation_passes_served_schemas_without_bound_fields() {
    let status = prepare(
        "bash_status",
        json!({"rich_ui_op":"bash_status@1","task":"viewed-key"}),
    )
    .unwrap();
    assert_eq!(
        status
            .translate_query(Some("bash-0123456789abcdef"), 5000)
            .unwrap(),
        json!({"taskId":"bash-0123456789abcdef"})
    );
    for regex in [false, true] {
        let op = prepare("bash_watch", json!({"rich_ui_op":"bash_watch@1","task":"key","pattern":"needle","regex":regex,"timeoutMs":10000})).unwrap();
        let args = op
            .translate_query(Some("bash-0123456789abcdef"), 5000)
            .unwrap();
        assert_eq!(args["timeoutMs"], 5000);
        assert_eq!(
            args["pattern"],
            if regex {
                json!({"regex":"needle"})
            } else {
                json!("needle")
            }
        );
        assert!(
            args.get("task").is_none()
                && args.get("rich_ui_op").is_none()
                && args.get("regex").is_none()
        );
    }
    let read = prepare("read", json!({"rich_ui_op":"read@1","path":"x"})).unwrap();
    assert_eq!(
        read.translate_query(None, 5000).unwrap(),
        json!({"path":"x"})
    );
}
