use super::*;
use std::io::Cursor;

fn args(raw: &[&str]) -> Vec<OsString> {
    raw.iter().map(OsString::from).collect()
}

fn additions() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/gh_shim/v22-additions.json"
    ))
    .unwrap()
}

/// A synthetic v21 baseline: the tracked v20 fixture's rows at version 21 with
/// only the test binding (cortexkit/aft -> alfonso-aft). The production v21
/// payload is not tracked; v21 changed only bindings, so its rows are these.
fn v21_value() -> Value {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/gh_shim/v20-manifest.json"
    ))
    .unwrap();
    value["manifest_version"] = json!(21);
    value["bindings"] = json!({ "cortexkit/aft": "alfonso-aft" });
    value
}

fn parse(value: Value) -> Manifest {
    let manifest: Manifest = serde_json::from_value(value).unwrap();
    manifest.validate().unwrap();
    manifest
}

fn v21_manifest() -> Manifest {
    parse(v21_value())
}

/// The synthetic v21 baseline with the v22 additions applied the way
/// `scripts/prepare-gh-shim-v22.py` applies them (bindings stay synthetic).
fn manifest() -> Manifest {
    let mut value = v21_value();
    let additions = additions();
    for removed in additions["removed_from_admin"].as_array().unwrap() {
        value["tiers"]["admin"]
            .as_array_mut()
            .unwrap()
            .retain(|row| &row["tuple"] != removed);
    }
    for (tier, rows) in additions["tiers"].as_object().unwrap() {
        value["tiers"][tier]
            .as_array_mut()
            .unwrap()
            .extend(rows.as_array().unwrap().iter().cloned());
    }
    value["api_rules"]
        .as_array_mut()
        .unwrap()
        .extend(additions["api_rules"].as_array().unwrap().iter().cloned());
    for (tuple, canonical) in additions["canonicalization"].as_object().unwrap() {
        value["canonicalization"][tuple] = canonical.clone();
    }
    value["manifest_version"] = json!(22);
    parse(value)
}

/// The same v22 rows on a manifest that claims version 21: a signed row alone
/// must not admit a v22 verb before the classifier reviewed it.
fn v22_rows_at_v21() -> Manifest {
    let mut manifest = manifest();
    manifest.manifest_version = 21;
    manifest
}

fn binding() -> AgentBinding {
    AgentBinding {
        repo: "cortexkit/aft".into(),
        agent_id: "alfonso-aft".into(),
    }
}

fn rung() -> RungRecord {
    RungDetermination::r3(
        1_700_000_000,
        22,
        &RungRecordProvenance {
            image_path: "/test/aft".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            repo_key: "cortexkit/aft".into(),
        },
    )
    .record
}

struct EnvGuard(&'static str, Option<OsString>);

impl EnvGuard {
    fn set(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var_os(key);
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self(key, previous)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.1 {
            Some(value) => std::env::set_var(self.0, value),
            None => std::env::remove_var(self.0),
        }
    }
}

const RESOLVE_LITERAL: &str = r#"mutation { resolveReviewThread(input: {threadId: "PRRT_kwDOAbc123"}) { thread { isResolved } } }"#;
const UNRESOLVE_VARIABLE: &str = r#"mutation($id: ID!) { unresolveReviewThread(input: {threadId: $id}) { thread { isResolved } } }"#;

fn governed_tuple(classification: Classification) -> Option<String> {
    match classification {
        Classification::Governed { tuple, .. } => Some(tuple),
        _ => None,
    }
}

fn admin_tuple(classification: Classification) -> Option<String> {
    match classification {
        Classification::Admin { tuple } => Some(tuple),
        _ => None,
    }
}

fn speech_rows() -> Vec<(Vec<&'static str>, String)> {
    vec![
        (
            vec![
                "pr",
                "edit",
                "7",
                "--title",
                "New title",
                "--repo",
                "cortexkit/aft",
            ],
            "pr edit".into(),
        ),
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/pulls/7/comments/99/replies",
                "-f",
                "body=thanks",
            ],
            review_reply_tuple(),
        ),
        (
            // An implicit POST: gh sends one whenever a field is given.
            vec![
                "api",
                "repos/cortexkit/aft/pulls/7/comments/99/replies",
                "-f",
                "body=thanks",
            ],
            review_reply_tuple(),
        ),
        (
            vec![
                "api",
                "-X",
                "PATCH",
                "repos/cortexkit/aft/pulls/7",
                "-f",
                "title=New title",
            ],
            v22_rows::pull_edit_tuple(),
        ),
        (
            vec![
                "api",
                "graphql",
                "-f",
                Box::leak(format!("query={RESOLVE_LITERAL}").into_boxed_str()),
            ],
            REVIEW_THREAD_RESOLVE_TUPLE.into(),
        ),
        (
            vec![
                "api",
                "graphql",
                "-f",
                Box::leak(format!("query={UNRESOLVE_VARIABLE}").into_boxed_str()),
                "-f",
                "id=PRRT_kwDOAbc123",
            ],
            REVIEW_THREAD_UNRESOLVE_TUPLE.into(),
        ),
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks",
                "-F",
                "pull_requests[]=7",
                "-F",
                "pull_requests[]=8",
            ],
            "api:POST:/repos/*/*/stacks".into(),
        ),
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks/3/add",
                "-F",
                "pull_requests[]=9",
            ],
            "api:POST:/repos/*/*/stacks/*/add".into(),
        ),
        (
            vec!["api", "-X", "POST", "repos/cortexkit/aft/stacks/3/unstack"],
            "api:POST:/repos/*/*/stacks/*/unstack".into(),
        ),
    ]
}

fn operator_rows() -> Vec<(Vec<&'static str>, &'static str)> {
    vec![
        (
            vec!["extension", "install", "github/gh-stack"],
            "extension install",
        ),
        (
            vec!["extension", "upgrade", "gh-stack"],
            "extension upgrade",
        ),
        (vec!["extension", "remove", "gh-stack"], "extension remove"),
        (vec!["stack", "merge", "--squash"], "stack merge"),
        (
            vec![
                "api",
                "-X",
                "PUT",
                "repos/cortexkit/aft/pulls/7/merge-async",
                "-f",
                "merge_action=direct_merge",
            ],
            "api:PUT:/repos/*/*/pulls/*/merge-async",
        ),
        (vec!["stack", "submit"], "stack submit"),
        (vec!["stack", "sync"], "stack sync"),
        (vec!["stack", "link", "7", "8"], "stack link"),
        (vec!["stack", "unstack"], "stack unstack"),
        (vec!["stack", "delete"], "stack delete"),
        (vec!["stack", "checkout", "7"], "stack checkout"),
    ]
}

const READ_ROWS: &[&[&str]] = &[
    &["extension", "list"],
    &["stack", "view", "--json"],
    &["stack", "switch"],
    &["stack", "up", "2"],
    &["stack", "down"],
    &["stack", "top"],
    &["stack", "bottom"],
    &["stack", "trunk"],
    &["stack", "rebase", "--upstack"],
    &["stack", "modify"],
    &["stack", "init", "--base", "main"],
    &["stack", "add", "next-branch"],
    &["stack", "push"],
];

#[test]
fn v22_additions_validate_and_bind_claustrum_auth_like_its_siblings() {
    let manifest = manifest();
    assert_eq!(manifest.manifest_version, 22);
    // `pr edit` moved tiers rather than being declared twice.
    assert_eq!(
        manifest.tier_for_tuple("pr edit", "linux"),
        Some(Tier::Governed)
    );
    assert_eq!(
        v21_manifest().tier_for_tuple("pr edit", "linux"),
        Some(Tier::Admin)
    );
    let bindings = additions()["bindings"].clone();
    assert_eq!(
        bindings,
        json!({ "cortexkit/claustrum-auth": "agent_0f4d7713e64e7cc4" })
    );
    let previous: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/gh_shim/v20-manifest.json"
    ))
    .unwrap();
    for sibling in ["cortexkit/openai-auth", "cortexkit/common-auth"] {
        assert_eq!(
            previous["bindings"][sibling],
            bindings["cortexkit/claustrum-auth"]
        );
    }
}

#[test]
fn v22_speech_rows_are_governed_only_at_v22() {
    let current = manifest();
    let previous = v21_manifest();
    let early = v22_rows_at_v21();
    for (raw, tuple) in speech_rows() {
        let argv = args(&raw);
        for platform in ["macos", "linux"] {
            assert_eq!(
                governed_tuple(classify(&argv, &current, platform)).as_deref(),
                Some(tuple.as_str()),
                "{raw:?}"
            );
        }
        assert!(
            governed_tuple(classify(&argv, &previous, "linux")).is_none(),
            "{raw:?} must not be bot speech on v21"
        );
        assert!(
            governed_tuple(classify(&argv, &early, "linux")).is_none(),
            "{raw:?} must not be bot speech on a v21 manifest carrying the v22 rows"
        );
    }
    // On v21 `pr edit` is still the operator's label-only row.
    assert_eq!(
        admin_tuple(classify(
            &args(&["pr", "edit", "7", "--title", "x"]),
            &previous,
            "linux"
        ))
        .as_deref(),
        Some("pr edit")
    );
}

#[test]
fn v22_operator_rows_are_admin_only_at_v22_and_reads_are_mechanical() {
    let current = manifest();
    let early = v22_rows_at_v21();
    for (raw, tuple) in operator_rows() {
        let argv = args(&raw);
        assert_eq!(
            admin_tuple(classify(&argv, &current, "linux")).as_deref(),
            Some(tuple),
            "{raw:?}"
        );
        assert!(
            matches!(
                classify(&argv, &early, "linux"),
                Classification::Unclassified
            ),
            "{raw:?} must stay undeclared below v22"
        );
        assert!(matches!(
            classify(&argv, &v21_manifest(), "linux"),
            Classification::Unclassified
        ));
    }
    for raw in READ_ROWS {
        assert!(
            matches!(
                classify(&args(raw), &current, "linux"),
                Classification::Mechanical
            ),
            "{raw:?}"
        );
        assert!(matches!(
            classify(&args(raw), &v21_manifest(), "linux"),
            Classification::Unclassified
        ));
    }
    // An undeclared subcommand, the extension's shell alias and running an
    // extension stay undeclared.
    for raw in [
        &["stack", "alias"][..],
        &["stack"][..],
        &["extension", "exec", "stack"][..],
    ] {
        assert!(
            matches!(
                classify(&args(raw), &current, "linux"),
                Classification::Unclassified
            ),
            "{raw:?}"
        );
    }
}

#[test]
fn v22_new_endpoints_match_exactly_one_resource() {
    let manifest = manifest();
    for (method, path) in [
        (
            "POST",
            "repos/cortexkit/aft/pulls/7/comments/99/replies/extra",
        ),
        ("POST", "repos/cortexkit/aft/pulls/7/comments"),
        ("PATCH", "repos/cortexkit/aft/pulls/7/comments/99"),
        ("PATCH", "repos/cortexkit/aft/pulls/7/extra"),
        ("PATCH", "repos/cortexkit/aft/pulls"),
        ("POST", "repos/cortexkit/aft/stacks/3/remove"),
        ("DELETE", "repos/cortexkit/aft/stacks/3"),
        ("POST", "repos/cortexkit/aft/pulls/7/merge-async"),
        ("PUT", "repos/cortexkit/aft/pulls/7/merge"),
    ] {
        assert!(
            matches!(
                classify(
                    &args(&["api", "-X", method, path, "-f", "body=x"]),
                    &manifest,
                    "linux"
                ),
                Classification::Unclassified
            ),
            "{method} {path}"
        );
    }
    // Reading a stack or a merge status stays a mechanical GET.
    for path in [
        "repos/cortexkit/aft/stacks",
        "repos/cortexkit/aft/stacks/3",
        "repos/cortexkit/aft/pulls/7/merge-async/0f0e",
    ] {
        assert!(matches!(
            classify(&args(&["api", path]), &manifest, "linux"),
            Classification::Mechanical
        ));
    }
}

#[test]
fn v22_graphql_admits_only_the_two_review_thread_mutations() {
    let manifest = manifest();
    let query = |document: &str| format!("query={document}");
    for (document, extra) in [
        (
            r#"mutation { addComment(input: {subjectId: "X", body: "y"}) { clientMutationId } }"#,
            vec![],
        ),
        (
            r#"mutation { resolveReviewThread(input: {threadId: "PRRT_a"}) { thread { id } } addComment(input: {subjectId: "X", body: "y"}) { clientMutationId } }"#,
            vec![],
        ),
        (
            r#"mutation { resolveReviewThread(input: {threadId: "PRRT_a", clientMutationId: "c"}) { thread { id } } }"#,
            vec![],
        ),
        (
            r#"mutation A { resolveReviewThread(input: {threadId: "PRRT_a"}) { thread { id } } } mutation B { unresolveReviewThread(input: {threadId: "PRRT_a"}) { thread { id } } }"#,
            vec![],
        ),
        (
            r#"mutation($id: ID!) { resolveReviewThread(input: {threadId: $id}) { thread { id } } }"#,
            vec!["-f", "id=PRRT_a", "-f", "other=1"],
        ),
        (
            r#"mutation($id: ID!) { resolveReviewThread(input: {threadId: $id}) { thread { id } } }"#,
            vec![],
        ),
        (
            r#"mutation { resolveReviewThread(input: {threadId: "not a node id"}) { thread { id } } }"#,
            vec![],
        ),
        (RESOLVE_LITERAL, vec!["--jq", ".data"]),
        (RESOLVE_LITERAL, vec!["-H", "X: y"]),
    ] {
        let mut raw = vec![
            "api".to_string(),
            "graphql".into(),
            "-f".into(),
            query(document),
        ];
        raw.extend(extra.iter().map(|value| value.to_string()));
        let argv = raw.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(
            matches!(
                classify(&argv, &manifest, "linux"),
                Classification::Unclassified
            ),
            "{raw:?}"
        );
    }
    // A typed field gh would rewrite (`@file`, placeholders) is not inspected.
    let argv = args(&["api", "graphql", "-F", "query=@mutation.graphql"]);
    assert!(matches!(
        classify(&argv, &manifest, "linux"),
        Classification::Unclassified
    ));
}

fn wire_of(request: GovernedRequest) -> Value {
    governed_wire_request(&rung(), "alfonso-aft", request)
}

#[test]
fn v22_pr_edit_routes_title_and_body_as_own_pull_request_speech() {
    let manifest = manifest();
    let canonical = &manifest.canonicalization["pr edit"];
    let request = canonicalize_governed_from(
        &args(&[
            "pr",
            "edit",
            "7",
            "-t",
            "New title",
            "--body-file",
            "-",
            "--repo",
            "cortexkit/aft",
        ]),
        "pr edit",
        canonical,
        22,
        &mut Cursor::new("Body from stdin"),
    )
    .unwrap();
    let mutation = GithubReadMutation::from_governed_request(&request).unwrap();
    assert_eq!(mutation.resource_kind, GithubReadResourceKind::PullRequest);
    let wire = wire_of(request);
    assert_eq!(wire["action"], "pr edit");
    assert_eq!(wire["target"], json!({ "number": "7" }));
    assert_eq!(
        wire["body"],
        json!({ "title": "New title", "body": "Body from stdin" })
    );
    assert_eq!(wire["repository"], "cortexkit/aft");
    assert_eq!(wire["author_scope"], "own");
    assert_eq!(wire["manifest_version"], 22);

    let refused = |raw: &[&str]| {
        canonicalize_governed_from(&args(raw), "pr edit", canonical, 22, &mut Cursor::new(""))
            .unwrap_err()
    };
    let label = refused(&["pr", "edit", "7", "--add-label", "bug", "--title", "x"]);
    assert_eq!(label.code, RefusalCode::UnsupportedFlag);
    assert_eq!(label.text, PR_EDIT_LABEL_REFUSAL_TEXT);
    for flag in ["--base", "--add-reviewer", "--milestone", "--add-assignee"] {
        let error = refused(&["pr", "edit", "7", "--title", "x", flag, "value"]);
        assert_eq!(error.code, RefusalCode::UnsupportedFlag, "{flag}");
        assert!(error.text.contains(PR_EDIT_FLAG_REFUSAL_TEXT), "{flag}");
    }
    // A title-less, body-less edit and an edit naming no pull request are not
    // guessed at.
    assert!(refused(&["pr", "edit", "7"])
        .text
        .contains("--title or --body"));
    assert!(refused(&["pr", "edit", "--title", "x"])
        .text
        .contains("exactly one pull request"));
    assert!(refused(&["pr", "edit", "7", "--title", "a", "-t", "b"])
        .text
        .contains("only once"));
    // The reader refuses a declaration it was not written for.
    let mut other = canonical.clone();
    other.body_fields.push("base".into());
    assert!(canonicalize_governed_from(
        &args(&["pr", "edit", "7", "--title", "x"]),
        "pr edit",
        &other,
        22,
        &mut Cursor::new("")
    )
    .is_err());
    assert!(canonicalize_governed_from(
        &args(&["pr", "edit", "7", "--title", "x"]),
        "pr edit",
        canonical,
        21,
        &mut Cursor::new("")
    )
    .is_err());
}

fn api_request(raw: &[&str], stdin: &str) -> Result<GovernedRequest, CanonicalizeError> {
    let manifest = manifest();
    let argv = args(raw);
    let Classification::Governed { tuple, canonical } = classify(&argv, &manifest, "linux") else {
        panic!("{raw:?} is not governed");
    };
    canonicalize_governed_api_from(&argv, &tuple, &canonical, 22, &mut Cursor::new(stdin))
}

#[test]
fn v22_pull_patch_is_routed_as_the_same_own_pr_edit() {
    let request = api_request(
        &[
            "api",
            "--method",
            "PATCH",
            "/repos/cortexkit/aft/pulls/7",
            "--input",
            "-",
        ],
        r#"{"title":"T","body":"B","base":"stack/parent"}"#,
    )
    .unwrap();
    let wire = wire_of(request);
    assert_eq!(wire["action"], "pr edit");
    assert_eq!(wire["target"], json!({ "number": "7" }));
    assert_eq!(
        wire["body"],
        json!({ "title": "T", "body": "B", "base": "stack/parent" })
    );
    assert_eq!(wire["author_scope"], "own");
    for (raw, stdin) in [
        (
            vec![
                "api",
                "-X",
                "PATCH",
                "repos/cortexkit/aft/pulls/7",
                "-f",
                "state=closed",
            ],
            "",
        ),
        (
            vec![
                "api",
                "-X",
                "PATCH",
                "repos/cortexkit/aft/pulls/7",
                "--input",
                "-",
            ],
            r#"{"title":"T","maintainer_can_modify":false}"#,
        ),
        (
            vec!["api", "-X", "PATCH", "repos/cortexkit/aft/pulls/7"],
            "",
        ),
        (
            vec![
                "api",
                "-X",
                "PATCH",
                "repos/cortexkit/aft/pulls/7",
                "-f",
                "title=a",
                "-f",
                "title=b",
            ],
            "",
        ),
        (
            vec![
                "api",
                "-X",
                "PATCH",
                "repos/cortexkit/aft/pulls/7",
                "-f",
                "title=a",
                "--jq",
                ".id",
            ],
            "",
        ),
    ] {
        assert!(api_request(&raw, stdin).is_err(), "{raw:?}");
    }
}

#[test]
fn v22_review_reply_carries_the_thread_from_the_path_and_one_body() {
    let request = api_request(
        &[
            "api",
            "repos/cortexkit/aft/pulls/7/comments/99/replies",
            "-f",
            "body=Fixed in the next push",
        ],
        "",
    )
    .unwrap();
    let mutation = GithubReadMutation::from_governed_request(&request).unwrap();
    assert_eq!(mutation.resource_number, 7);
    let wire = wire_of(request);
    assert_eq!(wire["action"], review_reply_tuple());
    assert_eq!(wire["target"], json!({ "number": "7", "comment_id": "99" }));
    assert_eq!(wire["body"], json!({ "body": "Fixed in the next push" }));
    assert_eq!(wire["repository"], "cortexkit/aft");
    assert!(wire.get("author_scope").is_none());
    for raw in [
        vec![
            "api",
            "repos/cortexkit/aft/pulls/7/comments/99/replies",
            "-f",
            "body=a",
            "-f",
            "path=x",
        ],
        vec![
            "api",
            "-X",
            "POST",
            "repos/cortexkit/aft/pulls/7/comments/99/replies",
        ],
    ] {
        assert!(api_request(&raw, "").is_err(), "{raw:?}");
    }
}

#[test]
fn v22_review_thread_mutations_route_the_thread_node_id() {
    let _lock = crate::test_env::process_env_lock();
    let _repo = EnvGuard::set("GH_REPO", Some("cortexkit/aft"));
    let manifest = manifest();
    for (raw, tuple) in [
        (
            vec![
                "api".to_string(),
                "graphql".into(),
                "-f".into(),
                format!("query={RESOLVE_LITERAL}"),
            ],
            REVIEW_THREAD_RESOLVE_TUPLE,
        ),
        (
            vec![
                "api".to_string(),
                "graphql".into(),
                "-X".into(),
                "POST".into(),
                "-f".into(),
                format!("query={UNRESOLVE_VARIABLE}"),
                "-F".into(),
                "id=PRRT_kwDOAbc123".into(),
            ],
            REVIEW_THREAD_UNRESOLVE_TUPLE,
        ),
    ] {
        let argv = raw.iter().map(OsString::from).collect::<Vec<_>>();
        let Classification::Governed {
            tuple: found,
            canonical,
        } = classify(&argv, &manifest, "linux")
        else {
            panic!("{raw:?} is not governed");
        };
        assert_eq!(found, tuple);
        let request = canonicalize_governed(&argv, tuple, &canonical, 22).unwrap();
        assert!(GithubReadMutation::from_governed_request(&request).is_none());
        let wire = wire_of(request);
        assert_eq!(wire["action"], tuple);
        assert_eq!(wire["target"], json!({ "thread_id": "PRRT_kwDOAbc123" }));
        assert_eq!(wire["body"], json!({}));
        assert_eq!(wire["repository"], "cortexkit/aft");
        // The document is not forwarded; the holder runs its own mutation.
        assert!(!wire.to_string().contains("isResolved"));
    }
}

#[test]
fn v22_stack_writes_carry_only_the_stack_and_pull_request_numbers() {
    let create = wire_of(
        api_request(
            &[
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks",
                "--input",
                "-",
            ],
            r#"{"pull_requests":[7,8,"9"]}"#,
        )
        .unwrap(),
    );
    assert_eq!(create["action"], "api:POST:/repos/*/*/stacks");
    assert_eq!(create["target"], json!({}));
    assert_eq!(create["body"], json!({ "pull_requests": [7, 8, 9] }));
    let add = wire_of(
        api_request(
            &[
                "api",
                "repos/cortexkit/aft/stacks/3/add",
                "-F",
                "pull_requests[]=10",
            ],
            "",
        )
        .unwrap(),
    );
    assert_eq!(add["target"], json!({ "stack_number": "3" }));
    assert_eq!(add["body"], json!({ "pull_requests": [10] }));
    let unstack = wire_of(
        api_request(
            &["api", "-X", "POST", "repos/cortexkit/aft/stacks/3/unstack"],
            "",
        )
        .unwrap(),
    );
    assert_eq!(unstack["target"], json!({ "stack_number": "3" }));
    assert_eq!(unstack["body"], json!({}));
    for (raw, stdin) in [
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks",
                "--input",
                "-",
            ],
            r#"{"pull_requests":[7],"title":"x"}"#,
        ),
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks",
                "--input",
                "-",
            ],
            r#"{"pull_requests":[]}"#,
        ),
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks",
                "--input",
                "-",
            ],
            r#"{"pull_requests":[7,7]}"#,
        ),
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks",
                "-f",
                "pull_requests[]=0",
            ],
            "",
        ),
        (
            vec![
                "api",
                "-X",
                "POST",
                "repos/cortexkit/aft/stacks/3/unstack",
                "-f",
                "x=y",
            ],
            "",
        ),
    ] {
        assert!(api_request(&raw, stdin).is_err(), "{raw:?} / {stdin}");
    }
}

#[test]
fn v22_speech_is_refused_outside_bot_bound_repositories() {
    let _lock = crate::test_env::process_env_lock();
    let _bypass = EnvGuard::set("GH_SHIM_BYPASS", None);
    let _repo = EnvGuard::set("GH_REPO", Some("outside/unbound"));
    let manifest = manifest();
    let directory = tempfile::tempdir().unwrap();
    let paths = StatePaths::from_root(directory.path().to_path_buf());
    let mut rows = vec![
        args(&[
            "pr",
            "edit",
            "7",
            "--title",
            "x",
            "--repo",
            "outside/unbound",
        ]),
        args(&[
            "api",
            "repos/outside/unbound/pulls/7/comments/99/replies",
            "-f",
            "body=x",
        ]),
        args(&[
            "api",
            "-X",
            "PATCH",
            "repos/outside/unbound/pulls/7",
            "-f",
            "title=x",
        ]),
        args(&[
            "api",
            "-X",
            "POST",
            "repos/outside/unbound/stacks",
            "-F",
            "pull_requests[]=7",
        ]),
    ];
    rows.push(
        ["api", "graphql", "-f", &format!("query={RESOLVE_LITERAL}")]
            .iter()
            .map(OsString::from)
            .collect(),
    );
    for argv in rows {
        let target = TargetRepository::from_invocation(&argv);
        assert!(governed_tuple(classify(&argv, &manifest, "linux")).is_some());
        assert!(
            governing_binding(
                &classify(&argv, &manifest, "linux"),
                &manifest,
                &target,
                directory.path()
            )
            .is_none(),
            "{argv:?}"
        );
        let write = unbound_write(&argv, &manifest, "linux", &target, directory.path())
            .unwrap_or_else(|| panic!("{argv:?} must be an unbound write"));
        assert_eq!(
            write.target,
            WriteTarget::Repository("outside/unbound".into()),
            "{argv:?}"
        );
        assert_eq!(
            dispatch_unbound_write(&argv, &write, &paths, 1_700_000_000, |_| panic!(
                "unbound bot speech must not reach upstream"
            )),
            REFUSAL_EXIT_STATUS
        );
        // The same verb aimed at the bound repository is left to the governed
        // route.
        let _bound = EnvGuard::set("GH_REPO", Some("cortexkit/aft"));
        let bound = argv
            .iter()
            .map(|arg| {
                OsString::from(
                    arg.to_str()
                        .unwrap()
                        .replace("outside/unbound", "cortexkit/aft"),
                )
            })
            .collect::<Vec<_>>();
        let target = TargetRepository::from_invocation(&bound);
        assert!(unbound_write(&bound, &manifest, "linux", &target, directory.path()).is_none());
    }
    assert!(!paths.bypass_audit.exists());
}

#[test]
fn v22_operator_rows_refuse_without_the_bypass_and_audit_with_it() {
    let _lock = crate::test_env::process_env_lock();
    let manifest = manifest();
    for (raw, tuple) in operator_rows() {
        let argv = args(&raw);
        let directory = tempfile::tempdir().unwrap();
        let paths = StatePaths::from_root(directory.path().to_path_buf());
        {
            let _bypass = EnvGuard::set("GH_SHIM_BYPASS", None);
            assert_eq!(
                dispatch_r3(
                    &argv,
                    classify(&argv, &manifest, "linux"),
                    &manifest,
                    &paths,
                    &rung(),
                    &binding(),
                    1_700_000_000,
                    |_| panic!("{tuple} reached upstream without the operator bypass"),
                ),
                REFUSAL_EXIT_STATUS
            );
            assert!(!paths.bypass_audit.exists());
            let text = admin_tier_refusal_text(tuple);
            if tuple.starts_with("stack ") && tuple != "stack merge" {
                assert!(text.starts_with("PLACEHOLDER(stack-write): "), "{text}");
                assert!(text.contains(&format!("`{tuple}`")));
                assert!(text.contains("gh pr create --base"));
            } else {
                assert_eq!(text, admin_refusal_text(tuple));
            }
        }
        let _bypass = EnvGuard::set("GH_SHIM_BYPASS", Some("operator"));
        assert_eq!(
            dispatch_r3(
                &argv,
                classify(&argv, &manifest, "linux"),
                &manifest,
                &paths,
                &rung(),
                &binding(),
                1_700_000_000,
                |forwarded| {
                    assert_eq!(forwarded, argv);
                    let records = read_bypass_audit(&paths).0.unwrap();
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0]["tuple"], tuple);
                    73
                },
            ),
            73
        );
    }
}

#[test]
fn v22_pr_edit_labels_keep_the_operator_row_and_speech_never_uses_operator_gh() {
    let _lock = crate::test_env::process_env_lock();
    let manifest = manifest();
    let directory = tempfile::tempdir().unwrap();
    let paths = StatePaths::from_root(directory.path().to_path_buf());
    let labels = args(&[
        "pr",
        "edit",
        "7",
        "--add-label",
        "trivial",
        "--repo",
        "cortexkit/aft",
    ]);
    {
        let _bypass = EnvGuard::set("GH_SHIM_BYPASS", Some("operator"));
        assert_eq!(
            dispatch_r3(
                &labels,
                classify(&labels, &manifest, "linux"),
                &manifest,
                &paths,
                &rung(),
                &binding(),
                1_700_000_000,
                |forwarded| {
                    assert_eq!(forwarded, labels);
                    let records = read_bypass_audit(&paths).0.unwrap();
                    assert_eq!(records[0]["tuple"], "pr edit");
                    73
                },
            ),
            73
        );
    }
    // Without the bypass a label edit is refused before routing, and a title
    // edit with no agent session refuses rather than falling back to the
    // operator's gh.
    let _bypass = EnvGuard::set("GH_SHIM_BYPASS", None);
    let relay = RelayContext {
        worker_broker: None,
        connection_file: None,
        ticket: None,
        transient_delays: [Duration::ZERO; 2],
        relay_budget: Duration::from_secs(1),
    };
    for argv in [
        labels.clone(),
        args(&["pr", "edit", "7", "--title", "x", "--repo", "cortexkit/aft"]),
    ] {
        assert_eq!(
            dispatch_r3_with_relay_at(
                &argv,
                classify(&argv, &manifest, "linux"),
                &manifest,
                &paths,
                &rung(),
                &binding(),
                1_700_000_000,
                |_| panic!("bot speech must not use operator credentials"),
                &relay,
                directory.path()
            ),
            REFUSAL_EXIT_STATUS
        );
    }
}

#[test]
fn v22_preparer_applies_the_additions_to_a_synthetic_v21_baseline() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().unwrap();
    // The production v21 payload is not tracked, so the preparer runs on a
    // synthetic baseline in the same JSON formatting, with its pinned digest
    // replaced by the synthetic one.
    let baseline = dir.path().join("v21.json");
    let encoded = {
        let mut value = v21_value();
        value["bindings"] = json!({
            "cortexkit/aft": "alfonso-aft",
            "cortexkit/openai-auth": "agent-fixture-auth"
        });
        let mut text = String::new();
        let python = Command::new("python3")
            .args([
                "-c",
                "import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2, ensure_ascii=False))",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        python
            .stdin
            .as_ref()
            .unwrap()
            .write_all(value.to_string().as_bytes())
            .unwrap();
        let output = python.wait_with_output().unwrap();
        assert!(output.status.success());
        text.push_str(&String::from_utf8(output.stdout).unwrap());
        text
    };
    fs::write(&baseline, &encoded).unwrap();
    let destination = dir.path().join("v22.json");
    let probe = "import hashlib, importlib.util, pathlib, sys\n\
spec = importlib.util.spec_from_file_location('prepare', sys.argv[1])\n\
m = importlib.util.module_from_spec(spec)\n\
spec.loader.exec_module(m)\n\
m.BASELINE_SHA256 = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()\n\
m.prepare(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), int(sys.argv[4]))\n";
    let output = Command::new("python3")
        .args(["-c", probe])
        .arg(root.join("scripts/prepare-gh-shim-v22.py"))
        .arg(&baseline)
        .arg(&destination)
        .arg("1800000000")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = fs::read(&destination).unwrap();
    let digest = format!("{:x}", Sha256::digest(&payload));
    assert!(String::from_utf8(output.stdout).unwrap().contains(&digest));
    let prepared: Manifest = serde_json::from_slice(&payload).unwrap();
    prepared.validate().unwrap();
    assert_eq!(prepared.manifest_version, 22);
    assert_eq!(prepared.issued_at_unix_secs, 1_800_000_000);
    assert_eq!(
        prepared
            .bindings
            .get("cortexkit/claustrum-auth")
            .map(String::as_str),
        Some("agent_0f4d7713e64e7cc4")
    );
    assert_eq!(
        prepared.bindings.get("cortexkit/aft").map(String::as_str),
        Some("alfonso-aft")
    );
    // For every speech row, the prepared payload yields the same governed tuple
    // as the in-test v22 manifest.
    let expected = manifest();
    for (raw, _) in speech_rows() {
        assert_eq!(
            governed_tuple(classify(&args(&raw), &prepared, "linux")),
            governed_tuple(classify(&args(&raw), &expected, "linux"))
        );
    }
    // Everything except the declared changes is unchanged from the baseline.
    let mut current: Value = serde_json::from_slice(&payload).unwrap();
    let mut previous: Value = serde_json::from_str(&encoded).unwrap();
    for value in [&mut current, &mut previous] {
        let object = value.as_object_mut().unwrap();
        for field in [
            "manifest_version",
            "issued_at_unix_secs",
            "tiers",
            "api_rules",
            "canonicalization",
            "bindings",
        ] {
            object.remove(field);
        }
    }
    assert_eq!(current, previous);
    // A baseline whose digest differs from the pin is refused.
    let output = Command::new("python3")
        .arg(root.join("scripts/prepare-gh-shim-v22.py"))
        .arg(&baseline)
        .arg(dir.path().join("refused.json"))
        .args(["--issued-at-unix-secs", "1800000000"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected reviewed v21 baseline"));
}
