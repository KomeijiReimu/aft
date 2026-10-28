use super::*;
use crate::bash_background::{
    persistence::{self, BgMode, PersistedTask, ResolvedTask},
    BgTaskStatus, TaskCallKey,
};

const TASK: &str = "bash-0000000000000081";
const TASK_TWO: &str = "bash-0000000000000082";

fn seed(
    f: &Fixture,
    id: &str,
    session: &str,
    requester: &str,
    key: &str,
    running: bool,
    pty: bool,
) -> (ResolvedTask, PersistedTask) {
    let harness: crate::harness::Harness = f.policy.harness.parse().unwrap();
    let storage = f.dir.path().join("storage").join(harness.storage_segment());
    let layout = persistence::create_task_layout(&storage, session, id).unwrap();
    let mut task = crate::db::rich_ui::terminal_task_metadata_for_test(None);
    task.task_id = id.into();
    task.session_id = session.into();
    task.harness = Some(harness.storage_segment());
    task.workdir = f.policy.project_root.clone();
    task.project_root = Some(f.policy.project_root.clone());
    task.call_key = Some(TaskCallKey {
        requester: requester.into(),
        key: key.into(),
        minted: false,
    });
    task.mode = if pty { BgMode::Pty } else { BgMode::Pipes };
    if running {
        task.status = BgTaskStatus::Running;
        task.finished_at = None;
        task.duration_ms = None;
        task.exit_code = None;
        task.completion_preview = None;
        task.child_pid = Some(std::process::id());
        task.timeout_ms = Some(1000);
        task.default_hard_kill = true;
    }
    persistence::write_task_at(&layout, &task).unwrap();
    std::fs::write(&layout.paths.stdout, b"one\n").unwrap();
    std::fs::write(&layout.paths.stderr, b"two\n").unwrap();
    if pty {
        std::fs::write(&layout.paths.pty, b"\x1b[31mpty\x1b[0m").unwrap();
    }
    save_row(f, &layout, &task);
    (layout, task)
}

fn save_row(f: &Fixture, layout: &ResolvedTask, task: &PersistedTask) {
    let harness: crate::harness::Harness = f.policy.harness.parse().unwrap();
    let row = task
        .to_bash_task_row(&harness.storage_segment(), &layout.paths)
        .unwrap();
    crate::db::rich_ui::upsert_task_row_with_view(&f.ctx.db().unwrap().lock().unwrap(), &row, task)
        .unwrap();
}

async fn query(f: &Fixture, id: &str, key: &str, extra: Value) -> Value {
    let name = if id == "bash_output" {
        "bash_status"
    } else {
        id
    };
    let mut args = extra;
    args["rich_ui_op"] = format!("{id}@1").into();
    args["task"] = key.into();
    let operation = super::super::super::admission::prepare(name, &args).unwrap();
    let reply = exchange(f, name, args, "worker").await;
    assert_eq!(reply.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    super::super::super::carrier::validate_body(Some(&operation.entry), &body).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 3, "no session sidecars");
    body
}

fn reopen(f: &Fixture) {
    f.ctx.clear_db();
    f.ctx.set_db(Arc::new(std::sync::Mutex::new(
        crate::db::open(&f.dir.path().join("aft.db")).unwrap(),
    )));
}

#[tokio::test]
async fn command_views_resolve_storage_segment_and_fresh_status_after_exit() {
    let _manifest =
        super::super::super::chunks::set_test_manifest_for_test(Some(MANIFEST.to_vec()));
    for kind in ["head", "worker"] {
        let f = Fixture::new(kind);
        let requester = principal(&f.policy).unwrap();
        let (layout, mut task) = seed(&f, TASK, &f.policy.session, requester, "call", true, false);
        let hard_kill = task.timeout_ms;
        let before = f.ctx.db().unwrap().lock().unwrap().total_changes();
        let body = query(&f, "bash_status", "call", json!({})).await;
        assert_eq!(
            body["structuredContent"],
            json!({"running":true, "exitCode":null}),
            "{body}"
        );
        assert_eq!(f.ctx.db().unwrap().lock().unwrap().total_changes(), before);
        assert_eq!(
            persistence::read_task_at(&layout).unwrap().timeout_ms,
            hard_kill
        );
        task.mark_terminal(BgTaskStatus::Completed, Some(3), None);
        persistence::write_task_at(&layout, &task).unwrap();
        save_row(&f, &layout, &task);
        let body = query(&f, "bash_status", "call", json!({})).await;
        assert_eq!(
            body["structuredContent"],
            json!({"running":false, "exitCode":3})
        );
        reopen(&f);
        let body = query(&f, "bash_status", "call", json!({})).await;
        assert_eq!(body["structuredContent"]["exitCode"], 3);
    }
}

#[tokio::test]
async fn command_output_cursor_survives_reopen_and_uses_database_key() {
    let _manifest =
        super::super::super::chunks::set_test_manifest_for_test(Some(MANIFEST.to_vec()));
    let f = Fixture::new("worker");
    let (layout, task) = seed(
        &f,
        TASK,
        &f.policy.session,
        principal(&f.policy).unwrap(),
        "call",
        false,
        false,
    );
    seed(
        &f,
        TASK_TWO,
        &f.policy.session,
        principal(&f.policy).unwrap(),
        "second",
        false,
        false,
    );
    let first = query(&f, "bash_output", "call", json!({"limit":1})).await;
    assert_eq!(
        first["structuredContent"]["items"],
        json!([{"stream":"stdout","text":"one\n","bytes":4,"continued":false,"firstAvailableOffset":null,"prefixDropped":false}])
    );
    let cursor = first["structuredContent"]["next"].clone();
    let key: Vec<u8> = f
        .ctx
        .db()
        .unwrap()
        .lock()
        .unwrap()
        .query_row(
            "SELECT key FROM rich_ui_cursor_key WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    reopen(&f);
    let second = query(
        &f,
        "bash_output",
        "call",
        json!({"limit":1,"cursor":cursor}),
    )
    .await;
    assert_eq!(
        second["structuredContent"]["items"],
        json!([{"stream":"stderr","text":"two\n","bytes":4,"continued":false,"firstAvailableOffset":null,"prefixDropped":false}])
    );
    assert!(second["structuredContent"]["next"].is_null());
    assert_eq!(
        persistence::read_task_at(&layout).unwrap().timeout_ms,
        task.timeout_ms
    );
    let replay = query(&f, "bash_output", "second", json!({"cursor":cursor})).await;
    assert_eq!(replay["structuredContent"]["code"], "malformed_cursor");
    let mut tampered = cursor.as_str().unwrap().as_bytes().to_vec();
    tampered[5] = if tampered[5] == b'A' { b'B' } else { b'A' };
    let tampered = query(
        &f,
        "bash_output",
        "call",
        json!({"cursor":String::from_utf8(tampered).unwrap()}),
    )
    .await;
    assert_eq!(tampered["structuredContent"]["code"], "malformed_cursor");
    f.ctx
        .db()
        .unwrap()
        .lock()
        .unwrap()
        .execute("UPDATE rich_ui_cursor_key SET key = ?1", [vec![0u8; 32]])
        .unwrap();
    let changed = query(&f, "bash_output", "call", json!({"cursor":cursor})).await;
    assert_eq!(changed["structuredContent"]["code"], "malformed_cursor");
    f.ctx
        .db()
        .unwrap()
        .lock()
        .unwrap()
        .execute("UPDATE rich_ui_cursor_key SET key = ?1", [key])
        .unwrap();
    assert_eq!(
        query(&f, "bash_output", "call", json!({"cursor":cursor})).await,
        second
    );
    f.ctx.clear_db();
    let unavailable = query(&f, "bash_output", "call", json!({"cursor":cursor})).await;
    assert_eq!(
        unavailable["structuredContent"]["code"],
        "database_unavailable"
    );
}

#[tokio::test]
async fn command_views_refuse_foreign_minted_duplicates_and_erased_rows() {
    let _manifest =
        super::super::super::chunks::set_test_manifest_for_test(Some(MANIFEST.to_vec()));
    for fault in ["foreign", "minted", "duplicate", "erased", "worker-owned"] {
        let f = Fixture::new("head");
        let requester = principal(&f.policy).unwrap();
        let (layout, mut task) = seed(
            &f,
            TASK,
            if fault == "worker-owned" {
                "worker-session"
            } else {
                &f.policy.session
            },
            if fault == "foreign" {
                "reserved:other"
            } else {
                requester
            },
            "call",
            false,
            false,
        );
        if fault == "minted" {
            task.call_key.as_mut().unwrap().minted = true;
            persistence::write_task_at(&layout, &task).unwrap();
            save_row(&f, &layout, &task);
        }
        if fault == "duplicate" {
            seed(
                &f,
                TASK_TWO,
                &f.policy.session,
                requester,
                "call",
                false,
                false,
            );
        }
        if fault == "erased" {
            crate::db::bash_tasks::delete_bash_task(
                &f.ctx.db().unwrap().lock().unwrap(),
                task.harness.as_deref().unwrap(),
                &task.session_id,
                TASK,
            )
            .unwrap();
        }
        for id in ["bash_status", "bash_output"] {
            assert_eq!(
                query(&f, id, "call", json!({})).await["structuredContent"]["code"],
                "task_not_found",
                "{fault}/{id}"
            );
        }
    }
}

#[tokio::test]
async fn command_output_pty_has_no_stderr_and_keeps_escape_bytes() {
    let _manifest =
        super::super::super::chunks::set_test_manifest_for_test(Some(MANIFEST.to_vec()));
    let f = Fixture::new("head");
    seed(
        &f,
        TASK,
        &f.policy.session,
        principal(&f.policy).unwrap(),
        "call",
        false,
        true,
    );
    let body = query(&f, "bash_output", "call", json!({})).await;
    assert_eq!(
        body["structuredContent"],
        json!({"items":[{"stream":"pty","text":"\x1b[31mpty\x1b[0m","bytes":12,"continued":false,"firstAvailableOffset":null,"prefixDropped":false}],"next":null})
    );
}
