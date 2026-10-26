use super::*;
use crate::config::UserServerDef;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const WAIT: Duration = Duration::from_secs(30);

thread_local! {
    static MANAGER_LOCK_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn locked<R>(f: &Fixture, operation: impl FnOnce(&mut LspManager) -> R) -> R {
    let mut manager = f.manager.lock();
    MANAGER_LOCK_HELD.set(true);
    let result = operation(&mut manager);
    MANAGER_LOCK_HELD.set(false);
    result
}

struct Fixture {
    _root: tempfile::TempDir,
    config: Config,
    file: PathBuf,
    manager: Arc<parking_lot::Mutex<LspManager>>,
    snapshot: ApplicableServerSnapshot,
    key: ServerKey,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("marker"), "marker").unwrap();
    let file = root.path().join("source.reserved");
    std::fs::write(&file, "content").unwrap();
    let mut frame = Vec::new();
    super::super::transport::write_message(
        &mut frame,
        r#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}"#,
    )
    .unwrap();
    let script = root.path().join("server.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nIFS= read -r header\nprintf '%s' '{}'\nwhile IFS= read -r line; do :; done\n",
            String::from_utf8(frame).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = Config {
        project_root: Some(root.path().to_path_buf()),
        lsp_servers: vec![UserServerDef {
            id: "reserved".into(),
            extensions: vec!["reserved".into()],
            binary: "reserved".into(),
            args: Vec::new(),
            root_markers: vec!["marker".into()],
            env: HashMap::new(),
            initialization_options: None,
            disabled: false,
        }],
        ..Config::default()
    };
    let mut manager = LspManager::new();
    manager.override_binary(ServerKind::Custom(Arc::from("reserved")), script);
    let definition = servers_for_file(&file, &config).remove(0);
    let key = server_key_for_definition(&definition, &file, &config).unwrap();
    let snapshot = ApplicableServerSnapshot {
        server_keys: vec![key.clone()],
        candidates: vec![ApplicableServerCandidate {
            key: key.clone(),
            definition,
            source_file: file.clone(),
        }],
        ..ApplicableServerSnapshot::default()
    };
    let manager = Arc::new(parking_lot::Mutex::new(manager));
    manager.lock().startup_owner = Arc::downgrade(&manager);
    Fixture {
        _root: root,
        config,
        file,
        manager,
        snapshot,
        key,
    }
}

struct Pause {
    entered: Receiver<()>,
    resume: Sender<()>,
    spawns: Arc<AtomicUsize>,
    under_lock: Arc<AtomicBool>,
}

fn pause_first_spawn(f: &Fixture) -> Pause {
    let (entered_tx, entered) = unbounded();
    let (resume, resume_rx) = unbounded();
    let spawns = Arc::new(AtomicUsize::new(0));
    let under_lock = Arc::new(AtomicBool::new(false));
    let count = Arc::clone(&spawns);
    let locked = Arc::clone(&under_lock);
    f.manager.lock().spawn_hook = Some(Arc::new(move || {
        // Only a guard held by the spawning thread violates the lock boundary;
        // another caller is allowed to inspect the manager during startup.
        if MANAGER_LOCK_HELD.get() {
            locked.store(true, Ordering::SeqCst);
        }
        if count.fetch_add(1, Ordering::SeqCst) == 0 {
            entered_tx.send(()).unwrap();
            resume_rx.recv_timeout(WAIT).unwrap();
        }
    }));
    Pause {
        entered,
        resume,
        spawns,
        under_lock,
    }
}

#[test]
fn locked_and_unlocked_starts_share_one_reservation() {
    let f = fixture();
    let pause = pause_first_spawn(&f);
    std::thread::scope(|scope| {
        let running = scope.spawn(|| {
            ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config)
        });
        pause.entered.recv_timeout(WAIT).unwrap();
        let file = locked(&f, |manager| {
            manager.ensure_server_for_file_detailed(&f.file, &f.config)
        });
        let area = locked(&f, |manager| {
            manager.start_applicable_servers(&f.snapshot, &f.config)
        });
        pause.resume.send(()).unwrap();
        let completed = running.join().unwrap();
        assert_eq!(pause.spawns.load(Ordering::SeqCst), 1, "duplicate spawn");
        assert_eq!(
            server_attempt_result_reason(&file.attempts[0].result),
            "start_in_progress"
        );
        assert!(file.successful.is_empty());
        assert!(area.successful.is_empty());
        assert!(area.failures.is_empty());
        assert_eq!(completed.successful, vec![f.key.clone()]);
        assert!(
            !pause.under_lock.load(Ordering::SeqCst),
            "spawn held manager lock"
        );
    });
}

#[test]
fn locked_cold_start_never_spawns_under_manager_lock() {
    for area in [false, true] {
        let f = fixture();
        let pause = pause_first_spawn(&f);
        pause.resume.send(()).unwrap();
        if area {
            locked(&f, |manager| {
                manager.start_applicable_servers(&f.snapshot, &f.config)
            });
        } else {
            locked(&f, |manager| {
                manager.ensure_server_for_file_detailed(&f.file, &f.config)
            });
        }
        pause.entered.recv_timeout(WAIT).unwrap();
        assert!(
            !pause.under_lock.load(Ordering::SeqCst),
            "spawn held manager lock"
        );
        let completed =
            ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config);
        assert_eq!(completed.successful, vec![f.key.clone()]);
    }
}

#[test]
fn waiter_sees_pending_then_the_real_result() {
    let f = fixture();
    let pause = pause_first_spawn(&f);
    let initial = locked(&f, |manager| {
        manager.ensure_server_for_file_detailed(&f.file, &f.config)
    });
    pause.entered.recv_timeout(WAIT).unwrap();
    let pending = locked(&f, |manager| {
        manager.ensure_server_for_file_detailed(&f.file, &f.config)
    });
    assert!(
        matches!(&initial.attempts[0].result, ServerAttemptResult::InProgress { server_key } if server_key == &f.key)
    );
    assert_eq!(START_IN_PROGRESS_STATUS, "start_in_progress");
    assert_eq!(
        START_IN_PROGRESS_REASON,
        "server startup is in progress; retry shortly"
    );
    assert_eq!(
        pending.attempts[0].result.failure_reason(),
        START_IN_PROGRESS_REASON
    );
    let response =
        crate::commands::lsp_diagnostics::startup_unavailable_response(&f.file, &pending);
    assert_eq!(response["complete"], false);
    assert_eq!(response["pending_servers"], serde_json::json!(["reserved"]));
    assert_eq!(
        response["unchecked_files"],
        serde_json::json!([f.file.display().to_string()])
    );
    assert_eq!(
        response["lsp_servers_used"][0]["status"],
        "start_in_progress"
    );
    let area = locked(&f, |manager| {
        manager.start_applicable_servers(&f.snapshot, &f.config)
    });
    assert_eq!(area.in_progress, vec![f.key.clone()]);
    assert!(area.successful.is_empty());
    assert!(!f.manager.lock().failed_spawns.contains_key(&f.key));
    assert!(!f.manager.lock().transient_backoff.contains_key(&f.key));
    pause.resume.send(()).unwrap();
    let ready = ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config);
    assert_eq!(ready.successful, vec![f.key.clone()]);
    assert_eq!(
        server_attempt_result_reason(&ready.attempts[0].result),
        "ok"
    );
    assert_eq!(
        ServerAttemptResult::BinaryNotInstalled {
            binary: "example-ls".into()
        }
        .failure_reason(),
        "example-ls is unavailable"
    );
    assert_eq!(pause.spawns.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_spawn_releases_reservation_for_retry_and_all_waiters() {
    let f = fixture();
    let binary = f.manager.lock().binary_overrides[&f.key.kind].clone();
    let original = std::fs::read(&binary).unwrap();
    let clock_offset = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = Arc::clone(&clock_offset);
    let now = Instant::now();
    f.manager
        .lock()
        .set_retry_clock(RetryClock::from_fn(move || {
            now + Duration::from_secs(clock.load(Ordering::SeqCst))
        }));
    let pause = pause_first_spawn(&f);
    locked(&f, |manager| {
        manager.ensure_server_for_file_detailed(&f.file, &f.config)
    });
    pause.entered.recv_timeout(WAIT).unwrap();
    // An executable image error occurs after binary resolution and is transient.
    std::fs::write(&binary, "invalid executable image\n").unwrap();
    std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config)
        });
        let two = scope.spawn(|| {
            ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config)
        });
        let mut manager = f.manager.lock();
        let signal = Arc::clone(&manager.starting[&f.key].signal);
        pause.resume.send(()).unwrap();
        assert!(signal.wait_until(Instant::now() + WAIT));
        manager.publish_completed_starts();
        assert!(manager.starting.is_empty());
        drop(manager);
        let one = one.join().unwrap();
        let two = two.join().unwrap();
        assert!(matches!(
            one.attempts[0].result,
            ServerAttemptResult::SpawnFailed { .. }
        ));
        assert_eq!(
            server_attempt_result_reason(&one.attempts[0].result),
            server_attempt_result_reason(&two.attempts[0].result)
        );
    });
    assert!(f.manager.lock().starting.is_empty());
    assert_eq!(pause.spawns.load(Ordering::SeqCst), 1);
    std::fs::write(&binary, original).unwrap();
    clock_offset.store(3600, Ordering::SeqCst);
    let retry = ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config);
    assert_eq!(retry.successful, vec![f.key.clone()]);
    assert_eq!(pause.spawns.load(Ordering::SeqCst), 2);
}

#[test]
fn closing_project_during_startup_reaps_child_and_never_installs_it() {
    for shutdown in [false, true] {
        let f = fixture();
        let (spawned_tx, spawned_rx) = unbounded();
        let (resume_tx, resume_rx) = unbounded();
        f.manager.lock().spawned_hook = Some(Arc::new(move |pid| {
            spawned_tx.send(pid).unwrap();
            resume_rx.recv_timeout(WAIT).unwrap();
        }));
        locked(&f, |manager| {
            manager.ensure_server_for_file_detailed(&f.file, &f.config)
        });
        let pid = spawned_rx.recv_timeout(WAIT).unwrap();
        let signal = Arc::clone(&f.manager.lock().starting[&f.key].signal);
        if shutdown {
            f.manager.lock().shutdown_all();
        } else {
            f.manager.lock().quiesce();
        }
        resume_tx.send(()).unwrap();
        assert!(signal.cancelled.load(Ordering::SeqCst));
        assert!(signal.wait_until(Instant::now() + WAIT));
        // waitpid blocks in the kernel, not a timing loop; the client's reaper
        // may already have consumed the exit status, which also proves exit.
        let waited = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), 0) };
        assert!(
            waited == pid as i32
                || (waited == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
        );
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        f.manager.lock().publish_completed_starts();
        assert_eq!(f.manager.lock().server_count(), 0);
        assert!(f.manager.lock().child_registry.pids().is_empty());
        if !shutdown {
            let result = locked(&f, |manager| {
                manager.ensure_server_for_file_detailed(&f.file, &f.config)
            });
            assert!(matches!(
                result.attempts[0].result,
                ServerAttemptResult::ProjectClosed
            ));
        }
    }
}

#[test]
fn cancelled_start_cannot_publish_over_a_new_reservation() {
    let f = fixture();
    let (finished_tx, finished_rx) = unbounded();
    f.manager.lock().startup_finished_hook = Some(Arc::new(move || {
        finished_tx.send(()).unwrap();
    }));
    let pause = pause_first_spawn(&f);
    let spawned = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&spawned);
    f.manager.lock().spawned_hook = Some(Arc::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
    }));
    locked(&f, |manager| {
        manager.ensure_server_for_file_detailed(&f.file, &f.config)
    });
    pause.entered.recv_timeout(WAIT).unwrap();
    let old = Arc::clone(&f.manager.lock().starting[&f.key].signal);
    f.manager.lock().quiesce();
    assert!(f.manager.lock().starting.is_empty());
    f.manager.lock().resume();
    let ready = ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config);
    assert_eq!(ready.successful, vec![f.key.clone()]);
    let pid = f.manager.lock().clients[&f.key].child_pid();
    finished_rx.recv_timeout(WAIT).unwrap();
    pause.resume.send(()).unwrap();
    finished_rx.recv_timeout(WAIT).unwrap();
    assert!(old.cancelled.load(Ordering::SeqCst));
    assert!(matches!(
        *old.outcome.lock(),
        Some(ServerAttemptResult::ProjectClosed)
    ));
    f.manager.lock().publish_completed_starts();
    assert_eq!(f.manager.lock().clients[&f.key].child_pid(), pid);
    assert_eq!(spawned.load(Ordering::SeqCst), 1);
}

#[test]
fn in_progress_is_not_a_cached_executable_failure() {
    let f = fixture();
    let result = f.manager.lock().record_failed_spawn(
        &f.key,
        ServerAttemptResult::InProgress {
            server_key: f.key.clone(),
        },
        FailureDurability::Transient,
    );
    assert!(matches!(result, ServerAttemptResult::InProgress { .. }));
    assert!(f.manager.lock().failed_spawns.is_empty());
    assert!(f.manager.lock().transient_backoff.is_empty());
}

fn notification_fixture() -> Fixture {
    let f = fixture();
    let binary = f.manager.lock().binary_overrides[&f.key.kind].clone();
    std::fs::write(&binary, r#"#!/usr/bin/env python3
import json, sys
seen = []
while True:
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            sys.exit(0)
        if line in (b'\r\n', b'\n'):
            break
        key, value = line.decode().split(':', 1)
        headers[key.lower()] = value.strip()
    message = json.loads(sys.stdin.buffer.read(int(headers['content-length'])))
    method = message.get('method')
    if method in ('textDocument/didOpen', 'textDocument/didChange'):
        seen.append(message)
    if 'id' in message:
        result = {'capabilities': {}} if method == 'initialize' else seen if method == 'test/notifications' else None
        body = json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': result}).encode()
        sys.stdout.buffer.write(('Content-Length: %d\r\n\r\n' % len(body)).encode() + body)
        sys.stdout.buffer.flush()
    if method == 'exit':
        break
"#).unwrap();
    f
}

enum RecordedNotifications {}
impl lsp_types::request::Request for RecordedNotifications {
    type Params = serde_json::Value;
    type Result = Vec<serde_json::Value>;
    const METHOD: &'static str = "test/notifications";
}

fn recorded_notifications(f: &Fixture) -> Vec<serde_json::Value> {
    let request = f
        .manager
        .lock()
        .clients
        .get_mut(&f.key)
        .unwrap()
        .start_request::<RecordedNotifications>(serde_json::json!({}))
        .unwrap();
    serde_json::from_value(request.wait(WAIT).unwrap()).unwrap()
}

#[test]
fn file_change_during_startup_replays_latest_did_open() {
    for changes in [1, 2] {
        let f = notification_fixture();
        let pause = pause_first_spawn(&f);
        locked(&f, |manager| {
            manager.ensure_server_for_file_detailed(&f.file, &f.config)
        });
        pause.entered.recv_timeout(WAIT).unwrap();
        let mut expected = Vec::new();
        for version in 0..changes {
            let content = format!("content version {version}");
            std::fs::write(&f.file, &content).unwrap();
            expected = locked(&f, |manager| {
                manager.notify_file_changed_versioned(&f.file, &content, &f.config)
            })
            .unwrap();
        }
        pause.resume.send(()).unwrap();
        let ready =
            ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config);
        assert_eq!(ready.successful, vec![f.key.clone()]);
        let messages = recorded_notifications(&f);
        assert_eq!(
            messages.len(),
            1,
            "startup changes must coalesce into one didOpen: {messages:?}"
        );
        assert_eq!(messages[0]["method"], "textDocument/didOpen");
        assert_eq!(
            messages[0]["params"]["textDocument"]["text"],
            format!("content version {}", changes - 1)
        );
        assert_eq!(
            messages[0]["params"]["textDocument"]["version"],
            changes - 1
        );
        assert_eq!(expected, vec![(f.key.clone(), changes - 1)]);
    }
}

#[test]
fn file_change_during_cancelled_startup_is_not_replayed() {
    let f = notification_fixture();
    let pause = pause_first_spawn(&f);
    let (done_tx, done_rx) = unbounded();
    f.manager.lock().startup_finished_hook = Some(Arc::new(move || {
        done_tx.send(()).unwrap();
    }));
    locked(&f, |manager| {
        manager.ensure_server_for_file_detailed(&f.file, &f.config)
    });
    pause.entered.recv_timeout(WAIT).unwrap();
    locked(&f, |manager| {
        manager.notify_file_changed_versioned(&f.file, "never replay", &f.config)
    })
    .unwrap();
    f.manager.lock().quiesce();
    pause.resume.send(()).unwrap();
    done_rx.recv_timeout(WAIT).unwrap();
    f.manager.lock().resume();
    f.manager.lock().spawn_hook = None;
    let ready = ensure_server_for_file_detailed_unlocked(|| f.manager.lock(), &f.file, &f.config);
    assert_eq!(ready.successful, vec![f.key.clone()]);
    assert!(
        recorded_notifications(&f).is_empty(),
        "closed reservation leaked a notification into its replacement"
    );
}
