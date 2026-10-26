use super::*;
use crate::context::{default_language_provider_factory, AppContext};
use crate::lsp::client::ServerExitReason;
use crossbeam_channel::{Receiver, Sender};
use lsp_types::notification::Notification;
use serde_json::{json, Value};
use std::sync::Mutex;

const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Reader,
    Dispatch,
}

struct Gate {
    instance: ServerInstanceId,
    stage: Stage,
    entered: Sender<()>,
    release: Receiver<()>,
}

static GATES: Mutex<Vec<Gate>> = Mutex::new(Vec::new());

struct Pause {
    entered: Receiver<()>,
    release: Sender<()>,
}

impl Pause {
    fn install(instance: ServerInstanceId, stage: Stage) -> Self {
        let (entered_tx, entered) = bounded(1);
        let (release, release_rx) = bounded(1);
        GATES.lock().unwrap().push(Gate {
            instance,
            stage,
            entered: entered_tx,
            release: release_rx,
        });
        Self { entered, release }
    }

    fn wait(&self) {
        self.entered.recv_timeout(DEADLINE).expect("pause reached");
    }
}

impl Drop for Pause {
    fn drop(&mut self) {
        let _ = self.release.try_send(());
    }
}

fn pause(instance: ServerInstanceId, stage: Stage) {
    let gate = {
        let mut gates = GATES.lock().unwrap();
        gates
            .iter()
            .position(|gate| gate.instance == instance && gate.stage == stage)
            .map(|position| gates.remove(position))
    };
    if let Some(gate) = gate {
        let _ = gate.entered.send(());
        gate.release.recv_timeout(DEADLINE).expect("pause released");
    }
}

pub(crate) fn pause_reader(instance: ServerInstanceId) {
    pause(instance, Stage::Reader);
}

pub(crate) fn pause_dispatch(instance: ServerInstanceId) {
    pause(instance, Stage::Dispatch);
}

fn key(root: &Path) -> ServerKey {
    ServerKey {
        kind: ServerKind::TypeScript,
        root: root.to_path_buf(),
    }
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn frame(message: Value) -> String {
    let body = message.to_string();
    format!("Content-Length: {}\r\n\r\n{body}", body.len())
}

fn diagnostics(file: &Path, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": {
        "uri": uri_for_path(file).unwrap(), "diagnostics": [{
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}},
            "severity": 1, "message": message
        }]
    }})
}

fn request() -> Value {
    json!({"jsonrpc": "2.0", "id": "retired-request", "method": "client/registerCapability",
        "params": {"registrations": []}})
}

fn spawn(
    manager: &LspManager,
    root: &Path,
    instance: ServerInstanceId,
    command: &str,
) -> LspClient {
    LspClient::spawn_with_reclaim_root(
        ServerKind::TypeScript,
        root.to_path_buf(),
        Path::new("/bin/sh"),
        &["-c".into(), command.into()],
        &HashMap::new(),
        LspEventSender::Managed {
            sender: manager.event_tx.clone(),
            instance,
        },
        manager.child_registry.clone(),
        None,
        false,
    )
    .expect("spawn framed reader")
}

fn next(manager: &LspManager) -> ReceivedLspEvent {
    manager
        .event_rx
        .recv_timeout(DEADLINE)
        .expect("reader event")
}

fn replace(
    manager: &mut LspManager,
    root: &Path,
    command: &str,
) -> (ServerInstanceId, Option<LspClient>) {
    let instance = ServerInstanceId::next();
    let client = spawn(manager, root, instance, command);
    let old = manager.clients.insert(key(root), client);
    (instance, old)
}

#[test]
fn retired_reader_diagnostics_leave_replacement_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("main.ts");
    let mut manager = LspManager::new();
    let retired = ServerInstanceId::next();
    let pause = Pause::install(retired, Stage::Reader);
    let command = format!(
        "printf '%s' {}; exec cat",
        quote(&frame(diagnostics(&file, "retired")))
    );
    let old = spawn(&manager, dir.path(), retired, &command);
    manager.clients.insert(key(dir.path()), old);
    pause.wait();
    let (_, _old) = replace(&mut manager, dir.path(), "exec cat");
    manager
        .diagnostics
        .publish(key(dir.path()), file.clone(), Vec::new());
    let epoch = manager.diagnostics.current_epoch();
    drop(pause);
    let receipt = next(&manager);
    assert_eq!(receipt.instance, Some(retired));
    manager.handle_waited_event(Some(receipt));
    assert!(
        manager.get_diagnostics_for_file(&file).is_empty(),
        "retired diagnostics replaced the new report"
    );
    assert_eq!(manager.diagnostics.current_epoch(), epoch);
    assert_eq!(manager.retired_events_dropped, 1);
}

#[test]
fn retired_reader_exit_leaves_replacement_alive() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = LspManager::new();
    let retired = ServerInstanceId::next();
    let pause = Pause::install(retired, Stage::Reader);
    let old = spawn(&manager, dir.path(), retired, "exit 0");
    manager.clients.insert(key(dir.path()), old);
    pause.wait();
    let (current, _old) = replace(&mut manager, dir.path(), "exec cat");
    drop(pause);
    let receipt = next(&manager);
    assert!(matches!(
        receipt.event,
        LspEvent::ServerExited {
            reason: ServerExitReason::Eof,
            ..
        }
    ));
    let (_, logs) =
        crate::logging::capture_log_lines(|| manager.handle_waited_event(Some(receipt)));
    assert_eq!(manager.clients[&key(dir.path())].instance, current);
    assert!(
        logs.iter().all(|line| !line.contains("status unavailable")),
        "retired exit was dispatched: {logs:?}"
    );
    assert_eq!(manager.retired_events_dropped, 1);
}

#[test]
fn retired_reader_request_is_not_replied_to_by_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = LspManager::new();
    let retired = ServerInstanceId::next();
    let pause = Pause::install(retired, Stage::Reader);
    let command = format!("printf '%s' {}; exec cat", quote(&frame(request())));
    let old = spawn(&manager, dir.path(), retired, &command);
    manager.clients.insert(key(dir.path()), old);
    pause.wait();
    let trace = dir.path().join("replacement-input");
    let command = format!("exec tee {}", quote(trace.to_str().unwrap()));
    let (current, _old) = replace(&mut manager, dir.path(), &command);
    drop(pause);
    let receipt = next(&manager);
    assert!(matches!(receipt.event, LspEvent::ServerRequest { .. }));
    manager.event_tx.send(receipt).unwrap();
    let drained = manager.drain_events();

    enum Barrier {}
    impl lsp_types::notification::Notification for Barrier {
        type Params = Value;
        const METHOD: &'static str = "aft/instanceBarrier";
    }
    manager
        .clients
        .get_mut(&key(dir.path()))
        .unwrap()
        .send_notification::<Barrier>(json!({}))
        .unwrap();
    let barrier = next(&manager);
    assert_eq!(barrier.instance, Some(current));
    assert!(
        matches!(barrier.event, LspEvent::Notification { ref method, .. } if method == Barrier::METHOD)
    );
    // The echoed barrier follows every earlier write in the replacement's FIFO.
    // Its trace therefore proves no reply was routed there before this check.
    let input = std::fs::read_to_string(trace).unwrap();
    assert!(
        !input.contains("retired-request"),
        "retired request was answered by the replacement: {input}"
    );
    assert!(
        drained.events.is_empty(),
        "retired request reached dispatch"
    );
    assert_eq!(manager.retired_events_dropped, 1);
}

#[test]
fn current_reader_events_still_apply() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("main.ts");
    let mut manager = LspManager::new();
    let instance = ServerInstanceId::next();
    let pause = Pause::install(instance, Stage::Reader);
    let command = format!(
        "printf '%s' {}; exec cat",
        quote(&frame(diagnostics(&file, "current")))
    );
    let client = spawn(&manager, dir.path(), instance, &command);
    manager.clients.insert(key(dir.path()), client);
    pause.wait();
    drop(pause);
    let receipt = next(&manager);
    manager.handle_waited_event(Some(receipt));
    assert_eq!(
        manager.get_diagnostics_for_file(&file)[0].message,
        "current"
    );
    assert_eq!(manager.retired_events_dropped, 0);

    let exit = Pause::install(instance, Stage::Reader);
    drop(manager.clients.remove(&key(dir.path())));
    exit.wait();
    drop(exit);
    let receipt = next(&manager);
    assert!(matches!(receipt.event, LspEvent::ServerExited { .. }));
    manager.handle_waited_event(Some(receipt));
    assert!(!manager
        .diagnostics
        .has_report_for_server_file(&key(dir.path()), &file));
    assert_eq!(manager.retired_events_dropped, 0);
}

#[test]
fn drain_dispatch_rechecks_instance_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = Arc::new(AppContext::new(
        default_language_provider_factory(),
        Config::default(),
    ));
    let instance = ServerInstanceId::next();
    let reader_pause = Pause::install(instance, Stage::Reader);
    let command = format!("printf '%s' {}; exec cat", quote(&frame(request())));
    let client = spawn(&ctx.lsp(), dir.path(), instance, &command);
    ctx.lsp().clients.insert(key(dir.path()), client);
    reader_pause.wait();
    drop(reader_pause);
    let receipt = next(&ctx.lsp());
    ctx.lsp().event_tx.send(receipt).unwrap();
    let dispatch_pause = Pause::install(instance, Stage::Dispatch);
    let worker_ctx = Arc::clone(&ctx);
    let worker =
        std::thread::spawn(move || crate::runtime_drain::drain_lsp_events_bounded(&worker_ctx, 1));
    dispatch_pause.wait();
    let (current, _old) = replace(&mut ctx.lsp(), dir.path(), "exec cat");
    drop(dispatch_pause);
    let outcome = worker.join().unwrap();
    assert_eq!(outcome.processed, 1);
    assert!(!outcome.has_more);
    assert_eq!(ctx.lsp().clients[&key(dir.path())].instance, current);
    assert_eq!(
        ctx.lsp().retired_events_dropped,
        1,
        "dispatch accepted a receipt retired after the manager drain"
    );
}

#[test]
fn startup_replay_preserves_reader_instance() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("main.ts");
    let mut manager = LspManager::new();
    let instance = ServerInstanceId::next();
    let pause = Pause::install(instance, Stage::Reader);
    let command = format!(
        "printf '%s' {}; exec cat",
        quote(&frame(diagnostics(&file, "starting")))
    );
    let old = spawn(&manager, dir.path(), instance, &command);
    manager.starting.insert(
        key(dir.path()),
        StartReservation {
            instance,
            deferred_events: Vec::new(),
            clients_generation: manager.clients_generation,
            signal: Arc::new(StartSignal::default()),
        },
    );
    pause.wait();
    drop(pause);
    let receipt = next(&manager);
    manager.handle_waited_event(Some(receipt));
    assert_eq!(
        manager.starting[&key(dir.path())].deferred_events[0].instance,
        Some(instance)
    );
    assert!(manager.get_diagnostics_for_file(&file).is_empty());
    manager.clients.insert(key(dir.path()), old);
    manager.release_start_reservation(&key(dir.path()));
    assert_eq!(
        manager.get_diagnostics_for_file(&file)[0].message,
        "starting"
    );
    assert_eq!(manager.retired_events_dropped, 0);
}

#[test]
fn retired_receipts_consume_the_raw_drain_budget() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = LspManager::new();
    let instance = ServerInstanceId::next();
    let pause = Pause::install(instance, Stage::Reader);
    let command = format!("printf '%s' {}; exec cat", quote(&frame(request())));
    let old = spawn(&manager, dir.path(), instance, &command);
    manager.clients.insert(key(dir.path()), old);
    pause.wait();
    let (_, _old) = replace(&mut manager, dir.path(), "exec cat");
    drop(pause);
    let receipt = next(&manager);
    for _ in 0..3 {
        manager.event_tx.send(receipt.clone()).unwrap();
    }
    let drained = manager.drain_events_bounded(1);
    assert!(drained.events.is_empty());
    assert_eq!(drained.processed, 1);
    assert!(drained.has_more);
    assert_eq!(manager.pending_event_count_for_test(), 2);
    assert_eq!(manager.retired_events_dropped, 1);
}

#[test]
fn drain_dispatch_does_not_wait_for_a_contended_manager() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = Arc::new(AppContext::new(
        default_language_provider_factory(),
        Config::default(),
    ));
    let instance = ServerInstanceId::next();
    let reader_pause = Pause::install(instance, Stage::Reader);
    let command = format!("printf '%s' {}; exec cat", quote(&frame(request())));
    let client = spawn(&ctx.lsp(), dir.path(), instance, &command);
    ctx.lsp().clients.insert(key(dir.path()), client);
    reader_pause.wait();
    drop(reader_pause);
    let receipt = next(&ctx.lsp());
    ctx.lsp().event_tx.send(receipt).unwrap();
    let dispatch_pause = Pause::install(instance, Stage::Dispatch);
    let worker_ctx = Arc::clone(&ctx);
    let (done_tx, done_rx) = bounded(1);
    let worker = std::thread::spawn(move || {
        done_tx
            .send(crate::runtime_drain::drain_lsp_events_bounded(
                &worker_ctx,
                1,
            ))
            .unwrap();
    });
    dispatch_pause.wait();
    let manager = ctx.lsp();
    drop(dispatch_pause);
    let outcome = done_rx
        .recv_timeout(DEADLINE)
        .expect("dispatch must not wait behind the manager");
    assert_eq!(outcome.processed, 1);
    assert!(outcome.has_more);
    drop(manager);
    worker.join().unwrap();
}
