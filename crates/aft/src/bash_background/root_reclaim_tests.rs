use super::*;

pub(crate) fn register_task(
    registry: &BgTaskRegistry,
    storage: &Path,
    root: &Path,
    task_id: &str,
    status: BgTaskStatus,
    pid: Option<u32>,
) {
    let layout =
        super::super::persistence::create_task_layout(storage, "reclaim", task_id).unwrap();
    let mut metadata = PersistedTask::starting(
        task_id.into(),
        "reclaim".into(),
        "owned reclaim fixture".into(),
        root.to_path_buf(),
        Some(root.to_path_buf()),
        None,
        true,
        false,
    );
    metadata.status = status;
    metadata.child_pid = pid;
    metadata.pgid = pid.map(|pid| pid as i32);
    metadata.live_descendants = pid.map(|pid| {
        vec![super::super::process::LiveDescendant {
            pid,
            comm: "sleep".into(),
            argv0: "sleep".into(),
        }]
    });
    super::super::persistence::write_task(&layout.paths.json, &metadata).unwrap();
    registry
        .insert_rehydrated_task(metadata, layout.paths, true)
        .unwrap();
    // Keep terminal fixtures in the watchdog index without starting a watchdog.
    let task = registry.task_for_session(task_id, "reclaim").unwrap();
    registry
        .inner
        .watchdog_tasks
        .lock()
        .unwrap()
        .insert(task_id.into(), task);
}

pub(crate) fn refuse_reclaim_kills(registry: &BgTaskRegistry) {
    registry
        .inner
        .reclaim_kill_noop
        .store(true, Ordering::SeqCst);
}

pub(crate) fn kill_attempts(registry: &BgTaskRegistry) -> usize {
    registry.inner.reclaim_kill_attempts.load(Ordering::SeqCst)
}

pub(crate) struct OwnedGroup(pub(crate) std::process::Child);

impl OwnedGroup {
    pub(crate) fn spawn() -> Self {
        use std::os::unix::process::CommandExt;
        Self(
            std::process::Command::new("sleep")
                .arg("60")
                .process_group(0)
                .spawn()
                .unwrap(),
        )
    }
}

impl Drop for OwnedGroup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn root_reclaim_probe_ignores_foreign_tasks_and_terminal_history() {
    let registry = BgTaskRegistry::default();
    let storage = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let root_id = crate::path_identity::ProjectRootId::from_path(root.path()).unwrap();
    let foreign = tempfile::tempdir().unwrap();
    register_task(
        &registry,
        storage.path(),
        root.path(),
        "bash-0000000000000010",
        BgTaskStatus::Completed,
        None,
    );
    register_task(
        &registry,
        storage.path(),
        foreign.path(),
        "bash-0000000000000011",
        BgTaskStatus::Running,
        None,
    );
    let foreign_task = registry
        .task_for_session("bash-0000000000000011", "reclaim")
        .unwrap();
    let _held = foreign_task.state.lock().unwrap();
    ROOT_LOCK_PROBE.with(|probe| {
        *probe.borrow_mut() = Some(Box::new(|| panic!("reclaim probe touched filesystem")))
    });
    assert_eq!(
        registry.try_has_reclaimable_tasks_for_root(&root_id),
        Some(false)
    );
    ROOT_LOCK_PROBE.with(|probe| *probe.borrow_mut() = None);
}

#[test]
fn root_reclaim_probe_defers_on_own_task_or_registry_contention() {
    let registry = BgTaskRegistry::default();
    let storage = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let root_id = crate::path_identity::ProjectRootId::from_path(root.path()).unwrap();
    let id = "bash-0000000000000012";
    register_task(
        &registry,
        storage.path(),
        root.path(),
        id,
        BgTaskStatus::Running,
        None,
    );
    assert_eq!(
        registry.try_has_reclaimable_tasks_for_root(&root_id),
        Some(true)
    );
    let task = registry.task_for_session(id, "reclaim").unwrap();
    let held = task.state.lock().unwrap();
    assert_eq!(registry.try_has_reclaimable_tasks_for_root(&root_id), None);
    drop(held);
    let _held = registry.inner.tasks.lock().unwrap();
    assert_eq!(registry.try_has_reclaimable_tasks_for_root(&root_id), None);
}

pub(crate) fn finish_task(registry: &BgTaskRegistry, id: &str) {
    registry
        .task_for_session(id, "reclaim")
        .unwrap()
        .lock_state()
        .unwrap()
        .metadata
        .status = BgTaskStatus::Killed;
}

pub(crate) fn clear_descendant_sample(registry: &BgTaskRegistry, id: &str) {
    registry
        .task_for_session(id, "reclaim")
        .unwrap()
        .lock_state()
        .unwrap()
        .metadata
        .live_descendants = None;
}

pub(crate) fn while_task_map_locked<T>(registry: &BgTaskRegistry, call: impl FnOnce() -> T) -> T {
    let _held = registry.inner.tasks.lock().unwrap();
    call()
}
