//! Durable rich-UI assets and catalog attestations in the process's shared aft.db.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;

pub use super::remote_exec::PolicyKey as PresetKey;

pub const SCHEMA_VERSION: u32 = 20;

pub(crate) const MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS bash_view_records (
  harness TEXT NOT NULL, session_id TEXT NOT NULL, task_id TEXT NOT NULL,
  record TEXT NOT NULL,
  row_template_digest TEXT NOT NULL, page_template_digest TEXT NOT NULL,
  PRIMARY KEY (harness, session_id, task_id),
  FOREIGN KEY (harness, session_id, task_id)
    REFERENCES bash_tasks(harness, session_id, task_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rich_ui_templates (
  digest TEXT NOT NULL PRIMARY KEY, bytes BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS rich_ui_cursor_key (
  id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
  key BLOB NOT NULL CHECK (length(key) = 32)
);
INSERT OR IGNORE INTO rich_ui_cursor_key(id, key) VALUES (1, randomblob(32));
CREATE TABLE IF NOT EXISTS rich_ui_session_presets (
  project_root TEXT NOT NULL, harness TEXT NOT NULL, session TEXT NOT NULL,
  principal TEXT NOT NULL, owner TEXT NOT NULL, scope_ref TEXT NOT NULL,
  epoch TEXT NOT NULL, preset TEXT NOT NULL CHECK (preset IN ('worker', 'reader')),
  recorded_at INTEGER NOT NULL,
  PRIMARY KEY (project_root, harness, session, principal, owner, scope_ref, epoch, preset)
);
CREATE INDEX IF NOT EXISTS idx_rich_ui_session_presets_recorded
  ON rich_ui_session_presets(recorded_at);
"#;

/// Each successful fetch refreshes only its exact identity, epoch and preset.
/// Unlike routing policies, attestations never carry forward from an older epoch.
pub fn record_preset(conn: &Connection, key: &PresetKey, now_ms: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO rich_ui_session_presets
         (project_root,harness,session,principal,owner,scope_ref,epoch,preset,recorded_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(project_root,harness,session,principal,owner,scope_ref,epoch,preset)
         DO UPDATE SET recorded_at=excluded.recorded_at",
        params![
            key.project_root,
            key.harness,
            key.session,
            key.principal,
            key.owner,
            key.scope_ref,
            key.epoch.to_string(),
            key.preset,
            now_ms
        ],
    )?;
    Ok(())
}

/// Read all presets for the exact route and scope without refreshing retention.
/// The key's preset is ignored so a worker/reader disagreement remains visible.
pub fn session_presets(conn: &Connection, key: &PresetKey) -> rusqlite::Result<Vec<String>> {
    conn.prepare(
        "SELECT preset FROM rich_ui_session_presets
         WHERE project_root=?1 AND harness=?2 AND session=?3 AND principal=?4
           AND owner=?5 AND scope_ref=?6 AND epoch=?7 ORDER BY preset",
    )?
    .query_map(
        params![
            key.project_root,
            key.harness,
            key.session,
            key.principal,
            key.owner,
            key.scope_ref,
            key.epoch.to_string()
        ],
        |row| row.get(0),
    )?
    .collect()
}

pub(crate) fn prune_presets(conn: &Connection, now_ms: i64) -> rusqlite::Result<usize> {
    const RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    conn.execute(
        "DELETE FROM rich_ui_session_presets WHERE recorded_at < ?1",
        [now_ms.saturating_sub(RETENTION_MS)],
    )
}

/// View-record writing stays off in production until the publication slice
/// turns it on together with the rest of the publication gate. Tests enable
/// it through [`enable_test_view_writing_for_test`]. The flag is checked
/// first, before any database work, so a disabled writer never touches aft.db.
static VIEW_RECORD_WRITING: AtomicBool = AtomicBool::new(false);

pub(crate) fn view_record_writing_enabled() -> bool {
    VIEW_RECORD_WRITING.load(Ordering::SeqCst)
}

/// A test manifest's published pins and row/page template bytes, standing in
/// for the publication slice's shipped manifest until it lands.
#[derive(Debug, Clone)]
pub(crate) struct ViewManifest {
    pub pins: Vec<String>,
    pub row_digest: String,
    pub row_bytes: Vec<u8>,
    pub page_digest: String,
    pub page_bytes: Vec<u8>,
}

#[cfg(test)]
static TEST_VIEW_MANIFEST: Mutex<Option<ViewManifest>> = Mutex::new(None);

#[cfg(test)]
static TEST_VIEW_SERIAL: Mutex<()> = Mutex::new(());

/// The manifest [`write_view_record`] validates pins against. Production has
/// no manifest until the publication slice ships one, so this is `None`
/// outside tests; with writing disabled that already means no record.
fn view_manifest_for_writing() -> Option<ViewManifest> {
    #[cfg(test)]
    {
        return TEST_VIEW_MANIFEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
    }
    #[cfg(not(test))]
    {
        None
    }
}

/// Test-only failure injection: when set, the next [`write_view_record`]
/// fails at the template insert, after the record insert, so the savepoint
/// rolls both back while the outer task-row upsert still commits.
#[cfg(test)]
static FAIL_VIEW_TEMPLATE_INSERT: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn fail_view_template_insert() -> bool {
    FAIL_VIEW_TEMPLATE_INSERT.load(Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) fn set_fail_view_template_insert_for_test(fail: bool) {
    FAIL_VIEW_TEMPLATE_INSERT.store(fail, Ordering::SeqCst);
}

/// Hold while any test enables view writing: the writing flag and the test
/// manifest are process-global, so parallel tests must not interleave them.
/// Dropping the guard disables writing and clears the manifest again.
#[cfg(test)]
pub(crate) struct TestViewWritingGuard {
    _serial: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TestViewWritingGuard {
    fn drop(&mut self) {
        VIEW_RECORD_WRITING.store(false, Ordering::SeqCst);
        *TEST_VIEW_MANIFEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        set_fail_view_template_insert_for_test(false);
    }
}

#[cfg(test)]
pub(crate) fn enable_test_view_writing_for_test(manifest: ViewManifest) -> TestViewWritingGuard {
    let serial = TEST_VIEW_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *TEST_VIEW_MANIFEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(manifest);
    FAIL_VIEW_TEMPLATE_INSERT.store(false, Ordering::SeqCst);
    VIEW_RECORD_WRITING.store(true, Ordering::SeqCst);
    TestViewWritingGuard { _serial: serial }
}

/// Digests the binary ships. No template ships until the publication slice,
/// so every stored template counts as unshipped and is eligible for the
/// retention tick once no record references it.
pub(crate) fn shipped_template_digests() -> Vec<String> {
    Vec::new()
}

fn terminal_end_reason(status: &crate::bash_background::BgTaskStatus) -> Option<&'static str> {
    use crate::bash_background::BgTaskStatus;
    match status {
        BgTaskStatus::Completed => Some("completed"),
        BgTaskStatus::Failed => Some("failed"),
        BgTaskStatus::Killed => Some("killed"),
        BgTaskStatus::TimedOut => Some("timed_out"),
        BgTaskStatus::FateUnknown => Some("fate_unknown"),
        _ => None,
    }
}

fn view_record_value(
    task_id: &str,
    pin: &str,
    metadata: &crate::bash_background::persistence::PersistedTask,
    output_bytes: Option<i64>,
    row_digest: &str,
    page_digest: &str,
) -> serde_json::Value {
    let end_reason = terminal_end_reason(&metadata.status);
    json!({
        "schema": "aft.bash.view",
        "version": 1,
        "task_id": task_id,
        "schema_pin": pin,
        "phase": "finished",
        "exitCode": metadata.exit_code,
        "durationMs": metadata.duration_ms,
        "outputBytes": output_bytes,
        "endReason": end_reason,
        "templates": {"row": row_digest, "page": page_digest},
    })
}

/// Record a terminal pinned task's view record and its template bytes.
///
/// Runs in a savepoint nested in the task-row transaction, with `INSERT OR
/// IGNORE` for the record (on its task key) and for the template bytes (on
/// digest). The first terminal write fixes the record: later re-upserts of
/// the same task never change its pin or digests. A failed savepoint rolls
/// back and is logged, and the caller still commits the `bash_tasks` upsert.
///
/// Returns whether the stored record matches this write: false when writing
/// is disabled, the task is not terminal, the call carried no pin, no
/// manifest is available, the pin is not published, or an older record for
/// another pin already stands.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_view_record(
    conn: &Connection,
    harness: &str,
    session_id: &str,
    task_id: &str,
    metadata: &crate::bash_background::persistence::PersistedTask,
    output_bytes: Option<i64>,
) -> rusqlite::Result<bool> {
    if !view_record_writing_enabled() {
        return Ok(false);
    }
    if !metadata.status.is_terminal() {
        return Ok(false);
    }
    let Some(pin) = metadata.schema_pin.as_deref() else {
        return Ok(false);
    };
    let Some(manifest) = view_manifest_for_writing() else {
        return Ok(false);
    };
    if !manifest.pins.iter().any(|published| published == pin) {
        return Ok(false);
    }
    let record = view_record_value(
        task_id,
        pin,
        metadata,
        output_bytes,
        &manifest.row_digest,
        &manifest.page_digest,
    );
    let record_text =
        serde_json::to_string(&record).map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?;
    conn.execute_batch("SAVEPOINT view_record")?;
    let outcome = (|| -> rusqlite::Result<bool> {
        conn.execute(
            "INSERT OR IGNORE INTO bash_view_records
              (harness, session_id, task_id, record, row_template_digest, page_template_digest)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                harness,
                session_id,
                task_id,
                record_text,
                manifest.row_digest,
                manifest.page_digest
            ],
        )?;
        #[cfg(test)]
        if fail_view_template_insert() {
            return Err(rusqlite::Error::InvalidParameterName(
                "forced template-insert error".to_string(),
            ));
        }
        conn.execute(
            "INSERT OR IGNORE INTO rich_ui_templates(digest, bytes) VALUES (?1, ?2)",
            params![manifest.row_digest, manifest.row_bytes],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO rich_ui_templates(digest, bytes) VALUES (?1, ?2)",
            params![manifest.page_digest, manifest.page_bytes],
        )?;
        let stored: (String, String, String) = conn.query_row(
            "SELECT record, row_template_digest, page_template_digest FROM bash_view_records
              WHERE harness = ?1 AND session_id = ?2 AND task_id = ?3",
            params![harness, session_id, task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let stored_record: serde_json::Value = serde_json::from_str(&stored.0)
            .map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into()))?;
        Ok(stored_record.get("schema_pin").and_then(|value| value.as_str()) == Some(pin)
            && stored.1 == manifest.row_digest
            && stored.2 == manifest.page_digest)
    })();
    match outcome {
        Ok(created) => {
            conn.execute_batch("RELEASE view_record")?;
            Ok(created)
        }
        Err(error) => {
            let _ =
                conn.execute_batch("ROLLBACK TO view_record; RELEASE view_record;");
            crate::slog_warn!(
                "view record write failed for {task_id}: {error}; bash_tasks upsert still commits"
            );
            Ok(false)
        }
    }
}

/// The task-row upsert both production write paths share, followed by its
/// view record in the same transaction. A view failure never fails the row.
pub(crate) fn upsert_task_row_with_view(
    conn: &Connection,
    row: &super::bash_tasks::BashTaskRow,
    metadata: &crate::bash_background::persistence::PersistedTask,
) -> rusqlite::Result<()> {
    super::bash_tasks::upsert_bash_task(conn, row)?;
    if let Err(error) = write_view_record(
        conn,
        &row.harness,
        &row.session_id,
        &row.task_id,
        metadata,
        row.output_bytes,
    ) {
        crate::slog_warn!(
            "view record write failed for {}: {error}; bash_tasks upsert still commits",
            row.task_id
        );
    }
    Ok(())
}

/// A task's stored view record, if any, as parsed JSON.
pub(crate) fn view_record_json(
    conn: &Connection,
    harness: &str,
    session_id: &str,
    task_id: &str,
) -> rusqlite::Result<Option<serde_json::Value>> {
    let text: Option<String> = conn
        .query_row(
            "SELECT record FROM bash_view_records
              WHERE harness = ?1 AND session_id = ?2 AND task_id = ?3",
            params![harness, session_id, task_id],
            |row| row.get(0),
        )
        .optional()?;
    text.map(|text| {
        serde_json::from_str(&text).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into())
        })
    })
    .transpose()
}

/// Stored bytes for one template digest, if any.
pub(crate) fn template_bytes(
    conn: &Connection,
    digest: &str,
) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT bytes FROM rich_ui_templates WHERE digest = ?1",
        [digest],
        |row| row.get(0),
    )
    .optional()
}

/// Delete every stored template no record references and the binary does not
/// ship. Records in every project share digest-keyed bytes, so a template
/// stays while any record references it.
pub(crate) fn prune_orphaned_templates(
    conn: &Connection,
    shipped: &[String],
) -> rusqlite::Result<usize> {
    if shipped.is_empty() {
        return conn.execute(
            "DELETE FROM rich_ui_templates
              WHERE digest NOT IN (
                SELECT row_template_digest FROM bash_view_records
                UNION
                SELECT page_template_digest FROM bash_view_records
              )",
            [],
        );
    }
    let placeholders = shipped.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "DELETE FROM rich_ui_templates
          WHERE digest NOT IN (
            SELECT row_template_digest FROM bash_view_records
            UNION
            SELECT page_template_digest FROM bash_view_records
          )
          AND digest NOT IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let params = shipped.iter().map(|digest| digest as &dyn rusqlite::ToSql).collect::<Vec<_>>();
    stmt.execute(rusqlite::params_from_iter(params)).map(|count| count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn assert_tables(conn: &Connection) {
        for table in [
            "bash_view_records",
            "rich_ui_templates",
            "rich_ui_cursor_key",
            "rich_ui_session_presets",
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing {table}");
        }
    }

    #[test]
    fn rich_ui_migration_fresh_database_has_four_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        super::super::run_migrations(&mut conn).unwrap();
        assert_tables(&conn);
        assert_eq!(cursor_key(&conn).len(), 32);
    }

    fn cursor_key(conn: &Connection) -> Vec<u8> {
        conn.query_row("SELECT key FROM rich_ui_cursor_key WHERE id=1", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    #[test]
    fn rich_ui_migration_reapplication_keeps_cursor_key() {
        let mut conn = Connection::open_in_memory().unwrap();
        super::super::run_migrations(&mut conn).unwrap();
        let key = cursor_key(&conn);
        conn.execute_batch(MIGRATION).unwrap();
        assert_eq!(cursor_key(&conn), key);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM rich_ui_cursor_key", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn rich_ui_migration_upgrade_reopen_and_downgrade_fence() {
        use super::super::{run_migrations, run_migrations_supported, CURRENT_SCHEMA_VERSION};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aft.db");
        let previous = CURRENT_SCHEMA_VERSION - 1;
        let mut conn = Connection::open(&path).unwrap();
        run_migrations_supported(&mut conn, previous).unwrap();
        conn.execute(
            "INSERT INTO host_state(key,value,updated_at) VALUES ('upgrade-canary','preserved',1)",
            [],
        )
        .unwrap();
        assert_eq!(run_migrations(&mut conn).unwrap(), CURRENT_SCHEMA_VERSION);
        assert_tables(&conn);
        let key = cursor_key(&conn);
        assert_eq!(key.len(), 32);
        assert_ne!(key, vec![0; 32]);
        drop(conn);

        let mut conn = super::super::open(&path).unwrap();
        let changes = conn.total_changes();
        assert_eq!(run_migrations(&mut conn).unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            conn.total_changes(),
            changes,
            "current-version open must not write"
        );
        assert_eq!(cursor_key(&conn), key);
        let canary: String = conn
            .query_row(
                "SELECT value FROM host_state WHERE key='upgrade-canary'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(canary, "preserved");
        assert!(matches!(
            run_migrations_supported(&mut conn, previous),
            Err(super::super::OpenError::DowngradeRefused { db_version, supported })
                if db_version == CURRENT_SCHEMA_VERSION && supported == previous
        ));
        let mut fresh = Connection::open_in_memory().unwrap();
        run_migrations(&mut fresh).unwrap();
        assert_ne!(
            cursor_key(&fresh),
            key,
            "databases must not share a fixed key"
        );
    }

    #[test]
    fn rich_ui_migration_upgrades_schema_18_without_losing_ledger_migration() {
        let mut conn = Connection::open_in_memory().unwrap();
        super::super::run_migrations_supported(&mut conn, 18).unwrap();
        super::super::run_migrations(&mut conn).unwrap();
        assert_tables(&conn);
        conn.prepare("SELECT tool_result_source FROM call_ledger")
            .unwrap();
    }

    fn key(epoch: u64) -> PresetKey {
        PresetKey {
            project_root: "/project".into(),
            harness: "Raw Harness".into(),
            session: "session".into(),
            principal: "reserved:broca".into(),
            owner: r#"{"kind":"reserved","module_id":"prefrontal-core"}"#.into(),
            scope_ref: "worker".into(),
            epoch,
            preset: "worker".into(),
        }
    }

    #[test]
    fn rich_ui_presets_epochs_are_exact_text_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aft.db");
        let conn = super::super::open(&path).unwrap();
        let epochs = [i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX];
        for epoch in epochs {
            record_preset(&conn, &key(epoch), 1).unwrap();
        }
        drop(conn);
        let conn = super::super::open(&path).unwrap();
        for epoch in epochs {
            let k = key(epoch);
            let stored: (String, String) = conn
                .query_row(
                    "SELECT epoch,typeof(epoch) FROM rich_ui_session_presets WHERE epoch=?1",
                    [epoch.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(stored, (epoch.to_string(), "text".into()));
            assert_eq!(session_presets(&conn, &k).unwrap(), ["worker"]);
            // Other requested boundary epochs are also present. Remove them
            // temporarily to prove each boundary misses both of its neighbours.
            for other in epochs.into_iter().filter(|&other| other != epoch) {
                conn.execute(
                    "DELETE FROM rich_ui_session_presets WHERE epoch=?1",
                    [other.to_string()],
                )
                .unwrap();
            }
            for neighbour in [epoch.checked_sub(1), epoch.checked_add(1)]
                .into_iter()
                .flatten()
            {
                assert!(session_presets(&conn, &key(neighbour)).unwrap().is_empty());
            }
            for other in epochs.into_iter().filter(|&other| other != epoch) {
                record_preset(&conn, &key(other), 1).unwrap();
            }
        }
    }

    #[test]
    fn rich_ui_presets_exact_identity_and_distinct_presets_are_read_only() {
        let mut conn = Connection::open_in_memory().unwrap();
        super::super::run_migrations(&mut conn).unwrap();
        let k = key(7);
        record_preset(&conn, &k, 10).unwrap();
        record_preset(
            &conn,
            &PresetKey {
                preset: "reader".into(),
                ..k.clone()
            },
            20,
        )
        .unwrap();
        let changes = conn.total_changes();
        assert_eq!(session_presets(&conn, &k).unwrap(), ["reader", "worker"]);
        for field in 0..7 {
            let mut wrong = k.clone();
            match field {
                0 => wrong.project_root.push('x'),
                1 => wrong.harness.push('x'),
                2 => wrong.session.push('x'),
                3 => wrong.principal.push('x'),
                4 => wrong.owner.push('x'),
                5 => wrong.scope_ref.push('x'),
                _ => wrong.epoch += 1,
            }
            assert!(
                session_presets(&conn, &wrong).unwrap().is_empty(),
                "field {field}"
            );
        }
        assert_eq!(conn.total_changes(), changes);
    }

    #[test]
    fn rich_ui_presets_retention_tick_removes_only_older_than_thirty_days() {
        let mut conn = Connection::open_in_memory().unwrap();
        super::super::run_migrations(&mut conn).unwrap();
        let now = 40 * 24 * 60 * 60 * 1000;
        let cutoff = now - 30 * 24 * 60 * 60 * 1000;
        record_preset(&conn, &key(1), cutoff - 1).unwrap();
        record_preset(&conn, &key(2), cutoff).unwrap();
        record_preset(&conn, &key(3), now).unwrap();
        super::super::compression_events::prune_retention_tick(&mut conn, now).unwrap();
        assert!(session_presets(&conn, &key(1)).unwrap().is_empty());
        assert_eq!(session_presets(&conn, &key(2)).unwrap(), ["worker"]);
        assert_eq!(session_presets(&conn, &key(3)).unwrap(), ["worker"]);
    }
}
