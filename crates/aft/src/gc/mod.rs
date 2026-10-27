//! Budgeted mark-and-sweep for immutable family blob stores.
//!
//! References from the retained manifests, live assembly pins, and active query
//! read markers are all marked before the budget selects eviction candidates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::params;

use crate::blob_store::BlobPlane;
use crate::pins::{self, PinMetadata};
use crate::root_cache;
use crate::views::reference_sidecar::SortedKeys;

pub mod family;
#[cfg(test)]
mod family_read_tests;

/// Payloads newer than this stay available even when a store is over budget.
pub const BLOB_AGE_FLOOR_MS: u64 = 15 * 60 * 1_000;

#[derive(Debug)]
pub enum SweepError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Pin(pins::PinError),
    Metadata(serde_json::Error),
}

impl fmt::Display for SweepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "GC I/O error: {error}"),
            Self::Sqlite(error) => write!(f, "GC SQLite error: {error}"),
            Self::Pin(error) => write!(f, "GC pin error: {error}"),
            Self::Metadata(error) => write!(f, "GC pin metadata error: {error}"),
        }
    }
}

impl std::error::Error for SweepError {}

impl From<std::io::Error> for SweepError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rusqlite::Error> for SweepError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}
impl From<pins::PinError> for SweepError {
    fn from(error: pins::PinError) -> Self {
        Self::Pin(error)
    }
}
impl From<serde_json::Error> for SweepError {
    fn from(error: serde_json::Error) -> Self {
        Self::Metadata(error)
    }
}

/// References assembled from the current and previous manifests. `generation_keys`
/// additionally lets active query markers protect an otherwise unretained generation.
#[derive(Clone, Debug, Default)]
pub struct SweepReferences {
    pub retained_keys: BTreeSet<[u8; 32]>,
    pub generation_keys: BTreeMap<String, BTreeSet<[u8; 32]>>,
}

#[derive(Clone, Debug)]
pub struct SweepRequest<'a> {
    pub durable_storage: &'a Path,
    pub storage: &'a Path,
    pub family: &'a str,
    pub view_dir: &'a Path,
    pub byte_budget: u64,
    pub now_ms: u64,
    pub references: SweepReferences,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub examined_blobs: usize,
    pub deleted_blobs: usize,
    pub deleted_bytes: u64,
    pub retained_bytes: u64,
    pub protected_pin_keys: usize,
    pub reclaimed_pins: usize,
    pub reclaimed_read_markers: usize,
    pub reclaim_deferred: bool,
    pub space_reclaim: crate::blob_store::reclaim::ReclaimReport,
}

/// Collect unreferenced payloads older than the age floor even below the disk
/// budget. A budget is not a reason to keep unreachable content forever.
pub fn sweep(request: SweepRequest<'_>) -> Result<SweepReport, SweepError> {
    sweep_bounded(request, &|| false)
}

pub(crate) fn sweep_bounded(
    request: SweepRequest<'_>,
    cancelled: &dyn Fn() -> bool,
) -> Result<SweepReport, SweepError> {
    sweep_planes_bounded(
        request,
        cancelled,
        &[BlobPlane::Semantic, BlobPlane::Callgraph],
    )
}

fn sweep_planes_bounded(
    request: SweepRequest<'_>,
    cancelled: &dyn Fn() -> bool,
    planes: &[BlobPlane],
) -> Result<SweepReport, SweepError> {
    sweep_planes_with_sidecars(
        request,
        cancelled,
        planes,
        crate::views::reference_sidecar::global(),
    )
}

fn sweep_planes_with_sidecars(
    request: SweepRequest<'_>,
    cancelled: &dyn Fn() -> bool,
    planes: &[BlobPlane],
    sidecars: &crate::views::reference_sidecar::ReferenceSidecars,
) -> Result<SweepReport, SweepError> {
    // V1 has no reference-epoch handoff, so sweep.lock must exclude pin admission
    // throughout marking, including pins from older binaries. A pending bind
    // cancels maintenance instead of waiting behind the whole mark pass.
    let cancelled_for_bind =
        || cancelled() || crate::storage_retention::bind_pending(request.durable_storage);
    let control = SweepControl {
        deadline: Instant::now() + Duration::from_secs(5),
        cancelled: &cancelled_for_bind,
    };
    control.check()?;
    let roots = crate::root_cache::StoragePaths::new(
        request.durable_storage.to_path_buf(),
        request.storage.to_path_buf(),
    );
    let _barrier = crate::storage_retention::cache_barrier(&roots)?;
    let mut report = SweepReport::default();
    // Choose this pass's candidates first, so marking only has to answer for
    // them: memory stays bounded by the batch rather than by the number of
    // keys every manifest names. The barrier above is held from here through
    // deletion, so no pin can be admitted between the choice and the delete.
    let mut batches = Vec::new();
    for &plane in planes {
        control.check()?;
        let path = plane_path(request.storage, request.family, plane);
        if !path.exists() {
            continue;
        }
        batches.push(PlaneBatch::fetch(
            path,
            request.now_ms,
            &mut report,
            &control,
        )?);
    }
    let mut keys = request.references.retained_keys.clone();
    // Families are shared across checkouts. A one-view mark can delete content
    // still named by a sibling's manifest. Keep every remaining manifest's keys;
    // generation GC removes superseded manifests before this storage-wide pass.
    let views = request.storage.join("views");
    if views.exists() {
        let entries = fs::read_dir(&views)?;
        let entries = entries.take(8193).collect::<Result<Vec<_>, _>>()?;
        if entries.len() > 8192 {
            return Err(std::io::Error::other("blob marking exceeded 8192 views").into());
        }
        for entry in entries {
            control.check()?;
            if !entry.file_type()?.is_dir() || entry.file_name() == "v2" {
                continue;
            }
            let view_dir = entry.path();
            if let Some(store) = crate::views::ViewStore::existing_dir(view_dir.clone()) {
                store
                    .visit_blob_references(sidecars, &mut || control.check(), &mut |_, run| {
                        for batch in &mut batches {
                            control.check()?;
                            batch.candidates.mark_run(run)?;
                        }
                        Ok(())
                    })
                    .map_err(|error| {
                        // Report a deadline hit inside the scan as the sweep's
                        // own cancellation, not as a view error.
                        control
                            .check()
                            .err()
                            .unwrap_or_else(|| std::io::Error::other(error.to_string()))
                    })?;
            }
            // Every generation's keys are already marked above, so a query
            // marker on a sibling generation cannot add anything; the sibling
            // pass still reclaims dead pins and stale read markers. Built field
            // by field: cloning `request` would copy its retained key set once
            // per view.
            let sibling = SweepRequest {
                durable_storage: request.durable_storage,
                storage: request.storage,
                family: request.family,
                view_dir: &view_dir,
                byte_budget: request.byte_budget,
                now_ms: request.now_ms,
                references: SweepReferences::default(),
            };
            mark_live_assembly_pins(&sibling, &mut keys, &mut report)?;
            mark_live_query_pins(&sibling, &mut keys, &mut report);
        }
    }
    mark_live_assembly_pins(&request, &mut keys, &mut report)?;
    mark_live_query_pins(&request, &mut keys, &mut report);
    for batch in &mut batches {
        batch.candidates.mark_set(&keys);
    }
    drop(keys);

    for batch in batches {
        control.check()?;
        batch.delete_unreferenced(&mut report, &control)?;
    }
    drop(_barrier);
    // Reclaim runs outside pin/bind admission; SQLite's own locks protect rows.
    let reclaim_control = SweepControl {
        deadline: Instant::now() + crate::blob_store::reclaim::PASS_BUDGET,
        cancelled,
    };
    for &plane in planes {
        let path = plane_path(request.storage, request.family, plane);
        let id = blake3::hash(path.to_string_lossy().as_bytes()).to_hex();
        let pending = request
            .durable_storage
            .join("retention/vacuum")
            .join(format!("{id}.json"));
        if !path.exists() {
            continue;
        }
        match reclaim_plane(&path, &reclaim_control) {
            Ok(reclaimed) => {
                report.reclaim_deferred |= reclaimed.deferred;
                report.space_reclaim.merge(reclaimed);
                // Old retry markers no longer bypass free-space eligibility.
                let _ = fs::remove_file(pending);
            }
            Err(_) => report.reclaim_deferred = true,
        }
    }
    Ok(report)
}

struct SweepControl<'a> {
    deadline: Instant,
    cancelled: &'a dyn Fn() -> bool,
}

impl SweepControl<'_> {
    fn check(&self) -> std::io::Result<()> {
        if Instant::now() >= self.deadline || (self.cancelled)() {
            Err(std::io::Error::other(
                "blob sweep cancelled or deadline reached",
            ))
        } else {
            Ok(())
        }
    }
}

/// Rows examined per plane and pass.
const BATCH_ROWS: usize = 4096;
/// Keys read from a sorted run per positioned read while walking it.
const RUN_CHUNK: usize = 8192;
/// A run's in-range span up to this many keys (or 64 per candidate, if more)
/// is walked in order; a wider span is binary-searched per candidate instead.
const RUN_WALK_MIN: usize = 65_536;

static CURSORS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<PathBuf, Vec<u8>>>> =
    std::sync::OnceLock::new();

/// One plane's deletion candidates for this pass and which of them some
/// reference protects.
struct PlaneBatch {
    path: PathBuf,
    connection: crate::db::file_identity::IdentityConnection,
    total_bytes: u64,
    /// Where the next pass starts, applied only once this batch is swept so an
    /// aborted pass re-examines the same rows.
    next_cursor: Option<Vec<u8>>,
    /// Old enough to delete, sorted ascending and unique, with their sizes.
    candidates: Candidates,
    bytes: Vec<u64>,
}

/// Sorted, unique deletion candidates and whether a reference protects each.
#[derive(Default)]
struct Candidates {
    keys: Vec<[u8; 32]>,
    referenced: Vec<bool>,
    /// Read buffer reused across runs, at most one chunk long.
    scratch: Vec<[u8; 32]>,
}

impl Candidates {
    fn new(keys: Vec<[u8; 32]>) -> Self {
        Self {
            referenced: vec![false; keys.len()],
            keys,
            scratch: Vec::new(),
        }
    }

    fn mark_set(&mut self, set: &BTreeSet<[u8; 32]>) {
        for (key, referenced) in self.keys.iter().zip(self.referenced.iter_mut()) {
            *referenced |= set.contains(key);
        }
    }

    /// Mark candidates that appear in `run`. Only the part of the run between
    /// the first and last candidate is read.
    fn mark_run(&mut self, run: &dyn SortedKeys) -> std::io::Result<()> {
        let walk_limit = RUN_WALK_MIN.max(self.keys.len().saturating_mul(64));
        self.mark_run_with(run, walk_limit, RUN_CHUNK)
    }

    fn mark_run_with(
        &mut self,
        run: &dyn SortedKeys,
        walk_limit: usize,
        chunk: usize,
    ) -> std::io::Result<()> {
        let Self {
            keys,
            referenced,
            scratch,
        } = self;
        let (Some(&first), Some(&last)) = (keys.first(), keys.last()) else {
            return Ok(());
        };
        let lo = lower_bound(run, 0, run.len(), |key| key < &first)?;
        let hi = lower_bound(run, lo, run.len(), |key| key <= &last)?;
        let span = hi - lo;
        if span <= walk_limit {
            // Walk the run's in-range keys and the candidates together.
            let chunk = chunk.max(1);
            if scratch.len() < span.min(chunk) {
                scratch.resize(span.min(chunk), [0_u8; 32]);
            }
            let mut candidate = 0;
            let mut position = lo;
            while position < hi && candidate < keys.len() {
                let take = (hi - position).min(chunk);
                run.read(position, &mut scratch[..take])?;
                for member in &scratch[..take] {
                    while candidate < keys.len() && keys[candidate] < *member {
                        candidate += 1;
                    }
                    if candidate < keys.len() && keys[candidate] == *member {
                        referenced[candidate] = true;
                    }
                }
                position += take;
            }
        } else {
            for (key, referenced) in keys.iter().zip(referenced.iter_mut()) {
                if !*referenced {
                    let at = lower_bound(run, lo, hi, |member| member < key)?;
                    if at < hi && read_one(run, at)? == *key {
                        *referenced = true;
                    }
                }
            }
        }
        Ok(())
    }
}

impl PlaneBatch {
    fn fetch(
        path: PathBuf,
        now_ms: u64,
        report: &mut SweepReport,
        control: &SweepControl<'_>,
    ) -> Result<Self, SweepError> {
        let connection =
            crate::db::file_identity::IdentityConnection::open(&path, "gc::sweep_plane")?;
        // Install a progress deadline through SQLite's own handle, not a second
        // descriptor or a helper that opens/closes the live file set. SQLite
        // drops the callback when this connection closes, and every batch is
        // dropped before the control it points at.
        unsafe {
            rusqlite::ffi::sqlite3_progress_handler(
                connection.handle(),
                1000,
                Some(abort_sweep),
                (control as *const SweepControl<'_>).cast_mut().cast(),
            );
        }
        let total_bytes = connection.query_row(
            "SELECT COALESCE(SUM(length(payload)), 0) FROM blob_payloads",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        let after = CURSORS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&path)
            .cloned()
            .unwrap_or_default();
        let mut rows = Vec::new();
        {
            let mut statement = connection.prepare(
                "SELECT full_key, length(payload), created_at_ms
                 FROM blob_payloads WHERE full_key > ?1 ORDER BY full_key ASC LIMIT 4096",
            )?;
            let found = statement.query_map(params![after], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })?;
            for row in found {
                let (key, bytes, created_at_ms) = row?;
                let Ok(key) = <Vec<u8> as TryInto<[u8; 32]>>::try_into(key) else {
                    continue;
                };
                rows.push((key, bytes, created_at_ms));
            }
        }
        report.examined_blobs += rows.len();
        let next_cursor = (rows.len() == BATCH_ROWS)
            .then(|| rows.last().map(|(key, _, _)| key.to_vec()))
            .flatten();
        // Young payloads are kept regardless, so only old ones need a reference
        // lookup. Sort explicitly: the lookup walks sorted lists and must not
        // depend on how SQLite ordered the rows.
        let mut eligible: Vec<([u8; 32], u64)> = rows
            .into_iter()
            .filter(|(_, _, created_at_ms)| {
                now_ms.saturating_sub(*created_at_ms) >= BLOB_AGE_FLOOR_MS
            })
            .map(|(key, bytes, _)| (key, bytes))
            .collect();
        eligible.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        eligible.dedup_by(|left, right| left.0 == right.0);
        let (keys, bytes): (Vec<_>, Vec<_>) = eligible.into_iter().unzip();
        Ok(Self {
            path,
            connection,
            total_bytes,
            next_cursor,
            candidates: Candidates::new(keys),
            bytes,
        })
    }

    fn delete_unreferenced(
        self,
        report: &mut SweepReport,
        control: &SweepControl<'_>,
    ) -> Result<(), SweepError> {
        let Self {
            path,
            connection,
            mut total_bytes,
            next_cursor,
            candidates: Candidates {
                keys, referenced, ..
            },
            bytes,
        } = self;
        let tx = rusqlite::Transaction::new_unchecked(
            &connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let mut delete = tx.prepare("DELETE FROM blob_payloads WHERE full_key = ?1")?;
        let mut deleted_blobs = 0;
        let mut deleted_bytes = 0_u64;
        // This reference check is the safety boundary: retained manifests and
        // live pins must win over budget pressure.
        for ((key, bytes), referenced) in keys.into_iter().zip(bytes).zip(referenced) {
            control.check()?;
            if referenced {
                continue;
            }
            #[cfg(test)]
            BEFORE_BLOB_DELETE.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(&connection);
                }
            });
            let deleted = delete.execute(params![key.as_slice()])?;
            if deleted == 1 {
                total_bytes = total_bytes.saturating_sub(bytes);
                deleted_blobs += 1;
                deleted_bytes = deleted_bytes.saturating_add(bytes);
            }
        }
        drop(delete);
        tx.commit()?;
        let mut cursors = CURSORS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match next_cursor {
            Some(cursor) => cursors.insert(path, cursor),
            None => cursors.remove(&path),
        };
        drop(cursors);
        report.deleted_blobs += deleted_blobs;
        report.deleted_bytes = report.deleted_bytes.saturating_add(deleted_bytes);
        report.retained_bytes = report.retained_bytes.saturating_add(total_bytes);
        Ok(())
    }
}

fn read_one(run: &dyn SortedKeys, index: usize) -> std::io::Result<[u8; 32]> {
    let mut key = [[0_u8; 32]; 1];
    run.read(index, &mut key)?;
    Ok(key[0])
}

/// The first index in `lo..hi` whose key does not satisfy `before`, for a
/// predicate that holds on a prefix of the sorted run.
fn lower_bound(
    run: &dyn SortedKeys,
    mut lo: usize,
    mut hi: usize,
    before: impl Fn(&[u8; 32]) -> bool,
) -> std::io::Result<usize> {
    while lo < hi {
        let middle = lo + (hi - lo) / 2;
        if before(&read_one(run, middle)?) {
            lo = middle + 1;
        } else {
            hi = middle;
        }
    }
    Ok(lo)
}

unsafe extern "C" fn abort_sweep(data: *mut std::ffi::c_void) -> std::os::raw::c_int {
    // SQLite invokes this synchronously on the owning connection. The control
    // outlives that connection, and no callback is installed on another handle.
    let control = unsafe { &*(data as *const SweepControl<'_>) };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| control.check())) {
        Ok(Ok(())) => 0,
        _ => 1,
    }
}

fn mark_live_assembly_pins(
    request: &SweepRequest<'_>,
    references: &mut BTreeSet<[u8; 32]>,
    report: &mut SweepReport,
) -> Result<(), SweepError> {
    let pins_dir = request.view_dir.join("pins");
    let entries = match fs::read_dir(&pins_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    for (index, entry) in entries.take(4097).enumerate() {
        if index == 4096 {
            return Err(std::io::Error::other("blob marking exceeded 4096 pins").into());
        }
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let metadata: PinMetadata = match serde_json::from_slice(&fs::read(&path)?) {
            Ok(metadata) => metadata,
            Err(error) => return Err(error.into()),
        };
        if metadata.family != request.family || metadata.view.is_empty() {
            continue;
        }
        let (metadata_path, keys_path) = pins::pin_paths(request.view_dir, &metadata.generation);
        if metadata_path != path {
            continue;
        }
        if !pins::owner_is_live(&metadata.owner) {
            let _ = fs::remove_file(&metadata_path);
            let _ = fs::remove_file(&keys_path);
            report.reclaimed_pins += 1;
            continue;
        }
        let keys = pins::read_keys(&keys_path)?;
        report.protected_pin_keys += keys.len();
        references.extend(keys);
    }
    Ok(())
}

fn mark_live_query_pins(
    request: &SweepRequest<'_>,
    references: &mut BTreeSet<[u8; 32]>,
    report: &mut SweepReport,
) {
    let readers = request.view_dir.join("readers");
    let Ok(entries) = fs::read_dir(readers) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(generation) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let marker_sweep = root_cache::sweep_read_markers(request.view_dir, &generation);
        report.reclaimed_read_markers += marker_sweep.removed_stale;
        if marker_sweep.protected {
            if let Some(keys) = request.references.generation_keys.get(&generation) {
                references.extend(keys.iter().copied());
            }
        }
    }
}

fn reclaim_plane(
    path: &Path,
    control: &SweepControl<'_>,
) -> Result<crate::blob_store::reclaim::ReclaimReport, SweepError> {
    let connection = crate::db::file_identity::IdentityConnection::open(path, "gc::reclaim_plane")?;
    connection.busy_timeout(Duration::from_millis(100))?;
    Ok(crate::blob_store::reclaim::reclaim(
        &connection,
        Some(control.deadline),
        control.cancelled,
    )?)
}

fn plane_path(storage: &Path, family: &str, plane: BlobPlane) -> PathBuf {
    storage
        .join("blobs")
        .join(family)
        .join(format!("{}.sqlite", plane.as_str()))
}

#[cfg(test)]
type BeforeBlobDelete = Box<dyn FnMut(&rusqlite::Connection)>;
#[cfg(test)]
thread_local! {
    static BEFORE_BLOB_DELETE: std::cell::RefCell<Option<BeforeBlobDelete>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod storage_retention_tests {
    use super::*;

    #[test]
    fn candidate_marking_matches_a_plain_union_on_random_runs() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..400 {
            // A narrow key space so runs, candidates and retained keys collide.
            let space = 1 + next() % 400;
            let key = |value: u64| {
                let mut key = [0_u8; 32];
                key[..8].copy_from_slice(&(value % space).to_be_bytes());
                key
            };
            // Alternate between always walking and always binary-searching,
            // with chunk sizes small enough to cross chunk boundaries.
            let walk_limit = if round % 2 == 0 { usize::MAX } else { 0 };
            let chunk = 1 + (next() % 7) as usize;
            let candidate_keys: Vec<[u8; 32]> = (0..next() % 200)
                .map(|_| key(next()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let mut candidates = Candidates::new(candidate_keys.clone());
            let mut union = BTreeSet::new();
            for _ in 0..next() % 6 {
                let run: Vec<[u8; 32]> = (0..next() % 300)
                    .map(|_| key(next()))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                union.extend(run.iter().copied());
                candidates.mark_run_with(&run, walk_limit, chunk).unwrap();
            }
            let retained: BTreeSet<[u8; 32]> = (0..next() % 20).map(|_| key(next())).collect();
            union.extend(retained.iter().copied());
            candidates.mark_set(&retained);
            let expected: Vec<bool> = candidate_keys
                .iter()
                .map(|key| union.contains(key))
                .collect();
            assert_eq!(candidates.referenced, expected, "round {round}");
        }
    }
    #[test]
    fn blob_gc_deletes_a_bounded_batch_in_one_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let path = plane_path(temp.path(), "family", BlobPlane::Callgraph);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection.execute_batch("CREATE TABLE blob_payloads (full_key BLOB PRIMARY KEY, payload BLOB, created_at_ms INTEGER)").unwrap();
            for key in [[1_u8; 32], [2_u8; 32], [3_u8; 32]] {
                connection
                    .execute(
                        "INSERT INTO blob_payloads VALUES (?1, X'01020304', 0)",
                        params![key.as_slice()],
                    )
                    .unwrap();
            }
        }
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let hook_calls = calls.clone();
        BEFORE_BLOB_DELETE.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |connection| {
                assert!(
                    !connection.is_autocommit(),
                    "collector is deleting with per-row autocommit"
                );
                hook_calls.set(hook_calls.get() + 1);
            }))
        });
        let report = sweep(SweepRequest {
            durable_storage: temp.path(),
            storage: temp.path(),
            family: "family",
            view_dir: &temp.path().join("view"),
            byte_budget: 1024,
            now_ms: BLOB_AGE_FLOOR_MS + 1,
            references: SweepReferences {
                retained_keys: BTreeSet::from([[1_u8; 32]]),
                ..Default::default()
            },
        })
        .unwrap();
        BEFORE_BLOB_DELETE.with(|slot| slot.borrow_mut().take());
        assert_eq!(calls.get(), 2);
        assert_eq!(report.deleted_blobs, 2);
        assert_eq!(report.deleted_bytes, 8);
        assert_eq!(report.retained_bytes, 4);
    }

    #[test]
    fn storage_retention_blob_gc_yields_to_waiting_bind() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("retention")).unwrap();
        let _pending = crate::fs_lock::try_acquire(
            &temp.path().join("retention/bind-pending.lock"),
            Duration::ZERO,
        )
        .unwrap();
        let error = sweep(SweepRequest {
            durable_storage: temp.path(),
            storage: temp.path(),
            family: "family",
            view_dir: &temp.path().join("view"),
            byte_budget: 1024,
            now_ms: BLOB_AGE_FLOOR_MS + 1,
            references: SweepReferences::default(),
        })
        .unwrap_err();
        assert!(matches!(error, SweepError::Io(_)), "{error}");
        assert_eq!(
            error.to_string(),
            "GC I/O error: blob sweep cancelled or deadline reached"
        );
    }

    #[test]
    fn storage_retention_collects_unreferenced_blobs_below_budget() {
        let temp = tempfile::tempdir().unwrap();
        let path = plane_path(temp.path(), "family", BlobPlane::Callgraph);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TABLE blob_payloads (full_key BLOB PRIMARY KEY, payload BLOB, created_at_ms INTEGER);").unwrap();
        for key in [[1_u8; 32], [2_u8; 32]] {
            connection
                .execute(
                    "INSERT INTO blob_payloads VALUES (?1, X'01020304', 0)",
                    params![key.as_slice()],
                )
                .unwrap();
        }
        drop(connection);
        let report = sweep(SweepRequest {
            durable_storage: temp.path(),
            storage: temp.path(),
            family: "family",
            view_dir: &temp.path().join("view"),
            byte_budget: 1024,
            now_ms: BLOB_AGE_FLOOR_MS + 1,
            references: SweepReferences {
                retained_keys: BTreeSet::from([[1_u8; 32]]),
                ..Default::default()
            },
        })
        .unwrap();
        assert_eq!(report.deleted_blobs, 1);
        assert_eq!(report.deleted_bytes, 4);
        let connection = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT hex(full_key) FROM blob_payloads", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "01".repeat(32)
        );
    }
    #[test]
    fn storage_retention_blob_mark_includes_sibling_manifests() {
        let temp = tempfile::tempdir().unwrap();
        let path = plane_path(temp.path(), "family", BlobPlane::Callgraph);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TABLE blob_payloads (full_key BLOB PRIMARY KEY, payload BLOB, created_at_ms INTEGER);").unwrap();
        connection
            .execute(
                "INSERT INTO blob_payloads VALUES (?1, X'01020304', 0)",
                params![[3_u8; 32].as_slice()],
            )
            .unwrap();
        drop(connection);
        let sibling = crate::views::ViewStore::open(temp.path(), "0123456789abcdef").unwrap();
        let manifest = crate::views::Manifest::new([(
            crate::views::RelPath::new(b"file.rs".to_vec()).unwrap(),
            crate::views::ManifestEntry::Regular {
                mode: 0o100644,
                resolution_input: true,
                planes: crate::views::RegularPlanes {
                    semantic: None,
                    callgraph: Some("03".repeat(32)),
                },
            },
        )])
        .unwrap();
        fs::write(
            sibling.manifest_path("current").unwrap(),
            manifest.to_json_bytes().unwrap(),
        )
        .unwrap();
        let report = sweep(SweepRequest {
            durable_storage: temp.path(),
            storage: temp.path(),
            family: "family",
            view_dir: &temp.path().join("requesting-view"),
            byte_budget: 0,
            now_ms: BLOB_AGE_FLOOR_MS + 1,
            references: Default::default(),
        })
        .unwrap();
        assert_eq!(report.deleted_blobs, 0);
        let connection = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM blob_payloads", [], |row| row
                    .get::<_, i32>(0))
                .unwrap(),
            1
        );
    }

    fn one_key_manifest(key: u8) -> Vec<u8> {
        crate::views::Manifest::new([(
            crate::views::RelPath::new(b"file.rs".to_vec()).unwrap(),
            crate::views::ManifestEntry::Regular {
                mode: 0o100644,
                resolution_input: true,
                planes: crate::views::RegularPlanes {
                    semantic: None,
                    callgraph: Some(format!("{key:02x}").repeat(32)),
                },
            },
        )])
        .unwrap()
        .to_json_bytes()
        .unwrap()
    }

    #[test]
    fn storage_retention_sidecar_marking_follows_replacement_and_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let path = plane_path(temp.path(), "family", BlobPlane::Callgraph);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TABLE blob_payloads (full_key BLOB PRIMARY KEY, payload BLOB, created_at_ms INTEGER);").unwrap();
        drop(connection);
        let insert = |key: u8| {
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute(
                    "INSERT OR IGNORE INTO blob_payloads VALUES (?1, X'01020304', 0)",
                    params![[key; 32].as_slice()],
                )
                .unwrap();
        };
        let remaining = || -> Vec<u8> {
            let connection = rusqlite::Connection::open(&path).unwrap();
            let mut statement = connection
                .prepare("SELECT full_key FROM blob_payloads ORDER BY full_key")
                .unwrap();
            let keys = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|key| key.unwrap()[0])
                .collect();
            keys
        };
        let sibling = crate::views::ViewStore::open(temp.path(), "0123456789abcdef").unwrap();
        let manifest = sibling.manifest_path("current").unwrap();
        let sidecar = sibling.view_dir().join("manifest-current.keys");
        let staging = sibling.view_dir().join("staging.tmp");
        fs::write(&staging, one_key_manifest(3)).unwrap();
        fs::rename(&staging, &manifest).unwrap();
        // No settle window, so a manifest written by the test can get a sidecar.
        let sidecars = crate::views::reference_sidecar::ReferenceSidecars::new(Duration::ZERO);
        let run = || {
            sweep_planes_with_sidecars(
                SweepRequest {
                    durable_storage: temp.path(),
                    storage: temp.path(),
                    family: "family",
                    view_dir: &temp.path().join("requesting-view"),
                    byte_budget: 0,
                    now_ms: BLOB_AGE_FLOOR_MS + 1,
                    references: Default::default(),
                },
                &|| false,
                &[BlobPlane::Callgraph],
                &sidecars,
            )
            .unwrap()
        };
        // The first pass decodes the JSON and writes the sidecar; the second
        // reads only the sidecar and must still protect the referenced blob.
        for _ in 0..2 {
            insert(3);
            insert(4);
            run();
            assert_eq!(remaining(), [3]);
            assert!(sidecar.is_file());
        }
        // Same name, same size, new file: the old sidecar no longer applies.
        fs::write(&staging, one_key_manifest(4)).unwrap();
        fs::rename(&staging, &manifest).unwrap();
        insert(3);
        insert(4);
        run();
        assert_eq!(remaining(), [4]);
        // Damage the stored key in place, keeping the length: the sweep must
        // re-derive the keys rather than treat the generation as empty.
        let mut bytes = fs::read(&sidecar).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&sidecar, &bytes).unwrap();
        insert(3);
        insert(4);
        run();
        assert_eq!(remaining(), [4]);
        assert_ne!(fs::read(&sidecar).unwrap(), bytes, "sidecar rewritten");
    }

    #[test]
    fn storage_retention_blob_deletion_keeps_legacy_free_pages_reusable() {
        let temp = tempfile::tempdir().unwrap();
        let path = plane_path(temp.path(), "family", BlobPlane::Callgraph);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TABLE blob_payloads (full_key BLOB PRIMARY KEY, payload BLOB, created_at_ms INTEGER);").unwrap();
        connection
            .execute(
                "INSERT INTO blob_payloads VALUES (?1, zeroblob(1048576), 0)",
                params![[4_u8; 32].as_slice()],
            )
            .unwrap();
        drop(connection);
        let before = fs::metadata(&path).unwrap().len();
        let report = sweep(SweepRequest {
            durable_storage: temp.path(),
            storage: temp.path(),
            family: "family",
            view_dir: &temp.path().join("requesting-view"),
            byte_budget: 0,
            now_ms: BLOB_AGE_FLOOR_MS + 1,
            references: Default::default(),
        })
        .unwrap();
        assert_eq!(report.deleted_blobs, 1);
        assert!(!report.reclaim_deferred);
        assert_eq!(report.space_reclaim.legacy_stores, 1);
        assert_eq!(report.space_reclaim.reclaimed_pages, 0);
        assert_eq!(fs::metadata(path).unwrap().len(), before);
    }
}
