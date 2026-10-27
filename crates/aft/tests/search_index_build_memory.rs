//! Peak heap of a cold trigram build, per file.
//!
//! The text index's posting records are spilled to disk under a fixed budget,
//! so what grows with the number of files is the file table and every copy of
//! the file paths the build holds while it runs. An earlier measurement on a
//! root with a million files found about 1.7 KB per file at publish, because
//! the build held the walked path list, the file table, the path lookup, full
//! clones of both for the cache writer, and the cache header as one buffer.
//!
//! This test builds a 250,000-file root and pins the peak live heap during
//! the build, per file. A counting global allocator in this test binary
//! measures live bytes exactly (allocations minus frees, across every thread,
//! including the build's worker pool), so the figure does not depend on the
//! operating system's page accounting or on timing. The binary holds only
//! this test, so no other test's allocations are counted.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use aft::search_index::SearchIndex;

const FILES: usize = 250_000;
const FILES_PER_DIR: usize = 20;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

struct PeakAllocator;

fn grow(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

// Live bytes go up on every allocation and down on every free, and the peak
// keeps the highest live total seen since the last reset.
unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
            grow(new_size);
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

/// Twenty small files per leaf directory across three directory levels.
fn write_tree(root: &Path) -> usize {
    let mut path_bytes = 0usize;
    for file in 0..FILES {
        let leaf = file / FILES_PER_DIR;
        let dir = root
            .join(format!("project_directory_{:02}", leaf / 2_500))
            .join(format!("component_module_{:02}", (leaf / 50) % 50))
            .join(format!("feature_package_{:03}", leaf % 50));
        if file % FILES_PER_DIR == 0 {
            std::fs::create_dir_all(&dir).unwrap();
        }
        let path = dir.join(format!("source_file_number_{file:07}.txt"));
        std::fs::write(&path, format!("{file}\n")).unwrap();
        path_bytes += path.as_os_str().len();
    }
    path_bytes
}

#[test]
fn cold_build_peak_heap_per_file_stays_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let path_bytes = write_tree(&root);
    let average_path = path_bytes / FILES;

    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);
    let index = SearchIndex::build_with_limit_to_cache_dir(&root, 1024 * 1024, cache.path());
    let peak = PEAK_BYTES.load(Ordering::Relaxed) - baseline;
    let retained = LIVE_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);
    assert_eq!(index.files.len(), FILES);

    let peak_per_file = peak / FILES;
    let retained_per_file = retained / FILES;
    println!(
        "cold build memory: files={FILES} average_path_bytes={average_path} \
         peak_bytes={peak} peak_per_file={peak_per_file} \
         retained_bytes={retained} retained_per_file={retained_per_file}"
    );

    // What the build may hold per file at its peak: the resident file table
    // and path lookup (two path copies plus about 150 bytes of entries) and
    // the posting records not yet spilled, with room to spare. Holding any
    // further copy of every path, as the build once did up to five times,
    // goes over it.
    let bound = 4 * average_path + 700;
    assert!(
        peak_per_file <= bound,
        "cold build peak {peak_per_file} B/file exceeds {bound} B/file \
         (average path {average_path} B)"
    );
}
