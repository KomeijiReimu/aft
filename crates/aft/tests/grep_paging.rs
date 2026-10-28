//! Paging, output byte budget and long-line handling of the grep tool.
//!
//! With default paging (no `max_results`), a result of at most 100 rows and
//! 16 KiB prints whole. A larger one starts
//! with a files-first summary and a first page of at most 40 rows and 12 KiB;
//! later pages hold up to 100 rows and stop once their rows reach 50 KB, and
//! `offset` fetches them. Lines longer than 500 characters are cut to a
//! window around the match. The limits are written out as literals here so a
//! change to any of them is a visible contract change.

use std::fs;
use std::path::{Path, PathBuf};

use aft::subc_format::{format_response_with_context, FormatContext};
use serde_json::Value;

/// Byte budget for the match rows of a page after the first.
const OUTPUT_BYTES: usize = 51_200;
/// Byte budget for the match rows of a first page.
const FIRST_PAGE_BYTES: usize = 12_288;
/// Characters of a matching line printed before it is cut.
const LINE_CHARS: usize = 500;
/// Marker appended to a cut line.
const LINE_MARKER: &str = "… [line truncated]";

fn grep_ctx(project: &Path) -> aft::context::AppContext {
    let config = aft::config::Config {
        project_root: Some(project.to_path_buf()),
        ..aft::config::Config::default()
    };
    aft::context::AppContext::from_app(
        aft::context::App::default_shared(),
        crate::context_storage::isolate(config),
    )
    .with_test_checkpoint_store()
}

/// Run grep through the command handler and the agent-facing formatter,
/// returning the JSON payload and the text the agent reads.
fn run_grep(ctx: &aft::context::AppContext, params: Value) -> (Value, String) {
    let req = aft::protocol::RawRequest {
        id: "grep-page".into(),
        command: "grep".into(),
        lsp_hints: None,
        session_id: None,
        params,
    };
    let response = aft::commands::grep::handle_grep(&req, ctx);
    assert!(response.success, "grep failed: {:?}", response.data);
    let formatted = format_response_with_context("grep", &response, &FormatContext::default());
    (response.data, formatted)
}

/// Line numbers of the match rows printed in grep text (`<line>: <text>`).
fn printed_lines(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| {
            line.split_once(": ")
                .and_then(|(n, _)| n.parse::<u32>().ok())
        })
        .collect()
}

fn write_needle_file(project: &Path, name: &str, lines: usize, filler: &str) -> PathBuf {
    let path = project.join(name);
    let mut content = String::new();
    for line in 1..=lines {
        content.push_str(&format!("needle {filler} row {line}\n"));
    }
    fs::write(&path, content).expect("write fixture");
    path
}

#[test]
fn grep_single_file_150_matches_pages_by_offset() {
    let project = tempfile::tempdir().expect("tempdir");
    let file = write_needle_file(project.path(), "many.txt", 150, "x");
    let ctx = grep_ctx(project.path());
    let path = file.to_string_lossy().to_string();

    // Page 1: 150 rows do not print whole, so a summary and the first 40.
    let (data, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle", "path": path}));
    let page_one = printed_lines(&text);
    assert_eq!(
        page_one,
        (1..=40).collect::<Vec<u32>>(),
        "page 1 text:\n{text}"
    );
    assert!(
        text.starts_with(
            "150 lines in 1 file match; the first page shows 40. Lines per file:\nmany.txt 150\n"
        ),
        "page 1 text:\n{text}"
    );
    assert_eq!(data["rendered_matches"], 40);
    assert_eq!(data["next_offset"], 40);
    assert!(text.contains("(More lines; continue with offset=40.)"));
    assert!(
        text.ends_with("shown 40 of 150 rows (cap) · narrow: offset, path, include"),
        "page 1 text:\n{text}"
    );

    // Page 2: offset=40 returns the next 100, contiguous with page 1.
    let (data, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "path": path, "offset": 40}),
    );
    assert_eq!(
        printed_lines(&text),
        (41..=140).collect::<Vec<u32>>(),
        "page 2 text:\n{text}"
    );
    assert_eq!(data["next_offset"], 140);
    assert!(!text.contains("Lines per file"), "page 2 text:\n{text}");

    // Page 3: the remaining 10, and offset is no longer a knob.
    let (data, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "path": path, "offset": 140}),
    );
    assert_eq!(
        printed_lines(&text),
        (141..=150).collect::<Vec<u32>>(),
        "page 3 text:\n{text}"
    );
    assert_eq!(data["rendered_matches"], 10);
    assert!(data["next_offset"].is_null());
    assert!(!text.contains("continue with offset"));
    assert!(
        text.ends_with("shown 10 of 150 rows (cap) · narrow: path, include"),
        "page 3 text:\n{text}"
    );
}

#[test]
fn grep_pages_are_disjoint_contiguous_and_in_the_same_order() {
    let project = tempfile::tempdir().expect("tempdir");
    for (i, lines) in [120usize, 90, 40].iter().enumerate() {
        write_needle_file(project.path(), &format!("ordered_{i}.txt"), *lines, "y");
    }
    let ctx = grep_ctx(project.path());

    // One page large enough to hold every match is the reference order:
    // rows dealt round-robin by file.
    let (data, _) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "max_results": 1000}),
    );
    let reference = page_matches(&data);
    assert_eq!(reference.len(), 250);
    let first_three: Vec<u64> = reference.iter().take(3).map(|(_, line)| *line).collect();
    assert_eq!(
        first_three,
        vec![1, 1, 1],
        "round-robin order: {reference:?}"
    );

    // Following next_offset from the first page walks the same order with
    // no row skipped or repeated.
    let mut paged = Vec::new();
    let mut offset = Some(0u64);
    while let Some(current) = offset {
        let (data, _) = run_grep(
            &ctx,
            serde_json::json!({"pattern": "needle", "offset": current}),
        );
        let rendered = data["rendered_matches"].as_u64().expect("rendered") as usize;
        paged.extend(page_matches(&data).into_iter().take(rendered));
        offset = data["next_offset"].as_u64();
    }
    assert_eq!(paged, reference);

    // The same page asked twice comes back identical.
    let again = |offset: u64| {
        run_grep(
            &ctx,
            serde_json::json!({"pattern": "needle", "offset": offset}),
        )
        .1
    };
    assert_eq!(again(15), again(15));
}

#[test]
fn grep_output_byte_cap_stops_the_page_and_is_disclosed() {
    let project = tempfile::tempdir().expect("tempdir");
    // Each row carries 450 two-byte characters (~900 bytes), so both the
    // 12 KiB first page and the 50 KB later pages fill before their row caps.
    let filler = "é".repeat(450);
    let file = write_needle_file(project.path(), "wide.txt", 150, &filler);
    let ctx = grep_ctx(project.path());
    let path = file.to_string_lossy().to_string();

    let (data, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle", "path": path}));
    let rendered = data["rendered_matches"].as_u64().expect("rendered_matches") as usize;
    assert!(rendered > 0 && rendered < 40, "rendered {rendered}");
    assert_eq!(data["output_byte_capped"], true);
    assert_eq!(data["matches"].as_array().expect("matches").len(), 40);
    assert_eq!(printed_lines(&text).len(), rendered);
    let rows_bytes = text
        .split_once("\n\n")
        .map(|(_, rest)| rest.split("\n\nFound ").next().unwrap_or(""))
        .unwrap_or("")
        .len();
    assert!(
        rows_bytes <= FIRST_PAGE_BYTES,
        "rows are {rows_bytes} bytes"
    );
    assert!(text.contains(&format!("(More lines; continue with offset={rendered}.)")));
    assert!(text.ends_with(&format!(
        "shown {rendered} of 150 rows (cap) · narrow: offset, path, include"
    )));

    // The next page starts right after the last printed row and stops at
    // the 50 KB budget.
    let (data, next) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "path": path, "offset": rendered}),
    );
    assert_eq!(
        printed_lines(&next).first().copied(),
        Some(rendered as u32 + 1)
    );
    let second = data["rendered_matches"].as_u64().expect("rendered") as usize;
    assert!(second > rendered && second < 100, "rendered {second}");
    assert_eq!(data["output_byte_capped"], true);
    assert!(
        next.len() < OUTPUT_BYTES + 1024,
        "text is {} bytes",
        next.len()
    );
}

#[test]
fn grep_long_line_is_cut_and_marked() {
    let project = tempfile::tempdir().expect("tempdir");
    let file = project.path().join("long.txt");
    let long_line = format!("needle {}", "z".repeat(800));
    fs::write(&file, format!("{long_line}\nneedle short\n")).expect("write fixture");
    let ctx = grep_ctx(project.path());

    let (data, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "path": file.to_string_lossy()}),
    );
    assert_eq!(data["lines_truncated"], 1);
    let printed = format!("1: {}{}", &long_line[..LINE_CHARS], LINE_MARKER);
    assert!(text.contains(&format!("{printed}\n")), "text:\n{text}");
    assert!(text.contains("2: needle short"));
    // The JSON carries the same cut as the printed row. Keeping a whole
    // multi-megabyte minified line per match is what made grep quadratic on
    // such files, and every renderer prints at most this prefix anyway.
    assert_eq!(
        data["matches"][0]["line_text"],
        format!("{}{}", &long_line[..LINE_CHARS], LINE_MARKER)
    );
}

#[test]
fn grep_search_across_files_pages_exactly() {
    let project = tempfile::tempdir().expect("tempdir");
    for i in 0..3 {
        write_needle_file(project.path(), &format!("part_{i}.txt"), 60, "w");
    }
    let ctx = grep_ctx(project.path());

    // Every match is counted before the page is cut, so the total is exact
    // and the old "pages may overlap or skip rows" warning is gone.
    let (data, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    assert_eq!(data["truncated"], false);
    assert_eq!(data["total_matches"], 180);
    assert!(!text.contains("may overlap or skip rows"), "text:\n{text}");
    assert!(text.ends_with("shown 15 of 180 rows (cap) · narrow: offset, path, include"));

    let (data, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "offset": 100}),
    );
    assert_eq!(data["truncated"], false);
    assert_eq!(data["rendered_matches"], 80);
    assert!(!text.contains("may overlap or skip rows"), "text:\n{text}");
    assert!(text.ends_with("shown 80 of 180 rows (cap) · narrow: path, include"));
}

#[test]
fn grep_offset_past_the_end_says_so() {
    let project = tempfile::tempdir().expect("tempdir");
    let file = write_needle_file(project.path(), "few.txt", 3, "v");
    let ctx = grep_ctx(project.path());

    let (data, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "path": file.to_string_lossy(), "offset": 10}),
    );
    assert_eq!(data["rendered_matches"], 0);
    assert!(text.contains("(offset=10 is past the last match; nothing left to show.)"));
}

// ---------------------------------------------------------------------------
// File kinds, exact counts, round-robin first pages and match windows.
//
// grep prints the lines of source, docs, config and tests, and counts the
// lines of lockfiles, generated and minified files, logs and command output,
// and JSON data files, naming the `path` or `include` value that prints them.
// ---------------------------------------------------------------------------

fn write_file(project: &Path, relative: &str, content: &str) -> PathBuf {
    let path = project.join(relative);
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture folder");
    fs::write(&path, content).expect("write fixture");
    path
}

fn numbered_lines(count: usize, text: &str) -> String {
    (1..=count).map(|n| format!("{text} {n}\n")).collect()
}

/// Rows printed under a file header: `(header, line)` pairs in text order.
/// Headers are returned with `/` separators: grep prints paths with the
/// platform's separator (`\` on Windows), and the tests name files with `/`.
fn printed_rows(text: &str) -> Vec<(String, u32)> {
    let mut rows = Vec::new();
    let mut header: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            header = None;
            continue;
        }
        if let Some((n, _)) = line.split_once(": ") {
            if let (Some(file), Ok(n)) = (&header, n.parse::<u32>()) {
                rows.push((file.clone(), n));
                continue;
            }
        }
        if header.is_none() {
            header = Some(slashed(line));
        }
    }
    rows
}

/// `text` with Windows `\` separators written as `/`, so the paths grep
/// prints compare equal to the `/`-spelled paths the tests expect on every
/// platform.
fn slashed(text: &str) -> String {
    text.replace('\\', "/")
}

/// `(file, line)` of every row in the JSON page, in page order.
fn page_matches(data: &Value) -> Vec<(String, u64)> {
    data["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|m| {
            (
                m["file"].as_str().expect("file").to_string(),
                m["line"].as_u64().expect("line"),
            )
        })
        .collect()
}

#[test]
fn grep_counts_lockfile_lines_and_names_the_path() {
    let project = tempfile::tempdir().expect("tempdir");
    write_file(
        project.path(),
        "tools/pack/bun.lock",
        &numbered_lines(20, "\"pkg\": [\"pkg@1.0.0\", \"\", {}, \"sha512-abc\"],"),
    );
    write_file(
        project.path(),
        "tools/pack/build.mjs",
        "import { sha512 } from './hash.mjs'\nconst digest = sha512(bytes)\n",
    );
    let ctx = grep_ctx(project.path());

    let (data, text) = run_grep(&ctx, serde_json::json!({"pattern": "sha512"}));
    let text = slashed(&text);
    let rows = printed_rows(&text);
    assert_eq!(
        rows,
        vec![
            ("tools/pack/build.mjs".to_string(), 1),
            ("tools/pack/build.mjs".to_string(), 2)
        ],
        "text:\n{text}"
    );
    assert!(
        text.contains(
            "Counted only, not shown: 20 lines in 1 file. To show them, pass a file below as path, or a pattern below as include.\ntools/pack/bun.lock: 20 lines (lockfile)"
        ),
        "text:\n{text}"
    );
    assert!(
        text.contains("Found 22 matches across 2 files"),
        "text:\n{text}"
    );
    assert!(
        text.ends_with("shown 2 of 22 rows (kind) · narrow: path, include"),
        "text:\n{text}"
    );
    assert_eq!(data["total_matches"], 22);
}

#[test]
fn grep_windows_long_line_around_match() {
    let project = tempfile::tempdir().expect("tempdir");
    let line = format!("{}needle{}", "a".repeat(2999), "b".repeat(1000));
    let file = write_file(project.path(), "src/wide.txt", &format!("{line}\n"));
    let ctx = grep_ctx(project.path());

    let (data, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "path": file.to_string_lossy()}),
    );
    // 80 characters lead into the match after a leading ellipsis, and the
    // window ends with the truncation marker.
    let expected = format!(
        "1: …{}needle{}{LINE_MARKER}",
        "a".repeat(80),
        "b".repeat(LINE_CHARS - 1 - 80 - 6)
    );
    assert!(text.contains(&expected), "text:\n{text}");
    assert_eq!(data["lines_truncated"], 1);
}

#[test]
fn grep_total_is_exact_past_the_page() {
    let project = tempfile::tempdir().expect("tempdir");
    for (i, lines) in [100usize, 100, 50].iter().enumerate() {
        write_needle_file(project.path(), &format!("part_{i}.txt"), *lines, "t");
    }
    let ctx = grep_ctx(project.path());

    let (data, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    assert_eq!(data["truncated"], false);
    assert_eq!(data["total_matches"], 250);
    assert!(
        text.contains("Found 250 matches across 3 files"),
        "text:\n{text}"
    );
    assert!(!text.contains("≥"), "text:\n{text}");
    assert!(!text.contains("may overlap or skip rows"), "text:\n{text}");
    let trailer = text.lines().last().expect("trailer");
    assert!(
        trailer.starts_with("shown ") && trailer.contains(" of 250 rows (cap)"),
        "text:\n{text}"
    );
}

#[test]
fn grep_first_page_round_robin_shows_every_file() {
    let project = tempfile::tempdir().expect("tempdir");
    for i in 0..3 {
        write_needle_file(project.path(), &format!("part_{i}.txt"), 60, "r");
    }
    let ctx = grep_ctx(project.path());

    let (data, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    let rows = printed_rows(&text);
    for i in 0..3 {
        let file = format!("part_{i}.txt");
        let lines: Vec<u32> = rows
            .iter()
            .filter(|(header, _)| *header == file)
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(lines, vec![1, 2, 3, 4, 5], "{file} in text:\n{text}");
    }
    assert!(
        text.starts_with("180 lines in 3 files match; the first page shows 15. Lines per file:\n"),
        "text:\n{text}"
    );
    assert!(
        text.contains("(More lines; continue with offset=15.)"),
        "text:\n{text}"
    );
    assert_eq!(data["next_offset"], 15);
}

#[test]
fn grep_path_naming_a_lockfile_prints_its_lines() {
    let project = tempfile::tempdir().expect("tempdir");
    let lock = write_file(
        project.path(),
        "bun.lock",
        &numbered_lines(20, "\"sha512-abc\""),
    );
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "sha512", "path": lock.to_string_lossy()}),
    );
    assert_eq!(printed_rows(&text).len(), 20, "text:\n{text}");
    assert!(!text.contains("Counted only"), "text:\n{text}");
    // Printed because `path` names the file, not as the fallback for a
    // search where only counted kinds matched.
    assert!(!text.contains("(Only "), "text:\n{text}");
}

#[test]
fn grep_include_marker_targets_logs() {
    let project = tempfile::tempdir().expect("tempdir");
    write_file(project.path(), "src/app.ts", "// needle in source\n");
    write_file(
        project.path(),
        "runs/run.log",
        &numbered_lines(20, "needle logged"),
    );
    write_file(
        project.path(),
        "runs/io/stdout",
        &numbered_lines(20, "needle printed"),
    );
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "include": "**/*.ts,*.log"}),
    );
    let rows = printed_rows(&text);
    assert_eq!(
        rows.iter()
            .filter(|(file, _)| file == "runs/run.log")
            .count(),
        20,
        "text:\n{text}"
    );
    assert!(!text.contains("Counted only"), "text:\n{text}");

    let (_, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "include": "**/*.ts,**/stdout"}),
    );
    let rows = printed_rows(&text);
    assert_eq!(
        rows.iter()
            .filter(|(file, _)| file == "runs/io/stdout")
            .count(),
        20,
        "text:\n{text}"
    );
    assert!(!text.contains("Counted only"), "text:\n{text}");

    // A broad pattern does not name the kind, so the log stays counted.
    let (_, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "include": "**/*"}),
    );
    assert!(
        slashed(&text).contains("runs/run.log: 20 lines (log or command output)"),
        "text:\n{text}"
    );
}

#[test]
fn grep_folder_path_does_not_target_captures() {
    let project = tempfile::tempdir().expect("tempdir");
    write_file(project.path(), "research/README.md", "needle explained\n");
    write_file(
        project.path(),
        "research/receipts/stdout",
        &numbered_lines(20, "needle printed"),
    );
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(
        &ctx,
        serde_json::json!({"pattern": "needle", "path": project.path().join("research").to_string_lossy()}),
    );
    let text = slashed(&text);
    assert_eq!(
        printed_rows(&text),
        vec![("research/README.md".to_string(), 1)],
        "text:\n{text}"
    );
    assert!(
        text.contains("research/receipts/stdout: 20 lines (log or command output)"),
        "text:\n{text}"
    );
}

#[test]
fn grep_only_counted_kinds_matched_prints_them() {
    let project = tempfile::tempdir().expect("tempdir");
    write_file(
        project.path(),
        "a/bun.lock",
        &numbered_lines(12, "\"@babel/core@7\""),
    );
    write_file(
        project.path(),
        "b/bun.lock",
        &numbered_lines(12, "\"@babel/core@7\""),
    );
    write_file(
        project.path(),
        "src/app.ts",
        "export const unrelated = 1;\n",
    );
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(&ctx, serde_json::json!({"pattern": "@babel/core@"}));
    assert!(
        text.contains("(Only lockfiles matched, so their lines are shown.)"),
        "text:\n{text}"
    );
    assert!(!text.contains("Counted only"), "text:\n{text}");
    assert_eq!(printed_rows(&text).len(), 24, "text:\n{text}");
}

#[test]
fn grep_too_few_counted_lines_are_printed() {
    let project = tempfile::tempdir().expect("tempdir");
    write_file(
        project.path(),
        "Cargo.toml",
        "tree-sitter-rust = \"0.24\"\n",
    );
    write_file(
        project.path(),
        "Cargo.lock",
        "name = \"tree-sitter-rust\"\n \"tree-sitter-rust\",\n",
    );
    let ctx = grep_ctx(project.path());

    let (data, text) = run_grep(&ctx, serde_json::json!({"pattern": "tree-sitter-rust"}));
    let rows = printed_rows(&text);
    assert_eq!(rows.len(), 3, "text:\n{text}");
    assert!(
        rows.iter().any(|(file, _)| file == "Cargo.lock"),
        "text:\n{text}"
    );
    assert!(!text.contains("Counted only"), "text:\n{text}");
    assert!(data.get("matches_list_envelope").is_none(), "{data:?}");
}

#[test]
fn grep_small_result_prints_whole() {
    let project = tempfile::tempdir().expect("tempdir");
    let files = [
        ("src/a.rs", "fn needle_a() {}\nlet needle = 1;\n"),
        ("src/b.rs", "// needle b\n"),
        ("docs/c.md", "The needle doc.\n"),
    ];
    let now = std::time::SystemTime::now();
    for (index, (relative, content)) in files.iter().enumerate() {
        let path = write_file(project.path(), relative, content);
        // Newest first: a.rs, then b.rs, then c.md.
        let mtime = now - std::time::Duration::from_secs(60 * (index as u64 + 1));
        fs::File::options()
            .write(true)
            .open(&path)
            .expect("open fixture")
            .set_modified(mtime)
            .expect("set mtime");
    }
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    // grep prints paths with the platform's separator.
    #[cfg(windows)]
    assert!(text.starts_with("src\\a.rs\n"), "text:\n{text}");
    let text = slashed(&text);
    let rows_and_footer = text
        .split_once("\n\nFound ")
        .map(|(rows, _)| rows)
        .expect("footer");
    assert_eq!(
        rows_and_footer,
        "src/a.rs\n1: fn needle_a() {}\n2: let needle = 1;\n\nsrc/b.rs\n1: // needle b\n\ndocs/c.md\n1: The needle doc.",
        "text:\n{text}"
    );
    assert!(!text.contains("shown "), "text:\n{text}");
    assert!(!text.contains("Lines per file"), "text:\n{text}");
}

/// Every counted-only row's `path` or `include` value: a pattern after
/// `include `, else the paths a row names.
fn counted_hints(text: &str) -> Vec<String> {
    let Some(block) = text.split("Counted only, not shown:").nth(1) else {
        return Vec::new();
    };
    let mut hints = Vec::new();
    for row in block.lines().skip(1) {
        if row.is_empty() {
            break;
        }
        if let Some((_, include)) = row.split_once("; include ") {
            hints.push(format!("include:{include}"));
        } else if let Some((_, paths)) = row.split_once("; paths ") {
            hints.extend(paths.split(", ").map(|path| format!("path:{path}")));
        } else if !row.starts_with('+') {
            let label = row.split(": ").next().unwrap_or_default();
            hints.push(format!("label:{label}"));
        } else {
            hints.push(format!("bare:{row}"));
        }
    }
    hints
}

/// Files whose lines grep prints when each counted-only hint in `text` is
/// passed back the way the block says: a path as `path`, a pattern as
/// `include`. The hints are passed exactly as printed, so a hint spelled in a
/// form grep cannot take back (for example a `\` path in an include glob on
/// Windows) shows nothing and fails here. Returned paths use `/`.
fn files_shown_by_hints(
    ctx: &aft::context::AppContext,
    text: &str,
) -> std::collections::BTreeSet<String> {
    let mut reached = std::collections::BTreeSet::new();
    for hint in counted_hints(text) {
        let params = if let Some(value) = hint
            .strip_prefix("label:")
            .or_else(|| hint.strip_prefix("path:"))
        {
            if value.contains(['*', '?', '[', '{']) {
                serde_json::json!({"pattern": "needle", "include": value})
            } else {
                serde_json::json!({"pattern": "needle", "path": value})
            }
        } else if let Some(include) = hint.strip_prefix("include:") {
            serde_json::json!({"pattern": "needle", "include": include})
        } else {
            panic!("folded row without a way to show it: {hint}\n{text}");
        };
        let (_, shown) = run_grep(ctx, params);
        let files: std::collections::BTreeSet<String> = printed_rows(&shown)
            .into_iter()
            .map(|(file, _)| file)
            .collect();
        assert!(!files.is_empty(), "{hint} shows nothing:\n{shown}");
        reached.extend(files);
    }
    reached
}

#[test]
fn grep_folded_counted_rows_name_every_file() {
    // Nine generated files (decided by their folder, so no include pattern
    // names them): more than the counted-only block lists one by one.
    let project = tempfile::tempdir().expect("tempdir");
    for index in 0..9 {
        write_file(
            project.path(),
            &format!("pkg{index}/generated/api_{index}.ts"),
            "needle one\nneedle two\n",
        );
    }
    write_file(project.path(), "src/main.ts", "needle main\n");
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    assert!(
        text.contains("Counted only, not shown: 18 lines in 9 files."),
        "text:\n{text}"
    );
    for index in 0..9 {
        assert!(
            slashed(&text).contains(&format!("pkg{index}/generated/api_{index}.ts")),
            "generated file {index} has no path to show it:\n{text}"
        );
    }
    assert!(
        counted_hints(&text)
            .iter()
            .all(|hint| !hint.starts_with("bare:")),
        "a folded row has no path or include:\n{text}"
    );
    let reached = files_shown_by_hints(&ctx, &text);
    for index in 0..9 {
        let file = format!("pkg{index}/generated/api_{index}.ts");
        assert!(reached.contains(&file), "{file} is not reachable:\n{text}");
    }
}

#[test]
fn grep_folded_counted_include_selects_the_folded_files() {
    // Nine rotated logs in separate folders: the folded row's include must
    // select them (`**/*.log` does not match `app.log.1`).
    let project = tempfile::tempdir().expect("tempdir");
    for index in 0..9 {
        write_file(
            project.path(),
            &format!("logs/r{index}/app{index}.log.1"),
            "needle a\nneedle b\n",
        );
    }
    write_file(project.path(), "src/main.ts", "needle main\n");
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    assert!(
        counted_hints(&text)
            .iter()
            .any(|hint| hint.starts_with("include:")),
        "no folded include row:\n{text}"
    );
    let reached = files_shown_by_hints(&ctx, &text);
    for index in 0..9 {
        let log = format!("logs/r{index}/app{index}.log.1");
        assert!(reached.contains(&log), "{log} is not reachable:\n{text}");
    }
}

#[test]
fn grep_counted_folder_include_selects_its_files() {
    // Two JSON-lines captures in one nested folder fold to one
    // `<folder>/*<suffix>` include row; it must select them when passed back,
    // whatever separator the platform prints paths with.
    let project = tempfile::tempdir().expect("tempdir");
    for name in ["a", "b"] {
        write_file(
            project.path(),
            &format!("runs/day1/{name}.jsonl"),
            &numbered_lines(20, "needle record"),
        );
    }
    write_file(project.path(), "src/main.ts", "needle main\n");
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    assert!(
        text.contains("runs/day1/*.jsonl: 40 lines in 2 files (log or command output)"),
        "text:\n{text}"
    );
    let reached = files_shown_by_hints(&ctx, &text);
    for name in ["a", "b"] {
        let file = format!("runs/day1/{name}.jsonl");
        assert!(reached.contains(&file), "{file} is not reachable:\n{text}");
    }
}

#[test]
fn grep_summary_rolls_files_up_under_their_folders() {
    // Sixty files in two folders, more than the summary lists one by one:
    // at least five files of each folder are left for the per-folder
    // roll-up, which must name both folders in grep's own path form
    // (`alpha\one\` on Windows), never put them all under the top folder.
    let project = tempfile::tempdir().expect("tempdir");
    for folder in ["alpha/one", "beta/two"] {
        for index in 0..30 {
            write_file(
                project.path(),
                &format!("{folder}/f{index:02}.txt"),
                &numbered_lines(3, "needle"),
            );
        }
    }
    let ctx = grep_ctx(project.path());

    let (_, text) = run_grep(&ctx, serde_json::json!({"pattern": "needle"}));
    let rollup = text
        .lines()
        .find(|line| line.starts_with("+35 more files (105 lines), files/lines per folder: "))
        .unwrap_or_else(|| panic!("no per-folder roll-up:\n{text}"));
    let separator = std::path::MAIN_SEPARATOR;
    let parts: Vec<&str> = rollup
        .split_once("per folder: ")
        .map(|(_, parts)| parts.split(", ").collect())
        .unwrap_or_default();
    let folders: Vec<&str> = parts
        .iter()
        .filter_map(|part| part.rsplit_once(' ').map(|(folder, _)| folder))
        .collect();
    let mut sorted = folders.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![
            format!("alpha{separator}one{separator}"),
            format!("beta{separator}two{separator}")
        ],
        "roll-up {rollup:?} in text:\n{text}"
    );
    let files: usize = parts
        .iter()
        .filter_map(|part| part.rsplit_once(' '))
        .filter_map(|(_, counts)| counts.split_once('/'))
        .map(|(count, _)| count.parse::<usize>().expect("file count"))
        .sum();
    assert_eq!(files, 35, "roll-up {rollup:?}");
}
