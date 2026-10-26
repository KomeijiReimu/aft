use aft::config::Config;
use aft::lsp::manager::LspManager;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fresh_git_worktree_produces_typescript_diagnostics_without_installing() {
    // Opt into real-server coverage with an externally installed npm bin directory.
    // Normal test runs still exercise SDK selection without network or Node.
    let Some(bin) = std::env::var_os("AFT_TEST_LSP_BIN_DIR").map(PathBuf::from) else {
        eprintln!("SKIP fresh_git_worktree_produces_typescript_diagnostics_without_installing: AFT_TEST_LSP_BIN_DIR not set (requires typescript-language-server and typescript)");
        return;
    };
    if !Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("SKIP fresh_git_worktree_produces_typescript_diagnostics_without_installing: node unavailable");
        return;
    }
    assert!(
        bin.join("typescript-language-server").is_file(),
        "server missing from explicit test bin directory"
    );
    let temp = tempfile::tempdir().unwrap();
    let main = temp.path().join("main");
    let fresh = temp.path().join("fresh");
    std::fs::create_dir(&main).unwrap();
    git(&main, &["init", "-q"]);
    std::fs::write(
        main.join("package.json"),
        r#"{"devDependencies":{"typescript":"5.9.3","@biomejs/biome":"2.2.4"}}"#,
    )
    .unwrap();
    std::fs::write(main.join("tsconfig.json"), "{}").unwrap();
    std::fs::write(main.join("index.ts"), "const value: number = 'wrong';\n").unwrap();
    git(&main, &["add", "."]);
    git(
        &main,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    git(&main, &["worktree", "add", "-q", fresh.to_str().unwrap()]);
    let fresh = fresh.canonicalize().unwrap();
    let file = fresh.join("index.ts");
    let mut before: Vec<_> = std::fs::read_dir(&fresh)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let config = Config {
        project_root: Some(fresh.clone()),
        lsp_paths_extra: vec![bin],
        ..Config::default()
    };
    let mut manager = LspManager::new();
    crate::test_helpers::settled_lsp(&mut manager, |startup_manager| {
        startup_manager.ensure_file_open(&file, &config)
    })
    .unwrap();
    manager.wait_for_diagnostics(&file, &config, Duration::from_secs(15));
    let diagnostics = manager.get_diagnostics_for_file(&file);
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("not assignable to type 'number'")),
        "expected TS2322, got {diagnostics:?}"
    );
    let notes = manager.runtime_notes();
    assert!(
        notes
            .iter()
            .any(|n| n.contains("not the project's pinned TypeScript")),
        "{notes:?}"
    );
    manager.shutdown_all();
    let mut after: Vec<_> = std::fs::read_dir(&fresh)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    before.sort();
    after.sort();
    assert_eq!(before, after);
    assert!(!fresh.join("node_modules").exists());
    let status = Command::new("git")
        .current_dir(&fresh)
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(
        status.stdout.is_empty(),
        "worktree modified: {}",
        String::from_utf8_lossy(&status.stdout)
    );
}
