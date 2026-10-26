use super::*;
use crate::callgraph_store::CallGraphStore;

fn fixture(files: &[(&str, &str)]) -> (tempfile::TempDir, CallGraphStore) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let mut paths = Vec::new();
    for (file, source) in files {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, source).unwrap();
        paths.push(path);
    }
    let store = CallGraphStore::open(temp.path().join("store"), root).unwrap();
    store.cold_build(&paths).unwrap();
    (temp, store)
}

fn callers(store: &CallGraphStore, file: &str, symbol: &str, tests: bool) -> String {
    let result = callers_result(store, Path::new(file), symbol, 5, tests).unwrap();
    crate::subc_format::format_callgraph("callers", &serde_json::to_value(result).unwrap(), false)
}

fn impact(store: &CallGraphStore, file: &str, symbol: &str, tests: bool) -> String {
    let result = impact_result(store, Path::new(file), symbol, 5, tests).unwrap();
    crate::subc_format::format_callgraph("impact", &serde_json::to_value(result).unwrap(), false)
}

#[test]
fn callgraph_callback_references_are_labelled_in_ts_js_and_rust() {
    for (file, source, entry) in [
        (
            "main.ts",
            "function transform() {}\nfunction process() { items.map(transform); }\n",
            "",
        ),
        (
            "main.js",
            "function transform() {}\nfunction process() { items.map(transform); }\n",
            "",
        ),
        (
            "lib.rs",
            "fn transform() {}\nfn process() { spawn(transform); }\n",
            "",
        ),
    ] {
        let (_temp, store) = fixture(&[(file, source)]);
        assert_eq!(
            callers(&store, file, "transform", false),
            format!(
                "1 caller dependency · 1 file group\n{file}\n  ↳ process:2 (callback reference)"
            )
        );
        assert_eq!(impact(&store, file, "transform", false), format!("1 affected dependency site · 1 file\n{file}:2\n  ↳ process{entry} (callback reference)\n  {}", source.lines().nth(1).unwrap()));
        let tree = call_tree_result(&store, Path::new(file), "process", 3, false).unwrap();
        let text = crate::subc_format::format_callgraph(
            "call_tree",
            &serde_json::to_value(tree).unwrap(),
            true,
        );
        assert!(
            !text.contains("↳ transform"),
            "references must not become invocations: {text}"
        );
        let reverse_trace =
            trace_to_result(&store, Path::new(file), "transform", 5, false).unwrap();
        assert!(reverse_trace.paths.is_empty());
    }
}

#[test]
fn callgraph_callback_import_alias_arrow_and_direct_call_stay_distinct() {
    let (_temp, store) = fixture(&[("helper.ts", "export function transform() {}\n"), ("main.ts", "import { transform as callback } from './helper';\nfunction process() { items.map(callback); callback(); }\n")]);
    assert_eq!(callers(&store, "helper.ts", "transform", false), "2 caller dependencies · 1 file group\nmain.ts\n  ↳ process:2\n  ↳ process:2 (callback reference)");
    let (_temp, store) = fixture(&[(
        "main.ts",
        "const transform = () => 1;\nfunction process() { items.map(transform); }\n",
    )]);
    assert_eq!(
        callers(&store, "main.ts", "transform", false),
        "1 caller dependency · 1 file group\nmain.ts\n  ↳ process:2 (callback reference)"
    );
    let (_temp, store) = fixture(&[(
        "main.ts",
        "function transform() {}\nfunction process(transform) { items.map(transform); }\n",
    )]);
    let result = callers_result(&store, Path::new("main.ts"), "transform", 5, false).unwrap();
    assert!(
        result.callers.is_empty(),
        "a parameter must not bind to the same-named function"
    );
}

#[test]
fn callgraph_construction_targets_only_explicit_constructor_and_method_owner() {
    for file in ["main.ts", "main.js"] {
        let source = "function helper() {}\nfunction ctorHelper() {}\nclass Service {\n  constructor() { ctorHelper(); }\n  step() { helper(); }\n}\nclass Empty { step() { helper(); } }\nfunction make() { new Service(); new Empty(); }\n";
        let (_temp, store) = fixture(&[(file, source)]);
        assert_eq!(
            callers(&store, file, "Service::constructor", false),
            format!("1 caller · 1 file group\n{file}\n  ↳ make:8")
        );
        assert_eq!(impact(&store, file, "ctorHelper", false), format!("2 affected call sites · 1 file\n{file}:4\n  ↳ Service::constructor\n  constructor() {{ ctorHelper(); }}\n{file}:8\n  ↳ make\n  function make() {{ new Service(); new Empty(); }}"));
        assert_eq!(
            callers(&store, file, "Empty", false),
            "0 callers · 0 file groups"
        );
        assert_eq!(
            callers(&store, file, "helper", false),
            format!("2 callers · 1 file group\n{file}\n  ↳ Empty::step:7\n  ↳ Service::step:5")
        );
        assert_eq!(impact(&store, file, "helper", false), format!("2 affected call sites · 1 file\n{file}:5\n  ↳ Service::step\n  step() {{ helper(); }}\n{file}:7\n  ↳ Empty::step\n  class Empty {{ step() {{ helper(); }} }}"));
    }
    let (_temp, store) = fixture(&[("lib.rs", "fn helper() {}\nstruct Service;\nimpl Service {\n fn new() -> Self { Service }\n fn step() { helper(); }\n}\nfn make() { Service::new(); }\n")]);
    assert_eq!(
        callers(&store, "lib.rs", "Service::new", false),
        "1 caller · 1 file group\nlib.rs\n  ↳ make:7"
    );
    assert_eq!(
        impact(&store, "lib.rs", "helper", false),
        "1 affected call site · 1 file\nlib.rs:5\n  ↳ Service::step\n  fn step() { helper(); }"
    );
}

#[test]
fn callgraph_zero_callers_discloses_unresolved_sites_but_clean_zero_stays_clean() {
    let (_temp, store) = fixture(&[(
        "main.ts",
        "function onlyB() {}\nconst m = { b: onlyB };\nfunction dynamic() { m['b'](); }\n",
    )]);
    assert_eq!(callers(&store, "main.ts", "onlyB", false), "Incomplete: 1 unresolved call site in the analyzed TypeScript scope could not be resolved; dynamic or indirect calls may target `onlyB`. Zero statically linked callers is not proof of no callers.\n0 callers · 0 file groups");
    let (_temp, store) = fixture(&[("main.ts", "function unused() {}\n")]);
    assert_eq!(
        callers(&store, "main.ts", "unused", false),
        "0 callers · 0 file groups"
    );
}

#[test]
fn callgraph_rust_inline_tests_are_hidden_per_item_including_nested_modules() {
    let source = "fn production() {}\nfn live() { production(); }\n#[test]\nfn standalone() { production(); }\n#[cfg(test)]\nmod tests {\n fn support() { super::production(); }\n mod nested { fn check() { crate::production(); } }\n}\n";
    let (_temp, store) = fixture(&[
        ("src/lib.rs", source),
        (
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
    ]);
    assert_eq!(callers(&store, "src/lib.rs", "production", false), "1 caller · 1 file group\nsrc/lib.rs\n  ↳ live:2\n3 callers in tests hidden — includeTests: true shows them");
    assert_eq!(callers(&store, "src/lib.rs", "production", true), "4 callers · 1 file group\nsrc/lib.rs\n  ↳ live:2\n  ↳ standalone:4\n  ↳ tests::nested::check:8\n  ↳ tests::support:7");
    assert_eq!(impact(&store, "src/lib.rs", "production", false), "1 affected call site · 1 file\nsrc/lib.rs:2\n  ↳ live\n  fn live() { production(); }\n3 callers in tests hidden — includeTests: true shows them");
    assert_eq!(impact(&store, "src/lib.rs", "production", true), "4 affected call sites · 1 file\nsrc/lib.rs:2\n  ↳ live\n  fn live() { production(); }\nsrc/lib.rs:4\n  ↳ standalone\n  fn standalone() { production(); }\nsrc/lib.rs:7\n  ↳ tests::support\n  fn support() { super::production(); }\nsrc/lib.rs:8\n  ↳ tests::nested::check\n  mod nested { fn check() { crate::production(); } }");
}

#[test]
fn callgraph_unknown_rust_test_status_is_disclosed_not_guessed() {
    let (_temp, store) = fixture(&[(
        "lib.rs",
        "fn target() {}\nfn caller() { target(); }\nfn broken(\n",
    )]);
    assert_eq!(callers(&store, "lib.rs", "target", false), "Test filtering incomplete: test-ness could not be determined for 1 caller site; they remain visible.\n1 caller · 1 file group\nlib.rs\n  ↳ caller:2");
    assert_eq!(impact(&store, "lib.rs", "target", false), "Test filtering incomplete: test-ness could not be determined for 1 caller site; they remain visible.\n1 affected call site · 1 file\nlib.rs:2\n  ↳ caller\n  fn caller() { target(); }");
}
