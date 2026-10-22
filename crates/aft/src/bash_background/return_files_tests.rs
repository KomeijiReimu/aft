use super::*;

#[test]
fn requested_paths_are_relative_files_listed_once_and_at_most_64() {
    let paths = |list: &[&str]| list.iter().map(|path| path.to_string()).collect::<Vec<_>>();
    assert_eq!(
        check_requested_paths(&paths(&["out.json", "dist/app.bin"])),
        Ok(())
    );
    let too_many: Vec<String> = (0..=MAX_RETURN_PATHS).map(|n| format!("f{n}")).collect();
    assert_eq!(
        check_requested_paths(&too_many),
        Err("return_paths lists 65 paths; at most 64 are allowed".into())
    );
    let refused = [
        ("/etc/passwd", "must be relative to workdir"),
        ("../outside.txt", "must not use .."),
        ("dist/../../outside.txt", "must not use .."),
        ("dist/", "names a directory"),
        (".", "names a directory"),
        ("", "empty path"),
    ];
    for (path, reason) in refused {
        let error = check_requested_paths(&paths(&[path])).unwrap_err();
        assert!(error.contains(reason), "{path:?}: {error}");
    }
    assert_eq!(
        check_requested_paths(&paths(&["a.txt", "a.txt"])),
        Err("return_paths lists a.txt twice".into())
    );
}

#[test]
fn report_lists_each_path_once_with_its_size_or_reason() {
    let report = render_report(&[
        ReturnedPath {
            path: "dist/app.bin".into(),
            outcome: ReturnOutcome::Returned { bytes: 430_112 },
        },
        ReturnedPath {
            path: "dist/one.txt".into(),
            outcome: ReturnOutcome::Returned { bytes: 1 },
        },
        ReturnedPath {
            path: "dist/absent.txt".into(),
            outcome: ReturnOutcome::NotReturned {
                reason: NotReturned::Runner {
                    cause: "missing".into(),
                },
            },
        },
        ReturnedPath {
            path: "dist/large.bin".into(),
            outcome: ReturnOutcome::NotReturned {
                reason: NotReturned::Runner {
                    cause: "over_cap".into(),
                },
            },
        },
    ]);
    assert_eq!(
        report,
        "Files requested back from the server (return_paths):\n  \
         dist/app.bin: returned (430112 bytes)\n  \
         dist/one.txt: returned (1 byte)\n  \
         dist/absent.txt: not returned (no such file on the server)\n  \
         dist/large.bin: not returned (it would take the total past the 10 MiB limit)"
    );
}

#[cfg(unix)]
mod receiving {
    use super::super::*;
    use crate::exec_remote::return_vectors::{
        return_vector, return_vector_paths, return_vector_records, RETURN_VECTORS,
    };
    use crate::exec_remote::types::StreamRecord;
    use base64::Engine;
    use std::fs;
    use std::path::Path;

    /// Feed a vector's returned-file records to a receiver rooted at `root`.
    fn receive(name: &str, root: &Path) -> Vec<ReturnedPath> {
        let vector = return_vector(name);
        let cap = vector["cap_bytes"].as_u64().unwrap();
        let mut receiver =
            ReturnReceiver::new(return_vector_paths(name), cap, root, root, "task-1").unwrap();
        for record in return_vector_records(name) {
            match record {
                StreamRecord::ReturnChunk(chunk) => receiver.chunk(&chunk),
                StreamRecord::ReturnManifest(manifest) => return receiver.manifest(&manifest),
                _ => {}
            }
        }
        panic!("{name} has no manifest")
    }

    /// Every file under `root`, relative to it, sorted.
    fn files_under(root: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            for entry in fs::read_dir(directory).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let relative = path.strip_prefix(root).unwrap();
                    found.push(relative.to_string_lossy().into_owned());
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn published_vectors_place_exactly_the_verified_files() {
        for (name, _, _) in RETURN_VECTORS {
            let dir = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(dir.path()).unwrap();
            let report = receive(name, &root);
            let vector = return_vector(name);
            let expect = &vector["expect"];
            let mut expected_files = Vec::new();
            if let Some(code) = expect["error"]["code"].as_str() {
                for entry in &report {
                    assert_eq!(
                        entry.outcome,
                        ReturnOutcome::NotReturned {
                            reason: NotReturned::Unverified { code: code.into() }
                        },
                        "{name}"
                    );
                }
            } else {
                for (entry, expected) in report.iter().zip(expect["files"].as_array().unwrap()) {
                    assert_eq!(entry.path, expected["path"].as_str().unwrap(), "{name}");
                    if let Some(cause) = expected["cause"].as_str() {
                        assert_eq!(
                            entry.outcome,
                            ReturnOutcome::NotReturned {
                                reason: NotReturned::Runner {
                                    cause: cause.into()
                                }
                            },
                            "{name}"
                        );
                        continue;
                    }
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(expected["data"].as_str().unwrap())
                        .unwrap();
                    assert_eq!(
                        entry.outcome,
                        ReturnOutcome::Returned {
                            bytes: data.len() as u64
                        },
                        "{name}"
                    );
                    assert_eq!(fs::read(root.join(&entry.path)).unwrap(), data, "{name}");
                    expected_files.push(entry.path.clone());
                }
                assert_eq!(report.len(), expect["files"].as_array().unwrap().len());
            }
            expected_files.sort();
            // Nothing else is left behind: no failed path and no staging file.
            assert_eq!(files_under(&root), expected_files, "{name}");
        }
    }

    #[test]
    fn digest_mismatch_writes_nothing_and_keeps_the_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir(root.join("dist")).unwrap();
        fs::write(root.join("dist/app.bin"), b"older build").unwrap();
        let report = receive("refuse-digest-mismatch", &root);
        assert_eq!(
            report[0].outcome,
            ReturnOutcome::NotReturned {
                reason: NotReturned::Unverified {
                    code: "digest_mismatch".into()
                }
            }
        );
        assert_eq!(fs::read(root.join("dist/app.bin")).unwrap(), b"older build");
        assert_eq!(files_under(&root), ["dist/app.bin"]);
    }

    #[test]
    fn over_cap_path_writes_nothing_beside_a_returned_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir(root.join("dist")).unwrap();
        fs::write(root.join("dist/large.bin"), b"kept").unwrap();
        let report = receive("failed-over-cap", &root);
        assert_eq!(report[0].outcome, ReturnOutcome::Returned { bytes: 5 });
        assert_eq!(
            report[1].outcome,
            ReturnOutcome::NotReturned {
                reason: NotReturned::Runner {
                    cause: "over_cap".into()
                }
            }
        );
        assert_eq!(fs::read(root.join("dist/hello.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(root.join("dist/large.bin")).unwrap(), b"kept");
    }

    #[test]
    fn read_error_after_chunks_writes_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let report = receive("read-error-after-chunks", &root);
        assert_eq!(
            report[0].outcome,
            ReturnOutcome::NotReturned {
                reason: NotReturned::Runner {
                    cause: "read_error".into()
                }
            }
        );
        assert_eq!(files_under(&root), ["dist/ok.txt"]);
    }

    #[test]
    fn symlinked_parent_leading_out_of_the_project_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let root = base.join("project");
        let outside = base.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("dist")).unwrap();
        // The runner reports both files as returned and verified.
        let report = receive("two-files-one-empty", &root);
        for entry in &report {
            assert_eq!(
                entry.outcome,
                ReturnOutcome::NotReturned {
                    reason: NotReturned::OutsideProject
                },
                "{}",
                entry.path
            );
        }
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert_eq!(files_under(&root), Vec::<String>::new());
    }

    #[test]
    fn symlinked_file_leading_out_of_the_project_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let root = base.join("project");
        let outside = base.join("outside.txt");
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::write(&outside, b"not ours").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("dist/hello.txt")).unwrap();
        let report = receive("two-files-one-empty", &root);
        assert_eq!(
            report[0].outcome,
            ReturnOutcome::NotReturned {
                reason: NotReturned::OutsideProject
            }
        );
        // The other path does not go through the link and is placed.
        assert_eq!(report[1].outcome, ReturnOutcome::Returned { bytes: 0 });
        assert_eq!(fs::read(&outside).unwrap(), b"not ours");
        assert!(fs::symlink_metadata(root.join("dist/hello.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn a_job_without_a_manifest_returns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let name = "failed-missing";
        let mut receiver =
            ReturnReceiver::new(return_vector_paths(name), 1 << 20, &root, &root, "task-1")
                .unwrap();
        for record in return_vector_records(name) {
            if let StreamRecord::ReturnChunk(chunk) = record {
                receiver.chunk(&chunk);
            }
        }
        let report = receiver.without_manifest();
        assert!(report.iter().all(|entry| entry.outcome
            == ReturnOutcome::NotReturned {
                reason: NotReturned::NoReport
            }));
        assert_eq!(files_under(&root), Vec::<String>::new());
    }
}
