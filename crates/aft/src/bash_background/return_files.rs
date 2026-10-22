//! Files a `runon` job copies back from the build server (`return_paths`).
//!
//! The runner streams each requested file in `return_chunk` records and then
//! reports every path in one `return_manifest`. [`ReturnReceiver`] stages the
//! bytes of each path in a private file inside the project and moves it to the
//! requested path only after the manifest verified its size and SHA-256
//! (checked by the contract crate's `ReturnAssembler`). A path that failed,
//! did not verify, or would resolve outside the project writes nothing and
//! leaves any file already there untouched.
//!
//! [`ReturnedPath`] is the per-path outcome saved with the task, and
//! [`render_report`] prints it with the command's result.

use serde::{Deserialize, Serialize};

/// Most paths one bash call may ask the runner to copy back.
pub(crate) const MAX_RETURN_PATHS: usize = 64;

/// What happened to one requested path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReturnedPath {
    /// The path as the caller wrote it, relative to the command's workdir.
    pub path: String,
    pub outcome: ReturnOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum ReturnOutcome {
    /// The verified file now sits at the requested local path.
    Returned { bytes: u64 },
    /// Nothing was written for this path.
    NotReturned { reason: NotReturned },
}

/// Why a requested path was not written locally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum NotReturned {
    /// The runner's manifest named this failure cause (`missing`,
    /// `not_regular`, `escape`, `over_cap`, `read_error`, `expired`, or a
    /// cause this version does not know).
    Runner { cause: String },
    /// The bytes the runner sent did not pass the stream checks, so every
    /// path of the job was discarded. `code` is the checker's error code.
    Unverified { code: String },
    /// The job ended without the runner's per-path report.
    NoReport,
    /// The local destination, or a symlink on the way to it, leads outside
    /// the project.
    OutsideProject,
    /// Staging or placing the verified file failed locally.
    LocalWrite { error: String },
}

// Only the Unix remote-run path prints the report.
#[cfg_attr(not(unix), allow(dead_code))]
impl NotReturned {
    fn describe(&self, cap_bytes: u64) -> String {
        match self {
            Self::Runner { cause } => match cause.as_str() {
                "missing" => "no such file on the server".into(),
                "not_regular" => "not a regular file on the server".into(),
                "escape" => "it resolves outside the checkout on the server".into(),
                "over_cap" => format!(
                    "it would take the total past the {} limit",
                    format_cap(cap_bytes)
                ),
                "read_error" => {
                    "the server could not read it, or it changed while being read".into()
                }
                "expired" => "the server no longer keeps this job's files".into(),
                other => format!("the server reported {}", other.escape_default()),
            },
            Self::Unverified { code } => {
                format!("the copy failed verification ({code}); nothing was written")
            }
            Self::NoReport => "the server sent no report for it".into(),
            Self::OutsideProject => "the local path resolves outside the project".into(),
            Self::LocalWrite { error } => format!("could not write it here: {error}"),
        }
    }
}

// Only the Unix remote-run path prints the report.
#[cfg_attr(not(unix), allow(dead_code))]
fn format_cap(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes % MIB == 0 {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{bytes}-byte")
    }
}

/// The block printed after a remote command's output: each requested path
/// once, returned with its size or not returned with the reason.
// Only the Unix remote-run path prints the report.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn render_report(paths: &[ReturnedPath]) -> String {
    let cap = crate::exec_remote::return_max_bytes();
    let mut block = String::from("Files requested back from the server (return_paths):");
    for entry in paths {
        let path = entry.path.escape_default();
        match &entry.outcome {
            ReturnOutcome::Returned { bytes } => block.push_str(&format!(
                "\n  {path}: returned ({bytes} byte{})",
                if *bytes == 1 { "" } else { "s" }
            )),
            ReturnOutcome::NotReturned { reason } => block.push_str(&format!(
                "\n  {path}: not returned ({})",
                reason.describe(cap)
            )),
        }
    }
    block
}

/// The note added when a command that asked for `return_paths` ran on this
/// machine instead of the build server.
// Only the Unix remote-run path prints the report.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const LOCAL_RUN_NOTE: &str =
    "return_paths: the command ran on this machine, so its files are already where it wrote them; nothing was copied back";

/// Check the shape of the requested paths before anything else happens.
/// Each is a file path relative to the command's workdir, without `..`,
/// listed once, and there are at most [`MAX_RETURN_PATHS`]. Whether each
/// resolves inside the project is checked separately against the filesystem.
pub(crate) fn check_requested_paths(paths: &[String]) -> Result<(), String> {
    use std::path::{Component, Path};
    if paths.len() > MAX_RETURN_PATHS {
        return Err(format!(
            "return_paths lists {} paths; at most {MAX_RETURN_PATHS} are allowed",
            paths.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        let shown = path.escape_default();
        if path.trim().is_empty() {
            return Err("return_paths has an empty path".into());
        }
        if path.contains('\0') {
            return Err(format!("return_paths path {shown} contains a NUL byte"));
        }
        let parsed = Path::new(path);
        if parsed.is_absolute() || path.starts_with(['/', '\\']) || parsed.has_root() {
            return Err(format!(
                "return_paths path {shown} must be relative to workdir"
            ));
        }
        if parsed
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(format!("return_paths path {shown} must not use .."));
        }
        if path.ends_with(['/', '\\'])
            || !parsed
                .components()
                .any(|component| matches!(component, Component::Normal(_)))
        {
            return Err(format!(
                "return_paths path {shown} names a directory; list the files to copy back"
            ));
        }
        if !seen.insert(path.as_str()) {
            return Err(format!("return_paths lists {shown} twice"));
        }
    }
    Ok(())
}

/// Where a returned path's file goes, as resolved before any of it is written.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Destination {
    /// The resolved file to replace or create.
    pub target: std::path::PathBuf,
    /// Parent directories that do not exist yet, shallowest first. Each lies
    /// below an existing directory already checked to be inside the project.
    pub missing_dirs: Vec<std::path::PathBuf>,
}

/// The local file a returned path writes: `requested` resolved through any
/// symlinks, refused unless every existing part of it stays inside `root`
/// (which must itself be resolved). Nothing is created here.
pub(crate) fn resolve_destination(
    root: &std::path::Path,
    requested: &std::path::Path,
) -> Result<Destination, NotReturned> {
    use std::{fs, io};
    let local = |error: io::Error| NotReturned::LocalWrite {
        error: error.to_string(),
    };
    let file_name = requested
        .file_name()
        .ok_or_else(|| NotReturned::LocalWrite {
            error: "the path has no file name".into(),
        })?
        .to_owned();
    let parent = requested.parent().ok_or(NotReturned::OutsideProject)?;
    // Resolve the deepest parent directory that exists, following symlinks,
    // and refuse it unless it is inside the project.
    let mut existing = parent;
    let mut missing = Vec::new();
    while fs::symlink_metadata(existing).is_err() {
        missing.push(existing.file_name().ok_or(NotReturned::OutsideProject)?);
        existing = existing.parent().ok_or(NotReturned::OutsideProject)?;
    }
    let resolved = fs::canonicalize(existing).map_err(|_| NotReturned::OutsideProject)?;
    if !resolved.starts_with(root) {
        return Err(NotReturned::OutsideProject);
    }
    let mut directory = resolved;
    let mut missing_dirs = Vec::with_capacity(missing.len());
    for component in missing.into_iter().rev() {
        directory.push(component);
        missing_dirs.push(directory.clone());
    }
    let target = directory.join(file_name);
    if !missing_dirs.is_empty() {
        return Ok(Destination {
            target,
            missing_dirs,
        });
    }
    match fs::symlink_metadata(&target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Destination {
            target,
            missing_dirs,
        }),
        Err(error) => Err(local(error)),
        Ok(metadata) => {
            // Like `write`, a symlink is followed to its target, which must
            // itself be inside the project.
            let resolved = if metadata.file_type().is_symlink() {
                fs::canonicalize(&target).map_err(|_| NotReturned::OutsideProject)?
            } else {
                target
            };
            if !resolved.starts_with(root) {
                return Err(NotReturned::OutsideProject);
            }
            if fs::metadata(&resolved).map_err(local)?.is_dir() {
                return Err(NotReturned::LocalWrite {
                    error: "a directory is at this path".into(),
                });
            }
            Ok(Destination {
                target: resolved,
                missing_dirs,
            })
        }
    }
}

/// Staging files and directories a task created for its returned files,
/// saved in the task record before each is created. After a restart they
/// are removed from these recorded places; nothing is found by scanning.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StagingRecord {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dirs: Vec<std::path::PathBuf>,
}

impl StagingRecord {
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty()
    }
}

/// The name of a path's staging file: hidden, beside its destination, and
/// specific to the task and the path's position in `return_paths`.
// Only the Unix remote-run path stages returned files.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn staging_name(task_id: &str, index: usize) -> String {
    format!(".aft-return-{task_id}-{index}.part")
}

/// Remove what an earlier AFT process staged for this task and did not
/// finish: each recorded staging file, then each recorded directory that is
/// still empty, deepest first. A recorded file whose name is not one of this
/// task's staging names is left alone.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn remove_recorded_staging(record: &StagingRecord, task_id: &str) {
    let prefix = format!(".aft-return-{task_id}-");
    for file in &record.files {
        let ours = file
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".part"));
        if ours {
            let _ = std::fs::remove_file(file);
        }
    }
    for dir in record.dirs.iter().rev() {
        // Fails, and keeps the directory, when anything is in it.
        let _ = std::fs::remove_dir(dir);
    }
}

#[cfg(unix)]
pub(crate) use receiver::ReturnReceiver;

#[cfg(unix)]
mod receiver {
    use super::{
        resolve_destination, staging_name, NotReturned, ReturnOutcome, ReturnedPath, StagingRecord,
    };
    use crate::exec_remote::types::{
        ReturnAssembler, ReturnChunk, ReturnManifest, ReturnManifestOutcome,
    };
    use std::fs;
    use std::io::{self, Seek, SeekFrom, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// Saves staging files and directories in the task record before the
    /// receiver creates them, so a restart can remove them.
    pub(crate) type Recorder<'a> = dyn FnMut(&StagingRecord) -> io::Result<()> + 'a;

    /// One path's bytes as received so far, in a private file beside the
    /// file it will replace.
    struct Staged {
        path: PathBuf,
        file: fs::File,
        /// The resolved destination when staging began.
        target: PathBuf,
    }

    /// Receives one job's returned files and places those that verify.
    pub(crate) struct ReturnReceiver {
        paths: Vec<String>,
        cap_bytes: u64,
        task_id: String,
        /// The command's working directory; requested paths are relative to it.
        cwd: PathBuf,
        /// The resolved project root. Every destination, and the directory
        /// of its staging file, must resolve inside it.
        root: PathBuf,
        /// `None` once a stream check failed; every path is then discarded.
        assembler: Option<ReturnAssembler>,
        stream_error: Option<String>,
        staged: Vec<Option<Staged>>,
        /// A local staging failure for one path. That path is not placed even
        /// if the manifest verifies it.
        write_errors: Vec<Option<NotReturned>>,
        /// Directories this receiver created, shallowest first. Those still
        /// empty when the job's files are settled are removed again.
        created_dirs: Vec<PathBuf>,
        received_chunk: bool,
    }

    impl ReturnReceiver {
        pub(crate) fn new(
            paths: Vec<String>,
            cap_bytes: u64,
            cwd: &Path,
            project_root: &Path,
            task_id: &str,
        ) -> io::Result<Self> {
            Ok(Self {
                staged: (0..paths.len()).map(|_| None).collect(),
                write_errors: vec![None; paths.len()],
                assembler: Some(ReturnAssembler::new(&paths, cap_bytes)),
                paths,
                cap_bytes,
                task_id: task_id.to_string(),
                cwd: cwd.to_path_buf(),
                root: fs::canonicalize(project_root)?,
                stream_error: None,
                created_dirs: Vec::new(),
                received_chunk: false,
            })
        }

        /// Whether any chunk has arrived since the receiver started or was
        /// last reset.
        pub(crate) fn received_chunk(&self) -> bool {
            self.received_chunk
        }

        /// Start over for a new job, such as a resubmission after the runner
        /// refused the first one, discarding anything already staged.
        pub(crate) fn reset(&mut self) {
            self.settle();
            self.assembler = Some(ReturnAssembler::new(&self.paths, self.cap_bytes));
            self.stream_error = None;
            self.write_errors = vec![None; self.paths.len()];
            self.received_chunk = false;
        }

        /// Check one chunk and append its bytes to the path's staging file.
        pub(crate) fn chunk(&mut self, chunk: &ReturnChunk, record: &mut Recorder<'_>) {
            self.received_chunk = true;
            let Some(assembler) = self.assembler.as_mut() else {
                return;
            };
            let data = match assembler.accept_chunk(chunk) {
                Ok(data) => data,
                Err(error) => {
                    // Any stream error voids every path of the job.
                    self.stream_error = Some(error.code().to_string());
                    self.assembler = None;
                    self.discard_all();
                    return;
                }
            };
            // The assembler accepted the index, so it is in range.
            let index = chunk.path_index as usize;
            if self.write_errors[index].is_some() {
                return;
            }
            if let Err(reason) = self.write(index, chunk.offset, data, record) {
                self.write_errors[index] = Some(reason);
                self.discard(index);
            }
        }

        fn write(
            &mut self,
            index: usize,
            offset: u64,
            data: &[u8],
            record: &mut Recorder<'_>,
        ) -> Result<(), NotReturned> {
            self.stage(index, record)?;
            let staged = self.staged[index].as_mut().unwrap();
            staged
                .file
                .seek(SeekFrom::Start(offset))
                .and_then(|_| staged.file.write_all(data))
                .map_err(local)
        }

        /// Create the path's staging file beside its destination, once.
        fn stage(&mut self, index: usize, record: &mut Recorder<'_>) -> Result<(), NotReturned> {
            if self.staged[index].is_some() {
                return Ok(());
            }
            let destination = resolve_destination(&self.root, &self.cwd.join(&self.paths[index]))?;
            let directory = destination
                .target
                .parent()
                .ok_or(NotReturned::OutsideProject)?
                .to_path_buf();
            let path = directory.join(staging_name(&self.task_id, index));
            record(&StagingRecord {
                files: vec![path.clone()],
                dirs: destination.missing_dirs.clone(),
            })
            .map_err(local)?;
            for dir in &destination.missing_dirs {
                match fs::create_dir(dir) {
                    Ok(()) => self.created_dirs.push(dir.clone()),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(local(error)),
                }
            }
            // The staging file's own directory must be inside the project too.
            if !fs::canonicalize(&directory)
                .map_err(local)?
                .starts_with(&self.root)
            {
                return Err(NotReturned::OutsideProject);
            }
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(local)?;
            self.staged[index] = Some(Staged {
                path,
                file,
                target: destination.target,
            });
            Ok(())
        }

        /// Verify the manifest and place every verified file. Returns one
        /// entry per requested path, in request order.
        pub(crate) fn manifest(
            &mut self,
            manifest: &ReturnManifest,
            record: &mut Recorder<'_>,
        ) -> Vec<ReturnedPath> {
            let verified = match self.assembler.take() {
                None => Err(self
                    .stream_error
                    .clone()
                    .unwrap_or_else(|| "stream_refused".into())),
                Some(assembler) => assembler
                    .finish(manifest)
                    .map_err(|error| error.code().to_string()),
            };
            let verified = match verified {
                Ok(verified) => verified,
                Err(code) => {
                    self.settle();
                    return self.all_not_returned(NotReturned::Unverified { code });
                }
            };
            let mut report = Vec::with_capacity(self.paths.len());
            for (index, entry) in verified.into_iter().enumerate() {
                let outcome = match entry.outcome {
                    ReturnManifestOutcome::Returned { size, .. } => {
                        match self.write_errors[index].take() {
                            Some(reason) => ReturnOutcome::NotReturned { reason },
                            None => match self.place(index, size, record) {
                                Ok(()) => ReturnOutcome::Returned { bytes: size },
                                Err(reason) => ReturnOutcome::NotReturned { reason },
                            },
                        }
                    }
                    ReturnManifestOutcome::Failed { cause, .. } => ReturnOutcome::NotReturned {
                        reason: NotReturned::Runner {
                            cause: String::from(cause),
                        },
                    },
                    // A future outcome shape is not proof the bytes are good.
                    _ => ReturnOutcome::NotReturned {
                        reason: NotReturned::Unverified {
                            code: "unknown_outcome".into(),
                        },
                    },
                };
                if !matches!(outcome, ReturnOutcome::Returned { .. }) {
                    self.discard(index);
                }
                report.push(self.entry(index, outcome));
            }
            self.settle();
            report
        }

        /// The job ended without a manifest: nothing is placed.
        pub(crate) fn without_manifest(&mut self) -> Vec<ReturnedPath> {
            self.assembler = None;
            self.settle();
            self.all_not_returned(NotReturned::NoReport)
        }

        fn all_not_returned(&self, reason: NotReturned) -> Vec<ReturnedPath> {
            (0..self.paths.len())
                .map(|index| {
                    self.entry(
                        index,
                        ReturnOutcome::NotReturned {
                            reason: reason.clone(),
                        },
                    )
                })
                .collect()
        }

        fn entry(&self, index: usize, outcome: ReturnOutcome) -> ReturnedPath {
            ReturnedPath {
                path: self.paths[index].clone(),
                outcome,
            }
        }

        /// Move a verified file to its destination, replacing it within the
        /// same directory. The destination is resolved again first and must
        /// still be where staging began, inside the project, whatever the
        /// runner reported.
        fn place(
            &mut self,
            index: usize,
            size: u64,
            record: &mut Recorder<'_>,
        ) -> Result<(), NotReturned> {
            // A zero-byte file has no chunks, so it has no staging file yet.
            self.stage(index, record)?;
            let staged = self.staged[index].take().unwrap();
            let result = (|| {
                let length = staged.file.metadata().map_err(local)?.len();
                if length != size {
                    return Err(NotReturned::LocalWrite {
                        error: format!("staged {length} bytes, expected {size}"),
                    });
                }
                staged.file.sync_all().map_err(local)?;
                let now = resolve_destination(&self.root, &self.cwd.join(&self.paths[index]))?;
                if now.target != staged.target || !now.missing_dirs.is_empty() {
                    return Err(NotReturned::LocalWrite {
                        error: "the destination changed while the file was arriving".into(),
                    });
                }
                // Keep an existing file's permissions; a new file gets the
                // usual owner-writable, world-readable mode, not the staging 0600.
                let mode = fs::metadata(&staged.target)
                    .map(|metadata| metadata.permissions().mode() & 0o7777)
                    .unwrap_or(0o644);
                fs::set_permissions(&staged.path, fs::Permissions::from_mode(mode))
                    .map_err(local)?;
                fs::rename(&staged.path, &staged.target).map_err(local)
            })();
            if result.is_err() {
                let _ = fs::remove_file(&staged.path);
            }
            result
        }

        fn discard(&mut self, index: usize) {
            if let Some(staged) = self.staged[index].take() {
                let _ = fs::remove_file(&staged.path);
            }
        }

        fn discard_all(&mut self) {
            for index in 0..self.staged.len() {
                self.discard(index);
            }
        }

        /// Discard what is still staged and remove the directories this
        /// receiver created that nothing was placed in, deepest first.
        fn settle(&mut self) {
            self.discard_all();
            for dir in self.created_dirs.drain(..).rev() {
                let _ = fs::remove_dir(dir);
            }
        }
    }

    fn local(error: io::Error) -> NotReturned {
        NotReturned::LocalWrite {
            error: error.to_string(),
        }
    }

    impl Drop for ReturnReceiver {
        fn drop(&mut self) {
            self.settle();
        }
    }
}

#[cfg(test)]
#[path = "return_files_tests.rs"]
mod tests;
