//! Capability-rooted, bounded reads for explicitly named workspace documents.
//!
//! This module owns the filesystem authority boundary shared by query and
//! policy loading. A [`WorkspaceRoot`] opens the ambient workspace exactly
//! once; every later file or directory operation is relative to that retained
//! directory capability.

#[cfg(unix)]
use cap_fs_ext::OpenOptionsExt;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirEntry, File, OpenOptions};
use std::fmt;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// One opened workspace directory capability.
pub struct WorkspaceRoot {
    display_path: PathBuf,
    directory: Dir,
}

impl WorkspaceRoot {
    /// Open `path` as the sole ambient filesystem authority used by this root.
    pub fn open(path: &Path) -> Result<Self, WorkspaceDocumentError> {
        let directory = Dir::open_ambient_dir(path, ambient_authority()).map_err(|source| {
            WorkspaceDocumentError::OpenWorkspace {
                path: path.to_path_buf(),
                source,
            }
        })?;
        let metadata =
            directory
                .dir_metadata()
                .map_err(|source| WorkspaceDocumentError::ReadDirectory {
                    path: PathBuf::new(),
                    source,
                })?;
        if !metadata.is_dir() {
            return Err(WorkspaceDocumentError::NotDirectory {
                path: path.to_path_buf(),
            });
        }
        Ok(Self {
            display_path: path.to_path_buf(),
            directory,
        })
    }

    /// The root directory itself, for documents that sit directly under it.
    pub fn root_directory(&self) -> Result<WorkspaceDirectory, WorkspaceDocumentError> {
        let directory =
            self.directory
                .try_clone()
                .map_err(|source| WorkspaceDocumentError::ReadDirectory {
                    path: PathBuf::new(),
                    source,
                })?;
        Ok(WorkspaceDirectory {
            relative_path: PathBuf::new(),
            directory,
        })
    }

    /// Open a workspace-relative directory without intentionally traversing a
    /// symlink. Each component is looked up directly from its parent handle,
    /// classified without following links, and atomically opened no-follow;
    /// resolving an explicit path never scans unrelated siblings.
    pub fn open_directory(
        &self,
        relative_path: &Path,
    ) -> Result<WorkspaceDirectory, WorkspaceDocumentError> {
        let relative_path = validate_workspace_relative_path(relative_path)?;
        let mut directory =
            self.directory
                .try_clone()
                .map_err(|source| WorkspaceDocumentError::ReadDirectory {
                    path: relative_path.clone(),
                    source,
                })?;
        let mut traversed = PathBuf::new();

        for component in relative_path.components() {
            let Component::Normal(name) = component else {
                unreachable!("workspace-relative path validation removes other components");
            };
            traversed.push(name);
            let metadata = directory.symlink_metadata(name).map_err(|source| {
                WorkspaceDocumentError::OpenDirectory {
                    path: traversed.clone(),
                    source,
                }
            })?;
            if metadata.file_type().is_symlink() {
                return Err(WorkspaceDocumentError::SymlinkNotAllowed {
                    path: traversed.clone(),
                });
            }
            if !metadata.is_dir() {
                return Err(WorkspaceDocumentError::NotDirectory {
                    path: traversed.clone(),
                });
            }
            directory = directory.open_dir_nofollow(name).map_err(|source| {
                WorkspaceDocumentError::OpenDirectory {
                    path: traversed.clone(),
                    source,
                }
            })?;
        }

        Ok(WorkspaceDirectory {
            relative_path,
            directory,
        })
    }
}

impl fmt::Debug for WorkspaceRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceRoot")
            .field("display_path", &self.display_path)
            .finish_non_exhaustive()
    }
}

/// UTF-8 source read from one regular file under a [`WorkspaceRoot`].
#[derive(Debug)]
pub struct WorkspaceDocument {
    relative_path: PathBuf,
    source: String,
}

impl WorkspaceDocument {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Open, classify, bounded-read, and UTF-8-decode one workspace document.
///
/// Metadata and bytes are both read from the same open file handle. The path
/// is never canonicalized and reopened.
pub fn read_workspace_document(
    root: &WorkspaceRoot,
    relative_path: &Path,
    allowed_extensions: &[&str],
    max_bytes: u64,
) -> Result<WorkspaceDocument, WorkspaceDocumentError> {
    let relative_path = validate_workspace_relative_path(relative_path)?;
    validate_extension(&relative_path, allowed_extensions)?;
    open_workspace_document(root, relative_path, max_bytes)
}

/// Read an optional workspace document, treating only a missing file as absent.
pub fn read_optional_workspace_document(
    root: &WorkspaceRoot,
    relative_path: &Path,
    allowed_extensions: &[&str],
    max_bytes: u64,
) -> Result<Option<WorkspaceDocument>, WorkspaceDocumentError> {
    match read_workspace_document(root, relative_path, allowed_extensions, max_bytes) {
        Ok(document) => Ok(Some(document)),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => Err(error),
    }
}

/// Write the shared diagnostic used by workspace documents with this wording.
pub fn fmt_json_decode_error(
    formatter: &mut fmt::Formatter<'_>,
    document: &str,
    message: &str,
    line: usize,
    column: usize,
) -> fmt::Result {
    write!(
        formatter,
        "{document} document is not valid JSON at line {line} column {column}: {message}"
    )
}

/// Open, classify, bounded-read, and UTF-8-decode one workspace document whose
/// name carries no extension.
///
/// A conventional dotfile such as `.nvmrc` is entirely a file stem, so
/// [`read_workspace_document`]'s extension allow-list can never admit it. Path
/// validation, the opened-handle regular-file check, and the byte bound are the
/// same ones every other explicitly named document goes through.
pub fn read_workspace_document_without_extension(
    root: &WorkspaceRoot,
    relative_path: &Path,
    max_bytes: u64,
) -> Result<WorkspaceDocument, WorkspaceDocumentError> {
    let relative_path = validate_workspace_relative_path(relative_path)?;
    open_workspace_document(root, relative_path, max_bytes)
}

fn open_workspace_document(
    root: &WorkspaceRoot,
    relative_path: PathBuf,
    max_bytes: u64,
) -> Result<WorkspaceDocument, WorkspaceDocumentError> {
    // Explicit files preserve the existing query behavior of accepting an
    // in-workspace symlink. `cap-std` resolves it beneath the retained root and
    // rejects a target that would escape. Match-directory traversal uses the
    // classified entry API below and never follows symlinks. Nonblocking mode
    // prevents an explicitly named or concurrently substituted FIFO from
    // stalling before the opened-handle regular-file check. `maybe_dir` lets
    // Windows open a directory handle so the same check can reject it as a
    // non-regular file, matching platforms where directories open normally.
    let mut options = OpenOptions::new();
    options.read(true).maybe_dir(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK);
    let file = root
        .directory
        .open_with(&relative_path, &options)
        .map_err(|source| classify_capability_open_error(relative_path.clone(), source))?;
    read_opened_workspace_document(file, relative_path, max_bytes)
}

fn classify_capability_open_error(path: PathBuf, source: io::Error) -> WorkspaceDocumentError {
    // cap-primitives exposes an escape attempt as a synthetic PermissionDenied
    // error without an OS code. Translate that dependency boundary once so
    // downstream query/policy loaders never classify human-readable prose.
    if source.kind() == io::ErrorKind::PermissionDenied
        && source.raw_os_error().is_none()
        && source.to_string() == "a path led outside of the filesystem"
    {
        WorkspaceDocumentError::PathEscapesWorkspace { path }
    } else {
        WorkspaceDocumentError::OpenFile { path, source }
    }
}

/// One already-open directory used for handle-relative traversal.
pub struct WorkspaceDirectory {
    relative_path: PathBuf,
    directory: Dir,
}

impl WorkspaceDirectory {
    /// Read at most `maximum` immediate entries from this directory.
    ///
    /// `None` means the directory contains more entries than the caller's
    /// remaining traversal budget. The scan stops before retaining the excess
    /// entry. Returned entries retain their parent directory handle, so
    /// opening one remains capability-relative.
    pub fn entries_up_to(
        &self,
        maximum: usize,
    ) -> Result<Option<Vec<WorkspaceDirectoryEntry>>, WorkspaceDocumentError> {
        let mut result = Vec::new();
        let entries =
            self.directory
                .entries()
                .map_err(|source| WorkspaceDocumentError::ReadDirectory {
                    path: self.relative_path.clone(),
                    source,
                })?;
        for entry in entries {
            let entry = entry.map_err(|source| WorkspaceDocumentError::ReadDirectory {
                path: self.relative_path.clone(),
                source,
            })?;
            if result.len() == maximum {
                return Ok(None);
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| WorkspaceDocumentError::NonUtf8Path {
                    path: self.relative_path.clone(),
                })?;
            let relative_path = self.relative_path.join(name);
            let file_type =
                entry
                    .file_type()
                    .map_err(|source| WorkspaceDocumentError::ReadDirectoryEntry {
                        path: relative_path.clone(),
                        source,
                    })?;
            let kind = if file_type.is_symlink() {
                WorkspaceDirectoryEntryKind::Symlink
            } else if file_type.is_file() {
                WorkspaceDirectoryEntryKind::File
            } else if file_type.is_dir() {
                WorkspaceDirectoryEntryKind::Directory
            } else {
                WorkspaceDirectoryEntryKind::Other
            };
            result.push(WorkspaceDirectoryEntry {
                relative_path,
                entry,
                kind,
            });
        }
        result.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(Some(result))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDirectoryEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// A classified entry tied to the opened parent directory used to enumerate it.
pub struct WorkspaceDirectoryEntry {
    relative_path: PathBuf,
    entry: cap_std::fs::DirEntry,
    kind: WorkspaceDirectoryEntryKind,
}

impl WorkspaceDirectoryEntry {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub const fn kind(&self) -> WorkspaceDirectoryEntryKind {
        self.kind
    }

    pub fn open_directory(self) -> Result<WorkspaceDirectory, WorkspaceDocumentError> {
        if self.kind == WorkspaceDirectoryEntryKind::Symlink {
            return Err(WorkspaceDocumentError::SymlinkNotAllowed {
                path: self.relative_path,
            });
        }
        if self.kind != WorkspaceDirectoryEntryKind::Directory {
            return Err(WorkspaceDocumentError::NotDirectory {
                path: self.relative_path,
            });
        }
        let directory = open_directory_entry_nofollow(&self.entry, self.relative_path.clone())?;
        Ok(WorkspaceDirectory {
            relative_path: self.relative_path,
            directory,
        })
    }

    pub fn read_document(
        self,
        allowed_extensions: &[&str],
        max_bytes: u64,
    ) -> Result<WorkspaceDocument, WorkspaceDocumentError> {
        validate_extension(&self.relative_path, allowed_extensions)?;
        if self.kind == WorkspaceDirectoryEntryKind::Symlink {
            return Err(WorkspaceDocumentError::SymlinkNotAllowed {
                path: self.relative_path,
            });
        }
        if self.kind != WorkspaceDirectoryEntryKind::File {
            return Err(WorkspaceDocumentError::NotRegularFile {
                path: self.relative_path,
            });
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        // `O_NOFOLLOW` closes symlink replacement, while `O_NONBLOCK`
        // prevents a concurrently substituted FIFO from stalling before the
        // opened-handle regular-file check below.
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK);
        let file =
            self.entry
                .open_with(&options)
                .map_err(|source| WorkspaceDocumentError::OpenFile {
                    path: self.relative_path.clone(),
                    source,
                })?;
        read_opened_workspace_document(file, self.relative_path, max_bytes)
    }
}

/// Atomically refuse a symlink in the final directory-entry component, then
/// classify the object through the opened handle. This closes the
/// classify-then-open race inherent in `DirEntry::file_type` followed by the
/// default symlink-following `open_dir` operation.
fn open_directory_entry_nofollow(
    entry: &DirEntry,
    relative_path: PathBuf,
) -> Result<Dir, WorkspaceDocumentError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    // On Unix, require the kernel to open a directory rather than opening an
    // attacker-substituted FIFO/device and classifying it only afterwards.
    #[cfg(unix)]
    options.custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK);
    let file =
        entry
            .open_with(&options)
            .map_err(|source| WorkspaceDocumentError::OpenDirectory {
                path: relative_path.clone(),
                source,
            })?;
    let metadata =
        file.metadata()
            .map_err(|source| WorkspaceDocumentError::ReadDirectoryEntry {
                path: relative_path.clone(),
                source,
            })?;
    if !metadata.is_dir() {
        return Err(WorkspaceDocumentError::NotDirectory {
            path: relative_path,
        });
    }
    Ok(Dir::from_std_file(file.into_std()))
}

fn read_opened_workspace_document(
    file: File,
    relative_path: PathBuf,
    max_bytes: u64,
) -> Result<WorkspaceDocument, WorkspaceDocumentError> {
    let metadata = file
        .metadata()
        .map_err(|source| WorkspaceDocumentError::ReadFileMetadata {
            path: relative_path.clone(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(WorkspaceDocumentError::NotRegularFile {
            path: relative_path,
        });
    }
    if metadata.len() > max_bytes {
        return Err(WorkspaceDocumentError::TooLarge {
            path: relative_path,
            bytes: Some(metadata.len()),
            max_bytes,
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len().min(max_bytes) as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| WorkspaceDocumentError::ReadFile {
            path: relative_path.clone(),
            source,
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(WorkspaceDocumentError::TooLarge {
            path: relative_path,
            bytes: None,
            max_bytes,
        });
    }
    let source =
        String::from_utf8(bytes).map_err(|source| WorkspaceDocumentError::InvalidUtf8 {
            path: relative_path.clone(),
            source,
        })?;
    Ok(WorkspaceDocument {
        relative_path,
        source,
    })
}

#[doc(hidden)]
pub fn validate_workspace_relative_path(
    relative_path: &Path,
) -> Result<PathBuf, WorkspaceDocumentError> {
    if relative_path.as_os_str().is_empty() {
        return Err(WorkspaceDocumentError::InvalidPath {
            path: relative_path.to_path_buf(),
            reason: WorkspacePathError::Empty,
        });
    }
    if let Some(raw) = relative_path.to_str()
        && has_portable_windows_path_prefix(raw)
    {
        return Err(WorkspaceDocumentError::InvalidPath {
            path: relative_path.to_path_buf(),
            reason: WorkspacePathError::AbsoluteOrPrefixed,
        });
    }

    let mut normalized = PathBuf::new();
    for component in relative_path.components() {
        match component {
            Component::Normal(component) => normalized.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(WorkspaceDocumentError::InvalidPath {
                    path: relative_path.to_path_buf(),
                    reason: WorkspacePathError::ParentComponent,
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(WorkspaceDocumentError::InvalidPath {
                    path: relative_path.to_path_buf(),
                    reason: WorkspacePathError::AbsoluteOrPrefixed,
                });
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(WorkspaceDocumentError::InvalidPath {
            path: relative_path.to_path_buf(),
            reason: WorkspacePathError::Empty,
        });
    }
    Ok(normalized)
}

pub use crate::analyzer::semantic::workspace_document::has_portable_windows_path_prefix;

fn validate_extension(
    relative_path: &Path,
    allowed_extensions: &[&str],
) -> Result<(), WorkspaceDocumentError> {
    let observed = relative_path
        .extension()
        .and_then(|extension| extension.to_str());
    if observed.is_some_and(|extension| allowed_extensions.contains(&extension)) {
        return Ok(());
    }
    Err(WorkspaceDocumentError::UnsupportedExtension {
        path: relative_path.to_path_buf(),
        observed: observed.map(str::to_owned),
        allowed: allowed_extensions
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspacePathError {
    Empty,
    AbsoluteOrPrefixed,
    ParentComponent,
}

impl fmt::Display for WorkspacePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "path must not be empty",
            Self::AbsoluteOrPrefixed => "path must be workspace-relative",
            Self::ParentComponent => "path must not contain a parent component",
        })
    }
}

#[derive(Debug)]
pub enum WorkspaceDocumentError {
    OpenWorkspace {
        path: PathBuf,
        source: io::Error,
    },
    InvalidPath {
        path: PathBuf,
        reason: WorkspacePathError,
    },
    NonUtf8Path {
        path: PathBuf,
    },
    UnsupportedExtension {
        path: PathBuf,
        observed: Option<String>,
        allowed: Vec<String>,
    },
    OpenFile {
        path: PathBuf,
        source: io::Error,
    },
    PathEscapesWorkspace {
        path: PathBuf,
    },
    ReadFileMetadata {
        path: PathBuf,
        source: io::Error,
    },
    NotRegularFile {
        path: PathBuf,
    },
    TooLarge {
        path: PathBuf,
        bytes: Option<u64>,
        max_bytes: u64,
    },
    ReadFile {
        path: PathBuf,
        source: io::Error,
    },
    InvalidUtf8 {
        path: PathBuf,
        source: std::string::FromUtf8Error,
    },
    OpenDirectory {
        path: PathBuf,
        source: io::Error,
    },
    ReadDirectory {
        path: PathBuf,
        source: io::Error,
    },
    ReadDirectoryEntry {
        path: PathBuf,
        source: io::Error,
    },
    NotDirectory {
        path: PathBuf,
    },
    SymlinkNotAllowed {
        path: PathBuf,
    },
}

impl WorkspaceDocumentError {
    /// Whether opening the requested workspace-relative file failed because it is absent.
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::OpenFile { source, .. } if source.kind() == io::ErrorKind::NotFound
        )
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::OpenWorkspace { path, .. }
            | Self::InvalidPath { path, .. }
            | Self::NonUtf8Path { path }
            | Self::UnsupportedExtension { path, .. }
            | Self::OpenFile { path, .. }
            | Self::PathEscapesWorkspace { path }
            | Self::ReadFileMetadata { path, .. }
            | Self::NotRegularFile { path }
            | Self::TooLarge { path, .. }
            | Self::ReadFile { path, .. }
            | Self::InvalidUtf8 { path, .. }
            | Self::OpenDirectory { path, .. }
            | Self::ReadDirectory { path, .. }
            | Self::ReadDirectoryEntry { path, .. }
            | Self::NotDirectory { path }
            | Self::SymlinkNotAllowed { path } => path,
        }
    }
}

impl fmt::Display for WorkspaceDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenWorkspace { path, source } => {
                write!(
                    formatter,
                    "failed to open workspace `{}`: {source}",
                    path.display()
                )
            }
            Self::InvalidPath { path, reason } => {
                write!(
                    formatter,
                    "invalid workspace path `{}`: {reason}",
                    path.display()
                )
            }
            Self::NonUtf8Path { path } => write!(
                formatter,
                "workspace path under `{}` is not valid UTF-8",
                path.display()
            ),
            Self::UnsupportedExtension {
                path,
                observed,
                allowed,
            } => {
                let observed = observed
                    .as_deref()
                    .map_or_else(|| "<none>".to_string(), |value| format!(".{value}"));
                let allowed = allowed
                    .iter()
                    .map(|value| format!(".{value}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    formatter,
                    "unsupported extension `{observed}` for `{}`; expected {allowed}",
                    path.display()
                )
            }
            Self::OpenFile { path, source } => {
                write!(formatter, "failed to open `{}`: {source}", path.display())
            }
            Self::PathEscapesWorkspace { path } => write!(
                formatter,
                "path `{}` resolves outside the workspace capability",
                path.display()
            ),
            Self::ReadFileMetadata { path, source } => write!(
                formatter,
                "failed to read metadata for `{}`: {source}",
                path.display()
            ),
            Self::NotRegularFile { path } => {
                write!(formatter, "`{}` must be a regular file", path.display())
            }
            Self::TooLarge {
                path,
                bytes,
                max_bytes,
            } => match bytes {
                Some(bytes) => write!(
                    formatter,
                    "`{}` is too large: {bytes} bytes exceeds {max_bytes}",
                    path.display()
                ),
                None => write!(
                    formatter,
                    "`{}` is too large: more than {max_bytes} bytes",
                    path.display()
                ),
            },
            Self::ReadFile { path, source } => {
                write!(formatter, "failed to read `{}`: {source}", path.display())
            }
            Self::InvalidUtf8 { path, source } => write!(
                formatter,
                "`{}` must contain valid UTF-8: {source}",
                path.display()
            ),
            Self::OpenDirectory { path, source } => write!(
                formatter,
                "failed to open directory `{}`: {source}",
                path.display()
            ),
            Self::ReadDirectory { path, source } => write!(
                formatter,
                "failed to read directory `{}`: {source}",
                path.display()
            ),
            Self::ReadDirectoryEntry { path, source } => write!(
                formatter,
                "failed to inspect directory entry `{}`: {source}",
                path.display()
            ),
            Self::NotDirectory { path } => {
                write!(formatter, "`{}` must be a directory", path.display())
            }
            Self::SymlinkNotAllowed { path } => write!(
                formatter,
                "symbolic links are not allowed in directory traversal: `{}`",
                path.display()
            ),
        }
    }
}

impl std::error::Error for WorkspaceDocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenWorkspace { source, .. }
            | Self::OpenFile { source, .. }
            | Self::ReadFileMetadata { source, .. }
            | Self::ReadFile { source, .. }
            | Self::OpenDirectory { source, .. }
            | Self::ReadDirectory { source, .. }
            | Self::ReadDirectoryEntry { source, .. } => Some(source),
            Self::InvalidUtf8 { source, .. } => Some(source),
            Self::InvalidPath { .. }
            | Self::NonUtf8Path { .. }
            | Self::UnsupportedExtension { .. }
            | Self::PathEscapesWorkspace { .. }
            | Self::NotRegularFile { .. }
            | Self::TooLarge { .. }
            | Self::NotDirectory { .. }
            | Self::SymlinkNotAllowed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::test_support::create_fifo;
    use brokk_bifrost_test_macros::hardwon;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(unix)]
    use std::sync::mpsc;
    #[cfg(unix)]
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    #[cfg(unix)]
    fn assert_fifo_operations_return_promptly<T>(
        fifo_paths: Vec<PathBuf>,
        operation: impl FnOnce() -> T,
    ) -> T {
        let (done_tx, done_rx) = mpsc::channel();
        let fallback = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(2));
            let guards = fifo_paths
                .into_iter()
                .map(|path| {
                    fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(path)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            done_rx.recv().unwrap();
            drop(guards);
        });

        let started = Instant::now();
        let result = operation();
        let elapsed = started.elapsed();
        done_tx.send(()).unwrap();
        fallback.join().unwrap();
        assert!(
            elapsed < Duration::from_secs(1),
            "special-file open blocked for {elapsed:?}"
        );
        result
    }

    #[test]
    fn bounded_read_preserves_unicode_paths_and_source() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("politiques-données")).unwrap();
        let source = "(policy :name \"Données privées π\")";
        fs::write(temp.path().join("politiques-données/entrée.rqlp"), source).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();

        let document = read_workspace_document(
            &root,
            Path::new("politiques-données/entrée.rqlp"),
            &["rqlp"],
            128,
        )
        .unwrap();

        assert_eq!(
            document.relative_path(),
            Path::new("politiques-données/entrée.rqlp")
        );
        assert_eq!(document.source(), source);
    }

    #[test]
    fn bounded_workspace_reads_accept_exact_limits_and_reject_overflow() {
        let workspace = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("données")).unwrap();
        fs::write(workspace.path().join("données/entrée.rql"), "π").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();

        let exact =
            read_workspace_document(&root, Path::new("données/entrée.rql"), &["rql"], 2).unwrap();
        assert_eq!(exact.source(), "π");
        assert!(matches!(
            read_workspace_document(&root, Path::new("données/entrée.rql"), &["rql"], 1,),
            Err(WorkspaceDocumentError::TooLarge { bytes: Some(2), .. })
        ));

        let models = workspace.path().join("models");
        fs::create_dir(&models).unwrap();
        for name in ["a.rql", "b.rql", "c.rql", "d.rql"] {
            fs::write(models.join(name), "x").unwrap();
        }
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        let directory = root.open_directory(Path::new("models")).unwrap();
        assert!(directory.entries_up_to(0).unwrap().is_none());
        assert!(directory.entries_up_to(3).unwrap().is_none());
        assert_eq!(directory.entries_up_to(4).unwrap().unwrap().len(), 4);
    }

    #[test]
    fn optional_reads_keep_present_documents_and_distinguish_missing_files() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("present.rql"), "(rule)").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();

        let present =
            read_optional_workspace_document(&root, Path::new("present.rql"), &["rql"], 64)
                .unwrap()
                .unwrap();
        assert_eq!(present.source(), "(rule)");
        assert!(
            read_optional_workspace_document(&root, Path::new("missing.rql"), &["rql"], 64,)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn directory_entry_reads_enforce_byte_limit() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("query.rql"), "π").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();

        let read_at_limit = |limit| {
            root.root_directory()
                .unwrap()
                .entries_up_to(1)
                .unwrap()
                .unwrap()
                .pop()
                .unwrap()
                .read_document(&["rql"], limit)
        };
        assert!(matches!(
            read_at_limit(1),
            Err(WorkspaceDocumentError::TooLarge { .. })
        ));
        assert_eq!(read_at_limit(2).unwrap().source(), "π");
        assert_eq!(read_at_limit(3).unwrap().source(), "π");
    }

    #[test]
    #[hardwon("3fdaa7196951: maximum byte limit overflowed during bounded reads")]
    fn explicit_and_entry_reads_accept_the_maximum_byte_limit() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("query.rql"), "(rule π)").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        let explicit =
            read_workspace_document(&root, Path::new("query.rql"), &["rql"], u64::MAX).unwrap();
        assert_eq!(explicit.source(), "(rule π)");

        let entry = root
            .root_directory()
            .unwrap()
            .entries_up_to(1)
            .unwrap()
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            entry.read_document(&["rql"], u64::MAX).unwrap().source(),
            "(rule π)"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_read_detects_proc_file_growth_beyond_metadata_size() {
        // procfs reports a zero length for a file whose read returns bytes,
        // so only the extra-byte probe can catch the overrun.
        let root = WorkspaceRoot::open(Path::new("/proc/self")).unwrap();
        assert_eq!(fs::metadata("/proc/self/cmdline").unwrap().len(), 0);

        assert!(matches!(
            read_workspace_document_without_extension(&root, Path::new("cmdline"), 1),
            Err(WorkspaceDocumentError::TooLarge { bytes: None, .. })
        ));
    }

    #[test]
    fn extension_allow_list_is_case_sensitive_for_all_readers() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("query.RQL"), "(rule)").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        assert!(matches!(
            read_workspace_document(&root, Path::new("query.RQL"), &["rql"], 64),
            Err(WorkspaceDocumentError::UnsupportedExtension { .. })
        ));
        let entry = root
            .root_directory()
            .unwrap()
            .entries_up_to(1)
            .unwrap()
            .unwrap()
            .pop()
            .unwrap();
        assert!(matches!(
            entry.read_document(&["rql"], 64),
            Err(WorkspaceDocumentError::UnsupportedExtension { .. })
        ));
        assert_eq!(
            read_workspace_document(&root, Path::new("query.RQL"), &["RQL"], 64)
                .unwrap()
                .source(),
            "(rule)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn optional_reads_propagate_permission_denied() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let workspace = TempDir::new().unwrap();
        let file = workspace.path().join("private.rql");
        fs::write(&file, "(rule)").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o0)).unwrap();
        let result =
            read_optional_workspace_document(&root, Path::new("private.rql"), &["rql"], 64);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            result,
            Err(WorkspaceDocumentError::OpenFile { source, .. })
                if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn opened_directory_entries_remain_directories() {
        let workspace = TempDir::new().unwrap();
        fs::create_dir_all(workspace.path().join("models/nested")).unwrap();
        fs::write(workspace.path().join("models/nested/item.rql"), "x").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        let entry = root
            .open_directory(Path::new("models"))
            .unwrap()
            .entries_up_to(2)
            .unwrap()
            .unwrap()
            .into_iter()
            .find(|entry| entry.relative_path() == Path::new("models/nested"))
            .unwrap();

        let directory = entry.open_directory().unwrap();
        assert_eq!(directory.entries_up_to(2).unwrap().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn explicit_directory_resolution_rejects_symlink_components() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("real/nested")).unwrap();
        symlink("real", temp.path().join("linked")).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();

        let Err(error) = root.open_directory(Path::new("linked/nested")) else {
            panic!("symlinked directory component was accepted");
        };

        assert!(matches!(
            error,
            WorkspaceDocumentError::SymlinkNotAllowed { path }
                if path == Path::new("linked")
        ));
    }

    #[test]
    fn rejects_absolute_parent_wrong_kind_size_and_utf8() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("directory.rql")).unwrap();
        fs::write(temp.path().join("large.rql"), b"12345").unwrap();
        fs::write(temp.path().join("binary.rql"), [0xff]).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();

        assert!(matches!(
            read_workspace_document(&root, Path::new("/outside.rql"), &["rql"], 64),
            Err(WorkspaceDocumentError::InvalidPath { .. })
        ));
        assert!(matches!(
            read_workspace_document(&root, Path::new("../outside.rql"), &["rql"], 64),
            Err(WorkspaceDocumentError::InvalidPath { .. })
        ));
        assert!(matches!(
            read_workspace_document(&root, Path::new("directory.rql"), &["rql"], 64),
            Err(WorkspaceDocumentError::NotRegularFile { .. })
        ));
        assert!(matches!(
            read_workspace_document(&root, Path::new("large.rql"), &["rql"], 4),
            Err(WorkspaceDocumentError::TooLarge { .. })
        ));
        assert!(matches!(
            read_workspace_document(&root, Path::new("binary.rql"), &["rql"], 64),
            Err(WorkspaceDocumentError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn directory_entries_are_sorted_by_workspace_path() {
        let workspace = TempDir::new().unwrap();
        fs::write(workspace.path().join("z.rql"), "z").unwrap();
        fs::create_dir(workspace.path().join("m-dir")).unwrap();
        fs::write(workspace.path().join("a.rql"), "a").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        let paths = root
            .root_directory()
            .unwrap()
            .entries_up_to(3)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|entry| entry.relative_path().to_path_buf())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                PathBuf::from("a.rql"),
                PathBuf::from("m-dir"),
                PathBuf::from("z.rql")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_entry_open_rejects_replacement_by_internal_symlink() {
        let workspace = TempDir::new().unwrap();
        fs::create_dir_all(workspace.path().join("models/nested")).unwrap();
        fs::create_dir(workspace.path().join("models/replacement")).unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        let entry = root
            .open_directory(Path::new("models"))
            .unwrap()
            .entries_up_to(2)
            .unwrap()
            .unwrap()
            .into_iter()
            .find(|entry| entry.relative_path() == Path::new("models/nested"))
            .unwrap();
        fs::remove_dir(workspace.path().join("models/nested")).unwrap();
        symlink("replacement", workspace.path().join("models/nested")).unwrap();

        assert!(matches!(
            entry.open_directory(),
            Err(WorkspaceDocumentError::OpenDirectory { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_portable_windows_prefixes_on_unix() {
        let temp = TempDir::new().unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();

        for path in [
            "C:foo",
            r"C:\foo",
            r"\\server\share\foo",
            r"\\?\C:\foo",
            r"\\?\UNC\server\share\foo",
            r"\\.\pipe\foo",
        ] {
            assert!(
                matches!(
                    read_workspace_document(&root, Path::new(path), &["rql"], 64),
                    Err(WorkspaceDocumentError::InvalidPath {
                        reason: WorkspacePathError::AbsoluteOrPrefixed,
                        ..
                    })
                ),
                "portable prefix was not rejected: {path}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn accepts_internal_file_symlink_and_rejects_escape() {
        let workspace = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(workspace.path().join("real.rql"), "(name \"A\")").unwrap();
        fs::write(outside.path().join("outside.rql"), "(name \"outside\")").unwrap();
        symlink("real.rql", workspace.path().join("internal-link.rql")).unwrap();
        symlink(
            outside.path().join("outside.rql"),
            workspace.path().join("outside-link.rql"),
        )
        .unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();

        assert_eq!(
            read_workspace_document(&root, Path::new("internal-link.rql"), &["rql"], 64)
                .unwrap()
                .source(),
            "(name \"A\")"
        );
        assert!(matches!(
            read_workspace_document(&root, Path::new("outside-link.rql"), &["rql"], 64),
            Err(WorkspaceDocumentError::PathEscapesWorkspace { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_file_fifo_is_rejected_without_blocking() {
        let workspace = TempDir::new().unwrap();
        let fifo_path = workspace.path().join("query.rql");
        create_fifo(&fifo_path);
        let root = WorkspaceRoot::open(workspace.path()).unwrap();

        let result = assert_fifo_operations_return_promptly(vec![fifo_path], || {
            read_workspace_document(&root, Path::new("query.rql"), &["rql"], 64)
        });
        assert!(matches!(
            result,
            Err(WorkspaceDocumentError::NotRegularFile { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn directory_entries_refuse_symlink_replacement_after_classification() {
        let workspace = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("models")).unwrap();
        fs::create_dir(workspace.path().join("models/nested")).unwrap();
        fs::write(workspace.path().join("models/endpoint.rqlp"), "endpoint").unwrap();
        fs::create_dir(workspace.path().join("replacement-directory")).unwrap();
        fs::write(workspace.path().join("replacement.rqlp"), "replacement").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        let directory = root.open_directory(Path::new("models")).unwrap();
        let mut entries = directory.entries_up_to(usize::MAX).unwrap().unwrap();
        let file = entries.remove(
            entries
                .iter()
                .position(|entry| entry.relative_path() == Path::new("models/endpoint.rqlp"))
                .unwrap(),
        );
        let nested = entries.remove(
            entries
                .iter()
                .position(|entry| entry.relative_path() == Path::new("models/nested"))
                .unwrap(),
        );

        fs::remove_file(workspace.path().join("models/endpoint.rqlp")).unwrap();
        symlink(
            "../replacement.rqlp",
            workspace.path().join("models/endpoint.rqlp"),
        )
        .unwrap();
        fs::remove_dir(workspace.path().join("models/nested")).unwrap();
        symlink(
            "../replacement-directory",
            workspace.path().join("models/nested"),
        )
        .unwrap();

        assert!(matches!(
            file.read_document(&["rqlp"], 64),
            Err(WorkspaceDocumentError::OpenFile { .. })
        ));
        assert!(matches!(
            nested.open_directory(),
            Err(WorkspaceDocumentError::OpenDirectory { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn directory_entries_reject_fifo_replacement_without_blocking() {
        let workspace = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("models")).unwrap();
        fs::create_dir(workspace.path().join("models/nested")).unwrap();
        fs::write(workspace.path().join("models/endpoint.rqlp"), "endpoint").unwrap();
        let root = WorkspaceRoot::open(workspace.path()).unwrap();
        let directory = root.open_directory(Path::new("models")).unwrap();
        let mut entries = directory.entries_up_to(usize::MAX).unwrap().unwrap();
        let file = entries.remove(
            entries
                .iter()
                .position(|entry| entry.relative_path() == Path::new("models/endpoint.rqlp"))
                .unwrap(),
        );
        let nested = entries.remove(
            entries
                .iter()
                .position(|entry| entry.relative_path() == Path::new("models/nested"))
                .unwrap(),
        );

        let file_path = workspace.path().join("models/endpoint.rqlp");
        let directory_path = workspace.path().join("models/nested");
        fs::remove_file(&file_path).unwrap();
        fs::remove_dir(&directory_path).unwrap();
        create_fifo(&file_path);
        create_fifo(&directory_path);

        let (file_result, directory_result) =
            assert_fifo_operations_return_promptly(vec![file_path, directory_path], || {
                (file.read_document(&["rqlp"], 64), nested.open_directory())
            });
        assert!(matches!(
            file_result,
            Err(WorkspaceDocumentError::NotRegularFile { .. })
        ));
        assert!(matches!(
            directory_result,
            Err(WorkspaceDocumentError::OpenDirectory { .. })
        ));
    }
}
