//! Deterministic, symlink-free traversal for explicit endpoint directories.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::analyzer::policy::{DirectoryScope, RqlpDocument};
use crate::analyzer::semantic::{WorkspaceRelativePath, WorkspaceRelativePathError};
use crate::workspace_document::{
    WorkspaceDirectoryEntry, WorkspaceDirectoryEntryKind, WorkspaceDocument,
    WorkspaceDocumentError, WorkspaceRoot,
};

use super::super::source::{
    MAX_RQLP_SOURCE_BYTES, PolicySourceIdentityError, workspace_policy_source_identity,
};
use super::{LoadedRqlpSource, PolicyDocumentLoadError, parse_workspace_rqlp_document};

pub(crate) const MAX_MATCH_DIRECTORY_DEPTH: usize = 32;
pub(crate) const MAX_MATCH_DIRECTORY_CANDIDATES: usize = 4_096;
pub(crate) const MAX_MATCH_DIRECTORY_ENTRIES: usize = 65_536;
pub(crate) const MAX_MATCH_DIRECTORY_SOURCE_BYTES: usize = 128 * 1024 * 1024;

/// Per-registry lowering of the schema-fixed directory traversal ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MatchDirectoryLimits {
    max_depth: usize,
    max_candidates: usize,
    max_entries: usize,
    max_source_bytes: usize,
}

impl MatchDirectoryLimits {
    pub(crate) fn with_max_depth(
        mut self,
        max_depth: usize,
    ) -> Result<Self, MatchDirectoryLimitError> {
        if max_depth > MAX_MATCH_DIRECTORY_DEPTH {
            return Err(MatchDirectoryLimitError::Depth {
                requested: max_depth,
                maximum: MAX_MATCH_DIRECTORY_DEPTH,
            });
        }
        self.max_depth = max_depth;
        Ok(self)
    }

    pub(crate) fn with_max_candidates(
        mut self,
        max_candidates: usize,
    ) -> Result<Self, MatchDirectoryLimitError> {
        if max_candidates > MAX_MATCH_DIRECTORY_CANDIDATES {
            return Err(MatchDirectoryLimitError::Candidates {
                requested: max_candidates,
                maximum: MAX_MATCH_DIRECTORY_CANDIDATES,
            });
        }
        self.max_candidates = max_candidates;
        Ok(self)
    }

    pub(crate) fn with_max_entries(
        mut self,
        max_entries: usize,
    ) -> Result<Self, MatchDirectoryLimitError> {
        if max_entries > MAX_MATCH_DIRECTORY_ENTRIES {
            return Err(MatchDirectoryLimitError::Entries {
                requested: max_entries,
                maximum: MAX_MATCH_DIRECTORY_ENTRIES,
            });
        }
        self.max_entries = max_entries;
        Ok(self)
    }

    pub(crate) fn with_max_source_bytes(
        mut self,
        max_source_bytes: usize,
    ) -> Result<Self, MatchDirectoryLimitError> {
        if max_source_bytes > MAX_MATCH_DIRECTORY_SOURCE_BYTES {
            return Err(MatchDirectoryLimitError::SourceBytes {
                requested: max_source_bytes,
                maximum: MAX_MATCH_DIRECTORY_SOURCE_BYTES,
            });
        }
        self.max_source_bytes = max_source_bytes;
        Ok(self)
    }
}

impl Default for MatchDirectoryLimits {
    fn default() -> Self {
        Self {
            max_depth: MAX_MATCH_DIRECTORY_DEPTH,
            max_candidates: MAX_MATCH_DIRECTORY_CANDIDATES,
            max_entries: MAX_MATCH_DIRECTORY_ENTRIES,
            max_source_bytes: MAX_MATCH_DIRECTORY_SOURCE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchDirectoryLimitError {
    Depth { requested: usize, maximum: usize },
    Candidates { requested: usize, maximum: usize },
    Entries { requested: usize, maximum: usize },
    SourceBytes { requested: usize, maximum: usize },
}

impl fmt::Display for MatchDirectoryLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Depth { requested, maximum } => write!(
                formatter,
                "match-directory depth limit {requested} exceeds schema maximum {maximum}"
            ),
            Self::Candidates { requested, maximum } => write!(
                formatter,
                "match-directory candidate limit {requested} exceeds schema maximum {maximum}"
            ),
            Self::Entries { requested, maximum } => write!(
                formatter,
                "match-directory entry limit {requested} exceeds schema maximum {maximum}"
            ),
            Self::SourceBytes { requested, maximum } => write!(
                formatter,
                "match-directory source-byte limit {requested} exceeds schema maximum {maximum}"
            ),
        }
    }
}

impl std::error::Error for MatchDirectoryLimitError {}

/// Complete result of one path-set-stable endpoint directory read.
#[derive(Debug)]
pub(crate) struct TransactionalEndpointDirectory {
    entries: Vec<LoadedRqlpSource>,
}

impl TransactionalEndpointDirectory {
    pub(crate) fn entries(&self) -> &[LoadedRqlpSource] {
        &self.entries
    }

    pub(crate) fn into_entries(self) -> Vec<LoadedRqlpSource> {
        self.entries
    }
}

/// Enumerate and parse every `.rqlp` endpoint candidate transactionally.
pub(crate) fn enumerate_endpoint_directory(
    root: &WorkspaceRoot,
    directory: &WorkspaceRelativePath,
    scope: DirectoryScope,
    limits: MatchDirectoryLimits,
) -> Result<TransactionalEndpointDirectory, EndpointDirectoryError> {
    enumerate_endpoint_directory_with_hook(root, directory, scope, limits, || {})
}

fn enumerate_endpoint_directory_with_hook(
    root: &WorkspaceRoot,
    directory: &WorkspaceRelativePath,
    scope: DirectoryScope,
    limits: MatchDirectoryLimits,
    after_first_enumeration: impl FnOnce(),
) -> Result<TransactionalEndpointDirectory, EndpointDirectoryError> {
    let first = enumerate(root, directory.as_path(), scope, limits, true)?;
    after_first_enumeration();
    let second = enumerate(root, directory.as_path(), scope, limits, false)?;
    if first.paths != second.paths {
        return Err(EndpointDirectoryError::DirectoryChangedDuringLoad {
            directory: directory.clone(),
            before: first.paths,
            after: second.paths,
        });
    }

    let mut entries = Vec::with_capacity(first.documents.len());
    for document in first.documents {
        let loaded = parse_workspace_rqlp_document(document)?;
        if !matches!(loaded.parsed().document(), RqlpDocument::Endpoint { .. }) {
            return Err(EndpointDirectoryError::WrongDocumentKind {
                path: loaded.workspace_path().clone(),
            });
        }
        entries.push(loaded);
    }
    entries.sort_by(|left, right| left.workspace_path().cmp(right.workspace_path()));

    Ok(TransactionalEndpointDirectory { entries })
}

struct Enumeration {
    paths: Vec<PathBuf>,
    documents: Vec<WorkspaceDocument>,
}

struct DirectoryFrame {
    depth: usize,
    entries: std::vec::IntoIter<WorkspaceDirectoryEntry>,
}

fn enumerate(
    root: &WorkspaceRoot,
    directory: &Path,
    scope: DirectoryScope,
    limits: MatchDirectoryLimits,
    read_documents: bool,
) -> Result<Enumeration, EndpointDirectoryError> {
    let root_directory = root.open_directory(directory)?;
    let mut paths = Vec::new();
    let mut documents = Vec::new();
    let mut retained_source_bytes = 0_usize;
    let root_entries = root_directory
        .entries_up_to(limits.max_entries)?
        .ok_or_else(|| EndpointDirectoryError::EntryLimitExceeded {
            directory: directory.to_path_buf(),
            maximum: limits.max_entries,
        })?;
    let mut visited_entries = root_entries.len();
    let mut stack = vec![DirectoryFrame {
        depth: 0,
        entries: root_entries.into_iter(),
    }];

    while !stack.is_empty() {
        let next = stack
            .last_mut()
            .and_then(|frame| frame.entries.next().map(|entry| (entry, frame.depth)));
        let Some((entry, depth)) = next else {
            stack.pop();
            continue;
        };

        match entry.kind() {
            WorkspaceDirectoryEntryKind::Symlink | WorkspaceDirectoryEntryKind::Other => {}
            WorkspaceDirectoryEntryKind::Directory if scope == DirectoryScope::Direct => {}
            WorkspaceDirectoryEntryKind::Directory => {
                let child_depth = depth + 1;
                if child_depth > limits.max_depth {
                    return Err(EndpointDirectoryError::DepthExceeded {
                        path: entry.relative_path().to_path_buf(),
                        maximum: limits.max_depth,
                    });
                }
                let child = entry.open_directory()?;
                let remaining_entries = limits
                    .max_entries
                    .checked_sub(visited_entries)
                    .expect("visited directory entries never exceed their limit");
                let child_entries = child.entries_up_to(remaining_entries)?.ok_or_else(|| {
                    EndpointDirectoryError::EntryLimitExceeded {
                        directory: directory.to_path_buf(),
                        maximum: limits.max_entries,
                    }
                })?;
                visited_entries += child_entries.len();
                stack.push(DirectoryFrame {
                    depth: child_depth,
                    entries: child_entries.into_iter(),
                });
            }
            WorkspaceDirectoryEntryKind::File => {
                if entry
                    .relative_path()
                    .extension()
                    .and_then(|value| value.to_str())
                    != Some("rqlp")
                {
                    continue;
                }
                let workspace_path = WorkspaceRelativePath::try_from_path(entry.relative_path())
                    .map_err(|source| EndpointDirectoryError::InvalidWorkspacePath {
                        path: entry.relative_path().to_path_buf(),
                        source,
                    })?;
                workspace_policy_source_identity(&workspace_path)
                    .map_err(|source| EndpointDirectoryError::InvalidSourceIdentity { source })?;
                if paths.len() >= limits.max_candidates {
                    return Err(EndpointDirectoryError::CandidateLimitExceeded {
                        directory: directory.to_path_buf(),
                        maximum: limits.max_candidates,
                    });
                }
                paths.push(entry.relative_path().to_path_buf());
                if read_documents {
                    let remaining_source_bytes = limits
                        .max_source_bytes
                        .checked_sub(retained_source_bytes)
                        .expect("retained directory bytes never exceed their limit");
                    let document = entry
                        .read_document(
                            &["rqlp"],
                            (MAX_RQLP_SOURCE_BYTES.min(remaining_source_bytes)) as u64,
                        )
                        .map_err(|error| {
                            if remaining_source_bytes < MAX_RQLP_SOURCE_BYTES
                                && matches!(error, WorkspaceDocumentError::TooLarge { .. })
                            {
                                EndpointDirectoryError::SourceByteLimitExceeded {
                                    directory: directory.to_path_buf(),
                                    maximum: limits.max_source_bytes,
                                }
                            } else {
                                EndpointDirectoryError::Workspace(error)
                            }
                        })?;
                    retained_source_bytes = retained_source_bytes
                        .checked_add(document.source().len())
                        .filter(|total| *total <= limits.max_source_bytes)
                        .ok_or_else(|| EndpointDirectoryError::SourceByteLimitExceeded {
                            directory: directory.to_path_buf(),
                            maximum: limits.max_source_bytes,
                        })?;
                    documents.push(document);
                }
            }
        }
    }

    paths.sort();
    documents.sort_by(|left, right| left.relative_path().cmp(right.relative_path()));
    Ok(Enumeration { paths, documents })
}

#[derive(Debug)]
pub(crate) enum EndpointDirectoryError {
    Workspace(WorkspaceDocumentError),
    Policy(PolicyDocumentLoadError),
    InvalidWorkspacePath {
        path: PathBuf,
        source: WorkspaceRelativePathError,
    },
    InvalidSourceIdentity {
        source: PolicySourceIdentityError,
    },
    DepthExceeded {
        path: PathBuf,
        maximum: usize,
    },
    CandidateLimitExceeded {
        directory: PathBuf,
        maximum: usize,
    },
    EntryLimitExceeded {
        directory: PathBuf,
        maximum: usize,
    },
    SourceByteLimitExceeded {
        directory: PathBuf,
        maximum: usize,
    },
    DirectoryChangedDuringLoad {
        directory: WorkspaceRelativePath,
        before: Vec<PathBuf>,
        after: Vec<PathBuf>,
    },
    WrongDocumentKind {
        path: WorkspaceRelativePath,
    },
}

impl fmt::Display for EndpointDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::InvalidWorkspacePath { path, source } => write!(
                formatter,
                "invalid portable match-directory path `{}`: {source}",
                path.display()
            ),
            Self::InvalidSourceIdentity { source } => {
                write!(
                    formatter,
                    "invalid match-directory source identity: {source}"
                )
            }
            Self::DepthExceeded { path, maximum } => write!(
                formatter,
                "match-directory recursion exceeds depth {maximum} at `{}`",
                path.display()
            ),
            Self::CandidateLimitExceeded { directory, maximum } => write!(
                formatter,
                "match-directory `{}` contains more than {maximum} `.rqlp` candidates",
                directory.display()
            ),
            Self::EntryLimitExceeded { directory, maximum } => write!(
                formatter,
                "match-directory `{}` contains more than {maximum} total entries",
                directory.display()
            ),
            Self::SourceByteLimitExceeded { directory, maximum } => write!(
                formatter,
                "match-directory `{}` retains more than {maximum} source bytes",
                directory.display()
            ),
            Self::DirectoryChangedDuringLoad {
                directory,
                before,
                after,
            } => write!(
                formatter,
                "match-directory `{directory}` changed while it was being loaded ({} paths before, {} after)",
                before.len(),
                after.len()
            ),
            Self::WrongDocumentKind { path } => write!(
                formatter,
                "match-directory candidate `{path}` must contain an endpoint document"
            ),
        }
    }
}

impl std::error::Error for EndpointDirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::InvalidWorkspacePath { source, .. } => Some(source),
            Self::InvalidSourceIdentity { source } => Some(source),
            Self::DepthExceeded { .. }
            | Self::CandidateLimitExceeded { .. }
            | Self::EntryLimitExceeded { .. }
            | Self::SourceByteLimitExceeded { .. }
            | Self::DirectoryChangedDuringLoad { .. }
            | Self::WrongDocumentKind { .. } => None,
        }
    }
}

impl From<WorkspaceDocumentError> for EndpointDirectoryError {
    fn from(error: WorkspaceDocumentError) -> Self {
        Self::Workspace(error)
    }
}

impl From<PolicyDocumentLoadError> for EndpointDirectoryError {
    fn from(error: PolicyDocumentLoadError) -> Self {
        Self::Policy(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::ffi::CString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn create_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is a live NUL-terminated string and `mkfifo` retains
        // neither the pointer nor any Rust-owned memory.
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
    }

    fn endpoint(id: &str) -> String {
        format!(
            "(endpoint :id \"{id}\" :name \"{id}\" :display-name \"{id}\" :role source :categories [test] :selector (rql (name \"{id}\")) :binding matched-value :supersedes [])"
        )
    }

    #[test]
    fn direct_and_recursive_results_are_sorted_and_endpoint_only() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("models/nested")).unwrap();
        fs::write(temp.path().join("models/z.rqlp"), endpoint("z")).unwrap();
        fs::write(temp.path().join("models/a.rqlp"), endpoint("a")).unwrap();
        fs::write(temp.path().join("models/ignored.txt"), "ignored").unwrap();
        fs::write(temp.path().join("models/nested/b.rqlp"), endpoint("b")).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();

        let direct = enumerate_endpoint_directory(
            &root,
            &path,
            DirectoryScope::Direct,
            MatchDirectoryLimits::default(),
        )
        .unwrap();
        assert_eq!(
            direct
                .entries()
                .iter()
                .map(|entry| entry.workspace_path().as_str())
                .collect::<Vec<_>>(),
            ["models/a.rqlp", "models/z.rqlp"]
        );

        let recursive = enumerate_endpoint_directory(
            &root,
            &path,
            DirectoryScope::Recursive,
            MatchDirectoryLimits::default(),
        )
        .unwrap();
        assert_eq!(
            recursive
                .entries()
                .iter()
                .map(|entry| entry.workspace_path().as_str())
                .collect::<Vec<_>>(),
            ["models/a.rqlp", "models/nested/b.rqlp", "models/z.rqlp"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_traversal_skips_file_and_directory_symlinks() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("models/real")).unwrap();
        fs::write(temp.path().join("models/a.rqlp"), endpoint("a")).unwrap();
        fs::write(temp.path().join("models/real/b.rqlp"), endpoint("b")).unwrap();
        symlink("a.rqlp", temp.path().join("models/file-link.rqlp")).unwrap();
        symlink("real", temp.path().join("models/directory-link")).unwrap();
        create_fifo(&temp.path().join("models/special.rqlp"));
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();

        let loaded = enumerate_endpoint_directory(
            &root,
            &path,
            DirectoryScope::Recursive,
            MatchDirectoryLimits::default(),
        )
        .unwrap();

        assert_eq!(loaded.entries().len(), 2);
    }

    #[test]
    fn detects_path_set_race_transactionally() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("models")).unwrap();
        fs::write(temp.path().join("models/a.rqlp"), endpoint("a")).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();

        let error = enumerate_endpoint_directory_with_hook(
            &root,
            &path,
            DirectoryScope::Direct,
            MatchDirectoryLimits::default(),
            || {
                fs::write(temp.path().join("models/b.rqlp"), endpoint("b")).unwrap();
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EndpointDirectoryError::DirectoryChangedDuringLoad { .. }
        ));
    }

    #[test]
    fn aggregate_source_bytes_are_bounded_before_documents_are_retained() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("models")).unwrap();
        let first = endpoint("a");
        let second = endpoint("b");
        fs::write(temp.path().join("models/a.rqlp"), &first).unwrap();
        fs::write(temp.path().join("models/b.rqlp"), &second).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();
        let limits = MatchDirectoryLimits::default()
            .with_max_source_bytes(first.len() + second.len() - 1)
            .unwrap();

        let error =
            enumerate_endpoint_directory(&root, &path, DirectoryScope::Direct, limits).unwrap_err();

        assert!(matches!(
            error,
            EndpointDirectoryError::SourceByteLimitExceeded { maximum, .. }
                if maximum == first.len() + second.len() - 1
        ));
    }

    #[test]
    fn total_entry_limit_counts_irrelevant_files_before_retention() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("models")).unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(temp.path().join("models").join(name), "ignored").unwrap();
        }
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();
        let limits = MatchDirectoryLimits::default().with_max_entries(2).unwrap();

        let error =
            enumerate_endpoint_directory(&root, &path, DirectoryScope::Direct, limits).unwrap_err();

        assert!(matches!(
            error,
            EndpointDirectoryError::EntryLimitExceeded { maximum: 2, .. }
        ));
    }

    #[test]
    fn explicit_directory_resolution_does_not_charge_workspace_siblings() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("models")).unwrap();
        for index in 0..32 {
            fs::write(
                temp.path().join(format!("workspace-sibling-{index}.txt")),
                "ignored",
            )
            .unwrap();
        }
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();
        let limits = MatchDirectoryLimits::default().with_max_entries(1).unwrap();

        let loaded =
            enumerate_endpoint_directory(&root, &path, DirectoryScope::Direct, limits).unwrap();

        assert!(loaded.entries().is_empty());
    }

    #[test]
    fn total_entry_limit_counts_empty_recursive_directories() {
        let temp = TempDir::new().unwrap();
        for name in ["a", "b", "c"] {
            fs::create_dir_all(temp.path().join("models").join(name)).unwrap();
        }
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();
        let limits = MatchDirectoryLimits::default().with_max_entries(2).unwrap();

        let error = enumerate_endpoint_directory(&root, &path, DirectoryScope::Recursive, limits)
            .unwrap_err();

        assert!(matches!(
            error,
            EndpointDirectoryError::EntryLimitExceeded { maximum: 2, .. }
        ));
    }

    #[test]
    fn directory_candidate_identity_rejects_control_characters_transactionally() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("models")).unwrap();
        fs::write(temp.path().join("models/bad\u{85}.rqlp"), endpoint("bad")).unwrap();
        let root = WorkspaceRoot::open(temp.path()).unwrap();
        let path = WorkspaceRelativePath::new("models").unwrap();

        let error = enumerate_endpoint_directory(
            &root,
            &path,
            DirectoryScope::Direct,
            MatchDirectoryLimits::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EndpointDirectoryError::InvalidSourceIdentity {
                source: PolicySourceIdentityError::ControlCharacter
            }
        ));
    }

    #[test]
    fn source_byte_limit_cannot_exceed_the_hard_maximum() {
        let error = MatchDirectoryLimits::default()
            .with_max_source_bytes(MAX_MATCH_DIRECTORY_SOURCE_BYTES + 1)
            .unwrap_err();

        assert_eq!(
            error,
            MatchDirectoryLimitError::SourceBytes {
                requested: MAX_MATCH_DIRECTORY_SOURCE_BYTES + 1,
                maximum: MAX_MATCH_DIRECTORY_SOURCE_BYTES,
            }
        );
    }
}
