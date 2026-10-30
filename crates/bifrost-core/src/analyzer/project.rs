use super::project_reads::{
    ProjectReadReceipt, ProjectReadSlot, ReadCapability, listing_read, publish_directory,
    publish_file_set, publish_git_ignore_presence_only, publish_ignore_rules, publish_receipt,
};
use crate::analyzer::common::{language_for_file, workspace_language_for_file};
use crate::analyzer::{Language, ProjectFile};
use crate::gitblob;
use crate::path_normalization::NormalizePath;
use crate::util::throttled_log::ThrottledLog;
use git2::{ObjectType, Oid};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::{WalkBuilder, WalkState};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Default upper bound (8 MiB) on the size of a single in-memory overlay.
/// Picked to cover all hand-written source comfortably while bounding the
/// blast radius of an editor that opens a multi-MB minified bundle or vendor
/// blob — tree-sitter still parses such files, but holding many of them in
/// memory simultaneously across an LSP session quickly becomes expensive.
/// `OverlayProject::set` rejects content above this cap (and logs once per
/// path per `OVERLAY_REJECTION_LOG_THROTTLE`); reads fall through to disk
/// instead.
pub const DEFAULT_MAX_OVERLAY_BYTES: usize = 8 * 1024 * 1024;

/// Minimum interval between stderr lines reporting an oversized overlay for
/// the same path. didChange fires per-keystroke, so an editor parked on a
/// >8 MB file would otherwise spam thousands of identical log lines.
const OVERLAY_REJECTION_LOG_THROTTLE: Duration = Duration::from_secs(60);

/// Soft cap on the throttle map's entry count. The map only grows on
/// rejections, which are rare in practice — this exists to bound the
/// pathological case (a client sending many unique oversized URIs over a
/// session) so the cap-the-memory module isn't itself unbounded. When the
/// limit is exceeded, stale entries past the throttle window are pruned;
/// if that doesn't reclaim enough, the rest are dropped wholesale (worst
/// case: a few paths emit one redundant log line each).
const OVERLAY_REJECTION_LOG_MAX_ENTRIES: usize = 256;

pub const BIFROST_IGNORE_FILE_NAME: &str = ".bifrostignore";

fn files_for_language(
    files: &BTreeSet<ProjectFile>,
    language: Language,
    mut file_language: impl FnMut(&ProjectFile) -> Language,
) -> BTreeSet<ProjectFile> {
    files
        .iter()
        .filter(|file| file_language(file) == language)
        .cloned()
        .collect()
}

fn relative_path_from_normalized_root<'a>(abs_path: &'a Path, root: &Path) -> Option<&'a Path> {
    abs_path.strip_prefix(root).ok()
}

fn relative_path_under_root(abs_path: &Path, root: &Path) -> Option<PathBuf> {
    let normalized = abs_path.to_path_buf().normalize();
    relative_path_from_normalized_root(&normalized, root).map(Path::to_path_buf)
}

/// One workspace tree's `.bifrostignore` rules, compiled per directory.
///
/// `.bifrostignore` uses gitignore syntax and excludes the paths it matches
/// from code intelligence -- the analyzable file set and
/// [`Project::is_bifrostignored`] -- while leaving them in the file-tool view
/// that [`Project::all_files`] serves. Every project that answers those
/// questions answers them through this matcher, so one interpretation of the
/// rules serves the working tree and any other tree a request analyzes.
///
/// The rules arrive through the caller rather than from the filesystem, because
/// a project does not necessarily keep its bytes there: an exported revision
/// image can hold empty placeholder files and serve every byte from the
/// repository's object database, so reading `.bifrostignore` from that root
/// would compile an empty rule set and ignore nothing.
#[derive(Debug)]
pub struct BifrostIgnoreMatcher {
    root: PathBuf,
    by_directory: HashMap<PathBuf, Gitignore>,
    rules_digest: [u8; 32],
    listing_receipt: ProjectReadReceipt,
}

/// Git ignores a byte-order mark at the start of an ignore file, and so does
/// the `ignore` crate's own file reader. Rules fed line by line must too.
const UTF8_BOM: &str = "\u{feff}";

impl BifrostIgnoreMatcher {
    /// Compile the ignore file of every directory that contains one of `files`,
    /// plus `root` itself.
    ///
    /// `read_ignore_file` receives the absolute path of each candidate
    /// `.bifrostignore` and answers `None` for a directory that has none. It is
    /// the only source of rule bytes: nothing here reads the filesystem.
    pub fn build_with(
        root: &Path,
        files: &BTreeSet<ProjectFile>,
        mut read_ignore_file: impl FnMut(&Path) -> io::Result<Option<String>>,
    ) -> io::Result<Self> {
        let mut directories = HashSet::from([root.to_path_buf()]);
        for file in files {
            let abs_path = file.abs_path();
            let mut directory = abs_path.parent();
            while let Some(path) = directory {
                if !path.starts_with(root) {
                    break;
                }
                directories.insert(path.to_path_buf());
                if path == root {
                    break;
                }
                directory = path.parent();
            }
        }

        let mut by_directory = HashMap::new();
        let mut rule_sets = Vec::new();
        for directory in directories {
            let ignore_file = directory.join(BIFROST_IGNORE_FILE_NAME);
            let Some(rules) = read_ignore_file(&ignore_file)? else {
                continue;
            };
            let mut builder = GitignoreBuilder::new(&directory);
            let mut normalized_rules = Vec::<String>::new();
            for (index, line) in rules.lines().enumerate() {
                let line = if index == 0 {
                    line.trim_start_matches(UTF8_BOM)
                } else {
                    line
                };
                // Match GitignoreBuilder's normalization of rule VALUES:
                // comments/empty lines add no glob; escaped trailing spaces
                // remain part of the pattern. Preserve precedence order.
                let normalized = if line.ends_with("\\ ") {
                    line
                } else {
                    line.trim_end()
                };
                if !normalized.is_empty() && !normalized.starts_with('#') {
                    normalized_rules.push(normalized.to_owned());
                }
                builder
                    .add_line(Some(ignore_file.clone()), line)
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "failed to parse Bifrost ignore file {} line {}: {error}",
                                ignore_file.display(),
                                index + 1
                            ),
                        )
                    })?;
            }
            let matcher = builder.build().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to compile Bifrost ignore file {}: {error}",
                        ignore_file.display()
                    ),
                )
            })?;
            if !normalized_rules.is_empty() {
                let relative = directory
                    .strip_prefix(root)
                    .expect("ignore directory belongs to root");
                rule_sets.push((
                    crate::path_utils::workspace_relative_slash_path(relative),
                    normalized_rules,
                ));
            }
            by_directory.insert(directory, matcher);
        }

        rule_sets.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut hash = crate::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-workspace-ignore-rules:v1",
        );
        // Bifrost has no implicit .bifrostignore patterns. Name that default
        // explicitly so a future built-in rule change must rotate it.
        hash.field("builtin_rules", b"none:v1");
        hash.sequence("directories", &rule_sets, |hash, (directory, rules)| {
            hash.field("directory", directory.as_bytes());
            hash.sequence("rules", rules, |hash, rule| {
                hash.field("rule", rule.as_bytes())
            });
        });
        let mut matcher = Self {
            root: root.to_path_buf(),
            by_directory,
            rules_digest: hash.finish(),
            listing_receipt: ProjectReadReceipt::default(),
        };
        matcher.listing_receipt = matcher.receipt_for(files);
        Ok(matcher)
    }

    /// Compile the ignore files the filesystem holds beneath `root`. A
    /// candidate path that is not a regular file contributes no rules, exactly
    /// as a directory with no ignore file does.
    fn build(root: &Path, files: &BTreeSet<ProjectFile>) -> io::Result<Self> {
        Self::build_with(root, files, |path| {
            if !path.is_file() {
                return Ok(None);
            }
            #[cfg(any(test, feature = "test-support"))]
            super::project_reads::count_project_io(super::project_reads::ProjectIo::Rule);
            std::fs::read_to_string(path).map(Some)
        })
    }

    /// The complete listing certificate built beside these same rule inputs.
    pub fn listing_receipt(&self) -> ProjectReadReceipt {
        self.listing_receipt.clone()
    }

    fn receipt_for(&self, files: &BTreeSet<ProjectFile>) -> ProjectReadReceipt {
        let paths = files
            .iter()
            .map(|file| {
                (
                    crate::path_utils::rel_path_string(file),
                    self.is_ignored(file),
                    false,
                )
            })
            .collect::<Vec<_>>();
        let selected = files
            .iter()
            .filter(|file| {
                Language::ANALYZABLE.contains(&file.language()) && !self.is_ignored(file)
            })
            .map(|file| (crate::path_utils::rel_path_string(file), false))
            .collect::<Vec<_>>();
        super::project_reads::file_set_receipt_from_entries(
            paths,
            selected,
            Vec::new(),
            self.rules_digest,
        )
    }

    pub const fn rules_digest(&self) -> [u8; 32] {
        self.rules_digest
    }

    pub fn empty_rules_digest() -> [u8; 32] {
        Self::build_with(Path::new(""), &BTreeSet::new(), |_| Ok(None))
            .expect("empty ignore rules build")
            .rules_digest()
    }

    /// Whether the rules exclude `file` from code intelligence, honoring
    /// directory rules and later whitelist rules the way Git does.
    pub fn is_ignored(&self, file: &ProjectFile) -> bool {
        let mut active = Vec::new();
        if let Some(matcher) = self.by_directory.get(&self.root) {
            active.push(matcher);
        }

        let mut directory = self.root.clone();
        if let Some(parent) = file.rel_path().parent() {
            for component in parent.components() {
                directory.push(component);
                if Self::last_match_is_ignored(&active, &directory, true) {
                    return true;
                }
                if let Some(matcher) = self.by_directory.get(&directory) {
                    active.push(matcher);
                }
            }
        }

        Self::last_match_is_ignored(&active, &file.abs_path(), false)
    }

    /// Whether `rel_path` is ignored beneath this matcher's workspace root.
    pub fn is_ignored_path(&self, rel_path: &Path) -> bool {
        self.is_ignored(&ProjectFile::new(self.root.clone(), rel_path.to_path_buf()))
    }

    fn last_match_is_ignored(matchers: &[&Gitignore], path: &Path, is_dir: bool) -> bool {
        let mut ignored = false;
        for matcher in matchers {
            let candidate = matcher.matched(path, is_dir);
            if candidate.is_ignore() {
                ignored = true;
            } else if candidate.is_whitelist() {
                ignored = false;
            }
        }
        ignored
    }
}

/// Opaque, process-local revision assigned whenever an overlay is accepted.
///
/// Revisions are monotonic across live [`OverlayProject`] snapshots. Source
/// consumers use them only as identity tokens; source content remains the
/// authoritative semantic revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OverlayRevision(u64);

impl OverlayRevision {
    /// Construct a token from a producer-owned monotonic counter.
    ///
    /// Project implementations, rather than consumers, assign these values.
    pub const fn from_monotonic_counter(value: u64) -> Self {
        assert!(value != 0, "overlay revisions start at one");
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Origin captured together with one immutable project source snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProjectSourceOrigin {
    Disk,
    Overlay(OverlayRevision),
}

/// Immutable decoded source, original content identity, and origin from one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSourceSnapshot {
    source: Arc<str>,
    oid: Oid,
    origin: ProjectSourceOrigin,
}

impl ProjectSourceSnapshot {
    /// Capture text supplied by a custom source reader, identified by its UTF-8 bytes.
    pub fn disk(source: impl Into<Arc<str>>) -> Self {
        let source = source.into();
        Self {
            oid: Oid::hash_object(ObjectType::Blob, source.as_bytes())
                .expect("hashing project source text"),
            source,
            origin: ProjectSourceOrigin::Disk,
        }
    }

    /// Decode disk or revision bytes while retaining their exact blob identity.
    pub fn disk_bytes(bytes: Vec<u8>) -> io::Result<Self> {
        let oid = Oid::hash_object(ObjectType::Blob, &bytes).expect("hashing project source bytes");
        let source = decode_source_bytes(bytes)?.into();
        Ok(Self {
            source,
            oid,
            origin: ProjectSourceOrigin::Disk,
        })
    }

    pub fn disk_bytes_limited(bytes: Vec<u8>, max_bytes: usize) -> io::Result<Option<Self>> {
        if bytes.len() > max_bytes {
            return Ok(None);
        }
        Self::disk_bytes(bytes).map(Some)
    }

    pub fn overlay(source: impl Into<Arc<str>>, revision: OverlayRevision) -> Self {
        let source = source.into();
        Self {
            oid: Oid::hash_object(ObjectType::Blob, source.as_bytes())
                .expect("hashing project overlay text"),
            source,
            origin: ProjectSourceOrigin::Overlay(revision),
        }
    }

    /// The original bytes' blob identity, before any lossy source decoding.
    pub const fn oid(&self) -> Oid {
        self.oid
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// Consume the snapshot and retain its immutable source allocation.
    pub fn into_source(self) -> Arc<str> {
        self.source
    }

    pub const fn origin(&self) -> ProjectSourceOrigin {
        self.origin
    }
}

/// How many of a workspace's files a project exposes, for a project that
/// exposes only some of them. Serialized as the `session_subset` marker on a
/// cross-file tool answer so a caller can read "no usages in these N files"
/// rather than "no usages in the workspace" (#2770).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct SubsetCoverage {
    /// The number of files the session covers.
    pub files: usize,
}

/// Whether a project exposes the whole workspace or an explicitly named subset
/// of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectCoverage {
    Whole,
    Subset(SubsetCoverage),
}

impl ProjectCoverage {
    /// The subset descriptor, or `None` for a whole-workspace project.
    pub const fn subset(self) -> Option<SubsetCoverage> {
        match self {
            Self::Whole => None,
            Self::Subset(coverage) => Some(coverage),
        }
    }
}

/// Object-safe access to the concrete Project view receiving a raw getter.
pub trait AsProject {
    fn as_project(&self) -> &dyn Project;
}
impl<T: Project> AsProject for T {
    fn as_project(&self) -> &dyn Project {
        self
    }
}

pub trait Project: AsProject + Send + Sync {
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        None
    }
    fn install_read_recorder(&self, _capability: ReadCapability) -> bool {
        false
    }

    fn ignore_rules_digest(&self) -> io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "custom Project must name its effective ignore rules",
        ))
    }

    fn root(&self) -> &Path;

    /// Published module identity for this project's exact selected revision.
    /// Raw projects return None while building the initial file projection.
    fn selected_module_name(&self, _file: &ProjectFile) -> io::Result<Option<String>> {
        Ok(None)
    }

    /// How much of the workspace under [`Project::root`] this project exposes.
    ///
    /// A project built over an explicitly named set of files answers
    /// [`ProjectCoverage::Subset`]; everything that walks the workspace keeps
    /// the whole-workspace default. Cross-file tool answers publish the subset
    /// descriptor so a caller can tell a scoped answer from a workspace one.
    fn coverage(&self) -> ProjectCoverage {
        ProjectCoverage::Whole
    }
    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        let _ = file;
        self.root().to_path_buf()
    }
    fn analyzer_languages(&self) -> BTreeSet<Language>;
    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>>;
    /// Share one immutable whole-workspace listing when the project owns a
    /// listing cache. The default preserves custom project implementations.
    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.all_files().map(Arc::new)
    }
    /// Whole-workspace file listings this project instance has performed --
    /// the per-instance complexity signal pinned by the issue #1325 regression
    /// tests. Per-instance rather than process-global so a test measures only
    /// its own project's walks: background threads from other analyzers in the
    /// same process (watchers, GC) cannot bleed into the window (the #1099
    /// lesson applied to walk counting).
    fn workspace_file_listing_count(&self) -> usize {
        0
    }
    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>>;

    /// Filter a caller-owned whole-workspace listing for one language.
    ///
    /// Workspace construction uses this hook to let every language delegate
    /// share one build-scoped listing. Projects with additional membership
    /// rules override it; the default selects files by their recognized
    /// language from the supplied set without enumerating the workspace.
    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        publish_file_set(self.as_project(), files)?;
        Ok(files_for_language(files, language, ProjectFile::language))
    }
    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile>;

    /// Whether the workspace could hold a directory at `rel_path` (the empty
    /// path meaning the workspace root itself).
    ///
    /// This exists so callers that only need "is this target a container?" can
    /// ask it without materializing the whole workspace file set. The answer is
    /// allowed to be conservative in one direction only: `false` is
    /// authoritative — no workspace file lives beneath `rel_path` — while
    /// `true` merely means a listing is worth computing. Callers must therefore
    /// still treat an empty listing as "not a directory", exactly as they do
    /// when they filter the file set themselves.
    ///
    /// The default answers by scanning `all_files()`, which is the semantics
    /// every caller had before the pre-check existed; filesystem-backed
    /// projects override it with a single `stat` (#1325).
    fn has_directory(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.directory(self.as_project(), rel_path));
        let exists = self.all_files().is_ok_and(|files| {
            files.iter().any(|file| {
                file.rel_path()
                    .strip_prefix(rel_path)
                    .is_ok_and(|remainder| remainder.components().next().is_some())
            })
        });
        publish_directory(exists);
        exists
    }

    fn file_by_abs_path(&self, abs_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), abs_path));
        let rel_path = relative_path_under_root(abs_path, self.root())?;
        self.file_by_rel_path(&rel_path)
    }

    fn file_by_abs_path_allow_missing(&self, abs_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), abs_path));
        let rel_path = relative_path_under_root(abs_path, self.root())?;
        Some(ProjectFile::new(self.root().to_path_buf(), rel_path))
    }

    fn persistence_root(&self) -> Option<&Path> {
        Some(self.root())
    }

    fn is_gitignored(&self, _rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.git_ignore(self.as_project(), _rel_path));
        publish_git_ignore_presence_only();
        false
    }

    /// Whether `.bifrostignore` excludes this path from code intelligence.
    /// Unlike [`Project::is_gitignored`], this does not describe membership in
    /// [`Project::all_files`]: matching paths remain in the file-tool view.
    fn is_bifrostignored(&self, _rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        publish_ignore_rules(BifrostIgnoreMatcher::empty_rules_digest());
        false
    }

    /// Drop any cached whole-workspace file listing so the next `all_files`
    /// reflects the filesystem again. Observers of workspace change (the
    /// session file watcher, explicit refresh paths) call this; projects
    /// without a listing cache ignore it.
    fn invalidate_cached_file_listing(&self) {}

    /// Update a cached whole-workspace listing for one created, removed or
    /// renamed path without walking the workspace. Returns `false` when the
    /// project cannot decide that path alone, and the caller then invalidates
    /// the listing instead. Projects without a listing cache return `false`.
    fn update_cached_listing_for_path(&self, _rel_path: &Path) -> bool {
        false
    }

    /// Read the source text of `file`. Default reads from disk and decodes it
    /// with [`decode_source_bytes`].
    /// The LSP server overrides this via `OverlayProject` to serve unsaved
    /// buffer content pushed in by `textDocument/did{Open,Change}`
    /// notifications.
    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        match self.project_read_slot() {
            Some(slot) => slot
                .source(
                    self.as_project(),
                    file,
                    || read_disk_source_snapshot(file),
                    |source| Some(source.oid()),
                )
                .map(|snapshot| snapshot.source().to_owned()),
            None => decode_source_bytes(std::fs::read(file.abs_path())?),
        }
    }

    /// Read source only when it fits in `max_bytes`, without allocating the
    /// rest of an oversized on-disk file. `None` means the source exceeded
    /// the caller's limit.
    fn read_source_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<String>> {
        match self.project_read_slot() {
            Some(slot) => slot
                .source(
                    self.as_project(),
                    file,
                    || read_disk_source_snapshot_limited(file, max_bytes),
                    |source| source.as_ref().map(ProjectSourceSnapshot::oid),
                )
                .map(|snapshot| snapshot.map(|snapshot| snapshot.source().to_owned())),
            None => read_disk_source_bytes_limited(file, max_bytes)?
                .map(decode_source_bytes)
                .transpose(),
        }
    }

    /// Capture source text and its disk/overlay identity in one read.
    ///
    /// The default preserves custom `read_source` implementations and hashes
    /// their supplied UTF-8 text. Disk-backed projects override this to retain
    /// the raw byte identity before decoding. Overlay projects capture their
    /// text and opaque revision under the same read lock.
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.read_source(file).map(ProjectSourceSnapshot::disk)
    }

    /// Capture one source snapshot only when it fits in `max_bytes`.
    ///
    /// `None` means the exact snapshot exceeded the limit. Implementations
    /// must decide that before returning source text to parser clients.
    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<ProjectSourceSnapshot>> {
        self.read_source_limited(file, max_bytes)
            .map(|source| source.map(ProjectSourceSnapshot::disk))
    }

    /// True when an in-memory overlay is shadowing `file`'s disk content.
    /// Analyzer persistence consults this to skip baseline writes for files
    /// whose parsed state was computed against unsaved content — otherwise the
    /// on-disk mtime would not change but the baseline row would be wrong.
    /// The unsaved buffers this project layers over its files, if it layers
    /// any.
    ///
    /// A project with no overlay concept answers `None`, which is the same
    /// statement as an empty set and costs no allocation on the path every
    /// non-editor caller takes. See [`WorkspaceOverlayContent`] for why a
    /// content-keyed cache must ask the project rather than the analyzer's
    /// live path map.
    fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.overlays(self.as_project()));
        let answer = None;
        super::project_reads::publish_overlays(&answer);
        answer
    }

    fn has_overlay(&self, file: &ProjectFile) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.overlay_membership(self.as_project(), file.rel_path()));
        let answer = false;
        super::project_reads::publish_overlay_membership(answer);
        answer
    }

    /// Monotonic process-local generation for source that can change behind
    /// an analyzer. Immutable/disk projects use zero because analyzer updates
    /// already create a fresh cache owner.
    fn analysis_generation(&self) -> u64 {
        0
    }
}

fn read_disk_source_snapshot(file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
    #[cfg(any(test, feature = "test-support"))]
    super::project_reads::count_project_io(super::project_reads::ProjectIo::Source);
    ProjectSourceSnapshot::disk_bytes(std::fs::read(file.abs_path())?)
}

fn read_disk_source_snapshot_limited(
    file: &ProjectFile,
    max_bytes: usize,
) -> io::Result<Option<ProjectSourceSnapshot>> {
    match read_disk_source_bytes_limited(file, max_bytes)? {
        Some(bytes) => ProjectSourceSnapshot::disk_bytes_limited(bytes, max_bytes),
        None => Ok(None),
    }
}

fn read_disk_source_bytes_limited(
    file: &ProjectFile,
    max_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    #[cfg(any(test, feature = "test-support"))]
    super::project_reads::count_project_io(super::project_reads::ProjectIo::Source);
    let mut source = Vec::new();
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    std::fs::File::open(file.abs_path())?
        .take(read_limit)
        .read_to_end(&mut source)?;
    Ok((source.len() <= max_bytes).then_some(source))
}

/// A source decoder rejected binary content, rather than failing to read it.
#[derive(Debug)]
pub struct BinarySourceRejection;

impl std::fmt::Display for BinarySourceRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source contains NUL bytes")
    }
}

impl std::error::Error for BinarySourceRejection {}

/// Decode source bytes the way every disk-backed [`Project`] does: legacy
/// non-UTF-8 text is admitted lossily, and UTF-8 text is kept exactly,
/// including any raw NUL byte. Whether a NUL-bearing file may be analyzed is
/// the analyzer's source-admission decision, which needs the exact bytes to
/// prove from the grammar that every NUL is string, comment or text payload.
/// NUL-bearing bytes that are not UTF-8 are rejected as binary: their lossy
/// decoding no longer addresses the original blob, so no proof could hold.
///
/// Public because a project can obtain a file's bytes from somewhere other than
/// the filesystem -- an immutable revision image reads them out of the Git
/// object database -- and the two readings of one file must not decode
/// differently.
pub fn decode_source_bytes(bytes: Vec<u8>) -> io::Result<String> {
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(error) if error.as_bytes().contains(&0) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            BinarySourceRejection,
        )),
        Err(error) => Ok(String::from_utf8_lossy(error.as_bytes()).into_owned()),
    }
}

#[derive(Debug, Clone)]
pub struct TestProject {
    project_reads: ProjectReadSlot,
    root: PathBuf,
    languages: BTreeSet<Language>,
    listing_count: Arc<AtomicUsize>,
}

impl TestProject {
    pub fn new(root: impl Into<PathBuf>, language: Language) -> Self {
        Self::with_languages(root, BTreeSet::from([language]))
    }

    pub fn with_languages(root: impl Into<PathBuf>, languages: BTreeSet<Language>) -> Self {
        let root = validated_test_project_root(root);
        assert!(
            !languages.is_empty(),
            "test project must contain at least one analyzer language"
        );

        Self::with_validated_root_and_languages(root, languages)
    }

    pub fn from_root_with_inferred_languages(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = validated_test_project_root(root);

        let languages = detect_languages(&root)?;
        if languages.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "test project root contains no supported analyzer files: {}",
                    root.display()
                ),
            ));
        }

        Ok(Self::with_validated_root_and_languages(root, languages))
    }

    fn with_validated_root_and_languages(root: PathBuf, languages: BTreeSet<Language>) -> Self {
        Self {
            project_reads: ProjectReadSlot::default(),
            root,
            languages,
            listing_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}

fn validated_test_project_root(root: impl Into<PathBuf>) -> PathBuf {
    let root = root.into().normalize();
    assert!(root.is_absolute(), "test project root must be absolute");
    assert!(root.is_dir(), "test project root must exist");
    root
}

fn filesystem_has_directory(root: &Path, rel_path: &Path) -> bool {
    root.join(rel_path).is_dir()
}

impl Project for TestProject {
    fn ignore_rules_digest(&self) -> io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        let digest = BifrostIgnoreMatcher::empty_rules_digest();
        publish_ignore_rules(digest);
        Ok(digest)
    }
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        Some(&self.project_reads)
    }
    fn install_read_recorder(&self, capability: ReadCapability) -> bool {
        self.project_reads.install(capability);
        true
    }
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot(file),
            |source| Some(source.oid()),
        )
    }

    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<ProjectSourceSnapshot>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot_limited(file, max_bytes),
            |source| source.as_ref().map(ProjectSourceSnapshot::oid),
        )
    }

    fn root(&self) -> &Path {
        self.root_path()
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.project_reads
            .languages(self.as_project(), || self.languages.clone())
    }

    fn workspace_file_listing_count(&self) -> usize {
        self.listing_count.load(Ordering::Relaxed)
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.listing_count.fetch_add(1, Ordering::Relaxed);
        let mut files = BTreeSet::new();

        for entry in WalkDir::new(&self.root) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }

            let rel = entry
                .path()
                .strip_prefix(&self.root)
                .expect("walkdir returned a path outside the project root");
            files.insert(ProjectFile::new(self.root.clone(), rel.to_path_buf()));
        }

        publish_file_set(self, &files)?;
        Ok(files)
    }

    fn has_directory(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.directory(self.as_project(), rel_path));
        let exists = filesystem_has_directory(&self.root, rel_path);
        publish_directory(exists);
        exists
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        let extensions = language.extensions();
        if extensions.is_empty() {
            self.all_files_shared()?;
            return Ok(BTreeSet::new());
        }

        let files = self.all_files()?;
        Ok(files
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| extensions.contains(&ext))
                    .unwrap_or(false)
            })
            .collect())
    }

    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        publish_file_set(self, files)?;
        Ok(files_for_language(files, language, ProjectFile::language))
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.path(self.as_project(), rel_path));
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        (super::project_reads::observed_path_kind(&file.abs_path())
            == super::project_reads::WorkspacePathKind::File)
            .then_some(file)
    }
}

/// Watcher-invalidated cache for the whole-workspace file listing produced by
/// [`collect_workspace_files`] (issue #1401). One instance is shared between a
/// session's [`FilesystemProject`] (serving every `all_files` consumer) and any
/// caller that must answer from the listing without touching session state,
/// such as the `find_filenames` fast path from #1388.
///
/// The cache owns only its own mutex, held for at most one walk's duration, so
/// readers never block behind session write locks held during watcher-delta
/// re-analysis, and a cold cache fills without waiting for the analyzer index
/// build. `invalidate` touches only an atomic and never blocks. Refills go
/// through [`collect_workspace_files`], so the git-index union is recomputed
/// together with the ignore-aware walk: tracked files shadowed by broad ignore
/// patterns stay listed after invalidation.
#[derive(Debug)]
pub struct WorkspaceFileListingCache {
    project_reads: ProjectReadSlot,
    root: PathBuf,
    generation: AtomicU64,
    walks: AtomicUsize,
    cached: Mutex<Option<CachedFileListing>>,
}

#[derive(Debug, Clone)]
struct CachedFileListing {
    generation: u64,
    files: Arc<BTreeSet<ProjectFile>>,
    matcher: Arc<BifrostIgnoreMatcher>,
    receipt: ProjectReadReceipt,
}

impl WorkspaceFileListingCache {
    pub fn new(root: PathBuf) -> Self {
        assert!(
            root.is_absolute(),
            "workspace file listing cache root must be absolute: {}",
            root.display()
        );
        Self {
            project_reads: ProjectReadSlot::default(),
            root,
            generation: AtomicU64::new(0),
            walks: AtomicUsize::new(0),
            cached: Mutex::new(None),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Drop the cached listing. The next `files` call re-walks the root and
    /// re-unions the git index. Never blocks, so watcher event handlers can
    /// call it inline.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// The current listing, walking the root only when no fresh listing is
    /// cached. Concurrent callers serialize on the internal mutex, so a cold
    /// cache is filled by exactly one walk. The generation is sampled before
    /// the walk: an `invalidate` racing with the fill leaves the stored entry
    /// stale-marked, so the next call re-walks instead of serving a listing
    /// that may predate the change.
    pub fn files(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        self.project_reads.cached_inventory(&self.root, || {
            let mut slot = self
                .cached
                .lock()
                .expect("workspace file listing cache poisoned");
            let generation = self.generation.load(Ordering::Acquire);
            if let Some(cached) = slot.as_ref()
                && cached.generation == generation
            {
                publish_receipt(cached.receipt.clone());
                return Ok(Arc::clone(&cached.files));
            }
            self.walks.fetch_add(1, Ordering::Relaxed);
            let files = Arc::new(collect_workspace_files(&self.root)?);
            let matcher = Arc::new(BifrostIgnoreMatcher::build(&self.root, &files)?);
            let receipt = matcher.listing_receipt();
            *slot = Some(CachedFileListing {
                generation,
                files: Arc::clone(&files),
                matcher,
                receipt: receipt.clone(),
            });
            publish_receipt(receipt);
            Ok(files)
        })
    }

    fn matcher(&self) -> io::Result<Arc<BifrostIgnoreMatcher>> {
        // Recheck the generation while holding the same lock as the listing.
        loop {
            self.files()?;
            let slot = self
                .cached
                .lock()
                .expect("workspace file listing cache poisoned");
            if let Some(cached) = slot.as_ref()
                && cached.generation == self.generation.load(Ordering::Acquire)
            {
                return Ok(Arc::clone(&cached.matcher));
            }
        }
    }

    /// Record one path's membership in the cached listing without walking.
    ///
    /// Returns `false` when the caller must invalidate instead: the listing
    /// holds files under a path that is being removed (a directory went away,
    /// and this path alone cannot say which of its files remain). When no
    /// fresh listing is cached there is nothing to update: the next
    /// [`Self::files`] walks anyway, so that also succeeds.
    pub fn update_path(&self, file: &ProjectFile, listed: bool) -> bool {
        let mut slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        if file
            .rel_path()
            .file_name()
            .is_some_and(|name| name == BIFROST_IGNORE_FILE_NAME)
        {
            return false;
        }
        let generation = self.generation.load(Ordering::Acquire);
        let Some(cached) = slot
            .as_mut()
            .filter(|cached| cached.generation == generation)
        else {
            return true;
        };
        if cached.files.contains(file) == listed {
            return true;
        }
        if !listed
            && cached
                .files
                .iter()
                .any(|listed| listed.rel_path().starts_with(file.rel_path()) && listed != file)
        {
            return false;
        }
        let mut files = (*cached.files).clone();
        if listed {
            files.insert(file.clone());
        } else {
            files.remove(file);
        }
        if listed
            && !cached
                .files
                .iter()
                .any(|existing| existing.rel_path().parent() == file.rel_path().parent())
        {
            return false;
        }
        let files = Arc::new(files);
        let receipt = cached.matcher.receipt_for(&files);
        cached.files = files;
        cached.receipt = receipt;
        true
    }

    /// Number of filesystem walks this cache has performed. The observable
    /// complexity signal for regression tests: calls minus walks is the cache's
    /// hit count.
    pub fn walk_count(&self) -> usize {
        self.walks.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct IgnoreRulesSnapshot {
    matcher: Arc<BifrostIgnoreMatcher>,
    receipt: ProjectReadReceipt,
}

#[derive(Debug, Clone)]
pub struct FilesystemProject {
    project_reads: ProjectReadSlot,
    root: PathBuf,
    languages: BTreeSet<Language>,
    listing_count: Arc<AtomicUsize>,
    cached_listing: Option<Arc<WorkspaceFileListingCache>>,
    /// The constructor's discovery walk is a useful build seed, but only for
    /// the first consumer. Manual sessions deliberately return to fresh walks
    /// after that one use rather than retaining a stale cache.
    initial_listing: Arc<Mutex<Option<Arc<BTreeSet<ProjectFile>>>>>,
    bifrost_ignore: Arc<Mutex<Option<IgnoreRulesSnapshot>>>,
}

impl FilesystemProject {
    pub(super) fn from_listing(root: &Path, files: Arc<BTreeSet<ProjectFile>>) -> Self {
        // Used only as the attribution source for an already completed cache call.
        Self::from_listing_and_matcher(
            root,
            files,
            Arc::new(
                BifrostIgnoreMatcher::build_with(root, &BTreeSet::new(), |_| Ok(None))
                    .expect("empty rules"),
            ),
        )
    }

    fn from_listing_and_matcher(
        root: &Path,
        files: Arc<BTreeSet<ProjectFile>>,
        matcher: Arc<BifrostIgnoreMatcher>,
    ) -> Self {
        let receipt = matcher.listing_receipt();
        Self {
            project_reads: ProjectReadSlot::default(),
            root: root.to_path_buf(),
            languages: detect_languages_in_files(&files),
            listing_count: Arc::new(AtomicUsize::new(0)),
            cached_listing: None,
            initial_listing: Arc::new(Mutex::new(Some(files))),
            bifrost_ignore: Arc::new(Mutex::new(Some(IgnoreRulesSnapshot { matcher, receipt }))),
        }
    }

    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into().canonicalize()?.normalize();
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("project root is not a directory: {}", root.display()),
            ));
        }

        let files = Arc::new(collect_workspace_files(&root)?);
        let matcher = Arc::new(BifrostIgnoreMatcher::build(&root, &files)?);
        let project = Self::from_listing_and_matcher(&root, Arc::clone(&files), matcher);
        Ok(project)
    }

    /// Construct a project whose `all_files` listing is served from `listing`
    /// instead of a fresh walk per call. The caller owns invalidation: wire
    /// the same cache handle to whatever observes workspace changes (the
    /// session file watcher) via [`Project::invalidate_cached_file_listing`].
    pub fn with_cached_listing(
        root: impl Into<PathBuf>,
        listing: Arc<WorkspaceFileListingCache>,
    ) -> io::Result<Self> {
        let root = root.into().canonicalize()?.normalize();
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("project root is not a directory: {}", root.display()),
            ));
        }
        assert_eq!(
            root,
            listing.root(),
            "cached listing root must match the canonical project root"
        );
        let files = listing.files()?;
        let matcher = listing.matcher()?;
        let mut project = Self::from_listing_and_matcher(&root, files, matcher);
        project.cached_listing = Some(listing);
        Ok(project)
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    fn bifrost_ignore_matcher(
        &self,
        files: &BTreeSet<ProjectFile>,
    ) -> io::Result<Arc<BifrostIgnoreMatcher>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        if let Some(cache) = &self.cached_listing {
            let matcher = cache.matcher()?;
            publish_ignore_rules(matcher.rules_digest());
            return Ok(matcher);
        }
        let mut slot = self
            .bifrost_ignore
            .lock()
            .expect("Bifrost ignore matcher lock poisoned");
        if slot.is_none() {
            let matcher = Arc::new(BifrostIgnoreMatcher::build(&self.root, files)?);
            let receipt = matcher.listing_receipt();
            *slot = Some(IgnoreRulesSnapshot { matcher, receipt });
        }
        let matcher = Arc::clone(&slot.as_ref().expect("built matcher").matcher);
        publish_ignore_rules(matcher.rules_digest());
        Ok(matcher)
    }

    /// The matcher this project has already built, if it has built one.
    ///
    /// A matcher is built from the whole-workspace listing, but only the first
    /// time: once built it answers from its own rules and never consults the
    /// listing again. Producing a listing to hand to an already-built matcher
    /// is therefore pure waste, and on this project it is expensive waste -- a
    /// directory walk plus a whole-repository `git status` subprocess. That
    /// cost landed on `is_bifrostignored`, which answers one path per call and
    /// is called once per path in loops over a whole revision, so a warm
    /// `--diff-base` policy run spawned one repository-wide `git status` per
    /// committed blob (#2769).
    fn cached_bifrost_ignore_matcher(&self) -> io::Result<Option<Arc<BifrostIgnoreMatcher>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        if let Some(cache) = &self.cached_listing {
            let matcher = cache.matcher()?;
            publish_ignore_rules(matcher.rules_digest());
            return Ok(Some(matcher));
        }
        let slot = self
            .bifrost_ignore
            .lock()
            .expect("Bifrost ignore matcher lock poisoned");
        let Some(snapshot) = slot.as_ref() else {
            return Ok(None);
        };
        publish_receipt(snapshot.receipt.clone());
        publish_ignore_rules(snapshot.matcher.rules_digest());
        Ok(Some(Arc::clone(&snapshot.matcher)))
    }

    fn take_initial_listing(&self) -> Option<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.initial_listing
            .lock()
            .expect("initial workspace listing mutex poisoned")
            .take()
    }
}

impl Project for FilesystemProject {
    fn ignore_rules_digest(&self) -> io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        if let Some(matcher) = self.cached_bifrost_ignore_matcher()? {
            return Ok(matcher.rules_digest());
        }
        let files = self.all_files_shared()?;
        Ok(self.bifrost_ignore_matcher(&files)?.rules_digest())
    }
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        Some(&self.project_reads)
    }
    fn install_read_recorder(&self, capability: ReadCapability) -> bool {
        if let Some(cache) = &self.cached_listing {
            cache.project_reads.install(capability.clone());
        }
        self.project_reads.install(capability);
        true
    }
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot(file),
            |source| Some(source.oid()),
        )
    }

    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<ProjectSourceSnapshot>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot_limited(file, max_bytes),
            |source| source.as_ref().map(ProjectSourceSnapshot::oid),
        )
    }

    fn root(&self) -> &Path {
        self.root_path()
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.project_reads
            .languages(self.as_project(), || self.languages.clone())
    }

    fn workspace_file_listing_count(&self) -> usize {
        self.listing_count.load(Ordering::Relaxed)
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.all_files_shared().map(|files| (*files).clone())
    }

    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.listing_count.fetch_add(1, Ordering::Relaxed);
        if let Some(cache) = &self.cached_listing {
            return cache.files();
        }
        let files = if let Some(files) = self.take_initial_listing() {
            files
        } else {
            let files = Arc::new(collect_workspace_files(&self.root)?);
            let mut slot = self
                .bifrost_ignore
                .lock()
                .expect("Bifrost ignore matcher lock poisoned");
            if let Some(snapshot) = slot.as_mut() {
                // Fresh file discovery does not invalidate ignore rules. Keep
                // the matcher until explicit invalidation, but certify this
                // walk's files using the rules that will filter them.
                snapshot.receipt = snapshot.matcher.receipt_for(&files);
            } else {
                let matcher = Arc::new(BifrostIgnoreMatcher::build(&self.root, &files)?);
                let receipt = matcher.listing_receipt();
                *slot = Some(IgnoreRulesSnapshot { matcher, receipt });
            }
            files
        };
        let receipt = self
            .bifrost_ignore
            .lock()
            .expect("Bifrost ignore matcher lock poisoned")
            .as_ref()
            .expect("listing filled matcher")
            .receipt
            .clone();
        publish_receipt(receipt);
        Ok(files)
    }

    fn update_cached_listing_for_path(&self, rel_path: &Path) -> bool {
        let Some(cache) = &self.cached_listing else {
            return false;
        };
        let absolute = self.root.join(rel_path);
        if absolute.is_dir() {
            return false;
        }
        let Some(repo) = crate::gitblob::discover(&self.root) else {
            return false;
        };
        let Some(workdir) = repo
            .workdir()
            .and_then(|workdir| workdir.canonicalize().ok())
            .map(|workdir| workdir.normalize())
        else {
            return false;
        };
        let Ok(workdir_rel) = absolute.strip_prefix(&workdir) else {
            return false;
        };
        let Ok(listed) = crate::gitblob::working_tree_path_is_listed(&repo, workdir_rel) else {
            return false;
        };
        cache.update_path(
            &ProjectFile::new(self.root.clone(), rel_path.to_path_buf()),
            listed,
        )
    }

    fn invalidate_cached_file_listing(&self) {
        if let Some(cache) = &self.cached_listing {
            cache.invalidate();
        }
        *self
            .initial_listing
            .lock()
            .expect("initial workspace listing mutex poisoned") = None;
        *self
            .bifrost_ignore
            .lock()
            .expect("Bifrost ignore matcher lock poisoned") = None;
    }

    /// A `stat` instead of a whole-tree walk. Every file this project reports
    /// comes from walking the real tree under `root`, so "no directory on disk"
    /// implies "no workspace file beneath it"; the reverse over-approximates
    /// only for directories whose contents are entirely ignored, which the
    /// caller's listing then filters out exactly as before.
    fn has_directory(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.directory(self.as_project(), rel_path));
        let exists = filesystem_has_directory(&self.root, rel_path);
        publish_directory(exists);
        exists
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        let extensions = language.extensions();
        if extensions.is_empty() {
            self.all_files_shared()?;
            return Ok(BTreeSet::new());
        }

        let files = self.all_files_shared()?;
        let bifrost_ignore = self.bifrost_ignore_matcher(&files)?;
        Ok(files_for_language(&files, language, ProjectFile::language)
            .into_iter()
            .filter(|file| !bifrost_ignore.is_ignored(file))
            .collect())
    }

    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        let bifrost_ignore = self.bifrost_ignore_matcher(files)?;
        publish_file_set(self, files)?;
        Ok(files_for_language(files, language, ProjectFile::language)
            .into_iter()
            .filter(|file| !bifrost_ignore.is_ignored(file))
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.path(self.as_project(), rel_path));
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        (super::project_reads::observed_path_kind(&file.abs_path())
            == super::project_reads::WorkspacePathKind::File)
            .then_some(file)
    }

    /// Both ignore probes read the listing and never keep it, so they take the
    /// shared handle: a per-probe `all_files` clone copies the whole workspace
    /// listing to answer one path.
    fn is_gitignored(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.git_ignore(self.as_project(), rel_path));
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        if super::project_reads::observed_path_kind(&file.abs_path())
            == super::project_reads::WorkspacePathKind::Absent
        {
            publish_git_ignore_presence_only();
            return false;
        }
        self.all_files_shared()
            .map(|files| !files.contains(&file))
            .unwrap_or(false)
    }

    fn is_bifrostignored(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        // The listing is taken only to build the matcher, so ask for it only
        // when there is no matcher yet. `invalidate_cached_file_listing` clears
        // the matcher and the listing together, so reading the matcher first
        // can never answer from rules older than the listing would have been.
        let matcher = self
            .cached_bifrost_ignore_matcher()
            .and_then(|cached| match cached {
                Some(matcher) => Ok(matcher),
                None => self
                    .all_files_shared()
                    .and_then(|files| self.bifrost_ignore_matcher(&files)),
            });
        matcher
            .map(|matcher| matcher.is_ignored_path(rel_path))
            .unwrap_or(false)
    }
}

/// A [`Project`] backed by an explicit, fixed set of files rather than a
/// directory walk. One-shot CLI paths can use this to parse only requested
/// files instead of indexing the whole workspace: building a
/// `WorkspaceAnalyzer` over it analyzes exactly
/// these files and nothing else.
#[derive(Debug, Clone)]
pub struct FileSetProject {
    project_reads: ProjectReadSlot,
    root: PathBuf,
    files: BTreeSet<ProjectFile>,
    receipt: ProjectReadReceipt,
    languages: BTreeSet<Language>,
}

impl FileSetProject {
    /// Build a project rooted at `root` containing exactly the files at the
    /// given project-relative paths. Analyzer languages are inferred from the
    /// file extensions; files of unsupported types stay listed but contribute
    /// no language (and so are never parsed).
    pub fn new(root: impl Into<PathBuf>, rel_paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let root = root.into().normalize();
        let files: BTreeSet<ProjectFile> = rel_paths
            .into_iter()
            .map(|rel| ProjectFile::new(root.clone(), rel))
            .collect();
        let languages = detect_languages_in_files(&files);
        let receipt = BifrostIgnoreMatcher::build_with(&root, &files, |_| Ok(None))
            .expect("explicit file set has no ignore-rule inputs")
            .listing_receipt();
        Self {
            project_reads: ProjectReadSlot::default(),
            root,
            files,
            receipt,
            languages,
        }
    }
}

impl Project for FileSetProject {
    fn ignore_rules_digest(&self) -> io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        let digest = BifrostIgnoreMatcher::empty_rules_digest();
        publish_ignore_rules(digest);
        Ok(digest)
    }
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        Some(&self.project_reads)
    }
    fn install_read_recorder(&self, capability: ReadCapability) -> bool {
        self.project_reads.install(capability);
        true
    }
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot(file),
            |source| Some(source.oid()),
        )
    }

    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<ProjectSourceSnapshot>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot_limited(file, max_bytes),
            |source| source.as_ref().map(ProjectSourceSnapshot::oid),
        )
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn coverage(&self) -> ProjectCoverage {
        ProjectCoverage::Subset(SubsetCoverage {
            files: self.files.len(),
        })
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.project_reads
            .languages(self.as_project(), || self.languages.clone())
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        publish_receipt(self.receipt.clone());
        Ok(self.files.clone())
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        publish_receipt(self.receipt.clone());
        Ok(files_for_language(&self.files, language, language_for_file))
    }

    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        publish_file_set(self, files)?;
        Ok(files_for_language(files, language, language_for_file))
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.path(self.as_project(), rel_path));
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        publish_receipt(self.receipt.clone());
        self.files.contains(&file).then_some(file)
    }

    fn persistence_root(&self) -> Option<&Path> {
        None
    }
}

/// A [`Project`] backed by several filesystem roots. File enumeration is
/// delegated to each root's own [`FilesystemProject`] so root-local ignore files
/// still decide what belongs to the analyzer.
#[derive(Debug, Clone)]
pub struct MultiRootProject {
    project_reads: ProjectReadSlot,
    root: PathBuf,
    roots: Vec<FilesystemProject>,
    languages: BTreeSet<Language>,
    persistence_dir: Option<PathBuf>,
}

impl MultiRootProject {
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        Self::build(roots, None)
    }

    /// A multi-root project whose persisted database lives under `cache_root`
    /// rather than under the machine cache root `BIFROST_CACHE_ROOT` or the
    /// platform names (see [`gitblob::multiroot_persistence_dir`]).
    ///
    /// A host that places its own caches, and a test that must not depend on
    /// the environment of the process it shares with every other test, says
    /// where the cache goes instead of setting a variable for the whole
    /// process.
    pub fn with_cache_root(
        roots: impl IntoIterator<Item = PathBuf>,
        cache_root: PathBuf,
    ) -> io::Result<Self> {
        Self::build(roots, Some(cache_root.into_os_string()))
    }

    fn build(
        roots: impl IntoIterator<Item = PathBuf>,
        cache_root: Option<std::ffi::OsString>,
    ) -> io::Result<Self> {
        let mut roots = roots
            .into_iter()
            .map(|root| root.canonicalize().map(NormalizePath::normalize))
            .collect::<io::Result<Vec<_>>>()?;
        roots.sort();
        roots.dedup();
        if roots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multi-root project requires at least one root",
            ));
        }

        let root = common_ancestor(&roots).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "multi-root project roots do not share a filesystem ancestor",
            )
        })?;
        // The parsed facts of N repositories share one database safely: a blob
        // row is keyed by content oid, language storage key and generation, and
        // never by the repository a file came from, so the same file analyzed
        // from two checkouts is one row and a differing file is two. The rows
        // that *are* workspace-shaped key on `WorkspaceId::for_root`, which
        // this project reports as its common ancestor, so they cannot collide
        // with another workspace's. A different set of roots hashes to a
        // different directory and therefore to a different database.
        let persistence_dir = gitblob::multiroot_persistence_dir_with_overrides(&roots, cache_root);
        let roots = roots
            .iter()
            .map(FilesystemProject::new)
            .collect::<io::Result<Vec<_>>>()?;
        let languages = roots
            .iter()
            .flat_map(|root| root.languages.iter().copied())
            .collect();
        Ok(Self {
            project_reads: ProjectReadSlot::default(),
            root,
            roots,
            languages,
            persistence_dir,
        })
    }

    fn common_file_for_root_file(&self, file: ProjectFile) -> ProjectFile {
        let rel_path = file
            .abs_path()
            .strip_prefix(&self.root)
            .expect("workspace root should be under common ancestor")
            .to_path_buf();
        ProjectFile::new(self.root.clone(), rel_path)
    }
}

impl Project for MultiRootProject {
    fn ignore_rules_digest(&self) -> io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        let mut hash = crate::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-multiroot-ignore-rules:v1",
        );
        for root in &self.roots {
            hash.field(
                "root",
                crate::path_utils::workspace_relative_slash_path(
                    root.root()
                        .strip_prefix(&self.root)
                        .expect("child root belongs to common root"),
                )
                .as_bytes(),
            );
            hash.field("rules", &root.ignore_rules_digest()?);
        }
        let digest = hash.finish();
        publish_ignore_rules(digest);
        Ok(digest)
    }
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        Some(&self.project_reads)
    }
    fn install_read_recorder(&self, capability: ReadCapability) -> bool {
        for root in &self.roots {
            root.install_read_recorder(capability.clone());
        }
        self.project_reads.install(capability);
        true
    }
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot(file),
            |source| Some(source.oid()),
        )
    }

    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<ProjectSourceSnapshot>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_source_snapshot_limited(file, max_bytes),
            |source| source.as_ref().map(ProjectSourceSnapshot::oid),
        )
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        let abs_path = file.abs_path();
        self.roots
            .iter()
            .filter(|root| abs_path.starts_with(root.root()))
            .max_by_key(|root| root.root().components().count())
            .map(|root| root.root().to_path_buf())
            .unwrap_or_else(|| self.root.clone())
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.project_reads
            .languages(self.as_project(), || self.languages.clone())
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let mut files = BTreeSet::new();
        for root in &self.roots {
            for file in root.all_files()? {
                files.insert(self.common_file_for_root_file(file));
            }
        }
        publish_file_set(self, &files)?;
        Ok(files)
    }

    fn workspace_file_listing_count(&self) -> usize {
        self.roots
            .iter()
            .map(Project::workspace_file_listing_count)
            .sum()
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        let files = self.all_files_shared()?;
        self.analyzable_files_from(&files, language)
    }

    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        let mut analyzable = BTreeSet::new();
        for root in &self.roots {
            let root_files = files
                .iter()
                .filter_map(|file| {
                    let abs_path = file.abs_path();
                    let rel_path = abs_path.strip_prefix(root.root()).ok()?;
                    Some(ProjectFile::new(
                        root.root().to_path_buf(),
                        rel_path.to_path_buf(),
                    ))
                })
                .collect::<BTreeSet<_>>();
            for file in root.analyzable_files_from(&root_files, language)? {
                analyzable.insert(self.common_file_for_root_file(file));
            }
        }
        publish_file_set(self, files)?;
        Ok(analyzable)
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.path(self.as_project(), rel_path));
        self.file_by_abs_path(&self.root.join(rel_path))
    }

    fn file_by_abs_path(&self, abs_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), abs_path));
        let abs_path = abs_path.to_path_buf().normalize();
        for root in &self.roots {
            let Some(root_rel_path) = relative_path_from_normalized_root(&abs_path, root.root())
            else {
                continue;
            };
            if let Some(file) = root.file_by_rel_path(root_rel_path) {
                return Some(self.common_file_for_root_file(file));
            }
        }
        None
    }

    fn file_by_abs_path_allow_missing(&self, abs_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), abs_path));
        let abs_path = abs_path.to_path_buf().normalize();
        let rel_path = relative_path_from_normalized_root(&abs_path, &self.root)?;
        for root in &self.roots {
            if relative_path_from_normalized_root(&abs_path, root.root()).is_some() {
                return Some(ProjectFile::new(self.root.clone(), rel_path.to_path_buf()));
            }
        }
        None
    }

    fn invalidate_cached_file_listing(&self) {
        for root in &self.roots {
            root.invalidate_cached_file_listing();
        }
    }

    fn is_bifrostignored(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        let abs_path = self.root.join(rel_path);
        let ignored = self.roots.iter().any(|root| {
            abs_path
                .strip_prefix(root.root())
                .is_ok_and(|root_rel_path| root.is_bifrostignored(root_rel_path))
        });
        self.ignore_rules_digest()
            .expect("workspace roots have readable rule inputs");
        ignored
    }

    fn persistence_root(&self) -> Option<&Path> {
        self.persistence_dir.as_deref()
    }
}

fn common_ancestor(paths: &[PathBuf]) -> Option<PathBuf> {
    let mut ancestor = paths[0].clone();
    for path in &paths[1..] {
        while !path.starts_with(&ancestor) {
            if !ancestor.pop() {
                return None;
            }
        }
    }
    Some(ancestor)
}

/// Collect every file under `root` that belongs to the analyzer's view of the
/// workspace. The walk is ignore-aware, skips `.git/`, and keeps other dotted
/// directories in scope.
pub fn collect_workspace_files(root: &Path) -> io::Result<BTreeSet<ProjectFile>> {
    #[cfg(any(test, feature = "test-support"))]
    super::project_reads::count_project_io(super::project_reads::ProjectIo::Walk);
    let _scope = crate::profiling::scope("project::collect_workspace_files");
    let mut apply_parent_ignores = true;
    if let Some(repo) = crate::gitblob::discover(root) {
        let workdir = repo
            .workdir()
            .ok_or_else(|| io::Error::other("repository has no working directory"))?;
        let canonical_root = root.canonicalize()?.normalize();
        let canonical_workdir = workdir.canonicalize()?.normalize();
        // An ancestor repository can own this root. The `strip_prefix` filter
        // below already discards everything outside it, so scoping the
        // enumeration to the subtree yields the same listing at a cost
        // proportional to the workspace instead of the ancestor repository.
        let active_paths =
            match crate::gitblob::subtree_pathspec(&canonical_workdir, &canonical_root) {
                Some(subtree) => crate::gitblob::working_tree_paths_under(&repo, &subtree),
                None => crate::gitblob::all_working_tree_paths(&repo),
            }
            .map_err(io::Error::other)?;
        let mut files = BTreeSet::new();
        for rel in active_paths {
            let absolute = canonical_workdir.join(rel);
            let Ok(project_rel) = absolute.strip_prefix(&canonical_root) else {
                continue;
            };
            files.insert(ProjectFile::new(
                root.to_path_buf(),
                project_rel.to_path_buf(),
            ));
        }
        // An ancestor repository can discover this root while its ignore rules
        // hide the complete subtree. In that case, Git cannot represent the
        // explicitly selected workspace. Walk the selected root instead.
        if !files.is_empty() {
            return Ok(files);
        }
        apply_parent_ignores = false;
    }

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .ignore(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        // When Git cannot represent the selected root, its ancestor ignore
        // files must not erase that explicit workspace during the fallback.
        .parents(apply_parent_ignores)
        .require_git(false)
        // Never descend into `.git`. We keep hidden entries (`hidden(false)`) so
        // legitimate dotted source/config like `.github/` is still analyzed, but
        // `.git` is VCS internals, never source, and is not covered by
        // `.gitignore`. Walking it is pure cost -- catastrophic on trees with
        // many clones -- and would otherwise index git's own files. `git_exclude`
        // detection (`.git/info/exclude`) is unaffected: the ignore crate reads
        // it during repo detection, independent of whether the walk yields `.git`.
        .filter_entry(|entry| entry.file_name() != std::ffi::OsStr::new(".git"))
        // Parallel traversal: the walk is `stat`/`readdir`-bound, so on large
        // trees (and high-latency filesystems) spreading directory enumeration
        // across threads is a substantial win. The ignore crate defaults the
        // thread count to the available parallelism.
        .build_parallel();

    // Each visitor thread streams its entries over the channel; a dedicated
    // collector thread merges them into the ordered `BTreeSet` concurrently with
    // the walk. We pay the ordering cost once, on the receiver side, instead of
    // contending a shared sorted set across every walker thread -- and draining
    // as we go keeps the peak memory to roughly one copy rather than buffering
    // the whole channel before building the set. The first walk error wins and
    // is surfaced after the traversal completes.
    let (tx, rx) = std::sync::mpsc::channel::<ProjectFile>();
    let collector = std::thread::spawn(move || rx.into_iter().collect::<BTreeSet<ProjectFile>>());
    let first_error: Arc<Mutex<Option<io::Error>>> = Arc::new(Mutex::new(None));
    walker.run(|| {
        let tx = tx.clone();
        let first_error = Arc::clone(&first_error);
        Box::new(move |result| {
            let entry = match result {
                Ok(entry) => entry,
                Err(err) => {
                    let mut slot = first_error.lock().expect("walk error lock poisoned");
                    if slot.is_none() {
                        *slot = Some(io::Error::other(err.to_string()));
                    }
                    // Keep walking the rest of the tree; the captured error is
                    // returned to the caller once the traversal finishes.
                    return WalkState::Continue;
                }
            };
            if entry
                .file_type()
                .is_some_and(|file_type| file_type.is_file())
            {
                let rel = entry
                    .path()
                    .strip_prefix(root)
                    .expect("walker returned a path outside the project root");
                // Receiver is dropped only after the walk returns, so a send
                // failure is impossible here; ignore the result to stay panic-free.
                let _ = tx.send(ProjectFile::new(root.to_path_buf(), rel.to_path_buf()));
            }
            WalkState::Continue
        })
    });
    // Drop our retained sender so the collector's iterator terminates once every
    // walker thread's clone has also been dropped.
    drop(tx);

    let files = collector.join().expect("file-collector thread panicked");

    if let Some(err) = first_error.lock().expect("walk error lock poisoned").take() {
        return Err(err);
    }
    Ok(files)
}

/// The content of every unsaved overlay a project currently layers over its
/// files, as (file, content digest) pairs in workspace-relative path order.
///
/// This exists so a derived value can be keyed by the content an analyzer will
/// actually see (#2449). An analyzer's own live path map learns an overlay's
/// identity lazily -- only once something parses that file -- so a cache that
/// asked the map would answer for the disk revision of a buffer the editor has
/// already changed. The project knows immediately, and it is the only thing
/// that does.
///
/// The digest is over content, never over the overlay revision counter: two
/// editors that arrive at the same buffer produce the same identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceOverlayContent {
    entries: Arc<[(ProjectFile, [u8; 32])]>,
    blob_ids: Arc<[Oid]>,
    digest: [u8; 32],
}

impl WorkspaceOverlayContent {
    const DOMAIN: &[u8] = b"bifrost-workspace-overlay-content:v1";

    pub fn new(entries: impl IntoIterator<Item = (ProjectFile, [u8; 32], Oid)>) -> Self {
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            crate::path_utils::rel_path_string(&left.0)
                .cmp(&crate::path_utils::rel_path_string(&right.0))
        });
        let mut hasher = crate::analyzer::canonical_hash::CanonicalHasher::new(Self::DOMAIN);
        for (file, digest, _) in &entries {
            hasher.field(&crate::path_utils::rel_path_string(file), digest);
        }
        // Split only after canonical ordering; the immutable arrays share the
        // same entry order for their entire lifetime.
        let (entries, blob_ids): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .map(|(file, digest, blob)| ((file, digest), blob))
            .unzip();
        Self {
            entries: entries.into(),
            blob_ids: blob_ids.into(),
            digest: hasher.finish(),
        }
    }

    /// Every overlaid file and its content digest, in workspace-relative path
    /// order.
    pub fn entries(&self) -> &[(ProjectFile, [u8; 32])] {
        &self.entries
    }

    /// The same ordered entries with their exact write-side Git blob identity.
    pub fn entries_with_blob_ids(
        &self,
    ) -> impl ExactSizeIterator<Item = (&ProjectFile, &[u8; 32], Oid)> {
        self.entries
            .iter()
            .zip(self.blob_ids.iter())
            .map(|((file, digest), blob)| (file, digest, *blob))
    }

    /// Whether `file` is currently overlaid, so a caller must take its content
    /// from here rather than from anything derived from disk.
    pub fn contains(&self, file: &ProjectFile) -> bool {
        self.entries.iter().any(|(candidate, _)| candidate == file)
    }

    /// The identity of the whole overlay set. Two projects with byte-equal
    /// buffers over the same relative paths agree.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// A [`Project`] wrapper that layers an in-memory content overlay on top of a
/// delegate project. Reads consult the overlay first and fall back to the
/// delegate. Used by the LSP server to feed `textDocument/did{Open,Change}`
/// buffer content into the analyzer without writing to disk.
///
/// A buffer outlives the file beneath it: a branch switch, a rebase or a rename
/// deletes the file while the editor still holds (and still edits) its
/// contents, and `didClose` is the only point at which the editor gives it up.
/// This project therefore lists such a path -- the bytes exist, and the buffer
/// is the only place they are -- and resolves every path it serves from a
/// buffer, so the editor can go on editing that document and can finally close
/// it. Delegating both made a buffer that outlived its file serve content
/// nobody could enumerate: an analyzer built over this project skipped it while
/// an incrementally updated one kept it, `didChange` could no longer resolve it,
/// and `didClose` could not clear it, so the buffer leaked for the life of the
/// session.
///
/// Membership stops there. A buffer supplies bytes; it does not overrule the
/// delegate's membership rules. A path the delegate excludes while its file is
/// on disk -- ignored, out of scope -- stays excluded when an editor opens it,
/// exactly as it was before the buffer existed.
pub struct OverlayProject {
    project_reads: ProjectReadSlot,
    /// The overlay content identity published for the map's current revision.
    /// Recomputing it hashes every open buffer, so it is derived once per
    /// accepted edit rather than once per query. The revision is a memo key
    /// only; it never enters the identity.
    overlay_content: Mutex<Option<(u64, Arc<WorkspaceOverlayContent>)>>,
    delegate: Arc<dyn Project>,
    overlays: Arc<RwLock<HashMap<PathBuf, Arc<OverlayEntry>>>>,
    /// Process-local allocator shared by every snapshot descended from this
    /// view. Entry revisions must remain unique even when the live view and an
    /// older request snapshot are both mutated.
    revision_allocator: Arc<AtomicU64>,
    /// Generation published by mutations to this view's map. Unlike the
    /// allocator, a snapshot owns this value so later live edits cannot make
    /// its frozen source look stale midway through a request.
    published_generation: AtomicU64,
    max_overlay_bytes: usize,
    /// Last instant we emitted a rejection log for a given path. Kept on a
    /// separate throttle helper so the per-keystroke read path doesn't
    /// contend with rejection logging on the main overlay lock.
    last_rejection_log: ThrottledLog<PathBuf>,
}

#[derive(Debug)]
struct OverlayEntry {
    source: Arc<str>,
    revision: OverlayRevision,
    content_digest: [u8; 32],
    blob_id: Oid,
}

impl OverlayEntry {
    fn snapshot(&self) -> ProjectSourceSnapshot {
        ProjectSourceSnapshot {
            source: Arc::clone(&self.source),
            oid: self.blob_id,
            origin: ProjectSourceOrigin::Overlay(self.revision),
        }
    }
}

impl OverlayProject {
    pub fn new(delegate: Arc<dyn Project>) -> Self {
        Self::with_max_bytes(delegate, DEFAULT_MAX_OVERLAY_BYTES)
    }

    /// Construct with a custom per-overlay size cap. Reserved for tests and
    /// future tuning; production LSP wiring uses [`Self::new`].
    pub fn with_max_bytes(delegate: Arc<dyn Project>, max_overlay_bytes: usize) -> Self {
        Self {
            project_reads: ProjectReadSlot::default(),
            overlay_content: Mutex::new(None),
            delegate,
            overlays: Arc::new(RwLock::new(HashMap::new())),
            revision_allocator: Arc::new(AtomicU64::new(0)),
            published_generation: AtomicU64::new(0),
            max_overlay_bytes,
            last_rejection_log: ThrottledLog::new(
                OVERLAY_REJECTION_LOG_THROTTLE,
                OVERLAY_REJECTION_LOG_MAX_ENTRIES,
            ),
        }
    }

    fn next_revision(&self) -> OverlayRevision {
        let previous = self
            .revision_allocator
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .expect("overlay revision space exhausted");
        OverlayRevision::from_monotonic_counter(
            previous
                .checked_add(1)
                .expect("successful overlay revision update cannot overflow"),
        )
    }

    /// Capture an independent read view of the current overlays.
    ///
    /// Subsequent editor changes mutate the live project's map without changing this
    /// snapshot, allowing background requests to use one coherent source generation.
    pub fn snapshot(&self) -> Self {
        let _project_read = self.project_reads.overlays(self.as_project());
        let overlays = self.overlays.read().expect("overlay lock poisoned");
        let frozen_overlays = overlays.clone();
        let frozen_generation = self.published_generation.load(Ordering::Acquire);
        let content = Arc::new(WorkspaceOverlayContent::new(
            frozen_overlays.iter().filter_map(|(path, entry)| {
                let rel_path = path.strip_prefix(self.delegate.root()).ok()?;
                Some((
                    ProjectFile::new(self.delegate.root().to_path_buf(), rel_path),
                    entry.content_digest,
                    entry.blob_id,
                ))
            }),
        ));
        super::project_reads::publish_overlays(&Some(content));
        Self {
            project_reads: ProjectReadSlot::default(),
            overlay_content: Mutex::new(None),
            delegate: Arc::clone(&self.delegate),
            overlays: Arc::new(RwLock::new(frozen_overlays)),
            revision_allocator: Arc::clone(&self.revision_allocator),
            published_generation: AtomicU64::new(frozen_generation),
            max_overlay_bytes: self.max_overlay_bytes,
            last_rejection_log: ThrottledLog::new(
                OVERLAY_REJECTION_LOG_THROTTLE,
                OVERLAY_REJECTION_LOG_MAX_ENTRIES,
            ),
        }
    }

    /// Replace (or insert) the overlay for `abs_path`. Returns `true` when
    /// the overlay was stored and `false` when it was rejected because
    /// `content` exceeded the configured per-overlay byte cap; in the reject
    /// case any prior overlay for the path is cleared so subsequent reads
    /// fall through to disk rather than serving stale content.
    pub fn set(&self, abs_path: PathBuf, content: String) -> bool {
        let abs_path = abs_path.normalize();
        if content.len() > self.max_overlay_bytes {
            self.log_rejection(&abs_path, content.len());
            // Drop any stale overlay so reads return disk content rather than
            // a now-misleading older version of the buffer.
            self.remove_overlay_with_revision_hook(&abs_path, || {});
            return false;
        }
        let mut overlays = self.overlays.write().expect("overlay lock poisoned");
        let revision = self.next_revision();
        overlays.insert(
            abs_path,
            Arc::new(OverlayEntry {
                content_digest: crate::analyzer::canonical_hash::sha256_bytes(content.as_bytes()),
                blob_id: Oid::hash_object(ObjectType::Blob, content.as_bytes())
                    .expect("hashing installed overlay"),
                source: Arc::from(content),
                revision,
            }),
        );
        self.published_generation
            .store(revision.get(), Ordering::Release);
        true
    }

    /// Remove an overlay, if present. Returns `true` when an overlay was
    /// actually removed — callers use this to decide whether reparse is needed.
    pub fn clear(&self, abs_path: &Path) -> bool {
        let abs_path = abs_path.to_path_buf().normalize();
        self.remove_overlay_with_revision_hook(&abs_path, || {})
    }

    fn remove_overlay_with_revision_hook(
        &self,
        abs_path: &Path,
        before_revision: impl FnOnce(),
    ) -> bool {
        let mut overlays = self.overlays.write().expect("overlay lock poisoned");
        let removed = overlays.remove(abs_path).is_some();
        if removed {
            // Publish the generation while the changed map is still hidden by
            // the write guard. Readers can observe either the old map and old
            // generation or the new map and new generation, never the removed
            // overlay under the old generation.
            before_revision();
            let revision = self.next_revision();
            self.published_generation
                .store(revision.get(), Ordering::Release);
        }
        removed
    }

    /// Drop every overlay. Not invoked by the LSP today; reserved for future
    /// session-reset paths.
    pub fn clear_all(&self) {
        let mut overlays = self.overlays.write().expect("overlay lock poisoned");
        if !overlays.is_empty() {
            overlays.clear();
            let revision = self.next_revision();
            self.published_generation
                .store(revision.get(), Ordering::Release);
        }
    }

    /// The buffers this project serves, as project files.
    ///
    /// An overlay is keyed by absolute path and installed by a caller that
    /// resolved it through this project, so in practice every key is under the
    /// root; a key that is not belongs to no workspace-relative path and is
    /// dropped rather than guessed at.
    fn overlay_project_files(&self) -> Vec<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let root = self.delegate.root();
        self.overlays
            .read()
            .expect("overlay lock poisoned")
            .keys()
            .filter_map(|abs_path| {
                let rel_path = abs_path.strip_prefix(root).ok()?;
                Some(ProjectFile::new(root.to_path_buf(), rel_path))
            })
            .collect()
    }

    /// The buffers among `candidates` this project must name itself, because
    /// `listed` does not name them and the delegate has no file there.
    ///
    /// This is the type's membership rule in one place: the existence probe is
    /// what keeps a buffer from carrying an ignored or out-of-scope path into
    /// the workspace, and it runs only for a path the delegate's own answer
    /// left out -- in a session whose files are all saved, none of them.
    fn buffers_missing_from<'a>(
        candidates: impl IntoIterator<Item = ProjectFile> + 'a,
        listed: &'a BTreeSet<ProjectFile>,
    ) -> impl Iterator<Item = ProjectFile> + 'a {
        candidates
            .into_iter()
            .filter(|file| !listed.contains(file) && !file.exists())
    }

    fn overlay_entry(&self, file: &ProjectFile) -> Option<Arc<OverlayEntry>> {
        self.project_reads.overlay(
            self.as_project(),
            file,
            || {
                self.overlays
                    .read()
                    .expect("overlay lock poisoned")
                    .get(&file.abs_path())
                    .cloned()
            },
            |entry| entry.blob_id,
        )
    }

    /// Add the buffers among `candidates` that belong in a `language` listing
    /// to `analyzable`.
    ///
    /// The membership rules stay the delegate's: the language is the path's own,
    /// and a `.bifrostignore` match excludes a buffer exactly as it excludes the
    /// file it shadows.
    fn add_analyzable_overlays(
        &self,
        language: Language,
        candidates: impl IntoIterator<Item = ProjectFile>,
        analyzable: &mut BTreeSet<ProjectFile>,
    ) {
        let additions: Vec<ProjectFile> = Self::buffers_missing_from(
            candidates
                .into_iter()
                .filter(|file| file.language() == language),
            analyzable,
        )
        .filter(|file| !self.delegate.is_bifrostignored(file.rel_path()))
        .collect();
        analyzable.extend(additions);
    }

    /// Emit a single stderr line reporting that `abs_path` was rejected, but
    /// only when we haven't logged for the same path within
    /// [`OVERLAY_REJECTION_LOG_THROTTLE`]. The throttle map is bounded by
    /// [`OVERLAY_REJECTION_LOG_MAX_ENTRIES`]; entries past the throttle
    /// window are pruned when it fills.
    ///
    /// The lock on `last_rejection_log` is dropped before `eprintln!` so
    /// stderr I/O (which can block if redirected) doesn't extend the
    /// critical section.
    fn log_rejection(&self, abs_path: &Path, content_len: usize) {
        let now = Instant::now();
        if self.last_rejection_log.should_log(abs_path, now) {
            eprintln!(
                "[bifrost-lsp] dropping overlay for {}: {} bytes exceeds cap of {} bytes",
                abs_path.display(),
                content_len,
                self.max_overlay_bytes,
            );
        }
    }
}

impl Project for OverlayProject {
    fn ignore_rules_digest(&self) -> io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.delegate.ignore_rules_digest()
    }
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        Some(&self.project_reads)
    }
    fn install_read_recorder(&self, capability: ReadCapability) -> bool {
        self.delegate.install_read_recorder(capability.clone());
        self.project_reads.install(capability);
        true
    }
    fn workspace_file_listing_count(&self) -> usize {
        self.delegate.workspace_file_listing_count()
    }

    /// An overlay supplies bytes, not membership: the session still covers
    /// exactly the workspace slice its delegate covers.
    fn coverage(&self) -> ProjectCoverage {
        self.delegate.coverage()
    }

    fn root(&self) -> &Path {
        self.delegate.root()
    }

    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        self.delegate.workspace_root_for_file(file)
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.project_reads
            .languages(self.as_project(), || self.delegate.analyzer_languages())
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.all_files_shared().map(|files| (*files).clone())
    }

    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let files = self.delegate.all_files_shared()?;
        let additions: Vec<ProjectFile> =
            Self::buffers_missing_from(self.overlay_project_files(), &files).collect();
        // Nothing to add is the ordinary case -- every open buffer has its file
        // on disk -- and the delegate's listing is the one every other reader of
        // this generation shares. Copying it per call to add nothing would make
        // a whole-workspace clone the price of holding a buffer open.
        if additions.is_empty() {
            publish_file_set(self, &files)?;
            return Ok(files);
        }
        let mut extended = (*files).clone();
        extended.extend(additions);
        publish_file_set(self, &extended)?;
        Ok(Arc::new(extended))
    }

    fn has_directory(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.directory(self.as_project(), rel_path));
        if self.delegate.has_directory(rel_path) {
            publish_directory(true);
            return true;
        }
        // `false` is the authoritative half of this answer -- no workspace file
        // lives beneath `rel_path` -- so a buffer under a directory the
        // delegate no longer has must still make it `true`. `true` needs no
        // existence probe: it only means a listing is worth computing, and that
        // listing applies the membership rule.
        let prefix = self.delegate.root().join(rel_path);
        let exists = self
            .overlays
            .read()
            .expect("overlay lock poisoned")
            .keys()
            .any(|abs_path| {
                abs_path
                    .strip_prefix(&prefix)
                    .is_ok_and(|remainder| remainder.components().next().is_some())
            });
        publish_directory(exists);
        exists
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        let files = self.all_files_shared()?;
        self.analyzable_files_from(&files, language)
    }

    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        let _project_read = listing_read(self);
        let mut analyzable = self.delegate.analyzable_files_from(files, language)?;
        // A caller-owned listing is filtered, not extended: a buffer belongs in
        // the answer only when the caller's set already names it (which a
        // listing from this project does). The delegate is asked first and the
        // buffers are re-added afterwards because a delegate that does not
        // implement this hook answers from its own disk listing, where a path
        // whose file is gone cannot appear.
        self.add_analyzable_overlays(
            language,
            self.overlay_project_files()
                .into_iter()
                .filter(|file| files.contains(file)),
            &mut analyzable,
        );
        publish_file_set(self, files)?;
        Ok(analyzable)
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.path(self.as_project(), rel_path));
        if let Some(file) = self.delegate.file_by_rel_path(rel_path) {
            return Some(file);
        }
        let file = ProjectFile::new(self.delegate.root().to_path_buf(), rel_path.to_path_buf());
        super::project_reads::observed_overlay_membership().then_some(file)
    }

    fn file_by_abs_path(&self, abs_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), abs_path));
        if let Some(file) = self.delegate.file_by_abs_path(abs_path) {
            return Some(file);
        }
        let rel_path = relative_path_under_root(abs_path, self.delegate.root())?;
        self.file_by_rel_path(&rel_path)
    }

    fn file_by_abs_path_allow_missing(&self, abs_path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.absolute_path(self.as_project(), abs_path));
        self.delegate.file_by_abs_path_allow_missing(abs_path)
    }

    fn persistence_root(&self) -> Option<&Path> {
        self.delegate.persistence_root()
    }

    fn is_gitignored(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.git_ignore(self.as_project(), rel_path));
        self.delegate.is_gitignored(rel_path)
    }

    fn is_bifrostignored(&self, rel_path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.delegate.is_bifrostignored(rel_path)
    }

    fn invalidate_cached_file_listing(&self) {
        self.delegate.invalidate_cached_file_listing();
    }

    fn update_cached_listing_for_path(&self, rel_path: &Path) -> bool {
        self.delegate.update_cached_listing_for_path(rel_path)
    }

    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        self.read_source_snapshot(file)
            .map(|snapshot| snapshot.source().to_owned())
    }

    fn read_source_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<String>> {
        self.read_source_snapshot_limited(file, max_bytes)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.source().to_owned()))
    }

    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                let entry = self.overlay_entry(file);
                if let Some(entry) = entry {
                    return Ok(entry.snapshot());
                }
                self.delegate.read_source_snapshot(file)
            },
            |source| Some(source.oid()),
        )
    }

    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> io::Result<Option<ProjectSourceSnapshot>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                let entry = self.overlay_entry(file);
                if let Some(entry) = entry {
                    return Ok((entry.source.len() <= max_bytes).then(|| entry.snapshot()));
                }
                self.delegate.read_source_snapshot_limited(file, max_bytes)
            },
            |source| source.as_ref().map(ProjectSourceSnapshot::oid),
        )
    }

    fn has_overlay(&self, file: &ProjectFile) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.overlay_membership(self.as_project(), file.rel_path()));
        let answer = {
            self.overlays
                .read()
                .expect("overlay lock poisoned")
                .contains_key(&file.abs_path())
        };
        super::project_reads::publish_overlay_membership(answer);
        answer
    }

    fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.overlays(self.as_project()));
        let answer = 'answer: {
            let revision = self.published_generation.load(Ordering::Acquire);
            let mut memo = self
                .overlay_content
                .lock()
                .expect("overlay content memo poisoned");
            if let Some((memoized_revision, content)) = memo.as_ref()
                && *memoized_revision == revision
            {
                break 'answer Some(Arc::clone(content));
            }
            let overlays = self.overlays.read().expect("overlay lock poisoned");
            let root = self.delegate.root();
            let content = Arc::new(WorkspaceOverlayContent::new(overlays.iter().filter_map(
                |(abs_path, entry)| {
                    let rel_path = abs_path.strip_prefix(root).ok()?;
                    Some((
                        ProjectFile::new(root.to_path_buf(), rel_path),
                        entry.content_digest,
                        entry.blob_id,
                    ))
                },
            )));
            *memo = Some((revision, Arc::clone(&content)));
            Some(content)
        };
        super::project_reads::publish_overlays(&answer);
        answer
    }

    fn analysis_generation(&self) -> u64 {
        self.published_generation.load(Ordering::Acquire)
    }
}

fn detect_languages(root: &Path) -> io::Result<BTreeSet<Language>> {
    Ok(detect_languages_in_files(&collect_workspace_files(root)?))
}

fn detect_languages_in_files(files: &BTreeSet<ProjectFile>) -> BTreeSet<Language> {
    let mut languages = BTreeSet::new();
    for file in files {
        let language = workspace_language_for_file(file);
        if language != Language::None {
            languages.insert(language);
        }
    }
    languages
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::write_file;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: the default supplied-set filter enumerated the workspace again while building listing receipts"
    )]
    fn default_language_filter_reuses_the_supplied_listing() {
        struct DefaultFilteringProject(TestProject);
        impl Project for DefaultFilteringProject {
            fn root(&self) -> &Path {
                self.0.root()
            }
            fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
                self.0.project_read_slot()
            }
            fn install_read_recorder(&self, capability: ReadCapability) -> bool {
                self.0.install_read_recorder(capability)
            }
            fn ignore_rules_digest(&self) -> io::Result<[u8; 32]> {
                self.0.ignore_rules_digest()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                self.0.analyzer_languages()
            }
            fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
                self.0.all_files()
            }
            fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
                self.0.analyzable_files(language)
            }
            fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
                self.0.file_by_rel_path(rel_path)
            }
        }

        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("a.py"), "answer = 42\n").unwrap();
        std::fs::write(root.join("b.ts"), "export const answer = 42;\n").unwrap();
        std::fs::write(root.join("README.md"), "Example project\n").unwrap();
        let project = DefaultFilteringProject(TestProject::new(root.clone(), Language::Python));
        let files = project.all_files().unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(project.0.workspace_file_listing_count(), 1);
        assert_eq!(
            project
                .analyzable_files_from(&files, Language::Python)
                .unwrap(),
            BTreeSet::from([ProjectFile::new(root, "a.py")])
        );
        let receipt = crate::analyzer::project_reads::file_set_receipt(&project, &files).unwrap();
        assert!(receipt.listing.is_some());
        assert!(receipt.inventory.is_some());
        assert_eq!(
            project.0.workspace_file_listing_count(),
            1,
            "language filtering and listing receipts must reuse the caller's one listing"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2770: file-set project coverage was not reported as its selected file count"
    )]
    #[test]
    fn file_set_project_reports_its_file_count_as_subset_coverage() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project =
            FileSetProject::new(&root, ["a.rs", "b.rs", "nested/c.rs"].map(PathBuf::from));

        assert_eq!(
            ProjectCoverage::Subset(SubsetCoverage { files: 3 }),
            project.coverage()
        );
        assert_eq!(
            Some(SubsetCoverage { files: 3 }),
            project.coverage().subset()
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2770: scoped sessions hid that query results covered only a subset of the workspace"
    )]
    #[test]
    fn overlay_project_reports_its_delegate_coverage() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let files = FileSetProject::new(&root, ["a.rs", "b.rs", "nested/c.rs"].map(PathBuf::from));
        let overlay = OverlayProject::new(Arc::new(files));

        assert_eq!(
            ProjectCoverage::Subset(SubsetCoverage { files: 3 }),
            overlay.coverage()
        );

        // A buffer supplies bytes, not membership, so opening one does not
        // change what slice of the workspace the session covers.
        assert!(overlay.set(root.join("a.rs"), "fn a() {}".to_string()));
        assert_eq!(
            ProjectCoverage::Subset(SubsetCoverage { files: 3 }),
            overlay.coverage()
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2770: filesystem project coverage did not identify whole-workspace analysis"
    )]
    #[test]
    fn filesystem_project_reports_whole_workspace_coverage() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "a.rs", "fn a() {}\n");
        let project = FilesystemProject::new(&root).unwrap();

        assert_eq!(ProjectCoverage::Whole, project.coverage());
        assert_eq!(None, project.coverage().subset());
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2770: subset coverage serialized with the wrong file-count shape"
    )]
    #[test]
    fn subset_coverage_serializes_as_a_file_count() {
        assert_eq!(
            serde_json::json!({ "files": 12 }),
            serde_json::to_value(SubsetCoverage { files: 12 }).unwrap()
        );
    }

    #[test]
    fn default_source_reads_admit_legacy_non_utf8_text() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "legacy.cpp");
        let source = b"void run(); // first \x97 then second\n";
        std::fs::write(file.abs_path(), source).unwrap();
        let project = TestProject::new(&root, Language::Cpp);

        let expected = "void run(); // first \u{FFFD} then second\n";
        assert_eq!(expected, project.read_source(&file).unwrap());
        let snapshot = project.read_source_snapshot(&file).unwrap();
        assert_eq!(snapshot.source(), expected);
        assert_eq!(
            snapshot.oid(),
            Oid::hash_object(ObjectType::Blob, source).unwrap()
        );
        assert_ne!(snapshot.oid(), ProjectSourceSnapshot::disk(expected).oid());
        assert_eq!(
            project
                .read_source_snapshot_limited(&file, source.len())
                .unwrap(),
            Some(snapshot)
        );
        assert!(
            project
                .read_source_snapshot_limited(&file, source.len() - 1)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            Some(expected.to_string()),
            project.read_source_limited(&file, source.len()).unwrap()
        );
        assert_eq!(
            None,
            project
                .read_source_limited(&file, source.len() - 1)
                .unwrap()
        );
    }

    #[test]
    fn source_snapshot_defaults_preserve_custom_readers() {
        struct CustomSourceProject {
            delegate: TestProject,
            reads: AtomicUsize,
        }

        impl Project for CustomSourceProject {
            fn root(&self) -> &Path {
                self.delegate.root()
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                let _project_read = listing_read(self);
                self.delegate.analyzer_languages()
            }
            fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
                let _project_read = listing_read(self);
                self.delegate.all_files()
            }
            fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
                let _project_read = listing_read(self);
                self.delegate.analyzable_files(language)
            }
            fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
                let _project_read = listing_read(self);
                self.delegate.file_by_rel_path(rel_path)
            }
            fn read_source(&self, _file: &ProjectFile) -> io::Result<String> {
                self.reads.fetch_add(1, Ordering::Relaxed);
                Ok("class Custom {}".to_owned())
            }
            fn read_source_limited(
                &self,
                file: &ProjectFile,
                max_bytes: usize,
            ) -> io::Result<Option<String>> {
                let source = self.read_source(file)?;
                Ok((source.len() <= max_bytes).then_some(source))
            }
        }

        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "Custom.java", "class Disk {}");
        let project = CustomSourceProject {
            delegate: TestProject::new(&root, Language::Java),
            reads: AtomicUsize::new(0),
        };
        let expected = ProjectSourceSnapshot::disk("class Custom {}");
        // Pin the snapshot's fields against independent values first, so the
        // comparisons below cannot pass on a `disk` that builds the same wrong
        // snapshot twice. The oid is the git blob id of the same bytes, from
        // `printf 'class Custom {}' | git hash-object --stdin`.
        assert_eq!(expected.source(), "class Custom {}");
        assert_eq!(
            expected.oid(),
            Oid::from_str("fb6c358aff440a7e0edb6ea631eecf20eb56f166").unwrap()
        );
        assert_eq!(expected.origin(), ProjectSourceOrigin::Disk);
        assert_ne!(
            expected.oid(),
            ProjectSourceSnapshot::disk("class Disk {}").oid(),
            "different texts must have different content identities"
        );
        assert_eq!(project.read_source_snapshot(&file).unwrap(), expected);
        assert_eq!(project.reads.load(Ordering::Relaxed), 1);
        assert_eq!(
            project
                .read_source_snapshot_limited(&file, expected.source().len())
                .unwrap(),
            Some(expected)
        );
        assert_eq!(project.reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn default_source_reads_reject_nul_bearing_binary_data() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "binary.java");
        let source = [0, b'J', b'A', b'V', b'A', 0xFF];
        std::fs::write(file.abs_path(), source).unwrap();
        let project = TestProject::new(&root, Language::Java);

        assert_eq!(
            io::ErrorKind::InvalidData,
            project.read_source(&file).unwrap_err().kind()
        );
        assert_eq!(
            io::ErrorKind::InvalidData,
            project.read_source_snapshot(&file).unwrap_err().kind()
        );
        assert_eq!(
            io::ErrorKind::InvalidData,
            project
                .read_source_snapshot_limited(&file, source.len())
                .unwrap_err()
                .kind()
        );
        assert_eq!(
            io::ErrorKind::InvalidData,
            project
                .read_source_limited(&file, source.len())
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn collect_project_files_skips_dot_git_but_keeps_other_dotdirs() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "real.rs", "fn real() {}\n");
        // VCS internals must never be walked, even though `.git` is not matched
        // by `.gitignore` and hidden entries are otherwise kept.
        write_file(&root, ".git/sneaky.rs", "fn sneaky() {}\n");
        write_file(&root, ".git/info/exclude", "excluded.rs\n");
        write_file(&root, "excluded.rs", "fn excluded() {}\n");
        write_file(&root, ".gitignore", "sub/\n");
        write_file(&root, "sub/ignored.rs", "fn ignored() {}\n");
        // Legitimate dotted source/config stays in scope.
        write_file(&root, ".github/wf.rs", "fn wf() {}\n");

        let rels: BTreeSet<String> = collect_workspace_files(&root)
            .unwrap()
            .into_iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(rels.contains("real.rs"), "{rels:?}");
        assert!(rels.contains(".github/wf.rs"), "{rels:?}");
        assert!(
            !rels.iter().any(|p| p.starts_with(".git/")),
            "`.git` internals must not be walked: {rels:?}"
        );
        assert!(
            !rels.contains("excluded.rs"),
            "`.git/info/exclude` must still apply: {rels:?}"
        );
        assert!(
            !rels.contains("sub/ignored.rs"),
            "`.gitignore` must still apply: {rels:?}"
        );
    }

    #[test]
    fn collect_project_files_keeps_tracked_files_that_match_gitignore() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&root);
        write_file(&root, "src/db/mod.rs", "pub fn connection() {}\n");
        crate::gitblob::test_repo::commit_all(&repo, "tracked source");
        write_file(&root, ".gitignore", "db/\n");
        write_file(&root, "generated/db/ignored.rs", "fn generated() {}\n");

        let rels: BTreeSet<String> = collect_workspace_files(&root)
            .unwrap()
            .into_iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(rels.contains("src/db/mod.rs"), "{rels:?}");
        assert!(!rels.contains("generated/db/ignored.rs"), "{rels:?}");
        let project = FilesystemProject::new(&root).unwrap();
        assert!(
            project
                .analyzable_files(Language::Rust)
                .unwrap()
                .contains(&ProjectFile::new(&root, "src/db/mod.rs"))
        );
    }

    #[test]
    fn collect_project_files_includes_nonignored_untracked_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&root);
        write_file(&root, "tracked.rs", "fn tracked() {}\n");
        crate::gitblob::test_repo::commit_all(&repo, "tracked source");
        write_file(&root, "generated.rs", "fn generated() {}\n");
        write_file(&root, ".gitignore", "ignored/\n");
        write_file(&root, "ignored/ignored.rs", "fn ignored() {}\n");

        let rels: BTreeSet<String> = collect_workspace_files(&root)
            .unwrap()
            .into_iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(rels.contains("tracked.rs"), "{rels:?}");
        assert!(rels.contains("generated.rs"), "{rels:?}");
        assert!(!rels.contains("ignored/ignored.rs"), "{rels:?}");
    }

    #[test]
    fn collect_project_files_maps_tracked_ignored_files_into_subdirectory_workspace() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&repo_root);
        write_file(
            &repo_root,
            "packages/app/src/db/mod.rs",
            "pub fn connection() {}\n",
        );
        write_file(&repo_root, "packages/lib/tracked.rs", "fn tracked() {}\n");
        crate::gitblob::test_repo::commit_all(&repo, "tracked app source");
        write_file(&repo_root, ".gitignore", "db/\n");
        // The enumeration is scoped to the workspace subtree. Tracked and
        // untracked files on both sides of that boundary pin the membership.
        write_file(&repo_root, "packages/app/untracked.rs", "fn app() {}\n");
        write_file(&repo_root, "packages/lib/untracked.rs", "fn lib() {}\n");
        let app_root = repo_root.join("packages/app");

        let rels: BTreeSet<String> = collect_workspace_files(&app_root)
            .unwrap()
            .into_iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect();

        assert_eq!(
            rels,
            BTreeSet::from(["src/db/mod.rs".to_string(), "untracked.rs".to_string()])
        );
    }

    #[test]
    fn collect_project_files_walks_explicit_root_ignored_by_ancestor_repository() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&repo_root);
        write_file(&repo_root, ".gitignore", "/target/\n");
        crate::gitblob::test_repo::commit_all(&repo, "ignore build output");
        write_file(
            &repo_root,
            "target/extracted/main.go",
            "package main\n\nfunc main() {}\n",
        );
        let extracted_root = repo_root.join("target/extracted");

        let rels: BTreeSet<String> = collect_workspace_files(&extracted_root)
            .unwrap()
            .into_iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect();

        assert_eq!(rels, BTreeSet::from(["main.go".to_string()]));
    }

    #[cfg(unix)]
    #[test]
    fn collect_project_files_maps_tracked_ignored_files_through_symlinked_workspace() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        std::fs::create_dir(&repo_root).unwrap();
        let repo_root = repo_root.canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&repo_root);
        write_file(
            &repo_root,
            "packages/app/src/db/mod.rs",
            "pub fn connection() {}\n",
        );
        crate::gitblob::test_repo::commit_all(&repo, "tracked app source");
        write_file(&repo_root, ".gitignore", "db/\n");
        let linked_root = temp.path().join("linked-app");
        std::os::unix::fs::symlink(repo_root.join("packages/app"), &linked_root).unwrap();

        let rels: BTreeSet<String> = collect_workspace_files(&linked_root)
            .unwrap()
            .into_iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect();

        assert_eq!(rels, BTreeSet::from(["src/db/mod.rs".to_string()]));
    }

    #[test]
    fn workspace_file_listing_cache_refreshes_git_index_union_on_invalidate() {
        // Tracked files shadowed by broad ignore patterns are listed via the
        // git-index union, not the walk; invalidation must recompute both.
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        let repo = crate::gitblob::test_repo::init_repo(&root);
        write_file(&root, "src/db/mod.rs", "pub fn connection() {}\n");
        crate::gitblob::test_repo::commit_all(&repo, "tracked source");
        write_file(&root, ".gitignore", "db/\n");

        let cache = WorkspaceFileListingCache::new(root.clone());
        let tracked = ProjectFile::new(&root, "src/db/mod.rs");
        assert!(cache.files().unwrap().contains(&tracked));

        // Ignored and untracked: hidden even after invalidation.
        let generated = write_file(&root, "generated/db/new.rs", "fn generated() {}\n");
        cache.invalidate();
        assert!(!cache.files().unwrap().contains(&generated));
        assert!(cache.files().unwrap().contains(&tracked));

        // Staging the ignored file makes it tracked; the refreshed index
        // union must list it after the next invalidation.
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("generated/db/new.rs")).unwrap();
        index.write().unwrap();
        cache.invalidate();
        assert!(cache.files().unwrap().contains(&generated));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2542: cached constructor listings hid newly added Kotlin source after invalidation"
    )]
    #[test]
    fn filesystem_project_invalidation_discards_constructor_listing() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "a.rs", "fn a() {}\n");
        let project = FilesystemProject::new(&root).unwrap();

        let added = write_file(&root, "b.rs", "fn b() {}\n");
        project.invalidate_cached_file_listing();

        assert!(project.all_files_shared().unwrap().contains(&added));
        assert_eq!(project.workspace_file_listing_count(), 1);
    }

    /// Invalidation must also drop the cached `.bifrostignore` matcher, or the
    /// project keeps answering from the rules it read before the edit. The
    /// oracle is the rule file on disk after the edit.
    #[test]
    fn invalidation_rereads_edited_bifrostignore_rules() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        write_file(&root, ".bifrostignore", "vendor/\n");
        let kept = write_file(&root, "a.rs", "fn a() {}\n");
        let vendored = write_file(&root, "vendor/x.rs", "fn x() {}\n");
        let project = FilesystemProject::new(&root).unwrap();

        assert!(project.is_bifrostignored(Path::new("vendor/x.rs")));
        assert_eq!(
            BTreeSet::from([kept.clone()]),
            project.analyzable_files(Language::Rust).unwrap()
        );

        write_file(&root, ".bifrostignore", "a.rs\n");
        project.invalidate_cached_file_listing();

        assert!(!project.is_bifrostignored(Path::new("vendor/x.rs")));
        assert!(project.is_bifrostignored(Path::new("a.rs")));
        assert_eq!(
            BTreeSet::from([vendored]),
            project.analyzable_files(Language::Rust).unwrap()
        );
    }

    /// `is_bifrostignored` answers one path per call and callers ask it per
    /// path across a whole revision, so its cost must not include a
    /// whole-workspace listing once the ignore matcher exists. On a
    /// `FilesystemProject` with no listing cache each listing is a fresh
    /// directory walk plus a repository-wide `git status` subprocess, which
    /// made a warm `--diff-base` policy run spawn one `git status` per
    /// committed blob (#2769).
    #[test]
    fn repeated_ignore_questions_take_one_workspace_listing() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        write_file(&root, ".bifrostignore", "vendor/\n");
        write_file(&root, "kept.rs", "fn kept() {}\n");
        write_file(&root, "vendor/skipped.rs", "fn skipped() {}\n");
        let project = FilesystemProject::new(&root).unwrap();

        // The discovery fill already compiled the matcher. Probes must use
        // those same rules without asking for another listing.
        for _ in 0..8 {
            assert!(project.is_bifrostignored(Path::new("vendor/skipped.rs")));
            assert!(!project.is_bifrostignored(Path::new("kept.rs")));
        }

        assert_eq!(
            project.workspace_file_listing_count(),
            0,
            "the discovery fill built the matcher; every later probe reuses it"
        );
    }

    /// `.bifrostignore` uses gitignore syntax, so Git is the oracle: the same
    /// tree is listed by `git ls-files --others --exclude-per-directory`
    /// naming `.bifrostignore` as the per-directory ignore file, and every
    /// answer the project gives must agree with it.
    ///
    /// The rules cover a leading byte-order mark, negation and last match
    /// wins, a negation that cannot re-include a file under an excluded
    /// directory, directory-only rules next to a regular file of the same
    /// name, anchored and middle-slash rules, `**` globs, a nested ignore file
    /// whose whitelist overrides the root rule, and a directory that is named
    /// `.bifrostignore` (Git reads no rules from it, and neither may we).
    #[test]
    fn bifrostignore_answers_agree_with_git_on_a_rule_family() {
        const ROOT_RULES: &str = concat!(
            "\u{feff}vendor/\n",
            "!vendor/keep.rs\n",
            "*.gen.rs\n",
            "!keep.gen.rs\n",
            "/anchored.rs\n",
            "lib/inner.rs\n",
            "docs/**/*.rs\n",
            "**/cache/\n",
            "out/\n",
            "tmp.rs/\n",
            "build\n",
        );
        const SUB_RULES: &str = "!kept.gen.rs\n/local.rs\n";
        const TREE: [&str; 26] = [
            "a.rs",
            "vendor/x.rs",
            "vendor/keep.rs",
            "one.gen.rs",
            "keep.gen.rs",
            "sub/kept.gen.rs",
            "sub/dropped.gen.rs",
            "sub/local.rs",
            "sub/deeper/local.rs",
            "anchored.rs",
            "src/anchored.rs",
            "lib/inner.rs",
            "src/lib/inner.rs",
            "docs/a.rs",
            "docs/x/y/b.rs",
            "docs/readme.md",
            "cache/a.rs",
            "deep/cache/b.rs",
            "out",
            "src/out/x.rs",
            "tmp.rs",
            "nested/tmp.rs/inner.rs",
            "build",
            "tools/build/x.rs",
            "docs2/a.rs",
            "sub/.bifrostignore",
        ];

        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        write_file(&root, BIFROST_IGNORE_FILE_NAME, ROOT_RULES);
        for rel in TREE {
            if rel != "sub/.bifrostignore" {
                write_file(&root, rel, "fn f() {}\n");
            }
        }
        write_file(&root, "sub/.bifrostignore", SUB_RULES);
        std::fs::create_dir_all(root.join("docs2").join(BIFROST_IGNORE_FILE_NAME)).unwrap();

        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .current_dir(&root)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(args)
                .output()
                .expect("run git");
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        git(&["init", "-q", "."]);
        let listed = git(&[
            "ls-files",
            "-z",
            "--others",
            "--exclude-per-directory=.bifrostignore",
        ]);
        let git_kept: BTreeSet<PathBuf> = String::from_utf8(listed)
            .unwrap()
            .split('\0')
            .filter(|rel| !rel.is_empty())
            .map(PathBuf::from)
            .collect();
        // Guard against a vacuous oracle: Git must have read the rules.
        assert!(!git_kept.contains(Path::new("vendor/x.rs")), "{git_kept:?}");
        assert!(
            git_kept.contains(Path::new("sub/kept.gen.rs")),
            "{git_kept:?}"
        );

        let project = FilesystemProject::new(&root).unwrap();
        let disagreements: Vec<(&str, bool)> = TREE
            .iter()
            .map(|rel| (*rel, project.is_bifrostignored(Path::new(rel))))
            .filter(|(rel, ignored)| *ignored == git_kept.contains(Path::new(rel)))
            .collect();
        assert!(
            disagreements.is_empty(),
            "is_bifrostignored disagrees with git on {disagreements:?}; git kept {git_kept:?}"
        );

        let all_files = project.all_files().unwrap();
        let expected: BTreeSet<ProjectFile> = all_files
            .iter()
            .filter(|file| file.language() == Language::Rust)
            .filter(|file| git_kept.contains(file.rel_path()))
            .cloned()
            .collect();
        assert_eq!(expected, project.analyzable_files(Language::Rust).unwrap());
        assert_eq!(
            expected,
            project
                .analyzable_files_from(&all_files, Language::Rust)
                .unwrap()
        );
    }

    /// Git reads ignore files as bytes, but `.bifrostignore` rules must be
    /// UTF-8, so here Bifrost deliberately differs from Git. Rules that cannot
    /// be read must not be taken for "no rules": the analyzable listing fails
    /// with the read error instead of analyzing files the user excluded. The
    /// single-path probe returns a bool and answers "not ignored", which is its
    /// documented fail-open choice; answering "ignored" would make an overlay
    /// drop every buffer.
    #[test]
    fn unreadable_bifrostignore_fails_listing_and_ignores_nothing() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        write_file(&root, "a.rs", "fn a() {}\n");
        let project = FilesystemProject::new(&root).unwrap();
        std::fs::write(root.join(BIFROST_IGNORE_FILE_NAME), b"vendor/\n\xff\xfe\n").unwrap();
        project.invalidate_cached_file_listing();
        assert!(!project.is_bifrostignored(Path::new("a.rs")));
        let error = project.analyzable_files(Language::Rust).unwrap_err();
        assert_eq!(io::ErrorKind::InvalidData, error.kind(), "{error}");
        // Construction also fills the listing and reads its rule inputs.
        let error = FilesystemProject::new(&root).unwrap_err();
        assert_eq!(io::ErrorKind::InvalidData, error.kind(), "{error}");
    }

    #[test]
    fn fileset_project_disables_persistence() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project = FileSetProject::new(root.clone(), [PathBuf::from("A.java")]);
        assert_eq!(project.root(), root.normalize());
        assert!(project.persistence_root().is_none());
    }

    /// A multi-root session has no repository of its own, but it does have a
    /// persistence identity: the machine-local directory named by its root set.
    #[test]
    fn multi_root_project_persists_under_the_machine_cache_root() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = root.join("service-a");
        let second = root.join("service-b");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let cache_root = root.join("machine-cache");

        let project =
            MultiRootProject::with_cache_root([first.clone(), second.clone()], cache_root.clone())
                .unwrap();
        let persistence_root = project
            .persistence_root()
            .expect("a multi-root project persists")
            .to_path_buf();

        assert!(
            persistence_root.starts_with(&cache_root),
            "expected a machine-local directory, got {}",
            persistence_root.display()
        );
        assert!(
            !persistence_root.starts_with(&first) && !persistence_root.starts_with(&second),
            "no member repository may host the shared database: {}",
            persistence_root.display()
        );
        assert_eq!(
            MultiRootProject::with_cache_root([second, first], cache_root)
                .unwrap()
                .persistence_root(),
            Some(persistence_root.as_path()),
            "the same folders in the other order are the same workspace"
        );
        assert!(
            !persistence_root.exists(),
            "constructing a project must not create cache directories"
        );
    }

    /// Sibling roots share their parent as the workspace root, and every file
    /// is listed relative to it. The oracle is the directory layout the test
    /// builds. The three-root case nests two roots one level deeper than the
    /// third, and the third sorts last, so only the last root lifts the
    /// ancestor from `group` to the parent.
    #[test]
    fn multi_root_project_roots_sibling_folders_at_their_parent() {
        let temp = TempDir::new().unwrap();
        let parent = temp.path().canonicalize().unwrap().normalize();
        let cache_root = parent.join("machine-cache");

        let a = write_file(&parent, "service-a/a.rs", "fn a() {}\n");
        let b = write_file(&parent, "service-b/b.rs", "fn b() {}\n");
        let two = MultiRootProject::with_cache_root(
            [parent.join("service-a"), parent.join("service-b")],
            cache_root.clone(),
        )
        .unwrap();
        assert_eq!(two.root(), parent.as_path());
        assert_eq!(BTreeSet::from([a, b]), two.all_files().unwrap());

        let grouped_a = write_file(&parent, "group/x/x.rs", "fn x() {}\n");
        let grouped_b = write_file(&parent, "group/y/y.rs", "fn y() {}\n");
        let lone = write_file(&parent, "lone/z.rs", "fn z() {}\n");
        let three = MultiRootProject::with_cache_root(
            [
                parent.join("group").join("x"),
                parent.join("group").join("y"),
                parent.join("lone"),
            ],
            cache_root,
        )
        .unwrap();
        assert_eq!(three.root(), parent.as_path());
        assert_eq!(
            BTreeSet::from([grouped_a, grouped_b, lone]),
            three.all_files().unwrap()
        );
    }

    #[test]
    fn a_buffer_outliving_its_file_stays_listed_until_it_is_cleared() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let open = write_file(&root, "src/open.rs", "fn saved() {}\n");
        let other = write_file(&root, "src/other.rs", "fn other() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);
        assert!(overlay.set(open.abs_path(), "fn unsaved() {}\n".to_string()));

        // The editor's file is deleted underneath the open buffer.
        std::fs::remove_file(open.abs_path()).unwrap();

        assert_eq!(
            BTreeSet::from([open.clone(), other.clone()]),
            overlay.all_files().unwrap(),
            "a path served from a buffer must be a path the project lists"
        );
        assert_eq!(
            BTreeSet::from([open.clone(), other.clone()]),
            *overlay.all_files_shared().unwrap(),
        );
        assert_eq!(
            BTreeSet::from([open.clone(), other.clone()]),
            overlay.analyzable_files(Language::Rust).unwrap(),
        );
        assert_eq!(
            BTreeSet::from([open.clone()]),
            overlay
                .analyzable_files_from(&BTreeSet::from([open.clone()]), Language::Rust)
                .unwrap(),
        );
        assert_eq!(
            Some(open.clone()),
            overlay.file_by_abs_path(&open.abs_path()),
            "the buffer must stay resolvable, or the editor can neither edit nor close it"
        );
        assert_eq!(
            Some(open.clone()),
            overlay.file_by_rel_path(open.rel_path())
        );
        assert!(overlay.has_directory(Path::new("src")));
        assert_eq!("fn unsaved() {}\n", overlay.read_source(&open).unwrap());

        // `didClose` is the release point: after it nothing serves the path.
        assert!(overlay.clear(&open.abs_path()));
        assert_eq!(
            BTreeSet::from([other.clone()]),
            overlay.all_files().unwrap(),
            "a closed buffer over a deleted file must leave nothing behind"
        );
        assert_eq!(
            BTreeSet::from([other]),
            overlay.analyzable_files(Language::Rust).unwrap(),
        );
        assert_eq!(None, overlay.file_by_abs_path(&open.abs_path()));
        assert!(overlay.read_source(&open).is_err());
    }

    #[test]
    fn a_buffer_does_not_carry_an_ignored_path_into_the_workspace() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, BIFROST_IGNORE_FILE_NAME, "generated/\n");
        let generated = write_file(&root, "generated/machine.rs", "fn generated() {}\n");
        let handwritten = write_file(&root, "src/handwritten.rs", "fn handwritten() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);
        assert!(overlay.set(generated.abs_path(), "fn edited() {}\n".to_string()));

        let analyzable = |overlay: &OverlayProject| {
            overlay
                .analyzable_files(Language::Rust)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            vec![handwritten.clone()],
            analyzable(&overlay),
            "opening an ignored file must not add it to the analyzed workspace"
        );
        assert_eq!("fn edited() {}\n", overlay.read_source(&generated).unwrap());

        // Still ignored once the file is gone and the buffer is all that is
        // left: what the delegate excludes by rule, a buffer cannot smuggle in.
        std::fs::remove_file(generated.abs_path()).unwrap();
        assert_eq!(vec![handwritten], analyzable(&overlay));
        assert_eq!(
            Some(generated.clone()),
            overlay.file_by_abs_path(&generated.abs_path()),
            "an ignored path still resolves while a buffer serves it, so the editor \
             can close the document"
        );
        assert_eq!("fn edited() {}\n", overlay.read_source(&generated).unwrap());
    }

    #[test]
    fn source_snapshots_are_bounded_and_preserve_overlay_revision_identity() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let disk_source = "fn disk() {}\n";
        let file = write_file(&root, "lib.rs", disk_source);
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);

        let disk = overlay.read_source_snapshot(&file).unwrap();
        assert_eq!(disk.source(), disk_source);
        assert_eq!(disk.origin(), ProjectSourceOrigin::Disk);
        assert_eq!(
            disk.oid(),
            Oid::hash_object(ObjectType::Blob, disk_source.as_bytes()).unwrap()
        );
        assert!(
            overlay
                .read_source_snapshot_limited(&file, disk_source.len() - 1)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            overlay
                .read_source_snapshot_limited(&file, disk_source.len())
                .unwrap()
                .unwrap(),
            disk
        );

        let repeated_source = "fn repeated() {}\n";
        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let first = overlay.read_source_snapshot(&file).unwrap();
        let ProjectSourceOrigin::Overlay(first_revision) = first.origin() else {
            panic!("accepted overlay snapshot must carry an overlay revision");
        };

        assert!(overlay.set(file.abs_path(), "fn middle() {}\n".to_owned()));
        let middle = overlay.read_source_snapshot(&file).unwrap();
        let ProjectSourceOrigin::Overlay(middle_revision) = middle.origin() else {
            panic!("replacement overlay snapshot must carry an overlay revision");
        };
        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let repeated = overlay.read_source_snapshot(&file).unwrap();
        let ProjectSourceOrigin::Overlay(repeated_revision) = repeated.origin() else {
            panic!("repeated overlay snapshot must carry an overlay revision");
        };

        assert_eq!(first.source(), repeated.source());
        assert_eq!(first.oid(), repeated.oid());
        assert_ne!(first.oid(), middle.oid());
        assert_eq!(
            first.oid(),
            Oid::hash_object(ObjectType::Blob, repeated_source.as_bytes()).unwrap()
        );
        assert!(first_revision < middle_revision);
        assert!(middle_revision < repeated_revision);
        assert_ne!(first_revision, repeated_revision);
        assert!(
            overlay
                .read_source_snapshot_limited(&file, repeated_source.len() - 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn overlay_project_snapshot_freezes_content_and_analysis_generation() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);
        assert!(overlay.set(file.abs_path(), "fn first() {}\n".to_string()));

        let snapshot = overlay.snapshot();
        let frozen_generation = snapshot.analysis_generation();
        assert_eq!(frozen_generation, overlay.analysis_generation());
        {
            let live = overlay.overlays.read().expect("overlay lock poisoned");
            let frozen = snapshot.overlays.read().expect("overlay lock poisoned");
            assert!(Arc::ptr_eq(
                live.get(&file.abs_path()).unwrap(),
                frozen.get(&file.abs_path()).unwrap(),
            ));
        }
        let frozen_revision = match snapshot.read_source_snapshot(&file).unwrap().origin() {
            ProjectSourceOrigin::Overlay(revision) => revision,
            ProjectSourceOrigin::Disk => panic!("snapshot should retain its overlay"),
        };
        assert!(overlay.set(file.abs_path(), "fn second() {}\n".to_string()));

        assert_eq!(snapshot.read_source(&file).unwrap(), "fn first() {}\n");
        assert_eq!(overlay.read_source(&file).unwrap(), "fn second() {}\n");
        assert_eq!(
            snapshot.analysis_generation(),
            frozen_generation,
            "a later live edit must not invalidate a frozen request view"
        );
        assert!(overlay.analysis_generation() > frozen_generation);
        assert_eq!(
            snapshot.read_source_snapshot(&file).unwrap().origin(),
            ProjectSourceOrigin::Overlay(frozen_revision)
        );
    }

    #[test]
    fn live_and_snapshot_mutations_publish_independent_globally_unique_revisions() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let live = OverlayProject::new(delegate);
        assert!(live.set(file.abs_path(), "fn first() {}\n".to_string()));
        let first_generation = live.analysis_generation();

        let snapshot = live.snapshot();
        assert_eq!(snapshot.analysis_generation(), first_generation);
        assert!(snapshot.set(file.abs_path(), "fn snapshot() {}\n".to_string()));
        let snapshot_generation = snapshot.analysis_generation();
        assert!(snapshot_generation > first_generation);
        assert_eq!(
            live.analysis_generation(),
            first_generation,
            "mutating the snapshot must not invalidate the live view"
        );
        let ProjectSourceOrigin::Overlay(snapshot_revision) =
            snapshot.read_source_snapshot(&file).unwrap().origin()
        else {
            panic!("the snapshot mutation must publish an overlay revision")
        };
        assert_eq!(snapshot_revision.get(), snapshot_generation);

        assert!(live.set(file.abs_path(), "fn live() {}\n".to_string()));
        let live_generation = live.analysis_generation();
        assert!(live_generation > snapshot_generation);
        assert_eq!(
            snapshot.analysis_generation(),
            snapshot_generation,
            "mutating the live view must not invalidate the snapshot"
        );
        let ProjectSourceOrigin::Overlay(live_revision) =
            live.read_source_snapshot(&file).unwrap().origin()
        else {
            panic!("the live mutation must publish an overlay revision")
        };
        assert_eq!(live_revision.get(), live_generation);
        assert_ne!(live_revision, snapshot_revision);
        assert_eq!(snapshot.read_source(&file).unwrap(), "fn snapshot() {}\n");
        assert_eq!(live.read_source(&file).unwrap(), "fn live() {}\n");

        assert!(snapshot.clear(&file.abs_path()));
        let snapshot_clear_generation = snapshot.analysis_generation();
        assert!(snapshot_clear_generation > live_generation);
        assert_eq!(live.analysis_generation(), live_generation);
        assert_eq!(snapshot.read_source(&file).unwrap(), "fn disk() {}\n");
        assert_eq!(live.read_source(&file).unwrap(), "fn live() {}\n");
    }

    #[test]
    fn overlay_analysis_generation_advances_for_set_clear_and_clear_all() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);
        let initial = overlay.analysis_generation();

        assert!(overlay.set(file.abs_path(), "fn first() {}\n".to_string()));
        let after_set = overlay.analysis_generation();
        assert!(after_set > initial);
        assert!(overlay.clear(&file.abs_path()));
        let after_clear = overlay.analysis_generation();
        assert!(after_clear > after_set);
        assert!(overlay.set(file.abs_path(), "fn second() {}\n".to_string()));
        let before_clear_all = overlay.analysis_generation();
        overlay.clear_all();
        assert!(overlay.analysis_generation() > before_clear_all);
    }

    #[test]
    fn overlay_removal_publishes_generation_before_readers_see_the_new_map() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "app.ts", "class Disk {}\n");
        let delegate: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(delegate));
        assert!(overlay.set(file.abs_path(), "class Overlay {}\n".to_string()));
        let old_generation = overlay.analysis_generation();

        let (removed_tx, removed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let clearing = {
            let overlay = Arc::clone(&overlay);
            let path = file.abs_path();
            thread::spawn(move || {
                overlay.remove_overlay_with_revision_hook(&path, || {
                    removed_tx.send(()).expect("signal removal");
                    release_rx.recv().expect("release removal");
                })
            })
        };
        removed_rx.recv().expect("overlay removed under write lock");
        assert_eq!(overlay.analysis_generation(), old_generation);

        let (read_tx, read_rx) = mpsc::channel();
        let reading = {
            let overlay = Arc::clone(&overlay);
            let file = file.clone();
            thread::spawn(move || {
                read_tx
                    .send(overlay.has_overlay(&file))
                    .expect("send observed overlay state");
            })
        };
        assert!(
            matches!(
                read_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "a reader must remain behind the removal write lock until the generation advances"
        );

        release_tx.send(()).expect("release removal hook");
        assert!(clearing.join().expect("clear thread"));
        assert!(!read_rx.recv().expect("reader result"));
        reading.join().expect("reader thread");
        assert!(overlay.analysis_generation() > old_generation);
    }

    #[test]
    fn file_by_rel_path_rejects_directories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src/nested")).unwrap();
        write_file(&root, "src/lib.rs", "fn lib() {}\n");

        let test_project = TestProject::new(root.clone(), Language::Rust);
        assert!(
            test_project
                .file_by_rel_path(Path::new("src/lib.rs"))
                .is_some()
        );
        assert!(test_project.file_by_rel_path(Path::new("src")).is_none());

        let filesystem_project = FilesystemProject::new(&root).unwrap();
        assert!(
            filesystem_project
                .file_by_rel_path(Path::new("src/lib.rs"))
                .is_some()
        );
        assert!(
            filesystem_project
                .file_by_rel_path(Path::new("src"))
                .is_none()
        );
    }

    #[test]
    fn overlay_project_oversized_set_clears_prior_overlay() {
        // Sequence: small overlay accepted, then huge overlay rejected. The
        // existing overlay must be cleared so the next read returns disk
        // content (not the now-misleading older buffer).
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::with_max_bytes(delegate, 16);

        assert!(overlay.set(file.abs_path(), "fn small() {}\n".to_string()));
        assert!(overlay.has_overlay(&file));
        assert_eq!(overlay.read_source(&file).unwrap(), "fn small() {}\n");

        // Now exceed the cap; the small overlay must be evicted.
        assert!(!overlay.set(file.abs_path(), "x".repeat(64)));
        assert!(
            !overlay.has_overlay(&file),
            "oversized set must evict the prior overlay"
        );
        assert_eq!(
            overlay.read_source(&file).unwrap(),
            "fn disk() {}\n",
            "after rejection, read must fall through to disk"
        );
    }
}
