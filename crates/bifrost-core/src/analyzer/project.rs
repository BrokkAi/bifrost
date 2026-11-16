pub(crate) mod ignore_inputs;
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
use std::time::{Duration, Instant, SystemTime};

/// Default upper bound (8 MiB) on the size of a single in-memory overlay.
/// Picked to cover all hand-written source comfortably while bounding the
/// blast radius of an editor that opens a multi-MB minified bundle or vendor
/// blob — tree-sitter still parses such files, but holding many of them in
/// memory simultaneously across an LSP session quickly becomes expensive.
/// `OverlayProject::set` rejects content above this cap (and logs once per
/// path per `OVERLAY_REJECTION_LOG_THROTTLE`); reads fall through to disk
/// instead.
pub const DEFAULT_MAX_OVERLAY_BYTES: usize = 8 * 1024 * 1024;

static NEXT_PROJECT_VIEW_ID: AtomicU64 = AtomicU64::new(1);

fn next_project_view_id() -> u64 {
    NEXT_PROJECT_VIEW_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("project view id space exhausted")
}

/// An owner-local view revision, optionally paired with the view it wraps.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProjectViewStamp {
    view_id: u64,
    generation: u64,
    delegate: Option<Box<ProjectViewStamp>>,
}

impl ProjectViewStamp {
    /// Frame this process-local view identity for in-memory request keys only.
    pub fn hash_into(&self, hash: &mut crate::analyzer::canonical_hash::CanonicalHasher) {
        let mut cursor = Some(self);
        while let Some(stamp) = cursor {
            hash.field("view_id", &stamp.view_id.to_be_bytes());
            hash.field("generation", &stamp.generation.to_be_bytes());
            cursor = stamp.delegate.as_deref();
            hash.field("has_delegate", &[u8::from(cursor.is_some())]);
        }
    }

    fn own(view_id: u64, generation: u64) -> Self {
        Self {
            view_id,
            generation,
            delegate: None,
        }
    }

    fn over(mut self, delegate: ProjectViewStamp) -> Self {
        self.delegate = Some(Box::new(delegate));
        self
    }
}

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

/// The operation whose failure prevented an ignore observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoreObservationOperation {
    Listing,
    Matcher,
}

/// An observation failure is neither an ignored nor a visible answer.
#[derive(Clone, Debug)]
pub struct IgnoreObservationError {
    pub path: PathBuf,
    pub operation: IgnoreObservationOperation,
    pub cause: Arc<io::Error>,
}

impl IgnoreObservationError {
    pub fn new(
        path: impl Into<PathBuf>,
        operation: IgnoreObservationOperation,
        cause: io::Error,
    ) -> Self {
        if let Some(error) = cause
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<Self>())
        {
            return error.clone();
        }
        Self {
            path: path.into(),
            operation,
            cause: Arc::new(cause),
        }
    }
}
impl std::fmt::Display for IgnoreObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ignore {:?} observation for {}: {}",
            self.operation,
            self.path.display(),
            self.cause
        )
    }
}
impl std::error::Error for IgnoreObservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
impl From<IgnoreObservationError> for io::Error {
    fn from(error: IgnoreObservationError) -> Self {
        Self::new(error.cause.kind(), error)
    }
}

#[cfg(test)]
thread_local! {
 static IGNORE_FAILURE_LOGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
 static MATCHER_ACQUISITIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn capture_ignore_matcher(
    root: &Path,
    files: &BTreeSet<ProjectFile>,
) -> Result<Arc<BifrostIgnoreMatcher>, IgnoreObservationError> {
    BifrostIgnoreMatcher::build(root, files)
        .map(Arc::new)
        .map_err(|cause| {
            let error =
                IgnoreObservationError::new(root, IgnoreObservationOperation::Matcher, cause);
            eprintln!("workspace ignore observation incomplete: {error}");
            #[cfg(test)]
            IGNORE_FAILURE_LOGS.with(|count| count.set(count.get() + 1));
            error
        })
}

fn ignore_matcher_receipt(
    matcher: &Result<Arc<BifrostIgnoreMatcher>, IgnoreObservationError>,
    files: &BTreeSet<ProjectFile>,
) -> ProjectReadReceipt {
    match matcher {
        Ok(matcher) => matcher.receipt_for(files),
        Err(cause) => ProjectReadReceipt {
            incomplete: Some(cause.clone()),
            ..ProjectReadReceipt::default()
        },
    }
}

/// Decisions and selection captured together for a supplied listing.
#[derive(Debug)]
pub struct IgnoreObservation {
    pub ignored: Vec<bool>,
    pub selected: BTreeSet<ProjectFile>,
    pub rules_digest: [u8; 32],
}

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

    /// Whether `directory` (absolute) contributed an ignore file to these rules.
    fn has_rules_directory(&self, directory: &Path) -> bool {
        self.by_directory.contains_key(directory)
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

/// Immutable raw file bytes, content identity and origin from one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectFileSnapshot {
    bytes: Vec<u8>,
    oid: Oid,
    origin: ProjectSourceOrigin,
}

impl ProjectFileSnapshot {
    pub fn disk(bytes: Vec<u8>) -> Self {
        Self {
            oid: Oid::hash_object(ObjectType::Blob, &bytes).expect("hashing project file bytes"),
            bytes,
            origin: ProjectSourceOrigin::Disk,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn oid(&self) -> Oid {
        self.oid
    }
    pub const fn origin(&self) -> ProjectSourceOrigin {
        self.origin
    }

    pub fn decode(self) -> io::Result<ProjectSourceSnapshot> {
        Ok(ProjectSourceSnapshot {
            source: decode_source_bytes(self.bytes)?.into(),
            oid: self.oid,
            origin: self.origin,
        })
    }
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

#[derive(Debug, Clone)]
pub enum RetainedIgnoreObservation {
    Unavailable,
    NotListed,
    Ok,
    Failed(IgnoreObservationError),
}

pub trait Project: AsProject + Send + Sync {
    fn project_read_slot(&self) -> Option<&ProjectReadSlot> {
        None
    }
    fn install_read_recorder(&self, _capability: ReadCapability) -> bool {
        false
    }

    /// For callers that must refuse success when the current listing could not
    /// be certified. Reads retained state only; never refreshes or re-stats.
    fn retained_ignore_observation(&self) -> RetainedIgnoreObservation {
        RetainedIgnoreObservation::Unavailable
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

    /// Resolve a published module using the caller's existing store read.
    /// Implementations backed by the analyzer store must reuse this connection.
    fn selected_module_name_with_conn(
        &self,
        _conn: &rusqlite::Connection,
        file: &ProjectFile,
    ) -> io::Result<Option<String>> {
        self.selected_module_name(file)
    }

    /// Whether the selected generation lists a target root.
    fn selected_configuration_lists_path(&self, path: &Path) -> bool {
        self.root().join(path).is_file()
    }

    /// Immutable selected configuration storage charged by the naming owner.
    fn selected_configuration_retained_bytes(&self) -> usize {
        0
    }

    /// Exact bytes of a configuration input. A store-backed project answers
    /// from the configuration its generation selected (the build capture, then
    /// the published store) and never from the live filesystem. A project that
    /// is not store-backed has no generations, so its own files are the
    /// authority.
    fn selected_configuration_bytes(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match self.read_file_snapshot(&ProjectFile::new(self.root(), path)) {
            Ok(snapshot) => Ok(Some(snapshot.bytes().to_vec())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Read optional configuration using an existing store read. Store-backed
    /// projects select retained bytes through this connection, including absence.
    fn configuration_source_with_conn(
        &self,
        _conn: &rusqlite::Connection,
        relative_path: &Path,
    ) -> io::Result<Option<String>> {
        let Some(file) = self.file_by_rel_path(relative_path) else {
            return Ok(None);
        };
        self.read_source(&file).map(Some)
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
    /// Visible immediate file and directory entries from this project's authoritative view.
    /// Disk enumeration owners override this to avoid a workspace walk.
    fn directory_entries(&self, parent: &Path) -> io::Result<BTreeSet<ProjectFile>> {
        let mut entries = BTreeSet::new();
        for file in self.authoritative_files()? {
            let mut path = file.rel_path();
            while let Some(ancestor) = path.parent() {
                if ancestor == parent {
                    entries.insert(ProjectFile::new(self.root(), path));
                    break;
                }
                path = ancestor;
            }
        }
        Ok(entries)
    }

    /// Recheck membership against the current project view without using a
    /// cached or constructor-seeded listing.
    fn authoritative_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        self.all_files()
    }
    /// Share one immutable whole-workspace listing when the project owns a
    /// listing cache. The default preserves custom project implementations.
    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.all_files().map(Arc::new)
    }
    /// Read cached omissions without starting a workspace walk. None means
    /// completeness cannot be certified from this project on a point update.
    fn cached_omissions_if_available(&self) -> io::Result<Option<Arc<Vec<WorkspaceFileOmission>>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        Ok(None)
    }
    fn cached_listing_if_available(&self) -> io::Result<Option<SharedWorkspaceFileListing>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        Ok(None)
    }
    fn cached_analyzable_files_from(
        &self,
        _files: &BTreeSet<ProjectFile>,
        _language: Language,
    ) -> io::Result<Option<BTreeSet<ProjectFile>>> {
        let _project_read = listing_read(self);
        Ok(None)
    }
    fn all_files_with_omissions(&self) -> io::Result<SharedWorkspaceFileListing> {
        self.all_files_shared().map(|files| {
            (
                files,
                Arc::new(vec![WorkspaceFileOmission {
                    path: PathBuf::new(),
                    reason: WorkspaceFileOmissionReason::Unknown,
                }]),
            )
        })
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
    fn is_bifrostignored(&self, _rel_path: &Path) -> Result<bool, IgnoreObservationError> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        publish_ignore_rules(BifrostIgnoreMatcher::empty_rules_digest());
        Ok(false)
    }

    /// Observe custom selection and per-path overrides without assuming filesystem rules.
    fn ignore_observation_for_files(
        &self,
        files: &BTreeSet<ProjectFile>,
    ) -> Result<IgnoreObservation, IgnoreObservationError> {
        let ignored = files
            .iter()
            .map(|file| self.is_bifrostignored(file.rel_path()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut selected = BTreeSet::new();
        for language in Language::ANALYZABLE {
            selected.extend(
                self.analyzable_files_from(files, language)
                    .map_err(|cause| {
                        IgnoreObservationError::new(
                            self.root(),
                            IgnoreObservationOperation::Listing,
                            cause,
                        )
                    })?,
            );
        }
        let rules_digest = self.ignore_rules_digest().map_err(|cause| {
            IgnoreObservationError::new(self.root(), IgnoreObservationOperation::Matcher, cause)
        })?;
        Ok(IgnoreObservation {
            ignored,
            selected,
            rules_digest,
        })
    }

    /// Drop any cached whole-workspace file listing so the next `all_files`
    /// reflects the filesystem again. Observers of workspace change (the
    /// session file watcher, explicit refresh paths) call this; projects
    /// without a listing cache ignore it.
    fn invalidate_cached_file_listing(&self) {}

    /// Revision of the mutable project view, if its owner can certify one.
    fn view_stamp(&self) -> Option<ProjectViewStamp> {
        None
    }

    /// Whether the exact reported name exists, including omitted entries.
    fn has_exact_directory_entry(&self, file: &ProjectFile) -> io::Result<bool> {
        Ok(self
            .directory_entries(file.rel_path().parent().expect("file parent"))?
            .contains(file))
    }

    /// Patch an exact member already admitted by the directory view.
    fn update_cached_listing_for_resolved_path(&self, file: &ProjectFile) -> bool {
        self.update_cached_listing_for_path(file.rel_path())
    }

    /// Update a cached whole-workspace listing for one created, removed or
    /// renamed path without walking the workspace. Returns `false` when the
    /// project cannot decide that path alone, and the caller then invalidates
    /// the listing instead. Projects without a listing cache return `false`.
    fn update_cached_listing_for_path(&self, _rel_path: &Path) -> bool {
        false
    }

    /// Remove confirmed missing paths in one cached-listing update. Returns
    /// false when omissions or directory membership require a fresh listing.
    fn update_cached_listing_for_removed_paths(&self, _files: &[ProjectFile]) -> bool {
        false
    }

    /// Drop the cached listing when a cached symlink omission's reason or
    /// target no longer matches. A target can change with no event on the
    /// link, so this rechecks the links that `changed` can affect, and every
    /// link whose target lies outside the workspace or did not resolve.
    /// Projects without a listing cache do nothing.
    fn revalidate_symlink_omissions(&self, _changed: &BTreeSet<ProjectFile>) {}

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

    /// Capture raw bytes without source decoding. Custom text readers retain
    /// their supplied UTF-8 identity by default.
    fn read_file_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectFileSnapshot> {
        self.read_source(file)
            .map(|source| ProjectFileSnapshot::disk(source.into_bytes()))
    }

    /// Capture source text and its disk/overlay identity in one read.
    ///
    /// The default preserves custom `read_source` implementations and hashes
    /// their supplied UTF-8 text. Disk-backed projects override this to retain
    /// the raw byte identity before decoding. Overlay projects capture their
    /// text and opaque revision under the same read lock.
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.read_file_snapshot(file)?.decode()
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

    /// Pin, in one atomic step, every source overlay this project layers over
    /// its files. The view is immutable: later edits to the project never reach
    /// it, and it answers overlay content only, never disk or a delegate.
    ///
    /// A request calls this while it holds its own entry map, so an
    /// implementation must not publish to the project-read receipt or call back
    /// into a query. A project that advertises no overlay gets an empty view.
    /// One that advertises overlays and cannot pin them fails closed with
    /// `ErrorKind::Unsupported` rather than pin a partial set.
    ///
    /// The view is a captured request input. Its identity and content metadata
    /// name what the request will read; they are never a validation receipt,
    /// certificate or proof that anything was checked.
    fn capture_source_overlays(&self) -> io::Result<Arc<PinnedSourceOverlayView>> {
        // The probe runs in its own suppressed frame: a nested read depth keeps
        // every recorder callback from firing, and the caller's open project-read
        // receipt is saved and restored, so the probe's `publish_overlays` cannot
        // overwrite it.
        match super::project_reads::with_project_read_suppression(true, || self.overlay_content()) {
            Some(content) if !content.entries().is_empty() => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "project layers source overlays but cannot pin them as one immutable view",
            )),
            _ => Ok(PinnedSourceOverlayView::empty()),
        }
    }

    /// Monotonic process-local generation for source that can change behind
    /// an analyzer. Every analyzer memo relies on this invariant: content the
    /// analyzer can observe changes only with a new analyzer, a replaced memo
    /// bundle, or an advance of this generation. Immutable/disk projects use
    /// zero because analyzer updates already create a fresh cache owner.
    /// Neither zero nor nonzero is a test of a project's capabilities.
    fn analysis_generation(&self) -> u64 {
        0
    }
}

fn disk_has_exact_directory_entry(file: &ProjectFile) -> io::Result<bool> {
    for entry in std::fs::read_dir(file.abs_path().parent().expect("file parent"))? {
        if entry?.file_name() == file.rel_path().file_name().expect("file name") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn disk_directory_entries(
    project: &dyn Project,
    parent: &Path,
) -> io::Result<BTreeSet<ProjectFile>> {
    let root = project.root();
    let owned = AnalyzerOwnedPaths::new(root);
    let repo = crate::gitblob::discover(root);
    let membership = repo
        .as_ref()
        .map(crate::gitblob::WorkingTreeMembership::new)
        .transpose()
        .map_err(io::Error::other)?;
    let mut files = BTreeSet::new();
    for entry in WalkBuilder::new(root.join(parent))
        .max_depth(Some(1))
        .hidden(false)
        .ignore(false)
        .require_git(false)
        .git_ignore(repo.is_none())
        .git_global(repo.is_none())
        .git_exclude(repo.is_none())
        .build()
    {
        let entry = entry.map_err(io::Error::other)?;
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.path();
        if !entry
            .file_type()
            .is_some_and(|kind| kind.is_file() || kind.is_dir())
            || owned.contains(path)
        {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("directory entry belongs to project");
        if relative.to_str().is_none() {
            continue;
        }
        // Git point membership accepts files, not directory containers.
        // Keep containers traversable; the final file probe still enforces
        // ignored paths and nested-repository membership.
        if let Some(repo) = &repo
            && entry.file_type().is_some_and(|kind| kind.is_file())
        {
            let workdir = repo
                .workdir()
                .ok_or_else(|| io::Error::other("repository has no working directory"))?;
            let workdir_relative = path.strip_prefix(workdir).map_err(io::Error::other)?;
            if !membership
                .as_ref()
                .expect("repository membership")
                .contains(workdir_relative)
                .map_err(io::Error::other)?
            {
                continue;
            }
        }
        files.insert(ProjectFile::new(root, relative));
    }
    Ok(files)
}

/// Resolve reported updates, retrying against fresh membership when needed.
///
/// `explicitly_read` names analyzer-owned inputs that a reader opens by path
/// even when the project's ignore rules omit them from enumeration, such as a
/// build file a language captures as configuration. An omitted entry named by
/// `explicitly_read` is admitted under its exact spelling without refreshing
/// the listing: it is an input, not a workspace member.
pub fn resolve_update_paths_with_refresh(
    project: &dyn Project,
    changed: &BTreeSet<ProjectFile>,
    listing: &mut SharedWorkspaceFileListing,
    explicitly_read: &dyn Fn(&ProjectFile) -> bool,
) -> io::Result<BTreeSet<ProjectFile>> {
    let (resolved, mut refresh, explicit_inputs) =
        resolve_update_paths_with_explicit_inputs(project, changed, &listing.0, explicitly_read)?;
    // Patch watcher deletions before capture so removed configuration inputs
    // leave cached membership without walking the workspace again.
    let mut patched = false;
    let mut removed = Vec::new();
    for file in &resolved {
        if !listing.0.contains(file) || project.has_overlay(file) {
            continue;
        }
        // Inspect the entry itself, not its target. Only a regular file stays
        // listed; symlinks and every other non-regular entry need a walk.
        match file.abs_path().symlink_metadata() {
            Ok(metadata) if !metadata.file_type().is_file() => refresh = true,
            Ok(_) => {}
            // A former child of a directory that became a file is gone too.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                removed.push(file.clone())
            }
            Err(error) => return Err(error),
        }
    }
    if !removed.is_empty() {
        if project.update_cached_listing_for_removed_paths(&removed) {
            patched = true;
        } else {
            refresh = true;
        }
    }
    let removed_paths = removed
        .iter()
        .map(|file| file.rel_path())
        .collect::<BTreeSet<_>>();
    for file in resolved.iter().filter(|file| {
        !listing.0.contains(*file) && !explicit_inputs.contains(*file) && !project.has_overlay(file)
    }) {
        // A directory deletion or replacement may name only the directory.
        // Its former children are not in `resolved`, so re-list unless the
        // batch already accounts for every child. Omissions have no batch
        // removal and always need enumeration.
        if listing.0.iter().any(|listed| {
            listed.rel_path().starts_with(file.rel_path())
                && !removed_paths.contains(listed.rel_path())
        }) || listing
            .1
            .iter()
            .any(|omission| omission.path.starts_with(file.rel_path()))
        {
            refresh = true;
        }
    }
    for file in resolved.iter().filter(|file| {
        !listing.0.contains(*file) && file.exists() && !explicit_inputs.contains(*file)
    }) {
        // The directory view established the exact spelling. The project point
        // update reuses that admission and applies the cache's omission checks.
        if project.update_cached_listing_for_resolved_path(file) {
            patched = true;
        } else {
            // No cache, or membership/omission status cannot be certified alone.
            refresh = true;
        }
    }
    if !refresh {
        if patched {
            *listing = project.all_files_with_omissions()?;
        }
        return Ok(resolved);
    }
    project.invalidate_cached_file_listing();
    *listing = project.all_files_with_omissions()?;
    Ok(resolve_update_paths_with_explicit_inputs(project, changed, &listing.0, explicitly_read)?.0)
}

/// Resolve watcher spellings before any update consumer publishes paths.
/// An unresolved existing name invalidates membership evidence; it is never admitted.
pub fn resolve_update_paths(
    project: &dyn Project,
    changed: &BTreeSet<ProjectFile>,
    listed: &BTreeSet<ProjectFile>,
) -> io::Result<(BTreeSet<ProjectFile>, bool)> {
    let (resolved, refresh, _) =
        resolve_update_paths_with_explicit_inputs(project, changed, listed, &|_| false)?;
    Ok((resolved, refresh))
}

/// Resolve update paths and report the inputs admitted despite enumeration
/// omitting them. The third set holds those paths so a caller can keep them
/// out of any listing patch.
fn resolve_update_paths_with_explicit_inputs(
    project: &dyn Project,
    changed: &BTreeSet<ProjectFile>,
    listed: &BTreeSet<ProjectFile>,
    explicitly_read: &dyn Fn(&ProjectFile) -> bool,
) -> io::Result<(BTreeSet<ProjectFile>, bool, BTreeSet<ProjectFile>)> {
    let mut resolved = BTreeSet::new();
    let mut refresh_listing = false;
    let mut explicit_inputs = BTreeSet::new();
    let mut directories = HashMap::new();
    for file in changed {
        if listed.contains(file) || project.has_overlay(file) || !file.exists() {
            resolved.insert(file.clone());
            continue;
        }
        let result = (|| -> io::Result<_> {
            let mut path_resolved = BTreeSet::new();
            let mut canonical_parent = PathBuf::new();
            let mut missing_parent = false;
            for component in file
                .rel_path()
                .parent()
                .expect("project file has a parent")
                .components()
            {
                let candidate = ProjectFile::new(project.root(), canonical_parent.join(component));
                let entries = match directories.entry(canonical_parent.clone()) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(project.directory_entries(&canonical_parent)?)
                    }
                };
                if entries.contains(&candidate) {
                    canonical_parent.push(component);
                    continue;
                }
                let mut matching = None;
                for entry in entries.iter() {
                    if same_file::is_same_file(candidate.abs_path(), entry.abs_path())? {
                        matching = Some(entry.rel_path().to_path_buf());
                        break;
                    }
                }
                match matching {
                    Some(parent) => canonical_parent = parent,
                    None => {
                        // Enumeration can omit an ignored directory and
                        // everything under it. An input the analyzer reads by
                        // path still reaches its exact spelling; it is not
                        // admitted as a listing member.
                        let reported =
                            ProjectFile::new(project.root(), file.rel_path().to_path_buf());
                        if explicitly_read(&reported)
                            && project.has_exact_directory_entry(&reported)?
                        {
                            explicit_inputs.insert(reported.clone());
                            path_resolved.insert(reported);
                            return Ok((path_resolved, false));
                        }
                        missing_parent = true;
                        break;
                    }
                }
            }
            if missing_parent {
                return Ok((path_resolved, true));
            }
            let canonical_file = ProjectFile::new(
                project.root(),
                canonical_parent.join(
                    file.rel_path()
                        .file_name()
                        .expect("project file has a name"),
                ),
            );
            let parent = canonical_parent.as_path();
            let entries = match directories.entry(parent.to_path_buf()) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(project.directory_entries(parent)?)
                }
            };
            if entries.contains(&canonical_file) {
                path_resolved.insert(canonical_file);
                return Ok((path_resolved, false));
            }
            // An omitted real entry is membership evidence, never a spelling
            // alias. Enumeration must retain its omission evidence. An input
            // the analyzer reads by path is the exception: ignore rules are
            // what hide it from enumeration, and its edit must still reach the
            // reader. It stays out of the listing.
            if project.has_exact_directory_entry(&canonical_file)? {
                if explicitly_read(&canonical_file) {
                    explicit_inputs.insert(canonical_file.clone());
                    path_resolved.insert(canonical_file);
                    return Ok((path_resolved, false));
                }
                return Ok((path_resolved, true));
            }
            let mut matched = false;
            for entry in entries.iter() {
                if listed.contains(entry)
                    && same_file::is_same_file(file.abs_path(), entry.abs_path())?
                {
                    path_resolved.insert(entry.clone());
                    matched = true;
                }
            }
            Ok((path_resolved, !matched))
        })();
        let (paths, refresh) = result?;
        resolved.extend(paths);
        refresh_listing |= refresh;
    }
    Ok((resolved, refresh_listing, explicit_inputs))
}

fn read_disk_file_snapshot(file: &ProjectFile) -> io::Result<ProjectFileSnapshot> {
    #[cfg(any(test, feature = "test-support"))]
    super::project_reads::count_project_io(super::project_reads::ProjectIo::Source);
    std::fs::read(file.abs_path()).map(ProjectFileSnapshot::disk)
}

fn read_disk_source_snapshot(file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
    read_disk_file_snapshot(file)?.decode()
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
    fn has_exact_directory_entry(&self, file: &ProjectFile) -> io::Result<bool> {
        disk_has_exact_directory_entry(file)
    }

    fn directory_entries(&self, parent: &Path) -> io::Result<BTreeSet<ProjectFile>> {
        disk_directory_entries(self, parent)
    }

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
    fn read_file_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectFileSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_file_snapshot(file),
            |snapshot| Some(snapshot.oid()),
        )
    }

    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.read_file_snapshot(file)?.decode()
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
        self.all_files_with_omissions()
            .map(|(files, _)| (*files).clone())
    }

    fn all_files_with_omissions(&self) -> io::Result<SharedWorkspaceFileListing> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.listing_count.fetch_add(1, Ordering::Relaxed);
        let listing = collect_workspace_files_with_omissions(&self.root)?;
        publish_file_set(self, &listing.files)?;
        Ok((Arc::new(listing.files), Arc::new(listing.omissions)))
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
            .filter(|file| file.language() == language)
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
/// build. `invalidate` serializes with refills and path updates. Refills go
/// through [`collect_workspace_files`], so the git-index union is recomputed
/// together with the ignore-aware walk: tracked files shadowed by broad ignore
/// patterns stay listed after invalidation.
#[derive(Debug)]
pub struct WorkspaceFileListingCache {
    project_reads: ProjectReadSlot,
    root: PathBuf,
    view_id: u64,
    generation: AtomicU64,
    walks: AtomicUsize,
    cached: Mutex<Option<CachedFileListing>>,
    failed_listing: Mutex<Option<(u64, IgnoreObservationError)>>,
}

#[derive(Debug, Clone)]
struct CachedFileListing {
    generation: u64,
    files: Arc<BTreeSet<ProjectFile>>,
    omissions: Arc<Vec<WorkspaceFileOmission>>,
    /// The resolved target of each symlink in `omissions`, for
    /// [`WorkspaceFileListingCache::revalidate_symlink_omissions`].
    symlinks: Arc<SymlinkTargets>,
    matcher: Result<Arc<BifrostIgnoreMatcher>, IgnoreObservationError>,
    receipt: ProjectReadReceipt,
    ignore_inputs: ignore_inputs::InputReceipt,
}

impl WorkspaceFileListingCache {
    /// Observe only retained listing storage. A cold cache stays cold.
    #[cfg(feature = "test-support")]
    pub fn retention_census_for_test(
        self: &Arc<Self>,
        census: &mut crate::retention_census::RetentionCensus,
    ) {
        use crate::retention_census::{
            AllocationAccounting, FamilyLifetime, ResidentWeightUnit, UnknownKind,
        };
        let family = "cached_workspace_file_listing";
        let lifetime = FamilyLifetime::Persistent;
        let accounting = AllocationAccounting::OutsideBudget;
        let cached = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned")
            .clone();
        census.record_arc_allocation(
            Arc::clone(self),
            family,
            lifetime,
            "workspace_file_listing_cache_container",
            (std::mem::size_of::<Self>()
                + self.root.capacity()
                + cached
                    .as_ref()
                    .and_then(|cached| cached.ignore_inputs.as_ref().err())
                    .map_or(0, |error| error.path.capacity())) as u64,
            accounting,
        );
        census.record_resident_reading(
            family,
            lifetime,
            cached.as_ref().map_or(0, |cached| cached.files.len()) as u64,
            cached.as_ref().map_or(0, |cached| cached.files.len()) as u64,
            ResidentWeightUnit::Entries,
        );
        census.record_unknown(
            family,
            lifetime,
            UnknownKind::Coverage,
            "allocator_and_arc_control_bytes_not_estimated",
        );
        let Some(cached) = cached else {
            return;
        };
        // Every captured payload is immutable; the mutable cache lock is gone.
        // BTreeSet exposes its entry count, not allocated node capacities.
        census.record_arc_allocation(
            Arc::clone(&cached.files),
            family,
            lifetime,
            "workspace_listing_file_set_header",
            std::mem::size_of_val(cached.files.as_ref()) as u64,
            accounting,
        );
        census.record_unknown(
            family,
            lifetime,
            UnknownKind::Coverage,
            "btree_node_capacity_and_shared_project_file_backing_unavailable",
        );
        let omissions = std::mem::size_of_val(cached.omissions.as_ref())
            + cached.omissions.capacity() * std::mem::size_of::<WorkspaceFileOmission>()
            + cached
                .omissions
                .iter()
                .map(|omission| omission.path.capacity())
                .sum::<usize>();
        census.record_arc_allocation(
            Arc::clone(&cached.omissions),
            family,
            lifetime,
            "workspace_listing_omissions",
            omissions as u64,
            accounting,
        );
        if let Ok(inputs) = &cached.ignore_inputs {
            census.record_arc_allocation(
                Arc::clone(inputs),
                family,
                lifetime,
                "workspace_listing_ignore_inputs",
                inputs.bytes() as u64,
                accounting,
            );
        }
        if let Err(error) = &cached.ignore_inputs {
            census.record_arc_allocation(
                Arc::clone(&error.cause),
                family,
                lifetime,
                "workspace_listing_ignore_input_failure",
                std::mem::size_of::<io::Error>() as u64,
                accounting,
            );
            census.record_unknown(
                family,
                lifetime,
                UnknownKind::Coverage,
                "ignore_input_failure_io_error_payload_capacity_unavailable",
            );
        }
        let symlinks = cached.symlinks.as_ref();
        let bytes = std::mem::size_of_val(symlinks)
            + symlinks.canonical_root.capacity()
            + symlinks.links.capacity() * std::mem::size_of::<SymlinkRecord>()
            + symlinks
                .links
                .iter()
                .map(|link| {
                    link.path.capacity()
                        + match &link.target {
                            SymlinkTarget::Inside(path) => path.capacity(),
                            _ => 0,
                        }
                })
                .sum::<usize>()
            + symlinks.by_path.capacity() * std::mem::size_of::<(PathBuf, Vec<usize>)>()
            + symlinks
                .by_path
                .iter()
                .map(|(path, indices)| {
                    path.capacity() + indices.capacity() * std::mem::size_of::<usize>()
                })
                .sum::<usize>()
            + symlinks.always.capacity() * std::mem::size_of::<usize>();
        census.record_arc_allocation(
            Arc::clone(&cached.symlinks),
            family,
            lifetime,
            "workspace_listing_symlink_targets",
            bytes as u64,
            accounting,
        );
        if let Ok(matcher_arc) = &cached.matcher {
            let matcher = matcher_arc.as_ref();
            let bytes = std::mem::size_of_val(matcher)
                + matcher.root.capacity()
                + matcher.by_directory.capacity() * std::mem::size_of::<(PathBuf, Gitignore)>()
                + matcher
                    .by_directory
                    .keys()
                    .map(PathBuf::capacity)
                    .sum::<usize>();
            census.record_arc_allocation(
                Arc::clone(matcher_arc),
                family,
                lifetime,
                "workspace_listing_ignore_matcher_partial_capacity",
                bytes as u64,
                accounting,
            );
            census.record_unknown(
                family,
                lifetime,
                UnknownKind::Coverage,
                "compiled_ignore_rules_receipts_and_hash_control_storage_not_walked",
            );
        }
        census.record_unknown(
            family,
            lifetime,
            UnknownKind::ActivePins,
            "external_listing_bundle_leases_are_not_enumerable",
        );
    }

    pub fn new(root: PathBuf) -> Self {
        assert!(
            root.is_absolute(),
            "workspace file listing cache root must be absolute: {}",
            root.display()
        );
        Self {
            project_reads: ProjectReadSlot::default(),
            // `FilesystemProject::with_cached_listing` normalizes its root, so
            // the cache stores the same spelling: on Windows a canonicalized
            // root is verbatim (`\\?\C:\...`) until `normalize` collapses it.
            root: root.normalize(),
            view_id: next_project_view_id(),
            generation: AtomicU64::new(0),
            walks: AtomicUsize::new(0),
            cached: Mutex::new(None),
            failed_listing: Mutex::new(None),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Drop the cached listing. The next `files` call re-walks the root and
    /// re-unions the git index. Serialization with fills and path updates
    /// ensures the listing epoch advances with the mutation.
    pub fn invalidate(&self) {
        let mut slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        *slot = None;
        *self
            .failed_listing
            .lock()
            .expect("listing failure lock poisoned") = None;
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn view_stamp(&self) -> ProjectViewStamp {
        let _slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        ProjectViewStamp::own(self.view_id, self.generation.load(Ordering::Acquire))
    }

    /// The current listing, walking the root only when no fresh listing is
    /// cached. Concurrent callers serialize on the internal mutex, so a cold
    /// cache is filled by exactly one walk. Invalidation serializes with that
    /// fill and clears it if the invalidation follows the walk.
    pub fn files(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        self.listing().map(|(files, _)| files)
    }

    fn cached_analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> Option<BTreeSet<ProjectFile>> {
        let slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        let cached = slot.as_ref()?;
        if cached.generation != self.generation.load(Ordering::Acquire) {
            return None;
        }
        let matcher = cached.matcher.as_ref().ok()?;
        Some(
            files_for_language(files, language, ProjectFile::language)
                .into_iter()
                .filter(|file| !matcher.is_ignored(file))
                .collect(),
        )
    }
    pub fn cached_listing(&self) -> Option<SharedWorkspaceFileListing> {
        let slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        let cached = slot.as_ref()?;
        (cached.generation == self.generation.load(Ordering::Acquire))
            .then(|| (Arc::clone(&cached.files), Arc::clone(&cached.omissions)))
    }

    pub fn listing(&self) -> io::Result<SharedWorkspaceFileListing> {
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
                return Ok((Arc::clone(&cached.files), Arc::clone(&cached.omissions)));
            }
            let mut failure = self
                .failed_listing
                .lock()
                .expect("listing failure lock poisoned");
            if let Some((failed_generation, error)) = &*failure
                && *failed_generation == generation
            {
                return Err(io::Error::from(error.clone()));
            }
            self.walks.fetch_add(1, Ordering::Relaxed);
            let listing = match collect_workspace_files_with_omissions(&self.root) {
                Ok(listing) => {
                    *failure = None;
                    listing
                }
                Err(cause) => {
                    let error = IgnoreObservationError::new(
                        &self.root,
                        IgnoreObservationOperation::Listing,
                        cause,
                    );
                    eprintln!("workspace ignore observation incomplete: {error}");
                    *failure = Some((generation, error.clone()));
                    return Err(error.into());
                }
            };
            let files = Arc::new(listing.files);
            let omissions = Arc::new(listing.omissions);
            let symlinks = Arc::new(listing.symlinks);
            let matcher = listing.matcher.expect("listing captured its matcher");
            let receipt = ignore_matcher_receipt(&matcher, &files);
            let generation = self.generation.fetch_add(1, Ordering::Release) + 1;
            *slot = Some(CachedFileListing {
                generation,
                files: Arc::clone(&files),
                omissions: Arc::clone(&omissions),
                symlinks,
                matcher,
                receipt: receipt.clone(),
                ignore_inputs: listing.ignore_inputs,
            });
            publish_receipt(receipt);
            Ok((files, omissions))
        })
    }

    fn matcher(&self) -> io::Result<Arc<BifrostIgnoreMatcher>> {
        #[cfg(test)]
        MATCHER_ACQUISITIONS.with(|count| count.set(count.get() + 1));
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
                return cached.matcher.clone().map_err(io::Error::from);
            }
        }
    }

    /// Validate the listing's stat-only ignore inputs, then recheck symlink omissions.
    ///
    /// A target can change with no event on the link, so a link is rechecked
    /// when a path in `changed` equals its target or one of the ancestors of
    /// its target or of itself; an index built with the listing finds those
    /// links from the changed paths. A link whose target lies outside the
    /// workspace, or did not resolve, has no workspace event to wait for and is
    /// rechecked on every update (two `stat` calls and a `canonicalize`). Every
    /// other link costs nothing. A link that is itself a changed
    /// path invalidates through [`Self::update_path`]. The symlink check holds
    /// no cache lock. A target outside the workspace that changes with no update at all
    /// is seen at the next update, like any other unwatched input.
    pub fn revalidate_symlink_omissions(&self, changed: &BTreeSet<ProjectFile>) {
        if self
            .failed_listing
            .lock()
            .expect("listing failure lock poisoned")
            .take()
            .is_some()
        {
            self.generation.fetch_add(1, Ordering::Release);
        }
        // One outer update owns validation. Nested consumers receive its listing.
        let mut slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        let stale = slot
            .as_ref()
            .is_some_and(|cached| match &cached.ignore_inputs {
                Ok(inputs) => match inputs.valid() {
                    Ok(valid) => !valid,
                    Err(cause) => {
                        eprintln!("workspace ignore input validation incomplete: {cause}");
                        true
                    }
                },
                Err(_) => true,
            });
        if stale {
            *slot = None;
            self.generation.fetch_add(1, Ordering::Release);
        }
        drop(slot);
        let (omissions, symlinks) = {
            let slot = self
                .cached
                .lock()
                .expect("workspace file listing cache poisoned");
            let Some(cached) = slot.as_ref() else {
                return;
            };
            (Arc::clone(&cached.omissions), Arc::clone(&cached.symlinks))
        };
        let changed = symlinks.affected_by(changed).any(|link| {
            #[cfg(any(test, feature = "test-support"))]
            super::project_reads::count_project_io(super::project_reads::ProjectIo::SymlinkRecheck);
            let absolute = self.root.join(&link.path);
            !absolute
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.is_symlink())
                || {
                    let now =
                        classify_symlink(&symlinks.canonical_root, &absolute, link.path.clone());
                    now.reason != link.reason || now.target != link.target
                }
        });
        if !changed {
            return;
        }
        let mut slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        // A walk meanwhile gives fresh omissions; a point patch keeps the
        // checked ones, which are stale.
        if slot
            .as_ref()
            .is_some_and(|cached| Arc::ptr_eq(&cached.omissions, &omissions))
        {
            *slot = None;
            self.generation.fetch_add(1, Ordering::Release);
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
        self.update_path_in(&TestProject::new(file.root(), Language::None), file, listed)
    }

    /// Patch membership using the owning project's visible directory view.
    pub fn update_path_in(&self, project: &dyn Project, file: &ProjectFile, listed: bool) -> bool {
        if listed {
            let files = {
                let slot = self
                    .cached
                    .lock()
                    .expect("workspace file listing cache poisoned");
                slot.as_ref().map(|cached| Arc::clone(&cached.files))
            };
            if let Some(files) = files {
                let Ok((paths, refresh)) =
                    resolve_update_paths(project, &BTreeSet::from([file.clone()]), &files)
                else {
                    return false;
                };
                if refresh {
                    return false;
                }
                if !paths.contains(file) {
                    return true;
                }
            }
        }
        self.update_resolved_path(file, listed)
    }

    fn removal_empties_rule_directory(
        matcher: &BifrostIgnoreMatcher,
        files: &BTreeSet<ProjectFile>,
        removed: &[ProjectFile],
    ) -> bool {
        removed.iter().any(|file| {
            let mut directory = file.rel_path().parent();
            while let Some(dir) = directory.filter(|dir| !dir.as_os_str().is_empty()) {
                if matcher.has_rules_directory(&file.root().join(dir))
                    && !files
                        .range(file.with_rel_path(dir)..)
                        .next()
                        .is_some_and(|next| next.rel_path().starts_with(dir))
                {
                    return true;
                }
                directory = dir.parent();
            }
            false
        })
    }

    /// Remove confirmed missing files with one set copy and one receipt rebuild.
    fn remove_paths(&self, removed: &[ProjectFile]) -> bool {
        // Removing an ignore file can admit paths it used to exclude, which a
        // removal cannot add, so the caller re-lists instead.
        if removed.iter().any(|file| {
            file.rel_path().to_str().is_none()
                || file
                    .rel_path()
                    .file_name()
                    .is_some_and(|name| name == BIFROST_IGNORE_FILE_NAME || name == ".gitignore")
        }) {
            return false;
        }
        let mut slot = self
            .cached
            .lock()
            .expect("workspace file listing cache poisoned");
        let generation = self.generation.load(Ordering::Acquire);
        let Some(cached) = slot
            .as_mut()
            .filter(|cached| cached.generation == generation)
        else {
            return true;
        };
        for file in removed {
            // A listed file cannot also be a directory. Only unlisted paths
            // need the prefix check that refuses directory removals.
            if !cached.files.contains(file)
                && cached
                    .files
                    .iter()
                    .any(|listed| listed.rel_path().starts_with(file.rel_path()))
            {
                return false;
            }
        }
        let mut files = (*cached.files).clone();
        for file in removed {
            files.remove(file);
        }
        // A directory's ignore rules are compiled only while a listed file lies
        // under it. Emptying a rule-bearing directory changes the rules a fresh
        // listing builds, so re-list.
        let Ok(matcher) = &cached.matcher else {
            return false;
        };
        if Self::removal_empties_rule_directory(matcher, &files, removed) {
            return false;
        }
        let files = Arc::new(files);
        cached.receipt = matcher.receipt_for(&files);
        cached.files = files;
        cached.generation = self.generation.fetch_add(1, Ordering::Release) + 1;
        true
    }

    fn update_resolved_path(&self, file: &ProjectFile, listed: bool) -> bool {
        // A point update cannot certify an omission's cause. Re-list when a
        // watcher sees a path whose metadata may be skipped by enumeration.
        if file.rel_path().to_str().is_none()
            || file
                .abs_path()
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.is_symlink())
            || listed
                && !file
                    .abs_path()
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            return false;
        }
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
        let Ok(matcher) = &cached.matcher else {
            return false;
        };
        if !listed
            && Self::removal_empties_rule_directory(matcher, &files, std::slice::from_ref(file))
        {
            return false;
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
        let receipt = matcher.receipt_for(&files);
        cached.files = files;
        cached.receipt = receipt;
        let next = self.generation.fetch_add(1, Ordering::Release) + 1;
        cached.generation = next;
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
    matcher: Result<Arc<BifrostIgnoreMatcher>, IgnoreObservationError>,
    receipt: ProjectReadReceipt,
}

#[derive(Debug, Clone)]
pub struct FilesystemProject {
    project_reads: ProjectReadSlot,
    view_id: u64,
    root: PathBuf,
    languages: BTreeSet<Language>,
    listing_count: Arc<AtomicUsize>,
    cached_listing: Option<Arc<WorkspaceFileListingCache>>,
    /// The constructor's discovery walk is a useful build seed, but only for
    /// the first consumer. Manual sessions deliberately return to fresh walks
    /// after that one use rather than retaining a stale cache.
    initial_listing: Arc<Mutex<InitialListing>>,
    bifrost_ignore: Arc<Mutex<Option<IgnoreRulesSnapshot>>>,
}

#[derive(Debug)]
struct InitialListing {
    files: Option<Arc<BTreeSet<ProjectFile>>>,
    omissions: Arc<Vec<WorkspaceFileOmission>>,
    epoch: u64,
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
            view_id: next_project_view_id(),
            root: root.to_path_buf(),
            languages: detect_languages_in_files(&files),
            listing_count: Arc::new(AtomicUsize::new(0)),
            cached_listing: None,
            initial_listing: Arc::new(Mutex::new(InitialListing {
                files: Some(files),
                omissions: Arc::new(Vec::new()),
                epoch: 0,
            })),
            bifrost_ignore: Arc::new(Mutex::new(Some(IgnoreRulesSnapshot {
                matcher: Ok(matcher),
                receipt,
            }))),
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

        let listing = collect_workspace_files_with_omissions(&root)?;
        let files = Arc::new(listing.files);
        let matcher = Arc::new(BifrostIgnoreMatcher::build(&root, &files)?);
        let project = Self::from_listing_and_matcher(&root, Arc::clone(&files), matcher);
        project
            .initial_listing
            .lock()
            .expect("initial listing lock")
            .omissions = Arc::new(listing.omissions);
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
        let (files, omissions) = listing.listing()?;
        let matcher = listing.matcher()?;
        let mut project = Self::from_listing_and_matcher(&root, files, matcher);
        project
            .initial_listing
            .lock()
            .expect("initial listing lock")
            .omissions = omissions;
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
            let matcher = capture_ignore_matcher(&self.root, files);
            let receipt = ignore_matcher_receipt(&matcher, files);
            *slot = Some(IgnoreRulesSnapshot { matcher, receipt });
        }
        let matcher = slot
            .as_ref()
            .expect("built matcher")
            .matcher
            .clone()
            .map_err(io::Error::from)?;
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
        let matcher = snapshot.matcher.clone().map_err(io::Error::from)?;
        publish_ignore_rules(matcher.rules_digest());
        Ok(Some(matcher))
    }

    fn take_initial_listing(&self) -> Option<SharedWorkspaceFileListing> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let mut initial = self
            .initial_listing
            .lock()
            .expect("initial workspace listing mutex poisoned");
        let files = initial
            .files
            .take()
            .map(|files| (files, Arc::clone(&initial.omissions)));
        if files.is_some() {
            initial.epoch = initial
                .epoch
                .checked_add(1)
                .expect("listing epoch exhausted");
        }
        files
    }
}

impl Project for FilesystemProject {
    fn retained_ignore_observation(&self) -> RetainedIgnoreObservation {
        let Some(cache) = &self.cached_listing else {
            return RetainedIgnoreObservation::Unavailable;
        };
        let retained = cache
            .cached
            .lock()
            .expect("workspace listing mutex poisoned");
        let Some(listing) = retained
            .as_ref()
            .filter(|listing| listing.generation == cache.generation.load(Ordering::Acquire))
        else {
            return RetainedIgnoreObservation::NotListed;
        };
        match listing
            .matcher
            .as_ref()
            .map(|_| ())
            .and_then(|()| listing.ignore_inputs.as_ref().map(|_| ()))
        {
            Ok(()) => RetainedIgnoreObservation::Ok,
            Err(cause) => RetainedIgnoreObservation::Failed(cause.clone()),
        }
    }
    fn has_exact_directory_entry(&self, file: &ProjectFile) -> io::Result<bool> {
        disk_has_exact_directory_entry(file)
    }

    fn directory_entries(&self, parent: &Path) -> io::Result<BTreeSet<ProjectFile>> {
        disk_directory_entries(self, parent)
    }

    fn view_stamp(&self) -> Option<ProjectViewStamp> {
        let initial = self
            .initial_listing
            .lock()
            .expect("initial workspace listing mutex poisoned");
        let own = ProjectViewStamp::own(self.view_id, initial.epoch);
        Some(match &self.cached_listing {
            Some(cache) => own.over(cache.view_stamp()),
            None => own,
        })
    }
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
    fn read_file_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectFileSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_file_snapshot(file),
            |snapshot| Some(snapshot.oid()),
        )
    }

    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.read_file_snapshot(file)?.decode()
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

    fn authoritative_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        collect_workspace_files(&self.root)
    }

    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        self.all_files_with_omissions().map(|(files, _)| files)
    }

    fn cached_omissions_if_available(&self) -> io::Result<Option<Arc<Vec<WorkspaceFileOmission>>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        Ok(self
            .cached_listing
            .as_ref()
            .and_then(|cache| cache.cached_listing().map(|(_, omissions)| omissions)))
    }
    fn cached_listing_if_available(&self) -> io::Result<Option<SharedWorkspaceFileListing>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        Ok(self
            .cached_listing
            .as_ref()
            .and_then(|cache| cache.cached_listing()))
    }
    fn cached_analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<Option<BTreeSet<ProjectFile>>> {
        let _project_read = listing_read(self);
        Ok(self
            .cached_listing
            .as_ref()
            .and_then(|cache| cache.cached_analyzable_files_from(files, language)))
    }
    fn all_files_with_omissions(&self) -> io::Result<SharedWorkspaceFileListing> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.listing_count.fetch_add(1, Ordering::Relaxed);
        if let Some(cache) = &self.cached_listing {
            return cache.listing();
        }
        let (files, omissions, walked) = match self.take_initial_listing() {
            Some((files, omissions)) => (files, omissions, false),
            None => {
                let listing = collect_workspace_files_with_omissions(&self.root)?;
                let matcher = listing.matcher.expect("listing matcher captured");
                let receipt = ignore_matcher_receipt(&matcher, &listing.files);
                *self
                    .bifrost_ignore
                    .lock()
                    .expect("Bifrost ignore matcher lock poisoned") =
                    Some(IgnoreRulesSnapshot { matcher, receipt });
                (Arc::new(listing.files), Arc::new(listing.omissions), true)
            }
        };
        // Read the receipt under the same lock that fills the matcher. The
        // watcher's `invalidate_cached_file_listing` clears the matcher on its
        // own lock, so a second lock acquisition here could find it gone and
        // had to panic. A matcher cleared after the seed was taken is rebuilt
        // over that seed, exactly as a walk rebuilds one over its own files.
        let mut slot = self
            .bifrost_ignore
            .lock()
            .expect("Bifrost ignore matcher lock poisoned");
        let receipt = match slot.as_mut() {
            Some(snapshot) => {
                if walked {
                    // Fresh file discovery does not invalidate ignore rules.
                    // Keep the matcher until explicit invalidation, but
                    // certify this walk's files using the rules that will
                    // filter them.
                    snapshot.receipt = ignore_matcher_receipt(&snapshot.matcher, &files);
                }
                snapshot.receipt.clone()
            }
            None => {
                let matcher = capture_ignore_matcher(&self.root, &files);
                let receipt = ignore_matcher_receipt(&matcher, &files);
                *slot = Some(IgnoreRulesSnapshot {
                    matcher,
                    receipt: receipt.clone(),
                });
                receipt
            }
        };
        drop(slot);
        publish_receipt(receipt);
        Ok((files, omissions))
    }

    fn revalidate_symlink_omissions(&self, changed: &BTreeSet<ProjectFile>) {
        if let Some(cache) = &self.cached_listing {
            cache.revalidate_symlink_omissions(changed);
        }
    }

    fn update_cached_listing_for_resolved_path(&self, file: &ProjectFile) -> bool {
        self.cached_listing
            .as_ref()
            .is_some_and(|cache| cache.update_resolved_path(file, true))
    }

    fn update_cached_listing_for_removed_paths(&self, files: &[ProjectFile]) -> bool {
        self.cached_listing
            .as_ref()
            .is_some_and(|cache| cache.remove_paths(files))
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
        cache.update_path_in(
            self,
            &ProjectFile::new(self.root.clone(), rel_path.to_path_buf()),
            listed,
        )
    }

    fn invalidate_cached_file_listing(&self) {
        let mut initial = self
            .initial_listing
            .lock()
            .expect("initial workspace listing mutex poisoned");
        initial.files = None;
        initial.epoch = initial
            .epoch
            .checked_add(1)
            .expect("listing epoch exhausted");
        if let Some(cache) = &self.cached_listing {
            cache.invalidate();
        }
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

    fn ignore_observation_for_files(
        &self,
        files: &BTreeSet<ProjectFile>,
    ) -> Result<IgnoreObservation, IgnoreObservationError> {
        let matcher = self.bifrost_ignore_matcher(files).map_err(|cause| {
            IgnoreObservationError::new(&self.root, IgnoreObservationOperation::Matcher, cause)
        })?;
        Ok(IgnoreObservation {
            ignored: files.iter().map(|file| matcher.is_ignored(file)).collect(),
            selected: files
                .iter()
                .filter(|file| file.language() != Language::None && !matcher.is_ignored(file))
                .cloned()
                .collect(),
            rules_digest: matcher.rules_digest(),
        })
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

    fn is_bifrostignored(&self, rel_path: &Path) -> Result<bool, IgnoreObservationError> {
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
            .map_err(|cause| {
                IgnoreObservationError::new(
                    self.root.join(rel_path),
                    IgnoreObservationOperation::Matcher,
                    cause,
                )
            })
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
    omissions: Arc<Vec<WorkspaceFileOmission>>,
    receipt: ProjectReadReceipt,
    languages: BTreeSet<Language>,
}

impl FileSetProject {
    /// Build a project rooted at `root` containing exactly the files at the
    /// given project-relative paths. Analyzer languages are inferred from the
    /// file extensions; files of unsupported types stay listed but contribute
    /// no language (and so are never parsed).
    ///
    /// The files are a subset of a workspace whose remainder is unknown, so the
    /// listing carries the fail-closed `Unknown` omission and a consumer cannot
    /// prove an absence from it. [`Self::from_listing`] states a complete
    /// listing instead.
    pub fn new(root: impl Into<PathBuf>, rel_paths: impl IntoIterator<Item = PathBuf>) -> Self {
        Self::from_listing(
            root,
            rel_paths,
            vec![WorkspaceFileOmission {
                path: PathBuf::new(),
                reason: WorkspaceFileOmissionReason::Unknown,
            }],
        )
    }

    /// Build a project over an authoritative listing: `rel_paths` are every file
    /// of the workspace and `omissions` are the only entries it left out.
    pub fn from_listing(
        root: impl Into<PathBuf>,
        rel_paths: impl IntoIterator<Item = PathBuf>,
        omissions: Vec<WorkspaceFileOmission>,
    ) -> Self {
        Self::build(root, rel_paths, omissions)
    }

    fn build(
        root: impl Into<PathBuf>,
        rel_paths: impl IntoIterator<Item = PathBuf>,
        omissions: Vec<WorkspaceFileOmission>,
    ) -> Self {
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
            omissions: Arc::new(omissions),
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
    fn read_file_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectFileSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_file_snapshot(file),
            |snapshot| Some(snapshot.oid()),
        )
    }

    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.read_file_snapshot(file)?.decode()
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

    fn all_files_with_omissions(&self) -> io::Result<SharedWorkspaceFileListing> {
        self.all_files_shared()
            .map(|files| (files, Arc::clone(&self.omissions)))
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
    fn retained_ignore_observation(&self) -> RetainedIgnoreObservation {
        let mut result = RetainedIgnoreObservation::Ok;
        for root in &self.roots {
            match root.retained_ignore_observation() {
                failed @ RetainedIgnoreObservation::Failed(_) => return failed,
                RetainedIgnoreObservation::Ok => {}
                other => result = other,
            }
        }
        result
    }
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
    fn read_file_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectFileSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || read_disk_file_snapshot(file),
            |snapshot| Some(snapshot.oid()),
        )
    }

    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.read_file_snapshot(file)?.decode()
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

    fn cached_omissions_if_available(&self) -> io::Result<Option<Arc<Vec<WorkspaceFileOmission>>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let mut omissions = Vec::new();
        for root in &self.roots {
            let Some(rows) = root.cached_omissions_if_available()? else {
                return Ok(None);
            };
            omissions.extend(rows.iter().map(|omission| {
                WorkspaceFileOmission {
                    path: root
                        .root()
                        .strip_prefix(&self.root)
                        .expect("child root belongs to common root")
                        .join(&omission.path),
                    reason: omission.reason,
                }
            }));
        }
        Ok(Some(Arc::new(omissions)))
    }
    fn cached_listing_if_available(&self) -> io::Result<Option<SharedWorkspaceFileListing>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let mut files = BTreeSet::new();
        let mut omissions = Vec::new();
        for root in &self.roots {
            let Some((root_files, rows)) = root.cached_listing_if_available()? else {
                return Ok(None);
            };
            files.extend(
                root_files
                    .iter()
                    .cloned()
                    .map(|file| self.common_file_for_root_file(file)),
            );
            omissions.extend(rows.iter().map(|omission| {
                WorkspaceFileOmission {
                    path: root
                        .root()
                        .strip_prefix(&self.root)
                        .expect("child root belongs to common root")
                        .join(&omission.path),
                    reason: omission.reason,
                }
            }));
        }
        Ok(Some((Arc::new(files), Arc::new(omissions))))
    }
    fn cached_analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<Option<BTreeSet<ProjectFile>>> {
        let _project_read = listing_read(self);
        let mut analyzable = BTreeSet::new();
        for root in &self.roots {
            let root_files = files
                .iter()
                .filter_map(|file| {
                    let abs_path = file.abs_path();
                    let rel = abs_path.strip_prefix(root.root()).ok()?;
                    Some(ProjectFile::new(
                        root.root().to_path_buf(),
                        rel.to_path_buf(),
                    ))
                })
                .collect();
            let Some(rows) = root.cached_analyzable_files_from(&root_files, language)? else {
                return Ok(None);
            };
            analyzable.extend(
                rows.into_iter()
                    .map(|file| self.common_file_for_root_file(file)),
            );
        }
        Ok(Some(analyzable))
    }
    fn all_files_with_omissions(&self) -> io::Result<SharedWorkspaceFileListing> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let mut files = BTreeSet::new();
        let mut omissions = Vec::new();
        for root in &self.roots {
            let (root_files, root_omissions) = root.all_files_with_omissions()?;
            files.extend(
                root_files
                    .iter()
                    .cloned()
                    .map(|file| self.common_file_for_root_file(file)),
            );
            omissions.extend(root_omissions.iter().map(|omission| {
                WorkspaceFileOmission {
                    path: root
                        .root()
                        .strip_prefix(&self.root)
                        .expect("child root belongs to common root")
                        .join(&omission.path),
                    reason: omission.reason,
                }
            }));
        }
        publish_file_set(self, &files)?;
        Ok((Arc::new(files), Arc::new(omissions)))
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

    fn revalidate_symlink_omissions(&self, changed: &BTreeSet<ProjectFile>) {
        for root in &self.roots {
            // Each child keeps its own listing cache, so it sees the changed
            // paths relative to its own root; paths outside it are not its.
            let root_changed = changed
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
            root.revalidate_symlink_omissions(&root_changed);
        }
    }

    fn is_bifrostignored(&self, rel_path: &Path) -> Result<bool, IgnoreObservationError> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        let abs_path = self.root.join(rel_path);
        let mut ignored = false;
        for root in &self.roots {
            if let Ok(root_rel_path) = abs_path.strip_prefix(root.root()) {
                ignored |= root.is_bifrostignored(root_rel_path)?;
            }
        }
        self.ignore_rules_digest().map_err(|cause| {
            IgnoreObservationError::new(&self.root, IgnoreObservationOperation::Matcher, cause)
        })?;
        Ok(ignored)
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

/// Analyzer-owned files beneath the selected workspace root. Construction
/// resolves every spelling once: the root and each cache directory in lexical
/// and canonical form, so a symlinked workspace root or cache directory
/// matches. `contains` is then a lexical prefix test with no filesystem access,
/// because it runs for every walked path.
#[derive(Clone)]
pub struct AnalyzerOwnedPaths {
    cache_dirs: Vec<PathBuf>,
    legacy_dirs: [PathBuf; 2],
}

impl AnalyzerOwnedPaths {
    pub fn new(root: &Path) -> Self {
        Self::with_cache_dir(root, gitblob::cache_dir_path(root))
    }

    fn with_cache_dir(root: &Path, effective_cache: PathBuf) -> Self {
        let root = root.to_path_buf().normalize();
        let canonical_root = root
            .canonicalize()
            .unwrap_or_else(|_| root.clone())
            .normalize();
        let default_root = gitblob::discover(&root)
            .as_ref()
            .and_then(gitblob::primary_repo_root)
            .unwrap_or_else(|| root.clone());
        let default_cache = default_root
            .join(gitblob::PROJECT_DIR_NAME)
            .join(gitblob::CACHE_SUBDIR_NAME);
        let mut cache_dirs = Vec::new();
        for dir in [effective_cache, default_cache] {
            add_directory_spellings(&mut cache_dirs, &root, &canonical_root, dir);
        }
        cache_dirs.sort_unstable();
        cache_dirs.dedup();
        Self {
            cache_dirs,
            legacy_dirs: [
                root.join(gitblob::PROJECT_DIR_NAME),
                canonical_root.join(gitblob::PROJECT_DIR_NAME),
            ],
        }
    }

    /// Extend the owned paths with one generated-state directory beneath
    /// `root`. A workspace-local semantic-pack catalog is opened read-write by
    /// the engine, so its SQLite files are analyzer state and must not look
    /// like workspace edits to the watcher.
    pub fn with_extra_directory(mut self, root: &Path, directory: PathBuf) -> Self {
        let root = root.to_path_buf().normalize();
        let canonical_root = root
            .canonicalize()
            .unwrap_or_else(|_| root.clone())
            .normalize();
        add_directory_spellings(&mut self.cache_dirs, &root, &canonical_root, directory);
        self.cache_dirs.sort_unstable();
        self.cache_dirs.dedup();
        self
    }

    pub fn contains(&self, path: &Path) -> bool {
        let path = path.to_path_buf().normalize();
        self.cache_dirs.iter().any(|dir| path.starts_with(dir))
            || (path
                .parent()
                .is_some_and(|parent| self.legacy_dirs.iter().any(|dir| parent == dir))
                && path
                    .file_name()
                    .is_some_and(crate::cache_db::is_legacy_project_cache_file_name))
    }
}

fn add_directory_spellings(
    owned_dirs: &mut Vec<PathBuf>,
    root: &Path,
    canonical_root: &Path,
    dir: PathBuf,
) {
    let dir = if dir.is_absolute() {
        dir
    } else {
        std::env::current_dir()
            .expect("workspace collection has a current directory")
            .join(dir)
    }
    .normalize();
    let canonical = dir.canonicalize().map(NormalizePath::normalize);
    // A directory that does not exist yet has no canonical form; rebasing it
    // onto the other root spelling covers the paths a walk or a watcher
    // reports once it is created.
    for spelling in [Some(dir), canonical.ok()].into_iter().flatten() {
        for (from, to) in [(root, canonical_root), (canonical_root, root)] {
            if let Ok(relative) = spelling.strip_prefix(from) {
                owned_dirs.push(spelling.clone());
                owned_dirs.push(to.join(relative));
            }
        }
    }
}

/// Collect every file under `root` that belongs to the analyzer's view of the
/// workspace. The walk is ignore-aware, skips `.git/`, and keeps other dotted
/// directories in scope.
pub fn collect_workspace_files(root: &Path) -> io::Result<BTreeSet<ProjectFile>> {
    collect_workspace_files_with_omissions(root).map(|listing| listing.files)
}

/// A listing and the paths discarded by enumeration itself. Ignore rules are
/// outside the listing universe and therefore do not produce omissions.
#[derive(Debug)]
pub struct WorkspaceFileListing {
    pub files: BTreeSet<ProjectFile>,
    pub omissions: Vec<WorkspaceFileOmission>,
    /// Where each symlink omission resolved when the listing was built.
    pub symlinks: SymlinkTargets,
    /// Err means input enumeration was unavailable: every outer update re-lists.
    pub(crate) ignore_inputs: ignore_inputs::InputReceipt,
    matcher: Option<Result<Arc<BifrostIgnoreMatcher>, IgnoreObservationError>>,
}

/// The resolved target of every symlink omission of one listing, kept beside
/// the omissions so that an update rechecks only the links a change can
/// affect.
#[derive(Debug, Default)]
pub struct SymlinkTargets {
    /// The canonical workspace root the targets were resolved against.
    canonical_root: PathBuf,
    links: Vec<SymlinkRecord>,
    /// For each path that can alter an in-workspace link's classification, the
    /// indices into `links` of the links it can alter: the link's target and
    /// every ancestor of the target, the link itself and every ancestor of the
    /// link (a directory removed, renamed or replaced).
    by_path: HashMap<PathBuf, Vec<usize>>,
    /// The links with no recorded path to wait for: a target outside the
    /// workspace, through another symlink, or none. Every update rechecks them.
    always: Vec<usize>,
}

impl SymlinkTargets {
    fn new(canonical_root: PathBuf, links: Vec<SymlinkRecord>) -> Self {
        let mut by_path: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        let mut always = Vec::new();
        for (index, link) in links.iter().enumerate() {
            match &link.target {
                SymlinkTarget::Inside(target) => {
                    for ancestor in target.ancestors().chain(link.path.ancestors()) {
                        let indices = by_path.entry(ancestor.to_path_buf()).or_default();
                        // The target and the link share their ancestors.
                        if indices.last() != Some(&index) {
                            indices.push(index);
                        }
                    }
                }
                SymlinkTarget::External | SymlinkTarget::Indirect | SymlinkTarget::Unresolved => {
                    always.push(index);
                }
            }
        }
        Self {
            canonical_root,
            links,
            by_path,
            always,
        }
    }

    /// The links a change to any path of `changed` can affect: the indexed
    /// links that name a changed path, then the links that are always rechecked.
    /// The cost follows the changed paths and the always-rechecked links, not
    /// the number of links in the workspace.
    fn affected_by<'a>(
        &'a self,
        changed: &BTreeSet<ProjectFile>,
    ) -> impl Iterator<Item = &'a SymlinkRecord> {
        let mut indexed: Vec<usize> = changed
            .iter()
            .filter_map(|file| self.by_path.get(file.rel_path()))
            .flatten()
            .copied()
            .collect();
        indexed.sort_unstable();
        indexed.dedup();
        #[cfg(any(test, feature = "test-support"))]
        for _ in &indexed {
            super::project_reads::count_project_io(
                super::project_reads::ProjectIo::SymlinkCandidate,
            );
        }
        // A link is in the index or in `always`, never both.
        indexed
            .into_iter()
            .chain(self.always.iter().copied())
            .map(|index| &self.links[index])
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SymlinkRecord {
    path: PathBuf,
    reason: WorkspaceFileOmissionReason,
    target: SymlinkTarget,
}

/// Where a symlink resolves, chains included.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SymlinkTarget {
    /// The canonical target, relative to the canonical workspace root.
    Inside(PathBuf),
    /// The target lies outside the workspace, so no workspace event names it.
    External,
    /// The link resolves through another symlink, in its target or in one of
    /// the target's directories. That hop can be ignored or unlisted, so no
    /// event on a recorded path need name it.
    Indirect,
    /// Canonicalization failed: dangling, a loop or no permission.
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkspaceFileOmission {
    pub path: PathBuf,
    pub reason: WorkspaceFileOmissionReason,
}

/// Serde's `PathBuf` implementation fails on the non-UTF-8 paths `NonUtf8GitPath`
/// records. The path is displayed through `workspace_relative_slash_path`, and
/// `lossy` is set when that display replaced bytes, so two different paths can
/// share a display. Identity and digests use the raw path, never this string.
impl serde::Serialize for WorkspaceFileOmission {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let lossy = self.path.to_str().is_none();
        let mut state =
            serializer.serialize_struct("WorkspaceFileOmission", 2 + usize::from(lossy))?;
        state.serialize_field(
            "path",
            &crate::path_utils::workspace_relative_slash_path(&self.path),
        )?;
        state.serialize_field("reason", &self.reason)?;
        if lossy {
            state.serialize_field("lossy", &true)?;
        }
        state.end()
    }
}

pub type SharedWorkspaceFileListing = (Arc<BTreeSet<ProjectFile>>, Arc<Vec<WorkspaceFileOmission>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum WorkspaceFileOmissionReason {
    Unknown,
    /// A regular file at a known path that this listing deliberately does not
    /// supply, such as a file outside a bounded revision image's ecosystem.
    /// A consumer whose own files could be at that path treats it as missing.
    NotSupplied,
    WalkError,
    NonUtf8GitPath,
    /// A symbolic link whose target is a file.
    Symlink,
    /// A symbolic link whose target is a directory. The files below it are not
    /// listed.
    SymlinkToDirectory,
    /// A symbolic link whose target could not be read, so its kind is unknown.
    UnreadableSymlink,
    NonRegular,
    NonUtf8Name,
}

/// Whether an omission can hide a workspace source for any language. A walk
/// error, an undecodable Git path, or a project that cannot say why
/// (`Unknown`, which is also the default listing's single row) may drop a
/// source this analyzer should have indexed. So may a symbolic link to a
/// directory, which the listing does not descend into, or an unreadable
/// symbolic link. Ignore rules, configured excludes and other non-regular
/// entries are outside the analyzer's universe. A file at a known path
/// (`NotSupplied`, a file `Symlink`) hides a source only for a consumer whose
/// own files could live at that path; the language hook decides that.
pub fn omission_may_hide_source(reason: WorkspaceFileOmissionReason) -> bool {
    matches!(
        reason,
        WorkspaceFileOmissionReason::WalkError
            | WorkspaceFileOmissionReason::NonUtf8GitPath
            | WorkspaceFileOmissionReason::Unknown
            | WorkspaceFileOmissionReason::SymlinkToDirectory
            | WorkspaceFileOmissionReason::UnreadableSymlink
    )
}

/// The omission reason and resolved target of the symbolic link at `absolute`
/// in the workspace whose canonical root is `canonical_root`. The kind of the
/// target decides whether files may hide behind it. The walk and the
/// revalidation share this classifier, so they agree on every link.
fn classify_symlink(canonical_root: &Path, absolute: &Path, path: PathBuf) -> SymlinkRecord {
    let reason = match std::fs::metadata(absolute) {
        Ok(target) if target.is_file() => WorkspaceFileOmissionReason::Symlink,
        Ok(target) if target.is_dir() => WorkspaceFileOmissionReason::SymlinkToDirectory,
        // A FIFO, socket or device: reading it can block, and nothing can
        // hide behind it.
        Ok(_) => WorkspaceFileOmissionReason::NonRegular,
        Err(_) => WorkspaceFileOmissionReason::UnreadableSymlink,
    };
    let target = match std::fs::canonicalize(absolute) {
        Ok(canonical) => {
            let canonical = canonical.normalize();
            // The link's own directories are real: the listing does not
            // descend through a symlink. So when its first hop, taken
            // lexically, already names the canonical path, no other symlink
            // took part in the resolution.
            let direct = std::fs::read_link(absolute).ok().is_some_and(|hop| {
                canonical_root
                    .join(&path)
                    .parent()
                    .expect("a listed symlink has a parent directory")
                    .join(hop)
                    .normalize()
                    == canonical
            });
            match canonical.strip_prefix(canonical_root) {
                Ok(rel) if direct => SymlinkTarget::Inside(rel.to_path_buf()),
                Ok(_) => SymlinkTarget::Indirect,
                Err(_) => SymlinkTarget::External,
            }
        }
        Err(_) => SymlinkTarget::Unresolved,
    };
    SymlinkRecord {
        path,
        reason,
        target,
    }
}

impl SymlinkRecord {
    fn omission(&self) -> WorkspaceFileOmission {
        WorkspaceFileOmission {
            path: self.path.clone(),
            reason: self.reason,
        }
    }
}

/// The workspace listing under `root` that one Git membership describes.
///
/// `active_paths` and `non_utf8_paths` are relative to `canonical_workdir`, as
/// [`crate::gitblob::working_tree_paths_with_non_utf8`] and
/// [`crate::gitblob::WorkingTreeIdentity::working_tree_paths`] return them.
/// Paths outside `canonical_root` and analyzer-owned paths are dropped, and
/// every symbolic link and non-regular entry is classified the same way the
/// walk classifies it.
///
/// `None` means Git names no file under the root: an ancestor repository's
/// ignore rules hide the whole selected subtree, so Git cannot represent the
/// workspace and the caller must walk it.
fn git_workspace_listing(
    root: &Path,
    canonical_root: &Path,
    canonical_workdir: &Path,
    active_paths: impl IntoIterator<Item = String>,
    non_utf8_paths: impl IntoIterator<Item = PathBuf>,
) -> Option<WorkspaceFileListing> {
    let owned_paths = AnalyzerOwnedPaths::new(root);
    let mut files = BTreeSet::new();
    let mut symlinks = Vec::new();
    let mut omissions: Vec<_> = non_utf8_paths
        .into_iter()
        .filter_map(|path| {
            canonical_workdir
                .join(path)
                .strip_prefix(canonical_root)
                .ok()
                .map(|rel| WorkspaceFileOmission {
                    path: rel.to_path_buf(),
                    reason: WorkspaceFileOmissionReason::NonUtf8GitPath,
                })
        })
        .collect();
    for rel in active_paths {
        let absolute = canonical_workdir.join(rel);
        let Ok(project_rel) = absolute.strip_prefix(canonical_root) else {
            continue;
        };
        if owned_paths.contains(&absolute) {
            continue;
        }
        if let Ok(metadata) = absolute.symlink_metadata() {
            let reason = if metadata.file_type().is_symlink() {
                let record = classify_symlink(canonical_root, &absolute, project_rel.to_path_buf());
                let reason = record.reason;
                symlinks.push(record);
                Some(reason)
            } else if !metadata.file_type().is_file() {
                Some(WorkspaceFileOmissionReason::NonRegular)
            } else {
                None
            };
            if let Some(reason) = reason {
                omissions.push(WorkspaceFileOmission {
                    path: project_rel.to_path_buf(),
                    reason,
                });
                // Git lists every symlink so that it reaches this
                // classification. Only a link to a regular file is read as a
                // file. A link to a directory, to a FIFO or device, or to
                // nothing readable has no content to analyze, and neither has
                // a non-regular entry.
                if reason != WorkspaceFileOmissionReason::Symlink {
                    continue;
                }
            }
        }
        files.insert(ProjectFile::new(
            root.to_path_buf(),
            project_rel.to_path_buf(),
        ));
    }
    (!files.is_empty()).then(|| WorkspaceFileListing {
        files,
        omissions,
        symlinks: SymlinkTargets::new(canonical_root.to_path_buf(), symlinks),
        ignore_inputs: Err(ignore_inputs::unavailable(
            root,
            "identity scan has no ignore inputs",
        )),
        matcher: None,
    })
}

/// The listing `project` serves, taken from a working-tree identity scan that
/// is already in hand instead of from another `git status`.
///
/// A built analyzer took one [`crate::gitblob::WorkingTreeIdentity`] scan for
/// its generation. A consumer that needs only the workspace's membership, such
/// as dependency discovery looking for manifests inside a host policy request,
/// reads it here rather than listing the worktree again (#11890). The
/// membership is the one [`collect_workspace_files_with_omissions`] computes,
/// through the same Git-branch classification, and the source overlays
/// `project` layers on top are added by [`OverlayProject`]'s own rule: a
/// buffer is listed only where no file is on disk.
///
/// `Ok(None)` means the scan cannot reproduce `project`'s listing, and the
/// caller must ask `project` itself:
/// - `project` exposes an explicit subset of the workspace, which a worktree
///   scan knows nothing about;
/// - the scan holds a gitlink (see
///   [`crate::gitblob::WorkingTreeIdentity::working_tree_paths`]);
/// - Git names no file under the root, the case where the listing walks the
///   selected root instead.
pub fn workspace_listing_from_identity(
    project: &dyn Project,
    identity: &crate::gitblob::WorkingTreeIdentity,
) -> io::Result<Option<SharedWorkspaceFileListing>> {
    if project.coverage().subset().is_some() {
        return Ok(None);
    }
    let root = project.root();
    let canonical_root = root.canonicalize()?.normalize();
    let canonical_workdir = identity.workdir();
    let Some((active_paths, non_utf8_paths)) = identity.working_tree_paths(
        crate::gitblob::subtree_pathspec(canonical_workdir, &canonical_root).as_deref(),
    ) else {
        return Ok(None);
    };
    let Some(listing) = git_workspace_listing(
        root,
        &canonical_root,
        canonical_workdir,
        active_paths,
        non_utf8_paths,
    ) else {
        return Ok(None);
    };
    let mut files = listing.files;
    if let Some(overlays) = project.capture_source_overlays()?.content() {
        let buffers: Vec<ProjectFile> = OverlayProject::buffers_missing_from(
            overlays.entries().iter().map(|(file, _)| file.clone()),
            &files,
        )
        .collect();
        files.extend(buffers);
    }
    Ok(Some((Arc::new(files), Arc::new(listing.omissions))))
}

pub fn collect_workspace_files_with_omissions(root: &Path) -> io::Result<WorkspaceFileListing> {
    let first = collect_workspace_files_once(root)?;
    let Ok(before) = &first.ignore_inputs else {
        return Ok(first);
    };
    if !before.needs_confirmation() {
        return Ok(first);
    }
    // One confirmation, never a retry loop. Keep the second observation even
    // on disagreement so this request returns the freshest complete listing.
    let mut second = collect_workspace_files_once(root)?;
    if let Ok(after) = &second.ignore_inputs {
        let same_matcher = match (
            first
                .matcher
                .as_ref()
                .expect("one-pass listing captures its matcher"),
            second
                .matcher
                .as_ref()
                .expect("one-pass listing captures its matcher"),
        ) {
            (Ok(left), Ok(right)) => {
                left.root == right.root && left.rules_digest == right.rules_digest
            }
            (Err(error), _) | (_, Err(error)) => {
                // Retain the complete first error even if the second matcher
                // succeeds. A second matcher error also remains in its field.
                second.ignore_inputs = Err(error.clone());
                return Ok(second);
            }
        };
        let same_listing = first.files == second.files
            && first.omissions.iter().collect::<BTreeSet<_>>()
                == second.omissions.iter().collect::<BTreeSet<_>>()
            && first.symlinks.canonical_root == second.symlinks.canonical_root
            && first.symlinks.links.iter().collect::<BTreeSet<_>>()
                == second.symlinks.links.iter().collect::<BTreeSet<_>>()
            && same_matcher;
        if !same_listing || !before.same_inputs(after) {
            second.ignore_inputs = Err(ignore_inputs::unavailable(
                root,
                "workspace listing or ignore input identities changed during confirmation",
            ));
        }
    }
    Ok(second)
}

fn collect_workspace_files_once(root: &Path) -> io::Result<WorkspaceFileListing> {
    let mut listing = collect_workspace_listing(root)?;
    // Include unreadable link paths in rule discovery; they can be the only
    // entry beneath a directory with a .bifrostignore. Apply this same captured
    // matcher to their OWN paths, never their targets (#12889).
    let mut matcher_files = listing.files.clone();
    matcher_files.extend(
        listing
            .symlinks
            .links
            .iter()
            .map(|link| ProjectFile::new(root, &link.path)),
    );
    let matcher = capture_ignore_matcher(root, &matcher_files);
    if let Ok(matcher) = &matcher {
        listing.omissions.retain(|omission| {
            omission.reason != WorkspaceFileOmissionReason::UnreadableSymlink
                || !matcher.is_ignored_path(&omission.path)
        });
    }
    // Receipt refusal is a performance fallback. Preserve its full typed error
    // in ignore_inputs for callers; it is not a CLI stderr diagnostic.
    listing.matcher = Some(matcher);
    Ok(listing)
}

#[cfg(test)]
thread_local! {
    static AFTER_WALK_IGNORE_INPUT_SAMPLE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_IGNORE_INPUT_CAPTURE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn collect_workspace_listing(root: &Path) -> io::Result<WorkspaceFileListing> {
    // Before Git reads any rules, or WalkBuilder constructs its ignore layers.
    let started = SystemTime::now();
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
        // in `git_workspace_listing` already discards everything outside it,
        // so scoping the enumeration to the subtree yields the same listing at
        // a cost proportional to the workspace instead of the ancestor
        // repository.
        // Capture fixed inputs before native Git status applies them. Path-only
        // Git enumerations do not need this receipt or its config subprocesses.
        let pre_inputs = ignore_inputs::git_pre_inputs(workdir).map_err(|error| error.to_string());
        let scan = crate::gitblob::working_tree_listing_with_inputs(
            &repo,
            crate::gitblob::subtree_pathspec(&canonical_workdir, &canonical_root).as_deref(),
        )
        .map_err(io::Error::other)?;
        #[cfg(test)]
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        if let Some(listing) = git_workspace_listing(
            root,
            &canonical_root,
            &canonical_workdir,
            scan.paths,
            scan.non_utf8,
        ) {
            let mut listing = listing;
            listing.ignore_inputs =
                ignore_inputs::git_receipt(root, pre_inputs, scan.directories, started);
            return Ok(listing);
        }
        // An ancestor repository can discover this root while its ignore rules
        // hide the complete subtree. In that case, Git cannot represent the
        // explicitly selected workspace. Walk the selected root instead.
        apply_parent_ignores = false;
    }

    let mut inputs = ignore_inputs::IgnoreInputs::default();
    let initial_inputs = ignore_inputs::walk_globals(root, &mut inputs).map(|()| inputs);
    #[cfg(test)]
    AFTER_WALK_IGNORE_INPUT_SAMPLE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let walk_inputs = Arc::new(Mutex::new(initial_inputs));
    let owned_paths = AnalyzerOwnedPaths::new(root);
    let canonical_root = root.canonicalize()?.normalize();
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
        .filter_entry(move |entry| {
            entry.file_name() != std::ffi::OsStr::new(".git") && !owned_paths.contains(entry.path())
        })
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
    enum Walked {
        File(ProjectFile),
        Omission(WorkspaceFileOmission),
        Symlink(SymlinkRecord),
    }
    let (tx, rx) = std::sync::mpsc::channel::<Walked>();
    let collector_root = canonical_root.clone();
    let collector = std::thread::spawn(move || {
        let mut files = BTreeSet::new();
        let mut omissions = Vec::new();
        let mut links = Vec::new();
        for item in rx {
            match item {
                Walked::File(file) => {
                    files.insert(file);
                }
                Walked::Omission(omission) => omissions.push(omission),
                Walked::Symlink(record) => {
                    omissions.push(record.omission());
                    links.push(record);
                }
            }
        }
        WorkspaceFileListing {
            files,
            omissions,
            symlinks: SymlinkTargets::new(collector_root.clone(), links),
            ignore_inputs: Err(ignore_inputs::unavailable(
                &collector_root,
                "walk inputs not captured yet",
            )),
            matcher: None,
        }
    });
    let first_error: Arc<Mutex<Option<io::Error>>> = Arc::new(Mutex::new(None));
    walker.run(|| {
        let tx = tx.clone();
        let canonical_root = canonical_root.clone();
        let first_error = Arc::clone(&first_error);
        let walk_inputs = Arc::clone(&walk_inputs);
        Box::new(move |result| {
            let entry = match result {
                Ok(entry) => entry,
                Err(err) => {
                    let mut source = &err;
                    let path = loop {
                        match source {
                            ignore::Error::WithPath { path, .. } => break path.as_path(),
                            ignore::Error::Loop { child, .. } => break child.as_path(),
                            ignore::Error::WithLineNumber { err, .. }
                            | ignore::Error::WithDepth { err, .. } => source = err,
                            _ => break root,
                        }
                    };
                    let path = path.strip_prefix(root).unwrap_or_else(|_| Path::new(""));
                    let _ = tx.send(Walked::Omission(WorkspaceFileOmission {
                        path: path.to_path_buf(),
                        reason: WorkspaceFileOmissionReason::WalkError,
                    }));
                    let mut slot = first_error.lock().expect("walk error lock poisoned");
                    if slot.is_none() {
                        *slot = Some(io::Error::other(err.to_string()));
                    }
                    // Keep walking the rest of the tree; the captured error is
                    // returned to the caller once the traversal finishes.
                    return WalkState::Continue;
                }
            };
            if entry.file_type().is_some_and(|kind| kind.is_dir()) {
                let mut slot = walk_inputs.lock().expect("walk input lock poisoned");
                if let Ok(inputs) = slot.as_mut() {
                    let captured = (|| {
                        if entry.path() != root && entry.path().join(".git").exists() {
                            return Err(io::Error::other("nested repository in fallback walk"));
                        }
                        inputs.record(entry.path().join(".gitignore"))?;
                        inputs.record(entry.path().join(".ignore"))?;
                        inputs.record(entry.path().join(".bifrostignore"))
                    })();
                    if let Err(error) = captured {
                        *slot = Err(error);
                    }
                }
            }
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
                let _ = tx.send(Walked::File(ProjectFile::new(
                    root.to_path_buf(),
                    rel.to_path_buf(),
                )));
                if rel.file_name().is_some_and(|name| name.to_str().is_none()) {
                    let _ = tx.send(Walked::Omission(WorkspaceFileOmission {
                        path: rel.to_path_buf(),
                        reason: WorkspaceFileOmissionReason::NonUtf8Name,
                    }));
                }
            } else if let Some(file_type) = entry.file_type()
                && !file_type.is_dir()
            {
                let rel = entry
                    .path()
                    .strip_prefix(root)
                    .expect("walker returned a path outside the project root");
                let _ = tx.send(if file_type.is_symlink() {
                    Walked::Symlink(classify_symlink(
                        &canonical_root,
                        entry.path(),
                        rel.to_path_buf(),
                    ))
                } else {
                    Walked::Omission(WorkspaceFileOmission {
                        path: rel.to_path_buf(),
                        reason: WorkspaceFileOmissionReason::NonRegular,
                    })
                });
            }
            WalkState::Continue
        })
    });
    // Drop our retained sender so the collector's iterator terminates once every
    // walker thread's clone has also been dropped.
    drop(tx);

    let mut listing = collector.join().expect("file-collector thread panicked");
    #[cfg(test)]
    BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    listing.ignore_inputs = Arc::try_unwrap(walk_inputs)
        .expect("walk visitors finished")
        .into_inner()
        .expect("walk input lock poisoned")
        .and_then(|inputs| inputs.finish(started))
        .map_err(|error| {
            IgnoreObservationError::new(root, IgnoreObservationOperation::Listing, error)
        });

    if let Some(error) = first_error.lock().expect("walk error lock poisoned").take() {
        return Err(io::Error::other(PartialWorkspaceListing {
            files: listing.files,
            error,
        }));
    }
    Ok(listing)
}

/// The error of a workspace walk that failed under part of the tree, carrying
/// the files the rest of the walk enumerated. A caller that can report an
/// incomplete answer recovers them with [`PartialWorkspaceListing::files_of`];
/// every other caller sees an ordinary listing error.
#[derive(Debug)]
pub struct PartialWorkspaceListing {
    pub files: BTreeSet<ProjectFile>,
    pub error: io::Error,
}

impl PartialWorkspaceListing {
    pub fn files_of(err: &io::Error) -> Option<&BTreeSet<ProjectFile>> {
        err.get_ref()?
            .downcast_ref::<Self>()
            .map(|partial| &partial.files)
    }
}

impl std::fmt::Display for PartialWorkspaceListing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for PartialWorkspaceListing {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
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

/// Process-monotonic identity of one [`PinnedSourceOverlayView`]. It comes from
/// the project-view counter, is never reused, and is neither an address nor a
/// content hash, so equal identities mean the same captured view. It names a
/// captured request input, not a validation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinnedSourceOverlayViewId(u64);

/// An immutable, overlay-only capture of a project's source overlays, taken by
/// [`Project::capture_source_overlays`]. It holds the overlays' shared entries
/// as they were at capture, so neither a later edit to the project nor a
/// replacement of an overlay changes what it answers, and reading it never
/// decodes or hashes source again.
///
/// This is a captured request input and nothing more. Its identity, content
/// metadata and source are what the request reads; they are never a validation
/// receipt, certificate or proof, and must not be converted into one.
pub struct PinnedSourceOverlayView {
    id: PinnedSourceOverlayViewId,
    content: Option<Arc<WorkspaceOverlayContent>>,
    entries: HashMap<PathBuf, Arc<OverlayEntry>>,
}

impl PinnedSourceOverlayView {
    fn new(
        content: Option<Arc<WorkspaceOverlayContent>>,
        entries: HashMap<PathBuf, Arc<OverlayEntry>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: PinnedSourceOverlayViewId(next_project_view_id()),
            content,
            entries,
        })
    }

    fn empty() -> Arc<Self> {
        Self::new(None, HashMap::new())
    }

    pub fn identity(&self) -> PinnedSourceOverlayViewId {
        self.id
    }

    /// The content identity of the pinned overlay set, or `None` when the
    /// project has no overlay concept. For a chain of overlay projects it
    /// covers the inherited and the outer overlays together (the outer one
    /// winning a shared path), unlike a single project's `overlay_content()`,
    /// which lists its own overlays only. An overlay outside the project root
    /// is pinned for `source_snapshot` but has no workspace path to list here.
    pub fn content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
        self.content.clone()
    }

    /// The pinned overlay of `file` with its text, original blob identity and
    /// overlay revision, or `None` when `file` was not overlaid. Disk and
    /// delegate content are never consulted.
    pub fn source_snapshot(&self, file: &ProjectFile) -> Option<ProjectSourceSnapshot> {
        self.entries
            .get(&file.abs_path())
            .map(|entry| entry.snapshot())
    }
}

/// Complete metadata, never source: the identity, the content identity and each
/// overlay's path, revision, blob identity and content digest in path order.
impl std::fmt::Debug for PinnedSourceOverlayView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut overlays = self
            .entries
            .iter()
            .map(|(path, entry)| (path, entry.revision, entry.blob_id, entry.content_digest))
            .collect::<Vec<_>>();
        overlays.sort();
        formatter
            .debug_struct("PinnedSourceOverlayView")
            .field("id", &self.id)
            .field("content", &self.content)
            .field("overlays", &overlays)
            .finish()
    }
}

/// The content identity of the overlays in `overlays`, keyed by workspace
/// relative path; an overlay outside `root` has no workspace path and is left
/// out, as it is from the project's own overlay content.
fn overlay_content_for(
    root: &Path,
    overlays: &HashMap<PathBuf, Arc<OverlayEntry>>,
) -> Arc<WorkspaceOverlayContent> {
    Arc::new(WorkspaceOverlayContent::new(overlays.iter().filter_map(
        |(abs_path, entry)| {
            let rel_path = abs_path.strip_prefix(root).ok()?;
            Some((
                ProjectFile::new(root.to_path_buf(), rel_path),
                entry.content_digest,
                entry.blob_id,
            ))
        },
    )))
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
    view_id: u64,
    /// The overlay content identity published for the map's current revision.
    /// Recomputing it hashes every open buffer, so it is derived once per
    /// accepted edit rather than once per query. The revision is a memo key
    /// only; it never enters the identity.
    overlay_content: Mutex<Option<(u64, Arc<WorkspaceOverlayContent>)>>,
    delegate: Arc<dyn Project>,
    /// Lock order: when overlay projects are nested, this map's lock is taken
    /// before the delegate's (outer, then inner). `view_stamp` and
    /// `capture_source_overlays` hold this guard while they call the delegate,
    /// and any path that holds both locks must follow that order. The delegate
    /// must never call back into this project or into a query while it is
    /// called under this lock.
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
            view_id: next_project_view_id(),
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
        let content = overlay_content_for(self.delegate.root(), &frozen_overlays);
        super::project_reads::publish_overlays(&Some(content));
        Self {
            project_reads: ProjectReadSlot::default(),
            view_id: next_project_view_id(),
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
    ) -> io::Result<()> {
        let additions = Self::buffers_missing_from(
            candidates
                .into_iter()
                .filter(|file| file.language() == language),
            analyzable,
        )
        .map(|file| {
            self.delegate
                .is_bifrostignored(file.rel_path())
                .map(|ignored| (!ignored).then_some(file))
        })
        .collect::<Result<Vec<_>, _>>()?;
        analyzable.extend(additions.into_iter().flatten());
        Ok(())
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
    fn retained_ignore_observation(&self) -> RetainedIgnoreObservation {
        self.delegate.retained_ignore_observation()
    }
    fn directory_entries(&self, parent: &Path) -> io::Result<BTreeSet<ProjectFile>> {
        self.delegate.directory_entries(parent)
    }

    fn view_stamp(&self) -> Option<ProjectViewStamp> {
        let _overlays = self.overlays.read().expect("overlay lock poisoned");
        let own = ProjectViewStamp::own(
            self.view_id,
            self.published_generation.load(Ordering::Acquire),
        );
        self.delegate
            .view_stamp()
            .map(|delegate| own.over(delegate))
    }
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

    fn authoritative_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let mut files = self.delegate.authoritative_files()?;
        files.extend(self.overlay_project_files());
        Ok(files)
    }

    fn all_files_shared(&self) -> io::Result<Arc<BTreeSet<ProjectFile>>> {
        self.all_files_with_omissions().map(|(files, _)| files)
    }

    fn cached_omissions_if_available(&self) -> io::Result<Option<Arc<Vec<WorkspaceFileOmission>>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.delegate.cached_omissions_if_available()
    }
    fn cached_listing_if_available(&self) -> io::Result<Option<SharedWorkspaceFileListing>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let Some((files, omissions)) = self.delegate.cached_listing_if_available()? else {
            return Ok(None);
        };
        let additions: Vec<ProjectFile> =
            Self::buffers_missing_from(self.overlay_project_files(), &files).collect();
        if additions.is_empty() {
            return Ok(Some((files, omissions)));
        }
        let mut extended = (*files).clone();
        extended.extend(additions);
        Ok(Some((Arc::new(extended), omissions)))
    }
    fn cached_analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> io::Result<Option<BTreeSet<ProjectFile>>> {
        let _project_read = listing_read(self);
        self.delegate.cached_analyzable_files_from(files, language)
    }
    fn all_files_with_omissions(&self) -> io::Result<SharedWorkspaceFileListing> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        let (files, omissions) = self.delegate.all_files_with_omissions()?;
        let additions: Vec<ProjectFile> =
            Self::buffers_missing_from(self.overlay_project_files(), &files).collect();
        // Nothing to add is the ordinary case -- every open buffer has its file
        // on disk -- and the delegate's listing is the one every other reader of
        // this generation shares. Copying it per call to add nothing would make
        // a whole-workspace clone the price of holding a buffer open.
        if additions.is_empty() {
            publish_file_set(self, &files)?;
            return Ok((files, omissions));
        }
        let mut extended = (*files).clone();
        extended.extend(additions);
        publish_file_set(self, &extended)?;
        Ok((Arc::new(extended), omissions))
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
        )?;
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

    fn ignore_observation_for_files(
        &self,
        files: &BTreeSet<ProjectFile>,
    ) -> Result<IgnoreObservation, IgnoreObservationError> {
        let mut observation = self.delegate.ignore_observation_for_files(files)?;
        let overlays = self.overlay_project_files();
        for (file, ignored) in files.iter().zip(&observation.ignored) {
            if !ignored && file.language() != Language::None && overlays.contains(file) {
                observation.selected.insert(file.clone());
            }
        }
        Ok(observation)
    }

    fn is_bifrostignored(&self, rel_path: &Path) -> Result<bool, IgnoreObservationError> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.delegate.is_bifrostignored(rel_path)
    }

    fn invalidate_cached_file_listing(&self) {
        self.delegate.invalidate_cached_file_listing();
    }

    fn revalidate_symlink_omissions(&self, changed: &BTreeSet<ProjectFile>) {
        self.delegate.revalidate_symlink_omissions(changed);
    }

    fn has_exact_directory_entry(&self, file: &ProjectFile) -> std::io::Result<bool> {
        self.delegate.has_exact_directory_entry(file)
    }

    fn update_cached_listing_for_resolved_path(&self, file: &ProjectFile) -> bool {
        self.delegate.update_cached_listing_for_resolved_path(file)
    }

    fn update_cached_listing_for_path(&self, rel_path: &Path) -> bool {
        self.delegate.update_cached_listing_for_path(rel_path)
    }

    fn update_cached_listing_for_removed_paths(&self, files: &[ProjectFile]) -> bool {
        self.delegate.update_cached_listing_for_removed_paths(files)
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

    fn read_file_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectFileSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                if let Some(entry) = self.overlay_entry(file) {
                    return Ok(ProjectFileSnapshot {
                        bytes: entry.source.as_bytes().to_vec(),
                        oid: entry.blob_id,
                        origin: ProjectSourceOrigin::Overlay(entry.revision),
                    });
                }
                self.delegate.read_file_snapshot(file)
            },
            |snapshot| Some(snapshot.oid()),
        )
    }

    // Overlay source reads share the entry's source allocation (the atomic
    // overlay reuse contract); only authority keys need the raw-bytes path.
    fn read_source_snapshot(&self, file: &ProjectFile) -> io::Result<ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                if let Some(entry) = self.overlay_entry(file) {
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
            let mut memo = self
                .overlay_content
                .lock()
                .expect("overlay content memo poisoned");
            let overlays = self.overlays.read().expect("overlay lock poisoned");
            let revision = self.published_generation.load(Ordering::Acquire);
            if let Some((memoized_revision, content)) = memo.as_ref()
                && *memoized_revision == revision
            {
                break 'answer Some(Arc::clone(content));
            }
            let content = overlay_content_for(self.delegate.root(), &overlays);
            *memo = Some((revision, Arc::clone(&content)));
            Some(content)
        };
        super::project_reads::publish_overlays(&answer);
        answer
    }

    fn capture_source_overlays(&self) -> io::Result<Arc<PinnedSourceOverlayView>> {
        // One instant across the chain. This project's read guard is held while
        // the delegate is captured (lock order outer, then inner; the delegate
        // never calls back into this project), so no edit to this project
        // interleaves with the delegate capture and both pin together. An
        // unsupported delegate fails the capture here rather than yield a view
        // that silently lacks its overlays.
        let overlays = self.overlays.read().expect("overlay lock poisoned");
        let beneath = self.delegate.capture_source_overlays()?;
        // Inherited entries first, then this project's, which win a shared
        // path. Entries are immutable shared allocations: cloning them reads
        // and hashes no source, and nothing is published to the project-read
        // receipt, because a request calls this while it holds its entry map.
        let mut entries = beneath.entries.clone();
        entries.extend(
            overlays
                .iter()
                .map(|(path, entry)| (path.clone(), Arc::clone(entry))),
        );
        drop(overlays);
        let content = overlay_content_for(self.delegate.root(), &entries);
        Ok(PinnedSourceOverlayView::new(Some(content), entries))
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

/// Cargo auto-discovery directories whose immediate children can own main.rs.
pub const RUST_TARGET_LAYOUT_DIRECTORIES: [&str; 4] = ["tests", "examples", "benches", "src/bin"];

/// Whether a workspace path has one of Cargo's directory-target layouts.
pub fn is_rust_target_layout_main(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "main.rs")
        && path.parent().and_then(Path::parent).is_some_and(|parent| {
            RUST_TARGET_LAYOUT_DIRECTORIES
                .iter()
                .any(|kind| parent.ends_with(kind))
        })
}

// nextest isolates each test in a process; these variables are restored
// before the temporary home is removed. Never invoke git config --global.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct IgnoreTestEnvironment(Vec<(&'static str, Option<std::ffi::OsString>)>);
#[cfg(any(test, feature = "test-support"))]
impl IgnoreTestEnvironment {
    pub fn new(home: &Path) -> Self {
        std::fs::create_dir_all(home.join("xdg/git")).unwrap();
        let mut saved = Vec::new();
        for (name, value) in [
            ("HOME", home.to_path_buf()),
            ("XDG_CONFIG_HOME", home.join("xdg")),
            ("GIT_CONFIG_GLOBAL", home.join(".gitconfig")),
            ("GIT_CONFIG_SYSTEM", home.join("system-config")),
            ("GIT_CONFIG_NOSYSTEM", PathBuf::from("0")),
        ] {
            saved.push((name, std::env::var_os(name)));
            unsafe {
                std::env::set_var(name, value);
            }
        }
        Self(saved)
    }
}
#[cfg(any(test, feature = "test-support"))]
impl Drop for IgnoreTestEnvironment {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

/// Establish old ignore-input timestamps inside an owned temporary parent.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn age_ignore_test_inputs(root: &Path) {
    // Callers own root's temporary parent and every child below it.
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    // Timestamps only need a handle, not write access: on Unix the owner may
    // set them through a read-only handle, and on Windows FILE_WRITE_ATTRIBUTES
    // (with FILE_FLAG_BACKUP_SEMANTICS for directories) suffices. Opening for
    // write would fail on read-only files such as git loose objects (#13358).
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.access_mode(0x100).custom_flags(0x02000000);
    }
    let mut pending = vec![root.parent().unwrap().to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.metadata().unwrap().modified().unwrap() != old {
                options
                    .open(entry.path())
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
            }
        }
        if std::fs::metadata(&path).unwrap().modified().unwrap() != old {
            options.open(path).unwrap().set_modified(old).unwrap();
        }
    }
    // Unix ctime cannot be backdated; establish a quiet capture window.
    std::thread::sleep(std::time::Duration::from_millis(2100));
}

#[cfg(test)]
mod tests {
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: global exclude origins and unset defaults escaped listing validation"
    )]
    fn ignore_receipt_global_origin_and_default() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        {
            age_ignore_test_inputs(cache.root());
            cache.files().unwrap()
        };
        std::fs::write(home.join("xdg/git/ignore"), "visible.rs\n").unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
        let rules = home.join("rules with spaces");
        std::fs::write(&rules, "# empty\n").unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            format!("[core]\nexcludesFile = {}\n", git_config_path(&rules)),
        )
        .unwrap();
        receipt_update(&cache);
        assert_eq!(
            cache.walk_count(),
            3,
            "creating the origin config invalidates an unset key"
        );
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_ok()
        );
        std::fs::write(&rules, "visible.rs\n").unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 4);
        std::fs::write(
            home.join(".gitconfig"),
            "[core]\nexcludesFile = nonexistent\n",
        )
        .unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 5);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: nested repository ignore inputs were silently certified"
    )]
    fn ignore_receipt_nested_repository_is_uncertified() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        git2::Repository::init(root.join("nested")).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        std::fs::write(root.join("nested/file.rs"), "fn f() {}\n").unwrap();
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        {
            age_ignore_test_inputs(cache.root());
            cache.files().unwrap()
        };
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_err()
        );
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: an unreadable ignore input was mistaken for an absent candidate"
    )]
    fn ignore_receipt_unreadable_input_is_not_absent() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        std::os::unix::fs::symlink("missing-rules", root.join(".gitignore")).unwrap();
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        {
            age_ignore_test_inputs(cache.root());
            cache.files().unwrap()
        };
        let slot = cache.cached.lock().unwrap();
        assert_eq!(
            slot.as_ref()
                .unwrap()
                .ignore_inputs
                .as_ref()
                .unwrap_err()
                .cause
                .kind(),
            io::ErrorKind::NotFound
        );
        drop(slot);
        receipt_update(&cache);
        receipt_update(&cache);
        assert_eq!(
            cache.walk_count(),
            3,
            "unreadable input has no receipt and retries on each update"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: included config origins and absent include candidates escaped stat validation"
    )]
    fn ignore_receipt_included_config_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        std::fs::write(home.join(".gitconfig"), "[include]\npath = extra-config\n").unwrap();
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        {
            age_ignore_test_inputs(cache.root());
            cache.files().unwrap()
        };
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_ok()
        );
        std::fs::write(
            home.join("extra-config"),
            "[core]\nexcludesFile = nonexistent\n",
        )
        .unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
        std::fs::write(
            home.join("extra-config"),
            "[core]\nexcludesFile = other-nonexistent\n",
        )
        .unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 3);
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 3);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: subtree listings stat-ed relative excludes against the workspace instead of Git workdir"
    )]
    fn ignore_receipt_subtree_relative_global_excludes() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        let repo = git2::Repository::init(&root).unwrap();
        let subtree = root.join("subtree");
        std::fs::create_dir_all(&subtree).unwrap();
        std::fs::write(subtree.join("visible.rs"), "fn f() {}\n").unwrap();
        std::fs::write(subtree.join("anchor.txt"), "keep Git listing nonempty\n").unwrap();
        std::fs::write(root.join("local-ignore"), "# initially visible\n").unwrap();
        repo.config()
            .unwrap()
            .set_str("core.excludesFile", "local-ignore")
            .unwrap();
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(subtree.clone());
        assert!(
            cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&subtree, "visible.rs"))
        );
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_ok()
        );
        std::fs::write(root.join("local-ignore"), "visible.rs\n").unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
        assert!(
            !cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&subtree, "visible.rs"))
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: a rule changed after Git read it was certified with its new stat identity"
    )]
    fn ignore_receipt_enumeration_race_retries_next_update() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        std::fs::write(root.join("anchor.txt"), "anchor\n").unwrap();
        std::fs::write(root.join(".gitignore"), "# visible\n").unwrap();
        age_ignore_test_inputs(&root);
        let rule = root.join(".gitignore");
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::write(rule, "visible.rs\n").unwrap();
            }))
        });
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        assert!(
            cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&root, "visible.rs"))
        );
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_err()
        );
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
        assert!(
            !cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&root, "visible.rs"))
        );
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: mtime-preserving rule writes escaped receipt validation"
    )]
    fn ignore_receipt_preserved_mtime_write_invalidates() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}").unwrap();
        let rule = root.join(".gitignore");
        std::fs::write(&rule, "#visible.rs\n").unwrap();
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        cache.files().unwrap();
        let old = std::fs::metadata(&rule).unwrap().modified().unwrap();
        std::fs::write(&rule, "visible.rs \n").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(rule)
            .unwrap()
            .set_modified(old)
            .unwrap();
        cache.revalidate_symlink_omissions(&BTreeSet::new());
        assert!(
            !cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&root, "visible.rs"))
        );
        assert_eq!(cache.walk_count(), 2);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: an exclude deleted before capture appeared absent twice and certified stale membership"
    )]
    fn ignore_receipt_deleted_exclude_during_enumeration_retries() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        let repo = git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("hidden.rs"), "fn f() {}\n").unwrap();
        std::fs::write(root.join("anchor.txt"), "anchor\n").unwrap();
        let exclude = repo.commondir().join("info/exclude");
        std::fs::write(&exclude, "hidden.rs\n").unwrap();
        age_ignore_test_inputs(&root);
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(exclude).unwrap();
            }));
        });
        let cache = WorkspaceFileListingCache::new(root.clone());
        assert!(
            !cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&root, "hidden.rs"))
        );
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_err()
        );
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
        assert!(
            cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&root, "hidden.rs"))
        );
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_ok()
        );
        // Unrelated churn after capture is not part of receipt validation.
        std::fs::write(root.join(".git/info/unrelated"), "churn").unwrap();
        cache.revalidate_symlink_omissions(&BTreeSet::new());
        cache.files().unwrap();
        assert_eq!(cache.walk_count(), 2);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: creating an absent system config could change excludes without invalidating the listing"
    )]
    fn ignore_receipt_system_config_creation_invalidates() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        std::fs::write(root.join("anchor.txt"), "anchor\n").unwrap();
        let rules = home.join("system-ignore");
        std::fs::write(&rules, "visible.rs\n").unwrap();
        age_ignore_test_inputs(&root);
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        cache.files().unwrap();
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_ok()
        );
        std::fs::write(
            home.join("system-config"),
            format!("[core]\nexcludesFile = {}\n", git_config_path(&rules)),
        )
        .unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
        assert!(
            !cache
                .files()
                .unwrap()
                .contains(&ProjectFile::new(&root, "visible.rs"))
        );
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: lossy non-UTF-8 ignored directory names produced a falsely complete census"
    )]
    fn ignore_receipt_non_utf8_ignored_directory_is_uncertified() {
        use std::os::unix::ffi::OsStringExt;
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        let directory = root.join(std::ffi::OsString::from_vec(b"dir-\xff".to_vec()));
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            // APFS refuses non-UTF-8 names with EILSEQ (#10379). Such a
            // filesystem cannot hold the name this test needs, so nothing
            // remains to check there.
            Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => return,
            Err(error) => panic!("non-UTF-8 directory: {error:?}"),
        }
        std::fs::write(directory.join("hidden.tmp"), "hidden").unwrap();
        std::fs::write(root.join(".gitignore"), "*.tmp\n").unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        age_ignore_test_inputs(&root);
        age_ignore_test_inputs(&root);
        let cache = WorkspaceFileListingCache::new(root.clone());
        cache.files().unwrap();
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_err()
        );
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 2);
    }

    // nextest isolates each test in a process; these variables are restored
    // before the temporary home is removed. Never invoke git config --global.

    fn capture_with_pre_known_change(
        change: impl FnOnce(PathBuf) + 'static,
    ) -> WorkspaceFileListing {
        let temp = tempfile::tempdir().unwrap();
        // Symlinked temp roots (macOS /var) keep the parent proxy by design.
        // Normalize the canonical root: on Windows it is verbatim (`\\?\C:\`),
        // and Git for Windows cannot open HOME or GIT_CONFIG_* paths with
        // that prefix, so git status fails before the capture is observed.
        let home = temp.path().canonicalize().unwrap().normalize().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        write_file(&root, "visible.rs", "fn f() {}\n");
        write_file(&home, "system-config", "");
        write_file(&home, "ignore", "*.tmp\n");
        write_file(
            &home,
            ".gitconfig",
            &format!(
                "[core]\nexcludesFile = {}\n",
                git_config_path(&home.join("ignore"))
            ),
        );
        age_ignore_test_inputs(&root);
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || change(home)));
        });
        collect_workspace_listing(&root).unwrap()
    }

    fn quiet_proxy_test_directory(case: &str) -> TempDir {
        // Certification needs stable ancestors too. Parallel tests churn the
        // default temp directory; use the existing quiet receipt-test tree.
        #[cfg(unix)]
        let base = PathBuf::from("/var/tmp/bifrost-ignore-receipt-tests/13309");
        #[cfg(windows)]
        let base = std::env::temp_dir()
            .parent()
            .expect("temporary directory has a parent")
            .join("bifrost-ignore-receipt-tests/13309");
        // Initialize every case before any capture so another case starting
        // does not change an ancestor shared with an active walk.
        for name in [
            "recent-parent",
            "parent-churn",
            "ancestor-change",
            "restored-mtime",
            "transient-rule",
            "harmless-rule",
        ] {
            std::fs::create_dir_all(base.join(name)).unwrap();
        }
        tempfile::Builder::new()
            .prefix("bifrost-receipt-test-")
            .tempdir_in(base.join(case))
            .unwrap()
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13309: churn in a workspace's parent directory refused the ignore-input receipt and printed to stderr"
    )]
    fn ignore_receipt_recent_stable_parent_certifies() {
        let temp = quiet_proxy_test_directory("recent-parent");
        let parent = temp.path().canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&parent.join("home"));
        let root = parent.join("workspace");
        write_file(&root, "visible.rs", "fn f() {}\n");
        age_ignore_test_inputs(&root);
        // Churn ends immediately before the pre-walk sample: recent is safe
        // when stable, whereas the previous two-second cutoff refused this.
        let sibling = parent.join("sibling");
        std::thread::spawn(move || {
            for _ in 0..100 {
                std::fs::write(&sibling, "churn").unwrap();
                std::fs::remove_file(&sibling).unwrap();
            }
        })
        .join()
        .unwrap();
        let modified = std::fs::metadata(&parent).unwrap().modified().unwrap();
        assert!(modified.elapsed().unwrap() < Duration::from_secs(2));
        let listing = collect_workspace_files_with_omissions(&root).unwrap();
        assert!(listing.ignore_inputs.is_ok(), "{:?}", listing.ignore_inputs);
    }

    #[test]
    fn ignore_receipt_parent_churn_during_capture_is_typed_refusal() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let temp = quiet_proxy_test_directory("parent-churn");
        let parent = temp.path().canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&parent.join("home"));
        let root = parent.join("workspace");
        write_file(&root, "visible.rs", "fn f() {}\n");
        age_ignore_test_inputs(&root);
        let stop = Arc::new(AtomicBool::new(false));
        let cycles = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_cycles = Arc::clone(&cycles);
        let sibling = parent.join("sibling");
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                std::fs::write(&sibling, "churn").unwrap();
                std::fs::remove_file(&sibling).unwrap();
                worker_cycles.fetch_add(1, Ordering::SeqCst);
            }
        });
        while cycles.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let before = cycles.load(Ordering::SeqCst);
                // Cross even coarse timestamp ticks after the pre-walk sample.
                std::thread::sleep(Duration::from_millis(2100));
                assert!(cycles.load(Ordering::SeqCst) > before);
            }));
        });
        let result = collect_workspace_files_with_omissions(&root);
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        let listing = result.unwrap();
        let error = listing.ignore_inputs.unwrap_err();
        assert_eq!(error.operation, IgnoreObservationOperation::Listing);
        assert!(
            error
                .to_string()
                .contains("directory changed during capture"),
            "{error}"
        );
    }

    fn capture_transient_ancestor_rule(case: &str, rule: &'static str) -> WorkspaceFileListing {
        let temp = quiet_proxy_test_directory(case);
        let parent = temp.path().canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&parent.join("home"));
        let root = parent.join("workspace");
        write_file(&root, "visible.rs", "fn f() {}\n");
        age_ignore_test_inputs(&root);
        // The proxy is recent, yet the original candidate sample sees absence.
        let sibling = parent.join("recent-churn");
        std::fs::write(&sibling, "churn").unwrap();
        std::fs::remove_file(sibling).unwrap();
        let modified =
            filetime::FileTime::from_last_modification_time(&std::fs::metadata(&parent).unwrap());
        let _coarse_tick = ignore_inputs::coarse_proxy_for_test(&parent);
        let ignore = parent.join(".gitignore");
        let delete_ignore = ignore.clone();
        AFTER_WALK_IGNORE_INPUT_SAMPLE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // Built-in .ignore is disabled; .gitignore is an applied
                // ancestor source in the product's require_git(false) walk.
                std::fs::write(ignore, rule).unwrap();
            }));
        });
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(delete_ignore).unwrap();
                filetime::set_file_mtime(parent, modified).unwrap();
            }));
        });
        collect_workspace_files_with_omissions(&root).unwrap()
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13309: a transient ancestor ignore rule read during capture was certified on a coarse-ctime filesystem"
    )]
    fn ignore_receipt_transient_ancestor_rule_returns_second_listing_uncertified() {
        let listing = capture_transient_ancestor_rule("transient-rule", "visible.rs\n");
        assert!(
            listing
                .files
                .iter()
                .any(|file| file.rel_path() == Path::new("visible.rs"))
        );
        let error = listing.ignore_inputs.unwrap_err();
        assert_eq!(error.operation, IgnoreObservationOperation::Listing);
        assert!(
            error.to_string().contains("changed during confirmation"),
            "{error}"
        );
    }

    #[test]
    fn ignore_receipt_harmless_transient_ancestor_rule_can_certify() {
        let listing = capture_transient_ancestor_rule("harmless-rule", "does-not-exist\n");
        assert!(
            listing
                .files
                .iter()
                .any(|file| file.rel_path() == Path::new("visible.rs"))
        );
        assert!(listing.ignore_inputs.is_ok(), "{:?}", listing.ignore_inputs);
    }

    #[test]
    fn ignore_receipt_ancestor_ignore_created_deleted_during_walk_refuses() {
        let temp = quiet_proxy_test_directory("ancestor-change");
        let parent = temp.path().canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&parent.join("home"));
        let root = parent.join("workspace");
        write_file(&root, "visible.rs", "fn f() {}\n");
        age_ignore_test_inputs(&root);
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // The hook is between the pre-walk sample and finish.
                std::thread::sleep(Duration::from_millis(2100));
                let ignore = parent.join(".ignore");
                std::fs::write(&ignore, "*.rs\n").unwrap();
                std::fs::remove_file(ignore).unwrap();
            }));
        });
        assert!(
            collect_workspace_files_with_omissions(&root)
                .unwrap()
                .ignore_inputs
                .is_err()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13309: a same-tick candidate creation hidden by an unchanged proxy mtime must still invalidate"
    )]
    fn ignore_receipt_candidate_creation_with_restored_proxy_mtime_invalidates() {
        let temp = quiet_proxy_test_directory("restored-mtime");
        let parent = temp.path().canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&parent.join("home"));
        let root = parent.join("workspace");
        write_file(&root, "visible.rs", "fn f() {}\n");
        age_ignore_test_inputs(&root);
        let receipt = collect_workspace_files_with_omissions(&root)
            .unwrap()
            .ignore_inputs
            .unwrap();
        let before =
            filetime::FileTime::from_last_modification_time(&std::fs::metadata(&parent).unwrap());
        std::fs::write(parent.join(".ignore"), "*.rs\n").unwrap();
        filetime::set_file_mtime(&parent, before).unwrap();
        assert_eq!(
            filetime::FileTime::from_last_modification_time(&std::fs::metadata(&parent).unwrap()),
            before
        );
        assert!(!receipt.valid().unwrap());
    }

    #[test]
    fn ignore_receipt_pre_known_config_modified_during_capture() {
        let listing = capture_with_pre_known_change(|home| {
            std::fs::write(home.join(".gitconfig"), "[core]\nexcludesFile = other\n").unwrap();
        });
        assert!(listing.ignore_inputs.is_err());
    }

    #[test]
    fn ignore_receipt_pre_known_config_replaced_during_capture() {
        let listing = capture_with_pre_known_change(|home| {
            let config = home.join(".gitconfig");
            std::fs::copy(&config, home.join("replacement")).unwrap();
            std::fs::rename(home.join("replacement"), config).unwrap();
        });
        assert!(listing.ignore_inputs.is_err());
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: a symlinked config redirected and restored during capture was certified"
    )]
    fn ignore_receipt_symlinked_config_redirected_during_capture() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        write_file(&root, "visible.rs", "fn f() {}\n");
        write_file(&home, "system-config", "");
        write_file(&home, "ignore", "*.tmp\n");
        write_file(
            &home,
            "real-config",
            &format!(
                "[core]\nexcludesFile = {}\n",
                git_config_path(&home.join("ignore"))
            ),
        );
        write_file(&home, "other-config", "[core]\nexcludesFile = other\n");
        let config = home.join(".gitconfig");
        std::os::unix::fs::symlink(home.join("real-config"), &config).unwrap();
        age_ignore_test_inputs(&root);
        // Redirect the link and restore it after the reader ran: the final
        // file's identity is unchanged, so only the link's directory shows it.
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&config).unwrap();
                std::os::unix::fs::symlink(home.join("other-config"), &config).unwrap();
                std::fs::remove_file(&config).unwrap();
                std::os::unix::fs::symlink(home.join("real-config"), &config).unwrap();
            }));
        });
        let listing = collect_workspace_listing(&root).unwrap();
        assert!(listing.ignore_inputs.is_err());
    }

    #[test]
    fn ignore_receipt_pre_known_config_renamed_aside_and_back_during_capture() {
        // The original inode returns, but rename moves its ctime, which the
        // identity compares.
        let listing = capture_with_pre_known_change(|home| {
            let config = home.join(".gitconfig");
            std::fs::rename(&config, home.join("aside")).unwrap();
            std::fs::write(&config, "[core]\nexcludesFile = other\n").unwrap();
            std::fs::rename(home.join("aside"), &config).unwrap();
        });
        assert!(listing.ignore_inputs.is_err());
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: an excludes file reached through a redirected ancestor symlink was certified"
    )]
    fn ignore_receipt_ancestor_symlink_redirected_during_capture() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        write_file(&root, "visible.rs", "fn f() {}\n");
        write_file(&home, "system-config", "");
        write_file(&home.join("real"), "ignore", "*.tmp\n");
        write_file(&home.join("other"), "ignore", "*.rs\n");
        let links = home.join("links");
        std::os::unix::fs::symlink(home.join("real"), &links).unwrap();
        write_file(
            &home,
            ".gitconfig",
            &format!(
                "[core]\nexcludesFile = {}\n",
                git_config_path(&links.join("ignore"))
            ),
        );
        age_ignore_test_inputs(&root);
        // Only HOME, which contains the link, shows the redirect; the input's
        // own parent resolves to the unchanged target directory.
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&links).unwrap();
                std::os::unix::fs::symlink(home.join("other"), &links).unwrap();
                std::fs::remove_file(&links).unwrap();
                std::os::unix::fs::symlink(home.join("real"), &links).unwrap();
            }));
        });
        let listing = collect_workspace_listing(&root).unwrap();
        assert!(listing.ignore_inputs.is_err());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#12752: HOME churn made every receipt capture Unknown")]
    fn ignore_receipt_pre_known_config_survives_home_churn() {
        let listing = capture_with_pre_known_change(|home| {
            std::fs::write(home.join("unrelated"), "churn").unwrap();
            std::fs::write(home.join("unrelated"), "more churn").unwrap();
        });
        assert!(listing.ignore_inputs.is_ok(), "{:?}", listing.ignore_inputs);
    }

    #[test]
    fn ignore_receipt_absent_pre_known_config_created_read_deleted_during_capture() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        write_file(&root, "visible.rs", "fn f() {}\n");
        age_ignore_test_inputs(&root);
        BEFORE_IGNORE_INPUT_CAPTURE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let config = home.join(".gitconfig");
                std::fs::write(&config, "[core]\nexcludesFile = ignore\n").unwrap();
                assert!(!std::fs::read(&config).unwrap().is_empty());
                std::fs::remove_file(config).unwrap();
            }));
        });
        assert!(
            collect_workspace_listing(&root)
                .unwrap()
                .ignore_inputs
                .is_err()
        );
    }

    #[cfg(unix)]
    fn refill_until_ignore_receipt_certified(cache: &Arc<WorkspaceFileListingCache>) {
        let project =
            FilesystemProject::with_cached_listing(cache.root(), Arc::clone(cache)).unwrap();
        for attempt in 1..=5 {
            cache.invalidate();
            cache.listing().unwrap();
            match project.retained_ignore_observation() {
                RetainedIgnoreObservation::Ok => return,
                RetainedIgnoreObservation::Failed(cause) => {
                    assert!(
                        attempt < 5,
                        "ignore receipt never certified after {attempt} fills: {cause}"
                    );
                }
                observation => panic!("filled listing has no ignore receipt: {observation:?}"),
            }
            // #13114: absent ancestor inputs still use shared directory mtimes.
            // Let sibling activity age beyond the receipt's two-second window.
            std::thread::sleep(Duration::from_millis(2100));
        }
    }

    /// Spell `path` as a quoted Git config value. Git and libgit2 read a
    /// backslash in a value as an escape and reject `\U`, so an unquoted
    /// Windows path makes the whole config file unparseable.
    fn git_config_path(path: &Path) -> String {
        let path = path.to_str().expect("test paths are UTF-8");
        format!("\"{}\"", path.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn receipt_update(cache: &WorkspaceFileListingCache) {
        age_ignore_test_inputs(cache.root());
        cache.revalidate_symlink_omissions(&BTreeSet::new());
        cache.files().unwrap();
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: ignore rule edits without watcher events retained stale membership"
    )]
    fn ignore_receipt_git_inputs_edit_create_delete() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        let repo = git2::Repository::init(&root).unwrap();
        std::fs::create_dir_all(root.join("nested/deep")).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        std::fs::write(root.join("nested/deep/hide.rs"), "fn f() {}\n").unwrap();
        let global = temp.path().join("global-ignore");
        repo.config()
            .unwrap()
            .set_str("core.excludesFile", global.to_str().unwrap())
            .unwrap();
        let cache = WorkspaceFileListingCache::new(root.clone());
        for input in [
            root.join(".gitignore"),
            root.join("nested/.gitignore"),
            repo.path().join("info/exclude"),
            global,
        ] {
            if input.exists() {
                std::fs::remove_file(&input).unwrap();
            }
            cache.invalidate();
            age_ignore_test_inputs(cache.root());
            cache.files().unwrap();
            assert!(
                cache
                    .cached
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .ignore_inputs
                    .is_ok()
            );
            let walks = cache.walk_count();
            std::fs::write(&input, "hide.rs\n").unwrap();
            receipt_update(&cache);
            assert_eq!(cache.walk_count(), walks + 1, "create {}", input.display());
            std::fs::write(&input, "# reveal all files again\n").unwrap();
            receipt_update(&cache);
            assert_eq!(cache.walk_count(), walks + 2, "edit {}", input.display());
            std::fs::remove_file(&input).unwrap();
            receipt_update(&cache);
            assert_eq!(cache.walk_count(), walks + 3, "delete {}", input.display());
            receipt_update(&cache);
            assert_eq!(cache.walk_count(), walks + 3, "plain update");
        }
        let walks = cache.walk_count();
        repo.config()
            .unwrap()
            .set_str(
                "core.excludesFile",
                temp.path().join("different-ignore").to_str().unwrap(),
            )
            .unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), walks + 1, "origin config edit");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: ignored nested rule files and intermediate absent candidates escaped the census"
    )]
    fn ignore_receipt_ignored_rules_and_intermediate_ancestors() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        git2::Repository::init(&root).unwrap();
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::create_dir_all(root.join("middle/deep")).unwrap();
        std::fs::create_dir_all(root.join("excluded")).unwrap();
        std::fs::write(root.join(".gitignore"), ".gitignore\nexcluded/\n").unwrap();
        std::fs::write(root.join("nested/.gitignore"), "*.tmp\n").unwrap();
        std::fs::write(root.join("nested/hidden.tmp"), "hidden").unwrap();
        std::fs::write(root.join("middle/deep/visible.rs"), "fn f() {}\n").unwrap();
        std::fs::write(root.join("excluded/hidden.rs"), "hidden").unwrap();
        let cache = WorkspaceFileListingCache::new(root.clone());
        age_ignore_test_inputs(cache.root());
        let files = cache.files().unwrap();
        assert_eq!(
            files.len(),
            1,
            "ignored entries never become members: {files:?}"
        );
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_ok()
        );
        let walks = cache.walk_count();
        std::fs::write(root.join("excluded/.gitignore"), "*\n").unwrap();
        receipt_update(&cache);
        assert_eq!(
            cache.walk_count(),
            walks,
            "rules below collapsed ignored directory are not applied"
        );
        std::fs::write(root.join("nested/.gitignore"), "*.tmp\n# changed\n").unwrap();
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), walks + 1);
        std::fs::write(root.join("middle/.gitignore"), "*.rs\n").unwrap();
        receipt_update(&cache);
        assert_eq!(
            cache.walk_count(),
            walks + 2,
            "intermediate ancestor has no direct files"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: submodule ignore inputs were certified without an enumerable scope"
    )]
    fn ignore_receipt_submodule_has_no_receipt_and_relists() {
        let temp = tempfile::tempdir().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let root = temp.path().join("repo");
        let repo = git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("visible.rs"), "fn f() {}\n").unwrap();
        let mut index = repo.index().unwrap();
        index
            .add(&git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: 0o160000,
                uid: 0,
                gid: 0,
                file_size: 0,
                id: git2::Oid::from_str("1111111111111111111111111111111111111111").unwrap(),
                flags: 0,
                flags_extended: 0,
                path: b"submodule".to_vec(),
            })
            .unwrap();
        index.write().unwrap();
        let cache = WorkspaceFileListingCache::new(root.clone());
        age_ignore_test_inputs(cache.root());
        cache.files().unwrap();
        assert!(
            cache
                .cached
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ignore_inputs
                .is_err()
        );
        receipt_update(&cache);
        receipt_update(&cache);
        assert_eq!(cache.walk_count(), 3);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: fallback directory ignore candidates were not validated on explicit updates"
    )]
    fn ignore_receipt_walk_inputs_and_global_default() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let _env = IgnoreTestEnvironment::new(&home);
        let root = temp.path().join("tree");
        std::fs::create_dir_all(root.join("middle/deep")).unwrap();
        std::fs::write(root.join("middle/deep/visible.rs"), "fn f() {}\n").unwrap();
        let cache = WorkspaceFileListingCache::new(root.clone());
        age_ignore_test_inputs(cache.root());
        cache.files().unwrap();
        for (n, input) in [
            root.join("middle/.gitignore"),
            root.join("middle/.ignore"),
            home.join("xdg/git/ignore"),
        ]
        .into_iter()
        .enumerate()
        {
            std::fs::write(input, "# candidate created\n").unwrap();
            receipt_update(&cache);
            assert_eq!(cache.walk_count(), n + 2);
        }
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12889: ignored broken links emitted omissions while target ignores hid visible links"
    )]
    fn ignore_receipt_broken_link_own_path_suppresses_omission() {
        let temp = tempfile::tempdir().unwrap();
        let temp_root = temp.path().canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp_root.join("home"));
        let root = temp_root.join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".bifrostignore"), "hidden-link\nignored/\n").unwrap();
        std::os::unix::fs::symlink("missing", root.join("hidden-link")).unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let (files, omissions) = project.all_files_with_omissions().unwrap();
        assert!(omissions.is_empty(), "{omissions:?}");
        assert!(
            super::super::project_reads::file_set_receipt(&project, &files)
                .unwrap()
                .incomplete
                .is_none()
        );
        std::os::unix::fs::symlink("ignored/missing", root.join("visible-link")).unwrap();
        cache.invalidate();
        let (_, omissions) = project.all_files_with_omissions().unwrap();
        assert_eq!(omissions.len(), 1);
        assert_eq!(omissions[0].path, Path::new("visible-link"));
        assert_eq!(
            omissions[0].reason,
            WorkspaceFileOmissionReason::UnreadableSymlink
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12889: receipt construction reacquired the matcher for every file"
    )]
    fn ignore_receipt_bulk_acquires_once_without_walking() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for n in 0..128 {
            std::fs::write(root.join(format!("file{n}.rs")), "fn f() {}\n").unwrap();
        }
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let files = cache.files().unwrap();
        let walks = cache.walk_count();
        let acquisitions = MATCHER_ACQUISITIONS.with(std::cell::Cell::get);
        let receipt = super::super::project_reads::file_set_receipt(&project, &files).unwrap();
        assert!(receipt.listing.is_some());
        assert_eq!(
            MATCHER_ACQUISITIONS.with(std::cell::Cell::get) - acquisitions,
            1
        );
        assert_eq!(cache.walk_count(), walks);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12752: retained ignore failures could not be inspected without refreshing"
    )]
    fn ignore_receipt_retained_failure_never_walks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        std::fs::write(root.join(".bifrostignore"), "[z-a]\n").unwrap();
        project.invalidate_cached_file_listing();
        assert!(project.is_bifrostignored(Path::new("a.rs")).is_err());
        let walks = cache.walk_count();
        for _ in 0..3 {
            let RetainedIgnoreObservation::Failed(cause) = project.retained_ignore_observation()
            else {
                panic!("missing retained failure")
            };
            assert_eq!(cause.operation, IgnoreObservationOperation::Matcher);
            assert!(!cause.cause.to_string().is_empty());
        }
        assert_eq!(cache.walk_count(), walks);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12889: failed matcher acquisition retried and logged for every path"
    )]
    fn ignore_receipt_failure_logs_once_per_generation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("a.rs"), "fn a() {}\n").unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        std::fs::write(root.join(".bifrostignore"), "[z-a]\n").unwrap();
        let before = IGNORE_FAILURE_LOGS.with(std::cell::Cell::get);
        for generation in 1..=2 {
            project.invalidate_cached_file_listing();
            for _ in 0..8 {
                assert!(project.is_bifrostignored(Path::new("a.rs")).is_err());
            }
            assert_eq!(
                IGNORE_FAILURE_LOGS.with(std::cell::Cell::get) - before,
                generation
            );
        }
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn retention_census_does_not_populate_a_cold_workspace_listing() {
        let root = tempfile::tempdir().unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.path().to_path_buf()));
        let mut census = crate::retention_census::RetentionCensus::new();
        cache.retention_census_for_test(&mut census);
        let report = census.finish();
        assert_eq!(cache.walks.load(Ordering::Relaxed), 0);
        assert!(cache.cached.lock().unwrap().is_none());
        assert_eq!(report.resident_readings[0].count, 0);
        assert!(
            !report
                .allocation_groups
                .iter()
                .any(|group| group.kind == Some("workspace_listing_file_set_header"))
        );
    }

    use super::*;
    use crate::test_support::write_file;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11129: a case-insensitive update alias became a second selected file"
    )]
    fn listing_update_path_distinguishes_alias_from_new_entry() {
        struct View(TestProject);
        impl Project for View {
            fn root(&self) -> &Path {
                self.0.root()
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
            fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
                self.0.file_by_rel_path(path)
            }
            fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
                self.0.read_source(file)
            }
            fn directory_entries(&self, parent: &Path) -> io::Result<BTreeSet<ProjectFile>> {
                Ok(self
                    .0
                    .directory_entries(parent)?
                    .into_iter()
                    .filter(|file| file.rel_path() != Path::new("Foo.rs"))
                    .collect())
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("foo.RS"), "before").unwrap();
        let cache = WorkspaceFileListingCache::new(root.clone());
        cache.files().unwrap();
        if !root.join("Foo.rs").exists() {
            std::fs::hard_link(root.join("foo.RS"), root.join("Foo.rs")).unwrap();
        }
        let alias = ProjectFile::new(&root, "Foo.rs");
        assert!(cache.update_path_in(&View(TestProject::new(&root, Language::None)), &alias, true));
        assert!(!cache.files().unwrap().contains(&alias));
        let added = ProjectFile::new(&root, "new.rs");
        std::fs::write(added.abs_path(), "new").unwrap();
        assert!(cache.update_path(&added, true));
        assert!(cache.files().unwrap().contains(&added));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9737: the default listing silently certified unknown omissions"
    )]
    fn default_listing_reports_unknown_omissions() {
        // TestProject certifies its listing through the shared collector, so
        // a project that keeps the trait's default listing wraps it.
        struct DefaultListingProject(TestProject);
        impl Project for DefaultListingProject {
            fn root(&self) -> &Path {
                self.0.root()
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
            fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
                self.0.file_by_rel_path(path)
            }
        }
        let temp = TempDir::new().unwrap();
        let project = DefaultListingProject(TestProject::new(temp.path(), Language::Rust));
        let (_, omissions) = project.all_files_with_omissions().unwrap();
        assert_eq!(omissions.len(), 1);
        assert_eq!(omissions[0].reason, WorkspaceFileOmissionReason::Unknown);
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon("#9737: multi-root listings dropped symlink omissions")]
    fn multi_root_listing_forwards_omissions() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        write_file(&first, "source.rs", "fn source() {}\n");
        std::os::unix::fs::symlink(first.join("source.rs"), first.join("linked.rs")).unwrap();
        let project = MultiRootProject::new([first, second]).unwrap();
        let (_, omissions) = project.all_files_with_omissions().unwrap();
        assert!(omissions.iter().any(|omission| {
            omission.path == Path::new("first/linked.rs")
                && omission.reason == WorkspaceFileOmissionReason::Symlink
        }));
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10321: a multi-root project never rechecked its children's symlinks after a target-only change"
    )]
    fn multi_root_revalidation_reaches_the_child_that_owns_the_changed_target() {
        // #13114: non-git walks still proxy absent ancestor inputs. Keep
        // these roots off the busy default temporary directory.
        let quiet_parent = Path::new("/var/tmp/bifrost-ignore-receipt-tests");
        // Initialize both stable parents before capture to reduce sibling
        // churn. Certification retries below handle shared ancestor activity.
        for name in ["multi-root", "symlinks"] {
            std::fs::create_dir_all(quiet_parent.join(name)).unwrap();
        }
        let temp = TempDir::new_in(quiet_parent.join("multi-root")).unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let mut children = Vec::new();
        let mut caches = Vec::new();
        for name in ["first", "second"] {
            let child = root.join(name);
            write_file(&child, "target.txt", "target\n");
            std::os::unix::fs::symlink("target.txt", child.join("link.txt")).unwrap();
            let cache = Arc::new(WorkspaceFileListingCache::new(child.clone()));
            cache.listing().unwrap();
            children
                .push(FilesystemProject::with_cached_listing(&child, Arc::clone(&cache)).unwrap());
            caches.push(cache);
        }
        let project = MultiRootProject {
            project_reads: ProjectReadSlot::default(),
            root: root.clone(),
            roots: children,
            languages: BTreeSet::new(),
            persistence_dir: None,
        };

        // Allow the discovered inputs and absent ancestor proxies to age.
        age_ignore_test_inputs(&root);
        for cache in &caches {
            refill_until_ignore_receipt_certified(cache);
        }

        // The changed path is named from the common root; the second child
        // and a path under no child are not affected by it.
        std::fs::remove_file(root.join("first/target.txt")).unwrap();
        project.revalidate_symlink_omissions(
            &[
                ProjectFile::new(&root, "first/target.txt"),
                ProjectFile::new(&root, "elsewhere/other.txt"),
            ]
            .into(),
        );
        assert!(
            caches[0].cached_listing().is_none(),
            "a deleted target must invalidate its child's listing"
        );
        assert!(
            caches[1].cached_listing().is_some(),
            "a change under the first child must not touch the second"
        );
    }

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

    #[test]
    fn file_set_constructors_state_what_their_listing_omits() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let omissions = |project: &FileSetProject| {
            project
                .all_files_with_omissions()
                .unwrap()
                .1
                .iter()
                .map(|omission| omission.reason)
                .collect::<Vec<_>>()
        };
        let files = || ["a.ts"].map(PathBuf::from);
        // A subset fails closed: it cannot show what the rest of the workspace holds.
        assert_eq!(
            omissions(&FileSetProject::new(&root, files())),
            [WorkspaceFileOmissionReason::Unknown]
        );
        // An authoritative listing states its own.
        let linked = WorkspaceFileOmission {
            path: PathBuf::from("linked"),
            reason: WorkspaceFileOmissionReason::SymlinkToDirectory,
        };
        assert_eq!(
            omissions(&FileSetProject::from_listing(&root, files(), vec![linked])),
            [WorkspaceFileOmissionReason::SymlinkToDirectory]
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
            advertised: Mutex<Option<Arc<WorkspaceOverlayContent>>>,
            probe_frames: Mutex<Vec<(bool, bool)>>,
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
            // Advertises what the test sets and records the frame it is probed in.
            fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
                self.probe_frames.lock().unwrap().push((
                    crate::analyzer::project_reads::project_reads_suppressed(),
                    crate::analyzer::project_reads::project_getter_in_progress(),
                ));
                self.advertised.lock().unwrap().clone()
            }
        }

        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "Custom.java", "class Disk {}");
        let project = CustomSourceProject {
            delegate: TestProject::new(&root, Language::Java),
            reads: AtomicUsize::new(0),
            advertised: Mutex::new(None),
            probe_frames: Mutex::new(Vec::new()),
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

        // Default overlay capture of a custom project. Nothing advertised pins
        // an empty view; an advertised set it cannot pin fails closed. The
        // probe runs in a suppressed, nested read frame, and an outer read's
        // receipt survives it (the sentinel is cached in the receipt, so only a
        // wiped or replaced receipt would recompute it from the now-absent path).
        use crate::analyzer::project_reads::{WorkspacePathKind, observed_path_kind};
        let sentinel = write_file(&root, "sentinel.txt", "present").abs_path();
        assert_eq!(observed_path_kind(&sentinel), WorkspacePathKind::File);
        std::fs::remove_file(&sentinel).unwrap();
        let empty = project.capture_source_overlays().unwrap();
        assert!(empty.content().is_none() && empty.source_snapshot(&file).is_none());
        *project.advertised.lock().unwrap() = Some(Arc::new(WorkspaceOverlayContent::new([(
            file.clone(),
            [7; 32],
            Oid::hash_object(ObjectType::Blob, b"class Overlay {}").unwrap(),
        )])));
        let error = project.capture_source_overlays().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            *project.probe_frames.lock().unwrap(),
            [(true, true), (true, true)],
            "each probe is suppressed and nested, so no recorder callback can fire"
        );
        assert!(
            !crate::analyzer::project_reads::project_reads_suppressed()
                && !crate::analyzer::project_reads::project_getter_in_progress(),
            "the caller's read frame is restored"
        );
        assert_eq!(
            observed_path_kind(&sentinel),
            WorkspacePathKind::File,
            "the outer read's receipt survives the probe"
        );
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
    #[brokk_bifrost_test_macros::hardwon(
        "#10166: analyzer cache files changed the workspace inventory digest across roots"
    )]
    fn analyzer_cache_does_not_change_inventory_digest_across_roots() {
        let temp = TempDir::new().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        write_file(&first, "src/main.rs", "fn main() {}\n");
        write_file(&second, "src/main.rs", "fn main() {}\n");
        write_file(&first, ".bifrost/cache/bifrost_cache.db", "cache bytes");
        std::fs::create_dir_all(second.join(".bifrost/cache")).unwrap();
        std::fs::copy(
            first.join(".bifrost/cache/bifrost_cache.db"),
            second.join(".bifrost/cache/bifrost_cache.db"),
        )
        .unwrap();
        let first = first.canonicalize().unwrap();
        let second = second.canonicalize().unwrap();
        let first_project = FilesystemProject::new(&first).unwrap();
        let second_project = FilesystemProject::new(&second).unwrap();
        let first_files = first_project.all_files().unwrap();
        let second_files = second_project.all_files().unwrap();
        assert!(
            !first_files
                .iter()
                .any(|file| file.rel_path().starts_with(".bifrost/cache"))
        );
        assert!(
            !second_files
                .iter()
                .any(|file| file.rel_path().starts_with(".bifrost/cache"))
        );
        let first_digest =
            crate::analyzer::project_reads::file_set_receipt(&first_project, &first_files)
                .unwrap()
                .inventory;
        let second_digest =
            crate::analyzer::project_reads::file_set_receipt(&second_project, &second_files)
                .unwrap()
                .inventory;
        assert_eq!(first_digest, second_digest);
    }

    #[test]
    fn analyzer_owned_paths_keep_configuration_and_cache_siblings() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&root);
        write_file(&root, ".bifrost/policies/rule.rqlp", "rule content");
        write_file(&root, ".bifrost/cachex/main.rs", "fn main() {}");
        write_file(&root, ".bifrost/cache/db", "cache");
        crate::gitblob::test_repo::commit_all(&repo, "track project inputs");
        let files = collect_workspace_files(&root).unwrap();
        assert!(files.contains(&ProjectFile::new(&root, ".bifrost/policies/rule.rqlp")));
        assert!(files.contains(&ProjectFile::new(&root, ".bifrost/cachex/main.rs")));
        assert!(!files.contains(&ProjectFile::new(&root, ".bifrost/cache/db")));
        let override_dir = root.join("other-cache");
        let owned = AnalyzerOwnedPaths::with_cache_dir(&root, override_dir.clone());
        assert!(owned.contains(&root.join(".bifrost/cache/db")));
        assert!(owned.contains(&override_dir.join("db")));
        assert!(!owned.contains(&root.join(".bifrost/cachex/main.rs")));
        assert!(owned.contains(&root.join(".bifrost/bifrost_cache.db-wal")));
    }

    #[test]
    fn analyzer_owned_paths_exclude_symlinked_cache_directory() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let target = temp.path().join("cache-target");
        std::fs::create_dir_all(root.join(".bifrost")).unwrap();
        write_file(&target, "db", "cache");
        #[cfg(unix)]
        let link_result = std::os::unix::fs::symlink(&target, root.join(".bifrost/cache"));
        #[cfg(windows)]
        let link_result = std::os::windows::fs::symlink_dir(&target, root.join(".bifrost/cache"));
        if let Err(error) = link_result {
            if error.kind() == io::ErrorKind::PermissionDenied
                || (cfg!(windows) && error.raw_os_error() == Some(1314))
            {
                eprintln!("skipping symlink cache test: symlink permission unavailable: {error}");
                return;
            }
            panic!("cannot create cache symlink: {error}");
        }
        let root = root.canonicalize().unwrap();
        let owned = AnalyzerOwnedPaths::new(&root);
        assert!(owned.contains(&root.join(".bifrost/cache/db")));
        assert!(!owned.contains(&target.join("db")));
        assert!(collect_workspace_files(&root).unwrap().is_empty());
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

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10321: every update stat-ed every cached symlink, so its cost grew with the symlink count"
    )]
    fn symlink_revalidation_rechecks_only_links_a_change_can_affect() {
        use super::super::project_reads::measure_project_io;
        // #13114: non-git walks still proxy absent ancestor inputs. Keep
        // these roots off the busy default temporary directory.
        let quiet_parent = Path::new("/var/tmp/bifrost-ignore-receipt-tests");
        // Initialize both stable parents before capture to reduce sibling
        // churn. Certification retries below handle shared ancestor activity.
        for name in ["multi-root", "symlinks"] {
            std::fs::create_dir_all(quiet_parent.join(name)).unwrap();
        }
        let temp = TempDir::new_in(quiet_parent.join("symlinks")).unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let _env = IgnoreTestEnvironment::new(&temp.path().join("home"));
        let outside = TempDir::new().unwrap();
        write_file(&root, "unrelated.txt", "unrelated\n");
        write_file(&root, "sub/inner.txt", "inner\n");
        write_file(outside.path(), "external.txt", "external\n");
        for index in 0..20 {
            write_file(&root, &format!("targets/t{index}.txt"), "target\n");
            std::os::unix::fs::symlink(
                root.join(format!("targets/t{index}.txt")),
                root.join(format!("link{index}.txt")),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink("sub/inner.txt", root.join("deep.link")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("external.txt"),
            root.join("external.link"),
        )
        .unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        cache.listing().unwrap();
        // Allow the discovered inputs and absent ancestor proxies to age.
        age_ignore_test_inputs(&root);
        refill_until_ignore_receipt_certified(&cache);
        let changed = |paths: &[&str]| -> BTreeSet<ProjectFile> {
            paths
                .iter()
                .map(|path| ProjectFile::new(&root, *path))
                .collect()
        };
        // The rechecks, and the in-workspace links the index offered for them.
        let recheck = |paths: &[&str]| {
            let counts =
                measure_project_io(|| cache.revalidate_symlink_omissions(&changed(paths))).1;
            (counts.symlink_candidates, counts.symlink_rechecks)
        };

        // Only the link to a target outside the workspace has no event to
        // wait for, and no in-workspace link is even considered.
        assert_eq!(recheck(&["unrelated.txt"]), (0, 1), "unrelated change");
        assert!(cache.cached_listing().is_some());
        // A changed target, and a changed ancestor of a target, name their links.
        assert_eq!(recheck(&["targets/t3.txt"]), (1, 2), "changed target");
        assert_eq!(recheck(&["sub"]), (1, 2), "changed ancestor of a target");
        assert_eq!(recheck(&["link4.txt"]), (1, 2), "changed link");
        assert_eq!(
            recheck(&["targets/t3.txt", "link3.txt", "link4.txt"]),
            (2, 3),
            "a link named by two changed paths is considered once"
        );
        assert!(cache.cached_listing().is_some());

        std::fs::remove_file(root.join("targets/t3.txt")).unwrap();
        recheck(&["targets/t3.txt"]);
        assert!(
            cache.cached_listing().is_none(),
            "a deleted target must invalidate the listing"
        );
        cache.listing().unwrap();
        std::fs::remove_dir_all(root.join("sub")).unwrap();
        recheck(&["sub"]);
        assert!(
            cache.cached_listing().is_none(),
            "a removed ancestor of a target must invalidate the listing"
        );
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10321: a link resolved through another symlink kept its class after the hop changed"
    )]
    fn symlink_reached_through_another_symlink_is_rechecked_on_every_update() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "unrelated.txt", "unrelated\n");
        write_file(&root, "data.txt", "data\n");
        write_file(&root, "hops/.keep", "");
        std::os::unix::fs::symlink("../data.txt", root.join("hops/alias")).unwrap();
        std::os::unix::fs::symlink("hops/alias", root.join("chain.link")).unwrap();
        let cache = WorkspaceFileListingCache::new(root.clone());
        cache.listing().unwrap();
        // The hop may be ignored or unlisted, so its change may arrive with no
        // event on a recorded path. Only an unrelated path is reported here.
        std::fs::remove_file(root.join("hops/alias")).unwrap();
        cache.revalidate_symlink_omissions(&[ProjectFile::new(&root, "unrelated.txt")].into());
        assert!(
            cache.cached_listing().is_none(),
            "a dangling chain must invalidate the listing"
        );
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10321: a Git listing made a symlink to a FIFO an analyzable file"
    )]
    fn git_listing_keeps_a_symlink_to_a_fifo_out_of_the_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&root);
        write_file(&root, "tracked.rs", "fn tracked() {}\n");
        crate::gitblob::test_repo::commit_all(&repo, "tracked source");
        let status = std::process::Command::new("mkfifo")
            .arg(root.join("pipe"))
            .status()
            .unwrap();
        assert!(status.success());
        std::os::unix::fs::symlink("pipe", root.join("generated.rs")).unwrap();

        let listing = collect_workspace_files_with_omissions(&root).unwrap();
        let generated = ProjectFile::new(&root, "generated.rs");
        assert!(!listing.files.contains(&generated), "{:?}", listing.files);
        assert!(
            listing.omissions.iter().any(|omission| {
                omission.path == std::path::Path::new("generated.rs")
                    && omission.reason == WorkspaceFileOmissionReason::NonRegular
            }),
            "{:?}",
            listing.omissions
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

    #[cfg(unix)]
    #[test]
    fn workspace_listing_reports_symlink_without_changing_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "source.rs", "fn source() {}\n");
        std::os::unix::fs::symlink(root.join("source.rs"), root.join("linked.rs")).unwrap();

        let listing = collect_workspace_files_with_omissions(&root).unwrap();
        assert!(
            listing
                .files
                .contains(&ProjectFile::new(&root, "source.rs"))
        );
        assert!(
            !listing
                .files
                .contains(&ProjectFile::new(&root, "linked.rs"))
        );
        assert!(listing.omissions.iter().any(|omission| {
            omission.path == Path::new("linked.rs")
                && omission.reason == WorkspaceFileOmissionReason::Symlink
        }));

        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let (files, omissions) = project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);
        assert!(!files.contains(&ProjectFile::new(&root, "linked.rs")));
        assert!(omissions.iter().any(|omission| {
            omission.path == Path::new("linked.rs")
                && omission.reason == WorkspaceFileOmissionReason::Symlink
        }));
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12447: a listed file replaced by a dangling symlink was patched out as a deletion, losing its omission"
    )]
    fn listed_file_replaced_by_dangling_symlink_relists_with_its_omission() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "kept.rs", "fn kept() {}\n");
        write_file(&root, "replaced.rs", "fn replaced() {}\n");
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let mut listing = project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);

        let replaced = ProjectFile::new(&root, "replaced.rs");
        std::fs::remove_file(replaced.abs_path()).unwrap();
        std::os::unix::fs::symlink(root.join("missing.rs"), replaced.abs_path()).unwrap();
        resolve_update_paths_with_refresh(
            &project,
            &BTreeSet::from([replaced.clone()]),
            &mut listing,
            &|_| false,
        )
        .unwrap();

        assert_eq!(cache.walk_count(), 2, "a new symlink needs enumeration");
        assert!(!listing.0.contains(&replaced));
        assert!(listing.1.iter().any(|omission| {
            omission.path == Path::new("replaced.rs")
                && omission.reason == WorkspaceFileOmissionReason::UnreadableSymlink
        }));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12447: a listed file replaced by a directory stayed a member after a point update"
    )]
    fn listed_file_replaced_by_directory_relists() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "kept.rs", "fn kept() {}\n");
        write_file(&root, "replaced.rs", "fn replaced() {}\n");
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let mut listing = project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);

        let replaced = ProjectFile::new(&root, "replaced.rs");
        std::fs::remove_file(replaced.abs_path()).unwrap();
        std::fs::create_dir(replaced.abs_path()).unwrap();
        write_file(&root, "replaced.rs/nested.rs", "fn nested() {}\n");
        resolve_update_paths_with_refresh(
            &project,
            &BTreeSet::from([replaced.clone()]),
            &mut listing,
            &|_| false,
        )
        .unwrap();

        assert_eq!(
            cache.walk_count(),
            2,
            "a directory replacement needs enumeration"
        );
        assert!(!listing.0.contains(&replaced));
        assert!(
            listing
                .0
                .contains(&ProjectFile::new(&root, "replaced.rs/nested.rs"))
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12447: a directory replaced by a file aborted the update instead of removing its children"
    )]
    fn directory_replaced_by_file_patches_children_out_without_walking() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "kept.rs", "fn kept() {}\n");
        write_file(&root, "old/child.rs", "fn child() {}\n");
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let mut listing = project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);

        let child = ProjectFile::new(&root, "old/child.rs");
        let replacement = ProjectFile::new(&root, "old");
        std::fs::remove_dir_all(root.join("old")).unwrap();
        write_file(&root, "old", "now a file\n");
        resolve_update_paths_with_refresh(
            &project,
            &BTreeSet::from([child.clone(), replacement.clone()]),
            &mut listing,
            &|_| false,
        )
        .unwrap();

        assert_eq!(
            cache.walk_count(),
            1,
            "the replacement and its removed children are patched in place"
        );
        assert!(!listing.0.contains(&child));
        assert!(listing.0.contains(&replacement));
        assert!(listing.0.contains(&ProjectFile::new(&root, "kept.rs")));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12447: a directory deletion reported without its children left every former child listed"
    )]
    fn removed_directory_reported_without_children_relists() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "kept.rs", "fn kept() {}\n");
        write_file(&root, "old/child.rs", "fn child() {}\n");
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let mut listing = project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);

        let child = ProjectFile::new(&root, "old/child.rs");
        std::fs::remove_dir_all(root.join("old")).unwrap();
        resolve_update_paths_with_refresh(
            &project,
            &BTreeSet::from([ProjectFile::new(&root, "old")]),
            &mut listing,
            &|_| false,
        )
        .unwrap();

        assert_eq!(cache.walk_count(), 2, "a directory removal needs a walk");
        assert!(!listing.0.contains(&child));
    }

    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12447: deleting a directory with only an omitted symlink left its stale omission"
    )]
    fn removed_directory_with_only_omitted_symlink_relists() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "kept.rs", "fn kept() {}\n");
        std::fs::create_dir(root.join("old")).unwrap();
        std::os::unix::fs::symlink(root.join("missing.rs"), root.join("old/link.rs")).unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let mut listing = project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);
        assert!(
            listing
                .1
                .iter()
                .any(|omission| omission.path == Path::new("old/link.rs"))
        );

        std::fs::remove_dir_all(root.join("old")).unwrap();
        resolve_update_paths_with_refresh(
            &project,
            &BTreeSet::from([ProjectFile::new(&root, "old")]),
            &mut listing,
            &|_| false,
        )
        .unwrap();

        assert_eq!(
            cache.walk_count(),
            2,
            "a removed omission needs enumeration"
        );
        assert!(
            !listing
                .1
                .iter()
                .any(|omission| omission.path.starts_with("old"))
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12447: removing the last listed file under a .bifrostignore kept its rules, so the receipt differed from a fresh listing"
    )]
    fn removing_last_file_under_ignore_rules_relists() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, ".gitignore", "sub/.bifrostignore\n");
        write_file(&root, "sub/.bifrostignore", "ignored.rs\n");
        write_file(&root, "sub/a.rs", "fn a() {}\n");
        write_file(&root, "plain/b.rs", "fn b() {}\n");
        write_file(&root, "plain/c.rs", "fn c() {}\n");
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        let mut listing = project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);
        assert!(
            !listing
                .0
                .contains(&ProjectFile::new(&root, "sub/.bifrostignore"))
        );

        // A directory without rules is patched in place.
        let plain = ProjectFile::new(&root, "plain/b.rs");
        std::fs::remove_file(plain.abs_path()).unwrap();
        resolve_update_paths_with_refresh(
            &project,
            &BTreeSet::from([plain]),
            &mut listing,
            &|_| false,
        )
        .unwrap();
        assert_eq!(cache.walk_count(), 1);

        // Emptying the rule-bearing directory re-lists.
        let last = ProjectFile::new(&root, "sub/a.rs");
        std::fs::remove_file(last.abs_path()).unwrap();
        resolve_update_paths_with_refresh(
            &project,
            &BTreeSet::from([last.clone()]),
            &mut listing,
            &|_| false,
        )
        .unwrap();
        assert_eq!(cache.walk_count(), 2);
        assert!(!listing.0.contains(&last));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12447: a watcher point deletion kept ignore rules that a fresh listing drops"
    )]
    fn point_removal_of_last_file_under_ignore_rules_relists() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = crate::gitblob::test_repo::init_repo(&root);
        write_file(&root, "kept.rs", "fn kept() {}\n");
        write_file(&root, ".gitignore", "sub/.bifrostignore\n");
        write_file(&root, "sub/.bifrostignore", "ignored.rs\n");
        write_file(&root, "sub/a.rs", "fn a() {}\n");
        crate::gitblob::test_repo::commit_all(&repo, "track point removal");
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap();
        project.all_files_with_omissions().unwrap();
        assert_eq!(cache.walk_count(), 1);
        let before = project.ignore_rules_digest().unwrap();

        std::fs::remove_file(root.join("sub/a.rs")).unwrap();
        assert!(
            !project.update_cached_listing_for_path(Path::new("sub/a.rs")),
            "a point removal that empties a rule-bearing directory must re-list"
        );
        project.invalidate_cached_file_listing();
        let fresh = FilesystemProject::new(&root).unwrap();
        assert_ne!(before, fresh.ignore_rules_digest().unwrap());
        assert_eq!(
            project.ignore_rules_digest().unwrap(),
            fresh.ignore_rules_digest().unwrap()
        );
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

    fn omissions_by_path(
        omissions: &[WorkspaceFileOmission],
    ) -> Vec<(PathBuf, WorkspaceFileOmissionReason)> {
        let mut omissions: Vec<_> = omissions
            .iter()
            .map(|omission| (omission.path.clone(), omission.reason))
            .collect();
        omissions.sort_by(|left, right| left.0.cmp(&right.0));
        omissions
    }

    fn identity_of(root: &Path) -> crate::gitblob::WorkingTreeIdentity {
        crate::gitblob::working_tree_identity(&git2::Repository::open(root).unwrap()).unwrap()
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11890: a Windows verbatim identity workdir made the identity listing empty"
    )]
    fn identity_listing_matches_the_workspace_listing() {
        // The project root is the plain normalized spelling. The identity is
        // opened through the temporary directory's own spelling, which is a
        // symbolic link on macOS and canonicalizes to a verbatim `\\?\` path
        // on Windows; the two must still describe the same files.
        let temp = TempDir::new().unwrap();
        #[cfg(windows)]
        assert!(
            temp.path()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .starts_with(r"\\?\"),
            "Windows canonicalizes to a verbatim path, the spelling this test pins"
        );
        let repo = crate::gitblob::test_repo::init_repo(temp.path());
        write_file(temp.path(), "package.json", "{}\n");
        write_file(temp.path(), "package-lock.json", "{}\n");
        write_file(temp.path(), "deleted.json", "{}\n");
        write_file(temp.path(), ".gitignore", "ignored/\n");
        write_file(temp.path(), "ignored/package.json", "{}\n");
        crate::gitblob::test_repo::commit_all(&repo, "init");
        write_file(temp.path(), "package.json", "{\"changed\":true}\n");
        std::fs::remove_file(temp.path().join("deleted.json")).unwrap();
        write_file(temp.path(), "untracked.json", "{}\n");
        write_file(temp.path(), ".bifrost/cache/package.json", "{}\n");
        #[cfg(unix)]
        {
            std::fs::create_dir_all(temp.path().join("dir")).unwrap();
            std::os::unix::fs::symlink("dir", temp.path().join("dir-link")).unwrap();
            std::os::unix::fs::symlink("package.json", temp.path().join("file-link")).unwrap();
        }
        let project = FilesystemProject::new(temp.path()).unwrap();
        let identity = identity_of(temp.path());

        let assert_agrees = |context: &str| {
            let (files, omissions) = workspace_listing_from_identity(&project, &identity)
                .unwrap()
                .unwrap_or_else(|| panic!("{context}: the identity describes this root"));
            let walked = collect_workspace_files_with_omissions(project.root()).unwrap();
            assert_eq!(*files, walked.files, "{context}");
            assert_eq!(
                omissions_by_path(&omissions),
                omissions_by_path(&walked.omissions),
                "{context}"
            );
        };
        assert_agrees("at the scan");

        // A later explicit invalidation adds membership the scan cannot know
        // about, and a removed invalidated path loses it.
        write_file(temp.path(), "added.json", "{}\n");
        std::fs::remove_file(temp.path().join("untracked.json")).unwrap();
        identity.invalidate_paths(["added.json".to_owned(), "untracked.json".to_owned()]);
        assert_agrees("after invalidation");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11890: the identity listing dropped an unsaved overlay-only package.json"
    )]
    fn identity_listing_keeps_an_overlay_project_s_unsaved_buffers() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        let repo = crate::gitblob::test_repo::init_repo(&root);
        write_file(&root, "src/index.js", "export {};\n");
        write_file(&root, ".gitignore", "ignored/\n");
        write_file(&root, "ignored/package.json", "{}\n");
        crate::gitblob::test_repo::commit_all(&repo, "init");
        let overlay = OverlayProject::new(Arc::new(FilesystemProject::new(&root).unwrap()));
        // A new manifest that exists only in the editor, and a buffer over an
        // ignored file, which a buffer does not bring into the workspace.
        let unsaved = ProjectFile::new(root.clone(), "package.json");
        assert!(overlay.set(unsaved.abs_path(), "{\"name\":\"app\"}\n".to_string()));
        assert!(overlay.set(root.join("ignored/package.json"), "{}\n".to_string()));

        let (files, _) = workspace_listing_from_identity(&overlay, &identity_of(&root))
            .unwrap()
            .expect("the identity describes this root");
        assert!(files.contains(&unsaved));
        assert_eq!(files, overlay.all_files_with_omissions().unwrap().0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11890: the identity listing emptied an ignored root and widened a subset project"
    )]
    fn identity_listing_defers_to_a_project_it_cannot_describe() {
        let temp = TempDir::new().unwrap();
        let ancestor = temp.path().canonicalize().unwrap().normalize();
        let repo = crate::gitblob::test_repo::init_repo(&ancestor);
        write_file(&ancestor, ".gitignore", "workspace/\n");
        write_file(&ancestor, "tracked.rs", "fn tracked() {}\n");
        crate::gitblob::test_repo::commit_all(&repo, "init");
        write_file(&ancestor, "workspace/package.json", "{}\n");
        let identity = identity_of(&ancestor);

        // The ancestor's ignore rules hide the whole selected root, so Git
        // names nothing there; the project's listing walks the root instead.
        let ignored = FilesystemProject::new(ancestor.join("workspace")).unwrap();
        assert!(!ignored.all_files().unwrap().is_empty());
        assert!(
            workspace_listing_from_identity(&ignored, &identity)
                .unwrap()
                .is_none()
        );

        // A subset project lists its explicit files, not the worktree.
        let subset = FileSetProject::new(ancestor.clone(), [PathBuf::from("tracked.rs")]);
        assert!(
            workspace_listing_from_identity(&subset, &identity)
                .unwrap()
                .is_none()
        );
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

    #[test]
    fn authoritative_walk_sees_nested_manifest_without_cache_event() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "a.rs", "fn a() {}\n");
        let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project = FilesystemProject::with_cached_listing(&root, listing).unwrap();
        let before = project.all_files_shared().unwrap();
        let added = write_file(&root, "nested/pom.xml", "<project/>\n");
        assert!(!before.contains(&added));
        assert!(!project.all_files().unwrap().contains(&added));
        assert!(project.authoritative_files().unwrap().contains(&added));
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

        assert!(project.is_bifrostignored(Path::new("vendor/x.rs")).unwrap());
        assert_eq!(
            BTreeSet::from([kept.clone()]),
            project.analyzable_files(Language::Rust).unwrap()
        );

        write_file(&root, ".bifrostignore", "a.rs\n");
        project.invalidate_cached_file_listing();

        assert!(!project.is_bifrostignored(Path::new("vendor/x.rs")).unwrap());
        assert!(project.is_bifrostignored(Path::new("a.rs")).unwrap());
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
            assert!(
                project
                    .is_bifrostignored(Path::new("vendor/skipped.rs"))
                    .unwrap()
            );
            assert!(!project.is_bifrostignored(Path::new("kept.rs")).unwrap());
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
            .map(|rel| (*rel, project.is_bifrostignored(Path::new(rel)).unwrap()))
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
    /// single-path probe must preserve the same failure rather than classify
    /// the path as visible or ignored.
    #[test]
    #[brokk_bifrost_test_macros::hardwon("#12889: unreadable rules classified paths as visible")]
    fn ignore_receipt_unreadable_bifrostignore_fails_selection_and_classification() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        write_file(&root, "a.rs", "fn a() {}\n");
        let project = FilesystemProject::new(&root).unwrap();
        std::fs::write(root.join(BIFROST_IGNORE_FILE_NAME), b"vendor/\n\xff\xfe\n").unwrap();
        project.invalidate_cached_file_listing();
        assert!(project.is_bifrostignored(Path::new("a.rs")).is_err());
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
        assert_eq!(disk.oid(), overlay.read_file_snapshot(&file).unwrap().oid());
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
        assert_eq!(
            first.oid(),
            overlay.read_file_snapshot(&file).unwrap().oid()
        );
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
        let other = write_file(&root, "other.rs", "fn other() {}\n");
        let pinned = (&overlay as &dyn Project)
            .capture_source_overlays()
            .unwrap();
        let again = (&overlay as &dyn Project)
            .capture_source_overlays()
            .unwrap();
        assert_ne!(pinned.identity(), again.identity());
        assert_eq!(
            pinned.content().unwrap().digest(),
            snapshot.overlay_content().unwrap().digest()
        );
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

        // The pinned view kept the replaced overlay's text, revision and
        // identity, answers overlays only, and a project with none pins none.
        let captured = pinned.source_snapshot(&file).unwrap();
        assert_eq!(captured.source(), "fn first() {}\n");
        assert_eq!(
            captured.origin(),
            ProjectSourceOrigin::Overlay(frozen_revision)
        );
        assert_eq!(
            captured.oid(),
            Oid::hash_object(ObjectType::Blob, b"fn first() {}\n").unwrap(),
            "the pinned overlay keeps the original blob identity"
        );
        // A capture after the replacement sees the replacement, with its own
        // revision and identity; the earlier view is untouched.
        let fresh = (&overlay as &dyn Project)
            .capture_source_overlays()
            .unwrap();
        assert_ne!(fresh.identity(), pinned.identity());
        let replaced = fresh.source_snapshot(&file).unwrap();
        assert_eq!(replaced.source(), "fn second() {}\n");
        assert_ne!(replaced.origin(), captured.origin());
        assert_ne!(replaced.oid(), captured.oid());
        assert_eq!(pinned.source_snapshot(&file).unwrap(), captured);
        assert!(pinned.source_snapshot(&other).is_none());
        let disk = FilesystemProject::new(&root).unwrap();
        let empty = disk.capture_source_overlays().unwrap();
        assert!(empty.content().is_none());
        assert!(empty.source_snapshot(&file).is_none());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9737: a nested overlay capture pinned the inner and outer overlays from different instants"
    )]
    fn overlay_chain_capture_is_coherent_and_deadlock_free_under_concurrent_edits() {
        const ROUNDS: usize = 300;
        type Views = Vec<Arc<PinnedSourceOverlayView>>;
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let shared = write_file(&root, "shared.rs", "fn disk() {}\n");
        let inner_only = write_file(&root, "inner.rs", "fn disk() {}\n");
        let outer_only = write_file(&root, "outer.rs", "fn disk() {}\n");
        let beyond = TempDir::new().unwrap();
        let outside = ProjectFile::new(beyond.path().canonicalize().unwrap(), "outside.rs");
        let inner = Arc::new(OverlayProject::new(Arc::new(
            FilesystemProject::new(&root).unwrap(),
        )));
        let outer = Arc::new(OverlayProject::new(inner.clone()));
        let text = |owner: &str, version: usize| format!("fn {owner}_{version}() {{}}\n");
        for (project, file, owner) in [
            (&inner, &shared, "inner"),
            (&inner, &inner_only, "inner"),
            (&inner, &outside, "inner"),
            (&outer, &shared, "outer"),
            (&outer, &outer_only, "outer"),
        ] {
            assert!(project.set(file.abs_path(), text(owner, 0)));
        }

        // Lock order. With the delegate's map write-locked, the capture waits
        // on it while holding this project's read guard, so an outer edit
        // queued meanwhile lands after the pinned instant.
        let inner_guard = inner.overlays.write().unwrap();
        let capturing = {
            let outer = Arc::clone(&outer);
            thread::spawn(move || outer.capture_source_overlays())
        };
        let waiting = Instant::now();
        while outer.overlays.try_write().is_ok() {
            assert!(
                !capturing.is_finished(),
                "capture ended while its delegate was locked"
            );
            assert!(
                waiting.elapsed() < Duration::from_secs(10),
                "capture did not acquire the outer map before waiting for its delegate"
            );
            thread::yield_now();
        }
        let late = {
            let outer = Arc::clone(&outer);
            let path = outer_only.abs_path();
            thread::spawn(move || outer.set(path, "fn outer_late() {}\n".to_string()))
        };
        drop(inner_guard);
        let pinned = capturing.join().unwrap().unwrap();
        assert!(late.join().unwrap());
        assert_eq!(
            pinned.source_snapshot(&outer_only).unwrap().source(),
            text("outer", 0),
            "an edit that waited for the capture is not in the view"
        );
        assert_eq!(
            outer.read_source(&outer_only).unwrap(),
            "fn outer_late() {}\n"
        );

        assert!(outer.set(outer_only.abs_path(), text("outer", 0)));

        // Independent writers while captures loop. The sequential writer keeps
        // the inner version one behind or level with the outer one, which a
        // view pinned from two instants breaks.
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let (done_tx, done_rx) = mpsc::channel::<(&'static str, thread::Result<Views>)>();
        let run = |name: &'static str, body: Box<dyn FnOnce() -> Views + Send>| {
            let barrier = Arc::clone(&barrier);
            let done_tx = done_tx.clone();
            thread::spawn(move || {
                barrier.wait();
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
                done_tx.send((name, outcome)).unwrap();
            })
        };
        let sequential = run("sequential writer", {
            let (inner, outer) = (Arc::clone(&inner), Arc::clone(&outer));
            let (inner_only, outer_only) = (inner_only.abs_path(), outer_only.abs_path());
            Box::new(move || {
                for version in 1..=ROUNDS {
                    assert!(outer.set(outer_only.clone(), text("outer", version)));
                    assert!(inner.set(inner_only.clone(), text("inner", version)));
                }
                Vec::new()
            })
        });
        let inner_writer = run("inner writer", {
            let inner = Arc::clone(&inner);
            let (shared, outside) = (shared.abs_path(), outside.abs_path());
            Box::new(move || {
                for version in 1..=ROUNDS {
                    assert!(inner.set(shared.clone(), text("inner", version)));
                    assert!(inner.set(outside.clone(), text("inner", version)));
                }
                Vec::new()
            })
        });
        let outer_writer = run("outer writer", {
            let outer = Arc::clone(&outer);
            let shared = shared.abs_path();
            Box::new(move || {
                for version in 1..=ROUNDS {
                    assert!(outer.set(shared.clone(), text("outer", version)));
                }
                Vec::new()
            })
        });
        let capture_loop = run("capturing", {
            let outer = Arc::clone(&outer);
            Box::new(move || {
                (0..ROUNDS)
                    .map(|_| outer.capture_source_overlays().unwrap())
                    .collect()
            })
        });
        let mut views = Vec::new();
        for _ in 0..4 {
            let (name, outcome) = done_rx
                .recv_timeout(Duration::from_secs(60))
                .expect("a writer or the capturing thread deadlocked");
            match outcome {
                Ok(found) => views.extend(found),
                Err(panic) => {
                    eprintln!("{name} panicked");
                    std::panic::resume_unwind(panic)
                }
            }
        }

        for worker in [sequential, inner_writer, outer_writer, capture_loop] {
            worker.join().unwrap();
        }
        // Fixture identities name each version without interpreting source syntax.
        let versions = (0..=ROUNDS)
            .flat_map(|version| [("inner", version), ("outer", version)])
            .map(|(owner, version)| {
                let source = text(owner, version);
                (
                    Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap(),
                    (owner, version),
                )
            })
            .collect::<HashMap<_, _>>();
        let version = |snapshot: ProjectSourceSnapshot, owner: &str| -> usize {
            let (actual_owner, version) = versions
                .get(&snapshot.oid())
                .expect("capture contains one of the fixture's actual input versions");
            assert_eq!(*actual_owner, owner);
            assert_eq!(snapshot.source(), text(owner, *version));
            *version
        };
        assert_eq!(views.len(), ROUNDS);
        assert!(
            views
                .windows(2)
                .all(|pair| pair[0].identity() < pair[1].identity()),
            "view identities are strictly increasing"
        );
        for view in &views {
            // The outer overlay wins the shared path; inherited and
            // outside-root entries are pinned.
            version(view.source_snapshot(&shared).unwrap(), "outer");
            version(view.source_snapshot(&outside).unwrap(), "inner");
            let (outer_version, inner_version) = (
                version(view.source_snapshot(&outer_only).unwrap(), "outer"),
                version(view.source_snapshot(&inner_only).unwrap(), "inner"),
            );
            assert!(
                inner_version == outer_version || inner_version + 1 == outer_version,
                "inner {inner_version} and outer {outer_version} were pinned at different instants"
            );
            // The content metadata is the combined map's, minus what has no
            // workspace path, and each listed blob is its entry's.
            let content = view.content().unwrap();
            let listed = content
                .entries_with_blob_ids()
                .map(|(file, _, blob)| (file.rel_path().to_path_buf(), blob))
                .collect::<Vec<_>>();
            assert_eq!(
                listed
                    .iter()
                    .map(|(path, _)| path.as_path())
                    .collect::<Vec<_>>(),
                [
                    Path::new("inner.rs"),
                    Path::new("outer.rs"),
                    Path::new("shared.rs")
                ]
            );
            for (path, blob) in listed {
                let snapshot = view
                    .source_snapshot(&ProjectFile::new(&root, path))
                    .unwrap();
                assert_eq!(snapshot.oid(), blob);
                assert_eq!(
                    blob,
                    Oid::hash_object(ObjectType::Blob, snapshot.source().as_bytes()).unwrap()
                );
            }
        }
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
    fn overlay_stamp_waits_for_mutation_and_composes_delegate() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "app.ts", "class Disk {}\n");
        let delegate = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = Arc::new(OverlayProject::new(delegate.clone()));
        let before = overlay.view_stamp().unwrap();
        assert!(overlay.set(file.abs_path(), "class Overlay {}\n".to_string()));
        let after_set = overlay.view_stamp().unwrap();
        assert_ne!(before, after_set);

        let (removed_tx, removed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let clearing = {
            let overlay = Arc::clone(&overlay);
            let path = file.abs_path();
            thread::spawn(move || {
                overlay.remove_overlay_with_revision_hook(&path, || {
                    removed_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
            })
        };
        removed_rx.recv().unwrap();
        let (stamp_tx, stamp_rx) = mpsc::channel();
        let reader = {
            let overlay = Arc::clone(&overlay);
            thread::spawn(move || stamp_tx.send(overlay.view_stamp()).unwrap())
        };
        assert!(matches!(
            stamp_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        assert!(clearing.join().unwrap());
        assert_ne!(stamp_rx.recv().unwrap().unwrap(), after_set);
        reader.join().unwrap();

        let before_delegate = overlay.view_stamp().unwrap();
        delegate.invalidate_cached_file_listing();
        assert_ne!(overlay.view_stamp().unwrap(), before_delegate);
    }

    #[test]
    fn listing_invalidate_and_path_update_each_advance_stamp_once() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = write_file(&root, "first.rs", "fn first() {}\n");
        let second = write_file(&root, "second.rs", "fn second() {}\n");
        let cache = Arc::new(WorkspaceFileListingCache::new(root));
        cache.files().unwrap();
        let before = cache.view_stamp().generation;
        let cache_for_update = Arc::clone(&cache);
        let updating = thread::spawn(move || cache_for_update.update_path(&first, false));
        let cache_for_invalidate = Arc::clone(&cache);
        let invalidating = thread::spawn(move || cache_for_invalidate.invalidate());
        assert!(updating.join().unwrap());
        invalidating.join().unwrap();
        let after = cache.view_stamp().generation;
        assert!(after == before + 1 || after == before + 2);
        // An update after invalidation has no fresh listing to change.
        cache.files().unwrap();
        let before_update = cache.view_stamp().generation;
        assert!(cache.update_path(&second, false));
        assert_eq!(cache.view_stamp().generation, before_update + 1);
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

/// The exact non-source probes behind a cached nearest-module answer.
#[derive(Clone, Debug)]
pub enum IdentityWalkInput {
    File {
        rel_path: String,
        blob: [u8; 20],
        content_digest: [u8; 32],
    },
    PathAbsent {
        rel_path: String,
    },
    Unavailable,
}
