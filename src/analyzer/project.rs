use crate::analyzer::common::language_for_file;
use crate::analyzer::{Language, ProjectFile};
use crate::util::throttled_log::ThrottledLog;
use ignore::{WalkBuilder, WalkState};
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Default upper bound (8 MiB) on the size of a single in-memory overlay.
/// Picked to cover all hand-written source comfortably while bounding the
/// blast radius of an editor that opens a multi-MB minified bundle or vendor
/// blob — tree-sitter still parses such files, but holding many of them in
/// memory simultaneously across an LSP session quickly becomes expensive.
/// `OverlayProject::set` rejects content above this cap (and logs once per
/// path per [`OVERLAY_REJECTION_LOG_THROTTLE`]); reads fall through to disk
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

pub trait Project: Send + Sync {
    fn root(&self) -> &Path;
    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        let _ = file;
        self.root().to_path_buf()
    }
    fn analyzer_languages(&self) -> BTreeSet<Language>;
    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>>;
    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>>;
    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile>;

    fn file_by_abs_path(&self, abs_path: &Path) -> Option<ProjectFile> {
        let rel_path = abs_path.strip_prefix(self.root()).ok()?;
        self.file_by_rel_path(rel_path)
    }

    fn file_by_abs_path_allow_missing(&self, abs_path: &Path) -> Option<ProjectFile> {
        let rel_path = abs_path.strip_prefix(self.root()).ok()?;
        Some(ProjectFile::new(
            self.root().to_path_buf(),
            rel_path.to_path_buf(),
        ))
    }

    fn persistence_root(&self) -> Option<&Path> {
        Some(self.root())
    }

    fn is_gitignored(&self, _rel_path: &Path) -> bool {
        false
    }

    /// Read the source text of `file`. Default reads from disk. The LSP server
    /// overrides this via `OverlayProject` to serve unsaved buffer content
    /// pushed in by `textDocument/did{Open,Change}` notifications.
    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        file.read_to_string()
    }

    /// True when an in-memory overlay is shadowing `file`'s disk content.
    /// Analyzer persistence consults this to skip baseline writes for files
    /// whose parsed state was computed against unsaved content — otherwise the
    /// on-disk mtime would not change but the baseline row would be wrong.
    fn has_overlay(&self, _file: &ProjectFile) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub struct TestProject {
    root: PathBuf,
    languages: BTreeSet<Language>,
}

impl TestProject {
    pub fn new(root: impl Into<PathBuf>, language: Language) -> Self {
        Self::with_languages(root, BTreeSet::from([language]))
    }

    pub fn with_languages(root: impl Into<PathBuf>, languages: BTreeSet<Language>) -> Self {
        let root = root.into();
        assert!(root.is_absolute(), "test project root must be absolute");
        assert!(root.is_dir(), "test project root must exist");
        assert!(
            !languages.is_empty(),
            "test project must contain at least one analyzer language"
        );

        Self { root, languages }
    }

    pub fn from_root_with_inferred_languages(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        assert!(root.is_absolute(), "test project root must be absolute");
        assert!(root.is_dir(), "test project root must exist");

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

        Ok(Self { root, languages })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}

impl Project for TestProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
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

        Ok(files)
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let extensions = language.extensions();
        if extensions.is_empty() {
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

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.abs_path().is_file().then_some(file)
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemProject {
    root: PathBuf,
    languages: BTreeSet<Language>,
}

impl FilesystemProject {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into().canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("project root is not a directory: {}", root.display()),
            ));
        }

        let languages = detect_languages(&root)?;
        Ok(Self { root, languages })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}

impl Project for FilesystemProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        collect_workspace_files(&self.root)
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let extensions = language.extensions();
        if extensions.is_empty() {
            return Ok(BTreeSet::new());
        }

        let files = self.all_files()?;
        Ok(files
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        let normalized = ext.to_ascii_lowercase();
                        extensions.contains(&normalized.as_str())
                    })
                    .unwrap_or(false)
            })
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.abs_path().is_file().then_some(file)
    }

    fn is_gitignored(&self, rel_path: &Path) -> bool {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists()
            && self
                .all_files()
                .map(|files| !files.contains(&file))
                .unwrap_or(false)
    }
}

/// A [`Project`] backed by an explicit, fixed set of files rather than a
/// directory walk. One-shot CLI paths can use this to parse only requested
/// files instead of indexing the whole workspace: building a
/// [`WorkspaceAnalyzer`](crate::WorkspaceAnalyzer) over it analyzes exactly
/// these files and nothing else.
#[derive(Debug, Clone)]
pub struct FileSetProject {
    root: PathBuf,
    files: BTreeSet<ProjectFile>,
    languages: BTreeSet<Language>,
}

impl FileSetProject {
    /// Build a project rooted at `root` containing exactly the files at the
    /// given project-relative paths. Analyzer languages are inferred from the
    /// file extensions; files of unsupported types stay listed but contribute
    /// no language (and so are never parsed).
    pub fn new(root: impl Into<PathBuf>, rel_paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let root = root.into();
        let files: BTreeSet<ProjectFile> = rel_paths
            .into_iter()
            .map(|rel| ProjectFile::new(root.clone(), rel))
            .collect();
        let languages = files
            .iter()
            .map(language_for_file)
            .filter(|language| *language != Language::None)
            .collect();
        Self {
            root,
            files,
            languages,
        }
    }
}

impl Project for FileSetProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        Ok(self.files.clone())
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        Ok(self
            .files
            .iter()
            .filter(|file| language_for_file(file) == language)
            .cloned()
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
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
    root: PathBuf,
    roots: Vec<FilesystemProject>,
}

impl MultiRootProject {
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        let mut roots = roots
            .into_iter()
            .map(|root| root.canonicalize())
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
        let roots = roots
            .iter()
            .map(FilesystemProject::new)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { root, roots })
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
        self.all_files()
            .map(|files| {
                files
                    .iter()
                    .map(language_for_file)
                    .filter(|language| *language != Language::None)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let mut files = BTreeSet::new();
        for root in &self.roots {
            for file in root.all_files()? {
                files.insert(self.common_file_for_root_file(file));
            }
        }
        Ok(files)
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        Ok(self
            .all_files()?
            .iter()
            .filter(|file| language_for_file(file) == language)
            .cloned()
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        self.file_by_abs_path(&self.root.join(rel_path))
    }

    fn file_by_abs_path(&self, abs_path: &Path) -> Option<ProjectFile> {
        for root in &self.roots {
            let Ok(root_rel_path) = abs_path.strip_prefix(root.root()) else {
                continue;
            };
            if let Some(file) = root.file_by_rel_path(root_rel_path) {
                return Some(self.common_file_for_root_file(file));
            }
        }
        None
    }

    fn file_by_abs_path_allow_missing(&self, abs_path: &Path) -> Option<ProjectFile> {
        let rel_path = abs_path.strip_prefix(&self.root).ok()?;
        for root in &self.roots {
            if abs_path.strip_prefix(root.root()).is_ok() {
                return Some(ProjectFile::new(self.root.clone(), rel_path.to_path_buf()));
            }
        }
        None
    }

    fn persistence_root(&self) -> Option<&Path> {
        None
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
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .ignore(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
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

/// A [`Project`] wrapper that layers an in-memory content overlay on top of a
/// delegate project. Reads consult the overlay first and fall back to the
/// delegate; every other [`Project`] method (file enumeration, language
/// detection) is delegated unchanged. Used by the LSP server to feed
/// `textDocument/did{Open,Change}` buffer content into the analyzer without
/// writing to disk.
pub struct OverlayProject {
    delegate: Arc<dyn Project>,
    overlays: Arc<RwLock<HashMap<PathBuf, Arc<str>>>>,
    max_overlay_bytes: usize,
    /// Last instant we emitted a rejection log for a given path. Kept on a
    /// separate throttle helper so the per-keystroke read path doesn't
    /// contend with rejection logging on the main overlay lock.
    last_rejection_log: ThrottledLog<PathBuf>,
}

impl OverlayProject {
    pub fn new(delegate: Arc<dyn Project>) -> Self {
        Self::with_max_bytes(delegate, DEFAULT_MAX_OVERLAY_BYTES)
    }

    /// Construct with a custom per-overlay size cap. Reserved for tests and
    /// future tuning; production LSP wiring uses [`Self::new`].
    pub fn with_max_bytes(delegate: Arc<dyn Project>, max_overlay_bytes: usize) -> Self {
        Self {
            delegate,
            overlays: Arc::new(RwLock::new(HashMap::new())),
            max_overlay_bytes,
            last_rejection_log: ThrottledLog::new(
                OVERLAY_REJECTION_LOG_THROTTLE,
                OVERLAY_REJECTION_LOG_MAX_ENTRIES,
            ),
        }
    }

    /// Capture an independent read view of the current overlays.
    ///
    /// Subsequent editor changes mutate the live project's map without changing this
    /// snapshot, allowing background requests to use one coherent source generation.
    pub(crate) fn snapshot(&self) -> Self {
        let overlays = self.overlays.read().expect("overlay lock poisoned").clone();
        Self {
            delegate: Arc::clone(&self.delegate),
            overlays: Arc::new(RwLock::new(overlays)),
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
        if content.len() > self.max_overlay_bytes {
            self.log_rejection(&abs_path, content.len());
            // Drop any stale overlay so reads return disk content rather than
            // a now-misleading older version of the buffer.
            self.overlays
                .write()
                .expect("overlay lock poisoned")
                .remove(&abs_path);
            return false;
        }
        self.overlays
            .write()
            .expect("overlay lock poisoned")
            .insert(abs_path, Arc::from(content));
        true
    }

    /// Remove an overlay, if present. Returns `true` when an overlay was
    /// actually removed — callers use this to decide whether reparse is needed.
    pub fn clear(&self, abs_path: &Path) -> bool {
        self.overlays
            .write()
            .expect("overlay lock poisoned")
            .remove(abs_path)
            .is_some()
    }

    /// Drop every overlay. Not invoked by the LSP today; reserved for future
    /// session-reset paths.
    pub fn clear_all(&self) {
        self.overlays
            .write()
            .expect("overlay lock poisoned")
            .clear();
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
    fn root(&self) -> &Path {
        self.delegate.root()
    }

    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        self.delegate.workspace_root_for_file(file)
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.delegate.analyzer_languages()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        self.delegate.all_files()
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        self.delegate.analyzable_files(language)
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        self.delegate.file_by_rel_path(rel_path)
    }

    fn file_by_abs_path(&self, abs_path: &Path) -> Option<ProjectFile> {
        self.delegate.file_by_abs_path(abs_path)
    }

    fn file_by_abs_path_allow_missing(&self, abs_path: &Path) -> Option<ProjectFile> {
        self.delegate.file_by_abs_path_allow_missing(abs_path)
    }

    fn persistence_root(&self) -> Option<&Path> {
        self.delegate.persistence_root()
    }

    fn is_gitignored(&self, rel_path: &Path) -> bool {
        self.delegate.is_gitignored(rel_path)
    }

    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        if let Some(text) = self
            .overlays
            .read()
            .expect("overlay lock poisoned")
            .get(&file.abs_path())
        {
            return Ok(text.to_string());
        }
        self.delegate.read_source(file)
    }

    fn has_overlay(&self, file: &ProjectFile) -> bool {
        self.overlays
            .read()
            .expect("overlay lock poisoned")
            .contains_key(&file.abs_path())
    }
}

fn detect_languages(root: &Path) -> io::Result<BTreeSet<Language>> {
    let mut languages = BTreeSet::new();
    for file in collect_workspace_files(root)? {
        let language = language_for_file(&file);
        if language != Language::None {
            languages.insert(language);
        }
    }
    Ok(languages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(root: &Path, rel: &str, contents: &str) -> ProjectFile {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, contents).unwrap();
        ProjectFile::new(root.to_path_buf(), PathBuf::from(rel))
    }

    #[test]
    fn filesystem_project_read_source_reads_disk() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "hello.py", "print('hi')\n");
        let project = FilesystemProject::new(&root).unwrap();
        assert_eq!(project.read_source(&file).unwrap(), "print('hi')\n");
        assert!(!project.has_overlay(&file));
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
    fn fileset_project_disables_persistence() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project = FileSetProject::new(root.clone(), [PathBuf::from("A.java")]);
        assert_eq!(project.root(), root.as_path());
        assert!(project.persistence_root().is_none());
    }

    #[test]
    fn overlay_project_returns_overlay_when_set_and_disk_otherwise() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn old() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);

        // No overlay yet: falls through to disk.
        assert_eq!(overlay.read_source(&file).unwrap(), "fn old() {}\n");
        assert!(!overlay.has_overlay(&file));

        // Set overlay: served from memory regardless of disk.
        assert!(overlay.set(file.abs_path(), "fn new() {}\n".to_string()));
        assert_eq!(overlay.read_source(&file).unwrap(), "fn new() {}\n");
        assert!(overlay.has_overlay(&file));

        // Disk is unchanged.
        assert_eq!(
            std::fs::read_to_string(file.abs_path()).unwrap(),
            "fn old() {}\n"
        );

        // Clear: disk reasserts.
        assert!(overlay.clear(&file.abs_path()));
        assert_eq!(overlay.read_source(&file).unwrap(), "fn old() {}\n");
        assert!(!overlay.has_overlay(&file));

        // Clearing a missing overlay returns false.
        assert!(!overlay.clear(&file.abs_path()));
    }

    #[test]
    fn overlay_project_snapshot_isolated_from_later_edits() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(delegate);
        assert!(overlay.set(file.abs_path(), "fn first() {}\n".to_string()));

        let snapshot = overlay.snapshot();
        {
            let live = overlay.overlays.read().expect("overlay lock poisoned");
            let frozen = snapshot.overlays.read().expect("overlay lock poisoned");
            assert!(Arc::ptr_eq(
                live.get(&file.abs_path()).unwrap(),
                frozen.get(&file.abs_path()).unwrap(),
            ));
        }
        assert!(overlay.set(file.abs_path(), "fn second() {}\n".to_string()));

        assert_eq!(snapshot.read_source(&file).unwrap(), "fn first() {}\n");
        assert_eq!(overlay.read_source(&file).unwrap(), "fn second() {}\n");
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
    fn overlay_project_delegates_non_read_methods() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        write_file(&root, "a.py", "");
        write_file(&root, "b.py", "");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::new(Arc::clone(&delegate));

        assert_eq!(overlay.root(), delegate.root());
        assert_eq!(overlay.analyzer_languages(), delegate.analyzer_languages());
        assert_eq!(overlay.all_files().unwrap(), delegate.all_files().unwrap());
    }

    #[test]
    fn overlay_project_rejects_oversized_set_and_falls_back_to_disk() {
        // A tiny cap (16 bytes) makes the oversized case trivial to construct.
        // Verifies the contract: set returns false, has_overlay stays false,
        // read_source returns disk content.
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::with_max_bytes(delegate, 16);

        let oversized = "x".repeat(64);
        assert!(
            !overlay.set(file.abs_path(), oversized),
            "set must reject content larger than the cap"
        );
        assert!(
            !overlay.has_overlay(&file),
            "rejected set must not leave an overlay record"
        );
        assert_eq!(
            overlay.read_source(&file).unwrap(),
            "fn disk() {}\n",
            "read must fall through to disk when overlay was rejected"
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

    #[test]
    fn overlay_project_accepts_set_exactly_at_cap() {
        // Boundary case: content_len == cap is accepted (the rejection rule
        // uses `>`, not `>=`).
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::with_max_bytes(delegate, 16);

        let exactly_at_cap = "x".repeat(16);
        assert!(
            overlay.set(file.abs_path(), exactly_at_cap.clone()),
            "set at exactly the cap must succeed"
        );
        assert_eq!(overlay.read_source(&file).unwrap(), exactly_at_cap);
    }

    #[test]
    fn overlay_project_default_cap_constant_is_eight_mib() {
        // Sanity check on the constant — bumping the default is a deliberate
        // memory-budget decision and should not happen by accident.
        assert_eq!(DEFAULT_MAX_OVERLAY_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn overlay_project_repeated_rejections_are_idempotent() {
        // didChange fires per-keystroke. An editor parked on a buffer that's
        // permanently over the cap will hammer set() repeatedly. The
        // visible-state contract — has_overlay false, reads return disk —
        // must hold for every call, and the throttled log path must not
        // panic on the second-onwards calls (they take the "skip log"
        // branch).
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "lib.rs", "fn disk() {}\n");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = OverlayProject::with_max_bytes(delegate, 16);

        for _ in 0..5 {
            assert!(!overlay.set(file.abs_path(), "x".repeat(64)));
            assert!(!overlay.has_overlay(&file));
            assert_eq!(overlay.read_source(&file).unwrap(), "fn disk() {}\n");
        }
    }
}
