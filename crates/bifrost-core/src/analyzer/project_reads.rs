//! Type-erased project read capability. Only analysis constructs recorders.
use super::ProjectFile;
use super::project::Project;
use std::cell::{Cell, RefCell};
use std::io;
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy)]
pub enum ProjectRead<'a> {
    Listing,
    Inventory,
    AnalyzerLanguages {
        languages: &'a std::collections::BTreeSet<super::Language>,
    },
    IgnoreRules,
    GitIgnore {
        rel_path: &'a std::path::Path,
    },
    OverlayMembership {
        rel_path: &'a std::path::Path,
    },
    Directory {
        rel_path: &'a std::path::Path,
    },
    Path {
        rel_path: &'a std::path::Path,
    },
    AbsolutePath {
        abs_path: &'a std::path::Path,
    },
    Overlays,
    Content {
        file: &'a ProjectFile,
        blob: Option<git2::Oid>,
    },
    Unattributed,
}

/// Certificates produced by the getter, never by the recorder.
/// Listing caches retain only the scalar fields; overlay Arcs live for one call.
#[derive(Clone, Debug, Default)]
pub struct ProjectReadReceipt {
    pub listing: Option<[u8; 32]>,
    pub inventory: Option<[u8; 32]>,
    pub ignore_rules: Option<[u8; 32]>,
    pub directory: Option<bool>,
    pub path_kind: Option<WorkspacePathKind>,
    pub observed_path: Option<std::path::PathBuf>,
    pub overlay_membership: Option<bool>,
    pub path_overlay_membership: Option<bool>,
    pub overlays: Option<Option<Arc<super::project::WorkspaceOverlayContent>>>,
    pub git_ignore_presence_only: bool,
}

/// Hash the actual configured/discovered set, independent of enum order.
pub fn workspace_analyzer_languages_digest(
    languages: &std::collections::BTreeSet<super::Language>,
) -> [u8; 32] {
    let mut labels = languages
        .iter()
        .map(|language| language.config_label())
        .collect::<Vec<_>>();
    labels.sort_unstable();
    let mut hash =
        super::canonical_hash::CanonicalHasher::new(b"bifrost-workspace-analyzer-languages:v1");
    hash.sequence("languages", &labels, |hash, language| {
        hash.field("language", language.as_bytes())
    });
    hash.finish()
}

/// The physical kind, following symlinks exactly as Path::is_file/exists do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspacePathKind {
    Absent,
    File,
    Directory,
    Other,
}

pub fn workspace_path_kind(path: &std::path::Path) -> WorkspacePathKind {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => WorkspacePathKind::File,
        Ok(metadata) if metadata.is_dir() => WorkspacePathKind::Directory,
        Ok(_) => WorkspacePathKind::Other,
        Err(_) => WorkspacePathKind::Absent,
    }
}

pub fn workspace_path_kind_digest(path: &std::path::Path) -> [u8; 32] {
    observed_path_kind_digest(workspace_path_kind(path))
}

pub fn observed_path_kind_digest(kind: WorkspacePathKind) -> [u8; 32] {
    let kind = match kind {
        WorkspacePathKind::Absent => "absent",
        WorkspacePathKind::File => "file",
        WorkspacePathKind::Directory => "directory",
        WorkspacePathKind::Other => "other",
    };
    let mut hash = super::canonical_hash::CanonicalHasher::new(b"bifrost-workspace-path-kind:v1");
    hash.field("kind", kind.as_bytes());
    hash.finish()
}

thread_local! {
    static READ_RECEIPT: RefCell<ProjectReadReceipt> = RefCell::new(ProjectReadReceipt::default());
    static BUILDING_RECEIPT: Cell<bool> = const { Cell::new(false) };
}

/// The getter proved its answer without consulting listing membership.
pub fn publish_git_ignore_presence_only() {
    READ_RECEIPT.with_borrow_mut(|receipt| receipt.git_ignore_presence_only = true);
}

pub fn publish_directory(exists: bool) {
    READ_RECEIPT.with_borrow_mut(|receipt| receipt.directory = Some(exists));
}

/// Observe a physical path once within the current getter, including delegates.
pub fn observed_path_kind(path: &std::path::Path) -> WorkspacePathKind {
    READ_RECEIPT.with_borrow_mut(|receipt| {
        if receipt.observed_path.as_deref() != Some(path) {
            receipt.observed_path = Some(path.to_path_buf());
            receipt.path_kind = Some(workspace_path_kind(path));
            receipt.path_overlay_membership = None;
        }
        receipt
            .path_kind
            .expect("the observed path carries its kind")
    })
}
/// The outer path getter and its delegates share one overlay observation.
fn observe_path_overlay_membership(project: &dyn Project, file: &ProjectFile) {
    if READ_RECEIPT.with_borrow(|receipt| receipt.path_overlay_membership.is_some()) {
        return;
    }
    let present = project.has_overlay(file);
    READ_RECEIPT.with_borrow_mut(|receipt| receipt.path_overlay_membership = Some(present));
}

pub fn observed_overlay_membership() -> bool {
    READ_RECEIPT.with_borrow(|receipt| {
        receipt
            .path_overlay_membership
            .expect("a path getter observes overlay membership before delegating")
    })
}

pub fn publish_overlay_membership(present: bool) {
    READ_RECEIPT.with_borrow_mut(|receipt| receipt.overlay_membership = Some(present));
}
pub fn publish_overlays(overlays: &Option<Arc<super::project::WorkspaceOverlayContent>>) {
    READ_RECEIPT.with_borrow_mut(|receipt| receipt.overlays = Some(overlays.clone()));
}

pub fn publish_ignore_rules(digest: [u8; 32]) {
    READ_RECEIPT.with_borrow_mut(|receipt| receipt.ignore_rules = Some(digest));
}

pub fn publish_receipt(receipt: ProjectReadReceipt) {
    READ_RECEIPT.with_borrow_mut(|current| {
        let kind = current.path_kind;
        let path = current.observed_path.take();
        let overlay = current.overlay_membership;
        let path_overlay = current.path_overlay_membership;
        *current = receipt;
        current.path_kind = kind.or(current.path_kind);
        current.observed_path = path.or(current.observed_path.take());
        current.overlay_membership = overlay.or(current.overlay_membership);
        current.path_overlay_membership = path_overlay.or(current.path_overlay_membership);
    });
}

/// Compose only from the completed call's files and already-built rule inputs.
/// Delegates can contribute receipts, but recursive receipt construction cannot.
pub fn publish_file_set(
    project: &dyn Project,
    files: &std::collections::BTreeSet<ProjectFile>,
) -> io::Result<()> {
    if PROJECT_READ_DEPTH.with(Cell::get) == 0 || BUILDING_RECEIPT.with(|flag| flag.replace(true)) {
        return Ok(());
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            BUILDING_RECEIPT.with(|flag| flag.set(false));
        }
    }
    let _reset = Reset;
    // Certification must not change a successful getter into an IO
    // failure. In particular, legacy custom projects may not expose
    // their ignore rules. Clear any delegate's listing certificates so
    // the recorder refuses reuse through its missing-receipt path.
    let receipt = file_set_receipt(project, files).unwrap_or_default();
    publish_receipt(receipt);
    Ok(())
}

pub fn file_set_receipt(
    project: &dyn Project,
    files: &std::collections::BTreeSet<ProjectFile>,
) -> io::Result<ProjectReadReceipt> {
    let was_building = BUILDING_RECEIPT.with(|flag| flag.replace(true));
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            BUILDING_RECEIPT.with(|flag| flag.set(self.0));
        }
    }
    let _reset = Reset(was_building);

    let mut analyzable = std::collections::BTreeSet::new();
    for language in super::Language::ANALYZABLE {
        analyzable.extend(project.analyzable_files_from(files, language)?);
    }
    let paths = files
        .iter()
        .map(|file| {
            (
                crate::path_utils::rel_path_string(file),
                project.is_bifrostignored(file.rel_path()),
                project.has_overlay(file),
            )
        })
        .collect::<Vec<_>>();
    let selected = analyzable
        .iter()
        .map(|file| {
            (
                crate::path_utils::rel_path_string(file),
                project.has_overlay(file),
            )
        })
        .collect::<Vec<_>>();
    let overlays = project
        .overlay_content()
        .into_iter()
        .flat_map(|content| {
            content
                .entries()
                .iter()
                .map(|(file, _)| crate::path_utils::rel_path_string(file))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    Ok(file_set_receipt_from_entries(
        paths,
        selected,
        overlays,
        project.ignore_rules_digest()?,
    ))
}

pub(crate) fn file_set_receipt_from_entries(
    mut paths: Vec<(String, bool, bool)>,
    mut selected: Vec<(String, bool)>,
    mut overlays: Vec<String>,
    rules: [u8; 32],
) -> ProjectReadReceipt {
    paths.sort_unstable();
    selected.sort_unstable();
    overlays.sort_unstable();
    overlays.dedup();
    let mut listing =
        super::canonical_hash::CanonicalHasher::new(b"bifrost-workspace-file-listing:v1");
    listing.sequence("files", &selected, |hash, (path, overlay)| {
        hash.field("rel_path", path.as_bytes());
        hash.field("overlay", &[*overlay as u8]);
    });
    let mut inventory =
        super::canonical_hash::CanonicalHasher::new(b"bifrost-workspace-file-inventory:v1");
    inventory.sequence("files", &paths, |hash, (path, ignored, overlay)| {
        hash.field("rel_path", path.as_bytes());
        hash.field("ignored", &[*ignored as u8]);
        hash.field("overlay", &[*overlay as u8]);
    });
    inventory.sequence("overlays", &overlays, |hash, path| {
        hash.field("rel_path", path.as_bytes())
    });
    ProjectReadReceipt {
        listing: Some(listing.finish()),
        inventory: Some(inventory.finish()),
        ignore_rules: Some(rules),
        ..ProjectReadReceipt::default()
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProjectIoCounts {
    pub walks: usize,
    pub rule_reads: usize,
    pub source_reads: usize,
    pub recording_io: usize,
}
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static PROJECT_IO: Cell<ProjectIoCounts> = Cell::new(ProjectIoCounts::default());
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}
#[cfg(any(test, feature = "test-support"))]
pub(crate) enum ProjectIo {
    Walk,
    Rule,
    Source,
}
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn count_project_io(kind: ProjectIo) {
    PROJECT_IO.with(|counts| {
        let mut value = counts.get();
        match kind {
            ProjectIo::Walk => value.walks += 1,
            ProjectIo::Rule => value.rule_reads += 1,
            ProjectIo::Source => value.source_reads += 1,
        }
        value.recording_io += usize::from(RECORDING.with(Cell::get));
        counts.set(value);
    });
}
#[cfg(any(test, feature = "test-support"))]
pub fn measure_project_io<T>(read: impl FnOnce() -> T) -> (T, ProjectIoCounts) {
    let before = PROJECT_IO.with(Cell::get);
    let result = read();
    let after = PROJECT_IO.with(Cell::get);
    (
        result,
        ProjectIoCounts {
            walks: after.walks - before.walks,
            rule_reads: after.rule_reads - before.rule_reads,
            source_reads: after.source_reads - before.source_reads,
            recording_io: after.recording_io - before.recording_io,
        },
    )
}

/// Implemented only by analysis; receipts contain no core-visible read keys.
pub trait ErasedReadAttribution: Send + Sync {
    fn is_live(&self) -> bool;
    fn is_capturing(&self) -> bool;
    fn record(&self, project: &dyn Project, read: ProjectRead<'_>, receipt: ProjectReadReceipt);
    fn capture_identity(&self) -> Option<super::memo_attribution::CaptureIdentity>;
    fn record_unattributed(&self);
    fn capture(&self, build: &mut dyn FnMut()) -> ErasedCapturedReads;
    fn capture_authority(&self, build: &mut dyn FnMut()) -> ErasedCapturedReads;
    fn replay(
        &self,
        receipts: &[OpaqueReadReceipt],
        unattributed_reads: usize,
        execution_dependences: usize,
    );
}

#[derive(Clone, Debug)]
pub struct OpaqueReadReceipt {
    value: Arc<dyn std::any::Any + Send + Sync>,
    retained_bytes: usize,
}
impl OpaqueReadReceipt {
    /// Analysis alone constructs receipts; the source gate enforces ownership.
    pub fn new(value: Arc<dyn std::any::Any + Send + Sync>, retained_bytes: usize) -> Self {
        Self {
            value,
            retained_bytes,
        }
    }
    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> {
        self.value.downcast_ref()
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

pub struct ErasedCapturedReads {
    pub receipt: OpaqueReadReceipt,
    pub unattributed_reads: usize,
    pub execution_dependences: usize,
    pub forwarded_to: Option<super::memo_attribution::CaptureIdentity>,
}

#[derive(Clone)]
pub struct ReadCapability(Arc<dyn ErasedReadAttribution>);
impl ReadCapability {
    pub fn new(recorder: impl ErasedReadAttribution + 'static) -> Self {
        Self(Arc::new(recorder))
    }
    pub fn memo_attribution(
        &self,
    ) -> super::memo_attribution::MemoCapability<ErasedMemoAttribution> {
        super::memo_attribution::MemoCapability::from_erased(self.clone())
    }
}
impl std::fmt::Debug for ReadCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReadCapability")
            .field(&Arc::as_ptr(&self.0))
            .finish()
    }
}

/// One slot per project source. Registrations hold weak analyzer owners in
/// analysis, so a project cannot keep an analyzer or its request caches alive.
#[derive(Clone, Debug, Default)]
pub struct ProjectReadSlot(Arc<RwLock<Vec<ReadCapability>>>);
thread_local! {
    static PROJECT_READ_DEPTH: Cell<usize> = const { Cell::new(0) };
    static PROJECT_READ_SUPPRESSION_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn project_reads_suppressed() -> bool {
    PROJECT_READ_SUPPRESSION_DEPTH.with(|depth| depth.get() != 0)
}

pub(crate) fn project_getter_in_progress() -> bool {
    PROJECT_READ_DEPTH.with(|depth| depth.get() != 0)
}

/// Install the transported work's state independently of a suspended job on
/// this worker. Rayon can service an unrelated task while that job waits.
/// Its partially built getter receipt must survive the task as well.
///
/// The two depths mean different things. `PROJECT_READ_DEPTH` is getter
/// nesting: the outermost getter builds and records the receipt.
/// `PROJECT_READ_SUPPRESSION_DEPTH` is maintenance intent. Under suppression
/// the read depth starts at 1, so a getter on the worker is nested into a
/// fresh receipt that is thrown away. For unrelated work it starts at 0, so
/// the worker's getter is outermost and records as usual.
pub(crate) fn with_project_read_suppression<T>(suppressed: bool, build: impl FnOnce() -> T) -> T {
    struct Restore {
        depth: usize,
        suppression_depth: usize,
        receipt: ProjectReadReceipt,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            PROJECT_READ_DEPTH.with(|depth| depth.set(self.depth));
            PROJECT_READ_SUPPRESSION_DEPTH.with(|depth| depth.set(self.suppression_depth));
            READ_RECEIPT.with_borrow_mut(|receipt| {
                *receipt = std::mem::take(&mut self.receipt);
            });
        }
    }
    let _restore = Restore {
        depth: PROJECT_READ_DEPTH.with(|depth| depth.replace(usize::from(suppressed))),
        suppression_depth: PROJECT_READ_SUPPRESSION_DEPTH
            .with(|depth| depth.replace(usize::from(suppressed))),
        receipt: READ_RECEIPT.with_borrow_mut(std::mem::take),
    };
    build()
}

impl ProjectReadSlot {
    pub fn install(&self, capability: ReadCapability) {
        let mut recorders = self.0.write().expect("project read recorders poisoned");
        recorders.retain(|recorder| recorder.0.is_live());
        if !recorders
            .iter()
            .any(|other| Arc::ptr_eq(&other.0, &capability.0))
        {
            recorders.push(capability);
        }
    }

    /// Nested delegate reads contribute to the outer answer. Its certificate
    /// is recorded only after the complete getter releases its locks.
    fn enter<'a>(
        &'a self,
        project: Option<&'a dyn Project>,
        read: ProjectRead<'a>,
    ) -> ProjectListingRead<'a> {
        let outermost = PROJECT_READ_DEPTH.with(|depth| {
            let old = depth.get();
            depth.set(old + 1);
            if old == 0 {
                READ_RECEIPT.with_borrow_mut(|receipt| *receipt = ProjectReadReceipt::default());
            }
            old == 0
        });
        ProjectListingRead {
            slot: self,
            outermost,
            read,
            project,
            _depth: ProjectReadDepth,
        }
    }
    pub fn listing<'a>(&'a self, project: &'a dyn Project) -> ProjectListingRead<'a> {
        self.enter(Some(project), ProjectRead::Listing)
    }
    pub fn languages(
        &self,
        project: &dyn Project,
        read: impl FnOnce() -> std::collections::BTreeSet<super::Language>,
    ) -> std::collections::BTreeSet<super::Language> {
        let mut guard = self.enter(Some(project), ProjectRead::Unattributed);
        let languages = read();
        if guard.outermost {
            self.record(project, || ProjectRead::AnalyzerLanguages {
                languages: &languages,
            });
        }
        guard.outermost = false;
        languages
    }

    pub fn inventory<'a>(&'a self, project: &'a dyn Project) -> ProjectListingRead<'a> {
        self.enter(Some(project), ProjectRead::Inventory)
    }
    pub fn ignore_rules<'a>(&'a self, project: &'a dyn Project) -> ProjectListingRead<'a> {
        self.enter(Some(project), ProjectRead::IgnoreRules)
    }
    pub fn git_ignore<'a>(
        &'a self,
        project: &'a dyn Project,
        rel_path: &'a std::path::Path,
    ) -> ProjectListingRead<'a> {
        let guard = self.enter(Some(project), ProjectRead::GitIgnore { rel_path });
        observed_path_kind(&project.root().join(rel_path));
        let file = ProjectFile::new(project.root().to_path_buf(), rel_path);
        observe_path_overlay_membership(project, &file);
        guard
    }
    pub fn overlay_membership<'a>(
        &'a self,
        project: &'a dyn Project,
        rel_path: &'a std::path::Path,
    ) -> ProjectListingRead<'a> {
        self.enter(Some(project), ProjectRead::OverlayMembership { rel_path })
    }
    pub fn directory<'a>(
        &'a self,
        project: &'a dyn Project,
        rel_path: &'a std::path::Path,
    ) -> ProjectListingRead<'a> {
        self.enter(Some(project), ProjectRead::Directory { rel_path })
    }
    pub fn path<'a>(
        &'a self,
        project: &'a dyn Project,
        rel_path: &'a std::path::Path,
    ) -> ProjectListingRead<'a> {
        let guard = self.enter(Some(project), ProjectRead::Path { rel_path });
        observed_path_kind(&project.root().join(rel_path));
        let file = ProjectFile::new(project.root().to_path_buf(), rel_path);
        observe_path_overlay_membership(project, &file);
        guard
    }
    pub fn absolute_path<'a>(
        &'a self,
        project: &'a dyn Project,
        abs_path: &'a std::path::Path,
    ) -> ProjectListingRead<'a> {
        let guard = self.enter(Some(project), ProjectRead::AbsolutePath { abs_path });
        if let Ok(rel_path) = abs_path.strip_prefix(project.root()) {
            observed_path_kind(abs_path);
            let file = ProjectFile::new(project.root().to_path_buf(), rel_path);
            observe_path_overlay_membership(project, &file);
        }
        guard
    }
    pub fn overlays<'a>(&'a self, project: &'a dyn Project) -> ProjectListingRead<'a> {
        self.enter(Some(project), ProjectRead::Overlays)
    }

    pub fn cached_inventory(
        &self,
        root: &std::path::Path,
        read: impl FnOnce() -> io::Result<Arc<std::collections::BTreeSet<ProjectFile>>>,
    ) -> io::Result<Arc<std::collections::BTreeSet<ProjectFile>>> {
        let mut guard = self.enter(None, ProjectRead::Unattributed);
        let files = read();
        if guard.outermost {
            match &files {
                Ok(files) => {
                    let source =
                        super::project::FilesystemProject::from_listing(root, Arc::clone(files));
                    self.record(&source, || ProjectRead::Inventory);
                }
                Err(_) => {
                    for recorder in self
                        .0
                        .read()
                        .expect("project read recorders poisoned")
                        .iter()
                    {
                        if recorder.0.is_capturing() {
                            recorder.0.record_unattributed();
                        }
                    }
                }
            }
        }
        guard.outermost = false;
        files
    }

    fn record<'a>(&self, project: &dyn Project, read: impl Fn() -> ProjectRead<'a>) {
        #[cfg(any(test, feature = "test-support"))]
        let _recording = {
            struct Reset(bool);
            impl Drop for Reset {
                fn drop(&mut self) {
                    RECORDING.with(|flag| flag.set(self.0));
                }
            }
            Reset(RECORDING.with(|flag| flag.replace(true)))
        };

        let recorders = self
            .0
            .read()
            .expect("project read recorders poisoned")
            .clone();
        for recorder in recorders {
            if recorder.0.is_capturing() {
                recorder
                    .0
                    .record(project, read(), READ_RECEIPT.with_borrow(Clone::clone));
            }
        }
    }

    pub fn overlay<T>(
        &self,
        project: &dyn Project,
        file: &ProjectFile,
        read: impl FnOnce() -> Option<T>,
        blob: impl FnOnce(&T) -> git2::Oid,
    ) -> Option<T> {
        let mut guard = self.listing(project);
        let result = read();
        if guard.outermost {
            match &result {
                Some(value) => {
                    let blob = blob(value);
                    self.record(project, || ProjectRead::Content {
                        file,
                        blob: Some(blob),
                    });
                }
                None => {
                    publish_overlay_membership(false);
                    self.record(project, || ProjectRead::OverlayMembership {
                        rel_path: file.rel_path(),
                    });
                }
            }
        }
        guard.outermost = false;
        result
    }

    pub fn source<T>(
        &self,
        project: &dyn Project,
        file: &ProjectFile,
        read: impl FnOnce() -> io::Result<T>,
        snapshot: impl FnOnce(&T) -> Option<git2::Oid>,
    ) -> io::Result<T> {
        let guard = self.listing(project);
        let result = read();
        if guard.outermost && !std::thread::panicking() {
            match &result {
                Ok(value) => match snapshot(value) {
                    Some(source) => self.record(project, || ProjectRead::Content {
                        file,
                        blob: Some(source),
                    }),
                    None => self.record(project, || ProjectRead::Unattributed),
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.record(project, || ProjectRead::Content { file, blob: None })
                }
                Err(_) => self.record(project, || ProjectRead::Unattributed),
            }
        }
        // Source reads name their exact snapshot, never the listing.
        let mut guard = guard;
        guard.outermost = false;
        result
    }
}

pub struct ProjectListingRead<'a> {
    slot: &'a ProjectReadSlot,
    outermost: bool,
    read: ProjectRead<'a>,
    project: Option<&'a dyn Project>,
    _depth: ProjectReadDepth,
}
struct ProjectReadDepth;
impl Drop for ProjectReadDepth {
    fn drop(&mut self) {
        PROJECT_READ_DEPTH.with(|depth| {
            let remaining = depth.get() - 1;
            depth.set(remaining);
            if remaining == 0 {
                READ_RECEIPT.with_borrow_mut(|receipt| *receipt = ProjectReadReceipt::default());
            }
        });
    }
}
impl Drop for ProjectListingRead<'_> {
    fn drop(&mut self) {
        // Keep nested suppression installed while recording the completed receipt. Never record a partially unwound build.
        if self.outermost && !std::thread::panicking() {
            self.slot.record(
                self.project
                    .expect("ordinary Project getter carries its source view"),
                || self.read,
            );
        }
    }
}

/// Suppress project input reads during maintenance or a covering fact build.
/// The scope is thread-local; `CarriedContext` transports it to nested workers.
/// Independent maintenance entry points must enter it on their own thread.
/// Ordinary readers record the resulting state when a query consumes it.
pub fn without_project_reads<T>(build: impl FnOnce() -> T) -> T {
    struct RestoreSuppression(usize);
    impl Drop for RestoreSuppression {
        fn drop(&mut self) {
            PROJECT_READ_SUPPRESSION_DEPTH.with(|depth| depth.set(self.0));
        }
    }
    let _suppression = RestoreSuppression(PROJECT_READ_SUPPRESSION_DEPTH.with(|depth| {
        let previous = depth.get();
        depth.set(previous + 1);
        previous
    }));
    let slot = ProjectReadSlot::default();
    let mut guard = slot.enter(None, ProjectRead::Unattributed);
    guard.outermost = false;
    build()
}

/// Obtain the optional capability carried by legacy custom project types.
pub fn listing_read(project: &(impl Project + ?Sized)) -> Option<ProjectListingRead<'_>> {
    project
        .project_read_slot()
        .map(|slot| slot.listing(project.as_project()))
}

/// Concrete adapter usable by object-safe sources in language core crates.
#[derive(Clone, Debug)]
pub struct ErasedMemoAttribution(pub(crate) ReadCapability);
impl super::memo_attribution::MemoAttribution for ErasedMemoAttribution {
    type Key = OpaqueReadReceipt;
    fn is_capturing(&self) -> bool {
        self.0.0.is_capturing()
    }
    fn capture_identity(&self) -> Option<super::memo_attribution::CaptureIdentity> {
        self.0.0.capture_identity()
    }
    fn record_unattributed(&self) {
        self.0.0.record_unattributed();
    }
    fn capture<T>(
        &self,
        build: impl FnOnce() -> T,
    ) -> (
        T,
        super::memo_attribution::CapturedMemoReads<Self::Key>,
        Option<super::memo_attribution::CaptureIdentity>,
    ) {
        self.capture_value(build, |backend, build| backend.capture(build))
    }
    fn capture_authority<T>(
        &self,
        build: impl FnOnce() -> T,
    ) -> (T, super::memo_attribution::CapturedMemoReads<Self::Key>) {
        let (value, reads, _) =
            self.capture_value(build, |backend, build| backend.capture_authority(build));
        (value, reads)
    }
    fn replay(&self, reads: &super::memo_attribution::CapturedMemoReads<Self::Key>) {
        self.0.0.replay(
            &reads.keys,
            reads.unattributed_reads,
            reads.execution_dependences,
        );
    }
}
impl ErasedMemoAttribution {
    fn capture_value<T>(
        &self,
        build: impl FnOnce() -> T,
        capture: impl FnOnce(&dyn ErasedReadAttribution, &mut dyn FnMut()) -> ErasedCapturedReads,
    ) -> (
        T,
        super::memo_attribution::CapturedMemoReads<OpaqueReadReceipt>,
        Option<super::memo_attribution::CaptureIdentity>,
    ) {
        let mut build = Some(build);
        let mut value = None;
        let reads = capture(self.0.0.as_ref(), &mut || {
            value = Some(build
                .take()
                .expect("capture invokes its builder exactly once")(
            ));
        });
        (
            value.expect("capture invokes its builder"),
            super::memo_attribution::CapturedMemoReads {
                keys: Arc::from([reads.receipt]),
                unattributed_reads: reads.unattributed_reads,
                execution_dependences: reads.execution_dependences,
            },
            reads.forwarded_to,
        )
    }
}
