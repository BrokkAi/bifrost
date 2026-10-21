//! Dormant Python environment summaries. The unstable native validation entry
//! stages file-local inputs in SQL; only the shared reconciler persists outputs.
//! No production parser, reader or workspace-build hook invokes this module.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use super::resolution_publication::{ResolutionContentInput, ResolutionContentPublicationOutcome};
use super::unit_summaries::{
    self, ConsumedDependency, UnitContainer, UnitGap, UnitInputs, UnitMember, UnitOutputs,
    UnitPlacement, UnitRead, UnitSummaryLanguage,
};
use super::{
    AnalyzerStore, PreparedParsedBlobPreparation, Result, StoreError, WorkspaceId,
    WorkspaceSnapshotId,
};
use crate::CancellationToken;
use crate::analyzer::store::file_state::FileState;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::analyzer::{Language, ProjectFile};
use brokk_bifrost_core::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PythonNativeCuratedSurface, PythonNativeExportOperationKind,
    PythonNativeImportForm, PythonNativeWildcardPolicy, ResolutionIdentifierRole,
};
use rusqlite::{Connection, OptionalExtension, params};

/// Authority for placement, separate from execution or installed-provider proof.
#[derive(Clone, Debug)]
pub enum PythonSummaryAuthority {
    /// Selected Project packaging and package-marker evidence; order is unknown.
    Workspace,
    /// Explicit roots supplied by the native validation caller, not sys.path proof.
    SuppliedAnalysis,
    /// Retained identity of an already checked declared runtime environment.
    /// This digest is NOT the request-lived provider proof.
    CheckedRuntime { project_config_digest: [u8; 32] },
}
impl PythonSummaryAuthority {
    fn label(&self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::SuppliedAnalysis => "supplied_analysis",
            Self::CheckedRuntime { .. } => "checked_runtime",
        }
    }
}

/// Runtime and typing inventories never stand in for one another.
#[derive(Clone, Copy, Debug)]
pub enum PythonSummaryObservation {
    Runtime,
    Typing,
}
impl PythonSummaryObservation {
    fn label(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Typing => "typing",
        }
    }
}

/// Selected inputs only. Roots are configuration, not a retained module index.
#[derive(Clone, Debug)]
pub struct PythonSummaryProfile {
    pub authority: PythonSummaryAuthority,
    pub observation: PythonSummaryObservation,
    pub roots: Vec<PathBuf>,
    pub ordered: bool,
    /// Exact target/model-selection identity. Unknown target uses zero, and
    /// cannot certify external absence or select a stub as runtime source.
    pub target_digest: [u8; 32],
}
impl PythonSummaryProfile {
    fn digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"python-environment-profile:v1");
        hash.field("authority", self.authority.label().as_bytes());
        hash.field("observation", self.observation.label().as_bytes());
        hash.field("ordered", &[u8::from(self.ordered)]);
        hash.field("target", &self.target_digest);
        if let PythonSummaryAuthority::CheckedRuntime {
            project_config_digest,
        } = self.authority
        {
            hash.field("declared-environment", &project_config_digest);
        }
        for root in &self.roots {
            hash.field("root", portable(root).as_bytes());
        }
        hash.finish()
    }
}

/// Receipt counts summary reconciliation separately from parse/lowering input work.
#[derive(Debug)]
pub struct PythonSummaryReceipt {
    pub elapsed_micros: u128,
    pub statements: usize,
    pub rows_written: usize,
    pub derived: usize,
    pub unchanged: usize,
    pub cancelled: bool,
    pub failed: Vec<(String, String)>,
}

const STAGING: &str = "
CREATE TEMP TABLE IF NOT EXISTS py_env_config(path TEXT PRIMARY KEY, digest BLOB NOT NULL CHECK(length(digest)=32)) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS py_env_files(
 rel_path TEXT PRIMARY KEY, blob_id INTEGER NOT NULL, blob_oid TEXT NOT NULL, scope INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS py_env_roots(slot INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE);
CREATE TEMP TABLE IF NOT EXISTS py_env_candidates(
 container TEXT PRIMARY KEY, module TEXT NOT NULL, parent TEXT NOT NULL, depth INTEGER NOT NULL,
 root INTEGER NOT NULL, kind TEXT NOT NULL, rel_path TEXT NOT NULL, blob_id INTEGER, scope INTEGER,
 state TEXT NOT NULL DEFAULT 'open', provider_digest BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS temp.py_env_candidates_name ON py_env_candidates(module,root,kind);
CREATE INDEX IF NOT EXISTS temp.py_env_candidates_parent ON py_env_candidates(parent,state,root);
CREATE TEMP TABLE IF NOT EXISTS py_env_imports(
 rel_path TEXT NOT NULL, site INTEGER NOT NULL, level INTEGER NOT NULL, form TEXT NOT NULL,
 requested TEXT NOT NULL, bound TEXT NOT NULL, PRIMARY KEY(rel_path,site)
) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS py_env_segments(
 rel_path TEXT NOT NULL, site INTEGER NOT NULL, ordinal INTEGER NOT NULL, name TEXT NOT NULL,
 PRIMARY KEY(rel_path,site,ordinal)
) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS py_env_surfaces(
 rel_path TEXT NOT NULL, surface TEXT NOT NULL, policy TEXT NOT NULL,
 PRIMARY KEY(rel_path,surface)
) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS py_env_names(
 rel_path TEXT NOT NULL, surface TEXT NOT NULL, name TEXT NOT NULL, site INTEGER,
 PRIMARY KEY(rel_path,surface,name)
) WITHOUT ROWID;
CREATE TEMP TABLE IF NOT EXISTS py_env_routes(
 rel_path TEXT NOT NULL, site INTEGER NOT NULL, importer TEXT NOT NULL, target TEXT NOT NULL,
 module TEXT NOT NULL, level INTEGER NOT NULL, requested TEXT NOT NULL, bound TEXT NOT NULL,
 form TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(rel_path,site,importer,target)
) WITHOUT ROWID;";
const CLEAR: &str = "DELETE FROM temp.py_env_routes; DELETE FROM temp.py_env_names;
DELETE FROM temp.py_env_surfaces; DELETE FROM temp.py_env_segments; DELETE FROM temp.py_env_imports;
DELETE FROM temp.py_env_candidates; DELETE FROM temp.py_env_roots; DELETE FROM temp.py_env_files; DELETE FROM temp.py_env_config;";

pub fn portable(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
fn key(domain: &'static [u8], parts: &[&str]) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(domain);
    for part in parts {
        hash.field("part", part.as_bytes());
    }
    hash.finish()
}
fn unit_key() -> [u8; 32] {
    key(b"python-environment-unit:v1", &["default"])
}
fn container(root: i64, path: &Path, kind: &str) -> String {
    lower_hex_string(&key(
        b"python-environment-container:v1",
        &[&root.to_string(), &portable(path), kind],
    ))
}
fn logical_container(module: &str) -> String {
    lower_hex_string(&key(b"python-environment-module:v1", &[module]))
}

/// Explicit native test path. All source metadata is TEMP and must be restaged
/// after reconcile; persisted summary outputs can be read without that metadata.
pub struct PythonEnvironmentPublication {
    pub store: AnalyzerStore,
    pub snapshot: WorkspaceSnapshotId,
    pub profile: PythonSummaryProfile,
}
impl PythonEnvironmentPublication {
    pub fn open(path: &Path, profile: PythonSummaryProfile) -> Result<Self> {
        assert!(
            !profile.ordered || !matches!(profile.authority, PythonSummaryAuthority::Workspace)
        );
        if matches!(
            profile.authority,
            PythonSummaryAuthority::CheckedRuntime { .. }
        ) {
            assert_eq!(
                profile.roots.len(),
                1,
                "checked runtime has exactly one source root"
            );
        }
        for root in &profile.roots {
            assert!(root.components().all(|part| matches!(
                part,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )));
        }
        let mut store = AnalyzerStore::open_persistent(path)?;
        // Native validation sessions need connection-private TEMP inventories even
        // when another profile uses the same database and persistent writer actor.
        store.conn = super::writer::StoreWriter::local(
            crate::cache_db::open_unified_connection(path).map_err(super::StoreError::new)?,
        );
        *store.crate_statement_counter.lock().expect("counter lock") =
            Some(Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        let generation = store
            .ensure_language_epoch_value("python", "python-native-environment-validation-v1")?;
        store.ensure_resolution_producer_epoch("python", Language::Python)?;
        let snapshot = WorkspaceSnapshotId {
            workspace_id: WorkspaceId("e".repeat(64)),
            lang: "python".to_owned(),
            generation,
            revision: 1,
        };
        let result = Self {
            store,
            snapshot,
            profile,
        };
        result.begin(1)?;
        Ok(result)
    }

    /// Select a revision and discard the previous pass's TEMP input inventory.
    pub fn begin(&self, revision: i64) -> Result<()> {
        let mut snapshot = self.snapshot.clone();
        snapshot.revision = revision;
        self.store.conn.execute(move |conn| -> Result<()> {
            conn.execute_batch(STAGING)?;
            conn.execute_batch(CLEAR)?;
            conn.execute("INSERT OR IGNORE INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,'python',?2,?3)",
                params![snapshot.workspace_id.as_str(), snapshot.generation.get(), snapshot.revision])?;
            Ok(())
        })
    }

    pub fn stage_configuration(&self, inputs: Vec<(String, [u8; 32])>) -> Result<()> {
        self.store.conn.execute(move |conn| -> Result<()> {
            for (path, digest) in inputs {
                conn.execute(
                    "INSERT OR IGNORE INTO temp.py_env_config VALUES(?1,?2)",
                    params![path, digest.as_slice()],
                )?;
                let selected: Vec<u8> = conn.query_row(
                    "SELECT digest FROM temp.py_env_config WHERE path=?1",
                    [&path],
                    |row| row.get(0),
                )?;
                assert_eq!(
                    selected, digest,
                    "configuration inputs must share one selected Project: {path}"
                );
            }
            Ok(())
        })
    }

    /// Publish one prepared selected source, then stage its file-local facts.
    /// The language crate owns parsing; preparation artifacts die here.
    #[allow(clippy::too_many_arguments)]
    pub fn stage_prepared_source<A: LanguageAdapter>(
        &self,
        file: ProjectFile,
        syntax: &PreparedSyntaxTree,
        oid: git2::Oid,
        adapter: &A,
        state: Arc<FileState>,
        revision: i64,
        facts: FileResolutionFacts,
        roots: Vec<PathBuf>,
    ) -> Result<()> {
        let generations = [("python".to_owned(), self.snapshot.generation)]
            .into_iter()
            .collect();
        let prepared = AnalyzerStore::prepare_parsed_blob_at_generations(
            &file,
            syntax,
            oid,
            "python",
            &generations,
            adapter,
            state,
            &[],
            &CancellationToken::default(),
        )?;
        let PreparedParsedBlobPreparation::Prepared(prepared) = prepared else {
            return Err(StoreError::new("native Python preparation was cancelled"));
        };
        let mut snapshot = self.snapshot.clone();
        snapshot.revision = revision;
        // The explicit native harness bridges cached admission and publication.
        // Keep that pair atomic with respect to other harness sessions: a second
        // profile must not replace identical blob rows and cascade old summaries.
        // This bounded lock retains no workspace data and is never on production.
        static PUBLICATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let publication_guard = PUBLICATION.lock().expect("native publication lock");
        let cached = self.store.admit_cached_selected_content(
            &snapshot,
            &portable(file.rel_path()),
            oid,
            &ResolutionContentInput::Parsed {
                content_oid: oid,
                semantic_language: Language::Python,
            },
            &CancellationToken::default(),
        )?;
        let published = if matches!(cached, ResolutionContentPublicationOutcome::Ready(_)) {
            cached
        } else {
            self.store.publish_selected_parsed_content(
                &snapshot,
                &portable(file.rel_path()),
                *prepared,
                &CancellationToken::default(),
            )?
        };
        drop(publication_guard);
        let ResolutionContentPublicationOutcome::Ready(content) = published else {
            return Err(StoreError::new(format!(
                "native Python publication: {published:?}"
            )));
        };
        let blob_id = content.witness().blob_id();
        self.stage_facts(file, oid.to_string(), blob_id, facts, roots)
    }

    pub fn stage_facts(
        &self,
        file: ProjectFile,
        oid: String,
        blob_id: i64,
        facts: FileResolutionFacts,
        roots: Vec<PathBuf>,
    ) -> Result<()> {
        self.store
            .conn
            .execute(move |conn| stage_file(conn, &file, &oid, blob_id, &facts, &roots))
    }

    pub fn reconcile(
        &self,
        revision: i64,
        cancellation: &CancellationToken,
    ) -> Result<PythonSummaryReceipt> {
        let mut snapshot = self.snapshot.clone();
        snapshot.revision = revision;
        let started = Instant::now();
        let report = self.store.reconcile_unit_summaries(
            &snapshot,
            PythonUnitSummaries {
                profile: self.profile.clone(),
            },
            cancellation,
        )?;
        Ok(PythonSummaryReceipt {
            elapsed_micros: started.elapsed().as_micros(),
            statements: report.statements,
            rows_written: report.rows_written,
            derived: report.derived,
            unchanged: report.unchanged,
            cancelled: report.cancelled,
            failed: report.failed,
        })
    }

    /// Read only persisted rows under the selected profile and revision.
    pub fn render(&self, revision: i64) -> Result<String> {
        let mut snapshot = self.snapshot.clone();
        snapshot.revision = revision;
        let profile = self.profile.clone();
        self.store
            .conn
            .execute(move |conn| render(conn, &snapshot, &profile))
    }
}

fn stage_file(
    conn: &Connection,
    file: &ProjectFile,
    oid: &str,
    blob_id: i64,
    facts: &FileResolutionFacts,
    roots: &[PathBuf],
) -> Result<()> {
    let path = portable(file.rel_path());
    let scope = facts
        .python_export_surfaces
        .first()
        .expect("Python module surface")
        .module_scope;
    conn.execute(
        "INSERT INTO temp.py_env_files VALUES(?1,?2,?3,?4)",
        params![path, blob_id, oid, scope.get()],
    )?;
    let name = |id: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId| {
        &facts.names[id.index()].spelling
    };
    for (ordinal, root) in roots.iter().enumerate() {
        let root = root
            .components()
            .filter(|part| !matches!(part, std::path::Component::CurDir))
            .collect::<PathBuf>();
        let root_path = portable(&root);
        // Workspace roots are discovered file by file. Slot identity cannot
        // depend on enumeration order or a SQLite row allocation.
        let digest = key(b"python-root-slot:v1", &[&root_path]);
        let unordered_slot =
            i64::from_be_bytes(digest[..8].try_into().expect("eight bytes")) & i64::MAX;
        let slot = if roots.len() == 1 {
            unordered_slot
        } else {
            ordinal as i64
        };
        conn.execute(
            "INSERT OR IGNORE INTO temp.py_env_roots VALUES(?1,?2)",
            params![slot, root_path],
        )?;
        let Ok(relative) = file.rel_path().strip_prefix(&root) else {
            continue;
        };
        let is_init = relative.file_stem().is_some_and(|name| name == "__init__");
        let parent = relative.parent().expect("relative source parent");
        // A literal dot in a path component is not a dotted-name separator.
        // Such files stay unplaced rather than aliasing e.g. a/b.py to a.b.py.
        if relative
            .file_stem()
            .and_then(|part| part.to_str())
            .is_none_or(|part| part.contains('.'))
            || parent.components().any(|part| {
                part.as_os_str()
                    .to_str()
                    .is_none_or(|part| part.contains('.'))
            })
        {
            continue;
        }
        let mut components = Vec::new();
        for part in parent.components() {
            components.push(part.as_os_str().to_string_lossy().into_owned());
            let module = components.join(".");
            let parent_module = components[..components.len() - 1].join(".");
            let directory: PathBuf = parent.components().take(components.len()).collect();
            let absolute_relative = root.join(&directory);
            let provider = container(slot, &absolute_relative, "namespace");
            conn.execute("INSERT OR IGNORE INTO temp.py_env_candidates(container,module,parent,depth,root,kind,rel_path,provider_digest) VALUES(?1,?2,?3,?4,?5,'namespace',?6,?7)",
                params![provider,module,parent_module,components.len() as i64,slot,portable(&absolute_relative),key(b"python-namespace-provider:v1", &[&root_path,&module]).as_slice()])?;
        }
        let parent_module;
        let kind;
        if is_init {
            if components.is_empty() {
                continue;
            }
            parent_module = components[..components.len() - 1].join(".");
            kind = "package";
        } else {
            parent_module = components.join(".");
            components.push(
                relative
                    .file_stem()
                    .expect("Python file stem")
                    .to_string_lossy()
                    .into_owned(),
            );
            kind = "module";
        }
        let module = components.join(".");
        let provider = container(slot, file.rel_path(), kind);
        conn.execute("INSERT INTO temp.py_env_candidates(container,module,parent,depth,root,kind,rel_path,blob_id,scope,provider_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![provider,module,parent_module,components.len() as i64,slot,kind,path,blob_id,scope.get(),key(b"python-source-provider:v1", &[&root_path,&path,kind]).as_slice()])?;
    }
    for import in &facts.python_imports {
        let route = facts
            .import_routes
            .iter()
            .find(|route| route.site == import.import_site)
            .expect("Python import route");
        let mut segments: Vec<_> = facts
            .import_route_segments
            .iter()
            .filter(|segment| segment.import_site == import.import_site)
            .collect();
        segments.sort_by_key(|segment| segment.ordinal);
        let requested = if matches!(import.form, PythonNativeImportForm::From) {
            name(segments[import.module_segment_count as usize].name).as_str()
        } else {
            ""
        };
        let form = match import.form {
            PythonNativeImportForm::Module => "module",
            PythonNativeImportForm::From => "from",
            PythonNativeImportForm::Star => "star",
        };
        conn.execute(
            "INSERT INTO temp.py_env_imports VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                path,
                import.import_site.get(),
                import.relative_level,
                form,
                requested,
                route.bound_name.map(name).map(String::as_str).unwrap_or("")
            ],
        )?;
        for segment in segments
            .into_iter()
            .take(import.module_segment_count as usize)
        {
            conn.execute(
                "INSERT INTO temp.py_env_segments VALUES(?1,?2,?3,?4)",
                params![
                    path,
                    import.import_site.get(),
                    segment.ordinal,
                    name(segment.name)
                ],
            )?;
        }
    }
    let surface = facts
        .python_export_surfaces
        .first()
        .expect("module surface");
    let curated = match surface.curated {
        PythonNativeCuratedSurface::Absent => "absent",
        PythonNativeCuratedSurface::Listed => "curated",
        PythonNativeCuratedSurface::Unreadable => "unknown",
    };
    let wildcard = match surface.wildcard_policy {
        PythonNativeWildcardPolicy::PublicNames => "public_names",
        PythonNativeWildcardPolicy::Curated => "curated",
        PythonNativeWildcardPolicy::Unknown => "unknown",
    };
    for (surface, policy) in [
        ("module", "slots"),
        ("wildcard", wildcard),
        ("curated", curated),
    ] {
        conn.execute(
            "INSERT INTO temp.py_env_surfaces VALUES(?1,?2,?3)",
            params![path, surface, policy],
        )?;
    }
    for export in &facts.root_exports {
        let site = facts
            .sites
            .iter()
            .find(|site| site.id == export.declaration)
            .expect("export slot site");
        if site.scope != scope {
            continue;
        }
        for identifier in facts.identifiers.iter().filter(|identifier| {
            identifier.site == site.id && identifier.role == ResolutionIdentifierRole::Declaration
        }) {
            conn.execute(
                "INSERT OR IGNORE INTO temp.py_env_names VALUES(?1,'module',?2,?3)",
                params![path, name(identifier.name), site.id.get()],
            )?;
        }
    }
    // Only the producer's readable straight-line fold certifies membership.
    // Literal observations inside an unreadable operation are not final names.
    if curated == "curated" {
        let replacement = facts
            .python_export_operations
            .iter()
            .rposition(|operation| {
                operation.readable
                    && matches!(
                        operation.kind,
                        PythonNativeExportOperationKind::ReplaceList
                            | PythonNativeExportOperationKind::ReplaceTuple
                    )
            })
            .expect("listed exports have a readable replacement");
        for operation in &facts.python_export_operations[replacement..] {
            assert!(operation.readable);
            if matches!(
                operation.kind,
                PythonNativeExportOperationKind::ReplaceList
                    | PythonNativeExportOperationKind::ReplaceTuple
                    | PythonNativeExportOperationKind::Delete
            ) {
                conn.execute(
                    "DELETE FROM temp.py_env_names WHERE rel_path=?1 AND surface='curated'",
                    [&path],
                )?;
            }
            for member in facts
                .python_export_members
                .iter()
                .filter(|member| member.operation_ordinal == operation.ordinal)
            {
                conn.execute(
                    "INSERT OR IGNORE INTO temp.py_env_names VALUES(?1,'curated',?2,NULL)",
                    params![path, name(member.name)],
                )?;
            }
        }
        conn.execute("UPDATE temp.py_env_names SET site=(SELECT slots.site FROM temp.py_env_names AS slots WHERE slots.rel_path=?1 AND slots.surface='module' AND slots.name=py_env_names.name) WHERE rel_path=?1 AND surface='curated'", [&path])?;
    }
    match wildcard {
        "public_names" => {
            conn.execute("INSERT INTO temp.py_env_names SELECT rel_path,'wildcard',name,site FROM temp.py_env_names WHERE rel_path=?1 AND surface='module' AND substr(name,1,1)<>'_'", [&path])?;
        }
        "curated" => {
            conn.execute("INSERT INTO temp.py_env_names SELECT rel_path,'wildcard',name,site FROM temp.py_env_names WHERE rel_path=?1 AND surface='curated'", [&path])?;
        }
        _ => {}
    }
    Ok(())
}

struct PythonUnitSummaries {
    profile: PythonSummaryProfile,
}
const LIVE: &str = unit_summaries::live_summary_select!("?8");
impl UnitSummaryLanguage for PythonUnitSummaries {
    fn lang(&self) -> &'static str {
        "python"
    }
    fn unit_kind(&self) -> &'static str {
        "python_environment"
    }
    fn derivation_version(&self) -> i64 {
        1
    }
    fn profile_digest(&self) -> [u8; 32] {
        self.profile.digest()
    }
    fn live_summary(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        epoch: &str,
        unit: &[u8; 32],
    ) -> Result<Option<(i64, Vec<u8>)>> {
        Ok(conn
            .query_row(
                LIVE,
                params![
                    snapshot.workspace_id.as_str(),
                    "python",
                    snapshot.generation.get(),
                    unit.as_slice(),
                    snapshot.revision,
                    epoch,
                    1,
                    self.profile.digest().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }
    fn stage(&self, conn: &Connection, _snapshot: &WorkspaceSnapshotId) -> Result<()> {
        let members: i64 = conn.query_row("SELECT count(*) FROM temp.py_env_files", [], |row| {
            row.get(0)
        })?;
        if members == 0 {
            return Ok(());
        }
        conn.execute("INSERT INTO temp.unit_summary_work VALUES(1)", [])?;
        // Component traversal is a Python filesystem placement rule. The shared
        // summary driver still owns recursion scheduling, publication and reuse.
        // Only the current depth's query rows live on the Rust heap.
        let max_depth: i64 = conn.query_row(
            "SELECT coalesce(max(depth),0) FROM temp.py_env_candidates",
            [],
            |row| row.get(0),
        )?;
        for depth in 1..=max_depth {
            // A child is admitted only by selected regular/namespace parents
            // from the SAME root. A module file is not a package search path.
            conn.execute("UPDATE temp.py_env_candidates AS child SET state='alternative' WHERE depth=?1 AND (parent='' OR EXISTS(SELECT 1 FROM temp.py_env_candidates AS parent WHERE parent.module=child.parent AND parent.root=child.root AND parent.kind IN ('package','namespace') AND parent.state IN ('selected','alternative')))", [depth])?;
            // In one root, a regular package wins over its same-name module and
            // provisional namespace portion; a module wins over namespace.
            conn.execute("UPDATE temp.py_env_candidates AS candidate SET state='shadowed' WHERE depth=?1 AND state='alternative' AND EXISTS(SELECT 1 FROM temp.py_env_candidates AS winner WHERE winner.module=candidate.module AND winner.root=candidate.root AND winner.state='alternative' AND (CASE winner.kind WHEN 'package' THEN 0 WHEN 'module' THEN 1 ELSE 2 END)<(CASE candidate.kind WHEN 'package' THEN 0 WHEN 'module' THEN 1 ELSE 2 END))", [depth])?;
            if self.profile.ordered {
                conn.execute("UPDATE temp.py_env_candidates AS candidate SET state='shadowed' WHERE depth=?1 AND state='alternative' AND EXISTS(SELECT 1 FROM temp.py_env_candidates AS winner WHERE winner.module=candidate.module AND winner.state='alternative' AND winner.kind<>'namespace' AND (candidate.kind='namespace' OR winner.root<candidate.root))", [depth])?;
            }
            conn.execute("UPDATE temp.py_env_candidates AS candidate SET state='selected' WHERE depth=?1 AND state='alternative' AND (parent='' OR EXISTS(SELECT 1 FROM temp.py_env_candidates AS enclosing WHERE enclosing.module=candidate.parent AND enclosing.root=candidate.root AND enclosing.state='selected')) AND (NOT EXISTS(SELECT 1 FROM temp.py_env_candidates AS other WHERE other.module=candidate.module AND other.state='alternative' AND other.container<>candidate.container) OR NOT EXISTS(SELECT 1 FROM temp.py_env_candidates AS concrete WHERE concrete.module=candidate.module AND concrete.state='alternative' AND concrete.kind<>'namespace'))", [depth])?;
        }
        build_routes(conn)?;
        Ok(())
    }
    fn clear_stage(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(CLEAR)?;
        Ok(())
    }
    fn inputs(
        &self,
        conn: &Connection,
        _snapshot: &WorkspaceSnapshotId,
        unit_id: i64,
    ) -> Result<UnitInputs> {
        let members = conn
            .prepare("SELECT blob_id,blob_oid,rel_path FROM temp.py_env_files ORDER BY rel_path")?
            .query_map([], |row| {
                Ok(UnitMember {
                    blob_id: row.get(0)?,
                    blob_oid: row.get(1)?,
                    rel_path: row.get(2)?,
                    source_role: "python".into(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut containers = vec![UnitContainer {
            path: String::new(),
            parent_path: None,
        }];
        let mut statement = conn
            .prepare("SELECT DISTINCT module,parent FROM temp.py_env_candidates ORDER BY module")?;
        for row in statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (module, parent) = row?;
            containers.push(UnitContainer {
                path: logical_container(&module),
                parent_path: Some(if parent.is_empty() {
                    String::new()
                } else {
                    logical_container(&parent)
                }),
            });
        }
        let mut placements = Vec::new();
        let ordinals = super::unit_summaries::member_ordinals(&members);
        let mut statement=conn.prepare("SELECT container,module,blob_id,rel_path,scope FROM temp.py_env_candidates ORDER BY container")?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })? {
            let (container, module, blob, path, scope) = row?;
            containers.push(UnitContainer {
                path: container.clone(),
                parent_path: Some(logical_container(&module)),
            });
            if let Some(blob) = blob {
                placements.push(UnitPlacement {
                    container_path: container,
                    member_ordinal: ordinals[&(blob, path.as_str(), "python")],
                    scope_ordinal: scope,
                });
            }
        }
        // Roots are authority inputs too, including negative __init__ observations
        // implied by the complete selected source membership. Read digests include
        // TEMP syntax but never SQLite blob ids or allocation order.
        let digest = staging_input_digest(conn)?;
        Ok(UnitInputs {
            unit_id,
            unit_key: unit_key(),
            label: "Python environment".into(),
            members,
            reads: vec![
                UnitRead {
                    kind: "configuration",
                    key_digest: key(b"python-summary-read:v1", &["profile"]),
                    digest: self.profile.digest(),
                },
                UnitRead {
                    kind: "context_publication",
                    key_digest: key(b"python-summary-read:v1", &["inventory"]),
                    digest,
                },
            ],
            dependencies: Vec::new(),
            dependency_names: Vec::new(),
            containers,
            placements,
        })
    }
    fn derive(
        &self,
        conn: &Connection,
        _snapshot: &WorkspaceSnapshotId,
        _unit: &UnitInputs,
        _dependencies: &[ConsumedDependency],
        _epoch: &str,
    ) -> Result<UnitOutputs> {
        let mut gaps = vec![UnitGap { kind:"python_environment_open",subject:"provider/activation/package_path".into(),
            detail:"{\"activation\":\"unproven\",\"package_path\":\"dynamic_uninspected\",\"external_providers\":\"unacquired\"}".into() }];
        let mut statement=conn.prepare("SELECT rel_path FROM temp.py_env_files AS files WHERE NOT EXISTS(SELECT 1 FROM temp.py_env_candidates AS provider WHERE provider.blob_id IS NOT NULL AND provider.rel_path=files.rel_path) ORDER BY rel_path")?;
        for row in statement.query_map([], |row| row.get::<_, String>(0))? {
            gaps.push(UnitGap {
                kind: "python_unknown_placement",
                subject: row?,
                detail: "{}".into(),
            });
        }
        Ok(UnitOutputs {
            exports: Vec::new(),
            imports: Vec::new(),
            complete: false,
            gaps,
            public_surface_digest: Some({
                let mut hash = CanonicalHasher::new(b"python-summary-public:v1");
                hash.field("profile", &self.profile.digest());
                hash.field("relations", &public_surface_digest(conn)?);
                hash.finish()
            }),
        })
    }
    fn write_language_rows(
        &self,
        conn: &Connection,
        _snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        _dependencies: &[ConsumedDependency],
        summary: i64,
    ) -> Result<usize> {
        let before = conn.total_changes();
        // Replacement of a corrupt/incomplete shared summary may reuse its id.
        conn.execute(
            "DELETE FROM python_unit_summary_roots WHERE summary_id=?1",
            [summary],
        )?;
        let mut roots = conn.prepare("SELECT slot,path FROM temp.py_env_roots ORDER BY slot")?;
        for row in roots.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })? {
            let (slot, path) = row?;
            conn.execute(
                "INSERT INTO python_unit_summary_roots VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    summary,
                    slot,
                    path,
                    self.profile.authority.label(),
                    self.profile.ordered,
                    self.profile.observation.label(),
                    self.profile.target_digest.as_slice()
                ],
            )?;
        }
        let ordinals = super::unit_summaries::member_ordinals(&unit.members);
        let mut statement=conn.prepare("SELECT container,module,parent,root,kind,state,rel_path,blob_id,provider_digest FROM temp.py_env_candidates ORDER BY container")?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })? {
            let (container, module, parent, root, kind, state, path, blob, digest) = row?;
            let ordinal = blob.map(|blob| ordinals[&(blob, path.as_str(), "python")] as i64);
            conn.execute(
                "INSERT INTO python_unit_summary_providers VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    summary, container, module, parent, root, kind, state, path, ordinal, digest
                ],
            )?;
        }
        for (ordinal, member) in unit.members.iter().enumerate() {
            conn.execute("INSERT INTO python_unit_summary_imports SELECT ?1,?2,site,importer,target,module,level,requested,bound,form,state FROM temp.py_env_routes WHERE rel_path=?3", params![summary,ordinal as i64,member.rel_path])?;
        }
        conn.execute("INSERT INTO python_unit_summary_surfaces SELECT ?1,providers.container,surfaces.surface,surfaces.policy FROM temp.py_env_candidates AS providers JOIN temp.py_env_surfaces AS surfaces ON surfaces.rel_path=providers.rel_path WHERE providers.blob_id IS NOT NULL", [summary])?;
        conn.execute("INSERT INTO python_unit_summary_export_names SELECT ?1,providers.container,names.surface,names.name,names.site FROM temp.py_env_candidates AS providers JOIN temp.py_env_names AS names ON names.rel_path=providers.rel_path WHERE providers.blob_id IS NOT NULL", [summary])?;
        Ok((conn.total_changes() - before) as usize)
    }
}

fn build_routes(conn: &Connection) -> Result<()> {
    let mut statement=conn.prepare("SELECT imports.rel_path,imports.site,imports.level,imports.form,imports.requested,imports.bound,providers.container,roots.path FROM temp.py_env_imports AS imports JOIN temp.py_env_candidates AS providers ON providers.rel_path=imports.rel_path AND providers.blob_id IS NOT NULL JOIN temp.py_env_roots AS roots ON roots.slot=providers.root ORDER BY imports.rel_path,imports.site,providers.container")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        let site: i64 = row.get(1)?;
        let level: usize = row.get(2)?;
        let form: String = row.get(3)?;
        let requested: String = row.get(4)?;
        let bound: String = row.get(5)?;
        let importer: String = row.get(6)?;
        let root: String = row.get(7)?;
        let mut components = Vec::new();
        let mut valid = true;
        if level > 0 {
            let relative = Path::new(&path)
                .strip_prefix(Path::new(&root))
                .expect("placed path under selected root");
            components = relative
                .parent()
                .expect("source parent")
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect();
            if components.len() < level {
                valid = false;
            } else {
                components.truncate(components.len() - (level - 1));
            }
        }
        let mut segments = conn.prepare(
            "SELECT name FROM temp.py_env_segments WHERE rel_path=?1 AND site=?2 ORDER BY ordinal",
        )?;
        for segment in segments.query_map(params![path, site], |row| row.get::<_, String>(0))? {
            components.push(segment?);
        }
        let module = components.join(".");
        let mut targets=conn.prepare("SELECT container FROM temp.py_env_candidates WHERE module=?1 AND state IN ('selected','alternative') ORDER BY container")?;
        let targets = if valid {
            targets
                .query_map([&module], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        if targets.is_empty() {
            conn.execute(
                "INSERT INTO temp.py_env_routes VALUES(?1,?2,?3,'',?4,?5,?6,?7,?8,?9)",
                params![
                    path,
                    site,
                    importer,
                    module,
                    level as i64,
                    requested,
                    bound,
                    form,
                    if valid {
                        "provider_open"
                    } else {
                        "relative_context_open"
                    }
                ],
            )?;
        } else {
            for target in targets {
                conn.execute("INSERT INTO temp.py_env_routes VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'activation_open')",params![path,site,importer,target,module,level as i64,requested,bound,form])?;
            }
        }
    }
    // Files without any selected-root placement still retain their import sites.
    conn.execute("INSERT INTO temp.py_env_routes SELECT rel_path,site,'','','',level,requested,bound,form,'relative_context_open' FROM temp.py_env_imports AS imports WHERE NOT EXISTS(SELECT 1 FROM temp.py_env_candidates AS provider WHERE provider.rel_path=imports.rel_path AND provider.blob_id IS NOT NULL)",[])?;
    Ok(())
}

fn staging_input_digest(conn: &Connection) -> Result<[u8; 32]> {
    hash_queries(
        conn,
        &[
            "SELECT path FROM temp.py_env_roots ORDER BY path",
            "SELECT rel_path,surface,policy FROM temp.py_env_surfaces ORDER BY rel_path,surface",
            "SELECT rel_path,surface,name,site FROM temp.py_env_names ORDER BY rel_path,surface,name",
            "SELECT rel_path,site,level,form,requested,bound FROM temp.py_env_imports ORDER BY rel_path,site",
            "SELECT rel_path,site,ordinal,name FROM temp.py_env_segments ORDER BY rel_path,site,ordinal",
        ],
    )
}
fn public_surface_digest(conn: &Connection) -> Result<[u8; 32]> {
    hash_queries(
        conn,
        &[
            "SELECT path FROM temp.py_env_roots ORDER BY path",
            "SELECT container,module,parent,root,kind,state,rel_path,provider_digest FROM temp.py_env_candidates ORDER BY container",
            "SELECT rel_path,surface,policy FROM temp.py_env_surfaces AS surfaces WHERE EXISTS(SELECT 1 FROM temp.py_env_candidates AS provider WHERE provider.blob_id IS NOT NULL AND provider.rel_path=surfaces.rel_path) ORDER BY rel_path,surface",
            "SELECT rel_path,surface,name FROM temp.py_env_names AS names WHERE EXISTS(SELECT 1 FROM temp.py_env_candidates AS provider WHERE provider.blob_id IS NOT NULL AND provider.rel_path=names.rel_path) ORDER BY rel_path,surface,name",
            "SELECT DISTINCT rel_path,importer,target,module,level,requested,bound,form,state FROM temp.py_env_routes ORDER BY rel_path,importer,target,module,level,requested,bound,form,state",
        ],
    )
}
fn hash_queries(conn: &Connection, queries: &[&str]) -> Result<[u8; 32]> {
    let mut hash = CanonicalHasher::new(b"python-summary-relations:v1");
    for (ordinal, query) in queries.iter().enumerate() {
        // Relation positions belong to this derivation version, not SQL spelling.
        hash.field("relation", &(ordinal as u64).to_be_bytes());
        let mut statement = conn.prepare(query)?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            hash.field("row", b"");
            for column in 0..columns {
                use rusqlite::types::ValueRef;
                match row.get_ref(column)? {
                    ValueRef::Null => hash.field("null", b""),
                    ValueRef::Integer(value) => hash.field("integer", &value.to_be_bytes()),
                    ValueRef::Real(_) => unreachable!("summary relations have no real values"),
                    ValueRef::Text(value) => hash.field("text", value),
                    ValueRef::Blob(value) => hash.field("digest", value),
                }
            }
        }
    }
    Ok(hash.finish())
}

fn render(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    profile: &PythonSummaryProfile,
) -> Result<String> {
    use std::fmt::Write;
    let language = PythonUnitSummaries {
        profile: profile.clone(),
    };
    let epoch: String = conn.query_row(
        "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='python'",
        [],
        |row| row.get(0),
    )?;
    let Some((summary, digest)) = language.live_summary(conn, snapshot, &epoch, &unit_key())?
    else {
        return Ok("no live Python environment\n".into());
    };
    let mut output = format!(
        "authority={} observation={} ordered={}\nobligations=activation,package_path,external_providers\n",
        profile.authority.label(),
        profile.observation.label(),
        profile.ordered
    );
    let digest: [u8; 32] = digest
        .try_into()
        .expect("summary output digest is 32 bytes");
    writeln!(output, "surface_digest={}", lower_hex_string(&digest)).expect("String write");
    let queries = [
        (
            "gaps",
            "SELECT gap_kind,subject FROM resolution_unit_summary_gaps WHERE summary_id=?1 ORDER BY gap_kind,subject",
        ),
        (
            "roots",
            "SELECT root_path,authority,observation FROM python_unit_summary_roots WHERE summary_id=?1 ORDER BY root_path",
        ),
        (
            "providers",
            "SELECT module_name,kind,state,rel_path FROM python_unit_summary_providers WHERE summary_id=?1 ORDER BY module_name,rel_path,kind",
        ),
        (
            "imports",
            "SELECT members.rel_path,imports.import_site,importer.module_name,imports.module_name,coalesce(target.rel_path,''),imports.requested_name,imports.bound_name,imports.form,imports.state FROM python_unit_summary_imports AS imports JOIN resolution_unit_summary_members AS members ON members.summary_id=imports.summary_id AND members.member_ordinal=imports.member_ordinal LEFT JOIN python_unit_summary_providers AS importer ON importer.summary_id=imports.summary_id AND importer.container_path=imports.importer_container LEFT JOIN python_unit_summary_providers AS target ON target.summary_id=imports.summary_id AND target.container_path=imports.target_container WHERE imports.summary_id=?1 ORDER BY members.rel_path,imports.import_site,importer.rel_path,target.rel_path",
        ),
        (
            "surfaces",
            "SELECT providers.rel_path,surfaces.surface,surfaces.policy FROM python_unit_summary_surfaces AS surfaces JOIN python_unit_summary_providers AS providers USING(summary_id,container_path) WHERE summary_id=?1 ORDER BY providers.rel_path,surfaces.surface",
        ),
        (
            "names",
            "SELECT providers.rel_path,names.surface,names.name,CASE WHEN names.slot_site IS NULL THEN 'unbound' ELSE 'slot' END FROM python_unit_summary_export_names AS names JOIN python_unit_summary_providers AS providers USING(summary_id,container_path) WHERE summary_id=?1 ORDER BY providers.rel_path,names.surface,names.name",
        ),
    ];
    for (label, query) in queries {
        writeln!(output, "[{label}]").expect("String write");
        let mut statement = conn.prepare(query)?;
        let columns = statement.column_count();
        let mut rows = statement.query([summary])?;
        while let Some(row) = rows.next()? {
            for column in 0..columns {
                if column > 0 {
                    output.push_str(" | ");
                }
                match row.get_ref(column)? {
                    rusqlite::types::ValueRef::Text(value) => {
                        output.push_str(std::str::from_utf8(value).expect("UTF-8 SQL text"))
                    }
                    rusqlite::types::ValueRef::Integer(value) => {
                        write!(output, "{value}").expect("String write")
                    }
                    rusqlite::types::ValueRef::Null => output.push('-'),
                    _ => unreachable!("rendered scalar"),
                }
            }
            output.push('\n');
        }
    }
    Ok(output)
}
