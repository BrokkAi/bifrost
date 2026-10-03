#[path = "resolution_operation_go_member_tests.rs"]
mod go_member_tests;
#[path = "resolution_operation_go_spelling_tests.rs"]
mod go_spelling_tests;

use brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, ResolutionGapKind, ResolutionIdentifierRole, ResolutionMemberKind,
    ResolutionNamespace, ResolutionRootImportAnchor, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_rust::selected_context::{
    RustCallerTargetKind, RustCallerTargetProfile, RustSelectedManifestMount,
    RustSelectedSourceMount, RustSelectedTopologySourceMount, build_rust_selected_context,
};
use git2::ObjectType;
use git2::Oid;
use rusqlite::params;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tree_sitter::Parser;

use crate::CancellationToken;
use crate::analyzer::go::GoAdapter;
use crate::analyzer::java::JavaAdapter;
use crate::analyzer::resolution::{
    FactPageVisitor, FactReferenceBatchAnswer, FactResolutionBatchSummary,
    FactReverseResolutionMetrics, LoweredResolutionFactsWithIdentityCatalog, LoweredSemanticRole,
    PreloadedFactResolutionService, ResolutionBatchMetrics, ResolutionLookupSemanticRecipe,
    SelectedFactOperationBlueprintConstruction, SelectedResolutionContextSet,
    SelectedResolutionContextValidationOutcome, SelectedResolutionMountContext,
    SelectedRootBridgeDescriptor, SelectedSemanticLocator, SelectedTypedFactSource,
    reset_selected_fact_operation_construction_count_for_test,
    selected_fact_operation_construction_count_for_test, visit_selected_root_export_half_pages,
    visit_selected_root_import_half_pages,
};
use crate::analyzer::rust::RustAdapter;
use crate::analyzer::tree_sitter_analyzer::{FileState, LanguageAdapter, ParsedFile};
use crate::analyzer::{Language, OverlayProject, Project, ProjectFile, TestProject};

use super::super::resolution_selection::{
    SelectedResolutionContentMountRequest, SelectedResolutionLanguage,
    SelectedResolutionOverlayMask, SelectedResolutionStale, SelectedResolutionUnavailable,
};
use super::super::{
    AnalyzerStore, GenerationId, PersistBatchTargets, Result, StoreError,
    WorkspaceConfigurationInput, WorkspaceFileRow, WorkspaceId, WorkspacePackageFileRow,
    WorkspaceSnapshotId, WorkspaceSnapshots,
};
use super::*;

#[path = "resolution_operation_reverse_tests.rs"]
mod reverse_query_tests;

#[path = "resolution_operation_forward_tests.rs"]
mod forward_query_tests;

#[path = "resolution_operation_privacy_tests.rs"]
mod privacy_tests;

#[path = "resolution_operation/point_latency.rs"]
pub(super) mod point_latency;

const WORKSPACE_ID: &str = "7171717171717171717171717171717171717171717171717171717171717171";
const SOURCE_PATH: &str = "src/A_Source.java";
const PROVIDER_PATH: &str = "src/B_Provider.java";
const REMOVED_PATH: &str = "src/C_Removed.java";
const SECOND_REPLACEMENT_PATH: &str = "src/D_Replacement.java";
/// The git blob oid of `RICH_JAVA_SOURCE`, which every persisted Java mount in
/// these fixtures carries.
///
/// A persisted mount's blob oid is the oid of the bytes on disk, and the lazy
/// interior rehashes the file it reads to prove it still has the selected
/// revision's source. A synthetic oid therefore reads as a changed file.
fn persisted_oid() -> Oid {
    Oid::hash_object(ObjectType::Blob, RICH_JAVA_SOURCE.as_bytes())
        .expect("hash the operation fixture source")
}

const RICH_JAVA_SOURCE: &str = r#"
package com.acme;
import dep.A;
import dep.*;
import static dep.Owner.FIELD;
import static dep.Owner.*;

public class Outer extends HierarchyBase {
    public class Nested {}
    public static int FIELD;
    public int qualifiedField;

    public static int method(int parameter) {
        return parameter;
    }

    public int use(A value) {
        int sourceOrderLocal = FIELD;
        this.qualifiedField = sourceOrderLocal;
        return method(value.hashCode());
    }
}
"#;

// Actual provider text replaces the former package/binder fact mutation.
const PROVIDER_JAVA_SOURCE: &str = r#"
package dep;
import dep.A;
import dep.*;
import static dep.Owner.FIELD;
import static dep.Owner.*;

public class Owner extends HierarchyBase {
    public class Nested {}
    public static int FIELD;
    public int qualifiedField;

    public static int method(int parameter) {
        return parameter;
    }

    public int use(A value) {
        int sourceOrderLocal = FIELD;
        this.qualifiedField = sourceOrderLocal;
        return method(value.hashCode());
    }
}
"#;

fn parsed_java_state(
    project_root: &Path,
    relative_path: &str,
) -> (Arc<FileState>, FileResolutionFacts) {
    parsed_operation_state(project_root, relative_path, RICH_JAVA_SOURCE, &JavaAdapter)
}

#[derive(Clone)]
struct MutableGenerationProject {
    delegate: TestProject,
    generation: Arc<AtomicU64>,
    overlay_content: Arc<Mutex<Option<Arc<WorkspaceOverlayContent>>>>,
}

impl MutableGenerationProject {
    fn new(root: &Path, language: Language) -> Self {
        Self {
            delegate: TestProject::new(root, language),
            generation: Arc::new(AtomicU64::new(0)),
            overlay_content: Arc::new(Mutex::new(None)),
        }
    }

    fn generation_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.generation)
    }

    fn advance(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    fn set_overlay_content(&self, file: ProjectFile, content: &str) {
        let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(content.as_bytes());
        let overlay = Arc::new(WorkspaceOverlayContent::new([(file, digest)]));
        *self
            .overlay_content
            .lock()
            .expect("operation test overlay lock") = Some(overlay);
    }
}

impl Project for MutableGenerationProject {
    fn root(&self) -> &Path {
        self.delegate.root()
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.delegate.analyzer_languages()
    }

    fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
        self.delegate.all_files()
    }

    fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
        self.delegate.analyzable_files(language)
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        self.delegate.file_by_rel_path(rel_path)
    }

    fn analysis_generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
        self.overlay_content
            .lock()
            .expect("operation test overlay lock")
            .clone()
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProductionSelectedSqlCost {
    statements: Vec<String>,
    /// Rows decoded by the execution at the same index in `statements`.
    /// Each SQLite statement pointer identifies its latest traced execution,
    /// so an outer cursor retains its row ownership while nested statements
    /// execute. Reusing a statement pointer starts a new execution entry.
    rows_by_statement: Vec<usize>,
    /// SQLite schema parsing emits ROW for an internal statement with no SQL
    /// text and hence no STMT event. Keep these rows explicit, never assigned
    /// to the outer DDL or a recycled statement pointer.
    internal_schema_rows: usize,
    decoded_rows: usize,
}

impl ProductionSelectedSqlCost {
    fn statement_count(&self) -> usize {
        self.statements.len()
    }

    /// Decoded rows and executions grouped by statement text, most rows first.
    fn rows_by_shape(&self) -> Vec<(usize, usize, &str)> {
        assert_eq!(self.statements.len(), self.rows_by_statement.len());
        let mut totals: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for (sql, rows) in self.statements.iter().zip(self.rows_by_statement.iter()) {
            let entry = totals.entry(sql.as_str()).or_default();
            entry.0 += rows;
            entry.1 += 1;
        }
        let mut shapes = totals
            .into_iter()
            .map(|(sql, (rows, executions))| (rows, executions, sql))
            .collect::<Vec<_>>();
        if self.internal_schema_rows != 0 {
            shapes.push((
                self.internal_schema_rows,
                0,
                "<SQLite internal schema rows: no STMT event>",
            ));
        }
        assert_eq!(
            self.decoded_rows,
            self.rows_by_statement.iter().sum::<usize>() + self.internal_schema_rows
        );
        shapes.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.2.cmp(right.2)));
        shapes
    }
}

fn point_read_freshness_groups(cost: &ProductionSelectedSqlCost) -> usize {
    // Each selected read group starts with one complete freshness triple.
    // Check that structure as well as the measured number of groups, including
    // callable-result projections and one wildcard page per 120 mounts.
    let groups = cost
        .statements
        .split(|sql| sql == "PRAGMA main.data_version")
        .skip(1)
        .collect::<Vec<_>>();
    assert!(
        !groups.is_empty(),
        "selected point search must emit freshness groups"
    );
    for (index, group) in groups.iter().enumerate() {
        assert_eq!(
            group.first().map(String::as_str),
            Some("PRAGMA main.schema_version"),
            "freshness group {index} must read main schema version: {groups:?}"
        );
        assert_eq!(
            group.get(1).map(String::as_str),
            Some("PRAGMA temp.schema_version"),
            "freshness group {index} must read temp schema version: {groups:?}"
        );
    }
    let freshness_groups = groups.len();
    // Only the page containing the demanded lookup issues the keyed wildcard
    // probe. Empty foreign pages still perform their freshness checks.
    for pragma in [
        "PRAGMA main.data_version",
        "PRAGMA main.schema_version",
        "PRAGMA temp.schema_version",
    ] {
        assert_eq!(
            cost.statements.iter().filter(|sql| *sql == pragma).count(),
            freshness_groups,
            "every emitted selected read group must have one {pragma} boundary"
        );
    }
    freshness_groups
}

thread_local! {
    static PRODUCTION_SELECTED_SQL_TRACE: RefCell<Option<ProductionSelectedSqlCost>> =
        const { RefCell::new(None) };
    static PRODUCTION_SELECTED_SQL_EXECUTIONS: RefCell<crate::hash::HashMap<usize, usize>> =
        RefCell::new(crate::hash::HashMap::default());
    static TRACE_CONTEXT_PUBLICATION_WORK: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static TRACE_SELECTED_MOUNT_CALLERS: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static PRODUCTION_SELECTED_SQL_TRACE_FAILED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

// Scoped to the scaling diagnostic; unwind also restores the callback policy.
struct SelectedMountCallerTrace;

impl SelectedMountCallerTrace {
    fn begin() -> Self {
        TRACE_SELECTED_MOUNT_CALLERS.with(|enabled| assert!(!enabled.replace(true)));
        Self
    }
}

impl Drop for SelectedMountCallerTrace {
    fn drop(&mut self) {
        TRACE_SELECTED_MOUNT_CALLERS.with(|enabled| assert!(enabled.replace(false)));
    }
}

struct ContextPublicationWorkTrace;

impl ContextPublicationWorkTrace {
    fn begin() -> Self {
        TRACE_CONTEXT_PUBLICATION_WORK.with(|enabled| assert!(!enabled.replace(true)));
        Self
    }
}

impl Drop for ContextPublicationWorkTrace {
    fn drop(&mut self) {
        TRACE_CONTEXT_PUBLICATION_WORK.with(|enabled| assert!(enabled.replace(false)));
    }
}

pub(super) fn context_publication_work(
    session: &ResolutionSession,
) -> Option<ReceiverAnalysisWork> {
    TRACE_CONTEXT_PUBLICATION_WORK.with(|enabled| enabled.get().then(|| session.finish(()).work()))
}

unsafe extern "C" fn record_production_selected_sql(
    event: std::ffi::c_uint,
    _context: *mut std::ffi::c_void,
    statement: *mut std::ffi::c_void,
    raw_sql: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    let result = std::panic::catch_unwind(|| {
        PRODUCTION_SELECTED_SQL_TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            let trace = trace
                .as_mut()
                .expect("production selected SQL trace must be active");
            match event {
                rusqlite::ffi::SQLITE_TRACE_STMT => {
                    assert!(!raw_sql.is_null(), "SQLite statement trace must name SQL");
                    // SAFETY: SQLITE_TRACE_STMT supplies a callback-lifetime SQL C string.
                    let sql = unsafe { std::ffi::CStr::from_ptr(raw_sql.cast()) }
                        .to_string_lossy()
                        .into_owned();
                    if TRACE_SELECTED_MOUNT_CALLERS.with(std::cell::Cell::get)
                        && sql.starts_with("SELECT mount_ordinal,fragment_id,workspace_id")
                        && sql
                            .contains("FROM temp.selected_resolution_mounts WHERE mount_ordinal=?1")
                    {
                        eprintln!(
                            "selected mount-record caller: {}",
                            std::backtrace::Backtrace::force_capture()
                        );
                    }
                    assert!(!statement.is_null());
                    PRODUCTION_SELECTED_SQL_EXECUTIONS.with(|executions| {
                        executions
                            .borrow_mut()
                            .insert(statement as usize, trace.statements.len());
                    });
                    trace.statements.push(sql);
                    trace.rows_by_statement.push(0);
                }
                rusqlite::ffi::SQLITE_TRACE_ROW => {
                    trace.decoded_rows = trace
                        .decoded_rows
                        .checked_add(1)
                        .expect("production selected decoded row count fits usize");
                    // SAFETY: SQLITE_TRACE_ROW supplies a live sqlite3_stmt.
                    let sql = unsafe { rusqlite::ffi::sqlite3_sql(statement.cast()) };
                    // Bundled SQLite skips SetSql while init.busy, suppressing
                    // STMT in OP_Init; OP_ResultRow still emits every ROW.
                    if sql.is_null() {
                        trace.internal_schema_rows += 1;
                    } else {
                        let execution = PRODUCTION_SELECTED_SQL_EXECUTIONS
                            .with(|executions| {
                                executions.borrow().get(&(statement as usize)).copied()
                            })
                            .unwrap_or_else(|| {
                                // SAFETY: sqlite3_sql text lives with this statement.
                                let sql = unsafe { std::ffi::CStr::from_ptr(sql) };
                                panic!("a named row requires its traced execution: {sql:?}");
                            });
                        trace.rows_by_statement[execution] += 1;
                    }
                }
                _ => unreachable!("production selected SQL trace registered known events only"),
            }
        });
    });
    if result.is_err() {
        PRODUCTION_SELECTED_SQL_TRACE_FAILED.with(|failed| failed.set(true));
    }
    0
}

#[test]
fn production_selected_sql_trace_attributes_nested_cursor_rows() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    PRODUCTION_SELECTED_SQL_TRACE.with(|trace| {
        assert!(trace.borrow().is_none());
        *trace.borrow_mut() = Some(ProductionSelectedSqlCost::default());
    });
    // SAFETY: the connection outlives the callback and it is unregistered below.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(
            connection.handle(),
            rusqlite::ffi::SQLITE_TRACE_STMT | rusqlite::ffi::SQLITE_TRACE_ROW,
            Some(record_production_selected_sql),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
    // The table has one schema entry and no implicit index. SQLite's
    // OP_ParseSchema reads that entry through a SQL-less internal statement.
    connection
        .execute_batch("CREATE TABLE trace_schema_probe(value INTEGER)")
        .unwrap();
    let schema = checkpoint_production_selected_sql_trace();
    let mut outer = connection
        .prepare("SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3")
        .unwrap();
    let mut inner = connection.prepare("SELECT 10 UNION ALL SELECT 20").unwrap();
    {
        let mut rows = outer.query([]).unwrap();
        while rows.next().unwrap().is_some() {
            let mut nested = inner.query([]).unwrap();
            while nested.next().unwrap().is_some() {}
        }
    }
    let nested = checkpoint_production_selected_sql_trace();
    {
        let mut rows = inner.query([]).unwrap();
        while rows.next().unwrap().is_some() {}
    }
    // SAFETY: a zero mask removes the callback before assertions/teardown.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(connection.handle(), 0, None, std::ptr::null_mut())
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
    let repeated = checkpoint_production_selected_sql_trace();
    PRODUCTION_SELECTED_SQL_TRACE.with(|trace| {
        trace.borrow_mut().take().unwrap();
    });
    assert_eq!(schema.statement_count(), 1);
    assert_eq!(schema.rows_by_statement, [0]);
    assert_eq!(schema.internal_schema_rows, 1);
    assert_eq!(schema.decoded_rows, 1);
    assert_eq!(nested.internal_schema_rows, 0);
    assert_eq!(repeated.internal_schema_rows, 0);
    assert_eq!(nested.statement_count(), 4);
    assert_eq!(nested.decoded_rows, 9);
    assert_eq!(nested.rows_by_statement, [3, 2, 2, 2]);
    assert_eq!(repeated.statement_count(), 1);
    assert_eq!(repeated.decoded_rows, 2);
    assert_eq!(repeated.rows_by_statement, [2]);
}

fn begin_production_selected_sql_trace(store: &AnalyzerStore) {
    PRODUCTION_SELECTED_SQL_EXECUTIONS.with(|executions| assert!(executions.borrow().is_empty()));
    PRODUCTION_SELECTED_SQL_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        assert!(trace.is_none(), "production selected SQL trace cannot nest");
        *trace = Some(ProductionSelectedSqlCost::default());
    });
    PRODUCTION_SELECTED_SQL_TRACE_FAILED.with(|failed| {
        assert!(
            !failed.replace(false),
            "the preceding production selected SQL trace failed before teardown"
        );
    });
    let connection = store
        .active_read_conn()
        .expect("check out the next production selected reader");
    // SAFETY: the reader is returned to this store's active pool and the test
    // checks the same reader out to unregister the callback before teardown.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(
            connection.handle(),
            rusqlite::ffi::SQLITE_TRACE_STMT | rusqlite::ffi::SQLITE_TRACE_ROW,
            Some(record_production_selected_sql),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
}

fn checkpoint_production_selected_sql_trace() -> ProductionSelectedSqlCost {
    // Callers checkpoint after closing cursors. No execution crosses a checkpoint.
    PRODUCTION_SELECTED_SQL_EXECUTIONS.with(|executions| {
        *executions.borrow_mut() = crate::hash::HashMap::default();
    });
    let failed = PRODUCTION_SELECTED_SQL_TRACE_FAILED.with(|failed| failed.replace(false));
    let cost = PRODUCTION_SELECTED_SQL_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        let trace = trace
            .as_mut()
            .expect("production selected SQL trace must be active");
        std::mem::take(trace)
    });
    assert!(!failed, "production selected SQL trace callback panicked");
    cost
}

fn finish_production_selected_sql_trace(store: &AnalyzerStore) -> ProductionSelectedSqlCost {
    let connection = store
        .active_read_conn()
        .expect("check out the traced production selected reader");
    // SAFETY: this is the same reader registered above. A zero mask removes
    // the callback before its thread-local state is read.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(connection.handle(), 0, None, std::ptr::null_mut())
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
    drop(connection);
    let cost = checkpoint_production_selected_sql_trace();
    PRODUCTION_SELECTED_SQL_TRACE.with(|trace| {
        trace
            .borrow_mut()
            .take()
            .expect("production selected SQL trace must be active");
    });
    cost
}

struct ResolutionOperationFixture {
    store: AnalyzerStore,
    _project_root: tempfile::TempDir,
    project: MutableGenerationProject,
    workspace_id: WorkspaceId,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    generation: GenerationId,
    source_facts: FileResolutionFacts,
    provider_facts: FileResolutionFacts,
}

impl ResolutionOperationFixture {
    fn new() -> Self {
        let project_root = tempfile::tempdir().expect("operation test project root");
        let project = MutableGenerationProject::new(project_root.path(), Language::Java);
        let store = AnalyzerStore::open_ephemeral().expect("operation test store");
        let generation = store
            .ensure_language_epoch_value("java", "resolution-operation-test-v1")
            .expect("operation test language epoch");
        store
            .ensure_resolution_producer_epoch("java", Language::Java)
            .expect("operation test producer epoch");

        let (state, source_facts) = parsed_java_state(project_root.path(), SOURCE_PATH);
        let (_, provider_facts) = parsed_operation_source_state(
            project_root.path(),
            PROVIDER_PATH,
            PROVIDER_JAVA_SOURCE,
            &JavaAdapter,
        );
        let prepared = AnalyzerStore::prepare_parsed_blob(
            persisted_oid(),
            "java",
            generation,
            &JavaAdapter,
            state,
        )
        .expect("prepare operation Java blob through the production path");
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);
        let workspace_id = WorkspaceId(WORKSPACE_ID.to_owned());
        let writer_workspace_id = workspace_id.as_str().to_owned();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 1)",
                params![writer_workspace_id, generation.get()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 1)",
                params![writer_workspace_id, generation.get()],
            )
            .unwrap();
            for (ordinal, path) in [
                SOURCE_PATH,
                PROVIDER_PATH,
                REMOVED_PATH,
                SECOND_REPLACEMENT_PATH,
            ]
            .into_iter()
            .enumerate()
            {
                tx.execute(
                    "INSERT INTO workspace_file_versions(
                       workspace_id, lang, generation, rel_path, blob_oid,
                       projection_digest, valid_from
                     ) VALUES(?1, 'java', ?2, ?3, ?4, ?5, 1)",
                    params![
                        writer_workspace_id,
                        generation.get(),
                        path,
                        persisted_oid().to_string(),
                        format!("{:064x}", ordinal + 1),
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        });

        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert(
            "java".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: "java".to_owned(),
                generation,
                revision: 1,
            },
        );
        Self {
            store,
            _project_root: project_root,
            project,
            workspace_id,
            snapshots,
            languages: vec![SelectedResolutionLanguage::new("java", Language::Java)],
            generation,
            source_facts,
            provider_facts,
        }
    }

    fn provider_replacement(&self) -> SelectedResolutionContentMountRequest {
        self.counterfactual_content(PROVIDER_PATH, RICH_JAVA_SOURCE, PROVIDER_JAVA_SOURCE)
    }

    fn published_content(&self, path: &str, source: &str) -> SelectedResolutionContentMountRequest {
        use super::super::resolution_publication::ResolutionContentPublicationOutcome;
        let (state, _) =
            parsed_operation_source_state(self._project_root.path(), path, source, &JavaAdapter);
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
            .expect("hash actual Java fixture content");
        let prepared =
            AnalyzerStore::prepare_parsed_blob(oid, "java", self.generation, &JavaAdapter, state)
                .expect("prepare actual Java fixture content");
        let ResolutionContentPublicationOutcome::Ready(content) = self
            .store
            .publish_selected_parsed_content(
                self.snapshots.get("java").expect("captured Java owner"),
                path,
                prepared,
                &CancellationToken::default(),
            )
            .expect("publish complete Java fixture content")
        else {
            panic!("uncancelled actual Java fixture publication must succeed");
        };
        SelectedResolutionContentMountRequest::new(
            content.into_parts().0,
            WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid: oid,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn live_content(&self, path: &str, source: &str) -> SelectedResolutionContentMountRequest {
        self.published_content(path, source)
            .with_live_overlay_content_digest(
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes()),
            )
    }

    fn counterfactual_content(
        &self,
        path: &str,
        original: &str,
        source: &str,
    ) -> SelectedResolutionContentMountRequest {
        self.published_content(path, source)
            .with_counterfactual_base_content_digest(
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes()),
            )
    }

    fn content_mount(&self, path: &str) -> SelectedResolutionContentMountRequest {
        use super::super::resolution_publication::{
            ResolutionContentInput, ResolutionContentPublicationOutcome,
        };
        let outcome = self
            .store
            .admit_cached_selected_content(
                &self.snapshots["java"],
                path,
                persisted_oid(),
                &ResolutionContentInput::Parsed {
                    content_oid: persisted_oid(),
                    semantic_language: Language::Java,
                },
                &CancellationToken::default(),
            )
            .unwrap();
        let ResolutionContentPublicationOutcome::Ready(content) = outcome else {
            panic!("real content fixture publication: {outcome:?}");
        };
        SelectedResolutionContentMountRequest::new(
            content.into_parts().0,
            WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid: persisted_oid(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn second_replacement(&self) -> SelectedResolutionContentMountRequest {
        self.counterfactual_content(SECOND_REPLACEMENT_PATH, RICH_JAVA_SOURCE, RICH_JAVA_SOURCE)
    }

    fn parity_masks(&self) -> Vec<SelectedResolutionOverlayMask> {
        vec![
            SelectedResolutionOverlayMask::replacement("java", PROVIDER_PATH),
            SelectedResolutionOverlayMask::removal("java", REMOVED_PATH),
            SelectedResolutionOverlayMask::removal("java", SECOND_REPLACEMENT_PATH),
        ]
    }

    fn two_replacement_masks(&self) -> Vec<SelectedResolutionOverlayMask> {
        vec![
            SelectedResolutionOverlayMask::replacement("java", PROVIDER_PATH),
            SelectedResolutionOverlayMask::removal("java", REMOVED_PATH),
            SelectedResolutionOverlayMask::replacement("java", SECOND_REPLACEMENT_PATH),
        ]
    }

    fn open<'a>(
        &'a self,
        masks: &'a [SelectedResolutionOverlayMask],
        replacements: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
        self.store.open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                &self.project,
                &self.workspace_id,
                &self.snapshots,
                &self.languages,
                masks,
            )
            .with_content_mounts(replacements),
            cancellation,
        )
    }

    fn open_ready<'a>(
        &'a self,
        masks: &'a [SelectedResolutionOverlayMask],
        replacements: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        match self.open(masks, replacements, cancellation).unwrap() {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("complete operation fixture must open Ready"),
        }
    }

    fn open_with_project<'a>(
        &'a self,
        project: &'a dyn Project,
        masks: &'a [SelectedResolutionOverlayMask],
        replacements: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
        self.store.open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                project,
                &self.workspace_id,
                &self.snapshots,
                &self.languages,
                masks,
            )
            .with_content_mounts(replacements),
            cancellation,
        )
    }

    fn open_with_project_and_content_mounts<'a>(
        &'a self,
        project: &'a dyn Project,
        masks: &'a [SelectedResolutionOverlayMask],
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
        self.store.open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                project,
                &self.workspace_id,
                &self.snapshots,
                &self.languages,
                masks,
            )
            .with_content_mounts(content_mounts),
            cancellation,
        )
    }

    fn open_parity_ready<'a>(
        &'a self,
        masks: &'a [SelectedResolutionOverlayMask],
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        self.open_ready(masks, vec![self.provider_replacement()], cancellation)
    }
}

const GO_WORKSPACE_ID: &str = "7272727272727272727272727272727272727272727272727272727272727272";
const GO_SOURCE_PATH: &str = "local.go";
const GO_SOURCE: &str = r#"package local

type Item struct{}

func Echo(input *Item) *Item {
    return input
}

func use(value *Item) *Item {
    return Echo(value)
}
"#;

fn parsed_go_state(
    project_root: &Path,
    relative_path: &str,
    source: &str,
) -> (Arc<FileState>, FileResolutionFacts) {
    parsed_operation_state(project_root, relative_path, source, &GoAdapter)
}

fn parsed_operation_state<A: LanguageAdapter>(
    project_root: &Path,
    relative_path: &str,
    source: &str,
    adapter: &A,
) -> (Arc<FileState>, FileResolutionFacts) {
    let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
    file.write(source).expect("write operation source");
    parsed_operation_source_state(project_root, relative_path, source, adapter)
}

/// Parse unsaved content without replacing the selected disk baseline.
fn parsed_operation_source_state<A: LanguageAdapter>(
    project_root: &Path,
    relative_path: &str,
    source: &str,
    adapter: &A,
) -> (Arc<FileState>, FileResolutionFacts) {
    let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
    let source = source.to_owned();
    let mut parser = Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .expect("set Go grammar");
    let tree = parser
        .parse(&source, None)
        .expect("parse Go operation source");
    let mut parsed: ParsedFile = adapter.parse_file(&file, &source, &tree);
    parsed.add_file_scope(&file, &source);
    let contains_tests = adapter.contains_tests(&file, &source, &tree, &parsed);
    let declarations = parsed.declarations().clone();
    let state = Arc::new(FileState {
        source,
        package_name: parsed.package_name,
        content_qualifier: parsed.content_qualifier,
        top_level_declarations: parsed.top_level_declarations,
        declarations,
        definition_lookup_units: parsed.definition_lookup_units,
        imports: parsed.imports,
        scala_exports: parsed.scala_exports,
        rust_usage_facts: parsed.rust_usage_facts,
        source_facts: parsed.source_facts,
        source_declaration_units: parsed.source_declaration_units,
        source_declaration_metadata: parsed.source_declaration_metadata,
        resolution_facts: parsed.resolution_facts,
        raw_supertypes: parsed.raw_supertypes,
        supertype_lookup_paths: parsed.supertype_lookup_paths,
        type_identifiers: parsed.type_identifiers,
        signatures: parsed.signatures,
        signature_metadata: parsed.signature_metadata,
        signature_metadata_signature_ordinals: parsed.signature_metadata_signature_ordinals,
        cpp_template_metadata: parsed.cpp_template_metadata,
        ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
        ranges: parsed.ranges,
        children: parsed.children,
        scala_traits: parsed.scala_traits,
        type_aliases: parsed.type_aliases,
        contains_tests,
        test_region_units: parsed.test_region_units,
        materialization_records: parsed.materialization_records,
        parse_errors: Some(Vec::new()),
        parse_complete: true,
        additional_projections: Vec::new(),
    });
    let facts = state.resolution_facts.clone();
    (state, facts)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustPrivatePointSummary {
    located: bool,
    definition_ids: Vec<String>,
    complete: bool,
}

fn rust_private_point_summaries<'store, 'input>(
    mut open_operation: impl FnMut() -> SelectedResolutionOperation<'store, 'input>,
    profile: RustCallerTargetProfile,
    facts: &FileResolutionFacts,
    path: &str,
    reference_sites: &[ResolutionSiteId],
    cancellation: &CancellationToken,
) -> Vec<RustPrivatePointSummary> {
    reference_sites
        .iter()
        .map(|reference_site| {
            let operation = open_operation();
            let range = facts
                .sites
                .iter()
                .find(|site| site.id == *reference_site)
                .expect("private Rust reference range");
            let SelectedRustFileContextOutcome::Ready { context, .. } = operation
                .rust_test_crate_context(profile.clone(), cancellation)
                .expect("build private Rust point context")
            else {
                panic!("private Rust point context must be ready")
            };
            let outcome = operation
                .resolve_rust_reference(
                    *context,
                    &SelectedSemanticLocator::for_reference_range(
                        "rust",
                        path,
                        range.start_byte,
                        range.end_byte,
                    ),
                    cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .expect("resolve private Rust point");
            match outcome {
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answer,
                )) => {
                    let answer = only_rust_point_answer(answer);
                    RustPrivatePointSummary {
                        located: true,
                        definition_ids: answer
                            .definitions
                            .iter()
                            .map(|definition| definition.declaration_id().to_string())
                            .collect(),
                        complete: matches!(
                            answer.resolution.binding().completion(),
                            ResolutionCompletion::Complete
                        ),
                    }
                }
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                    RustPrivatePointSummary {
                        located: false,
                        definition_ids: Vec::new(),
                        complete: false,
                    }
                }
                SelectedResolutionOperationOutcome::Unavailable(reason) => {
                    panic!("private Rust point operation unavailable: {reason:?}")
                }
                SelectedResolutionOperationOutcome::Stale(reason) => {
                    panic!("private Rust point operation stale: {reason:?}")
                }
                SelectedResolutionOperationOutcome::Cancelled(completion) => {
                    panic!("private Rust point operation cancelled: {completion:?}")
                }
            }
        })
        .collect()
}

struct GoResolutionOperationFixture {
    store: AnalyzerStore,
    _project_root: tempfile::TempDir,
    project: MutableGenerationProject,
    workspace_id: WorkspaceId,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    overlay_masks: Vec<SelectedResolutionOverlayMask>,
    facts: FileResolutionFacts,
}

impl GoResolutionOperationFixture {
    fn new() -> Self {
        Self::with_source(GO_SOURCE)
    }

    fn with_source(source: &str) -> Self {
        let project_root = tempfile::tempdir().expect("Go operation test project root");
        let project = MutableGenerationProject::new(project_root.path(), Language::Go);
        let adapter = GoAdapter;
        let (state, facts) = parsed_go_state(project_root.path(), GO_SOURCE_PATH, source);

        let store = AnalyzerStore::open_ephemeral().expect("Go operation test store");
        let generation = store
            .ensure_language_epoch_value("go", "resolution-operation-go-test-v1")
            .expect("Go operation test language epoch");
        store
            .ensure_resolution_producer_epoch("go", Language::Go)
            .expect("Go operation test producer epoch");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
            .expect("hash the Go operation fixture source");
        let prepared =
            AnalyzerStore::prepare_parsed_blob(oid, "go", generation, &adapter, Arc::clone(&state))
                .expect("prepare parsed Go blob with resolution bundle");
        assert!(
            prepared.resolution.logical_rows() > 1,
            "the real Go producer must prepare a nonempty resolution interior"
        );
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);

        let workspace_id = WorkspaceId(GO_WORKSPACE_ID.to_owned());
        let writer_workspace_id = workspace_id.as_str().to_owned();
        let oid = oid.to_string();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'go', ?2, 1)",
                params![writer_workspace_id, generation.get()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
                 VALUES(?1, 'go', ?2, 1)",
                params![writer_workspace_id, generation.get()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) VALUES(?1, 'go', ?2, ?3, ?4, ?5, 1)",
                params![
                    writer_workspace_id,
                    generation.get(),
                    GO_SOURCE_PATH,
                    oid,
                    format!("{:064x}", 701),
                ],
            )
            .unwrap();
            tx.commit().unwrap();
        });

        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert(
            "go".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: "go".to_owned(),
                generation,
                revision: 1,
            },
        );
        Self {
            store,
            _project_root: project_root,
            project,
            workspace_id,
            snapshots,
            languages: vec![SelectedResolutionLanguage::new("go", Language::Go)],
            overlay_masks: Vec::new(),
            facts,
        }
    }

    fn open_ready<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        let outcome = self
            .store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &self.project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    &self.overlay_masks,
                ),
                cancellation,
            )
            .expect("open persisted Go resolution operation");
        match outcome {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("complete persisted Go operation must open Ready"),
        }
    }
}

const GO_ROOT_WORKSPACE_ID: &str =
    "7373737373737373737373737373737373737373737373737373737373737373";
const GO_ROOT_CONSUMER_PATH: &str = "consumer/use.go";
const GO_ROOT_PROVIDER_PATH: &str = "provider/item.go";
const GO_ROOT_DECOY_PATH: &str = "other/provider/item.go";
const GO_ROOT_CONSUMER_SOURCE: &str = r#"package consumer

import . "example.test/root/provider"

var Use *Item
"#;
const GO_ROOT_PROVIDER_SOURCE: &str = r#"package provider

type Item struct{}
"#;
const GO_ROOT_DECOY_SOURCE: &str = r#"package provider

type Item struct{ Decoy bool }
"#;

struct GoRootResolutionOperationFixture {
    store: AnalyzerStore,
    _project_root: tempfile::TempDir,
    project: MutableGenerationProject,
    workspace_id: WorkspaceId,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    overlay_masks: Vec<SelectedResolutionOverlayMask>,
    consumer_facts: FileResolutionFacts,
    provider_facts: FileResolutionFacts,
    decoy_facts: FileResolutionFacts,
}

const RUST_ROOT_WORKSPACE_ID: &str =
    "7474747474747474747474747474747474747474747474747474747474747474";
const RUST_ROOT_CONSUMER_PATH: &str = "app/src/lib.rs";
const RUST_ROOT_PROVIDER_ROOT_PATH: &str = "engine/src/lib.rs";
const RUST_ROOT_PROVIDER_PATH: &str = "engine/src/model.rs";
const RUST_ROOT_CONSUMER_SOURCE: &str = concat!(
    "use engine::target as alias;\n",
    "use engine::model::target as direct_alias;\n",
    "fn caller() -> usize { alias() + direct_alias() }\n",
);
const RUST_ROOT_PROVIDER_ROOT_SOURCE: &str = "pub mod model;\npub use model::*;\n";
/// A consumer line whose receiver type this crate cannot resolve, so the call
/// is answered by a deferred member owner lookup on the member's name.
const RUST_ROOT_SHARED_MEMBER_CALLER: &str =
    "pub fn probe(value: Unresolved) -> usize { value.shared_member() }\n";

/// A consumer line whose receiver is a primitive, so the member call asks
/// whether the owner is an intrinsic type before it calls the owner a producer
/// shortfall.
const RUST_ROOT_INTRINSIC_OWNER_CALLER: &str =
    "pub fn intrinsic_probe(value: usize) -> usize { value.shared_member() }\n";

/// The default scale file: one free function named for its index that no other
/// file in the fixture mentions.
fn default_scale_source(index: usize) -> String {
    format!("pub fn scale_{index:04}() -> usize {{ {index} }}\n")
}

/// A file of the unrelated third crate that resolves completely.
fn default_unrelated_source(index: usize) -> String {
    format!("pub fn unrelated_{index:04}() -> usize {{ {index} }}\n")
}

/// A file of the unrelated third crate whose own resolution cannot complete:
/// the parameter names a type this workspace does not declare and the body
/// calls a member on it.
fn gapped_unrelated_source(index: usize) -> String {
    format!(
        "pub fn unrelated_{index:04}(value: UnresolvedUnrelated) -> usize {{ value.unresolved_member() }}\n"
    )
}

/// A scale file of the consumer's own crate whose resolution cannot complete,
/// in the same shape as `gapped_unrelated_source`: the parameter names a type
/// this workspace does not declare and the body calls a member on it.
///
/// The scale files are mounted under `app/src`, so their gaps are inside the
/// consumer's dependency closure and the unrelated crate's gaps are outside it.
fn gapped_scale_source(index: usize) -> String {
    format!(
        "pub fn scale_{index:04}(value: UnresolvedInClosure) -> usize {{ value.unresolved_member() }}\n"
    )
}

/// A scale file that mentions one shared member name without declaring it.
/// File 0 is the single blob that declares a member under that name.
fn deferred_member_lookup_scale_source(index: usize) -> String {
    if index == 0 {
        "pub struct Holder;\nimpl Holder { pub fn shared_member(&self) -> usize { 0 } }\n"
            .to_owned()
    } else {
        format!("pub fn scale_{index:04}(value: Unresolved) -> usize {{ value.shared_member() }}\n")
    }
}
const RUST_ROOT_PROVIDER_SOURCE: &str =
    "pub fn target() -> usize { 1 }\npub fn unrelated() -> usize { 2 }\n";

/// One reverse answer per target, obtained the way the shipped reverse route
/// obtains it.
///
/// `with_rust_row_reverse_queries` is what `with_rust_selected_reverse_queries`
/// runs for every MCP reverse tool, and its `confirm` callback is the forward
/// point request that turns a candidate site into a proven reference.
/// Production builds that callback from the analyzer
/// (`rust/selected_reverse.rs::confirm_rust_reverse_references`); here the
/// fixture opens the confirming operation from the same store, with the same
/// per-site budget, so these tests read the shipped route's answer and not a
/// stand-in for it.
fn rust_row_reverse_answers(
    fixture: &RustRootResolutionOperationFixture,
    targets: &[CodeUnit],
    cancellation: &CancellationToken,
) -> Vec<SelectedRustTargetReferences> {
    use crate::analyzer::usages::get_definition::BoundedResolution;
    let operation = fixture.open_ready(cancellation);
    let outcome = operation
        .with_rust_row_reverse_queries(
            None,
            cancellation,
            |root, locators| {
                // Each site keeps the allowance it would have had as its own
                // request, exactly as the analyzer's confirmation does.
                let sites = locators.len().max(1);
                let mut budget = ReceiverAnalysisBudget::default();
                budget.max_summary_expansions = budget.max_summary_expansions.saturating_mul(sites);
                budget.max_scope_nodes = budget.max_scope_nodes.saturating_mul(sites);
                let confirming = fixture.open_ready(cancellation);
                match confirming.confirm_rust_references_for_caller_bounded(
                    root,
                    locators,
                    budget,
                    cancellation,
                    &mut SelectedResolutionContextMetrics,
                    &mut ResolutionBatchMetrics::default(),
                )? {
                    BoundedResolution::Cancelled { .. } => Ok(RustReverseConfirmation::Cancelled),
                    BoundedResolution::Exceeded { .. } => Ok(RustReverseConfirmation::Bounded),
                    BoundedResolution::Complete { value, .. } => match value {
                        SelectedRustCallerReferencesOutcome::Operation(
                            SelectedResolutionOperationOutcome::Native(located),
                        ) => located
                            .into_iter()
                            .map(|located| match located {
                                SelectedResolutionLocated::Found(answers) => Ok(answers),
                                SelectedResolutionLocated::Missing => Err(StoreError::new(
                                    "reverse candidate has no forward reference",
                                )),
                            })
                            .collect::<Result<Vec<_>>>()
                            .map(RustReverseConfirmation::Confirmed),
                        SelectedRustCallerReferencesOutcome::Operation(
                            SelectedResolutionOperationOutcome::Cancelled(_),
                        ) => Ok(RustReverseConfirmation::Cancelled),
                        SelectedRustCallerReferencesOutcome::Operation(
                            SelectedResolutionOperationOutcome::Unavailable(reason),
                        ) => Err(StoreError::new(format!(
                            "reverse confirmation unavailable: {reason:?}"
                        ))),
                        SelectedRustCallerReferencesOutcome::Operation(
                            SelectedResolutionOperationOutcome::Stale(reason),
                        ) => Err(StoreError::new(format!(
                            "reverse confirmation stale: {reason:?}"
                        ))),
                        SelectedRustCallerReferencesOutcome::UnsupportedCallerProfile => Err(
                            StoreError::new("reverse confirmation caller profile unavailable"),
                        ),
                    },
                }
            },
            |queries| match queries.references_to(targets)? {
                SelectedRustReverseBatchOutcome::Ready(answers) => Ok(answers),
                SelectedRustReverseBatchOutcome::Unavailable(reason) => {
                    panic!("the fixture's reverse batch must be available: {reason:?}")
                }
                SelectedRustReverseBatchOutcome::Cancelled => {
                    panic!("an uncancelled reverse batch must be ready")
                }
            },
        )
        .expect("the row reverse route is an operational result");
    let SelectedResolutionOperationOutcome::Native(answers) = outcome else {
        panic!("an unchanged selected workspace must publish native reverse answers");
    };
    answers
}

fn rust_workspace_reverse_with_unresolved_prefix()
-> (SelectedReferenceSearchAnswer, SelectedReferenceSearchAnswer) {
    let mut fixture = RustRootResolutionOperationFixture::new();
    fixture.replace_persisted_consumer_source("pub fn caller() -> usize { Missing::target() }\n");
    let callee = site_for_identifier(
        &fixture.consumer_facts,
        "target",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    assert!(
        fixture
            .consumer_facts
            .identifiers
            .iter()
            .any(|identifier| { identifier.site == callee && identifier.qualifier.is_some() })
    );
    assert!(
        fixture
            .consumer_facts
            .binding_projections
            .iter()
            .any(|projection| projection.reference == callee),
        "the qualified callee has the projection required for a typed route obligation"
    );
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let (halves, _) = operation
        .rust_root_halves(
            &RustRootHalfScope::new(
                operation.mounts().unwrap().iter(),
                operation.mounts().unwrap().iter(),
            ),
            &cancellation,
            None,
        )
        .expect("read selected native root halves")
        .expect("uncancelled root inventory must exhaust");
    let prefixes = halves
        .iter()
        .filter_map(|half| match half {
            SelectedRootPathHalf::Reference {
                prefix_reference: Some(_),
                token,
                demand,
                ..
            } => Some((*token, *demand)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(prefixes.len(), 1, "fixture prefix halves: {prefixes:?}");
    let (_, demand) = prefixes[0];
    assert_eq!(
        demand,
        ResolutionLookupSemanticRecipe::new(Language::Rust, ResolutionNamespace::Value, "target")
            .semantic(&operation.ready.shared_names()),
        "the unresolved route retains its structured terminal demand"
    );
    assert_ne!(
        demand,
        ResolutionLookupSemanticRecipe::new(
            Language::Rust,
            ResolutionNamespace::Value,
            "unrelated",
        )
        .semantic(&operation.ready.shared_names()),
        "the other declaration has a disjoint terminal demand"
    );
    drop(operation);
    rust_workspace_reverse_provider_targets(&fixture, &cancellation)
}

fn rust_workspace_reverse_provider_targets(
    fixture: &RustRootResolutionOperationFixture,
    cancellation: &CancellationToken,
) -> (SelectedReferenceSearchAnswer, SelectedReferenceSearchAnswer) {
    let operation = fixture.open_ready(cancellation);
    let SelectedRustBindingDefinitionUnitsOutcome::Ready(units) = operation
        .rust_binding_definition_units(cancellation)
        .expect("read selected declaration inventory")
    else {
        panic!("uncancelled declaration inventory must be ready");
    };
    let targets = ["target", "unrelated"].map(|name| {
        units
            .values()
            .find(|unit| {
                unit.source().rel_path() == Path::new(RUST_ROOT_PROVIDER_PATH)
                    && unit.short_name() == name
            })
            .cloned()
            .expect("fixture provider declaration")
    });
    drop(operation);
    let answers = rust_row_reverse_answers(fixture, &targets, cancellation);
    let mut answers = answers.into_iter();
    let matching = answers.next().expect("matching-demand target answer");
    let disjoint = answers.next().expect("disjoint-demand target answer");
    assert!(answers.next().is_none());
    assert_eq!(matching.target, targets[0]);
    assert_eq!(disjoint.target, targets[1]);
    (matching.search, disjoint.search)
}

#[test]
fn rust_workspace_reverse_retains_matching_unresolved_prefix_gap() {
    let (matching, _) = rust_workspace_reverse_with_unresolved_prefix();
    assert!(matching.references().is_empty(), "{matching:?}");
    assert!(
        matches!(matching.completion(), ResolutionCompletion::Incomplete(_)),
        "an unresolved matching route cannot certify target absence: {matching:?}"
    );
    assert!(
        !matching
            .completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled),
        "the retained uncertainty is semantic, not cancellation: {matching:?}"
    );
}

#[test]
fn rust_workspace_reverse_unrelated_prefix_does_not_taint_absence() {
    let (_, disjoint) = rust_workspace_reverse_with_unresolved_prefix();
    assert!(disjoint.references().is_empty(), "{disjoint:?}");
    assert_eq!(
        disjoint.completion(),
        &ResolutionCompletion::Complete,
        "an unresolved route to another terminal demand cannot hide callers of this declaration"
    );
}

#[test]
fn rust_workspace_reverse_preserves_unresolved_prefix_through_renamed_reexports() {
    for (exports, call) in [
        (
            "pub mod facade { pub use engine::model::target as renamed; }\n",
            "pub fn caller() -> usize { Missing::renamed() }\n",
        ),
        (
            concat!(
                "pub mod facade { pub use engine::model::target as renamed; }\n",
                "pub mod outer { pub use crate::facade::renamed as again; }\n",
            ),
            "pub fn caller() -> usize { Missing::again() }\n",
        ),
    ] {
        let mut fixture = RustRootResolutionOperationFixture::new();
        fixture.replace_persisted_consumer_source(exports);
        let cancellation = CancellationToken::new();
        let (baseline, baseline_disjoint) =
            rust_workspace_reverse_provider_targets(&fixture, &cancellation);
        assert!(!baseline.references().is_empty(), "{exports}: {baseline:?}");
        assert_eq!(
            baseline.completion(),
            &ResolutionCompletion::Complete,
            "the reexport chain itself must be complete: {exports}"
        );
        assert_eq!(
            baseline_disjoint.completion(),
            &ResolutionCompletion::Complete,
            "the reexports do not introduce uncertainty for the other declaration: {exports}"
        );

        fixture.replace_persisted_consumer_source(&format!("{exports}{call}"));
        let (matching, disjoint) = rust_workspace_reverse_provider_targets(&fixture, &cancellation);
        assert!(!matching.references().is_empty(), "{call}: {matching:?}");
        assert!(
            matches!(matching.completion(), ResolutionCompletion::Incomplete(_)),
            "an unresolved exposed alias must retain uncertainty through the reexport chain: {call}: {matching:?}"
        );
        assert!(
            !matching
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled),
            "the alias uncertainty must be semantic: {matching:?}"
        );
        assert!(disjoint.references().is_empty(), "{disjoint:?}");
        assert_eq!(
            disjoint.completion(),
            &ResolutionCompletion::Complete,
            "the alias chain must not spread its route uncertainty to an unrelated declaration: {call}"
        );
    }
}

#[test]
fn rust_workspace_reverse_preserves_unknown_prefix_gap_with_value_projection() {
    let mut fixture = RustRootResolutionOperationFixture::new();
    fixture.replace_persisted_consumer_source("pub fn caller() { Missing::target; }\n");
    let reference = site_for_identifier(
        &fixture.consumer_facts,
        "target",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    assert!(
        fixture
            .consumer_facts
            .identifiers
            .iter()
            .any(|identifier| { identifier.site == reference && identifier.qualifier.is_some() })
    );
    assert!(
        fixture
            .consumer_facts
            .binding_projections
            .iter()
            .any(|projection| projection.reference == reference),
        "a qualified value now has a terminal projection, but that cannot resolve an unknown prefix"
    );
    let cancellation = CancellationToken::new();
    let (matching, _) = rust_workspace_reverse_provider_targets(&fixture, &cancellation);
    assert!(matching.references().is_empty(), "{matching:?}");
    assert!(
        matches!(matching.completion(), ResolutionCompletion::Incomplete(_)),
        "an unknown prefix cannot become complete target absence: {matching:?}"
    );
    assert!(
        !matching
            .completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled),
        "the unknown prefix is semantic uncertainty: {matching:?}"
    );
}

#[test]
fn selected_rust_associated_and_self_reverse_preserve_coordinate_roles_and_uncertainty() {
    for extra_call in ["", "Self::make();", "Missing::make();"] {
        let mut fixture = RustRootResolutionOperationFixture::new();
        let source = format!(
            "pub struct Service;\n\
             impl Service {{\n\
                 pub fn make() {{}}\n\
                 pub fn run(&self) {{}}\n\
                 pub fn caller(&self) {{ Service::make(); self.run(); {extra_call} }}\n\
             }}\n\
             pub fn disjoint() {{}}\n"
        );
        let (state, facts) = fixture.replace_persisted_consumer_source(&source);
        let names = facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut calls = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && matches!(names[&identifier.name], "make" | "run")
            })
            .collect::<Vec<_>>();
        calls.sort_by_key(|identifier| {
            facts
                .sites
                .iter()
                .find(|site| site.id == identifier.site)
                .expect("positioned member reference")
                .start_byte
        });
        assert_eq!(calls.len(), if extra_call.is_empty() { 2 } else { 3 });
        assert_eq!(names[&calls[0].name], "make");
        assert_eq!(calls[0].namespace, ResolutionNamespace::Value);
        assert_eq!(names[&calls[1].name], "run");
        assert_eq!(calls[1].namespace, ResolutionNamespace::Callable);
        assert!(
            calls
                .iter()
                .all(|identifier| identifier.qualifier.is_some())
        );
        let call_sites = calls
            .iter()
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        let self_qualified = extra_call == "Self::make();";
        if let Some(unresolved) = calls.get(2) {
            let route = facts
                .root_references
                .iter()
                .find(|root| root.reference == unresolved.site);
            // `Self` in an impl is the implementing type (Rust reference,
            // "implementations"), and it can never name a module or a crate.
            // That is a fact about what the prefix resolves to, not a reason
            // to withhold the route: the root reference is what carries a
            // member demand to the type the prefix resolves to, and it is how
            // `Foo::member` reaches the trait `Foo` implements. `Self::member`
            // therefore publishes the same route an ordinary Type-prefixed
            // path publishes, anchored on its own positioned Type prefix.
            let route = route.unwrap_or_else(|| {
                panic!("{extra_call}: every Type-prefixed path retains its route")
            });
            let prefix = route
                .prefix_reference
                .expect("the route retains a positioned Type prefix");
            let prefix = facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == prefix)
                .expect("the prefix is an exact source reference");
            assert_eq!(prefix.namespace, ResolutionNamespace::Type);
            assert!(matches!(names[&prefix.name], "Self" | "Missing"));
            assert!(
                !facts.identifiers.iter().any(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && identifier.namespace == ResolutionNamespace::Type
                        && identifier.name == prefix.name
                }),
                "the fixture must not invent an implicit Self binder"
            );
        }
        let cancellation = CancellationToken::new();
        let points = rust_private_point_summaries(
            || fixture.open_ready(&cancellation),
            fixture.profile.clone(),
            &facts,
            RUST_ROOT_CONSUMER_PATH,
            &call_sites,
            &cancellation,
        );
        for (point, name) in points.iter().take(2).zip(["make", "run"]) {
            let definition = state
                .declarations
                .iter()
                .find(|definition| definition.identifier() == name)
                .expect("the fixture declares each selected member once");
            assert!(point.located, "{extra_call}: {point:?}");
            assert_eq!(
                point.definition_ids,
                [definition.declaration_id().to_string()]
            );
            assert!(point.complete, "{extra_call}: {point:?}");
        }
        if let Some(point) = points.get(2) {
            assert!(point.located, "{extra_call}: {point:?}");
            if self_qualified {
                // `Self::make()` resolves through the enclosing owner with no
                // binder uncertainty: `Self` in an impl is the implementing
                // type (Rust reference, "implementations").
                let definition = state
                    .declarations
                    .iter()
                    .find(|definition| definition.identifier() == "make")
                    .expect("the fixture declares each selected member once");
                assert_eq!(
                    point.definition_ids,
                    [definition.declaration_id().to_string()],
                    "{extra_call}: {point:?}"
                );
                assert!(point.complete, "{extra_call}: {point:?}");
            } else {
                assert!(point.definition_ids.is_empty(), "{extra_call}: {point:?}");
                assert!(
                    !point.complete,
                    "an unresolved Type prefix must retain binding uncertainty: {extra_call}: {point:?}"
                );
            }
        }

        let operation = fixture.open_ready(&cancellation);
        let SelectedRustBindingDefinitionUnitsOutcome::Ready(units) = operation
            .rust_binding_definition_units(&cancellation)
            .expect("read exact selected member definitions")
        else {
            panic!("uncancelled definition inventory must be ready")
        };
        let targets = ["make", "run", "disjoint"].map(|name| {
            let declaration = state
                .declarations
                .iter()
                .find(|definition| definition.identifier() == name)
                .expect("fixture target declaration")
                .declaration_id();
            units
                .values()
                .find(|unit| unit.declaration_id() == declaration)
                .cloned()
                .expect("fixture target definition")
        });
        drop(operation);
        let answers = rust_row_reverse_answers(&fixture, &targets, &cancellation);
        assert_eq!(answers.len(), 3);
        for (index, answer) in answers.iter().enumerate() {
            assert_eq!(answer.target, targets[index]);
            let mut expected_sites = if index < 2 {
                vec![call_sites[index]]
            } else {
                Vec::new()
            };
            if index == 0 && self_qualified {
                // `Self::make()` is a real reference to `Service::make`:
                // `Self` in an impl is the implementing type (Rust reference,
                // "implementations"). Reverse search publishes both sites.
                expected_sites.push(call_sites[2]);
            }
            // Publication order across distinct references is not part of this
            // contract; compare the site sets.
            expected_sites.sort_unstable();
            let mut actual_sites = answer
                .search
                .source_sites()
                .iter()
                .map(|site| {
                    assert_eq!(site.file().rel_path(), Path::new(RUST_ROOT_CONSUMER_PATH));
                    assert!(answer.search.references().contains(&site.reference()));
                    site.metadata()
                        .expect("selected source reference metadata")
                        .site()
                })
                .collect::<Vec<_>>();
            actual_sites.sort_unstable();
            assert_eq!(actual_sites, expected_sites, "{extra_call}: {answer:?}");
            assert_eq!(answer.search.references().len(), expected_sites.len());
            if index == 0 && !extra_call.is_empty() && !self_qualified {
                assert!(
                    matches!(
                        answer.search.completion(),
                        ResolutionCompletion::Incomplete(_)
                    ),
                    "unresolved matching associated route cannot certify complete coverage: {extra_call}: {answer:?}"
                );
                assert!(
                    !answer
                        .search
                        .completion()
                        .contains_reason(ResolutionIncompleteReason::Cancelled)
                );
            } else {
                assert_eq!(
                    answer.search.completion(),
                    &ResolutionCompletion::Complete,
                    "valid members and disjoint absence retain complete coverage: {extra_call}: {answer:?}"
                );
            }
        }
    }
}
const RUST_PRIVATE_INHERENT_SOURCE: &str = concat!(
    "pub mod model {\n",
    "    pub struct Service;\n",
    "    impl Service {\n",
    "        fn hidden(&self) -> usize { 1 }\n",
    "        pub fn same(&self) -> usize { self.hidden() }\n",
    "    }\n",
    "    pub mod child {\n",
    "        pub fn descendant(value: super::Service) -> usize { value.hidden() }\n",
    "    }\n",
    "}\n",
    "pub mod sibling {\n",
    "    pub fn outside(value: super::model::Service) -> usize { value.hidden() }\n",
    "}\n",
);

#[test]
fn rust_crate_access_preserves_retained_prepared_statements() {
    use rusqlite::StatementStatus;

    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    for run in 1..=3 {
        if run > 1 {
            operation.crate_access_policy(Vec::new()).unwrap();
            operation.crate_set_access_policy(Vec::new()).unwrap();
        }
        let mut statement = operation
            .ready
            .inventory
            .connection()
            .prepare_cached("SELECT 1 /* retained crate access plan */")
            .unwrap();
        assert_eq!(
            statement.query_row([], |row| row.get::<_, i64>(0)).unwrap(),
            1
        );
        assert_eq!(statement.get_status(StatementStatus::Run), run);
        assert_eq!(
            statement.get_status(StatementStatus::RePrepare),
            0,
            "crate access must not invalidate unrelated prepared SQL at run {run}"
        );
    }
}

struct RustRootResolutionOperationFixture {
    store: AnalyzerStore,
    _project_root: tempfile::TempDir,
    project: MutableGenerationProject,
    generation: GenerationId,
    workspace_id: WorkspaceId,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    selected_context: brokk_bifrost_rust::selected_context::RustSelectedContext,
    profile: RustCallerTargetProfile,
    selected_sources: Box<[RustSelectedTopologySourceMount]>,
    selected_manifests: Box<[RustSelectedManifestMount]>,
    consumer_facts: FileResolutionFacts,
    provider_root_facts: FileResolutionFacts,
    provider_facts: FileResolutionFacts,
}

#[test]
fn named_root_route_absence_closes_the_mount_and_leaves_the_import_unbound() {
    assert_named_root_route_completion("", true);
}

#[test]
fn named_root_route_absent_crate_scopes_binding_uncertainty_to_its_name() {
    let mut fixture = RustRootResolutionOperationFixture::new();
    let (_, facts) = fixture.replace_persisted_consumer_source(
        "use unindexed::ExternalStore;\npub fn known() {}\npub fn caller(value: ExternalStore) { known(); }\n",
    );
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let SelectedRustContextOutcome::Ready(context) = operation
        .rust_context_for_all_crates(&cancellation)
        .unwrap()
    else {
        panic!("crate-key context must be ready");
    };
    let SelectedResolutionContextValidationOutcome::Ready(inputs) = operation
        .prepare_context(context, &cancellation, &SelectedResolutionContextMetrics)
        .unwrap()
    else {
        panic!("mount context must be ready");
    };
    let (_, completion, _, _, _, packages, imports) = inputs.into_parts();
    assert!(packages.is_empty() && imports.is_empty());
    assert_eq!(completion, ResolutionCompletion::Complete);
    let mut checked_unknown = false;
    let mut checked_known = false;
    for identifier in &facts.identifiers {
        if identifier.role != ResolutionIdentifierRole::Reference {
            continue;
        }
        let name = &facts.names[identifier.name.index()].spelling;
        if name != "ExternalStore" && name != "known" {
            continue;
        }
        let site = &facts.sites[identifier.site.index()];
        // Import-source terminals are not uses of the locally bound name.
        if facts.root_imports.iter().any(|import| {
            let declaration = &facts.sites[import.site.index()];
            declaration.start_byte <= site.start_byte && site.end_byte <= declaration.end_byte
        }) {
            continue;
        }
        let operation = fixture.open_ready(&cancellation);
        let SelectedRustFileContextOutcome::Ready { context, .. } = operation
            .rust_test_crate_context(fixture.profile.clone(), &cancellation)
            .unwrap()
        else {
            panic!("point context must be ready");
        };
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answers)) =
            operation
                .resolve_rust_reference(
                    *context,
                    &SelectedSemanticLocator::for_reference_range(
                        "rust",
                        RUST_ROOT_CONSUMER_PATH,
                        site.start_byte,
                        site.end_byte,
                    ),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap()
        else {
            panic!("positioned reference must be found: {name}");
        };
        assert!(!answers.is_empty());
        for answer in answers {
            if name == "ExternalStore" {
                checked_unknown = true;
                assert!(
                    answer.definitions.is_empty(),
                    "site={site:?}, completion={:?}, definitions={:?}",
                    answer.resolution.completion(),
                    answer.definitions
                );
                assert!(
                    matches!(
                        answer.resolution.completion(),
                        ResolutionCompletion::Incomplete(_)
                    ),
                    "site={site:?}, completion={:?}, definitions={:?}",
                    answer.resolution.completion(),
                    answer.definitions
                );
            } else {
                checked_known = true;
                assert_eq!(
                    answer.definitions.len(),
                    1,
                    "site={site:?}, completion={:?}, definitions={:?}",
                    answer.resolution.completion(),
                    answer.definitions
                );
                assert_eq!(
                    answer.resolution.completion(),
                    &ResolutionCompletion::Complete,
                    "site={site:?}, completion={:?}, definitions={:?}",
                    answer.resolution.completion(),
                    answer.definitions
                );
            }
        }
    }
    assert!(checked_unknown && checked_known);
}

#[test]
fn named_root_route_unknown_activation_does_not_prove_absence() {
    assert_named_root_route_completion("", true);
    assert_named_root_route_completion(
        "#[cfg(unknown_route)] mod service { pub struct Service; }\n",
        false,
    );
    assert_named_root_route_completion("#[cfg(unknown_route)] mod other {}\n", false);
}

#[test]
fn named_root_route_existing_bindings_and_generated_boundaries_stay_incomplete() {
    for prefix in [
        "pub struct service;\n",
        "pub const service: usize = 1;\n",
        "#[macro_export] macro_rules! service { () => {} }\n",
        "pub use engine::model::target as service;\n",
        "include!(\"generated.rs\");\n",
        "make_service!();\n",
    ] {
        assert_named_root_route_completion(prefix, false);
    }
}

fn assert_named_root_route_completion(prefix: &str, expected_complete: bool) {
    let mut fixture = RustRootResolutionOperationFixture::new();
    let (_, facts) = fixture.replace_persisted_consumer_source(&format!(
        "{prefix}use crate::service::Service;\npub fn unrelated() {{}}\n"
    ));
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let SelectedRustContextOutcome::Ready(context) = operation
        .rust_context_for_all_crates(&cancellation)
        .expect("build named root route context")
    else {
        panic!("uncancelled named root route context must be ready");
    };
    let demand_completion = ResolutionCompletion::Complete;
    let SelectedResolutionContextValidationOutcome::Ready(inputs) = operation
        .prepare_context(context, &cancellation, &SelectedResolutionContextMetrics)
        .expect("validate named root route mounts")
    else {
        panic!("uncancelled mount validation must be ready");
    };
    let (_, completion, _, _, _, packages, imports) = inputs.into_parts();
    assert!(packages.is_empty() && imports.is_empty());
    assert_eq!(
        completion, demand_completion,
        "workspace mounts must retain the demand inventory's exact reasons"
    );
    assert_eq!(
        completion,
        ResolutionCompletion::Complete,
        "row-backed mount preparation does not resolve a demand"
    );
    let import_sites = facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts
                    .names
                    .iter()
                    .any(|name| name.id == identifier.name && name.spelling == "Service")
        })
        .map(|identifier| identifier.site)
        .collect::<Vec<_>>();
    assert!(!import_sites.is_empty());
    let range = facts
        .sites
        .iter()
        .find(|site| site.id == import_sites[0])
        .unwrap();
    let operation = fixture.open_ready(&cancellation);
    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), &cancellation)
        .unwrap()
    else {
        panic!("uncancelled import point context must be ready");
    };
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answers)) =
        operation
            .resolve_rust_reference(
                *context,
                &SelectedSemanticLocator::for_reference_range(
                    "rust",
                    RUST_ROOT_CONSUMER_PATH,
                    range.start_byte,
                    range.end_byte,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap()
    else {
        panic!("the named import must have positioned reference answers");
    };
    assert_eq!(
        answers.len(),
        3,
        "a named import queries all three namespaces"
    );
    for answer in answers {
        assert!(answer.definitions.is_empty(), "{:?}", answer.definitions);
        if expected_complete {
            assert_eq!(
                answer.resolution.completion(),
                &ResolutionCompletion::Complete
            );
        }
    }
}

#[test]
fn named_and_glob_imports_share_executable_routes_without_losing_import_identity() {
    let mut fixture = RustRootResolutionOperationFixture::new();
    fixture.replace_persisted_consumer_source(concat!(
        "use engine::model::target;\n",
        "use engine::model::*;\n",
        "pub fn caller() -> usize { target() }\n",
    ));
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let SelectedRustContextOutcome::Ready(context) = operation
        .rust_context_for_all_crates(&cancellation)
        .expect("named and glob imports must compose without duplicate path errors")
    else {
        panic!("uncancelled crate-key context must be ready");
    };
    let source_imports = operation.ready.inventory.connection()
        .prepare_cached("SELECT i.import_ordinal FROM rust_crate_imports i JOIN temp.selected_resolution_mounts m ON m.blob_id=i.blob_id WHERE m.persisted_relative_path=?1 AND i.bound_name='target' UNION SELECT i.import_ordinal FROM rust_crate_glob_imports i JOIN temp.selected_resolution_mounts m ON m.blob_id=i.blob_id WHERE m.persisted_relative_path=?1")
        .unwrap().query_map([RUST_ROOT_CONSUMER_PATH], |row| row.get::<_, u32>(0))
        .unwrap().collect::<std::result::Result<BTreeSet<_>, _>>().unwrap();
    assert_eq!(source_imports, BTreeSet::from([0, 1]));
    let SelectedResolutionContextValidationOutcome::Ready(inputs) = operation
        .prepare_context(context, &cancellation, &SelectedResolutionContextMetrics)
        .expect("validate exact named and glob import mounts")
    else {
        panic!("uncancelled mount validation must be ready");
    };
    assert!(matches!(
        operation
            .ready
            .collect_blueprint(inputs, &cancellation)
            .expect("canonical relation union must pass the downstream unique-path guard"),
        SelectedFactOperationBlueprintConstruction::Ready(_)
    ));
}

fn sync_rust_operation_inputs(
    store: &AnalyzerStore,
    workspace_id: &WorkspaceId,
    generation: GenerationId,
    project_root: &Path,
    sources: &[WorkspaceFileRow],
    manifests: &[RustSelectedManifestMount],
) -> Result<WorkspaceSnapshotId> {
    for source in sources {
        let bytes = std::fs::read(project_root.join(&source.rel_path)).map_err(|error| {
            StoreError::new(format!(
                "read selected Rust fixture input {:?}: {error}",
                source.rel_path
            ))
        })?;
        let expected = Oid::hash_object(ObjectType::Blob, &bytes)?;
        if expected == source.blob_oid {
            let oid = source.blob_oid.to_string();
            store.conn.execute(move |connection| {
                connection.execute(
                    "INSERT OR IGNORE INTO workspace_input_sources(content_oid, source_bytes) VALUES(?1, ?2)",
                    params![oid, bytes],
                )
            })?;
        }
    }
    let configuration = manifests
        .iter()
        .map(|manifest| {
            WorkspaceConfigurationInput::new(
                crate::path_utils::rel_path_string(&ProjectFile::new(
                    project_root,
                    &manifest.relative_path,
                )),
                manifest.source_bytes().to_vec().into_boxed_slice(),
            )
        })
        .collect::<Vec<_>>();
    let snapshot = store.sync_workspace_inputs_for_workspace(
        workspace_id,
        "rust",
        generation,
        sources,
        &[],
        &[],
        &[],
        &[],
        &[],
        &configuration,
        &[],
    )?;
    store.reconcile_rust_crates(&snapshot)?;
    Ok(snapshot)
}

impl RustRootResolutionOperationFixture {
    fn new() -> Self {
        Self::new_with_source_mount_count(3)
    }

    fn source_rows(&self) -> Vec<WorkspaceFileRow> {
        self.selected_sources
            .iter()
            .map(|source| WorkspaceFileRow {
                rel_path: crate::path_utils::rel_path_string(&ProjectFile::new(
                    self._project_root.path(),
                    &source.relative_path,
                )),
                blob_oid: source.content_oid,
            })
            .collect()
    }

    fn replace_persisted_consumer_source(
        &mut self,
        source: &str,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        let (state, facts) = parsed_operation_state(
            self._project_root.path(),
            RUST_ROOT_CONSUMER_PATH,
            source,
            &RustAdapter,
        );
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
            .expect("hash private Rust persisted source");
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "rust",
            self.generation,
            &RustAdapter,
            Arc::clone(&state),
        )
        .expect("prepare private Rust persisted source");
        let (outcomes, _) = self
            .store
            .persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);

        let mut sources = self.source_rows();
        let consumer = sources
            .iter_mut()
            .find(|source| source.rel_path == RUST_ROOT_CONSUMER_PATH)
            .expect("Rust private persisted consumer source row");
        consumer.blob_oid = oid;
        let snapshot = sync_rust_operation_inputs(
            &self.store,
            &self.workspace_id,
            self.generation,
            self._project_root.path(),
            &sources,
            &self.selected_manifests,
        )
        .expect("publish private Rust persisted source");
        self.snapshots
            .get_mut("rust")
            .expect("Rust private persisted snapshot")
            .revision = snapshot.revision;
        self.consumer_facts = facts.clone();
        (state, facts)
    }

    fn new_with_source_mount_count(source_mount_count: usize) -> Self {
        Self::new_with_counts(source_mount_count, 0)
    }

    /// The same two-crate fixture plus `unrelated_crate_source_count` files in
    /// a third crate that neither `app` nor `engine` depends on. They are
    /// selected mounts of the same workspace, so a read that is bounded by the
    /// request's own crate never touches them and a read that scans the
    /// selection always does.
    fn new_with_unrelated_crate_source_count(unrelated_crate_source_count: usize) -> Self {
        Self::new_with_counts(3, unrelated_crate_source_count)
    }

    /// The same fixture whose scale files each call one shared member name on a
    /// receiver this crate cannot resolve, and whose consumer does the same.
    ///
    /// Every scale blob therefore *mentions* that lookup identity while only
    /// one blob *declares* a member under it. That is the shape that tells a
    /// read bounded by the declaring blobs apart from one bounded by the blobs
    /// that mention the name; with the default scale files the two are the
    /// same set and the difference is invisible.
    fn new_with_deferred_member_lookup_scale(source_mount_count: usize) -> Self {
        Self::new_with_scale_sources(
            source_mount_count,
            0,
            RUST_ROOT_SHARED_MEMBER_CALLER,
            deferred_member_lookup_scale_source,
        )
    }

    /// The same scale files, but the consumer calls the shared member on a
    /// `usize` receiver, so the forward evaluation reaches the intrinsic-seed
    /// read with a workspace-shared owner identity.
    fn new_with_intrinsic_owner_scale(source_mount_count: usize) -> Self {
        Self::new_with_scale_sources(
            source_mount_count,
            0,
            RUST_ROOT_INTRINSIC_OWNER_CALLER,
            deferred_member_lookup_scale_source,
        )
    }

    fn new_with_counts(source_mount_count: usize, unrelated_crate_source_count: usize) -> Self {
        Self::new_with_scale_sources(
            source_mount_count,
            unrelated_crate_source_count,
            "",
            default_scale_source,
        )
    }

    /// The same unrelated third crate, but every one of its files carries a
    /// resolution gap: an unresolvable parameter type and a member call on it.
    ///
    /// The default unrelated file resolves completely, so it produces no
    /// candidate gap header and a read that walks every gap header in the
    /// workspace measures the same as one that walks the request's own scope.
    /// These files give the workspace gaps that the request's crate closure
    /// excludes, which is what tells the two reads apart.
    fn new_with_unrelated_gapped_crate_source_count(unrelated_crate_source_count: usize) -> Self {
        Self::new_with_sources(
            3,
            unrelated_crate_source_count,
            "",
            default_scale_source,
            gapped_unrelated_source,
        )
    }

    /// The same fixture with `in_closure_gapped_source_count` gapped files in
    /// the consumer's own crate and one gapped file in the unrelated crate.
    ///
    /// The unrelated crate is what makes the two halves distinguishable: it is
    /// in the workspace and out of the request's closure, so a request that
    /// read every gap it can see would move with it too.
    fn new_with_in_closure_gapped_source_count(in_closure_gapped_source_count: usize) -> Self {
        Self::new_with_sources(
            3 + in_closure_gapped_source_count,
            1,
            "",
            gapped_scale_source,
            gapped_unrelated_source,
        )
    }

    fn new_with_scale_sources(
        source_mount_count: usize,
        unrelated_crate_source_count: usize,
        consumer_suffix: &str,
        scale_source: fn(usize) -> String,
    ) -> Self {
        Self::new_with_sources(
            source_mount_count,
            unrelated_crate_source_count,
            consumer_suffix,
            scale_source,
            default_unrelated_source,
        )
    }

    fn new_with_sources(
        source_mount_count: usize,
        unrelated_crate_source_count: usize,
        consumer_suffix: &str,
        scale_source: fn(usize) -> String,
        unrelated_source: fn(usize) -> String,
    ) -> Self {
        assert!(
            source_mount_count >= 3,
            "the Rust root fixture needs its consumer and two provider mounts"
        );
        let project_root = tempfile::tempdir().expect("Rust root operation test project root");
        let project = MutableGenerationProject::new(project_root.path(), Language::Rust);
        let adapter = RustAdapter;
        let store = AnalyzerStore::open_ephemeral().expect("Rust root operation test store");
        let generation = store
            .ensure_language_epoch_value("rust", "resolution-operation-rust-root-test-v1")
            .expect("Rust root operation test language epoch");
        store
            .ensure_resolution_producer_epoch("rust", Language::Rust)
            .expect("Rust root operation test producer epoch");

        let mut manifest_mounts = vec![
            RustSelectedManifestMount::from_source(
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nengine = { path = \"../engine\" }\n",
            )
            .expect("app manifest facts"),
            RustSelectedManifestMount::from_source(
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .expect("engine manifest facts"),
        ];
        if unrelated_crate_source_count > 0 {
            manifest_mounts.push(
                RustSelectedManifestMount::from_source(
                    "unrelated/Cargo.toml",
                    "[package]\nname = \"unrelated\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .expect("unrelated manifest facts"),
            );
        }
        for manifest in &manifest_mounts {
            let file = ProjectFile::new(project_root.path(), &manifest.relative_path);
            file.write(
                std::str::from_utf8(manifest.source_bytes()).expect("UTF-8 test Cargo input"),
            )
            .expect("write Cargo input before parsing selected source");
        }

        let mut prepared = Vec::new();
        let mut versions = Vec::new();
        let mut source_mounts = Vec::new();
        let mut facts_by_path = BTreeMap::new();
        let mut consumer_source = RUST_ROOT_CONSUMER_SOURCE.to_owned();
        consumer_source.push_str(consumer_suffix);
        for index in 0..source_mount_count - 3 {
            consumer_source.push_str(&format!("mod scale_{index:04};\n"));
        }
        let mut sources = vec![
            (RUST_ROOT_CONSUMER_PATH.to_owned(), consumer_source),
            (
                RUST_ROOT_PROVIDER_ROOT_PATH.to_owned(),
                RUST_ROOT_PROVIDER_ROOT_SOURCE.to_owned(),
            ),
            (
                RUST_ROOT_PROVIDER_PATH.to_owned(),
                RUST_ROOT_PROVIDER_SOURCE.to_owned(),
            ),
        ];
        for index in 0..source_mount_count - 3 {
            sources.push((format!("app/src/scale_{index:04}.rs"), scale_source(index)));
        }
        if unrelated_crate_source_count > 0 {
            let mut unrelated_root = String::new();
            for index in 0..unrelated_crate_source_count {
                unrelated_root.push_str(&format!("pub mod unrelated_{index:04};\n"));
                sources.push((
                    format!("unrelated/src/unrelated_{index:04}.rs"),
                    unrelated_source(index),
                ));
            }
            sources.push(("unrelated/src/lib.rs".to_owned(), unrelated_root));
        }
        let expected_mount_count = source_mount_count
            + if unrelated_crate_source_count > 0 {
                unrelated_crate_source_count + 1
            } else {
                0
            };
        for (path, source) in sources {
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                .expect("hash Rust root source");
            let (state, facts) =
                parsed_operation_state(project_root.path(), &path, &source, &adapter);
            source_mounts.push(RustSelectedSourceMount {
                relative_path: PathBuf::from(&path),
                content_oid: oid,
                facts: state.rust_usage_facts.clone(),
                resolution_facts: facts.clone(),
            });
            prepared.push(
                AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "rust",
                    generation,
                    &adapter,
                    Arc::clone(&state),
                )
                .expect("prepare parsed Rust root blob with resolution bundle"),
            );
            versions.push(WorkspaceFileRow {
                rel_path: path.clone(),
                blob_oid: oid,
            });
            assert!(facts_by_path.insert(path, facts).is_none());
        }
        let (outcomes, _) = store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
        assert_eq!(source_mounts.len(), expected_mount_count);
        assert_eq!(outcomes.len(), expected_mount_count);
        assert!(
            outcomes.iter().all(|outcome| outcome.error.is_none()),
            "{:#?}",
            outcomes
                .iter()
                .map(|outcome| &outcome.error)
                .collect::<Vec<_>>()
        );

        let selected_sources = source_mounts
            .iter()
            .map(|mount| RustSelectedTopologySourceMount {
                relative_path: mount.relative_path.clone(),
                content_oid: mount.content_oid,
                facts: mount.facts.clone(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let profile = RustCallerTargetProfile {
            manifest_path: PathBuf::from("app/Cargo.toml"),
            target_kind: RustCallerTargetKind::Library,
            target_root: PathBuf::from("src/lib.rs"),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            cfg_atoms: BTreeSet::new(),
            features: BTreeSet::new(),
            test: false,
        };
        let selected_context =
            build_rust_selected_context(source_mounts, manifest_mounts.clone(), profile.clone())
                .expect("build Rust root selected context");
        assert!(selected_context.gaps.is_empty());
        assert_eq!(selected_context.root_bridges.len(), 2);

        let workspace_id = WorkspaceId(RUST_ROOT_WORKSPACE_ID.to_owned());
        let manifest_snapshot = sync_rust_operation_inputs(
            &store,
            &workspace_id,
            generation,
            project_root.path(),
            &versions,
            &manifest_mounts,
        )
        .expect("publish selected Rust source and Cargo inputs");
        assert_eq!(manifest_snapshot.revision, 1);
        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert(
            "rust".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: "rust".to_owned(),
                generation,
                revision: manifest_snapshot.revision,
            },
        );
        Self {
            store,
            _project_root: project_root,
            project,
            generation,
            workspace_id,
            snapshots,
            languages: vec![SelectedResolutionLanguage::new("rust", Language::Rust)],
            selected_context,
            profile,
            selected_sources,
            selected_manifests: manifest_mounts.into(),
            consumer_facts: facts_by_path
                .remove(RUST_ROOT_CONSUMER_PATH)
                .expect("Rust consumer facts"),
            provider_root_facts: facts_by_path
                .remove(RUST_ROOT_PROVIDER_ROOT_PATH)
                .expect("Rust provider root facts"),
            provider_facts: facts_by_path
                .remove(RUST_ROOT_PROVIDER_PATH)
                .expect("Rust provider facts"),
        }
    }

    fn open_ready<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        self.open_selected_with_project(&self.project, &[], cancellation)
    }

    fn publish_content(
        &self,
        path: &str,
        source: &str,
        state: &Arc<FileState>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionContentMountRequest {
        use super::super::resolution_publication::ResolutionContentPublicationOutcome;
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
            .expect("hash Rust replacement source");
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "rust",
            self.generation,
            &RustAdapter,
            Arc::clone(state),
        )
        .expect("prepare actual parsed replacement content");
        let ResolutionContentPublicationOutcome::Ready(content) = self
            .store
            .publish_selected_parsed_content(
                self.snapshots.get("rust").expect("captured Rust owner"),
                path,
                prepared,
                cancellation,
            )
            .expect("publish complete replacement content")
        else {
            panic!("live Rust replacement publication must succeed");
        };
        SelectedResolutionContentMountRequest::new(
            content.into_parts().0,
            WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid: oid,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn publish_counterfactual_content(
        &self,
        path: &str,
        source: &str,
        state: &Arc<FileState>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionContentMountRequest {
        let original = ProjectFile::new(self._project_root.path(), path)
            .read_to_string()
            .expect("read original counterfactual source");
        self.publish_content(path, source, state, cancellation)
            .with_counterfactual_base_content_digest(
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes()),
            )
    }

    fn open_content_selected<'a>(
        &'a self,
        masks: &'a [SelectedResolutionOverlayMask],
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        match self
            .store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &self.project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    masks,
                )
                .with_content_mounts(content_mounts),
                cancellation,
            )
            .expect("open Rust operation with published content")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("complete published Rust content must open Ready"),
        }
    }

    fn open_selected_with_project<'a>(
        &'a self,
        project: &'a dyn Project,
        masks: &'a [SelectedResolutionOverlayMask],
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        match self
            .store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    masks,
                ),
                cancellation,
            )
            .expect("open persisted Rust root resolution operation")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("complete persisted Rust root operation must open Ready"),
        }
    }
}

fn measure_production_rust_point_sql(
    fixture: &RustRootResolutionOperationFixture,
) -> (
    ProductionSelectedSqlCost,
    ProductionSelectedSqlCost,
    ResolutionBatchMetrics,
) {
    let cancellation = CancellationToken::default();
    let reference = site_for_identifier(
        &fixture.consumer_facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let reference_range = fixture
        .consumer_facts
        .sites
        .iter()
        .find(|site| site.id == reference)
        .expect("Rust point-cost reference range");
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
        reference_range.start_byte,
        reference_range.end_byte,
    );

    begin_production_selected_sql_trace(&fixture.store);
    let operation = fixture.open_ready(&cancellation);
    let open = checkpoint_production_selected_sql_trace();
    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), &cancellation)
        .expect("build production Rust point-cost context")
    else {
        panic!("production Rust point-cost context must be ready")
    };
    let mut point_metrics = ResolutionBatchMetrics::default();
    let result = operation
        .resolve_rust_reference_with_metrics(
            *context,
            &locator,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut point_metrics,
        )
        .expect("run production Rust point-cost search");
    let search = finish_production_selected_sql_trace(&fixture.store);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(result)) =
        result
    else {
        panic!("production Rust point-cost search must find its provider")
    };
    let result = only_rust_point_answer(result);
    assert_eq!(result.definitions.len(), 1);
    (open, search, point_metrics)
}

/// R8.6. A point request's root inventory is bounded by its endpoint.
///
/// The root half read names the mounts whose halves the request can use: the
/// files it answers references for, and the modules its own crate graph
/// mounts. Adding a whole unrelated crate to the workspace therefore changes
/// neither the statements it issues, the rows it decodes, nor the halves it
/// returns, and adds no statement to the context request built on it.
///
/// Before the mount scope, the universal-root open-symbol request probed every
/// selected mount and hydrated every root path it found, so a point in a
/// three-file crate paid for the workspace. On the Bifrost corpus that
/// persisted import read alone took 60.7 seconds, followed by 21 minutes of
/// context construction that aborted at 6 GB under a 16 GB virtual limit.
/// Measured here on the same fixture with the scope removed: the read grows
/// from 41 to 401 rows and the context request from 149 to 151 statements and
/// 221 to 1,121 rows.
///
/// What this does not pin: growth in the request's *own* crate, and the
/// context build that follows the inventory read. On the merged interior
/// design that build still opens every selected mount's interior, because
/// `lazy_candidate_completion` visits the whole selection for any request that
/// is not one of the two scoped root readers, and the crate context's
/// qualified-prefix pass issues ordinary forward demands. That term is LI-3's;
/// both are recorded as open in the lane document.
#[test]
fn rust_crate_point_context_work_is_bounded_by_its_endpoint() {
    let measurements = [4_usize, 64].map(|unrelated_crate_sources| {
        let fixture = RustRootResolutionOperationFixture::new_with_unrelated_crate_source_count(
            unrelated_crate_sources,
        );
        let cancellation = CancellationToken::default();
        begin_production_selected_sql_trace(&fixture.store);
        let operation = fixture.open_ready(&cancellation);
        let _open = checkpoint_production_selected_sql_trace();
        let mount_count = operation.mount_table().mount_count();
        let endpoint = operation
            .mount_table()
            .mount_for_path("rust", RUST_ROOT_CONSUMER_PATH)
            .unwrap()
            .expect("the consumer file is a selected mount");
        let scope = RustRootHalfScope::new(std::iter::once(&endpoint), std::iter::once(&endpoint));
        let (halves, _) = operation
            .rust_root_halves(&scope, &cancellation, None)
            .expect("read the endpoint's root halves")
            .expect("an uncancelled root half read must exhaust");
        let inventory = checkpoint_production_selected_sql_trace();
        let before = heap_pin_bytes();
        let SelectedRustFileContextOutcome::Ready { context, .. } = operation
            .rust_context_for_file(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
            .expect("build the crate point context")
        else {
            panic!("an uncancelled crate point context must be ready")
        };
        let build = checkpoint_production_selected_sql_trace();
        let retained = heap_pin_bytes() - before;
        drop(context);
        // The operation owns the traced reader; the trace can only be removed
        // once it is checked back in.
        drop(operation);
        let _tail = finish_production_selected_sql_trace(&fixture.store);
        (
            unrelated_crate_sources,
            mount_count,
            halves.len(),
            inventory.statement_count(),
            inventory.decoded_rows,
            build.statement_count(),
            retained,
        )
    });
    eprintln!(
        "endpoint root inventory and crate point context (unrelated crate sources, selected mounts, halves, inventory statements, inventory rows, context statements, retained bytes): {measurements:?}"
    );
    assert!(
        measurements[0].2 > 0 && measurements[0].4 > 0,
        "the endpoint must own root halves for this pin to mean anything: {measurements:?}"
    );
    assert_eq!(
        measurements[0].2, measurements[1].2,
        "an unrelated crate must not add root halves: {measurements:?}"
    );
    assert_eq!(
        measurements[0].3, measurements[1].3,
        "an unrelated crate must not add root inventory statements: {measurements:?}"
    );
    // One tier-1 header row per selected mount is what the root inventory
    // still reads for the whole selection: `candidate_mount_positions` asks
    // which blobs carry a boundary-rooted path of the requested shape before
    // it opens anything. That row is the selection's discovery contract, not
    // this endpoint's work; opening one unrelated mount's interior instead
    // would cost many times this rate.
    let added_mounts = measurements[1].1 - measurements[0].1;
    assert!(
        measurements[1].4 - measurements[0].4 <= added_mounts,
        "an unrelated crate must add only tier-1 header rows: {measurements:?}"
    );
    // Retention is printed, not pinned: `SelectedResolutionContextSet` holds
    // only the mounts that carry a relation or inventory evidence, and is a
    // separate query-lived structure with its own owner.
}

/// A scoped root-half read costs its scope, not the selection.
///
/// `rust_crate_point_context_work_is_bounded_by_its_endpoint` measures the
/// same read, but it had to allow one decoded row per added mount: the tier-1
/// endpoint-header statement carried no scope, so discovering which mounts a
/// request may open cost one row for every mount in the workspace and the
/// scope was applied afterwards in Rust. With the scope bound into the
/// statement the read costs the same statements and the same rows whatever
/// else the workspace holds, which is the property and not a rate. Measured
/// on the same fixture before the scope went into SQL: 10 rows at 8 selected
/// mounts and 70 at 68.
#[test]
fn rust_root_half_read_work_is_bounded_by_its_mount_scope() {
    let measurements = [4_usize, 64].map(|unrelated_crate_sources| {
        let fixture = RustRootResolutionOperationFixture::new_with_unrelated_crate_source_count(
            unrelated_crate_sources,
        );
        let cancellation = CancellationToken::default();
        // The trace follows the reader the operation checks out, so it has to
        // be installed before the operation opens.
        begin_production_selected_sql_trace(&fixture.store);
        let operation = fixture.open_ready(&cancellation);
        let _open = checkpoint_production_selected_sql_trace();
        let mount_count = operation.mount_table().mount_count();
        let endpoint = operation
            .mount_table()
            .mount_for_path("rust", RUST_ROOT_CONSUMER_PATH)
            .unwrap()
            .expect("the consumer file is a selected mount");
        let scope = RustRootHalfScope::new(std::iter::once(&endpoint), std::iter::once(&endpoint));
        let (halves, _) = operation
            .rust_root_halves(&scope, &cancellation, None)
            .expect("read the endpoint's root halves")
            .expect("an uncancelled root half read must exhaust");
        let read = checkpoint_production_selected_sql_trace();
        // The operation owns the traced reader; the trace can only be removed
        // once it is checked back in.
        drop(operation);
        let _tail = finish_production_selected_sql_trace(&fixture.store);
        (
            unrelated_crate_sources,
            mount_count,
            halves.len(),
            read.statement_count(),
            read.decoded_rows,
        )
    });
    eprintln!(
        "scoped root half read (unrelated crate sources, selected mounts, halves, statements, decoded rows): {measurements:?}"
    );
    assert!(
        measurements[1].1 > measurements[0].1,
        "the larger workspace must hold more selected mounts for this pin to mean anything: {measurements:?}"
    );
    assert!(
        measurements[0].2 > 0 && measurements[0].4 > 0,
        "the endpoint must own root halves for this pin to mean anything: {measurements:?}"
    );
    assert_eq!(
        measurements[0].2, measurements[1].2,
        "an unrelated crate must not add root halves: {measurements:?}"
    );
    assert_eq!(
        measurements[0].3, measurements[1].3,
        "an unrelated crate must not add root half statements: {measurements:?}"
    );
    assert_eq!(
        measurements[0].4, measurements[1].4,
        "an unrelated crate must not add root half decoded rows: {measurements:?}"
    );
}

/// A candidate gap-header read costs its scope, not the workspace's gaps.
///
/// `CANDIDATE_GAP_HEADER_UNCONDITIONAL_SQL` states one direction's
/// unconditional completion: the union of every in-scope blob's fragment-wide
/// gap reasons. It used to drive from the header relation with only
/// `(direction, coverage_scope)` bound, so one execution walked every gap
/// header the workspace held for that direction and probed the scope per row.
/// On the tract corpus that is 122,728 rows and 37 to 97 ms, for a read whose
/// answer is a property of the request's own crate closure; lane PL measured
/// it at 20 to 25 percent of a median warm definition request's SQL.
///
/// The read drives from `temp.selected_resolution_scope_mounts`, so it is one
/// covering index seek per in-scope mount and it visits exactly the rows it
/// returns. What makes a point request's cost independent of the workspace's
/// gaps is the other half: the request installs its own crate closure as that
/// scope before it collects its blueprint, so the box the lexical source
/// memoizes per direction is its closure's and not the whole selection's. The
/// production point route installed no scope at all until 2026-09-17, and the
/// forward query session installed one only after the blueprint was built;
/// both now install it where the graph stage does. Measured before that: 1
/// unrelated gapped file gave 1 decoded row and 200 gave 200.
///
/// The owner decided on 2026-09-17 what a forward request's completion covers:
/// a gap in a blob the request cannot bind into cannot qualify its answer,
/// because nothing that blob hides was ever a candidate.
/// `narrowed_forward_scope_keeps_in_closure_gap_reasons` pins the other half,
/// that a gap inside the closure still qualifies it. The read itself is pinned
/// by `the_candidate_gap_header_reads_are_driven_by_their_mount_scope` (the
/// plan) and `the_candidate_gap_header_reads_answer_the_reads_they_replaced`
/// (the answer).
#[test]
fn rust_candidate_gap_header_read_work_is_bounded_by_its_mount_scope() {
    let measurements = [1_usize, 200].map(|unrelated_crate_sources| {
        let fixture =
            RustRootResolutionOperationFixture::new_with_unrelated_gapped_crate_source_count(
                unrelated_crate_sources,
            );
        let workspace_gap_headers = fixture.store.conn.execute(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM resolution_gaps WHERE covers IN (0, 2, 3)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count the workspace's fragment-wide candidate gap headers")
        });
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let reference_range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .expect("the consumer reference range");
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            reference_range.start_byte,
            reference_range.end_byte,
        );
        let cancellation = CancellationToken::default();
        // The trace follows the reader the operation checks out, so it has to
        // be installed before the operation opens.
        begin_production_selected_sql_trace(&fixture.store);
        let operation = fixture.open_ready(&cancellation);
        let _open = checkpoint_production_selected_sql_trace();
        let mount_count = operation.mount_table().mount_count();
        // The request consumes the operation, which returns the traced reader
        // so the trace can be removed below.
        let answered = operation
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
            )
            .expect("the point request answers");
        assert!(
            matches!(answered, BoundedResolution::Complete { .. }),
            "the point request must answer inside its budget"
        );
        let search = finish_production_selected_sql_trace(&fixture.store);
        let gap_header_rows = search
            .rows_by_shape()
            .iter()
            .filter(|(_, _, sql)| sql.contains("resolution_gaps"))
            .map(|(rows, _, _)| *rows)
            .sum::<usize>();
        (
            unrelated_crate_sources,
            mount_count,
            workspace_gap_headers,
            gap_header_rows,
        )
    });
    eprintln!(
        "candidate gap header read (unrelated gapped sources, selected mounts, workspace fragment gap headers, decoded gap header rows): {measurements:?}"
    );
    assert!(
        measurements[1].1 > measurements[0].1,
        "the larger workspace must hold more selected mounts for this pin to mean anything: {measurements:?}"
    );
    assert!(
        measurements[1].2 > measurements[0].2,
        "the unrelated files must carry fragment-wide gap headers for this pin to mean anything: {measurements:?}"
    );
    assert_eq!(
        measurements[0].3, measurements[1].3,
        "gap headers in a crate the request cannot bind into must cost it nothing: {measurements:?}"
    );
}

/// The completion reader must retain each decoded reason on cancellation,
/// and exact lookups must not decode the other buckets at a busy endpoint.
#[test]
fn endpoint_gap_reads_select_exact_buckets_and_retain_cancelled_evidence() {
    use crate::analyzer::resolution::{
        BatchCandidateRequest, BatchResolutionFragmentSource, BindingNodeId, EndpointSignature,
        ResolutionCompletion, ResolutionIncompleteReason, SemanticId, SharedNameId, StackPattern,
        StackVariableId,
    };
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    begin_production_selected_sql_trace(&fixture.store);
    let operation = fixture.open_ready(&cancellation);
    let mount = &operation.ready.inventory.mounts().unwrap()[0];
    let ordinal = mount.ordinal().get();
    let blob = mount.blob_id();
    const NODE: u32 = 900_000;
    const REASON: u32 = 910_000;
    const FANOUT: i64 = 128;
    // These are independent input rows, not the production gap encoder.
    // The schema's shared-name invariant is satisfied even for synthetic names.
    let lookups = fixture.store.conn.execute(move |conn| {
        let mut lookups = vec![0];
        for index in 1..=FANOUT {
            let mut digest = [0_u8; 32];
            digest[..8].copy_from_slice(&index.to_le_bytes());
            digest[31] = 254;
            conn.execute("INSERT INTO resolution_identities(identity_digest) VALUES (?1)", [digest.as_slice()]).expect("insert independent lookup");
            lookups.push(conn.last_insert_rowid());
        }
        for (index, lookup) in lookups.iter().enumerate() {
            conn.execute(
                "INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES (?1,5,?2,?3,?4,?4)",
                params![blob, NODE, lookup, REASON + index as u32],
            ).expect("insert independent gap");
        }
        lookups
    });
    let node = BindingNodeId::local(ordinal, NODE);
    let selected = SemanticId::shared_name(SharedNameId::interned(lookups[17]));
    let exact = || StackPattern::closed([selected]);
    let every = || StackPattern::open([], StackVariableId::local(ordinal, 920_000));
    let request = |index, symbols| {
        BatchCandidateRequest::new(
            index,
            EndpointSignature::new(node, symbols, StackPattern::closed([])),
        )
    };
    let expected = |indices: &[u32]| {
        ResolutionCompletion::incomplete(indices.iter().map(|index| {
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(
                ordinal,
                REASON + index,
            ))
        }))
    };
    let source = operation.ready.lexical_source();
    let _open = checkpoint_production_selected_sql_trace();
    let exact_result = source
        .match_forward_candidates(&[request(0, exact()), request(1, exact())], &cancellation)
        .expect("read exact duplicate requests");
    assert_eq!(
        exact_result.branch_completions(),
        &[expected(&[0, 17]), expected(&[0, 17])]
    );
    let trace = checkpoint_production_selected_sql_trace();
    let endpoint_rows = |trace: &ProductionSelectedSqlCost| {
        trace
            .rows_by_shape()
            .iter()
            .filter(|(_, _, sql)| sql.contains("json_each(?4)") && sql.contains("resolution_gaps"))
            .map(|(rows, _, _)| *rows)
            .sum::<usize>()
    };
    assert_eq!(
        endpoint_rows(&trace),
        2,
        "the exact seek decodes only its two buckets: {trace:?}"
    );
    let mixed = source
        .match_forward_candidates(
            &[
                request(0, exact()),
                request(1, every()),
                request(2, exact()),
                request(3, StackPattern::closed([])),
            ],
            &cancellation,
        )
        .expect("read mixed selectors");
    let all = (0..=FANOUT as u32).collect::<Vec<_>>();
    assert_eq!(
        mixed.branch_completions(),
        &[
            expected(&[0, 17]),
            expected(&all),
            expected(&[0, 17]),
            expected(&[0])
        ]
    );
    let trace = checkpoint_production_selected_sql_trace();
    assert_eq!(
        endpoint_rows(&trace),
        FANOUT as usize + 1,
        "Every subsumes the exact keys without duplicate decoding: {trace:?}"
    );
    let mut saw_partial = false;
    for checks in 1..=160 {
        let token = CancellationToken::cancel_after_checks_for_test(checks);
        let outcome = source
            .match_forward_candidates(&[request(0, every())], &token)
            .expect("cancel endpoint read");
        let branch = &outcome.branch_completions()[0];
        let retained = match branch {
            ResolutionCompletion::Complete => 0,
            ResolutionCompletion::Incomplete(reasons) => reasons.len(),
        };
        if retained > 0 && retained < all.len() {
            saw_partial = true;
            assert!(token.is_cancelled());
            // The all-lookup arm walks this endpoint's PK in lookup order.
            // Its independently inserted evidence prefix must survive intact.
            assert_eq!(*branch, expected(&all[..retained]));
        }
    }
    assert!(
        saw_partial,
        "cancellation must preserve a partially decoded evidence prefix"
    );
    drop(source);
    drop(operation);
    let _trace = finish_production_selected_sql_trace(&fixture.store);
}

/// The gap rows a real blob writes hold together.
///
/// The schema draft gave up composite intra-blob foreign keys because they
/// cost 89.2 MB and half the write rate (lane LD) for invariants the producer
/// asserts, and it put one validation statement per table in tests in their
/// place. This is that statement for `resolution_gaps` and
/// `resolution_gap_reasons`: every gap names a reason that has a provenance
/// row, and every keyed candidate gap names a `resolution_identities` row
/// rather than a number.
///
/// It is not a restatement of the writer. The writer emits two independent
/// row streams from one walk over the lowering, and nothing in it compares
/// them; what this says is that the two agree after the store has interned
/// the names, which is where the streams meet.
#[test]
fn a_blobs_gap_rows_name_reasons_and_identities_that_exist() {
    let fixture =
        RustRootResolutionOperationFixture::new_with_unrelated_gapped_crate_source_count(4);
    let (gaps, reasons, orphan_reasons, unknown_lookups) = fixture.store.conn.execute(|conn| {
        let count = |sql: &str| {
            conn.query_row(sql, [], |row| row.get::<_, i64>(0))
                .expect("count the gap rows")
        };
        (
            count("SELECT COUNT(*) FROM resolution_gaps"),
            count("SELECT COUNT(*) FROM resolution_gap_reasons"),
            count(
                "SELECT COUNT(*) FROM resolution_gaps AS g
                 LEFT JOIN resolution_gap_reasons AS r
                   ON r.blob_id = g.blob_id AND r.reason = g.reason
                 WHERE r.reason IS NULL",
            ),
            count(
                "SELECT COUNT(*) FROM resolution_gaps AS g
                 LEFT JOIN resolution_identities AS i ON i.id = g.lookup
                 WHERE g.lookup <> 0 AND i.id IS NULL",
            ),
        )
    });
    assert!(
        gaps > 0 && reasons > 0,
        "the validation needs real gap rows: {gaps} gaps over {reasons} reasons"
    );
    assert_eq!(
        orphan_reasons, 0,
        "every gap row names a reason with a provenance row"
    );
    assert_eq!(
        unknown_lookups, 0,
        "every keyed candidate gap names an interned shared name"
    );
}

/// The other half of the closure rule: a gap inside the request's own crate
/// closure still qualifies its answer.
///
/// `rust_candidate_gap_header_read_work_is_bounded_by_its_mount_scope` shows
/// that a gap in a crate the request cannot bind into costs it nothing.
/// Narrowing must not be read as "see fewer gaps": a blob the request can bind
/// into can hide a candidate, so its gaps do qualify the answer and every one
/// of them is in the box the request builds. The box is one reason per decoded
/// header row, so the rows are the reasons.
///
/// Each fixture holds `in_closure_gapped_sources` gapped files in the
/// consumer's own crate and exactly one in the unrelated crate, and the pin is
/// an equality rather than a growth rate: the request reads the in-closure
/// gaps and only those. A request that read the whole selection's gaps would
/// decode one row more at both sizes, and one that read none would decode
/// zero.
///
/// The reported completion is not the instrument here. The unconditional box
/// reaches an answer through `scope_reverse_inventory_completion`, which keeps
/// only the reasons whose semantic mounts in a reverse fragment the request
/// admitted, so a request whose binding completes reports none of them however
/// many its box holds. What this pin is about is which gaps reach the box.
#[test]
fn narrowed_forward_scope_keeps_in_closure_gap_reasons() {
    let measurements = [1_usize, 4].map(|in_closure_gapped_sources| {
        let fixture = RustRootResolutionOperationFixture::new_with_in_closure_gapped_source_count(
            in_closure_gapped_sources,
        );
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let reference_range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .expect("the consumer reference range");
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            reference_range.start_byte,
            reference_range.end_byte,
        );
        let cancellation = CancellationToken::default();
        begin_production_selected_sql_trace(&fixture.store);
        let operation = fixture.open_ready(&cancellation);
        let _open = checkpoint_production_selected_sql_trace();
        let answered = operation
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
            )
            .expect("the point request answers");
        let search = finish_production_selected_sql_trace(&fixture.store);
        assert!(
            matches!(answered, BoundedResolution::Complete { .. }),
            "the point request must answer inside its budget"
        );
        let shapes = search.rows_by_shape();
        let gap_shapes = shapes
            .iter()
            .filter(|(_, _, sql)| sql.contains("resolution_gaps"))
            .collect::<Vec<_>>();
        eprintln!("in-closure sources {in_closure_gapped_sources}, complete gap SQL shapes: {gap_shapes:?}");
        let gap_header_rows = shapes
            .iter()
            .filter(|(_, _, sql)| {
                sql.trim()
                    == super::super::resolution_lexical::CANDIDATE_GAP_UNCONDITIONAL_SQL.trim()
            })
            .map(|(rows, _, _)| *rows)
            .sum::<usize>();
        (in_closure_gapped_sources, gap_header_rows)
    });
    eprintln!(
        "in-closure candidate gaps (gapped sources in the caller's crate, decoded gap header rows): {measurements:?}"
    );
    for (in_closure_gapped_sources, gap_header_rows) in measurements {
        assert_eq!(
            gap_header_rows, in_closure_gapped_sources,
            "a forward request's gap box is exactly its closure's gaps: {measurements:?}"
        );
    }
}

/// The scoped endpoint-header statement answers the unscoped one, intersected
/// with the scope.
///
/// `SCOPED_PATH_ENDPOINT_HEADER_MOUNTS_SQL` is not the same text with a
/// predicate added: it drives from the scope instead of from the header
/// relation, and it splits the header rows by identity nullity so each half
/// can use its own partial index. That rewrite has to preserve the answer
/// exactly, and the unscoped statement is the reference implementation that
/// says what the answer is. This runs both over every probe shape the callers
/// can send, against a selection that holds real endpoint headers.
///
/// The producer writes no header with zero fixed symbols for this fixture, and
/// tract has none either, yet both statements give those rows a branch of
/// their own. So the test adds them: one per real (blob, direction), with an
/// open or a closed tail by blob parity. Without them the zero-count branches
/// of both statements would return nothing on every probe and agree
/// vacuously.
#[test]
fn the_scoped_endpoint_header_read_answers_the_unscoped_read_within_its_scope() {
    use crate::analyzer::store::resolution_lexical::{
        PATH_ENDPOINT_HEADER_MOUNTS_SQL, SCOPED_PATH_ENDPOINT_HEADER_MOUNTS_SQL,
    };
    use rusqlite::types::Value;

    let fixture = RustRootResolutionOperationFixture::new();
    let zero_count_tails = fixture.store.conn.execute(|conn| {
        conn.execute(
            "INSERT INTO resolution_path_endpoint_headers
                 (blob_id, direction, identity_id, symbol_fixed_count, open_tail)
             SELECT DISTINCT blob_id, direction, NULL, 0, blob_id % 2
             FROM resolution_path_endpoint_headers",
            [],
        )
        .expect("add headers with no fixed symbol");
        conn.query_row(
            "SELECT COUNT(DISTINCT open_tail) FROM resolution_path_endpoint_headers
             WHERE symbol_fixed_count = 0",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("count the tails of the added headers")
    });
    assert_eq!(
        zero_count_tails, 2,
        "the differential needs headers with no fixed symbol, with open and closed tails"
    );
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let ordinals = operation
        .mounts()
        .unwrap()
        .iter()
        .map(|mount| i64::from(mount.ordinal().get()))
        .collect::<Vec<_>>();
    assert!(ordinals.len() >= 3, "the differential needs a few mounts");
    let connection = operation.ready.inventory.connection();

    // The reader binds a first symbol as its persisted identity id, which is
    // what `identity_id` holds; a digest would never equal it and would leave
    // the keyed arm of both statements unexercised.
    let identities = connection
        .prepare(
            "SELECT DISTINCT h.identity_id
             FROM resolution_path_endpoint_headers AS h
             WHERE h.identity_id IS NOT NULL
             LIMIT 4",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        !identities.is_empty(),
        "the differential needs keyed endpoint headers"
    );

    let scopes = [
        ordinals.clone(),
        Vec::new(),
        ordinals[..1].to_vec(),
        ordinals[1..].to_vec(),
        ordinals.iter().copied().step_by(2).collect(),
    ];
    let mut first_symbols = vec![Value::Null];
    first_symbols.extend(identities.into_iter().map(Value::Integer));

    let mut observed_nonempty = false;
    let mut observed_keyed = false;
    for direction in ["forward", "reverse"] {
        for first_symbol in &first_symbols {
            for fixed_count in [0_i64, 1, 2, 3] {
                for has_tail in [0_i64, 1] {
                    let unscoped = connection
                        .prepare(PATH_ENDPOINT_HEADER_MOUNTS_SQL)
                        .unwrap()
                        .query_map(
                            rusqlite::params![direction, first_symbol, fixed_count, has_tail],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap()
                        .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                        .unwrap();
                    observed_nonempty |= !unscoped.is_empty();
                    observed_keyed |= !unscoped.is_empty()
                        && *first_symbol != Value::Null
                        && (fixed_count, has_tail) != (0, 1);
                    for scope in &scopes {
                        let array = format!("{scope:?}");
                        let scoped = connection
                            .prepare(SCOPED_PATH_ENDPOINT_HEADER_MOUNTS_SQL)
                            .unwrap()
                            .query_map(
                                rusqlite::params![
                                    direction,
                                    first_symbol,
                                    fixed_count,
                                    has_tail,
                                    array
                                ],
                                |row| row.get::<_, i64>(0),
                            )
                            .unwrap()
                            .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                            .unwrap();
                        let expected = unscoped
                            .iter()
                            .copied()
                            .filter(|ordinal| scope.contains(ordinal))
                            .collect::<std::collections::BTreeSet<_>>();
                        assert_eq!(
                            scoped, expected,
                            "direction={direction} first_symbol={first_symbol:?} \
                             fixed_count={fixed_count} has_tail={has_tail} scope={scope:?}"
                        );
                    }
                }
            }
        }
    }
    assert!(
        observed_nonempty,
        "the unscoped read must admit some mount for this differential to mean anything"
    );
    assert!(
        observed_keyed,
        "a keyed probe that is not the wildcard must admit some mount, or the keyed arms \
         were never compared"
    );
}

/// A panicking forward request leaves the whole selection in scope.
///
/// The forward crate scope narrows `temp.selected_resolution_scope_mounts` for
/// the length of one request. The selection's temp tables are materialized once
/// and reused by every later request on the same inventory, and this project
/// asserts instead of branching, so a panic inside a forward request is a
/// designed outcome that must not leave the scope narrowed: the next reverse
/// request would then miss usages in the crates that depend on the
/// definition's, which is a wrong answer and not a slow one.
///
/// `ForwardCrateScope`'s `Drop` is what makes the restore unwind-safe, and only
/// a panic distinguishes it from the ordinary restore it replaced. The middle
/// assertion is what gives the last one meaning: without it a scope that was
/// never narrowed would pass.
#[test]
fn a_panicking_forward_request_restores_the_whole_selection_scope() {
    // The unrelated-crate fixture is the one that makes the narrowing visible:
    // `app` and `engine` are the consumer's closure and the four files of the
    // third crate are outside it. With the default scale files every mount is
    // in the closure and the scope would measure the same either way.
    let fixture = RustRootResolutionOperationFixture::new_with_unrelated_crate_source_count(4);
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let keys = operation
        .rust_crate_keys_for_file(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
        .expect("the consumer file's crates");
    assert!(
        !keys.is_empty(),
        "the fixture's consumer file must belong to a crate for this to narrow anything"
    );
    let selected = operation.ready.inventory.persisted_mount_count();
    let narrowed = std::cell::Cell::new(usize::MAX);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation.with_rust_forward_crate_scope(&keys, &cancellation, || -> Result<()> {
            narrowed.set(
                operation
                    .ready
                    .inventory
                    .scope_mount_count()
                    .expect("the narrowed scope's mount count"),
            );
            panic!("a forward request panics inside its scope");
        })
    }));
    assert!(
        unwound.is_err(),
        "the closure's panic must reach this caller"
    );
    assert!(
        narrowed.get() < selected,
        "the scope must have been narrowed before the panic: {} of {selected} mounts",
        narrowed.get()
    );
    assert_eq!(
        operation
            .ready
            .inventory
            .scope_mount_count()
            .expect("the restored scope's mount count"),
        selected,
        "an unwind out of a forward request must leave the whole selection in scope"
    );
}

#[test]
fn production_rust_point_statement_and_decoded_row_work_is_repeatable() {
    // Production replacement for the private-harness law
    // `bifrost_rust_selected_sql_point_statement_work_is_repeatable`.
    let fixture = RustRootResolutionOperationFixture::new();
    let cold = measure_production_rust_point_sql(&fixture);
    let first_warm = measure_production_rust_point_sql(&fixture);
    let second_warm = measure_production_rust_point_sql(&fixture);
    eprintln!(
        "B1 cold open SQL shapes: {:#?}\nB1 cold search SQL shapes: {:#?}\nB1 first warm open SQL shapes: {:#?}\nB1 warm search SQL shapes: {:#?}\nB1 second warm open SQL shapes: {:#?}\nB1 second warm search SQL shapes: {:#?}",
        cold.0.rows_by_shape(),
        cold.1.rows_by_shape(),
        first_warm.0.rows_by_shape(),
        first_warm.1.rows_by_shape(),
        second_warm.0.rows_by_shape(),
        second_warm.1.rows_by_shape()
    );
    let observed_costs = [&cold, &first_warm, &second_warm].map(|(open, search, metrics)| {
        (
            open.statement_count(),
            open.decoded_rows,
            search.statement_count(),
            search.decoded_rows,
            metrics,
        )
    });
    eprintln!("production Rust point costs: {observed_costs:?}");
    for (_, search, _) in [&cold, &first_warm, &second_warm] {
        assert_eq!(
            point_read_freshness_groups(search),
            1,
            "selected crate-context read groups changed"
        );
        // The rows-era tables that no writer produces any more. This list is
        // not "tier 2 must not be SQL": milestone 6 is making every reader
        // read rows again, and lane TF's typed tables
        // (`resolution_type_frontiers`, `resolution_binding_projections`,
        // `resolution_definition_property_gaps` and the eleven beside them)
        // and the two tier 1 member families they reuse
        // (`resolution_member_scope_properties`,
        // `resolution_member_owner_properties`) are read by a production point
        // on purpose. What this list still holds is that the *old* design's
        // tables are gone: a statement naming one of them is reading something
        // the writer stopped producing.
        for removed in [
            "resolution_fragment_gaps",
            "resolution_reference_sites",
            "resolution_lookup_semantic_recipes",
            "resolution_nodes AS n",
            "resolution_partial_paths",
            "resolution_root_path_demands",
            "resolution_root_path_segments",
            "resolution_stack_variables",
            "resolution_type_transfer_rules",
            "resolution_intrinsic_type_seeds",
            "resolution_qualified_seeded_routes",
            "resolution_declared_type_relations",
            "resolution_relation_members",
            "resolution_declaration_type_properties",
            "resolution_deferred_member_owner_properties",
            "resolution_call_applicability_obligations",
            "resolution_callable_signature_properties",
        ] {
            assert!(
                search.statements.iter().all(|sql| !sql.contains(removed)),
                "tier-2 table {removed} must not serve a production Rust point: {:?}",
                search.statements
            );
        }
        assert!(
            search.statements.iter().all(|sql| {
                !sql.contains("resolution_semantic_sites")
                    || sql.contains("source_native_declaration_bridges")
                    // Unresolved imports retain a terminal root route. Its
                    // source-site bridge joins the exact import occurrence;
                    // this is not a reader of the deleted tier-2 interior.
                    || (sql.contains("source_rust_import_targets AS imported")
                        && sql.contains("bridge.blob_id=route.blob_id")
                        && sql.contains("bridge.source_site=route.reference_source_site")
                        && sql.contains("reference.source_occurrence=imported.target_occurrence_id"))
            }),
            "semantic-site SQL must use a source declaration bridge or keyed import occurrence bridge: {:?}",
            search.statements
        );
        assert!(
            !search
                .statements
                .iter()
                .any(|sql| sql.contains("import_statements")
                    || sql.contains("import_path_segments")
                    || sql.contains("import_lexical_scopes")
                    || sql.contains("import_lexical_prefixes")),
            "selected Rust routing must read canonical imports only: {:?}",
            search.statements
        );
    }
    assert_eq!(
        (
            cold.0.statement_count(),
            cold.0.decoded_rows,
            cold.1.statement_count(),
            cold.1.decoded_rows,
        ),
        // M6 cold setup adds 122 fixed schema statements and three stage
        // cleanup statements, and removes one obsolete metadata read. SQLite's
        // schema ROW events are now explicit; aggregate row counts retain them.
        // Selected module placement adds one TEMP view statement and one
        // schema ROW event. Returning the selected mount with the export
        // removes one export-source execution/row from every search.
        // The cold search adds six shared-name seeks to the warm search below.
        // Two seed reads now join site/catalog membership: each removes one
        // duplicate authority check and one provenance row/read (-4/-4 total).
        // A call result whose one callee is known reads that callee's
        // signature, which may name the argument deciding a generic result:
        // +4 statements and +3 decoded rows for the fixture's calls.
        // A bare path prefix also looks for a module an item macro declares
        // in the requester's module (`NAMED_MACRO_MODULE`): +1 statement and
        // no row. A walk step no declared module answers also asks whether
        // the name is a crate re-exported as a module (`ROOT_REEXPORT`): +10
        // statements and no row.
        // An unanswered closed module can still re-export an external import:
        // checking the original binding on those eight steps adds +8/0.
        // The single-trait scope probe runs
        // `RESOLUTION_FORWARD_CANDIDATE_MATCH_SQL` so an empty trait scope
        // cannot fall through to an enclosing module item: +1/0.
        // Java/Go context metadata adds three fixed TEMP tables and five
        // indexes, plus one implicit unique index: +8 statements/+9 schema
        // rows at first open only. The reference search and warm costs below
        // remain unchanged (native-import-cold-cost trace, 2026-09-28).
        // Go unsaved placement adds one TEMP index on the overlay masks and
        // one TEMP view: +2 statements/+2 schema rows at first open only.
        // The selected type-component and declared-underlying row families
        // add eight cold-open schema statement/row events; Rust's warm point
        // search and its query work remain unchanged.
        (220, 201, 539, 328),
        "production Rust cold point SQL changed; the crate-key open and row-backed point search have exact statement and decoded-row counts"
    );
    assert_eq!(
        (
            first_warm.0.statement_count(),
            first_warm.0.decoded_rows,
            first_warm.1.statement_count(),
            first_warm.1.decoded_rows,
        ),
        // Against the archived B1 warm search: context tokens add 39
        // statements/18 rows; combined stage authority and cleanup add 133/2;
        // publication transactions add six statements; ordinary requested
        // authority removes six statements/one row. The net is +172/+19.
        // Retained open removes one obsolete metadata statement and row.
        // Selected export authority then removes one export-source seek and
        // row. The two joined seed reads remove another four statements/rows,
        // with all other query shapes unchanged in the paired SQL traces.
        // The callee signature read for call results adds +4/+3, as cold.
        // The macro-declared module lookup for a bare prefix adds +1/0, as
        // cold. `ROOT_REEXPORT` on unanswered walk steps adds +10/0, as cold.
        // The same eight original-external-binding seeks add +8/0, as cold.
        // The single-trait scope probe adds +1/0 in each pass, as cold.
        (5, 4, 533, 322),
        "production Rust warm point SQL changed; exact relational selection verification and requested opening metadata keep the open at five statements while the row-backed search has exact statement and decoded-row counts"
    );
    assert_eq!(
        (
            second_warm.0.statement_count(),
            second_warm.0.decoded_rows,
            second_warm.1.statement_count(),
            second_warm.1.decoded_rows,
        ),
        (5, 4, 533, 322),
        "repeated production Rust warm point SQL changed; the repeated retained selection and row-backed search have identical measured counts"
    );
    assert_eq!(cold.2, first_warm.2);
    assert_eq!(first_warm.2, second_warm.2);
    assert_eq!(cold.2.reference_seeds(), 1);
    assert_eq!(cold.2.distinct_candidate_matches(), 4);
    assert_eq!(cold.2.distinct_path_hydrations(), 4);
    assert_eq!(cold.2.distinct_endpoint_classifications(), 4);
    assert_eq!(cold.2.composition_attempts(), 4);
    assert_eq!(cold.2.successful_stitches(), 4);
    assert_eq!(cold.2.worklist_rounds(), 5);
}

#[test]
fn selected_lexical_declarations_project_exact_source_identity_with_indexed_reads() {
    use super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
    use super::super::selected_definition::{
        SelectedDeclarationDefinition, SelectedLexicalDefinitionReadOutcome,
    };
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    let source = "fn first(target: usize) { let target: usize = target; target; }\nfn second(target: usize) { target; }\n";
    for statistics in PlannerStatisticsState::BOTH {
        let mut fixture = RustRootResolutionOperationFixture::new();
        fixture.replace_persisted_consumer_source(source);
        fixture
            .store
            .conn
            .execute(move |connection| statistics.install(connection));
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let inventory = &operation.ready.inventory;
        let requests = {
            let mut statement = inventory.connection().prepare(
                "SELECT mount.mount_ordinal, semantic.semantic_key
                 FROM temp.selected_resolution_mounts AS mount
                 JOIN resolution_semantic_sites AS semantic ON semantic.blob_id = mount.blob_id
                 JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id = semantic.blob_id AND bridge.source_site = semantic.source_site
                 JOIN source_declarations AS declaration ON declaration.blob_id = bridge.blob_id AND declaration.declaration_id = bridge.declaration_id
                 WHERE semantic.semantic_role = 'definition' AND declaration.lexical_kind IS NOT NULL
                 ORDER BY declaration.declaration_id",
            ).unwrap();
            statement
                .query_map([], |row| {
                    Ok((
                        SelectedResolutionMountOrdinal::new(row.get(0)?),
                        crate::analyzer::resolution::ResolutionLocalKey::new(row.get(1)?),
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(requests.len(), 3);
        for requested in [&requests[..1], requests.as_slice()] {
            let SelectedLexicalDefinitionReadOutcome::Ready(rows) = inventory
                .selected_lexical_definitions(requested, &cancellation)
                .unwrap()
            else {
                panic!("live canonical lexical projection must finish");
            };
            assert_eq!(rows.len(), requested.len());
            assert!(rows.iter().all(|(_, _, definition)| matches!(
                definition,
                SelectedDeclarationDefinition::Lexical(definition) if definition.identifier == "target"
            )));
            let plan = explain_pin(
                inventory.connection(),
                &pinned("selected_lexical_definitions"),
            );
            for alias in [
                "mount",
                "interior",
                "source",
                "semantic",
                "bridge",
                "declaration",
            ] {
                assert!(
                    plan.iter()
                        .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                    "canonical projection must seek {alias} with {statistics}: {plan:#?}"
                );
            }
            assert!(
                plan.iter().all(|detail| !detail.contains("AUTOMATIC")
                    && !detail.contains("TEMP B-TREE")
                    && !detail.contains("CO-ROUTINE")),
                "{statistics}: {plan:#?}"
            );
        }
        let SelectedLexicalDefinitionReadOutcome::Ready(rows) = inventory
            .selected_lexical_definitions(&requests, &cancellation)
            .unwrap()
        else {
            panic!("canonical lexical rows")
        };
        let mut actual = rows
            .into_iter()
            .map(|(_, _, definition)| {
                let SelectedDeclarationDefinition::Lexical(definition) = definition else {
                    panic!("every requested coordinate is a lexical binder: {definition:?}");
                };
                (
                    definition.name_range.start_byte,
                    definition.kind,
                    source[definition.declaration_range.start_byte
                        ..definition.declaration_range.end_byte]
                        .to_owned(),
                )
            })
            .collect::<Vec<_>>();
        actual.sort_unstable();
        let first_parameter = source.find("target: usize").unwrap();
        let local = source.find("let target").unwrap() + "let ".len();
        let second_parameter = source.rfind("target: usize").unwrap();
        assert_eq!(
            actual,
            vec![
                (
                    first_parameter,
                    crate::analyzer::DeclarationKind::Parameter,
                    "target: usize".to_owned()
                ),
                (
                    local,
                    crate::analyzer::DeclarationKind::LocalVariable,
                    "let target: usize = target;".to_owned()
                ),
                (
                    second_parameter,
                    crate::analyzer::DeclarationKind::Parameter,
                    "target: usize".to_owned()
                ),
            ]
        );
        cancellation.cancel();
        assert!(matches!(
            inventory
                .selected_lexical_definitions(&requests, &cancellation)
                .unwrap(),
            SelectedLexicalDefinitionReadOutcome::Cancelled
        ));
    }
}

#[derive(Debug)]
struct ProductionRustPointScaleMeasurement {
    source_mounts: usize,
    open: ProductionSelectedSqlCost,
    /// The workspace-scoped Rust context build, which reads the whole selected
    /// root inventory once for the profile.
    context: ProductionSelectedSqlCost,
    /// The request's own search, from the located reference to the projected
    /// definition.
    resolve: ProductionSelectedSqlCost,
    /// Both of the above, which is what the campaign pins have always
    /// measured.
    search: ProductionSelectedSqlCost,
    point_metrics: ResolutionBatchMetrics,
    outcome: ProductionRustPointScaleOutcome,
    receiver_work: ReceiverAnalysisWork,
    open_elapsed_ns: u128,
    point_elapsed_ns: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductionRustPointScaleOutcome {
    Complete,
    Exceeded(ReceiverBudgetLimit),
}

fn measure_production_rust_point_scale(
    fixture: &RustRootResolutionOperationFixture,
) -> ProductionRustPointScaleMeasurement {
    let cancellation = CancellationToken::default();
    let reference = site_for_identifier(
        &fixture.consumer_facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let reference_range = fixture
        .consumer_facts
        .sites
        .iter()
        .find(|site| site.id == reference)
        .expect("Rust point-scale reference range");
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
        reference_range.start_byte,
        reference_range.end_byte,
    );

    begin_production_selected_sql_trace(&fixture.store);
    let open_started = Instant::now();
    let operation = fixture.open_ready(&cancellation);
    let open_elapsed_ns = open_started.elapsed().as_nanos();
    let open = checkpoint_production_selected_sql_trace();
    let source_mounts = operation.mount_table().mount_count();

    // The eager route is the oracle. It runs on its own operation, it is not
    // part of the measured production cost, and its batch metrics are what the
    // composition pins below assert: a demand answer is composed from
    // per-endpoint relations, so no single batch summarises it.
    let oracle_operation = fixture.open_ready(&cancellation);
    // Expected target construction reads metadata on the separate oracle
    // operation, so it cannot prefill the measured request's row memo.
    let provider_mount = oracle_operation
        .mount_table()
        .mount_for_path("rust", RUST_ROOT_PROVIDER_PATH)
        .unwrap()
        .expect("Rust point-scale provider mount");
    let provider_artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        provider_mount.fragment(),
        crate::analyzer::resolution::test_shared_names(),
        Language::Rust,
        &fixture.provider_facts,
    );
    let provider_site = site_for_identifier(
        &fixture.provider_facts,
        "target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Value,
    );
    let expected_target = semantic_at(
        &provider_artifact,
        provider_site,
        LoweredSemanticRole::Definition,
    );
    let expected_provider_unit = fixture
        .provider_facts
        .definition_units
        .iter()
        .find(|crosswalk| crosswalk.declaration == provider_site)
        .expect("Rust point-scale provider definition parser unit")
        .unit
        .clone();
    let SelectedRustFileContextOutcome::Ready { context, .. } = oracle_operation
        .rust_test_crate_context(fixture.profile.clone(), &cancellation)
        .expect("build production Rust point-scale oracle context")
    else {
        panic!("production Rust point-scale oracle context must be ready")
    };
    let mut point_metrics = ResolutionBatchMetrics::default();
    let oracle = oracle_operation
        .resolve_rust_reference_bounded(
            *context,
            &locator,
            ReceiverAnalysisBudget::default(),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut point_metrics,
        )
        .expect("run the production Rust point-scale oracle");
    let _oracle_cost = checkpoint_production_selected_sql_trace();

    // The crate-row point path has no retained profile warmup. Measure its
    // own context queries and native stitching from this fresh operation.
    let point_started = Instant::now();
    let context_cost = checkpoint_production_selected_sql_trace();
    let bounded = operation
        .resolve_rust_reference_for_caller_bounded(
            Path::new(RUST_ROOT_CONSUMER_PATH),
            &locator,
            ReceiverAnalysisBudget::default(),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut ResolutionBatchMetrics::default(),
        )
        .expect("run production Rust point-scale search");
    let point_elapsed_ns = point_started.elapsed().as_nanos();
    let resolve_cost = finish_production_selected_sql_trace(&fixture.store);
    let search = ProductionSelectedSqlCost {
        statements: [
            context_cost.statements.clone(),
            resolve_cost.statements.clone(),
        ]
        .concat(),
        rows_by_statement: [
            context_cost.rows_by_statement.clone(),
            resolve_cost.rows_by_statement.clone(),
        ]
        .concat(),
        internal_schema_rows: context_cost.internal_schema_rows + resolve_cost.internal_schema_rows,
        decoded_rows: context_cost.decoded_rows + resolve_cost.decoded_rows,
    };
    let answer_of = |bounded| match bounded {
        BoundedResolution::Complete { value, work } => {
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                result,
            )) = value
            else {
                panic!("production Rust point-scale search must return a native found answer")
            };
            let result = only_rust_point_answer(result);
            assert_eq!(
                result.resolution.binding().completion(),
                &ResolutionCompletion::Complete
            );
            assert_eq!(
                result.resolution.binding().targets(),
                std::slice::from_ref(&expected_target),
                "production Rust point-scale target changed"
            );
            assert_eq!(
                result.definitions.as_slice(),
                std::slice::from_ref(&expected_provider_unit),
                "production Rust point-scale projected definition changed"
            );
            (
                ProductionRustPointScaleOutcome::Complete,
                work,
                Some(result),
            )
        }
        BoundedResolution::Exceeded { limit, work } => {
            (ProductionRustPointScaleOutcome::Exceeded(limit), work, None)
        }
        BoundedResolution::Cancelled { work } => {
            panic!("uncancelled production Rust point-scale search stopped at {work:?}")
        }
    };
    let (oracle_outcome, _, oracle_answer) = answer_of(oracle);
    let bounded = match bounded {
        BoundedResolution::Complete {
            value: SelectedRustCallerReferenceOutcome::Operation(value),
            work,
        } => BoundedResolution::Complete { value, work },
        BoundedResolution::Complete { work, .. } => {
            panic!("the point-scale caller owns a selected Cargo target: {work:?}")
        }
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    };
    let (outcome, receiver_work, answer) = answer_of(bounded);
    assert_eq!(
        outcome, oracle_outcome,
        "the demand and eager routes must agree on the outcome"
    );
    match (&answer, &oracle_answer) {
        (Some(answer), Some(oracle)) => {
            assert_eq!(answer.resolution, oracle.resolution);
            assert_eq!(answer.definitions, oracle.definitions);
            assert_eq!(answer.lexical_definitions, oracle.lexical_definitions);
        }
        (None, None) => {}
        _ => panic!("the demand and eager routes must agree on whether an answer exists"),
    }
    assert!(
        open.statement_count() > 0,
        "point-scale open must execute SQL"
    );
    assert!(
        search.statement_count() > 0,
        "point-scale search must execute SQL"
    );

    ProductionRustPointScaleMeasurement {
        source_mounts,
        open,
        context: context_cost,
        resolve: resolve_cost,
        search,
        point_metrics,
        outcome,
        receiver_work,
        open_elapsed_ns,
        point_elapsed_ns,
    }
}

fn run_production_rust_point_scale_campaign(
    source_mount_count: usize,
    expected_outcome: ProductionRustPointScaleOutcome,
) -> ProductionRustPointScaleMeasurement {
    let fixture =
        RustRootResolutionOperationFixture::new_with_source_mount_count(source_mount_count);
    let cold = measure_production_rust_point_scale(&fixture);
    let measurement = measure_production_rust_point_scale(&fixture);
    eprintln!(
        "production Rust point-scale cold baseline: mounts={}, open=({},{},{}ns), search=({},{},{}ns)",
        cold.source_mounts,
        cold.open.statement_count(),
        cold.open.decoded_rows,
        cold.open_elapsed_ns,
        cold.search.statement_count(),
        cold.search.decoded_rows,
        cold.point_elapsed_ns,
    );
    let (outcome, budget_limit) = match measurement.outcome {
        ProductionRustPointScaleOutcome::Complete => ("complete", "null"),
        ProductionRustPointScaleOutcome::Exceeded(limit) => ("exceeded", limit.as_str()),
    };
    println!(
        "{{\"campaign\":\"production_rust_point_scale\",\"source_mounts\":{},\"outcome\":\"{}\",\"budget_limit\":{},\"open\":{{\"statements\":{},\"decoded_rows\":{},\"elapsed_ns\":{}}},\"point_search\":{{\"statements\":{},\"decoded_rows\":{},\"elapsed_ns\":{}}},\"resolution_batch_metrics\":{{\"reference_seeds\":{},\"batches\":{},\"distinct_candidate_matches\":{},\"distinct_path_hydrations\":{},\"distinct_endpoint_classifications\":{},\"composition_attempts\":{},\"successful_stitches\":{},\"worklist_rounds\":{},\"peak_frontier_paths\":{},\"peak_candidate_matches\":{},\"peak_hydrated_paths\":{},\"peak_classified_endpoints\":{}}},\"receiver_analysis_work\":{{\"setup_nodes\":{},\"summary_expansions\":{},\"scope_nodes\":{}}}}}",
        measurement.source_mounts,
        outcome,
        if budget_limit == "null" {
            "null".to_owned()
        } else {
            format!("\"{budget_limit}\"")
        },
        measurement.open.statement_count(),
        measurement.open.decoded_rows,
        measurement.open_elapsed_ns,
        measurement.search.statement_count(),
        measurement.search.decoded_rows,
        measurement.point_elapsed_ns,
        measurement.point_metrics.reference_seeds(),
        measurement.point_metrics.batches(),
        measurement.point_metrics.distinct_candidate_matches(),
        measurement.point_metrics.distinct_path_hydrations(),
        measurement
            .point_metrics
            .distinct_endpoint_classifications(),
        measurement.point_metrics.composition_attempts(),
        measurement.point_metrics.successful_stitches(),
        measurement.point_metrics.worklist_rounds(),
        measurement.point_metrics.peak_frontier_paths(),
        measurement.point_metrics.peak_candidate_matches(),
        measurement.point_metrics.peak_hydrated_paths(),
        measurement.point_metrics.peak_classified_endpoints(),
        measurement.receiver_work.setup_nodes,
        measurement.receiver_work.summary_expansions,
        measurement.receiver_work.scope_nodes,
    );
    println!(
        "{{\"attribution\":\"production_rust_point_search_split\",\"source_mounts\":{source_mount_count},\"context_statements\":{},\"context_decoded_rows\":{},\"resolve_statements\":{},\"resolve_decoded_rows\":{}}}",
        measurement.context.statement_count(),
        measurement.context.decoded_rows,
        measurement.resolve.statement_count(),
        measurement.resolve.decoded_rows,
    );
    for (rows, executions, sql) in measurement.search.rows_by_shape() {
        println!(
            "{{\"attribution\":\"production_rust_point_search_rows\",\"source_mounts\":{source_mount_count},\"decoded_rows\":{rows},\"executions\":{executions},\"sql\":{sql:?}}}"
        );
    }
    assert_eq!(measurement.source_mounts, source_mount_count);
    assert_eq!(measurement.outcome, expected_outcome);
    measurement
}

fn assert_production_rust_point_scale_measurement(
    measurement: &ProductionRustPointScaleMeasurement,
    expected_sql: (usize, usize, usize, usize),
    expected_scope_nodes: usize,
) {
    assert_eq!(
        point_read_freshness_groups(&measurement.search),
        1,
        "selected point read groups changed"
    );
    assert_eq!(
        (
            measurement.open.statement_count(),
            measurement.open.decoded_rows,
            measurement.search.statement_count(),
            measurement.search.decoded_rows,
        ),
        expected_sql,
        "production Rust point-scale SQL cost changed; endpoint, declaration-authority, revalidation and request-keyed typed/gap reads remain exact"
    );
    assert_eq!(
        measurement.receiver_work,
        ReceiverAnalysisWork {
            setup_nodes: 0,
            summary_expansions: 10,
            scope_nodes: expected_scope_nodes,
        },
        "production Rust point-scale receiver work changed"
    );
    assert_eq!(measurement.point_metrics.reference_seeds(), 1);
    assert_eq!(measurement.point_metrics.batches(), 1);
    assert_eq!(
        measurement.point_metrics.distinct_candidate_matches(),
        4,
        "the point-scale fixture has the same four exact candidates as its eager oracle"
    );
    assert_eq!(measurement.point_metrics.distinct_path_hydrations(), 4);
    assert_eq!(
        measurement
            .point_metrics
            .distinct_endpoint_classifications(),
        4
    );
    assert_eq!(measurement.point_metrics.composition_attempts(), 4);
    assert_eq!(measurement.point_metrics.successful_stitches(), 4);
    assert_eq!(measurement.point_metrics.worklist_rounds(), 5);
    assert_eq!(measurement.point_metrics.peak_frontier_paths(), 1);
    assert_eq!(measurement.point_metrics.peak_candidate_matches(), 1);
    assert_eq!(measurement.point_metrics.peak_hydrated_paths(), 4);
    assert_eq!(measurement.point_metrics.peak_classified_endpoints(), 5);
}

#[test]
#[ignore = "explicit Milestone 4 production Rust 256-mount point-scale campaign"]
fn ignored_production_rust_point_scale_256_mounts() {
    let measurement =
        run_production_rust_point_scale_campaign(256, ProductionRustPointScaleOutcome::Complete);
    // These measure the production point path, which resolves prefixes through
    // the demand provider and obtains its Rust topology from crate rows. The
    // deleted eager workspace route no longer runs beside the measurement.
    //
    // The retained selection makes the warm open flat: three statements and
    // three decoded rows at every campaign size. Caller preparation is retained
    // per file, so a warm request reads no preparation SQL at all.
    //
    // Measured on the demand route at 256 / 1,024 / 2,048 unrelated mounts:
    //
    //   search statements       34 /    34 /     34
    //   search decoded rows     19 /    19 /     19
    //   interior index lookups  49 /    49 /     49
    //   scope steps            330 /   330 /    330
    //
    // After reconciliation with stage 2, CM's endpoint-only match takes it
    // to 65 search statements, 65 decoded rows, 79 interior dispatches and
    // 326 scope steps. Matches and classifications read rows; hydration is
    // a separate seek again. The four fewer scope steps are charges removed
    // for the empty second fragment source, not fewer admitted candidates.
    // Full root-prefix seeks then remove 24 rejected endpoint rows: search
    // remains 65 statements and now decodes 41 rows at every scale. Reverse
    // candidate reads return four rows in three executions; scope remains 326.
    //
    // The combined GR/ST/TF/CM run measures 86 search statements, 48 rows
    // and 58 interior dispatches at all three sizes; scope remains 326.
    //
    // Search statements were 35 until a boundary-rooted request's branch
    // completion box moved from the blobs' interiors to
    // `resolution_gaps` (then `resolution_candidate_gap_headers`). The boundary query used to run once
    // per candidate read that named the universal root; it now returns the gap
    // rows themselves and is memoized per direction per lexical source.
    //
    // The point search is now constant in workspace size. It was 66 / 120 /
    // 201 statements and 579 / 2,169 / 4,298 rows while the persisted
    // candidate pages still served the match half; with the interior as the
    // only candidate reader, the only SQL a search issues is tier-1 endpoint
    // headers and source and crate authority, and none of it pages per mount.
    //
    // Scope steps were `3 * mounts + 332`, then `2 * mounts + 331` once
    // `SelectedResolutionContextSet::extend_root_bridges` stopped rebuilding a
    // dense mount vector to append a handful of bridges. The last per-mount
    // term was the interior's own candidate index: keyed by the endpoint node
    // alone, a universal-root request walked every root-anchored path that
    // node offered and charged one step for each before
    // `endpoint_admits_candidate` rejected it on its first cell. The index is
    // keyed by that cell now, so the request walks its own bucket and the
    // open-tail bucket only. That removes exactly `2 * mounts + 1` charges at
    // every measured size -- two root halves per selected mount plus the one
    // the request's own fragment contributes -- and what is left is 330 at
    // 256, 1,024 and 2,048 mounts. The count is flat in the inventory.
    //
    // The search went from 36 statements and 21 decoded rows to 42 and 22 when
    // the forward crate scope reached this route. Six statements and one row,
    // none of which grows with the selection: the check that no requested crate
    // is a detached topology (the one decoded row), the three writes that
    // narrow `temp.selected_resolution_scope_mounts` to the closure and add the
    // mounts no crate row can place, and the two the guard's `Drop` spends
    // putting the whole selection back. The graph route and the forward query
    // session have paid the same six since lane CL. What they buy is that the
    // request never opens an interior in a crate that depends on its own, and
    // that its candidate gap box is its closure's rather than the workspace's.
    //
    // It then went from 42 and 22 to 54 and 35 when a shared name became an
    // interned integer (lane ID-2). Twelve statements and thirteen rows: one
    // seek per distinct shared name this request mints from a spelling, asked
    // once and memoized for the request. The figure is the same at 256, 1,024
    // and 2,048 mounts, which is the property this campaign measures: it is a
    // function of the names the request asks for, not of the selection. What
    // it replaces is a join to `resolution_identities` on five reads and a
    // second statement per hydration batch, which is why the warm point pin
    // above moves the other way.
    //
    // It then went from 54 and 35 to 51 and 32 when that seek moved to a
    // bounded cache on the store (stage 2). An interned id is a store fact
    // that is never reused, so the first request in the process pays the seek
    // and the campaign's measured request pays only for the names no earlier
    // request in it asked about. Three of the twelve are left, and they are
    // the same three at 256, 1,024 and 2,048 mounts.
    assert_production_rust_point_scale_measurement(&measurement, (6, 5, 175, 136), 326);
}

#[test]
#[ignore = "explicit Milestone 4 production Rust 1,024-mount point-scale campaign"]
fn ignored_production_rust_point_scale_1024_mounts() {
    let measurement =
        run_production_rust_point_scale_campaign(1_024, ProductionRustPointScaleOutcome::Complete);
    assert_production_rust_point_scale_measurement(&measurement, (6, 5, 175, 136), 326);
}

#[test]
#[ignore = "explicit Milestone 4 production Rust 2,048-mount point-scale campaign"]
fn ignored_production_rust_point_scale_2048_mounts() {
    let measurement =
        run_production_rust_point_scale_campaign(2_048, ProductionRustPointScaleOutcome::Complete);
    assert_production_rust_point_scale_measurement(&measurement, (6, 5, 175, 136), 326);
}

#[test]
fn persisted_rust_macro_reference_round_trips_through_the_selected_store() {
    const PATH: &str = "app/src/macro_case.rs";
    const SOURCE: &str = concat!(
        "macro_rules! persisted_macro { () => { 7usize }; }\n",
        "fn invoke() -> usize { persisted_macro!() }\n",
    );

    let fixture = RustRootResolutionOperationFixture::new();
    let (state, facts) =
        parsed_operation_state(fixture._project_root.path(), PATH, SOURCE, &RustAdapter);
    let definition = site_for_identifier(
        &facts,
        "persisted_macro",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Macro,
    );
    let reference = site_for_identifier(
        &facts,
        "persisted_macro",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Macro,
    );
    let expected = facts
        .definition_units
        .iter()
        .find(|crosswalk| crosswalk.declaration == definition)
        .expect("persisted macro definition has a parser-unit crosswalk")
        .unit
        .clone();
    let reference_range = facts
        .sites
        .iter()
        .find(|site| site.id == reference)
        .expect("persisted macro reference range");
    let oid =
        Oid::hash_object(ObjectType::Blob, SOURCE.as_bytes()).expect("hash Rust macro source");
    let prepared =
        AnalyzerStore::prepare_parsed_blob(oid, "rust", fixture.generation, &RustAdapter, state)
            .expect("prepare Rust macro blob with resolution bundle");
    let (outcomes, _) = fixture
        .store
        .persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);
    let workspace_id = fixture.workspace_id.as_str().to_owned();
    let generation = fixture.generation.get();
    fixture.store.conn.execute(move |conn| {
        conn.execute(
            "INSERT INTO workspace_file_versions(
               workspace_id, lang, generation, rel_path, blob_oid,
               projection_digest, valid_from
             ) VALUES(?1, 'rust', ?2, ?3, ?4, ?5, 1)",
            params![
                workspace_id,
                generation,
                PATH,
                oid.to_string(),
                format!("{:064x}", 799),
            ],
        )
        .unwrap();
    });

    fixture
        .store
        .reconcile_rust_crates(&fixture.snapshots["rust"])
        .unwrap();

    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), &cancellation)
        .expect("build persisted Rust macro context")
    else {
        panic!("persisted Rust macro context must be ready")
    };
    let result = operation
        .resolve_rust_reference(
            *context,
            &SelectedSemanticLocator::for_reference_range(
                "rust",
                PATH,
                reference_range.start_byte,
                reference_range.end_byte,
            ),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .expect("resolve persisted Rust macro reference");
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(result)) =
        result
    else {
        panic!("persisted Rust macro reference must be found natively")
    };
    let result = only_rust_point_answer(result);
    assert_eq!(result.definitions, [expected]);
    assert_eq!(
        result.resolution.completion(),
        &ResolutionCompletion::Complete
    );
}

#[test]
fn published_rust_authority_preserves_exact_bridge_and_rejects_duplicate_rows() {
    use super::rust_privacy::{
        read_selected_rust_declaration_authority_with_cancellation,
        rust_selected_declaration_authority,
    };
    use brokk_bifrost_core::analyzer::rust_facts::{RustDeclarationKind, RustVisibility};
    let fixture = RustRootResolutionOperationFixture::new();
    let source = "fn hidden() {}\n";
    let (state, _) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_CONSUMER_PATH,
        source,
        &RustAdapter,
    );
    let facts = state
        .source_facts
        .as_ref()
        .expect("actual parsed source authority");
    let property = facts
        .rust_declaration_properties
        .iter()
        .find(|property| property.kind == RustDeclarationKind::Function)
        .expect("parsed function property");
    let declaration = property.declaration;
    let source_site = facts
        .native_declaration_sources
        .iter()
        .find(|(_, native)| *native == declaration)
        .expect("parsed function source bridge")
        .0;
    let cancellation = CancellationToken::default();
    let content = fixture.publish_counterfactual_content(
        RUST_ROOT_CONSUMER_PATH,
        source,
        &state,
        &cancellation,
    );
    let blob_id = content.publication().blob_id();
    let masks = [SelectedResolutionOverlayMask::replacement(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
    )];
    let operation = fixture.open_content_selected(&masks, vec![content], &cancellation);
    let mount = operation
        .ready
        .inventory
        .mount_record_for_path("rust", RUST_ROOT_CONSUMER_PATH)
        .unwrap()
        .unwrap()
        .ordinal();
    let read = |site| {
        read_selected_rust_declaration_authority_with_cancellation(
            &operation.ready.inventory,
            &[(mount, site)],
            &cancellation,
            None,
        )
    };
    let mut rows = read(source_site).unwrap().unwrap();
    assert_eq!(rows.len(), 1);
    let fact = rows.pop().unwrap();
    assert_eq!(fact.mount, Some(mount));
    assert_eq!(fact.source_site, source_site);
    assert_eq!(fact.declaration, declaration);
    assert_eq!(fact.visibility, RustVisibility::Private);
    let crate_root = fixture._project_root.path().join("app");
    let authority = rust_selected_declaration_authority(fact, &crate_root, &["private".to_owned()]);
    assert_eq!(authority.source_site, source_site);
    assert_eq!(authority.declaration, declaration);
    assert_eq!(authority.crate_root, crate_root);
    assert_eq!(authority.declaring_module_segments.as_ref(), ["private"]);
    assert_store_error_contains(
        read(ResolutionSiteId::new(u32::MAX)),
        "incomplete Rust declaration authority",
    );

    // Isolate the primary-key invariant from the broader sealed-row guard.
    fixture.store.conn.execute(move |connection| {
        for table in [
            "source_native_declaration_bridges",
            "source_rust_declaration_properties",
        ] {
            connection
                .execute_batch(&format!("DROP TRIGGER {table}_no_insert_after_seal"))
                .expect("allow insertion to test canonical primary-key uniqueness");
            let error = connection
                .execute(
                    &format!("INSERT INTO {table} SELECT * FROM {table} WHERE blob_id=?1"),
                    [blob_id],
                )
                .expect_err("duplicate exact source authority rows must be rejected");
            let rusqlite::Error::SqliteFailure(error, _) = error else {
                panic!("duplicate authority failed outside SQLite constraints");
            };
            assert_eq!(
                error.extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
            );
        }
    });
}

#[test]
fn selected_rust_private_inherent_persisted_and_dirty_overlay_have_the_same_authority() {
    let mut fixture = RustRootResolutionOperationFixture::new();
    let (persisted_state, persisted_facts) =
        fixture.replace_persisted_consumer_source(RUST_PRIVATE_INHERENT_SOURCE);
    let names = persisted_facts
        .names
        .iter()
        .map(|name| (name.id, name.spelling.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut reference_sites = persisted_facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && names.get(&identifier.name).copied() == Some("hidden")
        })
        .map(|identifier| identifier.site)
        .collect::<Vec<_>>();
    reference_sites.sort_by_key(|site_id| {
        persisted_facts
            .sites
            .iter()
            .find(|site| site.id == *site_id)
            .expect("private Rust reference site")
            .start_byte
    });
    assert_eq!(
        reference_sites.len(),
        3,
        "same, descendant, and sibling calls must have distinct structured reference sites"
    );
    let expected_definition_id = persisted_state
        .declarations
        .iter()
        .find(|definition| definition.identifier() == "hidden")
        .expect("private Rust inherent method declaration")
        .declaration_id()
        .to_string();

    let dirty_source = format!("{RUST_PRIVATE_INHERENT_SOURCE}// dirty overlay\n");
    let (dirty_state, dirty_facts) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_CONSUMER_PATH,
        &dirty_source,
        &RustAdapter,
    );
    let masks = [SelectedResolutionOverlayMask::replacement(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
    )];
    let cancellation = CancellationToken::default();
    let persisted = rust_private_point_summaries(
        || fixture.open_ready(&cancellation),
        fixture.profile.clone(),
        &persisted_facts,
        RUST_ROOT_CONSUMER_PATH,
        &reference_sites,
        &cancellation,
    );
    let mut dirty_reference_sites = dirty_facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && dirty_facts
                    .names
                    .iter()
                    .find(|name| name.id == identifier.name)
                    .map(|name| name.spelling.as_str())
                    == Some("hidden")
        })
        .map(|identifier| identifier.site)
        .collect::<Vec<_>>();
    dirty_reference_sites.sort_by_key(|site_id| {
        dirty_facts
            .sites
            .iter()
            .find(|site| site.id == *site_id)
            .expect("dirty private Rust reference site")
            .start_byte
    });
    let overlay = rust_private_point_summaries(
        || {
            fixture.open_content_selected(
                &masks,
                vec![fixture.publish_counterfactual_content(
                    RUST_ROOT_CONSUMER_PATH,
                    &dirty_source,
                    &dirty_state,
                    &cancellation,
                )],
                &cancellation,
            )
        },
        fixture.profile.clone(),
        &dirty_facts,
        RUST_ROOT_CONSUMER_PATH,
        &dirty_reference_sites,
        &cancellation,
    );

    assert_eq!(
        persisted, overlay,
        "persisted and dirty Rust authority rows diverged"
    );
    assert_eq!(persisted.len(), 3);
    for allowed in &persisted[..2] {
        assert!(
            allowed.located,
            "same/descendant private calls must resolve"
        );
        assert_eq!(
            allowed.definition_ids,
            std::slice::from_ref(&expected_definition_id)
        );
        assert!(allowed.complete, "allowed private call must be complete");
    }
    assert!(
        persisted[2].located,
        "the denied sibling reference still has an exact source site"
    );
    assert!(
        persisted[2].definition_ids.is_empty(),
        "a sibling module must not resolve the private inherent method"
    );
    assert!(
        persisted[2].complete,
        "the denied sibling binding must be exhaustively empty"
    );
}

#[test]
fn selected_rust_exports_match_fresh_derivation_after_content_changes() {
    use super::rust_crate_context::Module;
    use super::rust_crate_rows::RustCrateRows;

    let query = |operation: &SelectedResolutionOperation<'_, '_>,
                 path: &str,
                 namespace: &str,
                 name: &str| {
        let conn = operation.ready.inventory.connection();
        crate::analyzer::store::rust_crates::register_point_export_functions(conn).unwrap();
        let (topology, blob, scope, edition): (i64, i64, u32, String) = conn.query_row(
            "SELECT source.topology_id, source.blob_id, scopes.resolution_scope, owner.edition
             FROM rust_crate_container_sources AS source
             JOIN selected_rust_crates AS owner ON owner.topology_id=source.topology_id
             JOIN source_rust_module_scopes AS scopes ON scopes.blob_id=source.blob_id AND scopes.ordinal=source.scope_ordinal
             WHERE source.rel_path=?1 AND source.container_path='crate'",
            [RUST_ROOT_CONSUMER_PATH],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap();
        let mount = operation
            .mount_table()
            .mount_for_path("rust", RUST_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let selected_blob = operation
            .ready
            .inventory
            .persisted_mount_record(mount.ordinal())
            .unwrap()
            .unwrap()
            .blob_id();
        let requester = Module {
            topology,
            path: "crate".to_owned(),
            blob,
            rel_path: RUST_ROOT_CONSUMER_PATH.to_owned(),
            selected_blob,
            fragment: mount.fragment(),
            scope: ResolutionScopeId::new(scope),
            edition,
            unmounted: false,
            overlay_completion: ResolutionCompletion::Complete,
        };
        let exports = RustCrateRows {
            ready: &operation.ready,
        }
        .crate_exports(&requester, topology, path, namespace, name)
        .unwrap();
        for export in &exports {
            assert_eq!(
                export.blob, selected_blob,
                "export must carry selected content: {exports:?}"
            );
            assert_eq!(
                export.mount,
                mount.ordinal(),
                "export must carry selected placement: {exports:?}"
            );
        }
        let mut sites = exports
            .into_iter()
            .map(|export| {
                let super::rust_crate_rows::RustCrateDeclaration::Site(site) = export.declaration
                else {
                    panic!("fixture exports persisted declarations: {export:?}");
                };
                let (_, reverse_sql, _) = super::rust_demand::rows::sql_pins()
                    .into_iter()
                    .find(|(name, _, _)| *name == "rust_point_demand_reverse_export_names")
                    .expect("production reverse export query is pinned");
                let mut names = conn
                    .prepare_cached(reverse_sql)
                    .unwrap()
                    .query_map(
                        rusqlite::params![export.blob, site, namespace, export.mount.get()],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                names.sort_unstable();
                (site, names)
            })
            .collect::<Vec<_>>();
        sites.sort_unstable();
        sites.dedup();
        sites
    };
    let mut observations = Vec::new();
    for (label, old, new, path, namespace, name, present) in [
        (
            "inline scope shift",
            "pub mod inner { pub fn target() {} }",
            "pub mod before {} pub mod inner { pub fn renamed() {} }",
            "crate::inner",
            "value",
            "renamed",
            true,
        ),
        (
            "enum variant",
            "pub enum Choice { Target }",
            "pub fn before() {} pub enum Choice { Renamed }",
            "crate::Choice",
            "value",
            "Renamed",
            true,
        ),
        (
            "exported nested macro",
            "pub mod inner { #[macro_export] macro_rules! target { () => {} } }",
            "pub fn before() {} pub mod inner { #[macro_export] macro_rules! renamed { () => {} } }",
            "crate",
            "macro",
            "renamed",
            true,
        ),
        (
            "private replacement",
            "pub mod inner { pub fn target() {} }",
            "pub mod inner { fn renamed() {} }",
            "crate::inner",
            "value",
            "renamed",
            false,
        ),
        (
            "parent restricted replacement",
            "pub mod inner { pub fn target() {} }",
            "pub mod inner { pub(super) fn renamed() {} }",
            "crate::inner",
            "value",
            "renamed",
            true,
        ),
        (
            "self restricted replacement",
            "pub mod inner { pub fn target() {} }",
            "pub mod inner { pub(self) fn renamed() {} }",
            "crate::inner",
            "value",
            "renamed",
            false,
        ),
        (
            "inactive replacement",
            "pub fn target() {}",
            "#[cfg(any())] pub fn renamed() {}",
            "crate",
            "value",
            "renamed",
            false,
        ),
        (
            "type replacement",
            "pub struct Target;",
            "pub fn before() {} pub struct Renamed;",
            "crate",
            "type",
            "Renamed",
            true,
        ),
    ] {
        let mut fixture = RustRootResolutionOperationFixture::new();
        fixture.replace_persisted_consumer_source(old);
        let (state, _) = parsed_operation_source_state(
            fixture._project_root.path(),
            RUST_ROOT_CONSUMER_PATH,
            new,
            &RustAdapter,
        );
        let cancellation = CancellationToken::new();
        let content = fixture.publish_counterfactual_content(
            RUST_ROOT_CONSUMER_PATH,
            new,
            &state,
            &cancellation,
        );
        let masks = [SelectedResolutionOverlayMask::replacement(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
        )];
        let selected = {
            let operation = fixture.open_content_selected(&masks, vec![content], &cancellation);
            query(&operation, path, namespace, name)
        };
        fixture.replace_persisted_consumer_source(new);
        let fresh = {
            let operation = fixture.open_ready(&cancellation);
            query(&operation, path, namespace, name)
        };
        for (_, names) in &fresh {
            assert!(
                names.contains(&(namespace.to_owned(), name.to_owned())),
                "fresh reverse names must include the declaration itself for {label}: {names:?}"
            );
        }
        observations.push((label, present, selected, fresh));
    }
    eprintln!("selected exports versus fresh crate derivation: {observations:?}");
    for (label, present, selected, fresh) in &observations {
        assert_eq!(
            !fresh.is_empty(),
            *present,
            "fresh fixture expectation: {observations:?}"
        );
        assert_eq!(
            selected, fresh,
            "selected export diverges for {label}: {observations:?}"
        );
    }
}

/// The crate declares a decided invocation's items against the persisted blob
/// of the file that invokes it and closes the module's export inventory. A
/// request that edits that file reads other content, which has no crate rows,
/// so the export lookup finds nothing there; the point inventory reopens the
/// module for that request (`EditedMacroHost`), so the lookup answers
/// incomplete rather than proving the item absent.
#[test]
fn selected_rust_edited_macro_host_reopens_its_module_inventory() {
    use super::rust_crate_context::Module;
    use super::rust_crate_rows::{RustCrateDeclaration, RustCrateRows};

    let persisted_source = concat!(
        "macro_rules! cfg_all { ($($item:item)*) => { $( #[cfg(all())] $item )* }; }\n",
        "cfg_all! { pub fn target() {} }\n",
    );
    let edited_source = concat!(
        "macro_rules! cfg_all { ($($item:item)*) => { $( #[cfg(all())] $item )* }; }\n",
        "pub fn before() {}\n",
        "cfg_all! { pub fn target() {} }\n",
    );
    let read = |operation: &SelectedResolutionOperation<'_, '_>| {
        let conn = operation.ready.inventory.connection();
        crate::analyzer::store::rust_crates::register_point_export_functions(conn).unwrap();
        let (topology, blob, scope, edition): (i64, i64, u32, String) = conn.query_row(
            "SELECT source.topology_id, source.blob_id, scopes.resolution_scope, owner.edition
             FROM rust_crate_container_sources AS source
             JOIN selected_rust_crates AS owner ON owner.topology_id=source.topology_id
             JOIN source_rust_module_scopes AS scopes ON scopes.blob_id=source.blob_id AND scopes.ordinal=source.scope_ordinal
             WHERE source.rel_path=?1 AND source.container_path='crate'",
            [RUST_ROOT_CONSUMER_PATH],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        let mount = operation
            .mount_table()
            .mount_for_path("rust", RUST_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let selected_blob = operation
            .ready
            .inventory
            .persisted_mount_record(mount.ordinal())
            .unwrap()
            .unwrap()
            .blob_id();
        let requester = Module {
            topology,
            path: "crate".to_owned(),
            blob,
            rel_path: RUST_ROOT_CONSUMER_PATH.to_owned(),
            selected_blob,
            fragment: mount.fragment(),
            scope: ResolutionScopeId::new(scope),
            edition,
            unmounted: false,
            overlay_completion: ResolutionCompletion::Complete,
        };
        let rows = RustCrateRows {
            ready: &operation.ready,
        };
        let macro_items = rows
            .crate_exports(&requester, topology, "crate", "value", "target")
            .unwrap()
            .into_iter()
            .filter(|export| matches!(export.declaration, RustCrateDeclaration::MacroItem(_)))
            .count();
        let inventory = rows
            .crate_inventory_completion(&requester, topology, "crate", "value", "target")
            .unwrap();
        (macro_items, inventory)
    };
    let cancellation = CancellationToken::new();
    let mut fixture = RustRootResolutionOperationFixture::new();
    fixture.replace_persisted_consumer_source(persisted_source);
    let persisted = {
        let operation = fixture.open_ready(&cancellation);
        read(&operation)
    };
    assert_eq!(
        persisted,
        (1, ResolutionCompletion::Complete),
        "the crate declares the decorated item and closes the inventory"
    );
    let (state, _) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_CONSUMER_PATH,
        edited_source,
        &RustAdapter,
    );
    let content = fixture.publish_counterfactual_content(
        RUST_ROOT_CONSUMER_PATH,
        edited_source,
        &state,
        &cancellation,
    );
    let masks = [SelectedResolutionOverlayMask::replacement(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
    )];
    let (macro_items, inventory) = {
        let operation = fixture.open_content_selected(&masks, vec![content], &cancellation);
        read(&operation)
    };
    assert_eq!(
        macro_items, 0,
        "the edited file's content has no crate rows"
    );
    assert_ne!(
        inventory,
        ResolutionCompletion::Complete,
        "an edited macro host reopens its module for the request"
    );
}

#[test]
fn selected_rust_dirty_replacement_preserves_topology_and_definition_projection() {
    let fixture = RustRootResolutionOperationFixture::new();
    let dirty_source = concat!(
        "// unsaved caller revision\n",
        "use engine::target as alias;\n",
        "fn caller() -> usize { alias() }\n",
    );
    let (state, dirty_facts) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_CONSUMER_PATH,
        dirty_source,
        &RustAdapter,
    );
    let cancellation = CancellationToken::new();
    fixture.project.set_overlay_content(
        ProjectFile::new(fixture._project_root.path(), RUST_ROOT_CONSUMER_PATH),
        dirty_source,
    );
    let replacement = fixture
        .publish_content(RUST_ROOT_CONSUMER_PATH, dirty_source, &state, &cancellation)
        .with_live_overlay_content_digest(
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(dirty_source.as_bytes()),
        );
    let masks = [SelectedResolutionOverlayMask::replacement(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
    )];
    let operation = fixture.open_content_selected(&masks, vec![replacement], &cancellation);
    let dirty_source_facts = operation
        .selected_rust_usage_facts(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
        .expect("read targeted dirty Rust facts")
        .expect("dirty Rust source is selected");
    assert_eq!(dirty_source_facts, state.rust_usage_facts);

    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), &cancellation)
        .expect("build Rust context with dirty replacement")
    else {
        panic!("live dirty Rust context must be ready")
    };
    let reference = site_for_identifier(
        &dirty_facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let range = dirty_facts
        .sites
        .iter()
        .find(|site| site.id == reference)
        .expect("dirty Rust reference range");
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
        range.start_byte,
        range.end_byte,
    );
    let result = operation
        .resolve_rust_reference(
            *context,
            &locator,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .expect("resolve dirty Rust reference");
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(result)) =
        result
    else {
        panic!("dirty Rust point resolution must publish one native answer")
    };
    let result = only_rust_point_answer(result);
    let expected = fixture
        .provider_facts
        .definition_units
        .iter()
        .find(|crosswalk| {
            crosswalk.declaration
                == site_for_identifier(
                    &fixture.provider_facts,
                    "target",
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                )
        })
        .expect("provider target parser unit")
        .unit
        .clone();
    assert_eq!(result.definitions, [expected]);
}

#[test]
fn selected_rust_dirty_constant_resolves_through_a_dependency_reexport() {
    assert_dirty_constant_resolves_through_a_dependency_reexport("pub const target: usize = 7;\n");
}

#[test]
fn selected_rust_dirty_export_uses_selected_site_after_declaration_insertion() {
    assert_dirty_constant_resolves_through_a_dependency_reexport(
        "pub fn unrelated() {}\npub const target: usize = 7;\n",
    );
}

fn assert_dirty_constant_resolves_through_a_dependency_reexport(dirty_provider_source: &str) {
    let fixture = RustRootResolutionOperationFixture::new();
    let dirty_consumer_source = concat!(
        "// unsaved constant consumer\n",
        "use engine::target as alias;\n",
        "fn caller() -> usize { alias }\n",
    );
    let (consumer_state, consumer_facts) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_CONSUMER_PATH,
        dirty_consumer_source,
        &RustAdapter,
    );
    let (provider_state, provider_facts) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_PROVIDER_PATH,
        dirty_provider_source,
        &RustAdapter,
    );
    let target = site_for_identifier(
        &provider_facts,
        "target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Value,
    );
    assert!(
        provider_facts
            .definition_units
            .iter()
            .any(|crosswalk| crosswalk.declaration == target),
        "dirty provider constant needs a parser-unit crosswalk: {:?}",
        provider_facts.definition_units
    );
    let cancellation = CancellationToken::new();
    let replacement = |path: &str, source: &str, state: &Arc<FileState>| {
        fixture.publish_counterfactual_content(path, source, state, &cancellation)
    };
    let replacements = vec![
        replacement(
            RUST_ROOT_CONSUMER_PATH,
            dirty_consumer_source,
            &consumer_state,
        ),
        replacement(
            RUST_ROOT_PROVIDER_PATH,
            dirty_provider_source,
            &provider_state,
        ),
    ];
    let masks = [
        SelectedResolutionOverlayMask::replacement("rust", RUST_ROOT_CONSUMER_PATH),
        SelectedResolutionOverlayMask::replacement("rust", RUST_ROOT_PROVIDER_PATH),
    ];
    let operation = fixture.open_content_selected(&masks, replacements, &cancellation);
    let expected = provider_facts
        .definition_units
        .iter()
        .find(|crosswalk| crosswalk.declaration == target)
        .expect("dirty provider constant parser unit")
        .unit
        .clone();
    assert_eq!(
        operation
            .locate_rust_definition(&expected, &cancellation)
            .expect("locate dirty Rust constant definition"),
        SelectedRustDefinitionSemanticOutcome::Found(semantic_at(
            &crate::analyzer::resolution::lower_resolution_facts_for_selection(
                operation
                    .mounts()
                    .unwrap()
                    .iter()
                    .find(|mount| mount.persisted_relative_path() == RUST_ROOT_PROVIDER_PATH)
                    .expect("dirty provider mount")
                    .fragment(),
                crate::analyzer::resolution::test_shared_names(),
                Language::Rust,
                &provider_facts,
            ),
            target,
            LoweredSemanticRole::Definition,
        ))
    );
    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), &cancellation)
        .expect("build Rust context with dirty constant")
    else {
        panic!("live dirty Rust constant context must be ready")
    };
    let reference = site_for_identifier(
        &consumer_facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let reference_range = consumer_facts
        .sites
        .iter()
        .find(|site| site.id == reference)
        .expect("dirty Rust constant reference range");
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
        reference_range.start_byte,
        reference_range.end_byte,
    );
    let result = operation
        .resolve_rust_reference(
            *context,
            &locator,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .expect("resolve dirty Rust constant reference");
    let result = match result {
        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(result)) => {
            only_rust_point_answer(result)
        }
        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
            panic!("dirty Rust constant reference range is absent")
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            panic!("dirty Rust constant operation is unavailable: {reason:?}")
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            panic!("dirty Rust constant operation is stale: {reason:?}")
        }
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            panic!("dirty Rust constant operation is cancelled")
        }
    };
    assert_eq!(result.definitions, [expected]);
    assert!(
        matches!(
            result.resolution.completion(),
            ResolutionCompletion::Incomplete(_)
        ),
        "an overlay that changes imports retains the persisted binding with uncertainty"
    );
}

#[test]
fn selected_rust_renamed_import_is_independent_of_target_site_ordinal() {
    let mut observations = Vec::new();
    for (old, source) in [
        (
            "pub fn target() {} use crate::target as alias; fn caller() { alias(); }",
            "pub fn renamed() {} use crate::renamed as alias; fn caller() { alias(); }",
        ),
        (
            "pub fn target() {} use crate::target as alias; fn caller() { alias(); }",
            "pub fn unrelated() {} pub fn renamed() {} use crate::renamed as alias; fn caller() { alias(); }",
        ),
        (
            "pub fn target() {} use crate::target as before; fn caller() { before(); }",
            "pub fn unrelated() {} pub fn renamed() {} use crate::renamed as alias; fn caller() { alias(); }",
        ),
        (
            "mod provider { pub fn target() {} } use provider::target as alias; fn caller() { alias(); }",
            "mod provider { pub fn renamed() {} } use provider::renamed as alias; fn caller() { alias(); }",
        ),
        (
            "mod provider { pub fn target() {} } use provider::target as alias; fn caller() { alias(); }",
            "mod provider { pub fn unrelated() {} pub fn renamed() {} } use provider::renamed as alias; fn caller() { alias(); }",
        ),
    ] {
        let mut fixture = RustRootResolutionOperationFixture::new();
        fixture.replace_persisted_consumer_source(old);
        let (state, facts) = parsed_operation_source_state(
            fixture._project_root.path(),
            RUST_ROOT_CONSUMER_PATH,
            source,
            &RustAdapter,
        );
        let cancellation = CancellationToken::new();
        let replacement = fixture.publish_counterfactual_content(
            RUST_ROOT_CONSUMER_PATH,
            source,
            &state,
            &cancellation,
        );
        let reference = site_for_identifier(
            &facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let reference_range = facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .unwrap();
        let target = site_for_identifier(
            &facts,
            "renamed",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        );
        let expected = facts
            .definition_units
            .iter()
            .find(|crosswalk| crosswalk.declaration == target)
            .unwrap()
            .unit
            .clone();
        let profile = fixture.profile.clone();
        let query = |operation: SelectedResolutionOperation<'_, '_>| {
            let SelectedRustFileContextOutcome::Ready { context, .. } = operation
                .rust_test_crate_context(profile.clone(), &cancellation)
                .unwrap()
            else {
                panic!("renamed import context must be ready")
            };
            let result = operation
                .resolve_rust_reference(
                    *context,
                    &SelectedSemanticLocator::for_reference_range(
                        "rust",
                        RUST_ROOT_CONSUMER_PATH,
                        reference_range.start_byte,
                        reference_range.end_byte,
                    ),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                result,
            )) = result
            else {
                panic!("renamed reference must resolve natively")
            };
            let result = only_rust_point_answer(result);
            (result.definitions, result.resolution.completion().clone())
        };
        let selected = {
            let masks = [SelectedResolutionOverlayMask::replacement(
                "rust",
                RUST_ROOT_CONSUMER_PATH,
            )];
            let operation = fixture.open_content_selected(&masks, vec![replacement], &cancellation);
            query(operation)
        };
        fixture.replace_persisted_consumer_source(source);
        let fresh = query(fixture.open_ready(&cancellation));
        assert_eq!(fresh.0, [expected]);
        assert!(matches!(fresh.1, ResolutionCompletion::Complete));
        observations.push((source, selected, fresh));
    }
    assert!(
        observations
            .iter()
            .all(|(_, selected, fresh)| selected == fresh),
        "selected renamed imports must match fresh derivation regardless of inserted declarations: {observations:#?}"
    );
}

#[test]
fn selected_rust_renamed_dependency_import_uses_selected_target() {
    let mut observations = Vec::new();
    for provider_source in [
        "pub fn renamed() -> usize { 1 }\n",
        "pub fn unrelated() {}\npub fn renamed() -> usize { 1 }\n",
    ] {
        let fixture = RustRootResolutionOperationFixture::new();
        let consumer_source = concat!(
            "use engine::renamed as alias;\n",
            "use engine::model::renamed as direct_alias;\n",
            "fn caller() -> usize { alias() + direct_alias() }\n",
        );
        let (consumer_state, consumer_facts) = parsed_operation_source_state(
            fixture._project_root.path(),
            RUST_ROOT_CONSUMER_PATH,
            consumer_source,
            &RustAdapter,
        );
        let (provider_state, provider_facts) = parsed_operation_source_state(
            fixture._project_root.path(),
            RUST_ROOT_PROVIDER_PATH,
            provider_source,
            &RustAdapter,
        );
        let cancellation = CancellationToken::new();
        let replacements = vec![
            fixture.publish_counterfactual_content(
                RUST_ROOT_CONSUMER_PATH,
                consumer_source,
                &consumer_state,
                &cancellation,
            ),
            fixture.publish_counterfactual_content(
                RUST_ROOT_PROVIDER_PATH,
                provider_source,
                &provider_state,
                &cancellation,
            ),
        ];
        let masks = [
            SelectedResolutionOverlayMask::replacement("rust", RUST_ROOT_CONSUMER_PATH),
            SelectedResolutionOverlayMask::replacement("rust", RUST_ROOT_PROVIDER_PATH),
        ];
        let operation = fixture.open_content_selected(&masks, replacements, &cancellation);
        let SelectedRustFileContextOutcome::Ready { context, .. } = operation
            .rust_test_crate_context(fixture.profile.clone(), &cancellation)
            .expect("renamed import crate context")
        else {
            panic!("renamed import context must be ready")
        };
        let target = site_for_identifier(
            &provider_facts,
            "renamed",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        );
        let expected = provider_facts
            .definition_units
            .iter()
            .find(|crosswalk| crosswalk.declaration == target)
            .expect("selected renamed definition")
            .unit
            .clone();
        let reference = site_for_identifier(
            &consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let reference_range = consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .unwrap();
        let result = operation
            .resolve_rust_reference(
                *context,
                &SelectedSemanticLocator::for_reference_range(
                    "rust",
                    RUST_ROOT_CONSUMER_PATH,
                    reference_range.start_byte,
                    reference_range.end_byte,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .expect("resolve renamed imported reference");
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(result)) =
            result
        else {
            panic!("renamed reference must resolve natively")
        };
        let result = only_rust_point_answer(result);
        observations.push((
            provider_source,
            result.definitions,
            expected,
            result.resolution.completion().clone(),
        ));
    }
    assert!(
        observations.iter().all(
            |(_, definitions, expected, completion)| definitions.as_slice()
                == std::slice::from_ref(expected)
                && matches!(completion, ResolutionCompletion::Complete)
        ),
        "inserting an unrelated declaration cannot change renamed import resolution: {observations:#?}"
    );
}

#[test]
fn selected_rust_2015_unsaved_extern_alias_keeps_persisted_route_incomplete() {
    let mut fixture = RustRootResolutionOperationFixture::new();
    let manifests = [
        RustSelectedManifestMount::from_source(
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2015\"\n[dependencies]\nengine = { path = \"../engine\" }\n",
        )
        .expect("Rust 2015 app manifest facts"),
        RustSelectedManifestMount::from_source(
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("engine manifest facts"),
    ];
    let manifest_snapshot = sync_rust_operation_inputs(
        &fixture.store,
        &fixture.workspace_id,
        fixture.generation,
        fixture._project_root.path(),
        &fixture.source_rows(),
        &manifests,
    )
    .expect("persist Rust 2015 selected manifests");
    fixture.snapshots.insert(
        "rust".to_owned(),
        WorkspaceSnapshotId {
            workspace_id: fixture.workspace_id.clone(),
            lang: "rust".to_owned(),
            generation: fixture.generation,
            revision: manifest_snapshot.revision,
        },
    );

    let dirty_source = concat!(
        "extern crate engine as dependency;\n",
        "use dependency::model::target as alias;\n",
        "fn caller() -> usize { alias() }\n",
    );
    let (state, facts) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_CONSUMER_PATH,
        dirty_source,
        &RustAdapter,
    );
    // Former transient limitation: retain expected evidence until native review.
    let cancellation = CancellationToken::new();
    let replacement = fixture.publish_counterfactual_content(
        RUST_ROOT_CONSUMER_PATH,
        dirty_source,
        &state,
        &cancellation,
    );
    let masks = [SelectedResolutionOverlayMask::replacement(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
    )];
    let operation = fixture.open_content_selected(&masks, vec![replacement], &cancellation);
    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), &cancellation)
        .expect("build Rust 2015 context with extern-crate alias")
    else {
        panic!("Rust 2015 extern-crate context must be ready")
    };
    let reference = site_for_identifier(
        &facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let reference_range = facts
        .sites
        .iter()
        .find(|site| site.id == reference)
        .expect("Rust 2015 alias reference range");
    let result = operation
        .resolve_rust_reference(
            *context,
            &SelectedSemanticLocator::for_reference_range(
                "rust",
                RUST_ROOT_CONSUMER_PATH,
                reference_range.start_byte,
                reference_range.end_byte,
            ),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .expect("resolve Rust 2015 extern-crate alias");
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(result)) =
        result
    else {
        panic!("Rust 2015 extern-crate alias must resolve natively")
    };
    let result = only_rust_point_answer(result);
    assert!(
        matches!(
            result.resolution.completion(),
            ResolutionCompletion::Incomplete(_)
        ),
        "an overlay that changes imports retains the persisted binding with uncertainty"
    );
    assert_eq!(
        result.definitions,
        [fixture.provider_facts.definition_units[0].unit.clone()]
    );
}

#[test]
fn selected_rust_cargo_dependency_path_switch_preserves_caller_inputs() {
    let mut fixture = RustRootResolutionOperationFixture::new();
    const ALT_PROVIDER_ROOT_PATH: &str = "engine_alt/src/lib.rs";
    const ALT_PROVIDER_ROOT_SOURCE: &str = "pub mod model;\npub use model::*;\n";
    const ALT_PROVIDER_PATH: &str = "engine_alt/src/model.rs";
    const ALT_PROVIDER_SOURCE: &str = "pub fn target() -> usize { 2 }\n";
    const APP_MANIFEST_A: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nengine = { path = \"../engine\" }\n";
    const APP_MANIFEST_B: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nengine = { package = \"engine_alt\", path = \"../engine_alt\" }\n";
    const ALT_MANIFEST: &str =
        "[package]\nname = \"engine_alt\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";

    // Add the second target's parsed source before publishing the first full
    // source/configuration input set. Every A/B/A selection therefore sees the
    // same source inventory; only the selected Cargo dependency edge changes.
    let (alt_root_state, _) = parsed_operation_state(
        fixture._project_root.path(),
        ALT_PROVIDER_ROOT_PATH,
        ALT_PROVIDER_ROOT_SOURCE,
        &RustAdapter,
    );
    let (alt_state, _) = parsed_operation_state(
        fixture._project_root.path(),
        ALT_PROVIDER_PATH,
        ALT_PROVIDER_SOURCE,
        &RustAdapter,
    );
    let alt_root_oid = Oid::hash_object(ObjectType::Blob, ALT_PROVIDER_ROOT_SOURCE.as_bytes())
        .expect("hash alternate Rust provider root source");
    let alt_oid = Oid::hash_object(ObjectType::Blob, ALT_PROVIDER_SOURCE.as_bytes())
        .expect("hash alternate Rust provider source");
    let prepared = vec![
        AnalyzerStore::prepare_parsed_blob(
            alt_root_oid,
            "rust",
            fixture.generation,
            &RustAdapter,
            alt_root_state,
        )
        .expect("prepare alternate Rust provider root blob"),
        AnalyzerStore::prepare_parsed_blob(
            alt_oid,
            "rust",
            fixture.generation,
            &RustAdapter,
            alt_state,
        )
        .expect("prepare alternate Rust provider blob"),
    ];
    let (outcomes, _) = fixture
        .store
        .persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes.iter().all(|outcome| outcome.error.is_none()),
        "{outcomes:#?}"
    );
    let mut source_rows = fixture.source_rows();
    source_rows.push(WorkspaceFileRow {
        rel_path: ALT_PROVIDER_ROOT_PATH.to_owned(),
        blob_oid: alt_root_oid,
    });
    source_rows.push(WorkspaceFileRow {
        rel_path: ALT_PROVIDER_PATH.to_owned(),
        blob_oid: alt_oid,
    });

    let caller_storage = |store: &AnalyzerStore, workspace_id: &WorkspaceId| {
        let workspace_id = workspace_id.clone();
        store.conn.execute(move |conn| -> Result<_> {
            let source_row = conn.query_row(
                "SELECT file_version_id, blob_oid, projection_digest,
                        valid_from, valid_until
                 FROM workspace_file_versions
                 WHERE workspace_id = ?1 AND lang = 'rust'
                   AND input_kind = 'source' AND rel_path = ?2
                   AND valid_until IS NULL",
                params![workspace_id.as_str(), RUST_ROOT_CONSUMER_PATH],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )?;
            let blob_id: i64 = conn.query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1",
                [&source_row.1],
                |row| row.get(0),
            )?;
            let semantic_sites = conn
                .prepare(
                    "SELECT source_site, semantic_key
                     FROM resolution_semantic_sites
                     WHERE blob_id = ?1 ORDER BY source_site",
                )?
                .query_map([blob_id], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok((source_row, semantic_sites))
        })
    };
    let app_a = RustSelectedManifestMount::from_source("app/Cargo.toml", APP_MANIFEST_A)
        .expect("app Cargo A facts");
    let app_b = RustSelectedManifestMount::from_source("app/Cargo.toml", APP_MANIFEST_B)
        .expect("app Cargo B facts");
    let engine = RustSelectedManifestMount::from_source(
        "engine/Cargo.toml",
        "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("engine Cargo facts");
    let engine_alt = RustSelectedManifestMount::from_source("engine_alt/Cargo.toml", ALT_MANIFEST)
        .expect("alternate engine Cargo facts");
    let manifests_a = [app_a.clone(), engine.clone(), engine_alt.clone()];
    let caller_storage_initial = caller_storage(&fixture.store, &fixture.workspace_id)
        .expect("read initial caller source storage identity");
    let snapshot_a = sync_rust_operation_inputs(
        &fixture.store,
        &fixture.workspace_id,
        fixture.generation,
        fixture._project_root.path(),
        &source_rows,
        &manifests_a,
    )
    .expect("publish full source and Cargo dependency-path A inputs");
    let caller_storage_before = caller_storage(&fixture.store, &fixture.workspace_id)
        .expect("read caller source storage identity");
    assert_eq!(caller_storage_before, caller_storage_initial);
    assert!(caller_storage_before.0.4.is_none());
    assert!(
        !caller_storage_before.1.is_empty(),
        "caller source must retain canonical partial-path rows"
    );
    let snapshot_b = sync_rust_operation_inputs(
        &fixture.store,
        &fixture.workspace_id,
        fixture.generation,
        fixture._project_root.path(),
        &source_rows,
        &[app_b.clone(), engine.clone(), engine_alt.clone()],
    )
    .expect("persist Cargo dependency-path B");
    let snapshot_a_again = sync_rust_operation_inputs(
        &fixture.store,
        &fixture.workspace_id,
        fixture.generation,
        fixture._project_root.path(),
        &source_rows,
        &manifests_a,
    )
    .expect("persist Cargo dependency-path A again");

    let persistent_project = fixture.project.clone();
    let resolve = |fixture: &mut RustRootResolutionOperationFixture,
                   project: &dyn Project,
                   snapshot: WorkspaceSnapshotId,
                   expected_target_path: &str| {
        fixture.snapshots.insert("rust".to_owned(), snapshot);
        let cancellation = CancellationToken::default();
        let operation = fixture.open_selected_with_project(project, &[], &cancellation);

        let caller_mount = operation
            .mounts()
            .unwrap()
            .iter()
            .find(|mount| mount.persisted_relative_path() == RUST_ROOT_CONSUMER_PATH)
            .expect("selected caller mount");
        let caller_mount_signature = caller_mount.fragment();
        assert!(
            operation
                .mounts()
                .unwrap()
                .iter()
                .any(|mount| mount.persisted_relative_path() == expected_target_path)
        );
        let caller_source = operation
            .selected_rust_usage_facts(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
            .expect("read selected caller facts")
            .expect("selected caller source");
        let SelectedRustFileContextOutcome::Ready { context, .. } = operation
            .rust_test_crate_context(fixture.profile.clone(), &cancellation)
            .expect("build selected Cargo dependency context")
        else {
            panic!("selected Cargo dependency context must be ready")
        };
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let reference_range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .expect("caller alias reference range");
        let result = operation
            .resolve_rust_reference(
                *context,
                &SelectedSemanticLocator::for_reference_range(
                    "rust",
                    RUST_ROOT_CONSUMER_PATH,
                    reference_range.start_byte,
                    reference_range.end_byte,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .expect("resolve selected Cargo dependency path");
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(result)) =
            result
        else {
            panic!("selected Cargo dependency path must resolve natively")
        };
        let result = only_rust_point_answer(result);
        assert_eq!(
            result.resolution.binding().completion(),
            &ResolutionCompletion::Complete
        );
        (result.definitions, caller_mount_signature, caller_source)
    };

    let (a_definitions, a_mount, a_source) = resolve(
        &mut fixture,
        &persistent_project,
        snapshot_a.clone(),
        RUST_ROOT_PROVIDER_PATH,
    );
    let (b_definitions, b_mount, b_source) = resolve(
        &mut fixture,
        &persistent_project,
        snapshot_b,
        ALT_PROVIDER_PATH,
    );
    let (a_again_definitions, a_again_mount, a_again_source) = resolve(
        &mut fixture,
        &persistent_project,
        snapshot_a_again,
        RUST_ROOT_PROVIDER_PATH,
    );
    assert_eq!(a_definitions, a_again_definitions);
    assert_ne!(a_definitions, b_definitions);
    assert_eq!(
        a_mount, b_mount,
        "Cargo-only changes must retain caller mount identity"
    );
    assert_eq!(a_mount, a_again_mount);
    assert_eq!(
        a_source, b_source,
        "Cargo-only changes must retain caller extraction"
    );
    assert_eq!(a_source, a_again_source);
    // Selected Cargo roots determine the package prefix. The standalone
    // parsed units retain path-derived prefixes and are not selected answers.
    for (definitions, path, package) in [
        (&a_definitions, RUST_ROOT_PROVIDER_PATH, "engine.model"),
        (&b_definitions, ALT_PROVIDER_PATH, "engine_alt.model"),
    ] {
        assert_eq!(definitions.len(), 1);
        let definition = &definitions[0];
        assert_eq!(definition.source().rel_path(), Path::new(path));
        assert_eq!(definition.package_name(), package);
        assert_eq!(definition.short_name(), "target");
        assert!(definition.is_function());
    }
    assert_eq!(
        caller_storage(&fixture.store, &fixture.workspace_id).expect("caller storage after A/B/A"),
        caller_storage_before
    );

    // A manifest overlay keeps the persisted crate's dependency rows. It does
    // not publish a new revision or transiently rederive Cargo topology.
    fixture.snapshots.insert("rust".to_owned(), snapshot_a);
    let overlay = Arc::new(OverlayProject::new(Arc::new(fixture.project.clone())));
    let app_manifest_file = ProjectFile::new(fixture._project_root.path(), "app/Cargo.toml");
    assert!(overlay.set(app_manifest_file.abs_path(), APP_MANIFEST_B.to_owned()));
    let frozen_overlay: Arc<dyn Project> = Arc::new(overlay.snapshot());
    let workspace_head = |fixture: &RustRootResolutionOperationFixture| -> i64 {
        let workspace_id = fixture.workspace_id.clone();
        let generation = fixture.generation;
        fixture
            .store
            .conn
            .execute(move |conn| {
                conn.query_row(
                    "SELECT revision FROM workspace_heads
                     WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2",
                    params![workspace_id.as_str(), generation.get()],
                    |row| row.get(0),
                )
                .map_err(StoreError::from)
            })
            .expect("read workspace head around Cargo overlay")
    };
    let head_before_overlay = workspace_head(&fixture);
    let overlay_snapshot = fixture.snapshots["rust"].clone();
    let (overlay_definitions, overlay_mount, overlay_source) = resolve(
        &mut fixture,
        frozen_overlay.as_ref(),
        overlay_snapshot,
        ALT_PROVIDER_PATH,
    );
    assert_eq!(overlay_definitions, a_definitions);
    assert_eq!(overlay_mount, a_mount);
    assert_eq!(overlay_source, a_source);
    let head_after_overlay = workspace_head(&fixture);
    assert_eq!(head_after_overlay, head_before_overlay);
    assert_eq!(
        caller_storage(&fixture.store, &fixture.workspace_id)
            .expect("caller storage after overlay"),
        caller_storage_before
    );
}

#[test]
fn selected_rust_caller_bounded_entry_charges_the_point_request_not_its_context() {
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let reference = site_for_identifier(
        &fixture.consumer_facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let range = fixture
        .consumer_facts
        .sites
        .iter()
        .find(|site| site.id == reference)
        .expect("selected Rust caller reference range");
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
        range.start_byte,
        range.end_byte,
    );
    let run_with_metrics = |budget, metrics: &mut ResolutionBatchMetrics| {
        fixture
            .open_ready(&cancellation)
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                budget,
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                metrics,
            )
            .expect("resolve bounded Rust caller and point")
    };
    let run = |budget| run_with_metrics(budget, &mut ResolutionBatchMetrics::default());
    let mut bounded_metrics = ResolutionBatchMetrics::default();
    let context_work_trace = ContextPublicationWorkTrace::begin();
    let complete = run_with_metrics(ReceiverAnalysisBudget::default(), &mut bounded_metrics);
    drop(context_work_trace);
    let BoundedResolution::Complete {
        value:
            SelectedRustCallerReferenceOutcome::Operation(SelectedResolutionOperationOutcome::Native(
                SelectedResolutionLocated::Found(answer),
            )),
        work,
    } = complete
    else {
        panic!("default budget must complete the combined Rust caller operation")
    };
    let answer = only_rust_point_answer(answer);
    assert_eq!(answer.definitions.len(), 1);
    // The caller preparation spans the whole Cargo target and does not depend
    // on which reference is asked about, so it is retained with the operation
    // and charged to no request. What remains is the point request: its located
    // reference, its composition, its projection, the boundary checks around
    // them, and -- since the point path was routed through the demand provider
    // -- the prefix resolution this exact reference needs.
    //
    // Four numbers, in order. It charged (15, 1,180) when the caller context
    // was built inside the request. Making that context preparation brought it
    // to (10, 326), where the prefix answers behind the request were already
    // compiled by the context build and cost the request nothing. Routing the
    // request through the demand provider took it to (10, 648): the request now
    // pays for its own prefixes, which is the trade the demand engine makes.
    // Moving the Export-half index out of the demand closure and into the
    // retained preparation brings it to (10, 632). The whole-workspace prefix
    // evaluation the route replaced was 408 s of a 479 s first request on the
    // #2767 corpus.
    //
    // It is (10, 638) since `selected_rust_module_prefix_bridges` stopped
    // asking every profile the same two questions once per reference. The six
    // extra steps are the one-time index it builds instead: one per profile,
    // one per file in which that profile declares a module edge, one per
    // declaration in those files while it folds the incomplete-module set, and
    // one per file it roots. The trade is invisible on this two-file fixture
    // and it removes a term that was workspace references times profiles on a
    // real workspace, where the profile count is one per Cargo target plus one
    // per Rust source no Cargo target reaches.
    // The eight decided default cfg atoms are part of selected identity.
    // Enumerated module prefixes add 25 source-inventory traversal steps.
    // Endpoint-local source admission replaces the retained-tail bucket walk.
    // Lazy candidate completion avoids eight SQL gap-decoding scope charges;
    // tier-1 candidate discovery and declaration access remain unchanged.
    // The interior then became the only candidate reader, so each admitted
    // mount's own paging charges the request where one SQL page did before:
    // 18 more steps on this two-file fixture, bounded by the request's
    // candidates and not by the workspace. The root inventory's mount scope
    // then removes the mounts a root request's caller cannot use, which moves
    // seven steps off the root reads and onto the demands that follow them.
    // It is 341 since the candidate index began deciding the whole shared
    // fixed prefix of a request and a stored path endpoint rather than only
    // their first cell. The 159 steps it removes are hydrations and
    // alpha-renaming unifications of paths whose first cell agreed and whose
    // second did not, and the count is the same 159 at every campaign size
    // because it is this request's own endpoint work, not the workspace's.
    //
    // It is 337 since the selected context set became sparse. The demand close
    // on this fixture extends a set over three selected mounts with one bridge,
    // and the extension used to charge that bridge, once per carried mount, and
    // once more for appending. The four steps it charged over the mounts that
    // earned nothing are the whole difference; no candidate, declaration, or
    // prefix work moved.
    //
    // It is 330 since the interior's candidate index began keying its stored
    // paths by the first fixed symbol admission checks, not by the endpoint
    // node alone. The seven steps are `2 * mounts + 1` over this fixture's
    // three selected mounts: the paging walk charged a step for each
    // root-anchored path the node offered before rejecting it on its first
    // cell, and it no longer visits those paths at all. The same arithmetic
    // takes the point-scale campaigns from `2 * mounts + 331` to a flat 330.
    //
    // CM's row-backed match removes four charges for the empty second
    // fragment source, producing 326 scope steps; it does not admit fewer
    // candidates. This fixture pins one definition and exact agreement of
    // bounded and unbounded responses with the same request budget contract.
    // This is not corpus parity evidence: the frozen corpus comparison has
    // 1,199 of 1,200 equal full replies and preserves one freshness diagnostic
    // difference. See the CM lane report for that acceptance limitation.
    //
    // Stage-backed readers now use 294 = 326 - 9 - 13 - 3 - 7 steps:
    // context representation walks cost 9, repeated demand publication cost
    // 13, and the removed composite visitor charged each fresh typed row
    // twice (3 preliminary rows and 7 final rows). Matched diagnostics retain
    // identical candidate requests and completion-copy charges. Summary work,
    // semantic answers and the exhaustion checks below remain exact.
    assert_eq!(
        work,
        ReceiverAnalysisWork {
            setup_nodes: 0,
            summary_expansions: 10,
            // 294, plus 10 steps for the callee signature reads that ask
            // whether an argument decides a generic call's result, is 304.
            // A round whose demanded slots are unchanged reuses the slot
            // structure its evaluation read (`SlotPrep`) and no longer
            // repeats those reads, whose request and row steps were 51 here.
            // Shared reference refinement now asks for transfer-owned type
            // identities before call projections. This fixture pays five
            // additional request-local reads; retained context work is unchanged.
            scope_nodes: 258,
        },
        "the interior's per-mount candidate paging charges the point request; tier-1 candidate and declaration work must remain exact"
    );

    let mut unbounded_metrics = ResolutionBatchMetrics::default();
    let SelectedRustCallerReferenceOutcome::Operation(SelectedResolutionOperationOutcome::Native(
        SelectedResolutionLocated::Found(unbounded),
    )) = fixture
        .open_ready(&cancellation)
        .resolve_rust_reference_for_caller(
            Path::new(RUST_ROOT_CONSUMER_PATH),
            &locator,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut unbounded_metrics,
        )
        .expect("resolve the same caller without budget limits")
    else {
        panic!("the unbounded caller operation must publish its native answer");
    };
    let unbounded = only_rust_point_answer(unbounded);
    assert_eq!(unbounded.resolution, answer.resolution);
    assert_eq!(unbounded.definitions, answer.definitions);
    assert_eq!(unbounded.lexical_definitions, answer.lexical_definitions);
    assert_eq!(unbounded_metrics, bounded_metrics);

    let zero_scope = run(ReceiverAnalysisBudget {
        max_scope_nodes: 0,
        ..ReceiverAnalysisBudget::default()
    });
    assert!(matches!(
        zero_scope,
        BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes,
            work: ReceiverAnalysisWork { scope_nodes: 0, .. },
        }
    ));
    assert!(!cancellation.is_cancelled());

    // The first operation used to charge more than every later one, because
    // it paid for the context build and the cold typed-frontier reads. Now
    // that both are preparation, the first request charges exactly what the
    // steady-state request does, which is the property the exact-budget and
    // one-unit-under checks below depend on.
    let BoundedResolution::Complete { work: warm, .. } = run(ReceiverAnalysisBudget::default())
    else {
        panic!("default budget must complete the warm Rust caller operation")
    };
    assert_eq!(
        warm, work,
        "the caller context is preparation, so the first request charges what every later one does"
    );
    let under_summary = run(ReceiverAnalysisBudget {
        max_summary_expansions: warm.summary_expansions - 1,
        max_scope_nodes: warm.scope_nodes,
        ..ReceiverAnalysisBudget::default()
    });
    assert!(matches!(
        under_summary,
        BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::SummaryExpansions,
            ..
        }
    ));
    assert!(!cancellation.is_cancelled());

    let exact = run(ReceiverAnalysisBudget {
        max_summary_expansions: warm.summary_expansions,
        max_scope_nodes: warm.scope_nodes,
        ..ReceiverAnalysisBudget::default()
    });
    assert!(matches!(
        exact,
        BoundedResolution::Complete {
            work: exact_work,
            ..
        } if exact_work == warm
    ));
    let under = run(ReceiverAnalysisBudget {
        max_summary_expansions: warm.summary_expansions,
        max_scope_nodes: warm.scope_nodes - 1,
        ..ReceiverAnalysisBudget::default()
    });
    assert!(matches!(
        under,
        BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes,
            ..
        }
    ));
    assert!(!cancellation.is_cancelled());

    let unsupported = fixture
        .open_ready(&cancellation)
        .resolve_rust_reference_for_caller_bounded(
            Path::new("standalone.rs"),
            &locator,
            ReceiverAnalysisBudget::default(),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut ResolutionBatchMetrics::default(),
        )
        .expect("classify unsupported Rust caller profile");
    assert!(matches!(
        unsupported,
        BoundedResolution::Complete {
            value: SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile,
            ..
        }
    ));
}

impl GoRootResolutionOperationFixture {
    fn new() -> Self {
        Self::with_consumer(GO_ROOT_CONSUMER_SOURCE)
    }

    fn with_consumer(consumer_source: &str) -> Self {
        Self::with_sources([
            consumer_source,
            GO_ROOT_PROVIDER_SOURCE,
            GO_ROOT_DECOY_SOURCE,
        ])
    }

    fn with_sources(sources: [&str; 3]) -> Self {
        let project_root = tempfile::tempdir().expect("Go root operation test project root");
        let project = MutableGenerationProject::new(project_root.path(), Language::Go);
        let adapter = GoAdapter;
        let store = AnalyzerStore::open_ephemeral().expect("Go root operation test store");
        let generation = store
            .ensure_language_epoch_value("go", "resolution-operation-go-root-test-v1")
            .expect("Go root operation test language epoch");
        store
            .ensure_resolution_producer_epoch("go", Language::Go)
            .expect("Go root operation test producer epoch");

        let mut versions = Vec::new();
        let mut prepared = Vec::new();
        let mut facts_by_path = BTreeMap::new();
        for (ordinal, (path, source)) in [
            (GO_ROOT_CONSUMER_PATH, sources[0]),
            (GO_ROOT_PROVIDER_PATH, sources[1]),
            (GO_ROOT_DECOY_PATH, sources[2]),
        ]
        .into_iter()
        .enumerate()
        {
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                .expect("hash the Go root operation fixture source");
            let (state, facts) = parsed_go_state(project_root.path(), path, source);
            prepared.push(
                AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "go",
                    generation,
                    &adapter,
                    Arc::clone(&state),
                )
                .expect("prepare parsed Go root blob with resolution bundle"),
            );
            versions.push((path.to_owned(), oid.to_string(), ordinal));
            assert!(facts_by_path.insert(path, facts).is_none());
        }
        let (outcomes, _) = store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 3);
        assert!(
            outcomes.iter().all(|outcome| outcome.error.is_none()),
            "{:#?}",
            outcomes
                .iter()
                .map(|outcome| &outcome.error)
                .collect::<Vec<_>>()
        );

        let workspace_id = WorkspaceId(GO_ROOT_WORKSPACE_ID.to_owned());
        let writer_workspace_id = workspace_id.as_str().to_owned();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'go', ?2, 1)",
                params![writer_workspace_id, generation.get()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
                 VALUES(?1, 'go', ?2, 1)",
                params![writer_workspace_id, generation.get()],
            )
            .unwrap();
            for (path, oid, ordinal) in versions {
                tx.execute(
                    "INSERT INTO workspace_file_versions(
                       workspace_id, lang, generation, rel_path, blob_oid,
                       projection_digest, valid_from
                     ) VALUES(?1, 'go', ?2, ?3, ?4, ?5, 1)",
                    params![
                        writer_workspace_id,
                        generation.get(),
                        path,
                        oid,
                        format!("{:064x}", 720 + ordinal),
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        });

        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert(
            "go".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: "go".to_owned(),
                generation,
                revision: 1,
            },
        );
        Self {
            store,
            _project_root: project_root,
            project,
            workspace_id,
            snapshots,
            languages: vec![SelectedResolutionLanguage::new("go", Language::Go)],
            overlay_masks: Vec::new(),
            consumer_facts: facts_by_path
                .remove(GO_ROOT_CONSUMER_PATH)
                .expect("consumer facts"),
            provider_facts: facts_by_path
                .remove(GO_ROOT_PROVIDER_PATH)
                .expect("provider facts"),
            decoy_facts: facts_by_path
                .remove(GO_ROOT_DECOY_PATH)
                .expect("decoy facts"),
        }
    }

    fn open_ready<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        match self
            .store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &self.project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    &self.overlay_masks,
                ),
                cancellation,
            )
            .expect("open persisted Go root resolution operation")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("complete persisted Go root operation must open Ready"),
        }
    }

    fn contexts_for(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
    ) -> SelectedResolutionContextSet {
        self.contexts_with_bridge(operation, self.root_bridge(operation))
    }

    fn root_bridge(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
    ) -> SelectedRootBridgeDescriptor {
        let mounts = operation.mounts().unwrap();
        let source = mounts
            .iter()
            .find(|mount| mount.persisted_relative_path() == GO_ROOT_CONSUMER_PATH)
            .expect("selected Go consumer mount");
        let target = mounts
            .iter()
            .find(|mount| mount.persisted_relative_path() == GO_ROOT_PROVIDER_PATH)
            .expect("selected Go provider mount");
        let import = self
            .consumer_facts
            .root_imports
            .first()
            .copied()
            .expect("consumer dot-import root fact");
        let mut segments = self
            .consumer_facts
            .root_import_segments
            .iter()
            .filter(|segment| segment.import_site == import.site)
            .copied()
            .collect::<Vec<_>>();
        segments.sort_unstable_by_key(|segment| segment.position);
        let route = segments
            .iter()
            .map(|segment| {
                ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Type,
                    &self.consumer_facts.names[segment.name.index()].spelling,
                )
            })
            .collect::<Vec<_>>();
        let demand = self
            .consumer_facts
            .root_import_demands
            .iter()
            .find(|demand| {
                demand.import_site == import.site
                    && self.consumer_facts.names[demand.name.index()].spelling == "Item"
            })
            .copied()
            .expect("consumer Item root demand");
        let source_demand = ResolutionLookupSemanticRecipe::new(
            Language::Go,
            demand.namespace,
            &self.consumer_facts.names[demand.name.index()].spelling,
        );
        let target_demand = source_demand.clone();
        let mut halves = Vec::new();
        let every_mount = operation
            .mounts()
            .unwrap()
            .iter()
            .map(|mount| mount.ordinal())
            .collect::<Vec<_>>();
        with_operation_lexical(operation, |composite, anchors| {
            for visit in [
                visit_selected_root_import_half_pages,
                visit_selected_root_export_half_pages,
            ] {
                let outcome = visit(
                    &SelectedContextIdentities::new(),
                    anchors,
                    composite,
                    Some(&every_mount),
                    &CancellationToken::default(),
                    &mut FactPageVisitor::new(&mut |page| {
                        halves.extend_from_slice(page);
                        Ok(true)
                    }),
                )
                .expect("read persisted Go root halves");
                assert!(outcome.is_exhausted());
            }
        });
        let (source_token, anchor, anchor_semantic) = halves
            .iter()
            .find_map(|half| match half {
                SelectedRootPathHalf::Import {
                    identity,
                    token,
                    anchor,
                    anchor_semantic,
                    demand,
                    ..
                } if identity.fragment() == source.fragment()
                    && *demand == source_demand.semantic(&operation.ready.shared_names()) =>
                {
                    Some((*token, *anchor, *anchor_semantic))
                }
                _ => None,
            })
            .expect("persisted Go import token and anchor");
        let target_token = halves
            .iter()
            .find_map(|half| match half {
                SelectedRootPathHalf::Export {
                    identity,
                    token,
                    demand,
                    ..
                } if identity.fragment() == target.fragment()
                    && *demand == target_demand.semantic(&operation.ready.shared_names()) =>
                {
                    Some(*token)
                }
                _ => None,
            })
            .expect("persisted Go export token");
        SelectedRootBridgeDescriptor::from_selected_path_tokens(
            source.fragment(),
            Language::Go,
            source_token,
            anchor,
            anchor_semantic,
            target.fragment(),
            Language::Go,
            target_token,
            route,
            source_demand,
            target_demand,
            ResolutionCompletion::Complete,
        )
    }

    fn contexts_with_bridge(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        bridge: SelectedRootBridgeDescriptor,
    ) -> SelectedResolutionContextSet {
        let mounts = operation.mounts().unwrap();
        let source = mounts
            .iter()
            .find(|mount| mount.fragment() == bridge.source_fragment())
            .expect("selected bridge source");
        SelectedResolutionContextSet::new(
            SelectedContextIdentities::new(),
            vec![
                SelectedResolutionMountContext::new(
                    source.ordinal(),
                    source.fragment(),
                    source.semantic_language(),
                    vec![bridge],
                    ResolutionCompletion::Complete,
                )
                .expect("valid Go root operation context"),
            ],
            mounts.len(),
            &mount_lookup(mounts),
        )
        .expect("exact Go root operation context set")
    }
}

fn assert_empty_context_metrics(metrics: &SelectedResolutionContextMetrics) {
    assert_eq!(metrics, &SelectedResolutionContextMetrics);
}

fn test_oid(ordinal: u64) -> Oid {
    Oid::from_str(&format!("{ordinal:040x}")).expect("test OID")
}

fn site_for_identifier(
    facts: &FileResolutionFacts,
    spelling: &str,
    role: ResolutionIdentifierRole,
    namespace: ResolutionNamespace,
) -> ResolutionSiteId {
    try_site_for_identifier(facts, spelling, role, namespace)
        .unwrap_or_else(|| panic!("fixture identifier {role:?} {namespace:?} {spelling:?}"))
}

fn try_site_for_identifier(
    facts: &FileResolutionFacts,
    spelling: &str,
    role: ResolutionIdentifierRole,
    namespace: ResolutionNamespace,
) -> Option<ResolutionSiteId> {
    let names = facts
        .names
        .iter()
        .map(|name| (name.id, name.spelling.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();
    facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.role == role
                && identifier.namespace == namespace
                && names.get(&identifier.name).copied() == Some(spelling)
        })
        .map(|identifier| identifier.site)
}

fn provider_method_site(facts: &FileResolutionFacts) -> ResolutionSiteId {
    facts
        .member_owners
        .iter()
        .find(|member| member.kind == ResolutionMemberKind::Method)
        .expect("rich provider static method")
        .member
}

fn locator(
    path: &str,
    site: ResolutionSiteId,
    role: LoweredSemanticRole,
) -> SelectedSemanticLocator {
    SelectedSemanticLocator::new("java", path, site, role)
}

fn semantic_at(
    artifact: &LoweredResolutionFactsWithIdentityCatalog,
    site: ResolutionSiteId,
    role: LoweredSemanticRole,
) -> crate::analyzer::resolution::SemanticId {
    artifact
        .lexical()
        .semantics()
        .iter()
        .find(|semantic| semantic.site() == site && semantic.role() == role)
        .unwrap_or_else(|| panic!("lowered semantic {role:?} at {site:?}"))
        .semantic()
}

fn contexts_for(
    _fixture: &ResolutionOperationFixture,
    mounts: &[SelectedResolutionOperationMount],
) -> SelectedResolutionContextSet {
    // A context set is sparse, so a context with no relation and no inventory
    // evidence is empty whatever the operation selected.
    SelectedResolutionContextSet::new(
        SelectedContextIdentities::new(),
        Vec::new(),
        mounts.len(),
        &mount_lookup(mounts),
    )
    .expect("exact Java operation context set")
}

/// The mount coverage lookup a test operation's context set is built against.
fn mount_lookup(
    mounts: &[SelectedResolutionOperationMount],
) -> impl Fn(BindingFragmentId) -> Result<Option<(SelectedResolutionMountOrdinal, Language)>> + '_ {
    |fragment| {
        Ok(mounts
            .iter()
            .find(|mount| mount.fragment() == fragment)
            .map(|mount| (mount.ordinal(), mount.semantic_language())))
    }
}

struct PreloadedOracle {
    service: PreloadedFactResolutionService,
    point_reference: crate::analyzer::resolution::SemanticId,
    reverse_definition: crate::analyzer::resolution::SemanticId,
    source_fragment: crate::analyzer::resolution::BindingFragmentId,
    provider_fragment: crate::analyzer::resolution::BindingFragmentId,
}

impl PreloadedOracle {
    fn from_operation(
        fixture: &ResolutionOperationFixture,
        operation: &SelectedResolutionOperation<'_, '_>,
    ) -> Self {
        assert_eq!(operation.mount_table().mount_count(), 2);
        let lowered = operation
            .mounts()
            .unwrap()
            .iter()
            .map(|mount| {
                let facts = match mount.persisted_relative_path() {
                    SOURCE_PATH => &fixture.source_facts,
                    PROVIDER_PATH => &fixture.provider_facts,
                    path => panic!("unexpected parity mount {path:?}"),
                };
                (
                    mount.persisted_relative_path().to_owned(),
                    crate::analyzer::resolution::lower_resolution_facts_for_selection(
                        mount.fragment(),
                        &operation.ready.shared_names(),
                        Language::Java,
                        facts,
                    ),
                )
            })
            .collect::<Vec<_>>();
        let source = lowered
            .iter()
            .find(|(path, _)| path == SOURCE_PATH)
            .expect("persisted source artifact");
        let provider = lowered
            .iter()
            .find(|(path, _)| path == PROVIDER_PATH)
            .expect("transient provider artifact");
        let point_site = site_for_identifier(
            &fixture.source_facts,
            "method",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        let definition_site = provider_method_site(&fixture.provider_facts);
        let point_reference = semantic_at(&source.1, point_site, LoweredSemanticRole::Reference);
        let reverse_definition = semantic_at(
            &provider.1,
            definition_site,
            LoweredSemanticRole::Definition,
        );
        let source_fragment = source.1.lexical().fragment();
        let provider_fragment = provider.1.lexical().fragment();
        let mut service = PreloadedFactResolutionService::from_lowered_fragments(
            lowered
                .iter()
                .map(|(_, artifact)| artifact.lexical().clone()),
            lowered.iter().map(|(_, artifact)| artifact.typed().clone()),
        );
        // The persisted operation reads Java inheritance declarations from its
        // indexed source rows. Install the same facts from the lowered member
        // scopes so the preloaded oracle runs the same Java hierarchy replay.
        // These fixtures author classes only, each in one known package.
        let mut declarations = Vec::new();
        for (path, artifact) in &lowered {
            let (text, package) = match path.as_str() {
                SOURCE_PATH => (RICH_JAVA_SOURCE, "com.acme"),
                PROVIDER_PATH => (PROVIDER_JAVA_SOURCE, "dep"),
                path => panic!("unexpected parity mount {path:?}"),
            };
            assert!(text.contains(&format!("package {package};")), "{path}");
            assert!(!text.contains("interface"), "{path}");
            declarations.extend(artifact.typed().member_scopes().iter().map(|row| {
                crate::analyzer::resolution::JavaInheritanceDeclaration {
                    definition: row.definition(),
                    package: Some(package.to_owned()),
                    kind: crate::analyzer::resolution::JavaInheritanceDeclarationKind::Type {
                        is_interface: false,
                    },
                }
            }));
        }
        service.set_java_inheritance_metadata(declarations);
        Self {
            service,
            point_reference,
            reverse_definition,
            source_fragment,
            provider_fragment,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedBatches {
    batches: Vec<FactReferenceBatchAnswer>,
    summary: FactResolutionBatchSummary,
}

#[derive(Default)]
struct StagerState {
    staged: Vec<FactReferenceBatchAnswer>,
    rollback_count: usize,
    publish_count: usize,
}

type StageHook = Box<dyn FnOnce() -> Result<()>>;

struct RollbackStager {
    state: Rc<RefCell<StagerState>>,
    first_stage_hook: Option<StageHook>,
    published: bool,
}

impl RollbackStager {
    fn new() -> (Self, Rc<RefCell<StagerState>>) {
        Self::with_first_stage_hook(Box::new(|| Ok(())))
    }

    fn with_first_stage_hook(first_stage_hook: StageHook) -> (Self, Rc<RefCell<StagerState>>) {
        let state = Rc::new(RefCell::new(StagerState::default()));
        (
            Self {
                state: Rc::clone(&state),
                first_stage_hook: Some(first_stage_hook),
                published: false,
            },
            state,
        )
    }
}

impl SelectedResolutionBroadStager for RollbackStager {
    type Published = PublishedBatches;

    fn stage(&mut self, batch: &FactReferenceBatchAnswer) -> Result<()> {
        self.state.borrow_mut().staged.push(batch.clone());
        if let Some(hook) = self.first_stage_hook.take() {
            hook()?;
        }
        Ok(())
    }

    fn publish(mut self, summary: FactResolutionBatchSummary) -> Result<Self::Published> {
        let batches = {
            let mut state = self.state.borrow_mut();
            state.publish_count += 1;
            std::mem::take(&mut state.staged)
        };
        self.published = true;
        Ok(PublishedBatches { batches, summary })
    }
}

impl Drop for RollbackStager {
    fn drop(&mut self) {
        if !self.published {
            let mut state = self.state.borrow_mut();
            state.staged.clear();
            state.rollback_count += 1;
        }
    }
}

struct CountRollbackStager {
    state: Rc<RefCell<StagerState>>,
    first_stage_hook: Option<StageHook>,
    published: bool,
}

impl CountRollbackStager {
    fn with_first_stage_hook(first_stage_hook: StageHook) -> (Self, Rc<RefCell<StagerState>>) {
        let state = Rc::new(RefCell::new(StagerState::default()));
        (
            Self {
                state: Rc::clone(&state),
                first_stage_hook: Some(first_stage_hook),
                published: false,
            },
            state,
        )
    }
}

impl SelectedResolutionBroadStager for CountRollbackStager {
    type Published = usize;

    fn stage(&mut self, batch: &FactReferenceBatchAnswer) -> Result<()> {
        self.state.borrow_mut().staged.push(batch.clone());
        if let Some(hook) = self.first_stage_hook.take() {
            hook()?;
        }
        Ok(())
    }

    fn publish(mut self, _summary: FactResolutionBatchSummary) -> Result<Self::Published> {
        let reference_count = {
            let mut state = self.state.borrow_mut();
            state.publish_count += 1;
            let reference_count = state.staged.iter().map(|batch| batch.answers().len()).sum();
            state.staged.clear();
            reference_count
        };
        self.published = true;
        Ok(reference_count)
    }
}

impl Drop for CountRollbackStager {
    fn drop(&mut self) {
        if !self.published {
            let mut state = self.state.borrow_mut();
            state.staged.clear();
            state.rollback_count += 1;
        }
    }
}

fn dispatch_usize(
    native: Result<SelectedResolutionOperationOutcome<usize>>,
    cancellation: &CancellationToken,
    legacy: impl FnOnce() -> Result<usize>,
) -> Result<SelectedResolutionOperationResult<usize>> {
    native?.with_legacy(cancellation, legacy)
}

fn canonical_broad_rows(
    batches: &[FactReferenceBatchAnswer],
) -> Vec<(
    crate::analyzer::resolution::BindingFragmentId,
    crate::analyzer::resolution::SemanticId,
    crate::analyzer::resolution::FactResolutionAnswer,
)> {
    let mut rows = batches
        .iter()
        .flat_map(|batch| {
            batch.answers().iter().map(|answer| {
                (
                    batch.fragment(),
                    answer.reference(),
                    answer.answer().clone(),
                )
            })
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|(fragment, reference, _)| (*fragment, *reference));
    rows
}

fn assert_semantic_summary_eq(
    actual: &FactResolutionBatchSummary,
    expected: &FactResolutionBatchSummary,
) {
    assert_eq!(actual.completion(), expected.completion());
    assert_eq!(
        actual.reference_enumeration_completion(),
        expected.reference_enumeration_completion()
    );
    assert_eq!(actual.reference_count(), expected.reference_count());
    assert_eq!(actual.batch_count(), expected.batch_count());
}

fn assert_store_error_contains<T>(result: Result<T>, needle: &str) {
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("expected store error containing {needle:?}"),
    };
    assert!(
        error.to_string().contains(needle),
        "unexpected store error: {error}"
    );
}

fn with_operation_lexical<T>(
    operation: &SelectedResolutionOperation<'_, '_>,
    inspect: impl FnOnce(
        &SelectedResolutionLexicalSource<'_, '_>,
        &SelectedResolutionLexicalSource<'_, '_>,
    ) -> T,
) -> T {
    let source = operation.ready.lexical_source();
    inspect(&source, &source)
}

#[test]
fn real_go_bundle_reopens_without_java_placement_and_matches_preload() {
    let fixture = GoResolutionOperationFixture::new();
    let facts = &fixture.facts;
    let point_site = site_for_identifier(
        facts,
        "Item",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let definition_site = site_for_identifier(
        facts,
        "Item",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Type,
    );
    let call_site = site_for_identifier(
        facts,
        "Echo",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::TypeOrValue,
    );
    let placement_gap = facts
        .gaps
        .iter()
        .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
        .collect::<Vec<_>>();
    assert_eq!(placement_gap.len(), 1);
    assert_eq!(facts.gaps.len(), 2);
    assert!(facts.gaps.iter().all(|gap| {
        (gap.site == call_site && gap.kind == ResolutionGapKind::UnsupportedCallApplicability)
            || (gap.site == placement_gap[0].site
                && gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
    }));
    assert!(facts.reference_enumeration_gaps.is_empty());
    assert!(facts.import_routes.is_empty());

    let cancellation = CancellationToken::default();
    let mounted = fixture.open_ready(&cancellation);
    assert_eq!(mounted.mounts().unwrap().len(), 1);
    let mount = &mounted.mounts().unwrap()[0];
    assert_eq!(mount.storage_language(), "go");
    assert_eq!(mount.persisted_relative_path(), GO_SOURCE_PATH);
    assert_eq!(mount.semantic_language(), Language::Go);
    assert!(
        mounted
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())
            .unwrap()
            .file_version_id()
            .is_some()
    );
    let fragment = mount.fragment();
    drop(mounted);

    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        fragment,
        crate::analyzer::resolution::test_shared_names(),
        Language::Go,
        facts,
    );
    assert!(!lowered.typed().frontiers().is_empty());
    let point_reference = semantic_at(&lowered, point_site, LoweredSemanticRole::Reference);
    let reverse_definition =
        semantic_at(&lowered, definition_site, LoweredSemanticRole::Definition);
    let call_reference = semantic_at(&lowered, call_site, LoweredSemanticRole::Reference);
    let preload = PreloadedFactResolutionService::from_lowered_fragments(
        [lowered.lexical().clone()],
        [lowered.typed().clone()],
    );

    let expected_point = preload
        .resolve_reference(point_reference, &cancellation)
        .expect("preloaded Go point resolution");
    assert!(
        expected_point
            .binding()
            .targets()
            .contains(&reverse_definition)
    );
    assert!(
        !expected_point.projected_frontiers().is_empty(),
        "the point fixture must exercise typed projection hydration"
    );
    let point_site_range = facts
        .sites
        .iter()
        .find(|site| site.id == point_site)
        .expect("Go point site range");
    let point_locator = SelectedSemanticLocator::for_reference_range(
        "go",
        GO_SOURCE_PATH,
        point_site_range.start_byte,
        point_site_range.end_byte,
    );
    let point_operation = fixture.open_ready(&cancellation);
    let point_context = point_operation
        .empty_contexts(&ResolutionCompletion::Complete)
        .unwrap();
    let mut point_context_metrics = SelectedResolutionContextMetrics;
    let point = point_operation
        .resolve_reference(
            point_context,
            &point_locator,
            &cancellation,
            &mut point_context_metrics,
        )
        .expect("persisted Go point resolution");
    assert_empty_context_metrics(&point_context_metrics);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(point)) = point
    else {
        panic!("persisted Go point operation must return a native found answer")
    };
    assert_eq!(point, expected_point);

    let expected_reverse = preload
        .references_to(reverse_definition, &cancellation)
        .expect("preloaded Go reverse resolution");
    let definition_locator = SelectedSemanticLocator::new(
        "go",
        GO_SOURCE_PATH,
        definition_site,
        LoweredSemanticRole::Definition,
    );
    let reverse_operation = fixture.open_ready(&cancellation);
    let reverse_context = reverse_operation
        .empty_contexts(&ResolutionCompletion::Complete)
        .unwrap();
    let mut reverse_context_metrics = SelectedResolutionContextMetrics;
    let mut reverse_metrics = FactReverseResolutionMetrics::default();
    let reverse = reverse_operation
        .references_to_selected_definition(
            reverse_context,
            2,
            &definition_locator,
            &cancellation,
            &mut reverse_context_metrics,
            &mut reverse_metrics,
        )
        .expect("persisted Go reverse resolution");
    assert_empty_context_metrics(&reverse_context_metrics);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(reverse)) =
        reverse
    else {
        panic!("persisted Go reverse operation must return a native found answer")
    };
    assert_eq!(reverse.answer(), &expected_reverse);
    assert!(reverse.references().contains(&point_reference));
    assert!(reverse_metrics.demanded_definition_count() > 0);
    assert!(reverse_metrics.published_reference_count() > 0);

    let expected_call_point = preload
        .resolve_reference(call_reference, &cancellation)
        .expect("preloaded Go call resolution");
    assert_eq!(
        expected_call_point.completion(),
        &ResolutionCompletion::Complete,
        "a unique Go function name and its selected result type resolve without argument filtering"
    );
    let call_locator = SelectedSemanticLocator::new(
        "go",
        GO_SOURCE_PATH,
        call_site,
        LoweredSemanticRole::Reference,
    );
    let call_operation = fixture.open_ready(&cancellation);
    let call_context = call_operation
        .empty_contexts(&ResolutionCompletion::Complete)
        .unwrap();
    let mut call_context_metrics = SelectedResolutionContextMetrics;
    let call = call_operation
        .resolve_reference(
            call_context,
            &call_locator,
            &cancellation,
            &mut call_context_metrics,
        )
        .expect("persisted Go call resolution");
    assert_empty_context_metrics(&call_context_metrics);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(call)) = call
    else {
        panic!("persisted Go call operation must return a native found answer")
    };
    assert_eq!(call, expected_call_point);
}

#[test]
fn selected_go_root_context_matches_preload_and_excludes_wrong_route() {
    let fixture = GoRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let mounted = fixture.open_ready(&cancellation);
    assert_eq!(mounted.mounts().unwrap().len(), 3);
    let mounts = mounted.mounts().unwrap().to_vec();
    let preload_context = fixture.contexts_for(&mounted);
    drop(mounted);

    let artifact_for = |path: &str, facts: &FileResolutionFacts| {
        let mount = mounts
            .iter()
            .find(|mount| mount.persisted_relative_path() == path)
            .unwrap_or_else(|| panic!("missing selected Go mount {path:?}"));
        crate::analyzer::resolution::lower_resolution_facts_for_selection(
            mount.fragment(),
            crate::analyzer::resolution::test_shared_names(),
            Language::Go,
            facts,
        )
    };
    let consumer = artifact_for(GO_ROOT_CONSUMER_PATH, &fixture.consumer_facts);
    let provider = artifact_for(GO_ROOT_PROVIDER_PATH, &fixture.provider_facts);
    let decoy = artifact_for(GO_ROOT_DECOY_PATH, &fixture.decoy_facts);
    let reference_site = site_for_identifier(
        &fixture.consumer_facts,
        "Item",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let provider_site = site_for_identifier(
        &fixture.provider_facts,
        "Item",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Type,
    );
    let decoy_site = site_for_identifier(
        &fixture.decoy_facts,
        "Item",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Type,
    );
    let reference = semantic_at(&consumer, reference_site, LoweredSemanticRole::Reference);
    let provider_definition =
        semantic_at(&provider, provider_site, LoweredSemanticRole::Definition);
    let decoy_definition = semantic_at(&decoy, decoy_site, LoweredSemanticRole::Definition);

    let preload = PreloadedFactResolutionService::from_lowered_fragments(
        [
            consumer.lexical().clone(),
            provider.lexical().clone(),
            decoy.lexical().clone(),
        ],
        [
            consumer.typed().clone(),
            provider.typed().clone(),
            decoy.typed().clone(),
        ],
    );
    let SelectedResolutionContextValidationOutcome::Ready(preload_context) = preload_context
        .validate_exact_mounts(mounts.len(), &mount_lookup(&mounts), &cancellation)
        .expect("validate preloaded Go root context")
    else {
        panic!("uncancelled preloaded Go root context must validate")
    };
    let preload_blueprint =
        crate::analyzer::resolution::SelectedContextTestOracle::collect_context(
            preload_context,
            crate::analyzer::resolution::test_shared_names(),
            &cancellation,
        )
        .expect("compile independent preloaded Go root context oracle");
    let expected_point = preload_blueprint
        .resolve_reference(&preload, &preload, reference, &cancellation)
        .expect("preloaded cross-package Go point resolution");
    assert!(
        expected_point
            .binding()
            .targets()
            .contains(&provider_definition)
    );
    assert!(
        !expected_point
            .binding()
            .targets()
            .contains(&decoy_definition)
    );
    assert!(matches!(
        expected_point.completion(),
        ResolutionCompletion::Incomplete(_)
    ));

    let point_locator = SelectedSemanticLocator::new(
        "go",
        GO_ROOT_CONSUMER_PATH,
        reference_site,
        LoweredSemanticRole::Reference,
    );
    let point_operation = fixture.open_ready(&cancellation);
    let point_context = fixture.contexts_for(&point_operation);
    let mut point_metrics = SelectedResolutionContextMetrics;
    let point = point_operation
        .resolve_reference(
            point_context,
            &point_locator,
            &cancellation,
            &mut point_metrics,
        )
        .expect("persisted cross-package Go point resolution");
    assert_empty_context_metrics(&point_metrics);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(point)) = point
    else {
        panic!("persisted cross-package Go point must return a native found answer")
    };
    assert_eq!(point, expected_point);

    let expected_reverse = preload_blueprint
        .references_to(
            &preload,
            &preload,
            2,
            provider_definition,
            &cancellation,
            &mut FactReverseResolutionMetrics::default(),
        )
        .expect("preloaded cross-package Go reverse resolution");
    assert!(expected_reverse.references().contains(&reference));
    assert!(matches!(
        expected_reverse.completion(),
        ResolutionCompletion::Incomplete(_)
    ));
    let definition_locator = SelectedSemanticLocator::new(
        "go",
        GO_ROOT_PROVIDER_PATH,
        provider_site,
        LoweredSemanticRole::Definition,
    );
    let reverse_operation = fixture.open_ready(&cancellation);
    let reverse_context = fixture.contexts_for(&reverse_operation);
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut reverse_metrics = FactReverseResolutionMetrics::default();
    let reverse = reverse_operation
        .references_to_selected_definition(
            reverse_context,
            2,
            &definition_locator,
            &cancellation,
            &mut context_metrics,
            &mut reverse_metrics,
        )
        .expect("persisted cross-package Go reverse resolution");
    assert_empty_context_metrics(&context_metrics);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(reverse)) =
        reverse
    else {
        panic!("persisted cross-package Go reverse must return a native found answer")
    };
    assert_eq!(reverse.answer(), &expected_reverse);
    assert!(reverse.references().contains(&reference));
}

fn publish_go_root_fixture_context(
    fixture: &GoRootResolutionOperationFixture,
    source_spelling: &'static str,
) -> i64 {
    let snapshot = fixture.snapshots["go"].clone();
    fixture.store.conn.execute(move |conn| {
        let tx = conn.transaction().unwrap();
        tx.execute("INSERT INTO go_context_selections(workspace_id,lang,generation,revision,profile_digest,derivation_version)
            VALUES(?1,'go',?2,?3,zeroblob(32),?4)", params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,super::super::go_package_context::DERIVATION_VERSION]).unwrap();
        let selection = tx.last_insert_rowid();
        tx.execute("INSERT INTO go_context_publications(selection_id,publication_digest,complete,gaps)
            VALUES(?1,zeroblob(32),0,jsonb('[]'))", [selection]).unwrap();
        let context = tx.last_insert_rowid();
        tx.execute("INSERT INTO go_context_heads(selection_id,context_id) VALUES(?1,?2)", params![selection,context]).unwrap();
        let mut packages = Vec::new();
        for (path, import_path, name) in [
            (GO_ROOT_CONSUMER_PATH,"example.test/root/consumer","consumer"),
            (GO_ROOT_PROVIDER_PATH,"example.test/root/provider","provider"),
            (GO_ROOT_DECOY_PATH,"example.test/root/other/provider","provider"),
        ] {
            tx.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps)
                VALUES(?1,?2,?3,'','',zeroblob(32),0,jsonb('[]'))",params![context,import_path,name]).unwrap();
            let package = tx.last_insert_rowid();
            packages.push(package);
            tx.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role)
                SELECT ?1,file_version_id,'go' FROM workspace_file_versions
                WHERE workspace_id=?2 AND lang='go' AND generation=?3 AND rel_path=?4 AND valid_from<=?5
                AND (valid_until IS NULL OR ?5<valid_until)",params![package,snapshot.workspace_id.as_str(),snapshot.generation.get(),path,snapshot.revision]).unwrap();
        }
        tx.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps)
            VALUES(?1,?2,?4,'go',?3,0,jsonb('[]'))",params![context,packages[0],packages[1],source_spelling]).unwrap();
        // Give statistics representative unrelated imports. A one-row table
        // legitimately favors a scan and cannot prove demand-local seeking.
        for index in 0..512 {
            tx.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps)
                VALUES(?1,?2,?3,'go',?4,0,jsonb('[]'))",params![context,packages[0],format!("unrelated/provider{index}"),packages[2]]).unwrap();
        }
        tx.commit().unwrap();
        context
     })
}

#[test]
fn selected_go_package_rows_compose_dot_import_without_manual_bridges() {
    let fixture = GoRootResolutionOperationFixture::new();
    let context_id = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
    let cancellation = CancellationToken::new();
    // The same demand query must seek persisted membership both before and
    // after statistics, using the operation's real selected mount table.
    for statistics in [false, true] {
        if statistics {
            fixture.store.refresh_planner_statistics().unwrap();
        } else {
            fixture.store.clear_planner_statistics().unwrap();
        }
        let operation = fixture.open_ready(&cancellation);
        let mount = operation
            .mount_table()
            .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let file_version = operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())
            .unwrap()
            .file_version_id()
            .unwrap();
        let mut pin =
            super::super::planner_statistics::pinned_plans::pinned("go_dot_import_target_mounts");
        pin.params = vec![
            rusqlite::types::Value::Integer(context_id),
            rusqlite::types::Value::Integer(file_version),
            rusqlite::types::Value::Text("go".to_owned()),
            rusqlite::types::Value::Text("example.test/root/provider".to_owned()),
        ];
        let plan = super::super::planner_statistics::pinned_plans::explain_pin(
            operation.ready.inventory.connection(),
            &pin,
        );
        assert!(
            !plan.iter().any(|line| line.contains("SCAN imports")
                || line.contains("SCAN mounted")
                || line.contains("AUTOMATIC")
                || line.contains("TEMP B-TREE")),
            "statistics={statistics}: {plan:?}"
        );
    }
    let operation = fixture.open_ready(&cancellation);
    let expected = fixture.contexts_for(&operation);
    let go_context::GoDotImportContext::Ready(derived) = operation
        .go_dot_import_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
        .unwrap()
    else {
        panic!("selected package rows must supply dot-import context")
    };
    let reference_site = site_for_identifier(
        &fixture.consumer_facts,
        "Item",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let locator = SelectedSemanticLocator::new(
        "go",
        GO_ROOT_CONSUMER_PATH,
        reference_site,
        LoweredSemanticRole::Reference,
    );
    let actual = operation
        .resolve_reference(
            derived,
            &locator,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let baseline = fixture
        .open_ready(&cancellation)
        .resolve_reference(
            expected,
            &locator,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(actual)) =
        actual
    else {
        panic!("native derived result")
    };
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(baseline)) =
        baseline
    else {
        panic!("native known-map result")
    };
    assert_eq!(actual.binding().targets(), baseline.binding().targets());
    assert!(!actual.binding().targets().is_empty());
    assert!(matches!(
        actual.completion(),
        ResolutionCompletion::Incomplete(_)
    ));
    let operation = fixture.open_ready(&cancellation);
    let go_context::GoDotImportContext::Ready(derived) = operation
        .go_dot_import_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
        .unwrap()
    else {
        panic!("context remains published")
    };
    fixture.store.conn.execute(move |conn| {
        conn.execute(
            "DELETE FROM go_context_heads WHERE context_id=?1",
            [context_id],
        )
        .unwrap();
    });
    assert!(matches!(
        operation
            .resolve_reference(
                derived,
                &locator,
                &cancellation,
                &mut SelectedResolutionContextMetrics
            )
            .unwrap(),
        SelectedResolutionOperationOutcome::Stale(
            SelectedResolutionStale::NativeContextPublication { .. }
        )
    ));
}

#[test]
fn selected_native_context_requires_matching_configuration_overlay() {
    let mut fixture = GoRootResolutionOperationFixture::new();
    let snapshot = fixture.snapshots["go"].clone();
    let source_rows = [
        (GO_ROOT_CONSUMER_PATH, GO_ROOT_CONSUMER_SOURCE),
        (GO_ROOT_PROVIDER_PATH, GO_ROOT_PROVIDER_SOURCE),
        (GO_ROOT_DECOY_PATH, GO_ROOT_DECOY_SOURCE),
    ]
    .map(|(path, source)| WorkspaceFileRow {
        rel_path: path.into(),
        blob_oid: Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap(),
    });
    let manifest = b"module example.test/root\n";
    let selected = fixture
        .store
        .sync_workspace_inputs_for_workspace(
            &fixture.workspace_id,
            "go",
            snapshot.generation,
            &source_rows,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[WorkspaceConfigurationInput::new(
                "go.mod".into(),
                manifest.as_slice().into(),
            )],
            &[],
        )
        .unwrap();
    fixture.snapshots.insert("go".into(), selected);
    let cancellation = CancellationToken::new();
    let manifest_file = ProjectFile::new(fixture.project.root(), "go.mod");
    fixture.project.set_overlay_content(
        manifest_file.clone(),
        std::str::from_utf8(manifest).unwrap(),
    );
    drop(fixture.open_ready(&cancellation));

    fixture
        .project
        .set_overlay_content(manifest_file, "module example.test/changed\n");
    let input = SelectedResolutionOperationInput::new(
        &fixture.project,
        &fixture.workspace_id,
        &fixture.snapshots,
        &fixture.languages,
        &fixture.overlay_masks,
    );
    assert!(matches!(
        fixture.store.open_selected_resolution_operation(input, &cancellation).unwrap(),
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language, persisted_relative_path,
            }
        ) if storage_language == "go" && persisted_relative_path == "go.mod"
    ));
    fixture.project.set_overlay_content(
        ProjectFile::new(fixture.project.root(), "notes.txt"),
        "unrelated overlay",
    );
    drop(fixture.open_ready(&cancellation));
}

#[test]
fn selected_go_root_context_missing_anchor_identity_fails_closed() {
    let fixture = GoRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let reference_site = site_for_identifier(
        &fixture.consumer_facts,
        "Item",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let locator = SelectedSemanticLocator::new(
        "go",
        GO_ROOT_CONSUMER_PATH,
        reference_site,
        LoweredSemanticRole::Reference,
    );
    let valid = fixture.root_bridge(&operation);
    let invalid = SelectedRootBridgeDescriptor::from_selected_path_tokens(
        valid.source_fragment(),
        valid.source_language(),
        valid.source_import_token(),
        ResolutionRootImportAnchor::Absolute,
        crate::analyzer::resolution::SemanticId::for_test(b"missing-go-root-anchor"),
        valid.target_fragment(),
        valid.target_language(),
        valid.target_export_token(),
        valid.route().to_vec(),
        valid.source_demand().clone(),
        valid.target_demand().clone(),
        valid.completion().clone(),
    );
    let context = fixture.contexts_with_bridge(&operation, invalid);
    let error = match operation.resolve_reference(
        context,
        &locator,
        &cancellation,
        &mut SelectedResolutionContextMetrics,
    ) {
        Ok(_) => panic!("a missing selected context anchor must fail closed"),
        Err(error) => error,
    };
    // The anchor's runtime id is the position it occupies in its blob's
    // catalog, so the catalog read that answers for it is what fails closed
    // now, before the provenance decode that used to report this.
    assert!(
        error.to_string().contains("is not in its blob's catalog"),
        "unexpected missing-anchor error: {error}"
    );
}

#[test]
fn persisted_rust_root_half_inventory_matches_preloaded_canonical_paths() {
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mounts = operation.mounts().unwrap().to_vec();
    let every_mount = mounts
        .iter()
        .map(|mount| mount.ordinal())
        .collect::<Vec<_>>();

    let mut actual = with_operation_lexical(&operation, |composite, anchors| {
        let mut halves = Vec::new();
        let imports = visit_selected_root_import_half_pages(
            &SelectedContextIdentities::new(),
            anchors,
            composite,
            Some(&every_mount),
            &cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                halves.extend_from_slice(page);
                Ok(true)
            }),
        )
        .expect("persisted Rust root import inventory");
        let exports = visit_selected_root_export_half_pages(
            &SelectedContextIdentities::new(),
            anchors,
            composite,
            Some(&every_mount),
            &cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                halves.extend_from_slice(page);
                Ok(true)
            }),
        )
        .expect("persisted Rust root export inventory");
        assert!(imports.is_exhausted());
        assert!(exports.is_exhausted());
        halves
    });

    let artifact_for = |path: &str, facts: &FileResolutionFacts| {
        let mount = mounts
            .iter()
            .find(|mount| mount.persisted_relative_path() == path)
            .unwrap_or_else(|| panic!("missing selected Rust mount {path:?}"));
        // Mounted at the mount it stands for, and recorded, because the
        // fixture anchors answer from the catalog that numbered the blob: a
        // lowering mints unmounted, and an unmounted artifact would hand the
        // import half identities no mount owns.
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            mount.fragment(),
            &operation.ready.shared_names(),
            Language::Rust,
            facts,
        )
        .remount(mount.fragment(), &cancellation)
        .expect("an uncancelled fixture remount finishes");
        crate::analyzer::resolution::record_fixture_identity_catalog(lowered.identities());
        lowered
    };
    let consumer = artifact_for(RUST_ROOT_CONSUMER_PATH, &fixture.consumer_facts);
    let provider_root = artifact_for(RUST_ROOT_PROVIDER_ROOT_PATH, &fixture.provider_root_facts);
    let provider = artifact_for(RUST_ROOT_PROVIDER_PATH, &fixture.provider_facts);
    let preload = PreloadedFactResolutionService::from_lowered_fragments(
        [
            consumer.lexical().clone(),
            provider_root.lexical().clone(),
            provider.lexical().clone(),
        ],
        [
            consumer.typed().clone(),
            provider_root.typed().clone(),
            provider.typed().clone(),
        ],
    );
    let mut expected = Vec::new();
    visit_selected_root_import_half_pages(
        &SelectedContextIdentities::new(),
        &crate::analyzer::resolution::FixtureRootImportAnchors,
        &preload,
        Some(&every_mount),
        &cancellation,
        &mut FactPageVisitor::new(&mut |page| {
            expected.extend_from_slice(page);
            Ok(true)
        }),
    )
    .expect("preloaded Rust root import inventory");
    visit_selected_root_export_half_pages(
        &SelectedContextIdentities::new(),
        &crate::analyzer::resolution::FixtureRootImportAnchors,
        &preload,
        Some(&every_mount),
        &cancellation,
        &mut FactPageVisitor::new(&mut |page| {
            expected.extend_from_slice(page);
            Ok(true)
        }),
    )
    .expect("preloaded Rust root export inventory");

    actual.sort_unstable();
    expected.sort_unstable();
    assert!(!actual.is_empty());
    assert_eq!(actual, expected);
}

#[test]
fn selected_operation_rejects_inexact_context_before_source_work_and_retries() {
    let fixture = GoResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let facts = &fixture.facts;
    let point_site = site_for_identifier(
        facts,
        "Item",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let point_locator = SelectedSemanticLocator::new(
        "go",
        GO_SOURCE_PATH,
        point_site,
        LoweredSemanticRole::Reference,
    );

    let operation = fixture.open_ready(&cancellation);
    let missing = SelectedResolutionContextSet::new(
        SelectedContextIdentities::new(),
        Vec::<SelectedResolutionMountContext>::new(),
        0,
        &|_| Ok(None),
    )
    .expect("empty context set is locally well-formed");
    let mut metrics = SelectedResolutionContextMetrics;
    reset_selected_fact_operation_construction_count_for_test();
    reset_selected_resolution_boundary_snapshot_for_test();
    assert_store_error_contains(
        operation.resolve_reference(missing, &point_locator, &cancellation, &mut metrics),
        "omits operation mounts",
    );
    assert_eq!(metrics, Default::default());
    assert_eq!(selected_fact_operation_construction_count_for_test(), 0);
    assert!(selected_resolution_boundary_snapshot_for_test().is_none());

    let retry = fixture.open_ready(&cancellation);
    let context = retry
        .empty_contexts(&ResolutionCompletion::Complete)
        .unwrap();
    let mut metrics = SelectedResolutionContextMetrics;
    let retry = retry
        .resolve_reference(context, &point_locator, &cancellation, &mut metrics)
        .expect("exact selected context retry");
    assert_empty_context_metrics(&metrics);
    assert!(matches!(
        retry,
        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(_))
    ));
}

#[test]
fn published_replacements_are_exact_sorted_dense_mounts() {
    let fixture = ResolutionOperationFixture::new();
    let masks = fixture.two_replacement_masks();
    let cancellation = CancellationToken::default();

    let first = fixture.open_ready(
        &masks,
        vec![fixture.second_replacement(), fixture.provider_replacement()],
        &cancellation,
    );
    let first_mounts = first.mounts().unwrap().to_vec();
    assert_eq!(
        first_mounts
            .iter()
            .map(|mount| {
                (
                    mount.ordinal().get(),
                    mount.persisted_relative_path(),
                    mount.storage_language(),
                    mount.semantic_language(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (0, SOURCE_PATH, "java", Language::Java),
            (1, PROVIDER_PATH, "java", Language::Java),
            (2, SECOND_REPLACEMENT_PATH, "java", Language::Java),
        ]
    );
    assert!(
        first_mounts
            .iter()
            .all(|mount| mount.persisted_relative_path() != REMOVED_PATH),
        "a removal owns no selected ordinal"
    );
    drop(first);

    let permuted = fixture.open_ready(
        &masks,
        vec![fixture.provider_replacement(), fixture.second_replacement()],
        &cancellation,
    );
    assert_eq!(permuted.mounts().unwrap(), first_mounts.as_slice());
    drop(permuted);

    assert!(matches!(
        fixture
            .open(&masks, vec![fixture.provider_replacement()], &cancellation)
            .unwrap(),
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientReplacement {
                storage_language,
                persisted_relative_path
            }
        ) if storage_language == "java" && persisted_relative_path == SECOND_REPLACEMENT_PATH
    ));
    assert!(matches!(
        fixture.open(
            &masks,
            vec![
                fixture.provider_replacement(),
                fixture.second_replacement(),
                fixture.counterfactual_content(
                    "src/E_Extra.java",
                    RICH_JAVA_SOURCE,
                    RICH_JAVA_SOURCE,
                ),
            ],
            &cancellation,
        ).unwrap(),
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "java" && persisted_relative_path == "src/E_Extra.java"
    ));
    assert_store_error_contains(
        fixture.open(
            &masks,
            vec![
                fixture.provider_replacement(),
                fixture.provider_replacement(),
                fixture.second_replacement(),
            ],
            &cancellation,
        ),
        "duplicate selected resolution content mount",
    );
}

#[test]
#[should_panic(expected = "content mount package-file row belongs to a foreign path")]
fn published_replacement_rejects_foreign_projection_path() {
    let fixture = ResolutionOperationFixture::new();
    let content = fixture.published_content(SECOND_REPLACEMENT_PATH, RICH_JAVA_SOURCE);
    let witness = content.publication().clone();
    let oid = witness.blob_oid();
    SelectedResolutionContentMountRequest::new(
        witness,
        WorkspaceFileRow {
            rel_path: SECOND_REPLACEMENT_PATH.to_owned(),
            blob_oid: oid,
        },
        Vec::new(),
        vec![WorkspacePackageFileRow {
            package_name: "foreign".to_owned(),
            rel_path: "src/Foreign.java".to_owned(),
        }],
        Vec::new(),
        Vec::new(),
    );
}

#[test]
#[should_panic(expected = "content mount package-file natural key repeats")]
fn published_replacement_rejects_duplicate_projection_key() {
    let fixture = ResolutionOperationFixture::new();
    let content = fixture.published_content(SECOND_REPLACEMENT_PATH, RICH_JAVA_SOURCE);
    let witness = content.publication().clone();
    let oid = witness.blob_oid();
    SelectedResolutionContentMountRequest::new(
        witness,
        WorkspaceFileRow {
            rel_path: SECOND_REPLACEMENT_PATH.to_owned(),
            blob_oid: oid,
        },
        Vec::new(),
        (0..2)
            .map(|_| WorkspacePackageFileRow {
                package_name: "duplicate".to_owned(),
                rel_path: SECOND_REPLACEMENT_PATH.to_owned(),
            })
            .collect(),
        Vec::new(),
        Vec::new(),
    );
}

#[test]
fn selected_operation_rejects_an_unprepared_source_overlay_before_sql() {
    let fixture = ResolutionOperationFixture::new();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    begin_production_selected_sql_trace(&fixture.store);
    let cancelled_result = fixture
        .open_with_project_and_content_mounts(&fixture.project, &[], Vec::new(), &cancelled)
        .expect("pre-cancelled selected operation must not fail the store call");
    let cancelled_cost = finish_production_selected_sql_trace(&fixture.store);
    assert!(matches!(
        cancelled_result,
        SelectedResolutionOperationOpenOutcome::Cancelled
    ));
    assert_eq!(
        cancelled_cost.statement_count(),
        0,
        "pre-cancelled operation must not open selected SQL"
    );

    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));

    begin_production_selected_sql_trace(&fixture.store);
    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &[],
            Vec::new(),
            &CancellationToken::default(),
        )
        .expect("unprepared overlay preflight must not fail the store call");
    let cost = finish_production_selected_sql_trace(&fixture.store);
    assert_eq!(
        cost.statement_count(),
        0,
        "overlay preflight must precede SQL"
    );
    assert!(matches!(
        result,
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "java" && persisted_relative_path == PROVIDER_PATH
    ));

    let removal_masks = [SelectedResolutionOverlayMask::removal(
        "java",
        PROVIDER_PATH,
    )];
    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &removal_masks,
            Vec::new(),
            &CancellationToken::default(),
        )
        .expect("removal-only overlay input must not fail the store call");
    assert!(matches!(
        result,
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "java" && persisted_relative_path == PROVIDER_PATH
    ));

    let replacement_masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &replacement_masks,
            Vec::new(),
            &CancellationToken::default(),
        )
        .expect("a mask without its overlay payload must not fail the store call");
    assert!(matches!(
        result,
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "java" && persisted_relative_path == PROVIDER_PATH
    ));
    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &replacement_masks,
            vec![fixture.published_content(PROVIDER_PATH, source)],
            &CancellationToken::default(),
        )
        .expect("unattested replacement must not fail the store call");
    assert!(matches!(
        result,
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "java" && persisted_relative_path == PROVIDER_PATH
    ));

    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &[],
            vec![fixture.live_content(PROVIDER_PATH, source)],
            &CancellationToken::default(),
        )
        .expect("missing overlay mask preflight must not fail the store call");
    assert!(matches!(
        result,
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "java" && persisted_relative_path == PROVIDER_PATH
    ));
}

#[test]
fn selected_operation_requires_the_live_overlay_digest_and_rejects_clear() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let original = "class Provider {}\n";
    let changed = "class ProviderChanged {}\n";
    assert!(overlay.set(file.abs_path(), original.to_owned()));
    let original_digest =
        brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];

    assert!(overlay.set(file.abs_path(), changed.to_owned()));
    let stale = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![fixture.live_content(PROVIDER_PATH, original)],
            &CancellationToken::default(),
        )
        .expect("stale overlay preflight must not fail the store call");
    assert!(matches!(
        stale,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: Some(_),
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == original_digest
    ));

    assert!(overlay.set(file.abs_path(), original.to_owned()));
    assert!(overlay.clear(&file.abs_path()));
    let cleared = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![fixture.live_content(PROVIDER_PATH, original)],
            &CancellationToken::default(),
        )
        .expect("cleared overlay preflight must not fail the store call");
    assert!(matches!(
        cleared,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: None,
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == original_digest
    ));
}

#[test]
fn selected_operation_accepts_matching_live_and_counterfactual_overlay_authority() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let base = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), base.to_owned()));
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];

    let live = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![fixture.live_content(PROVIDER_PATH, base)],
            &CancellationToken::default(),
        )
        .expect("matching live overlay must not fail the store call");
    let SelectedResolutionOperationOpenOutcome::Ready(live) = live else {
        panic!("matching live overlay must open Ready")
    };
    drop(live);

    let counterfactual = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![fixture.counterfactual_content(PROVIDER_PATH, base, PROVIDER_JAVA_SOURCE)],
            &CancellationToken::default(),
        )
        .expect("matching counterfactual base must not fail the store call");
    let SelectedResolutionOperationOpenOutcome::Ready(counterfactual) = counterfactual else {
        panic!("matching counterfactual base must open Ready")
    };
    drop(counterfactual);

    let disk_counterfactual = fixture
        .open_with_project_and_content_mounts(
            &fixture.project,
            &masks,
            vec![fixture.counterfactual_content(
                PROVIDER_PATH,
                RICH_JAVA_SOURCE,
                PROVIDER_JAVA_SOURCE,
            )],
            &CancellationToken::default(),
        )
        .expect("counterfactual base without a live overlay must be accepted");
    assert!(matches!(
        disk_counterfactual,
        SelectedResolutionOperationOpenOutcome::Ready(_)
    ));
}

#[test]
fn selected_operation_accepts_a_matching_cached_content_mount_authority() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("matching cached content authority must not fail the store call");
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = result else {
        panic!("matching cached content authority must open Ready")
    };
    let provider = operation
        .mounts()
        .unwrap()
        .iter()
        .find(|mount| mount.persisted_relative_path() == PROVIDER_PATH)
        .expect("cached provider mount");
    let selected = operation
        .ready
        .inventory
        .mount_record_by_ordinal(provider.ordinal())
        .unwrap();
    assert!(selected.file_version_id().is_none());
    assert_eq!(selected.blob_oid(), persisted_oid());
}

#[test]
fn selected_operation_rejects_cached_content_authority_before_sql_when_wrong_or_cleared() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];

    begin_production_selected_sql_trace(&fixture.store);
    let wrong = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest([0x5a; 32]),
            ],
            &CancellationToken::default(),
        )
        .expect("wrong cached content authority must not fail the store call");
    let wrong_cost = finish_production_selected_sql_trace(&fixture.store);
    assert_eq!(wrong_cost.statement_count(), 0);
    assert!(matches!(
        wrong,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: Some(_),
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == [0x5a; 32]
    ));

    assert!(overlay.clear(&file.abs_path()));
    begin_production_selected_sql_trace(&fixture.store);
    let cleared = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("cleared cached content authority must not fail the store call");
    let cleared_cost = finish_production_selected_sql_trace(&fixture.store);
    assert_eq!(cleared_cost.statement_count(), 0);
    assert!(matches!(
        cleared,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: None,
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == digest
    ));
}

#[test]
fn selected_operation_rechecks_cached_content_authority_at_final_boundary() {
    let fixture = ResolutionOperationFixture::new();
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    let changed = "class ProviderChanged {}\n";
    fixture.project.set_overlay_content(file.clone(), source);
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let operation = match fixture
        .open_with_project_and_content_mounts(
            &fixture.project,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("matching cached content authority must open")
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        _ => panic!("matching cached content authority must open Ready"),
    };
    let mut ready = operation.ready;
    fixture.project.set_overlay_content(file, changed);
    assert_eq!(fixture.project.analysis_generation(), 0);
    let result = ready.finish(
        (),
        &ResolutionCompletion::Complete,
        &CancellationToken::default(),
    );
    assert!(matches!(
        result.unwrap(),
        SelectedResolutionOperationOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: Some(_),
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == digest
    ));
}

#[test]
fn selected_operation_revalidates_cached_content_publication_before_native() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let operation = match fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("matching cached content authority must open")
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        _ => panic!("matching cached content authority must open Ready"),
    };
    let mut ready = operation.ready;
    fixture.store.conn.execute(|conn| {
        conn.execute(
            "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
            [persisted_oid().to_string()],
        )
        .unwrap();
    });
    let result = ready.finish(
        (),
        &ResolutionCompletion::Complete,
        &CancellationToken::default(),
    );
    assert!(matches!(
        result.unwrap(),
        SelectedResolutionOperationOutcome::Stale(SelectedResolutionStale::MountInventoryChanged)
    ));
}

#[test]
fn selected_operation_precancelled_cached_content_mount_does_no_sql() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    begin_production_selected_sql_trace(&fixture.store);
    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &cancellation,
        )
        .expect("pre-cancelled cached content operation must not fail the store call");
    let cost = finish_production_selected_sql_trace(&fixture.store);
    assert_eq!(cost.statement_count(), 0);
    assert!(matches!(
        result,
        SelectedResolutionOperationOpenOutcome::Cancelled
    ));
}

#[test]
fn unrelated_language_overlay_does_not_poison_selected_operation() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), "src/notes.py");
    assert!(overlay.set(file.abs_path(), "value = 1\n".to_owned()));

    let result = fixture
        .open_with_project(&overlay, &[], Vec::new(), &CancellationToken::default())
        .expect("unrelated overlay must not fail the store call");
    assert!(matches!(
        result,
        SelectedResolutionOperationOpenOutcome::Ready(_)
    ));
}

#[test]
fn selected_fragment_inventory_replaces_shadow_with_published_content_membership() {
    let fixture = ResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let baseline = fixture.open_ready(&[], Vec::new(), &cancellation);
    let baseline_by_path = baseline
        .mounts()
        .unwrap()
        .iter()
        .map(|mount| (mount.persisted_relative_path().to_owned(), mount.fragment()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(baseline_by_path.len(), 4);
    drop(baseline);

    let masks = fixture.parity_masks();
    let operation = fixture.open_parity_ready(&masks, &cancellation);
    let expected = operation
        .mounts()
        .unwrap()
        .iter()
        .map(SelectedResolutionOperationMount::fragment)
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 2);
    let provider = operation
        .ready
        .inventory
        .mount_record_for_path("java", PROVIDER_PATH)
        .unwrap()
        .unwrap();
    let expected_oid = Oid::hash_object(ObjectType::Blob, PROVIDER_JAVA_SOURCE.as_bytes()).unwrap();
    assert!(
        provider.file_version_id().is_none(),
        "replacement uses published content authority"
    );
    assert_eq!(provider.blob_oid(), expected_oid);
    let published_blob: i64 = operation
        .ready
        .inventory
        .connection()
        .query_row(
            "SELECT id FROM blobs WHERE blob_oid=?1 AND lang='java' AND generation=?2",
            params![expected_oid.to_string(), fixture.generation.get()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(provider.blob_id(), published_blob);
    assert!(
        operation
            .ready
            .inventory
            .mount_record_for_path("java", REMOVED_PATH)
            .unwrap()
            .is_none()
    );
    assert!(
        operation
            .ready
            .inventory
            .mount_record_for_path("java", SECOND_REPLACEMENT_PATH)
            .unwrap()
            .is_none()
    );
    let selected_masks = operation.ready.inventory.overlay_masks().unwrap();
    assert_eq!(selected_masks.len(), masks.len());
    assert!(
        selected_masks
            .iter()
            .any(|mask| mask.persisted_relative_path() == PROVIDER_PATH
                && mask.intent() == SelectedResolutionOverlayIntent::Replacement)
    );
    assert!(baseline_by_path.contains_key(PROVIDER_PATH));

    {
        let source = operation.ready.typed_source();
        let mut rows = Vec::new();
        let outcome = {
            let mut callback = |page: &[crate::analyzer::resolution::BindingFragmentId]| {
                rows.extend_from_slice(page);
                Ok(true)
            };
            let mut visitor = FactPageVisitor::new(&mut callback);
            source
                .visit_selected_fragment_pages(&cancellation, &mut visitor)
                .expect("composite membership read")
        };
        assert!(outcome.is_exhausted());
        rows.sort_unstable();
        let mut expected = expected.clone();
        expected.sort_unstable();
        assert_eq!(rows, expected);
        // A fragment is a mount ordinal, so a baseline fragment id cannot say
        // whether persisted membership leaked: both selections number their
        // own mounts from zero and the ids collide by construction. The
        // composite membership is exactly this selection's mounts, which the
        // comparison above states, and the masked paths are not among them.
        for path in [REMOVED_PATH, SECOND_REPLACEMENT_PATH] {
            assert!(
                operation
                    .mounts()
                    .unwrap()
                    .iter()
                    .all(|mount| mount.persisted_relative_path() != path),
                "masked persisted membership leaked for {path:?}"
            );
        }
    }
}

#[test]
fn persisted_and_transient_operations_match_preloaded_oracle_with_one_session_each() {
    let fixture = ResolutionOperationFixture::new();
    let masks = fixture.parity_masks();
    let cancellation = CancellationToken::default();
    let oracle_operation = fixture.open_parity_ready(&masks, &cancellation);
    let oracle = PreloadedOracle::from_operation(&fixture, &oracle_operation);
    assert_ne!(oracle.source_fragment, oracle.provider_fragment);
    drop(oracle_operation);

    let point_site = site_for_identifier(
        &fixture.source_facts,
        "method",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Callable,
    );
    let point_locator = locator(SOURCE_PATH, point_site, LoweredSemanticRole::Reference);
    let expected_point = oracle
        .service
        .resolve_reference(oracle.point_reference, &cancellation)
        .unwrap();
    let point_operation = fixture.open_parity_ready(&masks, &cancellation);
    let point_placements = contexts_for(&fixture, point_operation.mounts().unwrap());
    reset_selected_fact_operation_construction_count_for_test();
    let mut placement_metrics = SelectedResolutionContextMetrics;
    let point = point_operation
        .resolve_reference(
            point_placements,
            &point_locator,
            &cancellation,
            &mut placement_metrics,
        )
        .unwrap();
    assert_eq!(selected_fact_operation_construction_count_for_test(), 1);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(point)) = point
    else {
        panic!("selected point operation must return a native found answer")
    };
    assert_eq!(point, expected_point);
    assert!(
        !point
            .binding()
            .targets()
            .contains(&oracle.reverse_definition),
        "the collapsed schema intentionally has no cross-file Java root bridge before Milestone 5"
    );

    let definition_site = provider_method_site(&fixture.provider_facts);
    let definition_locator = locator(
        PROVIDER_PATH,
        definition_site,
        LoweredSemanticRole::Definition,
    );
    let expected_reverse = oracle
        .service
        .references_to(oracle.reverse_definition, &cancellation)
        .unwrap();
    let reverse_operation = fixture.open_parity_ready(&masks, &cancellation);
    let reverse_placements = contexts_for(&fixture, reverse_operation.mounts().unwrap());
    reset_selected_fact_operation_construction_count_for_test();
    let mut placement_metrics = SelectedResolutionContextMetrics;
    let mut reverse_metrics = FactReverseResolutionMetrics::default();
    let reverse = reverse_operation
        .references_to_selected_definition(
            reverse_placements,
            2,
            &definition_locator,
            &cancellation,
            &mut placement_metrics,
            &mut reverse_metrics,
        )
        .unwrap();
    assert_eq!(selected_fact_operation_construction_count_for_test(), 1);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(reverse)) =
        reverse
    else {
        panic!("selected reverse operation must return a native found answer")
    };
    assert_eq!(reverse.answer(), &expected_reverse);
    assert!(reverse_metrics.demanded_definition_count() > 0);
    assert!(reverse_metrics.published_reference_count() > 0);
    assert!(!reverse.references().contains(&oracle.point_reference));

    let mut expected_batches = Vec::new();
    let expected_summary = oracle
        .service
        .stage_all_reference_batches(2, &cancellation, &mut |batch| {
            expected_batches.push(batch.clone());
            Ok(())
        })
        .unwrap();
    let broad_operation = fixture.open_parity_ready(&masks, &cancellation);
    let broad_placements = contexts_for(&fixture, broad_operation.mounts().unwrap());
    let (stager, _) = RollbackStager::new();
    reset_selected_fact_operation_construction_count_for_test();
    let mut placement_metrics = SelectedResolutionContextMetrics;
    let broad = broad_operation
        .stage_selected_reference_batches(
            broad_placements,
            2,
            &cancellation,
            &mut placement_metrics,
            stager,
        )
        .unwrap();
    assert_eq!(selected_fact_operation_construction_count_for_test(), 1);
    let SelectedResolutionOperationOutcome::Native(broad) = broad else {
        panic!("selected broad operation must return a native publication")
    };
    assert_semantic_summary_eq(&broad.summary, &expected_summary);
    assert_eq!(
        canonical_broad_rows(&broad.batches),
        canonical_broad_rows(&expected_batches)
    );
    let fragments = broad
        .batches
        .iter()
        .map(FactReferenceBatchAnswer::fragment)
        .collect::<BTreeSet<_>>();
    assert!(fragments.contains(&oracle.source_fragment));
    assert!(fragments.contains(&oracle.provider_fragment));
}

#[test]
fn cancelled_or_final_stale_broad_attempt_rolls_back_and_retries_exactly() {
    let fixture = ResolutionOperationFixture::new();
    let masks = fixture.parity_masks();
    let oracle_token = CancellationToken::default();
    let oracle_operation = fixture.open_parity_ready(&masks, &oracle_token);
    let oracle = PreloadedOracle::from_operation(&fixture, &oracle_operation);
    drop(oracle_operation);
    let mut expected_batches = Vec::new();
    let expected_summary = oracle
        .service
        .stage_all_reference_batches(2, &oracle_token, &mut |batch| {
            expected_batches.push(batch.clone());
            Ok(())
        })
        .unwrap();

    let stale_token = CancellationToken::default();
    let stale_operation = fixture.open_parity_ready(&masks, &stale_token);
    let stale_placements = contexts_for(&fixture, stale_operation.mounts().unwrap());
    let generation = fixture.project.generation_handle();
    let (stale_stager, stale_state) = RollbackStager::with_first_stage_hook(Box::new(move || {
        generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }));
    let mut metrics = SelectedResolutionContextMetrics;
    let stale = stale_operation
        .stage_selected_reference_batches(
            stale_placements,
            2,
            &stale_token,
            &mut metrics,
            stale_stager,
        )
        .unwrap();
    assert!(matches!(
        stale,
        SelectedResolutionOperationOutcome::Stale(
            SelectedResolutionStale::TransientAnalysisGeneration {
                expected: 0,
                actual: 1
            }
        )
    ));
    assert_eq!(stale_state.borrow().rollback_count, 1);
    assert_eq!(stale_state.borrow().publish_count, 0);
    assert!(stale_state.borrow().staged.is_empty());

    let retry_token = CancellationToken::default();
    let retry_operation = fixture.open_parity_ready(&masks, &retry_token);
    let retry_placements = contexts_for(&fixture, retry_operation.mounts().unwrap());
    let (retry_stager, retry_state) = RollbackStager::new();
    let mut metrics = SelectedResolutionContextMetrics;
    let retry = retry_operation
        .stage_selected_reference_batches(
            retry_placements,
            2,
            &retry_token,
            &mut metrics,
            retry_stager,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(retry) = retry else {
        panic!("unchanged retry after final stale must publish natively")
    };
    assert_eq!(retry_state.borrow().rollback_count, 0);
    assert_eq!(retry_state.borrow().publish_count, 1);
    assert_semantic_summary_eq(&retry.summary, &expected_summary);
    assert_eq!(
        canonical_broad_rows(&retry.batches),
        canonical_broad_rows(&expected_batches)
    );

    let cancelled_token = CancellationToken::default();
    let cancelled_operation = fixture.open_parity_ready(&masks, &cancelled_token);
    let cancelled_placements = contexts_for(&fixture, cancelled_operation.mounts().unwrap());
    let cancellation_trigger = cancelled_token.clone();
    let (cancelled_stager, cancelled_state) =
        RollbackStager::with_first_stage_hook(Box::new(move || {
            cancellation_trigger.cancel();
            Ok(())
        }));
    let mut metrics = SelectedResolutionContextMetrics;
    let cancelled = cancelled_operation
        .stage_selected_reference_batches(
            cancelled_placements,
            2,
            &cancelled_token,
            &mut metrics,
            cancelled_stager,
        )
        .unwrap();
    assert!(matches!(
        cancelled,
        SelectedResolutionOperationOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled_state.borrow().rollback_count, 1);
    assert_eq!(cancelled_state.borrow().publish_count, 0);
    assert!(cancelled_state.borrow().staged.is_empty());

    let cancellation_retry_token = CancellationToken::default();
    let cancellation_retry_operation = fixture.open_parity_ready(&masks, &cancellation_retry_token);
    let cancellation_retry_placements =
        contexts_for(&fixture, cancellation_retry_operation.mounts().unwrap());
    let (cancellation_retry_stager, cancellation_retry_state) = RollbackStager::new();
    let mut metrics = SelectedResolutionContextMetrics;
    let cancellation_retry = cancellation_retry_operation
        .stage_selected_reference_batches(
            cancellation_retry_placements,
            2,
            &cancellation_retry_token,
            &mut metrics,
            cancellation_retry_stager,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(cancellation_retry) = cancellation_retry else {
        panic!("unchanged retry after cancellation must publish natively")
    };
    assert_eq!(cancellation_retry_state.borrow().rollback_count, 0);
    assert_eq!(cancellation_retry_state.borrow().publish_count, 1);
    assert_semantic_summary_eq(&cancellation_retry.summary, &expected_summary);
    assert_eq!(
        canonical_broad_rows(&cancellation_retry.batches),
        canonical_broad_rows(&expected_batches)
    );
}

#[test]
fn fallback_is_whole_operation_only_for_unavailable_or_stale() {
    let fixture = ResolutionOperationFixture::new();
    let effects = Rc::new(RefCell::new(Vec::new()));
    let cancellation = CancellationToken::default();
    let empty_snapshots = WorkspaceSnapshots::default();
    let empty_masks = Vec::new();
    let initial_unavailable = fixture
        .store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                &fixture.project,
                &fixture.workspace_id,
                &empty_snapshots,
                &fixture.languages,
                &empty_masks,
            ),
            &cancellation,
        )
        .unwrap();
    let unavailable_effects = Rc::clone(&effects);
    let initial_unavailable = initial_unavailable
        .with_legacy(&cancellation, move || {
            unavailable_effects.borrow_mut().push("initial-unavailable");
            Ok(11_usize)
        })
        .unwrap();
    assert!(matches!(
        initial_unavailable,
        SelectedResolutionOperationOpenResult::Legacy {
            value: 11,
            reason: SelectedResolutionFallbackReason::Unavailable(
                SelectedResolutionUnavailable::MissingWorkspaceSnapshot { .. }
            )
        }
    ));

    let stale_masks = fixture.parity_masks();
    let stale_input = SelectedResolutionOperationInput::new(
        &fixture.project,
        &fixture.workspace_id,
        &fixture.snapshots,
        &fixture.languages,
        &stale_masks,
    )
    .with_content_mounts(vec![fixture.counterfactual_content(
        PROVIDER_PATH,
        RICH_JAVA_SOURCE,
        PROVIDER_JAVA_SOURCE,
    )]);
    fixture.project.advance();
    let initial_stale = fixture
        .store
        .open_selected_resolution_operation(stale_input, &cancellation)
        .unwrap();
    let stale_effects = Rc::clone(&effects);
    let initial_stale = initial_stale
        .with_legacy(&cancellation, move || {
            stale_effects.borrow_mut().push("initial-stale");
            Ok(12_usize)
        })
        .unwrap();
    assert!(matches!(
        initial_stale,
        SelectedResolutionOperationOpenResult::Legacy {
            value: 12,
            reason: SelectedResolutionFallbackReason::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: 0,
                    actual: 1
                }
            )
        }
    ));

    let final_stale_operation = fixture.open_parity_ready(&stale_masks, &cancellation);
    let final_stale_placements = contexts_for(&fixture, final_stale_operation.mounts().unwrap());
    let generation = fixture.project.generation_handle();
    let (final_stale_stager, final_stale_state) =
        CountRollbackStager::with_first_stage_hook(Box::new(move || {
            generation.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
    let mut metrics = SelectedResolutionContextMetrics;
    let final_stale = final_stale_operation.stage_selected_reference_batches(
        final_stale_placements,
        2,
        &cancellation,
        &mut metrics,
        final_stale_stager,
    );
    let final_stale_effects = Rc::clone(&effects);
    let observed_final_stale_state = Rc::clone(&final_stale_state);
    let final_stale = dispatch_usize(final_stale, &cancellation, move || {
        let state = observed_final_stale_state.borrow();
        assert_eq!(state.rollback_count, 1);
        assert_eq!(state.publish_count, 0);
        assert!(state.staged.is_empty());
        drop(state);
        final_stale_effects.borrow_mut().push("final-stale");
        Ok(13)
    })
    .unwrap();
    assert!(matches!(
        final_stale,
        SelectedResolutionOperationResult::Legacy {
            value: 13,
            reason: SelectedResolutionFallbackReason::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: 1,
                    actual: 2
                }
            )
        }
    ));

    let cancelled_token = CancellationToken::default();
    let cancelled_operation = fixture.open_parity_ready(&stale_masks, &cancelled_token);
    let cancelled_placements = contexts_for(&fixture, cancelled_operation.mounts().unwrap());
    let cancellation_trigger = cancelled_token.clone();
    let (cancelled_stager, cancelled_state) =
        CountRollbackStager::with_first_stage_hook(Box::new(move || {
            cancellation_trigger.cancel();
            Ok(())
        }));
    let mut metrics = SelectedResolutionContextMetrics;
    let cancelled = cancelled_operation.stage_selected_reference_batches(
        cancelled_placements,
        2,
        &cancelled_token,
        &mut metrics,
        cancelled_stager,
    );
    let cancelled_effects = Rc::clone(&effects);
    let cancelled = dispatch_usize(cancelled, &cancelled_token, move || {
        cancelled_effects.borrow_mut().push("forbidden-cancelled");
        Ok(14)
    })
    .unwrap();
    assert!(matches!(
        cancelled,
        SelectedResolutionOperationResult::Cancelled(_)
    ));
    assert_eq!(cancelled_state.borrow().rollback_count, 1);
    assert_eq!(cancelled_state.borrow().publish_count, 0);

    let error_token = CancellationToken::default();
    let error_operation = fixture.open_parity_ready(&stale_masks, &error_token);
    let error_placements = contexts_for(&fixture, error_operation.mounts().unwrap());
    let (error_stager, error_state) = CountRollbackStager::with_first_stage_hook(Box::new(|| {
        Err(StoreError::new("injected broad staging failure"))
    }));
    let mut metrics = SelectedResolutionContextMetrics;
    let error_attempt = error_operation.stage_selected_reference_batches(
        error_placements,
        2,
        &error_token,
        &mut metrics,
        error_stager,
    );
    let error_effects = Rc::clone(&effects);
    let error = dispatch_usize(error_attempt, &error_token, move || {
        error_effects.borrow_mut().push("forbidden-error");
        Ok(15)
    });
    let error = match error {
        Err(error) => error,
        Ok(_) => panic!("store errors are direct and cannot authorize legacy"),
    };
    assert!(error.to_string().contains("injected broad staging failure"));
    assert_eq!(error_state.borrow().rollback_count, 1);
    assert_eq!(error_state.borrow().publish_count, 0);

    let native_token = CancellationToken::default();
    let native_operation = fixture.open_parity_ready(&stale_masks, &native_token);
    let native_placements = contexts_for(&fixture, native_operation.mounts().unwrap());
    let (native_stager, native_state) =
        CountRollbackStager::with_first_stage_hook(Box::new(|| Ok(())));
    let mut metrics = SelectedResolutionContextMetrics;
    let native = native_operation.stage_selected_reference_batches(
        native_placements,
        2,
        &native_token,
        &mut metrics,
        native_stager,
    );
    let native_effects = Rc::clone(&effects);
    let native = dispatch_usize(native, &native_token, move || {
        native_effects.borrow_mut().push("forbidden-native");
        Ok(16)
    })
    .unwrap();
    assert!(matches!(
        native,
        SelectedResolutionOperationResult::Native(reference_count) if reference_count > 0
    ));
    assert_eq!(native_state.borrow().rollback_count, 0);
    assert_eq!(native_state.borrow().publish_count, 1);
    assert_eq!(
        effects.borrow().as_slice(),
        ["initial-unavailable", "initial-stale", "final-stale"]
    );
}

fn only_rust_point_answer<T>(
    mut answers: Vec<SelectedRustReferenceAnswer<T>>,
) -> SelectedRustReferenceAnswer<T> {
    assert_eq!(
        answers.len(),
        1,
        "this fixture names one semantic reference"
    );
    answers.pop().expect("one semantic reference")
}

impl SelectedResolutionOperation<'_, '_> {
    fn rust_test_crate_context(
        &self,
        profile: RustCallerTargetProfile,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustFileContextOutcome> {
        let root = if profile.target_kind == RustCallerTargetKind::Detached {
            profile.target_root.clone()
        } else {
            profile
                .manifest_path
                .parent()
                .expect("manifest directory")
                .join(&profile.target_root)
        };
        self.rust_context_for_file(&root, cancellation)
    }
}

#[test]
fn rust_crate_point_context_does_not_prepare_workspace_profiles() {
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let owner = fixture.open_ready(&cancellation);
    let keys = owner
        .rust_crate_keys_for_file(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
        .unwrap();
    assert_eq!(keys.len(), 1);
    let SelectedRustContextOutcome::Ready(context) = owner
        .rust_crate_context(
            crate::analyzer::resolution::SelectedContextIdentities::new(),
            keys[0],
            owner.mounts().unwrap(),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("crate context should be ready");
    };
    let site = site_for_identifier(
        &fixture.consumer_facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let locator = SelectedSemanticLocator::new(
        "rust",
        RUST_ROOT_CONSUMER_PATH,
        site,
        LoweredSemanticRole::Reference,
    );
    let mut context_metrics = SelectedResolutionContextMetrics;
    let outcome = owner
        .resolve_rust_reference(context, &locator, &cancellation, &mut context_metrics)
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answers)) =
        outcome
    else {
        panic!("native point answer");
    };
    assert!(
        answers.iter().any(|answer| answer.definitions.len() == 1),
        "crate rows must connect the imported alias to its definition"
    );
}

fn active_macro_capsules(operation: &SelectedResolutionOperation<'_, '_>) -> Vec<(u32, u32)> {
    operation.ready.inventory.connection()
        .prepare("SELECT p.host_ordinal,a.invocation FROM temp.selected_resolution_stage_producers p JOIN temp.selected_resolution_admissions a USING(admission_id) WHERE a.input_kind=1 ORDER BY p.host_ordinal,a.invocation")
        .unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?))).unwrap()
        .collect::<rusqlite::Result<Vec<_>>>().unwrap()
}

#[test]
fn actual_macro_frontier_closures_preserve_unrelated_gap_reasons() {
    fn definition_source(index: usize) -> String {
        if index == 0 {
            "macro_rules! unmatched { (yes) => {} }\nmacro_rules! empty { ($value:expr) => {} }\n"
                .to_owned()
        } else {
            default_scale_source(index)
        }
    }
    for (closed_name, source) in [
        (
            "unmatched",
            "#[macro_use] mod scale_0000;\nunmatched!(no);\nunknown!(Missing);\n",
        ),
        (
            "empty",
            "#[macro_use] mod scale_0000;\nempty!(7);\nunknown!(Missing);\n",
        ),
        (
            "include",
            "include!(\"scale_0000.rs\");\nunknown!(Missing);\n",
        ),
    ] {
        let mut fixture =
            RustRootResolutionOperationFixture::new_with_scale_sources(4, 0, "", definition_source);
        fixture.replace_persisted_consumer_source(source);
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        assert!(
            operation
                .ensure_selected_rust_inputs(&cancellation)
                .unwrap()
        );
        let host = operation
            .ready
            .inventory
            .mount_record_for_path("rust", RUST_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let inputs = crate::analyzer::rust::source_storage::read_rust_macro_input_rows(
            operation.ready.inventory.connection(),
            host.blob_id(),
            &|| true,
        )
        .unwrap()
        .unwrap();
        let lexical = operation.ready.lexical_source();
        let mut expected = BTreeMap::new();
        for input in inputs {
            let (start,name): (usize,String) = operation.ready.inventory.connection().query_row(
                "SELECT start_byte,macro_name FROM source_rust_macro_invocations WHERE blob_id=?1 AND occurrence_id=?2",
                params![host.blob_id(),input.invocation.get()],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
            if name != closed_name && name != "unknown" {
                continue;
            }
            let (site, _) = input
                .native_frontier
                .expect("real invocation has a structured native gap");
            let reasons = lexical
                .unsupported_gap_reasons(host.ordinal(), site, &cancellation)
                .unwrap()
                .unwrap();
            assert!(
                !reasons.is_empty(),
                "{name} must have actual native gap evidence"
            );
            expected.insert(
                name.clone(),
                ResolutionCompletion::incomplete(
                    reasons
                        .into_iter()
                        .map(ResolutionIncompleteReason::UnsupportedSemantic),
                ),
            );
            if name == "unmatched" {
                assert_eq!(
                    operation
                        .match_selected_textual_macro(
                            Path::new(RUST_ROOT_CONSUMER_PATH),
                            start,
                            input.tree.start_byte,
                            &name,
                            &cancellation
                        )
                        .unwrap(),
                    Some(Err(
                        brokk_bifrost_rust::macro_matcher::MacroMatchError::NoArmMatched
                    ))
                );
            } else if name == "empty" {
                let Some(Ok(arm)) = operation
                    .match_selected_textual_macro(
                        Path::new(RUST_ROOT_CONSUMER_PATH),
                        start,
                        input.tree.start_byte,
                        &name,
                        &cancellation,
                    )
                    .unwrap()
                else {
                    panic!("actual structured empty arm matches");
                };
                let facts = brokk_bifrost_rust::macro_matcher::lower_selected_macro_input(
                    &input.tree,
                    &arm,
                    brokk_bifrost_rust::macro_matcher::RustMacroItemContainer::Lexical,
                );
                assert!(
                    facts.identifiers.is_empty()
                        && facts.gaps.is_empty()
                        && facts.reference_enumeration_gaps.is_empty()
                );
                let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                    host.fragment_id(),
                    &operation.ready.shared_names(),
                    Language::Rust,
                    &facts,
                );
                eprintln!("literal input complete lowered artifact census: {artifact:#?}");
            } else if name == "include" {
                let included: String = operation
                    .ready
                    .inventory
                    .connection()
                    .query_row(
                        rust_crate_context::MACRO_INCLUDE_STARTS,
                        [RUST_ROOT_CONSUMER_PATH],
                        |row| row.get(1),
                    )
                    .expect("actual selected include edge is placed");
                assert_eq!(included, "app/src/scale_0000.rs");
            }
        }
        assert_eq!(
            expected.len(),
            2,
            "both real invocations have exact evidence: {expected:?}"
        );
        assert!(matches!(
            operation
                .prepare_selected_macro_frontiers(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
                .unwrap(),
            SelectedResolutionStageOutcome::Ready
        ));
        assert_eq!(
            active_macro_capsules(&operation).len(),
            usize::from(closed_name == "empty"),
            "matched literal input preserves normal capsule publication; no-arm/include use source closure"
        );
        assert_eq!(
            lexical
                .close_completion(&expected[closed_name], &cancellation)
                .unwrap()
                .unwrap(),
            ResolutionCompletion::Complete,
            "{closed_name} closes its exact frontier"
        );
        assert_eq!(
            lexical
                .close_completion(&expected["unknown"], &cancellation)
                .unwrap()
                .unwrap(),
            expected["unknown"],
            "unresolved invocation evidence remains unchanged"
        );
    }
}

#[test]
fn generated_head_pair_preserves_actual_ordinary_definition_authority() {
    let fixture = RustRootResolutionOperationFixture::new();
    let live = CancellationToken::new();
    let operation = fixture.open_ready(&live);
    let host = operation
        .ready
        .inventory
        .mount_record_for_path("rust", RUST_ROOT_CONSUMER_PATH)
        .unwrap()
        .unwrap();
    let connection = operation.ready.inventory.connection();
    let semantic = |role: &str| {
        let key: u32 = connection.query_row("SELECT site.semantic_key FROM resolution_semantic_sites site JOIN resolution_semantic_catalog catalog ON catalog.blob_id=site.blob_id AND catalog.local_key=site.semantic_key WHERE site.blob_id=?1 AND site.semantic_role=?2 AND catalog.shared_identity IS NULL ORDER BY site.semantic_key LIMIT 1",params![host.blob_id(),role],|row|row.get(0)).unwrap();
        SemanticId::local(host.ordinal().get(), key)
    };
    let reference = semantic("reference");
    let definition = semantic("definition");
    let source = operation.ready.lexical_source();
    let seeds = source
        .lookup_reference_seeds(&[ResolutionQuery::new(reference)], &live)
        .unwrap();
    let reference_node = seeds.rows()[0].seed().unwrap().node();
    let definition_node = source
        .lookup_definition_node(definition, &live)
        .unwrap()
        .unwrap();
    let before = source
        .classify_endpoint_nodes(&[definition_node], &live)
        .unwrap();
    let stage =
        super::super::resolution_stage::SelectedResolutionStage::new(&operation.ready.inventory);
    assert_eq!(
        stage
            .admit_macro_head_pair(
                &host,
                reference,
                reference_node,
                &host,
                definition,
                definition_node,
                &live
            )
            .unwrap(),
        Some(())
    );
    assert_eq!(
        source.lookup_definition_node(definition, &live).unwrap(),
        Some(definition_node)
    );
    assert_eq!(
        source
            .classify_endpoint_nodes(&[definition_node], &live)
            .unwrap(),
        before
    );
}

#[test]
fn rust_macro_frontiers_only_prepare_the_demanded_file() {
    let mut fixture = RustRootResolutionOperationFixture::new_with_scale_sources(
        4,
        0,
        "",
        macro_definition_scale_source,
    );
    fixture.replace_persisted_consumer_source(RUST_MACRO_CONSUMER_SOURCE);
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    assert!(matches!(
        operation
            .prepare_selected_macro_frontiers(Path::new(RUST_ROOT_PROVIDER_PATH), &cancellation,)
            .unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));
    assert!(!operation.ready.macro_overlay.borrow().prepared);
    assert!(operation.ready.prepared_macro_files.borrow().is_empty());
    assert!(matches!(
        operation
            .prepare_selected_macro_frontiers(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation,)
            .unwrap(),
        SelectedResolutionStageOutcome::Ready
    ));
    let consumer = operation
        .mounts()
        .unwrap()
        .iter()
        .find(|mount| mount.persisted_relative_path() == RUST_ROOT_CONSUMER_PATH)
        .unwrap()
        .fragment();
    assert!(
        operation.ready.macro_overlay.borrow().prepared,
        "demanded macro file was prepared"
    );
    let admitted = active_macro_capsules(&operation);
    assert!(
        !admitted.is_empty(),
        "the demanded input has an active capsule"
    );
    assert!(admitted.iter().all(|(host, _)| *host == consumer.ordinal()));
    assert_eq!(
        *operation.ready.prepared_macro_files.borrow(),
        [PathBuf::from(RUST_ROOT_CONSUMER_PATH)]
            .into_iter()
            .collect::<HashSet<_>>()
    );
}

const RUST_FIELD_OWNER_SOURCE: &str = concat!(
    "pub struct Config {\n",
    "    pub font: FontConfig,\n",
    "}\n",
    "pub struct FontConfig {\n",
    "    pub mono_family: String,\n",
    "}\n",
);

/// The receiver type is written as a bare module prefix, so the route needs
/// the name the prefix is spelled with.
const RUST_FIELD_CALLER_BARE_PREFIX: &str = concat!(
    "pub fn mono_family(cfg: &scale_0000::Config) -> String {\n",
    "    cfg.font.mono_family.clone()\n",
    "}\n",
);

/// The same access with a `crate`-anchored receiver type, which needs no
/// prefix name. It is the control for the bare-prefix case.
const RUST_FIELD_CALLER_CRATE_ANCHORED: &str = concat!(
    "pub fn mono_family(cfg: &crate::scale_0000::Config) -> String {\n",
    "    cfg.font.mono_family.clone()\n",
    "}\n",
);

fn field_owner_scale_source(index: usize) -> String {
    if index == 0 {
        RUST_FIELD_OWNER_SOURCE.to_owned()
    } else {
        default_scale_source(index)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RustFieldPointAnswer {
    definitions: Vec<String>,
    completion: String,
}

/// One answer's completion, named so that two selections' answers compare.
///
/// A local reason is its mount's ordinal and the position it occupies in that
/// mount's catalog. The ordinal is the selection's own -- a selection that
/// mounts a replacement gives the same blob a different one -- so a rendering
/// that carries it says two identical answers differ. The blob is what the
/// two selections agree on, so a local reason is named by its mount's
/// persisted path and its catalog position, and every other reason by itself.
fn describe_completion(mount_paths: &[(u32, String)], completion: &ResolutionCompletion) -> String {
    let path_of = |semantic: SemanticId| {
        let ordinal = semantic.ordinal()?;
        mount_paths
            .iter()
            .find(|(mount, _)| *mount == ordinal)
            .map(|(_, path)| path.clone())
    };
    match completion {
        ResolutionCompletion::Complete => "complete".to_owned(),
        ResolutionCompletion::Incomplete(reasons) => reasons
            .iter()
            .map(|reason| match reason {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                    match (path_of(*semantic), semantic.local_key()) {
                        (Some(path), Some(key)) => {
                            format!("UnsupportedSemantic({path}#{key})")
                        }
                        _ => format!("{reason:?}"),
                    }
                }
                _ => format!("{reason:?}"),
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// Resolve one field reference in `reference_path` with every path in
/// `replaced` published and mounted as a replacement of its own byte-identical
/// disk content.
fn rust_field_point_answer(
    fixture: &RustRootResolutionOperationFixture,
    replaced: &[&str],
    reference_path: &str,
    field: &str,
    cancellation: &CancellationToken,
) -> RustFieldPointAnswer {
    let read = |path: &str| {
        ProjectFile::new(fixture._project_root.path(), path)
            .read_to_string()
            .expect("read selected Rust fixture source")
    };
    let states = replaced
        .iter()
        .map(|path| {
            let source = read(path);
            let (state, _) = parsed_operation_source_state(
                fixture._project_root.path(),
                path,
                &source,
                &RustAdapter,
            );
            ((*path).to_owned(), source, state)
        })
        .collect::<Vec<_>>();
    let masks = replaced
        .iter()
        .map(|path| SelectedResolutionOverlayMask::replacement("rust", *path))
        .collect::<Vec<_>>();
    let content_mounts = states
        .iter()
        .map(|(path, source, state)| {
            fixture
                .publish_content(path, source, state, cancellation)
                .with_counterfactual_base_content_digest(
                    brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes()),
                )
        })
        .collect::<Vec<_>>();
    let reference_source = read(reference_path);
    let (_, reference_facts) = parsed_operation_source_state(
        fixture._project_root.path(),
        reference_path,
        &reference_source,
        &RustAdapter,
    );
    let site = site_for_identifier(
        &reference_facts,
        field,
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let range = reference_facts
        .sites
        .iter()
        .find(|candidate| candidate.id == site)
        .expect("selected Rust field reference range");
    let operation = fixture.open_content_selected(&masks, content_mounts, cancellation);
    // Captured before the operation is consumed: a local reason names its
    // mount by ordinal and this selection's ordinals are its own.
    let mount_paths = operation
        .mounts()
        .unwrap()
        .iter()
        .map(|mount| {
            (
                mount.ordinal().get(),
                mount.persisted_relative_path().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), cancellation)
        .expect("build selected Rust field point context")
    else {
        panic!("an uncancelled field point context must be ready")
    };
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answers)) =
        operation
            .resolve_rust_reference(
                *context,
                &SelectedSemanticLocator::for_reference_range(
                    "rust",
                    reference_path,
                    range.start_byte,
                    range.end_byte,
                ),
                cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .expect("resolve the selected Rust field reference")
    else {
        panic!("a positioned field reference must publish one native answer")
    };
    let answer = only_rust_point_answer(answers);
    RustFieldPointAnswer {
        definitions: answer
            .definitions
            .iter()
            .map(|unit| unit.fq_name())
            .collect(),
        completion: describe_completion(&mount_paths, answer.resolution.completion()),
    }
}

/// An open document lowered as a transient mount answers a field access
/// exactly as the same bytes on disk answer it.
///
/// The discriminator is the bare route prefix. A replacement has no persisted
/// interior, so the persisted lexical source could not name any of its
/// references; every bare prefix in an open buffer was therefore unnamed and
/// never reached its crate row, and `cfg.font` resolved to nothing that the
/// same bytes on disk resolved exactly. The `crate`-anchored spelling needs no
/// prefix name and is the control: it answered correctly on both sides before
/// the fix and must keep doing so.
#[test]
fn selected_rust_dirty_buffer_answers_a_field_as_the_persisted_file_does() {
    let cancellation = CancellationToken::default();
    for (spelling, caller) in [
        ("bare prefix", RUST_FIELD_CALLER_BARE_PREFIX),
        ("crate anchored", RUST_FIELD_CALLER_CRATE_ANCHORED),
    ] {
        let fixture = RustRootResolutionOperationFixture::new_with_scale_sources(
            4,
            0,
            caller,
            field_owner_scale_source,
        );
        let persisted = rust_field_point_answer(
            &fixture,
            &[],
            RUST_ROOT_CONSUMER_PATH,
            "font",
            &cancellation,
        );
        assert_eq!(
            persisted.definitions,
            ["app.scale_0000.Config.font"],
            "{spelling}: the persisted file resolves the field: {persisted:#?}"
        );
        let dirty = rust_field_point_answer(
            &fixture,
            &[RUST_ROOT_CONSUMER_PATH],
            RUST_ROOT_CONSUMER_PATH,
            "font",
            &cancellation,
        );
        assert_eq!(
            persisted, dirty,
            "{spelling}: a byte-identical replacement must answer as its persisted file does"
        );
        // The second hop, `cfg.font.mono_family`. Its receiver type is
        // `FontConfig`, the declared type of a field in the persisted owner
        // file, so no part of it is the open buffer's. Whatever the route
        // answers, the replacement must answer the same: this is what says
        // `issue_693_profile`'s remaining hover failure is not a transient
        // mount's blindness.
        let persisted_second = rust_field_point_answer(
            &fixture,
            &[],
            RUST_ROOT_CONSUMER_PATH,
            "mono_family",
            &cancellation,
        );
        let dirty_second = rust_field_point_answer(
            &fixture,
            &[RUST_ROOT_CONSUMER_PATH],
            RUST_ROOT_CONSUMER_PATH,
            "mono_family",
            &cancellation,
        );
        assert_eq!(
            persisted_second, dirty_second,
            "{spelling}: the second field hop must answer alike on both sides"
        );
    }
}

const RUST_MACRO_DEFINITION_SOURCE: &str = concat!(
    "macro_rules! dispatch {\n",
    "    ($($path:ident)::* ($dt:expr) ($($args:expr),*)) => {{\n",
    "        match $dt {\n",
    "            0 => $($path)::*::<i8>($($args),*),\n",
    "            _ => $($path)::*::<i16>($($args),*),\n",
    "        }\n",
    "    }};\n",
    "}\n",
);

/// Lane IV's fixture shape: the macro is declared in one file and invoked in
/// expression position in another, with the invocation's arguments naming
/// declarations of the invoking file.
const RUST_MACRO_CONSUMER_SOURCE: &str = concat!(
    "#[macro_use]\n",
    "mod scale_0000;\n",
    "pub struct Tensor;\n",
    "impl Tensor {\n",
    "    pub fn datum_type(&self) -> u8 { 0 }\n",
    "}\n",
    "pub fn permute<T>(_dt: u8, _t: &Tensor) {}\n",
    "pub fn caller(t: &Tensor) {\n",
    "    let _x = dispatch!(permute(t.datum_type())(t));\n",
    "}\n",
);

fn macro_definition_scale_source(index: usize) -> String {
    if index == 0 {
        RUST_MACRO_DEFINITION_SOURCE.to_owned()
    } else {
        default_scale_source(index)
    }
}

/// Resolve `permute` inside the macro invocation, with `replacement` mounted
/// as published counterfactual content of the consumer when it is `Some`.
fn rust_macro_point_answer(
    fixture: &RustRootResolutionOperationFixture,
    replacement: Option<&str>,
    cancellation: &CancellationToken,
) -> RustFieldPointAnswer {
    let disk = ProjectFile::new(fixture._project_root.path(), RUST_ROOT_CONSUMER_PATH)
        .read_to_string()
        .expect("read the macro consumer source");
    let source = replacement.unwrap_or(&disk);
    let (state, facts) = parsed_operation_source_state(
        fixture._project_root.path(),
        RUST_ROOT_CONSUMER_PATH,
        source,
        &RustAdapter,
    );
    let masks = replacement
        .map(|_| {
            vec![SelectedResolutionOverlayMask::replacement(
                "rust",
                RUST_ROOT_CONSUMER_PATH,
            )]
        })
        .unwrap_or_default();
    let replacements = replacement
        .map(|source| {
            vec![fixture.publish_counterfactual_content(
                RUST_ROOT_CONSUMER_PATH,
                source,
                &state,
                cancellation,
            )]
        })
        .unwrap_or_default();
    let site = site_for_identifier(
        &facts,
        "permute",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let range = facts
        .sites
        .iter()
        .find(|candidate| candidate.id == site)
        .expect("macro argument reference range");
    let operation = fixture.open_content_selected(&masks, replacements, cancellation);
    // Captured before the operation is consumed: a local reason names its
    // mount by ordinal and this selection's ordinals are its own.
    let mount_paths = operation
        .mounts()
        .unwrap()
        .iter()
        .map(|mount| {
            (
                mount.ordinal().get(),
                mount.persisted_relative_path().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let SelectedRustFileContextOutcome::Ready { context, .. } = operation
        .rust_test_crate_context(fixture.profile.clone(), cancellation)
        .expect("build the macro point context")
    else {
        panic!("an uncancelled macro point context must be ready")
    };
    match operation
        .resolve_rust_reference(
            *context,
            &SelectedSemanticLocator::for_reference_range(
                "rust",
                RUST_ROOT_CONSUMER_PATH,
                range.start_byte,
                range.end_byte,
            ),
            cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .expect("resolve the macro argument reference")
    {
        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answers)) => {
            let answer = only_rust_point_answer(answers);
            RustFieldPointAnswer {
                definitions: answer
                    .definitions
                    .iter()
                    .map(|unit| unit.fq_name())
                    .collect(),
                completion: describe_completion(&mount_paths, answer.resolution.completion()),
            }
        }
        _ => RustFieldPointAnswer {
            definitions: Vec::new(),
            completion: "not located".to_owned(),
        },
    }
}

/// A byte-identical replacement uses the persisted macro capsule; an edited
/// one does not.
///
/// The capsule -- the parsed macro definitions, invocations and inputs a blob
/// publishes -- is a pure function of the blob's bytes, so a replacement whose
/// content OID equals the persisted blob's may use it and answers exactly as
/// the file on disk does. An edited replacement's bytes are different bytes:
/// it keeps skipping the capsule, so the invocation's gap stays open. The
/// third assertion is what stops this pin going vacuous if the capsule ever
/// stops mattering here.
/// A crate stage's macro overlay is dropped with the stage, registrations and
/// all, and the next stage builds its own.
///
/// This is the mechanism behind the `OnceLock` removal. The overlay used to be
/// prepared once per operation, so only the first crate stage with a macro host
/// ever got capsules (lane MD, lane MW); dropping it per stage without dropping
/// what it registered is what failed tract's warm `usage_graph` after 17 crate
/// stages with "cannot classify unknown preloaded endpoint" (lane MW), because
/// only the overlay's own service can answer for those identities.
///
/// The property is both halves at once: after the drop the operation's
/// identity inventory holds exactly what it held before the overlay existed,
/// and a second preparation builds the same overlay again rather than finding
/// the slot taken.
#[test]
fn a_crate_stage_s_macro_overlay_is_dropped_with_everything_it_registered() {
    let mut fixture = RustRootResolutionOperationFixture::new_with_scale_sources(
        4,
        0,
        "",
        macro_definition_scale_source,
    );
    fixture.replace_persisted_consumer_source(RUST_MACRO_CONSUMER_SOURCE);
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let connection = operation.ready.inventory.connection();
    let active_rows = || {
        connection.query_row(
        "SELECT (SELECT count(*) FROM temp.selected_resolution_stage_producers),(SELECT count(*) FROM temp.selected_resolution_stage_nodes),(SELECT count(*) FROM temp.selected_resolution_stage_paths),(SELECT count(*) FROM temp.selected_resolution_stage_semantic_coordinates),(SELECT count(*) FROM temp.selected_resolution_stage_node_coordinates),(SELECT count(*) FROM temp.selected_resolution_stage_path_coordinates),(SELECT count(*) FROM temp.selected_resolution_stage_variable_coordinates),(SELECT count(*) FROM temp.selected_resolution_stage_closed_reasons)", [],
        |row| Ok([row.get::<_,i64>(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?])).unwrap()
    };
    let counters = || {
        connection.prepare("SELECT host_ordinal,domain,next_key FROM temp.selected_resolution_stage_allocation_counters ORDER BY host_ordinal,domain").unwrap()
        .query_map([],|row| Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    };
    assert_eq!(active_rows(), [0; 8]);
    let prepare = || {
        assert!(matches!(
            operation
                .prepare_selected_macro_frontiers(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
                .unwrap(),
            SelectedResolutionStageOutcome::Ready
        ));
        active_macro_capsules(&operation)
    };
    let first = prepare();
    assert!(!first.is_empty(), "the capsule is admitted");
    let populated = active_rows();
    assert!(
        populated[0] > 0 && populated[1] > 0 && populated[2] > 0 && populated[3] > 0,
        "actual producer facts and identity coordinates exist: {populated:?}"
    );
    let allocated = counters();
    assert!(!allocated.is_empty());
    let admitted: i64 = connection
        .query_row(
            "SELECT count(*) FROM temp.selected_resolution_admissions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    operation.clear_selected_macro_overlay().unwrap();
    assert!(!operation.ready.macro_overlay.borrow().prepared);
    assert_eq!(
        active_rows(),
        [0; 8],
        "stage teardown removes facts and every producer-owned coordinate"
    );
    assert_eq!(
        counters(),
        allocated,
        "committed coordinate counters never rewind"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM temp.selected_resolution_admissions",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        admitted,
        "earlier-stage witnesses survive for final validation"
    );
    assert_eq!(
        prepare(),
        first,
        "the next stage republishes its own input facts"
    );
    let next = counters();
    for (host, domain, key) in allocated {
        assert!(
            next.iter()
                .any(|&(h, d, k)| h == host && d == domain && k >= key),
            "republication preserves monotonic counters: {next:?}"
        );
    }
}

#[test]
fn selected_rust_byte_identical_replacement_uses_the_persisted_macro_capsule() {
    let mut fixture = RustRootResolutionOperationFixture::new_with_scale_sources(
        4,
        0,
        "",
        macro_definition_scale_source,
    );
    fixture.replace_persisted_consumer_source(RUST_MACRO_CONSUMER_SOURCE);
    let cancellation = CancellationToken::default();

    let persisted = rust_macro_point_answer(&fixture, None, &cancellation);
    let identical =
        rust_macro_point_answer(&fixture, Some(RUST_MACRO_CONSUMER_SOURCE), &cancellation);
    let edited_source = format!("{RUST_MACRO_CONSUMER_SOURCE}// an unsaved edit\n");
    let edited = rust_macro_point_answer(&fixture, Some(&edited_source), &cancellation);

    assert_eq!(
        persisted, identical,
        "a byte-identical replacement must answer as its persisted file does:\n\
         persisted={persisted:#?}\nidentical={identical:#?}\nedited={edited:#?}"
    );
    // The edited replacement's answer used to differ here, and it differed in
    // one thing only: the eight bytes of mount identity every semantic id
    // carried. The three answers' reason recipes were identical on both
    // sides, which is why the pin below this one exists and says so in its
    // own words -- "two answers can agree for reasons that have nothing to do
    // with the capsule". A local id is its mount's ordinal and its catalog
    // position now and carries no content key, so the difference the
    // comparison was reading is not in an answer any more; the capsule
    // observation that replaced it is
    // `selected_rust_byte_identical_replacement_admits_the_persisted_macro_inputs`.
    //
    // The edited answer's two remaining reasons were the call's applicability
    // gaps, not a macro gap: `permute` declared no parameter rows and its call
    // wrote no argument rows. Both inventories are exact now, so an edit that
    // only appends a comment answers exactly as the persisted file does.
    assert_eq!(
        edited, persisted,
        "an edit outside the invocation answers as the persisted file does"
    );
}

/// The capsule itself: a byte-identical replacement admits the same macro
/// inputs the persisted file does; an edited one binds its capsule to the
/// edited content witness.
///
/// This is the direct observation the point pin above cannot make. That pin
/// compares two answers, and two answers can agree for reasons that have
/// nothing to do with the capsule. Here the measurement is the capsule: for
/// each of the three mountings, whether `rust_macro_capsule` answers for the
/// consumer at all, and how many macro inputs the reference overlay admits
/// once the frontiers are prepared.
#[test]
fn selected_rust_byte_identical_replacement_admits_the_persisted_macro_inputs() {
    let mut fixture = RustRootResolutionOperationFixture::new_with_scale_sources(
        4,
        0,
        "",
        macro_definition_scale_source,
    );
    fixture.replace_persisted_consumer_source(RUST_MACRO_CONSUMER_SOURCE);
    let cancellation = CancellationToken::default();
    let edited_source = format!("{RUST_MACRO_CONSUMER_SOURCE}// an unsaved edit\n");
    let measure = |replacement: Option<&str>| {
        let (state, _) = parsed_operation_source_state(
            fixture._project_root.path(),
            RUST_ROOT_CONSUMER_PATH,
            replacement.unwrap_or(RUST_MACRO_CONSUMER_SOURCE),
            &RustAdapter,
        );
        let masks = replacement
            .map(|_| {
                vec![SelectedResolutionOverlayMask::replacement(
                    "rust",
                    RUST_ROOT_CONSUMER_PATH,
                )]
            })
            .unwrap_or_default();
        let replacements = replacement
            .map(|source| {
                vec![fixture.publish_counterfactual_content(
                    RUST_ROOT_CONSUMER_PATH,
                    source,
                    &state,
                    &cancellation,
                )]
            })
            .unwrap_or_default();
        let operation = fixture.open_content_selected(&masks, replacements, &cancellation);
        let capsule = operation
            .rust_macro_capsule(RUST_ROOT_CONSUMER_PATH)
            .expect("query the consumer's macro capsule")
            .is_some();
        assert!(
            matches!(
                operation
                    .prepare_selected_macro_frontiers(
                        Path::new(RUST_ROOT_CONSUMER_PATH),
                        &cancellation
                    )
                    .expect("prepare the consumer's macro frontiers"),
                SelectedResolutionStageOutcome::Ready
            ),
            "an uncancelled frontier preparation completes"
        );
        let admitted = active_macro_capsules(&operation).len();
        let expected_host_oid = Oid::hash_object(
            ObjectType::Blob,
            replacement.unwrap_or(RUST_MACRO_CONSUMER_SOURCE).as_bytes(),
        )
        .unwrap();
        let host = operation
            .ready
            .inventory
            .mount_record_for_path("rust", RUST_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        assert_eq!(host.blob_oid(), expected_host_oid);
        let admitted_rows = operation.ready.inventory.connection().prepare(
            "SELECT a.host_content_oid,a.invocation,a.blob_oid FROM temp.selected_resolution_stage_producers p JOIN temp.selected_resolution_admissions a USING(admission_id) WHERE p.host_ordinal=?1 AND a.input_kind=1"
        ).unwrap().query_map([host.ordinal().get()], |row| Ok((row.get::<_, String>(0)?,row.get::<_,u32>(1)?,row.get::<_,String>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(admitted_rows.len(), 1);
        assert_eq!(admitted_rows[0].0, expected_host_oid.to_string());
        let host_invocation: bool = operation.ready.inventory.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM source_rust_macro_inputs WHERE blob_id=?1 AND invocation_occurrence_id=?2 AND native_gap_site IS NOT NULL)",
            params![host.blob_id(), admitted_rows[0].1], |row| row.get(0),
        ).unwrap();
        assert!(
            host_invocation,
            "admitted input belongs to the actual selected host"
        );
        ((capsule, admitted), admitted_rows[0].2.clone())
    };

    let persisted = measure(None);
    let identical = measure(Some(RUST_MACRO_CONSUMER_SOURCE));
    let edited = measure(Some(edited_source.as_str()));
    assert_eq!(persisted.0, (true, 1));
    assert_eq!(identical.0, (true, 1));
    assert_eq!(edited.0, (true, 1));
    assert_eq!(
        persisted.1, identical.1,
        "identical content reuses the exact capsule"
    );
    assert_ne!(
        persisted.1, edited.1,
        "edited host content requires a distinct authenticated capsule"
    );
}

pub(in crate::analyzer::store) struct DenseSelectedMacroFixture {
    pub(in crate::analyzer::store) key: super::super::resolution_publication::ResolutionCapsuleKey,
    pub(in crate::analyzer::store) checkpoint: crate::analyzer::resolution::ResolutionNodeIdentity,
    pub(in crate::analyzer::store) module_scope:
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
    pub(in crate::analyzer::store) dense: LoweredResolutionFactsWithIdentityCatalog,
    pub(in crate::analyzer::store) reordered: LoweredResolutionFactsWithIdentityCatalog,
    pub(in crate::analyzer::store) lowering:
        brokk_bifrost_rust::macro_matcher::SelectedMacroInputLowering,
    pub(in crate::analyzer::store) references:
        Vec<super::super::resolution_publication::ResolutionCapsuleReferenceContext>,
    pub(in crate::analyzer::store) host_input_start_line: usize,
    pub(in crate::analyzer::store) host_path: String,
    pub(in crate::analyzer::store) expected_declaration_ranges: Option<(
        brokk_bifrost_core::analyzer::Range,
        brokk_bifrost_core::analyzer::Range,
    )>,
}

#[test]
fn selected_macro_derivation_distinguishes_same_blob_definition_declarations() {
    with_dense_selected_macro_fixture(|_, _, _| ());
}

pub(in crate::analyzer::store) fn with_dense_selected_macro_fixture<T>(
    visit: impl FnOnce(&AnalyzerStore, &WorkspaceSnapshotId, Vec<DenseSelectedMacroFixture>) -> T,
) -> T {
    use crate::analyzer::resolution::{
        BatchCandidateRequest, BatchResolutionFragmentSource, BindingNodeId, EndpointSignature,
        PerRequestSharedNames, ResolutionQuery, ResolutionSemanticIdentity, SelectedNodeProvenance,
        SharedNameInterner, StackPattern,
    };
    const CHILD: &str = "take!(Item);\n";
    fn child_source(index: usize) -> String {
        if index == 2 {
            "// host line offset\n\n            take!({\n    let local = Item;\n    local\n});\n"
                .to_owned()
        } else {
            CHILD.to_owned()
        }
    }
    let mut fixture =
        RustRootResolutionOperationFixture::new_with_scale_sources(6, 0, "", child_source);
    fixture.replace_persisted_consumer_source(concat!(
        "macro_rules! take { ($t:ty) => {}; }\n",
        "mod scale_0000;\n",
        "macro_rules! take { ($e:expr) => {}; }\n",
        "mod scale_0001;\n",
        "macro_rules! take { ($b:expr) => {}; }\n",
        "mod scale_0002;\n",
    ));
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mut derivations = Vec::new();
    let mut host_inputs = Vec::new();
    let mut prepared_digests = Vec::new();
    let mut publications = Vec::new();
    for (index, (path, expected_namespace)) in [
        ("app/src/scale_0000.rs", ResolutionNamespace::Type),
        ("app/src/scale_0001.rs", ResolutionNamespace::Value),
        ("app/src/scale_0002.rs", ResolutionNamespace::Value),
    ]
    .into_iter()
    .enumerate()
    {
        let mount = operation.rust_macro_capsule(path).unwrap().unwrap();
        let inputs = crate::analyzer::rust::source_storage::read_rust_macro_input_rows(
            operation.ready.inventory.connection(),
            mount.blob_id(),
            &|| true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(inputs.len(), 1);
        let input = &inputs[0];
        let host_source = child_source(index);
        let mut parser = Parser::new();
        let host_file = ProjectFile::new(fixture._project_root.path().to_path_buf(), path);
        parser
            .set_language(&RustAdapter.parser_language_for_file(&host_file))
            .unwrap();
        let host_tree = parser.parse(&host_source, None).unwrap();
        let mut pending = vec![host_tree.root_node()];
        let mut macro_head = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "macro_invocation" {
                assert!(macro_head.is_none());
                macro_head = node.child_by_field_name("macro");
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let macro_head = macro_head.unwrap();
        let RustSelectedBuildOutcome::Ready(Some((definition_path, declaration))) = operation
            .select_textual_macro_definition(
                Path::new(path),
                macro_head.start_byte(),
                "take",
                &cancellation,
            )
            .unwrap()
        else {
            panic!("selected macro definition for {path}");
        };
        assert_eq!(definition_path, Path::new(RUST_ROOT_CONSUMER_PATH));
        let definition_mount = operation
            .rust_macro_capsule(&selected_path_key(&definition_path))
            .unwrap()
            .unwrap();
        let arm = operation
            .match_selected_textual_macro(
                Path::new(path),
                macro_head.start_byte(),
                input.tree.start_byte,
                "take",
                &cancellation,
            )
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(arm.arm_index, 0);
        // Parse the actual captured block under a normal function grammar. The
        // AST oracle retains host newlines and byte positions independently of
        // the capsule producer's source-occurrence and line-offset arithmetic.
        let expected_declaration_ranges = if index == 2 {
            let binding = &arm.bindings[0];
            let mut oracle_source = host_source[..binding.start_byte]
                .chars()
                .map(|ch| if ch == '\n' { '\n' } else { ' ' })
                .collect::<String>();
            const WRAPPER: &str = "fn oracle() ";
            let insertion = binding.start_byte - WRAPPER.len();
            assert!(!oracle_source[insertion..].contains('\n'));
            oracle_source.replace_range(insertion.., WRAPPER);
            oracle_source.push_str(&host_source[binding.start_byte..binding.end_byte]);
            let oracle_tree = parser.parse(&oracle_source, None).unwrap();
            assert!(!oracle_tree.root_node().has_error());
            let mut pending = vec![oracle_tree.root_node()];
            let mut expected = None;
            while let Some(node) = pending.pop() {
                if node.kind() == "let_declaration" {
                    assert!(expected.is_none());
                    let name = node.child_by_field_name("pattern").unwrap();
                    let range = |node: tree_sitter::Node<'_>| brokk_bifrost_core::analyzer::Range {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        start_line: node.start_position().row + 1,
                        end_line: node.end_position().row + 1,
                    };
                    expected = Some((range(name), range(node)));
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            assert!(expected.is_some());
            expected
        } else {
            None
        };
        let lowered = brokk_bifrost_rust::macro_matcher::lower_selected_macro_input_with_sources(
            &input.tree,
            &arm,
            brokk_bifrost_rust::macro_matcher::RustMacroItemContainer::Lexical,
        );
        let references = lowered
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && lowered.facts.names[identifier.name.index()].spelling == "Item"
            })
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 1, "{path}: {references:?}");
        assert_eq!(references[0].namespace, expected_namespace);
        let site = lowered
            .facts
            .sites
            .iter()
            .find(|site| site.id == references[0].site)
            .unwrap();
        assert_eq!(&child_source(index)[site.start_byte..site.end_byte], "Item");

        // These are the actual host inputs used by macro preparation: the
        // unique macro-head seed endpoint and nearest structural module scope.
        let source = operation
            .selected_rust_usage_facts(Path::new(path), &cancellation)
            .unwrap()
            .unwrap();
        let module_scope = source
            .module_routes
            .scopes
            .iter()
            .filter(|scope| scope.body_start == 0 && 0 < scope.body_end)
            .min_by_key(|scope| scope.body_end - scope.body_start)
            .and_then(|scope| scope.resolution_scope)
            .unwrap();
        let lexical = operation.ready.lexical_source();
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            path,
            macro_head.start_byte(),
            macro_head.end_byte(),
        );
        let LocatedSemantic::Found(head) = operation
            .ready
            .lookup_locator(&lexical, &locator, &cancellation)
            .unwrap()
        else {
            panic!("actual selected macro head");
        };
        let seeds = lexical
            .lookup_reference_seeds(&[ResolutionQuery::new(head)], &cancellation)
            .unwrap();
        let seed = seeds.rows()[0].seed().unwrap();
        let candidates = lexical
            .match_forward_candidates(
                &[BatchCandidateRequest::new(
                    0,
                    EndpointSignature::new(
                        seed.node(),
                        StackPattern::closed([]),
                        StackPattern::closed([]),
                    ),
                )],
                &cancellation,
            )
            .unwrap();
        let paths = lexical
            .hydrate_candidate_paths(
                &candidates
                    .matches()
                    .iter()
                    .map(|row| row.candidate())
                    .collect::<Vec<_>>(),
                &cancellation,
            )
            .unwrap();
        let checkpoints = paths
            .iter()
            .filter(|(_, path)| path.start().node() == seed.node())
            .map(|(_, path)| path.end().node())
            .collect::<BTreeSet<_>>();
        assert_eq!(checkpoints.len(), 1);
        let Some(SelectedNodeProvenance::FragmentLocal(checkpoint)) = lexical
            .node_provenance(*checkpoints.first().unwrap(), &cancellation)
            .unwrap()
            .unwrap()
        else {
            panic!("actual host checkpoint has producer identity");
        };
        let checkpoint = checkpoint.identity();
        host_inputs.push((checkpoint, module_scope));
        let capsule_key = super::super::resolution_publication::ResolutionCapsuleKey {
            host_content_oid: mount.content_oid(),
            invocation: input.invocation,
            definition_content_oid: definition_mount.content_oid(),
            selected_declaration: declaration,
            matched_arm_index: arm.arm_index,
            producer_epoch: super::super::resolution::resolution_bundle_epoch(Language::Rust)
                .to_owned(),
        };
        let key = selected_macro_capture_digest(input.invocation, &input.tree, &arm);
        let names = PerRequestSharedNames::new();
        let other_names = PerRequestSharedNames::new();
        let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            mount.mount().fragment(),
            &names,
            Language::Rust,
            &lowered.facts,
        )
        .instantiate_macro_input(key, checkpoint, module_scope, &cancellation)
        .unwrap();
        // Reverse all actual names, plus a foreign name, to force distinct
        // request IDs while retaining exactly the same producer content.
        other_names.intern([0xa7; 32]);
        for digest in artifact.identities().shared_names().into_iter().rev() {
            other_names.intern(digest);
        }
        let reordered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            mount.mount().fragment(),
            &other_names,
            Language::Rust,
            &lowered.facts,
        )
        .instantiate_macro_input(key, checkpoint, module_scope, &cancellation)
        .unwrap();
        for dense in [&artifact, &reordered] {
            let catalog = dense.identities();
            let shared_members = catalog
                .semantics()
                .iter()
                .filter_map(|(_, identity)| match identity {
                    ResolutionSemanticIdentity::Shared(name) => {
                        Some(catalog.shared_name_digest(*name))
                    }
                    ResolutionSemanticIdentity::FragmentLocal(_)
                    | ResolutionSemanticIdentity::GapReason(_) => None,
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(shared_members, catalog.shared_names().into_iter().collect());
            for site in dense.lexical().semantics() {
                assert_eq!(site.semantic().local_key(), Some(site.site().get()));
                assert_eq!(site.node().local_key(), Some(site.site().get()));
            }
            assert!(
                catalog
                    .nodes()
                    .iter()
                    .all(|(node, _)| *node != BindingNodeId::universal_root())
            );
        }
        // No host retargeting or fabricated ParsedSourceFacts/PreparedParsedBlob:
        // the real generic resolution preparer must accept the dense artifact.
        let prepare = |dense: &LoweredResolutionFactsWithIdentityCatalog| {
            let super::super::resolution_prepare::ResolutionInteriorPreparation::Prepared(bundle) =
                super::super::resolution_prepare::prepare_resolution_bundle_with_unit_keys(
                    dense,
                    None,
                    &cancellation,
                )
            else {
                panic!("live dense capsule preparation");
            };
            bundle
        };
        let prepared = prepare(&artifact);
        let reordered_prepared = prepare(&reordered);
        assert_eq!(
            prepared, reordered_prepared,
            "all prepared rows, membership and canonical digest ignore request interning order"
        );
        prepared_digests.push(prepared.interior_digest());
        eprintln!(
            "FR dense capsule key={key:?} checkpoint={checkpoint:?} module_scope={module_scope:?} digest={:?}",
            prepared.interior_digest()
        );
        derivations.push((
            mount.blob_id(),
            input.invocation,
            definition_mount.blob_id(),
            arm.arm_index,
            declaration,
        ));
        let mut host_context = Vec::new();
        let context_outcome = operation
            .ready
            .typed_source()
            .visit_rust_reference_context_pages(
                TypedFactRequest::new(&[head]),
                &cancellation,
                &mut FactPageVisitor::new(&mut |rows| {
                    host_context.extend_from_slice(rows);
                    Ok(true)
                }),
            )
            .unwrap();
        assert!(!context_outcome.is_cancelled());
        assert_eq!(host_context.len(), 1);
        let host_context = host_context[0].row();
        use super::super::resolution_publication::{
            ResolutionCapsuleReferenceContext, ResolutionCapsuleReferenceOwner,
        };
        let reference_owner = match seed.reference_owner() {
            None => ResolutionCapsuleReferenceOwner::Unknown,
            Some(None) => ResolutionCapsuleReferenceOwner::Root,
            Some(Some(owner)) => ResolutionCapsuleReferenceOwner::HostLocal(
                crate::analyzer::resolution::ResolutionLocalKey::new(i64::from(
                    owner.local_key().expect("host-local reference owner"),
                )),
            ),
        };
        let contexts = artifact
            .lexical()
            .semantics()
            .iter()
            .filter(|site| site.role() == LoweredSemanticRole::Reference)
            .map(|site| {
                let metadata = site.site_metadata().expect("dense reference range");
                let token = input
                    .tree
                    .tokens
                    .iter()
                    .position(|token| {
                        token.start_byte == metadata.start_byte()
                            && token.end_byte == metadata.end_byte()
                    })
                    .expect("actual host token occurrence");
                ResolutionCapsuleReferenceContext {
                    semantic_key: crate::analyzer::resolution::ResolutionLocalKey::new(i64::from(
                        site.semantic().local_key().unwrap(),
                    )),
                    source_site: site.site(),
                    host_occurrence: input.occurrences[token],
                    module_context: host_context.module_context(),
                    module_declaration: host_context.module_declaration(),
                    reference_owner,
                }
            })
            .collect();
        let host_input_start_line = operation.ready.inventory.connection().query_row(
            "SELECT json_extract(spans, '$[' || ?2 || '][2]') FROM source_occurrence_arenas WHERE blob_id=?1",
            params![mount.blob_id(),input.occurrences[0].get()], |row|row.get(0)).unwrap();
        publications.push(DenseSelectedMacroFixture {
            key: capsule_key,
            checkpoint,
            module_scope,
            dense: artifact,
            reordered,
            lowering: lowered,
            references: contexts,
            host_input_start_line,
            host_path: path.to_owned(),
            expected_declaration_ranges,
        });
    }
    eprintln!(
        "FR macro selected derivations (host blob, occurrence, definition blob, arm, declaration): {derivations:?}; namespaces=[Type, Value]"
    );
    let left = derivations[0];
    let right = derivations[1];
    assert_eq!(
        (left.0, left.1, left.2, left.3),
        (right.0, right.1, right.2, right.3)
    );
    assert_ne!(
        left.4, right.4,
        "the selected declaration is a necessary derivation input"
    );
    assert_eq!(
        host_inputs[0], host_inputs[1],
        "identical host content and invocation retain the checkpoint and structural module scope"
    );
    assert_ne!(
        prepared_digests[0], prepared_digests[1],
        "distinct selected declaration semantics produce distinct prepared capsules"
    );
    drop(operation);
    visit(
        &fixture.store,
        fixture.snapshots.get("rust").unwrap(),
        publications,
    )
}

#[test]
fn persisted_catalog_does_not_treat_a_shared_slot_as_a_local_semantic() {
    use crate::analyzer::resolution::{
        SelectedSemanticProvenance, SharedNameId, SharedNameInterner,
    };
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mount = operation.ready.inventory.mounts().unwrap().first().unwrap();
    let (slot, shared) = operation.ready.inventory.connection().query_row(
        "SELECT local_key, shared_identity FROM resolution_semantic_catalog WHERE blob_id=?1 AND shared_identity IS NOT NULL LIMIT 1",
        [mount.blob_id()], |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?)),
    ).unwrap();
    let lexical = operation.ready.lexical_source();
    let actual_shared = SemanticId::shared_name(
        operation
            .ready
            .shared_names()
            .from_persisted(SharedNameId::interned(shared)),
    );
    let Some(SelectedSemanticProvenance::Shared(identity)) = lexical
        .semantic_provenance(actual_shared, &cancellation)
        .unwrap()
    else {
        panic!("shared runtime identity retains shared provenance");
    };
    assert_eq!(identity.shared_name(), actual_shared.shared_name_id());
    let impostor = SemanticId::local(mount.ordinal().get(), slot);
    assert!(
        lexical
            .semantic_provenance(impostor, &cancellation)
            .is_err(),
        "a local runtime cannot impersonate a shared catalog position"
    );
}

#[test]
fn persisted_lexical_type_transfer_retains_fragment_gaps_without_rules_and_on_stop() {
    use crate::analyzer::resolution::{
        BatchResolutionFragmentSource, ResolutionCompletion, ResolutionIncompleteReason, SemanticId,
    };
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let (ordinal,blob,slot)=operation.ready.inventory.connection().query_row("SELECT m.mount_ordinal,m.blob_id,t.source_slot FROM temp.selected_resolution_mounts m JOIN resolution_type_transfers t ON t.blob_id=m.blob_id ORDER BY m.mount_ordinal,t.source_slot LIMIT 1",[],|row| Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?,row.get::<_,u32>(2)?))).expect("fixture has type transfer");
    let reason = SemanticId::local(ordinal, 930_001);
    // Independent coverage input: a fragment gap qualifies every lexical
    // transfer read, even when the requested slot has no typed frontier/rule.
    fixture.store.conn.execute(move |conn| {
        conn.execute("INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES(?1,930001,0,0)",[blob]).unwrap();
        conn.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES(?1,0,0,0,930001,930001)",[blob]).unwrap();
    });
    let expected =
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(reason)]);
    let source = operation.ready.lexical_source();
    let no_rule_slot: u32 = operation.ready.inventory.connection().query_row(
        "SELECT catalog.local_key FROM resolution_semantic_catalog catalog WHERE catalog.blob_id=?1 AND catalog.shared_identity IS NULL AND NOT EXISTS(SELECT 1 FROM resolution_type_transfers transfer WHERE transfer.blob_id=catalog.blob_id AND transfer.source_slot=catalog.local_key) ORDER BY catalog.local_key LIMIT 1",
        [blob], |row| row.get(0),
    ).expect("actual local catalog identity without a transfer rule");
    let absent = source
        .visit_type_transfer_rules(
            SemanticId::local(ordinal, no_rule_slot),
            &cancellation,
            &mut |_| panic!("absent slot has no rules"),
        )
        .unwrap();
    assert_eq!(absent, expected);
    let mut seen = 0;
    let stopped = source
        .visit_type_transfer_rules(SemanticId::local(ordinal, slot), &cancellation, &mut |_| {
            seen += 1;
            Ok(false)
        })
        .unwrap();
    assert_eq!(seen, 1);
    assert_eq!(stopped, expected);
    let token = CancellationToken::new();
    let cancelled = source
        .visit_type_transfer_rules(SemanticId::local(ordinal, slot), &token, &mut |rule| {
            assert_eq!(rule.completion(), &ResolutionCompletion::Complete);
            token.cancel();
            Ok(false)
        })
        .unwrap();
    assert_eq!(
        cancelled,
        expected.combine(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::Cancelled
        ]))
    );
}

#[test]
fn persisted_reverse_exclusions_keep_multiplicity_and_reuse_complete_authority_across_scopes() {
    use crate::analyzer::resolution::{
        BatchCandidateRequest, BindingNodeId, EndpointSignature, ResolutionCompletion,
        ResolutionIncompleteReason, ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity,
        SemanticId, StackPattern, StackVariableId,
    };
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mounts = operation.ready.inventory.mounts().unwrap();
    let first = &mounts[0];
    let second = mounts
        .iter()
        .find(|mount| mount.blob_id() != first.blob_id())
        .expect("different content mount");
    let coordinates = [
        (first.ordinal(), first.blob_id()),
        (second.ordinal(), second.blob_id()),
    ];
    fixture.store.conn.execute(move |conn| {
        for (_,blob) in coordinates {
            conn.execute("INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES(?1,960001,0,0)", [blob]).unwrap();
            for gap in [950_001,950_002] {
                conn.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES(?1,6,-1,0,?2,960001)",params![blob,gap]).unwrap();
            }
        }
    });
    let gap = |key| {
        ReverseCandidateGapIdentity::new(
            first.fragment_id(),
            SemanticId::local(first.ordinal().get(), key),
        )
    };
    let mut plan = ReverseCandidateGapExclusionPlan::new([gap(950_001)]);
    let request = BatchCandidateRequest::new(
        0,
        EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::open([], StackVariableId::local(first.ordinal().get(), 970_001)),
            StackPattern::closed([]),
        ),
    );
    let source = operation.ready.lexical_source();
    for mount in [first, second, first] {
        let (result, cancelled) = source
            .reverse_completion_with_exclusions(
                std::slice::from_ref(&request),
                Some(&[mount.ordinal()]),
                &mut plan,
                &cancellation,
            )
            .unwrap();
        assert!(!cancelled);
        assert!(result.branch_completions()[0].contains_reason(
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(
                mount.ordinal().get(),
                960_001
            ))
        ));
        let other = if mount.ordinal() == first.ordinal() {
            second
        } else {
            first
        };
        assert!(!result.branch_completions()[0].contains_reason(
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(
                other.ordinal().get(),
                960_001
            ))
        ));
    }
    let mut both = ReverseCandidateGapExclusionPlan::new([gap(950_001), gap(950_002)]);
    let (result, _) = source
        .reverse_completion_with_exclusions(
            std::slice::from_ref(&request),
            Some(&[first.ordinal()]),
            &mut both,
            &cancellation,
        )
        .unwrap();
    assert!(!result.branch_completions()[0].contains_reason(
        ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(
            first.ordinal().get(),
            960_001
        ))
    ));
    let mut missing = ReverseCandidateGapExclusionPlan::new([gap(950_003)]);
    assert!(
        source
            .reverse_completion_with_exclusions(&[request], None, &mut missing, &cancellation)
            .is_err()
    );
    assert_ne!(
        ResolutionCompletion::Complete,
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
            SemanticId::local(first.ordinal().get(), 960_001)
        )])
    );
}

#[test]
fn persisted_b1_authority_family_accounting_and_optional_node_classification() {
    let fixture = RustRootResolutionOperationFixture::new();
    fixture.store.conn.execute(|conn| {
        let counts=conn.query_row("SELECT (SELECT count(*) FROM resolution_semantic_catalog),(SELECT count(*) FROM resolution_node_catalog),(SELECT count(*) FROM resolution_contract_references),(SELECT count(*) FROM resolution_rust_reference_contexts),(SELECT count(*) FROM resolution_rust_declaration_authorities)",[],|row| Ok([row.get::<_,i64>(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?])).unwrap();
        let payload=conn.query_row("SELECT (SELECT count(*)*32 FROM resolution_semantic_catalog),(SELECT count(*)*32 FROM resolution_node_catalog),0,(SELECT coalesce(sum(length(CAST(json(cfg_condition) AS BLOB))),0) FROM resolution_rust_reference_contexts),(SELECT coalesce(sum(length(CAST(json(cfg_condition) AS BLOB))+coalesce(length(CAST(json(visibility) AS BLOB)),0)),0) FROM resolution_rust_declaration_authorities)",[],|row| Ok([row.get::<_,i64>(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?])).unwrap();
        let manifest=conn.query_row("SELECT sum(logical_rows),sum(payload_bytes) FROM resolution_fragment_interiors",[],|row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?))).unwrap();
        eprintln!("B1 authority family counts semantic/node/contract/reference/declaration={counts:?}; logical payload bytes={payload:?}; complete bundle rows/bytes={manifest:?}");
        assert!(counts[0]>0 && counts[1]>0 && counts[3]>0 && counts[4]>0);
        let classes=conn.query_row("SELECT sum(kind IS NULL),sum(kind IS NOT NULL) FROM resolution_node_catalog",[],|row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?))).unwrap();
        assert!(classes.0>0 && classes.1>0,"identity membership and producer classification are distinct: {classes:?}");
        let missing=conn.query_row("SELECT count(*) FROM resolution_fragment_interiors m WHERE m.expected_semantic_catalog_count<>(SELECT count(*) FROM resolution_semantic_catalog c WHERE c.blob_id=m.blob_id) OR m.expected_node_catalog_count<>(SELECT count(*) FROM resolution_node_catalog c WHERE c.blob_id=m.blob_id) OR m.expected_contract_reference_count<>(SELECT count(*) FROM resolution_contract_references c WHERE c.blob_id=m.blob_id) OR m.expected_rust_reference_context_count<>(SELECT count(*) FROM resolution_rust_reference_contexts c WHERE c.blob_id=m.blob_id) OR m.expected_rust_declaration_authority_count<>(SELECT count(*) FROM resolution_rust_declaration_authorities c WHERE c.blob_id=m.blob_id)",[],|row| row.get::<_,i64>(0)).unwrap();
        assert_eq!(missing,0);
    });
}

#[test]
fn persisted_reverse_exclusion_rejects_a_qualified_gap_owned_by_the_typed_route() {
    use crate::analyzer::resolution::{
        LoweringGapOrigin, ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity,
        SemanticId,
    };
    let mut fixture = RustRootResolutionOperationFixture::new();
    fixture
        .replace_persisted_consumer_source("pub fn caller() -> usize { engine::model::target() }");
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let origin = crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
        LoweringGapOrigin::QualifiedReference,
    );
    let (ordinal,key)=operation.ready.inventory.connection().query_row("SELECT m.mount_ordinal,g.gap FROM temp.selected_resolution_mounts m JOIN resolution_gaps g ON g.blob_id=m.blob_id AND g.covers=3 JOIN resolution_gap_reasons r ON r.blob_id=g.blob_id AND r.reason=g.reason JOIN resolution_qualified_routes q ON q.blob_id=r.blob_id AND q.reference=r.site AND q.coarse_gap_reason=r.reason WHERE r.origin=?1 ORDER BY m.mount_ordinal,g.gap LIMIT 1",[origin],|row| Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?))).expect("fixture has an exact typed-owned qualified route gap");
    let fragment = crate::analyzer::resolution::BindingFragmentId::at_ordinal(ordinal);
    let mut plan = ReverseCandidateGapExclusionPlan::new([ReverseCandidateGapIdentity::new(
        fragment,
        SemanticId::local(ordinal, key),
    )]);
    let error = operation
        .ready
        .lexical_source()
        .reverse_completion_with_exclusions(&[], None, &mut plan, &cancellation)
        .expect_err("typed-owned reason is absent from raw exclusion authority");
    assert!(error.to_string().contains("no exact gap"), "{error}");
}

#[test]
fn persisted_reference_seed_cancellation_retains_decoded_gap_prefix() {
    use crate::analyzer::resolution::{
        BatchResolutionFragmentSource, ResolutionCompletion, ResolutionIncompleteReason,
        ResolutionQuery, SemanticId,
    };
    let mut fixture = RustRootResolutionOperationFixture::new();
    fixture.replace_persisted_consumer_source("pub fn target() {} pub fn caller() { target(); }");
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mount = operation
        .ready
        .inventory
        .mount_record_for_path("rust", RUST_ROOT_CONSUMER_PATH)
        .unwrap()
        .unwrap();
    let conn = operation.ready.inventory.connection();
    let site: u32 = conn
        .query_row(
            "SELECT site FROM resolution_sites WHERE blob_id=?1 AND role=0 ORDER BY site LIMIT 1",
            [mount.blob_id()],
            |row| row.get(0),
        )
        .unwrap();
    let source = operation.ready.lexical_source();
    let query = ResolutionQuery::new(SemanticId::local(mount.ordinal().get(), site));
    let baseline = source
        .lookup_reference_seeds(&[query], &cancellation)
        .unwrap();
    let baseline_reasons = match baseline.rows()[0].seed().unwrap().completion() {
        ResolutionCompletion::Complete => Vec::new(),
        ResolutionCompletion::Incomplete(reasons) => reasons.iter().copied().collect::<Vec<_>>(),
    };
    const FIRST: u32 = 980_000;
    let blob_id = mount.blob_id();
    fixture.store.conn.execute(move |conn| {
    for offset in 0..64_u32 {
        conn.execute(
            "INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) VALUES(?1,?2,?3,0)",
            params![blob_id, FIRST + offset, site],
        )
        .unwrap();
        conn.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) VALUES(?1,4,?2,0,?3,?3)",params![blob_id,site,FIRST+offset]).unwrap();
    }
    });
    let expected = |count: u32| {
        ResolutionCompletion::incomplete(baseline_reasons.iter().copied().chain((0..count).map(
            |offset| {
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(
                    mount.ordinal().get(),
                    FIRST + offset,
                ))
            },
        )))
    };
    let full = source
        .lookup_reference_seeds(&[query], &cancellation)
        .unwrap();
    assert_eq!(full.rows()[0].seed().unwrap().completion(), &expected(64));
    let mut partial = false;
    for checks in 1..=120 {
        let token = CancellationToken::cancel_after_checks_for_test(checks);
        let result = source.lookup_reference_seeds(&[query], &token).unwrap();
        if result.is_cancelled() {
            let count = match result.evidence() {
                ResolutionCompletion::Complete => 0,
                ResolutionCompletion::Incomplete(reasons) => reasons.len(),
            };
            if count > baseline_reasons.len() && count < baseline_reasons.len() + 64 {
                partial = true;
                assert_eq!(
                    result.evidence(),
                    &expected((count - baseline_reasons.len()) as u32)
                );
                assert!(result.rows().is_empty());
            }
        }
    }
    assert!(
        partial,
        "an interrupted batch must retain its decoded evidence prefix"
    );
    let retry = source
        .lookup_reference_seeds(&[query], &cancellation)
        .unwrap();
    assert_eq!(retry.rows()[0].seed().unwrap().completion(), &expected(64));
}

#[test]
fn sql_context_adapter_descriptor_conflict_rolls_back_after_full_derivation_charge() {
    let fixture = RustRootResolutionOperationFixture::new();
    let live = CancellationToken::new();
    let operation = fixture.open_ready(&live);
    let SelectedRustContextOutcome::Ready(context) =
        operation.rust_context_for_all_crates(&live).unwrap()
    else {
        panic!("live Rust fixture context must be ready")
    };
    let SelectedResolutionContextValidationOutcome::Ready(inputs) = operation
        .prepare_context(context, &live, &SelectedResolutionContextMetrics)
        .unwrap()
    else {
        panic!("live Rust fixture context must validate")
    };
    let (bridges, _, _, _, _, packages, imports) = inputs.into_parts();
    assert!(packages.is_empty() && imports.is_empty());
    let template = bridges
        .iter()
        .find(|bridge| bridge.prefix_reference().is_none())
        .expect("fixture has a structured root bridge");
    let build = |completion| {
        crate::analyzer::resolution::SelectedRootBridgeDescriptor::from_selected_path_tokens(
            template.source_fragment(),
            template.source_language(),
            template.source_import_token(),
            template.anchor(),
            template.source_import_anchor(),
            template.target_fragment(),
            template.target_language(),
            template.target_export_token(),
            template.route().to_vec(),
            template.source_demand().clone(),
            template.target_demand().clone(),
            completion,
        )
    };
    let first = build(ResolutionCompletion::Complete);
    let conflict = build(ResolutionCompletion::incomplete([
        ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::context_local(808)),
    ]));
    let mounts = operation.mount_table();
    let owner = mounts
        .mount_for_fragment(first.source_fragment())
        .unwrap()
        .unwrap();
    let inputs_for = |bridges: Vec<crate::analyzer::resolution::SelectedRootBridgeDescriptor>| {
        let context = SelectedResolutionContextSet::new(
            operation.ready.context_identities.clone(),
            vec![
                SelectedResolutionMountContext::new(
                    owner.ordinal(),
                    owner.fragment(),
                    owner.semantic_language(),
                    bridges,
                    ResolutionCompletion::Complete,
                )
                .unwrap(),
            ],
            mounts.mount_count(),
            &selected_mount_lookup(mounts),
        )
        .unwrap();
        let SelectedResolutionContextValidationOutcome::Ready(inputs) = context
            .validate_exact_mounts(mounts.mount_count(), &selected_mount_lookup(mounts), &live)
            .unwrap()
        else {
            panic!("live fixture context must validate")
        };
        inputs
    };
    let count = || {
        operation.ready.inventory.connection().query_row(
        "SELECT (SELECT count(*) FROM temp.selected_resolution_contexts), (SELECT count(*) FROM temp.selected_resolution_context_paths)", [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    ).unwrap()
    };
    let first_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let crate::analyzer::resolution::SelectedContextPathPublicationOutcome::Ready(
        first_publication,
    ) = operation
        .ready
        .publish_context_paths(inputs_for(vec![first.clone()]), &live, &first_session)
        .unwrap()
    else {
        panic!("live context publication must complete")
    };
    let duplicate_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let crate::analyzer::resolution::SelectedContextPathPublicationOutcome::Ready(
        duplicate_publication,
    ) = operation
        .ready
        .publish_context_paths(
            inputs_for(vec![first.clone(), first.clone()]),
            &live,
            &duplicate_session,
        )
        .unwrap()
    else {
        panic!("identical derivations must deduplicate")
    };
    assert_ne!(first_publication.token, duplicate_publication.token);
    assert_eq!(
        duplicate_session.finish(()).work().scope_nodes,
        2 * first_session.finish(()).work().scope_nodes
    );
    let before = count();
    let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let error = match operation.ready.publish_context_paths(
        inputs_for(vec![first, conflict]),
        &live,
        &session,
    ) {
        Err(error) => error,
        Ok(_) => panic!("conflicting descriptor completion must reject publication"),
    };
    assert!(error.to_string().contains("conflicting derivations"));
    assert_eq!(count(), before);
    assert_eq!(
        session.finish(()).work().scope_nodes,
        duplicate_session.finish(()).work().scope_nodes
    );
}

/// A crate stage checks each mount's publication once
/// (`resolution_authority::AuthorityValidations`). A republication after that
/// check is not seen by the stage's later reads of the mount, but the graph
/// build's `finish_native` still ends the request `Stale`.
#[test]
fn a_republication_during_a_crate_stage_still_ends_stale() {
    use super::super::resolution_authority::SelectedResolutionAuthority;
    let fixture = ResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let mut operation = fixture.open_ready(&[], Vec::new(), &cancellation);
    {
        let _memos = operation.crate_stage_memos().unwrap();
        let inventory = &operation.ready.inventory;
        let authority = SelectedResolutionAuthority::new(
            inventory.connection(),
            inventory.shared_name_table(),
            inventory.requested_mount_rows(),
            inventory.persisted_mount_count(),
            inventory.authority_validations(),
        );
        let mount = inventory.mounts().unwrap()[0].clone();
        assert_eq!(
            authority.ensure_authority(&mount, &cancellation).unwrap(),
            Some(())
        );
        let blob = mount.blob_id();
        let republished = fixture.store.conn.execute(move |conn| {
            conn.execute(
                "UPDATE resolution_fragment_interiors SET publication_state = 'building' \
                 WHERE blob_id = ?1",
                [blob],
            )
            .unwrap()
        });
        assert_eq!(republished, 1);
        assert_eq!(
            authority.ensure_authority(&mount, &cancellation).unwrap(),
            Some(()),
            "the stage relies on its first check of the mount"
        );
    }
    let outcome = operation
        .finish_native((), &ResolutionCompletion::Complete, &cancellation)
        .unwrap();
    match outcome {
        SelectedResolutionOperationOutcome::Stale(reason) => {
            assert_eq!(reason, SelectedResolutionStale::MountInventoryChanged)
        }
        _ => panic!("a republication during the stage must end Stale"),
    }
}

/// A crate stage holds one read transaction on its reader. Temp writes nest
/// in it as savepoints, the request's own publication is seen only after the
/// stage's snapshot is renewed, and the reader leaves the stage outside any
/// transaction.
#[test]
fn a_crate_stage_reads_one_snapshot_and_renews_it_around_a_publication() {
    let fixture = ResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&[], Vec::new(), &cancellation);
    let inventory = &operation.ready.inventory;
    let digest = [0x5a_u8; 32];
    let seen = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row(
            "SELECT count(*) FROM resolution_identities WHERE identity_digest = ?1",
            [digest.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
    };
    {
        let _memos = operation.crate_stage_memos().unwrap();
        assert!(!inventory.connection().is_autocommit());
        assert_eq!(seen(inventory.connection()), 0);
        inventory
            .with_owned_temp_transaction(|conn| {
                conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS stage_probe(value INTEGER)")?;
                conn.execute("INSERT INTO temp.stage_probe VALUES(1)", [])?;
                Ok(
                    super::super::resolution_selection::SelectedResolutionTempTransaction::Commit(
                        (),
                    ),
                )
            })
            .unwrap();
        assert!(
            !inventory.connection().is_autocommit(),
            "a temp write is a savepoint inside the stage"
        );
        fixture.store.conn.execute(move |conn| {
            conn.execute(
                "INSERT INTO resolution_identities(identity_digest) VALUES(?1)",
                [digest.as_slice()],
            )
            .unwrap();
        });
        assert_eq!(
            seen(inventory.connection()),
            0,
            "the stage reads its own snapshot"
        );
        inventory.pause_stage_read().unwrap();
        inventory.resume_stage_read().unwrap();
        assert_eq!(
            seen(inventory.connection()),
            1,
            "the renewed snapshot sees it"
        );
    }
    assert!(inventory.connection().is_autocommit());
    let probe: i64 = inventory
        .connection()
        .query_row("SELECT count(*) FROM temp.stage_probe", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(probe, 1, "the stage committed its temp write");
}

#[path = "resolution_operation_java_tests.rs"]
mod java_query_tests;

#[test]
fn selected_go_import_names_bind_actual_file_definitions_without_basename_guessing() {
    for staged in [false, true] {
        for (source_text, bound) in [
            (
                "package consumer; import \"example.test/root/strange\"; var Item provider.Item",
                true,
            ),
            (
                "package consumer; import renamed \"example.test/root/strange\"; var Item renamed.Item",
                true,
            ),
            (
                "package consumer; import _ \"example.test/root/strange\"; var Item provider.Item",
                false,
            ),
        ] {
            let fixture = GoRootResolutionOperationFixture::with_consumer(source_text);
            let context_id = publish_go_root_fixture_context(&fixture, "example.test/root/strange");
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let source = operation
                .mount_table()
                .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
                .unwrap()
                .unwrap();
            let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                source.fragment(),
                &operation.ready.shared_names(),
                Language::Go,
                &fixture.consumer_facts,
            );
            let definition = lowered.common().go_package_imports[0].definition;
            if staged {
                stage_go_import_rows(
                    &operation,
                    source.ordinal(),
                    &lowered.common().go_package_imports,
                );
            }

            let prefix = fixture
                .consumer_facts
                .root_references
                .iter()
                .find_map(|reference| reference.prefix_reference)
                .expect("positioned package qualifier");
            let go_context::GoDotImportContext::Ready(context) = operation
                .go_import_binding_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
                .unwrap()
            else {
                panic!("selected source imports and canonical package names must compose");
            };
            let answer = operation
                .resolve_reference(
                    context,
                    &SelectedSemanticLocator::new(
                        "go",
                        GO_ROOT_CONSUMER_PATH,
                        prefix,
                        LoweredSemanticRole::Reference,
                    ),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) = answer
            else {
                panic!("source package qualifier must remain located");
            };
            assert_eq!(
                answer.binding().targets().contains(&definition),
                bound,
                "{source_text}: {answer:?}"
            );
        }
    }
}

#[test]
fn selected_go_context_rejects_an_obsolete_package_derivation() {
    let fixture = GoRootResolutionOperationFixture::new();
    let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
    fixture.store.conn.execute(move |connection| {
        connection.execute("UPDATE go_context_selections SET derivation_version=derivation_version-1 WHERE selection_id=(SELECT selection_id FROM go_context_publications WHERE context_id=?1)", [context]).unwrap();
    });
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    assert!(matches!(
        operation
            .go_dot_import_context(context, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
            .unwrap(),
        go_context::GoDotImportContext::Unavailable
    ));
}

#[test]
fn selected_go_qualified_imports_follow_bound_definitions_and_respect_local_shadowing() {
    for (source_text, bound) in [
        (
            "package consumer; import \"example.test/root/strange\"; var Use provider.Item",
            true,
        ),
        (
            "package consumer; import renamed \"example.test/root/strange\"; var Use renamed.Item",
            true,
        ),
        (
            "package consumer; import _ \"example.test/root/strange\"; var Use provider.Item",
            false,
        ),
        (
            "package consumer; import renamed \"example.test/root/strange\"; var Use provider.Item",
            false,
        ),
        (
            "package consumer; import \"example.test/root/strange\"; func f() { type provider struct{}; var Use provider.Item; _ = Use }",
            false,
        ),
    ] {
        let fixture = GoRootResolutionOperationFixture::with_consumer(source_text);
        let context_id = publish_go_root_fixture_context(&fixture, "example.test/root/strange");
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let provider = operation
            .mount_table()
            .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
            .unwrap()
            .unwrap();
        let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            provider.fragment(),
            &operation.ready.shared_names(),
            Language::Go,
            &fixture.provider_facts,
        );
        let expected = semantic_at(
            &artifact,
            site_for_identifier(
                &fixture.provider_facts,
                "Item",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            ),
            LoweredSemanticRole::Definition,
        );
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "Item",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        let go_context::GoDotImportContext::Ready(context) = operation
            .go_import_binding_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
            .unwrap()
        else {
            panic!("selected named import context");
        };
        let answer = operation
            .resolve_reference(
                context,
                &SelectedSemanticLocator::new(
                    "go",
                    GO_ROOT_CONSUMER_PATH,
                    reference,
                    LoweredSemanticRole::Reference,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            answer
        else {
            panic!("selected qualified reference");
        };
        if bound {
            assert_eq!(
                answer.binding().targets(),
                &[expected],
                "{source_text}: {answer:?}"
            );
        } else {
            assert!(
                !answer.binding().targets().contains(&expected),
                "{source_text}: {answer:?}"
            );
        }
    }
}

#[test]
fn selected_go_dot_import_excludes_a_test_variant_of_the_same_file() {
    let fixture = GoRootResolutionOperationFixture::new();
    let context_id = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
    fixture.store.conn.execute(move |connection| {
        let transaction = connection.transaction().unwrap();
        transaction.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps)
            VALUES(?1,'example.test/root/consumer [example.test/root/consumer.test]','consumer','example.test/root/consumer','',zeroblob(32),0,jsonb('[]'))", [context_id]).unwrap();
        let variant = transaction.last_insert_rowid();
        transaction.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role)
            SELECT ?2,files.file_version_id,'go' FROM go_context_source_files files
            JOIN go_package_instances package ON package.package_id=files.package_id
            WHERE files.context_id=?1 AND package.tool_import_path='example.test/root/consumer'", params![context_id,variant]).unwrap();
        transaction.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps)
            SELECT ?1,?2,'example.test/root/provider','go',package_id,0,jsonb('[]') FROM go_package_instances
            WHERE context_id=?1 AND tool_import_path='example.test/root/other/provider'", params![context_id,variant]).unwrap();
        transaction.commit().unwrap();
    });
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let go_context::GoDotImportContext::Ready(context) = operation
        .go_dot_import_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
        .unwrap()
    else {
        panic!("selected ordinary package context");
    };
    let reference = site_for_identifier(
        &fixture.consumer_facts,
        "Item",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let answer = operation
        .resolve_reference(
            context,
            &SelectedSemanticLocator::new(
                "go",
                GO_ROOT_CONSUMER_PATH,
                reference,
                LoweredSemanticRole::Reference,
            ),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
        answer
    else {
        panic!("selected dot-import reference");
    };
    assert_eq!(
        answer.binding().targets().len(),
        1,
        "test variant must not add the decoy: {answer:?}"
    );
}

#[test]
fn selected_go_external_tests_can_name_exports_from_the_selected_internal_test_variant() {
    // Independent compiler control: package provider's export_test.go declares
    // TestItem, and package provider_test refers to provider.TestItem. `go test`
    // accepts it: import authority is the exact ForTest package, not only its
    // ordinary Go files. The decoy package is never part of that import.
    for source in [
        "package consumer_test; import \"example.test/root/provider\"; var Use provider.Item",
        "package consumer_test; import . \"example.test/root/provider\"; var Use Item",
    ] {
        let fixture = GoRootResolutionOperationFixture::with_consumer(source);
        let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
        fixture.store.conn.execute(move |connection| {
            let transaction = connection.transaction().unwrap();
            transaction.execute("UPDATE go_package_instances SET for_test='example.test/root/provider' WHERE context_id=?1 AND tool_import_path IN ('example.test/root/consumer','example.test/root/provider')", [context]).unwrap();
            transaction.execute("UPDATE go_package_files SET source_role='xtest' WHERE package_id IN (SELECT package_id FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/consumer')", [context]).unwrap();
            transaction.execute("UPDATE go_package_files SET source_role='test' WHERE package_id IN (SELECT package_id FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/provider')", [context]).unwrap();
            transaction.execute("UPDATE go_package_imports SET import_role='xtest' WHERE context_id=?1", [context]).unwrap();
            transaction.execute("UPDATE go_package_instances SET package_name='consumer_test' WHERE context_id=?1 AND tool_import_path='example.test/root/consumer'", [context]).unwrap();
            transaction.commit().unwrap();
        });
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let provider = operation
            .mount_table()
            .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
            .unwrap()
            .unwrap();
        let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            provider.fragment(),
            &operation.ready.shared_names(),
            Language::Go,
            &fixture.provider_facts,
        );
        let expected = semantic_at(
            &artifact,
            site_for_identifier(
                &fixture.provider_facts,
                "Item",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            ),
            LoweredSemanticRole::Definition,
        );
        let go_context::GoDotImportContext::Ready(context) = operation
            .go_selected_import_context(context, GO_ROOT_CONSUMER_PATH, &cancellation)
            .unwrap()
        else {
            panic!("selected external test package context");
        };
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "Item",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        let answer = operation
            .resolve_reference(
                context,
                &SelectedSemanticLocator::new(
                    "go",
                    GO_ROOT_CONSUMER_PATH,
                    reference,
                    LoweredSemanticRole::Reference,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            answer
        else {
            panic!("selected test-variant import reference");
        };
        assert_eq!(
            answer.binding().targets(),
            &[expected],
            "{source}: {answer:?}"
        );
    }
}

fn stage_go_import_rows(
    operation: &SelectedResolutionOperation<'_, '_>,
    host: SelectedResolutionMountOrdinal,
    rows: &[crate::analyzer::resolution::LoweredGoPackageImport],
) {
    use super::super::resolution_stage::codec::{encode_node, encode_semantic};
    operation.ready.inventory.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)", params![host.get(), [31_u8;32].as_slice(), [32_u8;32].as_slice()])?;
        let producer = connection.last_insert_rowid();
        for row in rows {
            connection.execute("INSERT INTO temp.selected_resolution_stage_go_package_imports(host_ordinal,producer_id,definition_key,source_site,file_scope_key,spelling_choice_key,start_byte,end_byte,kind) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![host.get(),producer,encode_semantic(row.definition),row.source_site.get(),encode_node(row.file_scope),encode_semantic(row.spelling_choice),i64::try_from(row.start_byte).unwrap(),i64::try_from(row.end_byte).unwrap(),row.kind.label()])?;
        }
        Ok(())
    }).unwrap();
}

#[test]
fn selected_go_import_readers_seek_populated_selected_rows() {
    use super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
    use rusqlite::types::Value::{Integer, Text};
    let consumer =
        "package consumer; import renamed \"example.test/root/provider\"; var Item renamed.Item";
    let mut decoy = String::from("package provider;\n");
    for index in 0..129 {
        decoy.push_str(&format!(
            "import unrelated{index} \"example.test/unrelated/{index}\";\n"
        ));
    }
    decoy.push_str("type Item struct {}\n");
    let fixture =
        GoRootResolutionOperationFixture::with_sources([consumer, GO_ROOT_PROVIDER_SOURCE, &decoy]);
    let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
    // Populate unrelated canonical variants so membership indexes are tested
    // against a real choice of plans, not a three-row table that favors scans.
    fixture.store.conn.execute(move |connection| {
        let transaction = connection.transaction().unwrap();
        let version: i64 = transaction.query_row("SELECT file_version_id FROM go_context_source_files WHERE context_id=?1 AND rel_path=?2", params![context, GO_ROOT_PROVIDER_PATH], |row| row.get(0)).unwrap();
        for index in 0..512 {
            transaction.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps) VALUES(?1,?2,'provider',?2,'',zeroblob(32),0,jsonb('[]'))", params![context, format!("example.test/variant{index}")]).unwrap();
            let package = transaction.last_insert_rowid();
            transaction.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role) VALUES(?1,?2,'go')", params![package,version]).unwrap();
        }
        transaction.commit().unwrap();
    });
    let cancellation = CancellationToken::new();
    for statistics in [false, true] {
        if statistics {
            fixture.store.refresh_planner_statistics().unwrap();
        } else {
            fixture.store.clear_planner_statistics().unwrap();
        }
        let operation = fixture.open_ready(&cancellation);
        for (path, facts) in [
            (GO_ROOT_CONSUMER_PATH, &fixture.consumer_facts),
            (GO_ROOT_DECOY_PATH, &fixture.decoy_facts),
        ] {
            let source = operation
                .mount_table()
                .mount_for_path("go", path)
                .unwrap()
                .unwrap();
            let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
                source.fragment(),
                &operation.ready.shared_names(),
                Language::Go,
                facts,
            );
            stage_go_import_rows(
                &operation,
                source.ordinal(),
                &lowered.common().go_package_imports,
            );
        }
        let source = operation
            .mount_table()
            .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let version = operation
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())
            .unwrap()
            .file_version_id()
            .unwrap();
        let connection = operation.ready.inventory.connection();
        if statistics {
            connection.execute_batch("ANALYZE temp").unwrap();
        }
        let caller: i64 = connection
            .query_row(
                go_same_package::CALLER_PACKAGE,
                params![context, version, "go"],
                |row| row.get(0),
            )
            .unwrap();
        let target: i64 = connection
            .query_row(
                go_named::IMPORT_PACKAGE_NAME,
                params![context, caller, "go", "example.test/root/provider"],
                |row| row.get(1),
            )
            .unwrap();
        for (label, parameters, sought) in [
            (
                "go_named_import_bindings",
                vec![Integer(i64::from(source.ordinal().get()))],
                "p",
            ),
            (
                "go_named_stage_import_bindings",
                vec![Integer(i64::from(source.ordinal().get()))],
                "p",
            ),
            (
                "go_named_import_package_name",
                vec![
                    Integer(context),
                    Integer(caller),
                    Text("go".into()),
                    Text("example.test/root/provider".into()),
                ],
                "imports",
            ),
            (
                "go_named_import_target_mounts",
                vec![Integer(context), Integer(target)],
                "members",
            ),
            (
                "go_caller_source_role",
                vec![Integer(context), Integer(version)],
                "members",
            ),
            (
                "go_caller_package",
                vec![Integer(context), Integer(version), Text("go".into())],
                "members",
            ),
            (
                "go_package_peer_mounts",
                vec![Integer(context), Integer(caller), Text("go".into())],
                "members",
            ),
        ] {
            let mut pin = pinned(label);
            pin.params = parameters;
            let count = connection
                .prepare(&pin.sql)
                .unwrap()
                .query_map(rusqlite::params_from_iter(pin.params.iter()), |_| Ok(()))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .len();
            assert_eq!(count, 1, "{label} must read the relevant populated row");
            let plan = explain_pin(connection, &pin);
            assert!(
                plan.iter()
                    .any(|line| line.contains(&format!("SEARCH {sought} "))),
                "{label}, statistics={statistics}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.contains("AUTOMATIC")
                    || line.contains("TEMP B-TREE")
                    || line.contains(&format!("SCAN {sought}"))),
                "{label}, statistics={statistics}: {plan:?}"
            );
        }
    }
}

#[test]
fn go_definition_package_anchor_seeks_exact_selected_version() {
    use super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
    let fixture = GoRootResolutionOperationFixture::new();
    let version = fixture.store.conn.execute(|connection| {
        let transaction = connection.transaction().unwrap();
        let version: i64 = transaction.query_row(
            "SELECT file_version_id FROM workspace_file_versions WHERE lang='go' AND rel_path=?1",
            [GO_ROOT_PROVIDER_PATH], |row| row.get(0),
        ).unwrap();
        transaction.execute("INSERT INTO workspace_file_anchor_rows(file_version_id,anchor_kind,anchor_pop,package_name) VALUES(?1,'own_module',0,'example.test/root/provider')", [version]).unwrap();
        for index in 0..512 {
            transaction.execute(
                "INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from)
                 SELECT workspace_id,lang,generation,?2,blob_oid,projection_digest,valid_from
                 FROM workspace_file_versions WHERE file_version_id=?1",
                params![version,format!("unrelated{index}/provider.go")],
            ).unwrap();
            let unrelated = transaction.last_insert_rowid();
            transaction.execute("INSERT INTO workspace_file_anchor_rows(file_version_id,anchor_kind,anchor_pop,package_name) VALUES(?1,'own_module',0,?2)",params![unrelated,format!("example.test/root/unrelated{index}")]).unwrap();
        }
        transaction.commit().unwrap();
        version
    });
    for statistics in [false, true] {
        if statistics {
            fixture.store.refresh_planner_statistics().unwrap();
        } else {
            fixture.store.clear_planner_statistics().unwrap();
        }
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let connection = operation.ready.inventory.connection();
        let mut pin = pinned("go_definition_package_anchor");
        pin.params = vec![rusqlite::types::Value::Integer(version)];
        let package: String = connection
            .query_row(&pin.sql, [version], |row| row.get(0))
            .unwrap();
        assert_eq!(package, "example.test/root/provider");
        let plan = explain_pin(connection, &pin);
        assert!(
            plan.iter().any(|line| line.contains("SEARCH anchors")
                && line.contains("file_version_id=?")
                && line.contains("anchor_kind=?")
                && line.contains("anchor_pop=?")),
            "statistics={statistics}: {plan:?}"
        );
        for forbidden in ["SCAN anchors", "AUTOMATIC", "TEMP B-TREE"] {
            assert!(
                !plan.iter().any(|line| line.contains(forbidden)),
                "statistics={statistics}: {plan:?}"
            );
        }
    }
}
