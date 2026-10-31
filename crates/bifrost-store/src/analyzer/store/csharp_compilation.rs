//! Durable C# compilation membership.
//!
//! C# merges the global namespace across a compilation and the projects it
//! references, so type lookup must know which compilation holds a source file.
//! One revision's MSBuild configuration inputs (`.csproj`, `.props`,
//! `.targets`) derive a set of membership rules: one compilation per project,
//! its default Compile glob, its explicit Compile items and its resolved
//! ProjectReference edges. The set is keyed by the ordered configuration paths
//! and contents and the derivation version, so every revision with the same
//! configuration shares it, and a source edit publishes no new rules.
//!
//! Readers evaluate the rules per demand against the revision's selected
//! source rows and walk references with a recursive query. No reader retains
//! the relation: a structure keyed by workspace files that outlived a request
//! is the forbidden heap shape of the architecture guidance.
//!
//! Validity rule, used by publisher and readers alike: a revision's selection
//! names a set whose `derivation_version` is [`DERIVATION_VERSION`]. A
//! revision without one (unpublished, published by an older derivation, or
//! whose retained configuration bytes were missing) proves nothing; the next
//! publication of that revision retries.

use super::{AnalyzerStore, ReaderGuard, Result, WorkspaceSnapshotId};
use crate::analyzer::canonical_hash::CanonicalHasher;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Increment when the rules derived from the same inputs change. Older sets
/// stop satisfying the validity rule and the next publication replaces them.
// v4 retains ancestor absence and rejects unmodeled SDK imports.
// v3 includes symbol derivation and the SDK 10.0.403 implicit-symbol table v1.
pub const DERIVATION_VERSION: i64 = 4;
/// Rotate this table identity and DERIVATION_VERSION together when SDK rules change.
pub const IMPLICIT_SYMBOL_TABLE_VERSION: &[u8] = b"sdk-10.0.403-v1";
/// The storage language whose revisions publish compilation membership.
pub const STORAGE_LANGUAGE: &str = "csharp";
const MAX_CONFIGURATION_FILES: usize = 16 * 1024;
const MAX_CONFIGURATION_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONFIGURATION_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// One selected configuration input, in path order.
#[derive(Debug)]
pub struct CSharpConfigurationInput {
    pub rel_path: String,
    /// `None` when the input exceeded a byte cap and was not read.
    pub source: Option<Vec<u8>>,
}

/// The membership rules one configuration derives.
#[derive(Debug, Default)]
pub struct CSharpCompilationFacts {
    /// Ordered by project path; an implicit compilation (no project) is alone.
    pub compilations: Vec<CSharpCompilationFact>,
    /// Whether the rules state all source membership. Any gap that can add or
    /// remove a source anywhere (an unread input, a Directory.Build file, an
    /// `Import`, a conditioned or dynamic item) clears it.
    pub membership_complete: bool,
    pub gaps: Vec<CSharpCompilationGap>,
}

#[derive(Debug, Default)]
pub struct CSharpCompilationFact {
    /// Workspace-relative project path, `None` for the implicit compilation,
    /// which holds every selected source.
    pub project_path: Option<String>,
    /// Compile items in evaluation order, the SDK default glob among them.
    pub items: Vec<CSharpCompileItem>,
    /// Project paths of proven ProjectReference targets, each the
    /// `project_path` of another fact in the same set.
    pub references: Vec<String>,
    /// Whether `references` are all of the project's direct references.
    pub references_complete: bool,
    /// Whether the project receives its references' references by the SDK
    /// default, so readers may walk its edges transitively.
    pub transitive_flow: bool,
    pub metadata: CSharpCompilationMetadata,
    pub symbols: CSharpSymbolEnvironment,
}

/// One selected compilation environment. Open environments deliberately list no symbols.
#[derive(Debug)]
pub struct CSharpSymbolEnvironment {
    pub configuration: String,
    pub target_framework: Option<String>,
    pub open_reason: Option<String>,
    pub symbols: Vec<(String, String)>,
}

impl Default for CSharpSymbolEnvironment {
    fn default() -> Self {
        Self {
            configuration: "Debug".into(),
            target_framework: None,
            open_reason: Some("loose_files".into()),
            symbols: Vec::new(),
        }
    }
}

impl CSharpSymbolEnvironment {
    pub fn digest(&self) -> [u8; 32] {
        debug_assert!(self.open_reason.is_none() || self.symbols.is_empty());
        let mut hash =
            CanonicalHasher::new(b"csharp-symbol-environment:derivation-v1:sdk-10.0.403-v1");
        hash.field("configuration", self.configuration.as_bytes());
        hash.field(
            "framework",
            self.target_framework.as_deref().unwrap_or("").as_bytes(),
        );
        hash.field(
            "open_reason",
            self.open_reason.as_deref().unwrap_or("").as_bytes(),
        );
        for (symbol, source) in &self.symbols {
            hash.field(source, symbol.as_bytes());
        }
        hash.finish()
    }
}

/// Configuration facts read whole for one compilation, never retained as a workspace index.
#[derive(Debug, Default, PartialEq)]
pub struct CSharpCompilationMetadata {
    /// None when configuration cannot establish an assembly name (including a loose compilation).
    pub assembly_name: Option<String>,
    pub global_usings: Vec<CSharpGlobalUsing>,
    pub global_usings_complete: bool,
    pub internals_visible_to: Vec<String>,
    pub internals_visible_to_complete: bool,
}

/// SQL-readable positional [kind, segments, alias, origin] entry.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CSharpGlobalUsing(pub String, pub Vec<String>, pub Option<String>, pub String);

#[derive(Debug)]
pub struct CSharpCompileItem {
    pub kind: CSharpCompileItemKind,
    /// A file, or for a tree the directory.
    pub rel_path: String,
    /// For a tree, directories it leaves out.
    pub excluded_trees: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CSharpCompileItemKind {
    Include,
    /// Every C# source below `rel_path`, outside `excluded_trees`.
    IncludeTree,
    /// The SDK default Compile glob of a project directory: an
    /// [`Self::IncludeTree`] that also leaves out directories whose names
    /// start with `.` (`**/.*/**`), with the build output roots as
    /// `excluded_trees`.
    DefaultTree,
    Remove,
}

impl CSharpCompileItemKind {
    fn label(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::IncludeTree => "include_tree",
            Self::DefaultTree => "default_tree",
            Self::Remove => "remove",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CSharpCompilationGap {
    pub code: String,
    pub path: String,
    pub evidence: String,
}

pub(super) const COMPILATION_METADATA_SQL: &str =
    "SELECT assembly_name, global_usings_complete, internals_visible_to_complete,
                    json(global_usings), json(internals_visible_to)
             FROM csharp_compilations WHERE set_id = ?1 AND project_path IS ?2";

pub(super) const SELECTED_SET_SQL: &str =
    "SELECT sets.set_id, sets.membership_complete, sets.derivation_version
     FROM csharp_compilation_selections AS selections
     JOIN csharp_compilation_sets AS sets ON sets.set_id = selections.set_id
     WHERE selections.workspace_id = ?1 AND selections.lang = ?2
       AND selections.generation = ?3 AND selections.revision = ?4";

const CONFIGURATION_IDENTITIES_SQL: &str = "SELECT rel_path, blob_oid
     FROM workspace_file_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND input_kind = 'configuration'
       AND valid_from <= ?4 AND (valid_until IS NULL OR ?4 < valid_until)
     ORDER BY rel_path";

const CONFIGURATION_BYTES_SQL: &str = "SELECT versions.rel_path, length(retained.source_bytes),
            CASE WHEN length(retained.source_bytes) <= ?5 THEN retained.source_bytes END
     FROM workspace_file_versions AS versions
     LEFT JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
     WHERE versions.workspace_id = ?1 AND versions.lang = ?2 AND versions.generation = ?3
       AND versions.input_kind = 'configuration'
       AND versions.valid_from <= ?4 AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)
     ORDER BY versions.rel_path
     LIMIT ?6";

pub(super) const SELECTED_SOURCE_SQL: &str = "SELECT 1
     FROM workspace_file_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND input_kind = 'source' AND rel_path = ?4
       AND valid_from <= ?5 AND (valid_until IS NULL OR ?5 < valid_until)";

pub(super) const IMPLICIT_COMPILATION_SQL: &str = "SELECT compilation_id
     FROM csharp_compilations
     WHERE set_id = ?1 AND project_path IS NULL";

pub(super) const PATH_ITEMS_SQL: &str = "SELECT compilation_id, ordinal, kind
     FROM csharp_compilation_items
     WHERE set_id = ?1 AND rel_path = ?2 AND kind IN ('include', 'remove')";

/// Trees rooted at an ancestor directory of a path.
pub(super) const TREE_ITEMS_SQL: &str =
    "SELECT compilation_id, ordinal, kind = 'default_tree', rel_path, json(excluded_trees)
     FROM csharp_compilation_items
     WHERE set_id = ?1 AND kind IN ('include_tree', 'default_tree')
       AND rel_path IN (SELECT value FROM json_each(?2))";

/// Every compilation `?1` reaches over any edge, with whether its direct
/// references are complete: the bound on what `?1` can possibly see.
pub(super) const REFERENCE_CLOSURE_SQL: &str = "WITH RECURSIVE reach(compilation_id) AS (
         SELECT ?1
         UNION
         SELECT edges.target_compilation_id
         FROM csharp_project_references AS edges
         JOIN reach ON edges.from_compilation_id = reach.compilation_id
     )
     SELECT compilations.compilation_id, compilations.references_complete
     FROM reach
     JOIN csharp_compilations AS compilations
       ON compilations.compilation_id = reach.compilation_id";

/// The compilations `?1` provably sees: itself, its direct edges, and edges
/// beyond them only while both `?1` and each intermediate project flow
/// references transitively.
pub(super) const VISIBLE_CLOSURE_SQL: &str = "WITH RECURSIVE reach(compilation_id, expand) AS (
         SELECT ?1, 1
         UNION
         SELECT edges.target_compilation_id,
                targets.transitive_flow
                  AND (SELECT root.transitive_flow FROM csharp_compilations AS root
                       WHERE root.compilation_id = ?1)
         FROM reach
         JOIN csharp_project_references AS edges
           ON edges.from_compilation_id = reach.compilation_id
         JOIN csharp_compilations AS targets
           ON targets.compilation_id = edges.target_compilation_id
         WHERE reach.expand
     )
     SELECT compilation_id FROM reach";

pub(super) const PROJECT_COUNT_SQL: &str = "SELECT count(*)
     FROM csharp_compilations
     WHERE set_id = ?1 AND project_path IS NOT NULL";

pub(super) const UNSELECTED_INCLUDE_SQL: &str = "SELECT EXISTS(
         SELECT 1 FROM csharp_compilation_items AS items
         WHERE items.set_id = ?1 AND items.kind = 'include'
           AND NOT EXISTS(
               SELECT 1 FROM workspace_file_versions AS versions
               WHERE versions.workspace_id = ?2 AND versions.lang = ?3
                 AND versions.generation = ?4 AND versions.input_kind = 'source'
                 AND versions.rel_path = items.rel_path
                 AND versions.valid_from <= ?5
                 AND (versions.valid_until IS NULL OR ?5 < versions.valid_until)))";

/// Derive and select this revision's compilation membership, in the
/// transaction that publishes the revision.
pub(super) fn publish(tx: &Transaction<'_>, snapshot: &WorkspaceSnapshotId) -> Result<()> {
    if snapshot.lang != STORAGE_LANGUAGE {
        return Ok(());
    }
    let Some(support) = super::store_language_support(crate::analyzer::Language::CSharp) else {
        return Ok(());
    };
    let selected = tx
        .query_row(SELECTED_SET_SQL, snapshot_params(snapshot), |row| {
            row.get::<_, i64>(2)
        })
        .optional()?;
    if selected == Some(DERIVATION_VERSION) {
        return Ok(());
    }

    let mut hasher = CanonicalHasher::new(b"bifrost-csharp-compilation-inputs:v1");
    hasher.field("implicit_symbol_table", IMPLICIT_SYMBOL_TABLE_VERSION);
    {
        let mut identities = tx.prepare_cached(CONFIGURATION_IDENTITIES_SQL)?;
        let mut rows = identities.query(snapshot_params(snapshot))?;
        while let Some(row) = rows.next()? {
            hasher.field(
                &row.get::<_, String>(0)?,
                row.get::<_, String>(1)?.as_bytes(),
            );
        }
    }
    let input_digest = hasher.finish();
    let existing = tx
        .query_row(
            "SELECT set_id FROM csharp_compilation_sets
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
               AND derivation_version = ?4 AND input_digest = ?5",
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.0,
                DERIVATION_VERSION,
                input_digest.as_slice()
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let set_id = match existing {
        Some(set_id) => set_id,
        None => {
            let Some((inputs, mut store_gaps)) = selected_inputs(tx, snapshot)? else {
                // A selected input without retained bytes proves nothing.
                // Leave the revision unselected so the next publication
                // retries rather than freezing an incomplete set.
                return Ok(());
            };
            let Some(mut facts) = support.csharp_compilation_facts(&inputs) else {
                // A support without the C# producer (a neutral test fixture)
                // publishes nothing; readers see an unproven revision.
                return Ok(());
            };
            if !store_gaps.is_empty() {
                facts.membership_complete = false;
                for compilation in &mut facts.compilations {
                    compilation.metadata.assembly_name = None;
                    compilation.metadata.global_usings_complete = false;
                    compilation.metadata.internals_visible_to_complete = false;
                }
                facts.gaps.append(&mut store_gaps);
            }
            insert_set(tx, snapshot, &input_digest, &facts)?
        }
    };
    tx.execute(
        "INSERT INTO csharp_compilation_selections(workspace_id, lang, generation, revision, set_id)
         VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(workspace_id, lang, generation, revision) DO UPDATE SET set_id = excluded.set_id",
        params![
            snapshot.workspace_id.as_str(),
            snapshot.lang,
            snapshot.generation.0,
            snapshot.revision,
            set_id
        ],
    )?;
    Ok(())
}

fn snapshot_params(snapshot: &WorkspaceSnapshotId) -> (&str, &str, i64, i64) {
    (
        snapshot.workspace_id.as_str(),
        snapshot.lang.as_str(),
        snapshot.generation.0,
        snapshot.revision,
    )
}

/// The revision's configuration inputs within the publication caps, plus a
/// gap for each cap that omitted inputs. `None` when a selected input has no
/// retained bytes.
fn selected_inputs(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<(Vec<CSharpConfigurationInput>, Vec<CSharpCompilationGap>)>> {
    let mut inputs = Vec::new();
    let mut gaps = Vec::new();
    let mut total = 0_usize;
    let mut statement = tx.prepare_cached(CONFIGURATION_BYTES_SQL)?;
    let mut rows = statement.query(params![
        snapshot.workspace_id.as_str(),
        snapshot.lang,
        snapshot.generation.0,
        snapshot.revision,
        MAX_CONFIGURATION_FILE_BYTES,
        MAX_CONFIGURATION_FILES.saturating_add(1)
    ])?;
    while let Some(row) = rows.next()? {
        let rel_path = row.get::<_, String>(0)?;
        if inputs.len() == MAX_CONFIGURATION_FILES {
            gaps.push(CSharpCompilationGap {
                code: "configuration_file_cap".into(),
                path: rel_path,
                evidence: format!("more than {MAX_CONFIGURATION_FILES} configuration inputs"),
            });
            break;
        }
        let Some(length) = row.get::<_, Option<usize>>(1)? else {
            return Ok(None);
        };
        let source = row.get::<_, Option<Vec<u8>>>(2)?;
        let source = match source {
            Some(source) if total.saturating_add(length) <= MAX_CONFIGURATION_TOTAL_BYTES => {
                total += length;
                Some(source)
            }
            Some(_) => {
                gaps.push(CSharpCompilationGap {
                    code: "configuration_total_byte_cap".into(),
                    path: rel_path.clone(),
                    evidence: format!(
                        "configuration inputs exceed {MAX_CONFIGURATION_TOTAL_BYTES} bytes"
                    ),
                });
                None
            }
            None => None,
        };
        inputs.push(CSharpConfigurationInput { rel_path, source });
    }
    Ok(Some((inputs, gaps)))
}

fn insert_set(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
    input_digest: &[u8; 32],
    facts: &CSharpCompilationFacts,
) -> Result<i64> {
    let mut output = CanonicalHasher::new(b"bifrost-csharp-compilation-rules:v2");
    output.field(
        "membership_complete",
        &[u8::from(facts.membership_complete)],
    );
    for compilation in &facts.compilations {
        output.field(
            "project",
            compilation.project_path.as_deref().unwrap_or("").as_bytes(),
        );
        output.field("implicit", &[u8::from(compilation.project_path.is_none())]);
        output.field(
            "references_complete",
            &[u8::from(compilation.references_complete)],
        );
        output.field("transitive_flow", &[u8::from(compilation.transitive_flow)]);
        output.field("symbols", &compilation.symbols.digest());
        let metadata = &compilation.metadata;
        output.field(
            "assembly_name",
            &serde_json::to_vec(&metadata.assembly_name).expect("name serializes"),
        );
        output.field(
            "global_usings",
            &serde_json::to_vec(&metadata.global_usings).expect("usings serialize"),
        );
        output.field(
            "global_usings_complete",
            &[u8::from(metadata.global_usings_complete)],
        );
        output.field(
            "internals_visible_to",
            &serde_json::to_vec(&metadata.internals_visible_to).expect("friends serialize"),
        );
        output.field(
            "internals_visible_to_complete",
            &[u8::from(metadata.internals_visible_to_complete)],
        );
        for item in &compilation.items {
            output.field(item.kind.label(), item.rel_path.as_bytes());
            for excluded in &item.excluded_trees {
                output.field("excluded_tree", excluded.as_bytes());
            }
        }
        for reference in &compilation.references {
            output.field("reference", reference.as_bytes());
        }
    }
    // Gaps are caller-visible through `gaps()`, so they are output too.
    for gap in &facts.gaps {
        output.field("gap_code", gap.code.as_bytes());
        output.field("gap_path", gap.path.as_bytes());
        output.field("gap_evidence", gap.evidence.as_bytes());
    }
    let output_digest = output.finish();
    let gaps = serde_json::to_string(
        &facts
            .gaps
            .iter()
            .map(|gap| [&gap.code, &gap.path, &gap.evidence])
            .collect::<Vec<_>>(),
    )
    .expect("string triples serialize");
    tx.execute(
        "INSERT INTO csharp_compilation_sets(
           workspace_id, lang, generation, derivation_version, input_digest, output_digest,
           membership_complete, gaps
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, jsonb(?8))",
        params![
            snapshot.workspace_id.as_str(),
            snapshot.lang,
            snapshot.generation.0,
            DERIVATION_VERSION,
            input_digest.as_slice(),
            output_digest.as_slice(),
            facts.membership_complete,
            gaps
        ],
    )?;
    let set_id = tx.last_insert_rowid();

    let mut ids = crate::hash::HashMap::default();
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO csharp_compilations(
               set_id, project_path, references_complete, transitive_flow,
               assembly_name, global_usings_complete, internals_visible_to_complete,
               global_usings, internals_visible_to, configuration, target_framework,
               symbols_closed, open_reason, symbol_set_digest
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, jsonb(?8), jsonb(?9), ?10, ?11, ?12, ?13, ?14)",
        )?;
        let mut items = tx.prepare_cached(
            "INSERT INTO csharp_compilation_items(
               compilation_id, ordinal, set_id, kind, rel_path, excluded_trees
             ) VALUES(?1, ?2, ?3, ?4, ?5, jsonb(?6))",
        )?;
        for compilation in &facts.compilations {
            insert.execute(params![
                set_id,
                compilation.project_path,
                compilation.references_complete,
                compilation.transitive_flow,
                compilation.metadata.assembly_name,
                compilation.metadata.global_usings_complete,
                compilation.metadata.internals_visible_to_complete,
                serde_json::to_string(&compilation.metadata.global_usings)
                    .expect("usings serialize"),
                serde_json::to_string(&compilation.metadata.internals_visible_to)
                    .expect("friends serialize"),
                compilation.symbols.configuration,
                compilation.symbols.target_framework,
                compilation.symbols.open_reason.is_none(),
                compilation.symbols.open_reason,
                compilation.symbols.digest().as_slice()
            ])?;
            let compilation_id = tx.last_insert_rowid();
            for (symbol, source) in &compilation.symbols.symbols {
                tx.execute(
                    "INSERT INTO csharp_compilation_symbols(compilation_id, symbol, source) VALUES(?1, ?2, ?3)",
                    params![compilation_id, symbol, source],
                )?;
            }
            if let Some(path) = compilation.project_path.as_deref() {
                assert!(
                    ids.insert(path, compilation_id).is_none(),
                    "one compilation per project path: {path}"
                );
            }
            for (ordinal, item) in compilation.items.iter().enumerate() {
                let excluded_trees = matches!(
                    item.kind,
                    CSharpCompileItemKind::IncludeTree | CSharpCompileItemKind::DefaultTree
                )
                .then(|| serde_json::to_string(&item.excluded_trees).expect("strings serialize"));
                items.execute(params![
                    compilation_id,
                    ordinal,
                    set_id,
                    item.kind.label(),
                    item.rel_path,
                    excluded_trees
                ])?;
            }
        }
    }
    let mut edges = tx.prepare_cached(
        "INSERT OR IGNORE INTO csharp_project_references(from_compilation_id, target_compilation_id)
         VALUES(?1, ?2)",
    )?;
    for compilation in &facts.compilations {
        let Some(path) = compilation.project_path.as_deref() else {
            assert!(
                compilation.references.is_empty(),
                "the implicit compilation has no references"
            );
            continue;
        };
        for reference in &compilation.references {
            let target = ids.get(reference.as_str()).unwrap_or_else(|| {
                panic!("{path} references {reference}, which is not a compilation in its set")
            });
            edges.execute(params![ids[path], target])?;
        }
    }
    Ok(set_id)
}

/// One revision's selected compilation rules, read per demand.
pub struct SelectedCSharpCompilations<'a> {
    conn: ReaderGuard<'a>,
    snapshot: WorkspaceSnapshotId,
    set_id: i64,
    membership_complete: bool,
}

impl AnalyzerStore {
    /// The compilation rules `snapshot` selects, or `None` when the revision
    /// has no selection that satisfies the validity rule.
    #[doc(hidden)]
    pub fn selected_csharp_compilations(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<Option<SelectedCSharpCompilations<'_>>> {
        let conn = self.read_conn()?;
        let Some((set_id, membership_complete)) = selected_set(&conn, snapshot)? else {
            return Ok(None);
        };
        Ok(Some(SelectedCSharpCompilations {
            conn,
            snapshot: snapshot.clone(),
            set_id,
            membership_complete,
        }))
    }
}

fn selected_set(conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<Option<(i64, bool)>> {
    let selected = conn
        .query_row(SELECTED_SET_SQL, snapshot_params(snapshot), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .optional()?;
    let Some((set_id, membership_complete, DERIVATION_VERSION)) = selected else {
        return Ok(None);
    };
    Ok(Some((set_id, membership_complete)))
}

/// A borrowed view of one revision's compilation rules, with no retained rows.
/// The shared selection's connection is the one an operation already holds;
/// a second checkout would deadlock a single-connection store. The production
/// owner keeps its ReaderGuard and delegates each read through this view.
pub(super) struct CSharpCompilationView<'a> {
    conn: &'a Connection,
    snapshot: &'a WorkspaceSnapshotId,
    set_id: i64,
    membership_complete: bool,
}

impl SelectedCSharpCompilations<'_> {
    fn view(&self) -> CSharpCompilationView<'_> {
        CSharpCompilationView {
            conn: &self.conn,
            snapshot: &self.snapshot,
            set_id: self.set_id,
            membership_complete: self.membership_complete,
        }
    }

    /// Assembly and compilation-wide imports for one selected compilation.
    pub fn metadata(
        &self,
        project_path: Option<&str>,
    ) -> Result<Option<CSharpCompilationMetadata>> {
        self.view().metadata(project_path)
    }

    /// Whether the rules state all source membership.
    pub fn membership_complete(&self) -> bool {
        self.view().membership_complete()
    }

    /// Selected source memberships; None when membership is unproven.
    pub fn compilations_of(&self, rel_path: &str) -> Result<Option<Vec<i64>>> {
        self.view().compilations_of(rel_path)
    }

    /// All reference edges reachable from root, and their completeness.
    pub fn referenced_closure(&self, root: i64) -> Result<(Vec<i64>, bool)> {
        self.view().referenced_closure(root)
    }

    /// Compilations provably visible from root, including root itself.
    pub fn visible_closure(&self, root: i64) -> Result<Vec<i64>> {
        self.view().visible_closure(root)
    }

    /// Project count; zero denotes the implicit compilation.
    pub fn project_count(&self) -> Result<usize> {
        self.view().project_count()
    }

    /// Whether every explicit include selects a source in this revision.
    pub fn includes_selected(&self) -> Result<bool> {
        self.view().includes_selected()
    }

    /// The selected set's recorded diagnostic gaps.
    pub fn gaps(&self) -> Result<Vec<CSharpCompilationGap>> {
        self.view().gaps()
    }
}

impl<'a> CSharpCompilationView<'a> {
    // Its readers, C#'s demand installer and unit reader, are trial code.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn selected(
        conn: &'a Connection,
        snapshot: &'a WorkspaceSnapshotId,
    ) -> Result<Option<Self>> {
        Ok(
            selected_set(conn, snapshot)?.map(|(set_id, membership_complete)| Self {
                conn,
                snapshot,
                set_id,
                membership_complete,
            }),
        )
    }

    /// Assembly and compilation-wide imports for one member of this selection.
    pub(super) fn metadata(
        &self,
        project_path: Option<&str>,
    ) -> Result<Option<CSharpCompilationMetadata>> {
        let row = self
            .conn
            .query_row(
                COMPILATION_METADATA_SQL,
                params![self.set_id, project_path],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(
            |(
                assembly_name,
                global_usings_complete,
                internals_visible_to_complete,
                usings,
                friends,
            )| {
                Ok(CSharpCompilationMetadata {
                    assembly_name,
                    global_usings_complete,
                    internals_visible_to_complete,
                    global_usings: serde_json::from_str(&usings).map_err(|error| {
                        super::StoreError::corrupt(format!("invalid C# global usings: {error}"))
                    })?,
                    internals_visible_to: serde_json::from_str(&friends).map_err(|error| {
                        super::StoreError::corrupt(format!("invalid C# friend assemblies: {error}"))
                    })?,
                })
            },
        )
        .transpose()
    }

    /// Whether the rules state all source membership.
    pub(super) fn membership_complete(&self) -> bool {
        self.membership_complete
    }

    /// The compilations that contain the selected source `rel_path`, possibly
    /// none. `None` when membership is not proven: the rules are incomplete
    /// or the revision does not select that source.
    pub(super) fn compilations_of(&self, rel_path: &str) -> Result<Option<Vec<i64>>> {
        if !self.membership_complete {
            return Ok(None);
        }
        let selected = self
            .conn
            .prepare_cached(SELECTED_SOURCE_SQL)?
            .query_row(
                params![
                    self.snapshot.workspace_id.as_str(),
                    self.snapshot.lang,
                    self.snapshot.generation.0,
                    rel_path,
                    self.snapshot.revision
                ],
                |_| Ok(()),
            )
            .optional()?;
        if selected.is_none() {
            return Ok(None);
        }

        let mut ancestors = vec![String::new()];
        let mut end = 0;
        while let Some(offset) = rel_path[end..].find('/') {
            end += offset;
            ancestors.push(rel_path[..end].to_owned());
            end += 1;
        }
        let ancestors = serde_json::to_string(&ancestors).expect("strings serialize");
        let mut members = crate::hash::HashMap::default();
        if let Some(implicit) = self
            .conn
            .prepare_cached(IMPLICIT_COMPILATION_SQL)?
            .query_row(params![self.set_id], |row| row.get::<_, i64>(0))
            .optional()?
        {
            members.insert(implicit, true);
        }
        // Items in evaluation order; the last one claiming the path decides
        // it.
        let mut items = Vec::new();
        {
            let mut statement = self.conn.prepare_cached(PATH_ITEMS_SQL)?;
            let mut rows = statement.query(params![self.set_id, rel_path])?;
            while let Some(row) = rows.next()? {
                let member = match row.get::<_, String>(2)?.as_str() {
                    "include" => true,
                    "remove" => false,
                    other => unreachable!("the query selects item kinds: {other}"),
                };
                items.push((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, member));
            }
        }
        let is_csharp = rel_path
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("cs"));
        if is_csharp {
            let mut statement = self.conn.prepare_cached(TREE_ITEMS_SQL)?;
            let mut rows = statement.query(params![self.set_id, ancestors])?;
            while let Some(row) = rows.next()? {
                let default_tree = row.get::<_, bool>(2)?;
                let root = row.get::<_, String>(3)?;
                let excluded: Vec<String> = serde_json::from_str(&row.get::<_, String>(4)?)
                    .expect("excluded_trees holds strings");
                let below = |tree: &str| {
                    tree.is_empty()
                        || rel_path
                            .strip_prefix(tree)
                            .is_some_and(|rest| rest.starts_with('/'))
                };
                // The SDK's `**/.*/**` exclude: a directory below the project
                // whose name starts with `.`.
                let hidden = default_tree && {
                    let relative = if root.is_empty() {
                        rel_path
                    } else {
                        &rel_path[root.len() + 1..]
                    };
                    relative
                        .split('/')
                        .rev()
                        .skip(1)
                        .any(|directory| directory.starts_with('.'))
                };
                if !hidden && !excluded.iter().any(|tree| below(tree)) {
                    items.push((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, true));
                }
            }
        }
        items.sort_unstable();
        for (compilation_id, _, member) in items {
            members.insert(compilation_id, member);
        }
        let mut compilations = members
            .into_iter()
            .filter_map(|(compilation_id, member)| member.then_some(compilation_id))
            .collect::<Vec<_>>();
        compilations.sort_unstable();
        Ok(Some(compilations))
    }

    /// Every compilation `root` reaches over any ProjectReference edge,
    /// itself included, and whether each one's direct references are all
    /// known. A compilation outside a complete closure is provably invisible.
    pub(super) fn referenced_closure(&self, root: i64) -> Result<(Vec<i64>, bool)> {
        let mut statement = self.conn.prepare_cached(REFERENCE_CLOSURE_SQL)?;
        let mut rows = statement.query(params![root])?;
        let mut reached = Vec::new();
        let mut complete = true;
        while let Some(row) = rows.next()? {
            reached.push(row.get::<_, i64>(0)?);
            complete &= row.get::<_, bool>(1)?;
        }
        reached.sort_unstable();
        Ok((reached, complete))
    }

    /// The compilations `root` provably sees through proven edges and
    /// proven transitive flow, itself included.
    pub(super) fn visible_closure(&self, root: i64) -> Result<Vec<i64>> {
        let mut statement = self.conn.prepare_cached(VISIBLE_CLOSURE_SQL)?;
        let mut visible = statement
            .query_map(params![root], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // A compilation can be reached both expanding and not.
        visible.sort_unstable();
        visible.dedup();
        Ok(visible)
    }

    /// How many project files the configuration declares. Zero means the
    /// one implicit compilation of every selected source.
    pub(super) fn project_count(&self) -> Result<usize> {
        Ok(self
            .conn
            .prepare_cached(PROJECT_COUNT_SQL)?
            .query_row(params![self.set_id], |row| row.get::<_, usize>(0))?)
    }

    /// Whether every explicit Compile Include names a source the revision
    /// selects. An unselected include is a compilation member whose global
    /// directives and declarations this analysis cannot see.
    pub(super) fn includes_selected(&self) -> Result<bool> {
        Ok(!self
            .conn
            .prepare_cached(UNSELECTED_INCLUDE_SQL)?
            .query_row(
                params![
                    self.set_id,
                    self.snapshot.workspace_id.as_str(),
                    self.snapshot.lang,
                    self.snapshot.generation.0,
                    self.snapshot.revision
                ],
                |row| row.get::<_, bool>(0),
            )?)
    }

    /// The set's recorded gaps, for diagnostics.
    pub(super) fn gaps(&self) -> Result<Vec<CSharpCompilationGap>> {
        let gaps: String = self.conn.query_row(
            "SELECT json(gaps) FROM csharp_compilation_sets WHERE set_id = ?1",
            [self.set_id],
            |row| row.get(0),
        )?;
        let gaps: Vec<[String; 3]> =
            serde_json::from_str(&gaps).expect("gaps column holds string triples");
        Ok(gaps
            .into_iter()
            .map(|[code, path, evidence]| CSharpCompilationGap {
                code,
                path,
                evidence,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::planner_statistics::pinned_plans::{explain_pin, pinned};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    const WORKSPACE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const GENERATION: i64 = 1;
    const REVISION: i64 = 1;
    const SET_ID: i64 = 1;
    const COMPILATION_COUNT: i64 = 50;
    const SOURCE_ROWS: i64 = 300;

    /// The alias or table name a plan row scans, when that row is a `SCAN`.
    fn scanned_name(detail: &str) -> Option<&str> {
        detail.strip_prefix("SCAN ")?.split_whitespace().next()
    }

    fn assert_pin_plan(
        state: PlannerStatisticsState,
        name: &str,
        plan: &[String],
        required: &[&[&str]],
    ) {
        for alternatives in required {
            assert!(
                plan.iter()
                    .any(|detail| alternatives.iter().any(|needle| detail.contains(needle))),
                "{state} {name}: expected one of {alternatives:?}: {plan:#?}"
            );
        }
        for detail in plan {
            let scanned = scanned_name(detail);
            assert!(
                !matches!(
                    scanned,
                    Some(
                        "csharp_compilations"
                            | "compilations"
                            | "csharp_compilation_items"
                            | "items"
                            | "csharp_project_references"
                            | "edges"
                            | "workspace_file_versions"
                            | "versions"
                            | "csharp_compilation_sets"
                            | "sets"
                            | "csharp_compilation_selections"
                            | "selections"
                    )
                ),
                "{state} {name}: scanned a membership table: {plan:#?}"
            );
            assert!(
                !detail.contains("AUTOMATIC"),
                "{state} {name}: built an automatic index: {plan:#?}"
            );
            assert!(
                !detail.contains("TEMP B-TREE"),
                "{state} {name}: built a temp B-tree: {plan:#?}"
            );
        }
    }

    #[test]
    fn csharp_compilation_readers_plan_on_membership_indexes() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, 'csharp', ?2, ?3)",
            params![WORKSPACE, GENERATION, REVISION],
        )
        .unwrap();
        {
            let mut insert = conn
                .prepare(
                    "INSERT INTO workspace_file_versions(
                       workspace_id, lang, generation, rel_path, blob_oid, input_kind,
                       projection_digest, valid_from
                     ) VALUES(?1, 'csharp', ?2, ?3, ?4, 'source', ?5, ?6)",
                )
                .unwrap();
            for index in 0..SOURCE_ROWS {
                let rel_path = if index < 240 {
                    format!("App/Source{index:03}.cs")
                } else {
                    format!("App/Sub/Source{index:03}.cs")
                };
                insert
                    .execute(params![
                        WORKSPACE,
                        GENERATION,
                        rel_path,
                        format!("{index:040x}"),
                        format!("{index:064x}"),
                        REVISION
                    ])
                    .unwrap();
            }
            insert
                .execute(params![
                    WORKSPACE,
                    GENERATION,
                    "App/Sub/Thing.cs",
                    format!("{:040x}", SOURCE_ROWS),
                    format!("{:064x}", SOURCE_ROWS),
                    REVISION
                ])
                .unwrap();
        }
        {
            let mut insert = conn
                .prepare(
                    "INSERT INTO workspace_file_versions(
                       workspace_id, lang, generation, rel_path, blob_oid, input_kind,
                       projection_digest, valid_from
                     ) VALUES(?1, 'csharp', ?2, ?3, ?4, 'configuration', NULL, ?5)",
                )
                .unwrap();
            for (index, rel_path) in [
                "Directory.Build.props",
                "App/App.csproj",
                "App/Sub/Sub.csproj",
                "Lib/Lib.csproj",
                "src/src.csproj",
                "tools/tools.csproj",
            ]
            .iter()
            .enumerate()
            {
                insert
                    .execute(params![
                        WORKSPACE,
                        GENERATION,
                        rel_path,
                        format!("{:040x}", 10_000 + index),
                        REVISION
                    ])
                    .unwrap();
            }
        }
        conn.execute(
            "INSERT INTO csharp_compilation_sets(
               set_id, workspace_id, lang, generation, derivation_version,
               input_digest, output_digest, membership_complete, gaps
             ) VALUES(?1, ?2, 'csharp', ?3, ?4, ?5, ?5, 1, jsonb(?6))",
            params![
                SET_ID,
                WORKSPACE,
                GENERATION,
                DERIVATION_VERSION,
                &[0_u8; 32][..],
                "[]"
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO csharp_compilation_selections(
               workspace_id, lang, generation, revision, set_id
             ) VALUES(?1, 'csharp', ?2, ?3, ?4)",
            params![WORKSPACE, GENERATION, REVISION, SET_ID],
        )
        .unwrap();

        let directories = ["", "App", "App/Sub", "Lib", "App/Lib", "src", "tools"];
        for compilation_id in 1..=COMPILATION_COUNT {
            let project_path = (compilation_id != 1)
                .then(|| format!("Proj{compilation_id}/Proj{compilation_id}.csproj"));
            conn.execute(
                "INSERT INTO csharp_compilations(
                   compilation_id, set_id, project_path, references_complete, transitive_flow,
                   global_usings_complete, internals_visible_to_complete, global_usings, internals_visible_to
                 ) VALUES(?1, ?2, ?3, 1, 1, 1, 1, jsonb('[]'), jsonb('[]'))",
                params![compilation_id, SET_ID, project_path],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO csharp_compilation_items(
                   compilation_id, ordinal, set_id, kind, rel_path, excluded_trees
                 ) VALUES(?1, 0, ?2, 'default_tree', ?3, jsonb('[]'))",
                params![
                    compilation_id,
                    SET_ID,
                    directories[compilation_id as usize % directories.len()]
                ],
            )
            .unwrap();
        }
        {
            let mut insert = conn
                .prepare(
                    "INSERT INTO csharp_compilation_items(
                       compilation_id, ordinal, set_id, kind, rel_path
                     ) VALUES(?1, ?2, ?3, ?4, ?5)",
                )
                .unwrap();
            for compilation_id in 1..=COMPILATION_COUNT {
                for ordinal in 1..4 {
                    let rel_path = match ordinal {
                        1 => format!("App/Source{compilation_id:03}.cs"),
                        2 => "App/Sub/Thing.cs".to_owned(),
                        _ => format!("App/Sub/Source{:03}.cs", 240 + compilation_id),
                    };
                    let kind = if ordinal == 3 { "remove" } else { "include" };
                    insert
                        .execute(params![compilation_id, ordinal, SET_ID, kind, rel_path])
                        .unwrap();
                }
            }
        }
        {
            let mut insert = conn
                .prepare(
                    "INSERT INTO csharp_project_references(
                       from_compilation_id, target_compilation_id
                     ) VALUES(?1, ?2)",
                )
                .unwrap();
            for from in (2..COMPILATION_COUNT).step_by(2) {
                insert.execute(params![from, from + 1]).unwrap();
            }
        }

        let cases: [(&str, Vec<Vec<&str>>); 10] = [
            (
                "csharp_compilation_metadata",
                vec![vec!["sqlite_autoindex_csharp_compilations"]],
            ),
            (
                "csharp_selected_set",
                vec![vec!["selections USING PRIMARY KEY"]],
            ),
            (
                "csharp_selected_source",
                vec![vec![
                    "idx_workspace_file_versions_snapshot_kind",
                    "idx_workspace_file_versions_snapshot_path",
                ]],
            ),
            (
                "csharp_implicit_compilation",
                vec![vec!["sqlite_autoindex_csharp_compilations"]],
            ),
            (
                "csharp_path_items",
                vec![vec!["idx_csharp_compilation_items_path"]],
            ),
            (
                "csharp_reference_closure",
                vec![vec![
                    "edges USING PRIMARY KEY",
                    "csharp_project_references USING PRIMARY KEY",
                ]],
            ),
            (
                "csharp_visible_closure",
                vec![vec![
                    "edges USING PRIMARY KEY",
                    "csharp_project_references USING PRIMARY KEY",
                ]],
            ),
            (
                "csharp_tree_items",
                vec![vec!["idx_csharp_compilation_items_path"]],
            ),
            (
                "csharp_project_count",
                vec![vec!["sqlite_autoindex_csharp_compilations"]],
            ),
            (
                "csharp_unselected_include",
                vec![
                    vec!["idx_csharp_compilation_items_path"],
                    vec![
                        "idx_workspace_file_versions_snapshot_kind",
                        "idx_workspace_file_versions_snapshot_path",
                    ],
                ],
            ),
        ];
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (name, required) in &cases {
                let query = pinned(name);
                let plan = explain_pin(&conn, &query);
                let required = required
                    .iter()
                    .map(|alternatives| alternatives.as_slice())
                    .collect::<Vec<_>>();
                assert_pin_plan(state, name, &plan, &required);
            }
        }
    }

    #[test]
    fn output_digest_covers_recorded_gaps() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut conn = store.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: crate::analyzer::store::WorkspaceId(WORKSPACE.to_owned()),
            lang: STORAGE_LANGUAGE.to_owned(),
            generation: crate::analyzer::store::GenerationId(GENERATION),
            revision: REVISION,
        };
        let facts = |missing: &str| CSharpCompilationFacts {
            compilations: vec![CSharpCompilationFact {
                symbols: Default::default(),
                project_path: Some("App/App.csproj".to_owned()),
                items: Vec::new(),
                references: Vec::new(),
                references_complete: false,
                transitive_flow: true,
                metadata: CSharpCompilationMetadata::default(),
            }],
            membership_complete: true,
            gaps: vec![CSharpCompilationGap {
                code: "unresolved_project_reference".to_owned(),
                path: "App/App.csproj".to_owned(),
                evidence: missing.to_owned(),
            }],
        };
        let digest = |set_id: i64| {
            tx.query_row(
                "SELECT output_digest FROM csharp_compilation_sets WHERE set_id = ?1",
                [set_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
        };
        let first = insert_set(
            &tx,
            &snapshot,
            &[1; 32],
            &facts("../MissingA/MissingA.csproj"),
        )
        .unwrap();
        let second = insert_set(
            &tx,
            &snapshot,
            &[2; 32],
            &facts("../MissingB/MissingB.csproj"),
        )
        .unwrap();
        let same = insert_set(
            &tx,
            &snapshot,
            &[3; 32],
            &facts("../MissingA/MissingA.csproj"),
        )
        .unwrap();
        assert_ne!(
            digest(first),
            digest(second),
            "gap evidence is caller-visible output"
        );
        assert_eq!(
            digest(first),
            digest(same),
            "equal rules and gaps keep one output identity"
        );
    }
}
