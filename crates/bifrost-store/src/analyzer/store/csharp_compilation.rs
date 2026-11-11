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

pub(super) mod extent;

use super::{
    AnalyzerStore, GenerationId, ReaderGuard, Result, StoreError, WorkspaceId, WorkspaceSnapshotId,
};
use crate::analyzer::canonical_hash::CanonicalHasher;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Increment when the rules derived from the same inputs change. Older sets
/// stop satisfying the validity rule and the next publication replaces them.
// v4 retains ancestor absence and rejects unmodeled SDK imports.
// v3 includes symbol derivation and the SDK 10.0.403 implicit-symbol table v1.
pub const PROJECT_FILE_CAP: &str = "project_file_cap";
pub const CONFIGURATION_FILE_CAP: &str = "configuration_file_cap";
pub const CONFIGURATION_TOTAL_BYTE_CAP: &str = "configuration_total_byte_cap";
pub const MEMBERSHIP_CAP_CODES: [&str; 3] = [
    PROJECT_FILE_CAP,
    CONFIGURATION_FILE_CAP,
    CONFIGURATION_TOTAL_BYTE_CAP,
];
pub fn is_membership_cap(code: &str) -> bool {
    MEMBERSHIP_CAP_CODES.contains(&code)
}
pub const MEMBERSHIP_CAP_SQL: &str = "SELECT EXISTS(SELECT 1 FROM csharp_compilation_sets s, json_each(s.gaps) g WHERE s.set_id=?1 AND json_extract(g.value,'$[0]') IN (SELECT value FROM json_each(?2)))";
fn membership_capped(conn: &Connection, set_id: i64) -> Result<bool> {
    Ok(conn.query_row(
        MEMBERSHIP_CAP_SQL,
        params![
            set_id,
            serde_json::to_string(&MEMBERSHIP_CAP_CODES).expect("codes serialize")
        ],
        |r| r.get(0),
    )?)
}

// #8632: parent-relative open items resolve before workspace portability.
// #8831: Target property assignments change membership; 10 because #8832/#8839 also landed 9 on master.
// #8845: per-framework Razor path evaluation changes membership; 11 because #8831 landed 10 on master.
// #7314: coverage reasons now include source-enumeration gaps; 13 fences coverage rows written before the reason existed.
// #7314 AD3d: ordered MSBuild property evaluation changes membership; 14 above master's 13.
// #10356: derived Razor SDK default Compile membership changes; 15 above master's 14.
// #7314 AD3d EC2 r5: three-valued MSBuild conditions change membership; 16.
// #7314 M10a0: framework instances change compilation identity; 17.
// #7314 M10a0 part 2: named-open configuration symbols change membership; 19 above master 17.
// #7314 AD3d EC2 r5: three-valued MSBuild conditions decide more groups, changing membership; 16 above master's 14 and #10356's 15.
// #7314 M10a0: framework instances change compilation identity; 17 above master's 16.
// #10342: count only compilation import enumeration evidence; derivation 18 remains above master.
// #7314 M10a0 part 2 final merge: derivation 19 above master 18.
pub const DERIVATION_VERSION: i64 = 20;
/// Rotate this table identity and DERIVATION_VERSION together when SDK rules change.
pub const IMPLICIT_SYMBOL_TABLE_VERSION: &[u8] = b"sdk-10.0.403-named-open-v2";
/// The storage language whose revisions publish compilation membership.
pub const STORAGE_LANGUAGE: &str = "csharp";
/// Hash selected configuration identities in unique, strictly increasing
/// SQLite BINARY rel_path order. blob_oid is lowercase hexadecimal OID text.
pub fn compilation_input_digest<'a>(
    items: impl IntoIterator<Item = (&'a str, &'a str, bool)>,
) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(b"bifrost-csharp-compilation-inputs:v2");
    hasher.field("implicit_symbol_table", IMPLICIT_SYMBOL_TABLE_VERSION);
    let mut previous: Option<&str> = None;
    for (rel_path, blob_oid, present) in items {
        debug_assert!(previous.is_none_or(|previous| previous < rel_path));
        previous = Some(rel_path);
        hasher.field(rel_path, blob_oid.as_bytes());
        hasher.field("presence", &[u8::from(present)]);
    }
    hasher.finish()
}
const MAX_CONFIGURATION_FILES: usize = 16 * 1024;
const MAX_CONFIGURATION_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONFIGURATION_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// One selected configuration input, in path order.
#[derive(Debug)]
pub struct CSharpConfigurationInput {
    pub rel_path: String,
    /// `None` when the input exceeded a byte cap and was not read.
    pub source: CSharpConfigurationSource,
}

#[derive(Debug, Clone)]
pub enum CSharpConfigurationSource {
    Absent,
    Bytes(Box<[u8]>),
    Capped,
}

impl CSharpConfigurationSource {
    pub fn as_deref(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
    pub fn is_some(&self) -> bool {
        matches!(self, Self::Bytes(_))
    }
    pub fn is_none(&self) -> bool {
        !self.is_some()
    }
    pub fn as_ref(&self) -> Option<&[u8]> {
        self.as_deref()
    }
}

/// The membership rules one configuration derives.
#[derive(Debug, Default)]
pub struct CSharpCompilationFacts {
    /// Ordered by project path; an implicit compilation (no project) is alone.
    pub compilations: Vec<CSharpCompilationFact>,
    /// Diagnostic summary of this derivation result's open items. Not persisted;
    /// readers decide membership from the indexed item rows.
    pub membership_complete: bool,
    pub gaps: Vec<CSharpCompilationGap>,
}

#[derive(Debug, Default, Clone)]
pub struct CSharpCompilationFact {
    /// Workspace-relative project path, `None` for the implicit compilation,
    /// which holds every selected source.
    pub project_path: Option<String>,
    /// Compile items in evaluation order, the SDK default glob among them.
    pub items: Vec<CSharpCompileItem>,
    /// Ordinals into the enclosing fact set's canonical gaps, never copied text.
    pub inventory_gap_indices: Vec<usize>,
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
#[derive(Debug, Clone)]
pub struct CSharpSymbolEnvironment {
    pub configuration: String,
    pub target_framework: Option<String>,
    pub open_reason: Option<String>,
    pub symbols: Vec<(String, String)>,
    pub named_open: Vec<String>,
}

impl Default for CSharpSymbolEnvironment {
    fn default() -> Self {
        Self {
            configuration: "Debug".into(),
            target_framework: None,
            open_reason: Some("loose_files".into()),
            symbols: Vec::new(),
            named_open: Vec::new(),
        }
    }
}

impl CSharpSymbolEnvironment {
    pub fn digest(&self) -> [u8; 32] {
        debug_assert!(self.open_reason.is_none() || self.symbols.is_empty());
        let mut hash = CanonicalHasher::new(
            b"csharp-symbol-environment:derivation-v2:sdk-10.0.403-named-open-v2",
        );
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
        for symbol in &self.named_open {
            hash.field("named_open", symbol.as_bytes());
        }
        hash.finish()
    }
}

/// Configuration facts read whole for one compilation, never retained as a workspace index.
#[derive(Debug, Default, PartialEq, Clone)]
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

#[derive(Debug, Clone)]
pub struct CSharpCompileItem {
    pub kind: CSharpCompileItemKind,
    /// A file, or for a tree the directory.
    pub rel_path: String,
    /// For a tree, directories it leaves out.
    pub excluded_trees: Vec<String>,
    pub gap_indices: Vec<usize>,
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
    Open,
    OpenTree,
}

impl CSharpCompileItemKind {
    fn label(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::IncludeTree => "include_tree",
            Self::DefaultTree => "default_tree",
            Self::Remove => "remove",
            Self::Open => "open",
            Self::OpenTree => "open_tree",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CSharpCompilationGap {
    pub code: String,
    pub path: String,
    pub evidence: String,
}

pub(super) const COMPILATION_METADATA_SQL: &str =
    "SELECT assembly_name, global_usings_complete, internals_visible_to_complete,
                    json(global_usings), json(internals_visible_to)
             FROM csharp_compilations WHERE set_id = ?1 AND compilation_id = ?2";

/// Inputs to the preprocessor evaluator for one owning compilation.
#[derive(Debug, PartialEq, Eq)]
pub struct CSharpOwnerEnvironment {
    pub owner_key: String,
    pub symbols: Vec<String>,
    pub named_open: Vec<String>,
    pub closed: bool,
    pub open_reason: Option<String>,
}

/// Only C# file versions carry a decision today; every other language publishes none.
/// Content identity and local address of one compilation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CSharpCompilationSetRef {
    pub id: i64,
    pub output_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndecidedChainRow {
    pub chain: u32,
    pub directive_start: u32,
    pub directive_end: u32,
    pub omitted_nonblank: bool,
    pub invalid_condition: bool,
    pub unknown_symbols: Vec<String>,
    pub open_reasons: Vec<String>,
    pub disagreeing_owners: Vec<String>,
}

pub(super) const INSERT_UNDECIDED_CHAIN_SQL: &str = "INSERT INTO csharp_undecided_chains(blob_id,chain,directive_start,directive_end,omitted_nonblank,invalid_condition,unknown_symbols,open_reasons,disagreeing_owners) VALUES(?1,?2,?3,?4,?5,?6,jsonb(?7),jsonb(?8),jsonb(?9))";
pub(super) const DELETE_STALE_EPOCH_CHAINS_SQL: &str =
    "DELETE FROM csharp_undecided_chains WHERE blob_id IN (
                                   SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2
                                     AND parse_variant = ?4 AND generation <> ?3)";
pub(super) const DELETE_UNROOTED_CHAINS_SQL: &str = "DELETE FROM csharp_undecided_chains WHERE blob_id IN (
                               SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND parse_variant = ?3
                                 AND generation = COALESCE((SELECT generation FROM analysis_epochs WHERE lang = ?2), 0)
                                 AND NOT EXISTS (SELECT 1 FROM workspace_resolution_content_roots AS roots WHERE roots.blob_id = blobs.id))";
pub(super) const DELETE_REPLACED_CHAINS_SQL: &str =
    "DELETE FROM csharp_undecided_chains WHERE blob_id IN (
               SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND parse_variant = ?3)";
pub(super) const DELETE_RECLAIMED_CHAINS_SQL: &str = "DELETE FROM csharp_undecided_chains WHERE blob_id IN (
                       SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2 AND parse_variant = ?3
                         AND generation <> COALESCE((SELECT generation FROM analysis_epochs WHERE lang = ?2), 0))";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnseenBranchFile {
    pub rel_path: String,
    pub variant: [u8; 32],
    pub chains: Vec<UndecidedChainRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersionDecision {
    pub decision_digest: [u8; 32],
    pub assignment_digest: [u8; 32],
}

pub(super) fn decode_file_decision(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<Option<FileVersionDecision>> {
    let Some(decision) = row.get::<_, Option<Vec<u8>>>(offset)? else {
        return Ok(None);
    };
    let assignment = row.get::<_, Vec<u8>>(offset + 1)?;
    let digest = |bytes: Vec<u8>, column| {
        bytes.try_into().map_err(|_: Vec<u8>| {
            rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Blob,
                "invalid C# digest length".into(),
            )
        })
    };
    Ok(Some(FileVersionDecision {
        decision_digest: digest(decision, offset)?,
        assignment_digest: digest(assignment, offset + 1)?,
    }))
}

pub(super) const OWNER_ENVIRONMENT_SQL: &str =
    "SELECT c.project_path, c.symbols_closed, c.open_reason, s.symbol, json(c.named_open_symbols), c.target_framework
     FROM csharp_compilations AS c
     LEFT JOIN csharp_compilation_symbols AS s ON s.compilation_id = c.compilation_id
     WHERE c.compilation_id = ?1 ORDER BY s.symbol";

pub(super) const SELECTED_CONFIGURATIONS_SQL: &str =
    "SELECT c.project_path, c.configuration, c.target_framework,
            c.symbols_closed, c.open_reason, s.symbol, c.compilation_id, json(c.named_open_symbols)
     FROM csharp_compilations c
     LEFT JOIN csharp_compilation_symbols s USING(compilation_id)
     WHERE c.set_id = ?1
     ORDER BY c.compilation_id, s.symbol";

pub(super) const MISSING_DECISIONS_SQL: &str = "SELECT COUNT(*)
     FROM workspace_file_versions AS files
     LEFT JOIN csharp_file_version_decisions AS decisions
       ON decisions.file_version_id = files.file_version_id
     WHERE files.workspace_id = ?1 AND files.lang = 'csharp' AND files.generation = ?2
       AND files.input_kind = 'source' AND files.valid_until IS NULL
       AND decisions.file_version_id IS NULL";

pub(super) const SELECTED_FILE_DECISION_SQL: &str =
    "SELECT decisions.decision_digest, decisions.assignment_digest
     FROM workspace_file_versions AS files
     LEFT JOIN csharp_file_version_decisions AS decisions
       ON decisions.file_version_id = files.file_version_id
     WHERE files.workspace_id = ?1 AND files.lang = ?2 AND files.generation = ?3
       AND files.input_kind = 'source' AND files.rel_path = ?4
       AND files.valid_from <= ?5 AND (files.valid_until IS NULL OR ?5 < files.valid_until)";

pub(super) const SELECTED_REFUSAL_PATHS_SQL: &str =
    "SELECT rel_path, blob_oid FROM workspace_source_refusals
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND valid_from <= ?4 AND (valid_until IS NULL OR ?4 < valid_until)";

pub(super) const FILE_DECISION_SQL: &str =
    "SELECT decisions.decision_digest, decisions.assignment_digest
     FROM workspace_file_versions AS files
     JOIN csharp_file_version_decisions AS decisions ON decisions.file_version_id = files.file_version_id
     WHERE files.workspace_id = ?1 AND files.lang = ?2 AND files.generation = ?3
       AND files.input_kind = 'source' AND files.rel_path = ?4
       AND files.valid_from <= ?5 AND (files.valid_until IS NULL OR ?5 < files.valid_until)";

pub(super) const UNSEEN_BRANCH_FILES_SQL: &str = "SELECT files.rel_path, blobs.parse_variant,
       chains.chain, chains.directive_start, chains.directive_end, chains.omitted_nonblank,
       chains.invalid_condition, json(chains.unknown_symbols), json(chains.open_reasons), json(chains.disagreeing_owners)
  FROM csharp_undecided_chains AS chains INDEXED BY idx_csharp_undecided_chains_nonblank
  CROSS JOIN blobs ON blobs.id = chains.blob_id AND blobs.lang = 'csharp' AND blobs.generation = ?2
  CROSS JOIN workspace_file_versions AS files INDEXED BY idx_workspace_file_versions_snapshot_blob
    ON files.workspace_id = ?1 AND files.lang = 'csharp' AND files.generation = ?2
   AND files.blob_oid = blobs.blob_oid AND files.input_kind = 'source'
   AND files.valid_from <= ?3 AND (files.valid_until IS NULL OR ?3 < files.valid_until)
  CROSS JOIN csharp_file_version_decisions AS decisions ON decisions.file_version_id = files.file_version_id
   AND decisions.decision_digest = blobs.parse_variant
 WHERE chains.omitted_nonblank = 1";

pub(super) const UNCERTIFIED_SELECTED_CSHARP_SQL: &str = "SELECT files.rel_path
  FROM workspace_file_versions AS files INDEXED BY idx_workspace_file_versions_snapshot_kind
  LEFT JOIN analysis_epochs AS epochs ON epochs.lang = 'csharp' AND epochs.generation = files.generation
  LEFT JOIN csharp_file_version_decisions AS decisions ON decisions.file_version_id = files.file_version_id
  LEFT JOIN blobs ON blobs.blob_oid = files.blob_oid AND blobs.lang = 'csharp'
    AND blobs.parse_variant = decisions.decision_digest AND blobs.generation = ?2
  LEFT JOIN blob_meta ON blob_meta.blob_id = blobs.id AND blob_meta.is_complete = 1
 WHERE files.workspace_id = ?1 AND files.lang = 'csharp' AND files.generation = ?2
   AND files.input_kind = 'source'
   AND files.valid_from <= ?3 AND (files.valid_until IS NULL OR ?3 < files.valid_until)
   AND NOT EXISTS (SELECT 1 FROM json_each(?4) AS overlays WHERE overlays.value = files.rel_path)
   AND (epochs.lang IS NULL OR decisions.file_version_id IS NULL OR blob_meta.blob_id IS NULL)";

pub(super) const REFERENCED_SYMBOLS_SQL: &str = "SELECT symbols.symbol FROM blobs AS keys
     JOIN csharp_source_condition_symbols AS symbols ON symbols.blob_id = keys.id
     WHERE keys.blob_oid = ?1 AND keys.lang = ?2 AND keys.parse_variant = ?3
     ORDER BY symbols.symbol";

pub(super) const SET_MEMBERSHIP_SQL: &str = "SELECT 1 FROM csharp_compilation_sets
     WHERE set_id = ?1 AND derivation_version = ?2";

pub(super) const EXISTING_SET_SQL: &str =
    "SELECT set_id, output_digest FROM csharp_compilation_sets
             WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
               AND derivation_version = ?4 AND input_digest = ?5";

pub(super) const SELECTED_SET_SQL: &str =
    "SELECT sets.set_id, sets.derivation_version, sets.output_digest
     FROM csharp_compilation_selections AS selections
     JOIN csharp_compilation_sets AS sets ON sets.set_id = selections.set_id
     WHERE selections.workspace_id = ?1 AND selections.lang = ?2
       AND selections.generation = ?3 AND selections.revision = ?4";

const CONFIGURATION_IDENTITIES_SQL: &str = "SELECT rel_path, blob_oid, file_present
     FROM workspace_file_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND input_kind = 'configuration'
       AND valid_from <= ?4 AND (valid_until IS NULL OR ?4 < valid_until)
     ORDER BY rel_path";

const CONFIGURATION_BYTES_SQL: &str = "SELECT versions.rel_path, length(retained.source_bytes),
            CASE WHEN length(retained.source_bytes) <= ?5 THEN retained.source_bytes END, versions.file_present
     FROM workspace_file_versions AS versions
     LEFT JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
     WHERE versions.workspace_id = ?1 AND versions.lang = ?2 AND versions.generation = ?3
       AND versions.input_kind = 'configuration'
       AND versions.valid_from <= ?4 AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)
     ORDER BY versions.rel_path
     LIMIT ?6";

pub const SELECTED_CONFIGURATION_MASK_SQL: &str = "SELECT EXISTS(
 SELECT 1 FROM temp.selected_resolution_overlay_masks mask
 CROSS JOIN workspace_file_versions version ON version.workspace_id=?1 AND version.lang='csharp'
 AND version.generation=?2 AND version.rel_path=mask.persisted_relative_path
 WHERE mask.storage_language='csharp' AND version.input_kind='configuration'
 AND version.valid_from<=?3 AND (version.valid_until IS NULL OR version.valid_until>?3))";

pub(super) const SELECTED_SOURCE_SQL: &str = "SELECT 1
     FROM workspace_file_versions
     WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
       AND input_kind = 'source' AND rel_path = ?4
       AND valid_from <= ?5 AND (valid_until IS NULL OR ?5 < valid_until)";

pub(super) const IMPLICIT_COMPILATION_SQL: &str = "SELECT compilation_id
     FROM csharp_compilations
     WHERE set_id = ?1 AND project_path IS NULL";

pub(super) const PATH_ITEMS_SQL: &str = "SELECT item.compilation_id, item.ordinal, item.kind,
     item.rel_path, json(item.excluded_trees), compilation.project_path,
     (SELECT json_group_array(json_extract(rules.gaps,'$[' || gap.value || ']'))
      FROM json_each(item.gap_indices) gap)
     FROM csharp_compilation_items item
     JOIN csharp_compilations compilation ON compilation.compilation_id=item.compilation_id
     JOIN csharp_compilation_sets rules ON rules.set_id=item.set_id
     WHERE item.set_id=?1 AND item.rel_path=?2 AND item.kind IN ('include','remove','open')";

/// Trees rooted at an ancestor directory of a path, including open regions.
pub(super) const TREE_ITEMS_SQL: &str = "SELECT item.compilation_id, item.ordinal, item.kind,
     item.rel_path, json(item.excluded_trees), compilation.project_path,
     (SELECT json_group_array(json_extract(rules.gaps,'$[' || gap.value || ']'))
      FROM json_each(item.gap_indices) gap)
     FROM csharp_compilation_items item
     JOIN csharp_compilations compilation ON compilation.compilation_id=item.compilation_id
     JOIN csharp_compilation_sets rules ON rules.set_id=item.set_id
     WHERE item.set_id=?1 AND item.kind IN ('include_tree','default_tree','open_tree')
       AND item.rel_path IN (SELECT value FROM json_each(?2))";

pub(super) const MEMBERSHIP_COVERAGE_SQL: &str = "SELECT NOT EXISTS(
 SELECT 1 FROM csharp_compilation_membership_coverage WHERE set_id=?1 AND membership_complete=0)";
pub(super) const INVENTORY_SQL: &str = "SELECT compilation.inventory_open,
 (SELECT json_group_array(json_extract(rules.gaps,'$[' || gap.value || ']'))
  FROM json_each(compilation.inventory_gap_indices) gap)
 FROM csharp_compilations compilation JOIN csharp_compilation_sets rules USING(set_id)
 WHERE compilation.compilation_id=?1";

pub(super) const OPEN_INVENTORIES_SQL: &str = "WITH RECURSIVE reach(compilation_id) AS (
 SELECT ?1 UNION SELECT edge.target_compilation_id FROM csharp_project_references edge
 JOIN reach ON edge.from_compilation_id=reach.compilation_id)
 SELECT compilation.compilation_id,compilation.project_path,
 (SELECT json_group_array(json_extract(rules.gaps,'$[' || gap.value || ']'))
  FROM json_each(compilation.inventory_gap_indices) gap)
 FROM reach JOIN csharp_compilations compilation USING(compilation_id)
 JOIN csharp_compilation_sets rules USING(set_id)
 WHERE compilation.inventory_open=1 ORDER BY compilation.compilation_id";

/// Every compilation `?1` reaches over any edge, with whether its direct
/// references and declaration inventory are complete: the bound on what
/// `?1` can possibly see, including the proof required for a negative.
pub(super) const REFERENCE_CLOSURE_SQL: &str = "WITH RECURSIVE reach(compilation_id) AS (
         SELECT ?1
         UNION
         SELECT edges.target_compilation_id
         FROM csharp_project_references AS edges
         JOIN reach ON edges.from_compilation_id = reach.compilation_id
     )
     SELECT compilations.compilation_id,
            compilations.references_complete AND NOT compilations.inventory_open AS complete
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
    let Some(_support) = super::store_language_support(crate::analyzer::Language::CSharp) else {
        return Ok(());
    };
    // Legacy empty probes have unknown presence. Refuse before consulting any
    // retained selection or set identity, even when a file cap omits the row.
    let unvalidated: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_file_versions WHERE workspace_id=?1 AND lang=?2 AND generation=?3 AND input_kind='configuration' AND file_present IS NULL AND valid_from<=?4 AND (valid_until IS NULL OR ?4<valid_until))",
        snapshot_params(snapshot), |row| row.get(0),
    )?;
    if unvalidated {
        return Ok(());
    }
    let selected = selected_set_record(tx, snapshot)?.map(|(_, version)| version);
    if selected == Some(DERIVATION_VERSION) {
        return Ok(());
    }

    let mut identities = Vec::new();
    {
        let mut statement = tx.prepare_cached(CONFIGURATION_IDENTITIES_SQL)?;
        let mut rows = statement.query(snapshot_params(snapshot))?;
        while let Some(row) = rows.next()? {
            identities.push((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<bool>>(2)?
                    .expect("selected inputs validated presence"),
            ));
        }
    }
    let input_digest = compilation_input_digest(
        identities
            .iter()
            .map(|(path, oid, present)| (path.as_str(), oid.as_str(), *present)),
    );
    let set_id = if let Some(set_id) = existing_set(
        tx,
        &snapshot.workspace_id,
        snapshot.generation,
        &input_digest,
    )? {
        set_id
    } else {
        let Some((inputs, store_gaps)) = selected_inputs(tx, snapshot)? else {
            return Ok(());
        };
        let Some(set_id) = derive_set(
            tx,
            &snapshot.workspace_id,
            snapshot.generation,
            &input_digest,
            &inputs,
            store_gaps,
        )?
        else {
            return Ok(());
        };
        set_id
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
            set_id.id
        ],
    )?;
    Ok(())
}

fn existing_set(
    conn: &Connection,
    workspace_id: &super::WorkspaceId,
    generation: super::GenerationId,
    input_digest: &[u8; 32],
) -> Result<Option<CSharpCompilationSetRef>> {
    Ok(conn
        .query_row(
            EXISTING_SET_SQL,
            params![
                workspace_id.as_str(),
                STORAGE_LANGUAGE,
                generation.0,
                DERIVATION_VERSION,
                input_digest.as_slice()
            ],
            |row| {
                Ok(CSharpCompilationSetRef {
                    id: row.get(0)?,
                    output_digest: row.get(1)?,
                })
            },
        )
        .optional()?)
}

fn derive_set(
    tx: &Transaction<'_>,
    workspace_id: &super::WorkspaceId,
    generation: super::GenerationId,
    input_digest: &[u8; 32],
    inputs: &[CSharpConfigurationInput],
    mut store_gaps: Vec<CSharpCompilationGap>,
) -> Result<Option<CSharpCompilationSetRef>> {
    if let Some(set_id) = existing_set(tx, workspace_id, generation, input_digest)? {
        return Ok(Some(set_id));
    }
    let Some(support) = super::store_language_support(crate::analyzer::Language::CSharp) else {
        return Ok(None);
    };
    let Some(mut facts) = support.csharp_compilation_facts(inputs) else {
        return Ok(None);
    };
    if !store_gaps.is_empty() {
        let first_gap = facts.gaps.len();
        for compilation in &mut facts.compilations {
            let indices = (first_gap..first_gap + store_gaps.len()).collect::<Vec<_>>();
            compilation.inventory_gap_indices.extend(&indices);
            compilation.items.push(CSharpCompileItem {
                kind: CSharpCompileItemKind::OpenTree,
                rel_path: String::new(),
                excluded_trees: Vec::new(),
                gap_indices: indices,
            });
            compilation.metadata.assembly_name = None;
            compilation.metadata.global_usings_complete = false;
            compilation.metadata.internals_visible_to_complete = false;
        }
        facts.gaps.append(&mut store_gaps);
    }
    Ok(Some(insert_set(
        tx,
        workspace_id,
        generation,
        input_digest,
        &facts,
    )?))
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
    let mut statement = tx.prepare_cached(CONFIGURATION_BYTES_SQL)?;
    let rows = statement.query_map(
        params![
            snapshot.workspace_id.as_str(),
            snapshot.lang,
            snapshot.generation.0,
            snapshot.revision,
            MAX_CONFIGURATION_FILE_BYTES,
            MAX_CONFIGURATION_FILES.saturating_add(1)
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<usize>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<bool>>(3)?,
            ))
        },
    )?;
    bounded_configuration_inputs(rows.map(|row| row.map_err(Into::into)))
}

fn bounded_configuration_inputs(
    rows: impl IntoIterator<Item = Result<(String, Option<usize>, Option<Vec<u8>>, Option<bool>)>>,
) -> Result<Option<(Vec<CSharpConfigurationInput>, Vec<CSharpCompilationGap>)>> {
    let mut inputs = Vec::new();
    let mut gaps = Vec::new();
    let mut total = 0_usize;
    for row in rows {
        let (rel_path, length, source, present) = row?;
        let Some(present) = present else {
            return Ok(None);
        };
        if inputs.len() == MAX_CONFIGURATION_FILES {
            gaps.push(CSharpCompilationGap {
                code: CONFIGURATION_FILE_CAP.into(),
                path: rel_path,
                evidence: format!("more than {MAX_CONFIGURATION_FILES} configuration inputs"),
            });
            break;
        }
        let Some(length) = length else {
            return Ok(None);
        };
        let source = match source {
            Some(source) if total.saturating_add(length) <= MAX_CONFIGURATION_TOTAL_BYTES => {
                total += length;
                Some(source)
            }
            Some(_) => {
                gaps.push(CSharpCompilationGap {
                    code: CONFIGURATION_TOTAL_BYTE_CAP.into(),
                    path: rel_path.clone(),
                    evidence: format!(
                        "configuration inputs exceed {MAX_CONFIGURATION_TOTAL_BYTES} bytes"
                    ),
                });
                None
            }
            None => None,
        };
        let source = if !present {
            CSharpConfigurationSource::Absent
        } else {
            source
                .map(|bytes| CSharpConfigurationSource::Bytes(bytes.into_boxed_slice()))
                .unwrap_or(CSharpConfigurationSource::Capped)
        };
        inputs.push(CSharpConfigurationInput { rel_path, source });
    }
    Ok(Some((inputs, gaps)))
}

fn insert_set(
    tx: &Transaction<'_>,
    workspace_id: &super::WorkspaceId,
    generation: super::GenerationId,
    input_digest: &[u8; 32],
    facts: &CSharpCompilationFacts,
) -> Result<CSharpCompilationSetRef> {
    let mut output = CanonicalHasher::new(b"bifrost-csharp-compilation-rules:v2");

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
        output.field(
            "inventory_gap_indices",
            &serde_json::to_vec(&compilation.inventory_gap_indices).expect("indices serialize"),
        );
        for item in &compilation.items {
            output.field(
                "gap_indices",
                &serde_json::to_vec(&item.gap_indices).expect("indices serialize"),
            );
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
           gaps
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, jsonb(?7))",
        params![
            workspace_id.as_str(),
            STORAGE_LANGUAGE,
            generation.0,
            DERIVATION_VERSION,
            input_digest.as_slice(),
            output_digest.as_slice(),
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
               symbols_closed, open_reason, symbol_set_digest, inventory_open, inventory_gap_indices, named_open_symbols
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, jsonb(?8), jsonb(?9), ?10, ?11, ?12, ?13, ?14, ?15, jsonb(?16), jsonb(?17))",
        )?;
        let mut items = tx.prepare_cached(
            "INSERT INTO csharp_compilation_items(
               compilation_id, ordinal, set_id, kind, rel_path, excluded_trees, gap_indices
             ) VALUES(?1, ?2, ?3, ?4, ?5, jsonb(?6), jsonb(?7))",
        )?;
        for compilation in &facts.compilations {
            assert!(
                compilation
                    .inventory_gap_indices
                    .iter()
                    .all(|&index| index < facts.gaps.len()),
                "inventory gap indices are canonical"
            );
            assert!(
                compilation.items.iter().all(|item| item
                    .gap_indices
                    .iter()
                    .all(|index| compilation.inventory_gap_indices.contains(index))),
                "every open item opens its inventory"
            );
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
                compilation.symbols.digest().as_slice(),
                !compilation.inventory_gap_indices.is_empty(),
                serde_json::to_string(&compilation.inventory_gap_indices)
                    .expect("indices serialize"),
                serde_json::to_string(&compilation.symbols.named_open).expect("symbols serialize")
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
                    ids.insert(
                        (path, compilation.symbols.target_framework.as_deref()),
                        compilation_id
                    )
                    .is_none(),
                    "one compilation per project and framework: {path}"
                );
            }
            for (ordinal, item) in compilation.items.iter().enumerate() {
                let excluded_trees = matches!(
                    item.kind,
                    CSharpCompileItemKind::IncludeTree
                        | CSharpCompileItemKind::DefaultTree
                        | CSharpCompileItemKind::OpenTree
                )
                .then(|| serde_json::to_string(&item.excluded_trees).expect("strings serialize"));
                items.execute(params![
                    compilation_id,
                    ordinal,
                    set_id,
                    item.kind.label(),
                    item.rel_path,
                    excluded_trees,
                    serde_json::to_string(&item.gap_indices).expect("indices serialize")
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
            // Multi-target references must have been retained as typed open
            // edges by evaluation until nearest-framework selection is available.
            let mut targets = ids.iter().filter(|((project, _), _)| *project == reference);
            let (_, target) = targets.next().unwrap_or_else(|| {
                panic!("{path} references {reference}, which is not a compilation in its set")
            });
            if targets.next().is_some() {
                assert!(
                    !compilation.references_complete,
                    "an ambiguous framework reference cannot be complete"
                );
                continue;
            }
            edges.execute(params![
                ids[&(path, compilation.symbols.target_framework.as_deref())],
                target
            ])?;
        }
    }
    Ok(CSharpCompilationSetRef {
        id: set_id,
        output_digest,
    })
}

/// One revision's selected compilation rules, read per demand.
pub struct SelectedCSharpCompilations<'a> {
    conn: ReaderGuard<'a>,
    snapshot: WorkspaceSnapshotId,
    set_id: i64,
    input_digest: [u8; 32],
    // Derived predicate of this immutable selected set; never declaration authority.
    membership_capped: bool,
}

#[derive(Debug, Clone)]
pub struct SelectedCSharpCompilationConfiguration {
    pub project_path: Option<String>,
    pub configuration: String,
    pub target_framework: Option<String>,
    pub symbols: Vec<String>,
    pub named_open: Vec<String>,
    pub closed: bool,
    pub open_reason: Option<String>,
}

impl AnalyzerStore {
    /// The current-format compilation set selected by this retained snapshot.
    #[doc(hidden)]
    pub fn csharp_selected_compilation_set(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<Option<CSharpCompilationSetRef>> {
        let conn = self.read_conn()?;
        selected_set(&conn, snapshot)
    }

    /// Read one owner's evaluator inputs without retaining a compilation index.
    #[doc(hidden)]
    pub fn csharp_owner_environment(
        &self,
        compilation_id: i64,
    ) -> Result<Option<CSharpOwnerEnvironment>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(OWNER_ENVIRONMENT_SQL)?;
        let mut rows = statement.query([compilation_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        // NUL cannot occur in a workspace path on any supported platform.
        // This reserved loose owner key is distinct from the evaluator's empty no-owner key.
        let owner_key = row
            .get::<_, Option<String>>(0)?
            .unwrap_or_else(|| "\0loose".into());
        let owner_key = match row.get::<_, Option<String>>(5)? {
            Some(framework) => format!("{owner_key} [TargetFramework={framework}]"),
            None => owner_key,
        };
        let mut environment = CSharpOwnerEnvironment {
            owner_key,
            symbols: Vec::new(),
            named_open: serde_json::from_str(&row.get::<_, String>(4)?).map_err(|e| {
                super::StoreError::corrupt(format!("invalid C# named open symbols: {e}"))
            })?,
            closed: row.get(1)?,
            open_reason: row.get(2)?,
        };
        if let Some(symbol) = row.get::<_, Option<String>>(3)? {
            environment.symbols.push(symbol);
        }
        while let Some(row) = rows.next()? {
            if let Some(symbol) = row.get::<_, Option<String>>(3)? {
                environment.symbols.push(symbol);
            }
        }
        Ok(Some(environment))
    }

    /// Count missing decisions at a process's first read of this generation.
    #[doc(hidden)]
    pub fn csharp_missing_decision_count(
        &self,
        workspace: &WorkspaceId,
        generation: GenerationId,
    ) -> Result<u64> {
        let conn = self.read_conn()?;
        Ok(conn.query_row(
            MISSING_DECISIONS_SQL,
            params![workspace.as_str(), generation.0],
            |row| row.get(0),
        )?)
    }

    /// Revisioned C# source refusals in the selected snapshot, keyed by path.
    #[doc(hidden)]
    pub fn csharp_selected_refusal_paths(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<crate::hash::HashMap<String, git2::Oid>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(SELECTED_REFUSAL_PATHS_SQL)?;
        let rows = statement.query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.0,
                snapshot.revision
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut refusals = crate::hash::HashMap::default();
        for row in rows {
            let (path, blob): (String, String) = row?;
            let oid = blob.parse().map_err(|error| {
                StoreError::corrupt(format!("invalid source refusal blob OID {blob:?}: {error}"))
            })?;
            refusals.insert(path, oid);
        }
        Ok(refusals)
    }

    /// The decision attached to this path in the specified retained revision.
    /// None means no selected source version; Some(None) means a corrupt C#
    /// source version without its required decision.
    pub fn csharp_selected_file_decision(
        &self,
        snapshot: &WorkspaceSnapshotId,
        rel_path: &str,
    ) -> Result<Option<Option<FileVersionDecision>>> {
        let conn = self.read_conn()?;
        conn.query_row(
            SELECTED_FILE_DECISION_SQL,
            params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.0,
                rel_path,
                snapshot.revision
            ],
            |row| decode_file_decision(row, 0),
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn csharp_file_version_decision(
        &self,
        snapshot: &WorkspaceSnapshotId,
        rel_path: &str,
    ) -> Result<Option<FileVersionDecision>> {
        let conn = self.read_conn()?;
        Ok(conn
            .query_row(
                FILE_DECISION_SQL,
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.0,
                    rel_path,
                    snapshot.revision
                ],
                |row| decode_file_decision(row, 0),
            )
            .optional()?
            .flatten())
    }

    pub fn unseen_branch_files(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<Vec<UnseenBranchFile>> {
        assert_eq!(snapshot.lang, "csharp");
        let conn = self.checkout_read_conn()?;
        read_unseen_branch_files(&conn, snapshot)
    }

    /// Inventory-first certificate and the published nonempty chains from one read transaction.
    pub fn csharp_selected_unseen_branch_census(
        &self,
        snapshot: &WorkspaceSnapshotId,
        captured_generation: GenerationId,
        overlay_paths: &[String],
    ) -> Result<SelectedUnseenBranchCensus> {
        assert_eq!(snapshot.lang, "csharp");
        assert_eq!(captured_generation, snapshot.generation);
        let mut conn = self.checkout_read_conn()?;
        let tx = conn.transaction()?;
        super::require_current_generation(&tx, "csharp", captured_generation)?;
        let overlays = serde_json::to_string(overlay_paths).expect("overlay paths serialize");
        let mut stmt = tx.prepare_cached(UNCERTIFIED_SELECTED_CSHARP_SQL)?;
        let mut paths = stmt.query(params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            snapshot.revision,
            overlays
        ])?;
        let mut uncertified_count = 0u64;
        let mut sample = Vec::new();
        while let Some(row) = paths.next()? {
            uncertified_count += 1;
            if sample.len() < 5 {
                sample.push(row.get(0)?);
            }
        }
        drop(paths);
        drop(stmt);
        let mut rows = read_unseen_branch_files(&tx, snapshot)?;
        let overlay_set: crate::hash::HashSet<&str> =
            overlay_paths.iter().map(String::as_str).collect();
        rows.retain(|row| !overlay_set.contains(row.rel_path.as_str()));
        tx.commit()?;
        Ok(SelectedUnseenBranchCensus {
            uncertified_count,
            sample,
            rows,
        })
    }
}

#[derive(Debug)]
pub struct SelectedUnseenBranchCensus {
    pub uncertified_count: u64,
    pub sample: Vec<String>,
    pub rows: Vec<UnseenBranchFile>,
}

fn read_unseen_branch_files(
    conn: &rusqlite::Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Vec<UnseenBranchFile>> {
    let mut stmt = conn.prepare_cached(UNSEEN_BRANCH_FILES_SQL)?;
    let rows = stmt.query_map(
        params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            snapshot.revision
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                UndecidedChainRow {
                    chain: row.get(2)?,
                    directive_start: row.get(3)?,
                    directive_end: row.get(4)?,
                    omitted_nonblank: row.get(5)?,
                    invalid_condition: row.get(6)?,
                    unknown_symbols: serde_json::from_str(&row.get::<_, String>(7)?).map_err(
                        |e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                7,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        },
                    )?,
                    open_reasons: serde_json::from_str(&row.get::<_, String>(8)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            8,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    disagreeing_owners: serde_json::from_str(&row.get::<_, String>(9)?).map_err(
                        |e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                9,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        },
                    )?,
                },
            ))
        },
    )?;
    let mut rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    rows.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.chain.cmp(&b.2.chain)));
    let mut files: Vec<UnseenBranchFile> = Vec::new();
    for row in rows {
        let (rel_path, variant, chain) = row;
        let variant: [u8; 32] = variant
            .try_into()
            .map_err(|_| super::StoreError::corrupt("invalid C# variant digest"))?;
        if files.last().is_none_or(|file| file.rel_path != rel_path) {
            files.push(UnseenBranchFile {
                rel_path,
                variant,
                chains: Vec::new(),
            });
        }
        files
            .last_mut()
            .expect("one file pushed")
            .chains
            .push(chain);
    }
    Ok(files)
}

impl AnalyzerStore {
    /// Referenced symbols of the exact immutable variant, in symbol order.
    #[doc(hidden)]
    pub fn csharp_referenced_symbols(&self, key: &crate::gitblob::BlobKey) -> Result<Vec<String>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(REFERENCED_SYMBOLS_SQL)?;
        Ok(statement
            .query_map(params![key.oid.to_string(), key.lang, key.variant], |row| {
                row.get(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Persist a content-addressed compilation set before publishing a revision.
    /// Inputs must be ordered by unique workspace-relative path, as in capture.
    /// No revision or selection row is created. None means the C# producer is unavailable.
    #[doc(hidden)]
    pub fn derive_csharp_compilation_set(
        &self,
        workspace_id: &super::WorkspaceId,
        generation: super::GenerationId,
        captured: &[super::workspace_inputs::WorkspaceConfigurationInput],
    ) -> Result<Option<CSharpCompilationSetRef>> {
        let mut hasher = CanonicalHasher::new(b"bifrost-csharp-compilation-inputs:v2");
        hasher.field("implicit_symbol_table", IMPLICIT_SYMBOL_TABLE_VERSION);
        let mut previous: Option<&str> = None;
        for input in captured {
            assert!(
                previous.is_none_or(|path| path < input.relative_path.as_str()),
                "configuration inputs must be ordered by unique path"
            );
            previous = Some(&input.relative_path);
            hasher.field(
                &input.relative_path,
                input.content_oid().to_string().as_bytes(),
            );
            hasher.field("presence", &[u8::from(input.file_present)]);
        }
        let input_digest = hasher.finish();
        let (inputs, gaps) = bounded_configuration_inputs(captured.iter().map(|input| {
            let bytes = input.source_bytes();
            Ok((
                input.relative_path.clone(),
                Some(bytes.len()),
                (bytes.len() <= MAX_CONFIGURATION_FILE_BYTES).then(|| bytes.to_vec()),
                Some(input.file_present),
            ))
        }))?
        .expect("captured configuration inputs retain their bytes");
        let workspace_id = workspace_id.clone();
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            super::require_current_generation(&tx, STORAGE_LANGUAGE, generation)?;
            let set = derive_set(&tx, &workspace_id, generation, &input_digest, &inputs, gaps)?;
            tx.commit()?;
            Ok(set)
        })
    }

    /// Owners of a candidate from the build's inventory, before revision publication.
    /// The caller supplies a captured inventory path; this entry has no selected-source guard.
    /// None means the set is absent, obsolete or membership-capped.
    #[doc(hidden)]
    pub fn csharp_compilations_of_set(
        &self,
        set_id: i64,
        candidate_path: &str,
    ) -> Result<Option<CSharpMembership>> {
        let conn = self.read_conn()?;
        let complete = conn
            .query_row(
                SET_MEMBERSHIP_SQL,
                params![set_id, DERIVATION_VERSION],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if complete.is_none() || membership_capped(&conn, set_id)? {
            return Ok(None);
        }
        match compilations_of_set(&conn, set_id, candidate_path)? {
            SelectedCSharpMembership::Proven(membership) => Ok(Some(membership)),
            _ => Ok(None),
        }
    }

    /// The compilation rules `snapshot` selects, or `None` when the revision
    /// has no selection that satisfies the validity rule.
    #[doc(hidden)]
    pub fn selected_csharp_compilations(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<Option<SelectedCSharpCompilations<'_>>> {
        let conn = self.read_conn()?;
        let Some(set_id) = selected_set(&conn, snapshot)? else {
            return Ok(None);
        };
        let membership_capped = membership_capped(&conn, set_id.id)?;
        let input_digest = selected_input_digest(&conn, set_id.id)?;
        Ok(Some(SelectedCSharpCompilations {
            conn,
            snapshot: snapshot.clone(),
            set_id: set_id.id,
            input_digest,
            membership_capped,
        }))
    }
}

fn selected_input_digest(conn: &Connection, set_id: i64) -> Result<[u8; 32]> {
    Ok(conn.query_row(
        "SELECT input_digest FROM csharp_compilation_sets WHERE set_id=?1",
        [set_id],
        |row| row.get(0),
    )?)
}

fn selected_set_record(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<(CSharpCompilationSetRef, i64)>> {
    Ok(conn
        .query_row(SELECTED_SET_SQL, snapshot_params(snapshot), |row| {
            Ok((
                CSharpCompilationSetRef {
                    id: row.get(0)?,
                    output_digest: row.get(2)?,
                },
                row.get(1)?,
            ))
        })
        .optional()?)
}

fn selected_set(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<CSharpCompilationSetRef>> {
    let selected = selected_set_record(conn, snapshot)?;
    let Some((set_id, DERIVATION_VERSION)) = selected else {
        return Ok(None);
    };
    Ok(Some(set_id))
}

/// A borrowed view of one revision's compilation rules, with no retained rows.
/// The shared selection's connection is the one an operation already holds;
/// a second checkout would deadlock a test-only single-connection store. The production
/// owner keeps its ReaderGuard and delegates each read through this view.
pub(super) struct CSharpCompilationView<'a> {
    conn: &'a Connection,
    snapshot: &'a WorkspaceSnapshotId,
    set_id: i64,
    #[allow(dead_code)] // Consumed when the native read slice adds certification.
    input_digest: [u8; 32],
    // Derived predicate of this immutable selected set; never declaration authority.
    membership_capped: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CSharpSelectedHandle {
    pub snapshot: WorkspaceSnapshotId,
    pub set_id: i64,
    pub input_digest: [u8; 32],
    pub membership_capped: bool,
}

#[derive(Clone, Debug)]
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub struct CertifiedCSharpHandle(pub(super) CSharpSelectedHandle);

#[cfg(any(test, feature = "test-support"))]
impl CertifiedCSharpHandle {
    /// Direct reader fixtures only; production obtains this through certification.
    pub fn unchecked_for_test(
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<Option<Self>> {
        Ok(CSharpCompilationView::selected(conn, snapshot)?.map(|view| Self(view.handle())))
    }
}

impl SelectedCSharpCompilations<'_> {
    pub fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }
    /// Configuration rows for rendering one selected set in one request.
    pub fn configurations(&self) -> Result<Vec<SelectedCSharpCompilationConfiguration>> {
        let mut statement = self.conn.prepare_cached(SELECTED_CONFIGURATIONS_SQL)?;
        let mut rows = statement.query([self.set_id])?;
        let mut configurations: Vec<SelectedCSharpCompilationConfiguration> = Vec::new();
        let mut last_compilation_id = None;
        while let Some(row) = rows.next()? {
            let project_path: Option<String> = row.get(0)?;
            let compilation_id: i64 = row.get(6)?;
            if last_compilation_id != Some(compilation_id) {
                last_compilation_id = Some(compilation_id);
                configurations.push(SelectedCSharpCompilationConfiguration {
                    project_path,
                    configuration: row.get(1)?,
                    target_framework: row.get(2)?,
                    closed: row.get(3)?,
                    open_reason: row.get(4)?,
                    symbols: Vec::new(),
                    named_open: serde_json::from_str(&row.get::<_, String>(7)?).map_err(|e| {
                        super::StoreError::corrupt(format!("invalid C# named open symbols: {e}"))
                    })?,
                });
            }
            if let Some(symbol) = row.get(5)? {
                configurations
                    .last_mut()
                    .expect("compilation row exists")
                    .symbols
                    .push(symbol);
            }
        }
        for configuration in &mut configurations {
            configuration.symbols.sort_unstable();
        }
        Ok(configurations)
    }

    pub fn membership_capped(&self) -> bool {
        self.membership_capped
    }
    fn view(&self) -> CSharpCompilationView<'_> {
        CSharpCompilationView {
            conn: &self.conn,
            snapshot: &self.snapshot,
            set_id: self.set_id,
            input_digest: self.input_digest,
            membership_capped: self.membership_capped,
        }
    }

    /// Assembly and compilation-wide imports for one selected compilation.
    pub fn metadata(&self, compilation_id: i64) -> Result<Option<CSharpCompilationMetadata>> {
        self.view().metadata(compilation_id)
    }

    /// Whether the rules state all source membership.
    pub fn membership_complete(&self) -> Result<bool> {
        self.view().membership_complete()
    }

    /// Selected source memberships; None when membership is unproven.
    pub fn compilations_of(&self, rel_path: &str) -> Result<Option<CSharpMembership>> {
        self.view().compilations_of(rel_path)
    }

    pub fn open_inventories(&self, compilation: i64) -> Result<Vec<CSharpOpenInventory>> {
        self.view().open_inventories(compilation)
    }

    pub fn inventory_gaps(&self, compilation: i64) -> Result<Vec<CSharpCompilationGap>> {
        self.view().inventory_gaps(compilation)
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

#[derive(Debug)]
pub struct CSharpOpenInventory {
    pub compilation_id: i64,
    pub project_path: Option<String>,
    pub gaps: Vec<CSharpCompilationGap>,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static SOURCE_ENUMERATION_RECOMPUTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn source_enumeration_recomputes_for_test() -> usize {
    SOURCE_ENUMERATION_RECOMPUTES.with(std::cell::Cell::get)
}

/// One file's placements. Open compilations never erase independent proven ones.
#[derive(Debug, Default)]
pub struct CSharpMembership {
    pub proven: Vec<i64>,
    pub open: Vec<CSharpOpenPlacement>,
}
#[derive(Debug)]
pub struct CSharpOpenPlacement {
    pub compilation_id: i64,
    pub project_path: Option<String>,
    pub regions: Vec<CSharpOpenRegion>,
}
#[derive(Debug)]
pub struct CSharpOpenRegion {
    pub kind: String,
    pub rel_path: String,
    pub gaps: Vec<CSharpCompilationGap>,
}
fn decode_gaps(encoded: &str) -> Result<Vec<CSharpCompilationGap>> {
    let rows: Vec<[String; 3]> = serde_json::from_str(encoded)
        .map_err(|e| super::StoreError::corrupt(format!("invalid C# gap pointers: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|[code, path, evidence]| CSharpCompilationGap {
            code,
            path,
            evidence,
        })
        .collect())
}

/// Membership of a caller whose source authority is checked by the selection.
#[derive(Debug)]
pub(super) enum SelectedCSharpMembership {
    Proven(CSharpMembership),
    Unproven {
        #[cfg(any(test, feature = "test-support"))]
        code: &'static str,
        #[cfg(any(test, feature = "test-support"))]
        gaps: Vec<CSharpCompilationGap>,
        #[cfg(any(test, feature = "test-support"))]
        evidence: String,
    },
    #[cfg(any(test, feature = "test-support"))]
    NotSelected,
}

impl<'a> CSharpCompilationView<'a> {
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn handle(&self) -> CSharpSelectedHandle {
        CSharpSelectedHandle {
            snapshot: self.snapshot.clone(),
            set_id: self.set_id,
            input_digest: self.input_digest,
            membership_capped: self.membership_capped,
        }
    }

    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    pub(super) fn certified(
        conn: &'a Connection,
        snapshot: &'a WorkspaceSnapshotId,
        certified: &CertifiedCSharpHandle,
    ) -> Self {
        assert_eq!(snapshot, &certified.0.snapshot);
        Self {
            conn,
            snapshot,
            set_id: certified.0.set_id,
            input_digest: certified.0.input_digest,
            membership_capped: certified.0.membership_capped,
        }
    }
    // The native read slice consumes this captured identity.
    #[allow(dead_code)]
    pub(super) fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }
    pub(in crate::analyzer::store::csharp_compilation) fn selected(
        conn: &'a Connection,
        snapshot: &'a WorkspaceSnapshotId,
    ) -> Result<Option<Self>> {
        let Some(set_id) = selected_set(conn, snapshot)? else {
            return Ok(None);
        };
        let membership_capped = membership_capped(conn, set_id.id)?;
        Ok(Some(Self {
            conn,
            snapshot,
            set_id: set_id.id,
            input_digest: selected_input_digest(conn, set_id.id)?,
            membership_capped,
        }))
    }

    /// Assembly and compilation-wide imports for one member of this selection.
    pub(super) fn metadata(
        &self,
        compilation_id: i64,
    ) -> Result<Option<CSharpCompilationMetadata>> {
        let row = self
            .conn
            .query_row(
                COMPILATION_METADATA_SQL,
                params![self.set_id, compilation_id],
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
    pub(super) fn membership_complete(&self) -> Result<bool> {
        Ok(self
            .conn
            .prepare_cached(MEMBERSHIP_COVERAGE_SQL)?
            .query_row([self.set_id], |r| r.get(0))?)
    }

    pub(super) fn open_inventories(&self, compilation: i64) -> Result<Vec<CSharpOpenInventory>> {
        let mut statement = self.conn.prepare_cached(OPEN_INVENTORIES_SQL)?;
        let mut rows = statement.query([compilation])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let gaps = decode_gaps(&row.get::<_, String>(2)?)?;
            if gaps.is_empty() {
                return Err(super::StoreError::corrupt(
                    "open C# inventory lacks evidence",
                ));
            }
            result.push(CSharpOpenInventory {
                compilation_id: row.get(0)?,
                project_path: row.get(1)?,
                gaps,
            });
        }
        Ok(result)
    }

    pub(super) fn inventory_gaps(&self, compilation: i64) -> Result<Vec<CSharpCompilationGap>> {
        let (open, encoded): (bool, String) = self
            .conn
            .prepare_cached(INVENTORY_SQL)?
            .query_row([compilation], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let gaps = decode_gaps(&encoded)?;
        if open && gaps.is_empty() {
            return Err(super::StoreError::corrupt(
                "open C# inventory has no gap evidence",
            ));
        }
        Ok(gaps)
    }

    /// The compilations that contain the selected source `rel_path`, possibly
    /// none. `None` when membership is not proven: the rules are incomplete
    /// or the revision does not select that source.
    pub(super) fn compilations_of(&self, rel_path: &str) -> Result<Option<CSharpMembership>> {
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

        match self.evaluate_membership(rel_path)? {
            SelectedCSharpMembership::Proven(membership) => Ok(Some(membership)),
            SelectedCSharpMembership::Unproven { .. } => Ok(None),
            #[cfg(any(test, feature = "test-support"))]
            SelectedCSharpMembership::NotSelected => Ok(None),
        }
    }

    /// Membership for a source authorized by this selected inventory, including
    /// a new transient source with no persisted file-version row.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn selected_compilations_of(
        &self,
        selection: &super::resolution_selection::SelectedResolutionMountInventory<'_>,
        rel_path: &str,
    ) -> Result<SelectedCSharpMembership> {
        let Some(mount) = selection.mount_record_for_path("csharp", rel_path)? else {
            return Ok(SelectedCSharpMembership::NotSelected);
        };
        if mount.workspace_id() != self.snapshot.workspace_id.as_str()
            || mount.generation() != self.snapshot.generation.0
            || mount.revision() != self.snapshot.revision
        {
            return Ok(SelectedCSharpMembership::NotSelected);
        }
        // A selected source does not authorize borrowing rules derived from
        // replaced configuration content. A new derived set is needed first.
        let changed = selection
            .connection()
            .prepare_cached(SELECTED_CONFIGURATION_MASK_SQL)?
            .query_row(
                params![
                    self.snapshot.workspace_id.as_str(),
                    self.snapshot.generation.0,
                    self.snapshot.revision
                ],
                |row| row.get::<_, bool>(0),
            )?;
        if changed {
            return self.unproven_selected_membership(rel_path, "configuration_replaced");
        }
        let membership = if self.membership_capped {
            capped_membership(self.conn, self.set_id, rel_path)?
        } else {
            compilations_of_set(self.conn, self.set_id, rel_path)?
        };
        self.with_file_program_evidence(membership, mount.blob_id(), rel_path)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn unproven_selected_membership(
        &self,
        rel_path: &str,
        code: &'static str,
    ) -> Result<SelectedCSharpMembership> {
        let gaps = self.gaps()?;
        let entries = gaps
            .iter()
            .map(|gap| format!("{} at {}", gap.code, gap.path))
            .collect::<Vec<_>>()
            .join("; ");
        Ok(SelectedCSharpMembership::Unproven {
            code,
            evidence: format!("{code}: {entries}; caller: {rel_path}"),
            gaps,
        })
    }

    /// Exact, linked, tree and implicit rules have one evaluator, independent
    /// of how the caller proved that the source belongs to its selection.
    pub(super) fn evaluate_membership(&self, rel_path: &str) -> Result<SelectedCSharpMembership> {
        if self.membership_capped {
            return capped_membership(self.conn, self.set_id, rel_path);
        }
        let membership = compilations_of_set(self.conn, self.set_id, rel_path)?;
        // The file-program obligation applies only to a source no compilation
        // claims. The selected-blob lookup it needs is one statement per
        // membership evaluation, so ordinary members must not pay for it.
        if !matches!(
            &membership,
            SelectedCSharpMembership::Proven(members)
                if members.proven.is_empty() && members.open.is_empty()
        ) {
            return Ok(membership);
        }
        let blob = self.conn.query_row(
            "SELECT blobs.id FROM workspace_file_versions files
             JOIN csharp_file_version_decisions decisions USING(file_version_id)
             JOIN blobs ON blobs.blob_oid=files.blob_oid AND blobs.lang=files.lang
               AND blobs.generation=files.generation AND blobs.parse_variant=decisions.decision_digest
             WHERE files.workspace_id=?1 AND files.lang='csharp' AND files.generation=?2
               AND files.rel_path=?3 AND files.input_kind='source'
               AND files.valid_from<=?4 AND (files.valid_until IS NULL OR ?4<files.valid_until)",
            params![self.snapshot.workspace_id.as_str(), self.snapshot.generation.0,
                rel_path, self.snapshot.revision], |row| row.get::<_, i64>(0),
        ).optional()?;
        match blob {
            Some(blob) => self.with_file_program_evidence(membership, blob, rel_path),
            None => Ok(membership),
        }
    }

    fn with_file_program_evidence(
        &self,
        membership: SelectedCSharpMembership,
        blob: i64,
        _rel_path: &str,
    ) -> Result<SelectedCSharpMembership> {
        if let SelectedCSharpMembership::Proven(ref members) = membership
            && members.proven.is_empty()
            && members.open.is_empty()
        {
            let evidence: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM resolution_gap_reasons WHERE blob_id=?1 AND origin=?2)",
                params![blob, super::resolution_prepare::resolution_rows::gap_origin_code(
                    crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::FileProgramEvidence))],
                |row| row.get(0),
            )?;
            if evidence {
                return Ok(SelectedCSharpMembership::Unproven {
                    #[cfg(any(test, feature = "test-support"))]
                    code: "file_program_unevaluated",
                    #[cfg(any(test, feature = "test-support"))]
                    evidence: format!("file_program_unevaluated: {_rel_path}"),
                    #[cfg(any(test, feature = "test-support"))]
                    gaps: vec![CSharpCompilationGap {
                        code: "file_program_unevaluated".into(),
                        path: _rel_path.into(),
                        evidence: "file program membership has not been evaluated".into(),
                    }],
                });
            }
        }
        Ok(membership)
    }

    /// Every compilation `root` reaches over any ProjectReference edge,
    /// itself included, and whether every reached compilation has known
    /// direct references and a closed declaration inventory. Only then is a
    /// compilation outside the closure provably invisible.
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

pub(super) fn selected_csharp_handle(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<CSharpSelectedHandle>> {
    let Some(set_id) = selected_set(conn, snapshot)? else {
        return Ok(None);
    };
    Ok(Some(CSharpSelectedHandle {
        snapshot: snapshot.clone(),
        set_id: set_id.id,
        input_digest: selected_input_digest(conn, set_id.id)?,
        membership_capped: membership_capped(conn, set_id.id)?,
    }))
}

fn capped_membership(
    _conn: &Connection,
    _set_id: i64,
    _rel_path: &str,
) -> Result<SelectedCSharpMembership> {
    #[cfg(any(test, feature = "test-support"))]
    let gaps = {
        let encoded: String = _conn.query_row(
            "SELECT json(gaps) FROM csharp_compilation_sets WHERE set_id=?1",
            [_set_id],
            |row| row.get(0),
        )?;
        decode_gaps(&encoded)?
    }
    .into_iter()
    .filter(|gap| is_membership_cap(&gap.code))
    .collect::<Vec<_>>();
    #[cfg(any(test, feature = "test-support"))]
    let entries = gaps
        .iter()
        .map(|gap| format!("{} at {}: {}", gap.code, gap.path, gap.evidence))
        .collect::<Vec<_>>()
        .join("; ");
    Ok(SelectedCSharpMembership::Unproven {
        #[cfg(any(test, feature = "test-support"))]
        code: "membership_unproven",
        #[cfg(any(test, feature = "test-support"))]
        evidence: format!("membership_unproven: {entries}; caller: {_rel_path}"),
        #[cfg(any(test, feature = "test-support"))]
        gaps,
    })
}

// Both revision readers and the producer's candidate inventory use this walk.
fn compilations_of_set(
    conn: &Connection,
    set_id: i64,
    rel_path: &str,
) -> Result<SelectedCSharpMembership> {
    let mut ancestors = vec![String::new()];
    for (index, byte) in rel_path.bytes().enumerate() {
        if byte == b'/' {
            ancestors.push(rel_path[..index].to_owned());
        }
    }
    let encoded = serde_json::to_string(&ancestors).expect("paths serialize");
    let mut items = Vec::new();
    for (sql, argument) in [
        (PATH_ITEMS_SQL, rel_path),
        (TREE_ITEMS_SQL, encoded.as_str()),
    ] {
        let mut statement = conn.prepare_cached(sql)?;
        let mut rows = statement.query(params![set_id, argument])?;
        while let Some(row) = rows.next()? {
            let kind: String = row.get(2)?;
            let root: String = row.get(3)?;
            let tree = matches!(kind.as_str(), "include_tree" | "default_tree" | "open_tree");
            if tree {
                if !rel_path
                    .rsplit_once('.')
                    .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("cs"))
                {
                    continue;
                }
                let excluded: Vec<String> = serde_json::from_str(&row.get::<_, String>(4)?)
                    .map_err(|e| {
                        super::StoreError::corrupt(format!("invalid C# excluded trees: {e}"))
                    })?;
                let relative = if root.is_empty() {
                    rel_path
                } else {
                    &rel_path[root.len() + 1..]
                };
                let hidden = kind == "default_tree"
                    && relative
                        .split('/')
                        .rev()
                        .skip(1)
                        .any(|d| d.starts_with('.'));
                if hidden
                    || excluded.iter().any(|d| {
                        d.is_empty()
                            || rel_path
                                .strip_prefix(d)
                                .is_some_and(|rest| rest.starts_with('/'))
                    })
                {
                    continue;
                }
            }
            items.push((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                kind,
                root,
                row.get::<_, Option<String>>(5)?,
                decode_gaps(&row.get::<_, String>(6)?)?,
            ));
        }
    }
    let mut result = CSharpMembership::default();
    let mut members = crate::hash::HashMap::default();
    if let Some(id) = conn
        .prepare_cached(IMPLICIT_COMPILATION_SQL)?
        .query_row([set_id], |r| r.get::<_, i64>(0))
        .optional()?
    {
        members.insert(id, true);
    }
    items.sort_by_key(|item| (item.0, item.1));
    for (id, _, kind, path, project, gaps) in items {
        if matches!(kind.as_str(), "open" | "open_tree") {
            if gaps.is_empty() {
                return Err(super::StoreError::corrupt(
                    "open C# item lacks gap evidence",
                ));
            }
            let index = match result.open.iter().position(|p| p.compilation_id == id) {
                Some(index) => index,
                None => {
                    result.open.push(CSharpOpenPlacement {
                        compilation_id: id,
                        project_path: project,
                        regions: Vec::new(),
                    });
                    result.open.len() - 1
                }
            };
            result.open[index].regions.push(CSharpOpenRegion {
                kind,
                rel_path: path,
                gaps,
            });
        } else {
            members.insert(id, kind != "remove");
        }
    }
    result.proven = members
        .into_iter()
        .filter_map(|(id, member)| {
            (member && !result.open.iter().any(|p| p.compilation_id == id)).then_some(id)
        })
        .collect();
    result.proven.sort_unstable();
    Ok(SelectedCSharpMembership::Proven(result))
}

/// Cross-check incremental certificates against the independent membership recount.
#[cfg(any(test, feature = "test-support"))]
pub fn verify_using_counts_for_test(conn: &Connection) {
    let tx = conn.unchecked_transaction().unwrap();
    let blobs = tx
        .prepare("SELECT id FROM blobs WHERE lang='csharp'")
        .unwrap()
        .query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for blob in blobs {
        extent::content_available(&tx, "csharp", blob).unwrap();
        extent::content_available(&tx, "csharp", blob).unwrap();
    }
    let mut statement=tx.prepare("SELECT workspace_id,generation,compilation_id,valid_from,publications_expected,publications_installed,membership_complete,metadata_complete,json(reasons) FROM csharp_compilation_using_coverage").unwrap();
    let mut rows = statement.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let workspace: String = row.get(0).unwrap();
        let generation: i64 = row.get(1).unwrap();
        let compilation: i64 = row.get(2).unwrap();
        let revision: i64 = row.get(3).unwrap();
        let actual: (i64, i64) = (row.get(4).unwrap(), row.get(5).unwrap());
        let expected: (i64, i64) = tx
            .query_row(
                extent::COUNTS_SQL,
                params![
                    workspace,
                    generation,
                    compilation,
                    revision,
                    tx.query_row(
                        "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='csharp'",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .unwrap(),
                    0
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(actual, expected, "{workspace}/{compilation}@{revision}");
        let source_enumeration =
            extent::source_enumeration_paths(&tx, &workspace, generation, compilation, revision)
                .unwrap();
        assert_eq!(
            row.get::<_, String>(8).unwrap(),
            extent::coverage_reasons(
                row.get(6).unwrap(),
                row.get(7).unwrap(),
                expected.0,
                expected.1,
                &source_enumeration
            ),
            "{workspace}/{compilation}@{revision}: reasons follow the evidence"
        );
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
    #[brokk_bifrost_test_macros::hardwon(
        "#10342: local covering gaps poisoned global using certificates"
    )]
    fn csharp_compilation_enumeration_predicates_follow_error_edits() {
        use super::super::resolution_prepare::resolution_rows::gap_origin_code;
        use crate::analyzer::resolution::LoweringGapOrigin;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        let _fixture = super::super::sealed_families::Fixture::new(&conn);
        conn.execute_batch("INSERT INTO blobs(id,blob_oid,lang,generation) VALUES(1,'1111111111111111111111111111111111111111','csharp',1);
            INSERT INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,interior_digest,logical_rows,payload_bytes,publication_state,expected_semantic_site_count) VALUES(1,'csharp','csharp','test',zeroblob(32),1,0,'complete',0);
            INSERT INTO resolution_gap_reasons VALUES(1,0,0,0);
            INSERT INTO resolution_gaps VALUES(1,1,0,0,0,0);
            CREATE TEMP TABLE selected_csharp_compilation_members(compilation_id INTEGER,rel_path TEXT,blob_id INTEGER);
            INSERT INTO selected_csharp_compilation_members VALUES(1,'Peer.cs',1);").unwrap();
        for (kind, incomplete) in [
            (ResolutionGapKind::UnsupportedRoute, false),
            (ResolutionGapKind::CompilationImportsUnenumerated, true),
            (ResolutionGapKind::UnsupportedRoute, false),
        ] {
            conn.execute(
                "UPDATE resolution_gap_reasons SET origin=?1",
                [gap_origin_code(LoweringGapOrigin::Extracted(kind))],
            )
            .unwrap();
            let delta: bool = conn
                .query_row(extent::BLOB_COVERING_GAP_SQL, [1], |row| row.get(0))
                .unwrap();
            let overlay: String = conn
                .query_row(extent::OVERLAY_COUNTS_SQL, [1], |row| row.get(2))
                .unwrap();
            assert_eq!(delta, incomplete);
            assert_eq!(overlay, if incomplete { "[\"Peer.cs\"]" } else { "[]" });
        }
    }

    #[test]
    fn csharp_compilation_readers_plan_on_membership_indexes() {
        let store = AnalyzerStore::open_ephemeral_temp_file(
            &Default::default(),
            &brokk_bifrost_core::retention_budget::RetentionBudget::new(1024 * 1024 * 1024),
        )
        .unwrap();
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
                       projection_digest, valid_from, file_present
                     ) VALUES(?1, 'csharp', ?2, ?3, ?4, 'configuration', NULL, ?5, 1)",
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
        // A nonblank chain in this snapshot, one in another generation and
        // one in another workspace must all be present while planning.
        conn.execute_batch("INSERT INTO blobs(blob_oid,lang,parse_variant,generation)
            VALUES(printf('%040x',0),'csharp',zeroblob(32),1),
                  (printf('%040x',998),'csharp',zeroblob(32),2),
                  (printf('%040x',999),'csharp',zeroblob(32),1);
            INSERT INTO csharp_undecided_chains(blob_id,chain,directive_start,directive_end,omitted_nonblank,invalid_condition,unknown_symbols,open_reasons,disagreeing_owners)
            SELECT id,0,0,1,1,0,jsonb('[]'),jsonb('[]'),jsonb('[]') FROM blobs;
            INSERT INTO csharp_undecided_chains(blob_id,chain,directive_start,directive_end,omitted_nonblank,invalid_condition,unknown_symbols,open_reasons,disagreeing_owners)
            SELECT id,1,2,3,0,0,jsonb('[]'),jsonb('[]'),jsonb('[]') FROM blobs WHERE generation=1 LIMIT 1;
            INSERT INTO csharp_file_version_decisions(file_version_id,decision_digest,assignment_digest)
            SELECT file_version_id,zeroblob(32),zeroblob(32) FROM workspace_file_versions WHERE rel_path='App/Source000.cs';").unwrap();
        conn.execute(
            "INSERT INTO workspace_revisions VALUES(?1,'csharp',2,1)",
            [WORKSPACE],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspace_revisions VALUES(?1,'csharp',1,1)",
            ["b".repeat(64)],
        )
        .unwrap();
        for (workspace, generation, path, oid) in [
            (
                WORKSPACE.to_string(),
                2,
                "OtherGeneration.cs",
                format!("{:040x}", 998),
            ),
            (
                "b".repeat(64),
                1,
                "OtherWorkspace.cs",
                format!("{:040x}", 999),
            ),
        ] {
            conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,'csharp',?2,?3,?4,?5,1)",params![workspace,generation,path,oid,"0".repeat(64)]).unwrap();
            conn.execute("INSERT INTO csharp_file_version_decisions(file_version_id,decision_digest,assignment_digest) VALUES(?1,zeroblob(32),zeroblob(32))",[conn.last_insert_rowid()]).unwrap();
        }
        conn.execute(
            "INSERT INTO csharp_compilation_sets(
               set_id, workspace_id, lang, generation, derivation_version,
               input_digest, output_digest, gaps
             ) VALUES(?1, ?2, 'csharp', ?3, ?4, ?5, ?5, jsonb(?6))",
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

        {
            let tx = conn.unchecked_transaction().unwrap();
            extent::publish(
                &tx,
                &WorkspaceSnapshotId {
                    workspace_id: crate::analyzer::store::WorkspaceId(WORKSPACE.into()),
                    lang: STORAGE_LANGUAGE.into(),
                    generation: crate::analyzer::store::GenerationId(GENERATION),
                    revision: REVISION,
                },
                None,
                &[],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        conn.execute("INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent)
            VALUES('csharp','App/Sub/Thing.cs','removal')",[]).unwrap();
        let affected = conn
            .prepare(extent::OVERLAY_AFFECTED_SQL)
            .unwrap()
            .query_map(
                params![SET_ID, false, WORKSPACE, GENERATION, REVISION],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(affected.len(), COMPILATION_COUNT as usize, "{affected:?}");
        {
            let retained = store.checkout_read_conn().unwrap();
            crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(
                &retained,
            );
            let conn = &*retained;
            conn.execute(
                "INSERT INTO temp.selected_resolution_context VALUES(0,?1)",
                [WORKSPACE],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO temp.selected_workspace_revisions VALUES(?1,'csharp',?2,?3)",
                params![WORKSPACE, GENERATION, REVISION],
            )
            .unwrap();
            let tx = conn.unchecked_transaction().unwrap();
            assert!(extent::stage(&tx, &crate::CancellationToken::new()).unwrap());
            let first: i64 = tx
                .query_row(
                    "SELECT count(*) FROM temp.selected_csharp_compilation_using_coverage",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(first > 0, "staging ran");
            assert!(extent::stage(&tx, &crate::CancellationToken::new()).unwrap());
            assert_eq!(
                tx.query_row(
                    "SELECT count(*) FROM temp.selected_csharp_compilation_using_coverage",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                first
            );
            tx.commit().unwrap();
        }
        let cases: [(&str, Vec<Vec<&str>>); 31] = [
            (
                "csharp_compilation_metadata",
                vec![vec!["USING INTEGER PRIMARY KEY"]],
            ),
            (
                "csharp_owner_environment",
                vec![vec!["USING INTEGER PRIMARY KEY"], vec!["USING PRIMARY KEY"]],
            ),
            (
                "csharp_selected_configurations",
                vec![
                    vec!["idx_csharp_compilations_set_instance"],
                    vec!["USING COVERING INDEX", "USING PRIMARY KEY"],
                ],
            ),
            (
                "csharp_selected_file_decision",
                vec![
                    vec![
                        "idx_workspace_file_versions_snapshot_path",
                        "idx_workspace_file_versions_snapshot_kind",
                    ],
                    vec!["USING INTEGER PRIMARY KEY"],
                ],
            ),
            (
                "csharp_selected_refusal_paths",
                vec![vec!["USING PRIMARY KEY"]],
            ),
            (
                "csharp_file_version_decision",
                vec![
                    vec![
                        "idx_workspace_file_versions_snapshot_path",
                        "idx_workspace_file_versions_snapshot_kind",
                    ],
                    vec!["USING INTEGER PRIMARY KEY"],
                ],
            ),
            (
                "csharp_referenced_symbols",
                vec![vec!["USING COVERING INDEX"], vec!["USING PRIMARY KEY"]],
            ),
            (
                "csharp_set_membership",
                vec![vec!["USING INTEGER PRIMARY KEY"]],
            ),
            (
                "csharp_missing_decisions",
                vec![
                    vec!["idx_workspace_file_versions"],
                    vec!["USING INTEGER PRIMARY KEY"],
                ],
            ),
            (
                "workspace_path_parse_variants",
                vec![
                    vec!["CORRELATED SCALAR SUBQUERY"],
                    vec![
                        "idx_workspace_file_versions_snapshot_path",
                        "idx_workspace_file_versions_snapshot_kind",
                    ],
                    vec!["USING INTEGER PRIMARY KEY"],
                ],
            ),
            (
                "csharp_existing_set_content",
                vec![vec!["sqlite_autoindex_csharp_compilation_sets"]],
            ),
            (
                "csharp_selected_set_content",
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
                "csharp_uncertified_selected",
                vec![
                    vec!["idx_workspace_file_versions_snapshot_kind"],
                    vec!["SEARCH decisions USING INTEGER PRIMARY KEY"],
                    vec![
                        "SEARCH blobs USING COVERING INDEX",
                        "SEARCH blobs USING INDEX",
                    ],
                    vec!["SEARCH blob_meta USING PRIMARY KEY"],
                ],
            ),
            (
                "csharp_extent_source_enumeration",
                vec![vec!["idx_csharp_members_snapshot"]],
            ),
            (
                "csharp_extent_path_source_enumeration",
                vec![vec!["idx_csharp_members_path"]],
            ),
            ("csharp_extent_overlay_counts", vec![]),
            (
                "csharp_extent_blob_covering_gap",
                vec![
                    vec!["SEARCH g USING PRIMARY KEY"],
                    vec!["SEARCH r USING PRIMARY KEY"],
                ],
            ),
            (
                "csharp_extent_stored_source_enumeration",
                vec![vec!["USING PRIMARY KEY", "USING COVERING INDEX"]],
            ),
            ("csharp_selected_global_using_coverage", vec![]),
            ("csharp_selected_global_using_sites", vec![]),
            (
                "csharp_unseen_branch_files",
                vec![
                    vec!["SCAN chains USING INDEX idx_csharp_undecided_chains_nonblank"],
                    vec!["SEARCH blobs USING INTEGER PRIMARY KEY"],
                    vec!["SEARCH files USING INDEX idx_workspace_file_versions_snapshot_blob"],
                    vec!["SEARCH decisions USING INTEGER PRIMARY KEY"],
                ],
            ),
            (
                "open_file_version_decision",
                vec![vec!["idx_workspace_file_versions"]],
            ),
            (
                "open_partition_decisions",
                vec![vec!["idx_workspace_file_versions"]],
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
                if name.contains("source_enumeration")
                    || name.contains("covering_gap")
                    || name.contains("global_using")
                    || *name == "csharp_extent_overlay_counts"
                {
                    // Only one-row constants, JSON of one value, the one-row
                    // extent state and a compilation's staged members may be
                    // scanned; every persisted table is reached by an index.
                    for detail in &plan {
                        assert!(
                            !detail.starts_with("SCAN ")
                                || [
                                    "SCAN CONSTANT ROW",
                                    "SCAN j VIRTUAL TABLE",
                                    "SCAN m",
                                    "SCAN temp.selected_csharp_extent_state"
                                ]
                                .iter()
                                .any(|allowed| detail.starts_with(allowed)),
                            "{state} {name}: scanned a table: {plan:#?}"
                        );
                    }
                }
                if *name == "csharp_unseen_branch_files" {
                    assert!(
                        plan.first().is_some_and(|line| line.contains(
                            "SCAN chains USING INDEX idx_csharp_undecided_chains_nonblank"
                        )),
                        "{state}: nonblank chains must drive the reader: {plan:?}"
                    );
                }
                let required = required
                    .iter()
                    .map(|alternatives| alternatives.as_slice())
                    .collect::<Vec<_>>();
                assert_pin_plan(state, name, &plan, &required);
            }
            let plan = explain_pin(&conn, &pinned("csharp_extent_overlay_affected"));
            assert!(
                plan.iter()
                    .any(|line| line
                        .contains("idx_csharp_members_path (workspace_id=? AND rel_path=?)")),
                "{state}: overlay masks must seek individual member paths: {plan:?}"
            );
        }
        conn.execute("UPDATE csharp_compilations SET symbols_closed = 1, open_reason = NULL WHERE compilation_id = 1", []).unwrap();
        conn.execute("INSERT INTO csharp_compilation_symbols(compilation_id, symbol, source) VALUES(1, 'DEBUG', 'define_constants')", []).unwrap();
        drop(conn);
        let environment = store.csharp_owner_environment(1).unwrap().unwrap();
        assert_eq!(environment.owner_key, "\0loose");
        assert_eq!(environment.symbols, ["DEBUG"]);
        assert!(environment.closed);
        assert_eq!(environment.open_reason, None);
        assert_eq!(
            store
                .csharp_owner_environment(2)
                .unwrap()
                .unwrap()
                .owner_key,
            "Proj2/Proj2.csproj"
        );
        assert_eq!(store.csharp_owner_environment(-1).unwrap(), None);
        let snapshot = WorkspaceSnapshotId {
            workspace_id: super::super::WorkspaceId(WORKSPACE.to_owned()),
            lang: STORAGE_LANGUAGE.to_owned(),
            generation: super::super::GenerationId(GENERATION),
            revision: REVISION,
        };
        let selected = store
            .selected_csharp_compilations(&snapshot)
            .unwrap()
            .unwrap();
        let path = "App/Sub/Thing.cs";
        assert_eq!(
            selected.compilations_of(path).unwrap().unwrap().proven,
            store
                .csharp_compilations_of_set(SET_ID, path)
                .unwrap()
                .unwrap()
                .proven
        );
        let candidate = "App/Sub/NotYetPublished.cs";
        assert_eq!(
            selected
                .compilations_of(candidate)
                .unwrap()
                .map(|m| m.proven),
            None
        );
        assert!(
            store
                .csharp_compilations_of_set(SET_ID, candidate)
                .unwrap()
                .unwrap()
                .proven
                .contains(&1)
        );
        assert_eq!(
            store
                .csharp_compilations_of_set(-1, candidate)
                .unwrap()
                .map(|m| m.proven),
            None
        );
    }

    #[test]
    fn unseen_branch_reader_keeps_retained_revision_flags() {
        use super::super::{ParseVariant, WorkspaceFileRow, WorkspaceId};
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("csharp", "unseen-test")
            .unwrap();
        let workspace = WorkspaceId("e".repeat(64));
        let oid = git2::Oid::from_str("1111111111111111111111111111111111111111").unwrap();
        let other_oid = git2::Oid::from_str("2222222222222222222222222222222222222222").unwrap();
        let keys = [
            crate::gitblob::BlobKey {
                oid,
                lang: "csharp".into(),
                variant: ParseVariant::Digest([1; 32]),
            },
            crate::gitblob::BlobKey {
                oid: other_oid,
                lang: "csharp".into(),
                variant: ParseVariant::Digest([2; 32]),
            },
            crate::gitblob::BlobKey {
                oid,
                lang: "csharp".into(),
                variant: ParseVariant::Digest([3; 32]),
            },
        ];
        let decision = |byte| FileVersionDecision {
            decision_digest: [byte; 32],
            assignment_digest: [byte; 32],
        };
        let first_files = [
            WorkspaceFileRow {
                rel_path: "Flagged.cs".into(),
                blob_oid: oid,
                decision: Some(decision(1)),
            },
            WorkspaceFileRow {
                rel_path: "Quiet.cs".into(),
                blob_oid: other_oid,
                decision: Some(decision(2)),
            },
        ];
        let publish = |files: &[WorkspaceFileRow]| {
            store
                .sync_workspace_inputs_for_workspace(
                    &workspace,
                    "csharp",
                    generation,
                    files,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap()
        };
        let old = publish(&first_files);
        assert!(store.unseen_branch_files(&old).unwrap().is_empty());
        store.register_blobs(&keys, generation).unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute("INSERT INTO csharp_undecided_chains(blob_id,chain,directive_start,directive_end,omitted_nonblank,invalid_condition,unknown_symbols,open_reasons,disagreeing_owners) VALUES((SELECT id FROM blobs WHERE blob_oid=?1 AND lang='csharp' AND parse_variant=?2),0,4,12,1,0,jsonb('[\"DEBUG\"]'),jsonb('[]'),jsonb('[]'))", params![oid.to_string(), [1u8; 32].as_slice()]).unwrap();
        drop(conn);
        let expected = UnseenBranchFile {
            rel_path: "Flagged.cs".into(),
            variant: [1; 32],
            chains: vec![UndecidedChainRow {
                chain: 0,
                directive_start: 4,
                directive_end: 12,
                omitted_nonblank: true,
                invalid_condition: false,
                unknown_symbols: vec!["DEBUG".into()],
                open_reasons: vec![],
                disagreeing_owners: vec![],
            }],
        };
        assert_eq!(
            store.unseen_branch_files(&old).unwrap(),
            std::slice::from_ref(&expected)
        );
        let new = publish(&[
            WorkspaceFileRow {
                decision: Some(decision(3)),
                ..first_files[0].clone()
            },
            first_files[1].clone(),
        ]);
        assert_eq!(store.unseen_branch_files(&old).unwrap(), [expected]);
        assert!(store.unseen_branch_files(&new).unwrap().is_empty());
    }

    #[test]
    fn selected_source_census_counts_missing_and_incomplete_publications() {
        use super::super::{BlobKey, ParseVariant, WorkspaceFileRow, WorkspaceId};
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("csharp", "census-fixture")
            .unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let names = [
            "Flagged.cs",
            "Empty.cs",
            "Incomplete.cs",
            "MissingBlob.cs",
            "MissingDecision.cs",
        ];
        let oids = (1..=5)
            .map(|n| git2::Oid::from_str(&format!("{n:040x}")).unwrap())
            .collect::<Vec<_>>();
        let files = names
            .iter()
            .enumerate()
            .map(|(i, name)| WorkspaceFileRow {
                rel_path: (*name).into(),
                blob_oid: oids[i],
                decision: (i != 4).then_some(FileVersionDecision {
                    decision_digest: [i as u8 + 1; 32],
                    assignment_digest: [i as u8 + 1; 32],
                }),
            })
            .collect::<Vec<_>>();
        let snapshot = store
            .sync_workspace_inputs_for_workspace(
                &workspace,
                "csharp",
                generation,
                &files,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let keys = (0..3)
            .map(|i| BlobKey {
                oid: oids[i],
                lang: "csharp".into(),
                variant: ParseVariant::Digest([i as u8 + 1; 32]),
            })
            .collect::<Vec<_>>();
        store.register_blobs(&keys, generation).unwrap();
        let insert_meta = |oid: git2::Oid, digest: u8, complete: bool| {
            store.conn.lock().unwrap().execute(
                "INSERT INTO blob_meta(blob_id,lang,contains_tests,content_package,stored_unit_count,range_count,signature_count,signature_metadata_count,supertype_count,child_count,import_statement_count,type_identifier_count,is_complete) SELECT id,'csharp',0,'',0,0,0,0,0,0,0,0,?3 FROM blobs WHERE blob_oid=?1 AND parse_variant=?2",
                params![oid.to_string(), [digest;32].as_slice(), complete],
            ).unwrap();
        };
        insert_meta(oids[0], 1, true);
        insert_meta(oids[1], 2, true); // A complete zero-chain result is certified.
        insert_meta(oids[2], 3, false);
        store.conn.lock().unwrap().execute(
            "INSERT INTO csharp_undecided_chains(blob_id,chain,directive_start,directive_end,omitted_nonblank,invalid_condition,unknown_symbols,open_reasons,disagreeing_owners) VALUES((SELECT id FROM blobs WHERE blob_oid=?1 AND parse_variant=?2),0,0,1,1,0,jsonb('[]'),jsonb('[]'),jsonb('[]'))",
            params![oids[0].to_string(), [1u8;32].as_slice()],
        ).unwrap();
        let census = store
            .csharp_selected_unseen_branch_census(&snapshot, generation, &[])
            .unwrap();
        assert_eq!(census.uncertified_count, 3);
        assert_eq!(census.rows.len(), 1);
        assert_eq!(census.rows[0].rel_path, "Flagged.cs");
        assert_eq!(census.sample.len(), 3);
        let masked = store
            .csharp_selected_unseen_branch_census(
                &snapshot,
                generation,
                &["MissingDecision.cs".into(), "Flagged.cs".into()],
            )
            .unwrap();
        assert_eq!(masked.uncertified_count, 2);
        assert!(masked.rows.is_empty());
        let zero_chain_only = store
            .csharp_selected_unseen_branch_census(
                &snapshot,
                generation,
                &[
                    "Flagged.cs".into(),
                    "Incomplete.cs".into(),
                    "MissingBlob.cs".into(),
                    "MissingDecision.cs".into(),
                ],
            )
            .unwrap();
        assert_eq!(zero_chain_only.uncertified_count, 0);
        assert!(zero_chain_only.rows.is_empty());
        store.conn.lock().unwrap().execute(
            "UPDATE blob_meta SET is_complete=1 WHERE blob_id=(SELECT id FROM blobs WHERE blob_oid=?1 AND parse_variant=?2)",
            params![oids[2].to_string(), [3u8;32].as_slice()],
        ).unwrap();
        let census = store
            .csharp_selected_unseen_branch_census(&snapshot, generation, &[])
            .unwrap();
        assert_eq!(census.uncertified_count, 2);
        let key = BlobKey {
            oid: oids[3],
            lang: "csharp".into(),
            variant: ParseVariant::Digest([4; 32]),
        };
        store.register_blobs(&[key], generation).unwrap();
        insert_meta(oids[3], 4, true);
        let census = store
            .csharp_selected_unseen_branch_census(&snapshot, generation, &[])
            .unwrap();
        assert_eq!(census.uncertified_count, 1);
        assert_eq!(census.sample, ["MissingDecision.cs"]);
        store
            .ensure_language_epoch_value("csharp", "next-census-epoch")
            .unwrap();
        let stale = store.csharp_selected_unseen_branch_census(&snapshot, generation, &[]);
        assert!(
            stale.is_err(),
            "old generation cannot certify after an epoch advance"
        );
    }

    #[test]
    fn decision_replacement_keeps_earlier_revisions_for_unchanged_content() {
        use super::super::{WorkspaceFileRow, WorkspaceId, WorkspaceSnapshots};
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("csharp", "configured-test")
            .unwrap();
        let workspace = WorkspaceId("c".repeat(64));
        let oid = git2::Oid::from_str("1111111111111111111111111111111111111111").unwrap();
        let files = [WorkspaceFileRow {
            decision: None,
            rel_path: "App.cs".into(),
            blob_oid: oid,
        }];
        let first = FileVersionDecision {
            decision_digest: [1; 32],
            assignment_digest: [11; 32],
        };
        let second = FileVersionDecision {
            decision_digest: [2; 32],
            assignment_digest: [12; 32],
        };
        let third = FileVersionDecision {
            decision_digest: [3; 32],
            assignment_digest: [13; 32],
        };
        let publish = |decision| {
            store
                .sync_workspace_inputs_for_workspace(
                    &workspace,
                    "csharp",
                    generation,
                    &[WorkspaceFileRow {
                        decision: Some(decision),
                        ..files[0].clone()
                    }],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap()
        };
        let legacy = store
            .sync_workspace_inputs_for_workspace(
                &workspace,
                "csharp",
                generation,
                &files,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let old = publish(first);
        assert!(old.revision > legacy.revision);
        assert_eq!(
            store
                .csharp_file_version_decision(&legacy, "App.cs")
                .unwrap(),
            None
        );
        let current = publish(second);
        assert!(current.revision > old.revision);
        assert_eq!(
            publish(second),
            current,
            "unchanged identity carries the file version forward"
        );
        assert_eq!(
            store.csharp_file_version_decision(&old, "App.cs").unwrap(),
            Some(first)
        );
        assert_eq!(
            store
                .csharp_file_version_decision(&current, "App.cs")
                .unwrap(),
            Some(second)
        );
        assert_eq!(
            store
                .csharp_file_version_decision(&current, "Absent.cs")
                .unwrap(),
            None
        );
        let snapshots = [("csharp".into(), current.clone())]
            .into_iter()
            .collect::<WorkspaceSnapshots>();
        let generations = [("csharp".into(), generation)]
            .into_iter()
            .collect::<crate::hash::HashMap<_, _>>();
        let changed = store
            .replace_path_symbol_unit(
                &workspace,
                &snapshots,
                &["csharp".into()],
                &generations,
                "App.cs",
                Some(("csharp", oid, Some(third))),
                None,
                &[],
                &[],
                &[],
                &[],
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .csharp_file_version_decision(&changed["csharp"], "App.cs")
                .unwrap(),
            Some(third)
        );
        assert_eq!(
            store.csharp_file_version_decision(&old, "App.cs").unwrap(),
            Some(first)
        );
        assert_eq!(
            store
                .csharp_file_version_decision(&current, "App.cs")
                .unwrap(),
            Some(second)
        );
        let conn = store.read_conn().unwrap();
        assert_eq!(conn.query_row("SELECT count(*), count(DISTINCT blob_oid) FROM workspace_file_versions WHERE input_kind = 'source'", [], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?))).unwrap(), (4,1));
        drop(conn);
        let other = WorkspaceId("d".repeat(64));
        let legacy = store
            .sync_workspace_inputs_for_workspace(
                &other,
                "csharp",
                generation,
                &files,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let base = [("csharp".into(), legacy.clone())]
            .into_iter()
            .collect::<WorkspaceSnapshots>();
        let updated = store
            .replace_path_symbol_unit(
                &other,
                &base,
                &["csharp".into()],
                &generations,
                "App.cs",
                Some(("csharp", oid, Some(first))),
                None,
                &[],
                &[],
                &[],
                &[],
                None,
                None,
            )
            .unwrap();
        assert!(updated["csharp"].revision > legacy.revision);
        assert_eq!(
            store
                .csharp_file_version_decision(&legacy, "App.cs")
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .csharp_file_version_decision(&updated["csharp"], "App.cs")
                .unwrap(),
            Some(first)
        );
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
                inventory_gap_indices: Vec::new(),
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
            &snapshot.workspace_id,
            snapshot.generation,
            &[1; 32],
            &facts("../MissingA/MissingA.csproj"),
        )
        .unwrap();
        let second = insert_set(
            &tx,
            &snapshot.workspace_id,
            snapshot.generation,
            &[2; 32],
            &facts("../MissingB/MissingB.csproj"),
        )
        .unwrap();
        let same = insert_set(
            &tx,
            &snapshot.workspace_id,
            snapshot.generation,
            &[3; 32],
            &facts("../MissingA/MissingA.csproj"),
        )
        .unwrap();
        assert_ne!(
            digest(first.id),
            digest(second.id),
            "gap evidence is caller-visible output"
        );
        assert_eq!(
            digest(first.id),
            digest(same.id),
            "equal rules and gaps keep one output identity"
        );
    }
}
