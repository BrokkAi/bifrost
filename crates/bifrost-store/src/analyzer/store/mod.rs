#[doc(hidden)]
pub mod cache_budget;
#[doc(hidden)]
pub mod semantic_composition;

pub mod language_support;
pub use language_support::{StoreLanguageSupport, StoreLanguageTable};

/// Store and resolution capabilities for a registered language.
#[doc(hidden)]
pub fn store_language_support(
    language: crate::analyzer::Language,
) -> Option<&'static dyn StoreLanguageSupport> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(support) = language_support::neutral_fixture::support(language) {
        return Some(support);
    }
    linked_store_language_support(language)
}

/// Linked capability metadata is independent of query-local test overlays.
fn linked_store_language_support(
    language: crate::analyzer::Language,
) -> Option<&'static dyn StoreLanguageSupport> {
    unsafe extern "Rust" {
        safe fn __brokk_bifrost_store_language_supports_v1() -> &'static StoreLanguageTable;
    }

    let index = language_support::language_index(language)?;
    __brokk_bifrost_store_language_supports_v1()[index]
}

/// Resolve hook support, distinguishing an absent language from default hooks.
#[doc(hidden)]
pub fn store_language_support_for_hook(
    language: crate::analyzer::Language,
    hook: &str,
) -> Option<&'static dyn StoreLanguageSupport> {
    if language == crate::analyzer::Language::None {
        return None;
    }
    Some(
        store_language_support(language)
            .unwrap_or_else(|| panic!("unregistered language {language:?} for hook {hook}")),
    )
}

use self::resolution::PreparedResolutionBundle;

#[cfg(test)]
use self::resolution_prepare::prepare_resolution_bundle_with_source_facts;

use self::semantic_ir::PreparedSemanticIr;
use self::semantic_ir::SemanticIrLoweringOutcome;
use self::semantic_ir::insert_semantic_ir_tx;
use self::semantic_ir::semantic_ir_producer_epoch;

use crate::CancellationToken;

use crate::analyzer::fq_name::FqName;
use crate::analyzer::fq_name::SegmentKind;
use crate::analyzer::fq_name::segment_interner;

use crate::analyzer::model::MAX_SIGNATURE_METADATA_COLUMN_BYTES;

use crate::analyzer::read_ledger::IndexFamily;

use crate::analyzer::semantic::partial_flow::fixpoint::parse_time_partial_flows;

use crate::analyzer::semantic::service::ProgramSemanticsLowerer;
use crate::analyzer::semantic::service::semantic_artifact_key_from_content;

use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::semantic::SemanticArtifact;
use crate::analyzer::semantic::SemanticArtifactBuildError;
use crate::analyzer::semantic::SemanticBudget;
use crate::analyzer::semantic::SemanticOutcome;
use crate::analyzer::semantic::StableDigest;

use crate::analyzer::structural::DeclaredVisibility;

use crate::analyzer::structural::facts::AssignmentShape;

use crate::analyzer::store::structural_vocabulary::PersistedCallSite;

use crate::analyzer::store::structural_vocabulary::PersistedOccurrenceRole;

use crate::analyzer::store::structural_vocabulary::PersistedRecoveredRegion;

use crate::analyzer::store::structural_vocabulary::PersistedSpan;

use crate::analyzer::store::structural_vocabulary::PersistedStructuralFacts;

use crate::analyzer::store::structural_vocabulary::PersistedStructuralNode;

use crate::analyzer::store::structural_vocabulary::PersistedStructuralRole;

use crate::analyzer::structural::materialization::MaterializationRecord;
use crate::analyzer::structural::materialization::MaterializationRecordPayload;

use crate::analyzer::store::file_state::FileState;

pub use language_adapter::StoreLanguageAdapter;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use crate::analyzer::CallableArity;
use crate::analyzer::CallableLinkage;
use crate::analyzer::CallableOverrideModifier;
use crate::analyzer::CodeUnit;
use crate::analyzer::CodeUnitType;
use crate::analyzer::CppFieldLinkage;
use crate::analyzer::DispatchExtensibility;
use crate::analyzer::ImportInfo;
use crate::analyzer::Language;
use crate::analyzer::PackageAnchor;
use crate::analyzer::ParameterMetadata;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;
use crate::analyzer::RubyMethodDispatchMode;
use crate::analyzer::SignatureMetadata;
use crate::analyzer::StructuredImportPath;
use crate::analyzer::StructuredImportPathKind;
use crate::analyzer::StructuredImportScope;
use crate::analyzer::StructuredTypeIdentity;
use crate::analyzer::SummaryFileProjection;

use crate::gitblob;

use crate::hash::HashMap;
use crate::hash::HashSet;
use crate::hash::set_with_capacity;

use crate::text_utils::compute_line_starts;

use brokk_bifrost_core::analyzer::RelationalName;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;
use brokk_bifrost_core::analyzer::canonical_hash::write_length_prefixed as hash_length_prefixed;

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;

#[doc(hidden)]
pub use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;

use brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_CODE;
use brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_MACRO;
use brokk_bifrost_core::analyzer::rust_facts::RustExportFact;
use brokk_bifrost_core::analyzer::rust_facts::RustIdentifierOccurrence;
use brokk_bifrost_core::analyzer::rust_facts::RustImportTargetFact;
use brokk_bifrost_core::analyzer::rust_facts::RustIncludeEdgeFact;
use brokk_bifrost_core::analyzer::rust_facts::RustIncludeHostBindingFact;
use brokk_bifrost_core::analyzer::rust_facts::RustMacroGateFact;
use brokk_bifrost_core::analyzer::rust_facts::RustModuleFact;
use brokk_bifrost_core::analyzer::rust_facts::RustModuleRouteFact;
use brokk_bifrost_core::analyzer::rust_facts::RustModuleRouteFacts;
use brokk_bifrost_core::analyzer::rust_facts::RustModuleScopeFact;
use brokk_bifrost_core::analyzer::rust_facts::RustRulesItemMacroDefinition;
use brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts;
use brokk_bifrost_core::analyzer::rust_facts::decode_rust_cfg_condition;
use brokk_bifrost_core::analyzer::rust_facts::decode_rust_include_binding_kind;
use brokk_bifrost_core::analyzer::rust_facts::decode_rust_visibility;
use brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition;
use brokk_bifrost_core::analyzer::rust_facts::encode_rust_include_binding_kind;
use brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;

use brokk_bifrost_core::analyzer::source_facts::SourceImportId;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use brokk_bifrost_core::cache_db::OPTIONAL_FACT_KIND_CPP_CLASS_TEMPLATE;
use brokk_bifrost_core::cache_db::OPTIONAL_FACT_KIND_MATERIALIZATION_RECORD;
use brokk_bifrost_core::cache_db::OPTIONAL_FACT_KIND_RUBY_METHOD_DISPATCH_MODE;
use brokk_bifrost_core::cache_db::OPTIONAL_FACT_KIND_SCALA_EXPORT;
use brokk_bifrost_core::cache_db::OPTIONAL_FACT_KIND_SCALA_TRAIT;
use brokk_bifrost_core::cache_db::OPTIONAL_FACT_KIND_SIGNATURE_METADATA_SIGNATURE;

use git2::Oid;

pub(crate) use go_package_context::GoContextHeadStatus;
pub(crate) use go_package_context::GoContextIdentity;

use growable_bloom_filter::GrowableBloom;

#[doc(hidden)]
pub use import_graph::WorkspaceImportDirection;

#[doc(hidden)]
pub use import_graph::WorkspaceImportGraphBinding;

#[doc(hidden)]
pub use import_graph::WorkspaceImportGraphDependencies;

#[doc(hidden)]
pub use import_graph::WorkspaceImportGraphEdge;

#[doc(hidden)]
pub use import_graph::WorkspaceImportGraphRefreshPlan;

#[doc(hidden)]
pub use import_graph::WorkspaceImportGraphSource;

#[doc(hidden)]
pub use relational_query::RelationalStoreOutcome;

use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::ToSql;
use rusqlite::Transaction;
use rusqlite::TransactionBehavior;
use rusqlite::params;
use rusqlite::params_from_iter;

use sha2::Digest;
use sha2::Sha256;

pub use source_facts::SourceFactStorage;

use std::borrow::Cow;

use std::cell::RefCell;

use std::fmt;

use std::fmt::Write as _;

use std::path::Path;
use std::path::PathBuf;

#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::AtomicBool;

#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::AtomicUsize;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::Ordering;

use std::sync::Arc;
use std::sync::Condvar;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::OnceLock;

use std::time::Duration;

pub(crate) use workspace_inputs::NativeConfigurationOverlayAuthority;

#[doc(hidden)]
pub use workspace_inputs::WorkspaceConfigurationInput;

#[doc(hidden)]
pub use workspace_inputs::WorkspaceSourceRefusalRow;

#[doc(hidden)]
pub use workspace_inputs::configuration_digest;

use writer::StoreWriter;

pub mod class_set_field_slots;
pub mod class_set_procedure_surfaces;
pub mod class_set_root_results;
pub mod class_set_summaries;
#[doc(hidden)]
pub mod cpp_template;
#[doc(hidden)]
pub mod csharp_compilation;
#[doc(hidden)]
pub mod dependency_file_evidence;
pub mod epoch;
pub mod gc;
#[doc(hidden)]
pub mod jvm_package_context;
pub mod language_adapter;
pub mod liveness;
pub mod planner_statistics;
pub mod policy_units;
#[doc(hidden)]
pub mod python_runtime;
pub mod query;
mod read_keys;
#[doc(hidden)]
pub mod relational_query;
#[doc(hidden)]
pub mod rust_macro_source_sql;

#[doc(hidden)]
pub mod rust_crates;
#[doc(hidden)]
pub mod rust_impl_children;

#[doc(hidden)]
pub mod selected_definition;

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn selected_macro_item_unit_sql_for_plan() -> &'static str {
    selected_definition::SELECTED_MACRO_ITEM_UNIT_SQL.as_str()
}

#[doc(hidden)]
pub mod source_facts;

// Milestone 5 publishes the normalized writer seam before the producer and
// selected-hydration tranches wire it into analyzer construction.
#[doc(hidden)]
pub mod go_package_context;
#[doc(hidden)]
pub mod go_unit_summaries;
#[doc(hidden)]
pub mod import_graph;
#[doc(hidden)]
pub mod jvm_external_inventory;
#[doc(hidden)]
pub mod python_binding_rows;
#[doc(hidden)]
pub mod python_member_rows;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod python_unit_summaries;
#[doc(hidden)]
pub mod rust_unit_summaries;
#[doc(hidden)]
pub mod unit_schedule;
#[doc(hidden)]
pub mod unit_summaries;
mod versioned_relation;

#[allow(dead_code)]
#[doc(hidden)]
pub mod resolution;
#[doc(hidden)]
pub mod resolution_authority;
#[allow(dead_code)]
#[doc(hidden)]
pub mod resolution_lexical;
#[doc(hidden)]
pub mod resolution_manifest;
#[allow(dead_code)]
#[doc(hidden)]
pub mod resolution_operation;
#[allow(dead_code)]
#[doc(hidden)]
pub mod resolution_prepare;
#[doc(hidden)]
pub mod resolution_publication;
#[allow(dead_code)]
#[doc(hidden)]
pub mod resolution_selection;
#[doc(hidden)]
pub mod resolution_stage;
#[doc(hidden)]
pub mod resolution_typed;
pub(crate) mod row_batch;
pub(crate) mod selected_read_memo;
#[doc(hidden)]
pub mod semantic_ir;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_adapters;
#[doc(hidden)]
pub mod workspace_inputs;

#[doc(hidden)]
pub mod writer;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_blob_oid(contents: impl AsRef<[u8]>) -> Oid {
    Oid::hash_object(git2::ObjectType::Blob, contents.as_ref()).expect("test blob oid")
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn declaration_name<'a>(
    facts: &ParsedSourceFacts,
    source: &'a str,
    declaration: SourceDeclarationId,
) -> &'a str {
    facts
        .declaration_name(source, declaration)
        .expect("declaration has a source name inside the source")
}

const PREPARED_WRITE_IMMEDIATE_RETRIES: usize = 2;
/// How many stored bytes one row of a bounded query may materialize, and how
/// many the whole answer may.
///
/// These used to alias the signature-metadata blob cap, which was the same
/// number for a different reason: that cap was an admission gate on one write,
/// this is a materialization budget for one read. The schema enforces the write
/// gate now (see `0023-signature-metadata-columns.sql`), so the read budget
/// stands on its own.
#[doc(hidden)]
pub const MAX_LIMITED_QUERY_ROW_BYTES: usize = 8 << 20;
const LIMITED_UNIT_IDENTITY_PREDICATE: &str =
    "units.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
     AND (units.exact_fqn = ?3 OR units.exact_fqn IS NULL)
     AND units.kind = ?4
     AND units.short_name = ?5
     AND units.signature IS ?6
     AND units.synthetic = ?7";
#[doc(hidden)]
pub const MAX_LIMITED_QUERY_AGGREGATE_BYTES: usize = 8 << 20;

pub fn analyzer_db_path(workspace_root: &Path) -> PathBuf {
    gitblob::cache_db_path(workspace_root)
}

pub(super) fn valid_workspace_relative_path(path: &Path) -> bool {
    path.to_str().is_some_and(|path_text| {
        !path_text.is_empty()
            && crate::analyzer::semantic::WorkspaceRelativePath::try_from_path(path)
                .is_ok_and(|normalized| normalized.as_str() == path_text)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorKind {
    Generic,
    StaleGeneration,
    StaleResolution,
    SqliteInterrupted,
    Cancelled,
    ResourceBound,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    message: String,
    #[doc(hidden)]
    pub kind: StoreErrorKind,
    #[doc(hidden)]
    pub missing_required_source_facts: bool,
}

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Generic,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn missing_required_source_facts(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Generic,
            missing_required_source_facts: true,
        }
    }

    #[doc(hidden)]
    pub fn is_missing_required_source_facts(&self) -> bool {
        self.missing_required_source_facts
    }

    #[doc(hidden)]
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Cancelled,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn stale_generation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::StaleGeneration,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn stale_resolution(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::StaleResolution,
            missing_required_source_facts: false,
        }
    }

    fn resource_bound(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::ResourceBound,
            missing_required_source_facts: false,
        }
    }

    #[doc(hidden)]
    pub fn corrupt(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: StoreErrorKind::Corrupt,
            missing_required_source_facts: false,
        }
    }

    pub fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    pub fn is_stale_generation(&self) -> bool {
        self.kind == StoreErrorKind::StaleGeneration
    }

    pub fn is_resource_bound(&self) -> bool {
        self.kind == StoreErrorKind::ResourceBound
    }

    pub fn is_corrupt(&self) -> bool {
        self.kind == StoreErrorKind::Corrupt
    }

    #[doc(hidden)]
    pub fn is_stale_resolution(&self) -> bool {
        self.kind == StoreErrorKind::StaleResolution
    }

    #[doc(hidden)]
    pub fn is_cancelled(&self) -> bool {
        self.kind == StoreErrorKind::Cancelled
    }

    #[doc(hidden)]
    pub fn is_sqlite_interrupted(&self) -> bool {
        self.kind == StoreErrorKind::SqliteInterrupted
    }

    #[doc(hidden)]
    pub fn context(self, context: impl fmt::Display) -> Self {
        Self {
            message: format!("{context}: {}", self.message),
            kind: self.kind,
            missing_required_source_facts: self.missing_required_source_facts,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::new(format!("analyzer store I/O error: {err}"))
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        let sqlite_interrupted =
            err.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted);
        let message = if let Some(sqlite) = err.sqlite_error() {
            format!(
                "analyzer store SQLite error: {err} (code: {:?}, extended code: {})",
                sqlite.code, sqlite.extended_code
            )
        } else {
            format!("analyzer store SQLite error: {err}")
        };
        Self {
            message,
            kind: if sqlite_interrupted {
                StoreErrorKind::SqliteInterrupted
            } else {
                StoreErrorKind::Generic
            },
            missing_required_source_facts: false,
        }
    }
}

impl From<git2::Error> for StoreError {
    fn from(err: git2::Error) -> Self {
        Self::new(format!("analyzer store git error: {err}"))
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[doc(hidden)]
pub fn required_source_value<T>(value: Option<T>, context: &str, label: &str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(format!("{context} is missing {label}")))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct WorkspaceId(#[doc(hidden)] pub String);

impl WorkspaceId {
    #[doc(hidden)]
    pub fn for_root(root: &Path) -> Self {
        Self(brokk_bifrost_core::gitblob::workspace_cache_identity(root))
    }

    #[doc(hidden)]
    /// A partial listing must never reconcile under a live root's identity,
    /// or under another session's identity even when their roots coincide.
    pub fn for_session() -> Self {
        use brokk_bifrost_core::analyzer::canonical_hash::{hash_domain_bytes, lower_hex_string};

        Self(lower_hex_string(&hash_domain_bytes(
            b"bifrost-cache-workspace-session-v1",
            uuid::Uuid::new_v4().as_bytes(),
        )))
    }

    #[doc(hidden)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct WorkspaceSnapshotId {
    #[doc(hidden)]
    pub workspace_id: WorkspaceId,
    #[doc(hidden)]
    pub lang: String,
    #[doc(hidden)]
    pub generation: GenerationId,
    #[doc(hidden)]
    pub revision: i64,
}

#[doc(hidden)]
pub type WorkspaceSnapshots = HashMap<String, WorkspaceSnapshotId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SemanticPackActivationSourceKind {
    Installed,
    Generated,
    PreShipped,
    WorkspaceProduced,
    Embedded,
    EphemeralWorkspace,
}

impl SemanticPackActivationSourceKind {
    pub(crate) fn as_str(self) -> &'static str {
        crate::analyzer::semantic_model::activation_catalog_kind(self).as_str()
    }

    fn parse(value: &str) -> Result<Self> {
        crate::analyzer::semantic_model::parse_semantic_pack_activation_source_kind(value)
            .ok_or_else(|| {
                StoreError::new(format!(
                    "unknown semantic-pack activation source kind {value:?}"
                ))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticPackActiveReference {
    pub manifest_digest: String,
    pub source_kind: SemanticPackActivationSourceKind,
    pub source_id: String,
    pub workspace_produced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPackActiveSet {
    pub active_set_digest: String,
    pub members: Vec<SemanticPackActiveReference>,
}

impl SemanticPackActiveSet {
    pub fn from_members(members: &[SemanticPackActiveReference]) -> Result<Self> {
        let mut members = members.to_vec();
        members.sort();
        validate_semantic_pack_active_references(&members)?;
        let active_set_digest = semantic_pack_active_set_digest(&members)?;
        Ok(Self {
            active_set_digest,
            members,
        })
    }
}

// A completed parse is published atomically with its rows and required source
// family markers. Hot candidate queries check these witnesses; full count
// validation remains on hydration and explicit verification checks.
//
// This is also the read-path membership predicate; see
// `read_path_parsed_blob_condition`.
const PARSED_BLOB_COMPLETE_CONDITION: &str = "
meta.is_complete = 1
AND EXISTS (
  SELECT 1
  FROM blobs AS active_blob
  LEFT JOIN analysis_epochs AS active_epoch ON active_epoch.lang = active_blob.lang
  WHERE active_blob.id = meta.blob_id
    AND active_blob.generation = COALESCE(active_epoch.generation, 0)
) AND EXISTS (
  SELECT 1 FROM source_fact_readiness AS visibility
  WHERE visibility.blob_id = meta.blob_id AND visibility.available = 1
)";

const EXACT_PATH_SYMBOL_FQN_SQL: &str =
    "SELECT lang, rel_path, blob_oid, kind, package_name, short_name,
           exact_fqn, normalized_fqn, requires_imports
    FROM live_path_symbol_names
    WHERE lang = ?1 AND exact_fqn = ?2
    ORDER BY rel_path, exact_fqn";
const NORMALIZED_PATH_SYMBOL_FQN_SQL: &str =
    "SELECT lang, rel_path, blob_oid, kind, package_name, short_name,
           exact_fqn, normalized_fqn, requires_imports
    FROM live_path_symbol_names
    WHERE lang = ?1 AND normalized_fqn = ?2
    ORDER BY rel_path, exact_fqn";
#[doc(hidden)]
pub const REVISIONED_WORKSPACE_VIEWS_SQL: &str = include_str!("revisioned_workspace_views.sql");

/// `rust_selected_units_fill.sql` carries this token where its one
/// derivation-version predicate stands. The fill runs as a multi-statement
/// batch and `execute_batch` binds no parameters, so the token is rendered from
/// [`rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION`]; prepared
/// readers bind the same constant as a parameter instead.
static RUST_SELECTED_UNITS_FILL_SQL: LazyLock<String> = LazyLock::new(|| {
    include_str!("rust_selected_units_fill.sql").replace(
        ":rust_unit_summary_derivation_version",
        &rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION.to_string(),
    )
});

/// The rendered [`RUST_SELECTED_UNITS_FILL_SQL`], shared with the planner test
/// that replays its selection statement.
#[doc(hidden)]
pub fn rust_selected_units_fill_sql() -> &'static str {
    RUST_SELECTED_UNITS_FILL_SQL.as_str()
}

/// Rebuild selection-owned Rust rows for either reader pool after its input write.
#[doc(hidden)]
pub fn fill_selected_rust_units(conn: &Connection) -> Result<()> {
    conn.execute_batch(rust_selected_units_fill_sql())?;
    Ok(())
}

/// Structural publication verification, before source/native families seal:
/// base membership plus a re-count against the counts `blob_meta` recorded.
///
/// It costs 14 correlated scalar subqueries per requested key. Keep it on the
/// paths that exist to verify a cache -- the post-write check in
/// `insert_blob_meta_tx` and the explicit `contains_parsed_blob` /
/// `parsed_blob_keys` presence checks -- and off the read path, which asks the
/// same question millions of times per cold start. See
/// [`read_path_parsed_blob_condition`].
///
static PARSED_BLOB_STRUCTURAL_INTEGRITY_CONDITION: LazyLock<String> = LazyLock::new(|| {
    let mut condition = "
meta.is_complete = 1
AND EXISTS (
  SELECT 1
  FROM blobs AS active_blob
  LEFT JOIN analysis_epochs AS active_epoch ON active_epoch.lang = active_blob.lang
  WHERE active_blob.id = meta.blob_id
    AND active_blob.generation = COALESCE(active_epoch.generation, 0)
)
AND
meta.stored_unit_count = (
  SELECT COUNT(*) FROM code_units AS units
  WHERE units.blob_id = meta.blob_id
)
AND meta.range_count = (
  SELECT COUNT(*) FROM unit_ranges AS ranges
  WHERE ranges.blob_id = meta.blob_id
)
AND meta.signature_count = (
  SELECT COUNT(*) FROM unit_signatures AS signatures
  WHERE signatures.blob_id = meta.blob_id
)
AND meta.signature_metadata_count = (
  SELECT COUNT(*) FROM unit_signature_metadata AS metadata
  WHERE metadata.blob_id = meta.blob_id
)
AND (SELECT
"
    .to_string();
    for (index, descriptor) in OPTIONAL_FACT_DESCRIPTORS.iter().enumerate() {
        if index > 0 {
            condition.push_str("  AND ");
        } else {
            condition.push_str("  ");
        }
        writeln!(
            condition,
            "COALESCE(MAX(CASE WHEN manifest.fact_kind = {} THEN manifest.row_count END), 0) = (\n    SELECT COUNT(*) FROM {} AS facts\n    WHERE facts.blob_id = meta.blob_id\n  )",
            descriptor.kind as i64, descriptor.table
        )
        .expect("write optional fact integrity SQL");
    }
    let known_kinds = optional_fact_kind_list();
    write!(
        condition,
        "  AND COUNT(manifest.fact_kind) =\n      COUNT(CASE WHEN manifest.fact_kind IN ({known_kinds}) THEN 1 END)\n  FROM blob_optional_fact_manifest AS manifest\n  WHERE manifest.blob_id = meta.blob_id\n)\n"
    )
    .expect("write optional fact integrity guard");
    condition.push_str(
        "
AND meta.supertype_count = (
  SELECT COUNT(*) FROM unit_supertypes AS supertypes
  WHERE supertypes.blob_id = meta.blob_id
)
AND meta.child_count = (
  SELECT COUNT(*) FROM unit_children AS children
  WHERE children.blob_id = meta.blob_id
)
AND meta.import_statement_count = (
  SELECT COUNT(*) FROM import_statements AS statements
  WHERE statements.blob_id = meta.blob_id
)
AND meta.type_identifier_count = (
  SELECT COUNT(*) FROM reference_identifiers AS identifiers
  WHERE identifiers.blob_id = meta.blob_id
)
AND EXISTS (
  SELECT 1 FROM blob_reference_fact_manifests AS reference_manifest
  WHERE reference_manifest.blob_id = meta.blob_id
    AND reference_manifest.epoch = 1
    AND reference_manifest.identifier_count = meta.type_identifier_count
)
AND NOT EXISTS (
  SELECT 1 FROM code_units AS units
  WHERE units.blob_id = meta.blob_id
    AND (
      (units.fq_segment_count = 0) <> (units.exact_fqn_tail IS NULL)
      OR units.fq_segment_count <> (
        SELECT COUNT(*) FROM code_unit_fq_segments AS segments
        WHERE segments.blob_id = units.blob_id
          AND segments.unit_key = units.unit_key
      )
      OR units.fq_segment_bytes <> COALESCE((
        SELECT SUM(length(CAST(segments.seg_kind AS BLOB))
                   + length(CAST(segments.segment AS BLOB)))
        FROM code_unit_fq_segments AS segments
        WHERE segments.blob_id = units.blob_id
          AND segments.unit_key = units.unit_key
      ), 0)
      OR (units.fq_segment_count > 0 AND 0 <> (
        SELECT MIN(segments.seg_ordinal) FROM code_unit_fq_segments AS segments
        WHERE segments.blob_id = units.blob_id
          AND segments.unit_key = units.unit_key
      ))
      OR (units.fq_segment_count > 0 AND units.fq_segment_count - 1 <> (
        SELECT MAX(segments.seg_ordinal) FROM code_unit_fq_segments AS segments
        WHERE segments.blob_id = units.blob_id
          AND segments.unit_key = units.unit_key
      ))
    )
)
",
    );
    condition
});

static PARSED_BLOB_INTEGRITY_CONDITION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} AND EXISTS (
          SELECT 1 FROM source_fact_readiness AS visibility
          WHERE visibility.blob_id = meta.blob_id AND visibility.available = 1
        )",
        PARSED_BLOB_STRUCTURAL_INTEGRITY_CONDITION.as_str()
    )
});

/// Restores the full verification predicate on the read path when set to
/// `full`. Read once, at first use.
const STORE_INTEGRITY_ENV: &str = "BIFROST_STORE_INTEGRITY";

fn full_read_path_integrity_requested(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("full"))
}

/// The predicate every read-path membership question uses: `is_complete = 1`,
/// the active generation, and availability of required source families.
///
/// Those witnesses are what "this blob has a published parse for the generation
/// I am asking about" means. The write path already proves the fact-table counts
/// after every blob write (`insert_blob_meta_tx` fails the write otherwise), and
/// the epoch salt keeps a row from being read by a build that did not write it,
/// so re-proving those counts on every read re-verifies a state that cannot
/// occur. It is not free: the 2026-08-16 firefox measurement priced the full
/// condition at 56.2 us/key against 4.1 us/key for membership, which is 9.6 s of
/// a cold start's 171,035-key hydration pass and an order of magnitude worse
/// with cold pages.
///
/// Corruption written outside Bifrost is still caught, one step later:
/// `hydrate_file_state_conn` re-counts the rows it actually read and returns
/// `None`, so the file is reparsed and repaired. The verification consumers keep
/// [`PARSED_BLOB_INTEGRITY_CONDITION`].
///
/// [`STORE_INTEGRITY_ENV`] set to `full` puts the full condition back here for
/// diagnostics.
fn read_path_parsed_blob_condition() -> &'static str {
    static CONDITION: OnceLock<&'static str> = OnceLock::new();
    CONDITION.get_or_init(|| {
        if full_read_path_integrity_requested(std::env::var_os(STORE_INTEGRITY_ENV).as_deref()) {
            PARSED_BLOB_INTEGRITY_CONDITION.as_str()
        } else {
            PARSED_BLOB_COMPLETE_CONDITION
        }
    })
}

static OPTIONAL_FACT_COUNT_PROJECTION: LazyLock<String> = LazyLock::new(|| {
    let mut projection = OPTIONAL_FACT_DESCRIPTORS
        .iter()
        .map(|descriptor| {
            format!(
                "COALESCE(MAX(CASE WHEN manifest.fact_kind = {} THEN manifest.row_count END), 0)",
                descriptor.kind as i64
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let known_kinds = optional_fact_kind_list();
    write!(
        projection,
        ",\nCOUNT(manifest.fact_kind) -\nCOUNT(CASE WHEN manifest.fact_kind IN ({known_kinds}) THEN 1 END)"
    )
    .expect("write optional fact projection guard");
    projection
});

pub struct AnalyzerStore {
    // Field order is load-bearing for `Drop`: Rust drops struct fields in
    // declaration order, so the writer `conn` and every pooled reader must be
    // closed before `_ephemeral` runs and deletes the backing temp file (open
    // handles block deletion on Windows).
    #[doc(hidden)]
    pub conn: StoreWriter,
    #[doc(hidden)]
    pub readers: ReaderPool,
    #[doc(hidden)]
    pub active_readers: ReaderPool,
    streaming_readers: ReaderPool,
    /// The workspace selection held by the writer connection's temp schema, for
    /// the in-memory fallback that reads through it. Only the holder of the
    /// writer connection's guard ever reads or writes this, and it takes both
    /// guards together (see [`ReaderConn::Writer`]).
    #[doc(hidden)]
    pub writer_selection: Arc<Mutex<Option<AppliedWorkspaceSelection>>>,
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub crate_statement_counter: Mutex<Option<Arc<std::sync::atomic::AtomicUsize>>>,
    writer_resolution_selection: Mutex<Option<resolution_selection::RetainedResolutionSelection>>,
    /// All cross-request relation caches share this weighted capacity.
    #[doc(hidden)]
    pub cache_budget: cache_budget::StoreCacheBudget,
    #[cfg(any(test, feature = "test-support"))]
    workspace_selection_counters: WorkspaceSelectionCounters,
    #[doc(hidden)]
    pub db_path: Option<PathBuf>,
    lifetime: Arc<()>,
    _ephemeral: Option<EphemeralDb>,
    #[cfg(any(test, feature = "test-support"))]
    class_set_field_slot_operational_failure: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    class_set_root_result_operational_failure: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    parsed_blob_transaction_starts: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    parsed_blob_point_contains_queries: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    replacement_cost_lookup_queries: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    replacement_cost_fallback_queries: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    prepared_generation_lookup_queries: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    relational_batch_reader_checkouts: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    relational_batch_generation_validations: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    relational_batch_distinct_requests: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    relational_live_unit_count_queries: AtomicUsize,
}

/// A hand-rolled checkout pool of read-only SQLite connections for one store.
///
/// The writer connection (`AnalyzerStore::conn`) is untouched by reads; every
/// pure-SELECT method borrows a reader here instead, so N concurrent tool calls
/// run their symbol lookups / hydration / search in parallel against WAL
/// snapshots rather than serializing on the single writer mutex.
///
/// `capacity` is both the concurrency limit and the resident pool size. A
/// checkout takes one of `capacity` permits, then pops an idle reader or opens
/// one; the guard's drop returns the reader and the permit together. So a burst
/// wider than `capacity` waits for a reader instead of opening a cold one, and
/// after warm-up every checkout gets a connection whose temp schema already
/// holds the workspace selection (#2632). [`ReaderPool::new`] explains how
/// `capacity` is sized and what the retained readers cost.
///
/// Waiting is the cheaper of the two costs. A cold connection runs the 540-line
/// `revisioned_workspace_views.sql` before it can answer anything, and the
/// analyzer's rayon pool is `available_parallelism()` wide -- 120 workers on the
/// host #1748 measured, so a burst opened about 104 connections above capacity,
/// dropped them on checkin and opened them again on the next burst. A waiting
/// checkout costs the tail of another worker's query instead.
///
/// A thread that already holds a checkout from this pool does not wait for its
/// next one. Selected resolution nests checkouts: a Rust reverse operation keeps
/// its reader for its whole lifetime and opens a second operation, with a second
/// reader, to confirm each candidate blob. When `capacity` threads each held
/// their outer reader and asked for the inner one, every thread waited for a
/// checkin that only another waiting thread could make (#3798). So `capacity`
/// bounds the top-level checkouts, and each holder may exceed it by its own
/// nesting depth. A reader returned while `capacity` readers are idle is closed.
/// `ReaderGuard` is not `Send` (its writer variant holds a `MutexGuard`), so a
/// checkout is always returned on the thread that took it.
///
/// When `source` is `None` the store has no separate readable file (the
/// in-memory single-connection fallback); reads then route back through the
/// writer connection so correctness is preserved at the cost of read
/// parallelism. That path takes no permit: it is already serialized by the
/// writer mutex.
#[doc(hidden)]
pub struct ReaderPool {
    source: Option<PathBuf>,
    #[doc(hidden)]
    pub capacity: usize,
    #[doc(hidden)]
    pub state: Mutex<ReaderPoolState>,
    /// Signalled by every checkin, so a checkout blocked at `capacity` wakes as
    /// soon as a reader is back in `idle`.
    reader_returned: Condvar,
}

/// The idle readers and the outstanding checkouts, under one lock so a waiter
/// cannot miss a checkin between testing the count and sleeping.
#[derive(Default)]
#[doc(hidden)]
pub struct ReaderPoolState {
    #[doc(hidden)]
    pub idle: Vec<SelectedReader>,
    /// The thread that took each outstanding checkout, one entry per checkout.
    holders: Vec<std::thread::ThreadId>,
    /// Bumped by [`ReaderPool::recycle`] when this store's planner statistics
    /// change. A reader stamped with an older value planned against statistics
    /// that no longer exist and is dropped rather than reused.
    statistics_epoch: u64,
}

impl ReaderPoolState {
    /// Return the current thread's checkout. The pool takes and returns a
    /// checkout on one thread because `ReaderGuard` is not `Send`.
    fn release_checkout(&mut self) {
        let thread = std::thread::current().id();
        let index = self
            .holders
            .iter()
            .rposition(|holder| *holder == thread)
            .unwrap_or_else(|| {
                panic!(
                    "reader checkout returned on {thread:?}, which holds none; holders {:?}",
                    self.holders
                )
            });
        self.holders.swap_remove(index);
    }
}

/// The fixed-size SQLite freshness witnesses shared by both reader pools.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkspaceSelectionStamp {
    main_data_version: i64,
    main_schema_version: i64,
    temp_schema_version: i64,
}

fn workspace_selection_stamp(conn: &Connection) -> Result<WorkspaceSelectionStamp> {
    Ok(WorkspaceSelectionStamp {
        main_data_version: conn
            .prepare_cached("PRAGMA main.data_version")?
            .query_row([], |row| row.get(0))?,
        main_schema_version: conn
            .prepare_cached("PRAGMA main.schema_version")?
            .query_row([], |row| row.get(0))?,
        temp_schema_version: conn
            .prepare_cached("PRAGMA temp.schema_version")?
            .query_row([], |row| row.get(0))?,
    })
}

#[doc(hidden)]
pub struct AppliedWorkspaceSelection {
    snapshots: WorkspaceSnapshots,
    stamp: WorkspaceSelectionStamp,
    /// The rows that applying selections on this connection has changed,
    /// summed since the record was last cleared. A lent writer-backed reader
    /// uses it to tell those writes from any other
    /// ([`ReaderGuard::reclaim_writer`]).
    application_changes: u64,
}

/// A reader connection together with the workspace selection its temp schema
/// currently holds.
///
/// `temp.selected_workspace_revisions` and the revisioned views over it are
/// temp objects, so they live exactly as long as the connection does.
/// Remembering what is in them lets a checkout that wants the selection the
/// connection already holds check freshness without rebuilding rows. Every relational batch
/// used to probe `temp.sqlite_schema`, delete the selection table and
/// re-insert one row per snapshot, and a reader that had just been opened
/// re-parsed the 539-line view script on top of that (#2883).
#[doc(hidden)]
pub struct SelectedReader {
    conn: Connection,
    /// `None` until the revisioned views have been created on this connection;
    /// afterwards, the selection materialized in
    /// `temp.selected_workspace_revisions`.
    selection: Option<AppliedWorkspaceSelection>,
    #[doc(hidden)]
    pub resolution_selection: Option<resolution_selection::RetainedResolutionSelection>,
    /// The pool's [`ReaderPoolState::statistics_epoch`] when this connection
    /// was opened.
    statistics_epoch: u64,
    // A retained resolution reader keeps its compiled plans and QPSG policy
    // together. General borrowers restore this original policy on checkout.
    query_planner_stability_before_resolution: Option<bool>,
}

// Reader pool frames move this value repeatedly. Only fixed selection
// metadata and the SQLite connection may survive here; query preparation
// and requested mount records belong to the operation that checks it out.
const _: () = assert!(
    std::mem::size_of::<SelectedReader>() <= 512,
    "SelectedReader is moved by value through the reader pool; box large fields"
);

/// What the workspace-selection path actually did, for the cost pins.
#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
struct WorkspaceSelectionCounters {
    /// Runs of `revisioned_workspace_views.sql`, one per reader connection.
    view_creations: AtomicUsize,
    /// Rewrites of `temp.selected_workspace_revisions`, one per selection
    /// change on a connection.
    selection_writes: AtomicUsize,
}

thread_local! {
    static STREAMING_READ_DEPTHS: RefCell<HashMap<usize, usize>> =
        RefCell::new(HashMap::default());
}

// Target/base comparisons retain two complete connection-local selections.
// Larger histories must not accumulate workspace-sized operation arenas.
const MAX_RETAINED_RESOLUTION_READERS: usize = 2;

impl ReaderPool {
    /// `capacity` is the host's parallelism, at least 4, with no upper bound,
    /// and the pool keeps every reader it opens up to that number.
    ///
    /// A retained reader is not free. For the process's lifetime it holds its
    /// own SQLite page cache (`READER_PAGE_CACHE_KIB`, up to 8 MiB, filled as
    /// pages are read), its own prepared-statement cache
    /// (`PREPARED_STATEMENT_CACHE_CAPACITY`, 256 statements) and the temp schema
    /// with the workspace selection and the revisioned views. On the 120-core
    /// host one pool at capacity holds up to 960 MiB of page cache. The bound
    /// is the capacity, not the size of the workspace, and the pool reaches it
    /// only after a burst that wide.
    ///
    /// History. From #2632 until 2026-09-24 the capacity was clamped to
    /// [4, 32]. The 32 was sized for retention: a 2026-08-08 measurement, taken
    /// before checkout could block, saw a single `scan_usages` on a 120-CPU
    /// host reach 115 live cache-DB connections within 10 s and hold them for
    /// the remaining 166 s, while retention capped at 16 showed one transient
    /// 0.5 s sample at 41 connections and then 352 consecutive samples at 20.
    /// Those 115 connections were retention accumulating every burst
    /// connection, because nothing bounded the connections a burst opened. As
    /// the concurrency limit, 32 throttled a wide host: a 48-thread in-process
    /// point sweep on the 120-core, 128 GB host sat at about 30 busy cores,
    /// with 25 threads in `sqlite3_step`, 16 points in flight and 32 rayon
    /// workers idle behind the pool.
    ///
    /// On 2026-09-24 concurrency was raised to the host's parallelism with
    /// retention kept at 32, and a reader returned while 32 were idle was
    /// closed. In an 800-site, 64-thread sweep that raised busy cores from 32
    /// to between 43 and 55, but the process opened the cache database 83
    /// times instead of 53, and every burst wider than 32 would open those
    /// readers again. Each cold open runs the view script and compiles its own
    /// statements, so the split turned a one-time cost into a recurring one.
    /// The owner's decision is that retention equals concurrency.
    fn new(source: Option<PathBuf>) -> Self {
        let capacity = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(4);
        Self {
            source,
            capacity,
            state: Mutex::new(ReaderPoolState::default()),
            reader_returned: Condvar::new(),
        }
    }

    /// Take one of the pool's `capacity` checkouts, waiting while they are all
    /// out, and hand back the idle reader it found if there was one, together
    /// with the statistics epoch the checkout is being made under.
    ///
    /// `None` means the caller owns a permit for a connection that does not
    /// exist yet and must open it, then either check it in or abandon the
    /// checkout. The epoch is read here rather than after the open so that a
    /// [`Self::recycle`] racing the open stamps the new connection stale: it
    /// may have loaded its statistics before the refresh committed, and
    /// discarding a reader that did not need it costs one reopen.
    fn acquire(&self) -> (u64, Option<SelectedReader>) {
        self.acquire_with(|state| state.idle.len().checked_sub(1))
    }

    fn acquire_for_resolution(
        &self,
        key: &resolution_selection::RetainedResolutionSelectionKey,
    ) -> (u64, Option<SelectedReader>) {
        self.acquire_with(|state| {
            if let Some(index) = state.idle.iter().rposition(|reader| {
                reader
                    .resolution_selection
                    .as_ref()
                    .is_some_and(|retained| retained.matches_key(key))
            }) {
                return Some(index);
            }
            let retained = state
                .idle
                .iter()
                .filter(|reader| reader.resolution_selection.is_some())
                .count();
            if retained >= MAX_RETAINED_RESOLUTION_READERS {
                return state
                    .idle
                    .iter()
                    .position(|reader| reader.resolution_selection.is_some());
            }
            if let Some(index) = state
                .idle
                .iter()
                .rposition(|reader| reader.resolution_selection.is_none())
            {
                return Some(index);
            }
            if state.idle.len() + state.holders.len() < self.capacity {
                return None;
            }
            // At the resident cap, reuse the least recently returned reader.
            (!state.idle.is_empty()).then_some(0)
        })
    }

    fn acquire_with(
        &self,
        choose: impl FnOnce(&ReaderPoolState) -> Option<usize>,
    ) -> (u64, Option<SelectedReader>) {
        let thread = std::thread::current().id();
        let mut state = self
            .state
            .lock()
            .expect("analyzer store reader pool poisoned");
        // A nested checkout does not wait: the checkins it would wait for can
        // belong to threads that wait for it in turn (#3798).
        while state.holders.len() >= self.capacity && !state.holders.contains(&thread) {
            state = self
                .reader_returned
                .wait(state)
                .expect("analyzer store reader pool poisoned");
        }
        let index = choose(&state);
        state.holders.push(thread);
        let reader = index.map(|index| state.idle.remove(index));
        (state.statistics_epoch, reader)
    }

    /// Return a reader and the checkout it was held under, unless the store's
    /// planner statistics changed while it was out, in which case the
    /// connection is closed instead of returned to the idle set.
    fn checkin(&self, reader: SelectedReader) {
        let discarded = {
            let mut state = self
                .state
                .lock()
                .expect("analyzer store reader pool poisoned");
            // A full idle set means nested checkouts took this pool past
            // `capacity`; the resident pool stays at `capacity`.
            let discarded = if reader.statistics_epoch == state.statistics_epoch
                && state.idle.len() < self.capacity
            {
                let duplicate = reader
                    .resolution_selection
                    .as_ref()
                    .and_then(|incoming| {
                        state.idle.iter().position(|reader| {
                            reader
                                .resolution_selection
                                .as_ref()
                                .is_some_and(|retained| retained.same_key_as(incoming))
                        })
                    })
                    .map(|index| state.idle.remove(index));
                state.idle.push(reader);
                if duplicate.is_some() {
                    duplicate
                } else if state
                    .idle
                    .iter()
                    .filter(|reader| reader.resolution_selection.is_some())
                    .count()
                    > MAX_RETAINED_RESOLUTION_READERS
                {
                    let index = state
                        .idle
                        .iter()
                        .position(|reader| reader.resolution_selection.is_some())
                        .expect("the retained reader count is nonzero");
                    Some(state.idle.remove(index))
                } else {
                    None
                }
            } else {
                Some(reader)
            };
            state.release_checkout();
            discarded
        };
        // Closing the connection happens outside the pool lock; a waiter should
        // not queue behind another thread's `sqlite3_close`.
        #[cfg(any(test, feature = "test-support"))]
        let before_eviction = resolution_operation::heap_pin_bytes();
        drop(discarded);
        #[cfg(any(test, feature = "test-support"))]
        READER_EVICTION_BYTES.with(|bytes| {
            bytes.set(bytes.get() + before_eviction - resolution_operation::heap_pin_bytes())
        });
        self.reader_returned.notify_one();
    }

    /// Drop every idle reader and stale-mark the checked-out ones, so that the
    /// next query plans against the statistics the store now holds.
    ///
    /// Reports how many idle connections were closed.
    fn recycle(&self) -> usize {
        let discarded = {
            let mut state = self
                .state
                .lock()
                .expect("analyzer store reader pool poisoned");
            state.statistics_epoch += 1;
            std::mem::take(&mut state.idle)
        };
        discarded.len()
    }

    /// Return a checkout whose connection could not be opened.
    fn abandon_checkout(&self) {
        {
            let mut state = self
                .state
                .lock()
                .expect("analyzer store reader pool poisoned");
            state.release_checkout();
        }
        self.reader_returned.notify_one();
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn idle_len(&self) -> usize {
        self.state
            .lock()
            .expect("analyzer store reader pool poisoned")
            .idle
            .len()
    }
}

/// RAII handle to a checked-out reader (or the writer, in the fallback path).
/// Derefs to `Connection` so existing read methods — `conn.transaction()`,
/// helper calls taking `&Connection` — work unchanged. On drop, a pooled reader
/// is returned to its pool.
#[doc(hidden)]
pub struct ReaderGuard<'a> {
    inner: ReaderConn<'a>,
    checkin_cleanup: Option<&'static str>,
    query_planner_stability_on_checkin: Option<bool>,
    restore_reader_mmap_on_checkin: bool,
    reusable: bool,
}

// Keep the common pooled checkout inline instead of allocating for every read.
#[allow(clippy::large_enum_variant)]
enum ReaderConn<'a> {
    Pooled {
        pool: &'a ReaderPool,
        reader: Option<SelectedReader>,
    },
    /// The in-memory single-connection fallback reads through the writer, whose
    /// temp schema is shared with every other user of that connection. Its
    /// selection therefore lives beside the connection mutex rather than in a
    /// pool entry, and is held for as long as the connection guard is.
    Writer {
        store: &'a AnalyzerStore,
        conn: std::sync::MutexGuard<'a, Connection>,
        selection: std::sync::MutexGuard<'a, Option<AppliedWorkspaceSelection>>,
        resolution_selection:
            std::sync::MutexGuard<'a, Option<resolution_selection::RetainedResolutionSelection>>,
        // Another writer checkout on this thread would wait for this one.
        _exclusive: writer::RetainedExclusiveReader,
    },
    /// A writer-backed reader whose owner lent the connection to other store
    /// users ([`ReaderGuard::lend_writer`]). It holds no lock, so nothing may
    /// read through it until [`ReaderGuard::reclaim_writer`].
    LentWriter {
        store: &'a AnalyzerStore,
        witness: LentWriterWitness,
    },
}

/// Every way another user of the writer connection can change what a lent
/// reader left there: rows in either database (SQLite does not move
/// `data_version` for the connection's own commits) and either schema, with
/// the share of the rows that ordinary selection applications changed.
#[derive(Clone, Copy, PartialEq, Eq)]
struct LentWriterWitness {
    total_changes: u64,
    stamp: WorkspaceSelectionStamp,
    application_changes: Option<u64>,
}

impl LentWriterWitness {
    fn read(conn: &Connection, selection: Option<&AppliedWorkspaceSelection>) -> Result<Self> {
        Ok(Self {
            total_changes: conn.total_changes(),
            stamp: workspace_selection_stamp(conn)?,
            application_changes: selection.map(|selection| selection.application_changes),
        })
    }

    /// Whether ordinary selection applications made every row change since
    /// `lent`, with no schema or data-version change. They write only the
    /// revision rows and the Rust unit rows filled from them.
    fn only_selection_applications_since(&self, lent: &Self) -> bool {
        let applied = self
            .application_changes
            .zip(lent.application_changes)
            .and_then(|(now, then)| now.checked_sub(then));
        self.stamp == lent.stamp && applied == Some(self.total_changes - lent.total_changes)
    }
}

/// What a lent writer-backed reader found when it took the connection back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::analyzer::store) enum WriterReclaim {
    /// No other user changed the connection while it was lent.
    Unchanged,
    /// Other users only applied ordinary workspace selections, which share
    /// the lent selection's revision rows. Those rows hold its snapshots
    /// again; `changes` counts every row changed since the lend, theirs and
    /// the restoration's.
    Restored { changes: u64 },
    /// Another user wrote other rows or schema on the connection meanwhile.
    Changed,
    /// The caller's cancellation stopped the wait; the reader is still lent.
    Cancelled,
}

fn lent_writer_used() -> ! {
    panic!("a lent writer-backed reader was used before its owner reclaimed the connection")
}

#[cfg(any(test, feature = "test-support"))]
thread_local! { static READER_EVICTION_BYTES: std::cell::Cell<i64> = const { std::cell::Cell::new(0) }; }

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reader_eviction_bytes_for_test() -> i64 {
    READER_EVICTION_BYTES.with(std::cell::Cell::get)
}

impl<'a> ReaderGuard<'a> {
    /// Whether another store checkout on this thread would reacquire our mutex.
    #[doc(hidden)]
    pub fn excludes_store_access(&self) -> bool {
        matches!(self.inner, ReaderConn::Writer { .. })
    }

    pub(in crate::analyzer::store) fn is_lent_writer(&self) -> bool {
        matches!(self.inner, ReaderConn::LentWriter { .. })
    }

    /// Release a writer-backed reader's locks, so that other store users,
    /// including this thread, can use the connection until
    /// [`Self::reclaim_writer`] takes it back.
    ///
    /// The temp schema stays on the connection. `installed` names the
    /// workspace selection its revision rows hold, so that an ordinary read of
    /// the same snapshots reuses them instead of rewriting them; `None`
    /// records that the rows are no longer known.
    pub(in crate::analyzer::store) fn lend_writer(
        &mut self,
        installed: Option<&WorkspaceSnapshots>,
    ) -> Result<()> {
        let ReaderConn::Writer {
            store,
            conn,
            selection,
            ..
        } = &mut self.inner
        else {
            panic!("only a held writer-backed reader can lend its connection")
        };
        assert!(
            conn.is_autocommit(),
            "a writer-backed reader is lent only between transactions"
        );
        let stamp = workspace_selection_stamp(conn)?;
        let application_changes = selection
            .as_ref()
            .map_or(0, |selection| selection.application_changes);
        **selection = installed.map(|snapshots| AppliedWorkspaceSelection {
            snapshots: snapshots.clone(),
            stamp,
            application_changes,
        });
        let witness = LentWriterWitness::read(conn, selection.as_ref())?;
        let store = *store;
        // Dropping the held variant releases the connection and both
        // selection mutexes.
        self.inner = ReaderConn::LentWriter { store, witness };
        Ok(())
    }

    /// Take back a connection lent by [`Self::lend_writer`]. With a
    /// cancellation the wait for the connection observes it.
    ///
    /// When ordinary selection applications were the only writers meanwhile,
    /// the revision rows are restored to `installed`, the snapshots the
    /// lender staged. Every other row the lender staged is then as it left
    /// it. Without `installed` any change is reported as such.
    pub(in crate::analyzer::store) fn reclaim_writer(
        &mut self,
        cancellation: Option<&CancellationToken>,
        installed: Option<&WorkspaceSnapshots>,
    ) -> Result<WriterReclaim> {
        let ReaderConn::LentWriter { store, witness } = self.inner else {
            panic!("only a lent writer-backed reader can be reclaimed")
        };
        let conn = match cancellation {
            Some(cancellation) => match store.conn.lock_cancellable(cancellation) {
                Some(conn) => conn,
                None => return Ok(WriterReclaim::Cancelled),
            },
            None => store.conn.lock().expect("analyzer store mutex poisoned"),
        };
        self.inner = store.writer_reader_conn(conn);
        let (conn, selection) = self.connection_and_selection();
        let now = LentWriterWitness::read(conn, selection.as_ref())?;
        if now == witness {
            return Ok(WriterReclaim::Unchanged);
        }
        let Some(installed) = installed.filter(|_| now.only_selection_applications_since(&witness))
        else {
            return Ok(WriterReclaim::Changed);
        };
        store.apply_workspace_selection(conn, selection, installed)?;
        Ok(WriterReclaim::Restored {
            changes: conn.total_changes() - witness.total_changes,
        })
    }

    /// This connection and the selection its temp schema holds, borrowed
    /// together so a selection can be compared, applied, and recorded without
    /// releasing the connection.
    fn connection_and_selection(
        &mut self,
    ) -> (&Connection, &mut Option<AppliedWorkspaceSelection>) {
        match &mut self.inner {
            ReaderConn::Pooled { reader, .. } => {
                let reader = reader.as_mut().expect("reader guard already returned");
                (&reader.conn, &mut reader.selection)
            }
            ReaderConn::Writer {
                conn, selection, ..
            } => (conn, selection),
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        }
    }
}

impl std::ops::Deref for ReaderGuard<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        match &self.inner {
            ReaderConn::Pooled { reader, .. } => {
                &reader.as_ref().expect("reader guard already returned").conn
            }
            ReaderConn::Writer { conn, .. } => conn,
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        }
    }
}

impl std::ops::DerefMut for ReaderGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        match &mut self.inner {
            ReaderConn::Pooled { reader, .. } => {
                &mut reader.as_mut().expect("reader guard already returned").conn
            }
            ReaderConn::Writer { conn, .. } => conn,
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        }
    }
}

impl ReaderGuard<'_> {
    #[doc(hidden)]
    pub fn take_retained_resolution_selection(
        &mut self,
    ) -> Option<resolution_selection::RetainedResolutionSelection> {
        match &mut self.inner {
            ReaderConn::Pooled { reader, .. } => reader
                .as_mut()
                .expect("reader guard already returned")
                .resolution_selection
                .take(),
            ReaderConn::Writer {
                resolution_selection,
                ..
            } => resolution_selection.take(),
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        }
    }

    #[doc(hidden)]
    pub fn put_retained_resolution_selection(
        &mut self,
        retained: resolution_selection::RetainedResolutionSelection,
    ) {
        let slot = match &mut self.inner {
            ReaderConn::Pooled { reader, .. } => {
                &mut reader
                    .as_mut()
                    .expect("reader guard already returned")
                    .resolution_selection
            }
            ReaderConn::Writer {
                resolution_selection,
                ..
            } => &mut **resolution_selection,
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        };
        assert!(
            slot.replace(retained).is_none(),
            "one reader cannot retain two resolution selections"
        );
    }

    pub(in crate::analyzer::store) fn retain_before_checkin(&mut self) {
        assert!(!self.reusable, "only a discarded reader needs re-enabling");
        assert!(
            self.checkin_cleanup.is_none(),
            "a retained selection must not bypass pending TEMP cleanup"
        );
        self.reusable = true;
    }

    /// Keep parameter changes from recompiling the selected reader's indexed
    /// queries. Restore the borrowed connection's setting before releasing it.
    pub(super) fn stabilize_query_plans(&mut self) -> Result<()> {
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        assert!(
            self.query_planner_stability_on_checkin.is_none(),
            "reader query planner stability may be scoped only once"
        );
        let previous = self.db_config(SQLITE_DBCONFIG_ENABLE_QPSG)?;
        let enabled = self.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, true)?;
        assert!(
            enabled,
            "SQLite must enable the requested planner stability"
        );
        self.query_planner_stability_on_checkin = Some(previous);
        Ok(())
    }

    /// Keep plans valid between checkouts of an unchanged retained selection.
    /// Only pooled resolution readers retain this policy; a shared writer
    /// still restores its borrowed setting when the guard leaves scope.
    pub(super) fn retain_resolution_query_plans(&mut self) -> Result<()> {
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        match &mut self.inner {
            ReaderConn::Pooled { reader, .. } => {
                let reader = reader.as_mut().expect("reader guard already returned");
                if reader.query_planner_stability_before_resolution.is_none() {
                    let previous = reader.conn.db_config(SQLITE_DBCONFIG_ENABLE_QPSG)?;
                    let enabled = reader
                        .conn
                        .set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, true)?;
                    assert!(enabled, "SQLite must enable retained planner stability");
                    reader.query_planner_stability_before_resolution = Some(previous);
                }
                Ok(())
            }
            ReaderConn::Writer { .. } => self.stabilize_query_plans(),
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        }
    }

    fn restore_general_query_plans(&mut self) -> Result<()> {
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        let previous = match &mut self.inner {
            ReaderConn::Pooled { reader, .. } => reader
                .as_mut()
                .expect("reader guard already returned")
                .query_planner_stability_before_resolution
                .take(),
            ReaderConn::Writer { .. } => None,
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        };
        if let Some(previous) = previous {
            match self.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, previous) {
                Ok(restored) => assert_eq!(
                    restored, previous,
                    "general reader checkout restores its original planner policy"
                ),
                Err(error) => {
                    self.reusable = false;
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    /// Drop this connection instead of returning it to a pool. Selection calls
    /// this before their first TEMP mutation, then re-enable recycling only
    /// after committing a known-empty baseline and installing cleanup.
    #[doc(hidden)]
    pub fn discard_before_checkin(&mut self) {
        self.reusable = false;
    }

    /// Borrow the larger build-only map without changing the pool's policy.
    /// The single-connection fallback is in-memory and has no file to map.
    pub(crate) fn use_derivation_mmap(&mut self) -> Result<()> {
        if matches!(&self.inner, ReaderConn::Pooled { .. }) {
            assert!(
                !self.restore_reader_mmap_on_checkin,
                "derivation map may be requested only once per checkout"
            );
            // Install restoration before the fallible update, including exits
            // before the caller has registered its TEMP cleanup.
            self.restore_reader_mmap_on_checkin = true;
            self.pragma_update(
                None,
                "mmap_size",
                crate::cache_db::DERIVATION_MMAP_SIZE_BYTES,
            )?;
        }
        Ok(())
    }

    /// Run connection-local cleanup before this reader may re-enter its pool.
    /// A failed cleanup discards a pooled connection instead of making its
    /// TEMP state observable by the next checkout.
    pub(crate) fn cleanup_before_checkin(&mut self, sql: &'static str) {
        assert!(
            self.checkin_cleanup.replace(sql).is_none(),
            "reader checkin cleanup may be installed only once"
        );
        self.reusable = true;
    }
}

impl Drop for ReaderGuard<'_> {
    fn drop(&mut self) {
        // The owner reclaims a lent connection first: its cleanup, the
        // planner restoration and the checks below need the connection held.
        assert!(
            !self.is_lent_writer(),
            "a lent writer-backed reader must be reclaimed before it is dropped"
        );
        let had_cleanup = self.checkin_cleanup.is_some();
        let mut cleanup_errors = Vec::new();
        if let Some(sql) = self.checkin_cleanup.take() {
            let result = match &mut self.inner {
                ReaderConn::Pooled { reader, .. } => reader
                    .as_mut()
                    .expect("reader guard already returned")
                    .conn
                    .execute_batch(sql),
                ReaderConn::Writer { conn, .. } => conn.execute_batch(sql),
                ReaderConn::LentWriter { .. } => lent_writer_used(),
            };
            if let Err(error) = result {
                cleanup_errors.push(("TEMP cleanup", error));
            }
        }
        if self.restore_reader_mmap_on_checkin
            && let Err(error) =
                self.pragma_update(None, "mmap_size", crate::cache_db::READER_MMAP_SIZE_BYTES)
        {
            cleanup_errors.push(("reader mmap restoration", error));
        }
        if let Some(previous) = self.query_planner_stability_on_checkin.take() {
            use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

            match self.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, previous) {
                Ok(restored) => assert_eq!(
                    restored, previous,
                    "SQLite must restore the borrowed query planner setting"
                ),
                Err(error) => cleanup_errors.push(("query planner restoration", error)),
            }
        }
        match &mut self.inner {
            ReaderConn::Pooled { pool, reader } => {
                let mut reader = reader.take().expect("reader guard already returned");
                if !cleanup_errors.is_empty() {
                    eprintln!(
                        "analyzer store discarded pooled reader after cleanup failed: {cleanup_errors:?}"
                    );
                    drop(reader);
                    pool.abandon_checkout();
                } else if !self.reusable {
                    drop(reader);
                    pool.abandon_checkout();
                } else {
                    if had_cleanup {
                        if let Some(selection) = &mut reader.selection {
                            selection.snapshots.clear();
                        }
                        reader.resolution_selection = None;
                    }
                    pool.checkin(reader);
                }
            }
            ReaderConn::Writer {
                selection,
                resolution_selection,
                ..
            } => {
                if had_cleanup {
                    if let Some(selection) = selection.as_mut() {
                        selection.snapshots.clear();
                    }
                    **resolution_selection = None;
                }
                assert!(
                    cleanup_errors.is_empty(),
                    "analyzer store cleanup failed on the writer fallback: {cleanup_errors:?}"
                );
                assert!(
                    self.reusable,
                    "analyzer store writer fallback left TEMP state unverified"
                );
            }
            ReaderConn::LentWriter { .. } => lent_writer_used(),
        }
    }
}

/// Owns a delete-on-drop temp-file cache DB backing an ephemeral (non-git)
/// workspace. All connections are struct-ordered to close before this drops.
struct EphemeralDb {
    path: PathBuf,
}

impl Drop for EphemeralDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
    }
}

fn validate_semantic_pack_active_references(members: &[SemanticPackActiveReference]) -> Result<()> {
    for member in members {
        if member.manifest_digest.len() != 64
            || !member
                .manifest_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoreError::new(format!(
                "semantic-pack manifest digest must be lowercase SHA-256 hex: {:?}",
                member.manifest_digest
            )));
        }
        if member.source_id.is_empty() {
            return Err(StoreError::new(
                "semantic-pack activation source id must not be empty",
            ));
        }
        let expected_workspace_produced = matches!(
            member.source_kind,
            SemanticPackActivationSourceKind::WorkspaceProduced
                | SemanticPackActivationSourceKind::EphemeralWorkspace
        );
        if member.workspace_produced != expected_workspace_produced {
            return Err(StoreError::new(format!(
                "semantic-pack workspace-produced flag disagrees with source kind {:?}",
                member.source_kind
            )));
        }
    }
    if members
        .windows(2)
        .any(|pair| pair[0].manifest_digest == pair[1].manifest_digest)
    {
        return Err(StoreError::new(
            "semantic-pack active set contains a duplicate manifest digest",
        ));
    }
    Ok(())
}

fn semantic_pack_active_set_digest(members: &[SemanticPackActiveReference]) -> Result<String> {
    let mut canonical = members.to_vec();
    canonical.sort();
    validate_semantic_pack_active_references(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.semantic-pack-active-set.v1\0");
    hasher.update((canonical.len() as u64).to_be_bytes());
    for member in &canonical {
        hash_length_prefixed(&mut hasher, member.manifest_digest.as_bytes());
        hash_length_prefixed(&mut hasher, member.source_kind.as_str().as_bytes());
        hash_length_prefixed(&mut hasher, member.source_id.as_bytes());
        hasher.update([u8::from(member.workspace_produced)]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn update_sha256_with_length_prefix(hasher: &mut Sha256, value: &[u8]) {
    crate::analyzer::digest::update_length_delimited_sha256(hasher, value);
}

fn update_sha256_with_length_prefixed_text(hasher: &mut Sha256, value: &str) {
    update_sha256_with_length_prefix(hasher, value.as_bytes());
}

fn update_sha256_with_length_prefixed_byte(hasher: &mut Sha256, value: u8) {
    update_sha256_with_length_prefix(hasher, &[value]);
}

fn update_sha256_with_length_prefixed_u64(hasher: &mut Sha256, value: u64) {
    update_sha256_with_length_prefix(hasher, &value.to_le_bytes());
}

fn new_sha256_with_length_prefixed_domain(domain: &[u8]) -> Sha256 {
    crate::analyzer::digest::new_length_delimited_sha256(domain)
}

fn checked_fixed_digest(bytes: Vec<u8>) -> std::result::Result<[u8; 32], usize> {
    let digest: std::result::Result<[u8; 32], Vec<u8>> = bytes.try_into();
    digest.map_err(|bytes| bytes.len())
}

fn class_set_bounded_count(value: i64, max: usize, name: &str, owner: &str) -> Result<usize> {
    let value = usize::try_from(value)
        .map_err(|_| StoreError::corrupt(format!("class-set {owner} {name} count is invalid")))?;
    if value > max {
        return Err(StoreError::resource_bound(format!(
            "class-set {owner} {name} count exceeds {max}"
        )));
    }
    Ok(value)
}

fn admit_class_set_text_bytes(
    total: &mut usize,
    row_bytes: i64,
    max_bytes: usize,
    owner: &str,
    text_kind: &str,
) -> Result<()> {
    let row_bytes = class_set_bounded_count(row_bytes, max_bytes, "payload row text byte", owner)?;
    *total = total.checked_add(row_bytes).ok_or_else(|| {
        StoreError::resource_bound(format!(
            "class-set {owner} {text_kind} size overflows usize"
        ))
    })?;
    if *total > max_bytes {
        return Err(StoreError::resource_bound(format!(
            "class-set {owner} {text_kind} exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn class_set_u32(value: i64, name: &str, owner: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| StoreError::corrupt(format!("class-set {owner} {name} exceeds u32")))
}

fn ensure_store_not_cancelled(
    cancellation: &CancellationToken,
    message: &'static str,
) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(StoreError::new(message))
    } else {
        Ok(())
    }
}

fn canonical_language_label(label: &str) -> Option<Language> {
    Language::from_config_label(label).filter(|language| language.config_label() == label)
}

fn live_class_set_owner_blob_id(
    conn: &Connection,
    blob_oid: &str,
    storage_language_key: &crate::analyzer::semantic::StorageLanguageKey,
) -> Result<Option<i64>> {
    conn.query_row(
        &format!(
            "SELECT meta.blob_id FROM blob_meta AS meta
             JOIN blobs ON blobs.id=meta.blob_id
             WHERE blobs.blob_oid=?1 AND blobs.lang=?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        ),
        params![blob_oid, storage_language_key.as_str()],
        |row| row.get(0),
    )
    .optional()
    .map_err(StoreError::from)
}

fn reader_source_path(conn: &Connection) -> Option<PathBuf> {
    conn.path()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn unique_temp_db_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    // Deliberately not named `bifrost_cache.db`, so the writer's legacy-cache
    // cleanup treats it as unrelated and never touches sibling temp files.
    std::env::temp_dir().join(format!("bifrost-analyzer-{pid}-{nanos}-{counter}.db"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationId(#[doc(hidden)] pub i64);

impl GenerationId {
    /// Rehydrate an epoch identity from a schema-checked generation column.
    #[doc(hidden)]
    pub fn from_persisted(value: i64) -> Self {
        assert!(value >= 0, "persisted generations are nonnegative");
        Self(value)
    }

    #[doc(hidden)]
    pub const BOOTSTRAP: Self = Self(0);

    #[doc(hidden)]
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct CompleteAnalysisBlobRequest {
    oid: Oid,
    storage_language: String,
    possible_additional_storage_languages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct MissingCompleteAnalysisBlob {
    #[doc(hidden)]
    pub oid: Oid,
    #[doc(hidden)]
    pub storage_language: String,
    #[doc(hidden)]
    pub required_existing_additional_storage_languages: Vec<String>,
}

impl MissingCompleteAnalysisBlob {
    #[doc(hidden)]
    pub fn primary_only(oid: Oid, storage_language: String) -> Self {
        Self {
            oid,
            storage_language,
            required_existing_additional_storage_languages: Vec::new(),
        }
    }

    #[doc(hidden)]
    pub const fn oid(&self) -> Oid {
        self.oid
    }

    #[doc(hidden)]
    pub fn storage_language(&self) -> &str {
        &self.storage_language
    }

    #[doc(hidden)]
    pub fn required_existing_additional_storage_languages(&self) -> &[String] {
        &self.required_existing_additional_storage_languages
    }
}

impl CompleteAnalysisBlobRequest {
    #[doc(hidden)]
    pub fn new(
        oid: Oid,
        storage_language: impl Into<String>,
        possible_additional_storage_languages: impl IntoIterator<Item = String>,
    ) -> Self {
        let storage_language = storage_language.into();
        assert!(!storage_language.is_empty());
        let mut possible_additional_storage_languages = possible_additional_storage_languages
            .into_iter()
            .collect::<Vec<_>>();
        possible_additional_storage_languages.sort();
        possible_additional_storage_languages.dedup();
        assert!(
            possible_additional_storage_languages
                .iter()
                .all(|candidate| !candidate.is_empty() && candidate != &storage_language),
            "additional storage languages must be nonempty and distinct from the primary"
        );
        Self {
            oid,
            storage_language,
            possible_additional_storage_languages,
        }
    }

    #[doc(hidden)]
    pub const fn oid(&self) -> Oid {
        self.oid
    }

    #[doc(hidden)]
    pub fn storage_language(&self) -> &str {
        &self.storage_language
    }

    #[doc(hidden)]
    pub fn possible_additional_storage_languages(&self) -> &[String] {
        &self.possible_additional_storage_languages
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct ImportFacts {
    #[doc(hidden)]
    pub package_name: String,
    #[doc(hidden)]
    pub imports: Vec<ImportInfo>,
    #[doc(hidden)]
    pub contains_tests: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateFlags {
    pub is_type_alias: bool,
    pub is_top_level: bool,
    pub in_declarations: bool,
    pub in_definition_lookup: bool,
    pub synthetic: bool,
}

/// Persisted identity metadata that is cheap to select with a candidate row.
/// It deliberately contains no child segments; crossing from this header to a
/// complete identity requires an explicit relational batch read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FqIdentityHeader {
    anchor: Option<PackageAnchor>,
    package_tail_segments: usize,
    expected_segment_count: usize,
    expected_segment_bytes: usize,
    #[doc(hidden)]
    pub exact_tail: String,
    normalized_tail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRow<I = FqIdentityHeader> {
    pub blob_oid: Oid,
    pub lang: String,
    pub unit_key: i64,
    pub kind: CodeUnitType,
    pub short_name: String,
    pub content_qualifier: String,
    pub signature: Option<String>,
    pub flags: CandidateFlags,
    /// Header for the authoritative relational identity. The default type is
    /// intentionally not hydrated.
    pub fq: Option<I>,
}

pub type HydratedCandidateRow = CandidateRow<RelationalUnitFq>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct MountedCandidateRow<I = FqIdentityHeader> {
    #[doc(hidden)]
    pub candidate: CandidateRow<I>,
    #[doc(hidden)]
    pub rel_path: String,
}

#[doc(hidden)]
pub type HydratedMountedCandidateRow = MountedCandidateRow<RelationalUnitFq>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct MountedCandidatePrimaryRangeRow<I = FqIdentityHeader> {
    #[doc(hidden)]
    pub candidate: CandidateRow<I>,
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub primary_range: Option<Range>,
}

#[doc(hidden)]
pub type HydratedMountedCandidatePrimaryRangeRow =
    MountedCandidatePrimaryRangeRow<RelationalUnitFq>;

#[derive(Debug, Default)]
struct LimitedQueryByteBudget {
    admitted_bytes: usize,
}

impl LimitedQueryByteBudget {
    fn admit_sqlite_bytes(&mut self, raw_bytes: i64) -> Result<bool> {
        let row_bytes = i64_to_usize(raw_bytes)?;
        if row_bytes > MAX_LIMITED_QUERY_ROW_BYTES {
            return Ok(false);
        }
        let Some(total_bytes) = self.admitted_bytes.checked_add(row_bytes) else {
            return Ok(false);
        };
        if total_bytes > MAX_LIMITED_QUERY_AGGREGATE_BYTES {
            return Ok(false);
        }
        self.admitted_bytes = total_bytes;
        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct CandidatePrimaryRangeRow<I = FqIdentityHeader> {
    #[doc(hidden)]
    pub candidate: CandidateRow<I>,
    #[doc(hidden)]
    pub in_test_region: bool,
    #[doc(hidden)]
    pub primary_range: Option<Range>,
}

pub(crate) type HydratedCandidatePrimaryRangeRow = CandidatePrimaryRangeRow<RelationalUnitFq>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct HierarchyStorageKey {
    #[doc(hidden)]
    pub blob_oid: Oid,
    #[doc(hidden)]
    pub lang: String,
    #[doc(hidden)]
    pub unit_key: i64,
}

#[doc(hidden)]
pub struct PersistedHierarchyFacts {
    #[doc(hidden)]
    pub imports: Arc<[ImportInfo]>,
    #[doc(hidden)]
    pub raw_supertypes: Arc<[String]>,
}

/// Persisted metadata needed to preserve definition ordering without
/// reconstructing the candidate's complete file state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct DefinitionOrderCandidateRow<I = FqIdentityHeader> {
    #[doc(hidden)]
    pub candidate: CandidateRow<I>,
    #[doc(hidden)]
    pub first_start_byte: Option<usize>,
    /// The workspace-derived half of this candidate's live mounted identity.
    /// It comes from `live_definition_exact_names`, so filtering it never
    /// re-walks a language's package discovery rules or the filesystem.
    pub(crate) mounted_prefix: String,
}

#[doc(hidden)]
pub type HydratedDefinitionOrderCandidateRow = DefinitionOrderCandidateRow<RelationalUnitFq>;

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct RenderedDefinitionRequest {
    #[doc(hidden)]
    pub exact_name: String,
    #[doc(hidden)]
    pub normalized_name: String,
    /// False when the language's persisted spelling vocabulary proves this
    /// request cannot name a stored unit. It may still reach path symbols or
    /// dirty state outside this store query.
    #[doc(hidden)]
    pub seekable: bool,
}

#[doc(hidden)]
pub enum RenderedDefinitionCandidateOutcome {
    Complete(Vec<Vec<HydratedDefinitionOrderCandidateRow>>),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RenderedNameComponent {
    prefix: String,
    tail: String,
    normalized: bool,
    normalized_exact_fallback: bool,
    anchored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct PathSymbolRow {
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub blob_oid: Oid,
    #[doc(hidden)]
    pub kind: CodeUnitType,
    #[doc(hidden)]
    pub package_name: String,
    #[doc(hidden)]
    pub short_name: String,
    #[doc(hidden)]
    pub exact_fqn: String,
    #[doc(hidden)]
    pub normalized_fqn: String,
    #[doc(hidden)]
    /// Whether this row only counts when its file has an import statement.
    /// A static property of the language's adapter
    /// (`path_synthetic_module_requires_imports`), stored per row so
    /// `live_path_symbol_names` can gate on a column instead of naming
    /// languages in SQL.
    pub requires_imports: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct WorkspaceFileRow {
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub blob_oid: Oid,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct WorkspacePackageFileRow {
    #[doc(hidden)]
    pub package_name: String,
    #[doc(hidden)]
    pub rel_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct WorkspacePackageEdgeRow {
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub parent_package_name: String,
    #[doc(hidden)]
    pub child_package_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct WorkspaceAnchorRow {
    #[doc(hidden)]
    pub rel_path: String,
    #[doc(hidden)]
    pub anchor: PackageAnchor,
    #[doc(hidden)]
    pub package_name: String,
}

impl WorkspaceAnchorRow {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(rel_path: String, anchor: PackageAnchor, package_name: String) -> Self {
        Self {
            rel_path,
            anchor,
            package_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct WorkspaceContentPackageFact {
    #[doc(hidden)]
    pub blob_oid: Oid,
    #[doc(hidden)]
    pub anchor: Option<PackageAnchor>,
    #[doc(hidden)]
    pub content_qualifier: String,
    #[doc(hidden)]
    pub package_tail: FqName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct WorkspaceContentPackageFacts {
    #[doc(hidden)]
    pub facts: Vec<WorkspaceContentPackageFact>,
    /// Whether every requested blob contributed an exact package identity.
    /// Missing facts make package absence non-authoritative, but must not keep
    /// the workspace file snapshot (and its valid declarations) unpublished.
    #[doc(hidden)]
    pub complete: bool,
}

type PathSymbolRowsResult = Result<Vec<(String, PathSymbolRow)>>;

fn decode_path_symbol_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<PathSymbolRow> {
    let oid_text: String = row.get(offset + 1)?;
    let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            offset + 1,
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })?;
    let kind_raw: i64 = row.get(offset + 2)?;
    let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            offset + 2,
            rusqlite::types::Type::Integer,
            Box::new(err),
        )
    })?;
    Ok(PathSymbolRow {
        rel_path: row.get(offset)?,
        blob_oid,
        kind,
        package_name: row.get(offset + 3)?,
        short_name: row.get(offset + 4)?,
        exact_fqn: row.get(offset + 5)?,
        normalized_fqn: row.get(offset + 6)?,
        requires_imports: row.get::<_, i64>(offset + 7)? == 1,
    })
}

/// Shared row-fetch body of `path_symbol_rows_by_fqn_for_langs` and its batched sibling: runs entirely
/// within a caller-supplied transaction so the batch path can resolve many FQN pairs per transaction.
fn path_symbol_rows_by_fqn_in_tx(
    tx: &Transaction,
    langs: &[String],
    exact_fqn: &str,
    normalized_fqn: &str,
) -> Result<Vec<(String, PathSymbolRow)>> {
    let mut out = Vec::new();
    for lang in langs {
        let mut exact = tx.prepare_cached(EXACT_PATH_SYMBOL_FQN_SQL)?;
        let mapped = exact.query_map(params![lang, exact_fqn], |row| {
            Ok((row.get::<_, String>(0)?, decode_path_symbol_row(row, 1)?))
        })?;
        out.extend(mapped.collect::<std::result::Result<Vec<_>, _>>()?);
        if normalized_fqn != exact_fqn {
            let mut normalized = tx.prepare_cached(NORMALIZED_PATH_SYMBOL_FQN_SQL)?;
            let mapped = normalized.query_map(params![lang, normalized_fqn], |row| {
                Ok((row.get::<_, String>(0)?, decode_path_symbol_row(row, 1)?))
            })?;
            out.extend(mapped.collect::<std::result::Result<Vec<_>, _>>()?);
        }
    }
    out.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.rel_path.cmp(&right.1.rel_path))
            .then_with(|| left.1.exact_fqn.cmp(&right.1.exact_fqn))
            .then_with(|| left.1.kind.cmp(&right.1.kind))
    });
    out.dedup();
    Ok(out)
}

#[derive(Default)]
struct WorkspaceFileProjection<'a> {
    path_symbols: Vec<&'a PathSymbolRow>,
    package_files: Vec<&'a WorkspacePackageFileRow>,
    package_edges: Vec<&'a WorkspacePackageEdgeRow>,
    anchors: Vec<&'a WorkspaceAnchorRow>,
}

fn sort_workspace_file_projection(projection: &mut WorkspaceFileProjection<'_>) {
    projection.path_symbols.sort_by(|left, right| {
        left.exact_fqn
            .cmp(&right.exact_fqn)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    projection.package_files.sort_unstable();
    projection.package_edges.sort_unstable();
    projection.anchors.sort_unstable();
}

fn workspace_file_projections<'a>(
    files: &'a [WorkspaceFileRow],
    path_symbols: &'a [PathSymbolRow],
    package_files: &'a [WorkspacePackageFileRow],
    package_edges: &'a [WorkspacePackageEdgeRow],
    anchors: &'a [WorkspaceAnchorRow],
) -> HashMap<&'a str, WorkspaceFileProjection<'a>> {
    let mut projections = files
        .iter()
        .map(|file| (file.rel_path.as_str(), WorkspaceFileProjection::default()))
        .collect::<HashMap<_, _>>();
    assert_eq!(projections.len(), files.len(), "workspace paths are unique");

    for row in path_symbols {
        projections
            .get_mut(row.rel_path.as_str())
            .expect("path-symbol row belongs to a workspace file")
            .path_symbols
            .push(row);
    }
    for row in package_files {
        projections
            .get_mut(row.rel_path.as_str())
            .expect("package row belongs to a workspace file")
            .package_files
            .push(row);
    }
    for row in package_edges {
        projections
            .get_mut(row.rel_path.as_str())
            .expect("package-edge row belongs to a workspace file")
            .package_edges
            .push(row);
    }
    for row in anchors {
        projections
            .get_mut(row.rel_path.as_str())
            .expect("anchor row belongs to a workspace file")
            .anchors
            .push(row);
    }

    for projection in projections.values_mut() {
        sort_workspace_file_projection(projection);
    }
    projections
}

fn workspace_file_projection<'a>(
    rel_path: &str,
    path_symbols: &'a [PathSymbolRow],
    package_files: &'a [WorkspacePackageFileRow],
    package_edges: &'a [WorkspacePackageEdgeRow],
    anchors: &'a [WorkspaceAnchorRow],
) -> WorkspaceFileProjection<'a> {
    let mut projection = WorkspaceFileProjection {
        path_symbols: path_symbols
            .iter()
            .filter(|row| row.rel_path == rel_path)
            .collect(),
        package_files: package_files
            .iter()
            .filter(|row| row.rel_path == rel_path)
            .collect(),
        package_edges: package_edges
            .iter()
            .filter(|row| row.rel_path == rel_path)
            .collect(),
        anchors: anchors
            .iter()
            .filter(|row| row.rel_path == rel_path)
            .collect(),
    };
    sort_workspace_file_projection(&mut projection);
    projection
}

fn workspace_file_projection_digest_bytes(
    file: &WorkspaceFileRow,
    projection: &WorkspaceFileProjection<'_>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"bifrost.workspace-file-projection.v1\0");
    for value in [file.rel_path.as_bytes(), file.blob_oid.as_bytes()] {
        digest.update(value.len().to_le_bytes());
        digest.update(value);
    }
    for row in &projection.path_symbols {
        for value in [
            row.rel_path.as_bytes(),
            row.blob_oid.as_bytes(),
            row.package_name.as_bytes(),
            row.short_name.as_bytes(),
            row.exact_fqn.as_bytes(),
            row.normalized_fqn.as_bytes(),
        ] {
            digest.update(value.len().to_le_bytes());
            digest.update(value);
        }
        digest.update([code_unit_kind_to_i64(row.kind) as u8]);
        // Stored with the row, so a change to it alone must change the
        // digest; otherwise reconciliation keeps the stale flag.
        digest.update([u8::from(row.requires_imports)]);
    }
    for row in &projection.package_files {
        for value in [row.package_name.as_bytes(), row.rel_path.as_bytes()] {
            digest.update(value.len().to_le_bytes());
            digest.update(value);
        }
    }
    for row in &projection.package_edges {
        for value in [
            row.rel_path.as_bytes(),
            row.parent_package_name.as_bytes(),
            row.child_package_name.as_bytes(),
        ] {
            digest.update(value.len().to_le_bytes());
            digest.update(value);
        }
    }
    for row in &projection.anchors {
        for value in [row.rel_path.as_bytes(), row.package_name.as_bytes()] {
            digest.update(value.len().to_le_bytes());
            digest.update(value);
        }
        match row.anchor {
            PackageAnchor::OwnModule { pop } => digest.update([1, pop]),
            PackageAnchor::CrateRoot => digest.update([2, 0]),
        }
    }
    digest.finalize().into()
}

fn workspace_file_projection_digest(
    file: &WorkspaceFileRow,
    projection: &WorkspaceFileProjection<'_>,
) -> String {
    lower_hex_string(&workspace_file_projection_digest_bytes(file, projection))
}

/// Derive the exact revision-projection digest for one operation-local file
/// replacement from the same structured rows and canonical ordering used by
/// workspace publication.
pub(crate) fn selected_workspace_file_projection_digest(
    file: &WorkspaceFileRow,
    path_symbols: &[PathSymbolRow],
    package_files: &[WorkspacePackageFileRow],
    package_edges: &[WorkspacePackageEdgeRow],
    anchors: &[WorkspaceAnchorRow],
) -> [u8; 32] {
    let projection = workspace_file_projection(
        &file.rel_path,
        path_symbols,
        package_files,
        package_edges,
        anchors,
    );
    workspace_file_projection_digest_bytes(file, &projection)
}

fn workspace_snapshots_conn(
    conn: &Connection,
    workspace_id: &WorkspaceId,
    langs: &[String],
    generations: &HashMap<String, GenerationId>,
) -> Result<WorkspaceSnapshots> {
    let mut statement = conn.prepare_cached(
        "SELECT revision FROM workspace_heads
         WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3",
    )?;
    let mut snapshots = HashMap::default();
    for lang in langs {
        let generation = generations[lang];
        let revision = statement
            .query_row(params![workspace_id.as_str(), lang, generation.0], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(revision) = revision {
            snapshots.insert(
                lang.clone(),
                WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang: lang.clone(),
                    generation,
                    revision,
                },
            );
        }
    }
    Ok(snapshots)
}

#[doc(hidden)]
pub fn ensure_revisioned_workspace_views(conn: &Connection) -> Result<()> {
    let configured = conn
        .query_row(
            "SELECT 1 FROM temp.sqlite_schema
             WHERE type = 'table' AND name = 'selected_workspace_revisions'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !configured {
        conn.execute_batch(REVISIONED_WORKSPACE_VIEWS_SQL)?;
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
fn current_test_workspace_snapshots(conn: &Connection) -> Result<WorkspaceSnapshots> {
    let workspace_id =
        WorkspaceId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let snapshots = {
        let mut statement = conn.prepare_cached(
            "SELECT heads.lang, heads.generation, heads.revision
             FROM workspace_heads AS heads
             LEFT JOIN analysis_epochs AS epochs ON epochs.lang = heads.lang
             WHERE heads.workspace_id = ?1
               AND heads.generation = COALESCE(epochs.generation, 0)",
        )?;
        let rows = statement.query_map([workspace_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                GenerationId(row.get::<_, i64>(1)?),
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut snapshots = HashMap::default();
        for row in rows {
            let (lang, generation, revision) = row?;
            snapshots.insert(
                lang.clone(),
                WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang,
                    generation,
                    revision,
                },
            );
        }
        snapshots
    };
    Ok(snapshots)
}

fn insert_workspace_file_projection_rows(
    tx: &Transaction<'_>,
    file_version_id: i64,
    projection: &WorkspaceFileProjection<'_>,
) -> Result<()> {
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO workspace_file_package_rows(file_version_id, package_name)
             VALUES(?1, ?2)",
        )?;
        for row in &projection.package_files {
            insert.execute(params![file_version_id, row.package_name])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO workspace_file_package_edge_rows(
               file_version_id, parent_package_name, child_package_name
             ) VALUES(?1, ?2, ?3)",
        )?;
        for row in &projection.package_edges {
            insert.execute(params![
                file_version_id,
                row.parent_package_name,
                row.child_package_name
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO workspace_file_anchor_rows(
               file_version_id, anchor_kind, anchor_pop, package_name
             ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &projection.anchors {
            let (kind, pop) = match row.anchor {
                PackageAnchor::OwnModule { pop } => ("own_module", i64::from(pop)),
                PackageAnchor::CrateRoot => ("crate_root", 0),
            };
            insert.execute(params![file_version_id, kind, pop, row.package_name])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO workspace_file_path_symbol_rows(
               file_version_id, kind, package_name, short_name,
               exact_fqn, normalized_fqn, requires_imports
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in &projection.path_symbols {
            insert.execute(params![
                file_version_id,
                code_unit_kind_to_i64(row.kind),
                row.package_name,
                row.short_name,
                row.exact_fqn,
                row.normalized_fqn,
                i64::from(row.requires_imports),
            ])?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchCandidateRow<I = FqIdentityHeader> {
    pub candidate: CandidateRow<I>,
    pub primary_range: Option<Range>,
    pub has_multiple_ranges: bool,
    pub secondary_range: Option<Range>,
    pub has_more_ranges: bool,
    pub all_ranges_are_definitions: bool,
    /// Per-declaration test-region taint (issue #1102): true when this specific
    /// unit is inside a structurally-evidenced test region, replacing the old
    /// file-level `contains_tests` replication so production symbols in a file
    /// with inline tests are not hidden.
    pub in_test_region: bool,
}

pub type HydratedSearchCandidateRow = SearchCandidateRow<RelationalUnitFq>;

/// The minimum persisted projection a `search_symbols` pattern batch needs to
/// decide whether a declaration matches: its short name plus the qualifier its
/// package prefix hydrates from. `lang_index` indexes the caller's storage
/// language-key slice so a row never allocates a language string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct SearchCandidateNameRow {
    pub lang_index: usize,
    pub blob_oid: Oid,
    pub unit_key: i64,
    pub short_name: String,
    pub content_qualifier: String,
}

/// One live blob a symbol-search candidate scan may read, together with the
/// request-scoped facts the literal prefilter needs about it.
///
/// The prefilter compares required literals against persisted name columns, but
/// a pattern is matched against a *hydrated* fully-qualified name whose package
/// prefix can come from the live path instead. These two fields carry that live
/// half of the name into SQL: `package_literals` says which of the request's
/// literals the blob's own path prefixes supply, and `prefilter_exempt` says the
/// blob's prefixes cannot be enumerated at all, so its declarations must survive
/// the prefilter unconditionally.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct ActiveSearchBlob {
    #[doc(hidden)]
    pub oid: Oid,
    /// The required literals this blob's path-derived package prefixes contain,
    /// lowercased and joined with `\n`. A required literal is `[a-z0-9_]` only,
    /// so no literal can straddle the join.
    #[doc(hidden)]
    pub package_literals: String,
    #[doc(hidden)]
    pub prefilter_exempt: bool,
}

impl ActiveSearchBlob {
    /// A blob no literal prefilter will be applied against, for callers that
    /// pass no required literals.
    #[doc(hidden)]
    pub fn unfiltered(oid: Oid) -> Self {
        Self {
            oid,
            package_literals: String::new(),
            prefilter_exempt: false,
        }
    }
}

/// A declaration identity that survived pattern matching and therefore earns
/// the full candidate projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct SearchCandidateKey {
    pub lang_index: usize,
    pub blob_oid: Oid,
    pub unit_key: i64,
}

/// Persisted facts required to derive callable arity and return types without
/// reconstructing a complete file state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageFactRow<I = FqIdentityHeader> {
    pub candidate: CandidateRow<I>,
    pub signature: Option<String>,
    pub signature_metadata: Option<SignatureMetadata>,
}

pub type HydratedUsageFactRow = UsageFactRow<RelationalUnitFq>;

fn workspace_content_package_facts_sql(oid_count: usize) -> String {
    assert!(oid_count > 0, "package-fact query needs at least one blob");
    let placeholders = std::iter::repeat_n("?", oid_count)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH package_units AS (
           SELECT keys.blob_oid, units.blob_id, units.lang, units.fq_anchor_kind,
                  units.fq_anchor_pop, units.content_qualifier,
                  units.package_fqn_tail, units.fq_package_tail_segments,
                  MIN(units.unit_key) AS unit_key
           FROM blobs AS keys
           JOIN live_declarations AS units ON units.blob_id = keys.id
           WHERE keys.lang = ?
             AND keys.blob_oid IN ({placeholders})
             AND units.package_fqn_tail IS NOT NULL
             AND units.fq_package_tail_segments IS NOT NULL
           GROUP BY units.blob_id, units.fq_anchor_kind,
                    units.fq_anchor_pop, units.content_qualifier,
                    units.package_fqn_tail, units.fq_package_tail_segments
         )
         SELECT packages.blob_oid, packages.fq_anchor_kind,
                packages.fq_anchor_pop, packages.content_qualifier,
                packages.package_fqn_tail,
                packages.fq_package_tail_segments,
                segments.seg_ordinal, segments.seg_kind, segments.segment
         FROM package_units AS packages
         LEFT JOIN code_unit_fq_segments AS segments
           ON segments.blob_id = packages.blob_id
          AND segments.unit_key = packages.unit_key
          AND segments.seg_ordinal < packages.fq_package_tail_segments
         ORDER BY packages.blob_oid, packages.fq_anchor_kind,
                  packages.fq_anchor_pop, packages.content_qualifier,
                  packages.package_fqn_tail, segments.seg_ordinal"
    )
}

const RUST_UNRESOLVED_TRAIT_IMPL_FILES_SQL: &str = "SELECT DISTINCT blobs.blob_oid,
       members.rel_path, endpoints.impl_declaration_id
FROM rust_resolution_unit_summary_trait_endpoints AS endpoints
     INDEXED BY rust_resolution_unit_summary_trait_endpoints_unresolved
CROSS JOIN resolution_unit_summaries AS summaries
  ON summaries.summary_id = endpoints.summary_id
CROSS JOIN resolution_unit_summary_versions AS versions
     INDEXED BY resolution_unit_summary_versions_summary
  ON versions.summary_id = summaries.summary_id
CROSS JOIN workspace_heads AS heads
  ON heads.workspace_id = versions.workspace_id AND heads.lang = versions.lang
 AND heads.generation = versions.generation
 AND versions.valid_from <= heads.revision
 AND (versions.valid_until IS NULL OR heads.revision < versions.valid_until)
CROSS JOIN resolution_producer_epochs AS epochs
  ON epochs.lang = versions.lang AND epochs.producer_epoch = summaries.producer_epoch
CROSS JOIN rust_resolution_unit_summary_versions AS rust_versions
  ON rust_versions.workspace_id = versions.workspace_id AND rust_versions.lang = versions.lang
 AND rust_versions.generation = versions.generation AND rust_versions.unit_key = versions.unit_key
 AND rust_versions.valid_from = versions.valid_from AND rust_versions.summary_id = versions.summary_id
CROSS JOIN resolution_unit_summary_members AS members
  ON members.summary_id = endpoints.summary_id AND members.member_ordinal = endpoints.member_ordinal
CROSS JOIN blobs ON blobs.id = members.blob_id
WHERE endpoints.endpoint_role = 'trait' AND endpoints.endpoint_state = 'unresolved'
  AND endpoints.unresolved_spelling = ?1
  AND summaries.lang = 'rust' AND summaries.unit_kind = 'rust_crate'
  AND summaries.publication_state = 'complete'
  AND summaries.derivation_version = ?2";

impl AnalyzerStore {
    #[doc(hidden)]
    pub fn resolution_shared_name_cache(&self) -> &resolution::SharedNameCache {
        &self.cache_budget
    }

    #[doc(hidden)]
    pub fn workspace_content_package_facts(
        &self,
        lang: &str,
        generation: GenerationId,
        blob_oids: &[Oid],
        file_package_anchor: Option<PackageAnchor>,
    ) -> Result<WorkspaceContentPackageFacts> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        const OIDS_PER_QUERY: usize = 900;
        #[derive(PartialEq)]
        struct GroupKey {
            blob_oid: Oid,
            anchor_kind: Option<String>,
            anchor_pop: Option<i64>,
            content_qualifier: String,
            package_tail: String,
            package_segment_count: usize,
        }
        type RawRow = (
            String,
            Option<String>,
            Option<i64>,
            String,
            String,
            usize,
            Option<usize>,
            Option<String>,
            Option<String>,
        );
        let mut requested_blobs = blob_oids.iter().map(Oid::to_string).collect::<Vec<_>>();
        requested_blobs.sort_unstable();
        requested_blobs.dedup();
        let mut rows = Vec::new();
        for chunk in requested_blobs.chunks(OIDS_PER_QUERY) {
            let mut statement =
                tx.prepare_cached(&workspace_content_package_facts_sql(chunk.len()))?;
            let parameters = std::iter::once(lang).chain(chunk.iter().map(String::as_str));
            let mapped = statement.query_map(params_from_iter(parameters), |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            })?;
            rows.extend(mapped.collect::<std::result::Result<Vec<RawRow>, _>>()?);
        }
        let file_content_packages: HashMap<String, String> = if file_package_anchor.is_some() {
            read_import_metadata_bulk(&tx, lang, &requested_blobs)?
                .into_iter()
                .map(|(oid, (package_name, _contains_tests))| (oid, package_name))
                .collect()
        } else {
            HashMap::default()
        };
        tx.commit()?;

        let interner = segment_interner();
        let mut facts = Vec::new();
        let mut current: Option<(GroupKey, FqName)> = None;
        let finish = |facts: &mut Vec<WorkspaceContentPackageFact>,
                      key: GroupKey,
                      package_tail: FqName|
         -> Result<()> {
            if package_tail.len() != key.package_segment_count {
                return Err(StoreError::new(format!(
                    "relational package tail segment count disagrees for {}/{}: expected {}, found {}",
                    key.blob_oid,
                    lang,
                    key.package_segment_count,
                    package_tail.len()
                )));
            }
            let anchor = match (key.anchor_kind.as_deref(), key.anchor_pop) {
                (None, None) => None,
                (Some("own_module"), Some(pop)) => Some(PackageAnchor::OwnModule {
                    pop: u8::try_from(pop).map_err(|_| {
                        StoreError::new(format!("invalid own-module anchor pop {pop}"))
                    })?,
                }),
                (Some("crate_root"), Some(0)) => Some(PackageAnchor::CrateRoot),
                pair => {
                    return Err(StoreError::new(format!(
                        "invalid relational package anchor pair {pair:?}"
                    )));
                }
            };
            facts.push(WorkspaceContentPackageFact {
                blob_oid: key.blob_oid,
                anchor,
                content_qualifier: key.content_qualifier,
                package_tail,
            });
            Ok(())
        };
        for (
            oid_text,
            anchor_kind,
            anchor_pop,
            content_qualifier,
            package_tail,
            package_segment_count,
            ordinal,
            kind,
            segment,
        ) in rows
        {
            let key = GroupKey {
                blob_oid: Oid::from_str(&oid_text)?,
                anchor_kind,
                anchor_pop,
                content_qualifier,
                package_tail,
                package_segment_count,
            };
            if current.as_ref().is_some_and(|(current, _)| *current != key) {
                let (finished_key, finished_tail) = current.take().unwrap();
                finish(&mut facts, finished_key, finished_tail)?;
            }
            let (_, fq) = current.get_or_insert_with(|| (key, FqName::new()));
            match (ordinal, kind, segment) {
                (Some(ordinal), Some(kind), Some(segment)) => {
                    if ordinal != fq.len() {
                        return Err(StoreError::new(format!(
                            "relational package segments are not contiguous: expected {}, found {ordinal}",
                            fq.len()
                        )));
                    }
                    fq.push(interner.intern(&segment, segment_kind_from_sql(&kind)?));
                }
                (None, None, None) if package_segment_count == 0 => {}
                row => {
                    return Err(StoreError::new(format!(
                        "incomplete relational package segment row {row:?}"
                    )));
                }
            }
        }
        if let Some((key, package_tail)) = current {
            finish(&mut facts, key, package_tail)?;
        }
        let mut complete = true;
        if let Some(anchor) = file_package_anchor {
            let mut covered_blobs = facts
                .iter()
                .map(|fact| fact.blob_oid)
                .collect::<HashSet<_>>();
            for oid_text in &requested_blobs {
                let Some(content_qualifier) = file_content_packages.get(oid_text) else {
                    continue;
                };
                let blob_oid = Oid::from_str(oid_text)?;
                if covered_blobs.insert(blob_oid) {
                    facts.push(WorkspaceContentPackageFact {
                        blob_oid,
                        anchor: Some(anchor),
                        content_qualifier: content_qualifier.clone(),
                        package_tail: FqName::new(),
                    });
                }
            }
            complete = requested_blobs.iter().all(|oid_text| {
                Oid::from_str(oid_text)
                    .ok()
                    .is_some_and(|oid| covered_blobs.contains(&oid))
            });
        }
        Ok(WorkspaceContentPackageFacts { facts, complete })
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn sync_workspace_inputs_for_workspace(
        &self,
        workspace_id: &WorkspaceId,
        lang: &str,
        generation: GenerationId,
        files: &[WorkspaceFileRow],
        path_symbols: &[PathSymbolRow],
        _packages: &[String],
        package_files: &[WorkspacePackageFileRow],
        package_edges: &[WorkspacePackageEdgeRow],
        anchors: &[WorkspaceAnchorRow],
        configuration: &[WorkspaceConfigurationInput],
        foreign_source_paths: &[String],
        refusals: &[WorkspaceSourceRefusalRow],
    ) -> Result<WorkspaceSnapshotId> {
        let configuration = configuration.to_vec();
        let refusals = refusals.to_vec();
        let foreign_source_paths = foreign_source_paths
            .iter()
            .cloned()
            .collect::<crate::hash::HashSet<_>>();
        let workspace_id = workspace_id.clone();
        let lang = lang.to_string();
        let files = files.to_vec();
        let path_symbols = path_symbols.to_vec();
        let package_files = package_files.to_vec();
        let package_edges = package_edges.to_vec();
        let anchors = anchors.to_vec();
        self.execute_selection_publication(move |conn| {
            let lang = lang.as_str();
            let files = files.as_slice();
            let path_symbols = path_symbols.as_slice();
            let package_files = package_files.as_slice();
            let package_edges = package_edges.as_slice();
            let anchors = anchors.as_slice();
            let tx = conn.transaction()?;
            let projections = workspace_file_projections(
                files,
                path_symbols,
                package_files,
                package_edges,
                anchors,
            );
            let digests = files
                .iter()
                .map(|file| workspace_file_projection_digest(file, &projections[&*file.rel_path]))
                .collect::<Vec<_>>();
            let inputs = files
                .iter()
                .zip(&digests)
                .map(|(file, digest)| workspace_inputs::WorkspaceInputRow {
                    relative_path: &file.rel_path,
                    content_oid: file.blob_oid,
                    projection_digest: Some(digest),
                })
                .collect::<Vec<_>>();
            for input in &configuration {
                input.retain(&tx)?;
            }
            let configuration_rows = configuration
                .iter()
                .map(WorkspaceConfigurationInput::row)
                .collect::<Vec<_>>();
            // Refusals share the source family's ownership: a content-reading
            // publisher names the natural files, refused ones included, foreign.
            let refusal_changes = workspace_inputs::WorkspaceRefusalChanges::replacing(
                &tx,
                &workspace_id,
                lang,
                generation,
                &refusals,
                &foreign_source_paths,
            )?;
            let (snapshot, inserted) = workspace_inputs::replace_workspace_input_partitions(
                &tx,
                &workspace_id,
                lang,
                generation,
                &[
                    workspace_inputs::WorkspaceInputPartition {
                        kind: workspace_inputs::WorkspaceInputKind::Source,
                        rows: &inputs,
                        foreign_paths: &foreign_source_paths,
                    },
                    workspace_inputs::WorkspaceInputPartition {
                        kind: workspace_inputs::WorkspaceInputKind::Configuration,
                        rows: &configuration_rows,
                        foreign_paths: &crate::hash::HashSet::default(),
                    },
                ],
                &refusal_changes,
            )?;
            for ((kind, path), id) in inserted {
                if kind == workspace_inputs::WorkspaceInputKind::Source {
                    insert_workspace_file_projection_rows(&tx, id, &projections[path.as_str()])?;
                }
            }
            tx.commit()?;
            Ok(snapshot)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn sync_workspace_snapshot_for_workspace(
        &self,
        workspace_id: &WorkspaceId,
        lang: &str,
        generation: GenerationId,
        files: &[WorkspaceFileRow],
        path_symbols: &[PathSymbolRow],
        packages: &[String],
        package_files: &[WorkspacePackageFileRow],
        package_edges: &[WorkspacePackageEdgeRow],
        anchors: &[WorkspaceAnchorRow],
    ) -> Result<WorkspaceSnapshotId> {
        self.sync_workspace_inputs_for_workspace(
            workspace_id,
            lang,
            generation,
            files,
            path_symbols,
            packages,
            package_files,
            package_edges,
            anchors,
            &[],
            &[],
            &[],
        )
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn sync_workspace_snapshot(
        &self,
        lang: &str,
        generation: GenerationId,
        files: &[WorkspaceFileRow],
        path_symbols: &[PathSymbolRow],
        packages: &[String],
        package_files: &[WorkspacePackageFileRow],
        package_edges: &[WorkspacePackageEdgeRow],
        anchors: &[WorkspaceAnchorRow],
    ) -> Result<WorkspaceSnapshotId> {
        let snapshot = self.sync_workspace_snapshot_for_workspace(
            &WorkspaceId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            lang,
            generation,
            files,
            path_symbols,
            packages,
            package_files,
            package_edges,
            anchors,
        )?;
        if self.db_path.is_none() {
            let conn = self.conn.lock().expect("ephemeral test store mutex");
            self.select_writer_workspace_snapshots(
                &conn,
                &HashMap::from_iter([(lang.to_string(), snapshot.clone())]),
            )?;
        }
        Ok(snapshot)
    }

    /// Path-derived module facts for bounded batches of selected candidate blobs.
    /// Admission is deliberately separate: callers batch import presence once.
    #[doc(hidden)]
    pub fn path_symbol_rows_for_blob_keys_at_snapshots(
        &self,
        snapshots: &WorkspaceSnapshots,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<(String, PathSymbolRow)>> {
        let mut by_lang: HashMap<String, Vec<Oid>> = HashMap::default();
        for (oid, lang) in entries {
            by_lang.entry(lang.clone()).or_default().push(*oid);
        }
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, by_lang.keys().map(String::as_str))?;
        // Refusal rows complete the selected revision's source domain. Read
        // them once for this whole-set query, rather than re-scanning them for
        // every OID chunk. Their scope and OID must match: old or foreign
        // refusals cannot explain a currently unpublished input.
        let mut refused: HashMap<String, HashSet<Oid>> = HashMap::default();
        let mut refusal_statement = tx.prepare_cached(
            "SELECT refusals.blob_oid
             FROM temp.selected_workspace_revisions AS selected
             CROSS JOIN main.workspace_source_refusals AS refusals
               ON refusals.workspace_id=selected.workspace_id
              AND refusals.lang=selected.lang
              AND refusals.generation=selected.generation
             WHERE selected.lang=?1 AND refusals.valid_from<=selected.revision
               AND (refusals.valid_until IS NULL OR selected.revision<refusals.valid_until)",
        )?;
        for lang in by_lang.keys() {
            let rows = refusal_statement.query_map([lang], |row| row.get::<_, String>(0))?;
            let language_refusals = refused.entry(lang.clone()).or_default();
            for row in rows {
                language_refusals.insert(Oid::from_str(&row?)?);
            }
        }
        drop(refusal_statement);
        // The ready-only live view can omit an unavailable blob. Only an
        // explicit selected-revision refusal explains a missing publication.
        let published = parsed_blob_keys_conn(&tx, entries)?;
        let missing = entries
            .iter()
            .filter(|entry| {
                !published.contains(*entry)
                    && !refused
                        .get(&entry.1)
                        .is_some_and(|oids| oids.contains(&entry.0))
            })
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(StoreError::new(format!(
                "path-symbol set inputs are not complete: {missing:?}"
            )));
        }
        let mut out = Vec::new();
        for (lang, mut oids) in by_lang {
            if let Some(refused) = refused.get(&lang) {
                oids.retain(|oid| !refused.contains(oid));
            }
            oids.sort();
            oids.dedup();
            for chunk in oids.chunks(900) {
                let placeholders = std::iter::repeat_n("?", chunk.len())
                    .collect::<Vec<_>>()
                    .join(",");
                // Drive from bounded OIDs before expanding the live view. Without
                // this join order SQLite can range over every language file for
                // each chunk, even when the snapshot/blob index is available.
                let sql = format!(
                    "SELECT files.lang,files.rel_path,files.blob_oid,rows.kind,rows.package_name,
                            rows.short_name,rows.exact_fqn,rows.normalized_fqn,rows.requires_imports
                     FROM main.blobs AS candidates INDEXED BY sqlite_autoindex_blobs_1
                     CROSS JOIN live_workspace_files AS files
                       ON files.lang=candidates.lang AND files.blob_oid=candidates.blob_oid
                     CROSS JOIN main.workspace_file_path_symbol_rows AS rows
                       ON rows.file_version_id=files.file_id
                     WHERE candidates.lang=? AND candidates.blob_oid IN ({placeholders})"
                );
                let parameters = std::iter::once(lang.clone())
                    .chain(chunk.iter().map(Oid::to_string))
                    .collect::<Vec<_>>();
                let mut statement = tx.prepare_cached(&sql)?;
                let rows = statement.query_map(params_from_iter(parameters.iter()), |row| {
                    Ok((row.get(0)?, decode_path_symbol_row(row, 1)?))
                })?;
                out.extend(rows.collect::<std::result::Result<Vec<_>, _>>()?);
            }
        }
        tx.commit()?;
        Ok(out)
    }

    #[doc(hidden)]
    pub fn path_symbol_rows_by_fqn_for_langs_at_snapshots(
        &self,
        workspace_snapshots: &WorkspaceSnapshots,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        exact_fqn: &str,
        normalized_fqn: &str,
    ) -> Result<Vec<(String, PathSymbolRow)>> {
        let mut conn = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let out = path_symbol_rows_by_fqn_in_tx(&tx, langs, exact_fqn, normalized_fqn)?;
        tx.commit()?;
        Ok(out)
    }

    #[doc(hidden)]
    /// Existing path-symbol lookup with a source-row cap before hydration.
    pub fn path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
        &self,
        workspace_snapshots: &WorkspaceSnapshots,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        names: (&str, &str),
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> Result<LimitedQueryRows<(String, PathSymbolRow)>> {
        let (exact_fqn, normalized_fqn) = names;
        if limit == 0 || !continue_query() {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        }
        let mut conn = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let mut rows = Vec::new();
        for lang in langs {
            for (sql, name) in std::iter::once((EXACT_PATH_SYMBOL_FQN_SQL, exact_fqn)).chain(
                (normalized_fqn != exact_fqn)
                    .then_some((NORMALIZED_PATH_SYMBOL_FQN_SQL, normalized_fqn)),
            ) {
                let remaining = limit - rows.len();
                if remaining == 0 {
                    return Ok(LimitedQueryRows::incomplete(rows, limit));
                }
                let sql = format!("{sql} LIMIT ?3");
                let mut statement = tx.prepare_cached(&sql)?;
                let mut source = statement.query(params![
                    lang,
                    name,
                    i64::try_from(remaining).unwrap_or(i64::MAX)
                ])?;
                loop {
                    if !continue_query() {
                        let inspected = rows.len();
                        return Ok(LimitedQueryRows::incomplete(rows, inspected));
                    }
                    let Some(row) = source.next()? else { break };
                    rows.push((row.get::<_, String>(0)?, decode_path_symbol_row(row, 1)?));
                }
            }
        }
        tx.commit()?;
        let inspected = rows.len();
        Ok(if inspected == limit {
            LimitedQueryRows::incomplete(rows, inspected)
        } else {
            LimitedQueryRows::complete(rows, inspected)
        })
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn path_symbol_rows_by_fqn_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        exact_fqn: &str,
        normalized_fqn: &str,
    ) -> Result<Vec<(String, PathSymbolRow)>> {
        let workspace_id =
            WorkspaceId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        let snapshots = self.workspace_snapshots_for_langs(&workspace_id, langs, generations)?;
        self.path_symbol_rows_by_fqn_for_langs_at_snapshots(
            &snapshots,
            langs,
            generations,
            exact_fqn,
            normalized_fqn,
        )
    }

    /// Batched sibling of `path_symbol_rows_by_fqn_for_langs`: resolves many (exact_fqn,
    /// normalized_fqn) pairs in one transaction instead of one transaction per pair. Used by the
    /// Python import resolver so a file with many imports doesn't open one transaction per import.
    ///
    /// The outer `Result` covers setup failures (can't open the transaction at all); each item's own
    /// `Result` is independent, so one FQN's query/decode error doesn't discard the rest of the
    /// batch's already-successful results the way propagating a single `?` through the loop would.
    #[doc(hidden)]
    pub fn path_symbol_rows_by_fqns_for_langs_batch_at_snapshots(
        &self,
        workspace_snapshots: &WorkspaceSnapshots,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        fqns: &[(String, String)],
    ) -> Result<Vec<PathSymbolRowsResult>> {
        let mut conn = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let results = fqns
            .iter()
            .map(|(exact_fqn, normalized_fqn)| {
                path_symbol_rows_by_fqn_in_tx(&tx, langs, exact_fqn, normalized_fqn)
            })
            .collect();
        tx.commit()?;
        Ok(results)
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn replace_path_symbol_unit(
        &self,
        workspace_id: &WorkspaceId,
        base_snapshots: &WorkspaceSnapshots,
        storage_langs: &[String],
        generations: &HashMap<String, GenerationId>,
        rel_path: &str,
        file_replacement: Option<(&str, Oid)>,
        path_symbol_replacement: Option<(&str, &PathSymbolRow)>,
        _packages: &[String],
        package_files: &[WorkspacePackageFileRow],
        package_edges: &[WorkspacePackageEdgeRow],
        anchors: &[WorkspaceAnchorRow],
        refusal: Option<(&str, &WorkspaceSourceRefusalRow)>,
    ) -> Result<WorkspaceSnapshots> {
        assert!(
            file_replacement.is_none() || refusal.is_none(),
            "a live source is either selected or refused: {rel_path}"
        );
        let workspace_id = workspace_id.clone();
        let base_snapshots = base_snapshots.clone();
        let storage_langs = storage_langs.to_vec();
        let generations = generations.clone();
        let rel_path = rel_path.to_string();
        let refusal = refusal.map(|(lang, row)| (lang.to_string(), row.clone()));
        let file_replacement = file_replacement.map(|(lang, oid)| (lang.to_string(), oid));
        let path_symbol_replacement =
            path_symbol_replacement.map(|(lang, row)| (lang.to_string(), row.clone()));
        let package_files = package_files.to_vec();
        let package_edges = package_edges.to_vec();
        let anchors = anchors.to_vec();
        self.execute_selection_publication(move |conn| {
            let storage_langs = storage_langs.as_slice();
            let workspace_id_text = workspace_id.as_str();
            let generations = &generations;
            let base_snapshots = &base_snapshots;
            let rel_path = rel_path.as_str();
            let file_replacement = file_replacement
                .as_ref()
                .map(|(lang, oid)| (lang.as_str(), *oid));
            let path_symbol_replacement = path_symbol_replacement
                .as_ref()
                .map(|(lang, row)| (lang.as_str(), row));
            let package_files = package_files.as_slice();
            let package_edges = package_edges.as_slice();
            let anchors = anchors.as_slice();
            let refusal = refusal.as_ref().map(|(lang, row)| (lang.as_str(), row));
            let tx = conn.transaction()?;
            let mut snapshots = HashMap::default();
            let live_lang = file_replacement
                .map(|(lang, _)| lang)
                .or(refusal.map(|(lang, _)| lang));
            for lang in storage_langs {
                if let Some(file_lang) = live_lang
                    && file_lang != lang
                {
                    // A live file's row under another storage language is a
                    // content reading, and the analyzer that mounts it there
                    // publishes it (the C reading of a C++ header under
                    // `cpp:c`). A deleted file is closed everywhere (#3763).
                    continue;
                }
                let generation = generations.get(lang).copied().ok_or_else(|| {
                    StoreError::new(format!("missing captured generation for {lang}"))
                })?;
                let head_revision = require_base_workspace_revision(
                    &tx,
                    &workspace_id,
                    base_snapshots,
                    lang,
                    generation,
                )?;
                let old = tx
                    .query_row(
                        "SELECT file_version_id, projection_digest FROM workspace_file_versions
                         WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                           AND rel_path = ?4 AND input_kind = 'source' AND valid_until IS NULL",
                        params![workspace_id_text, lang, generation.0, rel_path],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                let replacement_file = file_replacement
                    .filter(|(replacement_lang, _)| *replacement_lang == lang)
                    .map(|(_, blob_oid)| WorkspaceFileRow {
                        rel_path: rel_path.to_string(),
                        blob_oid,
                    });
                let replacement_symbols = path_symbol_replacement
                    .filter(|(replacement_lang, _)| *replacement_lang == lang)
                    .map(|(_, row)| std::slice::from_ref(row))
                    .unwrap_or_default();
                let replacement_projection = workspace_file_projection(
                    rel_path,
                    replacement_symbols,
                    package_files,
                    package_edges,
                    anchors,
                );
                let new_digest = replacement_file
                    .as_ref()
                    .map(|file| workspace_file_projection_digest(file, &replacement_projection));
                let changed =
                    old.as_ref().map(|(_, digest)| digest.as_str()) != new_digest.as_deref();
                let closed = old.as_ref().filter(|_| changed).map(|(id, _)| *id);
                let replacement = replacement_file.as_ref().filter(|_| changed).map(|file| {
                    workspace_inputs::WorkspaceInputRow {
                        relative_path: rel_path,
                        content_oid: file.blob_oid,
                        projection_digest: new_digest.as_deref(),
                    }
                });
                let replacements = replacement
                    .as_ref()
                    .map(|row| (workspace_inputs::WorkspaceInputKind::Source, row));
                let refusal_changes = workspace_inputs::WorkspaceRefusalChanges::replacing_path(
                    &tx,
                    &workspace_id,
                    lang,
                    generation,
                    rel_path,
                    refusal
                        .filter(|(refusal_lang, _)| *refusal_lang == lang)
                        .map(|(_, row)| row),
                )?;
                let (snapshot, inserted) = workspace_inputs::publish_workspace_input_changes(
                    &tx,
                    &workspace_id,
                    lang,
                    generation,
                    Some(head_revision),
                    closed.as_slice(),
                    replacements.as_slice(),
                    &refusal_changes,
                )?;
                for id in inserted.into_values() {
                    insert_workspace_file_projection_rows(&tx, id, &replacement_projection)?;
                }
                snapshots.insert(lang.clone(), snapshot);
            }
            tx.commit()?;
            Ok(snapshots)
        })
    }

    /// Publish one changed configuration input at the next revision of every
    /// storage language and return the digest of that revision's complete
    /// configuration partition. An incremental update uses this only for an
    /// input that cannot rekey declarations; the rows it closes and opens have
    /// the same shape a full build writes.
    #[doc(hidden)]
    pub fn replace_configuration_input(
        &self,
        workspace_id: &WorkspaceId,
        base_snapshots: &WorkspaceSnapshots,
        storage_langs: &[String],
        generations: &HashMap<String, GenerationId>,
        input: WorkspaceConfigurationInput,
    ) -> Result<(
        WorkspaceSnapshots,
        crate::analyzer::semantic::ids::StableDigest,
    )> {
        let workspace_id = workspace_id.clone();
        let base_snapshots = base_snapshots.clone();
        let storage_langs = storage_langs.to_vec();
        let generations = generations.clone();
        self.conn.execute(move |conn| {
            let tx = conn.transaction()?;
            input.retain(&tx)?;
            let mut snapshots = HashMap::default();
            let mut digest = None;
            for lang in &storage_langs {
                let generation = generations.get(lang).copied().ok_or_else(|| {
                    StoreError::new(format!("missing captured generation for {lang}"))
                })?;
                let head_revision = require_base_workspace_revision(
                    &tx,
                    &workspace_id,
                    &base_snapshots,
                    lang,
                    generation,
                )?;
                let old = tx
                    .query_row(
                        "SELECT file_version_id, blob_oid FROM workspace_file_versions
                         WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                           AND rel_path = ?4 AND input_kind = 'configuration'
                           AND valid_until IS NULL",
                        params![
                            workspace_id.as_str(),
                            lang,
                            generation.0,
                            input.relative_path()
                        ],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                let changed = old
                    .as_ref()
                    .is_none_or(|(_, oid)| *oid != input.content_oid().to_string());
                let closed = old.as_ref().filter(|_| changed).map(|(id, _)| *id);
                let row = input.row();
                let replacements =
                    changed.then_some((workspace_inputs::WorkspaceInputKind::Configuration, &row));
                let (snapshot, _) = workspace_inputs::publish_workspace_input_changes(
                    &tx,
                    &workspace_id,
                    lang,
                    generation,
                    Some(head_revision),
                    closed.as_slice(),
                    replacements.as_slice(),
                    &Default::default(),
                )?;
                let rows = tx
                    .prepare_cached(
                        "SELECT rel_path, blob_oid FROM workspace_file_versions
                         WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                           AND input_kind = 'configuration' AND valid_until IS NULL
                         ORDER BY rel_path",
                    )?
                    .query_map(params![workspace_id.as_str(), lang, generation.0], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .map(|row| {
                        let (path, oid) = row?;
                        let oid = Oid::from_str(&oid).map_err(|error| {
                            StoreError::new(format!(
                                "invalid configuration oid {oid:?} at {path:?}: {error}"
                            ))
                        })?;
                        Ok((path, oid))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let lang_digest = workspace_inputs::configuration_digest(
                    rows.iter().map(|(path, oid)| (path.as_str(), *oid)),
                );
                assert!(
                    digest.is_none_or(|digest| digest == lang_digest),
                    "storage languages of one analyzer share its configuration: {rows:?}"
                );
                digest = Some(lang_digest);
                snapshots.insert(lang.clone(), snapshot);
            }
            tx.commit()?;
            let digest = digest.expect("an analyzer has at least one storage language");
            Ok((snapshots, digest))
        })
    }

    pub fn open_for_workspace(workspace_root: &Path) -> Result<Self> {
        if gitblob::discover(workspace_root).is_some() {
            Self::open_persistent(&analyzer_db_path(workspace_root))
        } else {
            Self::open_ephemeral()
        }
    }

    fn from_parts(
        conn: Connection,
        reader_source: Option<PathBuf>,
        db_path: Option<PathBuf>,
        ephemeral: Option<EphemeralDb>,
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
    ) -> Self {
        resolution_lexical::register_resolution_identity_functions(&conn)
            .expect("configure resolution identity SQL functions");
        rust_crates::register_point_export_functions(&conn)
            .expect("configure Rust export SQL functions");
        #[cfg(any(test, feature = "test-support"))]
        conn.execute_batch(REVISIONED_WORKSPACE_VIEWS_SQL)
            .expect("configure test workspace views");
        Self {
            conn: StoreWriter::local(conn),
            readers: ReaderPool::new(reader_source.clone()),
            active_readers: ReaderPool::new(reader_source.clone()),
            streaming_readers: ReaderPool::new(reader_source),
            writer_selection: Arc::new(Mutex::new(None)),
            #[cfg(any(test, feature = "test-support"))]
            crate_statement_counter: Mutex::new(None),
            writer_resolution_selection: Mutex::new(None),
            cache_budget: cache_budget::StoreCacheBudget::new(config.store_cache_budget_bytes()),
            #[cfg(any(test, feature = "test-support"))]
            workspace_selection_counters: WorkspaceSelectionCounters::default(),
            db_path,
            lifetime: Arc::new(()),
            _ephemeral: ephemeral,
            #[cfg(any(test, feature = "test-support"))]
            class_set_field_slot_operational_failure: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            class_set_root_result_operational_failure: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            parsed_blob_transaction_starts: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            parsed_blob_point_contains_queries: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            replacement_cost_lookup_queries: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            replacement_cost_fallback_queries: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            prepared_generation_lookup_queries: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            relational_batch_reader_checkouts: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            relational_batch_generation_validations: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            relational_batch_distinct_requests: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            relational_live_unit_count_queries: AtomicUsize::new(0),
        }
    }

    pub fn open_persistent(db_path: &Path) -> Result<Self> {
        Self::open_persistent_with_config(db_path, &Default::default())
    }

    pub fn open_persistent_with_config(
        db_path: &Path,
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
    ) -> Result<Self> {
        let (conn, reader_source) = StoreWriter::persistent(db_path)?;
        Ok(Self {
            conn,
            readers: ReaderPool::new(Some(reader_source.clone())),
            active_readers: ReaderPool::new(Some(reader_source.clone())),
            streaming_readers: ReaderPool::new(Some(reader_source)),
            writer_selection: Arc::new(Mutex::new(None)),
            #[cfg(any(test, feature = "test-support"))]
            crate_statement_counter: Mutex::new(None),
            writer_resolution_selection: Mutex::new(None),
            cache_budget: cache_budget::StoreCacheBudget::new(config.store_cache_budget_bytes()),
            #[cfg(any(test, feature = "test-support"))]
            workspace_selection_counters: WorkspaceSelectionCounters::default(),
            db_path: Some(db_path.to_path_buf()),
            lifetime: Arc::new(()),
            _ephemeral: None,
            #[cfg(any(test, feature = "test-support"))]
            class_set_field_slot_operational_failure: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            class_set_root_result_operational_failure: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            parsed_blob_transaction_starts: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            parsed_blob_point_contains_queries: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            replacement_cost_lookup_queries: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            replacement_cost_fallback_queries: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            prepared_generation_lookup_queries: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            relational_batch_reader_checkouts: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            relational_batch_generation_validations: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            relational_batch_distinct_requests: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            relational_live_unit_count_queries: AtomicUsize::new(0),
        })
    }

    /// Ephemeral (non-git) workspace store.
    ///
    /// Backed by a delete-on-drop temp *file* rather than `:memory:` so the
    /// reader pool works uniformly: an `:memory:` DB is private to a single
    /// connection, which a reader pool could never share. The temp file runs in
    /// WAL at page-cache speed. `db_path()` still reports `None` and
    /// `is_ephemeral()` still reports `true` — these mark "no persistent
    /// workspace identity", which is exactly what an ephemeral store is,
    /// independent of the on-disk backing.
    ///
    /// Documented fallback: if the temp-file backing cannot be established on
    /// this platform, fall back to a single in-memory connection whose reads
    /// route through the writer (no read parallelism, but correct).
    pub fn open_ephemeral() -> Result<Self> {
        Self::open_ephemeral_with_config(&Default::default())
    }

    pub fn open_ephemeral_with_config(
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
    ) -> Result<Self> {
        match Self::open_ephemeral_temp_file(config) {
            Ok(store) => Ok(store),
            Err(_) => Self::open_in_memory_single_connection_with_config(config),
        }
    }

    #[doc(hidden)]
    pub fn lifetime(&self) -> std::sync::Weak<()> {
        Arc::downgrade(&self.lifetime)
    }

    pub fn semantic_pack_active_set(&self) -> Result<Option<SemanticPackActiveSet>> {
        let connection = self.read_conn()?;
        let digest = connection
            .query_row(
                "SELECT active_set_digest
                 FROM semantic_pack_active_state
                 WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(active_set_digest) = digest else {
            return Ok(None);
        };
        let mut statement = connection.prepare(
            "SELECT manifest_digest, source_kind, source_id, workspace_produced
             FROM semantic_pack_active_members
             ORDER BY ordinal",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        let mut members = Vec::new();
        for row in rows {
            let (manifest_digest, source_kind, source_id, workspace_produced) = row?;
            members.push(SemanticPackActiveReference {
                manifest_digest,
                source_kind: SemanticPackActivationSourceKind::parse(&source_kind)?,
                source_id,
                workspace_produced,
            });
        }
        let computed = semantic_pack_active_set_digest(&members)?;
        if computed != active_set_digest {
            return Err(StoreError::new(format!(
                "semantic-pack active-set digest mismatch: stored {active_set_digest}, computed {computed}"
            )));
        }
        Ok(Some(SemanticPackActiveSet {
            active_set_digest,
            members,
        }))
    }

    pub fn replace_semantic_pack_active_set(
        &self,
        members: &[SemanticPackActiveReference],
    ) -> Result<SemanticPackActiveSet> {
        let active_set = SemanticPackActiveSet::from_members(members)?;
        let now = crate::cache_db::now_unix_seconds();
        self.conn.execute(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute("DELETE FROM semantic_pack_active_members", [])?;
            {
                let mut insert = transaction.prepare(
                    "INSERT INTO semantic_pack_active_members(
                   ordinal, manifest_digest, source_kind, source_id, workspace_produced
                 ) VALUES(?1, ?2, ?3, ?4, ?5)",
                )?;
                for (ordinal, member) in active_set.members.iter().enumerate() {
                    insert.execute(params![
                        ordinal,
                        &member.manifest_digest,
                        member.source_kind.as_str(),
                        &member.source_id,
                        member.workspace_produced
                    ])?;
                }
            }
            transaction.execute(
                "INSERT INTO semantic_pack_active_state(
               singleton, active_set_digest, updated_at
             ) VALUES(1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET
               active_set_digest = excluded.active_set_digest,
               updated_at = excluded.updated_at",
                params![&active_set.active_set_digest, now],
            )?;
            transaction.commit()?;
            Ok(active_set)
        })
    }

    fn open_ephemeral_temp_file(
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
    ) -> Result<Self> {
        let path = unique_temp_db_path();
        let conn = crate::cache_db::open_unified_connection(&path).map_err(StoreError::new)?;
        let Some(resolved) = reader_source_path(&conn) else {
            return Err(StoreError::new(
                "ephemeral analyzer cache temp file has no resolvable path",
            ));
        };
        Ok(Self::from_parts(
            conn,
            Some(resolved.clone()),
            None,
            Some(EphemeralDb { path: resolved }),
            config,
        ))
    }

    #[doc(hidden)]
    pub fn open_in_memory_single_connection() -> Result<Self> {
        Self::open_in_memory_single_connection_with_config(&Default::default())
    }

    pub fn open_in_memory_single_connection_with_config(
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
    ) -> Result<Self> {
        let mut conn = crate::cache_db::open_in_memory_store_connection()?;
        crate::cache_db::configure_connection(&mut conn).map_err(StoreError::new)?;
        crate::cache_db::migrate(&mut conn).map_err(StoreError::new)?;
        // `reader_source = None` routes reads back through the writer connection.
        Ok(Self::from_parts(conn, None, None, None, config))
    }

    /// Decode language-owned source rows in one generation-checked snapshot.
    /// Connection pooling and transaction lifetime stay in store infrastructure.
    #[doc(hidden)]
    pub fn read_source_transaction<T>(
        &self,
        lang: &str,
        generation: GenerationId,
        decode: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let value = decode(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// Check out a read-only connection for a pure-SELECT method. Pooled readers
    /// run concurrently against WAL snapshots; the writer connection is never
    /// taken by these paths (except in the in-memory single-connection
    /// fallback, where `source` is `None`).
    #[doc(hidden)]
    pub fn read_conn(&self) -> Result<ReaderGuard<'_>> {
        let conn = self.checkout_read_conn()?;
        #[cfg(any(test, feature = "test-support"))]
        let conn = {
            let mut conn = conn;
            // Streaming readers are query-only, so they cannot accept the
            // temp workspace-selection writes below. Streaming store reads
            // use the persisted blob tables directly and do not need those
            // revisioned views.
            if !self.streaming_read_active() {
                let snapshots = current_test_workspace_snapshots(&conn)?;
                self.select_workspace_snapshots(&mut conn, &snapshots)?;
            }
            conn
        };
        Ok(conn)
    }

    #[doc(hidden)]
    pub fn uses_single_connection_reads(&self) -> bool {
        self.readers.source.is_none()
    }

    /// Check out a reader and point its revisioned views at `snapshots`.
    ///
    /// This does not go through [`Self::read_conn`]: that path selects the test
    /// workspace, and alternating two selections on one connection would
    /// rewrite the selection rows on every checkout, which is the cost this
    /// exists to remove.
    #[doc(hidden)]
    pub fn read_conn_for_workspace(
        &self,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<ReaderGuard<'_>> {
        let mut conn = self.checkout_read_conn()?;
        self.select_workspace_snapshots(&mut conn, snapshots)?;
        Ok(conn)
    }

    fn checkout_read_conn(&self) -> Result<ReaderGuard<'_>> {
        let conn = if self.streaming_read_active() {
            self.read_conn_from_pool(
                &self.streaming_readers,
                crate::cache_db::open_streaming_readonly_connection,
            )
        } else {
            self.read_conn_from_pool(
                &self.readers,
                crate::cache_db::open_readonly_temp_connection,
            )
        }?;
        Ok(conn)
    }

    /// A publication job may commit before returning an error. Invalidate the
    /// writer fallback while its connection is still held, even in that case:
    /// SQLite data_version excludes commits made by the connection itself.
    #[doc(hidden)]
    pub fn execute_selection_publication<T, F>(&self, job: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> T + Send + 'static,
    {
        let selection = Arc::clone(&self.writer_selection);
        self.conn.execute(move |conn| {
            let outcome = job(conn);
            *selection
                .lock()
                .expect("analyzer store writer selection poisoned") = None;
            outcome
        })
    }

    /// Materialize `snapshots` in `guard`'s temp schema, unless that is already
    /// what the connection holds.
    ///
    /// The revisioned views are created once per connection and the selection
    /// rows are rewritten only when snapshots or publication freshness change, so a run of
    /// batches against one workspace generation costs one view script and one
    /// selection write however many batches it contains (#2883).
    #[doc(hidden)]
    pub fn select_workspace_snapshots(
        &self,
        guard: &mut ReaderGuard<'_>,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<()> {
        let (conn, selection) = guard.connection_and_selection();
        self.apply_workspace_selection(conn, selection, snapshots)
    }

    #[doc(hidden)]
    /// Point the writer connection's revisioned views at `snapshots`.
    ///
    /// Reads normally take a pooled reader; this is for the ephemeral store's
    /// own writer-connection queries, which hold that connection already. The
    /// selection it leaves behind is the one the writer-backed reader fallback
    /// then sees.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn select_writer_workspace_snapshots(
        &self,
        conn: &Connection,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<()> {
        let mut selection = self
            .writer_selection
            .lock()
            .expect("analyzer store writer selection poisoned");
        self.apply_workspace_selection(conn, &mut selection, snapshots)
    }

    fn apply_workspace_selection(
        &self,
        conn: &Connection,
        selection: &mut Option<AppliedWorkspaceSelection>,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<()> {
        let stamp = workspace_selection_stamp(conn)?;
        if selection
            .as_ref()
            .is_some_and(|selection| selection.snapshots == *snapshots && selection.stamp == stamp)
        {
            return Ok(());
        }
        if selection.is_none() {
            #[cfg(any(test, feature = "test-support"))]
            self.workspace_selection_counters
                .view_creations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ensure_revisioned_workspace_views(conn)?;
        }
        #[cfg(any(test, feature = "test-support"))]
        self.workspace_selection_counters
            .selection_writes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let changes_before = conn.total_changes();
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch("DELETE FROM temp.selected_rust_unit_closure; DELETE FROM temp.selected_rust_unit_summaries;")?;
        tx.prepare_cached("DELETE FROM temp.selected_workspace_revisions")?
            .execute([])?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO temp.selected_workspace_revisions(
                   workspace_id, lang, generation, revision
                 ) VALUES(?1, ?2, ?3, ?4)",
            )?;
            for snapshot in snapshots.values() {
                insert.execute(params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.0,
                    snapshot.revision,
                ])?;
            }
        }
        fill_selected_rust_units(&tx)?;
        // Read while this transaction still pins the publication used by the
        // fill. An external commit after it ends must differ on next checkout.
        let stamp = workspace_selection_stamp(&tx)?;
        tx.commit()?;
        let application_changes = selection
            .as_ref()
            .map_or(0, |selection| selection.application_changes)
            + (conn.total_changes() - changes_before);
        *selection = Some(AppliedWorkspaceSelection {
            snapshots: snapshots.clone(),
            stamp,
            application_changes,
        });
        Ok(())
    }

    /// Runs of the revisioned view script, and rewrites of the selection rows.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn workspace_selection_counts_for_test(&self) -> (usize, usize) {
        (
            self.workspace_selection_counters
                .view_creations
                .load(std::sync::atomic::Ordering::Relaxed),
            self.workspace_selection_counters
                .selection_writes
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    #[doc(hidden)]
    pub fn active_read_conn(&self) -> Result<ReaderGuard<'_>> {
        let conn = self.read_conn_from_pool(
            &self.active_readers,
            crate::cache_db::open_readonly_temp_connection,
        )?;
        Ok(conn)
    }

    fn read_conn_from_pool<'a>(
        &'a self,
        pool: &'a ReaderPool,
        open: fn(&Path) -> crate::cache_db::Result<Connection>,
    ) -> Result<ReaderGuard<'a>> {
        let mut reader = self.read_conn_with_acquisition(pool, open, || pool.acquire())?;
        reader.restore_general_query_plans()?;
        Ok(reader)
    }

    fn active_read_conn_for_resolution(
        &self,
        key: &resolution_selection::RetainedResolutionSelectionKey,
    ) -> Result<ReaderGuard<'_>> {
        let conn = self.read_conn_with_acquisition(
            &self.active_readers,
            crate::cache_db::open_readonly_temp_connection,
            || self.active_readers.acquire_for_resolution(key),
        )?;
        Ok(conn)
    }

    /// [`Self::active_read_conn_for_resolution`] for a selection opener. The
    /// in-memory fallback's only connection can be held by another request
    /// for as long as that request runs, so the wait for it observes
    /// `cancellation`; `None` means it stopped the wait.
    fn cancellable_read_conn_for_resolution(
        &self,
        key: &resolution_selection::RetainedResolutionSelectionKey,
        cancellation: &CancellationToken,
    ) -> Result<Option<ReaderGuard<'_>>> {
        if self.active_readers.source.is_none() {
            return Ok(self
                .conn
                .lock_cancellable(cancellation)
                .map(|conn| self.writer_reader_guard(conn)));
        }
        self.active_read_conn_for_resolution(key).map(Some)
    }

    fn read_conn_with_acquisition<'a>(
        &'a self,
        pool: &'a ReaderPool,
        open: fn(&Path) -> crate::cache_db::Result<Connection>,
        acquire: impl FnOnce() -> (u64, Option<SelectedReader>),
    ) -> Result<ReaderGuard<'a>> {
        match pool.source.as_deref() {
            Some(path) => {
                // The permit is held across the open, so a cold connection
                // still counts against capacity while it is being built.
                let (statistics_epoch, acquired) = acquire();
                let reader = match acquired {
                    Some(reader) => reader,
                    None => match open(path).map_err(StoreError::new).and_then(|conn| {
                        // Replacing a SQLite function expires every prepared
                        // statement. Install once per newly opened connection,
                        // never on checkout of an already configured reader.
                        resolution_lexical::register_resolution_identity_functions(&conn)?;
                        rust_crates::register_point_export_functions(&conn)?;
                        Ok(conn)
                    }) {
                        Ok(conn) => SelectedReader {
                            conn,
                            selection: None,
                            resolution_selection: None,
                            statistics_epoch,
                            query_planner_stability_before_resolution: None,
                        },
                        Err(error) => {
                            pool.abandon_checkout();
                            return Err(error);
                        }
                    },
                };
                Ok(ReaderGuard {
                    inner: ReaderConn::Pooled {
                        pool,
                        reader: Some(reader),
                    },
                    checkin_cleanup: None,
                    query_planner_stability_on_checkin: None,
                    restore_reader_mmap_on_checkin: false,
                    reusable: true,
                })
            }
            None => {
                Ok(self
                    .writer_reader_guard(self.conn.lock().expect("analyzer store mutex poisoned")))
            }
        }
    }

    /// The in-memory fallback's reader around a held writer connection.
    fn writer_reader_guard<'a>(
        &'a self,
        conn: std::sync::MutexGuard<'a, Connection>,
    ) -> ReaderGuard<'a> {
        ReaderGuard {
            inner: self.writer_reader_conn(conn),
            checkin_cleanup: None,
            query_planner_stability_on_checkin: None,
            restore_reader_mmap_on_checkin: false,
            reusable: true,
        }
    }

    /// The selection mutexes are taken only by a holder of the connection, so
    /// they never wait once `conn` is held.
    fn writer_reader_conn<'a>(
        &'a self,
        conn: std::sync::MutexGuard<'a, Connection>,
    ) -> ReaderConn<'a> {
        ReaderConn::Writer {
            store: self,
            conn,
            selection: self
                .writer_selection
                .lock()
                .expect("analyzer store writer selection poisoned"),
            resolution_selection: self
                .writer_resolution_selection
                .lock()
                .expect("analyzer store retained resolution selection poisoned"),
            _exclusive: self.conn.retain_exclusive_reader(),
        }
    }

    #[doc(hidden)]
    pub fn begin_streaming_read(&self) {
        let id = self as *const Self as usize;
        STREAMING_READ_DEPTHS.with(|depths| {
            *depths.borrow_mut().entry(id).or_default() += 1;
        });
    }

    #[doc(hidden)]
    pub fn end_streaming_read(&self) {
        let id = self as *const Self as usize;
        STREAMING_READ_DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            let depth = depths
                .get_mut(&id)
                .expect("analyzer store streaming read must be active");
            *depth = depth
                .checked_sub(1)
                .expect("analyzer store streaming read depth must be positive");
            if *depth == 0 {
                depths.remove(&id);
            }
        });
    }

    fn streaming_read_active(&self) -> bool {
        let id = self as *const Self as usize;
        STREAMING_READ_DEPTHS.with(|depths| depths.borrow().contains_key(&id))
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    pub fn is_ephemeral(&self) -> bool {
        self.db_path.is_none()
    }

    pub fn register_blobs(&self, oids: &[Oid], lang: &str, generation: GenerationId) -> Result<()> {
        let oids = oids.to_vec();
        let lang = lang.to_string();
        self.conn.execute(move |conn| {
            let lang = lang.as_str();
            let oids = oids.as_slice();
            let tx = conn.transaction()?;
            require_current_generation(&tx, lang, generation)?;
            {
                let mut remove_stale = tx.prepare(
                    "DELETE FROM blobs
                 WHERE blob_oid = ?1 AND lang = ?2 AND generation <> ?3",
                )?;
                let mut insert = tx.prepare(
                    "INSERT OR IGNORE INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, ?3)",
                )?;
                let mut seen = HashSet::default();
                for oid in oids {
                    if seen.insert(*oid) {
                        remove_stale.execute(params![oid.to_string(), lang, generation.0])?;
                        insert.execute(params![oid.to_string(), lang, generation.0])?;
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    pub fn ensure_language_epoch_value(
        &self,
        lang: &str,
        analysis_epoch: &str,
    ) -> Result<GenerationId> {
        let entries = [(lang.to_string(), analysis_epoch.to_string())];
        Ok(self.ensure_language_epoch_values(&entries)?[lang])
    }

    #[doc(hidden)]
    pub fn ensure_language_epoch_values(
        &self,
        entries: &[(String, String)],
    ) -> Result<HashMap<String, GenerationId>> {
        let conn = self.read_conn()?;
        if let Some(generations) = matching_language_epochs_conn(&conn, entries)? {
            return Ok(generations);
        }
        drop(conn);
        let entries = entries.to_vec();
        self.execute_selection_publication(move |conn| ensure_language_epochs_tx(conn, &entries))
    }

    /// Sum persisted analyzer payload bytes for complete blobs in the active
    /// language generations. The cache budget uses this as a corpus-size hint;
    /// it is not an exact heap measurement because source text is not stored in
    /// `blob_payload_costs`.
    #[doc(hidden)]
    pub fn active_file_state_payload_bytes(
        &self,
        generations: &HashMap<String, GenerationId>,
    ) -> Result<usize> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut total = 0usize;
        let mut statement = tx.prepare_cached(
            "SELECT COALESCE(SUM(costs.payload_bytes), 0)
             FROM blobs
             JOIN blob_meta AS meta
               ON meta.blob_id = blobs.id
             LEFT JOIN blob_payload_costs AS costs
               ON costs.blob_id = blobs.id
             JOIN source_fact_readiness AS visibility
               ON visibility.blob_id = blobs.id AND visibility.available = 1
             WHERE blobs.lang = ?1 AND blobs.generation = ?2
               AND meta.is_complete = 1",
        )?;
        for (lang, generation) in generations {
            let bytes =
                statement.query_row(params![lang, generation.0], |row| row.get::<_, usize>(0))?;
            total = total.saturating_add(bytes);
        }
        drop(statement);
        tx.commit()?;
        Ok(total)
    }

    fn current_blob_key_statement<'conn>(
        tx: &'conn Transaction<'_>,
    ) -> Result<rusqlite::Statement<'conn>> {
        Ok(tx.prepare(
            "SELECT 1 FROM blobs
             WHERE blob_oid = ?1 AND lang = ?2
               AND generation = COALESCE(
                 (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
               )
             LIMIT 1",
        )?)
    }

    fn current_blob_key_exists(
        statement: &mut rusqlite::Statement<'_>,
        oid: Oid,
        lang: &str,
    ) -> Result<bool> {
        Ok(statement
            .query_row(params![oid.to_string(), lang], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn missing_blobs(&self, oids: &[Oid], lang: &str) -> Result<Vec<Oid>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut stmt = Self::current_blob_key_statement(&tx)?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for oid in oids {
            if !seen.insert(*oid) {
                continue;
            }
            let exists = Self::current_blob_key_exists(&mut stmt, *oid, lang)?;
            if !exists {
                out.push(*oid);
            }
        }
        drop(stmt);
        tx.commit()?;
        Ok(out)
    }

    pub fn missing_blob_keys(&self, entries: &[(Oid, String)]) -> Result<Vec<(Oid, String)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut stmt = Self::current_blob_key_statement(&tx)?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for (oid, lang) in entries {
            if !seen.insert((*oid, lang.clone())) {
                continue;
            }
            let exists = Self::current_blob_key_exists(&mut stmt, *oid, lang)?;
            if !exists {
                out.push((*oid, lang.clone()));
            }
        }
        drop(stmt);
        tx.commit()?;
        Ok(out)
    }

    /// Verification form of the missing-key question: see
    /// [`Self::parsed_blob_keys`].
    pub fn missing_parsed_blob_keys(
        &self,
        entries: &[(Oid, String)],
    ) -> Result<Vec<(Oid, String)>> {
        let present = self.parsed_blob_keys(entries)?;
        let mut out = Vec::new();
        let mut seen = HashSet::default();
        for entry in entries {
            if seen.insert(entry.clone()) && !present.contains(entry) {
                out.push(entry.clone());
            }
        }
        Ok(out)
    }

    /// `semantic_ir_epoch` is the producer epoch of the adapter's parse-time
    /// lowerer, or `None` when the adapter has none. The caller holds the
    /// adapter; this method does not, so it cannot derive the epoch itself.
    #[doc(hidden)]
    pub fn missing_published_complete_analysis_blob_keys_at_generations(
        &self,
        requests: &[CompleteAnalysisBlobRequest],
        generations: &HashMap<String, GenerationId>,
        semantic_language: Language,
        semantic_ir_epoch: Option<&str>,
    ) -> Result<Vec<MissingCompleteAnalysisBlob>> {
        assert_ne!(semantic_language, Language::None);
        let mut storage_languages = HashSet::default();
        for request in requests {
            storage_languages.insert(request.storage_language());
            storage_languages.extend(
                request
                    .possible_additional_storage_languages()
                    .iter()
                    .map(String::as_str),
            );
        }
        for storage_language in &storage_languages {
            self.ensure_resolution_producer_epoch(storage_language, semantic_language)?;
            if let Some(epoch) = semantic_ir_epoch {
                self.ensure_semantic_ir_producer_epoch(storage_language, epoch)?;
            }
        }
        let mut conn = {
            let _scope = crate::profiling::scope("store.missing_analysis.open_reader");
            self.active_read_conn()?
        };
        let tx = conn.transaction()?;
        {
            let _scope = crate::profiling::scope("store.missing_analysis.check_generations");
            require_generation_map(
                &tx,
                generations,
                requests.iter().flat_map(|request| {
                    std::iter::once(request.storage_language()).chain(
                        request
                            .possible_additional_storage_languages()
                            .iter()
                            .map(String::as_str),
                    )
                }),
            )?;
            let expected_epoch = resolution::resolution_bundle_epoch(semantic_language);
            for storage_language in storage_languages {
                resolution::require_active_resolution_epoch(&tx, storage_language, expected_epoch)?;
            }
        }
        let missing =
            missing_published_complete_analysis_blob_keys_conn(&tx, requests, semantic_language)?;
        tx.commit()?;
        Ok(missing)
    }

    /// Return the verified parsed keys from `entries` using chunked set
    /// queries. This reads blob metadata only; it does not hydrate file state or
    /// source. Verification form: every fact-table count is re-proved per key.
    pub fn parsed_blob_keys(&self, entries: &[(Oid, String)]) -> Result<HashSet<(Oid, String)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let present = verified_parsed_blob_keys_conn(&tx, entries)?;
        tx.commit()?;
        Ok(present)
    }

    /// Read-path membership for a whole key set at the caller's generations.
    /// This is the query a workspace listing and a candidate retain run; it uses
    /// [`read_path_parsed_blob_condition`].
    #[doc(hidden)]
    pub fn parsed_blob_keys_at_generations(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashSet<(Oid, String)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(
            &tx,
            generations,
            entries.iter().map(|(_, lang)| lang.as_str()),
        )?;
        let present = parsed_blob_keys_conn(&tx, entries)?;
        tx.commit()?;
        Ok(present)
    }

    pub fn contains_blob(&self, oid: Oid, lang: &str) -> Result<bool> {
        let conn = self.read_conn()?;
        let exists = conn
            .query_row(
                "SELECT 1 FROM blobs
                 WHERE blob_oid = ?1 AND lang = ?2
                   AND generation = COALESCE(
                     (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
                   )
                 LIMIT 1",
                params![oid.to_string(), lang],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    /// Verification form: one blob's parse, with every fact-table count
    /// re-proved. Callers that only need to know whether a blob is readable at
    /// the active generation use
    /// [`Self::contains_parsed_blob_at_generation`] instead.
    pub fn contains_parsed_blob(&self, oid: Oid, lang: &str) -> Result<bool> {
        let conn = self.read_conn()?;
        contains_parsed_blob_conn(&conn, oid, lang, PARSED_BLOB_INTEGRITY_CONDITION.as_str())
    }

    /// Read-path membership for one blob at the caller's generation. Uses
    /// [`read_path_parsed_blob_condition`], the same predicate the batched
    /// hydration query uses.
    #[doc(hidden)]
    pub fn contains_parsed_blob_at_generation(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
    ) -> Result<bool> {
        #[cfg(any(test, feature = "test-support"))]
        self.parsed_blob_point_contains_queries
            .fetch_add(1, Ordering::SeqCst);
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let exists = contains_parsed_blob_conn(&tx, oid, lang, read_path_parsed_blob_condition())?;
        tx.commit()?;
        Ok(exists)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn load_structural_facts_rows(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        facts_version: i64,
    ) -> Result<Option<PersistedStructuralFacts>> {
        match self.load_structural_facts_rows_limited(
            oid,
            lang,
            generation,
            facts_version,
            usize::MAX,
            None,
        )? {
            StructuralFactRowsRead::Ready(facts) => Ok(Some(facts)),
            StructuralFactRowsRead::Unavailable => Ok(None),
            StructuralFactRowsRead::Exceeded { .. } | StructuralFactRowsRead::Cancelled => {
                unreachable!("unbounded uncancelled structural read cannot hit a request limit")
            }
        }
    }

    #[doc(hidden)]
    pub fn load_structural_facts_rows_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        facts_version: i64,
        max_work_items: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Result<StructuralFactRowsRead> {
        if facts_version <= 0 {
            return Err(StoreError::new(format!(
                "invalid structural facts version {facts_version}"
            )));
        }
        let fallback_cancellation = CancellationToken::default();
        let cancellation = cancellation.unwrap_or(&fallback_cancellation);
        if cancellation.is_cancelled() {
            return Ok(StructuralFactRowsRead::Cancelled);
        }
        let conn = self.read_conn()?;
        let result =
            resolution::with_resolution_read_progress_handler(&conn, cancellation, |conn| {
                let tx = conn.unchecked_transaction()?;
                require_current_generation(&tx, lang, generation)?;
                let sql = structural_fact_manifest_sql();
                let manifest = tx
                    .query_row(&sql, params![oid.to_string(), lang, facts_version], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, u32>(1)?,
                            row.get::<_, usize>(2)?,
                            row.get::<_, usize>(3)?,
                            row.get::<_, usize>(4)?,
                        ))
                    })
                    .optional()?;
                let Some((blob_id, source_bytes, node_count, role_count, occurrence_role_count)) =
                    manifest
                else {
                    tx.commit()?;
                    return Ok(StructuralFactRowsRead::Unavailable);
                };
                let work_items = node_count.saturating_add(role_count);
                if work_items > max_work_items {
                    return Ok(StructuralFactRowsRead::Exceeded {
                        minimum_work_items: work_items,
                    });
                }
                let (nodes_json, roles_json, occurrence_roles_json) = tx.query_row(
                    "SELECT nodes, roles, occurrence_roles
                     FROM structural_source_facts
                     WHERE blob_id = ?1",
                    [blob_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?;
                let recovered_regions = tx
                    .prepare_cached(STRUCTURAL_RECOVERED_REGIONS_SQL)?
                    .query_map(params![blob_id, callable_kind_codes_json()], |row| {
                        Ok(PersistedRecoveredRegion {
                            span: PersistedSpan {
                                start: row.get(0)?,
                                end: row.get(1)?,
                            },
                            inside_callable: row.get(2)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                tx.commit()?;
                let decode_error = |family: &str, err: serde_json::Error| {
                    StoreError::new(format!("invalid persisted structural {family}: {err}"))
                };
                let nodes = decode_structural_nodes(&nodes_json)
                    .map_err(|err| decode_error("nodes", err))?;
                let roles = decode_structural_roles(&roles_json)
                    .map_err(|err| decode_error("roles", err))?;
                let occurrence_roles = decode_structural_occurrence_roles(&occurrence_roles_json)
                    .map_err(|err| decode_error("occurrence roles", err))?;
                if nodes.len() != node_count
                    || roles.len() != role_count
                    || occurrence_roles.len() != occurrence_role_count
                {
                    return Ok(StructuralFactRowsRead::Unavailable);
                }
                Ok(StructuralFactRowsRead::Ready(PersistedStructuralFacts {
                    source_bytes,
                    nodes,
                    roles,
                    occurrence_roles,
                    recovered_regions,
                }))
            });
        if cancellation.is_cancelled() {
            return Ok(StructuralFactRowsRead::Cancelled);
        }
        result
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reset_parsed_blob_point_contains_queries_for_test(&self) {
        self.parsed_blob_point_contains_queries
            .store(0, Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn parsed_blob_point_contains_queries_for_test(&self) -> usize {
        self.parsed_blob_point_contains_queries
            .load(Ordering::SeqCst)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn mark_parsed_blob_incomplete_for_test(&self, oid: Oid, lang: &str) {
        let lang = lang.to_string();
        self.conn.execute(move |conn| {
            conn.execute(
                "UPDATE blob_meta SET is_complete = 0 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                params![oid.to_string(), lang],
            )
            .expect("mark parsed blob incomplete")
        });
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn parsed_blob_transaction_starts_for_test(&self) -> usize {
        self.parsed_blob_transaction_starts.load(Ordering::SeqCst)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reset_parsed_blob_transaction_starts_for_test(&self) {
        self.parsed_blob_transaction_starts
            .store(0, Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn current_generation(&self, lang: &str) -> Result<GenerationId> {
        let conn = self.read_conn()?;
        current_generation_conn(&conn, lang)
    }

    #[doc(hidden)]
    pub fn persist_prepared_blobs(
        &self,
        prepared: Vec<PreparedParsedBlob>,
        limits: PersistBatchTargets,
    ) -> (Vec<PersistBlobOutcome>, PersistBatchStats) {
        if let Err(error) = self.ensure_prepared_resolution_epochs(&prepared) {
            let failed_blobs = prepared.len();
            let failed_fragments = prepared
                .iter()
                .map(PreparedParsedBlob::fragment_count)
                .sum();
            return (
                prepared
                    .into_iter()
                    .map(|prepared| PersistBlobOutcome {
                        prepared,
                        error: Some(error.clone()),
                    })
                    .collect(),
                PersistBatchStats {
                    failed_blobs,
                    failed_fragments,
                    ..PersistBatchStats::default()
                },
            );
        }
        self.persist_prepared_blobs_with_cancellation(
            prepared,
            &CancellationToken::default(),
            limits,
        )
    }

    #[doc(hidden)]
    pub fn persist_prepared_blobs_with_cancellation(
        &self,
        prepared: Vec<PreparedParsedBlob>,
        cancellation: &CancellationToken,
        limits: PersistBatchTargets,
    ) -> (Vec<PersistBlobOutcome>, PersistBatchStats) {
        let counters = self.prepared_write_counters();
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| {
            PreparedPersistenceWriter::new(conn, counters, cancellation)
                .persist_prepared_blobs(prepared, limits)
        })
    }

    #[doc(hidden)]
    pub fn ensure_prepared_resolution_epochs(&self, prepared: &[PreparedParsedBlob]) -> Result<()> {
        let mut languages = HashMap::default();
        let mut semantic_ir_epochs = HashMap::default();
        for root in prepared {
            let mut fragments = Vec::with_capacity(root.fragment_count());
            root.append_fragments(&mut fragments);
            for fragment in fragments {
                let semantic_language = fragment.resolution.semantic_language();
                if let Some(existing) = languages.insert(fragment.lang(), semantic_language)
                    && existing != semantic_language
                {
                    return Err(StoreError::new(format!(
                        "conflicting semantic languages for prepared storage language {}",
                        fragment.lang()
                    )));
                }
                if let Some(semantic_ir) = fragment.semantic_ir.as_ref() {
                    // One lowerer serves every blob of a storage language, so
                    // its producer epoch cannot differ within one batch.
                    let previous =
                        semantic_ir_epochs.insert(fragment.lang(), semantic_ir.producer_epoch());
                    assert!(previous.is_none_or(|epoch| epoch == semantic_ir.producer_epoch()));
                }
            }
        }
        for (storage_language, semantic_language) in languages {
            self.ensure_resolution_producer_epoch(storage_language, semantic_language)?;
        }
        for (storage_language, producer_epoch) in semantic_ir_epochs {
            self.ensure_semantic_ir_producer_epoch(storage_language, producer_epoch)?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn repair_prepared_blob(&self, prepared: PreparedParsedBlob) -> Result<()> {
        self.conn
            .repair_prepared_blob(prepared, self.prepared_write_counters())
    }

    fn prepared_write_counters(&self) -> PreparedWriteCounters {
        PreparedWriteCounters {
            #[cfg(any(test, feature = "test-support"))]
            transaction_starts: Arc::clone(&self.parsed_blob_transaction_starts),
            #[cfg(any(test, feature = "test-support"))]
            generation_lookups: Arc::clone(&self.prepared_generation_lookup_queries),
            #[cfg(any(test, feature = "test-support"))]
            replacement_lookups: Arc::clone(&self.replacement_cost_lookup_queries),
            #[cfg(any(test, feature = "test-support"))]
            replacement_fallbacks: Arc::clone(&self.replacement_cost_fallback_queries),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn stored_blob_cascade_costs(
        &self,
        conn: &Connection,
        prepared: &[PreparedParsedBlob],
    ) -> Result<Vec<StoredCascadeCost>> {
        let prepared = prepared.iter().collect::<Vec<_>>();
        let mut restored_roots = PersistedMutationCost::default();
        stored_blob_cascade_costs_conn(
            conn,
            &prepared,
            || {
                #[cfg(any(test, feature = "test-support"))]
                self.replacement_cost_lookup_queries
                    .fetch_add(1, Ordering::SeqCst);
            },
            &mut restored_roots,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reset_replacement_cost_lookup_queries_for_test(&self) {
        self.replacement_cost_lookup_queries
            .store(0, Ordering::SeqCst);
        self.replacement_cost_fallback_queries
            .store(0, Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn replacement_cost_lookup_queries_for_test(&self) -> usize {
        self.replacement_cost_lookup_queries.load(Ordering::SeqCst)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn replacement_cost_fallback_queries_for_test(&self) -> usize {
        self.replacement_cost_fallback_queries
            .load(Ordering::SeqCst)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reset_prepared_generation_lookup_queries_for_test(&self) {
        self.prepared_generation_lookup_queries
            .store(0, Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn prepared_generation_lookup_queries_for_test(&self) -> usize {
        self.prepared_generation_lookup_queries
            .load(Ordering::SeqCst)
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn hydrate_file_state<A: StoreLanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        file: &ProjectFile,
    ) -> Result<Option<FileState>> {
        let source = file.read_to_string().unwrap_or_default();
        self.hydrate_file_state_with_source(
            oid,
            lang,
            self.current_generation(lang)?,
            adapter,
            file,
            &source,
        )
    }

    pub fn hydrate_file_state_with_source<A: StoreLanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        source: &str,
    ) -> Result<Option<FileState>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = hydrate_file_state_conn(&tx, oid, lang, adapter, file, source)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read only the persisted rows required to render a file summary. This
    /// does not replace full `FileState` hydration, which remains responsible
    /// for validating and serving the complete analyzer graph.
    pub fn summary_file_projection<A: StoreLanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
        source: &str,
    ) -> Result<Option<SummaryFileProjection>> {
        let _scope = crate::profiling::scope("AnalyzerStore::summary_file_projection");
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = summary_file_projection_conn(&tx, oid, lang, adapter, file, source)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read only the type-alias units for one persisted file. This avoids
    /// hydrating its source and unrelated analyzer facts for an alias check.
    #[doc(hidden)]
    pub fn type_aliases_for_file<A: StoreLanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
    ) -> Result<Option<Vec<CodeUnit>>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = type_aliases_for_file_conn(&tx, oid, lang, adapter, file)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read all persisted declaration ranges for one file. This compact
    /// projection is used by batched owner lookups and does not hydrate the
    /// file's source or unrelated analyzer facts.
    #[doc(hidden)]
    pub fn enclosing_declarations_for_file<A: StoreLanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        file: &ProjectFile,
    ) -> Result<Option<Vec<(CodeUnit, Range)>>> {
        let _scope = crate::profiling::scope("AnalyzerStore::enclosing_declarations_for_file");
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = enclosing_declarations_for_file_conn(&tx, oid, lang, adapter, file)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read every metadata alternative for one unit without hydrating or
    /// reparsing its file. Unlike the bounded API, this preserves the existing
    /// unbounded Vec contract and does not silently apply a byte cutoff.
    #[doc(hidden)]
    pub fn signature_metadata_for_unit(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
    ) -> Result<Vec<SignatureMetadata>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        require_declaration_visibility_available(&tx, &oid.to_string(), lang)?;
        let mut statement = tx.prepare_cached(signature_metadata_for_unit_sql())?;
        let rows = statement
            .query_map(
                params![
                    oid.to_string(),
                    lang,
                    unit.fq_name(),
                    code_unit_kind_to_i64(unit.kind()),
                    unit.short_name(),
                    unit.signature(),
                    bool_to_i64(unit.is_synthetic()),
                    -1i64,
                ],
                |row| signature_metadata_projection_from_row(row, 1),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        tx.commit()?;
        Ok(rows)
    }

    /// Run one bounded unit query under a generation-checked read transaction.
    fn with_current_generation_read_transaction<T>(
        &self,
        lang: &str,
        generation: GenerationId,
        read: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = read(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    /// Read at most `limit` signature-metadata rows for one persisted code
    /// unit without hydrating the owning file state.
    ///
    /// The target identity deliberately includes every stable `CodeUnit`
    /// discriminator. Callers supply a one-row lookahead in `limit`; a batch
    /// that fills the limit is therefore incomplete and must not be treated as
    /// authoritative.
    #[doc(hidden)]
    pub fn signature_metadata_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<SignatureMetadata>> {
        self.with_current_generation_read_transaction(lang, generation, |tx| {
            signature_metadata_for_unit_limited_conn(tx, oid, lang, unit, limit)
        })
    }

    /// Read at most `limit` signature labels for one persisted code unit
    /// without hydrating the owning file state.
    #[doc(hidden)]
    pub fn signatures_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        self.with_current_generation_read_transaction(lang, generation, |tx| {
            signatures_for_unit_limited_conn(tx, oid, lang, unit, limit)
        })
    }

    /// Read at most `limit` Ruby dispatch-mode rows for one persisted code
    /// unit without hydrating the owning file state.
    #[doc(hidden)]
    pub fn ruby_method_dispatch_modes_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<RubyMethodDispatchMode>> {
        self.with_current_generation_read_transaction(lang, generation, |tx| {
            ruby_method_dispatch_modes_for_unit_limited_conn(tx, oid, lang, unit, limit)
        })
    }

    /// Read at most `limit` direct declaration children for one persisted
    /// code unit without hydrating the owning file state.
    #[doc(hidden)]
    pub fn direct_children_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<HydratedCandidateRow>> {
        self.with_current_generation_read_transaction(lang, generation, |tx| {
            direct_children_for_unit_limited_conn(tx, oid, lang, unit, limit)
        })
    }

    #[doc(hidden)]
    pub fn raw_supertypes_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        self.with_current_generation_read_transaction(lang, generation, |tx| {
            raw_supertypes_for_unit_limited_conn(tx, oid, lang, unit, limit)
        })
    }

    #[doc(hidden)]
    pub fn supertype_lookup_paths_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        self.with_current_generation_read_transaction(lang, generation, |tx| {
            supertype_lookup_paths_for_unit_limited_conn(tx, oid, lang, unit, limit)
        })
    }

    /// Read at most `limit` declaration ranges for one persisted code unit
    /// without hydrating the owning file state.
    #[doc(hidden)]
    pub fn ranges_for_unit_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        unit: &CodeUnit,
        limit: usize,
    ) -> Result<LimitedQueryRows<Range>> {
        self.with_current_generation_read_transaction(lang, generation, |tx| {
            ranges_for_unit_limited_conn(tx, oid, lang, unit, limit)
        })
    }

    /// Hydrate many live file states from persisted blob rows using chunked
    /// `IN` scans over the requested OIDs. `source_by_file` controls whether
    /// source-dependent hydrate hooks and file-scope range synthesis run for a
    /// given file. Whole-workspace graph passes pass an empty map so they avoid
    /// all source reads and receive structural rows only.
    pub fn hydrate_file_states<A: StoreLanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid)],
        lang: &str,
        adapter: &A,
        source_by_file: &HashMap<ProjectFile, String>,
    ) -> Result<HashMap<ProjectFile, FileState>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let result = hydrate_file_states_conn(&tx, entries, lang, adapter, source_by_file)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn hydrate_file_states_by_key<A: StoreLanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
        source_by_file: &HashMap<ProjectFile, String>,
    ) -> Result<HashMap<ProjectFile, FileState>> {
        let mut out = HashMap::default();
        let mut by_lang: HashMap<String, Vec<(ProjectFile, Oid)>> = HashMap::default();
        for (file, oid, lang) in entries {
            by_lang
                .entry(lang.clone())
                .or_default()
                .push((file.clone(), *oid));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(
            &tx,
            generations,
            entries.iter().map(|(_, _, lang)| lang.as_str()),
        )?;
        for (lang, lang_entries) in by_lang {
            out.extend(hydrate_file_states_conn(
                &tx,
                &lang_entries,
                &lang,
                adapter,
                source_by_file,
            )?);
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn hydrate_import_infos<A: StoreLanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid)],
        lang: &str,
        _adapter: &A,
    ) -> Result<HashMap<ProjectFile, Vec<ImportInfo>>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let oids = unique_oid_strings(entries);
        let imports_by_oid = read_import_infos_bulk(&tx, lang, &oids)?;
        let mut out = HashMap::default();
        for (file, oid) in entries {
            if let Some(imports) = imports_by_oid.get(&oid.to_string()) {
                out.insert(file.clone(), imports.clone());
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn hydrate_import_infos_by_key<A: StoreLanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
    ) -> Result<HashMap<ProjectFile, Vec<ImportInfo>>> {
        Ok(self
            .hydrate_import_facts_by_key(entries, generations, adapter)?
            .into_iter()
            .map(|(file, facts)| (file, facts.imports))
            .collect())
    }

    #[doc(hidden)]
    pub fn hydrate_import_facts_by_key<A: StoreLanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
    ) -> Result<HashMap<ProjectFile, ImportFacts>> {
        self.hydrate_import_facts_by_key_with_metadata(
            entries,
            generations,
            adapter,
            read_import_metadata_bulk,
        )
    }

    /// Hydrate imports only from a blob whose canonical source publication is
    /// complete. Unlike the legacy reader above, a missing row is an
    /// unavailable answer, not an import-free file.
    #[doc(hidden)]
    pub fn hydrate_canonical_import_facts_by_key<A: StoreLanguageAdapter>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
    ) -> Result<HashMap<ProjectFile, ImportFacts>> {
        assert!(
            adapter.produces_canonical_source_facts(),
            "checked import hydration requires canonical source facts"
        );
        self.hydrate_import_facts_by_key_with_metadata(
            entries,
            generations,
            adapter,
            read_canonical_import_metadata_bulk,
        )
    }

    fn hydrate_import_facts_by_key_with_metadata<A, F>(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
        read_metadata: F,
    ) -> Result<HashMap<ProjectFile, ImportFacts>>
    where
        A: StoreLanguageAdapter,
        F: Fn(&Connection, &str, &[String]) -> Result<HashMap<String, (String, bool)>>,
    {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(
            &tx,
            generations,
            entries.iter().map(|(_, _, lang)| lang.as_str()),
        )?;
        let mut out = HashMap::default();
        let mut by_lang: HashMap<String, Vec<(ProjectFile, Oid)>> = HashMap::default();
        for (file, oid, lang) in entries {
            by_lang
                .entry(lang.clone())
                .or_default()
                .push((file.clone(), *oid));
        }
        for (lang, lang_entries) in by_lang {
            let oids = unique_oid_strings(&lang_entries);
            let metadata_by_oid = read_metadata(&tx, &lang, &oids)?;
            let imports_by_oid = read_import_infos_bulk(&tx, &lang, &oids)?;
            for (file, oid) in lang_entries {
                let oid = oid.to_string();
                let Some((package_name, contains_tests)) = metadata_by_oid.get(&oid) else {
                    continue;
                };
                out.insert(
                    file.clone(),
                    ImportFacts {
                        package_name: adapter.hydrate_content_qualifier(package_name, &file)?,
                        imports: imports_by_oid.get(&oid).cloned().unwrap_or_default(),
                        contains_tests: adapter.hydrate_contains_tests(*contains_tests, &file, ""),
                    },
                );
            }
        }
        tx.commit()?;
        Ok(out)
    }

    /// Return current candidate blobs that may reference one of a small set of
    /// declaration names through a non-static import or a lexical type use.
    ///
    /// This is deliberately a prefilter. Import paths are sought by any
    /// matching structured segment, then Java's resolver verifies the complete
    /// path and precedence after hydrating the small surviving set. False
    /// positives are harmless; a false negative would change relevance.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn reverse_reference_candidate_paths(
        &self,
        workspace_snapshots: &WorkspaceSnapshots,
        lang: &str,
        generation: GenerationId,
        explicit_import_segments: &HashSet<String>,
        wildcard_import_segments: &HashSet<String>,
        type_identifiers: &HashSet<String>,
        cancellation: &CancellationToken,
    ) -> Result<HashSet<String>> {
        if explicit_import_segments.is_empty()
            && wildcard_import_segments.is_empty()
            && type_identifiers.is_empty()
        {
            return Ok(HashSet::default());
        }

        let mut conn = self.active_read_conn()?;
        self.select_workspace_snapshots(&mut conn, workspace_snapshots)?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        sync_reverse_reference_lookup_keys(
            &tx,
            explicit_import_segments,
            wildcard_import_segments,
            type_identifiers,
        )?;

        let mut matches = HashSet::default();
        if !explicit_import_segments.is_empty() || !wildcard_import_segments.is_empty() {
            let _scope =
                crate::profiling::scope("AnalyzerStore::reverse_reference.import_candidates");
            let mut statement = tx.prepare_cached(REVERSE_IMPORT_CANDIDATE_BLOBS_SQL)?;
            let mut rows = statement.query([lang])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(HashSet::default());
                }
                matches.insert(row.get::<_, String>(0)?);
            }
        }
        if !type_identifiers.is_empty() {
            let _scope =
                crate::profiling::scope("AnalyzerStore::reverse_reference.type_candidates");
            let mut statement = tx.prepare_cached(REVERSE_TYPE_CANDIDATE_BLOBS_SQL)?;
            let mut rows = statement.query([lang])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(HashSet::default());
                }
                matches.insert(row.get::<_, String>(0)?);
            }
        }
        tx.commit()?;
        Ok(matches)
    }

    /// Return live workspace paths that contain one of the requested parsed
    /// identifiers, without requiring the caller to enumerate the workspace
    /// or construct a temporary active-blob relation first.
    #[doc(hidden)]
    pub fn reverse_identifier_candidate_paths(
        &self,
        workspace_snapshots: &WorkspaceSnapshots,
        lang: &str,
        generation: GenerationId,
        identifiers: &HashSet<String>,
        cancellation: &CancellationToken,
    ) -> Result<HashSet<PathBuf>> {
        if identifiers.is_empty() {
            return Ok(HashSet::default());
        }

        let mut conn = self.active_read_conn()?;
        self.select_workspace_snapshots(&mut conn, workspace_snapshots)?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        sync_reverse_reference_lookup_keys(
            &tx,
            &HashSet::default(),
            &HashSet::default(),
            identifiers,
        )?;
        let mut statement = tx.prepare_cached(REVERSE_IDENTIFIER_CANDIDATE_PATHS_SQL)?;
        let mut rows = statement.query([lang])?;
        let mut paths = HashSet::default();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(HashSet::default());
            }
            paths.insert(PathBuf::from(row.get::<_, String>(0)?));
        }
        drop(rows);
        drop(statement);
        tx.commit()?;
        Ok(paths)
    }

    #[doc(hidden)]
    pub fn hydrate_type_identifiers_by_key(
        &self,
        entries: &[(ProjectFile, Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashMap<ProjectFile, HashSet<String>>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(
            &tx,
            generations,
            entries.iter().map(|(_, _, lang)| lang.as_str()),
        )?;
        let mut by_lang: HashMap<String, Vec<(ProjectFile, Oid)>> = HashMap::default();
        for (file, oid, lang) in entries {
            by_lang
                .entry(lang.clone())
                .or_default()
                .push((file.clone(), *oid));
        }
        let mut out = HashMap::default();
        for (lang, lang_entries) in by_lang {
            let oids = unique_oid_strings(&lang_entries);
            let meta_by_oid = read_blob_meta_bulk(&tx, &lang, &oids)?;
            for (file, oid) in lang_entries {
                let Some(meta) = meta_by_oid.get(&oid.to_string()) else {
                    continue;
                };
                out.insert(file, meta.type_identifiers.clone());
            }
        }
        tx.commit()?;
        Ok(out)
    }

    #[doc(hidden)]
    pub fn content_package(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
    ) -> Result<Option<String>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let result = read_import_metadata_bulk(&tx, lang, &[oid.to_string()])?
            .remove(&oid.to_string())
            .map(|(package_name, _)| package_name);
        tx.commit()?;
        Ok(result)
    }

    #[doc(hidden)]
    pub fn content_package_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        if limit == 0 {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let sql = format!(
            "SELECT length(CAST(meta.content_package AS BLOB)),
                    CASE
                        WHEN length(CAST(meta.content_package AS BLOB))
                               <= {MAX_LIMITED_QUERY_ROW_BYTES}
                        THEN meta.content_package
                        ELSE NULL
                    END
             FROM blob_meta AS meta
             WHERE meta.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let mut statement = tx.prepare_cached(&sql)?;
        let mut query = statement.query(params![oid.to_string(), lang])?;
        let result = if let Some(row) = query.next()? {
            let mut bytes = LimitedQueryByteBudget::default();
            if !bytes.admit_sqlite_bytes(row.get::<_, i64>(0)?)? {
                LimitedQueryRows::incomplete(Vec::new(), 1)
            } else if let Some(content_package) = row.get::<_, Option<String>>(1)? {
                LimitedQueryRows::complete(vec![content_package], 1)
            } else {
                LimitedQueryRows::incomplete(Vec::new(), 1)
            }
        } else {
            LimitedQueryRows::incomplete(Vec::new(), 0)
        };
        drop(query);
        drop(statement);
        tx.commit()?;
        Ok(result)
    }

    /// The namespace of `oid`'s first top-level declaration in source order, as
    /// the persisted half of `file_namespace_hint_limited`'s fallback.
    ///
    /// `top_level_ordinal` is the index a unit had in the parsed file's
    /// top-level vector, so restricting the scan to non-null ordinals and
    /// ordering by them reproduces the source order the hydrated branch reads
    /// off `FileState::top_level_declarations`. Ordering by `unit_key` instead
    /// answered from an unrelated key order and admitted nested members, which
    /// made a two-namespace file answer differently depending on whether its
    /// state was hydrated (#1726).
    #[doc(hidden)]
    pub fn first_declaration_content_qualifier_for_key_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        limit: usize,
    ) -> Result<LimitedQueryRows<String>> {
        if limit == 0 {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT length(CAST(units.content_qualifier AS BLOB)),
                    CASE
                        WHEN length(CAST(units.content_qualifier AS BLOB))
                               <= {MAX_LIMITED_QUERY_ROW_BYTES}
                        THEN units.content_qualifier
                        ELSE NULL
                    END
             FROM code_units AS units
             JOIN blob_meta AS meta
               ON meta.blob_id = units.blob_id
             WHERE units.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
               AND units.top_level_ordinal IS NOT NULL
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY units.top_level_ordinal
             LIMIT ?3"
        );
        let mut statement = tx.prepare_cached(&sql)?;
        let mut query = statement.query(params![oid.to_string(), lang, sql_limit])?;
        let mut bytes = LimitedQueryByteBudget::default();
        let mut inspected = 0usize;
        let mut result = None;
        while let Some(row) = query.next()? {
            inspected = inspected.saturating_add(1);
            if !bytes.admit_sqlite_bytes(row.get::<_, i64>(0)?)? {
                result = Some(LimitedQueryRows::incomplete(Vec::new(), inspected));
                break;
            }
            let Some(content_qualifier) = row.get::<_, Option<String>>(1)? else {
                result = Some(LimitedQueryRows::incomplete(Vec::new(), inspected));
                break;
            };
            if !content_qualifier.is_empty() {
                result = Some(LimitedQueryRows::complete(
                    vec![content_qualifier],
                    inspected,
                ));
                break;
            }
        }
        let result = result.unwrap_or_else(|| {
            if inspected == limit {
                LimitedQueryRows::incomplete(Vec::new(), inspected)
            } else {
                LimitedQueryRows::complete(Vec::new(), inspected)
            }
        });
        drop(query);
        drop(statement);
        tx.commit()?;
        Ok(result)
    }

    #[doc(hidden)]
    pub fn import_infos_for_key_limited(
        &self,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        limit: usize,
    ) -> Result<LimitedQueryRows<ImportInfo>> {
        if limit == 0 {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let oid = oid.to_string();
        let meta_sql = format!(
            "SELECT meta.import_statement_count
             FROM blob_meta AS meta
             WHERE meta.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let Some(import_count) = tx
            .query_row(&meta_sql, params![&oid, lang], |row| row.get::<_, i64>(0))
            .optional()?
        else {
            tx.commit()?;
            return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
        };
        let import_count = i64_to_usize(import_count)?;
        let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        // The byte budget prices the row's own text. The child tables hold
        // pieces of the same declaration, so budgeting `statement` bounds them
        // within a small constant factor, and their integer columns are fixed
        // width. Only `statement` can be arbitrarily large, and only because
        // the source declaration can be.
        let sql = format!(
            "SELECT length(CAST(statement AS BLOB))
                      + COALESCE(length(CAST(identifier AS BLOB)), 0)
                      + COALESCE(length(CAST(alias AS BLOB)), 0),
                    {IMPORT_STATEMENT_COLUMNS}
             FROM source_import_statements
             WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
             ORDER BY ordinal
             LIMIT ?3"
        );
        let mut statement = tx.prepare_cached(&sql)?;
        let mut query = statement.query(params![&oid, lang, sql_limit])?;
        let mut rows = Vec::new();
        let mut inspected = 0usize;
        let mut bytes = LimitedQueryByteBudget::default();
        let mut byte_complete = true;
        while let Some(row) = query.next()? {
            inspected = inspected.saturating_add(1);
            let byte_len = row.get::<_, i64>(0)?;
            if !bytes.admit_sqlite_bytes(byte_len)? {
                byte_complete = false;
                break;
            }
            rows.push(import_info_from_statement_row(row, 1)?);
        }
        drop(query);
        drop(statement);
        // The admitted prefix is dense from ordinal zero, so the shared child
        // reader indexes it the same way the unbounded paths do.
        let mut by_oid = HashMap::default();
        by_oid.insert(oid.clone(), std::mem::take(&mut rows));
        assert!(
            attach_import_path_children(&tx, lang, std::slice::from_ref(&oid), &mut by_oid, None,)?,
            "unbounded import-path child validation cannot stop"
        );
        let rows = by_oid.remove(&oid).unwrap_or_default();
        tx.commit()?;
        if !byte_complete || inspected == limit || import_count != inspected {
            Ok(LimitedQueryRows::incomplete(rows, inspected))
        } else {
            Ok(LimitedQueryRows::complete(rows, inspected))
        }
    }

    fn declaration_candidate_rows_by_predicate<'a>(
        &self,
        langs: impl IntoIterator<Item = &'a str>,
        predicate: &str,
        values: &[&dyn ToSql],
    ) -> Result<Vec<HydratedCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let sql = declaration_candidate_sql(predicate);
        let rows = candidate_rows_for_languages(&tx, langs, &sql, values)?;
        tx.commit()?;
        Ok(rows)
    }

    fn declaration_candidate_rows_for_langs_by_predicate(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        predicate: &str,
        values: &[&dyn ToSql],
    ) -> Result<Vec<HydratedCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = declaration_candidate_sql(predicate);
        let rows =
            candidate_rows_for_languages(&tx, langs.iter().map(String::as_str), &sql, values)?;
        tx.commit()?;
        Ok(rows)
    }

    pub fn declaration_candidate_rows_by_short_name(
        &self,
        lang: &str,
        short_name: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_by_predicate(
            std::iter::once(lang),
            "units.lang = ?1 AND units.short_name = ?2",
            &[&short_name],
        )
    }

    pub fn declaration_candidate_rows_by_short_name_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        short_name: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_for_langs_by_predicate(
            langs,
            generations,
            "units.lang = ?1 AND units.short_name = ?2",
            &[&short_name],
        )
    }

    /// `complete` is false when the caller's deadline expired mid-seek. The
    /// rows returned with it are a prefix, not an answer: a caller must not
    /// present them as this name's candidate set, and must not memoize them.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn declaration_order_candidate_rows_by_short_name_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        short_name: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<DefinitionOrderCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = definition_order_candidate_sql(
            "live_definition_exact_names",
            "names.lang = ?1 AND names.short_name = ?2 AND names.source_kind <> 'path'",
            "units.in_declarations = 1",
        );
        let rows = definition_order_candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &[sql.as_str()],
            &[&short_name],
            cancellation,
        )?;
        tx.commit()?;
        Ok(rows)
    }

    /// Cross the candidate identity boundary for the rows that survived
    /// header-only name and liveness filtering. Generation validation is
    /// repeated in this transaction so a delayed read cannot combine headers
    /// from one publication with segments from another.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn hydrate_definition_order_candidate_rows(
        &self,
        rows: Vec<DefinitionOrderCandidateRow>,
        generations: &HashMap<String, GenerationId>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<HydratedDefinitionOrderCandidateRow>> {
        let inspected = rows.len();
        let mut langs = rows
            .iter()
            .map(|row| row.candidate.lang.as_str())
            .collect::<Vec<_>>();
        langs.sort_unstable();
        langs.dedup();
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs)?;
        let hydrated = hydrate_candidate_rows(&tx, rows, cancellation)?;
        tx.commit()?;
        Ok(match hydrated {
            Some(rows) => LimitedQueryRows::complete(rows, inspected),
            None => LimitedQueryRows::incomplete(Vec::new(), inspected),
        })
    }

    /// Invert rendered definition requests into bounded `(prefix, tail)`
    /// alternatives, seek their authoritative component relations, then
    /// hydrate only the physical identities that matched. Point lookup is the
    /// arity-one form of this batch contract.
    #[doc(hidden)]
    pub fn rendered_definition_order_candidate_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        workspace_snapshots: &WorkspaceSnapshots,
        requests: &[RenderedDefinitionRequest],
        include_definition_lookup_units: bool,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RenderedDefinitionCandidateOutcome> {
        if requests.is_empty() {
            return Ok(RenderedDefinitionCandidateOutcome::Complete(Vec::new()));
        }
        let components = requests
            .iter()
            .enumerate()
            .flat_map(|(request_index, request)| {
                rendered_definition_components(request_index, request)
            })
            .collect::<Vec<_>>();
        let membership = if include_definition_lookup_units {
            "(units.in_declarations = 1 OR units.in_definition_lookup = 1)"
        } else {
            "units.in_declarations = 1"
        };
        let _probe_scope = crate::profiling::scope_with(|| {
            format!(
                "store.rendered_definition_candidates[{}][{} components]",
                langs.join(","),
                components.len()
            )
        });
        let mut conn = {
            let _conn_scope = crate::profiling::scope("store.rdc.read_conn");
            self.read_conn_for_workspace(workspace_snapshots)?
        };
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let mut rows = Vec::new();

        // Arity one is semantically the same operation as the batch below,
        // but scalar parameters avoid constructing and scanning a JSON virtual
        // request table for the latency-sensitive point path.
        if requests.len() == 1 {
            for lang in langs {
                let generation = generations
                    .get(lang)
                    .expect("validated generation map contains every requested language")
                    .0;
                for tail_match in [
                    RenderedTailMatch::Exact,
                    RenderedTailMatch::NormalizedStored,
                    RenderedTailMatch::NormalizedExact,
                ] {
                    let normalized = tail_match != RenderedTailMatch::Exact;
                    for anchored in [false, true] {
                        let matching_components = components.iter().filter(|(_, component)| {
                            component.normalized == normalized
                                && component.anchored == anchored
                                && !component.tail.is_empty()
                                && (tail_match != RenderedTailMatch::NormalizedExact
                                    || component.normalized_exact_fallback)
                        });
                        let mut matching_components = matching_components.peekable();
                        if matching_components.peek().is_none() {
                            continue;
                        }
                        let sql = point_component_definition_candidate_sql(
                            anchored, tail_match, membership,
                        );
                        let mut statement = tx.prepare_cached(sql)?;
                        for (_, component) in matching_components {
                            let _point_scope = crate::profiling::scope_with(|| {
                                format!(
                                    "store.rdc.point[{lang}][{tail_match:?}][anchored={anchored}][{}#{}]",
                                    component.prefix, component.tail
                                )
                            });
                            let complete = if anchored {
                                collect_rendered_definition_candidate_rows(
                                    &mut statement,
                                    params![lang, generation, component.prefix, component.tail],
                                    &mut rows,
                                    cancellation,
                                )?
                            } else {
                                collect_rendered_definition_candidate_rows(
                                    &mut statement,
                                    params![lang, generation, component.tail],
                                    &mut rows,
                                    cancellation,
                                )?
                            };
                            if !complete {
                                return Ok(RenderedDefinitionCandidateOutcome::Cancelled);
                            }
                        }
                    }
                }
                let mut statement =
                    tx.prepare_cached(point_anchor_only_definition_candidate_sql(membership))?;
                for (_, component) in components.iter().filter(|(_, component)| {
                    component.anchored && !component.normalized && component.tail.is_empty()
                }) {
                    if !collect_rendered_definition_candidate_rows(
                        &mut statement,
                        params![lang, generation, component.prefix],
                        &mut rows,
                        cancellation,
                    )? {
                        return Ok(RenderedDefinitionCandidateOutcome::Cancelled);
                    }
                }
            }
        } else {
            let request_rows = components
                .iter()
                .map(|(request_index, component)| {
                    (
                        *request_index,
                        component.prefix.as_str(),
                        component.tail.as_str(),
                        i64::from(component.normalized),
                        i64::from(component.anchored),
                    )
                })
                .collect::<Vec<_>>();
            let request_json = serde_json::to_string(&request_rows).map_err(|error| {
                StoreError::new(format!(
                    "serializing definition request components: {error}"
                ))
            })?;
            for lang in langs {
                let generation = generations
                    .get(lang)
                    .expect("validated generation map contains every requested language")
                    .0;
                for anchored in [false, true] {
                    for tail_match in [
                        RenderedTailMatch::Exact,
                        RenderedTailMatch::NormalizedStored,
                        RenderedTailMatch::NormalizedExact,
                    ] {
                        let sql = batch_component_definition_candidate_sql(
                            anchored, tail_match, membership,
                        );
                        let mut statement = tx.prepare_cached(&sql)?;
                        if !collect_rendered_definition_candidate_rows(
                            &mut statement,
                            params![request_json, lang, generation],
                            &mut rows,
                            cancellation,
                        )? {
                            return Ok(RenderedDefinitionCandidateOutcome::Cancelled);
                        }
                    }
                }
                let sql = batch_anchor_only_definition_candidate_sql(membership);
                let mut statement = tx.prepare_cached(&sql)?;
                if !collect_rendered_definition_candidate_rows(
                    &mut statement,
                    params![request_json, lang, generation],
                    &mut rows,
                    cancellation,
                )? {
                    return Ok(RenderedDefinitionCandidateOutcome::Cancelled);
                }
            }
        }

        // Exact and normalized component alternatives can reach the same
        // physical identity. Preserve genuinely different mount prefixes but
        // hydrate each request/identity/prefix tuple only once.
        let mut seen = HashSet::default();
        rows.retain(|(candidate, (request_index, _, mounted_prefix))| {
            seen.insert((
                *request_index,
                candidate.blob_oid,
                candidate.lang.clone(),
                candidate.unit_key,
                mounted_prefix.clone(),
            ))
        });
        let Some(rows) = hydrate_candidate_rows(&tx, rows, cancellation)? else {
            tx.commit()?;
            return Ok(RenderedDefinitionCandidateOutcome::Cancelled);
        };
        let mut grouped = std::iter::repeat_with(Vec::new)
            .take(requests.len())
            .collect::<Vec<_>>();
        for (candidate, (request_index, first_start_byte, mounted_prefix)) in rows {
            assert!(request_index < grouped.len());
            grouped[request_index].push(DefinitionOrderCandidateRow {
                candidate,
                first_start_byte,
                mounted_prefix,
            });
        }
        tx.commit()?;
        Ok(RenderedDefinitionCandidateOutcome::Complete(grouped))
    }

    /// Backs `CodeUnitIndex::lookup_candidates_by_identifier`, the sole bare-name
    /// resolution path keyed on the terminal identifier. Its membership must
    /// match `definition_lookup_order_candidate_sql`'s `(in_declarations = 1
    /// OR in_definition_lookup = 1)`, not the `in_declarations`-only
    /// membership `declaration_candidate_sql` uses elsewhere: a spelling the
    /// fq lookup path resolves (which already consults that wider
    /// membership) must be visible here too, or bare-name ambiguity silently
    /// drops definition-lookup-only units (e.g. JS/TS object-literal
    /// properties) that the fq spelling resolves fine (#1088). This widening
    /// is scoped to resolution only — declaration listings
    /// (get_all_declarations, search, summaries) still use the unchanged
    /// `in_declarations`-only surfaces by design (#397).
    pub fn declaration_candidate_rows_by_identifier_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        identifier: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_by_identifiers_for_langs(langs, generations, &[identifier])
    }

    /// The several-spelling form of the above, for the suffix-pattern stage of
    /// symbol lookup: one query path can be spelled by more than one persisted
    /// `identifier` (`Foo.Bar` also matches the declaration indexed as
    /// `Foo$Bar`), and an `IN` list seeks the same `(lang, identifier)` index
    /// once per spelling instead of reading the whole declaration table once
    /// per language (#1688).
    #[doc(hidden)]
    pub fn declaration_candidate_rows_by_identifiers_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        identifiers: &[&str],
    ) -> Result<Vec<HydratedCandidateRow>> {
        assert!(
            !identifiers.is_empty(),
            "a suffix query path always spells at least its terminal segment"
        );
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        // `?1` is the language, so the spellings start at `?2`.
        let placeholders = (0..identifiers.len())
            .map(|index| format!("?{}", index + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = candidate_rows_sql_with_membership(
            "units",
            CODE_UNIT_CANDIDATE_FROM_CLAUSE,
            &format!("units.lang = ?1 AND units.identifier IN ({placeholders})"),
            "(units.in_declarations = 1 OR units.in_definition_lookup = 1)",
            "keys.blob_oid, units.unit_key",
        );
        let values: Vec<&dyn ToSql> = identifiers
            .iter()
            .map(|identifier| identifier as &dyn ToSql)
            .collect();
        let rows =
            candidate_rows_for_languages(&tx, langs.iter().map(String::as_str), &sql, &values)?;
        tx.commit()?;
        Ok(rows)
    }

    /// Candidate rows whose `identifier` starts with `prefix`.
    ///
    /// A half-open range over the same `(lang, identifier)` index the exact
    /// forms above seek, so this is a bounded range scan and not a table walk:
    /// `identifier` has the default BINARY collation, and `upper` is `prefix`
    /// with its last byte incremented. Symbol lookup needs it because C#
    /// indexes a generic type under a CLR arity of no fixed width
    /// (``Widget`1``, ``Widget``2``) while the lookup alias is the arity-free
    /// source spelling, so the decorated spellings cannot be enumerated into
    /// an `IN` list. See `decorated_identifier_seeks`; the caller verifies
    /// each row, because the range also admits non-arity spellings.
    ///
    /// `prefix` must be non-empty and must not end in `0xFF`, which has no
    /// byte successor. Every caller derives it by appending an ASCII
    /// decoration character to an identifier.
    #[doc(hidden)]
    pub fn declaration_candidate_rows_by_identifier_prefix_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        prefix: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        let upper = byte_successor(prefix)
            .expect("an identifier prefix is a non-empty string with a byte successor");
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let rows = candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &identifier_prefix_candidate_sql(),
            &[&prefix, &upper.as_str()],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    #[doc(hidden)]
    pub fn declaration_candidate_rows_by_identifier_for_langs_limited(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        identifier: &str,
        limit: usize,
    ) -> Result<LimitedQueryRows<HydratedCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = limited_identifier_candidate_sql();
        let rows =
            candidate_rows_for_identifier_languages_limited(&tx, langs, identifier, &sql, limit)?;
        tx.commit()?;
        Ok(rows)
    }

    #[doc(hidden)]
    pub fn declaration_candidate_rows_by_lookup_key_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        column: PersistedLookupKey,
        value: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        let column = match column {
            PersistedLookupKey::ExactFqn => "exact_fqn",
            PersistedLookupKey::NormalizedFqn => "normalized_fqn",
        };
        self.declaration_candidate_rows_for_langs_by_predicate(
            langs,
            generations,
            &format!("units.lang = ?1 AND units.{column} = ?2"),
            &[&value],
        )
    }

    #[doc(hidden)]
    pub fn declaration_candidate_rows_by_lookup_key_for_langs_limited(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        column: PersistedLookupKey,
        value: &str,
        limit: usize,
    ) -> Result<LimitedQueryRows<HydratedCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let column = match column {
            PersistedLookupKey::ExactFqn => "exact_fqn",
            PersistedLookupKey::NormalizedFqn => "normalized_fqn",
        };
        let sql =
            limited_declaration_candidate_sql(&format!("units.lang = ?1 AND units.{column} = ?2"));
        let sql = format!("{sql} LIMIT ?3");
        let rows = candidate_rows_for_languages_limited(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&value],
            limit,
        )?;
        tx.commit()?;
        Ok(rows)
    }

    #[doc(hidden)]
    pub fn declaration_member_rows_for_owner_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        owner: &str,
        normalized: bool,
        identifier: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let owner_column = if normalized {
            "normalized_fqn"
        } else {
            "exact_fqn"
        };
        let predicate = declaration_member_owner_predicate(owner_column);
        let sql = candidate_rows_sql(
            "child",
            DECLARATION_MEMBER_CANDIDATE_FROM_CLAUSE,
            &predicate,
        );
        let rows = candidate_rows_for_languages(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&owner, &identifier],
        )?;
        tx.commit()?;
        Ok(rows)
    }

    #[doc(hidden)]
    pub fn declaration_member_rows_for_owner_for_langs_limited(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        owner: &str,
        normalized: bool,
        identifier: &str,
        limit: usize,
    ) -> Result<LimitedQueryRows<HydratedCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let owner_column = if normalized {
            "normalized_fqn"
        } else {
            "exact_fqn"
        };
        let predicate = declaration_member_owner_predicate(owner_column);
        let sql = limited_candidate_rows_sql_with_membership(
            "child",
            DECLARATION_MEMBER_CANDIDATE_FROM_CLAUSE,
            &predicate,
            "child.in_declarations = 1",
            &["keys.blob_oid", "child.unit_key"],
        );
        let sql = format!("{sql} LIMIT ?4");
        let rows = candidate_rows_for_languages_limited(
            &tx,
            langs.iter().map(String::as_str),
            &sql,
            &[&owner, &identifier],
            limit,
        )?;
        tx.commit()?;
        Ok(rows)
    }

    #[doc(hidden)]
    pub fn declaration_rows_by_package_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        package: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_for_langs_by_predicate(
            langs,
            generations,
            "units.lang = ?1 AND units.content_qualifier = ?2",
            &[&package],
        )
    }

    /// One literal, index-ordered page of candidate rows whose persisted
    /// content qualifier is exactly `package` or is nested beneath it.
    ///
    /// The caller must still resolve rows against the live snapshot because
    /// some adapters derive the hydrated package identity from the live path.
    /// Paging lets that validation stop at the first live match without
    /// materializing the complete package subtree.
    #[doc(hidden)]
    pub fn declaration_rows_by_package_prefix_page(
        &self,
        lang: &str,
        generation: GenerationId,
        package: &str,
        after: Option<(&str, Oid, i64)>,
        limit: usize,
    ) -> Result<Vec<HydratedCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, lang, generation)?;
        let nested = format!("{package}.");
        // '/' is the immediate ASCII successor of '.', so the half-open range
        // ["pkg.", "pkg/") contains exactly strings with the literal "pkg."
        // prefix. Unlike LIKE, '%' and '_' in a legal package name remain data.
        let upper = format!("{package}/");
        let cursor_predicate = if after.is_some() {
            "AND (units.content_qualifier, keys.blob_oid, units.unit_key) > (?5, ?6, ?7)"
        } else {
            ""
        };
        let predicate = format!(
            "units.lang = ?1
             AND (units.content_qualifier = ?2
                  OR (units.content_qualifier >= ?3 AND units.content_qualifier < ?4))
             {cursor_predicate}"
        );
        let sql = declaration_candidate_sql_with_order(
            &predicate,
            "units.content_qualifier, keys.blob_oid, units.unit_key",
        );
        let sql = format!("{sql} LIMIT ?{}", if after.is_some() { 8 } else { 5 });
        let mut statement = tx.prepare(&sql)?;
        let mapped = match after {
            Some((after_qualifier, after_oid, after_unit_key)) => statement.query_map(
                params![
                    lang,
                    package,
                    nested,
                    upper,
                    after_qualifier,
                    after_oid.to_string(),
                    after_unit_key,
                    limit as i64,
                ],
                candidate_row_from_row,
            )?,
            None => statement.query_map(
                params![lang, package, nested, upper, limit as i64],
                candidate_row_from_row,
            )?,
        };
        let rows = collect_mapped_rows(mapped)?;
        drop(statement);
        let rows = hydrate_candidate_rows(&tx, rows, None)?
            .expect("uncancelled package-page hydration completes");
        tx.commit()?;
        Ok(rows)
    }

    pub fn declaration_candidate_rows_by_lang(
        &self,
        lang: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_by_predicate(std::iter::once(lang), "units.lang = ?1", &[])
    }

    /// Candidate rows for a literal ASCII substring over a persistently stable
    /// fully-qualified name. Callers must retain the Rust regex filter for
    /// final semantics and use this only when their adapter guarantees that
    /// `content_qualifier` is part of the searchable FQN.
    pub fn declaration_candidate_rows_by_literal_substring(
        &self,
        lang: &str,
        substring: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_by_predicate(
            std::iter::once(lang),
            "units.lang = ?1 AND (
               instr(lower(units.short_name), lower(?2)) > 0
               OR instr(lower(units.content_qualifier), lower(?2)) > 0
             )",
            &[&substring],
        )
    }

    pub fn declaration_candidate_rows_by_literal_substring_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        substring: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_for_langs_by_predicate(
            langs,
            generations,
            "units.lang = ?1 AND (
               instr(lower(units.short_name), lower(?2)) > 0
               OR instr(lower(units.content_qualifier), lower(?2)) > 0
             )",
            &[&substring],
        )
    }

    /// Search candidates carry the metadata that `search_symbols` otherwise
    /// obtains by repeatedly hydrating complete file states.
    pub fn search_candidate_rows_by_lang(
        &self,
        lang: &str,
    ) -> Result<Vec<HydratedSearchCandidateRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let rows = search_candidate_rows_by_lang_conn(&tx, lang)?;
        tx.commit()?;
        Ok(rows)
    }

    /// Enumerate the declaration projection needed to *decide* whether a
    /// `search_symbols` pattern batch matches, and nothing else.
    ///
    /// Matching only consults a unit's fully-qualified name, which is built
    /// from its short name plus the package prefix hydrated from
    /// `content_qualifier` and the live path. Signature text, primary ranges,
    /// and candidate flags are needed only for units that actually match, so
    /// they are deliberately excluded here and fetched by key afterwards
    /// (issue #1199): a broad request over this repository previously paid for
    /// ~13 MB of signature/range columns and a temp-B-tree sort to answer a
    /// query whose result was a few dozen rows.
    #[doc(hidden)]
    pub fn search_candidate_name_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        active_blobs: &[ActiveSearchBlob],
        required_literals: Option<&[Vec<String>]>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<SearchCandidateNameRow>> {
        self.search_candidate_name_rows(
            langs,
            generations,
            active_blobs,
            search_candidate_name_rows_sql(langs, required_literals),
            cancellation,
        )
    }

    #[doc(hidden)]
    pub fn search_candidate_name_rows_with_cpp_owners(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        active_blobs: &[ActiveSearchBlob],
        required_literals: Option<&[Vec<String>]>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<SearchCandidateNameRow>> {
        let (mut sql, mut parameters) = search_candidate_name_rows_sql(langs, required_literals);
        let (owners, owner_parameters) =
            cpp_search_owner_name_rows_sql(langs, required_literals, parameters.len());
        sql.push_str(" UNION ALL ");
        sql.push_str(&owners);
        parameters.extend(owner_parameters);
        self.search_candidate_name_rows(
            langs,
            generations,
            active_blobs,
            (sql, parameters),
            cancellation,
        )
    }

    fn search_candidate_name_rows(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        active_blobs: &[ActiveSearchBlob],
        query: (String, Vec<String>),
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<SearchCandidateNameRow>> {
        // Pattern matching is performed after language-specific FQN hydration.
        // One request may carry several patterns, so the storage projection
        // intentionally supplies one complete declaration candidate set for
        // the batch while avoiding per-candidate file-state hydration. Keep
        // all languages in one SQL statement: the active-blob join is the
        // dominant cost on large workspaces, and repeating it once per
        // language turned a broad Firefox search into a serial multi-minute
        // scan, and it makes a broad regex request scale with the number of
        // language indexes as well as with workspace size.
        let mut conn = {
            let _scope = crate::profiling::scope("store.symbol_names.open_reader");
            self.active_read_conn()?
        };
        let tx = conn.transaction()?;
        {
            let _scope = crate::profiling::scope("store.symbol_names.check_generations");
            require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        }
        {
            let _scope = crate::profiling::scope("store.symbol_names.sync_active_oids");
            sync_active_blob_oids(&tx, active_blobs)?;
        }
        let rows = {
            let _scope = crate::profiling::scope("store.symbol_names.query_all_languages");
            search_candidate_name_rows_conn_cancellable(&tx, langs, query, cancellation)?
        };
        tx.commit()?;
        if rows.complete && !cancellation.is_some_and(CancellationToken::is_cancelled) {
            Ok(LimitedQueryRows::complete(rows.rows, rows.inspected))
        } else {
            Ok(LimitedQueryRows::incomplete(rows.rows, rows.inspected))
        }
    }

    /// Hydrate the full search-candidate projection for the declaration keys a
    /// pattern batch already matched.
    ///
    /// The projection is fetched in exact `(language, blob, unit)` tuple batches.
    /// `code_units` is keyed by `(blob_id, unit_key)`, so each requested tuple is
    /// a primary-key seek, and the work is proportional to the matched units
    /// instead of rescanning every declaration in a matched blob or language.
    #[doc(hidden)]
    pub fn search_candidate_rows_for_keys(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        keys: &[SearchCandidateKey],
        cancellation: Option<&CancellationToken>,
    ) -> Result<LimitedQueryRows<HydratedSearchCandidateRow>> {
        if keys.is_empty() {
            return Ok(LimitedQueryRows::complete(Vec::new(), 0));
        }
        let mut requested = Vec::with_capacity(keys.len());
        let mut seen = HashSet::default();
        for key in keys {
            let Some(lang) = langs.get(key.lang_index) else {
                continue;
            };
            let tuple = (lang.clone(), key.blob_oid, key.unit_key);
            if seen.insert(tuple.clone()) {
                requested.push(tuple);
            }
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        if requested.is_empty() {
            tx.commit()?;
            return Ok(LimitedQueryRows::complete(Vec::new(), 0));
        }
        let mut out = Vec::new();
        let mut inspected = 0usize;
        let mut complete = true;
        for chunk in requested.chunks(SEARCH_CANDIDATE_KEY_BATCH_SIZE) {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            let padded = padded_arity(chunk.len(), &SEARCH_CANDIDATE_KEY_ARITY_LADDER);
            let sql = search_candidate_key_set_sql(padded);
            let mut parameters = Vec::with_capacity(padded * 3);
            for (lang, blob_oid, unit_key) in chunk {
                parameters.push(rusqlite::types::Value::Text(lang.clone()));
                parameters.push(rusqlite::types::Value::Text(blob_oid.to_string()));
                parameters.push(rusqlite::types::Value::Integer(*unit_key));
            }
            parameters.resize(padded * 3, rusqlite::types::Value::Null);
            let mut stmt = tx.prepare_cached(&sql)?;
            let mut query = stmt.query(params_from_iter(parameters.iter()))?;
            while let Some(row) = query.next()? {
                inspected = inspected.saturating_add(1);
                if inspected.is_multiple_of(CANDIDATE_ROWS_PER_CANCELLATION_POLL)
                    && cancellation.is_some_and(CancellationToken::is_cancelled)
                {
                    complete = false;
                    break;
                }
                out.push(search_candidate_row_from_row(row)?);
            }
        }
        if !complete || cancellation.is_some_and(CancellationToken::is_cancelled) {
            tx.commit()?;
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        }
        let Some(out) = hydrate_candidate_rows(&tx, out, cancellation)? else {
            tx.commit()?;
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        };
        tx.commit()?;
        Ok(LimitedQueryRows::complete(out, inspected))
    }

    pub fn usage_fact_rows_by_lang(&self, lang: &str) -> Result<Vec<HydratedUsageFactRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let rows = usage_fact_rows_by_lang_conn(&tx, lang)?;
        tx.commit()?;
        Ok(rows)
    }

    pub fn usage_fact_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<HydratedUsageFactRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(usage_fact_rows_by_lang_conn(&tx, lang)?);
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn declaration_candidate_rows_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_for_langs_by_predicate(
            langs,
            generations,
            "units.lang = ?1",
            &[],
        )
    }

    #[doc(hidden)]
    pub fn workspace_snapshots_for_langs(
        &self,
        workspace_id: &WorkspaceId,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<WorkspaceSnapshots> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let snapshots = workspace_snapshots_conn(&tx, workspace_id, langs, generations)?;
        tx.commit()?;
        Ok(snapshots)
    }

    #[doc(hidden)]
    pub fn workspace_snapshots_for_current_languages(
        &self,
        workspace_id: &WorkspaceId,
        langs: &[String],
    ) -> Result<WorkspaceSnapshots> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let generations = langs
            .iter()
            .map(|lang| Ok((lang.clone(), current_generation_conn(&tx, lang)?)))
            .collect::<Result<HashMap<_, _>>>()?;
        let snapshots = workspace_snapshots_conn(&tx, workspace_id, langs, &generations)?;
        tx.commit()?;
        Ok(snapshots)
    }

    /// Enumerate declarations through the schema's mounted-name interface.
    ///
    /// Unlike the legacy content-row scan, this query returns the workspace
    /// path that mounted each blob reading. A header can therefore be mounted
    /// under both `cpp` and `cpp:c` without asking Rust to reconstruct that
    /// workspace relation from the blob-to-path index.
    #[doc(hidden)]
    pub fn mounted_declaration_rows_for_langs(
        &self,
        workspace_snapshots: &WorkspaceSnapshots,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<HydratedMountedCandidateRow>> {
        let mut conn = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = mounted_declaration_sql();
        let mut statement = tx.prepare_cached(&sql)?;
        let mut out = Vec::new();
        for lang in langs {
            let rows = statement.query_map([lang], |row| {
                Ok(MountedCandidateRow {
                    candidate: candidate_row_from_row(row)?,
                    rel_path: row.get(19)?,
                })
            })?;
            out.extend(rows.collect::<std::result::Result<Vec<_>, _>>()?);
        }
        drop(statement);
        let out = hydrate_candidate_rows(&tx, out, None)?
            .expect("uncancelled mounted-candidate hydration completes");
        tx.commit()?;
        Ok(out)
    }

    /// Enumerate mounted declarations and their primary ranges through one
    /// cancellation-aware read transaction. `None` is an incomplete answer,
    /// never a partial prefix of the workspace inventory.
    #[doc(hidden)]
    pub fn mounted_declaration_rows_with_primary_ranges_for_langs(
        &self,
        workspace_snapshots: &WorkspaceSnapshots,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<HydratedMountedCandidatePrimaryRangeRow>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut conn = self.read_conn_for_workspace(workspace_snapshots)?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = mounted_declaration_sql_with_primary_ranges();
        let mut statement = tx.prepare_cached(&sql)?;
        let mut out = Vec::new();
        let mut inspected = 0usize;
        for lang in langs {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let mut rows = statement.query([lang])?;
            while let Some(row) = rows.next()? {
                inspected = inspected.saturating_add(1);
                out.push(mounted_candidate_primary_range_row_from_row(row)?);
                if inspected.is_multiple_of(CANDIDATE_ROWS_PER_CANCELLATION_POLL)
                    && cancellation.is_cancelled()
                {
                    return Ok(None);
                }
            }
        }
        drop(statement);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(out) = hydrate_candidate_rows(&tx, out, Some(cancellation))? else {
            return Ok(None);
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        tx.commit()?;
        Ok(Some(out))
    }

    pub fn declaration_candidate_rows_with_primary_ranges_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<(HydratedCandidateRow, Option<Range>)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let sql = declaration_candidate_sql("units.lang = ?1");
        let mut out = Vec::new();
        for lang in langs {
            let rows =
                candidate_rows_for_languages(&tx, std::iter::once(lang.as_str()), &sql, &[])?;
            let mut oids: Vec<_> = rows.iter().map(|row| row.blob_oid).collect();
            oids.sort();
            oids.dedup();
            let ranges = primary_ranges_by_unit_for_lang_conn(&tx, lang, &oids)?;
            out.extend(rows.into_iter().map(|row| {
                let range = ranges.get(&(row.blob_oid, row.unit_key)).copied();
                (row, range)
            }));
        }
        tx.commit()?;
        Ok(out)
    }

    #[doc(hidden)]
    pub fn declaration_candidate_rows_with_primary_ranges_by_kind_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        kind: CodeUnitType,
    ) -> Result<Vec<HydratedCandidatePrimaryRangeRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, langs.iter().map(String::as_str))?;
        let from_clause = format!(
            "{CODE_UNIT_CANDIDATE_FROM_CLAUSE}
             LEFT JOIN unit_ranges AS primary_range
               ON primary_range.blob_id = units.blob_id
              AND primary_range.unit_key = units.unit_key
              AND primary_range.ordinal = 0"
        );
        let sql = format!(
            "SELECT keys.blob_oid, {},
                    units.in_test_region,
                    primary_range.start_byte, primary_range.end_byte,
                    primary_range.start_line, primary_range.end_line
             {from_clause}
             WHERE units.lang = ?1 AND units.kind = ?2 AND units.in_declarations = 1
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY keys.blob_oid, units.unit_key",
            candidate_unit_projection_sql("units")
        );
        let kind = code_unit_kind_to_i64(kind);
        let mut statement = tx.prepare_cached(&sql)?;
        let mut out = Vec::new();
        for lang in langs {
            out.extend(collect_mapped_rows(statement.query_map(
                params![lang, kind],
                candidate_primary_range_row_from_row,
            )?)?);
        }
        drop(statement);
        let out = hydrate_candidate_rows(&tx, out, None)?
            .expect("uncancelled ranged-candidate hydration completes");
        tx.commit()?;
        Ok(out)
    }

    #[doc(hidden)]
    pub fn hierarchy_facts_by_keys(
        &self,
        keys: &[HierarchyStorageKey],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashMap<HierarchyStorageKey, PersistedHierarchyFacts>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, keys.iter().map(|key| key.lang.as_str()))?;
        let mut keys_by_lang: HashMap<String, Vec<&HierarchyStorageKey>> = HashMap::default();
        let unique_keys = keys.iter().collect::<HashSet<_>>();
        for key in unique_keys {
            keys_by_lang.entry(key.lang.clone()).or_default().push(key);
        }
        let mut out = HashMap::default();
        for (lang, lang_keys) in keys_by_lang {
            let mut oids = lang_keys
                .iter()
                .map(|key| key.blob_oid.to_string())
                .collect::<Vec<_>>();
            oids.sort();
            oids.dedup();
            let imports_by_oid = read_import_infos_bulk(&tx, &lang, &oids)?
                .into_iter()
                .map(|(oid, imports)| (oid, Arc::<[ImportInfo]>::from(imports)))
                .collect::<HashMap<_, _>>();
            let mut supertypes_by_unit = HashMap::default();
            for (oid, entries) in
                read_unit_string_vec_bulk(&tx, &lang, "unit_supertypes", "raw", &oids)?
            {
                for (unit_key, raw) in entries {
                    supertypes_by_unit
                        .entry((oid.clone(), unit_key))
                        .or_insert_with(Vec::new)
                        .push(raw);
                }
            }
            for key in lang_keys {
                let oid = key.blob_oid.to_string();
                let imports = imports_by_oid.get(&oid).cloned().unwrap_or_default();
                let raw_supertypes = Arc::from(
                    supertypes_by_unit
                        .remove(&(oid, key.unit_key))
                        .unwrap_or_default(),
                );
                out.insert(
                    key.clone(),
                    PersistedHierarchyFacts {
                        imports,
                        raw_supertypes,
                    },
                );
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn definition_lookup_candidate_rows_by_oids(
        &self,
        lang: &str,
        oids: &[Oid],
    ) -> Result<Vec<HydratedCandidateRow>> {
        let _scope = crate::profiling::scope("AnalyzerStore::definition_lookup_rows_by_oids");
        if crate::profiling::enabled() {
            crate::profiling::note(format!("language={lang} oid_count={}", oids.len()));
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut out = Vec::new();
        out.extend(definition_lookup_candidate_rows_by_oids_conn(
            &tx, lang, oids,
        )?);
        if crate::profiling::enabled() {
            crate::profiling::note(format!("row_count={}", out.len()));
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn definition_lookup_candidate_rows_by_keys(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<Vec<HydratedCandidateRow>> {
        let _scope = crate::profiling::scope("AnalyzerStore::definition_lookup_rows_by_keys");
        if crate::profiling::enabled() {
            crate::profiling::note(format!("key_count={}", entries.len()));
        }
        let mut by_lang: HashMap<String, Vec<Oid>> = HashMap::default();
        for (oid, lang) in entries {
            by_lang.entry(lang.clone()).or_default().push(*oid);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, by_lang.keys().map(String::as_str))?;
        let mut out = Vec::new();
        for (lang, mut oids) in by_lang {
            oids.sort();
            oids.dedup();
            out.extend(definition_lookup_candidate_rows_by_oids_conn(
                &tx, &lang, &oids,
            )?);
        }
        if crate::profiling::enabled() {
            crate::profiling::note(format!("row_count={}", out.len()));
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn declaration_candidate_rows_by_pattern(
        &self,
        lang: &str,
        _pattern: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        // Full match semantics are over recomposed, adapter-normalized FQNs,
        // so SQL intentionally supplies a declaration-row candidate set and
        // the query layer applies the existing Rust regex semantics after
        // live-path expansion.
        self.declaration_candidate_rows_by_lang(lang)
    }

    pub fn declaration_candidate_rows_by_pattern_for_langs(
        &self,
        langs: &[String],
        generations: &HashMap<String, GenerationId>,
        _pattern: &str,
    ) -> Result<Vec<HydratedCandidateRow>> {
        self.declaration_candidate_rows_for_langs(langs, generations)
    }

    pub fn blobs_with_structured_imports(&self, lang: &str, oids: &[Oid]) -> Result<HashSet<Oid>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let present = blobs_with_structured_imports_conn(&tx, lang, oids)?;
        tx.commit()?;
        Ok(present)
    }

    pub fn blobs_with_structured_imports_by_keys(
        &self,
        entries: &[(Oid, String)],
        generations: &HashMap<String, GenerationId>,
    ) -> Result<HashSet<(Oid, String)>> {
        let mut by_lang: HashMap<String, Vec<Oid>> = HashMap::default();
        for (oid, lang) in entries {
            by_lang.entry(lang.clone()).or_default().push(*oid);
        }
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        require_generation_map(&tx, generations, by_lang.keys().map(String::as_str))?;
        let mut out = HashSet::default();
        for (lang, mut oids) in by_lang {
            oids.sort();
            oids.dedup();
            for oid in blobs_with_structured_imports_conn(&tx, &lang, &oids)? {
                out.insert((oid, lang.clone()));
            }
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn content_row_count(&self, oid: Oid, lang: &str) -> Result<usize> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let oid = oid.to_string();
        let mut total = 0usize;
        for table in [
            "code_units",
            "unit_ranges",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_signature_metadata_signatures",
            "unit_supertypes",
            "unit_children",
            "import_statements",
            "blob_meta",
            "reference_identifiers",
            "blob_reference_fact_manifests",
            "ruby_method_dispatch_modes",
            "scala_traits",
        ] {
            let sql = format!(
                "SELECT COUNT(*)
                 FROM blobs AS keys
                 JOIN {table} AS rows
                   ON rows.blob_id = keys.id
                 LEFT JOIN analysis_epochs AS active_epoch
                   ON active_epoch.lang = keys.lang
                 WHERE keys.blob_oid = ?1 AND keys.lang = ?2
                   AND keys.generation = COALESCE(active_epoch.generation, 0)"
            );
            total = total.saturating_add(
                tx.query_row(&sql, params![oid, lang], |row| row.get::<_, usize>(0))?,
            );
        }
        tx.commit()?;
        Ok(total)
    }

    pub fn gc_with_bloom(&self, reachable: &GrowableBloom) -> Result<usize> {
        let reachable = reachable.clone();
        self.gc_with(move |oid| reachable.contains(oid))
    }

    pub fn gc_with(&self, keep: impl Fn(&str) -> bool + Send + 'static) -> Result<usize> {
        self.conn.execute(move |conn| {
            let tx = conn.transaction()?;
            let dead: Vec<(String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT blobs.blob_oid, blobs.lang
                 FROM blobs
                 LEFT JOIN analysis_epochs AS epochs ON epochs.lang = blobs.lang
                 WHERE blobs.generation = COALESCE(epochs.generation, 0)
                   AND NOT EXISTS (
                     SELECT 1 FROM workspace_file_versions AS files
                     WHERE files.input_kind = 'source' AND files.blob_oid = blobs.blob_oid
                   )
                   AND NOT EXISTS (
                     SELECT 1 FROM workspace_resolution_content_roots AS roots
                     WHERE roots.blob_id = blobs.id
                   )",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                let mut dead = Vec::new();
                for row in rows {
                    let (oid, lang) = row?;
                    if !keep(&oid) {
                        dead.push((oid, lang));
                    }
                }
                dead
            };
            {
                let mut del = tx.prepare(
                    "DELETE FROM blobs
                 WHERE blob_oid = ?1 AND lang = ?2
                   AND generation = COALESCE(
                     (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
                   )
                   AND NOT EXISTS (
                     SELECT 1 FROM workspace_resolution_content_roots AS roots
                     WHERE roots.blob_id = blobs.id
                   )",
                )?;
                for (oid, lang) in &dead {
                    del.execute(params![oid, lang])?;
                }
            }
            tx.commit()?;
            // Drain the whole freelist. A single `PRAGMA incremental_vacuum`
            // step frees exactly one page; see `cache_db::drain_free_pages`.
            crate::cache_db::drain_free_pages(conn).map_err(StoreError::new)?;
            Ok(dead.len())
        })
    }

    #[doc(hidden)]
    pub fn reclaim_stale_generations(&self, max_logical_rows: usize) -> Result<usize> {
        self.execute_selection_publication(move |conn| {
            reclaim_stale_generations_conn(conn, max_logical_rows)
        })
    }

    /// Drop every workspace projection row belonging to `workspace_id`.
    ///
    /// An immutable revision image is a workspace only for the length of one
    /// request: its root is a self-deleting export directory, so the rows that
    /// mount its files (`workspace_heads`, `workspace_revisions`, and the
    /// `workspace_file_versions` tree that cascades from a revision) describe a
    /// path that no longer exists once the request ends. The parsed blob facts
    /// and unit summaries the same build published stay, because those are
    /// keyed by content and are exactly what the next consumer of this cache
    /// reuses. Periodic GC reclaims summaries that remain unbound.
    ///
    /// Returns the number of `workspace_revisions` rows removed; the file
    /// versions and their package, edge, anchor and path-symbol rows follow
    /// through `ON DELETE CASCADE`.
    #[doc(hidden)]
    pub fn delete_workspace_projection(&self, workspace_id: &WorkspaceId) -> Result<usize> {
        let workspace_id = workspace_id.as_str().to_string();
        self.execute_selection_publication(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "DELETE FROM workspace_import_graphs WHERE workspace_id = ?1",
                params![workspace_id],
            )?;
            tx.execute(
                "DELETE FROM workspace_heads WHERE workspace_id = ?1",
                params![workspace_id],
            )?;
            tx.execute(
                "DELETE FROM rust_crate_versions WHERE workspace_id = ?1",
                params![workspace_id],
            )?;
            tx.execute(
                "DELETE FROM rust_crate_reconciliations WHERE workspace_id = ?1",
                params![workspace_id],
            )?;
            tx.execute(
                unit_summaries::DELETE_WORKSPACE_VERSIONS_SQL,
                params![workspace_id],
            )?;
            let revisions = tx.execute(
                "DELETE FROM workspace_revisions WHERE workspace_id = ?1",
                params![workspace_id],
            )?;
            tx.commit()?;
            Ok(revisions)
        })
    }

    /// Test hook: remove one package's membership rows while retaining its
    /// live files and declaration facts.
    ///
    /// This synthesizes a partial workspace package projection without making
    /// the exact FQN indexes partial, the recovery shape exercised by C#'s
    /// conservative namespace gate. Production reconciliation does not expose
    /// an API for publishing this deliberately inconsistent intermediate
    /// state.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn delete_workspace_package_membership_for_test(&self, package: &str) {
        let package = package.to_string();
        self.conn.execute(move |conn| {
            conn.execute(
                "DELETE FROM workspace_file_package_rows WHERE package_name = ?1",
                [package],
            )
            .expect("delete workspace package membership")
        });
    }

    pub fn seconds_since_gc(&self) -> Result<Option<i64>> {
        let conn = self.read_conn()?;
        let stored: i64 = conn.query_row(
            "SELECT last_gc_at FROM cache_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(Some(stored)
            .filter(|at| *at > 0)
            .map(|at| crate::cache_db::now_unix_seconds() - at))
    }

    // Read access to the per-file Rust usage fact tables, inverting
    // `insert_rust_fact_rows` above. Keeping the reader beside the writer is
    // what makes the round trip reviewable in one place. The Rust analyzer
    // reaches these through `RustFactSource`, which is the only production
    // caller; the store tests below exercise both halves directly.

    /// Every persisted per-file Rust usage fact for one blob.
    ///
    /// This is the forward direction of the `rust_*` fact tables: "what does
    /// this file export, import, declare, and mention". A caller that already
    /// knows the file reads it directly; a caller searching by name reaches
    /// these rows through the inverted lookups below and then verifies each
    /// candidate against its facts.
    #[doc(hidden)]
    pub fn rust_usage_facts(&self, oid: Oid, lang: &str) -> Result<RustUsageFacts> {
        let mut conn = self.read_conn()?;
        // The fact families are one publication, even if replacement or
        // reclamation commits between individual family reads.
        let tx = conn.transaction()?;
        let facts = read_rust_usage_facts(&tx, &oid.to_string(), lang)?;
        tx.commit()?;
        Ok(facts)
    }

    /// Blobs that import `module_path`, spelled exactly as the importing file
    /// writes it. The inverted direction of `rust_import_targets`.
    #[doc(hidden)]
    pub fn rust_import_target_blobs(&self, lang: &str, module_path: &str) -> Result<Vec<Oid>> {
        self.rust_fact_blobs(
            "SELECT DISTINCT keys.blob_oid
             FROM rust_import_targets AS facts
             JOIN blobs AS keys ON keys.id = facts.blob_id
             WHERE facts.lang = ?1 AND facts.module_path = ?2",
            lang,
            module_path,
        )
    }

    /// Blobs whose structured imports can name a module component.
    ///
    /// The exact identifier occurrence is the selective outer relation. For
    /// each matching blob, the primary key range reads only that blob's import
    /// rows and confirms that the component is either the imported name or the
    /// final component of the written module path. This avoids both a suffix
    /// scan of the import table and offering ordinary code mentions to the
    /// semantic import verifier.
    #[doc(hidden)]
    pub fn rust_module_import_candidate_blobs(
        &self,
        lang: &str,
        component: &str,
    ) -> Result<Vec<Oid>> {
        self.rust_fact_blobs(RUST_MODULE_IMPORT_CANDIDATE_BLOBS_SQL, lang, component)
    }

    /// Blobs that re-export `exported_name`. The inverted direction of
    /// `rust_exports`, and the seed of an export-chain walk.
    #[doc(hidden)]
    pub fn rust_export_blobs(&self, lang: &str, exported_name: &str) -> Result<Vec<Oid>> {
        self.rust_fact_blobs(
            "SELECT DISTINCT keys.blob_oid
             FROM rust_exports AS facts
             JOIN blobs AS keys ON keys.id = facts.blob_id
             WHERE facts.lang = ?1 AND facts.exported_name = ?2",
            lang,
            exported_name,
        )
    }

    /// The traits one placed type declaration implements, as the placed
    /// declarations that declare them: `(blob, declaration id, rel_path)`.
    ///
    /// Unit derivation already bound both ends of every `impl Trait for Type`
    /// it could reach, so this is an index seek on the Rust summary endpoint
    /// target index and the declaration bridge, not a walk of the workspace's
    /// impls. The asked end is keyed by its file as well as
    /// its `(blob, declaration)`: two byte-identical files are one blob, and
    /// only the file says which of them the question is about. The answer is
    /// one query's result: nothing here outlives the call.
    #[doc(hidden)]
    pub fn rust_traits_implemented_by(
        &self,
        blob: Oid,
        declaration_id: u32,
        rel_path: &str,
    ) -> Result<Vec<(Oid, u32, String)>> {
        self.rust_trait_impl_counterparts(
            &RUST_TRAITS_IMPLEMENTED_BY_SQL,
            blob,
            declaration_id,
            rel_path,
        )
    }

    /// The placed types that implement one placed trait declaration. The
    /// reverse of [`Self::rust_traits_implemented_by`], seeked on the Rust
    /// summary endpoint target index.
    #[doc(hidden)]
    pub fn rust_types_implementing(
        &self,
        blob: Oid,
        declaration_id: u32,
        rel_path: &str,
    ) -> Result<Vec<(Oid, u32, String)>> {
        self.rust_trait_impl_counterparts(
            &RUST_TYPES_IMPLEMENTING_SQL,
            blob,
            declaration_id,
            rel_path,
        )
    }

    fn rust_trait_impl_counterparts(
        &self,
        sql: &str,
        blob: Oid,
        declaration_id: u32,
        rel_path: &str,
    ) -> Result<Vec<(Oid, u32, String)>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(
            params![
                blob.to_string(),
                declaration_id,
                rel_path,
                rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (oid, declaration, rel_path) = row?;
            out.push((Oid::from_str(&oid)?, declaration, rel_path));
        }
        out.sort();
        Ok(out)
    }

    /// Every impl of one placed trait declaration as the published rows state it:
    /// the impl's blob, file and source declaration, and its subject's placed
    /// declaration.
    ///
    /// The member-family reader takes the trait's impls from here instead of
    /// resolving every impl header in the impl files. A NULL impl declaration
    /// or an unbridged subject is returned as `None`; the reader resolves that
    /// impl's header as it would without the row.
    #[doc(hidden)]
    pub fn rust_trait_impl_rows(
        &self,
        blob: Oid,
        declaration_id: u32,
        rel_path: &str,
    ) -> Result<Vec<StoredTraitImplRow>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(&RUST_TRAIT_IMPL_ROWS_SQL)?;
        let rows = stmt.query_map(
            params![
                blob.to_string(),
                declaration_id,
                rel_path,
                rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (
                impl_blob,
                impl_rel_path,
                impl_declaration,
                subject_blob,
                subject_declaration,
                subject_rel_path,
            ) = row?;
            let subject = match (subject_blob, subject_declaration) {
                (Some(blob), Some(declaration)) => {
                    Some((Oid::from_str(&blob)?, declaration, subject_rel_path))
                }
                _ => None,
            };
            out.push(StoredTraitImplRow {
                impl_blob: Oid::from_str(&impl_blob)?,
                impl_rel_path,
                impl_declaration,
                subject,
            });
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// The traits one placed impl item states, as placed declarations. Seeked
    /// on the Rust summary endpoint impl index.
    #[doc(hidden)]
    pub fn rust_traits_of_impl(
        &self,
        impl_blob: Oid,
        impl_declaration_id: u32,
        impl_rel_path: &str,
    ) -> Result<Vec<(Oid, u32, String)>> {
        self.rust_trait_impl_counterparts(
            &RUST_TRAITS_OF_IMPL_SQL,
            impl_blob,
            impl_declaration_id,
            impl_rel_path,
        )
    }

    /// Every item-position macro invocation of one placed file, with its
    /// unqualified name when it has one and what the crates that place the
    /// file decided about it.
    ///
    /// An invocation is decided only when every crate that places the file
    /// decided it; a file no crate places has no decision. A decided
    /// invocation's items are compiled unless its decoration is inactive in
    /// every such crate, as the crate's own cfg atoms evaluate it.
    #[doc(hidden)]
    pub fn rust_item_macro_decisions(
        &self,
        snapshots: &WorkspaceSnapshots,
        blob: Oid,
        rel_path: &str,
    ) -> Result<Vec<StoredItemMacroDecision>> {
        use brokk_bifrost_rust::graph_support::RustItemMacroDecided;
        use brokk_bifrost_rust::selected_context::RustSelectedActivation;
        let conn = self.read_conn_for_workspace(snapshots)?;
        let mut stmt = conn.prepare_cached(RUST_ITEM_MACRO_DECISIONS_SQL)?;
        let rows = stmt.query_map(params![blob.to_string(), rel_path], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        /// One invocation's rows: per selected unit summary, the decoration
        /// and that crate's cfg atoms when it decided it, `None` when it did not.
        struct Placed {
            invocation: u32,
            name: Option<String>,
            placements: HashMap<i64, Option<(String, String)>>,
        }
        let mut invocations: Vec<Placed> = Vec::new();
        for row in rows {
            let (invocation, name, owner_summary, decoration, atoms) = row?;
            if invocations
                .last()
                .is_none_or(|last| last.invocation != invocation)
            {
                invocations.push(Placed {
                    invocation,
                    name,
                    placements: HashMap::default(),
                });
            }
            let placements = &mut invocations.last_mut().expect("pushed above").placements;
            if let Some(owner_summary) = owner_summary {
                let atoms = atoms.expect("a placing crate has cfg atoms");
                placements.insert(
                    owner_summary,
                    decoration.map(|decoration| (decoration, atoms)),
                );
            }
        }
        let mut out = Vec::with_capacity(invocations.len());
        for Placed {
            invocation,
            name,
            placements,
        } in invocations
        {
            let decided = if placements.is_empty() || placements.values().any(Option::is_none) {
                RustItemMacroDecided::Undecided
            } else {
                let mut compiled = false;
                for (decoration, atoms) in placements.values().flatten() {
                    let condition = decode_rust_cfg_condition(decoration).ok_or_else(|| {
                        StoreError::corrupt(format!("decided item macro decoration {decoration:?}"))
                    })?;
                    let atoms = serde_json::from_str(atoms)
                        .map_err(|error| StoreError::corrupt(error.to_string()))?;
                    compiled |= brokk_bifrost_rust::cfg::crate_activation(&atoms, &condition)
                        != RustSelectedActivation::Inactive;
                }
                RustItemMacroDecided::Passthrough { compiled }
            };
            out.push(StoredItemMacroDecision {
                invocation,
                name,
                decided,
            });
        }
        Ok(out)
    }

    /// The blobs whose item macros could expand to an item that names one of
    /// `names`, a trait's spellings.
    ///
    /// A blob writes one of the names inside a macro token tree (`via` is
    /// `None`), or it writes, in code or in a token tree, the name of a macro
    /// defined in such a blob (`via` is that macro and its defining blob): the
    /// definition may be what writes the name, and its invocations elsewhere
    /// expand it into files that never spell it. The step repeats for the
    /// macros' own names, so a macro whose body invokes one of them joins too.
    ///
    /// File granularity throughout: a blob that defines several macros offers
    /// all of them, and a blob that writes a macro's name need not invoke it.
    /// The caller decides what each blob's invocations can expand to.
    #[doc(hidden)]
    pub fn rust_macro_expansion_blobs(
        &self,
        names: &[String],
    ) -> Result<Vec<StoredMacroExpansionBlob>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(RUST_MACRO_EXPANSION_BLOBS_SQL)?;
        let names = serde_json::to_string(names).expect("names serialize");
        let rows = stmt.query_map(
            params![
                names,
                RUST_OCCURRENCE_MACRO,
                RUST_OCCURRENCE_CODE | RUST_OCCURRENCE_MACRO
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (blob, macro_name, defining_blob) = row?;
            let via = match (macro_name, defining_blob) {
                (Some(name), Some(defining)) => Some((name, Oid::from_str(&defining)?)),
                (None, None) => None,
                other => unreachable!("a macro reason names its macro and its file: {other:?}"),
            };
            out.push(StoredMacroExpansionBlob {
                blob: Oid::from_str(&blob)?,
                via,
            });
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// The names the impls of one placed trait declaration wrote for it.
    ///
    /// Crate derivation bound each `impl Name for Type` to the trait `Name`
    /// denotes, so the rows of one trait carry every spelling that reaches it:
    /// its own identifier, and any name a `use ... as` or a re-export gave it.
    /// A member walk resolves only the impl headers spelled one of these ways;
    /// a header spelled otherwise cannot name this trait.
    #[doc(hidden)]
    pub fn rust_trait_impl_spellings(
        &self,
        blob: Oid,
        declaration_id: u32,
        rel_path: &str,
    ) -> Result<Vec<String>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(&RUST_TRAIT_IMPL_SPELLINGS_SQL)?;
        let rows = stmt.query_map(
            params![
                blob.to_string(),
                declaration_id,
                rel_path,
                rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ],
            |row| row.get::<_, String>(0),
        )?;
        let mut out = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Blobs that both declare a Rust type alias and mention `identifier`.
    ///
    /// The candidates for "which alias denotes this type". An alias that never
    /// writes the name cannot alias it, and a blob with no alias item has none
    /// to offer, so the two conditions together are a much smaller set than
    /// either alone. Aliases are rare -- 531 items in the whole of tract -- so
    /// this is normally empty and always short.
    #[doc(hidden)]
    pub fn rust_alias_blobs_mentioning(&self, lang: &str, identifier: &str) -> Result<Vec<Oid>> {
        self.rust_fact_blobs(
            "SELECT DISTINCT keys.blob_oid
             FROM rust_identifier_occurrences AS occurrence
             JOIN source_rust_alias_items AS alias ON alias.blob_id = occurrence.blob_id
             JOIN blobs AS keys ON keys.id = occurrence.blob_id
             WHERE occurrence.lang = ?1 AND occurrence.identifier = ?2",
            lang,
            identifier,
        )
    }

    /// The placed files holding `impl`s that named this trait spelling and did
    /// not become a trait-implementation row, as `(blob, rel_path)`.
    ///
    /// These are the impls the relation cannot point at: their trait side never
    /// bound, so there is no declaration to seek them by. They still decide
    /// whether a trait's implementations are exhaustively known, so a reader
    /// that wants to answer that has to be told where they are. The indexed
    /// Rust summary endpoint rows preserve each spelling under the unit's live
    /// summary version.
    #[doc(hidden)]
    pub fn rust_unresolved_trait_impl_files(
        &self,
        spelling: &str,
    ) -> Result<Vec<(Oid, String, Option<u32>)>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(RUST_UNRESOLVED_TRAIT_IMPL_FILES_SQL)?;
        let rows = stmt.query_map(
            params![
                spelling,
                rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (oid, rel_path, declaration) = row?;
            out.push((Oid::from_str(&oid)?, rel_path, declaration));
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Every blob that writes at least one `include!`.
    ///
    /// Bounded by the number of Rust files that use `include!`, which is a
    /// handful in even a very large workspace -- this is a scan of one narrow
    /// table, not of the workspace. The one caller is the inverse-scan file
    /// selection, which has to know which files are spliced into another
    /// before it can decide whether to read them.
    #[doc(hidden)]
    pub fn rust_include_host_blobs(&self, lang: &str) -> Result<Vec<Oid>> {
        self.rust_fact_blob_oids(
            "SELECT DISTINCT keys.blob_oid
                 FROM rust_include_edges AS facts
                 JOIN blobs AS keys ON keys.id = facts.blob_id
                 WHERE facts.lang = ?1",
            params![lang],
            |text| {
                Oid::from_str(&text)
                    .map_err(|err| StoreError::new(format!("invalid blob oid {text}: {err}")))
            },
        )
    }

    /// Blobs with an `include!` whose literal's last path component is
    /// `file_name`. The inverted direction of `rust_include_edges`.
    ///
    /// A candidate set: two directories can both hold a `table.rs`, so the
    /// caller confirms each candidate by resolving that candidate's own stored
    /// `relative_path` against its own directory.
    #[doc(hidden)]
    pub fn rust_include_blobs(&self, lang: &str, file_name: &str) -> Result<Vec<Oid>> {
        self.rust_fact_blobs(
            "SELECT DISTINCT keys.blob_oid
             FROM rust_include_edges AS facts
             JOIN blobs AS keys ON keys.id = facts.blob_id
             WHERE facts.lang = ?1 AND facts.file_name = ?2",
            lang,
            file_name,
        )
    }

    /// Blobs whose text mentions `identifier`, with the OR of the contexts it
    /// was seen in. These are CANDIDATES, never usages: a hit means the name
    /// occurs, and the caller must still resolve it against the candidate's
    /// own facts. Comparison is case-sensitive, matching the spelling the
    /// declaration side stores.
    #[doc(hidden)]
    pub fn rust_identifier_occurrence_blobs(
        &self,
        lang: &str,
        identifier: &str,
    ) -> Result<Vec<(Oid, u32)>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT keys.blob_oid, facts.context_mask
             FROM rust_identifier_occurrences AS facts
             JOIN blobs AS keys ON keys.id = facts.blob_id
             WHERE facts.lang = ?1 AND facts.identifier = ?2",
        )?;
        let rows = stmt.query_map(params![lang, identifier], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (oid, context_mask) = row?;
            out.push((
                Oid::from_str(&oid)?,
                u32::try_from(context_mask).map_err(|_| {
                    StoreError::new(format!(
                        "occurrence context mask out of range: {context_mask}"
                    ))
                })?,
            ));
        }
        out.sort();
        Ok(out)
    }

    /// Test hook: remove the canonical module publication witness. Source
    /// children remain sealed until ordinary replacement repairs the blob.
    ///
    /// This synthesizes the exact state the Milestone 3 catch-up policy exists
    /// for -- live files whose blobs carry no fact witness -- which no production
    /// path can be asked to produce on demand. It follows
    /// `mark_parsed_blob_incomplete_for_test`, the store's existing way of
    /// putting itself into a state only recovery code should see.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    #[doc(hidden)]
    pub fn delete_rust_facts_for_test(&self, lang: &str) {
        let lang = lang.to_string();
        self.conn.execute(move |conn| {
            // Lose the whole module family, not just its witness. Keeping
            // foreign keys enabled distinguishes missing facts from orphan
            // children in an invalid database.
            let tx = conn.transaction().expect("module fact loss transaction");
            for table in [
                "source_rust_module_route_gates", "source_rust_module_routes",
                "source_rust_module_scopes", "source_rust_module_declarations",
                "source_rust_module_inventory", "source_rust_macro_invocations",
                "source_rust_module_manifests",
            ] {
                let guard = format!("{table}_no_delete_after_seal");
                let sql: String = tx.query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [&guard], |row| row.get(0)).expect("module deletion guard");
                tx.execute_batch(&format!("DROP TRIGGER {guard}")).expect("allow deliberate module fact loss");
                tx.execute(&format!("DELETE FROM {table} WHERE blob_id IN (SELECT id FROM blobs WHERE lang = ?1)"),
                    [&lang]).expect("remove canonical module family rows");
                tx.execute_batch(&sql).expect("restore module deletion guard");
            }
            tx.commit().expect("module fact loss preserves foreign keys");
        });
    }

    /// Test hook: make the Rust fact witness table unreadable, so
    /// [`Self::blobs_with_rust_facts`] fails the way a damaged or concurrently
    /// migrated cache would.
    ///
    /// The catch-up probe has no production trigger for a read failure, and
    /// the defect it guards -- a failed probe reported as "no file needs
    /// catching up" -- is only observable when the read actually fails
    /// (#2325). Same intent as `delete_rust_facts_for_test` above: put the
    /// store into a state only recovery code should see.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    #[doc(hidden)]
    pub fn drop_rust_modules_table_for_test(&self) {
        self.conn.execute(move |conn| {
            conn.execute("DROP VIEW rust_published_fact_blobs", [])
                .expect("make Rust publication probe unreadable")
        });
    }

    /// Exercise inverse-read failure and retry against real SQL while retaining
    /// the publication rows. The callback runs without holding the writer.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_unreadable_rust_identifier_occurrences_for_test<T>(
        &self,
        check: impl FnOnce() -> T,
    ) -> T {
        self.conn.execute(|conn| {
            conn.execute(
                "ALTER TABLE rust_identifier_occurrences RENAME TO unreadable_rust_identifier_occurrences",
                [],
            )
            .expect("hide Rust identifier occurrences from inverse readers");
        });
        let result = check();
        self.conn.execute(|conn| {
            conn.execute(
                "ALTER TABLE unreadable_rust_identifier_occurrences RENAME TO rust_identifier_occurrences",
                [],
            )
            .expect("restore Rust identifier occurrences for retry");
        });
        result
    }

    /// Which of `oids` already carry the current, complete Rust publication.
    ///
    /// `rust_modules` and `rust_module_scopes` are the route witnesses: every
    /// analyzed Rust blob records its file-root extent at ordinal 0, so a blob
    /// absent from either table has no usable native route facts. The canonical
    /// source manifest and parsed-blob metadata must also be sealed and complete
    /// before the witness is authoritative.
    ///
    /// Chunked set membership over the primary key, following
    /// `parsed_blob_keys_conn_with_condition`: each chunk is a batch of index
    /// seeks, so the cost tracks the live file set rather than the table's
    /// accumulated history.
    #[doc(hidden)]
    pub fn blobs_with_rust_facts(
        &self,
        lang: &str,
        generation: GenerationId,
        oids: &[Oid],
    ) -> Result<HashSet<Oid>> {
        let unique = unique_rust_fact_oid_strings(oids);
        let conn = self.read_conn()?;
        let mut present = set_with_capacity(unique.len());
        for chunk in unique.chunks(RUST_FACT_OIDS_PER_QUERY) {
            let (placeholders, parameters) =
                rust_fact_oid_query_parameters(lang, generation, chunk);
            let sql = Self::blobs_with_rust_facts_sql(&placeholders);
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
                row.get::<_, String>(0)
            })?;
            for row in rows {
                present.insert(Oid::from_str(&row?)?);
            }
        }
        Ok(present)
    }

    #[doc(hidden)]
    pub fn blobs_with_rust_facts_sql(placeholders: &str) -> String {
        format!(
            "SELECT keys.blob_oid
         FROM rust_published_fact_blobs AS keys
         WHERE keys.lang = ?1
           AND keys.generation = ?2
           AND keys.blob_oid IN ({placeholders})"
        )
    }

    /// Every live blob's module-route facts, in one chunked pass.
    ///
    /// This is what replaced hydrating and parsing every analyzed Rust file to
    /// build `RustCargoRouteIndex` (issue #1793). The index is a
    /// whole-workspace product, so it genuinely needs every file's rows; asking
    /// per blob would be tens of thousands of round trips, where four chunked
    /// index seeks per batch is a scan of exactly the rows that exist.
    ///
    /// A blob with no rows is absent from the result, which the caller
    /// distinguishes from "this file declares nothing".
    #[doc(hidden)]
    pub fn rust_module_route_facts_while(
        &self,
        lang: &str,
        generation: GenerationId,
        oids: &[Oid],
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<HashMap<Oid, RustModuleRouteFacts>>> {
        if !keep_going() {
            return Ok(None);
        }
        let unique = unique_rust_fact_oid_strings(oids);
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let mut by_oid: HashMap<Oid, RustModuleRouteFacts> = HashMap::default();
        for chunk in unique.chunks(RUST_FACT_OIDS_PER_QUERY) {
            if !keep_going() {
                return Ok(None);
            }
            let (placeholders, parameters) =
                rust_fact_oid_query_parameters(lang, generation, chunk);
            let mut stmt = tx.prepare_cached(&format!(
                "SELECT keys.blob_oid, source_scope.declaration_id,
                        facts.parent_ordinal, facts.module_name,
                        facts.path_attribute, facts.visibility, facts.imports_macros,
                        facts.resolution_scope, facts.body_start, facts.body_end
                 FROM rust_published_fact_blobs AS keys
                 JOIN rust_module_scopes AS facts
                   ON facts.blob_id = keys.blob_id AND facts.lang = keys.lang
                 JOIN source_rust_module_scopes AS source_scope
                   ON source_scope.blob_id = facts.blob_id
                  AND source_scope.ordinal = facts.ordinal
                 WHERE keys.lang = ?1 AND keys.generation = ?2
                   AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.ordinal"
            ))?;
            let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    decode_rust_module_scope_row(row, 1)?,
                ))
            })?;
            for row in rows {
                let (oid, scope) = row?;
                if !keep_going() {
                    return Ok(None);
                }
                by_oid
                    .entry(Oid::from_str(&oid)?)
                    .or_default()
                    .scopes
                    .push(scope?);
            }
            drop(stmt);
            let mut stmt = tx.prepare_cached(&format!(
                "SELECT keys.blob_oid, source_route.declaration_id,
                        facts.scope_ordinal, facts.module_name,
                        facts.path_attribute, facts.visibility, facts.imports_macros,
                        facts.test_gated, facts.cfg_condition, facts.declaration_start,
                        facts.declaration_end
                 FROM rust_published_fact_blobs AS keys
                 JOIN rust_module_routes AS facts
                   ON facts.blob_id = keys.blob_id AND facts.lang = keys.lang
                 JOIN source_rust_module_routes AS source_route
                   ON source_route.blob_id = facts.blob_id
                  AND source_route.ordinal = facts.ordinal
                 WHERE keys.lang = ?1 AND keys.generation = ?2
                   AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.ordinal"
            ))?;
            let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    decode_rust_module_route_row(row, 1)?,
                ))
            })?;
            for row in rows {
                let (oid, route) = row?;
                if !keep_going() {
                    return Ok(None);
                }
                by_oid
                    .entry(Oid::from_str(&oid)?)
                    .or_default()
                    .routes
                    .push(route?);
            }
            drop(stmt);
            let mut stmt = tx.prepare_cached(&format!(
                "SELECT keys.blob_oid, facts.route_ordinal, facts.macro_name,
                        facts.invocation_start
                 FROM rust_published_fact_blobs AS keys
                 JOIN rust_module_route_gates AS facts
                   ON facts.blob_id = keys.blob_id AND facts.lang = keys.lang
                 WHERE keys.lang = ?1 AND keys.generation = ?2
                   AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.route_ordinal, facts.gate_ordinal"
            ))?;
            let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    decode_rust_module_route_gate_row(row, 1)?,
                ))
            })?;
            for row in rows {
                let (oid, gate) = row?;
                if !keep_going() {
                    return Ok(None);
                }
                let (route_ordinal, gate) = gate?;
                let facts = by_oid.entry(Oid::from_str(&oid)?).or_default();
                attach_rust_module_route_gate(&mut facts.routes, route_ordinal, gate)?;
            }
            drop(stmt);
            let mut stmt = tx.prepare_cached(&format!(
                "SELECT keys.blob_oid, facts.macro_name, facts.visible_after,
                        facts.scope_start, facts.scope_end, facts.passthrough,
                        facts.exported, facts.declaration_id, facts.arguments_only,
                        facts.decoration_cfg, facts.declares_no_item, facts.writes_only_impls
                 FROM rust_published_fact_blobs AS keys
                 JOIN rust_item_macros AS facts
                   ON facts.blob_id = keys.blob_id AND facts.lang = keys.lang
                 WHERE keys.lang = ?1 AND keys.generation = ?2
                   AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.ordinal"
            ))?;
            let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    decode_rust_item_macro_row(row, 1)?,
                ))
            })?;
            for row in rows {
                let (oid, definition) = row?;
                if !keep_going() {
                    return Ok(None);
                }
                by_oid
                    .entry(Oid::from_str(&oid)?)
                    .or_default()
                    .item_macros
                    .push(definition?);
            }
            drop(stmt);
        }
        tx.commit()?;
        Ok(keep_going().then_some(by_oid))
    }

    fn rust_fact_blobs(&self, sql: &str, lang: &str, key: &str) -> Result<Vec<Oid>> {
        let mut out =
            self.rust_fact_blob_oids(sql, params![lang, key], |text| Ok(Oid::from_str(&text)?))?;
        out.sort();
        Ok(out)
    }

    fn rust_fact_blob_oids(
        &self,
        sql: &str,
        parameters: impl rusqlite::Params,
        mut decode: impl FnMut(String) -> Result<Oid>,
    ) -> Result<Vec<Oid>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(parameters, |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let text = row?;
            out.push(decode(text)?);
        }
        Ok(out)
    }
}

const RUST_MODULE_IMPORT_CANDIDATE_BLOBS_SQL: &str = "SELECT DISTINCT keys.blob_oid
     FROM rust_identifier_occurrences AS occurrence
     JOIN source_rust_import_targets AS import_target
       ON import_target.blob_id = occurrence.blob_id
     JOIN blobs AS keys ON keys.id = occurrence.blob_id
     WHERE occurrence.lang = ?1
       AND occurrence.identifier = ?2
       AND (import_target.imported_name = ?2
            OR import_target.module_path = ?2
            OR import_target.module_path LIKE '%::' || ?2)";

/// The Rust unit-summary readers bind the writer's derivation version as a SQL
/// parameter instead of repeating the literal, so bumping
/// [`rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION`] changes one
/// constant. The live-summary readers built here all number it `?4`, after
/// their three declaration key parameters.
const RUST_SUMMARY_DERIVATION_VERSION_PARAM: &str = "?4";

/// One impl-relation direction, asked by the placed declaration the caller
/// holds.
///
/// `{asked}` is the side the question names and `{counterpart}` the side it
/// wants back. Both bridge hops are index seeks: declaration to source site on
/// the way in, source site to declaration on the way out. `?3` is the asked
/// declaration's file, which the seek includes so that one of two
/// byte-identical files does not answer for the other. `version_param` is the
/// caller's placeholder for
/// [`rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION`].
fn live_rust_summary_joins(
    prefix: &str,
    version_index: &str,
    version_predicate: &str,
    version_param: &str,
) -> String {
    format!(
        "CROSS JOIN main.resolution_unit_summary_versions AS {prefix}_versions \
           INDEXED BY {version_index} ON {version_predicate} \
         CROSS JOIN main.workspace_heads AS {prefix}_heads \
           ON {prefix}_heads.workspace_id={prefix}_versions.workspace_id \
          AND {prefix}_heads.lang={prefix}_versions.lang \
          AND {prefix}_heads.generation={prefix}_versions.generation \
          AND {prefix}_versions.valid_from<={prefix}_heads.revision \
          AND ({prefix}_versions.valid_until IS NULL OR \
               {prefix}_heads.revision<{prefix}_versions.valid_until) \
         CROSS JOIN main.resolution_unit_summaries AS {prefix}_summaries \
           ON {prefix}_summaries.summary_id={prefix}_versions.summary_id \
          AND {prefix}_summaries.lang='rust' \
          AND {prefix}_summaries.unit_kind='rust_crate' \
          AND {prefix}_summaries.publication_state='complete' \
          AND {prefix}_summaries.derivation_version={version_param} \
         CROSS JOIN main.resolution_producer_epochs AS {prefix}_epochs \
           ON {prefix}_epochs.lang={prefix}_versions.lang \
          AND {prefix}_epochs.producer_epoch={prefix}_summaries.producer_epoch \
         CROSS JOIN main.rust_resolution_unit_summary_versions AS {prefix}_rust_versions \
           ON {prefix}_rust_versions.workspace_id={prefix}_versions.workspace_id \
          AND {prefix}_rust_versions.lang={prefix}_versions.lang \
          AND {prefix}_rust_versions.generation={prefix}_versions.generation \
          AND {prefix}_rust_versions.unit_key={prefix}_versions.unit_key \
          AND {prefix}_rust_versions.valid_from={prefix}_versions.valid_from \
          AND {prefix}_rust_versions.summary_id={prefix}_versions.summary_id"
    )
}

fn live_rust_summary_by_id(prefix: &str, summary_id: &str) -> String {
    live_rust_summary_joins(
        prefix,
        "resolution_unit_summary_versions_summary",
        &format!("{prefix}_versions.summary_id={summary_id}"),
        RUST_SUMMARY_DERIVATION_VERSION_PARAM,
    )
}

fn live_rust_summary_by_key(prefix: &str, owner_prefix: &str, unit_key: &str) -> String {
    live_rust_summary_joins(
        prefix,
        "resolution_unit_summary_versions_open",
        &format!(
            "{prefix}_versions.workspace_id={owner_prefix}_versions.workspace_id \
             AND {prefix}_versions.lang='rust' \
             AND {prefix}_versions.generation={owner_prefix}_versions.generation \
             AND {prefix}_versions.unit_key={unit_key} \
             AND {prefix}_versions.valid_until IS NULL"
        ),
        RUST_SUMMARY_DERIVATION_VERSION_PARAM,
    )
}

fn live_rust_member_file_joins(prefix: &str, member: &str, version: &str) -> String {
    format!(
        "CROSS JOIN main.workspace_file_versions AS {prefix}_files \
           INDEXED BY idx_workspace_file_versions_snapshot_path \
           ON {prefix}_files.workspace_id={version}.workspace_id \
          AND {prefix}_files.lang={version}.lang \
          AND {prefix}_files.generation={version}.generation \
          AND {prefix}_files.input_kind='source' \
          AND {prefix}_files.rel_path={member}.rel_path \
          AND {prefix}_files.valid_from<={prefix}_heads.revision \
          AND ({prefix}_files.valid_until IS NULL OR \
               {prefix}_heads.revision<{prefix}_files.valid_until) \
         CROSS JOIN main.blobs AS {prefix}_blobs \
           ON {prefix}_blobs.id={member}.blob_id \
          AND {prefix}_blobs.lang={version}.lang \
          AND {prefix}_blobs.generation={version}.generation \
          AND {prefix}_blobs.blob_oid={prefix}_files.blob_oid"
    )
}

fn trait_impl_counterpart_sql(asked: &str, counterpart: &str) -> String {
    let asked_live = live_rust_summary_by_id("asked", "asked_member.summary_id");
    let asked_file = live_rust_member_file_joins("asked", "asked_member", "asked_versions");
    let owner_live = live_rust_summary_by_id("owner", "asked_endpoint.summary_id");
    let owner_file = live_rust_member_file_joins("owner", "owner_member", "owner_versions");
    let target_live = live_rust_summary_by_key(
        "counterpart",
        "owner",
        "counterpart_endpoint.target_unit_key",
    );
    let target_file =
        live_rust_member_file_joins("counterpart", "counterpart_member", "counterpart_versions");
    format!(
        "SELECT DISTINCT counterpart_blobs.blob_oid, counterpart_bridge.declaration_id, \
                counterpart_member.rel_path \
         FROM main.blobs AS asked_keys \
         CROSS JOIN main.source_native_declaration_bridges AS asked \
           INDEXED BY source_native_declaration_bridges_declaration \
           ON asked.blob_id=asked_keys.id AND asked.declaration_id=?2 \
         CROSS JOIN main.resolution_unit_summary_members AS asked_member \
           INDEXED BY resolution_unit_summary_members_blob \
           ON asked_member.blob_id=asked_keys.id AND asked_member.rel_path=?3 \
         {asked_live} {asked_file} \
         CROSS JOIN main.rust_resolution_unit_summary_exports AS asked_export \
           INDEXED BY rust_resolution_unit_summary_exports_declaration \
           ON asked_export.summary_id=asked_member.summary_id \
          AND asked_export.declaration_member_ordinal=asked_member.member_ordinal \
          AND asked_export.declaration_site=asked.source_site \
          AND asked_export.namespace='type' AND asked_export.origin='declaration' \
         CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS asked_endpoint \
           INDEXED BY rust_resolution_unit_summary_trait_endpoints_target \
           ON asked_endpoint.target_unit_key=asked_versions.unit_key \
          AND asked_endpoint.target_module_path=asked_export.module_path \
          AND asked_endpoint.target_identity_id=asked_export.identity_id \
          AND asked_endpoint.endpoint_role='{asked}' \
          AND asked_endpoint.endpoint_state='resolved' \
         CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS counterpart_endpoint \
           ON counterpart_endpoint.summary_id=asked_endpoint.summary_id \
          AND counterpart_endpoint.member_ordinal=asked_endpoint.member_ordinal \
          AND counterpart_endpoint.owner_module_path=asked_endpoint.owner_module_path \
          AND counterpart_endpoint.source_relation_key=asked_endpoint.source_relation_key \
          AND counterpart_endpoint.endpoint_role='{counterpart}' \
          AND counterpart_endpoint.endpoint_state='resolved' \
         {owner_live} \
         CROSS JOIN main.resolution_unit_summary_members AS owner_member \
           ON owner_member.summary_id=owner_versions.summary_id \
          AND owner_member.member_ordinal=asked_endpoint.member_ordinal \
         {owner_file} \
         {target_live} \
         CROSS JOIN main.rust_resolution_unit_summary_exports AS counterpart_export \
           INDEXED BY rust_resolution_unit_summary_exports_identity \
           ON counterpart_export.summary_id=counterpart_versions.summary_id \
          AND counterpart_export.identity_id=counterpart_endpoint.target_identity_id \
          AND counterpart_export.module_path=counterpart_endpoint.target_module_path \
          AND counterpart_export.namespace='type' AND counterpart_export.origin='declaration' \
         CROSS JOIN main.resolution_unit_summary_members AS counterpart_member \
           ON counterpart_member.summary_id=counterpart_export.summary_id \
          AND counterpart_member.member_ordinal=counterpart_export.declaration_member_ordinal \
         {target_file} \
         CROSS JOIN main.source_native_declaration_bridges AS counterpart_bridge \
           ON counterpart_bridge.blob_id=counterpart_member.blob_id \
          AND counterpart_bridge.source_site=counterpart_export.declaration_site \
         WHERE asked_keys.blob_oid=?1"
    )
}

/// One item-position macro invocation, as
/// [`AnalyzerStore::rust_item_macro_decisions`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct StoredItemMacroDecision {
    #[doc(hidden)]
    pub invocation: u32,
    #[doc(hidden)]
    pub name: Option<String>,
    #[doc(hidden)]
    pub decided: brokk_bifrost_rust::graph_support::RustItemMacroDecided,
}

/// One blob [`AnalyzerStore::rust_macro_expansion_blobs`] returns, with the
/// macro and its defining blob when it is there by a macro's name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct StoredMacroExpansionBlob {
    #[doc(hidden)]
    pub blob: Oid,
    #[doc(hidden)]
    pub via: Option<(String, Oid)>,
}

/// `source_position` 0 and 1 are the item positions: a direct item
/// (`name! { .. }`) and an expression statement at item level (`name!(..);`).
/// The name row exists only for an unqualified invocation, which is the only
/// kind textual `macro_rules!` scoping decides.
const RUST_ITEM_MACRO_DECISIONS_SQL: &str =
    "SELECT invocation.invocation_occurrence_id, head.macro_name, member.summary_id,
            decided.decoration_cfg, json(context.cfg_atoms)
     FROM blobs AS keys
     CROSS JOIN source_rust_item_macro_expansions AS invocation
       ON invocation.blob_id = keys.id
     LEFT JOIN source_rust_macro_invocations AS head
       ON head.blob_id = invocation.blob_id
      AND head.occurrence_id = invocation.invocation_occurrence_id
     LEFT JOIN main.resolution_unit_summary_members AS member
       INDEXED BY resolution_unit_summary_members_blob
       ON member.blob_id = invocation.blob_id AND member.rel_path = ?2
      AND EXISTS(SELECT 1 FROM temp.selected_rust_unit_summary_route_owners AS live
                 WHERE live.summary_id = member.summary_id)
     LEFT JOIN main.rust_resolution_unit_summary_macro_decisions AS decided
       ON decided.summary_id = member.summary_id
      AND decided.member_ordinal = member.member_ordinal
      AND decided.invocation_occurrence_id = invocation.invocation_occurrence_id
     LEFT JOIN main.rust_resolution_unit_summary_contexts AS context
       ON context.summary_id = member.summary_id
     WHERE keys.blob_oid = ?1 AND keys.lang = 'rust' AND invocation.source_position IN (0, 1)
     ORDER BY invocation.invocation_occurrence_id";

/// `?1` is a JSON array of names, `?2` the macro-token-tree occurrence bit and
/// `?3` the bits a macro's name is written with where it is invoked.
const RUST_MACRO_EXPANSION_BLOBS_SQL: &str = "WITH RECURSIVE
     names(name) AS (
       SELECT asked.value FROM json_each(?1) AS asked
       UNION
       SELECT definition.macro_name
       FROM names
       CROSS JOIN rust_identifier_occurrences AS occurrence
         ON occurrence.lang = 'rust' AND occurrence.identifier = names.name
        AND (occurrence.context_mask & ?2) != 0
       CROSS JOIN source_rust_item_macros AS definition
         ON definition.blob_id = occurrence.blob_id
     ),
     writers(blob_id) AS (
       SELECT occurrence.blob_id
       FROM names
       CROSS JOIN rust_identifier_occurrences AS occurrence
         ON occurrence.lang = 'rust' AND occurrence.identifier = names.name
        AND (occurrence.context_mask & ?2) != 0
     ),
     macros(name, blob_id) AS (
       SELECT DISTINCT definition.macro_name, definition.blob_id
       FROM writers
       CROSS JOIN source_rust_item_macros AS definition
         ON definition.blob_id = writers.blob_id
     )
     SELECT keys.blob_oid, NULL, NULL
     FROM writers CROSS JOIN blobs AS keys ON keys.id = writers.blob_id
     UNION
     SELECT keys.blob_oid, macros.name, defining.blob_oid
     FROM macros
     CROSS JOIN rust_identifier_occurrences AS occurrence
       ON occurrence.lang = 'rust' AND occurrence.identifier = macros.name
      AND (occurrence.context_mask & ?3) != 0
     CROSS JOIN blobs AS keys ON keys.id = occurrence.blob_id
     CROSS JOIN blobs AS defining ON defining.id = macros.blob_id";

/// One impl row of a trait, as [`AnalyzerStore::rust_trait_impl_rows`] reads it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct StoredTraitImplRow {
    #[doc(hidden)]
    pub impl_blob: Oid,
    #[doc(hidden)]
    pub impl_rel_path: String,
    #[doc(hidden)]
    pub impl_declaration: Option<u32>,
    #[doc(hidden)]
    pub subject: Option<(Oid, u32, String)>,
}

/// One placed trait's impl rows, with each impl's source declaration and its
/// subject's placed declaration. The subject is bridged with a LEFT JOIN so an
/// unbridged subject still returns its impl, to be resolved by the reader.
pub(crate) static RUST_TRAIT_IMPL_ROWS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        let target_live = live_rust_summary_by_id("asked", "asked_member.summary_id");
        let target_file = live_rust_member_file_joins("asked", "asked_member", "asked_versions");
        let impl_live = live_rust_summary_by_id("impl", "trait_endpoint.summary_id");
        let impl_file = live_rust_member_file_joins("impl", "impl_member", "impl_versions");
        let subject_live =
            live_rust_summary_by_key("subject", "impl", "subject_endpoint.target_unit_key");
        let subject_file =
            live_rust_member_file_joins("subject", "subject_member", "subject_versions");
        format!(
            "SELECT DISTINCT impl_blobs.blob_oid, impl_member.rel_path, \
                    trait_endpoint.impl_declaration_id, subject_blobs.blob_oid, \
                    subject_bridge.declaration_id, subject_member.rel_path \
             FROM main.blobs AS asked_keys \
             CROSS JOIN main.source_native_declaration_bridges AS asked \
               INDEXED BY source_native_declaration_bridges_declaration \
               ON asked.blob_id=asked_keys.id AND asked.declaration_id=?2 \
             CROSS JOIN main.resolution_unit_summary_members AS asked_member \
               INDEXED BY resolution_unit_summary_members_blob \
               ON asked_member.blob_id=asked_keys.id AND asked_member.rel_path=?3 \
             {target_live} {target_file} \
             CROSS JOIN main.rust_resolution_unit_summary_exports AS asked_export \
               INDEXED BY rust_resolution_unit_summary_exports_declaration \
               ON asked_export.summary_id=asked_member.summary_id \
              AND asked_export.declaration_member_ordinal=asked_member.member_ordinal \
              AND asked_export.declaration_site=asked.source_site \
              AND asked_export.namespace='type' AND asked_export.origin='declaration' \
             CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS trait_endpoint \
               INDEXED BY rust_resolution_unit_summary_trait_endpoints_target \
               ON trait_endpoint.target_unit_key=asked_versions.unit_key \
              AND trait_endpoint.target_module_path=asked_export.module_path \
              AND trait_endpoint.target_identity_id=asked_export.identity_id \
              AND trait_endpoint.endpoint_role='trait' \
              AND trait_endpoint.endpoint_state='resolved' \
             CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS subject_endpoint \
               ON subject_endpoint.summary_id=trait_endpoint.summary_id \
              AND subject_endpoint.member_ordinal=trait_endpoint.member_ordinal \
              AND subject_endpoint.owner_module_path=trait_endpoint.owner_module_path \
              AND subject_endpoint.source_relation_key=trait_endpoint.source_relation_key \
              AND subject_endpoint.endpoint_role='subject' \
              AND subject_endpoint.endpoint_state='resolved' \
             {impl_live} \
             CROSS JOIN main.resolution_unit_summary_members AS impl_member \
               ON impl_member.summary_id=impl_versions.summary_id \
              AND impl_member.member_ordinal=trait_endpoint.member_ordinal \
             {impl_file} \
             {subject_live} \
             CROSS JOIN main.rust_resolution_unit_summary_exports AS subject_export \
               INDEXED BY rust_resolution_unit_summary_exports_identity \
               ON subject_export.summary_id=subject_versions.summary_id \
              AND subject_export.identity_id=subject_endpoint.target_identity_id \
              AND subject_export.module_path=subject_endpoint.target_module_path \
              AND subject_export.namespace='type' AND subject_export.origin='declaration' \
             CROSS JOIN main.resolution_unit_summary_members AS subject_member \
               ON subject_member.summary_id=subject_export.summary_id \
              AND subject_member.member_ordinal=subject_export.declaration_member_ordinal \
             {subject_file} \
             LEFT JOIN main.source_native_declaration_bridges AS subject_bridge \
               ON subject_bridge.blob_id=subject_member.blob_id \
              AND subject_bridge.source_site=subject_export.declaration_site \
             WHERE asked_keys.blob_oid=?1"
        )
    });

/// The placed traits one placed impl item states.
pub(crate) static RUST_TRAITS_OF_IMPL_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        let owner_live = live_rust_summary_by_id("owner", "owner_member.summary_id");
        let owner_file = live_rust_member_file_joins("owner", "owner_member", "owner_versions");
        let target_live =
            live_rust_summary_by_key("trait", "owner", "trait_endpoint.target_unit_key");
        let target_file = live_rust_member_file_joins("trait", "trait_member", "trait_versions");
        format!(
            "SELECT DISTINCT trait_blobs.blob_oid, trait_bridge.declaration_id, \
                    trait_member.rel_path \
             FROM main.blobs AS impl_keys \
             CROSS JOIN main.resolution_unit_summary_members AS owner_member \
               INDEXED BY resolution_unit_summary_members_blob \
               ON owner_member.blob_id=impl_keys.id AND owner_member.rel_path=?3 \
             {owner_live} {owner_file} \
             CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS trait_endpoint \
               INDEXED BY rust_resolution_unit_summary_trait_endpoints_impl \
               ON trait_endpoint.summary_id=owner_versions.summary_id \
              AND trait_endpoint.member_ordinal=owner_member.member_ordinal \
              AND trait_endpoint.impl_declaration_id=?2 \
              AND trait_endpoint.endpoint_role='trait' \
              AND trait_endpoint.endpoint_state='resolved' \
             CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS subject_endpoint \
               ON subject_endpoint.summary_id=trait_endpoint.summary_id \
              AND subject_endpoint.member_ordinal=trait_endpoint.member_ordinal \
              AND subject_endpoint.owner_module_path=trait_endpoint.owner_module_path \
              AND subject_endpoint.source_relation_key=trait_endpoint.source_relation_key \
              AND subject_endpoint.endpoint_role='subject' \
              AND subject_endpoint.endpoint_state='resolved' \
             {target_live} \
             CROSS JOIN main.rust_resolution_unit_summary_exports AS trait_export \
               INDEXED BY rust_resolution_unit_summary_exports_identity \
               ON trait_export.summary_id=trait_versions.summary_id \
              AND trait_export.identity_id=trait_endpoint.target_identity_id \
              AND trait_export.module_path=trait_endpoint.target_module_path \
              AND trait_export.namespace='type' AND trait_export.origin='declaration' \
             CROSS JOIN main.resolution_unit_summary_members AS trait_member \
               ON trait_member.summary_id=trait_export.summary_id \
              AND trait_member.member_ordinal=trait_export.declaration_member_ordinal \
             {target_file} \
             CROSS JOIN main.source_native_declaration_bridges AS trait_bridge \
               ON trait_bridge.blob_id=trait_member.blob_id \
              AND trait_bridge.source_site=trait_export.declaration_site \
             WHERE impl_keys.blob_oid=?1"
        )
    });

/// The trait-side head names the impl rows of one placed trait were spelled
/// with. The impl's own route rows keep the spelling; they are reached by the
/// impl blob and the impl site the relation row already carries.
pub(crate) static RUST_TRAIT_IMPL_SPELLINGS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        let target_live = live_rust_summary_by_id("asked", "asked_member.summary_id");
        let target_file = live_rust_member_file_joins("asked", "asked_member", "asked_versions");
        let impl_live = live_rust_summary_by_id("impl", "trait_endpoint.summary_id");
        let impl_file = live_rust_member_file_joins("impl", "impl_member", "impl_versions");
        format!(
            "SELECT DISTINCT spelled.terminal_spelling \
             FROM main.blobs AS asked_keys \
             CROSS JOIN main.source_native_declaration_bridges AS asked \
               INDEXED BY source_native_declaration_bridges_declaration \
               ON asked.blob_id=asked_keys.id AND asked.declaration_id=?2 \
             CROSS JOIN main.resolution_unit_summary_members AS asked_member \
               INDEXED BY resolution_unit_summary_members_blob \
               ON asked_member.blob_id=asked_keys.id AND asked_member.rel_path=?3 \
             {target_live} {target_file} \
             CROSS JOIN main.rust_resolution_unit_summary_exports AS asked_export \
               INDEXED BY rust_resolution_unit_summary_exports_declaration \
               ON asked_export.summary_id=asked_member.summary_id \
              AND asked_export.declaration_member_ordinal=asked_member.member_ordinal \
              AND asked_export.declaration_site=asked.source_site \
              AND asked_export.namespace='type' AND asked_export.origin='declaration' \
             CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS trait_endpoint \
               INDEXED BY rust_resolution_unit_summary_trait_endpoints_target \
               ON trait_endpoint.target_unit_key=asked_versions.unit_key \
              AND trait_endpoint.target_module_path=asked_export.module_path \
              AND trait_endpoint.target_identity_id=asked_export.identity_id \
              AND trait_endpoint.endpoint_role='trait' \
              AND trait_endpoint.endpoint_state='resolved' \
             CROSS JOIN main.rust_resolution_unit_summary_trait_endpoints AS subject_endpoint \
               ON subject_endpoint.summary_id=trait_endpoint.summary_id \
              AND subject_endpoint.member_ordinal=trait_endpoint.member_ordinal \
              AND subject_endpoint.owner_module_path=trait_endpoint.owner_module_path \
              AND subject_endpoint.source_relation_key=trait_endpoint.source_relation_key \
              AND subject_endpoint.endpoint_role='subject' \
              AND subject_endpoint.endpoint_state='resolved' \
             {impl_live} \
             CROSS JOIN main.resolution_unit_summary_members AS impl_member \
               ON impl_member.summary_id=impl_versions.summary_id \
              AND impl_member.member_ordinal=trait_endpoint.member_ordinal \
             {impl_file} \
             CROSS JOIN main.resolution_trait_implementations AS spelled \
               ON spelled.blob_id=impl_member.blob_id \
              AND spelled.relation_key=trait_endpoint.source_relation_key \
              AND spelled.side='trait' AND spelled.terminal_spelling IS NOT NULL \
             WHERE asked_keys.blob_oid=?1"
        )
    });

pub(crate) static RUST_TRAITS_IMPLEMENTED_BY_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| trait_impl_counterpart_sql("subject", "trait"));
pub(crate) static RUST_TYPES_IMPLEMENTING_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| trait_impl_counterpart_sql("trait", "subject"));

fn declaration_candidate_sql(predicate: &str) -> String {
    declaration_candidate_sql_with_order(predicate, "keys.blob_oid, units.unit_key")
}

/// `mounted_declaration_rows_for_langs`'s query. Named so
/// `mounted_declaration_scan_seeks_live_workspace_files` can plan it.
///
/// `live_mounted_declarations` carries every predicate the other candidate
/// queries spell out at the call site -- blob liveness and epoch generation,
/// declaration membership, and the anchor mounting that makes `rel_path` the
/// path this reading was mounted under -- so language scope is the only
/// condition left here, and the blob-completeness `EXISTS` the other shapes
/// bolt on is the liveness the view already joins through. There is no
/// `ORDER BY`: both callers sort and dedup the hydrated units in Rust
/// (`resolve_mounted_candidate_rows`), and sorting a workspace-sized result in
/// SQLite only bought a TEMP B-TREE.
fn mounted_declaration_sql() -> String {
    candidate_rows_sql_with_membership_projection_and_completeness(
        "units",
        "FROM live_mounted_declarations AS units
         JOIN blobs AS keys
           ON keys.id = units.blob_id",
        "units.lang = ?1",
        "TRUE",
        "TRUE",
        "",
        ", units.rel_path",
    )
}

fn mounted_declaration_sql_with_primary_ranges() -> String {
    candidate_rows_sql_with_membership_projection_and_completeness(
        "units",
        "FROM live_mounted_declarations AS units
         JOIN blobs AS keys
           ON keys.id = units.blob_id
         LEFT JOIN unit_ranges AS primary_range
           ON primary_range.blob_id = units.blob_id
          AND primary_range.unit_key = units.unit_key
          AND primary_range.ordinal = 0",
        "units.lang = ?1",
        "TRUE",
        "TRUE",
        "",
        ", units.rel_path, primary_range.start_byte, primary_range.end_byte,
           primary_range.start_line, primary_range.end_line",
    )
}

const CODE_UNIT_CANDIDATE_FROM_CLAUSE: &str = "FROM code_units AS units
     JOIN blobs AS keys
       ON keys.id = units.blob_id
     JOIN blob_meta AS meta
       ON meta.blob_id = units.blob_id";

const DECLARATION_MEMBER_CANDIDATE_FROM_CLAUSE: &str = "FROM code_units AS owner
     JOIN unit_children AS edge
       ON edge.blob_id = owner.blob_id
      AND edge.parent_key = owner.unit_key
     JOIN code_units AS child
       ON child.blob_id = edge.blob_id
      AND child.unit_key = edge.child_key
     JOIN blobs AS keys
       ON keys.id = child.blob_id
     JOIN blob_meta AS meta
       ON meta.blob_id = child.blob_id";

fn declaration_member_owner_predicate(owner_column: &str) -> String {
    format!(
        "owner.lang = ?1 AND owner.{owner_column} = ?2
         AND owner.in_declarations = 1 AND child.identifier = ?3"
    )
}

/// `declaration_candidate_rows_by_identifier_prefix_for_langs`'s query. Named
/// so `identifier_prefix_lookup_seeks_the_identifier_index` can plan it.
fn identifier_prefix_candidate_sql() -> String {
    candidate_rows_sql_with_membership(
        "units",
        CODE_UNIT_CANDIDATE_FROM_CLAUSE,
        "units.lang = ?1 AND units.identifier >= ?2 AND units.identifier < ?3",
        "(units.in_declarations = 1 OR units.in_definition_lookup = 1)",
        "keys.blob_oid, units.unit_key",
    )
}

#[cfg(any(test, feature = "test-support"))]
fn limited_identifier_candidate_for_blob_sql() -> String {
    limited_candidate_rows_sql_with_membership(
        "units",
        CODE_UNIT_CANDIDATE_FROM_CLAUSE,
        "units.lang = ?1 AND units.identifier = ?2 AND keys.blob_oid = ?3",
        "(units.in_declarations = 1 OR units.in_definition_lookup = 1)",
        &["keys.blob_oid", "units.unit_key"],
    )
}

#[doc(hidden)]
pub fn limited_identifier_candidate_sql() -> String {
    format!(
        "{} LIMIT (
           SELECT request_limit
           FROM temp.declaration_candidate_requests
           ORDER BY request_ordinal
           LIMIT 1
         )",
        limited_candidate_rows_sql_with_membership(
            "units",
            "FROM temp.declaration_candidate_requests AS requested
             CROSS JOIN code_units AS units
             JOIN blobs AS keys
               ON keys.id = units.blob_id
             JOIN blob_meta AS meta
               ON meta.blob_id = units.blob_id",
            "units.lang = requested.lang AND units.identifier = requested.identifier",
            "(units.in_declarations = 1 OR units.in_definition_lookup = 1)",
            &[
                "requested.request_ordinal",
                "keys.blob_oid",
                "units.unit_key",
            ],
        )
    )
}

/// The least string greater than every string starting with `prefix`, under
/// SQLite's BINARY collation, so that `col >= prefix AND col < successor` is
/// an index range over exactly the prefix matches.
///
/// `None` when `prefix` is empty or ends in a byte with no successor that
/// keeps the result valid UTF-8 (`0x7f`, or any continuation byte of a
/// multi-byte character).
fn byte_successor(prefix: &str) -> Option<String> {
    let last = *prefix.as_bytes().last()?;
    if !last.is_ascii() || last == 0x7f {
        return None;
    }
    let mut bytes = prefix.as_bytes().to_vec();
    *bytes.last_mut().expect("prefix is non-empty") = last + 1;
    String::from_utf8(bytes).ok()
}

fn limited_declaration_candidate_sql(predicate: &str) -> String {
    limited_candidate_rows_sql_with_membership(
        "units",
        CODE_UNIT_CANDIDATE_FROM_CLAUSE,
        predicate,
        "units.in_declarations = 1",
        &["keys.blob_oid", "units.unit_key"],
    )
}

fn declaration_candidate_sql_with_order(predicate: &str, order_by: &str) -> String {
    candidate_rows_sql_with_membership(
        "units",
        CODE_UNIT_CANDIDATE_FROM_CLAUSE,
        predicate,
        "units.in_declarations = 1",
        order_by,
    )
}

fn candidate_rows_sql(candidate_alias: &str, from_clause: &str, predicate: &str) -> String {
    candidate_rows_sql_with_membership(
        candidate_alias,
        from_clause,
        predicate,
        &format!("{candidate_alias}.in_declarations = 1"),
        &format!("keys.blob_oid, {candidate_alias}.unit_key"),
    )
}

fn candidate_rows_sql_with_membership(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    order_by: &str,
) -> String {
    candidate_rows_sql_with_membership_and_projection(
        candidate_alias,
        from_clause,
        predicate,
        membership,
        order_by,
        "",
    )
}

fn limited_candidate_rows_sql_with_membership(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    order_by: &[&str],
) -> String {
    limited_candidate_rows_sql_with_membership_and_cte_prefix(
        candidate_alias,
        from_clause,
        predicate,
        membership,
        order_by,
        "",
    )
}

fn limited_candidate_rows_sql_with_membership_and_cte_prefix(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    order_by: &[&str],
    cte_prefix: &str,
) -> String {
    let row_bytes = format!(
        "length(CAST(keys.blob_oid AS BLOB))
         + length(CAST({candidate_alias}.lang AS BLOB))
         + length(CAST({candidate_alias}.short_name AS BLOB))
         + length(CAST({candidate_alias}.content_qualifier AS BLOB))
         + COALESCE(length(CAST({candidate_alias}.signature AS BLOB)), 0)
         + {candidate_alias}.fq_segment_bytes"
    );
    let admitted = |column: &str| {
        format!(
            "CASE WHEN bounded.row_bytes <= {MAX_LIMITED_QUERY_ROW_BYTES}
                  THEN bounded.{column}
                  ELSE NULL
             END"
        )
    };
    assert!(!order_by.is_empty());
    let order_projection = order_by
        .iter()
        .enumerate()
        .map(|(ordinal, expression)| format!(", {expression} AS result_order_{ordinal}"))
        .collect::<String>();
    let bounded_order = (0..order_by.len())
        .map(|ordinal| format!("bounded.result_order_{ordinal}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH {cte_prefix}bounded AS MATERIALIZED (
           SELECT keys.blob_oid, {candidate_alias}.lang,
                  {candidate_alias}.unit_key, {candidate_alias}.kind,
                  {candidate_alias}.short_name, {candidate_alias}.content_qualifier,
                  {candidate_alias}.signature, {candidate_alias}.synthetic,
                  {candidate_alias}.is_type_alias, {candidate_alias}.top_level_ordinal,
                  {candidate_alias}.in_declarations,
                  {candidate_alias}.in_definition_lookup,
                  {candidate_alias}.fq_anchor_kind, {candidate_alias}.fq_anchor_pop,
                  {candidate_alias}.fq_package_tail_segments,
                  {candidate_alias}.fq_segment_count, {candidate_alias}.exact_fqn_tail,
                  {candidate_alias}.fq_segment_bytes, {candidate_alias}.normalized_fqn_tail
                  {order_projection},
                  ({row_bytes}) AS row_bytes
           {from_clause}
           WHERE {predicate} AND {membership}
             AND {PARSED_BLOB_COMPLETE_CONDITION}
         )
         SELECT {}, {}, bounded.unit_key,
                bounded.kind, {},
                {}, {},
                bounded.synthetic, bounded.is_type_alias,
                bounded.top_level_ordinal, bounded.in_declarations,
                bounded.in_definition_lookup, bounded.fq_anchor_kind,
                bounded.fq_anchor_pop, bounded.fq_package_tail_segments,
                bounded.fq_segment_count, bounded.exact_fqn_tail,
                bounded.fq_segment_bytes, bounded.normalized_fqn_tail,
                bounded.row_bytes
         FROM bounded
         ORDER BY {bounded_order}",
        admitted("blob_oid"),
        admitted("lang"),
        admitted("short_name"),
        admitted("content_qualifier"),
        admitted("signature"),
    )
}

fn candidate_rows_sql_with_membership_and_projection(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    order_by: &str,
    extra_projection: &str,
) -> String {
    candidate_rows_sql_with_membership_projection_and_completeness(
        candidate_alias,
        from_clause,
        predicate,
        membership,
        PARSED_BLOB_COMPLETE_CONDITION,
        order_by,
        extra_projection,
    )
}

fn candidate_rows_sql_with_membership_projection_and_completeness(
    candidate_alias: &str,
    from_clause: &str,
    predicate: &str,
    membership: &str,
    completeness: &str,
    order_by: &str,
    extra_projection: &str,
) -> String {
    let candidate_projection = candidate_unit_projection_sql(candidate_alias);
    let order_by = if order_by.is_empty() {
        String::new()
    } else {
        format!("ORDER BY {order_by}")
    };
    format!(
        "SELECT keys.blob_oid, {candidate_projection}{extra_projection}
         {from_clause}
         WHERE {predicate} AND {membership}
           AND {completeness}
         {order_by}"
    )
}

fn candidate_unit_projection_sql(candidate_alias: &str) -> String {
    format!(
        "{candidate_alias}.lang, {candidate_alias}.unit_key,
         {candidate_alias}.kind, {candidate_alias}.short_name,
         {candidate_alias}.content_qualifier, {candidate_alias}.signature,
         {candidate_alias}.synthetic, {candidate_alias}.is_type_alias,
         {candidate_alias}.top_level_ordinal, {candidate_alias}.in_declarations,
         {candidate_alias}.in_definition_lookup,
         {candidate_alias}.fq_anchor_kind, {candidate_alias}.fq_anchor_pop,
         {candidate_alias}.fq_package_tail_segments,
         {candidate_alias}.fq_segment_count, {candidate_alias}.exact_fqn_tail,
         {candidate_alias}.fq_segment_bytes,
         {candidate_alias}.normalized_fqn_tail"
    )
}

#[cfg(any(test, feature = "test-support"))]
fn definition_order_candidate_sql(view: &str, predicate: &str, membership: &str) -> String {
    candidate_rows_sql_with_membership_and_projection(
        "units",
        &format!(
            "FROM {view} AS names
         JOIN code_units AS units
           ON units.blob_id = names.blob_id
          AND units.unit_key = names.unit_key
         JOIN blobs AS keys
           ON keys.id = units.blob_id
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id"
        ),
        predicate,
        membership,
        "keys.blob_oid, units.unit_key, names.prefix",
        ",
                (SELECT MIN(ranges.start_byte)
                 FROM unit_ranges AS ranges
                 WHERE ranges.blob_id = units.blob_id
                   AND ranges.unit_key = units.unit_key) AS first_start_byte,
                names.prefix",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderedTailMatch {
    Exact,
    NormalizedStored,
    NormalizedExact,
}

impl RenderedTailMatch {
    fn index(self) -> usize {
        match self {
            Self::Exact => 0,
            Self::NormalizedStored => 1,
            Self::NormalizedExact => 2,
        }
    }
}

fn rendered_name_components(name: &str, normalized: bool) -> Vec<RenderedNameComponent> {
    let mut components = Vec::new();
    let mut push = |prefix: &str, tail: &str, anchored: bool| {
        if tail.is_empty() {
            return;
        }
        components.push(RenderedNameComponent {
            prefix: prefix.to_string(),
            tail: tail.to_string(),
            normalized,
            normalized_exact_fallback: false,
            anchored,
        });
    };
    // A content-derived stable identity and a file mounted at the empty
    // workspace package can render the same complete request. They are
    // separate indexed relations, so retain both exact alternatives.
    push("", name, false);
    push("", name, true);
    for (index, character) in name.char_indices() {
        let separator_len = match character {
            '.' | '/' | '$' => 1,
            ':' if name[index..].starts_with("::") => 2,
            _ => continue,
        };
        let tail_start = index + separator_len;
        if index > 0 && tail_start < name.len() {
            push(&name[..index], &name[tail_start..], true);
        }
    }
    // A mounted module or package declaration can be represented entirely by
    // its workspace anchor, with no content-derived FQ-name tail. This remains
    // a bounded anchored seek; final hydrated identity comparison decides
    // whether the empty-tail row actually renders as the request.
    components.push(RenderedNameComponent {
        prefix: name.to_string(),
        tail: String::new(),
        normalized,
        normalized_exact_fallback: false,
        anchored: true,
    });
    components
}

fn rendered_definition_components(
    request_index: usize,
    request: &RenderedDefinitionRequest,
) -> Vec<(usize, RenderedNameComponent)> {
    if !request.seekable {
        return Vec::new();
    }
    let mut components = rendered_name_components(&request.exact_name, false)
        .into_iter()
        .map(|component| (request_index, component))
        .collect::<Vec<_>>();
    // A request that is already in normalized spelling must still probe the
    // normalized-tail relation: the stored declaration can have a distinct
    // exact spelling even though normalizing the request itself is a no-op.
    components.extend(
        rendered_name_components(&request.normalized_name, true)
            .into_iter()
            .map(|mut component| {
                component.normalized_exact_fallback = request.normalized_name != request.exact_name;
                (request_index, component)
            }),
    );
    components
}

fn component_tail_predicate(
    tail_match: RenderedTailMatch,
    request_tail: &str,
    stable: bool,
) -> String {
    let exact_tail = if stable {
        // Match the stable component index's expression exactly. Keeping this
        // equality out of the ordinary column's planner vocabulary prevents
        // the index from stealing parent-tail plans in shared relational
        // views; exact_fqn_tail is non-NULL in every component arm.
        "COALESCE(units.exact_fqn_tail, '')"
    } else {
        "units.exact_fqn_tail"
    };
    match tail_match {
        RenderedTailMatch::Exact => format!("{exact_tail} = {request_tail}"),
        RenderedTailMatch::NormalizedStored => {
            format!("units.normalized_fqn_tail = {request_tail}")
        }
        RenderedTailMatch::NormalizedExact => format!(
            "units.normalized_fqn_tail IS NULL
             AND {exact_tail} = {request_tail}"
        ),
    }
}

fn component_definition_candidate_projection(
    from_clause: &str,
    predicate: &str,
    membership: &str,
    mounted_prefix: &str,
    request_index: &str,
) -> String {
    candidate_rows_sql_with_membership_projection_and_completeness(
        "units",
        from_clause,
        predicate,
        membership,
        "meta.is_complete = 1",
        "",
        &format!(
            ",
             (SELECT MIN(ranges.start_byte)
              FROM unit_ranges AS ranges
              WHERE ranges.blob_id = units.blob_id
                AND ranges.unit_key = units.unit_key) AS first_start_byte,
             {mounted_prefix} AS mounted_prefix,
             {request_index} AS request_index"
        ),
    )
}

fn build_point_component_definition_candidate_sql(
    anchored: bool,
    tail_match: RenderedTailMatch,
    membership: &str,
) -> String {
    let tail_parameter = if anchored { "?4" } else { "?3" };
    let tail_predicate = component_tail_predicate(tail_match, tail_parameter, !anchored);
    if anchored {
        let unit_source = match tail_match {
            RenderedTailMatch::Exact | RenderedTailMatch::NormalizedExact => {
                "code_units AS units INDEXED BY idx_code_units_anchored_blob_exact_tail"
            }
            RenderedTailMatch::NormalizedStored => "code_units AS units",
        };
        // The anchor package seek must stay the outermost loop. Left to its own cost
        // model the planner drives from workspace_files, which enumerates every
        // per-language workspace file version for each probe (#2742). CROSS JOIN is
        // SQLite's documented directive to keep the written join order.
        component_definition_candidate_projection(
            &point_anchored_definition_from_clause(unit_source),
            &format!(
                "anchors.lang = ?1
                 AND anchors.generation = ?2
                 AND anchors.package_name = ?3
                 AND units.fq_anchor_kind IS NOT NULL
                 AND {tail_predicate}"
            ),
            membership,
            "anchors.package_name",
            "0",
        )
    } else {
        let unit_source = match tail_match {
            RenderedTailMatch::Exact | RenderedTailMatch::NormalizedExact => {
                "code_units AS units INDEXED BY idx_code_units_stable_exact_tail"
            }
            RenderedTailMatch::NormalizedStored => {
                "code_units AS units INDEXED BY idx_code_units_stable_normalized_tail"
            }
        };
        component_definition_candidate_projection(
            &format!(
                "FROM {unit_source}
             JOIN blobs AS keys
               ON keys.id = units.blob_id
              AND keys.generation = ?2
             JOIN blob_meta AS meta
               ON meta.blob_id = units.blob_id"
            ),
            &format!(
                "units.lang = ?1
                 AND units.fq_anchor_kind IS NULL
                 AND units.exact_fqn_tail IS NOT NULL
                 AND {tail_predicate}
                 AND EXISTS (
                   SELECT 1
                   FROM workspace_files AS files
                   WHERE files.lang = keys.lang
                     AND files.generation = ?2
                     AND files.blob_oid = keys.blob_oid
                 )"
            ),
            membership,
            "''",
            "0",
        )
    }
}

fn point_component_definition_candidate_sql(
    anchored: bool,
    tail_match: RenderedTailMatch,
    membership: &str,
) -> &'static str {
    static SQL: LazyLock<[[[String; 3]; 2]; 2]> = LazyLock::new(|| {
        std::array::from_fn(|membership_index| {
            let membership = if membership_index == 0 {
                "units.in_declarations = 1"
            } else {
                "(units.in_declarations = 1 OR units.in_definition_lookup = 1)"
            };
            std::array::from_fn(|anchored_index| {
                std::array::from_fn(|tail_index| {
                    let tail_match = match tail_index {
                        0 => RenderedTailMatch::Exact,
                        1 => RenderedTailMatch::NormalizedStored,
                        2 => RenderedTailMatch::NormalizedExact,
                        _ => unreachable!(),
                    };
                    build_point_component_definition_candidate_sql(
                        anchored_index == 1,
                        tail_match,
                        membership,
                    )
                })
            })
        })
    });
    let membership_index = match membership {
        "units.in_declarations = 1" => 0,
        "(units.in_declarations = 1 OR units.in_definition_lookup = 1)" => 1,
        _ => unreachable!("component lookup has one of two membership contracts"),
    };
    &SQL[membership_index][usize::from(anchored)][tail_match.index()]
}

fn point_anchor_only_definition_candidate_sql(membership: &str) -> &'static str {
    static SQL: LazyLock<[String; 2]> = LazyLock::new(|| {
        std::array::from_fn(|membership_index| {
            let membership = if membership_index == 0 {
                "units.in_declarations = 1"
            } else {
                "(units.in_declarations = 1 OR units.in_definition_lookup = 1)"
            };
            // Same join-order constraint as the anchored component lookup (#2742):
            // the package seek is the selective entry point and must stay outermost.
            component_definition_candidate_projection(
                &point_anchored_definition_from_clause("code_units AS units"),
                "anchors.lang = ?1
                 AND anchors.generation = ?2
                 AND anchors.package_name = ?3
                 AND units.fq_anchor_kind IS NOT NULL
                 AND units.exact_fqn_tail IS NULL",
                membership,
                "anchors.package_name",
                "0",
            )
        })
    });
    let membership_index = match membership {
        "units.in_declarations = 1" => 0,
        "(units.in_declarations = 1 OR units.in_definition_lookup = 1)" => 1,
        _ => unreachable!("anchor-only lookup has one of two membership contracts"),
    };
    &SQL[membership_index]
}

fn point_anchored_definition_from_clause(unit_source: &str) -> String {
    format!(
        "FROM workspace_file_anchors AS anchors
         CROSS JOIN workspace_files AS files
           ON files.lang = anchors.lang
          AND files.generation = anchors.generation
          AND files.file_id = anchors.file_id
         CROSS JOIN blobs AS keys
           ON keys.blob_oid = files.blob_oid
          AND keys.lang = files.lang
          AND keys.generation = ?2
         CROSS JOIN {unit_source}
           ON units.blob_id = keys.id
          AND units.fq_anchor_kind = anchors.anchor_kind
          AND units.fq_anchor_pop = anchors.anchor_pop
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id"
    )
}

fn batch_component_definition_candidate_sql(
    anchored: bool,
    tail_match: RenderedTailMatch,
    membership: &str,
) -> String {
    let normalized = match tail_match {
        RenderedTailMatch::Exact => 0,
        RenderedTailMatch::NormalizedStored | RenderedTailMatch::NormalizedExact => 1,
    };
    let tail_predicate = component_tail_predicate(tail_match, "requests.tail", !anchored);
    let select = if anchored {
        let unit_source = match tail_match {
            RenderedTailMatch::Exact | RenderedTailMatch::NormalizedExact => {
                "code_units AS units INDEXED BY idx_code_units_anchored_blob_exact_tail"
            }
            RenderedTailMatch::NormalizedStored => "code_units AS units",
        };
        // The materialized request rows must drive the anchor package seek, and that
        // seek must stay above the file and unit loops. Without the directive the
        // planner enumerates every per-language workspace file version and every
        // anchored unit in it before it consults a request prefix (#2742).
        component_definition_candidate_projection(
            &batch_anchored_definition_from_clause(unit_source),
            &format!(
                "requests.anchored = 1
                 AND requests.tail <> ''
                 AND requests.normalized = {normalized}
                 AND units.fq_anchor_kind IS NOT NULL
                 AND {tail_predicate}"
            ),
            membership,
            "anchors.package_name",
            "requests.request_index",
        )
    } else {
        let unit_source = match tail_match {
            RenderedTailMatch::Exact | RenderedTailMatch::NormalizedExact => {
                "code_units AS units INDEXED BY idx_code_units_stable_exact_tail"
            }
            RenderedTailMatch::NormalizedStored => {
                "code_units AS units INDEXED BY idx_code_units_stable_normalized_tail"
            }
        };
        // The request rows must drive the tail seek, the same constraint the
        // anchored arm above states with its own CROSS JOIN (#2742). Left as a
        // plain join, a store with no planner statistics reads `code_units`
        // through the language prefix of the tail index alone -- every unit of
        // the language -- builds an AUTOMATIC PARTIAL COVERING INDEX over the
        // materialized request rows, and probes that index once per unit. That
        // is the plan the `laravel/framework` store produces without
        // statistics, and the one behind the 40 to 58 second calls in issue
        // #3016's profile; with statistics SQLite picks the requests-first
        // order on its own, so this directive only removes its freedom to pick
        // the other one (issue #3030).
        component_definition_candidate_projection(
            &format!(
                "FROM requests
             CROSS JOIN {unit_source}
               ON units.lang = ?2
             JOIN blobs AS keys
               ON keys.id = units.blob_id
              AND keys.generation = ?3
             JOIN blob_meta AS meta
               ON meta.blob_id = units.blob_id"
            ),
            &format!(
                "requests.anchored = 0
                 AND requests.normalized = {normalized}
                 AND units.fq_anchor_kind IS NULL
                 AND units.exact_fqn_tail IS NOT NULL
                 AND {tail_predicate}
                 AND EXISTS (
                   SELECT 1
                   FROM workspace_files AS files
                   WHERE files.lang = keys.lang
                     AND files.generation = ?3
                     AND files.blob_oid = keys.blob_oid
                 )"
            ),
            membership,
            "''",
            "requests.request_index",
        )
    };
    format!(
        "WITH requests(request_index, prefix, tail, normalized, anchored) AS MATERIALIZED (
           SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'),
                  json_extract(value, '$[2]'), json_extract(value, '$[3]'),
                  json_extract(value, '$[4]')
           FROM json_each(?1)
         )
         {select}"
    )
}

fn batch_anchor_only_definition_candidate_sql(membership: &str) -> String {
    // Same join-order constraint as the anchored batch component lookup (#2742).
    let select = component_definition_candidate_projection(
        &batch_anchored_definition_from_clause("code_units AS units"),
        "requests.anchored = 1
         AND requests.normalized = 0
         AND requests.tail = ''
         AND units.fq_anchor_kind IS NOT NULL
         AND units.exact_fqn_tail IS NULL",
        membership,
        "anchors.package_name",
        "requests.request_index",
    );
    format!(
        "WITH requests(request_index, prefix, tail, normalized, anchored) AS MATERIALIZED (
           SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]'),
                  json_extract(value, '$[2]'), json_extract(value, '$[3]'),
                  json_extract(value, '$[4]')
           FROM json_each(?1)
         )
         {select}"
    )
}

fn batch_anchored_definition_from_clause(unit_source: &str) -> String {
    format!(
        "FROM requests
         CROSS JOIN workspace_file_anchors AS anchors
           ON anchors.lang = ?2
          AND anchors.generation = ?3
          AND anchors.package_name = requests.prefix
         CROSS JOIN workspace_files AS files
           ON files.lang = anchors.lang
          AND files.generation = anchors.generation
          AND files.file_id = anchors.file_id
         CROSS JOIN blobs AS keys
           ON keys.blob_oid = files.blob_oid
          AND keys.lang = files.lang
          AND keys.generation = ?3
         CROSS JOIN {unit_source}
           ON units.blob_id = keys.id
          AND units.fq_anchor_kind = anchors.anchor_kind
          AND units.fq_anchor_pop = anchors.anchor_pop
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id"
    )
}

type RenderedDefinitionCandidateHeader = (CandidateRow, (usize, Option<usize>, String));

fn collect_rendered_definition_candidate_rows<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    parameters: P,
    rows: &mut Vec<RenderedDefinitionCandidateHeader>,
    cancellation: Option<&CancellationToken>,
) -> Result<bool> {
    let mapped = statement.query_map(parameters, |row| {
        let first_start_byte = row
            .get::<_, Option<i64>>(19)?
            .map(i64_to_usize)
            .transpose()
            .map_err(rusqlite_error_from_store)?;
        Ok((
            candidate_row_from_row(row)?,
            (
                row.get::<_, usize>(21)?,
                first_start_byte,
                row.get::<_, String>(20)?,
            ),
        ))
    })?;
    for row in mapped {
        rows.push(row?);
        if rows
            .len()
            .is_multiple_of(CANDIDATE_ROWS_PER_CANCELLATION_POLL)
            && cancellation.is_some_and(CancellationToken::is_cancelled)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn candidate_rows_for_languages<'a>(
    conn: &Connection,
    langs: impl IntoIterator<Item = &'a str>,
    sql: &str,
    values: &[&dyn ToSql],
) -> Result<Vec<HydratedCandidateRow>> {
    let rows = candidate_rows_for_languages_with(conn, langs, sql, values, candidate_row_from_row)?;
    Ok(hydrate_candidate_rows(conn, rows, None)?
        .expect("uncancelled candidate hydration completes"))
}

fn candidate_rows_for_languages_with<'a, T>(
    conn: &Connection,
    langs: impl IntoIterator<Item = &'a str>,
    sql: &str,
    values: &[&dyn ToSql],
    mut row_from_row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut statement = conn.prepare_cached(sql)?;
    let mut rows = Vec::new();
    for lang in langs {
        let params = std::iter::once(&lang as &dyn ToSql).chain(values.iter().copied());
        rows.extend(collect_mapped_rows(
            statement.query_map(params_from_iter(params), &mut row_from_row)?,
        )?);
    }
    Ok(rows)
}

#[doc(hidden)]
pub fn candidate_rows_for_identifier_languages_limited(
    conn: &Connection,
    langs: &[String],
    identifier: &str,
    sql: &str,
    limit: usize,
) -> Result<LimitedQueryRows<HydratedCandidateRow>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }

    ensure_declaration_candidate_requests_table(conn)?;
    conn.execute("DELETE FROM temp.declaration_candidate_requests", [])?;
    {
        let mut insert = conn.prepare_cached(
            "INSERT INTO temp.declaration_candidate_requests(
               request_ordinal, lang, identifier, request_limit
             ) VALUES (?1, ?2, ?3, ?4)",
        )?;
        let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
        if langs.is_empty() {
            insert.execute(params![
                0_i64,
                Option::<String>::None,
                Option::<String>::None,
                sql_limit
            ])?;
        }
        for (ordinal, lang) in langs.iter().enumerate() {
            insert.execute(params![usize_to_i64(ordinal)?, lang, identifier, sql_limit])?;
        }
    }

    let mut statement = conn.prepare_cached(sql)?;
    let mut query = statement.query([])?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut bytes = LimitedQueryByteBudget::default();
    let mut complete = true;
    while let Some(row) = query.next()? {
        inspected = inspected.saturating_add(1);
        // The relational FQ header occupies 12..=18; row bytes follow.
        if !bytes.admit_sqlite_bytes(row.get::<_, i64>(19)?)? {
            complete = false;
            break;
        }
        rows.push(candidate_row_from_row(row)?);
    }
    drop(query);
    if inspected == limit {
        complete = false;
    }
    drop(statement);
    let rows = hydrate_candidate_rows(conn, rows, None)?
        .expect("uncancelled candidate hydration completes");
    conn.execute("DELETE FROM temp.declaration_candidate_requests", [])?;
    if complete {
        Ok(LimitedQueryRows::complete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    }
}

fn ensure_declaration_candidate_requests_table(conn: &Connection) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM temp.sqlite_schema
           WHERE type = 'table' AND name = 'declaration_candidate_requests'
         )",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        conn.execute_batch(
            "CREATE TEMP TABLE declaration_candidate_requests(
           request_ordinal INTEGER PRIMARY KEY,
           lang TEXT,
           identifier TEXT,
           request_limit INTEGER NOT NULL
         ) WITHOUT ROWID;",
        )?;
    }
    Ok(())
}

fn candidate_rows_for_languages_limited<'a>(
    conn: &Connection,
    langs: impl IntoIterator<Item = &'a str>,
    sql: &str,
    values: &[&dyn ToSql],
    limit: usize,
) -> Result<LimitedQueryRows<HydratedCandidateRow>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }

    let mut statement = conn.prepare_cached(sql)?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut bytes = LimitedQueryByteBudget::default();
    let mut complete = true;
    'languages: for lang in langs {
        let remaining = limit.saturating_sub(inspected);
        if remaining == 0 {
            complete = false;
            break;
        }
        let sql_limit = i64::try_from(remaining).unwrap_or(i64::MAX);
        let params = std::iter::once(&lang as &dyn ToSql)
            .chain(values.iter().copied())
            .chain(std::iter::once(&sql_limit as &dyn ToSql));
        let mut query = statement.query(params_from_iter(params))?;
        while let Some(row) = query.next()? {
            inspected = inspected.saturating_add(1);
            // The relational FQ header occupies 12..=18; row bytes follow.
            let row_bytes = row.get::<_, i64>(19)?;
            if !bytes.admit_sqlite_bytes(row_bytes)? {
                complete = false;
                break 'languages;
            }
            rows.push(candidate_row_from_row(row)?);
        }
        drop(query);
        if inspected == limit {
            complete = false;
            break;
        }
    }
    let rows = hydrate_candidate_rows(conn, rows, None)?
        .expect("uncancelled candidate hydration completes");
    if complete {
        Ok(LimitedQueryRows::complete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    }
}

/// Rows walked between two deadline checks inside one candidate-row seek.
///
/// The seek for one short name is a single statement, and on a large workspace
/// a hot name makes it a long one: `main` on the rustc tree reads 22k rows in
/// 1.14 s. That read is issued from inside the import-graph candidate walk,
/// which polls its deadline once per candidate file -- so the walk stopped on
/// time and the read it had already started did not, and the whole of
/// `scan_usages`' 0.57 s budget overshoot was that one read finishing. A
/// deadline is only honoured at the granularity of the longest thing that
/// ignores it, so the seek polls too. 512 rows is well under a millisecond of
/// row decoding and costs one `Instant::now` per 512 rows on the completing
/// path.
#[doc(hidden)]
pub const CANDIDATE_ROWS_PER_CANCELLATION_POLL: usize = 512;

#[cfg(any(test, feature = "test-support"))]
fn definition_order_candidate_rows_for_languages<'a>(
    conn: &Connection,
    langs: impl IntoIterator<Item = &'a str>,
    sqls: &[&str],
    values: &[&dyn ToSql],
    cancellation: Option<&CancellationToken>,
) -> Result<LimitedQueryRows<DefinitionOrderCandidateRow>> {
    let mut rows = Vec::new();
    for lang in langs {
        for &sql in sqls {
            let mut statement = conn.prepare_cached(sql)?;
            let params = std::iter::once(&lang as &dyn ToSql).chain(values.iter().copied());
            let mapped = statement.query_map(
                params_from_iter(params),
                definition_order_candidate_row_from_row,
            )?;
            for row in mapped {
                rows.push(row?);
                if rows
                    .len()
                    .is_multiple_of(CANDIDATE_ROWS_PER_CANCELLATION_POLL)
                    && cancellation.is_some_and(CancellationToken::is_cancelled)
                {
                    let inspected = rows.len();
                    return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
                }
            }
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            let inspected = rows.len();
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        }
    }
    let inspected = rows.len();
    Ok(LimitedQueryRows::complete(rows, inspected))
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub enum PersistedLookupKey {
    ExactFqn,
    NormalizedFqn,
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct StoredUnit {
    #[doc(hidden)]
    pub key: i64,
    #[doc(hidden)]
    pub unit: CodeUnit,
    #[doc(hidden)]
    pub is_type_alias: bool,
    #[doc(hidden)]
    pub top_level_ordinal: Option<usize>,
    #[doc(hidden)]
    pub in_declarations: bool,
    #[doc(hidden)]
    pub in_definition_lookup: bool,
    #[doc(hidden)]
    pub in_test_region: bool,
}

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PreparedUnitRow {
    #[doc(hidden)]
    pub key: i64,
    #[doc(hidden)]
    pub kind: i64,
    #[doc(hidden)]
    pub short_name: String,
    #[doc(hidden)]
    pub identifier: String,
    #[doc(hidden)]
    pub content_qualifier: String,
    #[doc(hidden)]
    pub exact_fqn: Option<String>,
    #[doc(hidden)]
    pub normalized_fqn: Option<String>,
    #[doc(hidden)]
    pub simple_type_name: Option<String>,
    #[doc(hidden)]
    pub signature: Option<String>,
    #[doc(hidden)]
    pub synthetic: i64,
    #[doc(hidden)]
    pub is_type_alias: i64,
    #[doc(hidden)]
    pub top_level_ordinal: Option<i64>,
    #[doc(hidden)]
    pub in_declarations: i64,
    #[doc(hidden)]
    pub in_definition_lookup: i64,
    #[doc(hidden)]
    pub in_test_region: i64,
    #[doc(hidden)]
    pub fq_segment_count: i64,
    #[doc(hidden)]
    pub fq_segment_bytes: i64,
    #[doc(hidden)]
    pub fq_anchor_kind: Option<&'static str>,
    #[doc(hidden)]
    pub fq_anchor_pop: Option<i64>,
    #[doc(hidden)]
    pub fq_package_tail_segments: Option<i64>,
    #[doc(hidden)]
    pub exact_fqn_tail: Option<String>,
    #[doc(hidden)]
    pub normalized_fqn_tail: Option<String>,
    #[doc(hidden)]
    pub exact_parent_fqn_tail: Option<String>,
    #[doc(hidden)]
    pub normalized_parent_fqn_tail: Option<String>,
    #[doc(hidden)]
    pub package_fqn_tail: Option<String>,
    /// `(ordinal, kind, text)` rows for `code_unit_fq_segments`.
    #[doc(hidden)]
    pub relational_fq_segments: Vec<(i64, &'static str, String)>,
}

/// The `rust_*` fact tables' rows for one blob, converted from
/// [`RustUsageFacts`] and validated for SQLite
/// binding.
///
/// Built during preparation rather than inside the write transaction, like
/// every other row shape here: the byte-offset conversions are the only thing
/// that can fail, and failing them must not abort a batch mid-commit. Empty for
/// every language except Rust.
#[derive(Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct RustFactRows {
    exports: Vec<RustExportRow>,
    import_targets: Vec<RustImportTargetRow>,
    /// `(identifier, context_mask)`
    identifier_occurrences: Vec<(String, i64)>,
    /// Canonical item-macro links. Module projections are source-owned.
    module_routes: RustModuleRouteRows,
    /// The `rust_include_edges` rows, each carrying its
    /// `rust_include_host_bindings` rows.
    include_edges: Vec<RustIncludeEdgeRow>,
}

/// One `rust_include_edges` row and the host bindings that hang off it.
#[derive(Debug, PartialEq, Eq)]
struct RustIncludeEdgeRow {
    ordinal: i64,
    relative_path: String,
    file_name: String,
    include_start: i64,
    host_bindings: Vec<RustIncludeHostBindingRow>,
}

/// One `rust_include_host_bindings` row.
#[derive(Debug, PartialEq, Eq)]
struct RustIncludeHostBindingRow {
    ordinal: i64,
    local_name: String,
    module_specifier: String,
    imported_name: Option<String>,
    scope_start: i64,
    kind: String,
}

/// The item-macro projection rows for one blob.
#[derive(Debug, Default, PartialEq, Eq)]
struct RustModuleRouteRows {
    item_macros: Vec<RustItemMacroRow>,
}

/// One `rust_item_macros` row.
#[derive(Debug, PartialEq, Eq)]
struct RustItemMacroRow {
    ordinal: i64,
    macro_name: String,
    passthrough: i64,
    arguments_only: i64,
    decoration_cfg: Option<String>,
    declares_no_item: i64,
    writes_only_impls: i64,
    declaration_id: i64,
}

/// One `rust_exports` row.
#[derive(Debug, PartialEq, Eq)]
struct RustExportRow {
    ordinal: i64,
    exported_name: Option<String>,
    source_path: Option<String>,
    imported_name: Option<String>,
    is_glob: Option<i64>,
    source_import_id: Option<i64>,
}

/// One `rust_import_targets` row. Canonical source/context links replace
/// legacy import properties; module_path and bound_name are indexed headers.
/// A grouped `self` import stores its complete module path so source views can
/// distinguish it from an import of the path's final segment.
#[derive(Debug, PartialEq, Eq)]
struct RustImportTargetRow {
    ordinal: i64,
    module_path: String,
    bound_name: Option<String>,
    imported_name: Option<String>,
    is_glob: Option<i64>,
    leading_absolute: Option<i64>,
    is_extern_crate: Option<i64>,
    is_macro_use: Option<i64>,
    visibility: Option<String>,
    cfg_condition: Option<String>,
    owner_module: Option<String>,
    owner_start: Option<i64>,
    owner_end: Option<i64>,
    local_start: Option<i64>,
    local_end: Option<i64>,
    declaration_occurrence_id: Option<i64>,
    target_occurrence_id: Option<i64>,
    alias_occurrence_id: Option<i64>,
    source_import_id: Option<i64>,
    source_context_occurrence_id: Option<i64>,
    declaration_start_byte: Option<i64>,
    declaration_end_byte: Option<i64>,
    target_start_byte: Option<i64>,
    target_end_byte: Option<i64>,
    alias_start_byte: Option<i64>,
    alias_end_byte: Option<i64>,
}

fn import_projection_source(
    id: Option<SourceImportId>,
    imports: Option<&[SourceImportFact]>,
) -> Option<&SourceImportFact> {
    match (id, imports) {
        (Some(id), Some(imports)) => Some(&imports[id.index()]),
        (None, None) => None,
        _ => panic!("canonical Rust import projections require both a source ID and source arena"),
    }
}

fn rust_import_bound_name(import: &SourceImportFact) -> Option<&String> {
    if import.is_wildcard || import.alias.as_deref() == Some("_") {
        None
    } else {
        import.alias.as_ref().or(import.identifier.as_ref())
    }
}

fn rust_import_qualifier(import: &SourceImportFact) -> &[String] {
    let path = import
        .path
        .as_ref()
        .expect("Rust source imports have structured paths");
    if import.is_wildcard {
        &path.segments
    } else {
        path.segments
            .split_last()
            .expect("named Rust import has a final segment")
            .1
    }
}

impl RustFactRows {
    #[doc(hidden)]
    pub fn from_facts(
        facts: &RustUsageFacts,
        source_facts: Option<&ParsedSourceFacts>,
    ) -> Result<Self> {
        let source_imports = source_facts.map(|facts| facts.imports.as_slice());
        let context_declarations: HashSet<_> = source_facts
            .into_iter()
            .flat_map(|facts| &facts.rust_import_contexts)
            .map(|context| context.declaration)
            .collect();
        assert_eq!(
            context_declarations.len(),
            source_facts.map_or(0, |facts| facts.rust_import_contexts.len()),
            "each Rust import declaration has one canonical context"
        );
        let exports = facts
            .exports
            .iter()
            .enumerate()
            .map(|(ordinal, export)| {
                let source = import_projection_source(export.source_import_id, source_imports);
                Ok(RustExportRow {
                    ordinal: usize_to_i64(ordinal)?,
                    exported_name: match source {
                        Some(source) => rust_import_bound_name(source).cloned(),
                        None => export.exported_name.clone(),
                    },
                    source_path: source.is_none().then(|| export.source_path.clone()),
                    imported_name: source
                        .is_none()
                        .then(|| export.imported_name.clone())
                        .flatten(),
                    is_glob: source.is_none().then(|| bool_to_i64(export.is_glob)),
                    source_import_id: export.source_import_id.map(|id| i64::from(id.get())),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let import_targets = facts
            .import_targets
            .iter()
            .enumerate()
            .map(|(ordinal, target)| {
                let source = import_projection_source(target.source_import_id, source_imports);
                let source_context_occurrence_id = source.map(|source| {
                    assert!(
                        context_declarations.contains(&source.declaration),
                        "canonical Rust target requires its declaration context"
                    );
                    i64::from(source.declaration.get())
                });
                let (local_start, local_end) = match target
                    .local_extent
                    .filter(|_| source.is_none())
                {
                    Some((start, end)) => (Some(usize_to_i64(start)?), Some(usize_to_i64(end)?)),
                    None => (None, None),
                };
                let occurrence_source = target.source_occurrences.filter(|_| source.is_none());
                let occurrence_rows = occurrence_source.map(|ids| {
                    (
                        &source_facts
                            .expect("occurrence-backed import has source facts")
                            .occurrences,
                        ids,
                    )
                });
                let declaration_occurrence =
                    occurrence_rows.map(|(arena, ids)| arena.occurrence(ids.declaration));
                let target_occurrence = occurrence_rows
                    .and_then(|(arena, ids)| ids.target.map(|id| arena.occurrence(id)));
                let alias_occurrence = occurrence_rows
                    .and_then(|(arena, ids)| ids.alias.map(|id| arena.occurrence(id)));
                let module_self =
                    source.is_some() && target.imported_name.as_deref() == Some("self");
                Ok(RustImportTargetRow {
                    ordinal: usize_to_i64(ordinal)?,
                    module_path: if module_self {
                        target.module_path.join("::")
                    } else {
                        source.map_or_else(
                            || target.module_path.join("::"),
                            |source| rust_import_qualifier(source).join("::"),
                        )
                    },
                    bound_name: match source {
                        Some(source) => rust_import_bound_name(source).cloned(),
                        None => target.bound_name.clone(),
                    },
                    imported_name: source
                        .is_none()
                        .then(|| target.imported_name.clone())
                        .flatten(),
                    is_glob: source.is_none().then(|| bool_to_i64(target.is_glob)),
                    leading_absolute: source
                        .is_none()
                        .then(|| bool_to_i64(target.leading_absolute)),
                    is_extern_crate: source
                        .is_none()
                        .then(|| bool_to_i64(target.is_extern_crate)),
                    is_macro_use: source.is_none().then(|| bool_to_i64(target.is_macro_use)),
                    visibility: source
                        .is_none()
                        .then(|| encode_rust_visibility(&target.visibility)),
                    cfg_condition: source
                        .is_none()
                        .then(|| encode_rust_cfg_condition(&target.cfg_condition)),
                    owner_module: source.is_none().then(|| target.owner_module.clone()),
                    owner_start: source
                        .is_none()
                        .then(|| usize_to_i64(target.owner_start))
                        .transpose()?,
                    owner_end: source
                        .is_none()
                        .then(|| usize_to_i64(target.owner_end))
                        .transpose()?,
                    local_start,
                    local_end,
                    declaration_occurrence_id: occurrence_source
                        .map(|source| i64::from(source.declaration.get())),
                    target_occurrence_id: occurrence_source
                        .and_then(|source| source.target)
                        .map(|id| i64::from(id.get())),
                    alias_occurrence_id: occurrence_source
                        .and_then(|source| source.alias)
                        .map(|id| i64::from(id.get())),
                    source_import_id: target.source_import_id.map(|id| i64::from(id.get())),
                    source_context_occurrence_id,
                    declaration_start_byte: declaration_occurrence
                        .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                        .transpose()?,
                    declaration_end_byte: declaration_occurrence
                        .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                        .transpose()?,
                    target_start_byte: target_occurrence
                        .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                        .transpose()?,
                    target_end_byte: target_occurrence
                        .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                        .transpose()?,
                    alias_start_byte: alias_occurrence
                        .map(|occurrence| usize_to_i64(occurrence.range.start_byte))
                        .transpose()?,
                    alias_end_byte: alias_occurrence
                        .map(|occurrence| usize_to_i64(occurrence.range.end_byte))
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let identifier_occurrences = facts
            .identifier_occurrences
            .iter()
            .map(|occurrence| {
                (
                    occurrence.identifier.clone(),
                    i64::from(occurrence.context_mask),
                )
            })
            .collect();
        let module_routes = RustModuleRouteRows::from_facts(&facts.module_routes)?;
        let include_edges = facts
            .include_edges
            .iter()
            .enumerate()
            .map(|(ordinal, edge)| {
                Ok(RustIncludeEdgeRow {
                    ordinal: usize_to_i64(ordinal)?,
                    relative_path: edge.relative_path.clone(),
                    file_name: edge.file_name.clone(),
                    include_start: usize_to_i64(edge.include_start)?,
                    host_bindings: edge
                        .host_bindings
                        .iter()
                        .enumerate()
                        .map(|(ordinal, binding)| {
                            Ok(RustIncludeHostBindingRow {
                                ordinal: usize_to_i64(ordinal)?,
                                local_name: binding.local_name.clone(),
                                module_specifier: binding.module_specifier.clone(),
                                imported_name: binding.imported_name.clone(),
                                scope_start: usize_to_i64(binding.scope_start)?,
                                kind: encode_rust_include_binding_kind(binding.kind).to_string(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            exports,
            import_targets,
            identifier_occurrences,
            module_routes,
            include_edges,
        })
    }

    #[doc(hidden)]
    pub fn logical_rows(&self) -> usize {
        saturating_sum([
            self.exports.len(),
            self.import_targets.len(),
            self.identifier_occurrences.len(),
            self.module_routes.logical_rows(),
            saturating_sum(
                self.include_edges
                    .iter()
                    .map(|edge| edge.host_bindings.len().saturating_add(1)),
            ),
        ])
    }

    #[doc(hidden)]
    pub fn string_bytes(&self) -> usize {
        saturating_sum([
            saturating_sum(self.exports.iter().map(|row| {
                saturating_sum([
                    row.exported_name.as_ref().map_or(0, String::len),
                    row.source_path.as_ref().map_or(0, String::len),
                    row.imported_name.as_ref().map_or(0, String::len),
                ])
            })),
            saturating_sum(self.import_targets.iter().map(|row| {
                saturating_sum([
                    row.module_path.len(),
                    row.bound_name.as_ref().map_or(0, String::len),
                    row.imported_name.as_ref().map_or(0, String::len),
                    row.visibility.as_ref().map_or(0, String::len),
                    row.cfg_condition.as_ref().map_or(0, String::len),
                    row.owner_module.as_ref().map_or(0, String::len),
                ])
            })),
            saturating_sum(
                self.identifier_occurrences
                    .iter()
                    .map(|(identifier, _)| identifier.len()),
            ),
            self.module_routes.string_bytes(),
            saturating_sum(self.include_edges.iter().map(|edge| {
                saturating_sum([
                    edge.relative_path.len(),
                    edge.file_name.len(),
                    saturating_sum(edge.host_bindings.iter().map(|binding| {
                        saturating_sum([
                            binding.local_name.len(),
                            binding.module_specifier.len(),
                            binding.imported_name.as_ref().map_or(0, String::len),
                            binding.kind.len(),
                        ])
                    })),
                ])
            })),
        ])
    }
}

impl RustModuleRouteRows {
    fn from_facts(facts: &RustModuleRouteFacts) -> Result<Self> {
        let item_macros = facts
            .item_macros
            .iter()
            .enumerate()
            .map(|(ordinal, definition)| {
                Ok(RustItemMacroRow {
                    ordinal: usize_to_i64(ordinal)?,
                    macro_name: definition.name.clone(),
                    passthrough: bool_to_i64(definition.passthrough),
                    arguments_only: bool_to_i64(definition.arguments_only),
                    decoration_cfg: definition
                        .decoration
                        .as_ref()
                        .map(brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition),
                    declares_no_item: bool_to_i64(definition.declares_no_item),
                    writes_only_impls: bool_to_i64(definition.writes_only_impls),
                    declaration_id: i64::from(definition.declaration.get()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { item_macros })
    }

    fn logical_rows(&self) -> usize {
        self.item_macros.len()
    }

    fn string_bytes(&self) -> usize {
        saturating_sum(
            self.item_macros.iter().map(|row| {
                row.macro_name.len() + row.decoration_cfg.as_ref().map_or(0, String::len)
            }),
        )
    }
}

/// Write one fresh blob's `rust_*` fact rows. The ordinary prepared writer
/// removes any previous publication and allocates its replacement blob first.
fn insert_rust_fact_rows(
    tx: &Transaction<'_>,
    blob_id: i64,
    lang: &str,
    rows: &RustFactRows,
) -> Result<()> {
    if !rows.exports.is_empty() {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO rust_exports(
               blob_id, lang, ordinal, exported_name, source_path, imported_name, is_glob, source_import_id
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for row in &rows.exports {
            stmt.execute(params![
                blob_id,
                lang,
                row.ordinal,
                row.exported_name,
                row.source_path,
                row.imported_name,
                row.is_glob,
                row.source_import_id,
            ])?;
        }
    }
    if !rows.import_targets.is_empty() {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO rust_import_targets(
               blob_id, lang, ordinal, module_path, bound_name, imported_name, is_glob,
               leading_absolute, is_extern_crate, is_macro_use, visibility, cfg_condition, owner_module,
               owner_start, owner_end, local_start, local_end,
               declaration_occurrence_id, target_occurrence_id, alias_occurrence_id, source_import_id,
               source_context_occurrence_id, declaration_start_byte, declaration_end_byte,
               target_start_byte, target_end_byte, alias_start_byte, alias_end_byte
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28)",
        )?;
        for row in &rows.import_targets {
            stmt.execute(params![
                blob_id,
                lang,
                row.ordinal,
                row.module_path,
                row.bound_name,
                row.imported_name,
                row.is_glob,
                row.leading_absolute,
                row.is_extern_crate,
                row.is_macro_use,
                row.visibility,
                row.cfg_condition,
                row.owner_module,
                row.owner_start,
                row.owner_end,
                row.local_start,
                row.local_end,
                row.declaration_occurrence_id,
                row.target_occurrence_id,
                row.alias_occurrence_id,
                row.source_import_id,
                row.source_context_occurrence_id,
                row.declaration_start_byte,
                row.declaration_end_byte,
                row.target_start_byte,
                row.target_end_byte,
                row.alias_start_byte,
                row.alias_end_byte,
            ])?;
        }
    }
    if !rows.identifier_occurrences.is_empty() {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO rust_identifier_occurrences(
               blob_id, lang, identifier, context_mask
             ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for (identifier, context_mask) in &rows.identifier_occurrences {
            stmt.execute(params![blob_id, lang, identifier, context_mask])?;
        }
    }
    let routes = &rows.module_routes;
    if !routes.item_macros.is_empty() {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO source_rust_item_macros(
               blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg,
               declaration_id, declares_no_item, writes_only_impls
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for row in &routes.item_macros {
            stmt.execute(params![
                blob_id,
                lang,
                row.ordinal,
                row.macro_name,
                row.passthrough,
                row.arguments_only,
                row.decoration_cfg,
                row.declaration_id,
                row.declares_no_item,
                row.writes_only_impls,
            ])?;
        }
    }
    if !rows.include_edges.is_empty() {
        let mut edge_stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO rust_include_edges(
               blob_id, lang, ordinal, relative_path, file_name, include_start
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        let mut binding_stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO rust_include_host_bindings(
               blob_id, lang, edge_ordinal, ordinal, local_name, module_specifier,
               imported_name, scope_start, kind
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;
        for edge in &rows.include_edges {
            edge_stmt.execute(params![
                blob_id,
                lang,
                edge.ordinal,
                edge.relative_path,
                edge.file_name,
                edge.include_start,
            ])?;
            for binding in &edge.host_bindings {
                binding_stmt.execute(params![
                    blob_id,
                    lang,
                    edge.ordinal,
                    binding.ordinal,
                    binding.local_name,
                    binding.module_specifier,
                    binding.imported_name,
                    binding.scope_start,
                    binding.kind,
                ])?;
            }
        }
    }
    Ok(())
}

// ==== store/mod.rs lines 8261-8560 at the Phase 1 merge ====
/// Read back one blob's `rust_*` fact rows through the common bulk decoder.
#[doc(hidden)]
pub fn read_rust_usage_facts(conn: &Connection, oid: &str, lang: &str) -> Result<RustUsageFacts> {
    require_unbounded_hydration(
        read_rust_usage_facts_with_session(conn, oid, lang, None)?,
        "unbounded Rust usage-fact hydration stopped unexpectedly",
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn read_rust_usage_facts_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, RustUsageFacts>> {
    require_unbounded_hydration(
        read_rust_usage_facts_bulk_with_session(conn, lang, oids, None)?,
        "unbounded Rust usage-fact hydration stopped unexpectedly",
    )
}

#[doc(hidden)]
pub fn rust_import_targets_sql(placeholders: &str) -> String {
    format!(
        "SELECT keys.blob_oid, facts.module_path, facts.bound_name,
                facts.imported_name, facts.is_glob, facts.leading_absolute,
                facts.visibility, facts.owner_module, facts.owner_start,
                facts.owner_end, facts.local_start, facts.local_end,
                facts.cfg_condition, facts.is_extern_crate, facts.is_macro_use,
                facts.declaration_occurrence_id, facts.target_occurrence_id,
                facts.alias_occurrence_id, facts.ordinal, facts.source_import_id,
                facts.native_scope
         FROM blobs AS keys
         JOIN source_rust_import_targets AS facts ON facts.blob_id = keys.id
         WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
         ORDER BY keys.blob_oid, facts.ordinal"
    )
}

#[doc(hidden)]
pub fn rust_import_module_segments_sql(placeholders: &str) -> String {
    format!(
        "SELECT keys.blob_oid, segments.import_ordinal, segments.ordinal, segments.segment
         FROM blobs AS keys
         JOIN source_rust_import_module_segments AS segments ON segments.blob_id = keys.id
         WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
         ORDER BY keys.blob_oid, segments.import_ordinal, segments.ordinal"
    )
}

/// Read every requested blob's Rust fact families with one indexed statement
/// per family and OID page. The selected topology reader supplies the OIDs from
/// its already validated mount inventory, so this is a bounded inventory read,
/// not a workspace scan. Values within each family remain source-ordered by
/// their persisted ordinal (or identifier key where that is the writer order).
#[doc(hidden)]
pub fn read_rust_usage_facts_bulk_with_session(
    conn: &Connection,
    lang: &str,
    oids: &[String],
    session: Option<&ResolutionSession>,
) -> Result<Option<HashMap<String, RustUsageFacts>>> {
    let mut out: HashMap<String, RustUsageFacts> = HashMap::default();
    let mut unique_oids = oids.to_vec();
    unique_oids.sort_unstable();
    unique_oids.dedup();
    for chunk in unique_oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let params = chunk_params(lang, chunk);

        // Registered, unparsed blobs have no metadata and remain absent. A
        // retained publication, however, must never hydrate legacy module rows.
        let sql = format!(
            "SELECT keys.blob_oid FROM blobs AS keys
             JOIN blob_meta AS meta ON meta.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
               AND NOT EXISTS (
                   SELECT 1 FROM rust_published_fact_blobs AS ready
                   WHERE ready.blob_id = keys.id
               )"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let unavailable = stmt
            .query_map(params_from_iter(params.iter()), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !unavailable.is_empty() {
            return Err(StoreError::new(format!(
                "canonical Rust module publication is unavailable for {unavailable:?}"
            )));
        }
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, facts.exported_name, facts.source_path,
                    facts.imported_name, facts.is_glob, facts.source_import_id
             FROM blobs AS keys
             JOIN source_rust_exports AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            out.entry(oid).or_default().exports.push(RustExportFact {
                source_import_id: row.get::<_, Option<u32>>(5)?.map(SourceImportId::new),
                exported_name: row.get(1)?,
                source_path: row.get(2)?,
                imported_name: row.get(3)?,
                is_glob: row.get::<_, i64>(4)? != 0,
            });
        }
        drop(rows);
        drop(stmt);

        let sql = rust_import_module_segments_sql(&placeholders);
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        let mut import_segments: HashMap<(String, i64), Vec<String>> = HashMap::default();
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let import_ordinal = row.get::<_, i64>(1)?;
            let segment_ordinal = i64_to_usize(row.get::<_, i64>(2)?)?;
            let segments = import_segments.entry((oid, import_ordinal)).or_default();
            if segment_ordinal != segments.len() {
                return Err(StoreError::new(
                    "non-dense canonical Rust import module segments",
                ));
            }
            segments.push(row.get(3)?);
        }
        drop(rows);
        drop(stmt);

        let sql = rust_import_targets_sql(&placeholders);
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let ordinal = row.get::<_, i64>(18)?;
            let module_path = import_segments
                .remove(&(oid.clone(), ordinal))
                .unwrap_or_default();
            if module_path.join("::") != row.get::<_, String>(1)? {
                return Err(StoreError::new(
                    "canonical Rust import module segments disagree with lookup header",
                ));
            }
            let visibility = row.get::<_, String>(6)?;
            let cfg_condition = row.get::<_, String>(12)?;
            let owner_start = row.get::<_, i64>(8)?;
            let owner_end = row.get::<_, i64>(9)?;
            let local_start = row.get::<_, Option<i64>>(10)?;
            let local_end = row.get::<_, Option<i64>>(11)?;
            let target = RustImportTargetFact {
                native_scope: row
                    .get::<_, Option<u32>>(20)?
                    .map(brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new),
                source_import_id: row.get::<_, Option<u32>>(19)?.map(SourceImportId::new),
                source_occurrences: {
                    use brokk_bifrost_core::analyzer::rust_facts::RustImportSourceOccurrences;
                    use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId;
                    let declaration = row.get::<_, Option<u32>>(15)?;
                    let target = row.get::<_, Option<u32>>(16)?;
                    let alias = row.get::<_, Option<u32>>(17)?;
                    declaration.map(|declaration| RustImportSourceOccurrences {
                        declaration: SourceOccurrenceId::new(declaration),
                        target: target.map(SourceOccurrenceId::new),
                        alias: alias.map(SourceOccurrenceId::new),
                    })
                },
                module_path,
                bound_name: row.get(2)?,
                imported_name: row.get(3)?,
                is_glob: row.get::<_, i64>(4)? != 0,
                leading_absolute: row.get::<_, i64>(5)? != 0,
                is_extern_crate: row.get::<_, i64>(13)? != 0,
                is_macro_use: row.get::<_, i64>(14)? != 0,
                visibility: decode_rust_visibility(&visibility)
                    .unwrap_or_else(|| panic!("unknown persisted Rust visibility: {visibility}")),
                cfg_condition: decode_rust_cfg_condition(&cfg_condition).unwrap_or_else(|| {
                    panic!("unknown persisted Rust cfg condition: {cfg_condition}")
                }),
                owner_module: row.get(7)?,
                owner_start: i64_to_usize(owner_start)?,
                owner_end: i64_to_usize(owner_end)?,
                local_extent: match (local_start, local_end) {
                    (Some(start), Some(end)) => Some((i64_to_usize(start)?, i64_to_usize(end)?)),
                    (None, None) => None,
                    mismatched => {
                        panic!("half-open persisted local import extent: {mismatched:?}")
                    }
                },
            };
            let targets = &mut out.entry(oid).or_default().import_targets;
            if i64_to_usize(ordinal)? != targets.len() {
                return Err(StoreError::new(
                    "non-dense canonical Rust import target ordinals",
                ));
            }
            targets.push(target);
        }
        drop(rows);
        drop(stmt);
        if !import_segments.is_empty() {
            return Err(StoreError::new(
                "canonical Rust import module segments have no parent target",
            ));
        }

        let sql = format!(
            "SELECT keys.blob_oid, facts.module_name, facts.is_inline,
                    facts.start_byte, facts.end_byte, facts.cfg_condition
             FROM blobs AS keys
             JOIN rust_modules AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let cfg_condition = row.get::<_, String>(5)?;
            out.entry(oid).or_default().modules.push(RustModuleFact {
                module_name: row.get(1)?,
                is_inline: row.get::<_, i64>(2)? != 0,
                start_byte: i64_to_usize(row.get::<_, i64>(3)?)?,
                end_byte: i64_to_usize(row.get::<_, i64>(4)?)?,
                cfg_condition: decode_rust_cfg_condition(&cfg_condition).unwrap_or_else(|| {
                    panic!("unknown persisted Rust module cfg condition: {cfg_condition}")
                }),
            });
        }
        drop(rows);
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, facts.identifier, facts.context_mask
             FROM blobs AS keys
             JOIN rust_identifier_occurrences AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.identifier"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let identifier = row.get::<_, String>(1)?;
            let context_mask = row.get::<_, i64>(2)?;
            out.entry(oid)
                .or_default()
                .identifier_occurrences
                .push(RustIdentifierOccurrence {
                    identifier,
                    context_mask: u32::try_from(context_mask).map_err(|_| {
                        StoreError::new(format!(
                            "occurrence context mask out of range: {context_mask}"
                        ))
                    })?,
                });
        }
        drop(rows);
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, source_scope.declaration_id,
                    facts.parent_ordinal, facts.module_name,
                    facts.path_attribute, facts.visibility, facts.imports_macros,
                    facts.resolution_scope, facts.body_start, facts.body_end
             FROM blobs AS keys
             JOIN rust_module_scopes AS facts ON facts.blob_id = keys.id
             JOIN source_rust_module_scopes AS source_scope
               ON source_scope.blob_id = facts.blob_id
              AND source_scope.ordinal = facts.ordinal
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let scope = decode_rust_module_scope_row(row, 1)?;
            out.entry(oid)
                .or_default()
                .module_routes
                .scopes
                .push(scope?);
        }
        drop(rows);
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, source_route.declaration_id,
                    facts.scope_ordinal, facts.module_name,
                    facts.path_attribute, facts.visibility, facts.imports_macros,
                    facts.test_gated, facts.cfg_condition, facts.declaration_start,
                    facts.declaration_end
             FROM blobs AS keys
             JOIN rust_module_routes AS facts ON facts.blob_id = keys.id
             JOIN source_rust_module_routes AS source_route
               ON source_route.blob_id = facts.blob_id
              AND source_route.ordinal = facts.ordinal
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let route = decode_rust_module_route_row(row, 1)?;
            out.entry(oid)
                .or_default()
                .module_routes
                .routes
                .push(route?);
        }
        drop(rows);
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, facts.route_ordinal, facts.macro_name,
                    facts.invocation_start
             FROM blobs AS keys
             JOIN rust_module_route_gates AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.route_ordinal, facts.gate_ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let gate = decode_rust_module_route_gate_row(row, 1)?;
            let (route_ordinal, gate) = gate?;
            attach_rust_module_route_gate(
                &mut out.entry(oid).or_default().module_routes.routes,
                route_ordinal,
                gate,
            )?;
        }
        drop(rows);
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, facts.macro_name, facts.visible_after,
                    facts.scope_start, facts.scope_end, facts.passthrough,
                    facts.exported, facts.declaration_id, facts.arguments_only,
                    facts.decoration_cfg, facts.declares_no_item, facts.writes_only_impls
             FROM blobs AS keys
             JOIN rust_item_macros AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let definition = decode_rust_item_macro_row(row, 1)?;
            out.entry(oid)
                .or_default()
                .module_routes
                .item_macros
                .push(definition?);
        }
        drop(rows);
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, facts.relative_path, facts.file_name,
                    facts.include_start
             FROM blobs AS keys
             JOIN rust_include_edges AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            out.entry(oid)
                .or_default()
                .include_edges
                .push(RustIncludeEdgeFact {
                    relative_path: row.get(1)?,
                    file_name: row.get(2)?,
                    include_start: i64_to_usize(row.get::<_, i64>(3)?)?,
                    host_bindings: Vec::new(),
                });
        }
        drop(rows);
        drop(stmt);

        let sql = format!(
            "SELECT keys.blob_oid, facts.edge_ordinal, facts.local_name,
                    facts.module_specifier, facts.imported_name, facts.scope_start,
                    facts.kind
             FROM blobs AS keys
             JOIN rust_include_host_bindings AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.edge_ordinal, facts.ordinal"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let edge_ordinal = i64_to_usize(row.get::<_, i64>(1)?)?;
            let Some(facts) = out.get_mut(&oid) else {
                continue;
            };
            let Some(edge) = facts.include_edges.get_mut(edge_ordinal) else {
                continue;
            };
            let kind = row.get::<_, String>(6)?;
            let binding = RustIncludeHostBindingFact {
                local_name: row.get(2)?,
                module_specifier: row.get(3)?,
                imported_name: row.get(4)?,
                scope_start: i64_to_usize(row.get::<_, i64>(5)?)?,
                kind: decode_rust_include_binding_kind(&kind)
                    .unwrap_or_else(|| panic!("unknown persisted include binding kind: {kind}")),
            };
            edge.host_bindings.push(binding);
        }
        drop(rows);
        drop(stmt);
    }
    Ok(Some(out))
}

pub(crate) fn read_rust_usage_facts_with_session(
    conn: &Connection,
    oid: &str,
    lang: &str,
    session: Option<&ResolutionSession>,
) -> Result<Option<RustUsageFacts>> {
    let requested = [oid.to_owned()];
    let Some(mut by_oid) =
        read_rust_usage_facts_bulk_with_session(conn, lang, &requested, session)?
    else {
        return Ok(None);
    };
    Ok(Some(by_oid.remove(oid).unwrap_or_default()))
}

/// `base` is the index of this row shape's first column in the bulk fact read.
fn decode_rust_module_scope_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<RustModuleScopeFact>> {
    let declaration = row.get::<_, Option<u32>>(base)?;
    let parent = row.get::<_, Option<i64>>(base + 1)?;
    let module_name = row.get::<_, String>(base + 2)?;
    let path_attribute = row.get::<_, Option<String>>(base + 3)?;
    let visibility = row.get::<_, String>(base + 4)?;
    let imports_macros = row.get::<_, i64>(base + 5)? != 0;
    let resolution_scope = row.get::<_, Option<i64>>(base + 6)?;
    let body_start = row.get::<_, i64>(base + 7)?;
    let body_end = row.get::<_, i64>(base + 8)?;
    Ok((|| {
        Ok(RustModuleScopeFact {
            parent: parent.map(i64_to_usize).transpose()?,
            declaration: declaration
                .map(brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId::new),
            module_name,
            path_attribute,
            visibility: decode_rust_visibility(&visibility).unwrap_or_else(|| {
                panic!("unknown persisted Rust module visibility: {visibility}")
            }),
            imports_macros,
            resolution_scope: resolution_scope
                .map(|scope| {
                    u32::try_from(scope)
                        .map(ResolutionScopeId::new)
                        .map_err(|_| StoreError::new("Rust resolution scope exceeds u32"))
                })
                .transpose()?,
            body_start: i64_to_usize(body_start)?,
            body_end: i64_to_usize(body_end)?,
        })
    })())
}

fn decode_rust_module_route_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<RustModuleRouteFact>> {
    let declaration = row.get::<_, u32>(base)?;
    let scope = row.get::<_, i64>(base + 1)?;
    let module_name = row.get::<_, String>(base + 2)?;
    let path_attribute = row.get::<_, Option<String>>(base + 3)?;
    let visibility = row.get::<_, String>(base + 4)?;
    let imports_macros = row.get::<_, i64>(base + 5)? != 0;
    let test_gated = row.get::<_, i64>(base + 6)? != 0;
    let cfg_condition = row.get::<_, String>(base + 7)?;
    let declaration_start = row.get::<_, i64>(base + 8)?;
    let declaration_end = row.get::<_, i64>(base + 9)?;
    Ok((|| {
        Ok(RustModuleRouteFact {
            scope: i64_to_usize(scope)?,
            declaration: brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId::new(
                declaration,
            ),
            module_name,
            path_attribute,
            visibility: decode_rust_visibility(&visibility)
                .unwrap_or_else(|| panic!("unknown persisted Rust visibility: {visibility}")),
            imports_macros,
            test_gated,
            cfg_condition: decode_rust_cfg_condition(&cfg_condition).unwrap_or_else(|| {
                panic!("unknown persisted Rust module-route cfg condition: {cfg_condition}")
            }),
            declaration_start: i64_to_usize(declaration_start)?,
            declaration_end: i64_to_usize(declaration_end)?,
            gates: Vec::new(),
        })
    })())
}

fn decode_rust_module_route_gate_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<(usize, RustMacroGateFact)>> {
    let route_ordinal = row.get::<_, i64>(base)?;
    let macro_name = row.get::<_, String>(base + 1)?;
    let invocation_start = row.get::<_, i64>(base + 2)?;
    Ok((|| {
        Ok((
            i64_to_usize(route_ordinal)?,
            RustMacroGateFact {
                macro_name,
                invocation_start: i64_to_usize(invocation_start)?,
            },
        ))
    })())
}

fn decode_rust_item_macro_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Result<RustRulesItemMacroDefinition>> {
    let name = row.get::<_, String>(base)?;
    let visible_after = row.get::<_, i64>(base + 1)?;
    let scope_start = row.get::<_, i64>(base + 2)?;
    let scope_end = row.get::<_, i64>(base + 3)?;
    let passthrough = row.get::<_, i64>(base + 4)? != 0;
    let exported = row.get::<_, i64>(base + 5)? != 0;
    let declaration =
        brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId::new(row.get(base + 6)?);
    let arguments_only = row.get::<_, i64>(base + 7)? != 0;
    let decoration_cfg = row.get::<_, Option<String>>(base + 8)?;
    let declares_no_item = row.get::<_, i64>(base + 9)? != 0;
    let writes_only_impls = row.get::<_, i64>(base + 10)? != 0;
    Ok((|| {
        Ok(RustRulesItemMacroDefinition {
            declaration,
            name,
            visible_after: i64_to_usize(visible_after)?,
            scope_start: i64_to_usize(scope_start)?,
            scope_end: i64_to_usize(scope_end)?,
            passthrough,
            arguments_only,
            declares_no_item,
            writes_only_impls,
            decoration: decoration_cfg
                .map(|encoded| {
                    brokk_bifrost_core::analyzer::rust_facts::decode_rust_cfg_condition(&encoded)
                        .ok_or_else(|| {
                            StoreError::corrupt(format!(
                                "rust item macro decoration is not a cfg encoding: {encoded:?}"
                            ))
                        })
                })
                .transpose()?,
            exported,
        })
    })())
}

/// Attach one gate row to the route it belongs to.
///
/// Gate rows are read in `(route_ordinal, gate_ordinal)` order, so appending
/// preserves the outermost-first order the reader relies on. A gate naming a
/// route that does not exist can only come from rows this build did not write.
fn attach_rust_module_route_gate(
    routes: &mut [RustModuleRouteFact],
    route_ordinal: usize,
    gate: RustMacroGateFact,
) -> Result<()> {
    let route = routes.get_mut(route_ordinal).ok_or_else(|| {
        StoreError::new(format!(
            "module route gate names missing route {route_ordinal}: {gate:?}"
        ))
    })?;
    route.gates.push(gate);
    Ok(())
}

#[derive(Debug)]
#[doc(hidden)]
pub enum PreparedParsedBlobPreparation {
    Prepared(Box<PreparedParsedBlob>),
    Cancelled,
}

#[derive(Debug)]
#[doc(hidden)]
pub enum StructuralFactRowsRead {
    Ready(PersistedStructuralFacts),
    Exceeded { minimum_work_items: usize },
    Unavailable,
    Cancelled,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct PreparedParsedBlob {
    #[doc(hidden)]
    pub oid: Oid,
    #[doc(hidden)]
    pub oid_text: String,
    #[doc(hidden)]
    pub lang: String,
    #[doc(hidden)]
    pub generation: GenerationId,
    #[doc(hidden)]
    pub state: Arc<FileState>,
    #[doc(hidden)]
    pub units: Vec<PreparedUnitRow>,
    #[doc(hidden)]
    pub source_declaration_units: Vec<(
        brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
        i64,
    )>,
    #[doc(hidden)]
    pub source_declaration_metadata: Vec<(
        brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
        i64,
        i64,
    )>,
    #[doc(hidden)]
    pub declaration_visibility_version: Option<i64>,
    #[doc(hidden)]
    pub java_type_constructor_version: Option<i64>,
    #[doc(hidden)]
    pub go_source_version: Option<i64>,
    #[doc(hidden)]
    pub java_source_version: Option<i64>,
    #[doc(hidden)]
    pub scala_source_version: Option<i64>,
    #[doc(hidden)]
    pub ruby_source_version: Option<i64>,
    #[doc(hidden)]
    pub php_source_version: Option<i64>,
    #[doc(hidden)]
    pub cpp_source_version: Option<i64>,
    #[doc(hidden)]
    pub source_facts_version: Option<i64>,
    #[doc(hidden)]
    pub source_storage: Option<&'static SourceFactStorage>,
    #[doc(hidden)]
    pub metadata_bridges_required: bool,
    #[doc(hidden)]
    pub js_ts_source_version: Option<i64>,
    #[doc(hidden)]
    pub python_source_version: Option<i64>,
    #[doc(hidden)]
    pub ranges: Vec<(i64, i64, i64, i64, i64, i64)>,
    #[doc(hidden)]
    pub signatures: Vec<(i64, i64, String)>,
    #[doc(hidden)]
    pub signature_metadata: Vec<(i64, i64, SignatureMetadataColumns)>,
    #[doc(hidden)]
    pub signature_metadata_signature_ordinals: Vec<(i64, i64, i64)>,
    #[doc(hidden)]
    pub cpp_templates: cpp_template::PreparedCppTemplates,
    #[doc(hidden)]
    pub supertypes: Vec<(i64, i64, String, String)>,
    #[doc(hidden)]
    pub children: Vec<(i64, i64, i64)>,
    #[doc(hidden)]
    pub imports: ImportRows,
    #[doc(hidden)]
    pub scala_exports: Vec<(i64, i64, Vec<u8>)>,
    #[doc(hidden)]
    pub rust_facts: RustFactRows,
    #[doc(hidden)]
    pub type_identifiers: Vec<String>,
    #[doc(hidden)]
    pub ruby_dispatch_modes: Vec<(i64, i64)>,
    #[doc(hidden)]
    pub scala_traits: Vec<i64>,
    #[doc(hidden)]
    pub materialization_records: Vec<(i64, Option<i64>, Vec<u8>)>,
    #[doc(hidden)]
    pub contains_tests: i64,
    #[doc(hidden)]
    pub content_package: String,
    #[doc(hidden)]
    pub resolution: PreparedResolutionBundle,
    /// The blob's semantic IR rows, lowered at parse time. `None` for a
    /// language whose adapter has no parse-time lowerer.
    #[doc(hidden)]
    pub semantic_ir: Option<PreparedSemanticIr>,
    #[doc(hidden)]
    pub logical_rows: usize,
    #[doc(hidden)]
    pub payload_bytes: usize,
    #[doc(hidden)]
    pub mutation_logical_rows: usize,
    #[doc(hidden)]
    pub mutation_payload_bytes: usize,
    /// Prepared row-sets for the same blob under other storage language keys
    /// (see [`FileState::additional_projections`]). Always empty on a nested
    /// entry, so flattening the persistence envelope is one bounded pass.
    #[doc(hidden)]
    pub additional: Vec<PreparedParsedBlob>,
}

impl PreparedParsedBlob {
    #[doc(hidden)]
    pub fn oid(&self) -> Oid {
        self.oid
    }

    #[doc(hidden)]
    pub fn lang(&self) -> &str {
        &self.lang
    }

    #[doc(hidden)]
    pub fn state(&self) -> &Arc<FileState> {
        &self.state
    }

    #[doc(hidden)]
    pub fn logical_rows(&self) -> usize {
        self.logical_rows
    }

    #[doc(hidden)]
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    #[doc(hidden)]
    pub fn fragment_count(&self) -> usize {
        1usize.saturating_add(self.additional.len())
    }

    fn append_fragments<'a>(&'a self, fragments: &mut Vec<&'a Self>) {
        assert!(
            self.additional
                .iter()
                .all(|projection| projection.additional.is_empty()),
            "prepared projection nesting must be exactly one level"
        );
        fragments.push(self);
        fragments.extend(self.additional.iter());
    }

    fn fragment_at(&self, ordinal: usize) -> &Self {
        if ordinal == 0 {
            self
        } else {
            &self.additional[ordinal - 1]
        }
    }

    fn has_same_persisted_fragment(&self, other: &Self) -> bool {
        self.oid == other.oid
            && self.lang == other.lang
            && self.generation == other.generation
            && self.units == other.units
            && self.ranges == other.ranges
            && self.signatures == other.signatures
            && self.signature_metadata == other.signature_metadata
            && self.signature_metadata_signature_ordinals
                == other.signature_metadata_signature_ordinals
            && self.cpp_templates == other.cpp_templates
            && self.supertypes == other.supertypes
            && self.children == other.children
            && self.imports == other.imports
            && self.scala_exports == other.scala_exports
            && self.rust_facts == other.rust_facts
            && self.type_identifiers == other.type_identifiers
            && self.ruby_dispatch_modes == other.ruby_dispatch_modes
            && self.scala_traits == other.scala_traits
            && self.materialization_records == other.materialization_records
            && self.contains_tests == other.contains_tests
            && self.content_package == other.content_package
            && self.resolution == other.resolution
            && self.semantic_ir == other.semantic_ir
            && self.state.source_facts == other.state.source_facts
            && self.source_declaration_units == other.source_declaration_units
            && self.source_declaration_metadata == other.source_declaration_metadata
            && self.declaration_visibility_version == other.declaration_visibility_version
            && self.java_type_constructor_version == other.java_type_constructor_version
            && self.go_source_version == other.go_source_version
            && self.java_source_version == other.java_source_version
            && self.scala_source_version == other.scala_source_version
            && self.ruby_source_version == other.ruby_source_version
            && self.php_source_version == other.php_source_version
            && self.cpp_source_version == other.cpp_source_version
            && self.source_facts_version == other.source_facts_version
            && self.source_storage.map(std::ptr::from_ref)
                == other.source_storage.map(std::ptr::from_ref)
            && self.metadata_bridges_required == other.metadata_bridges_required
            && self.js_ts_source_version == other.js_ts_source_version
            && self.python_source_version == other.python_source_version
            && self.logical_rows == other.logical_rows
            && self.persisted_payload_bytes() == other.persisted_payload_bytes()
    }

    pub(super) fn merge_compatible_persistence_envelope(
        &mut self,
        mut other: Self,
    ) -> (usize, usize, usize) {
        let expected_cost = self
            .compatible_persistence_envelope_addition_cost(&other)
            .expect("a compatible envelope preflight must remain compatible while merging");
        let mut added_fragments = 0usize;
        let mut added_rows = 0usize;
        let mut added_bytes = 0usize;
        for candidate in other.additional.drain(..) {
            if self
                .additional
                .iter()
                .any(|existing| existing.lang() == candidate.lang())
            {
                continue;
            }
            added_fragments = added_fragments.saturating_add(candidate.fragment_count());
            added_rows = added_rows.saturating_add(candidate.mutation_logical_rows());
            added_bytes = added_bytes.saturating_add(candidate.mutation_payload_bytes());
            self.additional.push(candidate);
        }
        self.additional
            .sort_by(|left, right| left.lang().cmp(right.lang()));
        self.mutation_logical_rows = saturating_sum(
            std::iter::once(self.logical_rows)
                .chain(self.additional.iter().map(Self::mutation_logical_rows)),
        );
        self.mutation_payload_bytes = saturating_sum(
            std::iter::once(self.payload_bytes)
                .chain(self.additional.iter().map(Self::mutation_payload_bytes)),
        );
        debug_assert_eq!(
            (added_fragments, added_rows, added_bytes),
            expected_cost,
            "compatible envelope preflight and merge must describe the same fragments"
        );
        expected_cost
    }

    pub(super) fn compatible_persistence_envelope_addition_cost(
        &self,
        other: &Self,
    ) -> Option<(usize, usize, usize)> {
        if !self.has_same_persisted_fragment(other) {
            return None;
        }
        for candidate in &other.additional {
            if let Some(existing) = self
                .additional
                .iter()
                .find(|existing| existing.lang() == candidate.lang())
                && !existing.has_same_persisted_fragment(candidate)
            {
                return None;
            }
        }

        let mut added_fragments = 0usize;
        let mut added_rows = 0usize;
        let mut added_bytes = 0usize;
        for candidate in &other.additional {
            if self
                .additional
                .iter()
                .any(|existing| existing.lang() == candidate.lang())
            {
                continue;
            }
            added_fragments = added_fragments.saturating_add(candidate.fragment_count());
            added_rows = added_rows.saturating_add(candidate.mutation_logical_rows());
            added_bytes = added_bytes.saturating_add(candidate.mutation_payload_bytes());
        }
        Some((added_fragments, added_rows, added_bytes))
    }

    pub(super) fn append_fragment_generations(
        &self,
        generations: &mut Vec<(Oid, String, GenerationId)>,
    ) {
        generations.push((self.oid(), self.lang().to_owned(), self.generation));
        generations.extend(self.additional.iter().map(|fragment| {
            (
                fragment.oid(),
                fragment.lang().to_owned(),
                fragment.generation,
            )
        }));
    }

    #[doc(hidden)]
    pub fn mutation_logical_rows(&self) -> usize {
        self.mutation_logical_rows
    }

    #[doc(hidden)]
    pub fn mutation_payload_bytes(&self) -> usize {
        self.mutation_payload_bytes
    }

    fn persisted_payload_bytes(&self) -> usize {
        self.payload_bytes.saturating_sub(self.state.source.len())
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn inject_invalid_range_for_test(&mut self) {
        self.ranges.push((i64::MAX, 0, 0, 0, 0, 0));
        self.logical_rows = self.logical_rows.saturating_add(1);
    }
}

/// Targets for grouping independent source publications into one transaction.
/// One indivisible OID group (including its language projections and replaced
/// rows) may exceed them and is published alone. These are not per-file
/// admission limits or a bound on preparation memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct PersistBatchTargets {
    #[doc(hidden)]
    pub max_blobs: usize,
    #[doc(hidden)]
    pub max_rows: usize,
    #[doc(hidden)]
    pub max_payload_bytes: usize,
}

impl PersistBatchTargets {
    // Issue #2326 writer-stage profile: with 32 KiB pages and a 512 MiB writer
    // page cache, 256-blob/400 k-row batches cut commit cost ~3.5x versus the
    // previous 64-blob/100 k-row batches. Keep these grouping targets without
    // rejecting a prepared source whose complete publication exceeds them.
    #[doc(hidden)]
    pub const PRODUCTION: Self = Self {
        max_blobs: 256,
        max_rows: 400_000,
        max_payload_bytes: 32 * 1024 * 1024,
    };

    fn normalized(self) -> Self {
        Self {
            max_blobs: self.max_blobs.max(1),
            max_rows: self.max_rows.max(1),
            max_payload_bytes: self.max_payload_bytes.max(1),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct PersistBatchStats {
    #[doc(hidden)]
    pub transactions: usize,
    #[doc(hidden)]
    pub failed_transaction_attempts: usize,
    #[doc(hidden)]
    pub committed_blobs: usize,
    #[doc(hidden)]
    pub failed_blobs: usize,
    #[doc(hidden)]
    pub committed_fragments: usize,
    #[doc(hidden)]
    pub failed_fragments: usize,
    #[doc(hidden)]
    pub logical_rows: usize,
    #[doc(hidden)]
    pub payload_bytes: usize,
    #[doc(hidden)]
    pub peak_batch_blobs: usize,
    #[doc(hidden)]
    pub peak_batch_fragments: usize,
    #[doc(hidden)]
    pub peak_batch_rows: usize,
    #[doc(hidden)]
    pub peak_batch_payload_bytes: usize,
    #[doc(hidden)]
    pub peak_in_flight_items: usize,
    #[doc(hidden)]
    pub peak_in_flight_payload_bytes: usize,
    #[doc(hidden)]
    pub configured_max_in_flight_items: usize,
}

impl PersistBatchStats {
    #[doc(hidden)]
    pub fn merge(&mut self, other: Self) {
        self.transactions = self.transactions.saturating_add(other.transactions);
        self.failed_transaction_attempts = self
            .failed_transaction_attempts
            .saturating_add(other.failed_transaction_attempts);
        self.committed_blobs = self.committed_blobs.saturating_add(other.committed_blobs);
        self.failed_blobs = self.failed_blobs.saturating_add(other.failed_blobs);
        self.committed_fragments = self
            .committed_fragments
            .saturating_add(other.committed_fragments);
        self.failed_fragments = self.failed_fragments.saturating_add(other.failed_fragments);
        self.logical_rows = self.logical_rows.saturating_add(other.logical_rows);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
        self.peak_batch_blobs = self.peak_batch_blobs.max(other.peak_batch_blobs);
        self.peak_batch_fragments = self.peak_batch_fragments.max(other.peak_batch_fragments);
        self.peak_batch_rows = self.peak_batch_rows.max(other.peak_batch_rows);
        self.peak_batch_payload_bytes = self
            .peak_batch_payload_bytes
            .max(other.peak_batch_payload_bytes);
        self.peak_in_flight_items = self.peak_in_flight_items.max(other.peak_in_flight_items);
        self.peak_in_flight_payload_bytes = self
            .peak_in_flight_payload_bytes
            .max(other.peak_in_flight_payload_bytes);
        self.configured_max_in_flight_items = self
            .configured_max_in_flight_items
            .max(other.configured_max_in_flight_items);
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct PersistBlobOutcome {
    #[doc(hidden)]
    pub prepared: PreparedParsedBlob,
    #[doc(hidden)]
    pub error: Option<StoreError>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct PersistedMutationCost {
    #[doc(hidden)]
    pub logical_rows: usize,
    #[doc(hidden)]
    pub payload_bytes: usize,
}

#[derive(Clone, Default)]
struct PreparedWriteCounters {
    #[cfg(any(test, feature = "test-support"))]
    transaction_starts: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    generation_lookups: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    replacement_lookups: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    replacement_fallbacks: Arc<AtomicUsize>,
}

/// Runs the existing adaptive prepared-blob writer on the connection owned by
/// a `StoreWriter` backend. Keeping this connection-taking implementation
/// separate from `AnalyzerStore` prevents a persistent actor job from
/// recursively submitting another actor job.
struct PreparedPersistenceWriter<'a> {
    conn: &'a mut Connection,
    cancellation: CancellationToken,
    counters: PreparedWriteCounters,
}

impl<'a> PreparedPersistenceWriter<'a> {
    fn new(
        conn: &'a mut Connection,
        counters: PreparedWriteCounters,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            conn,
            cancellation,
            counters,
        }
    }

    fn persist_prepared_blobs(
        &mut self,
        prepared: Vec<PreparedParsedBlob>,
        limits: PersistBatchTargets,
    ) -> (Vec<PersistBlobOutcome>, PersistBatchStats) {
        let limits = limits.normalized();
        let mut outcomes = Vec::with_capacity(prepared.len());
        let mut stats = PersistBatchStats::default();
        let mut owners = HashMap::default();
        let mut invalid = vec![false; prepared.len()];
        for (root_index, root) in prepared.iter().enumerate() {
            let mut fragments = Vec::with_capacity(root.fragment_count());
            root.append_fragments(&mut fragments);
            for (fragment_ordinal, fragment) in fragments.into_iter().enumerate() {
                let key = (fragment.oid(), fragment.lang().to_owned());
                owners
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push((root_index, fragment_ordinal));
            }
        }
        for key_owners in owners.values() {
            let &(first_root, first_fragment) = key_owners
                .first()
                .expect("one prepared fragment key has an owner");
            let first = prepared[first_root].fragment_at(first_fragment);
            if key_owners.iter().any(|&(root, fragment)| {
                !first.has_same_persisted_fragment(prepared[root].fragment_at(fragment))
            }) {
                for &(root, _) in key_owners {
                    invalid[root] = true;
                }
            }
        }
        let mut prepared = prepared
            .into_iter()
            .enumerate()
            .zip(invalid)
            .map(|((ordinal, prepared), invalid)| (ordinal, prepared, invalid))
            .collect::<Vec<_>>();
        prepared.sort_by(|(_, left, _), (_, right, _)| {
            left.oid()
                .as_bytes()
                .cmp(right.oid().as_bytes())
                .then_with(|| left.lang().cmp(right.lang()))
        });
        let mut batch = Vec::new();
        let mut batch_keys = HashSet::default();
        let mut batch_fragments = 0usize;
        let mut batch_rows = 0usize;
        let mut batch_bytes = 0usize;

        for (submission_ordinal, blob, invalid) in prepared {
            let fragment_count = blob.fragment_count();
            if invalid {
                outcomes.push((
                    submission_ordinal,
                    PersistBlobOutcome {
                        prepared: blob,
                        error: Some(StoreError::new(
                            "duplicate primary or projection blob key in one persistence call",
                        )),
                    },
                ));
                stats.failed_blobs = stats.failed_blobs.saturating_add(1);
                stats.failed_fragments = stats.failed_fragments.saturating_add(fragment_count);
                continue;
            }
            if self.cancellation.is_cancelled() {
                outcomes.push((
                    submission_ordinal,
                    PersistBlobOutcome {
                        prepared: blob,
                        error: Some(StoreError::new("prepared blob persistence was cancelled")),
                    },
                ));
                stats.failed_blobs = stats.failed_blobs.saturating_add(1);
                stats.failed_fragments = stats.failed_fragments.saturating_add(fragment_count);
                continue;
            }
            let mut fragments = Vec::with_capacity(fragment_count);
            blob.append_fragments(&mut fragments);
            let new_fragments = fragments
                .iter()
                .copied()
                .filter(|fragment| {
                    !batch_keys.contains(&(fragment.oid(), fragment.lang().to_owned()))
                })
                .collect::<Vec<_>>();
            let new_fragment_count = new_fragments.len();
            let new_rows =
                saturating_sum(new_fragments.iter().map(|fragment| fragment.logical_rows()));
            let new_bytes = saturating_sum(
                new_fragments
                    .iter()
                    .map(|fragment| fragment.payload_bytes()),
            );
            let exceeds = !batch.is_empty()
                && (batch_fragments.saturating_add(new_fragment_count) > limits.max_blobs
                    || batch_rows.saturating_add(new_rows) > limits.max_rows
                    || batch_bytes.saturating_add(new_bytes) > limits.max_payload_bytes);
            let same_oid_as_batch =
                batch
                    .last()
                    .is_some_and(|(_, current): &(usize, PreparedParsedBlob)| {
                        current.oid() == blob.oid()
                    });
            if exceeds && !same_oid_as_batch {
                let (batch_outcomes, batch_stats) = self.persist_prepared_chunk(batch, limits);
                outcomes.extend(batch_outcomes);
                stats.merge(batch_stats);
                batch = Vec::new();
                batch_keys.clear();
                batch_fragments = 0;
                batch_rows = 0;
                batch_bytes = 0;
            }
            let mut added_fragments = 0usize;
            let mut added_rows = 0usize;
            let mut added_bytes = 0usize;
            for fragment in fragments {
                if batch_keys.insert((fragment.oid(), fragment.lang().to_owned())) {
                    added_fragments = added_fragments.saturating_add(1);
                    added_rows = added_rows.saturating_add(fragment.logical_rows());
                    added_bytes = added_bytes.saturating_add(fragment.payload_bytes());
                }
            }
            batch_fragments = batch_fragments.saturating_add(added_fragments);
            batch_rows = batch_rows.saturating_add(added_rows);
            batch_bytes = batch_bytes.saturating_add(added_bytes);
            batch.push((submission_ordinal, blob));
        }
        if !batch.is_empty() {
            let (batch_outcomes, batch_stats) = self.persist_prepared_chunk(batch, limits);
            outcomes.extend(batch_outcomes);
            stats.merge(batch_stats);
        }
        outcomes.sort_by_key(|(ordinal, _)| *ordinal);
        (
            outcomes.into_iter().map(|(_, outcome)| outcome).collect(),
            stats,
        )
    }

    fn persist_prepared_chunk(
        &mut self,
        mut prepared: Vec<(usize, PreparedParsedBlob)>,
        limits: PersistBatchTargets,
    ) -> (Vec<(usize, PersistBlobOutcome)>, PersistBatchStats) {
        let batch_blobs = prepared.len();
        let mut fragment_keys = HashSet::default();
        let mut batch_fragments = 0usize;
        let mut batch_rows = 0usize;
        let mut batch_bytes = 0usize;
        for (_, root) in &prepared {
            let mut fragments = Vec::with_capacity(root.fragment_count());
            root.append_fragments(&mut fragments);
            for fragment in fragments {
                if fragment_keys.insert((fragment.oid(), fragment.lang().to_owned())) {
                    batch_fragments = batch_fragments.saturating_add(1);
                    batch_rows = batch_rows.saturating_add(fragment.logical_rows());
                    batch_bytes = batch_bytes.saturating_add(fragment.payload_bytes());
                }
            }
        }
        let result = self.try_persist_prepared_chunk(&prepared, limits);

        match result {
            Ok(actual_cost) => {
                let stats = PersistBatchStats {
                    transactions: 1,
                    committed_blobs: batch_blobs,
                    committed_fragments: batch_fragments,
                    logical_rows: actual_cost.logical_rows,
                    payload_bytes: actual_cost.payload_bytes,
                    peak_batch_blobs: batch_blobs,
                    peak_batch_fragments: batch_fragments,
                    peak_batch_rows: actual_cost.logical_rows,
                    peak_batch_payload_bytes: actual_cost.payload_bytes,
                    ..PersistBatchStats::default()
                };
                let outcomes = prepared
                    .into_iter()
                    .map(|(ordinal, prepared)| {
                        (
                            ordinal,
                            PersistBlobOutcome {
                                prepared,
                                error: None,
                            },
                        )
                    })
                    .collect();
                (outcomes, stats)
            }
            Err(error) if self.cancellation.is_cancelled() => {
                let outcomes = prepared
                    .into_iter()
                    .map(|(ordinal, prepared)| {
                        (
                            ordinal,
                            PersistBlobOutcome {
                                prepared,
                                error: Some(error.clone()),
                            },
                        )
                    })
                    .collect();
                (
                    outcomes,
                    PersistBatchStats {
                        failed_transaction_attempts: 1,
                        failed_blobs: batch_blobs,
                        failed_fragments: batch_fragments,
                        peak_batch_blobs: batch_blobs,
                        peak_batch_fragments: batch_fragments,
                        peak_batch_rows: batch_rows,
                        peak_batch_payload_bytes: batch_bytes,
                        ..PersistBatchStats::default()
                    },
                )
            }
            Err(error)
                if (error.is_stale_generation()
                    || error.is_stale_resolution()
                    || error.is_resource_bound())
                    && prepared
                        .first()
                        .zip(prepared.last())
                        .is_some_and(|((_, first), (_, last))| first.oid() == last.oid()) =>
            {
                let outcomes = prepared
                    .into_iter()
                    .map(|(ordinal, prepared)| {
                        (
                            ordinal,
                            PersistBlobOutcome {
                                prepared,
                                error: Some(error.clone()),
                            },
                        )
                    })
                    .collect();
                (
                    outcomes,
                    PersistBatchStats {
                        failed_transaction_attempts: 1,
                        failed_blobs: batch_blobs,
                        failed_fragments: batch_fragments,
                        peak_batch_blobs: batch_blobs,
                        peak_batch_fragments: batch_fragments,
                        peak_batch_rows: batch_rows,
                        peak_batch_payload_bytes: batch_bytes,
                        ..PersistBatchStats::default()
                    },
                )
            }
            Err(mut error)
                if prepared
                    .first()
                    .zip(prepared.last())
                    .is_some_and(|((_, first), (_, last))| first.oid() == last.oid()) =>
            {
                let mut failed_attempts = 1;
                for retry in 1..=PREPARED_WRITE_IMMEDIATE_RETRIES {
                    std::thread::sleep(Duration::from_millis(10 * retry as u64));
                    match self.try_persist_prepared_chunk(&prepared, limits) {
                        Ok(actual_cost) => {
                            let outcomes = prepared
                                .into_iter()
                                .map(|(ordinal, prepared)| {
                                    (
                                        ordinal,
                                        PersistBlobOutcome {
                                            prepared,
                                            error: None,
                                        },
                                    )
                                })
                                .collect();
                            return (
                                outcomes,
                                PersistBatchStats {
                                    transactions: 1,
                                    failed_transaction_attempts: failed_attempts,
                                    committed_blobs: batch_blobs,
                                    committed_fragments: batch_fragments,
                                    logical_rows: actual_cost.logical_rows,
                                    payload_bytes: actual_cost.payload_bytes,
                                    peak_batch_blobs: batch_blobs,
                                    peak_batch_fragments: batch_fragments,
                                    peak_batch_rows: actual_cost.logical_rows,
                                    peak_batch_payload_bytes: actual_cost.payload_bytes,
                                    ..PersistBatchStats::default()
                                },
                            );
                        }
                        Err(retry_error) => {
                            failed_attempts = failed_attempts.saturating_add(1);
                            if retry_error.is_stale_generation()
                                || retry_error.is_stale_resolution()
                                || self.cancellation.is_cancelled()
                            {
                                error = retry_error;
                                break;
                            }
                            error = retry_error;
                        }
                    }
                }
                let outcomes = prepared
                    .into_iter()
                    .map(|(ordinal, prepared)| {
                        (
                            ordinal,
                            PersistBlobOutcome {
                                prepared,
                                error: Some(error.clone()),
                            },
                        )
                    })
                    .collect();
                (
                    outcomes,
                    PersistBatchStats {
                        failed_transaction_attempts: failed_attempts,
                        failed_blobs: batch_blobs,
                        failed_fragments: batch_fragments,
                        peak_batch_blobs: batch_blobs,
                        peak_batch_fragments: batch_fragments,
                        peak_batch_rows: batch_rows,
                        peak_batch_payload_bytes: batch_bytes,
                        ..PersistBatchStats::default()
                    },
                )
            }
            Err(_) => {
                let mut middle = prepared.len() / 2;
                while middle < prepared.len()
                    && prepared[middle - 1].1.oid() == prepared[middle].1.oid()
                {
                    middle += 1;
                }
                if middle == prepared.len() {
                    middle = prepared.len() / 2;
                    while middle > 0 && prepared[middle - 1].1.oid() == prepared[middle].1.oid() {
                        middle -= 1;
                    }
                }
                assert!((1..prepared.len()).contains(&middle));
                let right = prepared.split_off(middle);
                let (mut left_outcomes, mut stats) = self.persist_prepared_chunk(prepared, limits);
                let (right_outcomes, right_stats) = self.persist_prepared_chunk(right, limits);
                left_outcomes.extend(right_outcomes);
                stats.failed_transaction_attempts =
                    stats.failed_transaction_attempts.saturating_add(1);
                stats.peak_batch_blobs = stats.peak_batch_blobs.max(batch_blobs);
                stats.peak_batch_fragments = stats.peak_batch_fragments.max(batch_fragments);
                stats.peak_batch_rows = stats.peak_batch_rows.max(batch_rows);
                stats.peak_batch_payload_bytes = stats.peak_batch_payload_bytes.max(batch_bytes);
                stats.merge(right_stats);
                (left_outcomes, stats)
            }
        }
    }

    fn try_persist_prepared_chunk(
        &mut self,
        prepared: &[(usize, PreparedParsedBlob)],
        limits: PersistBatchTargets,
    ) -> Result<PersistedMutationCost> {
        if self.cancellation.is_cancelled() {
            return Err(StoreError::new("prepared blob persistence was cancelled"));
        }
        let counters = self.counters.clone();
        let cancellation = self.cancellation.clone();
        let result =
            resolution::with_resolution_progress_handler(self.conn, &cancellation, |conn| {
                try_persist_prepared_chunk_tx(conn, prepared, limits, &counters, &cancellation)
            });
        match result {
            Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                Err(StoreError::new("prepared blob persistence was cancelled"))
            }
            result => result,
        }
    }
}

fn try_persist_prepared_chunk_tx(
    conn: &mut Connection,
    prepared: &[(usize, PreparedParsedBlob)],
    limits: PersistBatchTargets,
    counters: &PreparedWriteCounters,
    cancellation: &CancellationToken,
) -> Result<PersistedMutationCost> {
    if cancellation.is_cancelled() {
        return Err(StoreError::new("prepared blob persistence was cancelled"));
    }
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = counters;
    #[cfg(any(test, feature = "test-support"))]
    counters.transaction_starts.fetch_add(1, Ordering::SeqCst);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut fragments = Vec::new();
    for (_, root) in prepared {
        root.append_fragments(&mut fragments);
    }
    let mut unique_by_key: HashMap<(Oid, String), usize> = HashMap::default();
    let mut unique_fragments: Vec<&PreparedParsedBlob> = Vec::with_capacity(fragments.len());
    for fragment in fragments {
        let key = (fragment.oid(), fragment.lang().to_owned());
        if let Some(&previous) = unique_by_key.get(&key) {
            if !unique_fragments[previous].has_same_persisted_fragment(fragment) {
                return Err(StoreError::new(format!(
                    "conflicting prepared fragments for {}/{}",
                    fragment.oid(),
                    fragment.lang()
                )));
            }
        } else {
            unique_by_key.insert(key, unique_fragments.len());
            unique_fragments.push(fragment);
        }
    }
    let mut generations = HashMap::default();
    let mut producer_epochs = HashMap::default();
    for blob in &unique_fragments {
        if let Some(existing) = generations.insert(blob.lang(), blob.generation)
            && existing != blob.generation
        {
            return Err(StoreError::stale_generation(format!(
                "conflicting prepared generations for language {}",
                blob.lang()
            )));
        }
        let expected_epoch = blob.resolution.producer_epoch();
        if let Some(existing) = producer_epochs.insert(blob.lang(), expected_epoch)
            && existing != expected_epoch
        {
            return Err(StoreError::stale_resolution(format!(
                "conflicting prepared resolution epochs for language {}",
                blob.lang()
            )));
        }
    }
    for (lang, generation) in generations {
        #[cfg(any(test, feature = "test-support"))]
        counters.generation_lookups.fetch_add(1, Ordering::SeqCst);
        require_current_generation(&tx, lang, generation)?;
    }
    for (lang, expected_epoch) in producer_epochs {
        resolution::require_active_resolution_epoch(&tx, lang, expected_epoch)?;
    }
    let mut restored_roots = PersistedMutationCost::default();
    let stored_costs = stored_blob_cascade_costs_conn(
        &tx,
        &unique_fragments,
        || {
            #[cfg(any(test, feature = "test-support"))]
            counters.replacement_lookups.fetch_add(1, Ordering::SeqCst);
        },
        &mut restored_roots,
    )?;
    let mut fallback_cost_statement =
        tx.prepare_cached(persisted_blob_mutation_cost_fallback_sql())?;
    let mut cost = restored_roots;
    for (blob, stored) in unique_fragments.iter().zip(stored_costs) {
        let replaced = match stored {
            StoredCascadeCost::Missing => PersistedMutationCost::default(),
            StoredCascadeCost::Known(cost) => cost,
            StoredCascadeCost::Legacy => {
                #[cfg(any(test, feature = "test-support"))]
                counters
                    .replacement_fallbacks
                    .fetch_add(1, Ordering::SeqCst);
                persisted_blob_mutation_cost_fallback_statement(
                    &mut fallback_cost_statement,
                    blob.oid_text.as_str(),
                    blob.lang(),
                )?
            }
        };
        cost.logical_rows = cost
            .logical_rows
            .saturating_add(blob.logical_rows())
            .saturating_add(replaced.logical_rows);
        cost.payload_bytes = cost
            .payload_bytes
            .saturating_add(blob.payload_bytes())
            .saturating_add(replaced.payload_bytes);
    }
    drop(fallback_cost_statement);
    // The caller sorts and splits only between OIDs. A complete source and
    // all of its projections are the smallest atomic publication unit; the
    // batching target must not turn that unit into a permanent cache miss.
    let multiple_source_groups = prepared
        .first()
        .zip(prepared.last())
        .is_some_and(|((_, first), (_, last))| first.oid() != last.oid());
    if multiple_source_groups
        && (unique_fragments.len() > limits.max_blobs
            || cost.logical_rows > limits.max_rows
            || cost.payload_bytes > limits.max_payload_bytes)
    {
        return Err(StoreError::resource_bound(format!(
            "prepared mutation batch exceeds grouping targets: blobs={}, rows={}, bytes={}",
            unique_fragments.len(),
            cost.logical_rows,
            cost.payload_bytes
        )));
    }
    for blob in unique_fragments {
        if cancellation.is_cancelled() {
            tx.rollback()?;
            return Err(StoreError::new("prepared blob persistence was cancelled"));
        }
        let blob_id = write_prepared_blob_rows_tx(&tx, blob, blob.generation, cancellation)?;
        if let Some(support) = store_language_support(blob.resolution.semantic_language()) {
            support.publish_native_source_rows(
                &tx,
                blob_id,
                &blob.state.resolution_facts,
                cancellation,
            )?;
        }
    }
    if cancellation.is_cancelled() {
        tx.rollback()?;
        return Err(StoreError::new("prepared blob persistence was cancelled"));
    }
    tx.commit()?;
    Ok(cost)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PersistedSideTableCounts {
    range_count: usize,
    signature_count: usize,
    signature_metadata_count: usize,
    supertype_count: usize,
    child_count: usize,
    import_statement_count: usize,
    type_identifier_count: usize,
    optional: OptionalFactCounts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
#[doc(hidden)]
pub enum OptionalFactKind {
    CppClassTemplate = OPTIONAL_FACT_KIND_CPP_CLASS_TEMPLATE,
    RubyMethodDispatchMode = OPTIONAL_FACT_KIND_RUBY_METHOD_DISPATCH_MODE,
    ScalaTrait = OPTIONAL_FACT_KIND_SCALA_TRAIT,
    ScalaExport = OPTIONAL_FACT_KIND_SCALA_EXPORT,
    MaterializationRecord = OPTIONAL_FACT_KIND_MATERIALIZATION_RECORD,
    SignatureMetadataSignature = OPTIONAL_FACT_KIND_SIGNATURE_METADATA_SIGNATURE,
}

impl OptionalFactKind {
    const fn slot(self) -> usize {
        match self {
            Self::CppClassTemplate => 0,
            Self::RubyMethodDispatchMode => 1,
            Self::ScalaTrait => 2,
            Self::ScalaExport => 3,
            Self::MaterializationRecord => 4,
            Self::SignatureMetadataSignature => 5,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct OptionalFactDescriptor {
    kind: OptionalFactKind,
    table: &'static str,
}

const OPTIONAL_FACT_DESCRIPTORS: [OptionalFactDescriptor; 6] = [
    OptionalFactDescriptor {
        kind: OptionalFactKind::CppClassTemplate,
        table: "unit_cpp_class_templates",
    },
    OptionalFactDescriptor {
        kind: OptionalFactKind::RubyMethodDispatchMode,
        table: "ruby_method_dispatch_modes",
    },
    OptionalFactDescriptor {
        kind: OptionalFactKind::ScalaTrait,
        table: "scala_traits",
    },
    OptionalFactDescriptor {
        kind: OptionalFactKind::ScalaExport,
        table: "scala_exports",
    },
    OptionalFactDescriptor {
        kind: OptionalFactKind::MaterializationRecord,
        table: "materialization_records",
    },
    OptionalFactDescriptor {
        kind: OptionalFactKind::SignatureMetadataSignature,
        table: "unit_signature_metadata_signatures",
    },
];

fn optional_fact_kind_list() -> String {
    OPTIONAL_FACT_DESCRIPTORS
        .iter()
        .map(|descriptor| (descriptor.kind as i64).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct OptionalFactCounts([usize; OPTIONAL_FACT_DESCRIPTORS.len()]);

impl OptionalFactCounts {
    #[doc(hidden)]
    pub fn get(self, kind: OptionalFactKind) -> usize {
        self.0[kind.slot()]
    }

    fn set(&mut self, kind: OptionalFactKind, count: usize) {
        self.0[kind.slot()] = count;
    }

    #[doc(hidden)]
    pub fn nonzero_len(self) -> usize {
        self.0.into_iter().filter(|count| *count > 0).count()
    }
}

#[doc(hidden)]
pub fn optional_fact_counts(
    cpp_class_templates: usize,
    ruby_dispatch_modes: usize,
    scala_traits: usize,
    scala_exports: usize,
    materialization_records: usize,
    signature_metadata_signature_ordinals: usize,
) -> OptionalFactCounts {
    let mut counts = OptionalFactCounts::default();
    counts.set(OptionalFactKind::CppClassTemplate, cpp_class_templates);
    counts.set(
        OptionalFactKind::RubyMethodDispatchMode,
        ruby_dispatch_modes,
    );
    counts.set(OptionalFactKind::ScalaTrait, scala_traits);
    counts.set(OptionalFactKind::ScalaExport, scala_exports);
    counts.set(
        OptionalFactKind::MaterializationRecord,
        materialization_records,
    );
    counts.set(
        OptionalFactKind::SignatureMetadataSignature,
        signature_metadata_signature_ordinals,
    );
    counts
}

fn insert_optional_fact_manifest(
    tx: &Transaction<'_>,
    blob_id: i64,
    counts: OptionalFactCounts,
) -> Result<()> {
    let mut stmt = tx.prepare_cached(
        "INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
         VALUES(?1, ?2, ?3)",
    )?;
    for descriptor in OPTIONAL_FACT_DESCRIPTORS {
        let kind = descriptor.kind;
        let count = counts.get(kind);
        if count > 0 {
            stmt.execute(params![blob_id, kind as i64, usize_to_i64(count)?])?;
        }
    }
    Ok(())
}

/// One `import_statements` row: an `ImportInfo`'s scalars, ordinal-keyed.
///
/// Legacy imports store their properties; canonical rows only link the
/// producer-owned import record, with no duplicate properties or byte spans.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportStatementRow {
    ordinal: i64,
    statement: Option<String>,
    is_wildcard: Option<i64>,
    is_global: Option<i64>,
    identifier: Option<String>,
    alias: Option<String>,
    path_kind: Option<&'static str>,
    declaration_start_byte: Option<i64>,
    binder_start: Option<i64>,
    binder_end: Option<i64>,
    source_import_id: Option<i64>,
}

/// A blob's import bindings as `import_statements` stores them. Both write paths
/// build this from `FileState::imports` and hand it to `insert_import_rows`,
/// so the prepared batch and the direct transaction cannot drift apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct ImportRows {
    statements: Vec<ImportStatementRow>,
}

impl ImportRows {
    #[doc(hidden)]
    pub fn from_imports(
        imports: &[ImportInfo],
        source_imports: Option<&[SourceImportId]>,
    ) -> Result<Self> {
        if let Some(sources) = source_imports {
            assert_eq!(
                sources.len(),
                imports.len(),
                "canonical import projections follow the producer's generic import order"
            );
        }
        let mut rows = Self {
            statements: Vec::with_capacity(imports.len()),
        };
        for (ordinal, import) in imports.iter().enumerate() {
            let source = source_imports.map(|sources| sources[ordinal]);
            let ordinal = usize_to_i64(ordinal)?;
            if let Some(source) = source {
                rows.statements.push(ImportStatementRow {
                    ordinal,
                    statement: None,
                    is_wildcard: None,
                    is_global: None,
                    identifier: None,
                    alias: None,
                    path_kind: None,
                    declaration_start_byte: None,
                    binder_start: None,
                    binder_end: None,
                    source_import_id: Some(i64::from(source.get())),
                });
                continue;
            }
            let (path_kind, declaration_start_byte) = match &import.path {
                Some(path) => {
                    assert!(
                        path.segments.is_empty()
                            && path.lexical_scopes.is_empty()
                            && path.lexical_prefixes.is_empty(),
                        "structured imports require canonical source-import storage"
                    );
                    (
                        path.kind.map(StructuredImportPathKind::persist_tag),
                        Some(usize_to_i64(path.declaration_start_byte)?),
                    )
                }
                None => (None, None),
            };
            let (binder_start, binder_end) = match import.binder_span {
                Some(span) => (
                    Some(usize_to_i64(span.start_byte)?),
                    Some(usize_to_i64(span.end_byte)?),
                ),
                None => (None, None),
            };
            rows.statements.push(ImportStatementRow {
                ordinal,
                statement: Some(import.raw_snippet.clone()),
                is_wildcard: Some(bool_to_i64(import.is_wildcard)),
                is_global: Some(bool_to_i64(import.is_global)),
                identifier: import.identifier.clone(),
                alias: import.alias.clone(),
                path_kind,
                declaration_start_byte,
                binder_start,
                binder_end,
                source_import_id: None,
            });
        }
        Ok(rows)
    }

    #[doc(hidden)]
    pub fn logical_rows(&self) -> usize {
        self.statements.len()
    }

    /// Text bytes these rows store. Integer columns are fixed width and priced
    /// by the row count above, so only the strings are counted here.
    #[doc(hidden)]
    pub fn string_bytes(&self) -> usize {
        saturating_sum(self.statements.iter().map(|row| {
            saturating_sum([
                row.statement.as_ref().map_or(0, String::len),
                row.identifier.as_ref().map_or(0, String::len),
                row.alias.as_ref().map_or(0, String::len),
            ])
        }))
    }
}

fn insert_import_rows(
    tx: &Transaction<'_>,
    blob_id: i64,
    lang: &str,
    rows: &ImportRows,
) -> Result<()> {
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO import_statements(
               blob_id, lang, ordinal, statement, is_wildcard, is_global,
               identifier, alias, path_kind, declaration_start_byte,
               binder_start, binder_end, source_import_id
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;
        for row in &rows.statements {
            stmt.execute(params![
                blob_id,
                lang,
                row.ordinal,
                row.statement,
                row.is_wildcard,
                row.is_global,
                row.identifier,
                row.alias,
                row.path_kind,
                row.declaration_start_byte,
                row.binder_start,
                row.binder_end,
                row.source_import_id,
            ])?;
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn saturating_sum(values: impl IntoIterator<Item = usize>) -> usize {
    values
        .into_iter()
        .fold(0usize, |total, value| total.saturating_add(value))
}

/// Lowers one parsed blob with the parse-time lowerer and encodes the outcome
/// as semantic IR rows over the tree the analysis walk read. `Ok(None)` means
/// preparation was cancelled.
#[doc(hidden)]
pub fn prepare_parse_time_semantic_ir(
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    oid: Oid,
    lang: &str,
    cancellation: &CancellationToken,
) -> Result<Option<PreparedSemanticIr>> {
    let _timing = crate::profiling::scope_with(|| {
        format!("store.prepare_parsed_blob.semantic_ir[{lang}][{oid}]")
    });
    let producer_epoch = semantic_ir_producer_epoch(&lowerer.identity());
    let content = ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
    let (outcome, artifact) = {
        let _lower = crate::profiling::scope("semantic_ir.lower");
        match lower_parse_time_semantic_ir(lowerer, file, prepared, content, cancellation) {
            Some(lowered) => lowered,
            None => return Ok(None),
        }
    };
    let partial_flows = match artifact {
        Some(artifact) => {
            let _partial_flows = crate::profiling::scope("semantic_ir.partial_flows");
            match parse_time_partial_flows(&artifact, prepared, cancellation) {
                Some(flows) => Some(flows),
                None => return Ok(None),
            }
        }
        None => None,
    };
    let _encode = crate::profiling::scope("semantic_ir.encode");
    Ok(Some(PreparedSemanticIr::prepare(
        outcome,
        partial_flows.as_deref(),
        &producer_epoch,
        content,
        prepared.source().len(),
    )))
}

/// The lowering outcome, validated the way a reader would validate it, and the
/// validated artifact of a complete outcome. `None` means the lowering was
/// cancelled and the blob preparation must stop.
fn lower_parse_time_semantic_ir(
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    content: ContentIdentity,
    cancellation: &CancellationToken,
) -> Option<(SemanticIrLoweringOutcome, Option<Arc<SemanticArtifact>>)> {
    let lowered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        lowerer.lower(file, prepared, &SemanticBudget::default(), cancellation)
    }));
    let lowered = match lowered {
        Ok(lowered) => lowered,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            return Some((
                SemanticIrLoweringOutcome::Panicked(message.to_owned()),
                None,
            ));
        }
    };
    if cancellation.is_cancelled() {
        return None;
    }
    let unvalidated = |outcome| Some((outcome, None));
    match lowered {
        Err(error) => unvalidated(SemanticIrLoweringOutcome::Error(error.to_string())),
        Ok(SemanticOutcome::Complete { value: parts, .. }) => {
            let key = match semantic_artifact_key_from_content(
                file,
                prepared.dialect(),
                content,
                None,
                lowerer.identity(),
            ) {
                Ok(key) => key,
                Err(error) => {
                    return unvalidated(SemanticIrLoweringOutcome::Error(error.to_string()));
                }
            };
            match SemanticArtifact::try_new_with_budget(
                key,
                lowerer.capabilities(),
                parts.clone(),
                &mut SemanticBudget::default(),
            ) {
                Ok(artifact) => Some((
                    SemanticIrLoweringOutcome::Complete { parts },
                    Some(Arc::new(artifact)),
                )),
                Err(SemanticArtifactBuildError::Invalid(error)) => {
                    unvalidated(SemanticIrLoweringOutcome::Error(error.to_string()))
                }
                Err(SemanticArtifactBuildError::ExceededBudget(exceeded)) => {
                    unvalidated(SemanticIrLoweringOutcome::ExceededBudget(exceeded))
                }
            }
        }
        Ok(SemanticOutcome::ExceededBudget { exceeded, .. }) => {
            unvalidated(SemanticIrLoweringOutcome::ExceededBudget(exceeded))
        }
        Ok(SemanticOutcome::Unsupported { capability, .. }) => {
            unvalidated(SemanticIrLoweringOutcome::Unsupported(capability))
        }
        Ok(SemanticOutcome::Cancelled { .. }) => None,
        Ok(other) => unvalidated(SemanticIrLoweringOutcome::Incomplete {
            label: other.label(),
        }),
    }
}

/// The file a test blob is parsed and lowered as when the test does not name
/// one. It has no extension, so it takes its language's default grammar.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn test_blob_file() -> ProjectFile {
    ProjectFile::new(std::env::temp_dir(), "test_blob")
}

fn write_prepared_blob_rows_tx(
    tx: &Transaction<'_>,
    blob: &PreparedParsedBlob,
    generation: GenerationId,
    cancellation: &CancellationToken,
) -> Result<i64> {
    let oid = blob.oid_text.as_str();
    let lang = blob.lang.as_str();
    // Every statement in this batch path is connection-cached: a cold reconcile
    // writes hundreds of blobs per transaction and re-preparing ~25 statements
    // per blob was a measured writer-CPU cost (issue #2326).
    //
    // The DELETE is what clears the blob's previous publication: every fact
    // table cascades from `blobs`, directly or through `code_units`,
    // `import_statements` or `blob_meta`. IDs remain database-owned. A Rust
    // repair preserves its ID when persisted crate rows retain references
    // to the same immutable content and epoch. Nothing outside SQLite holds
    // an ID across a query.
    let Some(previous_owners) =
        resolution_publication::repair_owners_tx(tx, oid, lang, generation, cancellation)?
    else {
        return Err(StoreError::new("prepared blob persistence was cancelled"));
    };
    let previous_blob = if lang == "rust" {
        tx.prepare_cached(rust_crates::REPLACED_BLOB_ID_SQL)?
            .query_row(params![oid, lang, generation.0], |row| row.get::<_, i64>(0))
            .optional()?
    } else {
        None
    };
    if previous_blob.is_some() {
        // Crate rows retain blob IDs inside SQLite. A repair of the same
        // content and epoch preserves their facts and ID. Defer FK validation
        // across the delete/reinsert so the normal cascade clears damaged facts.
        tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    }
    // The delete below cascades away the old row's unit summary members, exports
    // and imports, so the summaries that listed it stop being live first.
    tx.prepare_cached(unit_summaries::WITHDRAW_VERSIONS_OF_REPLACED_BLOB_SQL)?
        .execute(params![oid, lang])?;
    tx.prepare_cached("DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2")?
        .execute(params![oid, lang])?;
    tx.prepare_cached(rust_crates::REINSERT_BLOB_SQL)?
        .execute(params![previous_blob, oid, lang, generation.0])?;
    let blob_id = tx.last_insert_rowid();
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
               exact_fqn, normalized_fqn, simple_type_name, signature, synthetic,
               is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup,
               in_test_region, fq_segment_count, fq_segment_bytes,
               fq_anchor_kind, fq_anchor_pop,
               fq_package_tail_segments, exact_fqn_tail, normalized_fqn_tail,
               exact_parent_fqn_tail, normalized_parent_fqn_tail, package_fqn_tail
             ) VALUES(
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
               ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27
             )",
        )?;
        for row in &blob.units {
            stmt.execute(params![
                blob_id,
                lang,
                row.key,
                row.kind,
                row.short_name,
                row.identifier,
                row.content_qualifier,
                row.exact_fqn,
                row.normalized_fqn,
                row.simple_type_name,
                row.signature,
                row.synthetic,
                row.is_type_alias,
                row.top_level_ordinal,
                row.in_declarations,
                row.in_definition_lookup,
                row.in_test_region,
                row.fq_segment_count,
                row.fq_segment_bytes,
                row.fq_anchor_kind,
                row.fq_anchor_pop,
                row.fq_package_tail_segments,
                row.exact_fqn_tail,
                row.normalized_fqn_tail,
                row.exact_parent_fqn_tail,
                row.normalized_parent_fqn_tail,
                row.package_fqn_tail,
            ])?;
        }
    }
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO code_unit_fq_segments(
               blob_id, lang, unit_key, seg_ordinal, seg_kind, segment
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for row in &blob.units {
            for (ordinal, kind, segment) in &row.relational_fq_segments {
                stmt.execute(params![blob_id, lang, row.key, ordinal, kind, segment])?;
            }
        }
    }
    macro_rules! insert_rows {
        ($sql:expr, $rows:expr, |$stmt:ident, $row:ident| $body:block) => {{
            let mut $stmt = tx.prepare_cached($sql)?;
            for $row in $rows $body
        }};
    }
    insert_rows!(
        "INSERT OR IGNORE INTO unit_ranges(blob_id, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &blob.ranges,
        |stmt, row| {
            stmt.execute(params![
                blob_id, lang, row.0, row.1, row.2, row.3, row.4, row.5
            ])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_signatures(blob_id, lang, unit_key, ordinal, text) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.signatures,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    {
        let rows = blob
            .signature_metadata
            .iter()
            .map(|(unit_key, ordinal, metadata)| {
                metadata.bound_row(blob_id, lang, *unit_key, *ordinal)
            })
            .collect::<Vec<_>>();
        let (prefix, _) = signature_metadata_insert_sql()
            .split_once(" VALUES")
            .expect("signature metadata insert has a VALUES clause");
        let prefix = format!("{prefix} VALUES");
        let arity = 4 + SIGNATURE_METADATA_VALUE_COLUMNS.len();
        let row_sql = format!("({})", vec!["?"; arity].join(", "));
        source_facts::insert_rows(tx, &prefix, &row_sql, &rows, cancellation)?;
    }
    insert_rows!(
        "INSERT OR IGNORE INTO unit_signature_metadata_signatures(
           blob_id, unit_key, metadata_ordinal, signature_ordinal
         ) VALUES(?1, ?2, ?3, ?4)",
        &blob.signature_metadata_signature_ordinals,
        |stmt, row| {
            stmt.execute(params![blob_id, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_supertypes(blob_id, lang, unit_key, ordinal, raw, lookup_path) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        &blob.supertypes,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2, row.3])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO unit_children(blob_id, lang, parent_key, child_key, ordinal) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.children,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    insert_import_rows(tx, blob_id, lang, &blob.imports)?;
    insert_rows!(
        "INSERT OR IGNORE INTO scala_exports(blob_id, lang, owner_key, ordinal, info) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.scala_exports,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO reference_identifiers(blob_id, lang, identifier) VALUES(?1, ?2, ?3)",
        &blob.type_identifiers,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO ruby_method_dispatch_modes(blob_id, lang, unit_key, mode) VALUES(?1, ?2, ?3, ?4)",
        &blob.ruby_dispatch_modes,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO materialization_records(blob_id, lang, ordinal, unit_key, payload) VALUES(?1, ?2, ?3, ?4, ?5)",
        &blob.materialization_records,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row.0, row.1, row.2])?;
        }
    );
    insert_rows!(
        "INSERT OR IGNORE INTO scala_traits(blob_id, lang, unit_key) VALUES(?1, ?2, ?3)",
        &blob.scala_traits,
        |stmt, row| {
            stmt.execute(params![blob_id, lang, row])?;
        }
    );
    insert_rust_fact_rows(tx, blob_id, lang, &blob.rust_facts)?;
    blob.cpp_templates.insert(tx, blob_id, cancellation)?;
    tx.prepare_cached("INSERT OR IGNORE INTO reference_fact_epochs(lang, epoch) VALUES(?1, 1)")?
        .execute([lang])?;
    tx.prepare_cached(
        "INSERT INTO blob_reference_fact_manifests(blob_id, lang, epoch, identifier_count)
         VALUES(?1, ?2, 1, ?3)
         ON CONFLICT(blob_id) DO UPDATE SET
           epoch = excluded.epoch,
           identifier_count = excluded.identifier_count",
    )?
    .execute(params![
        blob_id,
        lang,
        usize_to_i64(blob.type_identifiers.len())?
    ])?;
    tx.prepare_cached(
        "INSERT OR IGNORE INTO blob_meta(
           blob_id, lang, contains_tests, content_package, stored_unit_count,
           range_count, signature_count, signature_metadata_count, supertype_count,
           child_count, import_statement_count, type_identifier_count, is_complete,
           declaration_visibility_version, java_type_constructor_version, go_source_version, java_source_version, scala_source_version, ruby_source_version, php_source_version, cpp_source_version, source_facts_version, metadata_bridges_required, js_ts_source_version, python_source_version, native_bridges_required, parse_completeness
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
    )?
    .execute(params![
        blob_id,
        lang,
        blob.contains_tests,
        blob.content_package,
        usize_to_i64(blob.units.len())?,
        usize_to_i64(blob.ranges.len())?,
        usize_to_i64(blob.signatures.len())?,
        usize_to_i64(blob.signature_metadata.len())?,
        usize_to_i64(blob.supertypes.len())?,
        usize_to_i64(blob.children.len())?,
        usize_to_i64(blob.imports.statements.len())?,
        usize_to_i64(blob.type_identifiers.len())?,
        blob.declaration_visibility_version,
        blob.java_type_constructor_version,
        blob.go_source_version,
        blob.java_source_version,
        blob.scala_source_version,
        blob.ruby_source_version,
        blob.php_source_version,
        blob.cpp_source_version,
        blob.source_facts_version,
        blob.metadata_bridges_required,
        blob.js_ts_source_version,
        blob.python_source_version,
        blob.source_facts_version.is_some(),
        blob.state.completeness.label(),
    ])?;
    insert_optional_fact_manifest(
        tx,
        blob_id,
        optional_fact_counts(
            blob.cpp_templates.header_count(),
            blob.ruby_dispatch_modes.len(),
            blob.scala_traits.len(),
            blob.scala_exports.len(),
            blob.materialization_records.len(),
            blob.signature_metadata_signature_ordinals.len(),
        ),
    )?;
    let integrity_condition = PARSED_BLOB_STRUCTURAL_INTEGRITY_CONDITION.as_str();
    let integrity_sql = format!(
        "SELECT 1 FROM blob_meta AS meta
         WHERE meta.blob_id = ?1
           AND {integrity_condition}"
    );
    let complete = tx
        .prepare_cached(&integrity_sql)?
        .query_row(params![blob_id], |_| Ok(()))
        .optional()?
        .is_some();
    if !complete {
        return Err(StoreError::new(format!(
            "prepared blob {oid}/{lang} failed post-write integrity validation"
        )));
    }
    if let Some(facts) = blob.state.source_facts.as_ref() {
        source_facts::insert_source_facts_tx(
            blob.source_storage,
            tx,
            blob_id,
            facts,
            &blob.source_declaration_units,
            &blob.source_declaration_metadata,
            cancellation,
        )?;
    }
    if !resolution::insert_prepared_bundle_tx(tx, blob_id, lang, &blob.resolution, cancellation)? {
        return Err(StoreError::new("prepared blob persistence was cancelled"));
    }
    if let Some(semantic_ir) = blob.semantic_ir.as_ref()
        && !insert_semantic_ir_tx(tx, blob_id, lang, semantic_ir, cancellation)?
    {
        return Err(StoreError::new("prepared blob persistence was cancelled"));
    }
    let source_ready: bool = tx.query_row(
        "SELECT available FROM source_fact_readiness WHERE blob_id = ?1",
        [blob_id],
        |row| row.get(0),
    )?;
    if !source_ready {
        return Err(StoreError::new(format!(
            "prepared blob {oid}/{lang} has unavailable canonical source facts"
        )));
    }
    if let Some(version) = blob.cpp_source_version {
        let cpp_ready: bool = tx.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM source_cpp_manifests AS marker
               JOIN source_fact_manifests AS source ON source.blob_id = marker.blob_id
               WHERE marker.blob_id = ?1 AND marker.facts_version = ?2
                 AND source.publication_state = 'complete'
             )",
            params![blob_id, version],
            |row| row.get(0),
        )?;
        if !cpp_ready {
            return Err(StoreError::new(format!(
                "prepared blob {oid}/{lang} has unavailable C++ source facts"
            )));
        }
    }
    let resolution_payload_bytes: usize = tx.query_row(
        "SELECT payload_bytes FROM resolution_fragment_interiors WHERE blob_id = ?1",
        [blob_id],
        |row| row.get(0),
    )?;
    let persisted_payload_bytes = blob
        .persisted_payload_bytes()
        .checked_sub(
            blob.resolution
                .payload_bytes()
                .saturating_add(blob.lang.len()),
        )
        .expect("parsed publication includes its resolution estimate and storage language")
        .saturating_add(resolution_payload_bytes);
    insert_blob_payload_cost_tx(tx, blob_id, persisted_payload_bytes)?;
    for owner in &previous_owners {
        resolution_publication::root_content_tx(tx, owner, blob_id)?;
    }
    Ok(blob_id)
}

/// The language-specific side-fact tables one language's parse can fill.
///
/// Every language persists units, children, ranges, signatures, signature
/// metadata, imports and type identifiers. The families here belong to some
/// languages only: a Rust parse never writes a supertype, a Ruby dispatch mode,
/// a Scala trait or export, a materialization record or a C++ template. The
/// adapter says which of them its parse can produce; publishing a parsed blob
/// asserts the parse stayed inside that set, and hydrating one reads only
/// those tables, so a Rust file's first touch no longer runs a statement per
/// other language's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideFactFamilies {
    pub supertypes: bool,
    pub ruby_method_dispatch_modes: bool,
    pub scala_traits: bool,
    pub scala_exports: bool,
    pub materialization_records: bool,
    pub cpp_class_templates: bool,
}

impl SideFactFamilies {
    pub const EVERY: Self = Self {
        supertypes: true,
        ruby_method_dispatch_modes: true,
        scala_traits: true,
        scala_exports: true,
        materialization_records: true,
        cpp_class_templates: true,
    };
    pub const NONE: Self = Self {
        supertypes: false,
        ruby_method_dispatch_modes: false,
        scala_traits: false,
        scala_exports: false,
        materialization_records: false,
        cpp_class_templates: false,
    };

    /// Whether a parse produced facts only in these families.
    #[doc(hidden)]
    pub fn admits(self, state: &FileState) -> bool {
        (self.supertypes
            || state.raw_supertypes.is_empty() && state.supertype_lookup_paths.is_empty())
            && (self.ruby_method_dispatch_modes || state.ruby_method_dispatch_modes.is_empty())
            && (self.scala_traits || state.scala_traits.is_empty())
            && (self.scala_exports || state.scala_exports.is_empty())
            && (self.materialization_records || state.materialization_records.is_empty())
            && (self.cpp_class_templates || state.cpp_template_metadata.is_empty())
    }
}

#[doc(hidden)]
pub fn require_complete_file_state(state: &FileState) -> Result<()> {
    if !state.parse_complete {
        return Err(StoreError::new(
            "timed-out file analysis cannot be published as a complete parsed blob",
        ));
    }
    Ok(())
}

/// Enumerate the name-keyed entries exposed by a complete file projection.
///
/// Hydrated projections intentionally omit canonical publication facts. Reading
/// their index keys must not prepare a new publication. Use the same stored-unit
/// selection as the writer and the structured import paths restored by its views.
#[doc(hidden)]
pub fn file_state_index_keys<A: StoreLanguageAdapter>(
    adapter: &A,
    state: &FileState,
    sink: &mut dyn FnMut(IndexFamily, &[u8]),
) {
    for projection in std::iter::once(state).chain(
        state
            .additional_projections
            .iter()
            .map(|(_, state)| state.as_ref()),
    ) {
        debug_assert!(
            projection.additional_projections.is_empty() || std::ptr::eq(projection, state),
            "a projection reading carries no readings of its own"
        );
        for stored in collect_stored_units(adapter, projection) {
            let exact_fqn = stored.unit.fq_name();
            sink(IndexFamily::DefinitionExact, exact_fqn.as_bytes());
            sink(
                IndexFamily::DefinitionNormalizedTail,
                adapter.normalize_full_name(&exact_fqn).as_bytes(),
            );
            sink(
                IndexFamily::DefinitionIdentifier,
                stored.unit.short_name().as_bytes(),
            );
            sink(
                IndexFamily::DefinitionIdentifier,
                stored.unit.identifier().as_bytes(),
            );
        }
        for identifier in &projection.type_identifiers {
            sink(IndexFamily::ReferenceIdentifier, identifier.as_bytes());
        }
        for path in projection
            .imports
            .iter()
            .filter_map(|import| import.path.as_ref())
        {
            for segment in &path.segments {
                sink(IndexFamily::ImportPathSegment, segment.as_bytes());
            }
        }
    }
}

#[doc(hidden)]
pub fn collect_stored_units<A: StoreLanguageAdapter>(
    adapter: &A,
    state: &FileState,
) -> Vec<StoredUnit> {
    let mut candidates: HashSet<CodeUnit> = HashSet::default();
    candidates.extend(state.top_level_declarations.iter().cloned());
    candidates.extend(state.declarations.iter().cloned());
    candidates.extend(state.definition_lookup_units.iter().cloned());
    candidates.extend(state.raw_supertypes.keys().cloned());
    candidates.extend(state.signatures.keys().cloned());
    candidates.extend(state.signature_metadata.keys().cloned());
    candidates.extend(state.signature_metadata_signature_ordinals.keys().cloned());
    candidates.extend(state.cpp_template_metadata.keys().cloned());
    candidates.extend(state.ranges.keys().cloned());
    candidates.extend(state.children.keys().cloned());
    candidates.extend(state.children.values().flatten().cloned());
    candidates.extend(state.type_aliases.iter().cloned());
    candidates.extend(state.ruby_method_dispatch_modes.keys().cloned());
    candidates.extend(state.scala_traits.iter().cloned());
    candidates.extend(state.scala_exports.keys().cloned());
    candidates.extend(
        state
            .materialization_records
            .iter()
            .filter_map(|record| record.split().0.cloned()),
    );

    let top_level_ordinals: HashMap<CodeUnit, usize> = state
        .top_level_declarations
        .iter()
        .enumerate()
        .filter(|(_, unit)| adapter.should_persist_code_unit(unit))
        .map(|(ordinal, unit)| (unit.clone(), ordinal))
        .collect();

    let mut units: Vec<_> = candidates
        .into_iter()
        .filter(|unit| adapter.should_persist_code_unit(unit))
        .map(|unit| {
            let top_level_ordinal = top_level_ordinals.get(&unit).copied();
            StoredUnit {
                key: 0,
                is_type_alias: state.type_aliases.contains(&unit),
                top_level_ordinal,
                in_declarations: state.declarations.contains(&unit),
                in_definition_lookup: state.definition_lookup_units.contains(&unit),
                in_test_region: state.test_region_units.contains(&unit),
                unit,
            }
        })
        .collect();

    units.sort_by(|left, right| {
        stored_unit_order_key(state, &left.unit).cmp(&stored_unit_order_key(state, &right.unit))
    });
    for (index, unit) in units.iter_mut().enumerate() {
        unit.key = index as i64;
    }
    units
}

#[doc(hidden)]
pub fn stored_unit_keys_from_units(units: &[StoredUnit]) -> HashMap<CodeUnit, i64> {
    units
        .iter()
        .map(|stored| (stored.unit.clone(), stored.key))
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn stored_unit_keys<A: StoreLanguageAdapter>(
    adapter: &A,
    state: &FileState,
) -> HashMap<CodeUnit, i64> {
    stored_unit_keys_from_units(&collect_stored_units(adapter, state))
}

fn stored_unit_order_key(
    state: &FileState,
    unit: &CodeUnit,
) -> (usize, String, String, i64, String, bool) {
    let first_range = state
        .ranges
        .get(unit)
        .and_then(|ranges| ranges.iter().map(|range| range.start_byte).min())
        .unwrap_or(usize::MAX);
    (
        first_range,
        unit.short_name().to_string(),
        unit.signature().unwrap_or("").to_string(),
        code_unit_kind_to_i64(unit.kind()),
        unit.package_name().to_string(),
        unit.is_synthetic(),
    )
}

#[doc(hidden)]
pub struct UnitRow {
    key: i64,
    #[doc(hidden)]
    pub unit: CodeUnit,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
    in_test_region: bool,
}

#[derive(Debug, Clone)]
struct RawUnitRow {
    blob_oid: Oid,
    key: i64,
    kind: CodeUnitType,
    content_qualifier: String,
    signature: Option<String>,
    synthetic: bool,
    is_type_alias: bool,
    top_level_ordinal: Option<usize>,
    in_declarations: bool,
    in_definition_lookup: bool,
    in_test_region: bool,
    fq: Option<RelationalUnitFq>,
}

/// The unit columns a raw row decodes, WITHOUT the blob key: `blob_oid` lives
/// only in `blobs` now, so every caller projects it from the registry row it
/// already joins and puts it first.
const RAW_UNIT_COLUMNS: &str = "unit_key, kind, content_qualifier, signature, synthetic,
     is_type_alias, top_level_ordinal, in_declarations, in_definition_lookup,
     in_test_region, fq_anchor_kind, fq_anchor_pop, fq_package_tail_segments,
     fq_segment_count, exact_fqn_tail, fq_segment_bytes, normalized_fqn_tail";

fn raw_unit_columns_sql(alias: &str) -> String {
    format!(
        "keys.blob_oid, {alias}.unit_key, {alias}.kind,
         {alias}.content_qualifier, {alias}.signature, {alias}.synthetic,
         {alias}.is_type_alias, {alias}.top_level_ordinal,
         {alias}.in_declarations, {alias}.in_definition_lookup,
         {alias}.in_test_region, {alias}.fq_anchor_kind, {alias}.fq_anchor_pop,
         {alias}.fq_package_tail_segments, {alias}.fq_segment_count,
         {alias}.exact_fqn_tail, {alias}.fq_segment_bytes,
         {alias}.normalized_fqn_tail"
    )
}

fn raw_unit_row_from_row(row: &rusqlite::Row<'_>, base: usize) -> rusqlite::Result<RawUnitRow> {
    let oid_text = row.get::<_, String>(base)?;
    let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(base, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let kind_raw = row.get::<_, i64>(base + 2)?;
    let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            base + 2,
            rusqlite::types::Type::Integer,
            Box::new(err),
        )
    })?;
    Ok(RawUnitRow {
        blob_oid,
        key: row.get(base + 1)?,
        kind,
        content_qualifier: row.get(base + 3)?,
        signature: row.get(base + 4)?,
        synthetic: row.get::<_, i64>(base + 5)? != 0,
        is_type_alias: row.get::<_, i64>(base + 6)? != 0,
        top_level_ordinal: row
            .get::<_, Option<i64>>(base + 7)?
            .map(i64_to_usize)
            .transpose()
            .map_err(rusqlite_error_from_store)?,
        in_declarations: row.get::<_, i64>(base + 8)? != 0,
        in_definition_lookup: row.get::<_, i64>(base + 9)? != 0,
        in_test_region: row.get::<_, i64>(base + 10)? != 0,
        fq: fq_identity_header_from_row(row, base + 11)?.map(RelationalUnitFq::from_header),
    })
}

fn attach_raw_unit_fq_segments(
    conn: &Connection,
    lang: &str,
    oids: &[String],
    rows: &mut [RawUnitRow],
) -> Result<()> {
    assert!(attach_raw_unit_fq_segments_while(
        conn,
        lang,
        oids,
        rows,
        &|| true
    )?);
    Ok(())
}

fn attach_raw_unit_fq_segments_while(
    conn: &Connection,
    lang: &str,
    oids: &[String],
    rows: &mut [RawUnitRow],
    keep_going: &dyn Fn() -> bool,
) -> Result<bool> {
    let mut loaded: HashMap<(Oid, i64), Vec<(SegmentKind, String)>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if !keep_going() {
            return Ok(false);
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = raw_unit_fq_segments_sql(&placeholders);
        let parameters = chunk_params(lang, chunk);
        let mut statement = conn.prepare_cached(&sql)?;
        let mut query = statement.query(params_from_iter(parameters.iter()))?;
        while let Some(row) = query.next()? {
            if !keep_going() {
                return Ok(false);
            }
            let oid_text = row.get::<_, String>(0)?;
            let oid = Oid::from_str(&oid_text).map_err(|err| {
                StoreError::new(format!(
                    "invalid FqName segment blob oid {oid_text:?}: {err}"
                ))
            })?;
            let unit_key = row.get::<_, i64>(1)?;
            let ordinal = i64_to_usize(row.get::<_, i64>(2)?)?;
            let kind_text = row.get::<_, String>(3)?;
            let segment = row.get::<_, String>(4)?;
            let segments = loaded.entry((oid, unit_key)).or_default();
            if ordinal != segments.len() {
                return Err(StoreError::new(format!(
                    "analyzer store FqName segments are not dense: expected ordinal {}, got {ordinal}",
                    segments.len()
                )));
            }
            segments.push((segment_kind_from_sql(&kind_text)?, segment));
        }
    }
    for row in rows {
        if !keep_going() {
            return Ok(false);
        }
        let key = (row.blob_oid, lang.to_string(), row.key);
        let segments = loaded
            .get(&(row.blob_oid, row.key))
            .cloned()
            .unwrap_or_default();
        attach_complete_relational_fq(&mut row.fq, segments, &key)?;
    }
    Ok(keep_going())
}

fn raw_unit_fq_segments_sql(placeholders: &str) -> String {
    format!(
        "SELECT keys.blob_oid, facts.unit_key, facts.seg_ordinal, facts.seg_kind,
                facts.segment
         FROM blobs AS keys
         JOIN code_unit_fq_segments AS facts ON facts.blob_id = keys.id
         WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
         ORDER BY keys.blob_oid, facts.unit_key, facts.seg_ordinal"
    )
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct BlobMetaRow {
    contains_tests: bool,
    content_package: String,
    raw_content_package: String,
    type_identifiers: HashSet<String>,
    #[doc(hidden)]
    pub stored_unit_count: usize,
    completeness: crate::analyzer::ParseCompleteness,
    side_counts: PersistedSideTableCounts,
}

#[derive(Debug, Clone, Copy)]
struct SummaryProjectionMeta {
    stored_unit_count: usize,
    range_count: usize,
    signature_count: usize,
    child_count: usize,
    import_statement_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct RawSideTableCounts {
    range_count: i64,
    signature_count: i64,
    signature_metadata_count: i64,
    supertype_count: i64,
    child_count: i64,
    import_statement_count: i64,
    type_identifier_count: i64,
    optional: [i64; OPTIONAL_FACT_DESCRIPTORS.len()],
    unknown_optional_count: i64,
}

type BlobMetaRows = HashMap<String, BlobMetaRow>;
type SignatureMetadataRow = (i64, SignatureMetadata);
type SignatureMetadataRows = HashMap<String, Vec<SignatureMetadataRow>>;
type SignatureMetadataSignatureOrdinalRow = (i64, i64, i64);
type SignatureMetadataSignatureOrdinalRows =
    HashMap<String, Vec<SignatureMetadataSignatureOrdinalRow>>;
type ScalaExportRows = HashMap<String, Vec<(i64, Vec<u8>)>>;
type MaterializationRecordRows = HashMap<String, Vec<(Option<i64>, Vec<u8>)>>;
type RangeRow = (i64, i64, i64, i64, i64);
type RangeRows = HashMap<String, Vec<RangeRow>>;
type RubyDispatchRows = HashMap<String, Vec<(i64, i64)>>;
type ScalaTraitRows = HashMap<String, Vec<i64>>;

fn hydrate_file_state_conn<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> Result<Option<FileState>> {
    let oid = oid.to_string();
    let meta = read_blob_meta(conn, &oid, lang, adapter, file, source)?;
    let Some(meta) = meta else {
        return Ok(None);
    };

    let rows = read_unit_rows(conn, &oid, lang, adapter, file)?;
    if rows.len() != meta.stored_unit_count {
        return Ok(None);
    }
    let mut by_key = HashMap::default();
    for row in rows {
        by_key.insert(row.key, row);
    }

    let mut top_level: Vec<_> = by_key
        .values()
        .filter_map(|row| {
            row.top_level_ordinal
                .map(|ordinal| (ordinal, row.unit.clone()))
        })
        .collect();
    top_level.sort_by_key(|(ordinal, _)| *ordinal);

    let mut declarations = set_with_capacity(by_key.len());
    let mut definition_lookup_units = HashSet::default();
    let mut type_aliases = HashSet::default();
    let mut test_region_units = HashSet::default();
    for row in by_key.values() {
        if row.in_declarations {
            declarations.insert(row.unit.clone());
        }
        if row.in_definition_lookup {
            definition_lookup_units.insert(row.unit.clone());
        }
        if row.is_type_alias {
            type_aliases.insert(row.unit.clone());
        }
        if row.in_test_region {
            test_region_units.insert(row.unit.clone());
        }
    }

    // A family this language's parse cannot produce has no row for the blob:
    // publication asserted as much (`SideFactFamilies::admits`), so its table
    // is not read and the recount below compares it as empty.
    let families = adapter.side_fact_families();
    let children = read_children(conn, &oid, lang, &by_key)?;
    let (raw_supertypes, supertype_lookup_paths) = if families.supertypes {
        (
            read_unit_string_vec(conn, &oid, lang, "unit_supertypes", "raw", &by_key)?,
            read_unit_string_vec(conn, &oid, lang, "unit_supertypes", "lookup_path", &by_key)?,
        )
    } else {
        (HashMap::default(), HashMap::default())
    };
    let ruby_method_dispatch_modes = if families.ruby_method_dispatch_modes {
        read_ruby_method_dispatch_modes(conn, &oid, lang, &by_key)?
    } else {
        HashMap::default()
    };
    let scala_traits = if families.scala_traits {
        read_scala_traits(conn, &oid, lang, &by_key)?
    } else {
        HashSet::default()
    };
    let imports = read_import_infos(conn, &oid, lang)?;
    let scala_exports = if families.scala_exports {
        read_scala_exports(conn, &oid, lang, &by_key)?
    } else {
        HashMap::default()
    };
    let materialization_records = if families.materialization_records {
        read_materialization_records(conn, &oid, lang, &by_key)?
    } else {
        Vec::new()
    };
    let signatures = read_unit_string_vec(conn, &oid, lang, "unit_signatures", "text", &by_key)?;
    let signature_metadata = read_signature_metadata(conn, &oid, lang, &by_key)?;
    let signature_metadata_signature_ordinals =
        read_signature_metadata_signature_ordinals(conn, &oid, lang)?;
    let signature_metadata_signature_ordinals = signature_metadata_signature_ordinals_map_for_file(
        Some(&signature_metadata_signature_ordinals),
        &by_key,
        &signatures,
        &signature_metadata,
    )?;
    let ranges = read_ranges(conn, &oid, lang, &by_key)?;
    let cpp_template_metadata = if families.cpp_class_templates {
        let cpp_templates_by_oid = cpp_template::read_bulk(conn, lang, std::slice::from_ref(&oid))?;
        cpp_template::map_for_file(cpp_templates_by_oid.get(&oid), &by_key)?
    } else {
        HashMap::default()
    };

    let actual_counts = side_table_counts_from_hydrated_parts(HydratedSideTableParts {
        cpp_class_template_count: cpp_template_metadata.len(),
        ranges: &ranges,
        signatures: &signatures,
        signature_metadata: &signature_metadata,
        signature_metadata_signature_ordinals: &signature_metadata_signature_ordinals,
        raw_supertypes: &raw_supertypes,
        children: &children,
        import_statement_count: imports.len(),
        type_identifier_count: meta.type_identifiers.len(),
        ruby_dispatch_count: ruby_method_dispatch_modes.len(),
        scala_trait_count: scala_traits.len(),
        scala_export_count: scala_exports.values().map(Vec::len).sum(),
        materialization_record_count: materialization_records.len(),
    });
    if actual_counts != meta.side_counts {
        return Ok(None);
    }

    let mut state = FileState {
        source: String::new(),
        package_name: meta.content_package,
        content_qualifier: meta.raw_content_package,
        top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
        declarations,
        definition_lookup_units,
        imports,
        scala_exports,
        // Not hydrated: the Rust fact tables are read by blob oid straight from
        // SQL, never through a materialized `FileState`. See the field's doc.
        rust_usage_facts: Default::default(),
        // Intentionally not hydrated: selected consumers read the normalized
        // resolution rows from SQL. Hydration must never reconstruct them by
        // parsing request-time source.
        resolution_facts: Default::default(),
        source_facts: None,
        source_declaration_units: Vec::new(),
        source_declaration_metadata: Vec::new(),
        raw_supertypes,
        supertype_lookup_paths,
        type_identifiers: meta.type_identifiers,
        signatures,
        signature_metadata,
        signature_metadata_signature_ordinals,
        cpp_template_metadata,
        ranges,
        children,
        type_aliases,
        ruby_method_dispatch_modes,
        scala_traits,
        contains_tests: meta.contains_tests,
        test_region_units,
        materialization_records,
        completeness: meta.completeness,
        parse_errors: None,
        parse_complete: true,
        additional_projections: Vec::new(),
    };

    adapter.synthesize_hydrated_units(file, source, &mut state)?;
    synthesize_file_scope(file, source, &mut state);
    Ok(Some(state))
}

fn summary_file_projection_conn<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> Result<Option<SummaryFileProjection>> {
    let oid = oid.to_string();
    let Some(meta) = read_summary_projection_meta(conn, &oid, lang)? else {
        return Ok(None);
    };

    let rows = read_unit_rows(conn, &oid, lang, adapter, file)?;
    if rows.len() != meta.stored_unit_count {
        return Ok(None);
    }
    let mut by_key = HashMap::default();
    let mut declarations = Vec::new();
    for row in rows {
        if row.in_declarations {
            // `should_persist_code_unit` keeps file scopes out of storage and
            // only `FileState` hydration synthesizes them back, so the
            // persisted inventory is exactly the non-file-scope declaration
            // set that `all_declarations_with_primary_ranges` reports.
            debug_assert!(
                !row.unit.is_file_scope(),
                "persisted declaration rows must not carry a file scope: {:?}",
                row.unit
            );
            declarations.push(row.unit.clone());
        }
        by_key.insert(row.key, row);
    }
    // Storage order follows `unit_key`, which the writer assigns from a
    // rendering-oriented order. Publish the inventory in `CodeUnit` order so
    // every reader of this field sees one canonical enumeration.
    declarations.sort();

    let mut top_level: Vec<_> = by_key
        .values()
        .filter_map(|row| {
            row.top_level_ordinal
                .map(|ordinal| (ordinal, row.unit.clone()))
        })
        .collect();
    top_level.sort_by_key(|(ordinal, _)| *ordinal);

    let signatures = read_unit_string_vec(conn, &oid, lang, "unit_signatures", "text", &by_key)?;
    let ranges = read_ranges(conn, &oid, lang, &by_key)?;
    let children = read_children(conn, &oid, lang, &by_key)?;
    if count_vec_entries(&signatures) != meta.signature_count
        || count_vec_entries(&ranges) != meta.range_count
        || count_vec_entries(&children) != meta.child_count
    {
        return Ok(None);
    }

    let mut projection = SummaryFileProjection {
        top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
        declarations,
        signatures,
        ranges,
        children,
    };
    adapter.synthesize_summary_projection(
        file,
        source,
        meta.import_statement_count > 0,
        &mut projection,
    );
    Ok(Some(projection))
}

fn type_aliases_for_file_conn<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
) -> Result<Option<Vec<CodeUnit>>> {
    if read_summary_projection_meta(conn, &oid.to_string(), lang)?.is_none() {
        return Ok(None);
    }
    let unit_columns = raw_unit_columns_sql("units");
    let sql = format!(
        "SELECT {unit_columns}
         FROM blobs AS keys
         JOIN code_units AS units
           ON units.blob_id = keys.id
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         WHERE keys.blob_oid = ?1 AND keys.lang = ?2 AND units.is_type_alias = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY units.unit_key"
    );
    let oid = oid.to_string();
    let mut statement = conn.prepare_cached(&sql)?;
    let mapped = statement.query_map(params![oid, lang], |row| raw_unit_row_from_row(row, 0))?;
    let mut rows = mapped.collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);
    attach_raw_unit_fq_segments(conn, lang, std::slice::from_ref(&oid), &mut rows)?;
    let mut aliases = Vec::with_capacity(rows.len());
    for row in rows {
        let (fq_name, package_segment_count) =
            hydrate_unit_fq(adapter, row.fq.as_ref(), &row.content_qualifier, file)?;
        aliases.push(CodeUnit::from_fq(
            file.clone(),
            row.kind,
            fq_name,
            package_segment_count,
            row.signature,
            row.synthetic,
        ));
    }
    Ok(Some(aliases))
}

fn enclosing_declarations_for_file_conn<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
) -> Result<Option<Vec<(CodeUnit, Range)>>> {
    if read_summary_projection_meta(conn, &oid.to_string(), lang)?.is_none() {
        return Ok(None);
    }
    let sql = enclosing_declarations_for_file_sql();
    let oid = oid.to_string();
    let mut statement = conn.prepare_cached(&sql)?;
    let mut rows = statement.query(params![oid, lang])?;
    let mut raw_declarations = Vec::new();
    while let Some(row) = rows.next()? {
        let raw = raw_unit_row_from_row(row, 0)?;
        let range = Range {
            start_byte: i64_to_usize(row.get(18)?)?,
            end_byte: i64_to_usize(row.get(19)?)?,
            start_line: i64_to_usize(row.get(20)?)?,
            end_line: i64_to_usize(row.get(21)?)?,
        };
        raw_declarations.push((raw, range));
    }
    drop(rows);
    drop(statement);
    let mut raw_units_by_key = HashMap::default();
    for (raw, _) in &raw_declarations {
        raw_units_by_key
            .entry(raw.key)
            .or_insert_with(|| raw.clone());
    }
    let mut unique_raw_units = raw_units_by_key.into_values().collect::<Vec<_>>();
    attach_raw_unit_fq_segments(
        conn,
        lang,
        std::slice::from_ref(&oid),
        &mut unique_raw_units,
    )?;
    let raw_units_by_key = unique_raw_units
        .into_iter()
        .map(|raw| (raw.key, raw))
        .collect::<HashMap<_, _>>();
    let mut declarations = Vec::with_capacity(raw_declarations.len());
    for (raw, range) in raw_declarations {
        let raw = raw_units_by_key
            .get(&raw.key)
            .expect("every declaration range has a unit row");
        let (fq_name, package_segment_count) =
            hydrate_unit_fq(adapter, raw.fq.as_ref(), &raw.content_qualifier, file)?;
        declarations.push((
            CodeUnit::from_fq(
                file.clone(),
                raw.kind,
                fq_name,
                package_segment_count,
                raw.signature.clone(),
                raw.synthetic,
            ),
            range,
        ));
    }
    Ok(Some(declarations))
}

fn enclosing_declarations_for_file_sql() -> String {
    let unit_columns = raw_unit_columns_sql("units");
    format!(
        "SELECT {unit_columns},
                ranges.start_byte, ranges.end_byte, ranges.start_line, ranges.end_line
         FROM blobs AS keys
         CROSS JOIN code_units AS units
         CROSS JOIN blob_meta AS meta
         CROSS JOIN unit_ranges AS ranges
         WHERE units.blob_id = keys.id
           AND units.blob_id = meta.blob_id
           AND ranges.blob_id = units.blob_id
           AND ranges.unit_key = units.unit_key
           AND keys.blob_oid = ?1 AND keys.lang = ?2 AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY units.unit_key, ranges.ordinal"
    )
}

fn hydrate_file_states_conn<A: StoreLanguageAdapter>(
    conn: &Connection,
    entries: &[(ProjectFile, Oid)],
    lang: &str,
    adapter: &A,
    source_by_file: &HashMap<ProjectFile, String>,
) -> Result<HashMap<ProjectFile, FileState>> {
    if entries.is_empty() {
        return Ok(HashMap::default());
    }

    let oids = unique_oid_strings(entries);
    let meta_by_oid = read_blob_meta_bulk(conn, lang, &oids)?;
    let unit_rows_by_oid = read_unit_rows_bulk(conn, lang, &oids)?;
    let children_by_oid = read_children_bulk(conn, lang, &oids)?;
    let supertypes_by_oid = read_unit_string_vec_bulk(conn, lang, "unit_supertypes", "raw", &oids)?;
    let supertype_lookup_paths_by_oid =
        read_unit_string_vec_bulk(conn, lang, "unit_supertypes", "lookup_path", &oids)?;
    let signatures_by_oid =
        read_unit_string_vec_bulk(conn, lang, "unit_signatures", "text", &oids)?;
    let signature_metadata_by_oid = read_signature_metadata_bulk(conn, lang, &oids)?;
    let signature_metadata_signature_ordinals_by_oid =
        read_signature_metadata_signature_ordinals_bulk(conn, lang, &oids)?;
    let ranges_by_oid = read_ranges_bulk(conn, lang, &oids)?;
    let ruby_dispatch_by_oid = read_ruby_method_dispatch_modes_bulk(conn, lang, &oids)?;
    let scala_traits_by_oid = read_scala_traits_bulk(conn, lang, &oids)?;
    let import_infos_by_oid = read_import_infos_bulk(conn, lang, &oids)?;
    let scala_exports_by_oid = read_scala_exports_bulk(conn, lang, &oids)?;
    let materialization_records_by_oid = read_materialization_records_bulk(conn, lang, &oids)?;
    let cpp_templates_by_oid = cpp_template::read_bulk(conn, lang, &oids)?;

    let mut out = HashMap::default();
    for (file, oid) in entries {
        let oid_text = oid.to_string();
        let Some(meta) = meta_by_oid.get(&oid_text) else {
            continue;
        };
        let source = source_by_file.get(file).map(String::as_str);
        let source_text = source.unwrap_or("");
        let raw_units = unit_rows_by_oid.get(&oid_text).cloned().unwrap_or_default();
        if raw_units.len() != meta.stored_unit_count {
            continue;
        }
        let mut by_key = HashMap::default();
        for raw in raw_units {
            let (fq, package_segment_count) =
                hydrate_unit_fq(adapter, raw.fq.as_ref(), &raw.content_qualifier, file)?;
            let unit = CodeUnit::from_fq(
                file.clone(),
                raw.kind,
                fq,
                package_segment_count,
                raw.signature,
                raw.synthetic,
            );
            by_key.insert(
                raw.key,
                UnitRow {
                    key: raw.key,
                    unit,
                    is_type_alias: raw.is_type_alias,
                    top_level_ordinal: raw.top_level_ordinal,
                    in_declarations: raw.in_declarations,
                    in_definition_lookup: raw.in_definition_lookup,
                    in_test_region: raw.in_test_region,
                },
            );
        }

        let mut top_level: Vec<_> = by_key
            .values()
            .filter_map(|row| {
                row.top_level_ordinal
                    .map(|ordinal| (ordinal, row.unit.clone()))
            })
            .collect();
        top_level.sort_by_key(|(ordinal, _)| *ordinal);

        let mut declarations = set_with_capacity(by_key.len());
        let mut definition_lookup_units = HashSet::default();
        let mut type_aliases = HashSet::default();
        let mut test_region_units = HashSet::default();
        for row in by_key.values() {
            if row.in_declarations {
                declarations.insert(row.unit.clone());
            }
            if row.in_definition_lookup {
                definition_lookup_units.insert(row.unit.clone());
            }
            if row.is_type_alias {
                type_aliases.insert(row.unit.clone());
            }
            if row.in_test_region {
                test_region_units.insert(row.unit.clone());
            }
        }

        let ruby_method_dispatch_modes =
            ruby_dispatch_map_for_file(ruby_dispatch_by_oid.get(&oid_text), &by_key)?;
        let scala_traits = scala_traits_for_file(scala_traits_by_oid.get(&oid_text), &by_key);
        let imports = import_infos_by_oid
            .get(&oid_text)
            .cloned()
            .unwrap_or_default();
        let scala_exports =
            scala_exports_map_for_file(scala_exports_by_oid.get(&oid_text), &by_key)?;
        let materialization_records = materialization_records_for_file(
            materialization_records_by_oid.get(&oid_text),
            &by_key,
        )?;
        let raw_supertypes = unit_values_map_for_file(supertypes_by_oid.get(&oid_text), &by_key);
        let supertype_lookup_paths =
            unit_values_map_for_file(supertype_lookup_paths_by_oid.get(&oid_text), &by_key);
        let signatures = unit_values_map_for_file(signatures_by_oid.get(&oid_text), &by_key);
        let signature_metadata =
            unit_values_map_for_file(signature_metadata_by_oid.get(&oid_text), &by_key);
        let signature_metadata_signature_ordinals =
            signature_metadata_signature_ordinals_map_for_file(
                signature_metadata_signature_ordinals_by_oid.get(&oid_text),
                &by_key,
                &signatures,
                &signature_metadata,
            )?;
        let ranges = ranges_map_for_file(ranges_by_oid.get(&oid_text), &by_key)?;
        let cpp_template_metadata =
            cpp_template::map_for_file(cpp_templates_by_oid.get(&oid_text), &by_key)?;
        let children = children_map_for_file(children_by_oid.get(&oid_text), &by_key);

        let actual_counts = side_table_counts_from_hydrated_parts(HydratedSideTableParts {
            cpp_class_template_count: cpp_template_metadata.len(),
            ranges: &ranges,
            signatures: &signatures,
            signature_metadata: &signature_metadata,
            signature_metadata_signature_ordinals: &signature_metadata_signature_ordinals,
            raw_supertypes: &raw_supertypes,
            children: &children,
            import_statement_count: imports.len(),
            type_identifier_count: meta.type_identifiers.len(),
            ruby_dispatch_count: ruby_method_dispatch_modes.len(),
            scala_trait_count: scala_traits.len(),
            scala_export_count: scala_exports.values().map(Vec::len).sum(),
            materialization_record_count: materialization_records.len(),
        });
        if actual_counts != meta.side_counts {
            continue;
        }

        let mut state = FileState {
            source: source.unwrap_or("").to_string(),
            package_name: adapter.hydrate_content_qualifier(&meta.content_package, file)?,
            content_qualifier: meta.content_package.clone(),
            top_level_declarations: top_level.into_iter().map(|(_, unit)| unit).collect(),
            declarations,
            definition_lookup_units,
            imports,
            scala_exports,
            rust_usage_facts: Default::default(),
            resolution_facts: Default::default(),
            source_facts: None,
            source_declaration_units: Vec::new(),
            source_declaration_metadata: Vec::new(),
            raw_supertypes,
            supertype_lookup_paths,
            type_identifiers: meta.type_identifiers.clone(),
            signatures,
            signature_metadata,
            signature_metadata_signature_ordinals,
            cpp_template_metadata,
            ranges,
            children,
            type_aliases,
            ruby_method_dispatch_modes,
            scala_traits,
            contains_tests: adapter.hydrate_contains_tests(meta.contains_tests, file, source_text),
            test_region_units,
            materialization_records,
            completeness: meta.completeness,
            parse_errors: None,
            parse_complete: true,
            additional_projections: Vec::new(),
        };

        if let Some(source) = source {
            adapter.synthesize_hydrated_units(file, source, &mut state)?;
            synthesize_file_scope(file, source, &mut state);
        }
        out.insert(file.clone(), state);
    }

    Ok(out)
}

/// `read_blob_meta`'s statement: one text for every call, so one cached
/// statement per connection rather than one fresh preparation per hydration.
static BLOB_META_SQL: LazyLock<String> = LazyLock::new(|| {
    let optional_fact_projection = OPTIONAL_FACT_COUNT_PROJECTION.as_str();
    format!(
        "SELECT contains_tests, content_package, stored_unit_count, parse_completeness,
            range_count, signature_count, signature_metadata_count, supertype_count,
            child_count, import_statement_count, type_identifier_count,
            {optional_fact_projection}
     FROM blob_meta AS meta
     LEFT JOIN blob_optional_fact_manifest AS manifest
       ON manifest.blob_id = meta.blob_id
     WHERE meta.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
       AND {PARSED_BLOB_COMPLETE_CONDITION}
     GROUP BY meta.blob_id"
    )
});

#[doc(hidden)]
pub fn read_blob_meta<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> Result<Option<BlobMetaRow>> {
    let row: Option<(i64, String, i64, String, RawSideTableCounts)> = conn
        .prepare_cached(&BLOB_META_SQL)?
        .query_row(params![oid, lang], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                raw_side_table_counts_from_row(row, 4)?,
            ))
        })
        .optional()?;
    let Some((contains_tests, content_package, stored_unit_count, completeness, raw_side_counts)) =
        row
    else {
        return Ok(None);
    };
    let type_identifiers = read_type_identifiers(conn, oid, lang)?;
    let side_counts = side_table_counts_from_raw(raw_side_counts)?;
    Ok(Some(BlobMetaRow {
        contains_tests: adapter.hydrate_contains_tests(contains_tests != 0, file, source),
        content_package: adapter.hydrate_content_qualifier(&content_package, file)?,
        raw_content_package: content_package,
        type_identifiers,
        stored_unit_count: i64_to_usize(stored_unit_count)?,
        completeness: crate::analyzer::ParseCompleteness::from_label(&completeness),
        side_counts,
    }))
}

fn read_summary_projection_meta(
    conn: &Connection,
    oid: &str,
    lang: &str,
) -> Result<Option<SummaryProjectionMeta>> {
    let sql = format!(
        "SELECT stored_unit_count, range_count, signature_count, child_count,
                import_statement_count
         FROM blob_meta AS meta
         WHERE meta.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
           AND {PARSED_BLOB_COMPLETE_CONDITION}"
    );
    let row: Option<(i64, i64, i64, i64, i64)> = conn
        .query_row(&sql, params![oid, lang], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .optional()?;
    row.map(
        |(stored_unit_count, range_count, signature_count, child_count, import_statement_count)| {
            Ok(SummaryProjectionMeta {
                stored_unit_count: i64_to_usize(stored_unit_count)?,
                range_count: i64_to_usize(range_count)?,
                signature_count: i64_to_usize(signature_count)?,
                child_count: i64_to_usize(child_count)?,
                import_statement_count: i64_to_usize(import_statement_count)?,
            })
        },
    )
    .transpose()
}

fn read_type_identifiers(conn: &Connection, oid: &str, lang: &str) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT identifier FROM reference_identifiers
         WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| row.get::<_, String>(0))?;
    let mut out = HashSet::default();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

fn raw_side_table_counts_from_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<RawSideTableCounts> {
    Ok(RawSideTableCounts {
        range_count: row.get(offset)?,
        signature_count: row.get(offset + 1)?,
        signature_metadata_count: row.get(offset + 2)?,
        supertype_count: row.get(offset + 3)?,
        child_count: row.get(offset + 4)?,
        import_statement_count: row.get(offset + 5)?,
        type_identifier_count: row.get(offset + 6)?,
        optional: [
            row.get(offset + 7)?,
            row.get(offset + 8)?,
            row.get(offset + 9)?,
            row.get(offset + 10)?,
            row.get(offset + 11)?,
            row.get(offset + 12)?,
        ],
        unknown_optional_count: row.get(offset + 13)?,
    })
}

fn side_table_counts_from_raw(raw: RawSideTableCounts) -> Result<PersistedSideTableCounts> {
    if raw.unknown_optional_count != 0 {
        return Err(StoreError::new(format!(
            "manifest contains {} unknown optional analyzer fact kinds",
            raw.unknown_optional_count
        )));
    }
    let mut optional = OptionalFactCounts::default();
    for (descriptor, count) in OPTIONAL_FACT_DESCRIPTORS.into_iter().zip(raw.optional) {
        optional.set(descriptor.kind, i64_to_usize(count)?);
    }
    Ok(PersistedSideTableCounts {
        range_count: i64_to_usize(raw.range_count)?,
        signature_count: i64_to_usize(raw.signature_count)?,
        signature_metadata_count: i64_to_usize(raw.signature_metadata_count)?,
        supertype_count: i64_to_usize(raw.supertype_count)?,
        child_count: i64_to_usize(raw.child_count)?,
        import_statement_count: i64_to_usize(raw.import_statement_count)?,
        type_identifier_count: i64_to_usize(raw.type_identifier_count)?,
        optional,
    })
}

const RUST_FACT_OIDS_PER_QUERY: usize = 400;

fn unique_rust_fact_oid_strings(oids: &[Oid]) -> Vec<String> {
    let mut unique: Vec<String> = oids.iter().map(Oid::to_string).collect();
    unique.sort();
    unique.dedup();
    unique
}

#[doc(hidden)]
pub fn rust_fact_oid_query_parameters(
    lang: &str,
    generation: GenerationId,
    chunk: &[String],
) -> (String, Vec<rusqlite::types::Value>) {
    assert!(
        !chunk.is_empty(),
        "Rust fact query chunk must contain an OID"
    );
    let placeholders = std::iter::repeat_n("?", chunk.len())
        .collect::<Vec<_>>()
        .join(", ");
    let mut parameters = Vec::with_capacity(chunk.len() + 2);
    parameters.push(rusqlite::types::Value::Text(lang.to_owned()));
    parameters.push(rusqlite::types::Value::Integer(generation.get()));
    parameters.extend(chunk.iter().cloned().map(rusqlite::types::Value::Text));
    (placeholders, parameters)
}

fn unique_oid_strings(entries: &[(ProjectFile, Oid)]) -> Vec<String> {
    let mut seen = HashSet::default();
    let mut out = Vec::new();
    for (_, oid) in entries {
        let oid = oid.to_string();
        if seen.insert(oid.clone()) {
            out.push(oid);
        }
    }
    out
}

/// Fixed arities the variable-length `IN (…)` chunk queries are padded up to.
/// Every `chunks(900)` bulk reader lands on one of these four SQL shapes
/// instead of up to 900 distinct ones, so `prepare_cached` (64 slots) actually
/// caches them. `900` is the top because the callers chunk at 900.
const IN_CHUNK_ARITY_LADDER: [usize; 4] = [16, 64, 256, 900];

fn padded_arity(len: usize, ladder: &[usize]) -> usize {
    ladder
        .iter()
        .copied()
        .find(|&arity| arity >= len)
        .unwrap_or(*ladder.last().expect("arity ladder is nonempty"))
}

/// Parameters for a chunked `IN (…)` query, padded to the next fixed arity with
/// `NULL`s. `NULL` never matches `IN`, so the padding is semantics-preserving:
/// `x IN (a, b, NULL)` returns exactly what `x IN (a, b)` returns for the
/// non-null `blob_oid`s we query.
#[doc(hidden)]
pub fn chunk_params(lang: &str, chunk: &[String]) -> Vec<Option<String>> {
    let arity = padded_arity(chunk.len(), &IN_CHUNK_ARITY_LADDER);
    let mut params = Vec::with_capacity(arity + 1);
    params.push(Some(lang.to_string()));
    params.extend(chunk.iter().cloned().map(Some));
    params.resize(arity + 1, None);
    params
}

#[doc(hidden)]
pub fn chunk_placeholders(chunk: &[String]) -> String {
    let arity = padded_arity(chunk.len(), &IN_CHUNK_ARITY_LADDER);
    std::iter::repeat_n("?", arity)
        .collect::<Vec<_>>()
        .join(",")
}

fn read_grouped_bulk_rows<T>(
    conn: &Connection,
    lang: &str,
    oids: &[String],
    sql_for_placeholders: impl Fn(&str) -> String,
    mut row_from_sql: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<(String, T)>,
) -> Result<HashMap<String, Vec<T>>> {
    let mut out: HashMap<String, Vec<T>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = sql_for_placeholders(&placeholders);
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            row_from_sql(row)
        })?;
        for row in rows {
            let (oid, value) = row?;
            out.entry(oid).or_default().push(value);
        }
    }
    Ok(out)
}

fn read_blob_meta_bulk(conn: &Connection, lang: &str, oids: &[String]) -> Result<BlobMetaRows> {
    let mut out = HashMap::default();
    let optional_fact_projection = OPTIONAL_FACT_COUNT_PROJECTION.as_str();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT keys.blob_oid, contains_tests, content_package, stored_unit_count,
                    parse_completeness,
                    range_count, signature_count, signature_metadata_count, supertype_count,
                    child_count, import_statement_count, type_identifier_count,
                    {optional_fact_projection}
             FROM blobs AS keys
             JOIN blob_meta AS meta ON meta.blob_id = keys.id
             LEFT JOIN blob_optional_fact_manifest AS manifest
               ON manifest.blob_id = meta.blob_id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             GROUP BY meta.blob_id
             ORDER BY keys.blob_oid"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                raw_side_table_counts_from_row(row, 5)?,
            ))
        })?;
        for row in rows {
            let (
                oid,
                contains_tests,
                content_package,
                stored_unit_count,
                completeness,
                raw_side_counts,
            ) = row?;
            out.insert(
                oid,
                BlobMetaRow {
                    contains_tests: contains_tests != 0,
                    raw_content_package: content_package.clone(),
                    content_package,
                    type_identifiers: HashSet::default(),
                    stored_unit_count: i64_to_usize(stored_unit_count)?,
                    completeness: crate::analyzer::ParseCompleteness::from_label(&completeness),
                    side_counts: side_table_counts_from_raw(raw_side_counts)?,
                },
            );
        }
    }

    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT keys.blob_oid, facts.identifier
             FROM blobs AS keys
             JOIN reference_identifiers AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.identifier"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, identifier) = row?;
            if let Some(meta) = out.get_mut(&oid) {
                meta.type_identifiers.insert(identifier);
            }
        }
    }
    Ok(out)
}

fn read_import_metadata_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, (String, bool)>> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT keys.blob_oid, meta.content_package, meta.contains_tests
             FROM blobs AS keys
             JOIN blob_meta AS meta ON meta.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY keys.blob_oid"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
            ))
        })?;
        for row in rows {
            let (oid, package_name, contains_tests) = row?;
            out.insert(oid, (package_name, contains_tests));
        }
    }
    Ok(out)
}

fn read_canonical_import_metadata_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, (String, bool)>> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT keys.blob_oid, meta.content_package, meta.contains_tests
             FROM blobs AS keys
             JOIN blob_meta AS meta ON meta.blob_id = keys.id
             JOIN source_fact_manifests AS source
               ON source.blob_id = meta.blob_id
              AND source.publication_state = 'complete'
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY keys.blob_oid"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
            ))
        })?;
        for row in rows {
            let (oid, package_name, contains_tests) = row?;
            out.insert(oid, (package_name, contains_tests));
        }
    }
    Ok(out)
}

fn read_unit_rows_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<RawUnitRow>>> {
    let mut out = read_grouped_bulk_rows(
        conn,
        lang,
        oids,
        |placeholders| {
            format!(
                "SELECT keys.blob_oid, {RAW_UNIT_COLUMNS}
             FROM blobs AS keys
             JOIN code_units AS units ON units.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, units.unit_key"
            )
        },
        |row| {
            let raw = raw_unit_row_from_row(row, 0)?;
            Ok((raw.blob_oid.to_string(), raw))
        },
    )?;
    let mut all_rows = out
        .values_mut()
        .flat_map(|rows| rows.drain(..))
        .collect::<Vec<_>>();
    attach_raw_unit_fq_segments(conn, lang, oids, &mut all_rows)?;
    for row in all_rows {
        out.entry(row.blob_oid.to_string()).or_default().push(row);
    }
    Ok(out)
}

/// The `source_import_statements` columns every hydration path selects, in the order
/// `import_info_from_statement_row` reads them.
const IMPORT_STATEMENT_COLUMNS: &str = "statement, is_wildcard, is_global, identifier, alias, \
     path_kind, declaration_start_byte, binder_start, binder_end, \
     declaration_occurrence_id, binder_occurrence_id, has_structured_path";

/// Rebuild the scalar half of an `ImportInfo` from the shared import view.
///
/// Path availability is independent of the declaration source identity. The path
/// is created empty here and
/// `attach_import_path_children` fills its three lists.
fn import_info_from_statement_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<ImportInfo> {
    let path_kind = row.get::<_, Option<String>>(offset + 5)?;
    let declaration_start_byte = row.get::<_, Option<i64>>(offset + 6)?;
    let binder_start = row.get::<_, Option<i64>>(offset + 7)?;
    let binder_end = row.get::<_, Option<i64>>(offset + 8)?;
    let declaration_occurrence = row.get::<_, Option<i64>>(offset + 9)?;
    let binder_occurrence = row.get::<_, Option<i64>>(offset + 10)?;
    let has_path = row.get::<_, i64>(offset + 11)?;
    if !matches!(has_path, 0 | 1)
        || (has_path == 1 && declaration_start_byte.is_none())
        || (has_path == 0 && path_kind.is_some())
    {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            offset + 11,
            rusqlite::types::Type::Integer,
            Box::new(StoreError::new(format!(
                "invalid import path availability: flag={has_path}, declaration_start={declaration_start_byte:?}, kind={path_kind:?}"
            ))),
        ));
    }
    if (declaration_occurrence.is_some() && declaration_start_byte.is_none())
        || (binder_occurrence.is_some() && (binder_start.is_none() || binder_end.is_none()))
    {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            offset + 9,
            rusqlite::types::Type::Integer,
            Box::new(StoreError::new(format!(
                "canonical import source occurrences are unavailable: declaration={declaration_occurrence:?}, binder={binder_occurrence:?}"
            ))),
        ));
    }
    let to_usize = |column: usize, value: i64| {
        i64_to_usize(value).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Integer,
                Box::new(err),
            )
        })
    };
    let path = declaration_start_byte
        .filter(|_| has_path == 1)
        .map(|start| {
            let kind = match path_kind.as_deref() {
                Some(tag) => Some(StructuredImportPathKind::from_persist_tag(tag).ok_or_else(
                    || {
                        rusqlite::Error::FromSqlConversionFailure(
                            offset + 5,
                            rusqlite::types::Type::Text,
                            Box::new(StoreError::new(format!("unknown import path kind `{tag}`"))),
                        )
                    },
                )?),
                None => None,
            };
            Ok::<_, rusqlite::Error>(StructuredImportPath {
                segments: Vec::new(),
                kind,
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: to_usize(offset + 6, start)?,
            })
        })
        .transpose()?;
    let binder_span = match (binder_start, binder_end) {
        (Some(start), Some(end)) => Some(crate::analyzer::structural::facts::Span {
            start_byte: to_usize(offset + 7, start)?,
            end_byte: to_usize(offset + 8, end)?,
        }),
        _ => None,
    };
    Ok(ImportInfo {
        raw_snippet: row.get(offset)?,
        is_wildcard: row.get::<_, i64>(offset + 1)? != 0,
        is_global: row.get::<_, i64>(offset + 2)? != 0,
        identifier: row.get(offset + 3)?,
        alias: row.get(offset + 4)?,
        path,
        binder_span,
    })
}

#[doc(hidden)]
pub fn import_path_children_sql(
    table: &str,
    value_columns: &str,
    child_ordinal: &str,
    placeholders: &str,
) -> String {
    // SQLite can flatten the canonical/legacy UNION ALL views only when
    // every ORDER BY term is also projected (flattenSubquery restriction 18).
    // Keep the child ordinal in the result even though the DTO uses row order.
    format!(
        "SELECT keys.blob_oid, facts.ordinal, {value_columns}, facts.{child_ordinal}
         FROM blobs AS keys
         JOIN {table} AS facts ON facts.blob_id = keys.id
         WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
         ORDER BY keys.blob_oid, facts.ordinal, facts.{child_ordinal}"
    )
}

/// Fill the three child lists of every already-hydrated import in `by_oid`.
///
/// `ordinal` is dense from zero within a blob because the writer enumerates
/// `FileState::imports`, so it indexes the per-blob vector directly. A child
/// row whose blob is absent belongs to a blob the caller's parent query
/// excluded, and one whose ordinal is out of range cannot exist while the
/// foreign key to `import_statements` holds; both are skipped rather than
/// guessed at.
fn attach_import_path_children(
    conn: &Connection,
    lang: &str,
    oids: &[String],
    by_oid: &mut HashMap<String, Vec<ImportInfo>>,
    session: Option<&ResolutionSession>,
) -> Result<bool> {
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let params = chunk_params(lang, chunk);

        for (table, value_columns, child_ordinal) in [
            ("source_import_path_segments", "segment", "seg_ordinal"),
            ("source_import_lexical_prefixes", "prefix", "prefix_ordinal"),
            (
                "source_import_lexical_scopes",
                "start_byte, end_byte",
                "scope_ordinal",
            ),
        ] {
            let sql = import_path_children_sql(table, value_columns, child_ordinal, &placeholders);
            let mut stmt = conn.prepare_cached(&sql)?;
            let mut query = stmt.query(rusqlite::params_from_iter(params.iter()))?;
            while let Some(row) = query.next()? {
                if session.is_some_and(|session| !session.scope_step()) {
                    return Ok(false);
                }
                let oid = row.get::<_, String>(0)?;
                let ordinal = i64_to_usize(row.get::<_, i64>(1)?)?;
                let Some(import) = by_oid
                    .get_mut(&oid)
                    .and_then(|imports| imports.get_mut(ordinal))
                else {
                    continue;
                };
                let path = import.path.as_mut().ok_or_else(|| StoreError::new(format!(
                    "{table} child references unavailable import path: blob={oid:?}, ordinal={ordinal}"
                )))?;
                match table {
                    "source_import_path_segments" => path.segments.push(row.get(2)?),
                    "source_import_lexical_prefixes" => path.lexical_prefixes.push(row.get(2)?),
                    _ => path.lexical_scopes.push(StructuredImportScope {
                        start_byte: i64_to_usize(row.get::<_, i64>(2)?)?,
                        end_byte: i64_to_usize(row.get::<_, i64>(3)?)?,
                    }),
                }
            }
        }
    }
    Ok(true)
}

#[doc(hidden)]
pub fn read_import_infos_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<ImportInfo>>> {
    require_unbounded_hydration(
        read_import_infos_bulk_with_session(conn, lang, oids, None)?,
        "unbounded import-info hydration stopped unexpectedly",
    )
}

#[doc(hidden)]
pub fn import_infos_bulk_sql(placeholders: &str) -> String {
    format!(
        "SELECT keys.blob_oid, imports.statement, imports.is_wildcard,
                imports.is_global, imports.identifier, imports.alias,
                imports.path_kind, imports.declaration_start_byte,
                imports.binder_start, imports.binder_end,
                imports.declaration_occurrence_id, imports.binder_occurrence_id,
                imports.has_structured_path
         FROM blobs AS keys
         JOIN source_import_statements AS imports ON imports.blob_id = keys.id
         JOIN blob_meta AS meta ON meta.blob_id = imports.blob_id
         WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY keys.blob_oid, imports.ordinal"
    )
}

fn read_import_infos_bulk_with_session(
    conn: &Connection,
    lang: &str,
    oids: &[String],
    session: Option<&ResolutionSession>,
) -> Result<Option<HashMap<String, Vec<ImportInfo>>>> {
    let mut out: HashMap<String, Vec<ImportInfo>> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = import_infos_bulk_sql(&placeholders);
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
        while let Some(row) = rows.next()? {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(None);
            }
            let oid = row.get::<_, String>(0)?;
            let import = import_info_from_statement_row(row, 1)?;
            out.entry(oid).or_default().push(import);
        }
    }
    if !attach_import_path_children(conn, lang, oids, &mut out, session)? {
        return Ok(None);
    }
    Ok(Some(out))
}

fn read_scala_exports_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<ScalaExportRows> {
    read_grouped_bulk_rows(
        conn,
        lang,
        oids,
        |placeholders| {
            format!(
                "SELECT keys.blob_oid, facts.owner_key, facts.info
                 FROM blobs AS keys
                 JOIN scala_exports AS facts ON facts.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.owner_key, facts.ordinal"
            )
        },
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?),
            ))
        },
    )
}

fn read_materialization_records_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<MaterializationRecordRows> {
    read_grouped_bulk_rows(
        conn,
        lang,
        oids,
        |placeholders| {
            format!(
                "SELECT keys.blob_oid, facts.unit_key, facts.payload
                 FROM blobs AS keys
                 JOIN materialization_records AS facts ON facts.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.ordinal"
            )
        },
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, Option<i64>>(1)?, row.get::<_, Vec<u8>>(2)?),
            ))
        },
    )
}

fn materialization_records_for_file(
    rows: Option<&Vec<(Option<i64>, Vec<u8>)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<Vec<MaterializationRecord>> {
    let mut out = Vec::new();
    for (unit_key, payload) in rows.into_iter().flatten() {
        let payload: MaterializationRecordPayload = deserialize_blob(payload)?;
        let unit = unit_key
            .and_then(|key| by_key.get(&key))
            .map(|row| row.unit.clone());
        if let Some(record) = MaterializationRecord::join(payload, unit) {
            out.push(record);
        }
    }
    Ok(out)
}

fn read_unit_string_vec_bulk(
    conn: &Connection,
    lang: &str,
    table: &str,
    value_column: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<(i64, String)>>> {
    read_grouped_bulk_rows(
        conn,
        lang,
        oids,
        |placeholders| {
            format!(
                "SELECT keys.blob_oid, facts.unit_key, facts.{value_column}
                 FROM blobs AS keys
                 JOIN {table} AS facts ON facts.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.unit_key, facts.ordinal"
            )
        },
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, i64>(1)?, row.get::<_, String>(2)?),
            ))
        },
    )
}

fn read_signature_metadata_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<SignatureMetadataRows> {
    let columns = signature_metadata_projection_columns_sql("metadata");
    read_grouped_bulk_rows(
        conn,
        lang,
        oids,
        |placeholders| {
            format!(
                "SELECT keys.blob_oid, metadata.unit_key, {columns}
                 FROM blobs AS keys
                 JOIN unit_signature_metadata_values AS metadata ON metadata.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, metadata.unit_key, metadata.ordinal"
            )
        },
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                (
                    row.get::<_, i64>(1)?,
                    signature_metadata_projection_from_row(row, 2)?,
                ),
            ))
        },
    )
}

fn read_signature_metadata_signature_ordinals_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<SignatureMetadataSignatureOrdinalRows> {
    let mut out: SignatureMetadataSignatureOrdinalRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT keys.blob_oid, pairs.unit_key,
                    pairs.metadata_ordinal, pairs.signature_ordinal
             FROM blobs AS keys
             JOIN unit_signature_metadata_signatures AS pairs
               ON pairs.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, pairs.unit_key, pairs.metadata_ordinal"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (oid, unit_key, metadata_ordinal, signature_ordinal) = row?;
            out.entry(oid)
                .or_default()
                .push((unit_key, metadata_ordinal, signature_ordinal));
        }
    }
    Ok(out)
}

/// The bulk range read, as one builder so the EXPLAIN QUERY PLAN pin cannot
/// drift from the statement the hydration path runs.
///
/// This is the shape every bulk fact reader uses: seek `blobs` once per
/// requested OID on `UNIQUE(blob_oid, lang)`, then range-scan the fact table on
/// the interned id. The unique index carries the rowid, and the rowid IS the
/// id, so the seek is covering and never reads the `blobs` table itself.
fn ranges_bulk_sql(placeholders: &str) -> String {
    format!(
        "SELECT keys.blob_oid, facts.unit_key, facts.start_byte, facts.end_byte,
                facts.start_line, facts.end_line
         FROM blobs AS keys
         JOIN unit_ranges AS facts ON facts.blob_id = keys.id
         WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
         ORDER BY keys.blob_oid, facts.unit_key, facts.ordinal"
    )
}

fn read_ranges_bulk(conn: &Connection, lang: &str, oids: &[String]) -> Result<RangeRows> {
    let mut out: RangeRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = ranges_bulk_sql(&placeholders);
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        for row in rows {
            let (oid, key, start_byte, end_byte, start_line, end_line) = row?;
            out.entry(oid)
                .or_default()
                .push((key, start_byte, end_byte, start_line, end_line));
        }
    }
    Ok(out)
}

fn read_children_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, Vec<(i64, i64)>>> {
    read_grouped_bulk_rows(
        conn,
        lang,
        oids,
        |placeholders| {
            format!(
                "SELECT keys.blob_oid, facts.parent_key, facts.child_key
                 FROM blobs AS keys
                 JOIN unit_children AS facts ON facts.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.parent_key, facts.ordinal"
            )
        },
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, i64>(1)?, row.get::<_, i64>(2)?),
            ))
        },
    )
}

fn read_ruby_method_dispatch_modes_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<RubyDispatchRows> {
    let mut out: RubyDispatchRows = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let sql = format!(
            "SELECT keys.blob_oid, facts.unit_key, facts.mode
             FROM blobs AS keys
             JOIN ruby_method_dispatch_modes AS facts ON facts.blob_id = keys.id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
             ORDER BY keys.blob_oid, facts.unit_key"
        );
        let params = chunk_params(lang, chunk);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (oid, key, mode) = row?;
            out.entry(oid).or_default().push((key, mode));
        }
    }
    Ok(out)
}

fn read_scala_traits_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<ScalaTraitRows> {
    read_grouped_bulk_rows(
        conn,
        lang,
        oids,
        |placeholders| {
            format!(
                "SELECT keys.blob_oid, facts.unit_key
                 FROM blobs AS keys
                 JOIN scala_traits AS facts ON facts.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.unit_key"
            )
        },
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )
}

fn unit_values_map_for_file<T: Clone>(
    rows: Option<&Vec<(i64, T)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashMap<CodeUnit, Vec<T>> {
    let mut out: HashMap<CodeUnit, Vec<T>> = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(value.clone());
        }
    }
    out
}

fn signature_metadata_signature_ordinals_map_for_file(
    rows: Option<&Vec<SignatureMetadataSignatureOrdinalRow>>,
    by_key: &HashMap<i64, UnitRow>,
    signatures: &HashMap<CodeUnit, Vec<String>>,
    signature_metadata: &HashMap<CodeUnit, Vec<SignatureMetadata>>,
) -> Result<HashMap<CodeUnit, Vec<usize>>> {
    let mut out: HashMap<CodeUnit, Vec<usize>> = HashMap::default();
    let rows = rows.map(Vec::as_slice).unwrap_or_default();
    for &(unit_key, metadata_ordinal, signature_ordinal) in rows {
        let unit = by_key.get(&unit_key).ok_or_else(|| {
            StoreError::new(format!(
                "signature metadata pair names unknown unit key {unit_key}"
            ))
        })?;
        let metadata = signature_metadata.get(&unit.unit).ok_or_else(|| {
            StoreError::new(format!(
                "signature metadata pair names unit {unit_key} without metadata"
            ))
        })?;
        let signatures = signatures.get(&unit.unit).ok_or_else(|| {
            StoreError::new(format!(
                "signature metadata pair names unit {unit_key} without signatures"
            ))
        })?;
        let metadata_ordinal = i64_to_usize(metadata_ordinal)?;
        let signature_ordinal = i64_to_usize(signature_ordinal)?;
        if metadata_ordinal != out.get(&unit.unit).map_or(0, Vec::len) {
            return Err(StoreError::new(format!(
                "signature metadata pair ordinals are not dense for unit {unit_key}: expected {}, got {metadata_ordinal}",
                out.get(&unit.unit).map_or(0, Vec::len)
            )));
        }
        if metadata_ordinal >= metadata.len() {
            return Err(StoreError::new(format!(
                "signature metadata pair ordinal {metadata_ordinal} exceeds {} metadata rows for unit {unit_key}",
                metadata.len()
            )));
        }
        if signature_ordinal >= signatures.len() {
            return Err(StoreError::new(format!(
                "signature metadata pair points to signature ordinal {signature_ordinal} beyond {} rows for unit {unit_key}",
                signatures.len()
            )));
        }
        out.entry(unit.unit.clone())
            .or_default()
            .push(signature_ordinal);
    }
    if !rows.is_empty() {
        for (unit, metadata) in signature_metadata {
            if metadata.is_empty() {
                continue;
            }
            let captured = out.get(unit).map_or(0, Vec::len);
            if captured != metadata.len() {
                return Err(StoreError::new(format!(
                    "signature metadata unit {unit:?} has {} rows but {captured} captured pairs",
                    metadata.len()
                )));
            }
        }
    }
    Ok(out)
}

fn scala_exports_map_for_file(
    rows: Option<&Vec<(i64, Vec<u8>)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<crate::analyzer::ScalaExportInfo>>> {
    let mut out = HashMap::default();
    for (key, value) in rows.into_iter().flatten() {
        if let Some(owner) = by_key.get(key) {
            out.entry(owner.unit.clone())
                .or_insert_with(Vec::new)
                .push(deserialize_blob(value)?);
        }
    }
    Ok(out)
}

fn ranges_map_for_file(
    rows: Option<&Vec<RangeRow>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<Range>>> {
    let mut out: HashMap<CodeUnit, Vec<Range>> = HashMap::default();
    for (key, start_byte, end_byte, start_line, end_line) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.entry(unit.unit.clone())
                .or_default()
                .push(range_from_coordinate_values(
                    *start_byte,
                    *end_byte,
                    *start_line,
                    *end_line,
                )?);
        }
    }
    Ok(out)
}

fn range_from_coordinate_values(
    start_byte: i64,
    end_byte: i64,
    start_line: i64,
    end_line: i64,
) -> Result<Range> {
    Ok(Range {
        start_byte: i64_to_usize(start_byte)?,
        end_byte: i64_to_usize(end_byte)?,
        start_line: i64_to_usize(start_line)?,
        end_line: i64_to_usize(end_line)?,
    })
}

fn children_map_for_file(
    rows: Option<&Vec<(i64, i64)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashMap<CodeUnit, Vec<CodeUnit>> {
    let mut out: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for (parent_key, child_key) in rows.into_iter().flatten() {
        let (Some(parent), Some(child)) = (by_key.get(parent_key), by_key.get(child_key)) else {
            continue;
        };
        out.entry(parent.unit.clone())
            .or_default()
            .push(child.unit.clone());
    }
    out
}

fn ruby_dispatch_map_for_file(
    rows: Option<&Vec<(i64, i64)>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, RubyMethodDispatchMode>> {
    let mut out = HashMap::default();
    for (key, raw_mode) in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.insert(unit.unit.clone(), ruby_dispatch_mode_from_i64(*raw_mode)?);
        }
    }
    Ok(out)
}

fn scala_traits_for_file(
    rows: Option<&Vec<i64>>,
    by_key: &HashMap<i64, UnitRow>,
) -> HashSet<CodeUnit> {
    let mut out = HashSet::default();
    for key in rows.into_iter().flatten() {
        if let Some(unit) = by_key.get(key) {
            out.insert(unit.unit.clone());
        }
    }
    out
}

struct HydratedSideTableParts<'a> {
    cpp_class_template_count: usize,
    ranges: &'a HashMap<CodeUnit, Vec<Range>>,
    signatures: &'a HashMap<CodeUnit, Vec<String>>,
    signature_metadata: &'a HashMap<CodeUnit, Vec<SignatureMetadata>>,
    signature_metadata_signature_ordinals: &'a HashMap<CodeUnit, Vec<usize>>,
    raw_supertypes: &'a HashMap<CodeUnit, Vec<String>>,
    children: &'a HashMap<CodeUnit, Vec<CodeUnit>>,
    import_statement_count: usize,
    type_identifier_count: usize,
    ruby_dispatch_count: usize,
    scala_trait_count: usize,
    scala_export_count: usize,
    materialization_record_count: usize,
}

fn side_table_counts_from_hydrated_parts(
    parts: HydratedSideTableParts<'_>,
) -> PersistedSideTableCounts {
    PersistedSideTableCounts {
        range_count: count_vec_entries(parts.ranges),
        signature_count: count_vec_entries(parts.signatures),
        signature_metadata_count: count_vec_entries(parts.signature_metadata),
        supertype_count: count_vec_entries(parts.raw_supertypes),
        child_count: count_vec_entries(parts.children),
        import_statement_count: parts.import_statement_count,
        type_identifier_count: parts.type_identifier_count,
        optional: optional_fact_counts(
            parts.cpp_class_template_count,
            parts.ruby_dispatch_count,
            parts.scala_trait_count,
            parts.scala_export_count,
            parts.materialization_record_count,
            count_vec_entries(parts.signature_metadata_signature_ordinals),
        ),
    }
}

fn count_vec_entries<T>(map: &HashMap<CodeUnit, Vec<T>>) -> usize {
    map.values().map(Vec::len).sum()
}

fn candidate_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CandidateRow> {
    candidate_row_from_row_at(row, 0)
}

fn fq_identity_header_from_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<Option<FqIdentityHeader>> {
    let anchor_kind = row.get::<_, Option<String>>(base)?;
    let anchor_pop = row.get::<_, Option<i64>>(base + 1)?;
    let package_tail_segments = row.get::<_, Option<i64>>(base + 2)?;
    let expected_segment_count = row.get::<_, i64>(base + 3)?;
    let exact_tail = row.get::<_, Option<String>>(base + 4)?;
    let expected_segment_bytes = row.get::<_, i64>(base + 5)?;
    let normalized_tail = row.get::<_, Option<String>>(base + 6)?;
    let invalid = |message: String| rusqlite_error_from_store(StoreError::new(message));

    if exact_tail.is_none() {
        if expected_segment_count != 0
            || anchor_kind.is_some()
            || anchor_pop.is_some()
            || package_tail_segments.is_some()
            || expected_segment_bytes != 0
            || normalized_tail.is_some()
        {
            return Err(invalid(
                "analyzer store empty FqName row has relational identity metadata".to_string(),
            ));
        }
        return Ok(None);
    }
    if expected_segment_count <= 0 {
        return Err(invalid(format!(
            "analyzer store non-empty FqName declares invalid segment count {expected_segment_count}"
        )));
    }
    let package_tail_segments = package_tail_segments
        .ok_or_else(|| invalid("analyzer store FqName is missing its package boundary".to_string()))
        .and_then(|value| i64_to_usize(value).map_err(rusqlite_error_from_store))?;
    let expected_segment_count =
        i64_to_usize(expected_segment_count).map_err(rusqlite_error_from_store)?;
    let expected_segment_bytes =
        i64_to_usize(expected_segment_bytes).map_err(rusqlite_error_from_store)?;
    let anchor = match (anchor_kind.as_deref(), anchor_pop) {
        (None, None) => None,
        (Some("own_module"), Some(pop @ 0..=255)) => Some(PackageAnchor::OwnModule {
            pop: u8::try_from(pop).expect("validated anchor pop fits u8"),
        }),
        (Some("crate_root"), Some(0)) => Some(PackageAnchor::CrateRoot),
        (kind, pop) => {
            return Err(invalid(format!(
                "analyzer store FqName has invalid anchor pair ({kind:?}, {pop:?})"
            )));
        }
    };
    Ok(Some(FqIdentityHeader {
        anchor,
        package_tail_segments,
        expected_segment_count,
        expected_segment_bytes,
        exact_tail: exact_tail.expect("non-empty identity has an exact tail"),
        normalized_tail,
    }))
}

pub(super) trait CandidateRowContainer: Sized {
    type Hydrated;

    fn candidate(&self) -> &CandidateRow;
    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated;
}

fn attach_complete_relational_fq(
    fq: &mut Option<RelationalUnitFq>,
    segments: Vec<(SegmentKind, String)>,
    key: &(Oid, String, i64),
) -> Result<()> {
    match fq.as_mut() {
        None => {
            if !segments.is_empty() {
                return Err(StoreError::new(format!(
                    "analyzer store empty FqName has persisted segment rows for {key:?}"
                )));
            }
        }
        Some(fq) => {
            if segments.len() != fq.expected_segment_count {
                return Err(StoreError::new(format!(
                    "analyzer store FqName expected {} segments but loaded {} for {key:?}",
                    fq.expected_segment_count,
                    segments.len()
                )));
            }
            if fq.package_tail_segments >= segments.len() {
                return Err(StoreError::new(format!(
                    "analyzer store FqName package boundary {} leaves no declaration tail for {key:?}",
                    fq.package_tail_segments
                )));
            }
            let loaded_bytes = segments
                .iter()
                .map(|(kind, segment)| segment_kind_sql(*kind).len() + segment.len())
                .sum::<usize>();
            if loaded_bytes != fq.expected_segment_bytes {
                return Err(StoreError::new(format!(
                    "analyzer store FqName expected {} segment bytes but loaded {loaded_bytes} for {key:?}",
                    fq.expected_segment_bytes
                )));
            }
            fq.segments = segments;
        }
    }
    Ok(())
}

fn candidate_with_hydrated_fq(
    row: CandidateRow,
    fq: Option<RelationalUnitFq>,
) -> HydratedCandidateRow {
    CandidateRow {
        blob_oid: row.blob_oid,
        lang: row.lang,
        unit_key: row.unit_key,
        kind: row.kind,
        short_name: row.short_name,
        content_qualifier: row.content_qualifier,
        signature: row.signature,
        flags: row.flags,
        fq,
    }
}

fn code_unit_from_hydrated_row(
    row: &HydratedCandidateRow,
    file: &ProjectFile,
    fq: FqName,
    package_segment_count: usize,
) -> CodeUnit {
    CodeUnit::from_fq(
        file.clone(),
        row.kind,
        fq,
        package_segment_count,
        row.signature.clone(),
        row.flags.synthetic,
    )
}

impl CandidateRowContainer for CandidateRow {
    type Hydrated = HydratedCandidateRow;

    fn candidate(&self) -> &CandidateRow {
        self
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        candidate_with_hydrated_fq(self, fq)
    }
}

impl CandidateRowContainer for MountedCandidateRow {
    type Hydrated = HydratedMountedCandidateRow;

    fn candidate(&self) -> &CandidateRow {
        &self.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        MountedCandidateRow {
            candidate: candidate_with_hydrated_fq(self.candidate, fq),
            rel_path: self.rel_path,
        }
    }
}

impl CandidateRowContainer for MountedCandidatePrimaryRangeRow {
    type Hydrated = HydratedMountedCandidatePrimaryRangeRow;

    fn candidate(&self) -> &CandidateRow {
        &self.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        MountedCandidatePrimaryRangeRow {
            candidate: candidate_with_hydrated_fq(self.candidate, fq),
            rel_path: self.rel_path,
            primary_range: self.primary_range,
        }
    }
}

impl CandidateRowContainer for DefinitionOrderCandidateRow {
    type Hydrated = HydratedDefinitionOrderCandidateRow;

    fn candidate(&self) -> &CandidateRow {
        &self.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        DefinitionOrderCandidateRow {
            candidate: candidate_with_hydrated_fq(self.candidate, fq),
            first_start_byte: self.first_start_byte,
            mounted_prefix: self.mounted_prefix,
        }
    }
}

impl CandidateRowContainer for CandidatePrimaryRangeRow {
    type Hydrated = HydratedCandidatePrimaryRangeRow;

    fn candidate(&self) -> &CandidateRow {
        &self.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        CandidatePrimaryRangeRow {
            candidate: candidate_with_hydrated_fq(self.candidate, fq),
            in_test_region: self.in_test_region,
            primary_range: self.primary_range,
        }
    }
}

impl CandidateRowContainer for SearchCandidateRow {
    type Hydrated = HydratedSearchCandidateRow;

    fn candidate(&self) -> &CandidateRow {
        &self.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        SearchCandidateRow {
            candidate: candidate_with_hydrated_fq(self.candidate, fq),
            primary_range: self.primary_range,
            has_multiple_ranges: self.has_multiple_ranges,
            secondary_range: self.secondary_range,
            has_more_ranges: self.has_more_ranges,
            all_ranges_are_definitions: self.all_ranges_are_definitions,
            in_test_region: self.in_test_region,
        }
    }
}

impl CandidateRowContainer for UsageFactRow {
    type Hydrated = HydratedUsageFactRow;

    fn candidate(&self) -> &CandidateRow {
        &self.candidate
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        UsageFactRow {
            candidate: candidate_with_hydrated_fq(self.candidate, fq),
            signature: self.signature,
            signature_metadata: self.signature_metadata,
        }
    }
}

impl<T> CandidateRowContainer for (CandidateRow, T) {
    type Hydrated = (HydratedCandidateRow, T);

    fn candidate(&self) -> &CandidateRow {
        &self.0
    }

    fn with_hydrated_fq(self, fq: Option<RelationalUnitFq>) -> Self::Hydrated {
        (candidate_with_hydrated_fq(self.0, fq), self.1)
    }
}

const CANDIDATE_KEY_ARITY_LADDER: [usize; 5] = [1, 16, 64, 256, 400];

/// `NOT INDEXED` is the whole point of this function's shape, and removing it
/// costs hours (issue #2794).
///
/// `code_unit_fq_segments` is `WITHOUT ROWID` on `(blob_id, unit_key,
/// seg_ordinal)` and carries no secondary index, so the join above is a
/// primary-key prefix seek and there is nothing else here for the planner to
/// choose. It chose something else anyway. From the 256-key rung of
/// the 256-key rung upward -- that is, on every full chunk --
/// SQLite 3.53 stops seeking the primary key and instead builds an AUTOMATIC
/// COVERING INDEX on `segments(unit_key)`, over the whole table, *per
/// execution*. On dotnet/runtime that is a transient index over 3,842,193 rows
/// rebuilt 2,007 times inside one `all_declarations` call, which is where
/// `file_usage_graph.prefetch_targets` spent most of its time even after the
/// wide exact-names view stopped scanning `code_units`: a `balance_nonroot` and
/// `defragmentPage` storm at 100% of one core, with flat RSS because each index
/// is built and dropped again.
///
/// `NOT INDEXED` forbids exactly that, and nothing else: the table has no index
/// to lose, and its `WITHOUT ROWID` primary key is the table itself, so the
/// seek survives. `hydration_chunks_seek_the_segment_primary_key` pins every
/// rung of the ladder. Note that older SQLite builds plan this correctly, so a
/// check against the system `sqlite3` will not reproduce the defect; the pin
/// runs through the bundled engine the product ships.
fn candidate_fq_segments_sql(padded_arity: usize) -> String {
    let values = std::iter::repeat_n("(?, ?, ?, ?)", padded_arity)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH requested(request_ordinal, blob_oid, lang, unit_key) AS (VALUES {values})
         SELECT requested.request_ordinal, segments.seg_ordinal,
                segments.seg_kind, segments.segment
         FROM requested
         JOIN blobs AS keys
           ON keys.blob_oid = requested.blob_oid AND keys.lang = requested.lang
         JOIN code_unit_fq_segments AS segments NOT INDEXED
           ON segments.blob_id = keys.id
          AND segments.unit_key = requested.unit_key"
    )
}

/// Load complete ordered relational identities for a candidate batch.
///
/// The function does not mutate candidates until every requested segment has
/// been read and validated, so cancellation or corruption cannot expose a
/// partly hydrated identity. A point request is this same path with arity one.
pub(super) fn hydrate_candidate_rows<T: CandidateRowContainer>(
    conn: &Connection,
    rows: Vec<T>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<Vec<T::Hydrated>>> {
    let mut unique_keys = Vec::with_capacity(rows.len());
    let mut key_indices = HashMap::default();
    let mut remaining_uses = Vec::new();
    for row in &rows {
        let candidate = row.candidate();
        let key = (
            candidate.blob_oid,
            candidate.lang.clone(),
            candidate.unit_key,
        );
        if let Some(index) = key_indices.get(&key).copied() {
            remaining_uses[index] += 1;
        } else {
            let index = unique_keys.len();
            key_indices.insert(key.clone(), index);
            unique_keys.push(key);
            remaining_uses.push(1usize);
        }
    }

    let mut loaded: Vec<Vec<(usize, SegmentKind, String)>> =
        (0..unique_keys.len()).map(|_| Vec::new()).collect();
    let mut inspected_segments = 0usize;
    for (chunk_index, chunk) in unique_keys.chunks(400).enumerate() {
        let chunk_start = chunk_index * 400;
        let padded = padded_arity(chunk.len(), &CANDIDATE_KEY_ARITY_LADDER);
        let sql = candidate_fq_segments_sql(padded);
        let mut parameters = Vec::with_capacity(padded * 4);
        for (offset, (oid, lang, unit_key)) in chunk.iter().enumerate() {
            parameters.push(rusqlite::types::Value::Integer(
                i64::try_from(offset).expect("candidate chunk ordinal fits i64"),
            ));
            parameters.push(rusqlite::types::Value::Text(oid.to_string()));
            parameters.push(rusqlite::types::Value::Text(lang.clone()));
            parameters.push(rusqlite::types::Value::Integer(*unit_key));
        }
        parameters.resize(padded * 4, rusqlite::types::Value::Null);
        let mut statement = conn.prepare_cached(&sql)?;
        let mut query = statement.query(params_from_iter(parameters.iter()))?;
        while let Some(row) = query.next()? {
            inspected_segments = inspected_segments.saturating_add(1);
            if inspected_segments.is_multiple_of(CANDIDATE_ROWS_PER_CANCELLATION_POLL)
                && cancellation.is_some_and(CancellationToken::is_cancelled)
            {
                return Ok(None);
            }
            let request_ordinal = i64_to_usize(row.get::<_, i64>(0)?)?;
            let loaded_index = chunk_start + request_ordinal;
            let segments = loaded.get_mut(loaded_index).ok_or_else(|| {
                StoreError::new(format!(
                    "analyzer store returned invalid FqName request ordinal {request_ordinal} for chunk of {}",
                    chunk.len()
                ))
            })?;
            let ordinal = i64_to_usize(row.get::<_, i64>(1)?)?;
            let kind_text = row.get::<_, String>(2)?;
            let segment = row.get::<_, String>(3)?;
            segments.push((ordinal, segment_kind_from_sql(&kind_text)?, segment));
        }
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Ok(None);
    }

    let mut loaded: Vec<Vec<(SegmentKind, String)>> = loaded
        .into_iter()
        .enumerate()
        .map(|(index, mut segments)| {
            segments.sort_unstable_by_key(|(ordinal, _, _)| *ordinal);
            for (expected, (ordinal, _, _)) in segments.iter().enumerate() {
                if *ordinal != expected {
                    return Err(StoreError::new(format!(
                        "analyzer store FqName segments are not dense: expected ordinal {expected}, got {ordinal} for {:?}",
                        unique_keys[index]
                    )));
                }
            }
            Ok(segments
                .into_iter()
                .map(|(_, kind, segment)| (kind, segment))
                .collect())
        })
        .collect::<Result<_>>()?;

    let mut hydrated = Vec::with_capacity(rows.len());
    for row in rows {
        let candidate = row.candidate();
        let key = (
            candidate.blob_oid,
            candidate.lang.clone(),
            candidate.unit_key,
        );
        let index = *key_indices
            .get(&key)
            .expect("every candidate key was indexed before segment loading");
        remaining_uses[index] -= 1;
        let segments = if remaining_uses[index] == 0 {
            std::mem::take(&mut loaded[index])
        } else {
            loaded[index].clone()
        };
        let mut fq = candidate.fq.clone().map(RelationalUnitFq::from_header);
        attach_complete_relational_fq(&mut fq, segments, &key)?;
        hydrated.push(row.with_hydrated_fq(fq));
    }
    Ok(Some(hydrated))
}

fn candidate_row_from_row_at(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<CandidateRow> {
    let oid_text = row.get::<_, String>(base)?;
    let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(base, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let kind_raw = row.get::<_, i64>(base + 3)?;
    let kind = code_unit_kind_from_i64(kind_raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            base + 3,
            rusqlite::types::Type::Integer,
            Box::new(err),
        )
    })?;
    Ok(CandidateRow {
        blob_oid,
        lang: row.get(base + 1)?,
        unit_key: row.get(base + 2)?,
        kind,
        short_name: row.get(base + 4)?,
        content_qualifier: row.get(base + 5)?,
        signature: row.get(base + 6)?,
        flags: CandidateFlags {
            synthetic: row.get::<_, i64>(base + 7)? != 0,
            is_type_alias: row.get::<_, i64>(base + 8)? != 0,
            is_top_level: row.get::<_, Option<i64>>(base + 9)?.is_some(),
            in_declarations: row.get::<_, i64>(base + 10)? != 0,
            in_definition_lookup: row.get::<_, i64>(base + 11)? != 0,
        },
        // Every candidate projection selects the seven-column relational FQ
        // header at 12..=18; any per-query columns follow at 19+.
        fq: fq_identity_header_from_row(row, base + 12)?,
    })
}

#[cfg(any(test, feature = "test-support"))]
fn definition_order_candidate_row_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<DefinitionOrderCandidateRow> {
    // The relational FQ header occupies 12..=18.
    let first_start_byte = row
        .get::<_, Option<i64>>(19)?
        .map(i64_to_usize)
        .transpose()
        .map_err(rusqlite_error_from_store)?;
    Ok(DefinitionOrderCandidateRow {
        candidate: candidate_row_from_row(row)?,
        first_start_byte,
        mounted_prefix: row.get(20)?,
    })
}

fn candidate_primary_range_row_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CandidatePrimaryRangeRow> {
    let (primary_range, in_test_region) = candidate_range_and_test_region_from_row(row)?;
    Ok(CandidatePrimaryRangeRow {
        candidate: candidate_row_from_row(row)?,
        in_test_region,
        primary_range,
    })
}

fn candidate_range_and_test_region_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(Option<Range>, bool)> {
    // The relational FQ header occupies 12..=18; test-region evidence is 19
    // and the primary range follows at 20..=23.
    Ok((
        primary_range_from_row(row, 20)?,
        row.get::<_, i64>(19)? != 0,
    ))
}

fn primary_range_from_row(row: &rusqlite::Row<'_>, base: usize) -> rusqlite::Result<Option<Range>> {
    match (
        row.get::<_, Option<i64>>(base)?,
        row.get::<_, Option<i64>>(base + 1)?,
        row.get::<_, Option<i64>>(base + 2)?,
        row.get::<_, Option<i64>>(base + 3)?,
    ) {
        (Some(start_byte), Some(end_byte), Some(start_line), Some(end_line)) => Ok(Some(Range {
            start_byte: i64_to_usize(start_byte).map_err(rusqlite_error_from_store)?,
            end_byte: i64_to_usize(end_byte).map_err(rusqlite_error_from_store)?,
            start_line: i64_to_usize(start_line).map_err(rusqlite_error_from_store)?,
            end_line: i64_to_usize(end_line).map_err(rusqlite_error_from_store)?,
        })),
        _ => Ok(None),
    }
}

fn mounted_candidate_primary_range_row_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<MountedCandidatePrimaryRangeRow> {
    let primary_range = primary_range_from_row(row, 20)?;
    Ok(MountedCandidatePrimaryRangeRow {
        candidate: candidate_row_from_row(row)?,
        rel_path: row.get(19)?,
        primary_range,
    })
}

fn usage_fact_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsageFactRow> {
    // The relational FQ header occupies 12..=18, the unit's first signature
    // text is 19, and signature-metadata columns start at 20. `label` is NOT
    // NULL in the table, so a NULL there is the join missing, not a row with
    // no label. New blobs join the first metadata ordinal paired to signature
    // ordinal zero; legacy blobs retain the old metadata-ordinal-zero join.
    let metadata = row
        .get::<_, Option<String>>(20)?
        .is_some()
        .then(|| signature_metadata_projection_from_row(row, 20))
        .transpose()?;
    Ok(UsageFactRow {
        candidate: candidate_row_from_row(row)?,
        signature: row.get(19)?,
        signature_metadata: metadata,
    })
}

fn search_candidate_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SearchCandidateRow> {
    let candidate = candidate_row_from_row(row)?;
    // The second range is 24..=27,
    // column 28 says whether another range follows, and 29 proves complete
    // callable occurrence metadata with no prototypes.
    let (primary_range, in_test_region) = candidate_range_and_test_region_from_row(row)?;
    let secondary_range = primary_range_from_row(row, 24)?;
    Ok(SearchCandidateRow {
        candidate,
        primary_range,
        has_multiple_ranges: secondary_range.is_some(),
        secondary_range,
        has_more_ranges: row.get::<_, Option<i64>>(28)?.is_some(),
        all_ranges_are_definitions: row.get::<_, i64>(29)? != 0,
        in_test_region,
    })
}

fn collect_mapped_rows<T, F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<T>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// The full search-candidate projection, parameterized by its source and row
/// predicate so the by-key hydration and the whole-language enumeration share
/// their columns and completion predicate without sharing a join order.
fn search_candidate_projection_sql(prefix: &str, from: &str, predicate: &str) -> String {
    let candidate_projection = candidate_unit_projection_sql("units");
    format!(
        "{prefix}SELECT keys.blob_oid, {candidate_projection}, units.in_test_region,
                primary_range.start_byte, primary_range.end_byte,
                primary_range.start_line, primary_range.end_line,
                secondary_range.start_byte, secondary_range.end_byte,
                secondary_range.start_line, secondary_range.end_line,
                further_range.ordinal,
                CASE
                  WHEN units.kind = 1
                   AND (SELECT COUNT(*)
                        FROM unit_signature_metadata AS occurrence_metadata
                        WHERE occurrence_metadata.blob_id = units.blob_id
                          AND occurrence_metadata.unit_key = units.unit_key)
                       = (SELECT COUNT(*)
                          FROM unit_ranges AS occurrence_ranges
                          WHERE occurrence_ranges.blob_id = units.blob_id
                            AND occurrence_ranges.unit_key = units.unit_key)
                   AND NOT EXISTS (
                       SELECT 1
                       FROM unit_signature_metadata AS prototype_metadata
                       WHERE prototype_metadata.blob_id = units.blob_id
                         AND prototype_metadata.unit_key = units.unit_key
                         AND prototype_metadata.declaration_only = 1
                   )
                  THEN 1 ELSE 0
                END
         {from}
         WHERE {predicate} AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}"
    )
}

fn search_candidate_sql(predicate: &str) -> String {
    search_candidate_projection_sql(
        "",
        &format!(
            "{CODE_UNIT_CANDIDATE_FROM_CLAUSE}
         LEFT JOIN unit_ranges AS primary_range
           ON primary_range.blob_id = units.blob_id
          AND primary_range.unit_key = units.unit_key
          AND primary_range.ordinal = 0
         LEFT JOIN unit_ranges AS secondary_range
           ON secondary_range.blob_id = units.blob_id
          AND secondary_range.unit_key = units.unit_key
          AND secondary_range.ordinal = 1
         LEFT JOIN unit_ranges AS further_range
           ON further_range.blob_id = units.blob_id
          AND further_range.unit_key = units.unit_key
          AND further_range.ordinal = 2"
        ),
        predicate,
    )
}

/// Fixed arities for the tuple list used by key hydration. Padding with NULLs
/// keeps a small set of prepared SQL shapes; the inner joins discard padding.
#[doc(hidden)]
pub const SEARCH_CANDIDATE_KEY_BATCH_SIZE: usize = 400;
const SEARCH_CANDIDATE_KEY_ARITY_LADDER: [usize; 4] =
    [16, 64, 256, SEARCH_CANDIDATE_KEY_BATCH_SIZE];

/// The by-key path is driven by an exact `(lang, blob_oid, unit_key)` tuple
/// set. The requested CTE is the outer relation, so SQLite seeks each blob
/// through its unique OID/language index and each declaration through the
/// `(blob_id, unit_key)` primary key. This avoids both the language-wide index
/// scan and reading every declaration in a matched blob before filtering.
fn search_candidate_key_set_sql(padded_arity: usize) -> String {
    let values = std::iter::repeat_n("(?, ?, ?)", padded_arity)
        .collect::<Vec<_>>()
        .join(", ");
    search_candidate_projection_sql(
        &format!("WITH requested(lang, blob_oid, unit_key) AS (VALUES {values})\n"),
        "FROM requested
         JOIN blobs AS keys
           ON keys.blob_oid = requested.blob_oid
          AND keys.lang = requested.lang
         JOIN code_units AS units
           ON units.blob_id = keys.id
          AND units.lang = requested.lang
          AND units.unit_key = requested.unit_key
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         LEFT JOIN unit_ranges AS primary_range
           ON primary_range.blob_id = units.blob_id
          AND primary_range.unit_key = units.unit_key
          AND primary_range.ordinal = 0
         LEFT JOIN unit_ranges AS secondary_range
           ON secondary_range.blob_id = units.blob_id
          AND secondary_range.unit_key = units.unit_key
          AND secondary_range.ordinal = 1
         LEFT JOIN unit_ranges AS further_range
           ON further_range.blob_id = units.blob_id
          AND further_range.unit_key = units.unit_key
          AND further_range.ordinal = 2",
        "1 = 1",
    )
}

fn search_candidate_rows_by_lang_conn(
    conn: &Connection,
    lang: &str,
) -> Result<Vec<HydratedSearchCandidateRow>> {
    let sql = format!(
        "{} ORDER BY keys.blob_oid, units.unit_key",
        search_candidate_sql("units.lang = ?1")
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut query = stmt.query([lang])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        rows.push(search_candidate_row_from_row(row)?);
    }
    Ok(hydrate_candidate_rows(conn, rows, None)?
        .expect("uncancelled search-candidate hydration completes"))
}

/// The `LIKE` operand that holds when a column contains `literal`, with the
/// wildcards `LIKE` would otherwise read escaped for `ESCAPE '\'`.
fn like_contains_pattern(literal: &str) -> String {
    let mut pattern = String::with_capacity(literal.len() + 2);
    pattern.push('%');
    for character in literal.chars() {
        if matches!(character, '%' | '_' | '\\') {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern.push('%');
    pattern
}

/// The candidate-name projection and the literal prefilter parameters it binds.
///
/// The predicate is built here, next to the query it feeds, so a test can pin
/// both the plan and the parameter order the caller has to bind.
fn search_candidate_name_rows_sql(
    langs: &[String],
    required_literals: Option<&[Vec<String>]>,
) -> (String, Vec<String>) {
    // No `ORDER BY`: candidates are deduplicated through an ordered map after
    // matching, so the storage order carries no meaning, while sorting the
    // whole declaration projection cost a temp B-tree over every workspace
    // declaration on every request (issue #1199).
    //
    // The prefilter is one disjunct per pattern, and one conjunct per literal
    // that pattern requires, over the three channels the matched name is built
    // from. It is therefore a superset of the authoritative match, which still
    // runs over the returned rows. Without it, a batch holding a single regular
    // expression scanned every declaration in every language index: 86,688 rows
    // to answer 713 matches on this repository (issue #2316).
    //
    // Three channels are enough because a required literal is `[a-z0-9_]` only.
    // The matched name is the hydrated package prefix joined to the short name
    // with `.`, so such a literal lies inside one of them, never across the
    // join; the package prefix is either the persisted `content_qualifier` or
    // the live path prefix `active.package_literals` reports. `exact_fqn` and
    // `normalized_fqn` would only repeat that, at the price of the two longest
    // string comparisons in the row, and they are a snapshot of one path's
    // hydration rather than this request's.
    //
    // `LIKE` rather than `instr(lower(column), ...)`: `LIKE` is ASCII
    // case-insensitive on its own, which is the case rule the extracted literals
    // are built for, while `lower()` allocated a folded copy of every column of
    // every row for every literal.
    let mut literal_parameters: Vec<String> = Vec::new();
    let literal_predicate = required_literals
        .filter(|per_pattern| !per_pattern.is_empty())
        .map(|per_pattern| {
            assert!(
                per_pattern.iter().all(|literals| !literals.is_empty()),
                "a pattern without a required literal makes the prefilter unconditionally true: {per_pattern:?}"
            );
            let disjuncts = per_pattern
                .iter()
                .map(|literals| {
                    let conjuncts = literals
                        .iter()
                        .map(|literal| {
                            literal_parameters.push(like_contains_pattern(literal));
                            let parameter = langs.len() + literal_parameters.len();
                            format!(
                                r"(units.short_name LIKE ?{parameter} ESCAPE '\'
                                  OR units.content_qualifier LIKE ?{parameter} ESCAPE '\'
                                  OR active.package_literals LIKE ?{parameter} ESCAPE '\')"
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" AND ");
                    format!("({conjuncts})")
                })
                .collect::<Vec<_>>()
                .join(" OR ");
            format!(" AND (active.prefilter_exempt = 1 OR {disjuncts})")
        })
        .unwrap_or_default();
    let language_parameters = (1..=langs.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>();
    let language_cases = langs
        .iter()
        .enumerate()
        .map(|(index, _)| format!("WHEN ?{} THEN {index}", index + 1))
        .collect::<Vec<_>>()
        .join(" ");
    let sql = format!(
        "SELECT CASE units.lang {language_cases} END,
                keys.blob_oid, units.unit_key, units.short_name, units.content_qualifier
         FROM temp.active_blob_oids AS active
         CROSS JOIN blobs AS keys
           ON keys.blob_oid = active.blob_oid
         CROSS JOIN code_units AS units
           ON units.blob_id = keys.id
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         WHERE units.lang IN ({}) AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}{literal_predicate}",
        language_parameters.join(", ")
    );
    (sql, literal_parameters)
}

/// Candidate discovery only: combine a written member's unchanged terminal
/// segments with every live class having that terminal owner. Include visibility
/// and ambiguity are proved by the shared C++ reconciler after hydration. This
/// superset keeps canonical namespace/anchored patterns from being discarded by
/// provisional names, without hydrating every out-of-line body in the workspace.
fn cpp_search_owner_name_rows_sql(
    langs: &[String],
    required_literals: Option<&[Vec<String>]>,
    parameter_offset: usize,
) -> (String, Vec<String>) {
    let mut parameters = Vec::new();
    let literal_predicate = required_literals
        .map(|patterns| {
            let disjuncts = patterns
                .iter()
                .map(|literals| {
                    let conjuncts = literals
                        .iter()
                        .map(|literal| {
                            parameters.push(like_contains_pattern(literal));
                            let slot = langs.len() + parameter_offset + parameters.len();
                            format!(
                                r"(owner.short_name LIKE ?{slot} ESCAPE '\'
                    OR owner.content_qualifier LIKE ?{slot} ESCAPE '\'
                    OR member.segment LIKE ?{slot} ESCAPE '\')"
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" AND ");
                    format!("({conjuncts})")
                })
                .collect::<Vec<_>>()
                .join(" OR ");
            format!(" AND ({disjuncts})")
        })
        .unwrap_or_default();
    let language_slots = (1..=langs.len())
        .map(|slot| format!("?{slot}"))
        .collect::<Vec<_>>()
        .join(", ");
    let language_cases = langs
        .iter()
        .enumerate()
        .map(|(index, _)| format!("WHEN ?{} THEN {index}", index + 1))
        .collect::<Vec<_>>()
        .join(" ");
    (format!("SELECT CASE units.lang {language_cases} END,
                keys.blob_oid, units.unit_key,
                owner.short_name || '.' || member.segment, owner.content_qualifier
         FROM temp.active_blob_oids AS active
         CROSS JOIN blobs AS keys ON keys.blob_oid = active.blob_oid
         CROSS JOIN code_units AS units ON units.blob_id = keys.id
         JOIN blob_meta AS meta ON meta.blob_id = units.blob_id
         JOIN code_unit_fq_segments AS terminal_owner
           ON terminal_owner.blob_id = units.blob_id AND terminal_owner.unit_key = units.unit_key
          AND terminal_owner.seg_ordinal = units.fq_segment_count - 2
          AND terminal_owner.seg_kind IN ('package', 'type', 'nested')
         JOIN code_unit_fq_segments AS member
           ON member.blob_id = units.blob_id AND member.unit_key = units.unit_key
          AND member.seg_ordinal = units.fq_segment_count - 1 AND member.seg_kind = 'member'
         CROSS JOIN code_units AS owner
           ON owner.lang IN ({language_slots}) AND owner.identifier = terminal_owner.segment
          AND owner.kind = 0 AND owner.in_declarations = 1
         JOIN blobs AS owner_blob ON owner_blob.id = owner.blob_id
         JOIN temp.active_blob_oids AS owner_active ON owner_active.blob_oid = owner_blob.blob_oid
         WHERE units.lang = 'cpp' AND units.kind = 1 AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
           AND EXISTS (
             SELECT 1 FROM source_declaration_units AS link
             JOIN source_cpp_declarations AS declaration
               ON declaration.blob_id = link.blob_id AND declaration.declaration_id = link.declaration_id
              AND declaration.occurrence_role IN (1, 2)
             JOIN source_cpp_declaration_paths AS path
               ON path.blob_id = link.blob_id AND path.declaration_id = link.declaration_id
              AND path.path_kind = 0 AND path.ordinal = 0
             WHERE link.blob_id = units.blob_id AND link.unit_key = units.unit_key
           ){literal_predicate}"), parameters)
}

fn search_candidate_name_rows_conn_cancellable(
    conn: &Connection,
    langs: &[String],
    (sql, literal_parameters): (String, Vec<String>),
    cancellation: Option<&CancellationToken>,
) -> Result<LimitedQueryRows<SearchCandidateNameRow>> {
    if langs.is_empty() {
        return Ok(LimitedQueryRows::complete(Vec::new(), 0));
    }
    let mut stmt = conn.prepare_cached(&sql)?;
    let parameters = langs
        .iter()
        .map(String::as_str)
        .chain(literal_parameters.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let mut query = stmt.query(rusqlite::params_from_iter(parameters))?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    while let Some(row) = query.next()? {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        }
        inspected = inspected.saturating_add(1);
        let lang_index = row.get::<_, i64>(0)?;
        let lang_index = usize::try_from(lang_index)
            .map_err(|_| StoreError::new(format!("invalid search language index {lang_index}")))?;
        let oid_text = row.get::<_, String>(1)?;
        let blob_oid = Oid::from_str(&oid_text).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(err))
        })?;
        rows.push(SearchCandidateNameRow {
            lang_index,
            blob_oid,
            unit_key: row.get(2)?,
            short_name: row.get(3)?,
            content_qualifier: row.get(4)?,
        });
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn insert_temp_three_column_rows(
    conn: &Connection,
    table: &str,
    columns: &str,
    rows: impl IntoIterator<Item = [rusqlite::types::Value; 3]>,
) -> Result<()> {
    let mut rows = rows.into_iter();
    loop {
        let chunk = rows.by_ref().take(300).collect::<Vec<_>>();
        if chunk.is_empty() {
            break;
        }
        let values = std::iter::repeat_n("(?, ?, ?)", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("INSERT OR IGNORE INTO temp.{table}({columns}) VALUES {values}");
        let parameters = chunk.into_iter().flatten().collect::<Vec<_>>();
        conn.prepare_cached(&sql)?
            .execute(params_from_iter(parameters.iter()))?;
    }
    Ok(())
}

fn sync_active_blob_oids(conn: &Connection, active_blobs: &[ActiveSearchBlob]) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS active_blob_oids(
           blob_oid TEXT NOT NULL PRIMARY KEY
             CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*'),
           package_literals TEXT NOT NULL,
           prefilter_exempt INTEGER NOT NULL CHECK(prefilter_exempt IN (0, 1))
         ) WITHOUT ROWID, STRICT;
         DELETE FROM temp.active_blob_oids;",
    )?;
    insert_temp_three_column_rows(
        conn,
        "active_blob_oids",
        "blob_oid, package_literals, prefilter_exempt",
        active_blobs.iter().map(|blob| {
            [
                blob.oid.to_string().into(),
                blob.package_literals.clone().into(),
                i64::from(blob.prefilter_exempt).into(),
            ]
        }),
    )
}

#[doc(hidden)]
pub const REVERSE_IMPORT_CANDIDATE_BLOBS_SQL: &str = "SELECT DISTINCT files.rel_path
     FROM temp.reverse_import_lookup_keys AS requested
     CROSS JOIN source_import_segments AS segments
       INDEXED BY idx_source_import_segments_by_segment
       ON segments.segment = requested.value
     JOIN import_statements AS links
       ON links.blob_id = segments.blob_id
      AND links.source_import_id = segments.import_id
      AND links.lang = ?1
     JOIN source_import_statements AS imports
       ON imports.blob_id = links.blob_id
      AND imports.ordinal = links.ordinal
     JOIN blobs AS keys
       ON keys.id = segments.blob_id
     CROSS JOIN selected_workspace_revisions AS selected
       ON selected.lang = links.lang
     CROSS JOIN main.workspace_file_versions AS files
       INDEXED BY idx_workspace_file_versions_snapshot_blob
       ON files.input_kind = 'source'
      AND files.workspace_id = selected.workspace_id
      AND files.lang = selected.lang
      AND files.generation = selected.generation
      AND files.blob_oid = keys.blob_oid
      AND files.valid_from <= selected.revision
      AND (files.valid_until IS NULL OR selected.revision < files.valid_until)
     WHERE requested.kind IN (0, 1)
       AND imports.is_wildcard = requested.kind
       AND imports.path_kind IS NOT 'static_member'";

const REVERSE_TYPE_CANDIDATE_BLOBS_SQL: &str = "SELECT DISTINCT files.rel_path
     FROM temp.reverse_import_lookup_keys AS requested
     CROSS JOIN reference_identifiers AS identifiers
       INDEXED BY idx_reference_identifiers_by_identifier
       ON identifiers.lang = ?1 AND identifiers.identifier = requested.value
     JOIN blob_reference_fact_manifests AS reference_manifest
       ON reference_manifest.blob_id = identifiers.blob_id
     JOIN reference_fact_epochs AS reference_epoch
       ON reference_epoch.lang = reference_manifest.lang
      AND reference_epoch.epoch = reference_manifest.epoch
     JOIN blobs AS keys
       ON keys.id = identifiers.blob_id
     CROSS JOIN selected_workspace_revisions AS selected
       ON selected.lang = identifiers.lang
     CROSS JOIN main.workspace_file_versions AS files
       INDEXED BY idx_workspace_file_versions_snapshot_blob
       ON files.input_kind = 'source'
      AND files.workspace_id = selected.workspace_id
      AND files.lang = selected.lang
      AND files.generation = selected.generation
      AND files.blob_oid = keys.blob_oid
      AND files.valid_from <= selected.revision
      AND (files.valid_until IS NULL OR selected.revision < files.valid_until)
     WHERE requested.kind = 2";

const REVERSE_IDENTIFIER_CANDIDATE_PATHS_SQL: &str = "SELECT DISTINCT files.rel_path
     FROM temp.reverse_import_lookup_keys AS requested
     CROSS JOIN reference_identifiers AS identifiers
       INDEXED BY idx_reference_identifiers_by_identifier
       ON identifiers.lang = ?1 AND identifiers.identifier = requested.value
     JOIN blob_reference_fact_manifests AS reference_manifest
       ON reference_manifest.blob_id = identifiers.blob_id
     JOIN reference_fact_epochs AS reference_epoch
       ON reference_epoch.lang = reference_manifest.lang
      AND reference_epoch.epoch = reference_manifest.epoch
     JOIN blobs AS keys
       ON keys.id = identifiers.blob_id
     CROSS JOIN selected_workspace_revisions AS selected
       ON selected.lang = identifiers.lang
     CROSS JOIN main.workspace_file_versions AS files
       INDEXED BY idx_workspace_file_versions_snapshot_blob
       ON files.input_kind = 'source'
      AND files.workspace_id = selected.workspace_id
      AND files.lang = selected.lang
      AND files.generation = selected.generation
      AND files.blob_oid = keys.blob_oid
      AND files.valid_from <= selected.revision
      AND (files.valid_until IS NULL OR selected.revision < files.valid_until)
     WHERE requested.kind = 2";

#[doc(hidden)]
pub fn sync_reverse_reference_lookup_keys(
    conn: &Connection,
    explicit_import_segments: &HashSet<String>,
    wildcard_import_segments: &HashSet<String>,
    type_identifiers: &HashSet<String>,
) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS reverse_import_lookup_keys(
           kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
           value TEXT NOT NULL,
           PRIMARY KEY(kind, value)
         ) WITHOUT ROWID, STRICT;
         DELETE FROM temp.reverse_import_lookup_keys;",
    )?;
    let mut statement = conn.prepare_cached(
        "INSERT OR IGNORE INTO temp.reverse_import_lookup_keys(kind, value) VALUES(?1, ?2)",
    )?;
    for (kind, values) in [
        (0_i64, explicit_import_segments),
        (1_i64, wildcard_import_segments),
        (2_i64, type_identifiers),
    ] {
        for value in values {
            statement.execute(params![kind, value])?;
        }
    }
    Ok(())
}

fn usage_fact_rows_by_lang_conn(
    conn: &Connection,
    lang: &str,
) -> Result<Vec<HydratedUsageFactRow>> {
    // This API reads the whole language inventory. Check its publication
    // witnesses before membership filtering can turn unavailable into absent.
    let unavailable = conn
        .prepare_cached(
            "SELECT blob.blob_oid
             FROM blobs AS blob
             JOIN source_fact_readiness AS visibility
               ON visibility.blob_id = blob.id
             LEFT JOIN analysis_epochs AS epoch ON epoch.lang = blob.lang
             WHERE blob.lang = ?1
               AND blob.generation = COALESCE(epoch.generation, 0)
               AND visibility.available = 0
             LIMIT 1",
        )?
        .query_row([lang], |row| row.get::<_, String>(0))
        .optional()?;
    if let Some(oid) = unavailable {
        return Err(StoreError::new(format!(
            "canonical declaration visibility is unavailable for {oid}/{lang}"
        )));
    }
    let sql = usage_fact_rows_by_lang_sql();
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = collect_mapped_rows(stmt.query_map([lang], usage_fact_row_from_row)?)?;
    drop(stmt);
    Ok(hydrate_candidate_rows(conn, rows, None)?
        .expect("uncancelled usage-fact hydration completes"))
}

#[doc(hidden)]
pub fn usage_fact_rows_by_lang_sql() -> String {
    let metadata_columns = signature_metadata_projection_columns_sql("metadata");
    format!(
        "SELECT keys.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                units.content_qualifier, units.signature, units.synthetic,
                units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                units.in_definition_lookup, units.fq_anchor_kind, units.fq_anchor_pop,
                units.fq_package_tail_segments, units.fq_segment_count,
                units.exact_fqn_tail, units.fq_segment_bytes,
                units.normalized_fqn_tail, signature.text,
                {metadata_columns}
         FROM code_units AS units
         JOIN blobs AS keys
           ON keys.id = units.blob_id
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         LEFT JOIN unit_signatures AS signature
           ON signature.blob_id = units.blob_id
          AND signature.unit_key = units.unit_key
          AND signature.ordinal = 0
         LEFT JOIN blob_optional_fact_manifest AS pair_manifest
           ON pair_manifest.blob_id = units.blob_id
          AND pair_manifest.fact_kind = {OPTIONAL_FACT_KIND_SIGNATURE_METADATA_SIGNATURE}
         LEFT JOIN unit_signature_metadata_signatures AS pair
           ON pair.blob_id = units.blob_id
          AND pair.unit_key = units.unit_key
           AND pair.signature_ordinal = 0
          AND pair.metadata_ordinal = (
            SELECT MIN(first_pair.metadata_ordinal)
            FROM unit_signature_metadata_signatures AS first_pair
            WHERE first_pair.blob_id = units.blob_id
              AND first_pair.unit_key = units.unit_key
              AND first_pair.signature_ordinal = 0
          )
         LEFT JOIN unit_signature_metadata_values AS metadata
           ON metadata.blob_id = units.blob_id
          AND metadata.unit_key = units.unit_key
          AND metadata.ordinal = CASE
            WHEN pair_manifest.blob_id IS NULL THEN 0
            ELSE pair.metadata_ordinal
          END
         WHERE units.lang = ?1 AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY keys.blob_oid, units.unit_key"
    )
}

fn primary_ranges_by_unit_for_lang_conn(
    conn: &Connection,
    lang: &str,
    oids: &[Oid],
) -> Result<HashMap<(Oid, i64), Range>> {
    let mut out = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT keys.blob_oid, ranges.unit_key, ranges.start_byte,
                    ranges.end_byte, ranges.start_line, ranges.end_line
             FROM blobs AS keys
             JOIN unit_ranges AS ranges
               ON ranges.blob_id = keys.id AND ranges.ordinal = 0
             LEFT JOIN analysis_epochs AS active_epoch ON active_epoch.lang = keys.lang
             WHERE keys.lang = ?
               AND keys.blob_oid IN ({placeholders})
               AND keys.generation = COALESCE(active_epoch.generation, 0)"
        );
        let mut parameters = Vec::with_capacity(chunk.len() + 1);
        parameters.push(lang.to_string());
        parameters.extend(chunk.iter().map(Oid::to_string));
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
            let oid_text = row.get::<_, String>(0)?;
            let oid = Oid::from_str(&oid_text).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            let range =
                range_from_coordinate_values(row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)
                    .map_err(rusqlite_error_from_store)?;
            Ok(((oid, row.get(1)?), range))
        })?;
        for row in rows {
            let (key, range) = row?;
            out.insert(key, range);
        }
    }
    Ok(out)
}

fn definition_lookup_candidate_rows_by_oids_conn(
    conn: &Connection,
    lang: &str,
    oids: &[Oid],
) -> Result<Vec<HydratedCandidateRow>> {
    let mut out = Vec::new();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT keys.blob_oid, units.lang, units.unit_key, units.kind, units.short_name,
                    units.content_qualifier, units.signature, units.synthetic,
                    units.is_type_alias, units.top_level_ordinal, units.in_declarations,
                    units.in_definition_lookup, units.fq_anchor_kind, units.fq_anchor_pop,
                    units.fq_package_tail_segments, units.fq_segment_count,
                    units.exact_fqn_tail, units.fq_segment_bytes,
                    units.normalized_fqn_tail
             FROM blobs AS keys
             JOIN code_units AS units ON units.blob_id = keys.id
             JOIN blob_meta AS meta
               ON meta.blob_id = units.blob_id
             WHERE keys.lang = ?
               AND (units.in_declarations = 1 OR units.in_definition_lookup = 1)
               AND keys.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}
             ORDER BY keys.blob_oid, units.unit_key"
        );
        let mut parameters = Vec::with_capacity(chunk.len() + 1);
        parameters.push(lang.to_string());
        parameters.extend(chunk.iter().map(Oid::to_string));
        let mut stmt = conn.prepare_cached(&sql)?;
        out.extend(collect_mapped_rows(stmt.query_map(
            params_from_iter(parameters.iter()),
            candidate_row_from_row,
        )?)?);
    }
    Ok(hydrate_candidate_rows(conn, out, None)?
        .expect("uncancelled definition-candidate hydration completes"))
}

fn blobs_with_structured_imports_conn(
    conn: &Connection,
    lang: &str,
    oids: &[Oid],
) -> Result<HashSet<Oid>> {
    let mut out = HashSet::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT DISTINCT keys.blob_oid
             FROM blobs AS keys
             JOIN import_statements AS imports ON imports.blob_id = keys.id
             JOIN blob_meta AS meta
               ON meta.blob_id = imports.blob_id
             WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        );
        let mut parameters = Vec::with_capacity(chunk.len() + 1);
        parameters.push(lang.to_string());
        parameters.extend(chunk.iter().map(Oid::to_string));
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
            let oid_text = row.get::<_, String>(0)?;
            Oid::from_str(&oid_text).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })
        })?;
        for row in rows {
            out.insert(row?);
        }
    }
    Ok(out)
}

#[doc(hidden)]
pub fn read_unit_rows<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
) -> Result<Vec<UnitRow>> {
    Ok(
        read_unit_rows_while(conn, oid, lang, adapter, file, &|| true)?
            .expect("unconditional unit hydration cannot be cancelled"),
    )
}

/// Mount canonical unit identities for source-family declaration bridges.
#[doc(hidden)]
pub fn read_source_unit_map<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<HashMap<i64, CodeUnit>>> {
    Ok(
        read_unit_rows_while(conn, oid, lang, adapter, file, keep_going)?
            .map(|rows| rows.into_iter().map(|row| (row.key, row.unit)).collect()),
    )
}

#[doc(hidden)]
pub fn read_unit_rows_while<A: StoreLanguageAdapter>(
    conn: &Connection,
    oid: &str,
    lang: &str,
    adapter: &A,
    file: &ProjectFile,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<Vec<UnitRow>>> {
    if !keep_going() {
        return Ok(None);
    }
    let sql = format!(
        "SELECT keys.blob_oid, {RAW_UNIT_COLUMNS}
         FROM blobs AS keys
         JOIN code_units AS units ON units.blob_id = keys.id
         WHERE keys.blob_oid = ?1 AND keys.lang = ?2
         ORDER BY units.unit_key"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut query = stmt.query(params![oid, lang])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        if !keep_going() {
            return Ok(None);
        }
        rows.push(raw_unit_row_from_row(row, 0)?);
    }
    drop(query);
    drop(stmt);
    if !attach_raw_unit_fq_segments_while(conn, lang, &[oid.to_string()], &mut rows, keep_going)? {
        return Ok(None);
    }

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if !keep_going() {
            return Ok(None);
        }
        let (fq, package_segment_count) =
            hydrate_unit_fq(adapter, row.fq.as_ref(), &row.content_qualifier, file)?;
        let unit = CodeUnit::from_fq(
            file.clone(),
            row.kind,
            fq,
            package_segment_count,
            row.signature,
            row.synthetic,
        );
        out.push(UnitRow {
            key: row.key,
            unit,
            is_type_alias: row.is_type_alias,
            top_level_ordinal: row.top_level_ordinal,
            in_declarations: row.in_declarations,
            in_definition_lookup: row.in_definition_lookup,
            in_test_region: row.in_test_region,
        });
    }
    Ok(keep_going().then_some(out))
}

#[doc(hidden)]
pub fn read_import_infos(conn: &Connection, oid: &str, lang: &str) -> Result<Vec<ImportInfo>> {
    require_unbounded_hydration(
        read_import_infos_with_session(conn, oid, lang, None)?,
        "unbounded import-info hydration stopped unexpectedly",
    )
}

fn require_unbounded_hydration<T>(value: Option<T>, message: &'static str) -> Result<T> {
    value.ok_or_else(|| StoreError::new(message))
}

fn read_import_infos_with_session(
    conn: &Connection,
    oid: &str,
    lang: &str,
    session: Option<&ResolutionSession>,
) -> Result<Option<Vec<ImportInfo>>> {
    let sql = format!(
        "SELECT {IMPORT_STATEMENT_COLUMNS} FROM source_import_statements
         WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
         ORDER BY ordinal"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        if session.is_some_and(|session| !session.scope_step()) {
            return Ok(None);
        }
        import_info_from_statement_row(row, 0).map(Some)
    })?;
    let mut imports = Vec::new();
    for row in rows {
        let Some(import) = row? else {
            return Ok(None);
        };
        imports.push(import);
    }
    let mut by_oid = HashMap::default();
    by_oid.insert(oid.to_string(), imports);
    if !attach_import_path_children(conn, lang, &[oid.to_string()], &mut by_oid, session)? {
        return Ok(None);
    }
    Ok(Some(by_oid.remove(oid).unwrap_or_default()))
}

fn read_materialization_records(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<Vec<MaterializationRecord>> {
    let oid = oid.to_owned();
    let rows = read_materialization_records_bulk(conn, lang, std::slice::from_ref(&oid))?;
    materialization_records_for_file(rows.get(&oid), by_key)
}

fn read_scala_exports(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<crate::analyzer::ScalaExportInfo>>> {
    let oid = oid.to_owned();
    let rows = read_scala_exports_bulk(conn, lang, std::slice::from_ref(&oid))?;
    scala_exports_map_for_file(rows.get(&oid), by_key)
}

fn read_unit_string_vec(
    conn: &Connection,
    oid: &str,
    lang: &str,
    table: &str,
    value_column: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<String>>> {
    let oid = oid.to_owned();
    let rows =
        read_unit_string_vec_bulk(conn, lang, table, value_column, std::slice::from_ref(&oid))?;
    Ok(unit_values_map_for_file(rows.get(&oid), by_key))
}

fn read_signature_metadata(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<SignatureMetadata>>> {
    require_declaration_visibility_available(conn, oid, lang)?;
    let oid = oid.to_owned();
    let rows = read_signature_metadata_bulk(conn, lang, std::slice::from_ref(&oid))?;
    Ok(unit_values_map_for_file(rows.get(&oid), by_key))
}

fn read_signature_metadata_signature_ordinals(
    conn: &Connection,
    oid: &str,
    lang: &str,
) -> Result<Vec<SignatureMetadataSignatureOrdinalRow>> {
    let oid = oid.to_owned();
    let mut rows =
        read_signature_metadata_signature_ordinals_bulk(conn, lang, std::slice::from_ref(&oid))?;
    Ok(rows.remove(&oid).unwrap_or_default())
}

fn direct_children_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<HydratedCandidateRow>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = direct_children_limited_candidate_sql();
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
    ])?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut bytes = LimitedQueryByteBudget::default();
    let mut complete = true;
    while let Some(row) = query.next()? {
        inspected = inspected.saturating_add(1);
        // The relational FQ header occupies 12..=18; row bytes follow.
        if !bytes.admit_sqlite_bytes(row.get::<_, i64>(19)?)? {
            complete = false;
            break;
        }
        rows.push(candidate_row_from_row(row)?);
    }
    drop(query);
    let rows = hydrate_candidate_rows(conn, rows, None)?
        .expect("uncancelled direct-child hydration completes");
    if !complete || inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn direct_children_limited_candidate_sql() -> String {
    let sql = limited_candidate_rows_sql_with_membership(
        "child",
        "FROM code_units AS owner
         JOIN unit_children AS edge
           ON edge.blob_id = owner.blob_id
          AND edge.parent_key = owner.unit_key
         JOIN code_units AS child
           ON child.blob_id = edge.blob_id
          AND child.unit_key = edge.child_key
         JOIN blobs AS keys
           ON keys.id = child.blob_id
         JOIN blob_meta AS meta
           ON meta.blob_id = child.blob_id",
        "owner.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
         AND (owner.exact_fqn = ?3 OR owner.exact_fqn IS NULL)
         AND owner.kind = ?4
         AND owner.short_name = ?5
         AND owner.signature IS ?6
         AND owner.synthetic = ?7",
        "owner.in_declarations = 1 AND child.in_declarations = 1",
        &["edge.ordinal", "child.unit_key"],
    );
    format!("{sql} LIMIT ?8")
}

/// The per-unit signature-metadata read. Named so a plan pin can
/// assert it seeks the table's primary key rather than scanning it.
/// The unbounded API binds a negative SQL limit and does not consume row bytes.
#[doc(hidden)]
pub fn signature_metadata_for_unit_sql() -> &'static str {
    static SQL: LazyLock<String> = LazyLock::new(|| {
        let row_bytes = signature_metadata_row_bytes_sql("metadata");
        let columns = signature_metadata_projection_columns_sql("metadata");
        format!(
            "SELECT {row_bytes}, {columns}
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         JOIN unit_signature_metadata_values AS metadata
           ON metadata.blob_id = units.blob_id
          AND metadata.unit_key = units.unit_key
         WHERE {LIMITED_UNIT_IDENTITY_PREDICATE}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY metadata.ordinal
         LIMIT ?8"
        )
    });
    SQL.as_str()
}

fn signature_metadata_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<SignatureMetadata>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = signature_metadata_for_unit_sql();
    let oid = oid.to_string();
    require_declaration_visibility_available(conn, &oid, lang)?;
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
    ])?;
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut byte_budget = LimitedQueryByteBudget::default();
    while let Some(row) = query.next()? {
        inspected = inspected.saturating_add(1);
        let byte_len = row.get::<_, i64>(0)?;
        if !byte_budget.admit_sqlite_bytes(byte_len)? {
            return Ok(LimitedQueryRows::incomplete(Vec::new(), inspected));
        }
        rows.push(signature_metadata_projection_from_row(row, 1)?);
    }
    drop(query);
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn signatures_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<String>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT length(CAST(signatures.text AS BLOB)),
                CASE
                    WHEN length(CAST(signatures.text AS BLOB)) <= ?9 THEN signatures.text
                    ELSE NULL
                END
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         JOIN unit_signatures AS signatures
           ON signatures.blob_id = units.blob_id
          AND signatures.unit_key = units.unit_key
         WHERE {LIMITED_UNIT_IDENTITY_PREDICATE}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY signatures.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES)?,
    ])?;
    collect_limited_text_rows(&mut query, limit)
}

fn ruby_method_dispatch_modes_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<RubyMethodDispatchMode>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT modes.mode
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         JOIN ruby_method_dispatch_modes AS modes
           ON modes.blob_id = units.blob_id
          AND modes.unit_key = units.unit_key
         WHERE {LIMITED_UNIT_IDENTITY_PREDICATE}
           AND units.in_declarations = 1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY units.unit_key
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mapped = statement.query_map(
        params![
            oid,
            lang,
            unit.fq_name(),
            kind,
            unit.short_name(),
            unit.signature(),
            synthetic,
            sql_limit,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    let mut rows = Vec::new();
    for raw_mode in mapped {
        rows.push(ruby_dispatch_mode_from_i64(raw_mode?)?);
    }
    let inspected = rows.len();
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn collect_limited_text_rows(
    query: &mut rusqlite::Rows<'_>,
    limit: usize,
) -> Result<LimitedQueryRows<String>> {
    let mut rows = Vec::new();
    let mut inspected = 0usize;
    let mut bytes = LimitedQueryByteBudget::default();
    while let Some(row) = query.next()? {
        inspected = inspected.saturating_add(1);
        let byte_len = row.get::<_, i64>(0)?;
        if !bytes.admit_sqlite_bytes(byte_len)? {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        }
        let Some(value) = row.get::<_, Option<String>>(1)? else {
            return Ok(LimitedQueryRows::incomplete(rows, inspected));
        };
        rows.push(value);
    }
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn raw_supertypes_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<String>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT length(CAST(supertypes.raw AS BLOB)),
                CASE
                    WHEN length(CAST(supertypes.raw AS BLOB))
                           <= {MAX_LIMITED_QUERY_ROW_BYTES}
                    THEN supertypes.raw
                    ELSE NULL
                END
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         JOIN unit_supertypes AS supertypes
           ON supertypes.blob_id = units.blob_id
          AND supertypes.unit_key = units.unit_key
         WHERE {LIMITED_UNIT_IDENTITY_PREDICATE}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY supertypes.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
    ])?;
    collect_limited_text_rows(&mut query, limit)
}

fn supertype_lookup_paths_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<String>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT length(CAST(supertypes.lookup_path AS BLOB)),
                CASE
                    WHEN length(CAST(supertypes.lookup_path AS BLOB))
                           <= {MAX_LIMITED_QUERY_ROW_BYTES}
                    THEN supertypes.lookup_path
                    ELSE NULL
                END
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         JOIN unit_supertypes AS supertypes
           ON supertypes.blob_id = units.blob_id
          AND supertypes.unit_key = units.unit_key
         WHERE {LIMITED_UNIT_IDENTITY_PREDICATE}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY supertypes.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mut query = statement.query(params![
        oid,
        lang,
        unit.fq_name(),
        kind,
        unit.short_name(),
        unit.signature(),
        synthetic,
        sql_limit,
    ])?;
    collect_limited_text_rows(&mut query, limit)
}

fn ranges_for_unit_limited_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    unit: &CodeUnit,
    limit: usize,
) -> Result<LimitedQueryRows<Range>> {
    if limit == 0 {
        return Ok(LimitedQueryRows::incomplete(Vec::new(), 0));
    }
    let sql = format!(
        "SELECT ranges.start_byte, ranges.end_byte, ranges.start_line, ranges.end_line
         FROM code_units AS units
         JOIN blob_meta AS meta
           ON meta.blob_id = units.blob_id
         JOIN unit_ranges AS ranges
           ON ranges.blob_id = units.blob_id
          AND ranges.unit_key = units.unit_key
         WHERE {LIMITED_UNIT_IDENTITY_PREDICATE}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY ranges.ordinal
         LIMIT ?8"
    );
    let oid = oid.to_string();
    let kind = code_unit_kind_to_i64(unit.kind());
    let synthetic = bool_to_i64(unit.is_synthetic());
    let sql_limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = conn.prepare_cached(&sql)?;
    let mapped = statement.query_map(
        params![
            oid,
            lang,
            unit.fq_name(),
            kind,
            unit.short_name(),
            unit.signature(),
            synthetic,
            sql_limit,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let mut rows = Vec::new();
    for row in mapped {
        let (start_byte, end_byte, start_line, end_line) = row?;
        rows.push(Range {
            start_byte: i64_to_usize(start_byte)?,
            end_byte: i64_to_usize(end_byte)?,
            start_line: i64_to_usize(start_line)?,
            end_line: i64_to_usize(end_line)?,
        });
    }
    let inspected = rows.len();
    if inspected == limit {
        Ok(LimitedQueryRows::incomplete(rows, inspected))
    } else {
        Ok(LimitedQueryRows::complete(rows, inspected))
    }
}

fn read_ranges(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<Range>>> {
    let mut stmt = conn.prepare_cached(
        "SELECT unit_key, start_byte, end_byte, start_line, end_line
         FROM unit_ranges
         WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
         ORDER BY unit_key, ordinal",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut out: HashMap<CodeUnit, Vec<Range>> = HashMap::default();
    for row in rows {
        let (key, start_byte, end_byte, start_line, end_line) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.entry(unit.unit.clone()).or_default().push(Range {
                start_byte: i64_to_usize(start_byte)?,
                end_byte: i64_to_usize(end_byte)?,
                start_line: i64_to_usize(start_line)?,
                end_line: i64_to_usize(end_line)?,
            });
        }
    }
    Ok(out)
}

fn read_children(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, Vec<CodeUnit>>> {
    let oid = oid.to_owned();
    let rows = read_children_bulk(conn, lang, std::slice::from_ref(&oid))?;
    Ok(children_map_for_file(rows.get(&oid), by_key))
}

fn read_ruby_method_dispatch_modes(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, RubyMethodDispatchMode>> {
    let mut stmt = conn.prepare_cached(
        "SELECT unit_key, mode FROM ruby_method_dispatch_modes
         WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
         ORDER BY unit_key",
    )?;
    let rows = stmt.query_map(params![oid, lang], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut out = HashMap::default();
    for row in rows {
        let (key, raw_mode) = row?;
        if let Some(unit) = by_key.get(&key) {
            out.insert(unit.unit.clone(), ruby_dispatch_mode_from_i64(raw_mode)?);
        }
    }
    Ok(out)
}

fn read_scala_traits(
    conn: &Connection,
    oid: &str,
    lang: &str,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashSet<CodeUnit>> {
    let oid = oid.to_owned();
    let rows = read_scala_traits_bulk(conn, lang, std::slice::from_ref(&oid))?;
    Ok(scala_traits_for_file(rows.get(&oid), by_key))
}

fn synthesize_file_scope(file: &ProjectFile, source: &str, state: &mut FileState) {
    let code_unit = CodeUnit::file_scope(file.clone());
    if state.declarations.contains(&code_unit) {
        return;
    }
    state.top_level_declarations.push(code_unit.clone());
    state.declarations.insert(code_unit.clone());
    state.ranges.entry(code_unit).or_default().push(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 0,
        end_line: compute_line_starts(source).len().saturating_sub(1),
    });
}

fn ensure_language_epochs_tx(
    conn: &mut Connection,
    entries: &[(String, String)],
) -> Result<HashMap<String, GenerationId>> {
    if let Some(generations) = matching_language_epochs_conn(conn, entries)? {
        return Ok(generations);
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut generations = HashMap::default();
    for (lang, analysis_epoch) in entries {
        let stored_epoch: Option<String> = tx
            .query_row(
                "SELECT epoch FROM analysis_epochs WHERE lang = ?1",
                [lang],
                |row| row.get(0),
            )
            .optional()?;
        if stored_epoch.as_deref() == Some(analysis_epoch) {
            let generation = current_generation_conn(&tx, lang)?;
            generations.insert(lang.clone(), generation);
            continue;
        }
        if lang == "rust" {
            tx.execute("DELETE FROM rust_crate_versions WHERE lang = ?1", [lang])?;
            tx.execute("DELETE FROM rust_crate_reconciliations", [])?;
        }
        // Summaries are keyed by generation, so a rotation strands every version
        // row of the language. Withdraw them and delete the headers nothing binds.
        if tx.execute(unit_summaries::DELETE_LANGUAGE_VERSIONS_SQL, [lang])? > 0 {
            tx.execute(unit_summaries::DELETE_UNBOUND_SUMMARIES_SQL, [])?;
        }
        if lang == "rust" {
            // After the summary withdrawal: Rust summary versions bind topologies too.
            tx.execute(rust_crates::DELETE_UNBOUND_TOPOLOGIES_SQL, [])?;
        }
        let generation: i64 = tx.query_row(
            "UPDATE analysis_generation_sequence
         SET next_generation = next_generation + 1
         WHERE id = 1 AND next_generation < 9223372036854775807
         RETURNING next_generation - 1",
            [],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO analysis_epochs(lang, epoch, generation) VALUES(?1, ?2, ?3)
         ON CONFLICT(lang) DO UPDATE SET
           epoch = excluded.epoch,
           generation = excluded.generation",
            params![lang, analysis_epoch, generation],
        )?;
        generations.insert(lang.clone(), GenerationId(generation));
    }
    tx.commit()?;
    Ok(generations)
}

fn matching_language_epochs_conn(
    conn: &Connection,
    entries: &[(String, String)],
) -> Result<Option<HashMap<String, GenerationId>>> {
    let mut generations = HashMap::default();
    for (lang, analysis_epoch) in entries {
        let stored: Option<(String, i64)> = conn
            .query_row(
                "SELECT epoch, generation FROM analysis_epochs WHERE lang = ?1",
                [lang],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((stored_epoch, generation)) = stored else {
            return Ok(None);
        };
        if stored_epoch != *analysis_epoch {
            return Ok(None);
        }
        generations.insert(lang.clone(), GenerationId(generation));
    }
    Ok(Some(generations))
}

/// Return the head revision of one storage language after checking that it is
/// still the revision the analyzer based its change on.
fn require_base_workspace_revision(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &WorkspaceId,
    base_snapshots: &WorkspaceSnapshots,
    lang: &str,
    generation: GenerationId,
) -> Result<i64> {
    require_current_generation(tx, lang, generation)?;
    let head_revision = tx.query_row(
        "SELECT revision FROM workspace_heads
         WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3",
        params![workspace_id.as_str(), lang, generation.0],
        |row| row.get::<_, i64>(0),
    )?;
    let base_revision = base_snapshots
        .get(lang)
        .filter(|snapshot| {
            snapshot.workspace_id == *workspace_id && snapshot.generation == generation
        })
        .map(|snapshot| snapshot.revision)
        .ok_or_else(|| {
            StoreError::new(format!(
                "missing base workspace revision for {lang} generation {}",
                generation.0
            ))
        })?;
    if head_revision != base_revision {
        return Err(StoreError::new(format!(
            "workspace revision conflict for {lang}: analyzer has {base_revision}, head is {head_revision}"
        )));
    }
    Ok(head_revision)
}

#[doc(hidden)]
pub fn require_current_generation(
    conn: &Connection,
    lang: &str,
    generation: GenerationId,
) -> Result<()> {
    let current = current_generation_conn(conn, lang)?;
    if current != generation {
        return Err(StoreError::stale_generation(format!(
            "stale analyzer generation for {lang}: captured {}, current {}",
            generation.0, current.0
        )));
    }
    Ok(())
}

fn require_generation_map<'a>(
    conn: &Connection,
    generations: &HashMap<String, GenerationId>,
    requested_languages: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let mut seen = HashSet::default();
    for lang in requested_languages {
        if !seen.insert(lang) {
            continue;
        }
        let Some(generation) = generations.get(lang) else {
            return Err(StoreError::stale_generation(format!(
                "missing captured analyzer generation for {lang}"
            )));
        };
        require_current_generation(conn, lang, *generation)?;
    }
    Ok(())
}

#[doc(hidden)]
pub fn current_generation_conn(conn: &Connection, lang: &str) -> Result<GenerationId> {
    let generation = conn
        .prepare_cached("SELECT generation FROM analysis_epochs WHERE lang = ?1")?
        .query_row([lang], |row| row.get(0))
        .optional()?
        .unwrap_or(GenerationId::BOOTSTRAP.0);
    Ok(GenerationId(generation))
}

fn contains_parsed_blob_conn(
    conn: &Connection,
    oid: Oid,
    lang: &str,
    condition: &str,
) -> Result<bool> {
    let sql = format!(
        "SELECT 1 FROM blob_meta AS meta
         WHERE meta.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
           AND {condition}
         LIMIT 1"
    );
    Ok(conn
        .prepare_cached(&sql)?
        .query_row(params![oid.to_string(), lang], |_| Ok(()))
        .optional()?
        .is_some())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum StoredCascadeCost {
    Missing,
    Legacy,
    Known(PersistedMutationCost),
}

fn stored_blob_cascade_costs_conn(
    conn: &Connection,
    prepared: &[&PreparedParsedBlob],
    mut on_query: impl FnMut(),
    restored_roots: &mut PersistedMutationCost,
) -> Result<Vec<StoredCascadeCost>> {
    const KEYS_PER_QUERY: usize = PersistBatchTargets::PRODUCTION.max_blobs;
    let mut costs = Vec::with_capacity(prepared.len());
    for chunk in prepared.chunks(KEYS_PER_QUERY) {
        // Pad the `VALUES (ordinal, ?, ?)` list to a fixed arity so this query
        // collapses to two cached SQL shapes instead of one per chunk length.
        // The padded rows carry NULL blob_oid/lang, so their LEFT JOINs miss and
        // they report `Missing`; we size `chunk_costs` to the padded arity, fill
        // every ordinal, then truncate the padding away — semantics-preserving.
        let padded = padded_arity(chunk.len(), &CASCADE_ARITY_LADDER);
        let mut chunk_costs = vec![StoredCascadeCost::Missing; padded];
        let sql = stored_blob_cascade_costs_sql(padded);
        on_query();
        let mut statement = conn.prepare_cached(&sql)?;
        let mut parameters: Vec<Option<&str>> = Vec::with_capacity(padded * 2);
        for blob in chunk {
            parameters.push(Some(blob.oid_text.as_str()));
            parameters.push(Some(blob.lang.as_str()));
        }
        parameters.resize(padded * 2, None);
        let rows = statement.query_map(params_from_iter(parameters.iter()), |row| {
            Ok((
                row.get::<_, usize>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, usize>(3)?,
                row.get::<_, Option<usize>>(4)?,
                row.get::<_, usize>(5)?,
                row.get::<_, usize>(6)?,
            ))
        })?;
        for row in rows {
            let (
                ordinal,
                blob_present,
                meta_present,
                logical_rows,
                payload_bytes,
                restored_rows,
                restored_bytes,
            ) = row?;
            restored_roots.logical_rows = restored_roots.logical_rows.saturating_add(restored_rows);
            restored_roots.payload_bytes =
                restored_roots.payload_bytes.saturating_add(restored_bytes);
            chunk_costs[ordinal] = match (blob_present, meta_present, payload_bytes) {
                (false, _, _) => StoredCascadeCost::Missing,
                (true, false, Some(payload_bytes)) => {
                    StoredCascadeCost::Known(PersistedMutationCost {
                        logical_rows,
                        payload_bytes,
                    })
                }
                (true, false, None) => StoredCascadeCost::Legacy,
                (true, true, Some(payload_bytes)) => {
                    StoredCascadeCost::Known(PersistedMutationCost {
                        logical_rows,
                        payload_bytes,
                    })
                }
                (true, true, None) => StoredCascadeCost::Legacy,
            };
        }
        chunk_costs.truncate(chunk.len());
        costs.extend(chunk_costs);
    }
    Ok(costs)
}

/// Fixed arities for the cascade-cost `VALUES` query. Capped at
/// `PersistBatchTargets::PRODUCTION.max_blobs` (the chunk size), which the SQL
/// builder asserts against.
const CASCADE_ARITY_LADDER: [usize; 2] = [16, PersistBatchTargets::PRODUCTION.max_blobs];

// These are the projection rows written by insert_rust_fact_rows. Canonical
// source manifests explicitly exclude them. Integer coordinates and repeated
// language partition keys are not charged as semantic payload.
const RUST_PROJECTION_PAYLOAD_COLUMNS: &[(&str, &[&str])] = &[
    (
        "rust_exports",
        &["exported_name", "source_path", "imported_name"],
    ),
    (
        "rust_import_targets",
        &[
            "module_path",
            "bound_name",
            "imported_name",
            "visibility",
            "cfg_condition",
            "owner_module",
        ],
    ),
    ("rust_identifier_occurrences", &["identifier"]),
    ("source_rust_item_macros", &["macro_name", "decoration_cfg"]),
    ("rust_include_edges", &["relative_path", "file_name"]),
    (
        "rust_include_host_bindings",
        &["local_name", "module_specifier", "imported_name", "kind"],
    ),
];

/// The semantic IR head's `logical_rows` is the head plus every child row. Its
/// children go with the head through `ON DELETE CASCADE`, so the head is the
/// one place this count reads. A blob without a head counts zero.
fn semantic_ir_cascade_rows_sql(blob_id: &str) -> String {
    format!(
        "COALESCE((SELECT logical_rows FROM semantic_ir_publications WHERE blob_id = {blob_id}), 0)"
    )
}

fn semantic_ir_cascade_payload_bytes_sql(blob_id: &str) -> String {
    format!(
        "COALESCE((SELECT payload_bytes FROM semantic_ir_publications WHERE blob_id = {blob_id}), 0)"
    )
}

#[doc(hidden)]
pub fn rust_projection_cascade_rows_sql(blob_id: &str) -> String {
    RUST_PROJECTION_PAYLOAD_COLUMNS
        .iter()
        .map(|(table, _)| format!("(SELECT COUNT(*) FROM {table} WHERE blob_id = {blob_id})"))
        .collect::<Vec<_>>()
        .join(" + ")
}

#[doc(hidden)]
pub fn rust_projection_cascade_payload_bytes_sql(blob_id: &str) -> String {
    RUST_PROJECTION_PAYLOAD_COLUMNS
        .iter()
        .map(|(table, columns)| {
            let bytes = columns
                .iter()
                .map(|column| format!("COALESCE(length(CAST({column} AS BLOB)),0)"))
                .collect::<Vec<_>>()
                .join(" + ");
            format!("COALESCE((SELECT SUM({bytes}) FROM {table} WHERE blob_id = {blob_id}),0)")
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

// One whole-blob row authority for replacement and stale reclamation. The
// caller supplies the blob key expression; all three queries bind meta
// to that same blob. Headerless capsules own no parsed metadata rows.
fn complete_blob_cascade_rows_sql(blob_id: &str) -> String {
    let class_set_rows = class_set_summary_cascade_rows_sql(blob_id);
    let rust_projection_rows = rust_projection_cascade_rows_sql(blob_id);
    let semantic_ir_rows = semantic_ir_cascade_rows_sql(blob_id);
    format!(
        "1 + CASE WHEN meta.blob_id IS NULL THEN
         COALESCE((SELECT logical_rows FROM resolution_fragment_interiors
           WHERE blob_id = {blob_id} AND publication_state = 'complete'), 0) ELSE
         1 + meta.stored_unit_count + meta.range_count + meta.signature_count
           + meta.signature_metadata_count
           + (SELECT COUNT(*) FROM unit_signature_parameters AS parameters
              WHERE parameters.blob_id = meta.blob_id)
           + (SELECT COUNT(*) FROM unit_cpp_class_template_parameters AS cpp_parameters
              WHERE cpp_parameters.blob_id = meta.blob_id)
           + (SELECT COUNT(*) FROM unit_cpp_class_template_alias_components AS cpp_components
              WHERE cpp_components.blob_id = meta.blob_id)
           + (SELECT COUNT(*) FROM unit_cpp_class_template_expressions AS cpp_expressions
              WHERE cpp_expressions.blob_id = meta.blob_id)
           + (SELECT COUNT(*) FROM unit_cpp_class_template_terms AS cpp_terms
              WHERE cpp_terms.blob_id = meta.blob_id)
           + meta.supertype_count + meta.child_count
           + meta.import_statement_count + meta.type_identifier_count
           + (SELECT COUNT(*) FROM code_unit_fq_segments AS fq_segments
              WHERE fq_segments.blob_id = meta.blob_id)
           + (SELECT COALESCE(SUM(row_count), 0) + COUNT(*)
              FROM blob_optional_fact_manifest AS manifest
              WHERE manifest.blob_id = meta.blob_id)
           + COALESCE((SELECT facts.logical_rows FROM source_fact_manifests AS facts
              WHERE facts.blob_id = meta.blob_id AND facts.publication_state = 'complete'), 0)
           + (SELECT COUNT(*) FROM blob_reference_fact_manifests AS reference_manifest
              WHERE reference_manifest.blob_id = meta.blob_id)
           + COALESCE((
               SELECT interior.logical_rows - CASE
                 WHEN meta.declaration_visibility_version IS NOT NULL
                 THEN interior.expected_declaration_visibility_property_count ELSE 0 END
               FROM resolution_fragment_interiors AS interior
               WHERE interior.blob_id = meta.blob_id
                 AND interior.publication_state = 'complete'
             ), 0)
           + (SELECT COUNT(*) FROM blob_payload_costs AS costs
              WHERE costs.blob_id = meta.blob_id) END
         + {class_set_rows}
         + {rust_projection_rows}
         + {semantic_ir_rows}
         + (SELECT COUNT(*) FROM workspace_resolution_content_roots WHERE blob_id = {blob_id})"
    )
}

#[doc(hidden)]
pub fn stored_blob_cascade_costs_sql(key_count: usize) -> String {
    assert!((1..=PersistBatchTargets::PRODUCTION.max_blobs).contains(&key_count));
    let requested = (0..key_count)
        .map(|ordinal| format!("({ordinal}, ?, ?)"))
        .collect::<Vec<_>>()
        .join(", ");
    let complete_rows = complete_blob_cascade_rows_sql("blob.id");
    let class_set_bytes = class_set_summary_cascade_payload_bytes_sql("blob.id");
    let semantic_ir_bytes = semantic_ir_cascade_payload_bytes_sql("blob.id");
    format!(
        "WITH requested(ordinal, blob_oid, lang) AS (VALUES {requested})
         SELECT requested.ordinal,
           blob.id IS NOT NULL,
           meta.blob_id IS NOT NULL,
           CASE WHEN blob.id IS NULL THEN 0 ELSE {complete_rows} END,
           CASE WHEN blob.id IS NULL THEN 0
             WHEN meta.blob_id IS NULL THEN {class_set_bytes} + {semantic_ir_bytes}
               + COALESCE((SELECT payload_bytes FROM resolution_fragment_interiors
                 WHERE blob_id = blob.id AND publication_state = 'complete'), 0)
               + COALESCE((SELECT SUM(length(workspace_id) + length(lang))
                 FROM workspace_resolution_content_roots WHERE blob_id = blob.id), 0)
             WHEN costs.payload_bytes IS NULL THEN NULL
             ELSE costs.payload_bytes + {class_set_bytes}
               + COALESCE((SELECT SUM(length(workspace_id) + length(lang))
                 FROM workspace_resolution_content_roots WHERE blob_id = blob.id), 0) END
         , (SELECT COUNT(*) FROM workspace_resolution_content_roots AS roots
            WHERE roots.blob_id = blob.id AND roots.generation = blob.generation
                   AND blob.generation = COALESCE((SELECT generation FROM analysis_epochs WHERE lang = blob.lang), 0)),
           COALESCE((SELECT SUM(length(CAST(roots.workspace_id AS BLOB)) + length(CAST(roots.lang AS BLOB)))
             FROM workspace_resolution_content_roots AS roots WHERE roots.blob_id = blob.id AND roots.generation = blob.generation
                   AND blob.generation = COALESCE((SELECT generation FROM analysis_epochs WHERE lang = blob.lang), 0)), 0)
         FROM requested
         LEFT JOIN blobs AS blob
           ON blob.blob_oid = requested.blob_oid AND blob.lang = requested.lang
         LEFT JOIN blob_meta AS meta
           ON meta.blob_id = blob.id
         LEFT JOIN blob_payload_costs AS costs
           ON costs.blob_id = meta.blob_id"
    )
}

#[derive(Clone, Copy)]
struct ClassSetCascadeChild {
    table: &'static str,
    payload_bytes: &'static str,
}

const CLASS_SET_SUMMARY_CASCADE_CHILDREN: [ClassSetCascadeChild; 7] = [
    ClassSetCascadeChild {
        table: "class_set_summary_facts",
        payload_bytes: "length(CAST(child_cost.fact_kind AS BLOB))
             + length(CAST(child_cost.source_kind AS BLOB))
             + COALESCE(length(child_cost.source_event_key), 0)
             + COALESCE(length(child_cost.carrier_key), 0)
             + COALESCE(length(child_cost.sink_event_key), 0)",
    },
    ClassSetCascadeChild {
        table: "class_set_summary_exits",
        payload_bytes: "length(CAST(child_cost.exit_kind AS BLOB))",
    },
    ClassSetCascadeChild {
        table: "class_set_summary_reached",
        payload_bytes: "0",
    },
    ClassSetCascadeChild {
        table: "class_set_summary_dependencies",
        payload_bytes: "length(child_cost.callee_procedure_lineage)
             + length(child_cost.callee_entry_selector_digest)
             + length(child_cost.expected_output_digest)
             + length(child_cost.consumed_child_lookup_digest)
             + length(CAST(child_cost.entry_kind AS BLOB))
             + COALESCE(length(child_cost.entry_carrier_key), 0)
             + COALESCE(length(child_cost.entry_source_behavior_digest), 0)",
    },
    ClassSetCascadeChild {
        table: "class_set_summary_dependency_sources",
        payload_bytes: "length(child_cost.source_event_digest)",
    },
    ClassSetCascadeChild {
        table: "class_set_summary_reads",
        payload_bytes: "length(child_cost.key_digest) + length(CAST(child_cost.kind AS BLOB))
             + COALESCE(length(CAST(child_cost.family AS BLOB)), 0)
             + COALESCE(length(CAST(child_cost.languages AS BLOB)), 0)
             + COALESCE(length(CAST(child_cost.rel_path AS BLOB)), 0)
             + COALESCE(length(CAST(child_cost.name AS BLOB)), 0)
             + COALESCE(length(child_cost.index_key), 0)
             + COALESCE(length(CAST(child_cost.blob_oid AS BLOB)), 0)
             + COALESCE(length(child_cost.subject), 0)
             + COALESCE(length(child_cost.digest), 0)",
    },
    ClassSetCascadeChild {
        table: "class_set_summary_charges",
        payload_bytes: "length(CAST(child_cost.charge_kind AS BLOB))",
    },
];

const CLASS_SET_SURFACE_CASCADE_CHILDREN: [ClassSetCascadeChild; 5] = [
    ClassSetCascadeChild {
        table: "class_set_procedure_surface_calls",
        payload_bytes: "length(CAST(child_cost.dispatch_kind AS BLOB))
             + length(CAST(child_cost.dispatch_status AS BLOB))
             + COALESCE(length(CAST(child_cost.dispatch_capability AS BLOB)), 0)
             + COALESCE(length(CAST(child_cost.dispatch_coverage AS BLOB)), 0)",
    },
    ClassSetCascadeChild {
        table: "class_set_procedure_surface_bindings",
        payload_bytes: "length(CAST(child_cost.binding_status AS BLOB))
             + COALESCE(length(CAST(child_cost.binding_capability AS BLOB)), 0)",
    },
    ClassSetCascadeChild {
        table: "class_set_procedure_surface_entered",
        payload_bytes: "length(child_cost.target_procedure_lineage)
             + length(CAST(child_cost.target_rel_path AS BLOB))
             + length(CAST(child_cost.target_lang AS BLOB))
             + length(child_cost.target_artifact_public_identity)
             + length(child_cost.target_artifact_content_identity)
             + length(child_cost.target_local_structure_digest)",
    },
    ClassSetCascadeChild {
        table: "class_set_procedure_surface_lexical_children",
        payload_bytes: "length(child_cost.child_procedure_lineage)
             + length(CAST(child_cost.child_rel_path AS BLOB))
             + length(CAST(child_cost.child_lang AS BLOB))
             + length(child_cost.child_artifact_public_identity)
             + length(child_cost.child_artifact_content_identity)
             + length(child_cost.child_local_structure_digest)",
    },
    ClassSetCascadeChild {
        table: "class_set_procedure_surface_reads",
        payload_bytes: "length(child_cost.key_digest) + length(CAST(child_cost.kind AS BLOB))
             + length(CAST(child_cost.family AS BLOB))
             + length(CAST(child_cost.rel_path AS BLOB))
             + length(child_cost.subject) + length(child_cost.digest)",
    },
];

fn class_set_summary_cascade_rows_sql(blob_id: &str) -> String {
    let summary_predicate = class_set_summary_owner_or_surface_predicate("summary_cost", blob_id);
    let child_rows = CLASS_SET_SUMMARY_CASCADE_CHILDREN
        .map(|child| {
            format!(
                "(SELECT COUNT(*) FROM {table} AS child_cost
              JOIN class_set_summaries AS summary_cost
                ON summary_cost.summary_id = child_cost.summary_id
              WHERE {summary_predicate})",
                table = child.table,
            )
        })
        .join(" + ");
    let surface_child_rows = CLASS_SET_SURFACE_CASCADE_CHILDREN
        .map(|child| {
            format!(
                "(SELECT COUNT(*) FROM {table} AS child_cost
              JOIN class_set_procedure_surfaces AS surface_cost
                ON surface_cost.surface_id = child_cost.surface_id
              WHERE surface_cost.owner_blob_id = {blob_id})",
                table = child.table,
            )
        })
        .join(" + ");
    let root_result_rows = format!(
        "(SELECT COUNT(*) FROM class_set_finding_free_root_results AS root_result_cost
          WHERE root_result_cost.owner_blob_id = {blob_id})
         + (SELECT COUNT(*) FROM class_set_finding_free_root_rows AS child_cost
            JOIN class_set_finding_free_root_results AS root_result_cost
              ON root_result_cost.result_id = child_cost.result_id
            WHERE root_result_cost.owner_blob_id = {blob_id})"
    );
    format!(
        "(SELECT COUNT(*) FROM class_set_summaries AS summary_cost
          WHERE {summary_predicate}) + {child_rows}
          + (SELECT COUNT(*) FROM class_set_procedure_surfaces AS surface_cost
             WHERE surface_cost.owner_blob_id = {blob_id}) + {surface_child_rows}
          + {root_result_rows}"
    )
}

fn class_set_summary_cascade_payload_bytes_sql(blob_id: &str) -> String {
    let summary_predicate = class_set_summary_owner_or_surface_predicate("summary_cost", blob_id);
    let header = format!(
        "COALESCE((SELECT SUM(
            length(lookup_digest) + length(procedure_lineage)
            + length(CAST(owner_rel_path AS BLOB)) + length(CAST(lang AS BLOB))
            + length(artifact_public_identity) + length(artifact_content_identity)
            + length(semantics_digest) + length(context_digest)
            + length(behavior_read_digest) + length(dependency_digest)
            + length(carrier_digest) + length(field_slots_digest)
            + length(root_surface_digest)
            + length(direct_calls_digest)
            + length(CAST(completion AS BLOB)) + length(CAST(budget_mode AS BLOB))
            + length(output_digest) + length(content_digest))
          FROM class_set_summaries AS summary_cost
          WHERE {summary_predicate}), 0)"
    );
    let child_payloads = CLASS_SET_SUMMARY_CASCADE_CHILDREN
        .map(|child| {
            format!(
                "COALESCE((SELECT SUM({payload}) FROM {table} AS child_cost
              JOIN class_set_summaries AS summary_cost
                ON summary_cost.summary_id = child_cost.summary_id
              WHERE {summary_predicate}), 0)",
                payload = child.payload_bytes,
                table = child.table,
            )
        })
        .join(" + ");
    let surface_header = format!(
        "COALESCE((SELECT SUM(
            length(surface_digest) + length(procedure_lineage)
            + length(CAST(owner_rel_path AS BLOB)) + length(CAST(lang AS BLOB))
            + length(artifact_public_identity) + length(artifact_content_identity)
            + length(local_structure_digest) + length(behavior_read_digest)
            + length(carrier_semantics_digest) + length(direct_calls_digest)
            + length(CAST(completion AS BLOB)))
          FROM class_set_procedure_surfaces AS surface_cost
          WHERE surface_cost.owner_blob_id = {blob_id}), 0)"
    );
    let surface_child_payloads = CLASS_SET_SURFACE_CASCADE_CHILDREN
        .map(|child| {
            format!(
                "COALESCE((SELECT SUM({payload}) FROM {table} AS child_cost
              JOIN class_set_procedure_surfaces AS surface_cost
                ON surface_cost.surface_id = child_cost.surface_id
              WHERE surface_cost.owner_blob_id = {blob_id}), 0)",
                payload = child.payload_bytes,
                table = child.table,
            )
        })
        .join(" + ");
    let root_result_header = format!(
        "COALESCE((SELECT SUM(
            length(root_public_digest) + length(CAST(owner_rel_path AS BLOB))
            + length(CAST(lang AS BLOB)) + length(CAST(completion AS BLOB))
            + length(content_digest))
          FROM class_set_finding_free_root_results AS root_result_cost
          WHERE root_result_cost.owner_blob_id = {blob_id}), 0)"
    );
    let root_result_children = format!(
        "COALESCE((SELECT SUM(
            length(CAST(child_cost.rel_path AS BLOB))
            + length(CAST(child_cost.member AS BLOB))
            + length(CAST(child_cost.atom_kind AS BLOB))
            + COALESCE(length(CAST(child_cost.class_name AS BLOB)), 0)
            + COALESCE(length(CAST(child_cost.unknown_reason AS BLOB)), 0)
            + length(CAST(child_cost.class_set_status AS BLOB)))
          FROM class_set_finding_free_root_rows AS child_cost
          JOIN class_set_finding_free_root_results AS root_result_cost
            ON root_result_cost.result_id = child_cost.result_id
          WHERE root_result_cost.owner_blob_id = {blob_id}), 0)"
    );
    format!(
        "{header} + {child_payloads} + {surface_header} + {surface_child_payloads}
         + {root_result_header} + {root_result_children}"
    )
}

fn class_set_summary_owner_or_surface_predicate(summary: &str, blob_id: &str) -> String {
    format!(
        "({summary}.owner_blob_id = {blob_id}
          OR {summary}.root_surface_digest IN (
            SELECT surface_cost.surface_digest
            FROM class_set_procedure_surfaces AS surface_cost
            WHERE surface_cost.owner_blob_id = {blob_id}
          ))"
    )
}

#[doc(hidden)]
pub fn persisted_blob_mutation_cost_fallback_statement(
    statement: &mut rusqlite::Statement<'_>,
    oid: &str,
    lang: &str,
) -> Result<PersistedMutationCost> {
    statement
        .query_row(params![oid, lang], |row| {
            Ok(PersistedMutationCost {
                logical_rows: row.get(0)?,
                payload_bytes: row.get(1)?,
            })
        })
        .map_err(StoreError::from)
}

#[doc(hidden)]
pub fn persisted_blob_mutation_cost_fallback_sql() -> &'static str {
    // The signature-metadata term is composed rather than written out so that
    // it cannot drift from `SIGNATURE_METADATA_TEXT_COLUMNS`. The subquery
    // leaves the table unaliased on purpose: a plan pin asserts
    // `SEARCH unit_signature_metadata USING PRIMARY KEY`.
    // The visibility subtraction runs only for canonical visibility metadata.
    // Seek its native rows directly: correlating an aggregate over the legacy/
    // native UNION view prevents SQLite from pushing down the blob key.
    static SQL: LazyLock<String> = LazyLock::new(|| {
        let signature_metadata_bytes = signature_metadata_row_bytes_sql("unit_signature_metadata");
        let complete_rows = complete_blob_cascade_rows_sql("blob.id");
        let rust_projection_bytes = rust_projection_cascade_payload_bytes_sql("blob.id");
        let class_set_bytes = class_set_summary_cascade_payload_bytes_sql("blob.id");
        let semantic_ir_bytes = semantic_ir_cascade_payload_bytes_sql("blob.id");
        format!(
            "SELECT
       {complete_rows},
       CASE WHEN meta.blob_id IS NULL THEN
         COALESCE((SELECT payload_bytes FROM resolution_fragment_interiors
           WHERE blob_id = blob.id AND publication_state = 'complete'), 0) ELSE
         length(CAST(meta.content_package AS BLOB))
           + COALESCE((SELECT SUM(
               length(CAST(short_name AS BLOB)) + length(CAST(identifier AS BLOB))
               + length(CAST(content_qualifier AS BLOB))
               + COALESCE(length(CAST(exact_fqn AS BLOB)), 0)
               + COALESCE(length(CAST(normalized_fqn AS BLOB)), 0)
               + COALESCE(length(CAST(simple_type_name AS BLOB)), 0)
               + COALESCE(length(CAST(signature AS BLOB)), 0)
               + COALESCE(length(CAST(fq_anchor_kind AS BLOB)), 0)
               + COALESCE(length(CAST(exact_fqn_tail AS BLOB)), 0)
               + COALESCE(length(CAST(normalized_fqn_tail AS BLOB)), 0)
               + COALESCE(length(CAST(exact_parent_fqn_tail AS BLOB)), 0)
               + COALESCE(length(CAST(normalized_parent_fqn_tail AS BLOB)), 0)
               + COALESCE(length(CAST(package_fqn_tail AS BLOB)), 0)
             ) FROM code_units WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(seg_kind AS BLOB))
               + length(CAST(segment AS BLOB))) FROM code_unit_fq_segments
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(text AS BLOB))) FROM unit_signatures
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM({signature_metadata_bytes}) FROM unit_signature_metadata
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(label AS BLOB))
               + COALESCE(length(CAST(name AS BLOB)), 0)) FROM unit_signature_parameters
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(primary_name AS BLOB))
               + length(CAST(primary_fq_name AS BLOB))) FROM unit_cpp_class_templates
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(name AS BLOB)))
               FROM unit_cpp_class_template_parameters WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(component AS BLOB)))
               FROM unit_cpp_class_template_alias_components WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(text AS BLOB)))
               FROM unit_cpp_class_template_expressions WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(COALESCE(length(CAST(text AS BLOB)), 0)
               + COALESCE(length(CAST(atom_kind AS BLOB)), 0))
               FROM unit_cpp_class_template_terms WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(raw AS BLOB))
               + length(CAST(lookup_path AS BLOB))) FROM unit_supertypes
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(statement AS BLOB))
               + COALESCE(length(CAST(identifier AS BLOB)), 0)
               + COALESCE(length(CAST(alias AS BLOB)), 0)) FROM import_statements
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(info)) FROM scala_exports
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(payload)) FROM materialization_records
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT SUM(length(CAST(identifier AS BLOB))) FROM reference_identifiers
               WHERE blob_id = blob.id), 0)
           + COALESCE((SELECT facts.payload_bytes FROM source_fact_manifests AS facts
              WHERE facts.blob_id = blob.id AND facts.publication_state = 'complete'), 0)
           + COALESCE((
               SELECT interior.payload_bytes - CASE
                 WHEN meta.declaration_visibility_version IS NOT NULL THEN
                   COALESCE((SELECT SUM(length(CAST(property.visibility AS BLOB)))
                     FROM resolution_semantic_sites AS site
                     JOIN source_native_declaration_bridges AS native
                       ON native.blob_id = site.blob_id AND native.source_site = site.source_site
                     JOIN source_declaration_visibilities AS property
                       ON property.blob_id = native.blob_id
                      AND property.declaration_id = native.declaration_id
                     JOIN source_declaration_visibility_readiness AS readiness
                       ON readiness.blob_id = site.blob_id AND readiness.available = 1
                     WHERE site.blob_id = interior.blob_id
                       AND site.semantic_role = 'definition'), 0)
                 ELSE 0 END
               FROM resolution_fragment_interiors AS interior
               WHERE interior.blob_id = blob.id
                 AND interior.publication_state = 'complete'
             ), 0) END
         + {class_set_bytes}
         + {rust_projection_bytes}
         + {semantic_ir_bytes}
         + COALESCE((SELECT SUM(length(CAST(workspace_id AS BLOB)) + length(CAST(lang AS BLOB)))
           FROM workspace_resolution_content_roots WHERE blob_id = blob.id), 0)
     FROM blobs AS blob
     LEFT JOIN blob_meta AS meta
       ON meta.blob_id = blob.id
     WHERE blob.blob_oid = ?1 AND blob.lang = ?2"
        )
    });
    SQL.as_str()
}

fn insert_blob_payload_cost_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    payload_bytes: usize,
) -> Result<()> {
    tx.prepare_cached("INSERT INTO blob_payload_costs(blob_id, payload_bytes) VALUES(?1, ?2)")?
        .execute(params![blob_id, usize_to_i64(payload_bytes)?])?;
    Ok(())
}

/// Fixed arities for the `VALUES (?, ?)` pair lists, capped at the caller's
/// 400-key chunk size.
const PAIR_ARITY_LADDER: [usize; 4] = [16, 64, 256, 400];

/// Read-path membership for a key set: which of `entries` have a published
/// parse at the active generation. This is the hydration query.
fn parsed_blob_keys_conn(
    conn: &Connection,
    entries: &[(Oid, String)],
) -> Result<HashSet<(Oid, String)>> {
    parsed_blob_keys_conn_with_condition(conn, entries, "", read_path_parsed_blob_condition())
}

/// The same key set, answered with the full verification predicate. Used by the
/// startup reconcile that exists to verify the cache and by the explicit
/// presence checks, not by the read path.
fn verified_parsed_blob_keys_conn(
    conn: &Connection,
    entries: &[(Oid, String)],
) -> Result<HashSet<(Oid, String)>> {
    parsed_blob_keys_conn_with_condition(
        conn,
        entries,
        "",
        PARSED_BLOB_INTEGRITY_CONDITION.as_str(),
    )
}

const MISSING_PUBLISHED_COMPLETE_ANALYSIS_SQL: &str = "SELECT requested.blob_oid, requested.lang
     FROM temp.requested_parsed_blobs AS requested
     LEFT JOIN analysis_epochs AS primary_epoch
       ON primary_epoch.lang = requested.lang
     LEFT JOIN resolution_producer_epochs AS primary_resolution_epoch
       ON primary_resolution_epoch.lang = requested.lang
     LEFT JOIN blobs AS primary_blob
       ON primary_blob.blob_oid = requested.blob_oid
      AND primary_blob.lang = requested.lang
      AND primary_blob.generation = COALESCE(primary_epoch.generation, 0)
     LEFT JOIN blob_meta AS primary_meta
       ON primary_meta.blob_id = primary_blob.id
      AND primary_meta.lang = requested.lang
      AND primary_meta.is_complete = 1
      AND EXISTS (SELECT 1 FROM source_fact_readiness AS visibility
                  WHERE visibility.blob_id = primary_meta.blob_id AND visibility.available = 1)
     LEFT JOIN resolution_fragment_interiors AS primary_interior
       ON primary_interior.blob_id = primary_blob.id
      AND primary_interior.lang = requested.lang
      AND primary_interior.semantic_language = ?1
      AND primary_interior.producer_epoch = primary_resolution_epoch.producer_epoch
      AND primary_interior.publication_state = 'complete'
     LEFT JOIN semantic_ir_producer_epochs AS primary_semantic_epoch
       ON primary_semantic_epoch.lang = requested.lang
     LEFT JOIN semantic_ir_publications AS primary_semantic
       ON primary_semantic.blob_id = primary_blob.id
      AND primary_semantic.producer_epoch = primary_semantic_epoch.producer_epoch
      AND primary_semantic.publication_state = 'complete'
     WHERE primary_meta.blob_id IS NULL
        OR primary_interior.blob_id IS NULL
        OR (primary_semantic_epoch.producer_epoch IS NOT NULL AND primary_semantic.blob_id IS NULL)
        -- Projections are C++ only and carry no semantic IR rows, so they keep
        -- the resolution-only predicate below.
        OR EXISTS (
          SELECT 1
          FROM temp.requested_analysis_projections AS projection
          LEFT JOIN temp.requested_parsed_blobs AS independent
            ON independent.blob_oid = projection.blob_oid
           AND independent.lang = projection.projection_lang
          LEFT JOIN analysis_epochs AS projection_epoch
            ON projection_epoch.lang = projection.projection_lang
          JOIN blobs AS projection_blob
            ON projection_blob.blob_oid = projection.blob_oid
           AND projection_blob.lang = projection.projection_lang
          LEFT JOIN blob_meta AS projection_meta
            ON projection_meta.blob_id = projection_blob.id
           AND projection_meta.lang = projection.projection_lang
           AND projection_meta.is_complete = 1
           AND EXISTS (SELECT 1 FROM source_fact_readiness AS visibility
                       WHERE visibility.blob_id = projection_meta.blob_id AND visibility.available = 1)
          LEFT JOIN resolution_producer_epochs AS projection_resolution_epoch
            ON projection_resolution_epoch.lang = projection.projection_lang
          LEFT JOIN resolution_fragment_interiors AS projection_interior
            ON projection_interior.blob_id = projection_blob.id
           AND projection_interior.lang = projection.projection_lang
           AND projection_interior.semantic_language = ?1
           AND projection_interior.producer_epoch = projection_resolution_epoch.producer_epoch
           AND projection_interior.publication_state = 'complete'
          WHERE projection.blob_oid = requested.blob_oid
            AND projection.primary_lang = requested.lang
            AND independent.blob_oid IS NULL
            AND (
              projection_blob.generation != COALESCE(projection_epoch.generation, 0)
              OR projection_meta.blob_id IS NULL
              OR projection_interior.blob_id IS NULL
            )
        )
     ORDER BY requested.ordinal";

const REQUIRED_EXISTING_ANALYSIS_PROJECTIONS_SQL: &str = "SELECT projection.blob_oid,
            projection.primary_lang,
            projection.projection_lang
     FROM temp.requested_analysis_projections AS projection
     JOIN temp.requested_parsed_blobs AS owner
       ON owner.blob_oid = projection.blob_oid
      AND owner.lang = projection.primary_lang
     LEFT JOIN temp.requested_parsed_blobs AS independent
       ON independent.blob_oid = projection.blob_oid
      AND independent.lang = projection.projection_lang
     LEFT JOIN analysis_epochs AS projection_epoch
       ON projection_epoch.lang = projection.projection_lang
     JOIN blobs AS projection_blob
       ON projection_blob.blob_oid = projection.blob_oid
      AND projection_blob.lang = projection.projection_lang
     LEFT JOIN blob_meta AS projection_meta
       ON projection_meta.blob_id = projection_blob.id
      AND projection_meta.lang = projection.projection_lang
      AND projection_meta.is_complete = 1
      AND EXISTS (SELECT 1 FROM source_fact_readiness AS visibility
                  WHERE visibility.blob_id = projection_meta.blob_id AND visibility.available = 1)
     LEFT JOIN resolution_producer_epochs AS projection_resolution_epoch
       ON projection_resolution_epoch.lang = projection.projection_lang
     LEFT JOIN resolution_fragment_interiors AS projection_interior
       ON projection_interior.blob_id = projection_blob.id
      AND projection_interior.lang = projection.projection_lang
      AND projection_interior.semantic_language = ?1
      AND projection_interior.producer_epoch = projection_resolution_epoch.producer_epoch
      AND projection_interior.publication_state = 'complete'
     WHERE independent.blob_oid IS NULL
       AND (
         projection_blob.generation != COALESCE(projection_epoch.generation, 0)
         OR projection_meta.blob_id IS NULL
         OR projection_interior.blob_id IS NULL
       )
     ORDER BY owner.ordinal, projection.projection_lang";

fn missing_published_complete_analysis_blob_keys_conn(
    conn: &Connection,
    requests: &[CompleteAnalysisBlobRequest],
    semantic_language: Language,
) -> Result<Vec<MissingCompleteAnalysisBlob>> {
    let primary_keys = requests
        .iter()
        .map(|request| (request.oid(), request.storage_language().to_owned()))
        .collect::<Vec<_>>();
    {
        let _scope = crate::profiling::scope("store.missing_analysis.sync_requested");
        sync_requested_parsed_blobs(conn, &primary_keys)?;
        sync_requested_analysis_projections(conn, requests)?;
    }
    let _query_scope = crate::profiling::scope("store.missing_analysis.query");
    let mut statement = conn.prepare_cached(MISSING_PUBLISHED_COMPLETE_ANALYSIS_SQL)?;
    let rows = statement.query_map([semantic_language.config_label()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut missing_keys = Vec::new();
    for row in rows {
        let (oid, storage_language) = row?;
        if let Ok(oid) = Oid::from_str(&oid) {
            missing_keys.push((oid, storage_language));
        }
    }

    // An allowed projection that has never existed is the compact encoding of
    // "identical to the primary". An existing projection whose parsed or
    // resolution seal is no longer current is different: the owner must repair
    // that exact storage key even if a fresh parse now finds the two readings
    // identical and would ordinarily omit it.
    let mut projection_statement =
        conn.prepare_cached(REQUIRED_EXISTING_ANALYSIS_PROJECTIONS_SQL)?;
    let projection_rows =
        projection_statement.query_map([semantic_language.config_label()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
    let mut required_existing_projections: HashMap<(String, String), Vec<String>> =
        HashMap::default();
    for row in projection_rows {
        let (oid, primary, projection) = row?;
        required_existing_projections
            .entry((oid, primary))
            .or_default()
            .push(projection);
    }

    let mut missing = Vec::with_capacity(missing_keys.len());
    for (oid, storage_language) in missing_keys {
        let required_existing_additional_storage_languages = required_existing_projections
            .remove(&(oid.to_string(), storage_language.clone()))
            .unwrap_or_default();
        missing.push(MissingCompleteAnalysisBlob {
            oid,
            storage_language,
            required_existing_additional_storage_languages,
        });
    }
    Ok(missing)
}

fn sync_requested_analysis_projections(
    conn: &Connection,
    requests: &[CompleteAnalysisBlobRequest],
) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS requested_analysis_projections(
           blob_oid TEXT NOT NULL,
           primary_lang TEXT NOT NULL,
           projection_lang TEXT NOT NULL,
           PRIMARY KEY(blob_oid, primary_lang, projection_lang)
         ) WITHOUT ROWID, STRICT;
         DELETE FROM temp.requested_analysis_projections;",
    )?;
    let projections = requests
        .iter()
        .flat_map(|request| {
            request
                .possible_additional_storage_languages()
                .iter()
                .map(move |projection| {
                    (
                        request.oid().to_string(),
                        request.storage_language(),
                        projection.as_str(),
                    )
                })
        })
        .collect::<Vec<_>>();
    insert_temp_three_column_rows(
        conn,
        "requested_analysis_projections",
        "blob_oid, primary_lang, projection_lang",
        projections.into_iter().map(|(oid, primary, projection)| {
            [
                rusqlite::types::Value::Text(oid),
                rusqlite::types::Value::Text(primary.to_owned()),
                rusqlite::types::Value::Text(projection.to_owned()),
            ]
        }),
    )
}

fn sync_requested_parsed_blobs(conn: &Connection, entries: &[(Oid, String)]) -> Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS requested_parsed_blobs(
           blob_oid TEXT NOT NULL,
           lang TEXT NOT NULL,
           ordinal INTEGER NOT NULL,
           PRIMARY KEY(blob_oid, lang)
         ) WITHOUT ROWID, STRICT;
         DELETE FROM temp.requested_parsed_blobs;",
    )?;
    insert_temp_three_column_rows(
        conn,
        "requested_parsed_blobs",
        "blob_oid, lang, ordinal",
        entries.iter().enumerate().map(|(ordinal, (oid, lang))| {
            [
                rusqlite::types::Value::Text(oid.to_string()),
                rusqlite::types::Value::Text(lang.clone()),
                rusqlite::types::Value::Integer(ordinal as i64),
            ]
        }),
    )
}

/// The batched key-membership statement. Kept as one builder so the EXPLAIN
/// QUERY PLAN pin cannot drift away from the statement the read path runs.
fn parsed_blob_keys_sql(padded_arity: usize, joins: &str, condition: &str) -> String {
    let values = std::iter::repeat_n("(?, ?)", padded_arity)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH requested(blob_oid, lang) AS (VALUES {values})
             SELECT requested.blob_oid, requested.lang
             FROM requested
             JOIN blobs AS keys
               ON keys.blob_oid = requested.blob_oid AND keys.lang = requested.lang
             JOIN blob_meta AS meta
               ON meta.blob_id = keys.id
             {joins}
             WHERE {condition}"
    )
}

fn parsed_blob_keys_conn_with_condition(
    conn: &Connection,
    entries: &[(Oid, String)],
    joins: &str,
    condition: &str,
) -> Result<HashSet<(Oid, String)>> {
    const KEYS_PER_QUERY: usize = 400;
    let mut unique = Vec::with_capacity(entries.len());
    let mut seen = HashSet::default();
    for entry in entries {
        if seen.insert(entry.clone()) {
            unique.push(entry.clone());
        }
    }
    let mut present = set_with_capacity(unique.len());
    for chunk in unique.chunks(KEYS_PER_QUERY) {
        // Pad the `VALUES (?, ?)` pair list to a fixed arity so this read-path
        // query lands on a small set of cached SQL shapes. Padded rows carry
        // NULL blob_oid/lang; the inner JOIN drops them, so the matched-key set
        // is unchanged.
        let padded = padded_arity(chunk.len(), &PAIR_ARITY_LADDER);
        let sql = parsed_blob_keys_sql(padded, joins, condition);
        let mut parameters: Vec<Option<String>> = Vec::with_capacity(padded * 2);
        for (oid, lang) in chunk {
            parameters.push(Some(oid.to_string()));
            parameters.push(Some(lang.clone()));
        }
        parameters.resize(padded * 2, None);
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params_from_iter(parameters.iter()), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (oid, lang) = row?;
            if let Ok(oid) = Oid::from_str(&oid) {
                present.insert((oid, lang));
            }
        }
    }
    Ok(present)
}

#[doc(hidden)]
pub fn stale_generation_blob_costs_sql() -> &'static str {
    static SQL: LazyLock<String> = LazyLock::new(|| {
        let complete_rows = complete_blob_cascade_rows_sql("blobs.id");
        format!(
            "SELECT blobs.blob_oid, blobs.lang,
            {complete_rows} AS logical_rows
     FROM blobs
     LEFT JOIN analysis_epochs AS epochs ON epochs.lang = blobs.lang
     LEFT JOIN blob_meta AS meta
       ON meta.blob_id = blobs.id
     LEFT JOIN blob_payload_costs AS costs
       ON costs.blob_id = meta.blob_id
     WHERE blobs.generation <> COALESCE(epochs.generation, 0)
     ORDER BY blobs.lang, blobs.generation, blobs.blob_oid"
        )
    });
    SQL.as_str()
}

fn reclaim_stale_generations_conn(conn: &mut Connection, max_logical_rows: usize) -> Result<usize> {
    if max_logical_rows == 0 {
        return Ok(0);
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stale_blobs = {
        let mut stmt = tx.prepare(stale_generation_blob_costs_sql())?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, usize>(2)?,
            ))
        })?;
        let mut selected = Vec::new();
        let mut logical_rows = 0usize;
        for row in rows {
            let (oid, lang, rows) = row?;
            if !selected.is_empty() && logical_rows.saturating_add(rows) > max_logical_rows {
                break;
            }
            selected.push((oid, lang));
            logical_rows = logical_rows.saturating_add(rows);
            if logical_rows >= max_logical_rows {
                break;
            }
        }
        (selected, logical_rows)
    };
    let (stale_blobs, mut reclaimed) = stale_blobs;
    {
        let mut delete = tx.prepare(
            "DELETE FROM blobs
             WHERE blob_oid = ?1 AND lang = ?2
               AND generation <> COALESCE(
                 (SELECT generation FROM analysis_epochs WHERE lang = ?2), 0
               )",
        )?;
        for (oid, lang) in stale_blobs {
            delete.execute(params![oid, lang])?;
        }
    }

    let remaining = max_logical_rows.saturating_sub(reclaimed);
    if remaining > 0 {
        tx.execute(unit_summaries::DELETE_STALE_GENERATION_VERSIONS_SQL, [])?;
        tx.execute(
            "DELETE FROM workspace_heads
             WHERE generation <> COALESCE(
               (SELECT generation FROM analysis_epochs
                WHERE analysis_epochs.lang = workspace_heads.lang), 0
             )",
            [],
        )?;
        reclaimed = reclaimed.saturating_add(tx.execute(
            "DELETE FROM workspace_revisions
             WHERE (workspace_id, lang, generation, revision) IN (
               SELECT revisions.workspace_id, revisions.lang,
                      revisions.generation, revisions.revision
               FROM workspace_revisions AS revisions
               LEFT JOIN analysis_epochs AS epochs ON epochs.lang = revisions.lang
               WHERE revisions.generation <> COALESCE(epochs.generation, 0)
               ORDER BY revisions.lang, revisions.generation, revisions.revision
               LIMIT ?1
             )",
            [usize_to_i64(remaining)?],
        )?);
    }
    // Foreground projection withdrawal and publication retain content-addressed
    // summaries for the next build. Sweep even when no stale versions existed
    // or stale blobs exhausted this pass's logical-row budget.
    tx.execute(unit_summaries::DELETE_UNBOUND_SUMMARIES_SQL, [])?;
    tx.execute(rust_crates::DELETE_UNBOUND_TOPOLOGIES_SQL, [])?;
    tx.commit()?;
    Ok(reclaimed)
}

#[doc(hidden)]
pub fn serialize_blob<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value)
        .map_err(|err| StoreError::new(format!("analyzer store serialization error: {err}")))
}

#[doc(hidden)]
pub struct PersistedUnitFq {
    #[doc(hidden)]
    pub anchor: Option<PackageAnchor>,
    #[doc(hidden)]
    pub package_tail_segments: usize,
    #[doc(hidden)]
    pub tail: FqName,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct PreparedUnitFq {
    #[doc(hidden)]
    pub anchor_kind: Option<&'static str>,
    #[doc(hidden)]
    pub anchor_pop: Option<i64>,
    #[doc(hidden)]
    pub package_tail_segments: i64,
    #[doc(hidden)]
    pub exact_tail: String,
    #[doc(hidden)]
    pub normalized_tail: Option<String>,
    #[doc(hidden)]
    pub exact_parent_tail: String,
    #[doc(hidden)]
    pub normalized_parent_tail: Option<String>,
    #[doc(hidden)]
    pub package_tail: String,
    #[doc(hidden)]
    pub segments: Vec<(i64, &'static str, String)>,
}

#[doc(hidden)]
pub fn segment_kind_sql(kind: SegmentKind) -> &'static str {
    match kind {
        SegmentKind::Path => "path",
        SegmentKind::Package => "package",
        SegmentKind::Type => "type",
        SegmentKind::Companion => "companion",
        SegmentKind::Nested => "nested",
        SegmentKind::Member => "member",
        SegmentKind::Unknown => "unknown",
    }
}

fn segment_kind_from_sql(value: &str) -> Result<SegmentKind> {
    match value {
        "path" => Ok(SegmentKind::Path),
        "package" => Ok(SegmentKind::Package),
        "type" => Ok(SegmentKind::Type),
        "companion" => Ok(SegmentKind::Companion),
        "nested" => Ok(SegmentKind::Nested),
        "member" => Ok(SegmentKind::Member),
        "unknown" => Ok(SegmentKind::Unknown),
        _ => Err(StoreError::new(format!(
            "analyzer store row has unknown relational FqName segment kind {value:?}"
        ))),
    }
}

#[doc(hidden)]
pub fn persisted_unit_fq<A: StoreLanguageAdapter>(
    adapter: &A,
    unit: &CodeUnit,
    content_qualifier: &str,
) -> Option<PersistedUnitFq> {
    let fq = unit.fq();
    if fq.is_empty() {
        return None;
    }
    let explicit_anchor = unit.package_anchor();
    let anchored = explicit_anchor
        .or_else(|| adapter.default_package_anchor())
        .and_then(|anchor| {
            let prefix =
                adapter.resolve_package_anchor(anchor, content_qualifier, unit.source())?;
            let package = unit.package_fq();
            let placed = if explicit_anchor.is_some() {
                package.starts_with(&prefix)
            } else {
                package == prefix
            };
            if !placed {
                return None;
            }
            Some(PersistedUnitFq {
                anchor: Some(anchor),
                package_tail_segments: package.len() - prefix.len(),
                tail: fq.suffix_from(prefix.len()),
            })
        });
    match anchored {
        Some(anchored) => Some(anchored),
        None => {
            debug_assert!(
                explicit_anchor.is_none(),
                "an explicitly anchored CodeUnit must resolve to a prefix of its package \
                 (anchor={explicit_anchor:?}, content_qualifier={content_qualifier:?}, \
                 unit={unit:?})"
            );
            Some(PersistedUnitFq {
                anchor: None,
                package_tail_segments: unit.package_segment_count(),
                tail: fq.clone(),
            })
        }
    }
}

/// Address `unit` through the same mounted prefix/content tail split used by
/// persistence.
///
/// A hydrated unit carries its complete workspace identity, while relational
/// rows for path-derived languages store only the content-stable suffix. Query
/// construction must reproduce that boundary instead of treating the complete
/// identity as a stable tail.
#[doc(hidden)]
pub fn relational_name_for_unit<A: StoreLanguageAdapter>(
    adapter: &A,
    unit: &CodeUnit,
    content_qualifier: &str,
) -> RelationalName {
    let Some(persisted) = persisted_unit_fq(adapter, unit, content_qualifier) else {
        return RelationalName::stable(unit.fq().clone());
    };
    let prefix_len = unit
        .fq()
        .len()
        .checked_sub(persisted.tail.len())
        .expect("a persisted unit tail is a suffix of its hydrated identity");
    RelationalName::new(unit.fq().prefix(prefix_len), persisted.tail)
}

#[doc(hidden)]
pub fn prepare_unit_fq<A: StoreLanguageAdapter>(
    adapter: &A,
    unit: &CodeUnit,
    content_qualifier: &str,
) -> Result<Option<PreparedUnitFq>> {
    let Some(persisted) = persisted_unit_fq(adapter, unit, content_qualifier) else {
        return Ok(None);
    };
    let interner = segment_interner();
    let exact_tail = persisted.tail.display_native(adapter.language(), interner);
    let normalized_fq = adapter.normalize_fq_name(&persisted.tail);
    let normalized_text = normalized_fq.display_native(adapter.language(), interner);
    let normalized_tail = (normalized_text != exact_tail).then_some(normalized_text);
    let exact_parent_tail = persisted
        .tail
        .parent()
        .expect("a persisted unit identity has at least one segment")
        .display_native(adapter.language(), interner);
    let normalized_parent_text = normalized_fq
        .parent()
        .expect("a normalized unit identity has at least one segment")
        .display_native(adapter.language(), interner);
    let normalized_parent_tail =
        (normalized_parent_text != exact_parent_tail).then_some(normalized_parent_text);
    let package_tail = persisted
        .tail
        .prefix(persisted.package_tail_segments)
        .display_native(adapter.language(), interner);
    let mut segments = Vec::with_capacity(persisted.tail.len());
    for (ordinal, &segment_id) in persisted.tail.segments().iter().enumerate() {
        let (text, kind) = interner.resolve(segment_id);
        segments.push((
            usize_to_i64(ordinal)?,
            segment_kind_sql(kind),
            text.to_string(),
        ));
    }
    let (anchor_kind, anchor_pop) = match persisted.anchor {
        None => (None, None),
        Some(PackageAnchor::OwnModule { pop }) => (Some("own_module"), Some(i64::from(pop))),
        Some(PackageAnchor::CrateRoot) => (Some("crate_root"), Some(0)),
    };
    Ok(Some(PreparedUnitFq {
        anchor_kind,
        anchor_pop,
        package_tail_segments: usize_to_i64(persisted.package_tail_segments)?,
        exact_tail,
        normalized_tail,
        exact_parent_tail,
        normalized_parent_tail,
        package_tail,
        segments,
    }))
}

/// One complete relational identity loaded from `code_unit_fq_segments`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalUnitFq {
    anchor: Option<PackageAnchor>,
    package_tail_segments: usize,
    expected_segment_count: usize,
    expected_segment_bytes: usize,
    #[doc(hidden)]
    pub segments: Vec<(SegmentKind, String)>,
}

impl RelationalUnitFq {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(
        anchor: Option<PackageAnchor>,
        package_tail_segments: usize,
        expected_segment_count: usize,
        expected_segment_bytes: usize,
        segments: Vec<(SegmentKind, String)>,
    ) -> Self {
        Self {
            anchor,
            package_tail_segments,
            expected_segment_count,
            expected_segment_bytes,
            segments,
        }
    }
}

impl RelationalUnitFq {
    fn from_header(header: FqIdentityHeader) -> Self {
        let FqIdentityHeader {
            anchor,
            package_tail_segments,
            expected_segment_count,
            expected_segment_bytes,
            exact_tail: _,
            normalized_tail: _,
        } = header;
        Self {
            anchor,
            package_tail_segments,
            expected_segment_count,
            expected_segment_bytes,
            segments: Vec::with_capacity(expected_segment_count),
        }
    }
}

/// Hydrate the structured identity and its package boundary from authoritative
/// relational segments. There is no binary or rendered-name fallback.
#[doc(hidden)]
pub fn hydrate_unit_fq<A: StoreLanguageAdapter>(
    adapter: &A,
    persisted: Option<&RelationalUnitFq>,
    content_qualifier: &str,
    file: &ProjectFile,
) -> Result<(FqName, usize)> {
    let prefix = persisted
        .and_then(|identity| identity.anchor)
        .map(|anchor| adapter.hydrate_package_anchor(anchor, content_qualifier, file))
        .transpose()?
        .flatten();
    hydrate_unit_fq_with_anchor(persisted, content_qualifier, file, |_, _, _| prefix)
}

#[doc(hidden)]
pub fn hydrate_mounted_candidate<A: StoreLanguageAdapter>(
    adapter: &A,
    project_root: &Path,
    row: HydratedCandidateRow,
    rel_path: String,
) -> Result<CodeUnit> {
    let file = ProjectFile::new(project_root.to_path_buf(), rel_path);
    let (fq, package_segment_count) =
        hydrate_unit_fq(adapter, row.fq.as_ref(), &row.content_qualifier, &file)?;
    Ok(CodeUnit::from_fq(
        file,
        row.kind,
        fq,
        package_segment_count,
        row.signature,
        row.flags.synthetic,
    ))
}

/// Assemble a stored identity using the caller's selected package authority.
pub(crate) fn hydrate_unit_fq_with_anchor(
    persisted: Option<&RelationalUnitFq>,
    content_qualifier: &str,
    file: &ProjectFile,
    resolve_anchor: impl FnOnce(PackageAnchor, &str, &ProjectFile) -> Option<FqName>,
) -> Result<(FqName, usize)> {
    let interner = segment_interner();
    let persisted = persisted
        .ok_or_else(|| StoreError::new("analyzer store row is missing its structured FqName"))?;
    if persisted.segments.len() != persisted.expected_segment_count {
        return Err(StoreError::new(format!(
            "analyzer store FqName expected {} segments but loaded {}",
            persisted.expected_segment_count,
            persisted.segments.len()
        )));
    }
    let mut stored_fq = FqName::new();
    for (kind, segment) in &persisted.segments {
        stored_fq.push(interner.intern(segment, *kind));
    }
    let Some(anchor) = persisted.anchor else {
        if persisted.package_tail_segments >= stored_fq.len() {
            return Err(StoreError::new(
                "analyzer store FqName package boundary leaves no declaration tail",
            ));
        }
        return Ok((stored_fq, persisted.package_tail_segments));
    };
    let mut prefix = resolve_anchor(anchor, content_qualifier, file).ok_or_else(|| {
        StoreError::new("analyzer adapter did not provide the persisted anchored package prefix")
    })?;
    let package_segment_count = prefix.len() + persisted.package_tail_segments;
    prefix.extend_from(&stored_fq);
    if package_segment_count >= prefix.len() {
        return Err(StoreError::new(
            "analyzer store FqName package boundary leaves no declaration tail",
        ));
    }
    Ok((prefix, package_segment_count))
}

/// Every non-key column of `unit_signature_metadata`, in the one order the
/// writer binds and every reader decodes.
///
/// All positional readers and both writers share this order. That is what
/// makes positional decoding safe among them: a column added to the schema is
/// added to this list once, and the encoder and decoder beside it are the only
/// two places that have to agree about what index it lands on.
const SIGNATURE_METADATA_VALUE_COLUMNS: [&str; 38] = [
    "label",
    "parameters",
    "return_type_text",
    "return_type_identity",
    "underlying_type_identity",
    "declaration_only",
    "callable_arity_required",
    "callable_arity_total",
    "callable_arity_repeated",
    "type_parameters",
    "bare_return_type_parameter",
    "callable_linkage",
    "dispatch_extensibility",
    "extension_receiver_type",
    "extension_receiver_type_identity",
    "extension_receiver_is_unconstrained",
    "field_is_static",
    "field_is_final",
    "field_has_initializer",
    "cpp_field_linkage",
    "companion_object",
    "callable_is_static",
    "callable_is_constructor",
    "callable_declared_visibility",
    "callable_modifiers_recorded",
    "callable_parameter_types",
    "callable_is_native",
    "class_like_is_interface",
    "class_like_is_static",
    "java_constructor_shape",
    "java_constructor_arity_required",
    "java_constructor_arity_total",
    "java_constructor_arity_repeated",
    "class_like_kind",
    "type_parameters_recorded",
    "result_type_identities",
    "parameter_type_identities",
    "callable_override_modifier",
];

/// The variable-length subset of the columns above.
///
/// Their stored byte lengths are the row's payload cost and the read-side
/// materialization budget. The flags, the arity integers, and the short enum
/// spellings are bounded by their own CHECK constraints and are not worth
/// summing. The Rust accounting in [`SignatureMetadataColumns::stored_text_bytes`]
/// must sum exactly this set, because a test compares it against the SQL sum.
const SIGNATURE_METADATA_TEXT_COLUMNS: [&str; 12] = [
    "label",
    "parameters",
    "return_type_text",
    "return_type_identity",
    "underlying_type_identity",
    "type_parameters",
    "bare_return_type_parameter",
    "extension_receiver_type",
    "extension_receiver_type_identity",
    "callable_parameter_types",
    "result_type_identities",
    "parameter_type_identities",
];

/// The value columns as a SELECT list, each qualified by `qualifier`, which is
/// the table's name or its alias in the query being built.
fn signature_metadata_value_columns_sql(qualifier: &str) -> String {
    SIGNATURE_METADATA_VALUE_COLUMNS
        .iter()
        .map(|column| format!("{qualifier}.{column}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The logical metadata values retain the codec's column order and append an
/// availability witness. A missing canonical property is not nullable metadata.
fn signature_metadata_projection_columns_sql(qualifier: &str) -> String {
    format!(
        "{}, {qualifier}.metadata_available",
        signature_metadata_value_columns_sql(qualifier)
    )
}

fn require_declaration_visibility_available(
    conn: &Connection,
    oid: &str,
    lang: &str,
) -> Result<()> {
    let available = conn
        .prepare_cached(
            "SELECT available FROM source_fact_readiness
             WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
        )?
        .query_row(params![oid, lang], |row| row.get::<_, bool>(0))
        .optional()?;
    if available == Some(false) {
        return Err(StoreError::new(format!(
            "canonical declaration visibility is unavailable for {oid}/{lang}"
        )));
    }
    Ok(())
}

fn signature_metadata_projection_from_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<SignatureMetadata> {
    if row.get::<_, Option<bool>>(base + SIGNATURE_METADATA_VALUE_COLUMNS.len())? != Some(true) {
        return Err(rusqlite_error_from_store(StoreError::new(
            "canonical declaration visibility metadata is unavailable",
        )));
    }
    signature_metadata_from_row(row, base)
}

/// A SQL expression for one row's stored text bytes.
///
/// `length()` on a TEXT value counts characters, so every term casts to BLOB
/// first: the budget is bytes.
fn signature_metadata_row_bytes_sql(qualifier: &str) -> String {
    SIGNATURE_METADATA_TEXT_COLUMNS
        .iter()
        .map(|column| format!("COALESCE(length(CAST({qualifier}.{column} AS BLOB)), 0)"))
        .collect::<Vec<_>>()
        .join(" + ")
}

/// A plain INSERT, unlike every sibling side table, which uses
/// `INSERT OR IGNORE`.
///
/// This is the only side table whose columns carry CHECK constraints that can
/// reject a well-keyed row, and `OR IGNORE` suppresses a CHECK failure exactly
/// as it suppresses a duplicate key: the row is skipped and the statement
/// succeeds. That would turn the schema's size cap back into the silent
/// data-loss it was written to replace. The blob's own row is deleted before
/// any of this runs, and its cascade empties this table for the blob, so a
/// duplicate key here is impossible and there is nothing left for `OR IGNORE`
/// to do but hide a real failure.
fn signature_metadata_insert_sql() -> &'static str {
    static SQL: LazyLock<String> = LazyLock::new(|| {
        let columns = SIGNATURE_METADATA_VALUE_COLUMNS.join(", ");
        let placeholders = (0..SIGNATURE_METADATA_VALUE_COLUMNS.len())
            .map(|index| format!("?{}", index + 5))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "INSERT INTO unit_signature_metadata(
           blob_id, lang, unit_key, ordinal, {columns}
         ) VALUES(?1, ?2, ?3, ?4, {placeholders})"
        )
    });
    SQL.as_str()
}

/// One `unit_signature_metadata` row's non-key columns, already converted to
/// the SQL types they bind as.
///
/// The prepared-write path builds these outside the write transaction so it can
/// charge a blob's payload cost before it takes the lock; the direct write path
/// builds them per row. Neither checks the size caps: the schema does, and a
/// row that violates one fails its INSERT and rolls the whole blob back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct SignatureMetadataColumns {
    label: String,
    parameters: String,
    #[doc(hidden)]
    pub parameter_count: usize,
    parameter_payload_bytes: usize,
    return_type_text: Option<String>,
    return_type_identity: Option<String>,
    underlying_type_identity: Option<String>,
    declaration_only: i64,
    callable_arity_required: Option<i64>,
    callable_arity_total: Option<i64>,
    callable_arity_repeated: Option<i64>,
    type_parameters: String,
    bare_return_type_parameter: Option<String>,
    callable_linkage: Option<&'static str>,
    dispatch_extensibility: Option<&'static str>,
    extension_receiver_type: Option<String>,
    extension_receiver_type_identity: Option<String>,
    extension_receiver_is_unconstrained: i64,
    field_is_static: i64,
    field_is_final: i64,
    field_has_initializer: i64,
    cpp_field_linkage: Option<&'static str>,
    companion_object: i64,
    callable_is_static: i64,
    callable_is_constructor: i64,
    #[doc(hidden)]
    pub callable_declared_visibility: Option<&'static str>,
    callable_modifiers_recorded: i64,
    callable_parameter_types: Option<String>,
    callable_is_native: i64,
    class_like_is_interface: i64,
    class_like_is_static: i64,
    java_constructor_shape: Option<i64>,
    java_constructor_arity_required: Option<i64>,
    java_constructor_arity_total: Option<i64>,
    java_constructor_arity_repeated: Option<i64>,
    class_like_kind: Option<&'static str>,
    type_parameters_recorded: i64,
    result_type_identities: String,
    parameter_type_identities: String,
    callable_override_modifier: Option<&'static str>,
}

impl SignatureMetadataColumns {
    #[doc(hidden)]
    pub fn encode(value: &SignatureMetadata) -> Result<Self> {
        use brokk_bifrost_core::analyzer::model::JavaTypeConstructorShape;
        let arity = value.callable_arity();
        let (constructor_shape, constructor_arity) = match value.java_type_constructor_shape() {
            None => (None, None),
            Some(JavaTypeConstructorShape::NoImplicit) => (Some(0), None),
            Some(JavaTypeConstructorShape::Default) => (Some(1), None),
            Some(JavaTypeConstructorShape::RecordCanonical(arity)) => (Some(2), Some(arity)),
        };
        let (label, parameters) = bounded_signature_label(value.label(), value.parameters());
        Ok(Self {
            label: label.into_owned(),
            parameters: encode_signature_metadata_json("parameters", parameters.as_ref())?,
            parameter_count: parameters.len(),
            parameter_payload_bytes: saturating_sum(parameters.iter().map(|parameter| {
                parameter
                    .label()
                    .len()
                    .saturating_add(parameter.name().map_or(0, str::len))
            })),
            return_type_text: value.return_type_text().map(str::to_string),
            return_type_identity: value
                .return_type_identity()
                .map(|identity| encode_signature_metadata_json("return_type_identity", identity))
                .transpose()?,
            underlying_type_identity: value
                .underlying_type_identity()
                .map(|identity| {
                    encode_signature_metadata_json("underlying_type_identity", identity)
                })
                .transpose()?,
            declaration_only: bool_to_i64(value.is_declaration_only()),
            callable_arity_required: arity
                .map(|arity| usize_to_i64(arity.required()))
                .transpose()?,
            callable_arity_total: arity.map(|arity| usize_to_i64(arity.total())).transpose()?,
            callable_arity_repeated: arity.map(|arity| bool_to_i64(arity.is_repeated())),
            type_parameters: encode_signature_metadata_json(
                "type_parameters",
                value.type_parameters(),
            )?,
            bare_return_type_parameter: value.bare_return_type_parameter().map(str::to_string),
            callable_linkage: value.callable_linkage().map(CallableLinkage::label),
            dispatch_extensibility: value
                .dispatch_extensibility()
                .map(DispatchExtensibility::label),
            extension_receiver_type: value.extension_receiver_type().map(str::to_string),
            extension_receiver_type_identity: value
                .extension_receiver_type_identity()
                .map(|identity| {
                    encode_signature_metadata_json("extension_receiver_type_identity", identity)
                })
                .transpose()?,
            extension_receiver_is_unconstrained: bool_to_i64(
                value.extension_receiver_is_unconstrained_type_parameter(),
            ),
            field_is_static: bool_to_i64(value.field_is_static()),
            field_is_final: bool_to_i64(value.field_is_final()),
            field_has_initializer: bool_to_i64(value.field_has_initializer()),
            cpp_field_linkage: value.cpp_field_linkage().map(CppFieldLinkage::label),
            companion_object: bool_to_i64(value.is_companion_object()),
            callable_is_static: bool_to_i64(value.callable_is_static()),
            callable_is_constructor: bool_to_i64(value.callable_is_constructor()),
            callable_declared_visibility: value
                .callable_declared_visibility()
                .map(DeclaredVisibility::label),
            callable_modifiers_recorded: bool_to_i64(value.callable_modifiers_recorded()),
            callable_parameter_types: value
                .callable_parameter_types()
                .map(|types| encode_signature_metadata_json("callable_parameter_types", types))
                .transpose()?,
            callable_is_native: bool_to_i64(value.callable_is_native()),
            class_like_is_interface: bool_to_i64(
                value.class_like_kind().is_none() && value.class_like_is_interface(),
            ),
            class_like_kind: value
                .class_like_kind()
                .map(brokk_bifrost_core::analyzer::model::ClassLikeKind::label),
            class_like_is_static: bool_to_i64(value.class_like_is_static()),
            java_constructor_shape: constructor_shape,
            java_constructor_arity_required: constructor_arity
                .map(|arity| usize_to_i64(arity.required()))
                .transpose()?,
            java_constructor_arity_total: constructor_arity
                .map(|arity| usize_to_i64(arity.total()))
                .transpose()?,
            java_constructor_arity_repeated: constructor_arity
                .map(|arity| bool_to_i64(arity.is_repeated())),
            type_parameters_recorded: bool_to_i64(value.type_parameters_recorded()),
            result_type_identities: encode_signature_metadata_json(
                "result_type_identities",
                value.result_type_identities(),
            )?,
            parameter_type_identities: encode_signature_metadata_json(
                "parameter_type_identities",
                value.parameter_type_identities(),
            )?,
            callable_override_modifier: value
                .callable_override_modifier()
                .map(CallableOverrideModifier::label),
        })
    }

    /// Physical text payload of this metadata row and its parameter children.
    /// The write transport is discarded; the metadata parameter cell retains [].
    #[doc(hidden)]
    pub fn stored_text_bytes(&self) -> usize {
        saturating_sum([
            self.label.len(),
            2usize.saturating_add(self.parameter_payload_bytes),
            self.return_type_text.as_ref().map_or(0, String::len),
            self.return_type_identity.as_ref().map_or(0, String::len),
            self.underlying_type_identity
                .as_ref()
                .map_or(0, String::len),
            self.type_parameters.len(),
            self.bare_return_type_parameter
                .as_ref()
                .map_or(0, String::len),
            self.extension_receiver_type.as_ref().map_or(0, String::len),
            self.extension_receiver_type_identity
                .as_ref()
                .map_or(0, String::len),
            self.callable_parameter_types
                .as_ref()
                .map_or(0, String::len),
            self.result_type_identities.len(),
            self.parameter_type_identities.len(),
        ])
    }

    #[doc(hidden)]
    pub fn insert(
        &self,
        stmt: &mut rusqlite::Statement<'_>,
        blob_id: i64,
        lang: &str,
        unit_key: i64,
        ordinal: i64,
    ) -> Result<()> {
        let row = self.bound_row(blob_id, lang, unit_key, ordinal);
        let mut values = Vec::with_capacity(4 + SIGNATURE_METADATA_VALUE_COLUMNS.len());
        row_batch::RowBindings::append_values(&row, &mut values);
        stmt.execute(rusqlite::params_from_iter(values))?;
        Ok(())
    }

    fn bound_row<'a>(
        &'a self,
        blob_id: i64,
        lang: &'a str,
        unit_key: i64,
        ordinal: i64,
    ) -> impl row_batch::RowBindings + 'a {
        (
            blob_id,
            lang,
            unit_key,
            ordinal,
            &self.label,
            &self.parameters,
            &self.return_type_text,
            &self.return_type_identity,
            &self.underlying_type_identity,
            &self.declaration_only,
            &self.callable_arity_required,
            &self.callable_arity_total,
            &self.callable_arity_repeated,
            &self.type_parameters,
            &self.bare_return_type_parameter,
            &self.callable_linkage,
            &self.dispatch_extensibility,
            &self.extension_receiver_type,
            &self.extension_receiver_type_identity,
            &self.extension_receiver_is_unconstrained,
            &self.field_is_static,
            &self.field_is_final,
            &self.field_has_initializer,
            &self.cpp_field_linkage,
            &self.companion_object,
            &self.callable_is_static,
            &self.callable_is_constructor,
            &self.callable_declared_visibility,
            &self.callable_modifiers_recorded,
            &self.callable_parameter_types,
            &self.callable_is_native,
            &self.class_like_is_interface,
            &self.class_like_is_static,
            &self.java_constructor_shape,
            &self.java_constructor_arity_required,
            &self.java_constructor_arity_total,
            &self.java_constructor_arity_repeated,
            &self.class_like_kind,
            &self.type_parameters_recorded,
            &self.result_type_identities,
            &self.parameter_type_identities,
            &self.callable_override_modifier,
        )
    }
}

/// The marker an elided label carries in place of the text it lost.
///
/// It is inside the stored value on purpose: a reader that sees a label needs
/// no side channel to learn that the rendering is partial.
#[doc(hidden)]
pub const SIGNATURE_LABEL_ELISION: &str = " /* label elided */";

/// A declaration label and its parameter spans, clamped to the label column's
/// byte cap.
///
/// Every language adapter renders a label from the declaration's source text,
/// so a generated source with a megabyte-scale initializer can hand the store
/// a label larger than the schema allows. That row fails its CHECK, and
/// because the CHECK is the write-time admission gate the failure takes the
/// file's whole parsed blob with it -- which is right for a row nobody can
/// bound, and much too expensive for a rendering that can simply be shorter.
/// One pathological declaration must not cost a repository its index
/// (issue #2351).
///
/// The cap itself is unchanged and stays the interface. `label` is the only
/// column clamped here because it is the only one built by copying an
/// arbitrarily large declaration body; the type spellings beside it are
/// bounded by the type grammar, and a megabyte-scale one is an analyzer defect
/// that must stay loud.
///
/// [`ParameterMetadata`] spans are byte offsets *into* the label, so a clamped
/// label keeps only the parameters that still lie inside what it retained. A
/// span pointing past the end of the value it indexes is worse than a missing
/// one.
fn bounded_signature_label<'a>(
    label: &'a str,
    parameters: &'a [ParameterMetadata],
) -> (Cow<'a, str>, Cow<'a, [ParameterMetadata]>) {
    if label.len() <= MAX_SIGNATURE_METADATA_COLUMN_BYTES {
        return (Cow::Borrowed(label), Cow::Borrowed(parameters));
    }
    let mut end = MAX_SIGNATURE_METADATA_COLUMN_BYTES - SIGNATURE_LABEL_ELISION.len();
    while end > 0 && !label.is_char_boundary(end) {
        end -= 1;
    }
    let retained = parameters
        .iter()
        .filter(|parameter| parameter.end_byte() <= end)
        .cloned()
        .collect();
    (
        Cow::Owned(format!("{}{SIGNATURE_LABEL_ELISION}", &label[..end])),
        Cow::Owned(retained),
    )
}

fn encode_signature_metadata_json<T: serde::Serialize + ?Sized>(
    column: &str,
    value: &T,
) -> Result<String> {
    serde_json::to_string(value).map_err(|err| {
        StoreError::new(format!(
            "analyzer store cannot encode signature metadata column {column}: {err}"
        ))
    })
}

fn decode_signature_metadata_json<T: serde::de::DeserializeOwned>(
    column: &str,
    text: &str,
) -> rusqlite::Result<T> {
    serde_json::from_str(text).map_err(|err| {
        rusqlite_error_from_store(StoreError::new(format!(
            "analyzer store cannot decode signature metadata column {column}: {err}"
        )))
    })
}

fn signature_metadata_enum_from_label<T>(
    column: &str,
    label: Option<String>,
    parse: impl Fn(&str) -> Option<T>,
) -> rusqlite::Result<Option<T>> {
    label
        .map(|label| {
            parse(&label).ok_or_else(|| {
                rusqlite_error_from_store(StoreError::new(format!(
                    "analyzer store signature metadata column {column} holds unknown value {label}"
                )))
            })
        })
        .transpose()
}

/// Rebuild one [`SignatureMetadata`] from a row whose
/// [`SIGNATURE_METADATA_VALUE_COLUMNS`] start at index `base`.
fn signature_metadata_from_row(
    row: &rusqlite::Row<'_>,
    base: usize,
) -> rusqlite::Result<SignatureMetadata> {
    use brokk_bifrost_core::analyzer::model::JavaTypeConstructorShape;
    let flag =
        |index: usize| -> rusqlite::Result<bool> { Ok(row.get::<_, i64>(base + index)? != 0) };
    let parameters: Vec<ParameterMetadata> =
        decode_signature_metadata_json("parameters", &row.get::<_, String>(base + 1)?)?;
    let mut metadata = SignatureMetadata::new(row.get::<_, String>(base)?, parameters)
        .with_return_type_text(row.get::<_, Option<String>>(base + 2)?)
        .with_return_type_identity(signature_metadata_identity_from_row(
            row,
            base + 3,
            "return_type_identity",
        )?)
        .with_underlying_type_identity(signature_metadata_identity_from_row(
            row,
            base + 4,
            "underlying_type_identity",
        )?)
        .with_declaration_only(flag(5)?)
        .with_persisted_type_parameters(
            decode_signature_metadata_json("type_parameters", &row.get::<_, String>(base + 9)?)?,
            flag(34)?,
        )
        .with_bare_return_type_parameter(row.get::<_, Option<String>>(base + 10)?)
        .with_extension_receiver_type(row.get::<_, Option<String>>(base + 13)?)
        .with_extension_receiver_type_identity(signature_metadata_identity_from_row(
            row,
            base + 14,
            "extension_receiver_type_identity",
        )?)
        .with_extension_receiver_is_unconstrained_type_parameter(flag(15)?)
        .with_field_modifiers(flag(16)?, flag(17)?)
        .with_field_initializer(flag(18)?)
        .with_companion_object(flag(20)?)
        .with_persisted_callable_modifiers(
            flag(21)?,
            flag(22)?,
            signature_metadata_enum_from_label(
                "callable_declared_visibility",
                row.get::<_, Option<String>>(base + 23)?,
                DeclaredVisibility::from_label,
            )?,
            flag(24)?,
        )
        .with_callable_native(flag(26)?)
        .with_class_like_interface(flag(27)?)
        .with_class_like_static(flag(28)?);
    if let Some(arity) = signature_metadata_arity_from_row(row, base + 6)? {
        metadata = metadata.with_callable_arity(arity);
    }
    if let Some(kind) = signature_metadata_enum_from_label(
        "class_like_kind",
        row.get::<_, Option<String>>(base + 33)?,
        brokk_bifrost_core::analyzer::model::ClassLikeKind::from_label,
    )? {
        metadata = metadata.with_class_like_kind(kind);
    }
    let constructor_kind = row.get::<_, Option<i64>>(base + 29)?;
    let constructor_arity = signature_metadata_arity_from_row(row, base + 30)?;
    let constructor_shape = match (constructor_kind, constructor_arity) {
        (None, None) => None,
        (Some(0), None) => Some(JavaTypeConstructorShape::NoImplicit),
        (Some(1), None) => Some(JavaTypeConstructorShape::Default),
        (Some(2), Some(arity)) => Some(JavaTypeConstructorShape::RecordCanonical(arity)),
        _ => {
            return Err(rusqlite_error_from_store(StoreError::new(
                "invalid persisted Java type constructor shape",
            )));
        }
    };
    if let Some(shape) = constructor_shape {
        metadata = metadata.with_java_type_constructor_shape(shape);
    }
    if let Some(linkage) = signature_metadata_enum_from_label(
        "callable_linkage",
        row.get::<_, Option<String>>(base + 11)?,
        CallableLinkage::from_label,
    )? {
        metadata = metadata.with_callable_linkage(linkage);
    }
    if let Some(extensibility) = signature_metadata_enum_from_label(
        "dispatch_extensibility",
        row.get::<_, Option<String>>(base + 12)?,
        DispatchExtensibility::from_label,
    )? {
        metadata = metadata.with_dispatch_extensibility(extensibility);
    }
    if let Some(linkage) = signature_metadata_enum_from_label(
        "cpp_field_linkage",
        row.get::<_, Option<String>>(base + 19)?,
        CppFieldLinkage::from_label,
    )? {
        metadata = metadata.with_cpp_field_linkage(linkage);
    }
    if let Some(types) = row.get::<_, Option<String>>(base + 25)? {
        metadata = metadata.with_callable_parameter_types(decode_signature_metadata_json(
            "callable_parameter_types",
            &types,
        )?);
    }
    metadata = metadata.with_result_type_identities(decode_signature_metadata_json(
        "result_type_identities",
        &row.get::<_, String>(base + 35)?,
    )?);
    metadata = metadata.with_parameter_type_identities(decode_signature_metadata_json(
        "parameter_type_identities",
        &row.get::<_, String>(base + 36)?,
    )?);
    metadata =
        metadata.with_persisted_callable_override_modifier(signature_metadata_enum_from_label(
            "callable_override_modifier",
            row.get::<_, Option<String>>(base + 37)?,
            CallableOverrideModifier::from_label,
        )?);
    Ok(metadata)
}

fn signature_metadata_identity_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
    column: &str,
) -> rusqlite::Result<Option<StructuredTypeIdentity>> {
    row.get::<_, Option<String>>(index)?
        .map(|text| decode_signature_metadata_json(column, &text))
        .transpose()
}

/// The arity trio starting at `index`. The schema keeps the three columns all
/// present or all absent, so a half-present triple is a corrupted store rather
/// than a case to interpret.
fn signature_metadata_arity_from_row(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<CallableArity>> {
    let values = (
        row.get::<_, Option<i64>>(index)?,
        row.get::<_, Option<i64>>(index + 1)?,
        row.get::<_, Option<i64>>(index + 2)?,
    );
    let (required, total, repeated) = match values {
        (None, None, None) => return Ok(None),
        (Some(required), Some(total), Some(repeated))
            if required >= 0 && total >= required && matches!(repeated, 0 | 1) =>
        {
            (required, total, repeated)
        }
        _ => {
            return Err(rusqlite_error_from_store(StoreError::new(
                "invalid persisted callable arity fields",
            )));
        }
    };
    Ok(Some(CallableArity::new(
        i64_to_usize(required).map_err(rusqlite_error_from_store)?,
        i64_to_usize(total).map_err(rusqlite_error_from_store)?,
        repeated != 0,
    )))
}

fn deserialize_blob<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes)
        .map_err(|err| StoreError::new(format!("analyzer store deserialization error: {err}")))
}

#[doc(hidden)]
pub fn bool_to_i64(value: bool) -> i64 {
    i64::from(value)
}

/// One `source_structural_facts.nodes` element. Positions follow the current
/// structural-facts version; the node id is the array index.
#[derive(serde::Deserialize)]
struct StructuralNodeJson(
    u8,
    Option<u8>,
    Option<String>,
    u32,
    u32,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    u32,
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<AssignmentShape>,
    Option<crate::analyzer::structural::facts::IntegerLiteralValue>,
    Option<bool>,
    Option<String>,
    Option<u8>,
    Option<u8>,
    Option<u8>,
    Option<u32>,
    Option<u8>,
    Option<Vec<String>>,
    Option<bool>,
    Option<Vec<String>>,
    Option<String>,
);

/// One `source_structural_facts.roles` element, ordered by source node.
#[derive(serde::Deserialize)]
struct StructuralRoleJson(
    u32,
    u8,
    u8,
    Option<u32>,
    u32,
    u32,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
);

fn persisted_json_span(
    start: Option<u32>,
    end: Option<u32>,
) -> std::result::Result<Option<PersistedSpan>, serde_json::Error> {
    match (start, end) {
        (None, None) => Ok(None),
        (Some(start), Some(end)) => Ok(Some(PersistedSpan { start, end })),
        _ => Err(serde::de::Error::custom(
            "incomplete persisted structural span fields",
        )),
    }
}

fn decode_structural_nodes(
    json: &str,
) -> std::result::Result<Vec<PersistedStructuralNode>, serde_json::Error> {
    use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;
    let rows: Vec<StructuralNodeJson> = serde_json::from_str(json)?;
    rows.into_iter()
        .enumerate()
        .map(|(index, row)| {
            let StructuralNodeJson(
                kind,
                boolean_value,
                construct,
                start,
                end,
                name_start,
                name_end,
                parent,
                subtree_end,
                call_kind,
                call_coverage,
                continues,
                parenthesized,
                assignment_shape,
                integer_literal_value,
                duplicate_key,
                string_value,
                is_async,
                provenance,
                supplier_kind,
                supplier_ordinal,
                type_shape,
                bounds,
                unsafe_context,
                declaration_modifiers,
                declaration_type_kind,
            ) = row;
            let declaration_attributes = match (declaration_modifiers, declaration_type_kind) {
                (None, None) => None,
                (Some(modifiers), type_kind) => Some(
                    brokk_bifrost_core::analyzer::structural::facts::DeclarationAttributes {
                        modifiers,
                        type_kind,
                    },
                ),
                (None, Some(_)) => {
                    return Err(serde::de::Error::custom(
                        "declaration type kind without modifier attributes",
                    ));
                }
            };
            use brokk_bifrost_core::analyzer::structural::callable::{
                CalleeProvenance, CalleeProvenanceFact, CalleeSupplier, CalleeTypeShape,
            };
            let callee_provenance = match (
                provenance,
                supplier_kind,
                supplier_ordinal,
                type_shape,
                bounds,
            ) {
                (None, None, None, None, None) => None,
                (Some(provenance), supplier_kind, ordinal, Some(shape), Some(bounds)) => {
                    let supplier = match (supplier_kind, ordinal) {
                        (None, None) => None,
                        (Some(kind), ordinal) => {
                            Some(CalleeSupplier::from_parts(kind, ordinal).ok_or_else(|| {
                                <serde_json::Error as serde::de::Error>::custom(
                                    "invalid callee supplier",
                                )
                            })?)
                        }
                        _ => {
                            return Err(serde::de::Error::custom(
                                "callee supplier ordinal without kind",
                            ));
                        }
                    };
                    Some(CalleeProvenanceFact {
                        provenance: CalleeProvenance::from_code(provenance).ok_or_else(|| {
                            <serde_json::Error as serde::de::Error>::custom(
                                "invalid callee provenance",
                            )
                        })?,
                        supplier,
                        shape: CalleeTypeShape::from_code(shape).ok_or_else(|| {
                            <serde_json::Error as serde::de::Error>::custom(
                                "invalid callee type shape",
                            )
                        })?,
                        bounds,
                    })
                }
                _ => return Err(serde::de::Error::custom("incomplete callee provenance")),
            };
            let call_site = match (call_kind, call_coverage, continues) {
                (None, None, None) => None,
                (call_kind, Some(coverage), Some(continues)) => Some(PersistedCallSite {
                    call_kind,
                    coverage,
                    continues_callee_groups: continues != 0,
                    callee_provenance,
                }),
                _ => {
                    return Err(serde::de::Error::custom(
                        "incomplete persisted structural call-site fields",
                    ));
                }
            };
            Ok(PersistedStructuralNode {
                node_id: u32::try_from(index).expect("structural node ids must fit in u32"),
                kind,
                boolean_value: boolean_value.map(|value| value != 0),
                parenthesized: parenthesized.map(|value| value != 0),
                assignment_shape,
                integer_literal_value,
                duplicate_key,
                string_value,
                is_async: is_async.map(|value| value != 0),
                unsafe_context,
                declaration_attributes,
                construct,
                span: PersistedSpan { start, end },
                parent,
                name: persisted_json_span(name_start, name_end)?,
                subtree_end,
                call_site,
            })
        })
        .collect()
}

fn next_consecutive_ordinal<K: Copy + Eq>(
    previous_key: &mut Option<K>,
    ordinal: &mut u32,
    key: K,
) -> u32 {
    *ordinal = if *previous_key == Some(key) {
        *ordinal + 1
    } else {
        0
    };
    *previous_key = Some(key);
    *ordinal
}

fn decode_structural_roles(
    json: &str,
) -> std::result::Result<Vec<PersistedStructuralRole>, serde_json::Error> {
    let rows: Vec<StructuralRoleJson> = serde_json::from_str(json)?;
    let mut previous_node = None;
    let mut ordinal = 0u32;
    rows.into_iter()
        .map(|row| {
            let StructuralRoleJson(
                source_node_id,
                role,
                spread,
                node,
                start,
                end,
                name_start,
                name_end,
                keyword_start,
                keyword_end,
            ) = row;
            let ordinal =
                next_consecutive_ordinal(&mut previous_node, &mut ordinal, source_node_id);
            Ok(PersistedStructuralRole {
                source_node_id,
                ordinal,
                role,
                spread: spread != 0,
                keyword: persisted_json_span(keyword_start, keyword_end)?,
                node,
                span: PersistedSpan { start, end },
                name: persisted_json_span(name_start, name_end)?,
            })
        })
        .collect()
}

fn decode_structural_occurrence_roles(
    json: &str,
) -> std::result::Result<Vec<PersistedOccurrenceRole>, serde_json::Error> {
    let rows: Vec<(u32, u8)> = serde_json::from_str(json)?;
    let mut previous_node = None;
    let mut ordinal = 0u32;
    Ok(rows
        .into_iter()
        .map(|(node_id, role)| {
            let ordinal = next_consecutive_ordinal(&mut previous_node, &mut ordinal, node_id);
            PersistedOccurrenceRole {
                node_id,
                ordinal,
                role,
            }
        })
        .collect())
}

/// The one manifest row that admits a blob's persisted structural facts.
///
/// This is the only statement in the hydration path that joins and subqueries
/// rather than seeking one primary key, so it is the only one whose plan can
/// move with the store's statistics. It is written here once and pinned by
/// name from the registry in `store::planner_statistics`.
/// One blob's recovered regions in source order, each with whether a
/// callable fact's byte range contains it (#3777). `?2` is the JSON array of
/// callable kind codes from [`callable_kind_codes_json`]; node positions 0, 3
/// and 4 are the kind code and byte range documented in migration 0128.
pub(crate) const STRUCTURAL_RECOVERED_REGIONS_SQL: &str =
    "SELECT region.start_byte, region.end_byte,
        EXISTS(
          SELECT 1
          FROM source_structural_facts AS facts, json_each(facts.nodes) AS node
          WHERE facts.blob_id = region.blob_id
            AND node.value ->> 0 IN (SELECT value FROM json_each(?2))
            AND node.value ->> 3 <= region.start_byte
            AND region.end_byte <= node.value ->> 4
        ) AS inside_callable
 FROM source_structural_recovered_regions AS region
 WHERE region.blob_id = ?1
 ORDER BY region.ordinal";

/// The kind codes of every callable fact, as the JSON array
/// [`STRUCTURAL_RECOVERED_REGIONS_SQL`] binds.
pub(crate) fn callable_kind_codes_json() -> String {
    use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;
    let codes = crate::analyzer::structural::kinds::ALL_KINDS
        .iter()
        .filter(|kind| kind.satisfies(crate::analyzer::structural::kinds::NormalizedKind::Callable))
        .map(|kind| kind.code().to_string())
        .collect::<Vec<_>>();
    format!("[{}]", codes.join(","))
}

fn structural_fact_manifest_sql() -> String {
    format!(
        "SELECT facts.blob_id, facts.source_bytes, facts.node_count, facts.role_count,
                facts.occurrence_role_count
         FROM structural_source_manifests AS facts
         JOIN blob_meta AS meta
           ON meta.blob_id = facts.blob_id
         WHERE facts.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
           AND facts.facts_version = ?3
           AND {PARSED_BLOB_COMPLETE_CONDITION}"
    )
}

#[doc(hidden)]
pub fn usize_to_i64(value: usize) -> Result<i64> {
    sqlite_integer(value)
        .ok_or_else(|| StoreError::new(format!("value does not fit in SQLite INTEGER: {value}")))
}

fn sqlite_integer<T: TryInto<i64>>(value: T) -> Option<i64> {
    value.try_into().ok()
}

fn i64_to_usize(value: i64) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| StoreError::new(format!("negative or too-large SQLite INTEGER: {value}")))
}

fn rusqlite_error_from_store(err: StoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(err))
}

#[doc(hidden)]
pub fn code_unit_kind_to_i64(kind: CodeUnitType) -> i64 {
    match kind {
        CodeUnitType::Class => 0,
        CodeUnitType::Function => 1,
        CodeUnitType::Field => 2,
        CodeUnitType::Module => 3,
        CodeUnitType::Macro => 4,
        CodeUnitType::FileScope => 5,
    }
}

fn code_unit_kind_from_i64(value: i64) -> Result<CodeUnitType> {
    match value {
        0 => Ok(CodeUnitType::Class),
        1 => Ok(CodeUnitType::Function),
        2 => Ok(CodeUnitType::Field),
        3 => Ok(CodeUnitType::Module),
        4 => Ok(CodeUnitType::Macro),
        5 => Ok(CodeUnitType::FileScope),
        _ => Err(StoreError::new(format!("invalid code unit kind: {value}"))),
    }
}

#[doc(hidden)]
pub fn ruby_dispatch_mode_to_i64(mode: RubyMethodDispatchMode) -> i64 {
    match mode {
        RubyMethodDispatchMode::Instance => 0,
        RubyMethodDispatchMode::Singleton => 1,
        RubyMethodDispatchMode::ModuleFunction => 2,
    }
}

fn ruby_dispatch_mode_from_i64(value: i64) -> Result<RubyMethodDispatchMode> {
    match value {
        0 => Ok(RubyMethodDispatchMode::Instance),
        1 => Ok(RubyMethodDispatchMode::Singleton),
        2 => Ok(RubyMethodDispatchMode::ModuleFunction),
        other => Err(StoreError::new(format!(
            "unknown persisted Ruby dispatch mode {other}"
        ))),
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "resolution_producer_tests.rs"]
#[doc(hidden)]
pub mod resolution_producer_tests;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests {
    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "2532c07e7fa2: duplicate fragment comparison omitted semantic IR content"
    )]
    fn semantic_ir_only_conflicting_fragments_are_rejected() {
        use self::semantic_ir::SemanticIrMountScope;
        use crate::analyzer::semantic::{
            DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, EvidenceId,
            ProcedureId, ProcedureKind, ProcedureSemanticsParts, SemanticLocator, SemanticRole,
            SourceAnchor, SourceMappingId, SourcePosition, SourceSpan, WorkspaceMountId,
            WorkspaceRelativePath,
        };

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let oid = oid_for(b"semantic IR replacement");
        let state = Arc::new(FileState {
            source: Default::default(),
            package_name: Default::default(),
            content_qualifier: Default::default(),
            top_level_declarations: Default::default(),
            declarations: Default::default(),
            definition_lookup_units: Default::default(),
            imports: Default::default(),
            scala_exports: Default::default(),
            rust_usage_facts: Default::default(),
            resolution_facts: Default::default(),
            source_facts: Default::default(),
            source_declaration_units: Default::default(),
            source_declaration_metadata: Default::default(),
            raw_supertypes: Default::default(),
            supertype_lookup_paths: Default::default(),
            type_identifiers: Default::default(),
            signatures: Default::default(),
            signature_metadata: Default::default(),
            signature_metadata_signature_ordinals: Default::default(),
            cpp_template_metadata: Default::default(),
            ranges: Default::default(),
            children: Default::default(),
            type_aliases: Default::default(),
            ruby_method_dispatch_modes: Default::default(),
            scala_traits: Default::default(),
            contains_tests: Default::default(),
            test_region_units: Default::default(),
            materialization_records: Default::default(),
            parse_errors: Default::default(),
            additional_projections: Default::default(),
            parse_complete: true,
            completeness: crate::analyzer::ParseCompleteness::Complete,
        });
        let mount = WorkspaceMountId::from_root(&std::env::temp_dir());
        let content = ContentIdentity::from_digest(StableDigest::from_array([1; 32]));
        let make = |filename: &str| {
            // A neutral storage key avoids the Rust source producer, which
            // lives in a downstream crate. IR encoding is language-independent.
            let resolution = PreparedResolutionBundle::new(
                Language::Python,
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                &CancellationToken::default(),
            )
            .unwrap();
            // Rust's inventory includes the live filename in each declaration.
            // The encoder retains it even though the blob key is content-only.
            let anchor = SourceAnchor::new(
                SourceSpan::new(SourcePosition::new(0, 0, 0), SourcePosition::new(1, 0, 1))
                    .unwrap(),
                0,
            );
            let declaration = DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::File, filename, anchor, 0)
                    .unwrap(),
                DeclarationSegment::named(DeclarationSegmentKind::Function, "f", anchor, 0)
                    .unwrap(),
            ])
            .unwrap();
            let procedure = ProcedureSemanticsParts::new(
                ProcedureId::new(0),
                SemanticLocator::new(
                    mount,
                    WorkspaceRelativePath::new(filename).unwrap(),
                    Language::Rust.into(),
                    declaration,
                    SemanticRole::Procedure,
                    anchor,
                ),
                ProcedureKind::Function,
                SourceMappingId::new(0),
                EvidenceId::new(0),
            );
            let ir = PreparedSemanticIr::prepare(
                SemanticIrLoweringOutcome::Complete {
                    parts: vec![procedure],
                },
                None,
                "fragment-comparison-probe",
                content,
                0,
            );
            let logical_rows = resolution.logical_rows + ir.logical_rows();
            let payload_bytes = resolution.payload_bytes + ir.payload_bytes();
            PreparedParsedBlob {
                oid,
                oid_text: oid.to_string(),
                lang: "python".to_owned(),
                generation: GenerationId::BOOTSTRAP,
                state: Arc::clone(&state),
                resolution,
                semantic_ir: Some(ir),
                logical_rows,
                payload_bytes,
                mutation_logical_rows: logical_rows,
                mutation_payload_bytes: payload_bytes,
                units: Default::default(),
                source_declaration_units: Default::default(),
                source_declaration_metadata: Default::default(),
                declaration_visibility_version: Default::default(),
                java_type_constructor_version: Default::default(),
                go_source_version: Default::default(),
                java_source_version: Default::default(),
                scala_source_version: Default::default(),
                ruby_source_version: Default::default(),
                php_source_version: Default::default(),
                cpp_source_version: Default::default(),
                source_facts_version: Default::default(),
                source_storage: Default::default(),
                metadata_bridges_required: Default::default(),
                js_ts_source_version: Default::default(),
                python_source_version: Default::default(),
                ranges: Default::default(),
                signatures: Default::default(),
                signature_metadata: Default::default(),
                signature_metadata_signature_ordinals: Default::default(),
                cpp_templates: Default::default(),
                supertypes: Default::default(),
                children: Default::default(),
                imports: Default::default(),
                scala_exports: Default::default(),
                rust_facts: Default::default(),
                type_identifiers: Default::default(),
                ruby_dispatch_modes: Default::default(),
                scala_traits: Default::default(),
                materialization_records: Default::default(),
                contains_tests: Default::default(),
                content_package: Default::default(),
                additional: Default::default(),
            }
        };
        let first = make("a.rs");
        let later = make("b.rs");
        assert_eq!(first.logical_rows(), later.logical_rows());
        assert_eq!(first.payload_bytes(), later.payload_bytes());
        // Separate writes must replace the IR; they do not use fragment equality.
        for (fragment, expected) in [(first, "a.rs"), (later, "b.rs")] {
            let (outcomes, _) =
                store.persist_prepared_blobs(vec![fragment], PersistBatchTargets::PRODUCTION);
            assert!(
                outcomes.iter().all(|outcome| outcome.error.is_none()),
                "{outcomes:?}"
            );
            let publication = store
                .semantic_ir_publication(oid, "python")
                .unwrap()
                .unwrap();
            let parts = store
                .read_semantic_ir(
                    publication.blob_id,
                    &SemanticIrMountScope {
                        mount,
                        path: WorkspaceRelativePath::new(expected).unwrap(),
                        language: Language::Rust.into(),
                        content,
                    },
                )
                .unwrap();
            assert_eq!(
                parts[0].locator.declaration().segments()[0].name(),
                Some(expected)
            );
        }
        // Conflicting duplicates in one call must fail rather than silently
        // acknowledging both requests while persisting only the first IR.
        let (outcomes, _) = store.persist_prepared_blobs(
            vec![make("a.rs"), make("b.rs")],
            PersistBatchTargets::PRODUCTION,
        );
        let publication = store
            .semantic_ir_publication(oid, "python")
            .unwrap()
            .unwrap();
        let parts = store
            .read_semantic_ir(
                publication.blob_id,
                &SemanticIrMountScope {
                    mount,
                    path: WorkspaceRelativePath::new("b.rs").unwrap(),
                    language: Language::Rust.into(),
                    content,
                },
            )
            .unwrap();
        assert_eq!(
            (
                outcomes
                    .iter()
                    .filter(|outcome| outcome.error.is_some())
                    .count(),
                parts[0].locator.declaration().segments()[0].name(),
            ),
            (2, Some("b.rs")),
            "conflicting IR must be rejected, preserving the previous publication"
        );

        // Head-only publications must compare their outcome and detail too,
        // even when neither publication has child rows.
        let error_oid = oid_for(b"semantic IR error conflict");
        let errors = ["first", "other"].map(|detail| {
            let mut fragment = make("a.rs");
            let ir = PreparedSemanticIr::prepare(
                SemanticIrLoweringOutcome::Error(detail.to_owned()),
                None,
                "fragment-comparison-probe",
                content,
                0,
            );
            fragment.oid = error_oid;
            fragment.oid_text = error_oid.to_string();
            fragment.logical_rows = fragment.resolution.logical_rows + ir.logical_rows();
            fragment.payload_bytes = fragment.resolution.payload_bytes + ir.payload_bytes();
            fragment.mutation_logical_rows = fragment.logical_rows;
            fragment.mutation_payload_bytes = fragment.payload_bytes;
            fragment.semantic_ir = Some(ir);
            fragment
        });
        assert_eq!(errors[0].logical_rows(), errors[1].logical_rows());
        assert_eq!(errors[0].payload_bytes(), errors[1].payload_bytes());
        let (outcomes, _) =
            store.persist_prepared_blobs(Vec::from(errors), PersistBatchTargets::PRODUCTION);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.error.is_some())
                .count(),
            2,
            "conflicting error details must be rejected: {outcomes:?}"
        );
        assert!(
            store
                .semantic_ir_publication(error_oid, "python")
                .unwrap()
                .is_none()
        );
    }

    #[cfg(test)]
    #[cfg(any(test, feature = "test-support"))]
    pub(super) use super::test_support::*;

    use super::*;

    /// Persist coordinated import identities alongside legacy scoped imports,
    /// include bindings and independently classified macros. The producer facts
    /// are the oracle, including source-derived ranges and aliases.
    #[test]
    fn rust_fact_rows_round_trip_imports_includes_and_macro_flags() {
        use brokk_bifrost_core::analyzer::parsed_file::{SourceImportFact, SourceImportPathFact};
        use brokk_bifrost_core::analyzer::rust_facts::*;
        use brokk_bifrost_core::analyzer::source_facts::{
            SourceDeclaration, SourceDeclarationId, SourceFactRows, SourceImportId,
            SourceOccurrence, SourceOccurrenceId, SourceOccurrenceProvenance,
        };

        let occurrence = |start, end| SourceOccurrence {
            range: Range {
                start_byte: start,
                end_byte: end,
                start_line: 1,
                end_line: 1,
            },
            provenance: SourceOccurrenceProvenance::ExplicitSubspan,
        };
        let mut source = ParsedSourceFacts {
            source_bytes: 200,
            occurrences: SourceFactRows::new(
                vec![
                    occurrence(0, 200),
                    occurrence(10, 30),
                    occurrence(40, 60),
                    occurrence(70, 80),
                    occurrence(90, 100),
                    occurrence(110, 120),
                ],
                (3..6)
                    .map(|id| SourceDeclaration {
                        occurrence: SourceOccurrenceId::new(id),
                        name: None,
                    })
                    .collect(),
            ),
            js_ts: None,
            php: None,
            cpp: None,
            go: None,
            java: None,
            scala: None,
            ruby: None,
            python: None,
            structural: brokk_bifrost_core::analyzer::structural::facts::StructuralFactRows::new(
                vec![],
                brokk_bifrost_core::compact_graph::CompactRows::from_parts(vec![0], vec![]),
                brokk_bifrost_core::compact_graph::CompactRows::from_parts(vec![0], vec![]),
                vec![],
            ),
            native_site_occurrences: vec![],
            native_declaration_sources: vec![],
            declaration_visibilities: None,
            rust_declaration_properties: vec![],
            rust_modules: Some(RustModuleSourceFacts {
                root: SourceOccurrenceId::new(0),
                declarations: vec![],
                invocations: vec![],
                inventory: vec![],
                scopes: vec![],
                routes: vec![],
                inner_attributes: vec![],
            }),
            rust_types: vec![],
            rust_items: Default::default(),
            imports: vec![],
            generic_imports: vec![],
            rust_import_contexts: vec![],
        };
        for (index, (identifier, alias, segments)) in [
            ("m", "module_alias", vec!["outer", "m"]),
            ("Item", "Item", vec!["outer", "m", "Item"]),
        ]
        .into_iter()
        .enumerate()
        {
            let declaration = SourceOccurrenceId::new(u32::try_from(index + 1).unwrap());
            source.imports.push(SourceImportFact {
                declaration,
                target: None,
                alias_occurrence: None,
                statement: "use outer::m::{self as module_alias, Item};".into(),
                is_wildcard: false,
                is_global: false,
                is_macro_use: false,
                identifier: Some(identifier.into()),
                alias: Some(alias.into()),
                path: Some(SourceImportPathFact {
                    kind: None,
                    segments: segments.into_iter().map(str::to_owned).collect(),
                    lexical_prefixes: vec![],
                    lexical_scopes: vec![],
                }),
            });
            source.rust_import_contexts.push(RustImportContextFact {
                declaration,
                native_scope: None,
                owner_module: "".into(),
                owner_scope: None,
                local_scope: None,
                visibility: RustVisibility::Public,
                cfg_condition: RustCfgCondition::Always,
            });
        }
        source.rust_items.syntax.push(RustItemSyntaxFact {
            occurrence: SourceOccurrenceId::new(0),
            has_error: false,
        });
        source.rust_items.contexts.push(RustSourceContextFact {
            context: SourceOccurrenceId::new(0),
            parent: None,
            owner: None,
            kind: RustSourceContextKind::FileRoot,
            expanding_attribute_starts: vec![],
        });
        let mut facts = RustUsageFacts::default();
        for (index, imported) in ["self", "Item"].into_iter().enumerate() {
            facts.import_targets.push(RustImportTargetFact {
                native_scope: None,
                source_import_id: Some(SourceImportId::new(index as u32)),
                module_path: vec!["outer".into(), "m".into()],
                bound_name: Some(if index == 0 { "module_alias" } else { "Item" }.into()),
                imported_name: Some(imported.into()),
                is_glob: false,
                leading_absolute: false,
                is_extern_crate: false,
                is_macro_use: false,
                visibility: RustVisibility::Public,
                cfg_condition: RustCfgCondition::Always,
                owner_module: "".into(),
                owner_start: 0,
                owner_end: 200,
                local_extent: None,
                source_occurrences: Some(RustImportSourceOccurrences {
                    declaration: SourceOccurrenceId::new(index as u32 + 1),
                    target: None,
                    alias: None,
                }),
            });
        }
        let mut local = facts.import_targets[1].clone();
        local.module_path.clear();
        local.source_import_id = None;
        local.source_occurrences = None;
        local.owner_module = "nested".into();
        local.owner_start = 61;
        local.owner_end = 180;
        local.local_extent = Some((125, 170));
        let mut legacy = RustUsageFacts::default();
        legacy.import_targets.push(local);
        facts.exports = vec![RustExportFact {
            source_import_id: Some(SourceImportId::new(1)),
            exported_name: Some("Item".into()),
            source_path: "outer::m".into(),
            imported_name: Some("Item".into()),
            is_glob: false,
        }];
        legacy.exports = vec![RustExportFact {
            source_import_id: None,
            exported_name: None,
            source_path: "other".into(),
            imported_name: None,
            is_glob: true,
        }];
        for (index, (passthrough, arguments_only, declares_no_item, writes_only_impls)) in [
            (true, false, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ]
        .into_iter()
        .enumerate()
        {
            let declaration = SourceDeclarationId::new(index as u32);
            source
                .rust_items
                .macro_definitions
                .push(RustMacroDefinitionSourceFact {
                    declaration,
                    context: SourceOccurrenceId::new(0),
                    is_macro_rules: true,
                    arms: vec![],
                });
            facts
                .module_routes
                .item_macros
                .push(RustRulesItemMacroDefinition {
                    declaration,
                    name: format!("macro_{index}"),
                    visible_after: 80 + index * 20,
                    scope_start: 0,
                    scope_end: 200,
                    passthrough,
                    arguments_only,
                    decoration: None,
                    declares_no_item,
                    writes_only_impls,
                    exported: false,
                });
        }
        for (index, names) in [vec!["First", "Second"], vec!["Third"]]
            .into_iter()
            .enumerate()
        {
            let file_name = format!("part_{index}.rs");
            legacy.include_edges.push(RustIncludeEdgeFact {
                relative_path: format!("generated/{file_name}"),
                file_name,
                include_start: 140 + index * 10,
                host_bindings: names
                    .into_iter()
                    .map(|name| RustIncludeHostBindingFact {
                        local_name: name.into(),
                        module_specifier: "outer::m".into(),
                        imported_name: Some(name.into()),
                        scope_start: 125,
                        kind: RustIncludeBindingKind::Named,
                    })
                    .collect(),
            });
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("facts.db");
        let oid = Oid::hash_object(git2::ObjectType::Blob, b"rust fact row fixture").unwrap();
        let legacy_oid =
            Oid::hash_object(git2::ObjectType::Blob, b"legacy rust fact row fixture").unwrap();
        {
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            let projected = RustFactRows::from_facts(&facts, Some(&source)).unwrap();
            let projected_legacy = RustFactRows::from_facts(&legacy, None).unwrap();
            store.conn.execute(move |conn| {
                let tx = conn.transaction().unwrap();
                tx.execute(
                    "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)",
                    [oid.to_string()],
                )
                .unwrap();
                let blob = tx.last_insert_rowid();
                // The source publisher lives above this crate. Seed its relational
                // inputs in building state; this test exercises Rust projection
                // rows and their reader, not source publication admission.
                tx.execute("INSERT INTO blob_meta(blob_id, lang, contains_tests, content_package,
                    stored_unit_count, range_count, signature_count, signature_metadata_count,
                    supertype_count, child_count, import_statement_count, type_identifier_count, is_complete)
                    VALUES(?1, 'rust', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 0)", [blob]).unwrap();
                tx.execute(
                    "INSERT INTO source_fact_manifests(blob_id, facts_version, source_bytes,
                    occurrence_count, declaration_count, declaration_unit_count, node_count, role_count,
                    occurrence_role_count, logical_rows, payload_bytes, publication_state)
                    VALUES(?1, 1, 200, 6, 3, 0, 0, 0, 0, 1, 0, 'building')",
                    [blob],
                )
                .unwrap();
                for (index, import) in source.imports.iter().enumerate() {
                    let range = source.occurrences.occurrence(import.declaration).range;
                    tx.execute(
                        "INSERT INTO source_imports(blob_id, import_id, statement, is_wildcard,
                        is_global, identifier, alias, declaration_occurrence_id,
                        declaration_start_byte, declaration_end_byte)
                        VALUES(?1, ?2, ?3, 0, 0, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            blob,
                            index as i64,
                            import.statement,
                            import.identifier,
                            import.alias,
                            import.declaration.get(),
                            range.start_byte as i64,
                            range.end_byte as i64
                        ],
                    )
                    .unwrap();
                    for (ordinal, segment) in import.path.as_ref().unwrap().segments.iter().enumerate()
                    {
                        tx.execute(
                            "INSERT INTO source_import_segments(blob_id, import_id, ordinal, segment)
                            VALUES(?1, ?2, ?3, ?4)",
                            params![blob, index as i64, ordinal as i64, segment],
                        )
                        .unwrap();
                    }
                    tx.execute("INSERT INTO source_rust_import_contexts(blob_id, declaration_occurrence_id,
                        owner_module, visibility, cfg_condition, declaration_start_byte, declaration_end_byte)
                        VALUES(?1, ?2, '', 'public', 'always', ?3, ?4)",
                        params![blob, import.declaration.get(), range.start_byte as i64, range.end_byte as i64]).unwrap();
                }
                for (index, declaration) in source.occurrences.declarations().iter().enumerate() {
                    let range = source.occurrences.occurrence(declaration.occurrence).range;
                    tx.execute(
                        "INSERT INTO source_declarations(blob_id, declaration_id, occurrence_id,
                        start_byte, end_byte, start_line, end_line, provenance)
                        VALUES(?1, ?2, ?3, ?4, ?5, 1, 1, 1)",
                        params![
                            blob,
                            index as i64,
                            declaration.occurrence.get(),
                            range.start_byte as i64,
                            range.end_byte as i64
                        ],
                    )
                    .unwrap();
                    tx.execute(
                        "INSERT INTO source_rust_declaration_properties(blob_id, declaration_id,
                        visibility, cfg_condition, declaration_kind, macro_exported)
                        VALUES(?1, ?2, 'private', 'always', 12, 0)",
                        params![blob, index as i64],
                    )
                    .unwrap();
                }
                source_facts::rust_items::insert_rust_item_source_facts_tx(
                    &tx,
                    blob,
                    &source,
                    &CancellationToken::default(),
                )
                .unwrap();
                insert_rust_fact_rows(
                    &tx,
                    blob,
                    "rust",
                    &projected,
                )
                .unwrap();
                tx.execute("INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)", [legacy_oid.to_string()]).unwrap();
                insert_rust_fact_rows(&tx, tx.last_insert_rowid(), "rust", &projected_legacy).unwrap();
                let foreign_keys = tx.prepare("PRAGMA foreign_key_check").unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                assert!(foreign_keys.is_empty(), "{foreign_keys:?}");
                tx.commit().unwrap();
            });
        }
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        // Canonical publication admission is owned by the language crate.
        // Read its source-import view directly at this row-schema boundary.
        type ImportProjection = (String, Option<String>, Option<String>, i64, i64);
        let imports: Vec<ImportProjection> = store.conn.execute(|conn| {
            conn.prepare("SELECT module_path, bound_name, imported_name, owner_start, owner_end
                FROM source_rust_import_targets WHERE source_import_id IS NOT NULL ORDER BY ordinal")
                .unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
                .unwrap().collect::<rusqlite::Result<_>>().unwrap()
        });
        assert_eq!(
            imports,
            facts
                .import_targets
                .iter()
                .map(|target| (
                    target.module_path.join("::"),
                    target.bound_name.clone(),
                    target.imported_name.clone(),
                    target.owner_start as i64,
                    target.owner_end as i64,
                ))
                .collect::<Vec<_>>()
        );
        let macros: Vec<(bool, bool, bool, bool)> = store.conn.execute(|conn| {
            conn.prepare(
                "SELECT passthrough, arguments_only, declares_no_item, writes_only_impls
                FROM rust_item_macros ORDER BY ordinal",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
        });
        assert_eq!(
            macros,
            facts
                .module_routes
                .item_macros
                .iter()
                .map(|definition| (
                    definition.passthrough,
                    definition.arguments_only,
                    definition.declares_no_item,
                    definition.writes_only_impls,
                ))
                .collect::<Vec<_>>()
        );
        let exports: Vec<(Option<String>, String, Option<String>, bool)> =
            store.conn.execute(|conn| {
                conn.prepare(
                    "SELECT exported_name, source_path, imported_name, is_glob
                FROM source_rust_exports WHERE source_import_id IS NOT NULL ORDER BY ordinal",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
            });
        assert_eq!(
            exports,
            facts
                .exports
                .iter()
                .map(|export| (
                    export.exported_name.clone(),
                    export.source_path.clone(),
                    export.imported_name.clone(),
                    export.is_glob,
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(store.rust_usage_facts(legacy_oid, "rust").unwrap(), legacy);
        let flags: Vec<Option<bool>> = store.conn.execute(|conn| {
            conn.prepare("SELECT is_glob FROM rust_exports ORDER BY blob_id, ordinal")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        });
        assert_eq!(flags, vec![None, Some(true)]);
    }

    #[test]
    #[ignore = "finds real bug: source-less Rust import paths have no segment rows"]
    fn rust_fact_rows_round_trip_source_less_module_path() {
        use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustVisibility};

        let facts = RustUsageFacts {
            import_targets: vec![RustImportTargetFact {
                native_scope: None,
                source_import_id: None,
                module_path: vec!["outer".into(), "m".into()],
                bound_name: Some("Item".into()),
                imported_name: Some("Item".into()),
                is_glob: false,
                leading_absolute: false,
                is_extern_crate: false,
                is_macro_use: false,
                visibility: RustVisibility::Private,
                cfg_condition: RustCfgCondition::Always,
                owner_module: "".into(),
                owner_start: 0,
                owner_end: 200,
                local_extent: None,
                source_occurrences: None,
            }],
            ..Default::default()
        };
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let oid = Oid::hash_object(git2::ObjectType::Blob, b"source-less import path").unwrap();
        {
            let mut conn = store.conn.lock().unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 1)",
                [oid.to_string()],
            )
            .unwrap();
            insert_rust_fact_rows(
                &tx,
                tx.last_insert_rowid(),
                "rust",
                &RustFactRows::from_facts(&facts, None).unwrap(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(store.rust_usage_facts(oid, "rust").unwrap(), facts);
    }

    // The EXPLAIN QUERY PLAN pins below take their SQL and bindings from the
    // pinned-query registry in `planner_statistics`, so each pinned statement
    // is written once, and run each assertion in both planner-statistics
    // states (issue #3016).
    #[cfg(test)]
    use super::planner_statistics::pinned_plans::DEFINITION_CANDIDATE_ARITY_LADDER;

    #[cfg(test)]
    use super::planner_statistics::tests::{explain_pin, pinned};

    #[cfg(test)]
    #[cfg(any(test, feature = "test-support"))]
    use crate::gitblob::test_repo::commit_all;

    #[cfg(test)]
    #[cfg(any(test, feature = "test-support"))]
    use crate::gitblob::test_repo::init_repo;

    #[cfg(test)]
    #[cfg(any(test, feature = "test-support"))]
    use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;

    #[cfg(test)]
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    #[cfg(test)]
    #[cfg(any(test, feature = "test-support"))]
    use git2::ObjectType;

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "74238a905cc7: persisted integer fixture omitted the async field"
    )]
    fn decode_structural_node_keeps_integer_value_fields() {
        let encoded = serde_json::json!([[
            brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::NumericLiteral.code(),
            null,
            null,
            0,
            3,
            null,
            null,
            null,
            1,
            null,
            null,
            null,
            null,
            null,
            { "decimal": null, "low_bits": 4294967295u32, "negative": false },
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        ]])
        .to_string();
        let nodes = decode_structural_nodes(&encoded).expect("current node-row layout");

        assert_eq!(
            nodes[0].integer_literal_value,
            Some(crate::analyzer::structural::facts::IntegerLiteralValue {
                decimal: None,
                low_bits: u32::MAX,
                negative: false,
            })
        );
    }

    #[cfg(test)]
    #[test]
    fn store_error_context_preserves_resource_bound_kind() {
        let error = StoreError::resource_bound("over budget").context("repairing blob");

        assert_eq!(error.kind(), StoreErrorKind::ResourceBound);
        assert!(error.is_resource_bound());
        assert_eq!(error.to_string(), "repairing blob: over budget");
    }

    #[cfg(test)]
    #[test]
    fn store_error_classification_survives_real_sqlite_errors_and_context() {
        // Cancellation aborts a statement from a progress handler, as
        // `with_resolution_progress_handler` does; callers then match
        // `is_sqlite_interrupted` on the error after adding context.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE unique_key(value INTEGER PRIMARY KEY)")
            .unwrap();
        conn.progress_handler(1, Some(|| true)).unwrap();
        let interrupted = StoreError::from(
            conn.query_row(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n)
                 SELECT max(i) FROM n",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_err(),
        )
        .context("reading candidates");
        assert!(interrupted.is_sqlite_interrupted(), "{interrupted}");
        assert!(!interrupted.is_missing_required_source_facts());
        conn.progress_handler(0, None::<fn() -> bool>).unwrap();

        conn.execute("INSERT INTO unique_key VALUES (1)", [])
            .unwrap();
        let constraint = StoreError::from(
            conn.execute("INSERT INTO unique_key VALUES (1)", [])
                .unwrap_err(),
        )
        .context("publishing rows");
        assert_eq!(constraint.kind(), StoreErrorKind::Generic);
        // 1555 is SQLITE_CONSTRAINT_PRIMARYKEY; diagnostics keep the extended code.
        assert!(
            constraint.to_string().contains("extended code: 1555"),
            "{constraint}"
        );

        let cancelled = StoreError::cancelled("stopped").context("reading Python inputs");
        assert!(cancelled.is_cancelled(), "{cancelled}");
        assert!(!StoreError::new("stopped").is_cancelled());
        assert!(!interrupted.is_cancelled());

        let missing = StoreError::missing_required_source_facts("no source manifest")
            .context("hydrating Model.java");
        assert!(missing.is_missing_required_source_facts());
        assert!(!missing.is_sqlite_interrupted());
        assert_eq!(
            missing.to_string(),
            "hydrating Model.java: no source manifest"
        );
        assert!(
            !StoreError::new("no source manifest")
                .context("hydrating Model.java")
                .is_missing_required_source_facts()
        );
    }

    #[cfg(test)]
    fn empty_publication(oid: Oid, lang: &str) -> PreparedParsedBlob {
        // A valid empty Java parse with an empty complete resolution interior.
        // No parser or engine bridge is needed to exercise the SQL envelope.
        let state = Arc::new(FileState {
            source: Default::default(),
            package_name: Default::default(),
            content_qualifier: Default::default(),
            top_level_declarations: Default::default(),
            declarations: Default::default(),
            definition_lookup_units: Default::default(),
            imports: Default::default(),
            scala_exports: Default::default(),
            rust_usage_facts: Default::default(),
            resolution_facts: Default::default(),
            source_facts: Default::default(),
            source_declaration_units: Default::default(),
            source_declaration_metadata: Default::default(),
            raw_supertypes: Default::default(),
            supertype_lookup_paths: Default::default(),
            type_identifiers: Default::default(),
            signatures: Default::default(),
            signature_metadata: Default::default(),
            signature_metadata_signature_ordinals: Default::default(),
            cpp_template_metadata: Default::default(),
            ruby_method_dispatch_modes: Default::default(),
            ranges: Default::default(),
            children: Default::default(),
            scala_traits: Default::default(),
            type_aliases: Default::default(),
            contains_tests: Default::default(),
            test_region_units: Default::default(),
            materialization_records: Default::default(),
            parse_errors: Default::default(),
            parse_complete: true,
            completeness: Default::default(),
            additional_projections: Default::default(),
        });
        let resolution = PreparedResolutionBundle::new(
            Language::Java,
            Default::default(),
            Default::default(),
            Vec::new(),
            Default::default(),
            Vec::new(),
            Default::default(),
            Vec::new(),
            &CancellationToken::new(),
        )
        .unwrap();
        let logical_rows = resolution.logical_rows + 3;
        let payload_bytes = resolution.payload_bytes + lang.len();
        PreparedParsedBlob {
            oid,
            oid_text: oid.to_string(),
            lang: lang.into(),
            generation: GenerationId::BOOTSTRAP,
            state,
            units: Default::default(),
            source_declaration_units: Default::default(),
            source_declaration_metadata: Default::default(),
            declaration_visibility_version: Default::default(),
            java_type_constructor_version: Default::default(),
            go_source_version: Default::default(),
            java_source_version: Default::default(),
            scala_source_version: Default::default(),
            ruby_source_version: Default::default(),
            php_source_version: Default::default(),
            cpp_source_version: Default::default(),
            source_facts_version: Default::default(),
            source_storage: Default::default(),
            metadata_bridges_required: Default::default(),
            js_ts_source_version: Default::default(),
            python_source_version: Default::default(),
            ranges: Default::default(),
            signatures: Default::default(),
            signature_metadata: Default::default(),
            signature_metadata_signature_ordinals: Default::default(),
            cpp_templates: Default::default(),
            supertypes: Default::default(),
            children: Default::default(),
            imports: Default::default(),
            scala_exports: Default::default(),
            rust_facts: Default::default(),
            type_identifiers: Default::default(),
            ruby_dispatch_modes: Default::default(),
            scala_traits: Default::default(),
            materialization_records: Default::default(),
            contains_tests: Default::default(),
            content_package: Default::default(),
            resolution,
            semantic_ir: Default::default(),
            logical_rows,
            payload_bytes,
            mutation_logical_rows: logical_rows,
            mutation_payload_bytes: payload_bytes,
            additional: Default::default(),
        }
    }

    #[cfg(test)]
    #[test]
    fn overlapping_publication_envelopes_coalesce_and_conflicts_are_atomic() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let oid = oid_for(b"projection envelope");
        let envelope = || {
            let mut root = empty_publication(oid, "java");
            root.additional
                .push(empty_publication(oid, "java:projection"));
            root
        };
        let prepared = vec![empty_publication(oid, "java"), envelope(), envelope()];
        store.ensure_prepared_resolution_epochs(&prepared).unwrap();
        let (outcomes, _) = store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 3);
        for outcome in outcomes {
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
        }
        assert!(store.contains_parsed_blob(oid, "java").unwrap());
        assert!(store.contains_parsed_blob(oid, "java:projection").unwrap());
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM blobs WHERE blob_oid=?1",
                [oid.to_string()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        drop(conn);

        let conflicting_oid = oid_for(b"conflicting test flags");
        // Both flags are explicit persisted inputs; prove each works alone.
        for flag in [0, 1] {
            let mut control = empty_publication(conflicting_oid, "java");
            control.contains_tests = flag;
            let (outcomes, _) =
                store.persist_prepared_blobs(vec![control], PersistBatchTargets::PRODUCTION);
            assert!(outcomes[0].error.is_none(), "{:?}", outcomes[0].error);
            assert_eq!(store.conn.lock().unwrap().query_row("SELECT contains_tests FROM blob_meta JOIN blobs ON blobs.id=blob_meta.blob_id WHERE blob_oid=?1", [conflicting_oid.to_string()], |row| row.get::<_, i64>(0)).unwrap(), flag);
        }
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM blobs WHERE blob_oid=?1",
                [conflicting_oid.to_string()],
            )
            .unwrap();
        let left = empty_publication(conflicting_oid, "java");
        let mut right = empty_publication(conflicting_oid, "java");
        right.contains_tests = 1;
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![left, right], PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|outcome| outcome.error.is_some()));
        assert!(!store.contains_blob(conflicting_oid, "java").unwrap());
    }

    #[cfg(test)]
    #[test]
    fn requested_projection_repairs_do_not_leak_between_queries() {
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let oid = oid_for(b"stale projection");
        let mut root = empty_publication(oid, "java");
        root.additional
            .push(empty_publication(oid, "java:projection"));
        store
            .ensure_prepared_resolution_epochs(std::slice::from_ref(&root))
            .unwrap();
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![root], PersistBatchTargets::PRODUCTION);
        assert!(outcomes[0].error.is_none(), "{:?}", outcomes[0].error);
        let conn = store.conn.lock().unwrap();
        let request = CompleteAnalysisBlobRequest::new(oid, "java", ["java:projection".into()]);
        assert!(
            missing_published_complete_analysis_blob_keys_conn(
                &conn,
                std::slice::from_ref(&request),
                Language::Java
            )
            .unwrap()
            .is_empty()
        );
        conn.execute("DELETE FROM resolution_fragment_interiors WHERE blob_id=(SELECT id FROM blobs WHERE blob_oid=?1 AND lang='java:projection')", [oid.to_string()]).unwrap();
        assert_eq!(
            missing_published_complete_analysis_blob_keys_conn(
                &conn,
                std::slice::from_ref(&request),
                Language::Java
            )
            .unwrap(),
            vec![MissingCompleteAnalysisBlob {
                oid,
                storage_language: "java".into(),
                required_existing_additional_storage_languages: vec!["java:projection".into()]
            }]
        );
        assert!(
            missing_published_complete_analysis_blob_keys_conn(
                &conn,
                &[CompleteAnalysisBlobRequest::new(oid, "java", [])],
                Language::Java
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            missing_published_complete_analysis_blob_keys_conn(
                &conn,
                &[
                    request,
                    CompleteAnalysisBlobRequest::new(oid, "java:projection", [])
                ],
                Language::Java
            )
            .unwrap(),
            vec![MissingCompleteAnalysisBlob::primary_only(
                oid,
                "java:projection".into()
            )]
        );
    }

    #[cfg(test)]
    #[test]
    fn incomplete_publications_hide_import_and_signature_metadata() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let oids = [
            oid_for(b"complete metadata"),
            oid_for(b"incomplete metadata"),
        ];
        // Cross all three batch sizes while the AFTER INSERT trigger expands
        // each row's parameters and clears its JSON transport cell.
        let metadata = (0..73)
            .map(|ordinal| {
                let label = format!("f{ordinal}(value)");
                let start = label.len() - 6;
                SignatureMetadata::new(
                    label,
                    vec![ParameterMetadata::new("value", start, start + 5).with_name("value")],
                )
            })
            .collect::<Vec<_>>();
        let prepared = oids.map(|oid| {
            let mut blob = empty_publication(oid, "java");
            blob.content_package = "pkg".into();
            blob.contains_tests = 1;
            blob.units.push(PreparedUnitRow {
                key: Default::default(),
                kind: code_unit_kind_to_i64(CodeUnitType::Function),
                short_name: "f".into(),
                identifier: "f".into(),
                content_qualifier: Default::default(),
                exact_fqn: Some("f".into()),
                normalized_fqn: Default::default(),
                simple_type_name: Default::default(),
                signature: Default::default(),
                synthetic: Default::default(),
                is_type_alias: Default::default(),
                top_level_ordinal: Default::default(),
                in_declarations: 1,
                in_definition_lookup: 1,
                in_test_region: Default::default(),
                fq_segment_count: Default::default(),
                fq_segment_bytes: Default::default(),
                fq_anchor_kind: Default::default(),
                fq_anchor_pop: Default::default(),
                fq_package_tail_segments: Default::default(),
                exact_fqn_tail: Default::default(),
                normalized_fqn_tail: Default::default(),
                exact_parent_fqn_tail: Default::default(),
                normalized_parent_fqn_tail: Default::default(),
                package_fqn_tail: Default::default(),
                relational_fq_segments: Default::default(),
            });
            for (ordinal, row) in metadata.iter().enumerate() {
                blob.signature_metadata.push((
                    0,
                    usize_to_i64(ordinal).unwrap(),
                    SignatureMetadataColumns::encode(row).unwrap(),
                ));
            }
            blob.imports = ImportRows::from_imports(
                &[ImportInfo {
                    raw_snippet: "import pkg.Dependency;".into(),
                    is_wildcard: false,
                    is_global: false,
                    identifier: Some("Dependency".into()),
                    alias: None,
                    path: None,
                    binder_span: None,
                }],
                None,
            )
            .unwrap();
            blob
        });
        store.ensure_prepared_resolution_epochs(&prepared).unwrap();
        let (outcomes, _) =
            store.persist_prepared_blobs(prepared.into(), PersistBatchTargets::PRODUCTION);
        for outcome in outcomes {
            assert!(outcome.error.is_none(), "{:?}", outcome.error);
        }
        let unit = CodeUnit::new(test_blob_file(), CodeUnitType::Function, "", "f");
        // Positive controls prove that both populated publications are visible.
        for oid in oids {
            assert_eq!(
                store
                    .signature_metadata_for_unit(oid, "java", GenerationId::BOOTSTRAP, &unit)
                    .unwrap(),
                metadata.clone()
            );
        }
        assert_eq!(
            store.blobs_with_structured_imports("java", &oids).unwrap(),
            HashSet::from_iter(oids)
        );
        {
            let conn = store.conn.lock().unwrap();
            let texts = oids.map(|oid| oid.to_string());
            let expected = texts
                .iter()
                .cloned()
                .map(|oid| (oid, ("pkg".into(), true)))
                .collect::<HashMap<_, _>>();
            assert_eq!(
                read_import_metadata_bulk(&conn, "java", &texts).unwrap(),
                expected
            );
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM unit_signature_metadata
                     WHERE parameters = '[]' AND parameter_count = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
                146
            );
            // Leave declaration visibility available: parse completeness is an
            // independent witness that each of the three readers must check.
            conn.execute("UPDATE blob_meta SET is_complete=0 WHERE blob_id=(SELECT id FROM blobs WHERE blob_oid=?1)",[oids[1].to_string()]).unwrap();
            assert_eq!(
                read_import_metadata_bulk(&conn, "java", &texts).unwrap(),
                HashMap::from_iter([(texts[0].clone(), ("pkg".into(), true))])
            );
        }
        assert_eq!(
            store.blobs_with_structured_imports("java", &oids).unwrap(),
            HashSet::from_iter([oids[0]])
        );
        assert_eq!(
            store
                .signature_metadata_for_unit(oids[0], "java", GenerationId::BOOTSTRAP, &unit)
                .unwrap(),
            metadata
        );
        assert!(
            store
                .signature_metadata_for_unit(oids[1], "java", GenerationId::BOOTSTRAP, &unit)
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(test)]
    fn semantic_error_publication(oid: Oid, detail: &str) -> PreparedParsedBlob {
        use crate::analyzer::semantic::ContentIdentity;
        use semantic_ir::SemanticIrLoweringOutcome;
        let mut blob = empty_publication(oid, "java");
        let ir = PreparedSemanticIr::prepare(
            SemanticIrLoweringOutcome::Error(detail.into()),
            None,
            "test-error-v1",
            ContentIdentity::hash_bytes(b"error detail"),
            12,
        );
        blob.payload_bytes += ir.payload_bytes();
        blob.logical_rows += ir.logical_rows();
        blob.semantic_ir = Some(ir);
        blob
    }

    #[cfg(test)]
    #[test]
    fn unequal_semantic_error_payloads_conflict_without_publication() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let oid = oid_for(b"error detail");
        let prepare = |detail: &str| semantic_error_publication(oid, detail);
        store
            .ensure_semantic_ir_producer_epoch("java", "test-error-v1")
            .unwrap();
        let control = prepare("short");
        store
            .ensure_prepared_resolution_epochs(std::slice::from_ref(&control))
            .unwrap();
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![control], PersistBatchTargets::PRODUCTION);
        assert!(outcomes[0].error.is_none(), "{:?}", outcomes[0].error);
        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.query_row("SELECT detail FROM semantic_ir_publications", [], |row| row
                    .get::<_, String>(0))
                    .unwrap(),
                "short"
            );
            conn.execute("DELETE FROM blobs WHERE blob_oid=?1", [oid.to_string()])
                .unwrap();
        }
        let left = prepare("short");
        let right = prepare("a longer error detail");
        assert_eq!(left.logical_rows, right.logical_rows);
        assert_ne!(
            left.persisted_payload_bytes(),
            right.persisted_payload_bytes()
        );
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![left, right], PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|outcome| outcome.error.is_some()));
        assert!(!store.contains_blob(oid, "java").unwrap());
    }

    #[cfg(test)]
    #[test]
    fn active_set_sql_format_transitions_and_corruption() {
        use SemanticPackActivationSourceKind::{Installed, WorkspaceProduced};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("active.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let members = vec![
            SemanticPackActiveReference {
                manifest_digest: "1".repeat(64),
                source_kind: Installed,
                source_id: "registry".into(),
                workspace_produced: false,
            },
            SemanticPackActiveReference {
                manifest_digest: "2".repeat(64),
                source_kind: WorkspaceProduced,
                source_id: "workspace".into(),
                workspace_produced: true,
            },
        ];
        // Independently encoded SHA-256 v1 fixture, including big-endian lengths
        // and the final one-byte workspace-produced field of each member.
        let v1_digest = "f7f3316749c38eeddbed6a3c39402ff3996ce37519ff25400a37a9127527845c";
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("INSERT INTO semantic_pack_active_state(singleton,active_set_digest,updated_at) VALUES(1,?1,0)", [v1_digest]).unwrap();
            for (ordinal, digest, kind, source, produced) in [
                (1, "1".repeat(64), "installed", "registry", false),
                (0, "2".repeat(64), "workspace_produced", "workspace", true),
            ] {
                conn.execute("INSERT INTO semantic_pack_active_members(ordinal,manifest_digest,source_kind,source_id,workspace_produced) VALUES(?1,?2,?3,?4,?5)", params![ordinal,digest,kind,source,produced]).unwrap();
            }
        }
        let mut actual = store.semantic_pack_active_set().unwrap().unwrap();
        actual.members.sort();
        assert_eq!(
            actual,
            SemanticPackActiveSet {
                active_set_digest: v1_digest.into(),
                members: members.clone()
            }
        );
        let mut shared_source = members.clone();
        shared_source[1].source_id = "registry".into();
        let replacement = store
            .replace_semantic_pack_active_set(&shared_source)
            .unwrap();
        assert_ne!(replacement.active_set_digest, v1_digest);
        assert_eq!(replacement.members, shared_source);
        let mut duplicate = members.clone();
        duplicate[1].manifest_digest = duplicate[0].manifest_digest.clone();
        assert!(store.replace_semantic_pack_active_set(&duplicate).is_err());
        assert_eq!(
            store.semantic_pack_active_set().unwrap(),
            Some(replacement.clone())
        );
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        assert_eq!(
            store.semantic_pack_active_set().unwrap(),
            Some(replacement.clone())
        );
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE semantic_pack_active_state SET active_set_digest = ?1",
                ["0".repeat(64)],
            )
            .unwrap();
        }
        assert!(
            store
                .semantic_pack_active_set()
                .unwrap_err()
                .to_string()
                .contains("digest mismatch")
        );
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE semantic_pack_active_state SET active_set_digest = ?1",
                [&replacement.active_set_digest],
            )
            .unwrap();
        }
        assert_eq!(store.semantic_pack_active_set().unwrap(), Some(replacement));
        let empty = store.replace_semantic_pack_active_set(&[]).unwrap();
        assert!(empty.members.is_empty());
        drop(store);
        assert_eq!(
            AnalyzerStore::open_persistent(&path)
                .unwrap()
                .semantic_pack_active_set()
                .unwrap(),
            Some(empty)
        );
    }

    #[cfg(test)]
    #[test]
    fn workspace_projection_permutations_and_semantic_edits_preserve_history() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace = WorkspaceId("e".repeat(64));
        let file = WorkspaceFileRow {
            rel_path: "src/a.py".into(),
            blob_oid: oid_for(b"a"),
        };
        let mut symbols = ["pkg.A", "pkg.B"].map(|name| PathSymbolRow {
            rel_path: file.rel_path.clone(),
            blob_oid: file.blob_oid,
            kind: CodeUnitType::Class,
            package_name: "pkg".into(),
            short_name: name.into(),
            exact_fqn: name.into(),
            normalized_fqn: name.to_lowercase(),
            requires_imports: false,
        });
        let mut anchors = [0, 1].map(|pop| WorkspaceAnchorRow {
            rel_path: file.rel_path.clone(),
            anchor: PackageAnchor::OwnModule { pop },
            package_name: "pkg".into(),
        });
        let publish = |symbols: &[PathSymbolRow], anchors: &[WorkspaceAnchorRow]| {
            store
                .sync_workspace_snapshot_for_workspace(
                    &workspace,
                    "python",
                    GenerationId::BOOTSTRAP,
                    std::slice::from_ref(&file),
                    symbols,
                    &[],
                    &[],
                    &[],
                    anchors,
                )
                .unwrap()
        };
        let first = publish(&symbols, &anchors);
        anchors.reverse();
        symbols.reverse();
        assert_eq!(
            publish(&symbols, &anchors),
            first,
            "permutations retain the revision"
        );
        symbols[0].normalized_fqn = "changed.normalized".into();
        let renamed = publish(&symbols, &anchors);
        assert_eq!(renamed.revision, first.revision + 1);
        anchors[0].anchor = PackageAnchor::OwnModule { pop: 2 };
        let moved = publish(&symbols, &anchors);
        assert_eq!(moved.revision, renamed.revision + 1);
        let conn = store.conn.lock().unwrap();
        for (snapshot, expected_names, expected_pops) in [
            (&first, vec!["pkg.a", "pkg.b"], vec![0, 1]),
            (&renamed, vec!["changed.normalized", "pkg.a"], vec![0, 1]),
            (&moved, vec!["changed.normalized", "pkg.a"], vec![0, 2]),
        ] {
            store
                .select_writer_workspace_snapshots(
                    &conn,
                    &HashMap::from_iter([("python".into(), snapshot.clone())]),
                )
                .unwrap();
            let names = conn.prepare("SELECT normalized_fqn FROM workspace_file_path_symbol_rows AS names JOIN workspace_files AS files ON files.file_id=names.file_version_id ORDER BY normalized_fqn").unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(names, expected_names);
            let pops = conn
                .prepare("SELECT anchor_pop FROM workspace_file_anchors ORDER BY anchor_pop")
                .unwrap()
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(pops, expected_pops);
        }
        assert_eq!(
            conn.query_row("SELECT count(*) FROM workspace_file_versions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            3
        );
    }

    #[cfg(test)]
    #[test]
    fn selected_file_projection_digest_matches_published_workspace_digest() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id = WorkspaceId("c".repeat(64));
        let a = WorkspaceFileRow {
            rel_path: "src/a.py".into(),
            blob_oid: oid_for(b"a"),
        };
        let b = WorkspaceFileRow {
            rel_path: "src/b.py".into(),
            blob_oid: oid_for(b"b"),
        };
        let symbol = |file: &WorkspaceFileRow, exact_fqn: &str, kind| PathSymbolRow {
            rel_path: file.rel_path.clone(),
            blob_oid: file.blob_oid,
            kind,
            package_name: "src".into(),
            short_name: exact_fqn.rsplit('.').next().unwrap().into(),
            exact_fqn: exact_fqn.into(),
            normalized_fqn: exact_fqn.to_lowercase(),
            requires_imports: false,
        };
        let member = |file: &WorkspaceFileRow, package: &str| WorkspacePackageFileRow {
            package_name: package.into(),
            rel_path: file.rel_path.clone(),
        };
        let edge = |file: &WorkspaceFileRow, parent: &str, child: &str| WorkspacePackageEdgeRow {
            rel_path: file.rel_path.clone(),
            parent_package_name: parent.into(),
            child_package_name: child.into(),
        };
        let anchor = |file: &WorkspaceFileRow| WorkspaceAnchorRow {
            rel_path: file.rel_path.clone(),
            anchor: PackageAnchor::OwnModule { pop: 1 },
            package_name: "src".into(),
        };
        // The selected operation below receives A's rows out of canonical
        // order, including two symbols that tie on exact_fqn and differ only
        // by kind. Publication receives them in the reverse order.
        let a_symbols = vec![
            symbol(&a, "src.a.Z", CodeUnitType::Class),
            symbol(&a, "src.a", CodeUnitType::Module),
            symbol(&a, "src.a", CodeUnitType::Class),
        ];
        let a_members = vec![member(&a, "src.sub"), member(&a, "src")];
        let a_edges = vec![edge(&a, "src", "src.sub"), edge(&a, "", "src")];
        let b_symbols = vec![symbol(&b, "src.b", CodeUnitType::Module)];
        let b_members = vec![member(&b, "src")];
        let b_edges = vec![edge(&b, "", "src")];
        fn all<T: Clone>(a_rows: &[T], b_rows: &[T]) -> Vec<T> {
            [b_rows, a_rows].concat()
        }
        fn reversed<T: Clone>(rows: &[T]) -> Vec<T> {
            rows.iter().rev().cloned().collect()
        }
        store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "python",
                GenerationId::BOOTSTRAP,
                &[a.clone(), b.clone()],
                &all(&reversed(&a_symbols), &b_symbols),
                &[],
                &all(&reversed(&a_members), &b_members),
                &all(&reversed(&a_edges), &b_edges),
                &[anchor(&b), anchor(&a)],
            )
            .unwrap();
        let stored = |rel_path: &str| -> String {
            let conn = store.conn.lock().expect("store mutex");
            conn.query_row(
                "SELECT projection_digest FROM workspace_file_versions
                 WHERE rel_path = ?1 AND valid_until IS NULL",
                [rel_path],
                |row| row.get(0),
            )
            .unwrap()
        };
        let hex = |digest: [u8; 32]| {
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };

        // A selected operation passes only the replaced file's rows.
        let selected = selected_workspace_file_projection_digest(
            &a,
            &a_symbols,
            &a_members,
            &a_edges,
            &[anchor(&a)],
        );
        assert_eq!(hex(selected), stored(&a.rel_path));
        // Rows of other files do not belong to A's projection.
        let with_foreign_rows = selected_workspace_file_projection_digest(
            &a,
            &all(&a_symbols, &b_symbols),
            &all(&a_members, &b_members),
            &all(&a_edges, &b_edges),
            &[anchor(&b), anchor(&a)],
        );
        assert_eq!(with_foreign_rows, selected);
        assert_ne!(stored(&a.rel_path), stored(&b.rel_path));

        let mut renamed = a_symbols.clone();
        renamed[0].short_name = "Y".into();
        assert_ne!(
            selected_workspace_file_projection_digest(
                &a,
                &renamed,
                &a_members,
                &a_edges,
                &[anchor(&a)],
            ),
            selected,
            "a changed path-symbol row must change the projection identity"
        );
    }

    #[cfg(test)]
    #[test]
    fn configuration_replacement_publishes_the_same_partition_as_a_full_sync() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id = WorkspaceId("d".repeat(64));
        let langs = vec!["java".to_string(), "kotlin".to_string()];
        let generations = store
            .ensure_language_epoch_values(&[
                ("java".into(), "configuration".into()),
                ("kotlin".into(), "configuration".into()),
            ])
            .unwrap();
        let input = |path: &str, bytes: &str| {
            WorkspaceConfigurationInput::new(path.into(), bytes.as_bytes().into())
        };
        let source = WorkspaceFileRow {
            rel_path: "src/Main.java".into(),
            blob_oid: oid_for(b"class Main {}"),
        };
        let full_sync = |configuration: &[WorkspaceConfigurationInput]| -> WorkspaceSnapshots {
            langs
                .iter()
                .map(|lang| {
                    let snapshot = store
                        .sync_workspace_inputs_for_workspace(
                            &workspace_id,
                            lang,
                            generations[lang],
                            std::slice::from_ref(&source),
                            &[],
                            &[],
                            &[],
                            &[],
                            &[],
                            configuration,
                            &[],
                            &[],
                        )
                        .unwrap();
                    (lang.clone(), snapshot)
                })
                .collect()
        };
        let base = full_sync(&[
            input("gradle.properties", "version=1\n"),
            input("settings.gradle", "include 'app'\n"),
        ]);

        // One changed input, then one input the base did not have.
        let (changed, _) = store
            .replace_configuration_input(
                &workspace_id,
                &base,
                &langs,
                &generations,
                input("gradle.properties", "version=2\n"),
            )
            .unwrap();
        let (added, digest) = store
            .replace_configuration_input(
                &workspace_id,
                &changed,
                &langs,
                &generations,
                input("build.gradle", "plugins {}\n"),
            )
            .unwrap();

        // The full build digests the complete partition ordered by path.
        let full = [
            input("build.gradle", "plugins {}\n"),
            input("gradle.properties", "version=2\n"),
            input("settings.gradle", "include 'app'\n"),
        ];
        assert_eq!(
            digest,
            configuration_digest(
                full.iter()
                    .map(|input| (input.relative_path(), input.content_oid()))
            )
        );
        for lang in &langs {
            assert_eq!(added[lang].revision, base[lang].revision + 2, "{lang}");
        }
        assert_eq!(
            store
                .workspace_snapshots_for_current_languages(&workspace_id, &langs)
                .unwrap(),
            added
        );
        // A from-scratch sync of the same inputs finds nothing to publish.
        assert_eq!(full_sync(&full), added);

        let stale = store
            .replace_configuration_input(
                &workspace_id,
                &base,
                &langs,
                &generations,
                input("gradle.properties", "version=3\n"),
            )
            .unwrap_err();
        assert!(
            stale.to_string().contains("workspace revision conflict"),
            "{stale}"
        );
    }

    #[cfg(test)]
    /// Structural hydration reads one blob's recovered regions through the
    /// region table's primary key, and answers callable containment against
    /// that blob's one structural-facts row (#3777). The only scan is the
    /// `json_each` walk over that row's nodes.
    #[test]
    fn recovered_region_reader_seeks_one_blob() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().expect("store mutex");
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("structural_recovered_regions"));
            for table in ["region", "facts"] {
                assert!(
                    plan.iter()
                        .any(|detail| detail
                            .starts_with(&format!("SEARCH {table} USING PRIMARY KEY"))),
                    "{table} must be a primary-key seek {state}: {plan:#?}"
                );
            }
            assert!(
                plan.iter().all(|detail| !detail.contains("TEMP B-TREE")
                    && !detail.contains("AUTOMATIC")
                    && (!detail.contains("SCAN ") || detail.contains("VIRTUAL TABLE"))),
                "only the JSON nodes may be scanned {state}: {plan:#?}"
            );
        }
    }

    #[cfg(test)]
    /// Both signature-metadata readers that join reach their rows through the
    /// table's own primary key. A full scan here is a per-language table walk
    /// on a table measured at two million rows.
    #[test]
    fn signature_metadata_readers_seek_the_primary_key() {
        for state in PlannerStatisticsState::BOTH {
            signature_metadata_readers_seek_the_primary_key_in(state);
        }
    }

    #[cfg(test)]
    fn signature_metadata_readers_seek_the_primary_key_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);

        let batch_plan = explain_pin(&conn, &pinned("signature_metadata_batch_reader"));
        assert!(
            batch_plan
                .iter()
                .any(|detail| detail.contains("SEARCH metadata USING PRIMARY KEY")),
            "the batch reader must seek the primary key {state}: {batch_plan:#?}"
        );
        assert!(
            batch_plan.iter().all(|detail| !detail.contains("SCAN")),
            "the batch reader must not scan any table {state}: {batch_plan:#?}"
        );

        let joined_plan = explain_pin(&conn, &pinned("signature_metadata_for_unit_limited"));
        assert!(
            joined_plan
                .iter()
                .any(|detail| detail.contains("SEARCH metadata USING PRIMARY KEY")),
            "the joined reader must seek the primary key {state}: {joined_plan:#?}"
        );
        assert!(
            joined_plan.iter().all(|detail| !detail.contains("SCAN")),
            "the joined reader must not scan any table {state}: {joined_plan:#?}"
        );
    }

    #[cfg(test)]
    /// The view the relational callable-facts reader selects from projects
    /// every persisted signature-metadata column.
    ///
    /// That reader decodes [`SIGNATURE_METADATA_VALUE_COLUMNS`] positionally,
    /// so a column added to the table and to the list but not to the view
    /// makes its SELECT fail to prepare. The failure surfaces at run time
    /// inside a usage-graph frontier, as "a Scala file frontier failed", which
    /// is three layers away from the schema that caused it. Preparing the same
    /// projection here fails at push time instead.
    #[test]
    fn the_live_callable_facts_view_projects_every_signature_metadata_column() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let columns = signature_metadata_value_columns_sql("facts");
        conn.prepare(&format!(
            "SELECT facts.ordinal, facts.text, {columns} FROM live_callable_facts AS facts"
        ))
        .expect("live_callable_facts must project every signature metadata column");
    }

    #[cfg(test)]
    #[test]
    fn enclosing_declaration_file_projection_uses_ordered_primary_keys() {
        for state in PlannerStatisticsState::BOTH {
            enclosing_declaration_file_projection_uses_ordered_primary_keys_in(state);
        }
    }

    #[cfg(test)]
    fn enclosing_declaration_file_projection_uses_ordered_primary_keys_in(
        state: PlannerStatisticsState,
    ) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("enclosing_declarations_for_file"));

        for table in ["units", "meta", "ranges"] {
            assert!(
                plan.iter()
                    .any(|detail| detail.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
                "enclosing declaration projection must seek {table} {state}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                "enclosing declaration projection must not scan {table} {state}: {plan:#?}"
            );
        }
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("USE TEMP B-TREE")),
            "the primary-key order must satisfy the projection ORDER BY {state}: {plan:#?}"
        );
    }

    #[cfg(test)]
    /// The actionable cache-denial message reaches the workspace entry point,
    /// not just the SQLite open it wraps (issue #1544).
    #[test]
    #[cfg(unix)]
    fn unwritable_workspace_root_reports_the_ways_out() {
        use std::os::unix::fs::PermissionsExt;

        // Exercise the default location in a child without changing the parent
        // process environment or writing into the operator's cache override.
        if std::env::var_os(gitblob::CACHE_DIR_ENV).is_some()
            || std::env::var_os(gitblob::CACHE_ROOT_ENV).is_some()
        {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "analyzer::store::tests::unwritable_workspace_root_reports_the_ways_out",
                    "--nocapture",
                ])
                .env_remove(gitblob::CACHE_DIR_ENV)
                .env_remove(gitblob::CACHE_ROOT_ENV)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{output:?}"
            );
            return;
        }

        let temp = tempfile::TempDir::new().unwrap();
        let workspace_root = temp.path().join("repo");
        std::fs::create_dir(&workspace_root).unwrap();
        git2::Repository::init(&workspace_root).unwrap();
        std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o555)).unwrap();

        // POSIX mode bits do not constrain uid 0 (nor a process holding
        // CAP_DAC_OVERRIDE): the 0o555 injection cannot deny the write, the
        // store opens, and the assertion below would then fail for a reason
        // that is not the product's (issue #5090). Probe for a write denial the
        // way `cache_db::cache_write_denial` does, and assert the actionable
        // message only where the mode bits actually deny this process. CI runs
        // as the non-root `runner` user, which they do constrain.
        if tempfile::NamedTempFile::new_in(&workspace_root).is_ok() {
            std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o755))
                .unwrap();
            eprintln!(
                "skipping unwritable_workspace_root_reports_the_ways_out: this process \
                 bypasses the injected 0o555 write denial (issue #5090)"
            );
            return;
        }

        let opened = AnalyzerStore::open_for_workspace(&workspace_root);
        let error = match opened {
            Ok(_) => panic!("an unwritable workspace root must not open a persisted store"),
            Err(error) => error,
        };

        // Restored before any assertion can fail, so the tempdir still cleans up.
        std::fs::set_permissions(&workspace_root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let message = error.to_string();
        assert!(
            message.contains("permission denied for")
                && message.contains(&workspace_root.display().to_string())
                && message.contains("elevated filesystem permissions"),
            "{message}"
        );
    }

    #[cfg(test)]
    #[test]
    fn non_git_root_uses_in_memory_store_and_roundtrips_registry() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = AnalyzerStore::open_for_workspace(temp.path()).unwrap();
        assert!(store.is_ephemeral());
        assert!(store.db_path().is_none());

        let one = Oid::hash_object(ObjectType::Blob, b"one").unwrap();
        let two = Oid::hash_object(ObjectType::Blob, b"two").unwrap();
        assert_eq!(
            store.missing_blobs(&[one, two], "rust").unwrap(),
            vec![one, two]
        );

        store
            .register_blobs(&[one], "rust", GenerationId::BOOTSTRAP)
            .unwrap();
        store
            .register_blobs(&[one], "rust", GenerationId::BOOTSTRAP)
            .unwrap();
        assert_eq!(store.missing_blobs(&[one, two], "rust").unwrap(), vec![two]);
        assert_eq!(store.missing_blobs(&[one], "python").unwrap(), vec![one]);
    }

    #[cfg(test)]
    #[test]
    fn parsed_blob_presence_requires_completed_parse_rows() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, b"class Registered:\n    pass\n").unwrap();

        store
            .register_blobs(&[oid], "python", GenerationId::BOOTSTRAP)
            .unwrap();

        assert!(store.contains_blob(oid, "python").unwrap());
        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "python".to_string())])
                .unwrap(),
            vec![(oid, "python".to_string())]
        );
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "b67515a85a44: reader checkout cleanup invalidated cached statements and connection functions"
    )]
    #[test]
    fn reader_checkout_preserves_prepared_statements_and_identity_functions() {
        use rusqlite::StatementStatus;

        let temp = tempfile::TempDir::new().unwrap();
        let persistent = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        let fallback = AnalyzerStore::open_in_memory_single_connection().unwrap();
        for store in [&persistent, &fallback] {
            for route in ["ordinary", "active", "streaming"] {
                if route == "streaming" {
                    store.begin_streaming_read();
                }
                for run in 1..=3 {
                    let reader = if route == "active" {
                        store.active_read_conn().unwrap()
                    } else {
                        store.checkout_read_conn().unwrap()
                    };
                    // Include the route in the text so writer fallback's three
                    // routes each start with their own prepared statement.
                    let sql = format!(
                        "SELECT 17, length(resolution_node_identity('reference', 7, 11)) /* {route} */"
                    );
                    let mut statement = reader.prepare_cached(&sql).unwrap();
                    let value: (i64, i64) = statement
                        .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
                        .unwrap();
                    assert_eq!(value, (17, 32));
                    assert_eq!(statement.get_status(StatementStatus::Run), run, "{route}");
                    assert_eq!(
                        statement.get_status(StatementStatus::RePrepare),
                        0,
                        "checkout of {route} reader must not invalidate cached SQL at run {run}"
                    );
                }
                if route == "streaming" {
                    store.end_streaming_read();
                }
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn derivation_mmap_build_cap_and_pool_checkin_agree() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        {
            let mut reader = store.checkout_read_conn().unwrap();
            reader.use_derivation_mmap().unwrap();
            assert_eq!(
                reader
                    .query_row("PRAGMA mmap_size", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                crate::cache_db::DERIVATION_MMAP_SIZE_BYTES,
                "the SQLite build must permit the full derivation map"
            );
            reader
                .execute_batch("CREATE TEMP TABLE mmap_reader_reuse_marker(value INTEGER); INSERT INTO mmap_reader_reuse_marker VALUES(1);")
                .unwrap();
        }
        let reader = store.checkout_read_conn().unwrap();
        // Prove that this is the returned connection, not a fresh reader whose
        // default map could hide a missing checkin restoration.
        assert_eq!(
            reader
                .query_row("SELECT value FROM mmap_reader_reuse_marker", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        assert_eq!(
            reader
                .query_row("PRAGMA mmap_size", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            crate::cache_db::READER_MMAP_SIZE_BYTES
        );
    }

    #[cfg(test)]
    /// Connections `counting_reader_open` opened, which is the only way to
    /// observe how many a pool built: the pool takes its opener as a bare `fn`
    /// pointer, so the count has to live beside it rather than be captured.
    static BURST_READER_OPENS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    fn counting_reader_open(path: &Path) -> crate::cache_db::Result<Connection> {
        BURST_READER_OPENS.fetch_add(1, Ordering::Relaxed);
        crate::cache_db::open_readonly_temp_connection(path)
    }

    #[cfg(test)]
    /// A burst wider than the pool is gated at `capacity`, and a second burst
    /// opens nothing at all (#2632).
    ///
    /// Before the gate, checkout never blocked: the idle vector was empty, so
    /// every one of the `4 * capacity` workers opened its own connection, ran
    /// the 540-line revisioned-view script on it and dropped it on checkin --
    /// the shape that cost a 120-worker rayon burst about 104 cold opens per
    /// wave. `capacity` total opens is therefore the whole contract: it says
    /// no checkout ever found the pool empty after warm-up, so it also says no
    /// more than `capacity` readers were ever live at once.
    ///
    /// The barrier is `capacity` wide, not `burst` wide. It forces exactly as
    /// many simultaneous checkouts as the gate permits, which is what makes
    /// `capacity` opens deterministic rather than a race; a `burst`-wide
    /// barrier would deadlock against the gate by construction.
    ///
    /// The capacity is fixed at 48 so the test does not depend on the host.
    /// It is above the 32 that capped both concurrency and retention until
    /// 2026-09-24, so the barrier releases only if a burst wider than 32 runs
    /// at once, and the second round opens nothing only if the pool kept all
    /// 48 readers.
    #[test]
    fn reader_pool_gates_a_wide_burst_at_capacity_and_reuses_its_readers() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        store.readers.capacity = 48;
        let store = Arc::new(store);
        let capacity = store.readers.capacity;
        let burst = capacity * 4;
        BURST_READER_OPENS.store(0, Ordering::Relaxed);

        for round in 1..=2 {
            let all_out = Arc::new(std::sync::Barrier::new(capacity));
            std::thread::scope(|scope| {
                for _ in 0..burst {
                    let store = Arc::clone(&store);
                    let all_out = Arc::clone(&all_out);
                    scope.spawn(move || {
                        let reader = store
                            .read_conn_from_pool(&store.readers, counting_reader_open)
                            .unwrap();
                        let tables: i64 = reader
                            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
                            .unwrap();
                        assert!(tables > 0);
                        all_out.wait();
                    });
                }
            });

            assert_eq!(
                capacity,
                BURST_READER_OPENS.load(Ordering::Relaxed),
                "round {round}: a {burst}-wide burst must open {capacity} connections in total",
            );
            assert_eq!(
                capacity,
                store.readers.idle_len(),
                "round {round}: every gated reader must come back to the pool",
            );
        }
    }

    #[cfg(test)]
    /// #3798: every checkout is out, and each holder asks for a nested one, as
    /// a Rust reverse operation does when it confirms a candidate blob. Before
    /// nested checkouts skipped the gate, every thread waited for another's
    /// checkin and none came. The overflow readers close on checkin, so the
    /// resident pool stays at `capacity`.
    #[test]
    fn nested_checkouts_at_capacity_do_not_wait_for_each_other() {
        let mut pool = ReaderPool::new(None);
        pool.capacity = 2;
        let open = |statistics_epoch| SelectedReader {
            conn: Connection::open_in_memory().unwrap(),
            selection: None,
            resolution_selection: None,
            statistics_epoch,
            query_planner_stability_before_resolution: None,
        };
        let all_out = std::sync::Barrier::new(pool.capacity);
        std::thread::scope(|scope| {
            for _ in 0..pool.capacity {
                scope.spawn(|| {
                    let (outer_epoch, outer) = pool.acquire();
                    let outer = outer.unwrap_or_else(|| open(outer_epoch));
                    all_out.wait();
                    let (inner_epoch, inner) = pool.acquire();
                    pool.checkin(inner.unwrap_or_else(|| open(inner_epoch)));
                    pool.checkin(outer);
                });
            }
        });
        let state = pool.state.lock().unwrap();
        assert!(state.holders.is_empty(), "{:?}", state.holders);
        assert_eq!(pool.capacity, state.idle.len());
    }

    #[cfg(test)]
    /// The same two bursts through the workspace-selection path: #2883's view
    /// script runs once per connection, and the gate is what bounds the number
    /// of connections, so `4 * capacity` checkouts twice over cost exactly
    /// `capacity` view scripts rather than `capacity` plus one per cold open.
    #[test]
    fn a_gated_burst_creates_one_view_script_run_per_pooled_reader() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        // Fixed so the test does not depend on the host's parallelism.
        store.readers.capacity = 16;
        let store = Arc::new(store);
        let capacity = store.readers.capacity;
        let burst = capacity * 4;
        let workspace_id =
            WorkspaceId("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
        let selection = Arc::new(WorkspaceSnapshots::from_iter([(
            "java".to_string(),
            WorkspaceSnapshotId {
                workspace_id,
                lang: "java".to_string(),
                generation: GenerationId::BOOTSTRAP,
                revision: 1,
            },
        )]));

        for _ in 0..2 {
            let all_out = Arc::new(std::sync::Barrier::new(capacity));
            std::thread::scope(|scope| {
                for _ in 0..burst {
                    let store = Arc::clone(&store);
                    let all_out = Arc::clone(&all_out);
                    let selection = Arc::clone(&selection);
                    scope.spawn(move || {
                        let reader = store.read_conn_for_workspace(&selection).unwrap();
                        all_out.wait();
                        drop(reader);
                    });
                }
            });
        }

        assert_eq!(
            (capacity, capacity),
            store.workspace_selection_counts_for_test(),
            "one view script and one selection write per pooled reader, and nothing per burst",
        );
    }

    #[cfg(test)]
    /// Cost pin for #2883. `temp.selected_workspace_revisions` and the views
    /// over it belong to one connection, so a checkout that asks for the
    /// selection that connection already holds must only check freshness: no view
    /// script, no selection rewrite. A different selection is a real change and
    /// is written once.
    #[brokk_bifrost_test_macros::hardwon(
        "#2883: repeated workspace selection rewrote connection-local views on every checkout"
    )]
    #[test]
    fn a_repeated_workspace_selection_costs_the_connection_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        let workspace_id =
            WorkspaceId("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into());
        let selection = |revision| {
            WorkspaceSnapshots::from_iter([(
                "java".to_string(),
                WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang: "java".to_string(),
                    generation: GenerationId::BOOTSTRAP,
                    revision,
                },
            )])
        };

        drop(store.read_conn_for_workspace(&selection(1)).unwrap());
        assert_eq!(
            store.workspace_selection_counts_for_test(),
            (1, 1),
            "the first checkout creates the views and writes the selection once"
        );

        drop(store.read_conn_for_workspace(&selection(1)).unwrap());
        assert_eq!(
            store.workspace_selection_counts_for_test(),
            (1, 1),
            "the same selection and freshness must reuse the existing temporary rows"
        );

        drop(store.read_conn_for_workspace(&selection(2)).unwrap());
        assert_eq!(
            store.workspace_selection_counts_for_test(),
            (1, 2),
            "a different revision is a real change: written once, with no second view script"
        );

        let mut invalid = selection(3);
        invalid.insert("duplicate".into(), invalid["java"].clone());
        assert!(store.read_conn_for_workspace(&invalid).is_err());
        let reader = store.read_conn_for_workspace(&selection(2)).unwrap();
        assert_eq!(
            reader
                .query_row(
                    "SELECT revision FROM temp.selected_workspace_revisions",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2,
            "failed selection must roll back before the old cached selection is reused"
        );
        drop(reader);

        let mut reader = store.read_conn_for_workspace(&selection(2)).unwrap();
        reader.cleanup_before_checkin("DELETE FROM temp.selected_rust_unit_closure; DELETE FROM temp.selected_rust_unit_summaries; DELETE FROM temp.selected_workspace_revisions;");
        drop(reader);
        let reader = store.read_conn_for_workspace(&selection(2)).unwrap();
        assert_eq!(
            reader
                .query_row(
                    "SELECT revision FROM temp.selected_workspace_revisions",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2,
            "native cleanup must invalidate the remembered selection before reuse"
        );
        assert_eq!(store.workspace_selection_counts_for_test(), (1, 4));
        drop(reader);

        let mut reader = store.read_conn_for_workspace(&selection(2)).unwrap();
        reader.discard_before_checkin();
        drop(reader);
        assert_eq!(
            store.readers.state.lock().unwrap().holders.len(),
            0,
            "failed native initialization must release the pool permit"
        );
        assert_eq!(store.readers.idle_len(), 0);
    }

    #[cfg(test)]
    /// The prefilter must not change how the candidate scan is driven. A
    /// `LIKE '%literal%'` can never seek an index, so what is pinned here is the
    /// join order it could have flipped: the live blob set stays the outer table
    /// and `code_units` stays a primary-key seek from it. The reverse plan --
    /// scanning `code_units` and probing the temp table -- reads every
    /// declaration of every language in the database instead of only the live
    /// ones (issue #2316).
    #[brokk_bifrost_test_macros::hardwon(
        "#2316: candidate prefiltering caused SQLite to scan declarations outside live blobs"
    )]
    #[test]
    fn search_candidate_name_plan_is_driven_by_the_live_blob_set() {
        for state in PlannerStatisticsState::BOTH {
            search_candidate_name_plan_is_driven_by_the_live_blob_set_in(state);
        }
    }

    #[cfg(test)]
    fn search_candidate_name_plan_is_driven_by_the_live_blob_set_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        sync_active_blob_oids(&conn, &[]).unwrap();
        state.install(&conn);

        let unfiltered = explain_pin(&conn, &pinned("search_candidate_name_rows_unfiltered"));
        let prefiltered = explain_pin(&conn, &pinned("search_candidate_name_rows_prefiltered"));
        assert_eq!(
            unfiltered, prefiltered,
            "the prefilter must not change the plan {state}"
        );
        assert!(
            prefiltered.iter().any(|detail| detail
                .contains("SEARCH keys USING COVERING INDEX sqlite_autoindex_blobs_1")),
            "each live blob OID must intern through the unique index {state}: {prefiltered:#?}"
        );
        assert!(
            prefiltered
                .iter()
                .any(|detail| detail.contains("SEARCH units USING PRIMARY KEY")),
            "declarations must be sought per live blob {state}: {prefiltered:#?}"
        );
        assert!(
            !prefiltered
                .iter()
                .any(|detail| detail.contains("SCAN units")),
            "the declaration table must never be scanned {state}: {prefiltered:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn cpp_owner_search_plan_seeks_live_bodies_and_named_classes() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().expect("store mutex");
            sync_active_blob_oids(&conn, &[]).unwrap();
            state.install(&conn);
            for label in [
                "cpp_search_owner_name_rows_unfiltered",
                "cpp_search_owner_name_rows_prefiltered",
            ] {
                let plan = explain_pin(&conn, &pinned(label));
                assert!(
                    plan.iter()
                        .any(|row| row.contains("SEARCH units USING PRIMARY KEY")),
                    "{state}: {plan:#?}"
                );
                assert!(
                    plan.iter().any(|row| row.contains(
                        "SEARCH owner USING INDEX idx_code_units_lang_identifier_lookup"
                    )),
                    "{state}: {plan:#?}"
                );
                assert!(
                    plan.iter()
                        .any(|row| row.contains("source_declaration_units_unit")),
                    "{state}: {plan:#?}"
                );
                assert!(
                    !plan
                        .iter()
                        .any(|row| row.contains("SCAN units") || row.contains("SCAN owner")),
                    "{state}: {plan:#?}"
                );
            }
        }
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "#2785: by-key candidate hydration scanned unrelated declarations before the requested blob"
    )]
    #[test]
    fn search_candidate_key_plan_is_driven_by_the_requested_blob() {
        for state in PlannerStatisticsState::BOTH {
            search_candidate_key_plan_is_driven_by_the_requested_blob_in(state);
        }
    }

    #[cfg(test)]
    fn search_candidate_key_plan_is_driven_by_the_requested_blob_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let query = pinned("search_candidate_key_set");
        let sql = &query.sql;
        let plan = explain_pin(&conn, &query);

        let blob_seek = plan
            .iter()
            .position(|detail| {
                detail.contains(
                    "SEARCH keys USING COVERING INDEX sqlite_autoindex_blobs_1 (blob_oid=? AND lang=?)",
                )
            })
            .unwrap_or_else(|| panic!("the by-key query must seek the blob OID {state}: {plan:#?}"));
        let unit_seek = plan
            .iter()
            .position(|detail| {
                detail.contains("SEARCH units USING PRIMARY KEY (blob_id=? AND unit_key=?)")
            })
            .unwrap_or_else(|| {
                panic!("the by-key query must seek code_units by blob {state}: {plan:#?}")
            });
        assert!(
            blob_seek < unit_seek,
            "the requested blob must drive its code_units probe {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN units")),
            "the by-key query must not scan code_units {state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("idx_code_units_lang_identifier_lookup")),
            "the by-key query must not fall back to the language-wide index {state}: {plan:#?}"
        );
        assert!(
            sql.contains("requested.blob_oid")
                && sql.contains("requested.lang")
                && sql.contains("requested.unit_key")
                && sql.contains("active_blob.generation"),
            "the by-key query must retain blob, language, and live-generation predicates: {sql}"
        );
    }

    #[cfg(test)]
    #[test]
    fn search_candidate_key_hydration_honors_cancellation_before_batch() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let result = store
            .search_candidate_rows_for_keys(
                &["java".to_string()],
                &HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]),
                &[SearchCandidateKey {
                    lang_index: 0,
                    blob_oid: oid_for(b"missing candidate blob"),
                    unit_key: 0,
                }],
                Some(&cancellation),
            )
            .unwrap();

        assert!(!result.complete);
        assert!(result.rows.is_empty());
        assert_eq!(result.inspected, 0);
    }

    #[cfg(test)]
    /// A literal is matched as text, so the two characters `LIKE` would read as
    /// wildcards are escaped for `ESCAPE '\'`.
    #[test]
    fn like_contains_pattern_escapes_wildcards() {
        assert_eq!(like_contains_pattern("valueflow"), "%valueflow%");
        assert_eq!(like_contains_pattern("run_taint"), r"%run\_taint%");
        assert_eq!(like_contains_pattern(r"a%b_c\d"), r"%a\%b\_c\\d%");
    }

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "4fb16a86137c: mutation review found a flag-only update kept stale import gating"
    )]
    fn workspace_projection_updates_requires_imports_with_unchanged_oid() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut symbol = PathSymbolRow {
            rel_path: "pkg/model.py".into(),
            blob_oid: oid_for(b"class Model:\n    pass\n"),
            kind: CodeUnitType::Module,
            package_name: "pkg".into(),
            short_name: "model".into(),
            exact_fqn: "pkg.model".into(),
            normalized_fqn: "pkg.model".into(),
            requires_imports: false,
        };
        let file = WorkspaceFileRow {
            rel_path: symbol.rel_path.clone(),
            blob_oid: symbol.blob_oid,
        };
        for requires_imports in [false, true] {
            symbol.requires_imports = requires_imports;
            store
                .sync_workspace_snapshot(
                    "python",
                    GenerationId::BOOTSTRAP,
                    std::slice::from_ref(&file),
                    std::slice::from_ref(&symbol),
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap();
            let snapshots = store
                .workspace_snapshots_for_langs(
                    &WorkspaceId("a".repeat(64)),
                    &["python".into()],
                    &HashMap::from_iter([("python".into(), GenerationId::BOOTSTRAP)]),
                )
                .unwrap();
            let conn = store.read_conn_for_workspace(&snapshots).unwrap();
            let stored_flag = conn
                .query_row(
                    "SELECT symbols.requires_imports
                     FROM workspace_file_path_symbol_rows AS symbols
                     JOIN workspace_files AS files ON files.file_id = symbols.file_version_id
                     WHERE files.rel_path = ?1",
                    [&file.rel_path],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap();
            assert_eq!(stored_flag, requires_imports);
        }
    }

    #[cfg(test)]
    #[test]
    fn unchanged_path_symbol_snapshot_skips_table_reconciliation() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let row = PathSymbolRow {
            rel_path: "pkg/model.py".to_string(),
            blob_oid: oid_for(b"class Model:\n    pass\n"),
            kind: CodeUnitType::Module,
            package_name: "pkg".to_string(),
            short_name: "model".to_string(),
            exact_fqn: "pkg.model".to_string(),
            normalized_fqn: "pkg.model".to_string(),
            requires_imports: false,
        };

        store
            .sync_workspace_snapshot(
                "python",
                GenerationId::BOOTSTRAP,
                &[WorkspaceFileRow {
                    rel_path: row.rel_path.clone(),
                    blob_oid: row.blob_oid,
                }],
                std::slice::from_ref(&row),
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let rows_after_cold_sync = {
            let conn = store.conn.lock().expect("store mutex");
            (
                conn.query_row("SELECT COUNT(*) FROM workspace_revisions", [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap(),
                conn.query_row("SELECT COUNT(*) FROM workspace_file_versions", [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap(),
            )
        };
        store
            .sync_workspace_snapshot(
                "python",
                GenerationId::BOOTSTRAP,
                &[WorkspaceFileRow {
                    rel_path: row.rel_path.clone(),
                    blob_oid: row.blob_oid,
                }],
                std::slice::from_ref(&row),
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let rows_after_warm_sync = {
            let conn = store.conn.lock().expect("store mutex");
            (
                conn.query_row("SELECT COUNT(*) FROM workspace_revisions", [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap(),
                conn.query_row("SELECT COUNT(*) FROM workspace_file_versions", [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap(),
            )
        };

        assert_eq!(rows_after_warm_sync, rows_after_cold_sync);
    }

    #[cfg(test)]
    #[test]
    fn retained_workspace_revision_keeps_exact_file_and_child_projection() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id =
            WorkspaceId("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        let generation = GenerationId::BOOTSTRAP;
        let old_a = WorkspaceFileRow {
            rel_path: "src/A.java".into(),
            blob_oid: oid_for(b"old A"),
        };
        let old_b = WorkspaceFileRow {
            rel_path: "src/B.java".into(),
            blob_oid: oid_for(b"old B"),
        };
        let old_symbols = [old_a.clone(), old_b.clone()].map(|file| PathSymbolRow {
            rel_path: file.rel_path,
            blob_oid: file.blob_oid,
            kind: CodeUnitType::Class,
            package_name: "pkg".into(),
            short_name: "Old".into(),
            exact_fqn: "pkg.Old".into(),
            normalized_fqn: "pkg.Old".into(),
            requires_imports: false,
        });
        let old_members = [old_a.rel_path.clone(), old_b.rel_path.clone()].map(|rel_path| {
            WorkspacePackageFileRow {
                package_name: "pkg".into(),
                rel_path,
            }
        });
        let old_edges = [old_a.rel_path.clone(), old_b.rel_path.clone()].map(|rel_path| {
            WorkspacePackageEdgeRow {
                rel_path,
                parent_package_name: String::new(),
                child_package_name: "pkg".into(),
            }
        });
        let old_anchors =
            [old_a.rel_path.clone(), old_b.rel_path.clone()].map(|rel_path| WorkspaceAnchorRow {
                rel_path,
                anchor: PackageAnchor::OwnModule { pop: 0 },
                package_name: "pkg".into(),
            });
        let r1 = store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "java",
                generation,
                &[old_a, old_b],
                &old_symbols,
                &[String::new(), "pkg".into()],
                &old_members,
                &old_edges,
                &old_anchors,
            )
            .unwrap();

        let new_a = WorkspaceFileRow {
            rel_path: "src/A.java".into(),
            blob_oid: oid_for(b"new A"),
        };
        let new_c = WorkspaceFileRow {
            rel_path: "src/C.java".into(),
            blob_oid: oid_for(b"new C"),
        };
        let new_symbols = [new_a.clone(), new_c.clone()].map(|file| PathSymbolRow {
            rel_path: file.rel_path,
            blob_oid: file.blob_oid,
            kind: CodeUnitType::Class,
            package_name: "next".into(),
            short_name: "New".into(),
            exact_fqn: "next.New".into(),
            normalized_fqn: "next.New".into(),
            requires_imports: false,
        });
        let new_members = [new_a.rel_path.clone(), new_c.rel_path.clone()].map(|rel_path| {
            WorkspacePackageFileRow {
                package_name: "next".into(),
                rel_path,
            }
        });
        let new_edges = [new_a.rel_path.clone(), new_c.rel_path.clone()].map(|rel_path| {
            WorkspacePackageEdgeRow {
                rel_path,
                parent_package_name: String::new(),
                child_package_name: "next".into(),
            }
        });
        let new_anchors =
            [new_a.rel_path.clone(), new_c.rel_path.clone()].map(|rel_path| WorkspaceAnchorRow {
                rel_path,
                anchor: PackageAnchor::OwnModule { pop: 0 },
                package_name: "next".into(),
            });
        let r2 = store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "java",
                generation,
                &[new_a.clone(), new_c.clone()],
                &new_symbols,
                &[String::new(), "next".into()],
                &new_members,
                &new_edges,
                &new_anchors,
            )
            .unwrap();
        assert_eq!(r2.revision, r1.revision + 1);

        let conn = store.conn.lock().expect("store mutex");
        for (snapshot, expected_paths, expected_package) in [
            (&r1, vec!["src/A.java", "src/B.java"], "pkg"),
            (&r2, vec!["src/A.java", "src/C.java"], "next"),
        ] {
            store
                .select_writer_workspace_snapshots(
                    &conn,
                    &HashMap::from_iter([("java".to_string(), snapshot.clone())]),
                )
                .unwrap();
            let paths = conn
                .prepare("SELECT rel_path FROM workspace_files ORDER BY rel_path")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(paths, expected_paths);
            for (relation, expected_count) in [
                ("workspace_package_files", 2),
                ("workspace_package_edges", 1),
                ("workspace_file_anchors", 2),
                (
                    "main.workspace_file_path_symbol_rows AS rows
                     JOIN workspace_files AS files
                       ON files.file_id = rows.file_version_id",
                    2,
                ),
            ] {
                let count = conn
                    .query_row(&format!("SELECT COUNT(*) FROM {relation}"), [], |row| {
                        row.get::<_, usize>(0)
                    })
                    .unwrap();
                assert_eq!(count, expected_count, "{relation} is revision-bound");
            }
            assert_eq!(
                conn.query_row(
                    "SELECT package_name FROM workspace_package_files LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
                expected_package
            );
        }
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM workspace_file_versions", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap(),
            4
        );
        drop(conn);

        let unchanged = store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "java",
                generation,
                &[new_a, new_c],
                &new_symbols,
                &[String::new(), "next".into()],
                &new_members,
                &new_edges,
                &new_anchors,
            )
            .unwrap();
        assert_eq!(unchanged, r2);
    }

    #[cfg(test)]
    #[test]
    fn one_file_updates_grow_temporal_projection_by_one_row_each() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let workspace_id =
            WorkspaceId("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        let generation = GenerationId::BOOTSTRAP;
        let files = (0..10_000)
            .map(|index| WorkspaceFileRow {
                rel_path: format!("src/File{index}.java"),
                blob_oid: oid_for(format!("old {index}").as_bytes()),
            })
            .collect::<Vec<_>>();
        // One fact per file makes this a regression for the production-scale
        // grouping path. Rescanning the complete fact collection once per file
        // turns this initial publication quadratic before SQLite writes begin.
        let path_symbols = files
            .iter()
            .enumerate()
            .map(|(index, file)| PathSymbolRow {
                rel_path: file.rel_path.clone(),
                blob_oid: file.blob_oid,
                kind: CodeUnitType::Class,
                package_name: "example".into(),
                short_name: format!("File{index}"),
                exact_fqn: format!("example.File{index}"),
                normalized_fqn: format!("example.File{index}"),
                requires_imports: false,
            })
            .collect::<Vec<_>>();
        let first = store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "java",
                generation,
                &files,
                &path_symbols,
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let langs = vec!["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), generation)]);
        let mut snapshots = HashMap::from_iter([("java".to_string(), first)]);
        for index in 0..100 {
            let rel_path = format!("src/File{index}.java");
            snapshots = store
                .replace_path_symbol_unit(
                    &workspace_id,
                    &snapshots,
                    &langs,
                    &generations,
                    &rel_path,
                    Some(("java", oid_for(format!("new {index}").as_bytes()))),
                    None,
                    &[],
                    &[],
                    &[],
                    &[],
                    None,
                )
                .unwrap();
        }
        let conn = store.conn.lock().expect("store mutex");
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM workspace_file_versions", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap(),
            10_100
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM workspace_file_versions WHERE valid_until IS NULL",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            10_000
        );
    }

    #[cfg(test)]
    #[test]
    fn retained_logical_revision_does_not_pin_wal_and_roots_its_blob() {
        let temp = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        let workspace_id =
            WorkspaceId("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into());
        let generation = GenerationId::BOOTSTRAP;
        let old_oid = oid_for(b"old");
        store
            .conn
            .execute(move |conn| {
                conn.execute(
                    "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 0)",
                    [old_oid.to_string()],
                )?;
                Ok::<(), StoreError>(())
            })
            .unwrap();
        let r1 = store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "java",
                generation,
                &[WorkspaceFileRow {
                    rel_path: "Old.java".into(),
                    blob_oid: old_oid,
                }],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let r1_snapshots = HashMap::from_iter([("java".to_string(), r1)]);
        {
            let conn = store.read_conn_for_workspace(&r1_snapshots).unwrap();
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM workspace_files", [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap(),
                1
            );
        }
        store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "java",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        assert_eq!(store.gc_with(|_| false).unwrap(), 0);
        let checkpoint = store
            .conn
            .execute(|conn| {
                Ok::<_, StoreError>(conn.query_row(
                    "PRAGMA wal_checkpoint(TRUNCATE)",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?)
            })
            .unwrap();
        assert_eq!(checkpoint.0, 0, "logical snapshots hold no SQLite reader");
        let conn = store.read_conn_for_workspace(&r1_snapshots).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1",
                [old_oid.to_string()],
                |row| { row.get::<_, usize>(0) }
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT rel_path FROM workspace_files", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "Old.java"
        );
    }

    #[cfg(test)]
    /// Every table the full verification predicate re-counts. The read-path
    /// membership plan must name none of them.
    fn verified_fact_tables() -> Vec<&'static str> {
        let mut tables = vec![
            "code_units",
            "unit_ranges",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_supertypes",
            "unit_children",
            "import_statements",
            "reference_identifiers",
            "blob_reference_fact_manifests",
            "blob_optional_fact_manifest",
        ];
        tables.extend(
            OPTIONAL_FACT_DESCRIPTORS
                .iter()
                .map(|descriptor| descriptor.table),
        );
        tables
    }

    #[cfg(test)]
    /// The hydration membership query must seek both keyed tables it names and
    /// read no fact table at all. A plan that reaches a fact table is the full
    /// verification predicate leaking back onto the read path, which is what
    /// charged 56.2 us per key on the firefox cold start.
    #[brokk_bifrost_test_macros::hardwon(
        "bc616e71979d: read-path membership re-counted every persisted fact table for each key"
    )]
    #[test]
    fn read_path_membership_query_seeks_keys_without_reading_fact_tables() {
        for state in PlannerStatisticsState::BOTH {
            read_path_membership_query_seeks_keys_without_reading_fact_tables_in(state);
        }
    }

    #[cfg(test)]
    fn read_path_membership_query_seeks_keys_without_reading_fact_tables_in(
        state: PlannerStatisticsState,
    ) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("read_path_parsed_blob_membership"));

        assert!(
            plan.iter().any(|detail| detail
                .contains("SEARCH keys USING COVERING INDEX sqlite_autoindex_blobs_1")),
            "the (blob_oid, lang) pair must intern through the unique index, and \
             that index covers the id it returns, so this seek never reads the \
             blobs table itself {state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH meta USING PRIMARY KEY")),
            "the interned key must seek blob_meta {state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH active_blob USING INTEGER PRIMARY KEY")),
            "the active-generation check must seek blobs by its rowid id {state}: {plan:#?}"
        );
        for table in verified_fact_tables() {
            assert!(
                !plan.iter().any(|detail| detail.contains(table)),
                "the read-path plan must not touch {table} {state}: {plan:#?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn gc_drops_unreachable_blob_registry_rows() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let reachable = Oid::hash_object(ObjectType::Blob, b"reachable").unwrap();
        let unreachable = Oid::hash_object(ObjectType::Blob, b"unreachable").unwrap();
        store
            .register_blobs(&[reachable, unreachable], "rust", GenerationId::BOOTSTRAP)
            .unwrap();

        let mut bloom = GrowableBloom::new(0.01, 8);
        bloom.insert(reachable.to_string());
        assert_eq!(store.gc_with_bloom(&bloom).unwrap(), 1);
        assert_eq!(
            store
                .missing_blobs(&[reachable, unreachable], "rust")
                .unwrap(),
            vec![unreachable]
        );
    }

    #[cfg(test)]
    #[test]
    fn persistent_epoch_publishers_serialize_same_and_different_epochs() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        drop(AnalyzerStore::open_persistent(&db).unwrap());
        let same_barrier = Arc::new(std::sync::Barrier::new(2));
        let same_handles = [0, 1].map(|_| {
            let barrier = Arc::clone(&same_barrier);
            let db = db.clone();
            std::thread::spawn(move || {
                let store = AnalyzerStore::open_persistent(&db).unwrap();
                barrier.wait();
                store.ensure_language_epoch_value("java", "same").unwrap()
            })
        });
        let same = same_handles.map(|handle| handle.join().unwrap());
        assert_eq!(same[0], same[1]);

        let different_barrier = Arc::new(std::sync::Barrier::new(2));
        let different_handles = ["left", "right"].map(|epoch| {
            let barrier = Arc::clone(&different_barrier);
            let db = db.clone();
            std::thread::spawn(move || {
                let store = AnalyzerStore::open_persistent(&db).unwrap();
                barrier.wait();
                let generation = store.ensure_language_epoch_value("java", epoch).unwrap();
                (epoch, generation)
            })
        });
        let different = different_handles.map(|handle| handle.join().unwrap());
        assert_ne!(different[0].1, different[1].1);

        let conn = crate::cache_db::open_unified_connection(&db).unwrap();
        let final_pair: (String, i64) = conn
            .query_row(
                "SELECT epoch, generation FROM analysis_epochs WHERE lang = 'java'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            different.iter().any(|(epoch, generation)| {
                *epoch == final_pair.0 && generation.0 == final_pair.1
            })
        );
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "8c91d98583fb: opening a matching persistent epoch waited behind unrelated writer work"
    )]
    #[test]
    fn matching_persistent_epoch_does_not_wait_for_the_writer_slot() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        let writer = AnalyzerStore::open_persistent(&db).unwrap();
        let reader = AnalyzerStore::open_persistent(&db).unwrap();
        let observer = AnalyzerStore::open_persistent(&db).unwrap();
        let generation = writer.ensure_language_epoch_value("java", "same").unwrap();
        let submissions_before_blocker = observer.conn.execute_submissions();

        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let blocker = std::thread::spawn(move || {
            writer.conn.execute(move |conn| {
                let writer_tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                writer_tx.rollback().unwrap();
            });
        });
        entered_rx.recv().unwrap();
        let baseline_submissions = observer.conn.execute_submissions();
        assert_eq!(
            baseline_submissions,
            submissions_before_blocker + 1,
            "the blocked generic execute must be visible to every shared writer handle"
        );

        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let matching = std::thread::spawn(move || {
            result_tx
                .send(reader.ensure_language_epoch_value("java", "same"))
                .unwrap();
        });
        let mut unexpected_submissions = None;
        let observed = loop {
            match result_rx.try_recv() {
                Ok(result) => break Some(result),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break None,
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            let submissions = observer.conn.execute_submissions();
            if submissions != baseline_submissions {
                unexpected_submissions = Some(submissions);
                break None;
            }
            std::thread::yield_now();
        };
        release_tx.send(()).unwrap();
        blocker.join().unwrap();
        matching.join().unwrap();
        assert_eq!(
            unexpected_submissions, None,
            "a matching epoch submitted to the blocked writer: baseline {baseline_submissions}"
        );
        let observed = observed
            .expect("the matching epoch worker disconnected before returning")
            .unwrap();
        assert_eq!(
            observer.conn.execute_submissions(),
            baseline_submissions,
            "a matching epoch must use the read pool instead of the blocked writer"
        );
        assert_eq!(observed, generation);
    }

    // Preparation budgets JSONB with maximum headers and shared-ID spellings.
    // Read committed relation lengths independently of the cached blob cost and
    // the replacement fallback, then retain exact byte-equality assertions.
    #[doc(hidden)]
    pub fn measured_persisted_payload_bytes(
        conn: &Connection,
        prepared: &PreparedParsedBlob,
    ) -> usize {
        let (blob_id, manifest_bytes): (i64, usize) = conn
            .query_row(
                "SELECT blob.id, interior.payload_bytes FROM blobs AS blob
                 JOIN resolution_fragment_interiors AS interior ON interior.blob_id = blob.id
                 WHERE blob.blob_oid = ?1 AND blob.lang = ?2",
                params![prepared.oid_text, prepared.lang],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let measured_resolution_bytes: usize = conn
            .query_row(
                resolution_manifest::COMPLETE_PUBLICATION_PAYLOAD_BYTES_SQL,
                [blob_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(manifest_bytes, measured_resolution_bytes);
        let measured_bytes = prepared
            .persisted_payload_bytes()
            .checked_sub(prepared.resolution.payload_bytes() + prepared.lang.len())
            .expect("preparation includes resolution and storage-language bytes")
            .checked_add(measured_resolution_bytes)
            .expect("fixture payload fits usize");
        assert!(
            measured_bytes <= prepared.persisted_payload_bytes(),
            "committed bytes {measured_bytes} exceed prepared bound {}",
            prepared.persisted_payload_bytes()
        );
        measured_bytes
    }

    #[cfg(test)]
    #[test]
    fn replacement_cost_set_uses_only_bounded_primary_key_probes() {
        for state in PlannerStatisticsState::BOTH {
            replacement_cost_set_uses_only_bounded_primary_key_probes_in(state);
        }
    }

    #[cfg(test)]
    fn replacement_cost_set_uses_only_bounded_primary_key_probes_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);

        let fast_plan = explain_pin(&conn, &pinned("stored_blob_cascade_costs"));
        for table in ["blob", "meta", "costs", "reference_manifest", "interior"] {
            let keyed = if table == "blob" {
                format!(
                    "SEARCH {table} USING INDEX sqlite_autoindex_blobs_1 (blob_oid=? AND lang=?)"
                )
            } else {
                format!("SEARCH {table} USING PRIMARY KEY")
            };
            assert!(
                fast_plan.iter().any(|detail| {
                    // Reading generation adds one table lookup to the same exact key seek.
                    detail
                        .replace("USING COVERING INDEX", "USING INDEX")
                        .contains(&keyed)
                }),
                "set lookup for {table} must seek its own key {state}: {fast_plan:#?}"
            );
            assert!(
                fast_plan
                    .iter()
                    .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                "set lookup must not scan persisted table {table} {state}: {fast_plan:#?}"
            );
        }
        assert!(
            fast_plan
                .iter()
                .all(|detail| !detail.contains("USE TEMP B-TREE")),
            "set lookup must not materialize grouping or ordering state {state}: {fast_plan:#?}"
        );

        let fallback_plan = explain_pin(&conn, &pinned("persisted_blob_mutation_cost_fallback"));
        for table in [
            "blob",
            "meta",
            "code_units",
            "unit_signatures",
            "unit_signature_metadata",
            "unit_supertypes",
            "import_statements",
            "reference_identifiers",
            "reference_manifest",
            "interior",
        ] {
            let keyed = if table == "blob" {
                format!(
                    "SEARCH {table} USING INDEX sqlite_autoindex_blobs_1 (blob_oid=? AND lang=?)"
                )
            } else {
                format!("SEARCH {table} USING PRIMARY KEY")
            };
            assert!(
                fallback_plan.iter().any(|detail| {
                    // Reading generation adds one table lookup to the same exact key seek.
                    detail
                        .replace("USING COVERING INDEX", "USING INDEX")
                        .contains(&keyed)
                }),
                "legacy replacement-cost branch for {table} must seek its own key {state}: {fallback_plan:#?}"
            );
            assert!(
                fallback_plan
                    .iter()
                    .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                "legacy replacement-cost branch for {table} must not scan {state}: {fallback_plan:#?}"
            );
        }
        assert!(
            fallback_plan
                .iter()
                .all(|detail| !detail.contains("USE TEMP B-TREE")),
            "legacy replacement-cost fallback must not materialize grouping state {state}: {fallback_plan:#?}"
        );
        for table in ["site", "native", "property", "source", "marker"] {
            assert!(
                fallback_plan
                    .iter()
                    .any(|detail| detail.starts_with(&format!("SEARCH {table} "))),
                "canonical visibility cost must seek {table} by blob {state}: {fallback_plan:#?}"
            );
            assert!(
                fallback_plan
                    .iter()
                    .all(|detail| !detail.starts_with(&format!("SCAN {table}"))),
                "canonical visibility cost must not scan {table} {state}: {fallback_plan:#?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn limited_candidate_order_terms_survive_materialization() {
        for state in PlannerStatisticsState::BOTH {
            limited_candidate_order_terms_survive_materialization_in(state);
        }
    }

    #[cfg(test)]
    fn limited_candidate_order_terms_survive_materialization_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let query = pinned("direct_children_limited_candidate");
        let sql = &query.sql;
        assert!(
            sql.contains("edge.ordinal AS result_order_0")
                && sql.contains("child.unit_key AS result_order_1")
                && sql.contains("ORDER BY bounded.result_order_0, bounded.result_order_1"),
            "join-owned ordering terms must be projected through the bounded relation: {sql}"
        );
        let plan = explain_pin(&conn, &query);
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH edge USING PRIMARY KEY")),
            "the bounded direct-child query must retain its ordered edge relation {state}: {plan:#?}"
        );
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "#1748: rendered definition separators were not inverted into lookup identity components"
    )]
    #[test]
    fn rendered_name_components_invert_every_supported_boundary() {
        assert_eq!(
            rendered_name_components("pkg::thing.Value$Nested", false),
            vec![
                RenderedNameComponent {
                    prefix: String::new(),
                    tail: "pkg::thing.Value$Nested".to_string(),
                    normalized: false,
                    normalized_exact_fallback: false,
                    anchored: false,
                },
                RenderedNameComponent {
                    prefix: String::new(),
                    tail: "pkg::thing.Value$Nested".to_string(),
                    normalized: false,
                    normalized_exact_fallback: false,
                    anchored: true,
                },
                RenderedNameComponent {
                    prefix: "pkg".to_string(),
                    tail: "thing.Value$Nested".to_string(),
                    normalized: false,
                    normalized_exact_fallback: false,
                    anchored: true,
                },
                RenderedNameComponent {
                    prefix: "pkg::thing".to_string(),
                    tail: "Value$Nested".to_string(),
                    normalized: false,
                    normalized_exact_fallback: false,
                    anchored: true,
                },
                RenderedNameComponent {
                    prefix: "pkg::thing.Value".to_string(),
                    tail: "Nested".to_string(),
                    normalized: false,
                    normalized_exact_fallback: false,
                    anchored: true,
                },
                RenderedNameComponent {
                    prefix: "pkg::thing.Value$Nested".to_string(),
                    tail: String::new(),
                    normalized: false,
                    normalized_exact_fallback: false,
                    anchored: true,
                },
            ]
        );
    }

    #[cfg(test)]
    #[test]
    fn normalized_definition_components_probe_stored_normalized_tails() {
        let already_normalized = rendered_definition_components(
            0,
            &RenderedDefinitionRequest {
                exact_name: "app.api.v1".to_string(),
                normalized_name: "app.api.v1".to_string(),
                seekable: true,
            },
        );
        assert!(already_normalized.iter().any(|(_, component)| {
            component.normalized
                && component.prefix == "app.api"
                && component.tail == "v1"
                && !component.normalized_exact_fallback
        }));

        let changed_by_normalization = rendered_definition_components(
            0,
            &RenderedDefinitionRequest {
                exact_name: "app.Api.V1".to_string(),
                normalized_name: "app.api.v1".to_string(),
                seekable: true,
            },
        );
        assert!(changed_by_normalization.iter().any(|(_, component)| {
            component.normalized
                && component.prefix == "app.api"
                && component.tail == "v1"
                && component.normalized_exact_fallback
        }));
    }

    // EXPLAIN QUERY PLAN lists one row per loop in nesting order, so the position
    // of a row is the depth at which the relation is driven.
    #[cfg(test)]
    fn first_plan_row(plan: &[String], needles: &[&str]) -> Option<usize> {
        plan.iter()
            .position(|detail| needles.iter().all(|needle| detail.contains(needle)))
    }

    // The anchor package seek is the only selective entry point of an anchored
    // definition lookup. When the planner drives from the workspace file relation
    // instead, each probe walks every per-language workspace file version: on a
    // 1,447-file Ruby workspace that cost 2.510 ms per probe against 0.011 ms with
    // the seek outermost, and one bare-name definitions request runs thousands of
    // them (#2742).
    #[cfg(test)]
    fn assert_anchor_package_seek_is_outermost(plan: &[String], unit_relation: &str, label: &str) {
        let package_seek = first_plan_row(
            plan,
            &["idx_workspace_file_anchor_rows_package", "package_name=?"],
        )
        .unwrap_or_else(|| panic!("{label} must seek the anchor package index: {plan:#?}"));
        let unit_probe = first_plan_row(plan, &[unit_relation]).unwrap_or_else(|| {
            panic!("{label} must probe units through {unit_relation}: {plan:#?}")
        });
        assert!(
            package_seek < unit_probe,
            "{label} must seek the anchor package before it probes units: {plan:#?}"
        );
        assert!(
            first_plan_row(plan, &["versions"]).is_none_or(|index| package_seek < index),
            "{label} must seek the anchor package before it reads workspace file versions: {plan:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn anchored_definition_lookups_seek_the_anchor_package_outermost() {
        for state in PlannerStatisticsState::BOTH {
            anchored_definition_lookups_seek_the_anchor_package_outermost_in(state);
        }
    }

    #[cfg(test)]
    fn anchored_definition_lookups_seek_the_anchor_package_outermost_in(
        state: PlannerStatisticsState,
    ) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);

        for (name, unit_relation, label) in [
            (
                "point_anchor_only_definition_candidate",
                "SEARCH units USING PRIMARY KEY",
                "the anchor-only point lookup",
            ),
            (
                "batch_component_definition_candidate",
                "idx_code_units_anchored_blob_exact_tail",
                "the anchored batch component lookup",
            ),
            (
                "batch_anchor_only_definition_candidate",
                "SEARCH units USING PRIMARY KEY",
                "the anchor-only batch lookup",
            ),
        ] {
            assert_anchor_package_seek_is_outermost(
                &explain_pin(&conn, &pinned(name)),
                unit_relation,
                &format!("{label} {state}"),
            );
        }
    }

    // Issue #3030. The batch definition-candidate statements are pinned above
    // with one bound request, and the `laravel/framework` profile that motivated
    // issue #3016 shows the same statements issued with 6 to 542 of them, single
    // calls costing 40 to 58 s without planner statistics. Nothing chunks the
    // batch -- the requests ride in one JSON parameter -- so the SQL text is the
    // same at every arity, but the bound payload still reaches the planner: the
    // bundled SQLite is a `SQLITE_ENABLE_STAT4` build, which re-prepares a
    // statement using its bound values. This runs the production ladder and
    // asserts that the plan is the arity-one plan at every rung, in both
    // statistics states.
    #[cfg(test)]
    #[test]
    fn definition_candidate_batches_keep_their_plan_at_production_arity() {
        for state in PlannerStatisticsState::BOTH {
            definition_candidate_batches_keep_their_plan_at_production_arity_in(state);
        }
    }

    #[cfg(test)]
    fn definition_candidate_batches_keep_their_plan_at_production_arity_in(
        state: PlannerStatisticsState,
    ) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);

        for (family, unit_relation, label) in [
            (
                "batch_component_definition_candidate",
                "idx_code_units_anchored_blob_exact_tail",
                "the anchored batch component lookup",
            ),
            (
                "batch_anchor_only_definition_candidate",
                "SEARCH units USING PRIMARY KEY",
                "the anchor-only batch lookup",
            ),
        ] {
            let mut baseline: Option<(usize, Vec<String>)> = None;
            for arity in DEFINITION_CANDIDATE_ARITY_LADDER {
                let plan = explain_pin(&conn, &pinned(&format!("{family}_{arity}")));
                let at = format!("{label} at {arity} requests {state}");
                // The request rows must stay the driver: the anchor package
                // seek is the only selective entry point, and a batch that
                // enumerates workspace files first pays that per request
                // (#2742).
                assert_anchor_package_seek_is_outermost(&plan, unit_relation, &at);
                assert!(
                    plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                    "{at} must not build a transient index over the request rows: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| !detail.contains("SCAN units")
                        && !detail.contains("SCAN anchors")
                        && !detail.contains("SCAN keys")),
                    "{at} must not enumerate a persisted relation: {plan:#?}"
                );
                match &baseline {
                    None => baseline = Some((arity, plan)),
                    Some((base_arity, base_plan)) => assert_eq!(
                        &plan, base_plan,
                        "{label} plans {arity} requests differently from {base_arity} {state}, \
                         so the arity-one pin above does not cover production's statement"
                    ),
                }
            }
        }

        // The unanchored arm of the same statement reaches units through the
        // stable-tail index instead of an anchor package, so it is pinned on
        // that index rather than on the seek order.
        let mut baseline: Option<(usize, Vec<String>)> = None;
        for arity in DEFINITION_CANDIDATE_ARITY_LADDER {
            let plan = explain_pin(
                &conn,
                &pinned(&format!(
                    "batch_stable_component_definition_candidate_{arity}"
                )),
            );
            let at = format!("the stable batch component lookup at {arity} requests {state}");
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("idx_code_units_stable_exact_tail")
                        && detail.contains("<expr>=?")),
                "{at} must seek the complete request tail, not the language: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.contains("SCAN units")),
                "{at} must not enumerate language units: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                "{at} must not index the request rows to probe them per unit: {plan:#?}"
            );
            match &baseline {
                None => baseline = Some((arity, plan)),
                Some((base_arity, base_plan)) => assert_eq!(
                    &plan, base_plan,
                    "the stable batch component lookup plans {arity} requests differently from \
                     {base_arity} {state}"
                ),
            }
        }
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "#2794: anchor-only identities could not be recovered from relational definition storage"
    )]
    #[test]
    fn anchor_only_lookup_uses_the_null_tail_relation() {
        let sql = point_anchor_only_definition_candidate_sql("units.in_declarations = 1");
        assert!(sql.contains("units.exact_fqn_tail IS NULL"), "{sql}");
        assert!(
            !sql.contains("idx_code_units_anchored_blob_exact_tail"),
            "the partial exact-tail index excludes anchor-only identities: {sql}"
        );
    }

    // The C# arity-free lookup (#1063) reaches ``Widget`1`` through an
    // identifier *prefix*, which is only affordable as an index range. If the
    // planner ever reads `code_units` end to end for it, symbol lookup is back
    // to the per-language table walk #1688 and #1758 removed (194.3 s and
    // 443.1 s on the measured workspaces).
    // Issue #2794. `file_usage_graph.prefetch_targets` hydrates every mounted
    // declaration in the workspace through this one statement. Read through the
    // wide three-arm `live_definition_exact_names` view it cost 89.4 minutes on
    // dotnet/runtime against 4.2 s in the graph-only record: SQLite materialized
    // the compound view as a co-routine (including the path arm the caller's
    // `source_kind <> 'path'` discarded in full), built an AUTOMATIC PARTIAL
    // COVERING INDEX over the result, scanned all 802,432 `code_units` rows, and
    // sorted the join through a TEMP B-TREE. The lean view must instead walk the
    // workspace's own files and seek each blob's units by primary key.
    #[cfg(test)]
    #[test]
    fn mounted_declaration_scan_seeks_live_workspace_files() {
        for state in PlannerStatisticsState::BOTH {
            mounted_declaration_scan_seeks_live_workspace_files_in(state);
        }
    }

    #[cfg(test)]
    fn mounted_declaration_scan_seeks_live_workspace_files_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("mounted_declaration_scan"));

        assert_mounted_declaration_scan_plan(&plan, state, "mounted-declaration scan");
    }

    #[cfg(test)]
    fn assert_mounted_declaration_scan_plan(
        plan: &[String],
        state: PlannerStatisticsState,
        label: &str,
    ) {
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH units USING PRIMARY KEY")),
            "each mounted file's declarations must be a primary-key range in the {label} {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN units")),
            "the {label} must never read code_units end to end {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
            "the {label} must not build a transient index {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("CO-ROUTINE")),
            "the {label} must not materialize a compound view {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("TEMP B-TREE")),
            "the caller sorts in Rust, so the {label} must not sort {state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("workspace_file_path_symbol_rows")),
            "the path-symbol arm is discarded by the {label} and must not be read {state}: {plan:#?}"
        );
        // The workspace's own file versions are the outermost relation this
        // query is meant to walk, but they must be reached through a snapshot
        // range, never read end to end. `workspace_file_versions` holds every
        // workspace's rows: on a cache several worktrees share, a bare scan
        // reads all of them and filters, once per language. Both pinned states
        // reach it through one of these three selective entry points -- the
        // snapshot index range, the live-blob set of `idx_blobs_lang_generation`,
        // or the generated unique revision key (which includes input_kind
        // after migration 104) -- so requiring one bounded entry point costs
        // the query nothing and forbids the shared-cache regression.
        //
        // A real single-workspace store can legitimately plan a bare `SCAN
        // versions` here, and that is not a regression. Its statistics say
        // every row shares one (workspace_id, lang, generation) -- #3016
        // measured `789 789 789 789` for this index on tokio-rs/tokio -- so
        // the snapshot range covers the whole table and scanning it is the
        // cheaper way to read the same rows. Editing only that store's
        // `sqlite_stat1` to describe ten workspaces' worth of file versions
        // (`7890 789 789 789 1 1 1 1`), changing nothing else, puts the plan
        // straight back to
        // `SEARCH versions USING INDEX idx_workspace_file_versions_snapshot_blob`.
        // The planner adapts on its own; what has to be pinned is the shape
        // where the choice matters, and the captured fixture carries it
        // (9,687 rows, 1,001 per snapshot prefix).
        assert!(
            plan.iter().all(|detail| detail.trim() != "SCAN versions"),
            "the {label} must not read workspace_file_versions end to end {state}: {plan:#?}"
        );
        assert!(
            plan.iter().any(|detail| {
                detail.contains("idx_workspace_file_versions_snapshot_blob")
                    || detail.contains("idx_blobs_lang_generation")
                    || (detail.contains("sqlite_autoindex_workspace_file_versions_1")
                        && detail.contains("workspace_id=?")
                        && detail.contains("lang=?")
                        && detail.contains("generation=?")
                        && detail.contains("input_kind=?"))
            }),
            "the {label} must enter through the snapshot range, live-blob set, \
             or generated revision key {state}: {plan:#?}"
        );
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "#3035+888ce79b9d65: mounted declaration scans read rows outside the live workspace index"
    )]
    #[test]
    fn mounted_declaration_primary_range_scan_seeks_indexed_rows() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().expect("store mutex");
            state.install(&conn);
            let plan = explain_pin(
                &conn,
                &pinned("mounted_declaration_scan_with_primary_ranges"),
            );
            assert_mounted_declaration_scan_plan(
                &plan,
                state,
                "mounted-declaration primary-range scan",
            );
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("SEARCH primary_range USING PRIMARY KEY")),
                "primary-range mounted scan must seek ranges by their primary key {state}: {plan:#?}"
            );
        }
    }

    // Issue #2794. Every candidate query in the store hydrates its relational
    // identities through `candidate_fq_segments_sql`, one padded chunk of keys
    // at a time, so a bad plan here is a bad plan everywhere -- and the plan
    // only goes bad on the wide rungs, which is exactly what a large answer
    // uses. See that function's comment for what SQLite does without the hint.
    #[cfg(test)]
    #[test]
    fn hydration_chunks_seek_the_segment_primary_key() {
        for state in PlannerStatisticsState::BOTH {
            hydration_chunks_seek_the_segment_primary_key_in(state);
        }
    }

    #[cfg(test)]
    fn hydration_chunks_seek_the_segment_primary_key_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        for arity in [1usize, 16, 64, 256, 400] {
            let plan = explain_pin(&conn, &pinned(&format!("candidate_fq_segments_{arity}")));

            assert!(
                plan.iter().any(|detail| detail
                    .contains("SEARCH segments USING PRIMARY KEY (blob_id=? AND unit_key=?)")),
                "a {arity}-key chunk must seek the segment primary key {state}: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                "a {arity}-key chunk must not build a transient index over the segment table {state}: {plan:#?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    fn identifier_prefix_lookup_seeks_the_identifier_index() {
        for state in PlannerStatisticsState::BOTH {
            identifier_lookup_uses_index_in(state, "identifier_prefix_candidate", "prefix range");
        }
    }

    #[cfg(test)]
    #[test]
    fn file_identifier_lookup_seeks_identifier_index_before_blob_key_filter() {
        for state in PlannerStatisticsState::BOTH {
            identifier_lookup_uses_index_in(
                state,
                "limited_identifier_candidate_for_blob",
                "file-scoped lookup",
            );
        }
    }

    #[cfg(test)]
    fn identifier_lookup_uses_index_in(
        state: PlannerStatisticsState,
        query_name: &str,
        lookup_description: &str,
    ) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned(query_name));

        assert!(
            plan.iter().any(|detail| detail
                .contains("SEARCH units USING INDEX idx_code_units_lang_identifier_lookup")),
            "the {lookup_description} must seek the identifier index {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN units")),
            "the {lookup_description} must never scan code_units {state}: {plan:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn byte_successor_bounds_a_prefix_range() {
        assert_eq!(Some("Widgeta".to_string()), byte_successor("Widget`"));
        assert_eq!(Some("create%".to_string()), byte_successor("create$"));
        assert_eq!(None, byte_successor(""));
        // A multi-byte tail has no single-byte successor that stays UTF-8.
        assert_eq!(None, byte_successor("Wid\u{00e9}"));
    }

    #[cfg(test)]
    #[test]
    fn linked_worktrees_share_analyzer_db_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        std::fs::create_dir(&repo_root).unwrap();
        let repo = init_repo(&repo_root);
        std::fs::write(repo_root.join("tracked.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");

        let linked_root = temp.path().join("linked");
        let worktree = repo.worktree("linked", &linked_root, None).unwrap();
        let linked_repo = git2::Repository::open_from_worktree(&worktree).unwrap();
        assert!(linked_repo.is_worktree());

        assert_eq!(
            analyzer_db_path(&repo_root)
                .file_name()
                .and_then(|n| n.to_str()),
            Some(crate::cache_db::cache_db_file_name())
        );
        // Sharing must hold for both the default location and cache overrides.
        // The core path tests cover their individual directory layouts.
        assert_eq!(analyzer_db_path(&repo_root), analyzer_db_path(&linked_root));
    }

    #[cfg(test)]
    #[test]
    fn rejects_bad_blob_oid_hex() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        let err = conn
            .execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, ?2)",
                params!["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "rust"],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[cfg(test)]
    #[test]
    fn rejects_inverted_unit_range() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        insert_test_blob_and_unit(&conn);
        let err = conn
            .execute(
                "INSERT INTO unit_ranges(
                   blob_id, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line
                 ) VALUES((SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'), 'rust', 1, 0, 10, 2, 4, 3)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[cfg(test)]
    #[test]
    fn rejects_self_parent_child_edge() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        insert_test_blob_and_unit(&conn);
        let err = conn
            .execute(
                "INSERT INTO unit_children(blob_id, lang, parent_key, child_key, ordinal)
                 VALUES((SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'), 'rust', 1, 1, 0)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "CHECK");
    }

    #[cfg(test)]
    #[test]
    fn rejects_satellite_row_without_code_unit_parent() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        let err = conn
            .execute(
                "INSERT INTO unit_signatures(blob_id, lang, unit_key, ordinal, text)
                 VALUES((SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'), 'rust', 99, 0, 'fn orphan()')",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(err, "FOREIGN KEY");
    }

    #[cfg(test)]
    #[test]
    fn rejects_forbidden_persisted_code_unit_kinds() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        let file_scope_err = conn
            .execute(
                "INSERT INTO code_units(
                   blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
                   signature, synthetic, is_type_alias, top_level_ordinal,
                   in_declarations, in_definition_lookup
                 ) VALUES((SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'), 'rust', 1, 5, 'file', 'file', '', NULL, 0, 0, 0, 1, 0)",
                [TEST_OID],
            )
            .unwrap_err();
        assert_constraint_error(file_scope_err, "CHECK");

        let python_module_err = conn
            .execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'python')",
                [TEST_OID],
            )
            .and_then(|_| {
                conn.execute(
                    "INSERT INTO code_units(
                       blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
                       signature, synthetic, is_type_alias, top_level_ordinal,
                       in_declarations, in_definition_lookup
                     ) VALUES((SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'python'), 'python', 1, 3, 'mod', 'mod', '', NULL, 0, 0, 0, 1, 0)",
                    [TEST_OID],
                )
            })
            .unwrap_err();
        assert_constraint_error(python_module_err, "CHECK");
    }

    #[cfg(test)]
    const TEST_OID: &str = "1111111111111111111111111111111111111111";
    #[cfg(test)]
    fn import_shape_fixture() -> Vec<ImportInfo> {
        let path = |kind: Option<StructuredImportPathKind>, declaration_start_byte: usize| {
            Some(StructuredImportPath {
                segments: Vec::new(),
                kind,
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte,
            })
        };
        vec![
            // cpp: only the snippet is meaningful; no path, no binder.
            ImportInfo {
                raw_snippet: "#include <vector>".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: None,
                alias: None,
                path: None,
                binder_span: None,
            },
            // ruby: the required path string rides in `identifier`, still no path.
            ImportInfo {
                raw_snippet: "require 'json'".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("json".to_string()),
                alias: None,
                path: None,
                binder_span: None,
            },
            // js/ts named import: no path, but a binder span for the bound name.
            ImportInfo {
                raw_snippet: "import { Alpha as Beta } from 'm'".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("Alpha".to_string()),
                alias: Some("Beta".to_string()),
                path: None,
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 9,
                    end_byte: 14,
                }),
            },
            // ts namespace import: wildcard with an alias and no path.
            ImportInfo {
                raw_snippet: "import * as ns from 'm'".to_string(),
                is_wildcard: true,
                is_global: false,
                identifier: None,
                alias: Some("ns".to_string()),
                path: None,
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 12,
                    end_byte: 14,
                }),
            },
            // java wildcard: Namespace kind, no binder because nothing is bound.
            ImportInfo {
                raw_snippet: "import java.util.*;".to_string(),
                is_wildcard: true,
                is_global: false,
                identifier: None,
                alias: None,
                path: path(Some(StructuredImportPathKind::Namespace), 0),
                binder_span: None,
            },
            // java static member import.
            ImportInfo {
                raw_snippet: "import static java.util.Map.entry;".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("entry".to_string()),
                alias: None,
                path: path(Some(StructuredImportPathKind::StaticMember), 20),
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 42,
                    end_byte: 47,
                }),
            },
            // python from-import.
            ImportInfo {
                raw_snippet: "from pkg import alpha".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("alpha".to_string()),
                alias: None,
                path: path(Some(StructuredImportPathKind::ImportFrom), 3),
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 19,
                    end_byte: 24,
                }),
            },
            // go: a '/'-segmented path with an alias.
            ImportInfo {
                raw_snippet: "import svc \"example.com/app/service\"".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("svc".to_string()),
                alias: Some("svc".to_string()),
                path: path(Some(StructuredImportPathKind::Namespace), 11),
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 4,
                    end_byte: 7,
                }),
            },
            // Rust use path: Namespace kind with a late declaration start.
            ImportInfo {
                raw_snippet: "use serde::Deserialize;".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("Deserialize".to_string()),
                alias: None,
                path: path(Some(StructuredImportPathKind::Namespace), 686),
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 698,
                    end_byte: 709,
                }),
            },
            // Rust extern crate retains its distinct import form after hydration.
            ImportInfo {
                raw_snippet: "extern crate serde as serialization;".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("serde".to_string()),
                alias: Some("serialization".to_string()),
                path: path(Some(StructuredImportPathKind::ExternCrate), 0),
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 22,
                    end_byte: 35,
                }),
            },
            // scala: a structured path with no path kind.
            ImportInfo {
                raw_snippet: "import a.B".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: Some("B".to_string()),
                alias: None,
                path: path(None, 64),
                binder_span: Some(crate::analyzer::structural::facts::Span {
                    start_byte: 71,
                    end_byte: 72,
                }),
            },
            // csharp: a plain `global using`, wildcard with a structured path.
            ImportInfo {
                raw_snippet: "global using System.Text;".to_string(),
                is_wildcard: true,
                is_global: true,
                identifier: Some("Text".to_string()),
                alias: None,
                path: path(Some(StructuredImportPathKind::Namespace), 0),
                binder_span: None,
            },
            // An empty structured path still round-trips as `Some`, not `None`:
            // `declaration_start_byte` is the presence marker, and NULL vs 0 is
            // the difference a missing path cannot express.
            ImportInfo {
                raw_snippet: "using;".to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: None,
                alias: None,
                path: path(None, 0),
                binder_span: None,
            },
        ]
    }

    // Deliberately use a neutral language: these tests exercise relational
    // storage without a parser or a native resolution producer.
    #[cfg(test)]
    pub(super) fn roundtrip_blob_meta(conn: &Connection, blob_id: i64, package: &str) {
        conn.execute("INSERT INTO blob_meta(blob_id, lang, contains_tests, content_package,
            stored_unit_count, range_count, signature_count, signature_metadata_count,
            supertype_count, child_count, import_statement_count, type_identifier_count, is_complete)
            VALUES(?1, 'fixture', 0, ?2, 0, 0, 0, 0, 0, 0, 0, 0, 1)", params![blob_id, package]).unwrap();
    }

    #[cfg(test)]
    fn roundtrip_unit(conn: &Connection, blob_id: i64, key: i64) {
        conn.execute(
            "INSERT INTO code_units(blob_id, lang, unit_key, kind, short_name, identifier,
            content_qualifier, synthetic, is_type_alias, in_declarations, in_definition_lookup)
            VALUES(?1, 'fixture', ?2, 0, 'item', 'item', 'structured', 0, 0, 1, 0)",
            params![blob_id, key],
        )
        .unwrap();
    }

    #[test]
    fn package_facts_roundtrip_structured_identity_fallback_and_partial_coverage() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let oids = [
            oid_for(b"structured"),
            oid_for(b"fallback"),
            oid_for(b"uncovered"),
        ];
        {
            let conn = store.conn.lock().unwrap();
            for (index, oid) in oids.iter().enumerate() {
                conn.execute(
                    "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'fixture')",
                    [oid.to_string()],
                )
                .unwrap();
                let blob_id = conn.last_insert_rowid();
                if index < 2 {
                    roundtrip_blob_meta(&conn, blob_id, "file-package");
                }
                if index == 0 {
                    roundtrip_unit(&conn, blob_id, 0);
                    conn.execute(
                        "UPDATE code_units SET fq_anchor_kind='crate_root', fq_anchor_pop=0,
                        fq_package_tail_segments=3, package_fqn_tail='z.a.m' WHERE blob_id=?1",
                        [blob_id],
                    )
                    .unwrap();
                    for (ordinal, segment) in ["z", "a", "m"].iter().enumerate() {
                        conn.execute("INSERT INTO code_unit_fq_segments(blob_id, lang, unit_key, seg_ordinal, seg_kind, segment)
                            VALUES(?1, 'fixture', 0, ?2, 'package', ?3)", params![blob_id, ordinal as i64, segment]).unwrap();
                    }
                }
            }
            conn.execute_batch("PRAGMA reverse_unordered_selects=ON")
                .unwrap();
        }
        let read = |oids: &[Oid]| {
            store
                .workspace_content_package_facts(
                    "fixture",
                    GenerationId::BOOTSTRAP,
                    oids,
                    Some(PackageAnchor::OwnModule { pop: 0 }),
                )
                .unwrap()
        };
        let covered = read(&oids[..2]);
        assert!(covered.complete);
        assert_eq!(covered.facts.len(), 2);
        let structured = covered
            .facts
            .iter()
            .find(|fact| fact.blob_oid == oids[0])
            .unwrap();
        assert_eq!(structured.anchor, Some(PackageAnchor::CrateRoot));
        assert_eq!(structured.content_qualifier, "structured");
        let expected = ["z", "a", "m"]
            .into_iter()
            .map(|name| segment_interner().intern(name, SegmentKind::Package))
            .collect::<Vec<_>>();
        assert_eq!(structured.package_tail.segments(), expected.as_slice());
        let fallback = covered
            .facts
            .iter()
            .find(|fact| fact.blob_oid == oids[1])
            .unwrap();
        assert_eq!(fallback.anchor, Some(PackageAnchor::OwnModule { pop: 0 }));
        assert_eq!(fallback.content_qualifier, "file-package");
        assert!(fallback.package_tail.is_empty());
        assert!(!read(&oids).complete);
        let empty = read(&[]);
        assert!(empty.complete);
        assert!(empty.facts.is_empty());
    }

    #[test]
    fn optional_manifest_roundtrip_counts_and_rejects_one_unknown_family() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("optional.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let blob_id = store.conn.execute(|conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'fixture')",
                [TEST_OID],
            )
            .unwrap();
            let blob_id = tx.last_insert_rowid();
            roundtrip_blob_meta(&tx, blob_id, "");
            for key in 0..3 {
                roundtrip_unit(&tx, blob_id, key);
            }
            tx.execute("INSERT INTO unit_cpp_class_templates(blob_id, unit_key, primary_name, primary_fq_name,
                parameter_count, specialization_argument_count, alias_component_count, alias_argument_count)
                VALUES(?1, 0, 'Box', 'Box', 0, 0, 0, 0)", [blob_id]).unwrap();
            for (key, mode) in [(1, 0), (2, 2)] {
                tx.execute(
                    "INSERT INTO ruby_method_dispatch_modes(blob_id, lang, unit_key, mode)
                    VALUES(?1, 'fixture', ?2, ?3)",
                    params![blob_id, key, mode],
                )
                .unwrap();
            }
            insert_optional_fact_manifest(&tx, blob_id, optional_fact_counts(1, 2, 0, 0, 0, 0))
                .unwrap();
            tx.commit().unwrap();
            blob_id
        });
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store.conn.execute(move |conn| {
        let read = || {
            let sql = format!(
                "SELECT 0, 0, 0, 0, 0, 0, 0, {} FROM blob_optional_fact_manifest AS manifest WHERE blob_id=?1",
                OPTIONAL_FACT_COUNT_PROJECTION.as_str()
            );
            let raw = conn
                .query_row(&sql, [blob_id], |row| {
                    raw_side_table_counts_from_row(row, 0)
                })
                .unwrap();
            side_table_counts_from_raw(raw)
        };
        let counts = read().unwrap();
        for (table, kind, expected) in [
            (
                "unit_cpp_class_templates",
                OptionalFactKind::CppClassTemplate,
                1,
            ),
            (
                "ruby_method_dispatch_modes",
                OptionalFactKind::RubyMethodDispatchMode,
                2,
            ),
        ] {
            let actual: usize = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_id=?1"),
                    [blob_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(counts.optional.get(kind), expected);
        }
        conn.execute("INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count) VALUES(?1, 999, 1)", [blob_id]).unwrap();
        assert!(
            read()
                .unwrap_err()
                .to_string()
                .contains("unknown optional analyzer fact kinds")
        );
        });
    }

    #[test]
    fn scalar_imports_roundtrip_independent_flags_aliases_and_binder_ranges() {
        let mut imports = import_shape_fixture();
        imports.push(ImportInfo {
            raw_snippet: "global using Alias = Library;".into(),
            is_wildcard: false,
            is_global: true,
            identifier: Some("Library".into()),
            alias: Some("Alias".into()),
            path: None,
            binder_span: Some(crate::analyzer::structural::facts::Span {
                start_byte: 13,
                end_byte: 18,
            }),
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("imports.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        write_import_fixture(&store, "fixture", &imports);
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let conn = store.read_conn().unwrap();
        assert_eq!(
            read_import_infos(&conn, TEST_OID, "fixture").unwrap(),
            imports
        );
    }

    #[cfg(test)]
    fn write_import_fixture(store: &AnalyzerStore, lang: &str, imports: &[ImportInfo]) {
        let lang = lang.to_owned();
        let imports = imports.to_vec();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO blobs(blob_oid, lang) VALUES(?1, ?2)",
                params![TEST_OID, lang],
            )
            .unwrap();
            let blob_id = tx.last_insert_rowid();
            insert_import_rows(
                &tx,
                blob_id,
                &lang,
                &ImportRows::from_imports(&imports, None).unwrap(),
            )
            .unwrap();
            tx.commit().unwrap();
        });
    }

    #[cfg(test)]
    /// Deleting the blob has to reach its import statements. Schema 117 stores
    /// an import's structure in the canonical `source_import_*` families, which
    /// cascade from `source_fact_manifests`; `import_statements` is the only
    /// import relation that still hangs directly off `blobs`.
    #[brokk_bifrost_test_macros::hardwon(
        "a0398f1cdc9e: deleting an analyzer blob left its persisted import statements behind"
    )]
    #[test]
    fn deleting_a_blob_cascades_its_import_statements() {
        let imports = import_shape_fixture();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        write_import_fixture(&store, "rust", &imports);
        let conn = store.conn.lock().expect("store mutex");
        conn.execute("DELETE FROM blobs WHERE blob_oid = ?1", [TEST_OID])
            .unwrap();
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM import_statements
                 WHERE blob_id IN (SELECT id FROM blobs WHERE blob_oid = ?1)",
                [TEST_OID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "import_statements must cascade with its blob");
    }

    #[cfg(test)]
    #[test]
    fn workspace_package_fact_batch_seeks_each_requested_blob() {
        for state in PlannerStatisticsState::BOTH {
            workspace_package_fact_batch_seeks_each_requested_blob_in(state);
        }
    }

    #[cfg(test)]
    fn workspace_package_fact_batch_seeks_each_requested_blob_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("workspace_content_package_facts"));
        assert!(
            plan.iter().any(|detail| {
                detail.contains("SEARCH units USING PRIMARY KEY")
                    || detail.contains("SEARCH code_units USING PRIMARY KEY")
            }),
            "package facts must seek the requested blob keys {state}: {plan:#?}"
        );
        assert!(
            plan.iter().any(|detail| {
                detail.contains("SEARCH segments USING PRIMARY KEY")
                    || detail.contains("SEARCH code_unit_fq_segments USING PRIMARY KEY")
            }),
            "package segments must seek the selected declaration keys {state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| {
                !detail.contains("SCAN units")
                    && !detail.contains("SCAN code_units")
                    && !detail.contains("SCAN blobs")
                    && !detail.contains("SCAN blob_meta")
                    && !detail.contains("SCAN segments")
                    && !detail.contains("SCAN code_unit_fq_segments")
            }),
            "package-fact batching must not scan persisted fact tables {state}: {plan:#?}"
        );
    }

    #[cfg(test)]
    fn insert_test_blob_and_unit(conn: &Connection) {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang) VALUES(?1, 'rust')",
            [TEST_OID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
               signature, synthetic, is_type_alias, top_level_ordinal,
               in_declarations, in_definition_lookup
             ) VALUES((SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'), 'rust', 1, 0, 'Thing', 'Thing', '', NULL, 0, 0, 0, 1, 0)",
            [TEST_OID],
        )
        .unwrap();
    }

    #[cfg(test)]
    fn assert_constraint_error(err: rusqlite::Error, expected: &str) {
        let message = err.to_string();
        assert!(
            message.contains(expected),
            "expected {expected} constraint error, got {message}"
        );
    }

    #[cfg(test)]
    #[brokk_bifrost_test_macros::hardwon(
        "6074c794e6bd: Rust import candidate planning scanned rows outside the requested occurrence names"
    )]
    #[test]
    fn rust_module_import_candidates_seek_occurrences_then_blob_import_rows() {
        for state in PlannerStatisticsState::BOTH {
            rust_module_import_candidates_seek_occurrences_then_blob_import_rows_in(state);
        }
    }

    #[cfg(test)]
    fn rust_module_import_candidates_seek_occurrences_then_blob_import_rows_in(
        state: PlannerStatisticsState,
    ) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().expect("store mutex");
        state.install(&conn);
        let plan = explain_pin(&conn, &pinned("rust_module_import_candidate_blobs"));

        assert!(
            plan.iter().any(|detail| {
                detail.contains(
                    "SEARCH occurrence USING COVERING INDEX idx_rust_identifier_occurrences",
                )
            }),
            "the exact component must seek the occurrence index {state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH target USING PRIMARY KEY (blob_id=?)")),
            "each candidate blob must range-read its own import rows {state}: {plan:#?}"
        );
        assert!(
            !plan
                .iter()
                .any(|detail| detail.contains("SCAN target") || detail.contains("SCAN source")),
            "the query must not scan the workspace import table {state}: {plan:#?}"
        );
    }

    #[cfg(test)]
    #[test]
    fn selected_rust_declaration_authority_plan_seeks_canonical_site_chain_in_both_states() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().expect("store mutex");
            state.install(&conn);
            super::planner_statistics::pinned_plans::prepare_pin_context(&conn);
            let plan = explain_pin(&conn, &pinned("selected_rust_declaration_authority"));
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH semantic USING PRIMARY KEY")
                        && detail.contains("blob_id=? AND source_site=?")
                }),
                "authority reader must seek the semantic site by its primary key {state}: {plan:#?}"
            );
            for table in ["interior", "semantic", "native", "property"] {
                assert!(
                    plan.iter()
                        .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                    "authority reader must not scan {table} {state}: {plan:#?}"
                );
            }
        }
    }

    // ---- fixtures the parked tests above use ----
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "resolution_producer_tests_go_support.rs"]
pub mod resolution_producer_tests_go_support;

#[doc(hidden)]
pub mod active_models;
#[doc(hidden)]
pub mod model_catalog;
#[doc(hidden)]
pub mod model_provenance;

#[doc(hidden)]
pub mod maven_xml;

#[doc(hidden)]
pub mod xml_name;

#[doc(hidden)]
pub mod cache_gc;
#[doc(hidden)]
pub mod file_set_identity;
#[doc(hidden)]
pub mod file_state;
#[doc(hidden)]
pub mod maven;
#[doc(hidden)]
pub mod structural_vocabulary;

// Standalone store tests have no linked language implementation assembly.
#[cfg(test)]
mod standalone_language_table {
    #[unsafe(no_mangle)]
    fn __brokk_bifrost_store_language_supports_v1() -> &'static super::StoreLanguageTable {
        static TABLE: std::sync::OnceLock<super::StoreLanguageTable> = std::sync::OnceLock::new();
        TABLE.get_or_init(super::language_support::neutral_fixture::precedence_fixture_supports)
    }
}

#[cfg(test)]
mod roundtrip_unit_properties {
    use super::*;
    use brokk_bifrost_core::analyzer::model::JavaTypeConstructorShape;

    struct Adapter;
    impl StoreLanguageAdapter for Adapter {
        fn language(&self) -> Language {
            Language::Java
        }
    }

    fn empty_state() -> FileState {
        FileState {
            source: String::new(),
            package_name: String::new(),
            content_qualifier: String::new(),
            top_level_declarations: Vec::new(),
            declarations: Default::default(),
            definition_lookup_units: Default::default(),
            imports: Default::default(),
            scala_exports: Default::default(),
            rust_usage_facts: Default::default(),
            resolution_facts: Default::default(),
            source_facts: None,
            source_declaration_units: Vec::new(),
            source_declaration_metadata: Vec::new(),
            raw_supertypes: Default::default(),
            supertype_lookup_paths: Default::default(),
            type_identifiers: Default::default(),
            signatures: Default::default(),
            signature_metadata: Default::default(),
            signature_metadata_signature_ordinals: Default::default(),
            cpp_template_metadata: Default::default(),
            ranges: Default::default(),
            children: Default::default(),
            type_aliases: Default::default(),
            ruby_method_dispatch_modes: Default::default(),
            scala_traits: Default::default(),
            contains_tests: false,
            test_region_units: Default::default(),
            materialization_records: Default::default(),
            completeness: Default::default(),
            parse_errors: None,
            parse_complete: true,
            additional_projections: Vec::new(),
        }
    }

    fn unit(file: &ProjectFile, name: &str) -> CodeUnit {
        let mut fq = FqName::new();
        fq.push(segment_interner().intern(name, SegmentKind::Type));
        CodeUnit::from_fq(file.clone(), CodeUnitType::Class, fq, 0, None, false)
    }

    // Store-only tests cannot depend on the engine's parser/preparation bridge.
    // Feed explicit FileState facts into the relational boundary, using the
    // production identity and metadata writers and independent manifest counts.
    fn publish<A: StoreLanguageAdapter>(
        conn: &Connection,
        oid: Oid,
        lang: &str,
        adapter: &A,
        state: &FileState,
    ) {
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, 0)",
            params![oid.to_string(), lang],
        )
        .unwrap();
        let blob_id = conn.last_insert_rowid();
        let units = collect_stored_units(adapter, state);
        let keys = stored_unit_keys_from_units(&units);
        for stored in &units {
            let unit = &stored.unit;
            let qualifier = adapter.storage_content_qualifier(unit, "");
            let prepared = prepare_unit_fq(adapter, unit, &qualifier).unwrap().unwrap();
            let segment_bytes = prepared
                .segments
                .iter()
                .map(|(_, kind, text)| kind.len() + text.len())
                .sum::<usize>();
            conn.execute(
                "INSERT INTO code_units(
                   blob_id, lang, unit_key, kind, short_name, identifier, content_qualifier,
                   simple_type_name, signature, synthetic, is_type_alias, top_level_ordinal,
                   in_declarations, in_definition_lookup, in_test_region, fq_anchor_kind, fq_anchor_pop,
                   fq_package_tail_segments, exact_fqn_tail, normalized_fqn_tail,
                   exact_parent_fqn_tail, normalized_parent_fqn_tail, package_fqn_tail,
                   fq_segment_count, fq_segment_bytes
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?19, ?20, ?21, ?22, ?23, ?24, ?9, ?10,
                          ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    blob_id,
                    lang,
                    stored.key,
                    code_unit_kind_to_i64(unit.kind()),
                    unit.short_name(),
                    unit.identifier(),
                    qualifier,
                    unit.is_class().then(|| adapter.simple_type_name(unit)),
                    prepared.anchor_kind,
                    prepared.anchor_pop,
                    prepared.package_tail_segments,
                    prepared.exact_tail,
                    prepared.normalized_tail,
                    prepared.exact_parent_tail,
                    prepared.normalized_parent_tail,
                    prepared.package_tail,
                    prepared.segments.len(),
                    segment_bytes,
                    unit.is_synthetic(),
                    stored.is_type_alias,
                    stored.top_level_ordinal.map(|n| n as i64),
                    stored.in_declarations,
                    stored.in_definition_lookup,
                    stored.in_test_region,
                ],
            )
            .unwrap();
            for (ordinal, kind, text) in &prepared.segments {
                conn.execute(
                    "INSERT INTO code_unit_fq_segments(
                       blob_id, lang, unit_key, seg_ordinal, seg_kind, segment
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![blob_id, lang, stored.key, ordinal, kind, text],
                )
                .unwrap();
            }
        }
        for (unit, ranges) in &state.ranges {
            for (ordinal, range) in ranges.iter().enumerate() {
                conn.execute("INSERT INTO unit_ranges(blob_id, lang, unit_key, ordinal, start_byte, end_byte, start_line, end_line) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", params![blob_id, lang, keys[unit], ordinal, range.start_byte, range.end_byte, range.start_line, range.end_line]).unwrap();
            }
        }
        for (parent, children) in &state.children {
            for (ordinal, child) in children.iter().enumerate() {
                conn.execute("INSERT INTO unit_children(blob_id, lang, parent_key, child_key, ordinal) VALUES(?1, ?2, ?3, ?4, ?5)", params![blob_id, lang, keys[parent], keys[child], ordinal]).unwrap();
            }
        }
        for (unit, supertypes) in &state.raw_supertypes {
            for (ordinal, raw) in supertypes.iter().enumerate() {
                conn.execute("INSERT INTO unit_supertypes(blob_id, lang, unit_key, ordinal, raw, lookup_path) VALUES(?1, ?2, ?3, ?4, ?5, ?5)", params![blob_id, lang, keys[unit], ordinal, raw]).unwrap();
            }
        }
        for (unit, metadata) in &state.signature_metadata {
            for (ordinal, value) in metadata.iter().enumerate() {
                SignatureMetadataColumns::encode(value)
                    .unwrap()
                    .insert(
                        &mut conn.prepare(signature_metadata_insert_sql()).unwrap(),
                        blob_id,
                        lang,
                        keys[unit],
                        ordinal as i64,
                    )
                    .unwrap();
            }
        }
        for (unit, mode) in &state.ruby_method_dispatch_modes {
            conn.execute("INSERT INTO ruby_method_dispatch_modes(blob_id, lang, unit_key, mode) VALUES(?1, ?2, ?3, ?4)", params![blob_id, lang, keys[unit], ruby_dispatch_mode_to_i64(*mode)]).unwrap();
        }
        conn.execute("INSERT INTO blob_meta(blob_id, lang, contains_tests, content_package, stored_unit_count, range_count, signature_count, signature_metadata_count, supertype_count, child_count, import_statement_count, type_identifier_count, is_complete) VALUES(?1, ?2, 0, '', ?3, ?4, 0, ?5, ?6, ?7, 0, 0, 1)", params![blob_id, lang, units.len(), state.ranges.values().map(Vec::len).sum::<usize>(), state.signature_metadata.values().map(Vec::len).sum::<usize>(), state.raw_supertypes.values().map(Vec::len).sum::<usize>(), state.children.values().map(Vec::len).sum::<usize>()]).unwrap();
        if !state.ruby_method_dispatch_modes.is_empty() {
            conn.execute("INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count) VALUES(?1, ?2, ?3)", params![blob_id, OptionalFactKind::RubyMethodDispatchMode as i64, state.ruby_method_dispatch_modes.len()]).unwrap();
        }
    }

    #[test]
    fn sqlite_unit_membership_and_side_facts_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cache.db");
        let file = ProjectFile::new(temp.path().to_path_buf(), "Units.java");
        let names = [
            "Declared",
            "Lookup",
            "Test",
            "Ordinary",
            "OnlyChild",
            "OtherChild",
        ];
        let units = names.map(|name| unit(&file, name));
        let mut state = empty_state();
        state.declarations.insert(units[0].clone());
        state.definition_lookup_units.insert(units[1].clone());
        state.test_region_units.insert(units[2].clone());
        state
            .children
            .insert(units[0].clone(), vec![units[4].clone(), units[5].clone()]);
        state
            .raw_supertypes
            .insert(units[0].clone(), vec!["Base".to_owned()]);
        // One range, two edges, one supertype: side counts are deliberately unequal.
        state.ranges.insert(
            units[1].clone(),
            vec![Range {
                start_byte: 1,
                end_byte: 9,
                start_line: 0,
                end_line: 0,
            }],
        );
        state.type_aliases.insert(units[2].clone());
        state.type_aliases.insert(units[3].clone());
        let oid = test_blob_oid(b"membership");
        {
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            let input = state.clone();
            store
                .conn
                .execute(move |conn| publish(conn, oid, "java", &Adapter, &input));
        }
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let single = store
            .hydrate_file_state(oid, "java", &Adapter, &file)
            .unwrap()
            .expect("complete blob");
        let bulk = store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                "java",
                &Adapter,
                &HashMap::default(),
            )
            .unwrap();
        for actual in [&single, &bulk[&file]] {
            let mut actual = actual.clone();
            actual.declarations.retain(|unit| !unit.is_file_scope());
            actual.ranges.retain(|unit, _| !unit.is_file_scope());
            assert_eq!(actual.declarations, state.declarations);
            assert_eq!(
                actual.definition_lookup_units,
                state.definition_lookup_units
            );
            assert_eq!(actual.test_region_units, state.test_region_units);
            assert_eq!(actual.children, state.children);
            assert_eq!(actual.raw_supertypes, state.raw_supertypes);
            assert_eq!(actual.ranges, state.ranges);
            assert_eq!(actual.type_aliases, state.type_aliases);
        }
        store.conn.execute(move |conn| {
            // Compare the generated SQL projection and positional decoder with
            // input memberships, independently keyed by the supplied names.
            let sql = format!(
                "SELECT {}, units.short_name FROM blobs AS keys
                 JOIN code_units AS units ON units.blob_id = keys.id
                 WHERE keys.blob_oid = ?1 AND keys.lang = 'java'",
                raw_unit_columns_sql("units")
            );
            let memberships = conn
                .prepare(&sql)
                .unwrap()
                .query_map([oid.to_string()], |row| {
                    let raw = raw_unit_row_from_row(row, 0)?;
                    Ok((
                        row.get::<_, String>(18)?,
                        (
                            raw.in_declarations,
                            raw.in_definition_lookup,
                            raw.in_test_region,
                        ),
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<HashMap<_, _>>>()
                .unwrap();
            let expected = units
                .iter()
                .map(|unit| {
                    (
                        unit.short_name().to_string(),
                        (
                            state.declarations.contains(unit),
                            state.definition_lookup_units.contains(unit),
                            state.test_region_units.contains(unit),
                        ),
                    )
                })
                .collect::<HashMap<_, _>>();
            assert_eq!(memberships, expected);

            let rows = read_unit_rows(conn, &oid.to_string(), "java", &Adapter, &file).unwrap();
            assert_eq!(
                rows.iter()
                    .map(|row| row.unit.clone())
                    .collect::<HashSet<_>>(),
                units.into_iter().collect()
            );
            assert!(
                enclosing_declarations_for_file_conn(conn, oid, "java", &Adapter, &file)
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
            conn.execute(
                "UPDATE blob_meta SET stored_unit_count = stored_unit_count + 1",
                [],
            )
            .unwrap();
            assert!(
                hydrate_file_state_conn(conn, oid, "java", &Adapter, &file, "")
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn sqlite_asymmetric_signature_metadata_and_ruby_modes_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cache.db");
        let file = ProjectFile::new(temp.path().to_path_buf(), "Facts.java");
        let mut state = empty_state();
        let owner = unit(&file, "Owner");
        let metadata = vec![
            SignatureMetadata::new("plain", vec![]),
            SignatureMetadata::new("static", vec![]).with_field_modifiers(true, false),
            SignatureMetadata::new("final", vec![]).with_field_modifiers(false, true),
            SignatureMetadata::new("default", vec![])
                .with_java_type_constructor_shape(JavaTypeConstructorShape::Default),
            SignatureMetadata::new("none", vec![])
                .with_java_type_constructor_shape(JavaTypeConstructorShape::NoImplicit),
            SignatureMetadata::new("optional", vec![])
                .with_callable_arity(CallableArity::new(1, 3, false)),
        ];
        state.signature_metadata.insert(owner, metadata);
        for (index, mode) in [
            RubyMethodDispatchMode::Instance,
            RubyMethodDispatchMode::Singleton,
            RubyMethodDispatchMode::ModuleFunction,
        ]
        .into_iter()
        .enumerate()
        {
            let method = unit(&file, &format!("ZMethod{index}"));
            state.ruby_method_dispatch_modes.insert(method, mode);
        }
        // Padding ensures every dispatch key is above the mode codes 0..=2.
        for name in ["APad", "BPad", "CPad", "DPad"] {
            state.declarations.insert(unit(&file, name));
        }
        let oid = test_blob_oid(b"semantic metadata");
        {
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            let input = state.clone();
            store
                .conn
                .execute(move |conn| publish(conn, oid, "java", &Adapter, &input));
        }
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let single = store
            .hydrate_file_state(oid, "java", &Adapter, &file)
            .unwrap()
            .expect("complete metadata");
        let bulk = store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                "java",
                &Adapter,
                &HashMap::default(),
            )
            .unwrap();
        for actual in [&single, &bulk[&file]] {
            assert_eq!(actual.signature_metadata, state.signature_metadata);
            assert_eq!(
                actual.ruby_method_dispatch_modes,
                state.ruby_method_dispatch_modes
            );
        }
    }
    #[test]
    fn sqlite_candidate_membership_and_multichunk_identity() {
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().to_path_buf(), "Candidates.java");
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut state = empty_state();
        let declared = unit(&file, "Foo").with_synthetic(true);
        let lookup = CodeUnit::from_fq(
            file.clone(),
            CodeUnitType::Function,
            declared.fq().clone(),
            0,
            None,
            false,
        );
        state.declarations.insert(declared.clone());
        state.definition_lookup_units.insert(lookup.clone());
        state.declarations.insert(unit(&file, "Bar"));
        // Distinct structured names cross the candidate segment hydration batch.
        for index in 0..1001 {
            state
                .declarations
                .insert(unit(&file, &format!("Pad{index:04}")));
        }
        let oid = test_blob_oid(b"candidates");
        {
            let conn = store.conn.lock().unwrap();
            publish(&conn, oid, "java", &Adapter, &state);
            let mut other = empty_state();
            other.declarations.insert(unit(&file, "Foo"));
            publish(
                &conn,
                test_blob_oid(b"other language"),
                "kotlin",
                &Adapter,
                &other,
            );
        }
        let langs = vec!["java".to_owned()];
        let generations = HashMap::from_iter([
            ("java".to_owned(), GenerationId::BOOTSTRAP),
            ("kotlin".to_owned(), GenerationId::BOOTSTRAP),
        ]);
        let mounted = |rows: Vec<HydratedCandidateRow>| {
            rows.into_iter()
                .map(|row| {
                    hydrate_mounted_candidate(
                        &Adapter,
                        temp.path(),
                        row,
                        "Candidates.java".to_owned(),
                    )
                    .unwrap()
                })
                .collect::<HashSet<_>>()
        };
        assert_eq!(
            mounted(
                store
                    .declaration_candidate_rows_by_short_name_for_langs(&langs, &generations, "Foo")
                    .unwrap()
            ),
            HashSet::from_iter([declared.clone()])
        );
        let both = vec!["java".to_owned(), "kotlin".to_owned()];
        assert_eq!(
            store
                .declaration_candidate_rows_by_short_name_for_langs(&both, &generations, "Foo")
                .unwrap()
                .len(),
            2
        );
        let expected = HashSet::from_iter([declared, lookup]);
        assert_eq!(
            mounted(
                store
                    .declaration_candidate_rows_by_identifier_prefix_for_langs(
                        &langs,
                        &generations,
                        "Foo"
                    )
                    .unwrap()
            ),
            expected
        );
        assert_eq!(
            mounted(
                store
                    .declaration_candidate_rows_by_identifier_for_langs_limited(
                        &langs,
                        &generations,
                        "Foo",
                        100
                    )
                    .unwrap()
                    .rows
            ),
            expected
        );
        let conn = store.conn.lock().unwrap();
        let rows = candidate_rows_for_languages(
            &conn,
            ["java"],
            &limited_identifier_candidate_for_blob_sql(),
            &[&"Foo", &oid.to_string()],
        )
        .unwrap();
        assert_eq!(mounted(rows), expected);
        drop(conn);
        let all = store.declaration_candidate_rows_by_lang("java");
        assert_eq!(mounted(all.unwrap()), state.declarations);
    }

    struct AnchoredAdapter;
    impl StoreLanguageAdapter for AnchoredAdapter {
        fn language(&self) -> Language {
            Language::Java
        }
        fn default_package_anchor(&self) -> Option<PackageAnchor> {
            Some(PackageAnchor::OwnModule { pop: 0 })
        }
        fn resolve_package_anchor(
            &self,
            anchor: PackageAnchor,
            _: &str,
            file: &ProjectFile,
        ) -> Option<FqName> {
            let name = match anchor {
                PackageAnchor::CrateRoot => "root",
                PackageAnchor::OwnModule { .. } => {
                    if file.rel_path() == "First.java" {
                        "first"
                    } else {
                        "second"
                    }
                }
            };
            let mut fq = FqName::new();
            fq.push(segment_interner().intern(name, SegmentKind::Package));
            Some(fq)
        }
    }

    #[test]
    fn sqlite_companion_and_anchored_identity_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let file = ProjectFile::new(temp.path().to_path_buf(), "First.java");
        let moved = ProjectFile::new(temp.path().to_path_buf(), "Second.java");
        let make = |file: &ProjectFile, package: &[&str], kind| {
            let mut fq = FqName::new();
            for part in package {
                fq.push(segment_interner().intern(part, SegmentKind::Package));
            }
            fq.push(segment_interner().intern("Object", kind));
            CodeUnit::from_fq(
                file.clone(),
                CodeUnitType::Class,
                fq,
                package.len(),
                None,
                false,
            )
        };
        let mut state = empty_state();
        state
            .declarations
            .insert(make(&file, &["first"], SegmentKind::Companion));
        state
            .declarations
            .insert(make(&file, &["first", "explicit"], SegmentKind::Type));
        state.declarations.insert(
            make(&file, &["root"], SegmentKind::Type).with_package_anchor(PackageAnchor::CrateRoot),
        );
        let expected = HashSet::from_iter([
            make(&moved, &["second"], SegmentKind::Companion),
            make(&moved, &["first", "explicit"], SegmentKind::Type),
            make(&moved, &["root"], SegmentKind::Type),
        ]);
        let oid = test_blob_oid(b"anchored identities");
        let conn = store.conn.lock().unwrap();
        publish(&conn, oid, "java", &AnchoredAdapter, &state);
        let actual = hydrate_file_state_conn(&conn, oid, "java", &AnchoredAdapter, &moved, "")
            .unwrap()
            .unwrap();
        assert_eq!(
            actual
                .declarations
                .into_iter()
                .filter(|unit| !unit.is_file_scope())
                .collect::<HashSet<_>>(),
            expected
        );
        // The adapter cancels while the only row is being hydrated. This
        // event is independent of the reader's number of checkpoints.
        struct CancelOnAnchor(Arc<std::sync::atomic::AtomicBool>);
        impl StoreLanguageAdapter for CancelOnAnchor {
            fn language(&self) -> Language {
                Language::Java
            }
            fn resolve_package_anchor(
                &self,
                anchor: PackageAnchor,
                qualifier: &str,
                file: &ProjectFile,
            ) -> Option<FqName> {
                self.0.store(true, Ordering::SeqCst);
                AnchoredAdapter.resolve_package_anchor(anchor, qualifier, file)
            }
        }
        let mut last = empty_state();
        last.declarations.insert(
            make(&file, &["root"], SegmentKind::Type).with_package_anchor(PackageAnchor::CrateRoot),
        );
        let last_oid = test_blob_oid(b"last hydration cancellation");
        publish(&conn, last_oid, "java", &AnchoredAdapter, &last);
        assert_eq!(
            read_unit_rows(
                &conn,
                &last_oid.to_string(),
                "java",
                &AnchoredAdapter,
                &file
            )
            .unwrap()
            .len(),
            1
        );
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(
            read_unit_rows_while(
                &conn,
                &last_oid.to_string(),
                "java",
                &CancelOnAnchor(Arc::clone(&cancelled)),
                &file,
                &|| !cancelled.load(Ordering::SeqCst)
            )
            .unwrap()
            .is_none()
        );
        assert!(
            cancelled.load(Ordering::SeqCst),
            "the final hydration hook must run"
        );
    }
}

#[cfg(test)]
mod generation_liveness_properties {
    use super::*;
    use git2::ObjectType;

    struct Adapter;
    impl StoreLanguageAdapter for Adapter {
        fn language(&self) -> Language {
            Language::Java
        }
    }

    fn oid(bytes: &[u8]) -> Oid {
        Oid::hash_object(ObjectType::Blob, bytes).unwrap()
    }

    // Synthetic legacy publication: two declarations, one parent/child edge,
    // two imports, and no reference identifiers. No language engine is needed.
    fn publish(store: &AnalyzerStore, oid: Oid, lang: &str, generation: GenerationId) -> i64 {
        store.register_blobs(&[oid], lang, generation).unwrap();
        let lang = lang.to_string();
        store.conn.execute(move |conn| -> Result<i64> {
        let tx = conn.transaction().unwrap();
        let id: i64 = tx
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid=?1 AND lang=?2",
                params![oid.to_string(), lang],
                |r| r.get(0),
            )
            .unwrap();
        tx.execute(
            "INSERT INTO blob_meta(blob_id,lang,contains_tests,content_package,
            stored_unit_count,range_count,signature_count,signature_metadata_count,
            supertype_count,child_count,import_statement_count,type_identifier_count,is_complete)
            VALUES(?1,?2,0,'',2,0,0,0,0,1,2,0,1)",
            params![id, lang],
        )
        .unwrap();
        for (key, name) in [(0, "Parent"), (1, "Child")] {
            tx.execute(
                "INSERT INTO code_units(blob_id,lang,unit_key,kind,short_name,identifier,
                content_qualifier,synthetic,is_type_alias,in_declarations,in_definition_lookup,
                fq_segment_count,fq_segment_bytes,exact_fqn_tail,fq_package_tail_segments)
                VALUES(?1,?2,?3,0,?4,?4,'',0,0,1,1,1,?5,?4,0)",
                params![id, lang, key, name, name.len() + 4],
            )
            .unwrap();
            tx.execute("INSERT INTO code_unit_fq_segments(blob_id,lang,unit_key,seg_ordinal,seg_kind,segment)
                VALUES(?1,?2,?3,0,'type',?4)",params![id,lang,key,name]).unwrap();
        }
        tx.execute(
            "INSERT INTO unit_children(blob_id,lang,parent_key,ordinal,child_key)
            VALUES(?1,?2,0,0,1)",
            params![id, lang],
        )
        .unwrap();
        for (ordinal, statement) in [(0, "import alpha;"), (1, "import beta;")] {
            tx.execute("INSERT INTO import_statements(blob_id,lang,ordinal,statement,is_wildcard,is_global)
                VALUES(?1,?2,?3,?4,0,0)",params![id,lang,ordinal,statement]).unwrap();
        }
        tx.execute(
            "INSERT INTO blob_reference_fact_manifests(blob_id,lang,epoch,identifier_count)
            VALUES(?1,?2,1,0)",
            params![id, lang],
        )
        .unwrap();
        tx.commit().unwrap();
        Ok(id)
        }).unwrap()
    }

    #[test]
    fn registered_keys_are_language_scoped_sets_and_rotation_preserves_current_facts() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let a = oid(b"a");
        let b = oid(b"b");
        let generation = GenerationId::BOOTSTRAP;
        let id = publish(&store, a, "java", generation);
        store.register_blobs(&[a, a], "java", generation).unwrap();
        assert_eq!(
            store
                .declaration_candidate_rows_by_short_name("java", "Parent")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store.missing_blobs(&[a, a, b, b], "python").unwrap(),
            vec![a, b]
        );
        assert_eq!(store.missing_blobs(&[a, b, b], "java").unwrap(), vec![b]);
        store.register_blobs(&[a], "python", generation).unwrap();
        let next = store.ensure_language_epoch_value("java", "next").unwrap();
        store.register_blobs(&[a, a], "java", next).unwrap();
        let conn = store.conn.lock().unwrap();
        let rows = conn
            .prepare("SELECT lang,generation FROM blobs WHERE blob_oid=?1 ORDER BY lang")
            .unwrap()
            .query_map([a.to_string()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows, vec![("java".into(), next.0), ("python".into(), 0)]);
        let children: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM code_units WHERE blob_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(children, 0);
    }

    #[test]
    fn parsed_verification_detects_missing_rows_and_deduplicates_repairs() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let good = oid(b"good");
        let corrupt = oid(b"corrupt");
        let absent = oid(b"absent");
        publish(&store, good, "java", GenerationId::BOOTSTRAP);
        let id = publish(&store, corrupt, "java", GenerationId::BOOTSTRAP);
        let good = (good, "java".to_string());
        let corrupt = (corrupt, "java".to_string());
        let absent = (absent, "java".to_string());
        assert_eq!(
            store
                .parsed_blob_keys(&[good.clone(), corrupt.clone()])
                .unwrap()
                .len(),
            2
        );
        store
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM unit_children WHERE blob_id=?1", [id])
            .unwrap();
        let inputs = [
            good.clone(),
            corrupt.clone(),
            absent.clone(),
            corrupt.clone(),
            absent.clone(),
        ];
        assert_eq!(
            store.parsed_blob_keys(&inputs).unwrap(),
            HashSet::from_iter([good])
        );
        assert_eq!(
            store.missing_parsed_blob_keys(&inputs).unwrap(),
            vec![corrupt, absent]
        );
    }

    #[test]
    fn warm_publication_hydrates_imports_and_children_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cache.db");
        let a = oid(b"warm");
        {
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            publish(&store, a, "java", GenerationId::BOOTSTRAP);
        }
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let file = ProjectFile::new(temp.path().to_path_buf(), "Warm.java");
        let state = store
            .hydrate_file_state_with_source(a, "java", GenerationId::BOOTSTRAP, &Adapter, &file, "")
            .unwrap()
            .expect("warm hit");
        assert_eq!(
            state
                .imports
                .iter()
                .map(|i| i.raw_snippet.as_str())
                .collect::<Vec<_>>(),
            vec!["import alpha;", "import beta;"]
        );
        let edges = state
            .children
            .iter()
            .flat_map(|(p, cs)| {
                cs.iter()
                    .map(move |c| (p.identifier().to_string(), c.identifier().to_string()))
            })
            .collect::<Vec<_>>();
        assert_eq!(edges, vec![("Parent".into(), "Child".into())]);
        assert!(state.type_identifiers.is_empty());
    }

    #[test]
    fn captured_generations_reject_stale_and_missing_tokens_across_read_surfaces() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().to_path_buf(), "A.java");
        let a = oid(b"generation");
        let old = store.ensure_language_epoch_value("java", "first").unwrap();
        publish(&store, a, "java", old);
        let before = store
            .hydrate_file_state_with_source(a, "java", old, &Adapter, &file, "")
            .unwrap()
            .expect("published generation hydrates before rotation");
        let unit = before
            .declarations
            .iter()
            .find(|u| u.identifier() == "Parent")
            .unwrap();
        let current = store.ensure_language_epoch_value("java", "second").unwrap();
        assert_ne!(old, current);
        let entries = [(a, "java".to_string())];
        let langs = ["java".to_string()];
        let imports = [(file.clone(), a, "java".to_string())];
        let workspace =
            WorkspaceId("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        for token in [Some(old), None, Some(current)] {
            let generations = token
                .map(|g| HashMap::from_iter([("java".into(), g)]))
                .unwrap_or_default();
            let results = [
                (
                    "parsed",
                    store
                        .parsed_blob_keys_at_generations(&entries, &generations)
                        .map(|_| ()),
                ),
                (
                    "imports",
                    store
                        .hydrate_import_facts_by_key(&imports, &generations, &Adapter)
                        .map(|_| ()),
                ),
                (
                    "candidates",
                    store
                        .declaration_candidate_rows_for_langs_by_predicate(
                            &langs,
                            &generations,
                            "units.lang = ?1",
                            &[],
                        )
                        .map(|_| ()),
                ),
                (
                    "snapshots",
                    store
                        .workspace_snapshots_for_langs(&workspace, &langs, &generations)
                        .map(|_| ()),
                ),
                (
                    "structured imports",
                    store
                        .blobs_with_structured_imports_by_keys(&entries, &generations)
                        .map(|_| ()),
                ),
            ];
            for (surface, result) in results {
                if token == Some(current) {
                    result.unwrap_or_else(|e| panic!("{surface}: {e}"));
                } else {
                    assert!(
                        result.expect_err(surface).is_stale_generation(),
                        "{surface}: {token:?}"
                    );
                }
            }
        }
        for generation in [old, current] {
            let results = [
                store
                    .hydrate_file_state_with_source(a, "java", generation, &Adapter, &file, "")
                    .map(|_| ()),
                store
                    .signature_metadata_for_unit_limited(a, "java", generation, unit, 2)
                    .map(|_| ()),
            ];
            for result in results {
                if generation == current {
                    result.unwrap();
                } else {
                    assert!(result.unwrap_err().is_stale_generation());
                }
            }
        }
    }

    #[test]
    fn candidate_publication_excludes_stale_and_revoked_rows_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cache.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let old = store.ensure_language_epoch_value("java", "first").unwrap();
        publish(&store, oid(b"old"), "java", old);
        let current = store.ensure_language_epoch_value("java", "second").unwrap();
        let live = oid(b"live");
        publish(&store, live, "java", current);
        let revoked = publish(&store, oid(b"revoked"), "java", current);
        store
            .conn
            .execute(move |conn| -> Result<()> {
                conn.execute(
                    "UPDATE blob_meta SET is_complete=0 WHERE blob_id=?1",
                    [revoked],
                )?;
                Ok(())
            })
            .unwrap();
        let check = |store: &AnalyzerStore| {
            let rows = store
                .declaration_candidate_rows_by_short_name("java", "Parent")
                .unwrap();
            assert_eq!(
                rows.iter().map(|r| r.blob_oid).collect::<Vec<_>>(),
                vec![live]
            );
        };
        check(&store);
        drop(store);
        check(&AnalyzerStore::open_persistent(&path).unwrap());
    }

    #[test]
    fn fallback_snapshot_sync_selects_new_rows_before_any_reader_checkout() {
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        for (name, bytes) in [
            ("A.java", b"first".as_slice()),
            ("B.java", b"second".as_slice()),
        ] {
            let a = oid(bytes);
            store
                .sync_workspace_snapshot(
                    "java",
                    GenerationId::BOOTSTRAP,
                    &[WorkspaceFileRow {
                        rel_path: name.into(),
                        blob_oid: a,
                    }],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap();
            let conn = store.conn.lock().unwrap();
            let rows = conn
                .prepare("SELECT rel_path,blob_oid FROM workspace_files")
                .unwrap()
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(rows, vec![(name.into(), a.to_string())]);
        }
        let a = oid(b"fallback");
        publish(&store, a, "java", GenerationId::BOOTSTRAP);
        assert!(store.contains_parsed_blob(a, "java").unwrap());
        let conn = store.conn.lock().unwrap();
        let error=conn.execute("INSERT INTO blob_reference_fact_manifests(blob_id,lang,epoch,identifier_count) VALUES(-1,'java',1,0)",[]).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ConstraintViolation)
        );
    }
}
