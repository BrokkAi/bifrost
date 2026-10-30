//! Demand-local JVM import composition over exact selected source publications.
//!
//! This is one caller's query. Package and root membership stay in SQLite; the source
//! halves, candidate export halves and compiled bridges die with the query.

#[doc(hidden)]
pub use super::nominal_rules::ImportTargetMounts;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn jvm_import_target_mounts() -> ImportTargetMounts {
    nominal_rules::jvm_package_rules().import_target_mounts()
}

use super::context_preparation::{ContextPlanCell, ContextPlanMemo, RequestContextMemo};
use super::file_context::RootHalfRequest;
use super::imports::{
    ImportBinder, ImportBinderClass, ImportBinderRules, ImportTokenMetadata, SelectedImportRoute,
    SelectedImportRouteKind, SelectedImportSelector, hydrate_import_binders,
};
use super::nominal_rules::{
    CompilationUnitRelation, ImportOriginRoute, NominalPackageRules, PackageRelation,
    nominal_language_rules, nominal_package_rules,
};
use super::package_bridges::{
    PackageBridgeAdmission, PackageBridgePair, PackageBridgeRules, assemble_package_bridges,
};
use super::package_context::{SelectedPackageRows, unique_package_references_by_token};
use super::placement_access::{PlacementKey, PlacementSubject, read_placement_rows};
use super::root_bridges::{
    RootBridgePair, RootBridgeRules, RootBridgeStep, RootTargetRules, append_root_target,
};
use super::unit_access::{UnitAccess, UnitAccessRules, read_unit_access};
use super::*;
use crate::analyzer::resolution::{
    BatchEndpointClassification, BindingOrigin, CanonicalIdentityDescriptor, CanonicalIdentityPart,
    FactPageVisitor, FactReadOutcome, JvmImplicitRootProvider,
    LoweredDeclarationVisibilityProperty, LoweredPackageMember, LoweredPackageReference,
    PrecedenceStep, ResolutionIdentityDigestKey, SelectedJvmBridgeEvidence,
    SelectedJvmBridgeProvenance, SelectedJvmBridgeVisibility, SelectedPackageBridgeDescriptor,
    SelectedResolutionMountContext, SelectedRootBridgeDescriptor, SelectedRootPathHalf,
    SharedNameInterner, binding_origin_rank, language_callables_occupy_value_namespace,
    language_implicit_root_member_names, language_import_owner_steps_bind_singletons,
    language_jvm_declaration_access_rules, language_jvm_package_requires_directory_agreement,
    package_domain_semantic,
};
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionConstructionRequirementKind, ResolutionGapKind, ResolutionImportRouteKind,
    ResolutionImportSelectorKind, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionNamespace, ResolutionSiteId, ResolutionSupertypeKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, PrecedenceTier};
use brokk_bifrost_jvm::java::import_split::{
    JavaImportSplitGap, JavaSingleTypeImportProof, prove_java_single_type_import_from_selected_rows,
};
use std::cell::Cell;
use std::sync::{Arc, Mutex};

// Immutable derivation for the exact JVM source revision selected by this operation.
const CONTEXT_SELECTION: &str = r#"
SELECT c.context_id
FROM main.jvm_context_revisions AS c
JOIN temp.selected_workspace_revisions AS selected
  ON selected.workspace_id=c.workspace_id AND selected.lang=c.lang
 AND selected.generation=c.generation AND selected.revision=c.revision
WHERE c.lang=?1 AND c.derivation_version=1
"#;

const SCALA_PREDEF_DEFAULT_IMPORT: &str = "scala.Predef";

/// Opt-in exact-input counts. This ledger belongs to one query, never a reader
/// connection or an analyzer retained for a later request.
#[derive(Default)]
#[doc(hidden)]
pub struct JvmContextReadProfile {
    #[doc(hidden)]
    pub calls: HashMap<(&'static str, String), u64>,
}

#[cfg(any(test, feature = "test-support"))]
impl JvmContextReadProfile {
    #[doc(hidden)]
    pub fn calls(&self, kind: &str) -> u64 {
        self.calls
            .iter()
            .filter(|((entry, _), _)| *entry == kind)
            .map(|(_, calls)| *calls)
            .sum()
    }
}

impl Drop for JvmContextReadProfile {
    fn drop(&mut self) {
        if self.calls.is_empty() {
            return;
        }
        let reads = self.calls.iter().map(|((kind, key), calls)| {
            serde_json::json!({"kind": kind, "key": key, "calls": calls})
        }).collect::<Vec<_>>();
        crate::analyzer::resolution::seam_profile::record_jvm_operation_reads(
            serde_json::Value::Array(reads),
        );
    }
}

#[derive(Clone, Copy)]
struct JvmPackageImportContext<'a> {
    context_id: i64,
    source_ordinal: SelectedResolutionMountOrdinal,
    source_path: &'a str,
    caller_version: Option<i64>,
    caller_package: Option<&'a str>,
    lookup: Option<&'a str>,
    package_plan: &'a JvmFilePackagePlan,
}

// The mount language remains part of every candidate row. Package equality
// narrows the selected inventory; it does not erase language identity.
#[doc(hidden)]
pub const JVM_IMPORT_TARGET_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.workspace_file_package_rows AS package INDEXED BY idx_workspace_file_package_rows_name
CROSS JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.file_version_id=package.file_version_id
WHERE package.package_name=?1 AND mounted.storage_language IN ('java','kotlin','scala')
UNION ALL
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM temp.selected_resolution_mounts AS mounted
CROSS JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id
WHERE mounted.file_version_id IS NULL
  AND mounted.storage_language IN ('java','kotlin','scala')
  AND meta.content_package=?1 AND meta.is_complete=1
"#;

// Alias readers supply their exact semantic-language eligibility before any
// full mount records are read. Keep the persisted and transient package arms.
pub(in crate::analyzer::store) const JVM_ELIGIBLE_IMPORT_TARGET_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.workspace_file_package_rows AS package INDEXED BY idx_workspace_file_package_rows_name
CROSS JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.file_version_id=package.file_version_id
WHERE package.package_name=?1 AND mounted.storage_language IN ('java','kotlin','scala')
  AND mounted.semantic_language IN (?2,?3,?4)
UNION ALL
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM temp.selected_resolution_mounts AS mounted
CROSS JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id
WHERE mounted.file_version_id IS NULL
  AND mounted.storage_language IN ('java','kotlin','scala')
  AND mounted.semantic_language IN (?2,?3,?4)
  AND meta.content_package=?1 AND meta.is_complete=1
"#;

// Package membership is checked only for name/uncertainty hits, never by
// enumerating all closed files in a package. Both branches are primary-key seeks.
const JVM_IMPORT_TARGET_PACKAGE_FILTER: &str = r#"
AND (EXISTS (
  SELECT 1 FROM main.workspace_file_package_rows AS package
  WHERE package.file_version_id=mounted.file_version_id AND package.package_name=?1
) OR (mounted.file_version_id IS NULL AND EXISTS (
  SELECT 1 FROM main.blob_meta AS meta
  WHERE meta.blob_id=mounted.blob_id AND meta.content_package=?1 AND meta.is_complete=1
)))
"#;

// The shared-identity catalog index selects names across blobs; the member
// lookup index then turns each blob-local name into member hosts.
const JVM_NAMED_PACKAGE_MEMBER_TARGETS_HEAD: &str = r#"
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM json_each(?2) AS requested
CROSS JOIN main.resolution_semantic_catalog AS lookup
  ON lookup.shared_identity=requested.value
CROSS JOIN main.resolution_package_members AS member
  INDEXED BY resolution_package_members_lookup
  ON member.blob_id=lookup.blob_id AND member.lookup_key=lookup.local_key
CROSS JOIN temp.selected_resolution_mounts AS mounted
  INDEXED BY selected_resolution_mounts_blob_ordinal ON mounted.blob_id=member.blob_id
CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=mounted.mount_ordinal
WHERE mounted.semantic_language IN (?3,?4,?5)
"#;

const JVM_STAGE_PACKAGE_MEMBER_HOSTS: &str = r#"SELECT mounted.mount_ordinal, mounted.file_version_id
FROM temp.selected_resolution_mounts AS mounted
WHERE mounted.mount_ordinal IN (
  SELECT DISTINCT member.host_ordinal FROM temp.selected_resolution_stage_package_members AS member
  WHERE member.host_ordinal>=0
)"#;

const JVM_NAMED_IMPORT_TARGETS_HEAD: &str = r#"
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.resolution_identities AS identity INDEXED BY resolution_identities_spelling
CROSS JOIN main.resolution_path_endpoint_headers AS header
  INDEXED BY resolution_path_endpoint_headers_search
  ON header.direction='forward' AND header.identity_id=identity.id
CROSS JOIN temp.selected_resolution_mounts AS mounted
  INDEXED BY selected_resolution_mounts_blob_ordinal ON mounted.blob_id=header.blob_id
WHERE identity.spelling=?2 AND identity.semantic_language=?3
  AND identity.namespace IN (?4,?5) AND mounted.storage_language IN (?6,?7,?8)
"#;

// The open export reader asks every root gap lookup bucket, not just the
// demanded name. Stage host ranges enumerate only query-local staged rows;
// every host with a path or gap stays eligible for the existing full reader.
const JVM_IMPORT_UNCERTAINTY_HEADS: [&str; 5] = [
    r#"SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.resolution_path_endpoint_headers AS header
  INDEXED BY resolution_path_endpoint_headers_search
CROSS JOIN temp.selected_resolution_mounts AS mounted
  INDEXED BY selected_resolution_mounts_blob_ordinal ON mounted.blob_id=header.blob_id
WHERE header.direction='forward' AND header.identity_id IS NULL"#,
    r#"SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.resolution_gaps AS gap INDEXED BY resolution_gaps_fragment_wide
CROSS JOIN temp.selected_resolution_mounts AS mounted
  INDEXED BY selected_resolution_mounts_blob_ordinal ON mounted.blob_id=gap.blob_id
WHERE gap.covers<=3 AND gap.covers IN (0,2)"#,
    r#"SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.resolution_gaps AS gap INDEXED BY resolution_gaps_root_branches
CROSS JOIN temp.selected_resolution_mounts AS mounted
  INDEXED BY selected_resolution_mounts_blob_ordinal ON mounted.blob_id=gap.blob_id
WHERE gap.covers=5 AND gap.subject=-1"#,
    r#"SELECT mounted.mount_ordinal, mounted.file_version_id
FROM temp.selected_resolution_mounts AS mounted
WHERE mounted.mount_ordinal IN (
  SELECT DISTINCT path.host_ordinal FROM temp.selected_resolution_stage_paths AS path
  WHERE path.host_ordinal>=0
)"#,
    r#"SELECT mounted.mount_ordinal, mounted.file_version_id
FROM temp.selected_resolution_mounts AS mounted
WHERE mounted.mount_ordinal IN (
  SELECT DISTINCT gap.host_ordinal FROM temp.selected_resolution_stage_gaps AS gap
    INDEXED BY selected_resolution_stage_gap_tuple
  WHERE gap.host_ordinal>=0
)"#,
];

pub(in crate::analyzer::store) fn jvm_named_package_member_targets_sql() -> String {
    format!("{JVM_NAMED_PACKAGE_MEMBER_TARGETS_HEAD} {JVM_IMPORT_TARGET_PACKAGE_FILTER}")
}

pub(in crate::analyzer::store) fn jvm_package_member_uncertainty_sql() -> String {
    JVM_IMPORT_UNCERTAINTY_HEADS.iter().copied()
        .chain(std::iter::once(JVM_STAGE_PACKAGE_MEMBER_HOSTS))
        .map(|head| format!("{head} AND mounted.semantic_language IN (?2,?3,?4) \
            AND EXISTS(SELECT 1 FROM temp.selected_resolution_scope_mounts scope WHERE scope.mount_ordinal=mounted.mount_ordinal) \
            {JVM_IMPORT_TARGET_PACKAGE_FILTER}"))
        .collect::<Vec<_>>().join(" UNION ")
}

pub(in crate::analyzer::store) fn jvm_package_presence_sql() -> String {
    format!(
        "SELECT EXISTS({})",
        nominal_rules::jvm_package_rules()
            .import_target_mounts()
            .statement
    )
}

pub(in crate::analyzer::store) const JVM_SUPERTYPE_REFERENCE_MEMBERSHIP: &str = r#"
SELECT DISTINCT reference
FROM main.resolution_supertypes INDEXED BY resolution_supertypes_reference
WHERE blob_id=?1 AND reference IN (SELECT value FROM json_each(?2))
"#;

// Alias candidates are read by the exact selected blob and imported JVM
// member spelling. resolution_jvm_aliases_member_name bounds both predicates,
// including the common empty result.
pub(in crate::analyzer::store) const SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER: &str = r#"
SELECT alias.alias, alias.declaration_site, alias.status,
       declaration.semantic_key, alias.kind, alias.is_static
FROM main.resolution_jvm_aliases AS alias
JOIN main.resolution_semantic_sites AS declaration
  ON declaration.blob_id=alias.blob_id
 AND declaration.source_site=alias.declaration_site
 AND declaration.semantic_role='definition'
WHERE alias.blob_id=?1 AND alias.member_name=?2
"#;

// An exact alias endpoint bypasses lexical lookup. Reuse the persisted
// omitted-binder frontiers: the declaration itself, and the scope checkpoints
// of its authored binder paths. A named omitted declaration in that scope can
// affect export authority too, so this read intentionally includes keyed gaps.
// Reverse-only macro inventory and gaps in other scopes are not alias authority.
pub(in crate::analyzer::store) const SELECTED_JVM_ALIAS_DECLARATION_GAPS: &str = r#"
SELECT gap.reason
FROM main.resolution_gaps AS gap
JOIN main.resolution_gap_reasons AS reason
  ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason
WHERE gap.blob_id=?1 AND gap.covers=6 AND gap.subject=?2 AND gap.lookup=0
  AND reason.origin=?3
UNION ALL
SELECT gap.reason
FROM main.resolution_paths AS binder INDEXED BY resolution_paths_reverse
CROSS JOIN main.resolution_gaps AS gap
  ON gap.blob_id=binder.blob_id AND gap.covers=5 AND gap.subject=binder.start_node
JOIN main.resolution_gap_reasons AS reason
  ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason
WHERE binder.blob_id=?1 AND binder.end_node=?2 AND binder.start_node<>-1
  AND binder.start_lead_identity IS NOT NULL
  AND binder.end_lead_identity IS NULL AND binder.end_lead_local IS NULL
  AND reason.origin=?3
"#;

const SELECTED_JVM_ALIASES_BY_BLOB: &str = r#"
SELECT alias.alias, alias.status
FROM main.resolution_jvm_aliases AS alias
WHERE alias.blob_id=?1
"#;

// Package rows are source-derived and indexed by the exact canonical package.
// Only mounted versions selected by this operation can supply candidates.
pub(in crate::analyzer::store) const JAVA_IMPORT_TARGET_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM main.workspace_file_package_rows AS package INDEXED BY idx_workspace_file_package_rows_name
CROSS JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.file_version_id=package.file_version_id
WHERE package.package_name=?1 AND mounted.storage_language='java'
UNION ALL
SELECT mounted.mount_ordinal, mounted.file_version_id
FROM temp.selected_resolution_mounts AS mounted
CROSS JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id
WHERE mounted.file_version_id IS NULL AND mounted.storage_language='java'
  AND meta.content_package=?1 AND meta.is_complete=1
"#;

// Exact root evidence supports same-project main/test access and positive
// direct reactor dependencies. Unknown models never establish exclusion.
#[doc(hidden)]
pub const SOURCE_ACCESS: &str = r#"
WITH caller AS (
 SELECT m.*, p.group_id, p.artifact_id, p.version_state, p.version_value
 FROM main.jvm_selected_source_root_files m
 JOIN main.jvm_selected_projects p ON p.context_id=m.context_id AND p.project_id=m.project_id
 WHERE m.context_id=?1 AND
   ((?2 IS NOT NULL AND m.source_file_version_id=?2) OR (?2 IS NULL AND m.rel_path=?3))
), target_exact AS (
 SELECT m.*, p.group_id, p.artifact_id, p.version_state, p.version_value
 FROM main.jvm_selected_source_root_files m
 JOIN main.jvm_selected_projects p ON p.context_id=m.context_id AND p.project_id=m.project_id
 WHERE m.context_id=?1 AND
   ((?4 IS NOT NULL AND m.source_file_version_id=?4) OR (?4 IS NULL AND m.rel_path=?5))
), target_root AS (
 -- Source roots are shared by JVM languages, while exact selected source-file
 -- rows are language-scoped. The selected target mount supplies this path.
 SELECT root.project_id, root.role, project.pom_path, project.pom_content_oid,
        project.group_id, project.artifact_id, project.version_state, project.version_value
 FROM main.jvm_source_roots root
 JOIN main.jvm_selected_projects project
   ON project.context_id=root.context_id AND project.project_id=root.project_id
 WHERE root.context_id=?1 AND ?5 >= root.root_path || '/' AND ?5 < root.root_path || '0'
), target AS (
 SELECT project_id, role, pom_path, pom_content_oid, group_id, artifact_id, version_state, version_value
 FROM target_exact
 UNION ALL
 SELECT project_id, role, pom_path, pom_content_oid, group_id, artifact_id, version_state, version_value
 FROM target_root
 WHERE NOT EXISTS(SELECT 1 FROM target_exact)
)
SELECT CASE
 WHEN (SELECT count(*) FROM caller)<>1 OR (SELECT count(*) FROM target)<>1 THEN 'unknown'
 WHEN caller.pom_path=target.pom_path AND caller.pom_content_oid=target.pom_content_oid
 THEN CASE WHEN caller.role='main' AND target.role='test' THEN 'excluded' ELSE 'known' END
 -- A selected workspace source root establishes visibility for its own files;
 -- Maven dependency/configuration gaps do not make those files external.
 WHEN target.project_id=caller.project_id AND (SELECT count(*) FROM target_root)=1 THEN 'known'
 WHEN EXISTS(SELECT 1 FROM main.jvm_selected_context_gaps g WHERE g.context_id=?1
             AND g.project_id IN (caller.project_id,target.project_id)) THEN 'unknown'
 WHEN target.role='main' AND target.version_state='resolved' AND EXISTS(
   SELECT 1 FROM main.jvm_direct_dependencies d
   WHERE d.context_id=?1 AND d.project_id=caller.project_id
     AND d.group_id_state='resolved' AND d.group_id_value=target.group_id
     AND d.artifact_id_state='resolved' AND d.artifact_id_value=target.artifact_id
     AND d.version_state='resolved' AND d.version_value=target.version_value
     AND (d.artifact_type_state='missing' OR (d.artifact_type_state='resolved' AND d.artifact_type_value='jar'))
     AND (d.classifier_state='missing' OR (d.classifier_state='resolved' AND d.classifier_value=''))
     AND (d.scope_state='missing' OR (d.scope_state='resolved' AND
          (d.scope_value IN ('compile','provided') OR (d.scope_value='test' AND caller.role='test'))))
 ) THEN 'known'
 ELSE 'unknown' END
FROM caller CROSS JOIN target
"#;

/// Language/path identify the demanded file; scope and staged content identify
/// the exact selected rows read by its import builder. Entries die with the query.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmFileContextKey {
    language: Language,
    path: String,
    lookup: Option<String>,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmFileContextMemo = ExactReadMemo<JvmFileContextKey, JvmImportContext>;

pub(super) type JvmContextPreparationMemo =
    RequestContextMemo<JvmFileContextKey, Arc<JvmContextPreparation>>;

pub(super) struct JvmContextPreparation {
    context_id: i64,
    source: SelectedResolutionOperationMount,
    source_record: Arc<super::super::resolution_selection::SelectedResolutionMountRecord>,
    source_package: Option<String>,
    inventory_reason: Option<SemanticId>,
    binders: Vec<ImportBinder>,
    package_plan: JvmFilePackagePlan,
    qualifier_names_by_demand: HashMap<String, HashSet<String>>,
    package_reference_occurrences: Vec<crate::analyzer::resolution::LoweredPackageReference>,
    package_references: Vec<crate::analyzer::resolution::LoweredPackageReference>,
    same_package_lookups: BTreeSet<SemanticId>,
    references_by_name: HashMap<String, Vec<crate::analyzer::resolution::LoweredPackageReference>>,
    unqualified_type_references: BTreeSet<SemanticId>,
    // Share the selected rows without cloning them into each named builder.
    // Short-lived ledger locks preserve transfer of this owned preparation.
    imports: ContextPlanMemo<CandidatePathIdentity, Arc<JvmDerivedImport>>,
    java_imports: ContextPlanMemo<CandidatePathIdentity, Arc<JavaDerivedImport>>,
    implicit: ContextPlanCell<Arc<JvmImplicitContextParts>>,
    external_providers: JvmExternalProviderBlueprint,
}

type JvmScalaImports = BTreeMap<(BindingNodeId, String), Vec<ResolutionLookupSemanticRecipe>>;
type JvmScalaWildcards = BTreeMap<BindingNodeId, Vec<Vec<ResolutionLookupSemanticRecipe>>>;

struct JvmDerivedImport {
    earlier_head: Option<Vec<ResolutionLookupSemanticRecipe>>,
    earlier_wildcards: Vec<Vec<ResolutionLookupSemanticRecipe>>,
    bridges: Vec<SelectedRootBridgeDescriptor>,
    gaps: Vec<JvmImportContextGap>,
    model_routes: Vec<ModelDeclaredJvmImportRoute>,
    open_aliases: Vec<String>,
    inventory_open: bool,
    scala_imports: JvmScalaImports,
    scala_wildcards: JvmScalaWildcards,
}

struct JavaDerivedImport {
    bridges: Vec<SelectedRootBridgeDescriptor>,
    external_static_imports: Vec<JavaExternalStaticImportBoundary>,
    static_import_searches: BTreeMap<(Option<ResolutionSiteId>, bool), JavaStaticImportSearch>,
    open_jvm_alias_imports: Vec<String>,
    scoped_gaps: Vec<JvmImportContextGap>,
}

#[derive(Clone)]
struct JavaStaticImportSearch {
    source_site: Option<ResolutionSiteId>,
    staged: bool,
    complete: bool,
    found: bool,
    kind: ResolutionImportRouteKind,
}

struct JvmImplicitContextParts {
    bridges: Vec<SelectedPackageBridgeDescriptor>,
    gaps: Vec<JvmImportContextGap>,
    same_package_lookups: BTreeSet<SemanticId>,
    durable_owners: BTreeMap<String, crate::analyzer::resolution::ExternalOwnerIdentity>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmImplicitProjectKey {
    context: i64,
    caller: Option<i64>,
    caller_path: usize,
    target: Option<i64>,
    target_path: usize,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmImplicitProjectMemo = RequestContextMemo<JvmImplicitProjectKey, bool>;

#[derive(PartialEq, Eq, Hash)]
pub(super) struct JvmSourceDomainKey {
    context: i64,
    file_version: Option<i64>,
    path: usize,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

// Cache absent and ambiguous domains too. Sharing the root avoids allocating a
// PathBuf on every pair-memo miss that revisits the same file.
pub(super) type JvmSourceDomainMemo =
    RequestContextMemo<JvmSourceDomainKey, Option<Arc<super::super::maven::JvmSourceDomain>>>;

// The build-model evidence depends on context selection, not a source pair.
#[derive(Clone, Copy)]
pub(super) struct JvmImplicitProjectContext {
    has_selected_project: bool,
    language: Language,
}

pub(super) type JvmImplicitProjectContextMemo =
    RequestContextMemo<(i64, [u8; 32], (u64, u64)), JvmImplicitProjectContext>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmLookupRecipeKey {
    fragment: BindingFragmentId,
    semantic: SemanticId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmImportTargetKey {
    mounts: ImportTargetMounts,
    package: String,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmNamedImportTargetKey {
    mounts: ImportTargetMounts,
    package: String,
    spelling: String,
    domain: i64,
    namespaces: Box<[i64]>,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmNamedImportTargetMemo =
    ExactReadMemo<JvmNamedImportTargetKey, Arc<JvmImportTargetRows>>;
pub(super) type JvmImportUncertaintyMemo =
    ExactReadMemo<JvmImportTargetKey, Arc<[JvmImportTarget]>>;

pub(super) type JvmImportTarget = (u32, Option<i64>);

#[doc(hidden)]
pub struct JvmImportTargetRows {
    rows: Box<[JvmImportTarget]>,
    ordered: Box<[JvmImportTarget]>,
}

#[cfg(any(test, feature = "test-support"))]
impl JvmImportTargetRows {
    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

pub(super) type JvmImportTargetMemo = ExactReadMemo<JvmImportTargetKey, Arc<JvmImportTargetRows>>;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmAliasRowsKey {
    blob: i64,
    member: String,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

#[doc(hidden)]
pub struct JvmAliasRow {
    alias: u32,
    declaration_site: u32,
    status: String,
    declaration_key: u32,
    kind: String,
    is_static: bool,
}

pub(super) type JvmAliasRowsMemo = ExactReadMemo<JvmAliasRowsKey, Arc<[JvmAliasRow]>>;

#[doc(hidden)]
pub struct JvmGeneratedLookup {
    recipe: ResolutionLookupSemanticRecipe,
    semantic: std::sync::OnceLock<SemanticId>,
}

impl JvmGeneratedLookup {
    fn semantic(&self, names: &dyn SharedNameInterner) -> SemanticId {
        *self.semantic.get_or_init(|| self.recipe.semantic(names))
    }
}

// A generated recipe depends only on these value inputs. Its shared ID is
// minted by this operation's interner and never retained by another request.
pub(super) type JvmGeneratedLookupMemo = ExactReadMemo<
    (
        crate::analyzer::resolution::ResolutionIdentityDomain,
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        String,
    ),
    Arc<JvmGeneratedLookup>,
>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmPackageTargetKey {
    package: String,
    lookups: Box<[SemanticId]>,
    languages: [Option<&'static str>; 3],
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmPackageTargetMemo = ExactReadMemo<JvmPackageTargetKey, Arc<JvmImportTargetRows>>;
pub(super) type JvmPackagePresenceMemo = ExactReadMemo<JvmImportTargetKey, bool>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmPackageMemberKey {
    mount: SelectedResolutionMountOrdinal,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

type JvmPackageMemberSet = HashMap<SemanticId, Arc<[LoweredPackageMember]>>;
pub(super) type JvmPackageMemberMemo =
    RequestContextMemo<JvmPackageMemberKey, Arc<JvmPackageMemberSet>>;

#[derive(Clone)]
struct JvmPackageCandidate {
    mount: SelectedResolutionMountOrdinal,
    version: Option<i64>,
    order: usize,
    members: Arc<[LoweredPackageMember]>,
}

pub(super) struct JvmPackageIndex {
    empty: bool,
    by_lookup: HashMap<SemanticId, Vec<JvmPackageCandidate>>,
}

pub(super) type JvmPackageIndexMemo = ExactReadMemo<JvmPackageTargetKey, Arc<JvmPackageIndex>>;

struct JvmPlannedPackage {
    empty: bool,
    candidates: HashMap<SemanticId, Vec<JvmPackageCandidate>>,
}

type JvmFilePackagePlan = HashMap<String, JvmPlannedPackage>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmEndpointKey {
    node: BindingNodeId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmEndpointMemo = ExactReadMemo<JvmEndpointKey, Arc<[BatchEndpointClassification]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmVisibilityKey {
    definition: SemanticId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmVisibilityMemo =
    ExactReadMemo<JvmVisibilityKey, Arc<[LoweredDeclarationVisibilityProperty]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmRootExportKey {
    mount: SelectedResolutionMountOrdinal,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

#[doc(hidden)]
pub struct JvmRootExportInventory {
    pub(super) halves: Vec<SelectedRootPathHalf>,
    pub(super) outcome: FactReadOutcome,
}

// Share immutable pages inside this one query instead of cloning the whole
// inventory for every route. No handle is retained by a later request.
pub(super) type JvmRootExportMemo = ExactReadMemo<JvmRootExportKey, Arc<JvmRootExportInventory>>;

#[derive(Clone)]
#[doc(hidden)]
pub enum JvmImportContext {
    Ready {
        context: Box<SelectedResolutionContextSet>,
        external_static_imports: Vec<JavaExternalStaticImportBoundary>,
        inventory_reason: Option<SemanticId>,
        open_jvm_alias_imports: Vec<String>,
        scoped_gaps: Vec<JvmImportContextGap>,
    },
    Unavailable,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct JvmImportContextGap {
    #[doc(hidden)]
    pub source_token: SemanticId,
    pub(crate) source_reference: Option<SemanticId>,
    #[doc(hidden)]
    pub lookup: ResolutionLookupSemanticRecipe,
    #[doc(hidden)]
    pub reason: SemanticId,
    #[doc(hidden)]
    pub kind: &'static str,
    #[doc(hidden)]
    pub owner: Option<String>,
    pub(crate) boundary_status: Option<crate::analyzer::structural::BoundaryStatus>,
    pub(crate) nominal_type_identity: Option<SemanticId>,
    suppress_if_same_package_candidate: bool,
}

/// One exact selected terminal route published for a JVM root reference.
/// `complete` is set only when the selected package/member pages and access
/// evidence exhaust this namespace's candidate space.
pub(in crate::analyzer) struct JvmRoutePublication {
    pub(super) bridges: Vec<SelectedRootBridgeDescriptor>,
    pub(super) selected_targets: BTreeSet<SemanticId>,
    pub(super) complete: bool,
}

struct JvmAliasImportBridges {
    bridges: Vec<SelectedRootBridgeDescriptor>,
    open_imports: Vec<String>,
    found_alias: bool,
    coverage_gaps: Vec<JvmImportContextGap>,
}

fn jvm_alias_coverage_gaps(
    source_token: SemanticId,
    source_reference: Option<SemanticId>,
    lookup: &ResolutionLookupSemanticRecipe,
    owner: &str,
    completion: &ResolutionCompletion,
) -> Vec<JvmImportContextGap> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Vec::new();
    };
    reasons
        .iter()
        .map(|reason| {
            let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                unreachable!("alias surfaces contain only persisted coverage: {reason:?}");
            };
            JvmImportContextGap {
                source_token,
                source_reference,
                lookup: lookup.clone(),
                reason: *reason,
                kind: "jvm-import-alias-coverage-open",
                owner: Some(owner.to_owned()),
                boundary_status: None,
                nominal_type_identity: None,
                suppress_if_same_package_candidate: false,
            }
        })
        .collect()
}

// Gap ownership differs, but recording and identity construction stay shared.
pub(super) fn record_scoped_jvm_import_gap(
    operation: &SelectedResolutionOperation<'_, '_>,
    spec: JvmImportContextGapSpec,
    gaps: &mut Vec<JvmImportContextGap>,
    _inventory_open: &mut bool,
    cancellation: &CancellationToken,
) -> Result<()> {
    gaps.push(operation.jvm_import_context_gap(spec, cancellation)?);
    Ok(())
}

pub(super) fn record_open_jvm_import_gap(
    _operation: &SelectedResolutionOperation<'_, '_>,
    _spec: JvmImportContextGapSpec,
    _gaps: &mut Vec<JvmImportContextGap>,
    inventory_open: &mut bool,
    _cancellation: &CancellationToken,
) -> Result<()> {
    *inventory_open = true;
    Ok(())
}

pub(in crate::analyzer) struct JvmImportContextGapSpec {
    source: BindingFragmentId,
    source_token: SemanticId,
    source_reference: Option<SemanticId>,
    kind: &'static str,
    owner: Option<String>,
    lookup: ResolutionLookupSemanticRecipe,
    detail: String,
}

#[doc(hidden)]
pub type JavaImportContext = JvmImportContext;

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct JavaExternalStaticImportBoundary {
    pub member: String,
    pub owner: String,
}

#[derive(Clone, Copy)]
enum JvmPackageRelation {
    Same,
    Different,
    Unknown,
}
#[derive(Clone, Copy)]
struct JvmDeclarationAccessContext<'a> {
    relation: JvmPackageRelation,
    caller_package: Option<&'a str>,
    reference: Option<SemanticId>,
    scope_head: Option<BindingNodeId>,
    source_node: Option<BindingNodeId>,
    import_token: Option<SemanticId>,
}
impl<'a> JvmDeclarationAccessContext<'a> {
    fn between(caller_package: Option<&'a str>, target: &str) -> Self {
        let relation = match caller_package {
            Some(package) if package == target => JvmPackageRelation::Same,
            Some(_) => JvmPackageRelation::Different,
            None => JvmPackageRelation::Unknown,
        };
        Self {
            relation,
            caller_package,
            reference: None,
            scope_head: None,
            source_node: None,
            import_token: None,
        }
    }
    fn with_reference(mut self, reference: Option<SemanticId>) -> Self {
        self.reference = reference;
        self
    }
    fn with_source_node(mut self, source_node: BindingNodeId) -> Self {
        self.source_node = Some(source_node);
        self
    }
    fn with_import(mut self, token: SemanticId) -> Self {
        self.import_token = Some(token);
        self
    }
    fn with_scope(mut self, scope_head: Option<BindingNodeId>) -> Self {
        self.scope_head = scope_head;
        self
    }
}

enum JvmDeclarationAccess {
    Ready(ResolutionCompletion),
    Excluded,
    Cancelled,
}

struct JvmPackageBridgeCandidate<'a> {
    reference: &'a LoweredPackageReference,
    source_recipe: &'a ResolutionLookupSemanticRecipe,
    package: &'a str,
    candidate: &'a JvmPackageCandidate,
    target: SelectedResolutionOperationMount,
    target_digest: [u8; 32],
    target_lookup: Arc<JvmGeneratedLookup>,
    target_lookup_semantic: SemanticId,
    access: ResolutionCompletion,
}

struct JvmPackageBridgeEvidence<'a> {
    target_mount: &'a SelectedResolutionOperationMount,
    source_lookup: &'a ResolutionLookupSemanticRecipe,
    target_lookup: &'a JvmGeneratedLookup,
    target_definition: BindingNodeId,
    route_identity: [u8; 32],
    precedence: Option<PrecedenceStep>,
    candidate_origin_rank: Option<u32>,
    bridge: Option<SelectedJvmBridgeEvidence>,
}

struct JvmPackageBridgeRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    source: &'a SelectedResolutionOperationMount,
    context_id: i64,
    caller_version: Option<i64>,
    caller_package: Option<&'a str>,
    same_package_lookups: RefCell<&'a mut BTreeSet<SemanticId>>,
}

impl<'a> PackageBridgeRules for JvmPackageBridgeRules<'a, '_, '_> {
    type Extra = &'a JvmPackageBridgeCandidate<'a>;
    type Admission = PackageBridgeAdmission<JvmPackageBridgeEvidence<'a>>;

    fn admit(
        &self,
        operation: &ReadySelectedResolution<'_, '_>,
        pair: &PackageBridgePair<'_, Self::Extra>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        let reference = pair.reference;
        let member = pair.member;
        let candidate = pair.extra;
        let source_language = self.source.semantic_language();
        let target_mount = &candidate.target;
        debug_assert_ne!(pair.target_mount, self.source.ordinal());
        let target_language = target_mount.semantic_language();
        let target_version = candidate.candidate.version;
        let relation = JvmDeclarationAccessContext::between(self.caller_package, candidate.package)
            .with_reference(Some(reference.reference));
        if member.namespace != reference.namespace
            || member.lookup != candidate.target_lookup_semantic
        {
            return Ok(None);
        }
        let completion = match self.operation.jvm_declaration_access(
            member.definition,
            relation,
            &candidate.access,
            cancellation,
        )? {
            JvmDeclarationAccess::Ready(completion) => completion,
            JvmDeclarationAccess::Excluded | JvmDeclarationAccess::Cancelled => return Ok(None),
        };
        let Some(target_definition) = operation
            .lexical_source()
            .lookup_definition_node(member.definition, cancellation)?
        else {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            return Err(StoreError::corrupt(
                "selected JVM package member lacks a definition node",
            ));
        };
        let evidence = if target_language == source_language {
            None
        } else {
            let Some(visibility) =
                self.operation
                    .jvm_bridge_visibility(member.definition, relation, cancellation)?
            else {
                return Ok(None);
            };
            Some(SelectedJvmBridgeEvidence {
                provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                    source_package: reference.domain,
                    target_package: member.domain,
                },
                source_namespace: reference.namespace,
                target_namespace: member.namespace,
                visibility,
                dependency_identity: jvm_dependency_identity(
                    self.context_id,
                    self.caller_version,
                    self.source.persisted_relative_path(),
                    target_version,
                    target_mount.persisted_relative_path(),
                ),
                target_declaration: member.definition,
                target_definition,
            })
        };
        let route_identity = jvm_package_route_identity(
            source_language,
            target_language,
            candidate.package,
            reference,
            candidate.target_digest,
            |key| operation.identity_content_digest(key, cancellation),
        )?;
        if Some(candidate.package) == self.caller_package
            && completion == ResolutionCompletion::Complete
        {
            self.same_package_lookups
                .borrow_mut()
                .insert(reference.lookup);
        }
        let precedence = SelectedResolutionOperation::selected_jvm_package_precedence(
            source_language,
            self.caller_package,
            candidate.package,
        );
        Ok(Some(PackageBridgeAdmission {
            evidence: JvmPackageBridgeEvidence {
                target_mount,
                source_lookup: candidate.source_recipe,
                target_lookup: &candidate.target_lookup,
                target_definition,
                route_identity,
                precedence: precedence.tier.map(|tier| PrecedenceStep {
                    tier,
                    ordinal: 0,
                    semantic: reference
                        .choice
                        .expect("selected Kotlin package choice is persisted"),
                }),
                candidate_origin_rank: precedence.candidate_origin_rank,
                bridge: evidence,
            },
            completion,
        }))
    }

    fn descriptor(
        &self,
        pair: &PackageBridgePair<'_, Self::Extra>,
        admission: Self::Admission,
    ) -> SelectedPackageBridgeDescriptor {
        let evidence = admission.evidence;
        SelectedPackageBridgeDescriptor::new_jvm_import(
            self.source.fragment(),
            evidence.target_mount.fragment(),
            self.source.semantic_language(),
            evidence.target_mount.semantic_language(),
            pair.reference,
            pair.member,
            evidence.source_lookup,
            &evidence.target_lookup.recipe,
            evidence.target_definition,
            evidence.route_identity,
            evidence.precedence,
            &self.operation.ready.shared_names(),
            evidence.bridge,
            admission.completion,
        )
        .with_candidate_origin_rank(evidence.candidate_origin_rank)
    }
}

struct JavaPackageBridgeCandidate<'a> {
    reference: &'a LoweredPackageReference,
    candidate: &'a JvmPackageCandidate,
    target: SelectedResolutionOperationMount,
    access: ResolutionCompletion,
}

struct JavaPackageBridgeRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    source: &'a SelectedResolutionOperationMount,
    caller_package: Option<&'a str>,
}

impl<'a> PackageBridgeRules for JavaPackageBridgeRules<'a, '_, '_> {
    type Extra = &'a JavaPackageBridgeCandidate<'a>;
    type Admission = PackageBridgeAdmission<BindingFragmentId>;

    fn admit(
        &self,
        _operation: &ReadySelectedResolution<'_, '_>,
        pair: &PackageBridgePair<'_, Self::Extra>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        debug_assert_ne!(pair.target_mount, self.source.ordinal());
        if pair.member.domain != pair.reference.domain
            || pair.member.namespace != pair.reference.namespace
        {
            return Ok(None);
        }
        let access = match self.operation.jvm_declaration_access(
            pair.member.definition,
            JvmDeclarationAccessContext::between(
                self.caller_package,
                self.caller_package.unwrap_or(""),
            ),
            &pair.extra.access,
            cancellation,
        )? {
            JvmDeclarationAccess::Ready(completion) => completion,
            JvmDeclarationAccess::Excluded | JvmDeclarationAccess::Cancelled => return Ok(None),
        };
        Ok(Some(PackageBridgeAdmission {
            evidence: pair.target_fragment,
            completion: access,
        }))
    }

    fn descriptor(
        &self,
        pair: &PackageBridgePair<'_, Self::Extra>,
        admission: Self::Admission,
    ) -> SelectedPackageBridgeDescriptor {
        SelectedPackageBridgeDescriptor::new(
            self.source.fragment(),
            admission.evidence,
            Language::Java,
            pair.reference,
            pair.member,
            admission.completion,
        )
    }
}

/// SOURCE_ACCESS itself requires one root row per endpoint. The JVM supplies
/// exactly one key per endpoint, so combine receives one pair. Ambiguous exact
/// roots remain unknown until the conventional-domain proof establishes agreement
/// across every selected candidate for each endpoint.
struct JvmUnitAccessRules<'a, 'p, 'q> {
    operation: &'a SelectedResolutionOperation<'p, 'q>,
    context: i64,
    caller_path: &'a str,
    target_path: &'a str,
}

impl UnitAccessRules for JvmUnitAccessRules<'_, '_, '_> {
    fn exact_relation(
        &self,
        caller: &PlacementKey,
        target: &PlacementKey,
    ) -> Result<Option<UnitAccess>> {
        self.operation
            .profile_jvm_read("derive_source_access", (caller, target));
        if !self
            .operation
            .jvm_implicit_project_context(self.context)?
            .has_selected_project
        {
            return Ok(None);
        }
        let access = self
            .operation
            .ready
            .inventory
            .connection()
            .prepare_cached(SOURCE_ACCESS)?
            .query_row(
                rusqlite::params![
                    self.context,
                    caller.subject.file_version,
                    self.caller_path,
                    target.subject.file_version,
                    self.target_path
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(match access.as_deref().unwrap_or("unknown") {
            "excluded" => Some(UnitAccess::NotVisible),
            "known" => Some(UnitAccess::Visible),
            "unknown" => None,
            _ => unreachable!("source access SQL has three outcomes"),
        })
    }

    fn unknown_reason(&self, caller: &PlacementKey, target: &PlacementKey) -> Result<SemanticId> {
        let context = self.context;
        let caller_path = self.caller_path;
        let target_path = self.target_path;
        let caller_root =
            self.operation
                .jvm_source_domain(context, caller.subject.file_version, caller_path)?;
        let target_root =
            self.operation
                .jvm_source_domain(context, target.subject.file_version, target_path)?;
        let caller_root = caller_root
            .map(|domain| domain.root.clone())
            .unwrap_or_else(|| {
                std::path::Path::new(caller_path)
                    .parent()
                    .unwrap_or(std::path::Path::new(""))
                    .to_owned()
            });
        let target_root = target_root
            .map(|domain| domain.root.clone())
            .unwrap_or_else(|| {
                std::path::Path::new(target_path)
                    .parent()
                    .unwrap_or(std::path::Path::new(""))
                    .to_owned()
            });
        let caller_root =
            brokk_bifrost_core::path_utils::workspace_relative_slash_path(&caller_root);
        let target_root =
            brokk_bifrost_core::path_utils::workspace_relative_slash_path(&target_root);
        let mut hash = CanonicalHasher::new(b"bifrost-java-source-access-open:v2");
        hash.field("context", &context.to_le_bytes());
        hash.field("caller_root", caller_root.as_bytes());
        hash.field("target_root", target_root.as_bytes());
        let gap = self.operation.ready.context_identities.named_semantic(
    hash.finish(),
    "java-source-access-open",
    &format!("Source visibility from root `{}` to root `{}` is not established by selected build dependencies or JVM source-set conventions", caller_root, target_root),
);
        Ok(gap)
    }

    fn upgrade_unknown(
        &self,
        caller: &PlacementKey,
        target: &PlacementKey,
    ) -> Result<Option<UnitAccess>> {
        let caller = self.operation.jvm_source_domain(
            self.context,
            caller.subject.file_version,
            self.caller_path,
        )?;
        let target = self.operation.jvm_source_domain(
            self.context,
            target.subject.file_version,
            self.target_path,
        )?;
        Ok(
            matches!((caller, target), (Some(caller), Some(target)) if caller.can_access(&target))
                .then_some(UnitAccess::Visible),
        )
    }

    fn combine(&self, answers: &[(PlacementKey, PlacementKey, UnitAccess)]) -> UnitAccess {
        let [(_, _, access)] = answers else {
            panic!("JVM source access requires exactly one endpoint pair");
        };
        *access
    }
}

struct JvmImportBinderRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    language: Language,
}

impl ImportBinderRules for JvmImportBinderRules<'_, '_, '_> {
    fn lookup_recipes(
        &self,
        fragment: BindingFragmentId,
        route: &[SemanticId],
        demand: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<ResolutionLookupSemanticRecipe>>> {
        self.operation.jvm_lookup_recipes(
            fragment,
            route.iter().copied().chain([demand]),
            cancellation,
        )
    }

    fn token_metadata(
        &self,
        blob: i64,
        token: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<ImportTokenMetadata>>> {
        self.operation.import_token_metadata(
            blob,
            SelectedResolutionMountOrdinal::new(token.ordinal().expect("import token is mounted")),
            token,
            cancellation,
        )
    }

    fn classify(
        &self,
        selector: Option<&SelectedImportSelector>,
        route: Option<&SelectedImportRoute>,
    ) -> ImportBinderClass {
        let java_route = nominal_language_rules(self.language)
            .expect("caller belongs to a nominal family")
            .has_legacy_import_routes()
            .then(|| route.cloned())
            .flatten();
        let named = selector
            .is_some_and(|selector| selector.kind == ResolutionImportSelectorKind::Named)
            || java_route.as_ref().is_some_and(|route| {
                matches!(
                    route.kind,
                    SelectedImportRouteKind::SingleType | SelectedImportRouteKind::SingleStatic
                )
            });
        ImportBinderClass {
            named,
            route: java_route,
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn profile_jvm_read(&self, kind: &'static str, key: impl std::fmt::Debug) {
        if let Some(profile) = self.ready.jvm_context_profile.borrow_mut().as_mut() {
            *profile.calls.entry((kind, format!("{key:?}"))).or_default() += 1;
        }
    }

    /// Compose Java type and static source imports for one file.
    /// Inherited routes, peer-language routes and external inventory remain open.
    #[doc(hidden)]
    pub fn java_import_context(
        &self,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.jvm_import_context(Language::Java, caller_path, cancellation)
    }

    #[doc(hidden)]
    pub fn jvm_import_context(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.selected_jvm_import_context(source_language, caller_path, None, cancellation)
    }

    #[doc(hidden)]
    pub fn jvm_import_context_for_name(
        &self,
        source_language: Language,
        caller_path: &str,
        lookup: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.selected_jvm_import_context(source_language, caller_path, Some(lookup), cancellation)
    }

    fn selected_jvm_import_context(
        &self,
        source_language: Language,
        caller_path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.profile_jvm_read("file_context", (source_language, caller_path, lookup));
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let key = JvmFileContextKey {
            language: source_language,
            path: caller_path.to_owned(),
            lookup: lookup.map(str::to_owned),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        if let Some(context) = self.jvm_file_contexts.borrow().get(&key) {
            return Ok(context.clone());
        }
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let context = rules.selected_import_context(self, caller_path, lookup, cancellation)?;
        if !matches!(context, JvmImportContext::Cancelled) && !cancellation.is_cancelled() {
            self.jvm_file_contexts
                .borrow_mut()
                .insert(key, context.clone());
        }
        Ok(context)
    }

    pub(crate) fn jvm_reverse_import_context(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        rules.reverse_import_context(self, caller_path, cancellation)
    }

    pub(super) fn selected_java_import_context_with_jvm_peers(
        &self,
        caller_path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        let java = self.java_import_context_parts(caller_path, lookup, cancellation)?;
        let peers =
            self.assemble_jvm_import_context(Language::Java, caller_path, lookup, cancellation)?;
        match (java, peers) {
            (JvmImportContext::Cancelled, _) | (_, JvmImportContext::Cancelled) => {
                Ok(JvmImportContext::Cancelled)
            }
            (
                JvmImportContext::Ready {
                    context,
                    external_static_imports,
                    inventory_reason,
                    mut open_jvm_alias_imports,
                    scoped_gaps,
                },
                JvmImportContext::Ready {
                    context: peer_context,
                    open_jvm_alias_imports: peer_open_jvm_alias_imports,
                    scoped_gaps: peer_scoped_gaps,
                    ..
                },
            ) => {
                let mounts = self.mount_table();
                let selected_mount_of = selected_mount_lookup(mounts);
                let Some(context) =
                    (*context).merge(*peer_context, cancellation, &selected_mount_of)?
                else {
                    return Ok(JvmImportContext::Cancelled);
                };
                let mut scoped_gaps = scoped_gaps;
                open_jvm_alias_imports.extend(peer_open_jvm_alias_imports);
                open_jvm_alias_imports.sort_unstable();
                open_jvm_alias_imports.dedup();
                scoped_gaps.extend(peer_scoped_gaps);
                scoped_gaps.sort_by(|left, right| {
                    (&left.lookup, left.reason).cmp(&(&right.lookup, right.reason))
                });
                scoped_gaps.dedup();
                Ok(JvmImportContext::Ready {
                    context: Box::new(context),
                    external_static_imports,
                    inventory_reason,
                    open_jvm_alias_imports,
                    scoped_gaps,
                })
            }
            (ready @ JvmImportContext::Ready { .. }, JvmImportContext::Unavailable) => Ok(ready),
            (JvmImportContext::Unavailable, ready @ JvmImportContext::Ready { .. }) => Ok(ready),
            (JvmImportContext::Unavailable, JvmImportContext::Unavailable) => {
                Ok(JvmImportContext::Unavailable)
            }
        }
    }

    /// Read the structured binder table once for this selected file. Reference
    /// halves have already supplied file metadata; retain only import inputs.
    fn jvm_import_binders(
        &self,
        language: Language,
        blob: i64,
        fragment: BindingFragmentId,
        halves: Vec<SelectedRootPathHalf>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<ImportBinder>>> {
        hydrate_import_binders(
            &self.ready,
            &JvmImportBinderRules {
                operation: self,
                language,
            },
            blob,
            fragment,
            halves,
            cancellation,
        )
    }

    fn jvm_import_context_preparation(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmContextPreparation>>> {
        let key = JvmFileContextKey {
            language: source_language,
            path: caller_path.to_owned(),
            lookup: None,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.jvm_context_preparations
            .prepare(key, cancellation, || {
                self.jvm_import_context_parts(source_language, caller_path, cancellation)
            })
    }

    /// Name-independent selected rows, binders and provider inputs. This is
    /// entered only on a per-file/scope/stage operation-memo miss.
    fn jvm_import_context_parts(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmContextPreparation>>> {
        self.profile_jvm_read("derive_file_context", (source_language, caller_path));
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let connection = self.ready.inventory.connection();
        let Some(context_id) = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row([source_language.config_label()], |row| row.get::<_, i64>(0))
            .optional()?
        else {
            return Ok(None);
        };
        self.jvm_implicit_project_context(context_id)?;
        let Some(source) = self
            .mount_table()
            .mount_for_path(source_language.config_label(), caller_path)?
        else {
            return Ok(None);
        };
        assert_eq!(source.semantic_language(), source_language);
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let source_package: Option<String> = connection
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [source_record.blob_id()],
                |row| row.get(0),
            )
            .optional()?;
        let source_package = rules
            .lexical_package(self, source_record.blob_id())?
            .or(source_package);
        let identities = self.ready.context_identities.clone();
        let inventory_reason = if rules.has_context_import_inventory() {
            let mut descriptor =
                CanonicalIdentityDescriptor::new(b"bifrost-jvm-context-incomplete:v1", |key| {
                    self.ready.identity_content_digest(key, cancellation)
                });
            descriptor.field(
                "context",
                CanonicalIdentityPart::identity(source.fragment()),
            )?;
            descriptor.field(
                "language",
                CanonicalIdentityPart::Label(source_language.config_label()),
            )?;
            Some(identities.named_semantic(
                descriptor.finish(),
                "jvm-context-incomplete",
                "Selected JVM facts leave external artifacts, classpath ownership, inherited routes and peer-language inventory open",
            ))
        } else {
            None
        };
        let lexical = self.ready.lexical_source();
        let (mut import_halves, outcome) =
            self.read_root_inventory(RootHalfRequest::Imports(&[source.ordinal()]), cancellation)?;
        if outcome.is_cancelled() {
            return Ok(None);
        }
        // Within a mount, a positional import (Scala) is consumed in source
        // order of its activation. The stable sort keeps page order for ties,
        // and an import without an activation (Java, Kotlin, Go, Rust) keeps
        // page order within its mount, as it did when the key was the mount alone.
        import_halves.sort_by_key(|half| match half {
            SelectedRootPathHalf::Import {
                token, activation, ..
            } => (token.ordinal(), *activation),
            _ => (None, None),
        });
        // Classify the same candidate references as the singleton loop below,
        // through the shared batch reader. Publish complete per-node answers to
        // the existing operation memo, including negative classifications.
        let reference_nodes = import_halves
            .iter()
            .filter_map(|half| match half {
                SelectedRootPathHalf::Reference {
                    source_reference,
                    route,
                    anchor,
                    ..
                } if *anchor == ResolutionRootImportAnchor::Absolute || !route.is_empty() => {
                    Some(*source_reference)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let endpoint_key = |node| JvmEndpointKey {
            node,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        let mut seen = HashSet::default();
        let missing = reference_nodes
            .iter()
            .copied()
            .filter(|node| {
                seen.insert(*node)
                    && self
                        .jvm_endpoint_memo
                        .borrow()
                        .get(&endpoint_key(*node))
                        .is_none()
            })
            .collect::<Vec<_>>();
        let mut computed = Vec::new();
        for page in missing.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let rows = lexical.classify_endpoint_nodes(page, cancellation)?;
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            for &node in page {
                let rows: Arc<[BatchEndpointClassification]> = rows
                    .iter()
                    .filter(|row| row.node() == node)
                    .copied()
                    .collect::<Vec<_>>()
                    .into();
                computed.push((endpoint_key(node), rows));
            }
        }
        for (key, rows) in computed {
            self.jvm_endpoint_memo.borrow_mut().insert(key, rows);
        }
        let mut reference_keys = Vec::new();
        for &node in &reference_nodes {
            if let Some(reference) = self
                .jvm_endpoint_memo
                .borrow()
                .get(&endpoint_key(node))
                .and_then(|rows| rows.iter().find(|row| row.node() == node))
                .and_then(|row| row.reference())
            {
                reference_keys.push(
                    reference
                        .local_key()
                        .expect("a mounted reference has a local key"),
                );
            }
        }
        reference_keys.sort_unstable();
        reference_keys.dedup();
        let mut supertypes = HashSet::<u32>::default();
        for page in reference_keys.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let keys = serde_json::to_string(page).expect("integer key array serializes");
            let mut statement = connection.prepare_cached(JVM_SUPERTYPE_REFERENCE_MEMBERSHIP)?;
            let rows = statement
                .query_map(rusqlite::params![source_record.blob_id(), keys], |row| {
                    row.get::<_, u32>(0)
                })?;
            for row in rows {
                supertypes.insert(row?);
            }
        }
        let SelectedPackageRows::Ready(package_reference_occurrences) = self
            .ready
            .selected_package_references(source.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        let package_references =
            unique_package_references_by_token(&package_reference_occurrences)?;
        // Prefill only names the old loops consume: qualified lexical routes,
        // proven supertype routes, import binders and package lookup names.
        let mut recipe_semantics = Vec::new();
        for half in &import_halves {
            match half {
                SelectedRootPathHalf::Import { route, demand, .. } => {
                    recipe_semantics.extend(route.iter().copied());
                    recipe_semantics.push(*demand);
                }
                SelectedRootPathHalf::Reference {
                    source_reference,
                    route,
                    demand,
                    anchor,
                    ..
                } => {
                    let supertype = self
                        .jvm_endpoint_memo
                        .borrow()
                        .get(&endpoint_key(*source_reference))
                        .and_then(|rows| rows.iter().find(|row| row.node() == *source_reference))
                        .and_then(|row| row.reference())
                        .and_then(|reference| reference.local_key())
                        .is_some_and(|key| supertypes.contains(&key));
                    if (*anchor == ResolutionRootImportAnchor::Lexical && !route.is_empty())
                        || supertype
                    {
                        recipe_semantics.push(*demand);
                        recipe_semantics.extend(route.iter().copied());
                    }
                }
                SelectedRootPathHalf::Export { .. } => {}
            }
        }
        recipe_semantics.extend(package_references.iter().map(|reference| reference.lookup));
        if self
            .jvm_lookup_recipes(source.fragment(), recipe_semantics, cancellation)?
            .is_none()
        {
            return Ok(None);
        }
        // A named demand also needs the lexical bindings of its qualified
        // reference's heads. Keep these structured route facts in the shared
        // preparation: the terminal spelling alone does not identify every
        // explicit import needed to resolve, for example, Settings.answer.
        let mut qualifier_names_by_demand: HashMap<String, HashSet<String>> = HashMap::default();
        for half in &import_halves {
            let SelectedRootPathHalf::Reference {
                route,
                demand,
                anchor: ResolutionRootImportAnchor::Lexical,
                ..
            } = half
            else {
                continue;
            };
            if route.is_empty() {
                continue;
            }
            let Some(recipes) = self.jvm_lookup_recipes(
                source.fragment(),
                [*demand].into_iter().chain(route.iter().copied()),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let names = qualifier_names_by_demand
                .entry(recipes[0].spelling().to_owned())
                .or_default();
            names.extend(
                recipes[1..]
                    .iter()
                    .map(|recipe| recipe.spelling().to_owned()),
            );
        }
        let mut qualified_reference_nodes = BTreeSet::new();
        let mut qualified_reference_semantics = BTreeSet::new();
        for half in &import_halves {
            let SelectedRootPathHalf::Reference {
                source_reference,
                prefix_reference,
                owner_continued,
                anchor,
                ..
            } = half
            else {
                continue;
            };
            if prefix_reference.is_some()
                || *owner_continued
                || *anchor == ResolutionRootImportAnchor::Absolute
            {
                qualified_reference_nodes.insert(*source_reference);
                qualified_reference_semantics.extend(*prefix_reference);
            }
        }
        // Synthetic absolute parents and written qualified parents use the
        // same reviewed external declaration identity as an explicit import.
        for half in &import_halves {
            let SelectedRootPathHalf::Reference {
                source_reference,
                route,
                demand,
                anchor,
                ..
            } = half
            else {
                continue;
            };
            if *anchor != ResolutionRootImportAnchor::Absolute && route.is_empty() {
                continue;
            }
            let Some(classifications) =
                self.jvm_endpoint_classifications(*source_reference, cancellation)?
            else {
                return Ok(None);
            };
            let Some(reference) = classifications
                .iter()
                .find(|classification| classification.node() == *source_reference)
                .and_then(|classification| classification.reference())
            else {
                continue;
            };
            if !supertypes.contains(
                &reference
                    .local_key()
                    .expect("a mounted reference has a local key"),
            ) {
                continue;
            }
            let Some(recipes) = self.jvm_lookup_recipes(
                source.fragment(),
                route.iter().copied().chain([*demand]),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let declared = recipes
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".");
            // Name the producer's existing hierarchy reason. A second reason
            // would outlive the established direct-member cutoff transfers.
            let origin = super::super::resolution_prepare::resolution_rows::gap_origin_code(
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    ResolutionGapKind::UnsupportedHierarchyTraversal,
                ),
            );
            let mut statement = connection.prepare_cached(
                "SELECT gap.reason FROM main.resolution_semantic_sites site
                 JOIN main.resolution_gap_reasons gap
                   ON gap.blob_id=site.blob_id AND gap.site=site.source_site
                 WHERE site.blob_id=?1 AND site.semantic_role='reference'
                   AND site.semantic_key=?2 AND gap.origin=?3",
            )?;
            let gaps = statement.query_map(
                rusqlite::params![
                    source_record.blob_id(),
                    reference
                        .local_key()
                        .expect("one source reference has a local key"),
                    origin
                ],
                |row| row.get::<_, u32>(0),
            )?;
            for gap in gaps {
                identities.record_jvm_supertype_name(
                    SemanticId::local(source.ordinal().get(), gap?),
                    &declared,
                );
            }
            // A selected source declaration owns its hierarchy and member set.
            // A language-root inventory only fills an unavailable provider; it
            // must not replace a source root with an intrinsic negative answer.
            let Some(publication) = self.jvm_qualified_type_bridges(
                half,
                &ResolutionCompletion::Complete,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            if publication.bridges.is_empty()
                && self.declares_jvm_type(source_language, &declared)?
            {
                register_model_declared_jvm_type_identity(
                    self,
                    reference,
                    &declared,
                    self.declared_jvm_owner(source_language, &declared)?
                        .as_ref(),
                    &identities,
                    &self.ready.shared_names(),
                )?;
            }
        }
        let mut same_package_lookups = BTreeSet::new();
        let SelectedPackageRows::Ready(local_package_members) =
            self.jvm_package_member_set(source.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        for reference in &package_references {
            if local_package_members
                .get(&reference.lookup)
                .into_iter()
                .flat_map(|members| members.iter())
                .any(|member| {
                    member.domain == reference.domain && member.namespace == reference.namespace
                })
            {
                same_package_lookups.insert(reference.lookup);
            }
        }
        let type_references = package_reference_occurrences
            .iter()
            .filter(|reference| reference.namespace == ResolutionNamespace::Type)
            .map(|reference| reference.reference)
            .collect::<BTreeSet<_>>();
        let type_reference_queries = type_references
            .iter()
            .copied()
            .map(ResolutionQuery::new)
            .collect::<Vec<_>>();
        let mut unqualified_type_references = BTreeSet::new();
        for queries in type_reference_queries
            .chunks(crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH)
        {
            let outcome = lexical.lookup_reference_seeds(queries, cancellation)?;
            if outcome.is_cancelled() {
                return Ok(None);
            }
            for row in outcome.rows() {
                if let Some(seed) = row.seed()
                    && seed
                        .site_metadata()
                        .is_some_and(|metadata| {
                            let type_or_value_qualifier =
                                metadata.namespace() == ResolutionNamespace::TypeOrValue;
                            let is_type_reference = metadata.site_kind()
                                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::TypeReference;
                            let is_type_or_value_qualifier = type_or_value_qualifier
                                && rules.qualifier_site_kinds().contains(&metadata.site_kind());
                            matches!(
                                metadata.namespace(),
                                ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
                            )
                                && (is_type_reference || is_type_or_value_qualifier)
                                && (type_or_value_qualifier || metadata.unqualified())
                                && (type_or_value_qualifier
                                    || (!qualified_reference_nodes.contains(&seed.node())
                                        && !qualified_reference_semantics
                                            .contains(&seed.reference())))
                        })
                {
                    unqualified_type_references.insert(seed.reference());
                }
            }
        }

        let mut references_by_name: HashMap<
            String,
            Vec<crate::analyzer::resolution::LoweredPackageReference>,
        > = HashMap::default();
        for reference in &package_references {
            let Some(recipes) =
                self.jvm_lookup_recipes(source.fragment(), [reference.lookup], cancellation)?
            else {
                return Ok(None);
            };
            references_by_name
                .entry(recipes[0].spelling().to_owned())
                .or_default()
                .push(*reference);
        }
        let mut references_by_route: BTreeMap<(SemanticId, SemanticId), Vec<SemanticId>> =
            BTreeMap::new();
        for reference in &package_reference_occurrences {
            if reference.namespace == ResolutionNamespace::Type
                && unqualified_type_references.contains(&reference.reference)
            {
                references_by_route
                    .entry((reference.token, reference.lookup))
                    .or_default()
                    .push(reference.reference);
            }
        }
        for references in references_by_route.values_mut() {
            references.sort_unstable();
            references.dedup();
        }
        let mut provider_recipes = HashMap::default();
        for &(_, lookup) in references_by_route.keys() {
            if provider_recipes.contains_key(&lookup) {
                continue;
            }
            let Some(recipes) =
                self.jvm_lookup_recipes(source.fragment(), [lookup], cancellation)?
            else {
                return Ok(None);
            };
            provider_recipes.insert(lookup, recipes[0].clone());
        }
        let external_providers = JvmExternalProviderBlueprint {
            references_by_route,
            recipes: provider_recipes,
            registered: Mutex::default(),
        };
        let Some(package_plan) = self.jvm_file_package_plan(
            source_language,
            source.fragment(),
            source_package.as_deref(),
            &package_references,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let Some(binders) = self.jvm_import_binders(
            source_language,
            source_record.blob_id(),
            source.fragment(),
            import_halves,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(Arc::new(JvmContextPreparation {
            context_id,
            source,
            source_record,
            source_package,
            inventory_reason,
            binders,
            package_plan,
            qualifier_names_by_demand,
            package_reference_occurrences,
            package_references,
            same_package_lookups,
            references_by_name,
            unqualified_type_references,
            imports: ContextPlanMemo::default(),
            java_imports: ContextPlanMemo::default(),
            implicit: ContextPlanCell::default(),
            external_providers,
        })))
    }

    pub(super) fn assemble_jvm_import_context(
        &self,
        source_language: Language,
        caller_path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let Some(prepared) =
            self.jvm_import_context_preparation(source_language, caller_path, cancellation)?
        else {
            return Ok(if cancellation.is_cancelled() {
                JvmImportContext::Cancelled
            } else {
                JvmImportContext::Unavailable
            });
        };
        self.profile_jvm_read(
            "assemble_named_context",
            (source_language, caller_path, lookup),
        );
        let context_id = prepared.context_id;
        let source = &prepared.source;
        let source_record = &prepared.source_record;
        let source_package = prepared.source_package.clone();
        let caller_version = source_record.file_version_id();
        let inventory_reason = prepared.inventory_reason;
        let identities = self.ready.context_identities.clone();
        let lexical = self.ready.lexical_source();
        let package_reference_occurrences = &prepared.package_reference_occurrences;
        let package_references = &prepared.package_references;
        let unqualified_type_references = &prepared.unqualified_type_references;
        let mut same_package_lookups = prepared.same_package_lookups.clone();
        let retained_imports = lookup.map(|lookup| {
            jvm_imports_for_name(
                source_language,
                &prepared.binders,
                lookup,
                prepared.qualifier_names_by_demand.get(lookup),
            )
        });
        let mut root_bridges = Vec::new();
        let mut model_declared_routes = Vec::new();
        let mut route_inventory_open = false;
        let mut scoped_gaps = Vec::new();
        let mut open_jvm_alias_imports = Vec::new();
        let mut earlier_scala_imports = BTreeMap::new();
        let mut earlier_scala_wildcards: BTreeMap<
            BindingNodeId,
            Vec<Vec<ResolutionLookupSemanticRecipe>>,
        > = BTreeMap::new();
        let mut pending_scala_imports = BTreeMap::new();
        let mut pending_scala_wildcards: BTreeMap<
            BindingNodeId,
            Vec<Vec<ResolutionLookupSemanticRecipe>>,
        > = BTreeMap::new();
        let mut previous_activation = None;
        for binder in &prepared.binders {
            if retained_imports
                .as_ref()
                .is_some_and(|retained| !retained.contains(&binder.identity))
            {
                continue;
            }
            let half = binder.half.clone();
            let SelectedRootPathHalf::Import {
                identity,
                source_scope_head,
                route: _,
                token,
                anchor,
                anchor_semantic,
                demand: _,
                precedence: import_precedence,
                activation,
            } = half
            else {
                continue;
            };
            if previous_activation != Some(activation) {
                earlier_scala_imports.append(&mut pending_scala_imports);
                for (scope, routes) in std::mem::take(&mut pending_scala_wildcards) {
                    let earlier = earlier_scala_wildcards.entry(scope).or_default();
                    for route in routes {
                        if !earlier.contains(&route) {
                            earlier.push(route);
                        }
                    }
                }
                previous_activation = Some(activation);
            }
            let earlier_head = earlier_scala_imports
                .get(&(source_scope_head, binder.head.clone()))
                .cloned();
            let earlier_wildcards = earlier_scala_wildcards
                .get(&source_scope_head)
                .cloned()
                .unwrap_or_default();
            let cached = prepared.imports.get(&identity);
            let derived = if let Some(derived) = cached {
                debug_assert_eq!(
                    derived.earlier_head, earlier_head,
                    "retained Scala import closure preserves its selected head"
                );
                debug_assert_eq!(
                    derived.earlier_wildcards, earlier_wildcards,
                    "retained Scala wildcards preserve their selected heads"
                );
                derived
            } else {
                self.profile_jvm_read("derive_import", identity);
                let mut root_bridges = Vec::new();
                let mut scoped_gaps = Vec::new();
                let mut model_declared_routes = Vec::new();
                let mut open_jvm_alias_imports = Vec::new();
                let mut route_inventory_open = false;
                let mut pending_scala_imports = BTreeMap::new();
                let mut pending_scala_wildcards: JvmScalaWildcards = BTreeMap::new();
                'derive_import: {
                    let lexical_prefixes = rules.lexical_import_package_prefixes(
                        self,
                        source_record.blob_id(),
                        token,
                    )?;
                    let source_package =
                        lexical_prefixes.last().cloned().or(source_package.clone());
                    let selector = binder.selector.clone();
                    let java_single_type = jvm_single_type_import(binder);
                    let mut recipes = binder.recipes.clone();
                    let demand_recipe = recipes.pop().expect("one selected import demand");
                    if selector.is_none() && !java_single_type {
                        rules.record_import_gap(
                            self,
                            JvmImportContextGapSpec {
                                source: source.fragment(),
                                source_token: token,
                                source_reference: None,
                                kind: "jvm-import-selector-open",
                                owner: None,
                                lookup: demand_recipe.clone(),
                                detail: format!(
                                    "{} import `{}` has no supported selector route",
                                    source_language.config_label(),
                                    demand_recipe.spelling()
                                ),
                            },
                            &mut scoped_gaps,
                            &mut route_inventory_open,
                            cancellation,
                        )?;
                        break 'derive_import;
                    }
                    if selector.as_ref().is_some_and(|selector| {
                        selector.kind == ResolutionImportSelectorKind::ReceiverMember
                    }) {
                        rules.record_import_gap(
                            self,
                            JvmImportContextGapSpec {
                                source: source.fragment(),
                                source_token: token,
                                source_reference: None,
                                kind: "jvm-import-receiver-route-open",
                                owner: None,
                                lookup: demand_recipe.clone(),
                                detail: format!(
                                    "{} receiver import route for `{}` is not modeled",
                                    source_language.config_label(),
                                    demand_recipe.spelling()
                                ),
                            },
                            &mut scoped_gaps,
                            &mut route_inventory_open,
                            cancellation,
                        )?;
                        break 'derive_import;
                    }
                    let source_name = match selector.as_ref().map(|selector| selector.kind) {
                        Some(ResolutionImportSelectorKind::Named) => selector
                            .as_ref()
                            .and_then(|selector| selector.source_name.as_deref())
                            .expect("validated named selector has an imported name"),
                        Some(ResolutionImportSelectorKind::Star) | None => demand_recipe.spelling(),
                        Some(ResolutionImportSelectorKind::ReceiverMember) => unreachable!(),
                    };
                    let local_name = match selector.as_ref().map(|selector| selector.kind) {
                        Some(ResolutionImportSelectorKind::Named) => selector
                            .as_ref()
                            .and_then(|selector| selector.local_name.as_deref())
                            .unwrap_or(source_name),
                        Some(ResolutionImportSelectorKind::Star) | None => demand_recipe.spelling(),
                        Some(ResolutionImportSelectorKind::ReceiverMember) => unreachable!(),
                    };
                    let source_demand = self
                        .jvm_generated_lookup(
                            source_language,
                            demand_recipe.namespace(),
                            local_name,
                        )
                        .recipe
                        .clone();
                    let bridges_before = root_bridges.len();
                    if java_single_type {
                        let Some(open_owner_aliases) = self.jvm_open_owner_alias_imports(
                            source_language,
                            &recipes,
                            demand_recipe.spelling(),
                            cancellation,
                        )?
                        else {
                            return Ok(JvmImportContext::Cancelled);
                        };
                        route_inventory_open |= !open_owner_aliases.is_empty();
                        for (owner, completion) in open_owner_aliases {
                            scoped_gaps.extend(jvm_alias_coverage_gaps(
                                token,
                                None,
                                &source_demand,
                                &owner,
                                &completion,
                            ));
                            open_jvm_alias_imports.push(owner);
                        }
                    }
                    let mut package_prefix_found = false;
                    let mut member_owner_open = false;
                    let enclosing_scope_routes = if rules
                        .lexical_import_anchors()
                        .contains(&ResolutionRootImportAnchor::Lexical)
                        && anchor == ResolutionRootImportAnchor::Lexical
                    {
                        let Some(routes) = self.scala_enclosing_scope_import_routes(
                            source.fragment(),
                            source.ordinal(),
                            source_scope_head,
                            &recipes,
                            cancellation,
                        )?
                        else {
                            return Ok(JvmImportContext::Cancelled);
                        };
                        routes
                    } else {
                        Vec::new()
                    };
                    let earlier_route = if rules
                        .lexical_import_anchors()
                        .contains(&ResolutionRootImportAnchor::Lexical)
                        && anchor == ResolutionRootImportAnchor::Lexical
                    {
                        recipes.first().and_then(|head| {
                            earlier_scala_imports
                                .get(&(source_scope_head, head.spelling().to_owned()))
                                .map(|prefix: &Vec<ResolutionLookupSemanticRecipe>| {
                                    let mut route = prefix.clone();
                                    route.extend(recipes.iter().skip(1).cloned());
                                    route
                                })
                        })
                    } else {
                        None
                    };
                    // A wildcard import binds every member of its package, so an owner
                    // head that an earlier wildcard import of this scope reaches is read
                    // through that package as well.
                    let chained_wildcard_routes = if rules
                        .lexical_import_anchors()
                        .contains(&ResolutionRootImportAnchor::Lexical)
                        && anchor == ResolutionRootImportAnchor::Lexical
                    {
                        earlier_scala_wildcards
                            .get(&source_scope_head)
                            .into_iter()
                            .flatten()
                            .map(|wildcard| {
                                let mut route = wildcard.clone();
                                route.extend(recipes.iter().cloned());
                                route
                            })
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    let lookup_routes = jvm_import_lookup_routes(
                        source_language,
                        anchor,
                        &lexical_prefixes,
                        &recipes,
                        earlier_route.as_deref(),
                        &enclosing_scope_routes,
                        &chained_wildcard_routes,
                    );
                    let mut resolved_lookup_route = None;
                    let mut resolved_wildcard_route = None;
                    let mut route_misses = JvmImportLookupRouteMissMemo::default();
                    for lookup_route in &lookup_routes {
                        if cancellation.is_cancelled() {
                            return Ok(JvmImportContext::Cancelled);
                        }
                        if route_misses.replay(
                            lookup_route,
                            &mut resolved_wildcard_route,
                            &mut open_jvm_alias_imports,
                            &mut scoped_gaps,
                        ) {
                            continue;
                        }
                        let aliases_before = open_jvm_alias_imports.len();
                        let gaps_before = scoped_gaps.len();
                        let chained_wildcard_route = chained_wildcard_routes
                            .iter()
                            .any(|route| route == lookup_route);
                        // A relative reading finds the enclosing package itself for
                        // any route, so only an owner it also finds counts.
                        let relative = lookup_route.len() > recipes.len();
                        let mut candidate_prefix_found = false;
                        let mut selected_owner_found = false;
                        if java_single_type
                            || selector.as_ref().is_some_and(|selector| {
                                selector.kind == ResolutionImportSelectorKind::Named
                            })
                        {
                            let alias_import = JavaMemberImportDemand {
                                half: &binder.half,
                                import_kind: None,
                                caller_package: source_package.as_deref(),
                                source: identity.fragment(),
                                token,
                                prefix_reference: None,
                                scope_head: Some(source_scope_head),
                                anchor,
                                anchor_semantic,
                                selector_kind: selector.as_ref().map(|selector| selector.kind),
                                import_precedence: import_precedence
                                    .iter()
                                    .copied()
                                    .find(|step| step.tier != PrecedenceTier::CandidateOriginRank),
                                candidate_origin_rank: import_precedence
                                    .iter()
                                    .find(|step| step.tier == PrecedenceTier::CandidateOriginRank)
                                    .map(|step| step.ordinal),
                                route: &recipes,
                                lookup_route,
                                demand: &source_demand,
                                language: source_language,
                            };
                            let Some(alias_import_bridges) = self.jvm_alias_import_bridges(
                                &alias_import,
                                source_name,
                                caller_version,
                                source.persisted_relative_path(),
                                context_id,
                                cancellation,
                            )?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            let JvmAliasImportBridges {
                                bridges: aliases,
                                open_imports: open_aliases,
                                coverage_gaps,
                                ..
                            } = alias_import_bridges;
                            scoped_gaps.extend(coverage_gaps);
                            for open_alias in &open_aliases {
                                rules.record_import_gap(self, JvmImportContextGapSpec {
                                source: source.fragment(),
                                source_token: token,
                                source_reference: None,
                                kind: "jvm-import-alias-route-open",
                                owner: Some(open_alias.clone()),
                                lookup: source_demand.clone(),
                                detail: format!(
                                    "{} alias owner `{open_alias}` has no complete member route for `{}`",
                                    source_language.config_label(),
                                    source_demand.spelling()
                                ),
                            }, &mut scoped_gaps, &mut route_inventory_open, cancellation)?;
                            }
                            open_jvm_alias_imports.extend(open_aliases);
                            root_bridges.extend(aliases);
                        }
                        for prefix_length in (1..=lookup_route.len()).rev() {
                            if cancellation.is_cancelled() {
                                return Ok(JvmImportContext::Cancelled);
                            }
                            let package = lookup_route[..prefix_length]
                                .iter()
                                .map(ResolutionLookupSemanticRecipe::spelling)
                                .collect::<Vec<_>>()
                                .join(".");
                            if package.is_empty() {
                                continue;
                            }
                            if !self.jvm_package_exists(family, &package)? {
                                continue;
                            }
                            candidate_prefix_found = true;
                            selected_owner_found |= prefix_length == lookup_route.len();
                            package_prefix_found |= !relative;
                            if rules
                                .lexical_import_anchors()
                                .contains(&ResolutionRootImportAnchor::Lexical)
                                && anchor == ResolutionRootImportAnchor::Lexical
                                && selector.as_ref().is_some_and(|selector| {
                                    selector.kind == ResolutionImportSelectorKind::Star
                                })
                                && prefix_length == lookup_route.len()
                            {
                                // Retain the selected package even when this particular
                                // demand is not one of its members. A later import may
                                // resolve its owner head through this wildcard.
                                resolved_wildcard_route = Some(lookup_route.clone());
                            }
                            // A shorter package prefix only locates the package of
                            // an owner. Its members cannot stand in for the terminal
                            // owner written by this import.
                            let leading_segments = lookup_route.len().saturating_sub(recipes.len());
                            if !rules
                                .import_owner_prefix_lengths(lookup_route.len(), leading_segments)
                                .contains(&prefix_length)
                            {
                                continue;
                            }
                            let relation = JvmDeclarationAccessContext::between(
                                source_package.as_deref(),
                                &package,
                            )
                            .with_scope(Some(source_scope_head))
                            .with_import(token);
                            let mut package_bridges = Vec::new();
                            let member_lookups = family
                                .languages()
                                .iter()
                                .copied()
                                .map(|language| {
                                    self.jvm_generated_lookup(
                                        language,
                                        demand_recipe.namespace(),
                                        source_name,
                                    )
                                    .semantic(&self.ready.shared_names())
                                })
                                .collect::<Vec<_>>();
                            let languages = family.package_alias_target_languages(source_language);
                            let key =
                                self.jvm_package_target_key(&package, &member_lookups, languages);
                            let Some(targets) =
                                self.jvm_package_member_targets(&key, cancellation)?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            for (target_ordinal, target_version) in targets.ordered.iter().copied()
                            {
                                if cancellation.is_cancelled() {
                                    return Ok(JvmImportContext::Cancelled);
                                }
                                let target_ordinal =
                                    SelectedResolutionMountOrdinal::new(target_ordinal);
                                let target_mount =
                                    self.mount_table().mount_by_ordinal(target_ordinal)?;
                                let target_language = target_mount.semantic_language();
                                if !family
                                    .admits_package_alias_target(source_language, target_language)
                                {
                                    continue;
                                }
                                let target_demand = self
                                    .jvm_generated_lookup(
                                        target_language,
                                        demand_recipe.namespace(),
                                        source_name,
                                    )
                                    .recipe
                                    .clone();
                                let target_semantic =
                                    target_demand.semantic(&self.ready.shared_names());
                                let SelectedPackageRows::Ready(members) = self
                                    .jvm_package_members_for_lookup(
                                        target_ordinal,
                                        target_semantic,
                                        cancellation,
                                    )?
                                else {
                                    return Ok(JvmImportContext::Cancelled);
                                };
                                let access = self.jvm_qualified_source_access_completion(
                                    source_language,
                                    context_id,
                                    caller_version,
                                    source.persisted_relative_path(),
                                    target_version,
                                    target_mount.persisted_relative_path(),
                                    &ResolutionCompletion::Complete,
                                )?;
                                let Some(access) = access else {
                                    continue;
                                };
                                for member in members.iter().copied() {
                                    if member.namespace != demand_recipe.namespace()
                                        || member.lookup != target_semantic
                                    {
                                        continue;
                                    }
                                    let completion = match self.jvm_declaration_access(
                                        member.definition,
                                        relation,
                                        &access,
                                        cancellation,
                                    )? {
                                        JvmDeclarationAccess::Ready(completion) => completion,
                                        JvmDeclarationAccess::Excluded => continue,
                                        JvmDeclarationAccess::Cancelled => {
                                            return Ok(JvmImportContext::Cancelled);
                                        }
                                    };
                                    let Some(target_definition) = lexical
                                        .lookup_definition_node(member.definition, cancellation)?
                                    else {
                                        if cancellation.is_cancelled() {
                                            return Ok(JvmImportContext::Cancelled);
                                        }
                                        return Err(StoreError::corrupt(
                                            "selected JVM import member lacks a definition node",
                                        ));
                                    };
                                    let mut target_rules = JvmImportTargetRules {
                                        operation: self,
                                        target: &target_mount,
                                        route: JvmRootBridgeRoute {
                                            source_language,
                                            target_language,
                                            route: &recipes,
                                            source_demand: &source_demand,
                                            target_definition,
                                        },
                                        member: &member,
                                        target_semantic,
                                        relation,
                                        context_id,
                                        caller_version,
                                        caller_path: source.persisted_relative_path(),
                                        target_version,
                                        prefix_length,
                                        lookup_route_length: lookup_route.len(),
                                        selector_kind: selector
                                            .as_ref()
                                            .map(|selector| selector.kind),
                                        completion: &completion,
                                    };
                                    match append_root_target(
                                        &self.ready,
                                        &binder.half,
                                        &mut target_rules,
                                        &mut package_bridges,
                                        cancellation,
                                    )? {
                                        RootBridgeStep::Ready(_) => {}
                                        RootBridgeStep::Unavailable | RootBridgeStep::Cancelled => {
                                            return Ok(JvmImportContext::Cancelled);
                                        }
                                    }
                                }
                            }
                            if !package_bridges.is_empty() {
                                root_bridges.extend(package_bridges);
                                break;
                            }
                        }
                        // The route may end inside a type the package declares:
                        // `import pkg.Obj.member` names a member of `Obj`. An import that
                        // renames the member keeps the alias route above.
                        if (root_bridges.len() == bridges_before
                            || selector.as_ref().is_some_and(|selector| {
                                selector.kind == ResolutionImportSelectorKind::Named
                                    && !chained_wildcard_route
                            }))
                            && candidate_prefix_found
                            && source_name == local_name
                            && selector.as_ref().is_some_and(|selector| {
                                matches!(
                                    selector.kind,
                                    ResolutionImportSelectorKind::Named
                                        | ResolutionImportSelectorKind::Star
                                )
                            })
                            && family.member_continuation_mounts(source_language).is_some()
                        {
                            let mut owner_found = false;
                            let Some(inventory) = self.jvm_type_member_import_candidates(
                                context_id,
                                caller_version,
                                &JavaMemberImportDemand {
                                    half: &binder.half,
                                    import_kind: None,
                                    caller_package: source_package.as_deref(),
                                    source: identity.fragment(),
                                    token,
                                    prefix_reference: None,
                                    scope_head: Some(source_scope_head),
                                    anchor,
                                    anchor_semantic,
                                    selector_kind: selector.as_ref().map(|selector| selector.kind),
                                    import_precedence: import_precedence.iter().copied().find(
                                        |step| step.tier != PrecedenceTier::CandidateOriginRank,
                                    ),
                                    candidate_origin_rank: import_precedence
                                        .iter()
                                        .find(|step| {
                                            step.tier == PrecedenceTier::CandidateOriginRank
                                        })
                                        .map(|step| step.ordinal),
                                    route: &recipes,
                                    lookup_route,
                                    demand: &source_demand,
                                    language: source_language,
                                },
                                &ResolutionCompletion::Complete,
                                cancellation,
                                &mut owner_found,
                            )?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            selected_owner_found |= owner_found;
                            if owner_found
                                && rules
                                    .lexical_import_anchors()
                                    .contains(&ResolutionRootImportAnchor::Lexical)
                                && anchor == ResolutionRootImportAnchor::Lexical
                                && selector.as_ref().is_some_and(|selector| {
                                    selector.kind == ResolutionImportSelectorKind::Star
                                })
                            {
                                resolved_wildcard_route = Some(lookup_route.clone());
                            }
                            // A member the selected owner does not declare may still be
                            // inherited, and inherited routes are not modeled. The
                            // route stays open when a terminal owner may inherit a
                            // member of this name (an incomplete member inventory, or
                            // a terminal owner without the member that has a
                            // supertype row), and a complete direct miss stays open
                            // unless the owner's declared members are its whole member
                            // set (`jvm_import_owners_declare_every_member`: no
                            // declared supertype, no unsupported export, and a name
                            // outside the language's implicit root).
                            member_owner_open |= owner_found && inventory.inherited_route_open;
                            if owner_found && inventory.members.is_empty() {
                                let Some(closed) = self.jvm_import_owners_declare_every_member(
                                    source_language,
                                    &inventory,
                                    source_name,
                                    cancellation,
                                )?
                                else {
                                    return Ok(JvmImportContext::Cancelled);
                                };
                                member_owner_open |= !closed;
                            }
                            package_prefix_found |=
                                relative && (owner_found || !inventory.members.is_empty());
                            root_bridges
                                .extend(inventory.members.into_iter().map(|member| member.bridge));
                        }
                        if root_bridges.len() > bridges_before {
                            resolved_lookup_route = Some(lookup_route.clone());
                            break;
                        }
                        if rules
                            .lexical_import_anchors()
                            .contains(&ResolutionRootImportAnchor::Lexical)
                            && anchor == ResolutionRootImportAnchor::Lexical
                            && selected_owner_found
                        {
                            // Choosing the owner is independent of finding a member.
                            // A miss in that owner's inventory cannot import a member
                            // from a different root owner with the same name.
                            break;
                        }
                        // This is the route's first occurrence, so equality means this
                        // visit selected it as a wildcard fallback. Successful routes
                        // break above and do not need a retained miss.
                        route_misses.record(
                            lookup_route.clone(),
                            resolved_wildcard_route.as_ref() == Some(lookup_route),
                            open_jvm_alias_imports[aliases_before..].to_vec(),
                            scoped_gaps[gaps_before..].to_vec(),
                        );
                    }
                    let wildcard_route = if rules
                        .lexical_import_anchors()
                        .contains(&ResolutionRootImportAnchor::Lexical)
                        && anchor == ResolutionRootImportAnchor::Lexical
                        && selector.as_ref().is_some_and(|selector| {
                            selector.kind == ResolutionImportSelectorKind::Star
                        }) {
                        resolved_lookup_route
                            .clone()
                            .or(resolved_wildcard_route.clone())
                    } else {
                        None
                    };
                    package_prefix_found |= wildcard_route.is_some();
                    if let Some(route) = wildcard_route {
                        pending_scala_wildcards
                            .entry(source_scope_head)
                            .or_default()
                            .push(route);
                    }
                    if rules
                        .lexical_import_anchors()
                        .contains(&ResolutionRootImportAnchor::Lexical)
                        && anchor == ResolutionRootImportAnchor::Lexical
                        && selector.as_ref().is_some_and(|selector| {
                            selector.kind == ResolutionImportSelectorKind::Named
                        })
                        && root_bridges.len() > bridges_before
                        && let Some(mut resolved_route) = resolved_lookup_route
                    {
                        resolved_route.push(
                            self.jvm_generated_lookup(
                                source_language,
                                demand_recipe.namespace(),
                                source_name,
                            )
                            .recipe
                            .clone(),
                        );
                        pending_scala_imports
                            .insert((source_scope_head, local_name.to_owned()), resolved_route);
                    }
                    if member_owner_open {
                        let owner = recipes
                            .iter()
                            .map(ResolutionLookupSemanticRecipe::spelling)
                            .collect::<Vec<_>>()
                            .join(".");
                        scoped_gaps.push(self.jvm_import_context_gap(JvmImportContextGapSpec {
                    source: source.fragment(),
                    source_token: token,
                    source_reference: None,
                    kind: "jvm-import-member-route-open",
                    owner: Some(owner.clone()),
                    lookup: source_demand.clone(),
                    detail: format!(
                        "{} import owner `{owner}` declares no member `{}` in the selected sources",
                        source_language.config_label(),
                        source_demand.spelling()
                    ),
                }, cancellation)?);
                    }
                    if !package_prefix_found {
                        let owner = recipes
                            .iter()
                            .map(ResolutionLookupSemanticRecipe::spelling)
                            .collect::<Vec<_>>()
                            .join(".");
                        let declared = format!("{owner}.{}", source_demand.spelling());
                        if self.declares_jvm_type(source_language, &declared)? {
                            // The reviewed model declares this type, so the import
                            // closes with a model-declared identity instead of an
                            // open route. The shared registration checks whether
                            // its type and supertype inventories close that route.
                            model_declared_routes.push(ModelDeclaredJvmImportRoute {
                                source_token: token,
                                lookup: source_demand.clone(),
                                owner: self.declared_jvm_owner(source_language, &declared)?,
                                declared_fqn: declared,
                            });
                        } else {
                            let mut gap = self.jvm_import_context_gap(JvmImportContextGapSpec {
                        source: source.fragment(),
                        source_token: token,
                        source_reference: None,
                        kind: "jvm-import-owner-open",
                        owner: Some(owner.clone()),
                        lookup: source_demand.clone(),
                        detail: format!(
                            "{} import owner `{owner}` has no selected source or classpath route for `{}`",
                            source_language.config_label(),
                            source_demand.spelling()
                        ),
                    }, cancellation)?;
                            gap.boundary_status = Some(
                        crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                    );
                            let identity = model_declared_jvm_type_identity(
                                &declared,
                                &self.ready.shared_names(),
                            );
                            identities.record_jvm_unindexed_import_owner(identity, &declared);
                            gap.nominal_type_identity = Some(identity);
                            scoped_gaps.push(gap);
                        }
                        route_inventory_open |= rules.has_context_import_inventory();
                    }
                    if cancellation.is_cancelled() {
                        return Ok(JvmImportContext::Cancelled);
                    }
                }
                if cancellation.is_cancelled() {
                    return Ok(JvmImportContext::Cancelled);
                }
                let derived = Arc::new(JvmDerivedImport {
                    earlier_head,
                    earlier_wildcards,
                    bridges: root_bridges,
                    gaps: scoped_gaps,
                    model_routes: model_declared_routes,
                    open_aliases: open_jvm_alias_imports,
                    inventory_open: route_inventory_open,
                    scala_imports: pending_scala_imports,
                    scala_wildcards: pending_scala_wildcards,
                });
                prepared.imports.insert(identity, Arc::clone(&derived));
                derived
            };
            root_bridges.extend(derived.bridges.iter().cloned());
            scoped_gaps.extend(derived.gaps.iter().cloned());
            model_declared_routes.extend(derived.model_routes.iter().cloned());
            open_jvm_alias_imports.extend(derived.open_aliases.iter().cloned());
            route_inventory_open |= derived.inventory_open;
            pending_scala_imports.extend(derived.scala_imports.clone());
            for (scope, routes) in &derived.scala_wildcards {
                pending_scala_wildcards
                    .entry(*scope)
                    .or_default()
                    .extend(routes.iter().cloned());
            }
        }

        let implicit_root_providers = nominal_language_rules(source_language)
            .expect("caller belongs to a nominal family")
            .implicit_root_providers();
        let import_context = JvmPackageImportContext {
            context_id,
            source_ordinal: source.ordinal(),
            source_path: source.persisted_relative_path(),
            caller_version,
            caller_package: source_package.as_deref(),
            lookup,
            package_plan: &prepared.package_plan,
        };
        let cached_implicit = prepared.implicit.get();
        let implicit = if let Some(implicit) = cached_implicit {
            implicit
        } else {
            self.profile_jvm_read("derive_implicit_context", (source_language, caller_path));
            let mut package_names = implicit_root_providers
                .iter()
                .filter_map(|provider| match provider {
                    JvmImplicitRootProvider::Package(name) => Some((*name).to_owned()),
                    JvmImplicitRootProvider::ScalaPredef => None,
                })
                .collect::<Vec<_>>();
            package_names.sort_unstable();
            package_names.dedup();
            let mut gaps = Vec::new();
            let mut same_package_lookups = prepared.same_package_lookups.clone();
            let Some(mut bridges) = self.jvm_package_import_bridges(
                &import_context,
                &package_names,
                package_references,
                &mut gaps,
                &mut same_package_lookups,
                cancellation,
            )?
            else {
                return Ok(JvmImportContext::Cancelled);
            };
            if implicit_root_providers.contains(&JvmImplicitRootProvider::ScalaPredef) {
                let Some((predef_bridges, predef_gaps)) = self.scala_predef_import_bridges(
                    &import_context,
                    package_references,
                    cancellation,
                )?
                else {
                    return Ok(JvmImportContext::Cancelled);
                };
                bridges.extend(predef_bridges);
                gaps.extend(predef_gaps);
            }
            if cancellation.is_cancelled() {
                return Ok(JvmImportContext::Cancelled);
            }
            let mut durable_implicit_owners = BTreeMap::new();
            for gap in &gaps {
                if gap.boundary_status
                    != Some(crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed)
                    || gap.lookup.namespace() != ResolutionNamespace::Type
                {
                    continue;
                }
                for provider in implicit_root_providers {
                    let JvmImplicitRootProvider::Package(package) = provider else {
                        continue;
                    };
                    let fqn = format!("{package}.{}", gap.lookup.spelling());
                    if let Some(owner) = self.declared_jvm_owner(source_language, &fqn)? {
                        durable_implicit_owners.insert(fqn, owner);
                    }
                }
            }
            if rules.has_unqualified_implicit_owners() {
                for reference in package_reference_occurrences.iter().filter(|reference| {
                    reference.namespace == ResolutionNamespace::Type
                        && unqualified_type_references.contains(&reference.reference)
                }) {
                    let Some(mut lookups) = self.jvm_lookup_recipes(
                        source.fragment(),
                        [reference.lookup],
                        cancellation,
                    )?
                    else {
                        return Ok(JvmImportContext::Cancelled);
                    };
                    let Some(lookup) = lookups.pop() else {
                        continue;
                    };
                    for provider in implicit_root_providers {
                        let JvmImplicitRootProvider::Package(package) = provider else {
                            continue;
                        };
                        let fqn = format!("{package}.{}", lookup.spelling());
                        if let Some(owner) = self.declared_jvm_owner(source_language, &fqn)? {
                            durable_implicit_owners.insert(fqn, owner);
                        }
                    }
                }
            }
            let implicit = Arc::new(JvmImplicitContextParts {
                bridges,
                gaps,
                same_package_lookups,
                durable_owners: durable_implicit_owners,
            });
            prepared.implicit.set(Arc::clone(&implicit));
            implicit
        };
        let mut package_bridges = implicit.bridges.clone();
        scoped_gaps.extend(implicit.gaps.iter().cloned());
        same_package_lookups.extend(implicit.same_package_lookups.iter().copied());
        if let Some(package) = source_package.as_ref().filter(|package| !implicit_root_providers.iter().any(|provider| matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package.as_str()))) {
            let references = match lookup {
                Some(name) => prepared.references_by_name.get(name).map(Vec::as_slice).unwrap_or_default(),
                None => package_references.as_slice(),
            };
            let Some(peers) = self.jvm_package_import_bridges(&import_context, std::slice::from_ref(package), references, &mut scoped_gaps, &mut same_package_lookups, cancellation)? else { return Ok(JvmImportContext::Cancelled); };
            package_bridges.extend(peers);
        }
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let names = self.ready.shared_names();
        // Provider candidates remain invariant and complete in the preparation.
        // Their active gaps require the same name's package-peer shadowing proof;
        // another name's provisional absence must not enter the caller's ledger.
        let Some(current_package_references) = self.register_current_package_external_types(
            &prepared,
            lookup,
            &mut same_package_lookups,
            cancellation,
        )?
        else {
            return Ok(JvmImportContext::Cancelled);
        };
        scoped_gaps.retain(|gap| {
            !gap.suppress_if_same_package_candidate
                || (lookup.is_none_or(|name| gap.lookup.spelling() == name)
                    && !same_package_lookups.contains(&gap.lookup.semantic(&names)))
        });
        let Some(mut model_bound_references) = register_model_declared_jvm_type_identities(
            self,
            source.ordinal(),
            &model_declared_routes,
            &current_package_references,
            &identities,
            &names,
            cancellation,
        )?
        else {
            return Ok(JvmImportContext::Cancelled);
        };
        model_bound_references.extend(current_package_references);
        // A proven import binder owns its references. Lower-precedence implicit
        // providers must not replace that indexed identity during registration.
        let implicit_type_references = unqualified_type_references
            .difference(&model_bound_references)
            .copied()
            .collect::<BTreeSet<_>>();
        let durable_implicit_owners = &implicit.durable_owners;
        register_jvm_external_provider_type_identities(JvmExternalProviderIdentityRegistration {
            source_language,
            lookup,
            gaps: &scoped_gaps,
            blueprint: &prepared.external_providers,
            unqualified_type_references: &implicit_type_references,
            durable_owners: durable_implicit_owners,
            identities: &identities,
            names: &names,
            cancellation,
        })?;
        let mount = SelectedResolutionMountContext::new(
            source.ordinal(),
            source.fragment(),
            source_language,
            root_bridges,
            ResolutionCompletion::Complete,
        )?
        .with_package_bridges(package_bridges)?;
        let mounts = self.mount_table();
        let context = SelectedResolutionContextSet::new(
            identities,
            vec![mount],
            mounts.mount_count(),
            &selected_mount_lookup(mounts),
        )?
        .with_callable_imports(
            source.semantic_language(),
            prepared.binders.iter().map(|binder| &binder.half),
            &self.ready.lexical_source(),
            cancellation,
        )?;
        let access_identity = self.ready.context_identities.named_semantic(
            CanonicalHasher::new(b"jvm-selected-declaration-access:v2-lexical-regions").finish(),
            "jvm-selected-declaration-access",
            "JVM declaration visibility under exact selected package and lexical ownership",
        );
        let mut context = context;
        if let Some(access_source) = rules.declaration_access_source(self, access_identity) {
            context = context.with_declaration_access_source(access_source);
        }
        if route_inventory_open && rules.has_context_import_inventory() {
            let mut descriptor =
                CanonicalIdentityDescriptor::new(b"bifrost-jvm-import-selector-open:v1", |key| {
                    self.ready.identity_content_digest(key, cancellation)
                });
            descriptor.field(
                "context",
                CanonicalIdentityPart::identity(source.fragment()),
            )?;
            descriptor.field("source", CanonicalIdentityPart::identity(source.fragment()))?;
            let reason = self.ready.context_identities.named_semantic(
                descriptor.finish(),
                "jvm-import-selector-open",
                "A selected JVM import has no supported selector route or selected destination",
            );
            context = context.with_additional_context_owned_inventory_reason(reason);
        }
        scoped_gaps
            .sort_by(|left, right| (&left.lookup, left.reason).cmp(&(&right.lookup, right.reason)));
        scoped_gaps.dedup();
        Ok(JvmImportContext::Ready {
            context: Box::new(context),
            external_static_imports: Vec::new(),
            inventory_reason,
            open_jvm_alias_imports,
            scoped_gaps,
        })
    }

    /// The current package outranks on-demand imports, including java.lang.
    /// Register only declaration-backed owners and leave nearer lexical and
    /// hierarchy uncertainty on the reference's ordinary binding answer.
    fn register_current_package_external_types(
        &self,
        prepared: &JvmContextPreparation,
        demanded_name: Option<&str>,
        same_package_lookups: &mut BTreeSet<SemanticId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<BTreeSet<SemanticId>>> {
        let language = prepared.source.semantic_language();
        let package = prepared.source_package.as_deref().unwrap_or("");
        let precedence = Self::selected_jvm_package_precedence(language, Some(package), package);
        let rank = precedence
            .candidate_origin_rank
            .expect("a JVM current-package type has a binding rank");
        let names = self.ready.shared_names();
        let identities = &self.ready.context_identities;
        let mut selected = BTreeSet::new();
        for (&(_, lookup), references) in &prepared.external_providers.references_by_route {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if prepared.same_package_lookups.contains(&lookup) {
                continue;
            }
            let recipe = &prepared.external_providers.recipes[&lookup];
            if demanded_name.is_some_and(|name| name != recipe.spelling()) {
                continue;
            }
            let fqn = if package.is_empty() {
                recipe.spelling().to_owned()
            } else {
                format!("{package}.{}", recipe.spelling())
            };
            let Some(owner) = self.declared_jvm_owner(language, &fqn)? else {
                continue;
            };
            let Some(bindings) = super::jvm_demand::jvm_import_bindings_for_lookup(
                self,
                prepared.source.ordinal(),
                recipe,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            for &reference in references {
                if bindings
                    .iter()
                    .any(|binding| binding.reference == reference && binding.precedence.rank < rank)
                {
                    continue;
                }
                register_model_declared_jvm_type_identity(
                    self,
                    reference,
                    &fqn,
                    Some(&owner),
                    identities,
                    &names,
                )?;
                selected.insert(reference);
                same_package_lookups.insert(lookup);
            }
        }
        Ok(Some(selected))
    }

    fn jvm_import_context_gap(
        &self,
        spec: JvmImportContextGapSpec,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContextGap> {
        let mut descriptor =
            CanonicalIdentityDescriptor::new(b"bifrost-jvm-import-context-gap:v1", |key| {
                self.ready.identity_content_digest(key, cancellation)
            });
        descriptor.field("context", CanonicalIdentityPart::identity(spec.source))?;
        descriptor.field("source", CanonicalIdentityPart::identity(spec.source))?;
        descriptor.field(
            "source-token",
            CanonicalIdentityPart::identity(spec.source_token),
        )?;
        descriptor.field("kind", CanonicalIdentityPart::Content(spec.kind.as_bytes()))?;
        if let Some(owner) = &spec.owner {
            descriptor.field("owner", CanonicalIdentityPart::Content(owner.as_bytes()))?;
        }
        descriptor.field(
            "lookup",
            CanonicalIdentityPart::Content(&spec.lookup.name_digest()),
        )?;
        let reason = self.ready.context_identities.named_semantic(
            descriptor.finish(),
            spec.kind,
            &spec.detail,
        );
        self.ready.context_identities.record_named_reason_lookup(
            reason,
            spec.source,
            spec.lookup.semantic(&self.ready.shared_names()),
        );
        Ok(JvmImportContextGap {
            source_token: spec.source_token,
            source_reference: spec.source_reference,
            lookup: spec.lookup,
            reason,
            kind: spec.kind,
            owner: spec.owner,
            boundary_status: None,
            nominal_type_identity: None,
            suppress_if_same_package_candidate: false,
        })
    }

    fn jvm_import_context_boundary_gap_with_same_package_shadow(
        &self,
        spec: JvmImportContextGapSpec,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContextGap> {
        let mut gap = self.jvm_import_context_gap_with_same_package_shadow(spec, cancellation)?;
        gap.boundary_status =
            Some(crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed);
        Ok(gap)
    }

    fn jvm_import_context_gap_with_same_package_shadow(
        &self,
        spec: JvmImportContextGapSpec,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContextGap> {
        let mut gap = self.jvm_import_context_gap(spec, cancellation)?;
        gap.suppress_if_same_package_candidate = true;
        Ok(gap)
    }

    #[doc(hidden)]
    pub fn jvm_generated_lookup(
        &self,
        language: Language,
        namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        spelling: &str,
    ) -> Arc<JvmGeneratedLookup> {
        let key = (
            language_identity_domain(language),
            namespace,
            spelling.to_owned(),
        );
        if let Some(lookup) = self.jvm_generated_lookup_memo.borrow().get(&key) {
            return Arc::clone(lookup);
        }
        let recipe = ResolutionLookupSemanticRecipe::new(language, namespace, spelling);
        let lookup = Arc::new(JvmGeneratedLookup {
            recipe,
            semantic: std::sync::OnceLock::new(),
        });
        self.jvm_generated_lookup_memo
            .borrow_mut()
            .insert(key, Arc::clone(&lookup));
        lookup
    }

    #[doc(hidden)]
    pub fn jvm_alias_rows(
        &self,
        blob: i64,
        member: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<[JvmAliasRow]>>> {
        let key = JvmAliasRowsKey {
            blob,
            member: member.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("alias_rows", &key);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(rows) = self.jvm_alias_rows_memo.borrow().get(&key) {
            return Ok(Some(Arc::clone(rows)));
        }
        self.profile_jvm_read("derive_alias_rows", &key);
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER)?;
        let rows = statement
            .query_map(rusqlite::params![blob, member], |row| {
                Ok(JvmAliasRow {
                    alias: row.get(0)?,
                    declaration_site: row.get(1)?,
                    status: row.get(2)?,
                    declaration_key: row.get(3)?,
                    kind: row.get(4)?,
                    is_static: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let rows: Arc<[JvmAliasRow]> = Arc::from(rows);
        self.jvm_alias_rows_memo
            .borrow_mut()
            .insert(key, Arc::clone(&rows));
        Ok(Some(rows))
    }

    /// The query's complete target rows have no caller or route completion.
    /// Keep both existing consumer orderings; callers retain their polling.
    #[doc(hidden)]
    pub fn jvm_import_targets(
        &self,
        mounts: ImportTargetMounts,
        package: &str,
    ) -> Result<Arc<JvmImportTargetRows>> {
        let key = JvmImportTargetKey {
            mounts,
            package: package.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.jvm_import_target_rows(key, [package])
    }

    fn jvm_eligible_import_targets(
        &self,
        mounts: ImportTargetMounts,
        package: &str,
    ) -> Result<Arc<JvmImportTargetRows>> {
        let key = JvmImportTargetKey {
            mounts,
            package: package.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        let languages = mounts.languages;
        self.jvm_import_target_rows(
            key,
            rusqlite::params![package, languages[0], languages[1], languages[2]],
        )
    }

    fn jvm_import_target_rows(
        &self,
        key: JvmImportTargetKey,
        params: impl rusqlite::Params,
    ) -> Result<Arc<JvmImportTargetRows>> {
        self.profile_jvm_read("import_targets", &key);
        if let Some(rows) = self.jvm_import_target_memo.borrow().get(&key) {
            return Ok(Arc::clone(rows));
        }
        self.profile_jvm_read("derive_import_targets", &key);
        let connection = self.ready.inventory.connection();
        let mut query = connection.prepare_cached(key.mounts.statement)?;
        let rows = query
            .query_map(params, |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut ordered = rows.clone();
        ordered.sort_unstable();
        ordered.dedup();
        let rows = Arc::new(JvmImportTargetRows {
            rows: rows.into_boxed_slice(),
            ordered: ordered.into_boxed_slice(),
        });
        self.jvm_import_target_memo
            .borrow_mut()
            .insert(key, Arc::clone(&rows));
        Ok(rows)
    }

    // Start with the demanded shared name, then intersect its root headers
    // with selected package membership. Uncertainty is a separate indexed
    // inventory, shared across names of the same package and stage.
    #[doc(hidden)]
    pub fn jvm_named_import_targets(
        &self,
        mounts: ImportTargetMounts,
        package: &str,
        spelling: &str,
        namespaces: &[ResolutionNamespace],
        language: Language,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmImportTargetRows>>> {
        use super::super::resolution_prepare::resolution_rows::{
            identity_domain_code, namespace_code,
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut namespaces = namespaces
            .iter()
            .copied()
            .map(namespace_code)
            .collect::<Vec<_>>();
        namespaces.sort_unstable();
        namespaces.dedup();
        assert!(
            (1..=2).contains(&namespaces.len()),
            "JVM import owner namespaces: {namespaces:?}"
        );
        let key = JvmNamedImportTargetKey {
            mounts,
            package: package.to_owned(),
            spelling: spelling.to_owned(),
            domain: identity_domain_code(language_identity_domain(language)),
            namespaces: namespaces.into_boxed_slice(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("named_import_targets", &key);
        if let Some(rows) = self.jvm_named_import_target_memo.borrow().get(&key) {
            return Ok(Some(Arc::clone(rows)));
        }
        self.profile_jvm_read("derive_named_import_targets", &key);
        let languages = mounts.languages;
        let sql = format!("{JVM_NAMED_IMPORT_TARGETS_HEAD} {JVM_IMPORT_TARGET_PACKAGE_FILTER}");
        let connection = self.ready.inventory.connection();
        let mut query = connection.prepare_cached(&sql)?;
        let mut rows = query
            .query_map(
                rusqlite::params![
                    package,
                    spelling,
                    key.domain,
                    key.namespaces[0],
                    key.namespaces.get(1),
                    languages[0],
                    languages[1],
                    languages[2],
                ],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let Some(uncertain) = self.jvm_import_uncertainty_targets(mounts, package, cancellation)?
        else {
            return Ok(None);
        };
        rows.extend_from_slice(&uncertain);
        // Preserve source-version order followed by content-only mount order,
        // as in the two arms of the original package inventory.
        rows.sort_unstable_by_key(|&(ordinal, version)| (version.is_none(), version, ordinal));
        rows.dedup();
        let mut ordered = rows.clone();
        ordered.sort_unstable();
        ordered.dedup();
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let rows = Arc::new(JvmImportTargetRows {
            rows: rows.into_boxed_slice(),
            ordered: ordered.into_boxed_slice(),
        });
        // The exhausted answer is cached even when both inventories are empty.
        self.jvm_named_import_target_memo
            .borrow_mut()
            .insert(key, Arc::clone(&rows));
        Ok(Some(rows))
    }

    fn jvm_import_uncertainty_targets(
        &self,
        mounts: ImportTargetMounts,
        package: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<[JvmImportTarget]>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let key = JvmImportTargetKey {
            mounts,
            package: package.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("import_uncertainty_targets", &key);
        if let Some(rows) = self.jvm_import_uncertainty_memo.borrow().get(&key) {
            return Ok(Some(Arc::clone(rows)));
        }
        self.profile_jvm_read("derive_import_uncertainty_targets", &key);
        let languages = mounts.languages;
        let sql = JVM_IMPORT_UNCERTAINTY_HEADS.iter().map(|head| format!(
            "{head} AND mounted.storage_language IN (?2,?3,?4) {JVM_IMPORT_TARGET_PACKAGE_FILTER}"
        )).collect::<Vec<_>>().join(" UNION ");
        let connection = self.ready.inventory.connection();
        let mut query = connection.prepare_cached(&sql)?;
        let rows = query
            .query_map(
                rusqlite::params![package, languages[0], languages[1], languages[2]],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let rows: Arc<[JvmImportTarget]> = rows.into();
        self.jvm_import_uncertainty_memo
            .borrow_mut()
            .insert(key, Arc::clone(&rows));
        Ok(Some(rows))
    }

    /// Retain the complete selected-node answer, including an absent endpoint.
    #[doc(hidden)]
    pub fn jvm_endpoint_classifications(
        &self,
        node: BindingNodeId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<[BatchEndpointClassification]>>> {
        let key = JvmEndpointKey {
            node,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("endpoint", key);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(rows) = self.jvm_endpoint_memo.borrow().get(&key) {
            return Ok(Some(Arc::clone(rows)));
        }
        self.profile_jvm_read("derive_endpoint", key);
        let rows = self
            .ready
            .lexical_source()
            .classify_endpoint_nodes(&[node], cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let rows: Arc<[BatchEndpointClassification]> = rows.into();
        self.jvm_endpoint_memo
            .borrow_mut()
            .insert(key, Arc::clone(&rows));
        Ok(Some(rows))
    }

    /// Retain the modifier and lexical boundary together. Package relation and
    /// incoming completion are applied by each caller; entries die with the query.
    #[doc(hidden)]
    pub fn jvm_declaration_visibilities(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<[LoweredDeclarationVisibilityProperty]>>> {
        let key = JvmVisibilityKey {
            definition,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("visibility", key);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(rows) = self.jvm_visibility_memo.borrow().get(&key) {
            return Ok(Some(Arc::clone(rows)));
        }
        self.profile_jvm_read("derive_visibility", key);
        let mut rows = Vec::new();
        let outcome = self
            .ready
            .typed_source()
            .visit_declaration_visibility_pages_for_definitions(
                TypedFactRequest::new(&[definition]),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    rows.extend(page.iter().map(|row| row.row().clone()));
                    Ok(true)
                }),
            )?;
        if outcome.is_cancelled() || cancellation.is_cancelled() {
            return Ok(None);
        }
        let rows: Arc<[LoweredDeclarationVisibilityProperty]> = rows.into();
        if outcome.is_exhausted() {
            self.jvm_visibility_memo
                .borrow_mut()
                .insert(key, Arc::clone(&rows));
        }
        Ok(Some(rows))
    }

    fn jvm_package_target_key(
        &self,
        package: &str,
        lookups: &[SemanticId],
        languages: [Option<&'static str>; 3],
    ) -> JvmPackageTargetKey {
        let mut lookups = lookups.to_vec();
        lookups.sort_unstable();
        lookups.dedup();
        JvmPackageTargetKey {
            package: package.to_owned(),
            lookups: lookups.into_boxed_slice(),
            languages,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        }
    }

    // Existence is independent of a particular member name, and retains the
    // old package inventory's distinction between absent and present-but-empty.
    fn jvm_package_exists(&self, family: &dyn NominalPackageRules, package: &str) -> Result<bool> {
        let key = JvmImportTargetKey {
            mounts: family.import_target_mounts(),
            package: package.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        if let Some(exists) = self.jvm_package_presence_memo.borrow().get(&key) {
            return Ok(*exists);
        }
        let sql = format!("SELECT EXISTS({})", family.import_target_mounts().statement);
        let exists = self
            .ready
            .inventory
            .connection()
            .prepare_cached(&sql)?
            .query_row([package], |row| row.get::<_, bool>(0))?;
        self.jvm_package_presence_memo
            .borrow_mut()
            .insert(key, exists);
        Ok(exists)
    }

    fn jvm_package_member_targets(
        &self,
        key: &JvmPackageTargetKey,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmImportTargetRows>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(rows) = self.jvm_package_target_memo.borrow().get(key) {
            return Ok(Some(Arc::clone(rows)));
        }
        self.profile_jvm_read("derive_named_package_targets", key);
        let names = self.ready.shared_names();
        let persisted = key
            .lookups
            .iter()
            .filter_map(|lookup| {
                names
                    .to_persisted(lookup.shared_name_id().expect("package lookup is shared"))
                    .map(|name| name.get())
            })
            .collect::<Vec<_>>();
        let connection = self.ready.inventory.connection();
        let mut rows = Vec::new();
        if !persisted.is_empty() {
            let sql = jvm_named_package_member_targets_sql();
            let mut statement = connection.prepare_cached(&sql)?;
            rows = statement
                .query_map(
                    rusqlite::params![
                        key.package,
                        serde_json::to_string(&persisted).expect("shared IDs serialize"),
                        key.languages[0],
                        key.languages[1],
                        key.languages[2],
                    ],
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
        }
        // This inventory is deliberately independent of names. Full reads on
        // these hosts keep open roots, every root gap bucket and staged rename
        // authority, even when the ordinary lookup index has no matching row.
        let uncertainty_key = JvmPackageTargetKey {
            lookups: Box::new([]),
            ..key.clone()
        };
        let cached = self
            .jvm_package_uncertainty_memo
            .borrow()
            .get(&uncertainty_key)
            .cloned();
        let uncertainty = if let Some(rows) = cached {
            rows
        } else {
            let sql = jvm_package_member_uncertainty_sql();
            let mut statement = connection.prepare_cached(&sql)?;
            let rows = statement
                .query_map(
                    rusqlite::params![
                        key.package,
                        key.languages[0],
                        key.languages[1],
                        key.languages[2],
                    ],
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let rows: Arc<[JvmImportTarget]> = rows.into();
            self.jvm_package_uncertainty_memo
                .borrow_mut()
                .insert(uncertainty_key, Arc::clone(&rows));
            rows
        };
        rows.extend_from_slice(&uncertainty);
        rows.sort_unstable_by_key(|&(ordinal, version)| (version.is_none(), version, ordinal));
        rows.dedup();
        let mut ordered = rows.clone();
        ordered.sort_unstable();
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let rows = Arc::new(JvmImportTargetRows {
            rows: rows.into_boxed_slice(),
            ordered: ordered.into_boxed_slice(),
        });
        self.jvm_package_target_memo
            .borrow_mut()
            .insert(key.clone(), Arc::clone(&rows));
        Ok(Some(rows))
    }

    /// Reuse the existing staged-overlay reader only for this selected query.
    fn jvm_package_member_set(
        &self,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Arc<JvmPackageMemberSet>>> {
        let key = JvmPackageMemberKey {
            mount,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("package_members", key);
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        let members = self.jvm_package_member_memo.read(key, |key| {
            self.profile_jvm_read("derive_package_members", key);
            let SelectedPackageRows::Ready(members) = self
                .ready
                .selected_package_members_by_lookup(mount, cancellation)?
            else {
                return Ok(None);
            };
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                members
                    .into_iter()
                    .map(|(key, rows)| (key, rows.into()))
                    .collect(),
            )))
        })?;
        Ok(match members {
            Some(members) => SelectedPackageRows::Ready(members),
            None => SelectedPackageRows::Cancelled,
        })
    }

    #[doc(hidden)]
    pub fn jvm_package_members_for_lookup(
        &self,
        mount: SelectedResolutionMountOrdinal,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Arc<[LoweredPackageMember]>>> {
        assert!(
            lookup.shared_name_id().is_some(),
            "package lookup is a shared name"
        );
        let SelectedPackageRows::Ready(members) =
            self.jvm_package_member_set(mount, cancellation)?
        else {
            return Ok(SelectedPackageRows::Cancelled);
        };
        Ok(SelectedPackageRows::Ready(
            members.get(&lookup).cloned().unwrap_or_default(),
        ))
    }

    /// A package's selected membership is invariant across caller files and
    /// names. Preserve target order and staged definition authority in the
    /// request-owned keyed set; no derived resolution answers are retained.
    fn jvm_package_index(
        &self,
        family: &dyn NominalPackageRules,
        package: &str,
        lookups: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmPackageIndex>>> {
        let key =
            self.jvm_package_target_key(package, lookups, family.storage_language_parameters());
        self.profile_jvm_read("package_index", &key);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(index) = self.jvm_package_indexes.borrow().get(&key) {
            return Ok(Some(Arc::clone(index)));
        }
        self.profile_jvm_read("derive_package_index", &key);
        let Some(targets) = self.jvm_package_member_targets(&key, cancellation)? else {
            return Ok(None);
        };
        let mut by_lookup: HashMap<SemanticId, Vec<JvmPackageCandidate>> = HashMap::default();
        for (order, &(ordinal, version)) in targets.ordered.iter().enumerate() {
            let mount = SelectedResolutionMountOrdinal::new(ordinal);
            let SelectedPackageRows::Ready(members) =
                self.jvm_package_member_set(mount, cancellation)?
            else {
                return Ok(None);
            };
            for (&lookup, rows) in members.iter() {
                by_lookup
                    .entry(lookup)
                    .or_default()
                    .push(JvmPackageCandidate {
                        mount,
                        version,
                        order,
                        members: Arc::clone(rows),
                    });
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let index = Arc::new(JvmPackageIndex {
            empty: !self.jvm_package_exists(family, package)?,
            by_lookup,
        });
        self.jvm_package_indexes
            .borrow_mut()
            .insert(key, Arc::clone(&index));
        Ok(Some(index))
    }

    /// Match a file's structured reference names against its package/default
    /// import sets once. Named contexts consume only their reference rows from
    /// this plan; access evidence and bridge publication stay demand-scoped.
    fn jvm_file_package_plan(
        &self,
        language: Language,
        fragment: BindingFragmentId,
        source_package: Option<&str>,
        references: &[LoweredPackageReference],
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmFilePackagePlan>> {
        self.profile_jvm_read("derive_file_package_plan", (language, fragment));
        let rules = nominal_language_rules(language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let mut packages = nominal_language_rules(language)
            .expect("caller belongs to a nominal family")
            .implicit_root_providers()
            .iter()
            .filter_map(|provider| match provider {
                JvmImplicitRootProvider::Package(package) => Some((*package).to_owned()),
                JvmImplicitRootProvider::ScalaPredef => None,
            })
            .collect::<Vec<_>>();
        packages.extend(source_package.map(str::to_owned));
        packages.sort_unstable();
        packages.dedup();
        let names = self.ready.shared_names();
        let mut lookups = HashMap::default();
        for reference in references {
            if lookups.contains_key(&reference.lookup) {
                continue;
            }
            let Some(recipes) =
                self.jvm_lookup_recipes(fragment, [reference.lookup], cancellation)?
            else {
                return Ok(None);
            };
            let recipe = &recipes[0];
            let target_lookups = family
                .languages()
                .iter()
                .copied()
                .map(|target_language| {
                    self.jvm_generated_lookup(
                        target_language,
                        reference.namespace,
                        recipe.spelling(),
                    )
                    .semantic(&names)
                })
                .collect::<HashSet<_>>();
            lookups.insert(reference.lookup, target_lookups);
        }
        let all_lookups = lookups.values().flatten().copied().collect::<Vec<_>>();
        let mut plan = HashMap::default();
        for package in packages {
            let Some(index) =
                self.jvm_package_index(family, &package, &all_lookups, cancellation)?
            else {
                return Ok(None);
            };
            let mut candidates = HashMap::default();
            for (&lookup, target_lookups) in &lookups {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let mut matches = target_lookups
                    .iter()
                    .filter_map(|target| index.by_lookup.get(target))
                    .flatten()
                    .cloned()
                    .collect::<Vec<_>>();
                matches.sort_by_key(|candidate| candidate.order);
                if !matches.is_empty() {
                    candidates.insert(lookup, matches);
                }
            }
            plan.insert(
                package,
                JvmPlannedPackage {
                    empty: index.empty,
                    candidates,
                },
            );
        }
        Ok((!cancellation.is_cancelled()).then_some(plan))
    }

    /// Read one demanded mount's export rows and their full proof evidence.
    /// Route-specific filters run over the same immutable pages on every use.
    #[doc(hidden)]
    pub fn jvm_root_exports(
        &self,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmRootExportInventory>>> {
        let key = JvmRootExportKey {
            mount,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("root_exports", key);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(inventory) = self.jvm_root_exports_memo.borrow().get(&key) {
            return Ok(Some(Arc::clone(inventory)));
        }
        self.profile_jvm_read("derive_root_exports", key);
        let (halves, outcome) =
            self.read_root_inventory(RootHalfRequest::Exports(&[mount]), cancellation)?;
        if outcome.is_cancelled() || cancellation.is_cancelled() {
            return Ok(None);
        }
        let inventory = Arc::new(JvmRootExportInventory { halves, outcome });
        // A stopped read cannot stand in for an exhausted inventory. Preserve
        // its terminal and evidence for this caller without publishing it.
        if inventory.outcome.is_exhausted() {
            self.jvm_root_exports_memo
                .borrow_mut()
                .insert(key, Arc::clone(&inventory));
        }
        Ok(Some(inventory))
    }

    pub(super) fn jvm_lookup_recipes(
        &self,
        fragment: BindingFragmentId,
        semantics: impl IntoIterator<Item = SemanticId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<ResolutionLookupSemanticRecipe>>> {
        let semantics = semantics.into_iter().collect::<Vec<_>>();
        self.profile_jvm_read("lookup_recipes", (fragment, &semantics));
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let scope = self.ready.inventory.scope_identity();
        let stage_epoch = self.ready.inventory.staged_read_epoch();
        self.import_lookup_recipes(fragment, &semantics, cancellation, |request| {
            self.profile_jvm_read(
                "derive_lookup_recipe",
                JvmLookupRecipeKey {
                    fragment,
                    semantic: request.semantic,
                    scope,
                    stage_epoch,
                },
            )
        })
    }

    fn jvm_package_import_bridges(
        &self,
        import_context: &JvmPackageImportContext<'_>,
        packages: &[String],
        references: &[crate::analyzer::resolution::LoweredPackageReference],
        scoped_gaps: &mut Vec<JvmImportContextGap>,
        same_package_lookups: &mut BTreeSet<SemanticId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedPackageBridgeDescriptor>>> {
        let JvmPackageImportContext {
            context_id,
            source_ordinal,
            source_path,
            caller_version,
            caller_package,
            lookup,
            package_plan,
        } = *import_context;
        let source_language = self
            .mount_table()
            .mount_by_ordinal(source_ordinal)?
            .semantic_language();
        let implicit_root_providers = nominal_language_rules(source_language)
            .expect("caller belongs to a nominal family")
            .implicit_root_providers();
        let source_mount = self.mount_table().mount_by_ordinal(source_ordinal)?;
        let mut reference_recipes = Vec::with_capacity(references.len());
        for reference in references {
            let Some(mut source_recipes) =
                self.jvm_lookup_recipes(source_mount.fragment(), [reference.lookup], cancellation)?
            else {
                return Ok(None);
            };
            let source_recipe = source_recipes
                .pop()
                .expect("one selected package reference lookup");
            assert_eq!(
                source_recipe.identity_domain(),
                language_identity_domain(source_language)
            );
            reference_recipes.push((reference, source_recipe));
        }
        let names = self.ready.shared_names();
        let mut candidates = Vec::new();
        for (reference, source_recipe) in &reference_recipes {
            for package in packages {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let planned = package_plan
                    .get(package)
                    .expect("file preparation plans every package import");
                let is_default_import = implicit_root_providers.iter().any(|provider| {
                    matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package.as_str())
                });
                if !is_default_import
                    && lookup.is_some_and(|lookup| source_recipe.spelling() != lookup)
                {
                    continue;
                }
                if is_default_import && planned.empty {
                    scoped_gaps.push(self.jvm_import_context_boundary_gap_with_same_package_shadow(
                        JvmImportContextGapSpec {
                            source: source_mount.fragment(),
                            source_token: reference.token,
                            source_reference: Some(reference.reference),
                            kind: "jvm-default-import-package-open",
                            owner: Some(package.to_owned()),
                            lookup: source_recipe.clone(),
                            detail: format!(
                            "{} default import package `{package}` has no selected source or classpath owner for `{}`",
                            source_language.config_label(),
                            source_recipe.spelling()
                        ),
                        },
                        cancellation,
                    )?);
                }
                for candidate in planned
                    .candidates
                    .get(&reference.lookup)
                    .into_iter()
                    .flatten()
                {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let target_ordinal = candidate.mount;
                    if target_ordinal == source_ordinal {
                        continue;
                    }
                    let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                    let target_mount_record = self
                        .ready
                        .inventory
                        .mount_record_by_ordinal(target_ordinal)?;
                    let target_lookup = self.jvm_generated_lookup(
                        target_mount.semantic_language(),
                        reference.namespace,
                        source_recipe.spelling(),
                    );
                    let target_lookup_semantic = target_lookup.semantic(&names);
                    // These reads were outside the member loop before shared
                    // assembly. Carry their evidence in the candidate inventory.
                    let Some(access) = self.jvm_qualified_source_access_completion(
                        source_language,
                        context_id,
                        caller_version,
                        source_path,
                        candidate.version,
                        target_mount.persisted_relative_path(),
                        &ResolutionCompletion::Complete,
                    )?
                    else {
                        continue;
                    };
                    candidates.push(JvmPackageBridgeCandidate {
                        reference,
                        source_recipe,
                        package,
                        candidate,
                        target: target_mount,
                        target_digest: target_mount_record.fragment_digest().as_bytes(),
                        target_lookup,
                        target_lookup_semantic,
                        access,
                    });
                }
            }
        }
        let pairs = candidates.iter().flat_map(|candidate| {
            candidate
                .candidate
                .members
                .iter()
                .map(move |member| PackageBridgePair {
                    reference: candidate.reference,
                    member,
                    target_fragment: candidate.target.fragment(),
                    target_mount: candidate.target.ordinal(),
                    extra: candidate,
                })
        });
        let assembly = assemble_package_bridges(
            &self.ready,
            pairs,
            &JvmPackageBridgeRules {
                operation: self,
                source: &source_mount,
                context_id,
                caller_version,
                caller_package,
                same_package_lookups: RefCell::new(same_package_lookups),
            },
            cancellation,
        )?;
        Ok((!assembly
            .completion
            .contains_reason(ResolutionIncompleteReason::Cancelled))
        .then_some(assembly.descriptors))
    }

    fn selected_jvm_package_precedence(
        language: Language,
        caller_package: Option<&str>,
        target_package: &str,
    ) -> SelectedJvmPackagePrecedence {
        let relation = if caller_package == Some(target_package) {
            PackageRelation::SamePackage
        } else {
            PackageRelation::OtherPackage
        };
        let (tier, origin) = jvm_package_precedence_origin(language, relation);
        SelectedJvmPackagePrecedence {
            tier,
            candidate_origin_rank: binding_origin_rank(language, origin),
        }
    }

    fn scala_predef_import_bridges(
        &self,
        import_context: &JvmPackageImportContext<'_>,
        references: &[crate::analyzer::resolution::LoweredPackageReference],
        cancellation: &CancellationToken,
    ) -> Result<
        Option<(
            Vec<SelectedPackageBridgeDescriptor>,
            Vec<JvmImportContextGap>,
        )>,
    > {
        let JvmPackageImportContext {
            context_id,
            source_ordinal,
            source_path,
            caller_version,
            caller_package,
            lookup: _,
            package_plan: _,
        } = *import_context;
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let source_mount = self.mount_table().mount_by_ordinal(source_ordinal)?;
        let source_language = source_mount.semantic_language();
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let family = rules.family();
        assert!(rules.has_implicit_import_context());
        let predef = self
            .jvm_generated_lookup(Language::Scala, ResolutionNamespace::Value, "Predef")
            .recipe
            .clone();
        let predef_lookup = predef.semantic(&names);
        let target_mounts = self.jvm_import_targets(family.import_target_mounts(), "scala")?;
        let predef_root_unindexed = target_mounts.ordered.is_empty();
        let lexical = self.ready.lexical_source();
        let typed = self.ready.typed_source();
        let mut bridges = Vec::new();
        let mut resolved_lookups = BTreeSet::new();
        for (target_ordinal, target_version) in target_mounts.ordered.iter().copied() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let target_ordinal = SelectedResolutionMountOrdinal::new(target_ordinal);
            let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
            let target_language = target_mount.semantic_language();
            let SelectedPackageRows::Ready(predef_members) =
                self.jvm_package_members_for_lookup(target_ordinal, predef_lookup, cancellation)?
            else {
                return Ok(None);
            };
            let Some(access) = self.jvm_qualified_source_access_completion(
                source_language,
                context_id,
                caller_version,
                source_path,
                target_version,
                target_mount.persisted_relative_path(),
                &ResolutionCompletion::Complete,
            )?
            else {
                continue;
            };
            let relation = JvmDeclarationAccessContext::between(caller_package, "scala");
            let target_record = self
                .ready
                .inventory
                .mount_record_by_ordinal(target_ordinal)?;
            for predef_member in predef_members.iter().copied() {
                if predef_member.namespace != ResolutionNamespace::Value
                    || predef_member.lookup != predef_lookup
                {
                    continue;
                }
                let Some(local_key) = predef_member.definition.local_key() else {
                    continue;
                };
                let has_object_relation = connection
                    .query_row(
                        "SELECT 1 FROM main.resolution_semantic_sites AS site
                         JOIN main.resolution_singleton_relations AS singleton
                           ON singleton.blob_id=site.blob_id AND singleton.declaration_site=site.source_site
                         WHERE site.blob_id=?1 AND site.semantic_key=?2
                           AND site.semantic_role='definition' AND singleton.kind='object'",
                        rusqlite::params![target_record.blob_id(), local_key],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !has_object_relation {
                    continue;
                }
                let mut owner_members = Vec::new();
                let outcome = typed.visit_member_owner_pages_for_owners(
                    TypedFactRequest::new(&[predef_member.definition]),
                    cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        owner_members.extend(
                            page.iter()
                                .filter(|row| {
                                    row.fragment() == target_mount.fragment()
                                        && row.row().owner_definition() == predef_member.definition
                                })
                                .map(|row| row.row().clone()),
                        );
                        Ok(true)
                    }),
                )?;
                if outcome.is_cancelled() {
                    return Ok(None);
                }
                let coordinates = owner_members
                    .iter()
                    .filter_map(|member| {
                        (member.definition().ordinal() == Some(target_ordinal.get()))
                            .then(|| member.definition().local_key())
                            .flatten()
                            .map(|key| (target_ordinal, ResolutionLocalKey::new(i64::from(key))))
                    })
                    .collect::<Vec<_>>();
                let mut member_names = Vec::new();
                for page in coordinates.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                    let SelectedDefinitionUnitReadOutcome::Ready(rows) = self
                        .ready
                        .inventory
                        .selected_declaration_units(page, cancellation)?
                    else {
                        return Ok(None);
                    };
                    for (_, key, row) in rows {
                        let semantic = SemanticId::local(
                            target_ordinal.get(),
                            u32::try_from(key.get()).expect("a catalog position fits u32"),
                        );
                        let Some(name) = row
                            .fq
                            .as_ref()
                            .and_then(|identity| identity.segments.last())
                            .map(|(_, spelling)| spelling.clone())
                        else {
                            continue;
                        };
                        member_names.push((semantic, name));
                    }
                }
                for reference in references {
                    let Some(mut source_recipes) = self.jvm_lookup_recipes(
                        source_mount.fragment(),
                        [reference.lookup],
                        cancellation,
                    )?
                    else {
                        return Ok(None);
                    };
                    let source_recipe = source_recipes
                        .pop()
                        .expect("one selected Scala Predef reference recipe");
                    assert_eq!(
                        source_recipe.identity_domain(),
                        language_identity_domain(source_language)
                    );
                    let target_recipe = self
                        .jvm_generated_lookup(
                            Language::Scala,
                            reference.namespace,
                            source_recipe.spelling(),
                        )
                        .recipe
                        .clone();
                    for owner_member in owner_members.iter().filter(|owner_member| {
                        owner_member.definition() != predef_member.definition
                            && member_namespace(owner_member.kind()) == Some(reference.namespace)
                    }) {
                        let Some((_, member_name)) =
                            member_names.iter().find(|(definition, name)| {
                                *definition == owner_member.definition()
                                    && name == source_recipe.spelling()
                            })
                        else {
                            continue;
                        };
                        assert_eq!(member_name, source_recipe.spelling());
                        let Some(target_definition) = lexical
                            .lookup_definition_node(owner_member.definition(), cancellation)?
                        else {
                            if cancellation.is_cancelled() {
                                return Ok(None);
                            }
                            return Err(StoreError::corrupt(
                                "selected Scala Predef member lacks a definition node",
                            ));
                        };
                        let completion = match self.jvm_declaration_access(
                            owner_member.definition(),
                            relation,
                            &access,
                            cancellation,
                        )? {
                            JvmDeclarationAccess::Ready(completion) => completion,
                            JvmDeclarationAccess::Excluded => continue,
                            JvmDeclarationAccess::Cancelled => return Ok(None),
                        };
                        let route_identity = jvm_singleton_route_identity(
                            predef_member.definition,
                            owner_member.definition(),
                            source_language,
                            |key| self.ready.identity_content_digest(key, cancellation),
                        )?;
                        let evidence = if source_language == target_language {
                            None
                        } else {
                            let Some(visibility) = self.jvm_bridge_visibility(
                                owner_member.definition(),
                                relation,
                                cancellation,
                            )?
                            else {
                                continue;
                            };
                            Some(SelectedJvmBridgeEvidence {
                                provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                                    source_package: reference.domain,
                                    target_package: package_domain_semantic(
                                        Language::Scala,
                                        &names,
                                    ),
                                },
                                source_namespace: reference.namespace,
                                target_namespace: reference.namespace,
                                visibility,
                                dependency_identity: jvm_dependency_identity(
                                    context_id,
                                    caller_version,
                                    source_path,
                                    target_version,
                                    target_mount.persisted_relative_path(),
                                ),
                                target_declaration: owner_member.definition(),
                                target_definition,
                            })
                        };
                        bridges.push(
                            SelectedPackageBridgeDescriptor::new_jvm_selected_definition_import(
                                source_mount.fragment(),
                                target_mount.fragment(),
                                source_language,
                                target_language,
                                reference,
                                &source_recipe,
                                owner_member.definition(),
                                target_definition,
                                package_domain_semantic(Language::Scala, &names),
                                &target_recipe,
                                route_identity,
                                &names,
                                evidence,
                                completion,
                            ),
                        );
                        resolved_lookups.insert(reference.lookup);
                    }
                }
            }
        }
        let mut gaps = Vec::new();
        for reference in references {
            if resolved_lookups.contains(&reference.lookup) {
                continue;
            }
            let Some(mut source_recipes) =
                self.jvm_lookup_recipes(source_mount.fragment(), [reference.lookup], cancellation)?
            else {
                return Ok(None);
            };
            let source_recipe = source_recipes
                .pop()
                .expect("one selected Scala Predef reference recipe");
            let mut gap = self.jvm_import_context_gap_with_same_package_shadow(
                JvmImportContextGapSpec {
                    source: source_mount.fragment(),
                    source_token: reference.token,
                    source_reference: Some(reference.reference),
                    kind: "scala-predef-route-open",
                    owner: Some(SCALA_PREDEF_DEFAULT_IMPORT.to_owned()),
                    lookup: source_recipe.clone(),
                    detail: format!(
                    "Scala implicit Predef._ route has no selected singleton or inherited member for `{}`",
                    source_recipe.spelling()
                    ),
                },
                cancellation,
            )?;
            if predef_root_unindexed {
                gap.boundary_status =
                    Some(crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed);
            }
            gaps.push(gap);
        }
        Ok((!cancellation.is_cancelled()).then_some((bridges, gaps)))
    }

    fn jvm_alias_import_bridges(
        &self,
        import: &JavaMemberImportDemand<'_>,
        imported_name: &str,
        caller_version: Option<i64>,
        caller_path: &str,
        context_id: i64,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmAliasImportBridges>> {
        let rules =
            nominal_language_rules(import.language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let connection = self.ready.inventory.connection();
        let mut bridges = Vec::new();
        let mut open_imports = Vec::new();
        let mut found_alias = false;
        let mut coverage_gaps = Vec::new();
        let static_alias_import = matches!(
            import.import_kind,
            Some(
                ResolutionImportRouteKind::SingleStatic | ResolutionImportRouteKind::StaticOnDemand
            )
        );
        for prefix_length in (1..=import.lookup_route.len()).rev() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let owner_recipes = &import.lookup_route[..prefix_length];
            let package = owner_recipes
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".");
            if package.is_empty() {
                continue;
            }
            let targets = self.jvm_eligible_import_targets(
                family.eligible_alias_target_mounts(import.language),
                &package,
            )?;
            let expected_owner = import
                .lookup_route
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>();
            let source_owner = expected_owner
                .iter()
                .map(|segment| (*segment).to_owned())
                .collect::<Vec<_>>();
            let expected_owner = crate::analyzer::resolution::language_jvm_import_binary_owner(
                import.language,
                prefix_length,
                &expected_owner,
            );
            let relation = JvmDeclarationAccessContext::between(import.caller_package, &package)
                .with_reference(import.prefix_reference)
                .with_scope(import.scope_head)
                .with_import(import.token);
            for (target_ordinal, target_version) in targets.ordered.iter().copied() {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let target_ordinal = SelectedResolutionMountOrdinal::new(target_ordinal);
                let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                let target_language = target_mount.semantic_language();
                debug_assert!(family.admits_alias_target(import.language, target_language));
                if source_owner.len() <= prefix_length {
                    // Source-language imports bind authored names, not that
                    // language's JVM facade/module projections. A package-only
                    // route has no binary type owner to probe in this reader.
                    continue;
                }
                let target_record = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(target_ordinal)?;
                let Some(alias_completion) = self.jvm_alias_surface_completion(
                    target_mount.fragment(),
                    &expected_owner,
                    imported_name,
                    import.demand.namespace(),
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                if alias_completion != ResolutionCompletion::Complete {
                    // An omitted row is evidence of an open route, not proof
                    // of an external owner or an absent alias.
                    found_alias = true;
                    open_imports.push(format!("{}.{}", expected_owner.join("."), imported_name));
                    coverage_gaps.extend(jvm_alias_coverage_gaps(
                        import.token,
                        import.prefix_reference,
                        import.demand,
                        &expected_owner.join("."),
                        &alias_completion,
                    ));
                }
                let Some(aliases) =
                    self.jvm_alias_rows(target_record.blob_id(), imported_name, cancellation)?
                else {
                    return Ok(None);
                };
                for alias in aliases.iter() {
                    let alias_id = alias.alias;
                    let declaration_site = alias.declaration_site;
                    let declaration_key = alias.declaration_key;
                    let status = &alias.status;
                    let alias_kind = &alias.kind;
                    let is_static = alias.is_static;
                    let mut segments = connection.prepare_cached(
                        "SELECT spelling FROM main.resolution_jvm_alias_owner_segments
                         WHERE blob_id=?1 AND alias=?2 ORDER BY ordinal",
                    )?;
                    let owner = segments
                        .query_map(
                            rusqlite::params![target_record.blob_id(), alias_id],
                            |row| row.get::<_, String>(0),
                        )?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    if owner != expected_owner {
                        continue;
                    }
                    // Static callable imports must denote emitted methods, not
                    // source properties or constructors. Getter/setter aliases
                    // target Value declarations and need separate adaptation.
                    let static_kind_matches = matches!(
                        (alias_kind.as_str(), import.demand.namespace()),
                        ("method", ResolutionNamespace::Callable)
                            | (
                                "field" | "companion_object" | "singleton_instance",
                                ResolutionNamespace::Value
                            )
                    );
                    if static_alias_import && !is_static {
                        continue;
                    }
                    found_alias = true;
                    let alias_fqn = format!("{}.{}", owner.join("."), imported_name);
                    if status != "source_proven" {
                        open_imports.push(alias_fqn);
                        continue;
                    }
                    let singleton_kind = match alias_kind.as_str() {
                        "companion_object" => Some("companion"),
                        "singleton_instance" => Some("object"),
                        _ => None,
                    };
                    if let Some(singleton_kind) = singleton_kind {
                        let has_singleton = connection
                            .query_row(
                                "SELECT 1 FROM main.resolution_singleton_relations
                                 WHERE blob_id=?1 AND declaration_site=?2 AND kind=?3",
                                rusqlite::params![
                                    target_record.blob_id(),
                                    declaration_site,
                                    singleton_kind
                                ],
                                |_| Ok(()),
                            )
                            .optional()?
                            .is_some();
                        if !has_singleton {
                            open_imports.push(alias_fqn);
                            continue;
                        }
                    }
                    let declaration = SemanticId::local(target_ordinal.get(), declaration_key);
                    let target_definition = self
                        .ready
                        .lexical_source()
                        .lookup_definition_node(declaration, cancellation)?;
                    let Some(target_definition) = target_definition else {
                        if cancellation.is_cancelled() {
                            return Ok(None);
                        }
                        return Err(StoreError::corrupt(
                            "selected JVM alias lacks its exact declaration definition",
                        ));
                    };
                    let Some(access) = self.jvm_qualified_source_access_completion(
                        import.language,
                        context_id,
                        caller_version,
                        caller_path,
                        target_version,
                        target_mount.persisted_relative_path(),
                        &ResolutionCompletion::Complete,
                    )?
                    else {
                        continue;
                    };
                    let completion = match self.jvm_declaration_access(
                        declaration,
                        relation,
                        &access,
                        cancellation,
                    )? {
                        JvmDeclarationAccess::Ready(completion) => completion,
                        JvmDeclarationAccess::Excluded => continue,
                        JvmDeclarationAccess::Cancelled => return Ok(None),
                    };
                    let completion = if static_alias_import
                        && nominal_language_rules(import.language)
                            .expect("import caller belongs to a nominal family")
                            .static_alias_access_languages()
                            .contains(&target_language)
                    {
                        match self.jvm_static_alias_owner_access(
                            declaration,
                            &source_owner,
                            relation,
                            &completion,
                            cancellation,
                        )? {
                            Some(JvmDeclarationAccess::Ready(completion)) => completion,
                            Some(JvmDeclarationAccess::Excluded) => continue,
                            Some(JvmDeclarationAccess::Cancelled) => return Ok(None),
                            None => {
                                open_imports.push(alias_fqn);
                                continue;
                            }
                        }
                    } else {
                        completion
                    };
                    // A static alias proves the binary owner/name even when
                    // its declaration needs an unsupported namespace conversion.
                    // Keep that route open instead of claiming an unindexed
                    // owner or a complete absence of definitions.
                    if static_alias_import && !static_kind_matches {
                        open_imports.push(alias_fqn);
                        continue;
                    }
                    let completion = completion.combine(&alias_completion);
                    let mut alias_hash =
                        CanonicalIdentityDescriptor::new(b"bifrost-jvm-alias-fact:v1", |key| {
                            self.ready.identity_content_digest(key, cancellation)
                        });
                    alias_hash.field(
                        "target-blob",
                        CanonicalIdentityPart::Content(&target_record.fragment_digest().as_bytes()),
                    )?;
                    alias_hash.field(
                        "alias",
                        CanonicalIdentityPart::Content(&alias_id.to_le_bytes()),
                    )?;
                    alias_hash.field(
                        "declaration-site",
                        CanonicalIdentityPart::Content(&declaration_site.to_le_bytes()),
                    )?;
                    alias_hash.field(
                        "member-name",
                        CanonicalIdentityPart::Content(imported_name.as_bytes()),
                    )?;
                    for segment in &owner {
                        alias_hash.field(
                            "owner-segment",
                            CanonicalIdentityPart::Content(segment.as_bytes()),
                        )?;
                    }
                    let alias_identity = self.ready.context_identities.named_semantic(
                        alias_hash.finish(),
                        "jvm-alias-fact",
                        "Selected JVM alias rows map this binary owner and member to an authored declaration",
                    );
                    if static_alias_import {
                        let Some(exports_read) =
                            self.jvm_root_exports(target_ordinal, cancellation)?
                        else {
                            return Ok(None);
                        };
                        let exports = exports_read.halves.iter()
                            .filter(|half| matches!(half, SelectedRootPathHalf::Export { definition, .. } if *definition == target_definition))
                            .cloned()
                            .collect::<Vec<_>>();
                        // Matching exports retain their completion even though
                        // the bridge ends directly at the authored definition.
                        // Members without root exports use the same persisted
                        // declaration/scope omitted-binder authority instead.
                        let mut alias_reasons = Vec::new();
                        for export in &exports {
                            let SelectedRootPathHalf::Export {
                                incomplete_reasons, ..
                            } = export
                            else {
                                unreachable!("export-only visitor")
                            };
                            alias_reasons.extend(incomplete_reasons.iter().copied());
                        }
                        let origin =
                            super::super::resolution_prepare::resolution_rows::gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnsupportedScopeOrBinder,
                                ),
                            );
                        let mut gaps =
                            connection.prepare_cached(SELECTED_JVM_ALIAS_DECLARATION_GAPS)?;
                        let mut reasons = gaps.query(rusqlite::params![
                            target_record.blob_id(),
                            target_definition
                                .local_key()
                                .expect("alias definition is local"),
                            origin,
                        ])?;
                        while let Some(row) = reasons.next()? {
                            if cancellation.is_cancelled() {
                                return Ok(None);
                            }
                            let reason =
                                SemanticId::local(target_ordinal.get(), row.get::<_, u32>(0)?);
                            alias_reasons
                                .push(ResolutionIncompleteReason::UnsupportedSemantic(reason));
                        }
                        let completion = if alias_reasons.is_empty() {
                            completion
                        } else {
                            completion.combine(&ResolutionCompletion::incomplete(alias_reasons))
                        };
                        let bridge = SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
                            import.source,
                            import.language,
                            import.token,
                            import.anchor,
                            import.anchor_semantic,
                            target_mount.fragment(),
                            target_language,
                            declaration,
                            None,
                            import.route.to_vec(),
                            import.demand.clone(),
                            import.demand.clone(),
                            SelectedJvmBridgeEvidence {
                                provenance: SelectedJvmBridgeProvenance::AliasFact { alias: alias_identity },
                                source_namespace: import.demand.namespace(),
                                target_namespace: import.demand.namespace(),
                                visibility: match self.jvm_bridge_visibility(declaration, relation, cancellation)? {
                                    Some(visibility) => visibility,
                                    None => return Ok(None),
                                },
                                dependency_identity: jvm_dependency_identity(context_id, caller_version, caller_path, target_version, target_mount.persisted_relative_path()),
                                target_declaration: declaration,
                                target_definition,
                            },
                            completion,
                        );
                        bridges.push(
                            import
                                .rank_bridge(bridge)
                                .with_selected_member_definition(target_definition),
                        );
                        continue;
                    }
                    let mut target_rules = JvmAliasTargetRules {
                        operation: self,
                        import,
                        target: &target_mount,
                        alias_identity,
                        declaration,
                        target_definition,
                        relation,
                        context_id,
                        caller_version,
                        caller_path,
                        target_version,
                        completion: &completion,
                    };
                    match append_root_target(
                        &self.ready,
                        import.half,
                        &mut target_rules,
                        &mut bridges,
                        cancellation,
                    )? {
                        RootBridgeStep::Ready(_) => {}
                        RootBridgeStep::Unavailable | RootBridgeStep::Cancelled => return Ok(None),
                    }
                }
            }
        }
        open_imports.sort_unstable();
        open_imports.dedup();
        Ok(
            (!cancellation.is_cancelled()).then_some(JvmAliasImportBridges {
                bridges,
                open_imports,
                found_alias,
                coverage_gaps,
            }),
        )
    }

    /// Access follows the alias's binary owner, which can be an enclosing
    /// class rather than the callable's lexical companion. None leaves the
    /// alias route open when published ownership cannot establish that owner.
    fn jvm_static_alias_owner_access(
        &self,
        declaration: SemanticId,
        binary_owner: &[String],
        package: JvmDeclarationAccessContext<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmDeclarationAccess>> {
        let target = SelectedResolutionMountOrdinal::new(
            declaration.ordinal().expect("a selected alias is local"),
        );
        let target_mount = self.mount_table().mount_by_ordinal(target)?;
        let target_file = ProjectFile::new(
            self.ready.project.root().to_path_buf(),
            target_mount.persisted_relative_path(),
        );
        let typed = self.ready.typed_source();
        let mut current = declaration;
        let mut visited = HashSet::default();
        let mut binary_owner_found = false;
        let mut completion = completion.clone();
        loop {
            if cancellation.is_cancelled() {
                return Ok(Some(JvmDeclarationAccess::Cancelled));
            }
            assert!(
                visited.insert(current),
                "selected declaration owners are acyclic"
            );
            let Some(unit) =
                self.java_selected_type_unit(target, &target_file, current, cancellation)?
            else {
                return Ok(if cancellation.is_cancelled() {
                    Some(JvmDeclarationAccess::Cancelled)
                } else {
                    None
                });
            };
            let is_type = unit.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Class;
            if current != declaration && !is_type {
                return Ok(None);
            }
            if is_type
                && unit
                    .fq()
                    .resolved_segments()
                    .map(|(spelling, _)| spelling)
                    .eq(binary_owner.iter().map(String::as_str))
            {
                binary_owner_found = true;
            }
            if binary_owner_found {
                completion = match self.jvm_declaration_access(
                    current,
                    package,
                    &completion,
                    cancellation,
                )? {
                    JvmDeclarationAccess::Ready(completion) => completion,
                    decision => return Ok(Some(decision)),
                };
            }
            let mut owners = Vec::new();
            let outcome = typed.visit_member_owner_pages_for_definitions(
                TypedFactRequest::new(&[current]),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    owners.extend(page.iter().map(|row| row.row().owner_definition()));
                    Ok(true)
                }),
            )?;
            if outcome.is_cancelled() {
                return Ok(Some(JvmDeclarationAccess::Cancelled));
            }
            if !outcome.is_exhausted() || outcome.evidence() != &ResolutionCompletion::Complete {
                return Ok(None);
            }
            owners.sort_unstable();
            owners.dedup();
            assert!(owners.len() <= 1, "one selected declaration has one owner");
            match owners.pop() {
                Some(owner) => current = owner,
                None => {
                    if unit.declaration_segment_count() != 1 {
                        return Ok(None);
                    }
                    // A top-level callable or field has no declared source
                    // owner. Its source-proven alias establishes the facade;
                    // source-set and declaration access were checked above.
                    let file_facade = current == declaration && !is_type;
                    return Ok((binary_owner_found || file_facade)
                        .then_some(JvmDeclarationAccess::Ready(completion)));
                }
            }
        }
    }

    /// Read the JVM projection's candidate surface without reopening the
    /// declaration's independently proven Kotlin or Scala source identity.
    fn jvm_alias_surface_completion(
        &self,
        fragment: BindingFragmentId,
        owner: &[impl AsRef<str>],
        name: &str,
        namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>> {
        use crate::analyzer::resolution::{
            BatchCandidateRequest, BatchResolutionFragmentSource, EndpointSignature,
            PartialScopedSymbol, StackPattern,
        };
        let source = self.ready.lexical_source();
        let identities =
            crate::analyzer::resolution::alias_lookup_surface_node_identities(owner, namespace);
        let mut completion = ResolutionCompletion::Complete;
        for identity in identities {
            let Some(surface) = source.node_for_identity(fragment, identity, cancellation)? else {
                return Ok(None);
            };
            let Some(surface) = surface else {
                continue;
            };
            let lookup = ResolutionLookupSemanticRecipe::new(Language::Java, namespace, name)
                .semantic(&self.ready.shared_names());
            let request = BatchCandidateRequest::new(
                0,
                EndpointSignature::new_scoped(
                    surface,
                    StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
                    StackPattern::closed([]),
                ),
            );
            let outcome = source.visit_forward_candidate_match_pages(
                &[request],
                cancellation,
                &mut |_| unreachable!("alias coverage surfaces contain no lexical paths"),
            )?;
            completion = completion
                .combine(outcome.unconditional_completion())
                .combine(&outcome.branch_completions()[0]);
        }
        Ok((!cancellation.is_cancelled()).then_some(completion))
    }

    fn jvm_open_owner_alias_imports(
        &self,
        source_language: Language,
        route: &[ResolutionLookupSemanticRecipe],
        imported_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<(String, ResolutionCompletion)>>> {
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let connection = self.ready.inventory.connection();
        let mut open_imports = Vec::new();
        for prefix_length in (1..=route.len()).rev() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let owner_prefix = route[..prefix_length]
                .iter()
                .map(|segment| segment.spelling().to_owned())
                .collect::<Vec<_>>();
            let package = owner_prefix.join(".");
            if package.is_empty() {
                continue;
            }
            let targets = self.jvm_eligible_import_targets(
                family.eligible_package_alias_target_mounts(source_language),
                &package,
            )?;
            let mut expected_owner = route
                .iter()
                .map(|segment| segment.spelling().to_owned())
                .collect::<Vec<_>>();
            expected_owner.push(imported_name.to_owned());
            let expected_owner = crate::analyzer::resolution::language_jvm_import_binary_owner(
                source_language,
                prefix_length,
                &expected_owner
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            );
            for (target_ordinal, _) in targets.ordered.iter().copied() {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let target_ordinal = SelectedResolutionMountOrdinal::new(target_ordinal);
                let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                let target_language = target_mount.semantic_language();
                debug_assert!(family.admits_package_alias_target(source_language, target_language));
                let target_record = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(target_ordinal)?;
                // An authored source-language owner is not an omitted JVM
                // facade or module projection of that same language.
                if target_language != source_language {
                    let Some(completion) = self.jvm_alias_surface_completion(
                        target_mount.fragment(),
                        &expected_owner,
                        imported_name,
                        ResolutionNamespace::Type,
                        cancellation,
                    )?
                    else {
                        return Ok(None);
                    };
                    if completion != ResolutionCompletion::Complete {
                        open_imports.push((expected_owner.join("."), completion));
                    }
                }
                let mut aliases = connection.prepare_cached(SELECTED_JVM_ALIASES_BY_BLOB)?;
                let aliases = aliases
                    .query_map([target_record.blob_id()], |row| {
                        Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for (alias_id, status) in aliases {
                    let mut segments = connection.prepare_cached(
                        "SELECT spelling FROM main.resolution_jvm_alias_owner_segments
                         WHERE blob_id=?1 AND alias=?2 ORDER BY ordinal",
                    )?;
                    let owner = segments
                        .query_map(
                            rusqlite::params![target_record.blob_id(), alias_id],
                            |row| row.get::<_, String>(0),
                        )?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    if owner == expected_owner && status != "source_proven" {
                        open_imports
                            .push((expected_owner.join("."), ResolutionCompletion::Complete));
                    }
                }
            }
        }
        open_imports.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut result: Vec<(String, ResolutionCompletion)> = Vec::new();
        for (owner, completion) in open_imports {
            if let Some((previous_owner, previous_completion)) = result.last_mut()
                && previous_owner == &owner
            {
                *previous_completion = previous_completion.combine(&completion);
            } else {
                result.push((owner, completion));
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(result))
    }

    fn jvm_boundary_access(
        &self,
        boundary: &brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary<
            SemanticId,
        >,
        caller: JvmDeclarationAccessContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<crate::analyzer::resolution::DeclarationAccessDecision> {
        use crate::analyzer::resolution::DeclarationAccessDecision;
        use brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary;
        let typed = self.ready.typed_source();
        let lexical = self.ready.lexical_source();
        let mut templates = Vec::new();
        let mut known = false;
        if let DeclarationAccessBoundary::Template(_) = boundary {
            let mut reference = caller.reference;
            if reference.is_none()
                && let Some(node) = caller.source_node
            {
                let Some(rows) = self.jvm_endpoint_classifications(node, cancellation)? else {
                    return Ok(DeclarationAccessDecision::Unknown);
                };
                reference = rows.iter().find_map(|row| row.reference());
            }

            if let Some(token) = caller.import_token
                && let (Some(ordinal), Some(key)) = (token.ordinal(), token.local_key())
            {
                let mount = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                // Import-token positions and declaration spans are canonical
                // source facts. Exact type-body ownership selects the authored
                // template, including locals without an indexed CodeUnit.
                let mut statement = self.ready.inventory.connection().prepare_cached(
                        "SELECT semantic.semantic_key
                         FROM main.resolution_semantic_catalog AS token
                         CROSS JOIN main.source_declarations AS source ON source.blob_id=token.blob_id
                         CROSS JOIN main.source_scala_declarations AS template
                           ON template.blob_id=source.blob_id AND template.declaration_id=source.declaration_id AND template.kind IN (1,2,3,4)
                         CROSS JOIN main.source_native_declaration_bridges AS bridge ON bridge.blob_id=source.blob_id AND bridge.declaration_id=source.declaration_id
                         CROSS JOIN main.resolution_semantic_sites AS semantic ON semantic.blob_id=bridge.blob_id AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition'
                         WHERE token.blob_id=?1 AND token.local_key=?2 AND token.import_start_byte IS NOT NULL
                           AND source.name_occurrence_id IS NOT NULL
                           AND source.start_byte <= token.import_start_byte AND source.end_byte >= token.import_end_byte
                           AND EXISTS (SELECT 1 FROM main.resolution_member_scope_properties AS body
                             WHERE body.blob_id=semantic.blob_id AND body.definition_semantic_key=semantic.semantic_key AND body.scope_kind='type_body')"
                    )?;
                let owners = statement
                    .query_map(rusqlite::params![mount.blob_id(), key], |row| {
                        row.get::<_, u32>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                known = true;
                templates.extend(
                    owners
                        .into_iter()
                        .map(|key| SemanticId::local(ordinal, key)),
                );
            } else if let Some(reference) = reference {
                let Some(endpoints) = typed.jvm_access_endpoints(&[reference], cancellation)?
                else {
                    return Ok(DeclarationAccessDecision::Unknown);
                };
                for endpoint in endpoints {
                    known = true;
                    templates.extend(endpoint.enclosing_templates);
                }
            } else if let Some(scope_head) = caller.scope_head {
                let owners = lexical.scope_owners_for_heads(&[scope_head], cancellation)?;
                let definitions = owners
                    .iter()
                    .map(|owner| owner.definition())
                    .collect::<Vec<_>>();
                let Some(endpoints) = typed.jvm_access_endpoints(&definitions, cancellation)?
                else {
                    return Ok(DeclarationAccessDecision::Unknown);
                };
                for endpoint in endpoints {
                    known = true;
                    if owners.iter().any(|owner| {
                        owner.definition() == endpoint.semantic && owner.is_type_body()
                    }) {
                        templates.push(endpoint.semantic);
                    }
                    templates.extend(endpoint.enclosing_templates);
                }
            }
        }
        let mut companions = crate::hash::HashSet::default();
        if let DeclarationAccessBoundary::Template(owner) = boundary {
            let requests = templates
                .iter()
                .copied()
                .chain(std::iter::once(*owner))
                .collect::<Vec<_>>();
            for chunk in requests.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                let outcome =
                    typed.visit_companion_relation_pages_for_enclosing_types(
                        TypedFactRequest::new(chunk),
                        cancellation,
                        &mut FactPageVisitor::new(&mut |page| {
                            companions.extend(page.iter().map(|row| {
                                (row.row().enclosing_type(), row.row().companion_type())
                            }));
                            Ok(true)
                        }),
                    )?;
                if outcome.is_cancelled()
                    || !outcome.is_exhausted()
                    || outcome.evidence() != &ResolutionCompletion::Complete
                {
                    return Ok(DeclarationAccessDecision::Unknown);
                }
            }
        }
        Ok(super::java_access::boundary_access_decision(
            boundary,
            caller.caller_package,
            known.then_some(templates.as_slice()),
            &companions,
        ))
    }

    fn jvm_bridge_visibility(
        &self,
        definition: SemanticId,
        package: JvmDeclarationAccessContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<Option<SelectedJvmBridgeVisibility>> {
        let Some(properties) = self.jvm_declaration_visibilities(definition, cancellation)? else {
            return Ok(None);
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let visibilities = properties
            .iter()
            .map(|row| row.visibility())
            .collect::<Vec<_>>();
        let boundaries = properties
            .iter()
            .filter_map(|row| row.boundary())
            .collect::<Vec<_>>();
        if let [boundary] = boundaries.as_slice() {
            use crate::analyzer::resolution::DeclarationAccessDecision;
            return Ok(
                match self.jvm_boundary_access(boundary, package, cancellation)? {
                    DeclarationAccessDecision::Allowed => Some(SelectedJvmBridgeVisibility::Scoped),
                    DeclarationAccessDecision::Denied
                        if visibilities == [DeclaredVisibility::Private] =>
                    {
                        None
                    }
                    _ => Some(SelectedJvmBridgeVisibility::Open),
                },
            );
        }
        Ok(match (visibilities.as_slice(), package.relation) {
            ([DeclaredVisibility::Public], _) => Some(SelectedJvmBridgeVisibility::Public),
            ([DeclaredVisibility::Protected], JvmPackageRelation::Same) => {
                Some(SelectedJvmBridgeVisibility::Protected)
            }
            ([DeclaredVisibility::PackagePrivate], JvmPackageRelation::Same) => {
                Some(SelectedJvmBridgeVisibility::Package)
            }
            ([DeclaredVisibility::Private], _)
            | (
                [DeclaredVisibility::Protected | DeclaredVisibility::PackagePrivate],
                JvmPackageRelation::Different,
            ) => None,
            _ => Some(SelectedJvmBridgeVisibility::Open),
        })
    }

    fn java_import_context_parts(
        &self,
        caller_path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let Some(prepared) =
            self.jvm_import_context_preparation(Language::Java, caller_path, cancellation)?
        else {
            return Ok(if cancellation.is_cancelled() {
                JvmImportContext::Cancelled
            } else {
                JvmImportContext::Unavailable
            });
        };
        let connection = self.ready.inventory.connection();
        let context_id = prepared.context_id;
        let source = &prepared.source;
        let family = nominal_package_rules(source.semantic_language())
            .expect("caller belongs to a nominal family");
        let source_record = &prepared.source_record;
        let file_version = source_record.file_version_id();
        let source_package = prepared.source_package.clone();
        let identities = self.ready.context_identities.clone();
        let evidence = "JVM selected source facts leave effective classpath, external artifacts, inherited imports and peer-language routes open";
        let mut descriptor =
            CanonicalIdentityDescriptor::new(b"bifrost-java-context-incomplete:v1", |key| {
                self.ready.identity_content_digest(key, cancellation)
            });
        descriptor.field(
            "context",
            CanonicalIdentityPart::Content(&source_record.fragment_digest().as_bytes()),
        )?;
        let reason =
            identities.named_semantic(descriptor.finish(), "java-context-incomplete", evidence);
        let completion = ResolutionCompletion::Complete;
        // Inventory uncertainty describes routes we have not enumerated. A
        // positive source bridge carries its own source/declaration access
        // evidence; unrelated inventory gaps must not taint that witness.
        let mut bridges = Vec::new();
        let mut external_static_imports = Vec::new();
        // All namespace demands of one import must close before its source
        // placeholder can retire. A found member is not an exhaustive search.
        let mut static_import_searches = BTreeMap::new();
        let mut open_jvm_alias_imports = Vec::new();
        let mut scoped_gaps = Vec::new();
        for binder in &prepared.binders {
            if lookup.is_some_and(|lookup| {
                binder.route.as_ref().is_some_and(|route| {
                    matches!(
                        route.kind,
                        SelectedImportRouteKind::SingleType | SelectedImportRouteKind::SingleStatic
                    )
                }) && binder
                    .recipes
                    .last()
                    .expect("an import has a demand")
                    .spelling()
                    != lookup
            }) {
                continue;
            }
            let import = binder.half.clone();
            let SelectedRootPathHalf::Import {
                identity,
                token,
                anchor,
                anchor_semantic,
                ..
            } = import
            else {
                continue;
            };
            let Some(import_route) = &binder.route else {
                continue;
            };
            let kind = import_route.kind;
            if !matches!(
                kind,
                SelectedImportRouteKind::SingleType
                    | SelectedImportRouteKind::TypeOnDemand
                    | SelectedImportRouteKind::SingleStatic
                    | SelectedImportRouteKind::StaticOnDemand
            ) {
                // Actual token provenance is required before composing an import.
                continue;
            }
            let import_kind = match kind {
                SelectedImportRouteKind::SingleType => ResolutionImportRouteKind::SingleType,
                SelectedImportRouteKind::TypeOnDemand => ResolutionImportRouteKind::TypeOnDemand,
                SelectedImportRouteKind::SingleStatic => ResolutionImportRouteKind::SingleStatic,
                SelectedImportRouteKind::StaticOnDemand => {
                    ResolutionImportRouteKind::StaticOnDemand
                }
                SelectedImportRouteKind::Named | SelectedImportRouteKind::Star => {
                    unreachable!("Java import kind was checked above")
                }
            };
            let mut recipes = binder.recipes.clone();
            let demand_recipe = recipes.pop().expect("one import demand");
            let cached = prepared.java_imports.get(&identity);
            let derived = if let Some(derived) = cached {
                derived
            } else {
                self.profile_jvm_read("derive_java_import", identity);
                let mut bridges = Vec::new();
                let mut external_static_imports = Vec::new();
                let mut static_import_searches = BTreeMap::new();
                let mut open_jvm_alias_imports = Vec::new();
                let mut scoped_gaps = Vec::new();
                'derive_java_import: {
                    let mut owner_found = false;
                    let member_import = JavaMemberImportDemand {
                        half: &binder.half,
                        import_kind: Some(import_kind),
                        caller_package: source_package.as_deref(),
                        source: source.fragment(),
                        token,
                        prefix_reference: None,
                        scope_head: None,
                        anchor,
                        anchor_semantic,
                        selector_kind: None,
                        import_precedence: None,
                        candidate_origin_rank: None,
                        route: &recipes,
                        lookup_route: &recipes,
                        demand: &demand_recipe,
                        language: Language::Java,
                    };
                    let Some(member_inventory) = self.jvm_type_member_import_candidates(
                        context_id,
                        file_version,
                        &member_import,
                        &ResolutionCompletion::Complete,
                        cancellation,
                        &mut owner_found,
                    )?
                    else {
                        return Ok(JvmImportContext::Cancelled);
                    };
                    let static_search_complete = if matches!(
                        import_kind,
                        ResolutionImportRouteKind::SingleStatic
                            | ResolutionImportRouteKind::StaticOnDemand
                    ) && owner_found
                    {
                        let Some(complete) = self.jvm_import_owners_declare_every_member(
                            Language::Java,
                            &member_inventory,
                            demand_recipe.spelling(),
                            cancellation,
                        )?
                        else {
                            return Ok(JvmImportContext::Cancelled);
                        };
                        complete
                            && member_inventory.route_search_complete
                            && !member_inventory.inherited_route_open
                    } else {
                        false
                    };
                    let member_route_complete = member_inventory.route_search_complete
                        && !member_inventory.inherited_route_open;
                    let JavaTypeMemberImportInventory {
                        members,
                        workspace_type_rows,
                        workspace_inventory_complete: member_inventory_complete,
                        ..
                    } = member_inventory;
                    match kind {
                        SelectedImportRouteKind::SingleStatic
                        | SelectedImportRouteKind::StaticOnDemand => {
                            let member = demand_recipe.spelling().to_string();
                            let Some(alias_import_bridges) = self.jvm_alias_import_bridges(
                                &member_import,
                                &member,
                                file_version,
                                source.persisted_relative_path(),
                                context_id,
                                cancellation,
                            )?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            let JvmAliasImportBridges {
                                bridges: alias_bridges,
                                open_imports: open_aliases,
                                found_alias: alias_route_found,
                                coverage_gaps,
                            } = alias_import_bridges;
                            scoped_gaps.extend(coverage_gaps);
                            if !owner_found && !alias_route_found {
                                let owner = recipes
                                    .iter()
                                    .map(ResolutionLookupSemanticRecipe::spelling)
                                    .collect::<Vec<_>>()
                                    .join(".");
                                if !owner.is_empty() {
                                    external_static_imports
                                        .push(JavaExternalStaticImportBoundary { member, owner });
                                }
                            }
                            let Some(static_members) =
                                self.java_static_import_bridges(members, cancellation)?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            let search_complete = static_search_complete
                                && open_aliases.is_empty()
                                && static_members.iter().chain(&alias_bridges).all(|bridge| {
                                    bridge.completion() == &ResolutionCompletion::Complete
                                });
                            let search = static_import_searches
                                .entry((import_route.source_site, import_route.staged))
                                .or_insert(JavaStaticImportSearch {
                                    source_site: import_route.source_site,
                                    staged: import_route.staged,
                                    complete: true,
                                    found: false,
                                    kind: import_kind,
                                });
                            search.complete &= search_complete;
                            search.found |= !static_members.is_empty() || !alias_bridges.is_empty();
                            bridges.extend(static_members);
                            bridges.extend(alias_bridges);
                            for open_alias in &open_aliases {
                                scoped_gaps.push(self.jvm_import_context_gap(
                            JvmImportContextGapSpec {
                                source: source.fragment(),
                                source_token: token,
                                source_reference: None,
                                kind: "jvm-import-alias-route-open",
                                owner: Some(open_alias.clone()),
                                lookup: demand_recipe.clone(),
                                detail: format!(
                                    "Java static alias route `{open_alias}` has compiler-dependent or unsupported provenance"
                                ),
                            },
                            cancellation,
                        )?);
                            }
                            open_jvm_alias_imports.extend(open_aliases);
                            break 'derive_java_import;
                        }
                        SelectedImportRouteKind::SingleType => {
                            let path = recipes
                                .iter()
                                .map(|recipe| recipe.spelling().to_owned())
                                .chain(std::iter::once(demand_recipe.spelling().to_owned()))
                                .collect::<Vec<_>>();
                            let Some(package_inventory) = self.java_package_type_import_inventory(
                                context_id,
                                file_version,
                                &JavaMemberImportDemand {
                                    half: &binder.half,
                                    import_kind: Some(import_kind),
                                    source: source.fragment(),
                                    caller_package: source_package.as_deref(),
                                    token,
                                    prefix_reference: None,
                                    scope_head: None,
                                    anchor,
                                    anchor_semantic,
                                    selector_kind: None,
                                    import_precedence: None,
                                    candidate_origin_rank: None,
                                    route: &recipes,
                                    lookup_route: &recipes,
                                    demand: &demand_recipe,
                                    language: Language::Java,
                                },
                                &ResolutionCompletion::Complete,
                                cancellation,
                            )?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            let mut workspace_type_rows = workspace_type_rows;
                            workspace_type_rows.extend(
                                members
                                    .iter()
                                    .filter(|member| member.workspace_source)
                                    .map(|member| (member.definition, member.unit.clone())),
                            );
                            workspace_type_rows
                                .extend(package_inventory.workspace_type_rows.iter().cloned());
                            // Mounts of the same blob retain distinct navigation
                            // identities. For this proof, the same blob-local
                            // declaration is one reading; different content stays
                            // distinct even when its canonical name is identical.
                            let mut seen_type_rows = crate::hash::HashSet::default();
                            let mut selected_types = Vec::new();
                            for (definition, unit) in workspace_type_rows {
                                let ordinal = SelectedResolutionMountOrdinal::new(
                                    definition
                                        .ordinal()
                                        .expect("selected Java type belongs to a mount"),
                                );
                                let record =
                                    self.ready.inventory.mount_record_by_ordinal(ordinal)?;
                                let key = definition
                                    .local_key()
                                    .expect("selected Java type has a blob-local key");
                                if seen_type_rows.insert((record.blob_id(), key)) {
                                    selected_types.push(unit);
                                }
                            }
                            let proof = prove_java_single_type_import_from_selected_rows(
                                &path,
                                &selected_types,
                                member_inventory_complete
                                    && package_inventory.workspace_inventory_complete,
                            );
                            let targets = match proof {
                                JavaSingleTypeImportProof::Proven(unit) => {
                                    if let Some(source_site) = import_route.source_site {
                                        for reason in selected_java_import_route_gap_reasons(
                                            &self.ready.inventory,
                                            source_record.blob_id(),
                                            source.ordinal(),
                                            source_site,
                                            import_route.staged,
                                        )? {
                                            identities.record_java_import_route_gap_reason(reason);
                                        }
                                    }
                                    vec![unit]
                                }
                                JavaSingleTypeImportProof::Open { gap, targets } => {
                                    if targets.is_empty()
                                        && gap == JavaImportSplitGap::MissingDestination
                                    {
                                        let owner = recipes
                                            .iter()
                                            .map(ResolutionLookupSemanticRecipe::spelling)
                                            .collect::<Vec<_>>()
                                            .join(".");
                                        let declared =
                                            format!("{owner}.{}", demand_recipe.spelling());
                                        let mut selected_packages = connection.prepare_cached(
                                            family.import_target_mounts().statement,
                                        )?;
                                        let mut selected_packages = selected_packages
                                            .query_map([&owner], |row| row.get::<_, u32>(0))?;
                                        let package_prefix_found =
                                            selected_packages.next().transpose()?.is_some();
                                        if !package_prefix_found
                                            && self.declares_jvm_type(Language::Java, &declared)?
                                        {
                                            let model_owner =
                                                self.declared_jvm_owner(Language::Java, &declared)?;
                                            let boundary =
                                                register_model_declared_jvm_type_identity(
                                                    self,
                                                    token,
                                                    &declared,
                                                    model_owner.as_ref(),
                                                    &identities,
                                                    &self.ready.shared_names(),
                                                )?;
                                            if let Some(source_site) = import_route.source_site {
                                                for reason in
                                                    selected_java_import_route_gap_reasons(
                                                        &self.ready.inventory,
                                                        source_record.blob_id(),
                                                        source.ordinal(),
                                                        source_site,
                                                        import_route.staged,
                                                    )?
                                                {
                                                    identities.record_java_import_route_gap_reason(
                                                        reason,
                                                    );
                                                }
                                            }
                                            if let Some(boundary) = boundary {
                                                let mut gap = self.jvm_import_context_gap(
                                        JvmImportContextGapSpec {
                                            source: source.fragment(),
                                            source_token: token,
                                            source_reference: None,
                                            kind: "jvm-model-declared-import",
                                            owner: Some(owner),
                                            lookup: demand_recipe.clone(),
                                            detail: format!(
                                                "Java import type `{declared}` is model-declared; its members remain limited to the reviewed model"
                                            ),
                                        },
                                        cancellation,
                                    )?;
                                                // The import proves the nominal owner. Only its
                                                // member enumeration remains an external boundary.
                                                gap.reason = boundary;
                                                gap.boundary_status = Some(
                                                crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                                            );
                                                scoped_gaps.push(gap);
                                            }
                                        } else if !package_prefix_found {
                                            let mut gap = self.jvm_import_context_gap(
                                        JvmImportContextGapSpec {
                                            source: source.fragment(),
                                            source_token: token,
                                            source_reference: None,
                                            kind: "jvm-import-owner-open",
                                            owner: Some(owner),
                                            lookup: demand_recipe.clone(),
                                            detail: format!(
                                                "Java import owner has no selected source or classpath route for `{}`",
                                                demand_recipe.spelling()
                                            ),
                                        },
                                        cancellation,
                                    )?;
                                            gap.boundary_status = Some(
                                        crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                                    );
                                            let identity = model_declared_jvm_type_identity(
                                                &declared,
                                                &self.ready.shared_names(),
                                            );
                                            identities.record_jvm_unindexed_import_owner(
                                                identity, &declared,
                                            );
                                            gap.nominal_type_identity = Some(identity);
                                            scoped_gaps.push(gap);
                                        }
                                    }
                                    targets
                                }
                            };
                            bridges.extend(
                                members
                                    .into_iter()
                                    .filter(|member| {
                                        member.workspace_source && targets.contains(&member.unit)
                                    })
                                    .map(|member| member.bridge),
                            );
                            bridges.extend(
                                package_inventory
                                    .candidates
                                    .into_iter()
                                    .filter(|candidate| {
                                        candidate.workspace_source
                                            && candidate
                                                .unit
                                                .as_ref()
                                                .is_some_and(|unit| targets.contains(unit))
                                    })
                                    .map(|candidate| candidate.bridge),
                            );
                            break 'derive_java_import;
                        }
                        SelectedImportRouteKind::TypeOnDemand => {
                            bridges.extend(members.into_iter().map(|member| member.bridge));
                        }
                        SelectedImportRouteKind::Named | SelectedImportRouteKind::Star => {
                            unreachable!("Java import kind was checked above")
                        }
                    }
                    let Some(package_inventory) = self.java_package_type_import_inventory(
                        context_id,
                        file_version,
                        &JavaMemberImportDemand {
                            half: &binder.half,
                            import_kind: Some(import_kind),
                            source: source.fragment(),
                            caller_package: source_package.as_deref(),
                            token,
                            prefix_reference: None,
                            scope_head: None,
                            anchor,
                            anchor_semantic,
                            selector_kind: None,
                            import_precedence: None,
                            candidate_origin_rank: None,
                            route: &recipes,
                            lookup_route: &recipes,
                            demand: &demand_recipe,
                            language: Language::Java,
                        },
                        &ResolutionCompletion::Complete,
                        cancellation,
                    )?
                    else {
                        return Ok(JvmImportContext::Cancelled);
                    };
                    bridges.extend(
                        package_inventory
                            .candidates
                            .into_iter()
                            .take(1)
                            .map(|candidate| candidate.bridge),
                    );
                    if kind == SelectedImportRouteKind::TypeOnDemand
                        && member_route_complete
                        && package_inventory.route_inventory_complete
                        && let Some(source_site) = import_route.source_site
                    {
                        for reason in selected_java_import_route_gap_reasons(
                            &self.ready.inventory,
                            source_record.blob_id(),
                            source.ordinal(),
                            source_site,
                            import_route.staged,
                        )? {
                            identities.record_java_import_route_gap_reason(reason);
                        }
                    }
                }
                if cancellation.is_cancelled() {
                    return Ok(JvmImportContext::Cancelled);
                }
                let derived = Arc::new(JavaDerivedImport {
                    bridges,
                    external_static_imports,
                    static_import_searches,
                    open_jvm_alias_imports,
                    scoped_gaps,
                });
                prepared.java_imports.insert(identity, Arc::clone(&derived));
                derived
            };
            bridges.extend(derived.bridges.iter().cloned());
            external_static_imports.extend(derived.external_static_imports.iter().cloned());
            open_jvm_alias_imports.extend(derived.open_jvm_alias_imports.iter().cloned());
            scoped_gaps.extend(derived.scoped_gaps.iter().cloned());
            for (&key, search) in &derived.static_import_searches {
                let combined = static_import_searches
                    .entry(key)
                    .or_insert_with(|| search.clone());
                combined.complete &= search.complete;
                combined.found |= search.found;
            }
        }
        let package_references = match lookup {
            Some(name) => prepared
                .references_by_name
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            None => prepared.package_references.as_slice(),
        };
        let mut package_candidates = Vec::new();
        for package in source_package.iter() {
            let planned = prepared
                .package_plan
                .get(package)
                .expect("file preparation plans its own package");
            let mut candidate_references = Vec::new();
            for (position, reference) in package_references.iter().enumerate() {
                for candidate in planned
                    .candidates
                    .get(&reference.lookup)
                    .into_iter()
                    .flatten()
                {
                    candidate_references.push((candidate.order, position, reference, candidate));
                }
            }
            // Keep the old target-then-reference order while reading only
            // candidates present in the invariant file plan.
            candidate_references.sort_by_key(|(order, position, _, _)| (*order, *position));
            for (_, _, reference, candidate) in candidate_references {
                if cancellation.is_cancelled() {
                    return Ok(JvmImportContext::Cancelled);
                }
                let ordinal = candidate.mount;
                if ordinal == source.ordinal() {
                    continue;
                }
                let target_mount = self.mount_table().mount_by_ordinal(ordinal)?;
                // This hook's package peers are Java-only; mixed-language
                // imports continue through the separate JVM bridge proof.
                if !nominal_language_rules(source.semantic_language())
                    .expect("caller belongs to a nominal family")
                    .package_peer_languages()
                    .contains(&target_mount.semantic_language())
                {
                    continue;
                }
                let Some(access) = self.jvm_unit_access_completion(
                    source.semantic_language(),
                    context_id,
                    file_version,
                    source.persisted_relative_path(),
                    candidate.version,
                    target_mount.persisted_relative_path(),
                    &ResolutionCompletion::Complete,
                )?
                else {
                    continue;
                };
                package_candidates.push(JavaPackageBridgeCandidate {
                    reference,
                    candidate,
                    target: target_mount,
                    access,
                });
            }
        }
        let pairs = package_candidates.iter().flat_map(|candidate| {
            candidate
                .candidate
                .members
                .iter()
                .map(move |member| PackageBridgePair {
                    reference: candidate.reference,
                    member,
                    target_fragment: candidate.target.fragment(),
                    target_mount: candidate.target.ordinal(),
                    extra: candidate,
                })
        });
        let assembly = assemble_package_bridges(
            &self.ready,
            pairs,
            &JavaPackageBridgeRules {
                operation: self,
                source,
                caller_package: source_package.as_deref(),
            },
            cancellation,
        )?;
        if assembly
            .completion
            .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(JvmImportContext::Cancelled);
        }
        let package_bridges = assembly.descriptors;
        for search in static_import_searches.into_values() {
            if search.complete
                && (search.found || search.kind == ResolutionImportRouteKind::StaticOnDemand)
                && let Some(source_site) = search.source_site
            {
                for reason in selected_java_import_route_gap_reasons(
                    &self.ready.inventory,
                    source_record.blob_id(),
                    source.ordinal(),
                    source_site,
                    search.staged,
                )? {
                    identities.record_java_import_route_gap_reason(reason);
                }
            }
        }
        // An indexed same-named member from another import cannot close this
        // exact unavailable owner. Keep each boundary scoped to its own route.
        let mount = SelectedResolutionMountContext::new(
            source.ordinal(),
            source.fragment(),
            Language::Java,
            bridges,
            completion,
        )?
        .with_package_bridges(package_bridges)?;
        let mounts = self.mount_table();
        let context = SelectedResolutionContextSet::new(
            identities,
            vec![mount],
            mounts.mount_count(),
            &selected_mount_lookup(mounts),
        )?
        .with_callable_imports(
            source.semantic_language(),
            prepared.binders.iter().map(|binder| &binder.half),
            &self.ready.lexical_source(),
            cancellation,
        )?;
        let access_identity = self.ready.context_identities.named_semantic(
            CanonicalHasher::new(b"java-selected-declaration-access:v1").finish(),
            "java-selected-declaration-access",
            "Java declaration visibility under exact selected package and lexical ownership",
        );
        external_static_imports
            .sort_by(|left, right| (&left.member, &left.owner).cmp(&(&right.member, &right.owner)));
        external_static_imports.dedup();
        Ok(JvmImportContext::Ready {
            context: Box::new(context.with_declaration_access_source(
                self.jvm_declaration_access_source(access_identity),
            )),
            external_static_imports,
            inventory_reason: Some(reason),
            open_jvm_alias_imports,
            scoped_gaps,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn jvm_unit_access_completion(
        &self,
        language: Language,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ResolutionCompletion>> {
        self.profile_jvm_read(
            "source_access",
            (context, caller, caller_path, target, target_path),
        );
        // The JVM's unit identity is its implicit project context; this is its digest.
        let mut unit_hash = CanonicalHasher::new(b"bifrost-jvm-placement-unit:v1");
        unit_hash.field("context", &context.to_le_bytes());
        let unit_digest = unit_hash.finish();
        let placement = |version, path| PlacementKey {
            language,
            unit_digest,
            subject: PlacementSubject {
                blob: None,
                path: Some(self.jvm_source_path_id(path)),
                file_version: version,
            },
            declaration: None,
        };
        let caller_key = placement(caller, caller_path);
        let target_key = placement(target, target_path);
        let rules = JvmUnitAccessRules {
            operation: self,
            context,
            caller_path,
            target_path,
        };
        let access = read_unit_access(
            &self.ready.inventory,
            &rules,
            &[caller_key],
            &[target_key],
            Some(&mut self.jvm_source_access_memo.borrow_mut()),
        )?;
        self.profile_jvm_read(
            "unit_access_memo_entries",
            self.jvm_source_access_memo.borrow().entry_count(),
        );
        Ok(access.completion(completion))
    }

    fn jvm_implicit_project_key(
        &self,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
    ) -> JvmImplicitProjectKey {
        JvmImplicitProjectKey {
            context,
            caller,
            caller_path: self.jvm_source_path_id(caller_path),
            target,
            target_path: self.jvm_source_path_id(target_path),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        }
    }

    fn jvm_source_path_id(&self, path: &str) -> usize {
        let mut paths = self.jvm_source_paths.borrow_mut();
        if let Some(id) = paths.get(path) {
            return *id;
        }
        let id = paths.len();
        paths.insert(path.to_owned(), id);
        id
    }

    #[allow(clippy::too_many_arguments)]
    fn jvm_qualified_source_access_completion(
        &self,
        language: Language,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ResolutionCompletion>> {
        if nominal_language_rules(language)
            .expect("access caller belongs to a nominal family")
            .has_implicit_project_access()
            && !self
                .jvm_implicit_project_context(context)?
                .has_selected_project
            && self.in_implicit_project(context, caller, caller_path, target, target_path)?
        {
            return Ok(Some(completion.clone()));
        }
        self.jvm_unit_access_completion(
            language,
            context,
            caller,
            caller_path,
            target,
            target_path,
            completion,
        )
    }

    /// Whether an indexed artifact, reviewed model, or language-defined root
    /// declares this type. Fixed roots fill unavailable detail only when an
    /// indexed provider has not already supplied its own inventory.
    fn declares_jvm_type(&self, language: Language, fqn: &str) -> Result<bool> {
        if self
            .ready
            .analyzer
            .and_then(|analyzer| analyzer.model_authority())
            .is_some_and(|overlay| overlay.declares_jvm_type(fqn))
        {
            return Ok(true);
        }
        Ok(self.declared_jvm_owner(language, fqn)?.is_some())
    }

    fn declared_jvm_owner(
        &self,
        language: Language,
        fqn: &str,
    ) -> Result<Option<crate::analyzer::resolution::ExternalOwnerIdentity>> {
        let intrinsic = || {
            brokk_bifrost_jvm::intrinsics::language_has_member_inventory(language, fqn).then(|| {
                crate::analyzer::resolution::ExternalOwnerIdentity {
                    provider_id: std::sync::Arc::from("jvm-intrinsic"),
                    owner_fqn: std::sync::Arc::from(fqn),
                }
            })
        };
        let authority = self
            .ready
            .analyzer
            .and_then(|analyzer| analyzer.model_authority());
        let relations = nominal_language_rules(language)
            .expect("caller belongs to a nominal family")
            .family()
            .external_owners();
        let providers = relations.providers(self.ready.analyzer);
        Ok(super::selected_jvm_declaration_owner(
            relations,
            self.ready.inventory.connection(),
            authority.as_deref(),
            &providers,
            fqn,
        )?
        .unwrap_or_else(intrinsic))
    }

    /// Prove a conventional visibility-domain relation between two selected
    /// source mounts. Unrelated roots never form one implicit workspace project.
    fn in_implicit_project(
        &self,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
    ) -> Result<bool> {
        self.profile_jvm_read(
            "implicit_project",
            (context, caller, caller_path, target, target_path),
        );
        let key = self.jvm_implicit_project_key(context, caller, caller_path, target, target_path);
        Ok(self
            .jvm_implicit_project_memo
            .read(key, |key| {
                self.profile_jvm_read("derive_implicit_project", key);
                self.read_jvm_implicit_project(context, caller, caller_path, target, target_path)
                    .map(Some)
            })?
            .expect("implicit project proof is always derived"))
    }

    fn jvm_implicit_project_context(&self, context: i64) -> Result<JvmImplicitProjectContext> {
        let key = (
            context,
            self.ready.inventory.scope_identity(),
            self.ready.inventory.staged_read_epoch(),
        );
        Ok(self.jvm_implicit_project_contexts.read(key, |key| {
        self.profile_jvm_read("derive_implicit_project_context", key);
        let connection = self.ready.inventory.connection();
        let (has_selected_project, context_language): (bool, String) = connection.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM main.jvm_selected_projects WHERE context_id=?1),
                    (SELECT lang FROM main.jvm_context_revisions WHERE context_id=?1)",
        )?.query_row([context], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let language = Language::from_config_label(&context_language)
            .expect("selected JVM context has a known language");
        let fact = JvmImplicitProjectContext {
            has_selected_project,
            language,
        };
        Ok(Some(fact))
        })?.expect("implicit project context is always derived"))
    }

    fn read_jvm_implicit_project(
        &self,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
    ) -> Result<bool> {
        let caller = self.jvm_source_domain(context, caller, caller_path)?;
        let target = self.jvm_source_domain(context, target, target_path)?;
        Ok(matches!((caller, target), (Some(caller), Some(target)) if caller.can_access(&target)))
    }

    /// Derive each demanded file's domain once for the exact selected inputs.
    /// Both present and absent evidence die with this operation.
    fn jvm_source_domain(
        &self,
        context: i64,
        file_version: Option<i64>,
        path: &str,
    ) -> Result<Option<Arc<crate::analyzer::store::maven::JvmSourceDomain>>> {
        let key = JvmSourceDomainKey {
            context,
            file_version,
            path: self.jvm_source_path_id(path),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        Ok(self
            .jvm_source_domains
            .read(key, |_| {
                self.read_jvm_source_domain(context, file_version, path)
                    .map(|domain| Some(domain.map(Arc::new)))
            })?
            .expect("source domain derivation includes absent evidence"))
    }

    fn read_jvm_source_domain(
        &self,
        context: i64,
        file_version: Option<i64>,
        path: &str,
    ) -> Result<Option<crate::analyzer::store::maven::JvmSourceDomain>> {
        use crate::analyzer::store::maven::JvmSourceDomain;
        let query_language = self.jvm_implicit_project_context(context)?.language;
        let rows = read_placement_rows(
            &self.ready.inventory,
            nominal_language_rules(query_language)
                .expect("source-domain caller belongs to a nominal family")
                .family()
                .source_domain_sql(),
            rusqlite::params![path, file_version],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut domain = None;
        for (package, language) in rows {
            let Some(package) = package else {
                return Ok(None);
            };
            let language = Language::from_config_label(&language)
                .expect("selected JVM mount has a known language");
            let requires_directory =
                language_jvm_package_requires_directory_agreement(query_language, language);
            let candidate =
                JvmSourceDomain::discover(std::path::Path::new(path), &package, requires_directory);
            if candidate.is_none()
                || domain
                    .as_ref()
                    .is_some_and(|domain| Some(domain) != candidate.as_ref())
            {
                return Ok(None);
            }
            domain = candidate;
        }
        Ok(domain)
    }

    fn jvm_declaration_access(
        &self,
        definition: SemanticId,
        package: JvmDeclarationAccessContext<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<JvmDeclarationAccess> {
        let Some(properties) = self.jvm_declaration_visibilities(definition, cancellation)? else {
            return Ok(JvmDeclarationAccess::Cancelled);
        };
        if cancellation.is_cancelled() {
            return Ok(JvmDeclarationAccess::Cancelled);
        }
        let mut visibilities = properties
            .iter()
            .map(|row| row.visibility())
            .collect::<Vec<_>>();
        let boundaries = properties
            .iter()
            .filter_map(|row| row.boundary())
            .collect::<Vec<_>>();
        if let [boundary] = boundaries.as_slice() {
            use crate::analyzer::resolution::DeclarationAccessDecision;
            match self.jvm_boundary_access(boundary, package, cancellation)? {
                DeclarationAccessDecision::Allowed => {
                    return Ok(JvmDeclarationAccess::Ready(completion.clone()));
                }
                DeclarationAccessDecision::Denied
                    if visibilities == [DeclaredVisibility::Private] =>
                {
                    return Ok(JvmDeclarationAccess::Excluded);
                }
                _ if visibilities == [DeclaredVisibility::Protected] => {
                    let caller_ordinal = package
                        .reference
                        .or(package.import_token)
                        .and_then(SemanticId::ordinal)
                        .or_else(|| package.source_node.and_then(BindingNodeId::ordinal))
                        .or_else(|| package.scope_head.and_then(BindingNodeId::ordinal));
                    if let Some(ordinal) = caller_ordinal
                        && nominal_language_rules(
                            self.ready
                                .inventory
                                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(
                                    ordinal,
                                ))?
                                .semantic_language(),
                        )
                        .is_some_and(|rules| {
                            rules
                                .declaration_access_rules()
                                .contextual_visibility_without_gap()
                        })
                    {
                        // The Scala route remains subject to shared subclass
                        // refinement. An unrelated import gap would survive
                        // that exact access decision. Cross-language bridges
                        // still carry open visibility evidence below.
                        return Ok(JvmDeclarationAccess::Ready(completion.clone()));
                    }
                    visibilities.clear();
                }
                _ => visibilities.clear(),
            }
        }
        let known = match (visibilities.as_slice(), package.relation) {
            ([DeclaredVisibility::Public], _) => true,
            // Imports are outside a subclass body, so protected access cannot
            // authorize a cross-package import even when a declared class in
            // the caller later extends the member's owner.
            (
                [DeclaredVisibility::PackagePrivate | DeclaredVisibility::Protected],
                JvmPackageRelation::Different,
            )
            | ([DeclaredVisibility::Private], _) => return Ok(JvmDeclarationAccess::Excluded),
            (
                [DeclaredVisibility::PackagePrivate | DeclaredVisibility::Protected],
                JvmPackageRelation::Same,
            ) => true,
            _ => false,
        };
        if known {
            return Ok(JvmDeclarationAccess::Ready(completion.clone()));
        }
        let gap = self.ready.context_identities.named_semantic(
            CanonicalHasher::new(b"java-import-declaration-visibility-open:v1").finish(),
            "java-import-declaration-visibility-open",
            "Selected declaration visibility does not establish import access",
        );
        Ok(JvmDeclarationAccess::Ready(completion.combine(
            &ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                gap,
            )]),
        )))
    }
}

/// A route that contributed no bridge can recur later in the same import
/// half. Its inputs and selection are fixed during that half's construction.
/// Preserve append and last-writer effects at every occurrence; monotone flags
/// already retain the first visit's contribution.
#[derive(Default)]
struct JvmImportLookupRouteMissMemo {
    misses: HashMap<Vec<ResolutionLookupSemanticRecipe>, JvmImportLookupRouteMiss>,
}

struct JvmImportLookupRouteMiss {
    wildcard: bool,
    aliases: Vec<String>,
    gaps: Vec<JvmImportContextGap>,
}

impl JvmImportLookupRouteMissMemo {
    fn replay(
        &self,
        route: &[ResolutionLookupSemanticRecipe],
        wildcard: &mut Option<Vec<ResolutionLookupSemanticRecipe>>,
        aliases: &mut Vec<String>,
        gaps: &mut Vec<JvmImportContextGap>,
    ) -> bool {
        let Some(miss) = self.misses.get(route) else {
            return false;
        };
        if miss.wildcard {
            *wildcard = Some(route.to_vec());
        }
        aliases.extend_from_slice(&miss.aliases);
        gaps.extend_from_slice(&miss.gaps);
        true
    }

    fn record(
        &mut self,
        route: Vec<ResolutionLookupSemanticRecipe>,
        wildcard: bool,
        aliases: Vec<String>,
        gaps: Vec<JvmImportContextGap>,
    ) {
        let previous = self.misses.insert(
            route,
            JvmImportLookupRouteMiss {
                wildcard,
                aliases,
                gaps,
            },
        );
        debug_assert!(previous.is_none(), "an import route miss is computed once");
    }
}

fn jvm_single_type_import(binder: &ImportBinder) -> bool {
    binder.selector.is_none()
        && binder.route.as_ref().map(|route| route.kind)
            == Some(SelectedImportRouteKind::SingleType)
}

fn jvm_imports_for_name(
    language: Language,
    imports: &[ImportBinder],
    lookup: &str,
    qualifier_names: Option<&HashSet<String>>,
) -> HashSet<CandidatePathIdentity> {
    let mut retained = HashSet::default();
    let mut worklist = imports
        .iter()
        .enumerate()
        .filter_map(|(index, import)| {
            (import.bound.is_none()
                || import.bound.as_deref() == Some(lookup)
                || import.imported.as_deref() == Some(lookup)
                || qualifier_names.is_some_and(|names| {
                    import
                        .bound
                        .as_ref()
                        .is_some_and(|bound| names.contains(bound))
                        || import
                            .imported
                            .as_ref()
                            .is_some_and(|name| names.contains(name))
                }))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    for &index in &worklist {
        retained.insert(imports[index].identity);
    }
    while let Some(index) = worklist.pop() {
        for dependency in jvm_import_dependency_indices(language, imports, index) {
            if retained.insert(imports[dependency].identity) {
                worklist.push(dependency);
            }
        }
    }
    debug_assert!(retained.len() <= imports.len());
    retained
}

/// Java and Kotlin import owners are fully qualified. Scala permits earlier
/// bindings in the same import scope to supply a lexical route head. Keep all
/// possible earlier bindings here; the existing ordered owner-proof pass decides
/// which binding actually supplies that head.
fn jvm_import_dependency_indices(
    language: Language,
    imports: &[ImportBinder],
    index: usize,
) -> Vec<usize> {
    if !nominal_language_rules(language)
        .expect("caller belongs to a nominal family")
        .lexical_import_anchors()
        .contains(&ResolutionRootImportAnchor::Lexical)
        || imports[index].anchor != ResolutionRootImportAnchor::Lexical
    {
        return Vec::new();
    }
    let import = &imports[index];
    imports[..index]
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            (candidate.scope == import.scope
                && candidate.activation != import.activation
                && candidate.bound.as_deref() == Some(import.head.as_str()))
            .then_some(index)
        })
        .collect()
}

/// The routes the selected sources are searched for an import route, in
/// order. An import names its route as written. Scala also reads a route
/// relative to the package the file is in first, because a package member
/// outranks a root package of the same name; the written route follows for a
/// route no package member starts.
fn jvm_import_lookup_routes(
    language: Language,
    anchor: ResolutionRootImportAnchor,
    lexical_prefixes: &[String],
    route: &[ResolutionLookupSemanticRecipe],
    earlier_route: Option<&[ResolutionLookupSemanticRecipe]>,
    enclosing_scope_routes: &[Vec<ResolutionLookupSemanticRecipe>],
    chained_wildcard_routes: &[Vec<ResolutionLookupSemanticRecipe>],
) -> Vec<Vec<ResolutionLookupSemanticRecipe>> {
    let rules = nominal_language_rules(language).expect("caller belongs to a nominal family");
    let mut routes = Vec::with_capacity(3 + enclosing_scope_routes.len());
    if rules
        .lexical_import_anchors()
        .contains(&ResolutionRootImportAnchor::Lexical)
        && anchor == ResolutionRootImportAnchor::Lexical
    {
        if let Some(earlier_route) = earlier_route {
            routes.push(earlier_route.to_vec());
        }
        routes.extend(enclosing_scope_routes.iter().cloned());
    }
    if rules
        .lexical_import_anchors()
        .contains(&ResolutionRootImportAnchor::Lexical)
        && anchor == ResolutionRootImportAnchor::Lexical
    {
        let written = route
            .iter()
            .map(ResolutionLookupSemanticRecipe::spelling)
            .collect::<Vec<_>>()
            .join(".");
        routes.extend(
            brokk_bifrost_jvm::scala::wildcard_imports::scala_import_path_candidates(
                &written,
                lexical_prefixes,
            )
            .into_iter()
            .filter(|candidate| candidate != &written)
            .map(|candidate| {
                // Only the stored package-prefix value is dotted. Preserve
                // the written route's AST segment boundaries and namespaces.
                let prefix = candidate
                    .strip_suffix(&written)
                    .and_then(|prefix| prefix.strip_suffix('.'))
                    .expect("a relative candidate prepends a package to the written route");
                let mut relative = prefix
                    .split('.')
                    .map(|segment| {
                        ResolutionLookupSemanticRecipe::new(
                            language,
                            ResolutionNamespace::Type,
                            segment,
                        )
                    })
                    .collect::<Vec<_>>();
                relative.extend(route.iter().cloned());
                relative
            }),
        );
    }
    // A member supplied by the file's own package outranks a member imported
    // from a wildcard. Keep chained wildcard routes after this package read;
    // only a fully consumed owner supplies the imported member.
    if rules
        .lexical_import_anchors()
        .contains(&ResolutionRootImportAnchor::Lexical)
        && anchor == ResolutionRootImportAnchor::Lexical
    {
        routes.extend(chained_wildcard_routes.iter().cloned());
    }
    routes.push(route.to_vec());
    routes
}

fn selected_java_import_route_gap_reasons(
    inventory: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    blob_id: i64,
    source: SelectedResolutionMountOrdinal,
    source_site: ResolutionSiteId,
    staged: bool,
) -> Result<Vec<SemanticId>> {
    let connection = inventory.connection();
    if staged
        && inventory
            .stage_family_is_globally_empty(super::super::resolution_stage::StageFamily::Gaps)?
    {
        return Ok(Vec::new());
    }
    let origin = crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
        crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            ResolutionGapKind::UnsupportedRoute,
        ),
    );
    let reasons = if staged {
        let mut statement = connection.prepare_cached(
            "SELECT DISTINCT reason_key FROM temp.selected_resolution_stage_gaps
             WHERE host_ordinal=?1 AND source_site=?2 AND origin=?3 ORDER BY reason_key",
        )?;
        statement
            .query_map(
                rusqlite::params![source.get(), source_site.get(), origin],
                |row| {
                    Ok(super::super::resolution_stage::codec::decode_semantic(
                        row.get(0)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        let mut statement = connection.prepare_cached(
            "SELECT reason FROM main.resolution_gap_reasons
             WHERE blob_id=?1 AND site=?2 AND origin=?3 ORDER BY reason",
        )?;
        statement
            .query_map(
                rusqlite::params![blob_id, source_site.get(), origin],
                |row| {
                    let key = u32::try_from(row.get::<_, i64>(0)?)
                        .expect("a source gap reason key fits u32");
                    Ok(SemanticId::local(source.get(), key))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for reason in &reasons {
        assert_eq!(
            reason.ordinal(),
            Some(source.get()),
            "a Java import-site route gap is source-local"
        );
    }
    Ok(reasons)
}

/// JLS name classification does not select a member or close its hierarchy.
/// Java's typed member resolver owns those independent claims.
pub(super) fn jvm_prefix_defers_member_selection(language: Language) -> bool {
    nominal_language_rules(language).is_some_and(|rules| rules.has_typed_prefix_deferral())
}

fn member_namespace(kind: ResolutionMemberKind) -> Option<ResolutionNamespace> {
    match kind {
        ResolutionMemberKind::NestedType | ResolutionMemberKind::AssociatedType => {
            Some(ResolutionNamespace::Type)
        }
        ResolutionMemberKind::Method | ResolutionMemberKind::Constructor => {
            Some(ResolutionNamespace::Callable)
        }
        ResolutionMemberKind::Field => Some(ResolutionNamespace::Value),
    }
}

fn jvm_dependency_identity(
    context: i64,
    caller: Option<i64>,
    caller_path: &str,
    target: Option<i64>,
    target_path: &str,
) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-selected-dependency:v1");
    hash.field("context", &context.to_le_bytes());
    if let Some(caller) = caller {
        hash.field("caller-version", &caller.to_le_bytes());
    }
    hash.field("caller-path", caller_path.as_bytes());
    if let Some(target) = target {
        hash.field("target-version", &target.to_le_bytes());
    }
    hash.field("target-path", target_path.as_bytes());
    hash.finish()
}

fn jvm_package_route_identity(
    source_language: Language,
    target_language: Language,
    package: &str,
    reference: &crate::analyzer::resolution::LoweredPackageReference,
    target_mount_digest: [u8; 32],
    resolve: impl FnMut(ResolutionIdentityDigestKey) -> Result<[u8; 32]>,
) -> Result<[u8; 32]> {
    let mut descriptor =
        CanonicalIdentityDescriptor::new(b"bifrost-jvm-package-import-route:v2", resolve);
    descriptor.field(
        "source-language",
        CanonicalIdentityPart::Label(source_language.config_label()),
    )?;
    descriptor.field(
        "target-language",
        CanonicalIdentityPart::Label(target_language.config_label()),
    )?;
    descriptor.field(
        "package",
        CanonicalIdentityPart::Content(package.as_bytes()),
    )?;
    descriptor.field(
        "source-token",
        CanonicalIdentityPart::identity(reference.token),
    )?;
    descriptor.field(
        "source-lookup",
        CanonicalIdentityPart::identity(reference.lookup),
    )?;
    descriptor.field(
        "target-mount",
        CanonicalIdentityPart::Content(&target_mount_digest),
    )?;
    Ok(descriptor.finish())
}

fn jvm_singleton_route_identity(
    singleton: SemanticId,
    member: SemanticId,
    source_language: Language,
    resolve: impl FnMut(ResolutionIdentityDigestKey) -> Result<[u8; 32]>,
) -> Result<[u8; 32]> {
    let mut descriptor =
        CanonicalIdentityDescriptor::new(b"bifrost-jvm-singleton-import-route:v1", resolve);
    descriptor.field(
        "source-language",
        CanonicalIdentityPart::Label(source_language.config_label()),
    )?;
    descriptor.field("singleton", CanonicalIdentityPart::identity(singleton))?;
    descriptor.field("member", CanonicalIdentityPart::identity(member))?;
    descriptor.field(
        "predef",
        CanonicalIdentityPart::Content(SCALA_PREDEF_DEFAULT_IMPORT.as_bytes()),
    )?;
    Ok(descriptor.finish())
}

fn jvm_implicit_provider_gap_matches(
    gap: &JvmImportContextGap,
    provider: JvmImplicitRootProvider,
) -> bool {
    match provider {
        JvmImplicitRootProvider::Package(package) => {
            gap.kind == "jvm-default-import-package-open" && gap.owner.as_deref() == Some(package)
        }
        JvmImplicitRootProvider::ScalaPredef => {
            gap.kind == "scala-predef-route-open"
                && gap.owner.as_deref() == Some(SCALA_PREDEF_DEFAULT_IMPORT)
        }
    }
}

fn jvm_external_provider_type_identity(
    providers: &[JvmImplicitRootProvider],
    spelling: &str,
    names: &dyn SharedNameInterner,
) -> SemanticId {
    SemanticId::shared_name(names.intern(jvm_external_provider_type_content(providers, spelling)))
}

fn jvm_external_provider_type_content(
    providers: &[JvmImplicitRootProvider],
    spelling: &str,
) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-external-provider-type-identity:v1");
    hash.field(
        "provider-count",
        &u64::try_from(providers.len())
            .expect("the implicit provider count fits u64")
            .to_be_bytes(),
    );
    hash.sequence(
        "ordered-provider-set",
        providers,
        |hash, provider| match provider {
            JvmImplicitRootProvider::Package(package) => {
                hash.field("provider-kind", b"package");
                hash.field("provider-name", package.as_bytes());
            }
            JvmImplicitRootProvider::ScalaPredef => {
                hash.field("provider-kind", b"scala-predef");
                hash.field("provider-name", SCALA_PREDEF_DEFAULT_IMPORT.as_bytes());
            }
        },
    );
    hash.field("spelling", spelling.as_bytes());
    hash.finish()
}

/// An explicit import whose owner package has no selected route, but whose
/// type the reviewed JVM model declares.
#[derive(Clone)]
struct ModelDeclaredJvmImportRoute {
    source_token: SemanticId,
    lookup: ResolutionLookupSemanticRecipe,
    declared_fqn: String,
    owner: Option<crate::analyzer::resolution::ExternalOwnerIdentity>,
}

fn model_declared_jvm_type_identity(
    declared_fqn: &str,
    names: &dyn SharedNameInterner,
) -> SemanticId {
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-model-declared-type-identity:v1");
    hash.field("declared-type-fqn", declared_fqn.as_bytes());
    SemanticId::shared_name(names.intern(hash.finish()))
}

fn register_model_declared_jvm_type_identities(
    operation: &SelectedResolutionOperation<'_, '_>,
    source: SelectedResolutionMountOrdinal,
    routes: &[ModelDeclaredJvmImportRoute],
    current_package_references: &BTreeSet<SemanticId>,
    identities: &SelectedContextIdentities,
    names: &dyn SharedNameInterner,
    cancellation: &CancellationToken,
) -> Result<Option<BTreeSet<SemanticId>>> {
    let mut registered = BTreeSet::new();
    let mut bindings_by_lookup = HashMap::default();
    for route in routes {
        if route.lookup.namespace() != ResolutionNamespace::Type {
            continue;
        }
        let bindings = match bindings_by_lookup.entry(route.lookup.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let Some(bindings) = super::jvm_demand::jvm_import_bindings_for_lookup(
                    operation,
                    source,
                    &route.lookup,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                entry.insert(bindings)
            }
        };
        for binding in bindings
            .iter()
            .filter(|binding| binding.token == route.source_token)
            .filter(|binding| !current_package_references.contains(&binding.reference))
        {
            let best = bindings
                .iter()
                .filter(|other| other.reference == binding.reference)
                .map(|other| other.precedence)
                .min()
                .expect("one candidate binding");
            if binding.precedence != best
                || bindings
                    .iter()
                    .filter(|other| {
                        other.reference == binding.reference && other.precedence == best
                    })
                    .count()
                    != 1
            {
                continue;
            }
            let Some(seed) = operation
                .ready
                .lexical_source()
                .reference_seed(ResolutionQuery::new(binding.reference), cancellation)?
            else {
                continue;
            };
            if !seed.site_metadata().is_some_and(|metadata| {
                metadata.unqualified()
                    && matches!(
                        metadata.namespace(),
                        ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
                    )
            }) {
                continue;
            }
            operation.profile_jvm_read(
                "model_bound_type_identity",
                (&route.lookup, &route.declared_fqn, binding.reference),
            );
            register_model_declared_jvm_type_identity(
                operation,
                binding.reference,
                &route.declared_fqn,
                route.owner.as_ref(),
                identities,
                names,
            )?;
            registered.insert(binding.reference);
        }
    }
    Ok(Some(registered))
}

fn register_model_declared_jvm_type_identity(
    operation: &SelectedResolutionOperation<'_, '_>,
    reference: SemanticId,
    declared_fqn: &str,
    owner: Option<&crate::analyzer::resolution::ExternalOwnerIdentity>,
    identities: &SelectedContextIdentities,
    names: &dyn SharedNameInterner,
) -> Result<Option<SemanticId>> {
    let identity = owner.map_or_else(
        || model_declared_jvm_type_identity(declared_fqn, names),
        |owner| identities.external_owner_semantic(owner, names),
    );
    // Type destinations require independent enumeration and closed type and
    // supertype inventories, just as subsequent member reads do.
    if let Some(owner) = owner
        && operation
            .ready
            .typed_source()
            .external_owner_type_is_indexed(owner)?
    {
        identities.record_jvm_provider_type_reference(reference, identity);
        return Ok(None);
    }
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-model-declared-type-boundary:v1");
    hash.field("declared-type-fqn", declared_fqn.as_bytes());
    let intrinsic = owner.is_some_and(|owner| owner.provider_id.as_ref() == "jvm-intrinsic");
    let (kind, detail) = if intrinsic {
        (
            "jvm-intrinsic-root",
            format!("language-defined root `{declared_fqn}` has a fixed complete member inventory"),
        )
    } else {
        (
            "jvm-model-declared-type",
            format!(
                "the reviewed JVM model declares `{declared_fqn}`; its members are enumerated from the model only"
            ),
        )
    };
    let enumeration_boundary = identities.named_semantic(hash.finish(), kind, &detail);
    identities.record_jvm_external_provider_type_identity(
        crate::analyzer::resolution::ExternalOwnerLanguage::Jvm,
        reference,
        enumeration_boundary,
        identity,
        enumeration_boundary,
    );
    Ok(Some(enumeration_boundary))
}

/// Selected provider inputs and completed identity groups, owned by one file
/// preparation. A name can suppress a group without changing its derivation.
struct JvmExternalProviderBlueprint {
    references_by_route: BTreeMap<(SemanticId, SemanticId), Vec<SemanticId>>,
    recipes: HashMap<SemanticId, ResolutionLookupSemanticRecipe>,
    registered: Mutex<HashSet<(SemanticId, ResolutionLookupSemanticRecipe, Vec<SemanticId>)>>,
}

struct JvmExternalProviderIdentityRegistration<'a> {
    source_language: Language,
    lookup: Option<&'a str>,
    gaps: &'a [JvmImportContextGap],
    blueprint: &'a JvmExternalProviderBlueprint,
    unqualified_type_references: &'a BTreeSet<SemanticId>,
    durable_owners: &'a BTreeMap<String, crate::analyzer::resolution::ExternalOwnerIdentity>,
    identities: &'a SelectedContextIdentities,
    names: &'a dyn SharedNameInterner,
    cancellation: &'a CancellationToken,
}

fn register_jvm_external_provider_type_identities(
    registration: JvmExternalProviderIdentityRegistration<'_>,
) -> Result<()> {
    let JvmExternalProviderIdentityRegistration {
        source_language,
        lookup: demanded_name,
        gaps,
        blueprint,
        unqualified_type_references,
        durable_owners,
        identities,
        names,
        cancellation,
    } = registration;
    let providers = nominal_language_rules(source_language)
        .expect("caller belongs to a nominal family")
        .implicit_root_providers();
    let references_by_route = &blueprint.references_by_route;
    let mut gaps_by_lookup = std::collections::BTreeMap::<
        (SemanticId, ResolutionLookupSemanticRecipe),
        Vec<(JvmImplicitRootProvider, SemanticId)>,
    >::new();
    for gap in gaps {
        if gap.boundary_status
            != Some(crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed)
            || gap.lookup.namespace() != ResolutionNamespace::Type
        {
            continue;
        }
        let Some(provider) = providers
            .iter()
            .copied()
            .find(|provider| jvm_implicit_provider_gap_matches(gap, *provider))
        else {
            continue;
        };
        if brokk_bifrost_jvm::intrinsics::default_provider_excludes_name(
            source_language,
            gap.owner.as_deref().expect("implicit provider has a name"),
            gap.lookup.spelling(),
        ) {
            continue;
        }
        if !gap
            .source_reference
            .is_some_and(|reference| unqualified_type_references.contains(&reference))
        {
            continue;
        }
        debug_assert!(
            demanded_name.is_none_or(|name| gap.lookup.spelling() == name),
            "implicit provider identities require their prepared name's peer proof"
        );
        gaps_by_lookup
            .entry((gap.source_token, gap.lookup.clone()))
            .or_default()
            .push((provider, gap.reason));
    }

    for ((source_token, lookup), provider_gaps) in gaps_by_lookup {
        let key = (
            source_token,
            lookup.clone(),
            provider_gaps
                .iter()
                .map(|(_, reason)| *reason)
                .collect::<Vec<_>>(),
        );
        if blueprint
            .registered
            .lock()
            .expect("JVM preparation memo is not poisoned")
            .contains(&key)
        {
            continue;
        }

        let references = references_by_route
            .get(&(source_token, lookup.semantic(names)))
            .expect("a JVM implicit-provider gap names an unqualified Type route");
        let ordered_providers = providers
            .iter()
            .copied()
            .filter(|provider| {
                provider_gaps
                    .iter()
                    .any(|(candidate, _)| candidate == provider)
            })
            .collect::<Vec<_>>();
        assert!(
            !ordered_providers.is_empty(),
            "a JVM external type identity has at least one unindexed provider"
        );
        let durable_matches = ordered_providers
            .iter()
            .filter_map(|provider| match provider {
                JvmImplicitRootProvider::Package(package) => {
                    durable_owners.get(&format!("{package}.{}", lookup.spelling()))
                }
                JvmImplicitRootProvider::ScalaPredef => None,
            })
            .collect::<Vec<_>>();
        let identity = match durable_matches.as_slice() {
            [owner] => identities.external_owner_semantic(owner, names),
            _ => jvm_external_provider_type_identity(&ordered_providers, lookup.spelling(), names),
        };
        if let Some(package) = nominal_language_rules(source_language)
            .expect("caller belongs to a nominal family")
            .unindexed_implicit_owner_package()
            && ordered_providers.as_slice() == [JvmImplicitRootProvider::Package(package)]
            && durable_matches.is_empty()
        {
            identities.record_jvm_unindexed_import_owner(
                identity,
                &format!("{package}.{}", lookup.spelling()),
            );
        }
        let provider_names = ordered_providers
            .iter()
            .map(|provider| match provider {
                JvmImplicitRootProvider::Package(package) => *package,
                JvmImplicitRootProvider::ScalaPredef => SCALA_PREDEF_DEFAULT_IMPORT,
            })
            .collect::<Vec<_>>();
        let mut boundary_hash =
            CanonicalHasher::new(b"bifrost-jvm-external-provider-enumeration-boundary:v1");
        boundary_hash.field(
            "type-descriptor",
            &jvm_external_provider_type_content(&ordered_providers, lookup.spelling()),
        );
        if let [owner] = durable_matches.as_slice() {
            boundary_hash.field("provider-id", owner.provider_id.as_bytes());
            boundary_hash.field("owner-fqn", owner.owner_fqn.as_bytes());
        }
        let enumeration_boundary = identities.named_semantic(
            boundary_hash.finish(),
            "jvm-external-provider-type",
            &format!(
                "implicit JVM providers {provider_names:?} are unindexed for type `{}`",
                lookup.spelling()
            ),
        );
        let source_boundaries = provider_gaps
            .into_iter()
            .map(|(_, boundary)| boundary)
            .collect::<BTreeSet<_>>();
        for &reference in references {
            for &source_boundary in &source_boundaries {
                identities.record_jvm_external_provider_type_identity(
                    crate::analyzer::resolution::ExternalOwnerLanguage::Jvm,
                    reference,
                    source_boundary,
                    identity,
                    enumeration_boundary,
                );
            }
        }
        if !cancellation.is_cancelled() {
            blueprint
                .registered
                .lock()
                .expect("JVM preparation memo is not poisoned")
                .insert(key);
        }
    }

    if let Some(package) = nominal_language_rules(source_language)
        .expect("caller belongs to a nominal family")
        .unindexed_implicit_owner_package()
    {
        let implicit_providers = providers
            .iter()
            .copied()
            .filter(|provider| matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package))
            .collect::<Vec<_>>();
        for (&(source_token, lookup_semantic), references) in references_by_route {
            let lookup = &blueprint.recipes[&lookup_semantic];
            if gaps
                .iter()
                .any(|gap| gap.source_token == source_token && gap.lookup == *lookup)
            {
                continue;
            }
            let key = (source_token, lookup.clone(), Vec::new());
            if blueprint
                .registered
                .lock()
                .expect("JVM preparation memo is not poisoned")
                .contains(&key)
            {
                continue;
            }
            let durable = implicit_providers
                .iter()
                .filter_map(|provider| match provider {
                    JvmImplicitRootProvider::Package(package) => {
                        durable_owners.get(&format!("{package}.{}", lookup.spelling()))
                    }
                    JvmImplicitRootProvider::ScalaPredef => None,
                })
                .collect::<Vec<_>>();
            let identity = match durable.as_slice() {
                [owner] => identities.external_owner_semantic(owner, names),
                _ => jvm_external_provider_type_identity(
                    &implicit_providers,
                    lookup.spelling(),
                    names,
                ),
            };
            if durable.is_empty() {
                // This names the type selected by the implicit provider; it
                // supplies no declaration, hierarchy or member inventory.
                identities.record_jvm_unindexed_import_owner(
                    identity,
                    &format!("{package}.{}", lookup.spelling()),
                );
            }
            let mut boundary_hash =
                CanonicalHasher::new(b"bifrost-jvm-external-provider-enumeration-boundary:v1");
            boundary_hash.field(
                "type-descriptor",
                &jvm_external_provider_type_content(&implicit_providers, lookup.spelling()),
            );
            if let [owner] = durable.as_slice() {
                boundary_hash.field("provider-id", owner.provider_id.as_bytes());
                boundary_hash.field("owner-fqn", owner.owner_fqn.as_bytes());
            }
            let enumeration_boundary = identities.named_semantic(
                boundary_hash.finish(),
                "jvm-external-provider-type",
                &format!(
                    "implicit Java provider java.lang is unindexed for type `{}`",
                    lookup.spelling()
                ),
            );
            for &reference in references {
                identities.record_jvm_implicit_nominal_fallback(
                    reference,
                    identity,
                    enumeration_boundary,
                );
            }
            if !cancellation.is_cancelled() {
                blueprint
                    .registered
                    .lock()
                    .expect("JVM preparation memo is not poisoned")
                    .insert(key);
            }
        }
    }
    Ok(())
}

impl JvmImportContext {
    pub(super) fn with_open_inventory_gap(self) -> Self {
        match self {
            Self::Ready {
                context,
                external_static_imports,
                inventory_reason,
                open_jvm_alias_imports,
                scoped_gaps,
            } => Self::Ready {
                context: Box::new((*context).with_additional_context_owned_inventory_reason(
                    inventory_reason.expect("Java import context has its open inventory reason"),
                )),
                external_static_imports,
                inventory_reason,
                open_jvm_alias_imports,
                scoped_gaps,
            },
            Self::Unavailable => Self::Unavailable,
            Self::Cancelled => Self::Cancelled,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmMemberImportKey {
    context: i64,
    caller_version: Option<i64>,
    import_kind: Option<ResolutionImportRouteKind>,
    caller_package: Option<String>,
    source: BindingFragmentId,
    token: SemanticId,
    prefix_reference: Option<SemanticId>,
    scope_head: Option<BindingNodeId>,
    anchor: ResolutionRootImportAnchor,
    anchor_semantic: SemanticId,
    selector_kind: Option<ResolutionImportSelectorKind>,
    import_precedence: Option<PrecedenceStep>,
    candidate_origin_rank: Option<u32>,
    route: Vec<ResolutionLookupSemanticRecipe>,
    lookup_route: Vec<ResolutionLookupSemanticRecipe>,
    demand: ResolutionLookupSemanticRecipe,
    language: Language,
    // Preserve Complete versus a raw empty Incomplete, and reason order.
    completion: Option<Vec<ResolutionIncompleteReason>>,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmMemberImportMemo =
    ExactReadMemo<JvmMemberImportKey, (JavaTypeMemberImportInventory, bool)>;

struct JvmRootAdmission {
    target_fragment: BindingFragmentId,
    target_demand: ResolutionLookupSemanticRecipe,
    completion: ResolutionCompletion,
    evidence: Option<SelectedJvmBridgeEvidence>,
}

struct JvmRootBridgeRoute<'a> {
    source_language: Language,
    target_language: Language,
    route: &'a [ResolutionLookupSemanticRecipe],
    source_demand: &'a ResolutionLookupSemanticRecipe,
    target_definition: BindingNodeId,
}

impl JvmRootAdmission {
    fn descriptor(
        self,
        pair: &RootBridgePair<'_, ()>,
        route: &JvmRootBridgeRoute<'_>,
    ) -> SelectedRootBridgeDescriptor {
        let (
            SelectedRootPathHalf::Import {
                identity,
                token: import_token,
                anchor,
                anchor_semantic,
                ..
            }
            | SelectedRootPathHalf::Reference {
                identity,
                token: import_token,
                anchor,
                anchor_semantic,
                ..
            },
            SelectedRootPathHalf::Export {
                token: export_token,
                ..
            },
        ) = (pair.import_half, pair.export_half)
        else {
            unreachable!("selected import/reference and export visitors")
        };
        let bridge = if let Some(evidence) = self.evidence {
            SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
                identity.fragment(),
                route.source_language,
                *import_token,
                *anchor,
                *anchor_semantic,
                self.target_fragment,
                route.target_language,
                *export_token,
                None,
                route.route.to_vec(),
                route.source_demand.clone(),
                self.target_demand,
                evidence,
                self.completion,
            )
        } else {
            SelectedRootBridgeDescriptor::from_selected_path_tokens(
                identity.fragment(),
                route.source_language,
                *import_token,
                *anchor,
                *anchor_semantic,
                self.target_fragment,
                route.target_language,
                *export_token,
                route.route.to_vec(),
                route.source_demand.clone(),
                self.target_demand,
                self.completion,
            )
        };
        bridge
            .with_selected_member_definition(route.target_definition)
            .with_callable_import_half(pair.import_half)
    }
}

struct JvmImportTargetRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    target: &'a SelectedResolutionOperationMount,
    route: JvmRootBridgeRoute<'a>,
    member: &'a crate::analyzer::resolution::LoweredPackageMember,
    target_semantic: SemanticId,
    relation: JvmDeclarationAccessContext<'a>,
    context_id: i64,
    caller_version: Option<i64>,
    caller_path: &'a str,
    target_version: Option<i64>,
    prefix_length: usize,
    lookup_route_length: usize,
    selector_kind: Option<ResolutionImportSelectorKind>,
    completion: &'a ResolutionCompletion,
}

impl<'a, 'store, 'input> RootTargetRules for JvmImportTargetRules<'a, 'store, 'input> {
    type Exports = Arc<JvmRootExportInventory>;
    type Bridges = JvmImportRootRules<'a, 'store, 'input>;

    fn read_exports(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<RootBridgeStep<Self::Exports>> {
        Ok(
            match self
                .operation
                .jvm_root_exports(self.target.ordinal(), cancellation)?
            {
                Some(exports) => RootBridgeStep::Ready(exports),
                None => RootBridgeStep::Cancelled,
            },
        )
    }

    fn bridge_rules(&mut self, _exports: &Self::Exports) -> Self::Bridges {
        let binding_origin = jvm_assembled_import_origin(
            self.route.source_language,
            self.prefix_length,
            self.lookup_route_length,
            self.caller_version,
            self.target_version,
            self.selector_kind,
        );
        JvmImportRootRules {
            operation: self.operation,
            target: self.target,
            route: JvmRootBridgeRoute {
                source_language: self.route.source_language,
                target_language: self.route.target_language,
                route: self.route.route,
                source_demand: self.route.source_demand,
                target_definition: self.route.target_definition,
            },
            member: self.member,
            target_semantic: self.target_semantic,
            relation: self.relation,
            context_id: self.context_id,
            caller_version: self.caller_version,
            caller_path: self.caller_path,
            target_version: self.target_version,
            candidate_origin_rank: binding_origin_rank(self.route.source_language, binding_origin),
            completion: self.completion,
            unavailable: Cell::new(false),
        }
    }

    fn pairs<'b>(
        &'b self,
        import: &'b SelectedRootPathHalf,
        exports: &'b Self::Exports,
        rules: &'b Self::Bridges,
    ) -> impl Iterator<Item = RootBridgePair<'b, ()>> {
        exports.halves.iter()
            .take_while(|_| !rules.unavailable.get())
            .filter(|half| matches!(half, SelectedRootPathHalf::Export { definition, .. } if *definition == rules.route.target_definition))
            .map(move |export_half| RootBridgePair {
                import_half: import,
                export_half,
                extra: (),
            })
    }

    fn unavailable(&self, rules: &Self::Bridges) -> bool {
        rules.unavailable.get()
    }
}

struct JvmImportRootRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    target: &'a SelectedResolutionOperationMount,
    route: JvmRootBridgeRoute<'a>,
    member: &'a crate::analyzer::resolution::LoweredPackageMember,
    target_semantic: SemanticId,
    relation: JvmDeclarationAccessContext<'a>,
    context_id: i64,
    caller_version: Option<i64>,
    caller_path: &'a str,
    target_version: Option<i64>,
    candidate_origin_rank: Option<u32>,
    completion: &'a ResolutionCompletion,
    unavailable: Cell<bool>,
}

impl RootBridgeRules for JvmImportRootRules<'_, '_, '_> {
    type Extra = ();
    type Admission = JvmRootAdmission;

    fn admit(
        &self,
        _operation: &ReadySelectedResolution<'_, '_>,
        pair: &RootBridgePair<'_, Self::Extra>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        debug_assert!(!self.unavailable.get());
        let SelectedRootPathHalf::Export {
            identity,
            demand,
            incomplete_reasons,
            ..
        } = pair.export_half
        else {
            unreachable!("export-only visitor")
        };
        debug_assert_eq!(identity.fragment(), self.target.fragment());
        let Some(mut target_recipes) =
            self.operation
                .jvm_lookup_recipes(self.target.fragment(), [*demand], cancellation)?
        else {
            self.unavailable.set(true);
            return Ok(None);
        };
        let Some(target_demand) = target_recipes.pop() else {
            return Err(StoreError::corrupt(
                "selected JVM import export lacks its lookup recipe",
            ));
        };
        if target_demand.namespace() != self.member.namespace
            || target_demand.semantic(&self.operation.ready.shared_names()) != self.target_semantic
        {
            return Ok(None);
        }
        let completion = if incomplete_reasons.is_empty() {
            self.completion.clone()
        } else {
            self.completion.combine(&ResolutionCompletion::incomplete(
                incomplete_reasons.iter().copied(),
            ))
        };
        let evidence = if self.route.source_language == self.route.target_language {
            None
        } else {
            let Some(visibility) = self.operation.jvm_bridge_visibility(
                self.member.definition,
                self.relation,
                cancellation,
            )?
            else {
                // Visibility excludes only this export; an unavailable recipe
                // above instead cancels the whole import context.
                return Ok(None);
            };
            let names = self.operation.ready.shared_names();
            Some(SelectedJvmBridgeEvidence {
                provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                    source_package: package_domain_semantic(self.route.source_language, &names),
                    target_package: package_domain_semantic(self.route.target_language, &names),
                },
                source_namespace: self.member.namespace,
                target_namespace: self.member.namespace,
                visibility,
                dependency_identity: jvm_dependency_identity(
                    self.context_id,
                    self.caller_version,
                    self.caller_path,
                    self.target_version,
                    self.target.persisted_relative_path(),
                ),
                target_declaration: self.member.definition,
                target_definition: self.route.target_definition,
            })
        };
        // Keep the original per-admitted-export mount read, after visibility.
        // The constructor consumes this read's fragment without reading SQL.
        let target_fragment = self
            .operation
            .mount_table()
            .mount_by_ordinal(self.target.ordinal())?
            .fragment();
        Ok(Some(JvmRootAdmission {
            target_fragment,
            target_demand,
            completion,
            evidence,
        }))
    }

    fn descriptor(
        &self,
        pair: &RootBridgePair<'_, Self::Extra>,
        admission: Self::Admission,
    ) -> SelectedRootBridgeDescriptor {
        admission
            .descriptor(pair, &self.route)
            .with_candidate_origin_rank(self.candidate_origin_rank)
    }

    fn fold_completion(
        &self,
        _completion: &mut ResolutionCompletion,
        _descriptor: &SelectedRootBridgeDescriptor,
    ) {
        // Import evidence remains on the selected bridge.
    }
}

struct JvmAliasTargetRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    import: &'a JavaMemberImportDemand<'a>,
    target: &'a SelectedResolutionOperationMount,
    alias_identity: SemanticId,
    declaration: SemanticId,
    target_definition: BindingNodeId,
    relation: JvmDeclarationAccessContext<'a>,
    context_id: i64,
    caller_version: Option<i64>,
    caller_path: &'a str,
    target_version: Option<i64>,
    completion: &'a ResolutionCompletion,
}

impl<'a, 'store, 'input> RootTargetRules for JvmAliasTargetRules<'a, 'store, 'input> {
    type Exports = Arc<JvmRootExportInventory>;
    type Bridges = JvmAliasRootRules<'a, 'store, 'input>;

    fn read_exports(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<RootBridgeStep<Self::Exports>> {
        Ok(
            match self
                .operation
                .jvm_root_exports(self.target.ordinal(), cancellation)?
            {
                Some(exports) => RootBridgeStep::Ready(exports),
                None => RootBridgeStep::Cancelled,
            },
        )
    }

    fn bridge_rules(&mut self, _exports: &Self::Exports) -> Self::Bridges {
        JvmAliasRootRules {
            operation: self.operation,
            import: self.import,
            target: self.target,
            alias_identity: self.alias_identity,
            declaration: self.declaration,
            target_definition: self.target_definition,
            relation: self.relation,
            context_id: self.context_id,
            caller_version: self.caller_version,
            caller_path: self.caller_path,
            target_version: self.target_version,
            completion: self.completion,
            unavailable: Cell::new(false),
        }
    }

    fn pairs<'b>(
        &'b self,
        import: &'b SelectedRootPathHalf,
        exports: &'b Self::Exports,
        rules: &'b Self::Bridges,
    ) -> impl Iterator<Item = RootBridgePair<'b, ()>> {
        exports.halves.iter()
            .take_while(|_| !rules.unavailable.get())
            .filter(|half| matches!(half, SelectedRootPathHalf::Export { definition, .. } if *definition == rules.target_definition))
            .map(move |export_half| RootBridgePair {
                import_half: import,
                export_half,
                extra: (),
            })
    }

    fn unavailable(&self, rules: &Self::Bridges) -> bool {
        rules.unavailable.get()
    }
}

struct JvmAliasRootRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    import: &'a JavaMemberImportDemand<'a>,
    target: &'a SelectedResolutionOperationMount,
    alias_identity: SemanticId,
    declaration: SemanticId,
    target_definition: BindingNodeId,
    relation: JvmDeclarationAccessContext<'a>,
    context_id: i64,
    caller_version: Option<i64>,
    caller_path: &'a str,
    target_version: Option<i64>,
    completion: &'a ResolutionCompletion,
    unavailable: Cell<bool>,
}

impl RootBridgeRules for JvmAliasRootRules<'_, '_, '_> {
    type Extra = ();
    type Admission = JvmRootAdmission;

    fn admit(
        &self,
        _operation: &ReadySelectedResolution<'_, '_>,
        pair: &RootBridgePair<'_, Self::Extra>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        debug_assert!(!self.unavailable.get());
        let SelectedRootPathHalf::Export {
            identity,
            demand,
            incomplete_reasons,
            ..
        } = pair.export_half
        else {
            unreachable!("export-only visitor")
        };
        debug_assert_eq!(identity.fragment(), self.target.fragment());
        let Some(mut target_recipes) =
            self.operation
                .jvm_lookup_recipes(self.target.fragment(), [*demand], cancellation)?
        else {
            self.unavailable.set(true);
            return Ok(None);
        };
        let Some(target_demand) = target_recipes.pop() else {
            return Err(StoreError::corrupt(
                "selected JVM alias export lacks its lookup recipe",
            ));
        };
        if target_demand.namespace() != self.import.demand.namespace() {
            return Ok(None);
        }
        let completion = if incomplete_reasons.is_empty() {
            self.completion.clone()
        } else {
            self.completion.combine(&ResolutionCompletion::incomplete(
                incomplete_reasons.iter().copied(),
            ))
        };
        let evidence = if self.import.language == self.target.semantic_language() {
            None
        } else {
            let Some(visibility) = self.operation.jvm_bridge_visibility(
                self.declaration,
                self.relation,
                cancellation,
            )?
            else {
                // This reader returns no result for the whole alias route,
                // including its existing private-access case.
                self.unavailable.set(true);
                return Ok(None);
            };
            Some(SelectedJvmBridgeEvidence {
                provenance: SelectedJvmBridgeProvenance::AliasFact {
                    alias: self.alias_identity,
                },
                source_namespace: self.import.demand.namespace(),
                target_namespace: self.import.demand.namespace(),
                visibility,
                dependency_identity: jvm_dependency_identity(
                    self.context_id,
                    self.caller_version,
                    self.caller_path,
                    self.target_version,
                    self.target.persisted_relative_path(),
                ),
                target_declaration: self.declaration,
                target_definition: self.target_definition,
            })
        };
        Ok(Some(JvmRootAdmission {
            target_fragment: identity.fragment(),
            target_demand,
            completion,
            evidence,
        }))
    }

    fn descriptor(
        &self,
        pair: &RootBridgePair<'_, Self::Extra>,
        admission: Self::Admission,
    ) -> SelectedRootBridgeDescriptor {
        debug_assert_eq!(pair.import_half, self.import.half);
        // Alias facts land at the authored member definition. Attaching a root
        // export instead would change the existing alias path authority.
        admission.descriptor(
            pair,
            &JvmRootBridgeRoute {
                source_language: self.import.language,
                target_language: self.target.semantic_language(),
                route: self.import.route,
                source_demand: self.import.demand,
                target_definition: self.target_definition,
            },
        )
    }

    fn fold_completion(
        &self,
        _completion: &mut ResolutionCompletion,
        _descriptor: &SelectedRootBridgeDescriptor,
    ) {
        // Alias evidence stays on the selected bridge.
    }
}

struct JavaPackageRootMetadata {
    definition: BindingNodeId,
    unit: Option<CodeUnit>,
}

struct JavaPackageRootState {
    admitted: Vec<JavaPackageRootMetadata>,
    workspace_type_rows: Vec<(SemanticId, CodeUnit)>,
    workspace_inventory_complete: bool,
    unavailable: bool,
}

struct JavaPackageTargetRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    import: &'a JavaMemberImportDemand<'a>,
    target: &'a SelectedResolutionOperationMount,
    demand: SemanticId,
    spelling: &'a str,
    source_access: &'a ResolutionCompletion,
    workspace_source: bool,
    collect_workspace_type_rows: bool,
    workspace_type_rows: Vec<(SemanticId, CodeUnit)>,
    workspace_inventory_complete: bool,
    route_inventory_complete: &'a mut bool,
}

impl<'a, 'store, 'input> RootTargetRules for JavaPackageTargetRules<'a, 'store, 'input> {
    type Exports = Arc<JvmRootExportInventory>;
    type Bridges = JavaPackageRootRules<'a, 'store, 'input>;

    fn read_exports(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<RootBridgeStep<Self::Exports>> {
        Ok(
            match self
                .operation
                .jvm_root_exports(self.target.ordinal(), cancellation)?
            {
                Some(exports) => RootBridgeStep::Ready(exports),
                None => RootBridgeStep::Cancelled,
            },
        )
    }

    fn bridge_rules(&mut self, exports: &Self::Exports) -> Self::Bridges {
        let outcome = &exports.outcome;
        *self.route_inventory_complete &=
            outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete;
        if self.workspace_source && self.collect_workspace_type_rows {
            self.workspace_inventory_complete &=
                outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete;
        }
        JavaPackageRootRules {
            operation: self.operation,
            import: self.import,
            target: self.target,
            demand: self.demand,
            spelling: self.spelling,
            source_access: self.source_access,
            workspace_source: self.workspace_source,
            collect_workspace_type_rows: self.collect_workspace_type_rows,
            state: RefCell::new(JavaPackageRootState {
                admitted: Vec::new(),
                workspace_type_rows: std::mem::take(&mut self.workspace_type_rows),
                workspace_inventory_complete: self.workspace_inventory_complete,
                unavailable: false,
            }),
        }
    }

    fn pairs<'b>(
        &'b self,
        import: &'b SelectedRootPathHalf,
        exports: &'b Self::Exports,
        rules: &'b Self::Bridges,
    ) -> impl Iterator<Item = RootBridgePair<'b, ()>> {
        exports
            .halves
            .iter()
            .take_while(|_| {
                let state = rules.state.borrow();
                !state.unavailable
                    && (rules.collect_workspace_type_rows
                        || rules.import.import_kind
                            == Some(ResolutionImportRouteKind::TypeOnDemand)
                        || state.admitted.is_empty())
            })
            .map(move |export_half| RootBridgePair {
                import_half: import,
                export_half,
                extra: (),
            })
    }

    fn unavailable(&self, rules: &Self::Bridges) -> bool {
        rules.state.borrow().unavailable
    }
}

struct JavaPackageRootRules<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    import: &'a JavaMemberImportDemand<'a>,
    target: &'a SelectedResolutionOperationMount,
    demand: SemanticId,
    spelling: &'a str,
    source_access: &'a ResolutionCompletion,
    workspace_source: bool,
    collect_workspace_type_rows: bool,
    state: RefCell<JavaPackageRootState>,
}

impl RootBridgeRules for JavaPackageRootRules<'_, '_, '_> {
    type Extra = ();
    type Admission = ResolutionCompletion;

    fn admit(
        &self,
        operation: &ReadySelectedResolution<'_, '_>,
        pair: &RootBridgePair<'_, Self::Extra>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        let mut state = self.state.borrow_mut();
        debug_assert!(!state.unavailable);
        debug_assert!(
            self.collect_workspace_type_rows
                || self.import.import_kind == Some(ResolutionImportRouteKind::TypeOnDemand)
                || state.admitted.is_empty()
        );
        let SelectedRootPathHalf::Export {
            demand,
            definition,
            incomplete_reasons,
            ..
        } = pair.export_half
        else {
            unreachable!("export-only visitor")
        };
        if *demand != self.demand {
            return Ok(None);
        }
        let Some(endpoints) = self
            .operation
            .jvm_endpoint_classifications(*definition, cancellation)?
        else {
            state.unavailable = true;
            return Ok(None);
        };
        if cancellation.is_cancelled() {
            state.unavailable = true;
            return Ok(None);
        }
        let definition_semantic = endpoints
            .first()
            .and_then(|endpoint| endpoint.definition())
            .ok_or_else(|| StoreError::corrupt("Java export lacks a declaration endpoint"))?;
        let relation =
            JvmDeclarationAccessContext::between(self.import.caller_package, self.spelling)
                .with_reference(self.import.prefix_reference)
                .with_scope(self.import.scope_head)
                .with_import(self.import.token);
        let bridge_completion = match self.operation.jvm_declaration_access(
            definition_semantic,
            relation,
            self.source_access,
            cancellation,
        )? {
            JvmDeclarationAccess::Ready(completion) => completion,
            JvmDeclarationAccess::Excluded => return Ok(None),
            JvmDeclarationAccess::Cancelled => {
                state.unavailable = true;
                return Ok(None);
            }
        };
        if self.workspace_source
            && self.collect_workspace_type_rows
            && !incomplete_reasons.is_empty()
        {
            state.workspace_inventory_complete = false;
        }
        let target_file = ProjectFile::new(
            operation.project.root().to_path_buf(),
            self.target.persisted_relative_path(),
        );
        let unit = if self.collect_workspace_type_rows {
            let unit = self.operation.java_selected_type_unit(
                self.target.ordinal(),
                &target_file,
                definition_semantic,
                cancellation,
            )?;
            if unit.is_none() && cancellation.is_cancelled() {
                state.unavailable = true;
                return Ok(None);
            }
            if self.workspace_source && unit.is_none() {
                state.workspace_inventory_complete = false;
            }
            unit
        } else {
            None
        };
        if self.workspace_source
            && let Some(unit) = &unit
        {
            state
                .workspace_type_rows
                .push((definition_semantic, unit.clone()));
        }
        state.admitted.push(JavaPackageRootMetadata {
            definition: *definition,
            unit,
        });
        Ok(Some(bridge_completion))
    }

    fn descriptor(
        &self,
        pair: &RootBridgePair<'_, Self::Extra>,
        completion: Self::Admission,
    ) -> SelectedRootBridgeDescriptor {
        let SelectedRootPathHalf::Export {
            identity, token, ..
        } = pair.export_half
        else {
            unreachable!("export-only visitor")
        };
        debug_assert_eq!(pair.import_half, self.import.half);
        self.import
            .bridge(identity.fragment(), *token, completion)
            .with_selected_export(&self.operation.ready.shared_names(), pair.export_half)
    }

    fn fold_completion(
        &self,
        _completion: &mut ResolutionCompletion,
        _descriptor: &SelectedRootBridgeDescriptor,
    ) {
        // Source/declaration evidence remains descriptor-local.
    }
}

struct JavaMemberImportDemand<'a> {
    half: &'a SelectedRootPathHalf,
    import_kind: Option<ResolutionImportRouteKind>,
    caller_package: Option<&'a str>,
    source: BindingFragmentId,
    token: SemanticId,
    prefix_reference: Option<SemanticId>,
    scope_head: Option<BindingNodeId>,
    anchor: ResolutionRootImportAnchor,
    anchor_semantic: SemanticId,
    selector_kind: Option<ResolutionImportSelectorKind>,
    import_precedence: Option<PrecedenceStep>,
    candidate_origin_rank: Option<u32>,
    /// The route as the import half spells it; a bridge attaches to it.
    route: &'a [ResolutionLookupSemanticRecipe],
    /// The absolute route the selected sources are searched for. It is
    /// `route` unless the language reads a relative route against the
    /// enclosing package first.
    lookup_route: &'a [ResolutionLookupSemanticRecipe],
    demand: &'a ResolutionLookupSemanticRecipe,
    /// The source language. A cross-language destination supplies its own
    /// namespace rules and an explicit JVM bridge proof.
    language: Language,
}

fn jvm_member_name_matches(language: Language, selected: &str, requested: &str) -> bool {
    selected == requested
        || nominal_language_rules(language)
            .expect("caller belongs to a nominal family")
            .member_name(selected)
            == requested
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn scala_import_owner_gap(
        &self,
        half: &SelectedRootPathHalf,
        owner_anchor: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SemanticId> {
        let SelectedRootPathHalf::Import { token, demand, .. } = half else {
            unreachable!("a Scala import owner gap belongs to an import");
        };
        let mut descriptor =
            CanonicalIdentityDescriptor::new(b"bifrost-scala-import-owner-open:v1", |key| {
                self.ready.identity_content_digest(key, cancellation)
            });
        descriptor.field("import", CanonicalIdentityPart::identity(*token))?;
        descriptor.field("demand", CanonicalIdentityPart::identity(*demand))?;
        descriptor.field(
            "owner_anchor",
            CanonicalIdentityPart::identity(owner_anchor),
        )?;
        Ok(self.ready.context_identities.named_semantic(
            descriptor.finish(),
            "jvm-import-owner-open",
            "The Scala import qualifier does not establish a fully indexed member selection",
        ))
    }

    /// Recover a positioned qualifier from the import's structured source
    /// range and selected reference halves. Prefixed references intentionally
    /// do not appear in the compact package-route table, so read the same
    /// source halves the demand provider uses, bounded to this one blob.
    pub(super) fn scala_import_qualifiers(
        &self,
        half: &SelectedRootPathHalf,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SemanticId>>> {
        let SelectedRootPathHalf::Import {
            identity,
            token,
            route,
            demand,
            ..
        } = half
        else {
            return Ok(None);
        };
        if route.is_empty() {
            return Ok(None);
        }
        let ordinal = SelectedResolutionMountOrdinal::new(identity.fragment().ordinal());
        let record = self.ready.inventory.mount_record_by_ordinal(ordinal)?;
        let connection = self.ready.inventory.connection();
        let Some(mut recipes) = self.jvm_lookup_recipes(
            identity.fragment(),
            route.iter().copied().chain([*demand]),
            cancellation,
        )?
        else {
            return Ok(Some(Vec::new()));
        };
        let demand = recipes.pop().expect("import demand");
        if !matches!(
            demand.namespace(),
            ResolutionNamespace::Type | ResolutionNamespace::Value | ResolutionNamespace::Callable
        ) || recipes.is_empty()
        {
            return Ok(None);
        }
        let expected = recipes
            .iter()
            .map(ResolutionLookupSemanticRecipe::spelling)
            .collect::<Vec<_>>();
        let ranges = connection
            .prepare_cached(
                "SELECT DISTINCT source.declaration_start_byte,source.declaration_end_byte
             FROM main.resolution_semantic_catalog AS import
             JOIN main.source_imports AS source ON source.blob_id=import.blob_id
               AND source.declaration_start_byte<=import.import_start_byte
               AND source.declaration_end_byte>=import.import_end_byte
             WHERE import.blob_id=?1 AND import.local_key=?2",
            )?
            .query_map(
                rusqlite::params![
                    record.blob_id(),
                    token.local_key().expect("import token is mounted")
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let lexical = self.ready.lexical_source();
        let (halves, outcome) =
            self.read_root_inventory(RootHalfRequest::Imports(&[ordinal]), cancellation)?;
        if !outcome.is_exhausted() {
            return Ok(Some(Vec::new()));
        }
        let mut selected = BTreeSet::new();
        for half in halves {
            let SelectedRootPathHalf::Reference {
                source_reference,
                route,
                demand,
                ..
            } = half
            else {
                continue;
            };
            let Some(candidate) = self.jvm_lookup_recipes(
                identity.fragment(),
                route.iter().copied().chain([demand]),
                cancellation,
            )?
            else {
                return Ok(Some(Vec::new()));
            };
            if !candidate
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .eq(expected.iter().copied())
            {
                continue;
            }
            let key = source_reference
                .local_key()
                .expect("selected reference is mounted");
            let range = connection.prepare_cached(
                "SELECT start_byte,end_byte FROM main.resolution_sites WHERE blob_id=?1 AND site=?2 AND role=0
                   AND start_byte IS NOT NULL AND end_byte IS NOT NULL"
            )?.query_row(rusqlite::params![record.blob_id(),key], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?))).optional()?;
            let Some((start, end)) = range else {
                continue;
            };
            if !ranges
                .iter()
                .any(|(outer_start, outer_end)| *outer_start <= start && end <= *outer_end)
            {
                continue;
            }
            let endpoints = lexical.classify_endpoint_nodes(&[source_reference], cancellation)?;
            selected.extend(endpoints.iter().filter_map(|endpoint| endpoint.reference()));
        }
        // Named and wildcard selectors in one clause can publish distinct
        // references for the same qualifier occurrence. Resolve every view;
        // the consumer requires their exact projected owner values to agree.
        Ok(Some(selected.into_iter().collect()))
    }

    fn scala_reference_package_prefixes(
        &self,
        blob: i64,
        reference: BindingNodeId,
    ) -> Result<Vec<String>> {
        let key = reference
            .local_key()
            .expect("selected Scala reference has a local key");
        let connection = self.ready.inventory.connection();
        let import = connection
            .prepare_cached(
                "SELECT import.import_id
             FROM main.resolution_sites AS site
             JOIN main.source_imports AS import ON import.blob_id=site.blob_id
               AND import.declaration_start_byte<=site.start_byte
               AND import.declaration_end_byte>=site.end_byte
             WHERE site.blob_id=?1 AND site.site=?2 AND site.role=0
             ORDER BY import.declaration_end_byte-import.declaration_start_byte
             LIMIT 1",
            )?
            .query_row(rusqlite::params![blob, key], |row| row.get::<_, i64>(0))
            .optional()?;
        if let Some(import) = import {
            return Ok(connection
                .prepare_cached(
                    "SELECT prefix FROM main.source_import_prefixes
                 WHERE blob_id=?1 AND import_id=?2 ORDER BY ordinal",
                )?
                .query_map(rusqlite::params![blob, import], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?);
        }
        let declaration = connection
            .prepare_cached(
                "SELECT declaration.declaration_id
             FROM main.resolution_sites AS site
             JOIN main.source_declarations AS declaration ON declaration.blob_id=site.blob_id
               AND declaration.start_byte<=site.start_byte
               AND declaration.end_byte>=site.end_byte
             JOIN main.source_scala_declarations AS scala
               ON scala.blob_id=declaration.blob_id
              AND scala.declaration_id=declaration.declaration_id
             WHERE site.blob_id=?1 AND site.site=?2 AND site.role=0
             ORDER BY declaration.end_byte-declaration.start_byte, declaration.declaration_id
             LIMIT 1",
            )?
            .query_row(rusqlite::params![blob, key], |row| row.get::<_, i64>(0))
            .optional()?;
        if let Some(declaration) = declaration {
            return Ok(connection
                .prepare_cached(
                    "SELECT prefix FROM main.source_scala_declaration_lexical_prefixes
                 WHERE blob_id=?1 AND declaration_id=?2 ORDER BY ordinal",
                )?
                .query_map(rusqlite::params![blob, declaration], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?);
        }
        Ok(self.scala_primary_package(blob)?.into_iter().collect())
    }

    pub(super) fn scala_primary_package(&self, blob: i64) -> Result<Option<String>> {
        let segments = self
            .ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT segment.spelling
             FROM main.resolution_node_catalog AS scope
             JOIN main.resolution_package_route_segments AS segment
               ON segment.blob_id=scope.blob_id
              AND segment.package_scope_node_key=scope.local_key
             WHERE scope.blob_id=?1 AND scope.source_scope=0
             ORDER BY segment.ordinal",
            )?
            .query_map([blob], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((!segments.is_empty()).then(|| segments.join(".")))
    }

    /// Read the lexical package context captured by the import producer for
    /// the exact selected blob. Selector halves share their AST declaration's
    /// context, including distinct sibling package blocks.
    pub(super) fn scala_import_package_prefixes(
        &self,
        blob: i64,
        token: SemanticId,
    ) -> Result<Vec<String>> {
        let Some(key) = token.local_key() else {
            return Ok(Vec::new());
        };
        Ok(self
            .ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT DISTINCT prefix.ordinal, prefix.prefix
             FROM main.resolution_semantic_catalog AS token
             JOIN main.source_imports AS import ON import.blob_id=token.blob_id
               AND import.declaration_start_byte<=token.import_start_byte
               AND import.declaration_end_byte>=token.import_end_byte
             JOIN main.source_import_prefixes AS prefix
               ON prefix.blob_id=import.blob_id AND prefix.import_id=import.import_id
             WHERE token.blob_id=?1 AND token.local_key=?2
             ORDER BY prefix.ordinal",
            )?
            .query_map(rusqlite::params![blob, key], |row| row.get(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn scala_enclosing_scope_import_routes(
        &self,
        source_fragment: BindingFragmentId,
        source_mount: SelectedResolutionMountOrdinal,
        source_scope_head: BindingNodeId,
        route: &[ResolutionLookupSemanticRecipe],
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<Vec<ResolutionLookupSemanticRecipe>>>> {
        let typed = self.ready.typed_source();
        let mut owners = BTreeSet::new();
        let outcome = typed.visit_member_scope_pages_for_heads(
            TypedFactRequest::new(&[source_scope_head]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                owners.extend(page.iter().filter_map(|row| {
                    let definition = row.row().definition();
                    (row.fragment() == source_fragment
                        && definition.ordinal() == Some(source_mount.get()))
                    .then(|| {
                        definition
                            .local_key()
                            .map(|key| (source_mount, ResolutionLocalKey::new(i64::from(key))))
                    })
                    .flatten()
                }));
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(None);
        }
        let owners = owners.into_iter().collect::<Vec<_>>();
        let mut routes = BTreeSet::new();
        for coordinates in owners.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let SelectedDefinitionUnitReadOutcome::Ready(rows) = self
                .ready
                .inventory
                .selected_declaration_units(coordinates, cancellation)?
            else {
                return Ok(None);
            };
            for (_, _, row) in rows {
                if row.kind != brokk_bifrost_core::analyzer::model::CodeUnitType::Class {
                    continue;
                }
                let Some(identity) = row.fq.as_ref() else {
                    continue;
                };
                if identity.segments.is_empty() {
                    continue;
                }
                // The owner's identity names every type that encloses it. A
                // member of an enclosing type is visible from the import too, so
                // each enclosing prefix ending in a type is a route. The owner
                // itself is the longest prefix.
                let owner_route = identity
                    .segments
                    .iter()
                    .map(|(_, spelling)| {
                        self.jvm_generated_lookup(
                            Language::Scala,
                            ResolutionNamespace::Type,
                            spelling,
                        )
                        .recipe
                        .clone()
                    })
                    .collect::<Vec<_>>();
                let package_segments = identity
                    .segments
                    .iter()
                    .take_while(|(kind, _)| {
                        *kind == brokk_bifrost_core::analyzer::fq_name::SegmentKind::Package
                    })
                    .count();
                if package_segments > 0 {
                    let mut package_scope = owner_route[..package_segments].to_vec();
                    package_scope.extend(route.iter().cloned());
                    routes.insert(package_scope);
                }
                for (index, (kind, _)) in identity.segments.iter().enumerate() {
                    if !matches!(
                        kind,
                        brokk_bifrost_core::analyzer::fq_name::SegmentKind::Type
                            | brokk_bifrost_core::analyzer::fq_name::SegmentKind::Companion
                    ) {
                        continue;
                    }
                    let mut scoped = owner_route[..=index].to_vec();
                    scoped.extend(route.iter().cloned());
                    routes.insert(scoped);
                }
            }
        }
        let mut routes = routes.into_iter().collect::<Vec<_>>();
        routes.sort_by_key(|route| std::cmp::Reverse(route.len()));
        Ok(Some(routes))
    }

    fn java_selected_type_unit(
        &self,
        target: SelectedResolutionMountOrdinal,
        target_file: &ProjectFile,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<CodeUnit>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let (Some(ordinal), Some(local_key)) = (definition.ordinal(), definition.local_key())
        else {
            return Ok(None);
        };
        if ordinal != target.get() {
            return Ok(None);
        }
        let coordinate = [(target, ResolutionLocalKey::new(i64::from(local_key)))];
        let SelectedDefinitionUnitReadOutcome::Ready(rows) = self
            .ready
            .inventory
            .selected_declaration_units(&coordinate, cancellation)?
        else {
            return Ok(None);
        };
        let Some((mount, key, row)) = rows.into_iter().next() else {
            return Ok(None);
        };
        assert_eq!(
            mount, target,
            "Java type identity stays on its selected mount"
        );
        assert_eq!(
            key.get(),
            i64::from(local_key),
            "Java type identity resolves the requested declaration row"
        );
        let Some(identity) = row.fq.as_ref() else {
            return Ok(None);
        };
        let (fq, package_segments) = super::super::hydrate_unit_fq_with_anchor(
            Some(identity),
            &row.content_qualifier,
            target_file,
            |_, _, _| None,
        )?;
        Ok(Some(CodeUnit::from_fq(
            target_file.clone(),
            row.kind,
            fq,
            package_segments,
            row.signature,
            row.flags.synthetic,
        )))
    }

    /// Whether an import owner that declares no member `name` has no such
    /// member at all.
    ///
    /// The declared members are the whole member set when every declared member
    /// row was read and named, no owner declares a supertype or an unsupported
    /// export (the hierarchy gap the producers attach to a type whose member
    /// set extends past its body), and `name` is not a member of the language's
    /// implicit root. An owner's own edge to that implicit root (Java's
    /// `Object` row) is not a declared supertype: the root's names are the
    /// language hook's. The hierarchy walk is not run here; the import context
    /// is built before any evaluation exists, so an owner with a supertype
    /// keeps its route open.
    fn jvm_import_owners_declare_every_member(
        &self,
        language: Language,
        inventory: &JavaTypeMemberImportInventory,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        assert!(
            !inventory.owners.is_empty(),
            "a member-route decision is made only for a found owner"
        );
        if !inventory.declared_members_complete
            || language_implicit_root_member_names(language).contains(&name)
        {
            return Ok(Some(false));
        }
        let typed = self.ready.typed_source();
        let mut owners = inventory.owners.clone();
        owners.sort_unstable();
        owners.dedup();
        let mut inherits = false;
        for chunk in owners.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let mut implicit_root_frontiers = BTreeSet::new();
            let outcome = typed.visit_supertype_pages_for_definitions(
                TypedFactRequest::new(chunk),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    for row in page.iter().map(|row| row.row()) {
                        let implicit_root =
                            row.source_kind() == Some(ResolutionSupertypeKind::ImplicitSuperclass);
                        inherits |= !implicit_root;
                        if implicit_root {
                            implicit_root_frontiers.insert((row.definition(), row.frontier()));
                        }
                    }
                    Ok(true)
                }),
            )?;
            if outcome.is_cancelled() {
                return Ok(None);
            }
            inherits |=
                !(outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete);
            let outcome = typed.visit_definition_property_gap_pages_for_definitions(
                TypedFactRequest::new(chunk),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    inherits |= page.iter().any(|row| {
                        let gap = row.row();
                        gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal
                            // An implicit language-root edge contributes only the
                            // root names rejected above. Its exact property gap
                            // cannot keep a different member search open.
                            && !implicit_root_frontiers
                                .contains(&(gap.definition(), gap.frontier()))
                    });
                    Ok(true)
                }),
            )?;
            if outcome.is_cancelled() {
                return Ok(None);
            }
            inherits |=
                !(outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete);
        }
        Ok(Some(!inherits))
    }

    /// Query-owned direct member continuation. Package prefixes come from
    /// exact selected package rows; each remaining segment must name a member
    /// of the already-proven type. Inherited routes remain incomplete.
    pub(super) fn jvm_scala_object_definition(&self, definition: SemanticId) -> Result<bool> {
        let (Some(ordinal), Some(local_key)) = (definition.ordinal(), definition.local_key())
        else {
            return Ok(false);
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        self.ready
            .inventory
            .connection()
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM main.resolution_semantic_sites AS site
                    JOIN main.resolution_singleton_relations AS singleton
                      ON singleton.blob_id=site.blob_id
                     AND singleton.declaration_site=site.source_site
                    WHERE site.blob_id=?1 AND site.semantic_key=?2
                      AND site.semantic_role='definition'
                      AND singleton.kind IN ('object', 'companion')
                )",
                rusqlite::params![record.blob_id(), i64::from(local_key)],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Scala's singleton term and module class share a declaration identity.
    /// The explicit term-type namespace proof and owned type body distinguish
    /// that pair from an ordinary field or the former class namespace aliases.
    fn jvm_singleton_import_type_owner(
        &self,
        definition: SemanticId,
    ) -> Result<Option<SemanticId>> {
        let (Some(ordinal), Some(local_key)) = (definition.ordinal(), definition.local_key())
        else {
            return Ok(None);
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let proven = self.ready.inventory.connection().query_row(
            "SELECT EXISTS(
                SELECT 1 FROM main.resolution_semantic_sites AS site
                JOIN main.resolution_additional_definition_namespaces AS term_type
                  ON term_type.blob_id=site.blob_id
                 AND term_type.definition_semantic_key=site.semantic_key
                 AND term_type.namespace='value'
                JOIN main.resolution_member_scope_properties AS module
                  ON module.blob_id=site.blob_id
                 AND module.definition_semantic_key=site.semantic_key
                JOIN main.resolution_singleton_relations AS singleton
                  ON singleton.blob_id=site.blob_id
                 AND singleton.declaration_site=site.source_site
                 AND singleton.kind IN ('object', 'companion')
                WHERE site.blob_id=?1 AND site.semantic_key=?2
                  AND site.semantic_role='definition' AND site.namespace='value'
            )",
            rusqlite::params![record.blob_id(), i64::from(local_key)],
            |row| row.get::<_, bool>(0),
        )?;
        Ok(proven.then_some(definition))
    }

    fn jvm_type_member_import_candidates(
        &self,
        context: i64,
        caller_version: Option<i64>,
        import: &JavaMemberImportDemand<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        owner_found: &mut bool,
    ) -> Result<Option<JavaTypeMemberImportInventory>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let key = JvmMemberImportKey {
            context,
            caller_version,
            import_kind: import.import_kind,
            caller_package: import.caller_package.map(str::to_owned),
            source: import.source,
            token: import.token,
            prefix_reference: import.prefix_reference,
            scope_head: import.scope_head,
            anchor: import.anchor,
            anchor_semantic: import.anchor_semantic,
            selector_kind: import.selector_kind,
            import_precedence: import.import_precedence,
            candidate_origin_rank: import.candidate_origin_rank,
            route: import.route.to_vec(),
            lookup_route: import.lookup_route.to_vec(),
            demand: import.demand.clone(),
            language: import.language,
            completion: match completion {
                ResolutionCompletion::Complete => None,
                ResolutionCompletion::Incomplete(reasons) => {
                    Some(reasons.iter().copied().collect())
                }
            },
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("member_import", &key);
        if let Some((inventory, found)) = self.jvm_member_import_memo.borrow().get(&key) {
            *owner_found |= *found;
            return Ok(Some(inventory.clone()));
        }
        self.profile_jvm_read("derive_member_import", &key);
        let mut found = false;
        let inventory = self.read_jvm_type_member_import_candidates(
            context,
            caller_version,
            import,
            completion,
            cancellation,
            &mut found,
        )?;
        *owner_found |= found;
        if let Some(inventory) = &inventory
            && !cancellation.is_cancelled()
        {
            self.jvm_member_import_memo
                .borrow_mut()
                .insert(key, (inventory.clone(), found));
        }
        Ok(inventory)
    }

    fn read_jvm_type_member_import_candidates(
        &self,
        context: i64,
        caller_version: Option<i64>,
        import: &JavaMemberImportDemand<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        owner_found: &mut bool,
    ) -> Result<Option<JavaTypeMemberImportInventory>> {
        let lexical = self.ready.lexical_source();
        let rules =
            nominal_language_rules(import.language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let typed = self.ready.typed_source();
        let names = self.ready.shared_names();
        let collect_workspace_type_rows = matches!(
            import.import_kind,
            Some(ResolutionImportRouteKind::SingleType)
        );
        let mut bridges = Vec::new();
        let mut workspace_type_rows = Vec::new();
        let mut workspace_inventory_complete = true;
        let mut inherited_route_open = false;
        let mut owners_found = Vec::new();
        let mut declared_members_complete = true;
        let mut route_search_complete = true;
        // An imported type cannot be in the unnamed package. The final route
        // segment is an enclosing type here; ordinary package imports are
        // composed separately by the caller.
        for package_length in 1..import.lookup_route.len() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let package = import.lookup_route[..package_length]
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".");
            // A Scala import owner is a stable identifier, so it names the
            // object's term. A trait or class of the same name is type-only and
            // must not own the import's members.
            let static_owner_languages = rules.static_import_owner_languages(import.import_kind);
            let mounts = if !static_owner_languages.is_empty() {
                family.import_target_mounts()
            } else {
                family
                    .member_continuation_mounts(import.language)
                    .expect("a type-member continuation runs only for an adopting language")
            };
            let owner_namespace = rules.import_owner_namespace();
            let namespaces = if !static_owner_languages.is_empty() {
                static_owner_languages
                    .iter()
                    .copied()
                    .filter_map(|language| {
                        language_jvm_declaration_access_rules(language)
                            .and_then(|rules| rules.java_static_import_owner_namespace())
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![owner_namespace]
            };
            let Some(targets) = self.jvm_named_import_targets(
                mounts,
                &package,
                import.lookup_route[package_length].spelling(),
                &namespaces,
                import.language,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let relation = JvmDeclarationAccessContext::between(import.caller_package, &package)
                .with_reference(import.prefix_reference)
                .with_scope(import.scope_head)
                .with_import(import.token);
            let caller_mount = self
                .mount_table()
                .mount_for_fragment(import.source)?
                .expect("Java import source remains selected");
            for (ordinal, version) in targets.rows.iter().copied() {
                let target_ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                let target_language = target_mount.semantic_language();
                let outer_namespace = if !static_owner_languages.is_empty() {
                    let Some(namespace) = language_jvm_declaration_access_rules(target_language)
                        .and_then(|rules| rules.java_static_import_owner_namespace())
                    else {
                        continue;
                    };
                    namespace
                } else {
                    if target_language != import.language {
                        continue;
                    }
                    owner_namespace
                };
                let outer_lookup = self
                    .jvm_generated_lookup(
                        target_language,
                        outer_namespace,
                        import.lookup_route[package_length].spelling(),
                    )
                    .recipe
                    .clone()
                    .semantic(&names);
                // Classify the selected owner's declarations in its own
                // language; Scala methods also occupy the term namespace.
                let callables_in_value = language_callables_occupy_value_namespace(target_language);
                let source_access = self.jvm_qualified_source_access_completion(
                    import.language,
                    context,
                    caller_version,
                    caller_mount.persisted_relative_path(),
                    version,
                    target_mount.persisted_relative_path(),
                    completion,
                )?;
                if collect_workspace_type_rows && source_access.is_none() {
                    continue;
                }
                let bridge_allowed = source_access.is_some();
                let access = source_access.clone().unwrap_or_else(|| completion.clone());
                let target = target_ordinal;
                let Some(exports_read) = self.jvm_root_exports(target, cancellation)? else {
                    return Ok(None);
                };
                let outcome = &exports_read.outcome;
                route_search_complete &=
                    outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete;
                let exports = exports_read.halves.iter()
                    .filter(|half| matches!(half, SelectedRootPathHalf::Export { demand, .. } if *demand == outer_lookup))
                    .cloned();
                if version.is_some() && collect_workspace_type_rows {
                    workspace_inventory_complete &= outcome.is_exhausted()
                        && outcome.evidence() == &ResolutionCompletion::Complete;
                }
                for export in exports {
                    let nested_route = &import.lookup_route[package_length + 1..];
                    if nested_route.is_empty() {
                        *owner_found = true;
                    }
                    let SelectedRootPathHalf::Export {
                        identity,
                        token,
                        definition,
                        incomplete_reasons,
                        ..
                    } = export
                    else {
                        unreachable!("export-only visitor");
                    };
                    route_search_complete &= incomplete_reasons.is_empty();
                    let Some(endpoints) =
                        self.jvm_endpoint_classifications(definition, cancellation)?
                    else {
                        return Ok(None);
                    };
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let owner = endpoints
                        .first()
                        .and_then(|row| row.definition())
                        .ok_or_else(|| {
                            StoreError::corrupt("Java enclosing export lacks definition")
                        })?;
                    if nested_route.is_empty() {
                        owners_found.push(owner);
                    }
                    let target_file = ProjectFile::new(
                        self.ready.project.root().to_path_buf(),
                        target_mount.persisted_relative_path(),
                    );
                    let mut bridge_allowed = bridge_allowed;
                    let access = match self.jvm_declaration_access(
                        owner,
                        relation,
                        &access,
                        cancellation,
                    )? {
                        JvmDeclarationAccess::Ready(access) => {
                            if incomplete_reasons.is_empty() {
                                access
                            } else {
                                access.combine(&ResolutionCompletion::incomplete(
                                    incomplete_reasons.iter().copied(),
                                ))
                            }
                        }
                        JvmDeclarationAccess::Excluded => {
                            bridge_allowed = false;
                            access.clone()
                        }
                        JvmDeclarationAccess::Cancelled => return Ok(None),
                    };
                    if collect_workspace_type_rows && !bridge_allowed {
                        continue;
                    }
                    if version.is_some()
                        && collect_workspace_type_rows
                        && !incomplete_reasons.is_empty()
                    {
                        workspace_inventory_complete = false;
                    }
                    if bridge_allowed && version.is_some() && collect_workspace_type_rows {
                        match self.java_selected_type_unit(
                            target,
                            &target_file,
                            owner,
                            cancellation,
                        )? {
                            Some(unit) => workspace_type_rows.push((owner, unit)),
                            None if cancellation.is_cancelled() => return Ok(None),
                            None => workspace_inventory_complete = false,
                        }
                    }
                    let mut owners = vec![(
                        owner,
                        access,
                        ResolutionMemberAccess::Type,
                        None::<CodeUnit>,
                        bridge_allowed,
                    )];
                    let mut terminal_owners = Vec::new();
                    let mut terminal_owners_with_members = BTreeSet::new();
                    let mut terminal_member_inventory_complete = true;
                    // Every step is iterative, including deeply nested types.
                    for (step, (name, namespace)) in nested_route
                        .iter()
                        .map(|recipe| (recipe.spelling(), ResolutionNamespace::Type))
                        .chain(std::iter::once((
                            import.demand.spelling(),
                            import.demand.namespace(),
                        )))
                        .enumerate()
                    {
                        if step == nested_route.len() {
                            terminal_owners.extend(owners.iter().map(|(owner, ..)| *owner));
                        }
                        let mut next = BTreeMap::new();
                        let mut singleton_type_owners = BTreeMap::new();
                        for (owner, access, _, _, owner_bridge_allowed) in owners {
                            let mut members = Vec::new();
                            let outcome = typed.visit_member_owner_pages_for_owners(
                                TypedFactRequest::new(&[owner]),
                                cancellation,
                                &mut FactPageVisitor::new(&mut |page| {
                                    for row in page {
                                        let member = row.row();
                                        let singleton_owner = if member.kind()
                                            == ResolutionMemberKind::Field
                                            && language_import_owner_steps_bind_singletons(
                                                import.language,
                                            ) {
                                            self.jvm_singleton_import_type_owner(
                                                member.definition(),
                                            )?
                                        } else {
                                            None
                                        };
                                        if let Some(module) = singleton_owner {
                                            singleton_type_owners
                                                .insert(member.definition(), module);
                                        }
                                        // Methods share Scala's value namespace. A nested
                                        // singleton is also a value, although its physical
                                        // declaration unit is a class. Its published
                                        // singleton relation establishes that term role.
                                        let ordinary = matches!(
                                            (namespace, member.kind()),
                                            (
                                                ResolutionNamespace::Type,
                                                ResolutionMemberKind::NestedType
                                                    | ResolutionMemberKind::AssociatedType
                                            ) | (
                                                ResolutionNamespace::Value,
                                                ResolutionMemberKind::Field
                                            ) | (
                                                ResolutionNamespace::Callable,
                                                ResolutionMemberKind::Method
                                            )
                                        ) || (callables_in_value
                                            && namespace == ResolutionNamespace::Value
                                            && member.kind() == ResolutionMemberKind::Method)
                                            || (namespace == ResolutionNamespace::Callable
                                                && rules
                                                    .member_kinds(namespace)
                                                    .contains(&member.kind()));
                                        let singleton_value = rules.has_singleton_import_values()
                                            && namespace == ResolutionNamespace::Value
                                            && member.kind() == ResolutionMemberKind::NestedType
                                            && self
                                                .jvm_scala_object_definition(member.definition())?;
                                        if ordinary
                                            || singleton_value
                                            || (namespace == ResolutionNamespace::Type
                                                && singleton_owner.is_some())
                                        {
                                            members.push((member.definition(), member.access()));
                                        }
                                    }
                                    Ok(true)
                                }),
                            )?;
                            if outcome.is_cancelled() {
                                return Ok(None);
                            }
                            if step == nested_route.len() {
                                terminal_member_inventory_complete &= outcome.is_exhausted()
                                    && outcome.evidence() == &ResolutionCompletion::Complete;
                            }
                            declared_members_complete &= outcome.is_exhausted()
                                && outcome.evidence() == &ResolutionCompletion::Complete;
                            if version.is_some() && collect_workspace_type_rows {
                                workspace_inventory_complete &= outcome.is_exhausted()
                                    && outcome.evidence() == &ResolutionCompletion::Complete;
                            }
                            members.sort_unstable_by_key(|(definition, _)| *definition);
                            members.dedup();
                            if step == nested_route.len()
                                && members.iter().any(|(member, _)| {
                                    member.ordinal() != Some(ordinal)
                                        || member.local_key().is_none()
                                })
                            {
                                terminal_member_inventory_complete = false;
                            }
                            let member_access: BTreeMap<_, _> = members.iter().copied().collect();
                            let coordinates = members
                                .into_iter()
                                // Stage-only declarations lacking a parser-unit
                                // crosswalk stay inside the retained open gap.
                                .filter(|(member, _)| member.ordinal() == Some(ordinal))
                                .filter_map(|(member, _)| {
                                    member.local_key().map(|key| {
                                        (target, ResolutionLocalKey::new(i64::from(key)))
                                    })
                                })
                                .collect::<Vec<_>>();
                            for chunk in coordinates.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                                let SelectedDefinitionUnitReadOutcome::Ready(rows) = self
                                    .ready
                                    .inventory
                                    .selected_declaration_unit_candidates(chunk, cancellation)?
                                else {
                                    return Ok(None);
                                };
                                let named_keys =
                                    rows.iter().map(|(_, key, _)| *key).collect::<BTreeSet<_>>();
                                declared_members_complete &=
                                    chunk.iter().all(|(_, key)| named_keys.contains(key));
                                if version.is_some()
                                    && collect_workspace_type_rows
                                    && rows.len() != chunk.len()
                                {
                                    workspace_inventory_complete = false;
                                }
                                if step == nested_route.len() && rows.len() != chunk.len() {
                                    terminal_member_inventory_complete = false;
                                }
                                for (_, key, row) in rows {
                                    let member_definition = SemanticId::local(
                                        ordinal,
                                        u32::try_from(key.get())
                                            .expect("a catalog position fits u32"),
                                    );
                                    let unit_kind_matches = (singleton_type_owners.contains_key(&member_definition)
                                        && row.kind == brokk_bifrost_core::analyzer::model::CodeUnitType::Class)
                                        || match namespace {
                                        ResolutionNamespace::Type => {
                                            row.kind
                                                == brokk_bifrost_core::analyzer::model::CodeUnitType::Class
                                        }
                                        ResolutionNamespace::Value => {
                                            row.kind
                                                == brokk_bifrost_core::analyzer::model::CodeUnitType::Field
                                                || (callables_in_value
                                                    && row.kind
                                                        == brokk_bifrost_core::analyzer::model::CodeUnitType::Function)
                                                || (rules.has_singleton_import_values()
                                                    && row.kind
                                                        == brokk_bifrost_core::analyzer::model::CodeUnitType::Class
                                                    && self.jvm_scala_object_definition(
                                                        SemanticId::local(
                                                            ordinal,
                                                            u32::try_from(key.get())
                                                                .expect("a catalog position fits u32"),
                                                        ),
                                                    )?)
                                        }
                                        ResolutionNamespace::Callable => {
                                            row.kind
                                                == brokk_bifrost_core::analyzer::model::CodeUnitType::Function
                                                || (rules.has_callable_import_values()
                                                    && (row.kind
                                                        == brokk_bifrost_core::analyzer::model::CodeUnitType::Field
                                                        || (row.kind
                                                            == brokk_bifrost_core::analyzer::model::CodeUnitType::Class
                                                            // Named Scala imports bind both a
                                                            // class's type and its call role. For
                                                            // wildcard imports, an object is a term
                                                            // when its selected singleton row says so.
                                                            && (import.selector_kind
                                                                == Some(ResolutionImportSelectorKind::Named)
                                                                || row.fq.as_ref().is_some_and(|identity| {
                                                                    identity.segments.last().is_some_and(
                                                                        |(_, spelling)| spelling.ends_with('$'),
                                                                    )
                                                                })
                                                                || self.jvm_scala_object_definition(
                                                                    SemanticId::local(
                                                                        ordinal,
                                                                        u32::try_from(key.get())
                                                                            .expect("a catalog position fits u32"),
                                                                    ),
                                                                )?))))
                                        }
                                        ResolutionNamespace::TypeOrValue => matches!(
                                            row.kind,
                                            brokk_bifrost_core::analyzer::model::CodeUnitType::Class
                                                | brokk_bifrost_core::analyzer::model::CodeUnitType::Field
                                        ),
                                        ResolutionNamespace::Package
                                        | ResolutionNamespace::Constructor
                                        | ResolutionNamespace::Macro
                                        | ResolutionNamespace::Constant => false,
                                    };
                                    if !unit_kind_matches {
                                        if step == nested_route.len() {
                                            terminal_member_inventory_complete = false;
                                        }
                                        continue;
                                    }
                                    let Some(identity) = row.fq.as_ref() else {
                                        if step == nested_route.len() {
                                            terminal_member_inventory_complete = false;
                                        }
                                        declared_members_complete = false;
                                        if version.is_some() && collect_workspace_type_rows {
                                            workspace_inventory_complete = false;
                                        }
                                        continue;
                                    };
                                    if identity.segments.last().is_none_or(|(_, spelling)| {
                                        !jvm_member_name_matches(target_language, spelling, name)
                                    }) {
                                        continue;
                                    }
                                    if step == nested_route.len() {
                                        terminal_owners_with_members.insert(owner);
                                    }
                                    if step + 1 == nested_route.len()
                                        && namespace == ResolutionNamespace::Type
                                    {
                                        *owner_found = true;
                                    }
                                    let member = singleton_type_owners
                                        .get(&member_definition)
                                        .copied()
                                        .unwrap_or(member_definition);
                                    if step + 1 == nested_route.len()
                                        && namespace == ResolutionNamespace::Type
                                    {
                                        owners_found.push(member);
                                    }
                                    let (fq, package_segments) =
                                        super::super::hydrate_unit_fq_with_anchor(
                                            Some(identity),
                                            &row.content_qualifier,
                                            &target_file,
                                            |_, _, _| None,
                                        )?;
                                    let unit = CodeUnit::from_fq(
                                        target_file.clone(),
                                        row.kind,
                                        fq,
                                        package_segments,
                                        row.signature.clone(),
                                        row.flags.synthetic,
                                    );
                                    let (access, member_bridge_allowed) = match self
                                        .jvm_declaration_access(
                                            member,
                                            relation,
                                            &access,
                                            cancellation,
                                        )? {
                                        JvmDeclarationAccess::Ready(access) => (access, true),
                                        JvmDeclarationAccess::Excluded => (access.clone(), false),
                                        JvmDeclarationAccess::Cancelled => return Ok(None),
                                    };
                                    if owner_bridge_allowed
                                        && member_bridge_allowed
                                        && version.is_some()
                                        && collect_workspace_type_rows
                                    {
                                        workspace_type_rows.push((member, unit.clone()));
                                    }
                                    next.entry(member)
                                        .and_modify(
                                            |previous: &mut (
                                                ResolutionCompletion,
                                                ResolutionMemberAccess,
                                                CodeUnit,
                                                bool,
                                            )| {
                                                previous.0 = previous.0.combine(&access);
                                                assert_eq!(previous.2, unit);
                                                previous.3 |=
                                                    owner_bridge_allowed && member_bridge_allowed;
                                            },
                                        )
                                        .or_insert((
                                            access,
                                            member_access[&member],
                                            unit,
                                            owner_bridge_allowed && member_bridge_allowed,
                                        ));
                                }
                            }
                        }
                        owners = next
                            .into_iter()
                            .map(|(member, (completion, access, unit, bridge_allowed))| {
                                (member, completion, access, Some(unit), bridge_allowed)
                            })
                            .collect();
                        if owners.is_empty() {
                            break;
                        }
                    }
                    if !terminal_member_inventory_complete {
                        inherited_route_open = true;
                    }
                    let mut missing_terminal_owners = terminal_owners
                        .into_iter()
                        .filter(|owner| !terminal_owners_with_members.contains(owner))
                        .collect::<Vec<_>>();
                    if !missing_terminal_owners.is_empty() {
                        missing_terminal_owners.sort_unstable();
                        missing_terminal_owners.dedup();
                        let mut supertypes = Vec::new();
                        let outcome = typed.visit_supertype_pages_for_definitions(
                            TypedFactRequest::new(&missing_terminal_owners),
                            cancellation,
                            &mut FactPageVisitor::new(&mut |page| {
                                supertypes.extend(page.iter().map(|row| row.row().clone()));
                                Ok(true)
                            }),
                        )?;
                        if outcome.is_cancelled() {
                            return Ok(None);
                        }
                        inherited_route_open |= !outcome.is_exhausted()
                            || outcome.evidence() != &ResolutionCompletion::Complete
                            || supertypes.iter().any(|row| {
                                row.source_kind()
                                    != Some(ResolutionSupertypeKind::ImplicitSuperclass)
                                    || language_implicit_root_member_names(target_language)
                                        .contains(&import.demand.spelling())
                            });
                    }
                    for (member, access, member_access, unit, bridge_allowed) in owners {
                        let unit = unit.expect("selected import endpoint has a source CodeUnit");
                        if !bridge_allowed {
                            continue;
                        }
                        let Some(node) = lexical.lookup_definition_node(member, cancellation)?
                        else {
                            if cancellation.is_cancelled() {
                                return Ok(None);
                            }
                            return Err(StoreError::corrupt(
                                "selected Java member lacks definition node",
                            ));
                        };
                        let bridge = if target_language == import.language {
                            import.bridge(identity.fragment(), token, access)
                        } else {
                            let Some(visibility) = self.jvm_bridge_visibility(
                                member, relation, cancellation,
                            )? else {
                                return Ok(None);
                            };
                            let target_demand = self.jvm_generated_lookup(
                                target_language,
                                import.demand.namespace(),
                                import.demand.spelling(),
                                ).recipe.clone();
                            let bridge = SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
                                import.source,
                                import.language,
                                import.token,
                                import.anchor,
                                import.anchor_semantic,
                                identity.fragment(),
                                target_language,
                                token,
                                import.prefix_reference,
                                import.route.to_vec(),
                                import.demand.clone(),
                                target_demand,
                                SelectedJvmBridgeEvidence {
                                    provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                                        source_package: package_domain_semantic(import.language, &names),
                                        target_package: package_domain_semantic(target_language, &names),
                                    },
                                    source_namespace: import.demand.namespace(),
                                    target_namespace: import.demand.namespace(),
                                    visibility,
                                    dependency_identity: jvm_dependency_identity(
                                        context,
                                        caller_version,
                                        caller_mount.persisted_relative_path(),
                                        version,
                                        target_mount.persisted_relative_path(),
                                    ),
                                    target_declaration: member,
                                    target_definition: node,
                                },
                                access,
                            );
                            import.rank_bridge(bridge)
                        }.with_selected_member_definition(node);
                        bridges.push(JavaImportMemberCandidate {
                            definition: member,
                            access: member_access,
                            unit,
                            workspace_source: version.is_some(),
                            bridge,
                        });
                    }
                }
            }
        }
        Ok(
            (!cancellation.is_cancelled()).then_some(JavaTypeMemberImportInventory {
                members: bridges,
                owners: owners_found,
                declared_members_complete,
                route_search_complete,
                workspace_type_rows,
                workspace_inventory_complete,
                inherited_route_open,
            }),
        )
    }
}

/// A selected member before the source import's static-access rule is applied.
#[derive(Clone)]
struct JavaImportMemberCandidate {
    definition: SemanticId,
    access: ResolutionMemberAccess,
    unit: CodeUnit,
    workspace_source: bool,
    bridge: SelectedRootBridgeDescriptor,
}

#[derive(Clone)]
pub(super) struct JavaTypeMemberImportInventory {
    members: Vec<JavaImportMemberCandidate>,
    /// The definitions of the owners whose declared members were enumerated,
    /// one per owner the route reached.
    owners: Vec<SemanticId>,
    /// Whether every declared member row of those owners was read and named by
    /// a code unit, so that an absent name is absent from the declarations.
    declared_members_complete: bool,
    /// Every export page and selected owner route was exhausted, independent
    /// of whether one matching member was found.
    route_search_complete: bool,
    workspace_type_rows: Vec<(SemanticId, CodeUnit)>,
    workspace_inventory_complete: bool,
    inherited_route_open: bool,
}

struct JavaPackageTypeImportCandidate {
    unit: Option<CodeUnit>,
    workspace_source: bool,
    bridge: SelectedRootBridgeDescriptor,
}

struct JavaPackageTypeImportInventory {
    candidates: Vec<JavaPackageTypeImportCandidate>,
    workspace_type_rows: Vec<(SemanticId, CodeUnit)>,
    workspace_inventory_complete: bool,
    route_inventory_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedJvmPackagePrecedence {
    tier: Option<PrecedenceTier>,
    candidate_origin_rank: Option<u32>,
}

impl SelectedResolutionOperation<'_, '_> {
    fn java_static_import_bridges(
        &self,
        members: Vec<JavaImportMemberCandidate>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        let typed = self.ready.typed_source();
        let mut bridges = Vec::new();
        for member in members {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if member.access != ResolutionMemberAccess::Type {
                continue;
            }
            // Nested-type lookup uses Type access even for inner classes.
            // Their construction requirement distinguishes them from static
            // nested classes, interfaces, enums and records.
            let mut requires_instance = false;
            let outcome = typed.visit_construction_requirement_pages_for_definitions(
                TypedFactRequest::new(&[member.definition]),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    requires_instance |= page.iter().any(|row| {
                        row.row().kind() == ResolutionConstructionRequirementKind::EnclosingInstance
                    });
                    Ok(true)
                }),
            )?;
            if outcome.is_cancelled() {
                return Ok(None);
            }
            if !requires_instance {
                bridges.push(member.bridge);
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(bridges))
    }
}

impl JavaMemberImportDemand<'_> {
    fn bridge(
        &self,
        target: BindingFragmentId,
        export_token: SemanticId,
        completion: ResolutionCompletion,
    ) -> SelectedRootBridgeDescriptor {
        let bridge = if let Some(prefix) = self.prefix_reference {
            SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                self.source,
                self.language,
                self.token,
                self.anchor,
                self.anchor_semantic,
                target,
                self.language,
                export_token,
                prefix,
                self.route.to_vec(),
                self.demand.clone(),
                self.demand.clone(),
                completion,
            )
        } else {
            SelectedRootBridgeDescriptor::from_selected_path_tokens(
                self.source,
                self.language,
                self.token,
                self.anchor,
                self.anchor_semantic,
                target,
                self.language,
                export_token,
                self.route.to_vec(),
                self.demand.clone(),
                self.demand.clone(),
                completion,
            )
        };
        self.rank_bridge(bridge)
    }

    fn rank_bridge(&self, bridge: SelectedRootBridgeDescriptor) -> SelectedRootBridgeDescriptor {
        let explicit_import = self.selector_kind == Some(ResolutionImportSelectorKind::Named)
            || matches!(
                self.import_kind,
                Some(
                    ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic
                )
            );
        let precedence = explicit_import.then(|| {
            self.import_precedence.unwrap_or(PrecedenceStep {
                tier: PrecedenceTier::ExplicitImport,
                ordinal: 0,
                semantic: self.token,
            })
        });
        let origin = jvm_bridge_import_origin(self.language, self.import_kind, self.selector_kind);
        let rank = self
            .candidate_origin_rank
            .or_else(|| origin.and_then(|origin| binding_origin_rank(self.language, origin)));
        bridge
            .with_precedence(precedence)
            .with_candidate_origin_rank(rank)
            .with_callable_import_half(self.half)
    }
}

impl SelectedResolutionOperation<'_, '_> {
    fn java_package_type_import_bridges(
        &self,
        context: i64,
        caller_version: Option<i64>,
        import: &JavaMemberImportDemand<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        let Some(inventory) = self.java_package_type_import_inventory(
            context,
            caller_version,
            import,
            completion,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(
            inventory
                .candidates
                .into_iter()
                .take(1)
                .map(|candidate| candidate.bridge)
                .collect(),
        ))
    }

    fn java_package_type_import_inventory(
        &self,
        context: i64,
        caller_version: Option<i64>,
        import: &JavaMemberImportDemand<'_>,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JavaPackageTypeImportInventory>> {
        let demand = import.demand.semantic(&self.ready.shared_names());
        let collect_workspace_type_rows = matches!(
            import.import_kind,
            Some(ResolutionImportRouteKind::SingleType)
        );
        let mut candidates = Vec::new();
        let mut workspace_type_rows = Vec::new();
        let mut workspace_inventory_complete = true;
        let spelling = import
            .route
            .iter()
            .map(ResolutionLookupSemanticRecipe::spelling)
            .collect::<Vec<_>>()
            .join(".");
        let Some(targets) = self.jvm_named_import_targets(
            nominal_package_rules(import.language)
                .expect("caller belongs to a nominal family")
                .own_language_target_mounts(import.language),
            &spelling,
            import.demand.spelling(),
            &[import.demand.namespace()],
            import.language,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut route_inventory_complete = !targets.ordered.is_empty()
            || brokk_bifrost_jvm::intrinsics::default_provider_names(Language::Java, &spelling)
                .is_some();
        let caller_mount = self
            .mount_table()
            .mount_for_fragment(import.source)?
            .expect("Java import source remains selected");
        for (target, target_file_version) in targets.ordered.iter().copied() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ordinal = SelectedResolutionMountOrdinal::new(target);
            let target_mount = self.mount_table().mount_by_ordinal(ordinal)?;
            let source_access = self.jvm_unit_access_completion(
                caller_mount.semantic_language(),
                context,
                caller_version,
                caller_mount.persisted_relative_path(),
                target_file_version,
                target_mount.persisted_relative_path(),
                completion,
            )?;
            let Some(source_access) = source_access else {
                continue;
            };
            let mut descriptors = Vec::new();
            let mut target_rules = JavaPackageTargetRules {
                operation: self,
                import,
                target: &target_mount,
                demand,
                spelling: &spelling,
                source_access: &source_access,
                workspace_source: target_file_version.is_some(),
                collect_workspace_type_rows,
                workspace_type_rows,
                workspace_inventory_complete,
                route_inventory_complete: &mut route_inventory_complete,
            };
            let rules = match append_root_target(
                &self.ready,
                import.half,
                &mut target_rules,
                &mut descriptors,
                cancellation,
            )? {
                RootBridgeStep::Ready(rules) => rules,
                RootBridgeStep::Unavailable | RootBridgeStep::Cancelled => return Ok(None),
            };
            let state = rules.state.into_inner();
            workspace_type_rows = state.workspace_type_rows;
            workspace_inventory_complete = state.workspace_inventory_complete;
            assert_eq!(descriptors.len(), state.admitted.len());
            for (bridge, metadata) in descriptors.into_iter().zip(state.admitted) {
                assert_eq!(bridge.target_definition(), Some(metadata.definition));
                candidates.push(JavaPackageTypeImportCandidate {
                    unit: metadata.unit,
                    workspace_source: target_file_version.is_some(),
                    bridge,
                });
            }
            if !collect_workspace_type_rows
                && import.import_kind != Some(ResolutionImportRouteKind::TypeOnDemand)
                && !candidates.is_empty()
            {
                return Ok(Some(JavaPackageTypeImportInventory {
                    candidates,
                    workspace_type_rows,
                    workspace_inventory_complete,
                    route_inventory_complete,
                }));
            }
        }
        Ok(Some(JavaPackageTypeImportInventory {
            candidates,
            workspace_type_rows,
            workspace_inventory_complete,
            route_inventory_complete,
        }))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn jvm_lexical_import_qualifier(
        &self,
        node: BindingNodeId,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        let lexical = self.ready.lexical_source();
        let classified = lexical.classify_endpoint_nodes(&[node], cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(reference) = classified.iter().find_map(|row| row.reference()) else {
            return Ok(Some(false));
        };
        let (rows, terminal, _) = lexical
            .lookup_reference_seeds(
                &[crate::analyzer::resolution::ResolutionQuery::new(reference)],
                cancellation,
            )?
            .into_parts();
        if terminal != crate::analyzer::resolution::ReferenceSeedReadTerminal::Exhausted {
            return Ok(None);
        }
        Ok(Some(rows.iter().filter_map(|row| row.seed()).filter_map(|seed| seed.site_metadata())
            .any(|metadata| metadata.site_kind() ==
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ImportQualifierReference)))
    }

    pub(super) fn jvm_qualified_type_bridges(
        &self,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let SelectedRootPathHalf::Reference { identity, .. } = half else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let source_mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("selected source half has its mount");
        nominal_language_rules(source_mount.semantic_language())
            .expect("caller belongs to a nominal family")
            .qualified_type_bridges(self, half, completion, cancellation)
    }

    pub(super) fn java_qualified_type_publication(
        &self,
        _language: Language,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        Ok(self
            .java_qualified_type_bridges(half, completion, cancellation)?
            .map(|bridges| JvmRoutePublication {
                bridges,
                selected_targets: BTreeSet::new(),
                complete: false,
            }))
    }

    pub(super) fn common_qualified_type_publication(
        &self,
        language: Language,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let SelectedRootPathHalf::Reference {
            source_reference, ..
        } = half
        else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let Some(mut publication) =
            self.jvm_qualified_type_exports(half, completion, cancellation)?
        else {
            return Ok(None);
        };
        if let Some(origin) = jvm_lexical_import_head_origin(language) {
            let Some(import_head) =
                self.jvm_lexical_import_qualifier(*source_reference, cancellation)?
            else {
                return Ok(None);
            };
            if import_head {
                let rank = binding_origin_rank(language, origin);
                publication.bridges = publication
                    .bridges
                    .into_iter()
                    .map(|bridge| bridge.with_candidate_origin_rank(rank))
                    .collect();
            }
        }
        Ok(Some(publication))
    }

    /// Confirm a fully qualified Kotlin or Scala type through the selected
    /// package row and the target file's selected Type export. Spelling only
    /// forms the indexed package key and Type lookup; neither can authorize a
    /// bridge without both selected rows.
    fn jvm_qualified_type_exports(
        &self,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let SelectedRootPathHalf::Reference {
            identity,
            source_reference,
            route,
            anchor,
            ..
        } = half
        else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("selected source half has its mount");
        if !nominal_language_rules(mount.semantic_language())
            .expect("caller belongs to a nominal family")
            .lexical_import_anchors()
            .contains(&ResolutionRootImportAnchor::Lexical)
            || *anchor != ResolutionRootImportAnchor::Lexical
            || route.is_empty()
        {
            return self.jvm_qualified_type_exports_for_route(half, completion, None, cancellation);
        }
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let Some(recipes) =
            self.jvm_lookup_recipes(identity.fragment(), route.iter().copied(), cancellation)?
        else {
            return Ok(None);
        };
        let prefixes =
            self.scala_reference_package_prefixes(record.blob_id(), *source_reference)?;
        let routes = jvm_import_lookup_routes(
            Language::Scala,
            *anchor,
            &prefixes,
            &recipes,
            None,
            &[],
            &[],
        );
        let mut last = None;
        for lookup in routes {
            let Some(publication) = self.jvm_qualified_type_exports_for_route(
                half,
                completion,
                Some(&lookup),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            if !publication.selected_targets.is_empty() {
                return Ok(Some(publication));
            }
            last = Some(publication);
        }
        Ok(last)
    }

    fn jvm_qualified_type_exports_for_route(
        &self,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        lookup_route: Option<&[ResolutionLookupSemanticRecipe]>,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let SelectedRootPathHalf::Reference {
            identity,
            prefix_reference,
            source_scope_head,
            source_reference,
            route,
            token,
            anchor,
            anchor_semantic,
            demand,
            ..
        } = half
        else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let source_mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("selected source half has its mount");
        let source_language = source_mount.semantic_language();
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let family = rules.family();
        assert!(family.admits_qualified_type_bridge_source(source_language));
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source_mount.ordinal())?;
        let connection = self.ready.inventory.connection();
        let context = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row([source_language.config_label()], |row| row.get::<_, i64>(0))?;
        let caller_package: Option<String> = connection
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [source_record.blob_id()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(mut recipes) = self.jvm_lookup_recipes(
            identity.fragment(),
            route.iter().copied().chain(std::iter::once(*demand)),
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let source_demand = recipes.pop().expect("qualified type demand");
        let source_namespace = source_demand.namespace();
        if !matches!(
            source_namespace,
            ResolutionNamespace::Type | ResolutionNamespace::Value
        ) {
            return Ok(Some(JvmRoutePublication {
                bridges: Vec::new(),
                selected_targets: BTreeSet::new(),
                complete: false,
            }));
        }
        assert_eq!(
            source_demand.identity_domain(),
            language_identity_domain(source_language)
        );
        let lookup_route = lookup_route.unwrap_or(&recipes);
        let package = if lookup_route.is_empty() {
            let Some(package) = caller_package.as_deref() else {
                return Ok(Some(JvmRoutePublication {
                    bridges: Vec::new(),
                    selected_targets: BTreeSet::new(),
                    complete: false,
                }));
            };
            package.to_owned()
        } else {
            lookup_route
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".")
        };
        let names = self.ready.shared_names();
        let targets = self.jvm_import_targets(family.import_target_mounts(), &package)?;
        let mut bridges = Vec::new();
        let mut selected_targets = BTreeSet::new();
        let mut route_complete =
            completion == &ResolutionCompletion::Complete && !targets.ordered.is_empty();
        let relation = JvmDeclarationAccessContext::between(caller_package.as_deref(), &package)
            .with_reference(*prefix_reference)
            .with_scope(Some(*source_scope_head))
            .with_source_node(*source_reference);
        for (ordinal, target_version) in targets.ordered.iter().copied() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let target_ordinal = SelectedResolutionMountOrdinal::new(ordinal);
            let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
            let target_language = target_mount.semantic_language();
            if !family.admits(target_language) {
                route_complete = false;
                continue;
            }
            let Some(access) = self.jvm_qualified_source_access_completion(
                source_language,
                context,
                source_record.file_version_id(),
                source_record.persisted_relative_path(),
                target_version,
                target_mount.persisted_relative_path(),
                completion,
            )?
            else {
                route_complete = false;
                continue;
            };
            route_complete &= access == ResolutionCompletion::Complete;
            let target_lookup = self
                .jvm_generated_lookup(target_language, source_namespace, source_demand.spelling())
                .recipe
                .clone();
            let target_lookup_semantic = target_lookup.semantic(&names);
            let SelectedPackageRows::Ready(package_members) = self.jvm_package_members_for_lookup(
                target_ordinal,
                target_lookup_semantic,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let matching_members = package_members
                .iter()
                .copied()
                .filter(|member| {
                    member.namespace == source_namespace && member.lookup == target_lookup_semantic
                })
                .collect::<Vec<_>>();
            if matching_members.is_empty() {
                continue;
            }
            let matching_definitions = matching_members
                .iter()
                .map(|member| member.definition)
                .collect::<BTreeSet<_>>();
            let mut published_definitions = BTreeSet::new();
            let Some(exports_read) = self.jvm_root_exports(target_ordinal, cancellation)? else {
                return Ok(None);
            };
            let outcome = &exports_read.outcome;
            let exports = exports_read.halves.iter()
                .filter(|half| matches!(half, SelectedRootPathHalf::Export { demand, .. } if *demand == target_lookup_semantic))
                .cloned();
            route_complete &=
                outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete;
            for export in exports {
                let SelectedRootPathHalf::Export {
                    identity: export_identity,
                    token: export_token,
                    definition,
                    ..
                } = &export
                else {
                    unreachable!("selected export visitor");
                };
                let Some(endpoints) =
                    self.jvm_endpoint_classifications(*definition, cancellation)?
                else {
                    return Ok(None);
                };
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let definition_semantic = endpoints
                    .first()
                    .and_then(|endpoint| endpoint.definition())
                    .ok_or_else(|| {
                        StoreError::corrupt("selected JVM type export lacks a declaration")
                    })?;
                let Some(member) = matching_members
                    .iter()
                    .find(|member| member.definition == definition_semantic)
                else {
                    continue;
                };
                let bridge_completion = match self.jvm_declaration_access(
                    member.definition,
                    relation,
                    &access,
                    cancellation,
                )? {
                    JvmDeclarationAccess::Ready(completion) => {
                        route_complete &= completion == ResolutionCompletion::Complete;
                        completion
                    }
                    JvmDeclarationAccess::Excluded => {
                        published_definitions.insert(member.definition);
                        continue;
                    }
                    JvmDeclarationAccess::Cancelled => return Ok(None),
                };
                let bridge = if source_language == target_language {
                    if let Some(prefix) = prefix_reference {
                        SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                            identity.fragment(),
                            source_language,
                            *token,
                            *anchor,
                            *anchor_semantic,
                            export_identity.fragment(),
                            target_language,
                            *export_token,
                            *prefix,
                            recipes.clone(),
                            source_demand.clone(),
                            target_lookup.clone(),
                            bridge_completion,
                        )
                    } else {
                        SelectedRootBridgeDescriptor::from_selected_path_tokens(
                            identity.fragment(),
                            source_language,
                            *token,
                            *anchor,
                            *anchor_semantic,
                            export_identity.fragment(),
                            target_language,
                            *export_token,
                            recipes.clone(),
                            source_demand.clone(),
                            target_lookup.clone(),
                            bridge_completion,
                        )
                    }
                } else {
                    let Some(visibility) =
                        self.jvm_bridge_visibility(member.definition, relation, cancellation)?
                    else {
                        return Ok(None);
                    };
                    SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
                        identity.fragment(),
                        source_language,
                        *token,
                        *anchor,
                        *anchor_semantic,
                        export_identity.fragment(),
                        target_language,
                        *export_token,
                        *prefix_reference,
                        recipes.clone(),
                        source_demand.clone(),
                        target_lookup.clone(),
                        SelectedJvmBridgeEvidence {
                            provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                                source_package: package_domain_semantic(source_language, &names),
                                target_package: member.domain,
                            },
                            source_namespace,
                            target_namespace: source_namespace,
                            visibility,
                            dependency_identity: jvm_dependency_identity(
                                context,
                                source_record.file_version_id(),
                                source_record.persisted_relative_path(),
                                target_version,
                                target_mount.persisted_relative_path(),
                            ),
                            target_declaration: member.definition,
                            target_definition: *definition,
                        },
                        bridge_completion,
                    )
                };
                published_definitions.insert(member.definition);
                selected_targets.insert(member.definition);
                bridges.push(bridge.with_selected_export(&names, &export));
            }
            route_complete &= matching_definitions.is_subset(&published_definitions);
        }
        if family.member_continuation_mounts(source_language).is_some() {
            // The package route may also end inside a type: `pkg.Outer.Inner`
            // names a member of the type the package declares.
            let import = JavaMemberImportDemand {
                half,
                import_kind: None,
                caller_package: caller_package.as_deref(),
                source: identity.fragment(),
                token: *token,
                prefix_reference: *prefix_reference,
                scope_head: Some(*source_scope_head),
                anchor: *anchor,
                anchor_semantic: *anchor_semantic,
                selector_kind: None,
                import_precedence: None,
                candidate_origin_rank: None,
                route: &recipes,
                lookup_route,
                demand: &source_demand,
                language: source_language,
            };
            let mut owner_found = false;
            let Some(inventory) = self.jvm_type_member_import_candidates(
                context,
                source_record.file_version_id(),
                &import,
                completion,
                cancellation,
                &mut owner_found,
            )?
            else {
                return Ok(None);
            };
            route_complete &= inventory.workspace_inventory_complete;
            bridges.extend(inventory.members.into_iter().map(|member| {
                selected_targets.insert(member.definition);
                member.bridge
            }));
        }
        Ok(
            (!cancellation.is_cancelled()).then_some(JvmRoutePublication {
                bridges,
                selected_targets,
                complete: route_complete,
            }),
        )
    }

    pub(super) fn java_qualified_type_bridges(
        &self,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        let SelectedRootPathHalf::Reference {
            identity,
            prefix_reference,
            route,
            token,
            anchor,
            anchor_semantic,
            demand,
            ..
        } = half
        else {
            unreachable!("qualified Java demand has a reference half");
        };
        let mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("selected source half has its mount");
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let connection = self.ready.inventory.connection();
        let context: i64 = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row(["java"], |row| row.get(0))?;
        let package: Option<String> = connection
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [record.blob_id()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(mut recipes) = self.jvm_lookup_recipes(
            identity.fragment(),
            route.iter().copied().chain(std::iter::once(*demand)),
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let demand = recipes.pop().expect("qualified type demand");
        let import = JavaMemberImportDemand {
            half,
            import_kind: None,
            caller_package: package.as_deref(),
            source: identity.fragment(),
            token: *token,
            prefix_reference: *prefix_reference,
            scope_head: None,
            anchor: *anchor,
            anchor_semantic: *anchor_semantic,
            selector_kind: None,
            import_precedence: None,
            candidate_origin_rank: None,
            route: &recipes,
            lookup_route: &recipes,
            demand: &demand,
            language: Language::Java,
        };
        let Some(mut bridges) = self.java_package_type_import_bridges(
            context,
            record.file_version_id(),
            &import,
            completion,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut owner_found = false;
        let Some(member_inventory) = self.jvm_type_member_import_candidates(
            context,
            record.file_version_id(),
            &import,
            completion,
            cancellation,
            &mut owner_found,
        )?
        else {
            return Ok(None);
        };
        bridges.extend(
            member_inventory
                .members
                .into_iter()
                .map(|member| member.bridge),
        );
        Ok(Some(bridges))
    }
}

// Read once before source polling. Reconstructing a half view after a wait
// only borrows these facts; it must not repeat caller/context SQL.
pub(super) struct JvmSourceReaderContext {
    pub language: Language,
    pub source_reference: BindingNodeId,
    pub package: Option<String>,
    context: i64,
    mount: SelectedResolutionMountOrdinal,
    version: Option<i64>,
    path: String,
    pub precedence: Option<PrecedenceStep>,
    pub candidate_origin_rank: Option<u32>,
    pub package_origin_rank: Option<u32>,
    pub observations: RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
}
impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn jvm_source_reader_context(
        &self,
        half: &SelectedRootPathHalf,
    ) -> Result<JvmSourceReaderContext> {
        let (identity, source_reference, precedence) = match half {
            SelectedRootPathHalf::Reference {
                identity,
                source_reference,
                ..
            } => (*identity, *source_reference, &[][..]),
            SelectedRootPathHalf::Import {
                identity,
                source_scope_head,
                precedence,
                ..
            } => (*identity, *source_scope_head, precedence.as_ref()),
            _ => unreachable!("JVM source half"),
        };
        let mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("source half is mounted");
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let context = self
            .ready
            .inventory
            .connection()
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row([mount.semantic_language().config_label()], |row| {
                row.get::<_, i64>(0)
            })?;
        let mut package = self
            .ready
            .inventory
            .connection()
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [record.blob_id()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        if let SelectedRootPathHalf::Import { token, .. } = half {
            package = nominal_language_rules(mount.semantic_language())
                .expect("caller belongs to a nominal family")
                .lexical_import_package_prefixes(self, record.blob_id(), *token)?
                .pop()
                .or(package);
        }
        Ok(JvmSourceReaderContext {
            observations: RefCell::new(Vec::new()),
            package_origin_rank: None,
            language: mount.semantic_language(),
            source_reference,
            package,
            context,
            mount: mount.ordinal(),
            version: record.file_version_id(),
            path: record.persisted_relative_path().to_owned(),
            precedence: precedence
                .iter()
                .copied()
                .find(|step| step.tier != PrecedenceTier::CandidateOriginRank),
            candidate_origin_rank: precedence
                .iter()
                .find(|step| step.tier == PrecedenceTier::CandidateOriginRank)
                .map(|step| step.ordinal),
        })
    }
}

// Source member inventory and projection keep authority separate from exports.
// The caller supplies one scheduler-selected owner; no hierarchy walk occurs here.
pub(super) struct JvmSourceMemberRows {
    pub rows: Vec<crate::analyzer::resolution::LoweredMemberOwnerProperty>,
    pub observation: crate::analyzer::resolution::HierarchyProviderObservation,
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn jvm_source_owner_is_in_caller_file(
        &self,
        reader: &JvmSourceReaderContext,
        owner: SemanticId,
    ) -> Result<bool> {
        let Some(ordinal) = owner.ordinal() else {
            return Ok(false);
        };
        if ordinal == reader.mount.get() {
            return Ok(true);
        }
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        Ok(record.file_version_id() == reader.version)
    }

    pub(super) fn jvm_source_member_rows(
        &self,
        owner: SemanticId,
        route: &super::demand_closure::MemberRouteContext<
            '_,
            super::jvm_demand::JvmBindingPrecedence,
        >,
        occurrence: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmSourceMemberRows>> {
        use crate::analyzer::resolution::{
            HierarchyProviderAuthority, HierarchyProviderKey, HierarchyProviderObservation,
            HierarchyProviderOperand, HierarchyProviderVisit,
        };
        let lookup = route.lookup;
        let step =
            u32::try_from(route.cursor.consumed_prefix_segments).expect("route step fits u32");
        let mut rows = Vec::new();
        let outcome = self
            .ready
            .typed_source()
            .visit_member_owner_pages_for_owners(
                TypedFactRequest::new(&[owner]),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    rows.extend(page.iter().map(|row| row.row().clone()));
                    Ok(true)
                }),
            )?;
        if outcome.is_cancelled() {
            return Ok(None);
        }
        assert!(rows.iter().all(|row| row.owner_definition() == owner));
        // An exhausted empty page is an observation too. It certifies only
        // this declaration inventory, never an unsearched hierarchy boundary.
        let observation = HierarchyProviderObservation {
            provider: HierarchyProviderKey::source(
                owner,
                lookup.semantic(&self.ready.shared_names()),
                route.namespace,
                HierarchyProviderAuthority::Declaration(owner),
                HierarchyProviderOperand::CandidateInventory,
                occurrence,
                step,
            ),
            visit: HierarchyProviderVisit::Observed,
            completion: outcome.evidence().clone(),
            inventory_complete: Some(outcome.is_exhausted()),
        };
        Ok(Some(JvmSourceMemberRows { rows, observation }))
    }

    pub(super) fn jvm_source_member_target(
        &self,
        source: &super::demand_closure::SourceHalf,
        reader: &JvmSourceReaderContext,
        route: &super::demand_closure::MemberRouteContext<
            '_,
            super::jvm_demand::JvmBindingPrecedence,
        >,
        row: &crate::analyzer::resolution::LoweredMemberOwnerProperty,
        cancellation: &CancellationToken,
    ) -> Result<super::demand_closure::Read<Option<super::demand_closure::SelectedMemberRouteTarget>>>
    {
        use super::demand_closure::{
            BridgeMaterial, Read, RouteLocation, SelectedMemberRouteTarget, SelectedMemberTarget,
        };
        let lookup = route.lookup;
        let completion = &route.selection.completion;
        let language = reader.language;
        let rules = nominal_language_rules(language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let namespace = if route.position == super::demand_closure::MemberRoutePosition::Segment {
            rules.intermediate_member_namespace(route.namespace)
        } else {
            route.namespace
        };
        if !jvm_member_kind_matches(language, namespace, row.kind())
            || !jvm_member_name_matches(language, row.member_name(), lookup.spelling())
        {
            return Ok(Read::ready(None));
        }
        if rules.has_singleton_import_values()
            && matches!(
                namespace,
                ResolutionNamespace::Value | ResolutionNamespace::Callable
            )
            && row.kind() == ResolutionMemberKind::NestedType
            && !self.jvm_scala_object_definition(row.definition())?
        {
            return Ok(Read::ready(None));
        }
        let definition = row.definition();
        let Some(ordinal) = definition.ordinal() else {
            let gap = self.ready.context_identities.named_semantic(
                CanonicalHasher::new(b"jvm-external-member-source-unavailable:v1").finish(),
                "jvm-external-member-source-unavailable",
                "External member has no source declaration to hydrate",
            );
            return Ok(Read::Unavailable {
                reason:
                    crate::analyzer::resolution::DemandRootUnavailableReason::IncompletePreparation,
                completion: completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(gap),
                ])),
            });
        };
        let target = SelectedResolutionMountOrdinal::new(ordinal);
        let mount = self.mount_table().mount_by_ordinal(target)?;
        if !family.admits(mount.semantic_language()) {
            return Ok(Read::ready(None));
        }
        let target_record = self.ready.inventory.mount_record_by_ordinal(target)?;
        let target_package: Option<String> = self
            .ready
            .inventory
            .connection()
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [target_record.blob_id()],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let mut relation = JvmDeclarationAccessContext::between(
            reader.package.as_deref(),
            target_package.as_deref().unwrap_or(""),
        )
        .with_reference(source.prefix)
        .with_scope(Some(source.scope))
        .with_source_node(reader.source_reference);
        if source.is_import {
            relation = relation.with_import(source.token);
        }
        let access = if source.is_import {
            completion.clone()
        } else {
            let Some(access) = self.jvm_qualified_source_access_completion(
                language,
                reader.context,
                reader.version,
                &reader.path,
                target_record.file_version_id(),
                target_record.persisted_relative_path(),
                completion,
            )?
            else {
                let gap = self.ready.context_identities.named_semantic(
                    CanonicalHasher::new(b"jvm-source-member-access-unavailable:v1").finish(),
                    "jvm-source-member-access-unavailable",
                    "Source declaration access preparation is unavailable",
                );
                return Ok(Read::Unavailable {
                    reason: crate::analyzer::resolution::DemandRootUnavailableReason::IncompletePreparation,
                    completion: completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(gap),
                    ])),
                });
            };
            access
        };
        let decision = self.jvm_declaration_access(definition, relation, &access, cancellation)?;
        let observed = match &decision {
            JvmDeclarationAccess::Ready(completion) => completion.clone(),
            JvmDeclarationAccess::Excluded => access,
            JvmDeclarationAccess::Cancelled => return Ok(Read::Cancelled(cancelled_completion())),
        };
        use crate::analyzer::resolution::{
            HierarchyProviderAuthority, HierarchyProviderKey, HierarchyProviderObservation,
            HierarchyProviderOperand, HierarchyProviderVisit,
        };
        reader
            .observations
            .borrow_mut()
            .push(HierarchyProviderObservation {
                provider: HierarchyProviderKey::source(
                    row.owner_definition(),
                    lookup.semantic(&self.ready.shared_names()),
                    namespace,
                    HierarchyProviderAuthority::Declaration(definition),
                    HierarchyProviderOperand::Access { target: definition },
                    source.token,
                    u32::try_from(route.cursor.consumed_prefix_segments)
                        .expect("route step fits u32"),
                ),
                visit: HierarchyProviderVisit::Observed,
                completion: observed.clone(),
                inventory_complete: None,
            });
        if matches!(decision, JvmDeclarationAccess::Excluded) {
            return Ok(Read::Ready {
                value: None,
                completion: observed,
            });
        }
        let completion = observed;
        let Some(node) = self
            .ready
            .lexical_source()
            .lookup_definition_node(definition, cancellation)?
        else {
            if cancellation.is_cancelled() {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            return Err(StoreError::corrupt(
                "selected JVM source member lacks a definition node",
            ));
        };
        let target_language = mount.semantic_language();
        let target_namespace = if namespace == ResolutionNamespace::TypeOrValue {
            member_namespace(row.kind()).expect("selected member has an effective namespace")
        } else {
            namespace
        };
        let target_lookup = self
            .jvm_generated_lookup(target_language, target_namespace, lookup.spelling())
            .recipe
            .clone();
        let cross_language_evidence = if language == target_language {
            None
        } else {
            let Some(visibility) =
                self.jvm_bridge_visibility(definition, relation, cancellation)?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            let names = self.ready.shared_names();
            Some(SelectedJvmBridgeEvidence {
                provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                    source_package: package_domain_semantic(language, &names),
                    target_package: package_domain_semantic(target_language, &names),
                },
                source_namespace: target_namespace,
                target_namespace: target_lookup.namespace(),
                visibility,
                dependency_identity: jvm_dependency_identity(
                    reader.context,
                    reader.version,
                    &reader.path,
                    target_record.file_version_id(),
                    target_record.persisted_relative_path(),
                ),
                target_declaration: definition,
                target_definition: node,
            })
        };
        Ok(Read::Ready {
            value: Some(SelectedMemberRouteTarget {
                target: SelectedMemberTarget {
                    fragment: mount.fragment(),
                    token: row.owner_definition(),
                    definition: node,
                    lookup: target_lookup,
                    completion: completion.clone(),
                },
                location: RouteLocation::Owner {
                    definition,
                    scope: row.source_owner_scope_head(),
                },
                namespace: target_namespace,
                material: BridgeMaterial {
                    source_language: language,
                    target_language,
                    precedence: reader.precedence,
                    candidate_origin_rank: reader.candidate_origin_rank,
                    target_definition: Some(node),
                    cross_language_evidence,
                    callable_import: source.is_import.then_some(source.token),
                },
            }),
            completion,
        })
    }
}

fn jvm_member_kind_matches(
    language: Language,
    namespace: ResolutionNamespace,
    kind: ResolutionMemberKind,
) -> bool {
    nominal_language_rules(language)
        .expect("caller belongs to a nominal family")
        .member_kinds(namespace)
        .contains(&kind)
}

// One terminal package read. The shared source-half loop owns route traversal,
// candidate proofs and descriptor construction; this reader never selects a
// member continuation.
pub(super) struct JvmPurePackageExport {
    pub export: SelectedRootPathHalf,
    pub declaration: SemanticId,
    pub lookup: ResolutionLookupSemanticRecipe,
    pub completion: ResolutionCompletion,
    pub material: super::demand_closure::BridgeMaterial,
}

pub(super) struct JvmPurePackageRows {
    pub exports: Vec<JvmPurePackageExport>,
    pub external_owner: Option<SemanticId>,
    pub complete: bool,
    pub observations: Vec<crate::analyzer::resolution::HierarchyProviderObservation>,
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn jvm_pure_package_exports(
        &self,
        source: &super::demand_closure::SourceHalf,
        requested: &ResolutionLookupSemanticRecipe,
        package: &str,
        reader: &JvmSourceReaderContext,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmPurePackageRows>> {
        let source_language = reader.language;
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let caller_package = reader.package.as_deref();
        let context = reader.context;
        let relation = JvmDeclarationAccessContext::between(caller_package, package)
            .with_reference(source.prefix);
        let relation = match rules.package_access_anchor() {
            super::nominal_rules::PackageAccessAnchor::ImportToken => {
                relation.with_import(source.token)
            }
            super::nominal_rules::PackageAccessAnchor::LexicalSource => relation
                .with_scope(Some(source.scope))
                .with_source_node(reader.source_reference),
        };
        let provider = rules.pure_package_export_provider();
        let targets = self.jvm_import_targets(provider.mounts, package)?;
        let names = self.ready.shared_names();
        let mut result = Vec::new();
        let mut observations = Vec::new();
        use crate::analyzer::resolution::{
            HierarchyProviderAuthority, HierarchyProviderKey, HierarchyProviderObservation,
            HierarchyProviderOperand, HierarchyProviderVisit,
        };
        // The selected package mount list is an independent inventory. It
        // remains observed even when it has no exports.
        observations.push(HierarchyProviderObservation {
            provider: HierarchyProviderKey::source(
                source.token,
                requested.semantic(&names),
                requested.namespace(),
                HierarchyProviderAuthority::Context {
                    mount: reader.mount.get(),
                    version: context,
                    order: 0,
                    blob: Some(source.identity.fragment()),
                },
                HierarchyProviderOperand::PackageInventory,
                source.token,
                0,
            ),
            visit: HierarchyProviderVisit::Observed,
            completion: completion.clone(),
            inventory_complete: Some(true),
        });
        let mut complete = rules.has_package_member_inventory()
            && completion == &ResolutionCompletion::Complete
            && !targets.ordered.is_empty();
        for (ordinal, version) in targets.ordered.iter().copied() {
            let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
            let mount = self.mount_table().mount_by_ordinal(ordinal)?;
            let target_language = mount.semantic_language();
            if !family.admits(target_language) {
                complete = false;
                continue;
            }
            let Some(access) = self.jvm_qualified_source_access_completion(
                source_language,
                context,
                reader.version,
                &reader.path,
                version,
                mount.persisted_relative_path(),
                completion,
            )?
            else {
                complete = false;
                continue;
            };
            complete &= access == ResolutionCompletion::Complete;
            let lookup = self
                .jvm_generated_lookup(target_language, requested.namespace(), requested.spelling())
                .recipe
                .clone();
            let lookup_semantic = lookup.semantic(&names);
            let members = if let Some(read) = provider.members {
                let Some(members) = read(self, ordinal, lookup_semantic, cancellation)? else {
                    return Ok(None);
                };
                Some(members)
            } else {
                None
            };
            if rules.has_package_member_inventory() {
                observations.push(HierarchyProviderObservation {
                    provider: HierarchyProviderKey::source(
                        source.token,
                        lookup_semantic,
                        requested.namespace(),
                        HierarchyProviderAuthority::Context {
                            mount: ordinal.get(),
                            version: version.unwrap_or(0),
                            order: 0,
                            blob: Some(mount.fragment()),
                        },
                        HierarchyProviderOperand::CandidateInventory,
                        source.token,
                        0,
                    ),
                    visit: HierarchyProviderVisit::Observed,
                    completion: ResolutionCompletion::Complete,
                    inventory_complete: Some(true),
                });
            }
            if members.as_ref().is_some_and(|members| members.is_empty()) {
                continue;
            }
            let matching = members
                .iter()
                .flat_map(|members| members.iter())
                .filter(|member| member.namespace == requested.namespace())
                .map(|member| member.definition)
                .collect::<BTreeSet<_>>();
            let mut published = BTreeSet::new();
            let Some(exports) = self.jvm_root_exports(ordinal, cancellation)? else {
                return Ok(None);
            };
            observations.push(HierarchyProviderObservation {
                provider: HierarchyProviderKey::source(
                    source.token,
                    lookup_semantic,
                    requested.namespace(),
                    HierarchyProviderAuthority::Context {
                        mount: ordinal.get(),
                        version: version.unwrap_or(0),
                        order: 0,
                        blob: Some(mount.fragment()),
                    },
                    HierarchyProviderOperand::NamespaceInventory,
                    source.token,
                    0,
                ),
                visit: HierarchyProviderVisit::Observed,
                completion: exports.outcome.evidence().clone(),
                inventory_complete: Some(exports.outcome.is_exhausted()),
            });
            complete &= exports.outcome.is_exhausted()
                && exports.outcome.evidence() == &ResolutionCompletion::Complete;
            for export in exports.halves.iter() {
                let SelectedRootPathHalf::Export {
                    demand, definition, ..
                } = export
                else {
                    unreachable!("export reader");
                };
                if *demand != lookup_semantic {
                    continue;
                }
                let Some(definitions) =
                    self.jvm_endpoint_classifications(*definition, cancellation)?
                else {
                    return Ok(None);
                };
                let semantic = definitions
                    .first()
                    .and_then(|row| row.definition())
                    .ok_or_else(|| StoreError::corrupt("pure package export lacks declaration"))?;
                let member = members
                    .iter()
                    .flat_map(|members| members.iter())
                    .find(|member| {
                        member.definition == semantic && member.namespace == requested.namespace()
                    });
                if members.is_some() && member.is_none() {
                    continue;
                }
                let evidence =
                    match self.jvm_declaration_access(semantic, relation, &access, cancellation)? {
                        JvmDeclarationAccess::Ready(value) => value,
                        JvmDeclarationAccess::Excluded => {
                            published.insert(semantic);
                            continue;
                        }
                        JvmDeclarationAccess::Cancelled => return Ok(None),
                    };
                complete &= evidence == ResolutionCompletion::Complete;
                let cross_language_evidence = if source_language == target_language {
                    None
                } else {
                    let Some(visibility) =
                        self.jvm_bridge_visibility(semantic, relation, cancellation)?
                    else {
                        return Ok(None);
                    };
                    Some(SelectedJvmBridgeEvidence {
                        provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                            source_package: package_domain_semantic(source_language, &names),
                            target_package: member
                                .expect("peer package export has a member row")
                                .domain,
                        },
                        source_namespace: requested.namespace(),
                        target_namespace: lookup.namespace(),
                        visibility,
                        dependency_identity: jvm_dependency_identity(
                            context,
                            reader.version,
                            &reader.path,
                            version,
                            mount.persisted_relative_path(),
                        ),
                        target_declaration: semantic,
                        target_definition: *definition,
                    })
                };
                published.insert(semantic);
                result.push(JvmPurePackageExport {
                    export: export.clone(),
                    declaration: semantic,
                    lookup: lookup.clone(),
                    completion: evidence,
                    material: super::demand_closure::BridgeMaterial {
                        source_language,
                        target_language,
                        precedence: None,
                        candidate_origin_rank: reader.package_origin_rank,
                        target_definition: Some(*definition),
                        cross_language_evidence,
                        callable_import: source.is_import.then_some(source.token),
                    },
                });
                if provider
                    .result_bound
                    .is_some_and(|bound| result.len() >= bound)
                {
                    // The existing Java exact package rule selects its first
                    // admitted provider in canonical provider order.
                    return Ok(
                        (!cancellation.is_cancelled()).then_some(JvmPurePackageRows {
                            exports: result,
                            external_owner: None,
                            complete: false,
                            observations,
                        }),
                    );
                }
            }
            complete &= matching.is_subset(&published);
        }
        let mut external_owner = None;
        if result.is_empty() && requested.namespace() == ResolutionNamespace::Type {
            let fqn = if package.is_empty() {
                requested.spelling().to_owned()
            } else {
                format!("{package}.{}", requested.spelling())
            };
            // Intrinsic inventories prove name absence, not an external
            // declaration or a member-continuation owner. Preserve the ordinary
            // language route for them (including Kotlin companions and objects).
            if let Some(owner) = self
                .declared_jvm_owner(source_language, &fqn)?
                .filter(|owner| owner.provider_id.as_ref() != "jvm-intrinsic")
            {
                let identities = &self.ready.context_identities;
                external_owner = Some(identities.external_owner_semantic(&owner, &names));
                // The shared route walk already settled the lexical prefix.
                // Record its external declaration for nominal projection only;
                // the shared registration retains any provider enumeration boundary.
                if !source.is_import && requested == &source.demand {
                    let Some(classifications) =
                        self.jvm_endpoint_classifications(reader.source_reference, cancellation)?
                    else {
                        return Ok(None);
                    };
                    let reference = classifications
                        .iter()
                        .find(|row| row.node() == reader.source_reference)
                        .and_then(|row| row.reference())
                        .expect("a rooted type route has a reference endpoint");
                    register_model_declared_jvm_type_identity(
                        self,
                        reference,
                        &fqn,
                        Some(&owner),
                        identities,
                        &names,
                    )?;
                }
                complete = completion == &ResolutionCompletion::Complete;
            }
        }
        Ok(
            (!cancellation.is_cancelled()).then_some(JvmPurePackageRows {
                exports: result,
                external_owner,
                complete,
                observations,
            }),
        )
    }
}

/// JVM derivations are owned by one graph unit; only the projection memo may
/// survive into the next unit of this selected graph request.
#[doc(hidden)]
pub struct JvmGraphStageTables<'operation> {
    peer: FileContextPeerMemoGuard<'operation>,
    cleanup: Option<Box<dyn FnOnce() + 'operation>>,
}
impl super::graph_stage::GraphStageHelperTables for JvmGraphStageTables<'_> {
    fn memo_stats(&self) -> super::graph_stage::GraphStageMemoStats {
        super::graph_stage::GraphStageHelperTables::memo_stats(&self.peer)
    }
}
impl Drop for JvmGraphStageTables<'_> {
    fn drop(&mut self) {
        self.cleanup
            .take()
            .expect("a JVM graph unit has one memo owner")();
    }
}
impl SelectedResolutionOperation<'_, '_> {
    #[doc(hidden)]
    pub fn jvm_graph_stage_tables(&self) -> JvmGraphStageTables<'_> {
        JvmGraphStageTables {
            peer: self.file_context_peer_memo_scope(),
            cleanup: Some(Box::new(|| self.clear_jvm_graph_unit_memos())),
        }
    }
    fn clear_jvm_graph_unit_memos(&self) {
        self.jvm_file_contexts.replace(Default::default());
        self.jvm_access_policies.replace(Default::default());
        self.jvm_context_registrations.replace(Default::default());
        self.jvm_source_access_memo.replace(Default::default());
        self.jvm_source_paths.replace(Default::default());
        self.jvm_root_exports_memo.replace(Default::default());
        self.jvm_import_target_memo.replace(Default::default());
        self.jvm_named_import_target_memo
            .replace(Default::default());
        self.jvm_import_uncertainty_memo.replace(Default::default());
        self.jvm_alias_rows_memo.replace(Default::default());
        self.jvm_generated_lookup_memo.replace(Default::default());
        self.jvm_package_indexes.replace(Default::default());
        self.jvm_package_target_memo.replace(Default::default());
        self.jvm_package_uncertainty_memo
            .replace(Default::default());
        self.jvm_package_presence_memo.replace(Default::default());
        self.jvm_endpoint_memo.replace(Default::default());
        self.import_token_memo.replace(Default::default());
        self.jvm_visibility_memo.replace(Default::default());
        self.jvm_member_import_memo.replace(Default::default());
        self.jvm_context_preparations.clear();
        self.jvm_source_domains.clear();
        self.jvm_implicit_project_memo.clear();
        self.jvm_implicit_project_contexts.clear();
        self.jvm_package_member_memo.clear();
        self.clear_file_context_recipe_memo();
    }
}

pub(in crate::analyzer) fn jvm_assembled_import_origin(
    source_language: Language,
    prefix_length: usize,
    lookup_route_length: usize,
    caller_version: Option<i64>,
    target_version: Option<i64>,
    selector_kind: Option<ResolutionImportSelectorKind>,
) -> BindingOrigin {
    let route = if prefix_length < lookup_route_length {
        ImportOriginRoute::PackagePrefix(
            if caller_version.is_some() && caller_version == target_version {
                CompilationUnitRelation::SameCompilationUnit
            } else {
                CompilationUnitRelation::OtherCompilationUnit
            },
        )
    } else {
        ImportOriginRoute::Complete
    };
    nominal_language_rules(source_language)
        .expect("caller belongs to a nominal family")
        .assembled_import_origin(route, selector_kind)
}

pub(in crate::analyzer) fn jvm_package_precedence_origin(
    language: Language,
    relation: PackageRelation,
) -> (Option<PrecedenceTier>, BindingOrigin) {
    nominal_language_rules(language)
        .expect("caller belongs to a nominal family")
        .package_precedence(relation)
}

pub(in crate::analyzer) fn jvm_bridge_import_origin(
    language: Language,
    import_kind: Option<ResolutionImportRouteKind>,
    selector_kind: Option<ResolutionImportSelectorKind>,
) -> Option<BindingOrigin> {
    nominal_language_rules(language)
        .expect("caller belongs to a nominal family")
        .bridge_import_origin(import_kind, selector_kind)
}

pub(in crate::analyzer) fn jvm_lexical_import_head_origin(
    language: Language,
) -> Option<BindingOrigin> {
    nominal_language_rules(language)
        .expect("caller belongs to a nominal family")
        .lexical_import_head_origin()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::language_implicit_root_providers;
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    #[cfg(test)]
    #[test]
    fn jvm_default_import_tables_match_language_contracts() {
        let packages = |language| {
            nominal_language_rules(language)
                .expect("caller belongs to a nominal family")
                .implicit_root_providers()
                .iter()
                .filter_map(|provider| match provider {
                    JvmImplicitRootProvider::Package(name) => Some(*name),
                    JvmImplicitRootProvider::ScalaPredef => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(packages(Language::Java), ["java.lang"]);
        assert_eq!(
            packages(Language::Kotlin),
            [
                "kotlin",
                "kotlin.annotation",
                "kotlin.collections",
                "kotlin.comparisons",
                "kotlin.io",
                "kotlin.ranges",
                "kotlin.sequences",
                "kotlin.text",
                "kotlin.jvm",
                "java.lang",
            ]
        );
        assert_eq!(packages(Language::Scala), ["java.lang", "scala"]);
        assert!(
            language_implicit_root_providers(Language::Scala)
                .contains(&JvmImplicitRootProvider::ScalaPredef)
        );
        assert!(
            language_implicit_root_providers(Language::Java)
                .iter()
                .all(|provider| *provider != JvmImplicitRootProvider::ScalaPredef)
        );
        assert_eq!(SCALA_PREDEF_DEFAULT_IMPORT, "scala.Predef");
    }

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "7052beabe6ed: repeated wildcard demands rediscovered identical JVM routes"
    )]
    fn repeated_jvm_lookup_routes_keep_only_the_first_occurrence() {
        let recipe = |name| {
            ResolutionLookupSemanticRecipe::new(Language::Scala, ResolutionNamespace::Type, name)
        };
        let written = vec![recipe("Utility")];
        let through_model = vec![recipe("model"), recipe("Utility")];
        let routes = jvm_import_lookup_routes(
            Language::Scala,
            ResolutionRootImportAnchor::Lexical,
            &["app".to_owned()],
            &written,
            Some(&through_model),
            std::slice::from_ref(&written),
            &[
                through_model.clone(),
                through_model.clone(),
                written.clone(),
            ],
        );
        let gap = JvmImportContextGap {
            source_token: SemanticId::local(0, 1),
            source_reference: None,
            lookup: recipe("Utility"),
            reason: SemanticId::local(0, 2),
            kind: "jvm-import-alias-route-open",
            owner: Some("model.Utility".to_owned()),
            boundary_status: None,
            nominal_type_identity: None,
            suppress_if_same_package_candidate: false,
        };
        let mut misses = JvmImportLookupRouteMissMemo::default();
        let mut executed = Vec::new();
        let mut wildcard = None;
        let mut aliases = Vec::new();
        let mut gaps = Vec::new();
        for route in &routes {
            if misses.replay(route, &mut wildcard, &mut aliases, &mut gaps) {
                continue;
            }
            executed.push(route.clone());
            let alias = route
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".");
            let has_wildcard = route.len() > 1;
            if has_wildcard {
                wildcard = Some(route.clone());
            }
            aliases.push(alias.clone());
            gaps.push(gap.clone());
            misses.record(route.clone(), has_wildcard, vec![alias], vec![gap.clone()]);
        }
        assert_eq!(
            executed,
            vec![
                through_model.clone(),
                written,
                vec![recipe("app"), recipe("Utility")]
            ],
            "route computations retain first-seen candidate precedence"
        );
        assert_eq!(
            wildcard,
            Some(through_model),
            "a repeated failed route still has its original last-writer effect"
        );
        assert_eq!(
            aliases,
            [
                "model.Utility",
                "Utility",
                "app.Utility",
                "model.Utility",
                "model.Utility",
                "Utility",
                "Utility"
            ],
        );
        assert_eq!(gaps, vec![gap; 7]);
    }

    #[cfg(test)]
    #[test]
    fn kotlin_selected_package_routes_rank_same_package_before_defaults() {
        let precedence =
            SelectedResolutionOperation::<'static, 'static>::selected_jvm_package_precedence;
        assert_eq!(
            precedence(Language::Kotlin, Some("sample"), "sample").tier,
            Some(PrecedenceTier::PackageOrModule)
        );
        assert_eq!(
            precedence(Language::Kotlin, Some("sample"), "kotlin.collections").tier,
            Some(PrecedenceTier::DefaultImport)
        );
        assert_eq!(
            precedence(Language::Kotlin, Some("sample"), "sample").candidate_origin_rank,
            binding_origin_rank(Language::Kotlin, BindingOrigin::SamePackage)
        );
        assert_eq!(
            precedence(Language::Kotlin, Some("sample"), "kotlin.collections")
                .candidate_origin_rank,
            binding_origin_rank(Language::Kotlin, BindingOrigin::StarImport)
        );
        assert_eq!(
            precedence(Language::Java, Some("sample"), "sample").candidate_origin_rank,
            binding_origin_rank(Language::Java, BindingOrigin::SamePackage)
        );
        assert_eq!(
            precedence(Language::Scala, Some("sample"), "scala").candidate_origin_rank,
            binding_origin_rank(Language::Scala, BindingOrigin::OtherCompilationUnitPackage)
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#5331: exact static alias endpoints dropped target scoped binder gaps")]
    fn selected_jvm_alias_declaration_gaps_stay_scoped() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        // No root export is needed: these are the persisted lexical binder
        // endpoints of a member and a declaration in an unrelated scope.
        connection
            .execute_batch(
                "CREATE TABLE resolution_paths (
                    blob_id INTEGER NOT NULL, path INTEGER NOT NULL,
                    start_node INTEGER NOT NULL, end_node INTEGER NOT NULL,
                    start_lead_identity INTEGER, end_lead_identity INTEGER,
                    end_lead_local INTEGER,
                    PRIMARY KEY(blob_id, path)
                 ) STRICT;
                 CREATE INDEX resolution_paths_reverse ON resolution_paths (
                    blob_id, end_node, end_lead_identity, end_lead_local, path);
                 CREATE TABLE resolution_gaps (
                    blob_id INTEGER NOT NULL, covers INTEGER NOT NULL,
                    subject INTEGER NOT NULL, lookup INTEGER NOT NULL,
                    gap INTEGER NOT NULL, reason INTEGER NOT NULL,
                    PRIMARY KEY(blob_id, covers, subject, lookup, gap)
                 ) WITHOUT ROWID, STRICT;
                 CREATE TABLE resolution_gap_reasons (
                    blob_id INTEGER NOT NULL, reason INTEGER NOT NULL,
                    origin INTEGER NOT NULL, PRIMARY KEY(blob_id, reason)
                 ) WITHOUT ROWID, STRICT;
                 INSERT INTO resolution_paths VALUES
                    (7, 1, 100, 10, 5, NULL, NULL),
                    (7, 2, 200, 20, 5, NULL, NULL),
                    (7, 3, -1, 10, 5, NULL, NULL),
                    (7, 4, 300, 10, 5, 5, NULL),
                    (7, 5, 400, 10, NULL, NULL, NULL);
                 INSERT INTO resolution_gaps VALUES
                    (7, 6, 10, 0, 1, 1000),
                    (7, 5, 100, 0, 2, 1001),
                    (7, 5, 100, 17, 3, 1002),
                    (7, 5, 200, 0, 4, 1003),
                    (8, 5, 100, 0, 1, 1004),
                    (7, 5, -1, 0, 5, 1005),
                    (7, 6, 10, 0, 6, 1006),
                    (7, 5, 300, 0, 7, 1007),
                    (7, 5, 400, 0, 8, 1008);",
            )
            .unwrap();
        let origin = super::super::super::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                ResolutionGapKind::UnsupportedScopeOrBinder,
            ),
        );
        let other_origin =
            super::super::super::resolution_prepare::resolution_rows::gap_origin_code(
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    ResolutionGapKind::UnexpandedItemMacro,
                ),
            );
        connection
            .execute(
                "INSERT INTO resolution_gap_reasons
                 SELECT DISTINCT blob_id, reason,
                    CASE WHEN reason=1006 THEN ?2 ELSE ?1 END
                 FROM resolution_gaps",
                rusqlite::params![origin, other_origin],
            )
            .unwrap();
        let mut reasons = connection
            .prepare(SELECTED_JVM_ALIAS_DECLARATION_GAPS)
            .unwrap()
            .query_map(rusqlite::params![7, 10, origin], |row| row.get::<_, u32>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        reasons.sort_unstable();
        assert_eq!(reasons, [1000, 1001, 1002]);
    }

    #[cfg(test)]
    #[test]
    #[hardwon("#5331: Java static imports ignored persisted Kotlin JVM aliases")]
    fn selected_jvm_alias_reader_seeks_the_selected_blob_primary_key() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE resolution_jvm_aliases (
                    blob_id INTEGER NOT NULL,
                    alias INTEGER NOT NULL,
                    declaration_site INTEGER NOT NULL,
                    member_name TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'source_proven', 'compiler_mode_dependent')),
                    kind TEXT NOT NULL CHECK(kind IN (
                        'field', 'getter', 'setter', 'method', 'constructor',
                        'companion_object', 'singleton_instance')),
                    is_static INTEGER NOT NULL CHECK(is_static IN (0, 1)),
                    PRIMARY KEY(blob_id, alias)
                 ) STRICT;
                 CREATE TABLE resolution_semantic_sites (
                    blob_id INTEGER NOT NULL,
                    source_site INTEGER NOT NULL,
                    semantic_role TEXT NOT NULL,
                    semantic_key INTEGER NOT NULL,
                    PRIMARY KEY(blob_id, source_site),
                    UNIQUE(blob_id, semantic_role, semantic_key)
                 ) WITHOUT ROWID;
                 WITH RECURSIVE blobs(blob_id) AS (
                    SELECT 1 UNION ALL SELECT blob_id + 1 FROM blobs WHERE blob_id < 2000
                 )
                 , aliases(alias) AS (
                    SELECT 1 UNION ALL SELECT alias + 1 FROM aliases WHERE alias < 32
                 )
                 INSERT INTO resolution_jvm_aliases
                 SELECT blob_id, 1, 1,
                        CASE WHEN blob_id = 7 THEN 'member' ELSE 'other' END,
                        'source_proven', 'method', 1
                 FROM blobs;
                 INSERT INTO resolution_jvm_aliases
                 VALUES (7, 2, 2, 'member', 'source_proven', 'method', 0),
                        (7, 3, 3, 'member', 'compiler_mode_dependent', 'method', 1);
                 INSERT INTO resolution_semantic_sites
                 SELECT blob_id, alias, 'definition', alias FROM resolution_jvm_aliases;",
            )
            .unwrap();

        let mut rows = connection
            .prepare(SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER)
            .unwrap()
            .query_map(rusqlite::params![7, "member"], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        rows.sort_by_key(|row| row.0);
        assert_eq!(
            rows,
            [
                (
                    1,
                    1,
                    "source_proven".to_owned(),
                    1,
                    "method".to_owned(),
                    true
                ),
                (
                    2,
                    2,
                    "source_proven".to_owned(),
                    2,
                    "method".to_owned(),
                    false
                ),
                (
                    3,
                    3,
                    "compiler_mode_dependent".to_owned(),
                    3,
                    "method".to_owned(),
                    true
                ),
            ]
        );

        let pin = crate::analyzer::store::planner_statistics::pinned_plans::pinned(
            "jvm_native_alias_member_by_blob",
        );
        for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
            state.install(&connection);
            let mut statement = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {}", pin.sql))
                .unwrap();
            let plan = statement
                .query_map(rusqlite::params![7, "member"], |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter().any(|step| {
                    step.contains("SEARCH alias USING") && step.contains("(blob_id=?)")
                }),
                "{state}: selected blob must bound the alias lookup: {plan:?}"
            );
            assert!(
                plan.iter().all(|step| !step.contains("SCAN alias")),
                "{state}: alias lookup must not scan the workspace table: {plan:?}"
            );
        }
    }

    #[cfg(test)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: KotlinPoet alias probes scanned every alias in a selected blob"
    )]
    fn selected_jvm_alias_reader_seeks_the_selected_blob_and_member() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE resolution_jvm_aliases (
                    blob_id INTEGER NOT NULL,
                    alias INTEGER NOT NULL,
                    declaration_site INTEGER NOT NULL,
                    member_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    is_static INTEGER NOT NULL CHECK(is_static IN (0, 1)),
                    PRIMARY KEY(blob_id, alias)
                 ) STRICT;
                 CREATE TABLE resolution_semantic_sites (
                    blob_id INTEGER NOT NULL,
                    source_site INTEGER NOT NULL,
                    semantic_role TEXT NOT NULL,
                    semantic_key INTEGER NOT NULL,
                    PRIMARY KEY(blob_id, source_site),
                    UNIQUE(blob_id, semantic_role, semantic_key)
                 ) WITHOUT ROWID;
                 WITH RECURSIVE blobs(blob_id) AS (
                    SELECT 1 UNION ALL SELECT blob_id + 1 FROM blobs WHERE blob_id < 2000
                 )
                 , aliases(alias) AS (
                    SELECT 1 UNION ALL SELECT alias + 1 FROM aliases WHERE alias < 32
                 )
                 INSERT INTO resolution_jvm_aliases
                 SELECT blob_id, alias, 1,
                        CASE WHEN blob_id = 7 AND alias = 1 THEN 'member' ELSE 'other' END,
                        'source_proven', 'field', 1
                 FROM blobs CROSS JOIN aliases;
                 INSERT INTO resolution_semantic_sites
                 SELECT DISTINCT blob_id, 1, 'definition', 1 FROM resolution_jvm_aliases;",
            )
            .unwrap();

        connection
            .execute_batch(include_str!(
                "../../../../../bifrost-core/migrations/cache/0186-jvm-alias-member-index.sql"
            ))
            .unwrap();

        let rows = connection
            .prepare(SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER)
            .unwrap()
            .query_map(rusqlite::params![7, "member"], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            [(
                1,
                1,
                "source_proven".to_owned(),
                1,
                "field".to_owned(),
                true
            )]
        );

        for statistics in ["", "ANALYZE"] {
            connection.execute_batch(statistics).unwrap();
            let mut statement = connection
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER}"
                ))
                .unwrap();
            let plan = statement
                .query_map(rusqlite::params![7, "member"], |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter().any(|step| {
                    step.contains("resolution_jvm_aliases_member_name")
                        && step.contains("(blob_id=? AND member_name=?)")
                }),
                "both predicates must bound the alias read: {plan:?}"
            );
            assert!(
                plan.iter().all(|step| !step.contains("SCAN alias")),
                "{plan:?}"
            );
        }
    }
}
