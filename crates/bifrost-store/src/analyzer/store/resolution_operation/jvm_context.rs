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
use super::demand_closure::Read;
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
use crate::analyzer::resolution::SelectedExplicitImportBoundary;
use crate::analyzer::resolution::fact_resolution::demand_scheduler::{
    SelectedExternalOwner, SelectedExternalOwnerSelection,
};
use crate::analyzer::resolution::selected_context::{
    ExplicitImportAdmission, SelectedJavaOnDemandSource, SelectedJavaTypeNameOwner,
    SelectedJavaTypeNameWinner,
};
use crate::analyzer::resolution::tier_evaluator::{
    ContributorClosure, InheritedTierKnowledge, InheritedTierWitness, LexicalTypeLevel,
    TierContributor, TierDecision, TierInput, TierReceipt, TierWitness, evaluate_tiers,
    place_lexical_type,
};
use crate::analyzer::resolution::{
    BatchEndpointClassification, BindingOrigin, CanonicalIdentityDescriptor, CanonicalIdentityPart,
    FactPageVisitor, FactReadOutcome, JvmImplicitRootProvider,
    LoweredDeclarationVisibilityProperty, LoweredPackageMember, LoweredPackageReference,
    PrecedenceStep, ResolutionAnswer, ResolutionIdentityDigestKey, SelectedJvmBridgeEvidence,
    SelectedJvmBridgeProvenance, SelectedJvmBridgeVisibility, SelectedPackageBridgeDescriptor,
    SelectedResolutionMountContext, SelectedRootBridgeDescriptor, SelectedRootPathHalf,
    SharedNameInterner, binding_origin_rank, fact_source::JvmAccessEndpoint,
    language_callables_occupy_value_namespace, language_implicit_root_member_names,
    language_import_owner_steps_bind_singletons, language_jvm_declaration_access_rules,
    language_jvm_package_requires_directory_agreement, package_domain_semantic,
};
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionConstructionRequirementKind, ResolutionGapKind, ResolutionImportRouteKind,
    ResolutionImportSelectorKind, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionNamespace, ResolutionRootImportKind, ResolutionSiteId, ResolutionSupertypeKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, PrecedenceTier};
use brokk_bifrost_jvm::java::import_split::{
    JavaImportSplitGap, JavaSingleTypeImportProof, prove_java_single_type_import_from_selected_rows,
};
use std::cell::Cell;
use std::sync::{Arc, Mutex};

const JVM_IMPORT_ALIAS_COVERAGE_OPEN: &str = "jvm-import-alias-coverage-open";

// A selected member-owner visit certifies absence only after every page and
// its completion receipt have been consumed. Shared with inherited lookup.
pub(super) fn jvm_member_owner_pages_complete(outcome: &FactReadOutcome) -> bool {
    outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete
}

// Declaration-unit rows are the second half of the source-member certificate.
// A missing crosswalk must leave negative member answers open.
pub(super) fn jvm_member_crosswalk_complete(
    coordinates: &[(SelectedResolutionMountOrdinal, ResolutionLocalKey)],
    named_keys: &BTreeSet<ResolutionLocalKey>,
) -> bool {
    coordinates.iter().all(|(_, key)| named_keys.contains(key))
}

// Active package-member inventory is read once for all demands in a file plan.
const JVM_ACTIVE_PACKAGE_MEMBERS_SQL: &str = "SELECT CAST(demand.key AS INTEGER),member.provider_id,member.ordinal,member.member_kind,member.visibility,member.is_static,member.callable_family_complete,owner.callables_complete,owner.values_complete \
             FROM json_each(?2) AS demand \
             CROSS JOIN json_each(?1) AS provider \
             CROSS JOIN jvm_external_owner_members AS member INDEXED BY jvm_external_owner_members_by_name \
               ON member.provider_id=provider.value AND member.owner_fqn=json_extract(demand.value,'$[0]') AND member.member_name=json_extract(demand.value,'$[1]') \
             CROSS JOIN jvm_external_owners owner USING(provider_id,owner_fqn) \
             ORDER BY demand.key,member.provider_id,member.ordinal";
const JVM_ACTIVE_PACKAGE_OWNERS_SQL: &str = "SELECT DISTINCT owner_fqn FROM jvm_external_owners WHERE provider_id IN (SELECT value FROM json_each(?1)) AND owner_fqn IN (SELECT value FROM json_each(?2))";

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
    prepared: &'a JvmContextPreparation,
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

pub(in crate::analyzer::store) fn jvm_staged_root_member_targets_sql() -> String {
    format!(
        r#"SELECT mounted.mount_ordinal
FROM json_each(?2) AS requested
CROSS JOIN temp.selected_resolution_stage_package_members AS member
  INDEXED BY selected_resolution_stage_package_members_lookup
  ON member.lookup_shared=requested.value
CROSS JOIN temp.selected_resolution_mounts AS mounted ON mounted.mount_ordinal=member.host_ordinal
CROSS JOIN temp.selected_resolution_scope_mounts AS scope ON scope.mount_ordinal=mounted.mount_ordinal
WHERE member.namespace='type' AND mounted.semantic_language IN (?3,?4,?5)
{JVM_IMPORT_TARGET_PACKAGE_FILTER} LIMIT 1"#
    )
}

pub(in crate::analyzer::store) fn jvm_root_member_uncertainty_sql() -> String {
    JVM_IMPORT_UNCERTAINTY_HEADS
        .iter()
        .map(|head| {
            format!(
                "{head} AND mounted.storage_language IN (?2,?3,?4) \
                 AND EXISTS (SELECT 1 FROM temp.selected_resolution_scope_mounts AS scope \
                 WHERE scope.mount_ordinal=mounted.mount_ordinal) \
                 {JVM_IMPORT_TARGET_PACKAGE_FILTER}"
            )
        })
        .collect::<Vec<_>>()
        .join(" UNION ")
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone)]
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
    // Exact enclosing packaging clauses for each selected Scala occurrence.
    // None means the producer has not certified the clause boundary at this site.
    scala_reference_packages: HashMap<SemanticId, Option<Vec<String>>>,
    scala_local_package_by_token: HashMap<SemanticId, String>,
    same_package_lookups: BTreeSet<SemanticId>,
    references_by_name: HashMap<String, Vec<crate::analyzer::resolution::LoweredPackageReference>>,
    unqualified_type_references: BTreeSet<SemanticId>,
    // Share the selected rows without cloning them into each named builder.
    // Short-lived ledger locks preserve transfer of this owned preparation.
    imports: ContextPlanMemo<CandidatePathIdentity, Arc<JvmDerivedImport>>,
    implicit: ContextPlanCell<Arc<JvmImplicitContextParts>>,
    external_providers: JvmExternalProviderBlueprint,
    simple_type_name_decisions: ContextPlanMemo<SemanticId, Arc<JvmSimpleTypeNameDecision>>,
    on_demand_bindings: ContextPlanMemo<SemanticId, JvmOnDemandBindings>,
}

impl Clone for JvmExternalProviderBlueprint {
    fn clone(&self) -> Self {
        Self {
            references_by_route: self.references_by_route.clone(),
            recipes: self.recipes.clone(),
            registered: Mutex::new(
                self.registered
                    .lock()
                    .expect("JVM preparation memo is not poisoned")
                    .clone(),
            ),
        }
    }
}

type JvmOnDemandBindings = Arc<[super::jvm_demand::JvmImportBinding]>;

/// Bytes charged for each element of a nested type that has no retained-size
/// census of its own (members, references, routes, rank choices).
const UNCENSUSED_ELEMENT_BYTES: usize = 256;

type RetainedHeap = super::super::cache_budget::RetainedHeap;

fn charge_strings(heap: &mut RetainedHeap, strings: &Vec<String>) {
    heap.vec(strings);
    heap.add(strings.iter().map(String::capacity).sum());
}

fn charge_recipes(heap: &mut RetainedHeap, recipes: &Vec<ResolutionLookupSemanticRecipe>) {
    heap.vec(recipes);
    heap.add(
        recipes
            .iter()
            .map(ResolutionLookupSemanticRecipe::owned_bytes)
            .sum(),
    );
}

fn charge_gaps(heap: &mut RetainedHeap, gaps: &Vec<JvmImportContextGap>) {
    heap.vec(gaps);
    for gap in gaps {
        heap.add(gap.lookup.owned_bytes() + gap.owner.as_ref().map_or(0, String::capacity));
        heap.vec(&gap.external_member_targets);
        gap.pack_completion.charge_retained(heap);
    }
}

fn charge_root_bridges(heap: &mut RetainedHeap, bridges: &Vec<SelectedRootBridgeDescriptor>) {
    heap.vec(bridges);
    for bridge in bridges {
        bridge.charge_retained(heap);
    }
}

impl JvmContextPreparation {
    /// Retained size for a request memo's weigher. Collections are charged by
    /// their storage and walked into their nested collections; an element type
    /// with no census of its own is charged a fixed allowance per element.
    fn charge_retained(&self, heap: &mut RetainedHeap) {
        heap.add(std::mem::size_of_val(self));
        heap.add(self.source_package.as_ref().map_or(0, String::capacity));
        heap.vec(&self.binders);
        for binder in &self.binders {
            heap.add(
                binder.head.capacity()
                    + binder.bound.as_ref().map_or(0, String::capacity)
                    + binder.imported.as_ref().map_or(0, String::capacity)
                    + UNCENSUSED_ELEMENT_BYTES,
            );
            charge_recipes(heap, &binder.recipes);
        }
        heap.map(&self.package_plan);
        for (package, planned) in &self.package_plan {
            heap.add(package.capacity());
            heap.map(&planned.candidates);
            for candidates in planned.candidates.values() {
                heap.vec(candidates);
                for candidate in candidates {
                    match candidate {
                        JvmPackageCandidate::SourceMount { members, .. } => {
                            heap.arc(members, |members, heap| {
                                heap.add(members.len().saturating_mul(UNCENSUSED_ELEMENT_BYTES));
                            });
                        }
                        JvmPackageCandidate::ExternalMember(member) => {
                            heap.add(
                                UNCENSUSED_ELEMENT_BYTES
                                    + member.pack_id.capacity()
                                    + member.pack_version.capacity(),
                            );
                            member.completion.charge_retained(heap);
                        }
                    }
                }
            }
        }
        heap.map(&self.qualifier_names_by_demand);
        for (demand, names) in &self.qualifier_names_by_demand {
            heap.add(demand.capacity());
            heap.hash_set(names);
            heap.add(names.iter().map(String::capacity).sum());
        }
        for references in [
            &self.package_reference_occurrences,
            &self.package_references,
        ] {
            heap.vec(references);
            heap.add(references.len().saturating_mul(UNCENSUSED_ELEMENT_BYTES));
        }
        heap.btree_set(&self.same_package_lookups);
        heap.map(&self.references_by_name);
        for (name, references) in &self.references_by_name {
            heap.add(name.capacity());
            heap.vec(references);
            heap.add(references.len().saturating_mul(UNCENSUSED_ELEMENT_BYTES));
        }
        heap.btree_set(&self.unqualified_type_references);
        self.imports.for_each_entry(|_, import| {
            heap.arc(import, |import, heap| {
                if let Some(heads) = &import.earlier_head {
                    for head in heads {
                        charge_recipes(heap, head);
                    }
                }
                heap.vec(&import.earlier_wildcards);
                for wildcard in &import.earlier_wildcards {
                    charge_recipes(heap, wildcard);
                }
                charge_root_bridges(heap, &import.bridges);
                if let Some(evidence) = &import.on_demand {
                    evidence.charge_retained(heap);
                }
                charge_gaps(heap, &import.gaps);
                heap.vec(&import.model_routes);
                heap.add(
                    import
                        .model_routes
                        .len()
                        .saturating_mul(UNCENSUSED_ELEMENT_BYTES),
                );
                charge_strings(heap, &import.open_aliases);
                for routes in import.scala_imports.values() {
                    for recipes in routes {
                        charge_recipes(heap, recipes);
                    }
                }
                for wildcards in import.scala_wildcards.values() {
                    for recipes in wildcards {
                        charge_recipes(heap, recipes);
                    }
                }
                if let Some(alias) = &import.package_alias {
                    heap.add(std::mem::size_of_val(alias));
                    heap.add(alias.selected_name.capacity() + alias.container.capacity());
                    heap.vec(&alias.exact_hosts);
                    for (segment, hosts) in &alias.receipts {
                        heap.add(segment.capacity());
                        heap.vec(hosts);
                    }
                }
                heap.add(
                    (import.scala_imports.len() + import.scala_wildcards.len())
                        .saturating_mul(UNCENSUSED_ELEMENT_BYTES),
                );
            });
        });
        self.implicit.with_value(|implicit| {
            heap.arc(implicit, |implicit, heap| {
                heap.vec(&implicit.bridges);
                for bridge in &implicit.bridges {
                    bridge.charge_retained(heap);
                }
                charge_gaps(heap, &implicit.gaps);
                heap.btree_set(&implicit.same_package_lookups);
                heap.add(
                    implicit
                        .durable_owners
                        .len()
                        .saturating_mul(UNCENSUSED_ELEMENT_BYTES),
                );
            });
        });
        let providers = &self.external_providers;
        for references in providers.references_by_route.values() {
            heap.vec(references);
        }
        heap.add(
            providers
                .references_by_route
                .len()
                .saturating_mul(UNCENSUSED_ELEMENT_BYTES),
        );
        heap.map(&providers.recipes);
        heap.add(
            providers
                .recipes
                .values()
                .map(ResolutionLookupSemanticRecipe::owned_bytes)
                .sum(),
        );
        let registered = providers
            .registered
            .lock()
            .expect("JVM preparation memo is not poisoned");
        heap.hash_set(&registered);
        for (_, recipe, references) in registered.iter() {
            heap.add(
                recipe.owned_bytes() + references.capacity() * std::mem::size_of::<SemanticId>(),
            );
        }
        drop(registered);
        self.simple_type_name_decisions
            .for_each_entry(|_, decision| {
                heap.arc(decision, |decision, heap| {
                    heap.vec(&decision.witnesses);
                    heap.add(decision.witnesses.len() * UNCENSUSED_ELEMENT_BYTES);
                });
                match &decision.lower {
                    JvmOnDemandTypeChoice::Competing(candidates) => {
                        heap.vec(candidates);
                        for candidate in candidates {
                            heap.add(
                                candidate.fqn.capacity()
                                    + candidate.package.capacity()
                                    + UNCENSUSED_ELEMENT_BYTES,
                            );
                            if let Some(coordinate) = &candidate.coordinate {
                                heap.vec(&coordinate.outward);
                            }
                            if let Some(declared) = &candidate.declared {
                                heap.add(declared.fqn.capacity());
                            }
                        }
                    }
                    JvmOnDemandTypeChoice::Possible(winner) => {
                        heap.add(winner.package.capacity() + winner.declared.fqn.capacity());
                    }
                    JvmOnDemandTypeChoice::Unavailable
                    | JvmOnDemandTypeChoice::OpenDefault
                    | JvmOnDemandTypeChoice::Indexed(_)
                    | JvmOnDemandTypeChoice::Alias(_)
                    | JvmOnDemandTypeChoice::Intrinsic(_) => {}
                }
            });
        self.on_demand_bindings.for_each_entry(|_, bindings| {
            heap.arc(bindings, |_, _| {});
        });
    }
}

/// Identity of one file's base JVM import context, for reuse by later point
/// operations of the same request. The routing digest and scope cover every
/// selected row the base build reads; the provider list (artifact content
/// digests and model shard hashes) covers external declarations; the active
/// model set covers model authority. Root compilation also reads whether a
/// native rejection trace is active (it then attaches import routes for
/// rejection coverage), so a context built without the trace never serves an
/// operation that has one, or the reverse. The staged epoch is not a field:
/// only an operation at (0, 0) publishes or restores.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct JvmImportContextSnapshotKey {
    language: Language,
    path: String,
    scope: [u8; 32],
    routing: [u8; 32],
    providers: Vec<String>,
    model_set: Option<String>,
    native_rejection_trace: bool,
}

impl JvmImportContextSnapshotKey {
    #[doc(hidden)]
    pub fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            + self.path.capacity()
            + self.providers.capacity() * std::mem::size_of::<String>()
            + self.providers.iter().map(String::capacity).sum::<usize>()
            + self.model_set.as_ref().map_or(0, String::capacity)
    }
}

/// One file's base JVM import context as a cold build left its operation: the
/// identity table, the shared names the build minted, and the operation state
/// that later reads depend on (the context and preparation memos, the
/// canonical access policies the context points to, and the on-demand ranks
/// demand reads). Restoring it into a fresh operation of the same request
/// reproduces that state, so the restored operation answers as the cold build
/// would. Immutable once published; every restore copies it.
#[doc(hidden)]
pub struct JvmImportContextSnapshot {
    identities: crate::analyzer::resolution::SelectedContextIdentities,
    shared_names: super::super::resolution::MintedSharedNames,
    max_interned: i64,
    file_context_key: JvmFileContextKey,
    context: JvmImportContext,
    preparation: Option<JvmContextPreparation>,
    access_policies: super::java_access::JvmAccessPolicyMemo,
    on_demand_ranks: Vec<(SemanticId, super::jvm_demand::JvmBindingPrecedence)>,
}

// Policy evaluation runs points on several threads under one request memo.
const _: () = {
    const fn shared_across_threads<T: Send + Sync>() {}
    shared_across_threads::<JvmImportContextSnapshot>();
};

impl JvmImportContextSnapshot {
    #[cfg(any(test, feature = "test-support"))]
    pub fn minted_digest_for_test(&self) -> [u8; 32] {
        self.shared_names.first_digest_for_test()
    }
    #[doc(hidden)]
    pub fn retained_bytes(&self) -> usize {
        let mut heap = super::super::cache_budget::RetainedHeap::default();
        heap.add(std::mem::size_of_val(self));
        self.identities.charge_retained(&mut heap);
        heap.add(self.shared_names.estimated_heap_bytes());
        if let JvmImportContext::Ready {
            context,
            external_static_imports,
            open_jvm_alias_imports,
            scoped_gaps,
            ..
        } = &self.context
        {
            heap.add(std::mem::size_of_val(&**context));
            context.charge_retained(&mut heap);
            heap.vec(external_static_imports);
            heap.vec(open_jvm_alias_imports);
            for import in open_jvm_alias_imports {
                heap.add(import.capacity());
            }
            heap.vec(scoped_gaps);
        }
        if let Some(preparation) = &self.preparation {
            preparation.charge_retained(&mut heap);
        }
        heap.map(&self.access_policies);
        heap.vec(&self.on_demand_ranks);
        // A floor per entry, so the memo's byte cap also bounds its entry count
        // whatever the census misses.
        heap.total().max(JVM_IMPORT_CONTEXT_SNAPSHOT_FLOOR_BYTES)
    }
}

/// The least a published snapshot is charged, in bytes.
const JVM_IMPORT_CONTEXT_SNAPSHOT_FLOOR_BYTES: usize = 64 * 1024;

/// Why an operation neither published nor restored a base context snapshot.
/// Every refusal leaves the operation unchanged and costs a cold build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum JvmImportContextSnapshotRefusal {
    /// The operation is past staged epoch (0, 0) or already holds context
    /// identities or JVM context state.
    UsedOperation,
    /// The operation has already minted shared names or admitted aliases.
    MintedNames,
    /// The store interned a shared name after the snapshot was published.
    StoreInternedSincePublish,
    /// The cold build was not Ready.
    NotReady,
    /// The operation reads frozen or bottom inherited member-type knowledge,
    /// or a JVM decision consumed a walk result. The snapshot key does not
    /// name that evidence.
    InheritedTierKnowledge,
}

type JvmScalaImports = BTreeMap<(BindingNodeId, String), Vec<Vec<ResolutionLookupSemanticRecipe>>>;
type JvmScalaWildcards = BTreeMap<BindingNodeId, Vec<Vec<ResolutionLookupSemanticRecipe>>>;

struct JvmDerivedImport {
    on_demand: Option<JvmOnDemandPackageEvidence>,
    earlier_head: Option<Vec<Vec<ResolutionLookupSemanticRecipe>>>,
    earlier_wildcards: Vec<Vec<ResolutionLookupSemanticRecipe>>,
    bridges: Vec<SelectedRootBridgeDescriptor>,
    gaps: Vec<JvmImportContextGap>,
    model_routes: Vec<ModelDeclaredJvmImportRoute>,
    open_aliases: Vec<String>,
    // Authoritative binder-local derivations over this operation's fixed selected
    // facts, like bridges/gaps. No cross-request reuse or persisted admission.
    external_static_imports: Vec<JavaExternalStaticImportBoundary>,
    static_import_searches: BTreeMap<(Option<ResolutionSiteId>, bool), JavaStaticImportSearch>,
    inventory_open: bool,
    scala_imports: JvmScalaImports,
    scala_wildcards: JvmScalaWildcards,
    package_alias: Option<JvmSelectedPackageAlias>,
    explicit_import: Option<JvmExplicitImportOutcome>,
}

/// How a Java single-type import's own JLS 7.5.1 proof ended, for its own
/// declaration site and for the references whose decision it wins.
#[derive(Clone, Debug)]
enum JvmExplicitImportOutcome {
    /// A selected workspace source declaration, proven or competing.
    WorkspaceSource,
    /// No workspace source declaration. `declared` says the operation
    /// selected a model- or provider-declared type with this name.
    External { fqn: String, declared: bool },
}

/// A named import's selected package coordinate. `selected_name` is the
/// authored selector; `demand` is the local spelling used by references.
/// Each receipt is reread before a half consumes the coordinate.
#[derive(Clone, Debug)]
pub(super) struct JvmSelectedPackageAlias {
    pub(super) source_token: SemanticId,
    pub(super) selected_name: String,
    pub(super) demand: ResolutionLookupSemanticRecipe,
    pub(super) container: String,
    receipts: JvmPackageRouteReceipts,
    exact_hosts: Vec<JvmImportTarget>,
}

type JvmPackageRouteReceipts = Vec<(String, Vec<JvmImportTarget>)>;

// Package references retain a source-site ordinal; root-path halves retain a
// binding node whose selected endpoint supplies the reference semantic key.
enum ScalaPackageContextReference {
    Site(ResolutionSiteId),
    Semantic(SemanticId),
}

// Raw selected-fact evidence only. Frame ownership, precedence and obligations
// are decided when a demanded reference instantiates its provider frame.
#[derive(Clone)]
struct JvmOnDemandTargetEvidence {
    mount: SelectedResolutionMountOrdinal,
    access: Option<ResolutionCompletion>,
    export_inventory_complete: bool,
    complete_export: bool,
    incomplete_export: bool,
}

#[derive(Clone)]
pub(super) struct JvmOnDemandPackageEvidence {
    pub(super) import_identity: CandidatePathIdentity,
    pub(super) import_token: SemanticId,
    pub(super) source_site: Option<ResolutionSiteId>,
    pub(super) staged: bool,
    pub(super) package: String,
    pub(super) lookup: ResolutionLookupSemanticRecipe,
    pub(super) whole_package_targets_present: Option<bool>,
    pub(super) whole_package_read_exhausted: bool,
    pub(super) named_read_exhausted: bool,
    targets: Vec<JvmOnDemandTargetEvidence>,
    pub(super) published_bridge: Option<SelectedRootBridgeDescriptor>,
}

// Completion of the derivation is independent of whether the selected provider
// configuration admits a package frame receipt. Outer None remains cancellation.
struct JvmTypeOnDemandImportResult {
    frame_evidence: Option<JvmOnDemandPackageEvidence>,
}

impl JvmOnDemandPackageEvidence {
    fn charge_retained(&self, heap: &mut RetainedHeap) {
        heap.add(self.package.capacity() + self.lookup.owned_bytes());
        heap.vec(&self.targets);
        for target in &self.targets {
            if let Some(access) = &target.access {
                access.charge_retained(heap);
            }
        }
        if let Some(bridge) = &self.published_bridge {
            bridge.charge_retained(heap);
        }
    }
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

#[derive(Clone)]
pub(super) struct JvmDeclaredType {
    fqn: String,
    owner: Option<crate::analyzer::resolution::ExternalOwnerIdentity>,
    indexed: bool,
}

pub(super) type JvmDeclaredTypeMemo = ExactReadMemo<(Language, String), Option<JvmDeclaredType>>;
pub(super) type JvmDeclaredOwnerMemo =
    ExactReadMemo<String, Option<Option<crate::analyzer::resolution::ExternalOwnerIdentity>>>;
pub(super) type JvmDeclarationPackageMemo = ExactReadMemo<(SemanticId, (u64, u64)), Option<String>>;

#[derive(Clone)]
struct JvmOnDemandType {
    declared: JvmDeclaredType,
    precedence: super::jvm_demand::JvmBindingPrecedence,
    package: String,
    source: Option<SelectedJavaOnDemandSource>,
}

#[derive(Clone)]
struct JvmOnDemandCandidate {
    precedence: super::jvm_demand::JvmBindingPrecedence,
    coordinate: Option<crate::analyzer::resolution::precedence::BindingScopeCoordinate>,
    fqn: String,
    package: String,
    declared: Option<JvmDeclaredType>,
    implicit_root: bool,
    source: Option<SelectedJavaOnDemandSource>,
}

fn on_demand_candidate_shadows(
    language: Language,
    left: &JvmOnDemandCandidate,
    right: &JvmOnDemandCandidate,
) -> bool {
    use crate::analyzer::resolution::precedence::{BindingScopeRelation, Shadowing};
    if language != Language::Scala {
        return (left.precedence.rank, left.precedence.depth)
            < (right.precedence.rank, right.precedence.depth);
    }
    let relation = match (&left.coordinate, &right.coordinate) {
        (Some(left), Some(right)) => left.relative_to(right),
        (Some(_), None) if right.implicit_root => BindingScopeRelation::Inner,
        (None, Some(_)) if left.implicit_root => BindingScopeRelation::Outer,
        (None, None) if left.implicit_root && right.implicit_root => BindingScopeRelation::Same,
        _ => BindingScopeRelation::Unrelated,
    };
    super::jvm_demand::jvm_shadowing_rules(language).shadows(
        left.precedence.rank,
        right.precedence.rank,
        relation,
    ) == Shadowing::Shadows
}

fn retain_on_demand_candidate(
    language: Language,
    candidates: &mut Vec<JvmOnDemandCandidate>,
    candidate: JvmOnDemandCandidate,
) {
    if candidates
        .iter()
        .any(|other| on_demand_candidate_shadows(language, other, &candidate))
    {
        return;
    }
    candidates.retain(|other| !on_demand_candidate_shadows(language, &candidate, other));
    candidates.push(candidate);
}

#[derive(Clone)]
enum JvmOnDemandTypeChoice {
    Unavailable,
    Competing(Vec<JvmOnDemandCandidate>),
    OpenDefault,
    Possible(JvmOnDemandType),
    Indexed(JvmOnDemandType),
    Alias(JvmOnDemandType),
    Intrinsic(JvmOnDemandType),
}

/// What the on-demand and default chooser observed for one reference.
struct JvmOnDemandObservation {
    choice: JvmOnDemandTypeChoice,
    /// The reference's authored local path was read, so `lexical` is a
    /// closed answer rather than a missing read.
    local_path_read: bool,
    /// A definition on the reference's lexical path (JLS 6.4.1).
    lexical: bool,
    /// A current-package definition from another compilation unit.
    same_package: bool,
    /// The chooser did not search on-demand and default packages: a nearer
    /// definition preempted them, or no provider was selected for a name that
    /// needs one.
    unsearched: bool,
}

impl JvmOnDemandObservation {
    fn searched(choice: JvmOnDemandTypeChoice) -> Self {
        Self {
            choice,
            local_path_read: false,
            lexical: false,
            same_package: false,
            unsearched: false,
        }
    }
}

/// One alternative for a simple type name at one reference.
#[derive(Clone)]
enum JvmTypeNameAlternative {
    /// A definition on the reference's lexical path.
    Lexical,
    /// A selected single-type import binder for the name, by import token.
    ExplicitImport(SemanticId),
    /// A current-package definition from another compilation unit.
    SamePackage,
    /// An on-demand or default-import candidate, by canonical name.
    OnDemand(String),
    /// A lexical definition placed on the scope order, by definition.
    PlacedLexical(SemanticId),
    /// A lexical binder whose selected scope cannot be placed on the
    /// reference ancestry, so no dominance claim is supported.
    UnsupportedLexical(SemanticId),
    /// A member type an enclosing class inherits, by declaration.
    InheritedMember(SemanticId),
}

// Java tier ranks, nearest scope first (JLS 6.4.1). Milestone 2 of #9546 adds
// the inherited member-type tier at rank 1.
const JVM_LEXICAL_TYPE_TIER: u32 = 0;
const JVM_SINGLE_TYPE_IMPORT_TIER: u32 = 2;
const JVM_SAME_PACKAGE_TYPE_TIER: u32 = 3;
const JVM_ON_DEMAND_TYPE_TIER: u32 = 4;

/// The complete simple-type-name decision for one selected reference: every
/// applicable tier is enumerated and closed before the language order picks a
/// winner. `lower` is the on-demand and default chooser's own result.
struct JvmSimpleTypeNameDecision {
    /// The lookup the decision answers. The memo is keyed by reference, so
    /// every caller must ask the same question about it.
    lookup: SemanticId,
    witnesses: Vec<TierWitness<JvmTypeNameAlternative>>,
    decision: TierDecision<JvmTypeNameAlternative>,
    lower: JvmOnDemandTypeChoice,
    /// Assembled with inherited member-type tiers: any Open decision keeps a
    /// lower positive choice possible only.
    open_inherited_rank: Option<u32>,
    /// Some tier value came from the operation's inherited-tier table, so the
    /// answer depends on the walk and its reuse is refused.
    consumed_walk: bool,
    selected_owner: Option<SelectedJavaTypeNameOwner>,
}

/// The tiers above on-demand and default imports for one Java reference, the
/// on-demand rank below them, and whether any tier read the inherited table.
struct JvmInheritedTypeNameTiers {
    tiers: Vec<TierInput<JvmTypeNameAlternative>>,
    on_demand_rank: u32,
    consumed_walk: bool,
    open_inherited_rank: Option<u32>,
}

/// One enclosing class's inherited member types for one name.
fn jvm_inherited_tier(
    rank: u32,
    witness: InheritedTierWitness,
) -> TierInput<JvmTypeNameAlternative> {
    let (candidates, closure) = match witness {
        InheritedTierWitness::Absent => (
            Vec::new(),
            ContributorClosure::Closed(TierReceipt {
                selected_read: "jvm-inherited-member-walk",
            }),
        ),
        InheritedTierWitness::Proven(declarations) => (
            declarations
                .into_iter()
                .map(JvmTypeNameAlternative::InheritedMember)
                .collect(),
            ContributorClosure::Closed(TierReceipt {
                selected_read: "jvm-inherited-member-walk",
            }),
        ),
        InheritedTierWitness::Open { .. } => (Vec::new(), ContributorClosure::Open),
    };
    TierInput {
        rank,
        contributors: vec![TierContributor {
            candidates,
            closure,
        }],
    }
}

/// The reference's enclosing classes are unknown, so no inherited tier can be
/// ruled out ahead of any other candidate.
fn jvm_unknown_enclosing_classes_tier() -> TierInput<JvmTypeNameAlternative> {
    TierInput {
        rank: 0,
        contributors: vec![TierContributor {
            candidates: Vec::new(),
            closure: ContributorClosure::Open,
        }],
    }
}

/// Whether the inherited tier can displace this lexical binder. The Java
/// branch follows JLS class-body ordering. Kotlin and Scala have no complete
/// classifier dominance proof for non-local binders here, so they remain
/// competing at every enclosing level.
fn jvm_inherited_competes(
    language: Language,
    lexical: LexicalTypeLevel,
    inherited_level: usize,
) -> bool {
    match language {
        Language::Java => match lexical {
            LexicalTypeLevel::Local => false,
            LexicalTypeLevel::Declared(level) => inherited_level < level,
            LexicalTypeLevel::Outside(level) => inherited_level <= level,
            LexicalTypeLevel::Unit => true,
        },
        Language::Kotlin | Language::Scala => !matches!(lexical, LexicalTypeLevel::Local),
        _ => unreachable!("JVM simple type name"),
    }
}

impl JvmSimpleTypeNameDecision {
    /// The scoped gap the selected route must carry when an inherited member
    /// type keeps its selection from being certain. An Open decision also
    /// withholds import and default-import targets below the open tier.
    fn inherited_lexical_gap(&self) -> Option<&'static str> {
        if matches!(&self.decision, TierDecision::Open { possible, .. } if possible.iter().any(|alternative| matches!(alternative, JvmTypeNameAlternative::UnsupportedLexical(_))))
        {
            return Some("jvm-inherited-member-type-unsupported-form");
        }
        if matches!(&self.decision, TierDecision::Open { .. }) && self.open_inherited_rank.is_some()
        {
            return Some("jvm-inherited-member-type-open");
        }
        if !self.consumed_walk {
            return None;
        }
        let inherited = |alternative: &JvmTypeNameAlternative| {
            matches!(alternative, JvmTypeNameAlternative::InheritedMember(_))
        };
        match &self.decision {
            TierDecision::Unique { selected, .. } if inherited(selected) => {
                Some("jvm-inherited-member-type-competing")
            }
            TierDecision::Ambiguous { candidates, .. } if candidates.iter().any(inherited) => {
                Some("jvm-inherited-member-type-competing")
            }
            TierDecision::Absent { .. }
            | TierDecision::Open { .. }
            | TierDecision::Unique { .. }
            | TierDecision::Ambiguous { .. } => None,
        }
    }

    /// `nearer` holds the tiers above on-demand and default imports.
    fn from_tiers(
        lookup: SemanticId,
        mut nearer: Vec<TierInput<JvmTypeNameAlternative>>,
        on_demand_rank: u32,
        observed: JvmOnDemandObservation,
        consumed_walk: bool,
        open_inherited_rank: Option<u32>,
    ) -> Self {
        let (candidates, closed) = match &observed.choice {
            _ if observed.unsearched => (Vec::new(), false),
            JvmOnDemandTypeChoice::Unavailable => (Vec::new(), true),
            JvmOnDemandTypeChoice::OpenDefault => (Vec::new(), false),
            JvmOnDemandTypeChoice::Possible(winner) => (
                vec![JvmTypeNameAlternative::OnDemand(
                    winner.declared.fqn.clone(),
                )],
                false,
            ),
            JvmOnDemandTypeChoice::Competing(candidates) => (
                candidates
                    .iter()
                    .map(|candidate| JvmTypeNameAlternative::OnDemand(candidate.fqn.clone()))
                    .collect(),
                true,
            ),
            JvmOnDemandTypeChoice::Indexed(winner)
            | JvmOnDemandTypeChoice::Alias(winner)
            | JvmOnDemandTypeChoice::Intrinsic(winner) => (
                vec![JvmTypeNameAlternative::OnDemand(
                    winner.declared.fqn.clone(),
                )],
                true,
            ),
        };
        let highest_open_rank = nearer
            .iter()
            .filter(|tier| {
                tier.contributors
                    .iter()
                    .any(|contributor| matches!(contributor.closure, ContributorClosure::Open))
            })
            .map(|tier| tier.rank)
            .min();
        nearer.push(TierInput {
            rank: on_demand_rank,
            contributors: vec![TierContributor {
                candidates,
                closure: if closed {
                    ContributorClosure::Closed(TierReceipt {
                        selected_read: "jvm-on-demand-package-plan",
                    })
                } else {
                    ContributorClosure::Open
                },
            }],
        });
        // The chooser already ranks its own candidates; tiers are disjoint.
        let (witnesses, decision) = evaluate_tiers(nearer, |_| {});
        Self {
            lookup,
            witnesses,
            decision,
            lower: observed.choice,
            consumed_walk,
            open_inherited_rank: open_inherited_rank
                .filter(|rank| Some(*rank) == highest_open_rank),
            selected_owner: None,
        }
    }

    /// The choice the on-demand and default registrations consume. A nearer
    /// tier that is Proven leaves them nothing to bind. With inherited tiers
    /// an Open decision makes a lower positive choice possible only; the
    /// legacy path without them retains its existing result.
    fn on_demand_choice(&self) -> JvmOnDemandTypeChoice {
        let nearer = |alternative: &JvmTypeNameAlternative| {
            !matches!(alternative, JvmTypeNameAlternative::OnDemand(_))
        };
        match &self.decision {
            TierDecision::Unique { selected, .. } if nearer(selected) => {
                JvmOnDemandTypeChoice::Unavailable
            }
            TierDecision::Ambiguous { candidates, .. } if candidates.iter().all(nearer) => {
                JvmOnDemandTypeChoice::Unavailable
            }
            TierDecision::Open { .. } if self.open_inherited_rank.is_some() => match &self.lower {
                JvmOnDemandTypeChoice::Indexed(winner)
                | JvmOnDemandTypeChoice::Alias(winner)
                | JvmOnDemandTypeChoice::Intrinsic(winner) => {
                    JvmOnDemandTypeChoice::Possible(winner.clone())
                }
                other => other.clone(),
            },
            _ => self.lower.clone(),
        }
    }
}

pub(super) struct JvmLexicalAnswerFinalizer<'a, 'store, 'project> {
    pub(super) operation: &'a SelectedResolutionOperation<'store, 'project>,
}

impl crate::analyzer::resolution::fact_resolution::LexicalAnswerFinalizer
    for JvmLexicalAnswerFinalizer<'_, '_, '_>
{
    fn refuse_consumed_walk(&self, consumed_walk: bool) -> Result<()> {
        if consumed_walk {
            self.operation
                .ready
                .read_reuse
                .ok_or_else(|| super::missing_read_reuse_authority("JVM inherited member"))?
                .refuse_read_reuse();
        }
        Ok(())
    }

    fn finalize(
        &self,
        reference: SemanticId,
        answer: crate::analyzer::resolution::fact_resolution::SharedAnswer,
        cancellation: &CancellationToken,
    ) -> Result<crate::analyzer::resolution::fact_resolution::FinalizedLexicalAnswer> {
        use crate::analyzer::resolution::fact_resolution::FinalizedLexicalAnswer;
        let unchanged = |answer| FinalizedLexicalAnswer {
            answer,
            withheld: None,
            consumed_walk: false,
            labelled_incomplete: false,
        };
        if self.operation.jvm_inherited_tier_knowledge.is_none() {
            return Ok(unchanged(answer));
        }
        let Some(ordinal) = reference.ordinal() else {
            return Ok(unchanged(answer));
        };
        let source = self
            .operation
            .mount_table()
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let Some(prepared) = self.operation.jvm_import_context_preparation(
            source.semantic_language(),
            source.persisted_relative_path(),
            cancellation,
        )?
        else {
            return Ok(unchanged(answer));
        };
        let Some(decision) = prepared.simple_type_name_decisions.get(&reference) else {
            return Ok(unchanged(answer));
        };
        let Some(label) = decision.inherited_lexical_gap() else {
            return Ok(FinalizedLexicalAnswer {
                consumed_walk: decision.consumed_walk,
                ..unchanged(answer)
            });
        };
        if let TierDecision::Unique {
            selected: JvmTypeNameAlternative::InheritedMember(inherited),
            ..
        } = &decision.decision
            && answer.targets() == [*inherited]
        {
            return Ok(FinalizedLexicalAnswer {
                consumed_walk: decision.consumed_walk,
                ..unchanged(answer)
            });
        }
        if answer.targets().is_empty() {
            return Ok(FinalizedLexicalAnswer {
                consumed_walk: decision.consumed_walk,
                ..unchanged(answer)
            });
        }
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(
            self.operation.ready.context_identities.named_semantic(
                CanonicalHasher::new(label.as_bytes()).finish(),
                label,
                "Inherited member type may displace the lexical type",
            ),
        );
        let completion = answer
            .completion()
            .combine(&ResolutionCompletion::incomplete([reason]));
        let withheld = (label == "jvm-inherited-member-type-open").then(|| {
            crate::analyzer::resolution::batch::WithheldLexicalTargets {
                targets: answer.targets().to_vec().into_boxed_slice(),
                reason,
            }
        });
        Ok(FinalizedLexicalAnswer {
            answer: Arc::new(ResolutionAnswer::new([], [], completion)),
            withheld,
            consumed_walk: decision.consumed_walk,
            labelled_incomplete: true,
        })
    }
}

fn jvm_on_demand_import(binder: &ImportBinder) -> bool {
    match binder.route.as_ref().map(|route| route.kind) {
        Some(SelectedImportRouteKind::TypeOnDemand | SelectedImportRouteKind::Star) => true,
        Some(SelectedImportRouteKind::SingleStatic | SelectedImportRouteKind::StaticOnDemand) => {
            false
        }
        _ => binder
            .selector
            .as_ref()
            .is_some_and(|selector| selector.kind == ResolutionImportSelectorKind::Star),
    }
}

fn jvm_on_demand_package(binder: &ImportBinder) -> String {
    binder.recipes[..binder.recipes.len() - 1]
        .iter()
        .map(ResolutionLookupSemanticRecipe::spelling)
        .collect::<Vec<_>>()
        .join(".")
}

// A provider-free lookup can still inspect authored on-demand imports.
// Aliases admit both namespaces; compiler roots admit Type only. Share this
// with package planning so every inspected package is in the asserted plan.
fn on_demand_type_admitted_without_provider(
    language: Language,
    recipe: &ResolutionLookupSemanticRecipe,
) -> bool {
    brokk_bifrost_jvm::intrinsics::ordered_implicit_root(language, recipe.spelling(), |root| {
        brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(language, root, recipe.spelling())
            .or_else(|| {
                (recipe.namespace() == ResolutionNamespace::Type)
                    .then(|| {
                        brokk_bifrost_jvm::intrinsics::compiler_root_owner(
                            language,
                            root,
                            recipe.spelling(),
                        )
                    })
                    .flatten()
            })
    })
    .into_answer()
    .is_some()
}

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
enum JvmPackageCandidate {
    SourceMount {
        mount: SelectedResolutionMountOrdinal,
        version: Option<i64>,
        order: usize,
        members: Arc<[LoweredPackageMember]>,
    },
    ExternalMember(JvmExternalPackageMember),
}

#[derive(Clone)]
pub(in crate::analyzer) struct JvmExternalPackageMember {
    pub member: crate::analyzer::resolution::ExternalMemberIdentity,
    pub pack_id: String,
    pub pack_version: String,
    pub is_static: bool,
    pub visibility: DeclaredVisibility,
    pub completion: ResolutionCompletion,
}

pub(super) struct JvmPackageIndex {
    empty: bool,
    by_lookup: HashMap<SemanticId, Vec<JvmPackageCandidate>>,
}

pub(super) type JvmPackageIndexMemo = ExactReadMemo<JvmPackageTargetKey, Arc<JvmPackageIndex>>;

#[derive(Clone)]
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
    pub(crate) external_member_targets: Vec<SemanticId>,
    pub(crate) pack_completion: ResolutionCompletion,
    suppress_if_same_package_candidate: bool,
}

pub(super) fn assert_compatible_scoped_gap_reasons(
    previous: &JvmImportContextGap,
    current: &JvmImportContextGap,
) {
    assert_eq!(previous.reason, current.reason);
    if previous.kind == JVM_IMPORT_ALIAS_COVERAGE_OPEN {
        // This reason comes from the selected alias surface's incomplete
        // completion, so several imports can attach it to different lookups.
        // Their source token, reference, lookup and owner belong to the
        // attachment; the underlying coverage and closure must still agree.
        assert_eq!(
            (
                previous.kind,
                previous.boundary_status,
                previous.nominal_type_identity,
                &previous.external_member_targets,
                &previous.pack_completion,
                previous.suppress_if_same_package_candidate,
            ),
            (
                current.kind,
                current.boundary_status,
                current.nominal_type_identity,
                &current.external_member_targets,
                &current.pack_completion,
                current.suppress_if_same_package_candidate,
            ),
            "scoped alias coverage gaps sharing a reason disagree on closure"
        );
    } else {
        // A package-demand token can represent several references. Only the
        // representative source reference may differ for one owned reason.
        let mut previous = previous.clone();
        let mut current = current.clone();
        previous.source_reference = None;
        current.source_reference = None;
        assert_eq!(
            previous, current,
            "scoped gaps sharing a reason disagree on provenance or closure"
        );
    }
}

/// One exact selected terminal route published for a JVM root reference.
/// `complete` is set only when the selected package/member pages and access
/// evidence exhaust this namespace's candidate space.
pub(in crate::analyzer) struct JvmRoutePublication {
    pub(super) bridges: Vec<SelectedRootBridgeDescriptor>,
    pub(super) selected_targets: BTreeSet<SemanticId>,
    pub(super) complete: bool,
}

// One qualified reference's selected inputs, retained only for this query.
struct JvmQualifiedPublicationInput<'a> {
    half: &'a SelectedRootPathHalf,
    source_language: Language,
    source_record: Arc<crate::analyzer::store::resolution_selection::SelectedResolutionMountRecord>,
    context: i64,
    caller_package: Option<String>,
    recipes: Vec<ResolutionLookupSemanticRecipe>,
    source_demand: ResolutionLookupSemanticRecipe,
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
                kind: JVM_IMPORT_ALIAS_COVERAGE_OPEN,
                owner: Some(owner.to_owned()),
                boundary_status: None,
                nominal_type_identity: None,
                external_member_targets: Vec::new(),
                pack_completion: ResolutionCompletion::Complete,
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
    prepared: &'a JvmContextPreparation,
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
        let caller_package = if source_language == Language::Scala {
            self.prepared
                .scala_reference_packages
                .get(&reference.token)
                .and_then(Option::as_ref)
                .and_then(|prefixes| prefixes.last())
                .map(String::as_str)
        } else {
            self.caller_package
        };
        let target_mount = &candidate.target;
        debug_assert_ne!(pair.target_mount, self.source.ordinal());
        let target_language = target_mount.semantic_language();
        let target_version = match candidate.candidate {
            JvmPackageCandidate::SourceMount { version, .. } => *version,
            JvmPackageCandidate::ExternalMember(_) => {
                unreachable!("external member has no source bridge")
            }
        };
        if member.namespace != reference.namespace
            || member.lookup != candidate.target_lookup_semantic
        {
            return Ok(None);
        }
        if Some(candidate.package) == caller_package
            && !matches!(
                self.operation.jvm_current_package_candidate(
                    self.prepared,
                    reference.lookup,
                    member.definition,
                    candidate.package,
                    cancellation,
                )?,
                SelectedPackageRows::Ready(true)
            )
        {
            return Ok(None);
        }
        let relation = JvmDeclarationAccessContext::between(caller_package, candidate.package)
            .with_reference(Some(reference.reference));
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
        let lexical_package = source_language == Language::Scala
            && self
                .prepared
                .scala_reference_packages
                .get(&reference.token)
                .and_then(Option::as_ref)
                .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix == candidate.package));
        if (Some(candidate.package) == caller_package || lexical_package)
            && completion == ResolutionCompletion::Complete
        {
            self.same_package_lookups
                .borrow_mut()
                .insert(if source_language == Language::Scala {
                    reference.token
                } else {
                    reference.lookup
                });
        }
        let precedence = SelectedResolutionOperation::selected_jvm_package_precedence(
            source_language,
            caller_package,
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

// Borrowed site and alias evidence is consumed synchronously by Java's rule.
struct JvmUnresolvedStaticOwner<'a> {
    prepared: &'a JvmContextPreparation,
    binder: &'a ImportBinder,
    owner: &'a str,
    open_aliases: &'a [String],
    coverage_gaps: &'a [JvmImportContextGap],
    accumulated_alias_open: bool,
}

struct JvmStaticOwnerScope {
    owner: String,
}

fn has_open_jvm_alias_for_owner(
    aliases: &[String],
    gaps: &[JvmImportContextGap],
    recipes: &[ResolutionLookupSemanticRecipe],
) -> bool {
    if aliases.is_empty() && gaps.is_empty() {
        return false;
    }
    let source_owner = recipes
        .iter()
        .map(ResolutionLookupSemanticRecipe::spelling)
        .collect::<Vec<_>>();
    (1..=source_owner.len()).any(|package_segments| {
        let owner = crate::analyzer::resolution::language_jvm_import_binary_owner(
            Language::Java,
            package_segments,
            &source_owner,
        )
        .join(".");
        let owner_prefix = format!("{owner}.");
        aliases
            .iter()
            .any(|alias| alias == &owner || alias.starts_with(&owner_prefix))
            || gaps.iter().any(|gap| {
                matches!(
                    gap.kind,
                    JVM_IMPORT_ALIAS_COVERAGE_OPEN | "jvm-import-alias-route-open"
                ) && gap.owner.as_deref() == Some(owner.as_str())
            })
    })
}

fn java_unresolved_static_owner(
    witness: &JvmUnresolvedStaticOwner<'_>,
) -> Option<JvmStaticOwnerScope> {
    (!witness.accumulated_alias_open
        && witness.open_aliases.is_empty()
        && witness.coverage_gaps.is_empty()
        && !witness.owner.is_empty())
    .then(|| JvmStaticOwnerScope {
        owner: witness.owner.to_owned(),
    })
}

fn record_jvm_import_member_scope(
    operation: &SelectedResolutionOperation<'_, '_>,
    witness: &JvmUnresolvedStaticOwner<'_>,
    scope: &JvmStaticOwnerScope,
) -> Result<()> {
    let Some(route) = witness.binder.route.as_ref() else {
        return Ok(());
    };
    let Some(source_site) = route.source_site else {
        return Ok(());
    };
    for reason in selected_java_import_route_gap_reasons(
        &operation.ready.inventory,
        witness.prepared.source_record.blob_id(),
        witness.prepared.source.ordinal(),
        source_site,
        route.staged,
    )? {
        operation
            .ready
            .context_identities
            .record_jvm_import_member_scope(
                reason,
                crate::analyzer::resolution::fact_lowering::site_semantic(
                    witness.prepared.source.fragment(),
                    source_site,
                ),
                &scope.owner,
            );
    }
    Ok(())
}

// Rules for the common import assembly. Defaults retain the selected peer route.
trait JvmImportAssemblyRules {
    fn nominal(&self) -> &'static dyn super::nominal_rules::NominalLanguageRules;
    fn declaration_access_source(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        identity: super::SemanticId,
    ) -> Option<std::sync::Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>>
    {
        self.nominal()
            .declaration_access_source(operation, identity)
    }
    fn selector(&self, binder: &ImportBinder) -> Option<SelectedImportSelector> {
        binder.selector.clone()
    }
    fn import_kind(&self, _binder: &ImportBinder) -> Option<ResolutionImportRouteKind> {
        None
    }
    fn type_import_proof(&self, _binder: &ImportBinder) -> Option<ResolutionImportRouteKind> {
        None
    }
    fn static_import(&self, _binder: &ImportBinder) -> Option<ResolutionImportRouteKind> {
        None
    }
    // Called only after alias/member evaluation found no owner or alias, with
    // no open alias/coverage route, before recording the external owner.
    // Coverage has already been extended into scoped gaps even when the hook is not called.
    // Effects belong to the operation: an import memo hit reuses that same ledger.
    fn unresolved_static_owner(
        &self,
        _witness: &JvmUnresolvedStaticOwner<'_>,
    ) -> Option<JvmStaticOwnerScope> {
        None
    }
    fn needs_owner_global_alias_prepass(&self) -> bool {
        false
    }
    fn qualified_package_mounts(&self) -> ImportTargetMounts {
        self.nominal().family().import_target_mounts()
    }
    fn qualified_empty_route_package<'a>(&self, caller: Option<&'a str>) -> Option<&'a str> {
        caller
    }
    fn qualified_member_scope(&self, scope: BindingNodeId) -> Option<BindingNodeId> {
        Some(scope)
    }
    fn finalize_qualified_publication(&self, _publication: &mut JvmRoutePublication) {}
    fn finalize_aliases(&self, _aliases: &mut Vec<String>) {}
    fn package_targets(&self) -> [Option<&'static str>; 3] {
        self.nominal()
            .family()
            .package_alias_target_languages(self.nominal().language())
    }
    fn member_bridges(
        &self,
        _operation: &SelectedResolutionOperation<'_, '_>,
        _kind: Option<ResolutionImportRouteKind>,
        members: Vec<JavaImportMemberCandidate>,
        _cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        Ok(Some(
            members.into_iter().map(|member| member.bridge).collect(),
        ))
    }
}

fn jvm_inventory_reason_digest(
    fragment: BindingFragmentId,
    language: Language,
    resolve: impl FnMut(ResolutionIdentityDigestKey) -> Result<[u8; 32]>,
) -> Result<[u8; 32]> {
    let mut descriptor =
        CanonicalIdentityDescriptor::new(b"bifrost-jvm-context-incomplete:v1", resolve);
    descriptor.field("context", CanonicalIdentityPart::identity(fragment))?;
    descriptor.field(
        "language",
        CanonicalIdentityPart::Label(language.config_label()),
    )?;
    Ok(descriptor.finish())
}

struct SelectedJvmImportRules(&'static dyn super::nominal_rules::NominalLanguageRules);
impl JvmImportAssemblyRules for SelectedJvmImportRules {
    fn nominal(&self) -> &'static dyn super::nominal_rules::NominalLanguageRules {
        self.0
    }
}

// Java supplies its language rules to the one production JVM assembly.
struct JavaJvmImportRules;
impl JvmImportAssemblyRules for JavaJvmImportRules {
    fn nominal(&self) -> &'static dyn super::nominal_rules::NominalLanguageRules {
        nominal_language_rules(Language::Java).expect("Java has nominal rules")
    }

    fn unresolved_static_owner(
        &self,
        witness: &JvmUnresolvedStaticOwner<'_>,
    ) -> Option<JvmStaticOwnerScope> {
        java_unresolved_static_owner(witness)
    }
    fn needs_owner_global_alias_prepass(&self) -> bool {
        true
    }

    fn declaration_access_source(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        identity: super::SemanticId,
    ) -> Option<std::sync::Arc<dyn crate::analyzer::resolution::SelectedDeclarationAccessSource>>
    {
        Some(operation.jvm_declaration_access_source(identity))
    }
    fn qualified_package_mounts(&self) -> ImportTargetMounts {
        self.nominal()
            .family()
            .own_language_target_mounts(Language::Java)
    }
    fn qualified_empty_route_package<'a>(&self, caller: Option<&'a str>) -> Option<&'a str> {
        self.nominal().empty_route_package(caller)
    }
    fn qualified_member_scope(&self, _scope: BindingNodeId) -> Option<BindingNodeId> {
        None
    }
    fn finalize_qualified_publication(&self, publication: &mut JvmRoutePublication) {
        publication.complete = false;
        publication.selected_targets.clear();
    }
    fn package_targets(&self) -> [Option<&'static str>; 3] {
        self.nominal().family().storage_language_parameters()
    }
    fn import_kind(&self, binder: &ImportBinder) -> Option<ResolutionImportRouteKind> {
        Some(match binder.route.as_ref()?.kind {
            SelectedImportRouteKind::SingleType => ResolutionImportRouteKind::SingleType,
            SelectedImportRouteKind::TypeOnDemand => ResolutionImportRouteKind::TypeOnDemand,
            SelectedImportRouteKind::SingleStatic => ResolutionImportRouteKind::SingleStatic,
            SelectedImportRouteKind::StaticOnDemand => ResolutionImportRouteKind::StaticOnDemand,
            SelectedImportRouteKind::Named | SelectedImportRouteKind::Star => return None,
        })
    }
    fn type_import_proof(&self, binder: &ImportBinder) -> Option<ResolutionImportRouteKind> {
        self.import_kind(binder).filter(|kind| {
            matches!(
                kind,
                ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::TypeOnDemand
            )
        })
    }
    fn static_import(&self, binder: &ImportBinder) -> Option<ResolutionImportRouteKind> {
        self.import_kind(binder).filter(|kind| {
            matches!(
                kind,
                ResolutionImportRouteKind::SingleStatic | ResolutionImportRouteKind::StaticOnDemand
            )
        })
    }
    fn finalize_aliases(&self, aliases: &mut Vec<String>) {
        aliases.sort_unstable();
        aliases.dedup();
    }
    fn selector(&self, binder: &ImportBinder) -> Option<SelectedImportSelector> {
        if let Some(selector) = &binder.selector {
            return Some(selector.clone());
        }
        let (kind, source_name) = match self.import_kind(binder)? {
            ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic => (
                ResolutionImportSelectorKind::Named,
                Some(
                    binder
                        .recipes
                        .last()
                        .expect("one selected import demand")
                        .spelling()
                        .to_owned(),
                ),
            ),
            ResolutionImportRouteKind::TypeOnDemand | ResolutionImportRouteKind::StaticOnDemand => {
                (ResolutionImportSelectorKind::Star, None)
            }
            ResolutionImportRouteKind::Named | ResolutionImportRouteKind::Star => {
                unreachable!("candidate Java import kinds are structured")
            }
        };
        Some(SelectedImportSelector {
            kind,
            source_name,
            local_name: None,
        })
    }
    fn member_bridges(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        kind: Option<ResolutionImportRouteKind>,
        members: Vec<JavaImportMemberCandidate>,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
        if matches!(
            kind,
            Some(
                ResolutionImportRouteKind::SingleStatic | ResolutionImportRouteKind::StaticOnDemand
            )
        ) {
            operation.java_static_import_bridges(members, cancellation)
        } else {
            Ok(Some(
                members.into_iter().map(|member| member.bridge).collect(),
            ))
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Count one import-context snapshot outcome (published, restored, or a
    /// refusal cause) in this operation's `BIFROST_SEAM_PROFILE` record.
    #[doc(hidden)]
    pub fn profile_jvm_import_context_snapshot(&self, outcome: impl std::fmt::Debug) {
        self.profile_jvm_read("import_context_snapshot", outcome);
    }

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

    fn jvm_file_context_key(
        &self,
        language: Language,
        path: &str,
        lookup: Option<&str>,
    ) -> JvmFileContextKey {
        JvmFileContextKey {
            language,
            path: path.to_owned(),
            lookup: lookup.map(str::to_owned),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        }
    }

    /// The reuse key for this operation's base import context of one file.
    #[doc(hidden)]
    pub fn jvm_import_context_snapshot_key(
        &self,
        source_language: Language,
        caller_path: &str,
    ) -> JvmImportContextSnapshotKey {
        JvmImportContextSnapshotKey {
            language: source_language,
            path: caller_path.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            routing: self.ready.inventory.routing_digest(),
            providers: self.ready.selected_jvm_external_providers(),
            model_set: self
                .ready
                .model_authority()
                .map(|authority| authority.active_model_set_hash().to_owned()),
            native_rejection_trace: crate::analyzer::resolution::resolution_diagnostics()
                .native_rejection_projection_active(),
        }
    }

    /// A snapshot is published from, and restored into, only an operation
    /// that has done no JVM context work and minted no shared name, so its
    /// numbering and memo state are exactly the build's.
    fn jvm_import_context_snapshot_refusal(&self) -> Option<JvmImportContextSnapshotRefusal> {
        // Walk and Unavailable take the same tier-assembly path. Unavailable
        // fails if a witness is asked, so a completed context under either
        // variant has the same content until a decision consumes a witness.
        if matches!(
            self.jvm_inherited_tier_knowledge,
            Some(super::inherited_member_walk::JvmInheritedKnowledge::Frozen(
                _
            )) | Some(super::inherited_member_walk::JvmInheritedKnowledge::Bottom)
        ) || self.jvm_decision_consumed_walk.get()
        {
            return Some(JvmImportContextSnapshotRefusal::InheritedTierKnowledge);
        }
        if self.ready.inventory.staged_read_epoch() != (0, 0)
            || !self.ready.context_identities.is_empty()
            || !self.jvm_file_contexts.borrow().is_empty()
            || !self.jvm_context_preparations.is_empty()
            || !self.jvm_access_policies.borrow().is_empty()
            || !self.jvm_on_demand_type_ranks.borrow().is_empty()
        {
            return Some(JvmImportContextSnapshotRefusal::UsedOperation);
        }
        (!self.ready.inventory.shared_names.is_unminted())
            .then_some(JvmImportContextSnapshotRefusal::MintedNames)
    }

    /// Build a file's base import context cold. When this operation started
    /// fresh and the build is Ready, also capture it for later operations.
    #[doc(hidden)]
    pub fn jvm_import_context_with_snapshot(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<(
        JvmImportContext,
        std::result::Result<JvmImportContextSnapshot, JvmImportContextSnapshotRefusal>,
    )> {
        let refusal = self.jvm_import_context_snapshot_refusal();
        let max_interned = match refusal {
            None => super::super::resolution::max_interned_shared_name_id(
                self.ready.inventory.connection(),
            )?,
            Some(_) => 0,
        };
        let context = self.jvm_import_context(source_language, caller_path, cancellation)?;
        if let Some(refusal) = refusal.or_else(|| {
            self.jvm_decision_consumed_walk
                .get()
                .then_some(JvmImportContextSnapshotRefusal::InheritedTierKnowledge)
        }) {
            return Ok((context, Err(refusal)));
        }
        let JvmImportContext::Ready {
            context: set,
            external_static_imports,
            inventory_reason,
            open_jvm_alias_imports,
            scoped_gaps,
        } = &context
        else {
            return Ok((context, Err(JvmImportContextSnapshotRefusal::NotReady)));
        };
        if cancellation.is_cancelled() {
            return Ok((context, Err(JvmImportContextSnapshotRefusal::NotReady)));
        }
        let identities = self.ready.context_identities.isolated_clone();
        let file_context_key = self.jvm_file_context_key(source_language, caller_path, None);
        let snapshot = JvmImportContextSnapshot {
            shared_names: self.ready.inventory.shared_names.minted_names(),
            max_interned,
            preparation: self
                .jvm_context_preparations
                .get(&file_context_key)
                .map(|preparation| (*preparation).clone()),
            file_context_key,
            context: JvmImportContext::Ready {
                context: Box::new((**set).clone().with_identity_space(identities.clone())),
                external_static_imports: external_static_imports.clone(),
                inventory_reason: *inventory_reason,
                open_jvm_alias_imports: open_jvm_alias_imports.clone(),
                scoped_gaps: scoped_gaps.clone(),
            },
            identities,
            access_policies: self.jvm_access_policies.borrow().clone(),
            on_demand_ranks: self
                .jvm_on_demand_type_ranks
                .borrow()
                .iter()
                .map(|(identity, rank)| (*identity, *rank))
                .collect(),
        };
        Ok((context, Ok(snapshot)))
    }

    /// Install a published base context into this fresh operation, or report
    /// why not. A refusal leaves the operation unchanged; the caller then
    /// builds cold.
    #[doc(hidden)]
    pub fn restore_jvm_import_context_snapshot(
        &self,
        snapshot: &JvmImportContextSnapshot,
    ) -> Result<std::result::Result<JvmImportContext, JvmImportContextSnapshotRefusal>> {
        if let Some(refusal) = self.jvm_import_context_snapshot_refusal() {
            return Ok(Err(refusal));
        }
        if super::super::resolution::max_interned_shared_name_id(self.ready.inventory.connection())?
            != snapshot.max_interned
            || !self
                .ready
                .inventory
                .shared_names
                .seed_minted_names(&snapshot.shared_names)
        {
            return Ok(Err(
                JvmImportContextSnapshotRefusal::StoreInternedSincePublish,
            ));
        }
        self.ready
            .context_identities
            .copy_from_empty(&snapshot.identities);
        let JvmImportContext::Ready {
            context: set,
            external_static_imports,
            inventory_reason,
            open_jvm_alias_imports,
            scoped_gaps,
        } = &snapshot.context
        else {
            unreachable!("only a Ready base context is published");
        };
        let context = JvmImportContext::Ready {
            context: Box::new(
                (**set)
                    .clone()
                    .with_identity_space(self.ready.context_identities.clone()),
            ),
            external_static_imports: external_static_imports.clone(),
            inventory_reason: *inventory_reason,
            open_jvm_alias_imports: open_jvm_alias_imports.clone(),
            scoped_gaps: scoped_gaps.clone(),
        };
        self.jvm_file_contexts
            .borrow_mut()
            .insert(snapshot.file_context_key.clone(), context.clone());
        if let Some(preparation) = &snapshot.preparation {
            self.jvm_context_preparations.admit(
                snapshot.file_context_key.clone(),
                Arc::new(preparation.clone()),
            );
        }
        self.jvm_access_policies.borrow_mut().extend(
            snapshot
                .access_policies
                .iter()
                .map(|(identity, policy)| (*identity, Arc::clone(policy))),
        );
        let mut ranks = self.jvm_on_demand_type_ranks.borrow_mut();
        for &(identity, rank) in &snapshot.on_demand_ranks {
            ranks.insert(identity, rank);
        }
        Ok(Ok(context))
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
        let key = self.jvm_file_context_key(source_language, caller_path, lookup);
        if let Some(context) = self.jvm_file_contexts.borrow().get(&key) {
            return Ok(context.clone());
        }
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        let context = rules.selected_import_context(self, caller_path, lookup, cancellation)?;
        if let JvmImportContext::Ready { scoped_gaps, .. } = &context {
            let mut reasons: HashMap<SemanticId, &JvmImportContextGap> = HashMap::default();
            for gap in scoped_gaps {
                if let Some(previous) = reasons.insert(gap.reason, gap) {
                    // Different attachments may carry one reason. Validate
                    // the reason's provenance and closure before publication.
                    assert_compatible_scoped_gap_reasons(previous, gap);
                }
            }
        }
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

    /// The package one JVM source file declares, from its memoized context
    /// preparation: the outer None is cancellation or an unprepared file, the
    /// inner None the default package.
    pub(super) fn jvm_source_file_package(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Option<String>>> {
        Ok(self
            .jvm_import_context_preparation(source_language, caller_path, cancellation)?
            .map(|prepared| prepared.source_package.clone()))
    }

    fn jvm_import_context_preparation(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmContextPreparation>>> {
        let key = self.jvm_file_context_key(source_language, caller_path, None);
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
            .prepare_cached(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
            )?
            .query_row([source_record.blob_id()], |row| row.get(0))
            .optional()?;
        let source_package = rules
            .lexical_package(self, source_record.blob_id())?
            .or(source_package);
        let identities = self.ready.context_identities.clone();
        let inventory_reason = if rules.has_context_import_inventory() {
            let digest = jvm_inventory_reason_digest(source.fragment(), source_language, |key| {
                self.ready.identity_content_digest(key, cancellation)
            })?;
            Some(identities.named_semantic(
                digest,
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
        let mut scala_reference_packages = HashMap::default();
        if source_language == Language::Scala {
            for reference in &package_references {
                scala_reference_packages.insert(
                    reference.token,
                    self.scala_reference_package_prefixes_with_coverage(
                        source_record.blob_id(),
                        ScalaPackageContextReference::Site(reference.source_site),
                    )?,
                );
            }
        }
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
        let mut scala_local_package_by_token = HashMap::default();
        let SelectedPackageRows::Ready(local_package_members) =
            self.jvm_package_member_set(source.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        for reference in &package_references {
            let members = local_package_members
                .get(&reference.lookup)
                .into_iter()
                .flat_map(|members| members.iter())
                .filter(|member| {
                    member.domain == reference.domain && member.namespace == reference.namespace
                })
                .collect::<Vec<_>>();
            if source_language == Language::Scala {
                if let Some(prefixes) = scala_reference_packages
                    .get(&reference.token)
                    .and_then(Option::as_ref)
                {
                    for package in prefixes.iter().rev() {
                        let mut found = false;
                        for member in &members {
                            let SelectedPackageRows::Ready(declared) =
                                self.jvm_declaration_package(member.definition, cancellation)?
                            else {
                                return Ok(None);
                            };
                            found |= declared.as_deref() == Some(package.as_str());
                        }
                        if found {
                            // Scala keys same-package proof by occurrence token, as
                            // the bridge and current-package producers do. A member
                            // of a certified enclosing package outranks default
                            // imports, so it suppresses their gaps for this token.
                            scala_local_package_by_token.insert(reference.token, package.clone());
                            same_package_lookups.insert(reference.token);
                            break;
                        }
                    }
                }
            } else if !members.is_empty() {
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
        // A language whose types can be called (Kotlin's `Thread()`) also
        // searches an unqualified callee's Type namespace, so a default or
        // on-demand import offers the callee the type it offers a written type
        // reference. Explicit imports admit callees the same way.
        let callee_names_types = matches!(
            crate::analyzer::resolution::fact_resolution::type_in_call_position(source_language),
            crate::analyzer::resolution::fact_resolution::TypeInCallPosition::Constructors
                | crate::analyzer::resolution::fact_resolution::TypeInCallPosition::ApplyMembers
        );
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
                            let is_unqualified_callee = callee_names_types
                                && metadata.namespace() == ResolutionNamespace::Callable
                                && metadata.unqualified();
                            (is_unqualified_callee
                                || (matches!(
                                    metadata.namespace(),
                                    ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
                                ) && (is_type_reference || is_type_or_value_qualifier)))
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
        let Some(package_plan) = self.jvm_file_package_plan(
            source_language,
            source.fragment(),
            source_package.as_deref(),
            &scala_reference_packages,
            &package_references,
            &binders,
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
            scala_reference_packages,
            scala_local_package_by_token,
            same_package_lookups,
            references_by_name,
            unqualified_type_references,
            imports: ContextPlanMemo::default(),

            implicit: ContextPlanCell::default(),
            external_providers,
            simple_type_name_decisions: ContextPlanMemo::default(),
            on_demand_bindings: ContextPlanMemo::default(),
        })))
    }

    pub(super) fn assemble_jvm_import_context(
        &self,
        source_language: Language,
        caller_path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        let rules =
            nominal_language_rules(source_language).expect("caller belongs to a nominal family");
        if source_language == Language::Java {
            return self.assemble_jvm_import_context_with_rules(
                &JavaJvmImportRules,
                caller_path,
                lookup,
                cancellation,
            );
        }
        self.assemble_jvm_import_context_with_rules(
            &SelectedJvmImportRules(rules),
            caller_path,
            lookup,
            cancellation,
        )
    }

    fn assemble_jvm_import_context_with_rules(
        &self,
        assembly: &dyn JvmImportAssemblyRules,
        caller_path: &str,
        lookup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        let rules = assembly.nominal();
        let source_language = rules.language();
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
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
        let mut external_static_imports = Vec::new();
        let mut static_import_searches = BTreeMap::new();
        let mut root_bridges = Vec::new();
        let mut model_declared_routes = Vec::new();
        let mut route_inventory_open = false;
        let mut scoped_gaps = Vec::new();
        let mut open_jvm_alias_imports = Vec::new();
        let mut earlier_scala_imports = BTreeMap::new();
        let open_static_alias_owners = if assembly.needs_owner_global_alias_prepass() {
            let Some(owners) = self.jvm_open_static_alias_owners(&prepared, cancellation)? else {
                return Ok(JvmImportContext::Cancelled);
            };
            owners
        } else {
            std::collections::HashSet::new()
        };
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
            if self.jvm_indexed_on_demand_import(&prepared, binder, cancellation)? {
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
                ..
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
                let mut external_static_imports = Vec::new();
                let mut static_import_searches = BTreeMap::new();
                let mut root_bridges = Vec::new();
                let mut scoped_gaps = Vec::new();
                let mut model_declared_routes = Vec::new();
                let mut on_demand = None;
                let mut open_jvm_alias_imports = Vec::new();
                let mut route_inventory_open = false;
                let mut pending_scala_imports = BTreeMap::new();
                let mut pending_scala_wildcards: JvmScalaWildcards = BTreeMap::new();
                let mut package_alias = None;
                let mut explicit_import = None;
                'derive_import: {
                    let lexical_prefixes = rules.lexical_import_package_prefixes(
                        self,
                        source_record.blob_id(),
                        token,
                    )?;
                    let source_package =
                        lexical_prefixes.last().cloned().or(source_package.clone());
                    let selector = assembly.selector(binder);
                    let java_single_type = jvm_single_type_import(binder);
                    let import_kind = assembly.import_kind(binder);
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
                    let mut member_owner_found = false;
                    let mut found_alias = false;
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
                    if let Some(alternatives) = &earlier_head
                        && alternatives.len() > 1
                    {
                        rules.record_import_gap(
                            self,
                            JvmImportContextGapSpec {
                                source: source.fragment(),
                                source_token: token,
                                source_reference: None,
                                kind: "jvm-import-alias-route-open",
                                owner: None,
                                lookup: source_demand.clone(),
                                detail: format!(
                                    "competing selected import heads for `{}`: {alternatives:?}",
                                    binder.head
                                ),
                            },
                            &mut scoped_gaps,
                            &mut route_inventory_open,
                            cancellation,
                        )?;
                        break 'derive_import;
                    }
                    let earlier_route = if rules
                        .lexical_import_anchors()
                        .contains(&ResolutionRootImportAnchor::Lexical)
                        && anchor == ResolutionRootImportAnchor::Lexical
                    {
                        recipes.first().and_then(|head| {
                            earlier_scala_imports
                                .get(&(source_scope_head, head.spelling().to_owned()))
                                .and_then(|prefixes: &Vec<Vec<ResolutionLookupSemanticRecipe>>| {
                                    prefixes.first()
                                })
                                .map(|prefix| {
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
                        if source_language == Language::Scala
                            && demand_recipe.namespace() == ResolutionNamespace::Package
                            && selector.as_ref().is_some_and(|selector| {
                                selector.kind == ResolutionImportSelectorKind::Named
                            })
                        {
                            let Some(receipts) = self.jvm_selected_package_alias_receipts(
                                family,
                                lookup_route,
                                source_name,
                                cancellation,
                            )?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            if let Some(receipts) = receipts {
                                let container = receipts
                                    .last()
                                    .expect("package route has a selector")
                                    .0
                                    .clone();
                                let targets = self.jvm_import_targets(
                                    family.import_target_mounts(),
                                    &container,
                                )?;
                                let mut access_complete = true;
                                for &(ordinal, version) in targets.ordered.iter() {
                                    let target = self.mount_table().mount_by_ordinal(
                                        SelectedResolutionMountOrdinal::new(ordinal),
                                    )?;
                                    let access = self.jvm_qualified_source_access_completion(
                                        source_language,
                                        context_id,
                                        caller_version,
                                        source.persisted_relative_path(),
                                        version,
                                        target.persisted_relative_path(),
                                        &ResolutionCompletion::Complete,
                                    )?;
                                    access_complete &=
                                        access == Some(ResolutionCompletion::Complete);
                                }
                                if !access_complete {
                                    scoped_gaps.push(self.jvm_import_context_gap(JvmImportContextGapSpec {
                                        source: source.fragment(),
                                        source_token: token,
                                        source_reference: None,
                                        kind: "jvm-package-alias-route-open",
                                        owner: Some(container),
                                        lookup: source_demand.clone(),
                                        detail: format!("selected package alias `{local_name}` has incomplete source access"),
                                    }, cancellation)?);
                                    route_inventory_open = true;
                                    break;
                                }
                                package_alias = Some(JvmSelectedPackageAlias {
                                    source_token: token,
                                    selected_name: source_name.to_owned(),
                                    demand: source_demand.clone(),
                                    container,
                                    receipts,
                                    exact_hosts: targets.ordered.to_vec(),
                                });
                                resolved_lookup_route = Some(lookup_route.clone());
                                package_prefix_found = true;
                                break;
                            }
                            let owner = lookup_route
                                .iter()
                                .map(ResolutionLookupSemanticRecipe::spelling)
                                .collect::<Vec<_>>()
                                .join(".");
                            let Some(owner_hosts) = self.jvm_selected_package_segment_hosts(
                                family,
                                &owner,
                                cancellation,
                            )?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            if !owner_hosts.is_empty() {
                                scoped_gaps.push(self.jvm_import_context_gap(JvmImportContextGapSpec {
                                    source: source.fragment(),
                                    source_token: token,
                                    source_reference: None,
                                    kind: "jvm-package-alias-route-open",
                                    owner: Some(owner),
                                    lookup: source_demand.clone(),
                                    detail: format!("selected owner of `{}` does not prove package selector `{}`", local_name, source_name),
                                }, cancellation)?);
                                route_inventory_open = true;
                                break;
                            }
                            continue;
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
                                import_kind,
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
                                selected_name: None,
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
                                found_alias: alias_route_found,
                            } = alias_import_bridges;
                            found_alias |= alias_route_found;
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
                            let languages = assembly.package_targets();
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
                                if !assembly
                                    .package_targets()
                                    .contains(&Some(target_language.config_label()))
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
                        // `import pkg.Obj.member` names a member of `Obj`.
                        if (root_bridges.len() == bridges_before
                            || selector.as_ref().is_some_and(|selector| {
                                selector.kind == ResolutionImportSelectorKind::Named
                                    && !chained_wildcard_route
                            }))
                            && candidate_prefix_found
                            // A named import reads the authored member even when
                            // it binds a different local spelling. This applies
                            // to every namespace of Scala and Kotlin imports.
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
                                    import_kind,
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
                                    selected_name: (source_name != local_name)
                                        .then_some(source_name),
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
                            member_owner_found |= owner_found;
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
                            let Some(bridges) = assembly.member_bridges(
                                self,
                                import_kind,
                                inventory.members,
                                cancellation,
                            )?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            root_bridges.extend(bridges);
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
                        && (root_bridges.len() > bridges_before || package_alias.is_some())
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
                            .entry((source_scope_head, local_name.to_owned()))
                            .or_insert_with(Vec::new)
                            .push(resolved_route);
                    }
                    if let Some(kind) = assembly.static_import(binder) {
                        let import = JavaMemberImportDemand {
                            half: &binder.half,
                            import_kind: Some(kind),
                            caller_package: prepared.source_package.as_deref(),
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
                            selected_name: None,
                            language: source_language,
                        };
                        let mut owner_found = false;
                        let Some(inventory) = self.jvm_type_member_import_candidates(
                            context_id,
                            caller_version,
                            &import,
                            &ResolutionCompletion::Complete,
                            cancellation,
                            &mut owner_found,
                        )?
                        else {
                            return Ok(JvmImportContext::Cancelled);
                        };
                        let Some(complete) = self.jvm_static_import_search_complete(
                            kind,
                            owner_found,
                            &inventory,
                            &demand_recipe,
                            cancellation,
                        )?
                        else {
                            return Ok(JvmImportContext::Cancelled);
                        };
                        let mut static_bridges = Vec::new();
                        let owner_key = recipes
                            .iter()
                            .map(|part| part.spelling().to_owned())
                            .collect::<Vec<_>>();
                        let global_alias_open = open_static_alias_owners.contains(&owner_key);
                        let common_alias_open = global_alias_open
                            || has_open_jvm_alias_for_owner(
                                &open_jvm_alias_imports,
                                &scoped_gaps,
                                &recipes,
                            );
                        if self
                            .jvm_static_import(
                                &prepared,
                                binder,
                                &import,
                                inventory.members,
                                owner_found,
                                complete,
                                &mut static_bridges,
                                &mut external_static_imports,
                                &mut static_import_searches,
                                &mut open_jvm_alias_imports,
                                &mut scoped_gaps,
                                cancellation,
                                common_alias_open,
                                |evidence| {
                                    if !member_owner_found
                                        && !found_alias
                                        && let Some(scope) =
                                            assembly.unresolved_static_owner(&evidence)
                                    {
                                        record_jvm_import_member_scope(self, &evidence, &scope)?;
                                    }
                                    Ok(())
                                },
                            )?
                            .is_none()
                        {
                            return Ok(JvmImportContext::Cancelled);
                        }
                        static_bridges.extend(
                            root_bridges
                                .drain(..)
                                .filter(|bridge| bridge.target_language() != source_language),
                        );
                        root_bridges = static_bridges;
                    }
                    let package_owner = recipes
                        .iter()
                        .map(ResolutionLookupSemanticRecipe::spelling)
                        .collect::<Vec<_>>()
                        .join(".");
                    let package_candidates =
                        prepared
                            .package_plan
                            .get(&package_owner)
                            .and_then(|planned| {
                                planned
                                    .candidates
                                    .get(&source_demand.semantic(&self.ready.shared_names()))
                            });
                    let pack_members = package_candidates
                        .into_iter()
                        .flatten()
                        .filter_map(|candidate| match candidate {
                            JvmPackageCandidate::ExternalMember(member) => Some(member.clone()),
                            JvmPackageCandidate::SourceMount { .. } => None,
                        })
                        .collect::<Vec<_>>();
                    let competing_source =
                        package_candidates.into_iter().flatten().any(|candidate| {
                            matches!(candidate, JvmPackageCandidate::SourceMount { .. })
                        });
                    if !pack_members.is_empty() {
                        scoped_gaps.push(self.jvm_pack_package_member_gap(
                            JvmImportContextGapSpec {
                                source: source.fragment(),
                                source_token: token,
                                source_reference: None,
                                kind: "jvm-pack-package-member",
                                owner: Some(package_owner.clone()),
                                lookup: source_demand.clone(),
                                detail: format!(
                                    "{}@{} supplies package member `{}.{}`",
                                    pack_members[0].pack_id,
                                    pack_members[0].pack_version,
                                    package_owner,
                                    source_demand.spelling()
                                ),
                            },
                            &pack_members,
                            competing_source,
                            cancellation,
                        )?);
                    }
                    if member_owner_open && pack_members.is_empty() {
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
                    // A structured import kind delegates missing-owner claims to
                    // its type or static proof. A wildcard package or a static
                    // member is not evidence for a nominal type at this site.
                    // Rules without that evidence retain the nominal fallback.
                    if import_kind.is_none() && !package_prefix_found && pack_members.is_empty() {
                        let owner = recipes
                            .iter()
                            .map(ResolutionLookupSemanticRecipe::spelling)
                            .collect::<Vec<_>>()
                            .join(".");
                        let declared = format!("{owner}.{}", source_demand.spelling());
                        let competing_type = self.jvm_on_demand_import_competes(&prepared, binder);
                        if let Some(declared_type) = self
                            .jvm_declared_type(source_language, &declared)?
                            .filter(|_| !competing_type)
                        {
                            // The reviewed model declares this type, so the import
                            // closes with a model-declared identity instead of an
                            // open route. The shared registration checks whether
                            // its type and supertype inventories close that route.
                            model_declared_routes.push(ModelDeclaredJvmImportRoute {
                                source_token: token,
                                lookup: source_demand.clone(),
                                owner: declared_type.owner,
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
                            // A tie is an open route, not a nominal claim for
                            // either provider. The existing glob rank keeps
                            // this gap even when another glob finds a source.
                            if !competing_type {
                                let identity = model_declared_jvm_type_identity(
                                    &declared,
                                    &self.ready.shared_names(),
                                );
                                identities.record_jvm_unindexed_import_owner(identity, &declared);
                                gap.nominal_type_identity = Some(identity);
                            }
                            scoped_gaps.push(gap);
                        }
                        route_inventory_open |= rules.has_context_import_inventory();
                    } else if import_kind.is_some()
                        && !package_prefix_found
                        && pack_members.is_empty()
                    {
                        // The typed proof owns missing-import claims, but does
                        // not close the common route's inventory obligation.
                        route_inventory_open |= rules.has_context_import_inventory();
                    }
                    if cancellation.is_cancelled() {
                        return Ok(JvmImportContext::Cancelled);
                    }
                }
                if cancellation.is_cancelled() {
                    return Ok(JvmImportContext::Cancelled);
                }
                if let Some(kind) = assembly.type_import_proof(binder) {
                    // Keep the common route's peer metadata and inventory predicate.
                    // The JLS proof supplies Java targets and exact-site retirement;
                    // a positive common bridge alone cannot retire an authored gap.
                    if kind != ResolutionImportRouteKind::TypeOnDemand
                        || !self.jvm_indexed_on_demand_import(&prepared, binder, cancellation)?
                    {
                        let mut recipes = binder.recipes.clone();
                        let demand = recipes.pop().expect("one import demand");
                        let import = JavaMemberImportDemand {
                            half: &binder.half,
                            import_kind: Some(kind),
                            caller_package: prepared.source_package.as_deref(),
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
                            demand: &demand,
                            selected_name: None,
                            language: source_language,
                        };
                        let mut owner_found = false;
                        let Some(inventory) = self.jvm_type_member_import_candidates(
                            context_id,
                            caller_version,
                            &import,
                            &ResolutionCompletion::Complete,
                            cancellation,
                            &mut owner_found,
                        )?
                        else {
                            return Ok(JvmImportContext::Cancelled);
                        };
                        let mut proven_bridges = Vec::new();
                        match kind {
                            ResolutionImportRouteKind::SingleType => {
                                let Some((modeled, outcome)) = self.jvm_single_type_import(
                                    &prepared,
                                    binder,
                                    inventory.members,
                                    inventory.workspace_type_rows,
                                    inventory.workspace_inventory_complete,
                                    &mut proven_bridges,
                                    &mut scoped_gaps,
                                    cancellation,
                                )?
                                else {
                                    return Ok(JvmImportContext::Cancelled);
                                };
                                explicit_import = Some(outcome);
                                if let Some(declared) = modeled {
                                    // Registration retains token/endpoint, precedence and
                                    // unqualified-reference guards. Indexed status remains
                                    // in the existing exact declared-type memo used there.
                                    model_declared_routes.push(ModelDeclaredJvmImportRoute {
                                        source_token: token,
                                        lookup: demand.clone(),
                                        declared_fqn: declared.fqn,
                                        owner: declared.owner,
                                    });
                                }
                            }
                            ResolutionImportRouteKind::TypeOnDemand => {
                                let member_route_complete = inventory.route_search_complete
                                    && !inventory.inherited_route_open;
                                proven_bridges.extend(
                                    inventory.members.into_iter().map(|member| member.bridge),
                                );
                                let Some(evidence) = self.jvm_type_on_demand_import(
                                    &prepared,
                                    binder,
                                    member_route_complete,
                                    &mut proven_bridges,
                                    cancellation,
                                )?
                                else {
                                    return Ok(JvmImportContext::Cancelled);
                                };
                                on_demand = evidence.frame_evidence;
                            }
                            _ => unreachable!("type import proof requires a type import kind"),
                        }
                        proven_bridges.extend(
                            root_bridges
                                .drain(..)
                                .filter(|bridge| bridge.target_language() != source_language),
                        );
                        root_bridges = proven_bridges;
                    }
                }
                if cancellation.is_cancelled() {
                    return Ok(JvmImportContext::Cancelled);
                }
                let derived = Arc::new(JvmDerivedImport {
                    on_demand,
                    earlier_head,
                    earlier_wildcards,
                    bridges: root_bridges,
                    gaps: scoped_gaps,
                    model_routes: model_declared_routes,
                    open_aliases: open_jvm_alias_imports,
                    external_static_imports,
                    static_import_searches,
                    inventory_open: route_inventory_open,
                    scala_imports: pending_scala_imports,
                    scala_wildcards: pending_scala_wildcards,
                    package_alias,
                    explicit_import,
                });
                prepared.imports.insert(identity, Arc::clone(&derived));
                derived
            };
            external_static_imports.extend(derived.external_static_imports.iter().cloned());
            for (&key, search) in &derived.static_import_searches {
                let combined = static_import_searches
                    .entry(key)
                    .or_insert_with(|| search.clone());
                combined.complete &= search.complete;
                combined.found |= search.found;
            }
            root_bridges.extend(derived.bridges.iter().cloned());
            scoped_gaps.extend(derived.gaps.iter().cloned());
            model_declared_routes.extend(derived.model_routes.iter().cloned());
            open_jvm_alias_imports.extend(derived.open_aliases.iter().cloned());
            route_inventory_open |= derived.inventory_open;
            for (key, routes) in &derived.scala_imports {
                let selected = pending_scala_imports
                    .entry(key.clone())
                    .or_insert_with(Vec::new);
                for route in routes {
                    if !selected.contains(route) {
                        selected.push(route.clone());
                    }
                }
            }
            for (scope, routes) in &derived.scala_wildcards {
                pending_scala_wildcards
                    .entry(*scope)
                    .or_default()
                    .extend(routes.iter().cloned());
            }
        }

        self.jvm_complete_static_imports(&prepared, static_import_searches)?;
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
            prepared: &prepared,
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
                    if prepared.package_plan.get(*package).is_some_and(|plan| {
                        plan.candidates
                            .contains_key(&gap.lookup.semantic(&self.ready.shared_names()))
                    }) {
                        continue;
                    }
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
                        if prepared
                            .package_plan
                            .get(*package)
                            .is_some_and(|plan| plan.candidates.contains_key(&reference.lookup))
                        {
                            continue;
                        }
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
        let references = match lookup {
            Some(name) => prepared
                .references_by_name
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            None => package_references.as_slice(),
        };
        if source_language == Language::Scala {
            for reference in references {
                let Some(prefixes) = prepared.scala_reference_packages.get(&reference.token).and_then(Option::as_ref) else {
                    let Some(mut recipes) = self.jvm_lookup_recipes(source.fragment(), [reference.lookup], cancellation)? else { return Ok(JvmImportContext::Cancelled); };
                    scoped_gaps.push(self.jvm_import_context_boundary_gap_with_same_package_shadow(
                        JvmImportContextGapSpec {
                            source: source.fragment(),
                            source_token: reference.token,
                            source_reference: Some(reference.reference),
                            kind: "scala-package-clause-boundary-open",
                            owner: None,
                            lookup: recipes.pop().expect("one selected lookup recipe"),
                            detail: "selected Scala reference lacks an enclosing package-clause boundary".to_owned(),
                        },
                        cancellation,
                    )?);
                    continue;
                };
                for package in prefixes.iter().rev() {
                    if implicit_root_providers.iter().any(|provider| matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package.as_str())) { continue; }
                    let Some(peers) = self.jvm_package_import_bridges(&import_context, std::slice::from_ref(package), std::slice::from_ref(reference), &mut scoped_gaps, &mut same_package_lookups, cancellation)? else { return Ok(JvmImportContext::Cancelled); };
                    let found = !peers.is_empty();
                    package_bridges.extend(peers);
                    if found { break; }
                }
            }
        } else if let Some(package) = source_package.as_ref().filter(|package| !implicit_root_providers.iter().any(|provider| matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package.as_str()))) {
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
                    && !same_package_lookups.contains(&if source_language == Language::Scala {
                        gap.source_token
                    } else {
                        gap.lookup.semantic(&names)
                    }))
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
        let mut competing_references = BTreeSet::new();
        let demanded_name = lookup;
        for (&(source_token, lookup), references) in
            &prepared.external_providers.references_by_route
        {
            let recipe = &prepared.external_providers.recipes[&lookup];
            for &reference in references {
                let Some(choice) =
                    self.jvm_on_demand_type(&prepared, reference, lookup, recipe, cancellation)?
                else {
                    return Ok(JvmImportContext::Cancelled);
                };
                match choice {
                    JvmOnDemandTypeChoice::Indexed(winner)
                    | JvmOnDemandTypeChoice::Intrinsic(winner)
                    | JvmOnDemandTypeChoice::Alias(winner)
                        if !model_bound_references.contains(&reference) =>
                    {
                        // Candidate inventories cover the file; publish an alias
                        // identity only for the name this query demands.
                        if demanded_name.is_some_and(|name| name != recipe.spelling())
                            && brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                                source_language,
                                &winner.package,
                                recipe.spelling(),
                            )
                            .is_some()
                        {
                            continue;
                        }
                        register_model_declared_jvm_type_identity(
                            self,
                            reference,
                            &winner.declared.fqn,
                            winner.declared.owner.as_ref(),
                            &identities,
                            &names,
                        )?;
                        if !winner.declared.indexed
                            && brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                                source_language,
                                &winner.package,
                                recipe.spelling(),
                            )
                            .is_some()
                        {
                            let mut gap = self
                                .jvm_import_context_boundary_gap_with_same_package_shadow(
                                    JvmImportContextGapSpec {
                                        source: source.fragment(),
                                        source_token,
                                        source_reference: Some(reference),
                                        kind: if winner.package == SCALA_PREDEF_DEFAULT_IMPORT {
                                            "scala-predef-route-open"
                                        } else {
                                            "jvm-import-owner-open"
                                        },
                                        owner: Some(winner.declared.fqn.clone()),
                                        lookup: recipe.clone(),
                                        detail: format!(
                                            "Scala implicit alias `{}` targets unacquired `{}`",
                                            recipe.spelling(),
                                            winner.declared.fqn
                                        ),
                                    },
                                    cancellation,
                                )?;
                            gap.nominal_type_identity =
                                Some(winner.declared.owner.as_ref().map_or_else(
                                    || {
                                        model_declared_jvm_type_identity(
                                            &winner.declared.fqn,
                                            &names,
                                        )
                                    },
                                    |owner| identities.external_owner_semantic(owner, &names),
                                ));
                            scoped_gaps.push(gap);
                        }
                        if winner.declared.indexed
                            || brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                                source_language,
                                &winner.package,
                                recipe.spelling(),
                            )
                            .is_some()
                        {
                            self.jvm_on_demand_type_ranks
                                .borrow_mut()
                                .insert(reference, winner.precedence);
                        }
                        model_bound_references.insert(reference);
                    }
                    JvmOnDemandTypeChoice::Competing(_)
                    | JvmOnDemandTypeChoice::OpenDefault
                    | JvmOnDemandTypeChoice::Possible(_) => {
                        competing_references.insert(reference);
                    }
                    JvmOnDemandTypeChoice::Unavailable
                    | JvmOnDemandTypeChoice::Indexed(_)
                    | JvmOnDemandTypeChoice::Intrinsic(_)
                    | JvmOnDemandTypeChoice::Alias(_) => {}
                }
            }
        }
        if source_language == Language::Java
            && self
                .record_java_explicit_import_boundaries(
                    &prepared,
                    &open_jvm_alias_imports,
                    &identities,
                    cancellation,
                )?
                .is_none()
        {
            return Ok(JvmImportContext::Cancelled);
        }
        let implicit_type_references = unqualified_type_references
            .difference(&model_bound_references)
            .filter(|reference| !competing_references.contains(reference))
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
        if let Some(access_source) = assembly.declaration_access_source(self, access_identity) {
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
        assembly.finalize_aliases(&mut open_jvm_alias_imports);
        external_static_imports
            .sort_by(|left, right| (&left.member, &left.owner).cmp(&(&right.member, &right.owner)));
        external_static_imports.dedup();
        Ok(JvmImportContext::Ready {
            context: Box::new(context),
            external_static_imports,
            inventory_reason,
            open_jvm_alias_imports,
            scoped_gaps,
        })
    }

    /// Record the imported-type boundary of each Java single-type import whose
    /// own proof found no workspace source declaration, at each unqualified
    /// type reference whose simple-type-name decision the import wins. The
    /// projection renders it only when the selected answer has no target. The
    /// import declaration's own target name is a separate reference with no
    /// selected link to its binder, so Java's projection still answers it.
    fn record_java_explicit_import_boundaries(
        &self,
        prepared: &JvmContextPreparation,
        open_aliases: &[String],
        identities: &SelectedContextIdentities,
        cancellation: &CancellationToken,
    ) -> Result<Option<()>> {
        let mut recorded = BTreeSet::new();
        for binder in prepared
            .binders
            .iter()
            .filter(|binder| jvm_single_type_import(binder))
        {
            let Some(derived) = prepared.imports.get(&binder.identity) else {
                continue;
            };
            let Some(JvmExplicitImportOutcome::External { fqn, declared }) =
                &derived.explicit_import
            else {
                continue;
            };
            if open_aliases.iter().any(|alias| alias == fqn) {
                continue;
            }
            let SelectedRootPathHalf::Import { token, .. } = binder.half else {
                unreachable!("an import binder has an import half")
            };
            let demand = binder.recipes.last().expect("an import has a demand");
            let boundary = SelectedExplicitImportBoundary {
                imported_fqn: Arc::from(fqn.as_str()),
                simple_name: Arc::from(demand.spelling()),
                external_target: declared.then(|| Arc::from(fqn.as_str())),
            };
            // The references this import binds, as registration reads them:
            // the selected import bindings for the name, at unqualified Type
            // sites. A TypeOrValue site is an ambiguous expression name, which
            // a type-name decision does not reclassify.
            let recipe = self
                .jvm_generated_lookup(Language::Java, ResolutionNamespace::Type, demand.spelling())
                .recipe
                .clone();
            let lookup = recipe.semantic(&self.ready.shared_names());
            let Some(bindings) =
                self.jvm_on_demand_bindings(prepared, lookup, &recipe, cancellation)?
            else {
                return Ok(None);
            };
            for binding in bindings.iter().filter(|binding| binding.token == token) {
                if !recorded.insert((token, binding.reference)) {
                    continue;
                }
                let Some(seed) = self
                    .ready
                    .lexical_source()
                    .reference_seed(ResolutionQuery::new(binding.reference), cancellation)?
                else {
                    continue;
                };
                if !seed.site_metadata().is_some_and(|metadata| {
                    metadata.unqualified() && metadata.namespace() == ResolutionNamespace::Type
                }) {
                    continue;
                }
                let Some(decision) = self.jvm_simple_type_name_decision(
                    prepared,
                    binding.reference,
                    lookup,
                    &recipe,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                if matches!(
                    &decision.decision,
                    TierDecision::Unique {
                        selected: JvmTypeNameAlternative::ExplicitImport(winner),
                        ..
                    } if *winner == token
                ) {
                    identities
                        .record_java_explicit_import_boundary(binding.reference, boundary.clone());
                }
            }
        }
        Ok(Some(()))
    }

    /// The on-demand and default choice that registrations consume, from
    /// the reference's simple-type-name decision.
    fn jvm_on_demand_type(
        &self,
        prepared: &JvmContextPreparation,
        reference: SemanticId,
        lookup: SemanticId,
        recipe: &ResolutionLookupSemanticRecipe,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmOnDemandTypeChoice>> {
        Ok(self
            .jvm_simple_type_name_decision(prepared, reference, lookup, recipe, cancellation)?
            .map(|decision| decision.on_demand_choice()))
    }

    // The spelling and lexical reference are known here, including when a
    // name-independent implicit plan is first prepared for another lookup.
    // Exact owner reads are memoized by name and binding inputs by lookup.
    // The decision belongs to this reference's scope, independent of lookup
    // order. The preparation is per file, scope and stage, and the provider set
    // and model authority are fixed for the operation, so the reference keys it.
    fn jvm_simple_type_name_decision(
        &self,
        prepared: &JvmContextPreparation,
        reference: SemanticId,
        lookup: SemanticId,
        recipe: &ResolutionLookupSemanticRecipe,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmSimpleTypeNameDecision>>> {
        debug_assert_eq!(
            recipe.semantic(&self.ready.shared_names()),
            lookup,
            "the recipe spells the lookup the decision answers"
        );
        if let Some(decision) = prepared.simple_type_name_decisions.get(&reference) {
            debug_assert_eq!(
                decision.lookup, lookup,
                "one reference asks one simple-type-name question"
            );
            self.jvm_decision_consumed_walk
                .set(self.jvm_decision_consumed_walk.get() || decision.consumed_walk);
            if let Some(selected) = &decision.selected_owner {
                self.ready
                    .context_identities
                    .record_java_type_name_owner(reference, selected.clone());
            }
            return Ok(Some(decision));
        }
        let Some(observed) =
            self.jvm_on_demand_observation(prepared, reference, lookup, recipe, cancellation)?
        else {
            return Ok(None);
        };
        let inherited = self.jvm_inherited_tier_knowledge.is_some();
        let mut nearer = Vec::new();
        let mut on_demand_rank = JVM_ON_DEMAND_TYPE_TIER;
        let mut consumed_walk = false;
        let mut open_inherited_rank = None;
        if prepared.source.semantic_language() == Language::Java {
            let Some(bindings) =
                self.jvm_on_demand_bindings(prepared, lookup, recipe, cancellation)?
            else {
                return Ok(None);
            };
            let local_closure = if observed.local_path_read {
                ContributorClosure::Closed(TierReceipt {
                    selected_read: "jvm-authored-local-path",
                })
            } else {
                ContributorClosure::Open
            };
            // Java ignores a repeated single-type import of the same type (JLS
            // 7.5.1), so one imported path is one alternative, named by its
            // first import token. Distinct paths for one simple name stay
            // distinct alternatives and decide Ambiguous.
            let names = self.ready.shared_names();
            let mut imported_paths = HashSet::default();
            let explicit = bindings
                .iter()
                .filter(|binding| binding.reference == reference)
                .filter_map(|binding| {
                    prepared.binders.iter().find(|binder| {
                        jvm_single_type_import(binder)
                            && matches!(&binder.half, SelectedRootPathHalf::Import { token, .. } if *token == binding.token)
                    })
                    .map(|binder| (binder, binding.token))
                })
                .filter(|(binder, _)| {
                    imported_paths.insert(
                        binder
                            .recipes
                            .iter()
                            .map(|recipe| recipe.semantic(&names))
                            .collect::<Vec<_>>(),
                    )
                })
                .map(|(_, token)| JvmTypeNameAlternative::ExplicitImport(token))
                .collect();
            if inherited {
                let Some(tiers) = self.jvm_java_inherited_type_name_tiers(
                    reference,
                    lookup,
                    recipe.spelling(),
                    explicit,
                    local_closure,
                    observed.same_package,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                nearer = tiers.tiers;
                on_demand_rank = tiers.on_demand_rank;
                consumed_walk = tiers.consumed_walk;
                open_inherited_rank = tiers.open_inherited_rank;
            } else {
                nearer.extend([
                    TierInput {
                        rank: JVM_LEXICAL_TYPE_TIER,
                        contributors: vec![TierContributor {
                            candidates: observed
                                .lexical
                                .then_some(JvmTypeNameAlternative::Lexical)
                                .into_iter()
                                .collect(),
                            closure: local_closure.clone(),
                        }],
                    },
                    // The bindings are read from the file's selected root imports,
                    // which list every import declaration; the reader returns None
                    // only on cancellation. The context-wide inventory reason is
                    // about external artifacts and inherited routes, not about the
                    // import declarations, so it does not open this tier.
                    TierInput {
                        rank: JVM_SINGLE_TYPE_IMPORT_TIER,
                        contributors: vec![TierContributor {
                            candidates: explicit,
                            closure: ContributorClosure::Closed(TierReceipt {
                                selected_read: "jvm-selected-root-imports",
                            }),
                        }],
                    },
                    TierInput {
                        rank: JVM_SAME_PACKAGE_TYPE_TIER,
                        contributors: vec![TierContributor {
                            candidates: observed
                                .same_package
                                .then_some(JvmTypeNameAlternative::SamePackage)
                                .into_iter()
                                .collect(),
                            closure: local_closure,
                        }],
                    },
                ]);
            }
        } else if inherited {
            let Some(tiers) = self.jvm_non_java_inherited_tiers(
                prepared.source.semantic_language(),
                reference,
                lookup,
                recipe.spelling(),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            nearer = tiers.tiers;
            on_demand_rank = tiers.on_demand_rank;
            consumed_walk = tiers.consumed_walk;
        }
        let mut decision = JvmSimpleTypeNameDecision::from_tiers(
            lookup,
            nearer,
            on_demand_rank,
            observed,
            consumed_walk,
            open_inherited_rank,
        );

        self.jvm_decision_consumed_walk
            .set(self.jvm_decision_consumed_walk.get() || consumed_walk);

        if prepared.source.semantic_language() == Language::Java
            && recipe.namespace() == ResolutionNamespace::Type
            && self
                .ready
                .lexical_source()
                .reference_seed(ResolutionQuery::new(reference), cancellation)?
                .is_some_and(|seed| {
                    seed.site_metadata().is_some_and(|metadata| {
                        metadata.unqualified() && metadata.namespace() == ResolutionNamespace::Type
                    })
                })
        {
            let winning = match &decision.decision {
                TierDecision::Unique { selected: JvmTypeNameAlternative::ExplicitImport(token), .. } => {
                    prepared.binders.iter().find_map(|binder| {
                        matches!(&binder.half, SelectedRootPathHalf::Import { token: candidate, .. } if candidate == token)
                            .then(|| prepared.imports.get(&binder.identity))
                            .flatten()
                            .and_then(|derived| match &derived.explicit_import {
                                Some(JvmExplicitImportOutcome::External { fqn, declared: true }) =>
                                    Some((SelectedJavaTypeNameWinner::ExplicitImport(*token), fqn.clone())),
                                _ => None,
                            })
                    })
                }
                TierDecision::Unique { selected: JvmTypeNameAlternative::OnDemand(fqn), .. } => {
                    let source = match &decision.lower {
                        JvmOnDemandTypeChoice::Indexed(winner)
                        | JvmOnDemandTypeChoice::Alias(winner)
                        | JvmOnDemandTypeChoice::Intrinsic(winner) => winner.source.clone(),
                        _ => None,
                    };
                    // Two authored routes can supply the winning name at one
                    // rank (a repeated `import p.*;` is legal). The chooser
                    // then keeps no source, and neither route is certified.
                    source.map(|source| (SelectedJavaTypeNameWinner::OnDemand {
                        fqn: Arc::from(fqn.as_str()), source,
                    }, fqn.clone()))
                }
                _ => None,
            };
            if let Some((winner, fqn)) = winning
                && let Some(declared) = self.jvm_declared_type(Language::Java, &fqn)?
                && let Some(Some(owner)) =
                    self.jvm_declared_owner_selection(Language::Java, &fqn)?
            {
                debug_assert_eq!(declared.owner.as_ref(), Some(&owner));
                let authority = crate::analyzer::resolution::fact_resolution::demand_scheduler::jvm_external_nominal_authority(
                    &owner.provider_id,
                    declared.indexed,
                );
                let identities = &self.ready.context_identities;
                let semantic =
                    identities.external_owner_semantic(&owner, &self.ready.shared_names());
                let proposal = if let SelectedJavaTypeNameWinner::ExplicitImport(token) = &winner {
                    let mut proved_sites = BTreeSet::new();
                    for binder in &prepared.binders {
                        let Some(route) = &binder.route else { continue };
                        let selected = match route.kind {
                            SelectedImportRouteKind::SingleType => matches!(
                                &binder.half,
                                SelectedRootPathHalf::Import { token: candidate, .. } if candidate == token
                            ),
                            SelectedImportRouteKind::TypeOnDemand => {
                                binder.recipes.last().is_some_and(|demand| {
                                    demand.namespace() == ResolutionNamespace::Type
                                        && demand.spelling() == recipe.spelling()
                                })
                            }
                            _ => false,
                        };
                        if selected && let Some(site) = route.source_site {
                            proved_sites.insert(site.get());
                        }
                    }
                    Some(ExplicitImportAdmission {
                        token: *token,
                        lookup,
                        blob: prepared.source_record.blob_id(),
                        fragment: prepared.source.fragment(),
                        certificate: SelectedExternalOwner {
                            reference,
                            owner: semantic,
                            authority,
                            selection: SelectedExternalOwnerSelection::ExplicitImport(*token),
                        },
                        proved_sites,
                    })
                } else {
                    None
                };
                let selected = SelectedJavaTypeNameOwner {
                    winner,
                    owner: semantic,
                    authority,
                    proposal,
                };
                identities.record_java_type_name_owner(reference, selected.clone());
                decision.selected_owner = Some(selected);
            }
        }
        let decision = Arc::new(decision);
        prepared
            .simple_type_name_decisions
            .insert(reference, Arc::clone(&decision));
        Ok(Some(decision))
    }

    /// Freeze the inherited member-type knowledge this operation's JVM
    /// simple-type-name decisions read. Every decision memo lives in this
    /// operation, so installing the table before any JVM context work binds
    /// every memo to exactly this table.
    pub(crate) fn install_jvm_inherited_tier_knowledge(
        &mut self,
        knowledge: Arc<InheritedTierKnowledge>,
    ) {
        self.install_jvm_inherited_knowledge(
            super::inherited_member_walk::JvmInheritedKnowledge::Frozen(knowledge),
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn install_jvm_inherited_tier_knowledge_for_test(
        &mut self,
        knowledge: Arc<InheritedTierKnowledge>,
    ) {
        self.install_jvm_inherited_tier_knowledge(knowledge);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn finalize_jvm_lexical_targets_for_test(
        &self,
        reference: SemanticId,
        targets: Vec<SemanticId>,
        cancellation: &CancellationToken,
    ) -> Result<(Vec<SemanticId>, Option<Vec<SemanticId>>)> {
        use crate::analyzer::resolution::fact_resolution::LexicalAnswerFinalizer;
        let raw = Arc::new(ResolutionAnswer::new(
            targets,
            [],
            ResolutionCompletion::Complete,
        ));
        let finalized =
            JvmLexicalAnswerFinalizer { operation: self }.finalize(reference, raw, cancellation)?;
        Ok((
            finalized.answer.targets().to_vec(),
            finalized.withheld.map(|payload| payload.targets.to_vec()),
        ))
    }

    /// The selected access endpoint of one reference: its enclosing classes,
    /// innermost first, and their type-body heads. The inner None means the
    /// selected facts name no endpoint for it; the outer None is cancellation.
    fn jvm_reference_access_endpoint(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Option<JvmAccessEndpoint>>> {
        let Some(endpoints) = self
            .ready
            .typed_source()
            .jvm_access_endpoints(&[reference], cancellation)?
        else {
            return Ok(None);
        };
        Ok(Some(
            endpoints
                .into_iter()
                .find(|endpoint| endpoint.semantic == reference),
        ))
    }

    /// Whether the class bodies on the reference's checkpoint ancestry are
    /// exactly the endpoint's enclosing classes: the same heads, innermost
    /// first, with none missing and none extra. A class body missing from the
    /// list would be ranked by position alone and its inherited tier never
    /// asked, so any other shape keeps no level order. None is cancellation.
    fn jvm_endpoint_lists_every_body(
        &self,
        evidence: &crate::analyzer::resolution::ReferenceLocalPathEvidence,
        endpoint: &JvmAccessEndpoint,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        let lexical = self.ready.lexical_source();
        let nodes = evidence
            .ordered_checkpoint_ancestry()
            .iter()
            .map(|(node, _)| *node)
            .collect::<Vec<_>>();
        let mut bodies = HashSet::default();
        for chunk in nodes.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            let owners = lexical.scope_owners_for_heads(chunk, cancellation)?;
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            bodies.extend(
                owners
                    .iter()
                    .filter(|owner| owner.is_type_body())
                    .map(|owner| owner.scope_head()),
            );
        }
        let on_ancestry = nodes
            .iter()
            .filter(|node| bodies.contains(*node))
            .map(|node| Some(*node))
            .collect::<Vec<_>>();
        Ok(Some(on_ancestry == endpoint.enclosing_template_heads))
    }

    /// The declaring class of each definition that a selected member-owner row
    /// names as a nested type. A definition with no such row, or whose pages
    /// were not read to the end, is absent from the map. None is cancellation.
    fn jvm_nested_type_owners(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<Option<HashMap<SemanticId, SemanticId>>> {
        let mut owners = HashMap::default();
        let typed = self.ready.typed_source();
        for chunk in definitions.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let mut rows = Vec::new();
            let outcome = typed.visit_member_owner_pages_for_definitions(
                TypedFactRequest::new(chunk),
                cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    rows.extend(
                        page.iter()
                            .filter(|row| row.row().kind() == ResolutionMemberKind::NestedType)
                            .map(|row| (row.row().definition(), row.row().owner_definition())),
                    );
                    Ok(true)
                }),
            )?;
            if outcome.is_cancelled() {
                return Ok(None);
            }
            if jvm_member_owner_pages_complete(&outcome) {
                owners.extend(rows);
            }
        }
        Ok(Some(owners))
    }

    /// Place lexical type binders against the inherited tiers. Only a binder
    /// proved inside the innermost body is independent of inheritance in both
    /// languages. Other binders can compete with an inherited classifier.
    fn jvm_non_java_inherited_tiers(
        &self,
        language: Language,
        reference: SemanticId,
        lookup: SemanticId,
        spelling: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmInheritedTypeNameTiers>> {
        let local = super::imports::authored_reference_local_path_evidence(
            &self.ready,
            reference,
            cancellation,
        )?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(endpoint) = self.jvm_reference_access_endpoint(reference, cancellation)? else {
            return Ok(None);
        };
        let endpoint = match (endpoint, local.as_ref()) {
            (Some(endpoint), Some(evidence)) => {
                let Some(complete) =
                    self.jvm_endpoint_lists_every_body(evidence, &endpoint, cancellation)?
                else {
                    return Ok(None);
                };
                complete.then_some(endpoint)
            }
            (endpoint, _) => endpoint,
        };
        let Some(endpoint) = endpoint else {
            let mut tiers = vec![jvm_unknown_enclosing_classes_tier()];
            if let Some(definition) = local
                .as_ref()
                .and_then(|evidence| evidence.local_definitions().iter().next().copied())
            {
                tiers.push(TierInput {
                    rank: 0,
                    contributors: vec![TierContributor {
                        candidates: vec![JvmTypeNameAlternative::UnsupportedLexical(definition)],
                        closure: ContributorClosure::Open,
                    }],
                });
            }
            return Ok(Some(JvmInheritedTypeNameTiers {
                tiers,
                on_demand_rank: 1,
                consumed_walk: false,
                // Class-header references have no endpoint yet, so an
                // unknown-enclosing tier must not withhold their targets; that
                // waits for the header endpoint fix with #7006 enablement.
                open_inherited_rank: None,
            }));
        };
        let count = endpoint.enclosing_templates.len();
        let mut tiers = Vec::new();
        if let Some(evidence) = &local {
            let definitions = evidence.local_definitions();
            let mut placed = BTreeMap::<u32, (usize, Vec<SemanticId>)>::new();
            let mut unsupported = Vec::new();
            for definition in definitions {
                let Some(placement) = place_lexical_type(*definition, evidence, &endpoint) else {
                    unsupported.push(JvmTypeNameAlternative::UnsupportedLexical(*definition));
                    continue;
                };
                // The hook describes which inherited levels can compete. Java
                // uses its JLS level order; Kotlin and Scala conservatively
                // leave every non-local binder behind the applicable levels.
                let rank = (0..count)
                    .filter(|&level| jvm_inherited_competes(language, placement.level, level))
                    .map(|level| u32::try_from(level + 2).expect("enclosing classes fit u32"))
                    .max()
                    .unwrap_or(0);
                let entry = placed
                    .entry(rank)
                    .or_insert((placement.ancestry_position, Vec::new()));
                if placement.ancestry_position < entry.0 {
                    *entry = (placement.ancestry_position, Vec::new());
                }
                if placement.ancestry_position == entry.0 {
                    entry.1.push(*definition);
                }
            }
            if !unsupported.is_empty() {
                tiers.push(TierInput {
                    rank: 0,
                    contributors: vec![TierContributor {
                        candidates: unsupported,
                        closure: ContributorClosure::Open,
                    }],
                });
            }
            for (rank, (_, definitions)) in placed {
                tiers.push(TierInput {
                    rank,
                    contributors: vec![TierContributor {
                        candidates: definitions
                            .into_iter()
                            .map(JvmTypeNameAlternative::PlacedLexical)
                            .collect(),
                        closure: ContributorClosure::Closed(TierReceipt {
                            selected_read: "jvm-authored-local-path",
                        }),
                    }],
                });
            }
        }
        let mut open_inherited_rank = None;
        for (level, owner) in endpoint.enclosing_templates.iter().enumerate() {
            let Some(witness) =
                self.jvm_inherited_witness(*owner, lookup, spelling, cancellation)?
            else {
                return Ok(None);
            };
            let rank = u32::try_from(level + 1).expect("enclosing classes fit u32");
            if matches!(witness, InheritedTierWitness::Open { .. }) {
                open_inherited_rank =
                    Some(open_inherited_rank.map_or(rank, |prior: u32| prior.min(rank)));
            }
            tiers.push(jvm_inherited_tier(rank, witness));
        }
        Ok(Some(JvmInheritedTypeNameTiers {
            on_demand_rank: u32::try_from(count + 2).expect("enclosing classes fit u32"),
            consumed_walk: count > 0,
            open_inherited_rank,
            tiers,
        }))
    }

    /// Java's scope order for one simple type name with inherited member types
    /// (JLS 6.3, 6.4.1, 8.5). Ranks run from the reference outward: Local; for
    /// each enclosing class innermost first, the member types it declares,
    /// the member types it inherits, and the scopes between its body and the
    /// next class body (its type parameters, and for a local class the blocks
    /// around it); then single-type imports together with same-unit top-level
    /// types, which conflict (JLS 7.5.1); then the current package; then
    /// on-demand and default imports.
    #[allow(clippy::too_many_arguments)]
    fn jvm_java_inherited_type_name_tiers(
        &self,
        reference: SemanticId,
        lookup: SemanticId,
        spelling: &str,
        explicit: Vec<JvmTypeNameAlternative>,
        lexical_closure: ContributorClosure,
        same_package: bool,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmInheritedTypeNameTiers>> {
        let Some(endpoint) = self.jvm_reference_access_endpoint(reference, cancellation)? else {
            return Ok(None);
        };
        let local = super::imports::authored_reference_local_path_evidence(
            &self.ready,
            reference,
            cancellation,
        )?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let endpoint = match (endpoint, &local) {
            (Some(endpoint), Some(evidence)) => {
                let Some(complete) =
                    self.jvm_endpoint_lists_every_body(evidence, &endpoint, cancellation)?
                else {
                    return Ok(None);
                };
                complete.then_some(endpoint)
            }
            (endpoint, _) => endpoint,
        };
        let mut tiers = Vec::new();
        let mut open_inherited_rank = None;
        // Without every enclosing class, no level order is proved.
        let (templates, base) = match &endpoint {
            Some(endpoint) => (endpoint.enclosing_templates.as_slice(), 0),
            None => {
                // No withholding for an unknown-enclosing tier until class-header
                // references have endpoints (deferred with #7006 enablement).
                tiers.push(jvm_unknown_enclosing_classes_tier());
                (&[][..], 1)
            }
        };
        let levels = u32::try_from(templates.len()).expect("enclosing classes fit u32");
        let level_rank = |level: usize, slot: u32| {
            base + 1 + 3 * u32::try_from(level).expect("enclosing classes fit u32") + slot
        };
        let unit_rank = base + 1 + 3 * levels;
        // The nearest definition of each level, as the lexical engine selects
        // it; definitions whose order is not proved stay open.
        let definitions = local
            .as_ref()
            .map(|evidence| evidence.local_definitions())
            .unwrap_or_default();
        let placements = definitions
            .iter()
            .map(|definition| {
                local
                    .as_ref()
                    .zip(endpoint.as_ref())
                    .and_then(|(evidence, endpoint)| {
                        place_lexical_type(*definition, evidence, endpoint)
                    })
            })
            .collect::<Vec<_>>();
        // A type binder in a class body is that class's member type only when
        // the selected member-owner row says so; the binder's scope alone does
        // not prove it.
        let declared = definitions
            .iter()
            .zip(&placements)
            .filter(|(_, placement)| {
                matches!(
                    placement.map(|placement| placement.level),
                    Some(LexicalTypeLevel::Declared(_))
                )
            })
            .map(|(definition, _)| *definition)
            .collect::<Vec<_>>();
        let Some(member_types) = self.jvm_nested_type_owners(&declared, cancellation)? else {
            return Ok(None);
        };
        let mut placed = BTreeMap::<u32, (usize, Vec<SemanticId>)>::new();
        let mut unplaced = Vec::new();
        for (&definition, placement) in definitions.iter().zip(placements) {
            let confirmed = match placement.map(|placement| placement.level) {
                Some(LexicalTypeLevel::Declared(level)) => {
                    member_types.get(&definition) == Some(&templates[level])
                }
                _ => true,
            };
            let Some(placement) = placement.filter(|_| confirmed) else {
                unplaced.push(JvmTypeNameAlternative::PlacedLexical(definition));
                continue;
            };
            let competing = (0..templates.len())
                .filter(|&level| jvm_inherited_competes(Language::Java, placement.level, level))
                .count();
            let competing = u32::try_from(competing).expect("enclosing classes fit u32");
            let rank = match placement.level {
                LexicalTypeLevel::Local => base,
                LexicalTypeLevel::Declared(_) => base + 1 + 3 * competing,
                LexicalTypeLevel::Outside(_) => base + 3 * competing,
                // With no enclosing class there is no inherited tier to order
                // against, so the unit's types keep the single lexical tier.
                LexicalTypeLevel::Unit if levels == 0 => base,
                LexicalTypeLevel::Unit => base + 1 + 3 * competing,
            };
            debug_assert_eq!(
                rank,
                match placement.level {
                    LexicalTypeLevel::Local => base,
                    LexicalTypeLevel::Declared(level) => level_rank(level, 0),
                    LexicalTypeLevel::Outside(level) => level_rank(level, 2),
                    LexicalTypeLevel::Unit if levels == 0 => base,
                    LexicalTypeLevel::Unit => unit_rank,
                }
            );
            let entry = placed
                .entry(rank)
                .or_insert((placement.ancestry_position, Vec::new()));
            if placement.ancestry_position < entry.0 {
                *entry = (placement.ancestry_position, Vec::new());
            }
            if placement.ancestry_position == entry.0 {
                entry.1.push(definition);
            }
        }
        if !unplaced.is_empty() {
            tiers.push(TierInput {
                rank: base,
                contributors: vec![TierContributor {
                    candidates: unplaced,
                    closure: ContributorClosure::Open,
                }],
            });
        }
        let mut lexical = |rank: u32| TierContributor {
            candidates: placed
                .remove(&rank)
                .map(|(_, definitions)| {
                    definitions
                        .into_iter()
                        .map(JvmTypeNameAlternative::PlacedLexical)
                        .collect()
                })
                .unwrap_or_default(),
            closure: lexical_closure.clone(),
        };
        tiers.push(TierInput {
            rank: base,
            contributors: vec![lexical(base)],
        });
        for (level, owner) in templates.iter().enumerate() {
            tiers.push(TierInput {
                rank: level_rank(level, 0),
                contributors: vec![lexical(level_rank(level, 0))],
            });
            let Some(witness) =
                self.jvm_inherited_witness(*owner, lookup, spelling, cancellation)?
            else {
                return Ok(None);
            };
            let rank = level_rank(level, 1);
            if matches!(witness, InheritedTierWitness::Open { .. }) {
                open_inherited_rank =
                    Some(open_inherited_rank.map_or(rank, |prior: u32| prior.min(rank)));
            }
            tiers.push(jvm_inherited_tier(rank, witness));
            tiers.push(TierInput {
                rank: level_rank(level, 2),
                contributors: vec![lexical(level_rank(level, 2))],
            });
        }
        let mut unit = Vec::new();
        if levels > 0 {
            unit.push(lexical(unit_rank));
        }
        // JLS 7.5.1 ignores a single-type import of a type the unit itself
        // declares, and an import token does not identify its declaration. So
        // a same-unit type and an import with the same name stay open rather
        // than conflicting.
        let unit_conflict = unit
            .first()
            .is_some_and(|lexical| !lexical.candidates.is_empty())
            && !explicit.is_empty();
        // The bindings are read from the file's selected root imports, which
        // list every import declaration.
        unit.push(TierContributor {
            candidates: explicit,
            closure: if unit_conflict {
                ContributorClosure::Open
            } else {
                ContributorClosure::Closed(TierReceipt {
                    selected_read: "jvm-selected-root-imports",
                })
            },
        });
        tiers.push(TierInput {
            rank: unit_rank,
            contributors: unit,
        });
        tiers.push(TierInput {
            rank: unit_rank + 1,
            contributors: vec![TierContributor {
                candidates: same_package
                    .then_some(JvmTypeNameAlternative::SamePackage)
                    .into_iter()
                    .collect(),
                closure: lexical_closure.clone(),
            }],
        });
        assert!(
            placed.is_empty(),
            "every placed rank has a tier: {placed:?}"
        );
        Ok(Some(JvmInheritedTypeNameTiers {
            tiers,
            on_demand_rank: unit_rank + 2,
            consumed_walk: levels > 0,
            open_inherited_rank,
        }))
    }

    fn jvm_on_demand_observation(
        &self,
        prepared: &JvmContextPreparation,
        reference: SemanticId,
        lookup: SemanticId,
        recipe: &ResolutionLookupSemanticRecipe,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmOnDemandObservation>> {
        let language = prepared.source.semantic_language();
        let rules = nominal_language_rules(language).expect("JVM caller");
        let Some(bindings) = self.jvm_on_demand_bindings(prepared, lookup, recipe, cancellation)?
        else {
            return Ok(None);
        };
        let local = super::imports::authored_reference_local_path_evidence(
            &self.ready,
            reference,
            cancellation,
        )?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let scala_token = (language == Language::Scala)
            .then(|| {
                prepared
                    .package_references
                    .iter()
                    .find(|candidate| {
                        candidate.reference == reference
                            && candidate.lookup == lookup
                            && candidate.namespace == ResolutionNamespace::Type
                    })
                    .map(|candidate| candidate.token)
            })
            .flatten();
        let same_package = if language == Language::Scala {
            scala_token
                .and_then(|token| {
                    prepared
                        .scala_local_package_by_token
                        .get(&token)
                        .or_else(|| {
                            prepared
                                .scala_reference_packages
                                .get(&token)
                                .and_then(Option::as_ref)
                                .and_then(|prefixes| prefixes.last())
                        })
                })
                .map(String::as_str)
                .unwrap_or("")
        } else {
            prepared.source_package.as_deref().unwrap_or("")
        };
        let same_package_local = if language == Language::Scala {
            scala_token
                .is_some_and(|token| prepared.scala_local_package_by_token.contains_key(&token))
        } else {
            prepared.same_package_lookups.contains(&lookup)
        };
        // A package plan can contain enclosing-prefix hosts and imported
        // names. Its lookup bucket is not proof of same-package ownership.
        // Package bridges establish that stronger rank during binding.
        self.profile_jvm_read(
            "on_demand_scope",
            (
                reference,
                lookup,
                recipe.spelling(),
                same_package,
                same_package_local,
                local.as_ref().map(|local| local.local_definitions()),
            ),
        );
        let has_local_definition = local
            .as_ref()
            .is_some_and(|evidence| !evidence.local_definitions().is_empty());
        if language != Language::Scala && (same_package_local || has_local_definition) {
            // JLS 6.4.1: same-unit and current-package definitions preempt
            // Java on-demand type imports before their provider search.
            return Ok(Some(JvmOnDemandObservation {
                choice: JvmOnDemandTypeChoice::Unavailable,
                local_path_read: local.is_some(),
                lexical: has_local_definition,
                same_package: same_package_local,
                unsearched: true,
            }));
        }
        // With no selected provider, a name that needs one cannot be searched.
        // The nearer tiers above are still read, so they can close.
        if self
            .jvm_external_provider_ids
            .get_or_init(|| self.ready.selected_jvm_external_providers())
            .is_empty()
            && !on_demand_type_admitted_without_provider(language, recipe)
        {
            return Ok(Some(JvmOnDemandObservation {
                choice: JvmOnDemandTypeChoice::Unavailable,
                local_path_read: local.is_some(),
                lexical: has_local_definition,
                same_package: same_package_local,
                unsearched: true,
            }));
        }
        let package_coordinate = local.as_ref().and_then(|evidence| {
            evidence
                .ordered_checkpoint_ancestry()
                .last()
                .and_then(|(endpoint, _)| evidence.binding_scope_coordinate(*endpoint))
        });
        let mut packages = rules
            .implicit_root_providers()
            .iter()
            .filter_map(|provider| match provider {
                JvmImplicitRootProvider::Package(package) => {
                    binding_origin_rank(language, BindingOrigin::DefaultImport).map(|rank| {
                        (
                            (*package).to_owned(),
                            super::jvm_demand::JvmBindingPrecedence {
                                rank,
                                depth: rules
                                    .implicit_root_precedence(*provider)
                                    .unwrap_or(u32::MAX),
                            },
                            None,
                            Some(SelectedJavaOnDemandSource::Default),
                        )
                    })
                }
                JvmImplicitRootProvider::ScalaPredef => None,
            })
            .collect::<Vec<_>>();
        for binder in prepared
            .binders
            .iter()
            .filter(|binder| jvm_on_demand_import(binder))
        {
            let SelectedRootPathHalf::Import { token, .. } = &binder.half else {
                unreachable!("binder is an import")
            };
            if binder
                .recipes
                .last()
                .is_none_or(|demand| demand.spelling() != recipe.spelling())
            {
                continue;
            }
            let package = jvm_on_demand_package(binder);
            for binding in bindings
                .iter()
                .filter(|binding| binding.token == *token && binding.reference == reference)
            {
                packages.push((
                    package.clone(),
                    binding.precedence,
                    binding.coordinate.clone(),
                    Some(SelectedJavaOnDemandSource::AuthoredImport(*token)),
                ));
            }
        }
        // FQNs, rather than mounts or import clauses, distinguish candidates.
        // Repeated imports of P.N are the same candidate; mounted P.N shadows
        // its external half and is never sent to the external owner reader.
        let default_rank =
            binding_origin_rank(language, BindingOrigin::DefaultImport).expect("default rank");
        let priority = |precedence: super::jvm_demand::JvmBindingPrecedence| {
            (
                precedence.rank,
                if precedence.rank == default_rank {
                    precedence.depth
                } else {
                    u32::MAX
                },
            )
        };
        packages
            .sort_by_key(|(package, precedence, _, _)| (priority(*precedence), package.clone()));
        let mut deciding_rank = packages
            .iter()
            .filter(|(package, _, _, _)| {
                prepared
                    .package_plan
                    .get(package)
                    .is_some_and(|plan| plan.candidates.contains_key(&lookup))
            })
            .map(|(_, precedence, _, _)| priority(*precedence))
            .min();
        let mut candidates = Vec::new();
        if language == Language::Scala {
            // SLS chapter 2: an inner binding shadows an outer binding only
            // when its precedence is equal or stronger; within one scope it
            // must be strictly stronger. An outer package definition and a
            // later weaker wildcard can therefore both survive.
            let local_rank =
                binding_origin_rank(language, BindingOrigin::SameCompilationUnitPackage)
                    .expect("Scala same-unit rank");
            if has_local_definition || same_package_local {
                let coordinate = if same_package_local {
                    package_coordinate.clone()
                } else {
                    local.as_ref().and_then(|evidence| {
                        evidence
                            .ordered_checkpoint_ancestry()
                            .first()
                            .and_then(|(endpoint, _)| evidence.binding_scope_coordinate(*endpoint))
                    })
                };
                candidates.push(JvmOnDemandCandidate {
                    precedence: super::jvm_demand::JvmBindingPrecedence {
                        rank: local_rank,
                        depth: 0,
                    },
                    coordinate,
                    fqn: if same_package.is_empty() {
                        recipe.spelling().to_owned()
                    } else {
                        format!("{same_package}.{}", recipe.spelling())
                    },
                    package: same_package.to_owned(),
                    declared: None,
                    implicit_root: false,
                    source: None,
                });
            } else {
                if let Some(prefixes) = scala_token
                    .and_then(|token| prepared.scala_reference_packages.get(&token))
                    .and_then(Option::as_ref)
                {
                    for package in prefixes.iter().rev() {
                        let fqn = format!("{package}.{}", recipe.spelling());
                        if let Some(declared) = self.jvm_declared_type(language, &fqn)?
                            && declared.owner.is_some()
                        {
                            candidates.push(JvmOnDemandCandidate {
                                precedence: super::jvm_demand::JvmBindingPrecedence {
                                    rank: binding_origin_rank(
                                        language,
                                        BindingOrigin::OtherCompilationUnitPackage,
                                    )
                                    .expect("Scala other-unit package rank"),
                                    depth: 0,
                                },
                                coordinate: package_coordinate.clone(),
                                fqn,
                                package: package.clone(),
                                declared: Some(declared),
                                implicit_root: false,
                                source: None,
                            });
                            break;
                        }
                    }
                }
            }
        }
        let mut open_default = false;
        for (package, precedence, coordinate, source) in packages {
            if language != Language::Scala
                && deciding_rank.is_some_and(|best| priority(precedence) > best)
            {
                continue;
            }
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if language != Language::Scala
                && bindings.iter().any(|binding| {
                    binding.reference == reference
                        && binding.precedence.rank < precedence.rank
                        && binding_origin_rank(
                            language,
                            super::jvm_demand::jvm_root_import_origin(
                                language,
                                ResolutionRootImportKind::Glob,
                            ),
                        )
                        .is_some_and(|glob| binding.precedence.rank < glob)
                })
            {
                continue;
            }
            let plan = prepared
                .package_plan
                .get(&package)
                .expect("on-demand package was planned");
            let fqn = brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                language,
                &package,
                recipe.spelling(),
            )
            .map_or_else(|| format!("{package}.{}", recipe.spelling()), str::to_owned);
            let external = if plan.candidates.contains_key(&lookup) {
                None
            } else {
                if !plan.empty
                    && brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                        language,
                        &package,
                        recipe.spelling(),
                    )
                    .is_none()
                    && !(recipe.namespace() == ResolutionNamespace::Type
                        && brokk_bifrost_jvm::intrinsics::compiler_root_owner(
                            language,
                            &package,
                            recipe.spelling(),
                        )
                        .is_some())
                {
                    continue;
                }
                if !rules.imports_nested_types_on_demand()
                    && !rules.implicit_root_providers().iter().any(|provider| matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package))
                    && self.jvm_declared_type(language, &package)?.is_some()
                {
                    continue;
                }
                let key = (language, fqn.clone());
                if self.jvm_declared_type_memo.borrow().get(&key).is_none() {
                    self.profile_jvm_read("on_demand_external_type", (&package, recipe.spelling()));
                }
                let declared = self.jvm_declared_type(language, &fqn)?;
                let declared = match declared {
                    Some(declared) => declared,
                    None if brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                        language,
                        &package,
                        recipe.spelling(),
                    )
                    .is_some() =>
                    {
                        JvmDeclaredType {
                            fqn: fqn.clone(),
                            owner: None,
                            indexed: false,
                        }
                    }
                    None => continue,
                };
                Some(declared)
            };
            // Discover positive owners before testing shadowing. The certified
            // default-provider tables prove name absence without acquiring the
            // provider; a mounted positive member still takes precedence.
            if precedence.rank == default_rank
                // Walk the roots highest-first. A root that does not outrank this
                // candidate ends the walk unblocked (Answer(true)); a higher root
                // with a candidate of its own blocks it (Answer(false)); a higher
                // root without one is skipped only when its table proves the name
                // absent, and otherwise leaves the name Open.
                && matches!(
                    brokk_bifrost_jvm::intrinsics::ordered_implicit_root(
                        language,
                        recipe.spelling(),
                        |name| {
                            let root = if name == SCALA_PREDEF_DEFAULT_IMPORT {
                                JvmImplicitRootProvider::ScalaPredef
                            } else {
                                JvmImplicitRootProvider::Package(name)
                            };
                            if !rules
                                .implicit_root_precedence(root)
                                .is_some_and(|priority| priority < precedence.depth)
                            {
                                return Some(true);
                            }
                            if brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(language, name, recipe.spelling()).is_some()
                                || (recipe.namespace() == ResolutionNamespace::Type && brokk_bifrost_jvm::intrinsics::compiler_root_owner(language, name, recipe.spelling()).is_some()) {
                                return Some(false);
                            }
                            prepared
                                .package_plan
                                .get(name)
                                .filter(|plan| plan.candidates.contains_key(&lookup))
                                .map(|_| false)
                        },
                    ),
                    brokk_bifrost_jvm::intrinsics::ImplicitRootLookup::Open
                        | brokk_bifrost_jvm::intrinsics::ImplicitRootLookup::Answer(false)
                )
            {
                open_default = true;
                continue;
            }
            if language != Language::Scala {
                deciding_rank = Some(
                    deciding_rank
                        .map_or(priority(precedence), |best| best.min(priority(precedence))),
                );
            }
            let candidate = JvmOnDemandCandidate {
                precedence,
                coordinate,
                fqn: fqn.clone(),
                package,
                declared: external,
                implicit_root: precedence.rank == default_rank,
                source,
            };
            if language == Language::Scala {
                retain_on_demand_candidate(language, &mut candidates, candidate);
            } else if let Some(existing) =
                candidates.iter_mut().find(|existing| existing.fqn == fqn)
            {
                if (precedence.rank, precedence.depth)
                    < (existing.precedence.rank, existing.precedence.depth)
                {
                    *existing = candidate;
                } else if priority(precedence) == priority(existing.precedence)
                    && existing.source != candidate.source
                {
                    // One FQN at one winning rank can still have two authored
                    // routes. Keep the type choice, but certify neither route.
                    existing.source = None;
                }
            } else {
                candidates.push(candidate);
            }
        }
        let best = (language != Language::Scala)
            .then(|| {
                candidates
                    .iter()
                    .map(|candidate| priority(candidate.precedence))
                    .min()
            })
            .flatten();
        if language != Language::Scala {
            candidates.retain(|candidate| Some(priority(candidate.precedence)) == best);
        }
        let choice = if candidates.len() > 1 {
            JvmOnDemandTypeChoice::Competing(candidates)
        } else if let Some(candidate) = candidates.pop() {
            let JvmOnDemandCandidate {
                precedence,
                package,
                declared,
                source,
                ..
            } = candidate;
            match declared {
                Some(declared) if declared.indexed => {
                    JvmOnDemandTypeChoice::Indexed(JvmOnDemandType {
                        declared,
                        precedence,
                        package,
                        source,
                    })
                }
                Some(declared)
                    if declared
                        .owner
                        .as_ref()
                        .is_some_and(|owner| owner.provider_id.as_ref() == "jvm-intrinsic") =>
                {
                    JvmOnDemandTypeChoice::Intrinsic(JvmOnDemandType {
                        declared,
                        precedence,
                        package,
                        source,
                    })
                }
                Some(declared)
                    if brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                        language,
                        &package,
                        recipe.spelling(),
                    )
                    .is_some() =>
                {
                    JvmOnDemandTypeChoice::Alias(JvmOnDemandType {
                        declared,
                        precedence,
                        package,
                        source,
                    })
                }
                _ => JvmOnDemandTypeChoice::Unavailable,
            }
        } else if open_default {
            JvmOnDemandTypeChoice::OpenDefault
        } else {
            JvmOnDemandTypeChoice::Unavailable
        };
        Ok(Some(JvmOnDemandObservation {
            choice,
            local_path_read: local.is_some(),
            lexical: has_local_definition,
            same_package: same_package_local,
            unsearched: false,
        }))
    }

    fn jvm_on_demand_bindings(
        &self,
        prepared: &JvmContextPreparation,
        lookup: SemanticId,
        recipe: &ResolutionLookupSemanticRecipe,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmOnDemandBindings>> {
        if let Some(bindings) = prepared.on_demand_bindings.get(&lookup) {
            return Ok(Some(bindings));
        }
        let Some(bindings) = super::jvm_demand::jvm_import_bindings_for_lookup(
            self,
            prepared.source.ordinal(),
            recipe,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let bindings: JvmOnDemandBindings = bindings.into();
        prepared
            .on_demand_bindings
            .insert(lookup, Arc::clone(&bindings));
        Ok(Some(bindings))
    }

    fn jvm_competing_on_demand_gaps(
        &self,
        prepared: &JvmContextPreparation,
        reference: &LoweredPackageReference,
        recipe: &ResolutionLookupSemanticRecipe,
        scoped_gaps: &mut Vec<JvmImportContextGap>,
        cancellation: &CancellationToken,
    ) -> Result<Option<()>> {
        let Some(bindings) =
            self.jvm_on_demand_bindings(prepared, reference.lookup, recipe, cancellation)?
        else {
            return Ok(None);
        };
        for binding in bindings
            .iter()
            .filter(|binding| binding.reference == reference.reference)
        {
            let Some(binder) = prepared.binders.iter().find(|binder| {
                jvm_on_demand_import(binder)
                    && matches!(&binder.half, SelectedRootPathHalf::Import { token, .. } if *token == binding.token)
            }) else { continue; };
            let package = jvm_on_demand_package(binder);
            if !prepared
                .package_plan
                .get(&package)
                .expect("on-demand package was planned")
                .empty
            {
                continue;
            }
            // This gap belongs to the authored reference and its explicit glob,
            // not to the weaker implicit default. The existing binding metadata
            // therefore keeps an equal-rank source glob from discharging it.
            let mut gap = self.jvm_import_context_gap(JvmImportContextGapSpec {
                source: prepared.source.fragment(),
                source_token: binding.token,
                source_reference: Some(reference.reference),
                kind: "jvm-import-owner-open",
                owner: Some(package),
                lookup: recipe.clone(),
                detail: format!("{} on-demand type `{}` has competing selected providers or ambiguous provider authority",
                    prepared.source.semantic_language().config_label(), recipe.spelling()),
            }, cancellation)?;
            gap.boundary_status =
                Some(crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed);
            scoped_gaps.push(gap);
        }
        Ok(Some(()))
    }

    fn jvm_on_demand_import_competes(
        &self,
        prepared: &JvmContextPreparation,
        binder: &ImportBinder,
    ) -> bool {
        if !jvm_on_demand_import(binder) {
            return false;
        }
        let recipe = binder.recipes.last().expect("an import has a demand");
        prepared
            .external_providers
            .references_by_route
            .iter()
            .any(|(&(_, lookup), references)| {
                prepared.external_providers.recipes[&lookup].spelling() == recipe.spelling()
                    && references.iter().any(|reference| {
                        prepared
                            .simple_type_name_decisions
                            .get(reference)
                            .is_some_and(|decision| {
                                matches!(
                                    decision.on_demand_choice(),
                                    JvmOnDemandTypeChoice::Competing(_)
                                        | JvmOnDemandTypeChoice::Possible(_)
                                )
                            })
                    })
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
        if language == Language::Scala {
            for (&(source_token, lookup), references) in
                &prepared.external_providers.references_by_route
            {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                if same_package_lookups.contains(&source_token)
                    || prepared
                        .scala_local_package_by_token
                        .contains_key(&source_token)
                {
                    continue;
                }
                let Some(prefixes) = prepared
                    .scala_reference_packages
                    .get(&source_token)
                    .and_then(Option::as_ref)
                else {
                    continue;
                };
                let recipe = &prepared.external_providers.recipes[&lookup];
                if demanded_name.is_some_and(|name| name != recipe.spelling()) {
                    continue;
                }
                let Some(bindings) = super::jvm_demand::jvm_import_bindings_for_lookup(
                    self,
                    prepared.source.ordinal(),
                    recipe,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                for package in prefixes.iter().rev() {
                    let fqn = format!("{package}.{}", recipe.spelling());
                    let Some(owner) = self.declared_jvm_owner(language, &fqn)? else {
                        continue;
                    };
                    for &reference in references {
                        if bindings.iter().any(|binding| {
                            binding.reference == reference && binding.precedence.rank < rank
                        }) {
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
                        same_package_lookups.insert(source_token);
                    }
                    break;
                }
            }
            return Ok(Some(selected));
        }
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
            external_member_targets: Vec::new(),
            pack_completion: ResolutionCompletion::Complete,
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

    fn jvm_pack_package_member_gap(
        &self,
        spec: JvmImportContextGapSpec,
        members: &[JvmExternalPackageMember],
        competing_source: bool,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContextGap> {
        assert!(
            !members.is_empty(),
            "a positive package gap has inventory members"
        );
        let mut gap = self.jvm_import_context_gap(spec, cancellation)?;
        gap.boundary_status =
            Some(crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed);
        for member in members {
            gap.pack_completion = gap.pack_completion.combine(&member.completion);
            if competing_source {
                // #8540: same-rank source and pack members stay open without a pack claim.
                continue;
            }
            let target = self.ready.context_identities.external_member_semantic(
                &member.member.owner,
                member.member.ordinal,
                &self.ready.shared_names(),
            );
            self.ready.context_identities.record_jvm_package_member_gap(
                target,
                gap.reason,
                member.completion == ResolutionCompletion::Complete,
            );
            gap.external_member_targets.push(target);
        }
        // #8542: a positive member remains open until its persisted family is certified.
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

    // Direct selected package hosts and selected parent edges are separate
    // positive facts. A parent package can exist without a file directly in it.
    // Preserve every source fragment of a package as one namespace receipt.
    fn jvm_selected_package_segment_hosts(
        &self,
        family: &dyn NominalPackageRules,
        package: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<JvmImportTarget>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let direct = self.jvm_import_targets(family.import_target_mounts(), package)?;
        let mut hosts = direct.ordered.to_vec();
        let connection = self.ready.inventory.connection();
        let edges = connection
            .prepare_cached(
                "SELECT mounted.mount_ordinal,mounted.file_version_id
             FROM temp.selected_resolution_mounts AS mounted
             JOIN main.workspace_file_package_edge_rows AS edge
               ON edge.file_version_id=mounted.file_version_id
             WHERE mounted.storage_language IN ('java','kotlin','scala')
               AND (edge.parent_package_name=?1 OR edge.child_package_name=?1)",
            )?
            .query_map([package], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, Option<i64>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        hosts.extend(edges);
        hosts.sort_unstable();
        hosts.dedup();
        Ok((!cancellation.is_cancelled()).then_some(hosts))
    }

    fn jvm_selected_package_alias_receipts(
        &self,
        family: &dyn NominalPackageRules,
        owner_route: &[ResolutionLookupSemanticRecipe],
        selected_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Option<JvmPackageRouteReceipts>>> {
        let mut package = String::new();
        let mut receipts = Vec::with_capacity(owner_route.len() + 1);
        for segment in owner_route
            .iter()
            .map(ResolutionLookupSemanticRecipe::spelling)
            .chain([selected_name])
        {
            if !package.is_empty() {
                package.push('.');
            }
            package.push_str(segment);
            let Some(hosts) =
                self.jvm_selected_package_segment_hosts(family, &package, cancellation)?
            else {
                return Ok(None);
            };
            if hosts.is_empty() {
                return Ok(Some(None));
            }
            receipts.push((package.clone(), hosts));
        }
        // The selector itself needs a file in its exact package. An ancestor
        // edge only proves the existence of a namespace, not that selected full route.
        let full = self.jvm_import_targets(family.import_target_mounts(), &package)?;
        Ok(Some((!full.ordered.is_empty()).then_some(receipts)))
    }

    pub(super) fn jvm_selected_package_alias_for_import(
        &self,
        source_mount: SelectedResolutionMountOrdinal,
        source_token: SemanticId,
        source_lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Read<Option<JvmSelectedPackageAlias>>> {
        let source = self.mount_table().mount_by_ordinal(source_mount)?;
        let Some(prepared) = self.jvm_import_context_preparation(
            source.semantic_language(),
            source.persisted_relative_path(),
            cancellation,
        )?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        let names = self.ready.shared_names();
        let alias = prepared.binders.iter().filter(|binder| {
            matches!(&binder.half, SelectedRootPathHalf::Import { token, .. } if *token == source_token)
        }).filter_map(|binder| prepared.imports.get(&binder.identity))
          .filter_map(|derived| derived.package_alias.clone())
          .find(|alias| alias.source_token == source_token && alias.demand.semantic(&names) == source_lookup);
        let Some(alias) = alias else {
            return Ok(Read::ready(None));
        };
        let family = nominal_language_rules(source.semantic_language())
            .expect("selected package alias has nominal rules")
            .family();
        let mut valid = true;
        for (package, expected) in &alias.receipts {
            let Some(actual) =
                self.jvm_selected_package_segment_hosts(family, package, cancellation)?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            if &actual != expected {
                valid = false;
                break;
            }
        }
        let exact = self.jvm_import_targets(family.import_target_mounts(), &alias.container)?;
        valid &= exact.ordered.as_ref() == alias.exact_hosts.as_slice();
        if valid {
            for &(ordinal, version) in &alias.exact_hosts {
                if cancellation.is_cancelled() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                let target = self
                    .mount_table()
                    .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                valid &= self.jvm_qualified_source_access_completion(
                    source.semantic_language(),
                    prepared.context_id,
                    prepared.source_record.file_version_id(),
                    source.persisted_relative_path(),
                    version,
                    target.persisted_relative_path(),
                    &ResolutionCompletion::Complete,
                )? == Some(ResolutionCompletion::Complete);
            }
        }
        if !valid {
            let reason = self.ready.context_identities.named_semantic(
                CanonicalHasher::new(b"jvm-package-alias-route-open:v1").finish(),
                "jvm-package-alias-route-open",
                "Selected package alias route changed before replay",
            );
            return Ok(Read::Ready {
                value: None,
                completion: ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]),
            });
        }
        Ok(Read::ready(Some(alias)))
    }

    pub(super) fn jvm_selected_package_alias_for_site(
        &self,
        source_mount: SelectedResolutionMountOrdinal,
        source_site: ResolutionSiteId,
        source_lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Read<Option<JvmSelectedPackageAlias>>> {
        let source = self.mount_table().mount_by_ordinal(source_mount)?;
        let Some(prepared) = self.jvm_import_context_preparation(
            source.semantic_language(),
            source.persisted_relative_path(),
            cancellation,
        )?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        let names = self.ready.shared_names();
        let mut tokens = Vec::new();
        for binder in &prepared.binders {
            let Some(derived) = prepared.imports.get(&binder.identity) else {
                continue;
            };
            let Some(alias) = &derived.package_alias else {
                continue;
            };
            if alias.demand.semantic(&names) != source_lookup {
                continue;
            }
            let Some(metadata) = self.import_token_metadata(
                prepared.source_record.blob_id(),
                source_mount,
                alias.source_token,
                cancellation,
            )?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            if metadata.route.as_ref().and_then(|route| route.source_site) == Some(source_site)
                && !tokens.contains(&alias.source_token)
            {
                tokens.push(alias.source_token);
            }
        }
        match tokens.as_slice() {
            [] => Ok(Read::ready(None)),
            [token] => self.jvm_selected_package_alias_for_import(
                source_mount,
                *token,
                source_lookup,
                cancellation,
            ),
            _ => {
                let reason = self.ready.context_identities.named_semantic(
                    CanonicalHasher::new(b"jvm-package-alias-site-ambiguous:v1").finish(),
                    "jvm-package-alias-route-open",
                    "Competing selected package aliases at one import site",
                );
                Ok(Read::Ready {
                    value: None,
                    completion: ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                    ]),
                })
            }
        }
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

    /// The single active-pack answer for one package/name/namespace point.
    /// The Kotlin file package plan calls jvm_active_package_members_batch directly.
    /// The JVM package-outcome detector (jvm_pure_package_exports) does not call
    /// this single-name wrapper (#8764).
    pub(in crate::analyzer) fn jvm_active_package_members(
        &self,
        language: Language,
        package: &str,
        name: &str,
        namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<JvmExternalPackageMember>>> {
        let demands = [(package.to_owned(), name.to_owned(), namespace)];
        Ok(self
            .jvm_active_package_members_batch(language, &demands, cancellation)?
            .map(|mut rows| rows.pop().expect("one package member demand")))
    }

    /// One indexed statement for every package/name demand in a file plan.
    fn jvm_active_package_members_batch(
        &self,
        language: Language,
        demands: &[(String, String, ResolutionNamespace)],
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<Vec<JvmExternalPackageMember>>>> {
        let rules = nominal_language_rules(language).expect("JVM caller");
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut admitted = vec![Vec::new(); demands.len()];
        if language != Language::Kotlin || demands.is_empty() {
            return Ok(Some(admitted));
        }
        let Some(active) = self
            .ready
            .model_authority()
            .and_then(|authority| authority.active_models())
        else {
            return Ok(Some(admitted));
        };
        let shards = active.shards();
        let providers = shards
            .iter()
            .map(|shard| shard.manifest.semantic_sha256.as_str())
            .collect::<Vec<_>>();
        if providers.is_empty() {
            return Ok(Some(admitted));
        }
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(JVM_ACTIVE_PACKAGE_MEMBERS_SQL)?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    serde_json::to_string(&providers).expect("provider IDs serialize"),
                    serde_json::to_string(
                        &demands
                            .iter()
                            .map(|(package, name, _)| (package, name))
                            .collect::<Vec<_>>()
                    )
                    .expect("package demands serialize"),
                ],
                |row| {
                    Ok((
                        row.get::<_, usize>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, bool>(7)?,
                        row.get::<_, bool>(8)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        for (
            demand_index,
            provider,
            ordinal,
            kind,
            visibility,
            is_static,
            family_complete,
            callables_complete,
            values_complete,
        ) in rows
        {
            let (package, name, namespace) = &demands[demand_index];
            if !rules.admits_external_package_member(&kind, *namespace)
                || visibility != "public"
                || !is_static
            {
                continue;
            }
            let shard = shards
                .iter()
                .find(|shard| shard.manifest.semantic_sha256 == provider)
                .expect("the point read uses active shard digests");
            let complete = shard.manifest.completeness
                == crate::analyzer::semantic_model::Completeness::Complete
                && family_complete
                && match namespace {
                    ResolutionNamespace::Callable => callables_complete,
                    ResolutionNamespace::Value => values_complete,
                    _ => unreachable!("the language hook admits only package member namespaces"),
                };
            let completion = if complete {
                ResolutionCompletion::Complete
            } else {
                let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                    b"jvm-pack-package-member-open:v1",
                );
                hash.field("provider", provider.as_bytes());
                hash.field("package", package.as_bytes());
                hash.field("name", name.as_bytes());
                let reason = self.ready.context_identities.named_semantic(
                    hash.finish(),
                    "JvmPackPackageMemberOpen",
                    &format!(
                        "{}@{} supplies {}.{} with incomplete package member inventory",
                        shard.manifest.pack_id, shard.manifest.version, package, name
                    ),
                );
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                    reason,
                )])
            };
            admitted[demand_index].push(JvmExternalPackageMember {
                pack_id: shard.manifest.pack_id.clone(),
                pack_version: shard.manifest.version.clone(),
                member: crate::analyzer::resolution::ExternalMemberIdentity {
                    owner: crate::analyzer::resolution::ExternalOwnerIdentity {
                        provider_id: provider.into(),
                        owner_fqn: package.as_str().into(),
                    },
                    ordinal,
                },
                is_static,
                visibility: DeclaredVisibility::Public,
                completion,
            });
        }
        Ok(Some(admitted))
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
        demands: &[(SemanticId, String, ResolutionNamespace, HashSet<SemanticId>)],
        pack_members: &[Vec<JvmExternalPackageMember>],
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<JvmPackageIndex>>> {
        let key =
            self.jvm_package_target_key(package, lookups, family.storage_language_parameters());
        self.profile_jvm_read("package_index", &key);
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let source_index = if let Some(index) = self.jvm_package_indexes.borrow().get(&key) {
            Arc::clone(index)
        } else {
            self.profile_jvm_read("derive_package_index", &key);
            let Some(targets) = self.jvm_package_member_targets(&key, cancellation)? else {
                return Ok(None);
            };
            let Some(by_lookup) = self.source_mount_package_candidates(&targets, cancellation)?
            else {
                return Ok(None);
            };
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
            index
        };
        let mut by_lookup = source_index.by_lookup.clone();
        for ((lookup, _, _, _), members) in demands.iter().zip(pack_members) {
            by_lookup.entry(*lookup).or_default().extend(
                members
                    .iter()
                    .cloned()
                    .map(JvmPackageCandidate::ExternalMember),
            );
        }
        Ok(Some(Arc::new(JvmPackageIndex {
            empty: source_index.empty,
            by_lookup,
        })))
    }

    fn source_mount_package_candidates(
        &self,
        targets: &JvmImportTargetRows,
        cancellation: &CancellationToken,
    ) -> Result<Option<HashMap<SemanticId, Vec<JvmPackageCandidate>>>> {
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
                    .push(JvmPackageCandidate::SourceMount {
                        mount,
                        version,
                        order,
                        members: Arc::clone(rows),
                    });
            }
        }
        Ok(Some(by_lookup))
    }

    /// Match a file's structured reference names against its package/default
    /// import sets once. Named contexts consume only their reference rows from
    /// this plan; access evidence and bridge publication stay demand-scoped.
    #[expect(
        clippy::too_many_arguments,
        reason = "per-reference package evidence is explicit"
    )]
    fn jvm_file_package_plan(
        &self,
        language: Language,
        fragment: BindingFragmentId,
        source_package: Option<&str>,
        scala_reference_packages: &HashMap<SemanticId, Option<Vec<String>>>,
        references: &[LoweredPackageReference],
        binders: &[ImportBinder],
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
        if language == Language::Scala {
            packages.extend(
                scala_reference_packages
                    .values()
                    .flatten()
                    .flat_map(|prefixes| prefixes.iter().cloned()),
            );
        }
        let names = self.ready.shared_names();
        let mut lookups = HashMap::default();
        let mut has_provider_free_type = false;
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
            has_provider_free_type |= recipe.namespace() == ResolutionNamespace::Type
                && on_demand_type_admitted_without_provider(language, recipe);
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
        // Plan authored import peers for provider-free Type lookups, preserving shadows.
        if !self
            .jvm_external_provider_ids
            .get_or_init(|| self.ready.selected_jvm_external_providers())
            .is_empty()
            || has_provider_free_type
        {
            packages.extend(
                binders
                    .iter()
                    .filter(|binder| jvm_on_demand_import(binder))
                    .map(jvm_on_demand_package),
            );
        }
        // Only active published owners can add Kotlin explicit-import package
        // plans. Without them, source package planning stays byte-for-byte at
        // the provider-free route above.
        if language == Language::Kotlin {
            let mut candidate_packages = binders
                .iter()
                .filter(|binder| binder.recipes.len() > 1)
                .map(jvm_on_demand_package)
                .collect::<Vec<_>>();
            candidate_packages.sort_unstable();
            candidate_packages.dedup();
            if !candidate_packages.is_empty()
                && let Some(active) = self
                    .ready
                    .model_authority()
                    .and_then(|authority| authority.active_models())
            {
                let shards = active.shards();
                let providers = shards
                    .iter()
                    .map(|shard| shard.manifest.semantic_sha256.as_str())
                    .collect::<Vec<_>>();
                if !providers.is_empty() {
                    let mut statement = self
                        .ready
                        .inventory
                        .connection()
                        .prepare_cached(JVM_ACTIVE_PACKAGE_OWNERS_SQL)?;
                    let published = statement
                        .query_map(
                            rusqlite::params![
                                serde_json::to_string(&providers).expect("provider IDs serialize"),
                                serde_json::to_string(&candidate_packages)
                                    .expect("candidate packages serialize"),
                            ],
                            |row| row.get::<_, String>(0),
                        )?
                        .collect::<rusqlite::Result<HashSet<_>>>()?;
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    packages.extend(published.iter().cloned());
                    for binder in binders.iter().filter(|binder| {
                        binder.recipes.len() > 1
                            && published.contains(&jvm_on_demand_package(binder))
                    }) {
                        let recipe = binder.recipes.last().expect("named import has a recipe");
                        let lookup = recipe.semantic(&names);
                        lookups.entry(lookup).or_insert_with(|| {
                            family
                                .languages()
                                .iter()
                                .copied()
                                .map(|target_language| {
                                    self.jvm_generated_lookup(
                                        target_language,
                                        recipe.namespace(),
                                        recipe.spelling(),
                                    )
                                    .semantic(&names)
                                })
                                .collect()
                        });
                    }
                }
            }
        }
        packages.sort_unstable();
        packages.dedup();
        let all_lookups = lookups.values().flatten().copied().collect::<Vec<_>>();
        let mut demands = Vec::new();
        for reference in references {
            let Some(mut recipes) =
                self.jvm_lookup_recipes(fragment, [reference.lookup], cancellation)?
            else {
                return Ok(None);
            };
            let recipe = recipes.pop().expect("one package lookup recipe");
            if !demands
                .iter()
                .any(|(lookup, _, _, _)| *lookup == reference.lookup)
            {
                demands.push((
                    reference.lookup,
                    recipe.spelling().to_owned(),
                    reference.namespace,
                    lookups[&reference.lookup].clone(),
                ));
            }
        }
        if language == Language::Kotlin {
            for binder in binders {
                let Some(recipe) = binder.recipes.last() else {
                    continue;
                };
                let lookup = recipe.semantic(&names);
                let Some(target_lookups) = lookups.get(&lookup) else {
                    continue;
                };
                if !demands
                    .iter()
                    .any(|(existing, _, _, _)| *existing == lookup)
                {
                    demands.push((
                        lookup,
                        recipe.spelling().to_owned(),
                        recipe.namespace(),
                        target_lookups.clone(),
                    ));
                }
            }
        }
        let mut plan = HashMap::default();
        let batch_demands = packages
            .iter()
            .flat_map(|package| {
                demands
                    .iter()
                    .map(move |(_, name, namespace, _)| (package.clone(), name.clone(), *namespace))
            })
            .collect::<Vec<_>>();
        let Some(batch_members) =
            self.jvm_active_package_members_batch(language, &batch_demands, cancellation)?
        else {
            return Ok(None);
        };
        for (package_index, package) in packages.into_iter().enumerate() {
            let pack_members =
                &batch_members[package_index * demands.len()..(package_index + 1) * demands.len()];
            let Some(index) = self.jvm_package_index(
                family,
                &package,
                &all_lookups,
                &demands,
                pack_members,
                cancellation,
            )?
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
                if !target_lookups.contains(&lookup) {
                    matches.extend(index.by_lookup.get(&lookup).into_iter().flatten().cloned());
                }
                matches.sort_by_key(|candidate| match candidate {
                    JvmPackageCandidate::SourceMount { order, .. } => *order,
                    JvmPackageCandidate::ExternalMember(_) => usize::MAX,
                });
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
            prepared,
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
        let has_implicit_packages = packages.iter().any(|package| {
            implicit_root_providers.iter().any(|provider| {
            matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package.as_str())
        })
        });
        for (reference, source_recipe) in &reference_recipes {
            if has_implicit_packages
                && prepared
                    .unqualified_type_references
                    .contains(&reference.reference)
                && prepared
                    .external_providers
                    .recipes
                    .contains_key(&reference.lookup)
            {
                let Some(choice) = self.jvm_on_demand_type(
                    prepared,
                    reference.reference,
                    reference.lookup,
                    source_recipe,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                if matches!(
                    choice,
                    JvmOnDemandTypeChoice::Competing(_) | JvmOnDemandTypeChoice::Possible(_)
                ) && self
                    .jvm_competing_on_demand_gaps(
                        prepared,
                        reference,
                        source_recipe,
                        scoped_gaps,
                        cancellation,
                    )?
                    .is_none()
                {
                    return Ok(None);
                }
            }
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
                let (indexed_external, intrinsic_external) = if prepared
                    .unqualified_type_references
                    .contains(&reference.reference)
                    && prepared
                        .external_providers
                        .recipes
                        .contains_key(&reference.lookup)
                {
                    let Some(choice) = self.jvm_on_demand_type(
                        prepared,
                        reference.reference,
                        reference.lookup,
                        source_recipe,
                        cancellation,
                    )?
                    else {
                        return Ok(None);
                    };
                    match choice {
                        JvmOnDemandTypeChoice::Indexed(winner) => {
                            (winner.package == *package, false)
                        }
                        JvmOnDemandTypeChoice::Intrinsic(winner) => {
                            (false, winner.package == *package)
                        }
                        JvmOnDemandTypeChoice::Alias(winner) => {
                            // The alias itself is known at this root. Its target's
                            // acquisition gap is registered separately.
                            (winner.package == *package, false)
                        }
                        JvmOnDemandTypeChoice::Possible(_)
                        | JvmOnDemandTypeChoice::Competing(_)
                        | JvmOnDemandTypeChoice::OpenDefault
                        | JvmOnDemandTypeChoice::Unavailable => (false, false),
                    }
                } else {
                    (false, false)
                };
                // An Intrinsic winner has passed jvm_on_demand_type's ordered
                // higher-root proof: Open or answering Predef roots reject it.
                // A compiler-synthesized type exists without the library, which
                // cannot declare a type of that name. Acquisition cannot change
                // this answer. Other intrinsic winners retain their package gap.
                let compiler_root = intrinsic_external
                    && source_recipe.namespace() == ResolutionNamespace::Type
                    && brokk_bifrost_jvm::intrinsics::compiler_root_owner(
                        source_language,
                        package,
                        source_recipe.spelling(),
                    )
                    .is_some();
                let package_candidates = planned.candidates.get(&reference.lookup);
                let pack_members = package_candidates
                    .into_iter()
                    .flatten()
                    .filter_map(|candidate| match candidate {
                        JvmPackageCandidate::ExternalMember(member) => Some(member.clone()),
                        JvmPackageCandidate::SourceMount { .. } => None,
                    })
                    .collect::<Vec<_>>();
                let competing_source = package_candidates
                    .into_iter()
                    .flatten()
                    .any(|candidate| matches!(candidate, JvmPackageCandidate::SourceMount { .. }));
                // A compiler-root answer is fixed by the language; acquisition cannot add a pack gap.
                if is_default_import && !compiler_root && !pack_members.is_empty() {
                    scoped_gaps.push(self.jvm_pack_package_member_gap(
                        JvmImportContextGapSpec {
                            source: source_mount.fragment(),
                            source_token: reference.token,
                            source_reference: Some(reference.reference),
                            kind: "jvm-pack-package-member",
                            owner: Some(package.to_owned()),
                            lookup: source_recipe.clone(),
                            detail: format!(
                                "{}@{} supplies package member `{}.{}`",
                                pack_members[0].pack_id,
                                pack_members[0].pack_version,
                                package,
                                source_recipe.spelling()
                            ),
                        },
                        &pack_members,
                        competing_source,
                        cancellation,
                    )?);
                } else if is_default_import
                    && planned.empty
                    && !indexed_external
                    && !compiler_root
                    // A platform package declares only classes. With the JDK's
                    // declarations extracted, a value or callable name is
                    // absent from it, as a Kotlin or Scala default import of
                    // `java.lang` is asked for every name a body spells.
                    && !(source_recipe.namespace() != ResolutionNamespace::Type
                        && reserved_jdk_package(package)
                        && self.jdk_declaration_extraction_selected())
                {
                    scoped_gaps.push(self.jvm_import_context_boundary_gap_with_same_package_shadow(
                        JvmImportContextGapSpec {
                            source: source_mount.fragment(),
                            source_token: reference.token,
                            source_reference: Some(reference.reference),
                            kind: "jvm-default-import-package-open",
                            owner: Some(package.to_owned()),
                            lookup: source_recipe.clone(),
                            detail: if intrinsic_external {
                                format!("{} default import package `{package}` is unacquired; the language-defined root `{package}.{}` has a fixed intrinsic owner", source_language.config_label(), source_recipe.spelling())
                            } else {
                                format!("{} default import package `{package}` has no selected source or classpath owner for `{}`", source_language.config_label(), source_recipe.spelling())
                            },
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
                    let (target_ordinal, target_version) = match candidate {
                        JvmPackageCandidate::SourceMount { mount, version, .. } => {
                            (*mount, *version)
                        }
                        JvmPackageCandidate::ExternalMember(_) => continue,
                    };
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
                    let exact_scala_access = if source_language == Language::Scala
                        && !self
                            .jvm_implicit_project_context(context_id)?
                            .has_selected_project
                    {
                        prepared
                            .scala_reference_packages
                            .get(&reference.token)
                            .and_then(Option::as_ref)
                            .map(|prefixes| {
                                let caller =
                                    crate::analyzer::store::maven::JvmSourceDomain::discover(
                                        std::path::Path::new(source_path),
                                        prefixes.last().map(String::as_str).unwrap_or(""),
                                        language_jvm_package_requires_directory_agreement(
                                            source_language,
                                            target_mount.semantic_language(),
                                        ),
                                    );
                                let target =
                                    crate::analyzer::store::maven::JvmSourceDomain::discover(
                                        std::path::Path::new(
                                            target_mount.persisted_relative_path(),
                                        ),
                                        package,
                                        language_jvm_package_requires_directory_agreement(
                                            source_language,
                                            target_mount.semantic_language(),
                                        ),
                                    );
                                match (caller, target) {
                                    (Some(caller), Some(target)) => {
                                        Some(caller.can_access(&target))
                                    }
                                    _ => None,
                                }
                            })
                    } else {
                        None
                    };
                    let Some(access) = (if source_language == Language::Scala
                        && !self
                            .jvm_implicit_project_context(context_id)?
                            .has_selected_project
                    {
                        match exact_scala_access.flatten() {
                            Some(true) => Some(ResolutionCompletion::Complete),
                            Some(false) | None => {
                                let reason = self.ready.context_identities.named_semantic(
                                    CanonicalHasher::new(b"jvm-source-domain-open:v1").finish(),
                                    "jvm-source-domain-open",
                                    "Selected source package and path do not prove a source access domain",
                                );
                                Some(ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                                ]))
                            }
                        }
                    } else {
                        self.jvm_qualified_source_access_completion(
                            source_language,
                            context_id,
                            caller_version,
                            source_path,
                            target_version,
                            target_mount.persisted_relative_path(),
                            &ResolutionCompletion::Complete,
                        )?
                    }) else {
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
            match candidate.candidate {
                JvmPackageCandidate::SourceMount { members, .. } => members,
                JvmPackageCandidate::ExternalMember(_) => {
                    unreachable!("external members do not form source bridges")
                }
            }
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
                prepared,
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
            prepared: _,
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
                let has_object_relation = connection.prepare_cached("SELECT 1 FROM main.resolution_semantic_sites AS site
                         JOIN main.resolution_singleton_relations AS singleton
                           ON singleton.blob_id=site.blob_id AND singleton.declaration_site=site.source_site
                         WHERE site.blob_id=?1 AND site.semantic_key=?2
                           AND site.semantic_role='definition' AND singleton.kind='object'")?.query_row(
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
            if reference.namespace == ResolutionNamespace::Type
                && let Some(target) = brokk_bifrost_jvm::intrinsics::implicit_root_type_alias(
                    source_language,
                    SCALA_PREDEF_DEFAULT_IMPORT,
                    source_recipe.spelling(),
                )
            {
                let prepared = import_context.prepared;
                let Some(bindings) = self.jvm_on_demand_bindings(
                    prepared,
                    reference.lookup,
                    &source_recipe,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                let local = super::imports::authored_reference_local_path_evidence(
                    &self.ready,
                    reference.reference,
                    cancellation,
                )?;
                let precedence = super::jvm_demand::JvmBindingPrecedence {
                    rank: binding_origin_rank(source_language, BindingOrigin::DefaultImport)
                        .expect("default rank"),
                    depth: rules
                        .implicit_root_precedence(JvmImplicitRootProvider::ScalaPredef)
                        .expect("Predef rank"),
                };
                if !prepared.scala_local_package_by_token.contains_key(&reference.token)
                    && local.is_none_or(|local| local.local_definitions().is_empty())
                    && !bindings.iter().any(|binding| {
                        binding.reference == reference.reference
                            && (binding.coordinate.is_none()
                                || super::jvm_demand::jvm_shadowing_rules(source_language)
                                    .shadows(
                                        binding.precedence.rank,
                                        precedence.rank,
                                        crate::analyzer::resolution::precedence::BindingScopeRelation::Inner,
                                    ) == crate::analyzer::resolution::precedence::Shadowing::Shadows)
                    })
                {
                    let declared = self
                        .jvm_declared_type(source_language, target)?
                        .unwrap_or_else(|| JvmDeclaredType {
                            fqn: target.to_owned(),
                            owner: None,
                            indexed: false,
                        });
                    // A Predef alias still sits below the enclosing classes'
                    // inherited tiers when the operation has their table.
                    let tiers = match &self.jvm_inherited_tier_knowledge {
                        Some(_) => {
                            let Some(tiers) = self.jvm_non_java_inherited_tiers(
                                source_language,
                                reference.reference,
                                reference.lookup,
                                source_recipe.spelling(),
                                cancellation,
                            )?
                            else {
                                return Ok(None);
                            };
                            Some(tiers)
                        }
                        None => None,
                    };
                    let JvmInheritedTypeNameTiers {
                        tiers,
                        on_demand_rank,
                        consumed_walk,
                        open_inherited_rank,
                    } = tiers.unwrap_or(JvmInheritedTypeNameTiers {
                        tiers: Vec::new(),
                        on_demand_rank: JVM_ON_DEMAND_TYPE_TIER,
                        consumed_walk: false,
                        open_inherited_rank: None,
                    });
                    self.jvm_decision_consumed_walk
                        .set(self.jvm_decision_consumed_walk.get() || consumed_walk);
                    prepared.simple_type_name_decisions.insert(
                        reference.reference,
                        Arc::new(JvmSimpleTypeNameDecision::from_tiers(
                            reference.lookup,
                            tiers,
                            on_demand_rank,
                            JvmOnDemandObservation::searched(JvmOnDemandTypeChoice::Alias(
                                JvmOnDemandType {
                                    declared,
                                    precedence,
                                    package: SCALA_PREDEF_DEFAULT_IMPORT.to_owned(),
                                    source: None,
                                },
                            )),
                            consumed_walk,
                            open_inherited_rank,
                        )),
                    );
                    continue;
                }
            }
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
                            .prepare_cached(
                                "SELECT 1 FROM main.resolution_singleton_relations
                                 WHERE blob_id=?1 AND declaration_site=?2 AND kind=?3",
                            )?
                            .query_row(
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

    fn jvm_indexed_on_demand_import(
        &self,
        prepared: &JvmContextPreparation,
        binder: &ImportBinder,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if !jvm_on_demand_import(binder)
            || self
                .jvm_external_provider_ids
                .get_or_init(|| self.ready.selected_jvm_external_providers())
                .is_empty()
        {
            return Ok(false);
        }
        let recipe = binder.recipes.last().expect("an import has a demand");
        if recipe.namespace() != ResolutionNamespace::Type {
            return Ok(false);
        }
        let package = jvm_on_demand_package(binder);
        let mut found = false;
        for (&(_, lookup), references) in &prepared.external_providers.references_by_route {
            if prepared.external_providers.recipes[&lookup].spelling() != recipe.spelling() {
                continue;
            }
            for &reference in references {
                let Some(choice) =
                    self.jvm_on_demand_type(prepared, reference, lookup, recipe, cancellation)?
                else {
                    return Ok(false);
                };
                match choice {
                    JvmOnDemandTypeChoice::Indexed(winner) if winner.package == package => {
                        found = true;
                    }
                    JvmOnDemandTypeChoice::Possible(_)
                    | JvmOnDemandTypeChoice::Competing(_)
                    | JvmOnDemandTypeChoice::OpenDefault
                    | JvmOnDemandTypeChoice::Unavailable
                    | JvmOnDemandTypeChoice::Alias(_)
                    | JvmOnDemandTypeChoice::Intrinsic(_)
                    | JvmOnDemandTypeChoice::Indexed(_) => return Ok(false),
                }
            }
        }
        if found
            && prepared.source.semantic_language() == Language::Java
            && let Some(route) = &binder.route
            && let Some(source_site) = route.source_site
        {
            // The positive candidate completes this reference's type import.
            // Retire the authored route placeholder just as the single-type
            // indexed-destination path does; otherwise unsupported_route leaks.
            for reason in selected_java_import_route_gap_reasons(
                &self.ready.inventory,
                prepared.source_record.blob_id(),
                prepared.source.ordinal(),
                source_site,
                route.staged,
            )? {
                self.ready
                    .context_identities
                    .record_java_import_route_gap_reason(reason);
                self.ready
                    .context_identities
                    .record_java_selected_import_proof(
                        prepared.source.fragment(),
                        source_site,
                        reason,
                    );
            }
        }
        Ok(found)
    }

    pub(super) fn java_on_demand_package_evidence(
        &self,
        caller_path: &str,
        lookup: &ResolutionLookupSemanticRecipe,
        cancellation: &CancellationToken,
    ) -> Result<Option<(Vec<JvmOnDemandPackageEvidence>, bool)>> {
        let Some(prepared) =
            self.jvm_import_context_preparation(Language::Java, caller_path, cancellation)?
        else {
            return Ok(None);
        };
        let mut evidence = Vec::new();
        let mut retain = |row: Option<&JvmOnDemandPackageEvidence>| {
            if let Some(row) = row
                && row.lookup == *lookup
            {
                evidence.push(row.clone());
            }
        };
        prepared
            .imports
            .for_each_entry(|_, import| retain(import.on_demand.as_ref()));
        Ok(Some((
            evidence,
            prepared
                .same_package_lookups
                .contains(&lookup.semantic(&self.ready.shared_names())),
        )))
    }

    pub(super) fn java_on_demand_route_gap_reason(
        &self,
        caller_path: &str,
        evidence: &JvmOnDemandPackageEvidence,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        let Some(prepared) =
            self.jvm_import_context_preparation(Language::Java, caller_path, cancellation)?
        else {
            return Ok(None);
        };
        let Some(site) = evidence.source_site else {
            return Ok(None);
        };
        // The Java producer asserts that a supported type-on-demand site has
        // one UnknownBinder route gap. Read-time authority also requires the
        // selected route and exactly one extracted reason at that site. A
        // malformed or legacy row remains open.
        let matches = prepared
            .binders
            .iter()
            .filter(|binder| {
                binder.identity == evidence.import_identity
                    && binder.route.as_ref().is_some_and(|route| {
                        route.kind == SelectedImportRouteKind::TypeOnDemand
                            && route.source_site == Some(site)
                            && route.staged == evidence.staged
                    })
                    && matches!(&binder.half, SelectedRootPathHalf::Import { token, .. }
                    if *token == evidence.import_token)
            })
            .count();
        if matches != 1 {
            return Ok(None);
        }
        let reasons = selected_java_import_route_gap_reasons(
            &self.ready.inventory,
            prepared.source_record.blob_id(),
            prepared.source.ordinal(),
            site,
            evidence.staged,
        )?;
        Ok((reasons.len() == 1).then(|| reasons[0]))
    }

    pub(super) fn classify_java_on_demand_package(
        &self,
        evidence: &JvmOnDemandPackageEvidence,
    ) -> JvmPackageOutcome {
        let mut partial = Vec::new();
        if !evidence.whole_package_read_exhausted || !evidence.named_read_exhausted {
            partial.push(JvmPackagePartialReason::ExportExhaustion);
        }
        for target in &evidence.targets {
            match &target.access {
                None => {}
                Some(ResolutionCompletion::Complete) => {}
                Some(ResolutionCompletion::Incomplete(_)) => {
                    partial.push(JvmPackagePartialReason::QualifiedAccess)
                }
            }
            if target.access.is_some() && !target.export_inventory_complete {
                partial.push(JvmPackagePartialReason::ExportExhaustion);
            }
            if target.incomplete_export {
                partial.push(JvmPackagePartialReason::DeclarationAccess);
            }
        }
        let intrinsic = brokk_bifrost_jvm::intrinsics::language_has_member_inventory(
            Language::Java,
            &format!("{}.{}", evidence.package, evidence.lookup.spelling()),
        );
        classify_jvm_package(JvmPackageClassificationEvidence {
            external_owner: None,
            has_exports: evidence.published_bridge.is_some(),
            selected_package: evidence
                .whole_package_read_exhausted
                .then_some(evidence.whole_package_targets_present.unwrap_or(false)),
            partial,
            intrinsic,
            reserved_jdk_package: reserved_jdk_package(&evidence.package),
            jdk_extraction_selected: self.jdk_declaration_extraction_selected(),
        })
    }

    fn jvm_type_on_demand_import(
        &self,
        prepared: &JvmContextPreparation,
        binder: &ImportBinder,
        member_route_complete: bool,
        bridges: &mut Vec<SelectedRootBridgeDescriptor>,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmTypeOnDemandImportResult>> {
        let context_id = prepared.context_id;
        let source = &prepared.source;
        let source_record = &prepared.source_record;
        let file_version = source_record.file_version_id();
        let source_package = &prepared.source_package;
        let identities = &self.ready.context_identities;
        let SelectedRootPathHalf::Import {
            token,
            anchor,
            anchor_semantic,
            ..
        } = binder.half
        else {
            unreachable!("an import binder has an import half")
        };
        let import_route = binder
            .route
            .as_ref()
            .expect("type on-demand import has a route");
        let import_kind = ResolutionImportRouteKind::TypeOnDemand;
        let mut recipes = binder.recipes.clone();
        let demand_recipe = recipes.pop().expect("one import demand");
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
                selected_name: None,
                language: Language::Java,
            },
            &ResolutionCompletion::Complete,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let published_bridge = package_inventory
            .candidates
            .first()
            .map(|candidate| candidate.bridge.clone());
        bridges.extend(
            package_inventory
                .candidates
                .into_iter()
                .take(1)
                .map(|candidate| candidate.bridge),
        );
        if member_route_complete
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
                identities.record_java_selected_import_proof(
                    source.fragment(),
                    source_site,
                    reason,
                );
            }
        }
        // #8487: the frame also carries name-specific outcomes that the
        // existing complete-inventory retirement cannot establish.
        let SelectedRootPathHalf::Import { identity, .. } = &binder.half else {
            unreachable!("on-demand import retains its selected half")
        };
        let mut evidence = JvmOnDemandPackageEvidence {
            import_identity: *identity,
            import_token: token,
            source_site: import_route.source_site,
            staged: import_route.staged,
            package: recipes
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join("."),
            lookup: demand_recipe,
            whole_package_targets_present: None,
            whole_package_read_exhausted: false,
            named_read_exhausted: true,
            targets: package_inventory.target_evidence,
            published_bridge,
        };
        // #8487 Part 1 has no peer-provider evidence. Keep the
        // acquired-provider route and its reads exactly as before.
        let frame_evidence = if self
            .jvm_external_provider_ids
            .get_or_init(|| self.ready.selected_jvm_external_providers())
            .is_empty()
        {
            let package_targets = self.jvm_import_targets(
                nominal_package_rules(Language::Java)
                    .expect("Java caller has package rules")
                    .own_language_target_mounts(Language::Java),
                &evidence.package,
            )?;
            evidence.whole_package_targets_present = Some(!package_targets.ordered.is_empty());
            evidence.whole_package_read_exhausted = true;
            Some(evidence)
        } else {
            None
        };
        Ok(Some(JvmTypeOnDemandImportResult { frame_evidence }))
    }

    #[allow(clippy::too_many_arguments)]
    fn jvm_single_type_import(
        &self,
        prepared: &JvmContextPreparation,
        binder: &ImportBinder,
        members: Vec<JavaImportMemberCandidate>,
        workspace_type_rows: Vec<(SemanticId, CodeUnit)>,
        member_inventory_complete: bool,
        bridges: &mut Vec<SelectedRootBridgeDescriptor>,
        scoped_gaps: &mut Vec<JvmImportContextGap>,
        cancellation: &CancellationToken,
    ) -> Result<Option<(Option<JvmDeclaredType>, JvmExplicitImportOutcome)>> {
        let mut modeled = None;
        let connection = self.ready.inventory.connection();
        let context_id = prepared.context_id;
        let source = &prepared.source;
        let family = nominal_package_rules(source.semantic_language())
            .expect("caller belongs to a nominal family");
        let source_record = &prepared.source_record;
        let file_version = source_record.file_version_id();
        let source_package = prepared.source_package.clone();
        let identities = self.ready.context_identities.clone();
        let SelectedRootPathHalf::Import {
            token,
            anchor,
            anchor_semantic,
            ..
        } = binder.half
        else {
            unreachable!("an import binder has an import half")
        };
        let import_route = binder
            .route
            .as_ref()
            .expect("single-type import has a route");
        let import_kind = ResolutionImportRouteKind::SingleType;
        let mut recipes = binder.recipes.clone();
        let demand_recipe = recipes.pop().expect("one import demand");
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
                selected_name: None,
                language: Language::Java,
            },
            &ResolutionCompletion::Complete,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut workspace_type_rows = workspace_type_rows;
        workspace_type_rows.extend(
            members
                .iter()
                .filter(|member| member.workspace_source)
                .map(|member| (member.definition, member.unit.clone())),
        );
        workspace_type_rows.extend(package_inventory.workspace_type_rows.iter().cloned());
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
            let record = self.ready.inventory.mount_record_by_ordinal(ordinal)?;
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
            member_inventory_complete && package_inventory.workspace_inventory_complete,
        );
        let mut outcome = JvmExplicitImportOutcome::WorkspaceSource;
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
                        identities.record_java_selected_import_proof(
                            source.fragment(),
                            source_site,
                            reason,
                        );
                    }
                }
                vec![unit]
            }
            JavaSingleTypeImportProof::Open { gap, targets } => {
                if targets.is_empty() {
                    outcome = JvmExplicitImportOutcome::External {
                        fqn: path.join("."),
                        declared: false,
                    };
                }
                if targets.is_empty() && gap == JavaImportSplitGap::MissingDestination {
                    let owner = recipes
                        .iter()
                        .map(ResolutionLookupSemanticRecipe::spelling)
                        .collect::<Vec<_>>()
                        .join(".");
                    let declared = format!("{owner}.{}", demand_recipe.spelling());
                    let mut selected_packages =
                        connection.prepare_cached(family.import_target_mounts().statement)?;
                    let mut selected_packages =
                        selected_packages.query_map([&owner], |row| row.get::<_, u32>(0))?;
                    let package_prefix_found = selected_packages.next().transpose()?.is_some();
                    let declared_type = if package_prefix_found {
                        None
                    } else {
                        self.jvm_declared_type(Language::Java, &declared)?
                    };
                    if let Some(declared_type) = declared_type {
                        // Carry the successful typed proof, including indexed status.
                        // The legacy caller discards it; only the candidate consumes it.
                        outcome = JvmExplicitImportOutcome::External {
                            fqn: declared.clone(),
                            declared: true,
                        };
                        modeled = Some(declared_type.clone());
                        let model_owner = declared_type.owner;
                        let boundary = register_model_declared_jvm_type_identity(
                            self,
                            token,
                            &declared,
                            model_owner.as_ref(),
                            &identities,
                            &self.ready.shared_names(),
                        )?;
                        if let Some(source_site) = import_route.source_site {
                            for reason in selected_java_import_route_gap_reasons(
                                &self.ready.inventory,
                                source_record.blob_id(),
                                source.ordinal(),
                                source_site,
                                import_route.staged,
                            )? {
                                identities.record_java_import_route_gap_reason(reason);
                                identities.record_java_selected_import_proof(
                                    source.fragment(),
                                    source_site,
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
                        let identity =
                            model_declared_jvm_type_identity(&declared, &self.ready.shared_names());
                        identities.record_jvm_unindexed_import_owner(identity, &declared);
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
                .filter(|member| member.workspace_source && targets.contains(&member.unit))
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
        Ok(Some((modeled, outcome)))
    }

    fn jvm_static_import_search_complete(
        &self,
        import_kind: ResolutionImportRouteKind,
        owner_found: bool,
        inventory: &JavaTypeMemberImportInventory,
        demand_recipe: &ResolutionLookupSemanticRecipe,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        Ok(Some(
            if matches!(
                import_kind,
                ResolutionImportRouteKind::SingleStatic | ResolutionImportRouteKind::StaticOnDemand
            ) && owner_found
            {
                let Some(complete) = self.jvm_import_owners_declare_every_member(
                    Language::Java,
                    inventory,
                    demand_recipe.spelling(),
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                complete && inventory.route_search_complete && !inventory.inherited_route_open
            } else {
                false
            },
        ))
    }

    // Scope claims are read later without an alias re-check. Inspect every
    // import that can open this owner before writing any claim, including
    // imports omitted by a named lookup or later in source order.
    fn jvm_owner_global_alias_open(
        &self,
        prepared: &JvmContextPreparation,
        owner: &[ResolutionLookupSemanticRecipe],
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        for binder in &prepared.binders {
            let Some(route) = &binder.route else { continue };
            if route.kind == SelectedImportRouteKind::SingleType {
                // Named static selection can omit this type import, but its open
                // binary owner still vetoes a later member-scope claim.
                let Some((imported, prefix)) = binder.recipes.split_last() else {
                    continue;
                };
                let Some(aliases) = self.jvm_open_owner_alias_imports(
                    Language::Java,
                    prefix,
                    imported.spelling(),
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                let alias_owners = aliases
                    .into_iter()
                    .map(|(owner, _)| owner)
                    .collect::<Vec<_>>();
                if has_open_jvm_alias_for_owner(&alias_owners, &[], owner) {
                    return Ok(Some(true));
                }
                continue;
            }
            let kind = match route.kind {
                SelectedImportRouteKind::SingleStatic => ResolutionImportRouteKind::SingleStatic,
                SelectedImportRouteKind::StaticOnDemand => {
                    ResolutionImportRouteKind::StaticOnDemand
                }
                _ => continue,
            };
            let Some((demand, candidate_owner)) = binder.recipes.split_last() else {
                continue;
            };
            if candidate_owner.len() != owner.len()
                || !candidate_owner
                    .iter()
                    .zip(owner)
                    .all(|(a, b)| a.spelling() == b.spelling())
            {
                continue;
            }
            let SelectedRootPathHalf::Import {
                token,
                anchor,
                anchor_semantic,
                ..
            } = &binder.half
            else {
                continue;
            };
            let import = JavaMemberImportDemand {
                half: &binder.half,
                import_kind: Some(kind),
                caller_package: prepared.source_package.as_deref(),
                source: prepared.source.fragment(),
                token: *token,
                prefix_reference: None,
                scope_head: None,
                anchor: *anchor,
                anchor_semantic: *anchor_semantic,
                selector_kind: None,
                import_precedence: None,
                candidate_origin_rank: None,
                route: candidate_owner,
                lookup_route: candidate_owner,
                demand,
                selected_name: None,
                language: Language::Java,
            };
            let Some(aliases) = self.jvm_alias_import_bridges(
                &import,
                demand.spelling(),
                prepared.source_record.file_version_id(),
                prepared.source.persisted_relative_path(),
                prepared.context_id,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            if !aliases.open_imports.is_empty() || !aliases.coverage_gaps.is_empty() {
                return Ok(Some(true));
            }
        }
        Ok(Some(false))
    }

    fn jvm_open_static_alias_owners(
        &self,
        prepared: &JvmContextPreparation,
        cancellation: &CancellationToken,
    ) -> Result<Option<std::collections::HashSet<Vec<String>>>> {
        let mut checked = std::collections::HashSet::new();
        let mut open = std::collections::HashSet::new();
        for binder in &prepared.binders {
            if !binder.route.as_ref().is_some_and(|route| {
                matches!(
                    route.kind,
                    SelectedImportRouteKind::SingleStatic | SelectedImportRouteKind::StaticOnDemand
                )
            }) {
                continue;
            }
            let Some((_, owner)) = binder.recipes.split_last() else {
                continue;
            };
            let key = owner
                .iter()
                .map(|part| part.spelling().to_owned())
                .collect::<Vec<_>>();
            if !checked.insert(key.clone()) {
                continue;
            }
            let Some(is_open) = self.jvm_owner_global_alias_open(prepared, owner, cancellation)?
            else {
                return Ok(None);
            };
            if is_open {
                open.insert(key);
            }
        }
        Ok(Some(open))
    }

    #[allow(clippy::too_many_arguments)]
    fn jvm_static_import(
        &self,
        prepared: &JvmContextPreparation,
        binder: &ImportBinder,
        member_import: &JavaMemberImportDemand<'_>,
        members: Vec<JavaImportMemberCandidate>,
        owner_found: bool,
        static_search_complete: bool,
        bridges: &mut Vec<SelectedRootBridgeDescriptor>,
        external_static_imports: &mut Vec<JavaExternalStaticImportBoundary>,
        static_import_searches: &mut BTreeMap<
            (Option<ResolutionSiteId>, bool),
            JavaStaticImportSearch,
        >,
        open_jvm_alias_imports: &mut Vec<String>,
        scoped_gaps: &mut Vec<JvmImportContextGap>,
        cancellation: &CancellationToken,
        accumulated_alias_open: bool,
        on_unresolved: impl FnOnce(JvmUnresolvedStaticOwner<'_>) -> Result<()>,
    ) -> Result<Option<()>> {
        let source = &prepared.source;
        let context_id = prepared.context_id;
        let file_version = prepared.source_record.file_version_id();
        let token = member_import.token;
        let import_route = binder.route.as_ref().expect("static import has a route");
        let import_kind = member_import.import_kind.expect("static import has a kind");
        let recipes = member_import.route;
        let demand_recipe = member_import.demand;
        let member = demand_recipe.spelling().to_string();
        let Some(alias_import_bridges) = self.jvm_alias_import_bridges(
            member_import,
            &member,
            file_version,
            source.persisted_relative_path(),
            context_id,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let JvmAliasImportBridges {
            bridges: alias_bridges,
            open_imports: open_aliases,
            found_alias: alias_route_found,
            coverage_gaps,
        } = alias_import_bridges;
        let coverage_start = scoped_gaps.len();
        scoped_gaps.extend(coverage_gaps);
        if !owner_found && !alias_route_found {
            let owner = recipes
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".");
            if !owner.is_empty() {
                on_unresolved(JvmUnresolvedStaticOwner {
                    prepared,
                    binder,
                    owner: &owner,
                    open_aliases: &open_aliases,
                    coverage_gaps: &scoped_gaps[coverage_start..],
                    accumulated_alias_open,
                })?;
                external_static_imports.push(JavaExternalStaticImportBoundary { member, owner });
            }
        }
        let Some(static_members) = self.java_static_import_bridges(members, cancellation)? else {
            return Ok(None);
        };
        let search_complete = static_search_complete
            && open_aliases.is_empty()
            && static_members
                .iter()
                .chain(&alias_bridges)
                .all(|bridge| bridge.completion() == &ResolutionCompletion::Complete);
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
        Ok(Some(()))
    }

    fn jvm_complete_static_imports(
        &self,
        prepared: &JvmContextPreparation,
        static_import_searches: BTreeMap<(Option<ResolutionSiteId>, bool), JavaStaticImportSearch>,
    ) -> Result<()> {
        let source = &prepared.source;
        let source_record = &prepared.source_record;
        let identities = &self.ready.context_identities;
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
                    identities.record_java_selected_import_proof(
                        source.fragment(),
                        source_site,
                        reason,
                    );
                }
            }
        }
        Ok(())
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
    fn jvm_declared_type(&self, language: Language, fqn: &str) -> Result<Option<JvmDeclaredType>> {
        let key = (language, fqn.to_owned());
        if let Some(candidate) = self.jvm_declared_type_memo.borrow().get(&key) {
            return Ok(candidate.clone());
        }
        let candidate = if self.declares_jvm_type(language, fqn)? {
            let owner = self.declared_jvm_owner(language, fqn)?;
            let indexed = match &owner {
                Some(owner) => self.jvm_external_type_is_indexed(owner)?,
                None => false,
            };
            Some(JvmDeclaredType {
                fqn: fqn.to_owned(),
                owner,
                indexed,
            })
        } else {
            None
        };
        self.jvm_declared_type_memo
            .borrow_mut()
            .insert(key, candidate.clone());
        Ok(candidate)
    }

    /// A package host can contain declarations in nested packages. Validate
    /// ownership before letting a current-package bridge outrank a new external
    /// candidate. Both JVM context composers use the same predicate.
    fn jvm_current_package_candidate(
        &self,
        prepared: &JvmContextPreparation,
        lookup: SemanticId,
        definition: SemanticId,
        package: &str,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<bool>> {
        if self
            .jvm_external_provider_ids
            .get_or_init(|| self.ready.selected_jvm_external_providers())
            .is_empty()
        {
            return Ok(SelectedPackageRows::Ready(true));
        }
        let Some(recipe) = prepared.external_providers.recipes.get(&lookup) else {
            return Ok(SelectedPackageRows::Ready(true));
        };
        let mut external_comparison = false;
        for (&(_, candidate_lookup), references) in &prepared.external_providers.references_by_route
        {
            if candidate_lookup != lookup {
                continue;
            }
            for &reference in references {
                let Some(choice) =
                    self.jvm_on_demand_type(prepared, reference, lookup, recipe, cancellation)?
                else {
                    return Ok(SelectedPackageRows::Cancelled);
                };
                if matches!(
                    choice,
                    JvmOnDemandTypeChoice::Indexed(_) | JvmOnDemandTypeChoice::Competing(_)
                ) {
                    external_comparison = true;
                    break;
                }
            }
            if external_comparison {
                break;
            }
        }
        if !external_comparison {
            return Ok(SelectedPackageRows::Ready(true));
        }
        let SelectedPackageRows::Ready(actual_package) =
            self.jvm_declaration_package(definition, cancellation)?
        else {
            return Ok(SelectedPackageRows::Cancelled);
        };
        Ok(SelectedPackageRows::Ready(
            actual_package.as_deref().unwrap_or("") == package,
        ))
    }

    fn jvm_declaration_package(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Option<String>>> {
        let key = (definition, self.ready.inventory.staged_read_epoch());
        if let Some(package) = self.jvm_declaration_package_memo.borrow().get(&key) {
            return Ok(SelectedPackageRows::Ready(package.clone()));
        }
        let Some(endpoints) = self
            .ready
            .typed_source()
            .jvm_access_endpoints(&[definition], cancellation)?
        else {
            return Ok(SelectedPackageRows::Cancelled);
        };
        let package = endpoints.iter().find(|endpoint| endpoint.semantic == definition)
            .ok_or_else(|| StoreError::corrupt(format!(
                "selected JVM package member {definition:?} lacks package metadata in {endpoints:?}"
            )))?.package.clone();
        self.profile_jvm_read("on_demand_source_package", (definition, &package));
        self.jvm_declaration_package_memo
            .borrow_mut()
            .insert(key, package.clone());
        Ok(SelectedPackageRows::Ready(package))
    }

    pub(super) fn jvm_external_type_is_indexed(
        &self,
        owner: &crate::analyzer::resolution::ExternalOwnerIdentity,
    ) -> Result<bool> {
        if let Some(indexed) = self.jvm_indexed_type_memo.borrow().get(owner) {
            return Ok(*indexed);
        }
        let indexed = self
            .ready
            .typed_source()
            .external_owner_type_is_indexed(owner)?;
        self.jvm_indexed_type_memo
            .borrow_mut()
            .insert(owner.clone(), indexed);
        Ok(indexed)
    }

    fn declares_jvm_type(&self, language: Language, fqn: &str) -> Result<bool> {
        if self
            .ready
            .model_authority()
            .is_some_and(|overlay| overlay.declares_jvm_type(fqn))
        {
            return Ok(true);
        }
        // A NULL selected provider is a declaration with ambiguous authority,
        // not absence. Keep it in the on-demand comparison so another package
        // cannot win by dropping this provider.
        Ok(self.jvm_declared_owner_selection(language, fqn)?.is_some()
            || brokk_bifrost_jvm::intrinsics::language_has_member_inventory(language, fqn)
            || fqn.rsplit_once('.').is_some_and(|(package, name)| {
                brokk_bifrost_jvm::intrinsics::compiler_root_owner(language, package, name)
                    .is_some()
            }))
    }

    fn declared_jvm_owner(
        &self,
        language: Language,
        fqn: &str,
    ) -> Result<Option<crate::analyzer::resolution::ExternalOwnerIdentity>> {
        let intrinsic = || {
            (brokk_bifrost_jvm::intrinsics::language_has_member_inventory(language, fqn)
                || fqn.rsplit_once('.').is_some_and(|(package, name)| {
                    brokk_bifrost_jvm::intrinsics::compiler_root_owner(language, package, name)
                        .is_some()
                }))
            .then(|| crate::analyzer::resolution::ExternalOwnerIdentity {
                provider_id: std::sync::Arc::from("jvm-intrinsic"),
                owner_fqn: std::sync::Arc::from(fqn),
            })
        };
        Ok(self
            .jvm_declared_owner_selection(language, fqn)?
            .unwrap_or_else(intrinsic))
    }

    /// Preserve absence, ambiguous authority, and a unique selected owner as
    /// separate results. The selected provider set is immutable for an operation.
    fn jvm_declared_owner_selection(
        &self,
        language: Language,
        fqn: &str,
    ) -> Result<Option<Option<crate::analyzer::resolution::ExternalOwnerIdentity>>> {
        let providers = self
            .jvm_external_provider_ids
            .get_or_init(|| self.ready.selected_jvm_external_providers());
        let key = fqn.to_owned();
        if !providers.is_empty()
            && let Some(owner) = self.jvm_declared_owner_memo.borrow().get(&key)
        {
            return Ok(owner.clone());
        }
        let authority = self.ready.model_authority();
        let relations = nominal_language_rules(language)
            .expect("caller belongs to a nominal family")
            .family()
            .external_owners();
        let owner = super::selected_jvm_declaration_owner(
            relations,
            self.ready.inventory.connection(),
            authority.as_deref(),
            providers,
            fqn,
        )?;
        if !providers.is_empty() {
            self.jvm_declared_owner_memo
                .borrow_mut()
                .insert(key, owner.clone());
        }
        Ok(owner)
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
    let language = operation
        .mount_table()
        .mount_by_ordinal(source)?
        .semantic_language();
    // A language whose types can be called (Kotlin's `ZipInputStream(input)`)
    // also searches a callee's Type namespace. The import binding below proves
    // the callee is the lexical name the import binds, so the callee takes the
    // imported type like any type reference does.
    let callee_names_types = matches!(
        crate::analyzer::resolution::fact_resolution::type_in_call_position(language),
        crate::analyzer::resolution::fact_resolution::TypeInCallPosition::Constructors
            | crate::analyzer::resolution::fact_resolution::TypeInCallPosition::ApplyMembers
    );
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
            if !bindings
                .iter()
                .filter(|other| other.reference == binding.reference)
                .all(|other| {
                    (other.token == binding.token && other.endpoint == binding.endpoint)
                        || super::jvm_demand::jvm_import_binding_shadows(language, binding, other)
                })
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
                (metadata.unqualified()
                    && matches!(
                        metadata.namespace(),
                        ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
                    ))
                    || (metadata.namespace() == ResolutionNamespace::Callable && callee_names_types)
            }) {
                continue;
            }
            // A callee takes the type only from an indexed inventory, which
            // lists the constructors the call applies. A model-declared type
            // without one keeps the callee's import boundary.
            if seed
                .site_metadata()
                .is_some_and(|metadata| metadata.namespace() == ResolutionNamespace::Callable)
                && !route
                    .owner
                    .as_ref()
                    .map(|owner| operation.jvm_external_type_is_indexed(owner))
                    .transpose()?
                    .unwrap_or(false)
            {
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
        && operation.jvm_external_type_is_indexed(owner)?
    {
        identities.record_jvm_provider_type_reference(reference, identity);
        return Ok(None);
    }
    let enumeration_boundary = model_declared_jvm_boundary_id(declared_fqn, owner, identities);
    identities.record_jvm_external_provider_type_identity(
        crate::analyzer::resolution::ExternalOwnerLanguage::Jvm,
        reference,
        enumeration_boundary,
        identity,
        enumeration_boundary,
    );
    Ok(Some(enumeration_boundary))
}

fn model_declared_jvm_boundary_id(
    declared_fqn: &str,
    owner: Option<&crate::analyzer::resolution::ExternalOwnerIdentity>,
    identities: &SelectedContextIdentities,
) -> SemanticId {
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-model-declared-type-boundary:v1");
    hash.field("declared-type-fqn", declared_fqn.as_bytes());
    if let Some(owner) = owner {
        // #7728: equal FQNs from different models are different obligations.
        hash.field("declaring-provider", owner.provider_id.as_bytes());
    }
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
    identities.named_semantic(hash.finish(), kind, &detail)
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

// This memo retains access-filtered, namespace-selected and ranked bridges.
// The JLS proof and scoped continuation therefore keep their exact demands;
// sharing raw inventories would need a separate authority and decoration split.
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
    // A named import can bind a local spelling while reading another member.
    // Reusing a memo hit across those selections would return the wrong bridge.
    selected_name: Option<String>,
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
    export_inventory_complete: bool,
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
                export_inventory_complete: outcome.is_exhausted()
                    && outcome.evidence() == &ResolutionCompletion::Complete,
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
            .bridge(
                identity.fragment(),
                *token,
                self.import.demand.clone(),
                completion,
            )
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
    /// A renamed selector binds `demand` locally but searches this authored member.
    selected_name: Option<&'a str>,
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
            ResolutionNamespace::Type
                | ResolutionNamespace::Value
                | ResolutionNamespace::Callable
                | ResolutionNamespace::Package
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

    fn scala_reference_package_prefixes_with_coverage(
        &self,
        blob: i64,
        reference: ScalaPackageContextReference,
    ) -> Result<Option<Vec<String>>> {
        let connection = self.ready.inventory.connection();
        let site_key = match reference {
            ScalaPackageContextReference::Site(site) => i64::from(site.get()),
            ScalaPackageContextReference::Semantic(semantic) => semantic
                .local_key()
                .expect("selected Scala reference semantic has a local key")
                .into(),
        };
        // A selected blob and exact reference site are the only authority.
        // Absence remains Open; JSON [] is affirmative empty coverage.
        let encoded = connection
            .prepare_cached(
                "SELECT json(context.prefixes)
                 FROM main.resolution_reference_package_contexts AS context
                 JOIN main.resolution_sites AS site
                   ON site.blob_id=context.blob_id AND site.site=context.reference_site
                 WHERE context.blob_id=?1 AND context.reference_site=?2 AND site.role=0",
            )?
            .query_row(rusqlite::params![blob, site_key], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        encoded
            .map(|value| {
                let prefixes = serde_json::from_str::<Vec<String>>(&value).map_err(|error| {
                    StoreError::corrupt(format!(
                        "invalid selected reference package context: {error}"
                    ))
                })?;
                if prefixes
                    .iter()
                    .any(|prefix| prefix.is_empty() || prefix.split('.').any(str::is_empty))
                {
                    return Err(StoreError::corrupt(
                        "selected reference package context has an empty segment",
                    ));
                }
                Ok(prefixes)
            })
            .transpose()
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
            .prepare_cached(
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
            )?
            .query_row(
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
        let proven = self
            .ready
            .inventory
            .connection()
            .prepare_cached(
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
            )?
            .query_row(
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
            selected_name: import.selected_name.map(str::to_owned),
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
                            import.selected_name.unwrap_or(import.demand.spelling()),
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
                                terminal_member_inventory_complete &=
                                    jvm_member_owner_pages_complete(&outcome);
                            }
                            declared_members_complete &= jvm_member_owner_pages_complete(&outcome);
                            if version.is_some() && collect_workspace_type_rows {
                                workspace_inventory_complete &=
                                    jvm_member_owner_pages_complete(&outcome);
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
                                    jvm_member_crosswalk_complete(chunk, &named_keys);
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
                                        .contains(
                                            &import
                                                .selected_name
                                                .unwrap_or(import.demand.spelling()),
                                        )
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
                            let selected_demand = self.jvm_generated_lookup(
                                target_language,
                                import.demand.namespace(),
                                import.selected_name.unwrap_or(import.demand.spelling()),
                            ).recipe.clone();
                            import.bridge(identity.fragment(), token, selected_demand, access)
                        } else {
                            let Some(visibility) = self.jvm_bridge_visibility(
                                member, relation, cancellation,
                            )? else {
                                return Ok(None);
                            };
                            let target_demand = self.jvm_generated_lookup(
                                target_language,
                                import.demand.namespace(),
                                import.selected_name.unwrap_or(import.demand.spelling()),
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
    target_evidence: Vec<JvmOnDemandTargetEvidence>,
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
        target_demand: ResolutionLookupSemanticRecipe,
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
                target_demand,
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
                target_demand,
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
        let mut target_evidence = Vec::new();
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
                target_evidence.push(JvmOnDemandTargetEvidence {
                    mount: ordinal,
                    access: None,
                    export_inventory_complete: false,
                    complete_export: false,
                    incomplete_export: false,
                });
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
            target_evidence.push(JvmOnDemandTargetEvidence {
                mount: ordinal,
                access: Some(source_access.clone()),
                export_inventory_complete: state.export_inventory_complete,
                complete_export: descriptors
                    .iter()
                    .any(|bridge| bridge.completion() == &ResolutionCompletion::Complete),
                incomplete_export: descriptors
                    .iter()
                    .any(|bridge| bridge.completion() != &ResolutionCompletion::Complete),
            });
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
                    target_evidence,
                    candidates,
                    workspace_type_rows,
                    workspace_inventory_complete,
                    route_inventory_complete,
                }));
            }
        }
        Ok(Some(JavaPackageTypeImportInventory {
            target_evidence,
            candidates,
            workspace_type_rows,
            workspace_inventory_complete,
            route_inventory_complete,
        }))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn jvm_lexical_route_head(
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
        // A root-routed reference that keeps lexical lookup heads a lexical
        // route: an import qualifier or an owner-continued term path. Its
        // package reading ranks below every lexical binder.
        Ok(Some(
            rows.iter()
                .filter_map(|row| row.seed())
                .filter_map(|seed| seed.site_metadata())
                .any(|metadata| metadata.unqualified()),
        ))
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

    pub(super) fn common_qualified_type_publication(
        &self,
        language: Language,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let nominal = nominal_language_rules(language).expect("nominal caller");
        assert!(
            nominal
                .family()
                .admits_qualified_type_bridge_source(language)
        );
        if language == Language::Java {
            return self.common_qualified_type_publication_with_rules(
                &JavaJvmImportRules,
                half,
                completion,
                cancellation,
            );
        }
        self.common_qualified_type_publication_with_rules(
            &SelectedJvmImportRules(nominal),
            half,
            completion,
            cancellation,
        )
    }

    fn common_qualified_type_publication_with_rules(
        &self,
        rules: &impl JvmImportAssemblyRules,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let language = rules.nominal().language();
        let SelectedRootPathHalf::Reference {
            source_reference, ..
        } = half
        else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let Some(mut publication) =
            self.jvm_qualified_type_exports(rules, half, completion, cancellation)?
        else {
            return Ok(None);
        };
        if let Some(origin) = jvm_lexical_import_head_origin(language) {
            let Some(import_head) = self.jvm_lexical_route_head(*source_reference, cancellation)?
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
    /// source bridge without both selected rows. Compiler-root declarations
    /// can instead supply their intrinsic owner after source exports lose.
    fn jvm_qualified_type_exports(
        &self,
        rules: &impl JvmImportAssemblyRules,
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
            return self.jvm_qualified_type_exports_for_route(
                rules,
                half,
                completion,
                None,
                cancellation,
            );
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
        let Some(endpoints) = self.jvm_endpoint_classifications(*source_reference, cancellation)?
        else {
            return Ok(None);
        };
        let source_semantic = endpoints
            .iter()
            .find(|row| row.node() == *source_reference)
            .and_then(|row| row.reference());
        let Some(prefixes) = source_semantic
            .map(|semantic| {
                self.scala_reference_package_prefixes_with_coverage(
                    record.blob_id(),
                    ScalaPackageContextReference::Semantic(semantic),
                )
            })
            .transpose()?
            .flatten()
        else {
            return Ok(Some(JvmRoutePublication {
                bridges: Vec::new(),
                selected_targets: BTreeSet::new(),
                complete: false,
            }));
        };
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
                rules,
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
        rules: &impl JvmImportAssemblyRules,
        half: &SelectedRootPathHalf,
        completion: &ResolutionCompletion,
        lookup_route: Option<&[ResolutionLookupSemanticRecipe]>,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let SelectedRootPathHalf::Reference {
            identity,
            prefix_reference,
            source_scope_head,
            token,
            anchor,
            anchor_semantic,
            ..
        } = half
        else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let Some(input) = self.jvm_qualified_publication_input(half, cancellation)? else {
            return Ok(None);
        };
        let language = rules.nominal().language();
        debug_assert_eq!(language, input.source_language);
        let Some(package) = self.jvm_qualified_package_publication(
            rules,
            &input,
            completion,
            lookup_route,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let publication = match package {
            std::ops::ControlFlow::Break(mut publication) => {
                rules.finalize_qualified_publication(&mut publication);
                return Ok(Some(publication));
            }
            std::ops::ControlFlow::Continue(publication) => publication,
        };
        let JvmQualifiedPublicationInput {
            source_language,
            source_record,
            context,
            caller_package,
            recipes,
            source_demand,
            ..
        } = &input;
        let source_language = *source_language;
        let context = *context;
        let family = nominal_language_rules(source_language)
            .expect("caller belongs to a nominal family")
            .family();
        let lookup_route = lookup_route.unwrap_or(recipes);
        let JvmRoutePublication {
            mut bridges,
            mut selected_targets,
            complete: mut route_complete,
        } = publication;
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
                scope_head: rules.qualified_member_scope(*source_scope_head),
                anchor: *anchor,
                anchor_semantic: *anchor_semantic,
                selector_kind: None,
                import_precedence: None,
                candidate_origin_rank: None,
                route: recipes,
                lookup_route,
                demand: source_demand,
                selected_name: None,
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
        let mut publication = JvmRoutePublication {
            bridges,
            selected_targets,
            complete: route_complete,
        };
        rules.finalize_qualified_publication(&mut publication);
        Ok((!cancellation.is_cancelled()).then_some(publication))
    }

    fn jvm_qualified_publication_input<'a>(
        &self,
        half: &'a SelectedRootPathHalf,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmQualifiedPublicationInput<'a>>> {
        let SelectedRootPathHalf::Reference {
            identity,
            route,
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
        assert!(family.admits(source_language));
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source_mount.ordinal())?;
        let connection = self.ready.inventory.connection();
        let context = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row([source_language.config_label()], |row| row.get::<_, i64>(0))?;
        let caller_package: Option<String> = connection
            .prepare_cached(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
            )?
            .query_row([source_record.blob_id()], |row| row.get(0))
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
        Ok(Some(JvmQualifiedPublicationInput {
            half,
            source_language,
            source_record,
            context,
            caller_package,
            recipes,
            source_demand,
        }))
    }

    fn jvm_qualified_package_publication(
        &self,
        rules: &impl JvmImportAssemblyRules,
        input: &JvmQualifiedPublicationInput<'_>,
        completion: &ResolutionCompletion,
        lookup_route: Option<&[ResolutionLookupSemanticRecipe]>,
        cancellation: &CancellationToken,
    ) -> Result<Option<std::ops::ControlFlow<JvmRoutePublication, JvmRoutePublication>>> {
        let SelectedRootPathHalf::Reference {
            identity,
            prefix_reference,
            source_scope_head,
            source_reference,
            token,
            anchor,
            anchor_semantic,
            ..
        } = input.half
        else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let JvmQualifiedPublicationInput {
            source_language,
            source_record,
            context,
            caller_package,
            recipes,
            source_demand,
            ..
        } = input;
        let source_language = *source_language;
        let context = *context;
        let family = nominal_language_rules(source_language)
            .expect("caller belongs to a nominal family")
            .family();
        let source_namespace = source_demand.namespace();
        if !matches!(
            source_namespace,
            ResolutionNamespace::Type | ResolutionNamespace::Value
        ) {
            return Ok(Some(std::ops::ControlFlow::Break(JvmRoutePublication {
                bridges: Vec::new(),
                selected_targets: BTreeSet::new(),
                complete: false,
            })));
        }
        assert_eq!(
            source_demand.identity_domain(),
            language_identity_domain(source_language)
        );
        let lookup_route = lookup_route.unwrap_or(recipes);
        let package = if lookup_route.is_empty() {
            let Some(package) = rules.qualified_empty_route_package(caller_package.as_deref())
            else {
                return Ok(Some(std::ops::ControlFlow::Break(JvmRoutePublication {
                    bridges: Vec::new(),
                    selected_targets: BTreeSet::new(),
                    complete: false,
                })));
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
        let targets = self.jvm_import_targets(rules.qualified_package_mounts(), &package)?;
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
        Ok(Some(std::ops::ControlFlow::Continue(JvmRoutePublication {
            bridges,
            selected_targets,
            complete: route_complete,
        })))
    }
}

// Read once before source polling. Reconstructing a half view after a wait
// only borrows these facts; it must not repeat caller/context SQL.
pub(super) struct JvmSourceReaderContext {
    pub language: Language,
    pub source_reference: BindingNodeId,
    pub package: Option<String>,
    pub source_package: Option<String>,
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
    pub(super) fn jvm_source_prefix_namespace(
        &self,
        half: &SelectedRootPathHalf,
    ) -> Result<Option<ResolutionNamespace>> {
        Ok(
            matches!(half, SelectedRootPathHalf::Reference { source_origin, .. }
            if source_origin.role == Some(0) && source_origin.site_kind.is_none())
            .then_some(ResolutionNamespace::Package),
        )
    }

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
            .prepare_cached(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
            )?
            .query_row([record.blob_id()], |row| row.get::<_, Option<String>>(0))
            .optional()?
            .flatten();
        let source_package = nominal_language_rules(mount.semantic_language())
            .expect("caller belongs to a nominal family")
            .lexical_package(self, record.blob_id())?
            .or(package.clone());
        if let SelectedRootPathHalf::Import { token, .. } = half {
            package = nominal_language_rules(mount.semantic_language())
                .expect("caller belongs to a nominal family")
                .lexical_import_package_prefixes(self, record.blob_id(), *token)?
                .pop()
                .or(package);
        }
        Ok(JvmSourceReaderContext {
            source_package,
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
        route: &super::demand_closure::MemberRouteContext<'_, ()>,
        lookup: &ResolutionLookupSemanticRecipe,
        occurrence: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmSourceMemberRows>> {
        use crate::analyzer::resolution::{
            HierarchyProviderAuthority, HierarchyProviderKey, HierarchyProviderObservation,
            HierarchyProviderOperand, HierarchyProviderVisit,
        };
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

    fn jvm_member_route_namespace(
        &self,
        language: Language,
        route: &super::demand_closure::MemberRouteContext<'_, ()>,
    ) -> ResolutionNamespace {
        let rules = nominal_language_rules(language).expect("caller belongs to a nominal family");
        if route.position == super::demand_closure::MemberRoutePosition::Segment {
            rules.intermediate_member_namespace(route.namespace)
        } else {
            route.namespace
        }
    }

    /// Whether a member-owner row answers this route's lookup: its kind and
    /// spelling match, and a Scala value or callable route names an object,
    /// never a class, through a nested type.
    pub(super) fn jvm_member_row_selected(
        &self,
        language: Language,
        route: &super::demand_closure::MemberRouteContext<'_, ()>,
        lookup: &ResolutionLookupSemanticRecipe,
        row: &crate::analyzer::resolution::LoweredMemberOwnerProperty,
    ) -> Result<bool> {
        let rules = nominal_language_rules(language).expect("caller belongs to a nominal family");
        let namespace = self.jvm_member_route_namespace(language, route);
        if !jvm_member_kind_matches(language, namespace, row.kind())
            || !jvm_member_name_matches(language, row.member_name(), lookup.spelling())
        {
            return Ok(false);
        }
        Ok(!(rules.has_singleton_import_values()
            && matches!(
                namespace,
                ResolutionNamespace::Value | ResolutionNamespace::Callable
            )
            && row.kind() == ResolutionMemberKind::NestedType
            && !self.jvm_scala_object_definition(row.definition())?))
    }

    pub(super) fn jvm_source_member_target(
        &self,
        source: &super::demand_closure::SourceHalf,
        reader: &JvmSourceReaderContext,
        route: &super::demand_closure::MemberRouteContext<'_, ()>,
        lookup: &ResolutionLookupSemanticRecipe,
        row: &crate::analyzer::resolution::LoweredMemberOwnerProperty,
        cancellation: &CancellationToken,
    ) -> Result<super::demand_closure::Read<Option<super::demand_closure::SelectedMemberRouteTarget>>>
    {
        use super::demand_closure::{
            BridgeMaterial, Read, RouteLocation, SelectedMemberRouteTarget, SelectedMemberTarget,
        };
        let completion = &route.selection.completion;
        let language = reader.language;
        let rules = nominal_language_rules(language).expect("caller belongs to a nominal family");
        let family = rules.family();
        let namespace = self.jvm_member_route_namespace(language, route);
        if !self.jvm_member_row_selected(language, route, lookup, row)? {
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
            .prepare_cached(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
            )?
            .query_row([target_record.blob_id()], |row| row.get(0))
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

#[derive(Debug)]
pub(super) enum JvmPackagePartialReason {
    UnknownUnitPackage,
    MissingMemberInventory,
    IncomingCompletion,
    FamilyAdmission,
    QualifiedAccess,
    ExportExhaustion,
    ExportEvidence,
    DeclarationAccess,
    ResultBound,
    UnpublishedMembers,
}

#[derive(Debug)]
pub(super) enum JvmPackageOutcome {
    Exports {
        partial: Vec<JvmPackagePartialReason>,
    },
    ExternalOwner {
        owner: SemanticId,
        authority: super::demand_closure::OwnerAuthority,
        completion: ResolutionCompletion,
    },
    ProvenEmpty,
    Intrinsic,
    Partial(Vec<JvmPackagePartialReason>),
    Unacquired,
}

// Classification consumes selected facts only; callers own all SQL reads.
// An unread package inventory is never proof that a name is absent.
pub(super) struct JvmPackageClassificationEvidence {
    pub(super) external_owner: Option<(SemanticId, super::demand_closure::OwnerAuthority)>,
    pub(super) has_exports: bool,
    pub(super) selected_package: Option<bool>,
    pub(super) partial: Vec<JvmPackagePartialReason>,
    pub(super) intrinsic: bool,
    pub(super) reserved_jdk_package: bool,
    pub(super) jdk_extraction_selected: bool,
}

/// Only `java.*` is reserved to the platform: the JVM refuses to define a
/// class there from any loader but the boot loader, so no library, Kotlin
/// facade or Scala package object can add to these packages.
fn reserved_jdk_package(package: &str) -> bool {
    package == "java" || package.starts_with("java.")
}

impl SelectedResolutionOperation<'_, '_> {
    /// A reviewed JDK model with a few declaration facts is not an acquired
    /// JDK inventory; an extraction-backed declaration shard is required to
    /// prove absence in a reserved package.
    fn jdk_declaration_extraction_selected(&self) -> bool {
        self.ready
            .model_authority()
            .as_ref()
            .and_then(|authority| authority.active_models())
            .is_some_and(|models| jdk_declaration_extraction_selected(&models))
    }
}

/// Whether selected declaration facts include an extraction-backed JDK inventory.
pub fn jdk_declaration_extraction_selected(
    models: &crate::analyzer::store::active_models::ResolvedActiveSemanticModels,
) -> bool {
    models.shards().iter().any(|shard| {
        shard.manifest.ecosystem == "jdk"
            && shard.extraction().is_some_and(|extraction| {
                matches!(
                    extraction.kind,
                    crate::analyzer::semantic_model::ArtifactExtractionKind::JdkSourceZip
                        | crate::analyzer::semantic_model::ArtifactExtractionKind::JdkJmodSet
                )
            })
            && shard.descriptor.payload_kind
                == crate::analyzer::semantic_model::PayloadKind::DeclarationFacts
    })
}

pub(super) fn classify_jvm_package(
    evidence: JvmPackageClassificationEvidence,
) -> JvmPackageOutcome {
    let JvmPackageClassificationEvidence {
        external_owner,
        has_exports,
        selected_package,
        mut partial,
        intrinsic,
        reserved_jdk_package,
        jdk_extraction_selected,
    } = evidence;
    if let Some((owner, authority)) = external_owner {
        JvmPackageOutcome::ExternalOwner {
            owner,
            authority,
            completion: ResolutionCompletion::Complete,
        }
    } else if has_exports {
        partial.retain(|reason| !matches!(reason, JvmPackagePartialReason::IncomingCompletion));
        JvmPackageOutcome::Exports { partial }
    } else if selected_package == Some(true) {
        if partial.is_empty() {
            JvmPackageOutcome::ProvenEmpty
        } else {
            JvmPackageOutcome::Partial(partial)
        }
    } else if selected_package.is_none() {
        partial.push(JvmPackagePartialReason::ExportExhaustion);
        JvmPackageOutcome::Partial(partial)
    } else if intrinsic {
        JvmPackageOutcome::Intrinsic
    } else if reserved_jdk_package && jdk_extraction_selected {
        JvmPackageOutcome::ProvenEmpty
    } else {
        JvmPackageOutcome::Unacquired
    }
}

fn root_type_visibility_outcome(
    visibility: super::nominal_rules::RootTypeVisibility,
) -> Option<JvmPackageOutcome> {
    use super::nominal_rules::RootTypeVisibility;
    match visibility {
        RootTypeVisibility::Visible => None,
        RootTypeVisibility::Hidden => Some(JvmPackageOutcome::ProvenEmpty),
        RootTypeVisibility::Unknown => Some(JvmPackageOutcome::Partial(vec![
            JvmPackagePartialReason::UnknownUnitPackage,
        ])),
    }
}

pub(super) struct JvmPurePackageRows {
    pub exports: Vec<JvmPurePackageExport>,
    pub outcome: JvmPackageOutcome,
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
        // Root Type obscuring is a source-unit rule, including terminal reads
        // of a positioned first segment. Imports have their own visibility rules.
        if !source.is_import
            && package.is_empty()
            && requested.namespace() == ResolutionNamespace::Type
            && let Some(outcome) = root_type_visibility_outcome(
                nominal_language_rules(reader.language)
                    .expect("nominal caller")
                    .unnamed_package_types_visible(reader.source_package.as_deref()),
            )
        {
            return Ok(Some(JvmPurePackageRows {
                exports: Vec::new(),
                outcome,
                observations: Vec::new(),
            }));
        }
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
        let mut partial = Vec::new();
        if !rules.has_package_member_inventory() {
            partial.push(JvmPackagePartialReason::MissingMemberInventory);
        }
        if completion != &ResolutionCompletion::Complete {
            partial.push(JvmPackagePartialReason::IncomingCompletion);
        }
        for (ordinal, version) in targets.ordered.iter().copied() {
            let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
            let mount = self.mount_table().mount_by_ordinal(ordinal)?;
            let target_language = mount.semantic_language();
            if !family.admits(target_language) {
                partial.push(JvmPackagePartialReason::FamilyAdmission);
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
                partial.push(JvmPackagePartialReason::QualifiedAccess);
                continue;
            };
            if access != ResolutionCompletion::Complete {
                partial.push(JvmPackagePartialReason::QualifiedAccess);
            }
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
            if !exports.outcome.is_exhausted() {
                partial.push(JvmPackagePartialReason::ExportExhaustion);
            }
            if exports.outcome.evidence() != &ResolutionCompletion::Complete {
                partial.push(JvmPackagePartialReason::ExportEvidence);
            }
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
                if evidence != ResolutionCompletion::Complete {
                    partial.push(JvmPackagePartialReason::DeclarationAccess);
                }
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
                            outcome: JvmPackageOutcome::Exports {
                                partial: {
                                    partial.push(JvmPackagePartialReason::ResultBound);
                                    partial.retain(|reason| {
                                        !matches!(
                                            reason,
                                            JvmPackagePartialReason::IncomingCompletion
                                        )
                                    });
                                    partial
                                },
                            },
                            exports: result,
                            observations,
                        }),
                    );
                }
            }
            if !matching.is_subset(&published) {
                partial.push(JvmPackagePartialReason::UnpublishedMembers);
            }
        }
        let mut external_owner = None;
        if result.is_empty() && requested.namespace() == ResolutionNamespace::Type {
            let fqn = if package.is_empty() {
                requested.spelling().to_owned()
            } else {
                format!("{package}.{}", requested.spelling())
            };
            // Intrinsic inventories prove name absence, not an external
            // declaration or a member-continuation owner. Compiler declarations
            // have separate positive authority. A compiler root supplies a Type
            // declaration only; its members still use the existing intrinsic
            // inventory and hierarchy evidence, without new absence authority.
            // Preserve the ordinary
            // language route for them (including Kotlin companions and objects).
            if let Some(owner) = self
                .declared_jvm_owner(source_language, &fqn)?
                .filter(|owner| {
                    owner.provider_id.as_ref() != "jvm-intrinsic"
                        || brokk_bifrost_jvm::intrinsics::compiler_root_owner(
                            source_language,
                            package,
                            requested.spelling(),
                        )
                        .is_some()
                })
            {
                let identities = &self.ready.context_identities;
                external_owner = Some((
                    identities.external_owner_semantic(&owner, &names),
                    if owner.provider_id.as_ref() == "jvm-intrinsic" {
                        super::demand_closure::OwnerAuthority::LanguageRoot
                    } else {
                        super::demand_closure::OwnerAuthority::Declaration
                    },
                ));
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
            }
        }
        let needs_absence_classification =
            external_owner.is_none() && result.is_empty() && targets.ordered.is_empty();
        let intrinsic = needs_absence_classification
            && brokk_bifrost_jvm::intrinsics::language_has_member_inventory(
                source_language,
                &format!("{package}.{}", requested.spelling()),
            );
        let jdk_extraction_selected = needs_absence_classification
            && !intrinsic
            && self.jdk_declaration_extraction_selected();
        let outcome = classify_jvm_package(JvmPackageClassificationEvidence {
            external_owner,
            has_exports: !result.is_empty(),
            selected_package: Some(!targets.ordered.is_empty()),
            partial,
            intrinsic,
            reserved_jdk_package: reserved_jdk_package(package),
            jdk_extraction_selected,
        });
        Ok(
            (!cancellation.is_cancelled()).then_some(JvmPurePackageRows {
                exports: result,
                outcome,
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
        // External providers are immutable for the operation. Their exact
        // owner and inventory reads survive changes to staged source facts.
        self.jvm_on_demand_type_ranks.replace(Default::default());
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
mod inherited_decision_tests {
    use super::*;

    #[test]
    fn language_hook_preserves_only_proved_local_dominance() {
        for language in [Language::Kotlin, Language::Scala] {
            assert!(!jvm_inherited_competes(
                language,
                LexicalTypeLevel::Local,
                0
            ));
            for lexical in [
                LexicalTypeLevel::Declared(0),
                LexicalTypeLevel::Outside(0),
                LexicalTypeLevel::Unit,
            ] {
                assert!(jvm_inherited_competes(language, lexical, 0));
            }
        }
        assert!(!jvm_inherited_competes(
            Language::Java,
            LexicalTypeLevel::Declared(0),
            0
        ));
        assert!(jvm_inherited_competes(
            Language::Java,
            LexicalTypeLevel::Outside(0),
            0
        ));
    }

    fn closed(candidates: Vec<JvmTypeNameAlternative>) -> TierContributor<JvmTypeNameAlternative> {
        TierContributor {
            candidates,
            closure: ContributorClosure::Closed(TierReceipt {
                selected_read: "selected-test-facts",
            }),
        }
    }

    fn tier(
        rank: u32,
        candidates: Vec<JvmTypeNameAlternative>,
    ) -> TierInput<JvmTypeNameAlternative> {
        TierInput {
            rank,
            contributors: vec![closed(candidates)],
        }
    }

    fn decision(
        tiers: Vec<TierInput<JvmTypeNameAlternative>>,
        lower: JvmOnDemandTypeChoice,
        inherited: bool,
    ) -> JvmSimpleTypeNameDecision {
        let open_rank = inherited
            .then(|| {
                tiers
                    .iter()
                    .filter(|tier| {
                        tier.contributors
                            .iter()
                            .any(|c| matches!(c.closure, ContributorClosure::Open))
                    })
                    .map(|tier| tier.rank)
                    .min()
            })
            .flatten();
        JvmSimpleTypeNameDecision::from_tiers(
            SemanticId::for_test("name"),
            tiers,
            20,
            JvmOnDemandObservation::searched(lower),
            inherited,
            open_rank,
        )
    }

    fn intrinsic(name: &str) -> JvmOnDemandTypeChoice {
        JvmOnDemandTypeChoice::Intrinsic(JvmOnDemandType {
            declared: JvmDeclaredType {
                fqn: name.to_owned(),
                owner: None,
                indexed: false,
            },
            precedence: super::super::jvm_demand::JvmBindingPrecedence { rank: 0, depth: 0 },
            package: "java.lang".to_owned(),
            source: None,
        })
    }

    #[test]
    fn unsearched_on_demand_does_not_open_closed_inheritance() {
        let observed = JvmOnDemandObservation {
            unsearched: true,
            ..JvmOnDemandObservation::searched(JvmOnDemandTypeChoice::Unavailable)
        };
        let closed = JvmSimpleTypeNameDecision::from_tiers(
            SemanticId::for_test("name"),
            vec![jvm_inherited_tier(1, InheritedTierWitness::Absent)],
            20,
            observed,
            true,
            None,
        );
        assert!(matches!(closed.decision, TierDecision::Open { .. }));
        assert_eq!(closed.inherited_lexical_gap(), None);

        let open = JvmSimpleTypeNameDecision::from_tiers(
            SemanticId::for_test("name"),
            vec![jvm_inherited_tier(
                1,
                InheritedTierWitness::Open {
                    frontier: Vec::new(),
                    reasons: vec!["unresolved-supertype"],
                },
            )],
            20,
            JvmOnDemandObservation {
                unsearched: true,
                ..JvmOnDemandObservation::searched(JvmOnDemandTypeChoice::Unavailable)
            },
            true,
            Some(1),
        );
        assert_eq!(
            open.inherited_lexical_gap(),
            Some("jvm-inherited-member-type-open")
        );
    }

    #[test]
    fn open_inheritance_makes_default_import_possible() {
        let inherited = jvm_inherited_tier(
            1,
            InheritedTierWitness::Open {
                frontier: Vec::new(),
                reasons: vec!["unresolved-supertype"],
            },
        );
        let answer = decision(
            vec![tier(0, Vec::new()), inherited],
            intrinsic("java.lang.Exception"),
            true,
        );
        assert!(matches!(answer.decision, TierDecision::Open { .. }));
        assert!(matches!(
            answer.on_demand_choice(),
            JvmOnDemandTypeChoice::Possible(_)
        ));
        let legacy = decision(
            vec![tier(0, Vec::new())],
            intrinsic("java.lang.Exception"),
            false,
        );
        assert!(matches!(
            legacy.on_demand_choice(),
            JvmOnDemandTypeChoice::Intrinsic(_)
        ));
    }

    #[test]
    fn inherited_member_precedes_import_and_outer_lexical_type() {
        let member = SemanticId::for_test("Base.T");
        let outer = SemanticId::for_test("Outer.T");
        let imported = SemanticId::for_test("import T");
        let inherited = jvm_inherited_tier(2, InheritedTierWitness::Proven(vec![member]));
        let lower = vec![
            tier(0, Vec::new()),
            inherited,
            tier(3, vec![JvmTypeNameAlternative::PlacedLexical(outer)]),
            tier(4, vec![JvmTypeNameAlternative::ExplicitImport(imported)]),
        ];
        let answer = decision(lower, intrinsic("java.lang.T"), true);
        assert!(
            matches!(answer.decision, TierDecision::Unique { selected: JvmTypeNameAlternative::InheritedMember(id), .. } if id == member)
        );
        assert_eq!(
            answer.inherited_lexical_gap(),
            Some("jvm-inherited-member-type-competing")
        );
        assert!(matches!(
            answer.on_demand_choice(),
            JvmOnDemandTypeChoice::Unavailable
        ));

        let absent = decision(
            vec![
                tier(3, vec![JvmTypeNameAlternative::PlacedLexical(outer)]),
                jvm_inherited_tier(2, InheritedTierWitness::Absent),
            ],
            JvmOnDemandTypeChoice::Unavailable,
            true,
        );
        assert!(
            matches!(absent.decision, TierDecision::Unique { selected: JvmTypeNameAlternative::PlacedLexical(id), .. } if id == outer)
        );
        let open = decision(
            vec![
                tier(3, vec![JvmTypeNameAlternative::PlacedLexical(outer)]),
                jvm_inherited_tier(
                    2,
                    InheritedTierWitness::Open {
                        frontier: Vec::new(),
                        reasons: vec!["unresolved-supertype"],
                    },
                ),
            ],
            JvmOnDemandTypeChoice::Unavailable,
            true,
        );
        assert!(matches!(open.decision, TierDecision::Open { .. }));
        assert_eq!(
            open.inherited_lexical_gap(),
            Some("jvm-inherited-member-type-open")
        );
    }

    /// JLS 7.5.1 ignores a unit's single-type import of a type it declares,
    /// and an import token does not identify its declaration, so the tier
    /// builder leaves that import contributor open and the unit tier is
    /// undecided. Two closed identities in one tier still conflict.
    #[test]
    fn a_same_unit_type_and_its_import_stay_open_and_distinct_identities_conflict() {
        let local = SemanticId::for_test("local T");
        let imported = SemanticId::for_test("import T");
        let self_import = decision(
            vec![TierInput {
                rank: 4,
                contributors: vec![
                    closed(vec![JvmTypeNameAlternative::PlacedLexical(local)]),
                    TierContributor {
                        candidates: vec![JvmTypeNameAlternative::ExplicitImport(imported)],
                        closure: ContributorClosure::Open,
                    },
                ],
            }],
            JvmOnDemandTypeChoice::Unavailable,
            true,
        );
        assert!(matches!(self_import.decision, TierDecision::Open { .. }));
        let conflict = decision(
            vec![tier(
                4,
                vec![
                    JvmTypeNameAlternative::PlacedLexical(local),
                    JvmTypeNameAlternative::ExplicitImport(imported),
                ],
            )],
            JvmOnDemandTypeChoice::Unavailable,
            true,
        );
        assert!(
            matches!(conflict.decision, TierDecision::Ambiguous { ref candidates, .. } if candidates.len() == 2)
        );
    }

    #[test]
    fn inherited_member_precedes_class_type_parameter() {
        let member = SemanticId::for_test("Base.T");
        let parameter = SemanticId::for_test("C.T");
        let parameter_tier = tier(3, vec![JvmTypeNameAlternative::PlacedLexical(parameter)]);
        let answer = decision(
            vec![
                jvm_inherited_tier(2, InheritedTierWitness::Proven(vec![member])),
                parameter_tier.clone(),
            ],
            JvmOnDemandTypeChoice::Unavailable,
            true,
        );
        assert!(
            matches!(answer.decision, TierDecision::Unique { selected: JvmTypeNameAlternative::InheritedMember(id), .. } if id == member)
        );
        let absent = decision(
            vec![
                jvm_inherited_tier(2, InheritedTierWitness::Absent),
                parameter_tier,
            ],
            JvmOnDemandTypeChoice::Unavailable,
            true,
        );
        assert!(
            matches!(absent.decision, TierDecision::Unique { selected: JvmTypeNameAlternative::PlacedLexical(id), .. } if id == parameter)
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nested_static_owner_observes_preceding_binary_alias() {
        let recipes = ["p", "Outer", "Inner"]
            .into_iter()
            .map(|name| {
                super::ResolutionLookupSemanticRecipe::new(
                    crate::analyzer::Language::Java,
                    ResolutionNamespace::Type,
                    name,
                )
            })
            .collect::<Vec<_>>();
        let preceding_alias = vec!["p.Outer$Inner.foo".to_owned()];
        assert!(super::has_open_jvm_alias_for_owner(
            &preceding_alias,
            &[],
            &recipes,
        ));
        assert!(super::has_open_jvm_alias_for_owner(
            &["p.Outer.foo".to_owned()],
            &[],
            &recipes[..2],
        ));
        assert!(!super::has_open_jvm_alias_for_owner(
            &["routecontrol.RouteControl.routeControl".to_owned()],
            &[],
            &recipes,
        ));
    }
    #[test]
    fn model_declared_type_boundaries_retain_distinct_provider_identities() {
        use crate::analyzer::resolution::ExternalOwnerIdentity;
        let identities = SelectedContextIdentities::new();
        let owners = ["model-a", "model-b"].map(|provider| ExternalOwnerIdentity {
            provider_id: Arc::from(provider),
            owner_fqn: Arc::from("java.lang.Class"),
        });
        let boundaries: Vec<_> = owners
            .iter()
            .map(|owner| {
                model_declared_jvm_boundary_id("java.lang.Class", Some(owner), &identities)
            })
            .collect();
        assert_ne!(boundaries[0], boundaries[1]);
    }

    #[test]
    fn unknown_unit_package_cannot_prove_root_type_visibility() {
        for language in [super::Language::Java, super::Language::Scala] {
            let rules = super::nominal_language_rules(language).unwrap();
            assert!(
                matches!(super::root_type_visibility_outcome(rules.unnamed_package_types_visible(None)),
                Some(super::JvmPackageOutcome::Partial(reasons)) if matches!(reasons.as_slice(), [super::JvmPackagePartialReason::UnknownUnitPackage]))
            );
            assert!(
                super::root_type_visibility_outcome(rules.unnamed_package_types_visible(Some("")))
                    .is_none()
            );
            assert!(matches!(
                super::root_type_visibility_outcome(
                    rules.unnamed_package_types_visible(Some("app"))
                ),
                Some(super::JvmPackageOutcome::ProvenEmpty)
            ));
        }
    }

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
            external_member_targets: Vec::new(),
            pack_completion: ResolutionCompletion::Complete,
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
