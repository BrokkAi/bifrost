//! Demand-local JVM import composition over exact selected source publications.
//!
//! This is one caller's query. Package and root membership stay in SQLite; the source
//! halves, candidate export halves and compiled bridges die with the query.

use super::package_context::{SelectedPackageRows, unique_package_references_by_token};
use super::*;
use crate::analyzer::resolution::{
    BatchEndpointClassification, BindingOrigin, CanonicalIdentityDescriptor, CanonicalIdentityPart,
    FactPageVisitor, FactReadOutcome, JvmImplicitRootProvider, LoweredPackageMember,
    PrecedenceStep, ResolutionIdentityDigestKey, SelectedJvmBridgeEvidence,
    SelectedJvmBridgeProvenance, SelectedJvmBridgeVisibility, SelectedPackageBridgeDescriptor,
    SelectedResolutionMountContext, SelectedRootBridgeDescriptor, SelectedRootPathHalf,
    SharedNameInterner, binding_origin_rank, language_callables_occupy_value_namespace,
    language_implicit_root_member_names, language_implicit_root_providers,
    language_import_owner_steps_bind_singletons, language_jvm_declaration_access_rules,
    language_jvm_package_requires_directory_agreement, package_domain_semantic,
    selected_identity_content_digest, visit_selected_root_export_half_pages,
    visit_selected_root_import_half_pages,
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
use std::sync::Arc;

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
pub(super) struct JvmContextReadProfile {
    calls: HashMap<(&'static str, String), u64>,
}

#[cfg(test)]
impl JvmContextReadProfile {
    pub(super) fn calls(&self, kind: &str) -> u64 {
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
}

// The mount language remains part of every candidate row. Package equality
// narrows the selected inventory; it does not erase language identity.
pub(super) const JVM_IMPORT_TARGET_MOUNTS: &str = r#"
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

pub(in crate::analyzer::store) const SELECTED_IMPORT_SELECTOR: &str = r#"
SELECT selector.kind, selector.source_name, selector.local_name
FROM main.resolution_semantic_catalog AS catalog
JOIN main.resolution_import_selectors AS selector
  ON selector.blob_id=catalog.blob_id AND selector.site=catalog.import_source_site
WHERE catalog.blob_id=?1 AND catalog.local_key=?2
  AND catalog.import_source_site IS NOT NULL
"#;

// Alias candidates are read for one exact selected blob. The alias table's
// (blob_id, alias) primary key bounds the read to that fragment before the
// imported JVM spelling is compared.
pub(in crate::analyzer::store) const SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER: &str = r#"
SELECT alias.alias, alias.declaration_site, alias.status,
       declaration.semantic_key, alias.kind
FROM main.resolution_jvm_aliases AS alias
JOIN main.resolution_semantic_sites AS declaration
  ON declaration.blob_id=alias.blob_id
 AND declaration.source_site=alias.declaration_site
 AND declaration.semantic_role='definition'
WHERE alias.blob_id=?1 AND alias.member_name=?2
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
pub(in crate::analyzer::store) const SOURCE_ACCESS: &str = r#"
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
pub(super) type JvmFileContextMemo =
    ExactReadMemo<(Language, String, [u8; 32], (u64, u64)), JvmImportContext>;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmSourceAccessKey {
    context: i64,
    caller: Option<i64>,
    caller_path: String,
    target: Option<i64>,
    target_path: String,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

/// Source visibility is independent of each route's incoming completion.
/// Retain its evidence and combine that completion separately on every use.
#[derive(Clone, Copy)]
pub(super) enum JvmSourceAccessEvidence {
    Excluded,
    Known,
    Unknown(SemanticId),
}

pub(super) type JvmSourceAccessMemo = ExactReadMemo<JvmSourceAccessKey, JvmSourceAccessEvidence>;
pub(super) type JvmImplicitProjectMemo = ExactReadMemo<JvmSourceAccessKey, bool>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmLookupRecipeKey {
    fragment: BindingFragmentId,
    semantic: SemanticId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmLookupRecipeMemo =
    ExactReadMemo<JvmLookupRecipeKey, ResolutionLookupSemanticRecipe>;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmImportTargetKey {
    statement: &'static str,
    package: String,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

type JvmImportTarget = (u32, Option<i64>);

pub(super) struct JvmImportTargetRows {
    rows: Box<[JvmImportTarget]>,
    ordered: Box<[JvmImportTarget]>,
}

pub(super) type JvmImportTargetMemo = ExactReadMemo<JvmImportTargetKey, Arc<JvmImportTargetRows>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmPackageMemberKey {
    mount: SelectedResolutionMountOrdinal,
    lookup: SemanticId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmPackageMemberMemo =
    ExactReadMemo<JvmPackageMemberKey, Arc<[LoweredPackageMember]>>;

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

pub(super) type JvmVisibilityMemo = ExactReadMemo<JvmVisibilityKey, Arc<[DeclaredVisibility]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct JvmRootExportKey {
    mount: SelectedResolutionMountOrdinal,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) struct JvmRootExportInventory {
    halves: Vec<SelectedRootPathHalf>,
    outcome: FactReadOutcome,
}

// Share immutable pages inside this one query instead of cloning the whole
// inventory for every route. No handle is retained by a later request.
pub(super) type JvmRootExportMemo = ExactReadMemo<JvmRootExportKey, Arc<JvmRootExportInventory>>;

#[derive(Clone)]
pub(crate) enum JvmImportContext {
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
pub(crate) struct JvmImportContextGap {
    pub(crate) source_token: SemanticId,
    pub(crate) source_reference: Option<SemanticId>,
    pub(crate) lookup: ResolutionLookupSemanticRecipe,
    pub(crate) reason: SemanticId,
    pub(crate) kind: &'static str,
    pub(crate) owner: Option<String>,
    pub(crate) boundary_status: Option<crate::analyzer::structural::BoundaryStatus>,
    pub(crate) nominal_type_identity: Option<SemanticId>,
    suppress_if_same_package_candidate: bool,
}

/// One exact selected terminal route published for a JVM root reference.
/// `complete` is set only when the selected package/member pages and access
/// evidence exhaust this namespace's candidate space.
pub(super) struct JvmRoutePublication {
    pub(super) bridges: Vec<SelectedRootBridgeDescriptor>,
    pub(super) selected_targets: BTreeSet<SemanticId>,
    pub(super) complete: bool,
}

struct JvmMemberCandidateRead {
    candidates: Vec<(SemanticId, SemanticId, CodeUnit, ResolutionMemberAccess)>,
    complete: bool,
}

struct JvmImportContextGapSpec {
    context_id: i64,
    source: BindingFragmentId,
    source_token: SemanticId,
    source_reference: Option<SemanticId>,
    kind: &'static str,
    owner: Option<String>,
    lookup: ResolutionLookupSemanticRecipe,
    detail: String,
}

pub(crate) type JavaImportContext = JvmImportContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JavaExternalStaticImportBoundary {
    pub member: String,
    pub owner: String,
}

#[derive(Clone, Copy)]
enum JvmPackageRelation {
    Same,
    Different,
    Unknown,
}
impl JvmPackageRelation {
    fn between(caller: Option<&str>, target: &str) -> Self {
        match caller {
            Some(package) if package == target => Self::Same,
            Some(_) => Self::Different,
            None => Self::Unknown,
        }
    }
}

enum JvmDeclarationAccess {
    Ready(ResolutionCompletion),
    Excluded,
    Cancelled,
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn profile_jvm_read(&self, kind: &'static str, key: impl std::fmt::Debug) {
        if let Some(profile) = self.jvm_context_profile.borrow_mut().as_mut() {
            *profile.calls.entry((kind, format!("{key:?}"))).or_default() += 1;
        }
    }

    /// Compose Java type and static source imports for one file.
    /// Inherited routes, peer-language routes and external inventory remain open.
    pub(crate) fn java_import_context(
        &self,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.jvm_import_context(Language::Java, caller_path, cancellation)
    }

    /// Compose the same structured imports for inverse confirmation. Its
    /// selected candidate inventory and per-reference forward proof own the
    /// relevant absence questions, so the blanket point-lookup gap is omitted.
    pub(crate) fn java_reverse_import_context(
        &self,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.java_import_context_with_jvm_peers(caller_path, cancellation)
    }

    pub(crate) fn jvm_import_context(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.profile_jvm_read("file_context", (source_language, caller_path));
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let key = (
            source_language,
            caller_path.to_owned(),
            self.ready.inventory.scope_identity(),
            self.ready.inventory.staged_read_epoch(),
        );
        if let Some(context) = self.jvm_file_contexts.borrow().get(&key) {
            return Ok(context.clone());
        }
        let context = match source_language {
            Language::Java => self
                .java_import_context_with_jvm_peers(caller_path, cancellation)
                .map(JvmImportContext::with_open_inventory_gap),
            Language::Kotlin | Language::Scala => {
                self.jvm_import_context_parts(source_language, caller_path, cancellation)
            }
            _ => unreachable!("a selected JVM context has a JVM language"),
        }?;
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
        match source_language {
            Language::Java => self.java_reverse_import_context(caller_path, cancellation),
            Language::Kotlin | Language::Scala => {
                self.jvm_import_context(source_language, caller_path, cancellation)
            }
            _ => unreachable!("a selected JVM context has a JVM language"),
        }
    }

    fn java_import_context_with_jvm_peers(
        &self,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        let java = self.java_import_context_parts(caller_path, cancellation)?;
        let peers = self.jvm_import_context_parts(Language::Java, caller_path, cancellation)?;
        match (java, peers) {
            (JvmImportContext::Cancelled, _) | (_, JvmImportContext::Cancelled) => {
                Ok(JvmImportContext::Cancelled)
            }
            (
                JvmImportContext::Ready {
                    context,
                    external_static_imports,
                    inventory_reason,
                    open_jvm_alias_imports: _,
                    scoped_gaps,
                },
                JvmImportContext::Ready {
                    context: peer_context,
                    open_jvm_alias_imports,
                    scoped_gaps: peer_scoped_gaps,
                    ..
                },
            ) => {
                let mounts = self.mount_table();
                let selected_mount_of = |fragment| {
                    Ok(mounts
                        .mount_for_fragment(fragment)?
                        .map(|mount| (mount.ordinal(), mount.semantic_language())))
                };
                let Some(context) =
                    (*context).merge(*peer_context, cancellation, &selected_mount_of)?
                else {
                    return Ok(JvmImportContext::Cancelled);
                };
                let mut scoped_gaps = scoped_gaps;
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

    fn jvm_import_context_parts(
        &self,
        source_language: Language,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        self.profile_jvm_read("derive_file_context", (source_language, caller_path));
        assert!(is_jvm_language(source_language));
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let connection = self.ready.inventory.connection();
        let Some(context_id) = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row([source_language.config_label()], |row| row.get::<_, i64>(0))
            .optional()?
        else {
            return Ok(JvmImportContext::Unavailable);
        };
        let Some(source) = self
            .mount_table()
            .mount_for_path(source_language.config_label(), caller_path)?
        else {
            return Ok(JvmImportContext::Unavailable);
        };
        assert_eq!(source.semantic_language(), source_language);
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let caller_version = source_record.file_version_id();
        let source_package: Option<String> = connection
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [source_record.blob_id()],
                |row| row.get(0),
            )
            .optional()?;
        let source_package = if source_language == Language::Scala {
            self.scala_primary_package(source_record.blob_id())?
                .or(source_package)
        } else {
            source_package
        };
        let identities = self.ready.context_identities.clone();
        let inventory_reason = if source_language == Language::Java {
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
        let mut import_halves = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &identities,
            &lexical,
            &lexical,
            Some(&[source.ordinal()]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                import_halves.extend_from_slice(page);
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
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
                return Ok(JvmImportContext::Cancelled);
            };
            let Some(reference) = classifications
                .iter()
                .find(|classification| classification.node() == *source_reference)
                .and_then(|classification| classification.reference())
            else {
                continue;
            };
            let is_supertype: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.resolution_supertypes WHERE blob_id=?1 AND reference=?2)",
                rusqlite::params![source_record.blob_id(), reference.local_key().expect("a mounted reference has a local key")],
                |row| row.get(0),
            )?;
            if !is_supertype {
                continue;
            }
            let Some(recipes) = self.jvm_lookup_recipes(
                source.fragment(),
                route.iter().copied().chain([*demand]),
                cancellation,
            )?
            else {
                return Ok(JvmImportContext::Cancelled);
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
            if self.model_declares_jvm_type(&declared)? {
                register_model_declared_jvm_type_identity(
                    reference,
                    &declared,
                    self.model_declared_jvm_owner(&declared)?.as_ref(),
                    &identities,
                    &self.ready.shared_names(),
                );
            }
        }
        let mut root_bridges = Vec::new();
        let mut route_inventory_open = false;
        let mut scoped_gaps = Vec::new();
        let mut model_declared_routes = Vec::new();
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
        for half in import_halves {
            let SelectedRootPathHalf::Import {
                identity,
                source_scope_head,
                route,
                token,
                anchor,
                anchor_semantic,
                demand,
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
            let lexical_prefixes = if source_language == Language::Scala {
                self.scala_import_package_prefixes(source_record.blob_id(), token)?
            } else {
                Vec::new()
            };
            let source_package = if source_language == Language::Scala {
                lexical_prefixes
                    .last()
                    .cloned()
                    .or_else(|| source_package.clone())
            } else {
                source_package.clone()
            };
            let selector =
                selected_jvm_import_selector(connection, source_record.blob_id(), token)?;
            let java_single_type = selector.is_none()
                && source_language == Language::Java
                && selected_import_route(
                    connection,
                    source_record.blob_id(),
                    source.ordinal(),
                    token,
                )?
                .is_some_and(|route| route.kind == "single_type");
            let Some(mut recipes) = self.jvm_lookup_recipes(
                source.fragment(),
                route.iter().copied().chain([demand]),
                cancellation,
            )?
            else {
                return Ok(JvmImportContext::Cancelled);
            };
            let demand_recipe = recipes.pop().expect("one selected import demand");
            if selector.is_none() && !java_single_type {
                if matches!(source_language, Language::Kotlin | Language::Scala) {
                    scoped_gaps.push(self.jvm_import_context_gap(
                        JvmImportContextGapSpec {
                            context_id,
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
                        cancellation,
                    )?);
                } else {
                    route_inventory_open = true;
                }
                continue;
            }
            if selector.as_ref().is_some_and(|selector| {
                selector.kind == ResolutionImportSelectorKind::ReceiverMember
            }) {
                if matches!(source_language, Language::Kotlin | Language::Scala) {
                    scoped_gaps.push(self.jvm_import_context_gap(
                        JvmImportContextGapSpec {
                            context_id,
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
                        cancellation,
                    )?);
                } else {
                    route_inventory_open = true;
                }
                continue;
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
            let source_demand = ResolutionLookupSemanticRecipe::new(
                source_language,
                demand_recipe.namespace(),
                local_name,
            );
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
                open_jvm_alias_imports.extend(open_owner_aliases);
            }
            let mut package_prefix_found = false;
            let mut member_owner_open = false;
            let enclosing_scope_routes = if source_language == Language::Scala
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
            let earlier_route = if source_language == Language::Scala
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
            let chained_wildcard_routes = if source_language == Language::Scala
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
                    let Some((aliases, open_aliases)) = self.jvm_alias_import_bridges(
                        identity.fragment(),
                        source_language,
                        token,
                        anchor,
                        anchor_semantic,
                        caller_version,
                        source.persisted_relative_path(),
                        source_name,
                        &recipes,
                        lookup_route,
                        &source_demand,
                        context_id,
                        source_package.as_deref(),
                        cancellation,
                    )?
                    else {
                        return Ok(JvmImportContext::Cancelled);
                    };
                    if matches!(source_language, Language::Kotlin | Language::Scala) {
                        for open_alias in &open_aliases {
                            scoped_gaps.push(self.jvm_import_context_gap(JvmImportContextGapSpec {
                                context_id,
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
                            }, cancellation)?);
                        }
                    } else {
                        route_inventory_open |= !open_aliases.is_empty();
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
                    let targets = self.jvm_import_targets(JVM_IMPORT_TARGET_MOUNTS, &package)?;
                    if targets.ordered.is_empty() {
                        continue;
                    }
                    candidate_prefix_found = true;
                    selected_owner_found |= prefix_length == lookup_route.len();
                    package_prefix_found |= !relative;
                    if source_language == Language::Scala
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
                    if prefix_length != lookup_route.len()
                        && (source_language == Language::Scala
                            || leading_segments == 0
                            || prefix_length != leading_segments)
                    {
                        continue;
                    }
                    let relation = JvmPackageRelation::between(source_package.as_deref(), &package);
                    let mut package_bridges = Vec::new();
                    for (target_ordinal, target_version) in targets.ordered.iter().copied() {
                        if cancellation.is_cancelled() {
                            return Ok(JvmImportContext::Cancelled);
                        }
                        let target_ordinal = SelectedResolutionMountOrdinal::new(target_ordinal);
                        let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                        let target_language = target_mount.semantic_language();
                        if !is_jvm_language(target_language)
                            || (source_language == Language::Java
                                && target_language == Language::Java)
                        {
                            continue;
                        }
                        let target_demand = ResolutionLookupSemanticRecipe::new(
                            target_language,
                            demand_recipe.namespace(),
                            source_name,
                        );
                        let target_semantic = target_demand.semantic(&self.ready.shared_names());
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
                            let Some(target_definition) =
                                lexical.lookup_definition_node(member.definition, cancellation)?
                            else {
                                if cancellation.is_cancelled() {
                                    return Ok(JvmImportContext::Cancelled);
                                }
                                return Err(StoreError::corrupt(
                                    "selected JVM import member lacks a definition node",
                                ));
                            };
                            let Some(exports_read) =
                                self.jvm_root_exports(target_ordinal, cancellation)?
                            else {
                                return Ok(JvmImportContext::Cancelled);
                            };
                            let exports = exports_read.halves.iter()
                                .filter(|half| matches!(half, SelectedRootPathHalf::Export { definition, .. } if *definition == target_definition))
                                .cloned();
                            for export in exports {
                                let SelectedRootPathHalf::Export {
                                    token: target_export_token,
                                    demand: target_export_demand,
                                    incomplete_reasons,
                                    ..
                                } = export
                                else {
                                    unreachable!("export-only visitor")
                                };
                                let Some(mut target_recipes) = self.jvm_lookup_recipes(
                                    target_mount.fragment(),
                                    [target_export_demand],
                                    cancellation,
                                )?
                                else {
                                    return Ok(JvmImportContext::Cancelled);
                                };
                                let Some(target_export_recipe) = target_recipes.pop() else {
                                    return Err(StoreError::corrupt(
                                        "selected JVM import export lacks its lookup recipe",
                                    ));
                                };
                                if target_export_recipe.namespace() != demand_recipe.namespace()
                                    || target_export_recipe.semantic(&self.ready.shared_names())
                                        != target_semantic
                                {
                                    continue;
                                }
                                let bridge_completion = if incomplete_reasons.is_empty() {
                                    completion.clone()
                                } else {
                                    completion.combine(&ResolutionCompletion::incomplete(
                                        incomplete_reasons,
                                    ))
                                };
                                let binding_origin = if source_language == Language::Scala
                                    && prefix_length < lookup_route.len()
                                {
                                    if caller_version.is_some() && caller_version == target_version
                                    {
                                        BindingOrigin::SameCompilationUnitPackage
                                    } else {
                                        BindingOrigin::OtherCompilationUnitPackage
                                    }
                                } else {
                                    match selector.as_ref().map(|selector| selector.kind) {
                                        Some(ResolutionImportSelectorKind::Named) => {
                                            if source_language == Language::Java {
                                                BindingOrigin::SingleTypeImport
                                            } else {
                                                BindingOrigin::ExplicitImport
                                            }
                                        }
                                        Some(ResolutionImportSelectorKind::Star) => {
                                            if source_language == Language::Kotlin {
                                                BindingOrigin::StarImport
                                            } else {
                                                BindingOrigin::WildcardImport
                                            }
                                        }
                                        Some(ResolutionImportSelectorKind::ReceiverMember)
                                        | None => BindingOrigin::OtherCompilationUnitPackage,
                                    }
                                };
                                let candidate_origin_rank =
                                    binding_origin_rank(source_language, binding_origin);
                                let Some(bridge) = self.jvm_root_import_bridge(
                                    identity.fragment(),
                                    source_language,
                                    token,
                                    anchor,
                                    anchor_semantic,
                                    target_ordinal,
                                    target_language,
                                    target_export_token,
                                    target_definition,
                                    recipes.clone(),
                                    source_demand.clone(),
                                    target_export_recipe,
                                    &member,
                                    context_id,
                                    caller_version,
                                    source.persisted_relative_path(),
                                    target_version,
                                    target_mount.persisted_relative_path(),
                                    relation,
                                    candidate_origin_rank,
                                    bridge_completion,
                                    cancellation,
                                )?
                                else {
                                    continue;
                                };
                                package_bridges.push(bridge);
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
                    && jvm_member_continuation_mounts(source_language).is_some()
                {
                    let mut owner_found = false;
                    let Some(inventory) = self.jvm_type_member_import_candidates(
                        context_id,
                        caller_version,
                        &JavaMemberImportDemand {
                            import_kind: None,
                            caller_package: source_package.as_deref(),
                            source: identity.fragment(),
                            token,
                            prefix_reference: None,
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
                        && source_language == Language::Scala
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
                    root_bridges.extend(inventory.members.into_iter().map(|member| member.bridge));
                }
                if root_bridges.len() > bridges_before {
                    resolved_lookup_route = Some(lookup_route.clone());
                    break;
                }
                if source_language == Language::Scala
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
            let wildcard_route = if source_language == Language::Scala
                && anchor == ResolutionRootImportAnchor::Lexical
                && selector
                    .as_ref()
                    .is_some_and(|selector| selector.kind == ResolutionImportSelectorKind::Star)
            {
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
            if source_language == Language::Scala
                && anchor == ResolutionRootImportAnchor::Lexical
                && selector
                    .as_ref()
                    .is_some_and(|selector| selector.kind == ResolutionImportSelectorKind::Named)
                && root_bridges.len() > bridges_before
                && let Some(mut resolved_route) = resolved_lookup_route
            {
                resolved_route.push(ResolutionLookupSemanticRecipe::new(
                    source_language,
                    demand_recipe.namespace(),
                    source_name,
                ));
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
                    context_id,
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
                if self.model_declares_jvm_type(&declared)? {
                    // The reviewed model declares this type, so the import
                    // closes with a model-declared identity instead of an
                    // open route. Member enumeration stays open through the
                    // identity's enumeration boundary.
                    model_declared_routes.push(ModelDeclaredJvmImportRoute {
                        source_token: token,
                        lookup: source_demand.clone(),
                        owner: self.model_declared_jvm_owner(&declared)?,
                        declared_fqn: declared,
                    });
                } else {
                    let mut gap = self.jvm_import_context_gap(JvmImportContextGapSpec {
                        context_id,
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
                    let identity =
                        model_declared_jvm_type_identity(&declared, &self.ready.shared_names());
                    identities.record_jvm_unindexed_import_owner(identity, &declared);
                    gap.nominal_type_identity = Some(identity);
                    scoped_gaps.push(gap);
                }
                route_inventory_open |= source_language == Language::Java;
            }
            if cancellation.is_cancelled() {
                return Ok(JvmImportContext::Cancelled);
            }
        }

        let SelectedPackageRows::Ready(package_reference_occurrences) =
            self.selected_package_references(source.ordinal(), cancellation)?
        else {
            return Ok(JvmImportContext::Cancelled);
        };
        let package_references =
            unique_package_references_by_token(&package_reference_occurrences)?;
        let mut same_package_lookups = BTreeSet::new();
        let SelectedPackageRows::Ready(local_package_members) =
            self.selected_package_members_by_lookup(source.ordinal(), cancellation)?
        else {
            return Ok(JvmImportContext::Cancelled);
        };
        for reference in &package_references {
            if local_package_members
                .get(&reference.lookup)
                .into_iter()
                .flatten()
                .any(|member| {
                    member.domain == reference.domain && member.namespace == reference.namespace
                })
            {
                same_package_lookups.insert(reference.lookup);
            }
        }
        let implicit_root_providers = language_implicit_root_providers(source_language);
        let mut package_names = source_package.iter().cloned().collect::<Vec<_>>();
        package_names.extend(implicit_root_providers.iter().filter_map(
            |provider| match provider {
                JvmImplicitRootProvider::Package(name) => Some((*name).to_owned()),
                JvmImplicitRootProvider::ScalaPredef => None,
            },
        ));
        package_names.sort_unstable();
        package_names.dedup();
        let import_context = JvmPackageImportContext {
            context_id,
            source_ordinal: source.ordinal(),
            source_path: source.persisted_relative_path(),
            caller_version,
            caller_package: source_package.as_deref(),
        };
        let package_bridges = self.jvm_package_import_bridges(
            &import_context,
            &package_names,
            &package_references,
            &mut scoped_gaps,
            &mut same_package_lookups,
            cancellation,
        )?;
        let Some(mut package_bridges) = package_bridges else {
            return Ok(JvmImportContext::Cancelled);
        };
        if implicit_root_providers.contains(&JvmImplicitRootProvider::ScalaPredef) {
            let Some((predef_bridges, predef_gaps)) = self.scala_predef_import_bridges(
                &import_context,
                &package_references,
                cancellation,
            )?
            else {
                return Ok(JvmImportContext::Cancelled);
            };
            package_bridges.extend(predef_bridges);
            scoped_gaps.extend(predef_gaps);
        }
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let names = self.ready.shared_names();
        scoped_gaps.retain(|gap| {
            !gap.suppress_if_same_package_candidate
                || !same_package_lookups.contains(&gap.lookup.semantic(&names))
        });
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
                return Ok(JvmImportContext::Cancelled);
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
                                && (metadata.site_kind()
                                    == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ValueReference
                                    || (source_language == Language::Scala && metadata.site_kind()
                                        == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ImportQualifierReference));
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
        let mut durable_implicit_owners = BTreeMap::new();
        for gap in &scoped_gaps {
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
                if let Some(owner) = self.model_declared_jvm_owner(&fqn)? {
                    durable_implicit_owners.insert(fqn, owner);
                }
            }
        }
        if source_language == Language::Java {
            for reference in package_reference_occurrences.iter().filter(|reference| {
                reference.namespace == ResolutionNamespace::Type
                    && unqualified_type_references.contains(&reference.reference)
            }) {
                let Some(mut lookups) =
                    self.jvm_lookup_recipes(source.fragment(), [reference.lookup], cancellation)?
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
                    if let Some(owner) = self.model_declared_jvm_owner(&fqn)? {
                        durable_implicit_owners.insert(fqn, owner);
                    }
                }
            }
        }
        register_jvm_external_provider_type_identities(JvmExternalProviderIdentityRegistration {
            source_language,
            gaps: &scoped_gaps,
            package_reference_occurrences: &package_reference_occurrences,
            unqualified_type_references: &unqualified_type_references,
            durable_owners: &durable_implicit_owners,
            lexical: &lexical,
            source_fragment: source.fragment(),
            identities: &identities,
            names: &names,
            cancellation,
        })?;
        register_model_declared_jvm_type_identities(
            &model_declared_routes,
            &package_reference_occurrences,
            &unqualified_type_references,
            &identities,
            &names,
        );
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
            &|fragment| {
                Ok(mounts
                    .mount_for_fragment(fragment)?
                    .map(|mount| (mount.ordinal(), mount.semantic_language())))
            },
        )?;
        let access_identity = self.ready.context_identities.named_semantic(
            CanonicalHasher::new(b"jvm-selected-declaration-access:v1").finish(),
            "jvm-selected-declaration-access",
            "JVM declaration visibility under exact selected package and lexical ownership",
        );
        let mut context = if source_language == Language::Java {
            context
        } else {
            context.with_declaration_access_source(Arc::new(super::java_access::JvmAccessPolicy {
                identity: access_identity,
            }))
        };
        if route_inventory_open && !matches!(source_language, Language::Kotlin | Language::Scala) {
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

    /// The query's complete target rows have no caller or route completion.
    /// Keep both existing consumer orderings; callers retain their polling.
    pub(super) fn jvm_import_targets(
        &self,
        statement: &'static str,
        package: &str,
    ) -> Result<Arc<JvmImportTargetRows>> {
        let key = JvmImportTargetKey {
            statement,
            package: package.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("import_targets", &key);
        if let Some(rows) = self.jvm_import_target_memo.borrow().get(&key) {
            return Ok(Arc::clone(rows));
        }
        self.profile_jvm_read("derive_import_targets", &key);
        let connection = self.ready.inventory.connection();
        let mut query = connection.prepare_cached(statement)?;
        let rows = query
            .query_map([package], |row| {
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

    /// Retain the complete selected-node answer, including an absent endpoint.
    pub(super) fn jvm_endpoint_classifications(
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

    /// Package relation and incoming completion are applied by each caller.
    pub(super) fn jvm_declaration_visibilities(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<Arc<[DeclaredVisibility]>>> {
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
                    rows.extend(page.iter().map(|row| row.row().visibility()));
                    Ok(true)
                }),
            )?;
        if outcome.is_cancelled() || cancellation.is_cancelled() {
            return Ok(None);
        }
        let rows: Arc<[DeclaredVisibility]> = rows.into();
        if outcome.is_exhausted() {
            self.jvm_visibility_memo
                .borrow_mut()
                .insert(key, Arc::clone(&rows));
        }
        Ok(Some(rows))
    }

    /// Reuse the existing staged-overlay reader only for this selected query.
    pub(super) fn jvm_package_members_for_lookup(
        &self,
        mount: SelectedResolutionMountOrdinal,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedPackageRows<Arc<[LoweredPackageMember]>>> {
        assert!(
            lookup.shared_name_id().is_some(),
            "package lookup is a shared name"
        );
        let key = JvmPackageMemberKey {
            mount,
            lookup,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        };
        self.profile_jvm_read("package_members", key);
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        if let Some(members) = self.jvm_package_member_memo.borrow().get(&key) {
            return Ok(SelectedPackageRows::Ready(Arc::clone(members)));
        }
        self.profile_jvm_read("derive_package_members", key);
        let SelectedPackageRows::Ready(members) =
            self.selected_package_members_for_lookup(mount, lookup, cancellation)?
        else {
            return Ok(SelectedPackageRows::Cancelled);
        };
        if cancellation.is_cancelled() {
            return Ok(SelectedPackageRows::Cancelled);
        }
        let members: Arc<[LoweredPackageMember]> = members.into();
        self.jvm_package_member_memo
            .borrow_mut()
            .insert(key, Arc::clone(&members));
        Ok(SelectedPackageRows::Ready(members))
    }

    /// Read one demanded mount's export rows and their full proof evidence.
    /// Route-specific filters run over the same immutable pages on every use.
    pub(super) fn jvm_root_exports(
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
        let lexical = self.ready.lexical_source();
        let mut halves = Vec::new();
        let outcome = visit_selected_root_export_half_pages(
            &self.ready.context_identities,
            &lexical,
            &lexical,
            Some(&[mount]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                halves.extend_from_slice(page);
                Ok(true)
            }),
        )?;
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
        let key = |semantic| JvmLookupRecipeKey {
            fragment,
            semantic,
            scope,
            stage_epoch,
        };
        // A recipe is one name's fact. Deduplicate missing names, then retain
        // the caller's batch order and repetitions when assembling its result.
        let mut needed = Vec::new();
        let mut seen = HashSet::default();
        {
            let memo = self.jvm_lookup_recipe_memo.borrow();
            for page in semantics.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                for &semantic in page {
                    if memo.get(&key(semantic)).is_none() && seen.insert(semantic) {
                        needed.push(semantic);
                    }
                }
            }
        }
        let lexical = self.ready.lexical_source();
        let mut computed = Vec::with_capacity(needed.len());
        for page in needed.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let requests = page
                .iter()
                .map(|&semantic| SelectedLookupRecipeRequest { fragment, semantic })
                .collect::<Vec<_>>();
            for &semantic in page {
                self.profile_jvm_read("derive_lookup_recipe", key(semantic));
            }
            let SelectedLookupRecipeReadOutcome::Ready(rows) =
                lexical.lookup_semantic_recipes(&requests, cancellation, None)?
            else {
                return Ok(None);
            };
            assert_eq!(
                rows.len(),
                page.len(),
                "lookup recipe positions: semantics={page:?}, rows={rows:?}"
            );
            for (&semantic, row) in page.iter().zip(rows.into_vec()) {
                let recipe = row.ok_or_else(|| {
                    StoreError::corrupt("selected JVM import semantic lacks its lookup recipe")
                })?;
                computed.push((key(semantic), recipe));
            }
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        {
            let mut memo = self.jvm_lookup_recipe_memo.borrow_mut();
            for (key, recipe) in computed {
                memo.insert(key, recipe);
            }
        }
        let memo = self.jvm_lookup_recipe_memo.borrow();
        let mut recipes = Vec::with_capacity(semantics.len());
        for page in semantics.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            recipes.extend(page.iter().map(|&semantic| {
                memo.get(&key(semantic))
                    .expect("each requested JVM recipe was read")
                    .clone()
            }));
        }
        Ok((!cancellation.is_cancelled()).then_some(recipes))
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
        } = *import_context;
        let lexical = self.ready.lexical_source();
        let names = self.ready.shared_names();
        let source_language = self
            .mount_table()
            .mount_by_ordinal(source_ordinal)?
            .semantic_language();
        let implicit_root_providers = language_implicit_root_providers(source_language);
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
        let mut bridges = Vec::new();
        // The cache is local to this one file-context build and retains only
        // lookups requested by its deduplicated package references.
        let mut members_by_mount = HashMap::default();
        for (reference, source_recipe) in &reference_recipes {
            for package in packages {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let targets = self.jvm_import_targets(JVM_IMPORT_TARGET_MOUNTS, package)?;
                let relation = JvmPackageRelation::between(caller_package, package);
                let is_default_import = implicit_root_providers.iter().any(|provider| {
                    matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package.as_str())
                });
                if is_default_import && targets.ordered.is_empty() {
                    scoped_gaps.push(self.jvm_import_context_boundary_gap_with_same_package_shadow(
                        JvmImportContextGapSpec {
                            context_id,
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
                for (target, target_version) in targets.ordered.iter().copied() {
                    let target_ordinal = SelectedResolutionMountOrdinal::new(target);
                    if target_ordinal == source_ordinal {
                        continue;
                    }
                    let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                    let target_mount_record = self
                        .ready
                        .inventory
                        .mount_record_by_ordinal(target_ordinal)?;
                    let target_language = target_mount.semantic_language();
                    if !is_jvm_language(target_language) {
                        continue;
                    }
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        members_by_mount.entry(target_ordinal)
                    {
                        let SelectedPackageRows::Ready(mut grouped) =
                            self.selected_package_members_by_lookup(target_ordinal, cancellation)?
                        else {
                            return Ok(None);
                        };
                        let requested = reference_recipes
                            .iter()
                            .map(|(reference, source_recipe)| {
                                ResolutionLookupSemanticRecipe::new(
                                    target_language,
                                    reference.namespace,
                                    source_recipe.spelling(),
                                )
                                .semantic(&names)
                            })
                            .collect::<HashSet<_>>();
                        grouped.retain(|lookup, _| requested.contains(lookup));
                        entry.insert(grouped);
                    }
                    let members_by_lookup = &members_by_mount[&target_ordinal];
                    let target_recipe = ResolutionLookupSemanticRecipe::new(
                        target_language,
                        reference.namespace,
                        source_recipe.spelling(),
                    );
                    let target_lookup = target_recipe.semantic(&names);
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
                    for member in members_by_lookup.get(&target_lookup).into_iter().flatten() {
                        if member.namespace != reference.namespace || member.lookup != target_lookup
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
                            JvmDeclarationAccess::Cancelled => return Ok(None),
                        };
                        let Some(target_definition) =
                            lexical.lookup_definition_node(member.definition, cancellation)?
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
                            let Some(visibility) = self.jvm_bridge_visibility(
                                member.definition,
                                relation,
                                cancellation,
                            )?
                            else {
                                continue;
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
                                    context_id,
                                    caller_version,
                                    source_path,
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
                            package,
                            reference,
                            target_mount_record.fragment_digest().as_bytes(),
                            |key| self.ready.identity_content_digest(key, cancellation),
                        )?;
                        let same_package_candidate = Some(package.as_str()) == caller_package
                            && completion == ResolutionCompletion::Complete;
                        let precedence = Self::selected_jvm_package_precedence(
                            source_language,
                            caller_package,
                            package,
                        );
                        bridges.push(
                            SelectedPackageBridgeDescriptor::new_jvm_import(
                                source_mount.fragment(),
                                target_mount.fragment(),
                                source_language,
                                target_language,
                                reference,
                                member,
                                source_recipe,
                                &target_recipe,
                                target_definition,
                                route_identity,
                                precedence.tier.map(|tier| PrecedenceStep {
                                    tier,
                                    ordinal: 0,
                                    semantic: reference
                                        .choice
                                        .expect("selected Kotlin package choice is persisted"),
                                }),
                                &names,
                                evidence,
                                completion,
                            )
                            .with_candidate_origin_rank(precedence.candidate_origin_rank),
                        );
                        if same_package_candidate {
                            same_package_lookups.insert(reference.lookup);
                        }
                    }
                }
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(bridges))
    }

    fn selected_jvm_package_precedence(
        language: Language,
        caller_package: Option<&str>,
        target_package: &str,
    ) -> SelectedJvmPackagePrecedence {
        let same_package = caller_package == Some(target_package);
        let (tier, origin) = match language {
            Language::Kotlin if same_package => (
                Some(PrecedenceTier::PackageOrModule),
                BindingOrigin::SamePackage,
            ),
            Language::Kotlin => (
                Some(PrecedenceTier::DefaultImport),
                BindingOrigin::StarImport,
            ),
            Language::Java if same_package => (None, BindingOrigin::SamePackage),
            Language::Java | Language::Scala => (None, BindingOrigin::OtherCompilationUnitPackage),
            _ => unreachable!("selected JVM package imports belong to Java, Kotlin, or Scala"),
        };
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
        } = *import_context;
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let source_mount = self.mount_table().mount_by_ordinal(source_ordinal)?;
        let source_language = source_mount.semantic_language();
        assert!(matches!(
            source_language,
            Language::Kotlin | Language::Scala
        ));
        let predef = ResolutionLookupSemanticRecipe::new(
            Language::Scala,
            ResolutionNamespace::Value,
            "Predef",
        );
        let predef_lookup = predef.semantic(&names);
        let target_mounts = self.jvm_import_targets(JVM_IMPORT_TARGET_MOUNTS, "scala")?;
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
            let relation = JvmPackageRelation::between(caller_package, "scala");
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
                    let target_recipe = ResolutionLookupSemanticRecipe::new(
                        Language::Scala,
                        reference.namespace,
                        source_recipe.spelling(),
                    );
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
                    context_id,
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

    #[allow(clippy::too_many_arguments)]
    fn jvm_alias_import_bridges(
        &self,
        source_fragment: BindingFragmentId,
        source_language: Language,
        import_token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        anchor_semantic: SemanticId,
        caller_version: Option<i64>,
        caller_path: &str,
        imported_name: &str,
        route: &[ResolutionLookupSemanticRecipe],
        lookup_route: &[ResolutionLookupSemanticRecipe],
        source_demand: &ResolutionLookupSemanticRecipe,
        context_id: i64,
        caller_package: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<Option<(Vec<SelectedRootBridgeDescriptor>, Vec<String>)>> {
        let connection = self.ready.inventory.connection();
        let mut bridges = Vec::new();
        let mut open_imports = Vec::new();
        for prefix_length in (1..=lookup_route.len()).rev() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let owner_recipes = &lookup_route[..prefix_length];
            let package = owner_recipes
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join(".");
            if package.is_empty() {
                continue;
            }
            let targets = self.jvm_import_targets(JVM_IMPORT_TARGET_MOUNTS, &package)?;
            let expected_owner = owner_recipes
                .iter()
                .map(|segment| segment.spelling())
                .collect::<Vec<_>>();
            let relation = JvmPackageRelation::between(caller_package, &package);
            for (target_ordinal, target_version) in targets.ordered.iter().copied() {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let target_ordinal = SelectedResolutionMountOrdinal::new(target_ordinal);
                let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                let target_language = target_mount.semantic_language();
                if !is_jvm_language(target_language) {
                    continue;
                }
                let target_record = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(target_ordinal)?;
                let mut aliases =
                    connection.prepare_cached(SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER)?;
                let aliases = aliases
                    .query_map(
                        rusqlite::params![target_record.blob_id(), imported_name],
                        |row| {
                            Ok((
                                row.get::<_, u32>(0)?,
                                row.get::<_, u32>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, u32>(3)?,
                                row.get::<_, String>(4)?,
                            ))
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for (alias_id, declaration_site, status, declaration_key, alias_kind) in aliases {
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
                        source_language,
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
                    let Some(exports_read) = self.jvm_root_exports(target_ordinal, cancellation)?
                    else {
                        return Ok(None);
                    };
                    let exports = exports_read.halves.iter()
                        .filter(|half| matches!(half, SelectedRootPathHalf::Export { definition, .. } if *definition == target_definition))
                        .cloned();
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
                    for export in exports {
                        let SelectedRootPathHalf::Export {
                            identity,
                            token,
                            demand,
                            incomplete_reasons,
                            ..
                        } = export
                        else {
                            unreachable!("export-only visitor")
                        };
                        let Some(mut target_recipes) = self.jvm_lookup_recipes(
                            target_mount.fragment(),
                            [demand],
                            cancellation,
                        )?
                        else {
                            return Ok(None);
                        };
                        let Some(target_demand) = target_recipes.pop() else {
                            return Err(StoreError::corrupt(
                                "selected JVM alias export lacks its lookup recipe",
                            ));
                        };
                        if target_demand.namespace() != source_demand.namespace() {
                            continue;
                        }
                        let bridge_completion = if incomplete_reasons.is_empty() {
                            completion.clone()
                        } else {
                            completion
                                .combine(&ResolutionCompletion::incomplete(incomplete_reasons))
                        };
                        let bridge = if source_language == target_language {
                            SelectedRootBridgeDescriptor::from_selected_path_tokens(
                                source_fragment,
                                source_language,
                                import_token,
                                anchor,
                                anchor_semantic,
                                identity.fragment(),
                                target_language,
                                token,
                                route.to_vec(),
                                source_demand.clone(),
                                target_demand,
                                bridge_completion,
                            )
                        } else {
                            SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
                                source_fragment,
                                source_language,
                                import_token,
                                anchor,
                                anchor_semantic,
                                identity.fragment(),
                                target_language,
                                token,
                                None,
                                route.to_vec(),
                                source_demand.clone(),
                                target_demand,
                                SelectedJvmBridgeEvidence {
                                    provenance: SelectedJvmBridgeProvenance::AliasFact {
                                        alias: alias_identity,
                                    },
                                    source_namespace: source_demand.namespace(),
                                    target_namespace: source_demand.namespace(),
                                    visibility: match self.jvm_bridge_visibility(
                                        declaration,
                                        relation,
                                        cancellation,
                                    )? {
                                        Some(visibility) => visibility,
                                        None => return Ok(None),
                                    },
                                    dependency_identity: jvm_dependency_identity(
                                        context_id,
                                        caller_version,
                                        caller_path,
                                        target_version,
                                        target_mount.persisted_relative_path(),
                                    ),
                                    target_declaration: declaration,
                                    target_definition,
                                },
                                bridge_completion,
                            )
                        };
                        bridges.push(bridge.with_selected_member_definition(target_definition));
                    }
                }
            }
        }
        open_imports.sort_unstable();
        open_imports.dedup();
        Ok((!cancellation.is_cancelled()).then_some((bridges, open_imports)))
    }

    fn jvm_open_owner_alias_imports(
        &self,
        source_language: Language,
        route: &[ResolutionLookupSemanticRecipe],
        imported_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<String>>> {
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
            let targets = self.jvm_import_targets(JVM_IMPORT_TARGET_MOUNTS, &package)?;
            let mut expected_owner = owner_prefix;
            expected_owner.push(imported_name.to_owned());
            for (target_ordinal, _) in targets.ordered.iter().copied() {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let target_ordinal = SelectedResolutionMountOrdinal::new(target_ordinal);
                let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                let target_language = target_mount.semantic_language();
                if !is_jvm_language(target_language)
                    || (source_language == Language::Java && target_language == Language::Java)
                {
                    continue;
                }
                let target_record = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(target_ordinal)?;
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
                        open_imports.push(expected_owner.join("."));
                    }
                }
            }
        }
        open_imports.sort_unstable();
        open_imports.dedup();
        Ok((!cancellation.is_cancelled()).then_some(open_imports))
    }

    #[allow(clippy::too_many_arguments)]
    fn jvm_root_import_bridge(
        &self,
        source_fragment: BindingFragmentId,
        source_language: Language,
        import_token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        anchor_semantic: SemanticId,
        target_ordinal: SelectedResolutionMountOrdinal,
        target_language: Language,
        target_export_token: SemanticId,
        target_definition: BindingNodeId,
        route: Vec<ResolutionLookupSemanticRecipe>,
        source_demand: ResolutionLookupSemanticRecipe,
        target_demand: ResolutionLookupSemanticRecipe,
        member: &crate::analyzer::resolution::LoweredPackageMember,
        context_id: i64,
        caller_version: Option<i64>,
        caller_path: &str,
        target_version: Option<i64>,
        target_path: &str,
        relation: JvmPackageRelation,
        candidate_origin_rank: Option<u32>,
        completion: ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<SelectedRootBridgeDescriptor>> {
        let bridge = if source_language == target_language {
            SelectedRootBridgeDescriptor::from_selected_path_tokens(
                source_fragment,
                source_language,
                import_token,
                anchor,
                anchor_semantic,
                self.mount_table()
                    .mount_by_ordinal(target_ordinal)?
                    .fragment(),
                target_language,
                target_export_token,
                route,
                source_demand,
                target_demand,
                completion,
            )
        } else {
            let Some(visibility) =
                self.jvm_bridge_visibility(member.definition, relation, cancellation)?
            else {
                return Ok(None);
            };
            let names = self.ready.shared_names();
            let source_package = package_domain_semantic(source_language, &names);
            let target_package = package_domain_semantic(target_language, &names);
            SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
                source_fragment,
                source_language,
                import_token,
                anchor,
                anchor_semantic,
                self.mount_table()
                    .mount_by_ordinal(target_ordinal)?
                    .fragment(),
                target_language,
                target_export_token,
                None,
                route,
                source_demand,
                target_demand,
                SelectedJvmBridgeEvidence {
                    provenance: SelectedJvmBridgeProvenance::StructuredPackageType {
                        source_package,
                        target_package,
                    },
                    source_namespace: member.namespace,
                    target_namespace: member.namespace,
                    visibility,
                    dependency_identity: jvm_dependency_identity(
                        context_id,
                        caller_version,
                        caller_path,
                        target_version,
                        target_path,
                    ),
                    target_declaration: member.definition,
                    target_definition,
                },
                completion,
            )
        };
        Ok(Some(
            bridge
                .with_selected_member_definition(target_definition)
                .with_candidate_origin_rank(candidate_origin_rank),
        ))
    }

    fn jvm_bridge_visibility(
        &self,
        definition: SemanticId,
        package: JvmPackageRelation,
        cancellation: &CancellationToken,
    ) -> Result<Option<SelectedJvmBridgeVisibility>> {
        let Some(visibilities) = self.jvm_declaration_visibilities(definition, cancellation)?
        else {
            return Ok(None);
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(match (visibilities.as_ref(), package) {
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
        cancellation: &CancellationToken,
    ) -> Result<JvmImportContext> {
        if cancellation.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        let connection = self.ready.inventory.connection();
        let selected = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row(["java"], |row| row.get::<_, i64>(0))
            .optional()?;
        let Some(context_id) = selected else {
            return Ok(JvmImportContext::Unavailable);
        };
        let Some(source) = self.mount_table().mount_for_path("java", caller_path)? else {
            return Ok(JvmImportContext::Unavailable);
        };
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let file_version = source_record.file_version_id();
        // Package identity belongs to the selected content, including unsaved
        // replacements. Source-root/classpath access remains separately proven.
        let source_package: Option<String> = connection
            .query_row(
                "SELECT content_package FROM main.blob_meta WHERE blob_id=?1 AND is_complete=1",
                [source_record.blob_id()],
                |row| row.get(0),
            )
            .optional()?;
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
        let lexical = self.ready.lexical_source();
        let mut imports = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &identities,
            &lexical,
            &lexical,
            Some(&[source.ordinal()]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                imports.extend_from_slice(page);
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(JvmImportContext::Cancelled);
        }
        // Inventory uncertainty describes routes we have not enumerated. A
        // positive source bridge carries its own source/declaration access
        // evidence; unrelated inventory gaps must not taint that witness.
        let mut bridges = Vec::new();
        let mut external_static_imports = Vec::new();
        // All namespace demands of one import must close before its source
        // placeholder can retire. A found member is not an exhaustive search.
        struct StaticImportSearch {
            source_site: Option<ResolutionSiteId>,
            staged: bool,
            complete: bool,
            found: bool,
            kind: ResolutionImportRouteKind,
        }
        let mut static_import_searches = BTreeMap::new();
        let mut scoped_gaps = Vec::new();
        for import in imports {
            let SelectedRootPathHalf::Import {
                route,
                token,
                anchor,
                anchor_semantic,
                demand,
                ..
            } = import
            else {
                continue;
            };
            let Some(import_route) = selected_import_route(
                connection,
                source_record.blob_id(),
                source.ordinal(),
                token,
            )?
            else {
                continue;
            };
            let kind = import_route.kind.as_str();
            if !matches!(
                kind,
                "single_type" | "type_on_demand" | "single_static" | "static_on_demand"
            ) {
                // Actual token provenance is required before composing an import.
                continue;
            }
            let import_kind = match kind {
                "single_type" => ResolutionImportRouteKind::SingleType,
                "type_on_demand" => ResolutionImportRouteKind::TypeOnDemand,
                "single_static" => ResolutionImportRouteKind::SingleStatic,
                "static_on_demand" => ResolutionImportRouteKind::StaticOnDemand,
                _ => unreachable!("Java import kind was checked above"),
            };
            let mut semantics = route.into_vec();
            semantics.push(demand);
            let mut recipes = Vec::with_capacity(semantics.len());
            for page in semantics.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
                let requests = page
                    .iter()
                    .map(|&semantic| SelectedLookupRecipeRequest {
                        fragment: source.fragment(),
                        semantic,
                    })
                    .collect::<Vec<_>>();
                let SelectedLookupRecipeReadOutcome::Ready(rows) =
                    lexical.lookup_semantic_recipes(&requests, cancellation, None)?
                else {
                    return Ok(JvmImportContext::Cancelled);
                };
                for recipe in rows {
                    recipes.push(recipe.ok_or_else(|| {
                        StoreError::corrupt("selected Java root lookup has no shared recipe")
                    })?);
                }
            }
            let demand_recipe = recipes.pop().expect("one import demand");
            let mut owner_found = false;
            let Some(member_inventory) = self.jvm_type_member_import_candidates(
                context_id,
                file_version,
                &JavaMemberImportDemand {
                    import_kind: Some(import_kind),
                    source: source.fragment(),
                    caller_package: source_package.as_deref(),
                    token,
                    prefix_reference: None,
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
                &mut owner_found,
            )?
            else {
                return Ok(JvmImportContext::Cancelled);
            };
            let static_search_complete = if matches!(
                import_kind,
                ResolutionImportRouteKind::SingleStatic | ResolutionImportRouteKind::StaticOnDemand
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
            let JavaTypeMemberImportInventory {
                members,
                workspace_type_rows,
                workspace_inventory_complete: member_inventory_complete,
                ..
            } = member_inventory;
            match kind {
                "single_static" | "static_on_demand" => {
                    let member = demand_recipe.spelling().to_string();
                    if !owner_found {
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
                        && static_members
                            .iter()
                            .all(|bridge| bridge.completion() == &ResolutionCompletion::Complete);
                    let search = static_import_searches
                        .entry((import_route.source_site, import_route.staged))
                        .or_insert(StaticImportSearch {
                            source_site: import_route.source_site,
                            staged: import_route.staged,
                            complete: true,
                            found: false,
                            kind: import_kind,
                        });
                    search.complete &= search_complete;
                    search.found |= !static_members.is_empty();
                    bridges.extend(static_members);
                    continue;
                }
                "single_type" => {
                    let path = recipes
                        .iter()
                        .map(|recipe| recipe.spelling().to_owned())
                        .chain(std::iter::once(demand_recipe.spelling().to_owned()))
                        .collect::<Vec<_>>();
                    let Some(package_inventory) = self.java_package_type_import_inventory(
                        context_id,
                        file_version,
                        &JavaMemberImportDemand {
                            import_kind: Some(import_kind),
                            source: source.fragment(),
                            caller_package: source_package.as_deref(),
                            token,
                            prefix_reference: None,
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
                    let targets = match proof {
                        JavaSingleTypeImportProof::Proven(unit) => {
                            if let Some(source_site) = import_route.source_site {
                                for reason in selected_java_import_route_gap_reasons(
                                    connection,
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
                            if targets.is_empty() && gap == JavaImportSplitGap::MissingDestination {
                                let owner = recipes
                                    .iter()
                                    .map(ResolutionLookupSemanticRecipe::spelling)
                                    .collect::<Vec<_>>()
                                    .join(".");
                                let declared = format!("{owner}.{}", demand_recipe.spelling());
                                let mut selected_packages =
                                    connection.prepare_cached(JVM_IMPORT_TARGET_MOUNTS)?;
                                let mut selected_packages = selected_packages
                                    .query_map([&owner], |row| row.get::<_, u32>(0))?;
                                let package_prefix_found =
                                    selected_packages.next().transpose()?.is_some();
                                if !package_prefix_found
                                    && self.model_declares_jvm_type(&declared)?
                                {
                                    let model_owner = self.model_declared_jvm_owner(&declared)?;
                                    let boundary = register_model_declared_jvm_type_identity(
                                        token,
                                        &declared,
                                        model_owner.as_ref(),
                                        &identities,
                                        &self.ready.shared_names(),
                                    );
                                    let mut gap = self.jvm_import_context_gap(
                                        JvmImportContextGapSpec {
                                            context_id,
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
                                    gap.reason = boundary;
                                    scoped_gaps.push(gap);
                                } else if !package_prefix_found {
                                    let mut gap = self.jvm_import_context_gap(
                                        JvmImportContextGapSpec {
                                            context_id,
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
                                    identities
                                        .record_jvm_unindexed_import_owner(identity, &declared);
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
                    continue;
                }
                "type_on_demand" => {
                    bridges.extend(members.into_iter().map(|member| member.bridge));
                }
                _ => unreachable!("Java import kind was checked above"),
            }
            let Some(package_bridges) = self.java_package_type_import_bridges(
                context_id,
                file_version,
                &JavaMemberImportDemand {
                    import_kind: Some(import_kind),
                    source: source.fragment(),
                    caller_package: source_package.as_deref(),
                    token,
                    prefix_reference: None,
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
            bridges.extend(package_bridges);
        }
        let SelectedPackageRows::Ready(package_references) =
            self.selected_package_references(source.ordinal(), cancellation)?
        else {
            return Ok(JvmImportContext::Cancelled);
        };
        let package_references = unique_package_references_by_token(&package_references)?;
        let mut package_bridges = Vec::new();
        for package in source_package.iter() {
            let targets = self.jvm_import_targets(JAVA_IMPORT_TARGET_MOUNTS, package)?;
            for (target, target_file_version) in targets.ordered.iter().copied() {
                if cancellation.is_cancelled() {
                    return Ok(JvmImportContext::Cancelled);
                }
                let ordinal = SelectedResolutionMountOrdinal::new(target);
                if ordinal == source.ordinal() {
                    continue;
                }
                let target_mount = self.mount_table().mount_by_ordinal(ordinal)?;
                let Some(access) = self.jvm_source_access_completion(
                    context_id,
                    file_version,
                    source.persisted_relative_path(),
                    target_file_version,
                    target_mount.persisted_relative_path(),
                    &ResolutionCompletion::Complete,
                )?
                else {
                    continue;
                };
                let SelectedPackageRows::Ready(members_by_lookup) =
                    self.selected_package_members_by_lookup(ordinal, cancellation)?
                else {
                    return Ok(JvmImportContext::Cancelled);
                };
                for reference in &package_references {
                    if cancellation.is_cancelled() {
                        return Ok(JvmImportContext::Cancelled);
                    }
                    if let Some(members) = members_by_lookup.get(&reference.lookup) {
                        for member in members {
                            if member.domain != reference.domain
                                || member.namespace != reference.namespace
                            {
                                continue;
                            }
                            let access = match self.jvm_declaration_access(
                                member.definition,
                                JvmPackageRelation::Same,
                                &access,
                                cancellation,
                            )? {
                                JvmDeclarationAccess::Ready(completion) => completion,
                                JvmDeclarationAccess::Excluded => continue,
                                JvmDeclarationAccess::Cancelled => {
                                    return Ok(JvmImportContext::Cancelled);
                                }
                            };
                            package_bridges.push(SelectedPackageBridgeDescriptor::new(
                                source.fragment(),
                                target_mount.fragment(),
                                Language::Java,
                                reference,
                                member,
                                access,
                            ));
                        }
                    }
                }
            }
        }
        for search in static_import_searches.into_values() {
            if search.complete
                && (search.found || search.kind == ResolutionImportRouteKind::StaticOnDemand)
                && let Some(source_site) = search.source_site
            {
                for reason in selected_java_import_route_gap_reasons(
                    connection,
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
            &|fragment| {
                Ok(mounts
                    .mount_for_fragment(fragment)?
                    .map(|mount| (mount.ordinal(), mount.semantic_language())))
            },
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
            context: Box::new(context.with_declaration_access_source(Arc::new(
                super::java_access::JvmAccessPolicy {
                    identity: access_identity,
                },
            ))),
            external_static_imports,
            inventory_reason: Some(reason),
            open_jvm_alias_imports: Vec::new(),
            scoped_gaps,
        })
    }
    fn jvm_source_access_completion(
        &self,
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
        if caller_path == target_path {
            // A declaration in the exact caller file is source-accessible
            // without project or source-root ownership facts.
            return Ok(Some(completion.clone()));
        }
        let key = self.jvm_source_access_key(context, caller, caller_path, target, target_path);
        let cached = self.jvm_source_access_memo.borrow().get(&key).copied();
        let access = if let Some(access) = cached {
            access
        } else {
            self.profile_jvm_read("derive_source_access", &key);
            let access = self.read_jvm_source_access_evidence(
                context,
                caller,
                caller_path,
                target,
                target_path,
            )?;
            self.jvm_source_access_memo.borrow_mut().insert(key, access);
            access
        };
        match access {
            JvmSourceAccessEvidence::Excluded => Ok(None),
            JvmSourceAccessEvidence::Known => Ok(Some(completion.clone())),
            JvmSourceAccessEvidence::Unknown(gap) => {
                Ok(Some(completion.combine(&ResolutionCompletion::incomplete(
                    [ResolutionIncompleteReason::UnsupportedSemantic(gap)],
                ))))
            }
        }
    }

    fn jvm_source_access_key(
        &self,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
    ) -> JvmSourceAccessKey {
        JvmSourceAccessKey {
            context,
            caller,
            caller_path: caller_path.to_owned(),
            target,
            target_path: target_path.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        }
    }

    fn read_jvm_source_access_evidence(
        &self,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
    ) -> Result<JvmSourceAccessEvidence> {
        debug_assert_ne!(caller_path, target_path);
        let connection = self.ready.inventory.connection();
        if self.in_implicit_project(context, caller, caller_path, target, target_path)? {
            return Ok(JvmSourceAccessEvidence::Known);
        }
        // Every caller and target arm in SOURCE_ACCESS requires a selected
        // project. Without one, the Maven relation cannot establish access;
        // preserve the open result without planning its expanded root views.
        let has_selected_project: bool = connection
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM main.jvm_selected_projects WHERE context_id=?1)",
            )?
            .query_row([context], |row| row.get(0))?;
        let access = if has_selected_project {
            connection
                .prepare_cached(SOURCE_ACCESS)?
                .query_row(
                    rusqlite::params![context, caller, caller_path, target, target_path],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .unwrap_or_else(|| "unknown".to_owned())
        } else {
            "unknown".to_owned()
        };
        match access.as_str() {
            "excluded" => Ok(JvmSourceAccessEvidence::Excluded),
            "known" => Ok(JvmSourceAccessEvidence::Known),
            "unknown" => {
                let mut hash = CanonicalHasher::new(b"bifrost-java-source-access-open:v1");
                hash.field("context", &context.to_le_bytes());
                if let Some(caller) = caller {
                    hash.field("caller", &caller.to_le_bytes());
                }
                if let Some(target) = target {
                    hash.field("target", &target.to_le_bytes());
                }
                let gap = self.ready.context_identities.named_semantic(
                    hash.finish(),
                    "java-source-access-open",
                    "Selected Maven root/dependency facts do not establish this source visibility",
                );
                Ok(JvmSourceAccessEvidence::Unknown(gap))
            }
            _ => unreachable!("source access SQL has three outcomes"),
        }
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
        if matches!(language, Language::Kotlin | Language::Scala)
            && self.in_implicit_project(context, caller, caller_path, target, target_path)?
        {
            return Ok(Some(completion.clone()));
        }
        self.jvm_source_access_completion(
            context,
            caller,
            caller_path,
            target,
            target_path,
            completion,
        )
    }

    /// Whether the reviewed JVM semantic model declares the type `fqn`. The
    /// model is the analyzer's active overlay for this request; without an
    /// analyzer or an overlay nothing is declared.
    fn model_declares_jvm_type(&self, fqn: &str) -> Result<bool> {
        if self
            .ready
            .analyzer
            .and_then(|analyzer| analyzer.semantic_model_overlay())
            .is_some_and(|overlay| {
                crate::analyzer::jvm::external::model_declares_external_type(&overlay, fqn)
            })
        {
            return Ok(true);
        }
        Ok(self.model_declared_jvm_owner(fqn)?.is_some())
    }

    fn model_declared_jvm_owner(
        &self,
        fqn: &str,
    ) -> Result<Option<crate::analyzer::resolution::ExternalOwnerIdentity>> {
        let Some(analyzer) = self.ready.analyzer else {
            return Ok(None);
        };
        if let Some(overlay) = analyzer.semantic_model_overlay()
            && let Some(owner) =
                crate::analyzer::jvm::external::model_declared_external_owner(&overlay, fqn)
        {
            return Ok(Some(owner));
        }
        let providers = crate::analyzer::languages::selected_external_inventory_providers(analyzer);
        if providers.is_empty() {
            return Ok(None);
        }
        let providers =
            serde_json::to_string(&providers).expect("string provider identities serialize");
        let provider: Option<String> = self.ready.inventory.connection().query_row(
            "SELECT CASE WHEN count(*)=1 THEN min(provider_id) END FROM main.jvm_external_owners WHERE owner_fqn=?1 AND provider_id IN (SELECT value FROM json_each(?2))",
            rusqlite::params![fqn, providers], |row| row.get(0))?;
        Ok(provider.map(
            |provider| crate::analyzer::resolution::ExternalOwnerIdentity {
                provider_id: std::sync::Arc::from(provider),
                owner_fqn: std::sync::Arc::from(fqn),
            },
        ))
    }

    /// A manifest-free JVM workspace is one implicit project when each exact
    /// selected JVM mount satisfies its language's package placement rule.
    /// Manifest-backed projects and paths without package evidence remain
    /// governed by the selected build model or an open source-access result.
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
        let key = self.jvm_source_access_key(context, caller, caller_path, target, target_path);
        if let Some(implicit) = self.jvm_implicit_project_memo.borrow().get(&key).copied() {
            return Ok(implicit);
        }
        self.profile_jvm_read("derive_implicit_project", &key);
        let implicit =
            self.read_jvm_implicit_project(context, caller, caller_path, target, target_path)?;
        self.jvm_implicit_project_memo
            .borrow_mut()
            .insert(key, implicit);
        Ok(implicit)
    }

    fn read_jvm_implicit_project(
        &self,
        context: i64,
        caller: Option<i64>,
        caller_path: &str,
        target: Option<i64>,
        target_path: &str,
    ) -> Result<bool> {
        let connection = self.ready.inventory.connection();
        let (has_manifest, context_language): (bool, String) = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.jvm_selected_projects WHERE context_id=?1)
                OR EXISTS(SELECT 1 FROM main.jvm_context_gaps
                          WHERE context_id=?1
                            AND code IN ('maven_configuration_unavailable', 'gradle_topology_unsupported')),
                   (SELECT lang FROM main.jvm_context_revisions WHERE context_id=?1)",
            [context],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if has_manifest {
            return Ok(false);
        }
        let query_language = Language::from_config_label(&context_language)
            .expect("selected JVM context has a known language");
        for (file_version, path) in [(caller, caller_path), (target, target_path)] {
            let mut statement = connection.prepare_cached(
                "SELECT DISTINCT m.file_version_id, bm.content_package, m.storage_language
                 FROM temp.selected_resolution_mounts AS m
                 JOIN main.blob_meta AS bm ON bm.blob_id=m.blob_id AND bm.is_complete=1
                 WHERE m.storage_language IN ('java', 'kotlin', 'scala')
                   AND m.persisted_relative_path=?1",
            )?;
            let selected_packages = statement
                .query_map([path], |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut matching_packages = selected_packages
                .into_iter()
                .filter(|(selected_version, _, _)| {
                    file_version.is_none_or(|version| *selected_version == Some(version))
                })
                .map(|(_, package, language)| {
                    let source_language = Language::from_config_label(&language)
                        .expect("selected JVM mount has a known language");
                    (
                        package,
                        language_jvm_package_requires_directory_agreement(
                            query_language,
                            source_language,
                        ),
                    )
                });
            let Some((Some(package), requires_directory)) = matching_packages.next() else {
                return Ok(false);
            };
            let directory_agrees = package_path_agrees_with_file_path(&package, path);
            if (!directory_agrees && requires_directory)
                || matching_packages.any(|(candidate, requires_directory)| {
                    candidate.as_deref() != Some(package.as_str())
                        || (!directory_agrees && requires_directory)
                })
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn jvm_declaration_access(
        &self,
        definition: SemanticId,
        package: JvmPackageRelation,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<JvmDeclarationAccess> {
        let Some(visibilities) = self.jvm_declaration_visibilities(definition, cancellation)?
        else {
            return Ok(JvmDeclarationAccess::Cancelled);
        };
        let known = match (visibilities.as_ref(), package) {
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

#[derive(Debug)]
pub(super) struct SelectedJvmImportSelector {
    kind: ResolutionImportSelectorKind,
    pub(super) source_name: Option<String>,
    pub(super) local_name: Option<String>,
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
    let mut routes = Vec::with_capacity(3 + enclosing_scope_routes.len());
    if language == Language::Scala && anchor == ResolutionRootImportAnchor::Lexical {
        if let Some(earlier_route) = earlier_route {
            routes.push(earlier_route.to_vec());
        }
        routes.extend(enclosing_scope_routes.iter().cloned());
    }
    if language == Language::Scala && anchor == ResolutionRootImportAnchor::Lexical {
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
    if language == Language::Scala && anchor == ResolutionRootImportAnchor::Lexical {
        routes.extend(chained_wildcard_routes.iter().cloned());
    }
    routes.push(route.to_vec());
    routes
}

pub(super) fn selected_jvm_import_selector(
    connection: &rusqlite::Connection,
    blob_id: i64,
    token: SemanticId,
) -> Result<Option<SelectedJvmImportSelector>> {
    let Some(local_key) = token.local_key() else {
        return Ok(None);
    };
    let row = connection
        .prepare_cached(SELECTED_IMPORT_SELECTOR)?
        .query_row(rusqlite::params![blob_id, local_key], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .optional()?;
    let Some((kind, source_name, local_name)) = row else {
        return Ok(None);
    };
    let kind = ResolutionImportSelectorKind::from_label(&kind)
        .expect("selected import-selector kind is constrained by its schema");
    assert!(match kind {
        ResolutionImportSelectorKind::Named => source_name.is_some(),
        ResolutionImportSelectorKind::Star => source_name.is_none() && local_name.is_none(),
        ResolutionImportSelectorKind::ReceiverMember => source_name.is_some(),
    });
    Ok(Some(SelectedJvmImportSelector {
        kind,
        source_name,
        local_name,
    }))
}

pub(super) struct SelectedImportRoute {
    pub(super) kind: String,
    source_site: Option<ResolutionSiteId>,
    staged: bool,
}

pub(super) fn selected_import_route(
    connection: &rusqlite::Connection,
    blob_id: i64,
    source: SelectedResolutionMountOrdinal,
    token: SemanticId,
) -> Result<Option<SelectedImportRoute>> {
    let (runtime_key, shared_id) = super::super::resolution_stage::lexical::semantic_cells(token);
    let staged = connection
        .query_row(
            "SELECT c.import_route_kind,c.import_source_site FROM temp.selected_resolution_stage_semantic_coordinates c
             JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=c.host_ordinal
             WHERE c.runtime_key IS ?1 AND c.shared_id IS ?2 AND c.host_ordinal=?3",
            rusqlite::params![runtime_key, shared_id, source.get()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<u32>>(1)?,
                ))
            },
        )
        .optional()?;
    if let Some((kind, source_site)) = staged {
        return Ok(kind.map(|kind| SelectedImportRoute {
            kind,
            source_site: source_site.map(ResolutionSiteId::new),
            staged: true,
        }));
    }
    let Some(token_key) = token.local_key() else {
        return Ok(None);
    };
    let route = connection
        .query_row(
            "SELECT import_route_kind,import_source_site FROM main.resolution_semantic_catalog
             WHERE blob_id=?1 AND local_key=?2",
            rusqlite::params![blob_id, token_key],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<u32>>(1)?,
                ))
            },
        )
        .optional()?;
    Ok(route.and_then(|(kind, source_site)| {
        kind.map(|kind| SelectedImportRoute {
            kind,
            source_site: source_site.map(ResolutionSiteId::new),
            staged: false,
        })
    }))
}

fn selected_java_import_route_gap_reasons(
    connection: &rusqlite::Connection,
    blob_id: i64,
    source: SelectedResolutionMountOrdinal,
    source_site: ResolutionSiteId,
    staged: bool,
) -> Result<Vec<SemanticId>> {
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

/// Whether a selected JVM package's components match the suffix of its file
/// directory. The package comes from structured selected metadata, and paths
/// remain platform-native until their components are compared. For the default
/// package, every directory agrees.
fn package_path_agrees_with_file_path(package: &str, file_path: &str) -> bool {
    let directory = std::path::Path::new(file_path)
        .parent()
        .map(|parent| parent.components().collect::<Vec<_>>())
        .unwrap_or_default();
    let package = if package.is_empty() {
        Vec::new()
    } else {
        package.split('.').collect::<Vec<_>>()
    };
    directory.len() >= package.len()
        && directory[directory.len() - package.len()..]
            .iter()
            .zip(&package)
            .all(|(component, segment)| component.as_os_str() == std::ffi::OsStr::new(segment))
}

pub(super) fn is_jvm_language(language: Language) -> bool {
    matches!(
        language,
        Language::Java | Language::Kotlin | Language::Scala
    )
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
    SemanticId::shared_name(names.intern(hash.finish()))
}

/// An explicit import whose owner package has no selected route, but whose
/// type the reviewed JVM model declares.
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
    routes: &[ModelDeclaredJvmImportRoute],
    package_reference_occurrences: &[crate::analyzer::resolution::LoweredPackageReference],
    unqualified_type_references: &BTreeSet<SemanticId>,
    identities: &SelectedContextIdentities,
    names: &dyn SharedNameInterner,
) {
    for route in routes {
        let lookup = route.lookup.semantic(names);
        for reference in package_reference_occurrences {
            if reference.token == route.source_token
                && reference.lookup == lookup
                && reference.namespace == ResolutionNamespace::Type
                && unqualified_type_references.contains(&reference.reference)
            {
                register_model_declared_jvm_type_identity(
                    reference.reference,
                    &route.declared_fqn,
                    route.owner.as_ref(),
                    identities,
                    names,
                );
            }
        }
    }
}

fn register_model_declared_jvm_type_identity(
    reference: SemanticId,
    declared_fqn: &str,
    owner: Option<&crate::analyzer::resolution::ExternalOwnerIdentity>,
    identities: &SelectedContextIdentities,
    names: &dyn SharedNameInterner,
) -> SemanticId {
    let identity = owner.map_or_else(
        || model_declared_jvm_type_identity(declared_fqn, names),
        |owner| identities.external_owner_semantic(owner, names),
    );
    let mut hash = CanonicalHasher::new(b"bifrost-jvm-model-declared-type-boundary:v1");
    hash.field("declared-type-fqn", declared_fqn.as_bytes());
    let enumeration_boundary = identities.named_semantic(
        hash.finish(),
        "jvm-model-declared-type",
        &format!("the reviewed JVM model declares `{declared_fqn}`; its members are enumerated from the model only"),
    );
    identities.record_jvm_external_provider_type_identity(
        reference,
        enumeration_boundary,
        identity,
        enumeration_boundary,
    );
    enumeration_boundary
}

struct JvmExternalProviderIdentityRegistration<'a, 'lexical, 'source> {
    source_language: Language,
    gaps: &'a [JvmImportContextGap],
    package_reference_occurrences: &'a [crate::analyzer::resolution::LoweredPackageReference],
    unqualified_type_references: &'a BTreeSet<SemanticId>,
    durable_owners: &'a BTreeMap<String, crate::analyzer::resolution::ExternalOwnerIdentity>,
    lexical: &'a crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource<
        'lexical,
        'source,
    >,
    source_fragment: BindingFragmentId,
    identities: &'a SelectedContextIdentities,
    names: &'a dyn SharedNameInterner,
    cancellation: &'a CancellationToken,
}

fn register_jvm_external_provider_type_identities(
    registration: JvmExternalProviderIdentityRegistration<'_, '_, '_>,
) -> Result<()> {
    let JvmExternalProviderIdentityRegistration {
        source_language,
        gaps,
        package_reference_occurrences,
        unqualified_type_references,
        durable_owners,
        lexical,
        source_fragment,
        identities,
        names,
        cancellation,
    } = registration;
    let providers = language_implicit_root_providers(source_language);
    let mut references_by_route =
        std::collections::BTreeMap::<(SemanticId, SemanticId), Vec<SemanticId>>::new();
    for reference in package_reference_occurrences {
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
        if !gap
            .source_reference
            .is_some_and(|reference| unqualified_type_references.contains(&reference))
        {
            continue;
        }
        gaps_by_lookup
            .entry((gap.source_token, gap.lookup.clone()))
            .or_default()
            .push((provider, gap.reason));
    }

    for ((source_token, lookup), provider_gaps) in gaps_by_lookup {
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
        let provider_names = ordered_providers
            .iter()
            .map(|provider| match provider {
                JvmImplicitRootProvider::Package(package) => *package,
                JvmImplicitRootProvider::ScalaPredef => SCALA_PREDEF_DEFAULT_IMPORT,
            })
            .collect::<Vec<_>>();
        let mut boundary_hash = CanonicalIdentityDescriptor::new(
            b"bifrost-jvm-external-provider-enumeration-boundary:v1",
            |key| selected_identity_content_digest(identities, lexical, key, cancellation),
        );
        boundary_hash.field("type-identity", CanonicalIdentityPart::identity(identity))?;
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
                    reference,
                    source_boundary,
                    identity,
                    enumeration_boundary,
                );
            }
        }
    }

    if source_language == Language::Java {
        let implicit_providers = providers
            .iter()
            .copied()
            .filter(|provider| matches!(provider, JvmImplicitRootProvider::Package("java.lang")))
            .collect::<Vec<_>>();
        for ((source_token, lookup_semantic), references) in references_by_route {
            let request = crate::analyzer::store::resolution_lexical::SelectedLookupRecipeRequest {
                fragment: source_fragment,
                semantic: lookup_semantic,
            };
            let crate::analyzer::store::resolution_lexical::SelectedLookupRecipeReadOutcome::Ready(
                recipes,
            ) = lexical.lookup_semantic_recipes(&[request], cancellation, None)?
            else {
                return Ok(());
            };
            let lookup = recipes[0]
                .as_ref()
                .expect("selected Java type reference has a lookup recipe");
            if gaps
                .iter()
                .any(|gap| gap.source_token == source_token && gap.lookup == *lookup)
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
            let mut boundary_hash = CanonicalIdentityDescriptor::new(
                b"bifrost-jvm-external-provider-enumeration-boundary:v1",
                |key| selected_identity_content_digest(identities, lexical, key, cancellation),
            );
            boundary_hash.field("type-identity", CanonicalIdentityPart::identity(identity))?;
            let enumeration_boundary = identities.named_semantic(
                boundary_hash.finish(),
                "jvm-external-provider-type",
                &format!(
                    "implicit Java provider java.lang is unindexed for type `{}`",
                    lookup.spelling()
                ),
            );
            for reference in references {
                identities.record_jvm_external_provider_type_identity(
                    reference,
                    enumeration_boundary,
                    identity,
                    enumeration_boundary,
                );
            }
        }
    }
    Ok(())
}

impl JvmImportContext {
    fn with_open_inventory_gap(self) -> Self {
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

struct JavaMemberImportDemand<'a> {
    import_kind: Option<ResolutionImportRouteKind>,
    caller_package: Option<&'a str>,
    source: BindingFragmentId,
    token: SemanticId,
    prefix_reference: Option<SemanticId>,
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

/// The mount query a language's type-member continuation reads, or `None`
/// while the language has not adopted the continuation. Source and target
/// share the language. Java static imports can widen this inventory through
/// the selected target's owner-namespace hook and explicit JVM bridge proof.
const fn jvm_member_continuation_mounts(language: Language) -> Option<&'static str> {
    match language {
        Language::Java => Some(JAVA_IMPORT_TARGET_MOUNTS),
        Language::Kotlin | Language::Scala => Some(JVM_IMPORT_TARGET_MOUNTS),
        _ => None,
    }
}

fn jvm_member_name_matches(language: Language, selected: &str, requested: &str) -> bool {
    selected == requested
        || (language == Language::Scala
            && selected
                .strip_suffix('$')
                .is_some_and(|selected| selected == requested))
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
        let mut halves = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &self.ready.context_identities,
            &lexical,
            &lexical,
            Some(&[ordinal]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                halves.extend_from_slice(page);
                Ok(true)
            }),
        )?;
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

    pub(super) fn scala_selected_import_member_bridges(
        &self,
        half: &SelectedRootPathHalf,
        owners: &[SemanticId],
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let SelectedRootPathHalf::Import {
            identity,
            token,
            route,
            demand,
            anchor,
            anchor_semantic,
            precedence,
            ..
        } = half
        else {
            unreachable!("a selected import member belongs to an import");
        };
        let Some(mut recipes) = self.jvm_lookup_recipes(
            identity.fragment(),
            route.iter().copied().chain([*demand]),
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let demand = recipes.pop().expect("import demand");
        let Some(read) = self.jvm_qualified_prefix_member_candidates(
            owners,
            demand.spelling(),
            demand.namespace(),
            Language::Scala,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let source_mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("import source remains selected");
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source_mount.ordinal())?;
        let connection = self.ready.inventory.connection();
        let caller_package: Option<String> = connection.query_row(
            "SELECT content_package FROM main.blob_meta WHERE blob_id=?1",
            [source_record.blob_id()],
            |row| row.get(0),
        )?;
        let caller_package = self
            .scala_import_package_prefixes(source_record.blob_id(), *token)?
            .pop()
            .or(caller_package);
        let selector = selected_jvm_import_selector(connection, source_record.blob_id(), *token)?;
        let mut publication = JvmRoutePublication {
            bridges: Vec::new(),
            selected_targets: BTreeSet::new(),
            complete: read.complete
                && (owners.is_empty() || !read.candidates.is_empty())
                && completion == &ResolutionCompletion::Complete,
        };
        for (owner, definition, unit, _) in read.candidates {
            let ordinal = SelectedResolutionMountOrdinal::new(
                definition.ordinal().expect("selected member is mounted"),
            );
            let mount = self.mount_table().mount_by_ordinal(ordinal)?;
            if !is_jvm_language(mount.semantic_language()) {
                publication.complete = false;
                continue;
            }
            // The receiver binding and shared hierarchy selection already
            // prove the owner route. A declaring ancestor need not itself be
            // directly importable from this caller. Retain that evidence and
            // check the selected member's declaration visibility below.
            let access = match self.jvm_declaration_access(
                definition,
                JvmPackageRelation::between(caller_package.as_deref(), unit.package_name()),
                completion,
                cancellation,
            )? {
                JvmDeclarationAccess::Ready(access) => access,
                JvmDeclarationAccess::Excluded => continue,
                JvmDeclarationAccess::Cancelled => return Ok(None),
            };
            publication.complete &= access == ResolutionCompletion::Complete;
            let Some(node) = self
                .ready
                .lexical_source()
                .lookup_definition_node(definition, cancellation)?
            else {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                return Err(StoreError::corrupt(
                    "selected Scala import member lacks its definition node",
                ));
            };
            let import = JavaMemberImportDemand {
                import_kind: None,
                caller_package: caller_package.as_deref(),
                source: identity.fragment(),
                token: *token,
                prefix_reference: None,
                anchor: *anchor,
                anchor_semantic: *anchor_semantic,
                selector_kind: selector.as_ref().map(|selector| selector.kind),
                import_precedence: precedence
                    .iter()
                    .copied()
                    .find(|step| step.tier != PrecedenceTier::CandidateOriginRank),
                candidate_origin_rank: precedence
                    .iter()
                    .find(|step| step.tier == PrecedenceTier::CandidateOriginRank)
                    .map(|step| step.ordinal),
                route: &recipes,
                lookup_route: &recipes,
                demand: &demand,
                language: Language::Scala,
            };
            publication.bridges.push(
                import
                    .bridge(mount.fragment(), owner, access)
                    .with_selected_member_definition(node),
            );
            publication.selected_targets.insert(definition);
        }
        Ok(Some(publication))
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

    fn scala_primary_package(&self, blob: i64) -> Result<Option<String>> {
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
    fn scala_import_package_prefixes(&self, blob: i64, token: SemanticId) -> Result<Vec<String>> {
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
                        ResolutionLookupSemanticRecipe::new(
                            Language::Scala,
                            ResolutionNamespace::Type,
                            spelling,
                        )
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
                        let implicit_root = if language == Language::Java {
                            row.source_kind() == Some(ResolutionSupertypeKind::ImplicitSuperclass)
                        } else {
                            row.kind() == ResolutionSupertypeKind::ImplicitSuperclass
                        };
                        inherits |= !implicit_root;
                        if language == Language::Java && implicit_root {
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
                            // Java's implicit Object edge contributes only the
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
            let java_static_import = import.language == Language::Java
                && matches!(
                    import.import_kind,
                    Some(
                        ResolutionImportRouteKind::SingleStatic
                            | ResolutionImportRouteKind::StaticOnDemand
                    )
                );
            let mounts = if java_static_import {
                JVM_IMPORT_TARGET_MOUNTS
            } else {
                jvm_member_continuation_mounts(import.language)
                    .expect("a type-member continuation runs only for an adopting language")
            };
            let targets = self.jvm_import_targets(mounts, &package)?;
            let relation = JvmPackageRelation::between(import.caller_package, &package);
            let caller_mount = self
                .mount_table()
                .mount_for_fragment(import.source)?
                .expect("Java import source remains selected");
            for (ordinal, version) in targets.rows.iter().copied() {
                let target_ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
                let target_language = target_mount.semantic_language();
                let outer_namespace = if java_static_import {
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
                    match target_language {
                        Language::Scala => ResolutionNamespace::Value,
                        _ => ResolutionNamespace::Type,
                    }
                };
                let outer_lookup = ResolutionLookupSemanticRecipe::new(
                    target_language,
                    outer_namespace,
                    import.lookup_route[package_length].spelling(),
                )
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
                let exports = exports_read.halves.iter()
                    .filter(|half| matches!(half, SelectedRootPathHalf::Export { demand, .. } if *demand == outer_lookup))
                    .cloned();
                route_search_complete &=
                    outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete;
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
                                            || (import.language == Language::Scala
                                                && namespace == ResolutionNamespace::Callable
                                                && matches!(
                                                    member.kind(),
                                                    ResolutionMemberKind::Field
                                                        | ResolutionMemberKind::NestedType
                                                ));
                                        let singleton_value = import.language == Language::Scala
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
                                                || (import.language == Language::Scala
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
                                                || (import.language == Language::Scala
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
                            || !supertypes.is_empty();
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
                            let target_demand = ResolutionLookupSemanticRecipe::new(
                                target_language,
                                import.demand.namespace(),
                                import.demand.spelling(),
                            );
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
        let origin = match self.import_kind {
            Some(
                ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic,
            ) => Some(BindingOrigin::SingleTypeImport),
            Some(
                ResolutionImportRouteKind::TypeOnDemand | ResolutionImportRouteKind::StaticOnDemand,
            ) => Some(BindingOrigin::OnDemandImport),
            _ => match self.selector_kind {
                Some(ResolutionImportSelectorKind::Named) => Some(BindingOrigin::ExplicitImport),
                Some(ResolutionImportSelectorKind::Star) if self.language == Language::Kotlin => {
                    Some(BindingOrigin::StarImport)
                }
                Some(ResolutionImportSelectorKind::Star) => Some(BindingOrigin::WildcardImport),
                Some(ResolutionImportSelectorKind::ReceiverMember) | None => None,
            },
        };
        let rank = self
            .candidate_origin_rank
            .or_else(|| origin.and_then(|origin| binding_origin_rank(self.language, origin)));
        bridge
            .with_precedence(precedence)
            .with_candidate_origin_rank(rank)
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
        let targets = self.jvm_import_targets(JAVA_IMPORT_TARGET_MOUNTS, &spelling)?;
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
            let source_access = self.jvm_source_access_completion(
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
            let Some(exports_read) = self.jvm_root_exports(ordinal, cancellation)? else {
                return Ok(None);
            };
            let outcome = &exports_read.outcome;
            let exports = exports_read.halves.iter().cloned();
            if target_file_version.is_some() && collect_workspace_type_rows {
                workspace_inventory_complete &=
                    outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete;
            }
            for export in exports {
                let SelectedRootPathHalf::Export {
                    identity,
                    token: export_token,
                    demand: export_demand,
                    definition,
                    incomplete_reasons,
                    ..
                } = &export
                else {
                    unreachable!("export-only visitor")
                };
                if *export_demand != demand {
                    continue;
                }
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
                        StoreError::corrupt("Java export lacks a declaration endpoint")
                    })?;
                let bridge_completion = source_access.clone();
                let relation = JvmPackageRelation::between(import.caller_package, &spelling);
                let bridge_completion = match self.jvm_declaration_access(
                    definition_semantic,
                    relation,
                    &bridge_completion,
                    cancellation,
                )? {
                    JvmDeclarationAccess::Ready(completion) => completion,
                    JvmDeclarationAccess::Excluded => continue,
                    JvmDeclarationAccess::Cancelled => {
                        return Ok(None);
                    }
                };
                if target_file_version.is_some()
                    && collect_workspace_type_rows
                    && !incomplete_reasons.is_empty()
                {
                    workspace_inventory_complete = false;
                }
                let target_file = ProjectFile::new(
                    self.ready.project.root().to_path_buf(),
                    target_mount.persisted_relative_path(),
                );
                let unit = if collect_workspace_type_rows {
                    let unit = self.java_selected_type_unit(
                        ordinal,
                        &target_file,
                        definition_semantic,
                        cancellation,
                    )?;
                    if unit.is_none() && cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    if target_file_version.is_some() && unit.is_none() {
                        workspace_inventory_complete = false;
                    }
                    unit
                } else {
                    None
                };
                if target_file_version.is_some()
                    && let Some(unit) = &unit
                {
                    workspace_type_rows.push((definition_semantic, unit.clone()));
                }
                let bridge = import
                    .bridge(identity.fragment(), *export_token, bridge_completion)
                    .with_selected_export(&self.ready.shared_names(), &export);
                candidates.push(JavaPackageTypeImportCandidate {
                    unit,
                    workspace_source: target_file_version.is_some(),
                    bridge,
                });
                if !collect_workspace_type_rows {
                    return Ok(Some(JavaPackageTypeImportInventory {
                        candidates,
                        workspace_type_rows,
                        workspace_inventory_complete,
                    }));
                }
            }
        }
        Ok(Some(JavaPackageTypeImportInventory {
            candidates,
            workspace_type_rows,
            workspace_inventory_complete,
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
        let SelectedRootPathHalf::Reference {
            identity,
            source_reference,
            ..
        } = half
        else {
            unreachable!("qualified JVM demand has a reference half");
        };
        let source_mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("selected source half has its mount");
        if source_mount.semantic_language() == Language::Java {
            return Ok(self
                .java_qualified_type_bridges(half, completion, cancellation)?
                .map(|bridges| JvmRoutePublication {
                    bridges,
                    selected_targets: BTreeSet::new(),
                    complete: false,
                }));
        }
        let Some(mut publication) =
            self.jvm_qualified_type_exports(half, completion, cancellation)?
        else {
            return Ok(None);
        };
        if source_mount.semantic_language() == Language::Scala {
            let Some(import_head) =
                self.jvm_lexical_import_qualifier(*source_reference, cancellation)?
            else {
                return Ok(None);
            };
            if import_head {
                let rank = binding_origin_rank(Language::Scala, BindingOrigin::RootPackage);
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
        if mount.semantic_language() != Language::Scala
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
        assert!(matches!(
            source_language,
            Language::Kotlin | Language::Scala
        ));
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
        let targets = self.jvm_import_targets(JVM_IMPORT_TARGET_MOUNTS, &package)?;
        let mut bridges = Vec::new();
        let mut selected_targets = BTreeSet::new();
        let mut route_complete =
            completion == &ResolutionCompletion::Complete && !targets.ordered.is_empty();
        let relation = JvmPackageRelation::between(caller_package.as_deref(), &package);
        for (ordinal, target_version) in targets.ordered.iter().copied() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let target_ordinal = SelectedResolutionMountOrdinal::new(ordinal);
            let target_mount = self.mount_table().mount_by_ordinal(target_ordinal)?;
            let target_language = target_mount.semantic_language();
            if !is_jvm_language(target_language) {
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
            let target_lookup = ResolutionLookupSemanticRecipe::new(
                target_language,
                source_namespace,
                source_demand.spelling(),
            );
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
        if jvm_member_continuation_mounts(source_language).is_some() {
            // The package route may also end inside a type: `pkg.Outer.Inner`
            // names a member of the type the package declares.
            let import = JavaMemberImportDemand {
                import_kind: None,
                caller_package: caller_package.as_deref(),
                source: identity.fragment(),
                token: *token,
                prefix_reference: *prefix_reference,
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

    /// Continue a selected JVM type-or-value prefix through its own member
    /// scope. The root path's lexical prefix already selected the owner, so
    /// this route starts from that selected declaration and publishes only
    /// the exact terminal member proved by its structured member rows.
    pub(super) fn jvm_qualified_prefix_member_bridges(
        &self,
        half: &SelectedRootPathHalf,
        prefix_targets: &[SemanticId],
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmRoutePublication>> {
        let SelectedRootPathHalf::Reference {
            identity,
            prefix_reference: Some(prefix_reference),
            route,
            token,
            anchor,
            anchor_semantic,
            demand,
            ..
        } = half
        else {
            return Ok(Some(JvmRoutePublication {
                bridges: Vec::new(),
                selected_targets: BTreeSet::new(),
                complete: false,
            }));
        };
        let source_mount = self
            .mount_table()
            .mount_for_fragment(identity.fragment())?
            .expect("selected source half has its mount");
        let source_language = source_mount.semantic_language();
        if !matches!(source_language, Language::Kotlin | Language::Scala) {
            return Ok(Some(JvmRoutePublication {
                bridges: Vec::new(),
                selected_targets: BTreeSet::new(),
                complete: false,
            }));
        }
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
        // The selected prefix may itself be the whole receiver, leaving only
        // the terminal member demand in this half's route.
        if !matches!(
            source_demand.namespace(),
            ResolutionNamespace::Type
                | ResolutionNamespace::Value
                | ResolutionNamespace::Callable
                | ResolutionNamespace::TypeOrValue
        ) {
            return Ok(Some(JvmRoutePublication {
                bridges: Vec::new(),
                selected_targets: BTreeSet::new(),
                complete: false,
            }));
        }
        let Some(owner_routes) =
            self.jvm_qualified_prefix_member_owners(prefix_targets, source_language, cancellation)?
        else {
            return Ok(None);
        };
        let owners = owner_routes
            .iter()
            .map(|(_, owner)| *owner)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let owner_roots = owner_routes.into_iter().collect::<BTreeMap<_, _>>();
        let mut owner_access_complete = true;
        let mut owners_are_in_caller_file = true;
        for owner in &owners {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = owner.ordinal() else {
                owner_access_complete = false;
                continue;
            };
            let owner_mount = SelectedResolutionMountOrdinal::new(ordinal);
            let owner_record = self.ready.inventory.mount_record_by_ordinal(owner_mount)?;
            owners_are_in_caller_file &=
                owner_record.file_version_id() == source_record.file_version_id();
            let Some(access) = self.jvm_qualified_source_access_completion(
                source_language,
                context,
                source_record.file_version_id(),
                source_record.persisted_relative_path(),
                owner_record.file_version_id(),
                owner_record.persisted_relative_path(),
                &ResolutionCompletion::Complete,
            )?
            else {
                owner_access_complete = false;
                continue;
            };
            owner_access_complete &= access == ResolutionCompletion::Complete;
        }
        let Some(mut member_read) = self.jvm_qualified_prefix_member_candidates(
            &owners,
            source_demand.spelling(),
            source_demand.namespace(),
            source_language,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut route_complete = completion == &ResolutionCompletion::Complete
            && member_read.complete
            && owner_access_complete
            && !owners.is_empty();
        let mut candidates = member_read
            .candidates
            .drain(..)
            .filter_map(|(member_owner, definition, unit, access)| {
                owner_roots
                    .get(&member_owner)
                    .copied()
                    .map(|root_owner| (root_owner, member_owner, definition, unit, access))
            })
            .collect::<Vec<_>>();

        // A Scala object in a type position contributes a module class and
        // then its same-named nested type member. Continue through that
        // selected singleton when the member exists; otherwise the module
        // class itself remains the terminal type.
        if source_language == Language::Scala
            && source_demand.namespace() == ResolutionNamespace::Type
        {
            let Some(module_roots) =
                self.jvm_scala_object_member_roots(&candidates, cancellation)?
            else {
                return Ok(None);
            };
            let modules = module_roots.keys().copied().collect::<Vec<_>>();
            if !modules.is_empty() {
                let Some(nested) = self.jvm_qualified_prefix_member_candidates(
                    &modules,
                    source_demand.spelling(),
                    ResolutionNamespace::Type,
                    source_language,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                route_complete &= nested.complete;
                if !nested.candidates.is_empty() {
                    candidates = nested
                        .candidates
                        .into_iter()
                        .filter_map(|(member_owner, definition, unit, access)| {
                            module_roots.get(&member_owner).copied().map(|root_owner| {
                                (root_owner, member_owner, definition, unit, access)
                            })
                        })
                        .collect();
                }
            }
        }

        // Member-owner pages enumerate direct declarations. An empty result
        // from another file cannot discharge the qualified path's hierarchy
        // placeholder because this route does not traverse that owner's bases.
        if candidates.is_empty() && !owners_are_in_caller_file {
            route_complete = false;
        }

        let lexical = self.ready.lexical_source();
        let mut bridges = Vec::new();
        let mut selected_targets = BTreeSet::new();
        for (root_owner, _member_owner, definition, unit, _) in candidates.drain(..) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = definition.ordinal() else {
                continue;
            };
            let target_mount = SelectedResolutionMountOrdinal::new(ordinal);
            let mount = self.mount_table().mount_by_ordinal(target_mount)?;
            if mount.semantic_language() != source_language {
                route_complete = false;
                continue;
            }
            let target_record = self.ready.inventory.mount_record_by_ordinal(target_mount)?;
            let relation =
                JvmPackageRelation::between(caller_package.as_deref(), unit.package_name());
            let Some(access) = self.jvm_qualified_source_access_completion(
                source_language,
                context,
                source_record.file_version_id(),
                source_record.persisted_relative_path(),
                target_record.file_version_id(),
                target_record.persisted_relative_path(),
                completion,
            )?
            else {
                route_complete = false;
                continue;
            };
            route_complete &= access == ResolutionCompletion::Complete;
            let bridge_completion =
                match self.jvm_declaration_access(definition, relation, &access, cancellation)? {
                    JvmDeclarationAccess::Ready(completion) => {
                        route_complete &= completion == ResolutionCompletion::Complete;
                        completion
                    }
                    JvmDeclarationAccess::Excluded => continue,
                    JvmDeclarationAccess::Cancelled => return Ok(None),
                };
            let owner_ordinal = root_owner
                .ordinal()
                .expect("a selected JVM member owner belongs to a mount");
            if owner_ordinal != ordinal {
                route_complete = false;
                continue;
            }
            let Some(node) = lexical.lookup_definition_node(definition, cancellation)? else {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                return Err(StoreError::corrupt(
                    "selected JVM member route lacks a definition node",
                ));
            };
            let bridge = SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                identity.fragment(),
                source_language,
                *token,
                *anchor,
                *anchor_semantic,
                mount.fragment(),
                source_language,
                root_owner,
                *prefix_reference,
                recipes.clone(),
                source_demand.clone(),
                source_demand.clone(),
                bridge_completion,
            )
            .with_selected_member_definition(node);
            selected_targets.insert(definition);
            bridges.push(bridge);
        }
        Ok(
            (!cancellation.is_cancelled()).then_some(JvmRoutePublication {
                bridges,
                selected_targets,
                complete: route_complete,
            }),
        )
    }

    fn jvm_qualified_prefix_member_owners(
        &self,
        prefix_targets: &[SemanticId],
        language: Language,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<(SemanticId, SemanticId)>>> {
        let mut owners = prefix_targets
            .iter()
            .copied()
            .map(|owner| (owner, owner))
            .collect::<BTreeSet<_>>();
        if language == Language::Kotlin {
            let connection = self.ready.inventory.connection();
            let mut statement = connection.prepare_cached(
                "SELECT companion.semantic_key
                 FROM main.resolution_semantic_sites AS enclosing
                 JOIN main.resolution_singleton_relations AS relation
                   ON relation.blob_id=enclosing.blob_id
                  AND relation.enclosing_type_site=enclosing.source_site
                 JOIN main.resolution_semantic_sites AS companion
                   ON companion.blob_id=relation.blob_id
                  AND companion.source_site=relation.declaration_site
                 WHERE enclosing.blob_id=?1 AND enclosing.semantic_key=?2
                   AND enclosing.semantic_role='definition'
                   AND relation.kind='companion'
                   AND companion.semantic_role='definition'",
            )?;
            for enclosing_type in prefix_targets {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let Some(ordinal) = enclosing_type.ordinal() else {
                    continue;
                };
                let Some(local_key) = enclosing_type.local_key() else {
                    continue;
                };
                let mount = SelectedResolutionMountOrdinal::new(ordinal);
                let record = self.ready.inventory.mount_record_by_ordinal(mount)?;
                let companions = statement
                    .query_map(
                        rusqlite::params![record.blob_id(), i64::from(local_key)],
                        |row| row.get::<_, u32>(0),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                owners.extend(
                    companions
                        .into_iter()
                        .map(|key| (*enclosing_type, SemanticId::local(ordinal, key))),
                );
            }
        }
        Ok((!cancellation.is_cancelled()).then(|| owners.into_iter().collect()))
    }

    fn jvm_qualified_prefix_member_candidates(
        &self,
        owners: &[SemanticId],
        name: &str,
        namespace: ResolutionNamespace,
        language: Language,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmMemberCandidateRead>> {
        let typed = self.ready.typed_source();
        let mut members = Vec::new();
        let outcome = typed.visit_member_owner_pages_for_owners(
            TypedFactRequest::new(owners),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                members.extend(page.iter().map(|row| row.row().clone()));
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(None);
        }
        let mut read_complete =
            outcome.is_exhausted() && outcome.evidence() == &ResolutionCompletion::Complete;
        let member_kind_matches = |kind| match namespace {
            ResolutionNamespace::Type => matches!(
                kind,
                ResolutionMemberKind::NestedType | ResolutionMemberKind::AssociatedType
            ),
            ResolutionNamespace::Value => {
                kind == ResolutionMemberKind::Field
                    || (language == Language::Scala
                        && matches!(
                            kind,
                            ResolutionMemberKind::Method | ResolutionMemberKind::NestedType
                        ))
            }
            ResolutionNamespace::TypeOrValue => matches!(
                kind,
                ResolutionMemberKind::NestedType
                    | ResolutionMemberKind::AssociatedType
                    | ResolutionMemberKind::Field
            ),
            ResolutionNamespace::Callable => {
                kind == ResolutionMemberKind::Method
                    || (language == Language::Scala
                        && matches!(
                            kind,
                            ResolutionMemberKind::Field | ResolutionMemberKind::NestedType
                        ))
            }
            _ => false,
        };
        let owner_set = owners.iter().copied().collect::<BTreeSet<_>>();
        members.retain(|member| {
            owner_set.contains(&member.owner_definition()) && member_kind_matches(member.kind())
        });
        let coordinates = members
            .iter()
            .filter_map(|member| {
                let definition = member.definition();
                Some((
                    SelectedResolutionMountOrdinal::new(definition.ordinal()?),
                    ResolutionLocalKey::new(i64::from(definition.local_key()?)),
                ))
            })
            .collect::<Vec<_>>();
        let SelectedDefinitionUnitReadOutcome::Ready(units) = self
            .ready
            .inventory
            .selected_declaration_unit_candidates(&coordinates, cancellation)?
        else {
            return Ok(None);
        };
        let expected_coordinates = coordinates.iter().copied().collect::<BTreeSet<_>>();
        let returned_coordinates = units
            .iter()
            .map(|(mount, key, _)| (*mount, *key))
            .collect::<BTreeSet<_>>();
        read_complete &= returned_coordinates == expected_coordinates;
        let mut result = Vec::new();
        for (target, key, row) in units {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(identity) = row.fq.as_ref() else {
                read_complete = false;
                continue;
            };
            if identity
                .segments
                .last()
                .is_none_or(|(_, spelling)| !jvm_member_name_matches(language, spelling, name))
            {
                continue;
            }
            let member = SemanticId::local(
                target.get(),
                u32::try_from(key.get()).expect("a catalog position fits u32"),
            );
            if language == Language::Scala
                && matches!(
                    namespace,
                    ResolutionNamespace::Value | ResolutionNamespace::Callable
                )
                && members.iter().any(|candidate| {
                    candidate.definition() == member
                        && candidate.kind() == ResolutionMemberKind::NestedType
                })
                && !self.jvm_scala_object_definition(member)?
            {
                continue;
            }
            let mount = self.mount_table().mount_by_ordinal(target)?;
            let file = ProjectFile::new(
                self.ready.project.root().to_path_buf(),
                mount.persisted_relative_path(),
            );
            let (fq, package_segments) = super::super::hydrate_unit_fq_with_anchor(
                Some(identity),
                &row.content_qualifier,
                &file,
                |_, _, _| None,
            )?;
            let unit = CodeUnit::from_fq(
                file,
                row.kind,
                fq,
                package_segments,
                row.signature.clone(),
                row.flags.synthetic,
            );
            let access = members
                .iter()
                .find(|candidate| candidate.definition() == member)
                .expect("selected member row has a declaration unit")
                .access();
            result.push((
                members
                    .iter()
                    .find(|candidate| candidate.definition() == member)
                    .expect("selected member has its owner row")
                    .owner_definition(),
                member,
                unit,
                access,
            ));
        }
        result.sort_by_key(|(owner, definition, _, access)| (*owner, *definition, *access));
        result.dedup();
        Ok(Some(JvmMemberCandidateRead {
            candidates: result,
            complete: read_complete,
        }))
    }

    fn jvm_scala_object_member_roots(
        &self,
        candidates: &[(
            SemanticId,
            SemanticId,
            SemanticId,
            CodeUnit,
            ResolutionMemberAccess,
        )],
        cancellation: &CancellationToken,
    ) -> Result<Option<BTreeMap<SemanticId, SemanticId>>> {
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(
            "SELECT 1
             FROM main.resolution_semantic_sites AS site
             JOIN main.resolution_singleton_relations AS singleton
               ON singleton.blob_id=site.blob_id
              AND singleton.declaration_site=site.source_site
             WHERE site.blob_id=?1 AND site.semantic_key=?2
               AND site.semantic_role='definition' AND singleton.kind='object'",
        )?;
        let mut modules = BTreeMap::new();
        for (root_owner, _, definition, _, _) in candidates {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = definition.ordinal() else {
                continue;
            };
            let Some(local_key) = definition.local_key() else {
                continue;
            };
            let mount = SelectedResolutionMountOrdinal::new(ordinal);
            let record = self.ready.inventory.mount_record_by_ordinal(mount)?;
            let is_object = statement
                .query_row(
                    rusqlite::params![record.blob_id(), i64::from(local_key)],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if is_object {
                modules.insert(*definition, *root_owner);
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(modules))
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
        let lexical = self.ready.lexical_source();
        let mut recipes = Vec::new();
        let semantics = route
            .iter()
            .copied()
            .chain(std::iter::once(*demand))
            .collect::<Vec<_>>();
        for page in semantics.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            let requests = page
                .iter()
                .map(|&semantic| SelectedLookupRecipeRequest {
                    fragment: identity.fragment(),
                    semantic,
                })
                .collect::<Vec<_>>();
            let SelectedLookupRecipeReadOutcome::Ready(rows) =
                lexical.lookup_semantic_recipes(&requests, cancellation, None)?
            else {
                return Ok(None);
            };
            for recipe in rows {
                recipes.push(recipe.ok_or_else(|| {
                    StoreError::corrupt("selected Java qualified lookup lacks recipe")
                })?);
            }
        }
        let demand = recipes.pop().expect("qualified type demand");
        let import = JavaMemberImportDemand {
            import_kind: None,
            caller_package: package.as_deref(),
            source: identity.fragment(),
            token: *token,
            prefix_reference: *prefix_reference,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0242909d77ed: Java census G03 (2026-10-15): mismatched package paths retain targets without proving cross-file source access"
    )]
    fn java_cross_file_source_access_requires_package_aligned_paths() {
        use crate::analyzer::java::JavaAnalyzer;
        use crate::analyzer::java::native_points::resolve_java_definition_bounded;
        use crate::analyzer::languages::BoundedReceiverQuery;
        use crate::analyzer::usages::get_definition::{
            BoundedResolution, DefinitionLookupStatus, ResolvedReferenceSite,
        };
        use crate::inline_project::InlineTestProject;
        use crate::test_support::token_range;

        let source = "package fixture; class Caller { Target target; }";
        for (caller_path, target_path, expected_status) in [
            (
                "src/Caller.java",
                "src/Target.java",
                DefinitionLookupStatus::Incomplete,
            ),
            (
                "src/fixture/Caller.java",
                "src/fixture/Target.java",
                DefinitionLookupStatus::Resolved,
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Java)
                .file(caller_path, source)
                .file(target_path, "package fixture; public class Target {}")
                .build();
            let analyzer = JavaAnalyzer::new(fixture.project_dyn());
            let file = fixture.file(caller_path);
            let (start_byte, end_byte) = token_range(source, "Target target", "Target");
            let site = ResolvedReferenceSite {
                path: caller_path.into(),
                text: "Target".into(),
                focus_start_byte: start_byte,
                focus_end_byte: end_byte,
                range: crate::analyzer::Range {
                    start_byte,
                    end_byte,
                    start_line: 0,
                    end_line: 0,
                },
            };
            let result = resolve_java_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: &analyzer,
                    file: &file,
                    source,
                    tree: None,
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
                || {},
            );
            let BoundedResolution::Complete { value, .. } = result else {
                panic!("{caller_path}: {result:?}");
            };
            assert_eq!(value.status, expected_status, "{caller_path}: {value:?}");
            let [target] = value.definitions.as_slice() else {
                panic!("{caller_path}: retained target missing: {value:?}");
            };
            assert_eq!(target.source(), &fixture.file(target_path));
            assert_eq!(target.fq_name(), "fixture.Target");
            if expected_status == DefinitionLookupStatus::Incomplete {
                assert!(
                    value
                        .diagnostics
                        .iter()
                        .any(|reason| reason.kind == "java-source-access-open"),
                    "{value:?}"
                );
            } else {
                assert!(value.diagnostics.is_empty(), "{value:?}");
            }
        }
    }

    #[test]
    fn package_path_agreement_handles_default_nested_and_mismatched_paths() {
        assert!(package_path_agrees_with_file_path("", "Default.java"));
        assert!(package_path_agrees_with_file_path(
            "",
            "src/any/Default.java"
        ));
        assert!(package_path_agrees_with_file_path(
            "com.acme.deep",
            "generated/com/acme/deep/Widget.java"
        ));
        assert!(!package_path_agrees_with_file_path(
            "com.acme.deep",
            "generated/com/acme/other/Widget.java"
        ));
        assert!(!package_path_agrees_with_file_path(
            "com.acme",
            "generated/com/acmeExtra/Widget.java"
        ));
    }

    #[test]
    fn jvm_default_import_tables_match_language_contracts() {
        let packages = |language| {
            language_implicit_root_providers(language)
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

    #[test]
    fn selected_import_selector_reader_uses_exact_persisted_fact_rows() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE resolution_semantic_catalog (
                    blob_id INTEGER NOT NULL,
                    local_key INTEGER NOT NULL,
                    import_source_site INTEGER,
                    PRIMARY KEY(blob_id, local_key)
                 ) WITHOUT ROWID;
                 CREATE TABLE resolution_import_selectors (
                    blob_id INTEGER NOT NULL,
                    site INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    source_name TEXT,
                    local_name TEXT,
                    PRIMARY KEY(blob_id, site)
                 ) WITHOUT ROWID;
                 INSERT INTO resolution_semantic_catalog VALUES (7, 10, 50), (7, 11, 51), (7, 12, NULL);
                 INSERT INTO resolution_import_selectors VALUES
                    (7, 50, 'named', 'Original', 'Renamed'),
                    (7, 51, 'star', NULL, NULL);",
            )
            .unwrap();

        let named = selected_jvm_import_selector(&connection, 7, SemanticId::local(0, 10))
            .unwrap()
            .unwrap();
        assert_eq!(named.kind, ResolutionImportSelectorKind::Named);
        assert_eq!(named.source_name.as_deref(), Some("Original"));
        assert_eq!(named.local_name.as_deref(), Some("Renamed"));

        let star = selected_jvm_import_selector(&connection, 7, SemanticId::local(0, 11))
            .unwrap()
            .unwrap();
        assert_eq!(star.kind, ResolutionImportSelectorKind::Star);
        assert!(star.source_name.is_none() && star.local_name.is_none());
        assert!(
            selected_jvm_import_selector(&connection, 7, SemanticId::local(0, 12))
                .unwrap()
                .is_none()
        );

        let mut plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {SELECTED_IMPORT_SELECTOR}"))
            .unwrap();
        let plan = plan
            .query_map(rusqlite::params![7, 10], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(plan.iter().all(|step| step.contains("SEARCH")), "{plan:?}");
    }

    #[test]
    fn selected_jvm_alias_reader_seeks_the_selected_blob_primary_key() {
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
                 INSERT INTO resolution_jvm_aliases
                 SELECT blob_id, 1, 1,
                        CASE WHEN blob_id = 7 THEN 'member' ELSE 'other' END,
                        'source_proven', 'field'
                 FROM blobs;
                 INSERT INTO resolution_semantic_sites
                 SELECT blob_id, 1, 'definition', 1 FROM resolution_jvm_aliases;",
            )
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
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            [(1, 1, "source_proven".to_owned(), 1, "field".to_owned())]
        );

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
                step.contains("SEARCH alias USING") && step.contains("(blob_id=?)")
            }),
            "selected blob must bound the alias lookup: {plan:?}"
        );
        assert!(
            plan.iter().all(|step| !step.contains("SCAN alias")),
            "alias lookup must not scan the workspace table: {plan:?}"
        );
    }
}
