//! File-local Go import bindings from selected source and package authority.

use super::go_context::{GoContextSelection, GoDotImportContext, GoPackageInventoryState};
use super::placement_access::read_placement_rows;
use super::*;
use crate::analyzer::resolution::{
    LoweredGoPackageImport, SelectedGoImportBindingDescriptor, SharedNameInterner,
};
use crate::analyzer::store::resolution_stage::codec;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionGoPackageImportKind, ResolutionNamespace, ResolutionSiteId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum GoExternalPackageProvenance {
    GoTool {
        provider_kind: String,
        module_path: Option<String>,
        module_version: Option<String>,
    },
    SemanticModel {
        symbol_id: String,
        pack_id: String,
        pack_digest: String,
        record_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct GoSelectedExternalImport {
    #[doc(hidden)]
    pub source_spelling: String,
    #[doc(hidden)]
    pub import_path: String,
    #[doc(hidden)]
    pub package_name: String,
    #[doc(hidden)]
    pub provenance: GoExternalPackageProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct GoPackageStageUnit {
    #[doc(hidden)]
    pub context_id: i64,
    pub(crate) package_id: i64,
    #[doc(hidden)]
    pub source_role: String,
}

/// Completeness of an immutable prepared context; never persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum GoPreparationStage {
    ImportBase,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) enum GoPreparedContextKind {
    File,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct GoDemandContext {
    #[doc(hidden)]
    pub context_id: i64,
    #[doc(hidden)]
    pub import_packages: HashMap<(SelectedResolutionMountOrdinal, SemanticId), i64>,
    pub(crate) context_completions: HashMap<SelectedResolutionMountOrdinal, ResolutionCompletion>,
    #[doc(hidden)]
    /// External binder authority, including source-less GoTool packages.
    pub modeled_imports:
        HashMap<(SelectedResolutionMountOrdinal, SemanticId), GoSelectedExternalImport>,
}

impl GoDemandContext {
    #[doc(hidden)]
    pub fn merge(&mut self, other: Self) {
        assert_eq!(
            self.context_id, other.context_id,
            "one selected Go operation uses one publication context"
        );
        for (key, package) in other.import_packages {
            if let Some(previous) = self.import_packages.insert(key, package) {
                assert_eq!(
                    previous, package,
                    "one selected Go import binding has one package provider"
                );
            }
        }
        for (key, provider) in other.modeled_imports {
            if let Some(previous) = self.modeled_imports.insert(key, provider.clone()) {
                assert_eq!(
                    previous, provider,
                    "one selected Go import has one model provider"
                );
            }
        }
        for (mount, completion) in other.context_completions {
            if let Some(previous) = self.context_completions.insert(mount, completion.clone()) {
                assert_eq!(
                    previous, completion,
                    "one selected Go caller mount has one prepared context completion"
                );
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct GoPreparedContextCacheKey {
    kind: GoPreparedContextKind,
    stage: GoPreparationStage,
    routing_digest: [u8; 32],
    publication: super::super::GoContextIdentity,
    caller_mount: SelectedResolutionMountOrdinal,
    caller_path: String,
    source_role: String,
    derivation_version: i64,
    active_model_set_hash: Option<String>,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct GoPreparedImportContext {
    stage: GoPreparationStage,
    #[doc(hidden)]
    pub context: SelectedResolutionContextSet,
    #[doc(hidden)]
    pub demand: GoDemandContext,
    #[doc(hidden)]
    pub source_import_refusals: Vec<super::super::go_package_context::GoSourceImportRefusal>,
    pub(crate) package_inventory: GoPackageInventoryState,
    // Validated paths belong to this request's SQL token. Snapshots explicitly
    // discard this projection before crossing the request boundary.
    pub(crate) blueprint: Option<std::sync::Arc<SelectedFactOperationBlueprint>>,
    // Canonical diagnostic evidence shares the prepared context snapshot lifetime.
    diagnostic_view: Option<GoImportDiagnosticView>,
}

/// Exact preparation authority. Scope and staged content can change while an
/// operation prepares more than one file; published context paths are not
/// staged source content and do not change this identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct GoPreparedContextKey {
    kind: GoPreparedContextKind,
    stage: GoPreparationStage,
    context_id: i64,
    caller_mount: SelectedResolutionMountOrdinal,
    caller_path: String,
    source_role: String,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type GoPreparedContextMemo =
    super::context_preparation::RequestContextMemo<GoPreparedContextKey, GoPreparedImportContext>;

/// One bounded cache entry retains only shared names referenced by its file
/// context. Numeric keys are snapshot-local and never installed in a request.
#[derive(Clone)]
pub(crate) struct GoPreparedImportContextSnapshot {
    prepared: GoPreparedImportContext,
    shared_names: HashMap<SemanticId, [u8; 32]>,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedResolutionOperation<'_, '_> {
    /// Compare independently derived stages on a real selected fixture.
    #[doc(hidden)]
    pub fn assert_go_import_stages_equivalent_for_test(
        &self,
        context_id: i64,
        path: &str,
        role: &str,
        cancellation: &CancellationToken,
    ) {
        let selection = self
            .go_context_selection(context_id, role)
            .unwrap()
            .unwrap();
        let derive = |stage| {
            let GoPreparedImportContextOutcome::Ready(prepared) = self
                .go_import_binding_context_for_selection(
                    context_id,
                    path,
                    role,
                    &selection,
                    stage,
                    cancellation,
                )
                .unwrap()
            else {
                panic!("fixture preparation must complete")
            };
            prepared
        };
        let base = derive(GoPreparationStage::ImportBase);
        let full = derive(GoPreparationStage::Full);
        assert_eq!(base.demand.context_id, full.demand.context_id);
        assert_eq!(base.demand.import_packages, full.demand.import_packages);
        assert_eq!(base.demand.modeled_imports, full.demand.modeled_imports);
        assert_eq!(
            base.demand.context_completions,
            full.demand.context_completions
        );
        let inputs = |context: SelectedResolutionContextSet| {
            let SelectedResolutionContextValidationOutcome::Ready(inputs) = context
                .validate_exact_mounts(
                    self.mount_table().mount_count(),
                    &selected_mount_lookup(self.mount_table()),
                    cancellation,
                )
                .unwrap()
            else {
                panic!("fixture context validates")
            };
            inputs.into_parts()
        };
        let base_inputs = inputs(base.context.clone());
        let full_inputs = inputs(full.context.clone());
        assert_eq!(base_inputs.0, full_inputs.0, "dot-import root bridges");
        assert_eq!(base_inputs.1, full_inputs.1, "inventory completion");
        assert_eq!(base_inputs.3, full_inputs.3, "context-owned gaps");
        assert!(
            base_inputs.5.is_empty(),
            "ImportBase has no package bridges"
        );
        assert_eq!(base_inputs.6, full_inputs.6, "named import bindings");
        assert_eq!(base_inputs.7, full_inputs.7, "callable import boundaries");
        assert_eq!(
            format!("{:?}", base.diagnostic_view),
            format!("{:?}", full.diagnostic_view)
        );
        assert_eq!(
            base.package_inventory.complete,
            full.package_inventory.complete
        );
        assert_eq!(
            base.package_inventory.fragments,
            full.package_inventory.fragments
        );
        assert_eq!(
            format!("{:?}", base.source_import_refusals),
            format!("{:?}", full.source_import_refusals)
        );
    }

    /// Exercise the request-only mint boundary before preparing another file.
    #[doc(hidden)]
    pub fn mint_go_external_owner_for_test(&self) -> SemanticId {
        use crate::analyzer::resolution::{ExternalOwnerIdentity, ExternalOwnerLanguage};
        let identities = &self.ready.context_identities;
        let identity = identities.external_owner_semantic_for_language(
            ExternalOwnerLanguage::Go,
            &ExternalOwnerIdentity {
                provider_id: Arc::from("test-model-provider"),
                owner_fqn: Arc::from("example.test/model.Owner"),
            },
            &self.ready.shared_names(),
        );
        identities.record_jvm_external_provider_type_identity(
            ExternalOwnerLanguage::Go,
            identity,
            identity,
            identity,
            identity,
        );
        assert!(!identities.is_jvm_external_type_identity(identity));
        assert_eq!(
            identities.jvm_external_provider_type_identity_for_reference(
                ExternalOwnerLanguage::Jvm,
                identity
            ),
            None
        );
        assert_eq!(
            identities.jvm_external_provider_type_identity_for_reference(
                ExternalOwnerLanguage::Go,
                identity
            ),
            Some(identity)
        );
        identity
    }
}

/// Read-only projection of the import authority sealed by native preparation.
/// This file-sized value shares the bounded prepared-context cache and its key.
#[derive(Clone, Debug, Default)]
#[doc(hidden)]
pub struct GoImportDiagnosticView {
    pub bindings: Vec<GoImportDiagnosticBinding>,
    pub source_authority_gaps: Vec<GoSourceAuthorityGap>,
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct GoSourceAuthorityGap {
    pub code: String,
    pub file: std::path::PathBuf,
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct GoImportDiagnosticBinding {
    /// Explicit alias, selected declared identifier, or incomplete presumed name.
    /// Dot and blank imports retain their literal binder forms.
    pub local_name: String,
    pub source_spelling: String,
    pub provider_package_id: Option<i64>,
    pub provider_path: Option<String>,
    pub has_source_declarations: bool,
    pub completion: ResolutionCompletion,
    pub named_reasons: Vec<(&'static str, Arc<str>)>,
}

impl GoPreparedImportContext {
    /// Keep the snapshot's identity allow-list exhaustive, including projections.
    /// Scalar fields have explicit types so they cannot silently become tokens.
    fn assert_go_snapshot_safe(&self) {
        let Self {
            stage: _,
            context,
            demand: _,
            source_import_refusals: _,
            package_inventory: _,
            blueprint: _,
            diagnostic_view,
        } = self;
        let identities = context.identity_space();
        identities.assert_go_snapshot_safe();
        let Some(GoImportDiagnosticView {
            bindings,
            source_authority_gaps,
        }) = diagnostic_view
        else {
            return;
        };
        for GoSourceAuthorityGap { code, file } in source_authority_gaps {
            let _: &String = code;
            let _: &std::path::PathBuf = file;
        }
        for GoImportDiagnosticBinding {
            local_name,
            source_spelling,
            provider_package_id,
            provider_path,
            has_source_declarations,
            completion,
            named_reasons,
        } in bindings
        {
            let _: &String = local_name;
            let _: &String = source_spelling;
            let _: &Option<i64> = provider_package_id;
            let _: &Option<String> = provider_path;
            let _: &bool = has_source_declarations;
            let _: &Vec<(&'static str, Arc<str>)> = named_reasons;
            // go_dot_import_context_for_selection builds inventory completion only
            // from canonical named reasons; go_import_completion_for adds the same.
            // go_import_binding_context_for_selection returns cancellation separately,
            // and go_file_import_context_with_role snapshots only Ready preparations.
            // This preparation path does not run a budgeted resolution session.
            if let ResolutionCompletion::Incomplete(reasons) = completion {
                for reason in reasons.iter() {
                    match reason {
                        ResolutionIncompleteReason::UnsupportedSemantic(identity) => assert!(
                            identities.named_reason(*identity).is_some(),
                            "diagnostic snapshot retains only canonical named reasons: {identity:?}"
                        ),
                        ResolutionIncompleteReason::Cancelled
                        | ResolutionIncompleteReason::CyclicExpansion(_)
                        | ResolutionIncompleteReason::CyclicPrefixDependency(_)
                        | ResolutionIncompleteReason::InconsistentPrecedence(_)
                        | ResolutionIncompleteReason::OpenBoundary { .. }
                        | ResolutionIncompleteReason::ReceiverBudgetExhausted(_)
                        | ResolutionIncompleteReason::TimeBudgetExceeded(_)
                        | ResolutionIncompleteReason::UnmountedFile { .. } => panic!(
                            "request-only completion cannot enter a diagnostic snapshot: {reason:?}"
                        ),
                    }
                }
            }
        }
    }

    /// Allowed snapshot identities are bridges in unindexed_go_imports and
    /// their canonical numbers/named reasons. GoPreparedContextCacheKey covers
    /// their routing digest, publication identity, caller file/role, derivation
    /// version and active model-set hash. They travel through cache_snapshot,
    /// insert_go_prepared_context and restored_for_request under that key.
    /// Request-minted model owners, members and slots cannot travel this route.
    fn cache_snapshot(
        &self,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> Result<Option<GoPreparedImportContextSnapshot>> {
        self.assert_go_snapshot_safe();
        let identities = self.context.identity_space().isolated_clone();
        let mut context = self.context.clone().with_identity_space(identities);
        let mut shared_names = HashMap::default();
        context.remap_shared_names(|identity| {
            if let Some(digest) = source.shared_name_digest_for_identity(identity, cancellation)? {
                shared_names.insert(identity, digest);
            }
            Ok(identity)
        })?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(GoPreparedImportContextSnapshot {
            prepared: Self {
                stage: self.stage,
                context,
                demand: self.demand.clone(),
                source_import_refusals: self.source_import_refusals.clone(),
                package_inventory: self.package_inventory.clone(),
                blueprint: None,
                diagnostic_view: self.diagnostic_view.clone(),
            },
            shared_names,
        }))
    }
}

impl GoPreparedImportContextSnapshot {
    fn restored_for_request(
        &self,
        identities: &SelectedContextIdentities,
        names: &dyn SharedNameInterner,
    ) -> Result<GoPreparedImportContext> {
        self.prepared.assert_go_snapshot_safe();
        let mut context = self.prepared.context.clone();
        context.remap_shared_names(|identity| {
            let digest = self
                .shared_names
                .get(&identity)
                .expect("a cached context retains every referenced shared-name digest");
            Ok(SemanticId::shared_name(names.intern(*digest)))
        })?;
        identities.copy_from_empty(&self.prepared.context.identity_space());
        Ok(GoPreparedImportContext {
            stage: self.prepared.stage,
            context: context.with_identity_space(identities.clone()),
            demand: self.prepared.demand.clone(),
            source_import_refusals: self.prepared.source_import_refusals.clone(),
            package_inventory: self.prepared.package_inventory.clone(),
            blueprint: None,
            diagnostic_view: self.prepared.diagnostic_view.clone(),
        })
    }
}

#[doc(hidden)]
pub enum GoPreparedImportContextOutcome {
    Ready(Box<GoPreparedImportContext>),
    Unavailable,
    Cancelled,
}

impl GoSelectedExternalImport {
    #[doc(hidden)]
    pub fn has_authoritative_provenance(&self) -> bool {
        match &self.provenance {
            GoExternalPackageProvenance::GoTool { provider_kind, .. } => {
                matches!(provider_kind.as_str(), "standard" | "module")
            }
            GoExternalPackageProvenance::SemanticModel {
                symbol_id,
                pack_id,
                pack_digest,
                record_id,
            } => {
                !symbol_id.is_empty()
                    && !pack_id.is_empty()
                    && !pack_digest.is_empty()
                    && !record_id.is_empty()
            }
        }
    }
}

pub(crate) static SELECTED_EXTERNAL_IMPORTS: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT imports.source_spelling,target.tool_import_path,target.package_name,
       target.provider_kind,target.provider_module_path,target.provider_module_version
FROM ({}) caller
JOIN main.go_package_instances importer
  ON importer.context_id=caller.context_id AND importer.package_id=caller.package_id
 AND ((caller.source_role='go' AND importer.for_test='')
   OR (caller.source_role IN ('test','xtest') AND importer.for_test<>'')
   OR (caller.source_role IN ('test','xtest') AND importer.provider_provenance='source_inventory'))
JOIN main.go_package_imports imports
  ON imports.context_id=caller.context_id
 AND imports.importer_package_id=caller.package_id
 AND imports.import_role=caller.source_role
JOIN main.go_package_instances target
  ON target.context_id=imports.context_id AND target.package_id=imports.target_package_id
WHERE caller.context_id=?1 AND caller.file_version_id=?2
  AND imports.complete=1 AND target.complete=1
  AND target.provider_kind IN ('standard','module')
  AND NOT EXISTS (SELECT 1 FROM temp.selected_go_context_source_files files
                  WHERE files.package_id=target.package_id AND files.source_role<>'ignored')
ORDER BY imports.source_spelling,target.tool_import_path
"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

pub(crate) static SELECTED_UNRESOLVED_IMPORTS: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT DISTINCT imports.source_spelling
FROM ({}) caller
JOIN main.go_package_instances importer
  ON importer.context_id=caller.context_id AND importer.package_id=caller.package_id
 AND ((caller.source_role='go' AND importer.for_test='')
   OR (caller.source_role IN ('test','xtest') AND importer.for_test<>'')
   OR (caller.source_role IN ('test','xtest') AND importer.provider_provenance='source_inventory'))
JOIN main.go_package_imports imports
  ON imports.context_id=caller.context_id
 AND imports.importer_package_id=caller.package_id
 AND imports.import_role=caller.source_role
WHERE caller.context_id=?1 AND caller.file_version_id=?2
  AND imports.target_package_id IS NULL AND imports.complete=0
  AND NOT EXISTS (
    SELECT 1 FROM main.go_package_instances exact
    WHERE exact.context_id=caller.context_id
      AND exact.tool_import_path=imports.source_spelling
  )
ORDER BY imports.source_spelling
"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

pub(crate) static SELECTED_IMPORT_CONTEXT_FILES: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
WITH RECURSIVE reachable(package_id) AS (
  SELECT caller.package_id
  FROM ({}) caller
  WHERE caller.context_id=?1 AND caller.file_version_id=?2 AND caller.source_role<>'ignored'
  UNION
  SELECT imports.target_package_id
  FROM reachable
  JOIN main.go_package_imports imports
    ON imports.context_id=?1 AND imports.importer_package_id=reachable.package_id
  WHERE imports.complete=1 AND imports.target_package_id IS NOT NULL
), source_files(file_version_id, rel_path, source_role) AS (
  SELECT DISTINCT source.file_version_id, files.rel_path, source.source_role
  FROM reachable
  JOIN temp.selected_go_context_source_files source
    ON source.context_id=?1 AND source.package_id=reachable.package_id
  JOIN main.go_package_instances package
    ON package.context_id=source.context_id AND package.package_id=source.package_id
  JOIN main.workspace_file_versions files
    ON files.file_version_id=source.file_version_id
  WHERE source.source_role<>'ignored' AND (source.file_version_id=?2 OR source.source_role='go'
     OR (source.source_role='test' AND package.for_test<>''))
)
SELECT rel_path, source_role FROM (
  SELECT source_files.rel_path, source_files.source_role
  FROM source_files
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.file_version_id=source_files.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  UNION
  SELECT source_files.rel_path, source_files.source_role
  FROM source_files
  JOIN temp.selected_go_transient_placements placed
    ON placed.file_version_id=source_files.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=placed.mount_ordinal
)
ORDER BY rel_path, source_role
"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

pub(crate) static CALLER_SOURCE_ROLE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT caller.source_role
FROM ({}) caller
CROSS JOIN main.go_package_instances package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
WHERE caller.context_id=?1 AND caller.file_version_id=?2
 AND ((caller.source_role='go' AND package.for_test='')
   OR (caller.source_role='ignored' AND package.for_test='' AND NOT EXISTS (
       SELECT 1 FROM main.go_package_files participating
       WHERE participating.package_id=caller.package_id
         AND participating.rel_path=caller.rel_path AND participating.source_role<>'ignored'
   ))
   OR (caller.source_role IN ('test','xtest') AND package.for_test<>'')
   OR (caller.source_role='test' AND package.for_test='' AND package.complete=0
       AND NOT EXISTS(
         SELECT 1
         FROM ({}) selected_test
         JOIN main.go_package_instances selected_package
           ON selected_package.context_id=selected_test.context_id
          AND selected_package.package_id=selected_test.package_id
         WHERE selected_test.context_id=caller.context_id
           AND selected_test.file_version_id=caller.file_version_id
           AND selected_test.source_role='test'
           AND selected_package.for_test<>''
       ))
   OR (caller.source_role IN ('test','xtest') AND package.provider_provenance='source_inventory'))
"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

// Import bindings of every listed mount, one statement for the whole request.
// `?1` is a JSON array of mount ordinals. The scope-mount join keeps the read
// inside the request closure, and the last column names the mount a row
// belongs to.
pub(in crate::analyzer::store) const ORDINARY_IMPORT_BINDINGS: &str = r#"
SELECT p.definition_key,p.source_site,p.file_scope_key,p.spelling_choice_key,
       p.start_byte,p.end_byte,p.kind,i.import_id,selected.mount_ordinal
FROM json_each(?1) requested
CROSS JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=requested.value
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_go_package_imports p ON p.blob_id=mounted.blob_id
LEFT JOIN main.source_imports i ON i.blob_id=p.blob_id
 AND i.declaration_start_byte=p.start_byte AND i.declaration_end_byte=p.end_byte
"#;

pub(in crate::analyzer::store) const STAGED_IMPORT_BINDINGS: &str = r#"
SELECT p.definition_key,p.source_site,p.file_scope_key,p.spelling_choice_key,
       p.start_byte,p.end_byte,p.kind,i.import_id,selected.mount_ordinal
FROM json_each(?1) requested
CROSS JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=requested.value
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN temp.selected_resolution_stage_go_package_imports p ON p.host_ordinal=selected.mount_ordinal
LEFT JOIN main.source_imports i ON i.blob_id=mounted.blob_id
 AND i.declaration_start_byte=p.start_byte AND i.declaration_end_byte=p.end_byte
"#;

// Every source import of every listed file, joined to the selected package
// import row of that spelling and to the provider package. `?1` is the Go
// context and `?2` a JSON array of `[mount_ordinal, file_version_id,
// source_role]` triples. The import spelling is the source import's path
// segments joined by `/`, read from `source_import_segments`. The caller
// package is the one the exact selected placement admits (the CALLER_PACKAGE
// predicate in go_same_package.rs), so a file version placed in several
// packages does not mix their imports. A package's other imports are never
// read: the join starts from the file's own source imports. An import without
// a provider yields NULL provider columns. Every join is a CROSS JOIN so the
// planner keeps the request list outermost; without that, it starts from the
// context's packages and probes the list per package. The segment subquery
// orders by `ordinal` on the primary key, which needs no sort.
#[doc(hidden)]
pub static GO_FILE_IMPORT_ROWS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"
SELECT requested.value ->> 0, imports.source_spelling, imports.complete,
       json(imports.gaps), NULLIF(target.package_name,''), target.package_id,
       mounted.semantic_language, requested.value ->> 1, requested.value ->> 2,
       EXISTS(SELECT 1 FROM temp.selected_go_context_source_files provider
              WHERE provider.context_id=target.context_id
                AND provider.package_id=target.package_id
                AND (provider.source_role='go'
                     OR (provider.source_role='test' AND target.for_test<>''))),
       target.tool_import_path, target.provider_kind,
       target.provider_module_path, target.provider_module_version, target.complete,
       (SELECT anchor.package_name
        FROM temp.selected_go_context_source_files provider
        JOIN main.workspace_file_anchor_rows anchor ON anchor.file_version_id=provider.file_version_id
          AND anchor.anchor_kind='own_module' AND anchor.anchor_pop=0
        WHERE provider.context_id=target.context_id AND provider.package_id=target.package_id
          AND (provider.source_role='go'
               OR (provider.source_role='test' AND target.for_test<>''))
        LIMIT 1)
FROM json_each(?2) requested
CROSS JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=requested.value ->> 0
CROSS JOIN ({}) caller
  ON caller.context_id=?1 AND caller.file_version_id=requested.value ->> 1
 AND caller.source_role=requested.value ->> 2
JOIN main.go_package_instances package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
 AND ((caller.source_role='go' AND package.for_test='')
   OR (caller.source_role IN ('test','xtest') AND package.for_test<>'')
   OR (caller.source_role='test' AND package.for_test='' AND package.complete=0
       AND NOT EXISTS(
         SELECT 1
         FROM ({}) selected_test
         JOIN main.go_package_instances selected_package
           ON selected_package.context_id=selected_test.context_id
          AND selected_package.package_id=selected_test.package_id
         WHERE selected_test.context_id=caller.context_id
           AND selected_test.file_version_id=caller.file_version_id
           AND selected_test.source_role='test'
           AND selected_package.for_test<>''
       ))
   OR (caller.source_role IN ('test','xtest') AND package.provider_provenance='source_inventory'))
CROSS JOIN main.source_imports i ON i.blob_id=mounted.blob_id
CROSS JOIN main.go_package_imports imports
  ON imports.context_id=caller.context_id AND imports.importer_package_id=caller.package_id
 AND imports.import_role=caller.source_role
 AND imports.source_spelling=(
   SELECT group_concat(segment, '/')
   FROM (SELECT segment.segment FROM main.source_import_segments segment
         WHERE segment.blob_id=i.blob_id AND segment.import_id=i.import_id
         ORDER BY segment.ordinal))
LEFT JOIN main.go_package_instances target
  ON target.context_id=imports.context_id AND target.package_id=imports.target_package_id
"#,
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
        super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
    )
});

// Which of the listed mounts import a package with the `.` alias. `?1` is a
// JSON array of mount ordinals. Only a dot import publishes a root import path
// (a named import binds through `go_package_imports`), so a file without one
// has no root import halves to read.
pub(in crate::analyzer::store) const GO_DOT_IMPORT_MOUNTS: &str = r#"
SELECT DISTINCT requested.value
FROM json_each(?1) requested
CROSS JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=requested.value
CROSS JOIN main.source_imports i ON i.blob_id=mounted.blob_id
WHERE i.alias='.'
"#;

/// One selected import row of a Go file: its publication completeness and the
/// selected provider package.
#[derive(Clone)]
pub(super) struct GoFileImportRow {
    pub(super) complete: bool,
    pub(super) gaps: String,
    pub(super) source_refusal: Option<super::super::go_package_context::GoSourceImportRefusal>,
    /// A missing or nameless tool provider has no authoritative package clause.
    pub(super) package_name: Option<String>,
    /// Retained as provider evidence even when its package clause is unknown.
    pub(super) package_id: Option<i64>,
    pub(super) modeled_provider: Option<GoSelectedExternalImport>,
    /// Selected package files can supply native member declarations.
    pub(super) has_source_declarations: bool,
    pub(super) provider_path: Option<String>,
}

/// Syntax inputs of one mounted Go file. Neither bindings nor dot aliases
/// depend on the selected Go package context.
#[derive(Clone, Default)]
struct GoMountImportInputs {
    bindings: BTreeMap<SemanticId, GoImportBindingRow>,
    has_dot_import: bool,
}

/// Selected import rows bind context, file version and role in addition to mount.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct GoImportAuthority {
    mount: u32,
    context_id: i64,
    file_version: i64,
    source_role: String,
}

impl GoImportAuthority {
    pub(super) fn new(
        mount: SelectedResolutionMountOrdinal,
        context_id: i64,
        file_version: i64,
        source_role: &str,
    ) -> Self {
        Self {
            mount: mount.get(),
            context_id,
            file_version,
            source_role: source_role.to_owned(),
        }
    }
}

#[derive(Clone)]
struct GoSelectedImportInputs {
    authority: GoImportAuthority,
    imports: HashMap<String, GoFileImportRow>,
}

/// Import inputs prepared by one operation, dropped with that operation.
/// Syntax rows use the immutable mount (including its blob and staged facts).
/// Selected package rows use the full SQL authority: mount, context, version,
/// and role. Scope, staged facts and the captured model overlay belong to this
/// operation. Size is bounded by the files times contexts/roles this request
/// prepares, never an independently populated workspace index.
#[derive(Default)]
#[doc(hidden)]
pub struct GoImportInputCache {
    mounts: HashMap<u32, GoMountImportInputs>,
    selected: HashMap<GoImportAuthority, GoSelectedImportInputs>,
}

#[cfg(any(test, feature = "test-support"))]
impl GoImportInputCache {
    #[doc(hidden)]
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct GoImportBindingRow {
    metadata: LoweredGoPackageImport,
    source_import: usize,
}

impl GoImportBindingRow {
    fn source(
        row: &rusqlite::Row<'_>,
        definition: SemanticId,
        file_scope: BindingNodeId,
        spelling_choice: SemanticId,
    ) -> Result<Self> {
        Ok(Self {
            metadata: LoweredGoPackageImport {
                definition,
                source_site: ResolutionSiteId::new(row.get(1)?),
                file_scope,
                spelling_choice,
                start_byte: row.get(4)?,
                end_byte: row.get(5)?,
                kind: ResolutionGoPackageImportKind::from_label(&row.get::<_, String>(6)?)
                    .ok_or_else(|| StoreError::corrupt("invalid Go import kind"))?,
            },
            source_import: row.get::<_, Option<usize>>(7)?.ok_or_else(|| {
                StoreError::corrupt("Go import metadata lacks exact sealed source import span")
            })?,
        })
    }

    fn ordinary(row: &rusqlite::Row<'_>) -> Result<Self> {
        let ordinal: u32 = row.get(8)?;
        Self::source(
            row,
            SemanticId::local(ordinal, row.get(0)?),
            BindingNodeId::local(ordinal, row.get(2)?),
            SemanticId::local(ordinal, row.get(3)?),
        )
    }

    fn staged(row: &rusqlite::Row<'_>) -> Result<Self> {
        Self::source(
            row,
            codec::decode_semantic(row.get(0)?),
            codec::decode_node(row.get(2)?),
            codec::decode_semantic(row.get(3)?),
        )
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Capture the caller's overlay rather than the language delegate's cache.
    /// A multi-language analyzer can activate models without populating its
    /// Go delegate. This authority lives only for the selected operation.
    #[doc(hidden)]
    pub fn with_go_model_authority(
        self,
        overlay: Option<Arc<dyn super::SelectedModelAuthority + Send + Sync>>,
    ) -> Self {
        assert!(
            self.ready.attached_model_authority.is_none()
                && self.go_import_inputs.borrow().mounts.is_empty(),
            "model authority is captured before import preparation"
        );
        let mut operation = self;
        operation.ready.attached_model_authority = Some(overlay);
        // Validate a captured authority against any analyzer service set now.
        drop(operation.ready.model_authority());
        operation
    }

    /// Overlay authority precedes missing durable import authority, like
    /// `model_declared_jvm_owner` in the JVM context. The registered language
    /// hook supplies the package clause name and provider identity; no basename
    /// is evidence.
    /// Typed durable provider rows are deferred until a typed reader needs them.
    fn model_declared_go_package(
        &self,
        language: Language,
        import_path: &str,
    ) -> Option<GoSelectedExternalImport> {
        let overlay = self.ready.model_authority()?;
        let identity = overlay.modeled_external_package_identity(language, import_path)?;
        Some(GoSelectedExternalImport {
            source_spelling: import_path.to_owned(),
            import_path: import_path.to_owned(),
            package_name: identity.package_name,
            provenance: GoExternalPackageProvenance::SemanticModel {
                symbol_id: identity.symbol_id,
                pack_id: identity.pack_id,
                pack_digest: identity.pack_digest,
                record_id: identity.record_id,
            },
        })
    }

    /// Return this caller's complete, source-less standard/dependency import
    /// targets. The vector is request-owned and bounded by this file's imports.
    #[doc(hidden)]
    pub fn go_selected_external_imports(
        &self,
        context_id: i64,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<GoSelectedExternalImport>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let Some(source) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(Vec::new());
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let Some(version) = super::go_context::go_placement_file_version(
            self.ready.inventory.connection(),
            &record,
        )?
        else {
            return Ok(Vec::new());
        };
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(&SELECTED_EXTERNAL_IMPORTS)?;
        let mut rows = statement.query(rusqlite::params![context_id, version])?;
        let mut imports = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            imports.push(GoSelectedExternalImport {
                source_spelling: row.get(0)?,
                import_path: row.get(1)?,
                package_name: row.get(2)?,
                provenance: GoExternalPackageProvenance::GoTool {
                    provider_kind: row.get(3)?,
                    module_path: row.get(4)?,
                    module_version: row.get(5)?,
                },
            });
        }
        drop(rows);
        drop(statement);
        if self.ready.model_authority().is_none() {
            return Ok(imports);
        }
        for spelling in
            self.go_selected_unresolved_imports(context_id, caller_path, cancellation)?
        {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            if let Some(provider) =
                self.model_declared_go_package(source.semantic_language(), &spelling)
            {
                imports.push(provider);
            }
        }
        Ok(imports)
    }

    /// Return only exact unresolved import spellings from this selected
    /// source file. A caller may match these to a semantic model by exact
    /// import path; no path-derived package name is supplied here.
    #[doc(hidden)]
    pub fn go_selected_unresolved_imports(
        &self,
        context_id: i64,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<String>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let Some(source) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(Vec::new());
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let Some(version) = super::go_context::go_placement_file_version(
            self.ready.inventory.connection(),
            &record,
        )?
        else {
            return Ok(Vec::new());
        };
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(&SELECTED_UNRESOLVED_IMPORTS)?;
        let mut rows = statement.query(rusqlite::params![context_id, version])?;
        let mut imports = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            imports.push(row.get(0)?);
        }
        Ok(imports)
    }

    /// Project the same cached file context used by ordinary native requests.
    #[doc(hidden)]
    pub fn go_import_diagnostic_view(
        &self,
        context_id: i64,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<GoImportDiagnosticView>> {
        let Some(source) = self.mount_table().mount_for_path("go", path)? else {
            return Ok(None);
        };
        let Some(role) =
            self.go_source_role_for_mount(context_id, source.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        let GoPreparedImportContextOutcome::Ready(prepared) = self
            .go_file_import_context_at_stage(
                context_id,
                path,
                &role,
                GoPreparationStage::ImportBase,
                cancellation,
            )?
        else {
            return Ok(None);
        };
        Ok(Some(
            prepared
                .diagnostic_view
                .expect("file preparation retains diagnostic authority"),
        ))
    }

    /// Prepare only this file's package and import context. Other Go files are
    /// admitted by the demand provider when resolution reaches their mounts.
    #[doc(hidden)]
    pub fn go_file_import_context(
        &self,
        context_id: i64,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoPreparedImportContextOutcome> {
        if cancellation.is_cancelled() {
            return Ok(GoPreparedImportContextOutcome::Cancelled);
        }
        let Some(source) = self.mount_table().mount_for_path("go", path)? else {
            return Ok(GoPreparedImportContextOutcome::Unavailable);
        };
        let Some(source_role) =
            self.go_source_role_for_mount(context_id, source.ordinal(), cancellation)?
        else {
            return Ok(if cancellation.is_cancelled() {
                GoPreparedImportContextOutcome::Cancelled
            } else {
                GoPreparedImportContextOutcome::Unavailable
            });
        };
        self.go_file_import_context_with_role(context_id, path, &source_role, cancellation)
    }

    pub(crate) fn go_source_role_for_mount(
        &self,
        context_id: i64,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<Option<String>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let record = self.ready.inventory.mount_record_by_ordinal(mount)?;
        assert_eq!(record.semantic_language(), Language::Go);
        let connection = self.ready.inventory.connection();
        let Some(version) = super::go_context::go_placement_file_version(connection, &record)?
        else {
            return Ok(None);
        };
        let roles = read_placement_rows(
            &self.ready.inventory,
            CALLER_SOURCE_ROLE.as_str(),
            rusqlite::params![context_id, version],
            |row: &rusqlite::Row<'_>| {
                let role: String = row.get(0)?;
                Ok(role)
            },
        )?;
        let mut source_role = None;
        for role in roles {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if source_role
                .as_ref()
                .is_some_and(|previous| previous != &role)
            {
                return Ok(None);
            }
            source_role = Some(role);
        }
        Ok(source_role)
    }

    /// Q2 uses the nearest structurally selected module root, including when
    /// no package row was published for this particular file.
    #[doc(hidden)]
    pub fn go_graph_file_exclusion_for_domain(
        &self,
        base: &[u8; 32],
        path: &str,
        placement_context: Option<i64>,
        module_dir: Option<&std::path::Path>,
        module_path: Option<&str>,
    ) -> Result<super::graph_stage::GraphFileSkipReason> {
        use super::graph_stage::GraphFileSkipReason;
        let Some(snapshot) = self.captured_input.snapshots.get("go") else {
            return Ok(GraphFileSkipReason::Unplaced);
        };
        let dir = module_dir.map(selected_path_key);
        let domain = self
            .ready
            .inventory
            .connection()
            .query_row(
                DOMAIN_FOR_MODULE_SQL,
                rusqlite::params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision,
                    base,
                    super::super::go_package_context::DERIVATION_VERSION,
                    dir
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((context_id, domain_dir, gowork_path, error)) = domain {
            self.go_context_selection(context_id, "go")?;
            if let Some(message) = error {
                return Ok(GraphFileSkipReason::DomainDiscoveryFailed {
                    domain_dir,
                    gowork_path,
                    message,
                });
            }
            return self.go_graph_file_exclusion(context_id, path, module_path);
        }
        // Source-only inventory intentionally has no named-domain rows.
        // Its recorded path still supplies placement/overlay evidence.
        if let Some(context_id) = placement_context {
            return self.go_graph_file_exclusion(context_id, path, module_path);
        }
        Ok(
            module_path.map_or(GraphFileSkipReason::Unplaced, |module_path| {
                GraphFileSkipReason::OutsideSelectedModules {
                    module_path: module_path.to_owned(),
                }
            }),
        )
    }

    /// Classify an absent selected placement using publication evidence only.
    #[doc(hidden)]
    pub fn go_graph_file_exclusion(
        &self,
        context_id: i64,
        path: &str,
        module_path: Option<&str>,
    ) -> Result<super::graph_stage::GraphFileSkipReason> {
        use super::graph_stage::GraphFileSkipReason;
        let connection = self.ready.inventory.connection();
        let version = if let Some(mount) = self.mount_table().mount_for_path("go", path)? {
            let record = self
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())?;
            super::go_context::go_placement_file_version(connection, &record)?
        } else {
            // Exclusion evidence does not require a resolution bundle. Bind an
            // unmounted persisted source to this operation's exact revision;
            // an overlay must prove its placement through the mounted branch.
            connection
                .query_row(
                    "SELECT file.file_version_id FROM main.workspace_file_versions file
                 JOIN temp.selected_workspace_revisions selected
                   ON selected.workspace_id=file.workspace_id AND selected.lang=file.lang
                  AND selected.generation=file.generation
                 WHERE file.lang='go' AND file.rel_path=?1 AND file.input_kind='source'
                   AND file.valid_from<=selected.revision
                   AND (file.valid_until IS NULL OR selected.revision<file.valid_until)
                   AND NOT EXISTS(SELECT 1 FROM temp.selected_resolution_overlay_masks mask
                     WHERE mask.storage_language='go' AND mask.persisted_relative_path=?1)",
                    [path],
                    |row| row.get(0),
                )
                .optional()?
        };
        let Some(version) = version else {
            return Ok(GraphFileSkipReason::Unplaced);
        };
        let ignored: bool = connection.query_row(
            GO_INTERVAL_GO_GRAPH_FILE_EXCLUSION_0_SQL.as_str(),
            rusqlite::params![context_id, version],
            |row| row.get(0),
        )?;
        if ignored {
            return Ok(GraphFileSkipReason::ExcludedBuildSelection);
        }
        let inventory: bool = connection.query_row(
            GO_INTERVAL_GO_GRAPH_FILE_EXCLUSION_1_SQL.as_str(),
            [version],
            |row| row.get(0),
        )?;
        if let Some(module_path) = module_path.filter(|_| inventory) {
            let selected: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.go_package_instances
                 WHERE context_id=?1 AND provider_module_path=?2 AND provider_provenance='go_tool')",
                rusqlite::params![context_id, module_path], |row| row.get(0),
            )?;
            if !selected {
                return Ok(GraphFileSkipReason::OutsideSelectedModules {
                    module_path: module_path.to_owned(),
                });
            }
        }
        Ok(GraphFileSkipReason::Unplaced)
    }

    #[doc(hidden)]
    pub fn go_package_stage_unit_for_path(
        &self,
        context_id: i64,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<GoPackageStageUnit>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(source) = self.mount_table().mount_for_path("go", path)? else {
            return Ok(None);
        };
        let Some(source_role) =
            self.go_source_role_for_mount(context_id, source.ordinal(), cancellation)?
        else {
            return Ok(None);
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let Some(version) = super::go_context::go_placement_file_version(
            self.ready.inventory.connection(),
            &record,
        )?
        else {
            return Ok(None);
        };
        let package_id = self.go_selected_package_id(context_id, version, &source_role)?;
        Ok(package_id.map(|package_id| GoPackageStageUnit {
            context_id,
            package_id,
            source_role,
        }))
    }

    pub(super) fn go_file_preparation_key(
        &self,
        context_id: i64,
        caller_mount: SelectedResolutionMountOrdinal,
        path: &str,
        source_role: &str,
    ) -> GoPreparedContextKey {
        GoPreparedContextKey {
            kind: GoPreparedContextKind::File,
            stage: GoPreparationStage::Full,
            context_id,
            caller_mount,
            caller_path: path.to_owned(),
            source_role: source_role.to_owned(),
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        }
    }

    #[doc(hidden)]
    pub fn go_file_import_context_with_role(
        &self,
        context_id: i64,
        path: &str,
        source_role: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoPreparedImportContextOutcome> {
        let outcome = self.go_file_import_context_at_stage(
            context_id,
            path,
            source_role,
            GoPreparationStage::Full,
            cancellation,
        )?;
        if let GoPreparedImportContextOutcome::Ready(prepared) = &outcome {
            assert_eq!(prepared.stage, GoPreparationStage::Full);
        }
        Ok(outcome)
    }

    // Only this module can request ImportBase. Resolution entry points always
    // request Full and never receive a base product from either memo or cache.
    fn go_file_import_context_at_stage(
        &self,
        context_id: i64,
        path: &str,
        source_role: &str,
        stage: GoPreparationStage,
        cancellation: &CancellationToken,
    ) -> Result<GoPreparedImportContextOutcome> {
        if cancellation.is_cancelled() {
            return Ok(GoPreparedImportContextOutcome::Cancelled);
        }
        let Some(source) = self.mount_table().mount_for_path("go", path)? else {
            return Ok(GoPreparedImportContextOutcome::Unavailable);
        };
        assert_eq!(source.semantic_language(), Language::Go);
        let mut key = self.go_file_preparation_key(context_id, source.ordinal(), path, source_role);
        if stage == GoPreparationStage::ImportBase
            && let Some(full) = self.go_prepared_contexts.get(&key)
        {
            assert_eq!(full.stage, GoPreparationStage::Full);
            self.record_go_package_inventory_state(&full.package_inventory);
            return Ok(GoPreparedImportContextOutcome::Ready(Box::new(full)));
        }
        key.stage = stage;
        // Keep non-ready outcomes outside the memo. Ordinary read admission
        // retains a completed preparation even if cancellation prevents its
        // optional cross-request snapshot at the end of the derivation.
        let mut outcome = GoPreparedImportContextOutcome::Unavailable;
        let mut inventory_recorded = false;
        let prepared = self.go_prepared_contexts.read(key, |_| {
            let Some(selection) = self.go_context_selection(context_id, source_role)? else {
                return Ok(None);
            };
            let cache_key = GoPreparedContextCacheKey {
                kind: GoPreparedContextKind::File,
                stage,
                routing_digest: self.ready.inventory.routing_digest(),
                publication: selection.identity.clone(),
                caller_mount: source.ordinal(),
                caller_path: path.to_owned(),
                source_role: source_role.to_owned(),
                derivation_version: super::super::go_package_context::DERIVATION_VERSION,
                active_model_set_hash: self
                    .ready
                    .model_authority()
                    .map(|overlay| overlay.active_model_set_hash().to_owned()),
            };
            let cached = self
                .ready
                .context_identities
                .is_empty()
                .then(|| {
                    let budget = &self.ready.store.cache_budget;
                    if stage == GoPreparationStage::ImportBase {
                        let mut full_key = cache_key.clone();
                        full_key.stage = GoPreparationStage::Full;
                        if let Some(full) = budget.go_prepared_context(&full_key) {
                            return Some(full);
                        }
                    }
                    budget.go_prepared_context(&cache_key)
                })
                .flatten();
            if let Some(cached) = cached {
                return Ok(Some(cached.restored_for_request(
                    &self.ready.context_identities,
                    &self.ready.shared_names(),
                )?));
            }
            // A cached file context is read only into an empty identity table
            // (the lookup above). Its snapshot would also carry the request's
            // other identities. Publish only a context built from an empty table.
            let publishable = self.ready.context_identities.is_empty();
            match self.go_import_binding_context_for_selection(
                context_id,
                path,
                source_role,
                &selection,
                stage,
                cancellation,
            )? {
                GoPreparedImportContextOutcome::Ready(context) => {
                    // The derivation already observed its inventory certificate.
                    // Memo and snapshot hits must replay it below instead.
                    inventory_recorded = true;
                    if publishable
                        && let Some(snapshot) =
                            context.cache_snapshot(&self.ready.lexical_source(), cancellation)?
                    {
                        let cache_value = Arc::new(snapshot);
                        self.ready
                            .store
                            .cache_budget
                            .insert_go_prepared_context(cache_key, cache_value);
                    }
                    Ok(Some(*context))
                }
                not_ready => {
                    outcome = not_ready;
                    Ok(None)
                }
            }
        })?;
        if let Some(context) = prepared {
            if !inventory_recorded {
                self.record_go_package_inventory_state(&context.package_inventory);
            }
            return Ok(GoPreparedImportContextOutcome::Ready(Box::new(context)));
        }
        Ok(outcome)
    }

    pub(super) fn go_import_inputs_loaded(&self, authority: &GoImportAuthority) -> bool {
        self.go_import_inputs
            .borrow()
            .selected
            .contains_key(authority)
    }

    /// Whether a loaded mount has a dot import.
    pub(super) fn go_mount_has_dot_import(&self, mount: SelectedResolutionMountOrdinal) -> bool {
        self.go_import_inputs
            .borrow()
            .mounts
            .get(&mount.get())
            .is_some_and(|inputs| inputs.has_dot_import)
    }

    /// The selected import row of a loaded mount for one source spelling.
    pub(super) fn go_import_row(
        &self,
        authority: &GoImportAuthority,
        spelling: &str,
    ) -> Option<GoFileImportRow> {
        self.go_import_inputs
            .borrow()
            .selected
            .get(authority)
            .and_then(|inputs| {
                debug_assert_eq!(&inputs.authority, authority);
                inputs.imports.get(spelling).cloned()
            })
    }

    /// Read the import bindings and selected import rows of every listed Go
    /// file in one statement each and keep them for the rest of this
    /// operation. A request that prepares many Go files calls this once before
    /// its per-file loop; a single file is the one-element batch. Returns false
    /// when cancelled.
    pub(crate) fn prefetch_go_import_inputs(
        &self,
        context_id: i64,
        files: &[(&str, &str)],
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let connection = self.ready.inventory.connection();
        let mut pending = Vec::new();
        for &(path, source_role) in files {
            let Some(source) = self.mount_table().mount_for_path("go", path)? else {
                continue;
            };
            let record = self
                .ready
                .inventory
                .mount_record_by_ordinal(source.ordinal())?;
            if let Some(version) =
                super::go_context::go_placement_file_version(connection, &record)?
            {
                let authority =
                    GoImportAuthority::new(source.ordinal(), context_id, version, source_role);
                if !self.go_import_inputs_loaded(&authority) {
                    pending.push((source.ordinal(), version, source_role));
                }
            }
        }
        self.load_go_import_inputs(context_id, &pending, cancellation)
    }

    /// One statement for the bindings of all listed mounts (staged rows first,
    /// then ordinary rows, as the single-file reader merged them) and one for
    /// their selected import rows.
    pub(super) fn load_go_import_inputs(
        &self,
        context_id: i64,
        files: &[(SelectedResolutionMountOrdinal, i64, &str)],
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if files.is_empty() {
            return Ok(true);
        }
        let connection = self.ready.inventory.connection();
        let syntax_files: Vec<_> = files
            .iter()
            .filter(|(mount, _, _)| {
                !self
                    .go_import_inputs
                    .borrow()
                    .mounts
                    .contains_key(&mount.get())
            })
            .collect();
        let mut loaded: HashMap<u32, GoMountImportInputs> = syntax_files
            .iter()
            .map(|(mount, _, _)| (mount.get(), GoMountImportInputs::default()))
            .collect();
        let mounts = serde_json::to_string(
            &syntax_files
                .iter()
                .map(|(mount, _, _)| mount.get())
                .collect::<Vec<_>>(),
        )
        .map_err(|error| StoreError::new(format!("Go mount request is not JSON: {error}")))?;
        if !syntax_files.is_empty()
            && !self.ready.inventory.stage_family_is_empty(
                super::super::resolution_stage::StageFamily::GoPackageImports,
            )?
        {
            let mut statement = connection.prepare_cached(STAGED_IMPORT_BINDINGS)?;
            let mut rows = statement.query([&mounts])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                let fact = GoImportBindingRow::staged(row)?;
                let inputs = loaded
                    .get_mut(&row.get::<_, u32>(8)?)
                    .expect("Go import binding row names a requested mount");
                if inputs
                    .bindings
                    .insert(fact.metadata.definition, fact)
                    .is_some_and(|prior| prior != fact)
                {
                    return Err(StoreError::corrupt(
                        "contradictory staged Go import binding metadata",
                    ));
                }
            }
            drop(rows);
            drop(statement);
        }
        if !syntax_files.is_empty() {
            let mut statement = connection.prepare_cached(ORDINARY_IMPORT_BINDINGS)?;
            let mut rows = statement.query([&mounts])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                let fact = GoImportBindingRow::ordinary(row)?;
                loaded
                    .get_mut(&row.get::<_, u32>(8)?)
                    .expect("Go import binding row names a requested mount")
                    .bindings
                    .entry(fact.metadata.definition)
                    .or_insert(fact);
            }
            drop(rows);
            drop(statement);
        }
        let mut selected: HashMap<_, _> = files
            .iter()
            .map(|(mount, version, role)| {
                let authority = GoImportAuthority::new(*mount, context_id, *version, role);
                (
                    authority.clone(),
                    GoSelectedImportInputs {
                        authority,
                        imports: HashMap::default(),
                    },
                )
            })
            .collect();
        let requested = serde_json::to_string(
            &files
                .iter()
                .map(|(mount, version, role)| (mount.get(), version, role))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| StoreError::new(format!("Go file request is not JSON: {error}")))?;
        let mut statement = connection.prepare_cached(&GO_FILE_IMPORT_ROWS)?;
        let mut rows = statement.query(rusqlite::params![context_id, requested])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let mount: u32 = row.get(0)?;
            let package_name: Option<String> = row.get(4)?;
            let package_id: Option<i64> = row.get(5)?;
            let spelling: String = row.get(1)?;
            let language_label: String = row.get(6)?;
            let language = Language::from_config_label(&language_label).ok_or_else(|| {
                StoreError::corrupt(format!("unknown selected language {language_label:?}"))
            })?;
            let has_source_declarations: bool = row.get(9)?;
            // Read the same canonical source anchor as SOURCE_INVENTORY_SQL,
            // restricted to this already-selected provider's admitted source.
            // ForTest names the tested package even on copied dependencies,
            // and opaque tool ImportPath suffixes are never source FQN prefixes.
            let provider_path: Option<String> = if has_source_declarations {
                row.get::<_, Option<String>>(15)?
                    .filter(|path| !path.is_empty())
            } else {
                row.get(10)?
            };
            let provider_kind: Option<String> = row.get(11)?;
            let modeled_provider = if package_name.is_none() {
                self.model_declared_go_package(language, &spelling)
            } else if !has_source_declarations
                && row.get::<_, bool>(2)?
                && row.get::<_, Option<bool>>(14)? == Some(true)
                && provider_kind
                    .as_deref()
                    .is_some_and(|kind| matches!(kind, "standard" | "module"))
            {
                Some(GoSelectedExternalImport {
                    source_spelling: spelling.clone(),
                    import_path: row.get(10)?,
                    package_name: package_name.clone().expect("confirmed package name"),
                    provenance: GoExternalPackageProvenance::GoTool {
                        provider_kind: provider_kind.expect("confirmed tool provider"),
                        module_path: row.get(12)?,
                        module_version: row.get(13)?,
                    },
                })
            } else {
                None
            };
            let gaps: String = row.get(3)?;
            let gap_values: Vec<serde_json::Value> = serde_json::from_str(&gaps)
                .map_err(|error| StoreError::new(format!("invalid Go import gaps: {error}")))?;
            let source_refusal: Option<super::super::go_package_context::GoSourceImportRefusal> =
                gap_values
                    .into_iter()
                    .find_map(|gap| {
                        (gap["code"] == "incomplete_import_provider" && gap["evidence"].is_object())
                            .then(|| serde_json::from_value(gap["evidence"].clone()))
                    })
                    .transpose()
                    .map_err(|error| {
                        StoreError::new(format!("invalid Go source import refusal: {error}"))
                    })?;
            if let Some(refusal) = &source_refusal {
                use super::super::go_package_context::GoSourceImportRefusalReason;
                let valid = match refusal.reason {
                    GoSourceImportRefusalReason::RelativeImportInModuleMode => {
                        refusal.module_manifest.is_some()
                    }
                    GoSourceImportRefusalReason::RelativeImportOutsideWorkspace => {
                        refusal.directory.is_none()
                    }
                    GoSourceImportRefusalReason::SourcePackageDirectoryUnavailable
                    | GoSourceImportRefusalReason::ConflictingSourcePackageNames => {
                        refusal.directory.is_some()
                    }
                };
                if !valid {
                    return Err(StoreError::new(format!(
                        "invalid Go source import refusal fields: {refusal:?}"
                    )));
                }
            }
            let authority = GoImportAuthority {
                mount,
                context_id,
                file_version: row.get(7)?,
                source_role: row.get(8)?,
            };
            selected
                .get_mut(&authority)
                .expect("Go import row names a requested authority")
                .imports
                .insert(
                    spelling,
                    GoFileImportRow {
                        complete: modeled_provider.is_some() || row.get::<_, bool>(2)?,
                        gaps,
                        source_refusal,
                        package_name,
                        package_id,
                        modeled_provider,
                        has_source_declarations,
                        provider_path,
                    },
                );
        }
        drop(rows);
        drop(statement);
        if !syntax_files.is_empty() {
            let mut statement = connection.prepare_cached(GO_DOT_IMPORT_MOUNTS)?;
            let mut rows = statement.query([&mounts])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                loaded
                    .get_mut(&row.get::<_, u32>(0)?)
                    .expect("Go dot import row names a requested mount")
                    .has_dot_import = true;
            }
            drop(rows);
            drop(statement);
        }
        let mut cache = self.go_import_inputs.borrow_mut();
        cache.mounts.extend(loaded);
        cache.selected.extend(selected);
        Ok(true)
    }

    fn go_import_diagnostic_binding(
        &self,
        local_name: &str,
        source_spelling: String,
        provider: Option<&GoFileImportRow>,
        completion: ResolutionCompletion,
    ) -> GoImportDiagnosticBinding {
        let named_reasons = match &completion {
            ResolutionCompletion::Complete => Vec::new(),
            ResolutionCompletion::Incomplete(reasons) => reasons
                .iter()
                .filter_map(|reason| {
                    if let ResolutionIncompleteReason::UnsupportedSemantic(id) = reason {
                        self.ready.context_identities.named_reason(*id)
                    } else {
                        None
                    }
                })
                .collect(),
        };
        GoImportDiagnosticBinding {
            local_name: local_name.into(),
            source_spelling,
            provider_package_id: provider.and_then(|row| row.package_id),
            provider_path: provider.and_then(|row| {
                row.provider_path
                    .clone()
                    .or_else(|| row.modeled_provider.as_ref().map(|p| p.import_path.clone()))
            }),
            has_source_declarations: provider.is_some_and(|row| row.has_source_declarations),
            completion,
            named_reasons,
        }
    }

    /// Bind explicit aliases and selected canonical package names in this file.
    /// Positioned prefixes are answered later by the demand-root provider.
    /// Package bindings never establish a nominal receiver type.
    #[doc(hidden)]
    pub fn go_import_binding_context(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoPreparedImportContextOutcome> {
        if cancellation.is_cancelled() {
            return Ok(GoPreparedImportContextOutcome::Cancelled);
        }
        let Some(selection) = self.go_context_selection(context_id, source_role)? else {
            return Ok(GoPreparedImportContextOutcome::Unavailable);
        };
        self.go_import_binding_context_for_selection(
            context_id,
            caller_path,
            source_role,
            &selection,
            GoPreparationStage::Full,
            cancellation,
        )
    }

    fn go_import_binding_context_for_selection(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        selection: &GoContextSelection,
        stage: GoPreparationStage,
        cancellation: &CancellationToken,
    ) -> Result<GoPreparedImportContextOutcome> {
        let package_context = match stage {
            GoPreparationStage::Full => self.go_package_context_for_selection(
                context_id,
                caller_path,
                source_role,
                selection,
                cancellation,
            )?,
            GoPreparationStage::ImportBase => self.go_dot_import_context_for_selection(
                context_id,
                caller_path,
                source_role,
                selection,
                cancellation,
            )?,
        };
        let (context, package_inventory) = match package_context {
            GoDotImportContext::Ready { context, inventory } => (context, inventory),
            GoDotImportContext::Unavailable => {
                return Ok(GoPreparedImportContextOutcome::Unavailable);
            }
            GoDotImportContext::Cancelled => {
                return Ok(GoPreparedImportContextOutcome::Cancelled);
            }
        };
        let source = self
            .mount_table()
            .mount_for_path("go", caller_path)?
            .expect("package context validated its caller mount");
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let connection = self.ready.inventory.connection();
        let version = super::go_context::go_placement_file_version(connection, &record)?
            .expect("package context requires a selected placement");
        let authority = GoImportAuthority::new(source.ordinal(), context_id, version, source_role);
        if !self.go_import_inputs_loaded(&authority)
            && !self.load_go_import_inputs(
                context_id,
                &[(source.ordinal(), version, source_role)],
                cancellation,
            )?
        {
            return Ok(GoPreparedImportContextOutcome::Cancelled);
        }
        let cache = self.go_import_inputs.borrow();
        let inputs = cache
            .mounts
            .get(&source.ordinal().get())
            .expect("Go syntax inputs were loaded for the caller mount")
            .clone();
        let selected = cache
            .selected
            .get(&authority)
            .expect("Go import inputs were loaded for the caller authority");
        debug_assert_eq!(selected.authority, authority);
        let selected = selected.clone();
        drop(cache);
        let Some(imports) =
            super::super::source_facts::read_source_imports(connection, record.blob_id(), &|| {
                !cancellation.is_cancelled()
            })?
        else {
            return Ok(GoPreparedImportContextOutcome::Cancelled);
        };
        let names = self.ready.shared_names();
        let lexical = self.ready.lexical_source();
        let completion = context.inventory_completion().clone();
        let gaps: Vec<serde_json::Value> = serde_json::from_str(&selection.evidence)
            .map_err(|error| StoreError::corrupt(format!("invalid Go context gaps: {error}")))?;
        let mut diagnostic_view = GoImportDiagnosticView::default();
        for gap in gaps {
            if let Some(
                code @ ("missing_source_package_authority" | "unavailable_source_publication"),
            ) = gap.get("code").and_then(serde_json::Value::as_str)
            {
                let file = gap
                    .get("evidence")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        StoreError::corrupt("Go source authority gap has no file evidence")
                    })?;
                diagnostic_view
                    .source_authority_gaps
                    .push(GoSourceAuthorityGap {
                        code: code.into(),
                        file: file.into(),
                    });
            }
        }
        // Dot and blank imports do not create lexical binding descriptors, but
        // their selected provider authority is still diagnostic input.
        for import in &imports {
            let Some(alias @ ("." | "_")) = import.alias.as_deref() else {
                continue;
            };
            let Some(path) = &import.path else {
                continue;
            };
            let spelling = path.segments.join("/");
            let provider = selected.imports.get(&spelling);
            let import_completion = self.go_import_completion_for(
                context_id,
                version,
                source_role,
                &spelling,
                provider,
                &completion,
            );
            diagnostic_view
                .bindings
                .push(self.go_import_diagnostic_binding(
                    alias,
                    spelling,
                    provider,
                    import_completion,
                ));
        }
        let mut bindings = Vec::new();
        let mut import_packages = HashMap::default();
        let mut modeled_imports = HashMap::default();
        for row in inputs.bindings.into_values() {
            if cancellation.is_cancelled() {
                return Ok(GoPreparedImportContextOutcome::Cancelled);
            }
            if row.metadata.kind == ResolutionGoPackageImportKind::Blank {
                continue;
            }
            let import = imports.get(row.source_import).ok_or_else(|| {
                StoreError::corrupt("Go import metadata names absent source import")
            })?;
            let Some(path) = &import.path else {
                return Err(StoreError::corrupt(
                    "Go package import has no structured source path",
                ));
            };
            let spelling = path.segments.join("/");
            let selected = selected.imports.get(&spelling);
            let import_completion = self.go_import_completion_for(
                context_id,
                version,
                source_role,
                &spelling,
                selected,
                &completion,
            );
            let package_name = selected.and_then(|row| row.package_name.as_deref());
            let package_id = selected.and_then(|row| row.package_id);
            let modeled_provider = selected.and_then(|row| row.modeled_provider.as_ref());
            let presumed =
                import.alias.is_none() && package_name.is_none() && modeled_provider.is_none();
            let Some(name) = import
                .alias
                .as_deref()
                .or(package_name)
                .or(modeled_provider.map(|provider| provider.package_name.as_str()))
                .or_else(|| {
                    presumed
                        .then(|| path.segments.last().map(String::as_str))
                        .flatten()
                })
            else {
                continue;
            };
            if presumed {
                assert!(
                    !matches!(import_completion, ResolutionCompletion::Complete),
                    "a presumed binder requires an unresolved provider"
                );
            }
            diagnostic_view
                .bindings
                .push(self.go_import_diagnostic_binding(
                    name,
                    spelling.clone(),
                    selected,
                    import_completion.clone(),
                ));
            let Some(definition_node) =
                lexical.lookup_definition_node(row.metadata.definition, cancellation)?
            else {
                if cancellation.is_cancelled() {
                    return Ok(GoPreparedImportContextOutcome::Cancelled);
                }
                return Err(StoreError::corrupt(
                    "Go import metadata has no selected definition node",
                ));
            };
            if package_name.is_some() {
                import_packages.insert(
                    (source.ordinal(), row.metadata.definition),
                    package_id.expect("a durable package clause has a provider row"),
                );
            }
            if let Some(provider) = modeled_provider {
                modeled_imports.insert(
                    (source.ordinal(), row.metadata.definition),
                    provider.clone(),
                );
            }
            let binding = SelectedGoImportBindingDescriptor::new(
                source.fragment(),
                &row.metadata,
                definition_node,
                ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Package,
                    name,
                )
                .semantic(&names),
                import_completion,
            );
            bindings.push(
                if !selected.is_some_and(|row| row.has_source_declarations) {
                    binding.with_unindexed_provider(spelling.into(), package_id)
                } else {
                    binding
                },
            );
        }
        let mounts = self.mount_table();
        let Some(context) = context.extend_go_import_bindings(
            bindings,
            cancellation,
            &selected_mount_lookup(mounts),
        )?
        else {
            return Ok(GoPreparedImportContextOutcome::Cancelled);
        };
        let demand = GoDemandContext {
            context_id,
            import_packages,
            modeled_imports,
            context_completions: HashMap::from_iter([(
                source.ordinal(),
                context.inventory_completion().clone(),
            )]),
        };
        self.record_go_package_inventory_state(&package_inventory);
        Ok(GoPreparedImportContextOutcome::Ready(Box::new(
            GoPreparedImportContext {
                stage,
                context,
                demand,
                source_import_refusals: selected
                    .imports
                    .values()
                    .filter_map(|row| row.source_refusal.clone())
                    .collect(),
                package_inventory,
                blueprint: None,
                diagnostic_view: Some(diagnostic_view),
            },
        )))
    }

    /// Test-only oracle for the historical eager qualified-prefix compiler.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn go_eager_import_binding_context(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        let prepared = match self.go_import_binding_context(
            context_id,
            caller_path,
            source_role,
            cancellation,
        )? {
            GoPreparedImportContextOutcome::Ready(prepared) => prepared,
            GoPreparedImportContextOutcome::Unavailable => {
                return Ok(GoDotImportContext::Unavailable);
            }
            GoPreparedImportContextOutcome::Cancelled => {
                return Ok(GoDotImportContext::Cancelled);
            }
        };
        let source = self
            .mount_table()
            .mount_for_path("go", caller_path)?
            .expect("prepared Go context has a selected source mount");
        let providers = prepared
            .demand
            .import_packages
            .iter()
            .filter_map(|((mount, semantic), package)| {
                (*mount == source.ordinal()).then_some((*semantic, *package))
            })
            .collect::<HashMap<_, _>>();
        self.go_eager_qualified_import_context(
            prepared.context,
            source.ordinal(),
            context_id,
            &providers,
            prepared.package_inventory,
            cancellation,
        )
    }

    /// Authorize package exports only through definitions actually reached by
    /// the positioned lexical prefix. Local values and types remain blockers.
    #[cfg(any(test, feature = "test-support"))]
    fn go_eager_qualified_import_context(
        &self,
        context: SelectedResolutionContextSet,
        source: SelectedResolutionMountOrdinal,
        context_id: i64,
        providers: &HashMap<SemanticId, i64>,
        inventory: GoPackageInventoryState,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        let lexical = self.ready.lexical_source();
        let identities = self.ready.context_identities.clone();
        let mut halves = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &identities,
            &lexical,
            &lexical,
            Some(&[source]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                halves.extend(
                    page.iter()
                        .filter(|half| {
                            matches!(
                                half,
                                SelectedRootPathHalf::Reference {
                                    prefix_reference: Some(_),
                                    ..
                                }
                            )
                        })
                        .cloned(),
                );
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(GoDotImportContext::Cancelled);
        }
        if halves.is_empty() {
            return Ok(GoDotImportContext::Ready { context, inventory });
        }
        let mut references = halves
            .iter()
            .map(|half| match half {
                SelectedRootPathHalf::Reference {
                    prefix_reference: Some(reference),
                    route,
                    ..
                } => {
                    assert!(
                        route.is_empty(),
                        "Go package qualifier has exactly one prefix segment"
                    );
                    *reference
                }
                _ => unreachable!("qualified reference filter"),
            })
            .collect::<Vec<_>>();
        references.sort_unstable();
        references.dedup();
        let Some(blueprint) = self.prepare_prefix_blueprint(context.clone(), cancellation)? else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let typed = self.ready.typed_source();
        let resolutions = blueprint.with_forward_operation_in_session(
            &lexical,
            &lexical,
            &typed,
            cancellation,
            &ResolutionSession::unbounded(),
            |operation| {
                let mut resolutions = HashMap::default();
                for references in references.chunks(MAX_REFERENCE_SEEDS_PER_BATCH) {
                    let batch = operation.resolve_references_with_metrics(
                        references,
                        &mut ResolutionBatchMetrics::default(),
                    )?;
                    if cancellation.is_cancelled()
                        || batch
                            .completion()
                            .contains_reason(ResolutionIncompleteReason::Cancelled)
                    {
                        return Ok(None);
                    }
                    for answer in batch.answers() {
                        let binding = answer.answer().binding();
                        assert_eq!(
                            answer
                                .answer()
                                .site_metadata()
                                .expect("positioned Go prefix metadata")
                                .namespace(),
                            ResolutionNamespace::TypeOrValue
                        );
                        resolutions.insert(
                            answer.reference(),
                            (binding.targets().to_vec(), binding.completion().clone()),
                        );
                    }
                }
                Ok(Some(resolutions))
            },
        )?;
        let Some(resolutions) = resolutions else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let mut bridges = Vec::new();
        for half in halves {
            let SelectedRootPathHalf::Reference {
                identity,
                prefix_reference: Some(prefix),
                token,
                anchor,
                anchor_semantic,
                demand,
                ..
            } = half
            else {
                unreachable!("qualified reference filter")
            };
            let (targets, completion) = resolutions
                .get(&prefix)
                .expect("every requested prefix has an answer");
            let SelectedLookupRecipeReadOutcome::Ready(recipes) = lexical.lookup_semantic_recipes(
                &[SelectedLookupRecipeRequest {
                    fragment: identity.fragment(),
                    semantic: demand,
                }],
                cancellation,
                None,
            )?
            else {
                return Ok(GoDotImportContext::Cancelled);
            };
            let recipe =
                recipes.into_iter().next().flatten().ok_or_else(|| {
                    StoreError::corrupt("Go qualified demand lacks lookup recipe")
                })?;
            for target in targets {
                let Some(package) = providers.get(target) else {
                    continue;
                };
                let connection = self.ready.inventory.connection();
                let mut statement = connection.prepare_cached(NAMED_IMPORT_TARGET_MOUNTS)?;
                let mut rows = statement.query(rusqlite::params![context_id, package])?;
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(GoDotImportContext::Cancelled);
                    }
                    let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
                    let outcome = visit_selected_root_export_half_pages(
                        &identities,
                        &lexical,
                        &lexical,
                        Some(&[ordinal]),
                        cancellation,
                        &mut FactPageVisitor::new(&mut |page| {
                            for export in page {
                                let SelectedRootPathHalf::Export {
                                    identity: target,
                                    token: export_token,
                                    demand: export_demand,
                                    ..
                                } = export
                                else {
                                    unreachable!("export-only visitor")
                                };
                                if *export_demand == demand {
                                    bridges.push(SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                                        identity.fragment(), Language::Go, token, anchor, anchor_semantic,
                                        target.fragment(), Language::Go, *export_token, prefix,
                                        Vec::new(), recipe.clone(), recipe.clone(),
                                        completion.combine(context.inventory_completion()),
                                    ).with_selected_export(&self.ready.shared_names(), export));
                                }
                            }
                            Ok(true)
                        }),
                    )?;
                    if outcome.is_cancelled() {
                        return Ok(GoDotImportContext::Cancelled);
                    }
                }
            }
        }
        let mounts = self.mount_table();
        Ok(
            match context.extend_root_bridges(
                bridges,
                cancellation,
                None,
                &selected_mount_lookup(mounts),
            )? {
                Some(context) => GoDotImportContext::Ready { context, inventory },
                None => GoDotImportContext::Cancelled,
            },
        )
    }
}

pub(crate) const NAMED_IMPORT_TARGET_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal
FROM temp.selected_go_context_source_files provider
JOIN main.go_package_instances package ON package.context_id=provider.context_id AND package.package_id=provider.package_id
JOIN temp.selected_resolution_mounts mounted ON mounted.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=mounted.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND (provider.source_role='go' OR (provider.source_role='test' AND package.for_test<>''))
 AND mounted.storage_language='go'
UNION ALL
SELECT placed.mount_ordinal
FROM temp.selected_go_context_source_files provider
JOIN main.go_package_instances package ON package.context_id=provider.context_id AND package.package_id=provider.package_id
JOIN temp.selected_go_transient_placements placed ON placed.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=placed.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND (provider.source_role='go' OR (provider.source_role='test' AND package.for_test<>''))
"#;

pub(crate) static GO_INTERVAL_GO_GRAPH_FILE_EXCLUSION_0_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"SELECT EXISTS(SELECT 1 FROM ({})
             WHERE context_id=?1 AND file_version_id=?2 AND source_role='ignored')"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

pub(crate) static GO_INTERVAL_GO_GRAPH_FILE_EXCLUSION_1_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"SELECT EXISTS(SELECT 1 FROM ({}) source
             JOIN main.go_package_instances package USING(package_id)
             JOIN main.go_context_publications publication ON publication.context_id=source.context_id
             JOIN main.go_context_selections selection ON selection.selection_id=publication.selection_id
             JOIN temp.selected_workspace_revisions selected
               ON selected.workspace_id=selection.workspace_id AND selected.lang=selection.lang
              AND selected.generation=selection.generation
              AND publication.valid_from<=selected.revision AND (publication.valid_until IS NULL OR selected.revision<publication.valid_until)
             WHERE source.file_version_id=?1 AND package.provider_provenance='source_inventory')"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

pub(crate) const DOMAIN_FOR_MODULE_SQL: &str = r#"
SELECT c.context_id, s.domain_dir, s.gowork_path,
       (SELECT json_extract(gap.value, '$.evidence') FROM json_each(c.gaps) gap
        WHERE json_extract(gap.value, '$.code')='domain_discovery_failed' LIMIT 1)
FROM go_context_domain_modules m
JOIN go_context_publications c ON c.context_id=m.context_id
JOIN go_context_selections s ON s.selection_id=c.selection_id
WHERE m.module_dir=?6 AND s.workspace_id=?1 AND s.lang='go' AND s.generation=?2
  AND s.base_profile_digest=?4 AND s.derivation_version=?5
  AND c.valid_from<=?3 AND (c.valid_until IS NULL OR ?3<c.valid_until)
"#;

impl super::super::cache_budget::RetainedBytes for GoPreparedContextCacheKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            + self.caller_path.capacity()
            + self.source_role.capacity()
            + self
                .active_model_set_hash
                .as_ref()
                .map_or(0, String::capacity)
    }
}

impl super::super::cache_budget::RetainedBytes for GoPreparedImportContextSnapshot {
    fn retained_bytes(&self) -> usize {
        let mut heap = super::super::cache_budget::RetainedHeap::default();
        heap.add(std::mem::size_of_val(self));
        assert!(
            self.prepared.blueprint.is_none(),
            "a cached context retains no request blueprint"
        );
        self.prepared.context.charge_retained(&mut heap);
        heap.map(&self.shared_names);
        let demand = &self.prepared.demand;
        heap.map(&demand.import_packages);
        heap.map(&demand.context_completions);
        for completion in demand.context_completions.values() {
            completion.charge_retained(&mut heap);
        }
        heap.map(&demand.modeled_imports);
        for provider in demand.modeled_imports.values() {
            heap.add(
                provider.source_spelling.capacity()
                    + provider.import_path.capacity()
                    + provider.package_name.capacity(),
            );
            match &provider.provenance {
                GoExternalPackageProvenance::GoTool {
                    provider_kind,
                    module_path,
                    module_version,
                } => {
                    heap.add(
                        provider_kind.capacity()
                            + module_path.as_ref().map_or(0, String::capacity)
                            + module_version.as_ref().map_or(0, String::capacity),
                    );
                }
                GoExternalPackageProvenance::SemanticModel {
                    symbol_id,
                    pack_id,
                    pack_digest,
                    record_id,
                } => {
                    heap.add(
                        symbol_id.capacity()
                            + pack_id.capacity()
                            + pack_digest.capacity()
                            + record_id.capacity(),
                    );
                }
            }
        }
        heap.vec(&self.prepared.source_import_refusals);
        for refusal in &self.prepared.source_import_refusals {
            heap.add(
                refusal.importer.capacity()
                    + refusal.spelling.capacity()
                    + refusal.role.capacity()
                    + refusal.directory.as_ref().map_or(0, String::capacity)
                    + refusal.module_manifest.as_ref().map_or(0, String::capacity),
            );
            heap.vec(&refusal.candidates);
            heap.vec(&refusal.declared_names);
            heap.add(
                refusal
                    .candidates
                    .iter()
                    .chain(&refusal.declared_names)
                    .map(String::capacity)
                    .sum(),
            );
        }
        heap.map(&self.prepared.package_inventory.fragments);
        if let Some(view) = &self.prepared.diagnostic_view {
            heap.vec(&view.bindings);
            for binding in &view.bindings {
                heap.add(
                    binding.local_name.capacity()
                        + binding.source_spelling.capacity()
                        + binding.provider_path.as_ref().map_or(0, String::capacity),
                );
                binding.completion.charge_retained(&mut heap);
                heap.vec(&binding.named_reasons);
                for (_, reason) in &binding.named_reasons {
                    heap.arc(reason, |_, _| {});
                }
            }
            heap.vec(&view.source_authority_gaps);
            for gap in &view.source_authority_gaps {
                heap.add(gap.code.capacity() + gap.file.capacity());
            }
        }
        heap.total()
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::analyzer::resolution::local_identity::PerRequestSharedNames;
    use crate::analyzer::resolution::{ExternalOwnerIdentity, ExternalOwnerLanguage};
    use crate::analyzer::semantic_model::{ModelProvider, ModelSymbolRef};

    fn snapshot(identities: SelectedContextIdentities) -> GoPreparedImportContextSnapshot {
        GoPreparedImportContextSnapshot {
            prepared: GoPreparedImportContext {
                stage: GoPreparationStage::Full,
                context: SelectedResolutionContextSet::new(identities, Vec::new(), 0, &|_| {
                    Ok(None)
                })
                .unwrap(),
                demand: GoDemandContext {
                    context_id: 1,
                    import_packages: HashMap::default(),
                    context_completions: HashMap::default(),
                    modeled_imports: HashMap::default(),
                },
                source_import_refusals: Vec::new(),
                package_inventory: GoPackageInventoryState::default(),
                blueprint: None,
                diagnostic_view: None,
            },
            shared_names: HashMap::default(),
        }
    }

    #[test]
    #[should_panic(expected = "diagnostic snapshot retains only canonical named reasons")]
    fn prepared_context_snapshot_rejects_unregistered_diagnostic_identity() {
        let mut cached = snapshot(SelectedContextIdentities::new());
        cached.prepared.diagnostic_view = Some(GoImportDiagnosticView {
            bindings: vec![GoImportDiagnosticBinding {
                local_name: "missing".into(),
                source_spelling: "example.test/missing".into(),
                provider_package_id: None,
                provider_path: None,
                has_source_declarations: false,
                completion: ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::context_local(1)),
                ]),
                named_reasons: Vec::new(),
            }],
            source_authority_gaps: Vec::new(),
        });
        let _prepared = cached.restored_for_request(
            &SelectedContextIdentities::new(),
            &PerRequestSharedNames::new(),
        );
    }

    #[test]
    #[should_panic(
        expected = "external provider type identities cannot enter a prepared-context snapshot"
    )]
    fn prepared_context_snapshot_rejects_go_provider_boundary() {
        let names = PerRequestSharedNames::new();
        let identities = SelectedContextIdentities::new();
        let identity = SemanticId::shared_name(names.intern([1; 32]));
        identities.record_jvm_external_provider_type_identity(
            ExternalOwnerLanguage::Go,
            identity,
            identity,
            identity,
            identity,
        );
        let _prepared =
            snapshot(identities).restored_for_request(&SelectedContextIdentities::new(), &names);
    }

    #[test]
    #[should_panic(expected = "external owners cannot enter a prepared-context snapshot")]
    fn prepared_context_snapshot_rejects_go_external_owner() {
        let names = PerRequestSharedNames::new();
        let identities = SelectedContextIdentities::new();
        identities.external_owner_semantic_for_language(
            ExternalOwnerLanguage::Go,
            &ExternalOwnerIdentity {
                provider_id: Arc::from("test-provider"),
                owner_fqn: Arc::from("example.test/Owner"),
            },
            &names,
        );
        let _prepared =
            snapshot(identities).restored_for_request(&SelectedContextIdentities::new(), &names);
    }

    /// A kind outside the Go allow-list, here a JVM owner, is refused in
    /// release builds too, not only by a debug assertion.
    #[test]
    #[should_panic(expected = "external owners cannot enter a prepared-context snapshot")]
    fn prepared_context_snapshot_rejects_identity_outside_go_allow_list() {
        let names = PerRequestSharedNames::new();
        let identities = SelectedContextIdentities::new();
        identities.external_owner_semantic_for_language(
            ExternalOwnerLanguage::Jvm,
            &ExternalOwnerIdentity {
                provider_id: Arc::from("test-provider"),
                owner_fqn: Arc::from("example.Owner"),
            },
            &names,
        );
        let _prepared =
            snapshot(identities).restored_for_request(&SelectedContextIdentities::new(), &names);
    }

    #[test]
    #[should_panic(expected = "model member tokens cannot enter a prepared-context snapshot")]
    fn prepared_context_snapshot_rejects_model_member_token() {
        let names = PerRequestSharedNames::new();
        let identities = SelectedContextIdentities::new();
        let member = ModelSymbolRef {
            symbol_id: "owner.method".into(),
            provider: ModelProvider {
                pack_id: "test-pack".into(),
                pack_version: "1".into(),
                pack_digest: "digest".into(),
            },
        };
        let token = identities.model_member_semantic(&member, &names);
        assert_eq!(identities.model_member_identity(token), Some(member));
        let isolated = identities.isolated_clone();
        let restored = SelectedContextIdentities::new();
        restored.copy_from_empty(&isolated);
        assert!(!restored.is_empty());
        let _prepared =
            snapshot(restored).restored_for_request(&SelectedContextIdentities::new(), &names);
    }
}
