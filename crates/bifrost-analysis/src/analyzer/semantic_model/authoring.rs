use crate::analyzer::semantic_model::{
    CatalogError, ResolvedActiveSemanticModels, SemanticModelActivationEvidence,
    SemanticModelActivationStatus, SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
    SourceFormat, compile_source,
};
pub use brokk_bifrost_semantic::analyzer::semantic_model::authoring::*;
use std::fs;
use std::path::Path;
/// Discover, compile, and register the reviewed workspace-local semantic
/// models beneath `workspace_root` into `catalog`.
///
/// This is the one route every host uses for `.bifrost/semantic-models/`: the
/// MCP bind path, the CLI policy runner through the pack-activation
/// transaction, and the LSP through the same transaction. Each accepted file
/// becomes an [`SessionPackSourceKind::EphemeralWorkspace`] session pack whose
/// source id names the path and the reviewed source digest, so activation
/// provenance says the model came from the workspace.
///
/// Registration is not activation. The caller still has to put the returned
/// evidence into its activation request, and a `review_required` pack still
/// needs an explicit compatible `Enable` control before it becomes active.
/// [`workspace_semantic_models_not_active`] proves what actually happened.
pub fn register_workspace_semantic_models(
    workspace_root: &Path,
    catalog: &SemanticPackCatalog,
    options: WorkspaceSemanticModelOptions,
) -> Result<WorkspaceSemanticModelRegistration, WorkspaceSemanticModelRegistrationError> {
    let report = discover_workspace_semantic_models(workspace_root, options);
    if !report.complete {
        return Err(
            WorkspaceSemanticModelRegistrationError::DiscoveryIncomplete {
                report: Box::new(report),
            },
        );
    }
    if !report.enabled {
        return Ok(WorkspaceSemanticModelRegistration::default());
    }

    let mut registration = WorkspaceSemanticModelRegistration {
        enabled: true,
        models: Vec::with_capacity(report.files.len()),
        evidence: Vec::with_capacity(report.files.len()),
    };
    for file in report.files {
        let format = match file.source_format.as_str() {
            "json" => SourceFormat::Json,
            "yaml" => SourceFormat::Yaml,
            value => {
                return Err(
                    WorkspaceSemanticModelRegistrationError::UnsupportedSourceFormat {
                        path: file.path,
                        format: value.to_owned(),
                    },
                );
            }
        };
        let source_path = workspace_root.join(Path::new(&file.path));
        let bytes = fs::read(&source_path).map_err(|source| {
            WorkspaceSemanticModelRegistrationError::ReadFailed {
                path: file.path.clone(),
                source,
            }
        })?;
        let compiled =
            compile_source(format, &bytes, &options.compiler).map_err(|diagnostics| {
                WorkspaceSemanticModelRegistrationError::CompileFailed {
                    path: file.path.clone(),
                    diagnostics,
                }
            })?;
        let source_id = format!("workspace:{}#sha256={}", file.path, file.source_sha256);
        let manifest_digest = catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id,
                },
            )
            .map_err(
                |source| WorkspaceSemanticModelRegistrationError::RegistrationFailed {
                    path: file.path.clone(),
                    source,
                },
            )?;
        registration.evidence.push(SemanticModelActivationEvidence {
            language: compiled.manifest.language.clone(),
            ecosystem: compiled.manifest.ecosystem.clone(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: Some(compiled.manifest.pack_id.clone()),
            artifact_sha256: None,
        });
        registration.models.push(RegisteredWorkspaceSemanticModel {
            path: file.path,
            pack_id: compiled.manifest.pack_id.clone(),
            manifest_digest,
        });
    }
    Ok(registration)
}

/// Prove that every registered workspace model reached the active set.
///
/// A registered model that never activates is invisible, and an invisible
/// model decides verdicts by its absence. Hosts call this straight after
/// activation and report what comes back; the empty result is the proof.
pub fn workspace_semantic_models_not_active<'a>(
    models: &'a [RegisteredWorkspaceSemanticModel],
    active: &'a ResolvedActiveSemanticModels,
) -> Vec<InactiveWorkspaceSemanticModel<'a>> {
    let mut inactive = Vec::new();
    for model in models {
        if active
            .shards()
            .iter()
            .any(|shard| shard.manifest.content_sha256 == model.manifest_digest)
        {
            continue;
        }
        let explanation = active
            .activation_report()
            .explanations
            .iter()
            .find(|explanation| explanation.manifest_digest == model.manifest_digest);
        inactive.push(InactiveWorkspaceSemanticModel {
            model,
            status: explanation.map(|explanation| explanation.status),
            reason: explanation.map(|explanation| explanation.reason.as_str()),
        });
    }
    inactive
}

pub fn semantic_model_inventory(
    catalog: &SemanticPackCatalog,
    active: Option<&ResolvedActiveSemanticModels>,
    max_packs: usize,
) -> Result<SemanticModelInventoryReport, CatalogError> {
    let catalog_inventory = catalog.inventory_bounded(max_packs)?;
    let mut active_packs = Vec::new();
    let mut activation_explanations = Vec::new();
    if let Some(active) = active {
        for shard in active.shards() {
            let explanation = active
                .activation_report()
                .explanations
                .iter()
                .find(|explanation| {
                    explanation.manifest_digest == shard.manifest.content_sha256
                        && explanation.shard_id == shard.descriptor.shard_id
                        && explanation.source_kind == shard.source_kind
                        && explanation.source_id == shard.source_id
                        && explanation.status == SemanticModelActivationStatus::Active
                });
            active_packs.push(ActiveSemanticModelInventory {
                manifest_content_sha256: shard.manifest.content_sha256.clone(),
                manifest_semantic_sha256: shard.manifest.semantic_sha256.clone(),
                pack_id: shard.manifest.pack_id.clone(),
                pack_version: shard.manifest.version.clone(),
                shard_id: shard.descriptor.shard_id.clone(),
                payload_kind: payload_kind_name(shard.descriptor.payload_kind).to_owned(),
                source_kind: shard.source_kind.as_str().to_owned(),
                source_id: shard.source_id.clone(),
                activation_status: "active".to_owned(),
                activation_reason: explanation
                    .map(|explanation| explanation.reason.clone())
                    .unwrap_or_else(|| "selected by active semantic-model resolution".to_owned()),
                matched_evidence: inventory_evidence(&shard.matched_evidence),
                provenance: shard.manifest.provenance.clone(),
                completeness: shard.manifest.completeness,
            });
        }
        for explanation in &active.activation_report().explanations {
            activation_explanations.push(SemanticModelInventoryExplanation {
                manifest_content_sha256: explanation.manifest_digest.clone(),
                pack_id: explanation.pack_id.clone(),
                shard_id: explanation.shard_id.clone(),
                source_kind: explanation.source_kind.as_str().to_owned(),
                source_id: explanation.source_id.clone(),
                status: activation_status_name(explanation.status).to_owned(),
                reason: explanation.reason.clone(),
            });
        }
    }
    active_packs.sort_by(|left, right| {
        left.pack_id
            .cmp(&right.pack_id)
            .then_with(|| left.pack_version.cmp(&right.pack_version))
            .then_with(|| left.shard_id.cmp(&right.shard_id))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    activation_explanations.sort_by(|left, right| {
        left.pack_id
            .cmp(&right.pack_id)
            .then_with(|| left.shard_id.cmp(&right.shard_id))
            .then_with(|| left.status.cmp(&right.status))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    Ok(SemanticModelInventoryReport {
        format: SEMANTIC_MODEL_INVENTORY_FORMAT,
        complete: catalog_inventory.complete,
        installed: catalog_inventory.packs,
        active: active_packs,
        activation_explanations,
    })
}
