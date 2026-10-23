use brokk_bifrost_semantic::analyzer::semantic_model::overlay::*;

use crate::analyzer::semantic_model::Completeness;
use crate::analyzer::semantic_model::Locator;
use crate::analyzer::semantic_model::SemanticModelActivationStatus;
use crate::analyzer::store::active_models::ActiveSemanticModelShard;
use crate::analyzer::store::active_models::ResolvedActiveSemanticModels;
use crate::analyzer::store::model_catalog::CatalogPackSourceKind;

use url::Url;

pub fn model_location(
    shard: &ActiveSemanticModelShard,
    record_kind: &str,
    record_id: &str,
) -> SemanticModelLocation {
    let mut uri = Url::parse(MODEL_URI_BASE).expect("static Bifrost model URI base is valid");
    uri.path_segments_mut()
        .expect("Bifrost model URI base supports path segments")
        .extend([
            shard.manifest.semantic_sha256.as_str(),
            record_kind,
            record_id,
        ]);
    SemanticModelLocation::Model(SemanticModelVirtualLocation {
        uri: uri.to_string(),
        range: SemanticModelRange {
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            end_line: 1,
        },
    })
}

pub fn activated_record_provenance(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record_id: &str,
) -> SemanticModelProvenance {
    let location = model_location(shard, "procedure_summary", record_id);
    provenance(active, shard, record_id, &location, None, false)
}

pub fn provenance(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record_id: &str,
    location: &SemanticModelLocation,
    locator: Option<&Locator>,
    ambiguous: bool,
) -> SemanticModelProvenance {
    provenance_with_visits(
        active,
        shard,
        record_id,
        location,
        locator,
        ambiguous,
        &mut || Ok::<_, std::convert::Infallible>(()),
    )
    .unwrap_or_else(|never| match never {})
}

pub fn provenance_with_visits<E>(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record_id: &str,
    _location: &SemanticModelLocation,
    locator: Option<&Locator>,
    ambiguous: bool,
    visit: &mut impl FnMut() -> Result<(), E>,
) -> Result<SemanticModelProvenance, E> {
    let mut activation = None;
    for explanation in &active.activation_report().explanations {
        visit()?;
        if explanation.status == SemanticModelActivationStatus::Active
            && explanation.manifest_digest == shard.manifest.content_sha256
            && explanation.shard_id == shard.shard.shard_id()
            && explanation.source_kind == shard.source_kind
            && explanation.source_id == shard.source_id
        {
            activation = Some(explanation);
            break;
        }
    }
    Ok(SemanticModelProvenance {
        active_model_set_hash: active.active_model_set_hash().to_string(),
        pack_digest: shard.manifest.semantic_sha256.clone(),
        pack_id: shard.manifest.pack_id.clone(),
        pack_version: shard.manifest.version.clone(),
        producer: shard.manifest.producer.name.clone(),
        producer_version: shard.manifest.producer.version.clone(),
        record_id: record_id.to_string(),
        rule_id: None,
        origin: origin(shard, locator),
        activation: SemanticModelActivationProvenance {
            approximate: shard.approximate,
            status: "active".to_string(),
            reason: activation
                .map(|explanation| explanation.reason.clone())
                .unwrap_or_else(|| "selected by active semantic-model resolution".to_string()),
            source_kind: source_kind(shard.source_kind).to_string(),
            source_id: shard.source_id.clone(),
            matched_evidence: matched_evidence(&shard.matched_evidence),
        },
        proof: if shard.matched_evidence.artifact_sha256.is_some() {
            SemanticModelProof::ExactArtifact
        } else {
            SemanticModelProof::PackFact
        },
        completeness: match shard.manifest.completeness {
            Completeness::Partial => SemanticModelCompleteness::Partial,
            Completeness::Complete => SemanticModelCompleteness::Complete,
        },
        ambiguous,
    })
}

pub fn origin(
    shard: &ActiveSemanticModelShard,
    locator: Option<&Locator>,
) -> SemanticModelOriginKind {
    match shard.source_kind {
        CatalogPackSourceKind::Generated | CatalogPackSourceKind::WorkspaceProduced => {
            SemanticModelOriginKind::ExactGeneratedOutput
        }
        CatalogPackSourceKind::Installed => match locator {
            Some(Locator::Source { .. }) => SemanticModelOriginKind::DependencySource,
            Some(Locator::Artifact { .. }) => SemanticModelOriginKind::DependencyBinary,
            Some(Locator::Interchange { .. }) => SemanticModelOriginKind::DeclarativeModel,
            None => SemanticModelOriginKind::PrebuiltApiIndex,
        },
        CatalogPackSourceKind::PreShipped => SemanticModelOriginKind::PrebuiltApiIndex,
        CatalogPackSourceKind::Embedded | CatalogPackSourceKind::EphemeralWorkspace => {
            SemanticModelOriginKind::DeclarativeModel
        }
    }
}

pub fn source_kind(kind: CatalogPackSourceKind) -> &'static str {
    match kind {
        CatalogPackSourceKind::Installed => "installed",
        CatalogPackSourceKind::Generated => "generated",
        CatalogPackSourceKind::PreShipped => "pre_shipped",
        CatalogPackSourceKind::WorkspaceProduced => "workspace_produced",
        CatalogPackSourceKind::Embedded => "embedded",
        CatalogPackSourceKind::EphemeralWorkspace => "ephemeral_workspace",
    }
}
