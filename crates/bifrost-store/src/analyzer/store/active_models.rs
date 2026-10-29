mod rows;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily;
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
use rusqlite::named_params;

use crate::CancellationToken;
use crate::analyzer::canonical_hash::parse_lower_sha256;

use crate::analyzer::CallableArity;
use crate::analyzer::semantic::SemanticLocator;
use crate::analyzer::semantic::StableDigest;
use crate::analyzer::semantic::authored_procedure_target_identity;
use crate::analyzer::semantic_model::CollectionFlowsPayload;
use crate::analyzer::semantic_model::CompiledClassDecoratorIdentity;
use crate::analyzer::semantic_model::CompiledConcurrencyEffect;
use crate::analyzer::semantic_model::CompiledConditionalIndirectWrite;
use crate::analyzer::semantic_model::CompiledConditionalResultRefinement;
use crate::analyzer::semantic_model::CompiledDeclaredEffect;
use crate::analyzer::semantic_model::CompiledNormalReturnRefinement;
use crate::analyzer::semantic_model::CompiledNormalReturnTypeRefinement;
use crate::analyzer::semantic_model::CompiledOperationPrecondition;
use crate::analyzer::semantic_model::CompiledPackManifest;
use crate::analyzer::semantic_model::CompiledProcedureSummary;
use crate::analyzer::semantic_model::CompiledProcedureTarget;
use crate::analyzer::semantic_model::CompiledResultContract;
use crate::analyzer::semantic_model::CompiledResultUseObligation;
use crate::analyzer::semantic_model::CompiledShard;
use crate::analyzer::semantic_model::DeclarationGuard;
use crate::analyzer::semantic_model::DeferredYieldsPayload;
use crate::analyzer::semantic_model::GeneratorRule;
use crate::analyzer::semantic_model::MemberFact;
use crate::analyzer::semantic_model::RelationFact;
use crate::analyzer::semantic_model::RuleTrigger;
use crate::analyzer::semantic_model::RuntimeValuesPayload;
use crate::analyzer::semantic_model::TypeFact;
use crate::analyzer::store::model_catalog::CatalogPackSourceKind;
use crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader;

use crate::analyzer::Language;
use crate::analyzer::LanguageDialect;
use crate::analyzer::semantic_pack_realm;
use crate::hash::map_with_capacity;
use crate::hash::{HashMap, HashSet};

use brokk_bifrost_semantic::analyzer::semantic_model::runtime::*;
use serde::Deserialize;
use serde::Serialize;

use std::cmp::Ordering;

use std::sync::Arc;

impl ActivatedProcedureSummary {
    /// Prove that this activated record applies to the resolver-owned exact
    /// call shape. This is an applicability proof, not a consumer-specific
    /// winner selection: consumers may impose stricter conflict semantics.
    pub fn bind_unmaterialized_call_shape(
        &self,
        target: &UnmaterializedExternalTarget,
    ) -> Option<UnmaterializedExternalSummaryCallShapeBinding> {
        let content = parse_lower_sha256(&self.record.content_sha256)?;
        if self.record.model_id != format!("{}#{}", self.shard.manifest.pack_id, self.record.id)
            || self.record.contract_version == 0
            || !target
                .language()
                .accepts_semantic_pack_language(&self.shard.manifest.language)
            || self.record.target.has_receiver != target.has_receiver()
            || self.matched_target_locator.as_ref() != Some(target.locator())
            || self.matched_call_arguments.as_deref() != target.call_arguments()
            || target.locator_for_arity(target.arity()) != *target.locator()
            || authored_procedure_target_identity(
                &self.record.target.path,
                &self.record.target.symbol,
            )
            .is_none_or(|(owner, member)| {
                (owner != target.owner_fqn()
                    && self.matched_owner_identity.as_deref() != Some(target.owner_fqn()))
                    || member != target.member()
            })
            || !python_artifact_applies_to_target(&self.shard, target)
        {
            return None;
        }
        Some(UnmaterializedExternalSummaryCallShapeBinding {
            actual_locator: target.locator().clone(),
            actual_to_formal: self.actual_to_formal.clone(),
            formal_locator: target.formal_summary_locator(self.record.target.parameter_count),
            model_id: self.record.model_id.clone().into_boxed_str(),
            content: StableDigest::from_array(content),
            contract_version: self.record.contract_version,
            covers_overrides: self.record.covers_overrides,
        })
    }

    /// Whether this exact activated record explicitly claims that no normal
    /// continuation exists.
    pub fn normal_continuation_absent(&self) -> bool {
        self.record.normal_continuation_absent
    }

    /// The namespaced effects the activated pack declares for this procedure
    /// (#2437), in the compiler's canonical order (sorted by id).
    pub fn declared_effects(&self) -> &[CompiledDeclaredEffect] {
        &self.record.declared_effects
    }

    /// Reviewed task, synchronization, and atomic semantics for this exact
    /// procedure. Inputs are formal ports that consumers project to call-site
    /// receiver and argument values.
    pub fn concurrency_effects(&self) -> &[CompiledConcurrencyEffect] {
        &self.record.concurrency_effects
    }

    /// Whether this exact activated record explicitly claims that the call has
    /// no synchronization or concurrent retention effects.
    pub fn no_concurrency_effects(&self) -> bool {
        self.record.no_concurrency_effects
    }

    /// Reviewed predicates required of this exact procedure invocation's
    /// receiver and parameters. `None` means the operation was not reviewed;
    /// `Some([])` means it was reviewed and has no input preconditions.
    pub fn preconditions(&self) -> Option<&[CompiledOperationPrecondition]> {
        self.record.preconditions.as_deref()
    }

    /// The reviewed relationships among this procedure's normal result ports,
    /// in deterministic ordinal order.
    pub fn result_contracts(&self) -> &[CompiledResultContract] {
        &self.record.result_contracts
    }

    pub fn result_use_obligations(&self) -> &[CompiledResultUseObligation] {
        &self.record.result_use_obligations
    }

    /// Reviewed JDK result-use claims for an exact resolver-owned call whose
    /// selected declaration artifact is one of this shard's activating rows.
    /// A model name, release version, or source toolchain alone is insufficient.
    /// Dispatch coverage remains a separate consumer obligation.
    pub fn bind_reviewed_jdk_result_use_obligations(
        &self,
        target: &UnmaterializedExternalTarget,
    ) -> Option<&[CompiledResultUseObligation]> {
        if self.record.result_use_obligations.is_empty()
            || self.shard.manifest.language != "java"
            || self.shard.manifest.ecosystem != "jdk"
            || !target.has_resolver_owned_call_shape()
        {
            return None;
        }
        let selected = target.selected_jdk_artifact()?;
        if self
            .shard
            .matching_evidence
            .binary_search(selected)
            .is_err()
        {
            return None;
        }
        self.bind_unmaterialized_call_shape(target)?;
        Some(&self.record.result_use_obligations)
    }

    /// Bind reviewed result-use obligations to one exact call shape for any
    /// language adapter. The caller supplies the activation row selected by
    /// that adapter; this method verifies that the row is one of this shard's
    /// actual matching evidence and that the analyzer-minted call shape agrees
    /// with the authored summary. Dispatch-arm agreement remains a consumer
    /// operation over these bindings, so the same proof can serve Java later
    /// without changing the existing Java adapter today.
    pub fn bind_reviewed_result_use_obligations(
        &self,
        target: ReviewedObligationTarget<'_>,
    ) -> Result<ReviewedObligationBinding, ReviewedObligationBindFailure> {
        if self.record.result_use_obligations.is_empty() {
            return Err(ReviewedObligationBindFailure::NoObligation);
        }
        if !target
            .target
            .language()
            .accepts_semantic_pack_language(&self.shard.manifest.language)
        {
            return Err(ReviewedObligationBindFailure::LanguageMismatch);
        }
        if self
            .shard
            .matching_evidence
            .binary_search(target.evidence)
            .is_err()
        {
            return Err(ReviewedObligationBindFailure::EvidenceUnselected);
        }
        if let ReviewedObligationBasis::BuiltinReceiverAssumption(assumption) = target.basis
            && (target.target.language().semantic_pack_label() != assumption.language()
                || !target.target.has_receiver()
                || target.target.owner_fqn() != assumption.receiver())
        {
            return Err(ReviewedObligationBindFailure::BasisMismatch);
        }
        if matches!(
            target.basis,
            ReviewedObligationBasis::PythonStandardLibraryFunction
        ) && (target.target.language().semantic_pack_label() != "python"
            || !target.target.has_resolver_owned_call_shape()
            || target.target.has_receiver()
            || target.evidence.language != "python"
            || target.evidence.ecosystem != "python"
            || target
                .evidence
                .toolchain
                .as_ref()
                .map(|toolchain| toolchain.name.as_str())
                != Some("cpython"))
        {
            return Err(ReviewedObligationBindFailure::BasisMismatch);
        }
        if matches!(target.basis, ReviewedObligationBasis::ExactLiteralReceiver)
            && (target.target.language() != LanguageDialect::Standard(Language::JavaScript)
                || !target.target.has_receiver()
                || target.target.owner_fqn() != "String")
        {
            return Err(ReviewedObligationBindFailure::BasisMismatch);
        }
        if self.bind_unmaterialized_call_shape(target.target).is_none() {
            return Err(ReviewedObligationBindFailure::CallShapeMismatch);
        }
        Ok(ReviewedObligationBinding {
            record: Arc::clone(&self.record),
            basis: target.basis,
            ordinary_heap_unchanged: self.record.ordinary_heap_unchanged,
            covers_overrides: self.record.covers_overrides,
        })
    }

    /// Bind reviewed result-use obligations to an artifact-backed external
    /// declaration. The declaration locator is resolver-owned evidence, so it
    /// supplies the path and member shape that an unmaterialized target cannot
    /// carry. Callers still select the exact generated external artifact
    /// before invoking this method.
    pub fn bind_reviewed_result_use_obligations_for_declaration(
        &self,
        target: ProcedureSummaryDeclarationKey<'_>,
        evidence: &SemanticModelActivationEvidence,
        basis: ReviewedObligationBasis,
    ) -> Result<ReviewedObligationBinding, ReviewedObligationBindFailure> {
        if self.record.result_use_obligations.is_empty() {
            return Err(ReviewedObligationBindFailure::NoObligation);
        }
        let Some(language) = LanguageDialect::from_config_label(target.language) else {
            return Err(ReviewedObligationBindFailure::LanguageMismatch);
        };
        if !language.accepts_semantic_pack_language(&self.shard.manifest.language) {
            return Err(ReviewedObligationBindFailure::LanguageMismatch);
        }
        if self
            .shard
            .matching_evidence
            .binary_search(evidence)
            .is_err()
        {
            return Err(ReviewedObligationBindFailure::EvidenceUnselected);
        }
        let record_target = &self.record.target;
        if record_target.path != target.path
            || record_target.has_receiver != target.has_receiver
            || record_target.parameter_count != target.parameter_count
            || authored_procedure_target_identity(&record_target.path, &record_target.symbol)
                .is_none_or(|(_, member)| member != target.member)
        {
            return Err(ReviewedObligationBindFailure::CallShapeMismatch);
        }
        Ok(ReviewedObligationBinding {
            record: Arc::clone(&self.record),
            basis,
            ordinary_heap_unchanged: self.record.ordinary_heap_unchanged,
            covers_overrides: self.record.covers_overrides,
        })
    }

    /// Outcome-sensitive predicate effects this reviewed summary attributes to
    /// its boolean normal results.
    pub fn conditional_result_refinements(&self) -> &[CompiledConditionalResultRefinement] {
        &self.record.conditional_result_refinements
    }

    /// Outcome-sensitive one-step indirect writes attributed to this
    /// procedure's normal return.
    pub fn conditional_indirect_writes(&self) -> &[CompiledConditionalIndirectWrite] {
        &self.record.conditional_indirect_writes
    }

    /// Predicates this reviewed summary establishes for actual arguments on
    /// the call's normal continuation.
    pub fn normal_return_refinements(&self) -> &[CompiledNormalReturnRefinement] {
        &self.record.normal_return_refinements
    }

    /// Reviewed class assertions this summary establishes for actual
    /// arguments on the call's normal continuation.
    pub fn normal_return_type_refinements(&self) -> &[CompiledNormalReturnTypeRefinement] {
        &self.record.normal_return_type_refinements
    }

    /// Reviewed identity claims for a class decorator or decorator factory.
    /// Omission means that the activated summary makes no such claim.
    pub fn class_decorator_identity(&self) -> Option<&CompiledClassDecoratorIdentity> {
        self.record.class_decorator_identity.as_ref()
    }

    /// Whether the activated pack declares the named effect for this procedure.
    pub fn declares_effect(&self, id: &str) -> bool {
        self.record
            .declared_effects
            .iter()
            .any(|effect| effect.id == id)
    }

    /// Project the same activation provenance declaration rows expose for this
    /// exact summary record. Consumers that trust `covers_overrides` must keep
    /// the authored record and active pack identity beside that decision.
    pub fn provenance(
        &self,
        active: &ResolvedActiveSemanticModels,
    ) -> crate::analyzer::semantic_model::SemanticModelProvenance {
        let mut provenance = crate::analyzer::store::model_provenance::activated_record_provenance(
            active,
            &self.shard,
            &self.record.id,
        );
        provenance.completeness = match self.record.completeness {
            crate::analyzer::semantic_model::Completeness::Partial => {
                crate::analyzer::semantic_model::SemanticModelCompleteness::Partial
            }
            crate::analyzer::semantic_model::Completeness::Complete => {
                crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
            }
        };
        provenance
    }
}

use crate::analyzer::semantic::ids::{
    DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticArtifactKey,
    SemanticLanguage, SemanticRole,
};
use crate::analyzer::semantic::ir::SemanticCallArgument;
use crate::analyzer::semantic_model::SemanticModelActivationEvidence;
use brokk_bifrost_semantic::analyzer::semantic::oracle::dispatch::*;

/// A target carrier for one reviewed result-use binding.
///
/// `evidence` is the exact activation row selected for the summary shard. It
/// is carried separately from the unmaterialized call target because Python's
/// builtin assumption is type-flow evidence rather than resolver-owned
/// installed-artifact evidence. The same carrier supports a future adapter
/// that selects a JVM, npm, or another language-specific artifact.
#[derive(Debug, Clone, Copy)]
pub struct ReviewedObligationTarget<'a> {
    pub target: &'a UnmaterializedExternalTarget,
    pub evidence: &'a SemanticModelActivationEvidence,
    pub basis: ReviewedObligationBasis,
}

impl<'a> ReviewedObligationTarget<'a> {
    pub const fn new(
        target: &'a UnmaterializedExternalTarget,
        evidence: &'a SemanticModelActivationEvidence,
        basis: ReviewedObligationBasis,
    ) -> Self {
        Self {
            target,
            evidence,
            basis,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelActivationExplanation {
    pub manifest_digest: String,
    pub pack_id: Option<String>,
    pub shard_id: String,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub status: SemanticModelActivationStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelActivationReport {
    pub explanations: Vec<SemanticModelActivationExplanation>,
    pub suppressed_explanations: usize,
    pub catalog_candidates: usize,
    pub loaded_shards: usize,
    pub loaded_records: usize,
    /// Individually identified declaration gaps carried by active packs.
    #[serde(default)]
    pub extraction_gaps: usize,
    /// Declarations a loaded shard publishes that the pinned activation
    /// coordinates prove absent, so the matcher never indexed them (#1899).
    #[serde(default)]
    pub guard_excluded_records: usize,
    pub index_entries: usize,
    pub working_bytes: u64,
    pub retained_bytes: u64,
    pub phase_measurements: SemanticModelActivationPhaseMeasurements,
    /// Runtime-only rejection measurements; never written to the catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_budget_exceeded: Option<SemanticModelOverlayBudgetExceeded>,
}

/// A database-local key is meaningful only together with its publishing database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogShardRowIdentity {
    pub shard_key: i64,
    pub database: CatalogShardDatabase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogShardDatabase {
    Durable,
    Session,
}

#[derive(Debug, Clone)]
pub struct ActiveSemanticModelShardMetadata {
    /// The pack was selected without exact toolchain evidence.
    pub approximate: bool,
    /// Shared with the catalog's decoded-manifest memo and with every other
    /// shard of the same pack (#3101).
    pub manifest: Arc<CompiledPackManifest>,
    pub descriptor: crate::analyzer::semantic_model::CompiledShardDescriptor,
    pub selectors: Vec<crate::analyzer::semantic_model::ActivationSelector>,
    /// Present on catalog activations; standalone decoded test fixtures have no SQL reader.
    pub row_store: Option<CatalogShardRowIdentity>,
    /// Decoded shards keep their exact presence bit and debug-check it against
    /// catalog_semantic_payload_families. Row-backed shards read that family
    /// row: child rows cannot distinguish absent and present-empty payloads.
    pub has_callable_values: bool,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub matched_evidence: SemanticModelActivationEvidence,
    /// Every evidence row that satisfies a highest-rank selector. The legacy
    /// representative above remains the ordinary matcher input; an exact
    /// call-artifact proof must select its own row from this complete set.
    pub matching_evidence: Vec<SemanticModelActivationEvidence>,
    pub evidence_rank: EvidenceRank,
    pub source_rank: u8,
}

#[derive(Debug)]
pub struct ActiveSemanticModelShard {
    pub metadata: Arc<ActiveSemanticModelShardMetadata>,
    pub decoded: Option<CompiledShard>,
}

/// Metadata projection never requires a decoded payload.
impl std::ops::Deref for ActiveSemanticModelShard {
    type Target = ActiveSemanticModelShardMetadata;

    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

impl ActiveSemanticModelShard {
    /// Payload readers must make their dependency on decoded data explicit.
    pub fn decoded(&self) -> &CompiledShard {
        self.decoded
            .as_ref()
            .expect("semantic-model shard payload is decoded")
    }

    /// A positive declaration does not assert that its source enumerates the
    /// owner's complete member family. Behavior payloads have no TypeFact and
    /// cannot enter this declaration inventory.
    pub fn admits_jvm_owner_declaration(&self, owner: &TypeFact) -> bool {
        owner.guard.is_none()
            && super::resolution_operation::nominal_rules::nominal_package_rules_for_storage(
                &self.manifest.language,
            )
            .is_some()
    }

    pub fn independently_enumerates_jvm_owner(&self, owner: &TypeFact) -> bool {
        owner.guard.is_none()
            && (matches!(
                self.source_kind,
                CatalogPackSourceKind::Generated | CatalogPackSourceKind::WorkspaceProduced
            ) || (self.source_kind == CatalogPackSourceKind::Installed
                && matches!(
                    owner.locator,
                    crate::analyzer::semantic_model::Locator::Artifact { .. }
                        | crate::analyzer::semantic_model::Locator::Source { .. }
                )))
    }

    /// Whether the evidence this shard activated against proves the guarded
    /// record absent.
    ///
    /// This is the only place a declaration leaves an activated pack. An
    /// unguarded record, and a guard whose constraints the pinned coordinates
    /// satisfy or say nothing about, both stay active (#1899).
    pub fn guard_excludes(&self, guard: Option<&DeclarationGuard>) -> bool {
        guard.is_some_and(|guard| {
            guard.excludes(
                self.matched_evidence
                    .toolchain
                    .as_ref()
                    .and_then(|toolchain| toolchain.version.as_ref()),
                self.matched_evidence.target.as_deref(),
            )
        })
    }
}

#[derive(Debug)]
pub struct ResolvedActiveSemanticModels {
    pub active_model_set_hash: String,
    #[doc(hidden)]
    pub source_reader: Option<CatalogRuntimeSourceReader>,
    pub shards: Vec<Arc<ActiveSemanticModelShard>>,
    pub indexes: MatcherIndexes,
    pub extraction_gaps: Vec<Arc<ActivePackExtractionGap>>,
    pub extraction_gaps_by_declaration: HashMap<String, Vec<usize>>,
    pub report: SemanticModelActivationReport,
}

impl ResolvedActiveSemanticModels {
    /// Every defining provider in this activation, including metadata-only shards.
    pub fn model_provider_selection(
        &self,
    ) -> crate::analyzer::semantic_model::overlay::ModelProviderSelection {
        use crate::analyzer::semantic_model::overlay::{ModelProvider, ModelProviderSelection};
        ModelProviderSelection::new(self.shards.iter().map(|shard| ModelProvider {
            pack_id: shard.manifest.pack_id.clone(),
            pack_version: shard.manifest.version.clone(),
            pack_digest: shard.manifest.semantic_sha256.clone(),
        }))
    }

    /// Fixed SQL handles belonging to this activation publication. Source rows
    /// are read on demand and remain owned by one query.
    #[doc(hidden)]
    pub fn source_reader(&self) -> Option<&CatalogRuntimeSourceReader> {
        self.source_reader.as_ref()
    }

    pub fn active_model_set_hash(&self) -> &str {
        &self.active_model_set_hash
    }

    pub fn shards(&self) -> Vec<Arc<ActiveSemanticModelShard>> {
        self.shards.clone()
    }

    /// Project candidate names for result-contract source binding, in shard
    /// and payload order. Callers deduplicate the projected inventory.
    pub fn result_contract_name_inventory(
        &self,
    ) -> impl Iterator<Item = (String, String, bool, CallableArity)> + '_ {
        self.shards.iter().flat_map(|shard| {
            let rows = (shard.decoded.is_none()
                && shard.descriptor.payload_kind
                    == crate::analyzer::semantic_model::PayloadKind::ProcedureSummaries)
                .then(|| {
                    self.shard_summary_targets(
                        shard,
                        "SUMMARY_CONTRACT_TARGETS_BY_SHARD",
                        statements::SUMMARY_CONTRACT_TARGETS_BY_SHARD,
                    )
                    .into_iter()
                    .filter_map(|record| {
                        let (_, member) =
                            authored_procedure_target_identity(&record.1.path, &record.1.symbol)?;
                        Some((
                            shard.manifest.language.clone(),
                            member.to_owned(),
                            record.1.has_receiver,
                            record.1.callable_arity(),
                        ))
                    })
                    .collect()
                });
            query_or_posting(
                rows,
                shard
                    .decoded
                    .as_ref()
                    .and_then(|decoded| decoded.payload().procedure_summaries())
                    .into_iter()
                    .flatten()
                    .filter_map(|summary| {
                        if summary.result_contracts.is_empty() {
                            return None;
                        }
                        let (_, member) = authored_procedure_target_identity(
                            &summary.target.path,
                            &summary.target.symbol,
                        )?;
                        Some((
                            shard.manifest.language.clone(),
                            member.to_owned(),
                            summary.target.has_receiver,
                            summary.target.callable_arity(),
                        ))
                    }),
            )
        })
    }

    /// Stream the authored-target census one summary-bearing shard at a time,
    /// in activation and canonical payload order. Present-empty summary payloads
    /// still invoke the visitor; absent payloads do not.
    pub fn visit_procedure_summary_targets(
        &self,
        mut visit: impl FnMut(&str, &str, &mut dyn Iterator<Item = (&str, &CompiledProcedureTarget)>),
    ) {
        for shard in &self.shards {
            if let Some(decoded) = &shard.decoded {
                if let Some(summaries) = decoded.payload().procedure_summaries() {
                    let mut targets = summaries
                        .iter()
                        .map(|summary| (summary.id.as_str(), &summary.target));
                    visit(
                        &shard.manifest.content_sha256,
                        &shard.manifest.language,
                        &mut targets,
                    );
                }
            } else if shard.descriptor.payload_kind
                == crate::analyzer::semantic_model::PayloadKind::ProcedureSummaries
            {
                let records = self.shard_summary_targets(
                    shard,
                    "SUMMARY_TARGETS_BY_SHARD",
                    statements::SUMMARY_TARGETS_BY_SHARD,
                );
                let mut targets = records.iter().map(|record| (record.0.as_str(), &record.1));
                visit(
                    &shard.manifest.content_sha256,
                    &shard.manifest.language,
                    &mut targets,
                );
            }
        }
    }

    /// Close selected root IDs over same-shard dependencies in canonical payload order.
    /// Missing IDs stay absent for the consumers' existing diagnostics. M2c's row
    /// reader answers this query with shard-local ID lookups.
    pub fn procedure_summary_family<'a>(
        &self,
        shard: &ActiveSemanticModelShard,
        roots: impl IntoIterator<Item = &'a str>,
    ) -> Arc<[Arc<CompiledProcedureSummary>]> {
        if shard.decoded.is_none() {
            let selected = self
                .shards
                .iter()
                .find(|s| std::ptr::eq(s.as_ref(), shard))
                .expect("summary shard belongs to this active set");
            let roots = roots.into_iter().collect::<Vec<_>>();
            return crate::analyzer::store::model_catalog::semantic_catalog_question(
                "SUMMARY_BY_ID",
                (&shard.row_store, &roots),
                self.source_reader
                    .as_ref()
                    .expect("row-backed set has its reader")
                    .procedure_summary_family(selected, roots.iter().copied()),
            );
        }
        let payload = shard
            .decoded()
            .payload()
            .procedure_summaries()
            .expect("a selected procedure-summary shard has a summary payload");
        let by_id = payload
            .iter()
            .map(|summary| (summary.id.as_str(), summary))
            .collect::<HashMap<_, _>>();
        let mut pending = roots
            .into_iter()
            .filter_map(|id| by_id.get(id).map(|summary| summary.id.as_str()))
            .collect::<Vec<_>>();
        let mut visited = HashSet::default();
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let Some(summary) = by_id.get(id) else {
                continue;
            };
            for effect in &summary.effects {
                match effect {
                    crate::analyzer::semantic_model::CompiledSummaryEffect::Call {
                        callee, ..
                    } => pending.push(callee),
                    crate::analyzer::semantic_model::CompiledSummaryEffect::AmbiguousCall {
                        candidates,
                        ..
                    } => pending.extend(candidates.iter().map(String::as_str)),
                    _ => {}
                }
            }
        }
        payload
            .iter()
            .filter(|summary| visited.contains(summary.id.as_str()))
            .cloned()
            .collect()
    }

    /// Preserve the consumers' legacy whole-shard summary ordering without
    /// retaining that whole payload in an owned summary family.
    #[doc(hidden)]
    pub fn procedure_summary_shard_order(&self, selected: &ActiveSemanticModelShard) -> usize {
        if self.has_row_backed_shards() {
            let selected = self
                .shards
                .iter()
                .find(|s| std::ptr::eq(s.as_ref(), selected))
                .expect("summary shard belongs to this active set");
            return crate::analyzer::store::model_catalog::semantic_catalog_question(
                "SUMMARY_SHARD_FIRST/SUMMARY_SHARD_SEQUENCE",
                selected.row_store,
                self.source_reader
                    .as_ref()
                    .expect("row-backed set has its reader")
                    .procedure_summary_shard_order(selected, &self.shards),
            );
        }
        let selected_payload = selected
            .decoded()
            .payload()
            .procedure_summaries()
            .expect("a selected procedure-summary shard has a summary payload");
        self.shards
            .iter()
            .filter_map(|shard| {
                shard
                    .decoded()
                    .payload()
                    .procedure_summaries()
                    .map(|payload| (shard, payload))
            })
            .filter(|(shard, payload)| {
                shard
                    .manifest
                    .language
                    .cmp(&selected.manifest.language)
                    .then_with(|| {
                        payload
                            .iter()
                            .map(|summary| (&summary.model_id, &summary.id))
                            .cmp(
                                selected_payload
                                    .iter()
                                    .map(|summary| (&summary.model_id, &summary.id)),
                            )
                    })
                    .is_lt()
            })
            .count()
    }

    /// Runtime-value contracts are carried by the same activated shard as
    /// their selectors and declaration facts.  Keep the shard alongside the
    /// payload so callers retain activation and provenance evidence.
    pub fn runtime_values(
        &self,
    ) -> impl Iterator<Item = (Arc<RuntimeValuesPayload>, Arc<ActiveSemanticModelShard>)> {
        self.shards.iter().filter_map(|shard| {
            let payload = match &shard.decoded {
                Some(decoded) => decoded.runtime_values().cloned(),
                None => self.shard_payload::<RuntimeValuesPayload>(
                    shard,
                    "RUNTIME_VALUES",
                    statements::RUNTIME_VALUES,
                ),
            };
            payload.map(|payload| (payload, Arc::clone(shard)))
        })
    }

    /// Portable records retain their catalog shard and provenance. Catalog
    /// activation alone does not authorize their target-scoped runtime claims;
    /// consumers must also evaluate the portable activation and producer evidence.
    pub fn runtime_contracts(
        &self,
    ) -> impl Iterator<
        Item = (
            Arc<crate::analyzer::semantic_model::RuntimeContractsPayload>,
            Arc<ActiveSemanticModelShard>,
        ),
    > {
        self.shards.iter().filter_map(|shard| {
            let payload = match &shard.decoded {
                Some(decoded) => decoded.runtime_contracts().cloned(),
                None => self
                    .shard_payload::<crate::analyzer::semantic_model::RuntimeContractsPayload>(
                        shard,
                        "RUNTIME_CONTRACTS",
                        statements::RUNTIME_CONTRACTS,
                    ),
            };
            payload.map(|payload| (payload, Arc::clone(shard)))
        })
    }

    /// Collection-flow contracts are carried by the same activated shard as
    /// their selectors and declaration facts. Keeping the shard alongside the
    /// typed payload preserves activation and provenance evidence for exact
    /// callable lookup.
    pub fn collection_flows(
        &self,
    ) -> impl Iterator<Item = (Arc<CollectionFlowsPayload>, Arc<ActiveSemanticModelShard>)> {
        self.shards.iter().filter_map(|shard| {
            let payload = match &shard.decoded {
                Some(decoded) => decoded.collection_flows().cloned(),
                None => self
                    .has_family(shard, SemanticPayloadFamily::CollectionFlows)
                    .then(|| {
                        Arc::new(CollectionFlowsPayload {
                            flows: self
                                .shard_records(
                                    shard,
                                    "COLLECTION_FLOWS_BY_SHARD",
                                    statements::COLLECTION_FLOWS_BY_SHARD,
                                )
                                .into_iter()
                                .map(Arc::unwrap_or_clone)
                                .collect(),
                        })
                    }),
            };
            payload.map(|payload| (payload, Arc::clone(shard)))
        })
    }

    /// Deferred-yield contracts retain their activation shard so consumers can
    /// pair exact endpoint identities with the evidence that activated them.
    pub fn deferred_yields(
        &self,
    ) -> impl Iterator<Item = (Arc<DeferredYieldsPayload>, Arc<ActiveSemanticModelShard>)> {
        self.shards.iter().filter_map(|shard| {
            let payload = match &shard.decoded {
                Some(decoded) => decoded.deferred_yields().cloned(),
                None => self
                    .has_family(shard, SemanticPayloadFamily::DeferredYields)
                    .then(|| {
                        Arc::new(DeferredYieldsPayload {
                            yields: self
                                .shard_records(
                                    shard,
                                    "DEFERRED_YIELDS_BY_SHARD",
                                    statements::DEFERRED_YIELDS_BY_SHARD,
                                )
                                .into_iter()
                                .map(Arc::unwrap_or_clone)
                                .collect(),
                        })
                    }),
            };
            payload.map(|payload| (payload, Arc::clone(shard)))
        })
    }

    /// Rule enumeration is bounded by the active generator rules, not declarations.
    pub fn generator_rules(
        &self,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<GeneratorRule>> + '_ {
        self.shards.iter().flat_map(|shard| {
            let records = match &shard.decoded {
                Some(decoded) => decoded
                    .payload()
                    .generator_rules()
                    .into_iter()
                    .flatten()
                    .cloned()
                    .collect::<Vec<_>>(),
                None if shard.descriptor.payload_kind
                    == crate::analyzer::semantic_model::PayloadKind::GeneratorRules =>
                {
                    self.shard_records(shard, "RULES_BY_SHARD", statements::RULES_BY_SHARD)
                }
                None => Vec::new(),
            };
            records
                .into_iter()
                .map(|record| ActivatedSemanticModelRecord {
                    record,
                    shard: Arc::clone(shard),
                })
        })
    }

    pub fn activation_report(&self) -> &SemanticModelActivationReport {
        &self.report
    }

    pub fn extraction_gaps(&self) -> Vec<Arc<ActivePackExtractionGap>> {
        self.extraction_gaps.clone()
    }

    pub fn gapped(&self, declaration: &str) -> Option<Arc<ActivePackExtractionGap>> {
        self.extraction_gaps_by_declaration
            .get(declaration)
            .and_then(|indexes| indexes.first())
            .map(|index| Arc::clone(&self.extraction_gaps[*index]))
    }

    pub fn gapped_member_surface(
        &self,
        owner: &str,
        member: &str,
    ) -> Option<Arc<ActivePackExtractionGap>> {
        let member_declaration = format!("{owner}.{member}");
        self.gapped(&member_declaration)
            .or_else(|| self.gapped(owner))
    }

    pub fn retained_bytes(&self) -> u64 {
        self.report.retained_bytes
    }

    pub fn types_with_id(&self, id: &str) -> SemanticModelMatch<TypeFact> {
        let posting = self.indexes.types_by_id.get(id);
        if self.has_row_backed_shards() {
            return resolve_records(self.type_question(
                "TYPES_BY_ID",
                statements::TYPES_BY_ID,
                id,
                named_params! { ":id": id },
                posting,
            ));
        }
        self.type_match(posting)
    }

    pub fn types_named(&self, name: &str) -> SemanticModelMatch<TypeFact> {
        let posting = self.indexes.types_by_name.get(name);
        if self.has_row_backed_shards() {
            let records = self.type_question(
                "TYPES_BY_NAME",
                statements::TYPES_BY_NAME,
                name,
                named_params! { ":name": name },
                posting,
            );
            // Catalog names also contain terminal spellings. This raw matcher
            // indexes only the canonical name and explicit aliases, including
            // repeated postings when an alias repeats the canonical name.
            return resolve_records(
                records
                    .into_iter()
                    .flat_map(|r| {
                        let count = if r.shard.decoded.is_none() {
                            usize::from(r.record.name == name)
                                + r.record
                                    .aliases
                                    .iter()
                                    .filter(|alias| alias.as_str() == name)
                                    .count()
                        } else {
                            1
                        };
                        std::iter::repeat_n(r, count)
                    })
                    .collect(),
            );
        }
        self.type_match(posting)
    }

    /// All active postings, without rank selection or value deduplication.
    /// Exhaustive runtime claims must retain each contributor's provenance.
    /// The caller charges its query budget before retaining each record.
    #[doc(hidden)]
    pub fn all_type_records_named<'a>(
        &'a self,
        name: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<TypeFact>> + 'a {
        let posting = self.indexes.types_by_name.get(name);
        let rows = self.has_row_backed_shards().then(|| {
            rows::distinct_addresses(
                self.type_question(
                    "TYPES_BY_NAME",
                    statements::TYPES_BY_NAME,
                    name,
                    named_params! { ":name": name },
                    posting,
                )
                .into_iter()
                .filter(|r| {
                    r.record.name == name || r.record.aliases.iter().any(|alias| alias == name)
                })
                .collect(),
            )
        });
        query_or_posting(rows, self.all_type_records(posting))
    }

    #[doc(hidden)]
    pub fn all_type_records_with_id<'a>(
        &'a self,
        id: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<TypeFact>> + 'a {
        let posting = self.indexes.types_by_id.get(id);
        let rows = self.has_row_backed_shards().then(|| {
            rows::distinct_addresses(self.type_question(
                "TYPES_BY_ID",
                statements::TYPES_BY_ID,
                id,
                named_params! { ":id": id },
                posting,
            ))
        });
        query_or_posting(rows, self.all_type_records(posting))
    }

    /// Unranked decoded postings for selected composition, including mixed
    /// active sets whose other languages use catalog rows.
    #[doc(hidden)]
    pub fn decoded_type_records_with_id<'a>(
        &'a self,
        id: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<TypeFact>> + 'a {
        self.all_type_records(self.indexes.types_by_id.get(id))
    }

    #[doc(hidden)]
    pub fn decoded_type_records_named<'a>(
        &'a self,
        name: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<TypeFact>> + 'a {
        self.all_type_records(self.indexes.types_by_name.get(name))
    }

    #[doc(hidden)]
    pub fn decoded_member_records_with_id<'a>(
        &'a self,
        id: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<MemberFact>> + 'a {
        self.all_records(self.indexes.members_by_id.get(id), |shard, index| {
            &shard
                .decoded()
                .payload()
                .declaration_facts()
                .expect("member posting")
                .1[index]
        })
    }

    #[doc(hidden)]
    pub fn decoded_member_ids_by_owner(&self, owner: &str) -> Vec<String> {
        let mut addresses = self
            .indexes
            .members_by_owner_name
            .get(owner)
            .into_iter()
            .flat_map(|names| names.values())
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        addresses.sort_unstable_by_key(|address| (address.shard, address.record));
        addresses.dedup();
        self.all_records(Some(&addresses), |shard, index| {
            &shard
                .decoded()
                .payload()
                .declaration_facts()
                .expect("member posting")
                .1[index]
        })
        .map(|record| record.record.id.clone())
        .collect()
    }

    #[doc(hidden)]
    pub fn decoded_relation_records_with_id<'a>(
        &'a self,
        id: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<RelationFact>> + 'a {
        self.all_records(self.indexes.relations_by_id.get(id), |shard, index| {
            &shard
                .decoded()
                .payload()
                .declaration_facts()
                .expect("relation posting")
                .2[index]
        })
    }

    #[doc(hidden)]
    pub fn decoded_relation_records_from<'a>(
        &'a self,
        owner: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<RelationFact>> + 'a {
        self.all_records(self.indexes.relations_by_from.get(owner), |shard, index| {
            &shard
                .decoded()
                .payload()
                .declaration_facts()
                .expect("relation posting")
                .2[index]
        })
    }

    fn all_type_records<'a>(
        &'a self,
        posting: Option<&'a Vec<RecordAddress>>,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<TypeFact>> + 'a {
        self.all_records(posting, |shard, index| {
            &shard
                .decoded()
                .payload()
                .declaration_facts()
                .expect("type posting addresses declarations")
                .0[index]
        })
    }

    /// #6542: extraction authority is independent of delivery/evidence rank.
    #[doc(hidden)]
    pub fn all_member_records_with_id<'a>(
        &'a self,
        id: &str,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<MemberFact>> + 'a {
        let posting = self.indexes.members_by_id.get(id);
        let rows = self.has_row_backed_shards().then(|| {
            rows::distinct_addresses(self.member_question(
                "MEMBERS_BY_ID",
                statements::MEMBERS_BY_ID,
                id,
                named_params! { ":id": id },
                posting,
            ))
        });
        query_or_posting(
            rows,
            self.all_records(posting, |shard, index| {
                &shard
                    .decoded()
                    .payload()
                    .declaration_facts()
                    .expect("member posting addresses declarations")
                    .1[index]
            }),
        )
    }

    fn all_records<'a, T: 'a>(
        &'a self,
        posting: Option<&'a Vec<RecordAddress>>,
        record: impl Fn(&'a ActiveSemanticModelShard, usize) -> &'a Arc<T> + 'a,
    ) -> impl Iterator<Item = ActivatedSemanticModelRecord<T>> + 'a {
        // Aliases index adjacent copies of one address. Distinct contributors
        // remain distinct even when their values happen to agree.
        posting
            .into_iter()
            .flat_map(|posting| {
                posting
                    .iter()
                    .enumerate()
                    .filter(move |(index, address)| *index == 0 || **address != posting[*index - 1])
                    .map(|(_, address)| address)
            })
            .map(move |address| {
                let shard = &self.shards[address.shard as usize];
                ActivatedSemanticModelRecord {
                    record: Arc::clone(record(shard, address.record as usize)),
                    shard: Arc::clone(shard),
                }
            })
    }

    /// Whether this raw contributor agrees with the normally selected type
    /// declaration. Lower-ranked runtime claims are not silently discarded;
    /// their owner must still bind to an admitted declaration.
    #[doc(hidden)]
    pub fn type_declaration_admitted<E>(
        &self,
        record: &TypeFact,
        visit: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<bool, E> {
        let mut selected = None;
        for candidate in self.all_type_records_with_id(&record.id) {
            visit()?;
            let rank = (candidate.shard.evidence_rank, candidate.shard.source_rank);
            if selected.as_ref().is_none_or(|(best, _)| rank > *best) {
                selected = Some((rank, candidate.record));
            }
        }
        Ok(selected.is_some_and(|(_, selected)| {
            crate::analyzer::semantic_model::type_declarations_equivalent(record, &selected)
        }))
    }

    pub fn members_with_id(&self, id: &str) -> SemanticModelMatch<MemberFact> {
        let posting = self.indexes.members_by_id.get(id);
        if self.has_row_backed_shards() {
            return resolve_records(self.member_question(
                "MEMBERS_BY_ID",
                statements::MEMBERS_BY_ID,
                id,
                named_params! { ":id": id },
                posting,
            ));
        }
        self.member_match(posting)
    }

    pub fn members_named(&self, owner: &str, name: &str) -> SemanticModelMatch<MemberFact> {
        let posting = self
            .indexes
            .members_by_owner_name
            .get(owner)
            .and_then(|names| names.get(name));
        if self.has_row_backed_shards() {
            let records = self.member_question(
                "MEMBERS_BY_OWNER_NAME",
                statements::MEMBERS_BY_OWNER_NAME,
                (owner, name),
                named_params! { ":owner": owner, ":name": name },
                posting,
            );
            return resolve_records(
                records
                    .into_iter()
                    .flat_map(|r| {
                        let count = if r.shard.decoded.is_none() {
                            usize::from(r.record.name == name)
                                + r.record
                                    .aliases
                                    .iter()
                                    .filter(|alias| alias.as_str() == name)
                                    .count()
                        } else {
                            1
                        };
                        std::iter::repeat_n(r, count)
                    })
                    .collect(),
            );
        }
        self.member_match(posting)
    }

    pub fn relations_with_id(&self, id: &str) -> SemanticModelMatch<RelationFact> {
        let posting = self.indexes.relations_by_id.get(id);
        if self.has_row_backed_shards() {
            return self.relation_question(
                "RELATIONS_BY_ID",
                statements::RELATIONS_BY_ID,
                id,
                posting,
            );
        }
        self.relation_match(posting)
    }

    pub fn relations_from(&self, from: &str) -> SemanticModelMatch<RelationFact> {
        let posting = self.indexes.relations_by_from.get(from);
        if self.has_row_backed_shards() {
            return self.relation_question(
                "RELATIONS_FROM",
                statements::RELATIONS_FROM,
                from,
                posting,
            );
        }
        self.relation_match(posting)
    }

    pub fn relations_to(&self, to: &str) -> SemanticModelMatch<RelationFact> {
        let posting = self.indexes.relations_by_to.get(to);
        if self.has_row_backed_shards() {
            return self.relation_question("RELATIONS_TO", statements::RELATIONS_TO, to, posting);
        }
        self.relation_match(posting)
    }

    pub fn rules_for(&self, trigger: RuleTriggerKey<'_>) -> SemanticModelMatch<GeneratorRule> {
        let posting = match trigger {
            RuleTriggerKey::LanguageConstruct(value) => {
                self.indexes.rules_by_language_construct.get(value)
            }
            RuleTriggerKey::Annotation(value) => self.indexes.rules_by_annotation.get(value),
            RuleTriggerKey::MacroInvocation(value) => self.indexes.rules_by_macro.get(value),
            RuleTriggerKey::GeneratorInvocation(value) => {
                self.indexes.rules_by_generator.get(value)
            }
            RuleTriggerKey::ResolvedOwner(value) => self.indexes.rules_by_owner.get(value),
            RuleTriggerKey::ResolvedCall { owner, name } => self
                .indexes
                .rules_by_call
                .get(owner)
                .and_then(|names| names.get(name)),
        };
        if self.has_row_backed_shards() {
            let (family, key) = match trigger {
                RuleTriggerKey::LanguageConstruct(value) => ("language-construct", value),
                RuleTriggerKey::Annotation(value) => ("annotation", value),
                RuleTriggerKey::MacroInvocation(value) => ("macro", value),
                RuleTriggerKey::GeneratorInvocation(value) => ("generator", value),
                RuleTriggerKey::ResolvedOwner(value) => ("owner", value),
                RuleTriggerKey::ResolvedCall { owner, name } => {
                    return self.rule_question(
                        "RULES_BY_CALL",
                        statements::RULES_BY_CALL,
                        (owner, name),
                        named_params! { ":owner": owner, ":member": name },
                        posting,
                    );
                }
            };
            return self.rule_question(
                "RULES_BY_TRIGGER",
                statements::RULES_BY_TRIGGER,
                (family, key),
                named_params! { ":family": family, ":key": key },
                posting,
            );
        }
        self.rule_match(posting)
    }

    pub fn rules_with_id(&self, id: &str) -> SemanticModelMatch<GeneratorRule> {
        let posting = self.indexes.rules_by_id.get(id);
        if self.has_row_backed_shards() {
            return self.rule_question(
                "RULES_BY_ID",
                statements::RULES_BY_ID,
                id,
                named_params! { ":id": id },
                posting,
            );
        }
        self.rule_match(posting)
    }

    pub fn procedure_summaries_for(
        &self,
        target: ProcedureSummaryTargetKey<'_>,
    ) -> ProcedureSummaryMatch {
        let shapes = self
            .indexes
            .procedure_summaries_by_target
            .get(semantic_pack_realm(target.language))
            .and_then(|paths| paths.get(target.path))
            .and_then(|symbols| symbols.get(target.symbol));
        if self.has_row_backed_shards() {
            return self.exact_summary_question(target, shapes);
        }
        resolve_exact_procedure_postings(
            &self.shards,
            shapes,
            target.has_receiver,
            target.parameter_count,
        )
    }

    /// Select an activated summary for an unmaterialized external callee by its
    /// canonical identity (#1978).
    /// #6542: summaries use authored owner spellings, whereas structural
    /// targets use artifact identities. Join those spellings per lookup, using
    /// only explicit extraction aliases. No composed facts or provenance are
    /// persisted, and the temporary postings die with this summary query.
    fn procedure_shapes_for_member(
        &self,
        language: &str,
        owner: &str,
        member: &str,
    ) -> Option<std::borrow::Cow<'_, ProcedureSummaryShapePostings>> {
        let realm = semantic_pack_realm(language);
        let owners = self.indexes.procedure_summaries_by_member.get(realm)?;
        let direct = owners.get(owner).and_then(|members| members.get(member));
        let mut names = std::collections::HashSet::new();
        for declaration in self.all_type_records_named(owner) {
            if declaration.shard.manifest.extraction.is_some()
                && semantic_pack_realm(&declaration.shard.manifest.language) == realm
            {
                names.insert(declaration.record.name.clone());
                names.extend(declaration.record.aliases.iter().cloned());
            }
        }
        names.remove(owner);
        let mut names = names.into_iter().collect::<Vec<_>>();
        names.sort_unstable();
        let mut additional = names
            .into_iter()
            .filter_map(|name| owners.get(&name).and_then(|members| members.get(member)))
            .collect::<Vec<_>>();
        if additional.is_empty() {
            return direct.map(std::borrow::Cow::Borrowed);
        }
        additional.extend(direct);
        let mut combined = ProcedureSummaryShapePostings::default();
        for shapes in additional {
            for (key, posting) in &shapes.fixed {
                combined.fixed.entry(*key).or_default().extend(posting);
            }
            for (key, posting) in &shapes.variadic {
                combined.variadic.entry(*key).or_default().extend(posting);
            }
            for (key, posting) in &shapes.variadic_by_minimum_arity {
                combined
                    .variadic_by_minimum_arity
                    .entry(*key)
                    .or_default()
                    .extend(posting);
            }
            for (key, posting) in &shapes.optional_fixed {
                combined
                    .optional_fixed
                    .entry(*key)
                    .or_default()
                    .extend(posting);
            }
            for (target, source) in combined
                .raw_normal_continuation_absence_claim
                .iter_mut()
                .zip(shapes.raw_normal_continuation_absence_claim)
            {
                *target |= source;
            }
        }
        Some(std::borrow::Cow::Owned(combined))
    }

    pub fn procedure_summaries_for_member(
        &self,
        target: ProcedureSummaryMemberKey<'_>,
    ) -> ProcedureSummaryMatch {
        self.applicable_member_summaries(target, &[target.parameter_count], |_, _| {
            ProcedureSummaryAcceptance::Accept(None)
        })
    }

    /// Restrict the shared language realm to the target's exact manifest
    /// language before evidence ranking and claim deduplication.
    pub fn procedure_summaries_for_member_in_language(
        &self,
        target: ProcedureSummaryMemberKey<'_>,
    ) -> ProcedureSummaryMatch {
        self.applicable_member_summaries(target, &[target.parameter_count], |shard, _| {
            if shard.manifest.language == target.language {
                ProcedureSummaryAcceptance::Accept(None)
            } else {
                ProcedureSummaryAcceptance::Reject
            }
        })
    }

    /// Select summaries for an exact unmaterialized external target, applying
    /// Python distribution artifact evidence before evidence ranking and claim
    /// deduplication. The member-only lookup remains available for callers
    /// that need shape-based model-presence discovery.
    pub fn procedure_summaries_for_external_target(
        &self,
        target: &UnmaterializedExternalTarget,
    ) -> ProcedureSummaryMatch {
        let key = ProcedureSummaryMemberKey::new(
            target.language().semantic_pack_label(),
            target.owner_fqn(),
            target.member(),
            target.has_receiver(),
            target.arity(),
        );
        let mut parameter_counts = vec![target.arity()];
        if let Some(formal_count) = target.python_formal_parameter_count() {
            parameter_counts.push(formal_count);
        }
        let incomplete = std::cell::Cell::new(false);
        let rejected_artifact = std::cell::Cell::new(false);
        let mut matched =
            self.applicable_member_summaries(key, &parameter_counts, |shard, summary| {
                let artifact_applies = python_artifact_applies_to_target(shard, target);
                let actual_to_formal = procedure_summary_actual_to_formal(shard, summary, target);
                if python_shard_requires_distribution_artifact(shard, target) && !artifact_applies {
                    rejected_artifact.set(true);
                }
                if artifact_applies
                    && actual_to_formal.is_none()
                    && (!summary.target.formals.is_empty()
                        || python_shard_requires_distribution_artifact(shard, target))
                {
                    incomplete.set(true);
                }
                if !artifact_applies {
                    ProcedureSummaryAcceptance::Reject
                } else if let Some(mapping) = actual_to_formal {
                    ProcedureSummaryAcceptance::Accept(mapping)
                } else {
                    ProcedureSummaryAcceptance::Reject
                }
            });
        for record in &mut matched.records {
            record.matched_owner_identity = Some(target.owner_fqn().to_owned());
            record.matched_target_locator = Some(target.locator().clone());
            record.matched_call_arguments = target
                .call_arguments()
                .map(|arguments| arguments.to_vec().into_boxed_slice());
        }
        if incomplete.get() || (matched.records.is_empty() && rejected_artifact.get()) {
            matched.applicability = ProcedureSummaryApplicability::Incomplete;
        }
        matched
    }

    /// Select reviewed-JDK candidates only after pinning the exact artifact
    /// that the Java resolver proved for this call. Filtering before rank and
    /// claim deduplication keeps equal summaries from two JDK installations
    /// from collapsing into the wrong artifact's representative.
    pub fn procedure_summaries_for_selected_jdk_artifact(
        &self,
        target: &UnmaterializedExternalTarget,
    ) -> ProcedureSummaryMatch {
        if !target.has_resolver_owned_call_shape()
            || target.language()
                != crate::analyzer::semantic::SemanticLanguage::Standard(
                    crate::analyzer::Language::Java,
                )
        {
            return empty_procedure_match();
        }
        let Some(selected) = target.selected_jdk_artifact() else {
            return empty_procedure_match();
        };
        let shapes = self
            .indexes
            .procedure_summaries_by_member
            .get(semantic_pack_realm("java"))
            .and_then(|owners| owners.get(target.owner_fqn()))
            .and_then(|members| members.get(target.member()));
        let accepts = |shard: &ActiveSemanticModelShard, record: &CompiledProcedureSummary| {
            if shard.manifest.language == "java"
                && shard.manifest.ecosystem == "jdk"
                && shard.matching_evidence.binary_search(selected).is_ok()
                && !record.result_use_obligations.is_empty()
            {
                ProcedureSummaryAcceptance::Accept(None)
            } else {
                ProcedureSummaryAcceptance::Reject
            }
        };
        let mut matched = if self.has_row_backed_shards() {
            let key = ProcedureSummaryMemberKey::new(
                "java",
                target.owner_fqn(),
                target.member(),
                target.has_receiver(),
                target.arity(),
            );
            resolve_procedure_records(
                self.applicable_summary_records(
                    key,
                    &[target.owner_fqn().to_owned()],
                    &[target.arity()],
                ),
                procedure_claims_agree,
                accepts,
            )
        } else {
            resolve_applicable_procedure_postings_where(
                &self.shards,
                shapes,
                target.has_receiver(),
                target.arity(),
                accepts,
            )
        };
        for record in &mut matched.records {
            record.matched_target_locator = Some(target.locator().clone());
            record.matched_call_arguments = target
                .call_arguments()
                .map(|arguments| arguments.to_vec().into_boxed_slice());
        }
        matched
    }

    /// Cheap candidate filter before resolving a receiver's exact owner. This
    /// does not prove a binding: callers must still select the exact member.
    #[doc(hidden)]
    pub fn has_normal_return_type_refinement_candidate(
        &self,
        language: &str,
        member: &str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> bool {
        if self.has_row_backed_shards() {
            return self.refinement_candidate_question(
                language,
                member,
                has_receiver,
                parameter_count,
            );
        }
        self.indexes
            .procedure_summaries_by_member
            .get(semantic_pack_realm(language))
            .into_iter()
            .flat_map(|owners| owners.values())
            .filter_map(|members| members.get(member))
            .any(|shapes| {
                resolve_applicable_procedure_postings(
                    &self.shards,
                    Some(shapes),
                    has_receiver,
                    parameter_count,
                )
                .records
                .iter()
                .any(|selected| !selected.normal_return_type_refinements().is_empty())
            })
    }

    /// Select an activated summary from an exact external declaration locator
    /// when the resolver proves the artifact path and member declaration but
    /// cannot publish a canonical owner FQN. Unlike member lookup, path and
    /// the declaration segment jointly identify the authored target without
    /// reconstructing a source spelling.
    pub fn procedure_summaries_for_declaration(
        &self,
        target: ProcedureSummaryDeclarationKey<'_>,
    ) -> ProcedureSummaryMatch {
        let symbols = self
            .indexes
            .procedure_summaries_by_target
            .get(semantic_pack_realm(target.language))
            .and_then(|paths| paths.get(target.path));
        if self.has_row_backed_shards() {
            return self.declaration_summary_question(target, symbols);
        }
        let mut symbols = symbols
            .into_iter()
            .flat_map(|symbols| symbols.iter())
            .collect::<Vec<_>>();
        // Hash buckets do not define declaration order. A symbol was first
        // published at its earliest posting, before shape traversal.
        symbols.sort_by_key(|(_, shapes)| summary_symbol_publication_order(shapes));
        let postings = symbols
            .into_iter()
            .filter(|(symbol, _)| {
                authored_procedure_target_identity(target.path, symbol)
                    .is_some_and(|(_, member)| member == target.member)
            })
            .flat_map(|(_, shapes)| {
                fixed_and_variadic_postings(shapes, target.has_receiver, target.parameter_count)
            });
        resolve_procedure_postings(&self.shards, postings, procedure_declaration_claims_agree)
    }

    /// Whether this active set has any member whose exact matcher behavior can
    /// prove an absent normal continuation for at least one call arity.
    ///
    /// This is a discovery hint only. A consumer must still call
    /// [`Self::proves_normal_continuation_absent`] for the exact owner and
    /// actual arity before changing control flow.
    pub fn has_normal_continuation_absence_candidates(&self, language: &str) -> bool {
        if self.has_row_backed_shards() {
            return self
                .absence_candidate_question(language)
                .has_language(language);
        }
        self.indexes
            .normal_continuation_absence_candidates
            .has_language(language)
    }

    /// Candidate owners for one external member spelling and receiver shape.
    ///
    /// An owner appears only when the activated matcher uniquely selects an
    /// explicit absence claim at some applicable arity. The returned slice is
    /// stable for this immutable active set and sorted for deterministic
    /// traversal. It does not prove any particular call shape.
    pub fn normal_continuation_absence_candidate_owners(
        &self,
        language: &str,
        member: &str,
        has_receiver: bool,
    ) -> Vec<String> {
        if self.has_row_backed_shards() {
            return self
                .absence_candidate_question(language)
                .owners(language, member, has_receiver)
                .to_vec();
        }
        self.indexes
            .normal_continuation_absence_candidates
            .owners(language, member, has_receiver)
            .to_vec()
    }

    /// Whether exact active-model agreement proves that the external procedure
    /// has no normal continuation.
    ///
    /// Overall summary completeness is not an extra gate: the claim is an
    /// explicit, independently validated axis. Empty and conflicting matches
    /// fail closed.
    pub fn proves_normal_continuation_absent(&self, target: ProcedureSummaryMemberKey<'_>) -> bool {
        procedure_match_proves_normal_continuation_absent(
            &self.procedure_summaries_for_member(target),
        )
    }

    /// Whether an activated receiverless procedure summary names this exact
    /// language/owner/member identity, at any arity.
    ///
    /// Java uses this only after its structured name-resolution ladder has
    /// established that an unshadowed method qualifier is a type name. The
    /// query lets the implicit `java.lang` tier resolve in summary-only test
    /// projects where no classpath declaration index exists; it never turns a
    /// source spelling into an owner by itself.
    #[doc(hidden)]
    pub fn has_receiverless_procedure_summary_member(
        &self,
        language: &str,
        owner: &str,
        member: &str,
    ) -> bool {
        if self.has_row_backed_shards() {
            return !self
                .summary_member_records(
                    ProcedureSummaryMemberKey::new(language, owner, member, false, 0),
                    &[owner.to_owned()],
                )
                .is_empty();
        }
        self.indexes
            .procedure_summaries_by_member
            .get(semantic_pack_realm(language))
            .and_then(|owners| owners.get(owner))
            .and_then(|members| members.get(member))
            .is_some_and(|shapes| {
                shapes
                    .fixed
                    .iter()
                    .chain(shapes.variadic.iter())
                    .any(|((has_receiver, _), postings)| !has_receiver && !postings.is_empty())
            })
    }

    fn type_match(&self, posting: Option<&Vec<RecordAddress>>) -> SemanticModelMatch<TypeFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .decoded()
                .payload()
                .declaration_facts()
                .and_then(|(types, _, _)| types.get(record))
        })
    }

    fn member_match(&self, posting: Option<&Vec<RecordAddress>>) -> SemanticModelMatch<MemberFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .decoded()
                .payload()
                .declaration_facts()
                .and_then(|(_, members, _)| members.get(record))
        })
    }

    fn relation_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<RelationFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .decoded()
                .payload()
                .declaration_facts()
                .and_then(|(_, _, relations)| relations.get(record))
        })
    }

    fn rule_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<GeneratorRule> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard.decoded().payload().generator_rules()?.get(record)
        })
    }
}

pub fn python_artifact_applies_to_target(
    shard: &ActiveSemanticModelShard,
    target: &UnmaterializedExternalTarget,
) -> bool {
    if !python_shard_requires_distribution_artifact(shard, target) {
        return true;
    }
    target.selected_python_artifact().is_some_and(|selected| {
        evidence_is_exact_python_distribution_artifact(selected)
            && shard.matching_evidence.binary_search(selected).is_ok()
            && target
                .selected_python_model_manifest_sha256()
                .is_some_and(|digest| digest == shard.manifest.content_sha256)
    })
}

pub fn python_shard_requires_distribution_artifact(
    shard: &ActiveSemanticModelShard,
    target: &UnmaterializedExternalTarget,
) -> bool {
    target.language().semantic_pack_label() == "python"
        && shard.manifest.language == "python"
        && shard.selectors.as_slice().iter().any(|selector| {
            selector
                .package
                .as_ref()
                .is_some_and(|package| package.name.starts_with("pkg:pypi/"))
        })
}

pub fn procedure_summary_actual_to_formal(
    shard: &ActiveSemanticModelShard,
    summary: &CompiledProcedureSummary,
    target: &UnmaterializedExternalTarget,
) -> Option<Option<Box<[u32]>>> {
    if python_shard_requires_distribution_artifact(shard, target) {
        if target.python_formal_parameter_count() != Some(summary.target.parameter_count)
            || target.python_formal_call_shape_accepts_arity(target.arity()) != Some(true)
        {
            return None;
        }
        let external_mapping = target.python_actual_to_formal()?;
        if summary.target.formals.is_empty() {
            // Empty formals preserve the legacy positional summary contract:
            // Python default omission is callable, but this summary cannot
            // prove the omitted formal's default-aware transfer semantics.
            if summary.target.variadic || target.arity() != summary.target.parameter_count {
                return None;
            }
        }
        let summary_mapping = if summary.target.formals.is_empty() {
            None
        } else {
            if summary.target.formals.len() != summary.target.parameter_count as usize
                || target.python_defaulted_formals().is_none_or(|defaults| {
                    defaults.len() != summary.target.formals.len()
                        || defaults
                            .iter()
                            .zip(&summary.target.formals)
                            .any(|(defaulted, formal)| *defaulted != formal.optional)
                })
            {
                return None;
            }
            let layout = summary_formal_layout(&summary.target)?;
            let summary_mapping =
                crate::analyzer::semantic::call_binding::bind_semantic_call_arguments(
                    target.call_arguments()?,
                    &layout,
                )?;
            if summary_mapping.as_ref() != external_mapping {
                return None;
            }
            Some(summary_mapping)
        };
        let mapping = summary_mapping
            .as_deref()
            .unwrap_or(external_mapping.as_ref());
        let reordered = mapping_reorders_fixed_formals(mapping, &summary.target.formals);
        // The retained mapping reaches summary transfers. Other formal-input
        // consumers do not yet carry it, so keep their claims incomplete when
        // a keyword call reorders those inputs.
        let mapped_claims_supported = !reordered
            || (summary.locations.is_empty()
                && summary.effects.is_empty()
                && summary.concurrency_effects.is_empty()
                && summary.preconditions.as_ref().is_none_or(Vec::is_empty)
                && summary.result_contracts.is_empty()
                && summary.result_use_obligations.is_empty()
                && summary.conditional_result_refinements.is_empty()
                && summary.conditional_indirect_writes.is_empty()
                && summary.normal_return_refinements.is_empty()
                && summary.normal_return_type_refinements.is_empty()
                && summary.class_decorator_identity.is_none());
        mapped_claims_supported.then(|| Some(mapping.to_vec().into_boxed_slice()))
    } else if !summary.target.formals.is_empty() {
        let layout = summary_formal_layout(&summary.target)?;
        let mapping = crate::analyzer::semantic::call_binding::bind_semantic_call_arguments(
            target.call_arguments()?,
            &layout,
        )?;
        if mapping.len() != target.arity() as usize {
            return None;
        }
        let reordered = mapping_reorders_fixed_formals(&mapping, &summary.target.formals);
        let mapped_claims_supported = !reordered
            || (summary.locations.is_empty()
                && summary.effects.is_empty()
                && summary.concurrency_effects.is_empty()
                && summary.preconditions.as_ref().is_none_or(Vec::is_empty)
                && summary.result_contracts.is_empty()
                && summary.result_use_obligations.is_empty()
                && summary.conditional_result_refinements.is_empty()
                && summary.conditional_indirect_writes.is_empty()
                && summary.normal_return_refinements.is_empty()
                && summary.normal_return_type_refinements.is_empty()
                && summary.class_decorator_identity.is_none());
        mapped_claims_supported.then_some(Some(mapping))
    } else {
        summary
            .target
            .accepts_parameter_count(target.arity())
            .then_some(None)
    }
}

#[derive(Debug)]
pub struct SemanticModelMatch<T> {
    pub records: Vec<ActivatedSemanticModelRecord<T>>,
    pub disposition: SemanticModelMatchDisposition,
    pub candidates_examined: usize,
    pub fallback_candidates_examined: usize,
}

#[derive(Debug, Clone)]
pub struct ActivatedSemanticModelRecord<T> {
    pub record: Arc<T>,
    pub shard: Arc<ActiveSemanticModelShard>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(any(test, feature = "test-support")), non_exhaustive)]
pub struct ActivatedProcedureSummary {
    pub record: Arc<CompiledProcedureSummary>,
    pub shard: Arc<ActiveSemanticModelShard>,
    pub actual_to_formal: Option<Box<[u32]>>,
    pub matched_target_locator: Option<SemanticLocator>,
    #[doc(hidden)]
    pub matched_owner_identity: Option<String>,
    pub matched_call_arguments: Option<Box<[crate::analyzer::semantic::SemanticCallArgument]>>,
}

#[derive(Debug)]
pub struct ProcedureSummaryMatch {
    pub applicability: ProcedureSummaryApplicability,
    pub records: Vec<ActivatedProcedureSummary>,
    pub disposition: SemanticModelMatchDisposition,
    pub candidates_examined: usize,
    pub fallback_candidates_examined: usize,
}

#[derive(Debug, Default)]
pub struct MatcherIndexes {
    types_by_id: HashMap<String, Vec<RecordAddress>>,
    types_by_name: HashMap<String, Vec<RecordAddress>>,
    members_by_id: HashMap<String, Vec<RecordAddress>>,
    members_by_owner_name: HashMap<String, HashMap<String, Vec<RecordAddress>>>,
    relations_by_id: HashMap<String, Vec<RecordAddress>>,
    relations_by_from: HashMap<String, Vec<RecordAddress>>,
    relations_by_to: HashMap<String, Vec<RecordAddress>>,
    rules_by_id: HashMap<String, Vec<RecordAddress>>,
    rules_by_language_construct: HashMap<String, Vec<RecordAddress>>,
    rules_by_annotation: HashMap<String, Vec<RecordAddress>>,
    rules_by_macro: HashMap<String, Vec<RecordAddress>>,
    rules_by_generator: HashMap<String, Vec<RecordAddress>>,
    rules_by_owner: HashMap<String, Vec<RecordAddress>>,
    rules_by_call: HashMap<String, HashMap<String, Vec<RecordAddress>>>,
    procedure_summaries_by_target: ProcedureSummaryTargetPostings,
    /// Parallel to `procedure_summaries_by_target`, keyed by canonical identity
    /// (language, owner FQN, member, has_receiver, applicable arity) instead of
    /// (language, path, parameter-typed symbol). It binds an activated summary
    /// to a fully-qualified external callee that never materializes to an
    /// artifact, whose path and parameter types are unrecoverable (#1978).
    procedure_summaries_by_member: ProcedureSummaryTargetPostings,
    normal_continuation_absence_candidates: NormalContinuationAbsenceCandidateIndex,
}

impl MatcherIndexes {
    pub fn build(
        active: &[Arc<ActiveSemanticModelShard>],
        limits: SemanticModelRuntimeLimits,
        cancellation: &CancellationToken,
        report: &mut SemanticModelActivationReport,
    ) -> Result<Self, String> {
        let mut indexes = Self {
            types_by_id: map_with_capacity(active.len()),
            types_by_name: map_with_capacity(active.len()),
            members_by_id: map_with_capacity(active.len()),
            members_by_owner_name: map_with_capacity(active.len()),
            relations_by_id: map_with_capacity(active.len()),
            relations_by_from: map_with_capacity(active.len()),
            relations_by_to: map_with_capacity(active.len()),
            rules_by_id: map_with_capacity(active.len()),
            rules_by_language_construct: map_with_capacity(active.len()),
            rules_by_annotation: map_with_capacity(active.len()),
            rules_by_macro: map_with_capacity(active.len()),
            rules_by_generator: map_with_capacity(active.len()),
            rules_by_owner: map_with_capacity(active.len()),
            rules_by_call: map_with_capacity(active.len()),
            procedure_summaries_by_target: map_with_capacity(active.len()),
            procedure_summaries_by_member: map_with_capacity(active.len()),
            normal_continuation_absence_candidates:
                NormalContinuationAbsenceCandidateIndex::default(),
        };
        let mut entries = 0usize;
        let mut working_bytes = 0u64;
        let mut records_visited = 0usize;
        let mut guard_excluded_records = 0usize;

        for (shard_index, active_shard) in active.iter().enumerate() {
            if active_shard.decoded.is_none() {
                continue;
            }
            let shard_index = u32::try_from(shard_index)
                .map_err(|_| "semantic-model shard address exceeds u32".to_owned())?;
            if let Some((types, members, relations)) =
                active_shard.decoded().payload().declaration_facts()
            {
                for (record_index, fact) in types.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    if active_shard.guard_excludes(fact.guard.as_ref()) {
                        guard_excluded_records += 1;
                        continue;
                    }
                    let address = record_address(shard_index, record_index)?;
                    insert_posting(
                        &mut indexes.types_by_id,
                        fact.id.clone(),
                        fact.id.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    insert_posting(
                        &mut indexes.types_by_name,
                        fact.name.clone(),
                        fact.name.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    for alias in &fact.aliases {
                        insert_posting(
                            &mut indexes.types_by_name,
                            alias.clone(),
                            alias.len(),
                            address,
                            &mut entries,
                            &mut working_bytes,
                            limits,
                        )?;
                    }
                }
                for (record_index, fact) in members.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    if active_shard.guard_excludes(fact.guard.as_ref()) {
                        guard_excluded_records += 1;
                        continue;
                    }
                    let address = record_address(shard_index, record_index)?;
                    insert_posting(
                        &mut indexes.members_by_id,
                        fact.id.clone(),
                        fact.id.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    insert_member_name(
                        &mut indexes.members_by_owner_name,
                        fact,
                        &fact.name,
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    for alias in &fact.aliases {
                        insert_member_name(
                            &mut indexes.members_by_owner_name,
                            fact,
                            alias,
                            address,
                            &mut entries,
                            &mut working_bytes,
                            limits,
                        )?;
                    }
                }
                for (record_index, fact) in relations.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard_index, record_index)?;
                    for (map, key) in [
                        (&mut indexes.relations_by_id, &fact.id),
                        (&mut indexes.relations_by_from, &fact.from),
                        (&mut indexes.relations_by_to, &fact.to),
                    ] {
                        insert_posting(
                            map,
                            key.clone(),
                            key.len(),
                            address,
                            &mut entries,
                            &mut working_bytes,
                            limits,
                        )?;
                    }
                }
            }
            if let Some(rules) = active_shard.decoded().payload().generator_rules() {
                for (record_index, rule) in rules.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard_index, record_index)?;
                    insert_posting(
                        &mut indexes.rules_by_id,
                        rule.id.clone(),
                        rule.id.len(),
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    insert_rule_trigger(
                        &mut indexes,
                        &rule.trigger,
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                }
            }
            if let Some(summaries) = active_shard.decoded().payload().procedure_summaries() {
                for (record_index, summary) in summaries.iter().enumerate() {
                    poll_matcher_cancellation(cancellation, records_visited)?;
                    records_visited += 1;
                    let address = record_address(shard_index, record_index)?;
                    let key_bytes = active_shard
                        .manifest
                        .language
                        .len()
                        .saturating_add(summary.target.path.len())
                        .saturating_add(summary.target.symbol.len())
                        .saturating_add(size_of::<bool>())
                        .saturating_add(size_of::<u32>());
                    let paths = indexes
                        .procedure_summaries_by_target
                        .entry(semantic_pack_realm(&active_shard.manifest.language).to_owned())
                        .or_default();
                    let symbols = paths.entry(summary.target.path.clone()).or_default();
                    let shapes = symbols.entry(summary.target.symbol.clone()).or_default();
                    insert_procedure_posting(
                        shapes,
                        &summary.target,
                        key_bytes,
                        address,
                        &mut entries,
                        &mut working_bytes,
                        limits,
                    )?;
                    // #1978: also index by canonical identity so an unmaterialized
                    // external callee -- which cannot present the authored path or
                    // parameter-typed symbol -- can still find this summary. A bare
                    // symbol is a module-level target, so its owner is the module the
                    // authored path names (#2610).
                    if let Some((owner, member)) = authored_procedure_target_identity(
                        &summary.target.path,
                        &summary.target.symbol,
                    ) {
                        let member_key_bytes = active_shard
                            .manifest
                            .language
                            .len()
                            .saturating_add(owner.len())
                            .saturating_add(member.len())
                            .saturating_add(size_of::<bool>())
                            .saturating_add(size_of::<u32>());
                        let owners = indexes
                            .procedure_summaries_by_member
                            .entry(semantic_pack_realm(&active_shard.manifest.language).to_owned())
                            .or_default();
                        let members = owners.entry(owner.into_owned()).or_default();
                        let shapes = members.entry(member.to_owned()).or_default();
                        insert_procedure_posting(
                            shapes,
                            &summary.target,
                            member_key_bytes,
                            address,
                            &mut entries,
                            &mut working_bytes,
                            limits,
                        )?;
                        if !summary.target.formals.is_empty()
                            && summary.target.formals.iter().any(|formal| formal.optional)
                        {
                            let minimum_actual_count = u32::try_from(
                                summary
                                    .target
                                    .formals
                                    .iter()
                                    .filter(|formal| !formal.optional)
                                    .count(),
                            )
                            .expect("validated formal count fits u32");
                            let formal_count = summary.target.parameter_count;
                            charge_posting_entry(
                                member_key_bytes.saturating_add(size_of::<u32>() * 2),
                                &mut entries,
                                &mut working_bytes,
                                limits,
                            )?;
                            shapes
                                .optional_fixed
                                .entry((
                                    summary.target.has_receiver,
                                    minimum_actual_count,
                                    formal_count,
                                ))
                                .or_default()
                                .push(address);
                        }
                        shapes.raw_normal_continuation_absence_claim
                            [usize::from(summary.target.has_receiver)] |=
                            summary.normal_continuation_absent;
                    }
                }
            }
        }

        indexes.normal_continuation_absence_candidates =
            build_normal_continuation_absence_candidates(
                active,
                &indexes.procedure_summaries_by_member,
                cancellation,
                &mut entries,
                &mut working_bytes,
                limits,
            )?;

        let shard_bytes = active
            .iter()
            .try_fold(0u64, |total, active_shard| {
                total.checked_add(active_shard.descriptor.raw_size)
            })
            .ok_or_else(|| "semantic-model retained-byte accounting overflowed".to_owned())?;
        let retained_bytes = working_bytes
            .checked_add(shard_bytes)
            .ok_or_else(|| "semantic-model retained-byte accounting overflowed".to_owned())?;
        if retained_bytes > limits.max_retained_bytes {
            return Err("semantic-model retained-byte budget exceeded".to_owned());
        }
        report.index_entries = entries;
        report.working_bytes = working_bytes;
        report.retained_bytes = retained_bytes;
        report.guard_excluded_records = guard_excluded_records;
        Ok(indexes)
    }
}

// The schema/reader integration test enumerates the actual postings, including
// empty families. This hook never participates in product resolution.
#[cfg(any(test, feature = "test-support"))]
impl MatcherIndexes {
    #[doc(hidden)]
    pub fn parity_postings(&self) -> Vec<(&'static str, Vec<String>, &[RecordAddress])> {
        let mut result = Vec::new();
        for (family, map) in [
            ("types_id", &self.types_by_id),
            ("types_name", &self.types_by_name),
            ("members_id", &self.members_by_id),
            ("relations_id", &self.relations_by_id),
            ("relations_from", &self.relations_by_from),
            ("relations_to", &self.relations_by_to),
            ("rules_id", &self.rules_by_id),
            ("rules_construct", &self.rules_by_language_construct),
            ("rules_annotation", &self.rules_by_annotation),
            ("rules_macro", &self.rules_by_macro),
            ("rules_generator", &self.rules_by_generator),
            ("rules_owner", &self.rules_by_owner),
        ] {
            for (key, records) in map {
                result.push((family, vec![key.clone()], records.as_slice()));
            }
        }
        for (family, map) in [
            ("members_owner_name", &self.members_by_owner_name),
            ("rules_call", &self.rules_by_call),
        ] {
            for (owner, names) in map {
                for (name, records) in names {
                    result.push((
                        family,
                        vec![owner.clone(), name.clone()],
                        records.as_slice(),
                    ));
                }
            }
        }
        for (family, languages) in [
            ("summaries_target", &self.procedure_summaries_by_target),
            ("summaries_member", &self.procedure_summaries_by_member),
        ] {
            for (language, owners) in languages {
                for (owner, names) in owners {
                    for (name, shapes) in names {
                        for (kind, postings) in [
                            ("variadic", &shapes.variadic),
                            ("minimum", &shapes.variadic_by_minimum_arity),
                        ] {
                            for ((receiver, arity), records) in postings {
                                result.push((
                                    family,
                                    vec![
                                        language.clone(),
                                        owner.clone(),
                                        name.clone(),
                                        kind.into(),
                                        u8::from(*receiver).to_string(),
                                        arity.to_string(),
                                    ],
                                    records.as_slice(),
                                ));
                            }
                        }
                        for ((receiver, arity), records) in &shapes.fixed {
                            result.push((
                                family,
                                vec![
                                    language.clone(),
                                    owner.clone(),
                                    name.clone(),
                                    "fixed".into(),
                                    u8::from(*receiver).to_string(),
                                    arity.to_string(),
                                ],
                                records.as_slice(),
                            ));
                        }
                        for ((receiver, minimum, arity), records) in &shapes.optional_fixed {
                            result.push((
                                family,
                                vec![
                                    language.clone(),
                                    owner.clone(),
                                    name.clone(),
                                    "optional".into(),
                                    u8::from(*receiver).to_string(),
                                    minimum.to_string(),
                                    arity.to_string(),
                                ],
                                records.as_slice(),
                            ));
                        }
                    }
                }
            }
        }
        result
    }

    #[doc(hidden)]
    pub fn parity_raw_absence_claims(&self) -> Vec<(String, String, String, bool)> {
        let mut result = Vec::new();
        for (language, owners) in &self.procedure_summaries_by_member {
            for (owner, members) in owners {
                for (member, shapes) in members {
                    for receiver in [false, true] {
                        if shapes.raw_normal_continuation_absence_claim[usize::from(receiver)] {
                            result.push((
                                language.clone(),
                                owner.clone(),
                                member.clone(),
                                receiver,
                            ));
                        }
                    }
                }
            }
        }
        result
    }

    #[doc(hidden)]
    pub fn parity_absence_candidates(&self) -> &NormalContinuationAbsenceCandidateIndex {
        &self.normal_continuation_absence_candidates
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum EffectiveProcedureClaims {
    #[default]
    Empty,
    Unique {
        rank: (EvidenceRank, u8),
        representative: RecordAddress,
    },
    Conflict {
        rank: (EvidenceRank, u8),
    },
}

impl EffectiveProcedureClaims {
    fn absorb_with(
        &mut self,
        address: RecordAddress,
        lookup: &impl Fn(RecordAddress) -> (Arc<CompiledProcedureSummary>, (EvidenceRank, u8)),
    ) {
        let (_, rank) = lookup(address);
        match *self {
            Self::Empty => {
                *self = Self::Unique {
                    rank,
                    representative: address,
                };
            }
            Self::Unique {
                rank: effective_rank,
                representative,
            } => match rank.cmp(&effective_rank) {
                Ordering::Less => {}
                Ordering::Greater => {
                    *self = Self::Unique {
                        rank,
                        representative: address,
                    };
                }
                Ordering::Equal => {
                    if !procedure_claims_agree(&lookup(representative).0, &lookup(address).0) {
                        *self = Self::Conflict { rank };
                    }
                }
            },
            Self::Conflict {
                rank: effective_rank,
            } if rank > effective_rank => {
                *self = Self::Unique {
                    rank,
                    representative: address,
                };
            }
            Self::Conflict { .. } => {}
        }
    }
}

pub fn indexed_procedure_summary(
    active: &[Arc<ActiveSemanticModelShard>],
    address: RecordAddress,
) -> Arc<CompiledProcedureSummary> {
    active[address.shard as usize]
        .decoded()
        .payload()
        .procedure_summaries()
        .expect("procedure-summary index address must resolve to its payload kind")
        .get(address.record as usize)
        .expect("procedure-summary index address must resolve to its record")
        .clone()
}

pub fn absorb_procedure_posting(
    effective: &mut EffectiveProcedureClaims,
    active: &[Arc<ActiveSemanticModelShard>],
    posting: &[RecordAddress],
    cancellation: &CancellationToken,
    addresses_visited: &mut usize,
) -> Result<(), String> {
    absorb_procedure_posting_with(
        effective,
        &|address| {
            let shard = &active[address.shard as usize];
            (
                indexed_procedure_summary(active, address),
                (shard.evidence_rank, shard.source_rank),
            )
        },
        posting,
        cancellation,
        addresses_visited,
    )
}

fn absorb_procedure_posting_with(
    effective: &mut EffectiveProcedureClaims,
    lookup: &impl Fn(RecordAddress) -> (Arc<CompiledProcedureSummary>, (EvidenceRank, u8)),
    posting: &[RecordAddress],
    cancellation: &CancellationToken,
    addresses_visited: &mut usize,
) -> Result<(), String> {
    for &address in posting {
        poll_matcher_cancellation(cancellation, *addresses_visited)?;
        *addresses_visited = addresses_visited.saturating_add(1);
        effective.absorb_with(address, lookup);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_normal_continuation_absence_candidates(
    active: &[Arc<ActiveSemanticModelShard>],
    postings: &ProcedureSummaryTargetPostings,
    cancellation: &CancellationToken,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<NormalContinuationAbsenceCandidateIndex, String> {
    build_absence_candidates_with(
        postings,
        cancellation,
        entries,
        working_bytes,
        limits,
        &|address| {
            let shard = &active[address.shard as usize];
            (
                indexed_procedure_summary(active, address),
                (shard.evidence_rank, shard.source_rank),
            )
        },
    )
}

fn build_absence_candidates_with(
    postings: &ProcedureSummaryTargetPostings,
    cancellation: &CancellationToken,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
    lookup: &impl Fn(RecordAddress) -> (Arc<CompiledProcedureSummary>, (EvidenceRank, u8)),
) -> Result<NormalContinuationAbsenceCandidateIndex, String> {
    let mut candidates = NormalContinuationAbsenceCandidateIndex::default();
    let mut addresses_visited = 0usize;
    for (language, owners) in postings {
        for (owner, members) in owners {
            for (member, shapes) in members {
                for has_receiver in [false, true] {
                    if !shapes.raw_normal_continuation_absence_claim[usize::from(has_receiver)] {
                        continue;
                    }
                    // This pass runs only once per immutable active set. Poll
                    // every hinted target and arity so cancellation can never
                    // publish a partially derived candidate inventory.
                    poll_matcher_cancellation(cancellation, 0)?;

                    // A fixed record exists only at A, while a variadic record
                    // begins at its required fixed-formal count and remains
                    // applicable. The candidate set changes at each fixed A,
                    // immediately after it disappears, or at a variadic minimum.
                    let mut representative_arities = Vec::new();
                    for &(receiver, arity) in shapes.fixed.keys() {
                        if receiver != has_receiver {
                            continue;
                        }
                        representative_arities.push(arity);
                        if let Some(successor) = arity.checked_add(1) {
                            representative_arities.push(successor);
                        }
                    }
                    for &(receiver, minimum_actual_count) in shapes.variadic_by_minimum_arity.keys()
                    {
                        if receiver != has_receiver {
                            continue;
                        }
                        representative_arities.push(minimum_actual_count);
                    }
                    representative_arities.sort_unstable();
                    representative_arities.dedup();

                    // Sorting the shape boundaries costs O(S log S). The
                    // merge below then visits every applicable variadic and
                    // fixed posting address once, rather than rescanning the
                    // full variadic prefix at every boundary.
                    let mut variadic_postings = shapes
                        .variadic_by_minimum_arity
                        .range((has_receiver, 0)..=(has_receiver, u32::MAX))
                        .peekable();
                    let mut effective_variadic = EffectiveProcedureClaims::default();
                    let mut effective = false;
                    for arity in representative_arities {
                        poll_matcher_cancellation(cancellation, 0)?;
                        while let Some((shape, _posting)) = variadic_postings.peek() {
                            if shape.1 > arity {
                                break;
                            }
                            let (_shape, posting) = variadic_postings
                                .next()
                                .expect("peeked variadic posting must remain available");
                            absorb_procedure_posting_with(
                                &mut effective_variadic,
                                lookup,
                                posting,
                                cancellation,
                                &mut addresses_visited,
                            )?;
                        }

                        // Fixed claims apply only at this exact arity. Start
                        // from the accumulated variadic state so a successor
                        // boundary removes the fixed claims without rescanning
                        // any already-applicable variadic posting.
                        let mut effective_at_arity = effective_variadic;
                        if let Some(posting) = shapes.fixed.get(&(has_receiver, arity)) {
                            absorb_procedure_posting_with(
                                &mut effective_at_arity,
                                lookup,
                                posting,
                                cancellation,
                                &mut addresses_visited,
                            )?;
                        }
                        if matches!(effective_at_arity, EffectiveProcedureClaims::Unique { representative, .. } if lookup(representative).0.normal_continuation_absent)
                        {
                            effective = true;
                            break;
                        }
                    }
                    if !effective {
                        continue;
                    }

                    let retained_bytes = language
                        .len()
                        .saturating_add(member.len())
                        .saturating_add(owner.len())
                        .saturating_add(size_of::<String>().saturating_mul(3))
                        .saturating_add(size_of::<bool>())
                        .saturating_add(64);
                    charge_index_entry(retained_bytes, entries, working_bytes, limits)?;
                    candidates
                        .by_language
                        .entry(language.clone())
                        .or_default()
                        .entry(member.clone())
                        .or_default()
                        .owners_mut(has_receiver)
                        .push(owner.clone());
                }
            }
        }
    }
    for members in candidates.by_language.values_mut() {
        for candidates in members.values_mut() {
            candidates.receiverless_owners.sort_unstable();
            candidates.receiver_owners.sort_unstable();
        }
    }
    Ok(candidates)
}

#[allow(clippy::too_many_arguments)]
pub fn insert_rule_trigger(
    indexes: &mut MatcherIndexes,
    trigger: &RuleTrigger,
    address: RecordAddress,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    let (map, value) = match trigger {
        RuleTrigger::LanguageConstruct { construct } => {
            (&mut indexes.rules_by_language_construct, construct)
        }
        RuleTrigger::Annotation { name } => (&mut indexes.rules_by_annotation, name),
        RuleTrigger::AnnotatedField { annotation, .. } => {
            (&mut indexes.rules_by_annotation, annotation)
        }
        RuleTrigger::MacroInvocation { name } => (&mut indexes.rules_by_macro, name),
        RuleTrigger::GeneratorInvocation { name } => (&mut indexes.rules_by_generator, name),
        RuleTrigger::ResolvedOwner { owner } => (&mut indexes.rules_by_owner, owner),
        RuleTrigger::ResolvedCall { owner, name } => {
            let names = indexes.rules_by_call.entry(owner.clone()).or_default();
            return insert_posting(
                names,
                name.clone(),
                owner.len() + name.len(),
                address,
                entries,
                working_bytes,
                limits,
            );
        }
    };
    insert_posting(
        map,
        value.clone(),
        value.len(),
        address,
        entries,
        working_bytes,
        limits,
    )
}

pub fn resolve_posting<T: Eq, F>(
    shards: &[Arc<ActiveSemanticModelShard>],
    posting: Option<&Vec<RecordAddress>>,
    mut resolve: F,
) -> SemanticModelMatch<T>
where
    F: FnMut(&ActiveSemanticModelShard, usize) -> Option<&Arc<T>>,
{
    let posting = posting.map(Vec::as_slice).unwrap_or_default();
    let best_rank = posting
        .iter()
        .map(|address| {
            let shard = &shards[address.shard as usize];
            (shard.evidence_rank, shard.source_rank)
        })
        .max();
    let candidates = posting
        .iter()
        .filter(|address| {
            let shard = &shards[address.shard as usize];
            Some((shard.evidence_rank, shard.source_rank)) == best_rank
        })
        .map(|address| {
            let shard = &shards[address.shard as usize];
            ActivatedSemanticModelRecord {
                record: Arc::clone(
                    resolve(shard, address.record as usize)
                        .expect("semantic-model index address must resolve to its record kind"),
                ),
                shard: Arc::clone(shard),
            }
        });
    resolve_ranked_records(candidates, best_rank, posting.len())
}

/// Keep decoded-only callers lazy, without allocating a result vector. The row
/// branch already contains the ordered merge of both sources for this question.
#[doc(hidden)]
pub fn query_or_posting<T>(
    rows: Option<Vec<T>>,
    mut posting: impl Iterator<Item = T>,
) -> impl Iterator<Item = T> {
    let mut rows = rows.map(Vec::into_iter);
    std::iter::from_fn(move || match &mut rows {
        Some(rows) => rows.next(),
        None => posting.next(),
    })
}

/// Interleave publication-ordered answers from the two backings. Equal keys
/// keep the decoded contributor first, matching a stable publication sort.
#[doc(hidden)]
pub fn merge_ordered_semantic_results<T>(
    decoded: impl IntoIterator<Item = T>,
    rows: impl IntoIterator<Item = T>,
    compare: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Vec<T> {
    let mut decoded = decoded.into_iter().peekable();
    let mut rows = rows.into_iter().peekable();
    let mut result = Vec::new();
    loop {
        let next = match (decoded.peek(), rows.peek()) {
            (Some(left), Some(right)) => {
                if compare(left, right).is_le() {
                    decoded.next()
                } else {
                    rows.next()
                }
            }
            (Some(_), None) => decoded.next(),
            (None, Some(_)) => rows.next(),
            (None, None) => break,
        };
        result.push(next.expect("one merge input is nonempty"));
    }
    result
}

/// Shared evidence selection for decoded postings and query-owned catalog rows.
#[doc(hidden)]
pub fn resolve_records<T: Eq>(
    candidates: Vec<ActivatedSemanticModelRecord<T>>,
) -> SemanticModelMatch<T> {
    let best_rank = candidates
        .iter()
        .map(|candidate| (candidate.shard.evidence_rank, candidate.shard.source_rank))
        .max();
    let candidates_examined = candidates.len();
    resolve_ranked_records(candidates, best_rank, candidates_examined)
}

fn resolve_ranked_records<T: Eq>(
    candidates: impl IntoIterator<Item = ActivatedSemanticModelRecord<T>>,
    best_rank: Option<(EvidenceRank, u8)>,
    candidates_examined: usize,
) -> SemanticModelMatch<T> {
    let mut records = Vec::new();
    for candidate in candidates {
        let shard = &candidate.shard;
        if Some((shard.evidence_rank, shard.source_rank)) != best_rank {
            continue;
        }
        let record = &candidate.record;
        if !records
            .iter()
            .any(|candidate: &ActivatedSemanticModelRecord<T>| {
                candidate.record.as_ref() == record.as_ref()
                    && !(candidate.shard.matched_evidence.ecosystem == "jdk"
                        && shard.matched_evidence.ecosystem == "jdk"
                        && candidate.shard.matched_evidence.artifact_sha256
                            != shard.matched_evidence.artifact_sha256)
            })
        {
            records.push(ActivatedSemanticModelRecord {
                record: Arc::clone(record),
                shard: Arc::clone(shard),
            });
        }
    }
    SemanticModelMatch {
        disposition: match records.len() {
            0 => SemanticModelMatchDisposition::Empty,
            1 => SemanticModelMatchDisposition::Unique,
            _ => SemanticModelMatchDisposition::Conflict,
        },
        records,
        candidates_examined,
        fallback_candidates_examined: 0,
    }
}

fn summary_symbol_publication_order(shapes: &ProcedureSummaryShapePostings) -> (u32, u32) {
    shapes
        .fixed
        .values()
        .chain(shapes.variadic.values())
        .flatten()
        .map(|address| (address.shard, address.record))
        .min()
        .expect("an indexed summary symbol has a publication")
}

pub fn resolve_exact_procedure_postings(
    shards: &[Arc<ActiveSemanticModelShard>],
    shapes: Option<&ProcedureSummaryShapePostings>,
    has_receiver: bool,
    formal_parameter_count: u32,
) -> ProcedureSummaryMatch {
    let Some(shapes) = shapes else {
        return empty_procedure_match();
    };
    let key = (has_receiver, formal_parameter_count);
    resolve_procedure_postings(
        shards,
        [shapes.fixed.get(&key), shapes.variadic.get(&key)]
            .into_iter()
            .flatten(),
        procedure_declaration_claims_agree,
    )
}

pub fn resolve_applicable_procedure_postings(
    shards: &[Arc<ActiveSemanticModelShard>],
    shapes: Option<&ProcedureSummaryShapePostings>,
    has_receiver: bool,
    actual_parameter_count: u32,
) -> ProcedureSummaryMatch {
    resolve_applicable_procedure_postings_where(
        shards,
        shapes,
        has_receiver,
        actual_parameter_count,
        |_, _| ProcedureSummaryAcceptance::Accept(None),
    )
}

pub fn resolve_applicable_procedure_postings_where(
    shards: &[Arc<ActiveSemanticModelShard>],
    shapes: Option<&ProcedureSummaryShapePostings>,
    has_receiver: bool,
    actual_parameter_count: u32,
    accepts_record: impl Fn(
        &ActiveSemanticModelShard,
        &CompiledProcedureSummary,
    ) -> ProcedureSummaryAcceptance,
) -> ProcedureSummaryMatch {
    resolve_applicable_procedure_postings_where_for_counts(
        shards,
        shapes,
        has_receiver,
        &[actual_parameter_count],
        accepts_record,
    )
}

pub fn resolve_applicable_procedure_postings_where_for_counts(
    shards: &[Arc<ActiveSemanticModelShard>],
    shapes: Option<&ProcedureSummaryShapePostings>,
    has_receiver: bool,
    actual_parameter_counts: &[u32],
    accepts_record: impl Fn(
        &ActiveSemanticModelShard,
        &CompiledProcedureSummary,
    ) -> ProcedureSummaryAcceptance,
) -> ProcedureSummaryMatch {
    let Some(shapes) = shapes else {
        return empty_procedure_match();
    };
    let mut parameter_counts = actual_parameter_counts.to_vec();
    parameter_counts.sort_unstable();
    parameter_counts.dedup();
    let mut postings = Vec::new();
    for actual_parameter_count in parameter_counts {
        postings.extend(fixed_and_variadic_postings(
            shapes,
            has_receiver,
            actual_parameter_count,
        ));
        postings.extend(
            shapes
                .optional_fixed
                .range(
                    (has_receiver, 0, actual_parameter_count)
                        ..=(has_receiver, actual_parameter_count, u32::MAX),
                )
                .map(|(_key, posting)| posting),
        );
    }
    resolve_procedure_postings_where(shards, postings, procedure_claims_agree, accepts_record)
}

pub fn procedure_match_proves_normal_continuation_absent(matched: &ProcedureSummaryMatch) -> bool {
    matched.disposition == SemanticModelMatchDisposition::Unique
        && matches!(
            matched.records.as_slice(),
            [summary] if summary.normal_continuation_absent()
        )
}

pub fn empty_procedure_match() -> ProcedureSummaryMatch {
    ProcedureSummaryMatch {
        applicability: ProcedureSummaryApplicability::Complete,
        records: Vec::new(),
        disposition: SemanticModelMatchDisposition::Empty,
        candidates_examined: 0,
        fallback_candidates_examined: 0,
    }
}

pub fn resolve_procedure_postings<'posting>(
    shards: &[Arc<ActiveSemanticModelShard>],
    postings: impl IntoIterator<Item = &'posting Vec<RecordAddress>>,
    claims_agree: fn(&CompiledProcedureSummary, &CompiledProcedureSummary) -> bool,
) -> ProcedureSummaryMatch {
    resolve_procedure_postings_where(shards, postings, claims_agree, |_, _| {
        ProcedureSummaryAcceptance::Accept(None)
    })
}

pub fn resolve_procedure_postings_where<'posting>(
    shards: &[Arc<ActiveSemanticModelShard>],
    postings: impl IntoIterator<Item = &'posting Vec<RecordAddress>>,
    claims_agree: fn(&CompiledProcedureSummary, &CompiledProcedureSummary) -> bool,
    accepts_record: impl Fn(
        &ActiveSemanticModelShard,
        &CompiledProcedureSummary,
    ) -> ProcedureSummaryAcceptance,
) -> ProcedureSummaryMatch {
    let candidates = postings.into_iter().flat_map(|posting| {
        posting.iter().map(|address| {
            let shard = &shards[address.shard as usize];
            let record = &shard
                .decoded()
                .payload()
                .procedure_summaries()
                .expect("procedure-summary index address must resolve to its payload kind")
                [address.record as usize];
            ActivatedSemanticModelRecord {
                record: Arc::clone(record),
                shard: Arc::clone(shard),
            }
        })
    });
    resolve_procedure_records(candidates, claims_agree, accepts_record)
}

/// Keep rank, duplicate claims and acceptance order identical for both backings.
#[doc(hidden)]
pub fn resolve_procedure_records(
    candidates: impl IntoIterator<Item = ActivatedSemanticModelRecord<CompiledProcedureSummary>>,
    claims_agree: fn(&CompiledProcedureSummary, &CompiledProcedureSummary) -> bool,
    accepts_record: impl Fn(
        &ActiveSemanticModelShard,
        &CompiledProcedureSummary,
    ) -> ProcedureSummaryAcceptance,
) -> ProcedureSummaryMatch {
    let mut candidates_examined = 0usize;
    let mut best_rank = None;
    let mut records = Vec::<ActivatedProcedureSummary>::new();
    for candidate in candidates {
        candidates_examined = candidates_examined.saturating_add(1);
        let shard = candidate.shard;
        let record = candidate.record;
        let actual_to_formal = match accepts_record(&shard, &record) {
            ProcedureSummaryAcceptance::Reject => continue,
            ProcedureSummaryAcceptance::Accept(mapping) => mapping,
        };
        if records.iter().any(|candidate| {
            claims_agree(&candidate.record, &record)
                && candidate.actual_to_formal == actual_to_formal
        }) {
            continue;
        }
        let rank = (shard.evidence_rank, shard.source_rank);
        if best_rank.is_some_and(|best| rank < best) {
            continue;
        }
        if best_rank.is_none_or(|best| rank > best) {
            best_rank = Some(rank);
            records.clear();
        }
        if records
            .iter()
            .any(|candidate| claims_agree(&candidate.record, &record))
        {
            continue;
        }
        records.push(ActivatedProcedureSummary {
            record: Arc::clone(&record),
            shard: Arc::clone(&shard),
            actual_to_formal,
            matched_target_locator: None,
            matched_owner_identity: None,
            matched_call_arguments: None,
        });
    }
    ProcedureSummaryMatch {
        applicability: ProcedureSummaryApplicability::Complete,
        disposition: match records.len() {
            0 => SemanticModelMatchDisposition::Empty,
            1 => SemanticModelMatchDisposition::Unique,
            _ => SemanticModelMatchDisposition::Conflict,
        },
        records,
        candidates_examined,
        fallback_candidates_examined: 0,
    }
}

/// Translate a resolver-selected provider row to its published record identity.
/// Keep the publisher's owner-member order; overlay composition order is unrelated.
pub fn selected_external_descriptor(
    active: &ResolvedActiveSemanticModels,
    selected: &crate::analyzer::resolution::ExternalMemberIdentity,
) -> Option<(String, String)> {
    for owner in active.all_type_records_named(&selected.owner.owner_fqn) {
        if owner.shard.manifest.semantic_sha256 != selected.owner.provider_id.as_ref() {
            continue;
        }
        if owner.shard.decoded.is_none() {
            let identity = owner
                .shard
                .row_store
                .expect("row-backed owner has catalog coordinates");
            let source = match identity.database {
                CatalogShardDatabase::Durable => "durable",
                CatalogShardDatabase::Session => "session",
            };
            let records = crate::analyzer::store::model_catalog::semantic_catalog_question(
                "SELECTED_EXTERNAL_DESCRIPTOR", selected,
                active.source_reader().expect("row-backed set has its reader").raw_rows(
                    r#"SELECT source_db,shard_key,record_id FROM (
                      SELECT m.source_db,m.shard_key,m.record_id,0 AS origin,m.record_key AS position
                      FROM active_catalog_declaration_members m
                      WHERE m.source_db=:source AND m.shard_key=:shard AND m.owner_id=:owner
                        AND json_extract(m.record_json,'$.guard') IS NULL
                      UNION ALL
                      SELECT t.source_db,t.shard_key,json_extract(extra.value,'$.id'),1,CAST(extra.key AS INTEGER)
                      FROM active_catalog_declaration_types t,
                           json_each(t.record_json,'$.jvm_inventory.additional_members') extra
                      WHERE t.source_db=:source AND t.shard_key=:shard AND t.record_id=:owner
                        AND json_extract(extra.value,'$.guard') IS NULL
                        AND json_extract(extra.value,'$.owner')=:owner
                    ) ORDER BY origin,position LIMIT 1 OFFSET :ordinal"#,
                    named_params! { ":source": source, ":shard": identity.shard_key,
                        ":owner": owner.record.id, ":ordinal": selected.ordinal },
                    &active.shards, |row| row.get::<_, String>("record_id")),
            );
            return records.first().map(|record| {
                (
                    record.shard.manifest.semantic_sha256.clone(),
                    record.record.as_ref().clone(),
                )
            });
        }
        let (_, members, _) = owner.shard.decoded().payload().declaration_facts()?;
        let member = members
            .iter()
            .map(AsRef::as_ref)
            .chain(
                owner
                    .record
                    .jvm_inventory
                    .iter()
                    .flat_map(|inventory| &inventory.additional_members),
            )
            .filter(|member| member.owner == owner.record.id && member.guard.is_none())
            .nth(usize::try_from(selected.ordinal).expect("provider ordinal fits usize"))?;
        return Some((
            owner.shard.manifest.semantic_sha256.clone(),
            member.id.clone(),
        ));
    }
    None
}

/// Canonical identity for a fully-qualified external callee that never
/// materializes to a workspace or classpath artifact, yet whose name lets an
/// activated authored procedure summary bind (#1978).
///
/// The match identity is `(language, owner FQN, member, arity, has_receiver)`.
/// Parameter types are unrecoverable for an unmaterialized callee, so same-arity
/// overloads that differ only by parameter type cannot be told apart here. The
/// synthetic `locator` -- and the provenance artifact key derived from it -- is
/// not a real source location; it only anchors the bound summary so the boundary
/// and the summary compare equal. The owner FQN and member are stored verbatim
/// so the summary lookup never has to re-parse the locator. Private call-shape
/// authority is validation evidence; authored summary lookup still uses only
/// the documented match identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnmaterializedExternalTarget {
    owner_fqn: Box<str>,
    member: Box<str>,
    arity: u32,
    has_receiver: bool,
    #[doc(hidden)]
    pub resolver_owned_call_shape: bool,
    normalized_static_owner: Option<Box<str>>,
    /// Exact JDK artifact selected for the Java source module and verified
    /// against the selected external declaration. Model and dispatch
    /// applicability still require separate proofs.
    selected_jdk_artifact: Option<SemanticModelActivationEvidence>,
    /// Exact provider inventory row selected by call resolution.
    #[doc(hidden)]
    pub selected_external_descriptor: Option<crate::analyzer::resolution::ExternalMemberIdentity>,
    /// Exact PyPI distribution artifact selected for a Python external
    /// declaration by resolver-owned installed-artifact and active-profile
    /// evidence. Model and dispatch applicability still require separate
    /// proofs.
    #[doc(hidden)]
    pub selected_python_artifact: Option<SemanticModelActivationEvidence>,
    #[doc(hidden)]
    pub selected_python_model_manifest_sha256: Option<Box<str>>,
    /// Declaration formals from the checked Python defining binding. `arity`
    /// stays the actual call arity used by the locator alias.
    #[doc(hidden)]
    pub python_formal_call_shape: Option<PythonFormalCallShape>,
    /// Structured actuals from the exact semantic call. Summary formals use
    /// the shared call-binding slot matcher to produce one retained mapping.
    #[doc(hidden)]
    pub call_arguments: Option<Box<[SemanticCallArgument]>>,
    /// Constructed Python class whose inherited `__init__` this target binds.
    #[doc(hidden)]
    pub python_constructor_class: Option<Box<str>>,
    #[doc(hidden)]
    pub locator: SemanticLocator,
    python_formal_locator: Option<SemanticLocator>,
}

impl UnmaterializedExternalTarget {
    /// Construct a modeled external target from a language adapter's exact
    /// owner/member/receiver proof. The synthetic locator is provenance only;
    /// summary lookup still uses the structured identity carried by the target.
    /// Adapters should add their call-specific arguments when they have them.
    pub fn new_modeled(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        language: SemanticLanguage,
        arity: u32,
        has_receiver: bool,
    ) -> Option<Self> {
        let owner_fqn = owner_fqn.into();
        let member = member.into();
        let anchor = modeled_external_zero_source_anchor();
        let owner_segment =
            DeclarationSegment::named(DeclarationSegmentKind::Type, owner_fqn.clone(), anchor, 0)
                .ok()?;
        let member_kind = if has_receiver {
            DeclarationSegmentKind::Method
        } else {
            DeclarationSegmentKind::Function
        };
        let member_segment =
            DeclarationSegment::named(member_kind, member.clone(), anchor, arity).ok()?;
        let declaration = DeclarationLocator::new(vec![owner_segment, member_segment]).ok()?;
        let declaring_language = match language {
            SemanticLanguage::CppC => SemanticLanguage::Standard(Language::Cpp),
            other => other,
        };
        let locator = SemanticLocator::new(
            unmaterialized_external_mount(),
            unmaterialized_external_path(),
            declaring_language,
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        Some(Self::new_with_normalized_static_owner(
            owner_fqn,
            member,
            arity,
            has_receiver,
            None,
            locator,
        ))
    }

    #[doc(hidden)]
    pub fn new(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        arity: u32,
        has_receiver: bool,
        locator: SemanticLocator,
    ) -> Self {
        Self::new_with_normalized_static_owner(
            owner_fqn,
            member,
            arity,
            has_receiver,
            None,
            locator,
        )
    }

    pub fn new_with_normalized_static_owner(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        arity: u32,
        has_receiver: bool,
        normalized_static_owner: Option<Box<str>>,
        locator: SemanticLocator,
    ) -> Self {
        debug_assert_eq!(locator.role(), SemanticRole::Procedure);
        debug_assert!(is_unmaterialized_external_artifact_locator(&locator));
        let owner_fqn = owner_fqn.into();
        debug_assert!(
            normalized_static_owner
                .as_deref()
                .is_none_or(|owner| owner == owner_fqn.as_ref())
        );
        Self {
            owner_fqn,
            member: member.into(),
            arity,
            has_receiver,
            resolver_owned_call_shape: false,
            normalized_static_owner,
            selected_jdk_artifact: None,
            selected_external_descriptor: None,
            selected_python_artifact: None,
            selected_python_model_manifest_sha256: None,
            python_formal_call_shape: None,
            call_arguments: None,
            python_constructor_class: None,
            python_formal_locator: None,
            locator,
        }
    }

    /// Construct a target whose receiver and arity came from the exact source
    /// resolver rather than syntax-only semantic lowering.
    pub fn new_for_resolver_owned_call(
        owner_fqn: impl Into<Box<str>>,
        member: impl Into<Box<str>>,
        arity: u32,
        has_receiver: bool,
        selected_jdk_artifact: Option<SemanticModelActivationEvidence>,
        locator: SemanticLocator,
    ) -> Self {
        let mut target = Self::new(owner_fqn, member, arity, has_receiver, locator);
        target.resolver_owned_call_shape = true;
        debug_assert!(
            selected_jdk_artifact.is_none()
                || target.language() == SemanticLanguage::Standard(Language::Java)
        );
        debug_assert!(selected_jdk_artifact.as_ref().is_none_or(|evidence| {
            evidence.language == "java"
                && evidence.ecosystem == "jdk"
                && evidence.artifact_sha256.is_some()
        }));
        target.selected_jdk_artifact = selected_jdk_artifact;
        target
    }

    pub fn selected_jdk_artifact(&self) -> Option<&SemanticModelActivationEvidence> {
        self.selected_jdk_artifact.as_ref()
    }

    pub fn selected_python_artifact(&self) -> Option<&SemanticModelActivationEvidence> {
        self.selected_python_artifact.as_ref()
    }

    pub fn with_python_constructor_class(
        mut self,
        class_qualified_name: impl Into<Box<str>>,
    ) -> Option<Self> {
        let class_qualified_name = class_qualified_name.into();
        if self.language().language() != Language::Python
            || self.member() != "__init__"
            || !self.has_receiver()
            || class_qualified_name.is_empty()
            || class_qualified_name == self.owner_fqn
        {
            return None;
        }
        self.python_constructor_class = Some(class_qualified_name);
        Some(self)
    }

    /// Carry exact Python distribution selection to a related modeled target
    /// while leaving its call shape to be established independently.
    pub fn with_python_artifact_selection_from(
        self,
        selected_from: Option<&Self>,
        arguments: &[SemanticCallArgument],
        formals: &[brokk_bifrost_semantic::analyzer::semantic::lexical_definitions::FormalParameterSlot],
    ) -> Option<Self> {
        let (evidence, manifest) = match selected_from.map(|selected_from| {
            (
                selected_from.selected_python_artifact.as_ref(),
                selected_from
                    .selected_python_model_manifest_sha256
                    .as_deref(),
            )
        }) {
            None => (None, None),
            Some((Some(evidence), Some(manifest))) => (Some(evidence), Some(manifest)),
            Some((None, None)) => (None, None),
            Some(_) => return None,
        };
        self.with_python_artifact_selection_and_call_shape(evidence, manifest, arguments, formals)
    }

    /// Attach artifact evidence selected from an exact active Python model
    /// declaration and bind this related call against that declaration's
    /// formals.
    pub fn with_python_artifact_selection(
        self,
        evidence: &SemanticModelActivationEvidence,
        manifest: &str,
        arguments: &[SemanticCallArgument],
        formals: &[brokk_bifrost_semantic::analyzer::semantic::lexical_definitions::FormalParameterSlot],
    ) -> Option<Self> {
        self.with_python_artifact_selection_and_call_shape(
            Some(evidence),
            Some(manifest),
            arguments,
            formals,
        )
    }

    fn with_python_artifact_selection_and_call_shape(
        mut self,
        evidence: Option<&SemanticModelActivationEvidence>,
        manifest: Option<&str>,
        arguments: &[SemanticCallArgument],
        formals: &[brokk_bifrost_semantic::analyzer::semantic::lexical_definitions::FormalParameterSlot],
    ) -> Option<Self> {
        assert_eq!(
            self.language(),
            SemanticLanguage::Standard(Language::Python)
        );
        let (evidence, manifest) = match (evidence, manifest) {
            (None, None) => (None, None),
            (Some(evidence), Some(manifest)) => {
                if evidence.language != "python"
                    || evidence.ecosystem != "python"
                    || evidence.package.is_none()
                    || evidence.artifact_sha256.is_none()
                    || manifest.is_empty()
                {
                    return None;
                }
                let mut artifact_key = b"bifrost.python-runtime-target.v2\0".to_vec();
                for component in [
                    evidence.package.as_ref()?.name.as_bytes(),
                    evidence.artifact_sha256.as_ref()?.as_bytes(),
                    manifest.as_bytes(),
                ] {
                    artifact_key.extend_from_slice(&(component.len() as u64).to_le_bytes());
                    artifact_key.extend_from_slice(component);
                }
                let mut segments = self.locator.declaration().segments().to_vec();
                segments.insert(
                    0,
                    DeclarationSegment::named(
                        crate::analyzer::semantic::ids::DeclarationSegmentKind::Namespace,
                        format!(
                            "bifrost.python-artifact.{}",
                            crate::analyzer::canonical_hash::lower_hex_string(
                                &crate::analyzer::canonical_hash::sha256_bytes(&artifact_key)
                            )
                        ),
                        self.locator.anchor(),
                        0,
                    )
                    .ok()?,
                );
                self.locator = SemanticLocator::new(
                    self.locator.mount(),
                    self.locator.path().clone(),
                    self.locator.language(),
                    DeclarationLocator::new(segments).ok()?,
                    self.locator.role(),
                    self.locator.anchor(),
                );
                (Some(evidence.clone()), Some(Box::<str>::from(manifest)))
            }
            _ => return None,
        };
        let formal_parameter_count = u32::try_from(formals.len()).ok()?;
        let defaulted_formals = formals
            .iter()
            .map(|formal| formal.default_range.is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let variadic_formals = formals
            .iter()
            .map(|formal| formal.variadic.is_some())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let actual_to_formal = python_actual_to_formal_slots(arguments, formals);
        self.resolver_owned_call_shape = true;
        self.qualify_python_argument_mapping(formal_parameter_count, actual_to_formal.as_deref());
        self.selected_python_artifact = evidence;
        self.selected_python_model_manifest_sha256 = manifest;
        self.python_formal_call_shape = Some(PythonFormalCallShape {
            formal_parameter_count,
            defaulted_formals,
            variadic_formals,
            actual_to_formal,
        });
        self.call_arguments = Some(arguments.to_vec().into_boxed_slice());
        Some(self)
    }

    pub fn with_call_arguments(mut self, arguments: &[SemanticCallArgument]) -> Self {
        self.call_arguments = Some(arguments.to_vec().into_boxed_slice());
        self
    }

    #[doc(hidden)]
    pub fn qualify_python_argument_mapping(
        &mut self,
        formal_parameter_count: u32,
        actual_to_formal: Option<&[u32]>,
    ) {
        self.python_formal_locator = Some(self.locator.clone());
        if let Some(mapping) = actual_to_formal {
            // Call-specific argument order is part of the target alias, while
            // the shared summary remains anchored to its formal declaration.
            let mut bytes = b"bifrost.python-call-mapping.v1\0".to_vec();
            bytes.extend_from_slice(&formal_parameter_count.to_le_bytes());
            for formal in mapping {
                bytes.extend_from_slice(&formal.to_le_bytes());
            }
            let mut segments = self.locator.declaration().segments().to_vec();
            segments.insert(
                0,
                DeclarationSegment::named(
                    crate::analyzer::semantic::ids::DeclarationSegmentKind::Namespace,
                    format!(
                        "bifrost.python-call-mapping.{}",
                        crate::analyzer::canonical_hash::lower_hex_string(
                            &crate::analyzer::canonical_hash::sha256_bytes(&bytes)
                        )
                    ),
                    self.locator.anchor(),
                    0,
                )
                .expect("mapping digest namespace is nonempty"),
            );
            self.locator = SemanticLocator::new(
                self.locator.mount(),
                self.locator.path().clone(),
                self.locator.language(),
                DeclarationLocator::new(segments).expect("mapped target preserves declaration"),
                self.locator.role(),
                self.locator.anchor(),
            );
        }
    }

    pub fn python_formal_parameter_count(&self) -> Option<u32> {
        self.python_formal_call_shape
            .as_ref()
            .map(|shape| shape.formal_parameter_count)
    }

    pub fn python_formal_call_shape_accepts_arity(&self, arity: u32) -> Option<bool> {
        self.python_formal_call_shape
            .as_ref()
            .map(|shape| shape.accepts_arity(arity))
    }

    pub fn call_arguments(&self) -> Option<&[SemanticCallArgument]> {
        self.call_arguments.as_deref()
    }

    pub fn python_actual_to_formal(&self) -> Option<&[u32]> {
        self.python_formal_call_shape
            .as_ref()
            .and_then(|shape| shape.actual_to_formal.as_deref())
    }

    pub fn python_defaulted_formals(&self) -> Option<&[bool]> {
        self.python_formal_call_shape
            .as_ref()
            .map(|shape| shape.defaulted_formals.as_ref())
    }

    pub fn formal_summary_locator(&self, arity: u32) -> SemanticLocator {
        let Some(formal) = &self.python_formal_locator else {
            return self.locator_for_arity(arity);
        };
        let mut target = self.clone();
        target.locator = formal.clone();
        target.locator_for_arity(arity)
    }

    pub fn selected_python_model_manifest_sha256(&self) -> Option<&str> {
        self.selected_python_model_manifest_sha256.as_deref()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_python_model_manifest_for_test(mut self, manifest: &str) -> Self {
        self.selected_python_model_manifest_sha256 = Some(manifest.into());
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_selected_python_for_test(
        mut self,
        evidence: SemanticModelActivationEvidence,
    ) -> Self {
        assert_eq!(
            self.language(),
            SemanticLanguage::Standard(Language::Python)
        );
        self.resolver_owned_call_shape = true;
        self.selected_python_artifact = Some(evidence);
        self.python_formal_call_shape = Some(PythonFormalCallShape {
            formal_parameter_count: self.arity,
            defaulted_formals: vec![false; self.arity as usize].into_boxed_slice(),
            variadic_formals: vec![false; self.arity as usize].into_boxed_slice(),
            actual_to_formal: Some((0..self.arity).collect()),
        });
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_python_formal_shape_for_test(
        mut self,
        evidence: SemanticModelActivationEvidence,
        formal_parameter_count: u32,
        required_parameter_count: u32,
    ) -> Self {
        assert_eq!(
            self.language(),
            SemanticLanguage::Standard(Language::Python)
        );
        assert!(required_parameter_count <= formal_parameter_count);
        self.resolver_owned_call_shape = true;
        self.selected_python_artifact = Some(evidence);
        self.python_formal_call_shape = Some(PythonFormalCallShape {
            formal_parameter_count,
            defaulted_formals: (0..formal_parameter_count)
                .map(|formal| formal >= required_parameter_count)
                .collect(),
            variadic_formals: vec![false; formal_parameter_count as usize].into_boxed_slice(),
            actual_to_formal: Some((0..self.arity).collect()),
        });
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_python_mapping_for_test(mut self, mapping: Option<Vec<u32>>) -> Self {
        let count = self
            .python_formal_parameter_count()
            .expect("test has formal shape");
        self.qualify_python_argument_mapping(count, mapping.as_deref());
        self.python_formal_call_shape
            .as_mut()
            .expect("test has formal shape")
            .actual_to_formal = mapping.map(Vec::into_boxed_slice);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_selected_jdk_for_test(mut self, evidence: SemanticModelActivationEvidence) -> Self {
        assert_eq!(self.language(), SemanticLanguage::Standard(Language::Java));
        assert_eq!(evidence.ecosystem, "jdk");
        assert!(evidence.artifact_sha256.is_some());
        self.resolver_owned_call_shape = true;
        self.selected_jdk_artifact = Some(evidence);
        self
    }

    pub fn owner_fqn(&self) -> &str {
        &self.owner_fqn
    }

    pub fn member(&self) -> &str {
        &self.member
    }

    pub const fn arity(&self) -> u32 {
        self.arity
    }

    pub const fn has_receiver(&self) -> bool {
        self.has_receiver
    }

    /// Whether structured language resolution proved that this receiverless
    /// external call is statically selected. A resolver-owned proof has an
    /// exact owner, member, application, and arity, so a receiverless external
    /// callable cannot select an override.
    pub fn resolver_proves_static_call(&self) -> bool {
        if self.has_receiver {
            return false;
        }
        // A receiverless callee the resolver identified through an external
        // declaration and its exact call shape is a free function: nothing
        // dispatches it dynamically. C header functions and Rust external
        // crate functions use this proof; Python and Java also use it for
        // their resolver-owned imported declarations. C# type-qualified calls
        // use the same proof after the declaration overlay establishes that
        // the selected member is static.
        if self.resolver_owned_call_shape
            && matches!(
                self.language(),
                SemanticLanguage::Standard(
                    Language::CSharp
                        | Language::Cpp
                        | Language::Python
                        | Language::Java
                        | Language::Rust
                        | Language::Go,
                )
            )
        {
            return true;
        }
        match self.language() {
            SemanticLanguage::Standard(Language::Java) => self
                .normalized_static_owner
                .as_deref()
                .is_some_and(|owner| owner == self.owner_fqn.as_ref()),
            _ => false,
        }
    }

    pub const fn has_resolver_owned_call_shape(&self) -> bool {
        self.resolver_owned_call_shape
    }

    pub fn normalized_static_owner(&self) -> Option<&str> {
        self.normalized_static_owner.as_deref()
    }

    pub fn language(&self) -> SemanticLanguage {
        self.locator.language()
    }

    /// The synthetic procedure locator that both the boundary (at solve time) and
    /// the bound summary (at discovery time) name, so the two compare equal.
    pub fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    /// Rebuild this canonical external declaration locator with a different
    /// structured arity. Variadic semantic targets use their total formal
    /// count for the summary's stable declaration identity while retaining the
    /// resolver's actual-arity locators as exact lookup aliases.
    pub fn locator_for_arity(&self, arity: u32) -> SemanticLocator {
        let mut segments = self.locator.declaration().segments().to_vec();
        let last = segments
            .pop()
            .expect("unmaterialized external locator has a member segment");
        debug_assert_eq!(last.name(), Some(self.member()));
        segments.push(
            DeclarationSegment::named(last.kind(), self.member(), last.anchor(), arity)
                .expect("unmaterialized external member name remains non-empty"),
        );
        SemanticLocator::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            DeclarationLocator::new(segments)
                .expect("unmaterialized external declaration remains non-empty"),
            SemanticRole::Procedure,
            self.locator.anchor(),
        )
    }

    /// Build the provenance artifact key that anchors the bound summary. It
    /// reuses the synthetic mount, path, and language of `locator` -- so
    /// `ExternalSummaryTarget::matches(self.locator())` succeeds -- and copies the
    /// caller-analysis validity fields from `template` so the bound summary's
    /// dependency fingerprint matches the active compatibility key.
    pub fn provenance_artifact_key(&self, template: &SemanticArtifactKey) -> SemanticArtifactKey {
        SemanticArtifactKey::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            template.revision(),
            template.adapter().clone(),
            template.ir_version(),
            template.configuration(),
            template.dependencies(),
        )
    }
}
