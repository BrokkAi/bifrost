use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    ActivationSelector, CatalogCoordinate, CatalogMiss, CatalogPackSourceKind,
    CompiledConditionalResultRefinement, CompiledDeclaredEffect, CompiledNormalReturnRefinement,
    CompiledOperationPrecondition, CompiledPackManifest, CompiledProcedureSummary,
    CompiledProcedureTarget, CompiledResultContract, CompiledShard, DeclarationGuard,
    GeneratorRule, MemberFact, PayloadKind, RelationFact, RuleTrigger, SemanticModelOverlay,
    SemanticModelOverlayBuildError, SemanticPackCatalog, SemanticPackSelectorQuery, TypeFact,
};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::{is_lower_sha256, parse_lower_sha256};
use crate::analyzer::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};
use crate::analyzer::semantic::{
    SemanticLocator, StableDigest, UnmaterializedExternalTarget, split_qualified_member,
};
use crate::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
};
use crate::analyzer::{IAnalyzer, Language, LanguageDialect};
use crate::hash::{HashMap, map_with_capacity};

pub const SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION: u32 = 2;

type DependencyEvidencePublication = (Box<[Language]>, super::DependencyDiscoveryEvidence);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticModelActivationEvidence {
    pub language: String,
    pub ecosystem: String,
    pub package: Option<CatalogCoordinate>,
    pub module: Option<CatalogCoordinate>,
    pub toolchain: Option<CatalogCoordinate>,
    pub target: Option<String>,
    pub configuration: Option<String>,
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticModelControlScope {
    User,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticModelControlAction {
    Enable,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticModelPackSelector {
    pub pack_id: String,
    pub version: Option<VersionReq>,
    pub manifest_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticModelActivationControl {
    pub scope: SemanticModelControlScope,
    pub action: SemanticModelControlAction,
    pub selector: SemanticModelPackSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticModelRuntimeLimits {
    pub max_evidence_rows: usize,
    pub max_controls: usize,
    pub max_catalog_candidates: usize,
    pub max_loaded_shards: usize,
    pub max_records: usize,
    pub max_index_entries: usize,
    pub max_working_bytes: u64,
    pub max_retained_bytes: u64,
    pub max_explanations: usize,
}

impl Default for SemanticModelRuntimeLimits {
    fn default() -> Self {
        Self {
            max_evidence_rows: 4_096,
            max_controls: 4_096,
            max_catalog_candidates: 65_536,
            max_loaded_shards: 16_384,
            max_records: 4_000_000,
            max_index_entries: 16_000_000,
            max_working_bytes: 1 << 30,
            max_retained_bytes: 1 << 30,
            max_explanations: 65_536,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SemanticModelActivationRequest {
    pub bifrost_version: Version,
    pub evidence: Vec<SemanticModelActivationEvidence>,
    pub controls: Vec<SemanticModelActivationControl>,
    pub limits: SemanticModelRuntimeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelActivationStatus {
    Active,
    Disabled,
    Incompatible,
    ReviewRequired,
    Shadowed,
    Conflict,
    Unavailable,
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelActivationPhaseMeasurements {
    pub selection_nanos: u64,
    pub decode_hydration_nanos: u64,
    pub matcher_construction_nanos: u64,
    pub catalog_sql_statements: u64,
}

#[derive(Debug)]
pub struct ActiveSemanticModelShard {
    pub manifest: CompiledPackManifest,
    pub shard: CompiledShard,
    pub source_kind: CatalogPackSourceKind,
    pub source_id: String,
    pub matched_evidence: SemanticModelActivationEvidence,
    evidence_rank: EvidenceRank,
    source_rank: u8,
}

impl ActiveSemanticModelShard {
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
    active_model_set_hash: String,
    shards: Vec<ActiveSemanticModelShard>,
    indexes: MatcherIndexes,
    extraction_gaps: Vec<ActivePackExtractionGap>,
    extraction_gaps_by_declaration: HashMap<String, Vec<usize>>,
    report: SemanticModelActivationReport,
}

/// One immutable semantic-model publication captured under the runtime's
/// publication lock.
///
/// The declaration overlay is derived from `active_models`. Keeping the pair
/// in one owned value prevents a request from combining one activation's
/// procedure summaries with a later activation's declaration resolver.
#[derive(Debug)]
pub struct ActiveSemanticModelSnapshot {
    active_models: Arc<ResolvedActiveSemanticModels>,
    semantic_model_overlay: Option<Arc<SemanticModelOverlay>>,
}

impl ActiveSemanticModelSnapshot {
    fn new(
        active_models: Arc<ResolvedActiveSemanticModels>,
        semantic_model_overlay: Option<Arc<SemanticModelOverlay>>,
    ) -> Self {
        Self {
            active_models,
            semantic_model_overlay,
        }
    }

    pub fn active_models(&self) -> &Arc<ResolvedActiveSemanticModels> {
        &self.active_models
    }

    pub fn semantic_model_overlay(&self) -> Option<&Arc<SemanticModelOverlay>> {
        self.semantic_model_overlay.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePackExtractionGap {
    pub pack_id: String,
    pub declaration: String,
    pub reason: String,
}

impl ResolvedActiveSemanticModels {
    pub fn active_model_set_hash(&self) -> &str {
        &self.active_model_set_hash
    }

    pub fn shards(&self) -> &[ActiveSemanticModelShard] {
        &self.shards
    }

    pub fn activation_report(&self) -> &SemanticModelActivationReport {
        &self.report
    }

    pub fn extraction_gaps(&self) -> &[ActivePackExtractionGap] {
        &self.extraction_gaps
    }

    pub fn gapped(&self, declaration: &str) -> Option<&ActivePackExtractionGap> {
        self.extraction_gaps_by_declaration
            .get(declaration)
            .and_then(|indexes| indexes.first())
            .map(|index| &self.extraction_gaps[*index])
    }

    pub fn gapped_member_surface(
        &self,
        owner: &str,
        member: &str,
    ) -> Option<&ActivePackExtractionGap> {
        let member_declaration = format!("{owner}.{member}");
        self.gapped(&member_declaration)
            .or_else(|| self.gapped(owner))
    }

    pub fn retained_bytes(&self) -> u64 {
        self.report.retained_bytes
    }

    pub fn types_with_id(&self, id: &str) -> SemanticModelMatch<'_, TypeFact> {
        self.type_match(self.indexes.types_by_id.get(id))
    }

    pub fn types_named(&self, name: &str) -> SemanticModelMatch<'_, TypeFact> {
        self.type_match(self.indexes.types_by_name.get(name))
    }

    pub fn members_with_id(&self, id: &str) -> SemanticModelMatch<'_, MemberFact> {
        self.member_match(self.indexes.members_by_id.get(id))
    }

    pub fn members_named(&self, owner: &str, name: &str) -> SemanticModelMatch<'_, MemberFact> {
        self.member_match(
            self.indexes
                .members_by_owner_name
                .get(owner)
                .and_then(|names| names.get(name)),
        )
    }

    pub fn relations_with_id(&self, id: &str) -> SemanticModelMatch<'_, RelationFact> {
        self.relation_match(self.indexes.relations_by_id.get(id))
    }

    pub fn relations_from(&self, from: &str) -> SemanticModelMatch<'_, RelationFact> {
        self.relation_match(self.indexes.relations_by_from.get(from))
    }

    pub fn relations_to(&self, to: &str) -> SemanticModelMatch<'_, RelationFact> {
        self.relation_match(self.indexes.relations_by_to.get(to))
    }

    pub fn rules_for(&self, trigger: RuleTriggerKey<'_>) -> SemanticModelMatch<'_, GeneratorRule> {
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
        self.rule_match(posting)
    }

    pub fn rules_with_id(&self, id: &str) -> SemanticModelMatch<'_, GeneratorRule> {
        self.rule_match(self.indexes.rules_by_id.get(id))
    }

    pub fn procedure_summaries_for(
        &self,
        target: ProcedureSummaryTargetKey<'_>,
    ) -> ProcedureSummaryMatch<'_> {
        let shapes = self
            .indexes
            .procedure_summaries_by_target
            .get(target.language)
            .and_then(|paths| paths.get(target.path))
            .and_then(|symbols| symbols.get(target.symbol));
        resolve_exact_procedure_postings(
            &self.shards,
            shapes,
            target.has_receiver,
            target.parameter_count,
        )
    }

    /// Select an activated summary for an unmaterialized external callee by its
    /// canonical identity (#1978).
    pub fn procedure_summaries_for_member(
        &self,
        target: ProcedureSummaryMemberKey<'_>,
    ) -> ProcedureSummaryMatch<'_> {
        let shapes = self
            .indexes
            .procedure_summaries_by_member
            .get(target.language)
            .and_then(|owners| owners.get(target.owner))
            .and_then(|members| members.get(target.member));
        resolve_applicable_procedure_postings(
            &self.shards,
            shapes,
            target.has_receiver,
            target.parameter_count,
        )
    }

    /// Whether this active set has any member whose exact matcher behavior can
    /// prove an absent normal continuation for at least one call arity.
    ///
    /// This is a discovery hint only. A consumer must still call
    /// [`Self::proves_normal_continuation_absent`] for the exact owner and
    /// actual arity before changing control flow.
    pub fn has_normal_continuation_absence_candidates(&self, language: &str) -> bool {
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
    ) -> &[String] {
        self.indexes
            .normal_continuation_absence_candidates
            .owners(language, member, has_receiver)
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
    pub(crate) fn has_receiverless_procedure_summary_member(
        &self,
        language: &str,
        owner: &str,
        member: &str,
    ) -> bool {
        self.indexes
            .procedure_summaries_by_member
            .get(language)
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

    fn type_match(&self, posting: Option<&Vec<RecordAddress>>) -> SemanticModelMatch<'_, TypeFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .shard
                .payload()
                .declaration_facts()
                .and_then(|(types, _, _)| types.get(record))
        })
    }

    fn member_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<'_, MemberFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .shard
                .payload()
                .declaration_facts()
                .and_then(|(_, members, _)| members.get(record))
        })
    }

    fn relation_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<'_, RelationFact> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard
                .shard
                .payload()
                .declaration_facts()
                .and_then(|(_, _, relations)| relations.get(record))
        })
    }

    fn rule_match(
        &self,
        posting: Option<&Vec<RecordAddress>>,
    ) -> SemanticModelMatch<'_, GeneratorRule> {
        resolve_posting(&self.shards, posting, |shard, record| {
            shard.shard.payload().generator_rules()?.get(record)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelMatchDisposition {
    Empty,
    Unique,
    Conflict,
}

#[derive(Debug)]
pub struct SemanticModelMatch<'a, T> {
    pub records: Vec<ActivatedSemanticModelRecord<'a, T>>,
    pub disposition: SemanticModelMatchDisposition,
    pub candidates_examined: usize,
    pub fallback_candidates_examined: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ActivatedSemanticModelRecord<'a, T> {
    pub record: &'a T,
    pub shard: &'a ActiveSemanticModelShard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureSummaryTargetKey<'a> {
    pub language: &'a str,
    pub path: &'a str,
    pub symbol: &'a str,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

impl<'a> ProcedureSummaryTargetKey<'a> {
    pub fn new(
        language: &'a str,
        path: &'a str,
        symbol: &'a str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> Self {
        Self {
            language,
            path,
            symbol,
            has_receiver,
            parameter_count,
        }
    }
}

/// Canonical-identity lookup key for a fully-qualified external callee that never
/// materializes to an artifact (#1978). It selects an activated summary by owner
/// FQN and member name rather than by artifact path and parameter-typed symbol,
/// which an unmaterialized callee cannot present. `parameter_count` is the arity;
/// a fixed target must have exactly that many formals, while a variadic target
/// matches when the call has at least its non-variadic formal count. Same-arity
/// overloads that differ only by parameter type are indistinguishable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureSummaryMemberKey<'a> {
    pub language: &'a str,
    pub owner: &'a str,
    pub member: &'a str,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

impl<'a> ProcedureSummaryMemberKey<'a> {
    pub fn new(
        language: &'a str,
        owner: &'a str,
        member: &'a str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> Self {
        Self {
            language,
            owner,
            member,
            has_receiver,
            parameter_count,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ActivatedProcedureSummary<'a> {
    pub record: &'a CompiledProcedureSummary,
    pub shard: &'a ActiveSemanticModelShard,
    pub payload: &'a [CompiledProcedureSummary],
}

/// Analyzer-minted evidence that one activated authored summary applies to one
/// exact unmaterialized-external call shape.
///
/// The fields stay private so a downstream consumer cannot relabel a fixed
/// summary by manufacturing another actual arity. Flow may derive its own
/// internal summary identity from the proven formal locator and model id, then
/// must still check that identity against the lowered summary it publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmaterializedExternalSummaryCallShapeBinding {
    actual_locator: SemanticLocator,
    formal_locator: SemanticLocator,
    model_id: Box<str>,
    content: StableDigest,
    contract_version: u32,
    covers_overrides: bool,
}

impl UnmaterializedExternalSummaryCallShapeBinding {
    pub fn actual_locator(&self) -> &SemanticLocator {
        &self.actual_locator
    }

    pub fn formal_locator(&self) -> &SemanticLocator {
        &self.formal_locator
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub const fn content(&self) -> StableDigest {
        self.content
    }

    pub const fn contract_version(&self) -> u32 {
        self.contract_version
    }

    pub const fn covers_overrides(&self) -> bool {
        self.covers_overrides
    }
}

impl<'a> ActivatedProcedureSummary<'a> {
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
            || self.shard.manifest.language != target.language().semantic_pack_label()
            || self.record.target.has_receiver != target.has_receiver()
            || !self.record.target.accepts_parameter_count(target.arity())
            || target.locator_for_arity(target.arity()) != *target.locator()
            || split_qualified_member(&self.record.target.symbol)
                != Some((target.owner_fqn(), target.member()))
        {
            return None;
        }
        Some(UnmaterializedExternalSummaryCallShapeBinding {
            actual_locator: target.locator().clone(),
            formal_locator: target.locator_for_arity(self.record.target.parameter_count),
            model_id: self.record.model_id.clone().into_boxed_str(),
            content: StableDigest::from_array(content),
            contract_version: self.record.contract_version,
            covers_overrides: self.record.covers_overrides,
        })
    }

    pub fn summary_with_id(&self, id: &str) -> Option<&'a CompiledProcedureSummary> {
        self.payload.iter().find(|summary| summary.id == id)
    }

    /// Whether this exact activated record explicitly claims that no normal
    /// continuation exists.
    pub const fn normal_continuation_absent(&self) -> bool {
        self.record.normal_continuation_absent
    }

    /// The namespaced effects the activated pack declares for this procedure
    /// (#2437), in the compiler's canonical order (sorted by id).
    pub fn declared_effects(&self) -> &'a [CompiledDeclaredEffect] {
        &self.record.declared_effects
    }

    /// Reviewed predicates required of this exact procedure invocation's
    /// receiver and parameters. `None` means the operation was not reviewed;
    /// `Some([])` means it was reviewed and has no input preconditions.
    pub fn preconditions(&self) -> Option<&'a [CompiledOperationPrecondition]> {
        self.record.preconditions.as_deref()
    }

    /// The reviewed relationships among this procedure's normal result ports,
    /// in deterministic ordinal order.
    pub fn result_contracts(&self) -> &'a [CompiledResultContract] {
        &self.record.result_contracts
    }

    /// Outcome-sensitive predicate effects this reviewed summary attributes to
    /// its boolean normal results.
    pub fn conditional_result_refinements(&self) -> &'a [CompiledConditionalResultRefinement] {
        &self.record.conditional_result_refinements
    }

    /// Predicates this reviewed summary establishes for actual arguments on
    /// the call's normal continuation.
    pub fn normal_return_refinements(&self) -> &'a [CompiledNormalReturnRefinement] {
        &self.record.normal_return_refinements
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
    ) -> super::SemanticModelProvenance {
        let mut provenance =
            super::overlay::activated_record_provenance(active, self.shard, &self.record.id);
        provenance.completeness = match self.record.completeness {
            super::Completeness::Partial => super::SemanticModelCompleteness::Partial,
            super::Completeness::Complete => super::SemanticModelCompleteness::Complete,
        };
        provenance
    }
}

#[derive(Debug)]
pub struct ProcedureSummaryMatch<'a> {
    pub records: Vec<ActivatedProcedureSummary<'a>>,
    pub disposition: SemanticModelMatchDisposition,
    pub candidates_examined: usize,
    pub fallback_candidates_examined: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTriggerKey<'a> {
    LanguageConstruct(&'a str),
    Annotation(&'a str),
    MacroInvocation(&'a str),
    GeneratorInvocation(&'a str),
    ResolvedOwner(&'a str),
    ResolvedCall { owner: &'a str, name: &'a str },
}

#[derive(Debug, Clone, Copy)]
struct RecordAddress {
    shard: u32,
    record: u32,
}

#[derive(Debug, Default)]
struct ProcedureSummaryShapePostings {
    fixed: HashMap<(bool, u32), Vec<RecordAddress>>,
    /// Variadic postings are keyed by total formal count, including the final
    /// variadic formal. Ordered storage makes the applicable-prefix scan both
    /// bounded by the number of authored shapes and deterministic.
    variadic: BTreeMap<(bool, u32), Vec<RecordAddress>>,
    /// Coarse construction hint, split by receiver shape. A true bit says only
    /// that some indexed record authored the claim; matcher precedence and
    /// conflicts still decide the effective candidate index below.
    raw_normal_continuation_absence_claim: [bool; 2],
}

type ProcedureSummaryTargetPostings =
    HashMap<String, HashMap<String, HashMap<String, ProcedureSummaryShapePostings>>>;

#[derive(Debug, Default)]
struct NormalContinuationAbsenceMemberCandidates {
    receiverless_owners: Vec<String>,
    receiver_owners: Vec<String>,
}

impl NormalContinuationAbsenceMemberCandidates {
    fn owners(&self, has_receiver: bool) -> &[String] {
        if has_receiver {
            &self.receiver_owners
        } else {
            &self.receiverless_owners
        }
    }

    fn owners_mut(&mut self, has_receiver: bool) -> &mut Vec<String> {
        if has_receiver {
            &mut self.receiver_owners
        } else {
            &mut self.receiverless_owners
        }
    }
}

/// Reusable discovery candidates derived from effective matcher behavior.
///
/// The index deliberately stops at owner/name/receiver. Exact actual arities
/// remain runtime lookups, avoiding an unbounded variadic-arity cache.
#[derive(Debug, Default)]
struct NormalContinuationAbsenceCandidateIndex {
    by_language: HashMap<String, HashMap<String, NormalContinuationAbsenceMemberCandidates>>,
}

impl NormalContinuationAbsenceCandidateIndex {
    fn has_language(&self, language: &str) -> bool {
        self.by_language
            .get(language)
            .is_some_and(|members| !members.is_empty())
    }

    fn owners(&self, language: &str, member: &str, has_receiver: bool) -> &[String] {
        self.by_language
            .get(language)
            .and_then(|members| members.get(member))
            .map(|candidates| candidates.owners(has_receiver))
            .unwrap_or_default()
    }
}

#[derive(Debug, Default)]
struct MatcherIndexes {
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
    fn build(
        active: &[ActiveSemanticModelShard],
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
            let shard_index = u32::try_from(shard_index)
                .map_err(|_| "semantic-model shard address exceeds u32".to_owned())?;
            if let Some((types, members, relations)) =
                active_shard.shard.payload().declaration_facts()
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
            if let Some(rules) = active_shard.shard.payload().generator_rules() {
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
            if let Some(summaries) = active_shard.shard.payload().procedure_summaries() {
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
                        .entry(active_shard.manifest.language.clone())
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
                    // parameter-typed symbol -- can still find this summary.
                    if let Some((owner, member)) = split_qualified_member(&summary.target.symbol) {
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
                            .entry(active_shard.manifest.language.clone())
                            .or_default();
                        let members = owners.entry(owner.to_owned()).or_default();
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
                total.checked_add(
                    active_shard
                        .manifest
                        .shards
                        .iter()
                        .find(|descriptor| descriptor.shard_id == active_shard.shard.shard_id())?
                        .raw_size,
                )
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

fn record_address(shard: u32, record: usize) -> Result<RecordAddress, String> {
    Ok(RecordAddress {
        shard,
        record: u32::try_from(record)
            .map_err(|_| "semantic-model record address exceeds u32".to_owned())?,
    })
}

fn poll_matcher_cancellation(
    cancellation: &CancellationToken,
    records_visited: usize,
) -> Result<(), String> {
    if records_visited.is_multiple_of(1_024) && cancellation.is_cancelled() {
        return Err("semantic-model matcher construction cancelled".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
enum EffectiveProcedureClaims {
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
    fn absorb(&mut self, active: &[ActiveSemanticModelShard], address: RecordAddress) {
        let shard = &active[address.shard as usize];
        let rank = (shard.evidence_rank, shard.source_rank);
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
                    if !procedure_claims_agree(
                        indexed_procedure_summary(active, representative),
                        indexed_procedure_summary(active, address),
                    ) {
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

    fn proves_normal_continuation_absent(self, active: &[ActiveSemanticModelShard]) -> bool {
        matches!(
            self,
            Self::Unique { representative, .. }
                if indexed_procedure_summary(active, representative).normal_continuation_absent
        )
    }
}

fn indexed_procedure_summary(
    active: &[ActiveSemanticModelShard],
    address: RecordAddress,
) -> &CompiledProcedureSummary {
    active[address.shard as usize]
        .shard
        .payload()
        .procedure_summaries()
        .expect("procedure-summary index address must resolve to its payload kind")
        .get(address.record as usize)
        .expect("procedure-summary index address must resolve to its record")
}

fn absorb_procedure_posting(
    effective: &mut EffectiveProcedureClaims,
    active: &[ActiveSemanticModelShard],
    posting: &[RecordAddress],
    cancellation: &CancellationToken,
    addresses_visited: &mut usize,
) -> Result<(), String> {
    for &address in posting {
        poll_matcher_cancellation(cancellation, *addresses_visited)?;
        *addresses_visited = (*addresses_visited).saturating_add(1);
        effective.absorb(active, address);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_normal_continuation_absence_candidates(
    active: &[ActiveSemanticModelShard],
    postings: &ProcedureSummaryTargetPostings,
    cancellation: &CancellationToken,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
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
                    // begins at F-1 and remains applicable. The candidate set
                    // can therefore change only at each fixed A, immediately
                    // after it disappears, or at a variadic minimum.
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
                    for &(receiver, formal_count) in shapes.variadic.keys() {
                        if receiver != has_receiver {
                            continue;
                        }
                        assert!(
                            formal_count > 0,
                            "validated variadic summaries declare their final formal"
                        );
                        representative_arities.push(formal_count - 1);
                    }
                    representative_arities.sort_unstable();
                    representative_arities.dedup();

                    // Sorting the shape boundaries costs O(S log S). The
                    // merge below then visits every applicable variadic and
                    // fixed posting address once, rather than rescanning the
                    // full variadic prefix at every boundary.
                    let mut variadic_postings = shapes
                        .variadic
                        .range((has_receiver, 1)..=(has_receiver, u32::MAX))
                        .peekable();
                    let mut effective_variadic = EffectiveProcedureClaims::default();
                    let mut effective = false;
                    for arity in representative_arities {
                        poll_matcher_cancellation(cancellation, 0)?;
                        let maximum_variadic_formals = arity.saturating_add(1);
                        while let Some((shape, _posting)) = variadic_postings.peek() {
                            if shape.1 > maximum_variadic_formals {
                                break;
                            }
                            let (_shape, posting) = variadic_postings
                                .next()
                                .expect("peeked variadic posting must remain available");
                            absorb_procedure_posting(
                                &mut effective_variadic,
                                active,
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
                            absorb_procedure_posting(
                                &mut effective_at_arity,
                                active,
                                posting,
                                cancellation,
                                &mut addresses_visited,
                            )?;
                        }
                        if effective_at_arity.proves_normal_continuation_absent(active) {
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
fn insert_posting<K: Eq + std::hash::Hash>(
    map: &mut HashMap<K, Vec<RecordAddress>>,
    key: K,
    key_bytes: usize,
    address: RecordAddress,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    charge_posting_entry(key_bytes, entries, working_bytes, limits)?;
    map.entry(key).or_default().push(address);
    Ok(())
}

fn charge_posting_entry(
    key_bytes: usize,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    charge_index_entry(
        key_bytes
            .saturating_add(size_of::<RecordAddress>())
            .saturating_add(32),
        entries,
        working_bytes,
        limits,
    )
}

fn charge_index_entry(
    retained_bytes: usize,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    *entries = entries
        .checked_add(1)
        .ok_or_else(|| "semantic-model index-entry accounting overflowed".to_owned())?;
    if *entries > limits.max_index_entries {
        return Err("semantic-model index-entry budget exceeded".to_owned());
    }
    *working_bytes = working_bytes
        .checked_add(retained_bytes as u64)
        .ok_or_else(|| "semantic-model working-byte accounting overflowed".to_owned())?;
    if *working_bytes > limits.max_working_bytes {
        return Err("semantic-model working-byte budget exceeded".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_procedure_posting(
    shapes: &mut ProcedureSummaryShapePostings,
    target: &CompiledProcedureTarget,
    key_bytes: usize,
    address: RecordAddress,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    let key = (target.has_receiver, target.parameter_count);
    if target.variadic {
        charge_posting_entry(key_bytes, entries, working_bytes, limits)?;
        shapes.variadic.entry(key).or_default().push(address);
        Ok(())
    } else {
        insert_posting(
            &mut shapes.fixed,
            key,
            key_bytes,
            address,
            entries,
            working_bytes,
            limits,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_member_name(
    map: &mut HashMap<String, HashMap<String, Vec<RecordAddress>>>,
    fact: &MemberFact,
    name: &str,
    address: RecordAddress,
    entries: &mut usize,
    working_bytes: &mut u64,
    limits: SemanticModelRuntimeLimits,
) -> Result<(), String> {
    let names = map.entry(fact.owner.clone()).or_default();
    insert_posting(
        names,
        name.to_owned(),
        fact.owner.len() + name.len(),
        address,
        entries,
        working_bytes,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_rule_trigger(
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

fn resolve_posting<'a, T: Eq, F>(
    shards: &'a [ActiveSemanticModelShard],
    posting: Option<&Vec<RecordAddress>>,
    mut resolve: F,
) -> SemanticModelMatch<'a, T>
where
    F: FnMut(&'a ActiveSemanticModelShard, usize) -> Option<&'a T>,
{
    let Some(posting) = posting else {
        return SemanticModelMatch {
            records: Vec::new(),
            disposition: SemanticModelMatchDisposition::Empty,
            candidates_examined: 0,
            fallback_candidates_examined: 0,
        };
    };
    let best_rank = posting
        .iter()
        .map(|address| {
            let shard = &shards[address.shard as usize];
            (shard.evidence_rank, shard.source_rank)
        })
        .max()
        .expect("non-empty semantic-model posting");
    let mut records = Vec::new();
    for address in posting {
        let shard = &shards[address.shard as usize];
        if (shard.evidence_rank, shard.source_rank) != best_rank {
            continue;
        }
        let record = resolve(shard, address.record as usize)
            .expect("semantic-model index address must resolve to its record kind");
        if !records
            .iter()
            .any(|candidate: &ActivatedSemanticModelRecord<'_, T>| candidate.record == record)
        {
            records.push(ActivatedSemanticModelRecord { record, shard });
        }
    }
    SemanticModelMatch {
        disposition: if records.len() == 1 {
            SemanticModelMatchDisposition::Unique
        } else {
            SemanticModelMatchDisposition::Conflict
        },
        records,
        candidates_examined: posting.len(),
        fallback_candidates_examined: 0,
    }
}

/// Whether two activated records make all the same consumer-observable claims.
/// Identity fields (`id`, `model_id`, `content_sha256`) and the target spelling
/// are excluded, because they differ between records that nevertheless behave
/// identically.
///
/// This is what makes a posting with several records still a unique answer. The
/// canonical member key (#1978) is (language, owner, member, receiver, arity),
/// so it cannot tell same-arity overloads apart: `String.valueOf(int)`,
/// `String.valueOf(char[])`, and `String.valueOf(Object)` share one key, and a
/// standard-library summary pack legitimately ships all three. When their claims
/// are identical, either choice yields the same propagation, so refusing would
/// fail a policy closed over an ambiguity that does not change any answer. A
/// genuine disagreement still resolves to `Conflict` and still fails closed.
fn procedure_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.completeness == right.completeness
        && left.covers_overrides == right.covers_overrides
        && left.normal_continuation_absent == right.normal_continuation_absent
        && left.normal_result_count == right.normal_result_count
        && left.locations == right.locations
        && left.transfers == right.transfers
        && left.effects == right.effects
        && left.declared_effects == right.declared_effects
        && left.preconditions == right.preconditions
        && left.result_contracts == right.result_contracts
        && left.conditional_result_refinements == right.conditional_result_refinements
        && left.normal_return_refinements == right.normal_return_refinements
}

fn resolve_exact_procedure_postings<'a>(
    shards: &'a [ActiveSemanticModelShard],
    shapes: Option<&ProcedureSummaryShapePostings>,
    has_receiver: bool,
    formal_parameter_count: u32,
) -> ProcedureSummaryMatch<'a> {
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

fn resolve_applicable_procedure_postings<'a>(
    shards: &'a [ActiveSemanticModelShard],
    shapes: Option<&ProcedureSummaryShapePostings>,
    has_receiver: bool,
    actual_parameter_count: u32,
) -> ProcedureSummaryMatch<'a> {
    let Some(shapes) = shapes else {
        return empty_procedure_match();
    };
    // A variadic target's total formal count is one greater than its minimum
    // accepted actual count. Saturation keeps the full valid prefix available
    // for the largest representable call shape without iterating by arity.
    let maximum_variadic_formals = actual_parameter_count.saturating_add(1);
    let variadic = shapes
        .variadic
        .range((has_receiver, 1)..=(has_receiver, maximum_variadic_formals))
        .map(|(_key, posting)| posting);
    resolve_procedure_postings(
        shards,
        shapes
            .fixed
            .get(&(has_receiver, actual_parameter_count))
            .into_iter()
            .chain(variadic),
        procedure_claims_agree,
    )
}

fn procedure_match_proves_normal_continuation_absent(matched: &ProcedureSummaryMatch<'_>) -> bool {
    matched.disposition == SemanticModelMatchDisposition::Unique
        && matches!(
            matched.records.as_slice(),
            [summary] if summary.normal_continuation_absent()
        )
}

fn empty_procedure_match<'a>() -> ProcedureSummaryMatch<'a> {
    ProcedureSummaryMatch {
        records: Vec::new(),
        disposition: SemanticModelMatchDisposition::Empty,
        candidates_examined: 0,
        fallback_candidates_examined: 0,
    }
}

fn resolve_procedure_postings<'a, 'posting>(
    shards: &'a [ActiveSemanticModelShard],
    postings: impl IntoIterator<Item = &'posting Vec<RecordAddress>>,
    claims_agree: fn(&CompiledProcedureSummary, &CompiledProcedureSummary) -> bool,
) -> ProcedureSummaryMatch<'a> {
    let mut candidates_examined = 0usize;
    let mut best_rank = None;
    let mut records = Vec::<ActivatedProcedureSummary<'a>>::new();
    for posting in postings {
        candidates_examined = candidates_examined.saturating_add(posting.len());
        for address in posting {
            let shard = &shards[address.shard as usize];
            let rank = (shard.evidence_rank, shard.source_rank);
            if best_rank.is_some_and(|best| rank < best) {
                continue;
            }
            if best_rank.is_none_or(|best| rank > best) {
                best_rank = Some(rank);
                records.clear();
            }
            let payload = shard
                .shard
                .payload()
                .procedure_summaries()
                .expect("procedure-summary index address must resolve to its payload kind");
            let record = payload
                .get(address.record as usize)
                .expect("procedure-summary index address must resolve to its record");
            if records
                .iter()
                .any(|candidate| claims_agree(candidate.record, record))
            {
                continue;
            }
            records.push(ActivatedProcedureSummary {
                record,
                shard,
                payload,
            });
        }
    }
    ProcedureSummaryMatch {
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

fn procedure_declaration_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.target.variadic == right.target.variadic && procedure_claims_agree(left, right)
}

#[derive(Debug)]
pub enum SemanticModelResolutionOutcome {
    Ready(ResolvedActiveSemanticModels),
    Incomplete {
        usable: Option<ResolvedActiveSemanticModels>,
        report: SemanticModelActivationReport,
    },
    Cancelled(SemanticModelActivationReport),
    Unavailable(SemanticModelActivationReport),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelRuntimeLifecycle {
    Cached,
    Built,
    Uncached,
}

#[derive(Debug)]
pub enum SemanticModelRuntimeOutcome {
    Ready {
        active: Arc<ResolvedActiveSemanticModels>,
        snapshot: Arc<ActiveSemanticModelSnapshot>,
        lifecycle: SemanticModelRuntimeLifecycle,
    },
    Incomplete {
        usable: Option<Arc<ResolvedActiveSemanticModels>>,
        report: SemanticModelActivationReport,
    },
    Cancelled(SemanticModelActivationReport),
    Unavailable(SemanticModelActivationReport),
}

impl SemanticModelRuntimeOutcome {
    /// Convert an existing activation result into diagnostic suppression
    /// reasons. This method performs no activation, discovery, or package I/O.
    pub fn semantic_diagnostic_incomplete_reasons(
        &self,
    ) -> Vec<crate::analyzer::SemanticDiagnosticIncompleteReason> {
        use crate::analyzer::SemanticDiagnosticIncompleteReason;

        match self {
            Self::Ready { .. } => Vec::new(),
            Self::Incomplete { report, .. } => {
                vec![SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                    detail: format!("incomplete activation: {report:?}"),
                }]
            }
            Self::Cancelled(_) => vec![SemanticDiagnosticIncompleteReason::Cancelled],
            Self::Unavailable(report) => {
                vec![SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                    detail: format!("unavailable activation: {report:?}"),
                }]
            }
        }
    }
}

pub(crate) fn degrade_pack_gap_absences(
    analyzer: &dyn IAnalyzer,
    mut report: crate::analyzer::SemanticDiagnosticReport,
) -> crate::analyzer::SemanticDiagnosticReport {
    use crate::analyzer::{SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason};

    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return report;
    };
    report.degrade_absences(|domain| {
        let gap = match domain {
            SemanticDiagnosticDomain::Type { name }
            | SemanticDiagnosticDomain::Module { name }
            | SemanticDiagnosticDomain::Package { name } => overlay.gapped(name),
            SemanticDiagnosticDomain::MemberSurface { owner, member } => {
                overlay.gapped_member_surface(owner, member)
            }
            SemanticDiagnosticDomain::LexicalScope { .. } => None,
        }?;
        Some(SemanticDiagnosticIncompleteReason::PackExtractionGap {
            pack_id: gap.pack_id.clone(),
            declaration: gap.declaration.clone(),
        })
    });
    report
}

pub(crate) struct SemanticModelRuntimeCache {
    values: CompleteValueCache<String, ResolvedActiveSemanticModels>,
    published: Mutex<PublishedSemanticModelState>,
}

#[derive(Default)]
struct PublishedSemanticModelState {
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    dependency_evidence: HashMap<Language, Arc<super::DependencyDiscoveryEvidence>>,
}

#[derive(Clone, Copy)]
pub struct SemanticModelActivationPersistence<'a> {
    pub scope_id: &'a str,
    pub store: &'a AnalyzerStore,
}

impl Default for SemanticModelRuntimeCache {
    fn default() -> Self {
        Self::new(1)
    }
}

impl SemanticModelRuntimeCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            values: CompleteValueCache::<String, ResolvedActiveSemanticModels>::new(
                max_retained_bytes,
                |_, active| u32::try_from(active.retained_bytes()).unwrap_or(u32::MAX),
            ),
            published: Mutex::new(PublishedSemanticModelState::default()),
        }
    }

    /// Retain one discovery run's evidence for every language its ecosystem serves.
    /// Production hosts use the atomic activation method instead.
    #[cfg(test)]
    pub(crate) fn retain_dependency_discovery_evidence(
        &self,
        languages: &[Language],
        evidence: super::DependencyDiscoveryEvidence,
    ) {
        let evidence = Arc::new(evidence);
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        for language in languages {
            published
                .dependency_evidence
                .insert(*language, Arc::clone(&evidence));
        }
    }

    pub(crate) fn dependency_discovery_evidence(
        &self,
        language: Language,
    ) -> Option<Arc<super::DependencyDiscoveryEvidence>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .dependency_evidence
            .get(&language)
            .cloned()
    }

    pub(crate) fn invalidate_dependency_pack_state(&self, languages: &[Language]) -> bool {
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        let mut evidence_changed = false;
        for language in languages {
            evidence_changed |= published.dependency_evidence.remove(language).is_some();
        }
        let snapshot_changed = published.snapshot.take().is_some();
        evidence_changed || snapshot_changed
    }

    pub(crate) fn snapshot(&self) -> Option<Arc<ActiveSemanticModelSnapshot>> {
        self.published
            .lock()
            .expect("semantic-model publication mutex poisoned")
            .snapshot
            .as_ref()
            .map(Arc::clone)
    }

    pub(crate) fn overlay(&self) -> Option<Arc<SemanticModelOverlay>> {
        self.snapshot()
            .and_then(|snapshot| snapshot.semantic_model_overlay().map(Arc::clone))
    }

    fn publish_overlay(
        &self,
        analyzer: &dyn IAnalyzer,
        active: &Arc<ResolvedActiveSemanticModels>,
        dependency_evidence: Option<&[DependencyEvidencePublication]>,
        cancellation: &CancellationToken,
        max_combined_retained_bytes: u64,
    ) -> Result<Arc<ActiveSemanticModelSnapshot>, SemanticModelOverlayBuildError> {
        {
            let published = self
                .published
                .lock()
                .expect("semantic-model publication mutex poisoned");
            if dependency_evidence.is_none()
                && let Some(snapshot) = published.snapshot.as_ref()
                && Arc::ptr_eq(snapshot.active_models(), active)
            {
                return Ok(Arc::clone(snapshot));
            }
        }
        let overlay = Arc::new(SemanticModelOverlay::build(
            analyzer,
            active,
            cancellation,
            max_combined_retained_bytes,
        )?);
        let mut published = self
            .published
            .lock()
            .expect("semantic-model publication mutex poisoned");
        if dependency_evidence.is_none()
            && let Some(current) = published.snapshot.as_ref()
            && Arc::ptr_eq(current.active_models(), active)
        {
            return Ok(Arc::clone(current));
        }
        if let Some(evidence) = dependency_evidence {
            for (languages, value) in evidence {
                let value = Arc::new(value.clone());
                for language in languages {
                    published
                        .dependency_evidence
                        .insert(*language, Arc::clone(&value));
                }
            }
        }
        let snapshot = Arc::new(ActiveSemanticModelSnapshot::new(
            Arc::clone(active),
            Some(overlay),
        ));
        published.snapshot = Some(Arc::clone(&snapshot));
        Ok(snapshot)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EvidenceRank {
    Language,
    NamedCoordinate,
    VersionedCoordinate,
    ExactArtifact,
}

#[derive(Debug)]
struct CandidateSelection {
    active: ActiveSemanticModelShard,
    semantic_sha256: String,
    payload_kind: PayloadKind,
    evidence_rank: EvidenceRank,
    source_rank: u8,
}

pub fn resolve_active_semantic_models(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelResolutionOutcome {
    let mut report = SemanticModelActivationReport::default();
    let activation_sql_start = catalog.sql_statement_count();
    let selection_started = Instant::now();
    let evidence = match validate_and_canonicalize_request(request) {
        Ok(evidence) => evidence,
        Err(reason) => {
            push_request_explanation(&mut report, request.limits, reason);
            return SemanticModelResolutionOutcome::Unavailable(report);
        }
    };
    if cancellation.is_cancelled() {
        return SemanticModelResolutionOutcome::Cancelled(report);
    }

    let mut candidates = BTreeMap::new();
    for row in &evidence {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = evidence_query(row, request.bifrost_version.clone());
        let discovered = match catalog.candidates(&query) {
            Ok(discovered) => discovered,
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("catalog candidate discovery failed: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        for candidate in discovered {
            let key = (
                candidate.manifest_digest().to_owned(),
                candidate.shard_id().to_owned(),
                candidate.source_kind(),
                candidate.source_id().to_owned(),
            );
            candidates.entry(key).or_insert(candidate);
            if candidates.len() > request.limits.max_catalog_candidates {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    "semantic-model catalog candidate budget exceeded".to_owned(),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        }
    }
    let mut language_ecosystems = evidence
        .iter()
        .map(|row| {
            (
                semantic_pack_language(&row.language).to_owned(),
                row.ecosystem.clone(),
            )
        })
        .collect::<Vec<_>>();
    language_ecosystems.sort();
    language_ecosystems.dedup();
    for (language, ecosystem) in language_ecosystems {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let query = SemanticPackSelectorQuery {
            language,
            ecosystem,
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
            bifrost_version: request.bifrost_version.clone(),
        };
        let discovered = match catalog.candidates_bounded(
            &query,
            request.limits.max_catalog_candidates.saturating_add(1),
        ) {
            Ok(discovered) => discovered,
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("catalog candidate evaluation failed: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        for candidate in discovered {
            let key = (
                candidate.manifest_digest().to_owned(),
                candidate.shard_id().to_owned(),
                candidate.source_kind(),
                candidate.source_id().to_owned(),
            );
            candidates.entry(key).or_insert(candidate);
            if candidates.len() > request.limits.max_catalog_candidates {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    "semantic-model catalog candidate budget exceeded".to_owned(),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        }
    }
    report.catalog_candidates = candidates.len();
    report.phase_measurements.selection_nanos = elapsed_nanos(selection_started);

    let mut selected = Vec::<CandidateSelection>::new();
    let mut incomplete = false;
    let mut decode_hydration_nanos = 0u64;
    for candidate in candidates.into_values() {
        if cancellation.is_cancelled() {
            return SemanticModelResolutionOutcome::Cancelled(report);
        }
        let load_started = Instant::now();
        let loaded = match catalog.load(&candidate) {
            Ok(loaded) => loaded,
            Err(miss) => {
                incomplete = true;
                push_explanation(
                    &mut report,
                    request.limits,
                    SemanticModelActivationExplanation {
                        manifest_digest: candidate.manifest_digest().to_owned(),
                        pack_id: None,
                        shard_id: candidate.shard_id().to_owned(),
                        source_kind: candidate.source_kind(),
                        source_id: candidate.source_id().to_owned(),
                        status: SemanticModelActivationStatus::Unavailable,
                        reason: catalog_miss_reason(&miss),
                    },
                );
                continue;
            }
        };
        decode_hydration_nanos = decode_hydration_nanos.saturating_add(elapsed_nanos(load_started));
        report.loaded_shards = report.loaded_shards.saturating_add(1);
        report.loaded_records = report
            .loaded_records
            .saturating_add(loaded.shard.record_count());
        if report.loaded_shards > request.limits.max_loaded_shards
            || report.loaded_records > request.limits.max_records
        {
            push_request_explanation(
                &mut report,
                request.limits,
                "semantic-model decoded shard budget exceeded".to_owned(),
            );
            return SemanticModelResolutionOutcome::Unavailable(report);
        }

        let Some((evidence_rank, matched_evidence)) = strict_activation_match(
            &loaded.manifest,
            &loaded.shard,
            &evidence,
            &request.bifrost_version,
        ) else {
            let reason =
                strict_activation_mismatch_reason(&loaded.manifest, &loaded.shard, &evidence);
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::Incompatible,
                &reason,
            );
            continue;
        };
        let control = match effective_control(&loaded.manifest, &request.controls) {
            Ok(control) => control,
            Err(reason) => {
                push_loaded_explanation(
                    &mut report,
                    request.limits,
                    &loaded,
                    SemanticModelActivationStatus::Conflict,
                    &reason,
                );
                incomplete = true;
                continue;
            }
        };
        if control == Some(SemanticModelControlAction::Disable) {
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::Disabled,
                "a compatible activation control disables this pack",
            );
            continue;
        }
        if loaded.shard.safety().review_required
            && control != Some(SemanticModelControlAction::Enable)
        {
            push_loaded_explanation(
                &mut report,
                request.limits,
                &loaded,
                SemanticModelActivationStatus::ReviewRequired,
                "the pack requires an explicit compatible enable control",
            );
            continue;
        }

        let descriptor = candidate.descriptor();
        selected.push(CandidateSelection {
            semantic_sha256: descriptor.semantic_sha256.clone(),
            payload_kind: descriptor.payload_kind,
            evidence_rank,
            source_rank: source_rank(loaded.source_kind),
            active: ActiveSemanticModelShard {
                manifest: loaded.manifest,
                shard: loaded.shard,
                source_kind: loaded.source_kind,
                source_id: loaded.source_id,
                matched_evidence,
                evidence_rank,
                source_rank: source_rank(loaded.source_kind),
            },
        });
    }

    selected.sort_by(compare_selection);
    let mut active = Vec::new();
    let mut by_semantic_shard = BTreeMap::<(String, PayloadKind), usize>::new();
    for selection in selected.into_iter().rev() {
        let key = (selection.semantic_sha256.clone(), selection.payload_kind);
        if let Some(&winner) = by_semantic_shard.get(&key) {
            let active_winner: &CandidateSelection = &active[winner];
            push_explanation(
                &mut report,
                request.limits,
                SemanticModelActivationExplanation {
                    manifest_digest: selection.active.manifest.content_sha256.clone(),
                    pack_id: Some(selection.active.manifest.pack_id.clone()),
                    shard_id: selection.active.shard.shard_id().to_owned(),
                    source_kind: selection.active.source_kind,
                    source_id: selection.active.source_id.clone(),
                    status: SemanticModelActivationStatus::Shadowed,
                    reason: format!(
                        "equivalent semantic shard is supplied by higher-precedence source {}",
                        active_winner.active.source_id
                    ),
                },
            );
            continue;
        }
        by_semantic_shard.insert(key, active.len());
        active.push(selection);
    }
    active.sort_by(|left, right| {
        left.active
            .manifest
            .pack_id
            .cmp(&right.active.manifest.pack_id)
            .then_with(|| {
                left.active
                    .shard
                    .shard_id()
                    .cmp(right.active.shard.shard_id())
            })
            .then_with(|| left.semantic_sha256.cmp(&right.semantic_sha256))
    });

    for selection in &active {
        push_explanation(
            &mut report,
            request.limits,
            SemanticModelActivationExplanation {
                manifest_digest: selection.active.manifest.content_sha256.clone(),
                pack_id: Some(selection.active.manifest.pack_id.clone()),
                shard_id: selection.active.shard.shard_id().to_owned(),
                source_kind: selection.active.source_kind,
                source_id: selection.active.source_id.clone(),
                status: SemanticModelActivationStatus::Active,
                reason: "strict activation evidence and controls selected this shard".to_owned(),
            },
        );
    }
    report.explanations.sort_by(|left, right| {
        left.manifest_digest
            .cmp(&right.manifest_digest)
            .then_with(|| left.shard_id.cmp(&right.shard_id))
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source_id.cmp(&right.source_id))
            .then_with(|| left.status.cmp(&right.status))
    });

    let active_packs = active
        .iter()
        .map(|selection| {
            (
                selection.active.manifest.content_sha256.clone(),
                selection.active.manifest.pack_id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut extraction_gaps = Vec::new();
    let mut extraction_gap_counts = BTreeMap::new();
    for (manifest_digest, pack_id) in active_packs {
        let extraction = match catalog.extraction_accounting(&manifest_digest) {
            Ok(extraction) => extraction,
            Err(error) => {
                push_request_explanation(
                    &mut report,
                    request.limits,
                    format!("read extraction gaps for active pack {pack_id}: {error}"),
                );
                return SemanticModelResolutionOutcome::Unavailable(report);
            }
        };
        if let Some(extraction) = extraction {
            extraction_gap_counts.insert(manifest_digest, extraction.gaps.len());
            extraction_gaps.extend(extraction.gaps.into_iter().map(|gap| {
                ActivePackExtractionGap {
                    pack_id: pack_id.clone(),
                    declaration: gap.declaration,
                    reason: gap.reason,
                }
            }));
        } else {
            extraction_gap_counts.insert(manifest_digest, 0);
        }
    }
    for explanation in &mut report.explanations {
        if explanation.status == SemanticModelActivationStatus::Active
            && let Some(gaps) = extraction_gap_counts.get(&explanation.manifest_digest)
        {
            explanation.reason = format!(
                "strict activation evidence and controls selected this shard; gaps: {gaps}"
            );
        }
    }
    extraction_gaps.sort_by(|left, right| {
        left.declaration
            .cmp(&right.declaration)
            .then_with(|| left.pack_id.cmp(&right.pack_id))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    let mut extraction_gaps_by_declaration = map_with_capacity(extraction_gaps.len());
    for (index, gap) in extraction_gaps.iter().enumerate() {
        extraction_gaps_by_declaration
            .entry(gap.declaration.clone())
            .or_insert_with(Vec::new)
            .push(index);
    }
    report.extraction_gaps = extraction_gaps.len();

    let active_model_set_hash = active_model_set_hash(&active, &extraction_gaps);
    let shards = active
        .into_iter()
        .map(|selection| selection.active)
        .collect::<Vec<_>>();
    report.phase_measurements.decode_hydration_nanos = decode_hydration_nanos;
    let matcher_started = Instant::now();
    let indexes = match MatcherIndexes::build(&shards, request.limits, cancellation, &mut report) {
        Ok(indexes) => indexes,
        Err(reason) => {
            push_request_explanation(&mut report, request.limits, reason);
            return if cancellation.is_cancelled() {
                SemanticModelResolutionOutcome::Cancelled(report)
            } else {
                SemanticModelResolutionOutcome::Unavailable(report)
            };
        }
    };
    report.phase_measurements.matcher_construction_nanos = elapsed_nanos(matcher_started);
    report.phase_measurements.catalog_sql_statements = catalog
        .sql_statement_count()
        .saturating_sub(activation_sql_start);
    let resolved = ResolvedActiveSemanticModels {
        active_model_set_hash,
        shards,
        indexes,
        extraction_gaps,
        extraction_gaps_by_declaration,
        report: report.clone(),
    };
    if incomplete {
        SemanticModelResolutionOutcome::Incomplete {
            usable: (!resolved.shards.is_empty()).then_some(resolved),
            report,
        }
    } else {
        SemanticModelResolutionOutcome::Ready(resolved)
    }
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

pub fn acquire_active_semantic_models(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    acquire_active_semantic_models_with_evidence(
        analyzer,
        catalog,
        persistence,
        request,
        None,
        cancellation,
    )
}

/// Acquire and atomically publish one generation's overlay and discovery evidence.
/// A failed acquisition leaves the previously complete publication unchanged.
pub fn acquire_active_semantic_models_with_evidence(
    analyzer: &dyn IAnalyzer,
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    request: &SemanticModelActivationRequest,
    dependency_evidence: Option<&[DependencyEvidencePublication]>,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeOutcome {
    let request_key = match runtime_request_key(request) {
        Ok(key) => key,
        Err(reason) => {
            let mut report = SemanticModelActivationReport::default();
            push_request_explanation(&mut report, request.limits, reason);
            return SemanticModelRuntimeOutcome::Unavailable(report);
        }
    };
    if let Some(persistence) = persistence
        && let Err(error) =
            catalog.reconcile_workspace_active_set(persistence.scope_id, persistence.store)
    {
        return catalog_lifecycle_error(request.limits, "reconcile", error);
    }
    let catalog_identity = match catalog.cache_identity() {
        Ok(identity) => identity,
        Err(error) => return catalog_lifecycle_error(request.limits, "identify", error),
    };
    let key = format!(
        "{request_key}:{}:{}",
        catalog_identity.mutation_generation, catalog_identity.sqlite_data_version
    );
    // The activation guard asks whether the analyzer snapshot moved underneath
    // this resolution. Comparing the whole optional identity keeps an analyzer
    // that states none (an empty workspace) on its previous behavior instead of
    // reporting a permanent mismatch.
    let snapshot_content = analyzer.workspace_content_identity();
    let content_is_current = || analyzer.workspace_content_identity() == snapshot_content;
    let Some(caches) = analyzer.snapshot_caches() else {
        let outcome = resolve_active_semantic_models(catalog, request, cancellation);
        if !content_is_current() {
            return stale_generation_outcome(request.limits);
        }
        if let SemanticModelResolutionOutcome::Ready(active) = &outcome
            && let Err(error) = publish_active_models(catalog, persistence, active)
        {
            return catalog_lifecycle_error(request.limits, "publish", error);
        }
        return runtime_outcome(outcome, SemanticModelRuntimeLifecycle::Uncached);
    };
    let (acquisition, _) = caches.semantic_models().values.acquire(&key, cancellation);
    match acquisition {
        CompleteValueAcquisition::Cached { value } => {
            if !content_is_current() {
                return stale_generation_outcome(request.limits);
            }
            if let Err(error) = publish_active_models(catalog, persistence, &value) {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            let snapshot = match caches.semantic_models().publish_overlay(
                analyzer,
                &value,
                dependency_evidence,
                cancellation,
                request.limits.max_retained_bytes,
            ) {
                Ok(snapshot) => snapshot,
                Err(error) => return overlay_build_outcome(&value, error, request.limits),
            };
            SemanticModelRuntimeOutcome::Ready {
                active: value,
                snapshot,
                lifecycle: SemanticModelRuntimeLifecycle::Cached,
            }
        }
        CompleteValueAcquisition::Leader { permit } => {
            let outcome = resolve_active_semantic_models(catalog, request, cancellation);
            let SemanticModelResolutionOutcome::Ready(active) = outcome else {
                return runtime_outcome(outcome, SemanticModelRuntimeLifecycle::Built);
            };
            if !content_is_current() {
                return stale_generation_outcome(request.limits);
            }
            let active = Arc::new(active);
            if let Err(error) = publish_active_models(catalog, persistence, &active) {
                return catalog_lifecycle_error(request.limits, "publish", error);
            }
            let snapshot = match caches.semantic_models().publish_overlay(
                analyzer,
                &active,
                dependency_evidence,
                cancellation,
                request.limits.max_retained_bytes,
            ) {
                Ok(snapshot) => snapshot,
                Err(error) => return overlay_build_outcome(&active, error, request.limits),
            };
            permit.publish_complete(Arc::clone(&active));
            SemanticModelRuntimeOutcome::Ready {
                active,
                snapshot,
                lifecycle: SemanticModelRuntimeLifecycle::Built,
            }
        }
        CompleteValueAcquisition::Cancelled => {
            SemanticModelRuntimeOutcome::Cancelled(SemanticModelActivationReport::default())
        }
        CompleteValueAcquisition::Rejected => {
            unreachable!("semantic-model runtime cache never publishes deterministic rejections")
        }
    }
}

fn overlay_build_outcome(
    active: &ResolvedActiveSemanticModels,
    error: SemanticModelOverlayBuildError,
    limits: SemanticModelRuntimeLimits,
) -> SemanticModelRuntimeOutcome {
    let mut report = active.activation_report().clone();
    match error {
        SemanticModelOverlayBuildError::Cancelled => SemanticModelRuntimeOutcome::Cancelled(report),
        SemanticModelOverlayBuildError::RetainedBytesExceeded => {
            push_request_explanation(
                &mut report,
                limits,
                "semantic-model overlay exceeds the combined retained-byte budget".to_string(),
            );
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
        SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded => {
            push_request_explanation(
                &mut report,
                limits,
                "semantic-model Go promotion or interface traversal exceeds its bounded work limit"
                    .to_string(),
            );
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
    }
}

fn publish_active_models(
    catalog: &SemanticPackCatalog,
    persistence: Option<SemanticModelActivationPersistence<'_>>,
    active: &ResolvedActiveSemanticModels,
) -> Result<(), super::CatalogError> {
    let Some(persistence) = persistence else {
        return Ok(());
    };
    let mut members = active
        .shards
        .iter()
        .map(|shard| SemanticPackActiveReference {
            manifest_digest: shard.manifest.content_sha256.clone(),
            source_kind: activation_source_kind(shard.source_kind),
            source_id: shard.source_id.clone(),
            workspace_produced: shard.source_kind == CatalogPackSourceKind::WorkspaceProduced,
        })
        .collect::<Vec<_>>();
    members.sort();
    members.dedup();
    catalog
        .replace_workspace_active_set(persistence.scope_id, persistence.store, &members)
        .map(|_| ())
}

fn activation_source_kind(kind: CatalogPackSourceKind) -> SemanticPackActivationSourceKind {
    match kind {
        CatalogPackSourceKind::Installed => SemanticPackActivationSourceKind::Installed,
        CatalogPackSourceKind::Generated => SemanticPackActivationSourceKind::Generated,
        CatalogPackSourceKind::PreShipped => SemanticPackActivationSourceKind::PreShipped,
        CatalogPackSourceKind::WorkspaceProduced => {
            SemanticPackActivationSourceKind::WorkspaceProduced
        }
        CatalogPackSourceKind::Embedded => SemanticPackActivationSourceKind::Embedded,
        CatalogPackSourceKind::EphemeralWorkspace => {
            SemanticPackActivationSourceKind::EphemeralWorkspace
        }
    }
}

fn catalog_lifecycle_error(
    limits: SemanticModelRuntimeLimits,
    operation: &str,
    error: super::CatalogError,
) -> SemanticModelRuntimeOutcome {
    let mut report = SemanticModelActivationReport::default();
    push_request_explanation(
        &mut report,
        limits,
        format!("semantic-model active-set {operation} failed: {error}"),
    );
    SemanticModelRuntimeOutcome::Unavailable(report)
}

fn runtime_outcome(
    outcome: SemanticModelResolutionOutcome,
    lifecycle: SemanticModelRuntimeLifecycle,
) -> SemanticModelRuntimeOutcome {
    match outcome {
        SemanticModelResolutionOutcome::Ready(active) => {
            let active = Arc::new(active);
            let snapshot = Arc::new(ActiveSemanticModelSnapshot::new(Arc::clone(&active), None));
            SemanticModelRuntimeOutcome::Ready {
                active,
                snapshot,
                lifecycle,
            }
        }
        SemanticModelResolutionOutcome::Incomplete { usable, report } => {
            SemanticModelRuntimeOutcome::Incomplete {
                usable: usable.map(Arc::new),
                report,
            }
        }
        SemanticModelResolutionOutcome::Cancelled(report) => {
            SemanticModelRuntimeOutcome::Cancelled(report)
        }
        SemanticModelResolutionOutcome::Unavailable(report) => {
            SemanticModelRuntimeOutcome::Unavailable(report)
        }
    }
}

fn stale_generation_outcome(limits: SemanticModelRuntimeLimits) -> SemanticModelRuntimeOutcome {
    let mut report = SemanticModelActivationReport::default();
    push_request_explanation(
        &mut report,
        limits,
        "analyzer generation changed during semantic-model activation".to_owned(),
    );
    SemanticModelRuntimeOutcome::Unavailable(report)
}

fn runtime_request_key(request: &SemanticModelActivationRequest) -> Result<String, String> {
    let evidence = validate_and_canonicalize_request(request)?;
    let mut controls = request
        .controls
        .iter()
        .map(|control| {
            let mut hasher = Sha256::new();
            hasher.update([match control.scope {
                SemanticModelControlScope::User => 0,
                SemanticModelControlScope::Workspace => 1,
            }]);
            hasher.update([match control.action {
                SemanticModelControlAction::Enable => 0,
                SemanticModelControlAction::Disable => 1,
            }]);
            hash_key_part(&mut hasher, &control.selector.pack_id);
            hash_optional_key_part(
                &mut hasher,
                control
                    .selector
                    .version
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
            );
            hash_optional_key_part(&mut hasher, control.selector.manifest_digest.as_deref());
            hasher.finalize().to_vec()
        })
        .collect::<Vec<_>>();
    controls.sort_unstable();
    controls.dedup();
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.semantic-model.runtime-request.v1\0");
    hash_key_part(&mut hasher, &request.bifrost_version.to_string());
    for row in &evidence {
        hash_activation_evidence(&mut hasher, row);
    }
    for control in controls {
        hasher.update((control.len() as u64).to_be_bytes());
        hasher.update(control);
    }
    for limit in [
        request.limits.max_evidence_rows as u64,
        request.limits.max_controls as u64,
        request.limits.max_catalog_candidates as u64,
        request.limits.max_loaded_shards as u64,
        request.limits.max_records as u64,
        request.limits.max_index_entries as u64,
        request.limits.max_working_bytes,
        request.limits.max_retained_bytes,
        request.limits.max_explanations as u64,
    ] {
        hasher.update(limit.to_be_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_key_part(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_optional_key_part(hasher: &mut Sha256, value: Option<&str>) {
    hasher.update([u8::from(value.is_some())]);
    if let Some(value) = value {
        hash_key_part(hasher, value);
    }
}

fn hash_optional_coordinate(hasher: &mut Sha256, coordinate: Option<&CatalogCoordinate>) {
    hasher.update([u8::from(coordinate.is_some())]);
    if let Some(coordinate) = coordinate {
        hash_key_part(hasher, &coordinate.name);
        hash_optional_key_part(
            hasher,
            coordinate
                .version
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
        );
    }
}

fn hash_activation_evidence(hasher: &mut Sha256, evidence: &SemanticModelActivationEvidence) {
    hash_key_part(hasher, &evidence.language);
    hash_key_part(hasher, &evidence.ecosystem);
    hash_optional_coordinate(hasher, evidence.package.as_ref());
    hash_optional_coordinate(hasher, evidence.module.as_ref());
    hash_optional_coordinate(hasher, evidence.toolchain.as_ref());
    hash_optional_key_part(hasher, evidence.target.as_deref());
    hash_optional_key_part(hasher, evidence.configuration.as_deref());
    hash_optional_key_part(hasher, evidence.artifact_sha256.as_deref());
}

fn validate_and_canonicalize_request(
    request: &SemanticModelActivationRequest,
) -> Result<Vec<SemanticModelActivationEvidence>, String> {
    if request.evidence.len() > request.limits.max_evidence_rows {
        return Err("semantic-model activation evidence budget exceeded".to_owned());
    }
    if request.controls.len() > request.limits.max_controls {
        return Err("semantic-model activation control budget exceeded".to_owned());
    }
    let mut evidence = request.evidence.clone();
    for row in &evidence {
        if row.language.is_empty() || row.ecosystem.is_empty() {
            return Err("activation evidence language and ecosystem must not be empty".to_owned());
        }
        if row
            .artifact_sha256
            .as_deref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        {
            return Err("activation evidence artifact digest must be lowercase SHA-256".to_owned());
        }
    }
    for control in &request.controls {
        if control.selector.pack_id.is_empty() {
            return Err("semantic-model control pack ID must not be empty".to_owned());
        }
        if control
            .selector
            .manifest_digest
            .as_deref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        {
            return Err(
                "semantic-model control manifest digest must be lowercase SHA-256".to_owned(),
            );
        }
    }
    let mut control_actions = BTreeMap::new();
    for control in &request.controls {
        let key = (
            control.scope,
            control.selector.pack_id.as_str(),
            control.selector.version.as_ref().map(ToString::to_string),
            control.selector.manifest_digest.as_deref(),
        );
        if control_actions
            .insert(key, control.action)
            .is_some_and(|previous| previous != control.action)
        {
            return Err("equally specific activation controls conflict".to_owned());
        }
    }
    evidence.sort();
    evidence.dedup();
    Ok(evidence)
}

fn evidence_query(
    evidence: &SemanticModelActivationEvidence,
    bifrost_version: Version,
) -> SemanticPackSelectorQuery {
    SemanticPackSelectorQuery {
        language: semantic_pack_language(&evidence.language).to_owned(),
        ecosystem: evidence.ecosystem.clone(),
        package: evidence.package.clone(),
        module: evidence.module.clone(),
        toolchain: evidence.toolchain.clone(),
        target: evidence.target.clone(),
        configuration: evidence.configuration.clone(),
        artifact_sha256: evidence.artifact_sha256.clone(),
        bifrost_version,
    }
}

/// Project a source dialect label onto the language identity that owns shared
/// semantic-pack content. The original evidence row remains untouched so
/// activation diagnostics retain the precise source dialect.
fn semantic_pack_language(label: &str) -> &str {
    if LanguageDialect::from_config_label(label) == Some(LanguageDialect::TypeScriptTsx) {
        LanguageDialect::TypeScriptTsx.semantic_pack_label()
    } else {
        label
    }
}

fn strict_activation_match(
    manifest: &CompiledPackManifest,
    shard: &CompiledShard,
    evidence: &[SemanticModelActivationEvidence],
    bifrost_version: &Version,
) -> Option<(EvidenceRank, SemanticModelActivationEvidence)> {
    let bifrost = VersionReq::parse(&manifest.compatibility.bifrost).ok()?;
    if !bifrost.matches(bifrost_version) {
        return None;
    }
    if !manifest.compatibility.toolchains.iter().all(|constraint| {
        let Ok(requirement) = VersionReq::parse(&constraint.requirement) else {
            return false;
        };
        evidence.iter().any(|row| {
            semantic_pack_language(&row.language) == manifest.language
                && row.ecosystem == manifest.ecosystem
                && row.toolchain.as_ref().is_some_and(|toolchain| {
                    toolchain.name == constraint.name
                        && toolchain
                            .version
                            .as_ref()
                            .is_some_and(|version| requirement.matches(version))
                })
        })
    }) {
        return None;
    }
    shard
        .activation()
        .iter()
        .flat_map(|selector| {
            evidence
                .iter()
                .filter(move |row| {
                    semantic_pack_language(&row.language) == manifest.language
                        && row.ecosystem == manifest.ecosystem
                        && strict_selector_matches(selector, row)
                })
                .map(|row| (selector_rank(selector), row.clone()))
        })
        .max()
}

fn strict_selector_matches(
    selector: &ActivationSelector,
    evidence: &SemanticModelActivationEvidence,
) -> bool {
    strict_coordinate_matches(selector.package.as_ref(), evidence.package.as_ref())
        && strict_coordinate_matches(selector.module.as_ref(), evidence.module.as_ref())
        && strict_coordinate_matches(selector.toolchain.as_ref(), evidence.toolchain.as_ref())
        && (selector.targets.is_empty()
            || evidence
                .target
                .as_ref()
                .is_some_and(|target| selector.targets.contains(target)))
        && (selector.configurations.is_empty()
            || evidence
                .configuration
                .as_ref()
                .is_some_and(|configuration| selector.configurations.contains(configuration)))
        && selector
            .artifact_sha256
            .as_ref()
            .is_none_or(|expected| evidence.artifact_sha256.as_ref() == Some(expected))
}

fn strict_coordinate_matches(
    selector: Option<&super::NameSelector>,
    evidence: Option<&CatalogCoordinate>,
) -> bool {
    match (selector, evidence) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(selector), Some(evidence)) if selector.name != evidence.name => false,
        (Some(selector), Some(evidence)) => match (&selector.version, &evidence.version) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(requirement), Some(version)) => {
                VersionReq::parse(requirement).is_ok_and(|requirement| requirement.matches(version))
            }
        },
    }
}

/// Explain a failed strict activation match. When the evidence names a
/// required coordinate but an exact version requirement rejects it, the
/// explanation names the workspace version and the pack requirement (#1884).
/// Every other rejection keeps the generic statement.
fn strict_activation_mismatch_reason(
    manifest: &CompiledPackManifest,
    shard: &CompiledShard,
    evidence: &[SemanticModelActivationEvidence],
) -> String {
    let scoped = || {
        evidence.iter().filter(|row| {
            semantic_pack_language(&row.language) == manifest.language
                && row.ecosystem == manifest.ecosystem
        })
    };
    for constraint in &manifest.compatibility.toolchains {
        let Ok(requirement) = VersionReq::parse(&constraint.requirement) else {
            continue;
        };
        let satisfied = scoped().any(|row| {
            row.toolchain.as_ref().is_some_and(|toolchain| {
                toolchain.name == constraint.name
                    && toolchain
                        .version
                        .as_ref()
                        .is_some_and(|version| requirement.matches(version))
            })
        });
        if satisfied {
            continue;
        }
        if let Some(toolchain) = scoped()
            .filter_map(|row| row.toolchain.as_ref())
            .find(|toolchain| toolchain.name == constraint.name)
        {
            return match &toolchain.version {
                Some(version) => format!(
                    "workspace toolchain {} {version} does not satisfy the pack requirement {}",
                    constraint.name, constraint.requirement
                ),
                None => format!(
                    "workspace toolchain {} has no exact version and does not satisfy the pack requirement {}",
                    constraint.name, constraint.requirement
                ),
            };
        }
    }
    for selector in shard.activation() {
        for row in scoped() {
            if !strict_coordinate_names_match(selector.package.as_ref(), row.package.as_ref())
                || !strict_coordinate_names_match(selector.module.as_ref(), row.module.as_ref())
                || !strict_coordinate_names_match(
                    selector.toolchain.as_ref(),
                    row.toolchain.as_ref(),
                )
            {
                continue;
            }
            let non_version_predicates_pass = (selector.targets.is_empty()
                || row
                    .target
                    .as_ref()
                    .is_some_and(|target| selector.targets.contains(target)))
                && (selector.configurations.is_empty()
                    || row.configuration.as_ref().is_some_and(|configuration| {
                        selector.configurations.contains(configuration)
                    }))
                && selector
                    .artifact_sha256
                    .as_ref()
                    .is_none_or(|expected| row.artifact_sha256.as_ref() == Some(expected));
            if !non_version_predicates_pass {
                continue;
            }
            for (axis, coordinate_selector, coordinate_evidence) in [
                ("package", selector.package.as_ref(), row.package.as_ref()),
                ("module", selector.module.as_ref(), row.module.as_ref()),
                (
                    "toolchain",
                    selector.toolchain.as_ref(),
                    row.toolchain.as_ref(),
                ),
            ] {
                let (Some(coordinate_selector), Some(coordinate_evidence)) =
                    (coordinate_selector, coordinate_evidence)
                else {
                    continue;
                };
                let Some(requirement_source) = &coordinate_selector.version else {
                    continue;
                };
                let Ok(requirement) = VersionReq::parse(requirement_source) else {
                    continue;
                };
                let satisfied = coordinate_evidence
                    .version
                    .as_ref()
                    .is_some_and(|version| requirement.matches(version));
                if !satisfied {
                    return match &coordinate_evidence.version {
                        Some(version) => format!(
                            "workspace {axis} {} {version} does not satisfy the pack requirement {requirement_source}",
                            coordinate_selector.name
                        ),
                        None => format!(
                            "workspace {axis} {} has no exact version and does not satisfy the pack requirement {requirement_source}",
                            coordinate_selector.name
                        ),
                    };
                }
            }
        }
    }
    "complete activation evidence does not satisfy the manifest and shard selector".to_owned()
}

/// The name half of `strict_coordinate_matches`: whether the evidence names
/// the selector's coordinate at all.
fn strict_coordinate_names_match(
    selector: Option<&super::NameSelector>,
    evidence: Option<&CatalogCoordinate>,
) -> bool {
    match (selector, evidence) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(selector), Some(evidence)) => selector.name == evidence.name,
    }
}

fn selector_rank(selector: &ActivationSelector) -> EvidenceRank {
    if selector.artifact_sha256.is_some() {
        EvidenceRank::ExactArtifact
    } else if [&selector.package, &selector.module, &selector.toolchain]
        .into_iter()
        .flatten()
        .any(|coordinate| coordinate.version.is_some())
    {
        EvidenceRank::VersionedCoordinate
    } else if selector.package.is_some()
        || selector.module.is_some()
        || selector.toolchain.is_some()
    {
        EvidenceRank::NamedCoordinate
    } else {
        EvidenceRank::Language
    }
}

fn effective_control(
    manifest: &CompiledPackManifest,
    controls: &[SemanticModelActivationControl],
) -> Result<Option<SemanticModelControlAction>, String> {
    let pack_version = Version::parse(&manifest.version)
        .map_err(|error| format!("compiled pack version is invalid: {error}"))?;
    let mut matched = controls
        .iter()
        .filter(|control| {
            control.selector.pack_id == manifest.pack_id
                && control
                    .selector
                    .version
                    .as_ref()
                    .is_none_or(|requirement| requirement.matches(&pack_version))
                && control
                    .selector
                    .manifest_digest
                    .as_ref()
                    .is_none_or(|digest| digest == &manifest.content_sha256)
        })
        .map(|control| {
            let scope = match control.scope {
                SemanticModelControlScope::User => 0,
                SemanticModelControlScope::Workspace => 1,
            };
            let specificity = u8::from(control.selector.version.is_some())
                + 2 * u8::from(control.selector.manifest_digest.is_some());
            (scope, specificity, control.action)
        })
        .collect::<Vec<_>>();
    matched.sort();
    let Some(&(scope, specificity, action)) = matched.last() else {
        return Ok(None);
    };
    if matched
        .iter()
        .rev()
        .take_while(|(other_scope, other_specificity, _)| {
            *other_scope == scope && *other_specificity == specificity
        })
        .any(|(_, _, other_action)| *other_action != action)
    {
        return Err("equally specific activation controls conflict".to_owned());
    }
    Ok(Some(action))
}

fn compare_selection(left: &CandidateSelection, right: &CandidateSelection) -> Ordering {
    left.evidence_rank
        .cmp(&right.evidence_rank)
        .then_with(|| left.source_rank.cmp(&right.source_rank))
        .then_with(|| left.semantic_sha256.cmp(&right.semantic_sha256))
        .then_with(|| {
            left.active
                .manifest
                .content_sha256
                .cmp(&right.active.manifest.content_sha256)
        })
        .then_with(|| left.active.source_id.cmp(&right.active.source_id))
}

fn source_rank(kind: CatalogPackSourceKind) -> u8 {
    match kind {
        CatalogPackSourceKind::Embedded => 0,
        CatalogPackSourceKind::PreShipped => 1,
        CatalogPackSourceKind::Installed => 2,
        CatalogPackSourceKind::Generated => 3,
        CatalogPackSourceKind::WorkspaceProduced => 4,
        CatalogPackSourceKind::EphemeralWorkspace => 5,
    }
}

fn active_model_set_hash(
    active: &[CandidateSelection],
    extraction_gaps: &[ActivePackExtractionGap],
) -> String {
    let mut rows = active.iter().collect::<Vec<_>>();
    rows.sort_unstable_by(|left, right| {
        left.semantic_sha256
            .cmp(&right.semantic_sha256)
            .then_with(|| left.payload_kind.cmp(&right.payload_kind))
            .then_with(|| left.evidence_rank.cmp(&right.evidence_rank))
            .then_with(|| left.source_rank.cmp(&right.source_rank))
            .then_with(|| {
                left.active
                    .matched_evidence
                    .cmp(&right.active.matched_evidence)
            })
    });
    let mut gaps = extraction_gaps.iter().collect::<Vec<_>>();
    gaps.sort_unstable_by(|left, right| {
        left.declaration
            .cmp(&right.declaration)
            .then_with(|| left.pack_id.cmp(&right.pack_id))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.semantic-model.active-set.v2\0");
    hasher.update(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION.to_be_bytes());
    hasher.update((rows.len() as u64).to_be_bytes());
    for selection in rows {
        hash_key_part(&mut hasher, &selection.semantic_sha256);
        hasher.update([match selection.payload_kind {
            PayloadKind::DeclarationFacts => 0,
            PayloadKind::GeneratorRules => 1,
            PayloadKind::ProcedureSummaries => 2,
        }]);
        hasher.update([match selection.evidence_rank {
            EvidenceRank::Language => 0,
            EvidenceRank::NamedCoordinate => 1,
            EvidenceRank::VersionedCoordinate => 2,
            EvidenceRank::ExactArtifact => 3,
        }]);
        hasher.update([selection.source_rank]);
        hash_activation_evidence(&mut hasher, &selection.active.matched_evidence);
    }
    hasher.update((gaps.len() as u64).to_be_bytes());
    for gap in gaps {
        hash_key_part(&mut hasher, &gap.declaration);
        hash_key_part(&mut hasher, &gap.pack_id);
        hash_key_part(&mut hasher, &gap.reason);
    }
    format!("{:x}", hasher.finalize())
}

fn catalog_miss_reason(miss: &CatalogMiss) -> String {
    match miss {
        CatalogMiss::NotFound => "catalog candidate disappeared before verified load".to_owned(),
        CatalogMiss::Quarantined { reason } | CatalogMiss::Incompatible { reason } => {
            reason.clone()
        }
    }
}

fn push_request_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    reason: String,
) {
    push_explanation(
        report,
        limits,
        SemanticModelActivationExplanation {
            manifest_digest: String::new(),
            pack_id: None,
            shard_id: String::new(),
            source_kind: CatalogPackSourceKind::Embedded,
            source_id: String::new(),
            status: SemanticModelActivationStatus::Unavailable,
            reason,
        },
    );
}

fn push_loaded_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    loaded: &super::LoadedCatalogShard,
    status: SemanticModelActivationStatus,
    reason: &str,
) {
    push_explanation(
        report,
        limits,
        SemanticModelActivationExplanation {
            manifest_digest: loaded.manifest.content_sha256.clone(),
            pack_id: Some(loaded.manifest.pack_id.clone()),
            shard_id: loaded.shard.shard_id().to_owned(),
            source_kind: loaded.source_kind,
            source_id: loaded.source_id.clone(),
            status,
            reason: reason.to_owned(),
        },
    );
}

fn push_explanation(
    report: &mut SemanticModelActivationReport,
    limits: SemanticModelRuntimeLimits,
    explanation: SemanticModelActivationExplanation,
) {
    if report.explanations.len() < limits.max_explanations {
        report.explanations.push(explanation);
    } else {
        report.suppressed_explanations = report.suppressed_explanations.saturating_add(1);
    }
}

#[cfg(test)]
mod semantic_diagnostic_runtime_tests {
    use super::*;
    use crate::analyzer::SemanticDiagnosticIncompleteReason;

    #[test]
    fn runtime_outcomes_map_to_shared_suppression_reasons() {
        let report = SemanticModelActivationReport::default();
        assert_eq!(
            SemanticModelRuntimeOutcome::Cancelled(report.clone())
                .semantic_diagnostic_incomplete_reasons(),
            vec![SemanticDiagnosticIncompleteReason::Cancelled]
        );

        let incomplete = SemanticModelRuntimeOutcome::Incomplete {
            usable: None,
            report: report.clone(),
        }
        .semantic_diagnostic_incomplete_reasons();
        assert!(matches!(
            incomplete.as_slice(),
            [SemanticDiagnosticIncompleteReason::RuntimeUnavailable { detail }]
                if detail.starts_with("incomplete activation:")
        ));

        let unavailable = SemanticModelRuntimeOutcome::Unavailable(report)
            .semantic_diagnostic_incomplete_reasons();
        assert!(matches!(
            unavailable.as_slice(),
            [SemanticDiagnosticIncompleteReason::RuntimeUnavailable { detail }]
                if detail.starts_with("unavailable activation:")
        ));
    }
}

#[cfg(test)]
mod unmaterialized_call_shape_binding_tests {
    use super::*;
    use crate::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticLanguage,
        SemanticRole, SourceAnchor, SourcePosition, SourceSpan, unmaterialized_external_mount,
        unmaterialized_external_path,
    };
    use crate::analyzer::semantic_model::{
        CompilerOptions, DecodeLimits, SourceFormat, compile_source, decode_shard,
    };

    const PACK: &[u8] = br#"{
      "schema_version": 1,
      "pack_id": "test.call-shape",
      "version": "1.0.0",
      "producer": {"name": "test", "version": "1.0.0"},
      "language": "java",
      "ecosystem": "maven",
      "compatibility": {"bifrost": ">=0.8.0, <1.0.0"},
      "provenance": {"source": "https://example.invalid/call-shape"},
      "license": "Apache-2.0",
      "completeness": "complete",
      "safety": {"generated_code_only": false, "review_required": false},
      "shards": [{
        "id": "summaries",
        "activation": [{}],
        "payload": {
          "kind": "procedure_summaries",
          "summaries": [{
            "id": "summary.fixed",
            "target": {
              "path": "com/acme/Fixed.class",
              "symbol": "com.acme.Api.fixed(first, second, third)",
              "has_receiver": false,
              "parameter_count": 3
            },
            "completeness": "complete",
            "transfers": [{
              "input": {"kind": "parameter", "ordinal": 0},
              "exit_kind": "normal",
              "output": {"kind": "normal_return"}
            }]
          }, {
            "id": "summary.variadic",
            "target": {
              "path": "com/acme/Variadic.class",
              "symbol": "com.acme.Api.variadic(first, second, rest)",
              "has_receiver": false,
              "variadic": true,
              "parameter_count": 3
            },
            "completeness": "complete",
            "transfers": [{
              "input": {"kind": "parameter", "ordinal": 0},
              "exit_kind": "normal",
              "output": {"kind": "normal_return"}
            }]
          }]
        }
      }]
    }"#;

    fn target(member: &str, arity: u32) -> UnmaterializedExternalTarget {
        let position = SourcePosition::new(0, 0, 0);
        let anchor = SourceAnchor::new(
            SourceSpan::new(position, position).expect("fixture span is ordered"),
            0,
        );
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::Function, member, anchor, arity)
                .expect("fixture member is named"),
        ])
        .expect("fixture declaration is non-empty");
        let locator = SemanticLocator::new(
            unmaterialized_external_mount(),
            unmaterialized_external_path(),
            SemanticLanguage::Standard(crate::analyzer::Language::Java),
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        UnmaterializedExternalTarget::new("com.acme.Api", member, arity, false, locator)
    }

    #[test]
    fn call_shape_binding_proves_fixed_and_variadic_applicability() {
        let compiled = compile_source(SourceFormat::Json, PACK, &CompilerOptions::default())
            .expect("the call-shape fixture compiles");
        let artifact = &compiled.shards[0];
        let shard = decode_shard(
            &artifact.descriptor,
            &artifact.bytes,
            &DecodeLimits::default(),
        )
        .expect("the compiled call-shape shard decodes");
        let active = ActiveSemanticModelShard {
            manifest: compiled.manifest,
            shard,
            source_kind: CatalogPackSourceKind::Embedded,
            source_id: "test:call-shape".to_owned(),
            matched_evidence: SemanticModelActivationEvidence {
                language: "java".to_owned(),
                ecosystem: "maven".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
            evidence_rank: EvidenceRank::Language,
            source_rank: 0,
        };
        let payload = active
            .shard
            .payload()
            .procedure_summaries()
            .expect("the fixture carries procedure summaries");
        let activated = |index| ActivatedProcedureSummary {
            record: &payload[index],
            shard: &active,
            payload,
        };

        let fixed = activated(0);
        assert!(
            fixed
                .bind_unmaterialized_call_shape(&target("fixed", 3))
                .is_some(),
            "a fixed summary proves only its exact actual arity"
        );
        assert!(
            fixed
                .bind_unmaterialized_call_shape(&target("fixed", 4))
                .is_none(),
            "an opaque proof cannot be minted to relabel a fixed summary"
        );

        let variadic = activated(1);
        assert!(
            variadic
                .bind_unmaterialized_call_shape(&target("variadic", 1))
                .is_none(),
            "an actual arity below the variadic minimum has no proof"
        );
        for arity in [2, 3, 4] {
            let actual = target("variadic", arity);
            let binding = variadic
                .bind_unmaterialized_call_shape(&actual)
                .unwrap_or_else(|| panic!("variadic actual arity {arity} is applicable"));
            assert_eq!(binding.actual_locator(), actual.locator());
            assert_eq!(binding.formal_locator(), &actual.locator_for_arity(3));
            assert_eq!(binding.model_id(), "test.call-shape#summary.variadic");
            assert_eq!(
                binding.content().to_string(),
                variadic.record.content_sha256,
                "the proof binds the exact activated authored body"
            );
            assert_eq!(binding.contract_version(), 1);
            assert!(!binding.covers_overrides());
        }
    }
}

/// The active-set identity is a behavior key, not just a set of semantic
/// payload digests. Two activation contexts can retain the same payloads while
/// assigning their conflicting records opposite matcher precedence.
#[cfg(test)]
mod active_model_set_identity_tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        CompilerOptions, DecodeLimits, SourceFormat, compile_source, decode_shard,
    };

    fn procedure_selection(
        pack_id: &str,
        normal_continuation_absent: bool,
        evidence_rank: EvidenceRank,
    ) -> CandidateSelection {
        let source = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": {"name": "active-set-identity-test", "version": "1.0.0"},
            "language": "go",
            "ecosystem": "go",
            "compatibility": {"bifrost": ">=0.10.5, <1.0.0", "toolchains": []},
            "provenance": {"source": "test:active-set-identity", "revision": "reviewed"},
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{
                "id": "summaries",
                "activation": [{}],
                "payload": {
                    "kind": "procedure_summaries",
                    "summaries": [{
                        "id": format!("{pack_id}.exit"),
                        "target": {
                            "path": "src/os/proc.go",
                            "symbol": "os.Exit(code int)",
                            "has_receiver": false,
                            "parameter_count": 1
                        },
                        "completeness": "complete",
                        "normal_continuation_absent": normal_continuation_absent,
                        "transfers": [],
                        "effects": [{
                            "kind": "unknown_call_boundary",
                            "event": "test.identity.exit-boundary"
                        }]
                    }]
                }
            }]
        }))
        .expect("identity fixture serializes");
        let compiled = compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
            .unwrap_or_else(|diagnostics| panic!("identity fixture failed: {diagnostics:#?}"));
        let descriptor = compiled.shards[0].descriptor.clone();
        let shard = decode_shard(
            &descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("identity fixture decodes");
        let matched_evidence = SemanticModelActivationEvidence {
            language: "go".to_owned(),
            ecosystem: "go".to_owned(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: (evidence_rank == EvidenceRank::ExactArtifact)
                .then(|| "11".repeat(32)),
        };
        CandidateSelection {
            semantic_sha256: descriptor.semantic_sha256,
            payload_kind: descriptor.payload_kind,
            evidence_rank,
            source_rank: 0,
            active: ActiveSemanticModelShard {
                manifest: compiled.manifest,
                shard,
                source_kind: CatalogPackSourceKind::Embedded,
                source_id: format!("test:{pack_id}"),
                matched_evidence,
                evidence_rank,
                source_rank: 0,
            },
        }
    }

    fn legacy_payload_only_hash(active: &[CandidateSelection]) -> String {
        let mut rows = active
            .iter()
            .map(|selection| {
                (
                    selection.semantic_sha256.as_str(),
                    match selection.payload_kind {
                        PayloadKind::DeclarationFacts => 0u8,
                        PayloadKind::GeneratorRules => 1u8,
                        PayloadKind::ProcedureSummaries => 2u8,
                    },
                )
            })
            .collect::<Vec<_>>();
        rows.sort_unstable();
        let mut hasher = Sha256::new();
        hasher.update(b"bifrost.semantic-model.active-set.v1\0");
        hasher.update(SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION.to_be_bytes());
        hasher.update((rows.len() as u64).to_be_bytes());
        for (digest, kind) in rows {
            hasher.update((digest.len() as u64).to_be_bytes());
            hasher.update(digest.as_bytes());
            hasher.update([kind]);
        }
        format!("{:x}", hasher.finalize())
    }

    fn resolved(active: Vec<CandidateSelection>) -> ResolvedActiveSemanticModels {
        let active_model_set_hash = active_model_set_hash(&active, &[]);
        let shards = active
            .into_iter()
            .map(|selection| selection.active)
            .collect::<Vec<_>>();
        let mut report = SemanticModelActivationReport::default();
        let indexes = MatcherIndexes::build(
            &shards,
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::default(),
            &mut report,
        )
        .expect("identity fixture matcher builds");
        ResolvedActiveSemanticModels {
            active_model_set_hash,
            shards,
            indexes,
            extraction_gaps: Vec::new(),
            extraction_gaps_by_declaration: HashMap::default(),
            report,
        }
    }

    #[test]
    fn matcher_precedence_that_reverses_a_proof_changes_active_set_identity() {
        let returning_low = procedure_selection("test.returning", false, EvidenceRank::Language);
        let nonreturn_high =
            procedure_selection("test.nonreturn", true, EvidenceRank::ExactArtifact);
        let returning_high =
            procedure_selection("test.returning", false, EvidenceRank::ExactArtifact);
        let nonreturn_low = procedure_selection("test.nonreturn", true, EvidenceRank::Language);
        let first = vec![returning_low, nonreturn_high];
        let second = vec![returning_high, nonreturn_low];

        assert_eq!(
            legacy_payload_only_hash(&first),
            legacy_payload_only_hash(&second),
            "the v1 payload-only identity misses matcher precedence"
        );
        assert_ne!(
            active_model_set_hash(&first, &[]),
            active_model_set_hash(&second, &[]),
            "effective activation inputs must distinguish opposite winners"
        );

        let target = ProcedureSummaryMemberKey::new("go", "os", "Exit", false, 1);
        assert!(
            resolved(first).proves_normal_continuation_absent(target),
            "the exact-artifact non-return record wins in the first context"
        );
        assert!(
            !resolved(second).proves_normal_continuation_absent(target),
            "the exact-artifact returning record wins in the second context"
        );
    }
}

/// The conflict gate for procedure-summary lookup (#1871). The canonical member
/// key cannot tell same-arity overloads apart, so a posting legitimately carries
/// several records; whether that is one answer or a refusal is decided entirely
/// by [`procedure_claims_agree`]. These pin BOTH directions, because only the
/// second protects soundness: a weakened predicate would silently let two
/// disagreeing models resolve to whichever record happened to be indexed first.
#[cfg(test)]
mod procedure_claim_agreement_tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        CompiledConditionalResultRefinement, CompiledDeclaredEffect,
        CompiledDeclaredEffectCertainty, CompiledDeclaredEffectTiming,
        CompiledPredicateProofEffect, CompiledProcedureSummary, CompiledProcedureTarget,
        CompiledResultContract, CompiledResultPredicate, CompiledSummaryExitKind,
        CompiledSummaryInput, CompiledSummaryLocation, CompiledSummaryLocationKind,
        CompiledSummaryOutput, CompiledSummaryTransfer, Completeness,
    };

    fn transfer(input: CompiledSummaryInput) -> CompiledSummaryTransfer {
        CompiledSummaryTransfer {
            input,
            exit_kind: CompiledSummaryExitKind::Normal,
            output: CompiledSummaryOutput::NormalReturn {},
        }
    }

    /// Two records that differ in every identity field but make one claim. This
    /// is the real shape: `String.valueOf(int)` and `String.valueOf(Object)`
    /// share the canonical key and both carry parameter 0 to the return.
    fn overload(id: &str, symbol: &str) -> CompiledProcedureSummary {
        CompiledProcedureSummary {
            id: id.to_owned(),
            model_id: format!("model.{id}"),
            contract_version: 1,
            content_sha256: format!("{id:0>64}"),
            target: CompiledProcedureTarget {
                path: "java.base/java/lang/String.java".to_owned(),
                symbol: symbol.to_owned(),
                has_receiver: true,
                variadic: false,
                parameter_count: 1,
            },
            completeness: Completeness::Complete,
            covers_overrides: false,
            normal_continuation_absent: false,
            normal_result_count: None,
            locations: Vec::new(),
            transfers: vec![transfer(CompiledSummaryInput::Parameter { ordinal: 0 })],
            effects: Vec::new(),
            declared_effects: Vec::new(),
            preconditions: None,
            result_contracts: Vec::new(),
            conditional_result_refinements: Vec::new(),
            normal_return_refinements: Vec::new(),
        }
    }

    #[test]
    fn identity_fields_do_not_make_two_records_disagree() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        assert_ne!(
            left, right,
            "the two records are genuinely distinct records"
        );
        assert!(
            procedure_claims_agree(&left, &right),
            "records differing only in id, model id, digest, and target spelling make one claim"
        );
    }

    #[test]
    fn a_different_completeness_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.completeness = Completeness::Partial;
        assert!(
            !procedure_claims_agree(&left, &right),
            "completeness decides whether a run may conclude ProvenBySummary, so it must refuse"
        );
    }

    #[test]
    fn a_different_normal_continuation_claim_is_a_disagreement() {
        let mut left = overload("valueof-int", "java.lang.String.valueOf(int)");
        left.normal_continuation_absent = true;
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        assert!(
            !procedure_claims_agree(&left, &right),
            "an explicit absence claim cannot agree with an omitted claim"
        );

        right.normal_continuation_absent = true;
        assert!(
            procedure_claims_agree(&left, &right),
            "two explicit absence claims make one runtime claim"
        );
    }

    #[test]
    fn a_different_override_coverage_claim_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.covers_overrides = true;
        assert!(
            !procedure_claims_agree(&left, &right),
            "override coverage is a trust claim, so conflicting records must refuse"
        );
    }

    #[test]
    fn a_different_transfer_set_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.transfers = vec![transfer(CompiledSummaryInput::Receiver {})];
        assert!(
            !procedure_claims_agree(&left, &right),
            "a different transfer set propagates differently and must refuse"
        );
    }

    #[test]
    fn a_different_location_set_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.locations = vec![CompiledSummaryLocation {
            id: "buffer".to_owned(),
            location_kind: CompiledSummaryLocationKind::Heap,
        }];
        assert!(
            !procedure_claims_agree(&left, &right),
            "named locations are ports the transfers bind, so they are part of the claim"
        );
    }

    /// #2437: a declared effect is a claim a policy can read, so two records
    /// that disagree about it must refuse rather than resolve to whichever one
    /// the index happened to reach first.
    #[test]
    fn a_different_declared_effect_set_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.declared_effects = vec![CompiledDeclaredEffect {
            id: "acme.network_io".to_owned(),
            timing: CompiledDeclaredEffectTiming::Immediate,
            certainty: CompiledDeclaredEffectCertainty::Definite,
        }];
        assert!(
            !procedure_claims_agree(&left, &right),
            "one record claiming an effect the other does not is a disagreement"
        );

        let mut same_id_different_certainty = right.clone();
        same_id_different_certainty.declared_effects[0].certainty =
            CompiledDeclaredEffectCertainty::Possible;
        assert!(
            !procedure_claims_agree(&right, &same_id_different_certainty),
            "certainty is part of the claim, not decoration"
        );

        let mut same_id_different_timing = right.clone();
        same_id_different_timing.declared_effects[0].timing =
            CompiledDeclaredEffectTiming::Deferred;
        assert!(
            !procedure_claims_agree(&right, &same_id_different_timing),
            "timing is part of the claim, not decoration"
        );

        let mut identical = right.clone();
        identical.id = "valueof-charseq".to_owned();
        identical.model_id = "model.valueof-charseq".to_owned();
        assert!(
            procedure_claims_agree(&right, &identical),
            "two records declaring the same effects still make one claim"
        );
    }

    #[test]
    fn a_different_procedure_precondition_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.preconditions = Some(vec![CompiledOperationPrecondition {
            input: CompiledSummaryInput::Parameter { ordinal: 0 },
            predicate: CompiledResultPredicate::NonNull,
        }]);
        assert!(
            !procedure_claims_agree(&left, &right),
            "an unreviewed precondition facet cannot agree with a required predicate"
        );

        let mut reviewed_empty = left.clone();
        reviewed_empty.preconditions = Some(Vec::new());
        assert!(
            !procedure_claims_agree(&left, &reviewed_empty),
            "reviewed-empty and unreviewed are distinct procedure claims"
        );

        let mut identical = right.clone();
        identical.id = "valueof-charseq".to_owned();
        identical.model_id = "model.valueof-charseq".to_owned();
        assert!(
            procedure_claims_agree(&right, &identical),
            "identical reviewed preconditions still make one claim"
        );
    }

    #[test]
    fn a_different_result_contract_is_a_disagreement() {
        let mut left = overload("valueof-int", "java.lang.String.valueOf(int)");
        left.normal_result_count = Some(2);
        left.result_contracts = vec![CompiledResultContract {
            result_ordinal: 0,
            condition_result_ordinal: Some(1),
            predicate: Some(CompiledResultPredicate::Null),
            result_success_predicate: None,
            member_contracts: Vec::new(),
        }];
        let mut right = left.clone();
        right.result_contracts[0].predicate = Some(CompiledResultPredicate::NonNull);

        assert!(
            !procedure_claims_agree(&left, &right),
            "opposite validity predicates cannot resolve as one modeled answer"
        );

        right = left.clone();
        right.result_contracts[0].result_success_predicate = Some(CompiledResultPredicate::NonNull);
        assert!(
            !procedure_claims_agree(&left, &right),
            "a reviewed result-side success correlation is part of the modeled claim"
        );

        right.result_contracts = left.result_contracts.clone();
        right.normal_result_count = Some(3);
        assert!(
            !procedure_claims_agree(&left, &right),
            "the declared result-port shape is part of the modeled claim"
        );
    }

    #[test]
    fn a_different_normal_return_refinement_is_a_disagreement() {
        let mut left = overload("valueof-int", "java.lang.String.valueOf(int)");
        left.normal_return_refinements = vec![CompiledNormalReturnRefinement {
            parameter_ordinal: 0,
            predicate: CompiledResultPredicate::Null,
        }];
        let mut right = left.clone();
        right.normal_return_refinements[0].predicate = CompiledResultPredicate::NonNull;

        assert!(
            !procedure_claims_agree(&left, &right),
            "opposite normal-return predicates cannot resolve as one modeled answer"
        );
    }

    #[test]
    fn a_different_conditional_result_refinement_is_a_disagreement() {
        let mut left = overload("valueof-int", "java.lang.String.valueOf(int)");
        left.normal_result_count = Some(1);
        left.conditional_result_refinements = vec![CompiledConditionalResultRefinement {
            result_ordinal: 0,
            outcome: false,
            parameter_ordinal: 0,
            predicate: CompiledResultPredicate::Null,
            proof_effect: CompiledPredicateProofEffect::DoesNotEstablish,
        }];
        let mut right = left.clone();
        right.conditional_result_refinements[0].proof_effect =
            CompiledPredicateProofEffect::Establishes;

        assert!(
            !procedure_claims_agree(&left, &right),
            "opposite conditional proof effects cannot resolve as one modeled answer"
        );

        right = left.clone();
        right.conditional_result_refinements[0].outcome = true;
        assert!(
            !procedure_claims_agree(&left, &right),
            "the boolean result outcome is part of the modeled claim"
        );
    }
}
