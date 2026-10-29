use std::collections::BTreeMap;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analyzer::semantic_model::ActivationSelector;

use crate::analyzer::semantic_model::AuthoredProcedureFormal;

use crate::analyzer::semantic_model::AuthoredProcedureFormalPassingMode;

use crate::analyzer::semantic_model::AuthoredProcedureFormalVariadicKind;

use crate::analyzer::semantic_model::CatalogCoordinate;

use crate::analyzer::semantic_model::CatalogMiss;

#[cfg(test)]
use crate::analyzer::semantic_model::CompiledConcurrencyEffect;

#[cfg(test)]
use crate::analyzer::semantic_model::CompiledConditionalResultRefinement;

use crate::analyzer::semantic_model::CompiledPackManifest;

use crate::analyzer::semantic_model::CompiledProcedureSummary;

use crate::analyzer::semantic_model::CompiledProcedureTarget;

use crate::analyzer::semantic_model::CompiledResultUseObligation;

use crate::analyzer::semantic_model::MemberFact;

use crate::analyzer::semantic_model::SemanticPackSelectorQuery;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256;

use brokk_bifrost_core::analyzer::canonical_hash::write_length_prefixed;

use crate::analyzer::semantic::lexical_definitions::FormalParameterLayout;

use crate::analyzer::semantic::FormalParameterPassingMode;

use crate::analyzer::semantic::lexical_definitions::FormalParameterSlot;

use crate::analyzer::semantic::lexical_definitions::FormalVariadicKind;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::StableDigest;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::LanguageDialect;

use brokk_bifrost_core::analyzer::model::semantic_pack_realm;

use brokk_bifrost_core::hash::HashMap;

/// The encoding version of the resolved semantic-model runtime.
///
/// Rotating this value rotates every active-set identity a workspace derives
/// from its semantic packs. Java, Kotlin and Scala share one classpath and now
/// one durable index key ([`semantic_pack_realm`]), so the same active pack set
/// resolves a Kotlin or Scala call differently than the label-exact keying did.
/// A recorded identity from before this change must not satisfy the new
/// contract, so the version moves even though no pack changed. Version 8
/// retained no-concurrency-effects claims; version 9 includes directional
/// variadic summary-formal binding; version 10 retained independently
/// accepted review receipts in the active proof identity; version 11 drops
/// them again (#5218), so an identity recorded with a receipt byte does not
/// satisfy the receipt-free contract.
pub const SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION: u32 = 11;

#[doc(hidden)]
pub type DependencyEvidencePublication = (
    Box<[Language]>,
    crate::analyzer::semantic_model::DependencyDiscoveryEvidence,
);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// The reviewed proof basis attached to a result-use obligation binding.
///
/// The label is deliberately smaller than the typed basis. Query consumers
/// project the label, while the typed value prevents a language adapter from
/// silently treating an unrelated builtin as the reviewed receiver. Java's
/// existing binder continues to publish its established dispatch basis; a
/// future Java adapter can use this shared carrier after the native-engine
/// refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReviewedObligationBasis {
    DispatchAgreement,
    BuiltinReceiverAssumption(ReviewedBuiltinReceiverAssumption),
    LibcStandardDeclaration,
    PythonStandardLibraryFunction,
    /// A JavaScript receiver is proved from an exact literal/template or the
    /// unshadowed builtin `String(...)` constructor result. This is proof from
    /// source and type flow, not an ecosystem-wide receiver assumption.
    ExactLiteralReceiver,
}

impl ReviewedObligationBasis {
    pub const fn label(self) -> &'static str {
        match self {
            Self::DispatchAgreement => "dispatch_agreement",
            Self::BuiltinReceiverAssumption(_) => "builtin_receiver_assumption",
            Self::LibcStandardDeclaration => "libc_standard_declaration",
            Self::PythonStandardLibraryFunction => "python_stdlib_function",
            Self::ExactLiteralReceiver => "exact_literal_receiver",
        }
    }
}

/// A reviewed builtin receiver assumption. The receiver detail remains typed
/// in the runtime and is described by the semantic-pack provenance; only the
/// stable public basis label is projected into RQL rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReviewedBuiltinReceiverAssumption {
    PythonStr,
    RubyString,
    TypeScriptString,
}

impl ReviewedBuiltinReceiverAssumption {
    pub const fn language(self) -> &'static str {
        match self {
            Self::PythonStr => "python",
            Self::RubyString => "ruby",
            Self::TypeScriptString => "typescript",
        }
    }

    pub const fn receiver(self) -> &'static str {
        match self {
            Self::PythonStr => "builtins.str",
            Self::RubyString => "String",
            Self::TypeScriptString => "String",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewedObligationBindFailure {
    NoObligation,
    LanguageMismatch,
    EvidenceUnselected,
    CallShapeMismatch,
    BasisMismatch,
}

/// The result of binding reviewed obligations to one exact call shape.
#[derive(Debug, Clone)]
pub struct ReviewedObligationBinding {
    #[doc(hidden)]
    pub record: std::sync::Arc<crate::analyzer::semantic_model::CompiledProcedureSummary>,
    #[doc(hidden)]
    pub basis: ReviewedObligationBasis,
    #[doc(hidden)]
    pub ordinary_heap_unchanged: bool,
    #[doc(hidden)]
    pub covers_overrides: bool,
}

impl ReviewedObligationBinding {
    pub fn obligations(&self) -> &[CompiledResultUseObligation] {
        &self.record.result_use_obligations
    }

    pub const fn basis(&self) -> ReviewedObligationBasis {
        self.basis
    }

    pub const fn ordinary_heap_unchanged(&self) -> bool {
        self.ordinary_heap_unchanged
    }

    pub const fn covers_overrides(&self) -> bool {
        self.covers_overrides
    }
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

/// A request to select a named pack without claiming installed coordinates.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApproximateSemanticModelExpectation {
    pub language: String,
    pub ecosystem: String,
    pub pack_id: String,
}

#[derive(Debug, Clone)]
pub struct SemanticModelActivationRequest {
    pub bifrost_version: Version,
    /// Approximate expectations are never exact workspace evidence.
    pub approximate_standard_libraries: Vec<ApproximateSemanticModelExpectation>,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelActivationPhaseMeasurements {
    pub selection_nanos: u64,
    pub decode_hydration_nanos: u64,
    pub matcher_construction_nanos: u64,
    pub catalog_sql_statements: u64,
}

/// Measurements captured when the combined model and overlay budget is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SemanticModelOverlayBudgetExceeded {
    pub loaded_records: usize,
    pub models_retained_bytes: u64,
    pub overlay_working_bytes: u64,
    pub combined_budget_bytes: u64,
}

/// Cost and retained size of the declaration overlay paired with one active
/// semantic-model publication.
///
/// `publication_nanos` covers overlay construction and the wait to enter the
/// publication critical section. It excludes work performed after the
/// immutable snapshot is created. A cached acquisition returns the original
/// measurement rather than timing a lookup as though it rebuilt the overlay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelOverlayMeasurement {
    pub publication_nanos: u64,
    pub retained_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivePackExtractionGap {
    pub pack_id: String,
    pub declaration: String,
    pub reason: String,
}

#[doc(hidden)]
pub fn summary_formal_layout(target: &CompiledProcedureTarget) -> Option<FormalParameterLayout> {
    if target.formals.len() != target.parameter_count as usize {
        return None;
    }
    let sentinel = brokk_bifrost_core::analyzer::model::Range {
        start_byte: 0,
        end_byte: 0,
        start_line: 0,
        end_line: 0,
    };
    Some(FormalParameterLayout {
        slots: target
            .formals
            .iter()
            .map(|formal| FormalParameterSlot {
                names: vec![formal.name.clone()],
                declaration_range: sentinel,
                receiver: false,
                passing_mode: match formal.passing_mode {
                    AuthoredProcedureFormalPassingMode::PositionalOnly => {
                        FormalParameterPassingMode::PositionalOnly
                    }
                    AuthoredProcedureFormalPassingMode::PositionalOrNamed => {
                        FormalParameterPassingMode::PositionalOrNamed
                    }
                    AuthoredProcedureFormalPassingMode::NamedOnly => {
                        FormalParameterPassingMode::NamedOnly
                    }
                },
                variadic: formal.variadic_kind.map(|kind| match kind {
                    AuthoredProcedureFormalVariadicKind::Positional => {
                        FormalVariadicKind::Positional
                    }
                    AuthoredProcedureFormalVariadicKind::Keyword => FormalVariadicKind::Keyword,
                    AuthoredProcedureFormalVariadicKind::Both => FormalVariadicKind::Both,
                }),
                default_range: formal.optional.then_some(sentinel),
            })
            .collect(),
        python_binding: None,
    })
}

#[doc(hidden)]
pub fn mapping_reorders_fixed_formals(
    mapping: &[u32],
    formals: &[AuthoredProcedureFormal],
) -> bool {
    // Fixed-arity summaries without declared slots still carry the exact
    // external mapping; only its identity permutation leaves inputs in place.
    if formals.is_empty() {
        return mapping
            .iter()
            .enumerate()
            .any(|(actual, formal)| actual != *formal as usize);
    }
    let mut previous_fixed_formal = None;
    for formal in mapping {
        let Some(formal_shape) = formals.get(*formal as usize) else {
            return true;
        };
        if formal_shape.variadic_kind.is_some() {
            continue;
        }
        if previous_fixed_formal.is_some_and(|previous| *formal < previous) {
            return true;
        }
        previous_fixed_formal = Some(*formal);
    }
    false
}

#[doc(hidden)]
pub fn evidence_is_exact_python_distribution_artifact(
    evidence: &SemanticModelActivationEvidence,
) -> bool {
    if evidence.language != "python" || evidence.ecosystem != "python" {
        return false;
    }
    let (Some(package), Some(artifact_sha256)) = (
        evidence.package.as_ref(),
        evidence.artifact_sha256.as_deref(),
    ) else {
        return false;
    };
    if !package.name.starts_with("pkg:pypi/") || package.version.is_some() {
        return false;
    }
    let artifact = crate::analyzer::semantic_model::csmi::CsmiArtifactSelector {
        purl: package.name.clone(),
        version_range: None,
        digests: vec![crate::analyzer::semantic_model::csmi::CsmiArtifactDigest {
            algorithm: crate::analyzer::semantic_model::csmi::CsmiDigestAlgorithm::Sha256,
            coverage: "artifact".to_owned(),
            canonicalization: None,
            value: artifact_sha256.to_owned(),
        }],
    };
    crate::analyzer::semantic_model::csmi::validate_python_artifact(&artifact).is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelMatchDisposition {
    Empty,
    Unique,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureSummaryTargetKey<'a> {
    pub language: &'a str,
    pub path: &'a str,
    pub symbol: &'a str,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureSummaryDeclarationKey<'a> {
    pub language: &'a str,
    pub path: &'a str,
    pub member: &'a str,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

impl<'a> ProcedureSummaryDeclarationKey<'a> {
    pub fn new(
        language: &'a str,
        path: &'a str,
        member: &'a str,
        has_receiver: bool,
        parameter_count: u32,
    ) -> Self {
        Self {
            language,
            path,
            member,
            has_receiver,
            parameter_count,
        }
    }
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

/// Analyzer-minted evidence that one activated authored summary applies to one
/// exact unmaterialized-external call shape.
///
/// The fields stay private so a downstream consumer cannot relabel a fixed
/// summary by manufacturing another actual arity. Flow may derive its own
/// internal summary identity from the proven formal locator and model id, then
/// must still check that identity against the lowered summary it publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmaterializedExternalSummaryCallShapeBinding {
    #[doc(hidden)]
    pub actual_locator: SemanticLocator,
    #[doc(hidden)]
    pub actual_to_formal: Option<Box<[u32]>>,
    #[doc(hidden)]
    pub formal_locator: SemanticLocator,
    #[doc(hidden)]
    pub model_id: Box<str>,
    #[doc(hidden)]
    pub content: StableDigest,
    #[doc(hidden)]
    pub contract_version: u32,
    #[doc(hidden)]
    pub covers_overrides: bool,
}

impl UnmaterializedExternalSummaryCallShapeBinding {
    pub fn actual_locator(&self) -> &SemanticLocator {
        &self.actual_locator
    }

    /// Proven formal ordinal for each actual argument. Generic runtime calls
    /// retain their established positional binding with no explicit map.
    pub fn actual_to_formal(&self) -> Option<&[u32]> {
        self.actual_to_formal.as_deref()
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

/// Applicability coverage is independent of selected model presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureSummaryApplicability {
    Complete,
    Incomplete,
}

#[doc(hidden)]
pub enum ProcedureSummaryAcceptance {
    Reject,
    Accept(Option<Box<[u32]>>),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct RecordAddress {
    #[doc(hidden)]
    pub shard: u32,
    #[doc(hidden)]
    pub record: u32,
}

#[derive(Debug, Default, Clone)]
#[doc(hidden)]
pub struct ProcedureSummaryShapePostings {
    #[doc(hidden)]
    pub fixed: HashMap<(bool, u32), Vec<RecordAddress>>,
    /// Variadic postings keyed by total formal count, including the final rest
    /// formal, for exact declaration lookup.
    #[doc(hidden)]
    pub variadic: BTreeMap<(bool, u32), Vec<RecordAddress>>,
    /// Applicability postings keyed by the minimum number of direct actuals
    /// required by structured fixed formals.
    #[doc(hidden)]
    pub variadic_by_minimum_arity: BTreeMap<(bool, u32), Vec<RecordAddress>>,
    /// Optional-formal postings are keyed by receiver shape, minimum required
    /// actual count, and total formal count for exact external-call binding.
    #[doc(hidden)]
    pub optional_fixed: BTreeMap<(bool, u32, u32), Vec<RecordAddress>>,
    /// Coarse construction hint, split by receiver shape. A true bit says only
    /// that some indexed record authored the claim; matcher precedence and
    /// conflicts still decide the effective candidate index below.
    #[doc(hidden)]
    pub raw_normal_continuation_absence_claim: [bool; 2],
}

#[doc(hidden)]
pub type ProcedureSummaryTargetPostings =
    HashMap<String, HashMap<String, HashMap<String, ProcedureSummaryShapePostings>>>;

#[derive(Debug, Default)]
#[doc(hidden)]
pub struct NormalContinuationAbsenceMemberCandidates {
    #[doc(hidden)]
    pub receiverless_owners: Vec<String>,
    #[doc(hidden)]
    pub receiver_owners: Vec<String>,
}

impl NormalContinuationAbsenceMemberCandidates {
    fn owners(&self, has_receiver: bool) -> &[String] {
        if has_receiver {
            &self.receiver_owners
        } else {
            &self.receiverless_owners
        }
    }

    #[doc(hidden)]
    pub fn owners_mut(&mut self, has_receiver: bool) -> &mut Vec<String> {
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
///
/// It is keyed by [`semantic_pack_realm`], the same durable key the procedure
/// summary postings it is built from use, so a caller's own language label
/// reaches the candidates a pack declared for any language of that realm.
#[derive(Debug, Default)]
#[doc(hidden)]
pub struct NormalContinuationAbsenceCandidateIndex {
    #[doc(hidden)]
    pub by_language: HashMap<String, HashMap<String, NormalContinuationAbsenceMemberCandidates>>,
}

impl NormalContinuationAbsenceCandidateIndex {
    #[doc(hidden)]
    pub fn has_language(&self, language: &str) -> bool {
        self.by_language
            .get(semantic_pack_realm(language))
            .is_some_and(|members| !members.is_empty())
    }

    #[doc(hidden)]
    pub fn owners(&self, language: &str, member: &str, has_receiver: bool) -> &[String] {
        self.by_language
            .get(semantic_pack_realm(language))
            .and_then(|members| members.get(member))
            .map(|candidates| candidates.owners(has_receiver))
            .unwrap_or_default()
    }
}

#[doc(hidden)]
pub fn record_address(shard: u32, record: usize) -> Result<RecordAddress, String> {
    Ok(RecordAddress {
        shard,
        record: u32::try_from(record)
            .map_err(|_| "semantic-model record address exceeds u32".to_owned())?,
    })
}

#[doc(hidden)]
pub fn poll_matcher_cancellation(
    cancellation: &CancellationToken,
    records_visited: usize,
) -> Result<(), String> {
    if records_visited.is_multiple_of(1_024) && cancellation.is_cancelled() {
        return Err("semantic-model matcher construction cancelled".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn insert_posting<K: Eq + std::hash::Hash>(
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

#[doc(hidden)]
pub fn charge_posting_entry(
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

#[doc(hidden)]
pub fn procedure_summary_minimum_actual_count(target: &CompiledProcedureTarget) -> u32 {
    if target.formals.is_empty() {
        return target.parameter_count.saturating_sub(1);
    }
    u32::try_from(
        target
            .formals
            .iter()
            .filter(|formal| !formal.optional && formal.variadic_kind.is_none())
            .count(),
    )
    .expect("validated procedure formal count fits u32")
}

#[doc(hidden)]
pub fn charge_index_entry(
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
#[doc(hidden)]
pub fn insert_procedure_posting(
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
        charge_posting_entry(
            key_bytes.saturating_add(size_of::<u32>()),
            entries,
            working_bytes,
            limits,
        )?;
        shapes
            .variadic_by_minimum_arity
            .entry((
                target.has_receiver,
                procedure_summary_minimum_actual_count(target),
            ))
            .or_default()
            .push(address);
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
#[doc(hidden)]
pub fn insert_member_name(
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
#[doc(hidden)]
pub fn procedure_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.completeness == right.completeness
        && left.ordinary_heap_unchanged == right.ordinary_heap_unchanged
        && left.no_concurrency_effects == right.no_concurrency_effects
        && left.covers_overrides == right.covers_overrides
        && left.normal_continuation_absent == right.normal_continuation_absent
        && left.normal_result_count == right.normal_result_count
        && left.locations == right.locations
        && left.transfers == right.transfers
        && left.effects == right.effects
        && left.concurrency_effects == right.concurrency_effects
        && left.declared_effects == right.declared_effects
        && left.preconditions == right.preconditions
        && left.result_contracts == right.result_contracts
        && left.result_use_obligations == right.result_use_obligations
        && left.conditional_result_refinements == right.conditional_result_refinements
        && left.conditional_indirect_writes == right.conditional_indirect_writes
        && left.normal_return_refinements == right.normal_return_refinements
        && left.normal_return_type_refinements == right.normal_return_type_refinements
        && left.class_decorator_identity == right.class_decorator_identity
        && left.target.formals == right.target.formals
}

#[doc(hidden)]
pub fn fixed_and_variadic_postings<'a>(
    shapes: &'a ProcedureSummaryShapePostings,
    has_receiver: bool,
    parameter_count: u32,
) -> impl Iterator<Item = &'a Vec<RecordAddress>> + 'a {
    shapes
        .fixed
        .get(&(has_receiver, parameter_count))
        .into_iter()
        .chain(
            shapes
                .variadic_by_minimum_arity
                .range((has_receiver, 0)..=(has_receiver, parameter_count))
                .map(|(_, posting)| posting),
        )
}

#[doc(hidden)]
pub fn procedure_declaration_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.target.variadic == right.target.variadic
        && left.target.formals == right.target.formals
        && procedure_claims_agree(left, right)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelRuntimeLifecycle {
    Cached,
    Built,
    Uncached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub enum EvidenceRank {
    Language,
    NamedCoordinate,
    VersionedCoordinate,
    ExactArtifact,
}

#[doc(hidden)]
pub fn runtime_request_key(request: &SemanticModelActivationRequest) -> Result<String, String> {
    let CanonicalActivationEvidence {
        evidence,
        approximate_standard_libraries,
    } = validate_and_canonicalize_request(request)?;
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
    hasher.update(b"bifrost.semantic-model.runtime-request.v3\0");
    hash_key_part(&mut hasher, &request.bifrost_version.to_string());
    hasher.update(
        (crate::analyzer::semantic_model::SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS.len() as u64)
            .to_be_bytes(),
    );
    for schema_version in crate::analyzer::semantic_model::SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS
    {
        hasher.update(schema_version.to_be_bytes());
    }
    for row in &evidence {
        hash_activation_evidence(&mut hasher, row);
    }
    hasher.update((approximate_standard_libraries.len() as u64).to_be_bytes());
    for expectation in &approximate_standard_libraries {
        hash_key_part(&mut hasher, &expectation.language);
        hash_key_part(&mut hasher, &expectation.ecosystem);
        hash_key_part(&mut hasher, &expectation.pack_id);
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

#[doc(hidden)]
pub fn hash_key_part(hasher: &mut Sha256, value: &str) {
    write_length_prefixed(hasher, value.as_bytes());
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

#[doc(hidden)]
pub fn hash_activation_evidence(hasher: &mut Sha256, evidence: &SemanticModelActivationEvidence) {
    hash_key_part(hasher, &evidence.language);
    hash_key_part(hasher, &evidence.ecosystem);
    hash_optional_coordinate(hasher, evidence.package.as_ref());
    hash_optional_coordinate(hasher, evidence.module.as_ref());
    hash_optional_coordinate(hasher, evidence.toolchain.as_ref());
    hash_optional_key_part(hasher, evidence.target.as_deref());
    hash_optional_key_part(hasher, evidence.configuration.as_deref());
    hash_optional_key_part(hasher, evidence.artifact_sha256.as_deref());
}

#[doc(hidden)]
pub struct CanonicalActivationEvidence {
    pub evidence: Vec<SemanticModelActivationEvidence>,
    pub approximate_standard_libraries: Vec<ApproximateSemanticModelExpectation>,
}

#[doc(hidden)]
pub fn validate_and_canonicalize_request(
    request: &SemanticModelActivationRequest,
) -> Result<CanonicalActivationEvidence, String> {
    if request
        .evidence
        .len()
        .saturating_add(request.approximate_standard_libraries.len())
        > request.limits.max_evidence_rows
    {
        return Err("semantic-model activation evidence budget exceeded".to_owned());
    }
    if request.controls.len() > request.limits.max_controls {
        return Err("semantic-model activation control budget exceeded".to_owned());
    }
    for expectation in &request.approximate_standard_libraries {
        if expectation.language.is_empty()
            || expectation.ecosystem.is_empty()
            || expectation.pack_id.is_empty()
        {
            return Err(
                "approximate activation expectation must name its language, ecosystem and pack"
                    .to_owned(),
            );
        }
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
    let mut approximate_standard_libraries = request.approximate_standard_libraries.clone();
    approximate_standard_libraries.sort();
    approximate_standard_libraries.dedup();
    Ok(CanonicalActivationEvidence {
        evidence,
        approximate_standard_libraries,
    })
}

#[doc(hidden)]
pub fn evidence_query(
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
#[doc(hidden)]
pub fn semantic_pack_language(label: &str) -> &str {
    if LanguageDialect::from_config_label(label) == Some(LanguageDialect::TypeScriptTsx) {
        LanguageDialect::TypeScriptTsx.semantic_pack_label()
    } else {
        label
    }
}

/// One version requirement a strict activation satisfied, with the workspace
/// version that satisfied it.
///
/// A pack declares the compatible range its extracted API surface serves, so
/// "this pack activated" no longer implies "the workspace runs the exact build
/// the pack was extracted from". The activation decision must therefore name
/// which requirement admitted the workspace (#3465). The matcher is the only
/// place that decides this, so it is the only place that reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct MatchedVersionRequirement {
    axis: &'static str,
    name: String,
    requirement: String,
    version: Version,
}

impl MatchedVersionRequirement {
    #[doc(hidden)]
    pub fn describe(&self) -> String {
        format!(
            "matched {} {} {} against the pack requirement {}",
            self.axis, self.name, self.version, self.requirement
        )
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct StrictActivationMatch {
    #[doc(hidden)]
    pub evidence_rank: EvidenceRank,
    #[doc(hidden)]
    pub matched_evidence: SemanticModelActivationEvidence,
    #[doc(hidden)]
    pub matching_evidence: Vec<SemanticModelActivationEvidence>,
    #[doc(hidden)]
    pub matched_requirements: Vec<MatchedVersionRequirement>,
}

#[doc(hidden)]
pub fn strict_activation_match(
    manifest: &CompiledPackManifest,
    selectors: &[crate::analyzer::semantic_model::ActivationSelector],
    evidence: &[SemanticModelActivationEvidence],
    bifrost_version: &Version,
) -> Option<StrictActivationMatch> {
    if !manifest
        .compatibility
        .matches_engine(manifest.schema_version, bifrost_version)
        .ok()?
    {
        return None;
    }
    let toolchains = manifest
        .compatibility
        .toolchains
        .iter()
        .map(|constraint| {
            VersionReq::parse(&constraint.requirement)
                .ok()
                .map(|requirement| (constraint, requirement))
        })
        .collect::<Option<Vec<_>>>()?;
    let scoped = |row: &&SemanticModelActivationEvidence| {
        semantic_pack_language(&row.language) == manifest.language
            && row.ecosystem == manifest.ecosystem
            && toolchains.iter().all(|(constraint, requirement)| {
                row.toolchain.as_ref().is_some_and(|toolchain| {
                    toolchain.name == constraint.name
                        && toolchain
                            .version
                            .as_ref()
                            .is_some_and(|version| requirement.matches(version))
                })
            })
    };
    let mut matched_requirements = Vec::new();
    let (evidence_rank, matched_evidence, selector) = selectors
        .iter()
        .flat_map(|selector| {
            evidence
                .iter()
                .filter(move |row| scoped(row) && strict_selector_matches(selector, row))
                .map(move |row| (selector_rank(selector), row.clone(), selector))
        })
        .max_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)))?;
    let mut matching_evidence = selectors
        .iter()
        .filter(|selector| selector_rank(selector) == evidence_rank)
        .flat_map(|selector| {
            evidence
                .iter()
                .filter(move |row| scoped(row) && strict_selector_matches(selector, row))
                .cloned()
        })
        .collect::<Vec<_>>();
    matching_evidence.sort();
    matching_evidence.dedup();
    debug_assert!(matching_evidence.contains(&matched_evidence));
    for (constraint, _) in &toolchains {
        let version = matched_evidence
            .toolchain
            .as_ref()
            .and_then(|toolchain| toolchain.version.as_ref())
            .expect("a matched toolchain requirement has a version");
        push_matched_requirement(
            &mut matched_requirements,
            "toolchain",
            &constraint.name,
            &constraint.requirement,
            version,
        );
    }
    for (axis, coordinate_selector, coordinate_evidence) in [
        (
            "package",
            selector.package.as_ref(),
            matched_evidence.package.as_ref(),
        ),
        (
            "module",
            selector.module.as_ref(),
            matched_evidence.module.as_ref(),
        ),
        (
            "toolchain",
            selector.toolchain.as_ref(),
            matched_evidence.toolchain.as_ref(),
        ),
    ] {
        let (Some(coordinate_selector), Some(coordinate_evidence)) =
            (coordinate_selector, coordinate_evidence)
        else {
            continue;
        };
        let (Some(requirement), Some(version)) =
            (&coordinate_selector.version, &coordinate_evidence.version)
        else {
            continue;
        };
        push_matched_requirement(
            &mut matched_requirements,
            axis,
            &coordinate_selector.name,
            requirement,
            version,
        );
    }
    Some(StrictActivationMatch {
        evidence_rank,
        matched_evidence,
        matching_evidence,
        matched_requirements,
    })
}

/// Record one satisfied requirement, keeping the first statement of a
/// requirement that a manifest constraint and a shard selector both carry.
fn push_matched_requirement(
    matched: &mut Vec<MatchedVersionRequirement>,
    axis: &'static str,
    name: &str,
    requirement: &str,
    version: &Version,
) {
    if matched.iter().any(|existing| {
        existing.axis == axis && existing.name == name && existing.requirement == requirement
    }) {
        return;
    }
    matched.push(MatchedVersionRequirement {
        axis,
        name: name.to_owned(),
        requirement: requirement.to_owned(),
        version: version.clone(),
    });
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
    selector: Option<&crate::analyzer::semantic_model::NameSelector>,
    evidence: Option<&CatalogCoordinate>,
) -> bool {
    match (selector, evidence) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(selector), Some(evidence))
            if !strict_coordinate_names_match(Some(selector), Some(evidence)) =>
        {
            false
        }
        (Some(selector), Some(evidence)) => match (&selector.version, &evidence.version) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(requirement), Some(version)) => {
                coordinate_version_matches(requirement, version).is_ok_and(std::convert::identity)
            }
        },
    }
}

/// Explain a failed strict activation match. When the evidence names a
/// required coordinate but an exact version requirement rejects it, the
/// explanation names the workspace version and the pack requirement (#1884).
/// When no evidence row names a coordinate the selector requires at all, the
/// explanation names the missing coordinate and the selector's remaining
/// predicates, so a caller can act on it (#3462). When a row names the
/// coordinate but misses the selector's target, configuration, or artifact
/// digest, the explanation names those predicates (#3464). Every other
/// rejection keeps the generic statement.
#[doc(hidden)]
pub fn strict_activation_mismatch_reason(
    manifest: &CompiledPackManifest,
    selectors: &[crate::analyzer::semantic_model::ActivationSelector],
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
    let mut unmet_predicates = None;
    for selector in selectors {
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
            let mut unmet = Vec::new();
            if !selector.targets.is_empty()
                && !row
                    .target
                    .as_ref()
                    .is_some_and(|target| selector.targets.contains(target))
            {
                unmet.push(format!("target {}", selector.targets.join(", ")));
            }
            if !selector.configurations.is_empty()
                && !row
                    .configuration
                    .as_ref()
                    .is_some_and(|configuration| selector.configurations.contains(configuration))
            {
                unmet.push(format!(
                    "profile configuration {}",
                    selector.configurations.join(", ")
                ));
            }
            if let Some(expected) = &selector.artifact_sha256
                && row.artifact_sha256.as_ref() != Some(expected)
            {
                unmet.push(format!("artifact sha256 {expected}"));
            }
            if !unmet.is_empty() {
                unmet_predicates.get_or_insert_with(|| {
                    named_coordinate_unmet_predicates_reason(selector, &unmet)
                });
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
    for selector in selectors {
        let named = scoped().any(|row| {
            strict_coordinate_names_match(selector.package.as_ref(), row.package.as_ref())
                && strict_coordinate_names_match(selector.module.as_ref(), row.module.as_ref())
                && strict_coordinate_names_match(
                    selector.toolchain.as_ref(),
                    row.toolchain.as_ref(),
                )
        });
        if !named && let Some(reason) = missing_activation_evidence_reason(selector) {
            return reason;
        }
    }
    unmet_predicates.unwrap_or_else(|| {
        "complete activation evidence does not satisfy the manifest and shard selector".to_owned()
    })
}

/// Name the selector predicates an evidence row that names the selector's
/// coordinate does not satisfy. A declared toolchain names the coordinate of a
/// pack whose selector also binds the exact artifact it was produced from, and
/// without this the rejection read as the generic statement.
fn named_coordinate_unmet_predicates_reason(
    selector: &ActivationSelector,
    unmet: &[String],
) -> String {
    let named = [
        ("package", &selector.package),
        ("module", &selector.module),
        ("toolchain", &selector.toolchain),
    ]
    .into_iter()
    .filter_map(|(axis, coordinate)| {
        coordinate
            .as_ref()
            .map(|coordinate| format!("{axis} {}", coordinate.name))
    })
    .collect::<Vec<_>>();
    let evidence = if named.is_empty() {
        "the language and ecosystem".to_owned()
    } else {
        named.join(" and ")
    };
    format!(
        "activation evidence names {evidence}, but the shard selector also requires {}",
        unmet.join(", ")
    )
}

/// Name the activation evidence a selector requires when no evidence row names
/// its coordinate, or `None` for a selector that names none.
///
/// A selector may additionally require exact profile configurations, artifact
/// digests, or targets; an evidence row alone does not satisfy those, so the
/// reason lists them beside the missing coordinate.
fn missing_activation_evidence_reason(selector: &ActivationSelector) -> Option<String> {
    let (axis, coordinate) = match (&selector.package, &selector.module, &selector.toolchain) {
        (Some(package), _, _) => ("package", package),
        (_, Some(module), _) => ("module", module),
        (_, _, Some(toolchain)) => ("toolchain", toolchain),
        _ => return None,
    };
    let mut requirements = Vec::new();
    if !selector.targets.is_empty() {
        requirements.push(format!("target {}", selector.targets.join(", ")));
    }
    if !selector.configurations.is_empty() {
        requirements.push(format!(
            "profile configuration {}",
            selector.configurations.join(", ")
        ));
    }
    if let Some(artifact_sha256) = &selector.artifact_sha256 {
        requirements.push(format!("artifact sha256 {artifact_sha256}"));
    }
    let requirements = if requirements.is_empty() {
        String::new()
    } else {
        format!("; the shard selector requires {}", requirements.join(", "))
    };
    Some(format!(
        "no activation evidence names {axis} {}{requirements}",
        coordinate.name
    ))
}

/// The name half of `strict_coordinate_matches`: whether the evidence names
/// the selector's coordinate at all.
pub(crate) fn strict_coordinate_names_match(
    selector: Option<&crate::analyzer::semantic_model::NameSelector>,
    evidence: Option<&CatalogCoordinate>,
) -> bool {
    match (selector, evidence) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(selector), Some(evidence)) => selector.name == evidence.name,
    }
}

pub(crate) fn coordinate_version_matches(
    requirement: &str,
    version: &Version,
) -> Result<bool, semver::Error> {
    Ok(VersionReq::parse(requirement)?.matches(version))
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

#[doc(hidden)]
pub fn effective_control(
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

#[doc(hidden)]
pub fn catalog_miss_reason(miss: &CatalogMiss) -> String {
    match miss {
        CatalogMiss::IndexReconciliationRequired {
            manifest_digest,
            shard_id,
        } => crate::analyzer::semantic_model::catalog::CatalogError::IndexReconciliationRequired {
            manifest_digest: manifest_digest.clone(),
            shard_id: shard_id.clone(),
        }
        .to_string(),
        CatalogMiss::NotFound => "catalog candidate disappeared before verified load".to_owned(),
        CatalogMiss::Quarantined { reason } | CatalogMiss::Incompatible { reason } => {
            reason.clone()
        }
    }
}

#[cfg(test)]
mod semantic_diagnostic_runtime_tests {

    use crate::analyzer::semantic_model::runtime::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#6233: the activation request key ignored approximate stdlib expectations")]
    fn runtime_request_key_binds_canonical_approximate_expectations() {
        let mut request = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: Version::parse("0.12.0").unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let exact_key = runtime_request_key(&request).unwrap();
        let expectation = ApproximateSemanticModelExpectation {
            language: "rust".to_owned(),
            ecosystem: "cargo".to_owned(),
            pack_id: "bifrost.rust-stdlib".to_owned(),
        };
        request
            .approximate_standard_libraries
            .push(expectation.clone());
        let approximate_key = runtime_request_key(&request).unwrap();
        assert_ne!(exact_key, approximate_key);
        request
            .approximate_standard_libraries
            .push(expectation.clone());
        assert_eq!(approximate_key, runtime_request_key(&request).unwrap());
        let other = ApproximateSemanticModelExpectation {
            pack_id: "test.other-stdlib".to_owned(),
            ..expectation.clone()
        };
        request.approximate_standard_libraries = vec![expectation.clone(), other.clone()];
        let multiple_key = runtime_request_key(&request).unwrap();
        assert_ne!(approximate_key, multiple_key);
        request.approximate_standard_libraries =
            vec![other.clone(), expectation.clone(), other, expectation];
        assert_eq!(multiple_key, runtime_request_key(&request).unwrap());
    }

    #[test]
    #[hardwon("#3815: cached pack activation ignored the supported schema and engine contract")]
    fn runtime_request_key_binds_engine_and_supported_schema_contract() {
        let request = |bifrost_version| SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version,
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let version = Version::parse("0.12.0").unwrap();
        let key = runtime_request_key(&request(version.clone())).unwrap();
        assert_ne!(
            key,
            runtime_request_key(&request(Version::parse("0.13.0").unwrap())).unwrap()
        );
        let _supported_schemas_are_bound_by_runtime_request_key =
            crate::analyzer::semantic_model::SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS;
    }
}

/// The conflict gate for procedure-summary lookup (#1871). The canonical member
/// key cannot tell same-arity overloads apart, so a posting legitimately carries
/// several records. The #2738 regression pins that conflicting override
/// coverage cannot be resolved to whichever model was indexed first.
#[cfg(test)]
mod procedure_claim_agreement_tests {

    use crate::analyzer::semantic_model::runtime::*;

    use crate::analyzer::semantic_model::CompiledPredicateProofEffect;

    use crate::analyzer::semantic_model::CompiledProcedureSummary;

    use crate::analyzer::semantic_model::CompiledProcedureTarget;

    use crate::analyzer::semantic_model::CompiledResultPredicate;

    use crate::analyzer::semantic_model::CompiledSummaryExitKind;

    use crate::analyzer::semantic_model::CompiledSummaryInput;

    use crate::analyzer::semantic_model::CompiledSummaryOutput;

    use crate::analyzer::semantic_model::CompiledSummaryTransfer;

    use crate::analyzer::semantic_model::Completeness;
    use brokk_bifrost_test_macros::hardwon;

    fn transfer(input: CompiledSummaryInput) -> CompiledSummaryTransfer {
        CompiledSummaryTransfer {
            input,
            exit_kind: CompiledSummaryExitKind::Normal,
            output: CompiledSummaryOutput::NormalReturn {},
            value_transfer: None,
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
                formals: Vec::new(),
            },
            completeness: Completeness::Complete,
            ordinary_heap_unchanged: false,
            no_concurrency_effects: false,
            covers_overrides: false,
            normal_continuation_absent: false,
            normal_result_count: None,
            locations: Vec::new(),
            transfers: vec![transfer(CompiledSummaryInput::Parameter { ordinal: 0 })],
            transfer_partitions: Vec::new(),
            effects: Vec::new(),
            concurrency_effects: Vec::new(),
            returned_callables: Vec::new(),
            declared_effects: Vec::new(),
            preconditions: None,
            result_contracts: Vec::new(),
            result_use_obligations: Vec::new(),
            conditional_result_refinements: Vec::new(),
            conditional_indirect_writes: Vec::new(),
            normal_return_refinements: Vec::new(),
            normal_return_type_refinements: Vec::new(),
            class_decorator_identity: None,
        }
    }

    #[test]
    #[hardwon("#2738: same-key interface contract claims disagreed on override coverage")]
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
    fn concurrency_claims_make_same_shape_records_disagree() {
        let left = overload("1", "valueOf(java.lang.Object)");
        let mut right = overload("2", "valueOf(int)");
        right
            .concurrency_effects
            .push(CompiledConcurrencyEffect::TaskSpawn {
                callable: CompiledSummaryInput::Parameter { ordinal: 0 },
                group: None,
                condition: None,
                timer: None,
            });
        assert!(!procedure_claims_agree(&left, &right));
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
    fn a_different_ordinary_heap_unchanged_claim_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.ordinary_heap_unchanged = true;
        assert!(
            !procedure_claims_agree(&left, &right),
            "heap-preservation certification is a trust claim, so conflicting records must refuse"
        );

        let mut matching = left.clone();
        matching.ordinary_heap_unchanged = true;
        assert!(
            procedure_claims_agree(&matching, &right),
            "identical heap-preservation certifications still make one claim"
        );
    }

    #[test]
    fn a_different_no_concurrency_effects_claim_is_a_disagreement() {
        let left = overload("valueof-int", "java.lang.String.valueOf(int)");
        let mut right = overload(
            "valueof-object",
            "java.lang.String.valueOf(java.lang.Object)",
        );
        right.no_concurrency_effects = true;
        assert!(
            !procedure_claims_agree(&left, &right),
            "the explicit no-concurrency claim changes whether a call boundary is modeled"
        );

        let mut matching = left.clone();
        matching.no_concurrency_effects = true;
        assert!(procedure_claims_agree(&matching, &right));
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
