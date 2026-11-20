use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use crate::analyzer::identifier::define_identifier;
use crate::analyzer::semantic::partial_flow::PartialFlowPort;
use crate::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CallSiteHandle, CandidateCoverage, ControlEdgeKind,
    DeclarationLocator, DurableCallContext, DurableObjectIdentity, DurablePortIdentity,
    DurableValueIdentity, EvidenceCompleteness, ObjectCardinality, OracleCallContext,
    ProcedureHandle, ProgramPointHandle, ProofStatus, SemanticArtifact, SemanticArtifactKey,
    SemanticLocator, SourceAnchor,
};
use brokk_bifrost_core::analyzer::dense_id::define_dense_id;

use super::{
    CompiledProtocol, ProtocolEventId, ProtocolEventKey, ProtocolEventOccurrence,
    ProtocolExpectationId, ProtocolExpectationKey, ProtocolObjectCardinality,
    ProtocolObservationPhase, ProtocolProcedureExitKind, ProtocolStateId, ProtocolStateKey,
    ProtocolTerminalObservationSpec, TypestateBindingPlanHash, TypestateBindingSummaryHash,
    TypestateProtocolHash,
};

pub const BINDING_PLAN_SCHEMA_VERSION: u32 = 7;
pub const MAX_TYPESTATE_SUBJECTS: usize = 4_096;
pub const MAX_TYPESTATE_INITIAL_SEEDS: usize = 4_096;
pub const MAX_TYPESTATE_EVENT_BINDINGS: usize = 16_384;
pub const MAX_TYPESTATE_CALL_NONINTERFERENCE_BINDINGS: usize = 16_384;
pub const MAX_TYPESTATE_TERMINAL_BINDINGS: usize = 4_096;
pub const MAX_TYPESTATE_CONTEXT_DEPTH: usize = 64;
pub const MAX_TYPESTATE_SUBJECT_CLASS_BYTES: usize = 128;

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TypestateSubjectId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TypestateEventBindingId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TypestateTerminalBindingId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

pub type TypestateSubjectClassError = crate::analyzer::identifier::IdentifierError;

define_identifier! {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TypestateSubjectClassKey {
        max_bytes: MAX_TYPESTATE_SUBJECT_CLASS_BYTES,
        allow_dot: true,
        error: TypestateSubjectClassError,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypestateProcedurePortKey {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    IndexedNormalReturn { ordinal: u32 },
    ExceptionalReturn,
    Capture { identity: SemanticLocator },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypestateContextKey {
    calls: Box<[SemanticLocator]>,
    truncated: bool,
}

impl TypestateContextKey {
    pub fn calls(&self) -> &[SemanticLocator] {
        &self.calls
    }

    pub fn was_truncated(&self) -> bool {
        self.truncated
    }
}

/// Stable semantic counterpart of one runtime [`AbstractObject`] identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypestateObjectKey {
    Value(SemanticLocator),
    FieldPath {
        base: Box<TypestateObjectKey>,
        member: SemanticLocator,
    },
    CallResult {
        call: SemanticLocator,
        result: SemanticLocator,
        callee: SemanticLocator,
        caller_context: TypestateContextKey,
        callee_context: TypestateContextKey,
    },
    CallSubstitution {
        context: TypestateContextKey,
        base: Box<TypestateObjectKey>,
    },
    ProcedurePort {
        procedure: SemanticLocator,
        port: TypestateProcedurePortKey,
    },
    Allocation(SemanticLocator),
    Static(SemanticLocator),
    LexicalCell {
        locator: SemanticLocator,
        binding: DurableValueIdentity,
    },
    CaptureSlot {
        procedure: SemanticLocator,
        port: TypestateProcedurePortKey,
    },
    TypeSummary(SemanticLocator),
    ModuleObject(SemanticLocator),
    External(SemanticLocator),
    RuntimeObject {
        runtime_profile_digest: String,
        realm: String,
        exposure_id: String,
        container_member: String,
        state_boundary: String,
        refinement_identity: crate::analyzer::semantic::StableDigest,
        active_model_set_hash: String,
        manifest_digest: String,
        shard_id: String,
        behavior_id: String,
        activation_source: String,
    },
}

impl TypestateObjectKey {
    pub fn for_object(object: &AbstractObject) -> Self {
        typestate_object_key(object)
    }

    /// Render the source-facing stable object identity. This is the object-only
    /// counterpart of `TypestateSubjectKey::public_canonical_rendering`.
    pub fn public_canonical_rendering(&self) -> String {
        canonical_json(
            &canonical_object_key(self),
            "canonical typestate object identities are serializable",
        )
    }
}

/// Stable semantic identity for one tracked subject class and abstract object.
///
/// The object key is derived from validated semantic handles. Callers cannot
/// supply an unrelated locator or make two distinct abstract objects share one
/// canonical identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypestateSubjectKey {
    class: TypestateSubjectClassKey,
    object: TypestateObjectKey,
}

impl TypestateSubjectKey {
    pub fn for_object(class: TypestateSubjectClassKey, object: &AbstractObject) -> Self {
        Self {
            class,
            object: TypestateObjectKey::for_object(object),
        }
    }

    pub fn class(&self) -> &TypestateSubjectClassKey {
        &self.class
    }

    pub fn object(&self) -> &TypestateObjectKey {
        &self.object
    }

    /// Render the stable semantic subject identity used by public query rows.
    ///
    /// This is the same canonical representation that contributes to the
    /// binding-plan hash; it never contains a run-local dense subject ID, and
    /// it carries no absolute workspace mount (see [`CanonicalLocator`]), so
    /// the same indexed content has the same identity in every checkout.
    pub fn public_canonical_rendering(&self) -> String {
        canonical_json(
            &canonical_subject_key(self),
            "canonical typestate subject identities are serializable",
        )
    }

    /// The subject identity a policy finding id hashes, and whether it omitted
    /// a runtime object's refinement identity.
    ///
    /// It is [`Self::public_canonical_rendering`] without the refinement
    /// identity of any runtime object. That digest folds the procedure
    /// artifact's public fingerprint, which a cache-identity lever token
    /// rotates with no change to the code, and the read's byte range, so a
    /// finding id that kept it would change across an engine upgrade or an
    /// edit above the read (#12029). The refinement told distinct
    /// acquisitions apart; when it is omitted, the caller names the
    /// acquisition observation by its position-free site key instead.
    pub fn finding_identity_rendering(&self) -> (String, bool) {
        let mut key = canonical_subject_key(self);
        let omitted = omit_refinement_identities(&mut key.object);
        (
            canonical_json(
                &key,
                "canonical typestate subject identities are serializable",
            ),
            omitted,
        )
    }
}

/// Clear the refinement identity of every runtime object in `key`, and say
/// whether there was one.
fn omit_refinement_identities(mut key: &mut CanonicalObjectKey<'_>) -> bool {
    loop {
        match key {
            CanonicalObjectKey::FieldPath { base, .. }
            | CanonicalObjectKey::CallSubstitution { base, .. } => key = base,
            CanonicalObjectKey::RuntimeObject {
                refinement_identity,
                ..
            } => return refinement_identity.take().is_some(),
            CanonicalObjectKey::Value { .. }
            | CanonicalObjectKey::CallResult { .. }
            | CanonicalObjectKey::ProcedurePort { .. }
            | CanonicalObjectKey::Allocation { .. }
            | CanonicalObjectKey::Static { .. }
            | CanonicalObjectKey::LexicalCell { .. }
            | CanonicalObjectKey::CaptureSlot { .. }
            | CanonicalObjectKey::TypeSummary { .. }
            | CanonicalObjectKey::ModuleObject { .. }
            | CanonicalObjectKey::External { .. } => return false,
        }
    }
}

/// Candidate-set closure retained with every pre-resolved binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypestateBindingMultiplicity {
    coverage: CandidateCoverage,
    retained: u32,
}

impl TypestateBindingMultiplicity {
    pub fn new(
        coverage: CandidateCoverage,
        retained: usize,
    ) -> Result<Self, TypestateBindingPlanError> {
        if retained == 0 || retained > MAX_TYPESTATE_SUBJECTS {
            return Err(TypestateBindingPlanError::InvalidMultiplicity {
                retained,
                maximum: MAX_TYPESTATE_SUBJECTS,
            });
        }
        Ok(Self {
            coverage,
            retained: u32::try_from(retained)
                .expect("validated typestate multiplicity fits in u32"),
        })
    }

    pub const fn coverage(self) -> CandidateCoverage {
        self.coverage
    }

    pub const fn retained(self) -> u32 {
        self.retained
    }

    pub const fn is_ambiguous(self) -> bool {
        self.retained > 1 || !self.coverage.is_exhaustive()
    }
}

/// Proof, completeness, and ambiguity retained for one exact binding row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypestateBindingQuality {
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    multiplicity: TypestateBindingMultiplicity,
}

impl TypestateBindingQuality {
    pub fn new(
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        multiplicity: TypestateBindingMultiplicity,
    ) -> Self {
        Self {
            proof,
            completeness,
            multiplicity,
        }
    }

    pub fn proven_unique() -> Self {
        Self {
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            multiplicity: TypestateBindingMultiplicity {
                coverage: CandidateCoverage::Exhaustive,
                retained: 1,
            },
        }
    }

    pub fn proof(&self) -> &ProofStatus {
        &self.proof
    }

    pub fn completeness(&self) -> &EvidenceCompleteness {
        &self.completeness
    }

    pub const fn multiplicity(&self) -> TypestateBindingMultiplicity {
        self.multiplicity
    }

    pub const fn is_proven(&self) -> bool {
        matches!(self.proof, ProofStatus::Proven)
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self.completeness, EvidenceCompleteness::Complete)
            && self.multiplicity.coverage.is_exhaustive()
    }

    pub const fn is_definitive(&self) -> bool {
        self.is_proven() && self.is_complete() && !self.multiplicity.is_ambiguous()
    }
}

/// Runtime call context paired with its derived stable semantic key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypestateBindingContext {
    runtime: OracleCallContext,
    key: TypestateContextKey,
}

impl TypestateBindingContext {
    pub fn root() -> Self {
        Self {
            runtime: OracleCallContext::empty(),
            key: TypestateContextKey {
                calls: Box::new([]),
                truncated: false,
            },
        }
    }

    /// The binding context of a callee entered at this call. The oracle's
    /// bounded context and this plan's key are derived from the same stack.
    pub fn entered(&self, call: CallSiteHandle) -> Self {
        let runtime = self
            .runtime
            .extended(call, crate::analyzer::semantic::OracleLimits::default());
        let key = typestate_runtime_context_key(&runtime);
        Self { runtime, key }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn try_new(runtime: OracleCallContext) -> Result<Self, TypestateBindingPlanError> {
        if runtime.calls().len() > MAX_TYPESTATE_CONTEXT_DEPTH {
            return Err(TypestateBindingPlanError::TooManyEntries {
                collection: "context.calls",
                actual: runtime.calls().len(),
                maximum: MAX_TYPESTATE_CONTEXT_DEPTH,
            });
        }
        let key = typestate_runtime_context_key(&runtime);
        Ok(Self { runtime, key })
    }

    pub fn runtime(&self) -> &OracleCallContext {
        &self.runtime
    }

    pub fn key(&self) -> &TypestateContextKey {
        &self.key
    }

    pub fn was_truncated(&self) -> bool {
        self.runtime.was_truncated()
    }
}

impl Default for TypestateBindingContext {
    fn default() -> Self {
        Self::root()
    }
}

/// One exact execution site plus a stable semantic identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypestateObservationSite {
    ProgramPoint {
        point: ProgramPointHandle,
        identity: SemanticLocator,
        context: TypestateBindingContext,
    },
    CallSite {
        call: crate::analyzer::semantic::CallSiteHandle,
        identity: SemanticLocator,
        context: TypestateBindingContext,
    },
}

impl TypestateObservationSite {
    pub fn program_point(point: ProgramPointHandle, context: TypestateBindingContext) -> Self {
        let identity = program_point_locator(&point);
        Self::ProgramPoint {
            point,
            identity,
            context,
        }
    }

    pub fn call_site(
        call: crate::analyzer::semantic::CallSiteHandle,
        context: TypestateBindingContext,
    ) -> Self {
        let identity = call_site_locator(&call);
        Self::CallSite {
            call,
            identity,
            context,
        }
    }

    pub fn identity(&self) -> &SemanticLocator {
        match self {
            Self::ProgramPoint { identity, .. } | Self::CallSite { identity, .. } => identity,
        }
    }

    pub fn context(&self) -> &TypestateBindingContext {
        match self {
            Self::ProgramPoint { context, .. } | Self::CallSite { context, .. } => context,
        }
    }

    pub fn program_point_handle(&self) -> Option<&ProgramPointHandle> {
        match self {
            Self::ProgramPoint { point, .. } => Some(point),
            Self::CallSite { .. } => None,
        }
    }

    pub fn call_site_handle(&self) -> Option<&crate::analyzer::semantic::CallSiteHandle> {
        match self {
            Self::ProgramPoint { .. } => None,
            Self::CallSite { call, .. } => Some(call),
        }
    }
}

/// The exact structured object role resolved before solver propagation.
///
/// Concrete syntactic argument positions deliberately do not appear here.
/// Named and positional authoring forms both lower to the selected semantic
/// object and, when appropriate, its formal ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TypestateObjectRole {
    MatchedValue,
    AllocationResult,
    Receiver,
    Argument,
    FormalReceiver,
    FormalArgument { ordinal: u32 },
    NormalReturn,
    ExceptionalReturn,
    FieldBase,
    FieldValue,
    FieldLocation,
    EscapedObject,
    CurrentObject,
}

#[derive(Debug, Clone)]
pub struct BoundTypestateSubjectSpec {
    key: TypestateSubjectKey,
    object: AbstractObject,
    quality: TypestateBindingQuality,
}

impl BoundTypestateSubjectSpec {
    pub fn new(
        class: TypestateSubjectClassKey,
        object: AbstractObject,
        quality: TypestateBindingQuality,
    ) -> Self {
        let key = TypestateSubjectKey::for_object(class, &object);
        Self {
            key,
            object,
            quality,
        }
    }

    pub fn key(&self) -> &TypestateSubjectKey {
        &self.key
    }

    pub fn mark_discovery_incomplete(&mut self, reason: impl Into<Box<str>>) {
        self.quality = TypestateBindingQuality::new(
            self.quality.proof.clone(),
            EvidenceCompleteness::Partial(reason.into()),
            self.quality.multiplicity,
        );
    }
}

#[derive(Debug, Clone)]
pub struct TypestateStateTransferSpec {
    pub call: crate::analyzer::semantic::CallSiteHandle,
    pub source: Option<TypestateSubjectKey>,
    pub result: TypestateSubjectKey,
}

#[derive(Debug, Clone)]
pub struct BoundTypestateStateTransfer {
    pub call: crate::analyzer::semantic::CallSiteHandle,
    pub source: Option<TypestateSubjectId>,
    pub result: TypestateSubjectId,
}

#[derive(Debug, Clone)]
pub struct TypestateInitialSeedSpec {
    subject: TypestateSubjectKey,
    state: ProtocolStateKey,
    site: TypestateObservationSite,
    activation_edge: Option<crate::analyzer::semantic::ControlEdgeHandle>,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
    reviewed_fresh_result: bool,
}

impl TypestateInitialSeedSpec {
    pub fn new(
        subject: TypestateSubjectKey,
        state: ProtocolStateKey,
        site: TypestateObservationSite,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
    ) -> Self {
        Self {
            subject,
            state,
            site,
            activation_edge: None,
            role,
            quality,
            reviewed_fresh_result: false,
        }
    }

    pub fn new_on_control_edge(
        subject: TypestateSubjectKey,
        state: ProtocolStateKey,
        site: TypestateObservationSite,
        activation_edge: crate::analyzer::semantic::ControlEdgeHandle,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
    ) -> Self {
        let mut seed = Self::new(subject, state, site, role, quality);
        seed.activation_edge = Some(activation_edge);
        seed
    }

    pub fn new_reviewed_fresh_result(
        subject: TypestateSubjectKey,
        state: ProtocolStateKey,
        site: TypestateObservationSite,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
    ) -> Self {
        let mut seed = Self::new(subject, state, site, role, quality);
        seed.reviewed_fresh_result = true;
        seed
    }

    pub fn new_reviewed_fresh_result_on_control_edge(
        subject: TypestateSubjectKey,
        state: ProtocolStateKey,
        site: TypestateObservationSite,
        activation_edge: crate::analyzer::semantic::ControlEdgeHandle,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
    ) -> Self {
        let mut seed =
            Self::new_on_control_edge(subject, state, site, activation_edge, role, quality);
        seed.reviewed_fresh_result = true;
        seed
    }
}

#[derive(Debug, Clone)]
pub struct TypestateEventBindingSpec {
    event: ProtocolEventKey,
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    order: u32,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
    modeled_external_effect: Option<String>,
    semantic_effect: Option<Arc<str>>,
    condition: Option<TypestateEventCondition>,
    selected_operand: Option<TypestateSelectedOperand>,
}

/// The exact call operand selected by a policy event. A missing port cannot
/// authorize a formal-pair alias guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypestateEventPort {
    Receiver,
    Argument { ordinal: u32 },
    Result { ordinal: Option<u32> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypestateSelectedOperand {
    call: CallSiteHandle,
    port: TypestateEventPort,
    selected_target: Option<crate::analyzer::semantic::DurableProcedureKey>,
}

impl TypestateSelectedOperand {
    pub fn new(call: CallSiteHandle, port: TypestateEventPort) -> Self {
        Self {
            call,
            port,
            selected_target: None,
        }
    }

    pub fn with_selected_target(
        mut self,
        target: crate::analyzer::semantic::DurableProcedureKey,
    ) -> Self {
        self.selected_target = Some(target);
        self
    }

    pub fn selected_target(&self) -> Option<&crate::analyzer::semantic::DurableProcedureKey> {
        self.selected_target.as_ref()
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub const fn port(&self) -> TypestateEventPort {
        self.port
    }

    pub fn partial_flow_port(&self) -> PartialFlowPort {
        match self.port {
            TypestateEventPort::Receiver => PartialFlowPort::CallReceiver {
                call: self.call.id(),
            },
            TypestateEventPort::Argument { ordinal } => PartialFlowPort::CallArgument {
                call: self.call.id(),
                ordinal,
            },
            TypestateEventPort::Result { ordinal } => PartialFlowPort::CallResult {
                call: self.call.id(),
                ordinal,
            },
        }
    }
}

/// A Boolean equality condition evaluated against the selected call's
/// semantic argument value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypestateEventCondition {
    argument_index: u32,
    expected: bool,
}

impl TypestateEventCondition {
    pub const fn boolean_argument(argument_index: u32, expected: bool) -> Self {
        Self {
            argument_index,
            expected,
        }
    }

    pub const fn argument_index(self) -> u32 {
        self.argument_index
    }

    pub const fn expected(self) -> bool {
        self.expected
    }
}

/// A compiler-proven fact that one call cannot reach one live typestate
/// subject through its receiver, arguments, or any unreviewed prior
/// publication of that fresh object.
#[derive(Debug, Clone)]
pub struct TypestateCallNonInterferenceSpec {
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
}

impl TypestateCallNonInterferenceSpec {
    pub fn new(
        subject: TypestateSubjectKey,
        call: crate::analyzer::semantic::CallSiteHandle,
    ) -> Self {
        Self {
            subject,
            site: TypestateObservationSite::call_site(call, TypestateBindingContext::root()),
        }
    }
}

impl TypestateEventBindingSpec {
    pub fn new(
        event: ProtocolEventKey,
        subject: TypestateSubjectKey,
        site: TypestateObservationSite,
        order: u32,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
    ) -> Self {
        Self {
            event,
            subject,
            site,
            order,
            role,
            quality,
            modeled_external_effect: None,
            semantic_effect: None,
            condition: None,
            selected_operand: None,
        }
    }

    pub fn new_modeled_external_effect(
        event: ProtocolEventKey,
        subject: TypestateSubjectKey,
        site: TypestateObservationSite,
        order: u32,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
        effect_id: String,
    ) -> Self {
        assert!(
            !effect_id.is_empty(),
            "modeled external effect id is non-empty"
        );
        let mut binding = Self::new(event, subject, site, order, role, quality);
        binding.modeled_external_effect = Some(effect_id);
        binding
    }

    pub fn with_condition(mut self, condition: TypestateEventCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    pub fn with_selected_operand(mut self, operand: TypestateSelectedOperand) -> Self {
        assert_eq!(self.site.call_site_handle(), Some(operand.call()));
        self.selected_operand = Some(operand);
        self
    }
    pub fn with_semantic_effect(mut self, effect: Option<Arc<str>>) -> Self {
        self.semantic_effect = effect;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TypestateCoverageEventSet {
    pub name: String,
    pub version: u32,
    pub effects: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageCandidatePhase {
    AtMatch,
    BeforeCall,
    AfterNormalReturn,
    AfterExceptionalReturn,
    NormalProcedureExit,
    ExceptionalProcedureExit,
    SuspensionBoundary,
}

#[derive(Debug, Clone)]
pub struct CoverageCandidateSpec {
    pub event: String,
    pub semantic_effect: Option<Arc<str>>,
    pub quality: TypestateBindingQuality,
    pub alias_derived: bool,
    /// The selected operand that bound the subject: a receiver claim can only
    /// be discharged through candidates bound by the call's receiver.
    pub role: TypestateObjectRole,
}

impl CoverageCandidateSpec {
    pub fn is_definitive(&self) -> bool {
        !self.alias_derived && self.quality.is_definitive()
    }
}

#[derive(Debug, Clone)]
pub struct CoverageCandidateGroupSpec {
    pub subject: TypestateSubjectKey,
    pub site: TypestateObservationSite,
    pub phase: CoverageCandidatePhase,
    pub candidates: Vec<CoverageCandidateSpec>,
}

/// Provenance of the exact activated summary selected for a call. A model ID
/// alone is insufficient because two active shards may contain that ID.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CoverageRecordKey {
    pub active_model_set_hash: String,
    pub pack_id: String,
    pub pack_digest: String,
    pub shard_id: String,
    pub shard_digest: String,
    pub record_id: String,
    pub model_id: String,
    pub record_digest: String,
    pub selected_member_id: String,
    #[serde(serialize_with = "serialize_coverage_context")]
    pub context: TypestateContextKey,
    pub claim_id: Option<String>,
    pub witness_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageRefusalReason {
    MissingSelectedRecord,
    MissingContext,
    MissingClaim,
    EventSetMismatch,
    SubjectMismatch,
    ExtraActual,
    MultipleCandidates,
    CandidateUnproven,
    UnmappedCandidate,
    WitnessCountMismatch,
    WitnessEffectMismatch,
    WitnessNotDefinite,
    PhaseOutsideClaim,
    ReceiverTransportUnproven,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CoverageDecisionKind {
    Unclaimed {
        record: CoverageRecordKey,
    },
    Refused {
        reason: CoverageRefusalReason,
        record: Option<CoverageRecordKey>,
    },
    /// The claim accounts for every event-set effect on the subject at this
    /// exit, and the receiver-transport certificate holds: the call's dispatch
    /// boundary is modeled for this subject on this arm only.
    Covered {
        record: CoverageRecordKey,
    },
}

#[derive(Debug, Clone)]
pub struct CoverageDecisionSpec {
    pub subject: TypestateSubjectKey,
    pub site: TypestateObservationSite,
    pub phase: CoverageCandidatePhase,
    pub kind: CoverageDecisionKind,
}

#[derive(Debug, Clone)]
pub struct CoverageDecision {
    subject: TypestateSubjectId,
    site: TypestateObservationSite,
    phase: CoverageCandidatePhase,
    kind: CoverageDecisionKind,
}

impl CoverageDecision {
    pub fn kind(&self) -> &CoverageDecisionKind {
        &self.kind
    }
}

#[derive(Debug, Default)]
pub struct TypestateCoverageSpec {
    pub event_set: Option<TypestateCoverageEventSet>,
    pub candidate_groups: Vec<CoverageCandidateGroupSpec>,
    pub decisions: Vec<CoverageDecisionSpec>,
    pub unproven_relations: Vec<UnprovenEventRelation>,
}

/// One subject whose absence from an observed event has not been proved.
#[derive(Debug, Clone)]
pub struct UnprovenEventRelation {
    pub subject: TypestateSubjectKey,
    pub site: TypestateObservationSite,
    pub event: String,
    pub phase: String,
    pub exit: Option<String>,
    pub observation_procedure: SemanticLocator,
    pub reason: String,
}

fn canonical_unproven_relation(relation: &UnprovenEventRelation) -> CanonicalUnprovenRelation<'_> {
    CanonicalUnprovenRelation {
        subject: canonical_subject_key(&relation.subject),
        site: canonical_site(&relation.site),
        event: &relation.event,
        phase: &relation.phase,
        exit: relation.exit.as_deref(),
        observation_procedure: canonical_locator(&relation.observation_procedure),
        reason: &relation.reason,
    }
}

#[derive(Serialize)]
struct CanonicalUnprovenRelation<'a> {
    subject: CanonicalSubjectKey<'a>,
    site: CanonicalSite<'a>,
    event: &'a str,
    phase: &'a str,
    exit: Option<&'a str>,
    observation_procedure: CanonicalLocator<'a>,
    reason: &'a str,
}

#[derive(Debug, Clone)]
pub struct CoverageCandidateGroup {
    subject: TypestateSubjectId,
    site: TypestateObservationSite,
    phase: CoverageCandidatePhase,
    candidates: Box<[CoverageCandidateSpec]>,
}

impl CoverageCandidateGroup {
    pub const fn subject(&self) -> TypestateSubjectId {
        self.subject
    }
    pub fn site(&self) -> &TypestateObservationSite {
        &self.site
    }
    pub const fn phase(&self) -> CoverageCandidatePhase {
        self.phase
    }
    pub fn candidates(&self) -> &[CoverageCandidateSpec] {
        &self.candidates
    }
}

#[derive(Debug, Clone)]
pub struct TypestateTerminalBindingSpec {
    expectation: ProtocolExpectationKey,
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
}

impl TypestateTerminalBindingSpec {
    pub fn new(
        expectation: ProtocolExpectationKey,
        subject: TypestateSubjectKey,
        site: TypestateObservationSite,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
    ) -> Self {
        Self {
            expectation,
            subject,
            site,
            role,
            quality,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BoundTypestateSubject {
    id: TypestateSubjectId,
    key: TypestateSubjectKey,
    object: AbstractObject,
    quality: TypestateBindingQuality,
}

impl BoundTypestateSubject {
    /// Ephemeral subject for a selected receiver certificate. Its dense ID
    /// and class never enter a binding plan or a published answer.
    pub(super) fn receiver_event_probe(
        object: AbstractObject,
        quality: TypestateBindingQuality,
    ) -> Self {
        let class = TypestateSubjectClassKey::new("receiver-event-probe")
            .expect("receiver event probe class is valid");
        Self {
            id: TypestateSubjectId::new(0),
            key: TypestateSubjectKey::for_object(class, &object),
            object,
            quality,
        }
    }

    pub const fn id(&self) -> TypestateSubjectId {
        self.id
    }

    pub fn key(&self) -> &TypestateSubjectKey {
        &self.key
    }

    pub fn object(&self) -> &AbstractObject {
        &self.object
    }

    pub const fn cardinality(&self) -> ProtocolObjectCardinality {
        match self.object.cardinality() {
            ObjectCardinality::Singleton => ProtocolObjectCardinality::Singleton,
            ObjectCardinality::Summary => ProtocolObjectCardinality::Summary,
            ObjectCardinality::Unknown => ProtocolObjectCardinality::Unknown,
        }
    }

    pub fn quality(&self) -> &TypestateBindingQuality {
        &self.quality
    }
}

#[derive(Debug, Clone)]
pub struct BoundTypestateInitialSeed {
    subject: TypestateSubjectId,
    state: ProtocolStateId,
    site: TypestateObservationSite,
    activation_edge: Option<crate::analyzer::semantic::ControlEdgeHandle>,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
    reviewed_fresh_result: bool,
}

impl BoundTypestateInitialSeed {
    pub const fn subject(&self) -> TypestateSubjectId {
        self.subject
    }

    pub const fn state(&self) -> ProtocolStateId {
        self.state
    }

    pub fn site(&self) -> &TypestateObservationSite {
        &self.site
    }

    pub fn activation_edge(&self) -> Option<&crate::analyzer::semantic::ControlEdgeHandle> {
        self.activation_edge.as_ref()
    }

    pub(crate) fn activation_successor(&self) -> Option<(ProgramPointHandle, ControlEdgeKind)> {
        self.activation_edge().map(|edge| {
            let row = edge
                .procedure()
                .semantics()
                .control_edge(edge.id())
                .expect("validated control-edge activation resolves");
            let target = edge
                .procedure()
                .point_handle(row.target_point)
                .expect("validated control-edge activation retains its target");
            (target, row.kind)
        })
    }

    pub const fn role(&self) -> TypestateObjectRole {
        self.role
    }

    pub fn quality(&self) -> &TypestateBindingQuality {
        &self.quality
    }

    pub const fn reviewed_fresh_result(&self) -> bool {
        self.reviewed_fresh_result
    }
}

#[derive(Debug, Clone)]
pub struct BoundTypestateEvent {
    id: TypestateEventBindingId,
    event: ProtocolEventId,
    subject: TypestateSubjectId,
    site: TypestateObservationSite,
    order: u32,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
    modeled_external_effect: Option<String>,
    semantic_effect: Option<Arc<str>>,
    condition: Option<TypestateEventCondition>,
    selected_operand: Option<TypestateSelectedOperand>,
}

impl BoundTypestateEvent {
    pub const fn id(&self) -> TypestateEventBindingId {
        self.id
    }

    pub const fn event(&self) -> ProtocolEventId {
        self.event
    }

    pub const fn subject(&self) -> TypestateSubjectId {
        self.subject
    }

    pub fn site(&self) -> &TypestateObservationSite {
        &self.site
    }

    pub const fn order(&self) -> u32 {
        self.order
    }

    pub const fn role(&self) -> TypestateObjectRole {
        self.role
    }

    pub fn quality(&self) -> &TypestateBindingQuality {
        &self.quality
    }

    pub fn modeled_external_effect(&self) -> Option<&str> {
        self.modeled_external_effect.as_deref()
    }

    pub fn semantic_effect(&self) -> Option<&str> {
        self.semantic_effect.as_deref()
    }

    pub const fn condition(&self) -> Option<TypestateEventCondition> {
        self.condition
    }

    pub fn selected_operand(&self) -> Option<&TypestateSelectedOperand> {
        self.selected_operand.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct BoundTypestateCallNonInterference {
    subject: TypestateSubjectId,
    site: TypestateObservationSite,
}

impl BoundTypestateCallNonInterference {
    pub const fn subject(&self) -> TypestateSubjectId {
        self.subject
    }

    pub fn site(&self) -> &TypestateObservationSite {
        &self.site
    }
}

#[derive(Debug, Clone)]
pub struct BoundTypestateTerminal {
    id: TypestateTerminalBindingId,
    expectation: ProtocolExpectationId,
    subject: TypestateSubjectId,
    site: TypestateObservationSite,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
}

impl BoundTypestateTerminal {
    pub const fn id(&self) -> TypestateTerminalBindingId {
        self.id
    }

    pub const fn expectation(&self) -> ProtocolExpectationId {
        self.expectation
    }

    pub const fn subject(&self) -> TypestateSubjectId {
        self.subject
    }

    pub fn site(&self) -> &TypestateObservationSite {
        &self.site
    }

    pub const fn role(&self) -> TypestateObjectRole {
        self.role
    }

    pub fn quality(&self) -> &TypestateBindingQuality {
        &self.quality
    }
}

#[derive(Debug)]
pub struct TypestateBindingPlan {
    protocol_hash: TypestateProtocolHash,
    subjects: Box<[BoundTypestateSubject]>,
    state_transfers: Box<[BoundTypestateStateTransfer]>,
    transfers_by_call: HashMap<crate::analyzer::semantic::CallSiteHandle, Box<[usize]>>,
    transfers_by_point: HashMap<ProgramPointHandle, Box<[usize]>>,
    transfers_by_source: HashMap<TypestateSubjectId, Box<[usize]>>,
    transfers_by_result: HashMap<TypestateSubjectId, Box<[usize]>>,
    initial_seeds: Box<[BoundTypestateInitialSeed]>,
    event_bindings: Box<[BoundTypestateEvent]>,
    event_templates: Box<[BoundTypestateEvent]>,
    event_set: Option<TypestateCoverageEventSet>,
    coverage_candidate_groups: Box<[CoverageCandidateGroup]>,
    coverage_decisions: Box<[CoverageDecision]>,
    unproven_relations: Box<[UnprovenEventRelation]>,
    call_noninterference_bindings: Box<[BoundTypestateCallNonInterference]>,
    terminal_bindings: Box<[BoundTypestateTerminal]>,
    terminals_by_point: HashMap<ProgramPointHandle, HashMap<OracleCallContext, Box<[usize]>>>,
    initial_seeds_by_point_all_contexts: HashMap<ProgramPointHandle, Box<[usize]>>,
    events_by_point_all_contexts: HashMap<ProgramPointHandle, Box<[usize]>>,
    events_by_call_all_contexts: HashMap<crate::analyzer::semantic::CallSiteHandle, Box<[usize]>>,
    events_by_call_point_all_contexts: HashMap<ProgramPointHandle, Box<[usize]>>,
    call_noninterference_by_call: SubjectIndexByCall,
    call_noninterference_by_point: SubjectIndexByPoint,
    terminals_by_point_all_contexts: HashMap<ProgramPointHandle, Box<[usize]>>,
    terminals_by_call_all_contexts:
        HashMap<crate::analyzer::semantic::CallSiteHandle, Box<[usize]>>,
    terminals_by_call_point_all_contexts: HashMap<ProgramPointHandle, Box<[usize]>>,
    canonical_bytes: Box<[u8]>,
    canonical_rendering: Box<str>,
    hash: TypestateBindingPlanHash,
    summary_hashes:
        HashMap<SemanticArtifactKey, HashMap<DeclarationLocator, TypestateBindingSummaryHash>>,
    empty_summary_hash: TypestateBindingSummaryHash,
}

type SubjectIndexByCall =
    HashMap<crate::analyzer::semantic::CallSiteHandle, Box<[TypestateSubjectId]>>;
type SubjectIndexByPoint = HashMap<ProgramPointHandle, Box<[TypestateSubjectId]>>;

pub struct TypestateEventBindings {
    pub events: Vec<TypestateEventBindingSpec>,
    pub templates: Vec<TypestateEventBindingSpec>,
}

impl TypestateBindingPlan {
    pub fn try_new(
        protocol: &CompiledProtocol,
        subjects: Vec<BoundTypestateSubjectSpec>,
        initial_seeds: Vec<TypestateInitialSeedSpec>,
        event_bindings: Vec<TypestateEventBindingSpec>,
        terminal_bindings: Vec<TypestateTerminalBindingSpec>,
    ) -> Result<Self, TypestateBindingPlanError> {
        Self::try_new_with_call_noninterference(
            protocol,
            subjects,
            initial_seeds,
            event_bindings,
            Vec::new(),
            terminal_bindings,
        )
    }

    pub fn try_new_with_call_noninterference(
        protocol: &CompiledProtocol,
        subjects: Vec<BoundTypestateSubjectSpec>,
        initial_seeds: Vec<TypestateInitialSeedSpec>,
        event_bindings: Vec<TypestateEventBindingSpec>,
        call_noninterference_bindings: Vec<TypestateCallNonInterferenceSpec>,
        terminal_bindings: Vec<TypestateTerminalBindingSpec>,
    ) -> Result<Self, TypestateBindingPlanError> {
        Self::try_new_with_coverage(
            protocol,
            subjects,
            initial_seeds,
            TypestateEventBindings {
                events: event_bindings,
                templates: Vec::new(),
            },
            call_noninterference_bindings,
            terminal_bindings,
            TypestateCoverageSpec::default(),
        )
    }

    pub fn try_new_with_coverage(
        protocol: &CompiledProtocol,
        mut subjects: Vec<BoundTypestateSubjectSpec>,
        mut initial_seeds: Vec<TypestateInitialSeedSpec>,
        events: TypestateEventBindings,
        mut call_noninterference_bindings: Vec<TypestateCallNonInterferenceSpec>,
        mut terminal_bindings: Vec<TypestateTerminalBindingSpec>,
        coverage: TypestateCoverageSpec,
    ) -> Result<Self, TypestateBindingPlanError> {
        let TypestateEventBindings {
            events: mut event_bindings,
            templates: mut event_templates,
        } = events;
        let TypestateCoverageSpec {
            event_set,
            candidate_groups: mut coverage_candidate_groups,
            decisions: mut coverage_decisions,
            mut unproven_relations,
        } = coverage;
        check_count(
            "unproven_relations",
            unproven_relations.len(),
            MAX_TYPESTATE_EVENT_BINDINGS,
        )?;
        unproven_relations.sort_by(|left, right| {
            canonical_json(
                &canonical_unproven_relation(left),
                "unproven relation is canonical",
            )
            .cmp(&canonical_json(
                &canonical_unproven_relation(right),
                "unproven relation is canonical",
            ))
        });
        unproven_relations.dedup_by(|right, left| {
            canonical_json(
                &canonical_unproven_relation(left),
                "unproven relation is canonical",
            ) == canonical_json(
                &canonical_unproven_relation(right),
                "unproven relation is canonical",
            )
        });
        check_count("subjects", subjects.len(), MAX_TYPESTATE_SUBJECTS)?;
        check_count(
            "initial_seeds",
            initial_seeds.len(),
            MAX_TYPESTATE_INITIAL_SEEDS,
        )?;
        check_count(
            "event_bindings",
            event_bindings.len() + event_templates.len(),
            MAX_TYPESTATE_EVENT_BINDINGS,
        )?;
        check_count(
            "call_noninterference_bindings",
            call_noninterference_bindings.len(),
            MAX_TYPESTATE_CALL_NONINTERFERENCE_BINDINGS,
        )?;
        check_count(
            "terminal_bindings",
            terminal_bindings.len(),
            MAX_TYPESTATE_TERMINAL_BINDINGS,
        )?;

        subjects.sort_by(|left, right| left.key.cmp(&right.key));
        if subjects.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(TypestateBindingPlanError::DuplicateSubject);
        }
        initial_seeds.sort_by(compare_seed_specs);
        reject_adjacent_duplicates(
            &initial_seeds,
            compare_seed_specs,
            TypestateBindingPlanError::DuplicateInitialSeed,
        )?;
        event_bindings.sort_by(compare_event_specs);
        reject_adjacent_duplicates(
            &event_bindings,
            compare_event_specs,
            TypestateBindingPlanError::DuplicateEventBinding,
        )?;
        if event_bindings
            .windows(2)
            .any(|pair| compare_event_order_keys(&pair[0], &pair[1]) == Ordering::Equal)
        {
            return Err(TypestateBindingPlanError::ConflictingEventOrder);
        }
        event_templates.sort_by(compare_event_specs);
        event_templates.dedup_by(|right, left| compare_event_specs(left, right) == Ordering::Equal);
        call_noninterference_bindings.sort_by(compare_call_noninterference_specs);
        reject_adjacent_duplicates(
            &call_noninterference_bindings,
            compare_call_noninterference_specs,
            TypestateBindingPlanError::DuplicateCallNonInterferenceBinding,
        )?;
        terminal_bindings.sort_by(compare_terminal_specs);
        reject_adjacent_duplicates(
            &terminal_bindings,
            compare_terminal_specs,
            TypestateBindingPlanError::DuplicateTerminalBinding,
        )?;

        let subject_ids: HashMap<_, _> = subjects
            .iter()
            .enumerate()
            .map(|(index, subject)| {
                (
                    subject.key.clone(),
                    TypestateSubjectId::try_from_index(index)
                        .expect("validated typestate subject count fits in u32"),
                )
            })
            .collect();

        let compiled_subjects: Vec<_> = subjects
            .iter()
            .enumerate()
            .map(|(index, subject)| BoundTypestateSubject {
                id: TypestateSubjectId::try_from_index(index)
                    .expect("validated typestate subject count fits in u32"),
                key: subject.key.clone(),
                object: subject.object.clone(),
                quality: subject.quality.clone(),
            })
            .collect();

        let mut compiled_seeds = Vec::with_capacity(initial_seeds.len());
        for seed in &initial_seeds {
            let subject = subject_id(&subject_ids, &seed.subject)?;
            let state = protocol
                .state_id(&seed.state)
                .ok_or(TypestateBindingPlanError::UnknownState)?;
            validate_seed_site(&seed.site, seed.activation_edge.as_ref())?;
            compiled_seeds.push(BoundTypestateInitialSeed {
                subject,
                state,
                site: seed.site.clone(),
                activation_edge: seed.activation_edge.clone(),
                role: seed.role,
                quality: seed.quality.clone(),
                reviewed_fresh_result: seed.reviewed_fresh_result,
            });
        }

        let mut compiled_events = Vec::with_capacity(event_bindings.len() + event_templates.len());
        for (index, binding) in event_bindings
            .iter()
            .chain(event_templates.iter())
            .enumerate()
        {
            let subject = subject_id(&subject_ids, &binding.subject)?;
            let event = protocol
                .event_id(&binding.event)
                .ok_or(TypestateBindingPlanError::UnknownEvent)?;
            let occurrence = &protocol
                .event(event)
                .expect("compiled protocol event ID resolves")
                .observation()
                .occurrence;
            validate_observation_shape(occurrence, &binding.site, binding.role)?;
            if binding.condition.is_some() && binding.site.call_site_handle().is_none() {
                return Err(TypestateBindingPlanError::InvalidEventConditionSite);
            }
            compiled_events.push(BoundTypestateEvent {
                id: TypestateEventBindingId::try_from_index(index)
                    .expect("validated event-binding count fits in u32"),
                event,
                subject,
                site: binding.site.clone(),
                order: binding.order,
                role: binding.role,
                quality: binding.quality.clone(),
                modeled_external_effect: binding.modeled_external_effect.clone(),
                semantic_effect: binding.semantic_effect.clone(),
                condition: binding.condition,
                selected_operand: binding.selected_operand.clone(),
            });
        }

        // Open and exhaustive evidence at one observation remain distinct
        // groups. Canonicalize their contents before the group key so visit
        // order cannot change binding identity; do not coalesce the evidence.
        for group in &mut coverage_candidate_groups {
            group.candidates.sort_by_cached_key(|candidate| {
                canonical_json(
                    &canonical_coverage_candidate(candidate),
                    "coverage candidate is serializable",
                )
            });
        }
        coverage_candidate_groups.sort_by_cached_key(|group| {
            canonical_json(
                &canonical_coverage_candidate_group(group),
                "coverage candidate group key is serializable",
            )
        });
        let compiled_coverage_groups = coverage_candidate_groups
            .iter()
            .map(|group| {
                Ok(CoverageCandidateGroup {
                    subject: subject_id(&subject_ids, &group.subject)?,
                    site: group.site.clone(),
                    phase: group.phase,
                    candidates: group.candidates.clone().into_boxed_slice(),
                })
            })
            .collect::<Result<Vec<_>, TypestateBindingPlanError>>()?;

        coverage_decisions.sort_by_cached_key(|decision| {
            canonical_json(
                &(
                    canonical_subject_key(&decision.subject),
                    canonical_site(&decision.site),
                    decision.phase,
                ),
                "coverage decision key is serializable",
            )
        });
        let compiled_coverage_decisions = coverage_decisions
            .iter()
            .map(|decision| {
                Ok(CoverageDecision {
                    subject: subject_id(&subject_ids, &decision.subject)?,
                    site: decision.site.clone(),
                    phase: decision.phase,
                    kind: decision.kind.clone(),
                })
            })
            .collect::<Result<Vec<_>, TypestateBindingPlanError>>()?;

        let mut compiled_call_noninterference =
            Vec::with_capacity(call_noninterference_bindings.len());
        for binding in &call_noninterference_bindings {
            let subject = subject_id(&subject_ids, &binding.subject)?;
            if binding.site.call_site_handle().is_none() {
                return Err(TypestateBindingPlanError::InvalidCallNonInterferenceSite);
            }
            compiled_call_noninterference.push(BoundTypestateCallNonInterference {
                subject,
                site: binding.site.clone(),
            });
        }

        let mut compiled_terminals = Vec::with_capacity(terminal_bindings.len());
        for (index, binding) in terminal_bindings.iter().enumerate() {
            let subject = subject_id(&subject_ids, &binding.subject)?;
            let expectation = protocol
                .expectation_id(&binding.expectation)
                .ok_or(TypestateBindingPlanError::UnknownExpectation)?;
            let terminal = protocol
                .terminal_expectation(expectation)
                .expect("compiled protocol expectation ID resolves");
            match terminal.on() {
                ProtocolTerminalObservationSpec::AnalysisRootExit { kind } => {
                    validate_terminal_exit(*kind, &binding.site, binding.role)?;
                }
                ProtocolTerminalObservationSpec::Event { observation } => {
                    validate_observation_shape(
                        &observation.occurrence,
                        &binding.site,
                        binding.role,
                    )?;
                }
            }
            compiled_terminals.push(BoundTypestateTerminal {
                id: TypestateTerminalBindingId::try_from_index(index)
                    .expect("validated terminal-binding count fits in u32"),
                expectation,
                subject,
                site: binding.site.clone(),
                role: binding.role,
                quality: binding.quality.clone(),
            });
        }

        let template_start = event_bindings.len();
        let compiled_templates = compiled_events.split_off(template_start);
        let canonical = CanonicalBindingPlan {
            schema_version: BINDING_PLAN_SCHEMA_VERSION,
            protocol_hash: protocol.hash(),
            event_set: event_set.as_ref(),
            coverage_candidate_groups: coverage_candidate_groups
                .iter()
                .map(canonical_coverage_candidate_group)
                .collect(),
            coverage_decisions: coverage_decisions
                .iter()
                .map(|decision| CanonicalCoverageDecision {
                    subject: canonical_subject_key(&decision.subject),
                    site: canonical_site(&decision.site),
                    phase: decision.phase,
                    kind: &decision.kind,
                })
                .collect(),
            unproven_relations: unproven_relations
                .iter()
                .map(canonical_unproven_relation)
                .collect(),
            subjects: subjects.iter().map(canonical_subject).collect(),
            initial_seeds: initial_seeds
                .iter()
                .map(|seed| CanonicalSeed {
                    subject: canonical_subject_key(&seed.subject),
                    state: seed.state.as_str(),
                    site: canonical_site(&seed.site),
                    activation_edge: seed.activation_edge.as_ref().map(canonical_activation_edge),
                    role: seed.role,
                    quality: canonical_quality(&seed.quality),
                    reviewed_fresh_result: seed.reviewed_fresh_result,
                })
                .collect(),
            event_bindings: event_bindings.iter().map(canonical_event_binding).collect(),
            event_templates: event_templates
                .iter()
                .map(canonical_event_binding)
                .collect(),
            call_noninterference_bindings: call_noninterference_bindings
                .iter()
                .map(|binding| CanonicalCallNonInterferenceBinding {
                    subject: canonical_subject_key(&binding.subject),
                    site: canonical_site(&binding.site),
                })
                .collect(),
            terminal_bindings: terminal_bindings
                .iter()
                .map(|binding| CanonicalTerminalBinding {
                    expectation: binding.expectation.as_str(),
                    subject: canonical_subject_key(&binding.subject),
                    site: canonical_site(&binding.site),
                    role: binding.role,
                    quality: canonical_quality(&binding.quality),
                })
                .collect(),
        };
        let canonical_bytes =
            serde_json::to_vec(&canonical).map_err(TypestateBindingPlanError::Canonicalization)?;
        let canonical_rendering = serde_json::to_string_pretty(&canonical)
            .map_err(TypestateBindingPlanError::Canonicalization)?;
        let hash = TypestateBindingPlanHash::from_canonical_bytes(&canonical_bytes);
        let (summary_hashes, empty_summary_hash) = procedure_summary_hashes(
            protocol,
            &subjects,
            &initial_seeds,
            ProcedureEventBindings {
                events: &event_bindings,
                templates: &event_templates,
                coverage_decisions: &coverage_decisions,
                unproven_relations: &unproven_relations,
            },
            &call_noninterference_bindings,
            &terminal_bindings,
        )
        .map_err(TypestateBindingPlanError::Canonicalization)?;

        let event_indexes = index_sites(&compiled_events, |binding| &binding.site);
        let terminal_indexes = index_sites(&compiled_terminals, |binding| &binding.site);
        let initial_seed_indexes = index_initial_seed_points(&compiled_seeds);
        let event_call_point_indexes =
            index_call_point_sites(&compiled_events, |binding| &binding.site);
        let (call_noninterference_by_call, call_noninterference_by_point) =
            index_call_noninterference(&compiled_call_noninterference);
        let terminal_call_point_indexes =
            index_call_point_sites(&compiled_terminals, |binding| &binding.site);

        Ok(Self {
            protocol_hash: protocol.hash(),
            subjects: compiled_subjects.into_boxed_slice(),
            state_transfers: Box::new([]),
            transfers_by_call: HashMap::default(),
            transfers_by_point: HashMap::default(),
            transfers_by_source: HashMap::default(),
            transfers_by_result: HashMap::default(),
            initial_seeds: compiled_seeds.into_boxed_slice(),
            event_bindings: compiled_events.into_boxed_slice(),
            event_templates: compiled_templates.into_boxed_slice(),
            event_set,
            coverage_candidate_groups: compiled_coverage_groups.into_boxed_slice(),
            coverage_decisions: compiled_coverage_decisions.into_boxed_slice(),
            unproven_relations: unproven_relations.into_boxed_slice(),
            call_noninterference_bindings: compiled_call_noninterference.into_boxed_slice(),
            terminal_bindings: compiled_terminals.into_boxed_slice(),
            terminals_by_point: terminal_indexes.points,
            initial_seeds_by_point_all_contexts: initial_seed_indexes,
            events_by_point_all_contexts: event_indexes.all_points,
            events_by_call_all_contexts: event_indexes.all_calls,
            events_by_call_point_all_contexts: event_call_point_indexes,
            call_noninterference_by_call,
            call_noninterference_by_point,
            terminals_by_point_all_contexts: terminal_indexes.all_points,
            terminals_by_call_all_contexts: terminal_indexes.all_calls,
            terminals_by_call_point_all_contexts: terminal_call_point_indexes,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            canonical_rendering: canonical_rendering.into_boxed_str(),
            hash,
            summary_hashes,
            empty_summary_hash,
        })
    }

    /// The full pre-solve domain of possible finding-primary sites. Templates
    /// are subject-specific before solving; no root, context, quality or call
    /// closure filter is admissible here. This bounds the sealed production
    /// pipeline's locations, not event discovery or real-world findings.
    pub fn finding_primary_sites(
        &self,
    ) -> impl Iterator<Item = (TypestateSubjectId, &SemanticLocator)> {
        self.event_bindings
            .iter()
            .chain(self.event_templates.iter())
            .map(|event| (event.subject(), event.site().identity()))
            .chain(
                self.terminal_bindings
                    .iter()
                    .map(|terminal| (terminal.subject(), terminal.site().identity())),
            )
            .chain(self.unproven_relations.iter().map(|relation| {
                (
                    self.subject_id(&relation.subject)
                        .expect("compiled relation names a bound subject"),
                    relation.site.identity(),
                )
            }))
    }

    pub fn subjects(&self) -> &[BoundTypestateSubject] {
        &self.subjects
    }

    pub fn unproven_relations(&self) -> &[UnprovenEventRelation] {
        &self.unproven_relations
    }

    /// Visit the semantic artifact identity of every procedure and scoped
    /// locator that a subject root chain or an observation site names.
    ///
    /// This omits the relation arenas that a call-result root retains as
    /// audit provenance: call-result equality excludes that provenance, and
    /// typestate finding identities hash these keys. A registry that rejects
    /// stale bindings before solver execution must also validate the keys of
    /// `for_each_retained_artifact`, which includes those arenas.
    /// Duplicate keys are intentional here: callers that need a set can
    /// deduplicate without this hot-path model retaining another index.
    pub fn for_each_retained_artifact_key(&self, mut visit: impl FnMut(&SemanticArtifactKey)) {
        self.for_each_retained_subject_root(|root| {
            visit_access_path_root_artifacts(root, &mut visit)
        });
        self.for_each_retained_site(|site| visit_observation_site_artifacts(site, &mut visit));
        for transfer in &self.state_transfers {
            visit(transfer.call.procedure().artifact().key());
        }
    }

    /// Visit every concrete semantic artifact allocation retained by handles
    /// in this plan, including scoped locators and call-result relation arenas.
    pub fn for_each_retained_artifact(&self, mut visit: impl FnMut(&Arc<SemanticArtifact>)) {
        self.for_each_retained_subject_root(|root| {
            visit_access_path_root_artifact_values(root, &mut visit)
        });
        self.for_each_retained_site(|site| {
            visit_observation_site_artifact_values(site, &mut visit)
        });
        for transfer in &self.state_transfers {
            visit(transfer.call.procedure().artifact());
        }
    }

    fn for_each_retained_subject_root(&self, mut visit: impl FnMut(&AccessPathRoot)) {
        for subject in &self.subjects {
            visit(subject.object().identity());
        }
    }

    fn for_each_retained_site(&self, mut visit: impl FnMut(&TypestateObservationSite)) {
        for site in self
            .initial_seeds
            .iter()
            .map(BoundTypestateInitialSeed::site)
            .chain(self.event_bindings.iter().map(BoundTypestateEvent::site))
            .chain(
                self.call_noninterference_bindings
                    .iter()
                    .map(BoundTypestateCallNonInterference::site),
            )
            .chain(
                self.terminal_bindings
                    .iter()
                    .map(BoundTypestateTerminal::site),
            )
        {
            visit(site);
        }
    }

    pub const fn protocol_hash(&self) -> TypestateProtocolHash {
        self.protocol_hash
    }

    pub fn subject(&self, id: TypestateSubjectId) -> Option<&BoundTypestateSubject> {
        self.subjects.get(id.index())
    }

    pub fn subject_id(&self, key: &TypestateSubjectKey) -> Option<TypestateSubjectId> {
        self.subjects
            .binary_search_by(|subject| subject.key().cmp(key))
            .ok()
            .map(|index| self.subjects[index].id())
    }

    pub fn state_transfers(&self) -> &[BoundTypestateStateTransfer] {
        &self.state_transfers
    }

    pub(crate) fn state_transfers_at_edge(
        &self,
        origin: Option<&crate::analyzer::semantic::CallSiteHandle>,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateStateTransfer> {
        let indexes = match origin {
            Some(call) => self.transfers_by_call.get(call),
            None => self.transfers_by_point.get(point),
        };
        indexes
            .into_iter()
            .flat_map(|indexes| indexes.iter())
            .map(|index| &self.state_transfers[*index])
    }

    pub(crate) fn state_transfers_from(
        &self,
        source: TypestateSubjectId,
    ) -> impl Iterator<Item = &BoundTypestateStateTransfer> {
        self.transfers_by_source
            .get(&source)
            .into_iter()
            .flat_map(|indexes| indexes.iter())
            .map(|index| &self.state_transfers[*index])
    }

    pub fn state_transfers_to(
        &self,
        result: TypestateSubjectId,
    ) -> impl Iterator<Item = &BoundTypestateStateTransfer> {
        self.transfers_by_result
            .get(&result)
            .into_iter()
            .flat_map(|indexes| indexes.iter())
            .map(|index| &self.state_transfers[*index])
    }

    pub fn with_state_transfers(
        mut self,
        protocol: &CompiledProtocol,
        transfers: Vec<TypestateStateTransferSpec>,
    ) -> Result<Self, TypestateBindingPlanError> {
        check_count(
            "state_transfers",
            transfers.len(),
            MAX_TYPESTATE_EVENT_BINDINGS,
        )?;
        if transfers.is_empty() {
            return Ok(self);
        }
        let mut rows = Vec::new();
        let mut compiled = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut by_procedure =
            HashMap::<crate::analyzer::semantic::ProcedureHandle, Vec<serde_json::Value>>::new();
        for transfer in transfers {
            let result = self
                .subject_id(&transfer.result)
                .expect("transfer result is bound");
            let source = transfer
                .source
                .as_ref()
                .map(|key| self.subject_id(key).expect("transfer source is bound"));
            if !seen.insert((transfer.call.clone(), source, result)) {
                continue;
            }
            let site = TypestateObservationSite::call_site(
                transfer.call.clone(),
                TypestateBindingContext::root(),
            );
            let row = serde_json::json!({
                "call": canonical_site(&site),
                "source": transfer.source.as_ref().map(TypestateSubjectKey::public_canonical_rendering),
                "result": transfer.result.public_canonical_rendering(),
            });
            by_procedure
                .entry(transfer.call.procedure().clone())
                .or_default()
                .push(row.clone());
            rows.push(row);
            compiled.push(BoundTypestateStateTransfer {
                call: transfer.call,
                source,
                result,
            });
        }
        rows.sort_by_key(serde_json::Value::to_string);
        rows.dedup();
        let mut canonical: serde_json::Value = serde_json::from_slice(&self.canonical_bytes)
            .map_err(TypestateBindingPlanError::Canonicalization)?;
        canonical["state_transfers"] = serde_json::Value::Array(rows);
        // Only procedure summaries containing transfer calls acquire this relation.
        for (procedure, mut rows) in by_procedure {
            rows.sort_by_key(serde_json::Value::to_string);
            let old = self.summary_hash_for(
                procedure.artifact().key(),
                procedure.semantics().locator().declaration(),
            );
            let bytes = serde_json::to_vec(&(old, rows))
                .map_err(TypestateBindingPlanError::Canonicalization)?;
            self.summary_hashes
                .entry(procedure.artifact().key().clone())
                .or_default()
                .insert(
                    procedure.semantics().locator().declaration().clone(),
                    TypestateBindingSummaryHash::from_canonical_bytes(&bytes),
                );
        }
        // Replace only acquisitions at this call's invocation or normal-result
        // site. An earlier acquisition of the same subject still establishes
        // the state consumed by events before this transfer. These are exact
        // semantic handles, including context, rather than source positions.
        let mut replaced = std::collections::HashSet::new();
        for transfer in &compiled {
            if transfer.source == Some(transfer.result) {
                continue;
            }
            let procedure = transfer.call.procedure();
            let call = procedure
                .semantics()
                .call_site(transfer.call.id())
                .expect("transfer call exists");
            for point in std::iter::once(call.point).chain(call.normal_continuation.target()) {
                replaced.insert((
                    transfer.result,
                    TypestateObservationSite::program_point(
                        procedure
                            .point_handle(point)
                            .expect("transfer point exists"),
                        TypestateBindingContext::root(),
                    ),
                ));
            }
        }
        let mut seeds = self.initial_seeds.into_vec();
        seeds.retain(|seed| !replaced.contains(&(seed.subject, seed.site.clone())));
        for transfer in &compiled {
            if transfer.source.is_some() {
                continue;
            }
            let procedure = transfer.call.procedure();
            let call = procedure
                .semantics()
                .call_site(transfer.call.id())
                .expect("transfer call exists");
            let Some(point) = call.normal_continuation.target().map(|id| {
                procedure
                    .point_handle(id)
                    .expect("normal continuation belongs to the procedure")
            }) else {
                continue;
            };
            check_count(
                "initial_seeds",
                seeds.len().saturating_add(protocol.states().len()),
                MAX_TYPESTATE_INITIAL_SEEDS,
            )?;
            for (state, _) in protocol.states() {
                seeds.push(BoundTypestateInitialSeed {
                    subject: transfer.result,
                    state,
                    site: TypestateObservationSite::program_point(
                        point.clone(),
                        TypestateBindingContext::root(),
                    ),
                    activation_edge: None,
                    role: TypestateObjectRole::CurrentObject,
                    quality: TypestateBindingQuality::new(
                        ProofStatus::Unproven("uncertified state transfer source".into()),
                        EvidenceCompleteness::Partial("unknown transferred state".into()),
                        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1)
                            .expect("one transfer result"),
                    ),
                    reviewed_fresh_result: false,
                });
            }
        }
        self.initial_seeds_by_point_all_contexts = index_initial_seed_points(&seeds);
        self.initial_seeds = seeds.into();
        let mut seed_values = self
            .initial_seeds
            .iter()
            .map(|seed| {
                serde_json::to_value(CanonicalSeed {
                    subject: canonical_subject_key(
                        self.subject(seed.subject)
                            .expect("seed subject is bound")
                            .key(),
                    ),
                    state: protocol
                        .state_key(seed.state)
                        .expect("seed state is declared")
                        .as_str(),
                    site: canonical_site(&seed.site),
                    activation_edge: seed.activation_edge.as_ref().map(canonical_activation_edge),
                    role: seed.role,
                    quality: canonical_quality(&seed.quality),
                    reviewed_fresh_result: seed.reviewed_fresh_result,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(TypestateBindingPlanError::Canonicalization)?;
        seed_values.sort_by_key(serde_json::Value::to_string);
        canonical["initial_seeds"] = serde_json::Value::Array(seed_values);
        self.canonical_bytes = serde_json::to_vec(&canonical)
            .map_err(TypestateBindingPlanError::Canonicalization)?
            .into();
        self.canonical_rendering = serde_json::to_string_pretty(&canonical)
            .map_err(TypestateBindingPlanError::Canonicalization)?
            .into();
        self.hash = TypestateBindingPlanHash::from_canonical_bytes(&self.canonical_bytes);
        let mut by_call = HashMap::<_, Vec<usize>>::default();
        let mut by_point = HashMap::<_, Vec<usize>>::default();
        let mut by_source = HashMap::<_, Vec<usize>>::default();
        let mut by_result = HashMap::<_, Vec<usize>>::default();
        for (index, transfer) in compiled.iter().enumerate() {
            by_call
                .entry(transfer.call.clone())
                .or_default()
                .push(index);
            let procedure = transfer.call.procedure();
            let point = procedure
                .semantics()
                .call_site(transfer.call.id())
                .expect("transfer call exists")
                .point;
            by_point
                .entry(procedure.point_handle(point).expect("call point exists"))
                .or_default()
                .push(index);
            if let Some(source) = transfer.source {
                by_source.entry(source).or_default().push(index);
            }
            by_result.entry(transfer.result).or_default().push(index);
        }
        self.transfers_by_call = by_call
            .into_iter()
            .map(|(key, indexes)| (key, indexes.into_boxed_slice()))
            .collect();
        self.transfers_by_point = by_point
            .into_iter()
            .map(|(key, indexes)| (key, indexes.into_boxed_slice()))
            .collect();
        self.transfers_by_source = by_source
            .into_iter()
            .map(|(key, indexes)| (key, indexes.into_boxed_slice()))
            .collect();
        self.transfers_by_result = by_result
            .into_iter()
            .map(|(key, indexes)| (key, indexes.into_boxed_slice()))
            .collect();
        self.state_transfers = compiled.into();
        Ok(self)
    }

    pub fn initial_seeds(&self) -> &[BoundTypestateInitialSeed] {
        &self.initial_seeds
    }

    pub fn initial_seeds_at_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateInitialSeed> {
        flat_site_indexes(&self.initial_seeds_by_point_all_contexts, point)
            .map(|index| &self.initial_seeds[index])
    }

    pub fn event_bindings(&self) -> &[BoundTypestateEvent] {
        &self.event_bindings
    }

    pub fn event_templates(&self) -> &[BoundTypestateEvent] {
        &self.event_templates
    }

    pub fn event_set(&self) -> Option<&TypestateCoverageEventSet> {
        self.event_set.as_ref()
    }

    pub fn coverage_candidate_groups(&self) -> &[CoverageCandidateGroup] {
        &self.coverage_candidate_groups
    }

    pub fn coverage_candidate_group(
        &self,
        subject: TypestateSubjectId,
        site: &TypestateObservationSite,
        phase: CoverageCandidatePhase,
    ) -> Option<&CoverageCandidateGroup> {
        self.coverage_candidate_groups
            .iter()
            .find(|group| group.subject == subject && group.site == *site && group.phase == phase)
    }

    pub fn coverage_decision(
        &self,
        subject: TypestateSubjectId,
        site: &TypestateObservationSite,
        phase: CoverageCandidatePhase,
    ) -> Option<&CoverageDecision> {
        self.coverage_decisions.iter().find(|decision| {
            decision.subject == subject && decision.site == *site && decision.phase == phase
        })
    }

    pub fn event_binding(&self, id: TypestateEventBindingId) -> Option<&BoundTypestateEvent> {
        self.event_bindings.get(id.index()).or_else(|| {
            id.index()
                .checked_sub(self.event_bindings.len())
                .and_then(|index| self.event_templates.get(index))
        })
    }

    pub fn event_templates_at_call_site_all_contexts(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        self.event_templates
            .iter()
            .filter(move |template| template.site.call_site_handle() == Some(call))
    }

    pub fn call_noninterference_bindings(&self) -> &[BoundTypestateCallNonInterference] {
        &self.call_noninterference_bindings
    }

    pub fn call_is_proven_noninterfering(
        &self,
        subject: TypestateSubjectId,
        origin: Option<&crate::analyzer::semantic::CallSiteHandle>,
        point: &ProgramPointHandle,
    ) -> bool {
        let subjects = match origin {
            Some(call) => self.call_noninterference_by_call.get(call),
            None => self.call_noninterference_by_point.get(point),
        };
        subjects.is_some_and(|subjects| subjects.binary_search(&subject).is_ok())
    }

    pub fn terminal_bindings(&self) -> &[BoundTypestateTerminal] {
        &self.terminal_bindings
    }

    pub fn terminal_binding(
        &self,
        id: TypestateTerminalBindingId,
    ) -> Option<&BoundTypestateTerminal> {
        self.terminal_bindings.get(id.index())
    }

    pub fn event_bindings_at_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        indexed_bindings(
            flat_site_indexes(&self.events_by_point_all_contexts, point),
            &self.event_bindings,
        )
    }

    pub fn event_bindings_at_call_site_all_contexts(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        indexed_bindings(
            flat_site_indexes(&self.events_by_call_all_contexts, call),
            &self.event_bindings,
        )
    }

    pub fn event_bindings_at_call_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        indexed_bindings(
            flat_site_indexes(&self.events_by_call_point_all_contexts, point),
            &self.event_bindings,
        )
    }

    pub fn terminal_bindings_at_program_point(
        &self,
        point: &ProgramPointHandle,
        context: &OracleCallContext,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        indexed_bindings(
            site_indexes(&self.terminals_by_point, point, context),
            &self.terminal_bindings,
        )
    }

    pub fn terminal_bindings_at_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        indexed_bindings(
            flat_site_indexes(&self.terminals_by_point_all_contexts, point),
            &self.terminal_bindings,
        )
    }

    pub fn terminal_bindings_at_call_site_all_contexts(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        indexed_bindings(
            flat_site_indexes(&self.terminals_by_call_all_contexts, call),
            &self.terminal_bindings,
        )
    }

    pub fn terminal_bindings_at_call_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        indexed_bindings(
            flat_site_indexes(&self.terminals_by_call_point_all_contexts, point),
            &self.terminal_bindings,
        )
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn canonical_rendering(&self) -> &str {
        &self.canonical_rendering
    }

    pub const fn hash(&self) -> TypestateBindingPlanHash {
        self.hash
    }

    pub fn summary_hash_for(
        &self,
        artifact: &SemanticArtifactKey,
        declaration: &DeclarationLocator,
    ) -> TypestateBindingSummaryHash {
        self.summary_hashes
            .get(artifact)
            .and_then(|declarations| declarations.get(declaration))
            .copied()
            .unwrap_or(self.empty_summary_hash)
    }
}

enum AccessPathRootArtifactReference<'a> {
    Procedure(&'a ProcedureHandle),
    ScopedLocator(&'a crate::analyzer::semantic::ScopedSemanticLocator),
}

fn visit_access_path_root_references<'root>(
    root: &'root AccessPathRoot,
    mut visit: impl FnMut(AccessPathRootArtifactReference<'root>),
) {
    let mut root = root;
    loop {
        match root {
            AccessPathRoot::FieldPath { base, .. } => {
                root = base;
                continue;
            }
            AccessPathRoot::Value(value) => visit(AccessPathRootArtifactReference::Procedure(
                value.procedure(),
            )),
            AccessPathRoot::CallResult(result) => {
                visit(AccessPathRootArtifactReference::Procedure(
                    result.call().procedure(),
                ));
                visit(AccessPathRootArtifactReference::Procedure(
                    result.result().procedure(),
                ));
                visit(AccessPathRootArtifactReference::Procedure(result.callee()));
                for call in result
                    .caller_context()
                    .calls()
                    .iter()
                    .chain(result.callee_context().calls())
                {
                    visit(AccessPathRootArtifactReference::Procedure(call.procedure()));
                }
            }
            AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
                visit(AccessPathRootArtifactReference::Procedure(port.procedure()));
            }
            AccessPathRoot::Allocation(allocation) => visit(
                AccessPathRootArtifactReference::Procedure(allocation.procedure()),
            ),
            AccessPathRoot::LexicalCell(location) => visit(
                AccessPathRootArtifactReference::Procedure(location.procedure()),
            ),
            AccessPathRoot::Static(locator)
            | AccessPathRoot::TypeSummary(locator)
            | AccessPathRoot::ModuleObject(locator)
            | AccessPathRoot::External(locator) => {
                visit(AccessPathRootArtifactReference::ScopedLocator(locator))
            }
            AccessPathRoot::RuntimeObject(_) => {}
            AccessPathRoot::CallSubstitution {
                procedure, context, ..
            } => {
                visit(AccessPathRootArtifactReference::Procedure(procedure));
                for call in context.calls() {
                    visit(AccessPathRootArtifactReference::Procedure(call.procedure()));
                }
            }
        }
        break;
    }
}

fn visit_access_path_root_artifacts(
    root: &AccessPathRoot,
    visit: &mut impl FnMut(&SemanticArtifactKey),
) {
    visit_access_path_root_references(root, |reference| match reference {
        AccessPathRootArtifactReference::Procedure(procedure) => visit(procedure.artifact().key()),
        AccessPathRootArtifactReference::ScopedLocator(locator) => visit(locator.scope().key()),
    });
}

fn visit_observation_site_artifacts(
    site: &TypestateObservationSite,
    visit: &mut impl FnMut(&SemanticArtifactKey),
) {
    visit_observation_site_procedures(site, |procedure| visit(procedure.artifact().key()));
}

fn visit_observation_site_procedures(
    site: &TypestateObservationSite,
    mut visit: impl FnMut(&ProcedureHandle),
) {
    match site {
        TypestateObservationSite::ProgramPoint { point, context, .. } => {
            visit(point.procedure());
            for call in context.runtime().calls() {
                visit(call.procedure());
            }
        }
        TypestateObservationSite::CallSite { call, context, .. } => {
            visit(call.procedure());
            for context_call in context.runtime().calls() {
                visit(context_call.procedure());
            }
        }
    }
}

fn visit_access_path_root_artifact_values(
    root: &AccessPathRoot,
    visit: &mut impl FnMut(&Arc<SemanticArtifact>),
) {
    root.for_each_retained_artifact(visit);
}

fn visit_observation_site_artifact_values(
    site: &TypestateObservationSite,
    visit: &mut impl FnMut(&Arc<SemanticArtifact>),
) {
    visit_observation_site_procedures(site, |procedure| visit(procedure.artifact()));
}

#[derive(Debug)]
pub enum TypestateBindingPlanError {
    TooManyEntries {
        collection: &'static str,
        actual: usize,
        maximum: usize,
    },
    InvalidMultiplicity {
        retained: usize,
        maximum: usize,
    },
    DuplicateSubject,
    DuplicateInitialSeed,
    DuplicateEventBinding,
    ConflictingEventOrder,
    DuplicateCallNonInterferenceBinding,
    DuplicateTerminalBinding,
    UnknownSubject,
    UnknownState,
    UnknownEvent,
    UnknownExpectation,
    InvalidSeedSite,
    InvalidCallNonInterferenceSite,
    InvalidEventConditionSite,
    InvalidObservationShape,
    Canonicalization(serde_json::Error),
}

impl fmt::Display for TypestateBindingPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries {
                collection,
                actual,
                maximum,
            } => write!(
                formatter,
                "{collection} contains {actual} entries; maximum is {maximum}"
            ),
            Self::InvalidMultiplicity { retained, maximum } => write!(
                formatter,
                "binding multiplicity retains {retained} candidates; expected 1 through {maximum}"
            ),
            Self::DuplicateSubject => {
                formatter.write_str("binding plan contains a duplicate semantic subject")
            }
            Self::DuplicateInitialSeed => {
                formatter.write_str("binding plan contains a duplicate initial seed")
            }
            Self::DuplicateEventBinding => {
                formatter.write_str("binding plan contains a duplicate event binding")
            }
            Self::ConflictingEventOrder => formatter.write_str(
                "binding plan assigns more than one event to the same subject/site order",
            ),
            Self::DuplicateCallNonInterferenceBinding => formatter
                .write_str("binding plan contains a duplicate call non-interference binding"),
            Self::DuplicateTerminalBinding => {
                formatter.write_str("binding plan contains a duplicate terminal binding")
            }
            Self::UnknownSubject => {
                formatter.write_str("binding row references an unknown subject")
            }
            Self::UnknownState => formatter.write_str("binding seed references an unknown state"),
            Self::UnknownEvent => formatter.write_str("binding row references an unknown event"),
            Self::UnknownExpectation => {
                formatter.write_str("binding row references an unknown terminal expectation")
            }
            Self::InvalidSeedSite => formatter.write_str(
                "initial seeds must bind one object at a program point before propagation",
            ),
            Self::InvalidCallNonInterferenceSite => formatter
                .write_str("call non-interference bindings must retain one exact call site"),
            Self::InvalidEventConditionSite => {
                formatter.write_str("event argument conditions must retain one exact call site")
            }
            Self::InvalidObservationShape => formatter.write_str(
                "binding site or object role is incompatible with the protocol observation",
            ),
            Self::Canonicalization(error) => {
                write!(formatter, "failed to canonicalize binding plan: {error}")
            }
        }
    }
}

impl std::error::Error for TypestateBindingPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonicalization(error) => Some(error),
            Self::TooManyEntries { .. }
            | Self::InvalidMultiplicity { .. }
            | Self::DuplicateSubject
            | Self::DuplicateInitialSeed
            | Self::DuplicateEventBinding
            | Self::ConflictingEventOrder
            | Self::DuplicateCallNonInterferenceBinding
            | Self::DuplicateTerminalBinding
            | Self::UnknownSubject
            | Self::UnknownState
            | Self::UnknownEvent
            | Self::UnknownExpectation
            | Self::InvalidSeedSite
            | Self::InvalidCallNonInterferenceSite
            | Self::InvalidEventConditionSite
            | Self::InvalidObservationShape => None,
        }
    }
}

fn check_count(
    collection: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), TypestateBindingPlanError> {
    if actual > maximum {
        return Err(TypestateBindingPlanError::TooManyEntries {
            collection,
            actual,
            maximum,
        });
    }
    Ok(())
}

/// Project the oracle's durable object identity onto the subject key.
///
/// This view is lossy on purpose: a typestate subject names an object, not a
/// value slot, so the role and identity ordinal a durable value identity
/// carries are dropped for ordinary values and a capture port keeps only its
/// source locator. A lexical cell retains its bound value identity because
/// one lowering can create several cells at one source locator.
fn typestate_object_key(object: &AbstractObject) -> TypestateObjectKey {
    let identity = object
        .identity()
        .durable_identity()
        .expect("abstract object handles are validated at construction");
    match identity {
        DurableObjectIdentity::Value(value) => TypestateObjectKey::Value(value.locator),
        DurableObjectIdentity::FieldPath { base, member } => TypestateObjectKey::FieldPath {
            base: Box::new(typestate_durable_object_key(*base)),
            member,
        },
        DurableObjectIdentity::CallSubstitution { context, base } => {
            TypestateObjectKey::CallSubstitution {
                context: typestate_context_key(context),
                base: Box::new(typestate_durable_object_key(*base)),
            }
        }
        DurableObjectIdentity::CallResult {
            call,
            result,
            callee,
            caller_context,
            callee_context,
        } => TypestateObjectKey::CallResult {
            call,
            result: result.locator,
            callee,
            caller_context: typestate_context_key(caller_context),
            callee_context: typestate_context_key(callee_context),
        },
        DurableObjectIdentity::ProcedurePort { procedure, port } => {
            TypestateObjectKey::ProcedurePort {
                procedure,
                port: procedure_port_key(port),
            }
        }
        DurableObjectIdentity::CaptureSlot { procedure, port } => TypestateObjectKey::CaptureSlot {
            procedure,
            port: procedure_port_key(port),
        },
        DurableObjectIdentity::Allocation { locator } => TypestateObjectKey::Allocation(locator),
        DurableObjectIdentity::Static { locator } => TypestateObjectKey::Static(locator),
        DurableObjectIdentity::LexicalCell { locator, binding } => {
            TypestateObjectKey::LexicalCell { locator, binding }
        }
        DurableObjectIdentity::TypeSummary { locator } => TypestateObjectKey::TypeSummary(locator),
        DurableObjectIdentity::ModuleObject { locator } => {
            TypestateObjectKey::ModuleObject(locator)
        }
        DurableObjectIdentity::External { locator } => TypestateObjectKey::External(locator),
        DurableObjectIdentity::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            refinement_identity,
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
        } => TypestateObjectKey::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            refinement_identity,
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
        },
    }
}

fn typestate_durable_object_key(identity: DurableObjectIdentity) -> TypestateObjectKey {
    match identity {
        DurableObjectIdentity::Value(value) => TypestateObjectKey::Value(value.locator),
        DurableObjectIdentity::FieldPath { base, member } => TypestateObjectKey::FieldPath {
            base: Box::new(typestate_durable_object_key(*base)),
            member,
        },
        DurableObjectIdentity::CallSubstitution { context, base } => {
            TypestateObjectKey::CallSubstitution {
                context: typestate_context_key(context),
                base: Box::new(typestate_durable_object_key(*base)),
            }
        }
        DurableObjectIdentity::CallResult {
            call,
            result,
            callee,
            caller_context,
            callee_context,
        } => TypestateObjectKey::CallResult {
            call,
            result: result.locator,
            callee,
            caller_context: typestate_context_key(caller_context),
            callee_context: typestate_context_key(callee_context),
        },
        DurableObjectIdentity::ProcedurePort { procedure, port } => {
            TypestateObjectKey::ProcedurePort {
                procedure,
                port: procedure_port_key(port),
            }
        }
        DurableObjectIdentity::CaptureSlot { procedure, port } => TypestateObjectKey::CaptureSlot {
            procedure,
            port: procedure_port_key(port),
        },
        DurableObjectIdentity::Allocation { locator } => TypestateObjectKey::Allocation(locator),
        DurableObjectIdentity::Static { locator } => TypestateObjectKey::Static(locator),
        DurableObjectIdentity::LexicalCell { locator, binding } => {
            TypestateObjectKey::LexicalCell { locator, binding }
        }
        DurableObjectIdentity::TypeSummary { locator } => TypestateObjectKey::TypeSummary(locator),
        DurableObjectIdentity::ModuleObject { locator } => {
            TypestateObjectKey::ModuleObject(locator)
        }
        DurableObjectIdentity::External { locator } => TypestateObjectKey::External(locator),
        DurableObjectIdentity::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            refinement_identity,
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
        } => TypestateObjectKey::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            refinement_identity,
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
        },
    }
}

fn typestate_context_key(context: DurableCallContext) -> TypestateContextKey {
    TypestateContextKey {
        calls: context.calls,
        truncated: context.truncated,
    }
}

fn typestate_runtime_context_key(context: &OracleCallContext) -> TypestateContextKey {
    typestate_context_key(
        DurableCallContext::of(context).expect("call contexts retain validated call sites"),
    )
}

fn procedure_port_key(port: DurablePortIdentity) -> TypestateProcedurePortKey {
    match port {
        DurablePortIdentity::Receiver => TypestateProcedurePortKey::Receiver,
        DurablePortIdentity::Parameter { ordinal } => {
            TypestateProcedurePortKey::Parameter { ordinal }
        }
        DurablePortIdentity::NormalReturn => TypestateProcedurePortKey::NormalReturn,
        DurablePortIdentity::IndexedNormalReturn { ordinal } => {
            TypestateProcedurePortKey::IndexedNormalReturn { ordinal }
        }
        DurablePortIdentity::ExceptionalReturn => TypestateProcedurePortKey::ExceptionalReturn,
        DurablePortIdentity::Capture { locator, .. } => {
            TypestateProcedurePortKey::Capture { identity: locator }
        }
    }
}

pub(super) fn program_point_locator(point: &ProgramPointHandle) -> SemanticLocator {
    let _row = point
        .procedure()
        .semantics()
        .point(point.id())
        .expect("program-point handles are validated at construction");
    point
        .locator()
        .expect("validated semantic rows retain source mappings")
        .clone()
}

fn call_site_locator(call: &crate::analyzer::semantic::CallSiteHandle) -> SemanticLocator {
    let _row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("call-site handles are validated at construction");
    call.locator()
        .expect("validated semantic rows retain source mappings")
        .clone()
}

fn validate_seed_site(
    site: &TypestateObservationSite,
    activation_edge: Option<&crate::analyzer::semantic::ControlEdgeHandle>,
) -> Result<(), TypestateBindingPlanError> {
    let TypestateObservationSite::ProgramPoint { point, .. } = site else {
        return Err(TypestateBindingPlanError::InvalidSeedSite);
    };
    if activation_edge.is_some_and(|edge| edge.procedure() != point.procedure()) {
        return Err(TypestateBindingPlanError::InvalidSeedSite);
    }
    Ok(())
}

fn validate_terminal_exit(
    kind: ProtocolProcedureExitKind,
    site: &TypestateObservationSite,
    role: TypestateObjectRole,
) -> Result<(), TypestateBindingPlanError> {
    if role == TypestateObjectRole::CurrentObject && site_has_exit_kind(site, kind) {
        Ok(())
    } else {
        Err(TypestateBindingPlanError::InvalidObservationShape)
    }
}

fn validate_observation_shape(
    occurrence: &ProtocolEventOccurrence,
    site: &TypestateObservationSite,
    role: TypestateObjectRole,
) -> Result<(), TypestateBindingPlanError> {
    let valid = match occurrence {
        ProtocolEventOccurrence::Allocation => {
            matches!(site, TypestateObservationSite::ProgramPoint { .. })
                && role == TypestateObjectRole::AllocationResult
        }
        ProtocolEventOccurrence::Endpoint {
            phase: ProtocolObservationPhase::AtMatch,
        } => {
            matches!(site, TypestateObservationSite::ProgramPoint { .. })
                && role == TypestateObjectRole::MatchedValue
        }
        ProtocolEventOccurrence::Endpoint {
            phase:
                ProtocolObservationPhase::BeforeCall | ProtocolObservationPhase::AfterExceptionalReturn,
        } => {
            matches!(site, TypestateObservationSite::CallSite { .. })
                && matches!(
                    role,
                    TypestateObjectRole::Receiver | TypestateObjectRole::Argument
                )
        }
        ProtocolEventOccurrence::Endpoint {
            phase: ProtocolObservationPhase::AfterNormalReturn,
        } => {
            matches!(site, TypestateObservationSite::CallSite { .. })
                && matches!(
                    role,
                    TypestateObjectRole::Receiver
                        | TypestateObjectRole::Argument
                        | TypestateObjectRole::NormalReturn
                )
        }
        ProtocolEventOccurrence::ActualToFormal => {
            matches!(site, TypestateObservationSite::CallSite { .. })
                && matches!(
                    role,
                    TypestateObjectRole::Argument
                        | TypestateObjectRole::FormalReceiver
                        | TypestateObjectRole::FormalArgument { .. }
                )
        }
        ProtocolEventOccurrence::ReturnFlow => {
            matches!(site, TypestateObservationSite::CallSite { .. })
                && matches!(
                    role,
                    TypestateObjectRole::NormalReturn | TypestateObjectRole::ExceptionalReturn
                )
        }
        ProtocolEventOccurrence::FieldRead | ProtocolEventOccurrence::FieldWrite => {
            matches!(site, TypestateObservationSite::ProgramPoint { .. })
                && matches!(
                    role,
                    TypestateObjectRole::FieldBase
                        | TypestateObjectRole::FieldValue
                        | TypestateObjectRole::FieldLocation
                )
        }
        ProtocolEventOccurrence::Escape => {
            matches!(site, TypestateObservationSite::ProgramPoint { .. })
                && role == TypestateObjectRole::EscapedObject
        }
        ProtocolEventOccurrence::SuspensionBoundary => {
            let TypestateObservationSite::ProgramPoint { point, .. } = site else {
                return Err(TypestateBindingPlanError::InvalidObservationShape);
            };
            let point = point
                .procedure()
                .semantics()
                .point(point.id())
                .expect("validated program point handle resolves");
            role == TypestateObjectRole::CurrentObject
                && point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        crate::analyzer::semantic::SemanticEffect::AsyncSuspend { .. }
                    )
                })
        }
        ProtocolEventOccurrence::ProcedureExit { kind } => {
            role == TypestateObjectRole::CurrentObject && site_has_exit_kind(site, *kind)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(TypestateBindingPlanError::InvalidObservationShape)
    }
}

fn site_has_exit_kind(site: &TypestateObservationSite, kind: ProtocolProcedureExitKind) -> bool {
    let TypestateObservationSite::ProgramPoint { point, .. } = site else {
        return false;
    };
    crate::dataflow::is_procedure_exit_kind(
        point,
        match kind {
            ProtocolProcedureExitKind::Normal => {
                crate::analyzer::semantic::ReturnTransferKind::Normal
            }
            ProtocolProcedureExitKind::Exceptional => {
                crate::analyzer::semantic::ReturnTransferKind::Exceptional
            }
        },
    )
}

fn subject_id(
    subject_ids: &HashMap<TypestateSubjectKey, TypestateSubjectId>,
    subject: &TypestateSubjectKey,
) -> Result<TypestateSubjectId, TypestateBindingPlanError> {
    subject_ids
        .get(subject)
        .copied()
        .ok_or(TypestateBindingPlanError::UnknownSubject)
}

fn reject_adjacent_duplicates<T>(
    values: &[T],
    compare: fn(&T, &T) -> Ordering,
    error: TypestateBindingPlanError,
) -> Result<(), TypestateBindingPlanError> {
    if values
        .windows(2)
        .any(|pair| compare(&pair[0], &pair[1]) == Ordering::Equal)
    {
        return Err(error);
    }
    Ok(())
}

fn compare_seed_specs(
    left: &TypestateInitialSeedSpec,
    right: &TypestateInitialSeedSpec,
) -> Ordering {
    left.subject
        .cmp(&right.subject)
        .then_with(|| left.state.cmp(&right.state))
        .then_with(|| compare_sites(&left.site, &right.site))
        .then_with(|| {
            compare_activation_edges(
                left.activation_edge.as_ref(),
                right.activation_edge.as_ref(),
            )
        })
        .then_with(|| left.role.cmp(&right.role))
        .then_with(|| left.reviewed_fresh_result.cmp(&right.reviewed_fresh_result))
}

fn compare_activation_edges(
    left: Option<&crate::analyzer::semantic::ControlEdgeHandle>,
    right: Option<&crate::analyzer::semantic::ControlEdgeHandle>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => left.durable_key().cmp(&right.durable_key()),
    }
}

fn compare_event_specs(
    left: &TypestateEventBindingSpec,
    right: &TypestateEventBindingSpec,
) -> Ordering {
    compare_event_order_keys(left, right)
        .then_with(|| left.event.cmp(&right.event))
        .then_with(|| left.role.cmp(&right.role))
        .then_with(|| {
            left.modeled_external_effect
                .cmp(&right.modeled_external_effect)
        })
        .then_with(|| left.condition.cmp(&right.condition))
        .then_with(|| {
            compare_selected_operands(
                left.selected_operand.as_ref(),
                right.selected_operand.as_ref(),
            )
        })
}

fn compare_selected_operands(
    left: Option<&TypestateSelectedOperand>,
    right: Option<&TypestateSelectedOperand>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => left
            .call
            .durable_key()
            .cmp(&right.call.durable_key())
            .then_with(|| left.port.cmp(&right.port))
            .then_with(|| left.selected_target.cmp(&right.selected_target)),
    }
}

fn compare_event_order_keys(
    left: &TypestateEventBindingSpec,
    right: &TypestateEventBindingSpec,
) -> Ordering {
    compare_sites(&left.site, &right.site)
        .then_with(|| left.order.cmp(&right.order))
        .then_with(|| left.subject.cmp(&right.subject))
        .then_with(|| {
            compare_selected_operands(
                left.selected_operand.as_ref(),
                right.selected_operand.as_ref(),
            )
        })
}

fn compare_call_noninterference_specs(
    left: &TypestateCallNonInterferenceSpec,
    right: &TypestateCallNonInterferenceSpec,
) -> Ordering {
    compare_sites(&left.site, &right.site).then_with(|| left.subject.cmp(&right.subject))
}

fn compare_terminal_specs(
    left: &TypestateTerminalBindingSpec,
    right: &TypestateTerminalBindingSpec,
) -> Ordering {
    left.expectation
        .cmp(&right.expectation)
        .then_with(|| left.subject.cmp(&right.subject))
        .then_with(|| compare_sites(&left.site, &right.site))
        .then_with(|| left.role.cmp(&right.role))
}

fn compare_sites(left: &TypestateObservationSite, right: &TypestateObservationSite) -> Ordering {
    site_rank(left)
        .cmp(&site_rank(right))
        .then_with(|| left.identity().cmp(right.identity()))
        .then_with(|| left.context().key.cmp(&right.context().key))
}

const fn site_rank(site: &TypestateObservationSite) -> u8 {
    match site {
        TypestateObservationSite::ProgramPoint { .. } => 0,
        TypestateObservationSite::CallSite { .. } => 1,
    }
}

struct SiteIndexes {
    points: HashMap<ProgramPointHandle, HashMap<OracleCallContext, Box<[usize]>>>,
    all_points: HashMap<ProgramPointHandle, Box<[usize]>>,
    all_calls: HashMap<crate::analyzer::semantic::CallSiteHandle, Box<[usize]>>,
}

fn index_sites<T>(values: &[T], site: impl Fn(&T) -> &TypestateObservationSite) -> SiteIndexes {
    let mut points = HashMap::<ProgramPointHandle, HashMap<OracleCallContext, Vec<usize>>>::new();
    let mut calls = HashMap::<
        crate::analyzer::semantic::CallSiteHandle,
        HashMap<OracleCallContext, Vec<usize>>,
    >::new();
    for (index, value) in values.iter().enumerate() {
        match site(value) {
            TypestateObservationSite::ProgramPoint { point, context, .. } => {
                points
                    .entry(point.clone())
                    .or_default()
                    .entry(context.runtime.clone())
                    .or_default()
                    .push(index);
            }
            TypestateObservationSite::CallSite { call, context, .. } => {
                calls
                    .entry(call.clone())
                    .or_default()
                    .entry(context.runtime.clone())
                    .or_default()
                    .push(index);
            }
        }
    }
    let all_points = flatten_site_indexes(&points);
    let all_calls = flatten_site_indexes(&calls);
    SiteIndexes {
        points: box_site_indexes(points),
        all_points,
        all_calls,
    }
}

fn index_initial_seed_points(
    seeds: &[BoundTypestateInitialSeed],
) -> HashMap<ProgramPointHandle, Box<[usize]>> {
    let mut indexes = HashMap::<ProgramPointHandle, Vec<usize>>::new();
    for (index, seed) in seeds.iter().enumerate() {
        let point = match seed.activation_edge() {
            Some(edge) => {
                let row = edge
                    .procedure()
                    .semantics()
                    .control_edge(edge.id())
                    .expect("validated control-edge handles resolve");
                edge.procedure()
                    .point_handle(row.source_point)
                    .expect("validated control edges retain source points")
            }
            None => match seed.site() {
                TypestateObservationSite::ProgramPoint { point, .. } => point.clone(),
                TypestateObservationSite::CallSite { .. } => {
                    unreachable!("validated initial seeds use program-point observation sites")
                }
            },
        };
        indexes.entry(point).or_default().push(index);
    }
    indexes
        .into_iter()
        .map(|(point, indexes)| (point, indexes.into_boxed_slice()))
        .collect()
}

fn index_call_point_sites<T>(
    values: &[T],
    site: impl Fn(&T) -> &TypestateObservationSite,
) -> HashMap<ProgramPointHandle, Box<[usize]>> {
    let mut indexes = HashMap::<ProgramPointHandle, Vec<usize>>::new();
    for (index, value) in values.iter().enumerate() {
        if let TypestateObservationSite::CallSite { call, .. } = site(value) {
            let row = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("call-site handles are validated at construction");
            let point = call
                .procedure()
                .point_handle(row.point)
                .expect("validated call sites retain program points");
            indexes.entry(point).or_default().push(index);
        }
    }
    indexes
        .into_iter()
        .map(|(point, indexes)| (point, indexes.into_boxed_slice()))
        .collect()
}

fn index_call_noninterference(
    bindings: &[BoundTypestateCallNonInterference],
) -> (SubjectIndexByCall, SubjectIndexByPoint) {
    let mut by_call = HashMap::<_, Vec<_>>::new();
    let mut by_point = HashMap::<_, Vec<_>>::new();
    for binding in bindings {
        let call = binding
            .site()
            .call_site_handle()
            .expect("validated non-interference bindings retain call sites");
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("validated call-site handles resolve");
        let point = call
            .procedure()
            .point_handle(row.point)
            .expect("validated call sites retain program points");
        by_call
            .entry(call.clone())
            .or_default()
            .push(binding.subject());
        by_point.entry(point).or_default().push(binding.subject());
    }
    (box_subject_indexes(by_call), box_subject_indexes(by_point))
}

fn box_subject_indexes<K>(
    indexes: HashMap<K, Vec<TypestateSubjectId>>,
) -> HashMap<K, Box<[TypestateSubjectId]>>
where
    K: Eq + std::hash::Hash,
{
    indexes
        .into_iter()
        .map(|(key, mut subjects)| {
            subjects.sort_unstable();
            subjects.dedup();
            (key, subjects.into_boxed_slice())
        })
        .collect()
}

fn flatten_site_indexes<K>(
    indexes: &HashMap<K, HashMap<OracleCallContext, Vec<usize>>>,
) -> HashMap<K, Box<[usize]>>
where
    K: Clone + Eq + std::hash::Hash,
{
    indexes
        .iter()
        .map(|(site, contexts)| {
            let mut flattened = contexts
                .values()
                .flat_map(|indexes| indexes.iter().copied())
                .collect::<Vec<_>>();
            flattened.sort_unstable();
            flattened.dedup();
            (site.clone(), flattened.into_boxed_slice())
        })
        .collect()
}

fn box_site_indexes<K>(
    indexes: HashMap<K, HashMap<OracleCallContext, Vec<usize>>>,
) -> HashMap<K, HashMap<OracleCallContext, Box<[usize]>>>
where
    K: Eq + std::hash::Hash,
{
    indexes
        .into_iter()
        .map(|(key, contexts)| {
            (
                key,
                contexts
                    .into_iter()
                    .map(|(context, indexes)| (context, indexes.into_boxed_slice()))
                    .collect(),
            )
        })
        .collect()
}

fn site_indexes<'plan, K>(
    indexes: &'plan HashMap<K, HashMap<OracleCallContext, Box<[usize]>>>,
    site: &K,
    context: &OracleCallContext,
) -> impl Iterator<Item = usize> + 'plan
where
    K: Eq + std::hash::Hash,
{
    copied_site_indexes(
        indexes
            .get(site)
            .and_then(|contexts| contexts.get(context))
            .map(|indexes| indexes.as_ref()),
    )
}

fn flat_site_indexes<'plan, K>(
    indexes: &'plan HashMap<K, Box<[usize]>>,
    site: &K,
) -> impl Iterator<Item = usize> + 'plan
where
    K: Eq + std::hash::Hash,
{
    copied_site_indexes(indexes.get(site).map(|indexes| indexes.as_ref()))
}

fn copied_site_indexes<'plan>(
    indexes: Option<&'plan [usize]>,
) -> impl Iterator<Item = usize> + 'plan {
    indexes
        .into_iter()
        .flat_map(|indexes| indexes.iter().copied())
}

fn indexed_bindings<'plan, Binding>(
    indexes: impl Iterator<Item = usize> + 'plan,
    bindings: &'plan [Binding],
) -> impl Iterator<Item = &'plan Binding> + 'plan {
    indexes.map(move |index| &bindings[index])
}

fn canonical_json<T: serde::Serialize + ?Sized>(value: &T, invariant: &str) -> String {
    serde_json::to_string(value).expect(invariant)
}

#[derive(Default)]
struct ProcedureBindingIndexes {
    seeds: Vec<usize>,
    events: Vec<usize>,
    templates: Vec<usize>,
    coverage_decisions: Vec<usize>,
    unproven_relations: Vec<usize>,
    call_noninterference: Vec<usize>,
    terminals: Vec<usize>,
}

type ProcedureBindingSummaryHashes =
    HashMap<SemanticArtifactKey, HashMap<DeclarationLocator, TypestateBindingSummaryHash>>;
type ProcedureBindingSummaryHashResult =
    Result<(ProcedureBindingSummaryHashes, TypestateBindingSummaryHash), serde_json::Error>;

struct ProcedureEventBindings<'a> {
    events: &'a [TypestateEventBindingSpec],
    templates: &'a [TypestateEventBindingSpec],
    coverage_decisions: &'a [CoverageDecisionSpec],
    unproven_relations: &'a [UnprovenEventRelation],
}

fn procedure_summary_hashes(
    protocol: &CompiledProtocol,
    subjects: &[BoundTypestateSubjectSpec],
    initial_seeds: &[TypestateInitialSeedSpec],
    event_bindings: ProcedureEventBindings<'_>,
    call_noninterference_bindings: &[TypestateCallNonInterferenceSpec],
    terminal_bindings: &[TypestateTerminalBindingSpec],
) -> ProcedureBindingSummaryHashResult {
    let ProcedureEventBindings {
        events: event_bindings,
        templates: event_templates,
        coverage_decisions,
        unproven_relations,
    } = event_bindings;
    type ProcedureKey = (SemanticArtifactKey, DeclarationLocator);
    let mut indexes = HashMap::<ProcedureKey, ProcedureBindingIndexes>::new();
    for (index, seed) in initial_seeds.iter().enumerate() {
        indexes
            .entry(summary_binding_procedure_key(&seed.site))
            .or_default()
            .seeds
            .push(index);
    }
    for (index, event) in event_bindings.iter().enumerate() {
        indexes
            .entry(summary_binding_procedure_key(&event.site))
            .or_default()
            .events
            .push(index);
    }
    for (index, template) in event_templates.iter().enumerate() {
        indexes
            .entry(summary_binding_procedure_key(&template.site))
            .or_default()
            .templates
            .push(index);
    }
    for (index, decision) in coverage_decisions.iter().enumerate() {
        indexes
            .entry(summary_binding_procedure_key(&decision.site))
            .or_default()
            .coverage_decisions
            .push(index);
    }
    for (index, relation) in unproven_relations.iter().enumerate() {
        indexes
            .entry(summary_binding_procedure_key(&relation.site))
            .or_default()
            .unproven_relations
            .push(index);
    }
    for (index, binding) in call_noninterference_bindings.iter().enumerate() {
        indexes
            .entry(summary_binding_procedure_key(&binding.site))
            .or_default()
            .call_noninterference
            .push(index);
    }
    for (index, terminal) in terminal_bindings.iter().enumerate() {
        indexes
            .entry(summary_binding_procedure_key(&terminal.site))
            .or_default()
            .terminals
            .push(index);
    }

    let empty = CanonicalBindingPlan {
        event_set: None,
        coverage_candidate_groups: Vec::new(),
        coverage_decisions: Vec::new(),
        unproven_relations: Vec::new(),
        schema_version: BINDING_PLAN_SCHEMA_VERSION,
        protocol_hash: protocol.hash(),
        subjects: Vec::new(),
        initial_seeds: Vec::new(),
        event_bindings: Vec::new(),
        event_templates: Vec::new(),
        call_noninterference_bindings: Vec::new(),
        terminal_bindings: Vec::new(),
    };
    let empty_summary_hash =
        TypestateBindingSummaryHash::from_canonical_bytes(&serde_json::to_vec(&empty)?);
    let mut summary_hashes = ProcedureBindingSummaryHashes::new();
    for ((artifact, declaration), indexes) in indexes {
        let mut subject_keys = indexes
            .seeds
            .iter()
            .map(|index| &initial_seeds[*index].subject)
            .chain(
                indexes
                    .events
                    .iter()
                    .map(|index| &event_bindings[*index].subject),
            )
            .chain(
                indexes
                    .templates
                    .iter()
                    .map(|index| &event_templates[*index].subject),
            )
            .chain(
                indexes
                    .coverage_decisions
                    .iter()
                    .map(|index| &coverage_decisions[*index].subject),
            )
            .chain(
                indexes
                    .unproven_relations
                    .iter()
                    .map(|index| &unproven_relations[*index].subject),
            )
            .chain(
                indexes
                    .call_noninterference
                    .iter()
                    .map(|index| &call_noninterference_bindings[*index].subject),
            )
            .chain(
                indexes
                    .terminals
                    .iter()
                    .map(|index| &terminal_bindings[*index].subject),
            )
            .collect::<Vec<_>>();
        subject_keys.sort_unstable();
        subject_keys.dedup();
        let canonical = CanonicalBindingPlan {
            schema_version: BINDING_PLAN_SCHEMA_VERSION,
            protocol_hash: protocol.hash(),
            event_set: None,
            coverage_candidate_groups: Vec::new(),
            coverage_decisions: indexes
                .coverage_decisions
                .iter()
                .map(|index| {
                    let decision = &coverage_decisions[*index];
                    CanonicalCoverageDecision {
                        subject: canonical_subject_key(&decision.subject),
                        site: canonical_site(&decision.site),
                        phase: decision.phase,
                        kind: &decision.kind,
                    }
                })
                .collect(),
            unproven_relations: indexes
                .unproven_relations
                .iter()
                .map(|index| canonical_unproven_relation(&unproven_relations[*index]))
                .collect(),
            subjects: subject_keys
                .into_iter()
                .map(|key| {
                    let index = subjects
                        .binary_search_by(|subject| subject.key.cmp(key))
                        .expect("validated binding rows reference a declared subject");
                    canonical_subject(&subjects[index])
                })
                .collect(),
            initial_seeds: indexes
                .seeds
                .iter()
                .map(|index| {
                    let seed = &initial_seeds[*index];
                    CanonicalSeed {
                        subject: canonical_subject_key(&seed.subject),
                        state: seed.state.as_str(),
                        site: canonical_site(&seed.site),
                        activation_edge: seed
                            .activation_edge
                            .as_ref()
                            .map(canonical_activation_edge),
                        role: seed.role,
                        quality: canonical_quality(&seed.quality),
                        reviewed_fresh_result: seed.reviewed_fresh_result,
                    }
                })
                .collect(),
            event_bindings: indexes
                .events
                .iter()
                .map(|index| {
                    let binding = &event_bindings[*index];
                    CanonicalEventBinding {
                        event: binding.event.as_str(),
                        subject: canonical_subject_key(&binding.subject),
                        site: canonical_site(&binding.site),
                        order: binding.order,
                        role: binding.role,
                        quality: canonical_quality(&binding.quality),
                        modeled_external_effect: binding.modeled_external_effect.as_deref(),
                        semantic_effect: binding.semantic_effect.as_deref(),
                        condition: binding.condition.map(canonical_event_condition),
                        selected_operand: canonical_selected_operand(binding),
                    }
                })
                .collect(),
            event_templates: indexes
                .templates
                .iter()
                .map(|index| canonical_event_binding(&event_templates[*index]))
                .collect(),
            call_noninterference_bindings: indexes
                .call_noninterference
                .iter()
                .map(|index| {
                    let binding = &call_noninterference_bindings[*index];
                    CanonicalCallNonInterferenceBinding {
                        subject: canonical_subject_key(&binding.subject),
                        site: canonical_site(&binding.site),
                    }
                })
                .collect(),
            terminal_bindings: indexes
                .terminals
                .iter()
                .map(|index| {
                    let binding = &terminal_bindings[*index];
                    CanonicalTerminalBinding {
                        expectation: binding.expectation.as_str(),
                        subject: canonical_subject_key(&binding.subject),
                        site: canonical_site(&binding.site),
                        role: binding.role,
                        quality: canonical_quality(&binding.quality),
                    }
                })
                .collect(),
        };
        let hash =
            TypestateBindingSummaryHash::from_canonical_bytes(&serde_json::to_vec(&canonical)?);
        summary_hashes
            .entry(artifact)
            .or_default()
            .insert(declaration, hash);
    }
    Ok((summary_hashes, empty_summary_hash))
}

fn summary_binding_procedure_key(
    site: &TypestateObservationSite,
) -> (SemanticArtifactKey, DeclarationLocator) {
    let procedure = match site {
        TypestateObservationSite::ProgramPoint { point, .. } => point.procedure(),
        TypestateObservationSite::CallSite { call, .. } => call.procedure(),
    };
    (
        procedure.artifact().key().clone(),
        procedure.semantics().locator().declaration().clone(),
    )
}

#[derive(Serialize)]
struct CanonicalBindingPlan<'a> {
    schema_version: u32,
    protocol_hash: TypestateProtocolHash,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_set: Option<&'a TypestateCoverageEventSet>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    coverage_candidate_groups: Vec<CanonicalCoverageCandidateGroup<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    coverage_decisions: Vec<CanonicalCoverageDecision<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unproven_relations: Vec<CanonicalUnprovenRelation<'a>>,
    subjects: Vec<CanonicalSubject<'a>>,
    initial_seeds: Vec<CanonicalSeed<'a>>,
    event_bindings: Vec<CanonicalEventBinding<'a>>,
    event_templates: Vec<CanonicalEventBinding<'a>>,
    call_noninterference_bindings: Vec<CanonicalCallNonInterferenceBinding<'a>>,
    terminal_bindings: Vec<CanonicalTerminalBinding<'a>>,
}

#[derive(Serialize)]
struct CanonicalSubject<'a> {
    key: CanonicalSubjectKey<'a>,
    cardinality: &'static str,
    quality: CanonicalQuality,
}

#[derive(Serialize)]
struct CanonicalSubjectKey<'a> {
    class: &'a str,
    object: CanonicalObjectKey<'a>,
}

#[derive(Serialize)]
struct CanonicalValueIdentity<'a> {
    identity: CanonicalLocator<'a>,
    role: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ordinal: Option<u32>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CanonicalObjectKey<'a> {
    Value {
        identity: CanonicalLocator<'a>,
    },
    FieldPath {
        base: Box<CanonicalObjectKey<'a>>,
        member: CanonicalLocator<'a>,
    },
    CallSubstitution {
        context: CanonicalContext<'a>,
        base: Box<CanonicalObjectKey<'a>>,
    },
    CallResult {
        call: CanonicalLocator<'a>,
        result: CanonicalLocator<'a>,
        callee: CanonicalLocator<'a>,
        caller_context: CanonicalContext<'a>,
        callee_context: CanonicalContext<'a>,
    },
    ProcedurePort {
        procedure: CanonicalLocator<'a>,
        port: CanonicalProcedurePortKey<'a>,
    },
    Allocation {
        identity: CanonicalLocator<'a>,
    },
    Static {
        identity: CanonicalLocator<'a>,
    },
    LexicalCell {
        identity: CanonicalLocator<'a>,
        binding: CanonicalValueIdentity<'a>,
    },
    CaptureSlot {
        procedure: CanonicalLocator<'a>,
        port: CanonicalProcedurePortKey<'a>,
    },
    TypeSummary {
        identity: CanonicalLocator<'a>,
    },
    ModuleObject {
        identity: CanonicalLocator<'a>,
    },
    External {
        identity: CanonicalLocator<'a>,
    },
    RuntimeObject {
        runtime_profile_digest: &'a str,
        realm: &'a str,
        exposure_id: &'a str,
        container_member: &'a str,
        state_boundary: &'a str,
        /// Always present in the public rendering; omitted only by
        /// [`TypestateSubjectKey::finding_identity_rendering`].
        #[serde(skip_serializing_if = "Option::is_none")]
        refinement_identity: Option<crate::analyzer::semantic::StableDigest>,
        active_model_set_hash: &'a str,
        manifest_digest: &'a str,
        shard_id: &'a str,
        behavior_id: &'a str,
        activation_source: &'a str,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CanonicalProcedurePortKey<'a> {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    IndexedNormalReturn { ordinal: u32 },
    ExceptionalReturn,
    Capture { identity: CanonicalLocator<'a> },
}

#[derive(Serialize)]
struct CanonicalSeed<'a> {
    subject: CanonicalSubjectKey<'a>,
    state: &'a str,
    site: CanonicalSite<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    activation_edge: Option<CanonicalActivationEdge>,
    role: TypestateObjectRole,
    quality: CanonicalQuality,
    reviewed_fresh_result: bool,
}

#[derive(Serialize)]
struct CanonicalActivationEdge {
    artifact: String,
    procedure: u32,
    edge: u32,
}

#[derive(Serialize)]
struct CanonicalEventBinding<'a> {
    event: &'a str,
    subject: CanonicalSubjectKey<'a>,
    site: CanonicalSite<'a>,
    order: u32,
    role: TypestateObjectRole,
    quality: CanonicalQuality,
    #[serde(skip_serializing_if = "Option::is_none")]
    modeled_external_effect: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_effect: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    condition: Option<CanonicalEventCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_operand: Option<CanonicalSelectedOperand<'a>>,
}

fn canonical_event_binding(binding: &TypestateEventBindingSpec) -> CanonicalEventBinding<'_> {
    CanonicalEventBinding {
        event: binding.event.as_str(),
        subject: canonical_subject_key(&binding.subject),
        site: canonical_site(&binding.site),
        order: binding.order,
        role: binding.role,
        quality: canonical_quality(&binding.quality),
        modeled_external_effect: binding.modeled_external_effect.as_deref(),
        semantic_effect: binding.semantic_effect.as_deref(),
        condition: binding.condition.map(canonical_event_condition),
        selected_operand: canonical_selected_operand(binding),
    }
}

#[derive(Serialize)]
struct CanonicalSelectedOperand<'a> {
    call: CanonicalSite<'a>,
    port: TypestateEventPort,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_target: Option<CanonicalSelectedTarget>,
}

#[derive(Serialize)]
struct CanonicalSelectedTarget {
    artifact: String,
    procedure: u32,
    interpretation: crate::analyzer::semantic::ProcedureInterpretation,
}

fn canonical_selected_operand(
    binding: &TypestateEventBindingSpec,
) -> Option<CanonicalSelectedOperand<'_>> {
    binding
        .selected_operand
        .as_ref()
        .map(|operand| CanonicalSelectedOperand {
            call: canonical_site(&binding.site),
            port: operand.port,
            selected_target: operand.selected_target.as_ref().map(
                |(artifact, procedure, interpretation)| CanonicalSelectedTarget {
                    // Checkout-independent: a diff base evaluated from another mount
                    // must produce the same plan identity for the same content.
                    artifact: artifact.public_fingerprint().to_string(),
                    procedure: procedure.get(),
                    interpretation: *interpretation,
                },
            ),
        })
}

fn canonical_coverage_candidate(
    candidate: &CoverageCandidateSpec,
) -> CanonicalCoverageCandidate<'_> {
    CanonicalCoverageCandidate {
        event: &candidate.event,
        semantic_effect: candidate.semantic_effect.as_deref(),
        quality: canonical_quality(&candidate.quality),
        alias_derived: candidate.alias_derived,
        role: candidate.role,
    }
}

fn canonical_coverage_candidate_group(
    group: &CoverageCandidateGroupSpec,
) -> CanonicalCoverageCandidateGroup<'_> {
    CanonicalCoverageCandidateGroup {
        subject: canonical_subject_key(&group.subject),
        site: canonical_site(&group.site),
        phase: group.phase,
        candidates: group
            .candidates
            .iter()
            .map(canonical_coverage_candidate)
            .collect(),
    }
}

#[derive(Serialize)]
struct CanonicalCoverageCandidateGroup<'a> {
    subject: CanonicalSubjectKey<'a>,
    site: CanonicalSite<'a>,
    phase: CoverageCandidatePhase,
    candidates: Vec<CanonicalCoverageCandidate<'a>>,
}

#[derive(Serialize)]
struct CanonicalCoverageCandidate<'a> {
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_effect: Option<&'a str>,
    quality: CanonicalQuality,
    alias_derived: bool,
    role: TypestateObjectRole,
}

#[derive(Serialize)]
struct CanonicalCoverageDecision<'a> {
    subject: CanonicalSubjectKey<'a>,
    site: CanonicalSite<'a>,
    phase: CoverageCandidatePhase,
    kind: &'a CoverageDecisionKind,
}

#[derive(Serialize)]
struct CanonicalEventCondition {
    argument_index: u32,
    expected: bool,
}

fn canonical_event_condition(condition: TypestateEventCondition) -> CanonicalEventCondition {
    CanonicalEventCondition {
        argument_index: condition.argument_index(),
        expected: condition.expected(),
    }
}

#[derive(Serialize)]
struct CanonicalCallNonInterferenceBinding<'a> {
    subject: CanonicalSubjectKey<'a>,
    site: CanonicalSite<'a>,
}

#[derive(Serialize)]
struct CanonicalTerminalBinding<'a> {
    expectation: &'a str,
    subject: CanonicalSubjectKey<'a>,
    site: CanonicalSite<'a>,
    role: TypestateObjectRole,
    quality: CanonicalQuality,
}

#[derive(Serialize)]
struct CanonicalQuality {
    proof: &'static str,
    completeness: &'static str,
    coverage: &'static str,
    retained: u32,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CanonicalSite<'a> {
    ProgramPoint {
        identity: CanonicalLocator<'a>,
        context: CanonicalContext<'a>,
    },
    CallSite {
        identity: CanonicalLocator<'a>,
        context: CanonicalContext<'a>,
    },
}

#[derive(Serialize)]
struct CanonicalContext<'a> {
    calls: Vec<CanonicalLocator<'a>>,
    truncated: bool,
}

/// A semantic locator as the binding plan's canonical bytes carry it.
///
/// Deliberately without the locator's `WorkspaceMountId`. The mount is a hash
/// of the absolute workspace root, and the plan's hash reaches a typestate
/// finding's identity through `binding_plan_hash`, so folding it in made every
/// typestate finding identity depend on where the checkout happens to live: a
/// `--diff-base` run, which analyzes the base revision at a temporary root,
/// could never match a base finding to its head counterpart, and no evaluation
/// unit published from one root could ever be reused at another. The path,
/// language, declaration segments, role and anchor below already name the
/// procedure exactly, within a plan whose every locator comes from the one
/// workspace being analyzed.
///
/// The declaration segments carry no byte anchor either (#3022). A segment
/// names one enclosing declaration, and a declaration's identity is its kind,
/// its name and its ordinal among the same-kind, same-name siblings of its
/// parent -- which `ProcedureInventoryBuilder` mints so that no two segments
/// under one parent share the triple (an unmaterialized external declaration
/// overloads the same ordinal with its arity, which separates its members the
/// same way), and which is exactly what the policy crate's own
/// `append_declaration_identity` already hashes. A segment's
/// anchor is the span of the *container*, not of the thing the locator names:
/// the outermost `file` segment's anchor is the whole file, so any edit
/// anywhere in a file re-keyed every locator declared in it, and with it the
/// subject identity of every typestate finding whose tracked object was
/// acquired through a callee that file declares. Only `anchor` below stays,
/// and it belongs to what this locator names.
///
/// That anchor is rendered relative to the innermost declaration segment's
/// start (#3054), never as an absolute file offset. See [`CanonicalAnchor`].
#[derive(Serialize)]
struct CanonicalLocator<'a> {
    path: &'a str,
    language: &'static str,
    declaration: Vec<CanonicalDeclarationSegment<'a>>,
    role: &'static str,
    anchor: CanonicalAnchor,
}

#[derive(Serialize)]
struct CanonicalDeclarationSegment<'a> {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    sibling_ordinal: u32,
}

/// The span a canonical locator names, addressed relative to the declaration
/// the same locator names (#3054).
///
/// An absolute byte offset is not an identity: every declaration below an edit
/// in the same file moves by the edit's length delta, so lengthening anything
/// above an acquisition callee re-keyed every subject acquired through it and
/// re-keyed the binding-plan hash that folds them, exactly the way the byte
/// anchors that #3022 removed from the declaration segments did. Subtracting
/// the innermost declaration's start is a translation, so it is injective on
/// one declaration's spans and cannot merge two of them; and the declaration
/// path, path and role that accompany it in [`CanonicalLocator`] separate the
/// declarations from each other.
///
/// Line and byte-column coordinates are dropped with the absolute offset. They
/// are absolute in the same way -- a line inserted anywhere above shifts every
/// line below it -- and they add nothing: within one file revision the byte
/// range determines them.
///
/// Not every locator sits inside the declaration it carries.
/// `memory_member_locator` and `declared_member_locator` (Scala, Java, Kotlin,
/// Go, Rust, PHP, Python, JS/TS) name a class-level member from inside a
/// method, and attach it to the *enclosing procedure's* declaration path: the
/// member is a sibling of that procedure, not a part of it, so the subtraction
/// would underflow whenever the member is declared above the method.
/// `SemanticLocator::push_procedure_local_identity` meets the same shape and
/// answers it the same way, with an `external-locator` tag. Such an anchor is
/// tagged `out_of_declaration` and keeps its file-relative start, which is
/// still unique -- the tag keeps it from colliding with a declaration-relative
/// offset of the same number -- and is no less stable than what it replaces.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CanonicalAnchor {
    /// The locator's span lies inside the innermost declaration of its own
    /// path, and is addressed from that declaration's first byte.
    InDeclaration {
        start_offset: u32,
        length: u32,
        occurrence: u32,
    },
    /// The locator's span lies outside the innermost declaration of its own
    /// path, and is addressed from the first byte of the file.
    OutOfDeclaration {
        start_byte: u32,
        length: u32,
        occurrence: u32,
    },
}

fn canonical_subject(subject: &BoundTypestateSubjectSpec) -> CanonicalSubject<'_> {
    CanonicalSubject {
        key: canonical_subject_key(&subject.key),
        cardinality: cardinality_label(subject.object.cardinality()),
        quality: canonical_quality(&subject.quality),
    }
}

fn canonical_subject_key(key: &TypestateSubjectKey) -> CanonicalSubjectKey<'_> {
    CanonicalSubjectKey {
        class: key.class.as_str(),
        object: canonical_object_key(&key.object),
    }
}

fn canonical_object_key(key: &TypestateObjectKey) -> CanonicalObjectKey<'_> {
    match key {
        TypestateObjectKey::Value(identity) => CanonicalObjectKey::Value {
            identity: canonical_locator(identity),
        },
        TypestateObjectKey::FieldPath { base, member } => CanonicalObjectKey::FieldPath {
            base: Box::new(canonical_object_key(base)),
            member: canonical_locator(member),
        },
        TypestateObjectKey::CallSubstitution { context, base } => {
            CanonicalObjectKey::CallSubstitution {
                context: canonical_context_key(context),
                base: Box::new(canonical_object_key(base)),
            }
        }
        TypestateObjectKey::CallResult {
            call,
            result,
            callee,
            caller_context,
            callee_context,
        } => CanonicalObjectKey::CallResult {
            call: canonical_locator(call),
            result: canonical_locator(result),
            callee: canonical_locator(callee),
            caller_context: canonical_context_key(caller_context),
            callee_context: canonical_context_key(callee_context),
        },
        TypestateObjectKey::ProcedurePort { procedure, port } => {
            CanonicalObjectKey::ProcedurePort {
                procedure: canonical_locator(procedure),
                port: canonical_procedure_port_key(port),
            }
        }
        TypestateObjectKey::Allocation(identity) => CanonicalObjectKey::Allocation {
            identity: canonical_locator(identity),
        },
        TypestateObjectKey::Static(identity) => CanonicalObjectKey::Static {
            identity: canonical_locator(identity),
        },
        TypestateObjectKey::LexicalCell { locator, binding } => CanonicalObjectKey::LexicalCell {
            identity: canonical_locator(locator),
            binding: canonical_value_identity(binding),
        },
        TypestateObjectKey::CaptureSlot { procedure, port } => CanonicalObjectKey::CaptureSlot {
            procedure: canonical_locator(procedure),
            port: canonical_procedure_port_key(port),
        },
        TypestateObjectKey::TypeSummary(identity) => CanonicalObjectKey::TypeSummary {
            identity: canonical_locator(identity),
        },
        TypestateObjectKey::ModuleObject(identity) => CanonicalObjectKey::ModuleObject {
            identity: canonical_locator(identity),
        },
        TypestateObjectKey::External(identity) => CanonicalObjectKey::External {
            identity: canonical_locator(identity),
        },
        TypestateObjectKey::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            refinement_identity,
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
        } => CanonicalObjectKey::RuntimeObject {
            runtime_profile_digest,
            realm,
            exposure_id,
            container_member,
            state_boundary,
            refinement_identity: Some(*refinement_identity),
            active_model_set_hash,
            manifest_digest,
            shard_id,
            behavior_id,
            activation_source,
        },
    }
}

fn canonical_procedure_port_key(key: &TypestateProcedurePortKey) -> CanonicalProcedurePortKey<'_> {
    match key {
        TypestateProcedurePortKey::Receiver => CanonicalProcedurePortKey::Receiver,
        TypestateProcedurePortKey::Parameter { ordinal } => {
            CanonicalProcedurePortKey::Parameter { ordinal: *ordinal }
        }
        TypestateProcedurePortKey::NormalReturn => CanonicalProcedurePortKey::NormalReturn,
        TypestateProcedurePortKey::IndexedNormalReturn { ordinal } => {
            CanonicalProcedurePortKey::IndexedNormalReturn { ordinal: *ordinal }
        }
        TypestateProcedurePortKey::ExceptionalReturn => {
            CanonicalProcedurePortKey::ExceptionalReturn
        }
        TypestateProcedurePortKey::Capture { identity } => CanonicalProcedurePortKey::Capture {
            identity: canonical_locator(identity),
        },
    }
}

fn canonical_quality(quality: &TypestateBindingQuality) -> CanonicalQuality {
    CanonicalQuality {
        proof: quality.proof.label(),
        completeness: quality.completeness.label(),
        coverage: coverage_label(quality.multiplicity.coverage),
        retained: quality.multiplicity.retained,
    }
}

fn canonical_activation_edge(
    edge: &crate::analyzer::semantic::ControlEdgeHandle,
) -> CanonicalActivationEdge {
    CanonicalActivationEdge {
        artifact: edge
            .procedure()
            .artifact()
            .key()
            .public_fingerprint()
            .to_string(),
        procedure: edge.procedure().id().get(),
        edge: edge.id().get(),
    }
}

fn canonical_site(site: &TypestateObservationSite) -> CanonicalSite<'_> {
    match site {
        TypestateObservationSite::ProgramPoint {
            identity, context, ..
        } => CanonicalSite::ProgramPoint {
            identity: canonical_locator(identity),
            context: canonical_context(context),
        },
        TypestateObservationSite::CallSite {
            identity, context, ..
        } => CanonicalSite::CallSite {
            identity: canonical_locator(identity),
            context: canonical_context(context),
        },
    }
}

fn canonical_context(context: &TypestateBindingContext) -> CanonicalContext<'_> {
    canonical_context_key(&context.key)
}

fn canonical_context_key(context: &TypestateContextKey) -> CanonicalContext<'_> {
    CanonicalContext {
        calls: context.calls.iter().map(canonical_locator).collect(),
        truncated: context.truncated,
    }
}

fn serialize_coverage_context<S>(
    context: &TypestateContextKey,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    canonical_context_key(context).serialize(serializer)
}

fn canonical_value_identity(value: &DurableValueIdentity) -> CanonicalValueIdentity<'_> {
    CanonicalValueIdentity {
        identity: canonical_locator(&value.locator),
        role: value.role.as_ref(),
        ordinal: value.ordinal,
    }
}

fn canonical_locator(locator: &SemanticLocator) -> CanonicalLocator<'_> {
    CanonicalLocator {
        path: locator.path().as_str(),
        language: locator.language().stable_label(),
        declaration: locator
            .declaration()
            .segments()
            .iter()
            .map(|segment| CanonicalDeclarationSegment {
                kind: segment.kind().stable_label(),
                name: segment.name(),
                sibling_ordinal: segment.sibling_ordinal(),
            })
            .collect(),
        role: locator.role().stable_label(),
        anchor: canonical_anchor(locator.anchor(), locator.declaration()),
    }
}

/// Address `anchor` from the start of the innermost segment of `declaration`.
///
/// The innermost segment is the declaration the locator was minted inside: for
/// a procedure locator it is the procedure itself, so the offset is zero; for a
/// call site or a program point it is the enclosing procedure. See
/// [`CanonicalAnchor`] for why the absolute offset is not an identity and what
/// the out-of-declaration case is.
fn canonical_anchor(anchor: SourceAnchor, declaration: &DeclarationLocator) -> CanonicalAnchor {
    let span = anchor.span();
    // `SourceSpan::new` rejects a reversed span, so this cannot wrap.
    let length = span.end_byte() - span.start_byte();
    let occurrence = anchor.occurrence();
    let container = declaration
        .segments()
        .last()
        .expect("a declaration locator has at least one segment")
        .anchor()
        .span();
    if span.start_byte() >= container.start_byte() && span.end_byte() <= container.end_byte() {
        return CanonicalAnchor::InDeclaration {
            start_offset: span.start_byte() - container.start_byte(),
            length,
            occurrence,
        };
    }
    // A locator either sits inside the declaration it carries or names a
    // sibling of it. A span that straddles the boundary is neither, and means
    // the producer paired an anchor with a declaration path that does not
    // describe it -- which no clamped offset could make into an identity.
    debug_assert!(
        span.end_byte() <= container.start_byte() || span.start_byte() >= container.end_byte(),
        "an out-of-declaration locator anchor is a sibling of its declaration, \
         not a partial overlap of it: anchor {span:?}, declaration {container:?}"
    );
    CanonicalAnchor::OutOfDeclaration {
        start_byte: span.start_byte(),
        length,
        occurrence,
    }
}

const fn cardinality_label(cardinality: ObjectCardinality) -> &'static str {
    match cardinality {
        ObjectCardinality::Singleton => "singleton",
        ObjectCardinality::Summary => "summary",
        ObjectCardinality::Unknown => "unknown",
    }
}

const fn coverage_label(coverage: CandidateCoverage) -> &'static str {
    match coverage {
        CandidateCoverage::Exhaustive => "exhaustive",
        CandidateCoverage::Open => "open",
        CandidateCoverage::Truncated => "truncated",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[hardwon("#12769: self-transfer removed its own seed and hid a later violation")]
    fn self_transfer_keeps_source_seed_and_later_violation() {
        use crate::analyzer::semantic::{
            AbstractObject, AccessPathRoot, IcfgEdgeKind, ObjectCardinality, SemanticBudget,
            SemanticRequest,
        };
        use crate::cancellation::CancellationToken;
        use crate::dataflow::{DataflowEdge, DataflowOutput, DistributiveDataflowProblem};
        use crate::inline_project::InlineTestProject;
        use crate::typestate::*;
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "root.ts",
                "function root(value: object) { touch(value); }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("root.ts"),
                &mut SemanticRequest::new(
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                ),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|p| !p.call_sites().is_empty())
            .unwrap();
        let root = artifact.procedure_handle(procedure.id()).unwrap();
        let call = root.call_site_handle(procedure.call_sites()[0].id).unwrap();
        let object = AbstractObject::new(
            AccessPathRoot::Value(
                root.value_handle(procedure.call_sites()[0].arguments[0].value)
                    .unwrap(),
            ),
            ObjectCardinality::Singleton,
        )
        .unwrap();
        let class = TypestateSubjectClassKey::new("cookie").unwrap();
        let key = TypestateSubjectKey::for_object(class.clone(), &object);
        let protocol = ProtocolSpec::from_json(br#"{
          "schema_version":1,"states":["ready","marked","violated"],"initial_state":"ready",
          "accepting_states":["ready","marked"],"error_states":["violated"],
          "events":[{"id":"mark","observation":{"occurrence":{"type":"endpoint","phase":"after_normal_return"}}},{"id":"use","observation":{"occurrence":{"type":"endpoint","phase":"at_match"}}}],
          "transitions":[{"from":"ready","on":"mark","to":"marked"},{"from":"marked","on":"mark","to":"ready"},{"from":"ready","on":"use","to":"ready"},{"from":"marked","on":"use","to":"violated"}],"terminal_expectations":[],
          "semantics":{"analysis_mode":"may","unmatched_event":"preserve_state","uncertainty":{"ambiguous_dispatch":"preserve_uncertainty","unknown_call":"preserve_uncertainty","external_call":"preserve_uncertainty","escape":"preserve_uncertainty","incomplete_analysis":"preserve_uncertainty"}}
        }"#).unwrap().compile().unwrap();
        let row = root.semantics().call_site(call.id()).unwrap();
        let call_point = root.point_handle(row.point).unwrap();
        let returned_point = root
            .point_handle(row.normal_continuation.target().unwrap())
            .unwrap();
        let exit = root.point_handle(procedure.normal_exit_point()).unwrap();
        let site =
            |point| TypestateObservationSite::program_point(point, TypestateBindingContext::root());
        let bindings = TypestateBindingPlan::try_new(
            &protocol,
            vec![BoundTypestateSubjectSpec::new(
                class,
                object,
                TypestateBindingQuality::proven_unique(),
            )],
            vec![TypestateInitialSeedSpec::new(
                key.clone(),
                ProtocolStateKey::new("ready").unwrap(),
                site(call_point.clone()),
                TypestateObjectRole::MatchedValue,
                TypestateBindingQuality::proven_unique(),
            )],
            vec![
                TypestateEventBindingSpec::new(
                    ProtocolEventKey::new("mark").unwrap(),
                    key.clone(),
                    TypestateObservationSite::call_site(
                        call.clone(),
                        TypestateBindingContext::root(),
                    ),
                    0,
                    TypestateObjectRole::NormalReturn,
                    TypestateBindingQuality::proven_unique(),
                ),
                TypestateEventBindingSpec::new(
                    ProtocolEventKey::new("use").unwrap(),
                    key.clone(),
                    site(exit.clone()),
                    0,
                    TypestateObjectRole::MatchedValue,
                    TypestateBindingQuality::proven_unique(),
                ),
            ],
            vec![],
        )
        .unwrap()
        .with_state_transfers(
            &protocol,
            vec![TypestateStateTransferSpec {
                call: call.clone(),
                source: Some(key.clone()),
                result: key,
            }],
        )
        .unwrap();
        assert_eq!(bindings.initial_seeds().len(), 1);
        #[derive(Default)]
        struct Facts(Vec<TypestateFact>);
        impl DataflowOutput<TypestateFact> for Facts {
            fn emit(&mut self, fact: TypestateFact) -> bool {
                self.0.push(fact);
                true
            }
        }
        let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
        let proof = ProofStatus::Proven;
        let complete = EvidenceCompleteness::Complete;
        let mut returned = Facts::default();
        problem.normal_flow(
            DataflowEdge::new(
                IcfgEdgeKind::Intraprocedural(crate::analyzer::semantic::ControlEdgeKind::Normal),
                None,
                &call_point,
                &returned_point,
                &proof,
                &complete,
            ),
            TypestateFact::zero(),
            &mut returned,
        );
        // Applying the return event twice toggles marked back to ready.
        let states = returned
            .0
            .iter()
            .filter_map(|fact| fact.protocol_state())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            states,
            [protocol
                .state_id(&ProtocolStateKey::new("marked").unwrap())
                .unwrap()]
            .into_iter()
            .collect()
        );
        let mut observed = Facts::default();
        for fact in returned.0 {
            problem.normal_flow(
                DataflowEdge::new(
                    IcfgEdgeKind::Intraprocedural(
                        crate::analyzer::semantic::ControlEdgeKind::Normal,
                    ),
                    None,
                    &exit,
                    &exit,
                    &proof,
                    &complete,
                ),
                fact,
                &mut observed,
            );
        }
        assert!(
            observed.0.iter().any(|fact| fact.violation().is_some()),
            "{:?}",
            observed.0
        );
    }

    #[test]
    #[hardwon(
        "#13098: composition applied events to abstained facts while the ICFG solver skipped them"
    )]
    fn abstained_event_keeps_the_same_state_in_both_solvers() {
        use crate::analyzer::semantic::{
            AbstractObject, AccessPathRoot, IcfgEdgeKind, ObjectCardinality, SemanticBudget,
            SemanticRequest,
        };
        use crate::cancellation::CancellationToken;
        use crate::dataflow::{DataflowEdge, DataflowOutput, DistributiveDataflowProblem};
        use crate::inline_project::InlineTestProject;
        use crate::taint::compose::ComposeLabels;
        use crate::typestate::*;
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "root.ts",
                "function root(value: object) { touch(value); }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("root.ts"),
                &mut SemanticRequest::new(
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                ),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .unwrap();
        let root = artifact.procedure_handle(procedure.id()).unwrap();
        let object = AbstractObject::new(
            AccessPathRoot::Value(
                root.value_handle(procedure.call_sites()[0].arguments[0].value)
                    .unwrap(),
            ),
            ObjectCardinality::Singleton,
        )
        .unwrap();
        let class = TypestateSubjectClassKey::new("cookie").unwrap();
        let key = TypestateSubjectKey::for_object(class.clone(), &object);
        let protocol = ProtocolSpec::from_json(
            br#"{
          "schema_version":1,"states":["insecure","violated"],"initial_state":"insecure",
          "accepting_states":["insecure"],"error_states":["violated"],
          "events":[{"id":"seal","observation":{"occurrence":{"type":"endpoint","phase":"at_match"}}}],
          "transitions":[{"from":"insecure","on":"seal","to":"violated"}],"terminal_expectations":[],
          "semantics":{"analysis_mode":"may","unmatched_event":"preserve_state","uncertainty":{"ambiguous_dispatch":"preserve_uncertainty","unknown_call":"preserve_uncertainty","external_call":"preserve_uncertainty","escape":"preserve_uncertainty","incomplete_analysis":"preserve_uncertainty"}}
        }"#,
        )
        .unwrap()
        .compile()
        .unwrap();
        let exit = root.point_handle(procedure.normal_exit_point()).unwrap();
        let bindings = TypestateBindingPlan::try_new(
            &protocol,
            vec![BoundTypestateSubjectSpec::new(
                class,
                object,
                TypestateBindingQuality::proven_unique(),
            )],
            vec![],
            vec![TypestateEventBindingSpec::new(
                ProtocolEventKey::new("seal").unwrap(),
                key,
                TypestateObservationSite::program_point(
                    exit.clone(),
                    TypestateBindingContext::root(),
                ),
                0,
                TypestateObjectRole::MatchedValue,
                TypestateBindingQuality::proven_unique(),
            )],
            vec![],
        )
        .unwrap();
        let subject = bindings.subjects()[0].id();
        let insecure = protocol
            .state_id(&ProtocolStateKey::new("insecure").unwrap())
            .unwrap();
        let violated = protocol
            .state_id(&ProtocolStateKey::new("violated").unwrap())
            .unwrap();
        let uncertainty =
            TypestateUncertaintySet::default().with(TypestateUncertainty::IncompleteAnalysis);
        let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
        let labels = TypestateComposeLabels::new(&protocol, &bindings);
        let function = TypestateComposeFunction::event(bindings.event_bindings()[0].id());
        let proof = ProofStatus::Proven;
        let complete = EvidenceCompleteness::Complete;
        #[derive(Default)]
        struct Facts(Vec<TypestateFact>);
        impl DataflowOutput<TypestateFact> for Facts {
            fn emit(&mut self, fact: TypestateFact) -> bool {
                self.0.push(fact);
                true
            }
        }
        let apply = |fact: TypestateFact| {
            let mut icfg = Facts::default();
            problem.normal_flow(
                DataflowEdge::new(
                    IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Normal),
                    None,
                    &exit,
                    &exit,
                    &proof,
                    &complete,
                ),
                fact,
                &mut icfg,
            );
            let composed = labels.apply(&function, &TypestateComposeFact::new([fact]));
            (icfg.0, composed.alternatives().to_vec())
        };
        let project = |facts: &[TypestateFact]| {
            let mut states = facts
                .iter()
                .filter_map(|fact| fact.state_observation())
                .map(|(_, state, uncertainty, abstained)| (state, uncertainty, abstained))
                .collect::<Vec<_>>();
            let mut violations = facts
                .iter()
                .filter_map(|fact| {
                    fact.violation()
                        .map(|violation| (violation.from(), violation.to(), fact.abstained()))
                })
                .collect::<Vec<_>>();
            states.sort();
            violations.sort();
            (states, violations)
        };
        let live =
            TypestateFact::summary_state(bindings.hash(), subject, insecure, uncertainty, false);
        let (icfg_live, composed_live) = apply(live);
        assert_eq!(
            project(&icfg_live),
            project(&composed_live),
            "a live fact must take seal in both solvers: icfg {icfg_live:?} composition {composed_live:?}"
        );
        assert!(
            project(&icfg_live)
                .0
                .iter()
                .any(|(state, _, abstained)| { *state == violated && !*abstained }),
            "seal moves a live insecure fact to violated: {icfg_live:?}"
        );
        assert!(
            !project(&icfg_live).1.is_empty(),
            "the error transition is a violation in both solvers: {icfg_live:?}"
        );
        let frozen =
            TypestateFact::summary_state(bindings.hash(), subject, insecure, uncertainty, true);
        let (icfg_frozen, composed_frozen) = apply(frozen);
        assert_eq!(
            project(&icfg_frozen),
            project(&composed_frozen),
            "abstained input diverged: icfg {icfg_frozen:?} composition {composed_frozen:?}"
        );
        assert_eq!(
            project(&icfg_frozen).0,
            vec![(insecure, uncertainty, true)],
            "seal must leave the abstained state frozen: {icfg_frozen:?}"
        );
        assert!(
            project(&icfg_frozen).1.is_empty(),
            "an abstained fact must not gain a violation: {icfg_frozen:?}"
        );
    }

    #[test]
    #[hardwon(
        "#12769: later transfer removed an earlier acquisition seed and hid a preceding violation"
    )]
    fn later_transfer_preserves_earlier_acquisition_and_violation() {
        use crate::analyzer::semantic::{
            AbstractObject, AccessPathRoot, IcfgEdgeKind, ObjectCardinality, SemanticBudget,
            SemanticRequest,
        };
        use crate::cancellation::CancellationToken;
        use crate::dataflow::{DataflowEdge, DataflowOutput, DistributiveDataflowProblem};
        use crate::inline_project::InlineTestProject;
        use crate::typestate::*;
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "root.ts",
                "function root(value: object) { touch(value); }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("root.ts"),
                &mut SemanticRequest::new(
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                ),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|p| !p.call_sites().is_empty())
            .unwrap();
        let root = artifact.procedure_handle(procedure.id()).unwrap();
        let call = root.call_site_handle(procedure.call_sites()[0].id).unwrap();
        let object = AbstractObject::new(
            AccessPathRoot::Value(
                root.value_handle(procedure.call_sites()[0].arguments[0].value)
                    .unwrap(),
            ),
            ObjectCardinality::Singleton,
        )
        .unwrap();
        let class = TypestateSubjectClassKey::new("cookie").unwrap();
        let key = TypestateSubjectKey::for_object(class.clone(), &object);
        let protocol = ProtocolSpec::from_json(br#"{
          "schema_version":1,"states":["ready","violated"],"initial_state":"ready",
          "accepting_states":["ready"],"error_states":["violated"],
          "events":[{"id":"use","observation":{"occurrence":{"type":"endpoint","phase":"at_match"}}}],
          "transitions":[{"from":"ready","on":"use","to":"violated"}],"terminal_expectations":[],
          "semantics":{"analysis_mode":"may","unmatched_event":"preserve_state","uncertainty":{"ambiguous_dispatch":"preserve_uncertainty","unknown_call":"preserve_uncertainty","external_call":"preserve_uncertainty","escape":"preserve_uncertainty","incomplete_analysis":"preserve_uncertainty"}}
        }"#).unwrap().compile().unwrap();
        let entry = root.point_handle(procedure.entry_point()).unwrap();
        let site =
            |point| TypestateObservationSite::program_point(point, TypestateBindingContext::root());
        let source_class = TypestateSubjectClassKey::new("source").unwrap();
        let source_key = TypestateSubjectKey::for_object(source_class.clone(), &object);
        let bindings = TypestateBindingPlan::try_new(
            &protocol,
            vec![
                BoundTypestateSubjectSpec::new(
                    class,
                    object.clone(),
                    TypestateBindingQuality::proven_unique(),
                ),
                BoundTypestateSubjectSpec::new(
                    source_class,
                    object,
                    TypestateBindingQuality::proven_unique(),
                ),
            ],
            vec![TypestateInitialSeedSpec::new(
                key.clone(),
                ProtocolStateKey::new("ready").unwrap(),
                site(entry.clone()),
                TypestateObjectRole::MatchedValue,
                TypestateBindingQuality::proven_unique(),
            )],
            vec![TypestateEventBindingSpec::new(
                ProtocolEventKey::new("use").unwrap(),
                key.clone(),
                site(entry.clone()),
                0,
                TypestateObjectRole::MatchedValue,
                TypestateBindingQuality::proven_unique(),
            )],
            vec![],
        )
        .unwrap()
        .with_state_transfers(
            &protocol,
            vec![TypestateStateTransferSpec {
                call,
                source: Some(source_key),
                result: key,
            }],
        )
        .unwrap();
        assert_eq!(bindings.initial_seeds().len(), 1);
        #[derive(Default)]
        struct Facts(Vec<TypestateFact>);
        impl DataflowOutput<TypestateFact> for Facts {
            fn emit(&mut self, fact: TypestateFact) -> bool {
                self.0.push(fact);
                true
            }
        }
        let problem = TypestateFlowProblem::try_new(&protocol, &bindings).unwrap();
        let proof = ProofStatus::Proven;
        let complete = EvidenceCompleteness::Complete;
        let mut seeded = Facts::default();
        problem.normal_flow(
            DataflowEdge::new(
                IcfgEdgeKind::Intraprocedural(crate::analyzer::semantic::ControlEdgeKind::Normal),
                None,
                &entry,
                &entry,
                &proof,
                &complete,
            ),
            TypestateFact::zero(),
            &mut seeded,
        );
        assert!(
            seeded.0.iter().any(|fact| fact.violation().is_some()),
            "{:?}",
            seeded.0
        );
    }
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        DeclarationSegment, DeclarationSegmentKind, SemanticLanguage, SemanticRole,
        WorkspaceMountId, WorkspaceRelativePath,
    };
    use brokk_bifrost_analysis::test_support::source_anchor;
    use brokk_bifrost_test_macros::hardwon;

    use super::*;

    #[test]
    fn canonical_selected_target_retains_each_body_interpretation() {
        use crate::analyzer::semantic::ProcedureInterpretation;
        let mut encodings = Vec::new();
        for interpretation in [
            ProcedureInterpretation::Base,
            ProcedureInterpretation::CandidateAlternate,
            ProcedureInterpretation::ExecutableAlternate,
        ] {
            let target = CanonicalSelectedTarget {
                artifact: "same-selected-artifact".to_owned(),
                procedure: 0,
                interpretation,
            };
            let encoded = serde_json::to_value(target).unwrap();
            assert!(
                !encodings.contains(&encoded),
                "a selected body must not alias another target"
            );
            encodings.push(encoded);
        }
        assert_eq!(encodings.len(), 3);
    }

    #[test]
    #[hardwon(
        "#12029: a typestate finding id hashed a runtime object's refinement identity, which folds the lever-scoped artifact fingerprint"
    )]
    fn runtime_object_finding_rendering_omits_only_the_refinement_identity() {
        let span = source_anchor(0, 10, 0);
        let member = SemanticLocator::new(
            WorkspaceMountId::hash_bytes(b"/tmp/workspace"),
            WorkspaceRelativePath::new("res.go").expect("path"),
            SemanticLanguage::Standard(Language::Go),
            DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::File, "res.go", span, 0)
                    .expect("file segment"),
            ])
            .expect("declaration"),
            SemanticRole::Procedure,
            span,
        );
        let runtime_object = |refinement: &[u8]| TypestateSubjectKey {
            class: TypestateSubjectClassKey::new("connection").unwrap(),
            object: TypestateObjectKey::FieldPath {
                base: Box::new(TypestateObjectKey::RuntimeObject {
                    runtime_profile_digest: "profile".to_owned(),
                    realm: "realm".to_owned(),
                    exposure_id: "exposure".to_owned(),
                    container_member: "member".to_owned(),
                    state_boundary: "boundary".to_owned(),
                    refinement_identity: crate::analyzer::semantic::ids::StableDigest::sha256(
                        refinement,
                    ),
                    active_model_set_hash: "models".to_owned(),
                    manifest_digest: "manifest".to_owned(),
                    shard_id: "shard".to_owned(),
                    behavior_id: "behavior".to_owned(),
                    activation_source: "source".to_owned(),
                }),
                member: member.clone(),
            },
        };
        // A lever rotation changes the refinement identity and nothing else.
        let before = runtime_object(b"before-rotation");
        let after = runtime_object(b"after-rotation");
        assert_ne!(
            before.public_canonical_rendering(),
            after.public_canonical_rendering(),
            "the public rendering keeps the refinement identity"
        );
        let (rendering, omitted) = before.finding_identity_rendering();
        assert!(omitted);
        assert!(!rendering.contains("refinement_identity"), "{rendering}");
        assert!(rendering.contains("exposure"), "{rendering}");
        assert_eq!(after.finding_identity_rendering(), (rendering, true));
    }

    #[test]
    #[hardwon("#11577: tied coverage groups changed binding identity with input order")]
    fn tied_coverage_groups_have_canonical_binding_identity() {
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("main.rs", "pub fn root() { let value = 1; }")
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let cancellation = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("main.rs"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedure_handle(artifact.procedures()[0].id())
            .unwrap();
        let site = TypestateObservationSite::program_point(
            procedure
                .point_handle(procedure.semantics().entry_point())
                .unwrap(),
            TypestateBindingContext::root(),
        );
        let subject = BoundTypestateSubjectSpec::new(
            "resource".parse().unwrap(),
            AbstractObject::new(
                AccessPathRoot::Value(
                    procedure
                        .value_handle(procedure.semantics().values()[0].id)
                        .unwrap(),
                ),
                ObjectCardinality::Singleton,
            )
            .unwrap(),
            TypestateBindingQuality::proven_unique(),
        );
        let protocol = super::super::ProtocolSpec::from_json(
            br#"{
            "schema_version":1,"states":["open"],"initial_state":"open",
            "accepting_states":["open"],"error_states":[],"events":[],
            "transitions":[],"terminal_expectations":[],
            "semantics":{"analysis_mode":"may","unmatched_event":"preserve_state",
                "uncertainty":{"ambiguous_dispatch":"abstain","unknown_call":"abstain",
                    "external_call":"abstain","escape":"abstain","incomplete_analysis":"abstain"}}
        }"#,
        )
        .unwrap()
        .compile()
        .unwrap();
        let groups = [CandidateCoverage::Exhaustive, CandidateCoverage::Open].map(|coverage| {
            CoverageCandidateGroupSpec {
                subject: subject.key().clone(),
                site: site.clone(),
                phase: CoverageCandidatePhase::AfterNormalReturn,
                candidates: vec![CoverageCandidateSpec {
                    event: "close".into(),
                    semantic_effect: None,
                    quality: TypestateBindingQuality::new(
                        ProofStatus::Proven,
                        EvidenceCompleteness::Complete,
                        TypestateBindingMultiplicity {
                            coverage,
                            retained: 1,
                        },
                    ),
                    alias_derived: false,
                    role: TypestateObjectRole::Receiver,
                }],
            }
        });
        let build = |groups| {
            TypestateBindingPlan::try_new_with_coverage(
                &protocol,
                vec![subject.clone()],
                vec![],
                TypestateEventBindings {
                    events: vec![],
                    templates: vec![],
                },
                vec![],
                vec![],
                TypestateCoverageSpec {
                    candidate_groups: groups,
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let forward = build(groups.to_vec());
        let reverse = build(groups.into_iter().rev().collect());
        assert_eq!(forward.hash(), reverse.hash());
        assert_eq!(forward.canonical_bytes(), reverse.canonical_bytes());
        assert_eq!(forward.coverage_candidate_groups().len(), 2);
    }

    /// One `res.go` declaration, named by its declaration path and its own
    /// span, with the whole file's span on the enclosing `file` segment.
    fn declaration_key(file_span: SourceAnchor, name: &str, own_span: SourceAnchor) -> String {
        render_subject_key(file_span, name, own_span, SemanticRole::Procedure, own_span)
    }

    fn render_subject_key(
        file_span: SourceAnchor,
        name: &str,
        own_span: SourceAnchor,
        role: SemanticRole,
        site: SourceAnchor,
    ) -> String {
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::File, "res.go", file_span, 0)
                .expect("file segment"),
            DeclarationSegment::named(DeclarationSegmentKind::Function, name, own_span, 0)
                .expect("function segment"),
        ])
        .expect("declaration");
        TypestateSubjectKey {
            class: "res".parse().expect("subject class"),
            object: TypestateObjectKey::Value(SemanticLocator::new(
                WorkspaceMountId::hash_bytes(b"/tmp/workspace"),
                WorkspaceRelativePath::new("res.go").expect("path"),
                SemanticLanguage::Standard(Language::Go),
                declaration,
                role,
                site,
            )),
        }
        .public_canonical_rendering()
    }

    /// An edit elsewhere in the declaring file must not re-key a declaration
    /// (#3022). `OpenRes` keeps its own span; only the file it is declared in
    /// gets shorter, which is what an edit inside a later declaration does.
    #[test]
    #[hardwon(
        "#3022: Changing the file span while retaining the declaration span must not rotate the stable declaration identity."
    )]
    fn a_declaration_identity_survives_an_edit_elsewhere_in_its_file() {
        let before = declaration_key(
            source_anchor(0, 214, 0),
            "OpenRes",
            source_anchor(33, 69, 0),
        );
        let after = declaration_key(
            source_anchor(0, 208, 0),
            "OpenRes",
            source_anchor(33, 69, 0),
        );
        assert_eq!(
            before, after,
            "the file's length is not part of a declaration"
        );
    }

    /// Two declarations of one file still differ, and the name is what
    /// separates them: both sides here are given the same spans, so only the
    /// declaration path can tell them apart.
    #[test]
    #[hardwon(
        "#3022: Same-span declarations remain distinct because their structured declaration names differ."
    )]
    fn two_named_declarations_of_one_file_render_differently() {
        let file = source_anchor(0, 214, 0);
        let span = source_anchor(33, 69, 0);
        let open = declaration_key(file, "OpenRes", span);
        let close = declaration_key(file, "CloseRes", span);
        assert_ne!(open, close, "two named declarations are two identities");
    }

    /// Two anonymous declarations of one kind under one parent are separated
    /// by the sibling ordinal the inventory mints for them, which is the
    /// identity the removed byte anchor used to supply. Both sides here carry
    /// the same spans, so the ordinal is the only thing that can differ.
    #[test]
    #[hardwon(
        "#3022: Anonymous closures share a source span here, so sibling ordinal must keep their public identities distinct."
    )]
    fn two_anonymous_siblings_render_differently() {
        fn closure_key(ordinal: u32) -> String {
            let span = source_anchor(60, 90, 0);
            let declaration = DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    DeclarationSegmentKind::File,
                    "res.go",
                    source_anchor(0, 214, 0),
                    0,
                )
                .expect("file segment"),
                DeclarationSegment::named(
                    DeclarationSegmentKind::Function,
                    "Run",
                    source_anchor(33, 200, 0),
                    0,
                )
                .expect("function segment"),
                DeclarationSegment::anonymous(DeclarationSegmentKind::Closure, span, ordinal),
            ])
            .expect("declaration");
            TypestateSubjectKey {
                class: "res".parse().expect("subject class"),
                object: TypestateObjectKey::Value(SemanticLocator::new(
                    WorkspaceMountId::hash_bytes(b"/tmp/workspace"),
                    WorkspaceRelativePath::new("res.go").expect("path"),
                    SemanticLanguage::Standard(Language::Go),
                    declaration,
                    SemanticRole::Procedure,
                    span,
                )),
            }
            .public_canonical_rendering()
        }

        assert_ne!(
            closure_key(0),
            closure_key(1),
            "two anonymous siblings are two identities"
        );
    }

    /// One site inside `OpenRes`, named by the declaration path, the enclosing
    /// declaration's span, and the site's own span.
    fn site_key(file_span: SourceAnchor, own_span: SourceAnchor, site: SourceAnchor) -> String {
        render_subject_key(file_span, "OpenRes", own_span, SemanticRole::Value, site)
    }

    /// A length change in a declaration above the locator must not re-key it
    /// (#3054). Everything below an insertion moves by the insertion's length,
    /// so `OpenRes` and the site inside it both shift by 12 bytes here while
    /// nothing about either changes.
    #[test]
    #[hardwon(
        "#3054: Growing a preceding declaration and shifting the owner and site together must preserve the owner-relative site identity."
    )]
    fn a_site_identity_survives_a_length_change_in_a_declaration_above_it() {
        let before = site_key(
            source_anchor(0, 214, 0),
            source_anchor(33, 69, 0),
            source_anchor(45, 61, 0),
        );
        let after = site_key(
            source_anchor(0, 226, 0),
            source_anchor(45, 81, 0),
            source_anchor(57, 73, 0),
        );
        assert_eq!(
            before, after,
            "a site is addressed from the declaration that contains it"
        );
    }

    /// Two sites inside one declaration are still two identities: the offsets
    /// from the declaration's start differ exactly as the absolute offsets did,
    /// because subtracting one declaration start from both is a translation.
    #[test]
    #[hardwon(
        "#3054: Distinct observation spans in one declaration remain separate after anchors become owner-relative."
    )]
    fn two_sites_inside_one_declaration_render_differently() {
        let file = source_anchor(0, 214, 0);
        let own = source_anchor(33, 69, 0);
        assert_ne!(
            site_key(file, own, source_anchor(45, 61, 0)),
            site_key(file, own, source_anchor(50, 66, 0)),
            "two sites of one declaration are two identities"
        );
    }

    /// A class-level member named from inside a method is a sibling of that
    /// method, not a part of it, and Scala's `declared_member_locator` attaches
    /// it to the method's declaration path. Subtracting the method's start
    /// would underflow when the member is declared above the method, so the
    /// rendering tags it and keeps the file-relative start.
    #[test]
    #[hardwon(
        "#3054: A class member attached to a method path but lying outside its span is tagged out-of-declaration rather than clamped."
    )]
    fn a_member_declared_above_its_enclosing_method_renders_out_of_declaration() {
        fn member_key(member: SourceAnchor) -> String {
            let declaration = DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    DeclarationSegmentKind::File,
                    "Res.scala",
                    source_anchor(0, 260, 0),
                    0,
                )
                .expect("file segment"),
                DeclarationSegment::named(
                    DeclarationSegmentKind::Type,
                    "Res",
                    source_anchor(20, 250, 0),
                    0,
                )
                .expect("type segment"),
                DeclarationSegment::named(
                    DeclarationSegmentKind::Method,
                    "compute",
                    source_anchor(120, 240, 0),
                    0,
                )
                .expect("method segment"),
            ])
            .expect("declaration");
            TypestateSubjectKey {
                class: "res".parse().expect("subject class"),
                object: TypestateObjectKey::Static(SemanticLocator::new(
                    WorkspaceMountId::hash_bytes(b"/tmp/workspace"),
                    WorkspaceRelativePath::new("Res.scala").expect("path"),
                    SemanticLanguage::Standard(Language::Scala),
                    declaration,
                    SemanticRole::MemoryLocation,
                    member,
                )),
            }
            .public_canonical_rendering()
        }

        let rendering = member_key(source_anchor(40, 58, 0));
        assert!(
            rendering.contains("out_of_declaration"),
            "a member above its enclosing method is tagged, not clamped: {rendering}"
        );
        assert_ne!(
            rendering,
            member_key(source_anchor(70, 88, 0)),
            "two members of one class are two identities"
        );
    }

    fn lexical_cell_key(
        mount: &str,
        binding_role: &str,
        binding_ordinal: Option<u32>,
    ) -> TypestateObjectKey {
        TypestateObjectKey::LexicalCell {
            locator: SemanticLocator::new(
                WorkspaceMountId::hash_bytes(mount),
                WorkspaceRelativePath::new("res.go").expect("path"),
                SemanticLanguage::Standard(Language::Go),
                DeclarationLocator::new(vec![
                    DeclarationSegment::named(
                        DeclarationSegmentKind::Function,
                        "Run",
                        source_anchor(0, 80, 0),
                        0,
                    )
                    .expect("function segment"),
                ])
                .expect("declaration"),
                SemanticRole::MemoryLocation,
                source_anchor(12, 16, 0),
            ),
            binding: DurableValueIdentity {
                locator: SemanticLocator::new(
                    WorkspaceMountId::hash_bytes(mount),
                    WorkspaceRelativePath::new("res.go").expect("path"),
                    SemanticLanguage::Standard(Language::Go),
                    DeclarationLocator::new(vec![
                        DeclarationSegment::named(
                            DeclarationSegmentKind::Function,
                            "Run",
                            source_anchor(0, 80, 0),
                            0,
                        )
                        .expect("function segment"),
                    ])
                    .expect("declaration"),
                    SemanticRole::Value,
                    source_anchor(20, 24, 0),
                ),
                role: binding_role.into(),
                ordinal: binding_ordinal,
            },
        }
    }

    #[test]
    #[hardwon(
        "#3099: Captured cells with the same location but different role or ordinal must have different stable identity renderings."
    )]
    fn lexical_cell_rendering_retains_binding_role_and_ordinal() {
        let base = lexical_cell_key("mount", "parameter", Some(0));
        let changed_role = lexical_cell_key("mount", "local", Some(0));
        let changed_ordinal = lexical_cell_key("mount", "parameter", Some(1));

        assert_ne!(
            base.public_canonical_rendering(),
            changed_role.public_canonical_rendering()
        );
        assert_ne!(
            base.public_canonical_rendering(),
            changed_ordinal.public_canonical_rendering()
        );
    }

    #[test]
    #[hardwon(
        "#3099: Exact locators differ across mounts while their public canonical identity remains checkout-independent."
    )]
    fn lexical_cell_rendering_is_checkout_independent() {
        let first = lexical_cell_key("first checkout", "parameter", Some(0));
        let second = lexical_cell_key("second checkout", "parameter", Some(0));

        assert_ne!(first, second, "mounted locators retain exact equality");
        assert_eq!(
            first.public_canonical_rendering(),
            second.public_canonical_rendering()
        );
    }
}
