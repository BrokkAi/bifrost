use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use crate::analyzer::identifier::define_identifier;
use crate::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CandidateCoverage, DeclarationLocator, DeclarationSegmentKind,
    DurableCallContext, DurableObjectIdentity, DurablePortIdentity, DurableValueIdentity,
    EvidenceCompleteness, ObjectCardinality, OracleCallContext, ProcedureHandle,
    ProgramPointHandle, ProofStatus, SemanticArtifact, SemanticArtifactKey, SemanticLocator,
    SourceAnchor,
};
use brokk_bifrost_core::analyzer::dense_id::define_dense_id;

use super::{
    CompiledProtocol, ProtocolEventId, ProtocolEventKey, ProtocolEventOccurrence,
    ProtocolExpectationId, ProtocolExpectationKey, ProtocolObjectCardinality,
    ProtocolObservationPhase, ProtocolProcedureExitKind, ProtocolStateId, ProtocolStateKey,
    ProtocolTerminalObservationSpec, TypestateBindingPlanHash, TypestateBindingSummaryHash,
    TypestateProtocolHash,
};

pub const BINDING_PLAN_SCHEMA_VERSION: u32 = 6;
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

    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

/// Stable semantic counterpart of one runtime [`AbstractObject`] identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypestateObjectKey {
    Value(SemanticLocator),
    CallResult {
        call: SemanticLocator,
        result: SemanticLocator,
        callee: SemanticLocator,
        caller_context: TypestateContextKey,
        callee_context: TypestateContextKey,
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
        serde_json::to_string(&canonical_object_key(self))
            .expect("canonical typestate object identities are serializable")
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
        serde_json::to_string(&canonical_subject_key(self))
            .expect("canonical typestate subject identities are serializable")
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

    pub const fn was_truncated(&self) -> bool {
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
        Self {
            subject,
            state,
            site,
            activation_edge: Some(activation_edge),
            role,
            quality,
            reviewed_fresh_result: false,
        }
    }

    pub fn new_reviewed_fresh_result(
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
            reviewed_fresh_result: true,
        }
    }

    pub fn new_reviewed_fresh_result_on_control_edge(
        subject: TypestateSubjectKey,
        state: ProtocolStateKey,
        site: TypestateObservationSite,
        activation_edge: crate::analyzer::semantic::ControlEdgeHandle,
        role: TypestateObjectRole,
        quality: TypestateBindingQuality,
    ) -> Self {
        Self {
            subject,
            state,
            site,
            activation_edge: Some(activation_edge),
            role,
            quality,
            reviewed_fresh_result: true,
        }
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
        Self {
            event,
            subject,
            site,
            order,
            role,
            quality,
            modeled_external_effect: Some(effect_id),
        }
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
    initial_seeds: Box<[BoundTypestateInitialSeed]>,
    event_bindings: Box<[BoundTypestateEvent]>,
    call_noninterference_bindings: Box<[BoundTypestateCallNonInterference]>,
    terminal_bindings: Box<[BoundTypestateTerminal]>,
    subject_by_object:
        HashMap<TypestateSubjectClassKey, HashMap<AbstractObject, TypestateSubjectId>>,
    events_by_point: HashMap<ProgramPointHandle, HashMap<OracleCallContext, Box<[usize]>>>,
    events_by_call: HashMap<
        crate::analyzer::semantic::CallSiteHandle,
        HashMap<OracleCallContext, Box<[usize]>>,
    >,
    terminals_by_point: HashMap<ProgramPointHandle, HashMap<OracleCallContext, Box<[usize]>>>,
    terminals_by_call: HashMap<
        crate::analyzer::semantic::CallSiteHandle,
        HashMap<OracleCallContext, Box<[usize]>>,
    >,
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
        mut subjects: Vec<BoundTypestateSubjectSpec>,
        mut initial_seeds: Vec<TypestateInitialSeedSpec>,
        mut event_bindings: Vec<TypestateEventBindingSpec>,
        mut call_noninterference_bindings: Vec<TypestateCallNonInterferenceSpec>,
        mut terminal_bindings: Vec<TypestateTerminalBindingSpec>,
    ) -> Result<Self, TypestateBindingPlanError> {
        check_count("subjects", subjects.len(), MAX_TYPESTATE_SUBJECTS)?;
        check_count(
            "initial_seeds",
            initial_seeds.len(),
            MAX_TYPESTATE_INITIAL_SEEDS,
        )?;
        check_count(
            "event_bindings",
            event_bindings.len(),
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

        let mut compiled_events = Vec::with_capacity(event_bindings.len());
        for (index, binding) in event_bindings.iter().enumerate() {
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
            });
        }

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

        let canonical = CanonicalBindingPlan {
            schema_version: BINDING_PLAN_SCHEMA_VERSION,
            protocol_hash: protocol.hash(),
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
            event_bindings: event_bindings
                .iter()
                .map(|binding| CanonicalEventBinding {
                    event: binding.event.as_str(),
                    subject: canonical_subject_key(&binding.subject),
                    site: canonical_site(&binding.site),
                    order: binding.order,
                    role: binding.role,
                    quality: canonical_quality(&binding.quality),
                    modeled_external_effect: binding.modeled_external_effect.as_deref(),
                })
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
            &event_bindings,
            &call_noninterference_bindings,
            &terminal_bindings,
        )
        .map_err(TypestateBindingPlanError::Canonicalization)?;

        let mut subject_by_object =
            HashMap::<_, HashMap<AbstractObject, TypestateSubjectId>>::new();
        for subject in &compiled_subjects {
            subject_by_object
                .entry(subject.key.class.clone())
                .or_default()
                .insert(subject.object.clone(), subject.id);
        }
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
            initial_seeds: compiled_seeds.into_boxed_slice(),
            event_bindings: compiled_events.into_boxed_slice(),
            call_noninterference_bindings: compiled_call_noninterference.into_boxed_slice(),
            terminal_bindings: compiled_terminals.into_boxed_slice(),
            subject_by_object,
            events_by_point: event_indexes.points,
            events_by_call: event_indexes.calls,
            terminals_by_point: terminal_indexes.points,
            terminals_by_call: terminal_indexes.calls,
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

    pub fn subjects(&self) -> &[BoundTypestateSubject] {
        &self.subjects
    }

    /// Visit every semantic artifact identity retained by this plan.
    ///
    /// Registries use this to reject stale bindings before solver execution.
    /// Duplicate keys are intentional here: callers that need a set can
    /// deduplicate without this hot-path model retaining another index.
    pub fn for_each_retained_artifact_key(&self, mut visit: impl FnMut(&SemanticArtifactKey)) {
        for subject in &self.subjects {
            visit_access_path_root_artifacts(subject.object().identity(), &mut visit);
        }
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
            visit_observation_site_artifacts(site, &mut visit);
        }
    }

    /// Visit every concrete semantic artifact allocation retained by handles
    /// in this plan. Key-only scoped locators are intentionally excluded: they
    /// retain identities but do not own semantic IR allocations.
    pub fn for_each_retained_artifact(&self, mut visit: impl FnMut(&Arc<SemanticArtifact>)) {
        for subject in &self.subjects {
            visit_access_path_root_artifact_values(subject.object().identity(), &mut visit);
        }
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
            visit_observation_site_artifact_values(site, &mut visit);
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

    pub fn subject_for_object(
        &self,
        class: &TypestateSubjectClassKey,
        object: &AbstractObject,
    ) -> Option<TypestateSubjectId> {
        self.subject_by_object
            .get(class)
            .and_then(|subjects| subjects.get(object))
            .copied()
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

    pub fn event_binding(&self, id: TypestateEventBindingId) -> Option<&BoundTypestateEvent> {
        self.event_bindings.get(id.index())
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

    pub fn event_bindings_at_program_point(
        &self,
        point: &ProgramPointHandle,
        context: &OracleCallContext,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        site_indexes(&self.events_by_point, point, context).map(|index| &self.event_bindings[index])
    }

    pub fn event_bindings_at_call_site(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        context: &OracleCallContext,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        site_indexes(&self.events_by_call, call, context).map(|index| &self.event_bindings[index])
    }

    pub fn event_bindings_at_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        flat_site_indexes(&self.events_by_point_all_contexts, point)
            .map(|index| &self.event_bindings[index])
    }

    pub fn event_bindings_at_call_site_all_contexts(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        flat_site_indexes(&self.events_by_call_all_contexts, call)
            .map(|index| &self.event_bindings[index])
    }

    pub fn event_bindings_at_call_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateEvent> {
        flat_site_indexes(&self.events_by_call_point_all_contexts, point)
            .map(|index| &self.event_bindings[index])
    }

    pub fn terminal_bindings_at_program_point(
        &self,
        point: &ProgramPointHandle,
        context: &OracleCallContext,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        site_indexes(&self.terminals_by_point, point, context)
            .map(|index| &self.terminal_bindings[index])
    }

    pub fn terminal_bindings_at_call_site(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        context: &OracleCallContext,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        site_indexes(&self.terminals_by_call, call, context)
            .map(|index| &self.terminal_bindings[index])
    }

    pub fn terminal_bindings_at_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        flat_site_indexes(&self.terminals_by_point_all_contexts, point)
            .map(|index| &self.terminal_bindings[index])
    }

    pub fn terminal_bindings_at_call_site_all_contexts(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        flat_site_indexes(&self.terminals_by_call_all_contexts, call)
            .map(|index| &self.terminal_bindings[index])
    }

    pub fn terminal_bindings_at_call_program_point_all_contexts(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &BoundTypestateTerminal> {
        flat_site_indexes(&self.terminals_by_call_point_all_contexts, point)
            .map(|index| &self.terminal_bindings[index])
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

fn visit_access_path_root_artifacts(
    root: &AccessPathRoot,
    visit: &mut impl FnMut(&SemanticArtifactKey),
) {
    let mut visit_procedure = |procedure: &ProcedureHandle| visit(procedure.artifact().key());
    match root {
        AccessPathRoot::Value(value) => visit_procedure(value.procedure()),
        AccessPathRoot::CallResult(result) => {
            visit_procedure(result.call().procedure());
            visit_procedure(result.result().procedure());
            visit_procedure(result.callee());
            for call in result
                .caller_context()
                .calls()
                .iter()
                .chain(result.callee_context().calls())
            {
                visit_procedure(call.procedure());
            }
        }
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            visit_procedure(port.procedure());
        }
        AccessPathRoot::Allocation(allocation) => visit_procedure(allocation.procedure()),
        AccessPathRoot::LexicalCell(location) => visit_procedure(location.procedure()),
        AccessPathRoot::Static(locator)
        | AccessPathRoot::TypeSummary(locator)
        | AccessPathRoot::ModuleObject(locator)
        | AccessPathRoot::External(locator) => visit(locator.scope().key()),
        AccessPathRoot::RuntimeObject(_) => {}
    }
}

fn visit_observation_site_artifacts(
    site: &TypestateObservationSite,
    visit: &mut impl FnMut(&SemanticArtifactKey),
) {
    match site {
        TypestateObservationSite::ProgramPoint { point, context, .. } => {
            visit(point.procedure().artifact().key());
            for call in context.runtime().calls() {
                visit(call.procedure().artifact().key());
            }
        }
        TypestateObservationSite::CallSite { call, context, .. } => {
            visit(call.procedure().artifact().key());
            for context_call in context.runtime().calls() {
                visit(context_call.procedure().artifact().key());
            }
        }
    }
}

fn visit_access_path_root_artifact_values(
    root: &AccessPathRoot,
    visit: &mut impl FnMut(&Arc<SemanticArtifact>),
) {
    let mut visit_procedure = |procedure: &ProcedureHandle| visit(procedure.artifact());
    match root {
        AccessPathRoot::Value(value) => visit_procedure(value.procedure()),
        AccessPathRoot::CallResult(result) => {
            visit_procedure(result.call().procedure());
            visit_procedure(result.result().procedure());
            visit_procedure(result.callee());
            for call in result
                .caller_context()
                .calls()
                .iter()
                .chain(result.callee_context().calls())
            {
                visit_procedure(call.procedure());
            }
        }
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            visit_procedure(port.procedure());
        }
        AccessPathRoot::Allocation(allocation) => visit_procedure(allocation.procedure()),
        AccessPathRoot::LexicalCell(location) => visit_procedure(location.procedure()),
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => {}
        AccessPathRoot::RuntimeObject(_) => {}
    }
}

fn visit_observation_site_artifact_values(
    site: &TypestateObservationSite,
    visit: &mut impl FnMut(&Arc<SemanticArtifact>),
) {
    match site {
        TypestateObservationSite::ProgramPoint { point, context, .. } => {
            visit(point.procedure().artifact());
            for call in context.runtime().calls() {
                visit(call.procedure().artifact());
            }
        }
        TypestateObservationSite::CallSite { call, context, .. } => {
            visit(call.procedure().artifact());
            for context_call in context.runtime().calls() {
                visit(context_call.procedure().artifact());
            }
        }
    }
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
    let row = point
        .procedure()
        .semantics()
        .point(point.id())
        .expect("program-point handles are validated at construction");
    source_locator(point.procedure(), row.source)
}

fn call_site_locator(call: &crate::analyzer::semantic::CallSiteHandle) -> SemanticLocator {
    let row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("call-site handles are validated at construction");
    source_locator(call.procedure(), row.source)
}

fn source_locator(
    procedure: &ProcedureHandle,
    source: crate::analyzer::semantic::SourceMappingId,
) -> SemanticLocator {
    procedure
        .semantics()
        .source_mapping(source)
        .expect("validated semantic rows retain source mappings")
        .locator
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
    let semantics = point.procedure().semantics();
    match kind {
        ProtocolProcedureExitKind::Normal => point.id() == semantics.normal_exit_point(),
        ProtocolProcedureExitKind::Exceptional => point.id() == semantics.exceptional_exit_point(),
    }
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
    compare_sites(&left.site, &right.site)
        .then_with(|| left.order.cmp(&right.order))
        .then_with(|| left.subject.cmp(&right.subject))
        .then_with(|| left.event.cmp(&right.event))
        .then_with(|| left.role.cmp(&right.role))
        .then_with(|| {
            left.modeled_external_effect
                .cmp(&right.modeled_external_effect)
        })
}

fn compare_event_order_keys(
    left: &TypestateEventBindingSpec,
    right: &TypestateEventBindingSpec,
) -> Ordering {
    compare_sites(&left.site, &right.site)
        .then_with(|| left.order.cmp(&right.order))
        .then_with(|| left.subject.cmp(&right.subject))
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
    calls: HashMap<
        crate::analyzer::semantic::CallSiteHandle,
        HashMap<OracleCallContext, Box<[usize]>>,
    >,
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
        calls: box_site_indexes(calls),
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
    indexes
        .get(site)
        .and_then(|contexts| contexts.get(context))
        .into_iter()
        .flat_map(|indexes| indexes.iter().copied())
}

fn flat_site_indexes<'plan, K>(
    indexes: &'plan HashMap<K, Box<[usize]>>,
    site: &K,
) -> impl Iterator<Item = usize> + 'plan
where
    K: Eq + std::hash::Hash,
{
    indexes
        .get(site)
        .into_iter()
        .flat_map(|indexes| indexes.iter().copied())
}

#[derive(Default)]
struct ProcedureBindingIndexes {
    seeds: Vec<usize>,
    events: Vec<usize>,
    call_noninterference: Vec<usize>,
    terminals: Vec<usize>,
}

type ProcedureBindingSummaryHashes =
    HashMap<SemanticArtifactKey, HashMap<DeclarationLocator, TypestateBindingSummaryHash>>;
type ProcedureBindingSummaryHashResult =
    Result<(ProcedureBindingSummaryHashes, TypestateBindingSummaryHash), serde_json::Error>;

fn procedure_summary_hashes(
    protocol: &CompiledProtocol,
    subjects: &[BoundTypestateSubjectSpec],
    initial_seeds: &[TypestateInitialSeedSpec],
    event_bindings: &[TypestateEventBindingSpec],
    call_noninterference_bindings: &[TypestateCallNonInterferenceSpec],
    terminal_bindings: &[TypestateTerminalBindingSpec],
) -> ProcedureBindingSummaryHashResult {
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
        schema_version: BINDING_PLAN_SCHEMA_VERSION,
        protocol_hash: protocol.hash(),
        subjects: Vec::new(),
        initial_seeds: Vec::new(),
        event_bindings: Vec::new(),
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
                    }
                })
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
    subjects: Vec<CanonicalSubject<'a>>,
    initial_seeds: Vec<CanonicalSeed<'a>>,
    event_bindings: Vec<CanonicalEventBinding<'a>>,
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
        refinement_identity: crate::analyzer::semantic::StableDigest,
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
            refinement_identity: *refinement_identity,
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
        artifact: edge.procedure().artifact().key().fingerprint().to_string(),
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
                kind: declaration_kind_label(segment.kind()),
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

const fn declaration_kind_label(kind: DeclarationSegmentKind) -> &'static str {
    match kind {
        DeclarationSegmentKind::File => "file",
        DeclarationSegmentKind::Namespace => "namespace",
        DeclarationSegmentKind::Type => "type",
        DeclarationSegmentKind::Function => "function",
        DeclarationSegmentKind::Method => "method",
        DeclarationSegmentKind::Constructor => "constructor",
        DeclarationSegmentKind::Initializer => "initializer",
        DeclarationSegmentKind::LocalFunction => "local_function",
        DeclarationSegmentKind::Lambda => "lambda",
        DeclarationSegmentKind::Closure => "closure",
        DeclarationSegmentKind::AnonymousCallable => "anonymous_callable",
    }
}

#[cfg(test)]
mod tests {
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        DeclarationSegment, SemanticLanguage, SemanticRole, SourcePosition, SourceSpan,
        WorkspaceMountId, WorkspaceRelativePath,
    };

    use super::*;

    fn anchor(start: u32, end: u32) -> SourceAnchor {
        SourceAnchor::new(
            SourceSpan::new(
                SourcePosition::new(start, 0, start),
                SourcePosition::new(end, 0, end),
            )
            .expect("span"),
            0,
        )
    }

    /// One `res.go` declaration, named by its declaration path and its own
    /// span, with the whole file's span on the enclosing `file` segment.
    fn declaration_key(file_span: SourceAnchor, name: &str, own_span: SourceAnchor) -> String {
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
                SemanticRole::Procedure,
                own_span,
            )),
        }
        .public_canonical_rendering()
    }

    /// An edit elsewhere in the declaring file must not re-key a declaration
    /// (#3022). `OpenRes` keeps its own span; only the file it is declared in
    /// gets shorter, which is what an edit inside a later declaration does.
    #[test]
    fn a_declaration_identity_survives_an_edit_elsewhere_in_its_file() {
        let before = declaration_key(anchor(0, 214), "OpenRes", anchor(33, 69));
        let after = declaration_key(anchor(0, 208), "OpenRes", anchor(33, 69));
        assert_eq!(
            before, after,
            "the file's length is not part of a declaration"
        );
    }

    /// Two declarations of one file still differ, and the name is what
    /// separates them: both sides here are given the same spans, so only the
    /// declaration path can tell them apart.
    #[test]
    fn two_named_declarations_of_one_file_render_differently() {
        let file = anchor(0, 214);
        let span = anchor(33, 69);
        let open = declaration_key(file, "OpenRes", span);
        let close = declaration_key(file, "CloseRes", span);
        assert_ne!(open, close, "two named declarations are two identities");
    }

    /// Two anonymous declarations of one kind under one parent are separated
    /// by the sibling ordinal the inventory mints for them, which is the
    /// identity the removed byte anchor used to supply. Both sides here carry
    /// the same spans, so the ordinal is the only thing that can differ.
    #[test]
    fn two_anonymous_siblings_render_differently() {
        fn closure_key(ordinal: u32) -> String {
            let span = anchor(60, 90);
            let declaration = DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    DeclarationSegmentKind::File,
                    "res.go",
                    anchor(0, 214),
                    0,
                )
                .expect("file segment"),
                DeclarationSegment::named(
                    DeclarationSegmentKind::Function,
                    "Run",
                    anchor(33, 200),
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
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::File, "res.go", file_span, 0)
                .expect("file segment"),
            DeclarationSegment::named(DeclarationSegmentKind::Function, "OpenRes", own_span, 0)
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
                SemanticRole::Value,
                site,
            )),
        }
        .public_canonical_rendering()
    }

    /// A length change in a declaration above the locator must not re-key it
    /// (#3054). Everything below an insertion moves by the insertion's length,
    /// so `OpenRes` and the site inside it both shift by 12 bytes here while
    /// nothing about either changes.
    #[test]
    fn a_site_identity_survives_a_length_change_in_a_declaration_above_it() {
        let before = site_key(anchor(0, 214), anchor(33, 69), anchor(45, 61));
        let after = site_key(anchor(0, 226), anchor(45, 81), anchor(57, 73));
        assert_eq!(
            before, after,
            "a site is addressed from the declaration that contains it"
        );
    }

    /// Two sites inside one declaration are still two identities: the offsets
    /// from the declaration's start differ exactly as the absolute offsets did,
    /// because subtracting one declaration start from both is a translation.
    #[test]
    fn two_sites_inside_one_declaration_render_differently() {
        let file = anchor(0, 214);
        let own = anchor(33, 69);
        assert_ne!(
            site_key(file, own, anchor(45, 61)),
            site_key(file, own, anchor(50, 66)),
            "two sites of one declaration are two identities"
        );
    }

    /// A class-level member named from inside a method is a sibling of that
    /// method, not a part of it, and Scala's `declared_member_locator` attaches
    /// it to the method's declaration path. Subtracting the method's start
    /// would underflow when the member is declared above the method, so the
    /// rendering tags it and keeps the file-relative start.
    #[test]
    fn a_member_declared_above_its_enclosing_method_renders_out_of_declaration() {
        fn member_key(member: SourceAnchor) -> String {
            let declaration = DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    DeclarationSegmentKind::File,
                    "Res.scala",
                    anchor(0, 260),
                    0,
                )
                .expect("file segment"),
                DeclarationSegment::named(DeclarationSegmentKind::Type, "Res", anchor(20, 250), 0)
                    .expect("type segment"),
                DeclarationSegment::named(
                    DeclarationSegmentKind::Method,
                    "compute",
                    anchor(120, 240),
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

        let rendering = member_key(anchor(40, 58));
        assert!(
            rendering.contains("out_of_declaration"),
            "a member above its enclosing method is tagged, not clamped: {rendering}"
        );
        assert_ne!(
            rendering,
            member_key(anchor(70, 88)),
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
                        anchor(0, 80),
                        0,
                    )
                    .expect("function segment"),
                ])
                .expect("declaration"),
                SemanticRole::MemoryLocation,
                anchor(12, 16),
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
                            anchor(0, 80),
                            0,
                        )
                        .expect("function segment"),
                    ])
                    .expect("declaration"),
                    SemanticRole::Value,
                    anchor(20, 24),
                ),
                role: binding_role.into(),
                ordinal: binding_ordinal,
            },
        }
    }

    #[test]
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
