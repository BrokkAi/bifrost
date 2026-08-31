use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use crate::analyzer::identifier::define_identifier;
use crate::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CandidateCoverage, DeclarationLocator, DeclarationSegmentKind,
    DurableCallContext, DurableObjectIdentity, DurablePortIdentity, EvidenceCompleteness,
    ObjectCardinality, OracleCallContext, ProcedureHandle, ProgramPointHandle, ProofStatus,
    SemanticArtifact, SemanticArtifactKey, SemanticLocator, SourceAnchor,
};
use brokk_bifrost_core::analyzer::dense_id::define_dense_id;

use super::{
    CompiledProtocol, ProtocolEventId, ProtocolEventKey, ProtocolEventOccurrence,
    ProtocolExpectationId, ProtocolExpectationKey, ProtocolObjectCardinality,
    ProtocolObservationPhase, ProtocolProcedureExitKind, ProtocolStateId, ProtocolStateKey,
    ProtocolTerminalObservationSpec, TypestateBindingPlanHash, TypestateBindingSummaryHash,
    TypestateProtocolHash,
};

pub const BINDING_PLAN_SCHEMA_VERSION: u32 = 3;
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
    LexicalCell(SemanticLocator),
    CaptureSlot {
        procedure: SemanticLocator,
        port: TypestateProcedurePortKey,
    },
    TypeSummary(SemanticLocator),
    ModuleObject(SemanticLocator),
    External(SemanticLocator),
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
            object: typestate_object_key(object),
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
    /// binding-plan hash; it never contains a run-local dense subject ID.
    pub fn canonical_rendering(&self) -> String {
        serde_json::to_string(&canonical_subject_key(self))
            .expect("canonical typestate subject identities are serializable")
    }

    /// Render the source-facing identity without the absolute workspace mount.
    ///
    /// Registration and cache identities continue to use
    /// [`Self::canonical_rendering`]. Public query rows use this form so the
    /// same indexed content has the same identity in different checkouts.
    pub fn public_canonical_rendering(&self) -> String {
        let mut value = serde_json::to_value(canonical_subject_key(self))
            .expect("canonical typestate subject identities are serializable");
        remove_canonical_mounts(&mut value);
        serde_json::to_string(&value).expect("public typestate subject identities are serializable")
    }
}

fn remove_canonical_mounts(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            fields.remove("mount");
            for value in fields.values_mut() {
                remove_canonical_mounts(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                remove_canonical_mounts(value);
            }
        }
        _ => {}
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
/// carries are dropped and a capture port keeps only its source locator.
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
        DurableObjectIdentity::LexicalCell { locator } => TypestateObjectKey::LexicalCell(locator),
        DurableObjectIdentity::TypeSummary { locator } => TypestateObjectKey::TypeSummary(locator),
        DurableObjectIdentity::ModuleObject { locator } => {
            TypestateObjectKey::ModuleObject(locator)
        }
        DurableObjectIdentity::External { locator } => TypestateObjectKey::External(locator),
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

#[derive(Serialize)]
struct CanonicalLocator<'a> {
    mount: String,
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
    anchor: CanonicalAnchor,
    sibling_ordinal: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct CanonicalAnchor {
    start_byte: u32,
    start_line: u32,
    start_byte_column: u32,
    end_byte: u32,
    end_line: u32,
    end_byte_column: u32,
    occurrence: u32,
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
        TypestateObjectKey::LexicalCell(identity) => CanonicalObjectKey::LexicalCell {
            identity: canonical_locator(identity),
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

fn canonical_locator(locator: &SemanticLocator) -> CanonicalLocator<'_> {
    CanonicalLocator {
        mount: locator.mount().to_string(),
        path: locator.path().as_str(),
        language: locator.language().stable_label(),
        declaration: locator
            .declaration()
            .segments()
            .iter()
            .map(|segment| CanonicalDeclarationSegment {
                kind: declaration_kind_label(segment.kind()),
                name: segment.name(),
                anchor: canonical_anchor(segment.anchor()),
                sibling_ordinal: segment.sibling_ordinal(),
            })
            .collect(),
        role: locator.role().stable_label(),
        anchor: canonical_anchor(locator.anchor()),
    }
}

fn canonical_anchor(anchor: SourceAnchor) -> CanonicalAnchor {
    let span = anchor.span();
    let start = span.start();
    let end = span.end();
    CanonicalAnchor {
        start_byte: start.byte_offset(),
        start_line: start.line(),
        start_byte_column: start.byte_column(),
        end_byte: end.byte_offset(),
        end_line: end.line(),
        end_byte_column: end.byte_column(),
        occurrence: anchor.occurrence(),
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
