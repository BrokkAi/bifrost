use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

use serde::Serialize;

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::identifier::define_identifier;
use crate::analyzer::semantic::{
    AbstractObject, AccessPathRoot, CandidateCoverage, DeclarationSegmentKind,
    EvidenceCompleteness, ObjectCardinality, OracleCallContext, ProcedureHandle, ProcedurePortKind,
    ProgramPointHandle, ProofStatus, SemanticLocator, SourceAnchor,
};

use super::{
    CompiledProtocol, ProtocolEventId, ProtocolEventKey, ProtocolEventOccurrence,
    ProtocolExpectationId, ProtocolExpectationKey, ProtocolObjectCardinality,
    ProtocolObservationPhase, ProtocolProcedureExitKind, ProtocolStateId, ProtocolStateKey,
    ProtocolTerminalObservationSpec, TypestateBindingPlanHash, TypestateProtocolHash,
};

pub const BINDING_PLAN_SCHEMA_VERSION: u32 = 1;
pub const MAX_TYPESTATE_SUBJECTS: usize = 4_096;
pub const MAX_TYPESTATE_INITIAL_SEEDS: usize = 4_096;
pub const MAX_TYPESTATE_EVENT_BINDINGS: usize = 16_384;
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
        let key = typestate_context_key(&runtime);
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
}

#[derive(Debug, Clone)]
pub struct TypestateInitialSeedSpec {
    subject: TypestateSubjectKey,
    state: ProtocolStateKey,
    site: TypestateObservationSite,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
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
            role,
            quality,
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
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
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

    pub const fn role(&self) -> TypestateObjectRole {
        self.role
    }

    pub fn quality(&self) -> &TypestateBindingQuality {
        &self.quality
    }
}

#[derive(Debug, Clone)]
pub struct BoundTypestateEvent {
    event: ProtocolEventId,
    subject: TypestateSubjectId,
    site: TypestateObservationSite,
    order: u32,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
}

impl BoundTypestateEvent {
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
}

#[derive(Debug, Clone)]
pub struct BoundTypestateTerminal {
    expectation: ProtocolExpectationId,
    subject: TypestateSubjectId,
    site: TypestateObservationSite,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
}

impl BoundTypestateTerminal {
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
    terminals_by_point_all_contexts: HashMap<ProgramPointHandle, Box<[usize]>>,
    terminals_by_call_all_contexts:
        HashMap<crate::analyzer::semantic::CallSiteHandle, Box<[usize]>>,
    terminals_by_call_point_all_contexts: HashMap<ProgramPointHandle, Box<[usize]>>,
    canonical_bytes: Box<[u8]>,
    canonical_rendering: Box<str>,
    hash: TypestateBindingPlanHash,
}

impl TypestateBindingPlan {
    pub fn try_new(
        protocol: &CompiledProtocol,
        mut subjects: Vec<BoundTypestateSubjectSpec>,
        mut initial_seeds: Vec<TypestateInitialSeedSpec>,
        mut event_bindings: Vec<TypestateEventBindingSpec>,
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
            validate_seed_site(&seed.site)?;
            compiled_seeds.push(BoundTypestateInitialSeed {
                subject,
                state,
                site: seed.site.clone(),
                role: seed.role,
                quality: seed.quality.clone(),
            });
        }

        let mut compiled_events = Vec::with_capacity(event_bindings.len());
        for binding in &event_bindings {
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
                event,
                subject,
                site: binding.site.clone(),
                order: binding.order,
                role: binding.role,
                quality: binding.quality.clone(),
            });
        }

        let mut compiled_terminals = Vec::with_capacity(terminal_bindings.len());
        for binding in &terminal_bindings {
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
                    role: seed.role,
                    quality: canonical_quality(&seed.quality),
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
        let initial_seed_indexes = index_point_sites(&compiled_seeds, |binding| &binding.site);
        let event_call_point_indexes =
            index_call_point_sites(&compiled_events, |binding| &binding.site);
        let terminal_call_point_indexes =
            index_call_point_sites(&compiled_terminals, |binding| &binding.site);

        Ok(Self {
            protocol_hash: protocol.hash(),
            subjects: compiled_subjects.into_boxed_slice(),
            initial_seeds: compiled_seeds.into_boxed_slice(),
            event_bindings: compiled_events.into_boxed_slice(),
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
            terminals_by_point_all_contexts: terminal_indexes.all_points,
            terminals_by_call_all_contexts: terminal_indexes.all_calls,
            terminals_by_call_point_all_contexts: terminal_call_point_indexes,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            canonical_rendering: canonical_rendering.into_boxed_str(),
            hash,
        })
    }

    pub fn subjects(&self) -> &[BoundTypestateSubject] {
        &self.subjects
    }

    pub const fn protocol_hash(&self) -> TypestateProtocolHash {
        self.protocol_hash
    }

    pub fn subject(&self, id: TypestateSubjectId) -> Option<&BoundTypestateSubject> {
        self.subjects.get(id.index())
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

    pub fn terminal_bindings(&self) -> &[BoundTypestateTerminal] {
        &self.terminal_bindings
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
    DuplicateTerminalBinding,
    UnknownSubject,
    UnknownState,
    UnknownEvent,
    UnknownExpectation,
    InvalidSeedSite,
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
            | Self::DuplicateTerminalBinding
            | Self::UnknownSubject
            | Self::UnknownState
            | Self::UnknownEvent
            | Self::UnknownExpectation
            | Self::InvalidSeedSite
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

fn typestate_object_key(object: &AbstractObject) -> TypestateObjectKey {
    match object.identity() {
        AccessPathRoot::Value(value) => TypestateObjectKey::Value(value_locator(value)),
        AccessPathRoot::CallResult(result) => TypestateObjectKey::CallResult {
            call: call_site_locator(result.call()),
            result: value_locator(result.result()),
            callee: result.callee().semantics().locator().clone(),
            caller_context: typestate_context_key(result.caller_context()),
            callee_context: typestate_context_key(result.callee_context()),
        },
        AccessPathRoot::ProcedurePort(port) => TypestateObjectKey::ProcedurePort {
            procedure: port.procedure().semantics().locator().clone(),
            port: procedure_port_key(port),
        },
        AccessPathRoot::Allocation(allocation) => {
            let row = allocation
                .procedure()
                .semantics()
                .allocation(allocation.id())
                .expect("allocation handles are validated at construction");
            TypestateObjectKey::Allocation(source_locator(allocation.procedure(), row.source))
        }
        AccessPathRoot::Static(locator) => TypestateObjectKey::Static(locator.locator().clone()),
        AccessPathRoot::LexicalCell(location) => {
            let row = location
                .procedure()
                .semantics()
                .memory_location(location.id())
                .expect("memory-location handles are validated at construction");
            TypestateObjectKey::LexicalCell(source_locator(location.procedure(), row.source))
        }
        AccessPathRoot::CaptureSlot(port) => TypestateObjectKey::CaptureSlot {
            procedure: port.procedure().semantics().locator().clone(),
            port: procedure_port_key(port),
        },
        AccessPathRoot::TypeSummary(locator) => {
            TypestateObjectKey::TypeSummary(locator.locator().clone())
        }
        AccessPathRoot::ModuleObject(locator) => {
            TypestateObjectKey::ModuleObject(locator.locator().clone())
        }
        AccessPathRoot::External(locator) => {
            TypestateObjectKey::External(locator.locator().clone())
        }
    }
}

fn typestate_context_key(context: &OracleCallContext) -> TypestateContextKey {
    TypestateContextKey {
        calls: context
            .calls()
            .iter()
            .map(call_site_locator)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        truncated: context.was_truncated(),
    }
}

fn procedure_port_key(
    port: &crate::analyzer::semantic::ProcedurePortHandle,
) -> TypestateProcedurePortKey {
    match port.kind() {
        ProcedurePortKind::Receiver => TypestateProcedurePortKey::Receiver,
        ProcedurePortKind::Parameter { ordinal } => {
            TypestateProcedurePortKey::Parameter { ordinal }
        }
        ProcedurePortKind::NormalReturn => TypestateProcedurePortKey::NormalReturn,
        ProcedurePortKind::ExceptionalReturn => TypestateProcedurePortKey::ExceptionalReturn,
        ProcedurePortKind::Capture { slot } => {
            let row = port
                .procedure()
                .semantics()
                .memory_location(slot)
                .expect("capture ports are validated at construction");
            TypestateProcedurePortKey::Capture {
                identity: source_locator(port.procedure(), row.source),
            }
        }
    }
}

fn value_locator(value: &crate::analyzer::semantic::ValueHandle) -> SemanticLocator {
    let row = value
        .procedure()
        .semantics()
        .value(value.id())
        .expect("value handles are validated at construction");
    source_locator(value.procedure(), row.source)
}

fn program_point_locator(point: &ProgramPointHandle) -> SemanticLocator {
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

fn validate_seed_site(site: &TypestateObservationSite) -> Result<(), TypestateBindingPlanError> {
    if matches!(site, TypestateObservationSite::ProgramPoint { .. }) {
        Ok(())
    } else {
        Err(TypestateBindingPlanError::InvalidSeedSite)
    }
}

fn validate_terminal_exit(
    _kind: ProtocolProcedureExitKind,
    site: &TypestateObservationSite,
    role: TypestateObjectRole,
) -> Result<(), TypestateBindingPlanError> {
    if matches!(site, TypestateObservationSite::ProgramPoint { .. })
        && role == TypestateObjectRole::CurrentObject
    {
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
        ProtocolEventOccurrence::ProcedureExit { .. } => {
            matches!(site, TypestateObservationSite::ProgramPoint { .. })
                && role == TypestateObjectRole::CurrentObject
        }
    };
    if valid {
        Ok(())
    } else {
        Err(TypestateBindingPlanError::InvalidObservationShape)
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
        .then_with(|| left.role.cmp(&right.role))
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
}

fn compare_event_order_keys(
    left: &TypestateEventBindingSpec,
    right: &TypestateEventBindingSpec,
) -> Ordering {
    compare_sites(&left.site, &right.site)
        .then_with(|| left.order.cmp(&right.order))
        .then_with(|| left.subject.cmp(&right.subject))
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

fn index_point_sites<T>(
    values: &[T],
    site: impl Fn(&T) -> &TypestateObservationSite,
) -> HashMap<ProgramPointHandle, Box<[usize]>> {
    let mut indexes = HashMap::<ProgramPointHandle, Vec<usize>>::new();
    for (index, value) in values.iter().enumerate() {
        if let TypestateObservationSite::ProgramPoint { point, .. } = site(value) {
            indexes.entry(point.clone()).or_default().push(index);
        }
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

#[derive(Serialize)]
struct CanonicalBindingPlan<'a> {
    schema_version: u32,
    protocol_hash: TypestateProtocolHash,
    subjects: Vec<CanonicalSubject<'a>>,
    initial_seeds: Vec<CanonicalSeed<'a>>,
    event_bindings: Vec<CanonicalEventBinding<'a>>,
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
    ExceptionalReturn,
    Capture { identity: CanonicalLocator<'a> },
}

#[derive(Serialize)]
struct CanonicalSeed<'a> {
    subject: CanonicalSubjectKey<'a>,
    state: &'a str,
    site: CanonicalSite<'a>,
    role: TypestateObjectRole,
    quality: CanonicalQuality,
}

#[derive(Serialize)]
struct CanonicalEventBinding<'a> {
    event: &'a str,
    subject: CanonicalSubjectKey<'a>,
    site: CanonicalSite<'a>,
    order: u32,
    role: TypestateObjectRole,
    quality: CanonicalQuality,
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
