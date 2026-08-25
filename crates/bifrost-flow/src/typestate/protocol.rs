use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::analyzer::identifier::define_identifier;
use crate::dataflow::UnmodeledCallBehavior;
use brokk_bifrost_core::analyzer::dense_id::define_dense_id;

use super::TypestateProtocolHash;

pub const PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROTOCOL_SOURCE_BYTES: usize = 1 << 20;
pub const MAX_PROTOCOL_KEY_BYTES: usize = 128;
pub const MAX_PROTOCOL_STATES: usize = 4_096;
pub const MAX_PROTOCOL_EVENTS: usize = 4_096;
pub const MAX_PROTOCOL_TRANSITIONS: usize = 16_384;
pub const MAX_PROTOCOL_EXPECTATIONS: usize = 4_096;
pub const MAX_PROTOCOL_EXPECTED_STATE_MEMBERSHIPS: usize = 16_384;
const MAX_PROTOCOL_DIAGNOSTICS: usize = 256;
const MAX_DIAGNOSTIC_VALUE_BYTES: usize = 96;

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ProtocolStateId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ProtocolEventId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ProtocolExpectationId {
        new: pub(crate),
        get: pub,
        index: pub(crate),
        try_from_index: pub(crate),
    }
}

pub type ProtocolKeyError = crate::analyzer::identifier::IdentifierError;

macro_rules! define_protocol_key {
    ($name:ident) => {
        define_identifier! {
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
            #[serde(transparent)]
            pub struct $name {
                max_bytes: MAX_PROTOCOL_KEY_BYTES,
                allow_dot: false,
                error: ProtocolKeyError,
            }
        }
    };
}

define_protocol_key!(ProtocolStateKey);
define_protocol_key!(ProtocolEventKey);
define_protocol_key!(ProtocolExpectationKey);

/// Declarative, diagnostic-neutral internal protocol input.
///
/// Public `.rqlp` authoring types are intentionally separate and are lowered
/// into this shape by the future #824 adapter.
#[derive(Debug, Clone)]
pub struct ProtocolSpec {
    pub schema_version: u32,
    pub states: Vec<String>,
    pub initial_state: String,
    pub accepting_states: Vec<String>,
    pub error_states: Vec<String>,
    pub events: Vec<ProtocolEventSpec>,
    pub transitions: Vec<ProtocolTransitionSpec>,
    pub terminal_expectations: Vec<ProtocolTerminalExpectationSpec>,
    pub semantics: ProtocolSemantics,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolSpecWire {
    schema_version: u32,
    states: Vec<String>,
    initial_state: String,
    accepting_states: Vec<String>,
    error_states: Vec<String>,
    events: Vec<ProtocolEventSpec>,
    transitions: Vec<ProtocolTransitionSpec>,
    terminal_expectations: Vec<ProtocolTerminalExpectationSpec>,
    semantics: ProtocolSemantics,
}

impl From<ProtocolSpecWire> for ProtocolSpec {
    fn from(wire: ProtocolSpecWire) -> Self {
        Self {
            schema_version: wire.schema_version,
            states: wire.states,
            initial_state: wire.initial_state,
            accepting_states: wire.accepting_states,
            error_states: wire.error_states,
            events: wire.events,
            transitions: wire.transitions,
            terminal_expectations: wire.terminal_expectations,
            semantics: wire.semantics,
        }
    }
}

impl ProtocolSpec {
    pub fn from_json(source: &[u8]) -> Result<Self, ProtocolSpecParseError> {
        if source.len() > MAX_PROTOCOL_SOURCE_BYTES {
            return Err(ProtocolSpecParseError::TooLarge {
                actual_bytes: source.len(),
                max_bytes: MAX_PROTOCOL_SOURCE_BYTES,
            });
        }
        serde_json::from_slice::<ProtocolSpecWire>(source)
            .map(Into::into)
            .map_err(ProtocolSpecParseError::invalid_json)
    }

    pub fn compile(&self) -> Result<CompiledProtocol, ProtocolCompileError> {
        compile_protocol(self)
    }
}

#[derive(Debug)]
pub enum ProtocolSpecParseError {
    TooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    InvalidJson {
        message: Box<str>,
        line: usize,
        column: usize,
    },
}

impl ProtocolSpecParseError {
    fn invalid_json(error: serde_json::Error) -> Self {
        Self::InvalidJson {
            message: bounded_debug_display(&error),
            line: error.line(),
            column: error.column(),
        }
    }

    pub const fn line(&self) -> Option<usize> {
        match self {
            Self::TooLarge { .. } => None,
            Self::InvalidJson { line, .. } => Some(*line),
        }
    }

    pub const fn column(&self) -> Option<usize> {
        match self {
            Self::TooLarge { .. } => None,
            Self::InvalidJson { column, .. } => Some(*column),
        }
    }
}

impl fmt::Display for ProtocolSpecParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                actual_bytes,
                max_bytes,
            } => write!(
                formatter,
                "protocol source contains {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::InvalidJson { message, .. } => {
                write!(formatter, "invalid protocol JSON: {message}")
            }
        }
    }
}

impl std::error::Error for ProtocolSpecParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TooLarge { .. } => None,
            Self::InvalidJson { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolEventSpec {
    pub id: String,
    pub observation: ProtocolObservationSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolTransitionSpec {
    pub from: String,
    pub on: String,
    pub to: String,
    #[serde(default)]
    pub guard: ProtocolGuardSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolTerminalExpectationSpec {
    pub id: String,
    pub on: ProtocolTerminalObservationSpec,
    pub expected_states: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolObservationSpec {
    pub occurrence: ProtocolEventOccurrence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolEventOccurrence {
    Allocation,
    Endpoint { phase: ProtocolObservationPhase },
    ActualToFormal,
    ReturnFlow,
    FieldRead,
    FieldWrite,
    Escape,
    ProcedureExit { kind: ProtocolProcedureExitKind },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolObservationPhase {
    AtMatch,
    BeforeCall,
    AfterNormalReturn,
    AfterExceptionalReturn,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolGuardSpec {
    #[default]
    Always,
    ObjectCardinality {
        allowed: Vec<ProtocolObjectCardinality>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolObjectCardinality {
    Singleton,
    Summary,
    Unknown,
}

const PROTOCOL_OBJECT_CARDINALITIES: [ProtocolObjectCardinality; 3] = [
    ProtocolObjectCardinality::Singleton,
    ProtocolObjectCardinality::Summary,
    ProtocolObjectCardinality::Unknown,
];

const fn cardinality_index(cardinality: ProtocolObjectCardinality) -> usize {
    match cardinality {
        ProtocolObjectCardinality::Singleton => 0,
        ProtocolObjectCardinality::Summary => 1,
        ProtocolObjectCardinality::Unknown => 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSemantics {
    pub analysis_mode: ProtocolAnalysisMode,
    pub unmatched_event: ProtocolUnmatchedEventBehavior,
    pub uncertainty: ProtocolUncertaintySemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolAnalysisMode {
    May,
    Must,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolUnmatchedEventBehavior {
    PreserveState,
    MarkInconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolUncertaintySemantics {
    pub ambiguous_dispatch: ProtocolUncertaintyBehavior,
    pub unknown_call: ProtocolUncertaintyBehavior,
    pub external_call: ProtocolUncertaintyBehavior,
    pub escape: ProtocolUncertaintyBehavior,
    pub incomplete_analysis: ProtocolUncertaintyBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolUncertaintyBehavior {
    ConservativeTransition,
    PreserveUncertainty,
    Abstain,
}

impl From<UnmodeledCallBehavior> for ProtocolUncertaintyBehavior {
    fn from(behavior: UnmodeledCallBehavior) -> Self {
        match behavior {
            UnmodeledCallBehavior::Paranoid => Self::ConservativeTransition,
            UnmodeledCallBehavior::Optimistic => Self::PreserveUncertainty,
            UnmodeledCallBehavior::RequireModel => Self::Abstain,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolUncertaintyCause {
    AmbiguousDispatch,
    UnknownCall,
    ExternalCall,
    Escape,
    IncompleteAnalysis,
}

impl ProtocolUncertaintySemantics {
    pub fn with_unmodeled_call_behavior(mut self, behavior: UnmodeledCallBehavior) -> Self {
        let behavior = ProtocolUncertaintyBehavior::from(behavior);
        self.unknown_call = behavior;
        self.external_call = behavior;
        self
    }

    pub const fn behavior(self, cause: ProtocolUncertaintyCause) -> ProtocolUncertaintyBehavior {
        match cause {
            ProtocolUncertaintyCause::AmbiguousDispatch => self.ambiguous_dispatch,
            ProtocolUncertaintyCause::UnknownCall => self.unknown_call,
            ProtocolUncertaintyCause::ExternalCall => self.external_call,
            ProtocolUncertaintyCause::Escape => self.escape,
            ProtocolUncertaintyCause::IncompleteAnalysis => self.incomplete_analysis,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolUncertaintyResolution {
    StateSet(ProtocolUncertaintyStateSet),
    PreserveUncertainty { state: ProtocolStateId },
    Abstain,
}

impl ProtocolUncertaintyResolution {
    pub fn states(&self) -> Option<&[ProtocolStateId]> {
        match self {
            Self::StateSet(states) => Some(states.states()),
            Self::PreserveUncertainty { .. } | Self::Abstain => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolUncertaintyStateSet {
    states: Box<[ProtocolStateId]>,
    error_witnesses: Box<[ProtocolUncertaintyViolation]>,
}

impl ProtocolUncertaintyStateSet {
    pub fn states(&self) -> &[ProtocolStateId] {
        &self.states
    }

    pub fn error_witnesses(&self) -> &[ProtocolUncertaintyViolation] {
        &self.error_witnesses
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolUncertaintyViolation {
    event: ProtocolEventId,
    from: ProtocolStateId,
    to: ProtocolStateId,
}

impl ProtocolUncertaintyViolation {
    pub const fn event(self) -> ProtocolEventId {
        self.event
    }

    pub const fn from(self) -> ProtocolStateId {
        self.from
    }

    pub const fn to(self) -> ProtocolStateId {
        self.to
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolProcedureExitKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolTerminalObservationSpec {
    AnalysisRootExit {
        kind: ProtocolProcedureExitKind,
    },
    Event {
        observation: ProtocolObservationSpec,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CompiledProtocolGuard {
    Always,
    ObjectCardinality {
        allowed: Box<[ProtocolObjectCardinality]>,
    },
}

impl CompiledProtocolGuard {
    fn applies_to(&self, cardinality: ProtocolObjectCardinality) -> bool {
        match self {
            Self::Always => true,
            Self::ObjectCardinality { allowed } => allowed.binary_search(&cardinality).is_ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProtocolEvent {
    id: ProtocolEventId,
    key: ProtocolEventKey,
    observation: ProtocolObservationSpec,
}

impl CompiledProtocolEvent {
    pub const fn id(&self) -> ProtocolEventId {
        self.id
    }

    pub fn key(&self) -> &ProtocolEventKey {
        &self.key
    }

    pub const fn observation(&self) -> &ProtocolObservationSpec {
        &self.observation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProtocolTransition {
    from: ProtocolStateId,
    on: ProtocolEventId,
    to: ProtocolStateId,
    guard: CompiledProtocolGuard,
}

impl CompiledProtocolTransition {
    pub const fn from(&self) -> ProtocolStateId {
        self.from
    }

    pub const fn on(&self) -> ProtocolEventId {
        self.on
    }

    pub const fn to(&self) -> ProtocolStateId {
        self.to
    }

    pub const fn guard(&self) -> &CompiledProtocolGuard {
        &self.guard
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledTerminalExpectation {
    id: ProtocolExpectationId,
    key: ProtocolExpectationKey,
    on: ProtocolTerminalObservationSpec,
    expected_states: Box<[ProtocolStateId]>,
}

impl CompiledTerminalExpectation {
    pub const fn id(&self) -> ProtocolExpectationId {
        self.id
    }

    pub fn key(&self) -> &ProtocolExpectationKey {
        &self.key
    }

    pub const fn on(&self) -> &ProtocolTerminalObservationSpec {
        &self.on
    }

    pub fn expected_states(&self) -> &[ProtocolStateId] {
        &self.expected_states
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProtocol {
    schema_version: u32,
    state_keys: Box<[ProtocolStateKey]>,
    initial_state: ProtocolStateId,
    accepting_states: Box<[bool]>,
    error_states: Box<[bool]>,
    events: Box<[CompiledProtocolEvent]>,
    transitions: Box<[CompiledProtocolTransition]>,
    terminal_expectations: Box<[CompiledTerminalExpectation]>,
    semantics: ProtocolSemantics,
    canonical_bytes: Box<[u8]>,
    canonical_rendering: Box<str>,
    hash: TypestateProtocolHash,
}

impl CompiledProtocol {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn states(&self) -> impl ExactSizeIterator<Item = (ProtocolStateId, &ProtocolStateKey)> {
        self.state_keys.iter().enumerate().map(|(index, key)| {
            (
                ProtocolStateId::try_from_index(index)
                    .expect("compiled protocol state count fits in u32"),
                key,
            )
        })
    }

    pub fn state_key(&self, id: ProtocolStateId) -> Option<&ProtocolStateKey> {
        self.state_keys.get(id.index())
    }

    pub fn state_id(&self, key: &ProtocolStateKey) -> Option<ProtocolStateId> {
        self.state_keys
            .binary_search(key)
            .ok()
            .and_then(|index| ProtocolStateId::try_from_index(index).ok())
    }

    pub const fn initial_state(&self) -> ProtocolStateId {
        self.initial_state
    }

    pub fn is_accepting(&self, state: ProtocolStateId) -> bool {
        self.accepting_states
            .get(state.index())
            .copied()
            .unwrap_or(false)
    }

    pub fn is_error(&self, state: ProtocolStateId) -> bool {
        self.error_states
            .get(state.index())
            .copied()
            .unwrap_or(false)
    }

    pub fn events(&self) -> &[CompiledProtocolEvent] {
        &self.events
    }

    pub fn event_id(&self, key: &ProtocolEventKey) -> Option<ProtocolEventId> {
        self.events
            .binary_search_by(|event| event.key.cmp(key))
            .ok()
            .map(|index| self.events[index].id)
    }

    pub fn event(&self, id: ProtocolEventId) -> Option<&CompiledProtocolEvent> {
        self.events.get(id.index())
    }

    pub fn transitions(&self) -> &[CompiledProtocolTransition] {
        &self.transitions
    }

    pub fn transitions_for(
        &self,
        state: ProtocolStateId,
        event: ProtocolEventId,
    ) -> impl Iterator<Item = &CompiledProtocolTransition> {
        let start = self
            .transitions
            .partition_point(|transition| (transition.from, transition.on) < (state, event));
        self.transitions[start..]
            .iter()
            .take_while(move |transition| (transition.from, transition.on) == (state, event))
    }

    fn outgoing_transitions(
        &self,
        state: ProtocolStateId,
    ) -> impl Iterator<Item = &CompiledProtocolTransition> {
        let start = self
            .transitions
            .partition_point(|transition| transition.from < state);
        self.transitions[start..]
            .iter()
            .take_while(move |transition| transition.from == state)
    }

    pub fn transition_for(
        &self,
        state: ProtocolStateId,
        event: ProtocolEventId,
        cardinality: ProtocolObjectCardinality,
    ) -> Option<&CompiledProtocolTransition> {
        self.transitions_for(state, event)
            .find(|transition| transition.guard.applies_to(cardinality))
    }

    pub fn terminal_expectations(&self) -> &[CompiledTerminalExpectation] {
        &self.terminal_expectations
    }

    pub fn expectation_id(&self, key: &ProtocolExpectationKey) -> Option<ProtocolExpectationId> {
        self.terminal_expectations
            .binary_search_by(|expectation| expectation.key.cmp(key))
            .ok()
            .and_then(|index| ProtocolExpectationId::try_from_index(index).ok())
    }

    pub fn terminal_expectation(
        &self,
        id: ProtocolExpectationId,
    ) -> Option<&CompiledTerminalExpectation> {
        self.terminal_expectations.get(id.index())
    }

    pub const fn semantics(&self) -> ProtocolSemantics {
        self.semantics
    }

    /// Resolve one configured uncertainty cause into an executable state
    /// transfer.
    ///
    /// Ambiguous dispatch represents one uncertain observation and therefore
    /// includes the current state plus every matching one-event target.
    /// Unknown or external calls, escape, and incomplete analysis may conceal
    /// an arbitrary event sequence, so their conservative relation is the
    /// reflexive transitive closure of matching transitions. The caller
    /// supplies the finite events that the binding site may actually observe,
    /// preventing unrelated protocol events from entering that closure. All
    /// traversals are iterative and bounded by the compiled protocol.
    pub fn resolve_uncertainty(
        &self,
        cause: ProtocolUncertaintyCause,
        state: ProtocolStateId,
        cardinality: ProtocolObjectCardinality,
        eligible_events: &[ProtocolEventId],
    ) -> Option<ProtocolUncertaintyResolution> {
        self.resolve_uncertainty_events(cause, state, cardinality, eligible_events.iter().copied())
    }

    pub(crate) fn resolve_uncertainty_events(
        &self,
        cause: ProtocolUncertaintyCause,
        state: ProtocolStateId,
        cardinality: ProtocolObjectCardinality,
        eligible_events: impl ExactSizeIterator<Item = ProtocolEventId> + Clone,
    ) -> Option<ProtocolUncertaintyResolution> {
        self.state_keys.get(state.index())?;
        if eligible_events.len() > MAX_PROTOCOL_EVENTS {
            return None;
        }
        for event in eligible_events.clone() {
            self.events.get(event.index())?;
        }
        match self.semantics.uncertainty.behavior(cause) {
            ProtocolUncertaintyBehavior::PreserveUncertainty => {
                Some(ProtocolUncertaintyResolution::PreserveUncertainty { state })
            }
            ProtocolUncertaintyBehavior::Abstain => Some(ProtocolUncertaintyResolution::Abstain),
            ProtocolUncertaintyBehavior::ConservativeTransition => {
                let mut eligible = vec![false; self.events.len()];
                for event in eligible_events {
                    eligible[event.index()] = true;
                }
                let transitive = cause != ProtocolUncertaintyCause::AmbiguousDispatch;
                Some(ProtocolUncertaintyResolution::StateSet(
                    self.conservative_uncertainty_targets(
                        state,
                        cardinality,
                        &eligible,
                        transitive,
                    ),
                ))
            }
        }
    }

    fn conservative_uncertainty_targets(
        &self,
        state: ProtocolStateId,
        cardinality: ProtocolObjectCardinality,
        eligible_events: &[bool],
        transitive: bool,
    ) -> ProtocolUncertaintyStateSet {
        let mut reached = vec![false; self.state_keys.len()];
        let mut error_witnesses = Vec::new();
        reached[state.index()] = true;
        let mut stack = vec![state];
        while let Some(source) = stack.pop() {
            for transition in self.outgoing_transitions(source) {
                if !eligible_events[transition.on.index()]
                    || !transition.guard.applies_to(cardinality)
                {
                    continue;
                }
                let target = transition.to;
                if self.is_error(target) {
                    error_witnesses.push(ProtocolUncertaintyViolation {
                        event: transition.on,
                        from: source,
                        to: target,
                    });
                }
                if !reached[target.index()] {
                    reached[target.index()] = true;
                    if transitive {
                        stack.push(target);
                    }
                }
            }
            if !transitive {
                break;
            }
        }
        let states = reached
            .into_iter()
            .enumerate()
            .filter(|(_, present)| *present)
            .map(|(index, _)| {
                ProtocolStateId::try_from_index(index)
                    .expect("compiled protocol state count fits in u32")
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        error_witnesses.sort_unstable();
        error_witnesses.dedup();
        ProtocolUncertaintyStateSet {
            states,
            error_witnesses: error_witnesses.into_boxed_slice(),
        }
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn canonical_rendering(&self) -> &str {
        &self.canonical_rendering
    }

    pub const fn hash(&self) -> TypestateProtocolHash {
        self.hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolDiagnosticCode {
    UnsupportedSchemaVersion,
    TooManyStates,
    TooManyEvents,
    TooManyTransitions,
    TooManyTerminalExpectations,
    InvalidKey,
    DuplicateState,
    MissingInitialState,
    UnknownState,
    DuplicateClassification,
    ConflictingClassification,
    DuplicateEvent,
    TooManyExpectedStateMemberships,
    EmptyGuard,
    TooManyGuardValues,
    DuplicateGuardValue,
    UnknownEvent,
    DuplicateTransition,
    ConflictingTransition,
    OverlappingTransitionGuards,
    DuplicateExpectation,
    EmptyExpectedStates,
    DuplicateExpectedState,
    NonAcceptingExpectedState,
    UnreachableState,
    DiagnosticsTruncated,
}

impl ProtocolDiagnosticCode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::TooManyStates => "too_many_states",
            Self::TooManyEvents => "too_many_events",
            Self::TooManyTransitions => "too_many_transitions",
            Self::TooManyTerminalExpectations => "too_many_terminal_expectations",
            Self::InvalidKey => "invalid_key",
            Self::DuplicateState => "duplicate_state",
            Self::MissingInitialState => "missing_initial_state",
            Self::UnknownState => "unknown_state",
            Self::DuplicateClassification => "duplicate_classification",
            Self::ConflictingClassification => "conflicting_classification",
            Self::DuplicateEvent => "duplicate_event",
            Self::TooManyExpectedStateMemberships => "too_many_expected_state_memberships",
            Self::EmptyGuard => "empty_guard",
            Self::TooManyGuardValues => "too_many_guard_values",
            Self::DuplicateGuardValue => "duplicate_guard_value",
            Self::UnknownEvent => "unknown_event",
            Self::DuplicateTransition => "duplicate_transition",
            Self::ConflictingTransition => "conflicting_transition",
            Self::OverlappingTransitionGuards => "overlapping_transition_guards",
            Self::DuplicateExpectation => "duplicate_expectation",
            Self::EmptyExpectedStates => "empty_expected_states",
            Self::DuplicateExpectedState => "duplicate_expected_state",
            Self::NonAcceptingExpectedState => "non_accepting_expected_state",
            Self::UnreachableState => "unreachable_state",
            Self::DiagnosticsTruncated => "diagnostics_truncated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolDiagnostic {
    code: ProtocolDiagnosticCode,
    path: Box<str>,
    message: Box<str>,
}

impl ProtocolDiagnostic {
    fn new(
        code: ProtocolDiagnosticCode,
        path: impl Into<Box<str>>,
        message: impl Into<Box<str>>,
    ) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }

    pub const fn code(&self) -> ProtocolDiagnosticCode {
        self.code
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ProtocolDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.code.label(),
            self.path,
            self.message
        )
    }
}

#[derive(Debug)]
pub enum ProtocolCompileError {
    Invalid(Box<[ProtocolDiagnostic]>),
    Canonicalization(serde_json::Error),
}

impl ProtocolCompileError {
    pub fn diagnostics(&self) -> &[ProtocolDiagnostic] {
        match self {
            Self::Invalid(diagnostics) => diagnostics,
            Self::Canonicalization(_) => &[],
        }
    }
}

impl fmt::Display for ProtocolCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(diagnostics) => {
                write!(
                    formatter,
                    "protocol validation failed with {} diagnostic(s)",
                    diagnostics.len()
                )?;
                for diagnostic in diagnostics.iter().take(8) {
                    write!(formatter, "; {diagnostic}")?;
                }
                Ok(())
            }
            Self::Canonicalization(error) => {
                write!(
                    formatter,
                    "failed to canonicalize validated protocol: {error}"
                )
            }
        }
    }
}

impl std::error::Error for ProtocolCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Canonicalization(error) => Some(error),
        }
    }
}

#[derive(Default)]
struct DiagnosticCollector {
    diagnostics: Vec<ProtocolDiagnostic>,
    omitted: usize,
}

impl DiagnosticCollector {
    fn push(&mut self, diagnostic: ProtocolDiagnostic) {
        if self.diagnostics.len() < MAX_PROTOCOL_DIAGNOSTICS {
            self.diagnostics.push(diagnostic);
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }

    fn finish(mut self) -> Box<[ProtocolDiagnostic]> {
        if self.omitted > 0 {
            if self.diagnostics.len() == MAX_PROTOCOL_DIAGNOSTICS {
                self.diagnostics.pop();
            }
            self.diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::DiagnosticsTruncated,
                "$",
                format!(
                    "{} additional validation diagnostic(s) were omitted",
                    self.omitted.saturating_add(1)
                ),
            ));
        }
        self.diagnostics.sort_by(compare_diagnostics);
        self.diagnostics.into_boxed_slice()
    }
}

fn compare_diagnostics(left: &ProtocolDiagnostic, right: &ProtocolDiagnostic) -> Ordering {
    left.path
        .cmp(&right.path)
        .then_with(|| left.code.cmp(&right.code))
        .then_with(|| left.message.cmp(&right.message))
}

#[derive(Debug, Clone)]
struct ValidEvent {
    key: ProtocolEventKey,
    observation: ProtocolObservationSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidTransition {
    source_index: usize,
    from: ProtocolStateKey,
    on: ProtocolEventKey,
    to: ProtocolStateKey,
    guard: CompiledProtocolGuard,
}

#[derive(Debug, Clone)]
struct ValidExpectation {
    key: ProtocolExpectationKey,
    on: ProtocolTerminalObservationSpec,
    expected_states: Vec<ProtocolStateKey>,
}

fn compile_protocol(spec: &ProtocolSpec) -> Result<CompiledProtocol, ProtocolCompileError> {
    let mut diagnostics = DiagnosticCollector::default();
    if spec.schema_version != PROTOCOL_SCHEMA_VERSION {
        diagnostics.push(ProtocolDiagnostic::new(
            ProtocolDiagnosticCode::UnsupportedSchemaVersion,
            "schema_version",
            format!(
                "found {}; supported exact version is {PROTOCOL_SCHEMA_VERSION}",
                spec.schema_version
            ),
        ));
    }
    check_count(
        &mut diagnostics,
        "states",
        spec.states.len(),
        MAX_PROTOCOL_STATES,
        ProtocolDiagnosticCode::TooManyStates,
    );
    check_count(
        &mut diagnostics,
        "events",
        spec.events.len(),
        MAX_PROTOCOL_EVENTS,
        ProtocolDiagnosticCode::TooManyEvents,
    );
    check_count(
        &mut diagnostics,
        "accepting_states",
        spec.accepting_states.len(),
        MAX_PROTOCOL_STATES,
        ProtocolDiagnosticCode::TooManyStates,
    );
    check_count(
        &mut diagnostics,
        "error_states",
        spec.error_states.len(),
        MAX_PROTOCOL_STATES,
        ProtocolDiagnosticCode::TooManyStates,
    );
    check_count(
        &mut diagnostics,
        "transitions",
        spec.transitions.len(),
        MAX_PROTOCOL_TRANSITIONS,
        ProtocolDiagnosticCode::TooManyTransitions,
    );
    check_count(
        &mut diagnostics,
        "terminal_expectations",
        spec.terminal_expectations.len(),
        MAX_PROTOCOL_EXPECTATIONS,
        ProtocolDiagnosticCode::TooManyTerminalExpectations,
    );
    let expected_state_memberships = spec
        .terminal_expectations
        .iter()
        .take(MAX_PROTOCOL_EXPECTATIONS)
        .fold(0usize, |total, expectation| {
            total.saturating_add(expectation.expected_states.len())
        });
    check_count(
        &mut diagnostics,
        "terminal_expectations.expected_states",
        expected_state_memberships,
        MAX_PROTOCOL_EXPECTED_STATE_MEMBERSHIPS,
        ProtocolDiagnosticCode::TooManyExpectedStateMemberships,
    );

    let mut state_sources = HashMap::new();
    for (index, value) in spec.states.iter().take(MAX_PROTOCOL_STATES).enumerate() {
        let path = format!("states[{index}]");
        if let Some(key) = parse_key::<ProtocolStateKey>(value, &path, &mut diagnostics)
            && let Some(previous) = state_sources.insert(key.clone(), index)
        {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::DuplicateState,
                path,
                format!("state `{}` duplicates states[{previous}]", key),
            ));
        }
    }

    let initial_state =
        parse_key::<ProtocolStateKey>(&spec.initial_state, "initial_state", &mut diagnostics);
    if let Some(initial) = &initial_state
        && !state_sources.contains_key(initial)
    {
        diagnostics.push(ProtocolDiagnostic::new(
            ProtocolDiagnosticCode::MissingInitialState,
            "initial_state",
            format!("initial state `{initial}` is not declared"),
        ));
    }

    let accepting_states = parse_state_set(
        &spec.accepting_states,
        "accepting_states",
        &state_sources,
        &mut diagnostics,
    );
    let error_states = parse_state_set(
        &spec.error_states,
        "error_states",
        &state_sources,
        &mut diagnostics,
    );
    for state in accepting_states.intersection(&error_states) {
        diagnostics.push(ProtocolDiagnostic::new(
            ProtocolDiagnosticCode::ConflictingClassification,
            "error_states",
            format!("state `{state}` cannot be both accepting and error"),
        ));
    }

    let mut event_sources = HashMap::new();
    let mut valid_events = Vec::new();
    for (index, event) in spec.events.iter().take(MAX_PROTOCOL_EVENTS).enumerate() {
        let path = format!("events[{index}].id");
        let Some(key) = parse_key::<ProtocolEventKey>(&event.id, &path, &mut diagnostics) else {
            continue;
        };
        if let Some(previous) = event_sources.insert(key.clone(), index) {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::DuplicateEvent,
                path,
                format!("event `{key}` duplicates events[{previous}]"),
            ));
            continue;
        }
        valid_events.push(ValidEvent {
            key,
            observation: event.observation.clone(),
        });
    }

    let mut valid_transitions = Vec::new();
    for (index, transition) in spec
        .transitions
        .iter()
        .take(MAX_PROTOCOL_TRANSITIONS)
        .enumerate()
    {
        let base = format!("transitions[{index}]");
        let from = parse_key::<ProtocolStateKey>(
            &transition.from,
            &format!("{base}.from"),
            &mut diagnostics,
        );
        let on =
            parse_key::<ProtocolEventKey>(&transition.on, &format!("{base}.on"), &mut diagnostics);
        let to =
            parse_key::<ProtocolStateKey>(&transition.to, &format!("{base}.to"), &mut diagnostics);
        if let Some(from) = &from
            && !state_sources.contains_key(from)
        {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::UnknownState,
                format!("{base}.from"),
                format!("state `{from}` is not declared"),
            ));
        }
        if let Some(to) = &to
            && !state_sources.contains_key(to)
        {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::UnknownState,
                format!("{base}.to"),
                format!("state `{to}` is not declared"),
            ));
        }
        if let Some(on) = &on
            && !event_sources.contains_key(on)
        {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::UnknownEvent,
                format!("{base}.on"),
                format!("event `{on}` is not declared"),
            ));
        }
        let guard = normalize_guard(&transition.guard, &base, &mut diagnostics);
        if let (Some(from), Some(on), Some(to), Some(guard)) = (from, on, to, guard)
            && state_sources.contains_key(&from)
            && state_sources.contains_key(&to)
            && event_sources.contains_key(&on)
        {
            valid_transitions.push(ValidTransition {
                source_index: index,
                from,
                on,
                to,
                guard,
            });
        }
    }
    validate_transition_determinism(&valid_transitions, &mut diagnostics);

    let mut expectation_sources = HashMap::new();
    let mut valid_expectations = Vec::new();
    let mut remaining_expected_state_memberships = MAX_PROTOCOL_EXPECTED_STATE_MEMBERSHIPS;
    for (index, expectation) in spec
        .terminal_expectations
        .iter()
        .take(MAX_PROTOCOL_EXPECTATIONS)
        .enumerate()
    {
        let base = format!("terminal_expectations[{index}]");
        let key = parse_key::<ProtocolExpectationKey>(
            &expectation.id,
            &format!("{base}.id"),
            &mut diagnostics,
        );
        if let Some(key) = &key
            && let Some(previous) = expectation_sources.insert(key.clone(), index)
        {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::DuplicateExpectation,
                format!("{base}.id"),
                format!(
                    "terminal expectation `{key}` duplicates terminal_expectations[{previous}]"
                ),
            ));
        }
        let expected_states = parse_expected_states(
            &expectation.expected_states,
            &format!("{base}.expected_states"),
            &state_sources,
            &accepting_states,
            &mut diagnostics,
            &mut remaining_expected_state_memberships,
        );
        if let Some(key) = key
            && expectation_sources.get(&key) == Some(&index)
            && !expected_states.is_empty()
        {
            valid_expectations.push(ValidExpectation {
                key,
                on: expectation.on.clone(),
                expected_states,
            });
        }
    }

    if let Some(initial) = &initial_state
        && state_sources.contains_key(initial)
    {
        validate_reachability(
            initial,
            &state_sources,
            &valid_transitions,
            &mut diagnostics,
        );
    }

    let diagnostics = diagnostics.finish();
    if !diagnostics.is_empty() {
        return Err(ProtocolCompileError::Invalid(diagnostics));
    }

    build_compiled_protocol(
        spec,
        initial_state.expect("validated initial state"),
        state_sources.into_keys().collect(),
        accepting_states,
        error_states,
        valid_events,
        valid_transitions,
        valid_expectations,
    )
}

fn check_count(
    diagnostics: &mut DiagnosticCollector,
    path: &str,
    actual: usize,
    maximum: usize,
    code: ProtocolDiagnosticCode,
) {
    if actual > maximum {
        diagnostics.push(ProtocolDiagnostic::new(
            code,
            path.to_owned(),
            format!("contains {actual} entries; maximum is {maximum}"),
        ));
    }
}

fn parse_key<T>(value: &str, path: &str, diagnostics: &mut DiagnosticCollector) -> Option<T>
where
    T: FromStr<Err = ProtocolKeyError>,
{
    match value.parse() {
        Ok(key) => Some(key),
        Err(error) => {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::InvalidKey,
                path,
                format!("`{}`: {error}", bounded_debug_value(value)),
            ));
            None
        }
    }
}

struct BoundedDebugWriter {
    output: String,
    truncated: bool,
}

impl BoundedDebugWriter {
    fn new() -> Self {
        Self {
            output: String::with_capacity(MAX_DIAGNOSTIC_VALUE_BYTES + 3),
            truncated: false,
        }
    }

    fn finish(mut self) -> String {
        if self.truncated {
            self.output.push_str("...");
        }
        self.output
    }
}

impl fmt::Write for BoundedDebugWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated {
            return Ok(());
        }
        for character in value.escape_debug() {
            if self.output.len() + character.len_utf8() > MAX_DIAGNOSTIC_VALUE_BYTES {
                self.truncated = true;
                break;
            }
            self.output.push(character);
        }
        Ok(())
    }
}

fn bounded_debug_display(value: &impl fmt::Display) -> Box<str> {
    let mut writer = BoundedDebugWriter::new();
    let _ = write!(&mut writer, "{value}");
    writer.finish().into_boxed_str()
}

fn bounded_debug_value(value: &str) -> String {
    let mut writer = BoundedDebugWriter::new();
    let _ = writer.write_str(value);
    writer.finish()
}

fn parse_state_set(
    values: &[String],
    field: &str,
    states: &HashMap<ProtocolStateKey, usize>,
    diagnostics: &mut DiagnosticCollector,
) -> HashSet<ProtocolStateKey> {
    let mut retained = HashSet::new();
    for (index, value) in values.iter().take(MAX_PROTOCOL_STATES).enumerate() {
        let path = format!("{field}[{index}]");
        let Some(key) = parse_key::<ProtocolStateKey>(value, &path, diagnostics) else {
            continue;
        };
        if !states.contains_key(&key) {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::UnknownState,
                path,
                format!("state `{key}` is not declared"),
            ));
        } else if !retained.insert(key.clone()) {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::DuplicateClassification,
                path,
                format!("state `{key}` is listed more than once"),
            ));
        }
    }
    retained
}

fn normalize_guard(
    guard: &ProtocolGuardSpec,
    transition_path: &str,
    diagnostics: &mut DiagnosticCollector,
) -> Option<CompiledProtocolGuard> {
    match guard {
        ProtocolGuardSpec::Always => Some(CompiledProtocolGuard::Always),
        ProtocolGuardSpec::ObjectCardinality { allowed } => {
            if allowed.is_empty() {
                diagnostics.push(ProtocolDiagnostic::new(
                    ProtocolDiagnosticCode::EmptyGuard,
                    format!("{transition_path}.guard.allowed"),
                    "object-cardinality guard must allow at least one cardinality",
                ));
                return None;
            }
            if allowed.len() > PROTOCOL_OBJECT_CARDINALITIES.len() {
                diagnostics.push(ProtocolDiagnostic::new(
                    ProtocolDiagnosticCode::TooManyGuardValues,
                    format!("{transition_path}.guard.allowed"),
                    format!(
                        "object-cardinality guard contains {} values; maximum is {}",
                        allowed.len(),
                        PROTOCOL_OBJECT_CARDINALITIES.len()
                    ),
                ));
                return None;
            }
            let mut retained = [false; PROTOCOL_OBJECT_CARDINALITIES.len()];
            let mut duplicate = false;
            for cardinality in allowed {
                let already_present = &mut retained[cardinality_index(*cardinality)];
                duplicate |= *already_present;
                *already_present = true;
            }
            if duplicate {
                diagnostics.push(ProtocolDiagnostic::new(
                    ProtocolDiagnosticCode::DuplicateGuardValue,
                    format!("{transition_path}.guard.allowed"),
                    "object-cardinality guard contains a duplicate value",
                ));
            }
            if retained.iter().all(|present| *present) {
                return Some(CompiledProtocolGuard::Always);
            }
            let normalized: Vec<_> = PROTOCOL_OBJECT_CARDINALITIES
                .iter()
                .copied()
                .enumerate()
                .filter_map(|(index, cardinality)| retained[index].then_some(cardinality))
                .collect();
            Some(CompiledProtocolGuard::ObjectCardinality {
                allowed: normalized.into_boxed_slice(),
            })
        }
    }
}

fn validate_transition_determinism(
    transitions: &[ValidTransition],
    diagnostics: &mut DiagnosticCollector,
) {
    let mut ordered: Vec<_> = transitions.iter().collect();
    ordered.sort_unstable_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then_with(|| left.on.cmp(&right.on))
            .then_with(|| left.guard.cmp(&right.guard))
            .then_with(|| left.source_index.cmp(&right.source_index))
    });

    let mut group_start = 0;
    while group_start < ordered.len() {
        let mut group_end = group_start + 1;
        while group_end < ordered.len()
            && ordered[group_end].from == ordered[group_start].from
            && ordered[group_end].on == ordered[group_start].on
        {
            group_end += 1;
        }

        let mut cardinality_owners: [Option<&ValidTransition>;
            PROTOCOL_OBJECT_CARDINALITIES.len()] = [None; PROTOCOL_OBJECT_CARDINALITIES.len()];
        let mut previous: Option<&ValidTransition> = None;
        for transition in &ordered[group_start..group_end] {
            if let Some(prior) = previous
                && prior.guard == transition.guard
            {
                let code = if prior.to == transition.to {
                    ProtocolDiagnosticCode::DuplicateTransition
                } else {
                    ProtocolDiagnosticCode::ConflictingTransition
                };
                diagnostics.push(ProtocolDiagnostic::new(
                    code,
                    format!("transitions[{}]", transition.source_index),
                    format!(
                        "transition duplicates or conflicts with transitions[{}] for state `{}` and event `{}`",
                        prior.source_index, transition.from, transition.on
                    ),
                ));
            }

            let overlapping = PROTOCOL_OBJECT_CARDINALITIES
                .iter()
                .enumerate()
                .filter(|(_, cardinality)| transition.guard.applies_to(**cardinality))
                .filter_map(|(index, _)| cardinality_owners[index])
                .find(|prior| prior.guard != transition.guard);
            if let Some(prior) = overlapping {
                diagnostics.push(ProtocolDiagnostic::new(
                    ProtocolDiagnosticCode::OverlappingTransitionGuards,
                    format!("transitions[{}].guard", transition.source_index),
                    format!(
                        "guard overlaps transitions[{}] for state `{}` and event `{}`",
                        prior.source_index, transition.from, transition.on
                    ),
                ));
            }

            for (index, cardinality) in PROTOCOL_OBJECT_CARDINALITIES.iter().enumerate() {
                if transition.guard.applies_to(*cardinality) {
                    cardinality_owners[index] = Some(transition);
                }
            }
            previous = Some(transition);
        }
        group_start = group_end;
    }
}

fn parse_expected_states(
    values: &[String],
    path: &str,
    states: &HashMap<ProtocolStateKey, usize>,
    accepting: &HashSet<ProtocolStateKey>,
    diagnostics: &mut DiagnosticCollector,
    remaining_memberships: &mut usize,
) -> Vec<ProtocolStateKey> {
    check_count(
        diagnostics,
        path,
        values.len(),
        MAX_PROTOCOL_STATES,
        ProtocolDiagnosticCode::TooManyStates,
    );
    if values.is_empty() {
        diagnostics.push(ProtocolDiagnostic::new(
            ProtocolDiagnosticCode::EmptyExpectedStates,
            path,
            "terminal expectation must name at least one accepting state",
        ));
        return Vec::new();
    }
    let mut retained = HashSet::new();
    let retain_count = values
        .len()
        .min(MAX_PROTOCOL_STATES)
        .min(*remaining_memberships);
    *remaining_memberships -= retain_count;
    for (index, value) in values.iter().take(retain_count).enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(key) = parse_key::<ProtocolStateKey>(value, &item_path, diagnostics) else {
            continue;
        };
        if !states.contains_key(&key) {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::UnknownState,
                item_path,
                format!("state `{key}` is not declared"),
            ));
        } else if !accepting.contains(&key) {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::NonAcceptingExpectedState,
                item_path,
                format!("expected state `{key}` is not accepting"),
            ));
        } else if !retained.insert(key.clone()) {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::DuplicateExpectedState,
                item_path,
                format!("expected state `{key}` is listed more than once"),
            ));
        }
    }
    let mut values: Vec<_> = retained.into_iter().collect();
    values.sort_unstable();
    values
}

fn validate_reachability(
    initial: &ProtocolStateKey,
    states: &HashMap<ProtocolStateKey, usize>,
    transitions: &[ValidTransition],
    diagnostics: &mut DiagnosticCollector,
) {
    let mut outgoing = HashMap::<ProtocolStateKey, Vec<ProtocolStateKey>>::new();
    for transition in transitions {
        outgoing
            .entry(transition.from.clone())
            .or_default()
            .push(transition.to.clone());
    }
    let mut reached = HashSet::new();
    let mut stack = vec![initial.clone()];
    while let Some(state) = stack.pop() {
        if !reached.insert(state.clone()) {
            continue;
        }
        if let Some(targets) = outgoing.get(&state) {
            stack.extend(targets.iter().cloned());
        }
    }
    let mut unreachable: Vec<_> = states
        .keys()
        .filter(|state| !reached.contains(*state))
        .collect();
    unreachable.sort_unstable();
    for state in unreachable {
        diagnostics.push(ProtocolDiagnostic::new(
            ProtocolDiagnosticCode::UnreachableState,
            format!("states[{}]", states[state]),
            format!("state `{state}` is unreachable from `{initial}`"),
        ));
    }
}

#[derive(Serialize)]
struct CanonicalProtocol {
    schema_version: u32,
    states: Vec<ProtocolStateKey>,
    initial_state: ProtocolStateKey,
    accepting_states: Vec<ProtocolStateKey>,
    error_states: Vec<ProtocolStateKey>,
    events: Vec<CanonicalEvent>,
    transitions: Vec<CanonicalTransition>,
    terminal_expectations: Vec<CanonicalExpectation>,
    semantics: ProtocolSemantics,
}

#[derive(Serialize)]
struct CanonicalEvent {
    id: ProtocolEventKey,
    observation: ProtocolObservationSpec,
}

#[derive(Serialize)]
struct CanonicalTransition {
    from: ProtocolStateKey,
    on: ProtocolEventKey,
    to: ProtocolStateKey,
    guard: CompiledProtocolGuard,
}

#[derive(Serialize)]
struct CanonicalExpectation {
    id: ProtocolExpectationKey,
    on: ProtocolTerminalObservationSpec,
    expected_states: Vec<ProtocolStateKey>,
}

#[allow(clippy::too_many_arguments)]
fn build_compiled_protocol(
    spec: &ProtocolSpec,
    initial_state_key: ProtocolStateKey,
    mut state_keys: Vec<ProtocolStateKey>,
    accepting_keys: HashSet<ProtocolStateKey>,
    error_keys: HashSet<ProtocolStateKey>,
    mut events: Vec<ValidEvent>,
    transitions: Vec<ValidTransition>,
    mut expectations: Vec<ValidExpectation>,
) -> Result<CompiledProtocol, ProtocolCompileError> {
    state_keys.sort_unstable();
    events.sort_by(|left, right| left.key.cmp(&right.key));
    expectations.sort_by(|left, right| left.key.cmp(&right.key));

    let state_ids: HashMap<_, _> = state_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            (
                key.clone(),
                ProtocolStateId::try_from_index(index)
                    .expect("validated protocol state count fits in u32"),
            )
        })
        .collect();
    let event_ids: HashMap<_, _> = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            (
                event.key.clone(),
                ProtocolEventId::try_from_index(index)
                    .expect("validated protocol event count fits in u32"),
            )
        })
        .collect();

    let compiled_events: Vec<_> = events
        .iter()
        .enumerate()
        .map(|(index, event)| CompiledProtocolEvent {
            id: ProtocolEventId::try_from_index(index)
                .expect("validated protocol event count fits in u32"),
            key: event.key.clone(),
            observation: event.observation.clone(),
        })
        .collect();

    let mut compiled_transitions: Vec<_> = transitions
        .iter()
        .map(|transition| CompiledProtocolTransition {
            from: state_ids[&transition.from],
            on: event_ids[&transition.on],
            to: state_ids[&transition.to],
            guard: transition.guard.clone(),
        })
        .collect();
    compiled_transitions.sort_by(compare_compiled_transitions);

    let compiled_expectations: Vec<_> = expectations
        .iter()
        .enumerate()
        .map(|(index, expectation)| {
            let mut expected_states: Vec<_> = expectation
                .expected_states
                .iter()
                .map(|state| state_ids[state])
                .collect();
            expected_states.sort_unstable();
            CompiledTerminalExpectation {
                id: ProtocolExpectationId::try_from_index(index)
                    .expect("validated protocol expectation count fits in u32"),
                key: expectation.key.clone(),
                on: expectation.on.clone(),
                expected_states: expected_states.into_boxed_slice(),
            }
        })
        .collect();

    let canonical = CanonicalProtocol {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        states: state_keys.clone(),
        initial_state: initial_state_key.clone(),
        accepting_states: sorted_keys(&accepting_keys),
        error_states: sorted_keys(&error_keys),
        events: events
            .into_iter()
            .map(|event| CanonicalEvent {
                id: event.key,
                observation: event.observation,
            })
            .collect(),
        transitions: transitions
            .into_iter()
            .map(|transition| CanonicalTransition {
                from: transition.from,
                on: transition.on,
                to: transition.to,
                guard: transition.guard,
            })
            .collect::<Vec<_>>(),
        terminal_expectations: expectations
            .drain(..)
            .map(|expectation| CanonicalExpectation {
                id: expectation.key,
                on: expectation.on,
                expected_states: expectation.expected_states,
            })
            .collect(),
        semantics: spec.semantics,
    };
    let mut canonical = canonical;
    canonical.transitions.sort_by(compare_canonical_transitions);
    let canonical_bytes =
        serde_json::to_vec(&canonical).map_err(ProtocolCompileError::Canonicalization)?;
    let canonical_rendering =
        serde_json::to_string_pretty(&canonical).map_err(ProtocolCompileError::Canonicalization)?;
    let hash = TypestateProtocolHash::from_canonical_bytes(&canonical_bytes);
    let accepting_states = state_keys
        .iter()
        .map(|state| accepting_keys.contains(state))
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let error_states = state_keys
        .iter()
        .map(|state| error_keys.contains(state))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    Ok(CompiledProtocol {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        state_keys: state_keys.into_boxed_slice(),
        initial_state: state_ids[&initial_state_key],
        accepting_states,
        error_states,
        events: compiled_events.into_boxed_slice(),
        transitions: compiled_transitions.into_boxed_slice(),
        terminal_expectations: compiled_expectations.into_boxed_slice(),
        semantics: spec.semantics,
        canonical_bytes: canonical_bytes.into_boxed_slice(),
        canonical_rendering: canonical_rendering.into_boxed_str(),
        hash,
    })
}

fn sorted_keys(values: &HashSet<ProtocolStateKey>) -> Vec<ProtocolStateKey> {
    let mut values: Vec<_> = values.iter().cloned().collect();
    values.sort_unstable();
    values
}

fn compare_compiled_transitions(
    left: &CompiledProtocolTransition,
    right: &CompiledProtocolTransition,
) -> Ordering {
    (left.from, left.on)
        .cmp(&(right.from, right.on))
        .then_with(|| left.guard.cmp(&right.guard))
        .then_with(|| left.to.cmp(&right.to))
}

fn compare_canonical_transitions(
    left: &CanonicalTransition,
    right: &CanonicalTransition,
) -> Ordering {
    (&left.from, &left.on)
        .cmp(&(&right.from, &right.on))
        .then_with(|| left.guard.cmp(&right.guard))
        .then_with(|| left.to.cmp(&right.to))
}
