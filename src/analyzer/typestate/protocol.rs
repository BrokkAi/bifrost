use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::analyzer::dense_id::define_dense_id;
use crate::hash::{HashMap, HashSet};

use super::TypestateProtocolHash;

pub const PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROTOCOL_SOURCE_BYTES: usize = 1 << 20;
pub const MAX_PROTOCOL_KEY_BYTES: usize = 128;
pub const MAX_PROTOCOL_STATES: usize = 4_096;
pub const MAX_PROTOCOL_EVENTS: usize = 4_096;
pub const MAX_PROTOCOL_TRANSITIONS: usize = 16_384;
pub const MAX_PROTOCOL_EXPECTATIONS: usize = 4_096;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolKeyError {
    Empty,
    TooLong { max_bytes: usize },
    NonAscii,
    InvalidStart,
    InvalidEnd,
    InvalidCharacter { index: usize },
}

impl fmt::Display for ProtocolKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("protocol key must not be empty"),
            Self::TooLong { max_bytes } => {
                write!(formatter, "protocol key must be at most {max_bytes} bytes")
            }
            Self::NonAscii => {
                formatter.write_str("protocol key must contain only ASCII characters")
            }
            Self::InvalidStart => {
                formatter.write_str("protocol key must begin with a lowercase ASCII alphanumeric")
            }
            Self::InvalidEnd => {
                formatter.write_str("protocol key must end with a lowercase ASCII alphanumeric")
            }
            Self::InvalidCharacter { index } => {
                write!(
                    formatter,
                    "protocol key has an invalid character at byte {index}"
                )
            }
        }
    }
}

impl std::error::Error for ProtocolKeyError {}

fn validate_protocol_key(value: &str) -> Result<(), ProtocolKeyError> {
    if value.is_empty() {
        return Err(ProtocolKeyError::Empty);
    }
    if value.len() > MAX_PROTOCOL_KEY_BYTES {
        return Err(ProtocolKeyError::TooLong {
            max_bytes: MAX_PROTOCOL_KEY_BYTES,
        });
    }
    if !value.is_ascii() {
        return Err(ProtocolKeyError::NonAscii);
    }
    let bytes = value.as_bytes();
    if !is_lower_alphanumeric(bytes[0]) {
        return Err(ProtocolKeyError::InvalidStart);
    }
    if !is_lower_alphanumeric(bytes[bytes.len() - 1]) {
        return Err(ProtocolKeyError::InvalidEnd);
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if !(is_lower_alphanumeric(byte) || matches!(byte, b'-' | b'_')) {
            return Err(ProtocolKeyError::InvalidCharacter { index });
        }
    }
    Ok(())
}

const fn is_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

macro_rules! define_protocol_key {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(Box<str>);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self, ProtocolKeyError> {
                let value = value.as_ref();
                validate_protocol_key(value)?;
                Ok(Self(value.into()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = ProtocolKeyError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

define_protocol_key!(ProtocolStateKey);
define_protocol_key!(ProtocolEventKey);
define_protocol_key!(ProtocolExpectationKey);
define_protocol_key!(ProtocolViolationKey);

/// Declarative, diagnostic-neutral internal protocol input.
///
/// Public `.rqlp` authoring types are intentionally separate and are lowered
/// into this shape by the future #824 adapter.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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

impl ProtocolSpec {
    pub fn from_json(source: &[u8]) -> Result<Self, ProtocolSpecParseError> {
        if source.len() > MAX_PROTOCOL_SOURCE_BYTES {
            return Err(ProtocolSpecParseError::TooLarge {
                actual_bytes: source.len(),
                max_bytes: MAX_PROTOCOL_SOURCE_BYTES,
            });
        }
        serde_json::from_slice(source).map_err(ProtocolSpecParseError::InvalidJson)
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
    InvalidJson(serde_json::Error),
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
            Self::InvalidJson(error) => write!(formatter, "invalid protocol JSON: {error}"),
        }
    }
}

impl std::error::Error for ProtocolSpecParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TooLarge { .. } => None,
            Self::InvalidJson(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolEventSpec {
    pub id: String,
    pub action: ProtocolSemanticAction,
    pub phase: ProtocolObservationPhase,
    pub subject: ObjectBindingRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolTransitionSpec {
    pub from: String,
    pub on: String,
    pub to: String,
    #[serde(default)]
    pub guard: ProtocolGuardSpec,
    #[serde(default)]
    pub violation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolTerminalExpectationSpec {
    pub id: String,
    pub on: TerminalExitKind,
    pub expected_states: Vec<String>,
    pub violation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolSemanticAction {
    Allocation,
    ReceiverCall,
    ActualToFormal,
    ReturnFlow,
    FieldRead,
    FieldWrite,
    Escape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolObservationPhase {
    AtEvent,
    BeforeCall,
    AfterNormalReturn,
    AfterExceptionalReturn,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectBindingRole {
    AllocationResult,
    Receiver,
    Actual { index: u16 },
    Formal { index: u16 },
    ReturnValue,
    FieldBase,
    FieldValue,
    EscapedObject,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalExitKind {
    NormalAnalysisRoot,
    ExceptionalAnalysisRoot,
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
    action: ProtocolSemanticAction,
    phase: ProtocolObservationPhase,
    subject: ObjectBindingRole,
}

impl CompiledProtocolEvent {
    pub const fn id(&self) -> ProtocolEventId {
        self.id
    }

    pub fn key(&self) -> &ProtocolEventKey {
        &self.key
    }

    pub const fn action(&self) -> ProtocolSemanticAction {
        self.action
    }

    pub const fn phase(&self) -> ProtocolObservationPhase {
        self.phase
    }

    pub const fn subject(&self) -> &ObjectBindingRole {
        &self.subject
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProtocolTransition {
    from: ProtocolStateId,
    on: ProtocolEventId,
    to: ProtocolStateId,
    guard: CompiledProtocolGuard,
    violation: Option<ProtocolViolationKey>,
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

    pub const fn violation(&self) -> Option<&ProtocolViolationKey> {
        self.violation.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledTerminalExpectation {
    id: ProtocolExpectationId,
    key: ProtocolExpectationKey,
    on: TerminalExitKind,
    expected_states: Box<[ProtocolStateId]>,
    violation: ProtocolViolationKey,
}

impl CompiledTerminalExpectation {
    pub const fn id(&self) -> ProtocolExpectationId {
        self.id
    }

    pub fn key(&self) -> &ProtocolExpectationKey {
        &self.key
    }

    pub const fn on(&self) -> TerminalExitKind {
        self.on
    }

    pub fn expected_states(&self) -> &[ProtocolStateId] {
        &self.expected_states
    }

    pub const fn violation(&self) -> &ProtocolViolationKey {
        &self.violation
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

    pub fn terminal_expectation(
        &self,
        id: ProtocolExpectationId,
    ) -> Option<&CompiledTerminalExpectation> {
        self.terminal_expectations.get(id.index())
    }

    pub const fn semantics(&self) -> ProtocolSemantics {
        self.semantics
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
    InvalidEventShape,
    EmptyGuard,
    DuplicateGuardValue,
    UnknownEvent,
    InvalidViolationKey,
    DuplicateTransition,
    ConflictingTransition,
    OverlappingTransitionGuards,
    ErrorTransitionMissingViolation,
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
            Self::InvalidEventShape => "invalid_event_shape",
            Self::EmptyGuard => "empty_guard",
            Self::DuplicateGuardValue => "duplicate_guard_value",
            Self::UnknownEvent => "unknown_event",
            Self::InvalidViolationKey => "invalid_violation_key",
            Self::DuplicateTransition => "duplicate_transition",
            Self::ConflictingTransition => "conflicting_transition",
            Self::OverlappingTransitionGuards => "overlapping_transition_guards",
            Self::ErrorTransitionMissingViolation => "error_transition_missing_violation",
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
    action: ProtocolSemanticAction,
    phase: ProtocolObservationPhase,
    subject: ObjectBindingRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidTransition {
    source_index: usize,
    from: ProtocolStateKey,
    on: ProtocolEventKey,
    to: ProtocolStateKey,
    guard: CompiledProtocolGuard,
    violation: Option<ProtocolViolationKey>,
}

#[derive(Debug, Clone)]
struct ValidExpectation {
    key: ProtocolExpectationKey,
    on: TerminalExitKind,
    expected_states: Vec<ProtocolStateKey>,
    violation: ProtocolViolationKey,
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

    let mut state_sources = HashMap::default();
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

    let mut event_sources = HashMap::default();
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
        if !valid_event_shape(event) {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::InvalidEventShape,
                format!("events[{index}]"),
                format!(
                    "{:?} at {:?} cannot bind {:?}",
                    event.action, event.phase, event.subject
                ),
            ));
        }
        valid_events.push(ValidEvent {
            key,
            action: event.action,
            phase: event.phase,
            subject: event.subject.clone(),
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
        let violation = transition.violation.as_ref().and_then(|value| {
            parse_key::<ProtocolViolationKey>(value, &format!("{base}.violation"), &mut diagnostics)
        });
        if transition.violation.is_some() && violation.is_none() {
            diagnostics.push(ProtocolDiagnostic::new(
                ProtocolDiagnosticCode::InvalidViolationKey,
                format!("{base}.violation"),
                "transition violation identity is invalid",
            ));
        }
        if let (Some(from), Some(on), Some(to), Some(guard)) = (from, on, to, guard)
            && state_sources.contains_key(&from)
            && state_sources.contains_key(&to)
            && event_sources.contains_key(&on)
        {
            if error_states.contains(&to) && violation.is_none() {
                diagnostics.push(ProtocolDiagnostic::new(
                    ProtocolDiagnosticCode::ErrorTransitionMissingViolation,
                    base.clone(),
                    format!("transition into error state `{to}` must name a violation"),
                ));
            }
            valid_transitions.push(ValidTransition {
                source_index: index,
                from,
                on,
                to,
                guard,
                violation,
            });
        }
    }
    validate_transition_determinism(&valid_transitions, &mut diagnostics);

    let mut expectation_sources = HashMap::default();
    let mut valid_expectations = Vec::new();
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
        let violation = parse_key::<ProtocolViolationKey>(
            &expectation.violation,
            &format!("{base}.violation"),
            &mut diagnostics,
        );
        let expected_states = parse_expected_states(
            &expectation.expected_states,
            &format!("{base}.expected_states"),
            &state_sources,
            &accepting_states,
            &mut diagnostics,
        );
        if let (Some(key), Some(violation)) = (key, violation)
            && expectation_sources.get(&key) == Some(&index)
            && !expected_states.is_empty()
        {
            valid_expectations.push(ValidExpectation {
                key,
                on: expectation.on,
                expected_states,
                violation,
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
                format!("`{}`: {error}", bounded_value(value)),
            ));
            None
        }
    }
}

fn bounded_value(value: &str) -> String {
    if value.len() <= MAX_DIAGNOSTIC_VALUE_BYTES {
        return value.to_owned();
    }
    let boundary = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= MAX_DIAGNOSTIC_VALUE_BYTES)
        .last()
        .unwrap_or(0);
    format!("{}...", &value[..boundary])
}

fn parse_state_set(
    values: &[String],
    field: &str,
    states: &HashMap<ProtocolStateKey, usize>,
    diagnostics: &mut DiagnosticCollector,
) -> HashSet<ProtocolStateKey> {
    let mut retained = HashSet::default();
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

fn valid_event_shape(event: &ProtocolEventSpec) -> bool {
    matches!(
        (&event.action, &event.phase, &event.subject),
        (
            ProtocolSemanticAction::Allocation,
            ProtocolObservationPhase::AtEvent,
            ObjectBindingRole::AllocationResult,
        ) | (
            ProtocolSemanticAction::ReceiverCall,
            ProtocolObservationPhase::BeforeCall
                | ProtocolObservationPhase::AfterNormalReturn
                | ProtocolObservationPhase::AfterExceptionalReturn,
            ObjectBindingRole::Receiver,
        ) | (
            ProtocolSemanticAction::ActualToFormal,
            ProtocolObservationPhase::BeforeCall,
            ObjectBindingRole::Actual { .. } | ObjectBindingRole::Formal { .. },
        ) | (
            ProtocolSemanticAction::ReturnFlow,
            ProtocolObservationPhase::AfterNormalReturn,
            ObjectBindingRole::ReturnValue,
        ) | (
            ProtocolSemanticAction::FieldRead | ProtocolSemanticAction::FieldWrite,
            ProtocolObservationPhase::AtEvent,
            ObjectBindingRole::FieldBase | ObjectBindingRole::FieldValue,
        ) | (
            ProtocolSemanticAction::Escape,
            ProtocolObservationPhase::AtEvent,
            ObjectBindingRole::EscapedObject,
        )
    )
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
            let mut normalized = allowed.clone();
            normalized.sort_unstable();
            let original_len = normalized.len();
            normalized.dedup();
            if normalized.len() != original_len {
                diagnostics.push(ProtocolDiagnostic::new(
                    ProtocolDiagnosticCode::DuplicateGuardValue,
                    format!("{transition_path}.guard.allowed"),
                    "object-cardinality guard contains a duplicate value",
                ));
            }
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
    const CARDINALITIES: [ProtocolObjectCardinality; 3] = [
        ProtocolObjectCardinality::Singleton,
        ProtocolObjectCardinality::Summary,
        ProtocolObjectCardinality::Unknown,
    ];

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

        let mut cardinality_owners: [Option<&ValidTransition>; CARDINALITIES.len()] =
            [None; CARDINALITIES.len()];
        let mut previous: Option<&ValidTransition> = None;
        for transition in &ordered[group_start..group_end] {
            if let Some(prior) = previous
                && prior.guard == transition.guard
            {
                let code = if prior.to == transition.to && prior.violation == transition.violation {
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

            let overlapping = CARDINALITIES
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

            for (index, cardinality) in CARDINALITIES.iter().enumerate() {
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
    let mut retained = HashSet::default();
    for (index, value) in values.iter().take(MAX_PROTOCOL_STATES).enumerate() {
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
    let mut outgoing = HashMap::<ProtocolStateKey, Vec<ProtocolStateKey>>::default();
    for transition in transitions {
        outgoing
            .entry(transition.from.clone())
            .or_default()
            .push(transition.to.clone());
    }
    let mut reached = HashSet::default();
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
    action: ProtocolSemanticAction,
    phase: ProtocolObservationPhase,
    subject: ObjectBindingRole,
}

#[derive(Serialize)]
struct CanonicalTransition {
    from: ProtocolStateKey,
    on: ProtocolEventKey,
    to: ProtocolStateKey,
    guard: CompiledProtocolGuard,
    violation: Option<ProtocolViolationKey>,
}

#[derive(Serialize)]
struct CanonicalExpectation {
    id: ProtocolExpectationKey,
    on: TerminalExitKind,
    expected_states: Vec<ProtocolStateKey>,
    violation: ProtocolViolationKey,
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
            action: event.action,
            phase: event.phase,
            subject: event.subject.clone(),
        })
        .collect();

    let mut compiled_transitions: Vec<_> = transitions
        .iter()
        .map(|transition| CompiledProtocolTransition {
            from: state_ids[&transition.from],
            on: event_ids[&transition.on],
            to: state_ids[&transition.to],
            guard: transition.guard.clone(),
            violation: transition.violation.clone(),
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
                on: expectation.on,
                expected_states: expected_states.into_boxed_slice(),
                violation: expectation.violation.clone(),
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
                action: event.action,
                phase: event.phase,
                subject: event.subject,
            })
            .collect(),
        transitions: transitions
            .into_iter()
            .map(|transition| CanonicalTransition {
                from: transition.from,
                on: transition.on,
                to: transition.to,
                guard: transition.guard,
                violation: transition.violation,
            })
            .collect::<Vec<_>>(),
        terminal_expectations: expectations
            .drain(..)
            .map(|expectation| CanonicalExpectation {
                id: expectation.key,
                on: expectation.on,
                expected_states: expectation.expected_states,
                violation: expectation.violation,
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
        .then_with(|| left.violation.cmp(&right.violation))
}

fn compare_canonical_transitions(
    left: &CanonicalTransition,
    right: &CanonicalTransition,
) -> Ordering {
    (&left.from, &left.on)
        .cmp(&(&right.from, &right.on))
        .then_with(|| left.guard.cmp(&right.guard))
        .then_with(|| left.to.cmp(&right.to))
        .then_with(|| left.violation.cmp(&right.violation))
}
