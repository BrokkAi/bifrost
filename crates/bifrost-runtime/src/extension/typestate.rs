//! The `experimental.semantic.typestate` request and result contract.
//!
//! A typestate query asks one bounded question about one procedure: does the
//! tracked subject follow the caller's declared protocol inside the analysis
//! root, and if not, where, with what witness. It is shaped exactly like
//! `experimental.semantic.value_dependence` -- a schema-versioned request with
//! a negotiated compatibility block, a pinned generation, positive limits, and
//! a digest-verified canonical result -- so a host that already speaks the
//! relation surface speaks this one without new machinery.
//!
//! The protocol automaton is caller-owned and self-contained: it travels as the
//! engine's own protocol document, is compiled per request, and is never
//! registered across requests. Semantic handles never cross this boundary, so
//! every site the caller names is a `SourceSpan` and every state, event, and
//! expectation on the wire is the caller's own key rather than a dense engine
//! id.

use super::{
    ExtensionCompatibility, ExtensionLimitValues, SemanticProof, SemanticRelationCompleteness,
    SemanticRelationScope, SemanticRelationStatus, SourceSpan, StableDigest, WorkspaceGeneration,
    relation::{canonical_bytes, decode_json},
};
use brokk_bifrost_flow::typestate::{
    MAX_TYPESTATE_FINDING_CANDIDATES, MAX_TYPESTATE_FINDING_REACHED_ROWS,
    MAX_TYPESTATE_FINDING_WITNESS_BYTES, MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
    MAX_TYPESTATE_WITNESS_EXPANSIONS, MAX_TYPESTATE_WITNESS_STEPS,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, fmt};

const SCHEMA: &str = "1.0";

/// The published operation id this contract serves.
pub const TYPESTATE_OPERATION: &str = "experimental.semantic.typestate";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateCodecError(Box<str>);
impl TypestateCodecError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into().into_boxed_str())
    }
}
impl fmt::Display for TypestateCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for TypestateCodecError {}

/// Which value at a bound call site an observation is about.
///
/// This is the caller's half of a binding: the span says which call, the port
/// says which of that call's values carries the subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypestatePort {
    Receiver,
    Argument { ordinal: u32 },
    NormalResult { ordinal: u32 },
}

/// Where one protocol observation happens inside the analysis root.
///
/// `Call` names a written call by its source span. One span can lower to more
/// than one semantic call site (a Java `finally` body lowers once per
/// completion route), and every site the span names is bound, so a caller must
/// not read a binding as one-to-one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypestateSite {
    Call {
        span: SourceSpan,
        port: TypestatePort,
    },
    ProcedureEntry,
    NormalExit,
    ExceptionalExit,
}
impl TypestateSite {
    fn validate(&self) -> Result<(), TypestateCodecError> {
        if let Self::Call { span, .. } = self {
            span.validate().map_err(TypestateCodecError::new)?;
        }
        Ok(())
    }
}

/// Which role the observed object plays at its site.
///
/// A direct mirror of the engine's object-role vocabulary, restricted to the
/// roles a span-addressed v1 binding can name. Nothing here is inferred: the
/// caller states the role, so the surface never invents an observation the
/// compiled protocol does not declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypestateRole {
    MatchedValue,
    AllocationResult,
    Receiver,
    Argument,
    NormalReturn,
    ExceptionalReturn,
    CurrentObject,
}

/// The tracked subject: one object acquired at one call inside the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateSubject {
    /// Caller-owned subject family name, echoed on every finding.
    pub class: Box<str>,
    /// The protocol state the subject starts in at the root's entry.
    pub initial_state: Box<str>,
    /// The call that acquires the tracked object. This call's enclosing
    /// procedure is the analysis root.
    pub acquisition: SourceSpan,
    /// Which value of the acquisition call is the tracked object.
    pub port: TypestatePort,
}
impl TypestateSubject {
    fn validate(&self) -> Result<(), TypestateCodecError> {
        if self.class.is_empty() || self.initial_state.is_empty() {
            return Err(TypestateCodecError::new(
                "a typestate subject needs a class and an initial state",
            ));
        }
        self.acquisition
            .validate()
            .map_err(TypestateCodecError::new)
    }
}

/// One protocol event bound to one observable site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateEventBinding {
    /// The protocol event key this observation raises.
    pub event: Box<str>,
    pub site: TypestateSite,
    pub role: TypestateRole,
    /// Relative order among several events bound to the same site.
    pub order: u32,
}
impl TypestateEventBinding {
    fn validate(&self) -> Result<(), TypestateCodecError> {
        if self.event.is_empty() {
            return Err(TypestateCodecError::new(
                "a typestate event binding needs an event key",
            ));
        }
        self.site.validate()
    }
}

/// Which exit of the analysis root a terminal expectation is checked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypestateExit {
    Normal,
    Exceptional,
}

/// One protocol terminal expectation bound to a root exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateTerminalBinding {
    pub expectation: Box<str>,
    pub exit: TypestateExit,
}
impl TypestateTerminalBinding {
    fn validate(&self) -> Result<(), TypestateCodecError> {
        if self.expectation.is_empty() {
            return Err(TypestateCodecError::new(
                "a typestate terminal binding needs an expectation key",
            ));
        }
        Ok(())
    }
}

/// The caller's work budget for one typestate query.
///
/// Every dimension is positive and bounded above by the engine's own maximum,
/// so a request cannot ask for unbounded work and a rejected request names the
/// dimension it exceeded. The result echoes the enforced values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateLimits {
    /// Retained findings. Beyond this the result reports a finding-limit
    /// boundary and an omitted count rather than a shorter answer.
    pub max_findings: u32,
    /// Retained solver rows consulted while collecting findings.
    pub max_reached_rows: u32,
    pub max_witness_steps: u32,
    pub max_witness_expansions: u32,
    pub max_total_witness_expansions: u32,
    pub max_witness_bytes: u64,
    /// Uniform per-dimension solver budget, clamped to the engine's own
    /// per-dimension limits when the solve is planned.
    pub max_solver_steps: u64,
    pub max_output_bytes: u64,
    pub max_source_bytes: u64,
}
impl TypestateLimits {
    pub fn validate(self) -> Result<(), TypestateCodecError> {
        for (value, name) in [
            (u64::from(self.max_findings), "max_findings"),
            (u64::from(self.max_reached_rows), "max_reached_rows"),
            (u64::from(self.max_witness_steps), "max_witness_steps"),
            (
                u64::from(self.max_witness_expansions),
                "max_witness_expansions",
            ),
            (
                u64::from(self.max_total_witness_expansions),
                "max_total_witness_expansions",
            ),
            (self.max_witness_bytes, "max_witness_bytes"),
            (self.max_solver_steps, "max_solver_steps"),
            (self.max_output_bytes, "max_output_bytes"),
            (self.max_source_bytes, "max_source_bytes"),
        ] {
            if value == 0 {
                return Err(TypestateCodecError::new(format!(
                    "every typestate limit must be positive: {name}"
                )));
            }
        }
        for (value, maximum, name) in [
            (
                self.max_findings as usize,
                MAX_TYPESTATE_FINDING_CANDIDATES,
                "max_findings",
            ),
            (
                self.max_reached_rows as usize,
                MAX_TYPESTATE_FINDING_REACHED_ROWS,
                "max_reached_rows",
            ),
            (
                self.max_witness_steps as usize,
                MAX_TYPESTATE_WITNESS_STEPS,
                "max_witness_steps",
            ),
            (
                self.max_witness_expansions as usize,
                MAX_TYPESTATE_WITNESS_EXPANSIONS,
                "max_witness_expansions",
            ),
            (
                self.max_total_witness_expansions as usize,
                MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
                "max_total_witness_expansions",
            ),
            (
                usize::try_from(self.max_witness_bytes).unwrap_or(usize::MAX),
                MAX_TYPESTATE_FINDING_WITNESS_BYTES,
                "max_witness_bytes",
            ),
        ] {
            if value > maximum {
                return Err(TypestateCodecError::new(format!(
                    "typestate limit {name} exceeds the engine maximum {maximum}"
                )));
            }
        }
        Ok(())
    }
}
impl From<ExtensionLimitValues> for TypestateLimits {
    fn from(v: ExtensionLimitValues) -> Self {
        let clamp = |value: usize, maximum: usize| value.min(maximum) as u32;
        Self {
            max_findings: clamp(v.result_items as usize, MAX_TYPESTATE_FINDING_CANDIDATES),
            max_reached_rows: clamp(
                v.semantic_nodes as usize,
                MAX_TYPESTATE_FINDING_REACHED_ROWS,
            ),
            max_witness_steps: clamp(v.semantic_nodes as usize, MAX_TYPESTATE_WITNESS_STEPS),
            max_witness_expansions: clamp(
                v.semantic_edges as usize,
                MAX_TYPESTATE_WITNESS_EXPANSIONS,
            ),
            max_total_witness_expansions: clamp(
                v.semantic_edges as usize,
                MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
            ),
            max_witness_bytes: v
                .result_bytes
                .min(MAX_TYPESTATE_FINDING_WITNESS_BYTES as u64),
            max_solver_steps: v.traversal_steps,
            max_output_bytes: v.result_bytes,
            max_source_bytes: v.source_bytes,
        }
    }
}

/// One bounded typestate question about one procedure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateRequest {
    pub schema_version: Box<str>,
    pub compatibility: ExtensionCompatibility,
    pub expected_generation: WorkspaceGeneration,
    /// The caller-owned automaton, as the engine's protocol document. Compiled
    /// under the engine's own state, event, transition, and size bounds, so a
    /// hostile document is rejected before any analysis runs.
    pub protocol: Value,
    pub subject: TypestateSubject,
    pub events: Box<[TypestateEventBinding]>,
    pub terminals: Box<[TypestateTerminalBinding]>,
    /// `Procedure` is the only scope served in this version. `File` and
    /// `BoundedCalls` are declared by the shared vocabulary and refused here.
    pub scope: SemanticRelationScope,
    pub limits: TypestateLimits,
}
impl TypestateRequest {
    pub fn new(
        expected_generation: WorkspaceGeneration,
        protocol: Value,
        subject: TypestateSubject,
        events: Vec<TypestateEventBinding>,
        terminals: Vec<TypestateTerminalBinding>,
        limits: TypestateLimits,
    ) -> Result<Self, TypestateCodecError> {
        let request = Self {
            schema_version: SCHEMA.into(),
            compatibility: ExtensionCompatibility::default(),
            expected_generation,
            protocol,
            subject,
            events: events.into_boxed_slice(),
            terminals: terminals.into_boxed_slice(),
            scope: SemanticRelationScope::Procedure,
            limits,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), TypestateCodecError> {
        if self.schema_version.as_ref() != SCHEMA {
            return Err(TypestateCodecError::new(
                "unsupported typestate schema version",
            ));
        }
        if !self.protocol.is_object() {
            return Err(TypestateCodecError::new(
                "a typestate protocol document must be a JSON object",
            ));
        }
        self.subject.validate()?;
        if self.events.is_empty() && self.terminals.is_empty() {
            return Err(TypestateCodecError::new(
                "a typestate query needs at least one event or terminal binding",
            ));
        }
        for event in &self.events {
            event.validate()?;
        }
        for terminal in &self.terminals {
            terminal.validate()?;
        }
        self.limits.validate()
    }
}

/// Why a typestate query could not see everything it was asked about.
///
/// Split the way issue #2412 split the relation surface: a budget boundary is
/// an invitation to ask again with a larger limit, a frontier boundary is the
/// same answer at every budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypestateBoundaryKind {
    /// The seed file has no execution semantics in this workspace.
    MissingSemantics,
    /// The solver kept incomplete semantic evidence, so absence of a finding
    /// is not a claim that no violation exists.
    AnalysisIncomplete,
    FindingLimit,
    WitnessLimit,
    SolverWorkLimit,
    SemanticWorkLimit,
    Cancelled,
}
impl TypestateBoundaryKind {
    /// Whether a caller-supplied budget produced this boundary.
    pub const fn is_budget(self) -> bool {
        match self {
            Self::FindingLimit
            | Self::WitnessLimit
            | Self::SolverWorkLimit
            | Self::SemanticWorkLimit => true,
            Self::MissingSemantics | Self::AnalysisIncomplete | Self::Cancelled => false,
        }
    }

    /// The dimension name a truncated completion reports, so a caller knows
    /// which request limit to raise.
    pub const fn limit_label(self) -> &'static str {
        match self {
            Self::FindingLimit => "max_findings",
            Self::WitnessLimit => "max_witness_steps",
            Self::SolverWorkLimit => "max_solver_steps",
            Self::SemanticWorkLimit => "max_source_bytes",
            Self::MissingSemantics => "missing_semantics",
            Self::AnalysisIncomplete => "analysis_incomplete",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateBoundary {
    pub kind: TypestateBoundaryKind,
    pub message: Box<str>,
    /// How many results the boundary omitted, when the boundary is a retention
    /// limit. Zero for every other kind.
    pub omitted: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypestateCertainty {
    May,
    Must,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypestateUncertaintyKind {
    AmbiguousDispatch,
    UnknownCall,
    ExternalCall,
    Escape,
    IncompleteAnalysis,
    UnmatchedEvent,
}

/// The finding-level evidence envelope, taken verbatim from the engine.
///
/// Nothing here is invented by the surface: each field is one accessor on the
/// engine's own finding evidence, so a caller reasons about proof exactly as
/// the analysis did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateEvidence {
    pub path_proven: bool,
    pub path_complete: bool,
    pub analysis_complete: bool,
    pub uncertainty: Box<[TypestateUncertaintyKind]>,
    pub abstained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypestateReturnKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypestateWitnessStepKind {
    Seed,
    Edge {
        edge_kind: Box<str>,
    },
    /// The witness left a callee summary without a reconstructable body path.
    EndSummaryGap {
        return_kind: TypestateReturnKind,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateWitnessStep {
    pub kind: TypestateWitnessStepKind,
    pub source: SourceSpan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<SourceSpan>,
    pub proof: SemanticProof,
    pub completeness: SemanticRelationCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateWitnessRecord {
    /// The protocol state observed on this path, when the engine named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_state: Option<Box<str>>,
    pub steps: Box<[TypestateWitnessStep]>,
    pub truncated: bool,
    pub omitted_steps_lower_bound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateSubjectIdentity {
    pub class: Box<str>,
    /// The engine's public canonical rendering of the tracked object. Stable
    /// for the same object in the same generation; never a dense id.
    pub identity: Box<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypestateFindingKind {
    /// An observation drove the subject into an error state.
    ErrorTransition {
        event: Box<str>,
        from_state: Box<str>,
        to_state: Box<str>,
    },
    /// The subject reached a root exit in a state the expectation forbids.
    TerminalExpectation {
        expectation: Box<str>,
        actual_states: Box<[Box<str>]>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateFindingRecord {
    pub subject: TypestateSubjectIdentity,
    pub site: SourceSpan,
    pub kind: TypestateFindingKind,
    pub certainty: TypestateCertainty,
    pub evidence: TypestateEvidence,
    pub witnesses: Box<[TypestateWitnessRecord]>,
    pub omitted_witnesses: u64,
}

/// The answer to the protocol question, above the findings that support it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypestateVerdict {
    /// The subject follows the protocol on every path the analysis saw, and
    /// the analysis saw everything. The typestate analogue of an authoritative
    /// absence: only reachable from a complete status with complete analysis.
    Conforms,
    /// At least one finding is not merely inconclusive.
    Violations,
    /// The analysis abstained, was bounded, or kept only inconclusive
    /// findings. Never read as either conformance or violation.
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypestateSnapshot {
    pub schema_version: Box<str>,
    pub generation: WorkspaceGeneration,
    pub request_digest: StableDigest,
    /// The compiled protocol's own hash, so a caller can prove which automaton
    /// produced this answer without trusting the request echo.
    pub protocol_hash: StableDigest,
    pub status: SemanticRelationStatus,
    pub verdict: TypestateVerdict,
    pub findings: Box<[TypestateFindingRecord]>,
    pub boundaries: Box<[TypestateBoundary]>,
    pub snapshot_digest: StableDigest,
}

impl TypestateSnapshot {
    pub fn try_new(
        generation: WorkspaceGeneration,
        request_digest: StableDigest,
        protocol_hash: StableDigest,
        status: SemanticRelationStatus,
        mut findings: Vec<TypestateFindingRecord>,
        mut boundaries: Vec<TypestateBoundary>,
    ) -> Result<Self, TypestateCodecError> {
        findings.sort_by(compare_findings);
        boundaries.sort_by_key(|boundary| boundary.kind);
        boundaries.dedup_by(|left, right| left.kind == right.kind && left.message == right.message);
        let analysis_complete = findings
            .iter()
            .all(|finding| finding.evidence.analysis_complete);
        let verdict = if findings
            .iter()
            .any(|finding| finding.certainty != TypestateCertainty::Inconclusive)
        {
            TypestateVerdict::Violations
        } else if status == SemanticRelationStatus::Complete
            && findings.is_empty()
            && boundaries.is_empty()
            && analysis_complete
        {
            TypestateVerdict::Conforms
        } else {
            TypestateVerdict::Inconclusive
        };
        let zero = StableDigest::parse("0".repeat(64)).expect("a zero digest is well formed");
        let mut snapshot = Self {
            schema_version: SCHEMA.into(),
            generation,
            request_digest,
            protocol_hash,
            status,
            verdict,
            findings: findings.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
            snapshot_digest: zero,
        };
        snapshot.validate()?;
        snapshot.snapshot_digest = snapshot_digest(&snapshot)?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), TypestateCodecError> {
        if self.schema_version.as_ref() != SCHEMA {
            return Err(TypestateCodecError::new(
                "unsupported typestate schema version",
            ));
        }
        for finding in &self.findings {
            finding.site.validate().map_err(TypestateCodecError::new)?;
            for witness in &finding.witnesses {
                for step in &witness.steps {
                    step.source.validate().map_err(TypestateCodecError::new)?;
                    if let Some(target) = &step.target {
                        target.validate().map_err(TypestateCodecError::new)?;
                    }
                }
            }
        }
        if self
            .findings
            .windows(2)
            .any(|pair| compare_findings(&pair[0], &pair[1]) == Ordering::Greater)
        {
            return Err(TypestateCodecError::new(
                "typestate findings must be in canonical order",
            ));
        }
        let budget_boundaries = self
            .boundaries
            .iter()
            .filter(|boundary| boundary.kind.is_budget())
            .count();
        match self.status {
            SemanticRelationStatus::Complete if !self.boundaries.is_empty() => {
                return Err(TypestateCodecError::new(
                    "a complete typestate snapshot cannot carry boundaries",
                ));
            }
            SemanticRelationStatus::BudgetBounded if budget_boundaries == 0 => {
                return Err(TypestateCodecError::new(
                    "a budget-bounded typestate snapshot must name the exhausted dimension",
                ));
            }
            SemanticRelationStatus::FrontierBounded
                if budget_boundaries > 0 || self.boundaries.is_empty() =>
            {
                return Err(TypestateCodecError::new(
                    "a frontier-bounded typestate snapshot must carry only analysis boundaries",
                ));
            }
            _ => {}
        }
        match self.verdict {
            TypestateVerdict::Conforms
                if self.status != SemanticRelationStatus::Complete
                    || !self.findings.is_empty()
                    || !self.boundaries.is_empty() =>
            {
                return Err(TypestateCodecError::new(
                    "a conforming verdict requires a complete, finding-free, boundary-free result",
                ));
            }
            TypestateVerdict::Violations
                if !self
                    .findings
                    .iter()
                    .any(|finding| finding.certainty != TypestateCertainty::Inconclusive) =>
            {
                return Err(TypestateCodecError::new(
                    "a violation verdict requires at least one conclusive finding",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether an empty finding set is a claim that the subject conforms.
    ///
    /// Only a `Conforms` verdict qualifies. A bounded or abstaining result has
    /// not looked everywhere and must never be read as proof of conformance.
    pub fn authoritative_conformance(&self) -> bool {
        self.verdict == TypestateVerdict::Conforms
    }
}

fn compare_findings(left: &TypestateFindingRecord, right: &TypestateFindingRecord) -> Ordering {
    (
        &left.site.path,
        left.site.start_utf8_byte,
        left.site.end_utf8_byte,
    )
        .cmp(&(
            &right.site.path,
            right.site.start_utf8_byte,
            right.site.end_utf8_byte,
        ))
        .then_with(|| finding_kind_key(&left.kind).cmp(&finding_kind_key(&right.kind)))
        .then_with(|| left.certainty.cmp(&right.certainty))
        .then_with(|| left.subject.identity.cmp(&right.subject.identity))
}

/// A total, deterministic ordering key for one finding kind.
///
/// Rendering the caller's own keys keeps the order independent of dense engine
/// ids, which is the same discipline the node identities follow.
fn finding_kind_key(kind: &TypestateFindingKind) -> String {
    match kind {
        TypestateFindingKind::ErrorTransition {
            event,
            from_state,
            to_state,
        } => format!("error_transition\u{1}{event}\u{1}{from_state}\u{1}{to_state}"),
        TypestateFindingKind::TerminalExpectation {
            expectation,
            actual_states,
        } => format!(
            "terminal_expectation\u{1}{expectation}\u{1}{}",
            actual_states.join("\u{2}")
        ),
    }
}

pub fn encode_typestate_request_json(
    value: &TypestateRequest,
) -> Result<Vec<u8>, TypestateCodecError> {
    value.validate()?;
    canonical_bytes(value).map_err(|error| TypestateCodecError::new(error.to_string()))
}
pub fn decode_typestate_request_json(
    bytes: &[u8],
) -> Result<TypestateRequest, TypestateCodecError> {
    let value: TypestateRequest =
        decode_json(bytes).map_err(|error| TypestateCodecError::new(error.to_string()))?;
    value.validate()?;
    Ok(value)
}
pub fn encode_typestate_snapshot_json(
    value: &TypestateSnapshot,
) -> Result<Vec<u8>, TypestateCodecError> {
    value.validate()?;
    canonical_bytes(value).map_err(|error| TypestateCodecError::new(error.to_string()))
}
pub fn decode_typestate_snapshot_json(
    bytes: &[u8],
) -> Result<TypestateSnapshot, TypestateCodecError> {
    let value: TypestateSnapshot =
        decode_json(bytes).map_err(|error| TypestateCodecError::new(error.to_string()))?;
    value.validate()?;
    if snapshot_digest(&value)? != value.snapshot_digest {
        return Err(TypestateCodecError::new(
            "typestate snapshot digest mismatch",
        ));
    }
    Ok(value)
}

fn snapshot_digest(value: &TypestateSnapshot) -> Result<StableDigest, TypestateCodecError> {
    let mut json =
        serde_json::to_value(value).map_err(|error| TypestateCodecError::new(error.to_string()))?;
    json.as_object_mut()
        .expect("a snapshot serializes as a JSON object")
        .remove("snapshot_digest");
    let bytes =
        canonical_bytes(&json).map_err(|error| TypestateCodecError::new(error.to_string()))?;
    StableDigest::parse(format!("{:x}", Sha256::digest(bytes))).map_err(TypestateCodecError::new)
}

pub(crate) fn typestate_request_digest(
    value: &TypestateRequest,
) -> Result<StableDigest, TypestateCodecError> {
    StableDigest::parse(format!(
        "{:x}",
        Sha256::digest(encode_typestate_request_json(value)?)
    ))
    .map_err(TypestateCodecError::new)
}
