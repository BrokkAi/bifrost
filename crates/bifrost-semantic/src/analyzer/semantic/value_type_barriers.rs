//! Policy-independent contracts for classifying a value observation's type.
//!
//! Predicates describe types, not call transfers. A language proves their
//! meaning through `LanguageSupport`; flow engines decide whether a result
//! stops the policy's flow. These types store no cross-request answers.

use crate::analyzer::semantic::ObservationPhase;

use crate::analyzer::semantic::ProgramPointHandle;

use crate::analyzer::semantic::ValueId;

/// The initial language-neutral vocabulary for policy value-type barriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueTypePredicate {
    /// The resolved intrinsic Boolean identity, never a source spelling.
    IntrinsicBool,
    /// An enum with an exhaustive variant inventory and no payload fields.
    FieldlessEnum,
}

/// Why the available type evidence cannot decide a barrier predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueTypeBarrierReason {
    UnsupportedLanguage,
    UnknownType,
    AmbiguousType,
    IncompleteType,
    IncompleteEnumSurface,
    UnavailableObservation,
    BudgetExceeded,
    Cancelled,
}

/// A proof result, independent of the filter that consumes it.
///
/// A lenient filter retains undecided observations; a strict filter removes
/// them. Both remove proven matches and retain proven non-matches. A known
/// payload enum is a non-match, not an undecided fieldless-enum check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueTypeBarrierDecision {
    ProvenMatch,
    ProvenNonMatch,
    Undecided(ValueTypeBarrierReason),
}

/// One value at a point and phase in its owning semantic materialization.
///
/// The point retains the selected artifact/content identity. The value's
/// source mapping is read from that same procedure's semantic rows; storing
/// another source span here could disagree with the selected materialization.
/// Handles and any memo keyed by this observation must stay query-local.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BarrierObservation {
    point: ProgramPointHandle,
    value: ValueId,
    phase: ObservationPhase,
}

impl BarrierObservation {
    /// Construct an observation of a value in the point's procedure.
    pub fn new(point: ProgramPointHandle, value: ValueId, phase: ObservationPhase) -> Self {
        assert!(
            point.procedure().semantics().value(value).is_some(),
            "a barrier observation's value belongs to its point's procedure"
        );
        Self {
            point,
            value,
            phase,
        }
    }

    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn value(&self) -> ValueId {
        self.value
    }

    pub const fn phase(&self) -> ObservationPhase {
        self.phase
    }
}

/// Native operation and proof memos owned by one policy evaluation request.
///
/// Open through `LanguageSupport::value_type_barrier_context` once, then
/// attach by borrowing it with `SemanticRequest::with_value_type_barrier_context`.
/// The context must be dropped at the end of the request.
pub trait ValueTypeBarrierContext {
    fn classify(
        &self,
        observation: &BarrierObservation,
        predicate: ValueTypePredicate,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, crate::analyzer::semantic::SemanticProviderError>;
}

/// A propagation strategy consumes a proof; the worklist has no mode flag.
pub trait ValueTypeBarrierFilter {
    fn permits(&self, decision: ValueTypeBarrierDecision) -> bool;
}

pub struct LenientValueTypeBarriers;
impl ValueTypeBarrierFilter for LenientValueTypeBarriers {
    fn permits(&self, decision: ValueTypeBarrierDecision) -> bool {
        !matches!(decision, ValueTypeBarrierDecision::ProvenMatch)
    }
}

pub struct StrictValueTypeBarriers;
impl ValueTypeBarrierFilter for StrictValueTypeBarriers {
    fn permits(&self, decision: ValueTypeBarrierDecision) -> bool {
        matches!(decision, ValueTypeBarrierDecision::ProvenNonMatch)
    }
}
