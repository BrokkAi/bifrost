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
    /// Integer and floating-point identities, including language-defined numeric underlying types.
    /// Complex numbers and untyped constants are excluded.
    IntrinsicNumeric,
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

/// The resolved shape of a carrier, before any nominal immutability question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueShape {
    Pointer,
    Array,
    Slice,
    Map,
    Interface,
    Function,
    Channel,
}

/// Structured declared type evidence for one observed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedValueType {
    /// The resolved declared type's canonical spelling as produced by the
    /// structured resolver, never source text or a rendered display string.
    /// Generic arguments are excluded: the consumer classifies the nominal type.
    Named {
        canonical: String,
    },
    NonNamed(ValueShape),
    Undecided(ValueTypeBarrierReason),
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
    fn observed_type(
        &self,
        _observation: &BarrierObservation,
        _request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<ObservedValueType, crate::analyzer::semantic::SemanticProviderError> {
        Ok(ObservedValueType::Undecided(
            ValueTypeBarrierReason::UnsupportedLanguage,
        ))
    }

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

/// Check source identity before using syntax to prove a semantic observation.
/// Both disk content and overlay snapshot belong to the selected artifact.
pub fn value_type_barrier_source_matches(
    observation: &BarrierObservation,
    prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
) -> bool {
    use crate::analyzer::semantic::{
        ContentIdentity, OverlaySnapshotId, SourceRevision, StableDigest,
    };
    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceOrigin;
    let content = ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
    match (
        observation.point().procedure().artifact().key().revision(),
        prepared.origin(),
    ) {
        (SourceRevision::Disk { content: expected }, PreparedSourceOrigin::Disk) => {
            content == expected
        }
        (
            SourceRevision::Overlay {
                content: expected,
                snapshot,
            },
            PreparedSourceOrigin::Overlay,
        ) => {
            content == expected
                && prepared.overlay_revision().is_some_and(|revision| {
                    OverlaySnapshotId::hash_bytes(revision.get().to_le_bytes()) == snapshot
                })
        }
        _ => false,
    }
}

/// Locate the exact source operand of a frozen call, rather than the binding's
/// declaration anchor. Languages supply only call grammar and receiver syntax.
pub fn frozen_call_operand_node<'tree>(
    observation: &BarrierObservation,
    prepared: &'tree brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
    call_kind: &str,
    receiver: impl FnOnce(tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>>,
) -> Option<tree_sitter::Node<'tree>> {
    use crate::analyzer::semantic::SourceMappingKind;
    use brokk_bifrost_core::analyzer::tree_walk::named_children_by_field;
    let semantics = observation.point().procedure().semantics();
    let call = semantics
        .call_sites()
        .iter()
        .find(|call| call.point == observation.point().id())?;
    let mapping = semantics.source_mapping(call.source)?;
    if mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let span = mapping.locator.anchor().span();
    let node = prepared
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)?;
    if node.kind() != call_kind
        || node.start_byte() != span.start_byte() as usize
        || node.end_byte() != span.end_byte() as usize
    {
        return None;
    }
    call.arguments
        .iter()
        .zip(named_children_by_field(node, "arguments"))
        .find_map(|(argument, node)| (argument.value == observation.value()).then_some(node))
        .or_else(|| {
            (call.receiver == Some(observation.value()))
                .then(|| receiver(node))
                .flatten()
        })
}
