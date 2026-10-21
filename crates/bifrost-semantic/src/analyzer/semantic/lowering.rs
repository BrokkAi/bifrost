//! Shared emission mechanics for language-owned semantic lowerers.
//!
//! This module deliberately knows nothing about tree-sitter node kinds or
//! language syntax. Adapters choose source anchors, evaluation order, control
//! topology, and uncertainty; the session owns dense IDs, exact provenance,
//! common call rows, and batch-level budget/cancellation semantics.

use crate::analyzer::semantic::lexical_definitions::FormalVariadicKind;

use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, try_walk_named_tree_preorder};
use brokk_bifrost_core::hash::HashMap;
use std::hash::Hash;
use tree_sitter::Node;

use crate::analyzer::semantic::cfg::CleanupRegionId;

use crate::analyzer::semantic::cfg::CleanupRouteOperation;

use crate::analyzer::semantic::cfg::CompletionKind;

use crate::analyzer::semantic::cfg::CompletionRoute;

use crate::analyzer::semantic::cfg::DriveError;

use crate::analyzer::semantic::cfg::ProcedureCfgBuilder;

use crate::analyzer::semantic::cfg::ScopeBinding;

use crate::analyzer::semantic::cfg::ScopeCleanupAction;

use crate::analyzer::semantic::cfg::ScopeFrameId;

use crate::analyzer::semantic::AllocationId;

use crate::analyzer::semantic::AllocationKind;

use crate::analyzer::semantic::AllocationSite;

use crate::analyzer::semantic::ArgumentDomain;

use crate::analyzer::semantic::AsyncResumeKind;

use crate::analyzer::semantic::CallContinuationKind;

use crate::analyzer::semantic::CallInvocationMode;

use crate::analyzer::semantic::CallSiteId;

use crate::analyzer::semantic::CallableTargetResolution;

use brokk_bifrost_core::cancellation::CancellationToken;

use crate::analyzer::semantic::CaptureBinding;

use crate::analyzer::semantic::CaptureId;

use crate::analyzer::semantic::CaptureMode;

use crate::analyzer::semantic::CaptureSource;

use crate::analyzer::semantic::ControlContinuation;

use crate::analyzer::semantic::ControlEdge;

use crate::analyzer::semantic::ControlEdgeKind;

use crate::analyzer::semantic::Evidence;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::EvidenceId;

use crate::analyzer::semantic::ExecutionTiming;

use crate::analyzer::semantic::FormalMultiplicity;

use crate::analyzer::semantic::GuardArm;

use crate::analyzer::semantic::GuardFactParts;

use crate::analyzer::semantic::GuardId;

use crate::analyzer::semantic::GuardPredicate;

use crate::analyzer::semantic::LoopSite;

use crate::analyzer::semantic::MemoryAccessKind;

use crate::analyzer::semantic::MemoryLocation;

use crate::analyzer::semantic::MemoryLocationId;

use crate::analyzer::semantic::MemoryLocationKind;

use crate::analyzer::semantic::MemoryValueCopy;

use crate::analyzer::semantic::ProcedureId;

use crate::analyzer::semantic::ProcedureSemanticsParts;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticBudget;

use crate::analyzer::semantic::SemanticBudgetExceeded;

use crate::analyzer::semantic::SemanticCallArgument;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticEvent;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticGapDischarge;

use crate::analyzer::semantic::SemanticGapId;

use crate::analyzer::semantic::SemanticGapImpact;

use crate::analyzer::semantic::SemanticGapImpacts;

use crate::analyzer::semantic::SemanticGapKind;

use crate::analyzer::semantic::SemanticGapSubject;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRole;

use crate::analyzer::semantic::SemanticValue;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::SourceAnchor;

use crate::analyzer::semantic::SourceMapping;

use crate::analyzer::semantic::SourceMappingId;

use crate::analyzer::semantic::SourceMappingKind;

use crate::analyzer::semantic::SourcePosition;

use crate::analyzer::semantic::SourceSpan;

use crate::analyzer::semantic::StatementEntrySite;

use crate::analyzer::semantic::StructuralNodeIdentity;

use crate::analyzer::semantic::SwitchCaseFactParts;

use crate::analyzer::semantic::SwitchEdgeParts;

use crate::analyzer::semantic::SwitchFactId;

use crate::analyzer::semantic::SwitchFactKind;

use crate::analyzer::semantic::SwitchFactParts;

use crate::analyzer::semantic::SwitchSelectorDomain;

use crate::analyzer::semantic::ValueFlowKind;

use crate::analyzer::semantic::ValueId;

#[doc(hidden)]
pub fn required_field_or_else<'tree, E>(
    node: Node<'tree>,
    field: &str,
    missing_field: impl FnOnce(Node<'tree>, &str) -> E,
) -> Result<Node<'tree>, E> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

#[doc(hidden)]
pub fn missing_field(node: Node<'_>, field: &str) -> ProcedureLoweringError {
    ProcedureLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

#[doc(hidden)]
pub fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    brokk_bifrost_core::analyzer::structural::adapter_helpers::is_field_of(parent, child, field)
}

#[doc(hidden)]
pub fn resolve_binding_value(
    local: Option<ValueId>,
    parameter: Option<ValueId>,
    receiver: Option<ValueId>,
) -> Option<(ValueId, ValueFlowKind)> {
    local
        .map(|value| (value, ValueFlowKind::Local))
        .or_else(|| {
            parameter.map(|value| {
                let kind = if Some(value) == receiver {
                    ValueFlowKind::Receiver
                } else {
                    ValueFlowKind::Parameter
                };
                (value, kind)
            })
        })
}

#[doc(hidden)]
pub fn binding_flow_kind(
    value: ValueId,
    receiver: Option<ValueId>,
    local: Option<ValueId>,
) -> ValueFlowKind {
    if Some(value) == receiver {
        ValueFlowKind::Receiver
    } else if Some(value) == local {
        ValueFlowKind::Local
    } else {
        ValueFlowKind::Parameter
    }
}

#[doc(hidden)]
pub fn unique_map_value<K, V>(map: &HashMap<K, Option<V>>, key: &K) -> Option<V>
where
    K: Eq + Hash,
    V: Clone,
{
    map.get(key)?.clone()
}

/// Common operational failures produced while lowering one procedure.
#[derive(Debug)]
#[doc(hidden)]
pub enum ProcedureLoweringError {
    Cancelled(Box<SemanticWork>),
    Budget(SemanticBudgetExceeded, Box<SemanticWork>),
    Invalid(String),
}

/// Marker returned when shared adapter preparation observes cooperative
/// cancellation before procedure lowering starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct LoweringCancelled;

#[doc(hidden)]
pub fn lexical_capture_destination(
    captures_receiver: bool,
    capture_index: usize,
    language: &str,
) -> Result<MemoryLocationId, ProcedureLoweringError> {
    let too_many_captures =
        || ProcedureLoweringError::Invalid(format!("too many {language} captures"));
    let index = capture_index
        .checked_add(usize::from(captures_receiver))
        .ok_or_else(too_many_captures)?;
    let index = u32::try_from(index).map_err(|_| too_many_captures())?;
    Ok(MemoryLocationId::new(index))
}

#[doc(hidden)]
pub fn body_contains_matching_node<'tree>(
    body: Node<'tree>,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    mut is_nested_execution_boundary: impl FnMut(Node<'tree>) -> bool,
    mut is_target: impl FnMut(Node<'tree>) -> bool,
) -> Result<bool, LoweringCancelled> {
    let mut found = false;
    try_walk_named_tree_preorder(body, true, |node| {
        if cancellation.is_cancelled() {
            return Err(LoweringCancelled);
        }
        if is_nested_execution_boundary(node) {
            return Ok(WalkControl::SkipChildren);
        }
        if is_target(node) {
            found = true;
            return Ok(WalkControl::Break);
        }
        Ok(WalkControl::Continue)
    })?;
    Ok(found)
}

/// Minimal adapter-owned view needed to relay lexical receiver demand through
/// nested lambdas without coupling shared lowering to language syntax.
#[doc(hidden)]
pub trait ReceiverCaptureSpec {
    fn lexical_parent(&self) -> Option<ProcedureId>;
    fn relays_receiver_capture(&self) -> bool;
    fn captures_receiver(&self) -> bool;
    fn captures_receiver_mut(&mut self) -> &mut bool;

    fn require_receiver_capture(&mut self) {
        *self.captures_receiver_mut() = true;
    }
}

/// Propagate receiver demand from lexical children to their immediate lambda
/// parents in one reverse pass.
///
/// Procedure enumeration publishes dense IDs in parent-before-child order.
/// Walking that order backwards means a demand copied to one parent is seen
/// when that parent is visited, so even deeply nested chains remain linear.
#[doc(hidden)]
pub fn relay_receiver_capture_demand<T: ReceiverCaptureSpec>(
    specs: &mut [T],
    cancellation: &CancellationToken,
) -> Result<(), LoweringCancelled> {
    for index in (0..specs.len()).rev() {
        if cancellation.is_cancelled() {
            return Err(LoweringCancelled);
        }
        if !specs[index].captures_receiver() {
            continue;
        }
        let Some(parent) = specs[index].lexical_parent() else {
            continue;
        };
        let parent_index = parent.index();
        assert!(
            parent_index < index,
            "lexical parent {parent} must precede child procedure index {index}"
        );
        if specs[parent_index].relays_receiver_capture() {
            specs[parent_index].require_receiver_capture();
        }
    }
    Ok(())
}

impl From<SemanticBudgetExceeded> for ProcedureLoweringError {
    fn from(error: SemanticBudgetExceeded) -> Self {
        Self::Budget(error, Box::default())
    }
}

#[doc(hidden)]
pub const fn completion_label(kind: CompletionKind) -> &'static str {
    match kind {
        CompletionKind::Normal => "normal",
        CompletionKind::Return => "return",
        CompletionKind::Throw => "throw",
        CompletionKind::Break => "break",
        CompletionKind::Continue => "continue",
        _ => "unsupported completion",
    }
}

/// Return the source slice represented by a tree-sitter node.
#[doc(hidden)]
pub fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    brokk_bifrost_core::analyzer::common::try_node_source_text(node, source)
}

/// [`node_text`] filtered to reject the empty string, so a name-bearing node
/// that spans zero bytes (or an out-of-range slice) is treated as absent.
/// Shared by every per-language semantic lowering module.
#[doc(hidden)]
pub fn nonempty_node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

#[doc(hidden)]
pub fn callable_name_with_binding(
    source: &str,
    node: Node<'_>,
    enclosing_binding: impl FnOnce() -> Option<Box<str>>,
) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(enclosing_binding)
}

/// Convert one tree-sitter node into the stable source anchor used throughout
/// the neutral semantic IR.
#[doc(hidden)]
pub fn source_anchor(node: Node<'_>, occurrence: u32) -> Result<SourceAnchor, String> {
    source_anchor_between_nodes(node, node, occurrence)
}

#[doc(hidden)]
pub fn source_anchor_between_nodes(
    start_node: Node<'_>,
    end_node: Node<'_>,
    occurrence: u32,
) -> Result<SourceAnchor, String> {
    source_anchor_from_positions(
        start_node.start_byte(),
        start_node.start_position(),
        end_node.end_byte(),
        end_node.end_position(),
        occurrence,
    )
}

#[doc(hidden)]
pub fn source_anchor_from_positions(
    start_byte: usize,
    start_position: tree_sitter::Point,
    end_byte: usize,
    end_position: tree_sitter::Point,
    occurrence: u32,
) -> Result<SourceAnchor, String> {
    let start = SourcePosition::new(
        u32::try_from(start_byte).map_err(|_| "source start exceeds u32")?,
        u32::try_from(start_position.row).map_err(|_| "source start line exceeds u32")?,
        u32::try_from(start_position.column).map_err(|_| "source start column exceeds u32")?,
    );
    let end = SourcePosition::new(
        u32::try_from(end_byte).map_err(|_| "source end exceeds u32")?,
        u32::try_from(end_position.row).map_err(|_| "source end line exceeds u32")?,
        u32::try_from(end_position.column).map_err(|_| "source end column exceeds u32")?,
    );
    let span = SourceSpan::new(start, end).map_err(|error| error.to_string())?;
    Ok(SourceAnchor::new(span, occurrence))
}

/// Translate syntax-level variadic classification into the neutral call-port
/// multiplicity used by semantic adapters.
#[doc(hidden)]
pub const fn formal_multiplicity(variadic: Option<FormalVariadicKind>) -> FormalMultiplicity {
    match variadic {
        None => FormalMultiplicity::One,
        Some(FormalVariadicKind::Positional) => {
            FormalMultiplicity::Rest(ArgumentDomain::Positional)
        }
        Some(FormalVariadicKind::Keyword) => FormalMultiplicity::Rest(ArgumentDomain::Keyword),
        Some(FormalVariadicKind::Both) => {
            FormalMultiplicity::Rest(ArgumentDomain::PositionalOrKeyword)
        }
    }
}

/// Lower an adapter-owned sequence of procedure specs with one consistent
/// staging, cancellation, and error-to-outcome policy.
#[doc(hidden)]
pub fn lower_procedure_batch<I, F>(
    items: I,
    initial_work: SemanticWork,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
    lower: F,
) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>
where
    I: IntoIterator,
    F: FnMut(
        I::Item,
        &SemanticBudget,
        &CancellationToken,
    ) -> Result<(ProcedureSemanticsParts, SemanticWork), ProcedureLoweringError>,
{
    lower_procedure_batch_with_prepass_work(
        items,
        initial_work,
        SemanticWork::default(),
        budget,
        cancellation,
        lower,
    )
}

/// Drive one adapter's opaque work items, seal detached source regions, and
/// freeze the completed procedure.
///
/// The adapter owns the work-item type and step function. This helper owns the
/// identical cancellation, budget, and finalization policy used after syntax
/// has already been classified.
#[doc(hidden)]
pub fn drive_and_finish_procedure<I, F>(
    mut builder: ProcedureCfgBuilder,
    initial: I,
    entry: ProgramPointId,
    normal_exit: ProgramPointId,
    exceptional_exit: ProgramPointId,
    cancellation: &CancellationToken,
    step: F,
) -> Result<(ProcedureSemanticsParts, SemanticWork), ProcedureLoweringError>
where
    I: IntoIterator,
    F: FnMut(
        &mut ProcedureCfgBuilder,
        I::Item,
        &mut Vec<I::Item>,
    ) -> Result<(), ProcedureLoweringError>,
{
    drive_procedure_work(&mut builder, initial, cancellation, step)?;
    finish_procedure(builder, entry, normal_exit, exceptional_exit, cancellation)
}

/// Drive adapter-owned work without freezing the procedure. An adapter uses
/// this split form when it must publish a synthetic effect only after the
/// completed control graph proves that effect reachable.
#[doc(hidden)]
pub fn drive_procedure_work<I, F>(
    builder: &mut ProcedureCfgBuilder,
    initial: I,
    cancellation: &CancellationToken,
    mut step: F,
) -> Result<(), ProcedureLoweringError>
where
    I: IntoIterator,
    F: FnMut(
        &mut ProcedureCfgBuilder,
        I::Item,
        &mut Vec<I::Item>,
    ) -> Result<(), ProcedureLoweringError>,
{
    for initial in initial {
        if let Err(error) =
            builder.drive_iteratively(initial, cancellation, |builder, work, stack| {
                step(builder, work, stack)
            })
        {
            let work = Box::new(builder.prospective_work());
            return match error {
                DriveError::Cancelled | DriveError::Step(ProcedureLoweringError::Cancelled(_)) => {
                    Err(ProcedureLoweringError::Cancelled(work))
                }
                DriveError::ExceededBudget(exceeded)
                | DriveError::Step(ProcedureLoweringError::Budget(exceeded, _)) => {
                    Err(ProcedureLoweringError::Budget(exceeded, work))
                }
                DriveError::Step(ProcedureLoweringError::Invalid(detail)) => {
                    Err(ProcedureLoweringError::Invalid(detail))
                }
            };
        }
    }

    Ok(())
}

/// Observe cancellation and record adapter traversal before retaining work
/// outside the executable CFG. Traversal is non-refusing work telemetry;
/// retained CFG rows remain subject to the builder's resident admissions.
#[doc(hidden)]
pub fn charge_lowering_traversal_step(
    builder: &mut ProcedureCfgBuilder,
    cancellation: &CancellationToken,
) -> Result<(), ProcedureLoweringError> {
    if cancellation.is_cancelled() {
        return Err(ProcedureLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    builder.descend_nested_entry();
    Ok(())
}

#[doc(hidden)]
pub enum DecompositionStep<T, S, B> {
    Boundary(B),
    Leaf { target: T, source: S },
}

#[doc(hidden)]
pub enum DecompositionExpansion<B> {
    Leaf,
    Children { boundary: Option<B> },
}

/// Immediate children, retained in source order only after caller work is charged.
#[doc(hidden)]
pub struct DecompositionChildren<T, S> {
    items: Vec<(T, S)>,
}

impl<T, S> DecompositionChildren<T, S> {
    pub fn push(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        cancellation: &CancellationToken,
        target: T,
        source: S,
    ) -> Result<(), ProcedureLoweringError> {
        charge_lowering_traversal_step(builder, cancellation)?;
        self.items.push((target, source));
        Ok(())
    }
}

/// Plan source-ordered decomposition without interpreting a language's patterns.
/// A boundary precedes its children; children are visited left to right. The
/// adapter owns component proof and must charge auxiliary enumeration before
/// allocation. Neither expansion nor planning evaluates the source expression.
#[doc(hidden)]
pub fn ordered_decomposition_steps<T: Copy, S: Copy, B>(
    builder: &mut ProcedureCfgBuilder,
    cancellation: &CancellationToken,
    target: T,
    source: S,
    mut expand: impl FnMut(
        &mut ProcedureCfgBuilder,
        T,
        S,
        &mut DecompositionChildren<T, S>,
    ) -> Result<DecompositionExpansion<B>, ProcedureLoweringError>,
) -> Result<Vec<DecompositionStep<T, S, B>>, ProcedureLoweringError> {
    charge_lowering_traversal_step(builder, cancellation)?;
    let mut steps = Vec::new();
    drive_procedure_work(
        builder,
        [(target, source)],
        cancellation,
        |builder, (target, source), pending| {
            charge_lowering_traversal_step(builder, cancellation)?;
            let mut children = DecompositionChildren { items: Vec::new() };
            match expand(builder, target, source, &mut children)? {
                DecompositionExpansion::Leaf => {
                    assert!(
                        children.items.is_empty(),
                        "a decomposition leaf has no children"
                    );
                    charge_lowering_traversal_step(builder, cancellation)?;
                    steps.push(DecompositionStep::Leaf { target, source });
                }
                DecompositionExpansion::Children { boundary } => {
                    if let Some(boundary) = boundary {
                        charge_lowering_traversal_step(builder, cancellation)?;
                        steps.push(DecompositionStep::Boundary(boundary));
                    }
                    for child in children.items.into_iter().rev() {
                        charge_lowering_traversal_step(builder, cancellation)?;
                        pending.push(child);
                    }
                }
            }
            Ok(())
        },
    )?;
    charge_lowering_traversal_step(builder, cancellation)?;
    Ok(steps)
}

/// Seal detached control regions and freeze a procedure whose adapter work is
/// complete.
pub(crate) fn finish_procedure(
    mut builder: ProcedureCfgBuilder,
    entry: ProgramPointId,
    normal_exit: ProgramPointId,
    exceptional_exit: ProgramPointId,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), ProcedureLoweringError> {
    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(ProcedureLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| ProcedureLoweringError::Budget(error, Box::new(work_before_freeze)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct PointMetadata {
    #[doc(hidden)]
    pub source: SourceMappingId,
    #[doc(hidden)]
    pub evidence: EvidenceId,
}

/// One already-classified control-flow destination.
///
/// Language adapters decide which syntax owns the destination and which edge
/// kind applies. This shared value only carries that syntax-free decision
/// through their iterative work queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct ControlTarget {
    #[doc(hidden)]
    pub point: ProgramPointId,
    #[doc(hidden)]
    pub kind: ControlEdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct AwaitScaffold {
    #[doc(hidden)]
    pub suspend: ProgramPointId,
    #[doc(hidden)]
    pub normal_resume: ProgramPointId,
    #[doc(hidden)]
    pub exceptional_resume: ProgramPointId,
    #[doc(hidden)]
    pub awaited: ValueId,
    #[doc(hidden)]
    pub result: ValueId,
}

pub(crate) type ScheduledControlNode<T> = (T, ProgramPointId);

/// Push the three opaque work items for a conditional choice in execution
/// order: evaluate the condition first, then only the selected arm.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn schedule_conditional_choice<T, W>(
    stack: &mut Vec<W>,
    condition: ScheduledControlNode<T>,
    consequence: ScheduledControlNode<T>,
    alternative: ScheduledControlNode<T>,
    when_true: ControlTarget,
    when_false: ControlTarget,
    scope: ScopeFrameId,
    work: impl Fn(T, ProgramPointId, ControlTarget, ControlTarget, ScopeFrameId) -> W,
) where
    T: Copy,
{
    stack.push(work(
        alternative.0,
        alternative.1,
        when_true,
        when_false,
        scope,
    ));
    stack.push(work(
        consequence.0,
        consequence.1,
        when_true,
        when_false,
        scope,
    ));
    stack.push(work(
        condition.0,
        condition.1,
        ControlTarget {
            point: consequence.1,
            kind: ControlEdgeKind::ConditionalTrue,
        },
        ControlTarget {
            point: alternative.1,
            kind: ControlEdgeKind::ConditionalFalse,
        },
        scope,
    ));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ShortCircuitKind {
    And,
    Or,
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct CleanupSpecialization<R> {
    #[doc(hidden)]
    pub region: R,
    #[doc(hidden)]
    pub entry: ProgramPointId,
    #[doc(hidden)]
    pub next: ControlTarget,
}

#[allow(dead_code)] // Returned to the dependent Rust producer in Lane C.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct CleanupActionSpecialization {
    #[doc(hidden)]
    pub action: ScopeCleanupAction,
    #[doc(hidden)]
    pub entry: ProgramPointId,
    #[doc(hidden)]
    pub next: ControlTarget,
}

#[allow(dead_code)] // Returned to the dependent Rust producer in Lane C.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum CleanupRouteStep<R> {
    Region(CleanupSpecialization<R>),
    Action(Box<CleanupActionSpecialization>),
}

#[doc(hidden)]
pub struct CleanupRoutePlanner<'route> {
    route: &'route CompletionRoute,
    next_index: usize,
    next_operation_index: usize,
    #[doc(hidden)]
    pub next: ControlTarget,
}

impl<'route> CleanupRoutePlanner<'route> {
    #[doc(hidden)]
    pub fn new(route: &'route CompletionRoute) -> Self {
        Self {
            route,
            next_index: route.cleanups().len(),
            next_operation_index: route.operations().len(),
            next: ControlTarget {
                point: route.destination().target(),
                kind: route.destination().edge_kind(),
            },
        }
    }

    /// Advance through reused entries and return the next newly allocated step.
    ///
    /// Yielding one step at a time lets the adapter finish its relay, body, or
    /// gaps before the outer cleanup is allocated, preserving deterministic
    /// point order and tight-budget outcomes.
    #[doc(hidden)]
    pub fn next<'tree, R>(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        session: &mut ProcedureLoweringSession<'_>,
        regions: &[R],
        region_id: impl Fn(R) -> CleanupRegionId,
        source_node: impl Fn(R) -> Node<'tree>,
    ) -> Result<Option<CleanupSpecialization<R>>, ProcedureLoweringError>
    where
        R: Copy,
    {
        self.next_with_lookup(
            builder,
            session,
            |expected| {
                regions
                    .iter()
                    .copied()
                    .find(|region| region_id(*region) == expected)
            },
            source_node,
        )
    }

    /// Advance using an adapter-owned cleanup lookup.
    ///
    /// Adapters whose cleanup IDs index dense storage can avoid repeatedly
    /// scanning all registered regions as continuation histories specialize.
    #[doc(hidden)]
    pub fn next_with_lookup<'tree, R>(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        session: &mut ProcedureLoweringSession<'_>,
        mut lookup_region: impl FnMut(CleanupRegionId) -> Option<R>,
        source_node: impl Fn(R) -> Node<'tree>,
    ) -> Result<Option<CleanupSpecialization<R>>, ProcedureLoweringError>
    where
        R: Copy,
    {
        assert!(
            self.route
                .operations()
                .iter()
                .all(|operation| matches!(operation, CleanupRouteOperation::Region { .. })),
            "routes with lifecycle actions must use next_step_with_lookup"
        );
        while self.next_index > 0 {
            self.next_index -= 1;
            let index = self.next_index;
            self.next_operation_index -= 1;
            assert!(matches!(
                self.route.operations()[self.next_operation_index],
                CleanupRouteOperation::Region { cleanup_index, .. } if cleanup_index == index
            ));
            let expected = self.route.cleanups()[index];
            let region = lookup_region(expected)
                .ok_or_else(|| ProcedureLoweringError::Invalid("missing cleanup region".into()))?;
            let (entry, step) =
                if let Some(entry) = builder.cleanup_specialization_entry(self.route, index) {
                    (entry, None)
                } else {
                    let metadata = session.add_node_mapping(builder, source_node(region))?;
                    let (entry, created) = builder.cleanup_specialization(
                        self.route,
                        index,
                        metadata.source,
                        metadata.evidence,
                    )?;
                    debug_assert!(created, "cleanup lookup and allocation must agree");
                    session.register_point(
                        entry,
                        metadata,
                        "cleanup specialization broke dense point allocation",
                    )?;
                    (
                        entry,
                        Some(CleanupSpecialization {
                            region,
                            entry,
                            next: self.next,
                        }),
                    )
                };
            self.next = ControlTarget {
                point: entry,
                kind: ControlEdgeKind::Cleanup,
            };
            if step.is_some() {
                return Ok(step);
            }
        }
        Ok(None)
    }

    /// Advance through the route's mixed action and cleanup-region sequence.
    ///
    /// Operations are returned from the outer continuation toward the inner
    /// entry, matching the existing region planner's allocation order. The
    /// caller completes each returned action or cleanup body before asking
    /// for another step so point allocation remains deterministic.
    #[allow(dead_code)] // Lane C consumes this planner entry point.
    #[doc(hidden)]
    pub fn next_step_with_lookup<'tree, R>(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        session: &mut ProcedureLoweringSession<'_>,
        mut lookup_region: impl FnMut(CleanupRegionId) -> Option<R>,
        source_node: impl Fn(R) -> Node<'tree>,
    ) -> Result<Option<CleanupRouteStep<R>>, ProcedureLoweringError>
    where
        R: Copy,
    {
        while self.next_operation_index > 0 {
            self.next_operation_index -= 1;
            match self.route.operations()[self.next_operation_index].clone() {
                CleanupRouteOperation::Action(action) => {
                    let metadata = PointMetadata {
                        source: action.source(),
                        evidence: action.evidence(),
                    };
                    let entry = session.add_point(builder, metadata, Vec::new())?;
                    builder.emit_cleanup_action_fact(entry, &action)?;
                    let next = self.next;
                    self.next = ControlTarget {
                        point: entry,
                        kind: ControlEdgeKind::Cleanup,
                    };
                    return Ok(Some(CleanupRouteStep::Action(Box::new(
                        CleanupActionSpecialization {
                            action,
                            entry,
                            next,
                        },
                    ))));
                }
                CleanupRouteOperation::Region {
                    cleanup_index,
                    region: expected,
                } => {
                    assert_eq!(self.next_index.checked_sub(1), Some(cleanup_index));
                    self.next_index -= 1;
                    let region = lookup_region(expected).ok_or_else(|| {
                        ProcedureLoweringError::Invalid("missing cleanup region".into())
                    })?;
                    let (entry, step) = if let Some(entry) =
                        builder.cleanup_specialization_entry(self.route, cleanup_index)
                    {
                        (entry, None)
                    } else {
                        let metadata = session.add_node_mapping(builder, source_node(region))?;
                        let (entry, created) = builder.cleanup_specialization(
                            self.route,
                            cleanup_index,
                            metadata.source,
                            metadata.evidence,
                        )?;
                        debug_assert!(created, "cleanup lookup and allocation must agree");
                        session.register_point(
                            entry,
                            metadata,
                            "cleanup specialization broke dense point allocation",
                        )?;
                        (
                            entry,
                            Some(CleanupSpecialization {
                                region,
                                entry,
                                next: self.next,
                            }),
                        )
                    };
                    self.next = ControlTarget {
                        point: entry,
                        kind: ControlEdgeKind::Cleanup,
                    };
                    if let Some(step) = step {
                        return Ok(Some(CleanupRouteStep::Region(step)));
                    }
                }
            }
        }
        Ok(None)
    }

    #[doc(hidden)]
    pub fn target(&self) -> ControlTarget {
        debug_assert_eq!(self.next_index, 0, "cleanup region planning is incomplete");
        debug_assert_eq!(
            self.next_operation_index, 0,
            "cleanup action planning is incomplete"
        );
        self.next
    }
}

/// Publish cleanup actions on the real completion point and preserve the
/// route's original control edge. Adapters use this when cleanup is represented
/// as lifecycle facts rather than executable ICFG calls.
#[doc(hidden)]
pub fn emit_cleanup_completion_route(
    builder: &mut ProcedureCfgBuilder,
    session: &mut ProcedureLoweringSession<'_>,
    from: ProgramPointId,
    route: &CompletionRoute,
) -> Result<(), ProcedureLoweringError> {
    for operation in route.operations() {
        if let CleanupRouteOperation::Action(action) = operation {
            builder.emit_cleanup_action_fact(from, action)?;
        }
    }
    let destination = route.destination();
    session.add_target_edge(
        builder,
        from,
        ControlTarget {
            point: destination.target(),
            kind: destination.edge_kind(),
        },
    )
}

/// Schedule a boolean short-circuit pair after the adapter has identified its
/// operands and allocated the right-hand entry.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn schedule_short_circuit_condition<T, W>(
    stack: &mut Vec<W>,
    kind: ShortCircuitKind,
    left: ScheduledControlNode<T>,
    right: ScheduledControlNode<T>,
    when_true: ControlTarget,
    when_false: ControlTarget,
    scope: ScopeFrameId,
    work: impl Fn(T, ProgramPointId, ControlTarget, ControlTarget, ScopeFrameId) -> W,
) where
    T: Copy,
{
    stack.push(work(right.0, right.1, when_true, when_false, scope));
    let (left_true, left_false) = match kind {
        ShortCircuitKind::And => (
            ControlTarget {
                point: right.1,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false,
        ),
        ShortCircuitKind::Or => (
            when_true,
            ControlTarget {
                point: right.1,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        ),
    };
    stack.push(work(left.0, left.1, left_true, left_false, scope));
}

impl ControlTarget {
    #[doc(hidden)]
    pub const fn normal(point: ProgramPointId) -> Self {
        Self {
            point,
            kind: ControlEdgeKind::Normal,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub enum ProcedureWork<'tree> {
    Statement {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: ControlTarget,
        scope: ScopeFrameId,
    },
    Expression {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: ControlTarget,
        scope: ScopeFrameId,
    },
    Condition {
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: ControlTarget,
        when_false: ControlTarget,
        scope: ScopeFrameId,
    },
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct ConditionTargets {
    #[doc(hidden)]
    pub when_true: ControlTarget,
    #[doc(hidden)]
    pub when_false: ControlTarget,
}

#[doc(hidden)]
pub trait ProcedureWorkHandler<'tree> {
    fn cancellation_token(&self) -> &CancellationToken;
    fn lower_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: ControlTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<ProcedureWork<'tree>>,
    ) -> Result<(), ProcedureLoweringError>;
    fn lower_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: ControlTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<ProcedureWork<'tree>>,
    ) -> Result<(), ProcedureLoweringError>;
    fn lower_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        targets: ConditionTargets,
        scope: ScopeFrameId,
        stack: &mut Vec<ProcedureWork<'tree>>,
    ) -> Result<(), ProcedureLoweringError>;
}

#[doc(hidden)]
pub fn dispatch_procedure_work<'tree, H: ProcedureWorkHandler<'tree>>(
    handler: &mut H,
    builder: &mut ProcedureCfgBuilder,
    work: ProcedureWork<'tree>,
    stack: &mut Vec<ProcedureWork<'tree>>,
) -> Result<(), ProcedureLoweringError> {
    if handler.cancellation_token().is_cancelled() {
        return Err(ProcedureLoweringError::Cancelled(Box::default()));
    }
    match work {
        ProcedureWork::Statement {
            node,
            entry,
            next,
            scope,
        } => handler.lower_statement(builder, node, entry, next, scope, stack),
        ProcedureWork::Expression {
            node,
            entry,
            next,
            scope,
        } => handler.lower_expression(builder, node, entry, next, scope, stack),
        ProcedureWork::Condition {
            node,
            entry,
            when_true,
            when_false,
            scope,
        } => handler.lower_condition(
            builder,
            node,
            entry,
            ConditionTargets {
                when_true,
                when_false,
            },
            scope,
            stack,
        ),
    }
}

#[doc(hidden)]
pub fn conditional_false_target(
    next_condition: Option<ProgramPointId>,
    alternative: Option<ProgramPointId>,
    next: ControlTarget,
) -> ControlTarget {
    next_condition
        .or(alternative)
        .map(|point| ControlTarget {
            point,
            kind: ControlEdgeKind::ConditionalFalse,
        })
        .unwrap_or(ControlTarget {
            point: next.point,
            kind: ControlEdgeKind::ConditionalFalse,
        })
}

/// Push a linear child sequence in reverse order, linking each child to the
/// next entry while preserving the caller's work-item type.
#[doc(hidden)]
pub fn schedule_sequential_work<T, W>(
    stack: &mut Vec<W>,
    children: &[T],
    entries: &[ProgramPointId],
    next: ControlTarget,
    scope: ScopeFrameId,
    mut work: impl FnMut(usize, T, ProgramPointId, ControlTarget, ScopeFrameId) -> W,
) where
    T: Copy,
{
    debug_assert_eq!(children.len(), entries.len());
    for index in (0..children.len()).rev() {
        let child_next = entries
            .get(index + 1)
            .copied()
            .map(ControlTarget::normal)
            .unwrap_or(next);
        stack.push(work(
            index,
            children[index],
            entries[index],
            child_next,
            scope,
        ));
    }
}

/// Schedule a linear sequence whose active cleanup scope changes after
/// individual children, as for bindings initialized by sequential statements.
#[doc(hidden)]
pub fn schedule_sequential_work_with_scopes<T, W>(
    stack: &mut Vec<W>,
    children: &[T],
    entries: &[ProgramPointId],
    next: ControlTarget,
    scopes: &[ScopeFrameId],
    mut work: impl FnMut(usize, T, ProgramPointId, ControlTarget, ScopeFrameId) -> W,
) where
    T: Copy,
{
    debug_assert_eq!(children.len(), entries.len());
    debug_assert_eq!(children.len(), scopes.len());
    for index in (0..children.len()).rev() {
        let child_next = entries
            .get(index + 1)
            .copied()
            .map(ControlTarget::normal)
            .unwrap_or(next);
        stack.push(work(
            index,
            children[index],
            entries[index],
            child_next,
            scopes[index],
        ));
    }
}

/// Schedule shared loop control flow after an adapter identifies and allocates
/// every syntax node.
///
/// The adapter supplies opaque payloads and constructors for its work-item
/// enum. This function owns only scope targets, edge kinds, and reverse stack
/// ordering.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn schedule_loop_flow<T, W, Initializer, Expression, Statement, Condition>(
    builder: &mut ProcedureCfgBuilder,
    session: &ProcedureLoweringSession<'_>,
    entry: ProgramPointId,
    next: ControlTarget,
    parent_scope: ScopeFrameId,
    label: Option<Box<str>>,
    initializers: &[ScheduledControlNode<T>],
    condition: Option<ScheduledControlNode<T>>,
    condition_entry: ProgramPointId,
    initial_condition_target: ControlTarget,
    body: ScheduledControlNode<T>,
    updates: &[ScheduledControlNode<T>],
    stack: &mut Vec<W>,
    initializer_work: Initializer,
    expression_work: Expression,
    statement_work: Statement,
    condition_work: Condition,
) -> Result<ScopeFrameId, ProcedureLoweringError>
where
    T: Copy,
    Initializer: Fn(T, ProgramPointId, ControlTarget, ScopeFrameId) -> W,
    Expression: Fn(T, ProgramPointId, ControlTarget, ScopeFrameId) -> W,
    Statement: Fn(T, ProgramPointId, ControlTarget, ScopeFrameId) -> W,
    Condition: Fn(T, ProgramPointId, ControlTarget, ControlTarget, ScopeFrameId) -> W,
{
    let continue_target = updates.first().map_or(condition_entry, |update| update.1);
    let loop_scope = builder.push_scope(
        Some(parent_scope),
        ScopeBinding::Loop {
            label,
            break_target: next.point,
            break_edge_kind: next.kind,
            continue_target,
            continue_edge_kind: if updates.is_empty() {
                ControlEdgeKind::LoopBack
            } else {
                ControlEdgeKind::Normal
            },
        },
    );

    for (index, update) in updates.iter().enumerate().rev() {
        let next = updates
            .get(index + 1)
            .map(|next| ControlTarget::normal(next.1))
            .unwrap_or(ControlTarget {
                point: condition_entry,
                kind: ControlEdgeKind::LoopBack,
            });
        stack.push(expression_work(update.0, update.1, next, loop_scope));
    }
    stack.push(statement_work(
        body.0,
        body.1,
        ControlTarget {
            point: continue_target,
            kind: if updates.is_empty() {
                ControlEdgeKind::LoopBack
            } else {
                ControlEdgeKind::Normal
            },
        },
        loop_scope,
    ));
    if let Some(condition) = condition {
        stack.push(condition_work(
            condition.0,
            condition.1,
            ControlTarget {
                point: body.1,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            ControlTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            loop_scope,
        ));
    } else {
        session.add_edge(builder, condition_entry, body.1, ControlEdgeKind::Normal)?;
    }

    if let Some(first) = initializers.first() {
        // A caller may reuse the loop entry as the first initializer entry.
        if entry != first.1 {
            session.add_edge(builder, entry, first.1, ControlEdgeKind::Normal)?;
        }
        for (index, initializer) in initializers.iter().enumerate().rev() {
            let next = initializers
                .get(index + 1)
                .map_or(initial_condition_target.point, |next| next.1);
            stack.push(initializer_work(
                initializer.0,
                initializer.1,
                ControlTarget::normal(next),
                loop_scope,
            ));
        }
    } else if entry != initial_condition_target.point {
        session.add_edge(
            builder,
            entry,
            initial_condition_target.point,
            initial_condition_target.kind,
        )?;
    }
    Ok(loop_scope)
}

/// Target-local slot reserved for the lexical receiver capture, when present.
///
/// Parent capture rows are emitted before their child procedure is lowered, so
/// both sides use this planned destination. The child-side helper below checks
/// the dense allocation rather than relying on an adapter-local magic ID.
#[doc(hidden)]
pub const RECEIVER_CAPTURE_DESTINATION: MemoryLocationId = MemoryLocationId::new(0);

/// Adapter-supplied values needed to publish one ordinary call row and its
/// matched continuation events. Syntax evaluation and control edges remain
/// adapter-owned.
#[doc(hidden)]
pub struct CallSiteScaffold {
    #[doc(hidden)]
    pub point: ProgramPointId,
    #[doc(hidden)]
    pub callee: ValueId,
    #[doc(hidden)]
    pub receiver: Option<ValueId>,
    #[doc(hidden)]
    pub arguments: Box<[SemanticCallArgument]>,
    #[doc(hidden)]
    pub normal_results: Box<[ValueId]>,
    #[doc(hidden)]
    pub result: Option<ValueId>,
    #[doc(hidden)]
    pub thrown: Option<ValueId>,
    #[doc(hidden)]
    pub declared_targets: CallableTargetResolution,
    #[doc(hidden)]
    pub normal_continuation: ProgramPointId,
    #[doc(hidden)]
    pub exceptional_continuation: ProgramPointId,
}

/// Adapter-supplied values for an ordinary call whose declaration proves that
/// it cannot return normally. The exceptional continuation remains explicit;
/// the missing normal arm is part of the published call contract.
#[doc(hidden)]
pub struct DivergingCallSiteScaffold {
    #[doc(hidden)]
    pub point: ProgramPointId,
    #[doc(hidden)]
    pub callee: ValueId,
    #[doc(hidden)]
    pub receiver: Option<ValueId>,
    #[doc(hidden)]
    pub arguments: Box<[SemanticCallArgument]>,
    #[doc(hidden)]
    pub result: Option<ValueId>,
    #[doc(hidden)]
    pub thrown: Option<ValueId>,
    #[doc(hidden)]
    pub declared_targets: CallableTargetResolution,
    #[doc(hidden)]
    pub exceptional_continuation: ProgramPointId,
}

/// Adapter-supplied values for a call whose work starts in another task while
/// the registering procedure continues normally. The spawned work has no
/// exceptional continuation in its registering procedure.
#[doc(hidden)]
pub struct SpawnedCallSiteScaffold {
    #[doc(hidden)]
    pub point: ProgramPointId,
    #[doc(hidden)]
    pub callee: ValueId,
    #[doc(hidden)]
    pub receiver: Option<ValueId>,
    #[doc(hidden)]
    pub arguments: Box<[SemanticCallArgument]>,
    #[doc(hidden)]
    pub declared_targets: CallableTargetResolution,
    #[doc(hidden)]
    pub normal_continuation: ProgramPointId,
}

/// Adapter-supplied structure for one normalized switch fact. Source and
/// evidence metadata remain owned by the lowering session at `point`.
#[doc(hidden)]
pub struct SwitchFactScaffold {
    #[doc(hidden)]
    pub point: ProgramPointId,
    #[doc(hidden)]
    pub kind: SwitchFactKind,
    #[doc(hidden)]
    pub selector: Option<ValueId>,
    #[doc(hidden)]
    pub selector_domain: SwitchSelectorDomain,
    #[doc(hidden)]
    pub cases: Vec<SwitchCaseFactParts>,
    #[doc(hidden)]
    pub default_edge: Option<SwitchEdgeParts>,
    #[doc(hidden)]
    pub default_present: bool,
}

#[doc(hidden)]
pub struct ProcedureLoweringStart<'a> {
    #[doc(hidden)]
    pub builder: ProcedureCfgBuilder,
    #[doc(hidden)]
    pub session: ProcedureLoweringSession<'a>,
    #[doc(hidden)]
    pub entry: ProgramPointId,
    #[doc(hidden)]
    pub normal_exit: ProgramPointId,
    #[doc(hidden)]
    pub exceptional_exit: ProgramPointId,
    #[doc(hidden)]
    pub function_scope: ScopeFrameId,
}

#[doc(hidden)]
pub fn copy_scope_frames<T: Clone>(
    frames: &HashMap<ScopeFrameId, Box<[T]>>,
    parent: ScopeFrameId,
) -> Box<[T]> {
    frames.get(&parent).cloned().unwrap_or_default()
}

#[doc(hidden)]
pub fn extend_scope_frames<T: Clone>(
    frames: &HashMap<ScopeFrameId, Box<[T]>>,
    parent: ScopeFrameId,
    frame: T,
) -> Box<[T]> {
    let mut child_frames = copy_scope_frames(frames, parent).into_vec();
    child_frames.push(frame);
    child_frames.into_boxed_slice()
}

/// Source-anchor-aware emission state shared by every language adapter.
#[doc(hidden)]
pub struct ProcedureLoweringSession<'a> {
    #[doc(hidden)]
    pub locator: SemanticLocator,
    #[doc(hidden)]
    pub point_metadata: Vec<PointMetadata>,
    next_source: usize,
    next_evidence: usize,
    next_value: usize,
    next_allocation: usize,
    next_memory_location: usize,
    next_capture: usize,
    next_call_site: usize,
    next_gap: usize,
    next_guard: usize,
    next_switch_fact: usize,
    source_occurrences: HashMap<(usize, usize), u32>,
    #[doc(hidden)]
    pub cancellation: &'a CancellationToken,
}

impl<'a> ProcedureLoweringSession<'a> {
    /// Seed the exact procedure provenance, entry/exit points, and function
    /// completion scope used by every production adapter.
    #[doc(hidden)]
    pub fn start(
        parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
    ) -> Result<ProcedureLoweringStart<'a>, SemanticBudgetExceeded> {
        Self::start_with_function_throw_boundary(parts, budget, cancellation, false)
            .map(|(start, _)| start)
    }

    /// Seed ordinary boundaries while keeping the procedure identity locator
    /// separate from the exact callable locator used by its base source
    /// mapping. A language needs this when declaration identity deliberately
    /// uses a prefix or other stable anchor but source proofs need the full
    /// callable node.
    #[doc(hidden)]
    pub fn start_with_source_locator(
        parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
        source_locator: SemanticLocator,
    ) -> Result<ProcedureLoweringStart<'a>, SemanticBudgetExceeded> {
        Self::start_with_function_throw_boundary_and_source_locator(
            parts,
            budget,
            cancellation,
            false,
            Some(source_locator),
        )
        .map(|(start, _)| start)
    }

    /// Seed ordinary boundaries while optionally routing function-level throws
    /// to a distinct, adapter-owned terminal point. This preserves the common
    /// setup for languages whose procedure contract has a second exceptional
    /// terminal, such as unconditional C++ `noexcept` termination.
    #[doc(hidden)]
    pub fn start_with_function_throw_boundary(
        parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
        separate_throw_boundary: bool,
    ) -> Result<(ProcedureLoweringStart<'a>, Option<ProgramPointId>), SemanticBudgetExceeded> {
        Self::start_with_function_throw_boundary_and_source_locator(
            parts,
            budget,
            cancellation,
            separate_throw_boundary,
            None,
        )
    }

    fn start_with_function_throw_boundary_and_source_locator(
        mut parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
        separate_throw_boundary: bool,
        source_locator: Option<SemanticLocator>,
    ) -> Result<(ProcedureLoweringStart<'a>, Option<ProgramPointId>), SemanticBudgetExceeded> {
        assert!(
            parts.source_mappings.is_empty() && parts.evidence_rows.is_empty(),
            "procedure lowering session requires fresh provenance tables"
        );
        assert_eq!(parts.source.index(), 0, "base source mapping must be dense");
        assert_eq!(parts.evidence.index(), 0, "base evidence row must be dense");

        let locator = parts.locator.clone();
        let base_source = parts.source;
        let base_evidence = parts.evidence;
        parts.source_mappings.push(SourceMapping {
            id: base_source,
            locator: locator.clone(),
            kind: SourceMappingKind::Exact,
            ast_identity: None,
        });
        parts.evidence_rows.push(Evidence {
            id: base_evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([base_source]),
        });

        // Keep the procedure's declaration locator as the base source used by
        // ordinary semantic points. Some adapters deliberately use a stable
        // declaration anchor there for identity and navigation, while source
        // backed joins need a second mapping for the exact callable node.
        if let Some(source_locator) = source_locator {
            let source = SourceMappingId::try_from_index(parts.source_mappings.len())
                .expect("the exact callable source mapping id is bounded");
            let evidence = EvidenceId::try_from_index(parts.evidence_rows.len())
                .expect("the exact callable evidence id is bounded");
            parts.source_mappings.push(SourceMapping {
                id: source,
                locator: source_locator,
                kind: SourceMappingKind::Exact,
                ast_identity: None,
            });
            parts.evidence_rows.push(Evidence {
                id: evidence,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                sources: Box::new([source]),
            });
        }

        let next_source = parts.source_mappings.len();
        let next_evidence = parts.evidence_rows.len();

        let mut builder = ProcedureCfgBuilder::new(parts, budget)?;
        let entry = builder.add_point(
            vec![SemanticEvent::new(
                SemanticEffect::Entry,
                base_source,
                base_evidence,
            )],
            base_source,
            base_evidence,
        )?;
        let normal_exit = builder.add_point(
            vec![SemanticEvent::new(
                SemanticEffect::NormalExit,
                base_source,
                base_evidence,
            )],
            base_source,
            base_evidence,
        )?;
        let exceptional_exit = builder.add_point(
            vec![SemanticEvent::new(
                SemanticEffect::ExceptionalExit,
                base_source,
                base_evidence,
            )],
            base_source,
            base_evidence,
        )?;
        let separate_throw_target = separate_throw_boundary
            .then(|| builder.add_point(Vec::new(), base_source, base_evidence))
            .transpose()?;
        let function_scope = builder.push_scope(
            None,
            ScopeBinding::Function {
                return_target: normal_exit,
                throw_target: separate_throw_target.unwrap_or(exceptional_exit),
            },
        );
        let metadata = PointMetadata {
            source: base_source,
            evidence: base_evidence,
        };
        let session = Self {
            locator,
            point_metadata: vec![metadata; 3 + usize::from(separate_throw_target.is_some())],
            next_source,
            next_evidence,
            next_value: 0,
            next_allocation: 0,
            next_memory_location: 0,
            next_capture: 0,
            next_call_site: 0,
            next_gap: 0,
            next_guard: 0,
            next_switch_fact: 0,
            source_occurrences: HashMap::default(),
            cancellation,
        };
        Ok((
            ProcedureLoweringStart {
                builder,
                session,
                entry,
                normal_exit,
                exceptional_exit,
                function_scope,
            },
            separate_throw_target,
        ))
    }

    #[doc(hidden)]
    pub const fn cancellation(&self) -> &'a CancellationToken {
        self.cancellation
    }

    #[doc(hidden)]
    pub const fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    /// Return the next deterministic occurrence for an adapter-selected byte
    /// span. The adapter remains responsible for constructing the anchor.
    #[doc(hidden)]
    pub fn next_source_occurrence(&mut self, start: usize, end: usize) -> u32 {
        let occurrence = self.source_occurrences.entry((start, end)).or_default();
        let current = *occurrence;
        *occurrence = occurrence
            .checked_add(1)
            .expect("one source span cannot have more than u32::MAX semantic occurrences");
        current
    }

    #[doc(hidden)]
    pub fn add_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        anchor: SourceAnchor,
        kind: SourceMappingKind,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        self.add_mapping_with_ast_identity(builder, anchor, kind, None)
    }

    /// Add a source mapping with an exact producer-authored structural fact
    /// identity when the adapter has one for the same source snapshot.
    #[doc(hidden)]
    pub fn add_mapping_with_ast_identity(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        anchor: SourceAnchor,
        kind: SourceMappingKind,
        ast_identity: Option<StructuralNodeIdentity>,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        let source = SourceMappingId::try_from_index(self.next_source)
            .map_err(|_| ProcedureLoweringError::Invalid("too many source mappings".into()))?;
        let evidence = EvidenceId::try_from_index(self.next_evidence)
            .map_err(|_| ProcedureLoweringError::Invalid("too many evidence rows".into()))?;
        let locator = SemanticLocator::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            self.locator.declaration().clone(),
            SemanticRole::ProgramPoint,
            anchor,
        );
        builder.add_source_mapping(SourceMapping {
            id: source,
            locator,
            kind,
            ast_identity,
        })?;
        builder.add_evidence(Evidence {
            id: evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([source]),
        })?;
        self.next_source += 1;
        self.next_evidence += 1;
        Ok(PointMetadata { source, evidence })
    }

    #[doc(hidden)]
    pub fn add_node_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        let range = node.byte_range();
        let occurrence = self.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(ProcedureLoweringError::Invalid)?;
        self.add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    /// Add a synthetic cleanup mapping at the exact source range of its owner.
    ///
    /// The exact range keeps cleanup points selectable by their owning scope
    /// while preserving the selector behavior of ordinary node-backed points.
    pub(crate) fn add_cleanup_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        let range = node.byte_range();
        let occurrence = self.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(ProcedureLoweringError::Invalid)?;
        self.add_mapping(builder, anchor, SourceMappingKind::Synthetic)
    }

    /// Add a source-backed synthetic point at the end of a cleanup scope.
    #[doc(hidden)]
    pub fn add_cleanup_boundary_point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
    ) -> Result<ProgramPointId, ProcedureLoweringError> {
        let metadata = self.add_cleanup_mapping(builder, node)?;
        self.add_point(builder, metadata, Vec::new())
    }

    /// Map a value node to its source span using the adapters' shared exact
    /// value-mapping policy. Adapters with AST identities or occurrence
    /// tracking keep selecting those policies at their call sites.
    #[doc(hidden)]
    pub fn add_value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        let anchor = source_anchor(node, 0).map_err(ProcedureLoweringError::Invalid)?;
        self.add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    #[doc(hidden)]
    pub fn add_node_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ProcedureLoweringError> {
        let metadata = self.add_value_mapping(builder, node)?;
        self.add_value_with_metadata(builder, metadata, kind)
    }

    /// Map one syntax node and add the program point that carries its effects.
    #[doc(hidden)]
    pub fn add_node_point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, ProcedureLoweringError> {
        let metadata = self.add_node_mapping(builder, node)?;
        self.add_point(builder, metadata, effects)
    }

    #[doc(hidden)]
    pub fn cleanup_next_target(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'_>,
        next: ControlTarget,
    ) -> Result<ControlTarget, ProcedureLoweringError> {
        if next.kind == ControlEdgeKind::Normal {
            return Ok(next);
        }
        let relay = self.add_node_point(builder, body, Vec::new())?;
        self.add_target_edge(builder, relay, next)?;
        Ok(ControlTarget::normal(relay))
    }

    /// Attest that lowering enters the source statement `node` at `entry`.
    ///
    /// The entry point normally carries the statement's own exact mapping. A
    /// loop body can instead enter at its loop's point, and cleanup can
    /// specialize one statement for several completion paths; in those cases a
    /// fresh exact mapping for the statement keeps its source identity. The
    /// producer, not a range search, attests the entry.
    #[doc(hidden)]
    pub fn record_statement_entry(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
        entry: ProgramPointId,
    ) -> Result<(), ProcedureLoweringError> {
        let point_metadata = self.metadata(entry)?;
        let mapping = builder.source_mapping(point_metadata.source);
        let span = mapping.locator.anchor().span();
        let source = if mapping.kind == SourceMappingKind::Exact
            && span.start_byte() as usize == node.start_byte()
            && span.end_byte() as usize == node.end_byte()
        {
            point_metadata
        } else {
            self.add_node_mapping(builder, node)?
        };
        builder.add_statement_entry(StatementEntrySite {
            source: source.source,
            evidence: source.evidence,
            point: entry,
        })?;
        Ok(())
    }

    /// Attest one source loop: `header` is the point each new iteration
    /// re-enters and `body` is the body's entry. The mapping names the loop
    /// statement itself, since its entry point can be shared with a label.
    #[doc(hidden)]
    pub fn record_loop_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
        header: ProgramPointId,
        body: ProgramPointId,
    ) -> Result<(), ProcedureLoweringError> {
        let source = self.add_node_mapping(builder, node)?;
        builder.add_loop_site(LoopSite {
            source: source.source,
            evidence: source.evidence,
            header,
            body,
        })?;
        Ok(())
    }

    /// Record a loop whose CFG body point deliberately retains a narrower
    /// evaluation span while the structural loop role names the full body
    /// node. The second exact mapping keeps that producer attestation
    /// available to source joins without changing the point's semantic
    /// topology.
    #[doc(hidden)]
    pub fn record_loop_site_with_body_source(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
        body_node: Node<'_>,
        header: ProgramPointId,
        body: ProgramPointId,
    ) -> Result<(), ProcedureLoweringError> {
        let source = self.add_node_mapping(builder, node)?;
        let body_source = self.add_node_mapping(builder, body_node)?;
        let evidence = EvidenceId::try_from_index(self.next_evidence)
            .map_err(|_| ProcedureLoweringError::Invalid("too many evidence rows".into()))?;
        builder.add_evidence(Evidence {
            id: evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([source.source, body_source.source]),
        })?;
        self.next_evidence += 1;
        builder.add_loop_site(LoopSite {
            source: source.source,
            evidence,
            header,
            body,
        })?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn add_point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        metadata: PointMetadata,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, ProcedureLoweringError> {
        let events = effects
            .into_iter()
            .map(|effect| SemanticEvent::new(effect, metadata.source, metadata.evidence))
            .collect();
        let point = builder.add_point(events, metadata.source, metadata.evidence)?;
        self.register_point(point, metadata, "program-point allocation is not dense")?;
        Ok(point)
    }

    #[doc(hidden)]
    pub fn register_point(
        &mut self,
        point: ProgramPointId,
        metadata: PointMetadata,
        invalid_detail: &'static str,
    ) -> Result<(), ProcedureLoweringError> {
        if point.index() != self.point_metadata.len() {
            return Err(ProcedureLoweringError::Invalid(invalid_detail.into()));
        }
        self.point_metadata.push(metadata);
        Ok(())
    }

    #[doc(hidden)]
    pub fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, ProcedureLoweringError> {
        self.point_metadata
            .get(point.index())
            .copied()
            .ok_or_else(|| {
                ProcedureLoweringError::Invalid(format!(
                    "missing metadata for program point {point}"
                ))
            })
    }

    #[doc(hidden)]
    pub fn add_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        self.add_value_with_metadata(builder, metadata, kind)
    }

    #[doc(hidden)]
    pub fn add_value_with_metadata(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        metadata: PointMetadata,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ProcedureLoweringError> {
        let id = ValueId::try_from_index(self.next_value)
            .map_err(|_| ProcedureLoweringError::Invalid("too many semantic values".into()))?;
        builder.add_value(SemanticValue {
            id,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_value += 1;
        Ok(id)
    }

    /// Retain a semantic value after the adapter has established that its
    /// syntax identity is absent from the cache.
    ///
    /// Keeping the lookup adapter-side ensures source metadata is allocated
    /// only for a new value rather than leaked on a cache hit.
    #[doc(hidden)]
    pub fn insert_cached_value_with_metadata(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        cache: &mut HashMap<usize, ValueId>,
        syntax_id: usize,
        metadata: PointMetadata,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ProcedureLoweringError> {
        debug_assert!(
            !cache.contains_key(&syntax_id),
            "cached value insertion requires an adapter-side miss"
        );
        let value = self.add_value_with_metadata(builder, metadata, kind)?;
        let previous = cache.insert(syntax_id, value);
        debug_assert!(previous.is_none(), "cached value insertion replaced a row");
        Ok(value)
    }

    /// Reuse or create one value for an adapter-selected normalized syntax
    /// node. The adapter supplies the metadata policy so cache hits never
    /// allocate mappings and language-specific identities remain intact.
    #[doc(hidden)]
    pub fn cached_node_value<'tree>(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        cache: &mut HashMap<usize, ValueId>,
        node: Node<'tree>,
        kind: SemanticValueKind,
        add_mapping: impl FnOnce(
            &mut Self,
            &mut ProcedureCfgBuilder,
            Node<'tree>,
        ) -> Result<PointMetadata, ProcedureLoweringError>,
    ) -> Result<ValueId, ProcedureLoweringError> {
        let syntax_id = node.id();
        if let Some(value) = cache.get(&syntax_id) {
            return Ok(*value);
        }
        let metadata = add_mapping(self, builder, node)?;
        self.insert_cached_value_with_metadata(builder, cache, syntax_id, metadata, kind)
    }

    /// Emit the language-neutral suspend and two-resume core of an await.
    ///
    /// Operand selection, exceptional completion routing, and any
    /// runtime-specific uncertainty remain adapter-owned.
    #[doc(hidden)]
    pub fn add_await_scaffold(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        mut add_mapping: impl FnMut(
            &mut ProcedureLoweringSession<'_>,
            &mut ProcedureCfgBuilder,
        ) -> Result<PointMetadata, ProcedureLoweringError>,
    ) -> Result<AwaitScaffold, ProcedureLoweringError> {
        let suspend_metadata = add_mapping(self, builder)?;
        let suspend = self.add_point(builder, suspend_metadata, Vec::new())?;
        let normal_metadata = add_mapping(self, builder)?;
        let normal_resume = self.add_point(builder, normal_metadata, Vec::new())?;
        let exceptional_metadata = add_mapping(self, builder)?;
        let exceptional_resume = self.add_point(builder, exceptional_metadata, Vec::new())?;
        let awaited = self.add_value(builder, suspend, SemanticValueKind::Temporary)?;
        let result = self.add_value(builder, normal_resume, SemanticValueKind::AwaitResult)?;
        self.append_effect(
            builder,
            suspend,
            SemanticEffect::AsyncSuspend {
                awaited: Some(awaited),
                normal_resume: ControlContinuation::Target(normal_resume),
                exceptional_resume: ControlContinuation::Target(exceptional_resume),
            },
        )?;
        self.append_effect(
            builder,
            normal_resume,
            SemanticEffect::AsyncResume {
                suspend,
                kind: AsyncResumeKind::Normal,
                result: Some(result),
            },
        )?;
        self.append_effect(
            builder,
            exceptional_resume,
            SemanticEffect::AsyncResume {
                suspend,
                kind: AsyncResumeKind::Exceptional,
                result: None,
            },
        )?;
        self.add_edge(
            builder,
            suspend,
            normal_resume,
            ControlEdgeKind::AsyncNormal,
        )?;
        self.add_edge(
            builder,
            suspend,
            exceptional_resume,
            ControlEdgeKind::AsyncExceptional,
        )?;
        Ok(AwaitScaffold {
            suspend,
            normal_resume,
            exceptional_resume,
            awaited,
            result,
        })
    }

    #[doc(hidden)]
    pub fn add_allocation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        result: ValueId,
        kind: AllocationKind,
    ) -> Result<AllocationId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = AllocationId::try_from_index(self.next_allocation)
            .map_err(|_| ProcedureLoweringError::Invalid("too many allocations".into()))?;
        builder.add_allocation(AllocationSite {
            id,
            point,
            result,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_allocation += 1;
        self.append_effect(
            builder,
            point,
            SemanticEffect::Allocation { allocation: id },
        )?;
        Ok(id)
    }

    #[doc(hidden)]
    pub fn add_memory_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: MemoryLocationKind,
    ) -> Result<MemoryLocationId, ProcedureLoweringError> {
        self.add_memory_location_with_value_copy(builder, point, kind, MemoryValueCopy::Unknown)
    }

    #[doc(hidden)]
    pub fn add_memory_location_with_value_copy(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: MemoryLocationKind,
        value_copy: MemoryValueCopy,
    ) -> Result<MemoryLocationId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = MemoryLocationId::try_from_index(self.next_memory_location)
            .map_err(|_| ProcedureLoweringError::Invalid("too many memory locations".into()))?;
        builder.add_memory_location(MemoryLocation {
            id,
            kind,
            value_copy,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_memory_location += 1;
        Ok(id)
    }

    /// Reserve and load the target-local slot used to receive a lexical
    /// receiver captured from the immediate parent procedure.
    #[doc(hidden)]
    pub fn add_receiver_capture_input(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        metadata: PointMetadata,
        lexical_parent: ProcedureId,
    ) -> Result<(ValueId, MemoryLocationId), ProcedureLoweringError> {
        let value = self.add_value_with_metadata(builder, metadata, SemanticValueKind::Local)?;
        let location = self.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Capture {
                lexical_parent,
                binding: Some(value),
            },
        )?;
        if location != RECEIVER_CAPTURE_DESTINATION {
            return Err(ProcedureLoweringError::Invalid(format!(
                "receiver capture destination must be {}, allocated {location}",
                RECEIVER_CAPTURE_DESTINATION
            )));
        }
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Capture,
                location,
                result: value,
            },
        )?;
        Ok((value, location))
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn add_capture(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callable: ValueId,
        target: ProcedureId,
        environment: AllocationId,
        captured: CaptureSource,
        destination: MemoryLocationId,
        mode: CaptureMode,
    ) -> Result<CaptureId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = CaptureId::try_from_index(self.next_capture)
            .map_err(|_| ProcedureLoweringError::Invalid("too many captures".into()))?;
        builder.add_capture(CaptureBinding {
            id,
            point,
            callable,
            target,
            environment,
            captured,
            destination,
            mode,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_capture += 1;
        self.append_effect(builder, point, SemanticEffect::CaptureBind { capture: id })?;
        Ok(id)
    }

    #[doc(hidden)]
    pub fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        self.append_effect_with_metadata(builder, point, metadata, effect)
    }

    #[doc(hidden)]
    pub fn append_value_flow_if_distinct(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: ValueFlowKind,
        source: ValueId,
        target: ValueId,
    ) -> Result<(), ProcedureLoweringError> {
        if source == target {
            return Ok(());
        }
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind,
                source,
                target,
            },
        )
    }

    /// Append an effect whose event anchors on its own source mapping rather
    /// than inheriting the point's. An effect that models one token of a wider
    /// evaluation -- a binding read inside a `return`, for example -- is
    /// spelled by that token, not by whichever statement-level point the
    /// evaluation happened to be scheduled at.
    #[doc(hidden)]
    pub fn append_effect_with_metadata(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        metadata: PointMetadata,
        effect: SemanticEffect,
    ) -> Result<(), ProcedureLoweringError> {
        builder.append_event(
            point,
            SemanticEvent::new(effect, metadata.source, metadata.evidence),
        )?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn append_language_defined_value_flows(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        sources: impl IntoIterator<Item = ValueId>,
        target: ValueId,
    ) -> Result<(), ProcedureLoweringError> {
        for source in sources {
            self.append_effect(
                builder,
                point,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                },
            )?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn add_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        self.add_gap_with_impacts(
            builder,
            point,
            subject,
            capability,
            SemanticGapImpacts::NONE,
            kind,
            detail,
        )
    }

    /// Record a gap when the caller does not need its generated identifier.
    #[doc(hidden)]
    pub fn record_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), ProcedureLoweringError> {
        self.add_gap(builder, point, subject, capability, kind, detail)
            .map(|_| ())
    }

    #[doc(hidden)]
    pub fn add_unhandled_control_syntax_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node_kind: &str,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        let detail = format!("{node_kind} runtime/control syntax is not yet lowered structurally");
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            detail,
        )
    }

    #[doc(hidden)]
    pub fn add_unmatched_completion_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: CompletionKind,
        capability: SemanticCapability,
    ) -> Result<(), ProcedureLoweringError> {
        let detail = format!(
            "{} completion has no matching represented target",
            kind.label()
        );
        self.record_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            capability,
            SemanticGapKind::Unsupported,
            &detail,
        )
    }

    /// Publish the paired value/call-site gaps for one unresolved callable
    /// target while preserving adapter-owned diagnostics.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn add_callable_resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
        callable_detail: impl Into<Box<str>>,
        call_detail: impl Into<Box<str>>,
    ) -> Result<(), ProcedureLoweringError> {
        let kind = match resolution {
            CallableTargetResolution::Proven(_) => return Ok(()),
            CallableTargetResolution::Ambiguous(_) => SemanticGapKind::Ambiguous,
            CallableTargetResolution::Unknown => SemanticGapKind::Unknown,
            CallableTargetResolution::Unsupported => SemanticGapKind::Unsupported,
            CallableTargetResolution::Unproven(_) => SemanticGapKind::Unproven,
            CallableTargetResolution::ExceededBudget(_) => SemanticGapKind::ExceededBudget,
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Value(callee),
            SemanticCapability::CallableReferences,
            kind,
            callable_detail,
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::Calls,
            kind,
            call_detail,
        )?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn add_dispatch_resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), ProcedureLoweringError> {
        self.add_callable_resolution_gaps(
            builder,
            point,
            callee,
            call_site,
            resolution,
            "callable target requires whole-program dispatch refinement",
            "call target requires whole-program dispatch refinement",
        )
    }

    /// Record capability-default impacts unioned with explicit additions.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn add_gap_with_impacts(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        additional_impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        self.add_gap_with_impacts_and_discharge(
            builder,
            point,
            subject,
            capability,
            additional_impacts,
            kind,
            SemanticGapDischarge::None,
            detail,
        )
    }

    #[doc(hidden)]
    pub fn add_unprojected_index_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
        detail: impl Into<Box<str>>,
    ) -> Result<(), ProcedureLoweringError> {
        self.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unsupported,
            detail,
        )?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn add_unknown_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
        detail: impl Into<Box<str>>,
    ) -> Result<(), ProcedureLoweringError> {
        self.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::FieldMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            detail,
        )?;
        Ok(())
    }

    /// Add a gap whose downstream impact set is already complete.
    ///
    /// Most adapter gaps use the conservative capability-derived impacts plus
    /// additions. A partitioned gap uses this entry point only when the
    /// adapter has already lowered every other effect of the operation and the
    /// retained gap deliberately describes the one remaining partition.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn add_partitioned_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        self.add_gap_with_exact_impacts_and_discharge(
            builder,
            point,
            subject,
            capability,
            impacts,
            kind,
            SemanticGapDischarge::ModeledEffectPartition,
            detail,
        )
    }

    /// Record the complete impact set without capability defaults. Structured
    /// evidence must prove which dimensions the remaining uncertainty affects.
    /// The modeled-partition marker preserves that explicit contract in the IR.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn add_gap_with_exact_impacts(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        self.add_gap_with_exact_impacts_and_discharge(
            builder,
            point,
            subject,
            capability,
            impacts,
            kind,
            SemanticGapDischarge::ModeledEffectPartition,
            detail,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn add_gap_with_impacts_and_discharge(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        additional_impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        discharge: SemanticGapDischarge,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        self.add_gap_with_exact_impacts_and_discharge(
            builder,
            point,
            subject,
            capability,
            SemanticGapImpacts::for_gap(capability, subject).union(additional_impacts),
            kind,
            discharge,
            detail,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_gap_with_exact_impacts_and_discharge(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        discharge: SemanticGapDischarge,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = SemanticGapId::try_from_index(self.next_gap)
            .map_err(|_| ProcedureLoweringError::Invalid("too many semantic gaps".into()))?;
        builder.add_gap(SemanticGap {
            id,
            point,
            subject,
            capability,
            impacts,
            kind,
            budget: None,
            discharge,
            detail: detail.into(),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_gap += 1;
        self.append_effect(builder, point, SemanticEffect::Gap { gap: id })?;
        Ok(id)
    }

    #[doc(hidden)]
    pub fn add_edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target_point: ProgramPointId,
        kind: ControlEdgeKind,
    ) -> Result<(), ProcedureLoweringError> {
        let metadata = self.metadata(source_point)?;
        builder.add_edge(ControlEdge {
            source_point,
            target_point,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn add_target_edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: ControlTarget,
    ) -> Result<(), ProcedureLoweringError> {
        self.add_edge(builder, source_point, target.point, target.kind)
    }

    #[doc(hidden)]
    pub fn add_transparent_assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
        source: ValueId,
        target: ValueId,
        next: ControlTarget,
    ) -> Result<ProgramPointId, ProcedureLoweringError> {
        let point = self.add_node_point(builder, node, Vec::new())?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target,
                value: source,
            },
        )?;
        self.add_target_edge(builder, point, next)?;
        Ok(point)
    }

    /// Record one normalized decision-point condition (issue #2443).
    ///
    /// The guard's provenance is the decision point's own, which is what makes
    /// a guard row anchor at the condition an author wrote. Arms must already
    /// have been added as edges; the IR validator enforces that.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn add_guard_fact(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        predicate: GuardPredicate,
        subject: Option<ValueId>,
        true_arm: Option<GuardArm>,
        false_arm: Option<GuardArm>,
    ) -> Result<GuardId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = GuardId::try_from_index(self.next_guard)
            .map_err(|_| ProcedureLoweringError::Invalid("too many guard facts".into()))?;
        builder.add_guard_fact(GuardFactParts {
            id,
            point,
            subject,
            predicate,
            true_arm,
            false_arm,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_guard += 1;
        Ok(id)
    }

    #[doc(hidden)]
    pub fn add_guard_for_targets(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        predicate: GuardPredicate,
        subject: Option<ValueId>,
        when_true: Option<ControlTarget>,
        when_false: Option<ControlTarget>,
    ) -> Result<GuardId, ProcedureLoweringError> {
        let arm = |target: Option<ControlTarget>| {
            target.map(|target| GuardArm {
                target_point: target.point,
                kind: target.kind,
            })
        };
        self.add_guard_fact(
            builder,
            point,
            predicate,
            subject,
            arm(when_true),
            arm(when_false),
        )
    }

    #[doc(hidden)]
    pub fn add_switch_fact(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        fact: SwitchFactScaffold,
    ) -> Result<SwitchFactId, ProcedureLoweringError> {
        let metadata = self.metadata(fact.point)?;
        let id = SwitchFactId::try_from_index(self.next_switch_fact)
            .map_err(|_| ProcedureLoweringError::Invalid("too many switch facts".into()))?;
        builder.add_switch_fact(SwitchFactParts {
            id,
            kind: fact.kind,
            point: fact.point,
            selector: fact.selector,
            selector_domain: fact.selector_domain,
            cases: fact.cases,
            default_edge: fact.default_edge,
            default_present: fact.default_present,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_switch_fact += 1;
        Ok(id)
    }

    #[doc(hidden)]
    pub fn add_call_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: CallSiteScaffold,
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        self.add_call_site_with_timing(builder, call, ExecutionTiming::SameEvaluation)
    }

    /// Publish a supported call that executes later in the same procedure
    /// invocation, such as a Go defer reached on its cleanup route.
    #[doc(hidden)]
    pub fn add_deferred_call_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: CallSiteScaffold,
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        self.add_call_site_with_timing(builder, call, ExecutionTiming::SameInvocation)
    }

    fn next_call_site_id(&self) -> Result<CallSiteId, ProcedureLoweringError> {
        CallSiteId::try_from_index(self.next_call_site)
            .map_err(|_| ProcedureLoweringError::Invalid("too many call sites".into()))
    }

    fn publish_call_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call_site: SemanticCallSite,
        continuations: &[(ProgramPointId, CallContinuationKind)],
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        let id = call_site.id;
        let point = call_site.point;
        builder.add_call_site(call_site)?;
        self.next_call_site += 1;
        self.append_effect(builder, point, SemanticEffect::Invoke { call_site: id })?;
        for &(continuation_point, kind) in continuations {
            self.append_effect(
                builder,
                continuation_point,
                SemanticEffect::CallContinuation {
                    call_site: id,
                    kind,
                },
            )?;
        }
        Ok(id)
    }

    fn add_call_site_with_timing(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: CallSiteScaffold,
        execution_timing: ExecutionTiming,
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        let metadata = self.metadata(call.point)?;
        let id = self.next_call_site_id()?;
        self.publish_call_site(
            builder,
            SemanticCallSite {
                id,
                point: call.point,
                invocation_mode: CallInvocationMode::Ordinary,
                execution_timing,
                callee: call.callee,
                receiver: call.receiver,
                arguments: call.arguments,
                normal_results: call.normal_results,
                result: call.result,
                thrown: call.thrown,
                declared_targets: call.declared_targets,
                target_evidence: metadata.evidence,
                normal_continuation: ControlContinuation::Target(call.normal_continuation),
                exceptional_continuation: ControlContinuation::Target(
                    call.exceptional_continuation,
                ),
                source: metadata.source,
                evidence: metadata.evidence,
            },
            &[
                (call.normal_continuation, CallContinuationKind::Normal),
                (
                    call.exceptional_continuation,
                    CallContinuationKind::Exceptional,
                ),
            ],
        )
    }

    /// Publish an ordinary call whose declared return type proves that its
    /// normal continuation is absent.
    #[doc(hidden)]
    pub fn add_diverging_call_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: DivergingCallSiteScaffold,
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        let metadata = self.metadata(call.point)?;
        let id = self.next_call_site_id()?;
        self.publish_call_site(
            builder,
            SemanticCallSite {
                id,
                point: call.point,
                invocation_mode: CallInvocationMode::Ordinary,
                execution_timing: ExecutionTiming::SameEvaluation,
                callee: call.callee,
                receiver: call.receiver,
                arguments: call.arguments,
                normal_results: Box::new([]),
                result: call.result,
                thrown: call.thrown,
                declared_targets: call.declared_targets,
                target_evidence: metadata.evidence,
                normal_continuation: ControlContinuation::Absent,
                exceptional_continuation: ControlContinuation::Target(
                    call.exceptional_continuation,
                ),
                source: metadata.source,
                evidence: metadata.evidence,
            },
            &[(
                call.exceptional_continuation,
                CallContinuationKind::Exceptional,
            )],
        )
    }

    /// Publish a call started by an exact spawned-work construct. The
    /// registering activation has a normal continuation but never receives a
    /// return or panic edge from the spawned body.
    #[doc(hidden)]
    pub fn add_spawned_call_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: SpawnedCallSiteScaffold,
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        let metadata = self.metadata(call.point)?;
        let id = self.next_call_site_id()?;
        self.publish_call_site(
            builder,
            SemanticCallSite {
                id,
                point: call.point,
                invocation_mode: CallInvocationMode::Detached,
                execution_timing: ExecutionTiming::DifferentTask,
                callee: call.callee,
                receiver: call.receiver,
                arguments: call.arguments,
                normal_results: Box::new([]),
                result: None,
                thrown: None,
                declared_targets: call.declared_targets,
                target_evidence: metadata.evidence,
                normal_continuation: ControlContinuation::Target(call.normal_continuation),
                exceptional_continuation: ControlContinuation::Absent,
                source: metadata.source,
                evidence: metadata.evidence,
            },
            &[(call.normal_continuation, CallContinuationKind::Normal)],
        )
    }
}

/// Lower a batch after an adapter's temporary binding inventory has performed
/// work that will not survive publication. Its census and work stay separate.
#[doc(hidden)]
pub fn lower_procedure_batch_with_prepass_work<I, F>(
    items: I,
    initial_admission: SemanticWork,
    prepass_work: SemanticWork,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
    mut lower: F,
) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>
where
    I: IntoIterator,
    F: FnMut(
        I::Item,
        &SemanticBudget,
        &CancellationToken,
    ) -> Result<(ProcedureSemanticsParts, SemanticWork), ProcedureLoweringError>,
{
    let iterator = items.into_iter();
    let mut procedures = Vec::with_capacity(iterator.size_hint().0);
    let mut observed = initial_admission.conservative_add(prepass_work);
    let mut traversal = prepass_work;

    for item in iterator {
        if cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: observed,
            });
        }
        let mut staged_budget = budget.clone();
        if let Err(exceeded) = staged_budget
            .admit(observed.saturating_sub(traversal))
            .map(|()| staged_budget.charge_work(traversal))
        {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: observed,
            });
        }
        match lower(item, &staged_budget, cancellation) {
            Ok((parts, work)) => {
                let census = crate::analyzer::semantic::ir::measure_procedure_work(&parts);
                traversal = traversal.conservative_add(work.saturating_sub(census));
                let candidate = observed.conservative_add(work);
                if let Err(exceeded) = budget.check_admission(candidate.saturating_sub(traversal)) {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work: candidate,
                    });
                }
                observed = candidate;
                procedures.push(parts);
            }
            Err(ProcedureLoweringError::Cancelled(work)) => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: observed.conservative_add(*work),
                });
            }
            Err(ProcedureLoweringError::Budget(exceeded, work)) => {
                let work = observed.conservative_add(*work);
                let exceeded = budget.check_admission(work).err().unwrap_or(exceeded);
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            Err(ProcedureLoweringError::Invalid(detail)) => {
                return Err(SemanticProviderError::internal(detail));
            }
        }
    }

    Ok(SemanticOutcome::Complete {
        value: procedures,
        work: observed,
    })
}
