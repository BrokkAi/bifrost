//! Shared emission mechanics for language-owned semantic lowerers.
//!
//! This module deliberately knows nothing about tree-sitter node kinds or
//! language syntax. Adapters choose source anchors, evaluation order, control
//! topology, and uncertainty; the session owns dense IDs, exact provenance,
//! common call rows, and batch-level budget/cancellation semantics.

use crate::analyzer::lexical_definitions::FormalVariadicKind;
use crate::hash::HashMap;
use tree_sitter::Node;

use super::cfg::{
    CleanupRegionId, CompletionRoute, DriveError, ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use super::{
    AllocationId, AllocationKind, AllocationSite, ArgumentDomain, AsyncResumeKind,
    CallContinuationKind, CallSiteId, CallableTargetResolution, CancellationToken, CaptureBinding,
    CaptureId, CaptureMode, CaptureSource, ControlContinuation, ControlEdge, ControlEdgeKind,
    Evidence, EvidenceCompleteness, EvidenceId, FormalMultiplicity, MemoryAccessKind,
    MemoryLocation, MemoryLocationId, MemoryLocationKind, ProcedureId, ProcedureSemanticsParts,
    ProgramPointId, ProofStatus, SemanticBudget, SemanticBudgetExceeded, SemanticCallArgument,
    SemanticCallSite, SemanticCapability, SemanticEffect, SemanticEvent, SemanticGap,
    SemanticGapId, SemanticGapImpacts, SemanticGapKind, SemanticGapSubject, SemanticLocator,
    SemanticOutcome, SemanticProviderError, SemanticRole, SemanticValue, SemanticValueKind,
    SemanticWork, SourceAnchor, SourceMapping, SourceMappingId, SourceMappingKind, SourcePosition,
    SourceSpan, ValueId,
};

/// Common operational failures produced while lowering one procedure.
#[derive(Debug)]
pub(crate) enum ProcedureLoweringError {
    Cancelled(Box<SemanticWork>),
    Budget(SemanticBudgetExceeded, Box<SemanticWork>),
    Invalid(String),
}

/// Marker returned when shared adapter preparation observes cooperative
/// cancellation before procedure lowering starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoweringCancelled;

/// Minimal adapter-owned view needed to relay lexical receiver demand through
/// nested lambdas without coupling shared lowering to language syntax.
pub(crate) trait ReceiverCaptureSpec {
    fn lexical_parent(&self) -> Option<ProcedureId>;
    fn relays_receiver_capture(&self) -> bool;
    fn captures_receiver(&self) -> bool;
    fn require_receiver_capture(&mut self);
}

/// Propagate receiver demand from lexical children to their immediate lambda
/// parents in one reverse pass.
///
/// Procedure enumeration publishes dense IDs in parent-before-child order.
/// Walking that order backwards means a demand copied to one parent is seen
/// when that parent is visited, so even deeply nested chains remain linear.
pub(crate) fn relay_receiver_capture_demand<T: ReceiverCaptureSpec>(
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

pub(crate) fn sum_lowering_work(left: SemanticWork, right: SemanticWork) -> SemanticWork {
    left.conservative_add(right)
}

/// Return the source slice represented by a tree-sitter node.
pub(crate) fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    source.get(node.byte_range())
}

/// [`node_text`] filtered to reject the empty string, so a name-bearing node
/// that spans zero bytes (or an out-of-range slice) is treated as absent.
/// Shared by every per-language semantic lowering module.
pub(crate) fn nonempty_node_text<'source>(
    source: &'source str,
    node: Node<'_>,
) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

/// Collect children associated with one structured tree-sitter field.
pub(crate) fn children_by_field_name<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor).collect()
}

/// Convert one tree-sitter node into the stable source anchor used throughout
/// the neutral semantic IR.
pub(crate) fn source_anchor(node: Node<'_>, occurrence: u32) -> Result<SourceAnchor, String> {
    let start = node.start_position();
    let end = node.end_position();
    let start = SourcePosition::new(
        u32::try_from(node.start_byte()).map_err(|_| "source start exceeds u32")?,
        u32::try_from(start.row).map_err(|_| "source start line exceeds u32")?,
        u32::try_from(start.column).map_err(|_| "source start column exceeds u32")?,
    );
    let end = SourcePosition::new(
        u32::try_from(node.end_byte()).map_err(|_| "source end exceeds u32")?,
        u32::try_from(end.row).map_err(|_| "source end line exceeds u32")?,
        u32::try_from(end.column).map_err(|_| "source end column exceeds u32")?,
    );
    let span = SourceSpan::new(start, end).map_err(|error| error.to_string())?;
    Ok(SourceAnchor::new(span, occurrence))
}

/// Translate syntax-level variadic classification into the neutral call-port
/// multiplicity used by semantic adapters.
pub(crate) const fn formal_multiplicity(
    variadic: Option<FormalVariadicKind>,
) -> FormalMultiplicity {
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
pub(crate) fn lower_procedure_batch<I, F>(
    items: I,
    initial_work: SemanticWork,
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
    let mut observed = initial_work;

    for item in iterator {
        if cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: observed,
            });
        }
        let mut staged_budget = budget.clone();
        if let Err(exceeded) = staged_budget.charge(observed) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: observed,
            });
        }
        match lower(item, &staged_budget, cancellation) {
            Ok((parts, work)) => {
                let candidate = sum_lowering_work(observed, work);
                if let Err(exceeded) = budget.check(candidate) {
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
                    work: sum_lowering_work(observed, *work),
                });
            }
            Err(ProcedureLoweringError::Budget(exceeded, work)) => {
                let work = sum_lowering_work(observed, *work);
                let exceeded = budget.check(work).err().unwrap_or(exceeded);
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

/// Drive one adapter's opaque work items, seal detached source regions, and
/// freeze the completed procedure.
///
/// The adapter owns the work-item type and step function. This helper owns the
/// identical cancellation, budget, and finalization policy used after syntax
/// has already been classified.
pub(crate) fn drive_and_finish_procedure<I, F>(
    mut builder: ProcedureCfgBuilder,
    initial: I,
    entry: ProgramPointId,
    normal_exit: ProgramPointId,
    exceptional_exit: ProgramPointId,
    cancellation: &CancellationToken,
    mut step: F,
) -> Result<(ProcedureSemanticsParts, SemanticWork), ProcedureLoweringError>
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
pub(crate) struct PointMetadata {
    pub(crate) source: SourceMappingId,
    pub(crate) evidence: EvidenceId,
}

/// One already-classified control-flow destination.
///
/// Language adapters decide which syntax owns the destination and which edge
/// kind applies. This shared value only carries that syntax-free decision
/// through their iterative work queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlTarget {
    pub(crate) point: ProgramPointId,
    pub(crate) kind: ControlEdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AwaitScaffold {
    pub(crate) suspend: ProgramPointId,
    pub(crate) normal_resume: ProgramPointId,
    pub(crate) exceptional_resume: ProgramPointId,
    pub(crate) awaited: ValueId,
    pub(crate) result: ValueId,
}

pub(crate) type ScheduledControlNode<T> = (T, ProgramPointId);

/// Push the three opaque work items for a conditional choice in execution
/// order: evaluate the condition first, then only the selected arm.
#[allow(clippy::too_many_arguments)]
pub(crate) fn schedule_conditional_choice<T, W>(
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
pub(crate) enum ShortCircuitKind {
    And,
    Or,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CleanupSpecialization<R> {
    pub(crate) region: R,
    pub(crate) entry: ProgramPointId,
    pub(crate) next: ControlTarget,
}

pub(crate) struct CleanupRoutePlanner<'route> {
    route: &'route CompletionRoute,
    next_index: usize,
    next: ControlTarget,
}

impl<'route> CleanupRoutePlanner<'route> {
    pub(crate) fn new(route: &'route CompletionRoute) -> Self {
        Self {
            route,
            next_index: route.cleanups().len(),
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
    pub(crate) fn next<'tree, R>(
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
        while self.next_index > 0 {
            self.next_index -= 1;
            let index = self.next_index;
            let expected = self.route.cleanups()[index];
            let region = regions
                .iter()
                .copied()
                .find(|region| region_id(*region) == expected)
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

    pub(crate) fn target(&self) -> ControlTarget {
        debug_assert_eq!(self.next_index, 0, "cleanup route planning is incomplete");
        self.next
    }
}

/// Schedule a boolean short-circuit pair after the adapter has identified its
/// operands and allocated the right-hand entry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn schedule_short_circuit_condition<T, W>(
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
    pub(crate) const fn normal(point: ProgramPointId) -> Self {
        Self {
            point,
            kind: ControlEdgeKind::Normal,
        }
    }
}

/// Schedule the stable topology of a C-style loop after an adapter has
/// identified and allocated every syntax node.
///
/// The adapter supplies opaque payloads and constructors for its work-item
/// enum. This function owns only scope targets, edge kinds, and reverse stack
/// ordering.
#[allow(clippy::too_many_arguments)]
pub(crate) fn schedule_c_style_loop<T, W, Initializer, Expression, Statement, Condition>(
    builder: &mut ProcedureCfgBuilder,
    session: &ProcedureLoweringSession<'_>,
    entry: ProgramPointId,
    next: ControlTarget,
    parent_scope: ScopeFrameId,
    label: Option<Box<str>>,
    initializers: &[ScheduledControlNode<T>],
    condition: Option<ScheduledControlNode<T>>,
    condition_entry: ProgramPointId,
    body: ScheduledControlNode<T>,
    updates: &[ScheduledControlNode<T>],
    stack: &mut Vec<W>,
    initializer_work: Initializer,
    expression_work: Expression,
    statement_work: Statement,
    condition_work: Condition,
) -> Result<(), ProcedureLoweringError>
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
        session.add_edge(builder, entry, first.1, ControlEdgeKind::Normal)?;
        for (index, initializer) in initializers.iter().enumerate().rev() {
            let next = initializers
                .get(index + 1)
                .map_or(condition_entry, |next| next.1);
            stack.push(initializer_work(
                initializer.0,
                initializer.1,
                ControlTarget::normal(next),
                loop_scope,
            ));
        }
    } else if entry != condition_entry {
        session.add_edge(builder, entry, condition_entry, ControlEdgeKind::Normal)?;
    }
    Ok(())
}

/// Target-local slot reserved for the lexical receiver capture, when present.
///
/// Parent capture rows are emitted before their child procedure is lowered, so
/// both sides use this planned destination. The child-side helper below checks
/// the dense allocation rather than relying on an adapter-local magic ID.
pub(crate) const RECEIVER_CAPTURE_DESTINATION: MemoryLocationId = MemoryLocationId::new(0);

/// Adapter-supplied values needed to publish one ordinary call row and its
/// matched continuation events. Syntax evaluation and control edges remain
/// adapter-owned.
pub(crate) struct CallSiteScaffold {
    pub(crate) point: ProgramPointId,
    pub(crate) callee: ValueId,
    pub(crate) receiver: Option<ValueId>,
    pub(crate) arguments: Box<[SemanticCallArgument]>,
    pub(crate) result: Option<ValueId>,
    pub(crate) thrown: Option<ValueId>,
    pub(crate) declared_targets: CallableTargetResolution,
    pub(crate) normal_continuation: ProgramPointId,
    pub(crate) exceptional_continuation: ProgramPointId,
}

pub(crate) struct ProcedureLoweringStart<'a> {
    pub(crate) builder: ProcedureCfgBuilder,
    pub(crate) session: ProcedureLoweringSession<'a>,
    pub(crate) entry: ProgramPointId,
    pub(crate) normal_exit: ProgramPointId,
    pub(crate) exceptional_exit: ProgramPointId,
    pub(crate) function_scope: ScopeFrameId,
}

/// Source-anchor-aware emission state shared by every language adapter.
pub(crate) struct ProcedureLoweringSession<'a> {
    locator: SemanticLocator,
    point_metadata: Vec<PointMetadata>,
    next_source: usize,
    next_evidence: usize,
    next_value: usize,
    next_allocation: usize,
    next_memory_location: usize,
    next_capture: usize,
    next_call_site: usize,
    next_gap: usize,
    source_occurrences: HashMap<(usize, usize), u32>,
    cancellation: &'a CancellationToken,
}

impl<'a> ProcedureLoweringSession<'a> {
    /// Seed the exact procedure provenance, entry/exit points, and function
    /// completion scope used by every production adapter.
    pub(crate) fn start(
        parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
    ) -> Result<ProcedureLoweringStart<'a>, SemanticBudgetExceeded> {
        Self::start_with_function_throw_boundary(parts, budget, cancellation, false)
            .map(|(start, _)| start)
    }

    /// Seed ordinary boundaries while optionally routing function-level throws
    /// to a distinct, adapter-owned terminal point. This preserves the common
    /// setup for languages whose procedure contract has a second exceptional
    /// terminal, such as unconditional C++ `noexcept` termination.
    pub(crate) fn start_with_function_throw_boundary(
        mut parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
        cancellation: &'a CancellationToken,
        separate_throw_boundary: bool,
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
        });
        parts.evidence_rows.push(Evidence {
            id: base_evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([base_source]),
        });

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
            next_source: 1,
            next_evidence: 1,
            next_value: 0,
            next_allocation: 0,
            next_memory_location: 0,
            next_capture: 0,
            next_call_site: 0,
            next_gap: 0,
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

    pub(crate) const fn cancellation(&self) -> &'a CancellationToken {
        self.cancellation
    }

    pub(crate) const fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    /// Return the next deterministic occurrence for an adapter-selected byte
    /// span. The adapter remains responsible for constructing the anchor.
    pub(crate) fn next_source_occurrence(&mut self, start: usize, end: usize) -> u32 {
        let occurrence = self.source_occurrences.entry((start, end)).or_default();
        let current = *occurrence;
        *occurrence = occurrence
            .checked_add(1)
            .expect("one source span cannot have more than u32::MAX semantic occurrences");
        current
    }

    pub(crate) fn add_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        anchor: SourceAnchor,
        kind: SourceMappingKind,
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

    pub(crate) fn add_node_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'_>,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        let range = node.byte_range();
        let occurrence = self.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(ProcedureLoweringError::Invalid)?;
        self.add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    pub(crate) fn add_point(
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

    pub(crate) fn register_point(
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

    pub(crate) fn metadata(
        &self,
        point: ProgramPointId,
    ) -> Result<PointMetadata, ProcedureLoweringError> {
        self.point_metadata
            .get(point.index())
            .copied()
            .ok_or_else(|| {
                ProcedureLoweringError::Invalid(format!(
                    "missing metadata for program point {point}"
                ))
            })
    }

    pub(crate) fn add_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        self.add_value_with_metadata(builder, metadata, kind)
    }

    pub(crate) fn add_value_with_metadata(
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
    pub(crate) fn insert_cached_value_with_metadata(
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

    /// Emit the language-neutral suspend and two-resume core of an await.
    ///
    /// Operand selection, exceptional completion routing, and any
    /// runtime-specific uncertainty remain adapter-owned.
    pub(crate) fn add_await_scaffold(
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

    pub(crate) fn add_allocation(
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

    pub(crate) fn add_memory_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: MemoryLocationKind,
    ) -> Result<MemoryLocationId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let id = MemoryLocationId::try_from_index(self.next_memory_location)
            .map_err(|_| ProcedureLoweringError::Invalid("too many memory locations".into()))?;
        builder.add_memory_location(MemoryLocation {
            id,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_memory_location += 1;
        Ok(id)
    }

    /// Reserve and load the target-local slot used to receive a lexical
    /// receiver captured from the immediate parent procedure.
    pub(crate) fn add_receiver_capture_input(
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
            MemoryLocationKind::Capture { lexical_parent },
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
    pub(crate) fn add_capture(
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

    pub(crate) fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        builder.append_event(
            point,
            SemanticEvent::new(effect, metadata.source, metadata.evidence),
        )?;
        Ok(())
    }

    pub(crate) fn add_gap(
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

    /// Publish the paired value/call-site gaps for one unresolved callable
    /// target while preserving adapter-owned diagnostics.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_callable_resolution_gaps(
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_gap_with_impacts(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        additional_impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        detail: impl Into<Box<str>>,
    ) -> Result<SemanticGapId, ProcedureLoweringError> {
        let metadata = self.metadata(point)?;
        let impacts = SemanticGapImpacts::for_gap(capability, subject).union(additional_impacts);
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
            detail: detail.into(),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_gap += 1;
        self.append_effect(builder, point, SemanticEffect::Gap { gap: id })?;
        Ok(id)
    }

    pub(crate) fn add_edge(
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

    pub(crate) fn add_call_site(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: CallSiteScaffold,
    ) -> Result<CallSiteId, ProcedureLoweringError> {
        let metadata = self.metadata(call.point)?;
        let id = CallSiteId::try_from_index(self.next_call_site)
            .map_err(|_| ProcedureLoweringError::Invalid("too many call sites".into()))?;
        builder.add_call_site(SemanticCallSite {
            id,
            point: call.point,
            callee: call.callee,
            receiver: call.receiver,
            arguments: call.arguments,
            result: call.result,
            thrown: call.thrown,
            declared_targets: call.declared_targets,
            target_evidence: metadata.evidence,
            normal_continuation: ControlContinuation::Target(call.normal_continuation),
            exceptional_continuation: ControlContinuation::Target(call.exceptional_continuation),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_call_site += 1;
        self.append_effect(
            builder,
            call.point,
            SemanticEffect::Invoke { call_site: id },
        )?;
        self.append_effect(
            builder,
            call.normal_continuation,
            SemanticEffect::CallContinuation {
                call_site: id,
                kind: CallContinuationKind::Normal,
            },
        )?;
        self.append_effect(
            builder,
            call.exceptional_continuation,
            SemanticEffect::CallContinuation {
                call_site: id,
                kind: CallContinuationKind::Exceptional,
            },
        )?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::analyzer::semantic::cfg::{CompletionKind, CompletionRequest};
    use crate::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, ProcedureId, ProcedureKind,
        SemanticBudgetDimension, SemanticLanguage, SourcePosition, SourceSpan, WorkspaceMountId,
        WorkspaceRelativePath,
    };

    fn anchor(start: u32, end: u32, occurrence: u32) -> SourceAnchor {
        SourceAnchor::new(
            SourceSpan::new(
                SourcePosition::new(start, 0, start),
                SourcePosition::new(end, 0, end),
            )
            .expect("test span"),
            occurrence,
        )
    }

    fn parts() -> ProcedureSemanticsParts {
        let declaration_anchor = anchor(0, 7, 0);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(
                DeclarationSegmentKind::Function,
                "fixture",
                declaration_anchor,
                0,
            )
            .expect("declaration segment"),
        ])
        .expect("declaration locator");
        let locator = SemanticLocator::new(
            WorkspaceMountId::hash_bytes(b"lowering-session-test"),
            WorkspaceRelativePath::new("fixture.ts").expect("path"),
            SemanticLanguage::Standard(crate::analyzer::Language::TypeScript),
            declaration,
            SemanticRole::Procedure,
            declaration_anchor,
        );
        ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            locator,
            ProcedureKind::Function,
            SourceMappingId::new(0),
            EvidenceId::new(0),
        )
    }

    #[derive(Clone, Copy)]
    struct CaptureSpec {
        parent: Option<ProcedureId>,
        relays_receiver_capture: bool,
        captures_receiver: bool,
    }

    impl ReceiverCaptureSpec for CaptureSpec {
        fn lexical_parent(&self) -> Option<ProcedureId> {
            self.parent
        }

        fn relays_receiver_capture(&self) -> bool {
            self.relays_receiver_capture
        }

        fn captures_receiver(&self) -> bool {
            self.captures_receiver
        }

        fn require_receiver_capture(&mut self) {
            self.captures_receiver = true;
        }
    }

    fn nested_capture_specs(depth: usize) -> Vec<CaptureSpec> {
        (0..depth)
            .map(|index| CaptureSpec {
                parent: (index > 0).then(|| {
                    ProcedureId::try_from_index(index - 1).expect("small test procedure ID")
                }),
                relays_receiver_capture: true,
                captures_receiver: index + 1 == depth,
            })
            .collect()
    }

    #[test]
    fn receiver_capture_demand_relays_in_one_cancellable_reverse_pass() {
        const DEPTH: usize = 128;
        let mut specs = nested_capture_specs(DEPTH);
        let cancellation = CancellationToken::cancel_after_checks_for_test(DEPTH + 2);

        relay_receiver_capture_demand(&mut specs, &cancellation)
            .expect("one cancellation check per procedure must complete");

        assert!(specs.iter().all(|spec| spec.captures_receiver));
        assert!(!cancellation.is_cancelled());
    }

    #[test]
    fn receiver_capture_demand_stops_when_cancelled() {
        let mut specs = nested_capture_specs(128);
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);

        assert_eq!(
            relay_receiver_capture_demand(&mut specs, &cancellation),
            Err(LoweringCancelled)
        );
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn receiver_capture_demand_stops_at_non_relaying_parent() {
        let mut specs = nested_capture_specs(4);
        specs[2].relays_receiver_capture = false;

        relay_receiver_capture_demand(&mut specs, &CancellationToken::default())
            .expect("uncancelled relay must complete");

        assert!(!specs[0].captures_receiver);
        assert!(!specs[1].captures_receiver);
        assert!(!specs[2].captures_receiver);
        assert!(specs[3].captures_receiver);
    }

    #[test]
    fn session_seeds_exact_boundaries_and_dense_provenance() {
        let cancellation = CancellationToken::default();
        let start =
            ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
                .expect("lowering start");

        assert_eq!(start.entry.index(), 0);
        assert_eq!(start.normal_exit.index(), 1);
        assert_eq!(start.exceptional_exit.index(), 2);
        assert_eq!(
            start.session.metadata(start.entry).unwrap().source.index(),
            0
        );
        assert_eq!(start.session.point_metadata.len(), 3);
    }

    #[test]
    fn cached_value_insertion_retains_one_row() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let metadata = session
            .add_mapping(&mut builder, anchor(8, 14, 0), SourceMappingKind::Exact)
            .expect("value mapping");
        let mut cache = HashMap::default();

        let first = session
            .insert_cached_value_with_metadata(
                &mut builder,
                &mut cache,
                42,
                metadata,
                SemanticValueKind::Temporary,
            )
            .expect("first cached value");
        let (parts, _) = builder.finish_with_work().expect("finished parts");

        assert_eq!(cache.get(&42), Some(&first));
        assert_eq!(parts.values.len(), 1);
    }

    #[test]
    fn c_style_loop_schedules_execution_and_continue_targets() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            entry,
            normal_exit,
            function_scope,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let mut points = Vec::new();
        for occurrence in 0..6 {
            let metadata = session
                .add_mapping(
                    &mut builder,
                    anchor(20 + occurrence, 21 + occurrence, occurrence),
                    SourceMappingKind::Exact,
                )
                .expect("loop mapping");
            points.push(
                session
                    .add_point(&mut builder, metadata, Vec::new())
                    .expect("loop point"),
            );
        }
        let [condition, body, update_one, update_two, init_one, init_two] = points.as_slice()
        else {
            panic!("expected six loop points");
        };
        type LoopWork = (
            &'static str,
            u8,
            ProgramPointId,
            ControlTarget,
            Option<ControlTarget>,
            ScopeFrameId,
        );
        let mut stack: Vec<LoopWork> = Vec::new();

        schedule_c_style_loop(
            &mut builder,
            &session,
            entry,
            ControlTarget::normal(normal_exit),
            function_scope,
            None,
            &[(1, *init_one), (2, *init_two)],
            Some((3, *condition)),
            *condition,
            (4, *body),
            &[(5, *update_one), (6, *update_two)],
            &mut stack,
            |payload, entry, next, scope| ("init", payload, entry, next, None, scope),
            |payload, entry, next, scope| ("update", payload, entry, next, None, scope),
            |payload, entry, next, scope| ("body", payload, entry, next, None, scope),
            |payload, entry, when_true, when_false, scope| {
                (
                    "condition",
                    payload,
                    entry,
                    when_true,
                    Some(when_false),
                    scope,
                )
            },
        )
        .expect("scheduled C-style loop");

        let execution = stack.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(
            execution
                .iter()
                .map(|work| (work.0, work.1))
                .collect::<Vec<_>>(),
            vec![
                ("init", 1),
                ("init", 2),
                ("condition", 3),
                ("body", 4),
                ("update", 5),
                ("update", 6),
            ]
        );
        assert_eq!(execution[0].3, ControlTarget::normal(*init_two));
        assert_eq!(execution[1].3, ControlTarget::normal(*condition));
        assert_eq!(
            execution[2].3,
            ControlTarget {
                point: *body,
                kind: ControlEdgeKind::ConditionalTrue,
            }
        );
        assert_eq!(
            execution[2].4,
            Some(ControlTarget {
                point: normal_exit,
                kind: ControlEdgeKind::ConditionalFalse,
            })
        );
        assert_eq!(execution[3].3, ControlTarget::normal(*update_one));
        assert_eq!(execution[4].3, ControlTarget::normal(*update_two));
        assert_eq!(
            execution[5].3,
            ControlTarget {
                point: *condition,
                kind: ControlEdgeKind::LoopBack,
            }
        );

        let loop_scope = execution[0].5;
        let continue_route = builder
            .resolve_completion(
                loop_scope,
                &CompletionRequest::new(CompletionKind::Continue, None),
            )
            .expect("continue route");
        assert_eq!(continue_route.destination().target(), *update_one);
        assert_eq!(
            continue_route.destination().edge_kind(),
            ControlEdgeKind::Normal
        );
    }

    #[test]
    fn await_scaffold_emits_exact_suspend_resume_core() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let mut occurrence = 0;
        let scaffold = session
            .add_await_scaffold(&mut builder, |session, builder| {
                let current = occurrence;
                occurrence += 1;
                session.add_mapping(builder, anchor(8, 14, current), SourceMappingKind::Exact)
            })
            .expect("await scaffold");
        let (parts, _) = builder.finish_with_work().expect("finished parts");

        assert_eq!(scaffold.suspend.index(), 3);
        assert_eq!(scaffold.normal_resume.index(), 4);
        assert_eq!(scaffold.exceptional_resume.index(), 5);
        assert_eq!(scaffold.awaited.index(), 0);
        assert_eq!(scaffold.result.index(), 1);
        let resume_edges = parts
            .control_edges
            .iter()
            .filter(|edge| edge.source_point == scaffold.suspend)
            .map(|edge| (edge.target_point, edge.kind))
            .collect::<Vec<_>>();
        assert_eq!(
            resume_edges,
            vec![
                (scaffold.normal_resume, ControlEdgeKind::AsyncNormal),
                (
                    scaffold.exceptional_resume,
                    ControlEdgeKind::AsyncExceptional
                ),
            ]
        );
    }

    #[test]
    fn await_scaffold_preserves_mapping_point_budget_order() {
        let mut limits = SemanticBudget::default().limits();
        limits.program_points = 4;
        let budget = SemanticBudget::new(limits).expect("positive budget");
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            ..
        } = ProcedureLoweringSession::start(parts(), &budget, &cancellation)
            .expect("lowering start");
        let mut occurrence = 0;

        let error = session
            .add_await_scaffold(&mut builder, |session, builder| {
                let current = occurrence;
                occurrence += 1;
                session.add_mapping(builder, anchor(8, 14, current), SourceMappingKind::Exact)
            })
            .expect_err("second await point should exceed the point budget");

        let ProcedureLoweringError::Budget(exceeded, _) = error else {
            panic!("expected a budget error");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::ProgramPoints);
        let work = builder.prospective_work();
        assert_eq!(work.program_points, 4);
        assert_eq!(work.source_mappings, 3);
        assert_eq!(work.evidence, 3);
    }

    #[test]
    fn cleanup_planner_yields_before_allocating_the_next_step() {
        let mut limits = SemanticBudget::default().limits();
        limits.program_points = 5;
        let budget = SemanticBudget::new(limits).expect("positive budget");
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            exceptional_exit,
            function_scope,
            ..
        } = ProcedureLoweringSession::start(parts(), &budget, &cancellation)
            .expect("lowering start");
        let outer_region = CleanupRegionId::new(1);
        let inner_region = CleanupRegionId::new(2);
        let outer_scope = builder.push_scope(
            Some(function_scope),
            ScopeBinding::Cleanup {
                region: outer_region,
            },
        );
        let inner_scope = builder.push_scope(
            Some(outer_scope),
            ScopeBinding::Cleanup {
                region: inner_region,
            },
        );
        let route = builder
            .resolve_completion(
                inner_scope,
                &CompletionRequest::new(CompletionKind::Throw, None),
            )
            .expect("throw route");
        assert_eq!(route.destination().target(), exceptional_exit);

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser
            .parse("fn fixture() {}", None)
            .expect("parsed fixture");
        let node = tree.root_node();
        let regions = [(outer_region, node), (inner_region, node)];
        let mut planner = CleanupRoutePlanner::new(&route);

        let first = planner
            .next(
                &mut builder,
                &mut session,
                &regions,
                |region| region.0,
                |region| region.1,
            )
            .expect("first cleanup step")
            .expect("new outer cleanup specialization");
        assert_eq!(first.entry.index(), 3);

        let relay_metadata = session
            .add_node_mapping(&mut builder, node)
            .expect("relay mapping");
        let relay = session
            .add_point(&mut builder, relay_metadata, Vec::new())
            .expect("relay point");
        assert_eq!(relay.index(), 4);

        let error = planner
            .next(
                &mut builder,
                &mut session,
                &regions,
                |region| region.0,
                |region| region.1,
            )
            .expect_err("inner entry should follow the relay and exceed the point budget");
        let ProcedureLoweringError::Budget(exceeded, _) = error else {
            panic!("expected a budget error");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::ProgramPoints);
        let work = builder.prospective_work();
        assert_eq!(work.program_points, 5);
        assert_eq!(work.source_mappings, 4);
        assert_eq!(work.evidence, 4);
    }

    #[test]
    fn cleanup_planner_reuse_does_not_allocate_provenance() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            normal_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let region_id = CleanupRegionId::new(1);
        let route = builder.normal_cleanup_completion(region_id, normal_exit);

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser
            .parse("fn fixture() {}", None)
            .expect("parsed fixture");
        let node = tree.root_node();
        let regions = [(region_id, node)];

        let mut first_plan = CleanupRoutePlanner::new(&route);
        let first = first_plan
            .next(
                &mut builder,
                &mut session,
                &regions,
                |region| region.0,
                |region| region.1,
            )
            .expect("first cleanup step")
            .expect("new cleanup specialization");
        assert!(
            first_plan
                .next(
                    &mut builder,
                    &mut session,
                    &regions,
                    |region| region.0,
                    |region| region.1,
                )
                .expect("finished first plan")
                .is_none()
        );
        let before_reuse = builder.prospective_work();

        let mut reused_plan = CleanupRoutePlanner::new(&route);
        assert!(
            reused_plan
                .next(
                    &mut builder,
                    &mut session,
                    &regions,
                    |region| region.0,
                    |region| region.1,
                )
                .expect("reused cleanup plan")
                .is_none()
        );
        assert_eq!(
            reused_plan.target(),
            ControlTarget {
                point: first.entry,
                kind: ControlEdgeKind::Cleanup,
            }
        );
        assert_eq!(builder.prospective_work(), before_reuse);
    }

    #[test]
    fn shared_driver_reports_cancellation_with_retained_work() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            builder,
            entry,
            normal_exit,
            exceptional_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        cancellation.cancel();
        let outcome = drive_and_finish_procedure(
            builder,
            [()],
            entry,
            normal_exit,
            exceptional_exit,
            &cancellation,
            |_, (), _| Ok(()),
        );
        assert!(matches!(outcome, Err(ProcedureLoweringError::Cancelled(_))));
    }

    #[test]
    fn batch_lowering_preserves_initial_and_per_procedure_work() {
        let cancellation = CancellationToken::default();
        let initial = SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        };
        let per_procedure = SemanticWork {
            program_points: 3,
            ..SemanticWork::default()
        };
        let outcome = lower_procedure_batch(
            [(), ()],
            initial,
            &SemanticBudget::default(),
            &cancellation,
            |(), _, _| Ok((parts(), per_procedure)),
        )
        .expect("batch outcome");

        assert!(outcome.is_complete());
        assert_eq!(
            outcome.work(),
            sum_lowering_work(initial, sum_lowering_work(per_procedure, per_procedure))
        );
    }

    #[test]
    fn batch_cancellation_retains_precomputed_work_without_lowering() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let called = Cell::new(false);
        let initial = SemanticWork {
            source_bytes: 17,
            ..SemanticWork::default()
        };
        let outcome = lower_procedure_batch(
            [()],
            initial,
            &SemanticBudget::default(),
            &cancellation,
            |(), _, _| {
                called.set(true);
                Ok((parts(), SemanticWork::default()))
            },
        )
        .expect("batch outcome");

        assert!(matches!(outcome, SemanticOutcome::Cancelled { .. }));
        assert_eq!(outcome.work(), initial);
        assert!(!called.get());
    }

    #[test]
    fn occurrence_allocation_is_span_local_and_deterministic() {
        let cancellation = CancellationToken::default();
        let mut start =
            ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
                .expect("lowering start");

        assert_eq!(start.session.next_source_occurrence(10, 20), 0);
        assert_eq!(start.session.next_source_occurrence(10, 20), 1);
        assert_eq!(start.session.next_source_occurrence(11, 20), 0);
    }

    #[test]
    fn separate_function_throw_boundary_remains_dense_and_adapter_visible() {
        let cancellation = CancellationToken::default();
        let (start, throw_boundary) = ProcedureLoweringSession::start_with_function_throw_boundary(
            parts(),
            &SemanticBudget::default(),
            &cancellation,
            true,
        )
        .expect("lowering start");
        let throw_boundary = throw_boundary.expect("separate throw boundary");

        assert_eq!(throw_boundary.index(), 3);
        assert_eq!(start.session.point_metadata.len(), 4);
        assert_eq!(
            start.session.metadata(throw_boundary).unwrap(),
            start.session.metadata(start.exceptional_exit).unwrap()
        );
    }

    #[test]
    fn shared_call_scaffold_publishes_matched_events_and_metadata() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            normal_exit,
            exceptional_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let mapping = session
            .add_mapping(&mut builder, anchor(8, 14, 0), SourceMappingKind::Exact)
            .expect("call mapping");
        let invoke = session
            .add_point(&mut builder, mapping, Vec::new())
            .expect("invoke point");
        let callee = session
            .add_value(&mut builder, invoke, SemanticValueKind::Callable)
            .expect("callee value");
        let call_site = session
            .add_call_site(
                &mut builder,
                CallSiteScaffold {
                    point: invoke,
                    callee,
                    receiver: None,
                    arguments: Box::new([]),
                    result: None,
                    thrown: None,
                    declared_targets: CallableTargetResolution::Unknown,
                    normal_continuation: normal_exit,
                    exceptional_continuation: exceptional_exit,
                },
            )
            .expect("call scaffold");
        let (parts, _) = builder.finish_with_work().expect("finished parts");

        assert_eq!(call_site.index(), 0);
        assert_eq!(parts.call_sites.len(), 1);
        assert_eq!(parts.call_sites[0].source, mapping.source);
        assert!(
            parts.points[invoke.index()]
                .events
                .iter()
                .any(|event| event.effect == SemanticEffect::Invoke { call_site })
        );
        assert!(
            parts.points[normal_exit.index()]
                .events
                .iter()
                .any(|event| {
                    event.effect
                        == SemanticEffect::CallContinuation {
                            call_site,
                            kind: CallContinuationKind::Normal,
                        }
                })
        );
        assert!(
            parts.points[exceptional_exit.index()]
                .events
                .iter()
                .any(|event| {
                    event.effect
                        == SemanticEffect::CallContinuation {
                            call_site,
                            kind: CallContinuationKind::Exceptional,
                        }
                })
        );
    }
}
