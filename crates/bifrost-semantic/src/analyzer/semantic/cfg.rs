//! Private iterative construction mechanics for procedure-local CFGs.

use crate::analyzer::semantic::ir::{
    CleanupActionCursor, CleanupActionEntry, CleanupAnchor, CleanupAnchorPurpose,
    CleanupChainBuilder, CleanupChainNode, CleanupChainNodeId, CleanupEntryRef, CleanupOwnerEntry,
    CleanupProjectionId, CleanupSegment,
};
use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use crate::analyzer::semantic::AllocationId;

use crate::analyzer::semantic::AllocationKind;

use crate::analyzer::semantic::AllocationSite;

use crate::analyzer::semantic::BasicBlock;

use crate::analyzer::semantic::BlockId;

use crate::analyzer::semantic::CallReceiverTypeFact;

use crate::analyzer::semantic::CaptureBinding;

use crate::analyzer::semantic::CaptureId;

use crate::analyzer::semantic::CaptureMode;

use crate::analyzer::semantic::ControlEdge;

use crate::analyzer::semantic::ControlEdgeKind;

use crate::analyzer::semantic::DropBehavior;

use crate::analyzer::semantic::DropFact;

use crate::analyzer::semantic::Evidence;

use crate::analyzer::semantic::EvidenceId;

use crate::analyzer::semantic::GuardFactParts;

use crate::analyzer::semantic::GuardId;

use crate::analyzer::semantic::LoopSite;

use crate::analyzer::semantic::MemoryLocation;

use crate::analyzer::semantic::MemoryLocationId;

use crate::analyzer::semantic::MemoryLocationKind;

use crate::analyzer::semantic::ProcedureSemanticsParts;

use crate::analyzer::semantic::ProgramPoint;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::ScopeEndAt;

use crate::analyzer::semantic::ScopeEndFact;

use crate::analyzer::semantic::SemanticBudget;

use crate::analyzer::semantic::SemanticBudgetExceeded;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticEvent;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SemanticPlace;

use crate::analyzer::semantic::SemanticValue;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::SourceMapping;

use crate::analyzer::semantic::SourceMappingId;

use crate::analyzer::semantic::StatementEntrySite;

use crate::analyzer::semantic::SwitchFactId;

use crate::analyzer::semantic::SwitchFactParts;

use crate::analyzer::semantic::ValueFlowKind;

use crate::analyzer::semantic::ValueId;

#[derive(Debug, Clone)]
struct PendingPoint {
    events: Vec<SemanticEvent>,
    source: SourceMappingId,
    evidence: EvidenceId,
}

/// Mutable graph mechanics used by language-specific iterative lowerers.
///
/// The adapter owns syntax interpretation. This builder owns dense allocation,
/// continuation scopes, prospective budget checks, deterministic block
/// derivation, and the final construction parts consumed by the artifact
/// validator.
#[doc(hidden)]
pub struct ProcedureCfgBuilder {
    parts: ProcedureSemanticsParts,
    points: Vec<PendingPoint>,
    scopes: Vec<ScopeFrame>,
    #[cfg(debug_assertions)]
    scope_cleanup_actions: HashMap<ScopeFrameId, Vec<CleanupActionEntry>>,
    region_scopes: HashMap<CleanupRegionId, ScopeFrameId>,
    cleanup_specializations: HashMap<CleanupKey, ProgramPointId>,
    cleanup_chains: CleanupChainBuilder,
    cleanup_scopes: Vec<PendingCleanupScope>,
    // Base projections remain reusable for sparse moved-owner exclusions (#12490).
    gap_base_projections:
        HashMap<(CleanupChainNodeId, Option<CleanupChainNodeId>, bool), Option<CleanupChainNodeId>>,
    gap_exit_nodes: HashSet<(ProgramPointId, CleanupChainNodeId)>,
    gap_exit_owners: HashSet<(ProgramPointId, crate::analyzer::semantic::ValueId)>,
    gaps_by_point_capability: HashMap<
        (
            ProgramPointId,
            crate::analyzer::semantic::SemanticCapability,
        ),
        Vec<usize>,
    >,
    lifetime_coverage: HashSet<(ProgramPointId, CleanupChainNodeId)>,
    cleanup_plans: HashMap<CleanupPlanKey, ProgramPointId>,
    budget_snapshot: SemanticBudget,
    #[doc(hidden)]
    pub prospective_work: SemanticWork,
    traversal_work: SemanticWork,
}

#[doc(hidden)]
pub fn resolve_abrupt_throw(
    builder: &mut ProcedureCfgBuilder,
    scope: ScopeFrameId,
    value: ValueId,
    catch_binders: &HashMap<ProgramPointId, ValueId>,
) -> Option<(CompletionRoute, Option<SemanticEffect>)> {
    let route =
        builder.resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))?;
    let effect = catch_binders
        .get(&route.destination().target())
        .copied()
        .map(|target| SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Local,
            source: value,
            target,
        });
    Some((route, effect))
}

impl ProcedureCfgBuilder {
    pub(crate) fn new(
        mut parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
    ) -> Result<Self, SemanticBudgetExceeded> {
        assert!(
            parts.points.is_empty()
                && parts.blocks.is_empty()
                && parts.control_edges.is_empty()
                && parts.guard_facts.is_empty(),
            "CFG builder requires construction parts without prebuilt topology"
        );
        assert!(
            parts.values.is_empty()
                && parts.allocations.is_empty()
                && parts.memory_locations.is_empty()
                && parts.captures.is_empty()
                && parts.call_sites.is_empty()
                && parts.gaps.is_empty()
                && parts.go_predeclared_builtin_assumptions.is_empty()
                && parts.statement_entries.is_empty()
                && parts.loop_sites.is_empty(),
            "CFG builder requires side-table rows to be allocated through the builder"
        );
        let prospective_work = initial_procedure_cfg_work(
            &parts.locator,
            parts.source_mappings.iter().map(|mapping| &mapping.locator),
            parts
                .evidence_rows
                .iter()
                .map(|evidence| evidence.sources.len()),
        )
        .conservative_add(SemanticWork {
            nested_entries: parts.source_range_holes.len(),
            ..SemanticWork::default()
        });
        budget.check_admission(prospective_work)?;
        parts.points.clear();
        Ok(Self {
            parts,
            points: Vec::new(),
            scopes: Vec::new(),
            #[cfg(debug_assertions)]
            scope_cleanup_actions: HashMap::default(),
            region_scopes: HashMap::default(),
            cleanup_specializations: HashMap::default(),
            cleanup_chains: CleanupChainBuilder::default(),
            cleanup_scopes: Vec::new(),
            gap_base_projections: HashMap::default(),
            gap_exit_nodes: HashSet::default(),
            gap_exit_owners: HashSet::default(),
            gaps_by_point_capability: HashMap::default(),
            lifetime_coverage: HashSet::default(),
            cleanup_plans: HashMap::default(),
            budget_snapshot: budget.clone(),
            prospective_work,
            traversal_work: SemanticWork::default(),
        })
    }

    #[doc(hidden)]
    pub const fn prospective_work(&self) -> SemanticWork {
        self.prospective_work
    }

    /// Record a cleanup construction operation as work. Traversal and visits to
    /// existing chain rows never refuse; callers admit the rows they retain.
    #[doc(hidden)]
    pub fn note_cleanup_construction_step(&mut self) {
        self.cleanup_chains.construction_steps += 1;
    }

    /// Record one adapter-owned traversal step that is not otherwise
    /// represented by a retained CFG row.
    #[doc(hidden)]
    pub fn descend_nested_entry(&mut self) {
        let candidate = self.traversal_work.conservative_add(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        });

        self.traversal_work = candidate;
        self.budget_snapshot.note_lowering_work(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        });
    }

    pub(crate) fn add_source_mapping(
        &mut self,
        mapping: SourceMapping,
    ) -> Result<SourceMappingId, SemanticBudgetExceeded> {
        let id = SourceMappingId::try_from_index(self.parts.source_mappings.len())
            .expect("source-mapping count is bounded by the u32 semantic budget");
        assert_eq!(mapping.id, id, "source mappings must use dense builder IDs");
        self.reserve(SemanticWork::conservative_add(
            SemanticWork {
                source_mappings: 1,
                ..SemanticWork::default()
            },
            locator_work(&mapping.locator, 1),
        ))?;
        self.parts.source_mappings.push(mapping);
        Ok(id)
    }

    /// Read the control graph before final block derivation.
    #[doc(hidden)]
    pub fn control_graph(&self) -> crate::analyzer::semantic::cfg_algorithms::DenseUsizeGraph {
        crate::analyzer::semantic::cfg_algorithms::DenseUsizeGraph::new(
            self.points.len(),
            self.parts
                .control_edges
                .iter()
                .map(|edge| (edge.source_point.index(), edge.target_point.index())),
        )
    }

    /// Borrow the complete pending IR for shared initialization proofs.
    pub fn binding_initialization_ir<'a>(
        &'a self,
        entry: ProgramPointId,
        moves: &'a [crate::analyzer::semantic::MoveOutFact],
        declarations: &'a [(ProgramPointId, ValueId)],
    ) -> impl crate::analyzer::semantic::binding_initialization::BindingInitializationIr + 'a {
        struct PendingIr<'a> {
            builder: &'a ProcedureCfgBuilder,
            entry: ProgramPointId,
            moves: &'a [crate::analyzer::semantic::MoveOutFact],
            declarations: &'a [(ProgramPointId, ValueId)],
        }
        impl crate::analyzer::semantic::binding_initialization::BindingInitializationIr for PendingIr<'_> {
            fn entry_point(&self) -> ProgramPointId {
                self.entry
            }
            fn point_count(&self) -> usize {
                self.builder.points.len()
            }
            fn values(&self) -> &[SemanticValue] {
                &self.builder.parts.values
            }
            fn events_at(&self, point: ProgramPointId) -> &[SemanticEvent] {
                &self.builder.points[point.index()].events
            }
            fn move_outs(&self) -> &[crate::analyzer::semantic::MoveOutFact] {
                self.moves
            }
            fn uninitialized_declarations(&self) -> &[(ProgramPointId, ValueId)] {
                self.declarations
            }
        }
        PendingIr {
            builder: self,
            entry,
            moves,
            declarations,
        }
    }

    /// Pending allocation facts used to recognize fresh initializer storage.
    pub fn allocations(&self) -> &[AllocationSite] {
        &self.parts.allocations
    }

    /// Borrow one pending structured memory location for root attribution.
    pub fn memory_location(&self, id: MemoryLocationId) -> &MemoryLocation {
        &self.parts.memory_locations[id.index()]
    }

    /// Event insertion position retained by a deferred obligation publisher.
    pub fn point_event_count(&self, point: ProgramPointId) -> usize {
        self.points[point.index()].events.len()
    }

    /// Restore deferred gap events to their original semantic position.
    pub fn move_last_gap_events_before(
        &mut self,
        point: ProgramPointId,
        before: usize,
        count: usize,
    ) {
        let events = &mut self.points[point.index()].events;
        assert!(before <= events.len() - count);
        assert!(
            events[events.len() - count..]
                .iter()
                .all(|event| matches!(event.effect, SemanticEffect::Gap { .. }))
        );
        events[before..].rotate_right(count);
    }

    /// Raw obligations retained so far, before final block derivation.
    pub fn gaps(&self) -> &[SemanticGap] {
        &self.parts.gaps
    }

    /// Index writes in one pass over the pending graph.
    #[doc(hidden)]
    pub fn assignment_points_by_value(
        &self,
    ) -> impl Iterator<Item = (crate::analyzer::semantic::ValueId, ProgramPointId)> + '_ {
        self.points.iter().enumerate().flat_map(|(index, point)| {
            let point_id =
                ProgramPointId::try_from_index(index).expect("builder points use dense IDs");
            point
                .events
                .iter()
                .filter_map(move |event| match event.effect {
                    SemanticEffect::Assignment { target, .. }
                    | SemanticEffect::ValueFlow { target, .. } => Some((target, point_id)),
                    _ => None,
                })
        })
    }

    /// Whether a scoped fact already has a gap obligation.
    #[doc(hidden)]
    pub fn has_gap(
        &mut self,
        point: ProgramPointId,
        subject: crate::analyzer::semantic::SemanticGapSubject,
        capability: crate::analyzer::semantic::SemanticCapability,
    ) -> Result<bool, SemanticBudgetExceeded> {
        use crate::analyzer::semantic::SemanticGapSubject;
        let gaps = self.gaps_by_point_capability.get(&(point, capability));
        if gaps.is_some_and(|indices| {
            indices
                .iter()
                .any(|&index| self.parts.gaps[index].subject == subject)
        }) {
            return Ok(true);
        }
        let SemanticGapSubject::Value(owner) = subject else {
            return Ok(false);
        };
        let Some(indices) = gaps else {
            return Ok(false);
        };
        if !indices.iter().any(|&index| {
            matches!(
                self.parts.gaps[index].subject,
                SemanticGapSubject::CleanupOwners(_)
            )
        }) {
            return Ok(false);
        }
        self.reserve(SemanticWork {
            nested_entries: self.cleanup_chains.pending_membership_entries(),
            ..SemanticWork::default()
        })?;
        // Reserving borrows the builder mutably, so the key is read again.
        Ok(self.gaps_by_point_capability[&(point, capability)]
            .iter()
            .any(|&index| match self.parts.gaps[index].subject {
                SemanticGapSubject::CleanupOwners(segment) => {
                    self.cleanup_chains.contains_owner(segment, owner)
                }
                _ => false,
            }))
    }

    #[doc(hidden)]
    pub fn source_mapping(&self, id: SourceMappingId) -> &SourceMapping {
        self.parts
            .source_mappings
            .get(id.index())
            .expect("a point's registered source mapping exists")
    }

    #[doc(hidden)]
    pub fn value_source_mapping(&self, id: ValueId) -> &SourceMapping {
        let value = self
            .parts
            .values
            .get(id.index())
            .expect("a registered builder value exists");
        self.source_mapping(value.source)
    }

    pub(crate) fn add_loop_site(&mut self, site: LoopSite) -> Result<(), SemanticBudgetExceeded> {
        assert!(
            site.header.index() < self.points.len() && site.body.index() < self.points.len(),
            "loop site points exist"
        );
        assert!(
            site.source.index() < self.parts.source_mappings.len(),
            "loop site source exists"
        );
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.parts.loop_sites.push(site);
        Ok(())
    }

    pub(crate) fn add_statement_entry(
        &mut self,
        site: StatementEntrySite,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(
            site.point.index() < self.points.len(),
            "statement entry point exists"
        );
        assert!(
            site.source.index() < self.parts.source_mappings.len(),
            "statement entry source exists"
        );
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.parts.statement_entries.push(site);
        Ok(())
    }

    pub(crate) fn add_evidence(
        &mut self,
        evidence: Evidence,
    ) -> Result<EvidenceId, SemanticBudgetExceeded> {
        let id = EvidenceId::try_from_index(self.parts.evidence_rows.len())
            .expect("evidence count is bounded by the u32 semantic budget");
        assert_eq!(evidence.id, id, "evidence rows must use dense builder IDs");
        self.reserve(SemanticWork {
            evidence: 1,
            nested_entries: evidence.sources.len(),
            ..SemanticWork::default()
        })?;
        self.parts.evidence_rows.push(evidence);
        Ok(id)
    }

    pub(crate) fn set_call_target_dispatch(
        &mut self,
        id: crate::analyzer::semantic::SemanticGapId,
        dispatch: crate::analyzer::semantic::CallTargetDispatch,
    ) {
        let gap = &mut self.parts.gaps[id.index()];
        assert_eq!(
            gap.capability,
            crate::analyzer::semantic::SemanticCapability::Calls
        );
        gap.dispatch = dispatch;
    }

    pub(crate) fn add_gap(
        &mut self,
        gap: SemanticGap,
    ) -> Result<crate::analyzer::semantic::SemanticGapId, SemanticBudgetExceeded> {
        let id = crate::analyzer::semantic::SemanticGapId::try_from_index(self.parts.gaps.len())
            .expect("gap count is bounded by the u32 semantic budget");
        assert_eq!(gap.id, id, "gaps must use dense builder IDs");
        self.reserve(SemanticWork {
            gaps: 1,
            owned_text_bytes: gap.detail.len(),
            ..SemanticWork::default()
        })?;
        let key = (gap.point, gap.capability);
        self.parts.gaps.push(gap);
        self.gaps_by_point_capability
            .entry(key)
            .or_default()
            .push(id.index());
        Ok(id)
    }

    pub(crate) fn add_value(
        &mut self,
        value: SemanticValue,
    ) -> Result<crate::analyzer::semantic::ValueId, SemanticBudgetExceeded> {
        let id = crate::analyzer::semantic::ValueId::try_from_index(self.parts.values.len())
            .expect("value count is bounded by the u32 semantic budget");
        assert_eq!(value.id, id, "values must use dense builder IDs");
        let owned_text_bytes = match &value.kind {
            crate::analyzer::semantic::SemanticValueKind::LanguageDefined(name) => name.len(),
            crate::analyzer::semantic::SemanticValueKind::Parameter {
                multiplicity, name, ..
            } => name
                .as_deref()
                .map_or(0, str::len)
                .saturating_add(match multiplicity {
                    crate::analyzer::semantic::FormalMultiplicity::Rest(
                        crate::analyzer::semantic::ArgumentDomain::LanguageDefined(name),
                    ) => name.len(),
                    crate::analyzer::semantic::FormalMultiplicity::One
                    | crate::analyzer::semantic::FormalMultiplicity::Rest(
                        crate::analyzer::semantic::ArgumentDomain::Positional
                        | crate::analyzer::semantic::ArgumentDomain::Keyword
                        | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                    ) => 0,
                }),
            _ => 0,
        };
        self.reserve(SemanticWork {
            values: 1,
            owned_text_bytes,
            ..SemanticWork::default()
        })?;
        self.parts.values.push(value);
        Ok(id)
    }

    pub(crate) fn add_allocation(
        &mut self,
        allocation: AllocationSite,
    ) -> Result<AllocationId, SemanticBudgetExceeded> {
        let id = AllocationId::try_from_index(self.parts.allocations.len())
            .expect("allocation count is bounded by the u32 semantic budget");
        assert_eq!(allocation.id, id, "allocations must use dense builder IDs");
        let owned_text_bytes = match &allocation.kind {
            AllocationKind::LanguageDefined(name) => name.len(),
            AllocationKind::Object
            | AllocationKind::Array
            | AllocationKind::Slice
            | AllocationKind::Callable
            | AllocationKind::ClosureEnvironment
            | AllocationKind::SharedCell => 0,
        };
        self.reserve(SemanticWork {
            allocations: 1,
            owned_text_bytes,
            ..SemanticWork::default()
        })?;
        self.parts.allocations.push(allocation);
        Ok(id)
    }

    pub(crate) fn add_memory_location(
        &mut self,
        location: MemoryLocation,
    ) -> Result<MemoryLocationId, SemanticBudgetExceeded> {
        let id = MemoryLocationId::try_from_index(self.parts.memory_locations.len())
            .expect("memory-location count is bounded by the u32 semantic budget");
        assert_eq!(
            location.id, id,
            "memory locations must use dense builder IDs"
        );
        let work = match &location.kind {
            MemoryLocationKind::Field { member, .. } | MemoryLocationKind::Static { member } => {
                locator_work(member, 1)
            }
            MemoryLocationKind::Property { key, .. } => SemanticWork {
                owned_text_bytes: key.len(),
                ..SemanticWork::default()
            },
            MemoryLocationKind::Index { .. }
            | MemoryLocationKind::Dereference { .. }
            | MemoryLocationKind::LexicalCell { .. }
            | MemoryLocationKind::Capture { .. } => SemanticWork::default(),
        };
        self.reserve(SemanticWork::conservative_add(
            SemanticWork {
                memory_locations: 1,
                ..SemanticWork::default()
            },
            work,
        ))?;
        self.parts.memory_locations.push(location);
        Ok(id)
    }

    pub(crate) fn add_capture(
        &mut self,
        capture: CaptureBinding,
    ) -> Result<CaptureId, SemanticBudgetExceeded> {
        let id = CaptureId::try_from_index(self.parts.captures.len())
            .expect("capture count is bounded by the u32 semantic budget");
        assert_eq!(capture.id, id, "captures must use dense builder IDs");
        let owned_text_bytes = match &capture.mode {
            CaptureMode::LanguageDefined(name) => name.len(),
            CaptureMode::Value
            | CaptureMode::Move
            | CaptureMode::SharedCell
            | CaptureMode::MutableCell
            | CaptureMode::Receiver
            | CaptureMode::Unknown => 0,
        };
        self.reserve(SemanticWork {
            captures: 1,
            owned_text_bytes,
            ..SemanticWork::default()
        })?;
        self.parts.captures.push(capture);
        Ok(id)
    }

    pub(crate) fn add_call_site(
        &mut self,
        call_site: SemanticCallSite,
    ) -> Result<crate::analyzer::semantic::CallSiteId, SemanticBudgetExceeded> {
        let id = crate::analyzer::semantic::CallSiteId::try_from_index(self.parts.call_sites.len())
            .expect("call-site count is bounded by the u32 semantic budget");
        assert_eq!(call_site.id, id, "call sites must use dense builder IDs");
        let owned_text_bytes = call_site
            .arguments
            .iter()
            .map(|argument| {
                argument
                    .keyword
                    .as_deref()
                    .map_or(0, str::len)
                    .saturating_add(match argument.expansion.domain() {
                        Some(crate::analyzer::semantic::ArgumentDomain::LanguageDefined(name)) => {
                            name.len()
                        }
                        Some(
                            crate::analyzer::semantic::ArgumentDomain::Positional
                            | crate::analyzer::semantic::ArgumentDomain::Keyword
                            | crate::analyzer::semantic::ArgumentDomain::PositionalOrKeyword,
                        )
                        | None => 0,
                    })
            })
            .fold(0usize, usize::saturating_add);
        let mut work = SemanticWork {
            call_sites: 1,
            nested_entries: call_site.arguments.len(),
            owned_text_bytes,
            ..SemanticWork::default()
        };
        if let Some(selection) = &call_site.member_selection {
            work.nested_entries = work.nested_entries.saturating_add(1);
            work.owned_text_bytes = work.owned_text_bytes.saturating_add(selection.member.len());
            if let Some(crate::analyzer::semantic::SemanticPlace::LocalBinding(locator)) =
                &selection.receiver_place
            {
                work = work.conservative_add(locator_work(locator, 1));
            }
        }
        self.reserve(work)?;
        self.parts.call_sites.push(call_site);
        Ok(id)
    }

    /// Record the written receiver type of a method call. The call site must
    /// already be published, and facts arrive in increasing call-site order.
    #[doc(hidden)]
    pub fn add_call_receiver_type_fact(
        &mut self,
        fact: CallReceiverTypeFact,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(
            fact.call_site.index() < self.parts.call_sites.len(),
            "receiver type fact must follow its published call site"
        );
        debug_assert!(
            self.parts
                .receiver_type_facts
                .last()
                .is_none_or(|previous| previous.call_site < fact.call_site),
            "receiver type facts must be in strictly increasing call-site order"
        );
        let owned_text_bytes = fact
            .receiver_type
            .iter()
            .map(|segment| segment.len())
            .fold(fact.member.len(), usize::saturating_add);
        self.reserve(SemanticWork {
            nested_entries: fact.receiver_type.len(),
            owned_text_bytes,
            ..SemanticWork::default()
        })?;
        self.parts.receiver_type_facts.push(fact);
        Ok(())
    }

    /// Retain an inert syntax projection for selected declaration admission.
    #[doc(hidden)]
    pub fn next_guarded_pattern_projection_ordinal(&self) -> u32 {
        u32::try_from(self.parts.guarded_pattern_projections.len())
            .expect("guarded projection count is bounded by the semantic budget")
    }

    /// Retain an inert syntax projection for selected declaration admission.
    #[doc(hidden)]
    pub fn add_guarded_pattern_projection(
        &mut self,
        candidate: crate::analyzer::semantic::GuardedPatternProjection,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert_eq!(
            candidate.ordinal as usize,
            self.parts.guarded_pattern_projections.len(),
            "guarded projection ordinals must be dense"
        );
        let owned_text_bytes = candidate
            .path
            .iter()
            .map(|step| match step {
                crate::analyzer::semantic::PatternProjectionStep::Tuple(_)
                | crate::analyzer::semantic::PatternProjectionStep::Element => 0,
                crate::analyzer::semantic::PatternProjectionStep::Named(name) => name.len(),
                crate::analyzer::semantic::PatternProjectionStep::Variant { declaration } => {
                    declaration.len()
                }
            })
            .sum();
        self.reserve(SemanticWork {
            nested_entries: candidate.path.len().saturating_add(1),
            owned_text_bytes,
            ..SemanticWork::default()
        })?;
        self.parts.guarded_pattern_projections.push(candidate);
        Ok(())
    }

    pub(crate) fn add_point(
        &mut self,
        events: Vec<SemanticEvent>,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> Result<ProgramPointId, SemanticBudgetExceeded> {
        let id = ProgramPointId::try_from_index(self.points.len())
            .expect("program-point count is bounded by the u32 semantic budget");
        self.reserve(SemanticWork {
            program_points: 1,
            events: events.len(),
            // One offset in each adjacency direction.
            nested_entries: 2,
            ..SemanticWork::default()
        })?;
        self.points.push(PendingPoint {
            events,
            source,
            evidence,
        });
        Ok(id)
    }

    pub(crate) fn last_event_is_memory(&self, point: ProgramPointId) -> bool {
        self.points[point.index()]
            .events
            .last()
            .is_some_and(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::MemoryLoad { .. }
                        | SemanticEffect::MemoryStore { .. }
                        | SemanticEffect::ValueFlow {
                            kind: crate::analyzer::semantic::ValueFlowKind::MemoryLoad { .. },
                            ..
                        }
                )
            })
    }

    pub(crate) fn event_count(&self, point: ProgramPointId) -> usize {
        self.points[point.index()].events.len()
    }

    pub(crate) fn append_event(
        &mut self,
        point: ProgramPointId,
        event: SemanticEvent,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(point.index() < self.points.len(), "event point must exist");
        self.reserve(SemanticWork {
            events: 1,
            ..SemanticWork::default()
        })?;
        self.points[point.index()].events.push(event);
        Ok(())
    }

    /// Retain one normalized decision-point condition.
    ///
    /// The arms are named by destination and edge kind because control-edge IDs
    /// only exist once the canonical table is sorted at freeze time. The caller
    /// must have already added the arm edges: [`Self::seal_unreachable_regions`]
    /// drops an arm whose edge it removes, and the IR validator rejects an arm
    /// that names an edge the guard's point does not have.
    pub(crate) fn add_guard_fact(
        &mut self,
        guard: GuardFactParts,
    ) -> Result<GuardId, SemanticBudgetExceeded> {
        let id = GuardId::try_from_index(self.parts.guard_facts.len())
            .expect("guard count is bounded by the u32 semantic budget");
        assert_eq!(guard.id, id, "guard facts must use dense builder IDs");
        assert!(
            guard.point.index() < self.points.len(),
            "guard point must exist"
        );
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.parts.guard_facts.push(guard);
        Ok(id)
    }

    pub(crate) fn add_switch_fact(
        &mut self,
        fact: SwitchFactParts,
    ) -> Result<SwitchFactId, SemanticBudgetExceeded> {
        let id = SwitchFactId::try_from_index(self.parts.switch_facts.len())
            .expect("switch-fact count is bounded by the u32 semantic budget");
        assert_eq!(fact.id, id, "switch facts must use dense builder IDs");
        assert!(
            fact.point.index() < self.points.len(),
            "switch point must exist"
        );
        self.reserve(SemanticWork {
            nested_entries: fact.cases.len().saturating_add(1),
            ..SemanticWork::default()
        })?;
        self.parts.switch_facts.push(fact);
        Ok(id)
    }

    pub(crate) fn add_edge(&mut self, edge: ControlEdge) -> Result<(), SemanticBudgetExceeded> {
        self.reserve(SemanticWork {
            control_edges: 1,
            // The reverse adjacency retains one procedure-local edge ID.
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.parts.control_edges.push(edge);
        Ok(())
    }

    #[doc(hidden)]
    pub fn push_scope(
        &mut self,
        parent: Option<ScopeFrameId>,
        binding: ScopeBinding,
    ) -> ScopeFrameId {
        if let Some(parent) = parent {
            assert!(
                parent.index() < self.scopes.len(),
                "scope parent must already exist"
            );
        }
        let id = ScopeFrameId::try_from_index(self.scopes.len());
        let inherited = parent.and_then(|parent| self.capture_cleanup_scope(parent));
        let region = match &binding {
            ScopeBinding::Cleanup { region } => Some(*region),
            _ => None,
        };
        self.cleanup_scopes.push(PendingCleanupScope {
            head: inherited,
            inherited,
            region,
            started: false,
            actions: Vec::new(),
            owners: Vec::new(),
        });
        if let Some(region) = region {
            assert!(self.region_scopes.insert(region, id).is_none());
        }
        let targets = std::array::from_fn(|index| {
            let kind = COMPLETION_KINDS[index];
            binding_target(&binding, kind, None)
                .map(|target| (id, target))
                .or_else(|| parent.and_then(|parent| self.scopes[parent.index()].targets[index]))
        });
        let labeled = if matches!(
            &binding,
            ScopeBinding::Disconnected { .. }
                | ScopeBinding::Loop { label: Some(_), .. }
                | ScopeBinding::Breakable { label: Some(_), .. }
        ) {
            Some(id)
        } else {
            parent.and_then(|parent| self.scopes[parent.index()].labeled)
        };
        let function_throw_target = match &binding {
            ScopeBinding::Function { throw_target, .. } => Some(*throw_target),
            _ => parent.and_then(|parent| self.scopes[parent.index()].function_throw_target),
        };
        self.scopes.push(ScopeFrame {
            function_throw_target,
            parent,
            binding,
            targets,
            labeled,
        });
        id
    }

    /// Append one ordered lifecycle action to a cleanup scope.
    #[allow(dead_code)] // Lane C consumes this producer hook in the dependent change.
    #[doc(hidden)]
    pub fn register_scope_cleanup_action(
        &mut self,
        scope: ScopeFrameId,
        action: ScopeCleanupAction,
    ) -> Result<(), SemanticBudgetExceeded> {
        self.register_scope_cleanup_entry(
            scope,
            CleanupActionEntry {
                action,
                incomplete: None,
            },
        )
    }

    pub fn register_scope_cleanup_entry(
        &mut self,
        scope: ScopeFrameId,
        entry: CleanupActionEntry,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(
            matches!(
                self.scopes[scope.index()].binding,
                ScopeBinding::Cleanup { .. }
            ),
            "cleanup actions belong to cleanup scope frames"
        );
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        #[cfg(debug_assertions)]
        self.scope_cleanup_actions
            .entry(scope)
            .or_default()
            .push(entry.clone());
        self.cleanup_scopes[scope.index()].actions.push(entry);
        Ok(())
    }

    /// Register owner metadata once, independently of the exits that use it.
    pub fn register_scope_cleanup_owner(
        &mut self,
        scope: ScopeFrameId,
        owner: CleanupOwnerEntry,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(matches!(
            self.scopes[scope.index()].binding,
            ScopeBinding::Cleanup { .. }
        ));
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.cleanup_scopes[scope.index()].owners.push(owner);
        Ok(())
    }

    /// Freeze this scope's pending buffer. Previously captured chunks never change.
    fn capture_cleanup_scope(&mut self, scope: ScopeFrameId) -> Option<CleanupChainNodeId> {
        let pending = &mut self.cleanup_scopes[scope.index()];
        if pending.region.is_some()
            && (!pending.started || !pending.actions.is_empty() || !pending.owners.is_empty())
        {
            let node = CleanupChainNode {
                parent: pending.head,
                region: if pending.started {
                    None
                } else {
                    pending.region
                },
                actions: std::mem::take(&mut pending.actions).into_boxed_slice(),
                owners: std::mem::take(&mut pending.owners).into_boxed_slice(),
            };
            pending.head = Some(self.cleanup_chains.intern(node));
            pending.started = true;
        }
        pending.head
    }

    /// Capture the immutable cleanup path through `scope`, excluding `stop_before`.
    pub fn capture_cleanup_segment(
        &mut self,
        scope: ScopeFrameId,
        stop_before: Option<ScopeFrameId>,
    ) -> CleanupSegment {
        let head = self.capture_cleanup_scope(scope);
        let stop = stop_before.and_then(|stop| self.capture_cleanup_scope(stop));
        CleanupSegment { head, stop }
    }

    /// Capture only the entries registered in this scope.
    pub fn capture_local_cleanup_segment(&mut self, scope: ScopeFrameId) -> CleanupSegment {
        let head = self.capture_cleanup_scope(scope);
        CleanupSegment {
            head,
            stop: self.cleanup_scopes[scope.index()].inherited,
        }
    }

    pub fn cleanup_action(&self, cursor: CleanupActionCursor) -> &CleanupActionEntry {
        self.cleanup_chains.action(cursor)
    }

    pub fn append_direct_incomplete(
        &mut self,
        fact: crate::analyzer::semantic::SemanticIncompleteFact,
    ) -> Result<(), SemanticBudgetExceeded> {
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.parts.incomplete_facts.push(fact);
        Ok(())
    }

    pub fn append_direct_pointer_invalidation(
        &mut self,
        fact: crate::analyzer::semantic::PointerInvalidation,
    ) -> Result<(), SemanticBudgetExceeded> {
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.parts.pointer_invalidations.push(fact);
        Ok(())
    }

    /// Cover each immutable node once at a lifetime destination.
    pub fn append_lifetime_end_anchor(
        &mut self,
        segment: CleanupSegment,
        destination: CompletionTarget,
    ) -> Result<(), SemanticBudgetExceeded> {
        let mut stop = segment.head;
        while stop != segment.stop {
            self.note_cleanup_construction_step();
            let node = stop.expect("nonempty cleanup prefix has a head");
            if !self.lifetime_coverage.insert((destination.target(), node)) {
                break;
            }
            stop = self.cleanup_chains.node(node).parent;
        }
        let uncovered = CleanupSegment {
            head: segment.head,
            stop,
        };
        if !uncovered.is_empty() {
            self.append_cleanup_anchor(
                destination.target(),
                uncovered,
                destination,
                CleanupAnchorPurpose::LifetimeEnd,
                None,
            )?;
        }
        Ok(())
    }

    /// Publish one compact relation, recording the direct-row insertion boundaries.
    pub fn append_cleanup_anchor(
        &mut self,
        point: ProgramPointId,
        segment: CleanupSegment,
        destination: CompletionTarget,
        purpose: CleanupAnchorPurpose,
        projection: Option<CleanupProjectionId>,
    ) -> Result<(), SemanticBudgetExceeded> {
        assert!(point.index() < self.points.len());
        assert!(destination.target.index() < self.points.len());
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        let offset = |count| u32::try_from(count).expect("direct fact counts fit u32");
        self.cleanup_chains.append_anchor(CleanupAnchor {
            point,
            segment,
            destination: destination.target,
            destination_kind: destination.kind,
            edge_kind: destination.edge_kind,
            purpose,
            projection,
            drop_offset: offset(self.parts.drops.len()),
            scope_end_offset: offset(self.parts.scope_ends.len()),
            incomplete_offset: offset(self.parts.incomplete_facts.len()),
            pointer_invalidation_offset: offset(self.parts.pointer_invalidations.len()),
        });
        Ok(())
    }

    #[allow(dead_code)] // Lane C consumes this producer hook in the dependent change.
    fn add_cleanup_action_fact(
        &mut self,
        point: ProgramPointId,
        action: &ScopeCleanupAction,
    ) -> Result<(), SemanticBudgetExceeded> {
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        match action {
            ScopeCleanupAction::Drop {
                place,
                behavior,
                source,
                evidence,
            } => self.parts.drops.push(DropFact {
                place: place.clone(),
                point,
                behavior: behavior.clone(),
                source: *source,
                evidence: *evidence,
            }),
            ScopeCleanupAction::ScopeEnd {
                place,
                source,
                evidence,
            } => self.parts.scope_ends.push(ScopeEndFact {
                place: place.clone(),
                at: ScopeEndAt::Point(point),
                source: *source,
                evidence: *evidence,
            }),
        }
        Ok(())
    }

    #[allow(dead_code)] // Lane C consumes this producer hook in the dependent change.
    #[doc(hidden)]
    pub fn emit_cleanup_action_fact(
        &mut self,
        point: ProgramPointId,
        action: &ScopeCleanupAction,
    ) -> Result<(), SemanticBudgetExceeded> {
        self.add_cleanup_action_fact(point, action)
    }

    /// Resolve an abrupt completion by walking persistent parent-linked scope
    /// frames iteratively. Cleanup regions are returned inner-to-outer.
    #[doc(hidden)]
    pub fn resolve_completion(
        &mut self,
        scope: ScopeFrameId,
        request: &CompletionRequest<'_>,
    ) -> Option<CompletionRoute> {
        let (stop, destination) = self.completion_target(scope, request)?;
        let segment = self.capture_cleanup_segment(scope, Some(stop));
        #[cfg(debug_assertions)]
        self.assert_live_cleanup_segment(scope, Some(stop), segment);
        Some(CompletionRoute {
            destination,
            segment,
            projection: None,
        })
    }

    fn completion_target(
        &self,
        scope: ScopeFrameId,
        request: &CompletionRequest<'_>,
    ) -> Option<(ScopeFrameId, CompletionTarget)> {
        if request.label.is_none()
            || !matches!(
                request.kind,
                CompletionKind::Break | CompletionKind::Continue
            )
        {
            return self.scopes.get(scope.index())?.targets[request.kind as usize];
        }
        let mut cursor = self.scopes.get(scope.index())?.labeled;
        while let Some(id) = cursor {
            let frame = &self.scopes[id.index()];
            if let Some(target) = binding_target(&frame.binding, request.kind, request.label) {
                return Some((id, target));
            }
            cursor = frame
                .parent
                .and_then(|parent| self.scopes[parent.index()].labeled);
        }
        None
    }

    #[cfg(debug_assertions)]
    fn assert_live_cleanup_segment(
        &self,
        scope: ScopeFrameId,
        stop: Option<ScopeFrameId>,
        segment: CleanupSegment,
    ) {
        let mut live = Vec::new();
        let mut cursor = Some(scope);
        while cursor != stop {
            let id = cursor.expect("cleanup stop is an ancestor scope");
            let frame = &self.scopes[id.index()];
            if let ScopeBinding::Cleanup { region } = frame.binding {
                if let Some(actions) = self.scope_cleanup_actions.get(&id) {
                    live.extend(actions.iter().map(CleanupEntryRef::Action));
                }
                live.push(CleanupEntryRef::Region(region));
            }
            cursor = frame.parent;
        }
        let frozen: Vec<_> = self
            .cleanup_chains
            .entries(segment)
            .filter(|entry| !matches!(entry, CleanupEntryRef::Owner(_)))
            .collect();
        debug_assert_eq!(
            frozen, live,
            "frozen cleanup chain differs from live ancestor walk"
        );
    }

    pub fn mark_implicit_lifetime_region(&mut self, region: CleanupRegionId) {
        self.cleanup_chains.mark_implicit_lifetime_region(region);
    }

    /// Construction-only prefix differences: destructors, incompletes, explicit regions.
    pub fn cleanup_route_counts(&self, route: &CompletionRoute) -> [usize; 3] {
        self.cleanup_chains
            .route_counts(route.segment, route.projection)
    }

    pub fn cleanup_entries(
        &self,
        route: &CompletionRoute,
    ) -> crate::analyzer::semantic::ir::CleanupRouteEntries<'_> {
        self.cleanup_chains
            .route_entries(route.segment, route.projection)
    }

    pub fn cleanup_regions(
        &self,
        route: &CompletionRoute,
    ) -> impl Iterator<Item = CleanupRegionId> + '_ {
        self.cleanup_chains
            .entries(route.segment)
            .filter_map(|entry| match entry {
                CleanupEntryRef::Region(region) => Some(region),
                _ => None,
            })
    }

    /// Whether an abrupt throw from `scope` leaves this procedure directly:
    /// the resolved route targets the nearest function frame's throw target
    /// and crosses no cleanup region.
    ///
    /// An adapter that omits an operation's implicit-exception edge uses this
    /// to retain the `NonRejoiningExceptionalExit` proof: such a route cannot
    /// resume the procedure's normal evaluation, and it enters no handler or
    /// cleanup user code. A route that lands in a handler frame, crosses a
    /// cleanup region, or cannot resolve keeps the discharge closed.
    #[doc(hidden)]
    pub fn throw_exits_procedure(&mut self, scope: ScopeFrameId) -> bool {
        let Some(route) =
            self.resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
        else {
            return false;
        };
        route.segment.is_empty()
            && self
                .nearest_function_throw_target(scope)
                .is_some_and(|throw_target| route.destination().target() == throw_target)
    }

    fn nearest_function_throw_target(&self, scope: ScopeFrameId) -> Option<ProgramPointId> {
        self.scopes.get(scope.index())?.function_throw_target
    }

    #[doc(hidden)]
    pub fn normal_cleanup_completion(
        &mut self,
        region: CleanupRegionId,
        target: ProgramPointId,
    ) -> CompletionRoute {
        let scope = self.region_scopes[&region];
        let segment = self.capture_local_cleanup_segment(scope);
        #[cfg(debug_assertions)]
        self.assert_live_cleanup_segment(scope, self.scopes[scope.index()].parent, segment);
        CompletionRoute {
            destination: CompletionTarget::new(
                CompletionKind::Normal,
                target,
                ControlEdgeKind::Normal,
            ),
            segment,
            projection: None,
        }
    }

    pub fn normal_cleanup_completion_until(
        &mut self,
        scope: ScopeFrameId,
        stop_before: ScopeFrameId,
        target: ProgramPointId,
    ) -> CompletionRoute {
        let segment = self.capture_cleanup_segment(scope, Some(stop_before));
        #[cfg(debug_assertions)]
        self.assert_live_cleanup_segment(scope, Some(stop_before), segment);
        CompletionRoute {
            destination: CompletionTarget::new(
                CompletionKind::Normal,
                target,
                ControlEdgeKind::Normal,
            ),
            segment,
            projection: None,
        }
    }

    pub fn resolve_cancellation(
        &mut self,
        scope: ScopeFrameId,
        target: ProgramPointId,
        live_places: &[SemanticPlace],
    ) -> Option<CompletionRoute> {
        let mut cursor = Some(scope);
        let stop = loop {
            let id = cursor?;
            let frame = &self.scopes[id.index()];
            if matches!(frame.binding, ScopeBinding::Function { .. }) {
                break id;
            }
            cursor = frame.parent;
        };
        let segment = self.capture_cleanup_segment(scope, Some(stop));
        #[cfg(debug_assertions)]
        self.assert_live_cleanup_segment(scope, Some(stop), segment);
        let mut selected = Vec::new();
        let mut entries = self.cleanup_chains.entries(segment);
        while let Some((cursor, entry)) = entries.next_action() {
            if live_places.contains(entry.action.place()) {
                selected.push(cursor);
            }
        }
        let projection = self.cleanup_chains.intern_projection(selected);
        Some(CompletionRoute {
            destination: CompletionTarget::new(
                CompletionKind::Throw,
                target,
                ControlEdgeKind::Exceptional,
            ),
            segment,
            projection: Some(projection),
        })
    }

    /// Project route-independent owner obligations onto shared gap-only tails.
    /// `keep` must give the same answer for every route with this reachability.
    /// Stops are part of the key: excluded outer scopes must never enter a gap.
    pub fn filter_cleanup_gap_segment(
        &mut self,
        segment: CleanupSegment,
        origin_reachable: bool,
        mut keep: impl FnMut(crate::analyzer::semantic::ValueId) -> bool,
    ) -> Result<CleanupSegment, SemanticBudgetExceeded> {
        let mut cursor = segment.head;
        let mut pending = Vec::new();
        let mut head = None;
        while cursor != segment.stop {
            self.note_cleanup_construction_step();
            let id = cursor.expect("nonempty cleanup segment");
            let key = (id, segment.stop, origin_reachable);
            if let Some(projected) = self.gap_base_projections.get(&key) {
                head = *projected;
                break;
            }
            let owner_count = self.cleanup_chains.node(id).owners.len();
            let mut owners = Vec::new();
            for index in 0..owner_count {
                self.note_cleanup_construction_step();
                let owner = &self.cleanup_chains.node(id).owners[index];
                if keep(owner.value) {
                    owners.push(owner.clone());
                }
            }
            pending.push((key, owners));
            cursor = self.cleanup_chains.node(id).parent;
        }
        for (key, owners) in pending.into_iter().rev() {
            self.note_cleanup_construction_step();
            // Admit memo storage and prospective node/owner rows before interning.
            // Charging an intern hit too is conservative and bounds construction.
            self.reserve(SemanticWork {
                nested_entries: 1 + usize::from(!owners.is_empty()) + owners.len(),
                ..SemanticWork::default()
            })?;
            if !owners.is_empty() {
                head = Some(self.cleanup_chains.intern(CleanupChainNode {
                    parent: head,
                    region: None,
                    actions: Box::new([]),
                    owners: owners.into_boxed_slice(),
                }));
            }
            self.gap_base_projections.insert(key, head);
        }
        Ok(CleanupSegment { head, stop: None })
    }

    /// Admit a procedure-local deferred cleanup publication descriptor.
    pub fn reserve_deferred_cleanup_route(&mut self) -> Result<(), SemanticBudgetExceeded> {
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })
    }

    /// Publish only owners first encountered at this procedure exit.
    pub fn cleanup_gap_exit_segment(
        &mut self,
        segment: CleanupSegment,
        point: ProgramPointId,
    ) -> Result<CleanupSegment, SemanticBudgetExceeded> {
        let mut cursor = segment.head;
        let mut owners = Vec::new();
        while cursor != segment.stop {
            self.note_cleanup_construction_step();
            let id = cursor.expect("nonempty cleanup segment");
            if !self.gap_exit_nodes.insert((point, id)) {
                break;
            }
            let owner_count = self.cleanup_chains.node(id).owners.len();
            for _ in 0..owner_count {
                self.note_cleanup_construction_step();
            }
            let node = self.cleanup_chains.node(id);
            cursor = node.parent;
            for owner in &node.owners {
                if self.gap_exit_owners.insert((point, owner.value)) {
                    owners.push(owner.clone());
                }
            }
        }
        if owners.is_empty() {
            return Ok(CleanupSegment::default());
        }
        self.reserve(SemanticWork {
            nested_entries: 1 + owners.len(),
            ..SemanticWork::default()
        })?;
        let head = self.cleanup_chains.intern(CleanupChainNode {
            parent: None,
            region: None,
            actions: Box::new([]),
            owners: owners.into_boxed_slice(),
        });
        Ok(CleanupSegment {
            head: Some(head),
            stop: None,
        })
    }

    /// Preserve cleanup routing while inserting a final completion continuation.
    #[doc(hidden)]
    pub fn redirect_completion(
        &self,
        mut route: CompletionRoute,
        target: ProgramPointId,
    ) -> CompletionRoute {
        assert!(target.index() < self.points.len());
        route.destination.target = target;
        route
    }

    /// Reserve or reuse the entry point for one cleanup body specialized to
    pub(crate) fn cleanup_node(&self, node: CleanupChainNodeId) -> &CleanupChainNode {
        self.cleanup_chains.node(node)
    }
    pub(crate) fn cleanup_action_cursor(
        &self,
        node: CleanupChainNodeId,
        ordinal: usize,
    ) -> CleanupActionCursor {
        self.cleanup_chains.action_cursor(node, ordinal)
    }
    pub(crate) fn cleanup_projection(
        &self,
        route: &CompletionRoute,
    ) -> Option<&[CleanupActionCursor]> {
        route
            .projection
            .map(|id| self.cleanup_chains.projection(id))
    }
    pub(crate) fn cleanup_plan(
        &self,
        route: &CompletionRoute,
        node: CleanupChainNodeId,
    ) -> Option<ProgramPointId> {
        self.cleanup_plans
            .get(&CleanupPlanKey {
                node,
                stop: route.segment.stop,
                destination: route.destination,
                projection: route.projection,
            })
            .copied()
    }
    pub(crate) fn remember_cleanup_plan(
        &mut self,
        route: &CompletionRoute,
        node: CleanupChainNodeId,
        point: ProgramPointId,
    ) -> Result<(), SemanticBudgetExceeded> {
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        assert!(
            self.cleanup_plans
                .insert(
                    CleanupPlanKey {
                        node,
                        stop: route.segment.stop,
                        destination: route.destination,
                        projection: route.projection
                    },
                    point
                )
                .is_none()
        );
        Ok(())
    }

    /// an exact abrupt destination and remaining outer-cleanup chain.
    pub(crate) fn cleanup_specialization_entry(
        &self,
        route: &CompletionRoute,
        cursor: CleanupChainNodeId,
    ) -> Option<ProgramPointId> {
        self.cleanup_specializations
            .get(&cleanup_key(route, cursor))
            .copied()
    }

    #[doc(hidden)]
    pub fn cleanup_specialization(
        &mut self,
        route: &CompletionRoute,
        cursor: CleanupChainNodeId,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> Result<(ProgramPointId, bool), SemanticBudgetExceeded> {
        let key = cleanup_key(route, cursor);
        if let Some(point) = self.cleanup_specializations.get(&key).copied() {
            return Ok((point, false));
        }
        let point = self.add_point(Vec::new(), source, evidence)?;
        self.reserve(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        self.cleanup_specializations.insert(key, point);
        Ok((point, true))
    }

    /// Drive an opaque language task stack without Rust recursion.
    pub(crate) fn drive_iteratively<T, E>(
        &mut self,
        initial: T,
        cancellation: &crate::analyzer::semantic::CancellationToken,
        mut step: impl FnMut(&mut Self, T, &mut Vec<T>) -> Result<(), E>,
    ) -> Result<(), DriveError<E>> {
        let mut work = vec![initial];
        while let Some(item) = work.pop() {
            if cancellation.is_cancelled() {
                return Err(DriveError::Cancelled);
            }
            step(self, item, &mut work).map_err(DriveError::Step)?;
            self.budget_snapshot
                .check_admission(self.prospective_work)
                .map_err(DriveError::ExceededBudget)?;
        }
        Ok(())
    }

    /// Close every entry-unreachable region over itself before freezing.
    ///
    /// Syntax lowerers deliberately retain dead source, but a missed
    /// statement-specific abruptness case must never let that detached region
    /// reconnect to live control or either real procedure exit. Internal dead
    /// edges remain intact, including call continuations and cleanup chains.
    #[doc(hidden)]
    pub fn seal_unreachable_regions(
        &mut self,
        entry: ProgramPointId,
        normal_exit: ProgramPointId,
        exceptional_exit: ProgramPointId,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Box<[bool]>, ReachabilitySealCancelled> {
        let point_count = self.points.len();
        for (point, label) in [
            (entry, "entry"),
            (normal_exit, "normal exit"),
            (exceptional_exit, "exceptional exit"),
        ] {
            assert!(
                point.index() < point_count,
                "{label} must be allocated before sealing unreachable regions"
            );
        }

        let mut outgoing = vec![Vec::new(); point_count];
        for edge in &self.parts.control_edges {
            if cancellation.is_cancelled() {
                return Err(ReachabilitySealCancelled);
            }
            assert!(
                edge.source_point.index() < point_count && edge.target_point.index() < point_count,
                "builder edge endpoints must exist before reachability sealing"
            );
            outgoing[edge.source_point.index()].push(edge.target_point);
        }

        let mut reachable = vec![false; point_count];
        let mut stack = vec![entry];
        while let Some(point) = stack.pop() {
            if cancellation.is_cancelled() {
                return Err(ReachabilitySealCancelled);
            }
            if std::mem::replace(&mut reachable[point.index()], true) {
                continue;
            }
            stack.extend(outgoing[point.index()].iter().copied());
        }

        let mut keep = Vec::with_capacity(self.parts.control_edges.len());
        let mut removed = 0usize;
        for edge in &self.parts.control_edges {
            if cancellation.is_cancelled() {
                return Err(ReachabilitySealCancelled);
            }
            let source_reachable = reachable[edge.source_point.index()];
            let target_reachable = reachable[edge.target_point.index()];
            let targets_real_exit =
                edge.target_point == normal_exit || edge.target_point == exceptional_exit;
            let retain = source_reachable || (!target_reachable && !targets_real_exit);
            keep.push(retain);
            removed += usize::from(!retain);
        }

        if removed != 0 {
            let mut index = 0usize;
            self.parts.control_edges.retain(|_| {
                let retain = keep[index];
                index += 1;
                retain
            });
            // A guard arm names an edge, so an arm whose edge just went away is
            // no longer a claim this procedure can make. Clearing it keeps the
            // predicate -- the fact that a constant condition was here survives
            // the seal -- while the arm honestly reports that the frozen CFG
            // has no such successor.
            if !self.parts.guard_facts.is_empty() {
                let surviving = self
                    .parts
                    .control_edges
                    .iter()
                    .map(|edge| (edge.source_point, edge.target_point, edge.kind))
                    .collect::<HashSet<_>>();
                for guard in &mut self.parts.guard_facts {
                    let point = guard.point;
                    let retain_arm = |arm: &mut Option<crate::analyzer::semantic::GuardArm>| {
                        if arm.is_some_and(|arm| {
                            !surviving.contains(&(point, arm.target_point, arm.kind))
                        }) {
                            *arm = None;
                        }
                    };
                    retain_arm(&mut guard.true_arm);
                    retain_arm(&mut guard.false_arm);
                }
            }
            self.prospective_work.control_edges = self
                .prospective_work
                .control_edges
                .checked_sub(removed)
                .expect("removed edges were previously budgeted");
            self.prospective_work.nested_entries = self
                .prospective_work
                .nested_entries
                .checked_sub(removed)
                .expect("each removed edge owned one reverse-adjacency entry");
        }
        Ok(reachable.into_boxed_slice())
    }

    #[doc(hidden)]
    pub fn finish_with_work(
        mut self,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<(ProcedureSemanticsParts, SemanticWork), FinishError> {
        debug_assert_eq!(
            self.gaps_by_point_capability
                .values()
                .map(Vec::len)
                .sum::<usize>(),
            self.parts.gaps.len()
        );
        for index in 0..self.cleanup_scopes.len() {
            if cancellation.is_cancelled() {
                return Err(FinishError::Cancelled);
            }
            self.capture_cleanup_scope(ScopeFrameId::try_from_index(index));
        }
        self.reserve(SemanticWork {
            nested_entries: self.cleanup_chains.node_count()
                + self.cleanup_chains.projection_entries(),
            ..SemanticWork::default()
        })?;
        let (blocks, points, derived_work) = derive_blocks(
            &self.points,
            &self.parts.control_edges,
            &self.budget_snapshot,
            self.prospective_work,
            cancellation,
        )?;
        self.prospective_work = self.prospective_work.conservative_add(derived_work);
        self.parts.cleanup_chains = self.cleanup_chains.finish(cancellation).map_err(|error| {
            assert_eq!(
                error,
                crate::analyzer::semantic::ir::CleanupChainsError::Cancelled
            );
            FinishError::Cancelled
        })?;
        self.parts.blocks = blocks;
        self.parts.points = points;
        Ok((
            self.parts,
            self.prospective_work.conservative_add(self.traversal_work),
        ))
    }

    fn reserve(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        let candidate = self
            .prospective_work
            .checked_add(work)
            .unwrap_or(SemanticWork::uniform(usize::MAX));
        self.budget_snapshot.check_admission(candidate)?;
        self.prospective_work = candidate;
        Ok(())
    }
}

fn cleanup_key(route: &CompletionRoute, cursor: CleanupChainNodeId) -> CleanupKey {
    CleanupKey {
        cursor,
        stop: route.segment.stop,
        destination: route.destination,
        projection: route.projection,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct ReachabilitySealCancelled;

/// Work retained by a newly initialized procedure CFG before points or
/// adapter-owned rows are added.
///
/// Inventory preflight and the actual CFG builder both use this estimator so
/// additions to the base provenance or locator representation cannot drift.
pub(crate) fn initial_procedure_cfg_work<'locator>(
    procedure_locator: &SemanticLocator,
    source_mapping_locators: impl IntoIterator<Item = &'locator SemanticLocator>,
    evidence_source_counts: impl IntoIterator<Item = usize>,
) -> SemanticWork {
    let mut work = SemanticWork {
        procedures: 1,
        // Each frozen CFG retains two offset arrays, even with no points.
        nested_entries: 2,
        ..SemanticWork::default()
    };
    work = work.conservative_add(locator_work(procedure_locator, 2));
    for locator in source_mapping_locators {
        work.source_mappings = work.source_mappings.saturating_add(1);
        work = work.conservative_add(locator_work(locator, 1));
    }
    for source_count in evidence_source_counts {
        work.evidence = work.evidence.saturating_add(1);
        work.nested_entries = work.nested_entries.saturating_add(source_count);
    }
    work
}

fn locator_work(locator: &SemanticLocator, copies: usize) -> SemanticWork {
    let work = crate::analyzer::semantic::workspace_oracle::semantic_locator_work(locator);
    SemanticWork {
        nested_entries: work.nested_entries.saturating_mul(copies),
        owned_text_bytes: work.owned_text_bytes.saturating_mul(copies),
        ..SemanticWork::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct ScopeFrameId(u32);

impl ScopeFrameId {
    fn try_from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("scope depth must fit in u32"))
    }

    const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct CleanupRegionId(u32);

impl CleanupRegionId {
    #[doc(hidden)]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[doc(hidden)]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum ScopeBinding {
    /// Terminal targets for syntactically retained but unreachable regions.
    /// Every abrupt completion is intercepted before it can reconnect the
    /// detached region to a live outer loop, switch, handler, or function.
    Disconnected {
        normal_target: ProgramPointId,
        exceptional_target: ProgramPointId,
        control_target: ProgramPointId,
    },
    Function {
        return_target: ProgramPointId,
        throw_target: ProgramPointId,
    },
    /// Merge target for a construct-specific value-producing completion, such
    /// as Java switch-expression `yield`. The nearest frame wins.
    Yieldable {
        yield_target: ProgramPointId,
        yield_edge_kind: ControlEdgeKind,
    },
    Breakable {
        label: Option<Box<str>>,
        /// Whether an unlabeled `break` targets this construct. Switches do;
        /// labeled blocks and statements do not.
        accepts_unlabeled: bool,
        break_target: ProgramPointId,
        break_edge_kind: ControlEdgeKind,
    },
    Loop {
        label: Option<Box<str>>,
        break_target: ProgramPointId,
        break_edge_kind: ControlEdgeKind,
        continue_target: ProgramPointId,
        continue_edge_kind: ControlEdgeKind,
    },
    Handler {
        entry: ProgramPointId,
    },
    Cleanup {
        region: CleanupRegionId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum CompletionKind {
    Normal,
    Return,
    Throw,
    Break,
    Continue,
    Yield,
}

impl CompletionKind {
    #[doc(hidden)]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Return => "return",
            Self::Throw => "throw",
            Self::Break => "break",
            Self::Continue => "continue",
            Self::Yield => "yield",
        }
    }
}

const COMPLETION_KINDS: [CompletionKind; 6] = [
    CompletionKind::Normal,
    CompletionKind::Return,
    CompletionKind::Throw,
    CompletionKind::Break,
    CompletionKind::Continue,
    CompletionKind::Yield,
];

fn binding_target(
    binding: &ScopeBinding,
    kind: CompletionKind,
    label: Option<&str>,
) -> Option<CompletionTarget> {
    let (target, edge) = match (binding, kind) {
        (ScopeBinding::Disconnected { normal_target, .. }, CompletionKind::Return) => {
            (*normal_target, ControlEdgeKind::Normal)
        }
        (
            ScopeBinding::Disconnected {
                exceptional_target, ..
            },
            CompletionKind::Throw,
        ) => (*exceptional_target, ControlEdgeKind::Exceptional),
        (
            ScopeBinding::Disconnected { control_target, .. },
            CompletionKind::Break | CompletionKind::Yield,
        ) => (*control_target, ControlEdgeKind::Normal),
        (ScopeBinding::Disconnected { control_target, .. }, CompletionKind::Continue) => {
            (*control_target, ControlEdgeKind::LoopBack)
        }
        (ScopeBinding::Function { return_target, .. }, CompletionKind::Return) => {
            (*return_target, ControlEdgeKind::Normal)
        }
        (ScopeBinding::Function { throw_target, .. }, CompletionKind::Throw) => {
            (*throw_target, ControlEdgeKind::Exceptional)
        }
        (ScopeBinding::Handler { entry }, CompletionKind::Throw) => {
            (*entry, ControlEdgeKind::Exceptional)
        }
        (
            ScopeBinding::Yieldable {
                yield_target,
                yield_edge_kind,
            },
            CompletionKind::Yield,
        ) => (*yield_target, *yield_edge_kind),
        (
            ScopeBinding::Loop {
                label: actual,
                break_target,
                break_edge_kind,
                ..
            },
            CompletionKind::Break,
        ) if label_matches(label, actual.as_deref(), true) => (*break_target, *break_edge_kind),
        (
            ScopeBinding::Loop {
                label: actual,
                continue_target,
                continue_edge_kind,
                ..
            },
            CompletionKind::Continue,
        ) if label_matches(label, actual.as_deref(), true) => {
            (*continue_target, *continue_edge_kind)
        }
        (
            ScopeBinding::Breakable {
                label: actual,
                accepts_unlabeled,
                break_target,
                break_edge_kind,
            },
            CompletionKind::Break,
        ) if label_matches(label, actual.as_deref(), *accepts_unlabeled) => {
            (*break_target, *break_edge_kind)
        }
        _ => return None,
    };
    Some(CompletionTarget::new(kind, target, edge))
}

#[doc(hidden)]
pub struct CompletionRequest<'a> {
    pub(crate) kind: CompletionKind,
    pub(crate) label: Option<&'a str>,
}

impl<'a> CompletionRequest<'a> {
    #[doc(hidden)]
    pub const fn new(kind: CompletionKind, label: Option<&'a str>) -> Self {
        Self { kind, label }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct CompletionTarget {
    kind: CompletionKind,
    #[doc(hidden)]
    pub target: ProgramPointId,
    #[doc(hidden)]
    pub edge_kind: ControlEdgeKind,
}

impl CompletionTarget {
    pub const fn new(
        kind: CompletionKind,
        target: ProgramPointId,
        edge_kind: ControlEdgeKind,
    ) -> Self {
        Self {
            kind,
            target,
            edge_kind,
        }
    }

    #[doc(hidden)]
    pub const fn target(self) -> ProgramPointId {
        self.target
    }

    #[doc(hidden)]
    pub const fn edge_kind(self) -> ControlEdgeKind {
        self.edge_kind
    }
}

/// One typed lifecycle event registered for an owned cleanup scope.
#[allow(dead_code)] // Constructed by the dependent Rust producer in Lane C.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum ScopeCleanupAction {
    Drop {
        place: SemanticPlace,
        behavior: DropBehavior,
        source: SourceMappingId,
        evidence: EvidenceId,
    },
    ScopeEnd {
        place: SemanticPlace,
        source: SourceMappingId,
        evidence: EvidenceId,
    },
}

#[allow(dead_code)] // Accessed by the dependent Rust producer and planner in Lane C.
impl ScopeCleanupAction {
    const fn place(&self) -> &SemanticPlace {
        match self {
            Self::Drop { place, .. } | Self::ScopeEnd { place, .. } => place,
        }
    }

    pub(crate) const fn source(&self) -> SourceMappingId {
        match self {
            Self::Drop { source, .. } | Self::ScopeEnd { source, .. } => *source,
        }
    }

    pub(crate) const fn evidence(&self) -> EvidenceId {
        match self {
            Self::Drop { evidence, .. } | Self::ScopeEnd { evidence, .. } => *evidence,
        }
    }
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct CompletionRoute {
    pub destination: CompletionTarget,
    pub segment: CleanupSegment,
    projection: Option<CleanupProjectionId>,
}
impl CompletionRoute {
    pub const fn destination(&self) -> CompletionTarget {
        self.destination
    }
    pub const fn projection(&self) -> Option<CleanupProjectionId> {
        self.projection
    }

    pub fn redirect(&self, target: ProgramPointId, edge_kind: ControlEdgeKind) -> Self {
        Self {
            destination: CompletionTarget::new(self.destination.kind, target, edge_kind),
            ..self.clone()
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CleanupKey {
    cursor: CleanupChainNodeId,
    stop: Option<CleanupChainNodeId>,
    destination: CompletionTarget,
    projection: Option<CleanupProjectionId>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CleanupPlanKey {
    node: CleanupChainNodeId,
    stop: Option<CleanupChainNodeId>,
    destination: CompletionTarget,
    projection: Option<CleanupProjectionId>,
}

struct PendingCleanupScope {
    head: Option<CleanupChainNodeId>,
    inherited: Option<CleanupChainNodeId>,
    region: Option<CleanupRegionId>,
    started: bool,
    actions: Vec<CleanupActionEntry>,
    owners: Vec<CleanupOwnerEntry>,
}

struct ScopeFrame {
    function_throw_target: Option<ProgramPointId>,
    parent: Option<ScopeFrameId>,
    binding: ScopeBinding,
    targets: [Option<(ScopeFrameId, CompletionTarget)>; 6],
    labeled: Option<ScopeFrameId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum DriveError<E> {
    Cancelled,
    ExceededBudget(SemanticBudgetExceeded),
    Step(E),
}

fn label_matches(
    requested: Option<&str>,
    candidate: Option<&str>,
    accepts_unlabeled: bool,
) -> bool {
    requested.map_or(accepts_unlabeled, |label| candidate == Some(label))
}

/// Cancellation and admission are distinct finalization outcomes.
#[derive(Debug)]
#[doc(hidden)]
pub enum FinishError {
    Cancelled,
    ExceededBudget(SemanticBudgetExceeded),
}
impl From<SemanticBudgetExceeded> for FinishError {
    fn from(error: SemanticBudgetExceeded) -> Self {
        Self::ExceededBudget(error)
    }
}

fn derive_blocks(
    pending: &[PendingPoint],
    rich_edges: &[ControlEdge],
    budget: &SemanticBudget,
    base_work: SemanticWork,
    cancellation: &crate::analyzer::semantic::CancellationToken,
) -> Result<(Vec<BasicBlock>, Vec<ProgramPoint>, SemanticWork), FinishError> {
    if cancellation.is_cancelled() {
        return Err(FinishError::Cancelled);
    }
    let point_count = pending.len();
    let mut outgoing = vec![Vec::new(); point_count];
    let mut incoming = vec![Vec::new(); point_count];
    let mut logical = HashSet::default();
    for edge in rich_edges {
        if cancellation.is_cancelled() {
            return Err(FinishError::Cancelled);
        }
        let arc = (edge.source_point, edge.target_point, edge.kind);
        if logical.insert(arc)
            && edge.source_point.index() < point_count
            && edge.target_point.index() < point_count
        {
            outgoing[edge.source_point.index()].push((edge.target_point, edge.kind));
            incoming[edge.target_point.index()].push((edge.source_point, edge.kind));
        }
    }

    let barriers = pending
        .iter()
        .map(|point| {
            if cancellation.is_cancelled() {
                return Err(FinishError::Cancelled);
            }
            for event in &point.events {
                if cancellation.is_cancelled() {
                    return Err(FinishError::Cancelled);
                }
                if is_block_barrier(&event.effect) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut assignments = vec![None; point_count];
    let mut blocks = Vec::new();
    let mut derived_work = SemanticWork::default();

    for start in 0..point_count {
        if cancellation.is_cancelled() {
            return Err(FinishError::Cancelled);
        }
        if assignments[start].is_some() {
            continue;
        }
        let candidate = derived_work.conservative_add(SemanticWork {
            blocks: 1,
            ..SemanticWork::default()
        });
        budget.check_admission(base_work.conservative_add(candidate))?;
        derived_work = candidate;
        let block_id = BlockId::try_from_index(blocks.len())
            .expect("block count cannot exceed program-point count");
        let mut members = Vec::new();
        let mut cursor = ProgramPointId::try_from_index(start).expect("point IDs already fit");
        loop {
            if cancellation.is_cancelled() {
                return Err(FinishError::Cancelled);
            }
            if assignments[cursor.index()].replace(block_id).is_some() {
                break;
            }
            let candidate = derived_work.conservative_add(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            });
            budget.check_admission(base_work.conservative_add(candidate))?;
            derived_work = candidate;
            members.push(cursor);
            if barriers[cursor.index()] || outgoing[cursor.index()].len() != 1 {
                break;
            }
            let (target, kind) = outgoing[cursor.index()][0];
            if kind != ControlEdgeKind::Normal
                || incoming[target.index()].len() != 1
                || assignments[target.index()].is_some()
            {
                break;
            }
            cursor = target;
        }
        let first = &pending[members[0].index()];
        blocks.push(BasicBlock {
            id: block_id,
            points: members.into_boxed_slice(),
            source: first.source,
            evidence: first.evidence,
        });
    }

    let points = pending
        .iter()
        .enumerate()
        .map(|(index, pending)| {
            if cancellation.is_cancelled() {
                return Err(FinishError::Cancelled);
            }
            let mut events = Vec::with_capacity(pending.events.len());
            for event in &pending.events {
                if cancellation.is_cancelled() {
                    return Err(FinishError::Cancelled);
                }
                events.push(event.clone());
            }
            Ok(ProgramPoint {
                id: ProgramPointId::try_from_index(index).expect("pending point ID already fit"),
                block: assignments[index].expect("every dense point is assigned to a block"),
                events: events.into_boxed_slice(),
                source: pending.source,
                evidence: pending.evidence,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((blocks, points, derived_work))
}

fn is_block_barrier(effect: &crate::analyzer::semantic::SemanticEffect) -> bool {
    matches!(
        effect,
        crate::analyzer::semantic::SemanticEffect::NormalExit
            | crate::analyzer::semantic::SemanticEffect::ExceptionalExit
            | crate::analyzer::semantic::SemanticEffect::Invoke { .. }
            | crate::analyzer::semantic::SemanticEffect::ProcedureReturn { .. }
            | crate::analyzer::semantic::SemanticEffect::Throw { .. }
            | crate::analyzer::semantic::SemanticEffect::AsyncSuspend { .. }
    )
}

#[cfg(test)]
mod tests {

    use crate::analyzer::semantic::cfg::*;

    use crate::analyzer::semantic::ArgumentDomain;

    use crate::analyzer::semantic::CallArgumentExpansion;

    use crate::analyzer::semantic::CallSiteId;

    use crate::analyzer::semantic::CallableTargetResolution;

    use crate::analyzer::semantic::ControlContinuation;

    use crate::analyzer::semantic::DeclarationLocator;

    use crate::analyzer::semantic::DeclarationSegment;

    use crate::analyzer::semantic::DeclarationSegmentKind;

    use crate::analyzer::semantic::FormalMultiplicity;

    use crate::analyzer::semantic::FormalParameterPassingMode;

    use crate::analyzer::semantic::ProcedureId;

    use crate::analyzer::semantic::ProcedureKind;

    use crate::analyzer::semantic::SemanticBudgetDimension;

    use crate::analyzer::semantic::SemanticCallArgument;

    use crate::analyzer::semantic::SemanticEffect;

    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use crate::analyzer::semantic::SemanticLocator;

    use crate::analyzer::semantic::SemanticRole;

    use crate::analyzer::semantic::SemanticValueKind;

    use crate::analyzer::semantic::SourceAnchor;

    use crate::analyzer::semantic::SourcePosition;

    use crate::analyzer::semantic::SourceSpan;

    use crate::analyzer::semantic::ValueId;

    use crate::analyzer::semantic::WorkspaceMountId;

    use crate::analyzer::semantic::WorkspaceRelativePath;

    #[derive(Debug, PartialEq, Eq)]
    #[expect(
        clippy::large_enum_variant,
        reason = "short-lived test comparison values; tests match the action by value"
    )]
    enum CleanupRouteOperation {
        Action(ScopeCleanupAction),
        Region { region: CleanupRegionId },
    }
    fn route_operations(
        builder: &ProcedureCfgBuilder,
        route: &CompletionRoute,
    ) -> Vec<CleanupRouteOperation> {
        builder
            .cleanup_entries(route)
            .filter_map(|entry| match entry {
                crate::analyzer::semantic::ir::CleanupRouteEntryRef::Action { entry, .. } => {
                    Some(CleanupRouteOperation::Action(entry.action.clone()))
                }
                crate::analyzer::semantic::ir::CleanupRouteEntryRef::Region { region, .. } => {
                    Some(CleanupRouteOperation::Region { region })
                }
                crate::analyzer::semantic::ir::CleanupRouteEntryRef::Owner(_) => None,
            })
            .collect()
    }

    fn builder_with_budget(budget: &SemanticBudget) -> ProcedureCfgBuilder {
        let start = SourcePosition::new(0, 0, 0);
        let end = SourcePosition::new(1, 0, 1);
        let anchor = SourceAnchor::new(SourceSpan::new(start, end).expect("span"), 0);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::Function, "fixture", anchor, 0)
                .expect("segment"),
        ])
        .expect("declaration");
        let locator = SemanticLocator::new(
            WorkspaceMountId::hash_bytes(b"cfg-builder-test"),
            WorkspaceRelativePath::new("fixture.ts").expect("path"),
            SemanticLanguage::Standard(brokk_bifrost_core::analyzer::model::Language::TypeScript),
            declaration,
            SemanticRole::Procedure,
            anchor,
        );
        let parts = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            locator,
            ProcedureKind::Function,
            SourceMappingId::new(0),
            EvidenceId::new(0),
        );
        ProcedureCfgBuilder::new(parts, budget).expect("builder")
    }

    fn builder() -> ProcedureCfgBuilder {
        builder_with_budget(&SemanticBudget::default())
    }

    #[test]
    fn cleanup_captures_keep_prior_chunks_and_anchor_offsets() {
        let mut builder = builder();
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let point = builder
            .add_point(Vec::new(), source, evidence)
            .expect("point");
        let scope = builder.push_scope(
            None,
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(0),
            },
        );
        let first = ScopeCleanupAction::ScopeEnd {
            place: SemanticPlace::MemoryLocation(MemoryLocationId::new(3)),
            source,
            evidence,
        };
        builder
            .register_scope_cleanup_action(scope, first.clone())
            .expect("first action");
        let before = builder.capture_local_cleanup_segment(scope);
        let child = builder.push_scope(Some(scope), ScopeBinding::Handler { entry: point });
        assert_eq!(before, builder.capture_cleanup_segment(child, None));
        let second = ScopeCleanupAction::ScopeEnd {
            place: SemanticPlace::MemoryLocation(MemoryLocationId::new(8)),
            source,
            evidence,
        };
        builder
            .register_scope_cleanup_action(scope, second.clone())
            .expect("second action");
        let after = builder.capture_local_cleanup_segment(scope);
        assert_ne!(before.head, after.head);
        let destination =
            CompletionTarget::new(CompletionKind::Normal, point, ControlEdgeKind::Normal);
        builder
            .append_cleanup_anchor(
                point,
                before,
                destination,
                CleanupAnchorPurpose::Completion,
                None,
            )
            .expect("first anchor");
        builder
            .emit_cleanup_action_fact(point, &first)
            .expect("direct fact");
        builder
            .append_cleanup_anchor(
                point,
                after,
                destination,
                CleanupAnchorPurpose::Completion,
                None,
            )
            .expect("second anchor");
        let (parts, _) = builder
            .finish_with_work(&brokk_bifrost_core::cancellation::CancellationToken::default())
            .expect("freeze");
        assert_eq!(parts.cleanup_chains.nodes().len(), 2);
        let actions = |segment| {
            parts
                .cleanup_chains
                .actions(segment)
                .map(|entry| &entry.action)
                .collect::<Vec<_>>()
        };
        assert_eq!(actions(before), vec![&first]);
        assert_eq!(actions(after), vec![&first, &second]);
        assert_eq!(
            parts.cleanup_chains.regions(after).collect::<Vec<_>>(),
            vec![CleanupRegionId::new(0)]
        );
        assert_eq!(parts.cleanup_chains.anchors()[0].scope_end_offset, 0);
        assert_eq!(parts.cleanup_chains.anchors()[1].scope_end_offset, 1);
    }

    fn builder_with_owned_text_limit(limit: usize) -> ProcedureCfgBuilder {
        let mut limits = SemanticBudget::default().limits();
        limits.owned_text_bytes = limit;
        let budget = SemanticBudget::new(limits).expect("positive builder limits");
        builder_with_budget(&budget)
    }

    fn point(builder: &mut ProcedureCfgBuilder, effect: SemanticEffect) -> ProgramPointId {
        builder
            .add_point(
                vec![SemanticEvent::new(
                    effect,
                    SourceMappingId::new(0),
                    EvidenceId::new(0),
                )],
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("point")
    }

    #[test]
    fn cleanup_routes_preserve_action_order_and_filter_cancellation_by_live_place() {
        let mut builder = builder();
        let normal_exit = point(&mut builder, SemanticEffect::NormalExit);
        let exceptional_exit = point(&mut builder, SemanticEffect::ExceptionalExit);
        let function = builder.push_scope(
            None,
            ScopeBinding::Function {
                return_target: normal_exit,
                throw_target: exceptional_exit,
            },
        );
        let region = CleanupRegionId::new(0);
        let cleanup = builder.push_scope(Some(function), ScopeBinding::Cleanup { region });
        let local = SemanticPlace::MemoryLocation(MemoryLocationId::new(3));
        let retained = SemanticPlace::MemoryLocation(MemoryLocationId::new(8));
        for action in [
            ScopeCleanupAction::Drop {
                place: local.clone(),
                behavior: DropBehavior::Trivial,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
            ScopeCleanupAction::ScopeEnd {
                place: local.clone(),
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
            ScopeCleanupAction::Drop {
                place: retained.clone(),
                behavior: DropBehavior::Trivial,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
            ScopeCleanupAction::ScopeEnd {
                place: retained.clone(),
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            },
        ] {
            builder
                .register_scope_cleanup_action(cleanup, action)
                .expect("cleanup action fits the procedure budget");
        }

        let return_route = builder
            .resolve_completion(
                cleanup,
                &CompletionRequest::new(CompletionKind::Return, None),
            )
            .expect("return crosses the cleanup scope");
        assert_eq!(
            builder.cleanup_regions(&return_route).collect::<Vec<_>>(),
            &[region]
        );
        assert!(matches!(
            route_operations(&builder, &return_route).as_slice(),
            [
                CleanupRouteOperation::Action(ScopeCleanupAction::Drop { place: first, .. }),
                CleanupRouteOperation::Action(ScopeCleanupAction::ScopeEnd { place: second, .. }),
                CleanupRouteOperation::Action(ScopeCleanupAction::Drop { place: third, .. }),
                CleanupRouteOperation::Action(ScopeCleanupAction::ScopeEnd { place: fourth, .. }),
                CleanupRouteOperation::Region { region: actual, .. }
            ] if first == &local && second == &local && third == &retained && fourth == &retained && actual == &region
        ));

        let normal_route = builder.normal_cleanup_completion(region, normal_exit);
        assert_eq!(
            route_operations(&builder, &normal_route).as_slice(),
            route_operations(&builder, &return_route).as_slice()
        );

        let cancellation = builder
            .resolve_cancellation(cleanup, exceptional_exit, std::slice::from_ref(&retained))
            .expect("cancellation reaches the function boundary");
        assert_eq!(
            cancellation.destination().edge_kind(),
            ControlEdgeKind::Exceptional
        );
        assert!(matches!(
            route_operations(&builder, &cancellation).as_slice(),
            [
                CleanupRouteOperation::Action(ScopeCleanupAction::Drop { place, .. }),
                CleanupRouteOperation::Action(ScopeCleanupAction::ScopeEnd { place: ended, .. }),
                CleanupRouteOperation::Region { .. }
            ] if place == &retained && ended == &retained
        ));
    }

    #[test]
    fn cleanup_specialization_reuse_ignores_route_local_region_indices() {
        let mut builder = builder();
        let normal_exit = point(&mut builder, SemanticEffect::NormalExit);
        let exceptional_exit = point(&mut builder, SemanticEffect::ExceptionalExit);
        let function = builder.push_scope(
            None,
            ScopeBinding::Function {
                return_target: normal_exit,
                throw_target: exceptional_exit,
            },
        );
        let outer = builder.push_scope(
            Some(function),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(9),
            },
        );
        let shared = builder.push_scope(
            Some(outer),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(4),
            },
        );
        let route_without_extra_scope = builder
            .resolve_completion(
                shared,
                &CompletionRequest::new(CompletionKind::Return, None),
            )
            .expect("return resolves through shared cleanup");
        let inner = builder.push_scope(
            Some(shared),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(2),
            },
        );
        let route_with_extra_scope = builder
            .resolve_completion(inner, &CompletionRequest::new(CompletionKind::Return, None))
            .expect("nested return resolves through shared cleanup");

        let (first, first_created) = builder
            .cleanup_specialization(
                &route_without_extra_scope,
                route_without_extra_scope.segment.head.expect("region head"),
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("first shared cleanup specialization");
        let (second, second_created) = builder
            .cleanup_specialization(
                &route_with_extra_scope,
                route_without_extra_scope
                    .segment
                    .head
                    .expect("shared region head"),
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("second shared cleanup specialization");
        assert!(first_created);
        assert!(!second_created);
        assert_eq!(first, second);
    }

    #[test]
    fn iterative_driver_handles_deep_work_without_recursion() {
        let mut builder = builder();
        builder
            .drive_iteratively(
                100_000_usize,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
                |_builder, depth, work| {
                    if depth > 0 {
                        work.push(depth - 1);
                    }
                    Ok::<_, ()>(())
                },
            )
            .expect("deep iterative chain");
    }

    #[test]
    fn builder_budget_charges_owned_value_kind_and_rest_domain_text() {
        let baseline = builder().prospective_work().owned_text_bytes;
        for (kind, text_bytes) in [
            (
                SemanticValueKind::LanguageDefined("language-value".into()),
                "language-value".len(),
            ),
            (
                SemanticValueKind::Parameter {
                    ordinal: 0,
                    multiplicity: FormalMultiplicity::Rest(ArgumentDomain::LanguageDefined(
                        "language-rest".into(),
                    )),
                    name: None,
                    passing_mode: FormalParameterPassingMode::PositionalOrNamed,
                },
                "language-rest".len(),
            ),
            (
                SemanticValueKind::Parameter {
                    ordinal: 0,
                    multiplicity: FormalMultiplicity::One,
                    name: Some("parameter-name".into()),
                    passing_mode: FormalParameterPassingMode::NamedOnly,
                },
                "parameter-name".len(),
            ),
        ] {
            let limit = baseline + text_bytes - 1;
            let mut builder = builder_with_owned_text_limit(limit);
            let before = builder.prospective_work();
            let error = builder
                .add_value(SemanticValue {
                    static_type_origin: None,
                    static_type_class: Default::default(),
                    id: ValueId::new(0),
                    kind,
                    source: SourceMappingId::new(0),
                    evidence: EvidenceId::new(0),
                })
                .expect_err("owned value text must be checked before retention");

            assert_eq!(error.dimension(), SemanticBudgetDimension::OwnedTextBytes);
            assert_eq!(error.limit(), limit);
            assert_eq!(error.attempted(), baseline + text_bytes);
            assert_eq!(builder.prospective_work(), before);
        }
    }

    #[test]
    fn builder_budget_charges_owned_direct_and_spread_argument_domain_text() {
        let baseline = builder().prospective_work().owned_text_bytes;
        for (expansion, keyword, text_bytes) in [
            (
                CallArgumentExpansion::Direct(ArgumentDomain::LanguageDefined(
                    "direct-domain".into(),
                )),
                None,
                "direct-domain".len(),
            ),
            (
                CallArgumentExpansion::Spread(ArgumentDomain::LanguageDefined(
                    "spread-domain".into(),
                )),
                None,
                "spread-domain".len(),
            ),
            (
                CallArgumentExpansion::Direct(ArgumentDomain::Keyword),
                Some(Box::<str>::from("keyword-name")),
                "keyword-name".len(),
            ),
        ] {
            let limit = baseline + text_bytes - 1;
            let mut builder = builder_with_owned_text_limit(limit);
            let before = builder.prospective_work();
            let error = builder
                .add_call_site(SemanticCallSite {
                    id: CallSiteId::new(0),
                    point: ProgramPointId::new(0),
                    invocation_mode: crate::analyzer::semantic::CallInvocationMode::Ordinary,
                    execution_timing: crate::analyzer::semantic::ExecutionTiming::SameEvaluation,
                    callee: ValueId::new(0),
                    receiver: None,
                    member_selection: None,
                    arguments: Box::new([SemanticCallArgument {
                        value: ValueId::new(1),
                        expansion,
                        keyword,
                    }]),
                    normal_results: Box::new([]),
                    result: None,
                    thrown: None,
                    declared_targets: CallableTargetResolution::Unknown,
                    target_evidence: EvidenceId::new(0),
                    normal_continuation: ControlContinuation::Unknown,
                    exceptional_continuation: ControlContinuation::Unknown,
                    source: SourceMappingId::new(0),
                    evidence: EvidenceId::new(0),
                })
                .expect_err("owned argument-domain text must be checked before retention");

            assert_eq!(error.dimension(), SemanticBudgetDimension::OwnedTextBytes);
            assert_eq!(error.limit(), limit);
            assert_eq!(error.attempted(), baseline + text_bytes);
            assert_eq!(builder.prospective_work(), before);
        }
    }

    #[test]
    fn unlabeled_break_skips_a_labeled_block_and_targets_the_enclosing_loop() {
        let mut builder = builder();
        let loop_break = point(&mut builder, SemanticEffect::Entry);
        let loop_continue = point(&mut builder, SemanticEffect::Entry);
        let block_break = point(&mut builder, SemanticEffect::Entry);
        let loop_scope = builder.push_scope(
            None,
            ScopeBinding::Loop {
                label: Some("outer".into()),
                break_target: loop_break,
                break_edge_kind: ControlEdgeKind::Normal,
                continue_target: loop_continue,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let block_scope = builder.push_scope(
            Some(loop_scope),
            ScopeBinding::Breakable {
                label: Some("block".into()),
                accepts_unlabeled: false,
                break_target: block_break,
                break_edge_kind: ControlEdgeKind::Normal,
            },
        );

        let unlabeled = builder
            .resolve_completion(
                block_scope,
                &CompletionRequest::new(CompletionKind::Break, None),
            )
            .expect("unlabeled break should resolve to the enclosing loop");
        assert_eq!(unlabeled.destination().target(), loop_break);

        let labeled = builder
            .resolve_completion(
                block_scope,
                &CompletionRequest::new(CompletionKind::Break, Some("block")),
            )
            .expect("matching labeled break should resolve to the block merge");
        assert_eq!(labeled.destination().target(), block_break);
    }

    #[test]
    fn yield_bypasses_other_control_scopes_and_routes_through_cleanup_to_switch_merge() {
        let mut builder = builder();
        let normal_exit = point(&mut builder, SemanticEffect::NormalExit);
        let exceptional_exit = point(&mut builder, SemanticEffect::ExceptionalExit);
        let outer_switch_merge = point(&mut builder, SemanticEffect::Entry);
        let switch_merge = point(&mut builder, SemanticEffect::Entry);
        let loop_continue = point(&mut builder, SemanticEffect::Entry);
        let handler_entry = point(&mut builder, SemanticEffect::Entry);
        let function = builder.push_scope(
            None,
            ScopeBinding::Function {
                return_target: normal_exit,
                throw_target: exceptional_exit,
            },
        );
        let outer_yieldable = builder.push_scope(
            Some(function),
            ScopeBinding::Yieldable {
                yield_target: outer_switch_merge,
                yield_edge_kind: ControlEdgeKind::Normal,
            },
        );
        let yieldable = builder.push_scope(
            Some(outer_yieldable),
            ScopeBinding::Yieldable {
                yield_target: switch_merge,
                yield_edge_kind: ControlEdgeKind::Normal,
            },
        );
        let loop_scope = builder.push_scope(
            Some(yieldable),
            ScopeBinding::Loop {
                label: None,
                break_target: switch_merge,
                break_edge_kind: ControlEdgeKind::Normal,
                continue_target: loop_continue,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let breakable = builder.push_scope(
            Some(loop_scope),
            ScopeBinding::Breakable {
                label: None,
                accepts_unlabeled: true,
                break_target: switch_merge,
                break_edge_kind: ControlEdgeKind::Normal,
            },
        );
        let handler = builder.push_scope(
            Some(breakable),
            ScopeBinding::Handler {
                entry: handler_entry,
            },
        );
        let cleanup = builder.push_scope(
            Some(handler),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(7),
            },
        );

        let route = builder
            .resolve_completion(
                cleanup,
                &CompletionRequest::new(CompletionKind::Yield, None),
            )
            .expect("yield should resolve to the surrounding switch expression");

        assert_eq!(route.destination().kind, CompletionKind::Yield);
        assert_eq!(route.destination().target(), switch_merge);
        assert_ne!(route.destination().target(), outer_switch_merge);
        assert_ne!(route.destination().target(), normal_exit);
        assert_eq!(route.destination().edge_kind(), ControlEdgeKind::Normal);
        assert_eq!(
            builder.cleanup_regions(&route).collect::<Vec<_>>(),
            &[CleanupRegionId::new(7)]
        );
        let (cleanup_entry, created) = builder
            .cleanup_specialization(
                &route,
                route.segment.head.expect("region head"),
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("yield cleanup specialization");
        assert!(created);
        assert_ne!(cleanup_entry, switch_merge);
        assert_ne!(cleanup_entry, normal_exit);
    }

    #[test]
    fn disconnected_scope_intercepts_control_completions_before_live_outer_scopes() {
        let mut builder = builder();
        let live_exit = point(&mut builder, SemanticEffect::NormalExit);
        let dead_normal = point(&mut builder, SemanticEffect::NormalExit);
        let dead_exceptional = point(&mut builder, SemanticEffect::ExceptionalExit);
        let dead_control = point(&mut builder, SemanticEffect::Entry);
        let live_loop = builder.push_scope(
            None,
            ScopeBinding::Loop {
                label: Some("outer".into()),
                break_target: live_exit,
                break_edge_kind: ControlEdgeKind::Normal,
                continue_target: live_exit,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let disconnected = builder.push_scope(
            Some(live_loop),
            ScopeBinding::Disconnected {
                normal_target: dead_normal,
                exceptional_target: dead_exceptional,
                control_target: dead_control,
            },
        );

        for (kind, label, edge_kind) in [
            (
                CompletionKind::Break,
                Some("outer"),
                ControlEdgeKind::Normal,
            ),
            (
                CompletionKind::Continue,
                Some("outer"),
                ControlEdgeKind::LoopBack,
            ),
            (CompletionKind::Yield, None, ControlEdgeKind::Normal),
        ] {
            let route = builder
                .resolve_completion(disconnected, &CompletionRequest::new(kind, label))
                .expect("disconnected completion should resolve");
            assert_eq!(route.destination().target(), dead_control);
            assert_eq!(route.destination().edge_kind(), edge_kind);
        }
    }

    #[test]
    fn reachability_seal_keeps_dead_topology_but_removes_live_and_exit_reconnections() {
        let mut builder = builder();
        let entry = point(&mut builder, SemanticEffect::Entry);
        let live = point(
            &mut builder,
            SemanticEffect::ProcedureReturn { value: None },
        );
        let dead = point(&mut builder, SemanticEffect::Entry);
        let dead_tail = point(
            &mut builder,
            SemanticEffect::ProcedureReturn { value: None },
        );
        let normal_exit = point(&mut builder, SemanticEffect::NormalExit);
        let exceptional_exit = point(&mut builder, SemanticEffect::ExceptionalExit);
        for (source, target, kind) in [
            (entry, live, ControlEdgeKind::Normal),
            (live, normal_exit, ControlEdgeKind::Normal),
            (dead, dead_tail, ControlEdgeKind::Normal),
            (dead_tail, normal_exit, ControlEdgeKind::Normal),
            (dead_tail, live, ControlEdgeKind::Normal),
            (dead_tail, exceptional_exit, ControlEdgeKind::Exceptional),
        ] {
            builder
                .add_edge(ControlEdge {
                    source_point: source,
                    target_point: target,
                    kind,
                    source: SourceMappingId::new(0),
                    evidence: EvidenceId::new(0),
                })
                .expect("edge");
        }

        builder
            .seal_unreachable_regions(
                entry,
                normal_exit,
                exceptional_exit,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .expect("reachability seal");
        let (parts, work) = builder
            .finish_with_work(&brokk_bifrost_core::cancellation::CancellationToken::default())
            .expect("finish");

        assert_eq!(parts.control_edges.len(), 3);
        assert!(
            parts
                .control_edges
                .iter()
                .any(|edge| { edge.source_point == dead && edge.target_point == dead_tail })
        );
        assert!(!parts.control_edges.iter().any(|edge| {
            edge.source_point == dead_tail
                && matches!(edge.target_point, target if target == normal_exit || target == exceptional_exit || target == live)
        }));
        assert_eq!(work.control_edges, parts.control_edges.len());
    }

    #[test]
    fn derived_blocks_include_disconnected_points_and_ignore_provenance_parallel_edges() {
        let mut builder = builder();
        let entry = point(&mut builder, SemanticEffect::Entry);
        let middle = point(
            &mut builder,
            SemanticEffect::ProcedureReturn { value: None },
        );
        let dead = point(
            &mut builder,
            SemanticEffect::ProcedureReturn { value: None },
        );
        let normal = point(&mut builder, SemanticEffect::NormalExit);
        let exceptional = point(&mut builder, SemanticEffect::ExceptionalExit);
        for evidence in [EvidenceId::new(0), EvidenceId::new(1)] {
            builder
                .add_edge(ControlEdge {
                    source_point: entry,
                    target_point: middle,
                    kind: ControlEdgeKind::Normal,
                    source: SourceMappingId::new(0),
                    evidence,
                })
                .expect("parallel provenance edge");
        }
        builder
            .add_edge(ControlEdge {
                source_point: middle,
                target_point: normal,
                kind: ControlEdgeKind::Normal,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            })
            .expect("exit edge");
        let work_before_freeze = builder.prospective_work();
        let (parts, frozen_work) = builder
            .finish_with_work(&brokk_bifrost_core::cancellation::CancellationToken::default())
            .expect("finish");

        assert_eq!(parts.points.len(), 5);
        assert!(
            parts
                .blocks
                .iter()
                .any(|block| block.points.contains(&dead))
        );
        assert_eq!(
            parts.points[entry.index()].block,
            parts.points[middle.index()].block
        );
        assert_ne!(
            parts.points[middle.index()].block,
            parts.points[normal.index()].block
        );
        assert_ne!(
            parts.points[normal.index()].block,
            parts.points[exceptional.index()].block
        );
        assert_eq!(frozen_work.blocks, parts.blocks.len());
        assert!(frozen_work.nested_entries > work_before_freeze.nested_entries);
    }

    #[test]
    fn cleanup_specialization_key_keeps_completion_kinds_and_outer_chains_distinct() {
        let mut builder = builder();
        let normal = point(&mut builder, SemanticEffect::NormalExit);
        let exceptional = point(&mut builder, SemanticEffect::ExceptionalExit);
        let function = builder.push_scope(
            None,
            ScopeBinding::Function {
                return_target: normal,
                throw_target: exceptional,
            },
        );
        let yieldable = builder.push_scope(
            Some(function),
            ScopeBinding::Yieldable {
                // Match the function return target deliberately: the cleanup
                // cache must distinguish these routes by completion kind.
                yield_target: normal,
                yield_edge_kind: ControlEdgeKind::Normal,
            },
        );
        let outer = builder.push_scope(
            Some(yieldable),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(1),
            },
        );
        let inner = builder.push_scope(
            Some(outer),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(2),
            },
        );
        let returning = builder
            .resolve_completion(inner, &CompletionRequest::new(CompletionKind::Return, None))
            .expect("return route");
        let throwing = builder
            .resolve_completion(inner, &CompletionRequest::new(CompletionKind::Throw, None))
            .expect("throw route");
        let yielding = builder
            .resolve_completion(inner, &CompletionRequest::new(CompletionKind::Yield, None))
            .expect("yield route");

        let (return_entry, created) = builder
            .cleanup_specialization(
                &returning,
                returning.segment.head.expect("region head"),
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("return cleanup");
        assert!(created);
        let (same_return, created) = builder
            .cleanup_specialization(
                &returning,
                returning.segment.head.expect("region head"),
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("same return cleanup");
        assert!(!created);
        assert_eq!(same_return, return_entry);
        let (throw_entry, created) = builder
            .cleanup_specialization(
                &throwing,
                throwing.segment.head.expect("region head"),
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("throw cleanup");
        assert!(created);
        assert_ne!(throw_entry, return_entry);
        let (yield_entry, created) = builder
            .cleanup_specialization(
                &yielding,
                yielding.segment.head.expect("region head"),
                SourceMappingId::new(0),
                EvidenceId::new(0),
            )
            .expect("yield cleanup");
        assert!(created);
        assert_ne!(yield_entry, return_entry);
        assert_ne!(yield_entry, throw_entry);
    }

    #[test]
    fn block_derivation_checks_the_budget_before_retaining_each_block() {
        let mut limits = SemanticBudget::default().limits();
        limits.blocks = 2;
        let budget = SemanticBudget::new(limits).expect("positive limits");
        let mut builder = builder_with_budget(&budget);
        point(&mut builder, SemanticEffect::Entry);
        point(&mut builder, SemanticEffect::NormalExit);
        point(&mut builder, SemanticEffect::ExceptionalExit);

        let exceeded = builder
            .finish_with_work(&brokk_bifrost_core::cancellation::CancellationToken::default())
            .expect_err("three disconnected points require three blocks");
        let FinishError::ExceededBudget(exceeded) = exceeded else {
            panic!("unexpected cancellation")
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::Blocks);
        assert_eq!(exceeded.limit(), 2);
        assert_eq!(exceeded.attempted(), 3);
    }
}
