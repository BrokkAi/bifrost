//! Private iterative construction mechanics for procedure-local CFGs.

use crate::hash::{HashMap, HashSet};

use super::{
    BasicBlock, BlockId, ControlEdge, ControlEdgeKind, Evidence, EvidenceId,
    ProcedureSemanticsParts, ProgramPoint, ProgramPointId, SemanticBudget, SemanticBudgetExceeded,
    SemanticCallSite, SemanticEvent, SemanticGap, SemanticLocator, SemanticValue, SemanticWork,
    SourceMapping, SourceMappingId,
};

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
pub(crate) struct ProcedureCfgBuilder {
    parts: ProcedureSemanticsParts,
    points: Vec<PendingPoint>,
    scopes: Vec<ScopeFrame>,
    cleanup_specializations: HashMap<CleanupKey, ProgramPointId>,
    budget_snapshot: SemanticBudget,
    prospective_work: SemanticWork,
}

impl ProcedureCfgBuilder {
    pub(crate) fn new(
        mut parts: ProcedureSemanticsParts,
        budget: &SemanticBudget,
    ) -> Result<Self, SemanticBudgetExceeded> {
        assert!(
            parts.points.is_empty() && parts.blocks.is_empty() && parts.control_edges.is_empty(),
            "CFG builder requires construction parts without prebuilt topology"
        );
        assert!(
            parts.values.is_empty()
                && parts.allocations.is_empty()
                && parts.memory_locations.is_empty()
                && parts.captures.is_empty()
                && parts.call_sites.is_empty()
                && parts.gaps.is_empty(),
            "CFG builder requires side-table rows to be allocated through the builder"
        );
        let mut prospective_work = SemanticWork {
            procedures: 1,
            source_mappings: parts.source_mappings.len(),
            evidence: parts.evidence_rows.len(),
            // Each frozen CFG retains two offset arrays, even with no points.
            nested_entries: 2usize.saturating_add(
                parts
                    .evidence_rows
                    .iter()
                    .map(|evidence| evidence.sources.len())
                    .sum::<usize>(),
            ),
            ..SemanticWork::default()
        };
        prospective_work = combine_work(prospective_work, locator_work(&parts.locator, 2));
        for mapping in &parts.source_mappings {
            prospective_work = combine_work(prospective_work, locator_work(&mapping.locator, 1));
        }
        budget.check(prospective_work)?;
        parts.points.clear();
        Ok(Self {
            parts,
            points: Vec::new(),
            scopes: Vec::new(),
            cleanup_specializations: HashMap::default(),
            budget_snapshot: budget.clone(),
            prospective_work,
        })
    }

    pub(crate) const fn prospective_work(&self) -> SemanticWork {
        self.prospective_work
    }

    pub(crate) fn add_source_mapping(
        &mut self,
        mapping: SourceMapping,
    ) -> Result<SourceMappingId, SemanticBudgetExceeded> {
        let id = SourceMappingId::try_from_index(self.parts.source_mappings.len())
            .expect("source-mapping count is bounded by the u32 semantic budget");
        assert_eq!(mapping.id, id, "source mappings must use dense builder IDs");
        self.reserve(combine_work(
            SemanticWork {
                source_mappings: 1,
                ..SemanticWork::default()
            },
            locator_work(&mapping.locator, 1),
        ))?;
        self.parts.source_mappings.push(mapping);
        Ok(id)
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

    pub(crate) fn add_gap(
        &mut self,
        gap: SemanticGap,
    ) -> Result<super::SemanticGapId, SemanticBudgetExceeded> {
        let id = super::SemanticGapId::try_from_index(self.parts.gaps.len())
            .expect("gap count is bounded by the u32 semantic budget");
        assert_eq!(gap.id, id, "gaps must use dense builder IDs");
        self.reserve(SemanticWork {
            gaps: 1,
            owned_text_bytes: gap.detail.len(),
            ..SemanticWork::default()
        })?;
        self.parts.gaps.push(gap);
        Ok(id)
    }

    pub(crate) fn add_value(
        &mut self,
        value: SemanticValue,
    ) -> Result<super::ValueId, SemanticBudgetExceeded> {
        let id = super::ValueId::try_from_index(self.parts.values.len())
            .expect("value count is bounded by the u32 semantic budget");
        assert_eq!(value.id, id, "values must use dense builder IDs");
        self.reserve(SemanticWork {
            values: 1,
            ..SemanticWork::default()
        })?;
        self.parts.values.push(value);
        Ok(id)
    }

    pub(crate) fn add_call_site(
        &mut self,
        call_site: SemanticCallSite,
    ) -> Result<super::CallSiteId, SemanticBudgetExceeded> {
        let id = super::CallSiteId::try_from_index(self.parts.call_sites.len())
            .expect("call-site count is bounded by the u32 semantic budget");
        assert_eq!(call_site.id, id, "call sites must use dense builder IDs");
        self.reserve(SemanticWork {
            call_sites: 1,
            nested_entries: call_site.arguments.len(),
            ..SemanticWork::default()
        })?;
        self.parts.call_sites.push(call_site);
        Ok(id)
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

    pub(crate) fn push_scope(
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
        self.scopes.push(ScopeFrame { parent, binding });
        id
    }

    /// Resolve an abrupt completion by walking persistent parent-linked scope
    /// frames iteratively. Cleanup regions are returned inner-to-outer.
    pub(crate) fn resolve_completion(
        &self,
        scope: ScopeFrameId,
        request: &CompletionRequest<'_>,
    ) -> Option<CompletionRoute> {
        let mut cleanups = Vec::new();
        let mut cursor = Some(scope);
        while let Some(id) = cursor {
            let frame = self.scopes.get(id.index())?;
            match &frame.binding {
                ScopeBinding::Disconnected {
                    normal_target,
                    exceptional_target,
                    control_target,
                } => {
                    let (target, edge_kind) = match request.kind {
                        CompletionKind::Return => (*normal_target, ControlEdgeKind::Normal),
                        CompletionKind::Throw => {
                            (*exceptional_target, ControlEdgeKind::Exceptional)
                        }
                        CompletionKind::Break => (*control_target, ControlEdgeKind::Normal),
                        CompletionKind::Continue => (*control_target, ControlEdgeKind::LoopBack),
                        CompletionKind::Normal => {
                            cursor = frame.parent;
                            continue;
                        }
                    };
                    return Some(CompletionRoute::new(
                        CompletionTarget::new(request.kind, target, edge_kind),
                        cleanups,
                    ));
                }
                ScopeBinding::Function {
                    return_target,
                    throw_target,
                } => match request.kind {
                    CompletionKind::Return => {
                        return Some(CompletionRoute::new(
                            CompletionTarget::new(
                                CompletionKind::Return,
                                *return_target,
                                ControlEdgeKind::Normal,
                            ),
                            cleanups,
                        ));
                    }
                    CompletionKind::Throw => {
                        return Some(CompletionRoute::new(
                            CompletionTarget::new(
                                CompletionKind::Throw,
                                *throw_target,
                                ControlEdgeKind::Exceptional,
                            ),
                            cleanups,
                        ));
                    }
                    CompletionKind::Normal | CompletionKind::Break | CompletionKind::Continue => {}
                },
                ScopeBinding::Loop {
                    label,
                    break_target,
                    break_edge_kind,
                    continue_target,
                    continue_edge_kind,
                } => {
                    if label_matches(request.label, label.as_deref()) {
                        if request.kind == CompletionKind::Break {
                            return Some(CompletionRoute::new(
                                CompletionTarget::new(
                                    CompletionKind::Break,
                                    *break_target,
                                    *break_edge_kind,
                                ),
                                cleanups,
                            ));
                        }
                        if request.kind == CompletionKind::Continue {
                            return Some(CompletionRoute::new(
                                CompletionTarget::new(
                                    CompletionKind::Continue,
                                    *continue_target,
                                    *continue_edge_kind,
                                ),
                                cleanups,
                            ));
                        }
                    }
                }
                ScopeBinding::Breakable {
                    label,
                    break_target,
                    break_edge_kind,
                } => {
                    if request.kind == CompletionKind::Break
                        && label_matches(request.label, label.as_deref())
                    {
                        return Some(CompletionRoute::new(
                            CompletionTarget::new(
                                CompletionKind::Break,
                                *break_target,
                                *break_edge_kind,
                            ),
                            cleanups,
                        ));
                    }
                }
                ScopeBinding::Handler { entry } if request.kind == CompletionKind::Throw => {
                    return Some(CompletionRoute::new(
                        CompletionTarget::new(
                            CompletionKind::Throw,
                            *entry,
                            ControlEdgeKind::Exceptional,
                        ),
                        cleanups,
                    ));
                }
                ScopeBinding::Cleanup { region } => cleanups.push(*region),
                ScopeBinding::Handler { .. } => {}
            }
            cursor = frame.parent;
        }
        None
    }

    pub(crate) fn normal_cleanup_completion(
        &self,
        region: CleanupRegionId,
        target: ProgramPointId,
    ) -> CompletionRoute {
        CompletionRoute::new(
            CompletionTarget::new(CompletionKind::Normal, target, ControlEdgeKind::Normal),
            vec![region],
        )
    }

    /// Reserve or reuse the entry point for one cleanup body specialized to
    /// an exact abrupt destination and remaining outer-cleanup chain.
    pub(crate) fn cleanup_specialization(
        &mut self,
        route: &CompletionRoute,
        cleanup_index: usize,
        source: SourceMappingId,
        evidence: EvidenceId,
    ) -> Result<(ProgramPointId, bool), SemanticBudgetExceeded> {
        let region = route
            .cleanups
            .get(cleanup_index)
            .copied()
            .unwrap_or_else(|| panic!("cleanup index {cleanup_index} is outside completion route"));
        let key = CleanupKey {
            region,
            destination: route.destination,
            outer_cleanups: route.cleanups[cleanup_index + 1..]
                .to_vec()
                .into_boxed_slice(),
        };
        if let Some(point) = self.cleanup_specializations.get(&key).copied() {
            return Ok((point, false));
        }
        let point = self.add_point(Vec::new(), source, evidence)?;
        self.cleanup_specializations.insert(key, point);
        Ok((point, true))
    }

    /// Drive an opaque language task stack without Rust recursion.
    pub(crate) fn drive_iteratively<T, E>(
        &mut self,
        initial: T,
        cancellation: &super::CancellationToken,
        mut step: impl FnMut(&mut Self, T, &mut Vec<T>) -> Result<(), E>,
    ) -> Result<(), DriveError<E>> {
        let mut work = vec![initial];
        while let Some(item) = work.pop() {
            if cancellation.is_cancelled() {
                return Err(DriveError::Cancelled);
            }
            step(self, item, &mut work).map_err(DriveError::Step)?;
            self.budget_snapshot
                .check(self.prospective_work)
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
    pub(crate) fn seal_unreachable_regions(
        &mut self,
        entry: ProgramPointId,
        normal_exit: ProgramPointId,
        exceptional_exit: ProgramPointId,
        cancellation: &super::CancellationToken,
    ) -> Result<(), ReachabilitySealCancelled> {
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
        Ok(())
    }

    pub(crate) fn finish_with_work(
        mut self,
    ) -> Result<(ProcedureSemanticsParts, SemanticWork), SemanticBudgetExceeded> {
        let (blocks, points, derived_work) = derive_blocks(
            &self.points,
            &self.parts.control_edges,
            &self.budget_snapshot,
            self.prospective_work,
        )?;
        self.prospective_work = combine_work(self.prospective_work, derived_work);
        self.parts.blocks = blocks;
        self.parts.points = points;
        Ok((self.parts, self.prospective_work))
    }

    fn reserve(&mut self, work: SemanticWork) -> Result<(), SemanticBudgetExceeded> {
        let candidate = self
            .prospective_work
            .checked_add(work)
            .unwrap_or(SemanticWork::uniform(usize::MAX));
        self.budget_snapshot.check(candidate)?;
        self.prospective_work = candidate;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReachabilitySealCancelled;

fn combine_work(left: SemanticWork, right: SemanticWork) -> SemanticWork {
    left.checked_add(right)
        .unwrap_or_else(|| SemanticWork::uniform(usize::MAX))
}

fn locator_work(locator: &SemanticLocator, copies: usize) -> SemanticWork {
    let segment_count = locator.declaration().segments().len();
    let segment_name_bytes = locator
        .declaration()
        .segments()
        .iter()
        .filter_map(|segment| segment.name())
        .fold(0usize, |total, name| total.saturating_add(name.len()));
    SemanticWork {
        nested_entries: segment_count.saturating_mul(copies),
        owned_text_bytes: locator
            .path()
            .as_str()
            .len()
            .saturating_add(segment_name_bytes)
            .saturating_mul(copies),
        ..SemanticWork::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ScopeFrameId(u32);

impl ScopeFrameId {
    fn try_from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("scope depth must fit in u32"))
    }

    const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CleanupRegionId(u32);

impl CleanupRegionId {
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ScopeBinding {
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
    Breakable {
        label: Option<Box<str>>,
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
pub(crate) enum CompletionKind {
    Normal,
    Return,
    Throw,
    Break,
    Continue,
}

pub(crate) struct CompletionRequest<'a> {
    pub(crate) kind: CompletionKind,
    pub(crate) label: Option<&'a str>,
}

impl<'a> CompletionRequest<'a> {
    pub(crate) const fn new(kind: CompletionKind, label: Option<&'a str>) -> Self {
        Self { kind, label }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CompletionTarget {
    kind: CompletionKind,
    target: ProgramPointId,
    edge_kind: ControlEdgeKind,
}

impl CompletionTarget {
    const fn new(kind: CompletionKind, target: ProgramPointId, edge_kind: ControlEdgeKind) -> Self {
        Self {
            kind,
            target,
            edge_kind,
        }
    }

    pub(crate) const fn target(self) -> ProgramPointId {
        self.target
    }

    pub(crate) const fn edge_kind(self) -> ControlEdgeKind {
        self.edge_kind
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompletionRoute {
    destination: CompletionTarget,
    cleanups: Box<[CleanupRegionId]>,
}

impl CompletionRoute {
    fn new(destination: CompletionTarget, cleanups: Vec<CleanupRegionId>) -> Self {
        Self {
            destination,
            cleanups: cleanups.into_boxed_slice(),
        }
    }

    pub(crate) const fn destination(&self) -> CompletionTarget {
        self.destination
    }

    pub(crate) fn cleanups(&self) -> &[CleanupRegionId] {
        &self.cleanups
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CleanupKey {
    region: CleanupRegionId,
    destination: CompletionTarget,
    outer_cleanups: Box<[CleanupRegionId]>,
}

struct ScopeFrame {
    parent: Option<ScopeFrameId>,
    binding: ScopeBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DriveError<E> {
    Cancelled,
    ExceededBudget(SemanticBudgetExceeded),
    Step(E),
}

fn label_matches(requested: Option<&str>, candidate: Option<&str>) -> bool {
    requested.is_none_or(|label| candidate == Some(label))
}

fn derive_blocks(
    pending: &[PendingPoint],
    rich_edges: &[ControlEdge],
    budget: &SemanticBudget,
    base_work: SemanticWork,
) -> Result<(Vec<BasicBlock>, Vec<ProgramPoint>, SemanticWork), SemanticBudgetExceeded> {
    let point_count = pending.len();
    let mut outgoing = vec![Vec::new(); point_count];
    let mut incoming = vec![Vec::new(); point_count];
    let mut logical = HashSet::default();
    for edge in rich_edges {
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
            point
                .events
                .iter()
                .any(|event| is_block_barrier(&event.effect))
        })
        .collect::<Vec<_>>();
    let mut assignments = vec![None; point_count];
    let mut blocks = Vec::new();
    let mut derived_work = SemanticWork::default();

    for start in 0..point_count {
        if assignments[start].is_some() {
            continue;
        }
        let candidate = combine_work(
            derived_work,
            SemanticWork {
                blocks: 1,
                ..SemanticWork::default()
            },
        );
        budget.check(combine_work(base_work, candidate))?;
        derived_work = candidate;
        let block_id = BlockId::try_from_index(blocks.len())
            .expect("block count cannot exceed program-point count");
        let mut members = Vec::new();
        let mut cursor = ProgramPointId::try_from_index(start).expect("point IDs already fit");
        loop {
            if assignments[cursor.index()].replace(block_id).is_some() {
                break;
            }
            let candidate = combine_work(
                derived_work,
                SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                },
            );
            budget.check(combine_work(base_work, candidate))?;
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
        .map(|(index, pending)| ProgramPoint {
            id: ProgramPointId::try_from_index(index).expect("pending point ID already fit"),
            block: assignments[index].expect("every dense point is assigned to a block"),
            events: pending.events.clone().into_boxed_slice(),
            source: pending.source,
            evidence: pending.evidence,
        })
        .collect();
    Ok((blocks, points, derived_work))
}

fn is_block_barrier(effect: &super::SemanticEffect) -> bool {
    matches!(
        effect,
        super::SemanticEffect::NormalExit
            | super::SemanticEffect::ExceptionalExit
            | super::SemanticEffect::Invoke { .. }
            | super::SemanticEffect::ProcedureReturn { .. }
            | super::SemanticEffect::Throw { .. }
            | super::SemanticEffect::AsyncSuspend { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, ProcedureId, ProcedureKind,
        SemanticBudgetDimension, SemanticEffect, SemanticLanguage, SemanticLocator, SemanticRole,
        SourceAnchor, SourcePosition, SourceSpan, WorkspaceMountId, WorkspaceRelativePath,
    };

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
            SemanticLanguage::Standard(crate::analyzer::Language::TypeScript),
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
    fn iterative_driver_handles_deep_work_without_recursion() {
        let mut builder = builder();
        builder
            .drive_iteratively(
                100_000_usize,
                &super::super::CancellationToken::default(),
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
    fn builder_budget_includes_procedure_and_retained_locator_identity() {
        let builder = builder();
        let work = builder.prospective_work();

        assert_eq!(work.procedures, 1);
        assert!(work.nested_entries >= 2);
        assert!(work.owned_text_bytes > 0);
    }

    #[test]
    fn structured_continue_retains_its_loop_specific_edge_kind() {
        let mut builder = builder();
        let normal_exit = point(&mut builder, SemanticEffect::NormalExit);
        let exceptional_exit = point(&mut builder, SemanticEffect::ExceptionalExit);
        let loop_test = point(&mut builder, SemanticEffect::Entry);
        let function = builder.push_scope(
            None,
            ScopeBinding::Function {
                return_target: normal_exit,
                throw_target: exceptional_exit,
            },
        );
        let loop_scope = builder.push_scope(
            Some(function),
            ScopeBinding::Loop {
                label: Some("outer".into()),
                break_target: normal_exit,
                break_edge_kind: ControlEdgeKind::Normal,
                continue_target: loop_test,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );

        let route = builder
            .resolve_completion(
                loop_scope,
                &CompletionRequest::new(CompletionKind::Continue, Some("outer")),
            )
            .expect("labeled continue should resolve to the labeled loop");
        assert_eq!(route.destination().target(), loop_test);
        assert_eq!(route.destination().edge_kind(), ControlEdgeKind::LoopBack);
    }

    #[test]
    fn structured_break_retains_its_downstream_edge_kind() {
        let mut builder = builder();
        let outer_test = point(&mut builder, SemanticEffect::Entry);
        let breakable = builder.push_scope(
            None,
            ScopeBinding::Breakable {
                label: None,
                break_target: outer_test,
                break_edge_kind: ControlEdgeKind::LoopBack,
            },
        );

        let route = builder
            .resolve_completion(
                breakable,
                &CompletionRequest::new(CompletionKind::Break, None),
            )
            .expect("break should resolve through the nested breakable scope");
        assert_eq!(route.destination().target(), outer_test);
        assert_eq!(route.destination().edge_kind(), ControlEdgeKind::LoopBack);
    }

    #[test]
    fn disconnected_scope_intercepts_labeled_control_before_live_outer_scopes() {
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

        for (kind, edge_kind) in [
            (CompletionKind::Break, ControlEdgeKind::Normal),
            (CompletionKind::Continue, ControlEdgeKind::LoopBack),
        ] {
            let route = builder
                .resolve_completion(disconnected, &CompletionRequest::new(kind, Some("outer")))
                .expect("disconnected completion should resolve");
            assert_eq!(route.destination().target(), dead_control);
            assert_eq!(route.destination().edge_kind(), edge_kind);
        }
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
            .finish_with_work()
            .expect_err("three disconnected points require three blocks");
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::Blocks);
        assert_eq!(exceeded.limit(), 2);
        assert_eq!(exceeded.attempted(), 3);
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
                &super::super::CancellationToken::default(),
            )
            .expect("reachability seal");
        let (parts, work) = builder.finish_with_work().expect("finish");

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
        let (parts, frozen_work) = builder.finish_with_work().expect("finish");

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
        let outer = builder.push_scope(
            Some(function),
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

        let (return_entry, created) = builder
            .cleanup_specialization(&returning, 0, SourceMappingId::new(0), EvidenceId::new(0))
            .expect("return cleanup");
        assert!(created);
        let (same_return, created) = builder
            .cleanup_specialization(&returning, 0, SourceMappingId::new(0), EvidenceId::new(0))
            .expect("same return cleanup");
        assert!(!created);
        assert_eq!(same_return, return_entry);
        let (throw_entry, created) = builder
            .cleanup_specialization(&throwing, 0, SourceMappingId::new(0), EvidenceId::new(0))
            .expect("throw cleanup");
        assert!(created);
        assert_ne!(throw_entry, return_entry);
    }
}
