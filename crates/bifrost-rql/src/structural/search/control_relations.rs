//! The execution adapter between the query engine and the shared control-flow
//! algorithms (#2443, the first slice of #2102's exposure).
//!
//! One *control relation* says how two program points of one procedure's
//! production control-flow graph relate: `dominates`, `postdominates`,
//! `control_depends_on`, `reachable` (from the procedure entry), and `in_loop`.
//! Every row joins on the same stable wire ids the `program_point` and
//! `control_edge` rows publish, so a policy relates "the point that calls
//! validate" to "the point that calls store" by id equality rather than by
//! comparing ranges.
//!
//! No algorithm lives here. `crate::analyzer::semantic::cfg_algorithms` stays
//! the single source of truth for all five; this module runs them once per
//! procedure under one shared [`CfgAlgorithmBudget`], turns their answers into
//! rows, and turns their failures into typed diagnostics.
//!
//! Three properties the rows are built to keep:
//!
//! * Budget exhaustion and cancellation are *absence of evidence*. The affected
//!   relation emits no row at all and the derivation records the reason, so an
//!   empty `postdominates` set is never readable as "nothing postdominates".
//! * A backward claim states the exit universe it was computed against.
//!   Postdominance and control dependence are computed against one universe
//!   holding both real exits, which every row spells as
//!   `normal_and_exceptional`. A partitioned derivation would add a value, not
//!   change a column.
//! * A live region with no path to either exit makes every postdominance and
//!   control-dependence claim in the procedure a claim about terminating
//!   executions only, so those rows are downgraded to `may` and `partial`
//!   rather than presented as exact.
//!
//! Deliberately not stored: like the flow-state and rewrite-path row families,
//! these rows are derived on demand from one already-materialized artifact and
//! memoised per request. Nothing is added to the semantic IR, so no language
//! adapter version moves and no cached artifact rotates.

use super::results::{
    CodeQueryControlRelation, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryResultRef, DetailedCodeQueryKey,
};
use super::semantic::SemanticProcedureValue;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, CfgAlgorithmWork,
    LoopEntryStructure, control_dependence, dominators, forward_reachability, loop_regions,
    postdominators,
};
use crate::analyzer::semantic::{ControlEdgeId, ProcedureHandle, ProgramPointId};
use crate::analyzer::{Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::structural::control_relation::{
    ALL_CONTROL_RELATION_KINDS, ControlExitPartition, ControlRelationKind,
};
use brokk_bifrost_core::analyzer::structural::flow_state::FlowCertainty;
use brokk_bifrost_rql::ControlRelationFilter;
use std::sync::Arc;

/// The work one procedure's control-relation derivation may spend.
///
/// The pairwise relations are quadratic in the procedure's program-point count
/// by construction -- a straight-line procedure of `n` points really does have
/// `n * (n - 1) / 2` dominance pairs -- so the derivation charges one node visit
/// per candidate pair it considers and stops when the ledger is spent. A
/// procedure large enough to exhaust this is answered `Incomplete` with the
/// exact overrun, which is the honest answer; silently truncating the row set
/// would let a policy read a missing dominance row as a proven absence.
///
/// The limit is deliberately a fixed constant rather than a function of the
/// procedure: it is a bound on what one query is willing to spend, not a
/// property of the code under analysis.
pub(super) const CONTROL_RELATION_WORK_LIMIT: CfgAlgorithmWork = CfgAlgorithmWork {
    node_visits: 60_000,
    edge_visits: 60_000,
};

/// One derived control relation between two program points of one procedure.
///
/// Dense procedure-local ids travel here; the wire ids a policy joins on are
/// minted at projection time from the same procedure handle the derivation ran
/// over, so the two row families cannot disagree about a point's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ControlRelationRow {
    pub(super) relation: ControlRelationKind,
    pub(super) source: ProgramPointId,
    pub(super) target: ProgramPointId,
    /// The branch edge whose outcome governs the target, present exactly for
    /// `control_depends_on`.
    pub(super) controlling_edge: Option<ControlEdgeId>,
    pub(super) certainty: FlowCertainty,
}

/// Why a derivation's rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ControlRelationIncompleteReason {
    /// The shared budget ran out inside one relation's derivation. That
    /// relation emitted no rows at all; truncation is never silent.
    BudgetExhausted {
        relation: ControlRelationKind,
        detail: String,
    },
    /// The derivation was cancelled. No relation is complete.
    Cancelled,
    /// The procedure has a live region with no path to either real exit, so a
    /// postdominance claim is a claim about terminating executions only.
    NonExitingRegion { points: usize },
    /// A cyclic region no edge enters from outside, so no program point is its
    /// header and its membership rows have no source to hang off.
    LoopWithoutEntry { regions: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ControlRelationCompleteness {
    Complete,
    Incomplete {
        reasons: Vec<ControlRelationIncompleteReason>,
    },
}

impl ControlRelationCompleteness {
    pub(super) fn reasons(&self) -> &[ControlRelationIncompleteReason] {
        match self {
            Self::Complete => &[],
            Self::Incomplete { reasons } => reasons,
        }
    }

    /// Whether rows for `relation` can be trusted to be the complete set.
    ///
    /// Total over the reason vocabulary on purpose: a reason added later must
    /// be classified deliberately rather than defaulting into silence.
    pub(super) fn covers(&self, relation: ControlRelationKind) -> bool {
        use ControlRelationIncompleteReason::*;
        !self.reasons().iter().any(|reason| match reason {
            BudgetExhausted { relation: got, .. } => *got == relation,
            Cancelled => true,
            NonExitingRegion { .. } => relation.depends_on_exit_partition(),
            LoopWithoutEntry { .. } => relation == ControlRelationKind::InLoop,
        })
    }

    fn from_reasons(reasons: Vec<ControlRelationIncompleteReason>) -> Self {
        if reasons.is_empty() {
            Self::Complete
        } else {
            Self::Incomplete { reasons }
        }
    }
}

/// One procedure's control relations plus the account of what is missing.
#[derive(Debug, Clone)]
pub(super) struct ProcedureControlRelations {
    pub(super) rows: Vec<ControlRelationRow>,
    pub(super) completeness: ControlRelationCompleteness,
    pub(super) generation: u64,
}

/// Derive every control relation of one procedure.
///
/// All five algorithms share one budget ledger, so a procedure cannot spend the
/// whole allowance on dominance and then report the other four as absent
/// without a reason: whichever relation the ledger runs out inside records its
/// own `BudgetExhausted` and the ones after it record theirs.
pub(super) fn control_relations_for_procedure(
    handle: &ProcedureHandle,
    generation: u64,
    cancellation: &CancellationToken,
    budget: &mut CfgAlgorithmBudget,
) -> ProcedureControlRelations {
    let procedure = handle.semantics();
    let entry = procedure.entry_point();
    let mut rows = Vec::new();
    let mut reasons = Vec::new();
    let mut request = CfgAlgorithmRequest::new(budget, cancellation);

    // Forward reachability first: it is the cheapest, it is the relation the
    // other four are only meaningful over, and its membership vector narrows
    // every pairwise walk below to points that actually execute.
    let reachable = match forward_reachability(procedure, entry, &mut request) {
        Ok(reachable) => reachable,
        Err(error) => {
            // Without reachability there is no honest domain to enumerate the
            // pairwise relations over, so every relation is unanswered.
            for relation in ALL_CONTROL_RELATION_KINDS {
                push_algorithm_reason(&error, *relation, &mut reasons);
            }
            return ProcedureControlRelations {
                rows,
                completeness: ControlRelationCompleteness::from_reasons(reasons),
                generation,
            };
        }
    };
    let live: Vec<ProgramPointId> = reachable
        .membership()
        .iter()
        .enumerate()
        .filter(|(_, reached)| **reached)
        .map(|(index, _)| {
            ProgramPointId::try_from_index(index).expect("a validated point index fits u32")
        })
        .collect();
    for point in live.iter().copied().filter(|point| *point != entry) {
        rows.push(ControlRelationRow {
            relation: ControlRelationKind::Reachable,
            source: entry,
            target: point,
            controlling_edge: None,
            certainty: FlowCertainty::Exact,
        });
    }

    match dominators(procedure, entry, &mut request) {
        Ok(dominance) => {
            if let Err(error) = ancestor_rows(
                &live,
                &mut request,
                &mut rows,
                ControlRelationKind::Dominates,
                FlowCertainty::Exact,
                |point| dominance.immediate_dominator(procedure, point),
            ) {
                rows.retain(|row| row.relation != ControlRelationKind::Dominates);
                push_algorithm_reason(&error, ControlRelationKind::Dominates, &mut reasons);
            }
        }
        Err(error) => push_algorithm_reason(&error, ControlRelationKind::Dominates, &mut reasons),
    }

    // Postdominance and control dependence share one exit universe and one
    // divergence caveat, so they are derived together.
    let normal_exit = procedure.normal_exit_point();
    let exceptional_exit = procedure.exceptional_exit_point();
    match postdominators(
        procedure,
        entry,
        normal_exit,
        exceptional_exit,
        &mut request,
    ) {
        Ok(postdominance) => {
            let diverging: usize = postdominance
                .non_exiting_regions
                .iter()
                .map(|region| region.members.len())
                .sum();
            if diverging > 0 {
                reasons
                    .push(ControlRelationIncompleteReason::NonExitingRegion { points: diverging });
            }
            // A procedure that can diverge has executions that never reach an
            // exit, so "every path to an exit passes the source" is no longer a
            // statement about every execution. The derivation does not compute
            // which points can reach the divergent region, so it downgrades the
            // whole relation rather than claiming a precision it did not earn.
            let certainty = if diverging > 0 {
                FlowCertainty::May
            } else {
                FlowCertainty::Exact
            };
            if let Err(error) = ancestor_rows(
                &live,
                &mut request,
                &mut rows,
                ControlRelationKind::Postdominates,
                certainty,
                |point| postdominance.immediate_postdominator(procedure, point),
            ) {
                rows.retain(|row| row.relation != ControlRelationKind::Postdominates);
                push_algorithm_reason(&error, ControlRelationKind::Postdominates, &mut reasons);
            }
            match control_dependence(
                procedure,
                entry,
                normal_exit,
                exceptional_exit,
                &mut request,
            ) {
                Ok(dependence) => {
                    for row in dependence.rows.iter() {
                        let Some(edge) = procedure.control_edge(row.controlling_edge) else {
                            continue;
                        };
                        rows.push(ControlRelationRow {
                            relation: ControlRelationKind::ControlDependsOn,
                            source: edge.source_point,
                            target: row.governed,
                            controlling_edge: Some(row.controlling_edge),
                            certainty,
                        });
                    }
                }
                Err(error) => push_algorithm_reason(
                    &error,
                    ControlRelationKind::ControlDependsOn,
                    &mut reasons,
                ),
            }
        }
        Err(error) => {
            push_algorithm_reason(&error, ControlRelationKind::Postdominates, &mut reasons);
            push_algorithm_reason(&error, ControlRelationKind::ControlDependsOn, &mut reasons);
        }
    }

    match loop_regions(procedure, &mut request) {
        Ok(regions) => {
            let mut headerless = 0usize;
            for region in regions.regions.iter() {
                if region.entries.is_empty() {
                    headerless = headerless.saturating_add(1);
                    continue;
                }
                // An irreducible loop has several entries and therefore no
                // header, so "member of the loop entered here" holds only for
                // the executions that entered through this one.
                let certainty = match region.entry_structure {
                    LoopEntryStructure::Single => FlowCertainty::Exact,
                    LoopEntryStructure::Multiple | LoopEntryStructure::None => FlowCertainty::May,
                };
                for entry_point in region.entries.iter().copied() {
                    for member in region.members.iter().copied() {
                        rows.push(ControlRelationRow {
                            relation: ControlRelationKind::InLoop,
                            source: entry_point,
                            target: member,
                            controlling_edge: None,
                            certainty,
                        });
                    }
                }
            }
            if headerless > 0 {
                reasons.push(ControlRelationIncompleteReason::LoopWithoutEntry {
                    regions: headerless,
                });
            }
        }
        Err(error) => push_algorithm_reason(&error, ControlRelationKind::InLoop, &mut reasons),
    }

    // One canonical order, so two derivations of one artifact produce identical
    // rows and a policy's row identities do not depend on algorithm order.
    rows.sort_unstable_by_key(|row| {
        (
            row.relation as u8,
            row.source.index(),
            row.target.index(),
            row.controlling_edge.map_or(usize::MAX, |edge| edge.index()),
        )
    });
    rows.dedup();

    ProcedureControlRelations {
        rows,
        completeness: ControlRelationCompleteness::from_reasons(reasons),
        generation,
    }
}

/// The transitive closure of one immediate-ancestor function, as rows.
///
/// Dominance and postdominance are both trees: `a` dominates `b` exactly when
/// `a` is on `b`'s immediate-dominator chain, and likewise for postdominance.
/// Walking each live point's chain therefore enumerates the whole relation and
/// costs one charge per row it emits, where asking the `dominates` predicate
/// about every ordered pair would cost one chain walk per pair -- quadratic
/// work to discover a relation that is only as large as it is.
///
/// The charge per emitted row is what bounds the result: the relation itself is
/// quadratic in the procedure's point count (a straight-line procedure of `n`
/// points really does have `n * (n - 1) / 2` dominance pairs), so the ledger,
/// not the code, decides how large a procedure one query is willing to relate.
/// An overrun returns the exact failure and the caller drops the partial rows,
/// because a truncated relation would let a policy read a missing row as a
/// proven absence.
///
/// The walk terminates on its own -- an immediate-ancestor chain strictly
/// ascends and the root reports `None` -- and the assertion states that, so a
/// future ancestor function that returned a cycle would fail loudly here rather
/// than spinning until the budget ran out.
fn ancestor_rows(
    live: &[ProgramPointId],
    request: &mut CfgAlgorithmRequest<'_>,
    rows: &mut Vec<ControlRelationRow>,
    relation: ControlRelationKind,
    certainty: FlowCertainty,
    immediate_ancestor: impl Fn(ProgramPointId) -> Option<ProgramPointId>,
) -> Result<(), CfgAlgorithmError<ProgramPointId>> {
    for target in live.iter().copied() {
        let mut cursor = target;
        let mut steps = 0usize;
        while let Some(ancestor) = immediate_ancestor(cursor) {
            request.visit_pair()?;
            rows.push(ControlRelationRow {
                relation,
                source: ancestor,
                target,
                controlling_edge: None,
                certainty,
            });
            cursor = ancestor;
            steps = steps.saturating_add(1);
            debug_assert!(
                steps <= live.len(),
                "an immediate-ancestor chain must strictly ascend, so it cannot revisit a point"
            );
        }
    }
    Ok(())
}

fn push_algorithm_reason(
    error: &CfgAlgorithmError<ProgramPointId>,
    relation: ControlRelationKind,
    reasons: &mut Vec<ControlRelationIncompleteReason>,
) {
    match error {
        CfgAlgorithmError::Cancelled { .. } => {
            if !reasons.contains(&ControlRelationIncompleteReason::Cancelled) {
                reasons.push(ControlRelationIncompleteReason::Cancelled);
            }
        }
        CfgAlgorithmError::ExceededBudget(exceeded) => {
            reasons.push(ControlRelationIncompleteReason::BudgetExhausted {
                relation,
                detail: format!(
                    "{:?} limit {} exceeded at {}",
                    exceeded.limit_kind, exceeded.limit, exceeded.attempted
                ),
            });
        }
        CfgAlgorithmError::InvalidNode(node) => {
            unreachable!("a validated procedure owns its own program point {node:?}")
        }
    }
}

/// Per-request memo of derived control relations plus the diagnostics already
/// reported, so one procedure is derived once and one reason is reported once.
///
/// The budget is the *request's*, not the procedure's: a query that relates
/// twenty procedures spends one allowance across all of them, which is what
/// keeps a broad query bounded instead of bounded twenty times over.
pub(super) struct ControlRelationTraversalCache {
    procedures: HashMap<ProcedureHandle, Arc<ProcedureControlRelations>>,
    reported: HashSet<(String, &'static str)>,
    budget: CfgAlgorithmBudget,
}

impl Default for ControlRelationTraversalCache {
    fn default() -> Self {
        Self {
            procedures: HashMap::default(),
            reported: HashSet::default(),
            budget: CfgAlgorithmBudget::new(CONTROL_RELATION_WORK_LIMIT),
        }
    }
}

impl ControlRelationTraversalCache {
    /// Derive (or replay) the control relations of one procedure.
    pub(super) fn for_procedure(
        &mut self,
        procedure: &SemanticProcedureValue,
        generation: u64,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<ProcedureControlRelations> {
        if let Some(cached) = self.procedures.get(&procedure.handle) {
            return Arc::clone(cached);
        }
        let token = cancellation.cloned().unwrap_or_default();
        let derived = Arc::new(control_relations_for_procedure(
            &procedure.handle,
            generation,
            &token,
            &mut self.budget,
        ));
        self.procedures
            .insert(procedure.handle.clone(), Arc::clone(&derived));
        derived
    }

    /// Turn one derivation's completeness into typed diagnostics.
    ///
    /// Reported before any filter runs, so a `:relation postdominates` filter
    /// that drops every row still leaves the reason the answer is partial on
    /// the response. `subject` is the procedure's own wire id.
    pub(super) fn report_completeness(
        &mut self,
        subject: &str,
        language: Language,
        relations: &ProcedureControlRelations,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        for reason in relations.completeness.reasons() {
            let (code, detail) = classify_reason(reason);
            if !self.reported.insert((subject.to_string(), detail)) {
                continue;
            }
            diagnostics.push(CodeQueryDiagnostic {
                code,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "procedure {subject} has an incomplete control-relation derivation in \
                     generation {} ({detail}); uncovered relations: [{}]",
                    relations.generation,
                    uncovered_relations(&relations.completeness).join(", ")
                ),
            });
        }
    }
}

/// The diagnostic code and human reason of one incompleteness.
///
/// Total on purpose: a reason added to the derivation above must be classified
/// here deliberately rather than defaulting into a generic message.
fn classify_reason(
    reason: &ControlRelationIncompleteReason,
) -> (CodeQueryDiagnosticCode, &'static str) {
    match reason {
        ControlRelationIncompleteReason::BudgetExhausted { .. } => (
            CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete,
            "a control-flow algorithm exhausted its budget, so its relation emitted no rows",
        ),
        ControlRelationIncompleteReason::Cancelled => (
            CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete,
            "the derivation was cancelled",
        ),
        ControlRelationIncompleteReason::NonExitingRegion { .. } => (
            CodeQueryDiagnosticCode::ControlRelationExitPartitionPartial,
            "the procedure has a live region with no path to either exit, so a backward claim \
             covers terminating executions only",
        ),
        ControlRelationIncompleteReason::LoopWithoutEntry { .. } => (
            CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete,
            "a cyclic region has no entry edge, so its membership has no header to hang off",
        ),
    }
}

/// One control-relation row travelling through the pipeline.
///
/// The whole procedure derivation is held by `Arc` rather than the single row:
/// one query commonly asks for every relation of a procedure, and the rows
/// share it. The seed procedure travels too, because a wire id can only be
/// minted from the handle the derivation ran over.
#[derive(Debug, Clone)]
pub(super) struct ControlRelationValue {
    pub(super) relations: Arc<ProcedureControlRelations>,
    pub(super) index: usize,
    pub(super) procedure: SemanticProcedureValue,
}

impl ControlRelationValue {
    pub(super) fn row(&self) -> &ControlRelationRow {
        &self.relations.rows[self.index]
    }

    pub(super) fn key(&self) -> ControlRelationKey {
        ControlRelationKey {
            procedure: self.procedure.wire_id(),
            index: self.index,
        }
    }

    /// `complete` exactly when the derivation answers *this row's own relation*;
    /// otherwise `partial`. A row whose family was fully enumerated is not made
    /// partial by a hole in an unrelated relation.
    pub(super) fn completeness_label(&self) -> &'static str {
        if self.relations.completeness.covers(self.row().relation) {
            "complete"
        } else {
            "partial"
        }
    }
}

/// The value domain the `control_relation.completeness` row field publishes,
/// minted by [`ControlRelationValue::completeness_label`] (issue #2515).
pub(super) const CONTROL_RELATION_COMPLETENESS_LABELS: &[&str] = &["complete", "partial"];

/// Dedup identity of a control-relation row: the seed procedure's wire id plus
/// the dense index the derivation minted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ControlRelationKey {
    pub(super) procedure: String,
    pub(super) index: usize,
}

pub(super) fn control_relation_filter_matches(
    filter: &ControlRelationFilter,
    row: &ControlRelationRow,
) -> bool {
    if !filter.relations.is_empty() && !filter.relations.contains(&row.relation) {
        return false;
    }
    // Every row carries the one partition the derivation computes, so a filter
    // naming a reserved partition matches nothing -- which is the truth, not a
    // silent empty answer: the value domain publishes the reserved labels and
    // the row's own `exit_partition` states what was computed.
    if !filter.exit_partitions.is_empty()
        && !filter
            .exit_partitions
            .contains(&ControlExitPartition::DERIVED_TODAY)
    {
        return false;
    }
    true
}

/// Domain separator for the row family's stable ids.
const CONTROL_RELATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.control_relation.v1";

/// The public projection of one control-relation row.
///
/// Both endpoints are rendered inline from the same procedure handle the
/// derivation ran over, so `source.id` and `target.id` are literally the ids a
/// `program_point` row publishes and `controlling_edge_id` is literally a
/// `control_edge` row's id.
pub(super) fn public_control_relation(value: &ControlRelationValue) -> CodeQueryControlRelation {
    let row = value.row();
    let source = value
        .procedure
        .point_value(row.source)
        .expect("a validated procedure owns the point its own relation names")
        .point_ref();
    let target = value
        .procedure
        .point_value(row.target)
        .expect("a validated procedure owns the point its own relation names")
        .point_ref();
    let controlling_edge_id = row.controlling_edge.map(|edge| {
        value
            .procedure
            .edge_value(edge)
            .expect("a validated procedure owns the edge its own relation names")
            .public()
            .id
    });
    let procedure = value.procedure.public();
    let mut digest = LengthDelimitedDigest::new(CONTROL_RELATION_ID_DOMAIN);
    digest.push(procedure.id.as_bytes());
    digest.push(row.relation.label().as_bytes());
    digest.push(ControlExitPartition::DERIVED_TODAY.label().as_bytes());
    digest.push(source.id.as_bytes());
    digest.push(target.id.as_bytes());
    digest.push(controlling_edge_id.as_deref().unwrap_or("").as_bytes());
    CodeQueryControlRelation {
        id: digest.finish().to_string(),
        procedure_id: procedure.id,
        path: procedure.path,
        language: procedure.language,
        range: target.range,
        relation: row.relation.label(),
        certainty: row.certainty.label(),
        exit_partition: ControlExitPartition::DERIVED_TODAY.label(),
        source,
        target,
        controlling_edge_id,
        completeness: value.completeness_label(),
        uncovered_relations: uncovered_relations(&value.relations.completeness),
        generation: value.relations.generation,
    }
}

/// The typed key that addresses one control-relation row in detailed evidence.
pub(super) fn detailed_key(value: &ControlRelationValue) -> DetailedCodeQueryKey {
    let public = public_control_relation(value);
    DetailedCodeQueryKey::ControlRelation {
        id: public.id,
        procedure_id: public.procedure_id,
        relation: public.relation.to_string(),
        certainty: public.certainty.to_string(),
    }
}

/// The row's own source anchor: the target point, which is the position an
/// author is asking about when they ask what dominates or governs it.
pub(super) fn anchor(value: &ControlRelationValue) -> (ProjectFile, Range) {
    let point = value
        .procedure
        .point_value(value.row().target)
        .expect("a validated procedure owns the point its own relation names");
    (value.procedure.file().clone(), point.source_range())
}

/// The trace reference of one control-relation row: enough to name the claim
/// and find it again, without re-rendering both endpoints.
pub(super) fn control_relation_ref(value: &ControlRelationValue) -> CodeQueryResultRef {
    let public = public_control_relation(value);
    CodeQueryResultRef::ControlRelation {
        id: public.id,
        path: public.path,
        range: public.range,
        procedure_id: public.procedure_id,
        relation: public.relation,
        certainty: public.certainty,
        exit_partition: public.exit_partition,
    }
}

fn uncovered_relations(completeness: &ControlRelationCompleteness) -> Vec<&'static str> {
    ALL_CONTROL_RELATION_KINDS
        .iter()
        .filter(|relation| !completeness.covers(**relation))
        .map(|relation| relation.label())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_exhausted(relation: ControlRelationKind) -> ControlRelationCompleteness {
        ControlRelationCompleteness::Incomplete {
            reasons: vec![ControlRelationIncompleteReason::BudgetExhausted {
                relation,
                detail: "NodeVisits limit 1 exceeded at 2".to_string(),
            }],
        }
    }

    /// A hole in one relation is a hole in that relation only. This is the
    /// property that lets a dominance policy stay conclusive when the loop
    /// derivation ran out of budget.
    #[test]
    fn one_relations_budget_hole_leaves_the_others_covered() {
        let completeness = budget_exhausted(ControlRelationKind::InLoop);
        assert!(!completeness.covers(ControlRelationKind::InLoop));
        assert!(completeness.covers(ControlRelationKind::Dominates));
        assert_eq!(uncovered_relations(&completeness), vec!["in_loop"]);
    }

    /// Divergence is a property of the exit universe, so it blocks exactly the
    /// two relations computed backward from the exits.
    #[test]
    fn a_non_exiting_region_blocks_only_the_backward_relations() {
        let completeness = ControlRelationCompleteness::Incomplete {
            reasons: vec![ControlRelationIncompleteReason::NonExitingRegion { points: 3 }],
        };
        assert!(!completeness.covers(ControlRelationKind::Postdominates));
        assert!(!completeness.covers(ControlRelationKind::ControlDependsOn));
        assert!(completeness.covers(ControlRelationKind::Dominates));
        assert!(completeness.covers(ControlRelationKind::Reachable));
        assert!(completeness.covers(ControlRelationKind::InLoop));
    }

    /// Cancellation is not a per-relation hole: nothing the derivation produced
    /// before it can be claimed to be the complete set.
    #[test]
    fn cancellation_covers_nothing() {
        let completeness = ControlRelationCompleteness::Incomplete {
            reasons: vec![ControlRelationIncompleteReason::Cancelled],
        };
        for relation in ALL_CONTROL_RELATION_KINDS {
            assert!(!completeness.covers(*relation), "{relation:?}");
        }
    }

    #[test]
    fn an_incomplete_derivation_reports_every_reason_once_per_procedure() {
        let mut cache = ControlRelationTraversalCache::default();
        let relations = ProcedureControlRelations {
            rows: Vec::new(),
            completeness: ControlRelationCompleteness::Incomplete {
                reasons: vec![
                    ControlRelationIncompleteReason::BudgetExhausted {
                        relation: ControlRelationKind::Dominates,
                        detail: "NodeVisits limit 1 exceeded at 2".to_string(),
                    },
                    ControlRelationIncompleteReason::NonExitingRegion { points: 2 },
                ],
            },
            generation: 7,
        };
        let mut diagnostics = Vec::new();
        cache.report_completeness("procedure-1", Language::Java, &relations, &mut diagnostics);
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete),
            "{diagnostics:?}"
        );
        // The second call adds nothing: one reason is reported once per subject.
        cache.report_completeness("procedure-1", Language::Java, &relations, &mut diagnostics);
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
    }

    #[test]
    fn a_relation_filter_keeps_only_the_named_relation() {
        let row = ControlRelationRow {
            relation: ControlRelationKind::Dominates,
            source: ProgramPointId::try_from_index(0).expect("index fits"),
            target: ProgramPointId::try_from_index(1).expect("index fits"),
            controlling_edge: None,
            certainty: FlowCertainty::Exact,
        };
        let filter = ControlRelationFilter {
            relations: vec![ControlRelationKind::Postdominates],
            exit_partitions: Vec::new(),
        };
        assert!(!control_relation_filter_matches(&filter, &row));
        assert!(control_relation_filter_matches(
            &ControlRelationFilter::default(),
            &row
        ));
        // A reserved partition is a partition no row was computed against.
        let reserved = ControlRelationFilter {
            relations: Vec::new(),
            exit_partitions: vec![ControlExitPartition::NormalOnly],
        };
        assert!(!control_relation_filter_matches(&reserved, &row));
        let derived = ControlRelationFilter {
            relations: Vec::new(),
            exit_partitions: vec![ControlExitPartition::NormalAndExceptional],
        };
        assert!(control_relation_filter_matches(&derived, &row));
    }
}
