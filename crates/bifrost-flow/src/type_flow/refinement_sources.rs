//! May-source evidence at ordered definition boundaries in a preliminary solve.

use super::correlations::CorrelationError;
use crate::analyzer::semantic::{
    CancellationToken, EvidenceCompleteness, ProgramPointHandle, ProofStatus, SemanticBudget,
    SemanticWork,
};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowObservationPhase, ValueFlowPlan,
    ValueFlowSourceId, ValueFlowSummaryResult,
};

type Sources = HashMap<ValueFlowSourceId, bool>;
type Carriers = HashMap<ValueFlowCarrierId, Sources>;

pub(super) struct DefinitionSources {
    incoming: HashMap<ProgramPointHandle, Carriers>,
}

impl DefinitionSources {
    pub fn new(
        result: &ValueFlowSummaryResult,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<Self, CorrelationError> {
        let mut incoming = HashMap::<ProgramPointHandle, Carriers>::default();
        for reached in result.result().reached() {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            let fact = result
                .result()
                .fact(reached.fact())
                .expect("a retained fact is interned");
            let (Some(carrier), Some(source)) = (fact.carrier(), fact.source()) else {
                continue;
            };
            let sources = incoming
                .entry(reached.point().clone())
                .or_default()
                .entry(carrier)
                .or_default();
            sources
                .entry(source)
                .and_modify(|uncertain| *uncertain |= !fact.uncertainty().is_empty())
                .or_insert(!fact.uncertainty().is_empty());
        }
        Ok(Self { incoming })
    }

    pub fn before(
        &self,
        plan: &ValueFlowPlan,
        point: &ProgramPointHandle,
        event: usize,
        carrier: &ValueFlowCarrier,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<(ValueFlowSourceId, bool)>>, CorrelationError> {
        check_cancelled(cancellation)?;
        let target = plan.carrier_id(carrier);
        let Some(target) = target else {
            return Ok(None);
        };
        let mut rules = Vec::new();
        for rule in plan.local_rule_views(point) {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            if (rule.event_index as usize) >= event {
                break;
            }
            rules.push(rule);
        }
        // Only incoming carriers that can reach this observation are needed.
        // Backward dependency selection uses the same ordered replacement
        // semantics as the forward replay below. In particular, a direct
        // store at event zero only reads its RHS carrier, not every live value.
        let mut needed = HashSet::from_iter([target]);
        for rule in rules.iter().rev() {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            if needed.contains(&rule.target) {
                if crate::value_flow::rule_kills_target(rule) {
                    needed.remove(&rule.target);
                }
                needed.insert(rule.source);
            }
        }
        let mut active = clone_carriers(self.incoming.get(point), &needed, budget, cancellation)?;
        for source in plan.sources_at(point, ValueFlowObservationPhase::BeforeEffects) {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            if !needed.contains(&source.carrier) {
                continue;
            }
            let uncertain = source_is_uncertain(source.spec.proof(), source.spec.completeness());
            active
                .entry(source.carrier)
                .or_default()
                .entry(source.id)
                .and_modify(|old| *old |= uncertain)
                .or_insert(uncertain);
        }
        for rule in rules {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            let sources = clone_sources(active.get(&rule.source), budget, cancellation)?;
            if crate::value_flow::rule_kills_target(&rule) {
                active.remove(&rule.target);
            }
            if let Some(sources) = sources {
                let destination = active.entry(rule.target).or_default();
                for (source, uncertain) in sources {
                    check_cancelled(cancellation)?;
                    charge_entries(budget, 1)?;
                    destination
                        .entry(source)
                        .and_modify(|old| *old |= uncertain || !rule.complete)
                        .or_insert(uncertain || !rule.complete);
                }
            }
        }
        check_cancelled(cancellation)?;
        let Some(sources) = active.remove(&target) else {
            return Ok(None);
        };
        if sources.is_empty() {
            return Ok(None);
        }
        charge_entries(budget, sources.len())?;
        let mut sources = sources.into_iter().collect::<Vec<_>>();
        sources.sort_unstable_by_key(|(source, _)| *source);
        check_cancelled(cancellation)?;
        Ok(Some(sources))
    }
}

fn source_is_uncertain(proof: &ProofStatus, completeness: &EvidenceCompleteness) -> bool {
    !matches!(proof, ProofStatus::Proven) || !matches!(completeness, EvidenceCompleteness::Complete)
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), CorrelationError> {
    if cancellation.is_cancelled() {
        return Err(CorrelationError::Cancelled {
            timed_out: cancellation.is_timed_out(),
        });
    }
    Ok(())
}

fn charge_entries(budget: &mut SemanticBudget, count: usize) -> Result<(), CorrelationError> {
    if count == 0 {
        return Ok(());
    }
    budget.charge(SemanticWork {
        nested_entries: count,
        ..SemanticWork::default()
    })?;
    Ok(())
}

fn clone_carriers(
    incoming: Option<&Carriers>,
    needed: &HashSet<ValueFlowCarrierId>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<Carriers, CorrelationError> {
    let mut cloned = Carriers::default();
    let Some(incoming) = incoming else {
        return Ok(cloned);
    };
    for &carrier in needed {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        let Some(sources) = incoming.get(&carrier) else {
            continue;
        };
        let cloned_sources =
            clone_sources(Some(sources), budget, cancellation)?.expect("sources are present");
        cloned.insert(carrier, cloned_sources);
    }
    Ok(cloned)
}

fn clone_sources(
    sources: Option<&Sources>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<Option<Sources>, CorrelationError> {
    let Some(sources) = sources else {
        return Ok(None);
    };
    let mut cloned = Sources::default();
    for (&source, &uncertain) in sources {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        cloned.insert(source, uncertain);
    }
    Ok(Some(cloned))
}
