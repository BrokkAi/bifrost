//! Exact bridge from shared call conversion proofs to semantic call bindings.

use super::WorkspaceSemanticOracle;
use super::dispatch::{
    ProcedureRangeLookupStatus, exact_call_range, exact_source_for_procedure,
    procedures_for_definition_with_limits,
};
use crate::analyzer::semantic::{
    CallSiteHandle, DispatchCandidate, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticWork, ValueTransfer,
};
use crate::analyzer::usages::CallBindingCache;
use crate::analyzer::usages::call_binding::{
    CallBindingTarget, CallReceiverBinding, call_binding_report,
};
use crate::analyzer::usages::call_conversion::{CallConversionCache, ConversionUnknown};
use crate::analyzer::usages::call_shape::call_shapes_in_file;
use crate::analyzer::usages::callable_signature::callable_signature_reports;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_call_target_batch_with_source,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope, Range};

#[derive(Clone)]
pub(super) struct ArgumentConversion {
    pub range: Range,
    pub formal: usize,
    pub transfer: Result<Option<ValueTransfer>, ConversionUnknown>,
}

impl WorkspaceSemanticOracle<'_> {
    pub(super) fn java_call_conversions(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Vec<ArgumentConversion>>, SemanticProviderError> {
        let mut work = SemanticWork::default();
        macro_rules! charge {
            ($cost:expr) => {{
                let cost = $cost;
                work = work.conservative_add(cost);
                if let Err(exceeded) = request.budget.charge(cost) {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                if request.cancellation.is_cancelled() {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    });
                }
            }};
        }
        let mut sources = Vec::new();
        for procedure in [call.procedure(), candidate.target()] {
            let remaining = request.budget.remaining().source_bytes;
            let Some(source) = exact_source_for_procedure(self.workspace, procedure, remaining)?
            else {
                charge!(SemanticWork {
                    source_bytes: remaining.saturating_add(1),
                    ..SemanticWork::default()
                });
                unreachable!("over-budget source charge must stop");
            };
            charge!(SemanticWork {
                source_bytes: source.1.len(),
                ..SemanticWork::default()
            });
            sources.push(source);
        }
        let (file, source) = &sources[0];
        let analyzer = self.workspace.analyzer();
        let range = exact_call_range(call)?;
        let Some(facts) = analyzer
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file))
        else {
            return Ok(SemanticOutcome::Unknown {
                partial: None,
                work,
            });
        };
        charge!(SemanticWork {
            nested_entries: facts.nodes().len(),
            ..SemanticWork::default()
        });
        let mut examined = 0;
        let result = (|| {
            let shapes = call_shapes_in_file(&facts, file, facts.nodes().len());
            let mut matches = shapes.into_iter().filter(|shape| {
                shape.outcome.range.start_byte == range.start_byte
                    && shape.outcome.range.end_byte == range.end_byte
            });
            let shape = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            let callee_range = shape.outcome.callee_range?;
            let scope = AnalyzerQueryScope::with_semantic_model_overlay(
                analyzer,
                self.semantic_model_overlay(),
            );
            let lookup = resolve_call_target_batch_with_source(
                analyzer,
                scope.token(),
                vec![DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(callee_range.start_byte),
                    end_byte: Some(callee_range.end_byte),
                }],
                file.clone(),
                source.clone(),
                Some(request.cancellation),
            )
            .into_iter()
            .next()?;
            if lookup.outcome.status != DefinitionLookupStatus::Resolved
                || lookup.truncated
                || lookup.structure_unavailable
                || lookup.unproven_link_unit
            {
                return None;
            }
            let [target] = lookup.outcome.definitions.as_slice() else {
                return None;
            };
            if target.source() != &sources[1].0 {
                return None;
            }
            let procedures = procedures_for_definition_with_limits(
                analyzer,
                target,
                candidate.target().artifact(),
                request.budget.remaining().nested_entries,
                request.cancellation,
            );
            examined = if procedures.status == ProcedureRangeLookupStatus::BudgetExhausted {
                request.budget.remaining().nested_entries.saturating_add(1)
            } else {
                procedures.examined
            };
            if procedures.status != ProcedureRangeLookupStatus::Complete
                || procedures.handles.as_slice() != [candidate.target().clone()]
            {
                return None;
            }
            let ranges = analyzer.ranges_of(target);
            let [range] = ranges.as_slice() else {
                return None;
            };
            let metadata = analyzer.signature_metadata(target);
            if metadata.len() != 1 {
                return None;
            }
            let site_id = target
                .declaration_site_id(range.start_byte, range.end_byte)
                .to_string();
            let signatures = callable_signature_reports(&site_id, target, &metadata);
            let [signature] = signatures.as_slice() else {
                return None;
            };
            let mut bindings = CallBindingCache::default();
            let layout = bindings.formal_layout(analyzer, target, shape.arguments.len())?;
            // Java receivers do not consume an ordinary parameter slot. The
            // semantic binder retains their separate receiver evidence.
            let mut report = call_binding_report(
                file,
                &shape,
                CallBindingTarget::Resolved {
                    unit: target.clone(),
                    layout,
                    receiver: CallReceiverBinding::Absent,
                },
            );
            CallConversionCache::default().populate(
                analyzer,
                &mut report,
                Some(&signature.signature.id),
            );
            let conversions = report
                .rows
                .iter()
                .filter_map(|row| {
                    let formal = row.formal_index?;
                    row.argument_id.as_ref()?;
                    let mut matching = report.conversion_facts.iter().filter(|fact| {
                        row.argument_id == fact.argument_id
                            && row.site_id == fact.site_id
                            && row.formal_index == fact.formal_index
                            && fact.target.as_ref() == Some(target)
                            && fact.selected_signature.as_deref()
                                == Some(signature.signature.id.as_str())
                    });
                    let fact = matching
                        .next()
                        .expect("producer retains each exact actual/formal result");
                    assert!(matching.next().is_none(), "unique conversion witness");
                    Some(ArgumentConversion {
                        range: row.range,
                        formal,
                        transfer: fact
                            .result
                            .as_ref()
                            .map(|_| fact.transfer())
                            .map_err(|reason| *reason),
                    })
                })
                .collect();
            Some(conversions)
        })();
        charge!(SemanticWork {
            nested_entries: examined,
            ..SemanticWork::default()
        });
        let Some(value) = result else {
            return Ok(SemanticOutcome::Unknown {
                partial: None,
                work,
            });
        };
        Ok(SemanticOutcome::Complete { value, work })
    }
}
