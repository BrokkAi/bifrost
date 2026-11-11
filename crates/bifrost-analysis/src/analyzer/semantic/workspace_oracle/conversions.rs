//! Exact bridge from shared call conversion proofs to semantic call bindings.

use std::sync::Arc;

use crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
use crate::analyzer::semantic::workspace_oracle::dispatch::{
    ProcedureRangeLookupStatus, exact_call_range, exact_source_for_procedure,
    procedures_for_definition_with_limits,
};
use crate::analyzer::semantic::{
    CallSiteHandle, DispatchCandidate, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticWork,
};
use crate::analyzer::usages::call_binding::{
    CallBindingTarget, CallReceiverBinding, call_binding_report,
};
use crate::analyzer::usages::callable_signature::callable_signature_reports;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_call_target_batch_with_preparation,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
pub use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::conversions::*;
pub(super) struct ConversionRows {
    rows: Option<Vec<ArgumentConversion>>,
    lookup_incomplete: bool,
    examined: usize,
}

pub(super) struct ConversionCandidate {
    declaration: Option<(
        crate::analyzer::CodeUnit,
        crate::analyzer::usages::callable_signature::CallableSignatureReport,
    )>,
    examined: usize,
}

impl WorkspaceSemanticOracle<'_> {
    /// Whether argument conversion at this call can execute user code.
    /// Charge the same discovery reads on hits; only language proofs are memoized.
    pub fn call_conversion_may_run_user_code(
        &self,
        call: &CallSiteHandle,
        dispatch: &SemanticOutcome<crate::analyzer::semantic::DispatchResult>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<bool>, SemanticProviderError> {
        let before = request.budget.used();
        match dispatch {
            SemanticOutcome::Cancelled { .. } => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: request.budget.used().saturating_sub(before),
                });
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded: *exceeded,
                    work: request.budget.used().saturating_sub(before),
                });
            }
            _ => {}
        }
        let analyzer = self.workspace.analyzer();
        let language = call.procedure().artifact().key().language().language();
        let has_receiver = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .is_some_and(|site| site.receiver.is_some());
        if language == brokk_bifrost_core::analyzer::model::Language::Rust {
            let positive_deref = dispatch.available_value().is_some_and(|answer| {
                answer.candidates().iter().any(|candidate| {
                    candidate.receiver_owner_relation()
                        == crate::analyzer::semantic::ReceiverOwnerRelation::Promoted
                }) || answer.boundaries().iter().any(|boundary| {
                    boundary
                        .exact_external_target()
                        .is_some_and(|target| target.unadmitted_receiver_deref)
                        || boundary
                            .unmaterialized_external_target()
                            .is_some_and(|target| target.unadmitted_receiver_deref)
                })
            });
            // An actual unadmitted step wins over every direct-receiver proof.
            if positive_deref {
                return Ok(SemanticOutcome::Complete {
                    value: true,
                    work: request.budget.used().saturating_sub(before),
                });
            }
            let receiver_unknown = (has_receiver
                && !matches!(dispatch, SemanticOutcome::Complete { .. }))
                || dispatch.available_value().is_none_or(|answer| {
                    (has_receiver
                        && answer.coverage()
                            != crate::analyzer::semantic::CandidateCoverage::Exhaustive)
                        || answer.candidates().iter().any(|candidate| {
                            candidate.receiver_owner_relation()
                                == crate::analyzer::semantic::ReceiverOwnerRelation::Unknown
                        })
                        || answer.boundaries().iter().any(|boundary| {
                            has_receiver
                                && boundary.exact_external_target().is_none()
                                && boundary.unmaterialized_external_target().is_none()
                        })
                        || (has_receiver
                            && answer.candidates().is_empty()
                            && answer.boundaries().is_empty())
                });
            if receiver_unknown {
                // The intrinsic's canonical String owner comes from resolved std
                // identity, not source spelling. #10976: Str still accepts a
                // shadowed primitive spelling, so it cannot supply this proof.
                // Str eligibility will be restored by #10976. Its inferred
                // str.to_owned() result can also masquerade as String, so an
                // independently proven, explicitly typed receiver is required.
                // The reviewed zero-argument String operation proves only a
                // direct receiver with no implicit Deref. Ordinary argument
                // effects below remain checked; no transfer is invented here.
                let direct_intrinsic = if has_receiver
                    && call
                        .procedure()
                        .semantics()
                        .call_site(call.id())
                        .is_some_and(|site| site.arguments.is_empty())
                {
                    match crate::analyzer::languages::language_support(language) {
                        Some(support) => support.intrinsic_call_has_direct_receiver(self.workspace, call)? && support.intrinsic_call(self.workspace, call)?.is_some_and(|intrinsic| {
                            intrinsic.transfer == crate::analyzer::semantic::IntrinsicTransfer::ReceiverToResult && intrinsic.operation.rsplit_once('.').is_some_and(|(owner, _)| owner == "std.string.String")
                        }),
                        None => false,
                    }
                } else {
                    false
                };
                if !direct_intrinsic {
                    return Ok(SemanticOutcome::Complete {
                        value: true,
                        work: request.budget.used().saturating_sub(before),
                    });
                }
            }
        }
        if !crate::analyzer::usages::call_conversion::unread_conversion_may_run_user_code(
            analyzer, language,
        ) {
            return Ok(SemanticOutcome::Complete {
                value: false,
                work: SemanticWork::default(),
            });
        }
        let file = crate::analyzer::ProjectFile::new(
            analyzer.project().root().to_path_buf(),
            call.procedure().artifact().key().path().as_path(),
        );
        let range = exact_call_range(call)?;
        match self.conversion_sources.actuals_may_run_user_code(
            analyzer,
            &file,
            &range,
            request.budget,
        ) {
            Ok(false) => {
                return Ok(SemanticOutcome::Complete {
                    value: false,
                    work: request.budget.used().saturating_sub(before),
                });
            }
            Ok(true) => {}
            Err(exceeded) => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: request.budget.used().saturating_sub(before),
                });
            }
        }
        let mut candidates = Vec::new();
        if let Some(dispatch) = dispatch.available_value() {
            for candidate in dispatch.candidates() {
                let rows = self.call_conversions(call, candidate, request)?;
                match rows {
                    SemanticOutcome::Cancelled { .. } => {
                        return Ok(SemanticOutcome::Cancelled {
                            partial: None,
                            work: request.budget.used().saturating_sub(before),
                        });
                    }
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        return Ok(SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work: request.budget.used().saturating_sub(before),
                        });
                    }
                    rows => candidates.push((
                        candidate,
                        rows.available_value().cloned().unwrap_or_default(),
                    )),
                }
            }
        }
        // The answer depends on the dispatch the caller supplies, so the memo
        // holds one effect per (call, candidate): a later, more complete
        // dispatch for the same call reads its new candidates' effects.
        let answer = candidates.is_empty()
            || candidates.iter().any(|(candidate, rows)| {
                *crate::analyzer::usages::common::query_memo_value(
                    &self.conversion_effects,
                    analyzer,
                    &(call.clone(), (*candidate).clone()),
                    || {
                        rows.iter().any(|row| row.may_run_user_code)
                            || self
                                .conversion_sources
                                .shape(analyzer, &file, &range)
                                .as_ref()
                                .is_none_or(|shape| {
                                    shape.arguments.iter().any(|actual| {
                                        !rows.iter().any(|row| row.range == actual.range)
                                            && self.conversion_sources.actual_may_run_user_code(
                                                analyzer,
                                                &file,
                                                &actual.range,
                                            )
                                    })
                                })
                    },
                )
            });
        Ok(SemanticOutcome::Complete {
            value: answer,
            work: request.budget.used().saturating_sub(before),
        })
    }

    /// The argument conversions of one call against one dispatch candidate,
    /// proved by the call language's `CallArgumentConversionProver`. A
    /// conversion left unknown that the prover says may run user code carries
    /// an incomplete reason, which keeps the binding open.
    pub(crate) fn call_conversions(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Vec<ArgumentConversion>>, SemanticProviderError> {
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            self.workspace.analyzer(),
            self.active_semantic_model_snapshot(),
        );
        let mut work = SemanticWork::default();
        macro_rules! charge {
            ($cost:expr) => {{
                let cost = $cost;
                work = work.conservative_add(cost);
                request.budget.charge_work(cost);
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
            let maximum_source_bytes = request.budget.limits().source_bytes;
            let Some(source) =
                exact_source_for_procedure(self.workspace, procedure, maximum_source_bytes)?
            else {
                let census = SemanticWork {
                    source_bytes: maximum_source_bytes.saturating_add(1),
                    ..SemanticWork::default()
                };
                let exceeded = request
                    .budget
                    .check_admission(census)
                    .expect_err("source preparation exceeds the resident byte grant");
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            };
            if crate::analyzer::common::language_for_file(&source.0)
                == crate::analyzer::Language::Rust
                && let Some(parsed) = self
                    .conversion_sources
                    .source(self.workspace.analyzer(), &source.0)
            {
                match parsed.charge_parse(request.budget) {
                    Ok(cost) => work = work.conservative_add(cost),
                    Err(exceeded) => {
                        return Ok(SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work,
                        });
                    }
                }
            } else {
                charge!(SemanticWork {
                    source_bytes: source.1.len(),
                    ..SemanticWork::default()
                });
            }
            sources.push(source);
        }
        let (file, _source) = &sources[0];
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
        let census = SemanticWork {
            nested_entries: facts.nodes().len(),
            ..SemanticWork::default()
        };
        if crate::analyzer::common::language_for_file(file) == crate::analyzer::Language::Rust
            && let Some(parsed) = self.conversion_sources.source(analyzer, file)
        {
            match parsed.charge_shape(facts.nodes().len(), request.budget) {
                Ok(cost) => work = work.conservative_add(cost),
                Err(exceeded) => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
            }
        } else {
            charge!(census);
        }
        let conversion_context = self
            .conversion_sources
            .indexed_context(self.lexical_indexes.clone());
        let cache_key = (call.clone(), candidate.clone());
        // A cancelled lookup is not an answer: neither memo retains it, so a
        // later request with a live token recomputes it.
        struct LookupCancelled;
        let cached = match crate::analyzer::usages::common::query_memo_result(
            &self.conversion_rows,
            analyzer,
            &cache_key,
            || {
                let mut cancelled = false;
                let mut examined = 0;
                let mut lookup_incomplete_reason = candidate
                    .unique_incomplete_native_source_reason()
                    .map(str::to_owned);
                let lookup_status_incomplete = lookup_incomplete_reason.is_some();
                let result = (|| {
                    let shape = self.conversion_sources.shape(analyzer, file, &range)?;
                    if !candidate
                        .proof()
                        .establishes_complete_evidence(candidate.completeness())
                        && !lookup_status_incomplete
                    {
                        return None;
                    }
                    // Java conversion evidence requires a uniquely selected overload.
                    // A complete candidate declaration alone does not establish that
                    // this call selected its signature.
                    if crate::analyzer::common::language_for_file(file)
                        == crate::analyzer::Language::Java
                    {
                        let selected = match crate::analyzer::usages::common::query_memo_result(
                            &self.conversion_java_targets,
                            analyzer,
                            call,
                            || {
                                let selected = (|| {
                                    let prepared =
                                        self.conversion_sources.source(analyzer, file)?;
                                    let callee = shape.outcome.callee_range?;
                                    let lookup = resolve_call_target_batch_with_preparation(
                                        analyzer,
                                        _scope.token(),
                                        vec![DefinitionLookupRequest {
                                            file: file.clone(),
                                            line: None,
                                            column: None,
                                            start_byte: Some(callee.start_byte),
                                            end_byte: Some(callee.end_byte),
                                        }],
                                        file.clone(),
                                        Arc::clone(prepared.preparation.source()),
                                        None,
                                        Some(&prepared.preparation),
                                        Some(request.cancellation),
                                    )
                                    .into_iter()
                                    .next()?;
                                    if lookup.truncated
                                        || lookup.structure_unavailable
                                        || lookup.unproven_link_unit
                                    {
                                        return None;
                                    }
                                    if lookup.outcome.status == DefinitionLookupStatus::Resolved {
                                        let [target] = lookup.outcome.definitions.as_slice() else {
                                            return None;
                                        };
                                        Some((target.clone(), None))
                                    } else {
                                        // The lookup kept one source candidate but did
                                        // not complete the binding: the selection is
                                        // incomplete, and so are its conversions.
                                        let (target, reason) =
                                            lookup.unique_incomplete_native_source_candidate()?;
                                        Some((target.clone(), Some(Box::from(reason))))
                                    }
                                })();
                                if request.cancellation.is_cancelled() {
                                    return Err(LookupCancelled);
                                }
                                Ok(selected)
                            },
                        ) {
                            Ok(selected) => selected,
                            Err(LookupCancelled) => {
                                cancelled = true;
                                return None;
                            }
                        };
                        let (target, selection_incomplete) = selected.as_ref()?;
                        let span = candidate.target().semantics().locator().anchor().span();
                        if target.source() != &sources[1].0
                            || !analyzer.ranges_of(target).iter().any(|range| {
                                range.start_byte == span.start_byte() as usize
                                    && range.end_byte == span.end_byte() as usize
                            })
                        {
                            return None;
                        }
                        if let Some(reason) = selection_incomplete {
                            lookup_incomplete_reason.get_or_insert_with(|| reason.to_string());
                        }
                    }
                    let prepared = match crate::analyzer::usages::common::query_memo_result(
                        &self.conversion_candidates,
                        analyzer,
                        candidate.target(),
                        || {
                            let mut examined = 0;
                            let mut lookup_cancelled = false;
                            let declaration = (|| {
                                let span = candidate.target().semantics().locator().anchor().span();
                                let declarations = analyzer.get_declarations(&sources[1].0);
                                let mut matches = declarations.into_iter().filter(|unit| {
                                    analyzer.ranges_of(unit).iter().any(|range| {
                                        range.start_byte == span.start_byte() as usize
                                            && range.end_byte == span.end_byte() as usize
                                    })
                                });
                                let target = matches.next()?;
                                if matches.next().is_some() {
                                    return None;
                                }
                                let target = &target;
                                let procedures = procedures_for_definition_with_limits(
                                    analyzer,
                                    target,
                                    candidate.target().artifact(),
                                    usize::MAX,
                                    request.cancellation,
                                );
                                examined = procedures.examined;
                                if procedures.status == ProcedureRangeLookupStatus::Cancelled {
                                    lookup_cancelled = true;
                                    return None;
                                }
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
                                let signatures =
                                    callable_signature_reports(&site_id, target, &metadata);
                                let [signature] = signatures.as_slice() else {
                                    return None;
                                };
                                Some((target.clone(), signature.clone()))
                            })();
                            if lookup_cancelled {
                                return Err(LookupCancelled);
                            }
                            Ok(ConversionCandidate {
                                declaration,
                                examined,
                            })
                        },
                    ) {
                        Ok(prepared) => prepared,
                        Err(LookupCancelled) => {
                            cancelled = true;
                            return None;
                        }
                    };
                    examined = prepared.examined;
                    let (target, signature) = prepared.declaration.as_ref()?;
                    let mut bindings = self
                        .conversion_bindings
                        .lock()
                        .expect("conversion bindings poisoned");
                    let layout = bindings.formal_layout(analyzer, target, shape.arguments.len())?;
                    // Receivers do not consume an ordinary parameter slot. The
                    // semantic binder retains their separate receiver evidence.
                    let mut report = call_binding_report(
                        analyzer,
                        file,
                        &shape,
                        CallBindingTarget::Resolved {
                            unit: target.clone(),
                            layout,
                            receiver: CallReceiverBinding::Absent,
                        },
                        Some(request.cancellation),
                    );
                    let conversion_cache = &self.conversion_sources;
                    conversion_cache.populate_with_context(
                        &conversion_context,
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
                            let may_run_user_code = fact.result.is_err()
                                && conversion_cache
                                    .unknown_conversion_may_run_user_code(analyzer, &report, row);
                            let incomplete_reason = lookup_incomplete_reason.clone();
                            Some(ArgumentConversion {
                                range: row.range,
                                formal,
                                transfer: fact
                                    .result
                                    .as_ref()
                                    .map(|_| fact.transfer())
                                    .map_err(|reason| *reason),
                                may_run_user_code,
                                incomplete_reason,
                            })
                        })
                        .collect();
                    Some(conversions)
                })();
                if cancelled {
                    return Err(LookupCancelled);
                }
                Ok(ConversionRows {
                    rows: result,
                    lookup_incomplete: lookup_incomplete_reason.is_some(),
                    examined,
                })
            },
        ) {
            Ok(cached) => cached,
            Err(LookupCancelled) => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
        };
        charge!(SemanticWork {
            nested_entries: cached.examined,
            ..SemanticWork::default()
        });
        let Some(value) = cached.rows.clone() else {
            return Ok(SemanticOutcome::Unknown {
                partial: None,
                work,
            });
        };
        if cached.lookup_incomplete {
            Ok(SemanticOutcome::Unknown {
                partial: Some(value),
                work,
            })
        } else {
            Ok(SemanticOutcome::Complete { value, work })
        }
    }
}
