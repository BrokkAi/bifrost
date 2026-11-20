//! Rust outgoing calls from one bounded selected native forward operation.

use brokk_bifrost_analysis::analyzer::usages::call_relations::{
    CallRelationCanonicalTarget, CallRelationCompletion, CallRelationReceiverDisposition,
    call_relation_completion_semantics, call_relation_diagnostic_semantics,
};

use crate::analyzer::rust::RustAnalyzer;
use brokk_bifrost_analysis::analyzer::usages::call_relations::{
    CallRelationDiagnosticPayload, CallRelationFailure, LocatedCallRelationDiagnostic,
};

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustDefinitionSemanticOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustFileContextOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable;

use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

use brokk_bifrost_core::analyzer::usages::model::UsageProof;

use brokk_bifrost_analysis::analyzer::usages::call_relations::{
    CallArgument, CallRelationBudgetRefusal,
};

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::call_relations::{
    CallRelationDiagnosticCode, CallRelationScanLimit,
};

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationResult;

use crate::analyzer::usages::call_relations::CallRelationWork;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite;

use brokk_bifrost_analysis::analyzer::usages::call_relations::is_call_relation_unit;

use brokk_bifrost_analysis::analyzer::usages::call_shape::call_shape_for_call;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_core::path_utils::rel_path_string;

fn diagnostic(
    kind: &str,
    message: impl Into<LocatedCallRelationDiagnostic>,
    caller: &CodeUnit,
) -> CallRelationDiagnostic {
    CallRelationDiagnostic::analysis_failed(message, caller.fq_name().to_string(), kind.to_owned())
}

fn failed(
    kind: &str,
    message: impl Into<LocatedCallRelationDiagnostic>,
    caller: &CodeUnit,
) -> CallRelationResult {
    CallRelationResult {
        diagnostics: vec![diagnostic(kind, message, caller)],
        ..CallRelationResult::default()
    }
}

/// Resolve source-backed call shapes in one selected forward session. Native
/// source inventory, exact owner identity and per-call aggregate completion
/// are independent checks; none is inferred from an empty candidate list.
pub(crate) fn outgoing(
    rust: &RustAnalyzer,
    caller: &CodeUnit,
    limits: CallRelationLimits,
    budget: ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    outgoing_inner(rust, caller, limits, budget, cancellation).with_diagnostic_limits(limits)
}

fn outgoing_inner(
    rust: &RustAnalyzer,
    caller: &CodeUnit,
    limits: CallRelationLimits,
    budget: ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    if cancellation.is_cancelled() {
        return CallRelationResult {
            cancelled: true,
            ..CallRelationResult::default()
        };
    }
    if !is_call_relation_unit(caller) {
        return failed(
            "native_caller_not_callable",
            CallRelationDiagnosticPayload::Failure {
                reason: CallRelationFailure::Upstream {
                    kind: "native_caller_not_callable".into(),
                },
            },
            caller,
        );
    }
    if let Some(refusal) = CallRelationBudgetRefusal::preflight(limits) {
        let mut result = failed(
            "native_call_budget",
            CallRelationDiagnosticPayload::Failure {
                reason: CallRelationFailure::Upstream {
                    kind: "native_call_budget".into(),
                },
            },
            caller,
        );
        result.truncated = true;
        refusal.record(&mut result.budget_refusals);
        result.diagnostics[0].code = if limits.max_files == 0 {
            CallRelationDiagnosticCode::ScanGrantRefused(CallRelationScanLimit::Files)
        } else if limits.max_source_bytes == 0 {
            CallRelationDiagnosticCode::ScanGrantRefused(CallRelationScanLimit::SourceBytes)
        } else {
            CallRelationDiagnosticCode::BudgetExhausted
        };
        result.diagnostics[0].reason_kind = None;
        return result;
    }
    let Some(source) = rust.indexed_source(caller.source()) else {
        return failed(
            "native_source_unavailable",
            CallRelationDiagnosticPayload::Failure {
                reason: CallRelationFailure::Upstream {
                    kind: "native_source_unavailable".into(),
                },
            },
            caller,
        );
    };
    if source.len() > limits.max_source_bytes {
        let mut result = failed(
            "native_call_budget",
            CallRelationDiagnosticPayload::Failure {
                reason: CallRelationFailure::Upstream {
                    kind: "native_call_budget".into(),
                },
            },
            caller,
        );
        result.truncated = true;
        CallRelationBudgetRefusal::SourceBytes {
            consumed: 0,
            attempted: source.len(),
            limit: limits.max_source_bytes,
        }
        .record(&mut result.budget_refusals);
        result.diagnostics[0].code =
            CallRelationDiagnosticCode::ScanGrantRefused(CallRelationScanLimit::SourceBytes);
        result.diagnostics[0].reason_kind = None;
        return result;
    }
    let Some(caller_range) = rust
        .ranges_of(caller)
        .into_iter()
        .min_by_key(|range| range.start_byte)
    else {
        return failed(
            "native_caller_range_unavailable",
            CallRelationDiagnosticPayload::Failure {
                reason: CallRelationFailure::Upstream {
                    kind: "native_caller_range_unavailable".into(),
                },
            },
            caller,
        );
    };
    let mut work = CallRelationWork {
        scanned_files: 1,
        scanned_source_bytes: source.len(),
        examined_candidates: 0,
    };
    let session = ResolutionSession::bounded(budget, Some(cancellation));
    let selected = (|| -> Result<SelectedResolutionOperationOutcome<CallRelationResult>> {
        let snapshots = rust.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let (masks, content_mounts) = match rust
            .inner
            .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
        {
            SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            } => (masks, content_mounts),
            SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
            SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionOverlayInputsOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
                ));
            }
        };
        let input = rust
            .selected_resolution_operation_input(snapshots.as_ref(), &languages, &masks)
            .with_content_mounts(content_mounts);
        let operation = match rust
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(input, cancellation)?
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
            SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
                ));
            }
        };
        let (caller_context, caller_crate_keys) =
            match operation.rust_context_for_file(caller.source().rel_path(), cancellation)? {
                SelectedRustFileContextOutcome::Ready {
                    context,
                    crate_keys,
                } => (*context, crate_keys),
                SelectedRustFileContextOutcome::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
                    ));
                }
            };
        let caller_semantic = match operation.locate_rust_definition(caller, cancellation)? {
            SelectedRustDefinitionSemanticOutcome::Found(semantic) => semantic,
            SelectedRustDefinitionSemanticOutcome::Missing => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingDefinitionUnit {
                        reason: brokk_bifrost_analysis::analyzer::store::resolution_selection::MissingDefinitionReason::UncertifiedDefinition,
                        storage_language: "rust".to_owned(),
                        persisted_relative_path: rel_path_string(caller.source()),
                    },
                ));
            }
            SelectedRustDefinitionSemanticOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
                ));
            }
        };
        let caller_path = rel_path_string(caller.source());
        let fragment = operation
            .mount_table()
            .mount_for_path("rust", &caller_path)?
            .expect("a located Rust caller has an admitted source mount")
            .fragment();
        operation.with_rust_forward_queries_in_session(
            caller_context,
            &caller_crate_keys,
            &[caller.source().rel_path()],
            cancellation,
            &mut SelectedResolutionContextMetrics,
            &session,
            |queries| {
                let inventory = queries.reference_inventory_completion(fragment)?;
                let mut result = CallRelationResult::default();
                if inventory != ResolutionCompletion::Complete {
                    let semantics = call_relation_completion_semantics(&inventory);
                    let Some(projected) = queries.diagnostic_definitions(&semantics)? else {
                        return Ok(CallRelationResult {
                            cancelled: true,
                            ..CallRelationResult::default()
                        });
                    };
                    let canonical = semantics
                        .into_iter()
                        .zip(projected)
                        .map(|(id, target)| {
                            (id, CallRelationCanonicalTarget::from_projection(&target))
                        })
                        .collect::<brokk_bifrost_core::hash::HashMap<_, _>>();
                    result.diagnostics.push(diagnostic(
                        "native_reference_inventory_incomplete",
                        CallRelationDiagnosticPayload::RustInventory {
                            completion: CallRelationCompletion::from_resolution(&inventory, |id| {
                                canonical
                                    .get(&id)
                                    .expect("every diagnostic semantic has a projection slot")
                                    .clone()
                            }),
                        },
                        caller,
                    ));
                }
                let Some(facts) = rust
                    .structural_fact_providers()
                    .into_iter()
                    .find_map(|provider| provider.structural_facts(caller.source()))
                else {
                    return Ok(failed(
                        "native_structural_facts_unavailable",
                        CallRelationDiagnosticPayload::Failure {
                            reason: CallRelationFailure::Upstream {
                                kind: "native_structural_facts_unavailable".into(),
                            },
                        },
                        caller,
                    ));
                };
                if facts.source() != source.as_str()
                    || !rust
                        .inner
                        .source_matches_selected_native_content(caller.source(), &source)
                {
                    return Ok(failed(
                        "native_source_mismatch",
                        CallRelationDiagnosticPayload::Failure {
                            reason: CallRelationFailure::Upstream {
                                kind: "native_source_mismatch".into(),
                            },
                        },
                        caller,
                    ));
                }
                for (node_id, node) in facts.nodes().iter().enumerate() {
                    if !session.scope_step() || cancellation.is_cancelled() {
                        break;
                    }
                    if !node.kind.satisfies(NormalizedKind::Call)
                        || node.range.start_byte < caller_range.start_byte
                        || node.range.end_byte > caller_range.end_byte
                    {
                        continue;
                    }
                    let shape = call_shape_for_call(
                        &facts,
                        caller.source(),
                        u32::try_from(node_id).expect("source node ID fits u32"),
                        None,
                    )
                    .expect("a structured Call node has a call shape");
                    if !shape.outcome.coverage.is_exact() {
                        result.diagnostics.push(diagnostic(
                            "native_call_shape_incomplete",
                            CallRelationDiagnosticPayload::RustShape {
                                coverage: shape.outcome.coverage,
                            }
                            .at(caller.source(), Some(shape.outcome.range)),
                            caller,
                        ));
                        continue;
                    }
                    let Some(callee_range) = shape.outcome.callee_range else {
                        result.diagnostics.push(diagnostic(
                            "native_call_reference_unavailable",
                            CallRelationDiagnosticPayload::RustStructuredReferenceUnavailable
                                .at(caller.source(), Some(shape.outcome.range)),
                            caller,
                        ));
                        continue;
                    };
                    let locator = SelectedSemanticLocator::for_reference_range(
                        "rust",
                        caller_path.clone(),
                        callee_range.start_byte,
                        callee_range.end_byte,
                    );
                    let mut metrics = ResolutionBatchMetrics::default();
                    let answer = match queries.resolve_reference(&locator, &mut metrics)? {
                        SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Found(answer),
                        ) => answer,
                        SelectedResolutionOperationOutcome::Native(
                            SelectedResolutionLocated::Missing(_),
                        ) => {
                            result.diagnostics.push(diagnostic(
                                "native_call_reference_unavailable",
                                CallRelationDiagnosticPayload::RustReferenceUnavailable
                                    .at(caller.source(), Some(callee_range)),
                                caller,
                            ));
                            continue;
                        }
                        SelectedResolutionOperationOutcome::Unavailable(_)
                        | SelectedResolutionOperationOutcome::Stale(_)
                        | SelectedResolutionOperationOutcome::Cancelled(_) => break,
                    };
                    // A stop during this resolution may have cut its answer
                    // short; only sites finished before the stop are kept.
                    if session.is_stopped() {
                        break;
                    }
                    match answer.resolution.reference_owner() {
                        Some(Some(owner)) if owner == caller_semantic => {}
                        Some(_) => continue,
                        None => {
                            result.diagnostics.push(diagnostic(
                                "native_call_owner_unavailable",
                                CallRelationDiagnosticPayload::RustCanonicalOwnerUnavailable
                                    .at(caller.source(), Some(callee_range)),
                                caller,
                            ));
                            continue;
                        }
                    }
                    let diagnostic_semantics = if answer.resolution.call_target_completion()
                        != ResolutionCompletion::Complete
                        || answer.resolution.binding().targets().len() > 1
                    {
                        call_relation_diagnostic_semantics(&answer.resolution)
                    } else {
                        Vec::new()
                    };
                    let Some(projected) = queries.diagnostic_definitions(&diagnostic_semantics)?
                    else {
                        break;
                    };
                    assert_eq!(diagnostic_semantics.len(), projected.len());
                    let canonical = diagnostic_semantics
                        .into_iter()
                        .zip(projected)
                        .map(|(id, target)| {
                            (id, CallRelationCanonicalTarget::from_projection(&target))
                        })
                        .collect::<brokk_bifrost_core::hash::HashMap<_, _>>();
                    let project = |id| {
                        canonical
                            .get(&id)
                            .expect("every diagnostic semantic has a projection slot")
                            .clone()
                    };
                    let external_leaf = matches!(answer.resolution.call_target_completion(),
                        ResolutionCompletion::Incomplete(reasons) if reasons.iter().all(|reason|
                            matches!(reason, ResolutionIncompleteReason::OpenBoundary {
                                status: BoundaryStatus::ExternalDeclaredUnindexed, ..
                            }))
                    ) && answer.definitions.is_empty();
                    if external_leaf {
                        result
                            .external_terminal_sites
                            .push((caller.source().clone(), shape.outcome.range));
                        result.diagnostics.push(CallRelationDiagnostic::new(
                            CallRelationDiagnosticCode::ExternalBoundary,
                            CallRelationDiagnosticPayload::RustExternalTerminal
                                .at(caller.source(), Some(callee_range)),
                            caller.fq_name().to_string(),
                        ));
                    } else if answer.resolution.call_target_completion()
                        != ResolutionCompletion::Complete
                    {
                        result.diagnostics.push(diagnostic(
                            "native_call_resolution_incomplete",
                            CallRelationDiagnosticPayload::RustIncomplete {
                                completion: CallRelationCompletion::from_resolution(
                                    &answer.resolution.call_target_completion(),
                                    project,
                                ),
                                receivers: CallRelationReceiverDisposition::from_resolution(
                                    answer.resolution.callable_receiver_dispositions(),
                                    project,
                                ),
                            }
                            .at(caller.source(), Some(callee_range)),
                            caller,
                        ));
                    }
                    let cardinality = answer.resolution.binding().targets().len();
                    work.examined_candidates = work
                        .examined_candidates
                        .checked_add(cardinality)
                        .expect("call candidate work fits usize");
                    let proof = if cardinality == 1
                        && answer.resolution.binding().completion()
                            == &ResolutionCompletion::Complete
                    {
                        UsageProof::Proven
                    } else {
                        UsageProof::Unproven
                    };
                    if cardinality > 1 {
                        result.diagnostics.push(
                            CallRelationDiagnostic::new(
                                CallRelationDiagnosticCode::TargetsAmbiguous,
                                CallRelationDiagnosticPayload::RustAmbiguous {
                                    targets: {
                                        let mut targets = answer
                                            .resolution
                                            .binding()
                                            .targets()
                                            .iter()
                                            .copied()
                                            .map(project)
                                            .collect::<Vec<_>>();
                                        targets.sort();
                                        targets
                                    },
                                }
                                .at(caller.source(), Some(callee_range)),
                                caller.fq_name().to_string(),
                            )
                            .with_count(cardinality),
                        );
                    }
                    if !external_leaf
                        && (!answer.lexical_definitions.is_empty() || answer.definitions.is_empty())
                    {
                        result.diagnostics.push(diagnostic(
                            "native_call_target_unavailable",
                            CallRelationDiagnosticPayload::RustTargetUnavailable
                                .at(caller.source(), Some(callee_range)),
                            caller,
                        ));
                    }
                    let mut definitions = answer.definitions;
                    definitions.sort();
                    if definitions.len() > limits.max_candidates {
                        result.truncated = true;
                        CallRelationBudgetRefusal::Candidates {
                            consumed: limits.max_candidates,
                            limit: limits.max_candidates,
                        }
                        .record(&mut result.budget_refusals);
                        let mut omitted = diagnostic(
                            "native_call_candidates_omitted",
                            CallRelationDiagnosticPayload::RustCandidateBound {
                                limit: limits.max_candidates,
                            }
                            .at(caller.source(), Some(callee_range)),
                            caller,
                        );
                        omitted.code = CallRelationDiagnosticCode::CandidateLimit;
                        omitted.reason_kind = None;
                        result.diagnostics.push(
                            omitted.with_count(
                                definitions.len().saturating_sub(limits.max_candidates),
                            ),
                        );
                    }
                    let site_start = result.sites.len();
                    for callee in definitions.into_iter().take(limits.max_candidates) {
                        if !session.scope_step() || cancellation.is_cancelled() {
                            break;
                        }
                        if !is_call_relation_unit(&callee) {
                            result.diagnostics.push(diagnostic(
                                "native_call_target_not_callable",
                                CallRelationDiagnosticPayload::RustTargetNotCallable {
                                    target: (&callee).into(),
                                },
                                caller,
                            ));
                            continue;
                        }
                        let kind = if callee.is_class() {
                            CallSyntaxKind::Constructor
                        } else if shape.outcome.receiver_range.is_some() {
                            CallSyntaxKind::Method
                        } else {
                            CallSyntaxKind::Function
                        };
                        let arguments = shape
                            .arguments
                            .iter()
                            .map(|argument| CallArgument {
                                range: argument.range,
                                name: argument.name.clone(),
                                position: argument
                                    .name
                                    .is_none()
                                    .then_some(argument.argument_index),
                                written_position: argument.position,
                                formal_index: None,
                                formal_name: None,
                                variadic: false,
                                spread: argument.spread,
                            })
                            .collect();
                        result.sites.push(CallSite {
                            file: caller.source().clone(),
                            range: shape.outcome.range,
                            callee_range,
                            caller: caller.clone(),
                            callee,
                            kind,
                            proof,
                            receiver: shape.outcome.receiver_range,
                            arguments,
                        });
                    }
                    // A stop inside this call's candidates leaves it partly
                    // recorded; only finished sites are kept.
                    if session.is_stopped() {
                        result.sites.truncate(site_start);
                    }
                }
                result.sites.sort_by(|a, b| {
                    (a.range.start_byte, &a.callee).cmp(&(b.range.start_byte, &b.callee))
                });
                result.sites.dedup();
                result.diagnostics.sort();
                result.diagnostics.dedup();
                Ok(result)
            },
        )
    })();
    let (status, selected) = session.finish_keeping(selected);
    let mut result = match status {
        BoundedResolution::Cancelled { .. } => CallRelationResult {
            cancelled: true,
            ..CallRelationResult::default()
        },
        BoundedResolution::Exceeded { limit, work } => {
            let mut failure = failed(
                "native_call_budget",
                CallRelationDiagnosticPayload::RustBudget { limit, work },
                caller,
            );
            failure.diagnostics[0].code = CallRelationDiagnosticCode::BudgetExhausted;
            failure.diagnostics[0].reason_kind = None;
            CallRelationResult::budget_stopped(selected, failure)
        }
        BoundedResolution::Unavailable { .. } => {
            let mut result = failed(
                "native_input_unavailable",
                CallRelationDiagnosticPayload::Failure {
                    reason: CallRelationFailure::InputUnavailable,
                },
                caller,
            );
            result.truncated = true;
            result
        }
        BoundedResolution::Complete { .. } => match selected {
            Err(_error) => failed(
                "native_store_error",
                CallRelationDiagnosticPayload::Failure {
                    reason: CallRelationFailure::StoreError,
                },
                caller,
            ),
            Ok(SelectedResolutionOperationOutcome::Native(value)) => value,
            Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => failed(
                "native_unavailable",
                CallRelationDiagnosticPayload::NativeUnavailable {
                    reason: (&reason).into(),
                },
                caller,
            ),
            Ok(SelectedResolutionOperationOutcome::Stale(reason)) => failed(
                "native_stale",
                CallRelationDiagnosticPayload::NativeStale {
                    reason: (&reason).into(),
                },
                caller,
            ),
            Ok(SelectedResolutionOperationOutcome::Cancelled(_)) => CallRelationResult {
                cancelled: true,
                ..CallRelationResult::default()
            },
        },
    };
    result.work = work;
    if cancellation.is_cancelled() {
        result.sites.clear();
        result.cancelled = true;
    }
    result
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::native_outgoing::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_test_macros::hardwon;

    fn fixture() -> (crate::inline_project::BuiltInlineTestProject, RustAnalyzer) {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"native_outgoing\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", concat!(
                "pub mod hidden;\n",
                "pub fn target(value: usize) {}\n",
                "pub async fn deferred() {}\n",
                "pub struct Service;\n",
                "impl Service { pub fn method(&self, value: usize) {} }\n",
                "pub fn caller(service: Service) { target(1); service.method(2); deferred(); }\n",
                "pub fn empty() {}\n",
            ))
            // The token tree must stay unenumerable: since the producer reads the
            // arguments of a definition-less macro as expressions, only a group it
            // cannot lower -- here a module mount, which belongs to declaration
            // replay -- still leaves the reference inventory incomplete.
            .file("src/hidden.rs", "pub fn opaque() { unknown_macro! { mod generated; } }\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        (fixture, rust)
    }

    fn limits() -> CallRelationLimits {
        CallRelationLimits {
            max_files: 1,
            max_source_bytes: 16_384,
            max_candidates: 16,
        }
    }

    #[test]
    #[hardwon("#11321: native outgoing zero allowances omitted their typed refusal")]
    fn native_outgoing_budget_telemetry_names_zero_allowances() {
        let (fixture, rust) = fixture();
        let caller = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .unwrap();
        for (grant, expected) in [
            (
                CallRelationLimits {
                    max_files: 0,
                    ..limits()
                },
                CallRelationBudgetRefusal::Files {
                    consumed: 0,
                    limit: 0,
                },
            ),
            (
                CallRelationLimits {
                    max_source_bytes: 0,
                    ..limits()
                },
                CallRelationBudgetRefusal::SourceBytes {
                    consumed: 0,
                    attempted: 0,
                    limit: 0,
                },
            ),
            (
                CallRelationLimits {
                    max_candidates: 0,
                    ..limits()
                },
                CallRelationBudgetRefusal::Candidates {
                    consumed: 0,
                    limit: 0,
                },
            ),
        ] {
            let result = outgoing(
                &rust,
                &caller,
                grant,
                ReceiverAnalysisBudget::default(),
                &CancellationToken::new(),
            );
            assert!(result.truncated && result.sites.is_empty(), "{result:?}");
            assert_eq!(result.budget_refusals, [expected]);
            assert_eq!(result.work.examined_candidates, 0);
        }
    }

    #[test]
    #[hardwon("#11321: native outgoing source-byte refusal consumed no work and omitted its lane")]
    fn native_outgoing_budget_telemetry_names_source_bytes() {
        let (fixture, rust) = fixture();
        let file = fixture.file("src/lib.rs");
        let caller = rust
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .unwrap();
        let source_len = rust.indexed_source(&file).unwrap().len();
        let result = outgoing(
            &rust,
            &caller,
            CallRelationLimits {
                max_source_bytes: 1,
                ..limits()
            },
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        );
        assert!(result.truncated && result.sites.is_empty(), "{result:?}");
        assert_eq!(result.work.scanned_source_bytes, 0);
        assert_eq!(
            result.budget_refusals,
            [CallRelationBudgetRefusal::SourceBytes {
                consumed: 0,
                attempted: source_len,
                limit: 1
            }]
        );
    }

    #[test]
    #[hardwon("#11321: native target-projection candidate cuts omitted their typed refusal")]
    fn native_outgoing_budget_telemetry_names_target_projection() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"native_projection_cut\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .file("src/lib.rs", "mod left { pub fn target() {} }\nmod right { pub fn target() {} }\nuse left::*;\nuse right::*;\npub fn caller() { target(); }\n")
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let caller = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .unwrap();
        for cap in [1, 2] {
            let result = outgoing(
                &rust,
                &caller,
                CallRelationLimits {
                    max_candidates: cap,
                    ..limits()
                },
                ReceiverAnalysisBudget::default(),
                &CancellationToken::new(),
            );
            if cap == 1 {
                assert!(result.truncated, "{result:?}");
                assert_eq!(
                    result.budget_refusals,
                    [CallRelationBudgetRefusal::Candidates {
                        consumed: 1,
                        limit: 1
                    }]
                );
                assert_eq!(result.sites.len(), 1, "{result:?}");
            } else {
                assert!(!result.truncated, "{result:?}");
                assert!(result.budget_refusals.is_empty(), "{result:?}");
                assert_eq!(result.sites.len(), 2, "{result:?}");
            }
        }
    }

    #[test]
    fn native_outgoing_preserves_exact_sites_despite_async_type_uncertainty() {
        let (fixture, rust) = fixture();
        let caller = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .expect("caller declaration");
        let result = outgoing(
            &rust,
            &caller,
            limits(),
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        );
        assert!(!result.cancelled && !result.truncated, "{result:?}");
        assert_eq!(result.sites.len(), 3, "{result:?}");
        assert_eq!(
            result
                .sites
                .iter()
                .map(|site| site.callee.identifier())
                .collect::<Vec<_>>(),
            ["target", "method", "deferred"]
        );
        assert!(
            result
                .sites
                .iter()
                .all(|site| site.caller == caller && site.proof == UsageProof::Proven),
            "{result:?}"
        );
        let source = rust
            .indexed_source(caller.source())
            .expect("indexed source");
        let method = &result.sites[1];
        assert_eq!(
            &source[method.range.start_byte..method.range.end_byte],
            "service.method(2)"
        );
        let receiver = method.receiver.expect("method receiver");
        assert_eq!(&source[receiver.start_byte..receiver.end_byte], "service");
        assert_eq!(method.arguments.len(), 1);
        assert_eq!(
            &source[method.arguments[0].range.start_byte..method.arguments[0].range.end_byte],
            "2"
        );
        assert!(result.diagnostics.is_empty(), "{result:?}");
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.reason_kind.as_deref()
                    == Some("native_reference_inventory_incomplete")),
            "unrelated source gaps escaped their fragment: {result:?}"
        );
    }

    #[test]
    #[hardwon(
        "#6238: an incomplete return-type projection made a unique complete call binding report AnalysisFailed"
    )]
    fn native_outgoing_separates_return_projection_from_open_dispatch() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"completion\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                concat!(
                    "pub fn f(input: &[u8]) { helper() }\n",
                    "fn helper() {}\n",
                    "pub trait Action { fn run(&self); }\n",
                    "impl<T: Clone> Action for T { fn run(&self) {} }\n",
                    "pub fn dynamic(action: &dyn Action) { action.run(); }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let caller = declarations
            .iter()
            .find(|unit| unit.identifier() == "f")
            .unwrap();
        let result = outgoing(
            &rust,
            caller,
            limits(),
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        );
        assert!(!result.cancelled && !result.truncated, "{result:?}");
        assert!(result.diagnostics.is_empty(), "{result:?}");
        assert_eq!(result.sites.len(), 1, "{result:?}");
        assert_eq!(result.sites[0].callee.identifier(), "helper");
        assert_eq!(result.sites[0].proof, UsageProof::Proven);

        let caller = declarations
            .iter()
            .find(|unit| unit.identifier() == "dynamic")
            .unwrap();
        let result = outgoing(
            &rust,
            caller,
            limits(),
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        );
        assert!(!result.cancelled && !result.truncated, "{result:?}");
        assert!(
            !result.sites.is_empty(),
            "open dispatch still retains its known target: {result:?}"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.reason_kind.as_deref()
                    == Some("native_call_resolution_incomplete")),
            "{result:?}"
        );
    }

    #[test]
    fn native_outgoing_empty_requires_complete_source_inventory() {
        let (fixture, rust) = fixture();
        let empty = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "empty")
            .expect("empty declaration");
        let result = outgoing(
            &rust,
            &empty,
            limits(),
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        );
        assert!(
            result.sites.is_empty()
                && result.diagnostics.is_empty()
                && !result.cancelled
                && !result.truncated,
            "{result:?}"
        );
        let opaque = rust
            .declarations(&fixture.file("src/hidden.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "opaque")
            .expect("opaque declaration");
        let result = outgoing(
            &rust,
            &opaque,
            limits(),
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        );
        assert!(
            result.sites.is_empty() && !result.truncated && !result.cancelled,
            "{result:?}"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.reason_kind.as_deref()
                    == Some("native_reference_inventory_incomplete")),
            "{result:?}"
        );
    }

    #[test]
    fn native_outgoing_with_no_finished_site_or_after_cancellation_publishes_nothing() {
        let (fixture, rust) = fixture();
        let caller = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .expect("caller declaration");
        let result = outgoing(
            &rust,
            &caller,
            limits(),
            ReceiverAnalysisBudget {
                max_resolution_rounds: 0,
                ..ReceiverAnalysisBudget::default()
            },
            &CancellationToken::new(),
        );
        assert!(result.sites.is_empty() && result.truncated, "{result:?}");
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CallRelationDiagnosticCode::BudgetExhausted),
            "{result:?}"
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = outgoing(
            &rust,
            &caller,
            limits(),
            ReceiverAnalysisBudget::default(),
            &cancellation,
        );
        assert!(
            result.sites.is_empty() && result.cancelled && !result.truncated,
            "{result:?}"
        );
    }

    #[test]
    fn a_budget_stop_keeps_the_sites_finished_before_it_and_types_the_stop() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
            ReceiverAnalysisWork, ReceiverBudgetLimit,
        };
        let (fixture, rust) = fixture();
        let caller = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .expect("caller declaration");
        let full = outgoing(
            &rust,
            &caller,
            limits(),
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        );
        assert!(!full.truncated && full.sites.len() > 1, "{full:?}");
        let mut failure = failed(
            "native_call_budget",
            CallRelationDiagnosticPayload::RustBudget {
                limit: ReceiverBudgetLimit::ResolutionRounds,
                work: ReceiverAnalysisWork::default(),
            },
            &caller,
        );
        failure.diagnostics[0].code = CallRelationDiagnosticCode::BudgetExhausted;
        let mut prefix = full.clone();
        prefix.sites.truncate(1);
        let kept = CallRelationResult::budget_stopped(
            Ok::<_, ()>(SelectedResolutionOperationOutcome::Native(prefix.clone())),
            failure.clone(),
        );
        assert_eq!(kept.sites, prefix.sites);
        assert!(kept.truncated);
        assert!(
            kept.diagnostics
                .iter()
                .any(|d| d.code == CallRelationDiagnosticCode::BudgetExhausted),
            "{kept:?}"
        );
        let nothing = CallRelationResult::budget_stopped(
            Err::<SelectedResolutionOperationOutcome<CallRelationResult>, ()>(()),
            failure,
        );
        assert!(nothing.sites.is_empty() && nothing.truncated);
    }
}
