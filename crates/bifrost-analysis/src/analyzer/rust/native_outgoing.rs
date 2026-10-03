//! Rust outgoing calls from one bounded selected native forward operation.

use super::RustAnalyzer;
use crate::CancellationToken;
use crate::analyzer::resolution::{
    ResolutionBatchMetrics, ResolutionCompletion, ResolutionIncompleteReason,
    SelectedSemanticLocator,
};
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionLocated, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
    SelectedRustDefinitionSemanticOutcome, SelectedRustFileContextOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionLanguage, SelectedResolutionUnavailable,
};
use crate::analyzer::structural::NormalizedKind;
use crate::analyzer::usages::UsageProof;
use crate::analyzer::usages::call_relations::{
    CallArgument, CallRelationDiagnostic, CallRelationDiagnosticCode, CallRelationLimits,
    CallRelationResult, CallRelationWork, CallSite, is_call_relation_unit,
};
use crate::analyzer::usages::call_shape::call_shape_for_call;
use crate::analyzer::usages::get_definition::CallSyntaxKind;
use crate::analyzer::{CodeUnit, CodeUnitIndex, IAnalyzer, Language};
use crate::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::structural::callable::CallShapeCoverage;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};

fn diagnostic(kind: &str, message: impl Into<String>, caller: &CodeUnit) -> CallRelationDiagnostic {
    CallRelationDiagnostic {
        code: CallRelationDiagnosticCode::AnalysisFailed,
        message: message.into(),
        context: caller.fq_name().to_string(),
        reason_kind: Some(kind.to_owned()),
    }
}

fn failed(kind: &str, message: impl Into<String>, caller: &CodeUnit) -> CallRelationResult {
    CallRelationResult {
        diagnostics: vec![diagnostic(kind, message, caller)],
        ..CallRelationResult::default()
    }
}

/// Resolve source-backed call shapes in one selected forward session. Native
/// source inventory, exact owner identity and per-call aggregate completion
/// are independent checks; none is inferred from an empty candidate list.
pub(super) fn outgoing(
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
            "requested caller is not callable",
            caller,
        );
    }
    if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
        let mut result = failed(
            "native_call_budget",
            "outgoing call admission budget is zero",
            caller,
        );
        result.truncated = true;
        result.diagnostics[0].code = CallRelationDiagnosticCode::BudgetExhausted;
        return result;
    }
    let Some(source) = rust.indexed_source(caller.source()) else {
        return failed(
            "native_source_unavailable",
            "indexed caller source is unavailable",
            caller,
        );
    };
    if source.len() > limits.max_source_bytes {
        let mut result = failed(
            "native_call_budget",
            "caller source exceeds the source-byte budget",
            caller,
        );
        result.truncated = true;
        result.diagnostics[0].code = CallRelationDiagnosticCode::BudgetExhausted;
        return result;
    }
    let Some(caller_range) = rust
        .ranges_of(caller)
        .into_iter()
        .min_by_key(|range| range.start_byte)
    else {
        return failed(
            "native_caller_range_unavailable",
            "caller has no structured source range",
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
        let input = SelectedResolutionOperationInput::new(
            rust.inner.project(),
            rust.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
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
            caller_context, &caller_crate_keys, &[caller.source().rel_path()], cancellation, &mut SelectedResolutionContextMetrics, &session,
            |queries| {
                let inventory = queries.reference_inventory_completion(fragment)?;
                let mut result = CallRelationResult::default();
                if inventory != ResolutionCompletion::Complete {
                    result.diagnostics.push(diagnostic(
                        "native_reference_inventory_incomplete", format!("caller source reference inventory: {inventory:?}"), caller,
                    ));
                }
                let Some(facts) = rust.structural_fact_providers().into_iter()
                    .find_map(|provider| provider.structural_facts(caller.source())) else {
                    return Ok(failed("native_structural_facts_unavailable", "caller structural facts are unavailable", caller));
                };
                if facts.source() != source.as_str()
                    || !rust.inner.source_matches_selected_native_content(caller.source(), &source)
                {
                    return Ok(failed("native_source_mismatch", "call syntax does not match the admitted selected source", caller));
                }
                for (node_id, node) in facts.nodes().iter().enumerate() {
                    if !session.scope_step() || cancellation.is_cancelled() {
                        break;
                    }
                    if node.kind != NormalizedKind::Call || node.range.start_byte < caller_range.start_byte
                        || node.range.end_byte > caller_range.end_byte {
                        continue;
                    }
                    let shape = call_shape_for_call(&facts, caller.source(), u32::try_from(node_id).expect("source node ID fits u32"))
                        .expect("a structured Call node has a call shape");
                    if shape.outcome.coverage != CallShapeCoverage::Exact {
                        result.diagnostics.push(diagnostic("native_call_shape_incomplete", format!("call shape is {:?} at {:?}", shape.outcome.coverage, shape.outcome.range), caller));
                        continue;
                    }
                    let Some(callee_range) = shape.outcome.callee_range else {
                        result.diagnostics.push(diagnostic("native_call_reference_unavailable", format!("call has no structured callee reference at {:?}", shape.outcome.range), caller));
                        continue;
                    };
                    let locator = SelectedSemanticLocator::for_reference_range("rust", caller_path.clone(), callee_range.start_byte, callee_range.end_byte);
                    let mut metrics = ResolutionBatchMetrics::default();
                    let answer = match queries.resolve_reference(&locator, &mut metrics)? {
                        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) => answer,
                        SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                            result.diagnostics.push(diagnostic("native_call_reference_unavailable", format!("call has no native reference at {callee_range:?}"), caller));
                            continue;
                        }
                        SelectedResolutionOperationOutcome::Unavailable(_)
                        | SelectedResolutionOperationOutcome::Stale(_)
                        | SelectedResolutionOperationOutcome::Cancelled(_) => break,
                    };
                    match answer.resolution.reference_owner() {
                        Some(Some(owner)) if owner == caller_semantic => {}
                        Some(_) => continue,
                        None => {
                            result.diagnostics.push(diagnostic("native_call_owner_unavailable", format!("call has no canonical owner at {callee_range:?}"), caller));
                            continue;
                        }
                    }
                    if answer.resolution.completion() != &ResolutionCompletion::Complete {
                        result.diagnostics.push(diagnostic("native_call_resolution_incomplete", format!(
                            "call resolution at {callee_range:?}: {:?}; receiver dispositions: {:?}",
                            answer.resolution.completion(), answer.resolution.callable_receiver_dispositions(),
                        ), caller));
                    }
                    let cardinality = answer.resolution.binding().targets().len();
                    work.examined_candidates = work.examined_candidates.checked_add(cardinality).expect("call candidate work fits usize");
                    let proof = if cardinality == 1 && answer.resolution.binding().completion() == &ResolutionCompletion::Complete {
                        UsageProof::Proven
                    } else { UsageProof::Unproven };
                    if cardinality > 1 {
                        result.diagnostics.push(CallRelationDiagnostic {
                            code: CallRelationDiagnosticCode::TargetsAmbiguous,
                            message: format!("native call at {callee_range:?} has ambiguous canonical targets: {:?}", answer.resolution.binding().targets()),
                            context: caller.fq_name(),
                            reason_kind: Some("native_call_targets_ambiguous".to_owned()),
                        });
                    }
                    if !answer.lexical_definitions.is_empty() || answer.definitions.is_empty() {
                        result.diagnostics.push(diagnostic("native_call_target_unavailable", format!("call at {callee_range:?} has no complete callable unit projection"), caller));
                    }
                    let mut definitions = answer.definitions;
                    definitions.sort();
                    if definitions.len() > limits.max_candidates {
                        result.truncated = true;
                        let mut omitted = diagnostic("native_call_candidates_omitted", format!("call at {callee_range:?} exceeds its candidate bound"), caller);
                        omitted.code = CallRelationDiagnosticCode::CandidateLimit;
                        result.diagnostics.push(omitted);
                    }
                    for callee in definitions.into_iter().take(limits.max_candidates) {
                        if !session.scope_step() || cancellation.is_cancelled() { break; }
                        if !is_call_relation_unit(&callee) {
                            result.diagnostics.push(diagnostic("native_call_target_not_callable", format!("native call target is not callable: {callee:?}"), caller));
                            continue;
                        }
                        let kind = if callee.is_class() { CallSyntaxKind::Constructor }
                            else if shape.outcome.receiver_range.is_some() { CallSyntaxKind::Method }
                            else { CallSyntaxKind::Function };
                        let arguments = shape.arguments.iter().map(|argument| CallArgument {
                            range: argument.range, name: argument.name.clone(),
                            position: argument.name.is_none().then_some(argument.argument_index),
                            formal_index: None, formal_name: None, variadic: false, spread: argument.spread,
                        }).collect();
                        result.sites.push(CallSite {
                            file: caller.source().clone(), range: shape.outcome.range, callee_range,
                            caller: caller.clone(), callee, kind, proof,
                            receiver: shape.outcome.receiver_range, arguments,
                        });
                    }
                }
                result.sites.sort_by(|a, b| (a.range.start_byte, &a.callee).cmp(&(b.range.start_byte, &b.callee)));
                result.sites.dedup();
                result.diagnostics.sort();
                result.diagnostics.dedup();
                Ok(result)
            },
        )
    })();
    let mut result = match session.finish(selected) {
        BoundedResolution::Cancelled { .. } => CallRelationResult {
            cancelled: true,
            ..CallRelationResult::default()
        },
        BoundedResolution::Exceeded { limit, work } => {
            let mut result = failed(
                "native_call_budget",
                format!("native outgoing resolution exceeded {limit:?}: {work:?}"),
                caller,
            );
            result.truncated = true;
            result.diagnostics[0].code = CallRelationDiagnosticCode::BudgetExhausted;
            result
        }
        BoundedResolution::Complete {
            value: Err(error), ..
        } => failed("native_store_error", error.to_string(), caller),
        BoundedResolution::Complete {
            value: Ok(outcome), ..
        } => match outcome {
            SelectedResolutionOperationOutcome::Native(value) => value,
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                failed("native_unavailable", format!("{reason:?}"), caller)
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                failed("native_stale", format!("{reason:?}"), caller)
            }
            SelectedResolutionOperationOutcome::Cancelled(_) => CallRelationResult {
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
    use super::*;
    use crate::inline_project::InlineTestProject;

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
    fn native_outgoing_preserves_exact_sites_and_async_type_uncertainty() {
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
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.reason_kind.as_deref()
                    == Some("native_call_resolution_incomplete")),
            "{result:?}"
        );
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
    fn native_outgoing_does_not_publish_budget_or_cancelled_prefixes() {
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
                max_scope_nodes: 0,
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
}
