//! Go outgoing call relations from one selected forward operation.

use crate::analyzer::go::GoAnalyzer;
use brokk_bifrost_analysis::analyzer::store_bridge::go_graph::GoGraphStageExt;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationProvider;
use brokk_bifrost_core::analyzer::usages::model::{UsageProof, UsageProofAuthority};

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallArgument;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationResult;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationWork;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite;

use brokk_bifrost_analysis::analyzer::usages::call_relations::is_call_relation_binding;

use brokk_bifrost_analysis::analyzer::usages::call_relations::is_call_relation_unit;

use brokk_bifrost_analysis::analyzer::usages::call_shape::call_shape_for_call;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionSiteKind};
use brokk_bifrost_core::analyzer::structural::callable::CallShapeCoverage;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_core::hash::HashSet;

#[cfg(test)]
pub(crate) struct GoNativeCallRelationProvider;

#[cfg(test)]
impl CallRelationProvider for GoNativeCallRelationProvider {
    fn proof_authority(&self) -> brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority {
        brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority::Native
    }

    fn incoming(
        &self,
        _analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        _limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return CallRelationResult {
                cancelled: true,
                proof_authority: UsageProofAuthority::Native,
                ..CallRelationResult::default()
            };
        }
        failed(
            "native_go_incoming_unavailable",
            "native Go incoming call relations are not part of this test-support slice",
            target,
        )
    }

    fn outgoing(
        &self,
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let fallback = CancellationToken::new();
        let cancellation = cancellation.unwrap_or(&fallback);
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return failed(
                "native_analyzer_unavailable",
                "Go analyzer is unavailable",
                caller,
            );
        };
        outgoing(
            go,
            caller,
            limits,
            ReceiverAnalysisBudget::default(),
            cancellation,
        )
    }
}

fn diagnostic(kind: &str, message: impl Into<String>, caller: &CodeUnit) -> CallRelationDiagnostic {
    CallRelationDiagnostic::analysis_failed(
        message.into(),
        caller.fq_name().to_string(),
        kind.to_owned(),
    )
}

fn failed(kind: &str, message: impl Into<String>, caller: &CodeUnit) -> CallRelationResult {
    CallRelationResult {
        diagnostics: vec![diagnostic(kind, message, caller)],
        proof_authority: UsageProofAuthority::Native,
        ..CallRelationResult::default()
    }
}

struct GoCallShape {
    range: Range,
    callee_range: Option<Range>,
    receiver: Option<Range>,
    arguments: Vec<brokk_bifrost_analysis::analyzer::usages::call_shape::ArgumentRow>,
    coverage: CallShapeCoverage,
}

/// Resolve source-backed Go call shapes through one selected Go operation.
/// Exact external proofs classify a target as outside the workspace. The
/// current Rust provider still reports its no-source-unit diagnostic for the
/// same case; keep that completeness behavior aligned until the owner changes
/// the shared contract.
pub(crate) fn outgoing(
    go: &GoAnalyzer,
    caller: &CodeUnit,
    limits: CallRelationLimits,
    budget: ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    // Every result of this function, including cancellation and failures,
    // comes from the native engine (#6829).
    CallRelationResult {
        proof_authority: UsageProofAuthority::Native,
        ..resolve_outgoing(go, caller, limits, budget, cancellation)
    }
}

fn resolve_outgoing(
    go: &GoAnalyzer,
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
    let Some(source) = go.indexed_source(caller.source()) else {
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
    if !go
        .inner
        .source_matches_selected_native_content(caller.source(), &source)
    {
        return failed(
            "native_source_mismatch",
            "caller source differs from the selected Go source",
            caller,
        );
    }
    let Some(caller_range) = go
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
        let snapshots = go.inner.selected_workspace_snapshots();
        let Some(snapshot) = snapshots.get("go") else {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(
                brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable::MissingWorkspaceSnapshot {
                    storage_language: "go".to_owned(),
                },
            ));
        };
        let Some(profile) = go.context_profile_for_file(
            &brokk_bifrost_core::path_utils::rel_path_string(caller.source()),
        ) else {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(
                brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable::GoContextUnavailable {
                    persisted_relative_path: caller.source().rel_path().to_string_lossy().into_owned(),
                },
            ));
        };
        let Some(context) = go
            .inner
            .analyzer_store()
            .selected_go_context(snapshot, &profile)?
        else {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(
                brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable::GoContextUnavailable {
                    persisted_relative_path: caller.source().rel_path().to_string_lossy().into_owned(),
                },
            ));
        };
        let (masks, content_mounts) = match go
            .inner
            .selected_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
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
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let input = SelectedResolutionOperationInput::new(
            go.inner.project(),
            go.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts);
        let mut operation = match go
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(input, cancellation)?
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => (*operation).with_go_model_authority(
                go.inner.semantic_model_overlay().map(|overlay| overlay as std::sync::Arc<dyn brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedModelAuthority + Send + Sync>)
            ),
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
        operation.initialize_go_base_profile(
            &go.native_context_base_profile()
                .expect("outgoing query selected an active Go context"),
        );
        operation.bind_go_context_publication(context.clone());
        let caller_path = brokk_bifrost_core::path_utils::rel_path_string(caller.source());
        let mut selected_imports = operation.go_selected_external_imports(
            context.context_id,
            &caller_path,
            cancellation,
        )?;
        let semantic_model_overlay = go.inner.semantic_model_overlay();
        let unresolved_imports = operation.go_selected_unresolved_imports(
            context.context_id,
            &caller_path,
            cancellation,
        )?;
        crate::analyzer::go::native_points::append_model_backed_external_imports(
            unresolved_imports,
            semantic_model_overlay.as_deref(),
            cancellation,
            &mut selected_imports,
        );
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
            ));
        }
        let Some(facts) = go
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(caller.source()))
        else {
            return Ok(SelectedResolutionOperationOutcome::Native(failed(
                "native_structural_facts_unavailable",
                "caller structural facts are unavailable",
                caller,
            )));
        };
        if facts.source() != source.as_str() {
            return Ok(SelectedResolutionOperationOutcome::Native(failed(
                "native_source_mismatch",
                "caller structural facts do not match indexed source",
                caller,
            )));
        }
        let Some(tree) = crate::analyzer::usages::get_definition::go::parse_go_tree(&source) else {
            return Ok(SelectedResolutionOperationOutcome::Native(failed(
                "native_parse_failed",
                "caller Go source could not be parsed",
                caller,
            )));
        };
        let mut shapes = Vec::new();
        let mut seen_call_spans = HashSet::default();
        for (node_id, node) in facts.nodes().iter().enumerate() {
            if cancellation.is_cancelled() || !session.scope_step() {
                break;
            }
            if node.kind != NormalizedKind::Call
                || node.range.start_byte < caller_range.start_byte
                || node.range.end_byte > caller_range.end_byte
            {
                continue;
            }
            let call_id = u32::try_from(node_id).expect("source node ID fits u32");
            let Some(shape) = call_shape_for_call(&facts, caller.source(), call_id) else {
                continue;
            };
            if !seen_call_spans
                .insert((shape.outcome.range.start_byte, shape.outcome.range.end_byte))
            {
                continue;
            }
            shapes.push(GoCallShape {
                range: shape.outcome.range,
                callee_range: shape.outcome.callee_range,
                receiver: shape.outcome.receiver_range,
                arguments: shape.arguments,
                coverage: shape.outcome.coverage,
            });
        }
        shapes.sort_by_key(|shape| (shape.range.start_byte, shape.range.end_byte));
        let mut calls_by_callee = HashMap::<(usize, usize), Vec<usize>>::default();
        let mut result = CallRelationResult::default();
        for (index, shape) in shapes.iter().enumerate() {
            if !shape.coverage.is_exact() {
                result.diagnostics.push(diagnostic(
                    "native_call_shape_incomplete",
                    format!("Go call shape is {:?} at {:?}", shape.coverage, shape.range),
                    caller,
                ));
                continue;
            }
            let Some(callee_range) = shape.callee_range else {
                result.diagnostics.push(diagnostic(
                    "native_call_reference_unavailable",
                    format!(
                        "Go call has no structured callee reference at {:?}",
                        shape.range
                    ),
                    caller,
                ));
                continue;
            };
            calls_by_callee
                .entry((callee_range.start_byte, callee_range.end_byte))
                .or_default()
                .push(index);
        }
        let file = caller.source().clone();
        let mut selected_call_indices = HashSet::default();
        let mut receiver_candidate_calls = Vec::new();
        let mut files = HashSet::default();
        files.insert(file.clone());
        let staged = operation.stage_go_reference_edge_batches_in_files(
            go,
            context.context_id,
            &files,
            brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
            cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut |_file, source_batch, edge_batch, projections| {
                if edge_batch.generation() != go.inner.project().analysis_generation() {
                    return Err(brokk_bifrost_analysis::analyzer::store::StoreError::new(
                        "Go call batch crossed an analyzer generation",
                    ));
                }
                for (answer_index, answer) in source_batch.answers().iter().enumerate() {
                    if cancellation.is_cancelled() || !session.scope_step() {
                        break;
                    }
                    let Some(metadata) = answer.site_metadata() else {
                        continue;
                    };
                    let Some(call_indices) = calls_by_callee
                        .get(&(metadata.start_byte(), metadata.end_byte()))
                    else {
                        continue;
                    };
                    for &call_index in call_indices {
                        if !selected_call_indices.insert(call_index) {
                            continue;
                        }
                        let Some(owner) = projections[answer_index].reference_owner.as_ref()
                        else {
                            result.diagnostics.push(diagnostic(
                                "native_call_owner_unavailable",
                                format!(
                                    "call has no canonical owner at {}..{}",
                                    metadata.start_byte(),
                                    metadata.end_byte()
                                ),
                                caller,
                            ));
                            continue;
                        };
                        if owner != caller {
                            continue;
                        }
                        let binding = answer.answer().binding();
                        let completion = answer.answer().call_target_completion();
                        work.examined_candidates = work
                            .examined_candidates
                            .checked_add(binding.targets().len())
                            .expect("call candidate work fits usize");
                        if metadata.site_kind() == ResolutionSiteKind::TypeReference
                            && metadata.namespace() == ResolutionNamespace::Type
                            && binding.completion() == &ResolutionCompletion::Complete
                        {
                            // A call-shaped Go conversion binds to a type, not
                            // to a workspace callable.
                            continue;
                        }
                        let projected_targets = &projections[answer_index].binding_targets;
                        let mut callees = binding
                            .targets()
                            .iter()
                            .zip(projected_targets)
                            .filter_map(|(_, target)| {
                                target
                                    .as_ref()
                                    .filter(|target| {
                                        is_call_relation_binding(
                                            Language::Go,
                                            metadata.site_kind(),
                                            metadata.namespace(),
                                            target,
                                        )
                                    })
                                    .cloned()
                            })
                            .map(|target| (target, UsageProof::Unproven))
                            .collect::<Vec<_>>();
                        callees.sort_by(|left, right| left.0.cmp(&right.0));
                        callees.dedup();
                        if callees.is_empty() {
                            if let Some(site) = workspace_unqualified_call_site(
                                go,
                                caller,
                                &source,
                                &tree,
                                &shapes[call_index],
                                &session,
                                budget,
                                cancellation,
                            ) {
                                result.sites.push(site);
                                continue;
                            }
                            let model_selection = answer.answer().model_member_selection().and_then(|selection| brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::project_native_model_member_selection(selection, cancellation));
                            let exact_external = exact_external_call(
                                go,
                                caller,
                                &source,
                                &tree,
                                &shapes[call_index],
                                model_selection.as_deref(),
                                &selected_imports,
                                &session,
                                budget,
                                cancellation,
                            );
                            if exact_external.is_none() {
                                if completion != ResolutionCompletion::Complete {
                                    result.diagnostics.push(diagnostic(
                                        "native_call_resolution_incomplete",
                                        format!(
                                            "call resolution at {}..{}: {:?}; receiver dispositions: {:?}",
                                            metadata.start_byte(),
                                            metadata.end_byte(),
                                            completion,
                                            answer.callable_receiver_dispositions(),
                                        ),
                                        caller,
                                    ));
                                }
                                receiver_candidate_calls.push((call_index, model_selection.is_none() && binding.targets().is_empty(), diagnostic(
                                    "native_call_target_unavailable",
                                    format!(
                                        "call at {}..{} has no workspace target and no exact external proof; site kind {:?}, namespace {:?}, targets {:?}, completion {:?}",
                                        shapes[call_index].range.start_byte,
                                        shapes[call_index].range.end_byte,
                                        metadata.site_kind(),
                                        metadata.namespace(),
                                        binding.targets(),
                                        binding.completion(),
                                    ),
                                    caller,
                                )));
                            }
                            // An exact external proof is a complete, known
                            // non-workspace callee; omit it without an error.
                            continue;
                        }
                        if projected_targets.iter().any(Option::is_none)
                            || callees.len() < binding.targets().len()
                        {
                            result.diagnostics.push(diagnostic(
                                "native_call_target_unavailable",
                                format!(
                                    "call at {}..{} has one or more targets without a callable workspace unit",
                                    metadata.start_byte(),
                                    metadata.end_byte()
                                ),
                                caller,
                            ));
                        }
                        if completion != ResolutionCompletion::Complete {
                            result.diagnostics.push(diagnostic(
                                "native_call_resolution_incomplete",
                                format!(
                                    "call resolution at {}..{}: {:?}; receiver dispositions: {:?}",
                                    metadata.start_byte(),
                                    metadata.end_byte(),
                                    completion,
                                    answer.callable_receiver_dispositions(),
                                ),
                                caller,
                            ));
                        }
                        if binding.targets().len() > 1 {
                            result.diagnostics.push(CallRelationDiagnostic {
                                code: CallRelationDiagnosticCode::TargetsAmbiguous,
                                message: format!("Go call at {}..{} has ambiguous canonical targets: {:?}", metadata.start_byte(), metadata.end_byte(), callees),
                                context: caller.fq_name().to_string(),
                                reason_kind: Some("native_call_targets_ambiguous".to_owned()),
                            });
                        }
                        let proof = if binding.targets().len() == 1
                            && completion == ResolutionCompletion::Complete
                            && projected_targets.len() == binding.targets().len()
                            && projected_targets.iter().all(Option::is_some)
                            && callees.len() == binding.targets().len()
                        {
                            UsageProof::Proven
                        } else {
                            UsageProof::Unproven
                        };
                        if callees.len() > limits.max_candidates {
                            result.truncated = true;
                            result.diagnostics.push(CallRelationDiagnostic {
                                code: CallRelationDiagnosticCode::CandidateLimit,
                                message: format!("Go call at {}..{} exceeds its candidate bound", metadata.start_byte(), metadata.end_byte()),
                                context: caller.fq_name().to_string(),
                                reason_kind: Some("native_call_candidates_omitted".to_owned()),
                            });
                        }
                        let shape = &shapes[call_index];
                        let callee_range = shape.callee_range.expect("call candidates have a callee range");
                        let arguments = shape.arguments.iter().map(|argument| CallArgument {
                            range: argument.range,
                            name: argument.name.clone(),
                            position: argument.name.is_none().then_some(argument.argument_index),
                            formal_index: None,
                            formal_name: None,
                            variadic: false,
                            spread: argument.spread,
                        }).collect::<Vec<_>>();
                        for (callee, _) in callees.into_iter().take(limits.max_candidates) {
                            if !session.scope_step() || cancellation.is_cancelled() {
                                break;
                            }
                            let (kind, receiver) = if callee.declaration_segment_count() > 1 {
                                (CallSyntaxKind::Method, shape.receiver)
                            } else {
                                (CallSyntaxKind::Function, None)
                            };
                            result.sites.push(CallSite {
                                file: file.clone(),
                                range: shape.range,
                                callee_range,
                                caller: caller.clone(),
                                callee,
                                kind,
                                proof,
                                receiver,
                                arguments: arguments.clone(),
                            });
                        }
                    }
                }
                Ok(())
            },
        )?;
        let summary = match staged {
            SelectedResolutionOperationOutcome::Native(summary) => summary,
            SelectedResolutionOperationOutcome::Cancelled(completion) => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
        };
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
            ));
        }
        if !receiver_candidate_calls.is_empty() {
            let prepared =
                operation.go_file_import_context(context.context_id, &caller_path, cancellation)?;
            for (call_index, unmodeled, unavailable) in receiver_candidate_calls {
                let shape = &shapes[call_index];
                let range = shape
                    .callee_range
                    .expect("selected call has a callee range");
                let site = ResolvedReferenceSite {
                    path: caller_path.clone(),
                    text: source[range.start_byte..range.end_byte].to_owned(),
                    range,
                    focus_start_byte: range.start_byte,
                    focus_end_byte: range.end_byte,
                };
                let proof = if unmodeled {
                    if let brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoPreparedImportContextOutcome::Ready(prepared) = &prepared {
                        let answer = super::native_points::declared_external_receiver_call(
                            &mut operation, (**prepared).clone(), BoundedReceiverQuery {
                                analyzer: go, file: caller.source(), source: &source, tree: Some(&tree),
                                site: &site, budget: session.remaining_budget().expect("bounded outgoing session"), cancellation: Some(cancellation),
                            },
                        )?;
                        // Each queued call consumes the outgoing request's remaining
                        // allowance; do not reset the budget for the next call.
                        let hook_work = answer.work();
                        session.scope_steps(hook_work.scope_nodes);
                        for _ in 0..hook_work.summary_expansions { if !session.summary_step() { break; } }
                        for _ in 0..hook_work.resolution_rounds { if !session.round_step() { break; } }
                        match answer {
                            BoundedResolution::Complete { value, .. } => value,
                            BoundedResolution::Exceeded { .. } => {
                                result.truncated = true;
                                None
                            }
                            BoundedResolution::Cancelled { .. } => {
                                result.cancelled = true;
                                None
                            }
                        }
                    } else { None }
                } else {
                    None
                };
                if let Some(proof) = proof {
                    result.diagnostics.push(diagnostic(
                        "native_call_resolution_incomplete",
                        format!(
                            "external Go receiver member {} has no indexed declaration",
                            proof.canonical_callee()
                        ),
                        caller,
                    ));
                } else {
                    result.diagnostics.push(unavailable);
                }
            }
        }
        for (index, shape) in shapes.iter().enumerate() {
            if shape.coverage.is_exact()
                && shape.callee_range.is_some()
                && !selected_call_indices.contains(&index)
            {
                if exact_external_call(
                    go,
                    caller,
                    &source,
                    &tree,
                    shape,
                    None,
                    &selected_imports,
                    &session,
                    budget,
                    cancellation,
                )
                .is_some()
                {
                    continue;
                }
                if let Some(site) = workspace_unqualified_call_site(
                    go,
                    caller,
                    &source,
                    &tree,
                    shape,
                    &session,
                    budget,
                    cancellation,
                ) {
                    result.sites.push(site);
                    continue;
                }
                result.diagnostics.push(diagnostic(
                    "native_call_reference_unavailable",
                    format!(
                        "call has no selected native reference at {:?}",
                        shape.callee_range
                    ),
                    caller,
                ));
            }
        }
        let completion = summary
            .completion()
            .combine(summary.reference_enumeration_completion());
        match operation.finish_native(summary, &completion, cancellation)? {
            SelectedResolutionOperationOutcome::Native(_) => {}
            SelectedResolutionOperationOutcome::Cancelled(_) => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
                ));
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
        }
        result
            .sites
            .sort_by(|a, b| (a.range.start_byte, &a.callee).cmp(&(b.range.start_byte, &b.callee)));
        result.sites.dedup();
        result.diagnostics.sort();
        result.diagnostics.dedup();
        Ok(SelectedResolutionOperationOutcome::Native(result))
    })();
    let mut result = match session.finish(selected) {
        BoundedResolution::Cancelled { .. } => CallRelationResult {
            cancelled: true,
            ..CallRelationResult::default()
        },
        BoundedResolution::Exceeded {
            limit,
            work: analysis_work,
        } => {
            let mut result = failed(
                "native_call_budget",
                format!("native Go outgoing resolution exceeded {limit:?}: {analysis_work:?}"),
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
            SelectedResolutionOperationOutcome::Native(result) => result,
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

#[allow(clippy::too_many_arguments)]
fn exact_external_call(
    go: &GoAnalyzer,
    caller: &CodeUnit,
    source: &str,
    tree: &tree_sitter::Tree,
    shape: &GoCallShape,
    model_selection: Option<&brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeModelMemberSelection>,
    selected_imports: &[brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoSelectedExternalImport],
    session: &ResolutionSession,
    budget: ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> Option<ExactExternalCallProof> {
    let range = shape.callee_range?;
    if range.end_byte > source.len() || range.start_byte > range.end_byte {
        return None;
    }
    let site = ResolvedReferenceSite {
        path: brokk_bifrost_core::path_utils::rel_path_string(caller.source()),
        text: source[range.start_byte..range.end_byte].to_owned(),
        range,
        focus_start_byte: range.start_byte,
        focus_end_byte: range.end_byte,
    };
    let query = BoundedReceiverQuery {
        analyzer: go,
        file: caller.source(),
        source,
        tree: Some(tree),
        site: &site,
        budget,
        cancellation: Some(cancellation),
    };
    let selector = brokk_bifrost_go::references::go_selector_descriptor(tree.root_node(), &site);
    if let Some(selector) = selector.as_ref()
        && matches!(selector.base.kind(), "identifier" | "package_identifier")
        && selector.focus_segment == 1
    {
        for selected in selected_imports {
            if let Some((_, Some(proof), _, _)) = crate::analyzer::usages::get_definition::go::go_native_external_package_member_resolution(
                    query,
                    go,
                    session,
                    go.inner.semantic_model_overlay(),
                    selected,
                )
            {
                return Some(proof);
            }
        }
    }
    let selection = model_selection?;
    let descriptor = super::model_receiver::transient_selection(query, selection)?;
    let super::model_receiver::GoModelReceiverSelection::Handled(selected) =
        super::model_receiver::go_selected_model_receiver_call(
            query,
            Some(selection),
            &descriptor,
            session,
        )
    else {
        return None;
    };
    // Only a proved, fully prepared external route can suppress native
    // incompleteness diagnostics. Promoted model storage remains open.
    selected
        .proof
        .filter(|proof| selected.reasons.is_empty() && proof.dispatch_extensibility().is_some())
}

#[allow(clippy::too_many_arguments)]
fn workspace_unqualified_call_site(
    go: &GoAnalyzer,
    caller: &CodeUnit,
    source: &str,
    tree: &tree_sitter::Tree,
    shape: &GoCallShape,
    session: &ResolutionSession,
    budget: ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> Option<CallSite> {
    let callee_range = shape.callee_range?;
    let text = source.get(callee_range.start_byte..callee_range.end_byte)?;
    let site = ResolvedReferenceSite {
        path: brokk_bifrost_core::path_utils::rel_path_string(caller.source()),
        text: text.to_owned(),
        range: callee_range,
        focus_start_byte: callee_range.start_byte,
        focus_end_byte: callee_range.end_byte,
    };
    let resolution =
        crate::analyzer::usages::get_definition::go::go_native_workspace_unqualified_call_resolution(
            BoundedReceiverQuery {
                analyzer: go,
                file: caller.source(),
                source,
                tree: Some(tree),
                site: &site,
                budget,
                cancellation: Some(cancellation),
            },
            session,
        )?;
    if resolution.status != DefinitionLookupStatus::Resolved {
        return None;
    }
    let [callee] = resolution.definitions.as_slice() else {
        return None;
    };
    if !callee.is_function() {
        return None;
    }
    let callee = callee.clone();
    let arguments = shape
        .arguments
        .iter()
        .map(|argument| CallArgument {
            range: argument.range,
            name: argument.name.clone(),
            position: argument.name.is_none().then_some(argument.argument_index),
            formal_index: None,
            formal_name: None,
            variadic: false,
            spread: argument.spread,
        })
        .collect();
    Some(CallSite {
        file: caller.source().clone(),
        range: shape.range,
        callee_range,
        caller: caller.clone(),
        callee,
        kind: CallSyntaxKind::Function,
        proof: UsageProof::Proven,
        receiver: None,
        arguments,
    })
}

#[cfg(test)]
mod tests {

    use crate::analyzer::go::native_outgoing::*;

    use crate::inline_project::InlineTestProject;

    fn fixture() -> (
        crate::inline_project::BuiltInlineTestProject,
        GoAnalyzer,
        CodeUnit,
    ) {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/calls\n\ngo 1.22\n")
            .file(
                "model/model.go",
                "package model\ntype Widget struct{}\nfunc Target() {}\nfunc (Widget) Method() {}\n",
            )
            .file(
                "client/use.go",
                "package client\nimport (\"example.test/calls/model\"; \"os\")\nfunc Caller(w model.Widget, f *os.File) { model.Target(); w.Method(); model.Widget.Method(w); model.Widget(w); len([]int{}); f.Close(); }\n",
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        crate::analyzer::go::persist_live_go_sources_for_test(&go);
        let caller = go
            .declarations(&fixture.file("client/use.go"))
            .into_iter()
            .find(|unit| unit.identifier() == "Caller")
            .expect("caller declaration");
        (fixture, go, caller)
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6811: Go reverse search and outgoing calls read participation without a base profile"
    )]
    fn native_outgoing_excludes_build_ignored_sibling_method() {
        let Some((fixture, go)) = crate::analyzer::go::build_constrained_sibling_fixture_for_test(
            "package workerprofile\n\nfunc Invoke(s *Service) { s.Run() }\n",
        ) else {
            return;
        };
        let caller = go
            .declarations(&fixture.file("service.go"))
            .into_iter()
            .find(|unit| unit.identifier() == "Invoke")
            .expect("caller declaration");
        let result = GoNativeCallRelationProvider.outgoing(
            &go,
            &caller,
            CallRelationLimits {
                max_files: 4,
                max_source_bytes: 32_768,
                max_candidates: 16,
            },
            None,
        );
        assert!(!result.cancelled && !result.truncated, "{result:?}");
        assert!(result.diagnostics.is_empty(), "{result:?}");
        let [site] = result.sites.as_slice() else {
            panic!("one call to the participating method: {result:?}");
        };
        assert_eq!(site.callee.identifier(), "Run");
        assert_eq!(site.callee.source(), &fixture.file("service_linux.go"));
        assert_eq!(site.kind, CallSyntaxKind::Method);
        assert_eq!(site.proof, UsageProof::Proven);
    }

    #[test]
    fn native_outgoing_projects_workspace_calls_and_omits_conversions() {
        let (_fixture, go, caller) = fixture();
        let _catalog = crate::analyzer::go::native_points::activate_receiver_models_for_test(&go);
        let overlay = go
            .semantic_model_overlay()
            .expect("activated receiver models");
        let result = GoNativeCallRelationProvider.outgoing(
            &go,
            &caller,
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: 32_768,
                max_candidates: 16,
            },
            None,
        );
        assert!(!result.cancelled && !result.truncated, "{result:?}");
        assert_eq!(
            result
                .sites
                .iter()
                .map(|site| site.callee.identifier())
                .collect::<Vec<_>>(),
            ["Target", "Method", "Method"],
            "method expressions bind to the method, conversions do not become callees: {result:?}"
        );
        assert_eq!(
            result
                .sites
                .iter()
                .map(|site| (
                    (site.range.start_byte, site.range.end_byte),
                    (site.callee_range.start_byte, site.callee_range.end_byte),
                ))
                .collect::<Vec<_>>(),
            [
                ((99, 113), (105, 111)),
                ((115, 125), (117, 123)),
                ((127, 149), (140, 146))
            ],
            "native Go call and callee spans must preserve the structured source sites"
        );
        assert!(
            result
                .sites
                .iter()
                .all(|site| site.proof == UsageProof::Proven)
        );
        assert_eq!(
            result
                .sites
                .iter()
                .map(|site| site.kind)
                .collect::<Vec<_>>(),
            [
                CallSyntaxKind::Function,
                CallSyntaxKind::Method,
                CallSyntaxKind::Method,
            ],
            "bound methods and method expressions retain their syntax kind: {result:?}"
        );
        assert!(
            result.sites[0].receiver.is_none(),
            "a package qualifier is not a receiver: {result:?}"
        );
        assert!(
            result.diagnostics.iter().any(|diagnostic| {
                diagnostic
                    .reason_kind
                    .as_deref()
                    .is_some_and(|kind| kind.contains("incomplete") || kind.contains("unavailable"))
            }),
            "an unsupported Go builtin remains explicitly incomplete: {result:?}"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.reason_kind.as_deref()
                    != Some("native_call_resolution_incomplete")),
            "the builtin's return projection must not add a call-target diagnostic: {result:?}"
        );
        let source = go
            .indexed_source(caller.source())
            .expect("indexed caller source");
        let tree = crate::analyzer::usages::get_definition::go::parse_go_tree(&source)
            .expect("parse caller source");
        let mut model_backed_imports = Vec::new();
        crate::analyzer::go::native_points::append_model_backed_external_imports(
            ["os".to_owned()],
            Some(&overlay),
            &CancellationToken::new(),
            &mut model_backed_imports,
        );
        let external_call = GoCallShape {
            range: Range {
                start_byte: 182,
                end_byte: 191,
                start_line: 3,
                end_line: 3,
            },
            callee_range: Some(Range {
                start_byte: 184,
                end_byte: 189,
                start_line: 3,
                end_line: 3,
            }),
            receiver: Some(Range {
                start_byte: 182,
                end_byte: 183,
                start_line: 3,
                end_line: 3,
            }),
            arguments: Vec::new(),
            coverage: CallShapeCoverage::Exact,
        };
        let range = external_call.callee_range.unwrap();
        let site = ResolvedReferenceSite {
            path: brokk_bifrost_core::path_utils::rel_path_string(caller.source()),
            text: source[range.start_byte..range.end_byte].to_owned(),
            range,
            focus_start_byte: range.start_byte,
            focus_end_byte: range.end_byte,
        };
        let selected =
            crate::analyzer::go::native_points::resolve_go_definition_with_evidence_bounded(
                BoundedReceiverQuery {
                    analyzer: &go,
                    file: caller.source(),
                    source: &source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                },
                || {},
            );
        let brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Complete {
            value: selected,
            ..
        } = selected
        else {
            panic!("native selected model receiver")
        };
        let exact_proof = exact_external_call(
            &go,
            &caller,
            &source,
            &tree,
            &external_call,
            selected.model_member_selection.as_deref(),
            &model_backed_imports,
            &ResolutionSession::unbounded(),
            ReceiverAnalysisBudget::default(),
            &CancellationToken::new(),
        )
        .expect("the model-backed os import proves f.Close as external");
        assert_eq!(exact_proof.canonical_callee(), "os.File.Close");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6825: Go outgoing calls reported Complete-empty for a method declared in another file than its receiver type"
    )]
    fn native_outgoing_resolves_cross_file_receiver_method() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/calls\n\ngo 1.22\n")
            .file(
                "service.go",
                "package service\ntype Service struct{}\nfunc Invoke(s *Service) { s.Run() }\n",
            )
            .file("method.go", "package service\nfunc (s *Service) Run() {}\n")
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        crate::analyzer::go::persist_live_go_sources_for_test(&go);
        let caller = go
            .declarations(&fixture.file("service.go"))
            .into_iter()
            .find(|unit| unit.identifier() == "Invoke")
            .expect("caller");
        let result = GoNativeCallRelationProvider.outgoing(
            &go,
            &caller,
            CallRelationLimits {
                max_files: 4,
                max_source_bytes: 32_768,
                max_candidates: 16,
            },
            None,
        );
        assert_eq!(result.proof_authority, UsageProofAuthority::Native);
        assert!(result.diagnostics.is_empty(), "{result:#?}");
        let [site] = result.sites.as_slice() else {
            panic!("one cross-file method target: {result:#?}")
        };
        assert_eq!(site.callee.source(), &fixture.file("method.go"));
        assert_eq!(site.callee.identifier(), "Run");
        assert_eq!(site.proof, UsageProof::Proven);
    }

    #[test]
    fn native_outgoing_binds_same_package_calls_from_source_inventory() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/calls\n\ngo 1.22\n")
            .file(
                "main.go",
                "package main\nfunc Caller() { go writePointer(&Cell{}) }\n",
            )
            .file(
                "helper.go",
                "package main\ntype Cell struct {}\nfunc writePointer(cell *Cell) {}\n",
            )
            .build();
        let go = GoAnalyzer::new(fixture.project_dyn());
        crate::analyzer::go::persist_live_go_sources_for_test(&go);
        let caller = go
            .declarations(&fixture.file("main.go"))
            .into_iter()
            .find(|unit| unit.identifier() == "Caller")
            .expect("caller declaration");

        let result = GoNativeCallRelationProvider.outgoing(
            &go,
            &caller,
            CallRelationLimits {
                max_files: 2,
                max_source_bytes: 32_768,
                max_candidates: 16,
            },
            None,
        );

        assert!(result.diagnostics.is_empty(), "{result:#?}");
        let [site] = result.sites.as_slice() else {
            panic!("one same-package call relation: {result:#?}");
        };
        assert_eq!(
            site.callee.fq_name().to_string(),
            "example.test/calls.writePointer"
        );
        assert_eq!(site.kind, CallSyntaxKind::Function);
        assert_eq!(site.proof, UsageProof::Proven);
    }
}
