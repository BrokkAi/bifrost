//! Test-support Java incoming-call projection from selected inverse rows.
//!
//! The inverse resolver owns target identity, including overload selection.
//! This module only recognizes call syntax at those already-confirmed sites.

use crate::analyzer::java::JavaAnalyzer;

use crate::analyzer::java::selected_reverse::JavaSelectedInverseResolution;

use crate::analyzer::java::selected_reverse::JavaSelectedReverseOutcome;

use crate::analyzer::java::selected_reverse::java_selected_inverse_detailed_for;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::structural::facts::FileFacts;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;

use brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallArgument;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationProvider;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationResult;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite;

use brokk_bifrost_analysis::analyzer::usages::call_relations::is_call_relation_unit;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSiteSyntax;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_site_syntax_for_reference;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use std::sync::Arc;
use tree_sitter::{Node, Tree};

/// Native Java incoming calls, kept outside production dispatch.
pub struct JavaNativeCallRelations;

impl CallRelationProvider for JavaNativeCallRelations {
    fn proof_authority(&self) -> UsageProofAuthority {
        UsageProofAuthority::Native
    }

    fn incoming(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let cancellation = cancellation.cloned().unwrap_or_default();
        if cancellation.is_cancelled() {
            return CallRelationResult {
                cancelled: true,
                proof_authority: UsageProofAuthority::Native,
                ..CallRelationResult::default()
            };
        }
        if !is_call_relation_unit(target) {
            return CallRelationResult {
                proof_authority: UsageProofAuthority::Native,
                ..CallRelationResult::default()
            };
        }
        if limits.max_files == 0 || limits.max_source_bytes == 0 || limits.max_candidates == 0 {
            return CallRelationResult {
                truncated: true,
                proof_authority: UsageProofAuthority::Native,
                diagnostics: vec![diagnostic(
                    CallRelationDiagnosticCode::BudgetExhausted,
                    format!(
                        "native Java incoming-call budget omitted {}",
                        target.fq_name()
                    ),
                    target.fq_name().to_string(),
                    "native_call_budget_exhausted",
                )],
                ..CallRelationResult::default()
            };
        }
        let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
            return unavailable("native Java analyzer is unavailable", target);
        };
        let selected = match java_selected_inverse_detailed_for(java, java, target, &cancellation) {
            JavaSelectedReverseOutcome::Ready(answer) => answer,
            JavaSelectedReverseOutcome::Unavailable(reason) => {
                return unavailable(
                    format!("selected Java inverse is unavailable: {reason}"),
                    target,
                );
            }
            JavaSelectedReverseOutcome::Stale(reason) => {
                return unavailable(format!("selected Java inverse is stale: {reason}"), target);
            }
            JavaSelectedReverseOutcome::Cancelled => {
                return CallRelationResult {
                    cancelled: true,
                    proof_authority: UsageProofAuthority::Native,
                    ..CallRelationResult::default()
                };
            }
            JavaSelectedReverseOutcome::StoreError(reason) => {
                return unavailable(format!("selected Java inverse failed: {reason}"), target);
            }
        };
        project_incoming_calls(java, target, selected, limits, &cancellation)
    }

    fn outgoing(
        &self,
        _analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        _limits: CallRelationLimits,
        _cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        unavailable(
            "native Java outgoing calls are not part of this slice",
            caller,
        )
    }
}

/// Test-support entry point for comparing native calls with the incumbent.
pub fn java_native_incoming_calls(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    limits: CallRelationLimits,
    cancellation: Option<&CancellationToken>,
) -> CallRelationResult {
    JavaNativeCallRelations.incoming(analyzer, target, limits, cancellation)
}

fn project_incoming_calls(
    java: &JavaAnalyzer,
    target: &CodeUnit,
    mut selected: JavaSelectedInverseResolution,
    limits: CallRelationLimits,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    let mut result = CallRelationResult {
        proof_authority: UsageProofAuthority::Native,
        diagnostics: incomplete_diagnostics(&selected.edges, target),
        ..CallRelationResult::default()
    };
    let mut selected_edges = std::mem::take(&mut selected.edges.edges);
    selected_edges.sort_by(|left, right| {
        (
            left.site.file != *target.source(),
            &left.site.file,
            left.site.range.start_byte,
        )
            .cmp(&(
                right.site.file != *target.source(),
                &right.site.file,
                right.site.range.start_byte,
            ))
    });

    let mut files = HashMap::<ProjectFile, (String, Option<Arc<FileFacts>>, Tree)>::default();
    let mut rejected_files = HashSet::default();
    let mut source_bytes = 0usize;
    for edge in selected_edges {
        if cancellation.is_cancelled() {
            result.sites.clear();
            result.cancelled = true;
            return result;
        }
        let binding_target_count = selected.binding_target_count(&edge.site);
        if binding_target_count != Some(1) {
            let (code, reason) = if binding_target_count.is_some() {
                (
                    CallRelationDiagnosticCode::TargetsAmbiguous,
                    "native_call_target_ambiguous",
                )
            } else {
                (
                    CallRelationDiagnosticCode::AnalysisFailed,
                    "native_call_target_cardinality_unavailable",
                )
            };
            result.diagnostics.push(diagnostic(
                code,
                format!(
                    "selected Java binding target count is {binding_target_count:?}: {:?}",
                    edge.site
                ),
                edge.site.file.to_string(),
                reason,
            ));
            continue;
        }
        if !files.contains_key(&edge.site.file) {
            if rejected_files.contains(&edge.site.file) {
                continue;
            }
            if files.len() >= limits.max_files {
                result.truncated = true;
                rejected_files.insert(edge.site.file.clone());
                continue;
            }
            let Some(source) = java.indexed_source(&edge.site.file) else {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!(
                        "selected Java call source is unavailable: {}",
                        edge.site.file
                    ),
                    edge.site.file.to_string(),
                    "native_call_source_unavailable",
                ));
                rejected_files.insert(edge.site.file.clone());
                continue;
            };
            if source.len() > limits.max_source_bytes.saturating_sub(source_bytes) {
                result.truncated = true;
                rejected_files.insert(edge.site.file.clone());
                continue;
            }
            let Some(tree) = brokk_bifrost_jvm::java::declarations::parse_tree(&source) else {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::ParseFailed,
                    format!("cannot parse selected Java call source: {}", edge.site.file),
                    edge.site.file.to_string(),
                    "native_call_parse_failed",
                ));
                rejected_files.insert(edge.site.file.clone());
                continue;
            };
            if !java
                .inner
                .source_matches_selected_native_content(&edge.site.file, &source)
            {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!("selected Java call source changed: {}", edge.site.file),
                    edge.site.file.to_string(),
                    "native_call_source_stale",
                ));
                rejected_files.insert(edge.site.file.clone());
                continue;
            }
            let facts = java
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(&edge.site.file));
            if facts
                .as_ref()
                .is_some_and(|facts| facts.source() != source.as_str())
            {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!(
                        "selected Java structural source changed: {}",
                        edge.site.file
                    ),
                    edge.site.file.to_string(),
                    "native_call_source_stale",
                ));
                rejected_files.insert(edge.site.file.clone());
                continue;
            }
            source_bytes += source.len();
            result.work.scanned_files += 1;
            result.work.scanned_source_bytes += source.len();
            files.insert(edge.site.file.clone(), (source, facts, tree));
        }
        let Some((_, Some(facts), tree)) = files.get(&edge.site.file) else {
            if !result.diagnostics.iter().any(|item| {
                item.context == edge.site.file.to_string()
                    && item.reason_kind.as_deref() == Some("native_call_facts_unavailable")
            }) {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!(
                        "Java structural call facts are unavailable: {}",
                        edge.site.file
                    ),
                    edge.site.file.to_string(),
                    "native_call_facts_unavailable",
                ));
                rejected_files.insert(edge.site.file.clone());
            }
            continue;
        };
        let Some(syntax) = call_site_syntax_for_reference(
            facts,
            edge.site.range.start_byte,
            edge.site.range.end_byte,
        ) else {
            continue;
        };
        if !is_java_invocation_reference(
            tree.root_node(),
            edge.site.range.start_byte,
            edge.site.range.end_byte,
        ) {
            continue;
        }
        if result.work.examined_candidates >= limits.max_candidates {
            result.truncated = true;
            continue;
        }
        result.work.examined_candidates += 1;
        let caller = java
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| {
                provider
                    .structural_enclosing_code_units(&edge.site.file, &[syntax.range])
                    .and_then(|mut owners| owners.pop().flatten())
            })
            .or(edge.site.enclosing.clone())
            .filter(is_call_relation_unit);
        let Some(caller) = caller else {
            result.diagnostics.push(diagnostic(
                CallRelationDiagnosticCode::AnalysisFailed,
                format!("selected Java call has no callable owner: {:?}", edge.site),
                edge.site.file.to_string(),
                "native_call_owner_unavailable",
            ));
            continue;
        };
        let constructor = target.is_class()
            || java
                .signature_metadata(target)
                .iter()
                .any(|metadata| metadata.callable_is_constructor());
        result.sites.push(make_call_site(
            edge.site.file,
            caller,
            target,
            syntax,
            edge.proof,
            constructor,
        ));
    }
    result.sites.sort_by(|left, right| {
        (&left.file, left.range.start_byte, left.range.end_byte).cmp(&(
            &right.file,
            right.range.start_byte,
            right.range.end_byte,
        ))
    });
    result.sites.dedup_by(|left, right| {
        left.file == right.file
            && left.range.start_byte == right.range.start_byte
            && left.range.end_byte == right.range.end_byte
    });
    result
}

fn is_java_invocation_reference(root: Node<'_>, start_byte: usize, end_byte: usize) -> bool {
    let mut candidates = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= start_byte && end_byte <= node.end_byte() {
            if matches!(
                node.kind(),
                "method_invocation" | "object_creation_expression" | "method_reference"
            ) {
                candidates.push(node);
            }
            let mut children = (0..node.named_child_count())
                .filter_map(|index| node.named_child(index))
                .filter(|child| child.start_byte() <= start_byte && end_byte <= child.end_byte())
                .collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        }
    }
    let Some(node) = candidates
        .into_iter()
        .min_by_key(|node| node.end_byte().saturating_sub(node.start_byte()))
    else {
        return false;
    };
    match node.kind() {
        "method_invocation" => node
            .child_by_field_name("name")
            .is_some_and(|name| name.start_byte() <= start_byte && end_byte <= name.end_byte()),
        "object_creation_expression" => {
            let Some(ty) = node.child_by_field_name("type") else {
                return false;
            };
            let constructor_name = if ty.kind() == "generic_type" {
                ty.child_by_field_name("name").unwrap_or(ty)
            } else {
                ty
            };
            constructor_name.start_byte() <= start_byte && end_byte <= constructor_name.end_byte()
        }
        // A method reference names a callable value; it does not invoke it.
        "method_reference" => false,
        _ => unreachable!("Java invocation candidates were restricted above"),
    }
}

fn make_call_site(
    file: ProjectFile,
    caller: CodeUnit,
    target: &CodeUnit,
    syntax: CallSiteSyntax,
    proof: brokk_bifrost_core::analyzer::usages::model::UsageProof,
    constructor: bool,
) -> CallSite {
    let arguments = syntax
        .arguments
        .into_iter()
        .map(|argument| CallArgument {
            range: argument.range,
            name: argument.name,
            position: argument.position,
            formal_index: None,
            formal_name: None,
            variadic: false,
            spread: argument.spread,
        })
        .collect();
    CallSite {
        file,
        range: syntax.range,
        callee_range: syntax.callee_range,
        caller,
        callee: target.clone(),
        kind: if constructor {
            CallSyntaxKind::Constructor
        } else {
            syntax.kind
        },
        proof,
        receiver: syntax.receiver,
        arguments,
    }
}

fn incomplete_diagnostics(
    selected: &EdgeDerivationResult,
    target: &CodeUnit,
) -> Vec<CallRelationDiagnostic> {
    let EdgeCompleteness::Incomplete { reasons } = &selected.completeness else {
        return Vec::new();
    };
    reasons
        .iter()
        .map(|reason| {
            diagnostic(
                CallRelationDiagnosticCode::AnalysisFailed,
                format!(
                    "selected Java incoming-call inventory is incomplete for {}: {reason:?}",
                    target.fq_name()
                ),
                target.fq_name().to_string(),
                "native_call_inventory_incomplete",
            )
        })
        .collect()
}

fn unavailable(message: impl Into<String>, target: &CodeUnit) -> CallRelationResult {
    CallRelationResult {
        proof_authority: UsageProofAuthority::Native,
        diagnostics: vec![diagnostic(
            CallRelationDiagnosticCode::AnalysisFailed,
            message.into(),
            target.fq_name().to_string(),
            "native_call_unavailable",
        )],
        ..CallRelationResult::default()
    }
}

fn diagnostic(
    code: CallRelationDiagnosticCode,
    message: impl Into<String>,
    context: impl Into<String>,
    reason_kind: &str,
) -> CallRelationDiagnostic {
    CallRelationDiagnostic {
        code,
        message: message.into(),
        context: context.into(),
        reason_kind: Some(reason_kind.to_owned()),
    }
}
