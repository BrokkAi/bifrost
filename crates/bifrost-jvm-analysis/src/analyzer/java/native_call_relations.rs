//! Java grammar and source authority for the shared incoming-call projection.
//! Test-support Java incoming-call projection from selected inverse rows.
//!
//! The inverse resolver owns target identity, including overload selection.
//! This module only recognizes call syntax at those already-confirmed sites.

use crate::analyzer::java::JavaAnalyzer;

use crate::analyzer::java::selected_reverse::JavaSelectedInverseResolution;

use crate::analyzer::java::selected_reverse::JavaSelectedReverseOutcome;

use crate::analyzer::java::selected_reverse::java_selected_inverse_detailed_for;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;

use brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationProvider;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationResult;

use brokk_bifrost_analysis::analyzer::usages::call_relations::native_incoming_preflight;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSiteSyntax;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceEdgeRow;
use brokk_bifrost_analysis::analyzer::usages::native_incoming::{
    IncomingCallProjection, IncomingFile, IncomingFileBudget, IncomingProjectionIssue,
    finish_incoming_sites, project_selected_incoming, structural_incoming_caller,
};
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
        if let Some(result) = native_incoming_preflight(target, limits, &cancellation, || {
            diagnostic(
                CallRelationDiagnosticCode::BudgetExhausted,
                format!(
                    "native Java incoming-call budget omitted {}",
                    target.fq_name()
                ),
                target.fq_name().to_string(),
                "native_call_budget_exhausted",
            )
        }) {
            return result;
        }
        let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
            return unavailable("native Java analyzer is unavailable", target);
        };
        let selected = match java_selected_inverse_detailed_for(java, java, target, &cancellation) {
            JavaSelectedReverseOutcome::Ready(answer) => answer,
            JavaSelectedReverseOutcome::Unavailable(reason)
            | JavaSelectedReverseOutcome::TargetUncovered(reason) => {
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

    let mut rows = Vec::new();
    for edge in &selected_edges {
        if cancellation.is_cancelled() {
            result.cancelled = true;
            return result;
        }
        assert_eq!(
            &edge.target, target,
            "reverse batch preserves target identity"
        );
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
        rows.push((edge, ()));
    }
    let projected = project_selected_incoming(
        &mut JavaIncomingProjection {
            java,
            trees: HashMap::default(),
        },
        target,
        rows,
        limits,
        cancellation,
        &mut result,
    );
    if let Some(sites) = projected.unwrap_or_else(|never| match never {}) {
        finish_incoming_sites(sites, &mut result);
    }
    // Constructor identity is a Java rule; raw_call_site preserves syntax kind.
    if target.is_class()
        || java
            .signature_metadata(target)
            .iter()
            .any(|metadata| metadata.callable_is_constructor())
    {
        for site in &mut result.sites {
            site.kind = CallSyntaxKind::Constructor;
        }
    }
    result
}

struct JavaIncomingProjection<'a> {
    java: &'a JavaAnalyzer,
    trees: HashMap<ProjectFile, Tree>,
}

impl IncomingCallProjection for JavaIncomingProjection<'_> {
    type Error = std::convert::Infallible;

    fn load_file(
        &mut self,
        file: &ProjectFile,
        budget: &mut IncomingFileBudget<'_>,
        diagnostics: &mut Vec<CallRelationDiagnostic>,
    ) -> Result<IncomingFile, Self::Error> {
        if budget.file_capacity_exhausted() {
            return Ok(IncomingFile::Rejected);
        }
        let Some(source) = self.java.indexed_source(file) else {
            diagnostics.push(diagnostic(
                CallRelationDiagnosticCode::AnalysisFailed,
                format!("selected Java call source is unavailable: {}", file),
                file.to_string(),
                "native_call_source_unavailable",
            ));
            return Ok(IncomingFile::Rejected);
        };
        if !budget.source_fits(source.len()) {
            return Ok(IncomingFile::Rejected);
        }
        let Some(tree) = brokk_bifrost_jvm::java::declarations::parse_tree(&source) else {
            diagnostics.push(diagnostic(
                CallRelationDiagnosticCode::ParseFailed,
                format!("cannot parse selected Java call source: {}", file),
                file.to_string(),
                "native_call_parse_failed",
            ));
            return Ok(IncomingFile::Rejected);
        };
        if !self
            .java
            .inner
            .source_matches_selected_native_content(file, &source)
        {
            diagnostics.push(diagnostic(
                CallRelationDiagnosticCode::AnalysisFailed,
                format!("selected Java call source changed: {}", file),
                file.to_string(),
                "native_call_source_stale",
            ));
            return Ok(IncomingFile::Rejected);
        }
        let facts = self
            .java
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file));
        if facts
            .as_ref()
            .is_some_and(|facts| facts.source() != source.as_str())
        {
            diagnostics.push(diagnostic(
                CallRelationDiagnosticCode::AnalysisFailed,
                format!("selected Java structural source changed: {}", file),
                file.to_string(),
                "native_call_source_stale",
            ));
            return Ok(IncomingFile::Rejected);
        }
        assert!(
            budget.admit_source(source.len()),
            "prechecked source fits the unchanged budget"
        );
        self.trees.insert(file.clone(), tree);
        Ok(IncomingFile::Loaded(facts))
    }

    fn accept_reference(&self, edge: &ReferenceEdgeRow, _syntax: &CallSiteSyntax) -> bool {
        is_java_invocation_reference(
            self.trees[&edge.site.file].root_node(),
            edge.site.range.start_byte,
            edge.site.range.end_byte,
        )
    }

    fn caller(&self, edge: &ReferenceEdgeRow, syntax: &CallSiteSyntax) -> Option<CodeUnit> {
        structural_incoming_caller(self.java.structural_fact_providers(), edge, syntax)
    }

    fn report_issue(&self, issue: IncomingProjectionIssue<'_>) -> CallRelationDiagnostic {
        match issue {
            IncomingProjectionIssue::FactsUnavailable(file) => diagnostic(
                CallRelationDiagnosticCode::AnalysisFailed,
                format!("Java structural call facts are unavailable: {file}"),
                file.to_string(),
                "native_call_facts_unavailable",
            ),
            IncomingProjectionIssue::OwnerUnavailable(edge) => diagnostic(
                CallRelationDiagnosticCode::AnalysisFailed,
                format!("selected Java call has no callable owner: {:?}", edge.site),
                edge.site.file.to_string(),
                "native_call_owner_unavailable",
            ),
        }
    }
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
