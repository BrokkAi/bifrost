//! Test-support Go incoming-call projection from selected inverse evidence.
//!
//! Go call relations remain on the incumbent production route until the Go
//! consumer flip. This adapter projects only selected inverse rows and never
//! discovers callees independently.

use super::GoAnalyzer;
use super::selected_reverse::{GoSelectedReverseOutcome, go_selected_inverse_for};
use crate::CancellationToken;
use crate::analyzer::structural::FileFacts;
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, EdgeDerivationResult};
use crate::analyzer::usages::UsageProofAuthority;
use crate::analyzer::usages::call_relations::{
    CallArgument, CallRelationDiagnostic, CallRelationDiagnosticCode, CallRelationLimits,
    CallRelationProvider, CallRelationResult, CallSite, is_call_relation_unit,
};
use crate::analyzer::usages::get_definition::{
    CallSiteSyntax, CallSyntaxKind, call_site_syntax_for_reference,
};
use crate::analyzer::{CodeUnit, CodeUnitIndex, IAnalyzer, ProjectFile, resolve_analyzer};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

/// Native Go call-relation projection. Kept out of Go production dispatch.
pub struct GoNativeCallRelations;

impl CallRelationProvider for GoNativeCallRelations {
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
                        "native Go incoming-call budget omitted {}",
                        target.fq_name()
                    ),
                    target.fq_name().to_string(),
                    "native_call_budget_exhausted",
                )],
                ..CallRelationResult::default()
            };
        }
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return unavailable("native Go analyzer is unavailable", target);
        };
        let selected = match go_selected_inverse_for(go, target, &cancellation) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            GoSelectedReverseOutcome::Unavailable(reason) => {
                return unavailable(
                    format!("selected Go inverse is unavailable: {reason}"),
                    target,
                );
            }
            GoSelectedReverseOutcome::Stale(reason) => {
                return unavailable(format!("selected Go inverse is stale: {reason}"), target);
            }
            GoSelectedReverseOutcome::Cancelled => {
                return CallRelationResult {
                    cancelled: true,
                    proof_authority: UsageProofAuthority::Native,
                    ..CallRelationResult::default()
                };
            }
            GoSelectedReverseOutcome::StoreError(reason) => {
                return unavailable(format!("selected Go inverse failed: {reason}"), target);
            }
        };
        project_incoming_calls(go, target, selected, limits, &cancellation)
    }

    fn outgoing(
        &self,
        _analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        _limits: CallRelationLimits,
        _cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        unavailable(
            "native Go outgoing calls are not part of this slice",
            caller,
        )
    }
}

/// Public test-support entry point for comparing the native adapter with the
/// incumbent Go call relation path.
pub fn go_native_incoming_calls(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    limits: CallRelationLimits,
    cancellation: Option<&CancellationToken>,
) -> CallRelationResult {
    GoNativeCallRelations.incoming(analyzer, target, limits, cancellation)
}

fn project_incoming_calls(
    go: &GoAnalyzer,
    target: &CodeUnit,
    mut selected: EdgeDerivationResult,
    limits: CallRelationLimits,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    let mut result = CallRelationResult {
        proof_authority: UsageProofAuthority::Native,
        diagnostics: incomplete_diagnostics(&selected, target),
        ..CallRelationResult::default()
    };
    selected.edges.sort_by(|left, right| {
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

    let mut files = HashMap::<ProjectFile, (String, Option<Arc<FileFacts>>)>::default();
    let mut rejected_files = HashSet::default();
    let mut source_bytes = 0usize;
    for edge in selected.edges {
        if cancellation.is_cancelled() {
            result.sites.clear();
            result.cancelled = true;
            return result;
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
            let Some(source) = go.indexed_source(&edge.site.file) else {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!("selected Go call source is unavailable: {}", edge.site.file),
                    target.fq_name().to_string(),
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
            if !go
                .inner
                .source_matches_selected_native_content(&edge.site.file, &source)
            {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!("selected Go call source changed: {}", edge.site.file),
                    target.fq_name().to_string(),
                    "native_call_source_stale",
                ));
                rejected_files.insert(edge.site.file.clone());
                continue;
            }
            let facts = go
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(&edge.site.file));
            if facts
                .as_ref()
                .is_some_and(|facts| facts.source() != source.as_str())
            {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!("selected Go structural source changed: {}", edge.site.file),
                    target.fq_name().to_string(),
                    "native_call_source_stale",
                ));
                rejected_files.insert(edge.site.file.clone());
                continue;
            }
            source_bytes += source.len();
            result.work.scanned_files += 1;
            result.work.scanned_source_bytes += source.len();
            files.insert(edge.site.file.clone(), (source, facts));
        }
        let Some((_, Some(facts))) = files.get(&edge.site.file) else {
            if !result.diagnostics.iter().any(|diagnostic| {
                diagnostic.context == edge.site.file.to_string()
                    && diagnostic.reason_kind.as_deref() == Some("native_call_facts_unavailable")
            }) {
                result.diagnostics.push(diagnostic(
                    CallRelationDiagnosticCode::AnalysisFailed,
                    format!(
                        "Go structural call facts are unavailable: {}",
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
        if result.work.examined_candidates >= limits.max_candidates {
            result.truncated = true;
            continue;
        }
        result.work.examined_candidates += 1;
        let caller = go
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
                format!("selected Go call has no callable owner: {:?}", edge.site),
                edge.site.file.to_string(),
                "native_call_owner_unavailable",
            ));
            continue;
        };
        result.sites.push(make_call_site(
            edge.site.file,
            caller,
            target,
            syntax,
            edge.proof,
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

fn make_call_site(
    file: ProjectFile,
    caller: CodeUnit,
    target: &CodeUnit,
    syntax: CallSiteSyntax,
    proof: crate::analyzer::usages::UsageProof,
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
        kind: if target.is_class() || target.kind().display_lowercase() == "constructor" {
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
                    "selected Go incoming-call inventory is incomplete for {}: {reason:?}",
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
    message: String,
    context: String,
    reason_kind: &str,
) -> CallRelationDiagnostic {
    CallRelationDiagnostic {
        code,
        message,
        context,
        reason_kind: Some(reason_kind.to_owned()),
    }
}
