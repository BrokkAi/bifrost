//! Go call relations projected from selected inverse and forward operations.

use crate::analyzer::go::GoAnalyzer;

use crate::analyzer::go::selected_reverse::GoSelectedReverseOutcome;

use crate::analyzer::go::selected_reverse::go_selected_inverse_for;

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

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceEdgeRow;
use brokk_bifrost_analysis::analyzer::usages::native_incoming::{
    IncomingCallProjection, IncomingFile, IncomingFileBudget, IncomingProjectionIssue,
    finish_incoming_sites, project_selected_incoming, structural_incoming_caller,
};

/// Native Go call-relation projection used by Go production dispatch.
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
        if let Some(result) =
            native_incoming_preflight(target, limits, &cancellation, || CallRelationDiagnostic {
                code: CallRelationDiagnosticCode::BudgetExhausted,
                message: format!(
                    "native Go incoming-call budget omitted {}",
                    target.fq_name()
                ),
                context: target.fq_name().to_string(),
                reason_kind: None,
            })
        {
            return result;
        }
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return unavailable("native Go analyzer is unavailable", target);
        };
        let selected = match go_selected_inverse_for(go, target, &cancellation) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            GoSelectedReverseOutcome::Unavailable(reason)
            | GoSelectedReverseOutcome::TargetUncovered(reason) => {
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
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
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
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return unavailable("native Go analyzer is unavailable", caller);
        };
        crate::analyzer::go::native_outgoing::outgoing(
            go,
            caller,
            limits,
            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
            &cancellation,
        )
    }
}

/// Public test-support entry point for comparing the native adapter with the
/// incumbent Go call relation path.
#[cfg(any(test, feature = "test-support"))]
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

    let projected = project_selected_incoming(
        &mut GoIncomingProjection { go, target },
        target,
        selected.edges.iter().map(|edge| (edge, ())),
        limits,
        cancellation,
        &mut result,
    );
    if let Some(sites) = projected.unwrap_or_else(|never| match never {}) {
        finish_incoming_sites(sites, &mut result);
    }
    result
}

struct GoIncomingProjection<'a> {
    go: &'a GoAnalyzer,
    target: &'a CodeUnit,
}

impl IncomingCallProjection for GoIncomingProjection<'_> {
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
        let Some(source) = self.go.indexed_source(file) else {
            diagnostics.push(diagnostic(
                format!("selected Go call source is unavailable: {file}"),
                self.target.fq_name().to_string(),
                "native_call_source_unavailable",
            ));
            return Ok(IncomingFile::Rejected);
        };
        if !budget.source_fits(source.len()) {
            return Ok(IncomingFile::Rejected);
        }
        if !self
            .go
            .inner
            .source_matches_selected_native_content(file, &source)
        {
            diagnostics.push(diagnostic(
                format!("selected Go call source changed: {file}"),
                self.target.fq_name().to_string(),
                "native_call_source_stale",
            ));
            return Ok(IncomingFile::Rejected);
        }
        let facts = self
            .go
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file));
        if facts
            .as_ref()
            .is_some_and(|facts| facts.source() != source.as_str())
        {
            diagnostics.push(diagnostic(
                format!("selected Go structural source changed: {file}"),
                self.target.fq_name().to_string(),
                "native_call_source_stale",
            ));
            return Ok(IncomingFile::Rejected);
        }
        assert!(
            budget.admit_source(source.len()),
            "prechecked source fits the unchanged budget"
        );
        Ok(IncomingFile::Loaded(facts))
    }

    fn caller(&self, edge: &ReferenceEdgeRow, syntax: &CallSiteSyntax) -> Option<CodeUnit> {
        structural_incoming_caller(self.go.structural_fact_providers(), edge, syntax)
    }

    fn report_issue(&self, issue: IncomingProjectionIssue<'_>) -> CallRelationDiagnostic {
        match issue {
            IncomingProjectionIssue::FactsUnavailable(file) => diagnostic(
                format!("Go structural call facts are unavailable: {file}"),
                file.to_string(),
                "native_call_facts_unavailable",
            ),
            IncomingProjectionIssue::OwnerUnavailable(edge) => diagnostic(
                format!("selected Go call has no callable owner: {:?}", edge.site),
                edge.site.file.to_string(),
                "native_call_owner_unavailable",
            ),
        }
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
            message.into(),
            target.fq_name().to_string(),
            "native_call_unavailable",
        )],
        ..CallRelationResult::default()
    }
}

fn diagnostic(message: String, context: String, reason_kind: &str) -> CallRelationDiagnostic {
    CallRelationDiagnostic::analysis_failed(message, context, reason_kind.to_owned())
}
