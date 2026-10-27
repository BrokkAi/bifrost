//! Native Go usage queries over selected inverse rows.
use std::ops::ControlFlow;

use brokk_bifrost_analysis::analyzer::usages::native_result::{
    NativeUsageDiagnostics, NativeUsageFile, NativeUsagePending, NativeUsageProjection,
    NativeUsageSite, project_pending_files, unique_targets,
};

use crate::analyzer::go::GoAnalyzer;

use crate::analyzer::go::selected_reverse::GoSelectedReverseOutcome;

use crate::analyzer::go::selected_reverse::go_selected_inverse_for_usage_scope;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_core::analyzer::usages::outcome::GraphFailureReason;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

use brokk_bifrost_core::analyzer::usages::model::UsageAnalysisDiagnostic;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

/// Native Go forward-usage discovery through the selected reference index.
#[derive(Default)]
pub struct GoNativeUsageStrategy;

impl GoNativeUsageStrategy {
    pub const fn new() -> Self {
        Self
    }
}

impl GraphUsageAnalyzer for GoNativeUsageStrategy {
    fn proof_authority(&self) -> brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority {
        brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority::Native
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(primary) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return DIAGNOSTICS.failure(
                primary,
                "native_resolution_unavailable",
                "selected Go analyzer is unavailable".into(),
            );
        };
        let cancellation = scan_scope.cancellation().cloned().unwrap_or_default();
        let targets = unique_targets(overloads);
        let mut pending = NativeUsagePending::new(&targets);
        let mut projection = GoUsageProjection { go, primary };
        for (target_index, target) in targets.iter().enumerate() {
            if cancellation.is_cancelled() {
                return DIAGNOSTICS.cancelled(primary);
            }
            let answer =
                match go_selected_inverse_for_usage_scope(go, target, scan_scope, &cancellation) {
                    GoSelectedReverseOutcome::Ready(answer) => answer,
                    GoSelectedReverseOutcome::Unavailable(reason)
                    | GoSelectedReverseOutcome::TargetUncovered(reason) => {
                        let mut unavailable = GraphFailureReason::UnavailableCanonicalFacts(
                            "Go graph indexed source was unavailable",
                        )
                        .diagnostic(primary.fq_name(), "go_native");
                        unavailable.reason = format!("{}; {reason}", unavailable.reason);
                        return GraphUsageOutcome::TerminalFailure(unavailable);
                    }
                    GoSelectedReverseOutcome::Stale(reason) => {
                        return DIAGNOSTICS.failure(primary, "stale_selected_source", reason);
                    }
                    GoSelectedReverseOutcome::Cancelled => return DIAGNOSTICS.cancelled(primary),
                    GoSelectedReverseOutcome::StoreError(reason) => {
                        return DIAGNOSTICS.failure(primary, "native_store_error", reason);
                    }
                };
            if let EdgeCompleteness::Incomplete { reasons } = &answer.completeness {
                pending.diagnostics.push(DIAGNOSTICS.diagnostic(
                    target,
                    "native_reference_inventory_incomplete",
                    format!("selected Go reference inventory is incomplete: {reasons:?}"),
                ));
            }
            let edges = answer.edges;
            if let ControlFlow::Break(()) = pending.queue_target_edges::<GoUsageProjection<'_>>(
                target_index,
                edges,
                scan_scope,
                &cancellation,
            ) {
                return DIAGNOSTICS.cancelled(primary);
            }
        }
        match project_pending_files(
            &mut projection,
            pending,
            scan_scope,
            max_usages,
            &cancellation,
        ) {
            Ok(Some(result)) => GraphUsageOutcome::Resolved(result),
            Ok(None) => DIAGNOSTICS.cancelled(primary),
            Err(diagnostic) => GraphUsageOutcome::TerminalFailure(diagnostic),
        }
    }
}

const DIAGNOSTICS: NativeUsageDiagnostics = NativeUsageDiagnostics {
    strategy: "go_native",
    cancelled_reason: "native Go usage query was cancelled",
};

struct GoUsageProjection<'a> {
    go: &'a GoAnalyzer,
    primary: &'a CodeUnit,
}

impl NativeUsageProjection for GoUsageProjection<'_> {
    type Context = ();
    type Error = UsageAnalysisDiagnostic;

    fn load_file(
        &mut self,
        file: &ProjectFile,
        _pending: &[NativeUsageSite],
    ) -> Result<NativeUsageFile<Self::Context>, Self::Error> {
        let source = self.go.indexed_source(file).ok_or_else(|| {
            DIAGNOSTICS.diagnostic(
                self.primary,
                "native_source_unavailable",
                format!("selected Go usage source is unavailable: {file}"),
            )
        })?;
        if !self
            .go
            .inner
            .source_matches_selected_native_content(file, &source)
        {
            return Err(DIAGNOSTICS.diagnostic(
                self.primary,
                "stale_selected_source",
                format!("selected Go usage source changed: {file}"),
            ));
        }
        Ok(NativeUsageFile::new(source, ()))
    }
}
