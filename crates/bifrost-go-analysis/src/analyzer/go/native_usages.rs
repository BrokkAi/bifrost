//! Native Go usage queries over selected inverse rows.
use std::ops::ControlFlow;

use brokk_bifrost_analysis::analyzer::usages::native_result::{
    NativeUsageDiagnostics, NativeUsageFile, NativeUsagePending, NativeUsageProjection,
    NativeUsageSite, project_pending_files, unique_targets,
};

use crate::analyzer::go::GoAnalyzer;

use crate::analyzer::go::selected_reverse::GoSelectedReverseOutcome;

use crate::analyzer::go::selected_reverse::go_selected_inverse_for_usage_scope;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::GoReverseConfirmationMemo;
use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageBatchQuery;

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

    /// Resolve independent targets with one request-local confirmation memo.
    ///
    /// Memo hits replay publications but not read-ledger keys. Policy units must
    /// not route through this batch API until hits also replay their read keys
    /// (#7262). Dead-code reports are neither persisted nor policy units.
    fn find_graph_usages_batch(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
    ) -> Vec<GraphUsageOutcome> {
        self.find_graph_usages_batch_with_memo(
            analyzer,
            queries,
            max_usages,
            &mut GoReverseConfirmationMemo::default(),
        )
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        self.find_graph_usages_with_memo(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            &mut GoReverseConfirmationMemo::default(),
        )
    }
}

impl GoNativeUsageStrategy {
    /// Resolve independent targets, exposing their request-local memo to callers
    /// that need to observe confirmation reuse.
    ///
    /// Memo hits replay publications but not read-ledger keys. Policy units must
    /// not route through this batch API until hits also replay their read keys
    /// (#7262). Dead-code reports are neither persisted nor policy units.
    #[doc(hidden)]
    pub fn find_graph_usages_batch_with_memo(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
        memo: &mut GoReverseConfirmationMemo,
    ) -> Vec<GraphUsageOutcome> {
        queries
            .iter()
            .map(|query| match query.prepared {
                Some(prepared) => {
                    prepared.find_graph_usages(analyzer, query.overloads, &query.scope, max_usages)
                }
                None => self.find_graph_usages_with_memo(
                    analyzer,
                    query.overloads,
                    &query.scope,
                    max_usages,
                    memo,
                ),
            })
            .collect()
    }

    fn find_graph_usages_with_memo(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
        memo: &mut GoReverseConfirmationMemo,
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
            let answer = match go_selected_inverse_for_usage_scope(
                go,
                target,
                scan_scope,
                &cancellation,
                memo,
            ) {
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

#[cfg(test)]
mod migrated_usage_regressions {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::usages::traits::UsageAnalyzer;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;
    #[test]
    #[hardwon(
        "0dec6bce300f: dot imports and aliases must preserve method-use sites for typed variable receivers"
    )]
    fn native_typed_dot_imported_and_aliased_var_receivers_find_method_sites() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/app\n\ngo 1.24\n")
            .file(
                "types/types.go",
                "package types\ntype T struct{}\ntype A = T\nfunc (T) Method() {}\n",
            )
            .file(
                "main.go",
                r#"package main

import . "example.com/app/types"

func useDotImportedType() {
    var x T
    x.Method()
}

func useDotImportedAlias() {
    var x A
    x.Method()
}
"#,
            )
            .build();
        let (analyzer, _store) =
            crate::test_support::go_discovery_analyzer(project.project_dyn(), Default::default());
        let declarations = analyzer.get_all_declarations();
        let target = declarations
            .iter()
            .find(|unit| unit.fq_name() == "example.com/app/types.T.Method")
            .cloned()
            .expect("method declaration");

        let candidates = analyzer.get_analyzed_files().into_iter().collect();
        let forward = crate::analyzer::GoNativeUsageStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &candidates,
            1000,
        );
        let forward_lines: BTreeSet<_> = match forward {
            FuzzyResult::Success {
                hits_by_overload, ..
            } => hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| hit.line)
                .collect(),
            result => panic!("forward Go scan should succeed: {result:?}"),
        };

        assert_eq!(BTreeSet::from([7, 12]), forward_lines);
    }
}
