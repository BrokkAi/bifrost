//! Native Python usage discovery through the selected reverse operation.
//!
//! Preparation returns every nominated site's file, independent of proof tier.
//! M1 then applies its file/source budgets; truncation is explicit in
//! UsageQueryCompletion and CandidateFilesSample::omitted_count. Execution uses
//! the owned prepared result once, without another reverse confirmation.

use super::selected_reverse::project_reverse;
use super::{
    PythonAnalyzer,
    native_request::{PythonNativeOpen, PythonNativeRequest, open_python_native_request},
};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::python_reverse::{
    PythonNativeReverseResult, PythonReverseLimits,
};
use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;
use brokk_bifrost_analysis::analyzer::usages::native_result::{
    NativeUsageDiagnostics, NativeUsageFile, NativeUsagePending, NativeUsageProjection,
    NativeUsageSite, project_pending_files, unique_targets,
};
use brokk_bifrost_analysis::analyzer::usages::traits::{
    GraphUsageAnalyzer, GraphUsageBatchQuery, PreparedUsageQuery,
};
use brokk_bifrost_analysis::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::usages::model::{
    FuzzyResult, UsageAnalysisDiagnostic, UsageProofAuthority,
};
use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;
use std::sync::Mutex;

const DIAGNOSTICS: NativeUsageDiagnostics = NativeUsageDiagnostics {
    strategy: "python_native",
    cancelled_reason: "native Python usage query was cancelled",
};

pub(super) struct PythonNativeUsageStrategy;
impl GraphUsageAnalyzer for PythonNativeUsageStrategy {
    fn proof_authority(&self) -> UsageProofAuthority {
        UsageProofAuthority::Native
    }
    fn prepare_target_usage_query(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        cancellation: &CancellationToken,
    ) -> Option<Box<dyn PreparedUsageQuery>> {
        let primary = overloads.first()?;
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
        let generation = python.inner.project().analysis_generation();
        let targets = unique_targets(overloads);
        let (result, reads) =
            brokk_bifrost_analysis::analyzer::capture_query_reads(analyzer, || {
                match open_python_native_request(python, cancellation) {
                    Ok(PythonNativeOpen::Ready(request)) => {
                        let files = python.analyzed_files().into_iter().collect();
                        let scope = UsageScanScope::with_cancellation(&files, cancellation);
                        let session = ResolutionSession::bounded(
                            ReceiverAnalysisBudget::default(),
                            Some(cancellation),
                        );
                        request
                            .operation
                            .python_reverse_targets(
                                &request.environment,
                                &targets,
                                &scope,
                                PythonReverseLimits::default(),
                                &session,
                            )
                            .map_err(|error| {
                                Box::new(DIAGNOSTICS.failure(
                                    primary,
                                    "native_store_error",
                                    error.to_string(),
                                ))
                            })
                    }
                    Ok(PythonNativeOpen::Cancelled) => {
                        Err(Box::new(DIAGNOSTICS.cancelled(primary)))
                    }
                    Ok(PythonNativeOpen::Unavailable { kind, message }) => {
                        Err(Box::new(DIAGNOSTICS.failure(primary, kind, message)))
                    }
                    Err(error) => Err(Box::new(DIAGNOSTICS.failure(
                        primary,
                        "native_store_error",
                        error.to_string(),
                    ))),
                }
            });
        let files = result
            .as_ref()
            .ok()
            .into_iter()
            .flat_map(|result| {
                result.nominated_paths.iter().map(String::as_str).chain(
                    result
                        .targets
                        .iter()
                        .flat_map(|target| &target.sites)
                        .map(|site| site.path.as_str()),
                )
            })
            .map(|path| ProjectFile::new(python.inner.project().root(), path))
            .collect();
        Some(Box::new(PreparedPythonUsageQuery {
            generation,
            targets,
            files,
            result: Mutex::new(Some(result)),
            reads,
        }))
    }

    fn prepare_usage_query(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        _candidate_files: &HashSet<ProjectFile>,
        cancellation: &CancellationToken,
    ) -> Option<Box<dyn PreparedUsageQuery>> {
        self.prepare_target_usage_query(analyzer, overloads, cancellation)
    }

    fn find_graph_usages_batch(
        &self,
        analyzer: &dyn IAnalyzer,
        queries: &[GraphUsageBatchQuery<'_>],
        max_usages: usize,
    ) -> Vec<GraphUsageOutcome> {
        let Some(first) = queries.iter().find(|query| query.prepared.is_none()) else {
            return queries
                .iter()
                .map(|query| {
                    query
                        .prepared
                        .expect("every query was prepared")
                        .find_graph_usages(analyzer, query.overloads, &query.scope, max_usages)
                })
                .collect();
        };
        let failures = |kind: &str, reason: String| {
            queries
                .iter()
                .map(|query| match query.prepared {
                    Some(prepared) => prepared.find_graph_usages(
                        analyzer,
                        query.overloads,
                        &query.scope,
                        max_usages,
                    ),
                    None => match query.overloads.first() {
                        Some(primary) => DIAGNOSTICS.failure(primary, kind, reason.clone()),
                        None => GraphUsageOutcome::Resolved(FuzzyResult::empty_success()),
                    },
                })
                .collect()
        };
        let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
            return failures(
                "native_unavailable",
                "selected Python analyzer unavailable".into(),
            );
        };
        let cancellation = first.scope.cancellation().cloned().unwrap_or_default();
        let request = match open_python_native_request(python, &cancellation) {
            Ok(PythonNativeOpen::Ready(request)) => request,
            Ok(PythonNativeOpen::Cancelled) => {
                return failures("cancelled", DIAGNOSTICS.cancelled_reason.into());
            }
            Ok(PythonNativeOpen::Unavailable { kind, message }) => return failures(kind, message),
            Err(error) => return failures("native_store_error", error.to_string()),
        };
        queries
            .iter()
            .map(|query| match query.prepared {
                Some(prepared) => {
                    prepared.find_graph_usages(analyzer, query.overloads, &query.scope, max_usages)
                }
                None => find_usages_in_request(
                    python,
                    &request,
                    query.overloads,
                    &query.scope,
                    max_usages,
                ),
            })
            .collect()
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(primary) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
            return DIAGNOSTICS.failure(
                primary,
                "native_unavailable",
                "selected Python analyzer unavailable".into(),
            );
        };
        let cancellation = scope.cancellation().cloned().unwrap_or_default();
        let request = match open_python_native_request(python, &cancellation) {
            Ok(PythonNativeOpen::Ready(request)) => request,
            Ok(PythonNativeOpen::Cancelled) => return DIAGNOSTICS.cancelled(primary),
            Ok(PythonNativeOpen::Unavailable { kind, message }) => {
                return DIAGNOSTICS.failure(primary, kind, message);
            }
            Err(error) => {
                return DIAGNOSTICS.failure(primary, "native_store_error", error.to_string());
            }
        };
        find_usages_in_request(python, &request, overloads, scope, max_usages)
    }
}

struct PreparedPythonUsageQuery {
    generation: u64,
    targets: Vec<CodeUnit>,
    files: HashSet<ProjectFile>,
    /// The failed outcome is boxed: it is far larger than the success value.
    result: Mutex<Option<Result<PythonNativeReverseResult, Box<GraphUsageOutcome>>>>,
    reads: std::sync::Arc<brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger>,
}

impl PreparedUsageQuery for PreparedPythonUsageQuery {
    fn candidate_files(&self) -> &HashSet<ProjectFile> {
        &self.files
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer)
            .expect("prepared Python query retains its analyzer");
        assert_eq!(
            unique_targets(overloads),
            self.targets,
            "the find phase answers the overloads the prepare phase enumerated"
        );
        assert_eq!(
            python.inner.project().analysis_generation(),
            self.generation,
            "the selected Python generation changed between prepare and find"
        );
        debug_assert_eq!(
            self.reads.digest(),
            brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest(&self.reads.keys())
        );
        brokk_bifrost_analysis::analyzer::i_analyzer::replay_query_reads(analyzer, &self.reads);
        let result = self
            .result
            .lock()
            .expect("prepared Python result lock poisoned")
            .take()
            .expect("a prepared Python reverse result is consumed once");
        match result {
            Ok(result) => {
                project_usage_result(python, overloads, &self.targets, result, scope, max_usages)
            }
            Err(outcome) => *outcome,
        }
    }
}

fn find_usages_in_request(
    python: &PythonAnalyzer,
    request: &PythonNativeRequest<'_>,
    overloads: &[CodeUnit],
    scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> GraphUsageOutcome {
    let Some(primary) = overloads.first() else {
        return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
    };
    let cancellation = scope.cancellation().cloned().unwrap_or_default();
    let targets = unique_targets(overloads);
    let session =
        ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
    let result = match request.operation.python_reverse_targets(
        &request.environment,
        &targets,
        scope,
        PythonReverseLimits::default(),
        &session,
    ) {
        Ok(result) => result,
        Err(error) => {
            return DIAGNOSTICS.failure(primary, "native_store_error", error.to_string());
        }
    };
    project_usage_result(python, overloads, &targets, result, scope, max_usages)
}

fn project_usage_result(
    python: &PythonAnalyzer,
    overloads: &[CodeUnit],
    targets: &[CodeUnit],
    result: PythonNativeReverseResult,
    scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> GraphUsageOutcome {
    let primary = overloads.first().expect("reverse projection has a target");
    let cancellation = scope.cancellation().cloned().unwrap_or_default();
    if cancellation.is_cancelled() {
        return DIAGNOSTICS.cancelled(primary);
    }
    let projected = match project_reverse(python, result) {
        Ok(answers) => answers,
        Err(error) => {
            return DIAGNOSTICS.failure(primary, "native_store_error", error.to_string());
        }
    };
    let mut pending = NativeUsagePending::new(targets);
    for kind in [
        "python_environment_open",
        "python_unknown_placement",
        "python_dynamic_receiver_mutation_open",
    ] {
        let obligations = projected
            .query_obligations
            .iter()
            .filter(|label| label.starts_with(kind))
            .collect::<Vec<_>>();
        if !obligations.is_empty() {
            pending.diagnostics.push(DIAGNOSTICS.diagnostic(
                primary,
                kind,
                format!("{obligations:?}"),
            ));
        }
    }
    for (target, answer) in projected.targets {
        let index = targets
            .iter()
            .position(|candidate| candidate == &target)
            .expect("reverse result target belongs to request");
        if let EdgeCompleteness::Incomplete { reasons } = answer.completeness {
            pending.diagnostics.push(DIAGNOSTICS.diagnostic(
                &target,
                "native_reference_inventory_incomplete",
                format!("{reasons:?}"),
            ));
        }
        if pending
            .queue_target_edges::<PythonUsageProjection<'_>>(
                index,
                answer.edges,
                scope,
                &cancellation,
            )
            .is_break()
        {
            return DIAGNOSTICS.cancelled(primary);
        }
    }
    match project_pending_files(
        &mut PythonUsageProjection { python, primary },
        pending,
        scope,
        max_usages,
        &cancellation,
    ) {
        Ok(Some(result)) => GraphUsageOutcome::Resolved(result),
        Ok(None) => DIAGNOSTICS.cancelled(primary),
        Err(diagnostic) => GraphUsageOutcome::TerminalFailure(diagnostic),
    }
}

struct PythonUsageProjection<'a> {
    python: &'a PythonAnalyzer,
    primary: &'a CodeUnit,
}
impl NativeUsageProjection for PythonUsageProjection<'_> {
    type Context = ();
    type Error = UsageAnalysisDiagnostic;
    fn load_file(
        &mut self,
        file: &ProjectFile,
        _pending: &[NativeUsageSite],
    ) -> Result<NativeUsageFile<()>, Self::Error> {
        let source = self.python.indexed_source(file).ok_or_else(|| {
            DIAGNOSTICS.diagnostic(
                self.primary,
                "native_source_unavailable",
                format!("selected Python source unavailable: {file}"),
            )
        })?;
        if !self
            .python
            .inner
            .source_matches_selected_native_content(file, &source)
        {
            return Err(DIAGNOSTICS.diagnostic(
                self.primary,
                "stale_selected_source",
                format!("selected Python source changed: {file}"),
            ));
        }
        Ok(NativeUsageFile::new(source, ()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::usages::UsageFinder;
    use brokk_bifrost_analysis::analyzer::usages::finder::UsageQueryCompletion;
    use brokk_bifrost_analysis::analyzer::{Language, WorkspaceAnalyzer};
    use brokk_bifrost_core::cache_db::sql_profile;

    #[test]
    fn prepared_reverse_is_consumed_once_and_file_truncation_is_explicit() {
        if !super::super::trial_native_python_selected() {
            return;
        }
        let fixture = InlineTestProject::with_language(Language::Python)
            .file("model.py", "def pick(): pass\n")
            .file("a.py", "from model import pick\nx = pick()\n")
            .file("b.py", "from model import pick\ny = pick()\n")
            .build();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), Default::default())
                .unwrap();
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
        let target = python
            .top_level_declarations(&ProjectFile::new(fixture.root(), "model.py"))
            .into_iter()
            .find(|target| target.identifier() == "pick")
            .unwrap();
        let targets = [target];
        let cancellation = CancellationToken::new();
        let prepared = {
            let _profile = sql_profile::request_scope("python_reverse_prepare_once");
            PythonNativeUsageStrategy
                .prepare_usage_query(python, &targets, &HashSet::default(), &cancellation)
                .unwrap()
        };
        let files = prepared.candidate_files().clone();
        assert!(files.contains(&ProjectFile::new(fixture.root(), "a.py")));
        assert!(files.contains(&ProjectFile::new(fixture.root(), "b.py")));
        let outcome = {
            let _profile = sql_profile::request_scope("python_reverse_execute_prepared");
            prepared.find_graph_usages(
                python,
                &targets,
                &UsageScanScope::with_cancellation(&files, &cancellation),
                100,
            )
        };
        let GraphUsageOutcome::Resolved(FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            diagnostics,
            ..
        }) = outcome
        else {
            panic!("prepared sites must run and retain query obligations: {outcome:?}");
        };
        assert!(
            hits_by_overload
                .values()
                .map(|hits| hits.len())
                .sum::<usize>()
                + unproven_by_overload
                    .values()
                    .map(|hits| hits.len())
                    .sum::<usize>()
                >= 2
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.reason_kind == "python_environment_open")
                .count(),
            1
        );
        let query = {
            let _profile = sql_profile::request_scope("python_reverse_file_budget");
            UsageFinder::new().query(python, &targets, 1, 100)
        };
        assert_eq!(
            query.completion,
            UsageQueryCompletion::CandidateFilesBudgetExhausted
        );
        assert!(query.candidate_files_truncated);
        assert_eq!(query.candidate_files.len(), 1);
        let sample = query.candidate_files_sample.unwrap();
        assert!(sample.omitted_count > 0);
        assert_eq!(sample.omitted_count, sample.omitted.len());
    }
}
