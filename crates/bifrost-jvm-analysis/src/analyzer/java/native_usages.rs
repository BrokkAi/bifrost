//! Test-support native JVM forward usage over selected inverse references.

use brokk_bifrost_analysis::analyzer::usages::native_result::{
    NativeUsageAdmission, NativeUsageDiagnostics, NativeUsageFile, NativeUsagePending,
    NativeUsageProjection, NativeUsageSite, project_pending_files, unique_targets,
};

use std::ops::ControlFlow;

use crate::analyzer::java::JavaAnalyzer;

use crate::analyzer::java::selected_reverse::{JavaSelectedReverseOutcome, jvm_target_analyzer};

use crate::analyzer::java::selected_reverse::java_selected_inverse_detailed_for;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::selected_reverse_reference_file;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

use brokk_bifrost_core::analyzer::usages::model::UsageAnalysisDiagnostic;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use brokk_bifrost_core::hash::HashSet;

/// Native JVM forward-usage discovery. This remains test-support only until
/// the JVM consumer cutover is approved.
#[derive(Default)]
pub struct JavaNativeUsageStrategy;

impl JavaNativeUsageStrategy {
    pub const fn new() -> Self {
        Self
    }
}

impl GraphUsageAnalyzer for JavaNativeUsageStrategy {
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
        let Some(java) = jvm_target_analyzer(analyzer, primary) else {
            return DIAGNOSTICS.failure(
                primary,
                "native_resolution_unavailable",
                "selected Java analyzer is unavailable".into(),
            );
        };
        let cancellation = scan_scope.cancellation().cloned().unwrap_or_default();
        let targets = unique_targets(overloads);
        let mut pending = NativeUsagePending::new(&targets);
        let constructor_targets = overloads
            .iter()
            .filter(|target| {
                resolve_analyzer::<JavaAnalyzer>(java).is_some_and(|java| {
                    java.signature_metadata(target)
                        .iter()
                        .any(|metadata| metadata.callable_is_constructor())
                })
            })
            .cloned()
            .collect::<HashSet<_>>();
        let mut projection = JavaUsageProjection {
            analyzer,
            java,
            constructor_targets: &constructor_targets,
            primary,
        };
        for (target_index, target) in targets.iter().enumerate() {
            if cancellation.is_cancelled() {
                return DIAGNOSTICS.cancelled(primary);
            }
            let answer =
                match java_selected_inverse_detailed_for(analyzer, java, target, &cancellation) {
                    JavaSelectedReverseOutcome::Ready(answer) => answer,
                    JavaSelectedReverseOutcome::Unavailable(reason)
                    | JavaSelectedReverseOutcome::TargetUncovered(reason) => {
                        return DIAGNOSTICS.failure(
                            primary,
                            "native_resolution_unavailable",
                            reason,
                        );
                    }
                    JavaSelectedReverseOutcome::Stale(reason) => {
                        return DIAGNOSTICS.failure(primary, "stale_selected_source", reason);
                    }
                    JavaSelectedReverseOutcome::Cancelled => return DIAGNOSTICS.cancelled(primary),
                    JavaSelectedReverseOutcome::StoreError(reason) => {
                        return DIAGNOSTICS.failure(primary, "native_store_error", reason);
                    }
                };
            if let EdgeCompleteness::Incomplete { reasons } = &answer.edges.completeness {
                pending.diagnostics.push(DIAGNOSTICS.diagnostic(
                    target,
                    "native_reference_inventory_incomplete",
                    format!(
                        "selected {} reference inventory is incomplete: {reasons:?}",
                        if brokk_bifrost_core::analyzer::common::language_for_target(target)
                            == brokk_bifrost_core::analyzer::model::Language::Java
                        {
                            "Java"
                        } else {
                            "JVM"
                        }
                    ),
                ));
            }
            if answer.peer_language_inventory_open {
                let (kind, reason) = if brokk_bifrost_core::analyzer::common::language_for_target(
                    target,
                ) == brokk_bifrost_core::analyzer::model::Language::Java
                {
                    (
                        "native_java_peer_languages_omitted",
                        "native Java inverse references cover Java files only; selected Kotlin or Scala source can name this Java target",
                    )
                } else {
                    (
                        "native_jvm_peer_languages_open",
                        "selected peer JVM source can name this target; peer-language absence remains open",
                    )
                };
                pending
                    .diagnostics
                    .push(DIAGNOSTICS.diagnostic(target, kind, reason.into()));
            }
            let edges = answer.edges.edges;
            if let ControlFlow::Break(()) = pending.queue_target_edges::<JavaUsageProjection<'_>>(
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
    strategy: "java_native",
    cancelled_reason: "native Java usage query was cancelled",
};

struct JavaUsageProjection<'a> {
    analyzer: &'a dyn IAnalyzer,
    java: &'a dyn IAnalyzer,
    constructor_targets: &'a HashSet<CodeUnit>,
    primary: &'a CodeUnit,
}

impl<'a> NativeUsageProjection for JavaUsageProjection<'a> {
    type Context = Option<
        brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceSiteClassifier<'a>,
    >;
    type Error = UsageAnalysisDiagnostic;

    fn load_file(
        &mut self,
        file: &ProjectFile,
        _pending: &[NativeUsageSite],
    ) -> Result<NativeUsageFile<Self::Context>, Self::Error> {
        let projection =
            selected_reverse_reference_file(self.analyzer, self.java, file).map_err(|error| {
                DIAGNOSTICS.diagnostic(self.primary, "stale_selected_source", error.to_string())
            })?;
        Ok(NativeUsageFile {
            source: projection.source,
            line_starts: projection.state.line_starts,
            context: projection.state.classifier,
        })
    }

    fn presentation(
        &mut self,
        _file: &ProjectFile,
        loaded: &NativeUsageFile<Self::Context>,
        target: &CodeUnit,
        site: &mut NativeUsageSite,
    ) -> Result<NativeUsageAdmission, Self::Error> {
        if self.constructor_targets.contains(target)
            && let Some(range) = loaded.context.as_ref().and_then(|classifier| {
                classifier
                    .call_range_containing_reference(site.hit.start_offset, site.hit.end_offset)
            })
        {
            site.hit.line = range.start_line;
            site.hit.start_offset = range.start_byte;
            site.hit.end_offset = range.end_byte;
        }
        Ok(NativeUsageAdmission::Retain)
    }
}
