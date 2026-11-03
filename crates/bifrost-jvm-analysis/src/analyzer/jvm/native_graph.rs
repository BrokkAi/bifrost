//! Trial-only JVM graph provider over the shared selected forward closer.
use crate::analyzer::{java::JavaAnalyzer, kotlin::KotlinAnalyzer, scala::ScalaAnalyzer};
use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::{
    EdgePassId, LanguageEdgeFailure, NativeWorkspaceGraphProvider,
};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::Result;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
use brokk_bifrost_analysis::analyzer::store_bridge::jvm_graph::JvmGraphStageExt;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome as Outcome;
use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;

pub(crate) fn native_jvm_graph_selected() -> bool {
    static SELECTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SELECTED.get_or_init(|| {
        std::env::var("BIFROST_TRIAL_NATIVE_JVM_GRAPH").is_ok_and(|value| value == "1")
    })
}
#[doc(hidden)]
pub struct JvmNativeWorkspaceGraphProvider;
pub(crate) static JVM_NATIVE_GRAPH: JvmNativeWorkspaceGraphProvider =
    JvmNativeWorkspaceGraphProvider;
impl NativeWorkspaceGraphProvider for JvmNativeWorkspaceGraphProvider {
    fn id(&self) -> EdgePassId {
        // All JVM hooks share this provider ID so mixed callers enter one
        // selected operation instead of three independent language passes.
        EdgePassId::Java
    }
    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<Outcome> {
        if let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) {
            build(analyzer, java.inner(), files, cancellation)
        } else if let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(analyzer) {
            build(analyzer, kotlin.tree_sitter_analyzer(), files, cancellation)
        } else if let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) {
            build(analyzer, scala.tree_sitter_analyzer(), files, cancellation)
        } else {
            Ok(Outcome::Unavailable(
                "selected JVM analyzer is unavailable".into(),
            ))
        }
    }
    fn input_failure(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        let missing = files
            .iter()
            .filter(|file| {
                matches!(
                    language_for_file(file),
                    Language::Java | Language::Kotlin | Language::Scala
                ) && !analyzer.is_analyzed(file)
            })
            .cloned()
            .collect::<Vec<_>>();
        (!missing.is_empty()).then_some(LanguageEdgeFailure {
            reason: "selected JVM source publication is unavailable",
            files: missing,
        })
    }
}
fn build<A: LanguageAdapter>(
    analyzer: &dyn IAnalyzer,
    inner: &TreeSitterAnalyzer<A>,
    files: &[ProjectFile],
    cancellation: &CancellationToken,
) -> Result<Outcome> {
    if cancellation.is_cancelled() {
        return Ok(Outcome::Cancelled);
    }
    let generation = analyzer.project().analysis_generation();
    let recipe = super::selected_operation::SelectedJvmRecipe::new(inner)?;
    let mut operation = match recipe.open(cancellation)? {
        super::selected_operation::SelectedJvmOperationOutcome::Ready(operation) => *operation,
        super::selected_operation::SelectedJvmOperationOutcome::Cancelled => {
            return Ok(Outcome::Cancelled);
        }
        super::selected_operation::SelectedJvmOperationOutcome::Stale(_) => {
            return Ok(Outcome::Stale);
        }
        super::selected_operation::SelectedJvmOperationOutcome::Unavailable(reason) => {
            return Ok(Outcome::Unavailable(format!("{reason:?}")));
        }
    };
    let admitted = HashSet::from_iter(files.iter().cloned());
    let projection = brokk_bifrost_analysis::analyzer::store_bridge::native_graph::project_native_workspace_graph(
        analyzer, &mut operation, &admitted, UsageEcosystem::Jvm, cancellation,
        |operation, builder| {
    operation.stage_jvm_graph_units(
        analyzer,
        files,
        brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
        inner.analyzer_config().parallelism(),
        cancellation,
        &mut SelectedResolutionContextMetrics,
        &mut |source, edges| {
            if !builder.stage_batch(
                analyzer,
                source,
                edges,
                edges.edges().iter().cloned(),
                cancellation,
            ) {
                return Ok(());
            }
            Ok(())
        },
    )
        },
    )?;
    brokk_bifrost_analysis::analyzer::root_presence::record_consumed_root_presence(
        analyzer, &operation,
    );
    if cancellation.is_cancelled() {
        return Ok(Outcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(Outcome::Stale);
    }
    Ok(projection)
}
