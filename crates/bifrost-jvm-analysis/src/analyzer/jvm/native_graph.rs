//! Trial-only JVM graph provider over the shared selected forward closer.
use crate::analyzer::{java::JavaAnalyzer, kotlin::KotlinAnalyzer, scala::ScalaAnalyzer};
use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::{
    EdgePassId, LanguageEdgeFailure, NativeWorkspaceGraphProvider,
};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::Result;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use brokk_bifrost_analysis::analyzer::store_bridge::jvm_graph::JvmGraphStageExt;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::{
    NativeWorkspaceGraphBuilder, SelectedWorkspaceUsageGraphProjectionOutcome as Outcome,
};
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
    let selected = ["java", "kotlin", "scala"].map(str::to_owned);
    let snapshots = inner
        .analyzer_store()
        .workspace_snapshots_for_current_languages(inner.workspace_id(), &selected)?;
    let (masks, content_mounts) =
        match inner.selected_resolution_overlay_inputs(&snapshots, cancellation)? {
            SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            } => (masks, content_mounts),
            SelectedResolutionOverlayInputsOutcome::Cancelled => return Ok(Outcome::Cancelled),
            SelectedResolutionOverlayInputsOutcome::Stale(_) => return Ok(Outcome::Stale),
            SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                return Ok(Outcome::Unavailable(format!("{reason:?}")));
            }
        };
    let languages = [
        ("java", Language::Java),
        ("kotlin", Language::Kotlin),
        ("scala", Language::Scala),
    ]
    .into_iter()
    .filter(|(storage, _)| snapshots.contains_key(*storage))
    .map(|(storage, language)| SelectedResolutionLanguage::new(storage, language))
    .collect::<Vec<_>>();
    let input = SelectedResolutionOperationInput::new(
        inner.project(),
        inner.workspace_id(),
        &snapshots,
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let mut operation = match inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        SelectedResolutionOperationOpenOutcome::Cancelled => return Ok(Outcome::Cancelled),
        SelectedResolutionOperationOpenOutcome::Stale(_) => return Ok(Outcome::Stale),
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(Outcome::Unavailable(format!("{reason:?}")));
        }
    };
    let admitted = HashSet::from_iter(files.iter().cloned());
    let Some(mut builder) = NativeWorkspaceGraphBuilder::new(analyzer, &admitted, cancellation)
    else {
        return Ok(Outcome::Cancelled);
    };
    let staged = operation.stage_jvm_graph_units(
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
    )?;
    let staged = match staged {
        SelectedResolutionOperationOutcome::Native(staged) => staged,
        SelectedResolutionOperationOutcome::Cancelled(_) => return Ok(Outcome::Cancelled),
        SelectedResolutionOperationOutcome::Stale(_) => return Ok(Outcome::Stale),
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(Outcome::Unavailable(format!("{reason:?}")));
        }
    };
    let projection = builder.finish(
        &mut operation,
        staged.summary,
        staged.skipped,
        admitted,
        UsageEcosystem::Jvm,
        cancellation,
    )?;
    if cancellation.is_cancelled() {
        return Ok(Outcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(Outcome::Stale);
    }
    Ok(projection)
}
