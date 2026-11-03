//! One selected Java/Kotlin/Scala source recipe for JVM consumers and replay.

use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperation, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome,
};
use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
    SelectedResolutionLanguage, SelectedResolutionStale, SelectedResolutionUnavailable,
};
use brokk_bifrost_analysis::analyzer::store::{Result, WorkspaceSnapshots};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::cancellation::CancellationToken;

pub(crate) enum SelectedJvmOperationOutcome<'store, 'project> {
    Ready(Box<SelectedResolutionOperation<'store, 'project>>),
    Cancelled,
    // Only the test-support reverse path reads the reason; the graph provider
    // reports staleness without it.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    Stale(SelectedResolutionStale),
    Unavailable(SelectedResolutionUnavailable),
}

pub(crate) struct SelectedJvmRecipe<'a, A: LanguageAdapter> {
    inner: &'a TreeSitterAnalyzer<A>,
    snapshots: WorkspaceSnapshots,
}

impl<'a, A: LanguageAdapter> SelectedJvmRecipe<'a, A> {
    pub(crate) fn new(inner: &'a TreeSitterAnalyzer<A>) -> Result<Self> {
        let selected = ["java", "kotlin", "scala"].map(str::to_owned);
        let snapshots = inner
            .analyzer_store()
            .workspace_snapshots_for_current_languages(inner.workspace_id(), &selected)?;
        Ok(Self { inner, snapshots })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn has_language(&self, language: &str) -> bool {
        self.snapshots.contains_key(language)
    }

    pub(crate) fn open(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SelectedJvmOperationOutcome<'a, 'a>> {
        let inner = self.inner;
        let snapshots = &self.snapshots;
        let (masks, content_mounts) =
            match inner.selected_resolution_overlay_inputs(snapshots, cancellation)? {
                SelectedResolutionOverlayInputsOutcome::Ready {
                    masks,
                    content_mounts,
                } => (masks, content_mounts),
                SelectedResolutionOverlayInputsOutcome::Cancelled => {
                    return Ok(SelectedJvmOperationOutcome::Cancelled);
                }
                SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
                    return Ok(SelectedJvmOperationOutcome::Stale(reason));
                }
                SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
                    return Ok(SelectedJvmOperationOutcome::Unavailable(reason));
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
            snapshots,
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts);
        Ok(
            match inner
                .analyzer_store()
                .open_selected_resolution_operation(input, cancellation)?
            {
                SelectedResolutionOperationOpenOutcome::Ready(operation) => {
                    SelectedJvmOperationOutcome::Ready(operation)
                }
                SelectedResolutionOperationOpenOutcome::Cancelled => {
                    SelectedJvmOperationOutcome::Cancelled
                }
                SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                    SelectedJvmOperationOutcome::Stale(reason)
                }
                SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                    SelectedJvmOperationOutcome::Unavailable(reason)
                }
            },
        )
    }
}

pub(crate) fn replay_root_presence<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    root: &str,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest> {
    use brokk_bifrost_analysis::analyzer::resolution::BatchResolutionFragmentSource;
    if ![Language::Java, Language::Kotlin, Language::Scala]
        .into_iter()
        .filter_map(brokk_bifrost_jvm::intrinsics::implicit_superclass_root)
        .any(|known| known == root)
    {
        return None;
    }
    let cancellation = CancellationToken::new();
    let recipe = SelectedJvmRecipe::new(inner).ok()?;
    let SelectedJvmOperationOutcome::Ready(operation) = recipe.open(&cancellation).ok()? else {
        return None;
    };
    operation
        .ready()
        .lexical_source()
        .jvm_selected_root_presence(root, &cancellation)
        .ok()
        .map(|presence| presence.read_digest())
}
