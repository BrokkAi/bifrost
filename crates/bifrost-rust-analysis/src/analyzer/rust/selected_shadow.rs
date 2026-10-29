//! Rust selected-resolution diagnostics and native reference-index construction.
//!
//! Diagnostic helpers retain selected native evidence without invoking an
//! incumbent producer after the production adapter cutover.

use crate::analyzer::rust::RustAnalyzer;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::rust::native_rename::RustBindingTargetProof;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::rust::native_rename::RustBindingWorldOutcome;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::rust::native_rename::RustRenameSafetyOutcome;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::rust::native_rename::selected_rust_binding_world;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::rust::native_rename::validate_selected_rust_rename;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::rust::selected_projection::rust_selected_workspace_identity_gap;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::rename::RenameResult;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::resolution::model::{
    ExactCompletionAccumulator, ResolutionCompletion,
};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingDefinition;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingDefinitionUnitsOutcome;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingOwner;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingWorld;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustCallerReferenceOutcome;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use brokk_bifrost_analysis::analyzer::structural::selected_inverse::{
    LazySelectedInverse, SelectedInverseAdapter, SelectedInverseFailure,
};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::model::Range;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::project::Project;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedInverseIndexOutcome;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedInverseReferenceIndex;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedInverseReferenceProvider;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::usages::get_definition::candidates_outcome;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::usages::inverted_edges::MAX_CALLSITES;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageGraph;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::is_graph_declaration;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::model::Language;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::model::ProjectFile;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    UsageReferenceCounts, UsageReferenceKind,
};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisWork, ReceiverBudgetLimit,
};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::hash::HashSet;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::path_utils::rel_path_string;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
#[cfg(any(test, feature = "test-support"))]
use std::collections::btree_map::Entry;
#[cfg(any(test, feature = "test-support"))]
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustDefinitionShadowResult {
    Complete {
        status: DefinitionLookupStatus,
        definitions: Vec<CodeUnit>,
        work: ReceiverAnalysisWork,
    },
    Exceeded {
        limit: ReceiverBudgetLimit,
        work: ReceiverAnalysisWork,
    },
    Cancelled {
        work: ReceiverAnalysisWork,
    },
    UnsupportedCallerProfile {
        work: ReceiverAnalysisWork,
    },
    Incomplete {
        definitions: Vec<CodeUnit>,
        completion: ResolutionCompletion,
        work: ReceiverAnalysisWork,
    },
    Unavailable(String),
    Stale(String),
    StoreError(String),
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_definition_shadow_result(
    rust: &RustAnalyzer,
    query: BoundedReceiverQuery<'_>,
) -> RustDefinitionShadowResult {
    selected_rust_definition_shadow_result_with_after_open(rust, query, || {})
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_definition_shadow_result_with_after_open(
    rust: &RustAnalyzer,
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> RustDefinitionShadowResult {
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    if !cancellation.is_cancelled()
        && let Some(detail) = rust_selected_workspace_identity_gap(rust)
    {
        return RustDefinitionShadowResult::Unavailable(detail);
    }
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return RustDefinitionShadowResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return RustDefinitionShadowResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return RustDefinitionShadowResult::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => return RustDefinitionShadowResult::StoreError(error.to_string()),
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let mut operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return RustDefinitionShadowResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return RustDefinitionShadowResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return RustDefinitionShadowResult::Cancelled {
                work: ReceiverAnalysisWork::default(),
            };
        }
        Err(error) => return RustDefinitionShadowResult::StoreError(error.to_string()),
    };
    after_open();
    let locator = SelectedSemanticLocator::for_reference_range(
        "rust",
        rel_path_string(query.file),
        query.site.focus_start_byte,
        query.site.focus_end_byte,
    );
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut point_metrics = ResolutionBatchMetrics::default();
    let result = operation.resolve_rust_reference_for_caller_bounded(
        query.file.rel_path(),
        &locator,
        query.budget,
        &cancellation,
        &mut context_metrics,
        &mut point_metrics,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => return RustDefinitionShadowResult::StoreError(error.to_string()),
    };
    match result {
        BoundedResolution::Exceeded { limit, work } => {
            RustDefinitionShadowResult::Exceeded { limit, work }
        }
        BoundedResolution::Cancelled { work } => RustDefinitionShadowResult::Cancelled { work },
        BoundedResolution::Complete {
            value: SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile,
            work,
        } => RustDefinitionShadowResult::UnsupportedCallerProfile { work },
        BoundedResolution::Complete {
            value: SelectedRustCallerReferenceOutcome::Operation(operation),
            work,
        } => match operation {
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing) => {
                // The caller supplied a structured reference occurrence. A
                // missing native site is missing producer support, not proof
                // that this occurrence has no definition. Closed negatives
                // come from a found reference with a complete empty binding.
                RustDefinitionShadowResult::Unavailable(format!(
                    "selected Rust reference inventory has no site for {:?}:{}..{}",
                    query.file, query.site.focus_start_byte, query.site.focus_end_byte,
                ))
            }
            SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answers,
            )) => {
                let Some(completion) = ResolutionCompletion::combine_all_with_poll(
                    answers
                        .iter()
                        .map(|answer| answer.resolution.binding().completion()),
                    &mut || cancellation.is_cancelled(),
                ) else {
                    return RustDefinitionShadowResult::Cancelled { work };
                };
                let definitions = answers
                    .into_iter()
                    .flat_map(|answer| answer.definitions)
                    .collect();
                if !matches!(completion, ResolutionCompletion::Complete) {
                    RustDefinitionShadowResult::Incomplete {
                        definitions,
                        completion,
                        work,
                    }
                } else {
                    let translated = candidates_outcome(definitions);
                    RustDefinitionShadowResult::Complete {
                        status: translated.status,
                        definitions: translated.definitions,
                        work,
                    }
                }
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                RustDefinitionShadowResult::Unavailable(format!("{reason:?}"))
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                RustDefinitionShadowResult::Stale(format!("{reason:?}"))
            }
            SelectedResolutionOperationOutcome::Cancelled(_) => {
                RustDefinitionShadowResult::Cancelled { work }
            }
        },
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_native_usage_consumer_shadow(
    rust: &RustAnalyzer,
    target: &CodeUnit,
    files: &HashSet<ProjectFile>,
) -> brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome {
    crate::analyzer::rust::native_usages::find_native_usages(
        rust,
        std::slice::from_ref(target),
        &brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope::new(files),
        1,
    )
}

/// A generation-bound handle; each target owns and drops its row query.
#[doc(hidden)]
pub struct RustSelectedReferenceIndex {
    index: LazySelectedInverse<RustInverseAdapter>,
}

impl RustSelectedReferenceIndex {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn covers_target(&self, target: &CodeUnit) -> bool {
        use crate::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

        use crate::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;
        matches!(
            with_rust_selected_reverse_queries(
                &self.index.adapter().rust,
                self.index.cancellation(),
                |queries| queries.candidate_sets(std::slice::from_ref(target))
            ),
            RustSelectedReverseOutcome::Ready(Some(_))
        )
    }

    pub(crate) fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        self.index.inverse_for(target)
    }
}

struct RustInverseAdapter {
    rust: Box<RustAnalyzer>,
}

impl SelectedInverseAdapter for RustInverseAdapter {
    fn admit(
        analyzer: &dyn IAnalyzer,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> std::result::Result<(u64, Self), SelectedInverseFailure> {
        use crate::analyzer::rust::selected_reverse::{
            RustSelectedReverseOutcome, with_rust_selected_reverse_queries,
        };
        let Some(rust) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            RustAnalyzer,
        >(analyzer) else {
            return Err(SelectedInverseFailure::Unavailable(
                "the workspace has no Rust analyzer".into(),
            ));
        };
        let generation = rust.inner.project().analysis_generation();
        match with_rust_selected_reverse_queries(rust, cancellation, |_| Ok(())) {
            RustSelectedReverseOutcome::Ready(()) => Ok((
                generation,
                Self {
                    rust: Box::new(rust.clone()),
                },
            )),
            RustSelectedReverseOutcome::Unavailable(detail) => {
                Err(SelectedInverseFailure::Unavailable(detail))
            }
            RustSelectedReverseOutcome::Stale(detail) => Err(SelectedInverseFailure::Stale(detail)),
            RustSelectedReverseOutcome::Cancelled => Err(SelectedInverseFailure::Cancelled),
            RustSelectedReverseOutcome::StoreError(detail) => {
                Err(SelectedInverseFailure::StoreError(detail))
            }
        }
    }

    fn current_generation(&self) -> u64 {
        self.rust.inner.project().analysis_generation()
    }

    fn query(
        &self,
        target: &CodeUnit,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> std::result::Result<Option<EdgeDerivationResult>, SelectedInverseFailure> {
        use crate::analyzer::rust::selected_reverse::{
            RustSelectedReverseOutcome, with_rust_selected_reverse_queries,
        };
        match with_rust_selected_reverse_queries(&self.rust, cancellation, |queries| {
            queries.inverse_for(std::slice::from_ref(target))
        }) {
            RustSelectedReverseOutcome::Ready(Some(mut answers)) => {
                assert_eq!(answers.len(), 1);
                let mut answer = answers.pop().expect("one target answer");
                let mut edges = std::collections::BTreeMap::new();
                for row in answer.edges {
                    let key = (
                        row.site.file.clone(),
                        row.site.range.start_byte,
                        row.site.range.end_byte,
                        row.target.clone(),
                        row.usage_kind,
                    );
                    if let Some(previous) = edges.insert(key, row.clone()) {
                        assert_eq!(
                            previous, row,
                            "one physical inverse edge has one canonical projection"
                        );
                    }
                }
                answer.edges = edges.into_values().collect();
                Ok(Some(answer))
            }
            RustSelectedReverseOutcome::Ready(None) => Ok(None),
            RustSelectedReverseOutcome::Unavailable(detail) => {
                Err(SelectedInverseFailure::Unavailable(detail))
            }
            RustSelectedReverseOutcome::Stale(detail) => Err(SelectedInverseFailure::Stale(detail)),
            RustSelectedReverseOutcome::Cancelled => Err(SelectedInverseFailure::Cancelled),
            RustSelectedReverseOutcome::StoreError(detail) => {
                Err(SelectedInverseFailure::StoreError(detail))
            }
        }
    }
}

#[doc(hidden)]
pub enum RustSelectedReferenceIndexOutcome {
    Ready(RustSelectedReferenceIndex),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

impl SelectedInverseReferenceIndex for RustSelectedReferenceIndex {
    fn generation(&self) -> u64 {
        self.index.generation()
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        Self::inverse_for(self, target)
    }
}

/// The registered Rust selected inverse index builder.
///
/// RQL `edges_of` and the policy edge asserts reach Rust's native inverse
/// answer through this provider, so a workspace whose selected facts cannot
/// produce an index reports that refusal instead of an empty edge set.
pub(crate) struct RustNativeSelectedInverseProvider;

impl SelectedInverseReferenceProvider for RustNativeSelectedInverseProvider {
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> SelectedInverseIndexOutcome {
        let Some(rust) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            RustAnalyzer,
        >(analyzer) else {
            return SelectedInverseIndexOutcome::Unavailable(
                "the workspace has no Rust analyzer".to_string(),
            );
        };
        let token = cancellation.cloned().unwrap_or_default();
        match build_rust_selected_reference_index(rust, &token) {
            RustSelectedReferenceIndexOutcome::Ready(index) => {
                SelectedInverseIndexOutcome::Ready(Arc::new(index))
            }
            RustSelectedReferenceIndexOutcome::Unavailable(detail) => {
                SelectedInverseIndexOutcome::Unavailable(detail)
            }
            RustSelectedReferenceIndexOutcome::Stale(detail) => {
                SelectedInverseIndexOutcome::Stale(detail)
            }
            RustSelectedReferenceIndexOutcome::Cancelled => SelectedInverseIndexOutcome::Cancelled,
            RustSelectedReferenceIndexOutcome::StoreError(detail) => {
                SelectedInverseIndexOutcome::StoreError(detail)
            }
        }
    }
}

#[doc(hidden)]
pub fn build_rust_selected_reference_index(
    rust: &RustAnalyzer,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> RustSelectedReferenceIndexOutcome {
    match LazySelectedInverse::<RustInverseAdapter>::build(rust, cancellation) {
        Ok(index) => RustSelectedReferenceIndexOutcome::Ready(RustSelectedReferenceIndex { index }),
        Err(SelectedInverseFailure::Unavailable(detail)) => {
            RustSelectedReferenceIndexOutcome::Unavailable(detail)
        }
        Err(SelectedInverseFailure::Stale(detail)) => {
            RustSelectedReferenceIndexOutcome::Stale(detail)
        }
        Err(SelectedInverseFailure::Cancelled) => RustSelectedReferenceIndexOutcome::Cancelled,
        Err(SelectedInverseFailure::StoreError(detail)) => {
            RustSelectedReferenceIndexOutcome::StoreError(detail)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct RustUsageShadowSite {
    file: ProjectFile,
    start_byte: usize,
    end_byte: usize,
    #[doc(hidden)]
    pub enclosing: CodeUnit,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustUsageShadowResult {
    Complete {
        sites: BTreeSet<RustUsageShadowSite>,
        capped: bool,
    },
    Incomplete {
        sites: BTreeSet<RustUsageShadowSite>,
        capped: bool,
        completion: EdgeCompleteness,
    },
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_usage_shadow_result(
    rust: &RustAnalyzer,
    targets: &[CodeUnit],
    scan_scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> RustUsageShadowResult {
    use crate::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

    use crate::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;
    let fallback = brokk_bifrost_core::cancellation::CancellationToken::default();
    let cancellation = scan_scope.cancellation().unwrap_or(&fallback);
    let answers = match with_rust_selected_reverse_queries(rust, cancellation, |queries| {
        queries.inverse_for(targets)
    }) {
        RustSelectedReverseOutcome::Ready(Some(answers)) => answers,
        RustSelectedReverseOutcome::Ready(None) => {
            return RustUsageShadowResult::Unavailable(
                "selected inverse target is unavailable".into(),
            );
        }
        RustSelectedReverseOutcome::Unavailable(reason) => {
            return RustUsageShadowResult::Unavailable(reason);
        }
        RustSelectedReverseOutcome::Stale(reason) => return RustUsageShadowResult::Stale(reason),
        RustSelectedReverseOutcome::Cancelled => return RustUsageShadowResult::Cancelled,
        RustSelectedReverseOutcome::StoreError(reason) => {
            return RustUsageShadowResult::StoreError(reason);
        }
    };
    let mut sites = BTreeSet::new();
    let mut reasons = Vec::new();
    for answer in answers {
        if let EdgeCompleteness::Incomplete { reasons: gaps } = answer.completeness {
            reasons.extend(gaps);
        }
        for edge in answer.edges {
            if edge.usage_kind == UsageHitKind::Import
                || !scan_scope.candidate_files().contains(&edge.site.file)
            {
                continue;
            }
            let enclosing = edge
                .site
                .enclosing
                .unwrap_or_else(|| CodeUnit::file_scope(edge.site.file.clone()));
            if targets.contains(&enclosing) {
                continue;
            }
            sites.insert(RustUsageShadowSite {
                file: edge.site.file,
                start_byte: edge.site.range.start_byte,
                end_byte: edge.site.range.end_byte,
                enclosing,
            });
        }
    }
    let capped = sites.len() > max_usages;
    let sites = sites.into_iter().take(max_usages).collect();
    if reasons.is_empty() {
        RustUsageShadowResult::Complete { sites, capped }
    } else {
        RustUsageShadowResult::Incomplete {
            sites,
            capped,
            completion: EdgeCompleteness::Incomplete { reasons },
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct RustWorkspaceBindingWorld {
    #[doc(hidden)]
    pub definition_units: BTreeMap<SelectedRustBindingDefinition, CodeUnit>,
    #[doc(hidden)]
    pub world: SelectedRustBindingWorld,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub enum RustWorkspaceBindingWorldResult {
    Ready(RustWorkspaceBindingWorld),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

/// Test-only graph oracle assembled from per-definition row demands. Production
/// inverse consumers retain only the generation-bound query handle below.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_workspace_binding_world(
    rust: &RustAnalyzer,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> RustWorkspaceBindingWorldResult {
    let _timing = brokk_bifrost_core::profiling::scope("rust_selected::workspace_binding_world");
    if cancellation.is_cancelled() {
        return RustWorkspaceBindingWorldResult::Cancelled;
    }
    let generation = rust.inner.project().analysis_generation();
    let snapshots = rust.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let (masks, content_mounts) = match rust
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)
    {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
            return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
            return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
            return RustWorkspaceBindingWorldResult::Cancelled;
        }
        Err(error) => {
            return RustWorkspaceBindingWorldResult::StoreError(error.to_string());
        }
    };
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return RustWorkspaceBindingWorldResult::Cancelled;
        }
        Err(error) => {
            return RustWorkspaceBindingWorldResult::StoreError(error.to_string());
        }
    };
    let definition_timing = brokk_bifrost_core::profiling::scope("rust_selected::definition_units");
    let definition_units = match operation.rust_binding_definition_units(cancellation) {
        Ok(SelectedRustBindingDefinitionUnitsOutcome::Ready(units)) => units,
        Ok(SelectedRustBindingDefinitionUnitsOutcome::Cancelled) => {
            return RustWorkspaceBindingWorldResult::Cancelled;
        }
        Err(error) => {
            return RustWorkspaceBindingWorldResult::StoreError(error.to_string());
        }
    };
    drop(definition_timing);
    let Some(anchor) = definition_units
        .iter()
        .find_map(|(definition, unit)| is_graph_declaration(unit).then(|| definition.clone()))
    else {
        return RustWorkspaceBindingWorldResult::Unavailable(
            "selected Rust workspace has no graph declaration anchor".to_string(),
        );
    };
    let mut sites = Vec::new();
    let mut completion = ExactCompletionAccumulator::default();
    for unit in definition_units.values() {
        let (masks, content_mounts) = match rust
            .inner
            .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), cancellation)
        {
            Ok(SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            }) => (masks, content_mounts),
            Ok(SelectedResolutionOverlayInputsOutcome::Cancelled) => {
                return RustWorkspaceBindingWorldResult::Cancelled;
            }
            Ok(SelectedResolutionOverlayInputsOutcome::Stale(reason)) => {
                return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
            }
            Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(reason)) => {
                return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
            }
            Err(error) => return RustWorkspaceBindingWorldResult::StoreError(error.to_string()),
        };
        match selected_rust_binding_world(
            rust,
            snapshots.as_ref(),
            RustBindingTargetProof::Current(unit),
            &masks,
            content_mounts,
            cancellation,
        ) {
            RustBindingWorldOutcome::Ready(world) => {
                sites.extend_from_slice(world.sites());
                if completion
                    .include(world.completion(), &mut || cancellation.is_cancelled())
                    .is_none()
                {
                    return RustWorkspaceBindingWorldResult::Cancelled;
                }
            }
            RustBindingWorldOutcome::Unavailable(detail) => {
                return RustWorkspaceBindingWorldResult::Unavailable(detail);
            }
            RustBindingWorldOutcome::Stale(detail) => {
                return RustWorkspaceBindingWorldResult::Stale(detail);
            }
            RustBindingWorldOutcome::Cancelled => {
                return RustWorkspaceBindingWorldResult::Cancelled;
            }
            RustBindingWorldOutcome::StoreError(detail) => {
                return RustWorkspaceBindingWorldResult::StoreError(detail);
            }
        }
    }
    let Some(completion) = completion.finish(&mut || cancellation.is_cancelled()) else {
        return RustWorkspaceBindingWorldResult::Cancelled;
    };
    let world =
        match operation.finish_rust_row_binding_world(anchor, sites, completion, cancellation) {
            Ok(SelectedResolutionOperationOutcome::Native(world)) => world,
            Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
                return RustWorkspaceBindingWorldResult::Unavailable(format!("{reason:?}"));
            }
            Ok(SelectedResolutionOperationOutcome::Stale(reason)) => {
                return RustWorkspaceBindingWorldResult::Stale(format!("{reason:?}"));
            }
            Ok(SelectedResolutionOperationOutcome::Cancelled(_)) => {
                return RustWorkspaceBindingWorldResult::Cancelled;
            }
            Err(error) => return RustWorkspaceBindingWorldResult::StoreError(error.to_string()),
        };
    if cancellation.is_cancelled() {
        return RustWorkspaceBindingWorldResult::Cancelled;
    }
    if rust.inner.project().analysis_generation() != generation {
        return RustWorkspaceBindingWorldResult::Stale(
            "selected Rust binding world crossed an analyzer generation".to_string(),
        );
    }
    RustWorkspaceBindingWorldResult::Ready(RustWorkspaceBindingWorld {
        definition_units,
        world,
    })
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[doc(hidden)]
pub struct RustWorkspaceGraphShadow {
    #[doc(hidden)]
    pub edges: BTreeMap<(CodeUnit, CodeUnit), UsageReferenceCounts>,
    #[doc(hidden)]
    pub truncated: BTreeMap<CodeUnit, usize>,
    #[doc(hidden)]
    pub unproven_inbound: BTreeMap<CodeUnit, usize>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustWorkspaceGraphShadowResult {
    Complete(RustWorkspaceGraphShadow),
    Incomplete {
        graph: RustWorkspaceGraphShadow,
        detail: String,
    },
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

#[cfg(any(test, feature = "test-support"))]
fn rust_workspace_graph_reference_kind(
    site_kind: ResolutionSiteKind,
) -> Option<UsageReferenceKind> {
    match site_kind {
        ResolutionSiteKind::CallableReference | ResolutionSiteKind::ConstructorReference => {
            Some(UsageReferenceKind::Call)
        }
        ResolutionSiteKind::MemberReference => Some(UsageReferenceKind::Member),
        ResolutionSiteKind::TypeReference => Some(UsageReferenceKind::Type),
        ResolutionSiteKind::ImportDeclaration
        | ResolutionSiteKind::ModuleReference
        | ResolutionSiteKind::MacroReference
        | ResolutionSiteKind::ValueReference => Some(UsageReferenceKind::Other),
        _ => None,
    }
}

#[cfg(any(test, feature = "test-support"))]
fn native_rust_workspace_graph_shadow(
    rust: &RustAnalyzer,
    production: &WorkspaceUsageGraph,
    definition_units: &BTreeMap<SelectedRustBindingDefinition, CodeUnit>,
    world: &SelectedRustBindingWorld,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> RustWorkspaceGraphShadowResult {
    let graph_units = production
        .nodes
        .iter()
        .filter(|node| node.key.ecosystem == UsageEcosystem::Rust)
        .map(|node| (node.primary.clone(), node.primary.clone()))
        .collect::<BTreeMap<_, _>>();
    let required_units = definition_units
        .values()
        .filter(|unit| is_graph_declaration(unit))
        .cloned()
        .collect::<BTreeSet<_>>();
    let graph_definition_spans = production
        .nodes
        .iter()
        .filter(|node| node.key.ecosystem == UsageEcosystem::Rust)
        .filter_map(|node| {
            node.primary_range.map(|range| {
                (
                    node.primary.clone(),
                    vec![(node.primary.source().clone(), range)],
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    native_rust_graph_shadow_for_units(
        rust,
        definition_units,
        &graph_units,
        &required_units,
        &graph_definition_spans,
        world,
        cancellation,
    )
}

#[cfg(any(test, feature = "test-support"))]
fn native_rust_graph_shadow_for_units(
    rust: &RustAnalyzer,
    definition_units: &BTreeMap<SelectedRustBindingDefinition, CodeUnit>,
    graph_units: &BTreeMap<CodeUnit, CodeUnit>,
    required_units: &BTreeSet<CodeUnit>,
    graph_definition_spans: &BTreeMap<CodeUnit, Vec<(ProjectFile, Range)>>,
    world: &SelectedRustBindingWorld,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> RustWorkspaceGraphShadowResult {
    let mut edge_lines = BTreeMap::new();
    let mut callsites: BTreeMap<CodeUnit, BTreeSet<(ProjectFile, usize)>> = BTreeMap::new();
    let mut unproven: BTreeMap<CodeUnit, BTreeSet<(ProjectFile, usize)>> = BTreeMap::new();
    let mut line_starts = BTreeMap::new();
    let mut projection_complete = true;
    let mut completion = ExactCompletionAccumulator::default();
    if completion
        .include(world.completion(), &mut || cancellation.is_cancelled())
        .is_none()
    {
        return RustWorkspaceGraphShadowResult::Cancelled;
    }

    for site in world.sites() {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        if completion
            .include(site.completion(), &mut || cancellation.is_cancelled())
            .is_none()
        {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        let Some(metadata) = site.metadata() else {
            projection_complete = false;
            continue;
        };
        let Some(kind) = rust_workspace_graph_reference_kind(metadata.site_kind()) else {
            projection_complete = false;
            continue;
        };
        let caller = match site.owner() {
            SelectedRustBindingOwner::Definition(owner) => Some(owner),
            SelectedRustBindingOwner::FileRoot => None,
            SelectedRustBindingOwner::Unknown | SelectedRustBindingOwner::Unavailable => {
                projection_complete = false;
                None
            }
        };
        let Some(caller) = caller else {
            continue;
        };
        let targets = site
            .definitions()
            .iter()
            .filter_map(|definition| definition_units.get(definition))
            .filter_map(|unit| match graph_units.get(unit) {
                Some(unit) => Some(unit),
                None if required_units.contains(unit) => {
                    projection_complete = false;
                    None
                }
                None => None,
            })
            .collect::<Vec<_>>();
        let overlaps_target_definition = |target: &CodeUnit| {
            graph_definition_spans.get(target).is_some_and(|ranges| {
                ranges.iter().any(|(file, range)| {
                    file == site.file()
                        && range.start_byte < metadata.end_byte()
                        && metadata.start_byte() < range.end_byte
                })
            })
        };
        let proven = site.definitions().len() == 1
            && targets.len() == 1
            && site.completion() == &ResolutionCompletion::Complete;
        if !proven {
            for target in targets {
                if caller != target && !overlaps_target_definition(target) {
                    unproven
                        .entry(target.clone())
                        .or_default()
                        .insert((site.file().clone(), metadata.start_byte()));
                }
            }
            continue;
        }
        let target = targets[0];
        if caller == target {
            continue;
        }
        callsites
            .entry(target.clone())
            .or_default()
            .insert((site.file().clone(), metadata.start_byte()));
        if overlaps_target_definition(target) {
            continue;
        }
        let caller = match graph_units.get(caller) {
            Some(caller) => caller,
            None => {
                if required_units.contains(caller) {
                    projection_complete = false;
                }
                continue;
            }
        };
        let starts = match line_starts.entry(site.file().clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let Some(source) = rust.indexed_source(site.file()) else {
                    projection_complete = false;
                    continue;
                };
                entry.insert(compute_line_starts(&source))
            }
        };
        let line = find_line_index_for_offset(starts, metadata.start_byte()) + 1;
        let retained_kind = edge_lines
            .entry((caller.clone(), target.clone(), site.file().clone(), line))
            .or_insert(kind);
        *retained_kind = (*retained_kind).max(kind);
    }

    let mut truncated = BTreeMap::new();
    for (target, sites) in callsites {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        if sites.len() > MAX_CALLSITES {
            truncated.insert(target, sites.len());
        }
    }
    let mut edges: BTreeMap<(CodeUnit, CodeUnit), UsageReferenceCounts> = BTreeMap::new();
    for ((caller, target, _, _), kind) in edge_lines {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        if !truncated.contains_key(&target) {
            edges.entry((caller, target)).or_default().record(kind);
        }
    }
    let mut unproven_inbound = BTreeMap::new();
    for (target, sites) in unproven {
        if cancellation.is_cancelled() {
            return RustWorkspaceGraphShadowResult::Cancelled;
        }
        unproven_inbound.insert(target, sites.len());
    }
    if cancellation.is_cancelled() {
        return RustWorkspaceGraphShadowResult::Cancelled;
    }
    let graph = RustWorkspaceGraphShadow {
        edges,
        truncated,
        unproven_inbound,
    };
    let Some(completion) = completion.finish(&mut || cancellation.is_cancelled()) else {
        return RustWorkspaceGraphShadowResult::Cancelled;
    };
    if projection_complete && completion == ResolutionCompletion::Complete {
        RustWorkspaceGraphShadowResult::Complete(graph)
    } else {
        RustWorkspaceGraphShadowResult::Incomplete {
            graph,
            detail: format!(
                "selected Rust workspace graph is open: completion={completion:?}, projection_complete={projection_complete}"
            ),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_workspace_graph_shadow_result(
    rust: &RustAnalyzer,
    production: &WorkspaceUsageGraph,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> RustWorkspaceGraphShadowResult {
    match selected_rust_workspace_binding_world(rust, cancellation) {
        RustWorkspaceBindingWorldResult::Ready(selected) => native_rust_workspace_graph_shadow(
            rust,
            production,
            &selected.definition_units,
            &selected.world,
            cancellation,
        ),
        RustWorkspaceBindingWorldResult::Unavailable(detail) => {
            RustWorkspaceGraphShadowResult::Unavailable(detail)
        }
        RustWorkspaceBindingWorldResult::Stale(detail) => {
            RustWorkspaceGraphShadowResult::Stale(detail)
        }
        RustWorkspaceBindingWorldResult::Cancelled => RustWorkspaceGraphShadowResult::Cancelled,
        RustWorkspaceBindingWorldResult::StoreError(detail) => {
            RustWorkspaceGraphShadowResult::StoreError(detail)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_rename_shadow_result(
    rust: &RustAnalyzer,
    project: &dyn Project,
    result: &RenameResult,
    new_name: &str,
) -> RustRenameSafetyOutcome {
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
    validate_selected_rust_rename(rust, project, result, new_name, &cancellation)
}

#[cfg(test)]
#[path = "selected_shadow/module_system_tests.rs"]
mod module_system_tests;
