//! Test-support JVM-target inverse references over selected JVM forward resolution.
//!
//! Candidate discovery uses shared indexed reference paths, and every candidate
//! is confirmed in its own language's selected JVM import context. Current
//! producer and consumer coverage can keep peer-language absence explicitly open.

use crate::analyzer::java::JavaAnalyzer;
use crate::analyzer::kotlin::KotlinAnalyzer;
use crate::analyzer::scala::ScalaAnalyzer;
use brokk_bifrost_analysis::analyzer::structural::reference_edges::{
    SelectedInverseIndexOutcome, SelectedInverseReferenceIndex, SelectedInverseReferenceProvider,
};
use brokk_bifrost_analysis::analyzer::structural::selected_inverse::{
    LazySelectedInverse, SelectedInverseAdapter, SelectedInverseFailure,
};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use brokk_bifrost_core::analyzer::common::language_for_target;

pub(crate) fn jvm_target_analyzer<'a>(
    analyzer: &'a dyn IAnalyzer,
    target: &CodeUnit,
) -> Option<&'a dyn IAnalyzer> {
    match language_for_target(target) {
        Language::Java => resolve_analyzer::<JavaAnalyzer>(analyzer).map(|a| a as &dyn IAnalyzer),
        Language::Kotlin => {
            resolve_analyzer::<KotlinAnalyzer>(analyzer).map(|a| a as &dyn IAnalyzer)
        }
        Language::Scala => resolve_analyzer::<ScalaAnalyzer>(analyzer).map(|a| a as &dyn IAnalyzer),
        _ => None,
    }
}

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::nominal_reverse::NominalReverseCandidateOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::nominal_reverse::NominalReverseConfirmed;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseReferenceExecutionContext;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::selected_reverse_reference_file;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::selected_reverse_reference_owner;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_analysis::analyzer::store::StoreError;

use brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance;

use brokk_bifrost_core::analyzer::structural::edges::SiteClass;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeSite;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceEdgeRow;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedReferenceFileProjection;

use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionSiteKind,
};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

#[derive(Debug)]
pub enum JavaSelectedReverseOutcome<T> {
    Ready(T),
    /// The target is outside selected coverage; other consumers retain its detail.
    TargetUncovered(String),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

pub(crate) struct JavaSelectedInverseResolution {
    pub(crate) edges: EdgeDerivationResult,
    pub(crate) peer_language_inventory_open: bool,
    // Edge proof also reflects incomplete caller-context evidence. Retain the
    // binding arm count separately so call projection can distinguish a
    // singleton provisional target from a genuinely ambiguous overload.
    binding_target_counts: HashMap<(ProjectFile, usize, usize), Option<usize>>,
    execution_contexts: HashMap<(ProjectFile, usize, usize), ReverseReferenceExecutionContext>,
}

impl JavaSelectedInverseResolution {
    pub(crate) fn binding_target_count(&self, site: &EdgeSite) -> Option<usize> {
        self.binding_target_counts
            .get(&(
                site.file.clone(),
                site.range.start_byte,
                site.range.end_byte,
            ))
            .copied()
            .flatten()
    }

    pub(crate) fn execution_context(
        &self,
        file: &ProjectFile,
        start: usize,
        end: usize,
    ) -> Option<ReverseReferenceExecutionContext> {
        self.execution_contexts
            .get(&(file.clone(), start, end))
            .copied()
    }
}

/// Resolve one target against selected Java source identities and contexts.
pub fn java_selected_inverse_for(
    java: &dyn IAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> JavaSelectedReverseOutcome<EdgeDerivationResult> {
    match java_selected_inverse_detailed_for(java, java, target, cancellation) {
        JavaSelectedReverseOutcome::Ready(answer) => {
            JavaSelectedReverseOutcome::Ready(answer.edges)
        }
        JavaSelectedReverseOutcome::Unavailable(reason)
        | JavaSelectedReverseOutcome::TargetUncovered(reason) => {
            JavaSelectedReverseOutcome::Unavailable(reason)
        }
        JavaSelectedReverseOutcome::Stale(reason) => JavaSelectedReverseOutcome::Stale(reason),
        JavaSelectedReverseOutcome::Cancelled => JavaSelectedReverseOutcome::Cancelled,
        JavaSelectedReverseOutcome::StoreError(reason) => {
            JavaSelectedReverseOutcome::StoreError(reason)
        }
    }
}

pub(crate) fn java_selected_inverse_detailed_for(
    analyzer: &dyn IAnalyzer,
    java: &dyn IAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> JavaSelectedReverseOutcome<JavaSelectedInverseResolution> {
    let result = match language_for_target(target) {
        Language::Java => resolve_analyzer::<JavaAnalyzer>(java)
            .map(|a| java_selected_inverse_for_inner(analyzer, a, a.inner(), target, cancellation)),
        Language::Kotlin => resolve_analyzer::<KotlinAnalyzer>(java).map(|a| {
            java_selected_inverse_for_inner(
                analyzer,
                a,
                a.tree_sitter_analyzer(),
                target,
                cancellation,
            )
        }),
        Language::Scala => resolve_analyzer::<ScalaAnalyzer>(java).map(|a| {
            java_selected_inverse_for_inner(
                analyzer,
                a,
                a.tree_sitter_analyzer(),
                target,
                cancellation,
            )
        }),
        _ => {
            return JavaSelectedReverseOutcome::TargetUncovered(
                "selected inverse target is not a JVM language".into(),
            );
        }
    };
    match result {
        Some(Ok(outcome)) => outcome,
        Some(Err(error)) => JavaSelectedReverseOutcome::StoreError(error.to_string()),
        None => JavaSelectedReverseOutcome::Unavailable(
            "selected JVM target analyzer is unavailable".into(),
        ),
    }
}

fn java_selected_inverse_for_inner<A: LanguageAdapter>(
    analyzer: &dyn IAnalyzer,
    java: &dyn IAnalyzer,
    inner: &TreeSitterAnalyzer<A>,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> Result<JavaSelectedReverseOutcome<JavaSelectedInverseResolution>> {
    if cancellation.is_cancelled() {
        return Ok(JavaSelectedReverseOutcome::Cancelled);
    }
    // A Java delegate inside a multi-language analyzer can expose a
    // Java-filtered Project. Ask the shared store for every JVM source
    // snapshot at its current generation, then let selected mounts establish
    // whether peer-language source files actually exist.
    let recipe = crate::analyzer::jvm::selected_operation::SelectedJvmRecipe::new(inner)?;
    if !recipe.has_language(language_for_target(target).config_label()) {
        return Ok(JavaSelectedReverseOutcome::Unavailable(
            "the workspace has no selected Java snapshot".into(),
        ));
    }
    let operation = match recipe.open(cancellation)? {
        crate::analyzer::jvm::selected_operation::SelectedJvmOperationOutcome::Ready(operation) => {
            *operation
        }
        crate::analyzer::jvm::selected_operation::SelectedJvmOperationOutcome::Unavailable(
            reason,
        ) => {
            return Ok(JavaSelectedReverseOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
        crate::analyzer::jvm::selected_operation::SelectedJvmOperationOutcome::Stale(reason) => {
            return Ok(JavaSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        crate::analyzer::jvm::selected_operation::SelectedJvmOperationOutcome::Cancelled => {
            return Ok(JavaSelectedReverseOutcome::Cancelled);
        }
    };
    let generation = inner.project().analysis_generation();
    let candidates = {
        let _root_read_guard =
            brokk_bifrost_analysis::analyzer::root_presence::RootPresenceExportGuard {
                analyzer,
                handle: Some(operation.root_presence_read_handle()),
            };
        match operation.nominal_reverse_candidate_sites(target, cancellation)? {
            NominalReverseCandidateOutcome::Ready(candidates) => candidates,
            NominalReverseCandidateOutcome::TargetUncovered(reason) => {
                return Ok(JavaSelectedReverseOutcome::TargetUncovered(reason));
            }
            NominalReverseCandidateOutcome::Unavailable(reason) => {
                return Ok(JavaSelectedReverseOutcome::Unavailable(reason));
            }
            NominalReverseCandidateOutcome::Cancelled => {
                return Ok(JavaSelectedReverseOutcome::Cancelled);
            }
        }
    };
    let mut context_metrics = SelectedResolutionContextMetrics;
    let (confirmed, root_reads) = operation.confirm_nominal_reverse_candidates(
        candidates,
        cancellation,
        &mut context_metrics,
    )?;
    brokk_bifrost_analysis::analyzer::root_presence::record_root_presence_entries(
        analyzer,
        &root_reads,
    );
    let confirmed = match confirmed {
        SelectedResolutionOperationOutcome::Native(confirmed) => confirmed,
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(JavaSelectedReverseOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(JavaSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(JavaSelectedReverseOutcome::Cancelled);
        }
    };
    if inner.project().analysis_generation() != generation {
        return Ok(JavaSelectedReverseOutcome::Stale(
            "Java selected reverse query crossed an analyzer generation".into(),
        ));
    }
    let answer =
        project_confirmed_references(analyzer, java, target, generation, confirmed, cancellation)?;
    if inner.project().analysis_generation() != generation {
        return Ok(JavaSelectedReverseOutcome::Stale(
            "Java selected reverse projection crossed an analyzer generation".into(),
        ));
    }
    Ok(JavaSelectedReverseOutcome::Ready(answer))
}

fn project_confirmed_references(
    analyzer: &dyn IAnalyzer,
    java: &dyn IAnalyzer,
    target: &CodeUnit,
    generation: u64,
    confirmed: NominalReverseConfirmed,
    cancellation: &CancellationToken,
) -> Result<JavaSelectedInverseResolution> {
    let peer_language_inventory_open = confirmed.peer_language_inventory_open;
    let mut reasons = Vec::new();
    if !confirmed.candidate_inventory_complete {
        reasons.push(EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete);
    }
    if peer_language_inventory_open {
        push_reason(
            &mut reasons,
            EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete,
        );
    }
    if confirmed.completion != ResolutionCompletion::Complete {
        reasons.push(EdgeIncompleteReason::InverseIndexResolutionIncomplete);
    }

    let mut files = HashMap::<ProjectFile, SelectedReferenceFileProjection<'_>>::default();
    let mut edges = Vec::new();
    let mut binding_target_counts = HashMap::default();
    let mut execution_contexts = HashMap::default();
    for reference in confirmed.references {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("Java selected reverse query was cancelled"));
        }
        if matches!(
            reference.execution_context,
            ReverseReferenceExecutionContext::RowAbsent
        ) && reference.locator.storage_language == "java"
        {
            return Err(StoreError::corrupt(format!(
                "selected Java reference has no execution context row: {:?}",
                reference.locator
            )));
        }
        if matches!(reference.execution_context, ReverseReferenceExecutionContext::Present {
            disposition: brokk_bifrost_core::analyzer::resolution_facts::ResolutionReferenceExecutionDisposition::NonExecutable,
            ..
        }) && reference.answer.site_metadata().is_some_and(|metadata| matches!(
            metadata.site_kind(), ResolutionSiteKind::Call | ResolutionSiteKind::ConstructorReference
        )) {
            return Err(StoreError::corrupt(format!(
                "selected Java invocation has non-executable context: {:?}",
                reference.locator
            )));
        }
        let answer = reference.answer;
        if !answer.binding().targets().iter().any(|semantic| {
            *semantic == confirmed.target || confirmed.equivalent_targets.contains(semantic)
        }) {
            continue;
        }
        let binding_target_count = answer.binding().targets().len();
        let Some(metadata) = answer.site_metadata() else {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
            continue;
        };
        let file = ProjectFile::new(java.project().root(), reference.locator.relative_path());
        if !files.contains_key(&file) {
            files.insert(
                file.clone(),
                selected_reverse_reference_file(analyzer, java, &file)?,
            );
        }
        let projected_file = files
            .get(&file)
            .expect("selected caller source was projected");
        let owner = selected_reverse_reference_owner(&file, reference.owner)?;
        let projected_file = &projected_file.state;
        let reference_kind = projected_file.classifier.as_ref().map(|classifier| {
            classifier.classify_reference_facets(metadata.start_byte(), metadata.end_byte(), target)
        });
        let ast_id = projected_file
            .classifier
            .as_ref()
            .and_then(|classifier| classifier.ast_id(metadata.start_byte(), metadata.end_byte()));
        if projected_file.classifier.is_none() {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
        }
        let range = projected_file.range(metadata.start_byte(), metadata.end_byte());
        let site_key = (file.clone(), range.start_byte, range.end_byte);
        match execution_contexts.entry(site_key.clone()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(reference.execution_context);
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                if *slot.get() != reference.execution_context {
                    slot.insert(ReverseReferenceExecutionContext::Present {
                        disposition: brokk_bifrost_core::analyzer::resolution_facts::ResolutionReferenceExecutionDisposition::Unknown,
                        procedure_kind: None,
                        initializer_is_static: None,
                        callable_site: None,
                    });
                }
            }
        }
        if let Some(existing) = binding_target_counts.get_mut(&site_key) {
            if *existing != Some(binding_target_count) {
                *existing = None;
            }
        } else {
            binding_target_counts.insert(site_key, Some(binding_target_count));
        }
        let (proof, obligations_block_proof) = brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::selected_reverse_proof(
            binding_target_count == 1
                && answer.binding().completion() == &ResolutionCompletion::Complete,
            !answer.query_obligations.is_empty(),
        );
        if obligations_block_proof {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexQueryObligationsOutstanding,
            );
        }
        edges.push(ReferenceEdgeRow {
            dispatch_extensibility: None,
            site: EdgeSite {
                file,
                range,
                ast_id,
                enclosing: owner,
            },
            target: target.clone(),
            reference_kind: reference_kind.unwrap_or_else(|| {
                brokk_bifrost_core::analyzer::usages::model::facets_from_classified(None)
            }),
            proof,
            ambiguous_candidate: false,
            usage_kind: selected_usage_kind(metadata),
            site_class: SiteClass::UseSite,
            owner_relation: brokk_bifrost_core::analyzer::structural::edges::OwnerRelation::Unknown,
            provenance: EdgeProvenance::Inverse,
            generation,
        });
    }
    Ok(JavaSelectedInverseResolution {
        edges: EdgeDerivationResult {
            edges,
            completeness: if reasons.is_empty() {
                EdgeCompleteness::Complete
            } else {
                EdgeCompleteness::Incomplete { reasons }
            },
            provenance: EdgeProvenance::Inverse,
            generation,
        },
        binding_target_counts,
        execution_contexts,
        peer_language_inventory_open,
    })
}

fn selected_usage_kind(
    metadata: brokk_bifrost_analysis::analyzer::resolution::batch::FactReferenceSiteMetadata,
) -> UsageHitKind {
    if metadata.site_kind() == ResolutionSiteKind::ImportDeclaration {
        UsageHitKind::Import
    } else if metadata.callable_receiver_origin()
        == Some(ResolutionCallableReceiverOrigin::CurrentInstance)
    {
        UsageHitKind::SelfReceiver
    } else {
        UsageHitKind::Reference
    }
}

fn push_reason(reasons: &mut Vec<EdgeIncompleteReason>, reason: EdgeIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// A generation-bound lazy facade retaining no workspace inverse map.
pub struct JavaNativeSelectedReferenceIndex {
    index: LazySelectedInverse<JavaInverseAdapter>,
}

impl SelectedInverseReferenceIndex for JavaNativeSelectedReferenceIndex {
    fn generation(&self) -> u64 {
        self.index.generation()
    }
    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        self.index.inverse_for(target)
    }
}

struct JavaInverseAdapter {
    java: Box<JavaAnalyzer>,
    projection_analyzer: Box<dyn IAnalyzer>,
}

impl SelectedInverseAdapter for JavaInverseAdapter {
    fn admit(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(u64, Self), SelectedInverseFailure> {
        let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
            return Err(SelectedInverseFailure::Unavailable(
                "the workspace has no Java analyzer".into(),
            ));
        };
        if cancellation.is_cancelled() {
            return Err(SelectedInverseFailure::Cancelled);
        }
        if !java
            .inner
            .selected_workspace_snapshots()
            .contains_key("java")
        {
            return Err(SelectedInverseFailure::Unavailable(
                "the selected Java source publication is unavailable".into(),
            ));
        }
        Ok((java.inner.project().analysis_generation(), Self {
            java: Box::new(java.clone()),
            projection_analyzer: if let Some(multi) =
                (analyzer as &dyn std::any::Any).downcast_ref::<brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer>()
            {
                Box::new(multi.clone())
            } else {
                Box::new(java.clone())
            },
        }))
    }

    fn current_generation(&self) -> u64 {
        self.java.inner.project().analysis_generation()
    }

    fn query(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> std::result::Result<Option<EdgeDerivationResult>, SelectedInverseFailure> {
        match java_selected_inverse_detailed_for(
            self.projection_analyzer.as_ref(),
            self.java.as_ref(),
            target,
            cancellation,
        ) {
            JavaSelectedReverseOutcome::Ready(answer) => Ok(Some(answer.edges)),
            JavaSelectedReverseOutcome::TargetUncovered(_) => Ok(None),
            JavaSelectedReverseOutcome::Unavailable(detail) => {
                Err(SelectedInverseFailure::Unavailable(detail))
            }
            JavaSelectedReverseOutcome::Stale(detail) => Err(SelectedInverseFailure::Stale(detail)),
            JavaSelectedReverseOutcome::Cancelled => Err(SelectedInverseFailure::Cancelled),
            JavaSelectedReverseOutcome::StoreError(detail) => {
                Err(SelectedInverseFailure::StoreError(detail))
            }
        }
    }
}

pub struct JavaNativeSelectedInverseProvider;

impl SelectedInverseReferenceProvider for JavaNativeSelectedInverseProvider {
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
    ) -> SelectedInverseIndexOutcome {
        let token = cancellation.cloned().unwrap_or_default();
        match LazySelectedInverse::<JavaInverseAdapter>::build(analyzer, &token) {
            Ok(index) => {
                SelectedInverseIndexOutcome::Ready(Arc::new(JavaNativeSelectedReferenceIndex {
                    index,
                }))
            }
            Err(failure) => failure.into(),
        }
    }
}

#[cfg(test)]
mod tests;
