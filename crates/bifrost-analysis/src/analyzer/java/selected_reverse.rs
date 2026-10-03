//! Test-support Java inverse references over selected forward resolution.
//!
//! Candidate discovery uses the shared indexed reference-identity rows, and
//! every candidate is confirmed in its own selected Java import context. This
//! Candidate confirmation covers Java source files. Selected Kotlin and Scala
//! reference identities can keep a Java target's inverse explicitly open.

use super::JavaAnalyzer;
use crate::CancellationToken;
use crate::analyzer::resolution::ResolutionCompletion;
use crate::analyzer::store::resolution_operation::java_reverse_rows::{
    JavaReverseCandidateOutcome, JavaReverseConfirmed,
};
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::store::{Result, StoreError};
use crate::analyzer::structural::EdgeProvenance;
use crate::analyzer::structural::SiteClass;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, EdgeSite, ReferenceEdgeRow,
    ReferenceSiteClassifier,
};
use crate::analyzer::usages::{UsageHitKind, UsageProof};
use crate::analyzer::{
    CodeUnit, CodeUnitIndex, IAnalyzer, Language, ProjectFile, Range, resolve_analyzer,
};
use crate::hash::HashMap;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionSiteKind,
};
use std::sync::Arc;

#[derive(Debug)]
pub enum JavaSelectedReverseOutcome<T> {
    Ready(T),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

pub(super) struct JavaSelectedInverseResolution {
    pub(super) edges: EdgeDerivationResult,
    pub(super) peer_language_inventory_open: bool,
    // Edge proof also reflects incomplete caller-context evidence. Retain the
    // binding arm count separately so call projection can distinguish a
    // singleton provisional target from a genuinely ambiguous overload.
    binding_target_counts: HashMap<(ProjectFile, usize, usize), Option<usize>>,
}

impl JavaSelectedInverseResolution {
    pub(super) fn binding_target_count(&self, site: &EdgeSite) -> Option<usize> {
        self.binding_target_counts
            .get(&(
                site.file.clone(),
                site.range.start_byte,
                site.range.end_byte,
            ))
            .copied()
            .flatten()
    }
}

/// Resolve one target against selected Java source identities and contexts.
pub fn java_selected_inverse_for(
    java: &JavaAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> JavaSelectedReverseOutcome<EdgeDerivationResult> {
    match java_selected_inverse_detailed_for(java, target, cancellation) {
        JavaSelectedReverseOutcome::Ready(answer) => {
            JavaSelectedReverseOutcome::Ready(answer.edges)
        }
        JavaSelectedReverseOutcome::Unavailable(reason) => {
            JavaSelectedReverseOutcome::Unavailable(reason)
        }
        JavaSelectedReverseOutcome::Stale(reason) => JavaSelectedReverseOutcome::Stale(reason),
        JavaSelectedReverseOutcome::Cancelled => JavaSelectedReverseOutcome::Cancelled,
        JavaSelectedReverseOutcome::StoreError(reason) => {
            JavaSelectedReverseOutcome::StoreError(reason)
        }
    }
}

pub(super) fn java_selected_inverse_detailed_for(
    java: &JavaAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> JavaSelectedReverseOutcome<JavaSelectedInverseResolution> {
    match java_selected_inverse_for_inner(java, target, cancellation) {
        Ok(outcome) => outcome,
        Err(error) => JavaSelectedReverseOutcome::StoreError(error.to_string()),
    }
}

fn java_selected_inverse_for_inner(
    java: &JavaAnalyzer,
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
    let selected_languages = ["java", "kotlin", "scala"].map(str::to_owned);
    let snapshots = java
        .inner
        .analyzer_store()
        .workspace_snapshots_for_current_languages(
            java.inner.workspace_id(),
            &selected_languages,
        )?;
    let Some(_snapshot) = snapshots.get("java") else {
        return Ok(JavaSelectedReverseOutcome::Unavailable(
            "the workspace has no selected Java snapshot".into(),
        ));
    };
    let (masks, content_mounts) = match java
        .inner
        .selected_resolution_overlay_inputs(&snapshots, cancellation)?
    {
        SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } => (masks, content_mounts),
        SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
            return Ok(JavaSelectedReverseOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
            return Ok(JavaSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOverlayInputsOutcome::Cancelled => {
            return Ok(JavaSelectedReverseOutcome::Cancelled);
        }
    };
    let mut languages = vec![SelectedResolutionLanguage::new("java", Language::Java)];
    for (storage_language, language) in [("kotlin", Language::Kotlin), ("scala", Language::Scala)] {
        if snapshots.contains_key(storage_language) {
            languages.push(SelectedResolutionLanguage::new(storage_language, language));
        }
    }
    let input = SelectedResolutionOperationInput::new(
        java.inner.project(),
        java.inner.workspace_id(),
        &snapshots,
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let operation = match java
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(JavaSelectedReverseOutcome::Unavailable(format!(
                "{reason:?}"
            )));
        }
        SelectedResolutionOperationOpenOutcome::Stale(reason) => {
            return Ok(JavaSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(JavaSelectedReverseOutcome::Cancelled);
        }
    };
    let generation = java.inner.project().analysis_generation();
    let candidates = match operation.java_reverse_candidate_sites(target, cancellation)? {
        JavaReverseCandidateOutcome::Ready(candidates) => candidates,
        JavaReverseCandidateOutcome::Unavailable(reason) => {
            return Ok(JavaSelectedReverseOutcome::Unavailable(reason));
        }
        JavaReverseCandidateOutcome::Cancelled => {
            return Ok(JavaSelectedReverseOutcome::Cancelled);
        }
    };
    let mut context_metrics = SelectedResolutionContextMetrics;
    let confirmed = match operation.confirm_java_reverse_candidates(
        candidates,
        cancellation,
        &mut context_metrics,
    )? {
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
    if java.inner.project().analysis_generation() != generation {
        return Ok(JavaSelectedReverseOutcome::Stale(
            "Java selected reverse query crossed an analyzer generation".into(),
        ));
    }
    let answer = project_confirmed_references(java, target, generation, confirmed, cancellation)?;
    if java.inner.project().analysis_generation() != generation {
        return Ok(JavaSelectedReverseOutcome::Stale(
            "Java selected reverse projection crossed an analyzer generation".into(),
        ));
    }
    Ok(JavaSelectedReverseOutcome::Ready(answer))
}

fn project_confirmed_references(
    java: &JavaAnalyzer,
    target: &CodeUnit,
    generation: u64,
    confirmed: JavaReverseConfirmed,
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

    let mut files = HashMap::<ProjectFile, JavaSelectedReferenceFile<'_>>::default();
    let mut edges = Vec::new();
    let mut binding_target_counts = HashMap::default();
    for reference in confirmed.references {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("Java selected reverse query was cancelled"));
        }
        let answer = reference.answer;
        if !answer.binding().targets().contains(&confirmed.target) {
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
        let file = ProjectFile::new(
            java.inner.project().root(),
            reference.locator.relative_path(),
        );
        if !files.contains_key(&file) {
            let Some(source) = java.indexed_source(&file) else {
                return Err(StoreError::new(format!(
                    "selected Java reference has no indexed source: {file}"
                )));
            };
            if !java
                .inner
                .source_matches_selected_native_content(&file, &source)
            {
                return Err(StoreError::new(format!(
                    "selected Java reference source changed before projection: {file}"
                )));
            }
            files.insert(
                file.clone(),
                JavaSelectedReferenceFile::new(java, &file, &source),
            );
        }
        let projected_file = files
            .get(&file)
            .expect("selected Java source was projected");
        let owner = reference.owner;
        if answer
            .reference_owner()
            .is_some_and(|owner| owner.is_some())
            && owner.is_none()
        {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
        }
        let reference_kind = projected_file.classifier.as_ref().and_then(|classifier| {
            classifier.classify_reference_kind(metadata.start_byte(), metadata.end_byte(), target)
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
        if let Some(existing) = binding_target_counts.get_mut(&site_key) {
            if *existing != Some(binding_target_count) {
                *existing = None;
            }
        } else {
            binding_target_counts.insert(site_key, Some(binding_target_count));
        }
        edges.push(ReferenceEdgeRow {
            site: EdgeSite {
                file,
                range,
                ast_id,
                enclosing: owner,
            },
            target: target.clone(),
            reference_kind,
            proof: if answer.binding().targets().len() == 1
                && answer.binding().completion() == &ResolutionCompletion::Complete
            {
                UsageProof::Proven
            } else {
                UsageProof::Unproven
            },
            usage_kind: selected_usage_kind(metadata),
            site_class: SiteClass::UseSite,
            owner_relation: crate::analyzer::structural::OwnerRelation::Unknown,
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
        peer_language_inventory_open,
    })
}

fn selected_usage_kind(
    metadata: crate::analyzer::resolution::FactReferenceSiteMetadata,
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

struct JavaSelectedReferenceFile<'analyzer> {
    source_len: usize,
    line_starts: Box<[usize]>,
    classifier: Option<ReferenceSiteClassifier<'analyzer>>,
}

impl<'analyzer> JavaSelectedReferenceFile<'analyzer> {
    fn new(java: &'analyzer JavaAnalyzer, file: &ProjectFile, source: &str) -> Self {
        Self {
            source_len: source.len(),
            line_starts: compute_line_starts(source).into_boxed_slice(),
            classifier: ReferenceSiteClassifier::new(java, file),
        }
    }

    fn range(&self, start_byte: usize, end_byte: usize) -> Range {
        assert!(
            start_byte <= end_byte && end_byte <= self.source_len,
            "selected Java reference range must fit indexed source: {start_byte}..{end_byte} of {}",
            self.source_len,
        );
        Range {
            start_byte,
            end_byte,
            start_line: find_line_index_for_offset(&self.line_starts, start_byte) + 1,
            end_line: find_line_index_for_offset(&self.line_starts, end_byte.saturating_sub(1)) + 1,
        }
    }
}

/// Generation-bound lazy facade. It retains the analyzer, not an inverse map;
/// candidates and projected references live only for one target request.
pub struct JavaNativeSelectedReferenceIndex {
    generation: u64,
    java: Box<JavaAnalyzer>,
    cancellation: CancellationToken,
}

impl crate::analyzer::structural::reference_edges::SelectedInverseReferenceIndex
    for JavaNativeSelectedReferenceIndex
{
    fn generation(&self) -> u64 {
        self.generation
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        if self.java.inner.project().analysis_generation() != self.generation {
            return incomplete_inverse(
                self.generation,
                EdgeIncompleteReason::InverseIndexResolutionIncomplete,
            );
        }
        match java_selected_inverse_for(&self.java, target, &self.cancellation) {
            JavaSelectedReverseOutcome::Ready(answer) => answer,
            JavaSelectedReverseOutcome::Unavailable(detail) => {
                eprintln!("selected Java inverse query unavailable: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexTargetUncovered,
                )
            }
            JavaSelectedReverseOutcome::Stale(detail) => {
                eprintln!("selected Java inverse query stale: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexResolutionIncomplete,
                )
            }
            JavaSelectedReverseOutcome::Cancelled => {
                incomplete_inverse(self.generation, EdgeIncompleteReason::Cancelled)
            }
            JavaSelectedReverseOutcome::StoreError(detail) => {
                eprintln!("selected Java inverse query failed: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexResolutionIncomplete,
                )
            }
        }
    }
}

fn incomplete_inverse(generation: u64, reason: EdgeIncompleteReason) -> EdgeDerivationResult {
    EdgeDerivationResult {
        edges: Vec::new(),
        completeness: EdgeCompleteness::Incomplete {
            reasons: vec![reason],
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    }
}

pub struct JavaNativeSelectedInverseProvider;

impl crate::analyzer::structural::reference_edges::SelectedInverseReferenceProvider
    for JavaNativeSelectedInverseProvider
{
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::structural::reference_edges::SelectedInverseIndexOutcome {
        use crate::analyzer::structural::reference_edges::SelectedInverseIndexOutcome;
        let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
            return SelectedInverseIndexOutcome::Unavailable(
                "the workspace has no Java analyzer".into(),
            );
        };
        let token = cancellation.cloned().unwrap_or_default();
        if token.is_cancelled() {
            return SelectedInverseIndexOutcome::Cancelled;
        }
        if !java
            .inner
            .selected_workspace_snapshots()
            .contains_key("java")
        {
            return SelectedInverseIndexOutcome::Unavailable(
                "the selected Java source publication is unavailable".into(),
            );
        }
        SelectedInverseIndexOutcome::Ready(Arc::new(JavaNativeSelectedReferenceIndex {
            generation: java.inner.project().analysis_generation(),
            java: Box::new(java.clone()),
            cancellation: token,
        }))
    }
}

#[cfg(test)]
mod tests;
