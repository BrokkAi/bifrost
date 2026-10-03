//! The execution adapter between the query engine and the canonical
//! reference-edge derivation layer (#1479, Milestone 4).
//!
//! Edge rows follow the occurrence precedent: plain pipeline values derived on
//! demand and memoised per request, never semantic-artifact backed. Both
//! producers are cached separately -- a query that never says `edges-of` never
//! runs a usage query, and one that never says `edges-from` never runs a
//! resolution batch.
//!
//! The honesty rule lives here too: an axis the language's adapter does not
//! answer becomes an `Incomplete` diagnostic reported once per language, and a
//! truncated or failed derivation becomes one reported once per subject. An
//! empty answer is never silently a complete one.

use super::super::edges::EdgeAxis;
use super::super::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, ReferenceEdgeRow,
    SelectedInverseEdgeCache, forward_edges_for_file, inverse_edges_for_declaration,
};
use super::results::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryRange,
    CodeQueryReferenceEdge,
};
use super::{DeclarationValue, rel_path_string};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_rql::schema::{reference_kind_label, usage_proof_label};
#[cfg(any(test, feature = "test-support"))]
use serde::Serialize;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::native_resolution_test_support::SelectedReferenceInverseIndex;

/// Domain separator for a reference-edge row's stable id.
const EDGE_ID_DOMAIN: &[u8] = b"bifrost.code_query.reference_edge.v1";

/// Request-local counters for the comparable selected-Java `edges_of` route.
///
/// The handle is cheap to clone, so the public caller and the injected cache
/// observe the same counters without adding a lifetime to the ordinary query
/// execution state.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Default)]
pub struct SelectedEdgesOfTelemetry {
    inner: Arc<SelectedEdgesOfTelemetryInner>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
struct SelectedEdgesOfTelemetryInner {
    index_build_attempts: AtomicUsize,
    complete_index_builds: AtomicUsize,
    incomplete_index_builds: AtomicUsize,
    cancelled_index_builds: AtomicUsize,
    stale_index_builds: AtomicUsize,
    failed_index_builds: AtomicUsize,
    index_generation: AtomicU64,
    index_targets: AtomicUsize,
    index_nonempty_targets: AtomicUsize,
    index_references: AtomicUsize,
    index_edges: AtomicUsize,
    index_batches: AtomicUsize,
    provider_lookups: AtomicUsize,
    cache_hits: AtomicUsize,
    uncovered_target_lookups: AtomicUsize,
}

/// Immutable telemetry projection suitable for benchmark details and laws.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SelectedEdgesOfTelemetrySnapshot {
    pub index_build_attempts: usize,
    pub complete_index_builds: usize,
    pub incomplete_index_builds: usize,
    pub cancelled_index_builds: usize,
    pub stale_index_builds: usize,
    pub failed_index_builds: usize,
    pub index_generation: u64,
    pub index_targets: usize,
    pub index_nonempty_targets: usize,
    pub index_references: usize,
    pub index_edges: usize,
    pub index_batches: usize,
    pub provider_lookups: usize,
    pub cache_hits: usize,
    pub uncovered_target_lookups: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedEdgesOfTelemetry {
    pub fn snapshot(&self) -> SelectedEdgesOfTelemetrySnapshot {
        SelectedEdgesOfTelemetrySnapshot {
            index_build_attempts: self.inner.index_build_attempts.load(Ordering::Relaxed),
            complete_index_builds: self.inner.complete_index_builds.load(Ordering::Relaxed),
            incomplete_index_builds: self.inner.incomplete_index_builds.load(Ordering::Relaxed),
            cancelled_index_builds: self.inner.cancelled_index_builds.load(Ordering::Relaxed),
            stale_index_builds: self.inner.stale_index_builds.load(Ordering::Relaxed),
            failed_index_builds: self.inner.failed_index_builds.load(Ordering::Relaxed),
            index_generation: self.inner.index_generation.load(Ordering::Relaxed),
            index_targets: self.inner.index_targets.load(Ordering::Relaxed),
            index_nonempty_targets: self.inner.index_nonempty_targets.load(Ordering::Relaxed),
            index_references: self.inner.index_references.load(Ordering::Relaxed),
            index_edges: self.inner.index_edges.load(Ordering::Relaxed),
            index_batches: self.inner.index_batches.load(Ordering::Relaxed),
            provider_lookups: self.inner.provider_lookups.load(Ordering::Relaxed),
            cache_hits: self.inner.cache_hits.load(Ordering::Relaxed),
            uncovered_target_lookups: self.inner.uncovered_target_lookups.load(Ordering::Relaxed),
        }
    }

    pub(super) fn record_build_attempt(&self) {
        self.inner
            .index_build_attempts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_complete_build(&self, index: &SelectedReferenceInverseIndex) {
        self.inner
            .complete_index_builds
            .fetch_add(1, Ordering::Relaxed);
        self.record_index(index);
    }

    pub(super) fn record_incomplete_build(&self, index: &SelectedReferenceInverseIndex) {
        self.inner
            .incomplete_index_builds
            .fetch_add(1, Ordering::Relaxed);
        self.record_index(index);
    }

    pub(super) fn record_cancelled_build(&self) {
        self.inner
            .cancelled_index_builds
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_stale_build(&self) {
        self.inner
            .stale_index_builds
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_failed_build(&self) {
        self.inner
            .failed_index_builds
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_index(&self, index: &SelectedReferenceInverseIndex) {
        self.inner
            .index_generation
            .store(index.generation(), Ordering::Relaxed);
        self.inner
            .index_targets
            .store(index.target_count(), Ordering::Relaxed);
        self.inner
            .index_nonempty_targets
            .store(index.nonempty_target_count(), Ordering::Relaxed);
        self.inner
            .index_references
            .store(index.reference_count(), Ordering::Relaxed);
        self.inner
            .index_edges
            .store(index.edge_count(), Ordering::Relaxed);
        self.inner
            .index_batches
            .store(index.batch_count(), Ordering::Relaxed);
    }
}

/// Per-request memo of derived edge sets plus the diagnostics already
/// reported, so one subject is derived once and one axis gap is reported once.
#[derive(Default)]
pub(super) struct EdgeTraversalCache {
    inverse: HashMap<CodeUnit, Arc<EdgeDerivationResult>>,
    forward: HashMap<ProjectFile, Arc<EdgeDerivationResult>>,
    /// The selected inverse index of every language that registers one, built
    /// at most once per language per request.
    selected: SelectedInverseEdgeCache,
    reported: HashSet<(String, CodeQueryDiagnosticCode)>,
    reported_axes: HashSet<(Language, EdgeAxis)>,
    #[cfg(any(test, feature = "test-support"))]
    reported_selected_global: HashSet<(u64, SelectedGlobalIncompleteReason)>,
    #[cfg(any(test, feature = "test-support"))]
    reported_selected_local: HashSet<(CodeUnit, CodeQueryDiagnosticCode)>,
    #[cfg(any(test, feature = "test-support"))]
    selected_inverse: Option<Arc<SelectedReferenceInverseIndex>>,
    #[cfg(any(test, feature = "test-support"))]
    selected_java_telemetry: Option<SelectedEdgesOfTelemetry>,
}

impl EdgeTraversalCache {
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn with_selected_inverse(
        index: SelectedReferenceInverseIndex,
        telemetry: SelectedEdgesOfTelemetry,
    ) -> Self {
        Self {
            selected_inverse: Some(Arc::new(index)),
            selected_java_telemetry: Some(telemetry),
            ..Self::default()
        }
    }

    /// Derive (or replay) the inverse edges of one declaration.
    pub(super) fn inverse_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        declaration: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<EdgeDerivationResult> {
        if let Some(cached) = self.inverse.get(declaration) {
            #[cfg(any(test, feature = "test-support"))]
            if let Some(telemetry) = &self.selected_java_telemetry {
                telemetry.inner.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            return Arc::clone(cached);
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(index) = &self.selected_inverse {
            let telemetry = self
                .selected_java_telemetry
                .as_ref()
                .expect("a selected inverse index always carries telemetry");
            telemetry
                .inner
                .provider_lookups
                .fetch_add(1, Ordering::Relaxed);
            if !index.covers_target(declaration) {
                telemetry
                    .inner
                    .uncovered_target_lookups
                    .fetch_add(1, Ordering::Relaxed);
            }
            let derived = index.inverse_for(declaration);
            self.inverse
                .insert(declaration.clone(), Arc::clone(&derived));
            return derived;
        }
        // A language that registers a selected inverse provider answers from
        // its own whole-workspace index, including when that index refuses to
        // build: deriving the same question a second way would report a
        // refusal as an answer.
        if let Some(selected) = self
            .selected
            .inverse_for(analyzer, declaration, cancellation)
        {
            let derived = Arc::new(selected);
            self.inverse
                .insert(declaration.clone(), Arc::clone(&derived));
            return derived;
        }
        let derived = Arc::new(inverse_edges_for_declaration(
            analyzer,
            declaration,
            cancellation,
        ));
        self.inverse
            .insert(declaration.clone(), Arc::clone(&derived));
        derived
    }

    /// Derive (or replay) the forward edges of one file. `None` only on
    /// cancellation.
    pub(super) fn forward_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> Option<Arc<EdgeDerivationResult>> {
        if let Some(cached) = self.forward.get(file) {
            return Some(Arc::clone(cached));
        }
        let token = cancellation.cloned().unwrap_or_default();
        let derived = Arc::new(forward_edges_for_file(analyzer, file, &token).ok()?);
        self.forward.insert(file.clone(), Arc::clone(&derived));
        Some(derived)
    }

    /// Turn one derivation's completeness into typed diagnostics.
    ///
    /// `subject` is the human-readable thing the derivation was about (a
    /// declaration's fq-name, or a workspace-relative path); `language` is the
    /// adapter the axis claims belong to.
    pub(super) fn report_completeness(
        &mut self,
        subject: &str,
        language: Language,
        result: &EdgeDerivationResult,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        self.report_completeness_for_subject(subject, None, language, result, diagnostics);
    }

    pub(super) fn report_inverse_completeness(
        &mut self,
        declaration: &CodeUnit,
        language: Language,
        result: &EdgeDerivationResult,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let subject = declaration.fq_name();
        self.report_completeness_for_subject(
            &subject,
            Some(declaration),
            language,
            result,
            diagnostics,
        );
    }

    fn report_completeness_for_subject(
        &mut self,
        subject: &str,
        _inverse_declaration: Option<&CodeUnit>,
        language: Language,
        result: &EdgeDerivationResult,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let EdgeCompleteness::Incomplete { reasons } = &result.completeness else {
            return;
        };
        #[cfg(any(test, feature = "test-support"))]
        if self.selected_inverse.as_ref().is_some_and(|index| {
            result.provenance == super::super::edges::EdgeProvenance::Inverse
                && result.generation == index.generation()
        }) {
            self.report_selected_completeness(
                subject,
                _inverse_declaration.expect(
                    "selected inverse completeness must retain its exact declaration subject",
                ),
                language,
                result.generation,
                reasons,
                diagnostics,
            );
            return;
        }
        for reason in reasons {
            match reason {
                EdgeIncompleteReason::AxisUnsupported(axis) => {
                    // An unsupported axis is a property of the adapter, so it
                    // is reported once per language rather than once per
                    // subject.
                    if !self.reported_axes.insert((language, *axis)) {
                        continue;
                    }
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::EdgeAxisUnsupported,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: language.config_label(),
                        message: format!(
                            "structural adapter for {} does not support reference-edge axis(es): {}",
                            language.config_label(),
                            axis.label()
                        ),
                    exhausted_roots: Vec::new(),
                    });
                }
                EdgeIncompleteReason::NoStructuralAdapter
                | EdgeIncompleteReason::UsageListingTruncated
                | EdgeIncompleteReason::UsageAnalysisFailed { .. }
                | EdgeIncompleteReason::Cancelled
                | EdgeIncompleteReason::OccurrenceRowsIncomplete { .. }
                | EdgeIncompleteReason::ReferenceEnumerationIncomplete
                | EdgeIncompleteReason::ForwardResolutionIncomplete
                | EdgeIncompleteReason::ForwardAdmissionIncomplete
                | EdgeIncompleteReason::ForwardMetadataIncomplete
                | EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete
                | EdgeIncompleteReason::InverseIndexResolutionIncomplete
                | EdgeIncompleteReason::InverseIndexAdmissionIncomplete
                | EdgeIncompleteReason::InverseIndexMetadataIncomplete
                | EdgeIncompleteReason::InverseIndexTargetUncovered
                | EdgeIncompleteReason::TimeBudgetExceeded
                | EdgeIncompleteReason::SelectedInverseIndexUnavailable { .. } => {
                    let code = CodeQueryDiagnosticCode::EdgeDerivationIncomplete;
                    if !self.reported.insert((subject.to_string(), code)) {
                        continue;
                    }
                    diagnostics.push(CodeQueryDiagnostic {
                        code,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: language.config_label(),
                        message: format!(
                            "{subject} has an incomplete reference-edge derivation ({}); its edge rows are not the whole set",
                            incomplete_reason_label(reason)
                        ),
                    exhausted_roots: Vec::new(),
                    });
                }
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn report_selected_completeness(
        &mut self,
        subject: &str,
        declaration: &CodeUnit,
        language: Language,
        generation: u64,
        reasons: &[EdgeIncompleteReason],
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let mut newly_reported_global = Vec::new();
        let mut subject_local = Vec::new();
        for reason in reasons {
            if let Some(key) = selected_global_reason(reason) {
                if self.reported_selected_global.insert((generation, key)) {
                    newly_reported_global.push(reason);
                }
            } else {
                subject_local.push(reason);
            }
        }
        if !newly_reported_global.is_empty() {
            diagnostics.push(CodeQueryDiagnostic {
                exhausted_roots: Vec::new(),
                code: CodeQueryDiagnosticCode::EdgeDerivationIncomplete,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "selected Java inverse index generation {generation} is incomplete ({newly_reported_global:?}); it does not cover every requested reference-edge axis"
                ),
            });
        }
        if !subject_local.is_empty() {
            let code = CodeQueryDiagnosticCode::EdgeDerivationIncomplete;
            if self
                .reported_selected_local
                .insert((declaration.clone(), code))
            {
                diagnostics.push(CodeQueryDiagnostic {
                exhausted_roots: Vec::new(),
                    code,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: language.config_label(),
                    message: format!(
                        "{subject} has an incomplete selected Java inverse-index derivation ({subject_local:?}); it does not cover every requested reference-edge axis"
                    ),
                });
            }
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SelectedGlobalIncompleteReason {
    Axis(EdgeAxis),
    ReferenceEnumeration,
    Resolution,
    Metadata,
    TimeBudget,
}

#[cfg(any(test, feature = "test-support"))]
fn selected_global_reason(reason: &EdgeIncompleteReason) -> Option<SelectedGlobalIncompleteReason> {
    match reason {
        EdgeIncompleteReason::AxisUnsupported(EdgeAxis::KindClassification) => None,
        EdgeIncompleteReason::AxisUnsupported(axis) => {
            Some(SelectedGlobalIncompleteReason::Axis(*axis))
        }
        EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete => {
            Some(SelectedGlobalIncompleteReason::ReferenceEnumeration)
        }
        EdgeIncompleteReason::InverseIndexResolutionIncomplete => {
            Some(SelectedGlobalIncompleteReason::Resolution)
        }
        EdgeIncompleteReason::InverseIndexMetadataIncomplete => {
            Some(SelectedGlobalIncompleteReason::Metadata)
        }
        EdgeIncompleteReason::TimeBudgetExceeded => {
            Some(SelectedGlobalIncompleteReason::TimeBudget)
        }
        EdgeIncompleteReason::NoStructuralAdapter
        | EdgeIncompleteReason::UsageListingTruncated
        | EdgeIncompleteReason::UsageAnalysisFailed { .. }
        | EdgeIncompleteReason::Cancelled
        | EdgeIncompleteReason::OccurrenceRowsIncomplete { .. }
        | EdgeIncompleteReason::ReferenceEnumerationIncomplete
        | EdgeIncompleteReason::ForwardResolutionIncomplete
        | EdgeIncompleteReason::ForwardAdmissionIncomplete
        | EdgeIncompleteReason::ForwardMetadataIncomplete
        | EdgeIncompleteReason::InverseIndexAdmissionIncomplete
        | EdgeIncompleteReason::InverseIndexTargetUncovered
        | EdgeIncompleteReason::SelectedInverseIndexUnavailable { .. } => None,
    }
}

fn incomplete_reason_label(reason: &EdgeIncompleteReason) -> String {
    match reason {
        EdgeIncompleteReason::AxisUnsupported(_) => "axis unsupported".to_string(),
        EdgeIncompleteReason::NoStructuralAdapter => "no structural adapter".to_string(),
        EdgeIncompleteReason::UsageListingTruncated => {
            "the usage listing was truncated".to_string()
        }
        EdgeIncompleteReason::UsageAnalysisFailed {
            reason_kind,
            reason,
        } => format!("the usage analysis failed, {reason_kind}: {reason}"),
        EdgeIncompleteReason::Cancelled => "the derivation was cancelled".to_string(),
        EdgeIncompleteReason::OccurrenceRowsIncomplete { uncovered_roles } => format!(
            "the file's occurrence rows do not cover every reference role, uncovered: {uncovered_roles:?}"
        ),
        EdgeIncompleteReason::ReferenceEnumerationIncomplete => {
            "native reference enumeration was incomplete".to_string()
        }
        EdgeIncompleteReason::ForwardResolutionIncomplete => {
            "native forward resolution was incomplete".to_string()
        }
        EdgeIncompleteReason::ForwardAdmissionIncomplete => {
            "native forward edge admission was incomplete".to_string()
        }
        EdgeIncompleteReason::ForwardMetadataIncomplete => {
            "native forward edge metadata was incomplete".to_string()
        }
        EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete => {
            "selected inverse index reference enumeration was incomplete".to_string()
        }
        EdgeIncompleteReason::InverseIndexResolutionIncomplete => {
            "selected inverse index resolution was incomplete".to_string()
        }
        EdgeIncompleteReason::InverseIndexAdmissionIncomplete => {
            "selected inverse index edge admission was incomplete".to_string()
        }
        EdgeIncompleteReason::InverseIndexMetadataIncomplete => {
            "selected inverse index edge metadata was incomplete".to_string()
        }
        EdgeIncompleteReason::TimeBudgetExceeded => {
            "selected inverse query exceeded its time budget".to_string()
        }
        EdgeIncompleteReason::InverseIndexTargetUncovered => {
            "the declaration was outside the selected inverse index".to_string()
        }
        EdgeIncompleteReason::SelectedInverseIndexUnavailable {
            reason_kind,
            reason,
        } => format!("the selected inverse index is {reason_kind}: {reason}"),
    }
}

/// One reference-edge row travelling through the pipeline.
///
/// The target and enclosing declarations are indexed at expansion time (the
/// same `IndexedDeclarations` route every declaration-producing step uses), so
/// rendering needs no second lookup and `edge-target` is a projection.
#[derive(Debug, Clone)]
pub(super) struct EdgeValue {
    pub(super) row: Arc<ReferenceEdgeRow>,
    pub(super) target: DeclarationValue,
    pub(super) enclosing: Option<DeclarationValue>,
}

impl EdgeValue {
    pub(super) fn key(&self) -> EdgeKey {
        EdgeKey {
            file: self.row.site.file.clone(),
            start_byte: self.row.site.range.start_byte,
            end_byte: self.row.site.range.end_byte,
            target: self.target.unit.clone(),
            reference_kind: self.row.reference_kind.map(|kind| kind as u8),
            proof: self.row.proof,
            usage_kind: self.row.usage_kind,
            site_class: self.row.site_class,
            owner_relation: self.row.owner_relation,
            provenance: self.row.provenance,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.row.site.file
    }

    pub(super) fn id(&self) -> String {
        let row = &self.row;
        let mut digest = LengthDelimitedDigest::new(EDGE_ID_DOMAIN);
        digest.push(rel_path_string(&row.site.file).as_bytes());
        digest.push(&row.site.range.start_byte.to_le_bytes());
        digest.push(&row.site.range.end_byte.to_le_bytes());
        digest.push(self.target.unit.fq_name().as_bytes());
        digest.push(
            row.reference_kind
                .map_or("", reference_kind_label)
                .as_bytes(),
        );
        digest.push(row.usage_kind.wire_label().as_bytes());
        digest.push(row.provenance.label().as_bytes());
        digest.finish().to_string()
    }
}

/// Dedup identity: every compared field of the canonical row. Two rows that
/// disagree on proof, kind, or classification are two answers, which is the
/// entire point of the domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EdgeKey {
    pub(super) file: ProjectFile,
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    pub(super) target: CodeUnit,
    pub(super) reference_kind: Option<u8>,
    pub(super) proof: crate::analyzer::usages::UsageProof,
    pub(super) usage_kind: crate::analyzer::usages::UsageHitKind,
    pub(super) site_class: super::super::edges::SiteClass,
    pub(super) owner_relation: super::super::edges::OwnerRelation,
    pub(super) provenance: super::super::edges::EdgeProvenance,
}

/// The public projection of one edge row, minus the declaration rendering only
/// the engine can do.
pub(super) fn public_edge(
    value: &EdgeValue,
    range: CodeQueryRange,
    target: super::results::CodeQueryDeclaration,
    enclosing: Option<super::results::CodeQueryDeclaration>,
) -> CodeQueryReferenceEdge {
    let row = &value.row;
    CodeQueryReferenceEdge {
        id: value.id(),
        ast_id: row.site.ast_id.clone(),
        path: rel_path_string(&row.site.file),
        language: crate::analyzer::common::language_for_file(&row.site.file).config_label(),
        range,
        start_byte: row.site.range.start_byte,
        end_byte: row.site.range.end_byte,
        target,
        enclosing_declaration: enclosing,
        reference_kind: row.reference_kind.map(reference_kind_label),
        proof: usage_proof_label(row.proof),
        usage_kind: row.usage_kind.wire_label(),
        site_class: row.site_class.label(),
        owner_relation: row.owner_relation.label(),
        provenance: row.provenance.label(),
        generation: row.generation,
    }
}
