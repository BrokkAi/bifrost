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
use super::super::query::schema::{reference_kind_label, usage_proof_label};
use super::super::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, ReferenceEdgeRow,
    forward_edges_for_file, inverse_edges_for_declaration,
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
use std::sync::Arc;

/// Domain separator for a reference-edge row's stable id.
const EDGE_ID_DOMAIN: &[u8] = b"bifrost.code_query.reference_edge.v1";

/// Per-request memo of derived edge sets plus the diagnostics already
/// reported, so one subject is derived once and one axis gap is reported once.
#[derive(Default)]
pub(super) struct EdgeTraversalCache {
    inverse: HashMap<CodeUnit, Arc<EdgeDerivationResult>>,
    forward: HashMap<ProjectFile, Arc<EdgeDerivationResult>>,
    reported: HashSet<(String, CodeQueryDiagnosticCode)>,
    reported_axes: HashSet<(Language, EdgeAxis)>,
}

impl EdgeTraversalCache {
    /// Derive (or replay) the inverse edges of one declaration.
    pub(super) fn inverse_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        declaration: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<EdgeDerivationResult> {
        if let Some(cached) = self.inverse.get(declaration) {
            return Arc::clone(cached);
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
        let EdgeCompleteness::Incomplete { reasons } = &result.completeness else {
            return;
        };
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
                    });
                }
                EdgeIncompleteReason::NoStructuralAdapter
                | EdgeIncompleteReason::UsageListingTruncated
                | EdgeIncompleteReason::UsageAnalysisFailed { .. }
                | EdgeIncompleteReason::Cancelled
                | EdgeIncompleteReason::OccurrenceRowsIncomplete { .. } => {
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
                    });
                }
            }
        }
    }
}

fn incomplete_reason_label(reason: &EdgeIncompleteReason) -> &'static str {
    match reason {
        EdgeIncompleteReason::AxisUnsupported(_) => "axis unsupported",
        EdgeIncompleteReason::NoStructuralAdapter => "no structural adapter",
        EdgeIncompleteReason::UsageListingTruncated => "the usage listing was truncated",
        EdgeIncompleteReason::UsageAnalysisFailed { .. } => "the usage analysis failed",
        EdgeIncompleteReason::Cancelled => "the derivation was cancelled",
        EdgeIncompleteReason::OccurrenceRowsIncomplete { .. } => {
            "the file's occurrence rows do not cover every reference role"
        }
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
