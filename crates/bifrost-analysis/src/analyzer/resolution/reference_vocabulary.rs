use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;
use brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance;
use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;
use brokk_bifrost_core::analyzer::structural::edges::SiteClass;

use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

use crate::analyzer::CodeUnit;
use crate::analyzer::DeclarationId;
use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;
use brokk_bifrost_core::analyzer::usages::model::ReferenceKind;
use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;
use brokk_bifrost_core::analyzer::usages::model::UsageHitSurface;
use brokk_bifrost_core::analyzer::usages::model::UsageProof;

/// The site end of an edge: where in the workspace the reference is spelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeSite {
    pub file: ProjectFile,
    pub range: Range,
    /// The content-scoped AST identity of the site token, present exactly when
    /// the producer can address the token as a facts-arena node. Occurrence-row
    /// forward edges carry it directly; native fact and inverse rows may still
    /// be addressed exactly by file plus byte range while their AST join is
    /// unavailable.
    /// Never fabricated: `None` means the site is addressed by `file` plus
    /// byte range over the same content, which is exact, not heuristic.
    pub ast_id: Option<String>,
    /// The declaration lexically enclosing the site, when known.
    pub enclosing: Option<CodeUnit>,
}

/// One canonical reference edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceEdgeRow {
    pub site: EdgeSite,
    pub target: CodeUnit,
    /// Typed source-level classification, absent when no producer could state
    /// one. Absence is "unclassified", never a kind.
    pub reference_kind: Option<ReferenceKind>,
    pub proof: UsageProof,
    /// This exact target is one member of a closed ambiguous binding.
    /// Ranking graphs may retain it as a candidate edge while preserving the
    /// row's `Unproven` proof and the graph's incomplete inbound evidence.
    pub ambiguous_candidate: bool,
    pub usage_kind: UsageHitKind,
    pub site_class: SiteClass,
    /// How the site's enclosing declaration relates to the target, computed
    /// once by [`classify_owner_relation`] for both producers. `Unknown` when
    /// the classifier cannot relate the owners; never silently `External`.
    pub owner_relation: OwnerRelation,
    pub provenance: EdgeProvenance,
    /// The workspace generation both endpoints were read from. A comparison
    /// across two generations is refused, not fudged.
    pub generation: u64,
}

impl ReferenceEdgeRow {
    pub fn target_id(&self) -> DeclarationId {
        self.target.declaration_id()
    }

    /// The exact target declaration carries its source language in the
    /// declaration identity and source path. JVM edges may cross Java, Kotlin
    /// and Scala while retaining that target language.
    pub fn target_language(&self) -> Language {
        self.target.source().declaration_language()
    }

    pub fn source_id(&self) -> Option<DeclarationId> {
        self.site.enclosing.as_ref().map(CodeUnit::declaration_id)
    }

    /// Whether this edge belongs to the given usage surface. Definition sites
    /// and import bindings are editor-visible but not external usages, exactly
    /// as on the usage-hit surface this delegates to.
    pub fn included_in(&self, surface: UsageHitSurface) -> bool {
        self.usage_kind.included_in(surface)
    }

    /// Whether this source range overlaps any declaration span belonging to
    /// the target graph node in the same file.
    ///
    /// This predicate is intentionally independent of usage surface. A
    /// consumer may need the incumbent definition-overlap exclusion for a
    /// retained editor-only row such as an unproven self-receiver without
    /// reclassifying that row as an external usage.
    pub fn overlaps_target_definition_spans(
        &self,
        target_definition_spans: &[(ProjectFile, Range)],
    ) -> bool {
        target_definition_spans.iter().any(|(file, target)| {
            file == &self.site.file
                && target.start_byte < self.site.range.end_byte
                && self.site.range.start_byte < target.end_byte
        })
    }

    /// Retain references inside the target's declaration for navigation, while
    /// excluding them from external usage counts and budgets. Declaration
    /// spans, rather than the innermost owner, also cover nested field types.
    #[doc(hidden)]
    pub fn classify_target_self_reference(
        &mut self,
        target_definition_spans: &[(ProjectFile, Range)],
    ) {
        if self.overlaps_target_definition_spans(target_definition_spans) {
            self.usage_kind = UsageHitKind::SelfReceiver;
        }
    }

    /// Whether this row can enter the external workspace usage graph before
    /// graph-node membership is applied.
    ///
    /// The canonical row inventory deliberately retains self type/path
    /// references for editor and query consumers. The workspace graph has the
    /// narrower incumbent contract: it excludes every reference whose source
    /// range overlaps any declaration belonging to the target graph node in
    /// that file. `target_definition_spans` must contain file-tagged ranges from
    /// the same generation as this row, including every declaration grouped
    /// into a C++ or C# graph node. Graph-node membership and grouped self-edge
    /// exclusion remain the consumer's separate responsibility.
    pub fn included_in_external_usage_graph(
        &self,
        target_definition_spans: &[(ProjectFile, Range)],
    ) -> bool {
        if !self.included_in(UsageHitSurface::ExternalUsages) {
            return false;
        }
        if self.site.enclosing.is_none() {
            return false;
        }
        !self.overlaps_target_definition_spans(target_definition_spans)
    }
}

/// Why an edge derivation's rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeIncompleteReason {
    /// The adapter declares the axis unsupported, so absence of rows for it
    /// says nothing.
    AxisUnsupported(EdgeAxis),
    /// No structural provider is registered for the language in question.
    NoStructuralAdapter,
    /// The usage listing was cut short (too many call sites, or a scan
    /// budget), so absent inverse edges are unknown, not absent.
    UsageListingTruncated,
    /// The usage analysis reported a typed failure for the seed declaration.
    UsageAnalysisFailed { reason_kind: String, reason: String },
    /// The usage query was cancelled before completing.
    Cancelled,
    /// A selected inverse query reached its soft time budget after confirming
    /// only part of the requested candidate-blob inventory.
    TimeBudgetExceeded,
    /// The file's occurrence rows do not cover these reference-producing
    /// roles, so forward edges at sites of those roles may be missing. Roles
    /// the file does cover are unaffected: a consumer narrowed to one role
    /// checks [`EdgeDerivationResult::covers_forward_role`] rather than this
    /// blanket reason.
    OccurrenceRowsIncomplete {
        uncovered_roles: Vec<OccurrenceRole>,
    },
    /// The native selected source could not prove that it enumerated every
    /// reference occurrence in the requested snapshot.
    ReferenceEnumerationIncomplete,
    /// One admitted native reference retained an open binding, so omitted
    /// target edges may still exist even though every retained target remains
    /// available as unproven inventory.
    ForwardResolutionIncomplete,
    /// One native reference retained an open receiver/admission boundary, so
    /// its known channels remain available but another graph channel may
    /// still exist.
    ForwardAdmissionIncomplete,
    /// Exact source occurrence or declaration correspondence was unavailable
    /// for at least one native reference edge.
    ForwardMetadataIncomplete,
    /// A selected native inverse index could not prove that it enumerated
    /// every reference occurrence in its generation-bound workspace.
    InverseIndexReferenceEnumerationIncomplete,
    /// A selected native inverse index retained an open binding, so a target's
    /// indexed incoming rows may omit additional references.
    InverseIndexResolutionIncomplete,
    /// A selected native inverse index retained an open receiver/admission
    /// boundary, so a target's indexed incoming rows may omit another channel.
    InverseIndexAdmissionIncomplete,
    /// A selected native inverse index lacked required source or declaration
    /// correspondence for at least one reference edge.
    InverseIndexMetadataIncomplete,
    /// The requested declaration is not in the selected inverse index's exact
    /// covered target universe, so an empty bucket cannot prove absence.
    InverseIndexTargetUncovered,
    /// The language's registered selected inverse provider built no index for
    /// this generation, so no declaration in that language has a selected
    /// inverse answer. `reason_kind` names which refusal the provider gave and
    /// `reason` carries its exact detail.
    SelectedInverseIndexUnavailable { reason_kind: String, reason: String },
}

/// Which axes this derivation layer answers.
pub const EDGE_PRODUCER_AXES: &[EdgeAxis] = &[
    EdgeAxis::ForwardProjection,
    EdgeAxis::InverseProjection,
    EdgeAxis::KindClassification,
    EdgeAxis::ProofAttribution,
    EdgeAxis::OwnerClassification,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeCompleteness {
    Complete,
    Incomplete { reasons: Vec<EdgeIncompleteReason> },
}

impl EdgeCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Whether rows for `axis` can be trusted to be the complete set.
    pub fn covers(&self, axis: EdgeAxis) -> bool {
        if !EDGE_PRODUCER_AXES.contains(&axis) {
            return false;
        }
        match self {
            Self::Complete => true,
            Self::Incomplete { reasons } => !reasons.iter().any(|reason| match reason {
                EdgeIncompleteReason::AxisUnsupported(unsupported) => *unsupported == axis,
                EdgeIncompleteReason::UsageListingTruncated
                | EdgeIncompleteReason::UsageAnalysisFailed { .. } => {
                    axis == EdgeAxis::InverseProjection
                }
                EdgeIncompleteReason::OccurrenceRowsIncomplete { .. } => {
                    axis == EdgeAxis::ForwardProjection
                }
                EdgeIncompleteReason::ReferenceEnumerationIncomplete
                | EdgeIncompleteReason::ForwardResolutionIncomplete
                | EdgeIncompleteReason::ForwardAdmissionIncomplete => {
                    axis == EdgeAxis::ForwardProjection
                }
                EdgeIncompleteReason::ForwardMetadataIncomplete => matches!(
                    axis,
                    EdgeAxis::ForwardProjection
                        | EdgeAxis::KindClassification
                        | EdgeAxis::OwnerClassification
                ),
                EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete
                | EdgeIncompleteReason::InverseIndexResolutionIncomplete
                | EdgeIncompleteReason::InverseIndexAdmissionIncomplete
                | EdgeIncompleteReason::InverseIndexTargetUncovered
                | EdgeIncompleteReason::TimeBudgetExceeded
                | EdgeIncompleteReason::SelectedInverseIndexUnavailable { .. } => {
                    axis == EdgeAxis::InverseProjection
                }
                EdgeIncompleteReason::InverseIndexMetadataIncomplete => matches!(
                    axis,
                    EdgeAxis::InverseProjection
                        | EdgeAxis::KindClassification
                        | EdgeAxis::OwnerClassification
                ),
                EdgeIncompleteReason::NoStructuralAdapter | EdgeIncompleteReason::Cancelled => true,
            }),
        }
    }
}

/// The owner-relation rule, with the inheritance test supplied by the caller:
/// `inherits(hierarchy, site, target)` says whether `target` is among `site`'s
/// ancestors.
/// A same-owner value reference is a member reference only when its target
/// belongs to a declaration rather than directly to a namespace. Sharing a
/// module does not turn a free function or constant into a self receiver.
#[doc(hidden)]
pub fn is_same_owner_member_reference(relation: OwnerRelation, target: &CodeUnit) -> bool {
    relation == OwnerRelation::SameOwner && target.fq().namespace_prefix().is_none()
}
