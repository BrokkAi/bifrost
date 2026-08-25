//! The canonical reference-edge derivation layer (issue #1479).
//!
//! One edge states that a source site refers to a target declaration, with the
//! reference kind, the proof, the usage-kind classification and the producer
//! that derived it. Two producers project into this one row shape:
//!
//! - the *forward* producer walks a file's classified occurrence rows
//!   ([`super::occurrence_rows`]) and emits an edge per resolved target;
//! - the *inverse* producer runs the usage index for a seed declaration (the
//!   same [`UsageFinder`] query the `references-of` step performs) and emits
//!   an edge per usage hit.
//!
//! Neither producer re-implements the other's analysis: forward rows are the
//! resolver's own answers and inverse rows are the usage strategies' own
//! answers, so a disagreement between the two sets is a real disagreement
//! between the two production analyses -- which is exactly what the parity
//! assertions built on this layer exist to surface.
//!
//! Deliberately not a stored third graph: rows are derived on demand from the
//! two existing producers, and every row is stamped with the workspace
//! generation it was derived in so a comparison can refuse to relate rows
//! from two different snapshots.

use super::edges::{EdgeAxis, EdgeProvenance, OwnerRelation, SiteClass};
use super::facts::Span;
use super::kinds::{NormalizedKind, Role};
use super::lexical_environment::environment_for_file;
use super::occurrence_rows::{
    OccurrenceCompleteness, OccurrenceRow, OccurrenceTarget, OccurrencesCancelled, ast_id,
    occurrences_for_file,
};
use super::occurrences::{ALL_OCCURRENCE_ROLES, OccurrenceClass, OccurrenceRole};
use super::resolution::EnvironmentAxis;
use crate::analyzer::usages::{
    FuzzyResult, ReferenceEngine, ReferenceHit, ReferenceKind, UsageHit, UsageHitKind,
    UsageHitSurface, UsageProof, UsageQueryCompletion,
};
use crate::analyzer::{CodeUnit, DeclarationId, IAnalyzer, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};

/// Bounds for one inverse derivation. The file bound matches the reference
/// traversal's scan bound; the hit bound is per seed declaration.
pub const MAX_INVERSE_EDGE_FILES: usize = 20_000;
pub const MAX_INVERSE_EDGE_HITS: usize = 5_000;

pub fn reference_hit_for_target(
    analyzer: &dyn IAnalyzer,
    hit: UsageHit,
    target: CodeUnit,
    proof: UsageProof,
) -> ReferenceHit {
    let kind = hit.reference_kind.or_else(|| {
        classify_reference_kind(
            analyzer,
            &hit.file,
            hit.start_offset,
            hit.end_offset,
            &target,
        )
    });
    ReferenceHit {
        file: hit.file,
        range: Range {
            start_byte: hit.start_offset,
            end_byte: hit.end_offset,
            start_line: hit.line,
            end_line: hit.line,
        },
        enclosing_unit: hit.enclosing,
        kind,
        resolved: target,
        confidence: (hit.confidence.clamp(0.0, 1.0) * 1_000_000.0) as u32,
        usage_kind: hit.kind,
        proof,
    }
}

pub fn reference_hits_from_bounded_sample(
    analyzer: &dyn IAnalyzer,
    sample_hits: impl IntoIterator<Item = UsageHit>,
    target: CodeUnit,
    limit: usize,
) -> Vec<ReferenceHit> {
    sample_hits
        .into_iter()
        .take(limit)
        .map(|hit| reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Proven))
        .collect()
}

pub fn reference_hits_for_target(
    analyzer: &dyn IAnalyzer,
    result: FuzzyResult,
    target: &CodeUnit,
) -> (Vec<ReferenceHit>, bool) {
    reference_hits_from_fuzzy_result(analyzer, result, std::slice::from_ref(target))
}

fn reference_hits_from_fuzzy_result(
    analyzer: &dyn IAnalyzer,
    result: FuzzyResult,
    fallback_targets: &[CodeUnit],
) -> (Vec<ReferenceHit>, bool) {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } => (
            hits_by_overload
                .into_iter()
                .flat_map(|(target, hits)| {
                    hits.into_iter().map(move |hit| {
                        reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Proven)
                    })
                })
                .chain(unproven_by_overload.into_iter().flat_map(|(target, hits)| {
                    hits.into_iter().map(move |hit| {
                        reference_hit_for_target(
                            analyzer,
                            hit,
                            target.clone(),
                            UsageProof::Unproven,
                        )
                    })
                }))
                .collect(),
            false,
        ),
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => (
            hits_by_overload
                .into_iter()
                .flat_map(|(target, hits)| {
                    hits.into_iter().map(move |hit| {
                        reference_hit_for_target(
                            analyzer,
                            hit,
                            target.clone(),
                            UsageProof::Unproven,
                        )
                    })
                })
                .collect(),
            false,
        ),
        FuzzyResult::TooManyCallsites {
            sample_hits, limit, ..
        } => fallback_targets.first().map_or_else(
            || (Vec::new(), true),
            |target| {
                (
                    reference_hits_from_bounded_sample(
                        analyzer,
                        sample_hits,
                        target.clone(),
                        limit,
                    ),
                    true,
                )
            },
        ),
        FuzzyResult::Failure { .. } => (Vec::new(), false),
    }
}

pub fn classify_reference_kind(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start_byte: usize,
    end_byte: usize,
    target: &CodeUnit,
) -> Option<ReferenceKind> {
    let language = crate::analyzer::common::language_for_file(file);
    let facts = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)?
        .structural_facts(file)?;
    let covers = |span: Span| span.start_byte <= start_byte && end_byte <= span.end_byte;
    let mut candidates = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            node.name.is_some_and(covers)
                && matches!(
                    node.kind,
                    NormalizedKind::Call | NormalizedKind::FieldAccess
                )
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(_, node)| {
        (
            usize::from(node.kind != NormalizedKind::Call),
            node.range.end_byte - node.range.start_byte,
        )
    });
    if let Some((id, node)) = candidates.first().copied() {
        let receiver_role = if node.kind == NormalizedKind::FieldAccess {
            Role::Object
        } else {
            Role::Receiver
        };
        let receiver = facts
            .role_targets(id as u32, receiver_role)
            .next()
            .map(|role| role.span.text(facts.source()).trim());
        if receiver.is_some_and(|text| matches!(text, "super" | "base")) {
            return Some(ReferenceKind::SuperCall);
        }
        let static_receiver = analyzer
            .parent_of(target)
            .filter(|owner| owner.is_class())
            .is_some_and(|owner| receiver == Some(owner.short_name()));
        if static_receiver {
            return Some(ReferenceKind::StaticReference);
        }
        if node.kind == NormalizedKind::Call {
            return Some(
                if target.is_class() || target.kind().display_lowercase() == "constructor" {
                    ReferenceKind::ConstructorCall
                } else {
                    ReferenceKind::MethodCall
                },
            );
        }
        let mut parent = Some(id as u32);
        while let Some(current) = parent {
            let fact = facts.node(current);
            if fact.kind == NormalizedKind::Assignment {
                return Some(
                    if facts
                        .role_targets(current, Role::Left)
                        .any(|role| covers(role.span))
                    {
                        ReferenceKind::FieldWrite
                    } else {
                        ReferenceKind::FieldRead
                    },
                );
            }
            parent = fact.parent;
        }
        return Some(ReferenceKind::FieldRead);
    }
    if target.is_class() {
        let nearest = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                node.range.start_byte <= start_byte && end_byte <= node.range.end_byte
            })
            .min_by_key(|(_, node)| node.range.end_byte - node.range.start_byte)
            .map(|(id, _)| id as u32);
        let mut current = nearest;
        while let Some(id) = current {
            let node = facts.node(id);
            if node.kind.satisfies(NormalizedKind::Declaration) {
                if node.kind == NormalizedKind::Class && node.name.is_none_or(|name| !covers(name))
                {
                    return Some(ReferenceKind::Inheritance);
                }
                break;
            }
            current = node.parent;
        }
    }
    target.is_class().then_some(ReferenceKind::TypeReference)
}

/// The site end of an edge: where in the workspace the reference is spelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeSite {
    pub file: ProjectFile,
    pub range: Range,
    /// The content-scoped AST identity of the site token, present exactly when
    /// the producer can address the token as a facts-arena node (forward rows
    /// always can; inverse rows gain it in the classification milestone).
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

    pub fn source_id(&self) -> Option<DeclarationId> {
        self.site.enclosing.as_ref().map(CodeUnit::declaration_id)
    }

    /// Whether this edge belongs to the given usage surface. Definition sites
    /// and import bindings are editor-visible but not external usages, exactly
    /// as on the usage-hit surface this delegates to.
    pub fn included_in(&self, surface: UsageHitSurface) -> bool {
        self.usage_kind.included_in(surface)
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
    /// The file's occurrence rows do not cover these reference-producing
    /// roles, so forward edges at sites of those roles may be missing. Roles
    /// the file does cover are unaffected: a consumer narrowed to one role
    /// checks [`EdgeDerivationResult::covers_forward_role`] rather than this
    /// blanket reason.
    OccurrenceRowsIncomplete {
        uncovered_roles: Vec<OccurrenceRole>,
    },
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
                EdgeIncompleteReason::NoStructuralAdapter | EdgeIncompleteReason::Cancelled => true,
            }),
        }
    }
}

/// One producer's derived edges with an explicit account of what is missing.
#[derive(Debug, Clone)]
pub struct EdgeDerivationResult {
    pub edges: Vec<ReferenceEdgeRow>,
    pub completeness: EdgeCompleteness,
    /// Which producer derived this result. Also the reason
    /// [`Self::covers`] exists: a forward derivation can never vouch for the
    /// inverse projection, however complete it is, and vice versa.
    pub provenance: EdgeProvenance,
    pub generation: u64,
}

/// Work performed by one common-engine run. These counters are semantic cost
/// accounting rather than timing: they stay useful in deterministic regressions
/// and make an incomplete result explicit at the same boundary as its rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReferenceWork {
    pub candidate_files: usize,
    pub scanned_files: usize,
    pub scanned_source_bytes: usize,
    pub emitted_edges: usize,
}

/// Canonical output of either reference-engine workload.
#[derive(Debug, Clone)]
pub struct ReferenceRun {
    pub edges: Vec<ReferenceEdgeRow>,
    pub completeness: EdgeCompleteness,
    pub generation: u64,
    pub work: ReferenceWork,
}

impl<'a> ReferenceEngine<'a> {
    /// Resolve references to exact declaration targets through the common
    /// candidate-planning and admission pipeline, then project every overload
    /// bucket into canonical edge rows without losing its target identity.
    pub fn references_to_edges(
        &self,
        analyzer: &dyn IAnalyzer,
        targets: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
        max_source_bytes: Option<usize>,
    ) -> ReferenceRun {
        let query = self.query_with_provider_and_source_budget(
            analyzer,
            targets,
            None,
            max_files,
            max_usages,
            max_source_bytes,
        );
        let generation = analyzer.project().analysis_generation();
        let mut reasons = match query.completion {
            UsageQueryCompletion::Complete => Vec::new(),
            UsageQueryCompletion::Cancelled => vec![EdgeIncompleteReason::Cancelled],
            UsageQueryCompletion::CandidateFilesBudgetExhausted
            | UsageQueryCompletion::SourceBytesBudgetExhausted => {
                vec![EdgeIncompleteReason::UsageListingTruncated]
            }
        };
        let candidate_files = query.candidate_files.len();
        let scanned_source_bytes = query.scanned_source_bytes;
        if let FuzzyResult::Failure {
            reason_kind,
            reason,
            ..
        } = &query.result
        {
            reasons.push(EdgeIncompleteReason::UsageAnalysisFailed {
                reason_kind: reason_kind.clone(),
                reason: reason.clone(),
            });
        }
        let (hits, truncated) = reference_hits_from_fuzzy_result(analyzer, query.result, targets);
        if truncated {
            reasons.push(EdgeIncompleteReason::UsageListingTruncated);
        }
        let edges =
            edge_rows_from_reference_hits(analyzer, hits, generation, Some(self.cancellation()));
        let emitted_edges = edges.len();
        ReferenceRun {
            edges,
            completeness: if reasons.is_empty() {
                EdgeCompleteness::Complete
            } else {
                EdgeCompleteness::Incomplete { reasons }
            },
            generation,
            work: ReferenceWork {
                candidate_files,
                scanned_files: candidate_files,
                scanned_source_bytes,
                emitted_edges,
            },
        }
    }

    /// Stream the explicitly selected files through the same canonical
    /// occurrence-to-declaration relation. The input slice is the hard scope:
    /// this method never discovers or opens another file as a scan unit.
    pub fn scan_file_edges(&self, analyzer: &dyn IAnalyzer, files: &[ProjectFile]) -> ReferenceRun {
        let generation = analyzer.project().analysis_generation();
        let mut edges = Vec::new();
        let mut reasons = Vec::new();
        let mut scanned_files = 0usize;
        let mut scanned_source_bytes = 0usize;
        for file in files {
            if self.cancellation().is_cancelled() {
                reasons.push(EdgeIncompleteReason::Cancelled);
                break;
            }
            scanned_files += 1;
            scanned_source_bytes = scanned_source_bytes.saturating_add(
                analyzer
                    .indexed_source(file)
                    .map_or(0, |source| source.len()),
            );
            match forward_edges_for_file(analyzer, file, self.cancellation()) {
                Ok(result) => {
                    edges.extend(result.edges);
                    if let EdgeCompleteness::Incomplete {
                        reasons: file_reasons,
                    } = result.completeness
                    {
                        reasons.extend(file_reasons);
                    }
                }
                Err(OccurrencesCancelled) => {
                    reasons.push(EdgeIncompleteReason::Cancelled);
                    break;
                }
            }
        }
        let emitted_edges = edges.len();
        ReferenceRun {
            edges,
            completeness: if reasons.is_empty() {
                EdgeCompleteness::Complete
            } else {
                EdgeCompleteness::Incomplete { reasons }
            },
            generation,
            work: ReferenceWork {
                candidate_files: files.len(),
                scanned_files,
                scanned_source_bytes,
                emitted_edges,
            },
        }
    }
}

impl EdgeDerivationResult {
    fn incomplete(
        reasons: Vec<EdgeIncompleteReason>,
        provenance: EdgeProvenance,
        generation: u64,
    ) -> Self {
        Self {
            edges: Vec::new(),
            completeness: EdgeCompleteness::Incomplete { reasons },
            provenance,
            generation,
        }
    }

    /// Whether a forward derivation's rows are the complete set for sites of
    /// one occurrence role. Occurrence incompleteness in an unrelated role
    /// (a package segment the adapter cannot namespace, say) must not make a
    /// method-call parity claim inconclusive.
    pub fn covers_forward_role(&self, role: OccurrenceRole) -> bool {
        if self.provenance != EdgeProvenance::Forward {
            return false;
        }
        match &self.completeness {
            EdgeCompleteness::Complete => true,
            EdgeCompleteness::Incomplete { reasons } => {
                !reasons.iter().any(|reason| match reason {
                    EdgeIncompleteReason::OccurrenceRowsIncomplete { uncovered_roles } => {
                        uncovered_roles.contains(&role)
                    }
                    EdgeIncompleteReason::AxisUnsupported(axis) => {
                        *axis == EdgeAxis::ForwardProjection
                    }
                    EdgeIncompleteReason::NoStructuralAdapter | EdgeIncompleteReason::Cancelled => {
                        true
                    }
                    EdgeIncompleteReason::UsageListingTruncated
                    | EdgeIncompleteReason::UsageAnalysisFailed { .. } => false,
                })
            }
        }
    }

    /// Whether this result's rows can be trusted to be the complete set for
    /// `axis`. The other producer's projection axis is never covered: one
    /// producer vouching for the other's output is exactly the confusion this
    /// layer exists to remove.
    pub fn covers(&self, axis: EdgeAxis) -> bool {
        let foreign_projection = match self.provenance {
            EdgeProvenance::Forward => EdgeAxis::InverseProjection,
            EdgeProvenance::Inverse => EdgeAxis::ForwardProjection,
        };
        if axis == foreign_projection {
            return false;
        }
        self.completeness.covers(axis)
    }
}

fn supports_edge_axis(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    axis: EdgeAxis,
) -> Option<bool> {
    let language = crate::analyzer::common::language_for_file(file);
    analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .map(|provider| provider.structural_supports_edge_axis(axis))
}

/// How the declaration enclosing a use site relates to the edge's target.
/// One computation for both producers, so the classification can never drift
/// between the forward and inverse surfaces.
///
/// The owner of a unit is the unit itself when it is class-like, else its
/// parent declaration. `Unknown` is the honest answer whenever an owner is
/// missing, or the owners are distinct classes and no type-hierarchy provider
/// can rule inheritance in or out; it is never collapsed into `External`.
pub fn classify_owner_relation(
    analyzer: &dyn IAnalyzer,
    site_enclosing: Option<&CodeUnit>,
    target: &CodeUnit,
) -> OwnerRelation {
    let Some(enclosing) = site_enclosing else {
        return OwnerRelation::Unknown;
    };
    if enclosing == target {
        return OwnerRelation::SelfReference;
    }
    let owner_of = |unit: &CodeUnit| {
        if unit.is_class() {
            Some(unit.clone())
        } else {
            analyzer.parent_of(unit)
        }
    };
    let (Some(site_owner), Some(target_owner)) = (owner_of(enclosing), owner_of(target)) else {
        return OwnerRelation::Unknown;
    };
    if site_owner == target_owner {
        return OwnerRelation::SameOwner;
    }
    if !target_owner.is_class() {
        return OwnerRelation::External;
    }
    if !site_owner.is_class() {
        return OwnerRelation::External;
    }
    match analyzer.type_hierarchy_provider() {
        Some(hierarchy) => {
            if hierarchy.get_ancestors(&site_owner).contains(&target_owner) {
                OwnerRelation::InheritedOwner
            } else {
                OwnerRelation::External
            }
        }
        None => OwnerRelation::Unknown,
    }
}

/// Classify a forward edge from the structured occurrence role and the owner
/// relation already computed for the row.
///
/// An `ImportTarget` row is an import binding only when its exact facts node
/// belongs to a lexical-environment import binder. A re-export has the same
/// occurrence role but no import-binder fact, so it deliberately makes no
/// `Reexport` claim. A `SelfReference` owner relation proves recursion for
/// member, receiver, and value occurrences. `SameOwner` is intentionally not
/// enough: `other.helper()` and `this.helper()` share that relation, while
/// only the latter is a self receiver. Type/path/pattern occurrences remain
/// references even when the target happens to share an owner.
fn classify_forward_usage_kind(
    row: &OccurrenceRow,
    import_target_nodes: &HashSet<u32>,
    owner_relation: OwnerRelation,
) -> UsageHitKind {
    let import_binder_selected =
        row.role == OccurrenceRole::ImportTarget && import_target_nodes.contains(&row.node);
    classify_forward_usage_kind_from_evidence(row.role, import_binder_selected, owner_relation)
}

/// Return the exact occurrence nodes whose enclosing import fact has a
/// structured lexical-environment import binder. Export/re-export facts are
/// not import facts, so an `ImportTarget` row outside this set retains the
/// ordinary `Reference` fallback.
fn import_target_nodes_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<HashSet<u32>> {
    let environment = environment_for_file(analyzer, file);
    if !environment
        .completeness
        .covers(EnvironmentAxis::ImportBinders)
    {
        return None;
    }
    let facts = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| {
            provider.structural_language() == crate::analyzer::common::language_for_file(file)
        })
        .and_then(|provider| provider.structural_facts(file))?;
    Some(
        environment
            .bindings
            .iter()
            .filter(|binding| binding.import.is_some())
            .filter_map(|binding| binding.node)
            .filter(|node| {
                facts
                    .occurrence_roles(*node)
                    .contains(&OccurrenceRole::ImportTarget)
            })
            .collect(),
    )
}

fn classify_forward_usage_kind_from_evidence(
    role: OccurrenceRole,
    import_binder_selected: bool,
    owner_relation: OwnerRelation,
) -> UsageHitKind {
    if role == OccurrenceRole::ImportTarget && import_binder_selected {
        return UsageHitKind::Import;
    }
    if matches!(
        role,
        OccurrenceRole::ReceiverPosition
            | OccurrenceRole::MemberPosition
            | OccurrenceRole::ValueReference
    ) && matches!(owner_relation, OwnerRelation::SelfReference)
    {
        return UsageHitKind::SelfReceiver;
    }
    UsageHitKind::Reference
}

/// Per-file map from an identifier token's exact byte range to its
/// facts-arena AST identity, built once per file so a batch of inverse hits
/// pays one arena pass instead of one per hit.
///
/// The lookup is exact, not heuristic: the facts snapshot and the usage hit
/// address the same analyzed content, so range equality over it is the same
/// join the forward producer states through `OccurrenceRow::ast_id`.
struct SiteIdentityIndex {
    by_range: HashMap<(usize, usize), String>,
}

impl SiteIdentityIndex {
    fn build(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Self {
        let language = crate::analyzer::common::language_for_file(file);
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .and_then(|provider| provider.structural_facts(file));
        let mut by_range = HashMap::default();
        if let Some(facts) = facts {
            let identity = facts.source_identity();
            for (node, fact) in facts.nodes().iter().enumerate() {
                if fact.kind == NormalizedKind::Identifier {
                    by_range
                        .entry((fact.range.start_byte, fact.range.end_byte))
                        .or_insert_with(|| ast_id(identity, node as u32));
                }
            }
        }
        Self { by_range }
    }

    fn ast_id(&self, range: &Range) -> Option<String> {
        self.by_range
            .get(&(range.start_byte, range.end_byte))
            .cloned()
    }
}

/// Project one usage hit into the canonical row shape.
///
/// A `Vec` and not a set on purpose: two hits that disagree only on proof or
/// kind are two rows here, where the usage-hit identity would collapse them.
/// The disagreement is the data.
pub(crate) fn edge_rows_from_reference_hits(
    analyzer: &dyn IAnalyzer,
    hits: impl IntoIterator<Item = ReferenceHit>,
    generation: u64,
    cancellation: Option<&CancellationToken>,
) -> Vec<ReferenceEdgeRow> {
    let hits: Vec<ReferenceHit> = hits.into_iter().collect();
    let mut import_target_ranges: HashMap<ProjectFile, Option<Vec<ExactImportTarget>>> =
        HashMap::default();
    for hit in hits
        .iter()
        .filter(|hit| hit.usage_kind == UsageHitKind::Import)
    {
        import_target_ranges
            .entry(hit.file.clone())
            .or_insert_with(|| {
                exact_import_target_ranges_for_file(analyzer, &hit.file, cancellation)
            });
    }
    let mut site_identities: HashMap<ProjectFile, SiteIdentityIndex> = HashMap::default();
    hits.into_iter()
        .map(|hit| {
            let range = import_target_ranges
                .get(&hit.file)
                .map_or(hit.range, |ranges| {
                    ranges
                        .as_deref()
                        .map_or(hit.range, |ranges| exact_import_target_range(ranges, &hit))
                });
            let site_class = match hit.usage_kind {
                UsageHitKind::Definition | UsageHitKind::OverrideDeclaration => {
                    SiteClass::DeclarationSite
                }
                UsageHitKind::Reference
                | UsageHitKind::Import
                | UsageHitKind::Reexport
                | UsageHitKind::SelfReceiver => SiteClass::UseSite,
            };
            let owner_relation =
                classify_owner_relation(analyzer, Some(&hit.enclosing_unit), &hit.resolved);
            let ast_id = site_identities
                .entry(hit.file.clone())
                .or_insert_with(|| SiteIdentityIndex::build(analyzer, &hit.file))
                .ast_id(&range);
            ReferenceEdgeRow {
                site: EdgeSite {
                    file: hit.file,
                    range,
                    ast_id,
                    enclosing: Some(hit.enclosing_unit),
                },
                target: hit.resolved,
                reference_kind: hit.kind,
                proof: hit.proof,
                usage_kind: hit.usage_kind,
                site_class,
                owner_relation,
                provenance: EdgeProvenance::Inverse,
                generation,
            }
        })
        .collect()
}

/// Usage scanners can report a Java import hit over the whole qualified path,
/// while the forward occurrence surface identifies the exact `ImportTarget`
/// token. Narrow the inverse site only when the structured occurrence rows
/// prove one matching target; an incomplete or ambiguous result retains the
/// scanner's original range instead of guessing from source text.
struct ExactImportTarget {
    range: Range,
    target: CodeUnit,
}

fn exact_import_target_ranges_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: Option<&CancellationToken>,
) -> Option<Vec<ExactImportTarget>> {
    let owned_cancellation;
    let cancellation = match cancellation {
        Some(cancellation) => cancellation,
        None => {
            owned_cancellation = CancellationToken::new();
            &owned_cancellation
        }
    };
    let rows = match occurrences_for_file(analyzer, file, cancellation) {
        Ok(rows) => rows,
        Err(OccurrencesCancelled) => return None,
    };
    if !rows.completeness.covers(OccurrenceRole::ImportTarget) {
        return None;
    }
    Some(
        rows.rows
            .iter()
            .filter_map(|row| {
                (row.role == OccurrenceRole::ImportTarget)
                    .then_some(&row.target)
                    .and_then(|target| match target {
                        OccurrenceTarget::Resolved(units) => Some(
                            units
                                .iter()
                                .cloned()
                                .map(|target| ExactImportTarget {
                                    range: row.range,
                                    target,
                                })
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    })
            })
            .flatten()
            .collect(),
    )
}

fn exact_import_target_range(targets: &[ExactImportTarget], hit: &ReferenceHit) -> Range {
    let mut matching_ranges = targets.iter().filter(|target| {
        target.target == hit.resolved
            && target.range.start_byte >= hit.range.start_byte
            && target.range.end_byte <= hit.range.end_byte
    });
    let Some(range) = matching_ranges.next() else {
        return hit.range;
    };
    matching_ranges.next().map_or(range.range, |_| hit.range)
}

/// Every inverse edge of one seed declaration: the sites the usage index can
/// enumerate that point at it, in the canonical row shape.
pub fn inverse_edges_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> EdgeDerivationResult {
    let generation = analyzer.project().analysis_generation();
    let file = declaration.source();
    match supports_edge_axis(analyzer, file, EdgeAxis::InverseProjection) {
        Some(true) => {}
        Some(false) => {
            return EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::InverseProjection,
                )],
                EdgeProvenance::Inverse,
                generation,
            );
        }
        None => {
            return EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::NoStructuralAdapter],
                EdgeProvenance::Inverse,
                generation,
            );
        }
    }

    let mut finder = ReferenceEngine::new();
    if let Some(cancellation) = cancellation {
        finder = finder.with_cancellation(cancellation.clone());
    }
    let run = finder.references_to_edges(
        analyzer,
        std::slice::from_ref(declaration),
        MAX_INVERSE_EDGE_FILES,
        MAX_INVERSE_EDGE_HITS,
        None,
    );
    let mut reasons = match run.completeness {
        EdgeCompleteness::Complete => Vec::new(),
        EdgeCompleteness::Incomplete { reasons } => reasons,
    };
    if supports_edge_axis(analyzer, file, EdgeAxis::OwnerClassification) != Some(true) {
        reasons.push(EdgeIncompleteReason::AxisUnsupported(
            EdgeAxis::OwnerClassification,
        ));
    }

    EdgeDerivationResult {
        edges: run.edges,
        completeness: if reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete { reasons }
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    }
}

/// Every forward edge of one file: each reference-class occurrence that the
/// resolver resolved to declared targets, in the canonical row shape.
///
/// An occurrence whose resolution failed, stopped at a boundary, or landed on
/// a file-local lexical binding contributes no edge -- that is data about the
/// forward surface, not incompleteness: the parity comparison finding an
/// inverse edge with no forward counterpart at such a site is exactly the
/// mined regression shape this layer exists to expose. Ambiguity is preserved
/// as uncertainty: a multi-target resolution emits one row per target, each
/// `Unproven`.
pub fn forward_edges_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: &CancellationToken,
) -> Result<EdgeDerivationResult, OccurrencesCancelled> {
    let generation = analyzer.project().analysis_generation();
    match supports_edge_axis(analyzer, file, EdgeAxis::ForwardProjection) {
        Some(true) => {}
        Some(false) => {
            return Ok(EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::ForwardProjection,
                )],
                EdgeProvenance::Forward,
                generation,
            ));
        }
        None => {
            return Ok(EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::NoStructuralAdapter],
                EdgeProvenance::Forward,
                generation,
            ));
        }
    }

    let occurrences = occurrences_for_file(analyzer, file, cancellation)?;
    let import_target_nodes = import_target_nodes_for_file(analyzer, file).unwrap_or_default();
    let mut edges = Vec::new();
    for row in &occurrences.rows {
        let OccurrenceTarget::Resolved(units) = &row.target else {
            continue;
        };
        let proof = if units.len() == 1 {
            UsageProof::Proven
        } else {
            UsageProof::Unproven
        };
        for unit in units {
            let kind = classify_reference_kind(
                analyzer,
                file,
                row.range.start_byte,
                row.range.end_byte,
                unit,
            );
            let owner_relation = classify_owner_relation(analyzer, row.enclosing.as_ref(), unit);
            edges.push(ReferenceEdgeRow {
                site: EdgeSite {
                    file: file.clone(),
                    range: row.range,
                    ast_id: Some(row.ast_id()),
                    enclosing: row.enclosing.clone(),
                },
                target: unit.clone(),
                reference_kind: kind,
                proof,
                usage_kind: classify_forward_usage_kind(row, &import_target_nodes, owner_relation),
                site_class: SiteClass::UseSite,
                owner_relation,
                provenance: EdgeProvenance::Forward,
                generation,
            });
        }
    }

    let mut reasons = Vec::new();
    if let OccurrenceCompleteness::Incomplete { .. } = &occurrences.completeness {
        // Name the exact reference-producing roles the file does not cover,
        // so a consumer narrowed to one role can tell whether the gap is its
        // own. DeclarationName is included because the inverse-direction
        // parity join reads declaration-name tokens.
        let uncovered_roles = ALL_OCCURRENCE_ROLES
            .iter()
            .copied()
            .filter(|role| {
                (role.class() == OccurrenceClass::Reference
                    || *role == OccurrenceRole::DeclarationName)
                    && !occurrences.completeness.covers(*role)
            })
            .collect::<Vec<_>>();
        if !uncovered_roles.is_empty() {
            reasons.push(EdgeIncompleteReason::OccurrenceRowsIncomplete { uncovered_roles });
        }
    }
    if supports_edge_axis(analyzer, file, EdgeAxis::OwnerClassification) != Some(true) {
        reasons.push(EdgeIncompleteReason::AxisUnsupported(
            EdgeAxis::OwnerClassification,
        ));
    }
    let completeness = if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    };
    Ok(EdgeDerivationResult {
        edges,
        completeness,
        provenance: EdgeProvenance::Forward,
        generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        files: Vec<ProjectFile>,
    }

    impl Fixture {
        fn new(language: Language, sources: &[(&str, &str)]) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let files = sources
                .iter()
                .map(|(relative_path, source)| {
                    let file = ProjectFile::new(root.clone(), *relative_path);
                    file.write(source).expect("write fixture source");
                    file
                })
                .collect::<Vec<_>>();
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build_ephemeral(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            )
            .expect("ephemeral workspace should build");
            Self {
                _temp: temp,
                workspace,
                files,
            }
        }

        fn analyzer(&self) -> &dyn IAnalyzer {
            self.workspace.analyzer()
        }

        fn declaration(&self, fq_suffix: &str) -> CodeUnit {
            self.analyzer()
                .all_declarations()
                .find(|unit| unit.fq_name().ends_with(fq_suffix))
                .unwrap_or_else(|| panic!("fixture must declare {fq_suffix}"))
        }
    }

    const JAVA_TARGET: &str =
        "package fixture;\n\npublic class Registry {\n    public void register() {\n    }\n}\n";
    const JAVA_CALLER: &str = "package fixture;\n\npublic class Startup {\n    void boot(Registry registry) {\n        registry.register();\n    }\n}\n";

    /// The acceptance shape for this milestone: one plain proven cross-file
    /// call yields a forward row and an inverse row that agree field for field
    /// on everything except the fields that legitimately differ between the
    /// producers (`provenance`, and the forward-only `ast_id`).
    #[test]
    fn forward_and_inverse_producers_agree_on_a_plain_proven_call() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                ("src/Startup.java", JAVA_CALLER),
            ],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry.register");

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        assert!(
            inverse.completeness.is_complete(),
            "inverse derivation must be complete: {:?}",
            inverse.completeness
        );
        let inverse_call = inverse
            .edges
            .iter()
            .find(|edge| edge.usage_kind == UsageHitKind::Reference)
            .expect("the call site must appear as an inverse edge");

        let caller_file = &fixture.files[1];
        let forward = forward_edges_for_file(analyzer, caller_file, &CancellationToken::new())
            .expect("not cancelled");
        let forward_call = forward
            .edges
            .iter()
            .find(|edge| edge.target.fq_name() == target.fq_name())
            .expect("the call site must appear as a forward edge");

        assert_eq!(forward_call.site.file, inverse_call.site.file);
        assert_eq!(
            forward_call.site.range.start_byte,
            inverse_call.site.range.start_byte
        );
        assert_eq!(
            forward_call.site.range.end_byte,
            inverse_call.site.range.end_byte
        );
        assert_eq!(forward_call.target.fq_name(), inverse_call.target.fq_name());
        assert_eq!(forward_call.reference_kind, inverse_call.reference_kind);
        assert_eq!(forward_call.reference_kind, Some(ReferenceKind::MethodCall));
        assert_eq!(forward_call.proof, UsageProof::Proven);
        assert_eq!(inverse_call.proof, UsageProof::Proven);
        assert_eq!(forward_call.usage_kind, inverse_call.usage_kind);
        assert_eq!(forward_call.site_class, SiteClass::UseSite);
        assert_eq!(forward_call.generation, inverse_call.generation);
        assert_eq!(forward_call.provenance, EdgeProvenance::Forward);
        assert_eq!(inverse_call.provenance, EdgeProvenance::Inverse);
        assert!(forward_call.site.ast_id.is_some());
        assert_eq!(forward_call.site.ast_id, inverse_call.site.ast_id);
        assert_eq!(forward_call.owner_relation, inverse_call.owner_relation);
        assert_ne!(forward_call.owner_relation, OwnerRelation::Unknown);
    }

    #[test]
    fn fuzzy_overload_buckets_keep_their_exact_edge_targets() {
        let fixture = Fixture::new(
            Language::Java,
            &[(
                "src/Overloads.java",
                "package fixture; class Overloads { void call(int value) {} void call(String value) {} void caller() {} }",
            )],
        );
        let analyzer = fixture.analyzer();
        let mut overloads = analyzer
            .all_declarations()
            .filter(|unit| unit.fq_name().ends_with("Overloads.call"))
            .collect::<Vec<_>>();
        overloads.sort_by(|left, right| left.signature().cmp(&right.signature()));
        assert_eq!(overloads.len(), 2);
        let enclosing = fixture.declaration("Overloads.caller");
        let hits_by_overload = overloads
            .iter()
            .enumerate()
            .map(|(index, target)| {
                (
                    target.clone(),
                    BTreeSet::from([UsageHit::new(
                        fixture.files[0].clone(),
                        1,
                        index,
                        index + 1,
                        enclosing.clone(),
                        1.0,
                        "call",
                    )]),
                )
            })
            .collect();
        let (hits, truncated) = reference_hits_from_fuzzy_result(
            analyzer,
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload: HashMap::default(),
                unproven_total_by_overload: HashMap::default(),
            },
            &overloads,
        );
        assert!(!truncated);
        assert_eq!(hits.len(), 2);
        assert_eq!(
            hits.into_iter()
                .map(|hit| hit.resolved)
                .collect::<BTreeSet<_>>(),
            overloads.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn reference_engine_file_scan_never_expands_its_hard_scope() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                ("src/Startup.java", JAVA_CALLER),
                (
                    "src/Other.java",
                    "package fixture; class Other { void unrelated() {} }",
                ),
            ],
        );
        let run = ReferenceEngine::new().scan_file_edges(fixture.analyzer(), &fixture.files[1..2]);
        assert_eq!(run.work.candidate_files, 1);
        assert_eq!(run.work.scanned_files, 1);
        assert!(
            run.edges
                .iter()
                .all(|edge| edge.site.file == fixture.files[1])
        );
    }

    const JAVA_BASE: &str =
        "package fixture;\n\npublic class Base {\n    public void ping() {\n    }\n}\n";
    const JAVA_DERIVED: &str = "package fixture;\n\npublic class Derived extends Base {\n    void run() {\n        helper();\n        run();\n    }\n\n    void helper() {\n    }\n}\n";

    /// The one shared classifier answers every relation the issue names, from
    /// the units alone, so both producers inherit identical classifications by
    /// construction.
    #[test]
    fn the_owner_classifier_states_each_relation() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Base.java", JAVA_BASE),
                ("src/Derived.java", JAVA_DERIVED),
            ],
        );
        let analyzer = fixture.analyzer();
        let base_ping = fixture.declaration("Base.ping");
        let derived_run = fixture.declaration("Derived.run");
        let derived_helper = fixture.declaration("Derived.helper");

        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &derived_helper),
            OwnerRelation::SameOwner
        );
        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &derived_run),
            OwnerRelation::SelfReference
        );
        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &base_ping),
            OwnerRelation::InheritedOwner
        );
        assert_eq!(
            classify_owner_relation(analyzer, None, &base_ping),
            OwnerRelation::Unknown
        );
    }

    #[test]
    fn forward_usage_kind_uses_only_role_and_owner_evidence() {
        assert_eq!(
            classify_forward_usage_kind_from_evidence(
                OccurrenceRole::ImportTarget,
                true,
                OwnerRelation::External,
            ),
            UsageHitKind::Import
        );
        assert_eq!(
            classify_forward_usage_kind_from_evidence(
                OccurrenceRole::MemberPosition,
                false,
                OwnerRelation::SameOwner,
            ),
            UsageHitKind::Reference
        );
        assert_eq!(
            classify_forward_usage_kind_from_evidence(
                OccurrenceRole::ValueReference,
                false,
                OwnerRelation::SelfReference
            ),
            UsageHitKind::SelfReceiver
        );
        assert_eq!(
            classify_forward_usage_kind_from_evidence(
                OccurrenceRole::ImportTarget,
                false,
                OwnerRelation::External,
            ),
            UsageHitKind::Reference
        );

        // A type/path reference can share an owner without being a
        // self/this receiver, and an inherited or unknown owner does not prove
        // recursion. Those cases retain the public fallback.
        for role in [
            OccurrenceRole::TypeOperand,
            OccurrenceRole::PathSegment,
            OccurrenceRole::PatternPosition,
        ] {
            assert_eq!(
                classify_forward_usage_kind_from_evidence(role, false, OwnerRelation::SameOwner),
                UsageHitKind::Reference
            );
        }
        assert_eq!(
            classify_forward_usage_kind_from_evidence(
                OccurrenceRole::MemberPosition,
                false,
                OwnerRelation::InheritedOwner
            ),
            UsageHitKind::Reference
        );
        assert_eq!(
            classify_forward_usage_kind_from_evidence(
                OccurrenceRole::MemberPosition,
                false,
                OwnerRelation::Unknown,
            ),
            UsageHitKind::Reference
        );
    }

    #[test]
    fn forward_and_inverse_classify_import_binding() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                (
                    "src/client/Startup.java",
                    "package client;\n\nimport fixture.Registry;\n\nclass Startup {\n    Registry registry;\n}\n",
                ),
            ],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry");
        let forward =
            forward_edges_for_file(analyzer, &fixture.files[1], &CancellationToken::new())
                .expect("not cancelled");
        let import_edge = forward
            .edges
            .iter()
            .find(|edge| {
                edge.target == target
                    && edge.site.range.start_byte
                        == fixture.files[1]
                            .read_to_string()
                            .expect("fixture source")
                            .find("Registry;")
                            .expect("import target")
            })
            .expect("the import target must appear as a forward edge");
        assert_eq!(import_edge.usage_kind, UsageHitKind::Import);

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        let inverse_import = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.site.file == fixture.files[1] && edge.site.range == import_edge.site.range
            })
            .expect("the import target must appear as an inverse edge");
        assert_eq!(inverse_import.usage_kind, UsageHitKind::Import);
    }

    #[test]
    fn forward_and_inverse_classify_recursive_self_reference() {
        let fixture = Fixture::new(
            Language::Java,
            &[(
                "src/Registry.java",
                "package fixture;\n\nclass Registry {\n    void register() {\n        register();\n    }\n}\n",
            )],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry.register");
        let call_start = fixture.files[0]
            .read_to_string()
            .expect("fixture source")
            .rfind("register();")
            .expect("recursive call");
        let forward =
            forward_edges_for_file(analyzer, &fixture.files[0], &CancellationToken::new())
                .expect("not cancelled");
        let forward_self = forward
            .edges
            .iter()
            .find(|edge| edge.target == target && edge.site.range.start_byte == call_start)
            .expect("recursive call must appear as a forward edge");
        assert_eq!(forward_self.usage_kind, UsageHitKind::SelfReceiver);

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        let inverse_self = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.site.file == fixture.files[0] && edge.site.range == forward_self.site.range
            })
            .expect("recursive call must appear as an inverse edge");
        assert_eq!(inverse_self.usage_kind, UsageHitKind::SelfReceiver);
    }

    #[test]
    fn forward_keeps_same_owner_different_receiver_as_reference() {
        let fixture = Fixture::new(
            Language::Java,
            &[(
                "src/Registry.java",
                "package fixture;\n\nclass Registry {\n    void helper() {}\n    void invoke(Registry other) {\n        other.helper();\n    }\n}\n",
            )],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry.helper");
        let call_start = fixture.files[0]
            .read_to_string()
            .expect("fixture source")
            .rfind("helper();")
            .expect("member call");
        let forward =
            forward_edges_for_file(analyzer, &fixture.files[0], &CancellationToken::new())
                .expect("not cancelled");
        let forward_call = forward
            .edges
            .iter()
            .find(|edge| edge.target == target && edge.site.range.start_byte == call_start)
            .expect("the member call must appear as a forward edge");
        assert_eq!(forward_call.owner_relation, OwnerRelation::SameOwner);
        assert_eq!(forward_call.usage_kind, UsageHitKind::Reference);

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        let inverse_call = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.site.file == fixture.files[0] && edge.site.range == forward_call.site.range
            })
            .expect("the member call must appear as an inverse edge");
        assert_eq!(inverse_call.usage_kind, UsageHitKind::Reference);
    }

    /// Kotlin's forward surface is supported, while its one uncovered
    /// occurrence role remains an explicit completeness gap. Supported roles
    /// retain their role-scoped completeness even when this fixture has no
    /// reference sites.
    #[test]
    fn kotlin_forward_support_reports_only_its_uncovered_occurrence_role() {
        let fixture = Fixture::new(
            Language::Kotlin,
            &[(
                "src/Main.kt",
                "class Registry {\n    fun register() {\n    }\n}\n",
            )],
        );
        let result = forward_edges_for_file(
            fixture.analyzer(),
            &fixture.files[0],
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        assert!(result.edges.is_empty());
        assert_eq!(
            result.completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::OccurrenceRowsIncomplete {
                    uncovered_roles: vec![OccurrenceRole::PatternPosition]
                }]
            }
        );
        assert!(!result.covers(EdgeAxis::ForwardProjection));
        assert!(!result.covers(EdgeAxis::InverseProjection));
        assert!(result.covers_forward_role(OccurrenceRole::MemberPosition));
        assert!(!result.covers_forward_role(OccurrenceRole::PatternPosition));
    }

    /// Two hits that disagree only on proof are two canonical rows. The
    /// usage-hit identity excludes proof, so upstream sets collapse exactly
    /// this disagreement; the canonical layer must not.
    #[test]
    fn rows_that_disagree_only_on_proof_stay_distinct() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                ("src/Startup.java", JAVA_CALLER),
            ],
        );
        let target = fixture.declaration("Registry.register");
        let caller = fixture.declaration("Startup.boot");
        let range = Range {
            start_byte: 10,
            end_byte: 18,
            start_line: 4,
            end_line: 4,
        };
        let hit = |proof| ReferenceHit {
            file: fixture.files[1].clone(),
            range,
            enclosing_unit: caller.clone(),
            kind: Some(ReferenceKind::MethodCall),
            resolved: target.clone(),
            confidence: 1_000_000,
            usage_kind: UsageHitKind::Reference,
            proof,
        };
        let rows = edge_rows_from_reference_hits(
            fixture.analyzer(),
            [hit(UsageProof::Proven), hit(UsageProof::Unproven)],
            7,
            None,
        );
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0], rows[1]);
        assert_eq!(rows[0].proof, UsageProof::Proven);
        assert_eq!(rows[1].proof, UsageProof::Unproven);
    }

    /// The covers table: axes this producer does not answer are never covered,
    /// and each incomplete reason blocks exactly its own projection.
    #[test]
    fn completeness_covers_the_declared_axes_only() {
        let complete = EdgeCompleteness::Complete;
        for &axis in EDGE_PRODUCER_AXES {
            assert!(complete.covers(axis));
        }

        let truncated = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::UsageListingTruncated],
        };
        assert!(!truncated.covers(EdgeAxis::InverseProjection));
        assert!(truncated.covers(EdgeAxis::ForwardProjection));

        let occurrence_gap = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::OccurrenceRowsIncomplete {
                uncovered_roles: vec![OccurrenceRole::PathSegment],
            }],
        };
        assert!(!occurrence_gap.covers(EdgeAxis::ForwardProjection));
        assert!(occurrence_gap.covers(EdgeAxis::InverseProjection));

        let cancelled = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::Cancelled],
        };
        for &axis in EDGE_PRODUCER_AXES {
            assert!(!cancelled.covers(axis));
        }
    }
}
