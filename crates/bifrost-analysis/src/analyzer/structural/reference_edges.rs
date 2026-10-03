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
use super::facts::{FileFacts, Span};
use super::kinds::{NormalizedKind, Role};
use super::lexical_environment::environment_for_file;
use super::occurrence_rows::{
    OccurrenceCompleteness, OccurrenceFileResult, OccurrenceRow, OccurrenceTarget,
    OccurrencesCancelled, ast_id, occurrences_for_file, occurrences_for_file_at_lines,
};
use super::occurrences::{ALL_OCCURRENCE_ROLES, OccurrenceClass, OccurrenceRole};
use super::resolution::EnvironmentAxis;
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::usages::{
    FuzzyResult, ReferenceEngine, ReferenceHit, ReferenceKind, UsageHit, UsageHitKind,
    UsageHitSurface, UsageProof, UsageQueryCompletion,
};
use crate::analyzer::{
    CodeUnit, DeclarationId, FqName, IAnalyzer, ProjectFile, Range, TypeHierarchyProvider,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use rayon::prelude::*;
use std::sync::Arc;

/// The file a scan unit reads: a bare file scans whole, a file with demanded
/// lines scans only those lines' reference rows. Declared for
/// `ReferenceEngine::scan_units`, whose byte accounting needs the file either
/// way.
trait UnitFile {
    fn file(&self) -> &ProjectFile;
}

impl UnitFile for ProjectFile {
    fn file(&self) -> &ProjectFile {
        self
    }
}

impl UnitFile for (ProjectFile, std::collections::BTreeSet<usize>) {
    fn file(&self) -> &ProjectFile {
        &self.0
    }
}

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
        }
        | FuzzyResult::Incomplete {
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

#[derive(Clone, Copy)]
struct IndexedSpan<T> {
    span: Span,
    value: T,
}

struct ContainingSpanNode<T> {
    center: usize,
    spanning: Box<[IndexedSpan<T>]>,
    left: Option<usize>,
    right: Option<usize>,
}

impl<T> ContainingSpanNode<T> {
    fn placeholder() -> Self {
        Self {
            center: 0,
            spanning: Box::new([]),
            left: None,
            right: None,
        }
    }
}

/// Immutable interval index for finding facts whose spans contain one queried
/// source range.
///
/// Every node stores the intervals crossing its center. A containment lookup
/// inspects those intervals and follows at most one child, because an interval
/// wholly on the other side of the center cannot contain the query. This keeps
/// lookup proportional to tree depth plus the actual containing intervals,
/// without allocating a traversal stack or scanning the file arena.
struct ContainingSpanIndex<T> {
    nodes: Box<[ContainingSpanNode<T>]>,
}

impl<T: Copy> ContainingSpanIndex<T> {
    fn new(entries: impl IntoIterator<Item = (Span, T)>) -> Self {
        let entries = entries
            .into_iter()
            .map(|(span, value)| {
                assert!(
                    span.start_byte <= span.end_byte,
                    "indexed structural span must be ordered: {span:?}"
                );
                IndexedSpan { span, value }
            })
            .collect::<Vec<_>>();
        if entries.is_empty() {
            return Self {
                nodes: Box::new([]),
            };
        }

        let mut nodes = Vec::new();
        nodes.push(ContainingSpanNode::placeholder());
        let mut pending = vec![(0_usize, entries)];
        while let Some((node_index, mut entries)) = pending.pop() {
            let middle = entries.len() / 2;
            entries.select_nth_unstable_by_key(middle, |entry| {
                entry.span.start_byte + (entry.span.end_byte - entry.span.start_byte) / 2
            });
            let pivot = entries[middle].span;
            let center = pivot.start_byte + (pivot.end_byte - pivot.start_byte) / 2;
            let mut left = Vec::new();
            let mut spanning = Vec::new();
            let mut right = Vec::new();
            for entry in entries {
                if entry.span.end_byte < center {
                    left.push(entry);
                } else if entry.span.start_byte > center {
                    right.push(entry);
                } else {
                    spanning.push(entry);
                }
            }
            assert!(
                !spanning.is_empty(),
                "the pivot interval must cross its own midpoint"
            );

            let left_index = (!left.is_empty()).then(|| {
                let child = nodes.len();
                nodes.push(ContainingSpanNode::placeholder());
                pending.push((child, left));
                child
            });
            let right_index = (!right.is_empty()).then(|| {
                let child = nodes.len();
                nodes.push(ContainingSpanNode::placeholder());
                pending.push((child, right));
                child
            });
            nodes[node_index] = ContainingSpanNode {
                center,
                spanning: spanning.into_boxed_slice(),
                left: left_index,
                right: right_index,
            };
        }
        Self {
            nodes: nodes.into_boxed_slice(),
        }
    }

    fn best_containing_by_key<K: Ord>(
        &self,
        start_byte: usize,
        end_byte: usize,
        mut key: impl FnMut(T) -> K,
    ) -> Option<T> {
        assert!(
            start_byte <= end_byte,
            "reference source range must be ordered"
        );
        let mut best: Option<(K, T)> = None;
        let mut cursor = (!self.nodes.is_empty()).then_some(0_usize);
        while let Some(node_index) = cursor {
            let node = &self.nodes[node_index];
            for entry in &node.spanning {
                if entry.span.start_byte <= start_byte && end_byte <= entry.span.end_byte {
                    let candidate_key = key(entry.value);
                    if best
                        .as_ref()
                        .is_none_or(|(best_key, _)| candidate_key < *best_key)
                    {
                        best = Some((candidate_key, entry.value));
                    }
                }
            }
            cursor = if end_byte < node.center {
                node.left
            } else if start_byte > node.center {
                node.right
            } else {
                None
            };
        }
        best.map(|(_, value)| value)
    }
}

#[derive(Clone, Copy)]
struct NearestDeclaration {
    kind: NormalizedKind,
    name: Option<Span>,
}

/// Reusable per-file index for source-level reference classification.
///
/// Construction reads one immutable structural-facts snapshot and performs one
/// file-sized pass. Later target lookups use interval indexes for the selected
/// call/field site and nearest containing fact, plus precomputed declaration
/// and assignment ancestry. No lookup scans or sorts the file's node arena.
pub(crate) struct ReferenceSiteClassifier<'analyzer> {
    analyzer: &'analyzer dyn IAnalyzer,
    facts: Arc<FileFacts>,
    named_accesses: ContainingSpanIndex<u32>,
    containing_nodes: ContainingSpanIndex<u32>,
    nearest_declarations: Box<[Option<NearestDeclaration>]>,
    nearest_assignments: Box<[Option<u32>]>,
    site_identities: SiteIdentityIndex,
}

impl<'analyzer> ReferenceSiteClassifier<'analyzer> {
    /// Build the classifier from the analyzer's one facts snapshot for `file`.
    /// Returns `None` when the file has no structural adapter or facts.
    pub(crate) fn new(analyzer: &'analyzer dyn IAnalyzer, file: &ProjectFile) -> Option<Self> {
        let language = crate::analyzer::common::language_for_file(file);
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)?
            .structural_facts(file)?;

        let mut named_accesses = Vec::new();
        let mut containing_nodes = Vec::with_capacity(facts.nodes().len());
        let mut site_identity_nodes = HashMap::default();
        let mut nearest_declarations: Vec<Option<NearestDeclaration>> =
            Vec::with_capacity(facts.nodes().len());
        let mut nearest_assignments: Vec<Option<u32>> = Vec::with_capacity(facts.nodes().len());
        for (index, node) in facts.nodes().iter().enumerate() {
            let id = u32::try_from(index).expect("structural fact id must fit u32");
            containing_nodes.push((node.span(), id));
            if node.kind == NormalizedKind::Identifier {
                site_identity_nodes
                    .entry((node.range.start_byte, node.range.end_byte))
                    .or_insert(id);
            }
            if matches!(
                node.kind,
                NormalizedKind::Call | NormalizedKind::FieldAccess
            ) && let Some(name) = node.name
            {
                named_accesses.push((name, id));
            }

            let parent_declaration = node.parent.and_then(|parent| {
                assert!(
                    (parent as usize) < index,
                    "structural parent must precede its child: {parent} -> {id}"
                );
                nearest_declarations[parent as usize]
            });
            nearest_declarations.push(if node.kind.satisfies(NormalizedKind::Declaration) {
                Some(NearestDeclaration {
                    kind: node.kind,
                    name: node.name,
                })
            } else {
                parent_declaration
            });

            let parent_assignment = node.parent.and_then(|parent| {
                assert!(
                    (parent as usize) < index,
                    "structural parent must precede its child: {parent} -> {id}"
                );
                nearest_assignments[parent as usize]
            });
            nearest_assignments.push(if node.kind == NormalizedKind::Assignment {
                Some(id)
            } else {
                parent_assignment
            });
        }

        let site_identities = SiteIdentityIndex {
            content_identity: Some(facts.source_identity()),
            by_range: site_identity_nodes,
        };
        Some(Self {
            analyzer,
            facts,
            named_accesses: ContainingSpanIndex::new(named_accesses),
            containing_nodes: ContainingSpanIndex::new(containing_nodes),
            nearest_declarations: nearest_declarations.into_boxed_slice(),
            nearest_assignments: nearest_assignments.into_boxed_slice(),
            site_identities,
        })
    }

    /// Classify one exact source range against its resolved declaration.
    pub(crate) fn classify_reference_kind(
        &self,
        start_byte: usize,
        end_byte: usize,
        target: &CodeUnit,
    ) -> Option<ReferenceKind> {
        let covers = |span: Span| span.start_byte <= start_byte && end_byte <= span.end_byte;
        let candidate = self
            .named_accesses
            .best_containing_by_key(start_byte, end_byte, |id| {
                let node = self.facts.node(id);
                (
                    usize::from(node.kind != NormalizedKind::Call),
                    node.range.end_byte - node.range.start_byte,
                    id,
                )
            });
        if let Some(id) = candidate {
            let node = self.facts.node(id);
            let receiver_role = if node.kind == NormalizedKind::FieldAccess {
                Role::Object
            } else {
                Role::Receiver
            };
            let receiver = self
                .facts
                .role_targets(id, receiver_role)
                .next()
                .map(|role| role.span.text(self.facts.source()).trim());
            if receiver.is_some_and(|text| matches!(text, "super" | "base")) {
                return Some(ReferenceKind::SuperCall);
            }
            let static_receiver = self
                .analyzer
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
            if let Some(assignment) = self.nearest_assignments[id as usize] {
                return Some(
                    if self
                        .facts
                        .role_targets(assignment, Role::Left)
                        .any(|role| covers(role.span))
                    {
                        ReferenceKind::FieldWrite
                    } else {
                        ReferenceKind::FieldRead
                    },
                );
            }
            return Some(ReferenceKind::FieldRead);
        }

        if target.is_class()
            && let Some(nearest) =
                self.containing_nodes
                    .best_containing_by_key(start_byte, end_byte, |id| {
                        let node = self.facts.node(id);
                        (node.range.end_byte - node.range.start_byte, id)
                    })
            && let Some(declaration) = self.nearest_declarations[nearest as usize]
            && declaration.kind == NormalizedKind::Class
            && declaration.name.is_none_or(|name| !covers(name))
        {
            return Some(ReferenceKind::Inheritance);
        }
        target.is_class().then_some(ReferenceKind::TypeReference)
    }

    /// The enclosing structural call shape that owns a selected identifier,
    /// when that identifier is a call's callee. Usage surfaces for
    /// constructors report the allocation expression, while inverse edges
    /// remain anchored to the exact reference token.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn call_range_containing_reference(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<Range> {
        let id = self
            .named_accesses
            .best_containing_by_key(start_byte, end_byte, |id| {
                let node = self.facts.node(id);
                (
                    usize::from(node.kind != NormalizedKind::Call),
                    node.range.end_byte - node.range.start_byte,
                    id,
                )
            })?;
        let node = self.facts.node(id);
        (node.kind == NormalizedKind::Call).then_some(node.range)
    }

    /// Exact content-scoped AST identity for an identifier at this byte range.
    /// `None` means the structural snapshot has no identifier with that exact
    /// range; this method never guesses from containment or source text.
    pub(crate) fn ast_id(&self, start_byte: usize, end_byte: usize) -> Option<String> {
        self.site_identities.ast_id_for_bytes(start_byte, end_byte)
    }

    /// The identifier token that spans exactly these bytes, read from the
    /// file's structural facts rather than from the source text.
    ///
    /// `None` means no identifier node has that exact span, which is the
    /// honest answer for a range the parser did not produce an identifier for.
    /// A caller comparing this against a declaration's `short_name` must
    /// normalize a Rust raw identifier with
    /// `symbol_path::strip_raw_identifier_prefix`.
    pub(crate) fn identifier_at(&self, start_byte: usize, end_byte: usize) -> Option<&str> {
        let node = *self.site_identities.by_range.get(&(start_byte, end_byte))?;
        Some(self.facts.node(node).span().text(self.facts.source()))
    }
}

pub fn classify_reference_kind(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start_byte: usize,
    end_byte: usize,
    target: &CodeUnit,
) -> Option<ReferenceKind> {
    ReferenceSiteClassifier::new(analyzer, file)?
        .classify_reference_kind(start_byte, end_byte, target)
}

#[cfg(test)]
fn classify_reference_kind_scan_oracle(
    analyzer: &dyn IAnalyzer,
    facts: &FileFacts,
    start_byte: usize,
    end_byte: usize,
    target: &CodeUnit,
) -> Option<ReferenceKind> {
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
        self.references_to_edges_with_provider(
            analyzer,
            targets,
            None,
            max_files,
            max_usages,
            max_source_bytes,
        )
    }

    /// [`Self::references_to_edges`], but lets the caller pick the candidate
    /// file provider.
    ///
    /// `find_default_candidates_within` (the `None` case) chooses the
    /// interruptible, per-candidate importer scan specifically so a caller
    /// with a real deadline can bail out mid-scan instead of being forced
    /// through one uninterruptible workspace-wide reverse-import-index
    /// build. A caller whose cancellation token can never actually fire
    /// (e.g. a batch scan with no deadline) pays that scan's full cost on
    /// every call for a protection it will never use. Passing
    /// `Some(&ImportGraphCandidateProvider::new())` opts into the same
    /// import-graph candidates through the cached reverse-import-index path
    /// instead (bifrost#15).
    pub fn references_to_edges_with_provider(
        &self,
        analyzer: &dyn IAnalyzer,
        targets: &[CodeUnit],
        explicit_provider: Option<&dyn crate::analyzer::usages::CandidateFileProvider>,
        max_files: usize,
        max_usages: usize,
        max_source_bytes: Option<usize>,
    ) -> ReferenceRun {
        let query = self.query_with_provider_and_source_budget(
            analyzer,
            targets,
            explicit_provider,
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
        if let FuzzyResult::Incomplete { diagnostics, .. } = &query.result {
            reasons.extend(diagnostics.iter().map(|diagnostic| {
                EdgeIncompleteReason::UsageAnalysisFailed {
                    reason_kind: diagnostic.reason_kind.clone(),
                    reason: format!("{diagnostic:?}"),
                }
            }));
            if diagnostics.is_empty() {
                reasons.push(EdgeIncompleteReason::UsageAnalysisFailed {
                    reason_kind: "semantic_incomplete".to_string(),
                    reason: "Usage analysis did not complete semantic enumeration".to_string(),
                });
            }
        }
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
    /// See [`Self::scan_units`] for the fan-out and merge semantics.
    pub fn scan_file_edges(&self, analyzer: &dyn IAnalyzer, files: &[ProjectFile]) -> ReferenceRun {
        self.scan_units(analyzer, files, |file| {
            forward_edges_for_file(analyzer, file, self.cancellation())
        })
    }

    /// [`Self::scan_file_edges`], resolving only the reference rows that start
    /// on each file's demanded lines. A consumer that reads the resulting
    /// edges at known sites -- the usage-graph structural exact fallback probes
    /// its table at legacy call-site lines -- pays the definition batch for
    /// exactly those rows instead of every occurrence of every file
    /// (issue #2679).
    pub fn scan_file_edges_at_lines(
        &self,
        analyzer: &dyn IAnalyzer,
        demanded: &[(ProjectFile, std::collections::BTreeSet<usize>)],
    ) -> ReferenceRun {
        self.scan_units(analyzer, demanded, |(file, lines)| {
            forward_edges_for_file_at_lines(analyzer, file, lines, self.cancellation())
        })
    }

    /// The shared per-unit scan: fan the units out, merge in input order.
    ///
    /// One unit's occurrence batch is a long serial resolver ladder, and
    /// scanning units one after another left every other core idle for
    /// minutes on review-sized Rust diffs (issue #2679 -- every capture
    /// showed one busy worker and eleven idle cores). A short serial prefix
    /// runs first so the request-scoped analyzer memos are warm before the
    /// fan-out: a cold parallel start made every worker race the same common
    /// names through the racy per-request maps and cost more than the
    /// parallelism returned (measured: +42% user time at width 2). Per-unit
    /// results are merged in input order, so the emitted run matches the
    /// serial loop's output; on cancellation the merge stops at the first
    /// cancelled unit, exactly as a serial `break` discarded units it never
    /// reached.
    fn scan_units<T: UnitFile + Sync>(
        &self,
        analyzer: &dyn IAnalyzer,
        units: &[T],
        scan: impl Fn(&T) -> Result<EdgeDerivationResult, OccurrencesCancelled> + Sync,
    ) -> ReferenceRun {
        enum FileScan {
            Cancelled,
            Scanned {
                source_bytes: usize,
                result: EdgeDerivationResult,
            },
        }
        let generation = analyzer.project().analysis_generation();
        let scan_one = |unit: &T| {
            if self.cancellation().is_cancelled() {
                return FileScan::Cancelled;
            }
            let source_bytes = analyzer
                .indexed_source(unit.file())
                .map_or(0, |source| source.len());
            match scan(unit) {
                Ok(result) => FileScan::Scanned {
                    source_bytes,
                    result,
                },
                Err(OccurrencesCancelled) => FileScan::Cancelled,
            }
        };
        let warm_prefix = units.len().min(rayon::current_num_threads().max(2));
        let mut per_file: Vec<FileScan> = units[..warm_prefix].iter().map(scan_one).collect();
        per_file.extend(
            units[warm_prefix..]
                .par_iter()
                .map(scan_one)
                .collect::<Vec<FileScan>>(),
        );
        let mut edges = Vec::new();
        let mut reasons = Vec::new();
        let mut scanned_files = 0usize;
        let mut scanned_source_bytes = 0usize;
        for scan in per_file {
            match scan {
                FileScan::Cancelled => {
                    reasons.push(EdgeIncompleteReason::Cancelled);
                    break;
                }
                FileScan::Scanned {
                    source_bytes,
                    result,
                } => {
                    scanned_files += 1;
                    scanned_source_bytes = scanned_source_bytes.saturating_add(source_bytes);
                    edges.extend(result.edges);
                    if let EdgeCompleteness::Incomplete {
                        reasons: file_reasons,
                    } = result.completeness
                    {
                        reasons.extend(file_reasons);
                    }
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
                candidate_files: units.len(),
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
                    EdgeIncompleteReason::ReferenceEnumerationIncomplete
                    | EdgeIncompleteReason::ForwardResolutionIncomplete
                    | EdgeIncompleteReason::ForwardAdmissionIncomplete
                    | EdgeIncompleteReason::ForwardMetadataIncomplete => true,
                    EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete
                    | EdgeIncompleteReason::InverseIndexResolutionIncomplete
                    | EdgeIncompleteReason::InverseIndexAdmissionIncomplete
                    | EdgeIncompleteReason::InverseIndexMetadataIncomplete
                    | EdgeIncompleteReason::InverseIndexTargetUncovered
                    | EdgeIncompleteReason::TimeBudgetExceeded
                    | EdgeIncompleteReason::SelectedInverseIndexUnavailable { .. } => false,
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

/// What owns a declaration for the purpose of relating one edge's two ends.
///
/// The two scope shapes are kept apart because they are compared by different
/// evidence: two types are related by the type hierarchy, two namespaces by
/// their qualified names, and a type is never a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Owner {
    /// A class-like declaration: the unit itself when it is class-like, else
    /// the class-like declaration the unit hangs off.
    Type(CodeUnit),
    /// A module, package, namespace, or root scope, named by the qualified
    /// name that places declarations directly in it. The name is empty for a
    /// root scope -- Rust's crate root, a JS/TS file module, Ruby top level --
    /// which no qualified name spells, so two root scopes cannot be told apart
    /// or told to be the same.
    Namespace(FqName),
}

/// The scope that owns `unit`, or `None` when the recorded structure does not
/// establish one.
///
/// A class-like declaration owns itself, and so does a module-like one: both
/// are scopes that other declarations hang off. Otherwise the qualified name
/// answers first, because it records the owner directly: a name whose every
/// segment before the leaf denotes a namespace places the declaration in that
/// namespace and in no type, which is exactly the shape of a free function, a
/// Go package-level func, a PHP namespaced function, or a Kotlin top-level
/// function. Only a name that puts the declaration inside another declaration
/// needs the declaration lookup, which is also the only case where that
/// lookup can succeed.
fn owner_of(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<Owner> {
    if unit.is_class() {
        return Some(Owner::Type(unit.clone()));
    }
    if unit.is_module() || unit.is_file_scope() {
        return Some(Owner::Namespace(unit.fq().clone()));
    }
    if let Some(namespace) = unit.fq().namespace_prefix() {
        return Some(Owner::Namespace(namespace));
    }
    match analyzer.parent_of(unit)? {
        parent if parent.is_class() => Some(Owner::Type(parent)),
        parent => Some(Owner::Namespace(parent.fq().clone())),
    }
}

/// How the declaration enclosing a use site relates to the edge's target.
/// One computation for both producers, so the classification can never drift
/// between the forward and inverse surfaces.
///
/// The owner of a unit is [`owner_of`]'s answer. Two owners are the same owner
/// only when they are the same scope; containment is not sameness, so a
/// namespace that contains the target's type is `External`, exactly as Java
/// already states for a class calling a method of its own nested class. A
/// namespace owner and a type owner are always distinct and no type hierarchy
/// spans them, which is why a free function calling a method states `External`
/// rather than declining to answer.
///
/// `Unknown` is the honest answer whenever an owner is missing, whenever two
/// distinct class owners meet no type-hierarchy provider that can rule
/// inheritance in or out, and whenever a root scope is one of the two
/// namespaces being compared -- a root scope has no name, so two of them may
/// be one scope or two and the qualified names do not say. `Unknown` is never
/// collapsed into `External`.
pub fn classify_owner_relation(
    analyzer: &dyn IAnalyzer,
    site_enclosing: Option<&CodeUnit>,
    target: &CodeUnit,
) -> OwnerRelation {
    classify_owner_relation_by(
        analyzer,
        site_enclosing,
        target,
        |hierarchy, site, target| hierarchy.get_ancestors(site).contains(target),
    )
}

/// [`classify_owner_relation`] for one pass over many edges.
///
/// Each site type's ancestors are asked of the hierarchy once and kept, keyed
/// by the type. The edges of one crate stage share few enclosing types: tract's
/// generated flatbuffers file puts tens of thousands of references inside a
/// few hundred impl blocks, and every classification walked the same
/// ancestors again, canonicalising each type on the way. A type's ancestors do
/// not change within a request. The owner holds one memo per stage and drops
/// it with the stage, so no memo outlives the stage that filled it.
#[derive(Default)]
pub struct OwnerRelationMemo {
    ancestors: HashMap<CodeUnit, Vec<CodeUnit>>,
}

impl OwnerRelationMemo {
    /// The relation [`classify_owner_relation`] states, from this memo's
    /// ancestors.
    pub fn classify(
        &mut self,
        analyzer: &dyn IAnalyzer,
        site_enclosing: Option<&CodeUnit>,
        target: &CodeUnit,
    ) -> OwnerRelation {
        let ancestors = &mut self.ancestors;
        classify_owner_relation_by(
            analyzer,
            site_enclosing,
            target,
            |hierarchy, site, target| {
                ancestors
                    .entry(site.clone())
                    .or_insert_with(|| hierarchy.get_ancestors(site))
                    .contains(target)
            },
        )
    }
}

/// The owner-relation rule, with the inheritance test supplied by the caller:
/// `inherits(hierarchy, site, target)` says whether `target` is among `site`'s
/// ancestors.
/// A same-owner value reference is a member reference only when its target
/// belongs to a declaration rather than directly to a namespace. Sharing a
/// module does not turn a free function or constant into a self receiver.
pub(crate) fn is_same_owner_member_reference(relation: OwnerRelation, target: &CodeUnit) -> bool {
    relation == OwnerRelation::SameOwner && target.fq().namespace_prefix().is_none()
}

fn classify_owner_relation_by(
    analyzer: &dyn IAnalyzer,
    site_enclosing: Option<&CodeUnit>,
    target: &CodeUnit,
    inherits: impl FnOnce(&dyn TypeHierarchyProvider, &CodeUnit, &CodeUnit) -> bool,
) -> OwnerRelation {
    let Some(enclosing) = site_enclosing else {
        return OwnerRelation::Unknown;
    };
    if enclosing == target {
        return OwnerRelation::SelfReference;
    }
    let (Some(site_owner), Some(target_owner)) =
        (owner_of(analyzer, enclosing), owner_of(analyzer, target))
    else {
        return OwnerRelation::Unknown;
    };
    match (site_owner, target_owner) {
        (Owner::Type(site), Owner::Type(target)) if site == target => OwnerRelation::SameOwner,
        (Owner::Type(site), Owner::Type(target)) => match analyzer.type_hierarchy_provider() {
            Some(hierarchy) => {
                if inherits(hierarchy, &site, &target) {
                    OwnerRelation::InheritedOwner
                } else {
                    OwnerRelation::External
                }
            }
            None => OwnerRelation::Unknown,
        },
        (Owner::Namespace(site), Owner::Namespace(target)) => {
            if site.is_empty() || target.is_empty() {
                OwnerRelation::Unknown
            } else if site == target {
                OwnerRelation::SameOwner
            } else {
                OwnerRelation::External
            }
        }
        (Owner::Type(_), Owner::Namespace(_)) | (Owner::Namespace(_), Owner::Type(_)) => {
            OwnerRelation::External
        }
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

/// Per-file map from an identifier token's exact byte range to its facts-arena
/// node, built once per file so a batch of inverse hits pays one arena pass
/// instead of one per hit. The externally owned AST-id string is rendered only
/// for a published site instead of eagerly allocating one for every identifier.
///
/// The lookup is exact, not heuristic: the facts snapshot and the usage hit
/// address the same analyzed content, so range equality over it is the same
/// join the forward producer states through `OccurrenceRow::ast_id`.
struct SiteIdentityIndex {
    content_identity: Option<ContentIdentity>,
    by_range: HashMap<(usize, usize), u32>,
}

impl SiteIdentityIndex {
    fn from_facts(facts: &FileFacts) -> Self {
        let mut by_range = HashMap::default();
        for (node, fact) in facts.nodes().iter().enumerate() {
            if fact.kind == NormalizedKind::Identifier {
                by_range
                    .entry((fact.range.start_byte, fact.range.end_byte))
                    .or_insert_with(|| {
                        u32::try_from(node).expect("structural fact id must fit u32")
                    });
            }
        }
        Self {
            content_identity: Some(facts.source_identity()),
            by_range,
        }
    }

    fn build(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Self {
        let language = crate::analyzer::common::language_for_file(file);
        analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .and_then(|provider| provider.structural_facts(file))
            .as_deref()
            .map(Self::from_facts)
            .unwrap_or_else(|| Self {
                content_identity: None,
                by_range: HashMap::default(),
            })
    }

    fn ast_id_for_bytes(&self, start_byte: usize, end_byte: usize) -> Option<String> {
        let content_identity = self.content_identity?;
        let node = *self.by_range.get(&(start_byte, end_byte))?;
        Some(ast_id(content_identity, node))
    }

    fn ast_id(&self, range: &Range) -> Option<String> {
        self.ast_id_for_bytes(range.start_byte, range.end_byte)
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
                | UsageHitKind::SelfReceiver
                | UsageHitKind::DeclaredReference => SiteClass::UseSite,
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

/// One language's whole-workspace selected inverse reference index.
///
/// The index is that language's own answer to "which sites refer to this
/// declaration", derived once from its selected resolution facts and bound to
/// the analyzer generation it was derived in. A declaration the index does not
/// cover receives an explicit incomplete result, never a manufactured complete
/// empty one.
pub trait SelectedInverseReferenceIndex: Send + Sync {
    /// The analyzer generation the index was built in.
    fn generation(&self) -> u64;

    /// Every selected inverse edge of one declaration.
    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult;
}

/// What one build of a language's selected inverse index produced.
pub enum SelectedInverseIndexOutcome {
    Ready(Arc<dyn SelectedInverseReferenceIndex>),
    /// The selected facts the index is derived from do not exist for this
    /// workspace.
    Unavailable(String),
    /// The workspace generation moved while the index was being built.
    Stale(String),
    /// The build observed the caller's cancellation.
    Cancelled,
    /// The analyzer store refused a read the build needs.
    StoreError(String),
}

/// The registered builder of one language's selected inverse index.
///
/// Registering a provider makes the selected index that language's only
/// inverse-edge authority for every consumer holding a
/// [`SelectedInverseEdgeCache`], so a refusal is reported as an incomplete
/// answer rather than worked around by deriving the same question a second
/// way.
pub trait SelectedInverseReferenceProvider: Send + Sync {
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
    ) -> SelectedInverseIndexOutcome;
}

/// One language's state in a request's selected inverse memo.
enum SelectedInverseLanguage {
    Ready(Arc<dyn SelectedInverseReferenceIndex>),
    Refused(EdgeIncompleteReason),
}

/// Per-request memo of the selected inverse indexes of the languages that
/// register a provider.
///
/// One index per language per request: the index covers the whole workspace,
/// so building it per declaration would repeat the workspace walk for every
/// subject an `edges_of` query or an edge assert names.
#[derive(Default)]
pub struct SelectedInverseEdgeCache {
    languages: HashMap<crate::analyzer::Language, SelectedInverseLanguage>,
}

impl SelectedInverseEdgeCache {
    /// The selected inverse answer for `declaration`, or `None` when its
    /// language registers no selected inverse provider and the caller derives
    /// the answer through [`inverse_edges_for_declaration`] instead.
    pub fn inverse_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        declaration: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> Option<EdgeDerivationResult> {
        let language = crate::analyzer::common::language_for_file(declaration.source());
        let provider = crate::analyzer::languages::language_support(language)?
            .selected_inverse_reference_provider()?;
        let state = self.languages.entry(language).or_insert_with(|| {
            match provider.build_selected_inverse_index(analyzer, cancellation) {
                SelectedInverseIndexOutcome::Ready(index) => SelectedInverseLanguage::Ready(index),
                SelectedInverseIndexOutcome::Cancelled => {
                    SelectedInverseLanguage::Refused(EdgeIncompleteReason::Cancelled)
                }
                SelectedInverseIndexOutcome::Unavailable(reason) => {
                    SelectedInverseLanguage::Refused(
                        EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                            reason_kind: "unavailable".to_string(),
                            reason,
                        },
                    )
                }
                SelectedInverseIndexOutcome::Stale(reason) => SelectedInverseLanguage::Refused(
                    EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                        reason_kind: "stale".to_string(),
                        reason,
                    },
                ),
                SelectedInverseIndexOutcome::StoreError(reason) => {
                    SelectedInverseLanguage::Refused(
                        EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                            reason_kind: "store_error".to_string(),
                            reason,
                        },
                    )
                }
            }
        });
        Some(match state {
            SelectedInverseLanguage::Ready(index) => index.inverse_for(declaration),
            SelectedInverseLanguage::Refused(reason) => EdgeDerivationResult::incomplete(
                vec![reason.clone()],
                EdgeProvenance::Inverse,
                analyzer.project().analysis_generation(),
            ),
        })
    }
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
    let run = crate::analyzer::i_analyzer::capture_usage_lookup_reads(analyzer, || {
        finder.references_to_edges(
            analyzer,
            std::slice::from_ref(declaration),
            MAX_INVERSE_EDGE_FILES,
            MAX_INVERSE_EDGE_HITS,
            None,
        )
    });
    let mut reasons = match run.completeness {
        EdgeCompleteness::Complete => Vec::new(),
        EdgeCompleteness::Incomplete { reasons } => reasons,
    };
    if supports_edge_axis(analyzer, file, EdgeAxis::OwnerClassification) != Some(true) {
        reasons.push(EdgeIncompleteReason::AxisUnsupported(
            EdgeAxis::OwnerClassification,
        ));
    }

    let result = EdgeDerivationResult {
        edges: run.edges,
        completeness: if reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete { reasons }
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    };
    if analyzer.read_ledger_attached() {
        // The candidate set is a superset the reader confirms, and it is a
        // cross-file answer: a new reference in an unrelated file changes it
        // while no key the reader recorded moves.
        analyzer.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
            crate::analyzer::read_ledger::LookupKind::ReferenceCandidates,
            crate::analyzer::read_ledger::LookupQuestion::declaration(declaration),
            inverse_edge_answer_digest(&result),
        ));
    }
    result
}

/// Domain for the digest of one declaration's inverse-edge answer.
const INVERSE_EDGE_ANSWER_DOMAIN: &[u8] = b"bifrost-read-ledger:inverse-edge-answer:v1";

/// The canonical digest of an inverse-edge answer, by site path and byte range
/// and by completeness.
///
/// Never by row address or `ProjectFile`: the same edges over the same content
/// at two roots must digest identically. Completeness is folded in because a
/// truncated answer and a complete answer that happens to hold the same rows
/// are different facts about the workspace.
pub(crate) fn inverse_edge_answer_digest(result: &EdgeDerivationResult) -> StableDigest {
    let mut sites = result
        .edges
        .iter()
        .map(|edge| {
            (
                rel_path_string(&edge.site.file),
                edge.site.range.start_byte,
                edge.site.range.end_byte,
            )
        })
        .collect::<Vec<_>>();
    sites.sort();
    sites.dedup();
    let mut hasher = CanonicalHasher::new(INVERSE_EDGE_ANSWER_DOMAIN);
    hasher.field(
        "completeness",
        match result.completeness {
            EdgeCompleteness::Complete => b"complete".as_slice(),
            EdgeCompleteness::Incomplete { .. } => b"incomplete".as_slice(),
        },
    );
    for (path, start, end) in sites {
        hasher.field(&path, &(start as u64).to_be_bytes());
        hasher.value(&(end as u64).to_be_bytes());
    }
    StableDigest::from_array(hasher.finish())
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
    if let Some(unsupported) = forward_axis_gate(analyzer, file, generation) {
        return Ok(unsupported);
    }
    let occurrences = occurrences_for_file(analyzer, file, cancellation)?;
    forward_edges_from_occurrences(analyzer, file, occurrences, generation)
}

/// [`forward_edges_for_file`], resolving only the reference rows that start on
/// one of `lines`. Rows off those lines are never resolved and therefore emit
/// no edges; classification and the completeness account stay exhaustive. The
/// usage-graph structural exact fallback uses this because it only ever reads
/// its edge table at legacy call-site lines (issue #2679).
pub fn forward_edges_for_file_at_lines(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    lines: &std::collections::BTreeSet<usize>,
    cancellation: &CancellationToken,
) -> Result<EdgeDerivationResult, OccurrencesCancelled> {
    let generation = analyzer.project().analysis_generation();
    if let Some(unsupported) = forward_axis_gate(analyzer, file, generation) {
        return Ok(unsupported);
    }
    let occurrences = occurrences_for_file_at_lines(analyzer, file, lines, cancellation)?;
    forward_edges_from_occurrences(analyzer, file, occurrences, generation)
}

fn forward_axis_gate(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    generation: u64,
) -> Option<EdgeDerivationResult> {
    match supports_edge_axis(analyzer, file, EdgeAxis::ForwardProjection) {
        Some(true) => None,
        Some(false) => Some(EdgeDerivationResult::incomplete(
            vec![EdgeIncompleteReason::AxisUnsupported(
                EdgeAxis::ForwardProjection,
            )],
            EdgeProvenance::Forward,
            generation,
        )),
        None => Some(EdgeDerivationResult::incomplete(
            vec![EdgeIncompleteReason::NoStructuralAdapter],
            EdgeProvenance::Forward,
            generation,
        )),
    }
}

fn forward_edges_from_occurrences(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    occurrences: OccurrenceFileResult,
    generation: u64,
) -> Result<EdgeDerivationResult, OccurrencesCancelled> {
    let import_target_nodes = import_target_nodes_for_file(analyzer, file).unwrap_or_default();
    let reference_sites = ReferenceSiteClassifier::new(analyzer, file);
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
            let kind = reference_sites.as_ref().and_then(|sites| {
                sites.classify_reference_kind(row.range.start_byte, row.range.end_byte, unit)
            });
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
    use crate::analyzer::java::JavaAnalyzer;
    use crate::analyzer::{
        AnalyzerConfig, CodeUnitIndex, Language, Project, TestProject, WorkspaceAnalyzer,
    };
    use crate::inline_project::InlineTestProject;
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
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
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

    fn token_range(source: &str, marker: &str, token: &str) -> (usize, usize) {
        let marker_start = source
            .find(marker)
            .unwrap_or_else(|| panic!("fixture must contain marker {marker:?}"));
        let token_offset = marker
            .find(token)
            .unwrap_or_else(|| panic!("marker {marker:?} must contain token {token:?}"));
        let start = marker_start + token_offset;
        (start, start + token.len())
    }

    const JAVA_REFERENCE_KIND_SITES: &str = r#"package fixture;

class Base {
    void ping() {}
    static void staticPing() {}
}

class Child extends Base {
    int field;
    void method() {}
    void use(Base other) {
        method();
        Base.staticPing();
        super.ping();
        int read = this.field;
        this.field = read;
        Base local = other;
    }
}
"#;

    /// The reusable index is a semantics-preserving acceleration of the former
    /// arena scan. Exercise every source classification branch against that
    /// scan oracle, the public delegating function, and the exact AST-id join.
    #[test]
    fn indexed_reference_sites_match_the_scan_oracle_for_every_kind() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/ReferenceKinds.java", JAVA_REFERENCE_KIND_SITES)
            .build();
        let file = project.file("src/ReferenceKinds.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let declaration = |fq_suffix: &str| {
            analyzer
                .all_declarations()
                .find(|unit| unit.fq_name().ends_with(fq_suffix))
                .unwrap_or_else(|| panic!("fixture must declare {fq_suffix}"))
        };
        let classifier =
            ReferenceSiteClassifier::new(&analyzer, &file).expect("Java must provide facts");
        let base = declaration("Base");
        let cases = [
            (
                "method call",
                "        method();",
                "method",
                declaration("Child.method"),
                ReferenceKind::MethodCall,
            ),
            (
                "static call",
                "        Base.staticPing();",
                "staticPing",
                declaration("Base.staticPing"),
                ReferenceKind::StaticReference,
            ),
            (
                "super call",
                "        super.ping();",
                "ping",
                declaration("Base.ping"),
                ReferenceKind::SuperCall,
            ),
            (
                "field read",
                "        int read = this.field;",
                "field",
                declaration("Child.field"),
                ReferenceKind::FieldRead,
            ),
            (
                "field write",
                "        this.field = read;",
                "field",
                declaration("Child.field"),
                ReferenceKind::FieldWrite,
            ),
            (
                "type reference",
                "        Base local = other;",
                "Base",
                base.clone(),
                ReferenceKind::TypeReference,
            ),
            (
                "inheritance",
                "class Child extends Base",
                "Base",
                base,
                ReferenceKind::Inheritance,
            ),
        ];

        for (label, marker, token, target, expected) in cases {
            let (start_byte, end_byte) = token_range(JAVA_REFERENCE_KIND_SITES, marker, token);
            let indexed = classifier.classify_reference_kind(start_byte, end_byte, &target);
            let scanned = classify_reference_kind_scan_oracle(
                &analyzer,
                &classifier.facts,
                start_byte,
                end_byte,
                &target,
            );
            assert_eq!(indexed, scanned, "indexed/scanned disagreement at {label}");
            assert_eq!(indexed, Some(expected), "wrong kind at {label}");
            assert_eq!(
                classify_reference_kind(&analyzer, &file, start_byte, end_byte, &target),
                indexed,
                "public delegator disagrees at {label}"
            );
            let identifier = classifier
                .facts
                .nodes()
                .iter()
                .enumerate()
                .find(|(_, node)| {
                    node.kind == NormalizedKind::Identifier
                        && node.range.start_byte == start_byte
                        && node.range.end_byte == end_byte
                })
                .map(|(id, _)| u32::try_from(id).expect("structural fact id must fit u32"))
                .unwrap_or_else(|| panic!("exact identifier fact missing at {label}"));
            assert_eq!(
                classifier.ast_id(start_byte, end_byte),
                Some(ast_id(classifier.facts.source_identity(), identifier)),
                "wrong exact identifier AST id at {label}"
            );
        }
    }

    #[test]
    fn external_usage_graph_excludes_only_target_definition_overlap() {
        const SOURCE: &str = r#"package fixture;

class External {}

class Target {
    Target child() { return this; }
    External external() { return null; }
}
"#;
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Target.java", SOURCE)
            .build();
        let file = project.file("src/Target.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let declaration = |fq_suffix: &str| {
            analyzer
                .all_declarations()
                .find(|unit| unit.fq_name().ends_with(fq_suffix))
                .unwrap_or_else(|| panic!("fixture must declare {fq_suffix}"))
        };
        let target = declaration("Target");
        let external = declaration("External");
        let child = declaration("Target.child");
        let external_method = declaration("Target.external");
        let (self_start, self_end) = token_range(SOURCE, "    Target child()", "Target");
        let (external_start, external_end) =
            token_range(SOURCE, "    External external()", "External");
        let row = |start_byte, end_byte, enclosing, target| ReferenceEdgeRow {
            site: EdgeSite {
                file: file.clone(),
                range: Range {
                    start_byte,
                    end_byte,
                    start_line: 1,
                    end_line: 1,
                },
                ast_id: None,
                enclosing: Some(enclosing),
            },
            target,
            reference_kind: Some(ReferenceKind::TypeReference),
            proof: UsageProof::Proven,
            usage_kind: UsageHitKind::Reference,
            site_class: SiteClass::UseSite,
            owner_relation: OwnerRelation::SameOwner,
            provenance: EdgeProvenance::Forward,
            generation: analyzer.project().analysis_generation(),
        };
        let self_type = row(self_start, self_end, child, target.clone());
        let external_type = row(
            external_start,
            external_end,
            external_method,
            external.clone(),
        );

        assert!(self_type.included_in(UsageHitSurface::ExternalUsages));
        assert!(external_type.included_in(UsageHitSurface::ExternalUsages));
        let target_spans = analyzer
            .ranges(&target)
            .into_iter()
            .map(|range| (target.source().clone(), range))
            .collect::<Vec<_>>();
        let external_spans = analyzer
            .ranges(&external)
            .into_iter()
            .map(|range| (external.source().clone(), range))
            .collect::<Vec<_>>();
        assert!(!self_type.included_in_external_usage_graph(&target_spans));
        assert!(external_type.included_in_external_usage_graph(&external_spans));

        let mut self_receiver = self_type.clone();
        self_receiver.usage_kind = UsageHitKind::SelfReceiver;
        assert!(
            !self_receiver.included_in(UsageHitSurface::ExternalUsages),
            "querying definition overlap must not reclassify a self-receiver as external"
        );
        assert!(
            self_receiver.overlaps_target_definition_spans(&target_spans),
            "definition overlap remains available independently of usage surface"
        );
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

    /// The memo states the relation the plain classifier states, on the first
    /// ask of a site type and on every later one.
    #[test]
    fn the_owner_relation_memo_answers_the_classifier() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Base.java", JAVA_BASE),
                ("src/Derived.java", JAVA_DERIVED),
            ],
        );
        let analyzer = fixture.analyzer();
        let units = [
            fixture.declaration("Base.ping"),
            fixture.declaration("Derived.run"),
            fixture.declaration("Derived.helper"),
        ];
        let mut memo = OwnerRelationMemo::default();
        for _ in 0..2 {
            for site in units.iter().map(Some).chain([None]) {
                for target in &units {
                    assert_eq!(
                        memo.classify(analyzer, site, target),
                        classify_owner_relation(analyzer, site, target),
                        "{site:?} -> {target:?}"
                    );
                }
            }
        }
        assert_eq!(
            memo.classify(analyzer, Some(&units[1]), &units[0]),
            OwnerRelation::InheritedOwner
        );
    }

    /// A declaration whose qualified name places it in a namespace and in no
    /// type has that namespace as its owner, so a free function calling a
    /// method states `External` instead of declining to answer (#1645).
    ///
    /// The rule reads only the recorded segment kinds, so every language whose
    /// free functions carry a module, package, or namespace prefix -- or carry
    /// no type prefix at all -- answers the same way without a per-language
    /// branch. Each language is listed with the shape it contributes.
    #[test]
    fn a_namespace_owner_and_a_type_owner_are_external() {
        /// One language's contribution: the sources, the free callable, and
        /// the type-owned target it calls.
        struct Case {
            language: Language,
            sources: &'static [(&'static str, &'static str)],
            caller: &'static str,
            target: &'static str,
        }

        let cases: &[Case] = &[
            // Rust: the caller sits at the crate root, which the qualified
            // name spells by carrying no scope segment.
            Case {
                language: Language::Rust,
                sources: &[(
                    "src/lib.rs",
                    "pub struct Widget;\n\nimpl Widget {\n    pub fn new() -> Widget {\n        Widget\n    }\n\n    pub fn run(&self) -> usize {\n        1\n    }\n}\n\npub fn drive() -> usize {\n    let s = Widget::new();\n    s.run()\n}\n",
                )],
                caller: "drive",
                target: "Widget.run",
            },
            // Rust again, with a named module owner: containing the target's
            // type is not owning the target.
            Case {
                language: Language::Rust,
                sources: &[(
                    "src/lib.rs",
                    "pub mod thing {\n    pub struct Widget;\n    impl Widget {\n        pub fn run(&self) -> usize { 1 }\n    }\n    pub fn drive(w: &Widget) -> usize {\n        w.run()\n    }\n}\n",
                )],
                caller: "thing.drive",
                target: "thing.Widget.run",
            },
            // Go: the package prefix is a `Path` segment.
            Case {
                language: Language::Go,
                sources: &[(
                    "main.go",
                    "package main\n\ntype Widget struct{}\n\nfunc (w Widget) Run() int { return 1 }\n\nfunc Drive() int {\n\tw := Widget{}\n\treturn w.Run()\n}\n",
                )],
                caller: "main.Drive",
                target: "main.Widget.Run",
            },
            // PHP: a namespaced function.
            Case {
                language: Language::Php,
                sources: &[(
                    "app.php",
                    "<?php\nnamespace App;\n\nclass Widget {\n    public function run() { return 1; }\n}\n\nfunction drive() {\n    $w = new Widget();\n    return $w->run();\n}\n",
                )],
                caller: "App.drive",
                target: "App.Widget.run",
            },
            // Kotlin: a top-level function in a package.
            Case {
                language: Language::Kotlin,
                sources: &[(
                    "src/app.kt",
                    "package fixture\n\nclass Widget {\n    fun run(): Int = 1\n}\n\nfun drive(): Int {\n    val w = Widget()\n    return w.run()\n}\n",
                )],
                caller: "fixture.drive",
                target: "fixture.Widget.run",
            },
            // Ruby: a top-level method, whose type-owned counterpart carries a
            // `Nested` prefix rather than a namespace one.
            Case {
                language: Language::Ruby,
                sources: &[(
                    "app.rb",
                    "class Widget\n  def run\n    1\n  end\nend\n\ndef drive\n  w = Widget.new\n  w.run\nend\n",
                )],
                caller: "drive",
                target: "Widget.run",
            },
            // JavaScript: the same js/ts model, listed separately because it
            // is a separately claimed language.
            Case {
                language: Language::JavaScript,
                sources: &[
                    (
                        "widget.js",
                        "export class Widget {\n  run() { return 1; }\n}\n",
                    ),
                    (
                        "app.js",
                        "import { Widget } from './widget.js';\nexport function drive() {\n  const w = new Widget();\n  return w.run();\n}\n",
                    ),
                ],
                caller: "drive",
                target: "Widget.run",
            },
            // TypeScript: the module scope is the file and is unnamed, but the
            // caller still provably belongs to no type.
            Case {
                language: Language::TypeScript,
                sources: &[
                    (
                        "widget.ts",
                        "export class Widget {\n  run(): number { return 1; }\n}\n",
                    ),
                    (
                        "app.ts",
                        "import { Widget } from './widget';\nexport function drive(): number {\n  const w = new Widget();\n  return w.run();\n}\n",
                    ),
                ],
                caller: "drive",
                target: "Widget.run",
            },
        ];
        for case in cases {
            let language = case.language;
            let fixture = Fixture::new(language, case.sources);
            let analyzer = fixture.analyzer();
            let caller = fixture.declaration(case.caller);
            let target = fixture.declaration(case.target);
            assert_eq!(
                classify_owner_relation(analyzer, Some(&caller), &target),
                OwnerRelation::External,
                "{language:?}: {caller:?} owns no type, {target:?} does"
            );
            assert_eq!(
                classify_owner_relation(analyzer, Some(&target), &caller),
                OwnerRelation::External,
                "{language:?}: the relation is symmetric across the two scopes"
            );
        }
    }

    /// Two declarations directly in one named namespace share that owner, and
    /// two in different named namespaces are external -- the namespace half of
    /// the same rule.
    #[test]
    fn namespace_owners_are_compared_by_name() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                (
                    "main.go",
                    "package main\n\nfunc Drive() int { return Helper() }\n\nfunc Helper() int { return 1 }\n",
                ),
                (
                    "util/util.go",
                    "package util\n\nfunc Assist() int { return 1 }\n",
                ),
            ],
        );
        let analyzer = fixture.analyzer();
        let drive = fixture.declaration("main.Drive");
        let helper = fixture.declaration("main.Helper");
        let assist = fixture.declaration("util.Assist");
        assert_eq!(
            classify_owner_relation(analyzer, Some(&drive), &helper),
            OwnerRelation::SameOwner,
            "both funcs hang off package `main`"
        );
        assert_eq!(
            classify_owner_relation(analyzer, Some(&drive), &assist),
            OwnerRelation::External,
            "`main` and `util` are different packages"
        );
    }

    /// A root scope carries no name, so two declarations in one are not
    /// claimed to share an owner. `Unknown` here is the honesty rule, not a
    /// missing case: the qualified names cannot tell one root scope from
    /// another.
    #[test]
    fn two_root_scope_owners_stay_unknown() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                "pub fn drive() -> usize {\n    helper()\n}\n\npub fn helper() -> usize {\n    1\n}\n",
            )],
        );
        let analyzer = fixture.analyzer();
        let drive = fixture.declaration("drive");
        let helper = fixture.declaration("helper");
        assert_eq!(
            classify_owner_relation(analyzer, Some(&drive), &helper),
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
