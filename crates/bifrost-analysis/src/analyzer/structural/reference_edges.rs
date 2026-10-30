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

use super::edges::EdgeAxis;
use super::edges::EdgeProvenance;
use super::edges::OwnerRelation;
use super::edges::SiteClass;

use super::facts::FileFacts;
use super::facts::Span;

use super::kinds::NormalizedKind;
use super::kinds::Role;

use super::lexical_environment::environment_for_file;

use super::occurrence_rows::OccurrenceCompleteness;
use super::occurrence_rows::OccurrenceFileResult;
use super::occurrence_rows::OccurrenceRow;
use super::occurrence_rows::OccurrenceTarget;
use super::occurrence_rows::OccurrencesCancelled;
use super::occurrence_rows::ast_id;
use super::occurrence_rows::occurrences_for_file;
use super::occurrence_rows::occurrences_for_file_at_lines;

use super::occurrences::ALL_OCCURRENCE_ROLES;
use super::occurrences::OccurrenceClass;
use super::occurrences::OccurrenceRole;

use super::resolution::EnvironmentAxis;

use crate::analyzer::canonical_hash::CanonicalHasher;

use crate::analyzer::semantic::ContentIdentity;

use crate::analyzer::semantic::ids::StableDigest;

use crate::analyzer::usages::get_definition::DefinitionLookupStatus;

use crate::analyzer::usages::FuzzyResult;
use crate::analyzer::usages::ReferenceEngine;
use crate::analyzer::usages::ReferenceHit;
use crate::analyzer::usages::ReferenceKind;
use crate::analyzer::usages::UsageHit;
use crate::analyzer::usages::UsageHitKind;

use crate::analyzer::usages::UsageProof;
use crate::analyzer::usages::UsageQueryCompletion;

use crate::analyzer::CodeUnit;

use crate::analyzer::FqName;
use crate::analyzer::IAnalyzer;

use crate::analyzer::ProjectFile;
use crate::analyzer::Range;
use crate::analyzer::TypeHierarchyProvider;

use crate::cancellation::CancellationToken;

use crate::hash::HashMap;
use crate::hash::HashSet;

use crate::path_utils::rel_path_string;

use crate::text_utils::compute_line_starts;

use rayon::prelude::*;

use crate::analyzer::read_ledger::ReadKey;
use crate::analyzer::workspace_authority::{ReplayingMemo, ReplayingMemoEntry, memo_attribution};
use std::convert::Infallible;
use std::sync::{Arc, Mutex, OnceLock};

type RelationMemo<K, V> = ReplayingMemo<Mutex<HashMap<K, Arc<ReplayingMemoEntry<V, ReadKey>>>>>;
type ReplayingCell<V> = ReplayingMemo<OnceLock<Arc<ReplayingMemoEntry<V, ReadKey>>>>;

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

#[doc(hidden)]
pub fn reference_hits_from_fuzzy_result(
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
#[doc(hidden)]
pub struct ReferenceSiteClassifier<'analyzer> {
    analyzer: &'analyzer dyn IAnalyzer,
    #[doc(hidden)]
    pub facts: Arc<FileFacts>,
    named_accesses: ContainingSpanIndex<u32>,
    containing_nodes: ContainingSpanIndex<u32>,
    nearest_declarations: Box<[Option<NearestDeclaration>]>,
    nearest_assignments: Box<[Option<u32>]>,
    site_identities: SiteIdentityIndex,
    // The fill can read other files to prove import declarations, so a hit
    // replays the fill's reads into whichever capture asks.
    import_bindings: ReplayingCell<Option<HashSet<u32>>>,
}

/// Source-derived state shared by selected reference file wrappers.
#[doc(hidden)]
pub struct SelectedReferenceFileState<'analyzer> {
    #[doc(hidden)]
    pub source_len: usize,
    #[doc(hidden)]
    pub line_starts: Box<[usize]>,
    #[doc(hidden)]
    pub classifier: Option<ReferenceSiteClassifier<'analyzer>>,
}

impl<'analyzer> SelectedReferenceFileState<'analyzer> {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn range(&self, start_byte: usize, end_byte: usize) -> Range {
        assert!(
            start_byte <= end_byte && end_byte <= self.source_len,
            "selected reference range must fit indexed source: {start_byte}..{end_byte} of {}",
            self.source_len,
        );
        brokk_bifrost_core::analyzer::semantic_diagnostics::range_for_byte_span(
            &self.line_starts,
            start_byte,
            end_byte,
        )
    }

    #[doc(hidden)]
    pub fn new(analyzer: &'analyzer dyn IAnalyzer, file: &ProjectFile, source: &str) -> Self {
        Self {
            source_len: source.len(),
            line_starts: compute_line_starts(source).into_boxed_slice(),
            classifier: ReferenceSiteClassifier::new(analyzer, file),
        }
    }
}

/// One request-local caller projection. Admission and facts belong to the same
/// analyzer; the source is retained for usage snippets as well as line ranges.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct SelectedReferenceFileProjection<'a> {
    pub(crate) file: ProjectFile,
    #[doc(hidden)]
    pub source: String,
    #[doc(hidden)]
    pub state: SelectedReferenceFileState<'a>,
}

#[cfg(any(test, feature = "test-support"))]
impl<'a> SelectedReferenceFileProjection<'a> {
    #[doc(hidden)]
    pub fn new(
        analyzer: &'a dyn IAnalyzer,
        context_analyzer: &'a dyn IAnalyzer,
        file: &ProjectFile,
        matches_selected: impl FnOnce(&str) -> bool,
    ) -> crate::analyzer::store::Result<Self> {
        let source = analyzer.indexed_source(file).ok_or_else(|| {
            crate::analyzer::store::StoreError::new(format!(
                "selected reverse reference has no indexed source: {file}"
            ))
        })?;
        if !matches_selected(&source) {
            return Err(crate::analyzer::store::StoreError::new(format!(
                "selected reverse reference source changed before projection: {file}"
            )));
        }
        let mut state = SelectedReferenceFileState::new(analyzer, file, &source);
        if let Some(classifier) = state.classifier.as_mut() {
            // Facts belong to the caller, while target-owner lookup must still
            // see the whole selected workspace for cross-language static uses.
            classifier.analyzer = context_analyzer;
        }
        Ok(Self {
            state,
            source,
            file: file.clone(),
        })
    }
}

impl<'analyzer> ReferenceSiteClassifier<'analyzer> {
    /// Build the classifier from the analyzer's one facts snapshot for `file`.
    /// Returns `None` when the file has no structural adapter or facts.
    #[doc(hidden)]
    pub fn new(analyzer: &'analyzer dyn IAnalyzer, file: &ProjectFile) -> Option<Self> {
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
            if (node.kind.satisfies(NormalizedKind::Call)
                || node.kind == NormalizedKind::FieldAccess)
                && let Some(name) = node.name
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
            import_bindings: ReplayingMemo::new(OnceLock::new()),
        })
    }

    /// Native demand inputs may also read an import's local binding. Its
    /// structured occurrence is still an import, not another runtime use.
    #[doc(hidden)]
    pub fn is_import_binding_reference(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
    ) -> bool {
        let Some(&node) = self.site_identities.by_range.get(&(start_byte, end_byte)) else {
            return false;
        };
        if !self
            .facts
            .occurrence_roles(node)
            .iter()
            .copied()
            .any(is_import_binding_role)
        {
            return false;
        }
        self.import_bindings
            .read(&memo_attribution(self.analyzer), |cell, capture| {
                Ok::<_, Infallible>(Arc::clone(cell.get_or_init(|| {
                    Arc::new(capture.build(|| import_binding_nodes_for_file(self.analyzer, file)))
                })))
            })
            .unwrap()
            .as_ref()
            .is_some_and(|bindings| bindings.contains(&node))
    }

    /// Classify one exact source range against its resolved declaration.
    #[doc(hidden)]
    pub fn classify_reference_kind(
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
                    usize::from(!node.kind.satisfies(NormalizedKind::Call)),
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
            if node.kind.satisfies(NormalizedKind::Call) {
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
    #[doc(hidden)]
    pub fn call_range_containing_reference(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<Range> {
        let id = self
            .named_accesses
            .best_containing_by_key(start_byte, end_byte, |id| {
                let node = self.facts.node(id);
                (
                    usize::from(!node.kind.satisfies(NormalizedKind::Call)),
                    node.range.end_byte - node.range.start_byte,
                    id,
                )
            })?;
        let node = self.facts.node(id);
        node.kind
            .satisfies(NormalizedKind::Call)
            .then_some(node.range)
    }

    /// Exact content-scoped AST identity for an identifier at this byte range.
    /// `None` means the structural snapshot has no identifier with that exact
    /// range; this method never guesses from containment or source text.
    #[doc(hidden)]
    pub fn ast_id(&self, start_byte: usize, end_byte: usize) -> Option<String> {
        self.site_identities.ast_id_for_bytes(start_byte, end_byte)
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn classify_reference_kind_scan_oracle(
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
                && (node.kind.satisfies(NormalizedKind::Call)
                    || node.kind == NormalizedKind::FieldAccess)
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(_, node)| {
        (
            usize::from(!node.kind.satisfies(NormalizedKind::Call)),
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
        if node.kind.satisfies(NormalizedKind::Call) {
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
        let context = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        per_file.extend(
            units[warm_prefix..]
                .par_iter()
                .map(|unit| context.run(|| scan_one(unit)))
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
    #[doc(hidden)]
    pub fn incomplete(
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
pub struct OwnerRelationMemo {
    ancestors: RelationMemo<CodeUnit, Vec<CodeUnit>>,
}

impl Default for OwnerRelationMemo {
    fn default() -> Self {
        Self {
            ancestors: ReplayingMemo::new(Mutex::default()),
        }
    }
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
                    .read(&memo_attribution(analyzer), |cache, capture| {
                        if let Some(entry) = cache
                            .lock()
                            .expect("owner relation memo poisoned")
                            .get(site)
                            .cloned()
                        {
                            return Ok::<_, Infallible>(entry);
                        }
                        let entry = Arc::new(capture.build(|| hierarchy.get_ancestors(site)));
                        cache
                            .lock()
                            .expect("owner relation memo poisoned")
                            .insert(site.clone(), Arc::clone(&entry));
                        Ok(entry)
                    })
                    .unwrap()
                    .contains(target)
            },
        )
    }
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
fn import_binding_nodes_for_file(
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
    // A binder names the local token, but an aliased import also contains
    // the imported target token. Both are import occurrences. Select the
    // enclosing import declarations from proven binders, then visit each
    // declaration once; this also preserves the re-export distinction.
    let mut declarations = HashSet::default();
    for binding in environment
        .bindings
        .iter()
        .filter(|binding| binding.import.is_some())
    {
        let mut ancestor = binding.node;
        while let Some(node) = ancestor {
            if facts.node(node).kind == NormalizedKind::Import {
                declarations.insert(node);
                break;
            }
            ancestor = facts.node(node).parent;
        }
    }
    Some(
        declarations
            .into_iter()
            .flat_map(|declaration| declaration..facts.subtree_end(declaration))
            .filter(|&node| {
                facts
                    .occurrence_roles(node)
                    .iter()
                    .copied()
                    .any(is_import_binding_role)
            })
            .collect(),
    )
}

fn is_import_binding_role(role: OccurrenceRole) -> bool {
    matches!(
        role,
        OccurrenceRole::ImportTarget | OccurrenceRole::ImportAlias
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
                ambiguous_candidate: false,
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

/// One language's generation-bound selected inverse reference handle.
///
/// The index is that language's own answer to "which sites refer to this
/// declaration", queried lazily from its selected resolution facts and bound to
/// the analyzer generation it was admitted in. A declaration the handle does not
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
/// One handle per language per request shares admission and generation binding
/// across the subjects an `edges_of` query or an edge assert names. Each target
/// query owns its candidates and results; the handle retains no workspace map.
pub struct SelectedInverseEdgeCache {
    languages: RelationMemo<crate::analyzer::Language, SelectedInverseLanguage>,
}

impl Default for SelectedInverseEdgeCache {
    fn default() -> Self {
        Self {
            languages: ReplayingMemo::new(Mutex::default()),
        }
    }
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
        let provider = crate::analyzer::languages::language_support_for_hook(
            language,
            "selected_inverse_reference_provider",
        )?
        .selected_inverse_reference_provider()?;
        let state = self
            .languages
            .read(&memo_attribution(analyzer), |cache, capture| {
                if let Some(entry) = cache
                    .lock()
                    .expect("selected inverse memo poisoned")
                    .get(&language)
                    .cloned()
                {
                    return Ok::<_, Infallible>(entry);
                }
                let entry = Arc::new(capture.build(|| {
                    match provider.build_selected_inverse_index(analyzer, cancellation) {
                        SelectedInverseIndexOutcome::Ready(index) => {
                            SelectedInverseLanguage::Ready(index)
                        }
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
                        SelectedInverseIndexOutcome::Stale(reason) => {
                            SelectedInverseLanguage::Refused(
                                EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                                    reason_kind: "stale".to_string(),
                                    reason,
                                },
                            )
                        }
                        SelectedInverseIndexOutcome::StoreError(reason) => {
                            SelectedInverseLanguage::Refused(
                                EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                                    reason_kind: "store_error".to_string(),
                                    reason,
                                },
                            )
                        }
                    }
                }));
                cache
                    .lock()
                    .expect("selected inverse memo poisoned")
                    .insert(language, Arc::clone(&entry));
                Ok(entry)
            })
            .unwrap();
        Some(match &*state {
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
    if crate::analyzer::read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
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

#[doc(hidden)]
pub fn forward_axis_gate(
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

#[doc(hidden)]
pub fn forward_edges_from_occurrences(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    occurrences: OccurrenceFileResult,
    generation: u64,
) -> Result<EdgeDerivationResult, OccurrencesCancelled> {
    let import_target_nodes = import_binding_nodes_for_file(analyzer, file).unwrap_or_default();
    let reference_sites = ReferenceSiteClassifier::new(analyzer, file);
    let mut edges = Vec::new();
    let mut reasons = Vec::new();
    for row in &occurrences.rows {
        if let Some(reason) = forward_resolution_incomplete_reason(row)
            && !reasons.contains(&reason)
        {
            reasons.push(reason);
        }
        let OccurrenceTarget::Resolved(units) = &row.target else {
            continue;
        };
        let proof = if row.resolution_status == Some(DefinitionLookupStatus::Resolved)
            && units.len() == 1
        {
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
                ambiguous_candidate: false,
                usage_kind: classify_forward_usage_kind(row, &import_target_nodes, owner_relation),
                site_class: SiteClass::UseSite,
                owner_relation,
                provenance: EdgeProvenance::Forward,
                generation,
            });
        }
    }

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

fn forward_resolution_incomplete_reason(row: &OccurrenceRow) -> Option<EdgeIncompleteReason> {
    if row.class != OccurrenceClass::Reference {
        return None;
    }
    match row.resolution_status? {
        DefinitionLookupStatus::Resolved | DefinitionLookupStatus::NoDefinition => None,
        DefinitionLookupStatus::Cancelled => Some(EdgeIncompleteReason::Cancelled),
        DefinitionLookupStatus::Unavailable
        | DefinitionLookupStatus::Incomplete
        | DefinitionLookupStatus::UnresolvableImportBoundary
        | DefinitionLookupStatus::Ambiguous
        | DefinitionLookupStatus::UnsupportedLanguage
        | DefinitionLookupStatus::InvalidLocation
        | DefinitionLookupStatus::NotFound
        | DefinitionLookupStatus::ExceededBudget(_) => {
            Some(EdgeIncompleteReason::ForwardResolutionIncomplete)
        }
    }
}

// The selected inverse adapter belongs with this engine-owned trait; its
// concrete reference index lives in the resolution layer below the engine.
#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::structural::reference_edges::SelectedInverseReferenceIndex
    for crate::analyzer::resolution::fact_reference_edges::SelectedReferenceInverseIndex
{
    fn generation(&self) -> u64 {
        crate::analyzer::resolution::fact_reference_edges::SelectedReferenceInverseIndex::generation(
            self,
        )
    }

    fn inverse_for(
        &self,
        target: &crate::analyzer::CodeUnit,
    ) -> crate::analyzer::structural::reference_edges::EdgeDerivationResult {
        (*crate::analyzer::resolution::fact_reference_edges::SelectedReferenceInverseIndex::inverse_for(self, target)).clone()
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests {

    #[cfg(test)]
    use super::*;

    #[doc(hidden)]
    pub const JAVA_REFERENCE_KIND_SITES: &str = r#"package fixture;

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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const JAVA_TARGET: &str =
        "package fixture;\n\npublic class Registry {\n    public void register() {\n    }\n}\n";
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const JAVA_CALLER: &str = "package fixture;\n\npublic class Startup {\n    void boot(Registry registry) {\n        registry.register();\n    }\n}\n";

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const JAVA_BASE: &str =
        "package fixture;\n\npublic class Base {\n    public void ping() {\n    }\n}\n";
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const JAVA_DERIVED: &str = "package fixture;\n\npublic class Derived extends Base {\n    void run() {\n        helper();\n        run();\n    }\n\n    void helper() {\n    }\n}\n";

    #[cfg(test)]
    #[test]
    fn confidence_roundtrips_in_public_units() {
        let temp = tempfile::tempdir().unwrap();
        let analyzer = super::super::identity_routes::tests::MetadataAnalyzer::new(temp.path());
        let file = ProjectFile::new(temp.path(), "example.py");
        let unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Function,
            "",
            "f",
        );
        for confidence in [-2.0, 0.0, 0.1234567, 0.5, 1.0, 4.0] {
            let mut hit = UsageHit::new(file.clone(), 1, 0, 1, unit.clone(), confidence, "");
            hit.reference_kind = Some(ReferenceKind::StaticReference);
            let reference =
                reference_hit_for_target(&analyzer, hit, unit.clone(), UsageProof::Proven);
            assert!((reference.confidence_f64() - confidence.clamp(0.0, 1.0)).abs() <= 0.000001);
        }
    }

    #[cfg(test)]
    fn site_edge(file: ProjectFile, start: usize) -> ReferenceEdgeRow {
        ReferenceEdgeRow {
            target: CodeUnit::new(
                file.clone(),
                crate::analyzer::CodeUnitType::Function,
                "",
                "f",
            ),
            site: EdgeSite {
                file,
                range: Range {
                    start_byte: start,
                    end_byte: start + 1,
                    start_line: 1,
                    end_line: 1,
                },
                ast_id: None,
                enclosing: None,
            },
            reference_kind: None,
            proof: UsageProof::Proven,
            ambiguous_candidate: false,
            usage_kind: UsageHitKind::Reference,
            site_class: SiteClass::UseSite,
            owner_relation: OwnerRelation::Unknown,
            provenance: EdgeProvenance::Inverse,
            generation: 0,
        }
    }

    #[cfg(test)]
    #[test]
    fn inverse_answer_digest_depends_on_site_set_and_completeness() {
        let roots = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let result = |root: &std::path::Path| EdgeDerivationResult {
            edges: vec![
                site_edge(ProjectFile::new(root, "a.py"), 1),
                site_edge(ProjectFile::new(root, "b.py"), 3),
            ],
            completeness: EdgeCompleteness::Complete,
            provenance: EdgeProvenance::Inverse,
            generation: 0,
        };
        let baseline = result(roots[0].path());
        let digest = inverse_edge_answer_digest(&baseline);
        for root in &roots {
            let mut alternate = result(root.path());
            alternate.edges.reverse();
            let mut duplicate = alternate.edges[0].clone();
            duplicate.proof = UsageProof::Unproven;
            duplicate.reference_kind = Some(ReferenceKind::StaticReference);
            alternate.edges.push(duplicate);
            assert_eq!(inverse_edge_answer_digest(&alternate), digest);
        }
        let mut moved = baseline.clone();
        moved.edges[0].site.range.end_byte += 1;
        assert_ne!(inverse_edge_answer_digest(&moved), digest);
        moved = baseline.clone();
        moved.edges[0].site.file = ProjectFile::new(roots[0].path(), "c.py");
        assert_ne!(inverse_edge_answer_digest(&moved), digest);
        moved = baseline;
        moved.completeness = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::Cancelled],
        };
        assert_ne!(inverse_edge_answer_digest(&moved), digest);
    }

    #[cfg(test)]
    #[test]
    fn cancelled_scan_merges_only_the_serial_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let analyzer = super::super::identity_routes::tests::MetadataAnalyzer::new(temp.path());
        // The first width units are warmed serially. Put the cancellation in
        // the parallel suffix and force its successor to finish first.
        for width in [1, 2, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(width)
                .build()
                .unwrap();
            let prefix = width.max(2);
            let files = (0..prefix + 2)
                .map(|i| ProjectFile::new(temp.path(), format!("{i}.py")))
                .collect::<Vec<_>>();
            let completed = std::sync::atomic::AtomicBool::new(false);
            let run = pool.install(|| {
                ReferenceEngine::new().scan_units(&analyzer, &files, |file| {
                    let index = files
                        .iter()
                        .position(|candidate| candidate == file)
                        .unwrap();
                    if index == prefix {
                        if width > 1 {
                            while !completed.load(std::sync::atomic::Ordering::Acquire) {
                                std::thread::yield_now();
                            }
                        }
                        return Err(OccurrencesCancelled);
                    }
                    let result = EdgeDerivationResult {
                        edges: vec![site_edge(file.clone(), index)],
                        completeness: EdgeCompleteness::Complete,
                        provenance: EdgeProvenance::Forward,
                        generation: 0,
                    };
                    if index == prefix + 1 {
                        completed.store(true, std::sync::atomic::Ordering::Release);
                    }
                    Ok(result)
                })
            });
            assert!(completed.load(std::sync::atomic::Ordering::Acquire));
            assert_eq!(
                run.edges
                    .iter()
                    .map(|edge| edge.site.file.clone())
                    .collect::<Vec<_>>(),
                files[..prefix]
            );
            assert_eq!(
                run.work,
                ReferenceWork {
                    candidate_files: files.len(),
                    scanned_files: prefix,
                    scanned_source_bytes: 0,
                    emitted_edges: prefix
                }
            );
            assert_eq!(
                run.completeness,
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::Cancelled]
                }
            );
        }
    }

    #[cfg(test)]
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
    #[cfg(test)]
    #[test]
    fn interval_containment_matches_exhaustive_ordered_spans() {
        let entries: Vec<_> = (0..=5)
            .flat_map(|start_byte| {
                (start_byte..=5).map(move |end_byte| Span {
                    start_byte,
                    end_byte,
                })
            })
            .enumerate()
            .map(|(id, span)| (span, id))
            .collect();
        for rotation in 0..entries.len() {
            let mut input = entries.clone();
            input.rotate_left(rotation);
            if rotation % 2 == 0 {
                input.reverse();
            }
            let index = ContainingSpanIndex::new(input);
            for start in 0..=6 {
                for end in start..=6 {
                    let expected = entries
                        .iter()
                        .filter(|(span, _)| span.start_byte <= start && end <= span.end_byte)
                        .map(|(_, id)| *id)
                        .min();
                    assert_eq!(
                        index.best_containing_by_key(start, end, |id| id),
                        expected,
                        "query {start}..{end}, rotation {rotation}"
                    );
                }
            }
        }
        assert_eq!(
            ContainingSpanIndex::<usize>::new([]).best_containing_by_key(0, 0, |id| id),
            None
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

pub use crate::analyzer::resolution::reference_vocabulary::{
    EDGE_PRODUCER_AXES, EdgeCompleteness, EdgeIncompleteReason, EdgeSite, ReferenceEdgeRow,
    is_same_owner_member_reference,
};
