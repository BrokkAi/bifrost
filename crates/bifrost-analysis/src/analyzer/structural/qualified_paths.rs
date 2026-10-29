//! The per-file qualified-path derivation layer (#1475, Milestone 2).
//!
//! A qualified path (`java.util.Map`, `crate::io::Reader`, `os.path`) is a
//! linear sequence of segment tokens the grammar records as a chain. Before
//! this module the chain was queryable only as its resolved endpoint: the
//! segment tokens carry occurrence roles, but nothing states which path a
//! segment belongs to, at which position, or what its *prefix* resolves to.
//! This module derives, per file, one [`QualifiedPathRow`] per chain and one
//! [`PathSegmentRow`] per segment — ordered, with decoded identifier text, the
//! generic argument count the source spells, and (opt-in) the resolver's
//! answer for each segment's own position.
//!
//! Three properties are load-bearing, all inherited from the sibling
//! derivation layers (#1473 occurrence rows, #1474 lexical environment):
//!
//! - Grammar knowledge stays behind the adapter boundary. The chain structure
//!   comes from two [`StructuralSpec`] hooks (`qualified_path_root`,
//!   `path_segment_tokens`) that read AST fields; this layer never splits
//!   text.
//! - Identity is structural. A segment row is addressed by its token's
//!   `(content identity, arena node)` pair where the token is a fact, so
//!   captures, occurrence rows and segment rows over one token join on one
//!   digest. A segment token that is not a fact (Rust's `crate`/`self` path
//!   keywords) still gets a row — its position in the path is real — with an
//!   explicitly absent identity.
//! - Nothing is guessed. A segment's namespace is stated only when the
//!   adapter's own classification states it or the resolver's answer decides
//!   it; everything else is an explicit status, and files whose adapter cannot
//!   enumerate a chain report the axis incomplete rather than a partial
//!   ordering.
//!
//! Rows are derived per request and never persisted; the facts snapshot
//! underneath them is the cached part.

use super::facts::FileFacts;

use super::occurrence_rows::ast_id;
use super::occurrence_rows::declared_fact_kind;

use super::occurrences::Namespace;

use super::routes::IdentityAxis;
use super::routes::SegmentResolutionStatus;

use super::spec::StructuralSpec;

use crate::analyzer::common::language_for_file;

use crate::analyzer::semantic::ContentIdentity;

use crate::analyzer::structural_spec_for;

use crate::analyzer::usages::get_definition::DefinitionLookupRequest;
use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::usages::get_definition::resolve_definition_batch_with_source_and_cancellation;

use crate::analyzer::CodeUnit;
use crate::analyzer::IAnalyzer;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;

use crate::cancellation::CancellationToken;

use crate::hash::HashMap;

use std::sync::Arc;

use tree_sitter::Node;

/// The axes this producer answers. Route relations and canonical identity are
/// other producers' territory, so a path result never claims to cover them.
pub const QUALIFIED_PATH_PRODUCER_AXES: &[IdentityAxis] =
    &[IdentityAxis::PathSegments, IdentityAxis::SegmentResolution];

/// What the caller wants derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifiedPathDerivationOptions {
    /// Resolve each segment's own position through the definition resolver
    /// and attach a [`SegmentPrefixResolution`] to every segment row. Off by
    /// default because it runs one resolution batch per file.
    pub resolve_segments: bool,
}

impl QualifiedPathDerivationOptions {
    pub const ROWS_ONLY: Self = Self {
        resolve_segments: false,
    };
    pub const WITH_SEGMENT_RESOLUTION: Self = Self {
        resolve_segments: true,
    };
}

/// One qualified-path chain of a file, anchored at its terminal segment's
/// token (the join key with the occurrence row and any capture over it).
#[derive(Debug, Clone)]
pub struct QualifiedPathRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// The terminal segment token's arena node.
    pub terminal_node: u32,
    /// The whole chain's source range, from the first segment's start to the
    /// terminal's end.
    pub range: Range,
    pub segment_count: u32,
}

impl QualifiedPathRow {
    pub fn ast_id(&self) -> String {
        ast_id(self.content_identity, self.terminal_node)
    }
}

/// What resolving one segment's own position produced.
#[derive(Debug, Clone)]
pub struct SegmentPrefixResolution {
    pub status: SegmentResolutionStatus,
    /// The declarations the segment position resolves to. Non-empty exactly
    /// for `Resolved` (one) and `Ambiguous` (several).
    pub targets: Vec<CodeUnit>,
}

/// One segment of one qualified path.
#[derive(Debug, Clone)]
pub struct PathSegmentRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// The segment token's arena node — the equijoin key with occurrence rows
    /// and captures. `None` for a segment the kind table does not admit as a
    /// fact (Rust's `crate`/`self`/`super` path keywords): its position in the
    /// path is real, its structural identity is genuinely absent.
    pub node: Option<u32>,
    pub range: Range,
    /// The terminal segment token's arena node of the owning path — the group
    /// key back to [`QualifiedPathRow`].
    pub path_terminal_node: u32,
    /// 0-based position of this segment within the path, counting every
    /// segment the grammar spells, including non-fact ones.
    pub ordinal: u32,
    /// The identifier this segment denotes, after grammar escaping is removed
    /// (Rust's `r#type` is the identifier `type`). A quoted or
    /// punctuation-bearing identifier is one segment; this text is never
    /// re-split.
    pub text: String,
    /// The namespace this segment resolves in, when either the adapter's
    /// classification or the segment's own resolution states one. `None` is
    /// "not stated", never a guessed value.
    pub namespace: Option<Namespace>,
    /// The number of generic (type) arguments the source spells at this
    /// segment (`Map<String, Integer>` spells 2 at `Map`). `None` means the
    /// source spells none here.
    pub generic_arity: Option<u32>,
    /// The resolver's answer for this segment's own position. `None` means
    /// "not derived" (a `ROWS_ONLY` derivation, or an adapter without the
    /// axis), never "nothing considered".
    pub resolution: Option<SegmentPrefixResolution>,
}

impl PathSegmentRow {
    pub fn ast_id(&self) -> Option<String> {
        self.node.map(|node| ast_id(self.content_identity, node))
    }
}

/// Why a file's path rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualifiedPathIncompleteReason {
    /// The adapter declares the axis unsupported, so absence of rows for it
    /// says nothing about the file.
    AxisUnsupported(IdentityAxis),
    /// No structural adapter is registered for the file's language.
    NoStructuralAdapter,
    /// The analyzer holds no structural facts for the file.
    FactsUnavailable,
    /// The file's source did not parse, so no chain could be read from the
    /// syntax the adapter enumerates segments from.
    SyntaxUnavailable,
    /// The adapter named a chain root but could not enumerate its segments,
    /// so at least one path is missing rather than partially ordered.
    ChainUnenumerable,
    /// At least one chain's terminal segment is not a fact, so the path has
    /// no structural anchor and was omitted entirely.
    PathAnchorUnclassified,
    /// The derivation was cancelled before segment resolution completed.
    ResolutionCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualifiedPathCompleteness {
    Complete,
    Incomplete {
        unsupported_axes: Vec<IdentityAxis>,
        reasons: Vec<QualifiedPathIncompleteReason>,
    },
}

impl QualifiedPathCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Whether rows for `axis` can be trusted to be the complete set. Always
    /// `false` for axes outside [`QUALIFIED_PATH_PRODUCER_AXES`].
    pub fn covers(&self, axis: IdentityAxis) -> bool {
        if !QUALIFIED_PATH_PRODUCER_AXES.contains(&axis) {
            return false;
        }
        match self {
            Self::Complete => true,
            Self::Incomplete {
                unsupported_axes,
                reasons,
            } => {
                !unsupported_axes.contains(&axis)
                    && !reasons.iter().any(|reason| match reason {
                        QualifiedPathIncompleteReason::AxisUnsupported(unsupported) => {
                            *unsupported == axis
                        }
                        QualifiedPathIncompleteReason::ResolutionCancelled => {
                            axis == IdentityAxis::SegmentResolution
                        }
                        QualifiedPathIncompleteReason::NoStructuralAdapter
                        | QualifiedPathIncompleteReason::FactsUnavailable
                        | QualifiedPathIncompleteReason::SyntaxUnavailable
                        | QualifiedPathIncompleteReason::ChainUnenumerable
                        | QualifiedPathIncompleteReason::PathAnchorUnclassified => true,
                    })
            }
        }
    }
}

/// Every qualified path of one file, with an explicit account of what is
/// missing. Paths are ordered by source position; segments are ordered by
/// path and then by ordinal.
#[derive(Debug, Clone)]
pub struct QualifiedPathsFileResult {
    pub paths: Vec<QualifiedPathRow>,
    pub segments: Vec<PathSegmentRow>,
    pub completeness: QualifiedPathCompleteness,
}

impl QualifiedPathsFileResult {
    /// The segments of the path anchored at `terminal_node`, in ordinal order.
    pub fn segments_of(&self, terminal_node: u32) -> impl Iterator<Item = &PathSegmentRow> {
        self.segments
            .iter()
            .filter(move |segment| segment.path_terminal_node == terminal_node)
    }
}

/// The derivation was cancelled before the rows were complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifiedPathsCancelled;

/// Every qualified path of one file.
///
/// The source is taken from the facts snapshot rather than from the caller so
/// the rows, their spellings and their resolution requests are all addressed
/// by the same `ContentIdentity` the ids embed.
pub fn qualified_paths_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    options: QualifiedPathDerivationOptions,
    cancellation: &CancellationToken,
) -> Result<QualifiedPathsFileResult, QualifiedPathsCancelled> {
    if cancellation.is_cancelled() {
        return Err(QualifiedPathsCancelled);
    }
    let language = language_for_file(file);
    let Some(spec) = structural_spec_for(language) else {
        return Ok(unavailable(
            QualifiedPathIncompleteReason::NoStructuralAdapter,
        ));
    };
    let facts = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .and_then(|provider| provider.structural_facts(file));
    let Some(facts) = facts else {
        return Ok(unavailable(QualifiedPathIncompleteReason::FactsUnavailable));
    };

    let support = spec.identity_route_support();
    let mut reasons: Vec<QualifiedPathIncompleteReason> = QUALIFIED_PATH_PRODUCER_AXES
        .iter()
        .copied()
        .filter(|axis| !support.supports_axis(*axis))
        .map(QualifiedPathIncompleteReason::AxisUnsupported)
        .collect();

    let mut paths = Vec::new();
    let mut segments = Vec::new();
    if support.supports_axis(IdentityAxis::PathSegments) {
        match parse_tree_for_language(file, language, facts.source()) {
            Some(tree) => derive_rows(
                spec,
                file,
                &facts,
                tree.root_node(),
                &mut paths,
                &mut segments,
                &mut reasons,
            ),
            None => super::note_once(
                &mut reasons,
                QualifiedPathIncompleteReason::SyntaxUnavailable,
            ),
        }
    }

    if options.resolve_segments
        && support.supports_axis(IdentityAxis::SegmentResolution)
        && !segments.is_empty()
    {
        resolve_segments(analyzer, file, &facts, &mut segments, cancellation)?;
    }

    Ok(QualifiedPathsFileResult {
        paths,
        segments,
        completeness: completeness(reasons),
    })
}

fn unavailable(reason: QualifiedPathIncompleteReason) -> QualifiedPathsFileResult {
    QualifiedPathsFileResult {
        paths: Vec::new(),
        segments: Vec::new(),
        completeness: QualifiedPathCompleteness::Incomplete {
            unsupported_axes: QUALIFIED_PATH_PRODUCER_AXES.to_vec(),
            reasons: vec![reason],
        },
    }
}

fn completeness(reasons: Vec<QualifiedPathIncompleteReason>) -> QualifiedPathCompleteness {
    if reasons.is_empty() {
        return QualifiedPathCompleteness::Complete;
    }
    let unsupported_axes = reasons
        .iter()
        .filter_map(|reason| match reason {
            QualifiedPathIncompleteReason::AxisUnsupported(axis) => Some(*axis),
            _ => None,
        })
        .collect();
    QualifiedPathCompleteness::Incomplete {
        unsupported_axes,
        reasons,
    }
}

// Canonicalize roots independently of role-token discovery order. Equal-start
// wrappers precede their inner roots, matching grammar preorder.
fn qualified_path_roots<'tree>(
    spec: &dyn StructuralSpec,
    root: Node<'tree>,
    ranges: impl IntoIterator<Item = (usize, usize)>,
) -> Vec<Node<'tree>> {
    let mut roots: Vec<Node<'_>> = Vec::new();
    let mut seen_roots: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (start_byte, end_byte) in ranges {
        let Some(token) = root.descendant_for_byte_range(start_byte, end_byte) else {
            continue;
        };
        if token.start_byte() != start_byte || token.end_byte() != end_byte {
            continue;
        }
        if let Some(chain_root) = spec.qualified_path_root(token)
            && seen_roots.insert(chain_root.id())
        {
            roots.push(chain_root);
        }
    }
    roots.sort_by_key(|node| (node.start_byte(), std::cmp::Reverse(node.end_byte())));
    roots
}

/// Walk the arena's role-bearing tokens once, discover each chain root through
/// the adapter, and turn every chain into ordered rows.
fn derive_rows(
    spec: &dyn StructuralSpec,
    file: &ProjectFile,
    facts: &FileFacts,
    root: Node<'_>,
    paths: &mut Vec<QualifiedPathRow>,
    segments: &mut Vec<PathSegmentRow>,
    reasons: &mut Vec<QualifiedPathIncompleteReason>,
) {
    let content_identity = facts.source_identity();
    let source = facts.source();

    // Role-bearing facts by exact byte range: the inverse of the extraction
    // walk over the same source the snapshot carries, so a tree token maps to
    // its arena node without heuristics.
    let mut token_by_range: HashMap<(usize, usize), u32> = HashMap::default();
    for node in 0..facts.nodes().len() {
        let node = u32::try_from(node).expect("facts arena node count fits in u32");
        if facts.occurrence_roles(node).is_empty() {
            continue;
        }
        let normalized = facts.node(node);
        token_by_range.insert(
            (normalized.range.start_byte, normalized.range.end_byte),
            node,
        );
    }

    let roots = qualified_path_roots(spec, root, token_by_range.keys().copied());

    for chain_root in roots {
        let tokens = spec.path_segment_tokens(chain_root);
        if tokens.is_empty() {
            super::note_once(reasons, QualifiedPathIncompleteReason::ChainUnenumerable);
            continue;
        }
        debug_assert!(
            tokens
                .windows(2)
                .all(|pair| { pair[0].end_byte() <= pair[1].start_byte() }),
            "path_segment_tokens must be in source order (root kind {:?})",
            chain_root.kind()
        );
        // A single segment is a bare identifier, not a path.
        if tokens.len() < 2 {
            continue;
        }
        let terminal = tokens[tokens.len() - 1];
        let Some(&terminal_node) =
            token_by_range.get(&(terminal.start_byte(), terminal.end_byte()))
        else {
            super::note_once(
                reasons,
                QualifiedPathIncompleteReason::PathAnchorUnclassified,
            );
            continue;
        };

        paths.push(QualifiedPathRow {
            file: file.clone(),
            content_identity,
            terminal_node,
            range: Range {
                start_byte: tokens[0].start_byte(),
                end_byte: terminal.end_byte(),
                start_line: tokens[0].start_position().row + 1,
                end_line: terminal.end_position().row + 1,
            },
            segment_count: u32::try_from(tokens.len()).expect("segment count fits in u32"),
        });

        for (ordinal, token) in tokens.into_iter().enumerate() {
            let node = token_by_range
                .get(&(token.start_byte(), token.end_byte()))
                .copied();
            let raw = &source[token.start_byte()..token.end_byte()];
            let text = spec.decode_spelling(raw).unwrap_or_else(|| raw.to_owned());
            let namespace = node.and_then(|node| classified_namespace(spec, facts, node));
            segments.push(PathSegmentRow {
                file: file.clone(),
                content_identity,
                node,
                range: Range {
                    start_byte: token.start_byte(),
                    end_byte: token.end_byte(),
                    start_line: token.start_position().row + 1,
                    end_line: token.end_position().row + 1,
                },
                path_terminal_node: terminal_node,
                ordinal: u32::try_from(ordinal).expect("segment ordinal fits in u32"),
                text,
                namespace,
                generic_arity: spec.segment_generic_arity(token),
                resolution: None,
            });
        }
    }
}

/// The namespace the adapter's own occurrence classification states for this
/// token, through exactly the rule occurrence rows use. Java and Rust
/// qualifiers state `PathPrefix`, which segment resolution may refine.
/// `None` means the adapter does not classify the token.
fn classified_namespace(
    spec: &dyn StructuralSpec,
    facts: &FileFacts,
    node: u32,
) -> Option<Namespace> {
    let declared = declared_fact_kind(facts, node);
    facts
        .occurrence_roles(node)
        .iter()
        .find_map(|&role| spec.occurrence_namespace(role, declared))
}

/// One definition-resolution batch per file over every segment's own position,
/// mapped onto typed per-segment statuses.
fn resolve_segments(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    facts: &FileFacts,
    segments: &mut [PathSegmentRow],
    cancellation: &CancellationToken,
) -> Result<(), QualifiedPathsCancelled> {
    let requests = segments
        .iter()
        .map(|segment| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(segment.range.start_byte),
            end_byte: Some(segment.range.end_byte),
        })
        .collect();
    let source: Arc<str> = Arc::from(facts.source());
    let outcomes = resolve_definition_batch_with_source_and_cancellation(
        analyzer,
        requests,
        file.clone(),
        source,
        cancellation,
    );
    if cancellation.is_cancelled() {
        return Err(QualifiedPathsCancelled);
    }
    assert_eq!(
        outcomes.len(),
        segments.len(),
        "definition batch returned {} outcomes for {} segment rows",
        outcomes.len(),
        segments.len()
    );

    for (segment, outcome) in segments.iter_mut().zip(outcomes) {
        let status = match outcome.status {
            DefinitionLookupStatus::Resolved => SegmentResolutionStatus::Resolved,
            DefinitionLookupStatus::Ambiguous => SegmentResolutionStatus::Ambiguous,
            DefinitionLookupStatus::NoDefinition | DefinitionLookupStatus::NotFound => {
                SegmentResolutionStatus::Unresolved
            }
            DefinitionLookupStatus::UnresolvableImportBoundary
            | DefinitionLookupStatus::Unavailable
            | DefinitionLookupStatus::Incomplete
            | DefinitionLookupStatus::Cancelled
            | DefinitionLookupStatus::ExceededBudget(_)
            | DefinitionLookupStatus::UnsupportedLanguage
            | DefinitionLookupStatus::InvalidLocation => SegmentResolutionStatus::Incomplete,
        };
        let targets = outcome.definitions;
        // `PathPrefix` is the adapter's "a qualifier: a module or a type, the
        // syntax does not say" answer (#3064). A resolved target set says
        // which, and that is strictly more precise, so it replaces the
        // syntactic claim. A stated `Module`/`Type`/`Value` is the adapter's
        // own decision and stands.
        if matches!(segment.namespace, None | Some(Namespace::PathPrefix)) {
            segment.namespace = namespace_from_targets(&targets).or(segment.namespace);
        }
        segment.resolution = Some(SegmentPrefixResolution { status, targets });
    }
    Ok(())
}

/// The namespace a resolved target set decides, when every target agrees.
/// A mixed set decides nothing — that disagreement is the ambiguity the row's
/// status already reports, not something to average over.
fn namespace_from_targets(targets: &[CodeUnit]) -> Option<Namespace> {
    let mut decided: Option<Namespace> = None;
    for target in targets {
        let namespace = if target.is_module() {
            Namespace::Module
        } else if target.is_class() {
            Namespace::Type
        } else {
            Namespace::Value
        };
        match decided {
            None => decided = Some(namespace),
            Some(existing) if existing == namespace => {}
            Some(_) => return None,
        }
    }
    decided
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn coverage_reasons_preserve_their_declared_axis_scope() {
        for &axis in super::super::routes::ALL_IDENTITY_AXES {
            assert_eq!(
                QualifiedPathCompleteness::Complete.covers(axis),
                QUALIFIED_PATH_PRODUCER_AXES.contains(&axis)
            );
        }
        for &axis in QUALIFIED_PATH_PRODUCER_AXES {
            assert!(QualifiedPathCompleteness::Complete.covers(axis));
            for reason in [
                QualifiedPathIncompleteReason::FactsUnavailable,
                QualifiedPathIncompleteReason::NoStructuralAdapter,
                QualifiedPathIncompleteReason::SyntaxUnavailable,
                QualifiedPathIncompleteReason::ChainUnenumerable,
                QualifiedPathIncompleteReason::PathAnchorUnclassified,
            ] {
                let coverage = QualifiedPathCompleteness::Incomplete {
                    unsupported_axes: vec![],
                    reasons: vec![reason],
                };
                assert!(!coverage.covers(axis));
            }
            let cancelled = QualifiedPathCompleteness::Incomplete {
                unsupported_axes: vec![],
                reasons: vec![QualifiedPathIncompleteReason::ResolutionCancelled],
            };
            assert_eq!(
                cancelled.covers(axis),
                axis != IdentityAxis::SegmentResolution
            );
            for &unsupported in QUALIFIED_PATH_PRODUCER_AXES {
                let coverage = QualifiedPathCompleteness::Incomplete {
                    unsupported_axes: vec![],
                    reasons: vec![QualifiedPathIncompleteReason::AxisUnsupported(unsupported)],
                };
                assert_eq!(coverage.covers(axis), axis != unsupported);
            }
        }
    }

    #[test]
    #[hardwon(
        "dce884c96143: quicksilver round 12 on brokk-bifrost-analysis: equal-start generic path roots depend on discovery order"
    )]
    fn generic_path_roots_follow_grammar_preorder() {
        let source = "fn f() { std::vec::Vec::<u8>::new(); other::Thing::make(); }";
        let grammar = tree_sitter_rust::LANGUAGE.into();
        let spec = &brokk_bifrost_rust::structural::RUST_STRUCTURAL_SPEC;
        let facts = super::super::extract::extract_file_facts(spec, &grammar, source).unwrap();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&grammar).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path(), "example.rs");
        let ranges = (0..facts.nodes().len())
            .filter_map(|id| {
                let id = u32::try_from(id).unwrap();
                (!facts.occurrence_roles(id).is_empty()).then(|| {
                    let range = facts.node(id).range;
                    (range.start_byte, range.end_byte)
                })
            })
            .collect::<Vec<_>>();
        let forward = qualified_path_roots(spec, tree.root_node(), ranges.iter().copied());
        let reverse = qualified_path_roots(spec, tree.root_node(), ranges.iter().rev().copied());
        assert_eq!(
            forward.iter().map(Node::byte_range).collect::<Vec<_>>(),
            reverse.iter().map(Node::byte_range).collect::<Vec<_>>()
        );
        let mut paths = vec![];
        let mut segments = vec![];
        let mut reasons = vec![];
        derive_rows(
            spec,
            &file,
            &facts,
            tree.root_node(),
            &mut paths,
            &mut segments,
            &mut reasons,
        );
        let mut expected = vec![];
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier")
                && !node.parent().is_some_and(|parent| {
                    matches!(
                        parent.kind(),
                        "scoped_identifier" | "scoped_type_identifier"
                    )
                })
            {
                expected.push((node.start_byte(), node.end_byte()));
            }
            let mut cursor = node.walk();
            stack.extend(
                node.named_children(&mut cursor)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev(),
            );
        }
        expected.dedup();
        assert!(
            expected.windows(2).any(|pair| pair[0].0 == pair[1].0),
            "grammar has equal-start wrappers: {expected:?}"
        );
        assert_eq!(
            paths
                .iter()
                .map(|row| (row.range.start_byte, row.range.end_byte))
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "qualified_paths/js_ts_tests_support.rs"]
pub mod js_ts_tests_support;
