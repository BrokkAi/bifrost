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
use super::occurrence_rows::{ast_id, declared_fact_kind};
use super::occurrences::Namespace;
use super::routes::{IdentityAxis, SegmentResolutionStatus};
use super::spec::StructuralSpec;
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::structural_spec_for;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language,
    resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
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
        .structural_search_providers()
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
            None => note(
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

/// Record a reason once. Which wall was hit is what matters; how many chains
/// hit the same wall is not.
fn note(reasons: &mut Vec<QualifiedPathIncompleteReason>, reason: QualifiedPathIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
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

    // Discover chain roots from the classified tokens, deduplicated by the
    // root's tree node, in source order for deterministic row order.
    let mut roots: Vec<Node<'_>> = Vec::new();
    let mut seen_roots: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut ranges: Vec<(usize, usize)> = token_by_range.keys().copied().collect();
    ranges.sort_unstable();
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
    roots.sort_by_key(Node::start_byte);

    for chain_root in roots {
        let tokens = spec.path_segment_tokens(chain_root);
        if tokens.is_empty() {
            note(reasons, QualifiedPathIncompleteReason::ChainUnenumerable);
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
            note(
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
/// token, through exactly the rule occurrence rows use. `None` where the
/// adapter cannot say (Java and Rust path segments), which segment resolution
/// may later decide.
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
            | DefinitionLookupStatus::UnsupportedLanguage
            | DefinitionLookupStatus::InvalidLocation => SegmentResolutionStatus::Incomplete,
        };
        let targets = outcome.definitions;
        if segment.namespace.is_none() {
            segment.namespace = namespace_from_targets(&targets);
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
    use crate::analyzer::structural::routes::ALL_IDENTITY_AXES;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        file: ProjectFile,
        source: String,
    }

    impl Fixture {
        fn new(language: Language, relative_path: &str, source: &str) -> Self {
            Self::with_files(language, &[(relative_path, source)])
        }

        /// The first file is the one rows are derived for.
        fn with_files(language: Language, files: &[(&str, &str)]) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let mut subject = None;
            for (relative_path, source) in files {
                let file = ProjectFile::new(root.clone(), *relative_path);
                file.write(source).expect("write fixture source");
                subject.get_or_insert(file);
            }
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            );
            Self {
                _temp: temp,
                workspace,
                file: subject.expect("at least one fixture file"),
                source: files[0].1.to_owned(),
            }
        }

        fn rows(&self, options: QualifiedPathDerivationOptions) -> QualifiedPathsFileResult {
            qualified_paths_for_file(
                self.workspace.analyzer(),
                &self.file,
                options,
                &CancellationToken::new(),
            )
            .expect("derivation not cancelled")
        }

        fn at(&self, needle: &str) -> usize {
            self.source
                .find(needle)
                .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"))
        }
    }

    /// The segments of the one path whose first segment starts at `start`,
    /// ordinal-ordered, with the ordering asserted.
    fn path_segments_at(result: &QualifiedPathsFileResult, start: usize) -> Vec<&PathSegmentRow> {
        let path = result
            .paths
            .iter()
            .find(|path| path.range.start_byte == start)
            .unwrap_or_else(|| {
                panic!(
                    "no path starting at byte {start}; paths: {:?}",
                    result.paths
                )
            });
        let segments: Vec<_> = result.segments_of(path.terminal_node).collect();
        assert_eq!(segments.len(), path.segment_count as usize);
        for (position, segment) in segments.iter().enumerate() {
            assert_eq!(segment.ordinal as usize, position);
            assert_eq!(segment.path_terminal_node, path.terminal_node);
        }
        segments
    }

    /// A Java import chain is one path: ordered segments, each its own row,
    /// the terminal anchoring the path, and — because Java cannot name a path
    /// segment's namespace from the token alone — no namespace stated without
    /// resolution, rather than a guessed one.
    #[test]
    fn java_import_chain_is_one_ordered_path() {
        let fixture = Fixture::new(
            Language::Java,
            "src/Widget.java",
            concat!(
                "import java.util.List;\n",
                "class Widget {\n",
                "    List<String> items() { return null; }\n",
                "}\n",
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);

        let segments = path_segments_at(&result, fixture.at("java.util"));
        assert_eq!(
            segments.iter().map(|s| s.text.as_str()).collect::<Vec<_>>(),
            ["java", "util", "List"],
        );
        for segment in &segments {
            assert!(segment.node.is_some(), "Java segment tokens are facts");
            assert!(
                segment.resolution.is_none(),
                "ROWS_ONLY derives no resolution"
            );
        }
        // Java cannot name a scope segment's namespace from the token alone,
        // so the two path segments state none; the terminal is an import
        // target, whose namespace is the adapter's existing classification.
        assert_eq!(segments[0].namespace, None);
        assert_eq!(segments[1].namespace, None);
        assert_eq!(segments[2].namespace, Some(Namespace::Value));
        assert!(result.completeness.covers(IdentityAxis::PathSegments));
    }

    /// The generic argument count is per segment and reads the grammar's
    /// argument list: nested arguments attach to the inner segment, not the
    /// outer one, and a segment without spelled arguments has `None`.
    #[test]
    fn java_generic_arity_is_spelled_per_segment() {
        let fixture = Fixture::new(
            Language::Java,
            "src/Widget.java",
            concat!(
                "import java.util.Map;\n",
                "import java.util.List;\n",
                "class Widget {\n",
                "    java.util.Map<String, List<Integer>> index() { return null; }\n",
                "}\n",
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);

        let segments = path_segments_at(&result, fixture.at("java.util.Map<String"));
        assert_eq!(
            segments
                .iter()
                .map(|s| (s.text.as_str(), s.generic_arity))
                .collect::<Vec<_>>(),
            [("java", None), ("util", None), ("Map", Some(2))],
        );
    }

    /// A Rust path keyword (`crate`) is a real segment at a real ordinal with
    /// a genuinely absent structural identity, and a raw identifier decodes to
    /// the identifier it denotes while staying one segment.
    #[test]
    fn rust_path_keywords_and_raw_identifiers_stay_honest_segments() {
        let fixture = Fixture::new(
            Language::Rust,
            "src/lib.rs",
            concat!(
                "pub mod util {\n",
                "    pub struct r#type;\n",
                "}\n",
                "pub fn build() -> crate::util::r#type {\n",
                "    crate::util::r#type\n",
                "}\n",
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);

        let segments = path_segments_at(&result, fixture.at("crate::util::r#type {"));
        assert_eq!(
            segments
                .iter()
                .map(|s| (s.text.as_str(), s.node.is_some()))
                .collect::<Vec<_>>(),
            [("crate", false), ("util", true), ("type", true)],
        );
    }

    /// Segment resolution answers each focused segment independently: the
    /// module segment of a workspace-local Rust path resolves to the module
    /// declaration and decides the module namespace, the terminal to the
    /// struct, and the `crate` keyword's answer is an explicit status rather
    /// than an omitted row.
    #[test]
    fn rust_segment_prefixes_resolve_independently() {
        let fixture = Fixture::new(
            Language::Rust,
            "src/lib.rs",
            concat!(
                "pub mod util {\n",
                "    pub struct Widget;\n",
                "}\n",
                "pub fn build() -> crate::util::Widget {\n",
                "    crate::util::Widget\n",
                "}\n",
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::WITH_SEGMENT_RESOLUTION);

        let segments = path_segments_at(&result, fixture.at("crate::util::Widget {"));
        let util = &segments[1];
        let util_resolution = util.resolution.as_ref().expect("resolution derived");
        assert_eq!(
            util_resolution.status,
            SegmentResolutionStatus::Resolved,
            "util resolution: {util_resolution:?}"
        );
        assert_eq!(util.namespace, Some(Namespace::Module));

        let terminal = &segments[2];
        let terminal_resolution = terminal.resolution.as_ref().expect("resolution derived");
        assert_eq!(
            terminal_resolution.status,
            SegmentResolutionStatus::Resolved,
            "terminal resolution: {terminal_resolution:?}"
        );
        assert_eq!(terminal.namespace, Some(Namespace::Type));

        let keyword = &segments[0];
        assert!(
            keyword.resolution.is_some(),
            "the crate keyword's answer is an explicit status, not an omitted row"
        );
    }

    /// Python's flat dotted chain: ordered module segments whose namespace the
    /// adapter itself states, no resolution required.
    #[test]
    fn python_dotted_name_states_module_segments() {
        let fixture = Fixture::new(
            Language::Python,
            "app.py",
            concat!("import os.path\n", "print(os.path)\n"),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);

        let segments = path_segments_at(&result, fixture.at("os.path\n"));
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].text, "os");
        assert_eq!(segments[0].namespace, Some(Namespace::Module));
    }

    /// A TypeScript qualified type name is a chain, and its terminal's spelled
    /// generic arguments count at the terminal segment.
    #[test]
    fn typescript_qualified_type_chain_with_generics() {
        let fixture = Fixture::new(
            Language::TypeScript,
            "app.ts",
            concat!(
                "namespace api { export namespace types { export type Box<T> = { value: T }; } }\n",
                "let boxed: api.types.Box<string> | null = null;\n",
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);

        let segments = path_segments_at(&result, fixture.at("api.types.Box<string>"));
        assert_eq!(
            segments
                .iter()
                .map(|s| (s.text.as_str(), s.generic_arity))
                .collect::<Vec<_>>(),
            [("api", None), ("types", None), ("Box", Some(1))],
        );
    }

    /// An adapter without the axes yields per-axis incompleteness, never an
    /// empty complete answer.
    #[test]
    fn unclaimed_language_reports_incomplete_axes() {
        let fixture = Fixture::new(Language::Go, "main.go", "package main\n\nfunc main() {}\n");
        let result = fixture.rows(QualifiedPathDerivationOptions::WITH_SEGMENT_RESOLUTION);

        assert!(result.paths.is_empty());
        assert!(!result.completeness.is_complete());
        for &axis in ALL_IDENTITY_AXES {
            assert!(
                !result.completeness.covers(axis),
                "an unclaimed adapter must not cover {axis}"
            );
        }
    }

    /// A bare identifier is not a path: no single-segment rows exist.
    #[test]
    fn bare_identifiers_produce_no_paths() {
        let fixture = Fixture::new(
            Language::Rust,
            "src/lib.rs",
            concat!(
                "pub fn build() -> u32 {\n",
                "    let value = 1;\n",
                "    value\n",
                "}\n"
            ),
        );
        let result = fixture.rows(QualifiedPathDerivationOptions::ROWS_ONLY);
        assert!(result.paths.is_empty(), "paths: {:?}", result.paths);
        assert!(result.segments.is_empty());
    }
}
