//! The driver for the inverted whole-workspace edge build.
//!
//! `usage_graph` builds a caller→callee graph. The scalable shape is a single
//! pass over files: walk each file once, resolve every reference to the callee it
//! names, and attribute it to its enclosing declaration. This module owns
//! everything except the walk:
//!
//! - [`build_file_declarations`] — the per-file declaration index, from an
//!   `IAnalyzer` or a cached `FileState`.
//! - [`parse_and_collect`] — parse one file on demand, hand the language a
//!   [`FileEdgeScanInput`], and drop the tree when it returns.
//! - [`build_edge_output`] — the parallel fan-out over files.
//! - [`merge_and_cap`] — sum per-file results and drop callees past the call-site
//!   cap into `truncated`.
//!
//! A language supplies one function per file: `FnOnce(&FileEdgeScanInput<K>) ->
//! PerFileEdges<K>`. Both of those types, and the per-reference accounting rules
//! on `PerFileEdges`, live in `brokk-bifrost-core`, so the scan is pure logic
//! over core types and a language crate can implement it without depending on
//! this one. See the Go implementation in [`super::go_graph`] for the reference
//! shape.
//!
//! The engine is generic over its node-key type `K` (see [`NodeKey`]). Most
//! languages are package-scoped: a bare fqn is globally unique, so `K = String`
//! (the default). Module-scoped ecosystems (JS/TS), where the same bare export
//! name in two files is two distinct symbols, instantiate the same engine with
//! `K = UsageNodeKey` so endpoints carry the file. There is one implementation of
//! every accounting rule — only the key type differs.

pub(crate) use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    CallSite, ClassRangeIndex, FileDeclarations, FileEdgeScanInput, NodeKey, PerFileEdges,
    UsageEdgeWeights, UsageEdges, UsageNodeKey, UsageReferenceCounts, UsageReferenceKind,
    classify_reference_node, first_precise,
};

use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::parsed_tree::{
    ParsedTreeFile, parse_tree_sitter_file, parse_tree_sitter_source,
};
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::BTreeMap;
use tree_sitter::Language as TreeSitterLanguage;

/// [`ClassRangeIndex`] over a persisted file state, for scans that already
/// hydrated one and would otherwise pay the declaration/range queries twice.
pub(crate) fn class_range_index_from_state(state: &FileState) -> ClassRangeIndex {
    ClassRangeIndex::from_class_spans(
        state
            .declarations
            .iter()
            .filter(|unit| unit.is_class())
            .flat_map(|unit| {
                state
                    .ranges
                    .get(unit)
                    .into_iter()
                    .flatten()
                    .map(move |range| (unit.clone(), *range))
            }),
    )
}

/// A callee with more distinct call sites than this is reported as truncated and
/// contributes no edges. Tied to the per-symbol scan's guardrail
/// (`DEFAULT_MAX_USAGES`) so `usage_graph`'s truncation matches `scan_usages`.
pub(crate) const MAX_CALLSITES: usize = crate::analyzer::usages::DEFAULT_MAX_USAGES;

/// Selects how a whole-workspace per-file scan is finalized. Language builders
/// are generic over this trait so the AST walk is written once while callers can
/// request either site-bearing API edges or compact weights for graph algorithms.
pub(crate) trait UsageEdgeBuildOutput<K: NodeKey>: Sized {
    fn merge(per_file: Vec<PerFileEdges<K>>) -> Self;
}

impl<K: NodeKey> UsageEdgeBuildOutput<K> for UsageEdges<K> {
    fn merge(per_file: Vec<PerFileEdges<K>>) -> Self {
        merge_and_cap(per_file)
    }
}

impl<K: NodeKey> UsageEdgeBuildOutput<K> for UsageEdgeWeights<K> {
    fn merge(per_file: Vec<PerFileEdges<K>>) -> Self {
        merge_weights_and_cap(per_file)
    }
}

pub(crate) fn build_file_declarations<K: NodeKey>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> FileDeclarations<K> {
    let mut enclosers = Vec::new();
    let mut definitions: HashMap<K, Vec<(usize, usize)>> = HashMap::default();
    for unit in analyzer.declarations(file) {
        let key = K::from_unit(&unit);
        for unit_range in analyzer.ranges(&unit) {
            let span = (unit_range.start_byte, unit_range.end_byte);
            enclosers.push((span.0, span.1, key.clone()));
            definitions.entry(key.clone()).or_default().push(span);
        }
    }
    FileDeclarations {
        enclosers,
        definitions,
    }
}

pub(crate) fn build_file_declarations_from_state<K: NodeKey>(
    state: &FileState,
) -> FileDeclarations<K> {
    let mut enclosers = Vec::new();
    let mut definitions: HashMap<K, Vec<(usize, usize)>> = HashMap::default();
    for unit in state
        .declarations
        .iter()
        .filter(|unit| !unit.is_file_scope())
    {
        let key = K::from_unit(unit);
        for unit_range in state.ranges.get(unit).into_iter().flatten() {
            let span = (unit_range.start_byte, unit_range.end_byte);
            enclosers.push((span.0, span.1, key.clone()));
            definitions.entry(key.clone()).or_default().push(span);
        }
    }
    FileDeclarations {
        enclosers,
        definitions,
    }
}

/// Drive a whole-workspace inverted edge build over `files` in parallel, where each
/// language closure produces one file's [`PerFileEdges`] (or `None` to skip it).
///
/// This owns the language-agnostic parts — the parallel fan-out and the final
/// merge/cap — and leaves each language a single `scan(file) -> Option<PerFileEdges>`
/// closure. The closure obtains the file's source/tree/line starts (the local-parse
/// languages parse it on demand via [`super::parsed_tree::parse_tree_sitter_file`];
/// the graph-based languages borrow it from their project graph), then builds its
/// edges with [`collect_file_edges`]. Because nothing is borrowed across the walk,
/// a closure that parses on demand can drop its tree before returning — so at most a
/// handful of trees (≈ the rayon worker count) are live at once instead of the whole
/// workspace.
///
/// `keep_file` drops out-of-scope caller files (tests / path filter) before the
/// closure runs. See the Go implementation in [`super::go_graph`] for the canonical
/// `scan` shape.
#[allow(clippy::redundant_closure)] // the closure borrows `scan`; see the note above
pub(crate) fn build_edge_weights<K, KeepFn, ScanFn>(
    files: &[ProjectFile],
    keep_file: KeepFn,
    scan: ScanFn,
) -> UsageEdgeWeights<K>
where
    K: NodeKey + Send,
    KeepFn: Fn(&ProjectFile) -> bool + Sync,
    ScanFn: Fn(&ProjectFile) -> Option<PerFileEdges<K>> + Sync,
{
    build_edge_output(files, keep_file, scan)
}

#[allow(clippy::redundant_closure)] // the closure borrows `scan`; see the note above
pub(crate) fn build_edge_output<K, Output, KeepFn, ScanFn>(
    files: &[ProjectFile],
    keep_file: KeepFn,
    scan: ScanFn,
) -> Output
where
    K: NodeKey + Send,
    Output: UsageEdgeBuildOutput<K>,
    KeepFn: Fn(&ProjectFile) -> bool + Sync,
    ScanFn: Fn(&ProjectFile) -> Option<PerFileEdges<K>> + Sync,
{
    Output::merge(collect_per_file_edges(files, keep_file, scan))
}

#[allow(clippy::redundant_closure)] // the closure borrows `scan`; see the note below
fn collect_per_file_edges<K, KeepFn, ScanFn>(
    files: &[ProjectFile],
    keep_file: KeepFn,
    scan: ScanFn,
) -> Vec<PerFileEdges<K>>
where
    K: NodeKey + Send,
    KeepFn: Fn(&ProjectFile) -> bool + Sync,
    ScanFn: Fn(&ProjectFile) -> Option<PerFileEdges<K>> + Sync,
{
    files
        .par_iter()
        .filter(|file| keep_file(file))
        // Borrow `scan` rather than move it: it's `Sync` but not necessarily `Send`,
        // and rayon shares one mapper across worker threads.
        .filter_map(|file| scan(file))
        .collect()
}

/// Build one file's edges: construct its declaration index and the
/// [`FileEdgeScanInput`] the language reads, run the language `scan`, and stamp the
/// file path onto the result. Every borrow the input hands out is scoped to this
/// call, so the caller is free to drop the parsed tree / source / line starts as
/// soon as this returns.
pub(crate) fn collect_file_edges<K, S>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    nodes: &HashSet<K>,
    parsed: &ParsedTreeFile,
    scan: S,
) -> PerFileEdges<K>
where
    K: NodeKey,
    S: FnOnce(&FileEdgeScanInput<'_, K>) -> PerFileEdges<K>,
{
    let declarations = build_file_declarations(analyzer, file);
    collect_file_edges_with_declarations(file, nodes, parsed, declarations, scan)
}

pub(crate) fn collect_file_edges_with_declarations<K, S>(
    file: &ProjectFile,
    nodes: &HashSet<K>,
    parsed: &ParsedTreeFile,
    declarations: FileDeclarations<K>,
    scan: S,
) -> PerFileEdges<K>
where
    K: NodeKey,
    S: FnOnce(&FileEdgeScanInput<'_, K>) -> PerFileEdges<K>,
{
    let input = FileEdgeScanInput::new(
        &parsed.tree,
        parsed.source.as_str(),
        &parsed.line_starts,
        nodes,
        &declarations,
    );
    let mut out = scan(&input);
    out.path = crate::path_utils::rel_path_string(file);
    out
}

/// Parse `file` on demand, build its edges via [`collect_file_edges`], and drop the
/// tree / source / line starts when this returns — bounding live trees to ≈ the rayon
/// worker count. Returns `None` to skip an unreadable or empty file. The `scan`
/// closure receives the file's [`FileEdgeScanInput`] and owns the language AST walk.
/// Centralizing the parse, the skip-on-failure, and the tree-lifetime scoping here
/// keeps the six local-parse adapters from each repeating them, and gives a single
/// home for any later parse-failure handling, tracing, or memory instrumentation.
/// See the Java builder for the shape.
///
/// String-keyed only: the six local-parse package languages are package-scoped, so
/// generalizing this over [`NodeKey`] would push file-scoping bounds onto code that
/// has no business knowing about it. Module-scoped languages route through their own
/// cross-file index instead of this on-demand parse.
pub(crate) fn parse_and_collect<S>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    nodes: &HashSet<String>,
    language: &TreeSitterLanguage,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&FileEdgeScanInput<'_>) -> PerFileEdges,
{
    let parsed = parse_tree_sitter_file(file, language)?;
    Some(collect_file_edges(analyzer, file, nodes, &parsed, scan))
}

pub(crate) fn parse_and_collect_with_declarations<S>(
    file: &ProjectFile,
    nodes: &HashSet<String>,
    language: &TreeSitterLanguage,
    declarations: FileDeclarations,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&FileEdgeScanInput<'_>) -> PerFileEdges,
{
    let parsed = parse_tree_sitter_file(file, language)?;
    Some(collect_file_edges_with_declarations(
        file,
        nodes,
        &parsed,
        declarations,
        scan,
    ))
}

pub(crate) fn parse_source_and_collect_with_declarations<S>(
    source: String,
    file: &ProjectFile,
    nodes: &HashSet<String>,
    language: &TreeSitterLanguage,
    declarations: FileDeclarations,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&FileEdgeScanInput<'_>) -> PerFileEdges,
{
    let parsed = parse_tree_sitter_source(source, language)?;
    Some(collect_file_edges_with_declarations(
        file,
        nodes,
        &parsed,
        declarations,
        scan,
    ))
}

/// Sum per-file results and drop callees past [`MAX_CALLSITES`] into `truncated`.
pub(crate) fn merge_and_cap<K: NodeKey>(per_file: Vec<PerFileEdges<K>>) -> UsageEdges<K> {
    // Each file's `edge_lines` already holds the distinct lines for that file, so
    // concatenating per-file `(path, line)` pairs yields distinct `(file, line)`
    // sites per edge. Unioning line numbers across files would instead collapse the
    // same line number appearing in two files (e.g. a partial class) and undercount.
    let mut edge_sites: BTreeMap<(K, K), Vec<CallSite>> = BTreeMap::new();
    let mut callsites: BTreeMap<K, usize> = BTreeMap::new();
    let mut unproven_inbound: BTreeMap<K, usize> = BTreeMap::new();
    for file in per_file {
        for (key, lines) in file.edge_lines {
            let sites = edge_sites.entry(key).or_default();
            sites.extend(lines.into_keys().map(|line| CallSite {
                path: file.path.clone(),
                line,
            }));
        }
        for (callee, sites) in file.callsites {
            *callsites.entry(callee).or_insert(0) += sites.len();
        }
        for (callee, sites) in file.unproven_inbound {
            *unproven_inbound.entry(callee).or_insert(0) += sites.len();
        }
    }

    let truncated: BTreeMap<K, usize> = callsites
        .into_iter()
        .filter(|(_, total)| *total > MAX_CALLSITES)
        .collect();
    let edges: BTreeMap<(K, K), Vec<CallSite>> = edge_sites
        .into_iter()
        .filter(|((_, callee), _)| !truncated.contains_key(callee))
        .map(|(key, mut sites)| {
            // Deterministic output independent of file/line hash iteration order.
            sites.sort();
            (key, sites)
        })
        .collect();

    UsageEdges {
        edges,
        truncated,
        unproven_inbound,
    }
}

pub(crate) fn merge_weights_and_cap<K: NodeKey>(
    per_file: Vec<PerFileEdges<K>>,
) -> UsageEdgeWeights<K> {
    let mut edge_weights: BTreeMap<(K, K), UsageReferenceCounts> = BTreeMap::new();
    let mut callsites: BTreeMap<K, usize> = BTreeMap::new();
    let mut unproven_inbound: BTreeMap<K, usize> = BTreeMap::new();
    for file in per_file {
        for (key, lines) in file.edge_lines {
            let counts = edge_weights.entry(key).or_default();
            for kind in lines.into_values() {
                counts.record(kind);
            }
        }
        for (callee, sites) in file.callsites {
            *callsites.entry(callee).or_insert(0) += sites.len();
        }
        for (callee, sites) in file.unproven_inbound {
            *unproven_inbound.entry(callee).or_insert(0) += sites.len();
        }
    }

    let truncated: BTreeMap<K, usize> = callsites
        .into_iter()
        .filter(|(_, total)| *total > MAX_CALLSITES)
        .collect();
    let edges: BTreeMap<(K, K), UsageReferenceCounts> = edge_weights
        .into_iter()
        .filter(|((_, callee), _)| !truncated.contains_key(callee))
        .collect();

    UsageEdgeWeights {
        edges,
        truncated,
        unproven_inbound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_utils::find_line_index_for_offset;
    use tree_sitter::Node;

    fn find_node<'tree>(root: Node<'tree>, source: &str, kind: &str, text: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind
                && source
                    .get(node.start_byte()..node.end_byte())
                    .is_some_and(|candidate| candidate == text)
            {
                return node;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        panic!("missing {kind} node {text:?}");
    }

    #[test]
    fn structured_reference_classifier_distinguishes_rust_kinds() {
        let source = "fn caller(value: Model) { helper(); value.member; value.run(); OTHER; }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        assert_eq!(
            classify_reference_node(find_node(root, source, "type_identifier", "Model")),
            UsageReferenceKind::Type
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "helper")),
            UsageReferenceKind::Call
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "field_identifier", "member")),
            UsageReferenceKind::Member
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "field_identifier", "run")),
            UsageReferenceKind::Call
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "OTHER")),
            UsageReferenceKind::Other
        );
    }

    #[test]
    fn structured_reference_classifier_distinguishes_python_calls_and_members() {
        let source = "def caller(value: Model):\n    helper()\n    value.member\n    value.run()\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "Model")),
            UsageReferenceKind::Type
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "helper")),
            UsageReferenceKind::Call
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "member")),
            UsageReferenceKind::Member
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "run")),
            UsageReferenceKind::Call
        );
    }

    #[test]
    fn structured_reference_classifier_distinguishes_typescript_kinds() {
        let source =
            "function caller(value: Model) { helper(); value.member; value.run(); OTHER; }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        assert_eq!(
            classify_reference_node(find_node(root, source, "type_identifier", "Model")),
            UsageReferenceKind::Type
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "helper")),
            UsageReferenceKind::Call
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "property_identifier", "member")),
            UsageReferenceKind::Member
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "property_identifier", "run")),
            UsageReferenceKind::Call
        );
        assert_eq!(
            classify_reference_node(find_node(root, source, "identifier", "OTHER")),
            UsageReferenceKind::Other
        );
    }

    fn per_file_with_edge(path: &str, caller: &str, callee: &str, line: usize) -> PerFileEdges {
        let mut edges = PerFileEdges {
            path: path.to_string(),
            ..PerFileEdges::default()
        };
        edges
            .edge_lines
            .entry((caller.to_string(), callee.to_string()))
            .or_default()
            .insert(line, UsageReferenceKind::Other);
        edges
    }

    #[test]
    fn edge_weight_sums_distinct_file_line_sites_across_files() {
        // The same (caller, callee) edge from two files, both on line 5. Distinct
        // (file, line) sites = 2; unioning line sets would collapse to 1.
        let merged = merge_and_cap(vec![
            per_file_with_edge("a.rs", "caller", "callee", 5),
            per_file_with_edge("b.rs", "caller", "callee", 5),
        ]);
        let sites = merged
            .edges
            .get(&("caller".to_string(), "callee".to_string()))
            .expect("edge present");
        // Weight is the site count.
        assert_eq!(sites.len(), 2);
        // Sites carry their file path and 1-based line, sorted by (path, line).
        assert_eq!(
            sites,
            &vec![
                CallSite {
                    path: "a.rs".to_string(),
                    line: 5,
                },
                CallSite {
                    path: "b.rs".to_string(),
                    line: 5,
                },
            ],
        );
    }

    #[test]
    fn edge_weight_only_merge_sums_distinct_file_line_sites() {
        let merged = merge_weights_and_cap(vec![
            per_file_with_edge("a.rs", "caller", "callee", 5),
            per_file_with_edge("b.rs", "caller", "callee", 5),
        ]);

        assert_eq!(
            merged
                .edges
                .get(&("caller".to_string(), "callee".to_string())),
            Some(&UsageReferenceCounts {
                other: 2,
                ..UsageReferenceCounts::default()
            })
        );
        let weights: Vec<_> = merged
            .edges
            .into_iter()
            .map(|((caller, callee), weight)| (caller, callee, weight))
            .collect();
        assert_eq!(
            weights,
            vec![(
                "caller".to_string(),
                "callee".to_string(),
                UsageReferenceCounts {
                    other: 2,
                    ..UsageReferenceCounts::default()
                }
            )]
        );
    }

    #[test]
    fn strongest_kind_wins_when_one_edge_repeats_on_a_line() {
        let mut per_file = per_file_with_edge("a.rs", "caller", "callee", 5);
        per_file
            .edge_lines
            .get_mut(&("caller".to_string(), "callee".to_string()))
            .unwrap()
            .insert(5, UsageReferenceKind::Call);

        let merged = merge_weights_and_cap(vec![per_file]);
        assert_eq!(
            merged
                .edges
                .get(&("caller".to_string(), "callee".to_string())),
            Some(&UsageReferenceCounts {
                calls: 1,
                ..UsageReferenceCounts::default()
            })
        );
    }

    #[test]
    fn reference_counts_keep_the_legacy_edge_payload_size() {
        assert_eq!(std::mem::size_of::<UsageReferenceCounts>(), 8);
    }

    #[test]
    fn edge_weight_only_merge_matches_truncation_cap() {
        let mut per_file = PerFileEdges {
            path: "a.rs".to_string(),
            ..PerFileEdges::default()
        };
        for index in 0..=MAX_CALLSITES {
            per_file
                .edge_lines
                .entry(("caller".to_string(), "callee".to_string()))
                .or_default()
                .insert(index + 1, UsageReferenceKind::Other);
            per_file
                .callsites
                .entry("callee".to_string())
                .or_default()
                .insert(index);
        }

        let site_merged = merge_and_cap(vec![per_file]);
        let mut weight_file = PerFileEdges {
            path: "a.rs".to_string(),
            ..PerFileEdges::default()
        };
        for index in 0..=MAX_CALLSITES {
            weight_file
                .edge_lines
                .entry(("caller".to_string(), "callee".to_string()))
                .or_default()
                .insert(index + 1, UsageReferenceKind::Other);
            weight_file
                .callsites
                .entry("callee".to_string())
                .or_default()
                .insert(index);
        }
        let weight_merged = merge_weights_and_cap(vec![weight_file]);

        assert!(site_merged.edges.is_empty());
        assert!(weight_merged.edges.is_empty());
        assert_eq!(site_merged.truncated, weight_merged.truncated);
        assert_eq!(
            weight_merged.truncated.get("callee"),
            Some(&(MAX_CALLSITES + 1))
        );
    }

    // Regression guard for the #190 off-by-one: the file-aware (`UsageNodeKey`)
    // engine instantiation must record 1-based lines, exactly like the String one.
    // The bug was a `record()` that omitted the `+ 1` for the scoped path; after
    // unifying to one `record()` there is a single code path, and this pins it.
    #[test]
    fn record_emits_one_based_line_for_file_scoped_key() {
        use crate::analyzer::ProjectFile;

        // The scan input carries a parsed tree the language would walk; this pin
        // exercises only the offset arithmetic, so any tree will do.
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse("const a = 1;\n", None).unwrap();

        // `temp_dir()` is absolute on every platform (a bare "/repo" is not
        // absolute on Windows, which `ProjectFile::new` asserts).
        let file = ProjectFile::new(std::env::temp_dir(), "src/a.ts");
        let caller = UsageNodeKey::new(file.clone(), "caller".to_string());
        let callee = UsageNodeKey::new(file.clone(), "callee".to_string());

        // Line starts for a 3-line file; the reference sits on line 3 (offset 20),
        // well past line 1 so an off-by-one cannot pass by reading `0 + 1 == 1`.
        // Lines begin at byte offsets [0, 10, 18]; `find_line_index_for_offset(20)`
        // returns index 2, so the recorded line must be 3.
        let line_starts = [0usize, 10, 18];
        let offset = 20usize;
        let expected_line = find_line_index_for_offset(&line_starts, offset) + 1;
        assert_eq!(expected_line, 3, "fixture sanity: reference is on line 3");

        // The caller declaration spans the whole file; the callee is declared
        // elsewhere (a different file) so the reference is a real edge, not a
        // self/definition-overlap exclusion.
        let mut nodes: HashSet<UsageNodeKey> = HashSet::default();
        nodes.insert(caller.clone());
        nodes.insert(callee.clone());
        let declarations: FileDeclarations<UsageNodeKey> = FileDeclarations {
            enclosers: vec![(0, 100, caller.clone())],
            definitions: HashMap::default(),
        };

        let input = FileEdgeScanInput::new(&tree, "", &line_starts, &nodes, &declarations);
        let mut per_file: PerFileEdges<UsageNodeKey> = PerFileEdges::default();
        per_file.record_kind(
            &input,
            callee.clone(),
            UsageReferenceKind::Other,
            offset,
            offset + 2,
        );

        let lines = per_file
            .edge_lines
            .get(&(caller, callee))
            .expect("edge recorded");
        assert_eq!(
            lines.keys().copied().collect::<Vec<_>>(),
            vec![3],
            "file-scoped record must emit a 1-based line (3), not 0-based (2)"
        );
    }
}
