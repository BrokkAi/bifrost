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
    CallSite, ClassRangeIndex, FileDeclarations, FileEdgeScanInput, JsTsScopedNodeStatus,
    JsTsScopedUsageEdges, NodeKey, PerFileEdges, UsageEdgeWeights, UsageEdges, UsageNodeKey,
    UsageReferenceCounts, first_precise,
};

use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::parsed_tree::{
    ParseSpec, ParsedTreeFile, parse_tree_sitter_file, parse_tree_sitter_source,
};
use crate::analyzer::{AnalyzerQueryScope, CodeUnit, IAnalyzer, ProjectFile, QueryScope, Range};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::Arc;

/// [`ClassRangeIndex`] over a persisted file state, for scans that already
/// hydrated one and would otherwise pay the declaration/range queries twice.
pub(crate) fn class_range_index_from_state(state: &FileState) -> ClassRangeIndex {
    class_range_index_from_declaration_ranges(&state.declarations, &state.ranges)
}

/// [`class_range_index_from_state`] over the two maps it actually reads, for a
/// scan whose per-file record is a language crate's decode of the state rather
/// than the state itself.
pub(crate) fn class_range_index_from_declaration_ranges(
    declarations: &HashSet<CodeUnit>,
    ranges: &HashMap<CodeUnit, Vec<Range>>,
) -> ClassRangeIndex {
    ClassRangeIndex::from_class_spans(declarations.iter().filter(|unit| unit.is_class()).flat_map(
        |unit| {
            ranges
                .get(unit)
                .into_iter()
                .flatten()
                .map(move |range| (unit.clone(), *range))
        },
    ))
}

/// A callee with more distinct call sites than this is reported as truncated and
/// contributes no edges. Tied to the per-symbol scan's guardrail
/// (`DEFAULT_MAX_USAGES`) so `usage_graph`'s truncation matches `scan_usages`.
pub(crate) const MAX_CALLSITES: usize = crate::analyzer::usages::DEFAULT_MAX_USAGES;

/// The endpoint-admission contract for one inverted edge build.
///
/// Weight consumers retain a closed graph domain. The public rooted graph uses
/// an open callee domain so it can start with only its caller frontier and
/// validate exact resolved targets after the scan. Inbound consumers invert
/// that shape: every indexed enclosing declaration may be a caller, while the
/// requested callee catalog remains closed.
pub(crate) enum EdgeNodeDomain<'a, K = String> {
    Closed(&'a HashSet<K>),
    Rooted(&'a HashSet<K>),
    Inbound(&'a HashSet<K>),
}

impl<K> Copy for EdgeNodeDomain<'_, K> {}

impl<K> Clone for EdgeNodeDomain<'_, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K> EdgeNodeDomain<'a, K> {
    pub(crate) fn callers(self) -> &'a HashSet<K> {
        match self {
            Self::Closed(nodes) | Self::Rooted(nodes) => nodes,
            Self::Inbound(_) => unreachable!("inbound domains do not enumerate callers"),
        }
    }
}

/// Selects how a whole-workspace per-file scan is finalized. Language builders
/// are generic over this trait so the AST walk is written once while callers can
/// request either site-bearing API edges or compact weights for graph algorithms.
pub(crate) trait UsageEdgeBuildOutput<K: NodeKey>: Sized {
    fn merge(per_file: Vec<PerFileEdges<K>>) -> Self;
}

/// The result of a whole-workspace edge build that also records whether every
/// selected file produced a per-file result.
///
/// The ordinary usage-graph callers retain their historical best-effort
/// behaviour and may consume the output from an omitted file. Dead-code bulk
/// proofs use this status to avoid retaining such a graph: a missing parse,
/// file state, or provider result is evidence that the graph is incomplete.
pub(crate) enum UsageEdgeBuildResult<Output> {
    Complete(Output),
    Uncacheable {
        output: Output,
        omitted_files: Vec<ProjectFile>,
    },
}

impl<Output> UsageEdgeBuildResult<Output> {
    pub(crate) fn mark_uncacheable(self) -> Self {
        match self {
            Self::Complete(output) => Self::Uncacheable {
                output,
                omitted_files: Vec::new(),
            },
            uncacheable @ Self::Uncacheable { .. } => uncacheable,
        }
    }
}

/// Cache shape used by dead-code bulk proofs. The owner is one language
/// analyzer instance, so the key only needs the canonical target FQNs; the
/// analyzer instance supplies the generation and language domain.
pub(crate) type UsageEdgesCache = Cache<Arc<[String]>, Arc<UsageEdges>>;

pub(crate) fn sorted_usage_edge_targets(targets: &HashSet<String>) -> Arc<[String]> {
    let mut targets = targets.iter().cloned().collect::<Vec<_>>();
    targets.sort_unstable();
    targets.into()
}

pub(crate) fn weight_usage_edges(key: &Arc<[String]>, edges: &Arc<UsageEdges>) -> u32 {
    let key_bytes = size_of::<Arc<[String]>>()
        + key
            .iter()
            .map(|target| size_of::<String>() + target.len())
            .sum::<usize>();
    let edge_bytes = edges
        .edges
        .iter()
        .map(|((caller, callee), sites)| {
            caller.len()
                + callee.len()
                + sites
                    .iter()
                    .map(|site| size_of::<CallSite>() + site.path.len())
                    .sum::<usize>()
        })
        .sum::<usize>();
    let summary_bytes = edges
        .truncated
        .keys()
        .chain(edges.unproven_inbound.keys())
        .map(|name| size_of::<String>() + name.len() + size_of::<usize>())
        .sum::<usize>();
    (key_bytes + edge_bytes + summary_bytes).clamp(1, u32::MAX as usize) as u32
}

/// Cache a dead-code bulk graph only when its builder explicitly reports that
/// every selected input was processed. A best-effort graph from an omitted
/// input remains available to the current report, but is never published into
/// the generation-local cache.
pub(crate) fn cached_dead_code_usage_edges(
    analyzer: &dyn IAnalyzer,
    cache: &UsageEdgesCache,
    targets: &HashSet<String>,
    build: impl FnOnce(
        brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    ) -> Option<UsageEdgeBuildResult<UsageEdges>>,
) -> Option<Arc<UsageEdges>> {
    let cancellation = analyzer.active_query_cancellation();
    if cancellation
        .as_ref()
        .is_some_and(crate::CancellationToken::is_cancelled)
    {
        return None;
    }
    let scope = match cancellation.as_ref() {
        Some(cancellation) => AnalyzerQueryScope::with_cancellation(analyzer, cancellation),
        None => AnalyzerQueryScope::new(analyzer),
    };
    let result = cache_complete_usage_edges(cache, targets, || {
        let result = build(scope.token())?;
        if cancellation
            .as_ref()
            .is_some_and(crate::CancellationToken::is_cancelled)
            || scope.store_error().is_some()
        {
            Some(result.mark_uncacheable())
        } else {
            Some(result)
        }
    });
    if cancellation
        .as_ref()
        .is_some_and(crate::CancellationToken::is_cancelled)
    {
        None
    } else {
        result
    }
}

fn cache_complete_usage_edges(
    cache: &UsageEdgesCache,
    targets: &HashSet<String>,
    build: impl FnOnce() -> Option<UsageEdgeBuildResult<UsageEdges>>,
) -> Option<Arc<UsageEdges>> {
    let key = sorted_usage_edge_targets(targets);
    if let Some(cached) = cache.get(&key) {
        return Some(cached);
    }
    match build()? {
        UsageEdgeBuildResult::Complete(edges) => {
            let edges = Arc::new(edges);
            cache.insert(key, Arc::clone(&edges));
            Some(edges)
        }
        UsageEdgeBuildResult::Uncacheable {
            output,
            omitted_files,
        } => {
            debug_assert!(omitted_files.windows(2).all(|files| files[0] < files[1]));
            Some(Arc::new(output))
        }
    }
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
    build_file_declarations_with_file_scope(analyzer, file, false)
}

pub(crate) fn build_file_declarations_with_file_scope<K: NodeKey>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    include_file_scope: bool,
) -> FileDeclarations<K> {
    let mut enclosers = Vec::new();
    let mut definitions: HashMap<K, Vec<(usize, usize)>> = HashMap::default();
    for unit in analyzer
        .declarations(file)
        .into_iter()
        .filter(|unit| include_file_scope || !unit.is_file_scope())
    {
        let key = K::from_unit(&unit);
        for unit_range in analyzer.ranges(&unit) {
            let span = (unit_range.start_byte, unit_range.end_byte);
            enclosers.push((span.0, span.1, key.clone()));
            definitions.entry(key.clone()).or_default().push(span);
        }
    }
    if include_file_scope {
        let file_scope = CodeUnit::file_scope(file.clone());
        for unit_range in analyzer.ranges(&file_scope) {
            let span = (unit_range.start_byte, unit_range.end_byte);
            enclosers.push((span.0, span.1, K::from_unit(&file_scope)));
            definitions
                .entry(K::from_unit(&file_scope))
                .or_default()
                .push(span);
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
    build_file_declarations_from_state_with_file_scope(state, false)
}

pub(crate) fn build_file_declarations_from_state_with_file_scope<K: NodeKey>(
    state: &FileState,
    include_file_scope: bool,
) -> FileDeclarations<K> {
    build_file_declarations_from_declaration_ranges_with_file_scope(
        &state.declarations,
        &state.ranges,
        include_file_scope,
    )
}

/// [`build_file_declarations_from_state`] over the two maps it actually reads,
/// with a declaration filter; see [`class_range_index_from_declaration_ranges`].
pub(crate) fn build_file_declarations_from_declaration_ranges_filtered<K: NodeKey>(
    declarations: &HashSet<CodeUnit>,
    ranges: &HashMap<CodeUnit, Vec<Range>>,
    include: impl Fn(&CodeUnit) -> bool,
) -> FileDeclarations<K> {
    build_file_declarations_from_declaration_ranges_with_filter(
        declarations,
        ranges,
        false,
        include,
    )
}

pub(crate) fn build_file_declarations_from_declaration_ranges_with_file_scope<K: NodeKey>(
    declarations: &HashSet<CodeUnit>,
    ranges: &HashMap<CodeUnit, Vec<Range>>,
    include_file_scope: bool,
) -> FileDeclarations<K> {
    build_file_declarations_from_declaration_ranges_with_filter(
        declarations,
        ranges,
        include_file_scope,
        |_| true,
    )
}

fn build_file_declarations_from_declaration_ranges_with_filter<K: NodeKey>(
    declarations: &HashSet<CodeUnit>,
    ranges: &HashMap<CodeUnit, Vec<Range>>,
    include_file_scope: bool,
    include: impl Fn(&CodeUnit) -> bool,
) -> FileDeclarations<K> {
    let mut enclosers = Vec::new();
    let mut definitions: HashMap<K, Vec<(usize, usize)>> = HashMap::default();
    for unit in declarations
        .iter()
        .filter(|unit| include_file_scope || !unit.is_file_scope())
        .filter(|unit| include(unit))
    {
        let key = K::from_unit(unit);
        for unit_range in ranges.get(unit).into_iter().flatten() {
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

/// Drive a whole-workspace edge build while retaining the identities of files
/// whose scan could not produce a per-file result.
///
/// This is deliberately an opt-in sibling of [`build_edge_output`]. Existing
/// usage paths continue to receive their best-effort graph, while callers that
/// publish a graph beyond the current request can fail closed on omitted input.
pub(crate) fn build_edge_output_with_completeness<K, Output, KeepFn, ScanFn>(
    files: &[ProjectFile],
    keep_file: KeepFn,
    scan: ScanFn,
) -> UsageEdgeBuildResult<Output>
where
    K: NodeKey + Send,
    Output: UsageEdgeBuildOutput<K>,
    KeepFn: Fn(&ProjectFile) -> bool + Sync,
    ScanFn: Fn(&ProjectFile) -> Option<PerFileEdges<K>> + Sync,
{
    let (per_file, omitted_files) = files
        .par_iter()
        .filter(|file| keep_file(file))
        .map(|file| scan(file).map_or_else(|| Err(file.clone()), Ok))
        .partition::<Vec<_>, Vec<_>, _>(Result::is_ok);
    let mut omitted_files = omitted_files
        .into_iter()
        .map(|result| match result {
            Ok(_) => unreachable!("partitioned successful file result into omissions"),
            Err(file) => file,
        })
        .collect::<Vec<_>>();
    omitted_files.sort_unstable();
    omitted_files.dedup();
    let per_file = per_file.into_iter().map(Result::unwrap).collect::<Vec<_>>();
    let output = Output::merge(per_file);
    if omitted_files.is_empty() {
        UsageEdgeBuildResult::Complete(output)
    } else {
        UsageEdgeBuildResult::Uncacheable {
            output,
            omitted_files,
        }
    }
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
    collect_file_edges_with_domain(
        file,
        EdgeNodeDomain::Closed(nodes),
        parsed,
        declarations,
        scan,
    )
}

pub(crate) fn collect_file_edges_with_domain<K, S>(
    file: &ProjectFile,
    domain: EdgeNodeDomain<'_, K>,
    parsed: &ParsedTreeFile,
    declarations: FileDeclarations<K>,
    scan: S,
) -> PerFileEdges<K>
where
    K: NodeKey,
    S: FnOnce(&FileEdgeScanInput<'_, K>) -> PerFileEdges<K>,
{
    let input = match domain {
        EdgeNodeDomain::Closed(nodes) => FileEdgeScanInput::new(
            &parsed.tree,
            parsed.source.as_str(),
            &parsed.line_starts,
            nodes,
            &declarations,
        ),
        EdgeNodeDomain::Rooted(callers) => FileEdgeScanInput::new_rooted(
            &parsed.tree,
            parsed.source.as_str(),
            &parsed.line_starts,
            callers,
            &declarations,
        ),
        EdgeNodeDomain::Inbound(callees) => FileEdgeScanInput::new_inbound(
            &parsed.tree,
            parsed.source.as_str(),
            &parsed.line_starts,
            callees,
            &declarations,
        ),
    };
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
pub(crate) fn parse_and_collect_with_domain<S>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    domain: EdgeNodeDomain<'_>,
    spec: ParseSpec<'_>,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&FileEdgeScanInput<'_>) -> PerFileEdges,
{
    let parsed = parse_tree_sitter_file(file, spec)?;
    let declarations = build_file_declarations(analyzer, file);
    Some(collect_file_edges_with_domain(
        file,
        domain,
        &parsed,
        declarations,
        scan,
    ))
}

pub(crate) fn parse_and_collect_with_declarations_and_domain<S>(
    file: &ProjectFile,
    domain: EdgeNodeDomain<'_>,
    spec: ParseSpec<'_>,
    declarations: FileDeclarations,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&FileEdgeScanInput<'_>) -> PerFileEdges,
{
    let parsed = parse_tree_sitter_file(file, spec)?;
    Some(collect_file_edges_with_domain(
        file,
        domain,
        &parsed,
        declarations,
        scan,
    ))
}

pub(crate) fn parse_source_and_collect_with_declarations_and_domain<S>(
    source: String,
    file: &ProjectFile,
    domain: EdgeNodeDomain<'_>,
    spec: ParseSpec<'_>,
    declarations: FileDeclarations,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&FileEdgeScanInput<'_>) -> PerFileEdges,
{
    let parsed = parse_tree_sitter_source(source, spec)?;
    Some(collect_file_edges_with_domain(
        file,
        domain,
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
            sites.extend(lines.into_iter().map(|(line, mut evidence)| {
                evidence.spans.sort_unstable();
                CallSite {
                    path: file.path.clone(),
                    line,
                    spans: evidence.spans,
                    exact_targets: evidence.exact_targets,
                }
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
            for evidence in lines.into_values() {
                counts.record(evidence.kind);
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
    use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageReferenceKind;
    use brokk_bifrost_core::analyzer::usages::inverted_edges::classify_reference_node;
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
            .insert(
                line,
                brokk_bifrost_core::analyzer::usages::inverted_edges::UsageLineEvidence {
                    kind: UsageReferenceKind::Other,
                    spans: vec![(line, line + 1)],
                    exact_targets: Vec::new(),
                },
            );
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
                    spans: vec![(5, 6)],
                    exact_targets: Vec::new(),
                },
                CallSite {
                    path: "b.rs".to_string(),
                    line: 5,
                    spans: vec![(5, 6)],
                    exact_targets: Vec::new(),
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
            .insert(
                5,
                brokk_bifrost_core::analyzer::usages::inverted_edges::UsageLineEvidence {
                    kind: UsageReferenceKind::Call,
                    spans: vec![(5, 6)],
                    exact_targets: Vec::new(),
                },
            );

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
                .insert(
                    index + 1,
                    brokk_bifrost_core::analyzer::usages::inverted_edges::UsageLineEvidence {
                        kind: UsageReferenceKind::Other,
                        spans: vec![(index, index + 1)],
                        exact_targets: Vec::new(),
                    },
                );
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
                .insert(
                    index + 1,
                    brokk_bifrost_core::analyzer::usages::inverted_edges::UsageLineEvidence {
                        kind: UsageReferenceKind::Other,
                        spans: vec![(index, index + 1)],
                        exact_targets: Vec::new(),
                    },
                );
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

    #[test]
    fn inbound_domain_bounds_callees_but_keeps_all_indexed_callers() {
        let source = "function caller() { target(); unknown(); }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let caller = "app.caller".to_string();
        let callee = "app.target".to_string();
        let other = "app.other".to_string();
        let callees = HashSet::from_iter([callee.clone()]);
        let declarations = FileDeclarations {
            enclosers: vec![(0, source.len(), caller.clone())],
            definitions: HashMap::default(),
        };
        let input = FileEdgeScanInput::new_inbound(&tree, source, &[0], &callees, &declarations);
        assert!(input.may_match_terminal("target"));
        assert!(!input.may_match_terminal("unknown"));

        let callers = HashSet::from_iter([caller.clone()]);
        let rooted = FileEdgeScanInput::new_rooted(&tree, source, &[0], &callers, &declarations);
        assert!(rooted.may_match_terminal("unknown"));
        let mut file = PerFileEdges::default();

        file.record_kind(&input, callee.clone(), UsageReferenceKind::Call, 22, 28);
        file.record_kind(&input, other.clone(), UsageReferenceKind::Call, 30, 37);
        file.record_unproven(&input, callee.clone(), 22, 28);
        file.record_unproven(&input, other, 30, 37);

        assert!(file.edge_lines.contains_key(&(caller, callee.clone())));
        assert!(
            !file
                .edge_lines
                .keys()
                .any(|(_, recorded_callee)| recorded_callee == "app.other")
        );
        assert_eq!(file.unproven_inbound[&callee].len(), 1);
        assert!(!file.unproven_inbound.contains_key("app.other"));
    }

    fn usage_edges_cache() -> UsageEdgesCache {
        Cache::builder()
            .max_capacity(1024 * 1024)
            .weigher(weight_usage_edges)
            .build()
    }

    fn cached_edges_fixture() -> UsageEdges {
        UsageEdges {
            edges: BTreeMap::from([(
                ("caller".to_string(), "target".to_string()),
                vec![CallSite {
                    path: "src/caller.rs".to_string(),
                    line: 7,
                    spans: vec![(41, 47)],
                    exact_targets: Vec::new(),
                }],
            )]),
            truncated: BTreeMap::from([("busy".to_string(), 12)]),
            unproven_inbound: BTreeMap::from([("uncertain".to_string(), 2)]),
        }
    }

    #[test]
    fn dead_code_cache_keys_are_order_insensitive_and_preserve_evidence_on_hit() {
        let cache = usage_edges_cache();
        let first_targets = HashSet::from_iter(["z.target".to_string(), "a.target".to_string()]);
        let second_targets = HashSet::from_iter(["a.target".to_string(), "z.target".to_string()]);
        let builds = std::sync::atomic::AtomicUsize::new(0);

        let first = cache_complete_usage_edges(&cache, &first_targets, || {
            builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(UsageEdgeBuildResult::Complete(cached_edges_fixture()))
        })
        .expect("complete graph should be returned");
        let second = cache_complete_usage_edges(&cache, &second_targets, || {
            builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(UsageEdgeBuildResult::Complete(UsageEdges::default()))
        })
        .expect("canonical key should hit");

        assert_eq!(builds.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert_eq!(second.edges, first.edges);
        assert_eq!(second.truncated, BTreeMap::from([("busy".to_string(), 12)]));
        assert_eq!(
            second.unproven_inbound,
            BTreeMap::from([("uncertain".to_string(), 2)])
        );
    }

    #[test]
    fn incomplete_file_results_are_observable_and_never_published() {
        let root = std::env::temp_dir();
        let missing = ProjectFile::new(root.clone(), "missing.rs");
        let present = ProjectFile::new(root, "present.rs");
        let files = vec![missing.clone(), present.clone(), missing.clone()];
        let result = build_edge_output_with_completeness::<String, UsageEdges, _, _>(
            &files,
            |_| true,
            |file| {
                (file == &present).then(|| per_file_with_edge("present.rs", "caller", "target", 3))
            },
        );

        let UsageEdgeBuildResult::Uncacheable {
            output,
            omitted_files,
        } = result
        else {
            panic!("an omitted file must make the result uncacheable");
        };
        assert_eq!(omitted_files, vec![missing]);
        assert_eq!(output.edges.len(), 1);

        let cache = usage_edges_cache();
        let targets = HashSet::from_iter(["target".to_string()]);
        let builds = std::sync::atomic::AtomicUsize::new(0);
        let first = cache_complete_usage_edges(&cache, &targets, || {
            builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(UsageEdgeBuildResult::Uncacheable {
                output: cached_edges_fixture(),
                omitted_files: vec![ProjectFile::new(std::env::temp_dir(), "unreadable.rs")],
            })
        })
        .expect("current incomplete request still receives its graph");
        let second = cache_complete_usage_edges(&cache, &targets, || {
            builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(UsageEdgeBuildResult::Complete(cached_edges_fixture()))
        })
        .expect("a later complete request should rebuild");

        assert_eq!(builds.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert!(!std::sync::Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn none_results_are_not_published_and_ordinary_output_is_unchanged() {
        let cache = usage_edges_cache();
        let targets = HashSet::from_iter(["target".to_string()]);
        let builds = std::sync::atomic::AtomicUsize::new(0);
        assert!(
            cache_complete_usage_edges(&cache, &targets, || {
                builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                None
            })
            .is_none()
        );
        assert!(
            cache_complete_usage_edges(&cache, &targets, || {
                builds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(UsageEdgeBuildResult::Complete(cached_edges_fixture()))
            })
            .is_some()
        );
        assert_eq!(builds.load(std::sync::atomic::Ordering::Relaxed), 2);

        let files = vec![
            ProjectFile::new(std::env::temp_dir(), "one.rs"),
            ProjectFile::new(std::env::temp_dir(), "two.rs"),
        ];
        let ordinary: UsageEdges = build_edge_output(
            &files,
            |_| true,
            |file| {
                Some(per_file_with_edge(
                    &file.rel_path().to_string_lossy(),
                    "caller",
                    "target",
                    3,
                ))
            },
        );
        let checked: UsageEdgeBuildResult<UsageEdges> = build_edge_output_with_completeness(
            &files,
            |_| true,
            |file| {
                Some(per_file_with_edge(
                    &file.rel_path().to_string_lossy(),
                    "caller",
                    "target",
                    3,
                ))
            },
        );
        let UsageEdgeBuildResult::Complete(checked) = checked else {
            panic!("all successful files should be complete");
        };
        assert_eq!(ordinary.edges, checked.edges);
        assert_eq!(ordinary.truncated, checked.truncated);
        assert_eq!(ordinary.unproven_inbound, checked.unproven_inbound);
    }
}
