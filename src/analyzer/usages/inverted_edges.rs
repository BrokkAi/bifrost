//! Language-agnostic machinery for the inverted whole-workspace edge build.
//!
//! `usage_graph` builds a caller→callee graph. The scalable shape is a single
//! pass over files: walk each file once, resolve every reference to the callee it
//! names, and attribute it to its enclosing declaration. Everything except the
//! per-language "walk + resolve a reference to a callee fqn" is identical across
//! languages, and lives here:
//!
//! - [`build_enclosers`] / [`EdgeCollector::enclosing`] — attribute a reference to
//!   its smallest enclosing declaration (the caller), matching
//!   `IAnalyzer::enclosing_code_unit` but precomputed once per file.
//! - [`EdgeCollector::record`] — the per-reference rules: drop self-references and
//!   references inside the callee's own definition, require both endpoints to be
//!   nodes, count distinct call sites for the cap, and dedup edge weight by
//!   `(file, line, caller)`.
//! - [`merge_and_cap`] — sum per-file results and drop callees past the call-site
//!   cap into `truncated`.
//!
//! Each language provides only a `scan_file` that walks its AST and calls
//! [`EdgeCollector::record`]; see the Go implementation in
//! [`super::go_graph`] for the reference shape.

use crate::analyzer::usages::local_inference::LocalInferenceEngine;
use crate::analyzer::usages::parsed_tree::{ParsedTreeFile, parse_tree_sitter_file};
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::find_line_index_for_offset;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::hash::Hash;
use tree_sitter::Language as TreeSitterLanguage;

/// Per-file index of class-like declaration spans, for attributing an
/// unqualified / `this` / `self` reference to its enclosing class. Sources the
/// analyzer's own fqns, so nested classes resolve to whatever fqn the analyzer
/// emits.
pub(crate) struct ClassRangeIndex {
    ranges: Vec<(usize, usize, String)>,
}

impl ClassRangeIndex {
    pub(crate) fn build(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Self {
        let ranges = analyzer
            .declarations(file)
            .filter(|unit| unit.is_class())
            .flat_map(|unit| {
                analyzer
                    .ranges(unit)
                    .iter()
                    .map(move |range| (range.start_byte, range.end_byte, unit.fq_name()))
            })
            .collect();
        Self { ranges }
    }

    /// The fqn of the smallest class declaration containing `byte`.
    pub(crate) fn enclosing(&self, byte: usize) -> Option<&str> {
        self.ranges
            .iter()
            .filter(|(start, end, _)| *start <= byte && byte < *end)
            .min_by_key(|(start, end, _)| end - start)
            .map(|(_, _, fqn)| fqn.as_str())
    }
}

/// The single precise binding for `name`, if the engine resolved it to exactly
/// one (or a first-of) target. Shared by the per-language receiver typing.
pub(crate) fn first_precise<T: Clone + Eq + Hash>(
    bindings: &LocalInferenceEngine<T>,
    name: &str,
) -> Option<T> {
    bindings
        .resolve_symbol(name)
        .as_precise()
        .and_then(|targets| targets.iter().next().cloned())
}

/// A callee with more distinct call sites than this is reported as truncated and
/// contributes no edges. Tied to the per-symbol scan's guardrail
/// (`DEFAULT_MAX_USAGES`) so `usage_graph`'s truncation matches `scan_usages`.
pub(crate) const MAX_CALLSITES: usize = crate::analyzer::usages::DEFAULT_MAX_USAGES;

/// A single resolved call site for an edge: a workspace-relative file path and the
/// 1-based line where a reference to the callee occurs. Lines are 1-based to match
/// `scan_usages` hit lines and node `start_line`. The set of call sites for an edge
/// is exactly its distinct `(file, line, caller)` reference sites, so an edge's
/// weight equals its call-site count.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CallSite {
    pub(crate) path: String,
    pub(crate) line: usize,
}

/// Aggregated result of an inverted edge build.
#[derive(Default)]
pub(crate) struct UsageEdges {
    /// `(caller fqn, callee fqn) -> call sites`. The site count is the edge weight
    /// (distinct `(file, line, caller)` sites); sites are sorted by `(path, line)`.
    pub(crate) edges: BTreeMap<(String, String), Vec<CallSite>>,
    /// Callees past the call-site cap: `fqn -> total call sites`.
    pub(crate) truncated: BTreeMap<String, usize>,
}

impl UsageEdges {
    /// Iterate edges as `(caller, callee, weight)`, where weight is the call-site
    /// count. The single place edge weight is derived from the site list, so
    /// weight-only consumers (e.g. dead-code inbound counts) stay decoupled from
    /// how — or whether — per-site locations are stored.
    pub(crate) fn edge_weights(&self) -> impl Iterator<Item = (&str, &str, usize)> {
        self.edges
            .iter()
            .map(|((caller, callee), sites)| (caller.as_str(), callee.as_str(), sites.len()))
    }
}

/// File-scoped declaration identity for languages where a bare fqn/export name is
/// not globally unique.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct UsageNodeKey {
    pub(crate) file: ProjectFile,
    pub(crate) fqn: String,
}

impl UsageNodeKey {
    pub(crate) fn new(file: ProjectFile, fqn: String) -> Self {
        Self { file, fqn }
    }
}

/// Aggregated result of an inverted edge build whose endpoints are file-scoped.
#[derive(Default)]
pub(crate) struct ScopedUsageEdges {
    /// `(caller key, callee key) -> weight` (distinct `(file, line, caller)` sites).
    pub(crate) edges: BTreeMap<(UsageNodeKey, UsageNodeKey), usize>,
    /// Callees past the call-site cap: `key -> total call sites`.
    pub(crate) truncated: BTreeMap<UsageNodeKey, usize>,
}

/// One file's contribution, merged by [`merge_and_cap`].
#[derive(Default)]
pub(crate) struct PerFileEdges {
    /// Workspace-relative path of the file these edges came from. Every reference is
    /// recorded in the file being scanned, so a single path covers all of this
    /// file's sites; [`merge_and_cap`] pairs it with each line to build `CallSite`s.
    path: String,
    /// `(caller, callee) -> distinct 1-based lines` (edge weight before the cap).
    edge_lines: BTreeMap<(String, String), HashSet<usize>>,
    /// `callee -> distinct call-site offsets` (for the cap).
    callsites: BTreeMap<String, HashSet<usize>>,
}

/// Per-file declaration index for one source file, built in a single pass over
/// the file's declarations.
pub(crate) struct FileDeclarations {
    /// `(start_byte, end_byte, fqn)` for every declaration — attribute a reference
    /// to its smallest enclosing declaration (the caller).
    enclosers: Vec<(usize, usize, String)>,
    /// `fqn -> declaration byte spans in *this* file` — exclude a reference that
    /// falls inside the callee's own declaration. Keyed per file (not globally) so
    /// a callee declared in a *different* file can never spuriously match a
    /// caller-file reference whose byte offset happens to overlap.
    definitions: HashMap<String, Vec<(usize, usize)>>,
}

pub(crate) fn build_file_declarations(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> FileDeclarations {
    let mut enclosers = Vec::new();
    let mut definitions: HashMap<String, Vec<(usize, usize)>> = HashMap::default();
    for unit in analyzer.declarations(file) {
        let fqn = unit.fq_name();
        for unit_range in analyzer.ranges(unit) {
            let span = (unit_range.start_byte, unit_range.end_byte);
            enclosers.push((span.0, span.1, fqn.clone()));
            definitions.entry(fqn.clone()).or_default().push(span);
        }
    }
    FileDeclarations {
        enclosers,
        definitions,
    }
}

/// Accumulates one file's edges. A language's `scan_file` walks the AST and calls
/// [`record`](Self::record) for every reference it resolves to a callee fqn.
pub(crate) struct EdgeCollector<'a> {
    line_starts: &'a [usize],
    nodes: &'a HashSet<String>,
    declarations: FileDeclarations,
    out: PerFileEdges,
}

impl<'a> EdgeCollector<'a> {
    pub(crate) fn new(
        line_starts: &'a [usize],
        nodes: &'a HashSet<String>,
        declarations: FileDeclarations,
    ) -> Self {
        Self {
            line_starts,
            nodes,
            declarations,
            out: PerFileEdges::default(),
        }
    }

    /// The fqn of the smallest declaration whose byte span contains `[start, end)`
    /// — the call site's enclosing caller. Mirrors `IAnalyzer::enclosing_code_unit`.
    fn enclosing(&self, start: usize, end: usize) -> Option<&str> {
        self.declarations
            .enclosers
            .iter()
            .filter(|(unit_start, unit_end, _)| *unit_start <= start && end <= *unit_end)
            .min_by_key(|(unit_start, unit_end, _)| unit_end - unit_start)
            .map(|(_, _, fqn)| fqn.as_str())
    }

    /// Record a reference at `[start, end)` that resolves to `callee`. Updates the
    /// per-callee call-site count (for the cap) and, when the site is a real edge,
    /// the `(caller, callee)` weight.
    pub(crate) fn record(&mut self, callee: String, start: usize, end: usize) {
        if !self.nodes.contains(&callee) {
            return;
        }
        let caller = match self.enclosing(start, end) {
            Some(caller) => caller.to_string(),
            None => return,
        };
        self.record_with_caller(caller, callee, start, end);
    }

    pub(crate) fn record_with_caller(
        &mut self,
        caller: String,
        callee: String,
        start: usize,
        end: usize,
    ) {
        if !self.nodes.contains(&callee) {
            return;
        }
        // A recursive call's enclosing definition is the callee itself; the
        // per-symbol path excludes it from the call-site count.
        if caller == callee {
            return;
        }
        self.out
            .callsites
            .entry(callee.clone())
            .or_default()
            .insert(start);

        // Edge-only exclusions (the cap count above ignores these): a reference
        // overlapping the callee's own declaration *in this file*, and a caller
        // that is not a node a consumer can rank.
        if self
            .declarations
            .definitions
            .get(&callee)
            .is_some_and(|spans| spans.iter().any(|(s, e)| *s < end && start < *e))
        {
            return;
        }
        if !self.nodes.contains(&caller) {
            return;
        }
        // 1-based, matching `scan_usages` hit lines and node `start_line`.
        let line = find_line_index_for_offset(self.line_starts, start) + 1;
        self.out
            .edge_lines
            .entry((caller, callee))
            .or_default()
            .insert(line);
    }

    pub(crate) fn finish(self) -> PerFileEdges {
        self.out
    }
}

#[derive(Default)]
pub(crate) struct ScopedPerFileEdges {
    edge_lines: BTreeMap<(UsageNodeKey, UsageNodeKey), HashSet<usize>>,
    callsites: BTreeMap<UsageNodeKey, HashSet<usize>>,
}

pub(crate) struct ScopedFileDeclarations {
    enclosers: Vec<(usize, usize, UsageNodeKey)>,
    definitions: HashMap<UsageNodeKey, Vec<(usize, usize)>>,
}

pub(crate) fn build_scoped_file_declarations(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> ScopedFileDeclarations {
    let mut enclosers = Vec::new();
    let mut definitions: HashMap<UsageNodeKey, Vec<(usize, usize)>> = HashMap::default();
    for unit in analyzer.declarations(file) {
        let key = UsageNodeKey::new(unit.source().clone(), unit.fq_name());
        for unit_range in analyzer.ranges(unit) {
            let span = (unit_range.start_byte, unit_range.end_byte);
            enclosers.push((span.0, span.1, key.clone()));
            definitions.entry(key.clone()).or_default().push(span);
        }
    }
    ScopedFileDeclarations {
        enclosers,
        definitions,
    }
}

pub(crate) struct ScopedEdgeCollector<'a> {
    line_starts: &'a [usize],
    nodes: &'a HashSet<UsageNodeKey>,
    declarations: ScopedFileDeclarations,
    out: ScopedPerFileEdges,
}

impl<'a> ScopedEdgeCollector<'a> {
    pub(crate) fn new(
        line_starts: &'a [usize],
        nodes: &'a HashSet<UsageNodeKey>,
        declarations: ScopedFileDeclarations,
    ) -> Self {
        Self {
            line_starts,
            nodes,
            declarations,
            out: ScopedPerFileEdges::default(),
        }
    }

    fn enclosing(&self, start: usize, end: usize) -> Option<&UsageNodeKey> {
        self.declarations
            .enclosers
            .iter()
            .filter(|(unit_start, unit_end, _)| *unit_start <= start && end <= *unit_end)
            .min_by_key(|(unit_start, unit_end, _)| unit_end - unit_start)
            .map(|(_, _, key)| key)
    }

    pub(crate) fn record(&mut self, callee: UsageNodeKey, start: usize, end: usize) {
        if !self.nodes.contains(&callee) {
            return;
        }
        let caller = match self.enclosing(start, end) {
            Some(caller) => caller.clone(),
            None => return,
        };
        if caller == callee {
            return;
        }
        self.out
            .callsites
            .entry(callee.clone())
            .or_default()
            .insert(start);

        if self
            .declarations
            .definitions
            .get(&callee)
            .is_some_and(|spans| spans.iter().any(|(s, e)| *s < end && start < *e))
        {
            return;
        }
        if !self.nodes.contains(&caller) {
            return;
        }
        let line = find_line_index_for_offset(self.line_starts, start);
        self.out
            .edge_lines
            .entry((caller, callee))
            .or_default()
            .insert(line);
    }

    pub(crate) fn finish(self) -> ScopedPerFileEdges {
        self.out
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
#[allow(clippy::redundant_closure)] // the closure borrows `scan`; see the note below
pub(crate) fn build_edges<KeepFn, ScanFn>(
    files: &[ProjectFile],
    keep_file: KeepFn,
    scan: ScanFn,
) -> UsageEdges
where
    KeepFn: Fn(&ProjectFile) -> bool + Sync,
    ScanFn: Fn(&ProjectFile) -> Option<PerFileEdges> + Sync,
{
    let per_file: Vec<PerFileEdges> = files
        .par_iter()
        .filter(|file| keep_file(file))
        // Borrow `scan` rather than move it: it's `Sync` but not necessarily `Send`,
        // and rayon shares one mapper across worker threads.
        .filter_map(|file| scan(file))
        .collect();
    merge_and_cap(per_file)
}

#[allow(clippy::redundant_closure)] // the closure borrows `scan` (Sync, not necessarily Send)
pub(crate) fn build_scoped_edges<KeepFn, ScanFn>(
    files: &[ProjectFile],
    keep_file: KeepFn,
    scan: ScanFn,
) -> ScopedUsageEdges
where
    KeepFn: Fn(&ProjectFile) -> bool + Sync,
    ScanFn: Fn(&ProjectFile) -> Option<ScopedPerFileEdges> + Sync,
{
    let per_file: Vec<ScopedPerFileEdges> = files
        .par_iter()
        .filter(|file| keep_file(file))
        .filter_map(|file| scan(file))
        .collect();
    merge_scoped_and_cap(per_file)
}

/// Scoped counterpart to [`collect_file_edges`]: build one file's declaration index and a
/// [`ScopedEdgeCollector`], run the language `walk`, and return the owned per-file edges.
/// The collector's borrows of `line_starts`/`nodes` are scoped to this call, so the caller
/// can drop the parsed tree as soon as it returns.
pub(crate) fn collect_scoped_file_edges<'a, W>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    nodes: &'a HashSet<UsageNodeKey>,
    line_starts: &'a [usize],
    walk: W,
) -> ScopedPerFileEdges
where
    W: FnOnce(&mut ScopedEdgeCollector<'a>),
{
    let declarations = build_scoped_file_declarations(analyzer, file);
    let mut collector = ScopedEdgeCollector::new(line_starts, nodes, declarations);
    walk(&mut collector);
    collector.finish()
}

/// Build one file's edges: construct its declaration index and an [`EdgeCollector`],
/// run the language `walk` against the collector, and return the owned result. The
/// collector's borrow of `line_starts` is scoped to this call, so the caller is free
/// to drop the parsed tree / source / line starts as soon as this returns.
pub(crate) fn collect_file_edges<W>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    nodes: &HashSet<String>,
    line_starts: &[usize],
    walk: W,
) -> PerFileEdges
where
    W: FnOnce(&mut EdgeCollector),
{
    let declarations = build_file_declarations(analyzer, file);
    let mut collector = EdgeCollector::new(line_starts, nodes, declarations);
    walk(&mut collector);
    let mut out = collector.finish();
    out.path = crate::path_utils::rel_path_string(file);
    out
}

/// Parse `file` on demand, build its edges via [`collect_file_edges`], and drop the
/// tree / source / line starts when this returns — bounding live trees to ≈ the rayon
/// worker count. Returns `None` to skip an unreadable or empty file. The `scan`
/// closure receives the parsed file and the collector and owns the language AST walk.
/// Centralizing the parse, the skip-on-failure, and the tree-lifetime scoping here
/// keeps the six local-parse adapters from each repeating them, and gives a single
/// home for any later parse-failure handling, tracing, or memory instrumentation.
/// See the Java builder for the shape.
pub(crate) fn parse_and_collect<S>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    nodes: &HashSet<String>,
    language: &TreeSitterLanguage,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&ParsedTreeFile, &mut EdgeCollector),
{
    let parsed = parse_tree_sitter_file(file, language)?;
    Some(collect_file_edges(
        analyzer,
        file,
        nodes,
        &parsed.line_starts,
        |collector| scan(&parsed, collector),
    ))
}

/// Sum per-file results and drop callees past [`MAX_CALLSITES`] into `truncated`.
pub(crate) fn merge_and_cap(per_file: Vec<PerFileEdges>) -> UsageEdges {
    // Each file's `edge_lines` already holds the distinct lines for that file, so
    // concatenating per-file `(path, line)` pairs yields distinct `(file, line)`
    // sites per edge. Unioning line numbers across files would instead collapse the
    // same line number appearing in two files (e.g. a partial class) and undercount.
    let mut edge_sites: BTreeMap<(String, String), Vec<CallSite>> = BTreeMap::new();
    let mut callsites: BTreeMap<String, usize> = BTreeMap::new();
    for file in per_file {
        for (key, lines) in file.edge_lines {
            let sites = edge_sites.entry(key).or_default();
            sites.extend(lines.into_iter().map(|line| CallSite {
                path: file.path.clone(),
                line,
            }));
        }
        for (callee, sites) in file.callsites {
            *callsites.entry(callee).or_insert(0) += sites.len();
        }
    }

    let truncated: BTreeMap<String, usize> = callsites
        .into_iter()
        .filter(|(_, total)| *total > MAX_CALLSITES)
        .collect();
    let edges: BTreeMap<(String, String), Vec<CallSite>> = edge_sites
        .into_iter()
        .filter(|((_, callee), _)| !truncated.contains_key(callee))
        .map(|(key, mut sites)| {
            // Deterministic output independent of file/line hash iteration order.
            sites.sort();
            (key, sites)
        })
        .collect();

    UsageEdges { edges, truncated }
}

pub(crate) fn merge_scoped_and_cap(per_file: Vec<ScopedPerFileEdges>) -> ScopedUsageEdges {
    let mut edge_weights: BTreeMap<(UsageNodeKey, UsageNodeKey), usize> = BTreeMap::new();
    let mut callsites: BTreeMap<UsageNodeKey, usize> = BTreeMap::new();
    for file in per_file {
        for (key, lines) in file.edge_lines {
            *edge_weights.entry(key).or_insert(0) += lines.len();
        }
        for (callee, sites) in file.callsites {
            *callsites.entry(callee).or_insert(0) += sites.len();
        }
    }

    let truncated: BTreeMap<UsageNodeKey, usize> = callsites
        .into_iter()
        .filter(|(_, total)| *total > MAX_CALLSITES)
        .collect();
    let edges: BTreeMap<(UsageNodeKey, UsageNodeKey), usize> = edge_weights
        .into_iter()
        .filter(|((_, callee), _)| !truncated.contains_key(callee))
        .collect();

    ScopedUsageEdges { edges, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn per_file_with_edge(path: &str, caller: &str, callee: &str, line: usize) -> PerFileEdges {
        let mut edges = PerFileEdges {
            path: path.to_string(),
            ..PerFileEdges::default()
        };
        edges
            .edge_lines
            .entry((caller.to_string(), callee.to_string()))
            .or_default()
            .insert(line);
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
}
