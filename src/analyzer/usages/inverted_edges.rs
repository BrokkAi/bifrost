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
//! - [`EdgeCollector::record_kind`] — the per-reference rules: drop self-references and
//!   references inside the callee's own definition, require both endpoints to be
//!   nodes, count distinct call sites for the cap, and dedup edge weight by
//!   `(file, line, caller)`.
//! - [`merge_and_cap`] — sum per-file results and drop callees past the call-site
//!   cap into `truncated`.
//!
//! The engine is generic over its node-key type `K` (see [`NodeKey`]). Most
//! languages are package-scoped: a bare fqn is globally unique, so `K = String`
//! (the default). Module-scoped ecosystems (JS/TS), where the same bare export
//! name in two files is two distinct symbols, instantiate the same engine with
//! `K = UsageNodeKey` so endpoints carry the file. There is one implementation of
//! every accounting rule — only the key type differs.
//!
//! Each language provides only a `scan_file` that walks its AST and calls
//! [`EdgeCollector::record_kind`]; see the Go implementation in
//! [`super::go_graph`] for the reference shape.

use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::usages::parsed_tree::{
    ParsedTreeFile, parse_tree_sitter_file, parse_tree_sitter_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::find_line_index_for_offset;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::hash::Hash;
use tree_sitter::{Language as TreeSitterLanguage, Node};

/// Per-file index of class-like declaration spans, for attributing an
/// unqualified / `this` / `self` reference to its enclosing class. Sources the
/// analyzer's own fqns, so nested classes resolve to whatever fqn the analyzer
/// emits.
pub(crate) struct ClassRangeIndex {
    ranges: Vec<(usize, usize, CodeUnit, String)>,
}

impl ClassRangeIndex {
    pub(crate) fn build(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Self {
        let ranges = analyzer
            .declarations(file)
            .into_iter()
            .filter(|unit| unit.is_class())
            .flat_map(|unit| {
                analyzer.ranges(&unit).into_iter().map(move |range| {
                    (
                        range.start_byte,
                        range.end_byte,
                        unit.clone(),
                        unit.fq_name(),
                    )
                })
            })
            .collect();
        Self { ranges }
    }

    pub(crate) fn build_from_state(state: &FileState) -> Self {
        let ranges = state
            .declarations
            .iter()
            .filter(|unit| unit.is_class())
            .flat_map(|unit| {
                state
                    .ranges
                    .get(unit)
                    .into_iter()
                    .flatten()
                    .map(move |range| {
                        (
                            range.start_byte,
                            range.end_byte,
                            unit.clone(),
                            unit.fq_name(),
                        )
                    })
            })
            .collect();
        Self { ranges }
    }

    /// The fqn of the smallest class declaration containing `byte`.
    pub(crate) fn enclosing(&self, byte: usize) -> Option<&str> {
        self.ranges
            .iter()
            .filter(|(start, end, _, _)| *start <= byte && byte < *end)
            .min_by_key(|(start, end, _, _)| end - start)
            .map(|(_, _, _, fqn)| fqn.as_str())
    }

    /// The exact declaration identity of the smallest class containing `byte`.
    pub(crate) fn enclosing_unit(&self, byte: usize) -> Option<&CodeUnit> {
        self.ranges
            .iter()
            .filter(|(start, end, _, _)| *start <= byte && byte < *end)
            .min_by_key(|(start, end, _, _)| end - start)
            .map(|(_, _, unit, _)| unit)
    }

    /// Apply `resolve` to class/object declarations containing `byte`, choosing
    /// the successful result from the innermost owner. This preserves exact
    /// analyzer identities without allocating or reconstructing lexical parents
    /// from rendered fqns.
    pub(crate) fn find_in_enclosing_units<T>(
        &self,
        byte: usize,
        mut resolve: impl FnMut(&CodeUnit) -> Option<T>,
    ) -> Option<T> {
        self.ranges
            .iter()
            .filter(|(start, end, _, _)| *start <= byte && byte < *end)
            .filter_map(|(start, end, unit, _)| {
                resolve(unit).map(|resolved| (end - start, resolved))
            })
            .min_by_key(|(length, _)| *length)
            .map(|(_, resolved)| resolved)
    }
}

/// The single precise binding for `name`, if the engine resolved it to exactly
/// one (or a first-of) target. Shared by the per-language receiver typing.
pub(crate) fn first_precise<T: Clone + Eq + Hash>(
    bindings: &LocalInferenceEngine<T>,
    name: &str,
) -> Option<T> {
    bindings
        .resolve_symbol_ref(name)
        .and_then(SymbolResolution::as_precise)
        .and_then(|targets| targets.iter().next().cloned())
}

/// A callee with more distinct call sites than this is reported as truncated and
/// contributes no edges. Tied to the per-symbol scan's guardrail
/// (`DEFAULT_MAX_USAGES`) so `usage_graph`'s truncation matches `scan_usages`.
pub(crate) const MAX_CALLSITES: usize = crate::analyzer::usages::DEFAULT_MAX_USAGES;

/// Broad semantic category of a proven usage reference. The categories stay
/// deliberately small so every supported grammar can classify sites without
/// inventing language-specific public vocabulary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UsageReferenceKind {
    #[default]
    Other,
    Type,
    Member,
    Call,
}

/// Distinct source-line counts for one caller/callee pair, split by reference kind.
/// Summing the fields reproduces the legacy unit-per-line edge weight.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UsageReferenceCounts {
    pub(crate) calls: u16,
    pub(crate) members: u16,
    pub(crate) types: u16,
    pub(crate) other: u16,
}

impl UsageReferenceCounts {
    pub(crate) fn total(self) -> usize {
        usize::from(self.calls)
            + usize::from(self.members)
            + usize::from(self.types)
            + usize::from(self.other)
    }

    fn record(&mut self, kind: UsageReferenceKind) {
        match kind {
            UsageReferenceKind::Call => self.calls = self.calls.saturating_add(1),
            UsageReferenceKind::Member => self.members = self.members.saturating_add(1),
            UsageReferenceKind::Type => self.types = self.types.saturating_add(1),
            UsageReferenceKind::Other => self.other = self.other.saturating_add(1),
        }
    }
}

/// Classify a resolved reference from tree-sitter structure. Language scanners
/// pass the precise identifier/member/type node they resolved; walking only its
/// named ancestors keeps this independent of source spelling while covering the
/// common grammar shapes used by Bifrost's supported languages.
pub(crate) fn classify_reference_node(node: Node<'_>) -> UsageReferenceKind {
    if matches!(
        node.kind(),
        "type_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "template_type"
            | "predefined_type"
            | "nullable_type"
            | "array_type"
            | "pointer_type"
            | "reference_type"
            | "union_type"
            | "intersection_type"
            | "type_projection"
            | "stable_type_identifier"
    ) {
        return UsageReferenceKind::Type;
    }

    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    let mut member = false;
    for _ in 0..4 {
        let Some(parent) = current.parent() else {
            break;
        };
        let kind = parent.kind();
        if matches!(
            kind,
            "type_annotation"
                | "generic_type"
                | "type_arguments"
                | "type_parameters"
                | "base_list"
                | "superclass"
                | "extends_type_clause"
                | "implements_clause"
                | "trait_bounds"
        ) || field_contains_site(
            parent,
            &["type", "return_type", "superclass"],
            site_start,
            site_end,
        ) {
            return UsageReferenceKind::Type;
        }
        if matches!(
            kind,
            "member_expression"
                | "field_expression"
                | "member_access_expression"
                | "selector_expression"
                | "navigation_expression"
                | "scope_resolution_expression"
                | "attribute"
                | "field_access"
                | "scoped_property_access_expression"
        ) && field_contains_site(
            parent,
            &["property", "field", "name", "attribute"],
            site_start,
            site_end,
        ) {
            member = true;
        }
        if matches!(
            kind,
            "call"
                | "call_expression"
                | "method_invocation"
                | "invocation_expression"
                | "function_call_expression"
                | "member_call_expression"
                | "scoped_call_expression"
                | "command"
        ) && field_contains_site(
            parent,
            &["function", "name", "method", "call"],
            site_start,
            site_end,
        ) {
            return UsageReferenceKind::Call;
        }
        if matches!(
            kind,
            "function_item"
                | "function_declaration"
                | "method_declaration"
                | "method_definition"
                | "class_declaration"
        ) {
            break;
        }
        current = parent;
    }

    if member {
        UsageReferenceKind::Member
    } else {
        UsageReferenceKind::Other
    }
}

fn field_contains_site(
    node: Node<'_>,
    fields: &[&str],
    site_start: usize,
    site_end: usize,
) -> bool {
    fields.iter().any(|field| {
        node.child_by_field_name(field)
            .is_some_and(|child| child.start_byte() <= site_start && site_end <= child.end_byte())
    })
}

impl std::ops::AddAssign for UsageReferenceCounts {
    fn add_assign(&mut self, rhs: Self) {
        self.calls = self.calls.saturating_add(rhs.calls);
        self.members = self.members.saturating_add(rhs.members);
        self.types = self.types.saturating_add(rhs.types);
        self.other = self.other.saturating_add(rhs.other);
    }
}

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

/// The identity of a usage-graph node, as seen by the edge engine. Implemented for
/// `String` (package-scoped languages: the fqn is globally unique) and
/// [`UsageNodeKey`] (module-scoped languages: the fqn plus its file). The engine is
/// generic over this trait so there is one implementation of every accounting rule.
pub(crate) trait NodeKey: Clone + Ord + Hash {
    /// The node key for a declaration.
    fn from_unit(unit: &CodeUnit) -> Self;
    /// The fqn component used for terminal-name matching.
    fn fqn(&self) -> &str;
}

impl NodeKey for String {
    fn from_unit(unit: &CodeUnit) -> Self {
        unit.fq_name()
    }

    fn fqn(&self) -> &str {
        self
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

impl NodeKey for UsageNodeKey {
    fn from_unit(unit: &CodeUnit) -> Self {
        UsageNodeKey::new(unit.source().clone(), unit.fq_name())
    }

    fn fqn(&self) -> &str {
        &self.fqn
    }
}

/// Aggregated result of an inverted edge build, keyed by node-key type `K`.
pub(crate) struct UsageEdges<K = String> {
    /// `(caller, callee) -> call sites`. The site count is the edge weight
    /// (distinct `(file, line, caller)` sites); sites are sorted by `(path, line)`.
    pub(crate) edges: BTreeMap<(K, K), Vec<CallSite>>,
    /// Callees past the call-site cap: `callee -> total call sites`.
    pub(crate) truncated: BTreeMap<K, usize>,
    /// Per-callee count of structurally matching call/member sites whose receiver
    /// could not be resolved to a proven edge.
    pub(crate) unproven_inbound: BTreeMap<K, usize>,
}

// Hand-written so the bound is `K: Ord` (BTreeMap), not `K: Default` that
// `#[derive(Default)]` would impose — `UsageNodeKey` has no `Default`.
impl<K: Ord> Default for UsageEdges<K> {
    fn default() -> Self {
        Self {
            edges: BTreeMap::new(),
            truncated: BTreeMap::new(),
            unproven_inbound: BTreeMap::new(),
        }
    }
}

impl<K: NodeKey> UsageEdges<K> {
    /// Iterate edges as `(caller, callee, weight)`, where weight is the call-site
    /// count. The single place edge weight is derived from the site list, so
    /// weight-only consumers (e.g. dead-code inbound counts) stay decoupled from
    /// how — or whether — per-site locations are stored.
    pub(crate) fn edge_weights(&self) -> impl Iterator<Item = (&K, &K, usize)> {
        self.edges
            .iter()
            .map(|((caller, callee), sites)| (caller, callee, sites.len()))
    }
}

/// Aggregated edge weights for callers that do not need per-site locations.
pub(crate) struct UsageEdgeWeights<K = String> {
    /// `(caller, callee) -> reference-kind counts`, with each distinct
    /// `(file, line, caller)` site assigned to exactly one kind.
    pub(crate) edges: BTreeMap<(K, K), UsageReferenceCounts>,
    /// Callees past the call-site cap: `callee -> total call sites`.
    pub(crate) truncated: BTreeMap<K, usize>,
    /// Per-callee count of structurally matching call/member sites whose receiver
    /// could not be resolved to a proven edge.
    pub(crate) unproven_inbound: BTreeMap<K, usize>,
}

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

impl<K: Ord> Default for UsageEdgeWeights<K> {
    fn default() -> Self {
        Self {
            edges: BTreeMap::new(),
            truncated: BTreeMap::new(),
            unproven_inbound: BTreeMap::new(),
        }
    }
}

/// One file's contribution, merged by [`merge_and_cap`].
pub(crate) struct PerFileEdges<K = String> {
    /// Workspace-relative path of the file these edges came from. Every reference is
    /// recorded in the file being scanned, so a single path covers all of this
    /// file's sites; [`merge_and_cap`] pairs it with each line to build `CallSite`s.
    path: String,
    /// `(caller, callee) -> distinct 1-based lines and their strongest observed
    /// kind`. A line remains one legacy site even if the scanner resolves the same
    /// declaration more than once on that line.
    edge_lines: BTreeMap<(K, K), HashMap<usize, UsageReferenceKind>>,
    /// `callee -> distinct call-site offsets` (for the cap).
    callsites: BTreeMap<K, HashSet<usize>>,
    /// `callee -> distinct unresolved structural member offsets`.
    unproven_inbound: BTreeMap<K, HashSet<usize>>,
}

impl<K: Ord> Default for PerFileEdges<K> {
    fn default() -> Self {
        Self {
            path: String::new(),
            edge_lines: BTreeMap::new(),
            callsites: BTreeMap::new(),
            unproven_inbound: BTreeMap::new(),
        }
    }
}

/// Per-file declaration index for one source file, built in a single pass over
/// the file's declarations.
pub(crate) struct FileDeclarations<K = String> {
    /// `(start_byte, end_byte, key)` for every declaration — attribute a reference
    /// to its smallest enclosing declaration (the caller).
    enclosers: Vec<(usize, usize, K)>,
    /// `key -> declaration byte spans in *this* file` — exclude a reference that
    /// falls inside the callee's own declaration. Keyed per file (not globally) so
    /// a callee declared in a *different* file can never spuriously match a
    /// caller-file reference whose byte offset happens to overlap.
    definitions: HashMap<K, Vec<(usize, usize)>>,
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

/// Accumulates one file's edges. A language's `scan_file` walks the AST and calls
/// [`record_kind`](Self::record_kind) for every reference it resolves to a callee key.
pub(crate) struct EdgeCollector<'a, K = String> {
    line_starts: &'a [usize],
    nodes: &'a HashSet<K>,
    nodes_by_terminal: HashMap<String, Vec<K>>,
    declarations: FileDeclarations<K>,
    out: PerFileEdges<K>,
}

impl<'a, K: NodeKey> EdgeCollector<'a, K> {
    pub(crate) fn new(
        line_starts: &'a [usize],
        nodes: &'a HashSet<K>,
        declarations: FileDeclarations<K>,
    ) -> Self {
        let mut nodes_by_terminal: HashMap<String, Vec<K>> = HashMap::default();
        for node in nodes {
            nodes_by_terminal
                .entry(node_terminal(node))
                .or_default()
                .push(node.clone());
        }
        Self {
            line_starts,
            nodes,
            nodes_by_terminal,
            declarations,
            out: PerFileEdges::default(),
        }
    }

    /// The key of the smallest declaration whose byte span contains `[start, end)`
    /// — the call site's enclosing caller. Mirrors `IAnalyzer::enclosing_code_unit`.
    fn enclosing(&self, start: usize, end: usize) -> Option<&K> {
        self.declarations
            .enclosers
            .iter()
            .filter(|(unit_start, unit_end, _)| *unit_start <= start && end <= *unit_end)
            .min_by_key(|(unit_start, unit_end, _)| unit_end - unit_start)
            .map(|(_, _, key)| key)
    }

    /// Record a reference at `[start, end)` that resolves to `callee`. Updates the
    /// per-callee call-site count (for the cap) and, when the site is a real edge,
    /// the `(caller, callee)` weight.
    pub(crate) fn record_kind(
        &mut self,
        callee: K,
        kind: UsageReferenceKind,
        start: usize,
        end: usize,
    ) {
        if !self.nodes.contains(&callee) {
            return;
        }
        let caller = match self.enclosing(start, end) {
            Some(caller) => caller.clone(),
            None => return,
        };
        self.record_with_caller_kind(caller, callee, kind, start, end);
    }

    pub(crate) fn record_with_caller_kind(
        &mut self,
        caller: K,
        callee: K,
        kind: UsageReferenceKind,
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
        let line_kinds = self.out.edge_lines.entry((caller, callee)).or_default();
        line_kinds
            .entry(line)
            .and_modify(|existing| *existing = (*existing).max(kind))
            .or_insert(kind);
    }

    pub(crate) fn contains_node(&self, node: &K) -> bool {
        self.nodes.contains(node)
    }

    /// Record that a structured call/member site with terminal member `name`
    /// matched requested nodes but could not be resolved to a proven callee.
    pub(crate) fn record_unproven_name(&mut self, name: &str, start: usize, end: usize) {
        let Some(candidates) = self.nodes_by_terminal.get(name) else {
            return;
        };
        let candidates = candidates.clone();
        for callee in candidates {
            self.record_unproven(callee, start, end);
        }
    }

    /// Record that a structured call/member site matched `callee` exactly but
    /// could not be resolved to a proven edge.
    pub(crate) fn record_unproven(&mut self, callee: K, start: usize, end: usize) {
        if !self.nodes.contains(&callee) {
            return;
        }
        let Some(caller) = self.enclosing(start, end).cloned() else {
            return;
        };
        if caller == callee {
            return;
        }
        if self
            .declarations
            .definitions
            .get(&callee)
            .is_some_and(|spans| spans.iter().any(|(s, e)| *s < end && start < *e))
        {
            return;
        }
        self.out
            .unproven_inbound
            .entry(callee)
            .or_default()
            .insert(start);
    }

    pub(crate) fn finish(self) -> PerFileEdges<K> {
        self.out
    }
}

fn node_terminal<K: NodeKey>(node: &K) -> String {
    let fqn = node.fqn();
    fqn.rsplit('.').next().unwrap_or(fqn).to_string()
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

/// Build one file's edges: construct its declaration index and an [`EdgeCollector`],
/// run the language `walk` against the collector, and return the owned result. The
/// collector's borrow of `line_starts` is scoped to this call, so the caller is free
/// to drop the parsed tree / source / line starts as soon as this returns.
pub(crate) fn collect_file_edges<K, W>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    nodes: &HashSet<K>,
    line_starts: &[usize],
    walk: W,
) -> PerFileEdges<K>
where
    K: NodeKey,
    W: FnOnce(&mut EdgeCollector<K>),
{
    let declarations = build_file_declarations(analyzer, file);
    let mut collector = EdgeCollector::new(line_starts, nodes, declarations);
    walk(&mut collector);
    let mut out = collector.finish();
    out.path = crate::path_utils::rel_path_string(file);
    out
}

pub(crate) fn collect_file_edges_with_declarations<K, W>(
    file: &ProjectFile,
    nodes: &HashSet<K>,
    line_starts: &[usize],
    declarations: FileDeclarations<K>,
    walk: W,
) -> PerFileEdges<K>
where
    K: NodeKey,
    W: FnOnce(&mut EdgeCollector<K>),
{
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

pub(crate) fn parse_and_collect_with_declarations<S>(
    file: &ProjectFile,
    nodes: &HashSet<String>,
    language: &TreeSitterLanguage,
    declarations: FileDeclarations,
    scan: S,
) -> Option<PerFileEdges>
where
    S: FnOnce(&ParsedTreeFile, &mut EdgeCollector),
{
    let parsed = parse_tree_sitter_file(file, language)?;
    Some(collect_file_edges_with_declarations(
        file,
        nodes,
        &parsed.line_starts,
        declarations,
        |collector| scan(&parsed, collector),
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
    S: FnOnce(&ParsedTreeFile, &mut EdgeCollector),
{
    let parsed = parse_tree_sitter_source(source, language)?;
    Some(collect_file_edges_with_declarations(
        file,
        nodes,
        &parsed.line_starts,
        declarations,
        |collector| scan(&parsed, collector),
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

        let mut collector = EdgeCollector::new(&line_starts, &nodes, declarations);
        collector.record_kind(
            callee.clone(),
            UsageReferenceKind::Other,
            offset,
            offset + 2,
        );
        let per_file = collector.finish();

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
