//! The products of the inverted whole-workspace edge build, and the per-file
//! contract a language scan implements to produce them.
//!
//! `usage_graph` builds a caller->callee graph in a single pass over files. The
//! driver -- the parallel fan-out, building the per-file declaration index from
//! an `IAnalyzer`, parsing on demand, and the final merge/cap -- needs an
//! analyzer handle and a parsed-file cache, so it lives in
//! `brokk-bifrost-analysis`. What it hands a language ([`FileEdgeScanInput`]),
//! what a language hands back ([`PerFileEdges`]), and the accounting rules that
//! turn one resolved reference into an edge live here, so a language pass is a
//! pure function over core types.
//!
//! The engine is generic over its node-key type `K` (see [`NodeKey`]). Most
//! languages are package-scoped: a bare fqn is globally unique, so `K = String`
//! (the default). Module-scoped ecosystems (JS/TS), where the same bare export
//! name in two files is two distinct symbols, instantiate the same engine with
//! `K = UsageNodeKey` so endpoints carry the file. There is one implementation of
//! every accounting rule -- only the key type differs.

use crate::analyzer::code_unit_index::CodeUnitIndex;
use crate::analyzer::model::Range;
use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::find_line_index_for_offset;
use std::collections::BTreeMap;
use std::hash::Hash;
use tree_sitter::{Node, Tree};

/// The single precise binding for `name`, if the engine resolved it to exactly
/// one (or a first-of) target. Shared by the per-language receiver typing.
pub fn first_precise<T: Clone + Eq + Hash>(
    bindings: &LocalInferenceEngine<T>,
    name: &str,
) -> Option<T> {
    bindings
        .resolve_symbol_ref(name)
        .and_then(SymbolResolution::as_precise)
        .and_then(|targets| targets.iter().next().cloned())
}

/// Per-file index of class-like declaration spans, for attributing an
/// unqualified / `this` / `self` reference to its enclosing class. Sources the
/// analyzer's own fqns, so nested classes resolve to whatever fqn the analyzer
/// emits.
#[derive(Clone)]
pub struct ClassRangeIndex {
    ranges: Vec<(usize, usize, CodeUnit, String)>,
}

impl ClassRangeIndex {
    /// The general constructor: every class-like declaration paired with each
    /// span it occupies. Callers that hold a declaration index use
    /// [`Self::build`]; callers that already have the declarations and ranges
    /// in hand (a persisted file state, say) pass them straight in.
    pub fn from_class_spans(spans: impl IntoIterator<Item = (CodeUnit, Range)>) -> Self {
        let ranges = spans
            .into_iter()
            .map(|(unit, range)| {
                let fqn = unit.fq_name();
                (range.start_byte, range.end_byte, unit, fqn)
            })
            .collect();
        Self { ranges }
    }

    pub fn build(index: &dyn CodeUnitIndex, file: &ProjectFile) -> Self {
        Self::from_class_spans(
            index
                .declarations(file)
                .into_iter()
                .filter(|unit| unit.is_class())
                .flat_map(|unit| {
                    index
                        .ranges(&unit)
                        .into_iter()
                        .map(move |range| (unit.clone(), range))
                }),
        )
    }

    /// The fqn of the smallest class declaration containing `byte`.
    pub fn enclosing(&self, byte: usize) -> Option<&str> {
        self.ranges
            .iter()
            .filter(|(start, end, _, _)| *start <= byte && byte < *end)
            .min_by_key(|(start, end, _, _)| end - start)
            .map(|(_, _, _, fqn)| fqn.as_str())
    }

    /// The exact declaration identity of the smallest class containing `byte`.
    pub fn enclosing_unit(&self, byte: usize) -> Option<&CodeUnit> {
        self.ranges
            .iter()
            .filter(|(start, end, _, _)| *start <= byte && byte < *end)
            .min_by_key(|(start, end, _, _)| end - start)
            .map(|(_, _, unit, _)| unit)
    }

    /// The indexed class-like declaration whose parser span is exactly
    /// `[start, end)`. Local templates have no entry and are resolved from
    /// their parser-recorded supertypes by the Scala usage scanners.
    pub fn unit_for_exact_span(&self, start: usize, end: usize) -> Option<&CodeUnit> {
        self.ranges
            .iter()
            .find(|(range_start, range_end, _, _)| *range_start == start && *range_end == end)
            .map(|(_, _, unit, _)| unit)
    }

    /// Apply `resolve` to class/object declarations containing `byte`, choosing
    /// the successful result from the innermost owner. This preserves exact
    /// analyzer identities without allocating or reconstructing lexical parents
    /// from rendered fqns.
    pub fn find_in_enclosing_units<T>(
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

/// Broad semantic category of a proven usage reference. The categories stay
/// deliberately small so every supported grammar can classify sites without
/// inventing language-specific public vocabulary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum UsageReferenceKind {
    #[default]
    Other,
    Type,
    Member,
    Call,
}

/// Distinct source-line counts for one caller/callee pair, split by reference kind.
/// Summing the fields reproduces the legacy unit-per-line edge weight.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsageReferenceCounts {
    pub calls: u16,
    pub members: u16,
    pub types: u16,
    pub other: u16,
}

impl UsageReferenceCounts {
    pub fn total(self) -> usize {
        usize::from(self.calls)
            + usize::from(self.members)
            + usize::from(self.types)
            + usize::from(self.other)
    }

    pub fn record(&mut self, kind: UsageReferenceKind) {
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
pub fn classify_reference_node(node: Node<'_>) -> UsageReferenceKind {
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
pub struct CallSite {
    pub path: String,
    pub line: usize,
}

/// The identity of a usage-graph node, as seen by the edge engine. Implemented for
/// `String` (package-scoped languages: the fqn is globally unique) and
/// [`UsageNodeKey`] (module-scoped languages: the fqn plus its file). The engine is
/// generic over this trait so there is one implementation of every accounting rule.
pub trait NodeKey: Clone + Ord + Hash {
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
pub struct UsageNodeKey {
    pub file: ProjectFile,
    pub fqn: String,
}

impl UsageNodeKey {
    pub fn new(file: ProjectFile, fqn: String) -> Self {
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
///
/// `BTreeMap` rather than `HashMap`, deliberately: the maps are consumed at
/// ordered boundaries -- the scan_usages tool renders edges directly into its
/// response, the workspace-graph builders fold them into further keyed
/// products, and diagnostics format the complete key set -- so map order is
/// output order. One ordered insert per edge at build time buys stable output
/// at every one of those boundaries without per-consumer sorts; no profile
/// has shown the build-side inserts on a hot path (#1732).
#[derive(Clone)]
pub struct UsageEdges<K = String> {
    /// `(caller, callee) -> call sites`. The site count is the edge weight
    /// (distinct `(file, line, caller)` sites); sites are sorted by `(path, line)`.
    pub edges: BTreeMap<(K, K), Vec<CallSite>>,
    /// Callees past the call-site cap: `callee -> total call sites`.
    pub truncated: BTreeMap<K, usize>,
    /// Per-callee count of structurally matching call/member sites whose receiver
    /// could not be resolved to a proven edge.
    pub unproven_inbound: BTreeMap<K, usize>,
}

// Hand-written so the bound is `K: Ord` (BTreeMap), not `K: Default` that
// `#[derive(Default)]` would impose -- `UsageNodeKey` has no `Default`.
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
    /// how -- or whether -- per-site locations are stored.
    pub fn edge_weights(&self) -> impl Iterator<Item = (&K, &K, usize)> {
        self.edges
            .iter()
            .map(|((caller, callee), sites)| (caller, callee, sites.len()))
    }
}

/// Aggregated edge weights for callers that do not need per-site locations.
///
/// `BTreeMap` for the same ordered-boundary reasons as [`UsageEdges`].
pub struct UsageEdgeWeights<K = String> {
    /// `(caller, callee) -> reference-kind counts`, with each distinct
    /// `(file, line, caller)` site assigned to exactly one kind.
    pub edges: BTreeMap<(K, K), UsageReferenceCounts>,
    /// Callees past the call-site cap: `callee -> total call sites`.
    pub truncated: BTreeMap<K, usize>,
    /// Per-callee count of structurally matching call/member sites whose receiver
    /// could not be resolved to a proven edge.
    pub unproven_inbound: BTreeMap<K, usize>,
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

/// Why a scoped node did or did not become a proof seed.
///
/// Lives beside [`UsageEdgeWeights`] for the reason this module is generic at
/// all: the module-scoped ecosystem (JS/TS) is the one that needs a per-node
/// verdict, and the framework's dead-code proof reads all three variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsTsScopedNodeStatus {
    Resolved,
    Ambiguous,
    Unseedable,
}

/// Module-scoped edge weights plus the per-node seeding verdict that produced
/// them.
///
/// `node_status` is a `BTreeMap` rather than a `HashMap`: the dead-code proof
/// walks it, and a deterministic order keeps a proof's reported candidates
/// stable across runs.
pub struct JsTsScopedUsageEdges {
    pub edges: UsageEdgeWeights<UsageNodeKey>,
    pub node_status: BTreeMap<UsageNodeKey, JsTsScopedNodeStatus>,
}

/// Per-file declaration index for one source file, built in a single pass over
/// the file's declarations. The driver builds it from an analyzer handle; a
/// language scan only reads it, through [`FileEdgeScanInput`].
pub struct FileDeclarations<K = String> {
    /// `(start_byte, end_byte, key)` for every declaration -- attribute a reference
    /// to its smallest enclosing declaration (the caller).
    pub enclosers: Vec<(usize, usize, K)>,
    /// `key -> declaration byte spans in *this* file` -- exclude a reference that
    /// falls inside the callee's own declaration. Keyed per file (not globally) so
    /// a callee declared in a *different* file can never spuriously match a
    /// caller-file reference whose byte offset happens to overlap.
    pub definitions: HashMap<K, Vec<(usize, usize)>>,
}

/// Everything one file's edge scan reads: the parsed tree and its source text,
/// the node domain the build is keyed on, and this file's declaration index.
///
/// The driver constructs one of these per file and hands it to the language
/// scan, which returns [`PerFileEdges`]. Nothing here borrows an analyzer, so a
/// language crate can implement the scan without depending on
/// `brokk-bifrost-analysis`.
pub struct FileEdgeScanInput<'a, K = String> {
    pub tree: &'a Tree,
    pub source: &'a str,
    pub line_starts: &'a [usize],
    /// The caller/callee domain: only keys in here become edge endpoints.
    pub nodes: &'a HashSet<K>,
    pub declarations: &'a FileDeclarations<K>,
    nodes_by_terminal: HashMap<String, Vec<K>>,
}

impl<'a, K: NodeKey> FileEdgeScanInput<'a, K> {
    pub fn new(
        tree: &'a Tree,
        source: &'a str,
        line_starts: &'a [usize],
        nodes: &'a HashSet<K>,
        declarations: &'a FileDeclarations<K>,
    ) -> Self {
        let mut nodes_by_terminal: HashMap<String, Vec<K>> = HashMap::default();
        for node in nodes {
            nodes_by_terminal
                .entry(node_terminal(node))
                .or_default()
                .push(node.clone());
        }
        Self {
            tree,
            source,
            line_starts,
            nodes,
            declarations,
            nodes_by_terminal,
        }
    }

    pub fn root(&self) -> Node<'a> {
        self.tree.root_node()
    }

    pub fn is_node(&self, key: &K) -> bool {
        self.nodes.contains(key)
    }

    /// The key of the smallest declaration whose byte span contains `[start, end)`
    /// -- the call site's enclosing caller. Mirrors `IAnalyzer::enclosing_code_unit`.
    fn enclosing(&self, start: usize, end: usize) -> Option<&K> {
        self.declarations
            .enclosers
            .iter()
            .filter(|(unit_start, unit_end, _)| *unit_start <= start && end <= *unit_end)
            .min_by_key(|(unit_start, unit_end, _)| unit_end - unit_start)
            .map(|(_, _, key)| key)
    }

    fn overlaps_definition(&self, callee: &K, start: usize, end: usize) -> bool {
        self.declarations
            .definitions
            .get(callee)
            .is_some_and(|spans| spans.iter().any(|(s, e)| *s < end && start < *e))
    }
}

fn node_terminal<K: NodeKey>(node: &K) -> String {
    let fqn = node.fqn();
    fqn.rsplit('.').next().unwrap_or(fqn).to_string()
}

/// One file's edge contributions -- what a language scan returns and the driver
/// merges. The `record_*` methods are the per-reference rules: drop
/// self-references and references inside the callee's own definition, require
/// both endpoints to be nodes, count distinct call sites for the cap, and dedup
/// edge weight by `(file, line, caller)`.
pub struct PerFileEdges<K = String> {
    /// Workspace-relative path of the file these edges came from. Every reference is
    /// recorded in the file being scanned, so a single path covers all of this
    /// file's sites; the driver's merge pairs it with each line to build `CallSite`s.
    /// The driver stamps it once the scan returns.
    pub path: String,
    /// `(caller, callee) -> distinct 1-based lines and their strongest observed
    /// kind`. A line remains one legacy site even if the scanner resolves the same
    /// declaration more than once on that line.
    pub edge_lines: BTreeMap<(K, K), HashMap<usize, UsageReferenceKind>>,
    /// `callee -> distinct call-site offsets` (for the cap).
    pub callsites: BTreeMap<K, HashSet<usize>>,
    /// `callee -> distinct unresolved structural member offsets`.
    pub unproven_inbound: BTreeMap<K, HashSet<usize>>,
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

impl<K: NodeKey> PerFileEdges<K> {
    /// Record a reference at `[start, end)` that resolves to `callee`. Updates the
    /// per-callee call-site count (for the cap) and, when the site is a real edge,
    /// the `(caller, callee)` weight.
    pub fn record_kind(
        &mut self,
        input: &FileEdgeScanInput<'_, K>,
        callee: K,
        kind: UsageReferenceKind,
        start: usize,
        end: usize,
    ) {
        if !input.nodes.contains(&callee) {
            return;
        }
        let caller = match input.enclosing(start, end) {
            Some(caller) => caller.clone(),
            None => return,
        };
        self.record_with_caller_kind(input, caller, callee, kind, start, end);
    }

    pub fn record_with_caller_kind(
        &mut self,
        input: &FileEdgeScanInput<'_, K>,
        caller: K,
        callee: K,
        kind: UsageReferenceKind,
        start: usize,
        end: usize,
    ) {
        if !input.nodes.contains(&callee) {
            return;
        }
        // A recursive call's enclosing definition is the callee itself; the
        // per-symbol path excludes it from the call-site count.
        if caller == callee {
            return;
        }
        self.callsites
            .entry(callee.clone())
            .or_default()
            .insert(start);

        // Edge-only exclusions (the cap count above ignores these): a reference
        // overlapping the callee's own declaration *in this file*, and a caller
        // that is not a node a consumer can rank.
        if input.overlaps_definition(&callee, start, end) {
            return;
        }
        if !input.nodes.contains(&caller) {
            return;
        }
        // 1-based, matching `scan_usages` hit lines and node `start_line`.
        let line = find_line_index_for_offset(input.line_starts, start) + 1;
        let line_kinds = self.edge_lines.entry((caller, callee)).or_default();
        line_kinds
            .entry(line)
            .and_modify(|existing| *existing = (*existing).max(kind))
            .or_insert(kind);
    }

    /// Record that a structured call/member site with terminal member `name`
    /// matched requested nodes but could not be resolved to a proven callee.
    pub fn record_unproven_name(
        &mut self,
        input: &FileEdgeScanInput<'_, K>,
        name: &str,
        start: usize,
        end: usize,
    ) {
        let Some(candidates) = input.nodes_by_terminal.get(name) else {
            return;
        };
        let candidates = candidates.clone();
        for callee in candidates {
            self.record_unproven(input, callee, start, end);
        }
    }

    /// Record that a structured call/member site matched `callee` exactly but
    /// could not be resolved to a proven edge.
    pub fn record_unproven(
        &mut self,
        input: &FileEdgeScanInput<'_, K>,
        callee: K,
        start: usize,
        end: usize,
    ) {
        if !input.nodes.contains(&callee) {
            return;
        }
        let Some(caller) = input.enclosing(start, end).cloned() else {
            return;
        };
        if caller == callee {
            return;
        }
        if input.overlaps_definition(&callee, start, end) {
            return;
        }
        self.unproven_inbound
            .entry(callee)
            .or_default()
            .insert(start);
    }
}
