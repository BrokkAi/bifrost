//! The products of the inverted whole-workspace edge build.
//!
//! `usage_graph` builds a caller->callee graph in a single pass over files. The
//! pass itself -- the parallel fan-out, the per-file declaration index, the
//! `EdgeCollector` accounting rules, the merge/cap -- needs an `IAnalyzer` and a
//! parsed-file cache, so it lives in `brokk-bifrost-analysis`. What it *produces*
//! lives here, because a language pass has to be able to name its own output
//! without depending on the analyzer crate.
//!
//! The engine is generic over its node-key type `K` (see [`NodeKey`]). Most
//! languages are package-scoped: a bare fqn is globally unique, so `K = String`
//! (the default). Module-scoped ecosystems (JS/TS), where the same bare export
//! name in two files is two distinct symbols, instantiate the same engine with
//! `K = UsageNodeKey` so endpoints carry the file. There is one implementation of
//! every accounting rule -- only the key type differs.

use crate::analyzer::{CodeUnit, ProjectFile};
use std::collections::BTreeMap;
use std::hash::Hash;
use tree_sitter::Node;

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
