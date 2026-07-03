//! The per-language boundary of structural search.
//!
//! A [`StructuralSpec`] is everything a language contributes: a static table
//! mapping its tree-sitter node-type names onto [`NormalizedKind`]s, an
//! optional context-sensitive kind refinement (Python turns a `function`
//! directly inside a `class` into `method`), and role extraction that reads
//! tree-sitter AST *fields* — never source-text splitting — to attach
//! `callee`/`receiver`/`args`/... edges to facts. Everything else (walking,
//! matching, planning, tooling) is language-independent.

use super::facts::{RoleTarget, Span};
use super::kinds::{NormalizedKind, Role};
use crate::analyzer::Language;
use crate::hash::HashMap;
use tree_sitter::{Language as TsLanguage, Node};

pub trait StructuralSpec: Send + Sync + 'static {
    fn language(&self) -> Language;

    /// Grammar-specific node-type name → normalized kind. Compiled once per
    /// extraction into an id-indexed lookup via `Language::id_for_node_kind`;
    /// a per-language test must assert every entry resolves (id != 0) so
    /// grammar bumps that rename nodes fail loudly.
    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)];

    /// Context-sensitive refinement applied after table lookup. `enclosing`
    /// is the kind of the nearest enclosing normalized node.
    fn refine_kind(
        &self,
        _node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
    ) -> NormalizedKind {
        kind
    }

    /// Whether this normalized node should become a fact at all. Use this for
    /// grammar nodes whose normalized kind is conditional on fields, such as
    /// variable declarators that are assignments only when they have values.
    fn should_extract(&self, _node: Node<'_>, _kind: NormalizedKind) -> bool {
        true
    }

    /// Whether this adapter can model `role` precisely enough to evaluate a
    /// query that asks for it.
    fn supports_role(&self, _role: Role) -> bool {
        true
    }

    /// Whether this adapter can produce facts satisfying `kind`.
    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        self.kind_table()
            .iter()
            .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    /// Attach the fact's name and role edges by reading AST fields of `node`.
    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>);
}

/// Kind-table lookup compiled against a concrete grammar: node kind id →
/// normalized kind, O(1) per node during extraction walks.
pub(crate) struct CompiledKinds {
    by_id: Vec<Option<NormalizedKind>>,
}

impl CompiledKinds {
    pub(crate) fn compile(grammar: &TsLanguage, table: &[(&'static str, NormalizedKind)]) -> Self {
        let mut by_id = vec![None; grammar.node_kind_count() + 1];
        for (name, kind) in table {
            let id = grammar.id_for_node_kind(name, true);
            if id != 0 {
                by_id[id as usize] = Some(*kind);
            }
        }
        Self { by_id }
    }

    pub(crate) fn kind_of(&self, node: &Node<'_>) -> Option<NormalizedKind> {
        self.by_id.get(node.kind_id() as usize).copied().flatten()
    }
}

/// Collects the name and role edges for one fact during extraction. Resolves
/// target nodes to fact ids through the tree-node→fact map built in the first
/// extraction pass.
pub struct RoleSink<'a> {
    fact_by_ts_node: &'a HashMap<usize, u32>,
    name: Option<Span>,
    roles: Vec<RoleTarget>,
}

fn span_of(node: Node<'_>) -> Span {
    Span {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

impl<'a> RoleSink<'a> {
    pub(crate) fn new(fact_by_ts_node: &'a HashMap<usize, u32>) -> Self {
        Self {
            fact_by_ts_node,
            name: None,
            roles: Vec::new(),
        }
    }

    pub(crate) fn into_parts(self) -> (Option<Span>, Vec<RoleTarget>) {
        (self.name, self.roles)
    }

    /// Set the fact's own name from the given node's span.
    pub fn set_name(&mut self, name_node: Node<'_>) {
        self.name = Some(span_of(name_node));
    }

    /// Attach a role edge without a derived name.
    pub fn role(&mut self, role: Role, target: Node<'_>) {
        self.push(role, None, target, None);
    }

    /// Attach a role edge whose name is the span of `name_node`.
    pub fn role_named(&mut self, role: Role, target: Node<'_>, name_node: Node<'_>) {
        self.push(role, None, target, Some(span_of(name_node)));
    }

    /// Attach a role edge with a derived name when the language spec found
    /// one, otherwise attach the raw role target. This keeps fallback
    /// semantics consistent across adapters.
    pub fn role_maybe_named(&mut self, role: Role, target: Node<'_>, name: Option<Node<'_>>) {
        match name {
            Some(name) => self.role_named(role, target, name),
            None => self.role(role, target),
        }
    }

    /// Attach a role edge whose name is a precise span inside `target`.
    pub fn role_named_span(&mut self, role: Role, target: Node<'_>, name: Span) {
        self.push(role, None, target, Some(name));
    }

    /// Attach a keyword-argument edge (`shell=True` → keyword `shell`,
    /// target the value node).
    pub fn kwarg(&mut self, keyword_node: Node<'_>, value: Node<'_>) {
        self.push(Role::Kwarg, Some(span_of(keyword_node)), value, None);
    }

    fn push(&mut self, role: Role, keyword: Option<Span>, target: Node<'_>, name: Option<Span>) {
        self.roles.push(RoleTarget {
            role,
            keyword,
            node: self.fact_by_ts_node.get(&target.id()).copied(),
            span: span_of(target),
            name,
        });
    }
}
