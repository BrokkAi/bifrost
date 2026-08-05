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
use super::occurrences::{
    Namespace, OccurrenceRole, OccurrenceRoleSupport, default_occurrence_namespace,
};
use super::resolution::{BindingActivation, LexicalEnvironmentSupport};
use super::routes::{IdentityRouteSupport, RouteHopKind};
use crate::analyzer::{Language, Range};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use tree_sitter::{Language as TsLanguage, Node};

/// One source-backed leaf fact parsed from an opaque region of a primary node.
///
/// The descriptor is owned because the secondary parse tree does not survive
/// structural extraction. The extraction engine inserts the fact directly
/// below the primary node passed to [`StructuralSpec::embedded_leaf_facts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedLeafFact {
    pub kind: NormalizedKind,
    pub range: Range,
    pub occurrence_role: OccurrenceRole,
}

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

    /// A grammar-backed construct label for semantic generator rules.
    ///
    /// The label describes source syntax only. It must not describe generated
    /// behavior. Adapters must derive it from the tree-sitter node and fields.
    fn generator_construct(&self, _node: Node<'_>, _kind: NormalizedKind) -> Option<&'static str> {
        None
    }

    /// Whether this adapter can model `role` precisely enough to evaluate a
    /// query that asks for it.
    fn supports_role(&self, _role: Role) -> bool {
        true
    }

    /// Which occurrence roles this adapter classifies during [`Self::extract`].
    ///
    /// Deliberately has no default: the table is total, so a default would let
    /// a new adapter (or a new role) advertise support nobody implemented.
    /// Adapters that do not classify occurrences yet return
    /// [`super::occurrences::NO_OCCURRENCE_ROLE_SUPPORT`].
    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport;

    /// Which parts of a file's lexical environment this adapter answers:
    /// its scope tree, the interval each binding is in effect over, the local
    /// names its imports introduce, its package clause, and what its resolver
    /// reports about the candidates it considered.
    ///
    /// Deliberately has no default, for the same reason as
    /// [`Self::occurrence_role_support`]: the table is total, so a default
    /// would let a new adapter (or a new axis) advertise support nobody
    /// implemented. Adapters that derive no environment yet return
    /// [`super::resolution::NO_LEXICAL_ENVIRONMENT_SUPPORT`].
    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport;

    /// Which parts of the identity/route surface this adapter answers: whether
    /// it can group and decode qualified paths, resolve segment prefixes,
    /// project canonical identities, group physical occurrences, and which
    /// indirection relations it supplies route edges for.
    ///
    /// Deliberately has no default, for the same reason as
    /// [`Self::occurrence_role_support`]: the tables are total, so a default
    /// would let a new adapter (or a new axis or relation) advertise support
    /// nobody implemented. Adapters that answer nothing yet return
    /// [`super::routes::NO_IDENTITY_ROUTE_SUPPORT`].
    fn identity_route_support(&self) -> &IdentityRouteSupport;

    /// What binding `binder` introduces into the scope whose range is `scope`,
    /// and over which byte interval it is in effect.
    ///
    /// `binder` is the identifier token the adapter classified as
    /// [`OccurrenceRole::Binder`]; `scope` is the range of the innermost
    /// scope-forming fact that contains it, which is the scope the binding is
    /// declared in.
    ///
    /// `None` means the adapter cannot state an interval for this binder. The
    /// file's `BindingIntervals` axis then becomes incomplete and reaching
    /// bindings over it refuse to answer — an interval is never guessed. The
    /// default is `None` for exactly that reason: an adapter that declares the
    /// axis supported but implements nothing reports incomplete rather than
    /// wrong.
    fn binding_activation(&self, _binder: Node<'_>, _scope: Range) -> Option<BindingActivation> {
        None
    }

    /// The namespace an occurrence of `role` resolves in, where `declares` is
    /// the normalized kind of the fact this token names -- the enclosing fact
    /// whose own name span is exactly this token, and `None` when the token
    /// names no fact.
    ///
    /// `None` means the adapter cannot say; the occurrence row is dropped and
    /// the file's occurrence result becomes incomplete for that role, so no
    /// consumer ever reads a guessed namespace.
    fn occurrence_namespace(
        &self,
        role: OccurrenceRole,
        declares: Option<NormalizedKind>,
    ) -> Option<Namespace> {
        default_occurrence_namespace(role, declares)
    }

    /// The indirection relation an import/export token participates in:
    /// `Import` for a plain import, `Export` for an export of a local
    /// declaration, `ReExport` for an export whose subject comes from
    /// elsewhere (`pub use`, `export ... from`). Read from the token's
    /// enclosing statement through AST fields.
    ///
    /// `None` means the adapter cannot classify the statement; the derivation
    /// layer then treats an import-target token as a plain `Import`, which is
    /// what the occurrence role already states.
    fn indirection_relation(&self, _token: Node<'_>) -> Option<RouteHopKind> {
        None
    }

    /// The root node of the qualified-path chain `token` participates in: the
    /// outermost chain node (a `scoped_identifier`, `dotted_name`,
    /// `nested_identifier`, or language equivalent) whose ordered segments
    /// include this token. `None` when the token is not part of a qualified
    /// path — including when it is a bare single identifier, which is not a
    /// path.
    ///
    /// Must not cross a branching construct: for a Rust
    /// `use a::{B, C}` the shared prefix chain is one path and each list item
    /// stands alone, because a path is a linear sequence of segments.
    fn qualified_path_root<'tree>(&self, _token: Node<'tree>) -> Option<Node<'tree>> {
        None
    }

    /// Every segment token of the qualified-path chain rooted at `root`, in
    /// source order, read from the grammar's own chain structure (AST fields,
    /// never text splitting). Includes segment tokens that are not facts
    /// (Rust's `crate`/`self`/`super` path keywords), so ordinals state the
    /// real position of each segment within the path.
    ///
    /// The default is empty, which the derivation layer treats as "this
    /// adapter cannot enumerate the chain" — the path is skipped and the
    /// file's path axis reports incomplete, never a partial ordering.
    fn path_segment_tokens<'tree>(&self, _root: Node<'tree>) -> Vec<Node<'tree>> {
        Vec::new()
    }

    /// The number of generic (type) arguments the source spells at `token`'s
    /// segment position, read from the grammar's argument-list field. `None`
    /// means no generic arguments are spelled there — which is a statement
    /// about the source text, not about the declaration's own arity.
    fn segment_generic_arity(&self, _token: Node<'_>) -> Option<u32> {
        None
    }

    /// The spelling `raw` denotes once the grammar's identifier escaping is
    /// removed (Rust's `r#type` is the identifier `type`).
    ///
    /// `Some` only when decoding changes the spelling, so a consumer can treat
    /// the presence of a decoded spelling as "this token was escaped".
    fn decode_spelling(&self, _raw: &str) -> Option<String> {
        None
    }

    /// Parse source-backed leaf facts hidden inside an otherwise opaque node.
    ///
    /// The returned facts must be non-overlapping, ordered by source position,
    /// and strictly contained by `node`. They become direct normalized children
    /// of that node. Adapters must use a structured parser and must return no
    /// fact when an exact source range is unavailable.
    fn embedded_leaf_facts(
        &self,
        _node: Node<'_>,
        _kind: NormalizedKind,
        _source: &str,
        _cancellation: Option<&CancellationToken>,
    ) -> Vec<EmbeddedLeafFact> {
        Vec::new()
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
pub struct CompiledKinds {
    by_id: Vec<Option<NormalizedKind>>,
}

impl CompiledKinds {
    pub fn compile(grammar: &TsLanguage, table: &[(&'static str, NormalizedKind)]) -> Self {
        let mut by_id = vec![None; grammar.node_kind_count() + 1];
        for (name, kind) in table {
            let id = grammar.id_for_node_kind(name, true);
            if id != 0 {
                by_id[id as usize] = Some(*kind);
            }
        }
        Self { by_id }
    }

    pub fn kind_of(&self, node: &Node<'_>) -> Option<NormalizedKind> {
        self.by_id.get(node.kind_id() as usize).copied().flatten()
    }
}

/// Collects the name and role edges for one fact during extraction. Resolves
/// target nodes to fact ids through the tree-node→fact map built in the first
/// extraction pass.
pub struct RoleSink<'a> {
    fact_by_ts_node: &'a HashMap<usize, u32>,
    name: Option<Span>,
    roles: &'a mut Vec<RoleTarget>,
    /// Per-node occurrence-role classifications emitted during this walk,
    /// addressed by fact id rather than by the emitting fact. Extraction
    /// buckets them into the file's occurrence-role rows once the walk ends.
    occurrence_roles: &'a mut Vec<(u32, OccurrenceRole)>,
    max_roles: usize,
    cancellation: Option<&'a CancellationToken>,
    stop: Option<RoleSinkStop>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleSinkStop {
    Exceeded,
    Cancelled,
}

fn span_of(node: Node<'_>) -> Span {
    Span {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

impl<'a> RoleSink<'a> {
    pub fn new(
        fact_by_ts_node: &'a HashMap<usize, u32>,
        roles: &'a mut Vec<RoleTarget>,
        occurrence_roles: &'a mut Vec<(u32, OccurrenceRole)>,
        max_roles: usize,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            fact_by_ts_node,
            name: None,
            roles,
            occurrence_roles,
            max_roles,
            cancellation,
            stop: None,
        }
    }

    /// Classify one identifier-bearing node's occurrence role.
    ///
    /// `target` must itself be a fact — an occurrence is addressed by the
    /// `(content identity, fact id)` pair every later layer joins on, so a
    /// classification for a node the kind table does not admit has nowhere to
    /// live. Adapters extend their kind table rather than emitting here.
    pub fn occurrence_role(&mut self, target: Node<'_>, role: OccurrenceRole) {
        let node = self.fact_by_ts_node.get(&target.id()).copied();
        debug_assert!(
            node.is_some(),
            "occurrence role {role:?} emitted for non-fact node {:?}; add its kind to the kind table",
            target.kind()
        );
        if let Some(node) = node {
            self.occurrence_roles.push((node, role));
        }
    }

    pub fn into_parts(self) -> (Option<Span>, Option<RoleSinkStop>) {
        (self.name, self.stop)
    }

    /// Poll cancellation and the role-edge admission cap before adapters
    /// inspect or append the next variable-length role.
    pub fn should_continue(&mut self) -> bool {
        if self.stop.is_some() {
            return false;
        }
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            self.stop = Some(RoleSinkStop::Cancelled);
            return false;
        }
        if self.roles.len() >= self.max_roles {
            self.stop = Some(RoleSinkStop::Exceeded);
            return false;
        }
        true
    }

    /// Set the fact's own name from the given node's span.
    pub fn set_name(&mut self, name_node: Node<'_>) {
        self.name = Some(span_of(name_node));
    }

    /// Attach a role edge without a derived name.
    pub fn role(&mut self, role: Role, target: Node<'_>) {
        let _ = self.push(role, false, None, target, None);
    }

    /// Attach a role edge whose name is the span of `name_node`.
    pub fn role_named(&mut self, role: Role, target: Node<'_>, name_node: Node<'_>) {
        let _ = self.push(role, false, None, target, Some(span_of(name_node)));
    }

    /// Attach an argument role, preserving whether it came from a
    /// spread/unpack expression.
    pub fn argument_maybe_named(&mut self, target: Node<'_>, name: Option<Node<'_>>, spread: bool) {
        let _ = self.push(Role::Arg, spread, None, target, name.map(span_of));
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
        let _ = self.push(role, false, None, target, Some(name));
    }

    /// Attach a keyword-argument edge (`shell=True` → keyword `shell`,
    /// target the value node).
    pub fn kwarg(&mut self, keyword_node: Node<'_>, value: Node<'_>) {
        let _ = self.push(Role::Kwarg, false, Some(span_of(keyword_node)), value, None);
    }

    fn push(
        &mut self,
        role: Role,
        spread: bool,
        keyword: Option<Span>,
        target: Node<'_>,
        name: Option<Span>,
    ) -> bool {
        if !self.should_continue() {
            return false;
        }
        self.roles.push(RoleTarget {
            role,
            spread,
            keyword,
            node: self.fact_by_ts_node.get(&target.id()).copied(),
            span: span_of(target),
            name,
        });
        true
    }
}
