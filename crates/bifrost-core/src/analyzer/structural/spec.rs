//! The per-language boundary of structural search.
//!
//! A [`StructuralSpec`] is everything a language contributes: a static table
//! mapping its tree-sitter node-type names onto [`NormalizedKind`]s, an
//! optional context-sensitive kind refinement (Python turns a `function`
//! directly inside a `class` into `method`), and role extraction that reads
//! tree-sitter AST *fields* — never source-text splitting — to attach
//! `callee`/`receiver`/`args`/... edges to facts. Everything else (walking,
//! matching, planning, tooling) is language-independent.

use super::callable::{CallSiteContext, CallSiteFacts};
use super::edges::ReferenceEdgeSupport;
use super::facts::{AssignmentShape, IntegerLiteralValue, Span};
use super::kinds::{NormalizedKind, Role};
use super::materialization::{DeclarationMaterializationSupport, SourceExportFacts};
use super::occurrences::{
    Namespace, OccurrenceRole, OccurrenceRoleSupport, default_occurrence_namespace,
};
use super::resolution::{
    BindingActivation, BindingScopeCandidate, BindingScopeSelection, ImportActivation,
    LexicalEnvironmentSupport, ScopeFormation, default_scope_formation,
};
use super::routes::{CuratedExportSurface, IdentityRouteSupport, RouteHopKind};
use crate::analyzer::model::AmbientUseRole;
use crate::analyzer::source_facts::{
    SourceOccurrenceId, SourceOccurrenceProvenance, SourceOccurrenceSink,
};
use crate::analyzer::tree_walk::ParentIndex;
use crate::analyzer::{Language, Range};
use crate::cancellation::CancellationToken;
use tree_sitter::{Language as TsLanguage, Node};

pub const fn supports_role_without_iterable_or_element(role: Role) -> bool {
    !matches!(role, Role::Iterable | Role::Element)
}

pub const fn supports_role_without_kwarg(role: Role) -> bool {
    !matches!(role, Role::Kwarg)
}

/// Whether `kind` is a language-specific extra or is satisfied by a grammar
/// kind-table entry.
pub fn supports_kind_from_table(
    kind: NormalizedKind,
    extra_kinds: &[NormalizedKind],
    kind_table: &[(&str, NormalizedKind)],
) -> bool {
    extra_kinds.contains(&kind)
        || kind_table
            .iter()
            .any(|(_, fact_kind)| fact_kind.satisfies(kind))
}

/// A binding whose name is written outside its owning scope.
/// The name retains its source token identity; the consuming scope owns its
/// activation, as for a parameter written directly in that scope.
#[derive(Debug, Clone, Copy)]
pub struct ImplicitScopeBinder<'tree> {
    pub name: Node<'tree>,
}

/// One source-backed fact parsed from a structured value inside a primary node.
///
/// The descriptor is owned because the secondary parse tree does not survive
/// structural extraction. Facts are supplied in pre-order; `parent` indexes a
/// prior fact in the same vector, or `None` attaches below the primary node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedLeafFact {
    pub kind: NormalizedKind,
    pub range: Range,
    pub parent: Option<usize>,
    pub construct: Option<String>,
    pub occurrence_role: Option<OccurrenceRole>,
}

/// A source-backed tree replacing the opaque children of one parser node.
/// Only `range` is exposed: synthetic fragment wrappers are never extracted.
#[derive(Debug)]
pub struct EmbeddedSyntaxTree {
    pub anchor: usize,
    pub tree: tree_sitter::Tree,
    pub range: tree_sitter::Range,
}

impl EmbeddedSyntaxTree {
    pub fn root(&self) -> Node<'_> {
        self.tree
            .root_node()
            .descendant_for_byte_range(self.range.start_byte, self.range.end_byte)
            .expect("embedded syntax retains its admitted range")
    }
}

#[derive(Debug)]
pub struct EmbeddedSyntaxForest {
    trees: Vec<EmbeddedSyntaxTree>,
    by_anchor: crate::hash::HashMap<usize, Vec<usize>>,
}

#[derive(Debug)]
pub enum EmbeddedSyntaxStop {
    Exceeded,
    Cancelled,
}

impl EmbeddedSyntaxForest {
    /// One bounded file/query parse. Trees are dropped with this forest, never
    /// retained in a workspace index or an unbounded cache.
    pub fn parse(
        spec: &dyn StructuralSpec,
        root: Node<'_>,
        source: &str,
        max_trees: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, EmbeddedSyntaxStop> {
        if spec.embedded_syntax_kinds().is_empty() {
            return Ok(Self {
                trees: Vec::new(),
                by_anchor: crate::hash::HashMap::default(),
            });
        }
        let mut trees: Vec<EmbeddedSyntaxTree> = Vec::new();
        let mut index = 0;
        let mut retained_nodes = 0usize;
        loop {
            let root = if index == 0 {
                root
            } else {
                trees[index - 1].root()
            };
            let mut additions = Vec::new();
            let mut pending = vec![root];
            while let Some(node) = pending.pop() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return Err(EmbeddedSyntaxStop::Cancelled);
                }
                let embedded = if spec.embedded_syntax_kinds().contains(&node.kind()) {
                    spec.embedded_syntax(node, source)
                } else {
                    Vec::new()
                };
                if !embedded.is_empty() {
                    retained_nodes = embedded.iter().fold(retained_nodes, |total, tree| {
                        total.saturating_add(tree.root().descendant_count())
                    });
                    if retained_nodes > max_trees {
                        return Err(EmbeddedSyntaxStop::Exceeded);
                    }
                    additions.extend(embedded);
                } else {
                    crate::analyzer::tree_walk::push_named_children_reversed_as(
                        node,
                        &mut pending,
                        |child| child,
                    );
                }
            }
            trees.extend(additions);
            index += 1;
            if index > trees.len() {
                break;
            }
        }
        let mut by_anchor: crate::hash::HashMap<usize, Vec<usize>> =
            crate::hash::HashMap::default();
        for (index, tree) in trees.iter().enumerate() {
            by_anchor.entry(tree.anchor).or_default().push(index);
        }
        Ok(Self { trees, by_anchor })
    }

    /// Select syntax by original source coordinates before interpreting a site.
    /// The narrowest admitted fragment owns its interior; synthetic wrappers
    /// never acquire source authority. This is independent of lookup success.
    pub fn tree_for_range<'a>(
        &'a self,
        primary: &'a tree_sitter::Tree,
        start: usize,
        end: usize,
    ) -> &'a tree_sitter::Tree {
        self.trees
            .iter()
            .filter(|tree| tree.range.start_byte <= start && end <= tree.range.end_byte)
            .min_by_key(|tree| tree.range.end_byte - tree.range.start_byte)
            .map_or(primary, |tree| &tree.tree)
    }

    pub fn children(&self, anchor: usize) -> Option<impl DoubleEndedIterator<Item = Node<'_>>> {
        self.by_anchor
            .get(&anchor)
            .map(|indices| indices.iter().map(|index| self.trees[*index].root()))
    }

    /// Establish fragment provenance before any ordinary structural role asks
    /// to intern the same live node. Only one file's admitted trees are walked.
    pub fn register_occurrences(
        &self,
        collector: &mut crate::analyzer::source_facts::PrimarySourceFactCollector<'_>,
        cancellation: Option<&CancellationToken>,
    ) -> bool {
        self.for_each_node(|_, node| {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(());
            }
            collector.intern_embedded_node(node);
            Ok(())
        })
        .is_ok()
    }

    /// Visit admitted nodes in forest order. An anchor from a parent fragment
    /// has already been visited when its embedded children are reached.
    pub fn for_each_node<'tree, E>(
        &'tree self,
        mut visit: impl FnMut(usize, Node<'tree>) -> Result<(), E>,
    ) -> Result<(), E> {
        for tree in &self.trees {
            let mut pending = vec![tree.root()];
            while let Some(node) = pending.pop() {
                visit(tree.anchor, node)?;
                crate::analyzer::tree_walk::push_named_children_reversed_as(
                    node,
                    &mut pending,
                    |child| child,
                );
            }
        }
        Ok(())
    }

    pub fn trees(&self) -> &[EmbeddedSyntaxTree] {
        &self.trees
    }
}

pub trait StructuralSpec: Send + Sync + 'static {
    fn language(&self) -> Language;

    /// Grammar-specific node-type name → normalized kind. Compiled once per
    /// extraction into an id-indexed lookup via `Language::id_for_node_kind`;
    /// a per-language test must assert every entry resolves (id != 0) so
    /// grammar bumps that rename nodes fail loudly.
    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)];

    /// Byte ranges of `source` the parser may read, or `None` to parse the
    /// whole file.
    ///
    /// Only C# overrides this. Its grammar cannot represent a preprocessor
    /// directive inside a declaration, so C# hides directive lines and inactive
    /// conditional branches from the parser (issue #1803). Ranges select bytes
    /// of the original source, so every fact keeps its raw-file offset.
    fn parser_included_ranges(&self, _source: &str) -> Option<Vec<tree_sitter::Range>> {
        None
    }

    /// Conditional-compilation evidence for this file. It is query-time data,
    /// not part of persisted structural rows.
    fn preprocess(
        &self,
        _source: &str,
    ) -> Option<std::sync::Arc<dyn crate::analyzer::prepared_syntax::SourcePreprocessor>> {
        None
    }

    /// A tree re-parsed around syntax the bundled grammar cannot represent, or
    /// `None` when `tree` stands as parsed.
    ///
    /// Only Go overrides this. Its grammar models `new` as a keyword whose
    /// argument must be a type, so Go 1.26's `new(expr)` fails to parse and
    /// recovery swallows the expression -- and sometimes the statement after it
    /// (issue #3325). Whether a file contains that shape is only visible in a
    /// tree, which is why this runs after the parse rather than before it.
    fn reparse_grammar_gap(
        &self,
        _source: &str,
        _tree: &tree_sitter::Tree,
        _cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<tree_sitter::Tree> {
        None
    }

    /// Context-sensitive refinement applied after table lookup. `enclosing`
    /// is the kind of the nearest enclosing normalized node, and `context` is
    /// the per-file [`CallSiteContext`] from [`Self::call_site_context`], for
    /// refinements that depend on file-wide facts (Ruby's value-position bare
    /// calls).
    fn refine_kind(
        &self,
        _node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        kind
    }

    /// Context-sensitive refinement with the parent index owned by the
    /// structural walk. Adapters that need ancestry can override this hook so
    /// each question is an indexed lookup rather than a tree-sitter re-descent.
    fn refine_kind_with_parents<'tree>(
        &self,
        node: Node<'tree>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        source: &str,
        context: &CallSiteContext,
        _parents: &ParentIndex<'tree>,
    ) -> NormalizedKind {
        self.refine_kind(node, kind, enclosing, source, context)
    }

    /// Whether this normalized node should become a fact at all. Use this for
    /// grammar nodes whose normalized kind is conditional on fields, such as
    /// variable declarators that are assignments only when they have values.
    fn should_extract(&self, _node: Node<'_>, _kind: NormalizedKind) -> bool {
        true
    }

    /// Source-local statement aggregation is unsupported unless the adapter
    /// supplies grammar roles and the evidence absent from normalized kinds.
    fn statement_fact_syntax(
        &self,
    ) -> Option<&dyn crate::analyzer::statement_facts::producer::StatementFactSyntax> {
        None
    }

    /// A grammar-backed construct label for semantic generator rules.
    ///
    /// The label describes source syntax only. It must not describe generated
    /// behavior. Adapters must derive it from the tree-sitter node and fields.
    fn generator_construct(
        &self,
        _node: Node<'_>,
        _kind: NormalizedKind,
        _source: &str,
    ) -> Option<&'static str> {
        None
    }

    /// Per-file knowledge this adapter needs before it can classify any call
    /// site, gathered once from the file's own parse tree.
    ///
    /// The default is empty, which is the honest answer for a language whose
    /// call sites are decided by their own grammar node alone. C and C++
    /// override it to collect the function-like macro names of the
    /// translation unit, because whether `FOO(a, b)` has a readable argument
    /// list is a fact about the file's `#define`s, not about the call.
    fn call_site_context(&self, _root: Node<'_>, _source: &str) -> CallSiteContext {
        CallSiteContext::default()
    }

    /// What this adapter's grammar says about the call site at `node`, whose
    /// normalized kind satisfies [`NormalizedKind::Call`].
    ///
    /// `None` means "this language does not refine this site", which keeps the
    /// shared baseline: the call kind follows receiver presence, coverage is
    /// exact, and the site owns its own argument lists. Adapters must read
    /// grammar node types and AST fields only — a call kind that source text
    /// would have to be re-parsed to discover is left unrefined instead.
    fn call_site_facts(
        &self,
        _node: Node<'_>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        None
    }

    /// Blob-local callee provenance, charged against structural extraction's
    /// existing work allowance. Other adapters do not publish this fact.
    fn callee_provenance(
        &self,
        _node: Node<'_>,
        _source: &str,
        _charge: &mut dyn FnMut(usize) -> Result<(), super::collector::StructuralFactCollectorStop>,
    ) -> Result<
        Option<super::callable::CalleeProvenanceFact>,
        super::collector::StructuralFactCollectorStop,
    > {
        Ok(None)
    }

    /// Whether this adapter can model `role` precisely enough to evaluate a
    /// query that asks for it.
    fn supports_role(&self, _role: Role) -> bool {
        true
    }

    /// Whether this adapter can state the exact language-neutral value of
    /// every boolean-literal fact it extracts. The default is deliberately
    /// unsupported so a third-party adapter cannot silently answer an exact
    /// value query from kind alone.
    fn supports_boolean_literal_value(&self) -> bool {
        false
    }

    /// Whether this adapter publishes parenthesized-expression state for all
    /// normalized string-literal facts.
    fn supports_string_literal_parenthesized(&self) -> bool {
        false
    }

    /// Whether this adapter can decode supported string-literal source forms
    /// into their language-neutral value. Individual unsupported forms may
    /// still return `None`, which exact-value queries report as incomplete.
    fn supports_string_literal_value(&self) -> bool {
        false
    }

    /// Whether this normalized string-literal node has a known reason to lack
    /// a decoded UTF-8 value, such as a byte string or parser-reported invalid
    /// literal syntax. This per-node exception must not mask a missing decoder
    /// for an otherwise supported valid literal.
    fn string_literal_value_may_be_absent(&self, _node: Node<'_>, _source: &str) -> bool {
        false
    }

    /// Exact decoded value of a node normalized as
    /// [`NormalizedKind::StringLiteral`]. The adapter must read the grammar's
    /// string-content and escape nodes rather than trimming source text.
    fn string_literal_value(&self, _node: Node<'_>, _source: &str) -> Option<String> {
        None
    }

    /// Whether a normalized string-literal expression has parenthesized
    /// expression wrappers around it.
    fn string_literal_parenthesized(&self, _node: Node<'_>) -> Option<bool> {
        None
    }

    /// Complete comparison operator spans from this grammar node. Unknown by
    /// default. This transient shape is only a negative candidate proof: it
    /// does not publish singular roles or correlated operand pairs.
    /// Each span must be both the exact name and text spelling used by an
    /// un-normalized Operator role; otherwise the adapter must return None.
    /// Call `step` before inspecting each child or growing the result and once
    /// before returning a complete answer; a stopped callback must return None.
    fn comparison_operator_spans(
        &self,
        _node: Node<'_>,
        _step: &mut dyn FnMut() -> bool,
    ) -> Option<Vec<Span>> {
        None
    }

    /// Whether this adapter records directly paired tuple/list assignment
    /// shapes for the supported syntax it recognizes.
    fn supports_assignment_shape(&self) -> bool {
        false
    }

    /// Paired direct sequence sides of a multiple assignment, if both sides
    /// have a supported tuple/list shape.
    fn assignment_shape(&self, _node: Node<'_>) -> Option<AssignmentShape> {
        None
    }

    /// Whether this adapter publishes integer literal values and permission bits.
    fn supports_integer_literal_value(&self) -> bool {
        false
    }

    /// Canonical decimal value, when queryable, and low 32 bits for a
    /// grammar-backed integer literal.
    fn integer_literal_value(&self, _node: Node<'_>, _source: &str) -> Option<IntegerLiteralValue> {
        None
    }

    /// Whether a Python dictionary entry repeats an earlier key by decoded
    /// literal value. `None` means the key syntax is outside the supported
    /// literal subset.
    fn duplicate_dictionary_key(&self, _node: Node<'_>, _source: &str) -> Option<bool> {
        None
    }

    /// Whether this adapter can classify duplicate keys in dictionary
    /// literals, including reporting unsupported key forms as incomplete.
    fn supports_duplicate_dictionary_keys(&self) -> bool {
        false
    }

    /// Whether this adapter records unsafe context for every call fact.
    fn supports_unsafe_context(&self) -> bool {
        false
    }

    /// Called only for call nodes while their AST is available. Syntax work
    /// shares the collector allowance used by callee provenance.
    fn unsafe_context_value(
        &self,
        _node: Node<'_>,
        _charge: &mut dyn FnMut(usize) -> Result<(), super::collector::StructuralFactCollectorStop>,
    ) -> Result<Option<bool>, super::collector::StructuralFactCollectorStop> {
        Ok(None)
    }

    /// Source-written attributes of declarations supported by this adapter.
    fn declaration_attributes(
        &self,
        _node: Node<'_>,
        _source: &str,
    ) -> Option<super::facts::DeclarationAttributes> {
        None
    }

    /// Whether this adapter records AST-backed async modifiers for callable facts.
    fn supports_async_callable_value(&self) -> bool {
        false
    }

    /// Exact value of a node normalized as [`NormalizedKind::BooleanLiteral`].
    /// This default reads tree-sitter's underlying grammar symbol identity,
    /// which remains structured even when a grammar aliases both tokens to a
    /// common named `boolean_literal` node. For grammars that retain a named
    /// wrapper, it reads that wrapper's sole non-extra child. It never reads
    /// source text.
    fn boolean_literal_value(&self, node: Node<'_>) -> Option<bool> {
        if let Some(value) = super::adapter_helpers::boolean_literal_value(node.grammar_name()) {
            return Some(value);
        }
        let mut cursor = node.walk();
        let mut children = node.children(&mut cursor).filter(|child| !child.is_extra());
        let child = children.next()?;
        if children.next().is_some() {
            return None;
        }
        super::adapter_helpers::boolean_literal_value(child.grammar_name())
    }

    /// Exact async property of a normalized callable. The default leaves the
    /// property unknown; adapters must read callable modifiers from AST nodes.
    fn async_callable_value(&self, _node: Node<'_>) -> Option<bool> {
        None
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

    /// Which parts of a file's declaration-materialization story this adapter
    /// answers: the origin and state of its declarations, its generation
    /// sites and their generated sets, its export declarations, the link from
    /// a declaration-only signature to its implementation, and which
    /// declarations are gated by a preprocessing configuration.
    ///
    /// Deliberately has no default, for the same reason as
    /// [`Self::occurrence_role_support`]: the table is total, so a default
    /// would let a new adapter (or a new axis) advertise support nobody
    /// implemented. Adapters that record no materialization provenance yet
    /// return [`super::materialization::NO_MATERIALIZATION_SUPPORT`].
    fn materialization_support(&self) -> &DeclarationMaterializationSupport;

    /// Source export declarations derived directly from a prepared parse tree.
    ///
    /// These rows are query-time facts. Adapters that do not use this source
    /// form return `None`; Python uses it for a module-level `__all__` list so
    /// its exports do not need a serialized materialization payload.
    fn source_export_facts(&self, _root: Node<'_>, _source: &str) -> Option<SourceExportFacts> {
        None
    }

    /// Which parts of the reference-edge domain this adapter answers: whether
    /// forward (site-to-target) and inverse (target-to-site) edge projections
    /// exist for it, and which classification axes those edges carry.
    ///
    /// Deliberately has no default, for the same reason as
    /// [`Self::occurrence_role_support`]: the table is total, so a default
    /// would let a new adapter (or a new axis) advertise support nobody
    /// implemented. Adapters that derive no edges yet return
    /// [`super::edges::NO_REFERENCE_EDGE_SUPPORT`].
    fn reference_edge_support(&self) -> &ReferenceEdgeSupport;
    /// Which parts of the identity/route surface this adapter answers: whether
    /// it can group and decode qualified paths, resolve segment prefixes,
    /// project canonical identities, group physical occurrences, and which
    /// indirection relations it supplies route edges for.
    /// [`Self::occurrence_role_support`]: the tables are total, so a default
    /// would let a new adapter (or a new axis or relation) advertise support
    /// nobody implemented. Adapters that answer nothing yet return
    /// [`super::routes::NO_IDENTITY_ROUTE_SUPPORT`].
    fn identity_route_support(&self) -> &IdentityRouteSupport;

    /// How a fact of normalized kind `kind` participates in this language's
    /// lexical scope tree: whether it opens a scope at all, and whether the
    /// binders written directly inside it are lexical bindings or members.
    ///
    /// The default is the C-family and Python answer
    /// ([`default_scope_formation`]). An adapter overrides it when its
    /// language disagrees about what a scope is rather than bending its kind
    /// table to fit: Ruby's `while`, `for` and `rescue` do not open
    /// variable scopes (a local assigned inside one outlives it), its
    /// `module` bodies do, and a bare assignment in a `class` body is an
    /// ordinary local rather than a member.
    fn scope_formation(&self, kind: NormalizedKind) -> ScopeFormation {
        default_scope_formation(kind)
    }

    /// Select the owner of a binder from its nearest scope and successive parents.
    /// The producer owns that iterative walk; adapters classify only this candidate.
    /// Unknown ownership withholds the binding and leaves intervals incomplete.
    fn binding_scope_selection(
        &self,
        _binder: Node<'_>,
        _candidate: BindingScopeCandidate<'_>,
    ) -> BindingScopeSelection {
        BindingScopeSelection::Use
    }

    /// The declaration whose signature and body are in scope for this formal.
    fn type_parameter_owner<'tree>(&self, _name: Node<'tree>) -> Option<Node<'tree>> {
        None
    }

    /// Whether this syntax owner stops inheritance of enclosing type formals.
    /// Owners without ordinary lexical scopes (for example static fields) are
    /// barriers over their syntax range as well.
    fn type_parameter_scope_barrier(&self, _owner: Node<'_>) -> bool {
        false
    }

    /// Source-backed binders implicitly introduced by this syntax scope.
    ///
    /// These tokens need not be descendants of `scope_node`. Their binding
    /// kind and activation use [`Self::binding_activation`] with this scope's
    /// range, just like ordinary binder tokens. `None` means the syntax does
    /// not establish the implicit bindings and makes binding intervals incomplete.
    fn implicit_scope_binders<'tree>(
        &self,
        _scope_node: Node<'tree>,
    ) -> Option<Vec<ImplicitScopeBinder<'tree>>> {
        Some(Vec::new())
    }

    /// What binding `binder` introduces into the scope whose range is `scope`,
    /// and over which byte interval it is in effect.
    ///
    /// `binder` is the identifier token the adapter classified as
    /// [`OccurrenceRole::Binder`]; `scope` is the range of the declaring scope selected by
    /// [`Self::binding_scope_selection`]. Ownership and activation use the same row.
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

    /// What lexical binding, if any, a declaration-name token introduces.
    ///
    /// Most declaration names are not pure binders: their occurrence role
    /// remains [`OccurrenceRole::DeclarationName`]. Some languages also have
    /// declaration heads, such as named function declarations, that introduce
    /// a lexical name while retaining that declaration role. Those adapters
    /// state the environment fact here without emitting a second occurrence
    /// row with [`OccurrenceRole::Binder`].
    fn declaration_binding_activation(
        &self,
        _declaration_name: Node<'_>,
        _scope: Range,
    ) -> Option<BindingActivation> {
        None
    }

    /// The interval the local name of the import declaration spanning
    /// `declaration` is in effect over, inside the scope whose range is
    /// `scope` and whose normalized kind is `scope_kind` (`None` for the
    /// synthesized whole-file scope).
    ///
    /// This is the import-binder counterpart of [`Self::binding_activation`]:
    /// the derivation layer knows which scope an import is written in, and the
    /// adapter states when the name it introduces starts being in effect. The
    /// default is scope-wide, which every language whose imports either hoist
    /// or are required at the top of their scope keeps by not overriding it.
    /// Scala overrides it because a block-local `import` is in effect from the
    /// import statement onward (#2925).
    ///
    /// There is no `None` here, unlike [`Self::binding_activation`]: the
    /// import row exists either way, and the scope it is written in is always
    /// an interval the layer can state, so an adapter that says nothing is
    /// stating the scope-wide answer rather than failing to answer.
    fn import_binder_activation(
        &self,
        _declaration: Range,
        scope: Range,
        _scope_kind: Option<NormalizedKind>,
    ) -> ImportActivation {
        ImportActivation::scope_wide(scope)
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

    /// The public surface the file rooted at `root` curates by listing names
    /// rather than by marking each declaration (Python's module-level
    /// `__all__`), gathered once per file so
    /// [`Self::indirection_relation`] can read it per token.
    ///
    /// The default is [`CuratedExportSurface::Absent`], which is the honest
    /// answer for a language whose exports are decided declaration by
    /// declaration.
    fn curated_export_surface(&self, _root: Node<'_>, _source: &str) -> CuratedExportSurface {
        CuratedExportSurface::Absent
    }

    /// The indirection relation an import/export token participates in:
    /// `Import` for a plain import, `Export` for an export of a local
    /// declaration, `ReExport` for an export whose subject comes from
    /// elsewhere (`pub use`, `export ... from`, a name on Python's `__all__`).
    /// Read from the token's enclosing statement through AST fields, plus the
    /// file's `surface` from [`Self::curated_export_surface`].
    ///
    /// `None` means the adapter cannot classify this token; the derivation
    /// layer then treats an import-target token as a plain `Import` — which is
    /// what the occurrence role already states — and reports the file's
    /// import, export and re-export rows as incomplete, so absence of a
    /// re-export row proves nothing.
    fn indirection_relation(
        &self,
        _token: Node<'_>,
        _source: &str,
        _surface: &CuratedExportSurface,
    ) -> Option<RouteHopKind> {
        None
    }

    /// The contextual role the declaration at `node` carries: whether importing
    /// it can consume it without the importing file spelling the imported name.
    ///
    /// `node` is a declaration node, located from an analyzer declaration range
    /// rather than from source text. The answer is a positive syntax fact, so
    /// `None` means this adapter does not establish a role for this node kind
    /// and a consumer must treat the declaration as unreviewed. The default is
    /// `None`, which is the honest answer for a language whose imports cannot be
    /// consumed without spelling the imported name at all -- absence of the
    /// spelling already decides those.
    fn declaration_ambient_use(&self, _node: Node<'_>) -> Option<AmbientUseRole> {
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

    /// Parse source-backed facts hidden inside an otherwise opaque node.
    ///
    /// The returned facts are in pre-order; a fact with no `parent` becomes a
    /// direct normalized child of `node`, and other facts become children of
    /// their earlier local parent. Every span must be contained by its parent
    /// and by `node`. Adapters must use a structured parser and must return no
    /// fact when an exact source range is unavailable.
    /// Parse expression trees hidden below an opaque grammar node. Returned
    /// roots use exact source coordinates and replace that anchor's children.
    fn embedded_syntax_kinds(&self) -> &'static [&'static str] {
        &[]
    }

    fn embedded_syntax(&self, _node: Node<'_>, _source: &str) -> Vec<EmbeddedSyntaxTree> {
        Vec::new()
    }

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
        supports_kind_from_table(kind, &[NormalizedKind::SyntaxError], self.kind_table())
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

/// A role edge captured before the coordinated structural walk has seen every
/// normalized node. The collector resolves `target_node` against the complete
/// AST-node key map when extraction finishes.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct PendingRoleTarget {
    pub role: Role,
    pub spread: bool,
    pub keyword: Option<SourceOccurrenceId>,
    pub target_node: usize,
    pub occurrence: SourceOccurrenceId,
    pub name: Option<SourceOccurrenceId>,
}

/// An occurrence-role classification captured before the collector has built
/// the complete AST-node key map.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct PendingOccurrenceRole {
    pub target_node: usize,
    pub role: OccurrenceRole,
}

/// Collects the name and role edges for one fact during extraction. Target
/// nodes remain exact tree-sitter node keys until the structural collector has
/// seen every event in the language-owned walk.
pub struct RoleSink<'a> {
    source: &'a str,
    parents: &'a crate::analyzer::tree_walk::ParentIndex<'a>,
    source_facts: &'a mut dyn SourceOccurrenceSink,
    name: Option<SourceOccurrenceId>,
    roles: Vec<PendingRoleTarget>,
    occurrence_roles: Vec<PendingOccurrenceRole>,
    max_roles: usize,
    cancellation: Option<&'a CancellationToken>,
    stop: Option<RoleSinkStop>,
}

pub type RoleSinkParts = (
    Option<SourceOccurrenceId>,
    Vec<PendingRoleTarget>,
    Vec<PendingOccurrenceRole>,
    Option<RoleSinkStop>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleSinkStop {
    Exceeded,
    Cancelled,
}

impl<'a> RoleSink<'a> {
    pub fn new(
        source: &'a str,
        source_facts: &'a mut dyn SourceOccurrenceSink,
        max_roles: usize,
        cancellation: Option<&'a CancellationToken>,
        parents: &'a ParentIndex<'a>,
    ) -> Self {
        Self {
            source,
            source_facts,
            name: None,
            roles: Vec::new(),
            occurrence_roles: Vec::new(),
            max_roles,
            cancellation,
            stop: None,
            parents,
        }
    }

    /// Source snapshot for adapters whose selected AST node contains an
    /// opaque token tree that needs a grammar-backed secondary parse.
    pub fn source(&self) -> &'a str {
        self.source
    }

    /// The AST parent of `node`, answered from the walk's index.
    ///
    /// Identical to [`Node::parent`] -- the index is built from the same
    /// visible-child relation -- but constant time rather than a re-descent
    /// from the root.
    pub fn parent(&self, node: Node<'a>) -> Option<Node<'a>> {
        self.parents.parent(node)
    }

    /// The walk's parent index, for spec helpers that climb ancestors
    /// themselves rather than asking one question.
    pub fn parents(&self) -> &'a ParentIndex<'a> {
        self.parents
    }

    /// Classify one identifier-bearing node's occurrence role.
    ///
    /// `target` must itself be a fact — an occurrence is addressed by the
    /// `(content identity, fact id)` pair every later layer joins on, so a
    /// classification for a node the kind table does not admit has nowhere to
    /// live. Adapters extend their kind table rather than emitting here.
    pub fn occurrence_role(&mut self, target: Node<'_>, role: OccurrenceRole) {
        self.source_facts.intern_node(target);
        self.occurrence_roles.push(PendingOccurrenceRole {
            target_node: target.id(),
            role,
        });
    }

    pub fn into_parts(
        self,
    ) -> (
        Option<SourceOccurrenceId>,
        Vec<PendingRoleTarget>,
        Vec<PendingOccurrenceRole>,
        Option<RoleSinkStop>,
    ) {
        (self.name, self.roles, self.occurrence_roles, self.stop)
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
        self.name = Some(self.source_facts.intern_node(name_node));
    }

    /// Attach a role edge without a derived name.
    pub fn role(&mut self, role: Role, target: Node<'_>) {
        let _ = self.push(role, false, None, target, None);
    }

    /// Attach a role edge whose name is the span of `name_node`.
    pub fn role_named(&mut self, role: Role, target: Node<'_>, name_node: Node<'_>) {
        let _ = self.push(role, false, None, target, Some(name_node));
    }

    /// Attach the terminal name of a path and, when it spans multiple nodes,
    /// the full path span as a second name edge.
    pub fn role_named_between_nodes(
        &mut self,
        role: Role,
        target: Node<'_>,
        first: Node<'_>,
        last: Node<'_>,
    ) {
        self.role_named(role, target, last);
        self.role_named_span(
            role,
            target,
            crate::analyzer::common::span_from_nodes(first, last),
        );
    }

    /// Attach an argument role, preserving whether it came from a
    /// spread/unpack expression.
    pub fn argument_maybe_named(&mut self, target: Node<'_>, name: Option<Node<'_>>, spread: bool) {
        let _ = self.push(Role::Arg, spread, None, target, name);
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
        let _ = self.push_span(role, false, None, target, name);
    }

    /// Attach a keyword-argument edge (`shell=True` → keyword `shell`,
    /// target the value node).
    pub fn kwarg(&mut self, keyword_node: Node<'_>, value: Node<'_>) {
        let _ = self.push(Role::Kwarg, false, Some(keyword_node), value, None);
    }

    /// Attach a keyword whose decoded name occupies an exact source subspan.
    /// The language adapter proves that the subspan is the keyword's value.
    pub fn kwarg_span(&mut self, keyword: Span, value: Node<'_>) {
        if !self.should_continue() {
            return;
        }
        let keyword = self.source_facts.intern_subspan_bytes(
            keyword.start_byte,
            keyword.end_byte,
            SourceOccurrenceProvenance::ExplicitSubspan,
        );
        let occurrence = self.source_facts.intern_node(value);
        self.roles.push(PendingRoleTarget {
            role: Role::Kwarg,
            spread: false,
            keyword: Some(keyword),
            target_node: value.id(),
            occurrence,
            name: None,
        });
    }

    fn push(
        &mut self,
        role: Role,
        spread: bool,
        keyword: Option<Node<'_>>,
        target: Node<'_>,
        name: Option<Node<'_>>,
    ) -> bool {
        if !self.should_continue() {
            return false;
        }
        let keyword = keyword.map(|node| self.source_facts.intern_node(node));
        let occurrence = self.source_facts.intern_node(target);
        let name = name.map(|node| self.source_facts.intern_node(node));
        self.roles.push(PendingRoleTarget {
            role,
            spread,
            keyword,
            target_node: target.id(),
            occurrence,
            name,
        });
        true
    }

    fn push_span(
        &mut self,
        role: Role,
        spread: bool,
        keyword: Option<Node<'_>>,
        target: Node<'_>,
        name: Span,
    ) -> bool {
        if !self.should_continue() {
            return false;
        }
        let keyword = keyword.map(|node| self.source_facts.intern_node(node));
        let occurrence = self.source_facts.intern_node(target);
        let name = self.source_facts.intern_subspan_bytes(
            name.start_byte,
            name.end_byte,
            SourceOccurrenceProvenance::ExplicitSubspan,
        );
        self.roles.push(PendingRoleTarget {
            role,
            spread,
            keyword,
            target_node: target.id(),
            occurrence,
            name: Some(name),
        });
        true
    }
}
