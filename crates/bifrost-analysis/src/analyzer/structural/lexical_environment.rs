//! The per-file lexical environment derivation layer (#1474, Milestone 2).
//!
//! An identifier resolves against an *environment*: the scopes a file is made
//! of, the bindings each scope introduces, the interval each binding is in
//! effect over, the local names its imports introduce, and the package the
//! file belongs to. Every one of those was previously either absent or private
//! to one language; this module derives all of them from the facts arena plus
//! one per-language hook, and answers the question they exist for — *which
//! binding of this name is in effect at this exact position?*
//!
//! Three properties are load-bearing:
//!
//! - The algorithm is single. Name equality, activation containment, scope
//!   ancestry and nearest-scope-wins are language-neutral; a language
//!   selects among ancestor scopes through [`StructuralSpec::binding_scope_selection`]
//!   and contributes [`BindingActivation`] through [`StructuralSpec::binding_activation`].
//! - Identity is structural, exactly as for occurrence rows: a binding is
//!   addressed by its binder token's `(content_identity, arena node)` pair, so
//!   a capture, an occurrence and a binding over the same token join on one
//!   digest rather than on a range or a spelling.
//! - Nothing is guessed. An adapter that cannot state an interval makes the
//!   file's `BindingIntervals` axis incomplete, and
//!   [`binding_of`] then refuses to answer instead of returning a
//!   plausible winner.
//!
//! Rows are derived per request and never persisted; the facts snapshot
//! underneath them is the cached part.

use std::collections::HashMap;

use super::facts::FileFacts;
use super::facts::Span;

use super::kinds::NormalizedKind;

use super::occurrence_rows::OccurrenceRow;
use super::occurrence_rows::ast_id;

use super::occurrences::Namespace;
use super::occurrences::OccurrenceRole;

use super::resolution::BindingKind;
use super::resolution::BindingScopeCandidate;
use super::resolution::BindingScopeSelection;
use super::resolution::BoundaryStatus;
use super::resolution::DeclaredVisibility;
use super::resolution::EnvironmentAxis;
use super::resolution::HoistingClass;
use super::resolution::ImportActivation;
use super::resolution::LexicalEnvironmentSupport;
use super::resolution::ScopeFormation;

use super::spec::StructuralSpec;

use crate::analyzer::common::language_for_file;

use crate::analyzer::semantic::ContentIdentity;

use crate::analyzer::structural_spec_for;

use crate::analyzer::usages::get_definition::parse_tree_for_language;

use crate::analyzer::AnalyzerQueryScope;
use crate::analyzer::QueryScope;

use crate::analyzer::CodeUnit;
use crate::analyzer::FqName;
use crate::analyzer::IAnalyzer;
use crate::analyzer::ImportInfo;
use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;

use brokk_bifrost_core::analyzer::query_token::QueryToken;

/// The axes this producer answers. The two candidate axes
/// ([`EnvironmentAxis::CandidateSelection`] and
/// [`EnvironmentAxis::CandidateRejection`]) describe the resolver's trace, a
/// different producer, so an environment result never claims to cover them.
pub const ENVIRONMENT_PRODUCER_AXES: &[EnvironmentAxis] = &[
    EnvironmentAxis::Scopes,
    EnvironmentAxis::BindingIntervals,
    EnvironmentAxis::ImportBinders,
    EnvironmentAxis::PackageClause,
];

/// What a scope row is anchored to.
///
/// Every scope except one is a fact in the arena and therefore has an AST
/// identity. The exception is the file scope: no adapter maps its grammar's
/// root node to a normalized kind (see the ExecPlan's decision on Python's
/// `module`), and a root fact in one grammar only would give that language a
/// scope shape no other has. The file scope is therefore synthesized here,
/// uniformly, as the root of every file's scope chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeAnchor {
    /// The synthesized whole-file scope. Always scope index 0.
    File,
    Node {
        node: u32,
        kind: NormalizedKind,
    },
}

impl ScopeAnchor {
    pub const fn node(self) -> Option<u32> {
        match self {
            ScopeAnchor::File => None,
            ScopeAnchor::Node { node, .. } => Some(node),
        }
    }

    pub const fn kind(self) -> Option<NormalizedKind> {
        match self {
            ScopeAnchor::File => None,
            ScopeAnchor::Node { kind, .. } => Some(kind),
        }
    }
}

/// One lexical scope of a file.
#[derive(Debug, Clone)]
pub struct ScopeRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// Dense per-file scope index. Index 0 is always the file scope, and
    /// indices increase in pre-order, so a parent always precedes its children.
    pub index: u32,
    pub anchor: ScopeAnchor,
    pub range: Range,
    /// Index of the enclosing scope; `None` only for the file scope.
    pub parent_scope: Option<u32>,
}

impl ScopeRow {
    /// The AST identity of the anchoring fact, or `None` for the file scope,
    /// which has no arena node to be identified by.
    pub fn ast_id(&self) -> Option<String> {
        self.anchor
            .node()
            .map(|node| ast_id(self.content_identity, node))
    }

    pub fn contains(&self, position_byte: usize) -> bool {
        brokk_bifrost_core::analyzer::model::byte_range_contains(
            self.range.start_byte,
            self.range.end_byte,
            position_byte,
        )
    }
}

/// What an import contributes to the environment: one local name, its target,
/// and how ambiguous a selection through it would be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportBinderDetail {
    pub local_name: String,
    /// The parser-derived name exported by the import target. This is kept
    /// separate from `local_name` so an aliased import remains distinguishable
    /// from a same-named local binder without recovering it from source text.
    pub imported_name: Option<String>,
    pub alias: Option<String>,
    pub target_segments: Vec<String>,
    pub wildcard: bool,
    /// `None` when this language does not compute wildcard ambiguity at all.
    /// `Some(true)` means more than one wildcard import in this file could
    /// supply a simple name, so a selection through the wildcard tier here is
    /// not provably unique -- the state Java's own resolver expresses today by
    /// silently returning no answer.
    pub wildcard_ambiguous: Option<bool>,
    pub boundary: BoundaryStatus,
}

/// One name introduced into one scope.
#[derive(Debug, Clone)]
pub struct BindingRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// The binder token's arena node, which is the join key with the
    /// binder-class occurrence row over the same token. `None` for an import
    /// binder whose local name is not spelled by a classified token.
    pub node: Option<u32>,
    pub range: Range,
    pub name: String,
    pub kind: BindingKind,
    pub hoisting: HoistingClass,
    /// Index of the [`ScopeRow`] that owns this binding.
    pub declaring_scope: u32,
    /// The byte interval in which this binding is in effect.
    pub activation: Range,
    /// Ordinal of this binder among its scope's binders, in source order.
    pub source_order: u32,
    pub visibility: DeclaredVisibility,
    /// `Some` exactly when `kind == BindingKind::ImportBinder`.
    pub import: Option<ImportBinderDetail>,
}

impl BindingRow {
    pub fn ast_id(&self) -> Option<String> {
        self.node.map(|node| ast_id(self.content_identity, node))
    }

    /// The namespace this binding occupies. A type parameter binds a type
    /// name; every other binder kind binds a value name.
    pub const fn namespace(&self) -> Namespace {
        match self.kind {
            BindingKind::TypeParameter => Namespace::Type,
            _ => Namespace::Value,
        }
    }

    /// Whether a lookup in `wanted` can select this binding.
    ///
    /// For every binder the file itself writes this is namespace equality: a
    /// parameter, local, pattern binder, loop or catch variable binds a value
    /// name, and a type parameter binds a type name.
    ///
    /// An import binder is the exception, and it is not a widening: the
    /// namespace an import's local name occupies is its *target's*, and the
    /// target is a declaration in another file, which is not part of this
    /// file's environment. Testing it against [`Self::namespace`] rejected
    /// every type-position reference to an imported name -- a Java `import
    /// java.util.List` followed by `List<String> rows`, a PHP `use
    /// App\Model\Widget as Gadget` followed by `new Gadget()` (#2962) -- and
    /// answered `NoBinding`, which claims "that name is not an import" rather
    /// than "this layer does not classify import targets". A binding is only
    /// rejected here on a namespace this layer actually stated.
    pub const fn occupies(&self, wanted: Namespace) -> bool {
        match self.kind {
            BindingKind::ImportBinder => true,
            _ => matches!(
                (self.namespace(), wanted),
                (Namespace::Type, Namespace::Type)
                    | (Namespace::Value, Namespace::Value)
                    | (Namespace::Module, Namespace::Module)
                    | (Namespace::Macro, Namespace::Macro)
                    | (Namespace::Label, Namespace::Label)
                    | (Namespace::PathPrefix, Namespace::PathPrefix)
                    // A qualifier selects whatever can contain further names,
                    // which is a module or a type; this is the lookup side of
                    // `Namespace::PathPrefix` and matches how the Rust
                    // resolver already accepts a path prefix (#3064).
                    | (Namespace::Module | Namespace::Type, Namespace::PathPrefix)
            ),
        }
    }

    pub fn is_active_at(&self, position_byte: usize) -> bool {
        self.activation.start_byte <= position_byte && position_byte < self.activation.end_byte
    }
}

/// The package or module a file belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageClauseRow {
    pub file: ProjectFile,
    pub package_fq: Option<FqName>,
    /// `true` when the language spells the package in the source (Java's
    /// `package a.b;`), `false` when it is derived from the file's path
    /// (Python, Rust, JavaScript).
    pub syntactic: bool,
}

/// Why a file's environment rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentIncompleteReason {
    /// The adapter declares the axis unsupported, so absence of rows for it
    /// says nothing about the file.
    AxisUnsupported(EnvironmentAxis),
    /// No structural adapter is registered for the file's language.
    NoStructuralAdapter,
    /// The analyzer holds no structural facts for the file.
    FactsUnavailable,
    /// The file's source did not parse, so no binder token could be located in
    /// the syntax the adapter reads intervals from.
    SyntaxUnavailable,
    /// The adapter could not state an activation interval for at least one
    /// binder, so the binding set is missing rows rather than complete.
    BindingActivationUnknown,
    /// At least one import carries no parser-derived path, so its binder row
    /// names a local name whose target this layer cannot state. The row still
    /// exists; what it says about the target is nothing, not "no target".
    ImportTargetUnstructured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentCompleteness {
    Complete,
    Incomplete {
        unsupported_axes: Vec<EnvironmentAxis>,
        reasons: Vec<EnvironmentIncompleteReason>,
    },
}

impl EnvironmentCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Whether rows for `axis` can be trusted to be the complete set.
    ///
    /// Always `false` for the two candidate axes: this producer derives the
    /// environment, never the resolver's candidate trace, so it can say
    /// nothing about them.
    pub fn covers(&self, axis: EnvironmentAxis) -> bool {
        if !ENVIRONMENT_PRODUCER_AXES.contains(&axis) {
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
                        EnvironmentIncompleteReason::AxisUnsupported(unsupported) => {
                            *unsupported == axis
                        }
                        EnvironmentIncompleteReason::BindingActivationUnknown => {
                            axis == EnvironmentAxis::BindingIntervals
                        }
                        EnvironmentIncompleteReason::ImportTargetUnstructured => {
                            axis == EnvironmentAxis::ImportBinders
                        }
                        EnvironmentIncompleteReason::NoStructuralAdapter
                        | EnvironmentIncompleteReason::FactsUnavailable
                        | EnvironmentIncompleteReason::SyntaxUnavailable => true,
                    })
            }
        }
    }
}

/// One file's lexical environment.
#[derive(Debug, Clone)]
pub struct EnvironmentFileResult {
    /// Scope rows in pre-order; `scopes[0]` is always the file scope, so
    /// `scopes[index as usize]` addresses a scope by its index.
    pub scopes: Vec<ScopeRow>,
    pub bindings: Vec<BindingRow>,
    pub package: PackageClauseRow,
    pub completeness: EnvironmentCompleteness,
    /// Binding row indices grouped by binder name, in row order.
    ///
    /// The question this layer exists to answer -- which binding of *this
    /// name* is in effect here -- is asked once per occurrence, and the file's
    /// binding list is the wrong place to ask it: a 13k-line file has
    /// thousands of bindings, and a linear pass compared every one of their
    /// names against the spelling. That made the environment cost
    /// O(occurrences x bindings) in string comparisons, which is why one large
    /// file took minutes. The name is a key, so it is indexed as one; the
    /// candidate list a lookup returns is the same set the linear filter kept,
    /// in the same order.
    bindings_by_name: HashMap<Box<str>, Vec<usize>>,
    type_parameter_barriers: Vec<Range>,
}

impl EnvironmentFileResult {
    /// Build a file's environment and the name index over its bindings.
    ///
    /// The index is derived here rather than lazily so that every result has
    /// it: a caller cannot construct one without it, and no query path can
    /// fall back to the linear scan it replaces.
    pub fn new(
        scopes: Vec<ScopeRow>,
        bindings: Vec<BindingRow>,
        package: PackageClauseRow,
        completeness: EnvironmentCompleteness,
    ) -> Self {
        let mut bindings_by_name: HashMap<Box<str>, Vec<usize>> = HashMap::new();
        for (index, binding) in bindings.iter().enumerate() {
            match bindings_by_name.get_mut(binding.name.as_str()) {
                Some(rows) => rows.push(index),
                None => {
                    bindings_by_name.insert(binding.name.as_str().into(), vec![index]);
                }
            }
        }
        Self {
            scopes,
            bindings,
            package,
            completeness,
            bindings_by_name,
            type_parameter_barriers: Vec::new(),
        }
    }

    pub fn scope(&self, index: u32) -> &ScopeRow {
        &self.scopes[index as usize]
    }

    /// The binding rows whose binder spells `name`, in row order.
    ///
    /// Row order is what the shadowing sort below relies on for its final
    /// tie-break, so the index preserves it rather than grouping arbitrarily.
    pub fn bindings_named(&self, name: &str) -> &[usize] {
        self.bindings_by_name
            .get(name)
            .map_or(&[][..], Vec::as_slice)
    }

    /// The innermost scope containing `position_byte`.
    ///
    /// Scopes are pre-order and properly nested, so the last scope in row
    /// order that contains the position is the innermost one.
    pub fn innermost_scope(&self, position_byte: usize) -> Option<u32> {
        self.scopes
            .iter()
            .filter(|scope| scope.contains(position_byte))
            .map(|scope| scope.index)
            .next_back()
    }

    /// `scope` and every enclosing scope, innermost first.
    pub fn scope_ancestry(&self, scope: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut current = Some(scope);
        while let Some(index) = current {
            chain.push(index);
            current = self.scope(index).parent_scope;
        }
        chain
    }
}

/// Which binding of a name is in effect at a position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingOfOutcome {
    /// Exactly one binding of the name is in effect. The payload indexes
    /// [`EnvironmentFileResult::bindings`].
    Reached(usize),
    /// More than one binding of the name is in effect; `winner` is the one the
    /// language's scoping rules select and `shadowed` are the losers, nearest
    /// first.
    Shadowed { winner: usize, shadowed: Vec<usize> },
    /// No binding of that name is in effect here. This is a complete answer:
    /// the name resolves to something other than a lexical binding.
    NoBinding,
    /// The environment cannot answer, because this axis is not covered for
    /// this file.
    Incomplete(EnvironmentAxis),
}

/// One file's lexical environment, derived from its structural facts plus the
/// adapter's binding-activation hook.
pub fn environment_for_file(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> EnvironmentFileResult {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let language = language_for_file(file);
    let Some(spec) = structural_spec_for(language) else {
        return unavailable(file, EnvironmentIncompleteReason::NoStructuralAdapter);
    };
    let facts = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .and_then(|provider| provider.structural_facts(file));
    let Some(facts) = facts else {
        return unavailable(file, EnvironmentIncompleteReason::FactsUnavailable);
    };

    let support = spec.lexical_environment_support();
    let mut reasons: Vec<EnvironmentIncompleteReason> = ENVIRONMENT_PRODUCER_AXES
        .iter()
        .copied()
        .filter(|axis| !support.is_supported(*axis))
        .map(EnvironmentIncompleteReason::AxisUnsupported)
        .collect();

    let scopes = if support.is_supported(EnvironmentAxis::Scopes) {
        scope_rows(spec, file, &facts)
    } else {
        Vec::new()
    };

    let mut bindings = Vec::new();
    let mut type_parameter_barriers = Vec::new();
    if support.is_supported(EnvironmentAxis::BindingIntervals) && !scopes.is_empty() {
        match parse_tree_for_language(file, language, facts.source()) {
            Some(tree) => {
                let (rows, barriers) =
                    binding_rows(spec, file, &facts, &scopes, tree.root_node(), &mut reasons);
                bindings.extend(rows);
                type_parameter_barriers = barriers;
            }
            None => reasons.push(EnvironmentIncompleteReason::SyntaxUnavailable),
        }
    }
    if support.is_supported(EnvironmentAxis::ImportBinders) && !scopes.is_empty() {
        bindings.extend(import_binder_rows(
            spec,
            analyzer,
            token,
            file,
            &facts,
            &scopes,
            &mut reasons,
        ));
    }
    assign_source_order(&mut bindings);

    let package = package_clause(analyzer, file, language);
    let completeness = completeness(support, reasons);
    let mut environment = EnvironmentFileResult::new(scopes, bindings, package, completeness);
    environment.type_parameter_barriers = type_parameter_barriers;
    environment
}

fn unavailable(file: &ProjectFile, reason: EnvironmentIncompleteReason) -> EnvironmentFileResult {
    EnvironmentFileResult::new(
        Vec::new(),
        Vec::new(),
        PackageClauseRow {
            file: file.clone(),
            package_fq: None,
            syntactic: false,
        },
        EnvironmentCompleteness::Incomplete {
            unsupported_axes: ENVIRONMENT_PRODUCER_AXES.to_vec(),
            reasons: vec![reason],
        },
    )
}

fn completeness(
    support: &LexicalEnvironmentSupport,
    mut reasons: Vec<EnvironmentIncompleteReason>,
) -> EnvironmentCompleteness {
    if reasons.is_empty() {
        return EnvironmentCompleteness::Complete;
    }
    reasons.dedup();
    let unsupported_axes = ENVIRONMENT_PRODUCER_AXES
        .iter()
        .copied()
        .filter(|axis| !support.is_supported(*axis))
        .collect();
    EnvironmentCompleteness::Incomplete {
        unsupported_axes,
        reasons,
    }
}

/// The scope tree of a file: the synthesized file scope, then every
/// scope-forming fact in arena pre-order.
///
/// Which kinds form a scope is the adapter's answer
/// ([`StructuralSpec::scope_formation`]), not this layer's: Ruby's `while`,
/// `for` and `rescue` do not open variable scopes where Java's equivalents do.
/// Python likewise keeps ordinary loop assignments in their enclosing scope.
fn scope_rows(spec: &dyn StructuralSpec, file: &ProjectFile, facts: &FileFacts) -> Vec<ScopeRow> {
    let content_identity = facts.source_identity();
    let source = facts.source();
    let mut rows = vec![ScopeRow {
        file: file.clone(),
        content_identity,
        index: 0,
        anchor: ScopeAnchor::File,
        range: Range {
            start_byte: 0,
            end_byte: source.len(),
            start_line: 1,
            end_line: source.lines().count().max(1),
        },
        parent_scope: None,
    }];
    // Arena node -> scope index, for the nodes that are scopes. Facts are
    // pre-order, so an ancestor's row already exists when its child is read.
    let mut scope_of_node: Vec<Option<u32>> = vec![None; facts.nodes().len()];
    for node in 0..facts.nodes().len() {
        let node = u32::try_from(node).expect("facts arena node count fits in u32");
        let normalized = facts.node(node);
        if !spec.scope_formation(normalized.kind).opens_scope() {
            continue;
        }
        let index = u32::try_from(rows.len()).expect("scope count fits in u32");
        scope_of_node[node as usize] = Some(index);
        rows.push(ScopeRow {
            file: file.clone(),
            content_identity,
            index,
            anchor: ScopeAnchor::Node {
                node,
                kind: normalized.kind,
            },
            range: normalized.range,
            parent_scope: Some(enclosing_scope(facts, &scope_of_node, node)),
        });
    }
    rows
}

/// The index of the nearest scope strictly enclosing `node`, defaulting to the
/// file scope. The walk is the arena's parent chain, never a range comparison.
fn enclosing_scope(facts: &FileFacts, scope_of_node: &[Option<u32>], node: u32) -> u32 {
    let mut current = facts.node(node).parent;
    while let Some(ancestor) = current {
        if let Some(scope) = scope_of_node[ancestor as usize] {
            return scope;
        }
        current = facts.node(ancestor).parent;
    }
    0
}

/// Every binder token of the file, turned into a binding with an interval.
fn binding_rows(
    spec: &dyn StructuralSpec,
    file: &ProjectFile,
    facts: &FileFacts,
    scopes: &[ScopeRow],
    root: tree_sitter::Node<'_>,
    reasons: &mut Vec<EnvironmentIncompleteReason>,
) -> (Vec<BindingRow>, Vec<Range>) {
    let content_identity = facts.source_identity();
    let source = facts.source();
    let mut scope_of_node: Vec<Option<u32>> = vec![None; facts.nodes().len()];
    for scope in scopes {
        if let Some(node) = scope.anchor.node() {
            scope_of_node[node as usize] = Some(scope.index);
        }
    }

    // Correspondence lives only for this prepared file/query. No language walks
    // syntax ancestors independently of the parent-linked scope rows.
    let scope_syntax: Vec<_> = scopes
        .iter()
        .map(|scope| match scope.anchor {
            ScopeAnchor::File => Some(BindingScopeCandidate::File { root }),
            ScopeAnchor::Node { .. } => root
                .descendant_for_byte_range(scope.range.start_byte, scope.range.end_byte)
                .map(BindingScopeCandidate::Syntax),
        })
        .collect();
    // One file/query correspondence, dropped with the derived rows. Implicit
    // binders keep the same token identity as the existing occurrence arena.
    let mut binder_nodes_by_range = HashMap::new();
    let make_row = |node, declaring_scope, activation: super::resolution::BindingActivation| {
        let normalized = facts.node(node);
        let raw = &source[normalized.range.start_byte..normalized.range.end_byte];
        let name = spec.decode_spelling(raw).unwrap_or_else(|| raw.to_owned());
        BindingRow {
            file: file.clone(),
            content_identity,
            node: Some(node),
            range: normalized.range,
            name,
            kind: activation.kind,
            hoisting: activation.hoisting,
            declaring_scope,
            activation: activation.activation,
            source_order: 0,
            visibility: DeclaredVisibility::Unknown,
            import: None,
        }
    };
    // Index only binding candidates. The syntax walk below also collects
    // barriers, including owners such as static fields that have no scope row.
    let mut candidates_by_syntax: HashMap<_, Vec<_>> = HashMap::new();
    for (index, normalized) in facts.nodes().iter().enumerate() {
        let node = u32::try_from(index).expect("facts arena node count fits in u32");
        let roles = facts.occurrence_roles(node);
        if roles.contains(&OccurrenceRole::Binder)
            || roles.contains(&OccurrenceRole::DeclarationName)
        {
            let range = (normalized.range.start_byte, normalized.range.end_byte);
            binder_nodes_by_range.insert(range, node);
            // Preserve the fact-to-syntax join for contextual wrappers and
            // explicit subspans instead of assuming exact range equality.
            let Some(binder) = root.named_descendant_for_byte_range(range.0, range.1) else {
                super::note_once(reasons, EnvironmentIncompleteReason::SyntaxUnavailable);
                continue;
            };
            candidates_by_syntax
                .entry(binder.id())
                .or_default()
                .push(node);
        }
    }
    let mut rows = Vec::new();
    let mut barriers = Vec::new();
    let mut pending = vec![root];
    while let Some(syntax) = pending.pop() {
        let mut cursor = syntax.walk();
        pending.extend(syntax.named_children(&mut cursor));
        if spec.type_parameter_scope_barrier(syntax) {
            barriers.push(Range {
                start_byte: syntax.start_byte(),
                end_byte: syntax.end_byte(),
                start_line: syntax.start_position().row + 1,
                end_line: syntax.end_position().row + 1,
            });
        }
        let Some(candidates) = candidates_by_syntax.remove(&syntax.id()) else {
            continue;
        };
        for node in candidates {
            let roles = facts.occurrence_roles(node);
            let is_binder = roles.contains(&OccurrenceRole::Binder);
            let binder = syntax;
            let type_owner = spec.type_parameter_owner(binder);
            let mut candidate_index = enclosing_scope(facts, &scope_of_node, node);
            let declaring_scope = loop {
                let Some(candidate) = scope_syntax[candidate_index as usize] else {
                    break None;
                };
                let selection = if let Some(owner) = type_owner {
                    if scopes[candidate_index as usize].range.start_byte == owner.start_byte()
                        && scopes[candidate_index as usize].range.end_byte == owner.end_byte()
                    {
                        BindingScopeSelection::Use
                    } else {
                        BindingScopeSelection::Continue
                    }
                } else {
                    spec.binding_scope_selection(binder, candidate)
                };
                match selection {
                    BindingScopeSelection::Use => break Some(candidate_index),
                    BindingScopeSelection::Continue => {
                        let Some(parent) = scopes[candidate_index as usize].parent_scope else {
                            break None;
                        };
                        debug_assert!(parent < candidate_index, "scope parents precede children");
                        candidate_index = parent;
                    }
                    BindingScopeSelection::Unknown => break None,
                }
            };
            let Some(declaring_scope) = declaring_scope else {
                super::note_once(
                    reasons,
                    EnvironmentIncompleteReason::BindingActivationUnknown,
                );
                continue;
            };
            if type_owner.is_none()
                && scopes[declaring_scope as usize]
                    .anchor
                    .kind()
                    .is_some_and(|kind| spec.scope_formation(kind) == ScopeFormation::MemberScope)
            {
                continue;
            }
            let activation = if type_owner.is_some() {
                Some(super::resolution::BindingActivation {
                    kind: BindingKind::TypeParameter,
                    hoisting: HoistingClass::ScopeWide,
                    activation: scopes[declaring_scope as usize].range,
                })
            } else if is_binder {
                spec.binding_activation(binder, scopes[declaring_scope as usize].range)
            } else {
                spec.declaration_binding_activation(binder, scopes[declaring_scope as usize].range)
            };
            let Some(activation) = activation else {
                if is_binder {
                    super::note_once(
                        reasons,
                        EnvironmentIncompleteReason::BindingActivationUnknown,
                    );
                }
                continue;
            };
            rows.push(make_row(node, declaring_scope, activation));
        }
    }
    debug_assert!(
        candidates_by_syntax.is_empty(),
        "all selected named nodes were visited"
    );
    // Keep fact order, including ties, before appending implicit binders.
    rows.sort_by_key(|row| row.node);
    for (scope, syntax) in scopes.iter().zip(scope_syntax) {
        let Some(BindingScopeCandidate::Syntax(scope_node)) = syntax else {
            continue;
        };
        // Member scopes stay excluded. A language supplies implicit binders
        // for their executable owner rather than reopening member names.
        if scope
            .anchor
            .kind()
            .is_some_and(|kind| spec.scope_formation(kind) == ScopeFormation::MemberScope)
        {
            continue;
        }
        let Some(binders) = spec.implicit_scope_binders(scope_node) else {
            super::note_once(
                reasons,
                EnvironmentIncompleteReason::BindingActivationUnknown,
            );
            continue;
        };
        for binder in binders {
            let Some(&node) =
                binder_nodes_by_range.get(&(binder.name.start_byte(), binder.name.end_byte()))
            else {
                super::note_once(reasons, EnvironmentIncompleteReason::SyntaxUnavailable);
                continue;
            };
            let Some(activation) = spec.binding_activation(binder.name, scope.range) else {
                super::note_once(
                    reasons,
                    EnvironmentIncompleteReason::BindingActivationUnknown,
                );
                continue;
            };
            rows.push(make_row(node, scope.index, activation));
        }
    }
    (rows, barriers)
}

/// The local names this file's imports introduce.
///
/// Import binders never overlap with binder-token rows: an adapter classifies
/// an import's tokens as `ImportTarget`/`ImportAlias`, never as `Binder`, so
/// the two row sources are disjoint by construction.
fn import_binder_rows(
    spec: &dyn StructuralSpec,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    facts: &FileFacts,
    scopes: &[ScopeRow],
    reasons: &mut Vec<EnvironmentIncompleteReason>,
) -> Vec<BindingRow> {
    let Some(provider) = analyzer.import_analysis_provider_for_file(file) else {
        return Vec::new();
    };
    let imports = provider.import_info_of(token, file);
    let wildcard_count = imports.iter().filter(|import| import.is_wildcard).count();
    let content_identity = facts.source_identity();

    let mut rows = Vec::new();
    for import in &imports {
        let Some(local_name) = import_local_name(import) else {
            continue;
        };
        if import.path.is_none() {
            super::note_once(
                reasons,
                EnvironmentIncompleteReason::ImportTargetUnstructured,
            );
        }
        let declaration_start = import
            .path
            .as_ref()
            .map_or(0, |path| path.declaration_start_byte);
        let declaring_scope = import_scope(import, scopes);
        let scope = &scopes[declaring_scope as usize];
        let declaration = import_declaration_fact(facts, declaration_start);
        let node = declaration.and_then(|declaration| {
            import_binder_node(facts, declaration, local_name, import.binder_span)
        });
        // Tokenless binders (notably wildcard imports) are anchored to
        // their declaration, so source ordering never uses the scope start.
        let range = node
            .or(declaration)
            .map_or(scope.range, |node| facts.node(node).range);
        // Which bytes the imported name is in effect over is the adapter's
        // answer, not this layer's: a Scala block-local import starts at the
        // import statement where every other language's import is in effect
        // over its whole scope. An import whose declaration is not a fact of
        // this file has no position to activate from, so it keeps the
        // scope-wide interval rather than a guessed one.
        let activation = declaration.map_or_else(
            || ImportActivation::scope_wide(scope.range),
            |declaration| {
                spec.import_binder_activation(
                    facts.node(declaration).range,
                    scope.range,
                    scope.anchor.kind(),
                )
            },
        );
        rows.push(BindingRow {
            file: file.clone(),
            content_identity,
            node,
            range,
            name: local_name.to_owned(),
            kind: BindingKind::ImportBinder,
            hoisting: activation.hoisting,
            declaring_scope,
            activation: activation.activation,
            source_order: 0,
            visibility: DeclaredVisibility::Unknown,
            import: Some(ImportBinderDetail {
                local_name: local_name.to_owned(),
                imported_name: if import.is_wildcard {
                    None
                } else {
                    import.identifier.clone()
                },
                alias: import.alias.clone(),
                target_segments: import
                    .path
                    .as_ref()
                    .map(|path| path.segments.clone())
                    .unwrap_or_default(),
                wildcard: import.is_wildcard,
                wildcard_ambiguous: wildcard_ambiguity(spec.language(), import, wildcard_count),
                boundary: BoundaryStatus::ExternalUnknown,
            }),
        });
    }
    rows
}

/// The name a wildcard import row carries instead of a local name.
///
/// A wildcard introduces an unspecified set of names, so there is no single
/// name it binds. The row still exists, because its target and its ambiguity
/// are evidence the resolution trace needs, but it never matches a name:
/// [`binding_of`] skips wildcard rows rather than letting this marker
/// behave like an identifier.
pub const WILDCARD_IMPORT_NAME: &str = "*";

/// The local name an import introduces, or the wildcard marker.
fn import_local_name(import: &ImportInfo) -> Option<&str> {
    if import.is_wildcard {
        Some(WILDCARD_IMPORT_NAME)
    } else {
        import.local_name()
    }
}

/// Whether a selection through this wildcard import is provably unique.
///
/// Only Java computes this today, and only from what the file itself states:
/// two wildcard imports can both supply a simple name, which is exactly the
/// collision `JavaImportResolver::resolve_external_imports` answers by
/// returning nothing at all. Every other language reports `None` -- not
/// computed -- rather than a default that reads as "unambiguous".
fn wildcard_ambiguity(
    language: Language,
    import: &ImportInfo,
    wildcard_count: usize,
) -> Option<bool> {
    if language != Language::Java || !import.is_wildcard {
        return None;
    }
    Some(wildcard_count > 1)
}

/// The scope an import is written in: the innermost scope row whose range
/// contains the import declaration, or the file scope.
///
/// The declaration's start byte is the structural anchor here. The parser also
/// records `StructuredImportPath::lexical_scopes` as byte ranges, but those are
/// a second opinion about the same containment, and matching one range set
/// against the other would pick a scope by range coincidence rather than by
/// asking which scope actually contains the declaration. Scope rows are built
/// from the pre-order facts arena, so the last row containing a position is the
/// innermost one.
fn import_scope(import: &ImportInfo, scopes: &[ScopeRow]) -> u32 {
    let Some(declaration_start) = import.path.as_ref().map(|path| path.declaration_start_byte)
    else {
        return 0;
    };
    scopes
        .iter()
        .rev()
        .find(|scope| scope.contains(declaration_start))
        .map_or(0, |scope| scope.index)
}

/// The arena node of the import declaration that starts at
/// `declaration_start`, which is both the subtree a binder token is looked for
/// inside and the interval the adapter states an activation from.
///
/// `None` when the declaration is not a fact of this file, which is the case
/// for an import whose parser recorded no structured path: the row then has no
/// start byte to be found by.
fn import_declaration_fact(facts: &FileFacts, declaration_start: usize) -> Option<u32> {
    (0..facts.nodes().len())
        .map(|node| u32::try_from(node).expect("facts arena node count fits in u32"))
        .find(|&node| {
            let normalized = facts.node(node);
            normalized.kind == NormalizedKind::Import
                && normalized.range.start_byte == declaration_start
        })
}

/// The arena node of the token that spells an import's local name, so an
/// import binding carries the same AST identity as any other row over that
/// token. `None` when the import's local name is not spelled by a classified
/// token (a wildcard has no local name token, and a desugared tail may sit
/// inside a compound path node).
///
/// The candidate set is structural: only tokens inside the `import`
/// declaration's arena subtree that carry an import role are considered. When
/// the adapter recorded the binder token's byte span on `ImportInfo` (#1600),
/// the binder is the candidate at exactly that span -- a purely structural
/// join. Only when the adapter recorded no span does choosing fall back to a
/// spelling comparison: a statement that introduces several names (`from pkg
/// import alpha, beta`) yields several `ImportInfo` rows sharing one
/// declaration start, and the name is then all that tells them apart. The
/// fallback never leaves the declaration it is about.
fn import_binder_node(
    facts: &FileFacts,
    import: u32,
    local_name: &str,
    binder_span: Option<Span>,
) -> Option<u32> {
    let source = facts.source();
    (import + 1..facts.subtree_end(import)).find(|&node| {
        let roles = facts.occurrence_roles(node);
        let alias_or_target = roles.contains(&OccurrenceRole::ImportAlias)
            || roles.contains(&OccurrenceRole::ImportTarget);
        if !alias_or_target {
            return false;
        }
        let normalized = facts.node(node);
        match binder_span {
            Some(span) => {
                normalized.range.start_byte == span.start_byte
                    && normalized.range.end_byte == span.end_byte
            }
            None => &source[normalized.range.start_byte..normalized.range.end_byte] == local_name,
        }
    })
}

/// Number each scope's binders in source order, so a consumer can tell a
/// re-binding of the same name from its predecessor without re-deriving order.
fn assign_source_order(bindings: &mut [BindingRow]) {
    let mut order: Vec<usize> = (0..bindings.len()).collect();
    order.sort_by_key(|&index| {
        (
            bindings[index].declaring_scope,
            bindings[index].range.start_byte,
        )
    });
    let mut scope = None;
    let mut ordinal = 0u32;
    for index in order {
        if scope != Some(bindings[index].declaring_scope) {
            scope = Some(bindings[index].declaring_scope);
            ordinal = 0;
        }
        bindings[index].source_order = ordinal;
        ordinal += 1;
    }
}

/// The package a file belongs to, and whether the language spells it.
/// The package or module clause of one file.
///
/// Exposed on its own because the file row carries the package as fields
/// (#1474) and a file row must not pay for a whole environment derivation --
/// this reads indexed declarations and never re-parses.
pub fn package_clause_for_file(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> PackageClauseRow {
    package_clause(analyzer, file, language_for_file(file))
}

fn package_clause(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: Language,
) -> PackageClauseRow {
    let package_fq = analyzer
        .get_top_level_declarations(file)
        .iter()
        .find_map(package_prefix);
    PackageClauseRow {
        file: file.clone(),
        package_fq,
        syntactic: language_spells_its_package(language),
    }
}

/// The package prefix of a declaration's qualified name, taken as segments
/// rather than by splitting a rendered string: the unit already records how
/// many of its leading segments are the package.
fn package_prefix(unit: &CodeUnit) -> Option<FqName> {
    let mut fq = unit.fq().clone();
    while fq.len() > unit.package_segment_count() {
        fq = fq.parent()?;
    }
    (!fq.is_empty()).then_some(fq)
}

/// Whether the language writes its package or module membership in the source
/// (as opposed to deriving it from the file's path).
fn language_spells_its_package(language: Language) -> bool {
    match language {
        // PHP's package is its `namespace` statement and nothing else: each
        // declaration takes the namespace in force where it is written, and a
        // file with no namespace at all answers empty, so a PHP package is
        // spelled wherever it exists at all (#2962). `package_clause` above
        // reads it off the first top-level declaration rather than off the
        // file-level qualifier, which is exactly the answer a file holding
        // more than one namespace needs (#3104).
        Language::Java
        | Language::Kotlin
        | Language::Scala
        | Language::Go
        | Language::CSharp
        | Language::Php => true,
        Language::Python
        | Language::JavaScript
        | Language::TypeScript
        | Language::Rust
        | Language::Cpp
        | Language::Ruby
        | Language::None => false,
    }
}

/// Which binding of `name` is in effect at `position_byte`.
///
/// The algorithm is the whole point of this module and is language-neutral:
///
/// 1. Refuse unless the file's scope and binding-interval axes are covered.
/// 2. Take the innermost scope containing the position and its ancestry.
/// 3. Keep the bindings that share the name, occupy the requested namespace,
///    are declared in one of those scopes, and whose activation interval
///    contains the position.
/// 4. The winner is the one declared in the nearest scope; ties inside one
///    scope go to the latest activation start, which is what makes a
///    re-binding of the same name win over its predecessor below it.
pub fn binding_of(
    env: &EnvironmentFileResult,
    name: &str,
    position_byte: usize,
    namespace: Option<Namespace>,
) -> BindingOfOutcome {
    if !env.completeness.covers(EnvironmentAxis::Scopes) {
        return BindingOfOutcome::Incomplete(EnvironmentAxis::Scopes);
    }
    if !env.completeness.covers(EnvironmentAxis::BindingIntervals) {
        return BindingOfOutcome::Incomplete(EnvironmentAxis::BindingIntervals);
    }
    let Some(innermost) = env.innermost_scope(position_byte) else {
        return BindingOfOutcome::NoBinding;
    };
    let ancestry = env.scope_ancestry(innermost);

    // Only bindings that spell this name can be in effect for it, and the
    // index knows which those are. The remaining predicates are the same ones
    // the linear pass applied, in the same order, over the same rows.
    let mut candidates: Vec<usize> = env
        .bindings_named(name)
        .iter()
        .copied()
        .filter(|index| {
            let binding = &env.bindings[*index];
            debug_assert_eq!(
                binding.name, name,
                "the binding name index must group rows by their binder spelling"
            );
            !binding
                .import
                .as_ref()
                .is_some_and(|detail| detail.wildcard)
                && namespace.is_none_or(|wanted| binding.occupies(wanted))
                && (binding.kind != BindingKind::TypeParameter
                    || !env.type_parameter_barriers.iter().any(|barrier| {
                        let owner = &env.scopes[binding.declaring_scope as usize].range;
                        barrier.start_byte <= position_byte
                            && position_byte < barrier.end_byte
                            && owner.start_byte <= barrier.start_byte
                            && barrier.end_byte <= owner.end_byte
                            && (owner.start_byte != barrier.start_byte
                                || owner.end_byte != barrier.end_byte)
                    }))
                && binding.is_active_at(position_byte)
                && ancestry.contains(&binding.declaring_scope)
        })
        .collect();
    if candidates.is_empty() {
        return BindingOfOutcome::NoBinding;
    }
    // Nearest scope first, then latest activation, then latest binder.
    candidates.sort_by_key(|&index| {
        let binding = &env.bindings[index];
        let depth = ancestry
            .iter()
            .position(|scope| *scope == binding.declaring_scope)
            .expect("candidate scopes come from the ancestry");
        (
            depth,
            std::cmp::Reverse(binding.activation.start_byte),
            std::cmp::Reverse(binding.range.start_byte),
        )
    });
    let winner = candidates[0];
    if candidates.len() == 1 {
        BindingOfOutcome::Reached(winner)
    } else {
        BindingOfOutcome::Shadowed {
            winner,
            shadowed: candidates[1..].to_vec(),
        }
    }
}

/// Resolve a reference position or a binder preceding its binding's activation.
///
/// A binder token can precede its own activation interval. Looking up its name
/// positionally would then borrow an outer binding instead of identifying the
/// declaration. Active binders retain positional ranking, including repeated
/// scope-wide assignments that reach the same winning binding.
pub fn binding_of_occurrence(
    env: &EnvironmentFileResult,
    occurrence: &OccurrenceRow,
) -> BindingOfOutcome {
    let positional = binding_of(
        env,
        occurrence.effective_spelling(),
        occurrence.range.start_byte,
        Some(occurrence.namespace),
    );
    if matches!(positional, BindingOfOutcome::Incomplete(_))
        || occurrence.role != OccurrenceRole::Binder
    {
        return positional;
    }
    let mut introduced = env
        .bindings_named(occurrence.effective_spelling())
        .iter()
        .copied()
        .filter(|index| {
            let binding = &env.bindings[*index];
            binding.content_identity == occurrence.content_identity
                && binding.node == Some(occurrence.node)
                && binding.occupies(occurrence.namespace)
        });
    if let Some(index) = introduced.next() {
        // binding_rows emits one row per facts node; import binder tokens do
        // not overlap those rows.
        assert!(
            introduced.next().is_none(),
            "one binder token introduces one binding"
        );
        if occurrence.range.start_byte < env.bindings[index].activation.start_byte {
            return BindingOfOutcome::Reached(index);
        }
    }
    positional
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn parsed_environment(source: &str) -> EnvironmentFileResult {
        let spec = &brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;
        let grammar = tree_sitter_python::LANGUAGE.into();
        let facts = super::super::extract::extract_file_facts(spec, &grammar, source).unwrap();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&grammar).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path(), "example.py");
        let mut analyzer = super::super::identity_routes::tests::MetadataAnalyzer::new(temp.path());
        let mut cursor = tree.root_node().walk();
        for node in tree.root_node().named_children(&mut cursor) {
            analyzer
                .imports
                .extend(brokk_bifrost_python::imports::python_import_infos_from_node(node, source));
        }
        let scopes = scope_rows(spec, &file, &facts);
        let mut reasons = vec![];
        let (mut bindings, _) =
            binding_rows(spec, &file, &facts, &scopes, tree.root_node(), &mut reasons);
        let query = AnalyzerQueryScope::new(&analyzer);
        bindings.extend(import_binder_rows(
            spec,
            &analyzer,
            query.token(),
            &file,
            &facts,
            &scopes,
            &mut reasons,
        ));
        assign_source_order(&mut bindings);
        EnvironmentFileResult::new(
            scopes,
            bindings,
            PackageClauseRow {
                file,
                package_fq: None,
                syntactic: false,
            },
            completeness(spec.lexical_environment_support(), reasons),
        )
    }

    #[test]
    #[hardwon(
        "dce884c96143: quicksilver round 12 on brokk-bifrost-analysis: wildcard imports sort before earlier locals"
    )]
    fn import_binders_follow_declaration_source_order() {
        for comment in ["# comment\n", "# caf\u{e9}\n"] {
            let source = format!(
                "{comment}before = 1\nfrom pkg import *\nmiddle = 2\nimport named\nfrom other import *\nafter = 3\n"
            );
            let environment = parsed_environment(&source);
            let mut bindings = environment.bindings.iter().collect::<Vec<_>>();
            bindings.sort_by_key(|binding| binding.source_order);
            assert_eq!(
                bindings
                    .iter()
                    .map(|binding| binding.name.as_str())
                    .collect::<Vec<_>>(),
                ["before", "*", "middle", "named", "*", "after"]
            );
        }
    }

    #[test]
    fn lexical_intervals_match_grammar_byte_boundaries() {
        for source in [
            "",
            "# caf\u{e9}\ndef first(x):\n    return x\ndef second(y):\n    return y\n",
        ] {
            let environment = parsed_environment(source);
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            for scope in &environment.scopes {
                let expected = if matches!(scope.anchor, ScopeAnchor::File) {
                    0..source.len()
                } else {
                    let node = tree
                        .root_node()
                        .named_descendant_for_byte_range(
                            scope.range.start_byte,
                            scope.range.end_byte,
                        )
                        .unwrap();
                    node.byte_range()
                };
                for position in 0..=source.len() {
                    assert_eq!(scope.contains(position), expected.contains(&position));
                }
            }
            for binding in &environment.bindings {
                // Python parameters remain active through their function's body,
                // whose end is the exact grammar scope boundary.
                let scope = &environment.scopes[binding.declaring_scope as usize];
                assert_eq!(binding.activation.end_byte, scope.range.end_byte);
                assert!(!binding.is_active_at(scope.range.end_byte));
                if binding.activation.start_byte < scope.range.end_byte {
                    assert!(binding.is_active_at(scope.range.end_byte - 1));
                }
            }
        }
    }
    #[test]
    fn active_binder_ranking_is_invariant_under_leading_comment() {
        use super::super::occurrence_rows::{OccurrenceRow, OccurrenceTarget};
        use super::super::occurrences::OccurrenceClass;
        for prefix in ["", "# comment\n"] {
            let source = format!("{prefix}x = 1\nx = 2\n");
            let env = parsed_environment(&source);
            let binders: Vec<_> = env
                .bindings
                .iter()
                .filter(|binding| binding.name == "x")
                .collect();
            assert_eq!(binders.len(), 2);
            for binding in binders {
                let occurrence = OccurrenceRow {
                    file: binding.file.clone(),
                    content_identity: binding.content_identity,
                    node: binding.node.unwrap(),
                    range: binding.range,
                    role: OccurrenceRole::Binder,
                    class: OccurrenceClass::Binding,
                    namespace: Namespace::Value,
                    enclosing: None,
                    raw_spelling: "x".into(),
                    decoded_spelling: None,
                    resolution_status: None,
                    target: OccurrenceTarget::None,
                    candidates: None,
                };
                let positional =
                    binding_of(&env, "x", binding.range.start_byte, Some(Namespace::Value));
                let outcome = binding_of_occurrence(&env, &occurrence);
                assert_eq!(outcome, positional);
                let BindingOfOutcome::Shadowed { winner, shadowed } = outcome else {
                    panic!("scope-wide assignments share ranking")
                };
                assert_eq!(env.bindings[winner].range.start_byte, prefix.len() + 6);
                assert_eq!(shadowed.len(), 1);
            }
        }
    }
}
