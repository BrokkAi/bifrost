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

use super::facts::{FileFacts, Span};
use super::kinds::NormalizedKind;
use super::occurrence_rows::{OccurrenceRow, ast_id};
use super::occurrences::{Namespace, OccurrenceRole};
use super::resolution::{
    BindingKind, BindingScopeCandidate, BindingScopeSelection, BoundaryStatus, DeclaredVisibility,
    EnvironmentAxis, HoistingClass, ImportActivation, LexicalEnvironmentSupport, ScopeFormation,
};
use super::spec::StructuralSpec;
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::structural_spec_for;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{CodeUnit, FqName, IAnalyzer, ImportInfo, Language, ProjectFile, Range};
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
    if support.is_supported(EnvironmentAxis::BindingIntervals) && !scopes.is_empty() {
        match parse_tree_for_language(file, language, facts.source()) {
            Some(tree) => bindings.extend(binding_rows(
                spec,
                file,
                &facts,
                &scopes,
                tree.root_node(),
                &mut reasons,
            )),
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
    EnvironmentFileResult::new(scopes, bindings, package, completeness)
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
) -> Vec<BindingRow> {
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
    let mut rows = Vec::new();
    for node in 0..facts.nodes().len() {
        let node = u32::try_from(node).expect("facts arena node count fits in u32");
        let roles = facts.occurrence_roles(node);
        let is_binder = roles.contains(&OccurrenceRole::Binder);
        let is_declaration_name = roles.contains(&OccurrenceRole::DeclarationName);
        if !is_binder && !is_declaration_name {
            continue;
        }
        let normalized = facts.node(node);
        let Some(binder) =
            root.descendant_for_byte_range(normalized.range.start_byte, normalized.range.end_byte)
        else {
            super::note_once(reasons, EnvironmentIncompleteReason::SyntaxUnavailable);
            continue;
        };
        let mut candidate_index = enclosing_scope(facts, &scope_of_node, node);
        let declaring_scope = loop {
            let Some(candidate) = scope_syntax[candidate_index as usize] else {
                break None;
            };
            match spec.binding_scope_selection(binder, candidate) {
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
        // Member-space owners still declare members rather than lexical names.
        if scopes[declaring_scope as usize]
            .anchor
            .kind()
            .is_some_and(|kind| spec.scope_formation(kind) == ScopeFormation::MemberScope)
        {
            continue;
        }
        let activation = if is_binder {
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
        let raw = &source[normalized.range.start_byte..normalized.range.end_byte];
        let name = spec.decode_spelling(raw).unwrap_or_else(|| raw.to_owned());
        rows.push(BindingRow {
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
        });
    }
    rows
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
        let range = node.map_or(scope.range, |node| facts.node(node).range);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::AnalyzerFixture;

    struct Fixture {
        analyzer: AnalyzerFixture,
        file: ProjectFile,
        source: String,
    }

    impl Fixture {
        fn new(language: Language, relative_path: &str, source: &str) -> Self {
            let analyzer = AnalyzerFixture::new_for_language(language, &[(relative_path, source)]);
            let file = ProjectFile::new(analyzer.project_root(), relative_path);
            Self {
                analyzer,
                file,
                source: source.to_owned(),
            }
        }

        fn environment(&self) -> EnvironmentFileResult {
            environment_for_file(self.analyzer.analyzer().analyzer(), &self.file)
        }

        /// Byte offset of `needle`; the marker keeps a position assertion
        /// readable without re-scanning the fixture.
        fn at(&self, needle: &str) -> usize {
            crate::test_support::fixture_marker(&self.source, needle)
        }
    }

    fn binding<'env>(env: &'env EnvironmentFileResult, name: &str) -> &'env BindingRow {
        let mut matches = env.bindings.iter().filter(|row| row.name == name);
        let found = matches
            .next()
            .unwrap_or_else(|| panic!("no binding named {name:?}; bindings: {:?}", env.bindings));
        assert!(
            matches.next().is_none(),
            "more than one binding named {name:?}; bindings: {:?}",
            env.bindings
        );
        found
    }

    /// The single binding in effect at `position`, failing with the whole
    /// environment when the answer is anything else.
    fn reached<'env>(
        env: &'env EnvironmentFileResult,
        name: &str,
        position: usize,
    ) -> &'env BindingRow {
        match binding_of(env, name, position, None) {
            BindingOfOutcome::Reached(index) => &env.bindings[index],
            BindingOfOutcome::Shadowed { winner, .. } => &env.bindings[winner],
            other => panic!(
                "expected {name:?} to reach a binding at byte {position}, got {other:?}; \
                 bindings: {:?}",
                env.bindings
            ),
        }
    }

    #[test]
    fn js_var_read_before_its_declaration_reaches_the_hoisted_binding() {
        let source = concat!(
            "function render() {\n",
            "    const before = value;\n",
            "    var value = 2;\n",
            "    return before + value;\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::JavaScript, "src/app.js", source);
        let env = fixture.environment();

        let value = binding(&env, "value");
        assert_eq!(value.hoisting, HoistingClass::ScopeWide);
        assert_eq!(
            reached(&env, "value", fixture.at("value;\n    var")).node,
            value.node
        );
    }

    #[test]
    fn python_function_local_assigned_in_a_block_reaches_after_the_block() {
        let source = concat!(
            "def render(choose):\n",
            "    if choose:\n",
            "        value = 1\n",
            "    return value\n",
        );
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let env = fixture.environment();

        let value = binding(&env, "value");
        assert_eq!(value.kind, BindingKind::Local);
        assert_eq!(
            env.scope(value.declaring_scope).anchor.kind(),
            Some(NormalizedKind::Function),
            "Python's if block does not open a lexical scope"
        );
        assert_eq!(
            reached(&env, "value", fixture.at("return value") + "return ".len()).node,
            value.node
        );
    }

    #[test]
    fn python_module_root_keeps_top_level_imports_in_file_scope() {
        let fixture = Fixture::new(
            Language::Python,
            "src/app.py",
            "import json\nvalue = json\n",
        );
        let env = fixture.environment();

        assert_eq!(env.scopes.len(), 1, "scopes: {:?}", env.scopes);
        let json = binding(&env, "json");
        assert_eq!(json.declaring_scope, 0);
        assert_eq!(env.scope(json.declaring_scope).anchor, ScopeAnchor::File);
    }

    /// One import statement can introduce several names, and a rename can make
    /// two rows' spellings collide with each other's targets. The binder token
    /// is joined by the adapter-recorded span (#1600), so each row lands on
    /// its own alias token; a spelling comparison would send the first row to
    /// the second selector's *name* token, which also spells `beta`.
    #[test]
    fn python_swapped_import_aliases_keep_their_own_binder_tokens() {
        let source = "from pkg import alpha as beta, beta as alpha\n";
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let env = fixture.environment();

        let beta = binding(&env, "beta");
        let alpha = binding(&env, "alpha");
        assert_eq!(beta.kind, BindingKind::ImportBinder);
        assert_eq!(alpha.kind, BindingKind::ImportBinder);
        // Both rows keep the scope-wide interval the shared default states:
        // Python does not override `import_binder_activation`, so #2925 left
        // its rows exactly as they were.
        assert_eq!(beta.hoisting, HoistingClass::ScopeWide);
        assert_eq!(alpha.hoisting, HoistingClass::ScopeWide);
        assert_eq!(beta.activation, env.scopes[0].range);
        assert_eq!(alpha.activation, env.scopes[0].range);
        assert_eq!(
            beta.range.start_byte,
            fixture.at("beta,"),
            "the row bound as beta anchors on its own alias token: {beta:?}"
        );
        assert_eq!(
            alpha.range.start_byte,
            fixture.at("as alpha") + "as ".len(),
            "the row bound as alpha anchors on its own alias token: {alpha:?}"
        );
        assert_ne!(
            beta.node, alpha.node,
            "two rows of one declaration keep distinct AST identities"
        );
    }

    /// Two wildcard imports in one file can both supply a simple name, which is
    /// exactly the collision the Java resolver answers today by returning
    /// nothing. The row keeps it explicit instead.
    #[test]
    fn java_colliding_wildcard_imports_are_reported_as_ambiguous() {
        let source = concat!(
            "package app;\n",
            "import java.util.*;\n",
            "import java.awt.*;\n",
            "class Widget {\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        let wildcards: Vec<&ImportBinderDetail> = env
            .bindings
            .iter()
            .filter_map(|row| row.import.as_ref())
            .filter(|detail| detail.wildcard)
            .collect();
        assert_eq!(
            wildcards
                .iter()
                .map(|detail| (detail.local_name.as_str(), detail.wildcard_ambiguous))
                .collect::<Vec<_>>(),
            vec![
                (WILDCARD_IMPORT_NAME, Some(true)),
                (WILDCARD_IMPORT_NAME, Some(true)),
            ],
            "bindings: {:?}",
            env.bindings
        );
        assert_eq!(
            binding_of(&env, WILDCARD_IMPORT_NAME, fixture.at("class Widget"), None),
            BindingOfOutcome::NoBinding,
            "a wildcard row is evidence, never a name that reaches"
        );
    }

    /// A Scala `import` is a statement, so one written inside a block is in
    /// effect from the import onward and not from the block's first byte. A
    /// file-level import stays scope-wide, which is what every other language
    /// reports for every import (#2925).
    #[brokk_bifrost_test_macros::hardwon(
        "317af407fd3b: Scala imports and contextual parameters need their exact lexical scope"
    )]
    #[test]
    fn a_scala_block_local_import_is_in_effect_only_below_the_import() {
        let source = concat!(
            "package app\n",
            "\n",
            "import scala.util.Try\n",
            "\n",
            "object Host {\n",
            "  def run(seed: Int): Int = {\n",
            "    val guarded = Try(seed).getOrElse(0)\n",
            "    import scala.math.max\n",
            "    max(guarded, 2)\n",
            "  }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Scala, "src/Host.scala", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let file_level = binding(&env, "Try");
        assert_eq!(file_level.kind, BindingKind::ImportBinder);
        assert_eq!(file_level.hoisting, HoistingClass::ScopeWide);
        assert_eq!(file_level.declaring_scope, 0);
        assert_eq!(file_level.activation, env.scopes[0].range);

        let block_local = binding(&env, "max");
        assert_eq!(block_local.kind, BindingKind::ImportBinder);
        assert_eq!(block_local.hoisting, HoistingClass::SourceOrder);
        let block = env.scope(block_local.declaring_scope);
        assert_eq!(
            block.anchor.kind(),
            Some(NormalizedKind::Block),
            "a block-local import is declared in the block: {block:?}"
        );
        assert_eq!(
            block_local.activation.start_byte,
            fixture.at("import scala.math.max") + "import scala.math.max".len(),
            "the import is in effect from the end of its own statement"
        );
        assert_eq!(block_local.activation.end_byte, block.range.end_byte);

        assert_eq!(
            binding_of(&env, "max", fixture.at("Try(seed)"), None),
            BindingOfOutcome::NoBinding,
            "a read above the import reaches no binding of the imported name"
        );
        assert_eq!(
            reached(&env, "max", fixture.at("max(guarded")).node,
            block_local.node,
            "a read below the import reaches it"
        );
        assert_eq!(
            reached(&env, "Try", fixture.at("Try(seed)")).node,
            file_level.node,
            "the file-level import reaches the whole file"
        );
    }

    /// A `given` and an `extension` are scopes of their own, so their
    /// parameters bind inside the definition rather than being excluded as
    /// members of the template they are written in (#2925).
    #[brokk_bifrost_test_macros::hardwon(
        "317af407fd3b: Scala imports and contextual parameters need their exact lexical scope"
    )]
    #[test]
    fn scala_given_and_extension_parameters_bind_inside_their_definition() {
        let source = concat!(
            "package app\n",
            "\n",
            "trait Ord[T]\n",
            "\n",
            "object Host {\n",
            "  given ordering(using base: Int): Ord[Int] = build(base)\n",
            "\n",
            "  extension (value: String) {\n",
            "    def twice(sep: String): String = value + sep + value\n",
            "  }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Scala, "src/Host.scala", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let template = env
            .scopes
            .iter()
            .find(|scope| scope.anchor.kind() == Some(NormalizedKind::Class))
            .unwrap_or_else(|| panic!("the object is a scope: {:?}", env.scopes));

        let base = binding(&env, "base");
        assert_eq!(base.kind, BindingKind::Parameter);
        assert_eq!(base.hoisting, HoistingClass::ScopeWide);
        let given = env.scope(base.declaring_scope);
        assert_ne!(
            given.index, template.index,
            "a given parameter is not a member of the enclosing object: {given:?}"
        );
        assert_eq!(
            &source[given.range.start_byte..given.range.end_byte],
            "given ordering(using base: Int): Ord[Int] = build(base)"
        );
        assert_eq!(base.activation, given.range);

        let value = binding(&env, "value");
        assert_eq!(value.kind, BindingKind::Parameter);
        assert_eq!(value.hoisting, HoistingClass::ScopeWide);
        let extension = env.scope(value.declaring_scope);
        assert_ne!(
            extension.index, template.index,
            "an extension parameter is not a member of the enclosing object: {extension:?}"
        );
        assert!(
            source[extension.range.start_byte..extension.range.end_byte]
                .starts_with("extension (value: String)"),
            "the extension group is the scope: {extension:?}"
        );
        assert_eq!(value.activation, extension.range);

        let sep = binding(&env, "sep");
        assert_eq!(sep.kind, BindingKind::Parameter);
        assert_eq!(
            env.scope(sep.declaring_scope).anchor.kind(),
            Some(NormalizedKind::Method),
            "the extension method scopes its own parameters"
        );

        assert_eq!(
            reached(&env, "base", fixture.at("build(base)") + "build(".len()).node,
            base.node,
            "the given parameter is reached in the given's body"
        );
        assert_eq!(
            binding_of(&env, "base", fixture.at("value + sep"), None),
            BindingOfOutcome::NoBinding,
            "and nowhere else"
        );
        assert_eq!(
            reached(&env, "value", fixture.at("value + sep")).node,
            value.node,
            "the extension parameter is reached in the extension method's body"
        );
        assert_eq!(
            binding_of(&env, "value", fixture.at("build(base)"), None),
            BindingOfOutcome::NoBinding,
            "and nowhere else"
        );
    }

    /// An unbraced `namespace N;` makes the rest of the file that namespace,
    /// so a `use` written under it binds over the file scope. PHP resolves the
    /// imported name at compile time but sequentially: a reference written
    /// above the `use` does not resolve through it, which is `SourceOrder`.
    #[test]
    fn php_use_aliases_bind_from_their_declaration_over_an_unbraced_namespace() {
        let source = concat!(
            "<?php\n",
            "\n",
            "namespace App\\Util;\n",
            "\n",
            "use App\\Model\\Widget as Gadget;\n",
            "\n",
            "function make(): Gadget {\n",
            "    return new Gadget();\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Php, "src/make.php", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let gadget = binding(&env, "Gadget");
        assert_eq!(gadget.kind, BindingKind::ImportBinder);
        assert_eq!(gadget.hoisting, HoistingClass::SourceOrder);
        assert_eq!(
            gadget.declaring_scope, 0,
            "an unbraced namespace does not open a body, so the file scope is the namespace scope"
        );
        let detail = gadget
            .import
            .as_ref()
            .expect("an import binder carries a detail");
        assert_eq!(detail.alias.as_deref(), Some("Gadget"));
        assert_eq!(detail.imported_name.as_deref(), Some("Widget"));
        assert_eq!(detail.target_segments, ["App", "Model", "Widget"]);
        assert!(!detail.wildcard, "PHP has no wildcard import");

        assert_eq!(
            reached(&env, "Gadget", fixture.at("new Gadget()")).node,
            gadget.node,
            "the alias is in effect below its declaration"
        );
        assert_eq!(
            binding_of(&env, "Gadget", fixture.at("namespace App"), None),
            BindingOfOutcome::NoBinding,
            "and not above it"
        );

        assert_eq!(
            env.package
                .package_fq
                .as_ref()
                .map(|fq| fq.display(brokk_bifrost_core::analyzer::fq_name::segment_interner())),
            Some("App.Util".to_owned())
        );
        assert!(
            env.package.syntactic,
            "PHP writes its namespace in the source"
        );
    }

    /// A braced `namespace N { ... }` is its own scope, and the `use` names it
    /// imports stop at its closing brace.
    #[test]
    fn php_use_aliases_stop_at_the_end_of_a_braced_namespace() {
        let source = concat!(
            "<?php\n",
            "\n",
            "namespace First {\n",
            "    use App\\Model\\Widget as Gadget;\n",
            "\n",
            "    function first(): Gadget {\n",
            "        return new Gadget();\n",
            "    }\n",
            "}\n",
            "\n",
            "namespace Second {\n",
            "    function second(): int {\n",
            "        return 1;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Php, "src/braced.php", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let gadget = binding(&env, "Gadget");
        assert_eq!(gadget.kind, BindingKind::ImportBinder);
        let namespace = env.scope(gadget.declaring_scope);
        assert_eq!(
            namespace.anchor.kind(),
            Some(NormalizedKind::Module),
            "a braced namespace body is the scope its imports are written in"
        );
        assert_eq!(
            gadget.activation.end_byte, namespace.range.end_byte,
            "and the alias stops where that namespace does"
        );
        assert_eq!(
            reached(&env, "Gadget", fixture.at("new Gadget()")).node,
            gadget.node
        );
        assert_eq!(
            binding_of(&env, "Gadget", fixture.at("return 1"), None),
            BindingOfOutcome::NoBinding,
            "the sibling namespace never sees it"
        );
    }
}
