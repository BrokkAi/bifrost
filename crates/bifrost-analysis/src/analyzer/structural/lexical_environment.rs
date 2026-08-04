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
//!   contributes only [`BindingActivation`] per binder token through
//!   [`StructuralSpec::binding_activation`].
//! - Identity is structural, exactly as for occurrence rows: a binding is
//!   addressed by its binder token's `(content_identity, arena node)` pair, so
//!   a capture, an occurrence and a binding over the same token join on one
//!   digest rather than on a range or a spelling.
//! - Nothing is guessed. An adapter that cannot state an interval makes the
//!   file's `BindingIntervals` axis incomplete, and
//!   [`reaching_binding`] then refuses to answer instead of returning a
//!   plausible winner.
//!
//! Rows are derived per request and never persisted; the facts snapshot
//! underneath them is the cached part.

use super::facts::FileFacts;
use super::kinds::NormalizedKind;
use super::occurrence_rows::ast_id;
use super::occurrences::{Namespace, OccurrenceRole};
use super::resolution::{
    BindingKind, BoundaryStatus, DeclaredVisibility, EnvironmentAxis, HoistingClass,
    LexicalEnvironmentSupport,
};
use super::spec::StructuralSpec;
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::structural_spec_for;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CodeUnit, FqName, IAnalyzer, ImportInfo, Language, ProjectFile, Range};

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
        self.range.start_byte <= position_byte && position_byte < self.range.end_byte
    }
}

/// What an import contributes to the environment: one local name, its target,
/// and how ambiguous a selection through it would be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportBinderDetail {
    pub local_name: String,
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
}

impl EnvironmentFileResult {
    pub fn scope(&self, index: u32) -> &ScopeRow {
        &self.scopes[index as usize]
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
pub enum ReachingBindingOutcome {
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
    let language = language_for_file(file);
    let Some(spec) = structural_spec_for(language) else {
        return unavailable(file, EnvironmentIncompleteReason::NoStructuralAdapter);
    };
    let facts = analyzer
        .structural_search_providers()
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
        scope_rows(file, &facts)
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
            analyzer,
            file,
            &facts,
            &scopes,
            language,
            &mut reasons,
        ));
    }
    assign_source_order(&mut bindings);

    let package = package_clause(analyzer, file, language);
    EnvironmentFileResult {
        scopes,
        bindings,
        package,
        completeness: completeness(support, reasons),
    }
}

fn unavailable(file: &ProjectFile, reason: EnvironmentIncompleteReason) -> EnvironmentFileResult {
    EnvironmentFileResult {
        scopes: Vec::new(),
        bindings: Vec::new(),
        package: PackageClauseRow {
            file: file.clone(),
            package_fq: None,
            syntactic: false,
        },
        completeness: EnvironmentCompleteness::Incomplete {
            unsupported_axes: ENVIRONMENT_PRODUCER_AXES.to_vec(),
            reasons: vec![reason],
        },
    }
}

/// Record a reason once. Which axis is incomplete is what matters; how many
/// rows hit the same wall is not.
fn note(reasons: &mut Vec<EnvironmentIncompleteReason>, reason: EnvironmentIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
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

/// Whether a normalized kind forms a lexical scope.
///
/// Callables scope their parameters, classes scope their members and type
/// parameters, loops scope their headers, catch clauses scope their exception
/// parameter, and `Block` -- added for exactly this purpose in Milestone 1 --
/// scopes a statement list.
fn is_scope_forming(kind: NormalizedKind) -> bool {
    kind.satisfies(NormalizedKind::Callable)
        || kind.satisfies(NormalizedKind::Class)
        || kind.satisfies(NormalizedKind::Loop)
        || matches!(kind, NormalizedKind::Block | NormalizedKind::Catch)
}

/// The scope tree of a file: the synthesized file scope, then every
/// scope-forming fact in arena pre-order.
fn scope_rows(file: &ProjectFile, facts: &FileFacts) -> Vec<ScopeRow> {
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
        if !is_scope_forming(normalized.kind) {
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

    let mut rows = Vec::new();
    for node in 0..facts.nodes().len() {
        let node = u32::try_from(node).expect("facts arena node count fits in u32");
        if !facts
            .occurrence_roles(node)
            .contains(&OccurrenceRole::Binder)
        {
            continue;
        }
        let declaring_scope = enclosing_scope(facts, &scope_of_node, node);
        // A binder whose nearest scope is a class body declares a member, not
        // a lexical binding: it resolves at the member tiers, which are the
        // resolution trace's territory rather than the environment's.
        if scopes[declaring_scope as usize]
            .anchor
            .kind()
            .is_some_and(|kind| kind.satisfies(NormalizedKind::Class))
        {
            continue;
        }
        let normalized = facts.node(node);
        let Some(binder) =
            root.descendant_for_byte_range(normalized.range.start_byte, normalized.range.end_byte)
        else {
            note(reasons, EnvironmentIncompleteReason::SyntaxUnavailable);
            continue;
        };
        let Some(activation) =
            spec.binding_activation(binder, scopes[declaring_scope as usize].range)
        else {
            note(
                reasons,
                EnvironmentIncompleteReason::BindingActivationUnknown,
            );
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
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    facts: &FileFacts,
    scopes: &[ScopeRow],
    language: Language,
    reasons: &mut Vec<EnvironmentIncompleteReason>,
) -> Vec<BindingRow> {
    let Some(provider) = analyzer.import_analysis_provider_for_file(file) else {
        return Vec::new();
    };
    let imports = provider.import_info_of(file);
    let wildcard_count = imports.iter().filter(|import| import.is_wildcard).count();
    let content_identity = facts.source_identity();

    let mut rows = Vec::new();
    for import in &imports {
        let Some(local_name) = import_local_name(import) else {
            continue;
        };
        if import.path.is_none() {
            note(
                reasons,
                EnvironmentIncompleteReason::ImportTargetUnstructured,
            );
        }
        let declaration_start = import
            .path
            .as_ref()
            .map_or(0, |path| path.declaration_start_byte);
        let declaring_scope = import_scope(import, scopes);
        let node = import_binder_node(facts, declaration_start, local_name);
        let range = node.map_or(scopes[declaring_scope as usize].range, |node| {
            facts.node(node).range
        });
        rows.push(BindingRow {
            file: file.clone(),
            content_identity,
            node,
            range,
            name: local_name.to_owned(),
            kind: BindingKind::ImportBinder,
            // An import is in effect over the whole scope it is written in,
            // whatever the position of the reference: every claimed language
            // either hoists imports to the top of their scope or requires
            // them there.
            hoisting: HoistingClass::ScopeWide,
            declaring_scope,
            activation: scopes[declaring_scope as usize].range,
            source_order: 0,
            visibility: DeclaredVisibility::Unknown,
            import: Some(ImportBinderDetail {
                local_name: local_name.to_owned(),
                alias: import.alias.clone(),
                target_segments: import
                    .path
                    .as_ref()
                    .map(|path| path.segments.clone())
                    .unwrap_or_default(),
                wildcard: import.is_wildcard,
                wildcard_ambiguous: wildcard_ambiguity(language, import, wildcard_count),
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
/// [`reaching_binding`] skips wildcard rows rather than letting this marker
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

/// The scope an import is written in: the innermost lexical scope the parser
/// recorded on the structured path, or the file scope.
fn import_scope(import: &ImportInfo, scopes: &[ScopeRow]) -> u32 {
    let Some(innermost) = import
        .path
        .as_ref()
        .and_then(|path| path.lexical_scopes.last())
    else {
        return 0;
    };
    scopes
        .iter()
        .filter(|scope| {
            scope.range.start_byte >= innermost.start_byte
                && scope.range.end_byte <= innermost.end_byte
        })
        .map(|scope| scope.index)
        .next_back()
        .unwrap_or(0)
}

/// The arena node of the token that spells an import's local name, so an
/// import binding carries the same AST identity as any other row over that
/// token. `None` when the import's local name is not spelled by a classified
/// token (a wildcard has no local name token, and a desugared tail may sit
/// inside a compound path node).
fn import_binder_node(
    facts: &FileFacts,
    declaration_start: usize,
    local_name: &str,
) -> Option<u32> {
    let source = facts.source();
    let import = (0..facts.nodes().len())
        .map(|node| u32::try_from(node).expect("facts arena node count fits in u32"))
        .find(|&node| {
            let normalized = facts.node(node);
            normalized.kind == NormalizedKind::Import
                && normalized.range.start_byte == declaration_start
        })?;
    (import + 1..facts.subtree_end(import)).find(|&node| {
        let roles = facts.occurrence_roles(node);
        let alias_or_target = roles.contains(&OccurrenceRole::ImportAlias)
            || roles.contains(&OccurrenceRole::ImportTarget);
        let normalized = facts.node(node);
        alias_or_target
            && &source[normalized.range.start_byte..normalized.range.end_byte] == local_name
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
        Language::Java | Language::Kotlin | Language::Scala | Language::Go | Language::CSharp => {
            true
        }
        Language::Python
        | Language::JavaScript
        | Language::TypeScript
        | Language::Rust
        | Language::Cpp
        | Language::Php
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
pub fn reaching_binding(
    env: &EnvironmentFileResult,
    name: &str,
    position_byte: usize,
    namespace: Option<Namespace>,
) -> ReachingBindingOutcome {
    if !env.completeness.covers(EnvironmentAxis::Scopes) {
        return ReachingBindingOutcome::Incomplete(EnvironmentAxis::Scopes);
    }
    if !env.completeness.covers(EnvironmentAxis::BindingIntervals) {
        return ReachingBindingOutcome::Incomplete(EnvironmentAxis::BindingIntervals);
    }
    let Some(innermost) = env.innermost_scope(position_byte) else {
        return ReachingBindingOutcome::NoBinding;
    };
    let ancestry = env.scope_ancestry(innermost);

    let mut candidates: Vec<usize> = env
        .bindings
        .iter()
        .enumerate()
        .filter(|(_, binding)| {
            binding.name == name
                && !binding
                    .import
                    .as_ref()
                    .is_some_and(|detail| detail.wildcard)
                && namespace.is_none_or(|wanted| binding.namespace() == wanted)
                && binding.is_active_at(position_byte)
                && ancestry.contains(&binding.declaring_scope)
        })
        .map(|(index, _)| index)
        .collect();
    if candidates.is_empty() {
        return ReachingBindingOutcome::NoBinding;
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
        ReachingBindingOutcome::Reached(winner)
    } else {
        ReachingBindingOutcome::Shadowed {
            winner,
            shadowed: candidates[1..].to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::resolution::ALL_ENVIRONMENT_AXES;
    use crate::analyzer::{AnalyzerConfig, Project, TestProject, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        file: ProjectFile,
        source: String,
    }

    impl Fixture {
        fn new(language: Language, relative_path: &str, source: &str) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let file = ProjectFile::new(root.clone(), relative_path);
            file.write(source).expect("write fixture source");
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            );
            Self {
                _temp: temp,
                workspace,
                file,
                source: source.to_owned(),
            }
        }

        fn environment(&self) -> EnvironmentFileResult {
            environment_for_file(self.workspace.analyzer(), &self.file)
        }

        /// Byte offset of `needle`; the marker keeps a position assertion
        /// readable without re-scanning the fixture.
        fn at(&self, needle: &str) -> usize {
            self.source
                .find(needle)
                .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"))
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
        match reaching_binding(env, name, position, None) {
            ReachingBindingOutcome::Reached(index) => &env.bindings[index],
            ReachingBindingOutcome::Shadowed { winner, .. } => &env.bindings[winner],
            other => panic!(
                "expected {name:?} to reach a binding at byte {position}, got {other:?}; \
                 bindings: {:?}",
                env.bindings
            ),
        }
    }

    fn scope_kinds(env: &EnvironmentFileResult) -> Vec<Option<NormalizedKind>> {
        env.scopes.iter().map(|scope| scope.anchor.kind()).collect()
    }

    /// The file scope is synthesized, not read from a fact, and it is the root
    /// of every chain: no adapter maps its grammar's root node, so a consumer
    /// that walked only facts would have no scope to stop at.
    #[test]
    fn the_file_scope_is_the_synthesized_root_of_the_scope_chain() {
        let source = concat!(
            "class Widget {\n",
            "    int render(String label) {\n",
            "        return label.length();\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        assert_eq!(env.scopes[0].anchor, ScopeAnchor::File);
        assert_eq!(env.scopes[0].parent_scope, None);
        assert_eq!(env.scopes[0].ast_id(), None);
        assert_eq!(env.scopes[0].range.start_byte, 0);
        assert_eq!(env.scopes[0].range.end_byte, source.len());
        assert!(
            env.scopes[1..]
                .iter()
                .all(|scope| scope.parent_scope.is_some() && scope.ast_id().is_some()),
            "every non-file scope has a parent and an AST identity: {:?}",
            env.scopes
        );
        assert_eq!(
            scope_kinds(&env),
            vec![
                None,
                Some(NormalizedKind::Class),
                Some(NormalizedKind::Method),
                Some(NormalizedKind::Block),
            ],
            "scopes are the file, the class, the method and its body block"
        );
        assert_eq!(env.scope_ancestry(3), vec![3, 2, 1, 0]);
    }

    /// A Java parameter list sits outside the body block's byte range, so the
    /// scope that owns a parameter is the callable, not the block. The
    /// reaching-binding walk climbs the ancestry, which is what makes the
    /// parameter reachable from inside the body regardless.
    #[test]
    fn java_parameters_belong_to_the_callable_and_reach_into_its_body() {
        let source = concat!(
            "class Widget {\n",
            "    int render(String label) {\n",
            "        int size = label.length();\n",
            "        return size;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let label = binding(&env, "label");
        assert_eq!(label.kind, BindingKind::Parameter);
        assert_eq!(label.hoisting, HoistingClass::ScopeWide);
        assert_eq!(
            env.scope(label.declaring_scope).anchor.kind(),
            Some(NormalizedKind::Method)
        );
        assert!(
            label.range.start_byte < env.scope(label.declaring_scope).range.end_byte
                && !env
                    .scopes
                    .iter()
                    .any(|scope| scope.anchor.kind() == Some(NormalizedKind::Block)
                        && scope.contains(label.range.start_byte)),
            "the parameter lies outside every block: {:?}",
            env.scopes
        );

        let size = binding(&env, "size");
        assert_eq!(size.kind, BindingKind::Local);
        assert_eq!(size.hoisting, HoistingClass::SourceOrder);
        assert_eq!(
            env.scope(size.declaring_scope).anchor.kind(),
            Some(NormalizedKind::Block)
        );

        assert_eq!(
            reached(&env, "label", fixture.at("label.length")).node,
            label.node,
            "a read inside the body reaches the parameter declared outside it"
        );
        assert_eq!(
            reached(&env, "size", fixture.at("size;")).node,
            size.node,
            "and the local reaches its own binder"
        );
    }

    /// Re-binding the same name in one block is two bindings with adjacent
    /// intervals: a read between them reaches the first, a read below the
    /// second reaches the second.
    #[test]
    fn rust_rebinding_in_one_block_reaches_the_binder_above_the_read() {
        let source = concat!(
            "fn render() -> u32 {\n",
            "    let value = 1;\n",
            "    let seen = value;\n",
            "    let value = 2;\n",
            "    return value;\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);
        let env = fixture.environment();
        assert!(env.completeness.is_complete(), "{:?}", env.completeness);

        let first = fixture.at("value = 1");
        let second = fixture.at("value = 2");
        let between = fixture.at("value;\n    let value = 2");
        let below = fixture.at("value;\n}");

        assert_eq!(
            reached(&env, "value", between).range.start_byte,
            first,
            "the read between the two bindings reaches the first"
        );
        assert_eq!(
            reached(&env, "value", below).range.start_byte,
            second,
            "the read below the re-binding reaches the second"
        );
        match reaching_binding(&env, "value", below, None) {
            ReachingBindingOutcome::Shadowed { winner, shadowed } => {
                assert_eq!(env.bindings[winner].range.start_byte, second);
                assert_eq!(
                    shadowed
                        .iter()
                        .map(|index| env.bindings[*index].range.start_byte)
                        .collect::<Vec<_>>(),
                    vec![first],
                    "the earlier binding is reported as shadowed, not dropped"
                );
            }
            other => panic!("a re-binding is a shadowing answer, got {other:?}"),
        }
    }

    /// A try-with-resources resource is in effect over the try block only.
    #[test]
    fn java_try_resource_is_in_effect_over_the_try_block() {
        let source = concat!(
            "class Widget {\n",
            "    void run() throws Exception {\n",
            "        try (AutoCloseable handle = open()) {\n",
            "            handle.toString();\n",
            "        }\n",
            "        after();\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        let handle = binding(&env, "handle");
        assert_eq!(handle.kind, BindingKind::CatchOrResource);
        assert_eq!(handle.hoisting, HoistingClass::DeclaredHead);
        assert_eq!(
            handle.activation.start_byte,
            fixture.at("{\n            handle")
        );

        assert_eq!(
            reached(&env, "handle", fixture.at("handle.toString")).node,
            handle.node
        );
        assert_eq!(
            reaching_binding(&env, "handle", fixture.at("after()"), None),
            ReachingBindingOutcome::NoBinding,
            "the resource is out of effect below the try block"
        );
    }

    /// A Java local is in effect from the end of its declaration, so a read
    /// above it reaches nothing at all.
    #[test]
    fn java_local_read_before_its_declaration_reaches_nothing() {
        let source = concat!(
            "class Widget {\n",
            "    int render() {\n",
            "        int first = later;\n",
            "        int later = 2;\n",
            "        return first + later;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        assert_eq!(
            reaching_binding(&env, "later", fixture.at("later;\n        int later"), None),
            ReachingBindingOutcome::NoBinding
        );
        assert_eq!(
            reached(&env, "later", fixture.at("later;\n    }"))
                .range
                .start_byte,
            fixture.at("later = 2")
        );
    }

    /// JavaScript is the opposite case, and deliberately so: `var` hoists, so a
    /// read above the declaration reaches the hoisted binding rather than
    /// nothing or an outer name.
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

    /// A comprehension target lives in the comprehension's own implicit scope,
    /// which is a declared sub-interval of the block it is written in.
    #[test]
    fn python_comprehension_target_is_a_declared_head_binder() {
        let source = concat!(
            "def render(items):\n",
            "    doubled = [item * 2 for item in items]\n",
            "    return doubled\n",
        );
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let env = fixture.environment();

        let item = binding(&env, "item");
        assert_eq!(item.kind, BindingKind::LoopVariable);
        assert_eq!(item.hoisting, HoistingClass::DeclaredHead);
        assert_eq!(item.activation.start_byte, fixture.at("[item * 2"));

        assert_eq!(
            reached(&env, "item", fixture.at("item * 2")).node,
            item.node
        );
        assert_eq!(
            reaching_binding(&env, "item", fixture.at("doubled\n"), None),
            ReachingBindingOutcome::NoBinding,
            "the comprehension target does not leak into the function body"
        );

        let items = binding(&env, "items");
        assert_eq!(items.kind, BindingKind::Parameter);
        assert_eq!(items.hoisting, HoistingClass::ScopeWide);
    }

    /// Import binders and local binders are separate row families over the
    /// same file, each with its own interval, so Milestone 3 can trace which
    /// of the two a reference selected.
    #[test]
    fn java_import_and_local_rows_coexist_with_their_own_intervals() {
        let source = concat!(
            "package app;\n",
            "import java.util.List;\n",
            "class Widget {\n",
            "    int render() {\n",
            "        List items = null;\n",
            "        return items.size();\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        let list = binding(&env, "List");
        let detail = list
            .import
            .as_ref()
            .unwrap_or_else(|| panic!("List must be an import binder: {list:?}"));
        assert_eq!(list.kind, BindingKind::ImportBinder);
        assert_eq!(list.declaring_scope, 0, "a Java import binds file-wide");
        assert_eq!(list.activation, env.scopes[0].range);
        assert_eq!(detail.local_name, "List");
        assert!(!detail.wildcard);
        assert_eq!(detail.wildcard_ambiguous, None);
        // The Java adapter records no parser-derived import path, so the row
        // can name the local name but not its target. That is reported, not
        // papered over: the import axis is incomplete while the binding axis
        // stays trustworthy.
        assert!(detail.target_segments.is_empty());
        assert!(!env.completeness.covers(EnvironmentAxis::ImportBinders));
        assert!(env.completeness.covers(EnvironmentAxis::BindingIntervals));
        assert!(env.completeness.covers(EnvironmentAxis::Scopes));
        match &env.completeness {
            EnvironmentCompleteness::Incomplete { reasons, .. } => assert_eq!(
                reasons.as_slice(),
                [EnvironmentIncompleteReason::ImportTargetUnstructured]
            ),
            EnvironmentCompleteness::Complete => {
                panic!("an import with no structured path cannot be complete")
            }
        }

        let items = binding(&env, "items");
        assert_eq!(items.kind, BindingKind::Local);
        assert_ne!(items.declaring_scope, 0);
        assert_eq!(
            reached(&env, "items", fixture.at("items.size")).node,
            items.node
        );

        assert!(env.package.syntactic, "Java spells its package in source");
        assert!(
            env.package.package_fq.is_some(),
            "package clause: {:?}",
            env.package
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
            reaching_binding(&env, WILDCARD_IMPORT_NAME, fixture.at("class Widget"), None),
            ReachingBindingOutcome::NoBinding,
            "a wildcard row is evidence, never a name that reaches"
        );
    }

    /// The motivating discriminator of the whole plan: is the value operated on
    /// inside this loop declared inside or outside the loop body?
    #[test]
    fn java_loop_reads_separate_outer_and_loop_local_bindings() {
        let source = concat!(
            "class Widget {\n",
            "    void run() {\n",
            "        String outer = \"a\";\n",
            "        for (int index = 0; index < 3; index++) {\n",
            "            String inner = \"b\";\n",
            "            use(outer);\n",
            "            use(inner);\n",
            "        }\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        let loop_scope = env
            .scopes
            .iter()
            .find(|scope| {
                scope
                    .anchor
                    .kind()
                    .is_some_and(|kind| kind.satisfies(NormalizedKind::Loop))
            })
            .unwrap_or_else(|| panic!("the for statement must be a scope: {:?}", env.scopes));

        let outer = reached(&env, "outer", fixture.at("outer);"));
        let outer_scope = env.scope(outer.declaring_scope);
        assert!(
            outer_scope.range.start_byte < loop_scope.range.start_byte
                && outer_scope.range.end_byte > loop_scope.range.end_byte,
            "the outer binding is declared in a scope that contains the loop: {outer_scope:?} vs {loop_scope:?}"
        );

        let inner = reached(&env, "inner", fixture.at("inner);"));
        let inner_scope = env.scope(inner.declaring_scope);
        assert!(
            inner_scope.range.start_byte >= loop_scope.range.start_byte
                && inner_scope.range.end_byte <= loop_scope.range.end_byte,
            "the loop-local binding is declared inside the loop: {inner_scope:?} vs {loop_scope:?}"
        );
    }

    /// An adapter that declares no environment support reports every axis
    /// incomplete. An empty row set from such a file must never read as "this
    /// file has no bindings".
    #[test]
    fn an_adapter_without_environment_support_reports_incomplete_not_empty_complete() {
        let source = "class Widget { def render(label: String): String = label }\n";
        let fixture = Fixture::new(Language::Scala, "src/app.scala", source);
        let env = fixture.environment();

        assert!(env.scopes.is_empty());
        assert!(env.bindings.is_empty());
        match &env.completeness {
            EnvironmentCompleteness::Incomplete {
                unsupported_axes, ..
            } => assert_eq!(
                unsupported_axes.as_slice(),
                ENVIRONMENT_PRODUCER_AXES,
                "every producer axis is unsupported for Scala"
            ),
            EnvironmentCompleteness::Complete => {
                panic!("an adapter with no environment support must never report Complete")
            }
        }
        for &axis in ALL_ENVIRONMENT_AXES {
            assert!(!env.completeness.covers(axis), "{axis} claimed covered");
        }
        assert_eq!(
            reaching_binding(&env, "label", 40, None),
            ReachingBindingOutcome::Incomplete(EnvironmentAxis::Scopes),
            "an uncovered environment refuses to answer instead of guessing"
        );
    }

    /// The two candidate axes belong to the resolution trace, so an
    /// environment result never claims them even when it is otherwise
    /// complete.
    #[test]
    fn an_environment_result_never_covers_the_candidate_axes() {
        let source = "class Widget {\n    int render() { return 1; }\n}\n";
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let env = fixture.environment();

        assert!(env.completeness.is_complete(), "{:?}", env.completeness);
        assert!(!env.completeness.covers(EnvironmentAxis::CandidateSelection));
        assert!(!env.completeness.covers(EnvironmentAxis::CandidateRejection));
        for &axis in ENVIRONMENT_PRODUCER_AXES {
            assert!(env.completeness.covers(axis), "{axis} not covered");
        }
    }
}
