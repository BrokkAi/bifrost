//! The per-language configuration the cognitive-complexity scorer is driven by.
//!
//! This is plain data: node-kind tables plus optional function-pointer
//! predicates, all of it decided by a tree-sitter node kind and the source
//! bytes. A language declares its own [`Config`] without needing the scorer, so
//! the config lives here while the engine (`compute` and its frame walk) stays
//! in `brokk-bifrost-analysis`.

use tree_sitter::Node;

/// Predicate returning `true` when a switch/match case node is the
/// language's "default"/"wildcard" branch and therefore must not add
/// complexity. Receives the case node and the full source text.
pub type DefaultCasePredicate = fn(Node<'_>, &str) -> bool;

/// Predicate returning the number of case labels represented by a case node.
/// This supports grammars that group multiple labels into one container.
pub type CaseIncrementPredicate = fn(Node<'_>, &str) -> u32;

/// Predicate returning `true` when a configured jump contributes complexity.
/// When absent, jumps retain the shared labeled-jump behavior.
pub type JumpPredicate = fn(Node<'_>) -> bool;

/// Predicate returning `true` when a node should be treated as a named
/// function boundary (i.e. analysis should not descend into it once the
/// scorer has already entered a function). Used for languages where the
/// concrete function-decoration node type varies (e.g. Python's
/// `decorated_definition` wrapping a `function_definition`).
pub type NamedFunctionBoundaryPredicate = fn(Node<'_>) -> bool;

/// Configuration that adapts the generic scorer to a specific language.
///
/// Each `*_types` slice lists the tree-sitter node kinds that map to a
/// SonarSource cognitive-complexity category. Slices use `&'static [&'static
/// str]` rather than a set type because each language declares <= 12 entries
/// per category and the scorer hot loop performs a linear scan per node.
pub struct Config {
    /// Primary `if`-statement node types. Contribute +1+nesting on entry,
    /// or just +1 when the scorer recognizes them as `else if` continuations.
    pub if_types: &'static [&'static str],
    /// Additional node types treated as `if`-like for the `else if` flatten
    /// rule (e.g. Python's `elif_clause`).
    pub alternate_if_types: &'static [&'static str],
    /// Loop node types (`for`, `while`, `do`, `loop`).
    pub loop_types: &'static [&'static str],
    /// Catch/except node types.
    pub catch_types: &'static [&'static str],
    /// Ternary / conditional-expression node types.
    pub conditional_types: &'static [&'static str],
    /// Case-clause node types within a switch/match. Default cases are
    /// filtered out by [`Self::default_case_predicate`] if set.
    pub case_types: &'static [&'static str],
    /// Default-case container node types whose children should be walked
    /// without contributing to the score.
    pub default_case_types: &'static [&'static str],
    /// Binary-expression node types that may contain logical operators.
    pub binary_types: &'static [&'static str],
    /// Logical-operator tokens (`"&&"`, `"||"`, `"and"`, `"or"`...). Compared
    /// both against tree-sitter node kinds (Python exposes `and`/`or` as
    /// named kinds) and against the literal source bytes of anonymous tokens
    /// (Java/Rust expose `&&`/`||` as anonymous tokens).
    pub logical_operators: &'static [&'static str],
    /// Jump node types (`break`, `continue`, `goto`). Only contribute when
    /// they carry a label.
    pub jump_types: &'static [&'static str],
    /// Node types that mark a named (non-anonymous) function boundary --
    /// the scorer enters one such node at the root and refuses to descend
    /// into nested ones.
    pub named_function_boundary_types: &'static [&'static str],
    /// Node types treated as anonymous functions (lambdas, closures): the
    /// scorer descends into them, bumping nesting by one.
    pub anonymous_function_types: &'static [&'static str],
    /// Node types representing `else` clauses; required so that `else if`
    /// is folded into a single increment rather than `else` + `if`.
    pub else_clause_types: &'static [&'static str],
    /// Optional predicate identifying the default branch of a case-like
    /// construct (e.g. Java's `default:`, Rust's `_ =>`).
    pub default_case_predicate: Option<DefaultCasePredicate>,
    /// Optional counter for grammars where one case node can contain multiple
    /// labels. Takes precedence over [`Self::default_case_predicate`].
    pub case_increment_predicate: Option<CaseIncrementPredicate>,
    /// Optional language-specific jump predicate.
    pub jump_predicate: Option<JumpPredicate>,
    /// Optional predicate marking additional named-function-boundary nodes
    /// that cannot be enumerated by kind alone (e.g. Python decorated
    /// functions).
    pub named_function_boundary_predicate: Option<NamedFunctionBoundaryPredicate>,
}

impl Config {
    /// Const constructor producing a no-op config. Language configs override
    /// the relevant slices in their static initializer.
    pub const fn empty() -> Self {
        Self {
            if_types: &[],
            alternate_if_types: &[],
            loop_types: &[],
            catch_types: &[],
            conditional_types: &[],
            case_types: &[],
            default_case_types: &[],
            binary_types: &[],
            logical_operators: &[],
            jump_types: &[],
            named_function_boundary_types: &[],
            anonymous_function_types: &[],
            else_clause_types: &[],
            default_case_predicate: None,
            case_increment_predicate: None,
            jump_predicate: None,
            named_function_boundary_predicate: None,
        }
    }

    pub fn is_any_if(&self, kind: &str) -> bool {
        slice_contains(self.if_types, kind) || slice_contains(self.alternate_if_types, kind)
    }
}

pub fn slice_contains(haystack: &[&str], needle: &str) -> bool {
    haystack.contains(&needle)
}
