use super::super::kinds::{NormalizedKind, Role};
use crate::analyzer::Language;
use regex::Regex;
use std::fmt;

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;
pub const MAX_WHERE_GLOBS: usize = 128;
pub const MAX_GLOB_LENGTH: usize = 1024;
pub const MAX_LANGUAGE_FILTERS: usize = 32;
pub const MAX_PATTERN_DEPTH: usize = 64;
pub const MAX_PATTERN_NODES: usize = 256;
pub const MAX_KIND_LIST_ENTRIES: usize = 32;
pub const MAX_ROLE_LIST_ENTRIES: usize = 64;
pub const MAX_KWARGS: usize = 64;
pub const MAX_STRING_PREDICATE_LENGTH: usize = 4096;
pub const MAX_CAPTURE_LENGTH: usize = 128;
pub const MAX_KWARG_NAME_LENGTH: usize = 128;
pub const MAX_QUERY_STEPS: usize = 16;
pub const SCHEMA_VERSION: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryValueKind {
    StructuralMatch,
    Declaration,
    File,
}

impl QueryValueKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::StructuralMatch => "structural_match",
            Self::Declaration => "declaration",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryStep {
    EnclosingDecl,
    FileOf,
    ImportsOf,
    ImportersOf,
}

impl QueryStep {
    pub fn label(self) -> &'static str {
        match self {
            Self::EnclosingDecl => "enclosing_decl",
            Self::FileOf => "file_of",
            Self::ImportsOf => "imports_of",
            Self::ImportersOf => "importers_of",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "enclosing_decl" => Some(Self::EnclosingDecl),
            "file_of" => Some(Self::FileOf),
            "imports_of" => Some(Self::ImportsOf),
            "importers_of" => Some(Self::ImportersOf),
            _ => None,
        }
    }

    pub fn output_kind(self, input: QueryValueKind) -> Option<QueryValueKind> {
        match (self, input) {
            (Self::EnclosingDecl, QueryValueKind::StructuralMatch) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::FileOf, QueryValueKind::StructuralMatch | QueryValueKind::Declaration) => {
                Some(QueryValueKind::File)
            }
            (Self::ImportsOf | Self::ImportersOf, QueryValueKind::File) => {
                Some(QueryValueKind::File)
            }
            _ => None,
        }
    }
}

pub(super) fn validate_query_steps(steps: &[QueryStep]) -> Result<QueryValueKind, QueryError> {
    if steps.len() > MAX_QUERY_STEPS {
        return Err(QueryError::new(
            "steps",
            format!("at most {MAX_QUERY_STEPS} query steps are allowed"),
        ));
    }

    let mut value_kind = QueryValueKind::StructuralMatch;
    for (index, &step) in steps.iter().enumerate() {
        let expected_input = match step {
            QueryStep::EnclosingDecl => "structural_match",
            QueryStep::FileOf => "structural_match or declaration",
            QueryStep::ImportsOf | QueryStep::ImportersOf => "file",
        };
        value_kind = step.output_kind(value_kind).ok_or_else(|| {
            QueryError::new(
                format!("steps[{index}]"),
                format!(
                    "step {} requires {expected_input}, but the previous stage produces {}",
                    step.label(),
                    value_kind.label()
                ),
            )
        })?;
    }
    Ok(value_kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeQueryResultDetail {
    Compact,
    Full,
}

impl CodeQueryResultDetail {
    pub fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Full => "full",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "compact" => Some(Self::Compact),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn is_compact(self) -> bool {
        matches!(self, Self::Compact)
    }
}

/// A structural query: one root pattern plus containment constraints and
/// workspace scoping. This is the semantic authority both syntaxes parse into.
#[derive(Debug, Clone)]
pub struct CodeQuery {
    pub schema_version: u64,
    /// Path globs relative to the workspace root; empty means all files.
    pub where_globs: Vec<glob::Pattern>,
    /// Language filter; empty means all languages with structural adapters.
    pub languages: Vec<Language>,
    pub root: Pattern,
    /// The root match must be lexically contained in a node matching this.
    pub inside: Option<Pattern>,
    /// Verifier-only negative containment: never used for candidate pruning.
    pub not_inside: Option<Pattern>,
    /// Ordered semantic transformations applied after structural matching.
    pub steps: Vec<QueryStep>,
    pub limit: usize,
    pub result_detail: CodeQueryResultDetail,
}

impl CodeQuery {
    /// Validate the semantic pipeline independently of its JSON/RQL origin.
    /// Embedders may construct this public IR directly, so execution cannot
    /// rely solely on decoder validation.
    pub fn validate_steps(&self) -> Result<QueryValueKind, QueryError> {
        validate_query_steps(&self.steps)
    }
}

/// Predicate over a string attribute of a fact (its name or source text).
#[derive(Debug, Clone)]
pub enum StringPredicate {
    Exact(String),
    Regex(Regex),
}

impl StringPredicate {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            StringPredicate::Exact(expected) => value == expected,
            StringPredicate::Regex(regex) => regex.is_match(value),
        }
    }
}

/// One node pattern. All fields optional; the *root* `match` pattern must
/// constrain at least one of kind/name/text (a wildcard root would match
/// every node in the workspace), while nested patterns may be capture-only
/// or empty (an empty `args` entry means "some argument exists").
#[derive(Debug, Clone, Default)]
pub struct Pattern {
    /// JSON `kind`: a union of kinds, each subtype-aware (`literal` matches
    /// `string_literal`; `["function", "method"]` matches either). Empty
    /// means unconstrained. There is deliberately no exact-match variant:
    /// leaf kinds are their own exact match, and "exactly an abstract kind"
    /// would only select facts from adapters too coarse to classify further —
    /// adapter precision is surfaced through diagnostics, not query
    /// semantics.
    pub kinds: Vec<NormalizedKind>,
    /// JSON `not_kind`: subtype-aware exclusion, verifier-only (never used
    /// for candidate pruning). `{"kind": "callable", "not_kind":
    /// ["constructor", "lambda"]}` matches named functions and methods.
    pub not_kinds: Vec<NormalizedKind>,
    pub name: Option<StringPredicate>,
    pub text: Option<StringPredicate>,
    pub capture: Option<String>,
    pub has: Option<Box<Pattern>>,
    /// Verifier-only: never used for candidate pruning.
    pub not_has: Option<Box<Pattern>>,
    // Role sub-patterns. Only valid when `kind` is declared and the role is
    // valid for at least one of its kinds (see `Role::valid_for`).
    pub callee: Option<Box<Pattern>>,
    pub receiver: Option<Box<Pattern>>,
    /// Each listed pattern must match some positional argument; matches must
    /// appear in argument order but need not be contiguous.
    pub args: Vec<Pattern>,
    /// Named/keyword arguments: each entry must match the value of the
    /// keyword argument with that name.
    pub kwargs: Vec<(String, Pattern)>,
    pub left: Option<Box<Pattern>>,
    pub right: Option<Box<Pattern>>,
    pub module: Option<Box<Pattern>>,
    /// Each listed pattern must match some decorator/annotation.
    pub decorators: Vec<Pattern>,
    pub object: Option<Box<Pattern>>,
    pub field: Option<Box<Pattern>>,
}

impl Pattern {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
            && self.not_kinds.is_empty()
            && self.name.is_none()
            && self.text.is_none()
            && self.capture.is_none()
            && self.has.is_none()
            && self.not_has.is_none()
            && !self.constrains_roles()
    }

    fn constrains_roles(&self) -> bool {
        Role::single_target_roles()
            .iter()
            .any(|&role| self.single_role_pattern(role).is_some())
            || Role::list_target_roles()
                .iter()
                .any(|&role| !self.list_role_patterns(role).is_empty())
            || !self.kwargs.is_empty()
    }

    pub(crate) fn single_role_pattern(&self, role: Role) -> Option<&Pattern> {
        match role {
            Role::Callee => self.callee.as_deref(),
            Role::Receiver => self.receiver.as_deref(),
            Role::Left => self.left.as_deref(),
            Role::Right => self.right.as_deref(),
            Role::Module => self.module.as_deref(),
            Role::Object => self.object.as_deref(),
            Role::Field => self.field.as_deref(),
            Role::Arg | Role::Kwarg | Role::Decorator => None,
        }
    }

    pub(crate) fn list_role_patterns(&self, role: Role) -> &[Pattern] {
        match role {
            Role::Arg => &self.args,
            Role::Decorator => &self.decorators,
            Role::Callee
            | Role::Receiver
            | Role::Kwarg
            | Role::Left
            | Role::Right
            | Role::Module
            | Role::Object
            | Role::Field => &[],
        }
    }

    pub(crate) fn has_role_constraints(&self) -> bool {
        self.constrains_roles()
    }
}

/// A query rejection, carrying the JSON path of the offending field so
/// callers (especially agents) can self-correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub path: String,
    pub message: String,
}

impl QueryError {
    pub(super) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "invalid query: {}", self.message)
        } else {
            write!(f, "invalid query at {}: {}", self.path, self.message)
        }
    }
}

impl std::error::Error for QueryError {}
