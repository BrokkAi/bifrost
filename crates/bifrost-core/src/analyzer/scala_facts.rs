//! Content-local Scala declaration syntax captured by the primary producer.
//!
//! The producer owns source declaration identities and records the syntax that
//! Scala consumers need after the parser has been dropped.  In particular, this
//! module deliberately does not contain tree-sitter nodes or byte ranges.  A
//! store can therefore publish the facts once and consumers can mount the
//! exact source occurrence arena beside them.

use crate::analyzer::dense_id::define_dense_id;
use crate::analyzer::model::CallableArity;
use crate::analyzer::source_facts::{SourceDeclarationId, SourceFactRows, SourceOccurrenceId};

pub const SCALA_SOURCE_FACTS_VERSION: i64 = 1;

define_dense_id! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ScalaTypeExpressionId {
        new: pub,
        get: pub,
        index: pub,
        try_from_index: pub,
    }
}

/// A parser-independent Scala type expression.  `segments` is the structured
/// lookup path of the expression head; arguments retain nested type syntax.
/// The store flattens this tree into rows, but keeping the source-side shape
/// here makes producer and consumer code independent of the SQL representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalaTypeExpressionPath {
    pub segments: Vec<String>,
    pub arguments: Vec<ScalaTypeExpressionPath>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScalaGenericOwnerSourceFacts {
    pub type_parameters: Vec<String>,
    pub supertypes: Vec<ScalaTypeExpressionPath>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalaCallableRole {
    Ordinary,
    PrimaryConstructor,
    SecondaryConstructor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalaParameterListKind {
    Explicit,
    Contextual,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ScalaDeclarationKind {
    Other,
    Class,
    Trait,
    Object,
    Enum,
    EnumCase,
    TypeAlias,
}

impl ScalaDeclarationKind {
    pub const fn encoded(self) -> i64 {
        match self {
            Self::Other => 0,
            Self::Class => 1,
            Self::Trait => 2,
            Self::Object => 3,
            Self::Enum => 4,
            Self::EnumCase => 5,
            Self::TypeAlias => 6,
        }
    }

    pub const fn from_encoded(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Other),
            1 => Some(Self::Class),
            2 => Some(Self::Trait),
            3 => Some(Self::Object),
            4 => Some(Self::Enum),
            5 => Some(Self::EnumCase),
            6 => Some(Self::TypeAlias),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ScalaDeclarationVisibility {
    Public,
    Protected,
    NonApi,
}

impl ScalaDeclarationVisibility {
    pub const fn encoded(self) -> i64 {
        match self {
            Self::Public => 0,
            Self::Protected => 1,
            Self::NonApi => 2,
        }
    }

    pub const fn from_encoded(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Public),
            1 => Some(Self::Protected),
            2 => Some(Self::NonApi),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalaCallableParameterList {
    pub arity: CallableArity,
    pub kind: ScalaParameterListKind,
}

impl ScalaCallableParameterList {
    pub const fn explicit(arity: CallableArity) -> Self {
        Self {
            arity,
            kind: ScalaParameterListKind::Explicit,
        }
    }
}

/// How many application lists a callable's declared result can consume after
/// its declared parameter lists have been filled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScalaDeclaredResult {
    pub function_lists: usize,
    pub open: bool,
}

impl ScalaDeclaredResult {
    pub const UNDECLARED: Self = Self {
        function_lists: 0,
        open: false,
    };

    pub const OPEN: Self = Self {
        function_lists: 0,
        open: true,
    };

    pub const fn new(function_lists: usize, open: bool) -> Self {
        Self {
            function_lists,
            open,
        }
    }

    pub const fn function_lists(self) -> usize {
        self.function_lists
    }

    pub const fn is_open(self) -> bool {
        self.open
    }

    pub const fn accepts_application_lists(self, lists: usize) -> bool {
        self.open || lists <= self.function_lists
    }
}

/// Declared lookup paths for the parameters of one function-typed parameter.
pub type ScalaFunctionParameterTypePaths = Vec<Option<Vec<String>>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalaCallableSourceAlternative {
    pub role: ScalaCallableRole,
    pub shape: Vec<ScalaCallableParameterList>,
    pub result: ScalaDeclaredResult,
    pub parameter_defaults: Vec<Vec<bool>>,
    pub parameter_function_arities: Vec<Vec<Option<usize>>>,
    pub parameter_type_paths: Vec<Vec<Option<Vec<String>>>>,
    pub parameter_type_expressions: Vec<Vec<Option<ScalaTypeExpressionPath>>>,
    /// One optional function-type path per parameter.  A present outer path
    /// has one optional type path per function parameter.
    pub parameter_function_type_paths: Vec<Vec<Option<ScalaFunctionParameterTypePaths>>>,
    pub extension_receiver_type_path: Option<Vec<String>>,
    pub return_type_path: Option<Vec<String>>,
    pub return_type_is_singleton: bool,
    pub return_type_expression: Option<ScalaTypeExpressionPath>,
}

/// All source-owned properties attached to one declaration identity.  A fact
/// may describe a source-only declaration with no mounted `CodeUnit`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalaDeclarationSourceFact {
    pub declaration: SourceDeclarationId,
    pub kind: ScalaDeclarationKind,
    pub visibility: ScalaDeclarationVisibility,
    pub callable: Option<ScalaCallableSourceAlternative>,
    pub field_type_path: Option<Vec<String>>,
    pub type_alias_path: Option<Vec<String>>,
    pub stable_owner: bool,
    pub is_enum: bool,
    pub is_term_field: bool,
    pub is_case_class: bool,
    pub is_full_enum_case: bool,
    pub is_abstract_callable: bool,
    pub is_explicitly_abstract: bool,
    pub is_sealed: bool,
    pub is_final: bool,
    pub generic_owner: Option<ScalaGenericOwnerSourceFacts>,
    pub lexical_prefixes: Vec<String>,
    pub lexical_scopes: Vec<SourceOccurrenceId>,
}

/// `Some(empty)` is an authoritative Scala publication.  Absence of the
/// family on `ParsedSourceFacts` means that Scala source facts were not made
/// available by the producer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScalaSourceFacts {
    pub declarations: Vec<ScalaDeclarationSourceFact>,
}

impl ScalaSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = self
            .declarations
            .capacity()
            .saturating_mul(std::mem::size_of::<ScalaDeclarationSourceFact>());
        for fact in &self.declarations {
            bytes = bytes
                .saturating_add(
                    fact.lexical_prefixes
                        .capacity()
                        .saturating_mul(std::mem::size_of::<String>()),
                )
                .saturating_add(
                    fact.lexical_prefixes
                        .iter()
                        .map(String::capacity)
                        .sum::<usize>(),
                )
                .saturating_add(
                    fact.lexical_scopes
                        .capacity()
                        .saturating_mul(std::mem::size_of::<SourceOccurrenceId>()),
                )
                .saturating_add(path_bytes(fact.field_type_path.as_deref()))
                .saturating_add(path_bytes(fact.type_alias_path.as_deref()));
            if let Some(owner) = &fact.generic_owner {
                bytes = bytes
                    .saturating_add(
                        owner
                            .type_parameters
                            .capacity()
                            .saturating_mul(std::mem::size_of::<String>()),
                    )
                    .saturating_add(
                        owner
                            .type_parameters
                            .iter()
                            .map(String::capacity)
                            .sum::<usize>(),
                    );
                for expression in &owner.supertypes {
                    bytes = bytes.saturating_add(expression_bytes(expression));
                }
            }
            if let Some(callable) = &fact.callable {
                bytes = bytes.saturating_add(callable_bytes(callable));
            }
        }
        bytes
    }

    /// Validate source handles and the shape alignments before persistence or
    /// consumer access.  Expression trees are walked with an explicit stack so
    /// deeply nested Scala types cannot overflow the Rust call stack.
    pub fn valid_links(&self, source: &SourceFactRows) -> bool {
        let mut seen = crate::hash::HashSet::default();
        for fact in &self.declarations {
            if fact.declaration.index() >= source.declaration_count()
                || !seen.insert(fact.declaration)
                || !valid_segments(fact.field_type_path.as_deref())
                || !valid_segments(fact.type_alias_path.as_deref())
                || (fact.is_enum != (fact.kind == ScalaDeclarationKind::Enum))
                || (fact.is_full_enum_case && fact.kind != ScalaDeclarationKind::EnumCase)
                || fact
                    .lexical_scopes
                    .iter()
                    .any(|scope| scope.index() >= source.occurrence_count())
                || fact.lexical_prefixes.iter().any(String::is_empty)
            {
                return false;
            }
            if let Some(owner) = &fact.generic_owner
                && (owner.type_parameters.iter().any(String::is_empty)
                    || owner
                        .supertypes
                        .iter()
                        .any(|expression| !valid_expression(expression)))
            {
                return false;
            }
            if let Some(callable) = &fact.callable
                && !valid_callable(callable)
            {
                return false;
            }
        }
        true
    }
}

fn valid_segments(path: Option<&[String]>) -> bool {
    path.is_none_or(|segments| {
        !segments.is_empty() && segments.iter().all(|segment| !segment.is_empty())
    })
}

fn valid_expression(root: &ScalaTypeExpressionPath) -> bool {
    let mut stack = vec![root];
    while let Some(expression) = stack.pop() {
        if expression.segments.is_empty() || expression.segments.iter().any(String::is_empty) {
            return false;
        }
        stack.extend(expression.arguments.iter());
    }
    true
}

fn valid_callable(callable: &ScalaCallableSourceAlternative) -> bool {
    let lists = callable.shape.len();
    if callable.parameter_defaults.len() != lists {
        return false;
    }
    for matrix_length in [
        callable.parameter_function_arities.len(),
        callable.parameter_type_paths.len(),
        callable.parameter_type_expressions.len(),
        callable.parameter_function_type_paths.len(),
    ] {
        if matrix_length != 0 && matrix_length != lists {
            return false;
        }
    }
    for (list_index, list) in callable.shape.iter().enumerate() {
        let parameter_count = list.arity.total();
        let defaults = &callable.parameter_defaults[list_index];
        if defaults.len() != parameter_count {
            return false;
        }
        for (present, row_len) in [
            (
                !callable.parameter_function_arities.is_empty(),
                callable
                    .parameter_function_arities
                    .get(list_index)
                    .map(Vec::len),
            ),
            (
                !callable.parameter_type_paths.is_empty(),
                callable.parameter_type_paths.get(list_index).map(Vec::len),
            ),
            (
                !callable.parameter_type_expressions.is_empty(),
                callable
                    .parameter_type_expressions
                    .get(list_index)
                    .map(Vec::len),
            ),
            (
                !callable.parameter_function_type_paths.is_empty(),
                callable
                    .parameter_function_type_paths
                    .get(list_index)
                    .map(Vec::len),
            ),
        ] {
            if present && row_len != Some(parameter_count) {
                return false;
            }
        }
        if let Some(type_paths) = callable.parameter_type_paths.get(list_index)
            && type_paths
                .iter()
                .any(|path| !valid_segments(path.as_deref()))
        {
            return false;
        }
        if let Some(type_expressions) = callable.parameter_type_expressions.get(list_index)
            && type_expressions
                .iter()
                .flatten()
                .any(|expression| !valid_expression(expression))
        {
            return false;
        }
        if let Some(function_paths) = callable.parameter_function_type_paths.get(list_index) {
            for function_path in function_paths.iter().flatten() {
                if function_path
                    .iter()
                    .any(|path| !valid_segments(path.as_deref()))
                {
                    return false;
                }
            }
        }
    }
    valid_segments(callable.extension_receiver_type_path.as_deref())
        && valid_segments(callable.return_type_path.as_deref())
        && (!callable.return_type_is_singleton
            || (callable.return_type_path.is_some() && callable.return_type_expression.is_some()))
        && callable
            .return_type_expression
            .as_ref()
            .is_none_or(valid_expression)
}

fn path_bytes(path: Option<&[String]>) -> usize {
    path.map_or(0, |segments| {
        segments
            .len()
            .saturating_mul(std::mem::size_of::<String>())
            .saturating_add(segments.iter().map(String::capacity).sum::<usize>())
    })
}

fn expression_bytes(root: &ScalaTypeExpressionPath) -> usize {
    let mut bytes = 0usize;
    let mut stack = vec![root];
    while let Some(expression) = stack.pop() {
        bytes = bytes
            .saturating_add(
                expression
                    .segments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            )
            .saturating_add(
                expression
                    .segments
                    .iter()
                    .map(String::capacity)
                    .sum::<usize>(),
            )
            .saturating_add(
                expression
                    .arguments
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ScalaTypeExpressionPath>()),
            );
        stack.extend(expression.arguments.iter());
    }
    bytes
}

fn callable_bytes(callable: &ScalaCallableSourceAlternative) -> usize {
    let mut bytes = path_bytes(callable.extension_receiver_type_path.as_deref())
        .saturating_add(path_bytes(callable.return_type_path.as_deref()));
    if let Some(expression) = &callable.return_type_expression {
        bytes = bytes.saturating_add(expression_bytes(expression));
    }
    for list in &callable.parameter_type_paths {
        for path in list {
            bytes = bytes.saturating_add(path_bytes(path.as_deref()));
        }
    }
    for list in &callable.parameter_type_expressions {
        for expression in list.iter().flatten() {
            bytes = bytes.saturating_add(expression_bytes(expression));
        }
    }
    for list in &callable.parameter_function_type_paths {
        for function in list.iter().flatten() {
            for path in function {
                bytes = bytes.saturating_add(path_bytes(path.as_deref()));
            }
        }
    }
    bytes
}
