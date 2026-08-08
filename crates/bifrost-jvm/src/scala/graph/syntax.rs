use crate::scala::scala_parenthesized_arity;
use crate::scala::supertypes::scala_type_lookup_segments;
use crate::scala::wildcard_imports::scala_package_prefixes_at;
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::{CallableArity, ImportInfo};
use brokk_bifrost_core::analyzer::tree_walk::subtree_contains;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

/// The builtin type a Scala literal node denotes.
///
/// Moved here from `scala_graph/resolver.rs` ahead of the rest of that file:
/// it is a pure node-kind mapping and this module's `types.push(...)` walk is
/// its only caller on this side of the seam.
pub fn scala_literal_type_name(kind: &str) -> Option<&'static str> {
    match kind {
        "string" | "string_literal" | "interpolated_string_expression" => Some("String"),
        "integer_literal" => Some("Int"),
        "floating_point_literal" => Some("Double"),
        "boolean_literal" | "true" | "false" => Some("Boolean"),
        "character_literal" => Some("Char"),
        _ => None,
    }
}

type ScalaParameterFunctionTypePaths = Vec<Vec<Option<Vec<Option<Vec<String>>>>>>;

#[derive(Default)]
pub struct ScalaSourceFacts {
    pub callable_alternatives_by_range: HashMap<(usize, usize), ScalaCallableSourceAlternative>,
    pub field_type_paths_by_range: HashMap<(usize, usize), Vec<String>>,
    pub type_alias_paths_by_range: HashMap<(usize, usize), Vec<String>>,
    pub stable_owner_ranges: HashSet<(usize, usize)>,
    pub enum_ranges: HashSet<(usize, usize)>,
    pub case_class_ranges: HashSet<(usize, usize)>,
    pub abstract_callable_ranges: HashSet<(usize, usize)>,
    pub generic_owner_facts_by_range: HashMap<(usize, usize), ScalaGenericOwnerSourceFacts>,
}

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

#[derive(Clone)]
pub struct ScalaCallableSourceAlternative {
    pub role: ScalaCallableRole,
    pub shape: Vec<ScalaCallableParameterList>,
    pub result: ScalaDeclaredResult,
    pub parameter_defaults: Vec<Vec<bool>>,
    pub parameter_function_arities: Vec<Vec<Option<usize>>>,
    pub parameter_type_paths: Vec<Vec<Option<Vec<String>>>>,
    pub parameter_type_expressions: Vec<Vec<Option<ScalaTypeExpressionPath>>>,
    pub parameter_function_type_paths: ScalaParameterFunctionTypePaths,
    pub extension_receiver_type_path: Option<Vec<String>>,
    pub return_type_path: Option<Vec<String>>,
    pub return_type_expression: Option<ScalaTypeExpressionPath>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalaCallableRole {
    Ordinary,
    PrimaryConstructor,
    SecondaryConstructor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalaMethodValueContext {
    Unknown,
    Function(ScalaFunctionParameterShape),
    Incompatible,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ScalaParameterTypeIdentity {
    Builtin(&'static str),
    Declaration(CodeUnit),
    Logical(String),
    LogicalCandidates(Vec<String>),
    TypeParameter(String),
    Unresolved(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalaFunctionParameterShape {
    pub arity: usize,
    pub parameter_types: Option<Vec<ScalaParameterTypeIdentity>>,
    pub parameter_types_authoritative: bool,
}

impl ScalaFunctionParameterShape {
    pub fn arity_only(arity: usize) -> Self {
        Self {
            arity,
            parameter_types: None,
            parameter_types_authoritative: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalaParameterListKind {
    Explicit,
    Contextual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalaCallArgumentListKind {
    Ordinary,
    Contextual,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalaCallArgumentList {
    pub arity: usize,
    pub kind: ScalaCallArgumentListKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalaCallSiteShape {
    pub lists: Vec<ScalaCallArgumentList>,
    /// Builtin types of the first ordinary argument list's literal arguments,
    /// positionally aligned (`None` per argument when it is not a literal, and
    /// `None` overall when the list is unknown or uses named arguments).
    /// Purely kind-derived, so numeric literal suffixes are not represented;
    /// consumers must treat numeric/numeric differences as inconclusive
    /// (see `scala_numeric_builtins`).
    pub leading_literal_argument_types: Option<Vec<Option<&'static str>>>,
    pub method_value_arity: Option<usize>,
    pub method_value_parameter_types: Option<Vec<ScalaParameterTypeIdentity>>,
    pub method_value_parameter_types_authoritative: bool,
    pub type_arguments_only: bool,
}

impl ScalaCallSiteShape {
    pub fn ordinary(arities: &[usize]) -> Self {
        Self {
            lists: arities
                .iter()
                .copied()
                .map(|arity| ScalaCallArgumentList {
                    arity,
                    kind: ScalaCallArgumentListKind::Ordinary,
                })
                .collect(),
            leading_literal_argument_types: None,
            method_value_arity: None,
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        }
    }

    pub fn with_method_value_arity(mut self, arity: Option<usize>) -> Self {
        self.method_value_arity = arity;
        self.method_value_parameter_types = None;
        self.method_value_parameter_types_authoritative = false;
        self
    }

    pub fn with_method_value_shape(mut self, shape: Option<ScalaFunctionParameterShape>) -> Self {
        self.method_value_arity = shape.as_ref().map(|shape| shape.arity);
        self.method_value_parameter_types_authoritative = shape
            .as_ref()
            .is_some_and(|shape| shape.parameter_types_authoritative);
        self.method_value_parameter_types = shape.and_then(|shape| shape.parameter_types);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalaCallableUsePolicy {
    OrdinaryMethod,
    CompleteCall,
}

/// The callable namespace selected by Scala syntax before overload shapes are
/// considered.
///
/// A source-backed constructor `CodeUnit` may carry the primary constructor
/// and one or more `def this` alternatives.  Conversely, a class and its
/// companion `apply` share a source-visible name.  Keeping the site role
/// separate from call shape prevents either family from making an unrelated
/// alternative look unique merely because its arity happens to fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalaCallableSiteRole {
    Ordinary,
    ExplicitConstruction,
    PrimaryConstruction,
}

impl ScalaCallableSiteRole {
    pub fn accepts(self, declared: ScalaCallableRole) -> bool {
        match self {
            Self::Ordinary => declared == ScalaCallableRole::Ordinary,
            Self::ExplicitConstruction => matches!(
                declared,
                ScalaCallableRole::PrimaryConstructor | ScalaCallableRole::SecondaryConstructor
            ),
            Self::PrimaryConstruction => declared == ScalaCallableRole::PrimaryConstructor,
        }
    }

    pub fn use_policy(self) -> ScalaCallableUsePolicy {
        match self {
            Self::Ordinary => ScalaCallableUsePolicy::OrdinaryMethod,
            Self::ExplicitConstruction | Self::PrimaryConstruction => {
                ScalaCallableUsePolicy::CompleteCall
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalaCallShapeRelation {
    Incompatible,
    Complete,
    Partial { next_explicit_arity: CallableArity },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalaCallableParameterList {
    pub arity: CallableArity,
    pub kind: ScalaParameterListKind,
}

impl ScalaCallableParameterList {
    pub fn explicit(arity: CallableArity) -> Self {
        Self {
            arity,
            kind: ScalaParameterListKind::Explicit,
        }
    }
}

/// How many application lists a callable's declared RESULT can consume once the
/// site has filled every declared parameter list (#1853).
///
/// `def transform(flag: Boolean): Int => Int` is written `transform(true)(x)`:
/// the second list applies the returned function, not the method. The
/// declaration is the only structure that can decide such a site, so this is
/// read from the return-type node beside the parameter lists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalaDeclaredResult {
    /// Application lists the declared result type supplies directly: `A => B`
    /// supplies one, `A => B => C` two.
    function_lists: usize,
    /// Whether what remains after those lists can still be applied. An inferred
    /// result is unknown, and a named result can alias a function type or carry
    /// an `apply` member, so both stay open; a value type such as `Int` and an
    /// absent declaration do not.
    open: bool,
}

impl ScalaDeclaredResult {
    /// No declaration structure was available (an arity-only fallback shape),
    /// so nothing beyond the declared parameter lists is admitted. This is the
    /// `Default`.
    pub const UNDECLARED: Self = Self {
        function_lists: 0,
        open: false,
    };

    /// A declared result that could be a function value under some type.
    pub const OPEN: Self = Self {
        function_lists: 0,
        open: true,
    };

    pub fn accepts_application_lists(self, lists: usize) -> bool {
        self.open || lists <= self.function_lists
    }
}

pub fn scala_source_facts(source: &str) -> Option<ScalaSourceFacts> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::scala::language::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    Some(scala_source_facts_from_tree(&tree, source))
}

pub fn scala_source_facts_from_tree(tree: &tree_sitter::Tree, source: &str) -> ScalaSourceFacts {
    let mut facts = ScalaSourceFacts::default();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "val_definition" | "var_definition" | "class_parameter" => {
                if let Some(path) = node
                    .child_by_field_name("type")
                    .map(|type_node| scala_type_lookup_segments(type_node, source))
                    .filter(|segments| !segments.is_empty())
                {
                    facts
                        .field_type_paths_by_range
                        .insert((node.start_byte(), node.end_byte()), path);
                }
            }
            "type_definition" => {
                if let Some(path) = node
                    .child_by_field_name("type")
                    .map(|type_node| scala_alias_underlying_type_path(type_node, source))
                    .filter(|segments| !segments.is_empty())
                {
                    facts
                        .type_alias_paths_by_range
                        .insert((node.start_byte(), node.end_byte()), path);
                }
            }
            "function_definition" | "function_declaration" => {
                if node.kind() == "function_declaration" {
                    facts
                        .abstract_callable_ranges
                        .insert((node.start_byte(), node.end_byte()));
                }
                let mut cursor = node.walk();
                let parameter_lists = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "parameters")
                    .collect::<Vec<_>>();
                let shape = parameter_lists
                    .iter()
                    .copied()
                    .map(callable_parameter_list)
                    .collect();
                let parameter_function_arities = parameter_lists
                    .iter()
                    .copied()
                    .map(parameter_function_arities)
                    .collect();
                let parameter_defaults = parameter_lists
                    .iter()
                    .copied()
                    .map(callable_parameter_defaults)
                    .collect();
                let parameter_type_paths = parameter_lists
                    .iter()
                    .copied()
                    .map(|parameters| parameter_type_paths(parameters, source))
                    .collect();
                let parameter_type_expressions = parameter_lists
                    .iter()
                    .copied()
                    .map(|parameters| parameter_type_expressions(parameters, source))
                    .collect();
                let parameter_function_type_paths = parameter_lists
                    .iter()
                    .copied()
                    .map(|parameters| parameter_function_type_paths(parameters, source))
                    .collect();
                facts.callable_alternatives_by_range.insert(
                    (node.start_byte(), node.end_byte()),
                    ScalaCallableSourceAlternative {
                        role: node
                            .child_by_field_name("name")
                            .filter(|name| node_text(*name, source).trim() == "this")
                            .map_or(ScalaCallableRole::Ordinary, |_| {
                                ScalaCallableRole::SecondaryConstructor
                            }),
                        shape,
                        result: declared_result(node.child_by_field_name("return_type"), source),
                        parameter_defaults,
                        parameter_function_arities,
                        parameter_type_paths,
                        parameter_type_expressions,
                        parameter_function_type_paths,
                        extension_receiver_type_path: enclosing_extension_receiver_type_path(
                            node, source,
                        ),
                        return_type_path: node
                            .child_by_field_name("return_type")
                            .map(|return_type| scala_type_lookup_segments(return_type, source))
                            .filter(|segments| !segments.is_empty()),
                        return_type_expression: node.child_by_field_name("return_type").and_then(
                            |return_type| scala_type_expression_path(return_type, source),
                        ),
                    },
                );
                record_generic_owner_facts(node, source, &mut facts);
            }
            "class_definition" | "full_enum_case" => {
                let mut cursor = node.walk();
                let parameter_lists = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "class_parameters")
                    .collect::<Vec<_>>();
                let mut lists = parameter_lists
                    .iter()
                    .copied()
                    .map(callable_parameter_list)
                    .collect::<Vec<_>>();
                let mut parameter_defaults = parameter_lists
                    .iter()
                    .copied()
                    .map(callable_parameter_defaults)
                    .collect::<Vec<_>>();
                let parameter_function_arities = parameter_lists
                    .iter()
                    .copied()
                    .map(parameter_function_arities)
                    .collect::<Vec<_>>();
                let parameter_type_paths = parameter_lists
                    .iter()
                    .copied()
                    .map(|parameters| parameter_type_paths(parameters, source))
                    .collect::<Vec<_>>();
                let parameter_type_expressions = parameter_lists
                    .iter()
                    .copied()
                    .map(|parameters| parameter_type_expressions(parameters, source))
                    .collect::<Vec<_>>();
                let parameter_function_type_paths = parameter_lists
                    .iter()
                    .copied()
                    .map(|parameters| parameter_function_type_paths(parameters, source))
                    .collect::<Vec<_>>();
                if lists.is_empty() {
                    lists.push(ScalaCallableParameterList::explicit(CallableArity::exact(
                        0,
                    )));
                    parameter_defaults.push(Vec::new());
                }
                facts.callable_alternatives_by_range.insert(
                    (node.start_byte(), node.end_byte()),
                    ScalaCallableSourceAlternative {
                        role: ScalaCallableRole::PrimaryConstructor,
                        shape: lists,
                        // A constructor's result is the class being defined,
                        // and construction syntax consumes exactly the class's
                        // parameter lists.
                        result: ScalaDeclaredResult::UNDECLARED,
                        parameter_defaults,
                        parameter_function_arities,
                        parameter_type_paths,
                        parameter_type_expressions,
                        parameter_function_type_paths,
                        extension_receiver_type_path: None,
                        return_type_path: None,
                        return_type_expression: None,
                    },
                );
                let is_case_class = if node.kind() == "full_enum_case" {
                    true
                } else {
                    let mut children = node.walk();
                    node.children(&mut children)
                        .any(|child| child.kind() == "case")
                };
                if is_case_class {
                    facts
                        .case_class_ranges
                        .insert((node.start_byte(), node.end_byte()));
                }
                record_generic_owner_facts(node, source, &mut facts);
            }
            "object_definition" | "enum_definition" => {
                facts
                    .stable_owner_ranges
                    .insert((node.start_byte(), node.end_byte()));
                if node.kind() == "enum_definition" {
                    facts
                        .enum_ranges
                        .insert((node.start_byte(), node.end_byte()));
                }
                record_generic_owner_facts(node, source, &mut facts);
            }
            "trait_definition" => {
                record_generic_owner_facts(node, source, &mut facts);
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    facts
}

fn scala_alias_underlying_type_path(type_node: Node<'_>, source: &str) -> Vec<String> {
    if type_node.kind() != "compound_type" {
        return scala_type_lookup_segments(type_node, source);
    }

    let mut cursor = type_node.walk();
    let mut candidates = type_node
        .named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "refinement" | "structural_type"))
        .map(|child| scala_type_lookup_segments(child, source))
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    if candidates.len() == 1 {
        candidates.pop().expect("one compound alias base")
    } else {
        Vec::new()
    }
}

fn record_generic_owner_facts(node: Node<'_>, source: &str, facts: &mut ScalaSourceFacts) {
    let type_parameters = node
        .child_by_field_name("type_parameters")
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "type_parameters")
        })
        .map(|parameters| {
            let mut cursor = parameters.walk();
            parameters
                .named_children(&mut cursor)
                .filter(|parameter| {
                    matches!(
                        parameter.kind(),
                        "contravariant_type_parameter"
                            | "covariant_type_parameter"
                            | "identifier"
                            | "operator_identifier"
                            | "type_lambda"
                            | "wildcard"
                    )
                })
                .filter_map(|parameter| {
                    let name = parameter
                        .child_by_field_name("name")
                        .or_else(|| {
                            let mut cursor = parameter.walk();
                            parameter.named_children(&mut cursor).find(|child| {
                                matches!(child.kind(), "type_identifier" | "operator_identifier")
                            })
                        })
                        .or_else(|| {
                            let mut cursor = parameter.walk();
                            parameter
                                .named_children(&mut cursor)
                                .find(|child| child.kind() == "identifier")
                        })
                        .unwrap_or(parameter);
                    matches!(
                        name.kind(),
                        "identifier" | "operator_identifier" | "type_identifier"
                    )
                    .then(|| node_text(name, source).trim().to_string())
                    .filter(|name| !name.is_empty())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let supertypes = crate::scala::supertypes::scala_supertype_lookup_nodes(node)
        .into_iter()
        .filter_map(|(parent, _)| scala_type_expression_path(parent, source))
        .collect::<Vec<_>>();
    facts.generic_owner_facts_by_range.insert(
        (node.start_byte(), node.end_byte()),
        ScalaGenericOwnerSourceFacts {
            type_parameters,
            supertypes,
        },
    );
}

fn scala_type_expression_path(node: Node<'_>, source: &str) -> Option<ScalaTypeExpressionPath> {
    if matches!(
        node.kind(),
        "repeated_parameter_type" | "by_name_type" | "lazy_parameter_type"
    ) {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .next()
            .and_then(|element| scala_type_expression_path(element, source));
    }
    if node.kind() == "function_type" {
        let parameter_types = node.child_by_field_name("parameter_types")?;
        let mut cursor = parameter_types.walk();
        let mut arguments = parameter_types
            .named_children(&mut cursor)
            .map(|parameter| scala_type_expression_path(parameter, source))
            .collect::<Option<Vec<_>>>()?;
        arguments.push(scala_type_expression_path(
            node.child_by_field_name("return_type")?,
            source,
        )?);
        return Some(ScalaTypeExpressionPath {
            segments: vec![format!("scala.Function{}", arguments.len() - 1)],
            arguments,
        });
    }
    if node.kind() == "tuple_type" {
        let mut cursor = node.walk();
        let arguments = node
            .named_children(&mut cursor)
            .map(|element| scala_type_expression_path(element, source))
            .collect::<Option<Vec<_>>>()?;
        return Some(ScalaTypeExpressionPath {
            segments: vec![format!("scala.Tuple{}", arguments.len())],
            arguments,
        });
    }
    if matches!(node.kind(), "wildcard_type" | "wildcard") {
        return Some(ScalaTypeExpressionPath {
            segments: vec!["_".to_owned()],
            arguments: Vec::new(),
        });
    }
    if matches!(node.kind(), "generic_type" | "applied_constructor_type") {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        let arguments = match children
            .iter()
            .copied()
            .find(|child| child.kind() == "type_arguments")
        {
            Some(arguments) => {
                let mut cursor = arguments.walk();
                arguments
                    .named_children(&mut cursor)
                    .map(|argument| scala_type_expression_path(argument, source))
                    .collect::<Option<Vec<_>>>()
            }
            None => Some(Vec::new()),
        }?;
        let constructor = children.into_iter().find(|child| {
            !matches!(
                child.kind(),
                "type_arguments" | "arguments" | "annotation" | "structural_type"
            )
        })?;
        let segments = scala_type_lookup_segments(constructor, source);
        return (!segments.is_empty()).then_some(ScalaTypeExpressionPath {
            segments,
            arguments,
        });
    }
    if matches!(node.kind(), "annotated_type") {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .find(|child| child.kind() != "annotation")
            .and_then(|child| scala_type_expression_path(child, source));
    }
    if !matches!(
        node.kind(),
        "identifier"
            | "operator_identifier"
            | "type_identifier"
            | "stable_type_identifier"
            | "projected_type"
            | "singleton_type"
    ) {
        return None;
    }
    let segments = scala_type_lookup_segments(node, source);
    (!segments.is_empty()).then_some(ScalaTypeExpressionPath {
        segments,
        arguments: Vec::new(),
    })
}

/// Return only the value binders introduced by a Scala pattern.
///
/// Pattern syntax mixes declaration positions with type paths, extractor
/// owners, infix operators, and named-pattern labels.  A generic identifier
/// walk therefore cannot define lexical scope correctly.  This parser-backed
/// collector follows the grammar's pattern fields and deliberately excludes
/// every non-binding role.
pub fn scala_pattern_binder_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    scala_pattern_binder_nodes(node)
        .into_iter()
        .filter_map(|node| {
            let name = node_text(node, source).trim();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

fn scala_pattern_binder_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut binders = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" | "operator_identifier" => binders.push(node),
            "typed_pattern" | "repeat_pattern" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    stack.push(pattern);
                }
            }
            "case_class_pattern" => {
                let mut cursor = node.walk();
                let mut patterns = node
                    .children_by_field_name("pattern", &mut cursor)
                    .collect::<Vec<_>>();
                patterns.reverse();
                stack.extend(patterns);
            }
            "capture_pattern" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    stack.push(pattern);
                }
                if let Some(name) = node.child_by_field_name("name") {
                    stack.push(name);
                }
            }
            "infix_pattern" => {
                if let Some(right) = node.child_by_field_name("right") {
                    stack.push(right);
                }
                if let Some(left) = node.child_by_field_name("left") {
                    stack.push(left);
                }
            }
            // Scala 3 named extractor arguments use `label = pattern`; the
            // leading identifier names the extractor field and is not a new
            // local.  The grammar does not expose fields for this node, so skip
            // its first named child and recurse into the value pattern only.
            "named_pattern" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor).skip(1).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children);
            }
            "stable_identifier"
            | "stable_type_identifier"
            | "type_identifier"
            | "given_pattern"
            | "literal"
            | "wildcard" => {}
            _ => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children);
            }
        }
    }
    binders
}

/// Whether this exact identifier node declares a case-pattern value binder.
/// Comparing node identities matters when a binder intentionally has the same
/// spelling as a qualifier in its own type annotation.
pub fn is_scala_case_pattern_binder(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "operator_identifier") {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "case_clause" {
            return parent
                .child_by_field_name("pattern")
                .filter(|pattern| {
                    pattern.start_byte() <= node.start_byte()
                        && node.end_byte() <= pattern.end_byte()
                })
                .is_some_and(|pattern| {
                    scala_pattern_binder_nodes(pattern)
                        .into_iter()
                        .any(|binder| binder.id() == node.id())
                });
        }
        current = parent.parent();
    }
    false
}

/// Return the parser-derived lookup paths of every direct alternative in a
/// Scala 3 union type. Tree-sitter represents `A | B` as an `infix_type`; only
/// the `|` operator is flattened, so unrelated infix/compound type syntax is
/// never reinterpreted as a union.
pub fn scala_union_type_alternative_paths(
    node: Node<'_>,
    source: &str,
) -> Option<Vec<Vec<String>>> {
    if !is_union_type(node, source) {
        return None;
    }

    let mut alternatives = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if is_union_type(current, source) {
            stack.push(current.child_by_field_name("right")?);
            stack.push(current.child_by_field_name("left")?);
            continue;
        }
        let path = scala_type_lookup_segments(current, source);
        if path.is_empty() {
            return None;
        }
        alternatives.push(path);
    }
    (!alternatives.is_empty()).then_some(alternatives)
}

fn is_union_type(node: Node<'_>, source: &str) -> bool {
    node.kind() == "infix_type"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source).trim() == "|")
}

fn enclosing_extension_receiver_type_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "extension_definition" {
            let parameters = ancestor.child_by_field_name("parameters")?;
            let mut cursor = parameters.walk();
            return parameters
                .named_children(&mut cursor)
                .find(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
                .and_then(|parameter| parameter.child_by_field_name("type"))
                .map(|type_node| scala_type_lookup_segments(type_node, source))
                .filter(|segments| !segments.is_empty());
        }
        if matches!(
            ancestor.kind(),
            "function_definition" | "function_declaration"
        ) {
            return None;
        }
        current = ancestor.parent();
    }
    None
}

fn callable_arity_for_parameters(parameters: Node<'_>) -> CallableArity {
    let mut total = 0usize;
    let mut required = 0usize;
    let mut repeated = false;
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !matches!(parameter.kind(), "parameter" | "class_parameter") {
            continue;
        }
        total += 1;
        let is_repeated = parameter
            .child_by_field_name("type")
            .is_some_and(contains_repeated_parameter_type);
        repeated |= is_repeated;
        if parameter.child_by_field_name("default_value").is_none() && !is_repeated {
            required += 1;
        }
    }
    CallableArity::new(required, total, repeated)
}

fn callable_parameter_list(parameters: Node<'_>) -> ScalaCallableParameterList {
    let mut cursor = parameters.walk();
    let kind = if parameters
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "using" | "implicit"))
    {
        ScalaParameterListKind::Contextual
    } else {
        ScalaParameterListKind::Explicit
    };
    ScalaCallableParameterList {
        arity: callable_arity_for_parameters(parameters),
        kind,
    }
}

fn callable_parameter_defaults(parameters: Node<'_>) -> Vec<bool> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
        .map(|parameter| parameter.child_by_field_name("default_value").is_some())
        .collect()
}

fn parameter_function_arities(parameters: Node<'_>) -> Vec<Option<usize>> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
        .map(|parameter| {
            parameter
                .child_by_field_name("type")
                .and_then(function_type_arity)
        })
        .collect()
}

fn parameter_type_paths(parameters: Node<'_>, source: &str) -> Vec<Option<Vec<String>>> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
        .map(|parameter| {
            parameter
                .child_by_field_name("type")
                .and_then(|type_node| named_type_path(type_node, source))
        })
        .collect()
}

fn parameter_type_expressions(
    parameters: Node<'_>,
    source: &str,
) -> Vec<Option<ScalaTypeExpressionPath>> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
        .map(|parameter| {
            parameter
                .child_by_field_name("type")
                .and_then(|type_node| scala_type_expression_path(type_node, source))
        })
        .collect()
}

fn parameter_function_type_paths(
    parameters: Node<'_>,
    source: &str,
) -> Vec<Option<Vec<Option<Vec<String>>>>> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
        .map(|parameter| {
            parameter
                .child_by_field_name("type")
                .and_then(|type_node| function_parameter_type_paths(type_node, source))
        })
        .collect()
}

fn function_parameter_type_paths(
    type_node: Node<'_>,
    source: &str,
) -> Option<Vec<Option<Vec<String>>>> {
    if type_node.kind() != "function_type" {
        return None;
    }
    let parameter_types = type_node.child_by_field_name("parameter_types")?;
    let mut cursor = parameter_types.walk();
    Some(
        parameter_types
            .named_children(&mut cursor)
            .map(|parameter_type| named_type_path(parameter_type, source))
            .collect(),
    )
}

/// Preserve only parser-proven named type paths. Applied, function, union, and
/// other compound types need richer structural comparison; treating only
/// their leading constructor as exact would make same-arity overloads unsafe.
fn named_type_path(type_node: Node<'_>, source: &str) -> Option<Vec<String>> {
    if !matches!(
        type_node.kind(),
        "type_identifier" | "stable_type_identifier" | "projected_type"
    ) {
        return None;
    }
    let path = scala_type_lookup_segments(type_node, source);
    (!path.is_empty()).then_some(path)
}

fn function_type_arity(type_node: Node<'_>) -> Option<usize> {
    if type_node.kind() != "function_type" {
        return None;
    }
    let parameter_types = type_node.child_by_field_name("parameter_types")?;
    let mut cursor = parameter_types.walk();
    Some(parameter_types.named_children(&mut cursor).count())
}

fn contains_repeated_parameter_type(node: Node<'_>) -> bool {
    subtree_contains(node, |current| current.kind() == "repeated_parameter_type")
}

/// Scala value types that no application list can consume. Every other named
/// type stays applicable: it can alias a function type, and `Seq`, `Map`,
/// `String` and friends carry an `apply` member of their own.
const NON_APPLICABLE_RESULT_TYPES: [&str; 9] = [
    "Unit", "Boolean", "Byte", "Short", "Int", "Long", "Float", "Double", "Char",
];

/// Read from the declaration how many application lists its result can consume
/// beyond the declared parameter lists (#1853).
fn declared_result(return_type: Option<Node<'_>>, source: &str) -> ScalaDeclaredResult {
    // An inferred result rules nothing out.
    let Some(return_type) = return_type else {
        return ScalaDeclaredResult::OPEN;
    };
    let mut result = return_type;
    let mut function_lists = 0usize;
    while result.kind() == "function_type" {
        let Some(next) = result.child_by_field_name("return_type") else {
            break;
        };
        function_lists += 1;
        result = next;
    }
    ScalaDeclaredResult {
        function_lists,
        open: result.kind() != "type_identifier"
            || !NON_APPLICABLE_RESULT_TYPES.contains(&node_text(result, source).trim()),
    }
}

pub fn parenthesized_arity(source: &str) -> Option<usize> {
    scala_parenthesized_arity(source)
}

pub fn scala_import_path(info: &ImportInfo) -> Option<String> {
    crate::scala::wildcard_imports::scala_import_path(info)
}

pub struct ScalaImportContextIndex {
    segments: Vec<ScalaImportContextSegment>,
}

pub struct ScalaPackageContextIndex {
    segments: Vec<ScalaPackageContextSegment>,
}

struct ScalaPackageContextSegment {
    start_byte: usize,
    prefixes: Vec<String>,
}

impl ScalaPackageContextIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut boundaries = vec![0, root.end_byte()];
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "package_clause" {
                boundaries.push(node.start_byte());
                boundaries.push(node.end_byte());
                if let Some(body) = node.child_by_field_name("body") {
                    boundaries.push(body.start_byte());
                    boundaries.push(body.end_byte());
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        boundaries.sort_unstable();
        boundaries.dedup();

        let mut segments = Vec::<ScalaPackageContextSegment>::new();
        for start_byte in boundaries {
            let prefixes = scala_package_prefixes_at(root, source, start_byte);
            if let Some(last) = segments.last()
                && last.prefixes == prefixes
            {
                continue;
            }
            segments.push(ScalaPackageContextSegment {
                start_byte,
                prefixes,
            });
        }
        if segments.is_empty() {
            segments.push(ScalaPackageContextSegment {
                start_byte: 0,
                prefixes: Vec::new(),
            });
        }
        Self { segments }
    }

    pub fn advance_to(&self, byte: usize, cursor: &mut usize) -> &[String] {
        while *cursor + 1 < self.segments.len() && self.segments[*cursor + 1].start_byte <= byte {
            *cursor += 1;
        }
        &self.segments[*cursor].prefixes
    }

    pub fn prefixes_at(&self, byte: usize) -> &[String] {
        let index = self
            .segments
            .partition_point(|segment| segment.start_byte <= byte)
            .saturating_sub(1);
        &self.segments[index].prefixes
    }
}

pub fn scala_import_is_visible_at_byte(import: &ImportInfo, byte: usize) -> bool {
    let Some(path) = import.path.as_ref() else {
        return true;
    };
    let end_byte = path
        .lexical_scopes
        .last()
        .map(|scope| scope.end_byte)
        .unwrap_or(usize::MAX);
    path.declaration_start_byte <= byte && byte < end_byte
}

struct ScalaImportContextSegment {
    start_byte: usize,
    import_indices: Vec<usize>,
}

impl ScalaImportContextIndex {
    pub fn new(imports: &[ImportInfo], file_end_byte: usize) -> Self {
        let mut events = Vec::with_capacity(imports.len() * 2);
        for (index, import) in imports.iter().enumerate() {
            let Some(path) = import.path.as_ref() else {
                events.push((0, true, index));
                events.push((file_end_byte, false, index));
                continue;
            };
            let end_byte = path
                .lexical_scopes
                .last()
                .map(|scope| scope.end_byte)
                .unwrap_or(file_end_byte);
            if path.declaration_start_byte < end_byte {
                events.push((path.declaration_start_byte, true, index));
                events.push((end_byte, false, index));
            }
        }
        events.sort_by_key(|(byte, enters, index)| (*byte, *enters, *index));

        let mut active = vec![false; imports.len()];
        let mut segments = vec![ScalaImportContextSegment {
            start_byte: 0,
            import_indices: Vec::new(),
        }];
        let mut cursor = 0;
        while cursor < events.len() {
            let byte = events[cursor].0;
            while cursor < events.len() && events[cursor].0 == byte {
                let (_, enters, index) = events[cursor];
                active[index] = enters;
                cursor += 1;
            }
            let import_indices = active
                .iter()
                .enumerate()
                .filter_map(|(index, active)| active.then_some(index))
                .collect();
            if let Some(last) = segments.last_mut().filter(|last| last.start_byte == byte) {
                last.import_indices = import_indices;
            } else {
                segments.push(ScalaImportContextSegment {
                    start_byte: byte,
                    import_indices,
                });
            }
        }
        Self { segments }
    }

    pub fn advance_to(&self, byte: usize, cursor: &mut usize) -> &[usize] {
        while *cursor + 1 < self.segments.len() && self.segments[*cursor + 1].start_byte <= byte {
            *cursor += 1;
        }
        &self.segments[*cursor].import_indices
    }
}

pub fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "operator_identifier"
    )
}

pub fn is_bare_companion_method_value_reference(node: Node<'_>) -> bool {
    if node.kind() != "identifier" || is_call_function_reference(node) {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "arguments" => true,
        "val_definition" | "var_definition" => parent.child_by_field_name("value") == Some(node),
        _ => false,
    }
}

pub fn is_type_like_reference(node: Node<'_>, source: &str) -> bool {
    node.kind() == "type_identifier"
        || is_constructor_like_reference(node, source)
        || is_anonymous_instance_mixin_type_reference(node, source)
        || is_infix_type_operator_reference(node)
        || parent_kind(node).is_some_and(|kind| {
            matches!(
                kind,
                "type" | "generic_type" | "parameterized_type" | "extends_clause"
            )
        })
}

/// Tree-sitter parses Scala 2-style anonymous mixins such as
/// `new Base with First with Mixin` as a left-associated `infix_expression`
/// chain. Only the right-hand operands of a `with` chain rooted at an
/// `instance_expression` are type roles; an ordinary term infix expression is
/// not.
fn is_anonymous_instance_mixin_type_reference(node: Node<'_>, source: &str) -> bool {
    let mut operand = node;
    while let Some(parent) = operand.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "generic_type" | "applied_constructor_type" | "annotated_type" | "type"
        ) && (parent.child_by_field_name("type") == Some(operand)
            || parent.named_child(0) == Some(operand))
    }) {
        operand = parent;
    }

    let Some(expression) = operand.parent().filter(|parent| {
        parent.kind() == "infix_expression"
            && parent.child_by_field_name("right") == Some(operand)
            && parent
                .child_by_field_name("operator")
                .is_some_and(|operator| node_text(operator, source).trim() == "with")
    }) else {
        return false;
    };

    let Some(mut left) = expression.child_by_field_name("left") else {
        return false;
    };
    loop {
        let mut constructed = left;
        while constructed.kind() == "call_expression" {
            let Some(function) = constructed.child_by_field_name("function") else {
                return false;
            };
            constructed = function;
        }
        if constructed.kind() == "instance_expression" {
            return true;
        }
        let Some(previous) = left.child_by_field_name("left").filter(|_| {
            left.kind() == "infix_expression"
                && left
                    .child_by_field_name("operator")
                    .is_some_and(|operator| node_text(operator, source).trim() == "with")
        }) else {
            return false;
        };
        left = previous;
    }
}

/// In `A TypeOperator B`, the grammar exposes `TypeOperator` as the exact
/// `operator` field of `infix_type`, even when it is an ordinary `identifier`.
pub fn is_infix_type_operator_reference(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "infix_type" && parent.child_by_field_name("operator") == Some(node)
    })
}

pub fn is_scala_object_reference(node: Node<'_>) -> bool {
    is_singleton_type_reference(node)
        || is_stable_type_qualifier(node)
        || qualified_stable_type_expression_shape_role(node).is_some_and(|role| {
            matches!(
                role,
                ScalaQualifiedStableTypeRole::Apply | ScalaQualifiedStableTypeRole::Extractor
            )
        })
        || is_extractor_reference(node)
        || is_infix_pattern_operator(node)
        || is_field_expression_value(node)
        || is_bare_term_reference(node)
}

fn qualified_stable_type_expression_shape_role(
    node: Node<'_>,
) -> Option<ScalaQualifiedStableTypeRole> {
    let mut stable = node.parent()?;
    if stable.kind() != "stable_type_identifier" {
        return None;
    }
    let mut cursor = stable.walk();
    if stable.named_children(&mut cursor).last() != Some(node) {
        return None;
    }
    while let Some(parent) = stable
        .parent()
        .filter(|parent| parent.kind() == "stable_type_identifier")
    {
        let mut cursor = parent.walk();
        if parent.named_children(&mut cursor).last() != Some(stable) {
            break;
        }
        stable = parent;
    }
    let mut expression = stable;
    while let Some(parent) = expression.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "generic_type" | "applied_constructor_type" | "annotated_type" | "type"
        )
    }) {
        expression = parent;
    }
    Some(
        expression
            .parent()
            .map(|parent| {
                if parent.kind() == "call_expression"
                    && parent.child_by_field_name("function") == Some(expression)
                {
                    ScalaQualifiedStableTypeRole::Apply
                } else if parent.kind() == "case_class_pattern"
                    && parent.child_by_field_name("type") == Some(expression)
                {
                    ScalaQualifiedStableTypeRole::Extractor
                } else if parent.kind() == "instance_expression" {
                    ScalaQualifiedStableTypeRole::Constructor
                } else {
                    ScalaQualifiedStableTypeRole::Type
                }
            })
            .unwrap_or(ScalaQualifiedStableTypeRole::Type),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScalaQualifiedStableTypeRole {
    Type,
    Apply,
    Extractor,
    Constructor,
}

pub struct ScalaQualifiedStableTypeReference<'tree> {
    pub segments: Vec<String>,
    pub expression: Node<'tree>,
    pub role: ScalaQualifiedStableTypeRole,
}

pub fn qualified_stable_type_reference<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<ScalaQualifiedStableTypeReference<'tree>> {
    let (expression, role, segments) = if let Some((expression, role, segments)) =
        qualified_stable_type_expression_role(node, source)
    {
        (expression, role, segments)
    } else {
        qualified_stable_term_application(node, source)?
    };
    if segments.len() <= 1 {
        return None;
    }

    Some(ScalaQualifiedStableTypeReference {
        segments,
        expression,
        role,
    })
}

fn qualified_stable_term_application<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, ScalaQualifiedStableTypeRole, Vec<String>)> {
    let mut expression = node.parent()?;
    if expression.kind() != "field_expression"
        || expression.child_by_field_name("field") != Some(node)
    {
        return None;
    }

    let mut fields = Vec::new();
    let mut path = expression;
    while path.kind() == "field_expression" {
        fields.push(path.child_by_field_name("field")?);
        path = path.child_by_field_name("value")?;
    }
    if !matches!(path.kind(), "identifier" | "type_identifier") {
        return None;
    }
    fields.push(path);
    fields.reverse();
    let segments = fields
        .into_iter()
        .map(|segment| node_text(segment, source).trim().to_string())
        .collect::<Vec<_>>();
    if segments.iter().any(String::is_empty) {
        return None;
    }

    if expression.parent().is_some_and(|parent| {
        parent.kind() == "generic_function"
            && parent.child_by_field_name("function") == Some(expression)
    }) {
        expression = expression.parent()?;
    }
    let call = expression.parent()?;
    if call.kind() != "call_expression" || call.child_by_field_name("function") != Some(expression)
    {
        return None;
    }
    Some((expression, ScalaQualifiedStableTypeRole::Apply, segments))
}

fn qualified_stable_type_expression_role<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, ScalaQualifiedStableTypeRole, Vec<String>)> {
    let mut expression;
    let segments = if let Some(mut stable) = node
        .parent()
        .filter(|parent| parent.kind() == "stable_type_identifier")
    {
        let mut cursor = stable.walk();
        if stable.named_children(&mut cursor).last() != Some(node) {
            return None;
        }
        while let Some(parent) = stable
            .parent()
            .filter(|parent| parent.kind() == "stable_type_identifier")
        {
            let mut cursor = parent.walk();
            if parent.named_children(&mut cursor).last() != Some(stable) {
                break;
            }
            stable = parent;
        }
        expression = stable;
        scala_type_lookup_segments(stable, source)
    } else {
        let stable = node
            .parent()
            .filter(|parent| parent.kind() == "stable_identifier")?;
        let reference = stable_identifier_reference(node, source)?;
        expression = stable;
        reference.segments
    };
    while let Some(parent) = expression.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "generic_type" | "applied_constructor_type" | "annotated_type" | "type"
        )
    }) {
        expression = parent;
    }
    let role = expression
        .parent()
        .map(|parent| {
            if parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(expression)
            {
                ScalaQualifiedStableTypeRole::Apply
            } else if parent.kind() == "case_class_pattern"
                && parent.child_by_field_name("type") == Some(expression)
            {
                ScalaQualifiedStableTypeRole::Extractor
            } else if parent.kind() == "instance_expression" {
                ScalaQualifiedStableTypeRole::Constructor
            } else {
                ScalaQualifiedStableTypeRole::Type
            }
        })
        .unwrap_or(ScalaQualifiedStableTypeRole::Type);
    Some((expression, role, segments))
}

pub fn is_scala_class_reference(node: Node<'_>, source: &str) -> bool {
    is_type_like_reference(node, source)
        && !is_singleton_type_reference(node)
        && !is_stable_type_qualifier(node)
        && !is_extractor_reference(node)
        && !is_infix_pattern_operator(node)
        && !node.parent().is_some_and(|parent| {
            parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node)
        })
}

fn is_singleton_type_reference(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "singleton_type")
}

pub fn is_stable_type_qualifier(node: Node<'_>) -> bool {
    let Some(parent) = node
        .parent()
        .filter(|parent| parent.kind() == "stable_type_identifier")
    else {
        return false;
    };
    let mut cursor = parent.walk();
    parent.named_children(&mut cursor).last() != Some(node)
}

pub fn is_extractor_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "case_class_pattern" {
        return parent
            .named_child(0)
            .is_some_and(|constructor| constructor == node);
    }
    if parent.kind() != "call_expression" || parent.child_by_field_name("function") != Some(node) {
        return false;
    }
    let mut current = Some(parent);
    while let Some(ancestor) = current {
        if ancestor.kind() == "case_clause" {
            return ancestor
                .child_by_field_name("pattern")
                .is_some_and(|pattern| {
                    pattern.start_byte() <= node.start_byte()
                        && node.end_byte() <= pattern.end_byte()
                });
        }
        current = ancestor.parent();
    }
    false
}

pub fn is_infix_pattern_operator(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "infix_pattern" && parent.child_by_field_name("operator") == Some(node)
    })
}

pub fn is_call_function_reference(node: Node<'_>) -> bool {
    let mut expression = node;
    if let Some(generic) = expression.parent().filter(|parent| {
        parent.kind() == "generic_function"
            && parent.child_by_field_name("function") == Some(expression)
    }) {
        expression = generic;
    }
    expression.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(expression)
    })
}

/// Peel the type-argument wrapper from a call's parser-recorded function.
///
/// Scala `Factory[A](...)` is a `call_expression` whose function is a
/// `generic_function`, while `Factory(...)` exposes the identifier directly.
/// Call-role consumers must classify both through the same reference node so
/// generic applications retain the identifier's exact source range.
pub fn invocation_function_reference(function: Node<'_>) -> Node<'_> {
    if function.kind() == "generic_function" {
        function.child_by_field_name("function").unwrap_or(function)
    } else {
        function
    }
}

pub fn is_terminal_stable_field_reference(node: Node<'_>) -> bool {
    let Some(field) = node.parent().filter(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node)
    }) else {
        return false;
    };
    !field.parent().is_some_and(|parent| {
        parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(field)
    })
}

/// Resolve a stable object path from its tree-sitter structure. The root and
/// each child segment are resolved independently so callers never infer object
/// identity by splitting source text.
pub fn resolve_stable_object_expression<T>(
    mut node: Node<'_>,
    source: &str,
    mut resolve_root: impl FnMut(&str) -> Option<T>,
    mut resolve_child: impl FnMut(&T, &str) -> Option<T>,
) -> Option<T> {
    let mut fields = Vec::new();
    while node.kind() == "field_expression" {
        fields.push(node.child_by_field_name("field")?);
        node = node.child_by_field_name("value")?;
    }
    if !matches!(node.kind(), "identifier" | "type_identifier") {
        return None;
    }
    let root = node_text(node, source).trim();
    if root.is_empty() {
        return None;
    }
    let mut resolved = resolve_root(root)?;
    for field in fields.into_iter().rev() {
        let field = node_text(field, source).trim();
        if field.is_empty() {
            return None;
        }
        resolved = resolve_child(&resolved, field)?;
    }
    Some(resolved)
}

pub struct ScalaStableIdentifierReference {
    pub segments: Vec<String>,
}

/// Return the ordered identifier leaves of the outermost `stable_identifier`
/// containing `node`, but only when `node` is that path's terminal leaf. Scala
/// represents these paths recursively, so walking named children preserves the
/// grammar's structure without reparsing the source spelling.
pub fn stable_identifier_reference<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<ScalaStableIdentifierReference> {
    let mut expression = node
        .parent()
        .filter(|parent| parent.kind() == "stable_identifier")?;
    while let Some(parent) = expression
        .parent()
        .filter(|parent| parent.kind() == "stable_identifier")
    {
        expression = parent;
    }

    let mut leaves = Vec::new();
    let mut stack = vec![expression];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "identifier" | "operator_identifier") {
            leaves.push(current);
            continue;
        }
        if current.kind() != "stable_identifier" {
            return None;
        }
        for index in (0..current.named_child_count()).rev() {
            stack.push(current.named_child(index)?);
        }
    }
    if leaves.last().copied() != Some(node) {
        return None;
    }
    let segments = leaves
        .into_iter()
        .map(|leaf| node_text(leaf, source).trim().to_string())
        .collect::<Vec<_>>();
    if segments.len() < 2 || segments.iter().any(String::is_empty) {
        return None;
    }
    Some(ScalaStableIdentifierReference { segments })
}

/// Return the shortest parser-backed stable path ending at `node`. Unlike
/// `stable_identifier_reference`, this preserves intermediate selections in a
/// nested chain so a file-major walk can emit every field edge exactly once.
pub fn stable_identifier_prefix_reference<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<ScalaStableIdentifierReference> {
    let mut expression = node
        .parent()
        .filter(|parent| parent.kind() == "stable_identifier")?;
    loop {
        let mut leaves = Vec::new();
        let mut stack = vec![expression];
        while let Some(current) = stack.pop() {
            if matches!(current.kind(), "identifier" | "operator_identifier") {
                leaves.push(current);
                continue;
            }
            if current.kind() != "stable_identifier" {
                return None;
            }
            for index in (0..current.named_child_count()).rev() {
                stack.push(current.named_child(index)?);
            }
        }
        if leaves.last().copied() == Some(node) {
            let segments = leaves
                .into_iter()
                .map(|leaf| node_text(leaf, source).trim().to_string())
                .collect::<Vec<_>>();
            if segments.len() >= 2 && segments.iter().all(|segment| !segment.is_empty()) {
                return Some(ScalaStableIdentifierReference { segments });
            }
        }
        expression = expression
            .parent()
            .filter(|parent| parent.kind() == "stable_identifier")?;
    }
}

/// Return the parser-backed stable type path ending at an intermediate
/// qualifier. For example, visiting `ReferenceOr` in
/// `OpenAPI.ReferenceOr.Or[Int]` yields `[OpenAPI, ReferenceOr]`.
pub fn stable_type_prefix_reference<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<ScalaStableIdentifierReference> {
    let mut stable = node
        .parent()
        .filter(|parent| parent.kind() == "stable_type_identifier")?;
    while let Some(parent) = stable
        .parent()
        .filter(|parent| parent.kind() == "stable_type_identifier")
    {
        let mut cursor = parent.walk();
        if parent.named_children(&mut cursor).last() != Some(stable) {
            break;
        }
        stable = parent;
    }

    let mut leaves = Vec::new();
    let mut stack = vec![stable];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "identifier" | "type_identifier") {
            leaves.push(current);
            continue;
        }
        if current.kind() != "stable_type_identifier" {
            return None;
        }
        for index in (0..current.named_child_count()).rev() {
            stack.push(current.named_child(index)?);
        }
    }
    let node_index = leaves.iter().position(|leaf| *leaf == node)?;
    if node_index == 0 || node_index + 1 >= leaves.len() {
        return None;
    }
    let segments = leaves[..=node_index]
        .iter()
        .map(|leaf| node_text(*leaf, source).trim().to_string())
        .collect::<Vec<_>>();
    if segments.iter().any(String::is_empty) {
        return None;
    }
    Some(ScalaStableIdentifierReference { segments })
}

/// Return the parser-backed stable field path whose terminal leaf is an
/// intermediate qualifier of a longer selection. For example, visiting `Sink`
/// in `scaladsl.Sink.foreachAsync` yields `[scaladsl, Sink]`. Requiring the
/// enclosing field expression to be the value of another field expression
/// keeps ordinary terminal selections under their existing receiver/member
/// dispatch.
pub fn intermediate_field_qualifier_reference<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<ScalaStableIdentifierReference> {
    let expression = node.parent().filter(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node)
    })?;
    if !expression.parent().is_some_and(|parent| {
        parent.kind() == "field_expression"
            && parent.child_by_field_name("value") == Some(expression)
    }) {
        return None;
    }

    let mut fields = Vec::new();
    let mut path = expression;
    while path.kind() == "field_expression" {
        fields.push(path.child_by_field_name("field")?);
        path = path.child_by_field_name("value")?;
    }
    if !matches!(path.kind(), "identifier" | "type_identifier") {
        return None;
    }
    fields.push(path);
    fields.reverse();
    let segments = fields
        .into_iter()
        .map(|segment| node_text(segment, source).trim().to_string())
        .collect::<Vec<_>>();
    (segments.len() >= 2 && segments.iter().all(|segment| !segment.is_empty()))
        .then_some(ScalaStableIdentifierReference { segments })
}

fn is_bare_term_reference(node: Node<'_>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "class_definition"
        | "object_definition"
        | "trait_definition"
        | "enum_definition"
        | "function_declaration"
        | "type_parameters"
        | "import_declaration"
        | "stable_type_identifier"
        | "singleton_type"
        | "case_class_pattern"
        | "infix_pattern" => false,
        "parameter" | "class_parameter" => {
            parent.child_by_field_name("default_value") == Some(node)
        }
        "function_definition" => parent.child_by_field_name("body") == Some(node),
        "val_definition" | "var_definition" => parent.child_by_field_name("pattern") != Some(node),
        "field_expression" => parent.child_by_field_name("field") != Some(node),
        _ => true,
    }
}

pub fn is_field_expression_value(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("value") == Some(node)
    })
}

pub fn is_qualified_stable_root(node: Node<'_>) -> bool {
    if is_field_expression_value(node) {
        return true;
    }
    let Some(mut path) = node.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "stable_identifier" | "stable_type_identifier"
        )
    }) else {
        return false;
    };
    loop {
        let Some(first) = path.named_child(0) else {
            return false;
        };
        if matches!(
            first.kind(),
            "identifier" | "operator_identifier" | "type_identifier"
        ) {
            return first == node;
        }
        if !matches!(first.kind(), "stable_identifier" | "stable_type_identifier") {
            return false;
        }
        path = first;
    }
}

pub fn is_constructor_like_reference(node: Node<'_>, source: &str) -> bool {
    let prefix = source[..node.start_byte()].trim_end();
    prefix.ends_with("new")
        || parent_kind(node).is_some_and(|kind| matches!(kind, "call_expression" | "type"))
}

pub fn parent_kind(node: Node<'_>) -> Option<&str> {
    node.parent().map(|parent| parent.kind())
}

pub fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub fn field_expression_for_member(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    if parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node) {
        Some(parent)
    } else {
        None
    }
}

pub fn member_qualifier_node(node: Node<'_>) -> Option<Node<'_>> {
    field_expression_for_member(node)?.child_by_field_name("value")
}

pub fn member_qualifier(node: Node<'_>, source: &str) -> Option<String> {
    member_qualifier_node(node)
        .map(|value| {
            node_text(value, source)
                .trim()
                .trim_end_matches('$')
                .to_string()
        })
        .filter(|qualifier| !qualifier.is_empty())
}

pub fn is_owner_qualified_this(qualifier: Node<'_>, source: &str) -> bool {
    qualifier.kind() == "field_expression"
        && qualifier
            .child_by_field_name("field")
            .is_some_and(|field| node_text(field, source).trim() == "this")
}

pub fn stable_type_qualifier(node: Node<'_>, source: &str) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "stable_type_identifier" || parent.end_byte() != node.end_byte() {
        return None;
    }
    let prefix = source[parent.start_byte()..node.start_byte()]
        .trim()
        .trim_end_matches('.')
        .trim_end_matches('$')
        .to_string();
    (!prefix.is_empty()).then_some(prefix)
}

pub fn call_arities_for_reference(node: Node<'_>) -> Option<Vec<usize>> {
    call_site_shape_for_reference(node)
        .map(|shape| shape.lists.into_iter().map(|list| list.arity).collect())
}

pub fn call_site_shape_for_reference(node: Node<'_>) -> Option<ScalaCallSiteShape> {
    // Qualified extractor types may wrap the focused terminal in stable and
    // applied type nodes before reaching the case-class pattern.
    let mut pattern_type = node;
    while let Some(parent) = pattern_type.parent().filter(|parent| {
        if parent.kind() == "stable_type_identifier" {
            let mut cursor = parent.walk();
            return parent.named_children(&mut cursor).last() == Some(pattern_type);
        }
        matches!(
            parent.kind(),
            "generic_type" | "applied_constructor_type" | "annotated_type" | "type"
        )
    }) {
        pattern_type = parent;
    }
    if let Some(parent) = pattern_type.parent().filter(|parent| {
        parent.kind() == "case_class_pattern"
            && parent.child_by_field_name("type") == Some(pattern_type)
    }) {
        // In Scala 3 indented cases tree-sitter exposes the constructor type
        // through the same `pattern` field as the arguments. Counting named
        // children other than the parser-proven type is stable in both forms.
        let mut cursor = parent.walk();
        let arity = parent
            .named_children(&mut cursor)
            .filter(|child| *child != pattern_type)
            .count();
        return Some(ScalaCallSiteShape::ordinary(&[arity]));
    }
    let parent = node.parent()?;
    if parent.kind() == "infix_pattern" && parent.child_by_field_name("operator") == Some(node) {
        return Some(ScalaCallSiteShape::ordinary(&[1]));
    }
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return Some(ScalaCallSiteShape {
            lists: vec![ScalaCallArgumentList {
                arity: 1,
                kind: ScalaCallArgumentListKind::Ordinary,
            }],
            leading_literal_argument_types: None,
            method_value_arity: None,
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        });
    }
    let mut expression = field_expression_for_member(node).unwrap_or(node);
    let mut leading_literal_argument_types = None;
    let mut type_arguments_only = false;
    while let Some(generic) = expression.parent().filter(|generic| {
        (generic.kind() == "generic_function"
            && generic.child_by_field_name("function") == Some(expression))
            || (generic.kind() == "generic_type"
                && generic.child_by_field_name("type") == Some(expression))
    }) {
        type_arguments_only |= generic.kind() == "generic_function";
        expression = generic;
    }
    let mut lists = Vec::new();
    // `new C(args) with T` does not parse as a `call_expression` under the
    // `instance_expression`: tree-sitter-scala wraps the first parent in an
    // `applied_constructor_type` that owns the argument list, and hangs that
    // off a `compound_type`. It is still a constructor application of `C`, so
    // its arguments are this reference's call-site shape (#1857). The same
    // node spells a parent constructor in an `extends` clause.
    if let Some(applied) = expression.parent().filter(|parent| {
        parent.kind() == "applied_constructor_type" && parent.named_child(0) == Some(expression)
    }) {
        let mut cursor = applied.walk();
        if let Some(arguments) = applied
            .named_children(&mut cursor)
            .find(|child| child.kind() == "arguments")
        {
            let list = call_argument_list(arguments);
            if list.kind == ScalaCallArgumentListKind::Ordinary {
                leading_literal_argument_types = literal_argument_types(arguments);
            }
            lists.push(list);
        }
        expression = applied;
    }
    if let Some(instance) = expression
        .parent()
        .filter(|parent| parent.kind() == "instance_expression")
    {
        let arguments = instance.child_by_field_name("arguments").or_else(|| {
            let mut cursor = instance.walk();
            instance
                .named_children(&mut cursor)
                .find(|child| child.kind() == "arguments")
        });
        if let Some(arguments) = arguments {
            let list = call_argument_list(arguments);
            if lists.is_empty() && list.kind == ScalaCallArgumentListKind::Ordinary {
                leading_literal_argument_types = literal_argument_types(arguments);
            }
            lists.push(list);
        } else {
            // `new T:` / `new T { ... }` has no `arguments` child, but it still
            // invokes the argumentless primary constructor.
            lists.push(ScalaCallArgumentList {
                arity: 0,
                kind: ScalaCallArgumentListKind::Ordinary,
            });
        }
        expression = instance;
    }
    while let Some(call) = expression.parent() {
        if call.kind() != "call_expression"
            || call.child_by_field_name("function") != Some(expression)
        {
            break;
        }
        let arguments = call.child_by_field_name("arguments")?;
        let list = call_argument_list(arguments);
        if lists.is_empty() && list.kind == ScalaCallArgumentListKind::Ordinary {
            leading_literal_argument_types = literal_argument_types(arguments);
        }
        lists.push(list);
        type_arguments_only = false;
        expression = call;
    }
    if lists.is_empty() && type_arguments_only {
        lists.push(ScalaCallArgumentList {
            arity: 0,
            kind: ScalaCallArgumentListKind::Ordinary,
        });
    }
    (!lists.is_empty()).then_some(ScalaCallSiteShape {
        lists,
        leading_literal_argument_types,
        method_value_arity: None,
        method_value_parameter_types: None,
        method_value_parameter_types_authoritative: false,
        type_arguments_only,
    })
}

/// Kind-derived builtin types of a plain `arguments` list's literal arguments.
/// `None` when the node is not a plain argument list or any argument is named:
/// named arguments may reorder positions, and a wrong positional mapping would
/// turn the conservative literal filter into false absences.
fn literal_argument_types(arguments: Node<'_>) -> Option<Vec<Option<&'static str>>> {
    if arguments.kind() != "arguments" {
        return None;
    }
    let mut cursor = arguments.walk();
    let mut types = Vec::new();
    for argument in arguments
        .named_children(&mut cursor)
        .filter(|argument| is_semantic_call_argument(*argument))
    {
        if argument.kind() == "assignment_expression" {
            return None;
        }
        types.push(scala_literal_type_name(argument.kind()));
    }
    Some(types)
}

pub fn applied_expression_for_reference(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return Some(parent);
    }
    let mut expression = field_expression_for_member(node).unwrap_or(node);
    while let Some(generic) = expression.parent().filter(|generic| {
        (generic.kind() == "generic_function"
            && generic.child_by_field_name("function") == Some(expression))
            || (generic.kind() == "generic_type"
                && generic.child_by_field_name("type") == Some(expression))
    }) {
        expression = generic;
    }
    let mut applied = None;
    if let Some(instance) = expression
        .parent()
        .filter(|parent| parent.kind() == "instance_expression")
    {
        expression = instance;
        applied = Some(instance);
    }
    while let Some(call) = expression.parent() {
        if call.kind() != "call_expression"
            || call.child_by_field_name("function") != Some(expression)
        {
            break;
        }
        expression = call;
        applied = Some(call);
    }
    applied
}

fn call_argument_list(arguments: Node<'_>) -> ScalaCallArgumentList {
    if matches!(
        arguments.kind(),
        "block" | "indented_block" | "case_block" | "colon_argument"
    ) {
        return ScalaCallArgumentList {
            arity: 1,
            kind: ScalaCallArgumentListKind::Block,
        };
    }
    let mut children = arguments.walk();
    let kind = if arguments
        .children(&mut children)
        .any(|child| matches!(child.kind(), "using" | "implicit"))
    {
        ScalaCallArgumentListKind::Contextual
    } else {
        ScalaCallArgumentListKind::Ordinary
    };
    let mut named = arguments.walk();
    ScalaCallArgumentList {
        arity: arguments
            .named_children(&mut named)
            .filter(|argument| is_semantic_call_argument(*argument))
            .count(),
        kind,
    }
}

pub fn is_semantic_call_argument(node: Node<'_>) -> bool {
    !matches!(node.kind(), "comment" | "block_comment")
}

pub fn scala_call_shape_relation(
    declared: &[ScalaCallableParameterList],
    result: ScalaDeclaredResult,
    actual: &ScalaCallSiteShape,
) -> ScalaCallShapeRelation {
    if actual.type_arguments_only {
        return if declared
            .iter()
            .all(|list| list.kind == ScalaParameterListKind::Contextual)
        {
            ScalaCallShapeRelation::Complete
        } else {
            ScalaCallShapeRelation::Incompatible
        };
    }
    if actual.lists.len() == 1
        && actual.lists[0].kind == ScalaCallArgumentListKind::Ordinary
        && actual.lists[0].arity == 0
        && !declared.is_empty()
        && declared
            .iter()
            .all(|list| list.kind == ScalaParameterListKind::Contextual)
    {
        return ScalaCallShapeRelation::Complete;
    }

    // Every declared parameter list is filled, so the lists that are left apply
    // the RESULT of the call (#1853): `def transform(flag: Boolean): Int => Int`
    // is written `transform(true)(x)`, and `def transform: Int => Int` is
    // written `transform(x)`. Only a result no type could make applicable
    // rejects the site.
    let applies_result = |remaining: usize| {
        if result.accepts_application_lists(remaining) {
            ScalaCallShapeRelation::Complete
        } else {
            ScalaCallShapeRelation::Incompatible
        }
    };

    let mut declared_index = 0usize;
    for (position, actual_list) in actual.lists.iter().enumerate() {
        match actual_list.kind {
            ScalaCallArgumentListKind::Ordinary | ScalaCallArgumentListKind::Block => {
                while declared.get(declared_index).is_some_and(|list| {
                    list.kind == ScalaParameterListKind::Contextual
                        && declared[declared_index + 1..]
                            .iter()
                            .any(|remaining| remaining.kind == ScalaParameterListKind::Explicit)
                }) {
                    declared_index += 1;
                }
                let Some(declared_list) = declared.get(declared_index) else {
                    return applies_result(actual.lists.len() - position);
                };
                if !matches!(
                    declared_list.kind,
                    ScalaParameterListKind::Explicit | ScalaParameterListKind::Contextual
                ) || !declared_list.arity.accepts(actual_list.arity)
                {
                    return ScalaCallShapeRelation::Incompatible;
                }
            }
            ScalaCallArgumentListKind::Contextual => {
                let Some(declared_list) = declared.get(declared_index) else {
                    return applies_result(actual.lists.len() - position);
                };
                if declared_list.kind != ScalaParameterListKind::Contextual
                    || !declared_list.arity.accepts(actual_list.arity)
                {
                    return ScalaCallShapeRelation::Incompatible;
                }
            }
        }
        declared_index += 1;
    }

    let remaining = &declared[declared_index..];
    if remaining
        .iter()
        .all(|list| list.kind == ScalaParameterListKind::Contextual)
    {
        return ScalaCallShapeRelation::Complete;
    }
    let mut explicit = remaining
        .iter()
        .filter(|list| list.kind == ScalaParameterListKind::Explicit);
    let Some(next) = explicit.next() else {
        return ScalaCallShapeRelation::Complete;
    };
    if explicit.next().is_some() {
        return ScalaCallShapeRelation::Incompatible;
    }
    ScalaCallShapeRelation::Partial {
        next_explicit_arity: next.arity,
    }
}

pub fn scala_callable_shape_matches(
    declared: &[ScalaCallableParameterList],
    result: ScalaDeclaredResult,
    actual: Option<&ScalaCallSiteShape>,
    policy: ScalaCallableUsePolicy,
    unique_callable: bool,
) -> bool {
    let Some(actual) = actual else {
        return declared.first().is_none_or(|list| list.arity.total() == 0)
            || policy == ScalaCallableUsePolicy::OrdinaryMethod && unique_callable;
    };
    if !scala_callable_shape_is_candidate(declared, result, actual, policy) {
        return false;
    }
    match scala_call_shape_relation(declared, result, actual) {
        ScalaCallShapeRelation::Incompatible => false,
        ScalaCallShapeRelation::Complete => true,
        ScalaCallShapeRelation::Partial { .. } => unique_callable,
    }
}

pub fn scala_callable_alternative_matches(
    declared_role: ScalaCallableRole,
    declared_shape: &[ScalaCallableParameterList],
    declared_result: ScalaDeclaredResult,
    actual: Option<&ScalaCallSiteShape>,
    site_role: ScalaCallableSiteRole,
    unique_callable: bool,
) -> bool {
    site_role.accepts(declared_role)
        && scala_callable_shape_matches(
            declared_shape,
            declared_result,
            actual,
            site_role.use_policy(),
            unique_callable,
        )
}

pub fn scala_callable_alternative_is_candidate(
    declared_role: ScalaCallableRole,
    declared_shape: &[ScalaCallableParameterList],
    declared_result: ScalaDeclaredResult,
    actual: &ScalaCallSiteShape,
    site_role: ScalaCallableSiteRole,
) -> bool {
    site_role.accepts(declared_role)
        && scala_callable_shape_is_candidate(
            declared_shape,
            declared_result,
            actual,
            site_role.use_policy(),
        )
}

pub fn scala_callable_shape_is_candidate(
    declared: &[ScalaCallableParameterList],
    result: ScalaDeclaredResult,
    actual: &ScalaCallSiteShape,
    policy: ScalaCallableUsePolicy,
) -> bool {
    match scala_call_shape_relation(declared, result, actual) {
        ScalaCallShapeRelation::Incompatible => false,
        ScalaCallShapeRelation::Complete => true,
        ScalaCallShapeRelation::Partial {
            next_explicit_arity,
        } => {
            // Fewer application lists than declared is partial application, and
            // the site's expected function arity refutes it only when that
            // arity is known (#1853): `xs.map(render("p"))` on an unresolved
            // receiver proves nothing about the function `map` wants, and an
            // unproven arity is not a mismatch. `scala_callable_shape_matches`
            // still requires the partially applied callable to be the only one.
            policy == ScalaCallableUsePolicy::OrdinaryMethod
                && actual
                    .method_value_arity
                    .is_none_or(|arity| next_explicit_arity.accepts(arity))
        }
    }
}

pub fn named_argument_invocation_owner(node: Node<'_>) -> Option<Node<'_>> {
    let assignment = node.parent()?;
    if assignment.kind() != "assignment_expression"
        || assignment.child_by_field_name("left") != Some(node)
    {
        return None;
    }
    let arguments = assignment.parent()?;
    if arguments.kind() != "arguments" {
        return None;
    }
    let invocation = arguments.parent()?;
    match invocation.kind() {
        "call_expression" => invocation.child_by_field_name("function"),
        "instance_expression" => {
            let mut cursor = invocation.walk();
            invocation.named_children(&mut cursor).find(|child| {
                matches!(
                    child.kind(),
                    "type_identifier" | "stable_type_identifier" | "generic_type"
                )
            })
        }
        _ => None,
    }
}

/// Whether this assignment-shaped node is a Scala named argument rather than
/// a mutation of a local binding.
///
/// Tree-sitter represents both `call(name = value)` and
/// `new Type(name = value)` with an `assignment_expression` directly inside
/// the invocation's `arguments`. Binding inference must not refresh `name`
/// after visiting that node: the left side names a parameter/member of the
/// callee, not a value being reassigned in the current lexical scope.
pub fn is_scala_named_argument_assignment(node: Node<'_>) -> bool {
    if node.kind() != "assignment_expression" {
        return false;
    }
    let Some(arguments) = node.parent().filter(|parent| parent.kind() == "arguments") else {
        return false;
    };
    arguments.parent().is_some_and(|invocation| {
        matches!(invocation.kind(), "call_expression" | "instance_expression")
    })
}

pub fn terminal_invocation_owner_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "type_identifier" => Some(node),
        "generic_function" => node
            .child_by_field_name("function")
            .and_then(terminal_invocation_owner_name),
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(terminal_invocation_owner_name),
        "field_expression" => node
            .child_by_field_name("field")
            .and_then(terminal_invocation_owner_name),
        "stable_type_identifier" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .last()
                .and_then(terminal_invocation_owner_name)
        }
        _ => None,
    }
}

/// Enclosing class/object/trait/enum declarations from the innermost template
/// to the outermost. This includes local templates that the analyzer does not
/// publish as global declarations.
pub fn enclosing_template_declarations(node: Node<'_>) -> Vec<Node<'_>> {
    let mut declarations = Vec::new();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "template_body" | "enum_body")
            && let Some(declaration) = parent.parent()
            && matches!(
                declaration.kind(),
                "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
            )
        {
            declarations.push(declaration);
        }
        current = parent;
    }
    declarations
}

pub fn template_self_type(declaration: Node<'_>) -> Option<Node<'_>> {
    let mut declaration_cursor = declaration.walk();
    declaration
        .named_children(&mut declaration_cursor)
        .find(|child| matches!(child.kind(), "template_body" | "enum_body"))
        .and_then(|body| {
            let mut body_cursor = body.walk();
            body.named_children(&mut body_cursor)
                .find(|child| child.kind() == "self_type")
        })
        .and_then(|self_type| {
            let mut self_cursor = self_type.walk();
            let mut children = self_type.named_children(&mut self_cursor);
            let _binder = children.next()?;
            children.next()
        })
}

/// Whether a template directly declares a term with `name`. For local
/// templates, such a declaration must conservatively block inherited-member
/// resolution because it has no globally indexed CodeUnit/signature.
pub fn template_direct_term_member_named(declaration: Node<'_>, name: &str, source: &str) -> bool {
    let mut declaration_cursor = declaration.walk();
    let Some(body) = declaration
        .named_children(&mut declaration_cursor)
        .find(|child| matches!(child.kind(), "template_body" | "enum_body"))
    else {
        return false;
    };
    let mut body_cursor = body.walk();
    body.named_children(&mut body_cursor).any(|child| {
        if matches!(
            child.kind(),
            "function_definition"
                | "function_declaration"
                | "object_definition"
                | "val_definition"
                | "val_declaration"
                | "var_definition"
                | "var_declaration"
        ) && child
            .child_by_field_name("name")
            .is_some_and(|node| node_text(node, source).trim() == name)
        {
            return true;
        }
        if !matches!(
            child.kind(),
            "val_definition" | "val_declaration" | "var_definition" | "var_declaration"
        ) {
            return false;
        }
        child
            .child_by_field_name("pattern")
            .is_some_and(|pattern| pattern_contains_identifier(pattern, name, source))
    })
}

fn pattern_contains_identifier(node: Node<'_>, name: &str, source: &str) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "identifier" | "operator_identifier")
            && node_text(current, source).trim() == name
        {
            return true;
        }
        if current.kind() == "stable_identifier" {
            continue;
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

pub fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

pub fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        if parent.kind() == "type_definition" {
            let mut cursor = parent.walk();
            return parent
                .named_children(&mut cursor)
                .find(|child| child.kind() == "identifier")
                == Some(node);
        }
        matches!(
            parent.kind(),
            "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "function_definition"
                | "function_declaration"
                | "parameter"
                | "class_parameter"
        ) && parent.child_by_field_name("name") == Some(node)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explicit(arity: usize) -> ScalaCallableParameterList {
        ScalaCallableParameterList {
            arity: CallableArity::exact(arity),
            kind: ScalaParameterListKind::Explicit,
        }
    }

    fn contextual(arity: usize) -> ScalaCallableParameterList {
        ScalaCallableParameterList {
            arity: CallableArity::exact(arity),
            kind: ScalaParameterListKind::Contextual,
        }
    }

    #[test]
    fn call_site_shape_treats_blocks_as_one_argument_and_records_using_lists() {
        let source = r#"object Use:
  val block = run {
    val first = 1
    val second = 2
    first + second
  }
  val contextual = run(1)(using context)
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala tree");
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" && node_text(node, source) == "run" {
                calls.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        assert_eq!(calls.len(), 2);
        let block = call_site_shape_for_reference(calls[0]).expect("block call shape");
        assert_eq!(
            block.lists,
            [ScalaCallArgumentList {
                arity: 1,
                kind: ScalaCallArgumentListKind::Block,
            }]
        );
        let contextual = call_site_shape_for_reference(calls[1]).expect("contextual call shape");
        assert_eq!(
            contextual.lists,
            [
                ScalaCallArgumentList {
                    arity: 1,
                    kind: ScalaCallArgumentListKind::Ordinary,
                },
                ScalaCallArgumentList {
                    arity: 1,
                    kind: ScalaCallArgumentListKind::Contextual,
                },
            ]
        );
    }

    #[test]
    fn call_shape_aligns_contextual_lists_and_requires_proven_partial_use() {
        let ordinary = ScalaCallArgumentList {
            arity: 1,
            kind: ScalaCallArgumentListKind::Ordinary,
        };
        let empty = ScalaCallArgumentList {
            arity: 0,
            kind: ScalaCallArgumentListKind::Ordinary,
        };
        let supplied = ScalaCallSiteShape {
            lists: vec![ordinary],
            leading_literal_argument_types: None,
            method_value_arity: None,
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        };
        assert_eq!(
            scala_call_shape_relation(
                &[contextual(1), explicit(1), contextual(2)],
                ScalaDeclaredResult::UNDECLARED,
                &supplied,
            ),
            ScalaCallShapeRelation::Complete
        );
        assert_eq!(
            scala_call_shape_relation(
                &[contextual(1), explicit(1)],
                ScalaDeclaredResult::UNDECLARED,
                &supplied,
            ),
            ScalaCallShapeRelation::Complete
        );
        assert_eq!(
            scala_call_shape_relation(
                &[contextual(1)],
                ScalaDeclaredResult::UNDECLARED,
                &ScalaCallSiteShape {
                    lists: vec![empty],
                    leading_literal_argument_types: None,
                    method_value_arity: None,
                    method_value_parameter_types: None,
                    method_value_parameter_types_authoritative: false,
                    type_arguments_only: false,
                }
            ),
            ScalaCallShapeRelation::Complete
        );
        assert_eq!(
            scala_call_shape_relation(
                &[contextual(1)],
                ScalaDeclaredResult::UNDECLARED,
                &ScalaCallSiteShape {
                    lists: vec![ordinary],
                    leading_literal_argument_types: None,
                    method_value_arity: None,
                    method_value_parameter_types: None,
                    method_value_parameter_types_authoritative: false,
                    type_arguments_only: false,
                }
            ),
            ScalaCallShapeRelation::Complete
        );
        assert_eq!(
            scala_call_shape_relation(
                &[explicit(1), contextual(1)],
                ScalaDeclaredResult::UNDECLARED,
                &ScalaCallSiteShape {
                    lists: vec![ordinary, ordinary],
                    leading_literal_argument_types: None,
                    method_value_arity: None,
                    method_value_parameter_types: None,
                    method_value_parameter_types_authoritative: false,
                    type_arguments_only: false,
                }
            ),
            ScalaCallShapeRelation::Complete
        );
        assert_eq!(
            scala_call_shape_relation(
                &[contextual(1), explicit(1)],
                ScalaDeclaredResult::UNDECLARED,
                &ScalaCallSiteShape {
                    lists: vec![ordinary],
                    leading_literal_argument_types: None,
                    method_value_arity: None,
                    method_value_parameter_types: None,
                    method_value_parameter_types_authoritative: false,
                    type_arguments_only: false,
                }
            ),
            ScalaCallShapeRelation::Complete
        );

        let partial = ScalaCallSiteShape {
            lists: vec![ordinary],
            leading_literal_argument_types: None,
            method_value_arity: Some(1),
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        };
        assert_eq!(
            scala_call_shape_relation(
                &[explicit(1), explicit(1)],
                ScalaDeclaredResult::UNDECLARED,
                &partial,
            ),
            ScalaCallShapeRelation::Partial {
                next_explicit_arity: CallableArity::exact(1)
            }
        );
        assert!(scala_callable_shape_matches(
            &[explicit(1), explicit(1)],
            ScalaDeclaredResult::UNDECLARED,
            Some(&partial),
            ScalaCallableUsePolicy::OrdinaryMethod,
            true,
        ));
        assert!(!scala_callable_shape_matches(
            &[explicit(1), explicit(1)],
            ScalaDeclaredResult::UNDECLARED,
            Some(&partial),
            ScalaCallableUsePolicy::OrdinaryMethod,
            false,
        ));
        assert!(!scala_callable_shape_matches(
            &[explicit(1), explicit(1)],
            ScalaDeclaredResult::UNDECLARED,
            Some(&partial),
            ScalaCallableUsePolicy::CompleteCall,
            true,
        ));
    }

    #[test]
    fn pattern_binders_exclude_types_extractors_operators_and_named_labels() {
        let source = r#"object Patterns {
  def read(value: Any): Any = value match {
    case owner: owner.Nested if owner != null => owner
    case captured @ Root.Box(label = nested, pair = (left, right)) => captured
    case head :: tail => tail
    case given Root.Context => value
  }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala tree");
        let mut actual = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "case_clause"
                && let Some(pattern) = node.child_by_field_name("pattern")
            {
                actual.push(scala_pattern_binder_names(pattern, source));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        actual.reverse();

        assert_eq!(
            actual,
            vec![
                vec!["owner"],
                vec!["captured", "nested", "left", "right"],
                vec!["head", "tail"],
                Vec::<&str>::new(),
            ],
            "{}",
            tree.root_node().to_sexp()
        );
    }

    #[test]
    fn parameterized_enum_case_records_primary_constructor_source_facts() {
        let source = r#"trait Tagged
enum Event:
  case Idle extends Tagged
  case Data(id: Int, label: String = "default")
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala tree");
        let mut simple_case = None;
        let mut full_case = None;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "simple_enum_case" => simple_case = Some(node),
                "full_enum_case" => full_case = Some(node),
                _ => {}
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let simple_case = simple_case.expect("simple enum case");
        let full_case = full_case.expect("full enum case");

        let facts = scala_source_facts(source).expect("Scala source facts");
        let simple_range = (simple_case.start_byte(), simple_case.end_byte());
        assert_eq!(node_text(simple_case, source), "Idle extends Tagged");
        assert!(
            !facts
                .callable_alternatives_by_range
                .contains_key(&simple_range)
        );
        assert!(!facts.case_class_ranges.contains(&simple_range));

        let range = (full_case.start_byte(), full_case.end_byte());
        assert_eq!(
            node_text(full_case, source),
            "Data(id: Int, label: String = \"default\")"
        );
        let callable = facts
            .callable_alternatives_by_range
            .get(&range)
            .expect("enum case constructor facts");
        assert_eq!(callable.role, ScalaCallableRole::PrimaryConstructor);
        assert_eq!(callable.shape.len(), 1);
        assert!(callable.shape[0].arity.accepts(1));
        assert!(callable.shape[0].arity.accepts(2));
        assert!(!callable.shape[0].arity.accepts(0));
        assert_eq!(callable.parameter_defaults, vec![vec![false, true]]);
        assert!(facts.case_class_ranges.contains(&range));
    }

    #[test]
    fn callable_roles_precede_shape_matching_for_primary_and_secondary_construction() {
        let source = r#"class Roleful(value: Int) {
  def this() = this(0)
  def this(text: String, flag: Boolean) = this(text.length)
}
object Roleful { def apply(using String): Roleful = new Roleful(0) }
"#;
        let facts = scala_source_facts(source).expect("Scala source facts");
        let mut roles = facts
            .callable_alternatives_by_range
            .values()
            .map(|alternative| (alternative.role, alternative.shape.len()))
            .collect::<Vec<_>>();
        roles.sort_by_key(|(role, lists)| {
            let role = match role {
                ScalaCallableRole::Ordinary => 0,
                ScalaCallableRole::PrimaryConstructor => 1,
                ScalaCallableRole::SecondaryConstructor => 2,
            };
            (role, *lists)
        });
        assert_eq!(
            roles,
            vec![
                (ScalaCallableRole::Ordinary, 1),
                (ScalaCallableRole::PrimaryConstructor, 1),
                (ScalaCallableRole::SecondaryConstructor, 1),
                (ScalaCallableRole::SecondaryConstructor, 1),
            ]
        );

        let zero = ScalaCallSiteShape::ordinary(&[0]);
        let declared = [ScalaCallableParameterList::explicit(CallableArity::exact(
            0,
        ))];
        assert!(scala_callable_alternative_matches(
            ScalaCallableRole::SecondaryConstructor,
            &declared,
            ScalaDeclaredResult::UNDECLARED,
            Some(&zero),
            ScalaCallableSiteRole::ExplicitConstruction,
            false,
        ));
        assert!(!scala_callable_alternative_matches(
            ScalaCallableRole::SecondaryConstructor,
            &declared,
            ScalaDeclaredResult::UNDECLARED,
            Some(&zero),
            ScalaCallableSiteRole::PrimaryConstruction,
            false,
        ));
        assert!(!scala_callable_alternative_matches(
            ScalaCallableRole::SecondaryConstructor,
            &declared,
            ScalaDeclaredResult::UNDECLARED,
            Some(&zero),
            ScalaCallableSiteRole::Ordinary,
            false,
        ));
    }

    #[test]
    fn package_context_index_preserves_only_parser_active_prefixes() {
        let source = r#"package scala.collection
package immutable
object Use { val value = new ArrayOps(1) }
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala tree");
        let index = ScalaPackageContextIndex::new(tree.root_node(), source);
        let mut cursor = 0;
        assert_eq!(
            index.advance_to(source.find("ArrayOps").unwrap(), &mut cursor),
            ["scala.collection", "scala.collection.immutable"]
        );

        let dotted =
            "package scala.collection.immutable\nobject Use { val value = new ArrayOps(1) }\n";
        let tree = parser.parse(dotted, None).expect("Scala tree");
        let index = ScalaPackageContextIndex::new(tree.root_node(), dotted);
        let mut cursor = 0;
        assert_eq!(
            index.advance_to(dotted.find("ArrayOps").unwrap(), &mut cursor),
            ["scala.collection.immutable"]
        );
    }

    #[test]
    fn qualified_stable_type_roles_follow_parser_structure() {
        let source = r#"object Use {
  val applied = Structure.Value(1)
  def extracted(value: Any): Any = value match { case Structure.Value(number) => number }
  val created = new Structure.Value(1)
  val generic = new Structure.Box[Int](1)
  val typed: Structure.Value = ???
  val packageTyped: model.Structure.Value = ???
}
enum Token:
  case Number(value: Int)
object EnumUse:
  def invalid(token: Token): Int = token match
    case Token.Number(first, second) => first + second
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala tree");
        let mut value_roles = Vec::new();
        let mut box_roles = Vec::new();
        let mut package_paths = Vec::new();
        let mut extractor_shapes = Vec::new();
        let mut enum_extractor_shapes = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "identifier" | "type_identifier")
                && let Some(reference) = qualified_stable_type_reference(node, source)
            {
                match node_text(node, source) {
                    "Value" => {
                        if reference
                            .segments
                            .first()
                            .is_some_and(|root| root == "model")
                        {
                            package_paths.push(reference.segments.clone());
                        }
                        if reference.role == ScalaQualifiedStableTypeRole::Extractor {
                            extractor_shapes
                                .push(call_site_shape_for_reference(reference.expression));
                        }
                        value_roles.push(reference.role);
                    }
                    "Box" => box_roles.push(reference.role),
                    "Number" if reference.role == ScalaQualifiedStableTypeRole::Extractor => {
                        enum_extractor_shapes
                            .push(call_site_shape_for_reference(reference.expression));
                    }
                    _ => {}
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        value_roles.sort();
        assert_eq!(
            value_roles,
            vec![
                ScalaQualifiedStableTypeRole::Type,
                ScalaQualifiedStableTypeRole::Type,
                ScalaQualifiedStableTypeRole::Apply,
                ScalaQualifiedStableTypeRole::Extractor,
                ScalaQualifiedStableTypeRole::Constructor,
            ],
            "{}",
            tree.root_node().to_sexp(),
        );
        assert_eq!(package_paths, vec![vec!["model", "Structure", "Value"]]);
        assert_eq!(box_roles, vec![ScalaQualifiedStableTypeRole::Constructor]);
        assert_eq!(
            extractor_shapes,
            vec![Some(ScalaCallSiteShape::ordinary(&[1]))],
            "{}",
            tree.root_node().to_sexp(),
        );
        assert_eq!(
            enum_extractor_shapes,
            vec![Some(ScalaCallSiteShape::ordinary(&[2]))],
            "{}",
            tree.root_node().to_sexp(),
        );
    }
}
