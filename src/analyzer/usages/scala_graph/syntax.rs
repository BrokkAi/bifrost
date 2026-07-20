use crate::analyzer::scala::{scala_package_prefixes_at, scala_type_lookup_segments};
use crate::analyzer::{CallableArity, CodeUnit, ImportInfo, scala_parenthesized_arity};
use crate::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

type ScalaParameterFunctionTypePaths = Vec<Vec<Option<Vec<Option<Vec<String>>>>>>;

#[derive(Default)]
pub(crate) struct ScalaSourceFacts {
    pub(crate) callable_alternatives_by_range:
        HashMap<(usize, usize), ScalaCallableSourceAlternative>,
    pub(crate) field_type_paths_by_range: HashMap<(usize, usize), Vec<String>>,
    pub(crate) stable_owner_ranges: HashSet<(usize, usize)>,
    pub(crate) enum_ranges: HashSet<(usize, usize)>,
    pub(crate) case_class_ranges: HashSet<(usize, usize)>,
    pub(crate) abstract_callable_ranges: HashSet<(usize, usize)>,
    pub(crate) generic_owner_facts_by_range: HashMap<(usize, usize), ScalaGenericOwnerSourceFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScalaTypeExpressionPath {
    pub(crate) segments: Vec<String>,
    pub(crate) arguments: Vec<ScalaTypeExpressionPath>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ScalaGenericOwnerSourceFacts {
    pub(crate) type_parameters: Vec<String>,
    pub(crate) supertypes: Vec<ScalaTypeExpressionPath>,
}

#[derive(Clone)]
pub(crate) struct ScalaCallableSourceAlternative {
    pub(crate) role: ScalaCallableRole,
    pub(crate) shape: Vec<ScalaCallableParameterList>,
    pub(crate) parameter_defaults: Vec<Vec<bool>>,
    pub(crate) parameter_function_arities: Vec<Vec<Option<usize>>>,
    pub(crate) parameter_type_paths: Vec<Vec<Option<Vec<String>>>>,
    pub(crate) parameter_function_type_paths: ScalaParameterFunctionTypePaths,
    pub(crate) extension_receiver_type_path: Option<Vec<String>>,
    pub(crate) return_type_path: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalaCallableRole {
    Ordinary,
    PrimaryConstructor,
    SecondaryConstructor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScalaMethodValueContext {
    Unknown,
    Function(ScalaFunctionParameterShape),
    Incompatible,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ScalaParameterTypeIdentity {
    Builtin(&'static str),
    Declaration(CodeUnit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScalaFunctionParameterShape {
    pub(crate) arity: usize,
    pub(crate) parameter_types: Option<Vec<ScalaParameterTypeIdentity>>,
    pub(crate) parameter_types_authoritative: bool,
}

impl ScalaFunctionParameterShape {
    pub(crate) fn arity_only(arity: usize) -> Self {
        Self {
            arity,
            parameter_types: None,
            parameter_types_authoritative: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalaParameterListKind {
    Explicit,
    Contextual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalaCallArgumentListKind {
    Ordinary,
    Contextual,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScalaCallArgumentList {
    pub(crate) arity: usize,
    pub(crate) kind: ScalaCallArgumentListKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScalaCallSiteShape {
    pub(crate) lists: Vec<ScalaCallArgumentList>,
    pub(crate) method_value_arity: Option<usize>,
    pub(crate) method_value_parameter_types: Option<Vec<ScalaParameterTypeIdentity>>,
    pub(crate) method_value_parameter_types_authoritative: bool,
    pub(crate) type_arguments_only: bool,
}

impl ScalaCallSiteShape {
    pub(crate) fn ordinary(arities: &[usize]) -> Self {
        Self {
            lists: arities
                .iter()
                .copied()
                .map(|arity| ScalaCallArgumentList {
                    arity,
                    kind: ScalaCallArgumentListKind::Ordinary,
                })
                .collect(),
            method_value_arity: None,
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        }
    }

    pub(crate) fn with_method_value_arity(mut self, arity: Option<usize>) -> Self {
        self.method_value_arity = arity;
        self.method_value_parameter_types = None;
        self.method_value_parameter_types_authoritative = false;
        self
    }

    pub(crate) fn with_method_value_shape(
        mut self,
        shape: Option<ScalaFunctionParameterShape>,
    ) -> Self {
        self.method_value_arity = shape.as_ref().map(|shape| shape.arity);
        self.method_value_parameter_types_authoritative = shape
            .as_ref()
            .is_some_and(|shape| shape.parameter_types_authoritative);
        self.method_value_parameter_types = shape.and_then(|shape| shape.parameter_types);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalaCallableUsePolicy {
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
pub(crate) enum ScalaCallableSiteRole {
    Ordinary,
    ExplicitConstruction,
    PrimaryConstruction,
}

impl ScalaCallableSiteRole {
    pub(crate) fn accepts(self, declared: ScalaCallableRole) -> bool {
        match self {
            Self::Ordinary => declared == ScalaCallableRole::Ordinary,
            Self::ExplicitConstruction => matches!(
                declared,
                ScalaCallableRole::PrimaryConstructor | ScalaCallableRole::SecondaryConstructor
            ),
            Self::PrimaryConstruction => declared == ScalaCallableRole::PrimaryConstructor,
        }
    }

    pub(crate) fn use_policy(self) -> ScalaCallableUsePolicy {
        match self {
            Self::Ordinary => ScalaCallableUsePolicy::OrdinaryMethod,
            Self::ExplicitConstruction | Self::PrimaryConstruction => {
                ScalaCallableUsePolicy::CompleteCall
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalaCallShapeRelation {
    Incompatible,
    Complete,
    Partial { next_explicit_arity: CallableArity },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScalaCallableParameterList {
    pub(crate) arity: CallableArity,
    pub(crate) kind: ScalaParameterListKind,
}

impl ScalaCallableParameterList {
    pub(crate) fn explicit(arity: CallableArity) -> Self {
        Self {
            arity,
            kind: ScalaParameterListKind::Explicit,
        }
    }
}

pub(crate) fn scala_source_facts(source: &str) -> Option<ScalaSourceFacts> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
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
                        parameter_defaults,
                        parameter_function_arities,
                        parameter_type_paths,
                        parameter_function_type_paths,
                        extension_receiver_type_path: enclosing_extension_receiver_type_path(
                            node, source,
                        ),
                        return_type_path: node
                            .child_by_field_name("return_type")
                            .map(|return_type| scala_type_lookup_segments(return_type, source))
                            .filter(|segments| !segments.is_empty()),
                    },
                );
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
                        parameter_defaults,
                        parameter_function_arities: Vec::new(),
                        parameter_type_paths: Vec::new(),
                        parameter_function_type_paths: Vec::new(),
                        extension_receiver_type_path: None,
                        return_type_path: None,
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
    Some(facts)
}

fn record_generic_owner_facts(node: Node<'_>, source: &str, facts: &mut ScalaSourceFacts) {
    let type_parameters = node
        .child_by_field_name("type_parameters")
        .map(|parameters| {
            let mut cursor = parameters.walk();
            parameters
                .named_children(&mut cursor)
                .filter_map(|parameter| {
                    let name = parameter.child_by_field_name("name").unwrap_or(parameter);
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
    let supertypes = crate::analyzer::scala::scala_supertype_lookup_nodes(node)
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
pub(crate) fn scala_pattern_binder_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
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
pub(crate) fn is_scala_case_pattern_binder(node: Node<'_>) -> bool {
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
pub(crate) fn scala_union_type_alternative_paths(
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
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "repeated_parameter_type" {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

pub(super) fn parenthesized_arity(source: &str) -> Option<usize> {
    scala_parenthesized_arity(source)
}

pub(crate) fn scala_import_path(info: &ImportInfo) -> Option<String> {
    crate::analyzer::scala::scala_import_path(info)
}

pub(crate) struct ScalaImportContextIndex {
    segments: Vec<ScalaImportContextSegment>,
}

pub(crate) struct ScalaPackageContextIndex {
    segments: Vec<ScalaPackageContextSegment>,
}

struct ScalaPackageContextSegment {
    start_byte: usize,
    prefixes: Vec<String>,
}

impl ScalaPackageContextIndex {
    pub(crate) fn new(root: Node<'_>, source: &str) -> Self {
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

    pub(crate) fn advance_to(&self, byte: usize, cursor: &mut usize) -> &[String] {
        while *cursor + 1 < self.segments.len() && self.segments[*cursor + 1].start_byte <= byte {
            *cursor += 1;
        }
        &self.segments[*cursor].prefixes
    }
}

pub(crate) fn scala_import_is_visible_at_byte(import: &ImportInfo, byte: usize) -> bool {
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
    pub(crate) fn new(imports: &[ImportInfo], file_end_byte: usize) -> Self {
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

    pub(crate) fn advance_to(&self, byte: usize, cursor: &mut usize) -> &[usize] {
        while *cursor + 1 < self.segments.len() && self.segments[*cursor + 1].start_byte <= byte {
            *cursor += 1;
        }
        &self.segments[*cursor].import_indices
    }
}

pub(crate) fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "operator_identifier"
    )
}

pub(crate) fn is_bare_companion_method_value_reference(node: Node<'_>) -> bool {
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

pub(crate) fn is_type_like_reference(node: Node<'_>, source: &str) -> bool {
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
pub(crate) fn is_infix_type_operator_reference(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "infix_type" && parent.child_by_field_name("operator") == Some(node)
    })
}

pub(crate) fn is_scala_object_reference(node: Node<'_>) -> bool {
    is_singleton_type_reference(node)
        || is_stable_type_qualifier(node)
        || qualified_stable_type_expression_role(node).is_some_and(|(_, _, role)| {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ScalaQualifiedStableTypeRole {
    Type,
    Apply,
    Extractor,
    Constructor,
}

pub(crate) struct ScalaQualifiedStableTypeReference<'tree> {
    pub(crate) segments: Vec<String>,
    pub(crate) expression: Node<'tree>,
    pub(crate) role: ScalaQualifiedStableTypeRole,
}

pub(crate) fn qualified_stable_type_reference<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<ScalaQualifiedStableTypeReference<'tree>> {
    let (expression, role, segments) =
        if let Some((stable, expression, role)) = qualified_stable_type_expression_role(node) {
            (expression, role, scala_type_lookup_segments(stable, source))
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

fn qualified_stable_type_expression_role(
    node: Node<'_>,
) -> Option<(Node<'_>, Node<'_>, ScalaQualifiedStableTypeRole)> {
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
    Some((stable, expression, role))
}

pub(crate) fn is_scala_class_reference(node: Node<'_>, source: &str) -> bool {
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

fn is_stable_type_qualifier(node: Node<'_>) -> bool {
    let Some(parent) = node
        .parent()
        .filter(|parent| parent.kind() == "stable_type_identifier")
    else {
        return false;
    };
    let mut cursor = parent.walk();
    parent.named_children(&mut cursor).last() != Some(node)
}

pub(crate) fn is_extractor_reference(node: Node<'_>) -> bool {
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

pub(crate) fn is_infix_pattern_operator(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "infix_pattern" && parent.child_by_field_name("operator") == Some(node)
    })
}

pub(crate) fn is_call_function_reference(node: Node<'_>) -> bool {
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
pub(crate) fn invocation_function_reference(function: Node<'_>) -> Node<'_> {
    if function.kind() == "generic_function" {
        function.child_by_field_name("function").unwrap_or(function)
    } else {
        function
    }
}

pub(crate) fn is_terminal_stable_field_reference(node: Node<'_>) -> bool {
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
pub(crate) fn resolve_stable_object_expression<T>(
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

pub(crate) struct ScalaStableIdentifierReference {
    pub(crate) segments: Vec<String>,
}

/// Return the ordered identifier leaves of the outermost `stable_identifier`
/// containing `node`, but only when `node` is that path's terminal leaf. Scala
/// represents these paths recursively, so walking named children preserves the
/// grammar's structure without reparsing the source spelling.
pub(crate) fn stable_identifier_reference<'tree>(
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
pub(crate) fn stable_identifier_prefix_reference<'tree>(
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
        | "parameter"
        | "class_parameter"
        | "type_parameters"
        | "import_declaration"
        | "stable_type_identifier"
        | "singleton_type"
        | "case_class_pattern"
        | "infix_pattern" => false,
        "function_definition" => parent.child_by_field_name("body") == Some(node),
        "val_definition" | "var_definition" => parent.child_by_field_name("pattern") != Some(node),
        "field_expression" => parent.child_by_field_name("field") != Some(node),
        _ => true,
    }
}

pub(crate) fn is_field_expression_value(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("value") == Some(node)
    })
}

pub(crate) fn is_constructor_like_reference(node: Node<'_>, source: &str) -> bool {
    let prefix = source[..node.start_byte()].trim_end();
    prefix.ends_with("new")
        || parent_kind(node).is_some_and(|kind| matches!(kind, "call_expression" | "type"))
}

pub(crate) fn parent_kind(node: Node<'_>) -> Option<&str> {
    node.parent().map(|parent| parent.kind())
}

pub(crate) fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(crate) fn field_expression_for_member(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    if parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node) {
        Some(parent)
    } else {
        None
    }
}

pub(crate) fn member_qualifier_node(node: Node<'_>) -> Option<Node<'_>> {
    field_expression_for_member(node)?.child_by_field_name("value")
}

pub(crate) fn member_qualifier(node: Node<'_>, source: &str) -> Option<String> {
    member_qualifier_node(node)
        .map(|value| {
            node_text(value, source)
                .trim()
                .trim_end_matches('$')
                .to_string()
        })
        .filter(|qualifier| !qualifier.is_empty())
}

pub(crate) fn is_owner_qualified_this(qualifier: Node<'_>, source: &str) -> bool {
    qualifier.kind() == "field_expression"
        && qualifier
            .child_by_field_name("field")
            .is_some_and(|field| node_text(field, source).trim() == "this")
}

pub(crate) fn stable_type_qualifier(node: Node<'_>, source: &str) -> Option<String> {
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

pub(crate) fn call_arities_for_reference(node: Node<'_>) -> Option<Vec<usize>> {
    call_site_shape_for_reference(node)
        .map(|shape| shape.lists.into_iter().map(|list| list.arity).collect())
}

pub(crate) fn call_site_shape_for_reference(node: Node<'_>) -> Option<ScalaCallSiteShape> {
    let parent = node.parent()?;
    if parent.kind() == "case_class_pattern" && parent.named_child(0) == Some(node) {
        let mut cursor = parent.walk();
        let arity = parent
            .children_by_field_name("pattern", &mut cursor)
            .count();
        return Some(ScalaCallSiteShape::ordinary(&[arity]));
    }
    if parent.kind() == "infix_pattern" && parent.child_by_field_name("operator") == Some(node) {
        return Some(ScalaCallSiteShape::ordinary(&[1]));
    }
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return Some(ScalaCallSiteShape {
            lists: vec![ScalaCallArgumentList {
                arity: 1,
                kind: ScalaCallArgumentListKind::Ordinary,
            }],
            method_value_arity: None,
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        });
    }
    let mut expression = field_expression_for_member(node).unwrap_or(node);
    let mut type_arguments_only = false;
    if let Some(generic) = expression.parent().filter(|generic| {
        (generic.kind() == "generic_function"
            && generic.child_by_field_name("function") == Some(expression))
            || (generic.kind() == "generic_type"
                && generic.child_by_field_name("type") == Some(expression))
    }) {
        type_arguments_only = generic.kind() == "generic_function";
        expression = generic;
    }
    let mut lists = Vec::new();
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
            lists.push(call_argument_list(arguments));
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
        lists.push(call_argument_list(arguments));
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
        method_value_arity: None,
        method_value_parameter_types: None,
        method_value_parameter_types_authoritative: false,
        type_arguments_only,
    })
}

pub(crate) fn applied_expression_for_reference(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return Some(parent);
    }
    let mut expression = field_expression_for_member(node).unwrap_or(node);
    if let Some(generic) = expression.parent().filter(|generic| {
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
    if matches!(arguments.kind(), "block" | "indented_block") {
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

pub(crate) fn is_semantic_call_argument(node: Node<'_>) -> bool {
    !matches!(node.kind(), "comment" | "block_comment")
}

pub(crate) fn scala_call_shape_relation(
    declared: &[ScalaCallableParameterList],
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

    let mut declared_index = 0usize;
    for actual_list in &actual.lists {
        match actual_list.kind {
            ScalaCallArgumentListKind::Ordinary | ScalaCallArgumentListKind::Block => {
                while declared
                    .get(declared_index)
                    .is_some_and(|list| list.kind == ScalaParameterListKind::Contextual)
                {
                    declared_index += 1;
                }
                let Some(declared_list) = declared.get(declared_index) else {
                    return ScalaCallShapeRelation::Incompatible;
                };
                if declared_list.kind != ScalaParameterListKind::Explicit
                    || !declared_list.arity.accepts(actual_list.arity)
                {
                    return ScalaCallShapeRelation::Incompatible;
                }
            }
            ScalaCallArgumentListKind::Contextual => {
                let Some(declared_list) = declared.get(declared_index) else {
                    return ScalaCallShapeRelation::Incompatible;
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

pub(crate) fn scala_callable_shape_matches(
    declared: &[ScalaCallableParameterList],
    actual: Option<&ScalaCallSiteShape>,
    policy: ScalaCallableUsePolicy,
    unique_callable: bool,
) -> bool {
    let Some(actual) = actual else {
        return declared.first().is_none_or(|list| list.arity.total() == 0)
            || policy == ScalaCallableUsePolicy::OrdinaryMethod && unique_callable;
    };
    if !scala_callable_shape_is_candidate(declared, actual, policy) {
        return false;
    }
    match scala_call_shape_relation(declared, actual) {
        ScalaCallShapeRelation::Incompatible => false,
        ScalaCallShapeRelation::Complete => true,
        ScalaCallShapeRelation::Partial { .. } => unique_callable,
    }
}

pub(crate) fn scala_callable_alternative_matches(
    declared_role: ScalaCallableRole,
    declared_shape: &[ScalaCallableParameterList],
    actual: Option<&ScalaCallSiteShape>,
    site_role: ScalaCallableSiteRole,
    unique_callable: bool,
) -> bool {
    site_role.accepts(declared_role)
        && scala_callable_shape_matches(
            declared_shape,
            actual,
            site_role.use_policy(),
            unique_callable,
        )
}

pub(crate) fn scala_callable_alternative_is_candidate(
    declared_role: ScalaCallableRole,
    declared_shape: &[ScalaCallableParameterList],
    actual: &ScalaCallSiteShape,
    site_role: ScalaCallableSiteRole,
) -> bool {
    site_role.accepts(declared_role)
        && scala_callable_shape_is_candidate(declared_shape, actual, site_role.use_policy())
}

pub(crate) fn scala_callable_shape_is_candidate(
    declared: &[ScalaCallableParameterList],
    actual: &ScalaCallSiteShape,
    policy: ScalaCallableUsePolicy,
) -> bool {
    match scala_call_shape_relation(declared, actual) {
        ScalaCallShapeRelation::Incompatible => false,
        ScalaCallShapeRelation::Complete => true,
        ScalaCallShapeRelation::Partial {
            next_explicit_arity,
        } => {
            policy == ScalaCallableUsePolicy::OrdinaryMethod
                && actual
                    .method_value_arity
                    .is_some_and(|arity| next_explicit_arity.accepts(arity))
        }
    }
}

pub(crate) fn named_argument_invocation_owner(node: Node<'_>) -> Option<Node<'_>> {
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
pub(crate) fn is_scala_named_argument_assignment(node: Node<'_>) -> bool {
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

pub(crate) fn terminal_invocation_owner_name(node: Node<'_>) -> Option<Node<'_>> {
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
pub(crate) fn enclosing_template_declarations(node: Node<'_>) -> Vec<Node<'_>> {
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

pub(crate) fn template_self_type(declaration: Node<'_>) -> Option<Node<'_>> {
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
pub(crate) fn template_direct_term_member_named(
    declaration: Node<'_>,
    name: &str,
    source: &str,
) -> bool {
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

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

pub(crate) fn is_declaration_name(node: Node<'_>) -> bool {
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
            .set_language(&tree_sitter_scala::LANGUAGE.into())
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
            method_value_arity: None,
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        };
        assert_eq!(
            scala_call_shape_relation(&[contextual(1), explicit(1), contextual(2)], &supplied),
            ScalaCallShapeRelation::Complete
        );
        assert_eq!(
            scala_call_shape_relation(&[contextual(1), explicit(1)], &supplied),
            ScalaCallShapeRelation::Complete
        );
        assert_eq!(
            scala_call_shape_relation(
                &[contextual(1)],
                &ScalaCallSiteShape {
                    lists: vec![empty],
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
                &ScalaCallSiteShape {
                    lists: vec![ordinary],
                    method_value_arity: None,
                    method_value_parameter_types: None,
                    method_value_parameter_types_authoritative: false,
                    type_arguments_only: false,
                }
            ),
            ScalaCallShapeRelation::Incompatible
        );

        let partial = ScalaCallSiteShape {
            lists: vec![ordinary],
            method_value_arity: Some(1),
            method_value_parameter_types: None,
            method_value_parameter_types_authoritative: false,
            type_arguments_only: false,
        };
        assert_eq!(
            scala_call_shape_relation(&[explicit(1), explicit(1)], &partial),
            ScalaCallShapeRelation::Partial {
                next_explicit_arity: CallableArity::exact(1)
            }
        );
        assert!(scala_callable_shape_matches(
            &[explicit(1), explicit(1)],
            Some(&partial),
            ScalaCallableUsePolicy::OrdinaryMethod,
            true,
        ));
        assert!(!scala_callable_shape_matches(
            &[explicit(1), explicit(1)],
            Some(&partial),
            ScalaCallableUsePolicy::OrdinaryMethod,
            false,
        ));
        assert!(!scala_callable_shape_matches(
            &[explicit(1), explicit(1)],
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
            .set_language(&tree_sitter_scala::LANGUAGE.into())
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
            .set_language(&tree_sitter_scala::LANGUAGE.into())
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
            Some(&zero),
            ScalaCallableSiteRole::ExplicitConstruction,
            false,
        ));
        assert!(!scala_callable_alternative_matches(
            ScalaCallableRole::SecondaryConstructor,
            &declared,
            Some(&zero),
            ScalaCallableSiteRole::PrimaryConstruction,
            false,
        ));
        assert!(!scala_callable_alternative_matches(
            ScalaCallableRole::SecondaryConstructor,
            &declared,
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
            .set_language(&tree_sitter_scala::LANGUAGE.into())
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
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_scala::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala tree");
        let mut value_roles = Vec::new();
        let mut box_roles = Vec::new();
        let mut package_paths = Vec::new();
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
                        value_roles.push(reference.role);
                    }
                    "Box" => box_roles.push(reference.role),
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
    }
}
