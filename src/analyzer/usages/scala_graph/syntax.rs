use crate::analyzer::scala::{scala_package_prefixes_at, scala_type_lookup_segments};
use crate::analyzer::{CallableArity, ImportInfo, scala_parenthesized_arity};
use crate::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

#[derive(Default)]
pub(crate) struct ScalaSourceFacts {
    pub(crate) callable_alternatives_by_range:
        HashMap<(usize, usize), ScalaCallableSourceAlternative>,
    pub(crate) field_type_paths_by_range: HashMap<(usize, usize), Vec<String>>,
    pub(crate) stable_owner_ranges: HashSet<(usize, usize)>,
    pub(crate) case_class_ranges: HashSet<(usize, usize)>,
}

#[derive(Clone)]
pub(crate) struct ScalaCallableSourceAlternative {
    pub(crate) shape: Vec<ScalaCallableParameterList>,
    pub(crate) parameter_function_arities: Vec<Vec<Option<usize>>>,
    pub(crate) extension_receiver_type_path: Option<Vec<String>>,
    pub(crate) return_type_path: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalaMethodValueContext {
    Unknown,
    Function(usize),
    Incompatible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalaParameterListKind {
    Explicit,
    Contextual,
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
                facts.callable_alternatives_by_range.insert(
                    (node.start_byte(), node.end_byte()),
                    ScalaCallableSourceAlternative {
                        shape,
                        parameter_function_arities,
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
            "class_definition" => {
                let mut cursor = node.walk();
                let lists = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "class_parameters")
                    .map(callable_parameter_list)
                    .collect::<Vec<_>>();
                if !lists.is_empty() {
                    facts.callable_alternatives_by_range.insert(
                        (node.start_byte(), node.end_byte()),
                        ScalaCallableSourceAlternative {
                            shape: lists,
                            parameter_function_arities: Vec::new(),
                            extension_receiver_type_path: None,
                            return_type_path: None,
                        },
                    );
                }
                let mut children = node.walk();
                if node
                    .children(&mut children)
                    .any(|child| child.kind() == "case")
                {
                    facts
                        .case_class_ranges
                        .insert((node.start_byte(), node.end_byte()));
                }
            }
            "object_definition" | "enum_definition" => {
                facts
                    .stable_owner_ranges
                    .insert((node.start_byte(), node.end_byte()));
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Some(facts)
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
        if left.kind() == "instance_expression" {
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
fn is_infix_type_operator_reference(node: Node<'_>) -> bool {
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
    node.parent().is_some_and(|parent| {
        parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(node)
    })
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

pub(crate) fn has_member_qualifier(node: Node<'_>) -> bool {
    field_expression_for_member(node).is_some()
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

pub(crate) fn call_arity_for_reference(node: Node<'_>) -> Option<usize> {
    call_arities_for_reference(node).and_then(|arities| arities.first().copied())
}

pub(crate) fn call_arities_for_reference(node: Node<'_>) -> Option<Vec<usize>> {
    let parent = node.parent()?;
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return Some(vec![1]);
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
    let mut arities = Vec::new();
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
            let mut cursor = arguments.walk();
            arities.push(arguments.named_children(&mut cursor).count());
        } else {
            // `new T:` / `new T { ... }` has no `arguments` child, but it still
            // invokes the argumentless primary constructor.
            arities.push(0);
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
        let mut cursor = arguments.walk();
        arities.push(arguments.named_children(&mut cursor).count());
        expression = call;
    }
    (!arities.is_empty()).then_some(arities)
}

pub(crate) fn infix_receiver_for_operator(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node))
        .then(|| parent.child_by_field_name("left"))
        .flatten()
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

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

#[cfg(test)]
mod tests {
    use super::*;

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
