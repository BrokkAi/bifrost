pub(in crate::analyzer::usages) use crate::analyzer::usages::common::node_text;
pub(super) use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::inverted_edges::ClassRangeIndex;
use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::{
    CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile, csharp_normalize_full_name,
    csharp_signature_arity, csharp_signature_return_type, csharp_using_directive_is_static,
    resolve_analyzer,
};
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner: CodeUnit,
    pub(super) member_name: String,
    pub(super) method_arity: Option<usize>,
    pub(super) is_extension_method: bool,
    pub(super) extension_receiver_type: Option<String>,
}

impl TargetSpec {
    pub(super) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: target.clone(),
                member_name: target.identifier().to_string(),
                method_arity: None,
                is_extension_method: false,
                extension_receiver_type: None,
            });
        }

        let owner = analyzer.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.identifier() == owner.identifier() {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner,
            member_name: target.identifier().to_string(),
            method_arity: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| signature_arity(target.signature())),
            is_extension_method: kind == TargetKind::Method
                && is_extension_method(analyzer, target),
            extension_receiver_type: (kind == TargetKind::Method)
                .then(|| extension_method_receiver_type(analyzer, target))
                .flatten(),
        })
    }

    pub(super) fn is_extension_method(&self) -> bool {
        self.is_extension_method
    }
}

pub(in crate::analyzer::usages) fn signature_arity(signature: Option<&str>) -> usize {
    csharp_signature_arity(signature)
}

pub(in crate::analyzer::usages) fn seed_visible_bindings_at(
    scope: Node<'_>,
    target: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_visible_bindings_inner(scope, target, csharp, file, source, bindings);
}

pub(in crate::analyzer::usages) fn seed_bindings_before(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_bindings_before_inner(node, cutoff_start, csharp, file, source, bindings);
}

fn seed_bindings_before_inner(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }

    match node.kind() {
        "parameter" => seed_parameter(node, csharp, file, source, bindings),
        "variable_declaration" => seed_variable_declaration(node, csharp, file, source, bindings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        seed_bindings_before_inner(child, cutoff_start, csharp, file, source, bindings);
    }
}

const SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "property_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "block",
    "for_statement",
    "for_each_statement",
    "using_statement",
    "catch_clause",
];

fn seed_visible_bindings_inner(
    node: Node<'_>,
    target: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.start_byte() >= target.start_byte() {
        return;
    }

    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope && !node_covers(node, target) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }

    match node.kind() {
        "parameter" => seed_parameter(node, csharp, file, source, bindings),
        "variable_declaration" => seed_variable_declaration(node, csharp, file, source, bindings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= target.start_byte() {
            break;
        }
        if SCOPE_NODES.contains(&child.kind()) && !node_covers(child, target) {
            continue;
        }
        seed_visible_bindings_inner(child, target, csharp, file, source, bindings);
    }
}

fn node_covers(container: Node<'_>, target: Node<'_>) -> bool {
    container.start_byte() <= target.start_byte() && target.end_byte() <= container.end_byte()
}

fn seed_parameter(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings);
}

fn seed_variable_declaration(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = node_text(type_node, source);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if type_text == "var" {
            if let Some(initializer_type) = object_created_type(child)
                && let Some(target) =
                    resolve_type_fq_name(csharp, file, node_text(initializer_type, source))
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else if let Some(target) =
                var_initializer_member_type(child, csharp, file, source, bindings)
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else {
                bindings.declare_shadow(node_text(name_node, source));
            }
        } else {
            seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings);
        }
    }
}

fn var_initializer_member_type(
    declarator: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    let initializer = variable_declarator_initializer(declarator)?;
    expression_type_fq_name(initializer, csharp, file, source, bindings)
}

fn variable_declarator_initializer(declarator: Node<'_>) -> Option<Node<'_>> {
    declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .or_else(|| {
            let mut cursor = declarator.walk();
            declarator
                .named_children(&mut cursor)
                .find(|child| child.kind() == "equals_value_clause")
                .and_then(|clause| {
                    clause
                        .child_by_field_name("value")
                        .or_else(|| clause.named_child(0))
                })
        })
        .or_else(|| {
            let name = declarator.child_by_field_name("name")?;
            let mut cursor = declarator.walk();
            declarator
                .named_children(&mut cursor)
                .find(|child| child.start_byte() > name.end_byte())
        })
}

fn expression_type_fq_name(
    expression: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let name = node_text(expression, source);
            first_precise_binding(bindings, name).or_else(|| {
                let owner = enclosing_declared_type(expression, csharp, file, source)?;
                member_declared_type_fq_name(csharp, file, &owner, name)
            })
        }
        "member_access_expression" => {
            let receiver = member_access_receiver(expression)?;
            let name = member_access_name(expression)?;
            let owners = receiver_type_units(receiver, csharp, file, source, bindings);
            owners.into_iter().find_map(|owner| {
                member_declared_type_fq_name(csharp, file, &owner, node_text(name, source))
            })
        }
        "invocation_expression" => {
            invocation_expression_return_type_fq_name(expression, csharp, file, source, bindings)
        }
        _ => None,
    }
}

fn invocation_expression_return_type_fq_name(
    invocation: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    let function = invocation.child_by_field_name("function")?;
    let arity = argument_count(invocation, source);
    match function.kind() {
        "identifier" => {
            let owner = enclosing_declared_type(function, csharp, file, source)?;
            method_return_type_fq_name_for_arity(
                csharp,
                file,
                &owner,
                node_text(function, source),
                Some(arity),
            )
        }
        "member_access_expression" => {
            let receiver = member_access_receiver(function)?;
            let name = member_access_name(function)?;
            let owners = receiver_type_units(receiver, csharp, file, source, bindings);
            owners.into_iter().find_map(|owner| {
                method_return_type_fq_name_for_arity(
                    csharp,
                    file,
                    &owner,
                    node_text(name, source),
                    Some(arity),
                )
            })
        }
        _ => None,
    }
}

fn receiver_type_units(
    receiver: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, source);
            if let Some(target) = first_precise_binding(bindings, name) {
                return type_declarations_for_fq_name(csharp, &target);
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else {
                enclosing_declared_type(receiver, csharp, file, source)
                    .and_then(|owner| member_declared_type_fq_name(csharp, file, &owner, name))
                    .into_iter()
                    .flat_map(|fq_name| type_declarations_for_fq_name(csharp, &fq_name))
                    .collect()
            }
        }
        "this" => enclosing_declared_type(receiver, csharp, file, source)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn first_precise_binding(bindings: &LocalInferenceEngine<String>, name: &str) -> Option<String> {
    let crate::analyzer::usages::local_inference::SymbolResolution::Precise(targets) =
        bindings.resolve_symbol(name)
    else {
        return None;
    };
    (targets.len() == 1)
        .then(|| targets.into_iter().next())
        .flatten()
}

fn member_access_receiver(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("expression")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("receiver"))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() != "identifier")
        })
}

fn member_access_name(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .last()
    })
}

pub(super) fn enclosing_declared_type(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    _source: &str,
) -> Option<CodeUnit> {
    let byte = node.start_byte();
    let class_ranges = ClassRangeIndex::build(csharp, file);
    let fqn = class_ranges.enclosing(byte)?;
    class_unit_for_fq_name(csharp, fqn)
}

fn class_unit_for_fq_name(csharp: &CSharpAnalyzer, fqn: &str) -> Option<CodeUnit> {
    let mut candidates = type_declarations_for_fq_name(csharp, fqn);
    csharp.sort_dedup_type_candidates(&mut candidates);
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn type_declarations_for_fq_name(csharp: &CSharpAnalyzer, fqn: &str) -> Vec<CodeUnit> {
    let index = csharp.definition_lookup_index();
    let normalized = csharp_normalize_full_name(fqn);
    let mut candidates = index
        .by_fqn(fqn)
        .iter()
        .chain(index.by_normalized_fqn(&normalized).iter())
        .filter(|unit| unit.is_class())
        .cloned()
        .collect::<Vec<_>>();
    csharp.sort_dedup_type_candidates(&mut candidates);
    candidates
}

pub(in crate::analyzer::usages) fn member_declared_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    owner: &CodeUnit,
    member_name: &str,
) -> Option<String> {
    let member_fqn = format!("{}.{}", owner.fq_name(), member_name);
    csharp
        .definition_lookup_index()
        .members_for_owner_name(
            owner.fq_name().as_str(),
            &csharp_normalize_full_name(&owner.fq_name()),
            member_name,
        )
        .into_iter()
        .filter(|unit| unit.is_field() && unit.fq_name() == member_fqn)
        .filter_map(|unit| {
            let indexed = csharp
                .usage_facts_index()
                .fact_for_declaration(unit)
                .and_then(|facts| facts.return_type_fqn.as_deref())
                .map(str::to_string);
            indexed.or_else(|| {
                member_declared_type(csharp, unit).and_then(|type_text| {
                    resolve_member_type_fq_name(csharp, file, owner, &type_text)
                })
            })
        })
        .next()
}

/// Resolve the type named by a method's declared return type, so a call
/// receiver (`GetFoo().Member`) can be typed by the callee. The stored member
/// `signature()` keeps only the parameter list, so read the return type from the
/// full signature text (`signatures`), which is `Return Name(params) { … }`.
pub(in crate::analyzer::usages) fn method_return_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    owner: &CodeUnit,
    method_name: &str,
) -> Option<String> {
    method_return_type_fq_name_for_arity(csharp, file, owner, method_name, None)
}

pub(in crate::analyzer::usages) fn method_return_type_fq_name_for_arity(
    csharp: &CSharpAnalyzer,
    _file: &ProjectFile,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
) -> Option<String> {
    let method_fqn = format!("{}.{}", owner.fq_name(), method_name);
    let mut resolved = csharp
        .definition_lookup_index()
        .members_for_owner_name(
            owner.fq_name().as_str(),
            &csharp_normalize_full_name(&owner.fq_name()),
            method_name,
        )
        .into_iter()
        .filter(|unit| unit.is_function() && unit.fq_name() == method_fqn)
        .filter_map(|unit| {
            let facts = csharp.usage_facts_index().fact_for_declaration(unit);
            let unit_arity = facts
                .and_then(|facts| facts.arity)
                .unwrap_or_else(|| signature_arity(unit.signature()));
            if arity.is_some_and(|arity| unit_arity != arity) {
                return None;
            }
            facts
                .and_then(|facts| facts.return_type_fqn.clone())
                .or_else(|| {
                    let type_text = method_return_type(csharp, unit)?;
                    resolve_member_type_fq_name(csharp, unit.source(), owner, &type_text)
                })
        })
        .collect::<Vec<_>>();
    resolved.sort();
    resolved.dedup();
    (resolved.len() == 1).then(|| resolved.remove(0))
}

pub(in crate::analyzer::usages) fn method_unit_return_type_fq_name(
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    method: &CodeUnit,
) -> Option<String> {
    let type_text = method_return_type(csharp, method)?;
    resolve_member_type_fq_name(csharp, method.source(), owner, &type_text)
}

fn resolve_member_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    owner: &CodeUnit,
    type_text: &str,
) -> Option<String> {
    let nested_fq_name = if owner.package_name().is_empty() {
        format!("{}${type_text}", owner.short_name())
    } else {
        format!(
            "{}.{}${type_text}",
            owner.package_name(),
            owner.short_name()
        )
    };
    class_unit_for_fq_name(csharp, &nested_fq_name)
        .map(|unit| unit.fq_name())
        .or_else(|| resolve_type_fq_name(csharp, file, type_text))
}

fn member_declared_type(csharp: &CSharpAnalyzer, member: &CodeUnit) -> Option<String> {
    let signatures = csharp.signatures(member);
    let signature = member
        .signature()
        .or_else(|| signatures.first().map(String::as_str))?;
    type_text_before_name(signature, member.identifier())
}

/// A method's declared return type, read from the full signature
/// (`Return Name(params) { … }`); constructors, whose signature starts at the
/// name, yield `None`.
fn method_return_type(csharp: &CSharpAnalyzer, method: &CodeUnit) -> Option<String> {
    let signatures = csharp.signatures(method);
    let signature = signatures.first().map(String::as_str)?;
    type_text_before_name(signature, method.identifier())
}

/// Extract the (normalized) type token that precedes `name` in a declaration
/// signature — the field/parameter type or a method's return type.
fn type_text_before_name(signature: &str, name: &str) -> Option<String> {
    csharp_signature_return_type(signature, name)
}

fn seed_symbol_for_type(
    name_node: Node<'_>,
    type_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if let Some(target) = resolve_type_fq_name(csharp, file, node_text(type_node, source)) {
        bindings.seed_symbol(node_text(name_node, source), target);
    } else {
        bindings.declare_shadow(node_text(name_node, source));
    }
}

pub(in crate::analyzer::usages) fn object_created_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .or_else(|| first_type_child(node));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = object_created_type(child) {
            return Some(found);
        }
    }
    None
}

pub(super) fn resolves_to_target(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
    target: &CodeUnit,
) -> bool {
    let normalized = normalize_type_text(reference);
    csharp
        .resolve_visible_type(file, &normalized)
        .is_some_and(|resolved| resolved == *target)
        || reference_matches_target_fq_name(&normalized, target)
}

pub(super) fn resolves_to_target_at(
    file: &ProjectFile,
    class_ranges: &ClassRangeIndex,
    reference: &str,
    node: Node<'_>,
    source: &str,
    target: &CodeUnit,
    csharp: &CSharpAnalyzer,
) -> bool {
    resolve_type_fq_name_at(csharp, file, class_ranges, reference, node, source)
        .is_some_and(|resolved| type_identity_matches(&resolved, &target.fq_name()))
}

pub(super) fn resolve_type_fq_name_at(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    class_ranges: &ClassRangeIndex,
    reference: &str,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let normalized = normalize_type_text(reference);
    if normalized.is_empty() || type_parameter_shadows_reference(node, source, &normalized) {
        return None;
    }
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    resolve_in_enclosing_class_ranges(csharp, class_ranges, &normalized, node.start_byte())
        .map(|unit| unit.fq_name())
        .or_else(|| {
            csharp
                .resolve_visible_type(file, &normalized)
                .map(|unit| unit.fq_name())
        })
        .or_else(|| class_unit_for_fq_name(csharp, &normalized).map(|unit| unit.fq_name()))
}

fn resolve_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let normalized = normalize_type_text(reference);
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    if let Some(target) = csharp.resolve_visible_type(file, &normalized) {
        return Some(target.fq_name());
    }
    class_unit_for_fq_name(csharp, &normalized).map(|unit| unit.fq_name())
}

fn resolve_in_enclosing_class_ranges(
    csharp: &CSharpAnalyzer,
    class_ranges: &ClassRangeIndex,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if name.is_empty() || name.contains('.') {
        return None;
    }
    let mut scope = class_ranges.enclosing(byte)?.to_string();
    loop {
        if scope.is_empty() {
            return None;
        }
        let child_fqn = format!("{scope}.{name}");
        if let Some(child) = class_unit_for_fq_name(csharp, &child_fqn) {
            return Some(child);
        }
        match scope.rfind('.') {
            Some(idx) => scope.truncate(idx),
            None => return None,
        }
    }
}

fn type_parameter_shadows_reference(node: Node<'_>, source: &str, reference: &str) -> bool {
    if reference.contains('.') {
        return false;
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if declaration_type_parameters_shadow(parent, source, reference) {
            return true;
        }
        current = parent;
    }
    false
}

fn declaration_type_parameters_shadow(
    declaration: Node<'_>,
    source: &str,
    reference: &str,
) -> bool {
    if !matches!(
        declaration.kind(),
        "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "operator_declaration"
            | "delegate_declaration"
            | "local_function_statement"
    ) {
        return false;
    }
    declaration
        .child_by_field_name("type_parameters")
        .or_else(|| first_named_child_of_kind(declaration, "type_parameter_list"))
        .is_some_and(|parameters| type_parameter_list_contains(parameters, source, reference))
}

fn type_parameter_list_contains(parameters: Node<'_>, source: &str, reference: &str) -> bool {
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        parameter.kind() == "type_parameter" && type_parameter_name(parameter, source) == reference
    })
}

fn type_parameter_name<'a>(parameter: Node<'_>, source: &'a str) -> &'a str {
    parameter
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .unwrap_or_else(|| node_text(parameter, source))
        .trim()
}

pub(super) fn type_identity_matches(left: &str, right: &str) -> bool {
    left == right
        || canonical_builtin_type_identity(left).is_some_and(|left| {
            canonical_builtin_type_identity(right).is_some_and(|right| left == right)
        })
}

fn canonical_builtin_type_identity(reference: &str) -> Option<&'static str> {
    match reference.strip_prefix("global::").unwrap_or(reference) {
        "bool" | "System.Boolean" => Some("System.Boolean"),
        "byte" | "System.Byte" => Some("System.Byte"),
        "sbyte" | "System.SByte" => Some("System.SByte"),
        "char" | "System.Char" => Some("System.Char"),
        "decimal" | "System.Decimal" => Some("System.Decimal"),
        "double" | "System.Double" => Some("System.Double"),
        "float" | "System.Single" => Some("System.Single"),
        "int" | "System.Int32" => Some("System.Int32"),
        "uint" | "System.UInt32" => Some("System.UInt32"),
        "nint" | "System.IntPtr" => Some("System.IntPtr"),
        "nuint" | "System.UIntPtr" => Some("System.UIntPtr"),
        "long" | "System.Int64" => Some("System.Int64"),
        "ulong" | "System.UInt64" => Some("System.UInt64"),
        "short" | "System.Int16" => Some("System.Int16"),
        "ushort" | "System.UInt16" => Some("System.UInt16"),
        "string" | "System.String" => Some("System.String"),
        "object" | "System.Object" => Some("System.Object"),
        _ => None,
    }
}

pub(in crate::analyzer::usages) fn is_extension_method(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> bool {
    unit.is_function()
        && analyzer
            .signatures(unit)
            .iter()
            .any(|signature| extension_receiver_type_from_signature(signature).is_some())
}

pub(in crate::analyzer::usages) fn extension_method_receiver_type(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<String> {
    if !unit.is_function() {
        return None;
    }
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
    let owner = analyzer.parent_of(unit)?;
    analyzer
        .signatures(unit)
        .iter()
        .find_map(|signature| extension_receiver_type_from_signature(signature))
        .and_then(|type_text| {
            resolve_member_type_fq_name(csharp, unit.source(), &owner, &type_text)
        })
}

fn extension_receiver_type_from_signature(signature: &str) -> Option<String> {
    let parameters = signature.split_once('(')?.1;
    let first_parameter = parameters.split(')').next()?.split(',').next()?.trim();
    let without_this = first_parameter.strip_prefix("this ")?.trim();
    let parameter_name = without_this.split_whitespace().last()?;
    let type_text = without_this
        .strip_suffix(parameter_name)
        .unwrap_or(without_this)
        .trim();
    let normalized = normalize_type_text(type_text);
    (!normalized.is_empty()).then_some(normalized)
}

fn reference_matches_target_fq_name(reference: &str, target: &CodeUnit) -> bool {
    reference == target.fq_name() || reference == target.fq_name().replace('$', ".")
}

pub(super) fn normalize_type_text(reference: &str) -> String {
    let mut normalized = reference.trim();
    loop {
        let without_nullable = normalized.trim_end_matches('?').trim();
        let without_arrays = without_nullable.trim_end_matches("[]").trim();
        if without_arrays == normalized {
            break;
        }
        normalized = without_arrays;
    }
    normalized
        .split('<')
        .next()
        .unwrap_or(normalized)
        .trim()
        .to_string()
}

pub(in crate::analyzer::usages) fn reference_type_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "qualified_name" | "generic_name" | "nullable_type" | "array_type"
        ) {
            node = parent;
            continue;
        }
        break;
    }
    node
}

pub(in crate::analyzer::usages) fn reference_type_text(node: Node<'_>, source: &str) -> String {
    normalize_type_text(node_text(reference_type_node(node), source))
}

pub(in crate::analyzer::usages) fn binding_scope_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "property_declaration"
                | "accessor_declaration"
                | "local_function_statement"
        ) {
            return parent;
        }
        node = parent;
    }
    node
}

pub(super) fn receiver_targets_owner(
    receiver_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> SymbolResolution<String> {
    receiver_type_fq_names(receiver_node, csharp, file, source, bindings)
}

fn receiver_type_fq_names(
    receiver_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> SymbolResolution<String> {
    match receiver_node.kind() {
        "identifier" => {
            let receiver = node_text(receiver_node, source);
            match bindings.resolve_symbol(receiver) {
                SymbolResolution::Precise(targets) => SymbolResolution::Precise(targets),
                SymbolResolution::Unknown if !bindings.is_shadowed(receiver) => {
                    class_field_receiver_type(receiver_node, receiver, csharp, file, source)
                }
                resolution => resolution,
            }
        }
        "member_access_expression" => {
            expression_type_fq_name(receiver_node, csharp, file, source, bindings)
                .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
                .unwrap_or(SymbolResolution::Unknown)
        }
        "invocation_expression" => {
            expression_type_fq_name(receiver_node, csharp, file, source, bindings)
                .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
                .unwrap_or(SymbolResolution::Unknown)
        }
        "this" => enclosing_declared_type(receiver_node, csharp, file, source)
            .map(|owner| SymbolResolution::Precise(std::iter::once(owner.fq_name()).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        _ => SymbolResolution::Unknown,
    }
}

pub(in crate::analyzer::usages) fn class_field_receiver_type(
    receiver_node: Node<'_>,
    receiver: &str,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SymbolResolution<String> {
    enclosing_declared_type(receiver_node, csharp, file, source)
        .and_then(|enclosing| member_declared_type_fq_name(csharp, file, &enclosing, receiver))
        .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
        .unwrap_or(SymbolResolution::Unknown)
}

pub(super) fn expression_resolves_to_type(
    expression: Node<'_>,
    owner: &CodeUnit,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> SymbolResolution<String> {
    match expression_type_fq_name(expression, csharp, file, source, bindings) {
        Some(fq_name) if fq_name == owner.fq_name() => {
            SymbolResolution::Precise(std::iter::once(fq_name).collect())
        }
        _ => SymbolResolution::Unknown,
    }
}

/// Whether an unqualified `member_name` is bound by a local (parameter or local
/// variable) of the same name in scope — in which case it is provably *not* the
/// field, so the occurrence should be skipped rather than treated as an ambiguous
/// (fallback-forcing) match.
pub(super) fn member_name_is_locally_bound(
    member_name: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    !matches!(
        bindings.resolve_symbol(member_name),
        SymbolResolution::Unknown
    ) || bindings.is_shadowed(member_name)
}

/// An unqualified identifier (no receiver) that matches a field/property name resolves to
/// that field only when it appears inside the owning type and is not shadowed by a local
/// binding (parameter or local variable) of the same name. This proves self-references such
/// as `Last = value` inside a method of the field's own class.
pub(super) fn unqualified_member_resolves_to_owner(
    node: Node<'_>,
    member_name: &str,
    owner: &CodeUnit,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    if member_name_is_locally_bound(member_name, bindings) {
        return false;
    }
    enclosing_declared_type(node, csharp, file, source)
        .is_some_and(|enclosing| enclosing.fq_name() == owner.fq_name())
}

pub(in crate::analyzer::usages) fn is_type_reference_node(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent
            .child_by_field_name("type")
            .is_some_and(|type_node| same_node(type_node, node))
            || parent
                .child_by_field_name("return_type")
                .is_some_and(|type_node| same_node(type_node, node))
            || parent
                .child_by_field_name("returns")
                .is_some_and(|type_node| same_node(type_node, node))
        {
            return true;
        }
        if parent.kind() == "type" {
            return true;
        }
        if parent.kind() == "type_argument_list" {
            return true;
        }
        if parent.kind() == "explicit_interface_specifier" {
            return true;
        }
        if parent.kind() == "object_creation_expression" {
            return true;
        }
        if csharp_using_directive_is_static(parent) {
            return true;
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) && !parent
            .child_by_field_name("name")
            .is_some_and(|name| same_node(name, node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "qualified_name" | "generic_name" | "nullable_type" | "array_type" | "base_list"
        ) {
            node = parent;
            continue;
        }
        return false;
    }
    false
}

pub(in crate::analyzer::usages) fn argument_count(node: Node<'_>, _source: &str) -> usize {
    let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
    else {
        return 0;
    };
    count_named_children_of_kind(arguments, "argument")
}

pub(in crate::analyzer::usages) fn object_initializer_for_label(
    node: Node<'_>,
) -> Option<Node<'_>> {
    let parent = node.parent()?;
    if parent.kind() != "assignment_expression" {
        return None;
    }
    if parent.child_by_field_name("left") != Some(node) && parent.named_child(0) != Some(node) {
        return None;
    }
    let initializer = parent.parent()?;
    matches!(
        initializer.kind(),
        "initializer_expression" | "object_initializer_expression"
    )
    .then_some(initializer)
}

fn count_named_children_of_kind(node: Node<'_>, kind: &str) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == kind)
        .count()
}

pub(in crate::analyzer::usages) fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "identifier"
                | "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type"
        )
    })
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}
