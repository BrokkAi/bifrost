pub(in crate::analyzer::usages) use crate::analyzer::usages::common::node_text;
pub(super) use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::inverted_edges::ClassRangeIndex;
use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::usages::parsed_tree::parse_tree_sitter_file;
use crate::analyzer::{
    CSharpAnalyzer, CSharpMemberName, CallableArity, CodeUnit, IAnalyzer, ProjectFile,
    csharp_callable_arity, csharp_conditional_member_access, csharp_member_name,
    csharp_method_generic_arity, csharp_normalize_full_name, csharp_signature_return_type,
    csharp_source_identifier, csharp_type_node_identity, csharp_type_reference_root,
    csharp_using_directive_is_global, csharp_using_directive_is_static,
    csharp_using_directive_namespace, csharp_using_directive_target, resolve_analyzer,
};
use crate::hash::HashSet;
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
    pub(super) callable_arity: Option<CallableArity>,
    pub(super) generic_arity: Option<usize>,
    pub(super) is_extension_method: bool,
}

impl TargetSpec {
    pub(super) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: target.clone(),
                member_name: csharp_source_identifier(target).to_string(),
                callable_arity: None,
                generic_arity: None,
                is_extension_method: false,
            });
        }

        let owner = analyzer.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.identifier() == csharp_source_identifier(&owner) {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner,
            member_name: target.identifier().to_string(),
            callable_arity: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| csharp_callable_arity(analyzer, target)),
            generic_arity: (kind == TargetKind::Method)
                .then(|| csharp_method_generic_arity(target.signature())),
            is_extension_method: kind == TargetKind::Method
                && is_extension_method(analyzer, target),
        })
    }

    pub(super) fn is_extension_method(&self) -> bool {
        self.is_extension_method
    }

    pub(super) fn accepts_explicit_generic_arity(&self, arity: Option<usize>) -> bool {
        arity.is_none_or(|arity| self.generic_arity == Some(arity))
    }
}

pub(in crate::analyzer::usages) fn seed_visible_bindings_at(
    scope: Node<'_>,
    target: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_visible_bindings_inner(scope, target, csharp, file, source, bindings, true);
}

pub(in crate::analyzer::usages) fn seed_bindings_before(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_bindings_before_inner(node, cutoff_start, csharp, file, source, bindings, false);
}

fn seed_bindings_before_inner(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    usage: bool,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }

    match node.kind() {
        "parameter" => seed_parameter(node, csharp, file, source, bindings, usage),
        "variable_declaration" => {
            seed_variable_declaration(node, csharp, file, source, bindings, usage)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        seed_bindings_before_inner(child, cutoff_start, csharp, file, source, bindings, usage);
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
    usage: bool,
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
        "parameter" => seed_parameter(node, csharp, file, source, bindings, usage),
        "variable_declaration" => {
            seed_variable_declaration(node, csharp, file, source, bindings, usage)
        }
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
        seed_visible_bindings_inner(child, target, csharp, file, source, bindings, usage);
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
    usage: bool,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings, usage);
}

fn seed_variable_declaration(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
    usage: bool,
) {
    if is_member_variable_declaration(node) {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = reference_type_text(type_node, source);

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
                && let Some(target) = resolve_type_fq_name_for_scope(
                    csharp,
                    file,
                    &reference_type_text(initializer_type, source),
                    usage,
                )
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else if let Some(target) =
                var_initializer_member_type(child, csharp, file, source, bindings, usage)
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else {
                bindings.declare_shadow(node_text(name_node, source));
            }
        } else {
            seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings, usage);
        }
    }
}

pub(super) fn is_member_variable_declaration(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "field_declaration" | "event_field_declaration"
        )
    })
}

fn var_initializer_member_type(
    declarator: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
    usage: bool,
) -> Option<String> {
    let initializer = variable_declarator_initializer(declarator)?;
    expression_type_fq_name_inner(initializer, csharp, file, source, bindings, usage)
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
    expression_type_fq_name_inner(expression, csharp, file, source, bindings, true)
}

fn expression_type_fq_name_inner(
    expression: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
    usage: bool,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let name = node_text(expression, source);
            first_precise_binding(bindings, name).or_else(|| {
                let owner = enclosing_declared_type(expression, csharp, file, source)?;
                member_declared_type_fq_name_for_scope(csharp, &owner, name, usage)
            })
        }
        "member_access_expression" | "conditional_access_expression" => {
            let (receiver, name_node) = match expression.kind() {
                "member_access_expression" => (
                    member_access_receiver(expression)?,
                    member_access_name(expression)?,
                ),
                _ => {
                    let access = csharp_conditional_member_access(expression)?;
                    (access.receiver, access.name)
                }
            };
            let name = csharp_member_name(name_node)?;
            let owners = receiver_type_units(receiver, csharp, file, source, bindings);
            owners.into_iter().find_map(|owner| {
                member_declared_type_fq_name_for_scope(
                    csharp,
                    &owner,
                    node_text(name.identifier, source),
                    usage,
                )
            })
        }
        "invocation_expression" => invocation_expression_return_type_fq_name(
            expression, csharp, file, source, bindings, usage,
        ),
        "parenthesized_expression" | "checked_expression" => {
            expression.named_child(0).and_then(|inner| {
                expression_type_fq_name_inner(inner, csharp, file, source, bindings, usage)
            })
        }
        "cast_expression" | "as_expression" => expression
            .child_by_field_name(if expression.kind() == "cast_expression" {
                "type"
            } else {
                "right"
            })
            .and_then(|type_node| {
                resolve_type_fq_name_for_scope(
                    csharp,
                    file,
                    &reference_type_text(type_node, source),
                    usage,
                )
            }),
        _ => None,
    }
}

fn invocation_expression_return_type_fq_name(
    invocation: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
    usage: bool,
) -> Option<String> {
    let function = invocation.child_by_field_name("function")?;
    let arity = argument_count(invocation, source);
    match function.kind() {
        "identifier" => {
            let owner = enclosing_declared_type(function, csharp, file, source)?;
            method_return_type_fq_name_for_arity_inner(
                csharp,
                &owner,
                node_text(function, source),
                Some(arity),
                None,
                None,
                usage,
            )
        }
        "generic_name" => {
            let name = csharp_member_name(function)?;
            let type_arguments = resolved_type_arguments(name, csharp, file, source, usage);
            let owner = enclosing_declared_type(function, csharp, file, source)?;
            method_return_type_fq_name_for_arity_inner(
                csharp,
                &owner,
                node_text(name.identifier, source),
                Some(arity),
                name.explicit_generic_arity,
                type_arguments.as_deref(),
                usage,
            )
        }
        "member_access_expression" | "conditional_access_expression" => {
            let (receiver, name_node) = match function.kind() {
                "member_access_expression" => (
                    member_access_receiver(function)?,
                    member_access_name(function)?,
                ),
                _ => {
                    let access = csharp_conditional_member_access(function)?;
                    (access.receiver, access.name)
                }
            };
            let name = csharp_member_name(name_node)?;
            let type_arguments = resolved_type_arguments(name, csharp, file, source, usage);
            let owners = receiver_type_units(receiver, csharp, file, source, bindings);
            owners.into_iter().find_map(|owner| {
                method_return_type_fq_name_for_arity_inner(
                    csharp,
                    &owner,
                    node_text(name.identifier, source),
                    Some(arity),
                    name.explicit_generic_arity,
                    type_arguments.as_deref(),
                    usage,
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
                return usage_type_declarations_for_fq_name(csharp, &target);
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else {
                enclosing_declared_type(receiver, csharp, file, source)
                    .and_then(|owner| usage_member_declared_type_fq_name(csharp, &owner, name))
                    .or_else(|| resolve_usage_type_fq_name(csharp, file, name))
                    .into_iter()
                    .flat_map(|fq_name| usage_type_declarations_for_fq_name(csharp, &fq_name))
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

pub(super) fn class_unit_for_fq_name(csharp: &CSharpAnalyzer, fqn: &str) -> Option<CodeUnit> {
    let mut candidates = usage_type_declarations_for_fq_name(csharp, fqn);
    csharp.sort_dedup_type_candidates(&mut candidates);
    (candidates.len() == 1).then(|| candidates.remove(0))
}

pub(in crate::analyzer::usages) fn usage_direct_base(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
) -> Option<CodeUnit> {
    let mut candidates = csharp
        .usage_direct_ancestors(owner)
        .into_iter()
        .filter(|candidate| csharp_is_class_base_declaration(analyzer, candidate))
        .collect::<Vec<_>>();
    csharp.sort_dedup_type_candidates(&mut candidates);
    (csharp.logical_type_count(&candidates) == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

fn csharp_is_class_base_declaration(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    let Some(parsed) = parse_tree_sitter_file(candidate.source(), &language) else {
        return false;
    };
    analyzer.ranges(candidate).into_iter().any(|range| {
        parsed
            .tree
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
            .is_some_and(|node| matches!(node.kind(), "class_declaration" | "record_declaration"))
    })
}

fn forward_class_unit_for_fq_name(csharp: &CSharpAnalyzer, fqn: &str) -> Option<CodeUnit> {
    let mut candidates = forward_type_declarations_for_fq_name(csharp, fqn);
    csharp.sort_dedup_type_candidates(&mut candidates);
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn usage_type_declarations_for_fq_name(csharp: &CSharpAnalyzer, fqn: &str) -> Vec<CodeUnit> {
    let mut candidates = csharp.usage_type_candidates_by_fqn(fqn);
    csharp.sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn forward_type_declarations_for_fq_name(csharp: &CSharpAnalyzer, fqn: &str) -> Vec<CodeUnit> {
    let mut candidates = csharp
        .declaration_candidates_by_fqn(fqn, false)
        .into_iter()
        .filter(|unit| unit.is_class())
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = csharp
            .declaration_candidates_by_fqn(fqn, true)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect();
    }
    csharp.sort_dedup_type_candidates(&mut candidates);
    candidates
}

pub(in crate::analyzer::usages) fn member_declared_type_fq_name(
    csharp: &CSharpAnalyzer,
    _file: &ProjectFile,
    owner: &CodeUnit,
    member_name: &str,
) -> Option<String> {
    member_declared_type_fq_name_inner(csharp, owner, member_name, false)
}

pub(super) fn usage_member_declared_type_fq_name(
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    member_name: &str,
) -> Option<String> {
    member_declared_type_fq_name_inner(csharp, owner, member_name, true)
}

fn member_declared_type_fq_name_for_scope(
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    member_name: &str,
    usage: bool,
) -> Option<String> {
    member_declared_type_fq_name_inner(csharp, owner, member_name, usage)
}

fn member_declared_type_fq_name_inner(
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    member_name: &str,
    usage: bool,
) -> Option<String> {
    let member_fqn = format!("{}.{}", owner.fq_name(), member_name);
    let candidates = if usage {
        csharp.usage_member_candidates_for_owner(owner.fq_name().as_str(), member_name)
    } else {
        csharp
            .member_candidates_for_owner(owner.fq_name().as_str(), member_name)
            .into_iter()
            .collect()
    };
    let mut resolved_types = candidates
        .into_iter()
        .filter(|unit| unit.is_field() && unit.fq_name() == member_fqn)
        .filter_map(|unit| {
            let declared_type = csharp
                .signature_metadata(&unit)
                .into_iter()
                .find_map(|metadata| metadata.return_type_text().map(str::to_string))
                .or_else(|| member_declared_type(csharp, &unit));
            declared_type.as_deref().and_then(|type_text| {
                resolve_member_type_fq_name(csharp, unit.source(), owner, type_text, usage)
            })
        })
        .collect::<Vec<_>>();
    resolved_types.sort();
    resolved_types.dedup();
    (resolved_types.len() == 1).then(|| resolved_types.remove(0))
}

/// Resolve the type named by a method's declared return type, so a call
/// receiver (`GetFoo().Member`) can be typed by the callee. The stored member
/// `signature()` keeps only the parameter list, so read the return type from the
/// full signature text (`signatures`), which is `Return Name(params) { … }`.
pub(in crate::analyzer::usages) fn method_return_type_fq_name_for_arity(
    csharp: &CSharpAnalyzer,
    _file: &ProjectFile,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
) -> Option<String> {
    method_return_type_fq_name_for_arity_inner(
        csharp,
        owner,
        method_name,
        arity,
        explicit_generic_arity,
        explicit_type_arguments,
        false,
    )
}

pub(super) fn usage_method_return_type_fq_name_for_arity(
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
) -> Option<String> {
    method_return_type_fq_name_for_arity_inner(
        csharp,
        owner,
        method_name,
        arity,
        explicit_generic_arity,
        explicit_type_arguments,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn method_return_type_fq_name_for_arity_inner(
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
) -> Option<String> {
    let mut resolved = nearest_member_candidates_for_owner_inner(
        csharp,
        csharp,
        owner,
        method_name,
        explicit_generic_arity,
        arity,
        usage,
    )
    .into_iter()
    .filter(|unit| unit.is_function())
    .filter_map(|unit| {
        let callable_arity = csharp_callable_arity(csharp, &unit);
        if arity.is_some_and(|call_arity| !callable_arity.accepts(call_arity)) {
            return None;
        }
        callable_return_type_fq_name(csharp, &unit, owner, explicit_type_arguments, usage)
    })
    .collect::<Vec<_>>();
    resolved.sort();
    resolved.dedup();
    (resolved.len() == 1).then(|| resolved.remove(0))
}

/// Resolve a callable's declared return type to a fully-qualified type name,
/// applying explicit type-argument substitution when the return is a bare method
/// type parameter. `owner_fallback` supplies the declaring owner only when the
/// unit's own parent is unavailable. Shared between ordinary member return typing
/// and extension-method return typing so both derive the return FQN identically.
fn callable_return_type_fq_name(
    csharp: &CSharpAnalyzer,
    unit: &CodeUnit,
    owner_fallback: &CodeUnit,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
) -> Option<String> {
    let metadata = csharp.signature_metadata(unit);
    if let Some(substituted) = (!metadata.is_empty())
        .then_some(metadata.as_slice())
        .and_then(|metadata| substituted_method_type_parameter(metadata, explicit_type_arguments))
    {
        return Some(substituted);
    }
    let declared_type = metadata
        .iter()
        .find_map(|metadata| metadata.return_type_text().map(str::to_string))
        .or_else(|| method_return_type(csharp, unit))?;
    let declaring_owner = csharp
        .parent_of(unit)
        .unwrap_or_else(|| owner_fallback.clone());
    resolve_member_type_fq_name(
        csharp,
        unit.source(),
        &declaring_owner,
        &declared_type,
        usage,
    )
}

/// Type an invocation whose callee is an extension method by that extension's
/// declared return type. Mirrors `method_return_type_fq_name_for_arity` for the
/// case the invoked name is not an ordinary member of the receiver type but a
/// visible extension method — the piece that lets chained receivers such as
/// `handler.Handle("Ada").Tag()` be typed when `Handle` is itself an extension.
/// Reuses the shared extension-candidate matcher (so the same visibility scoping
/// and `this`-parameter compatibility gate apply) and the shared return-type
/// derivation. Returns a type FQN only when the matching extensions agree on one.
#[allow(clippy::too_many_arguments)]
pub(in crate::analyzer::usages) fn extension_invocation_return_type_fq_name(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    method: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
) -> Option<String> {
    if receiver_type_names.is_empty() {
        return None;
    }
    let candidates = visible_extension_method_candidates_inner(
        csharp,
        analyzer,
        source,
        site,
        receiver_type_names,
        method,
        call_arity,
        explicit_generic_arity,
        false,
        usage,
    );
    let mut resolved = candidates
        .into_iter()
        .filter(|unit| unit.is_function())
        .filter_map(|unit| {
            callable_return_type_fq_name(csharp, &unit, &unit, explicit_type_arguments, usage)
        })
        .collect::<Vec<_>>();
    resolved.sort();
    resolved.dedup();
    (resolved.len() == 1).then(|| resolved.remove(0))
}

fn resolved_type_arguments(
    name: CSharpMemberName<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    usage: bool,
) -> Option<Vec<String>> {
    let arguments = name.type_arguments?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .map(|argument| {
            resolve_type_fq_name_for_scope(
                csharp,
                file,
                &reference_type_text(argument, source),
                usage,
            )
        })
        .collect()
}

fn substituted_method_type_parameter(
    metadata: &[crate::analyzer::SignatureMetadata],
    explicit_type_arguments: Option<&[String]>,
) -> Option<String> {
    let arguments = explicit_type_arguments?;
    metadata.iter().find_map(|metadata| {
        let return_type = metadata.bare_return_type_parameter()?;
        metadata
            .type_parameters()
            .iter()
            .position(|parameter| parameter == return_type)
            .and_then(|index| arguments.get(index).cloned())
    })
}

fn resolve_member_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    owner: &CodeUnit,
    type_text: &str,
    usage: bool,
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
    let nested = if usage {
        class_unit_for_fq_name(csharp, &nested_fq_name)
    } else {
        forward_class_unit_for_fq_name(csharp, &nested_fq_name)
    };
    nested.map(|unit| unit.fq_name()).or_else(|| {
        if usage {
            resolve_usage_type_fq_name(csharp, file, type_text)
        } else {
            resolve_type_fq_name(csharp, file, type_text)
        }
    })
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
    usage: bool,
) {
    let reference = reference_type_text(type_node, source);
    if let Some(target) = resolve_type_fq_name_for_scope(csharp, file, &reference, usage) {
        bindings.seed_symbol(node_text(name_node, source), target);
    } else if !usage {
        let normalized = normalize_type_text(&reference);
        let raw_type = csharp
            .using_aliases_of(file)
            .get(&normalized)
            .cloned()
            .unwrap_or(normalized);
        if raw_type.is_empty() || raw_type == "var" {
            bindings.declare_shadow(node_text(name_node, source));
        } else {
            bindings.seed_symbol(node_text(name_node, source), raw_type);
        }
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
        .resolve_usage_visible_type(file, &normalized)
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
    let normalized = expand_alias_qualified_type(csharp, file, &normalize_type_text(reference));
    if normalized.is_empty() || type_parameter_shadows_reference(node, source, &normalized) {
        return None;
    }
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    resolve_in_enclosing_type_scopes(csharp, class_ranges, &normalized, node.start_byte())
        .map(|unit| unit.fq_name())
        .or_else(|| resolve_usage_visible_type_fq_name(csharp, file, &normalized))
        .or_else(|| class_unit_for_fq_name(csharp, &normalized).map(|unit| unit.fq_name()))
}

pub(in crate::analyzer::usages) fn resolve_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let normalized = expand_alias_qualified_type(csharp, file, &normalize_type_text(reference));
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    if let Some(target) = resolve_visible_type_fq_name(csharp, file, &normalized) {
        return Some(target);
    }
    forward_class_unit_for_fq_name(csharp, &normalized).map(|unit| unit.fq_name())
}

fn resolve_usage_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let normalized = expand_alias_qualified_type(csharp, file, &normalize_type_text(reference));
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    if let Some(target) = resolve_usage_visible_type_fq_name(csharp, file, &normalized) {
        return Some(target);
    }
    class_unit_for_fq_name(csharp, &normalized).map(|unit| unit.fq_name())
}

fn resolve_type_fq_name_for_scope(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
    usage: bool,
) -> Option<String> {
    if usage {
        resolve_usage_type_fq_name(csharp, file, reference)
    } else {
        resolve_type_fq_name(csharp, file, reference)
    }
}

fn expand_alias_qualified_type(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> String {
    let Some((alias, suffix)) = reference.split_once("::") else {
        return reference.to_string();
    };
    if alias == "global" {
        return reference.to_string();
    }
    csharp
        .using_aliases_of(file)
        .get(alias)
        .map(|target| {
            if suffix.is_empty() {
                target.clone()
            } else {
                format!("{target}.{suffix}")
            }
        })
        .unwrap_or_else(|| reference.to_string())
}

fn resolve_visible_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let candidates = csharp.visible_type_candidates(file, reference);
    (csharp.logical_type_count(&candidates) == 1)
        .then(|| csharp.first_logical_type_fqn(&candidates))
        .flatten()
}

fn resolve_usage_visible_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let candidates = csharp.usage_visible_type_candidates(file, reference);
    (csharp.logical_type_count(&candidates) == 1)
        .then(|| csharp.first_logical_type_fqn(&candidates))
        .flatten()
}

fn resolve_in_enclosing_type_scopes(
    csharp: &CSharpAnalyzer,
    class_ranges: &ClassRangeIndex,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if name.is_empty() || name.contains('.') {
        return None;
    }

    let mut scope = class_ranges.enclosing_unit(byte)?.clone();
    loop {
        let mut parts = csharp.usage_partial_type_parts(&scope);
        if parts.is_empty() {
            parts.push(scope.clone());
        }
        let mut candidates = parts
            .into_iter()
            .flat_map(|part| csharp.direct_children(&part))
            .filter(|child| child.is_class() && child.identifier() == name)
            .collect::<Vec<_>>();
        if !candidates.is_empty() {
            csharp.sort_dedup_type_candidates(&mut candidates);
            return (csharp.logical_type_count(&candidates) == 1)
                .then(|| candidates.into_iter().next())
                .flatten();
        }

        let Some(parent) = csharp.parent_of(&scope) else {
            return resolve_in_enclosing_namespace(csharp, scope.package_name(), name);
        };
        scope = parent;
    }
}

fn resolve_in_enclosing_namespace(
    csharp: &CSharpAnalyzer,
    namespace: &str,
    name: &str,
) -> Option<CodeUnit> {
    let mut namespace = namespace.to_string();
    loop {
        let candidate_fqn = if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{namespace}.{name}")
        };
        if let Some(candidate) = class_unit_for_fq_name(csharp, &candidate_fqn) {
            return Some(candidate);
        }
        let separator = namespace.rfind('.')?;
        namespace.truncate(separator);
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
    extension_method_receiver_type_inner(analyzer, unit, false)
}

fn usage_extension_method_receiver_type(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<String> {
    extension_method_receiver_type_inner(analyzer, unit, true)
}

fn extension_method_receiver_type_inner(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    usage: bool,
) -> Option<String> {
    if !unit.is_function() {
        return None;
    }
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
    let owner = analyzer.parent_of(unit)?;
    let receiver_type = analyzer
        .signatures(unit)
        .iter()
        .find_map(|signature| extension_receiver_type_from_signature(signature))?;
    let resolved =
        resolve_member_type_fq_name(csharp, unit.source(), &owner, &receiver_type, usage);
    if usage {
        resolved
    } else {
        resolved.or_else(|| Some(normalize_type_text(&receiver_type)))
    }
}

#[derive(Default)]
struct CSharpExtensionScope {
    namespaces: HashSet<String>,
    static_owner_fqns: HashSet<String>,
}

pub(super) fn extension_visibility_site_key(site: Node<'_>) -> (usize, usize) {
    let mut root = site;
    while let Some(parent) = root.parent() {
        if parent.kind() == "namespace_declaration" {
            return (parent.start_byte(), parent.end_byte());
        }
        root = parent;
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .find(|child| child.kind() == "file_scoped_namespace_declaration")
        .map_or((root.start_byte(), root.end_byte()), |namespace| {
            (namespace.start_byte(), namespace.end_byte())
        })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::analyzer::usages) fn visible_extension_method_candidates(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    _file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    fallback_when_inapplicable: bool,
) -> Vec<CodeUnit> {
    visible_extension_method_candidates_inner(
        csharp,
        analyzer,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        fallback_when_inapplicable,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn usage_visible_extension_method_candidates(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    fallback_when_inapplicable: bool,
) -> Vec<CodeUnit> {
    visible_extension_method_candidates_inner(
        csharp,
        analyzer,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        fallback_when_inapplicable,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn visible_extension_method_candidates_inner(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    fallback_when_inapplicable: bool,
    usage: bool,
) -> Vec<CodeUnit> {
    let compatible_receiver_types =
        compatible_receiver_type_names(csharp, analyzer, receiver_type_names, usage);
    if !usage && compatible_receiver_types.is_empty() {
        return Vec::new();
    }
    let scopes = extension_visibility_scopes(csharp, source, site, usage);
    let named_candidates = if usage {
        csharp
            .usage_declaration_candidates_by_identifier(member)
            .to_vec()
    } else {
        csharp
            .declaration_candidates_by_identifier(member)
            .into_iter()
            .collect()
    };
    let named_candidates = named_candidates
        .into_iter()
        .filter(|unit| unit.is_function() && unit.identifier() == member)
        .collect::<Vec<_>>();
    for scope in scopes {
        let mut candidates = named_candidates
            .iter()
            .filter(|unit| scope.namespaces.contains(unit.package_name()))
            .cloned()
            .collect::<Vec<_>>();
        for owner_fqn in &scope.static_owner_fqns {
            let static_candidates: Vec<_> = if usage {
                csharp.usage_member_candidates_for_owner(owner_fqn, member)
            } else {
                csharp
                    .member_candidates_for_owner(owner_fqn, member)
                    .into_iter()
                    .collect()
            };
            candidates.extend(
                static_candidates
                    .into_iter()
                    .filter(|unit| unit.is_function() && unit.identifier() == member),
            );
        }
        candidates.sort();
        candidates.dedup();
        let candidates = candidates
            .into_iter()
            .filter(|unit| {
                explicit_generic_arity
                    .is_none_or(|arity| csharp_method_generic_arity(unit.signature()) == arity)
            })
            .filter(|unit| is_extension_method(analyzer, unit))
            .filter(|unit| {
                let receiver = if usage {
                    usage_extension_method_receiver_type(analyzer, unit)
                } else {
                    extension_method_receiver_type(analyzer, unit)
                };
                let matches_receiver = |receiver: String| {
                    let receiver = csharp_normalize_full_name(&receiver);
                    compatible_receiver_types
                        .iter()
                        .any(|candidate| type_identity_matches(candidate, &receiver))
                };
                if usage {
                    compatible_receiver_types.is_empty() || receiver.is_none_or(matches_receiver)
                } else {
                    receiver.is_some_and(matches_receiver)
                }
            })
            .collect::<Vec<_>>();
        let Some(call_arity) = call_arity else {
            if !candidates.is_empty() {
                return candidates;
            }
            continue;
        };
        let Some(declared_arity) = call_arity.checked_add(1) else {
            return Vec::new();
        };
        let applicable = candidates
            .iter()
            .filter(|candidate| csharp_callable_arity(analyzer, candidate).accepts(declared_arity))
            .cloned()
            .collect::<Vec<_>>();
        if !applicable.is_empty() {
            return applicable;
        }
        if fallback_when_inapplicable && !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

fn extension_visibility_scopes(
    csharp: &CSharpAnalyzer,
    source: &str,
    site: Node<'_>,
    usage: bool,
) -> Vec<CSharpExtensionScope> {
    let mut root = site;
    let mut namespace_nodes = Vec::new();
    while let Some(parent) = root.parent() {
        if parent.kind() == "namespace_declaration" {
            namespace_nodes.push(parent);
        }
        root = parent;
    }

    let mut namespace_declarations = Vec::with_capacity(namespace_nodes.len());
    let mut namespace = String::new();
    for declaration in namespace_nodes.iter().rev() {
        let Some(name) = declaration.child_by_field_name("name") else {
            continue;
        };
        let segment = csharp_type_node_identity(name, source);
        if segment.is_empty() {
            continue;
        }
        let parent_namespace = namespace.clone();
        namespace = if parent_namespace.is_empty() {
            segment
        } else {
            format!("{parent_namespace}.{segment}")
        };
        namespace_declarations.push((*declaration, parent_namespace, namespace.clone()));
    }

    let mut scopes = Vec::new();
    for (declaration, parent_namespace, namespace) in namespace_declarations.iter().rev() {
        push_namespace_scopes(
            csharp,
            source,
            &mut scopes,
            namespace,
            parent_namespace,
            declaration.child_by_field_name("body"),
            0,
            usize::MAX,
            usage,
        );
    }

    let file_scoped_declaration = if namespace_nodes.is_empty() {
        let mut cursor = root.walk();
        root.named_children(&mut cursor)
            .find(|child| child.kind() == "file_scoped_namespace_declaration")
    } else {
        None
    };
    if let Some(declaration) = file_scoped_declaration
        && let Some(namespace) = declaration
            .child_by_field_name("name")
            .map(|name| csharp_type_node_identity(name, source))
            .filter(|namespace| !namespace.is_empty())
    {
        push_namespace_scopes(
            csharp,
            source,
            &mut scopes,
            &namespace,
            "",
            Some(root),
            declaration.end_byte(),
            usize::MAX,
            usage,
        );
    }

    let mut compilation_scope = CSharpExtensionScope::default();
    compilation_scope.namespaces.insert(String::new());
    collect_scope_using_directives(
        csharp,
        source,
        root,
        "",
        0,
        file_scoped_declaration.map_or(usize::MAX, |declaration| declaration.start_byte()),
        &mut compilation_scope,
        usage,
    );
    compilation_scope
        .namespaces
        .extend(csharp.global_using_namespaces().iter().cloned());
    let global_static_types: &[CodeUnit] = if usage {
        csharp.usage_global_static_using_types()
    } else {
        csharp.global_static_using_types()
    };
    compilation_scope
        .static_owner_fqns
        .extend(global_static_types.iter().map(CodeUnit::fq_name));
    scopes.push(compilation_scope);
    scopes
}

#[allow(clippy::too_many_arguments)]
fn push_namespace_scopes(
    csharp: &CSharpAnalyzer,
    source: &str,
    scopes: &mut Vec<CSharpExtensionScope>,
    namespace: &str,
    parent_namespace: &str,
    using_scope_node: Option<Node<'_>>,
    using_start: usize,
    using_end: usize,
    usage: bool,
) {
    let mut current = namespace.to_string();
    let mut include_usings = true;
    while !current.is_empty() && current != parent_namespace {
        let mut scope = CSharpExtensionScope::default();
        scope.namespaces.insert(current.clone());
        if include_usings && let Some(scope_node) = using_scope_node {
            collect_scope_using_directives(
                csharp,
                source,
                scope_node,
                &current,
                using_start,
                using_end,
                &mut scope,
                usage,
            );
        }
        scopes.push(scope);
        include_usings = false;
        let Some((parent, _)) = current.rsplit_once('.') else {
            break;
        };
        current.truncate(parent.len());
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_scope_using_directives(
    csharp: &CSharpAnalyzer,
    source: &str,
    scope_node: Node<'_>,
    resolution_namespace: &str,
    using_start: usize,
    using_end: usize,
    scope: &mut CSharpExtensionScope,
    usage: bool,
) {
    let mut cursor = scope_node.walk();
    for directive in scope_node.named_children(&mut cursor).filter(|child| {
        child.kind() == "using_directive"
            && !csharp_using_directive_is_global(*child)
            && using_start <= child.start_byte()
            && child.end_byte() <= using_end
    }) {
        if csharp_using_directive_is_static(directive) {
            if let Some(target) = csharp_using_directive_target(directive, source)
                && let Some(owner) = namespace_relative_names(resolution_namespace, &target)
                    .into_iter()
                    .find_map(|candidate| {
                        if usage {
                            class_unit_for_fq_name(csharp, &candidate)
                        } else {
                            forward_class_unit_for_fq_name(csharp, &candidate)
                        }
                    })
            {
                scope.static_owner_fqns.insert(owner.fq_name());
            }
        } else if let Some(target) = csharp_using_directive_namespace(directive, source) {
            let namespace = namespace_relative_names(resolution_namespace, &target)
                .into_iter()
                .find(|candidate| {
                    if usage {
                        csharp.usage_workspace_namespace_exists(candidate)
                    } else {
                        csharp.workspace_namespace_exists(candidate)
                    }
                })
                .unwrap_or_else(|| normalize_type_text(&target));
            if !namespace.is_empty() {
                scope.namespaces.insert(namespace);
            }
        }
    }
}

fn namespace_relative_names(namespace: &str, target: &str) -> Vec<String> {
    let target = normalize_type_text(target);
    if target.is_empty() {
        return Vec::new();
    }
    if target.starts_with("global::") {
        return vec![target.trim_start_matches("global::").to_string()];
    }
    let mut names = Vec::new();
    let mut prefix = namespace;
    while !prefix.is_empty() {
        names.push(format!("{prefix}.{target}"));
        prefix = prefix.rsplit_once('.').map_or("", |(parent, _)| parent);
    }
    names.push(target);
    names
}

fn compatible_receiver_type_names(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    receiver_type_names: &[String],
    usage: bool,
) -> HashSet<String> {
    let mut compatible = HashSet::default();
    for receiver_type in receiver_type_names {
        compatible.insert(csharp_normalize_full_name(receiver_type));
        let owners = if usage {
            csharp.usage_type_candidates_by_fqn(receiver_type)
        } else {
            forward_type_declarations_for_fq_name(csharp, receiver_type)
        };
        for owner in owners {
            if usage {
                let mut stack = csharp.usage_direct_ancestors(&owner);
                let mut seen = HashSet::default();
                while let Some(ancestor) = stack.pop() {
                    if !seen.insert(ancestor.clone()) {
                        continue;
                    }
                    compatible.insert(csharp_normalize_full_name(&ancestor.fq_name()));
                    stack.extend(csharp.usage_direct_ancestors(&ancestor));
                }
            } else if let Some(provider) = analyzer.type_hierarchy_provider() {
                compatible.extend(
                    provider
                        .get_ancestors(&owner)
                        .into_iter()
                        .map(|ancestor| csharp_normalize_full_name(&ancestor.fq_name())),
                );
            }
        }
    }
    compatible
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
    csharp_type_node_identity(reference_type_node(node), source)
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
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> SymbolResolution<String> {
    receiver_type_fq_names(receiver_node, analyzer, csharp, file, source, bindings)
}

fn receiver_type_fq_names(
    receiver_node: Node<'_>,
    analyzer: &dyn IAnalyzer,
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
                    usage_class_field_receiver_type(
                        receiver_node,
                        receiver,
                        analyzer,
                        csharp,
                        file,
                        source,
                    )
                }
                resolution => resolution,
            }
        }
        "member_access_expression" | "conditional_access_expression" => {
            expression_type_fq_name(receiver_node, csharp, file, source, bindings)
                .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
                .unwrap_or(SymbolResolution::Unknown)
        }
        "invocation_expression" => {
            expression_type_fq_name(receiver_node, csharp, file, source, bindings)
                .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
                .unwrap_or(SymbolResolution::Unknown)
        }
        "object_creation_expression" => object_created_type(receiver_node)
            .and_then(|type_node| {
                resolve_usage_type_fq_name(csharp, file, &reference_type_text(type_node, source))
            })
            .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        "parenthesized_expression" | "checked_expression" => receiver_node
            .named_child(0)
            .map(|inner| receiver_type_fq_names(inner, analyzer, csharp, file, source, bindings))
            .unwrap_or(SymbolResolution::Unknown),
        "cast_expression" | "as_expression" => receiver_node
            .child_by_field_name(if receiver_node.kind() == "cast_expression" {
                "type"
            } else {
                "right"
            })
            .and_then(|type_node| {
                resolve_usage_type_fq_name(csharp, file, &reference_type_text(type_node, source))
            })
            .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        "this" => enclosing_declared_type(receiver_node, csharp, file, source)
            .map(|owner| SymbolResolution::Precise(std::iter::once(owner.fq_name()).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        "base" => enclosing_declared_type(receiver_node, csharp, file, source)
            .and_then(|owner| usage_direct_base(analyzer, csharp, &owner))
            .map(|owner| SymbolResolution::Precise(std::iter::once(owner.fq_name()).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        _ => SymbolResolution::Unknown,
    }
}

pub(super) fn usage_class_field_receiver_type(
    receiver_node: Node<'_>,
    receiver: &str,
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SymbolResolution<String> {
    let Some(enclosing) = enclosing_declared_type(receiver_node, csharp, file, source) else {
        return SymbolResolution::Unknown;
    };
    let candidates =
        nearest_member_candidates_for_owner(analyzer, csharp, &enclosing, receiver, None)
            .into_iter()
            .filter(|candidate| {
                !(candidate.is_function()
                    && analyzer.parent_of(candidate).is_some_and(|owner| {
                        candidate.identifier() == csharp_source_identifier(&owner)
                    }))
            })
            .collect::<Vec<_>>();
    if candidates.is_empty() {
        return SymbolResolution::Unknown;
    }
    let mut resolved_types = candidates
        .iter()
        .filter(|candidate| candidate.is_field())
        .filter_map(|candidate| analyzer.parent_of(candidate))
        .filter_map(|owner| usage_member_declared_type_fq_name(csharp, &owner, receiver))
        .collect::<Vec<_>>();
    resolved_types.sort();
    resolved_types.dedup();
    if resolved_types.len() == 1 {
        SymbolResolution::Precise(resolved_types.into_iter().collect())
    } else {
        SymbolResolution::Ambiguous
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

#[derive(Clone)]
pub(super) enum UnqualifiedMethodGroupResolution {
    Unique(CodeUnit),
    Ambiguous(Vec<CodeUnit>),
    NoMember,
}

pub(super) fn nearest_member_candidates_for_owner(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
) -> Vec<CodeUnit> {
    nearest_member_candidates_for_owner_inner(
        analyzer,
        csharp,
        owner,
        name,
        explicit_generic_arity,
        None,
        true,
    )
}

pub(super) fn applicable_member_candidates_for_owner(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
    call_arity: usize,
) -> Vec<CodeUnit> {
    nearest_member_candidates_for_owner_inner(
        analyzer,
        csharp,
        owner,
        name,
        explicit_generic_arity,
        Some(call_arity),
        true,
    )
}

/// Resolve the callable selected by invocation syntax. The invocation may call
/// either a method or the delegate value read from a field/property, so only
/// method candidates are constrained by the outer argument list.
pub(super) fn invocation_member_candidates_for_owner(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
    call_arity: usize,
) -> Vec<CodeUnit> {
    let mut candidates = applicable_member_candidates_for_owner(
        analyzer,
        csharp,
        owner,
        name,
        explicit_generic_arity,
        call_arity,
    );
    if explicit_generic_arity.is_none() {
        candidates.extend(
            nearest_member_candidates_for_owner(analyzer, csharp, owner, name, None)
                .into_iter()
                .filter(|candidate| !candidate.is_function()),
        );
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn nearest_member_candidates_for_owner_inner(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
    call_arity: Option<usize>,
    usage: bool,
) -> Vec<CodeUnit> {
    let mut hierarchy = None;
    let mut seen = HashSet::default();
    let mut level = if usage {
        csharp.usage_partial_type_parts(owner)
    } else {
        csharp.partial_type_parts(owner)
    };
    if level.is_empty() {
        level.push(owner.clone());
    }
    while !level.is_empty() {
        let mut members = Vec::new();
        let mut current_level = Vec::new();
        for current in level {
            if !seen.insert(current.clone()) {
                continue;
            }
            let candidates: Vec<_> = if usage {
                csharp.usage_member_candidates_for_owner(&current.fq_name(), name)
            } else {
                csharp
                    .member_candidates_for_owner(&current.fq_name(), name)
                    .into_iter()
                    .collect()
            };
            members.extend(
                candidates
                    .into_iter()
                    .filter(|candidate: &CodeUnit| candidate.identifier() == name)
                    .filter(|candidate| {
                        analyzer
                            .parent_of(candidate)
                            .is_some_and(|parent| parent.fq_name() == current.fq_name())
                    })
                    .filter(|candidate| {
                        explicit_generic_arity.is_none_or(|arity| {
                            candidate.is_function()
                                && csharp_method_generic_arity(candidate.signature()) == arity
                        })
                    })
                    .filter(|candidate| {
                        call_arity.is_none_or(|arity| {
                            candidate.is_function()
                                && csharp_callable_arity(analyzer, candidate).accepts(arity)
                        })
                    }),
            );
            current_level.push(current);
        }
        members.sort();
        members.dedup();
        if !members.is_empty() {
            return members;
        }
        if !usage && hierarchy.is_none() {
            hierarchy = analyzer.type_hierarchy_provider();
        }
        let mut next_level = Vec::new();
        if usage {
            for current in current_level {
                for ancestor in csharp.usage_direct_ancestors(&current) {
                    let mut parts = csharp.usage_partial_type_parts(&ancestor);
                    if parts.is_empty() {
                        parts.push(ancestor);
                    }
                    next_level.extend(parts);
                }
            }
        } else if let Some(hierarchy) = hierarchy {
            for current in current_level {
                for ancestor in hierarchy.get_direct_ancestors(&current) {
                    let mut parts = csharp.partial_type_parts(&ancestor);
                    if parts.is_empty() {
                        parts.push(ancestor);
                    }
                    next_level.extend(parts);
                }
            }
        }
        level = next_level;
    }
    Vec::new()
}

pub(super) fn unqualified_member_has_local_binding(
    node: Node<'_>,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    member_name_is_locally_bound(node_text(node, source), bindings)
}

pub(super) fn unqualified_member_has_structured_shadow(node: Node<'_>, source: &str) -> bool {
    let name = node_text(node, source);
    local_function_name_is_in_scope(node, source, name)
        || structured_local_name_is_in_scope(node, source, name)
}

pub(super) fn resolve_unqualified_method_group_for_owner(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    owner: &CodeUnit,
    name: &str,
) -> UnqualifiedMethodGroupResolution {
    let members = nearest_member_candidates_for_owner(analyzer, csharp, owner, name, None);
    if members.is_empty() {
        return UnqualifiedMethodGroupResolution::NoMember;
    }
    let mut candidates = members
        .iter()
        .filter(|candidate| {
            candidate.is_function()
                && analyzer
                    .parent_of(candidate)
                    .is_some_and(|declaring_owner| {
                        candidate.identifier() != csharp_source_identifier(&declaring_owner)
                    })
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    if candidates.len() != members.len() {
        return UnqualifiedMethodGroupResolution::NoMember;
    }
    if candidates.len() == 1 {
        return UnqualifiedMethodGroupResolution::Unique(candidates.remove(0));
    }
    UnqualifiedMethodGroupResolution::Ambiguous(candidates)
}

fn local_function_name_is_in_scope(node: Node<'_>, source: &str, name: &str) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "block" | "switch_section") {
            let mut cursor = parent.walk();
            if parent.named_children(&mut cursor).any(|child| {
                child.kind() == "local_function_statement"
                    && child
                        .child_by_field_name("name")
                        .is_some_and(|candidate| node_text(candidate, source) == name)
            }) {
                return true;
            }
        }
        current = parent;
    }
    false
}

fn structured_local_name_is_in_scope(node: Node<'_>, source: &str, name: &str) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "foreach_statement"
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| node_covers(body, node))
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| binding_container_has_name(left, source, name))
        {
            return true;
        }

        let mut cursor = parent.walk();
        for sibling in parent.named_children(&mut cursor) {
            if same_node(sibling, current) || sibling.start_byte() >= current.start_byte() {
                break;
            }
            if prior_node_declares_local_name(sibling, source, name) {
                return true;
            }
        }
        current = parent;
    }
    false
}

fn prior_node_declares_local_name(root: Node<'_>, source: &str, name: &str) -> bool {
    if LOCAL_BINDING_SCOPE_BARRIERS.contains(&root.kind()) {
        return false;
    }
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if !same_node(current, root) && LOCAL_BINDING_SCOPE_BARRIERS.contains(&current.kind()) {
            continue;
        }
        if matches!(
            current.kind(),
            "variable_declarator"
                | "declaration_expression"
                | "declaration_pattern"
                | "catch_declaration"
                | "tuple_pattern"
                | "parenthesized_variable_designation"
        ) && binding_container_has_name(current, source, name)
        {
            return true;
        }
        let mut cursor = current.walk();
        let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    false
}

const LOCAL_BINDING_SCOPE_BARRIERS: &[&str] = &[
    "block",
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "property_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "anonymous_method_expression",
    "field_declaration",
    "event_field_declaration",
    "class_declaration",
    "interface_declaration",
    "struct_declaration",
    "record_declaration",
    "record_struct_declaration",
    "for_statement",
    "foreach_statement",
    "using_statement",
    "catch_clause",
];

fn binding_container_has_name(node: Node<'_>, source: &str, name: &str) -> bool {
    if node.kind() == "identifier" {
        return node_text(node, source) == name;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        for index in 0..current.child_count() {
            let Some(child) = current.child(index) else {
                continue;
            };
            if !child.is_named() {
                continue;
            }
            if current.field_name_for_child(index as u32) == Some("name")
                && child.kind() == "identifier"
                && node_text(child, source) == name
            {
                return true;
            }
            if matches!(
                child.kind(),
                "tuple_pattern" | "parenthesized_variable_designation"
            ) {
                stack.push(child);
            }
        }
    }
    false
}

/// An unqualified identifier (no receiver) that matches a field/property name resolves to
/// that field only when it appears inside the owning type and is not shadowed by a local
/// binding (parameter or local variable) of the same name. This proves self-references such
/// as `Last = value` inside a method of the field's own class.
#[allow(clippy::too_many_arguments)]
pub(super) fn unqualified_member_resolves_to_owner(
    node: Node<'_>,
    member_name: &str,
    owner: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    if member_name_is_locally_bound(member_name, bindings) {
        return false;
    }
    enclosing_declared_type(node, csharp, file, source).is_some_and(|enclosing| {
        let candidates =
            nearest_member_candidates_for_owner(analyzer, csharp, &enclosing, member_name, None);
        candidates.iter().any(|candidate| {
            analyzer
                .parent_of(candidate)
                .is_some_and(|declaring_owner| declaring_owner.fq_name() == owner.fq_name())
        })
    })
}

pub(in crate::analyzer::usages) fn is_type_reference_node(node: Node<'_>) -> bool {
    csharp_type_reference_root(node).is_some()
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

pub(in crate::analyzer::usages) fn object_initializer_owner_type_node(
    initializer: Node<'_>,
) -> Option<Node<'_>> {
    let object_creation = initializer.parent()?;
    match object_creation.kind() {
        "object_creation_expression" => object_creation
            .child_by_field_name("type")
            .or_else(|| first_type_child(object_creation))
            .or_else(|| implicit_object_creation_declarator_type(object_creation)),
        "implicit_object_creation_expression" => {
            implicit_object_creation_declarator_type(object_creation)
        }
        _ => None,
    }
}

fn implicit_object_creation_declarator_type(object_creation: Node<'_>) -> Option<Node<'_>> {
    let mut current = object_creation;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "equals_value_clause" | "parenthesized_expression" | "checked_expression" => {
                current = parent;
            }
            "ERROR" => {
                if let Some(type_node) = error_recovered_implicit_declarator_type(parent, current) {
                    return Some(type_node);
                }
                current = parent;
            }
            "variable_declarator" => {
                let initializer = variable_declarator_initializer(parent)?;
                if initializer.start_byte() > object_creation.start_byte()
                    || object_creation.end_byte() > initializer.end_byte()
                {
                    return None;
                }
                let declaration = parent.parent()?;
                return declaration
                    .child_by_field_name("type")
                    .or_else(|| first_type_child(declaration));
            }
            _ => return None,
        }
    }
    None
}

fn error_recovered_implicit_declarator_type<'tree>(
    error: Node<'tree>,
    value: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut cursor = error.walk();
    let children = error.named_children(&mut cursor).collect::<Vec<_>>();
    let value_index = children.iter().position(|child| same_node(*child, value))?;
    let name = value_index
        .checked_sub(1)
        .and_then(|index| children.get(index))?;
    if !matches!(name.kind(), "identifier" | "implicit_parameter") {
        return None;
    }
    let type_node = value_index
        .checked_sub(2)
        .and_then(|index| children.get(index))?;
    is_type_syntax_kind(type_node.kind()).then_some(*type_node)
}

fn count_named_children_of_kind(node: Node<'_>, kind: &str) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == kind)
        .count()
}

pub(in crate::analyzer::usages) fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| is_type_syntax_kind(child.kind()))
}

fn is_type_syntax_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "qualified_name" | "generic_name" | "nullable_type" | "array_type" | "type"
    )
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}
