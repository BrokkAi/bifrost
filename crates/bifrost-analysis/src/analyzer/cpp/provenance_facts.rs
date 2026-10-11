//! Direct, procedure-local C/C++ provenance facts.
//!
//! This adapter deliberately joins syntax to the semantic procedure that
//! owns it.  It does not recover facts by scanning source text, and it does
//! not retain a translation-unit-sized index.  Every result is a bounded
//! query product for one source anchor.

use crate::CancellationToken;
use crate::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use crate::analyzer::semantic::{
    CallableTarget, CallableTargetResolution, ProcedureHandle, SemanticCapability, SemanticEffect,
    SourceMappingKind,
};
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::usages::effects::ModeledProcedureKey;
use crate::analyzer::{Language, LanguageDialect, ProjectFile, Range, WorkspaceAnalyzer};
use brokk_bifrost_core::analyzer::cpp_facts::{
    CppProvenanceFact, CppProvenanceRule, CppProvenanceStorage,
};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use brokk_bifrost_cpp::graph::resolver::cast_expression_type_node;
use brokk_bifrost_cpp::structural::declarator_name_node;
use std::collections::HashSet;
use tree_sitter::Node;

use super::semantic::{
    cpp_declarator_contains_kind, cpp_declarator_initializer, cpp_local_declarators,
};

const MAX_SOURCE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone)]
pub struct CppProvenanceOutcome {
    pub fact: Option<CppProvenanceFact>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseType {
    Char,
    Void,
    Known(u64),
    Unknown,
}

impl BaseType {
    const fn width(self) -> Option<u64> {
        match self {
            Self::Char => Some(1),
            Self::Known(width) => Some(width),
            Self::Void | Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TypeInfo {
    base: BaseType,
    pointer: bool,
    array: bool,
}

#[derive(Debug, Clone)]
struct Binding<'tree> {
    name: Box<str>,
    scope: (usize, usize),
    ty: TypeInfo,
    storage: CppProvenanceStorage,
    initializer: Option<Node<'tree>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PointerInfo {
    current: BaseType,
    origin: BaseType,
    storage: CppProvenanceStorage,
}

#[derive(Debug, Clone, Copy)]
enum PointerLayer {
    Cast(BaseType),
    Binding {
        current: BaseType,
        storage: CppProvenanceStorage,
    },
}

pub fn cpp_provenance_for_anchor(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    anchor: Range,
    rule: CppProvenanceRule,
    cancellation: Option<&CancellationToken>,
) -> CppProvenanceOutcome {
    cpp_provenance_for_anchor_with_model_key(workspace, procedure, anchor, rule, None, cancellation)
}

/// Derive a C/C++ provenance fact with an exact resolver-owned model key when
/// the query already selected one through `call_bindings`. The semantic IR
/// retains the source call shape but does not rewrite its declared target with
/// a later semantic-model dispatch answer, so an external C call needs this
/// exact key to carry its header identity into the provenance producer.
pub fn cpp_provenance_for_anchor_with_model_key(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    anchor: Range,
    rule: CppProvenanceRule,
    modeled_key: Option<&ModeledProcedureKey>,
    cancellation: Option<&CancellationToken>,
) -> CppProvenanceOutcome {
    if !matches!(
        procedure.artifact().key().language(),
        LanguageDialect::CppC | LanguageDialect::Standard(Language::Cpp)
    ) {
        return unavailable("not_cpp");
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable("cancelled");
    }

    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        procedure.artifact().key().path().as_path(),
    );
    let Some(syntax) = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Cpp)
        .map(|provider| provider.structural_syntax_limited(&file, MAX_SOURCE_BYTES, cancellation))
    else {
        return unavailable("prepared_syntax_unavailable");
    };
    let syntax = match syntax {
        StructuralSyntaxLimitedOutcome::Available(syntax) => syntax,
        StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
            return unavailable("source_budget_exhausted");
        }
        StructuralSyntaxLimitedOutcome::Cancelled => return unavailable("cancelled"),
        StructuralSyntaxLimitedOutcome::Unavailable => {
            return unavailable("prepared_syntax_unavailable");
        }
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return unavailable("source_identity_mismatch");
    };

    let semantics = procedure.semantics();
    let Some(procedure_mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    if procedure_mapping.kind != SourceMappingKind::Exact {
        return unavailable("procedure_mapping_inexact");
    }
    let procedure_span = procedure_mapping.locator.anchor().span();
    let Some(procedure_node) = syntax.tree().root_node().named_descendant_for_byte_range(
        procedure_span.start_byte() as usize,
        procedure_span.end_byte() as usize,
    ) else {
        return unavailable("procedure_syntax_missing");
    };
    if procedure_node.start_byte() != procedure_span.start_byte() as usize
        || procedure_node.end_byte() != procedure_span.end_byte() as usize
        || procedure_node.has_error()
    {
        return unavailable("procedure_syntax_inexact");
    }
    let Some(anchor_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(anchor.start_byte, anchor.end_byte)
        .filter(|node| {
            node.start_byte() == anchor.start_byte
                && node.end_byte() == anchor.end_byte
                && procedure_node.start_byte() <= node.start_byte()
                && node.end_byte() <= procedure_node.end_byte()
        })
    else {
        return unavailable("anchor_syntax_missing");
    };

    let source = syntax.source();
    let bindings = collect_bindings(source, procedure_node);
    let globals = collect_global_names(source, syntax.tree().root_node(), procedure_node);
    let result = match rule {
        CppProvenanceRule::IncorrectPointerScalingChar
        | CppProvenanceRule::SuspiciousPointerScaling
        | CppProvenanceRule::SuspiciousPointerScalingVoid => {
            pointer_scaling_fact(source, anchor_node, &bindings, rule, cancellation)
        }
        CppProvenanceRule::ReturnStackAllocatedMemory => {
            return_stack_fact(source, anchor_node, procedure, &bindings, cancellation)
        }
        CppProvenanceRule::StackAddressEscape => stack_escape_fact(
            source,
            anchor_node,
            procedure,
            &bindings,
            &globals,
            cancellation,
        ),
        CppProvenanceRule::ImproperNullTermination => null_termination_fact(
            source,
            anchor_node,
            procedure,
            procedure_node,
            &bindings,
            modeled_key,
            cancellation,
        ),
    };
    match result {
        Ok(fact) => CppProvenanceOutcome {
            fact,
            complete: true,
            reason: None,
        },
        Err(reason) => unavailable(reason),
    }
}

fn unavailable(reason: &'static str) -> CppProvenanceOutcome {
    CppProvenanceOutcome {
        fact: None,
        complete: false,
        reason: Some(reason),
    }
}

fn collect_bindings<'tree>(source: &'tree str, procedure: Node<'tree>) -> Vec<Binding<'tree>> {
    let mut bindings = Vec::new();
    let mut stack = vec![procedure];
    while let Some(node) = stack.pop() {
        if node.id() != procedure.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        if node.kind() == "declaration" {
            let Some(type_node) = node.child_by_field_name("type") else {
                stack.extend(named_children(node));
                continue;
            };
            for declarator in cpp_local_declarators(node) {
                let Some(name_node) = declarator_name_node(declarator) else {
                    continue;
                };
                let Some(name) = source.get(name_node.byte_range()) else {
                    continue;
                };
                let ty = type_info(source, type_node, declarator);
                let scope = lexical_scope(declarator, procedure);
                bindings.push(Binding {
                    name: name.into(),
                    scope,
                    ty,
                    storage: declaration_storage(node),
                    initializer: cpp_declarator_initializer(node, declarator),
                });
            }
        } else if node.kind() == "parameter_declaration"
            && let Some(declarator) = node.child_by_field_name("declarator")
            && let Some(name_node) = declarator_name_node(declarator)
            && let Some(name) = source.get(name_node.byte_range())
        {
            let ty = node
                .child_by_field_name("type")
                .map(|type_node| type_info(source, type_node, declarator))
                .unwrap_or(TypeInfo {
                    base: BaseType::Unknown,
                    pointer: false,
                    array: false,
                });
            bindings.push(Binding {
                name: name.into(),
                scope: (procedure.start_byte(), procedure.end_byte()),
                ty,
                storage: CppProvenanceStorage::Parameter,
                initializer: None,
            });
        }
        stack.extend(named_children(node));
    }
    bindings
}

fn collect_global_names(source: &str, root: Node<'_>, procedure: Node<'_>) -> HashSet<Box<str>> {
    let mut names = HashSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.id() == procedure.id() {
            continue;
        }
        if node.kind() == "declaration"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "translation_unit")
        {
            for declarator in cpp_local_declarators(node) {
                if let Some(name_node) = declarator_name_node(declarator)
                    && let Some(name) = source.get(name_node.byte_range())
                {
                    names.insert(name.into());
                }
            }
        }
        stack.extend(named_children(node));
    }
    names
}

fn named_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn lexical_scope(node: Node<'_>, procedure: Node<'_>) -> (usize, usize) {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "compound_statement"
                | "for_statement"
                | "for_range_loop"
                | "if_statement"
                | "switch_statement"
                | "while_statement"
                | "do_statement"
                | "catch_clause"
        ) {
            return (parent.start_byte(), parent.end_byte());
        }
        if parent.id() == procedure.id() {
            return (procedure.start_byte(), procedure.end_byte());
        }
        current = parent.parent();
    }
    (procedure.start_byte(), procedure.end_byte())
}

fn type_info(source: &str, type_node: Node<'_>, declarator: Node<'_>) -> TypeInfo {
    let text = source.get(type_node.byte_range()).unwrap_or_default();
    TypeInfo {
        base: base_type(text),
        pointer: cpp_declarator_contains_kind(declarator, "pointer_declarator"),
        array: cpp_declarator_contains_kind(declarator, "array_declarator"),
    }
}

fn declaration_storage(declaration: Node<'_>) -> CppProvenanceStorage {
    let mut cursor = declaration.walk();
    if declaration
        .named_children(&mut cursor)
        .any(|child| child.kind() == "storage_class_specifier")
    {
        CppProvenanceStorage::Unknown
    } else {
        CppProvenanceStorage::Stack
    }
}

fn base_type(text: &str) -> BaseType {
    let text = text
        .split_whitespace()
        .filter(|part| !matches!(*part, "const" | "volatile" | "signed" | "unsigned"))
        .collect::<Vec<_>>();
    match text.as_slice() {
        ["char"] | ["signed", "char"] | ["unsigned", "char"] => BaseType::Char,
        ["void"] => BaseType::Void,
        ["bool"] => BaseType::Known(1),
        ["short"] | ["short", "int"] => BaseType::Known(2),
        ["int"] | ["unsigned"] | ["unsigned", "int"] => BaseType::Known(4),
        ["long"] | ["long", "int"] | ["long", "long"] | ["long", "long", "int"] => {
            BaseType::Known(8)
        }
        ["float"] => BaseType::Known(4),
        ["double"] => BaseType::Known(8),
        ["long", "double"] => BaseType::Known(16),
        _ if text.iter().any(|part| part.ends_with("int8")) => BaseType::Known(1),
        _ if text.iter().any(|part| part.ends_with("int16")) => BaseType::Known(2),
        _ if text.iter().any(|part| part.ends_with("int32")) => BaseType::Known(4),
        _ if text.iter().any(|part| part.ends_with("int64")) => BaseType::Known(8),
        _ => BaseType::Unknown,
    }
}

fn pointer_scaling_fact(
    source: &str,
    anchor: Node<'_>,
    bindings: &[Binding<'_>],
    rule: CppProvenanceRule,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<CppProvenanceFact>, &'static str> {
    let mut stack = vec![anchor];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err("cancelled");
        }
        if node.kind() == "binary_expression"
            && binary_operator(node).is_some_and(|operator| matches!(operator, "+" | "-"))
        {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let candidate = [left, right].into_iter().flatten().find_map(|operand| {
                pointer_info(source, operand, bindings).map(|pointer| (operand, pointer))
            });
            if let Some((operand, pointer)) = candidate {
                let integer = if left.is_some_and(|left| left.id() == operand.id()) {
                    right
                } else {
                    left
                };
                if integer.is_some_and(|node| is_sizeof_expression(node)) {
                    stack.extend(named_children(node));
                    continue;
                }
                if !integer.is_some_and(is_integer_expression) {
                    stack.extend(named_children(node));
                    continue;
                }
                let qualifies = match rule {
                    CppProvenanceRule::IncorrectPointerScalingChar => {
                        pointer.current == BaseType::Char
                            && pointer.origin.width().is_some_and(|width| width > 1)
                    }
                    CppProvenanceRule::SuspiciousPointerScaling => {
                        pointer.current != BaseType::Char
                            && pointer.current != BaseType::Void
                            && pointer.origin != BaseType::Char
                            && pointer.origin != BaseType::Void
                            && pointer.current.width().is_some()
                            && pointer.origin.width().is_some()
                            && pointer.current.width() != pointer.origin.width()
                    }
                    CppProvenanceRule::SuspiciousPointerScalingVoid => {
                        pointer.current == BaseType::Void
                            && pointer.origin != BaseType::Void
                            && pointer.origin.width().is_some()
                    }
                    _ => false,
                };
                if qualifies {
                    return Ok(Some(CppProvenanceFact {
                        rule,
                        range: node_range(anchor),
                        source_width: pointer.origin.width(),
                        destination_width: pointer.current.width(),
                        offset: integer.and_then(|node| integer_value(source, node)),
                        source_storage: pointer.storage,
                        destination_storage: pointer.storage,
                    }));
                }
            }
        }
        stack.extend(named_children(node));
    }
    Ok(None)
}

fn binary_operator(node: Node<'_>) -> Option<&'static str> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| match child.kind() {
            "+" => Some("+"),
            "-" => Some("-"),
            _ => None,
        })
}

fn pointer_info(source: &str, node: Node<'_>, bindings: &[Binding<'_>]) -> Option<PointerInfo> {
    let mut node = strip_parentheses(node);
    let mut layers = Vec::new();
    let pointer = loop {
        match node.kind() {
            "identifier" | "field_identifier" => {
                let name = source.get(node.byte_range())?;
                let binding = resolve_binding(bindings, name, node.start_byte())?;
                if !binding.ty.pointer {
                    return None;
                }
                if let Some(initializer) = binding.initializer {
                    layers.push(PointerLayer::Binding {
                        current: binding.ty.base,
                        storage: binding.storage,
                    });
                    node = strip_parentheses(initializer);
                    continue;
                }
                break PointerInfo {
                    current: binding.ty.base,
                    origin: binding.ty.base,
                    storage: binding.storage,
                };
            }
            "cast_expression" => {
                let value = node.child_by_field_name("value")?;
                let descriptor = cast_expression_type_node(node)?;
                layers.push(PointerLayer::Cast(base_type(
                    source.get(descriptor.byte_range())?,
                )));
                node = strip_parentheses(value);
                continue;
            }
            "new_expression" => {
                break PointerInfo {
                    current: BaseType::Unknown,
                    origin: BaseType::Unknown,
                    storage: CppProvenanceStorage::Heap,
                };
            }
            "binary_expression"
                if binary_operator(node).is_some_and(|operator| matches!(operator, "+" | "-")) =>
            {
                node = node
                    .child_by_field_name("left")
                    .filter(|left| !is_integer_expression(*left))
                    .or_else(|| node.child_by_field_name("right"))
                    .map(strip_parentheses)?;
                continue;
            }
            _ => return None,
        }
    };
    let mut pointer = pointer;
    for layer in layers.into_iter().rev() {
        match layer {
            PointerLayer::Cast(current) => pointer.current = current,
            PointerLayer::Binding { current, storage } => {
                pointer.current = current;
                pointer.storage = storage;
            }
        }
    }
    Some(pointer)
}

fn resolve_binding<'tree>(
    bindings: &'tree [Binding<'tree>],
    name: &str,
    byte: usize,
) -> Option<&'tree Binding<'tree>> {
    bindings.iter().rev().find(|binding| {
        binding.name.as_ref() == name && binding.scope.0 <= byte && byte <= binding.scope.1
    })
}

fn strip_parentheses(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" || node.kind() == "argument_list" {
        let Some(child) = node.named_child(0) else {
            break;
        };
        node = child;
    }
    node
}

fn is_sizeof_expression(node: Node<'_>) -> bool {
    node.kind() == "sizeof_expression" || node.kind() == "sizeof_type_expression"
}

fn is_integer_expression(node: Node<'_>) -> bool {
    matches!(
        strip_parentheses(node).kind(),
        "number_literal" | "integer_literal" | "unary_expression"
    )
}

fn integer_value(source: &str, node: Node<'_>) -> Option<i128> {
    let node = strip_parentheses(node);
    if node.kind() == "unary_expression" {
        let argument = node.child_by_field_name("argument")?;
        let value = integer_value(source, argument)?;
        let text = source.get(node.byte_range())?;
        return text.starts_with('-').then_some(-value).or(Some(value));
    }
    source.get(node.byte_range())?.trim().parse::<i128>().ok()
}

fn return_stack_fact(
    source: &str,
    anchor: Node<'_>,
    procedure: &ProcedureHandle,
    bindings: &[Binding<'_>],
    cancellation: Option<&CancellationToken>,
) -> Result<Option<CppProvenanceFact>, &'static str> {
    if anchor.kind() != "return_statement" {
        return Ok(None);
    }
    if !has_semantic_return(procedure, anchor) {
        return Err("return_semantics_missing");
    }
    let Some(value) = anchor.named_child(0) else {
        return Ok(None);
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err("cancelled");
    }
    let (binding, is_address) = address_or_binding(source, value, bindings);
    let Some(binding) = binding else {
        return Ok(None);
    };
    if binding.storage != CppProvenanceStorage::Stack {
        return Ok(None);
    }
    if !is_address && !binding.ty.array {
        return Ok(None);
    }
    Ok(Some(CppProvenanceFact {
        rule: CppProvenanceRule::ReturnStackAllocatedMemory,
        range: node_range(anchor),
        source_width: binding.ty.base.width(),
        destination_width: None,
        offset: None,
        source_storage: CppProvenanceStorage::Stack,
        destination_storage: CppProvenanceStorage::Unknown,
    }))
}

fn address_or_binding<'tree>(
    source: &str,
    node: Node<'tree>,
    bindings: &'tree [Binding<'tree>],
) -> (Option<&'tree Binding<'tree>>, bool) {
    let node = strip_parentheses(node);
    if node.kind() == "pointer_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| operator.kind() == "&")
    {
        let argument = node.child_by_field_name("argument");
        let binding = argument.and_then(|argument| {
            let argument = strip_parentheses(argument);
            let name = source.get(argument.byte_range())?;
            resolve_binding(bindings, name, argument.start_byte())
        });
        return (binding, true);
    }
    let name = source.get(node.byte_range());
    (
        name.and_then(|name| resolve_binding(bindings, name, node.start_byte())),
        false,
    )
}

fn stack_escape_fact(
    source: &str,
    anchor: Node<'_>,
    procedure: &ProcedureHandle,
    bindings: &[Binding<'_>],
    globals: &HashSet<Box<str>>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<CppProvenanceFact>, &'static str> {
    if anchor.kind() != "assignment_expression" {
        return Ok(None);
    }
    if !has_semantic_assignment(procedure, anchor) {
        return Err("assignment_semantics_missing");
    }
    let Some(left) = anchor.child_by_field_name("left") else {
        return Ok(None);
    };
    let Some(right) = anchor.child_by_field_name("right") else {
        return Ok(None);
    };
    let Some(local) = address_or_binding(source, right, bindings).0 else {
        return Ok(None);
    };
    if local.storage != CppProvenanceStorage::Stack {
        return Ok(None);
    }
    let left = strip_parentheses(left);
    let Some(left_name) = source.get(left.byte_range()) else {
        return Ok(None);
    };
    if !globals.contains(left_name)
        || resolve_binding(bindings, left_name, left.start_byte()).is_some()
    {
        return Ok(None);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err("cancelled");
    }
    Ok(Some(CppProvenanceFact {
        rule: CppProvenanceRule::StackAddressEscape,
        range: node_range(anchor),
        source_width: local.ty.base.width(),
        destination_width: None,
        offset: None,
        source_storage: CppProvenanceStorage::Stack,
        destination_storage: CppProvenanceStorage::Global,
    }))
}

fn null_termination_fact(
    source: &str,
    anchor: Node<'_>,
    procedure: &ProcedureHandle,
    procedure_node: Node<'_>,
    bindings: &[Binding<'_>],
    modeled_key: Option<&ModeledProcedureKey>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<CppProvenanceFact>, &'static str> {
    if anchor.kind() != "call_expression" {
        return Ok(None);
    }
    let name = if let Some(key) = modeled_key {
        if key.language != "cpp"
            || key.has_receiver
            || key.parameter_count != 1
            || key.owner.is_empty()
        {
            return Err("resolved_call_identity_unavailable");
        }
        let Some(function) = anchor.child_by_field_name("function") else {
            return Err("call_function_missing");
        };
        let Some(spelled_name) = super::range_facts::terminal_name(function, source) else {
            return Err("resolved_call_name_missing");
        };
        if spelled_name != key.member {
            return Err("resolved_call_identity_mismatch");
        }
        key.member.as_str()
    } else {
        let Some(call) = call_site_for_node(procedure, anchor) else {
            return Err("call_semantics_missing");
        };
        let CallableTargetResolution::Proven(CallableTarget::External(locator)) =
            &call.declared_targets
        else {
            return Err("resolved_call_identity_unavailable");
        };
        if locator
            .path()
            .as_path()
            .extension()
            .is_none_or(|extension| !matches!(extension.to_str(), Some("h" | "hh" | "hpp" | "hxx")))
        {
            return Err("resolved_call_header_owner_missing");
        }
        locator
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            .ok_or("resolved_call_name_missing")?
    };
    if !matches!(name, "strdup" | "strcpy" | "strcat") {
        return Ok(None);
    }
    let Some(arguments) = anchor.child_by_field_name("arguments") else {
        return Err("call_arguments_missing");
    };
    let Some(argument) = arguments.named_child(0) else {
        return Err("call_argument_missing");
    };
    let argument = strip_parentheses(argument);
    let Some(argument_name) = source.get(argument.byte_range()) else {
        return Err("call_argument_unreadable");
    };
    let Some(binding) = resolve_binding(bindings, argument_name, argument.start_byte()) else {
        return Err("call_argument_alias_unknown");
    };
    if binding.storage != CppProvenanceStorage::Stack || !binding.ty.array {
        return Ok(None);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err("cancelled");
    }
    if buffer_is_terminated(source, procedure_node, binding, anchor) {
        return Ok(None);
    }
    Ok(Some(CppProvenanceFact {
        rule: CppProvenanceRule::ImproperNullTermination,
        range: node_range(anchor),
        source_width: binding.ty.base.width(),
        destination_width: None,
        offset: None,
        source_storage: CppProvenanceStorage::Stack,
        destination_storage: CppProvenanceStorage::Unknown,
    }))
}

fn buffer_is_terminated(
    source: &str,
    procedure: Node<'_>,
    binding: &Binding<'_>,
    call: Node<'_>,
) -> bool {
    if binding
        .initializer
        .is_some_and(|initializer| initializer_has_zero(source, initializer))
    {
        return true;
    }
    let mut stack = vec![procedure];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= call.start_byte() {
            continue;
        }
        if node.kind() == "assignment_expression"
            && assignment_zeros_first_element(source, node, binding)
        {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

fn initializer_has_zero(source: &str, initializer: Node<'_>) -> bool {
    let initializer = strip_parentheses(initializer);
    if matches!(initializer.kind(), "string_literal" | "raw_string_literal") {
        return true;
    }
    if initializer.kind() != "initializer_list" {
        return false;
    }
    initializer
        .named_child(0)
        .is_some_and(|child| integer_value(source, child) == Some(0))
}

fn assignment_zeros_first_element(
    source: &str,
    assignment: Node<'_>,
    binding: &Binding<'_>,
) -> bool {
    let Some(left) = assignment.child_by_field_name("left") else {
        return false;
    };
    if left.kind() != "subscript_expression" {
        return false;
    }
    let Some(base) = left
        .child_by_field_name("argument")
        .or_else(|| left.named_child(0))
    else {
        return false;
    };
    let Some(index) = left
        .child_by_field_name("index")
        .or_else(|| left.named_child(1))
    else {
        return false;
    };
    let Some(right) = assignment.child_by_field_name("right") else {
        return false;
    };
    source
        .get(strip_parentheses(base).byte_range())
        .is_some_and(|name| name == binding.name.as_ref())
        && integer_value(source, index) == Some(0)
        && integer_value(source, right) == Some(0)
}

fn call_site_for_node<'a>(
    procedure: &'a ProcedureHandle,
    node: Node<'_>,
) -> Option<&'a crate::analyzer::semantic::SemanticCallSite> {
    let semantics = procedure.semantics();
    semantics.call_sites().iter().find(|call| {
        semantics
            .source_mapping(call.source)
            .is_some_and(|mapping| mapping_matches_node(mapping, node))
    })
}

fn has_semantic_return(procedure: &ProcedureHandle, node: Node<'_>) -> bool {
    let semantics = procedure.semantics();
    semantics.points().iter().any(|point| {
        point.events.iter().any(|event| {
            matches!(event.effect, SemanticEffect::ProcedureReturn { .. })
                && semantics
                    .source_mapping(event.source)
                    .is_some_and(|mapping| mapping_matches_node(mapping, node))
        })
    })
}

fn has_semantic_assignment(procedure: &ProcedureHandle, node: Node<'_>) -> bool {
    let semantics = procedure.semantics();
    semantics.points().iter().any(|point| {
        point.events.iter().any(|event| {
            let source_matches = semantics
                .source_mapping(event.source)
                .is_some_and(|mapping| mapping_matches_node(mapping, node));
            if !source_matches {
                return false;
            }
            match event.effect {
                SemanticEffect::Assignment { .. } => true,
                // A file-scope target has no procedure-local ValueId. The
                // C++ lowerer records that structured write as an explicit
                // assignment-capability gap at the exact assignment node;
                // the caller still proves the global destination and stack
                // source from the prepared tree below.
                SemanticEffect::Gap { gap } => semantics
                    .gap(gap)
                    .is_some_and(|gap| gap.capability == SemanticCapability::Assignments),
                _ => false,
            }
        })
    })
}

fn mapping_matches_node(
    mapping: &crate::analyzer::semantic::SourceMapping,
    node: Node<'_>,
) -> bool {
    let span = mapping.locator.anchor().span();
    span.start_byte() as usize == node.start_byte() && span.end_byte() as usize == node.end_byte()
}
