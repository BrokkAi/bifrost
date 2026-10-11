//! Python class-set adapter: the per-language seeds and member lookup the
//! type-flow engine cannot derive from the language-neutral semantic IR.
//!
//! Every answer comes from structured sources: the semantic IR's exact source
//! mappings, the analyzer's prepared tree-sitter syntax, bounded direct-site type lookup
//! for callee and annotation resolution, the declaration index for class
//! members, and the active semantic-model overlay for external classes. No
//! source text is parsed or scanned here; reading a node's text at an
//! AST-provided span is structured access.

use std::sync::{Arc, Mutex};

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_python::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution, python_comprehension_binds_name_at,
    python_direct_scope_bindings_bounded, python_module_or_class_scope_binds_name_bounded,
    python_type_parameter_binds_name_at, python_unambiguous_module_binding_bounded,
    python_unambiguous_module_class_binding_bounded,
};
use brokk_bifrost_python::declarations::{
    python_base_origin_node, python_first_parameter_name, python_function_has_property_decorator,
};
use brokk_bifrost_python::diagnostics::is_python_builtin_or_constant;
use brokk_bifrost_python::syntax::{
    python_deferred_annotation_tree, python_plain_string_literal, python_static_attribute_path,
};
use tree_sitter::Node;

use super::PythonAnalyzer;
use super::lexical_scope::python_lexical_scope_inventory_bounded;
use crate::analyzer::lexical_definitions::{
    FormalVariadicKind, PythonMethodBinding, formal_parameter_slots_for_owner,
};
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, GenKillFacts, reaching_definitions,
};
use crate::analyzer::semantic::type_flow::{
    CallGuardOutcome, ClassBodyMemberBinding, ClassHierarchy, ClassIdentity, ClassSeed,
    DynamicFieldNameSet, DynamicFieldWrite, ExternalClassCache, ExternalMemberDeclaration,
    MemberAccessKind, MemberAccessQuery, MemberDeclaration, MemberLookup, MemberLookupHit,
    MemberReceiverQuery, NarrowingVerdict, NormalReturnTypeConstraint, SourceSite, TypeFlowAdapter,
    UnknownReason, analyzer_range_for_span, class_seed_from_lookup_types, external_class_identity,
    external_member_lookup, file_for_locator, source_span_for_node,
};
use crate::analyzer::semantic::{
    AdapterSemanticsVersion, AllocationSite, BindingOriginIndex, CancellationToken,
    CandidateCoverage, ConstructorResultEvidence, ConstructorResultOrigin, GuardFact,
    GuardPredicate, IndexedLocationIdentity, MemoryLocation, MemoryLocationKind, ProcedureHandle,
    ProcedureKind, ProgramPointId, SemanticCallSite, SemanticEffect, SemanticValue,
    SemanticValueKind, SourceMappingKind, SourceSiteKind, SourceSpan, ValueFlowKind, ValueId,
};
use crate::analyzer::semantic_model::{
    ProcedureSummaryMemberKey, SemanticModelCompleteness, SemanticModelMatchDisposition,
    SemanticModelOverlay, SemanticModelOverlayDisposition, SemanticModelSurfaceGap,
    SemanticModelSymbol, SemanticModelSymbolKind, TypeRef,
};
use crate::analyzer::usages::ImportKind;
use crate::analyzer::usages::get_definition::{
    PythonAttributeCalleeKind, PythonDefinitionProvider, ResolutionSession,
    python_attribute_callee_kind_bounded,
    python_attribute_callee_names_enclosing_nested_class_bounded,
    python_attribute_callee_reads_a_field_bounded,
    python_attribute_callee_uses_self_or_cls_bounded, python_class_candidate_for_name,
    python_external_imported_symbol_bounded, python_namespace_imported_class_name_bounded,
    python_type_checking_imported_class_candidate,
};
use crate::analyzer::usages::get_type::{
    TypeLookupStatus, resolve_type_at_reference_site_with_budget,
};
use crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, IAnalyzer, Language, ProjectFile, QueryScope,
    TypeHierarchyProvider, WorkspaceAnalyzer, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;

/// The Python [`TypeFlowAdapter`]. Zero-sized: every method receives the
/// workspace it consults.
pub struct PythonTypeFlowAdapter;

/// One name-resolution cache, local to a single adapter call.
pub(super) fn python_analyzer(workspace: &WorkspaceAnalyzer) -> &PythonAnalyzer {
    resolve_analyzer::<PythonAnalyzer>(workspace.analyzer())
        .expect("PythonTypeFlowAdapter serves only workspaces that analyze Python")
}

pub(super) fn prepared_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let python = python_analyzer(workspace);
    let scope = AnalyzerQueryScope::new(python);
    let prepared = python.inner.prepared_syntax(scope.token(), file);
    crate::analyzer::semantic::type_flow::prepared_syntax_for_procedure(
        workspace, procedure, file, prepared,
    )
}

pub(super) fn current_indexed_prepared(
    python: &PythonAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    let scope = AnalyzerQueryScope::new(python);
    crate::analyzer::semantic::type_flow::current_indexed_prepared(
        python.inner.prepared_syntax(scope.token(), file),
        |prepared| python.indexed_source_matches(file, prepared.source()),
    )
}

pub(super) use crate::analyzer::semantic::type_flow::node_at_span;

fn node_text_at(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Box<str>> {
    let node = node_at_span(prepared, span)?;
    node.utf8_text(prepared.source().as_bytes())
        .ok()
        .map(Box::from)
}

fn span_for_node(node: Node<'_>) -> SourceSpan {
    source_span_for_node(node)
}

fn enclosing_workspace_class(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
) -> Option<CodeUnit> {
    let locator = procedure.semantics().locator();
    let file = file_for_locator(workspace, locator)?;
    crate::analyzer::semantic::type_flow::enclosing_workspace_class_unit(
        workspace.analyzer(),
        &file,
        locator.anchor().span(),
        |_| true,
    )
}

fn class_node_for_unit<'tree>(
    python: &PythonAnalyzer,
    prepared: &'tree PreparedSyntaxTree,
    unit: &CodeUnit,
) -> Option<Node<'tree>> {
    python.ranges(unit).into_iter().find_map(|range| {
        let node = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        match node.kind() {
            "class_definition" => Some(node),
            "decorated_definition" => class_definition_node(node),
            _ => node
                .parent()
                .filter(|parent| parent.kind() == "class_definition"),
        }
    })
}

fn definition_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    let definition = if node.kind() == "decorated_definition" {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "function_definition")?
    } else {
        node
    };
    definition
        .child_by_field_name("name")?
        .utf8_text(source.as_bytes())
        .ok()
}

fn assignment_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    let node = if node.kind() == "expression_statement" {
        node.named_child(0)?
    } else {
        node
    };
    if !matches!(node.kind(), "assignment" | "augmented_assignment") {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    (left.kind() == "identifier")
        .then(|| left.utf8_text(source.as_bytes()).ok())
        .flatten()
}

/// Whether a class installs members on its own instances at run time.
///
/// `setattr(self, name, value)` with a name the syntax does not spell, and
/// `self.__dict__[name] = value`, both add members no declaration shows.
/// mutagen's `StrictFileObject.__init__` installs `tell`, `seek` and five more
/// this way, so its declared surface bounds nothing.
fn class_installs_dynamic_members(python: &PythonAnalyzer, unit: &CodeUnit) -> bool {
    let Some(prepared) = current_indexed_prepared(python, unit.source()) else {
        return true;
    };
    let Some(class) = class_node_for_unit(python, &prepared, unit) else {
        return true;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let source = prepared.source();
    let mut cursor = body.walk();
    for member in body.named_children(&mut cursor) {
        let function = match member.kind() {
            "function_definition" => member,
            "decorated_definition" => {
                let mut inner = member.walk();
                match member
                    .named_children(&mut inner)
                    .find(|child| child.kind() == "function_definition")
                {
                    Some(function) => function,
                    None => continue,
                }
            }
            _ => continue,
        };
        let Some(receiver) = python_first_parameter_name(function, source) else {
            continue;
        };
        if method_installs_dynamic_members(function, source, &receiver) {
            return true;
        }
    }
    false
}

/// Whether one method body installs a member on `receiver` under a name the
/// syntax does not spell.
fn method_installs_dynamic_members(function: Node<'_>, source: &str, receiver: &str) -> bool {
    let root_id = function.id();
    let mut stack = vec![function];
    while let Some(node) = stack.pop() {
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        let installs = match node.kind() {
            "call" => {
                (setattr_write(node, source)
                    .is_some_and(|name| matches!(name, DynamicMemberName::Any))
                    && call_receiver_argument_is(node, source, receiver))
                    || instance_dict_mutation(node, source, receiver)
            }
            "assignment" | "augmented_assignment" => {
                dictionary_write(node, source).is_some()
                    && dictionary_write_receiver_is(node, source, receiver)
            }
            _ => false,
        };
        if installs {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

/// Whether a call mutates `receiver.__dict__`, which installs members under
/// names the syntax does not spell.
///
/// celery's `Context.update` is `self.__dict__.update(*args, **kwargs)`, so
/// every attribute a caller supplies becomes a member of that instance.
fn instance_dict_mutation(call: Node<'_>, source: &str, receiver: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "attribute" {
        return false;
    }
    let mutates = function
        .child_by_field_name("attribute")
        .and_then(|member| member.utf8_text(source.as_bytes()).ok())
        .is_some_and(|member| matches!(member, "update" | "setdefault"));
    if !mutates {
        return false;
    }
    let Some(object) = function.child_by_field_name("object") else {
        return false;
    };
    object.kind() == "attribute"
        && object
            .child_by_field_name("attribute")
            .and_then(|member| member.utf8_text(source.as_bytes()).ok())
            == Some("__dict__")
        && object.child_by_field_name("object").is_some_and(|base| {
            base.kind() == "identifier" && base.utf8_text(source.as_bytes()) == Ok(receiver)
        })
}

/// Whether a call's first positional argument names `receiver`.
fn call_receiver_argument_is(call: Node<'_>, source: &str, receiver: &str) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .next()
        .is_some_and(|first| {
            first.kind() == "identifier" && first.utf8_text(source.as_bytes()) == Ok(receiver)
        })
}

/// Whether a `receiver.__dict__[...] = ...` assignment targets `receiver`.
fn dictionary_write_receiver_is(node: Node<'_>, source: &str, receiver: &str) -> bool {
    node.child_by_field_name("left")
        .and_then(|left| left.child_by_field_name("value"))
        .and_then(|value| value.child_by_field_name("object"))
        .is_some_and(|object| {
            object.kind() == "identifier" && object.utf8_text(source.as_bytes()) == Ok(receiver)
        })
}

#[derive(Clone)]
enum DynamicMemberName {
    Member(Box<str>),
    Exact(Vec<Box<str>>),
    Prefix(Box<str>),
    Any,
    None,
}

fn dynamic_member_name_affects(name: &DynamicMemberName, member: &str) -> bool {
    match name {
        DynamicMemberName::Member(name) => name.as_ref() == member,
        DynamicMemberName::Exact(names) => names.iter().any(|name| name.as_ref() == member),
        DynamicMemberName::Prefix(prefix) => member.starts_with(prefix.as_ref()),
        DynamicMemberName::Any => true,
        DynamicMemberName::None => false,
    }
}

fn setattr_write(node: Node<'_>, source: &str) -> Option<DynamicMemberName> {
    let function = node.child_by_field_name("function")?;
    if function.kind() != "identifier" || function.utf8_text(source.as_bytes()).ok()? != "setattr" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let actuals = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    let Some(name) = actuals.get(1) else {
        return Some(DynamicMemberName::Any);
    };
    Some(
        python_plain_string_literal(*name, source)
            .map(|name| DynamicMemberName::Member(name.into()))
            .unwrap_or(DynamicMemberName::Any),
    )
}

fn dictionary_write(node: Node<'_>, source: &str) -> Option<DynamicMemberName> {
    let left = node.child_by_field_name("left")?;
    if left.kind() != "subscript" {
        return None;
    }
    let value = left.child_by_field_name("value")?;
    if value.kind() != "attribute" {
        return None;
    }
    let attribute = value.child_by_field_name("attribute")?;
    if attribute.utf8_text(source.as_bytes()).ok()? != "__dict__" {
        return None;
    }
    let subscript = left.child_by_field_name("subscript")?;
    Some(
        python_plain_string_literal(subscript, source)
            .map(|name| DynamicMemberName::Member(name.into()))
            .unwrap_or(DynamicMemberName::Any),
    )
}

fn dynamic_field_name_set(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    expression: Node<'_>,
    prepared: &PreparedSyntaxTree,
) -> DynamicFieldNameSet {
    dynamic_field_name_set_at(workspace, file, expression, prepared, 0)
}

fn dynamic_field_name_set_at(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    expression: Node<'_>,
    prepared: &PreparedSyntaxTree,
    depth: u8,
) -> DynamicFieldNameSet {
    if depth == 32 {
        return DynamicFieldNameSet::Any;
    }
    let expression = unwrap_parenthesized(expression);
    let source = prepared.source();
    if let Some(name) = python_plain_string_literal(expression, source) {
        return DynamicFieldNameSet::Exact(vec![name.into()]);
    }
    if let Some(names) = literal_string_sequence(expression, source) {
        return DynamicFieldNameSet::Exact(names);
    }
    match expression.kind() {
        "binary_operator" => {
            let Some(operator) = expression.child_by_field_name("operator") else {
                return DynamicFieldNameSet::Any;
            };
            if operator.utf8_text(source.as_bytes()).ok() != Some("+") {
                return DynamicFieldNameSet::Any;
            }
            let (Some(left), Some(right)) = (
                expression.child_by_field_name("left"),
                expression.child_by_field_name("right"),
            ) else {
                return DynamicFieldNameSet::Any;
            };
            let left_names = dynamic_field_name_set_at(workspace, file, left, prepared, depth + 1);
            let right_names =
                dynamic_field_name_set_at(workspace, file, right, prepared, depth + 1);
            match (left_names, right_names) {
                (DynamicFieldNameSet::Prefix(prefix), _) => DynamicFieldNameSet::Prefix(prefix),
                (DynamicFieldNameSet::Exact(mut left), DynamicFieldNameSet::Exact(right))
                    if left.len() == 1 && right.len() == 1 =>
                {
                    let left = left.pop().expect("one exact left string");
                    let right = &right[0];
                    DynamicFieldNameSet::Exact(vec![format!("{left}{right}").into()])
                }
                (DynamicFieldNameSet::Exact(mut left), _) if left.len() == 1 => {
                    let prefix = left.pop().expect("one exact left string");
                    if prefix.is_empty() {
                        DynamicFieldNameSet::Any
                    } else {
                        DynamicFieldNameSet::Prefix(prefix)
                    }
                }
                _ => DynamicFieldNameSet::Any,
            }
        }
        "string" | "concatenated_string" => string_expression_name_set(expression, source),
        "identifier" => {
            if let Some(loop_statement) = matching_for_loop(expression, source) {
                let Some(iterable) = loop_statement.child_by_field_name("right") else {
                    return DynamicFieldNameSet::Any;
                };
                if let Some(names) = literal_string_sequence(iterable, source) {
                    return DynamicFieldNameSet::Exact(names);
                }
                if let Some(value) = local_assignment_value(iterable, source) {
                    return dynamic_field_name_set_at(workspace, file, value, prepared, depth + 1);
                }
                return enum_member_names(workspace, file, iterable, prepared)
                    .map(DynamicFieldNameSet::Exact)
                    .unwrap_or(DynamicFieldNameSet::Any);
            }
            local_assignment_value(expression, source)
                .map(|value| dynamic_field_name_set_at(workspace, file, value, prepared, depth + 1))
                .unwrap_or(DynamicFieldNameSet::Any)
        }
        "attribute" => {
            let attribute = expression
                .child_by_field_name("attribute")
                .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok());
            let Some(object) = expression.child_by_field_name("object") else {
                return DynamicFieldNameSet::Any;
            };
            if attribute != Some("name") {
                return class_attribute_assignment_value(workspace, file, expression, prepared)
                    .map(|value| {
                        dynamic_field_name_set_at(workspace, file, value, prepared, depth + 1)
                    })
                    .unwrap_or(DynamicFieldNameSet::Any);
            }
            if object.kind() == "identifier" {
                let Some(loop_statement) = matching_for_loop(object, source) else {
                    return DynamicFieldNameSet::Any;
                };
                let Some(iterable) = loop_statement.child_by_field_name("right") else {
                    return DynamicFieldNameSet::Any;
                };
                return enum_member_names(workspace, file, iterable, prepared)
                    .map(DynamicFieldNameSet::Exact)
                    .unwrap_or(DynamicFieldNameSet::Any);
            }
            let Some(path) = python_static_attribute_path(object) else {
                return DynamicFieldNameSet::Any;
            };
            let Some(member) = path
                .last()
                .and_then(|node| node.utf8_text(source.as_bytes()).ok())
            else {
                return DynamicFieldNameSet::Any;
            };
            if path.len() < 2 {
                return DynamicFieldNameSet::Any;
            }
            let Some(class_reference) = object.child_by_field_name("object") else {
                return DynamicFieldNameSet::Any;
            };
            enum_member_names(workspace, file, class_reference, prepared)
                .filter(|members| members.iter().any(|name| name.as_ref() == member))
                .map(|_| DynamicFieldNameSet::Exact(vec![member.into()]))
                .unwrap_or(DynamicFieldNameSet::Any)
        }
        _ => DynamicFieldNameSet::Any,
    }
}

fn local_assignment_value<'tree>(reference: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let name = reference.utf8_text(source.as_bytes()).ok()?;
    let mut scopes = Vec::new();
    let mut current = reference;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference.start_byte()
                    && reference.end_byte() <= body.end_byte()
            })
        {
            scopes.push(parent);
        }
        if matches!(parent.kind(), "class_definition" | "module") {
            break;
        }
        current = parent;
    }
    for scope in scopes {
        let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
        let inventory =
            python_lexical_scope_inventory_bounded(scope, source, || session.scope_step())?;
        match inventory.name_resolution_at(name, reference) {
            PythonLexicalNameResolution::Unbound | PythonLexicalNameResolution::Nonlocal => {
                continue;
            }
            PythonLexicalNameResolution::Global => return None,
            PythonLexicalNameResolution::Local => {
                let (_, declaration) = inventory
                    .local_bindings()
                    .find(|(bound, _)| *bound == name)?;
                let assignment = declaration.parent()?;
                if assignment.kind() != "assignment"
                    || assignment
                        .child_by_field_name("left")
                        .is_none_or(|left| left.id() != declaration.id())
                {
                    return None;
                }
                return unique_local_assignment_value(scope, name, source);
            }
        }
    }
    None
}

fn unique_local_assignment_value<'tree>(
    scope: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let body = scope.child_by_field_name("body")?;
    let mut value = None;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        let target = match node.kind() {
            "assignment" | "augmented_assignment" | "for_statement" | "delete_statement" => {
                node.child_by_field_name("left").or_else(|| {
                    node.named_child(0)
                        .filter(|_| node.kind() == "delete_statement")
                })
            }
            "named_expression" => node.child_by_field_name("name"),
            _ => None,
        };
        if target.is_some_and(|target| target_mentions_name(target, name, source)) {
            if node.kind() == "assignment"
                && target.is_some_and(|target| {
                    target.kind() == "identifier"
                        && target.utf8_text(source.as_bytes()).ok() == Some(name)
                })
                && value.is_none()
            {
                value = node.child_by_field_name("right");
                value?;
            } else {
                return None;
            }
        }
        if matches!(node.kind(), "import_statement" | "import_from_statement") {
            return None;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    value
}

fn class_attribute_assignment_value<'tree>(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    expression: Node<'tree>,
    prepared: &PreparedSyntaxTree,
) -> Option<Node<'tree>> {
    let source = prepared.source();
    let path = python_static_attribute_path(expression)?;
    if path.len() < 2 {
        return None;
    }
    let member = path.last()?.utf8_text(source.as_bytes()).ok()?;
    let receiver = expression.child_by_field_name("object")?;
    if receiver.kind() != "identifier" {
        return None;
    }
    let receiver_name = receiver.utf8_text(source.as_bytes()).ok()?;
    let mut current = expression;
    let class = loop {
        let parent = current.parent()?;
        if parent.kind() == "class_definition" {
            break parent;
        }
        if parent.kind() == "module" {
            return None;
        }
        current = parent;
    };
    let body = class.child_by_field_name("body")?;
    let mut value = None;
    let mut method_context = false;
    for statement in named_children(body) {
        let function = match statement.kind() {
            "function_definition" => statement,
            "decorated_definition" => {
                let Some(function) = named_children(statement)
                    .into_iter()
                    .find(|child| child.kind() == "function_definition")
                else {
                    continue;
                };
                function
            }
            _ => continue,
        };
        if python_first_parameter_name(function, source).as_deref() != Some(receiver_name) {
            continue;
        }
        let Some(function_body) = function.child_by_field_name("body") else {
            continue;
        };
        method_context |= function_body.start_byte() <= expression.start_byte()
            && expression.end_byte() <= function_body.end_byte();
        let mut stack = vec![function_body];
        while let Some(node) = stack.pop() {
            if node != function_body
                && matches!(
                    node.kind(),
                    "function_definition" | "class_definition" | "lambda"
                )
            {
                continue;
            }
            if matches!(node.kind(), "assignment" | "augmented_assignment")
                && let Some(left) = node.child_by_field_name("left")
                && left.kind() == "attribute"
                && left.child_by_field_name("object").is_some_and(|object| {
                    object.kind() == "identifier"
                        && object.utf8_text(source.as_bytes()).ok() == Some(receiver_name)
                })
                && left
                    .child_by_field_name("attribute")
                    .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                    == Some(member)
            {
                if node.kind() != "assignment" || value.is_some() {
                    return None;
                }
                value = node.child_by_field_name("right");
                value?;
            }
            if node.kind() == "delete_statement"
                && named_children(node).into_iter().any(|target| {
                    target.kind() == "attribute"
                        && target.child_by_field_name("object").is_some_and(|object| {
                            object.kind() == "identifier"
                                && object.utf8_text(source.as_bytes()).ok() == Some(receiver_name)
                        })
                        && target
                            .child_by_field_name("attribute")
                            .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                            == Some(member)
                })
            {
                return None;
            }
            if node.kind() == "call"
                && dynamic_mutation_targets_receiver(node, source, receiver_name, member)
            {
                return None;
            }
            if matches!(node.kind(), "assignment" | "augmented_assignment")
                && dictionary_write(node, source).is_some_and(|name| {
                    dynamic_member_name_affects(&name, member)
                        && dictionary_write_receiver_is(node, source, receiver_name)
                })
            {
                return None;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    let value = value.filter(|_| method_context)?;
    let class_name = class.child_by_field_name("name")?;
    let ClassSeed::Class(ClassIdentity::Workspace(unit)) =
        resolve_class_at_span(workspace, file.clone(), span_for_node(class_name), prepared)
    else {
        return None;
    };
    let hierarchy =
        PythonTypeFlowAdapter.class_hierarchy(workspace, &ClassIdentity::Workspace(unit));
    (hierarchy.descendants.as_deref() == Some(&[])
        && !hierarchy.unresolved_base
        && !hierarchy.dynamic_attributes)
        .then_some(value)
}

fn dynamic_mutation_targets_receiver(
    call: Node<'_>,
    source: &str,
    receiver: &str,
    member: &str,
) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() == "identifier" {
        let Some(function_name) = function.utf8_text(source.as_bytes()).ok() else {
            return false;
        };
        match function_name {
            "setattr" => {
                return call_receiver_argument_is(call, source, receiver)
                    && setattr_write(call, source)
                        .is_some_and(|name| dynamic_member_name_affects(&name, member));
            }
            "delattr" => return call_receiver_argument_is(call, source, receiver),
            _ => {}
        }
    }
    let Some(object) = function.child_by_field_name("object") else {
        return false;
    };
    if object.kind() == "identifier"
        && object.utf8_text(source.as_bytes()).ok() == Some(receiver)
        && let Some(method) = function
            .child_by_field_name("attribute")
            .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
    {
        if method == "__delattr__" {
            return true;
        }
        if method != "__setattr__" {
            return false;
        }
        return dynamic_call_write(call, source)
            .is_some_and(|name| dynamic_member_name_affects(&name, member));
    }
    (object.kind() == "attribute"
        && object
            .child_by_field_name("attribute")
            .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
            == Some("__dict__")
        && object.child_by_field_name("object").is_some_and(|base| {
            base.kind() == "identifier" && base.utf8_text(source.as_bytes()).ok() == Some(receiver)
        })
        && dynamic_call_write(call, source).is_some())
        || (object.kind() == "call"
            && object
                .child_by_field_name("function")
                .is_some_and(|function| {
                    function.kind() == "identifier"
                        && function.utf8_text(source.as_bytes()).ok() == Some("vars")
                })
            && call_receiver_argument_is(object, source, receiver)
            && function
                .child_by_field_name("attribute")
                .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                .is_some_and(|method| {
                    matches!(
                        method,
                        "update"
                            | "setdefault"
                            | "pop"
                            | "popitem"
                            | "clear"
                            | "__setitem__"
                            | "__delitem__"
                    )
                }))
}

fn unwrap_parenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        node = node
            .named_child(0)
            .expect("one parenthesized expression child");
    }
    node
}

fn string_expression_name_set(node: Node<'_>, source: &str) -> DynamicFieldNameSet {
    let parts = if node.kind() == "concatenated_string" {
        named_children(node)
    } else {
        vec![node]
    };
    let mut prefix = String::new();
    for part in parts {
        if let Some(value) = plain_string_segment(part, source) {
            prefix.push_str(value);
            continue;
        }
        let Some((literal, interpolated)) = f_string_literal_prefix(part, source) else {
            return DynamicFieldNameSet::Any;
        };
        prefix.push_str(&literal);
        if interpolated {
            return if prefix.is_empty() {
                DynamicFieldNameSet::Any
            } else {
                DynamicFieldNameSet::Prefix(prefix.into())
            };
        }
    }
    DynamicFieldNameSet::Exact(vec![prefix.into()])
}

fn plain_string_segment<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    if node.kind() != "string" {
        return None;
    }
    let mut content = None;
    for child in named_children(node) {
        match child.kind() {
            "string_start" | "string_end" => {
                let delimiter = child.utf8_text(source.as_bytes()).ok()?;
                if delimiter
                    .chars()
                    .any(|character| character != '\'' && character != '"')
                {
                    return None;
                }
            }
            "string_content" if child.named_child_count() == 0 && content.is_none() => {
                content = Some(child);
            }
            _ => return None,
        }
    }
    Some(content.map_or("", |child| {
        child
            .utf8_text(source.as_bytes())
            .expect("a tree-sitter node range is valid UTF-8 source")
    }))
}

fn f_string_literal_prefix(node: Node<'_>, source: &str) -> Option<(String, bool)> {
    if node.kind() != "string" {
        return None;
    }
    let children = named_children(node);
    let start = children
        .iter()
        .find(|child| child.kind() == "string_start")?;
    let prefix = start.utf8_text(source.as_bytes()).ok()?;
    if !prefix
        .chars()
        .any(|character| matches!(character, 'f' | 'F'))
    {
        return None;
    }
    let mut literal = String::new();
    for child in children {
        match child.kind() {
            "string_start" | "string_end" => {}
            "string_content" => {
                let content = child.utf8_text(source.as_bytes()).ok()?;
                if content
                    .chars()
                    .any(|character| matches!(character, '\\' | '{' | '}'))
                {
                    return None;
                }
                literal.push_str(content);
            }
            "interpolation" => return Some((literal, true)),
            _ => return None,
        }
    }
    Some((literal, false))
}

fn literal_string_sequence(node: Node<'_>, source: &str) -> Option<Vec<Box<str>>> {
    let node = unwrap_parenthesized(node);
    if !matches!(node.kind(), "list" | "tuple") {
        return None;
    }
    let mut values = Vec::new();
    let mut seen = HashSet::default();
    for child in named_children(node)
        .into_iter()
        .filter(|child| !child.is_extra())
    {
        let value = plain_string_segment(child, source)?;
        let value: Box<str> = value.into();
        if seen.insert(value.clone()) {
            values.push(value);
        }
    }
    Some(values)
}

fn matching_for_loop<'tree>(expression: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let name = expression.utf8_text(source.as_bytes()).ok()?;
    let mut current = expression;
    while let Some(parent) = current.parent() {
        if parent.kind() == "for_statement" {
            let left = parent.child_by_field_name("left")?;
            let body = parent.child_by_field_name("body")?;
            if left.kind() == "identifier"
                && left.utf8_text(source.as_bytes()).ok() == Some(name)
                && body.start_byte() <= expression.start_byte()
                && expression.end_byte() <= body.end_byte()
                && !loop_variable_reassigned(body, expression, name, source)
            {
                return Some(parent);
            }
        }
        if matches!(
            parent.kind(),
            "function_definition"
                | "class_definition"
                | "lambda"
                | "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression"
        ) {
            return None;
        }
        current = parent;
    }
    None
}

fn loop_variable_reassigned(
    body: Node<'_>,
    expression: Node<'_>,
    name: &str,
    source: &str,
) -> bool {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= expression.start_byte() {
            continue;
        }
        if node != body
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            continue;
        }
        let target = match node.kind() {
            "assignment" | "augmented_assignment" | "for_statement" => {
                node.child_by_field_name("left")
            }
            "named_expression" => node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("left")),
            "delete_statement" => node.named_child(0),
            _ => None,
        };
        if target.is_some_and(|target| target_mentions_name(target, name, source)) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn target_mentions_name(node: Node<'_>, name: &str, source: &str) -> bool {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).ok() == Some(name),
        "tuple" | "list" | "pattern_list" | "pattern_tuple" => named_children(node)
            .into_iter()
            .any(|child| target_mentions_name(child, name, source)),
        _ => false,
    }
}

fn enum_member_names(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    reference: Node<'_>,
    prepared: &PreparedSyntaxTree,
) -> Option<Vec<Box<str>>> {
    let seed = resolve_class_at_span(workspace, file.clone(), span_for_node(reference), prepared);
    let ClassSeed::Class(ClassIdentity::Workspace(unit)) = seed else {
        return None;
    };
    let python = python_analyzer(workspace);
    let class_file = unit.source();
    let class_prepared = current_indexed_prepared(python, class_file)?;
    let class = class_node_for_unit(python, &class_prepared, &unit)?;
    let bases = class.child_by_field_name("superclasses")?;
    let is_enum = named_children(bases).into_iter().any(|base| {
        import_bound_external_symbol(python, class_file, &class_prepared, base)
            .is_some_and(|(module, member)| module == "enum" && member == "Enum")
    });
    if !is_enum {
        return None;
    }
    enum_class_member_names(class, class_prepared.source())
}

fn enum_class_member_names(class: Node<'_>, source: &str) -> Option<Vec<Box<str>>> {
    let body = class.child_by_field_name("body")?;
    let mut names = Vec::new();
    let mut values = HashSet::default();
    for statement in named_children(body)
        .into_iter()
        .filter(|node| !node.is_extra())
    {
        let assignment = match statement.kind() {
            "assignment" => statement,
            "expression_statement" => {
                let expression = statement.named_child(0)?;
                if expression.kind() == "string" {
                    continue;
                }
                if expression.kind() != "assignment" {
                    return None;
                }
                expression
            }
            "function_definition" | "pass_statement" | "comment" => continue,
            "decorated_definition" => {
                let children = named_children(statement);
                if !children
                    .iter()
                    .any(|child| child.kind() == "function_definition")
                {
                    return None;
                }
                continue;
            }
            _ => return None,
        };
        let name = assignment_name(assignment, source)?;
        if name.starts_with('_') || name.ends_with('_') {
            return None;
        }
        let value = assignment.child_by_field_name("right")?;
        let value = enum_literal_value_identity(value, source)?;
        if values.insert(value) {
            names.push(name.into());
        }
    }
    Some(names)
}

fn enum_literal_value_identity(node: Node<'_>, source: &str) -> Option<Box<str>> {
    let node = unwrap_parenthesized(node);
    if let Some(value) = python_plain_string_literal(node, source) {
        return Some(format!("str:{}:{value}", value.len()).into());
    }
    if node.kind() == "integer" {
        let value = node
            .utf8_text(source.as_bytes())
            .ok()?
            .parse::<i128>()
            .ok()?;
        return Some(format!("int:{value}").into());
    }
    (node.kind() == "none").then(|| "none".into())
}

fn dynamic_call_write_for_field(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    prepared: &PreparedSyntaxTree,
) -> Option<DynamicMemberName> {
    if node.kind() != "call" {
        return None;
    }
    let source = prepared.source();
    let function = node.child_by_field_name("function")?;
    if function.kind() == "identifier" {
        let name = function.utf8_text(source.as_bytes()).ok()?;
        let arguments = node.child_by_field_name("arguments")?;
        let actuals = named_children(arguments);
        if name == "setattr" {
            let Some(attribute) = actuals.get(1).copied() else {
                return Some(DynamicMemberName::Any);
            };
            return Some(dynamic_member_name(workspace, file, attribute, prepared));
        }
        if name == "delattr" {
            return Some(DynamicMemberName::None);
        }
        return None;
    }
    if function.kind() != "attribute" {
        return None;
    }
    let method = function
        .child_by_field_name("attribute")?
        .utf8_text(source.as_bytes())
        .ok()?;
    if matches!(
        method,
        "get"
            | "items"
            | "keys"
            | "values"
            | "copy"
            | "fromkeys"
            | "__contains__"
            | "__getitem__"
            | "__len__"
            | "__iter__"
            | "__reversed__"
            | "__or__"
            | "__ror__"
            | "__eq__"
            | "__ne__"
            | "__lt__"
            | "__le__"
            | "__gt__"
            | "__ge__"
            | "__repr__"
            | "__str__"
    ) {
        return None;
    }
    let object = function.child_by_field_name("object")?;
    if method == "__setattr__" {
        let arguments = node.child_by_field_name("arguments")?;
        return Some(
            named_children(arguments)
                .first()
                .copied()
                .map(|name| dynamic_member_name(workspace, file, name, prepared))
                .unwrap_or(DynamicMemberName::Any),
        );
    }
    let dictionary = object.kind() == "attribute"
        && object
            .child_by_field_name("attribute")
            .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
            == Some("__dict__");
    let vars_call = object.kind() == "call"
        && object
            .child_by_field_name("function")
            .is_some_and(|function| {
                function.kind() == "identifier"
                    && function.utf8_text(source.as_bytes()) == Ok("vars")
                    && indexed_builtin_is_unshadowed(python_analyzer(workspace), function, prepared)
                        == Some(true)
            });
    if !dictionary && !vars_call {
        return None;
    }
    if matches!(method, "pop" | "popitem" | "clear" | "__delitem__") {
        return Some(DynamicMemberName::None);
    }
    let arguments = node.child_by_field_name("arguments")?;
    let actuals = named_children(arguments);
    match method {
        "__setitem__" => Some(
            actuals
                .first()
                .copied()
                .map(|name| dynamic_member_name(workspace, file, name, prepared))
                .unwrap_or(DynamicMemberName::Any),
        ),
        "update" => Some(match mapping_literal_keys(&actuals, source) {
            Some(names) => DynamicMemberName::Exact(names),
            None => DynamicMemberName::Any,
        }),
        "setdefault" => Some(
            actuals
                .first()
                .copied()
                .map(|name| dynamic_member_name(workspace, file, name, prepared))
                .unwrap_or(DynamicMemberName::Any),
        ),
        _ => Some(DynamicMemberName::Any),
    }
}

fn mapping_literal_keys(arguments: &[Node<'_>], source: &str) -> Option<Vec<Box<str>>> {
    let mut names = Vec::new();
    let mut seen = HashSet::default();
    for argument in arguments {
        match argument.kind() {
            "dictionary" => {
                for pair in named_children(*argument) {
                    if pair.kind() != "pair" {
                        return None;
                    }
                    let key = pair.child_by_field_name("key")?;
                    let key = plain_string_segment(key, source)?;
                    let key: Box<str> = key.into();
                    if seen.insert(key.clone()) {
                        names.push(key);
                    }
                }
            }
            "keyword_argument" => {
                let name = argument
                    .child_by_field_name("name")?
                    .utf8_text(source.as_bytes())
                    .ok()?;
                let name: Box<str> = name.into();
                if seen.insert(name.clone()) {
                    names.push(name);
                }
            }
            _ => return None,
        }
    }
    Some(names)
}

fn dynamic_member_name(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    expression: Node<'_>,
    prepared: &PreparedSyntaxTree,
) -> DynamicMemberName {
    if let Some(name) = python_plain_string_literal(expression, prepared.source()) {
        return DynamicMemberName::Member(name.into());
    }
    match dynamic_field_name_set(workspace, file, expression, prepared) {
        DynamicFieldNameSet::Exact(names) => DynamicMemberName::Exact(names),
        DynamicFieldNameSet::Prefix(prefix) => DynamicMemberName::Prefix(prefix),
        DynamicFieldNameSet::Any => DynamicMemberName::Any,
        DynamicFieldNameSet::None => DynamicMemberName::None,
    }
}

fn dictionary_write_for_field(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    prepared: &PreparedSyntaxTree,
) -> Option<DynamicMemberName> {
    let left = node.child_by_field_name("left")?;
    if left.kind() != "subscript" {
        return None;
    }
    let value = left.child_by_field_name("value")?;
    if value.kind() != "attribute"
        || value
            .child_by_field_name("attribute")
            .and_then(|attribute| attribute.utf8_text(prepared.source().as_bytes()).ok())
            != Some("__dict__")
    {
        return None;
    }
    let key = left.child_by_field_name("subscript")?;
    Some(dynamic_member_name(workspace, file, key, prepared))
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect()
}

fn class_definition_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "class_definition" {
        return Some(node);
    }
    (node.kind() == "decorated_definition")
        .then(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "class_definition")
        })
        .flatten()
}

fn writes_member_name(node: Node<'_>, source: &str, member: &str) -> bool {
    if matches!(node.kind(), "assignment" | "augmented_assignment") {
        if assignment_name(node, source) == Some(member) {
            return true;
        }
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "attribute"
                && left
                    .child_by_field_name("attribute")
                    .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                    == Some(member)
            {
                return true;
            }
            if let Some(write) = dictionary_write(node, source) {
                return dynamic_member_name_affects(&write, member);
            }
        }
    }
    dynamic_call_write(node, source)
        .is_some_and(|write| dynamic_member_name_affects(&write, member))
}

/// Shared structured interpretation for member shadowing and the store survey.
fn dynamic_call_write(node: Node<'_>, source: &str) -> Option<DynamicMemberName> {
    if node.kind() != "call" {
        return None;
    }
    if let Some(write) = setattr_write(node, source) {
        return Some(write);
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "attribute" {
        return None;
    }
    let attribute = function
        .child_by_field_name("attribute")?
        .utf8_text(source.as_bytes())
        .ok()?;
    if matches!(
        attribute,
        "get"
            | "items"
            | "keys"
            | "values"
            | "copy"
            | "fromkeys"
            | "__contains__"
            | "__getitem__"
            | "__len__"
            | "__iter__"
            | "__reversed__"
            | "__or__"
            | "__ror__"
            | "__eq__"
            | "__ne__"
            | "__lt__"
            | "__le__"
            | "__gt__"
            | "__ge__"
            | "__repr__"
            | "__str__"
    ) {
        return None;
    }
    if matches!(attribute, "pop" | "popitem" | "clear" | "__delitem__") {
        return Some(DynamicMemberName::None);
    }
    if attribute == "__setattr__" {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return Some(DynamicMemberName::Any);
        };
        let mut cursor = arguments.walk();
        let name = arguments
            .named_children(&mut cursor)
            .next()
            .and_then(|name| python_plain_string_literal(name, source));
        return Some(
            name.map(|name| DynamicMemberName::Member(name.into()))
                .unwrap_or(DynamicMemberName::Any),
        );
    }
    // Calls through an instance dictionary can install unspelled members
    // without a MemoryStore event, for example self.__dict__.update(...).
    (function
        .child_by_field_name("object")
        .and_then(|object| object.child_by_field_name("attribute"))
        .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
        == Some("__dict__"))
    .then_some(DynamicMemberName::Any)
}

/// Keep the same AST interpretation for member shadowing and receiver scoping.
fn scoped_dynamic_write(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    node: Node<'_>,
    name: DynamicMemberName,
    prepared: &PreparedSyntaxTree,
) -> DynamicFieldWrite {
    let source = prepared.source();
    if let DynamicMemberName::Member(member) = name {
        return DynamicFieldWrite::Member(member);
    }
    let names = match name {
        DynamicMemberName::Exact(names) => DynamicFieldNameSet::Exact(names),
        DynamicMemberName::Prefix(prefix) => DynamicFieldNameSet::Prefix(prefix),
        DynamicMemberName::Any => DynamicFieldNameSet::Any,
        DynamicMemberName::None => DynamicFieldNameSet::None,
        DynamicMemberName::Member(_) => unreachable!("member writes returned above"),
    };
    let span = span_for_node(node);
    let semantics = procedure.semantics();
    let dictionary_owner =
        |dictionary: Node<'_>| dynamic_dictionary_receiver(procedure, dictionary, source);
    let receiver = if node.kind() == "call" {
        semantics
            .call_sites()
            .iter()
            .find(|call| {
                semantics
                    .source_mapping(call.source)
                    .is_some_and(|mapping| {
                        mapping.kind == SourceMappingKind::Exact
                            && mapping.locator.anchor().span() == span
                    })
            })
            .and_then(|call| {
                let function = node.child_by_field_name("function")?;
                if function.kind() == "identifier" {
                    call.arguments
                        .first()
                        .filter(|argument| !argument.expansion.is_spread())
                        .map(|argument| argument.value)
                } else {
                    let object = function.child_by_field_name("object")?;
                    if object
                        .child_by_field_name("attribute")
                        .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                        == Some("__dict__")
                    {
                        dictionary_owner(object)
                    } else if object.kind() == "call"
                        && object
                            .child_by_field_name("function")
                            .is_some_and(|function| {
                                function.kind() == "identifier"
                                    && function.utf8_text(source.as_bytes()) == Ok("vars")
                            })
                    {
                        let vars_span = span_for_node(object);
                        semantics
                            .call_sites()
                            .iter()
                            .find(|vars_call| {
                                semantics
                                    .source_mapping(vars_call.source)
                                    .is_some_and(|mapping| {
                                        mapping.kind == SourceMappingKind::Exact
                                            && mapping.locator.anchor().span() == vars_span
                                    })
                            })
                            .and_then(|vars_call| vars_call.arguments.first())
                            .filter(|argument| !argument.expansion.is_spread())
                            .map(|argument| argument.value)
                    } else {
                        match semantics.proven_caller_receiver_binding(call.id) {
                            Some(
                                crate::analyzer::semantic::CallerReceiverBinding::TypeQualified(_),
                            ) => call
                                .arguments
                                .first()
                                .filter(|argument| !argument.expansion.is_spread())
                                .map(|argument| argument.value),
                            _ if matches!(
                                builtin_class_reference(
                                    python_analyzer(workspace),
                                    workspace.analyzer().semantic_model_overlay().as_deref(),
                                    object,
                                    prepared,
                                    &mut ExternalClassCache::default()
                                ),
                                Some(ClassSeed::Class(_))
                            ) =>
                            {
                                call.arguments
                                    .first()
                                    .filter(|argument| !argument.expansion.is_spread())
                                    .map(|argument| argument.value)
                            }
                            _ => call.receiver,
                        }
                    }
                }
            })
    } else {
        node.child_by_field_name("left")
            .and_then(|left| left.child_by_field_name("value"))
            .and_then(dictionary_owner)
    };
    DynamicFieldWrite::Scoped {
        names,
        receiver,
        span,
    }
}

enum RuntimeCreatedTypeCall {
    NotRuntimeCreated,
    RuntimeCreated,
}

fn node_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn resolved_class_bounds(seed: ClassSeed) -> Option<Vec<ClassIdentity>> {
    match seed {
        ClassSeed::Class(class) => Some(vec![class]),
        ClassSeed::Classes(classes) => Some(classes.into_vec()),
        ClassSeed::ClassWithOpenBound(_)
        | ClassSeed::ClassesWithOpenBound(_)
        | ClassSeed::Unknown(_)
        | ClassSeed::NotApplicable => None,
    }
}

fn require_complete_dynamic_receiver_bounds(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    classes: Vec<ClassIdentity>,
) -> Result<Vec<ClassIdentity>, UnknownReason> {
    if classes.is_empty()
        || classes
            .iter()
            .any(|class| adapter.class_hierarchy(workspace, class).unresolved_base)
    {
        return Err(UnknownReason::OpenTypeBound);
    }
    let mut unique = Vec::new();
    for class in classes {
        if !unique.contains(&class) {
            unique.push(class);
        }
    }
    Ok(unique)
}

fn runtime_created_type_call(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    call: Node<'_>,
) -> RuntimeCreatedTypeCall {
    if call.kind() != "call" {
        return RuntimeCreatedTypeCall::NotRuntimeCreated;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return RuntimeCreatedTypeCall::NotRuntimeCreated;
    };
    let ClassSeed::Class(ClassIdentity::External { qualified_name, .. }) =
        resolve_class_at_span(workspace, file.clone(), span_for_node(function), prepared)
    else {
        return RuntimeCreatedTypeCall::NotRuntimeCreated;
    };
    if qualified_name.as_ref() != "builtins.type" {
        return RuntimeCreatedTypeCall::NotRuntimeCreated;
    }

    let Some(arguments) = call.child_by_field_name("arguments") else {
        return RuntimeCreatedTypeCall::NotRuntimeCreated;
    };
    let arguments = node_children(arguments)
        .into_iter()
        .filter(|argument| argument.kind() != "comment")
        .collect::<Vec<_>>();
    if arguments.len() != 3
        || arguments.iter().any(|argument| {
            matches!(
                argument.kind(),
                "keyword_argument"
                    | "list_splat"
                    | "dictionary_splat"
                    | "list_splat_pattern"
                    | "dictionary_splat_pattern"
            )
        })
    {
        return RuntimeCreatedTypeCall::NotRuntimeCreated;
    }
    // The three-positional-argument builtin creates a new runtime class. Its
    // bases affect Python inheritance, but do not make instances of that new
    // class instances of any base's exact static class atom.
    RuntimeCreatedTypeCall::RuntimeCreated
}

fn target_contains_identifier(target: Node<'_>, name: &str, source: &str) -> bool {
    let mut pending = vec![target];
    while let Some(node) = pending.pop() {
        if node.kind() == "identifier" && node.utf8_text(source.as_bytes()).ok() == Some(name) {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    false
}

fn syntax_binds_name(node: Node<'_>, name: &str, source: &str) -> bool {
    match node.kind() {
        "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => node
            .child_by_field_name("left")
            .is_some_and(|left| target_contains_identifier(left, name, source)),
        "named_expression" => ["left", "name"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .any(|target| target_contains_identifier(target, name, source)),
        "with_item" | "except_clause" | "as_pattern" => ["alias", "name"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .any(|target| target_contains_identifier(target, name, source)),
        "function_definition" | "class_definition" => node
            .child_by_field_name("name")
            .is_some_and(|binding| binding.utf8_text(source.as_bytes()).ok() == Some(name)),
        "global_statement"
        | "nonlocal_statement"
        | "import_statement"
        | "import_from_statement" => target_contains_identifier(node, name, source),
        _ => false,
    }
}

fn direct_local_assignment_rhs<'tree>(
    scope: Node<'tree>,
    reference: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if scope.kind() != "function_definition" {
        return None;
    }
    let name = reference.utf8_text(source.as_bytes()).ok()?;
    let mut block = reference;
    loop {
        let parent = block.parent()?;
        if parent.kind() == "block" {
            block = parent;
            break;
        }
        if parent == scope
            || matches!(
                parent.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            return None;
        }
        block = parent;
    }

    let mut containing_statement = reference;
    while containing_statement.parent() != Some(block) {
        containing_statement = containing_statement.parent()?;
    }
    loop {
        let mut assignment = None;
        let mut pending = Vec::new();
        for statement in node_children(block) {
            if statement == containing_statement {
                break;
            }
            pending.push(statement);
            while let Some(node) = pending.pop() {
                if syntax_binds_name(node, name, source) {
                    if node.kind() == "assignment"
                        && assignment_name(node, source) == Some(name)
                        && node
                            .parent()
                            .is_some_and(|statement| statement.kind() == "expression_statement")
                        && node.parent().and_then(|statement| statement.parent()) == Some(block)
                    {
                        assignment = Some(node);
                    } else {
                        return None;
                    }
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
        }
        if let Some(rhs) = assignment.and_then(|node| node.child_by_field_name("right")) {
            return (rhs.end_byte() <= reference.start_byte()).then_some(rhs);
        }

        let mut container = block;
        let mut ancestor = block.parent()?;
        while ancestor != scope && ancestor.kind() != "block" {
            container = ancestor;
            if matches!(
                ancestor.kind(),
                "function_definition" | "lambda" | "class_definition"
            ) {
                return None;
            }
            ancestor = ancestor.parent()?;
        }
        if ancestor.kind() != "block" {
            return None;
        }
        let mut pending = vec![container];
        while let Some(node) = pending.pop() {
            if syntax_binds_name(node, name, source) {
                return None;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        containing_statement = container;
        block = ancestor;
    }
}

fn runtime_created_type_expression(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    scope: Node<'_>,
    expression: Node<'_>,
) -> bool {
    let mut pending = vec![expression];
    let mut visited = HashSet::default();
    while let Some(node) = pending.pop() {
        if matches!(
            runtime_created_type_call(workspace, file, prepared, node),
            RuntimeCreatedTypeCall::RuntimeCreated
        ) {
            return true;
        }
        if node.kind() == "identifier"
            && let Ok(name) = node.utf8_text(prepared.source().as_bytes())
            && visited.insert(Box::<str>::from(name))
            && let Some(rhs) = direct_local_assignment_rhs(scope, node, prepared.source())
        {
            pending.push(rhs);
        }
        match node.kind() {
            "call" => {
                if let Some(function) = node.child_by_field_name("function") {
                    pending.push(function);
                }
            }
            "parenthesized_expression" => {
                if let Some(child) = node.named_child(0) {
                    pending.push(child);
                }
            }
            _ => {}
        }
    }
    false
}

fn expression_dynamic_receiver_bounds(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    scope: Node<'_>,
    expression: Node<'_>,
) -> Result<Vec<ClassIdentity>, UnknownReason> {
    if runtime_created_type_expression(workspace, file, prepared, scope, expression) {
        return Ok(Vec::new());
    }
    let mut pending = vec![expression];
    let mut visited = HashSet::default();
    while let Some(node) = pending.pop() {
        let seed = resolve_class_at_span(workspace, file.clone(), span_for_node(node), prepared);
        if let Some(classes) = resolved_class_bounds(seed) {
            return require_complete_dynamic_receiver_bounds(adapter, workspace, classes);
        }
        if node.kind() == "identifier"
            && let Ok(name) = node.utf8_text(prepared.source().as_bytes())
            && visited.insert(Box::<str>::from(name))
            && let Some(rhs) = direct_local_assignment_rhs(scope, node, prepared.source())
        {
            pending.push(rhs);
        }
        match node.kind() {
            "call" => {
                if let Some(function) = node.child_by_field_name("function") {
                    pending.push(function);
                }
            }
            "parenthesized_expression" => {
                if let Some(child) = node.named_child(0) {
                    pending.push(child);
                }
            }
            _ => {}
        }
    }
    Err(UnknownReason::UnmodeledLoad)
}

fn dynamic_dictionary_receiver(
    procedure: &ProcedureHandle,
    dictionary: Node<'_>,
    source: &str,
) -> Option<ValueId> {
    let attribute = dictionary.child_by_field_name("attribute")?;
    let member_span = span_for_node(attribute);
    procedure
        .semantics()
        .memory_locations()
        .iter()
        .find_map(|location| {
            let MemoryLocationKind::Field { base, member } = &location.kind else {
                return None;
            };
            (member.anchor().span() == member_span
                && attribute.utf8_text(source.as_bytes()).ok() == Some("__dict__"))
            .then_some(*base)
        })
}

fn dynamic_write_receiver_expression<'tree>(
    procedure: &ProcedureHandle,
    prepared: &'tree PreparedSyntaxTree,
    receiver: ValueId,
    write_span: SourceSpan,
) -> Option<Node<'tree>> {
    let site = node_at_span(prepared, write_span)?;
    let semantics = procedure.semantics();
    if site.kind() == "call" {
        let call = semantics.call_sites().iter().find(|call| {
            semantics
                .source_mapping(call.source)
                .is_some_and(|mapping| {
                    mapping.kind == SourceMappingKind::Exact
                        && mapping.locator.anchor().span() == write_span
                })
        })?;
        let function = site.child_by_field_name("function")?;
        if setattr_write(site, prepared.source()).is_some() {
            if !call.arguments.first().is_some_and(|argument| {
                argument.value == receiver && !argument.expansion.is_spread()
            }) {
                return None;
            }
            let arguments = site.child_by_field_name("arguments")?;
            return node_children(arguments)
                .into_iter()
                .find(|argument| argument.kind() != "comment");
        }
        if dynamic_call_write(site, prepared.source()).is_some() {
            let dictionary = function.child_by_field_name("object")?;
            if dynamic_dictionary_receiver(procedure, dictionary, prepared.source())? == receiver {
                return dictionary.child_by_field_name("object");
            }
        }
        return None;
    }

    if matches!(site.kind(), "assignment" | "augmented_assignment")
        && dictionary_write(site, prepared.source()).is_some()
    {
        let dictionary = site
            .child_by_field_name("left")?
            .child_by_field_name("value")?;
        if dynamic_dictionary_receiver(procedure, dictionary, prepared.source())? == receiver {
            return dictionary.child_by_field_name("object");
        }
    }
    None
}

fn enclosing_function_definition<'tree>(mut node: Node<'tree>) -> Option<Node<'tree>> {
    loop {
        if node.kind() == "function_definition" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn nested_helper_reference_runs_in_outer_scope<'tree>(
    mut node: Node<'tree>,
    outer: Node<'tree>,
) -> bool {
    while node != outer {
        if matches!(
            node.kind(),
            "function_definition" | "lambda" | "class_definition" | "generator_expression"
        ) {
            return false;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
    true
}

fn parameter_name_node<'tree>(parameter: Node<'tree>) -> Option<Node<'tree>> {
    if parameter.kind() == "identifier" {
        return Some(parameter);
    }
    parameter.child_by_field_name("name").or_else(|| {
        node_children(parameter)
            .into_iter()
            .find(|node| node.kind() == "identifier")
    })
}

fn nested_receiver_parameter(
    helper: Node<'_>,
    receiver: Node<'_>,
    source: &str,
) -> Option<(usize, Box<str>, bool)> {
    if receiver.kind() != "identifier" {
        return None;
    }
    let receiver_name = receiver.utf8_text(source.as_bytes()).ok()?;
    let parameters = helper.child_by_field_name("parameters")?;
    let mut positional_ordinal = 0;
    let mut keyword_only = false;
    for parameter in node_children(parameters) {
        if parameter.kind() == "keyword_separator" {
            keyword_only = true;
            continue;
        }
        if parameter.kind() == "list_splat_pattern" {
            keyword_only = true;
            continue;
        }
        if parameter.kind() == "dictionary_splat_pattern" {
            continue;
        }
        let Some(name) = parameter_name_node(parameter) else {
            continue;
        };
        let name_text = name.utf8_text(source.as_bytes()).ok()?;
        if name_text == receiver_name {
            return Some((positional_ordinal, Box::from(name_text), keyword_only));
        }
        if !keyword_only {
            positional_ordinal += 1;
        }
    }
    None
}

fn nested_helper_direct_calls<'tree>(
    outer: Node<'tree>,
    helper: Node<'tree>,
    source: &str,
) -> Result<Vec<Node<'tree>>, UnknownReason> {
    if helper
        .parent()
        .is_some_and(|parent| parent.kind() == "decorated_definition")
    {
        return Err(UnknownReason::UncertainFlow);
    }
    let Some(body) = outer.child_by_field_name("body") else {
        return Err(UnknownReason::UncertainFlow);
    };
    let helper_block = helper.parent();
    if helper_block.is_none_or(|block| block.parent() != Some(outer) || block != body) {
        return Err(UnknownReason::UncertainFlow);
    }
    let Some(name_node) = helper.child_by_field_name("name") else {
        return Err(UnknownReason::UncertainFlow);
    };
    let Ok(name) = name_node.utf8_text(source.as_bytes()) else {
        return Err(UnknownReason::UncertainFlow);
    };
    let mut calls = Vec::new();
    let mut pending = vec![body];
    while let Some(node) = pending.pop() {
        if node == name_node {
            continue;
        }
        if node.kind() == "identifier" && node.utf8_text(source.as_bytes()).ok() == Some(name) {
            if enclosing_function_definition(node) != Some(outer)
                || !nested_helper_reference_runs_in_outer_scope(node, outer)
            {
                return Err(UnknownReason::UncertainFlow);
            }
            let direct_callee = node.parent().is_some_and(|parent| {
                parent.kind() == "call" && parent.child_by_field_name("function") == Some(node)
            });
            if !direct_callee {
                return Err(UnknownReason::UncertainFlow);
            }
            calls.push(node.parent().expect("a direct callee has a call parent"));
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    if calls.is_empty() {
        return Err(UnknownReason::UnmodeledLoad);
    }
    Ok(calls)
}

fn nested_helper_argument_expression<'tree>(
    call: Node<'tree>,
    parameter_name: &str,
    positional_ordinal: usize,
    keyword_only: bool,
    source: &str,
) -> Result<Node<'tree>, UnknownReason> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Err(UnknownReason::UnmodeledLoad);
    };
    let mut positional = 0;
    let mut positional_match = None;
    let mut keyword_match = None;
    for argument in node_children(arguments) {
        match argument.kind() {
            "comment" => {}
            "keyword_argument" => {
                if argument
                    .child_by_field_name("name")
                    .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                    == Some(parameter_name)
                {
                    keyword_match = argument.child_by_field_name("value");
                }
            }
            "list_splat" | "dictionary_splat" => {
                return Err(UnknownReason::UnmodeledLoad);
            }
            _ => {
                if positional == positional_ordinal {
                    positional_match = Some(argument);
                }
                positional += 1;
            }
        }
    }
    if keyword_only {
        keyword_match.ok_or(UnknownReason::UnmodeledLoad)
    } else if positional_match.is_some() && keyword_match.is_some() {
        Err(UnknownReason::UnmodeledLoad)
    } else {
        positional_match
            .or(keyword_match)
            .ok_or(UnknownReason::UnmodeledLoad)
    }
}

/// Whether a workspace class can shadow an inherited modeled member through
/// class state or an instance/dynamic write. This intentionally errs toward
/// no narrowing: an unnameable dynamic write is enough to invalidate the
/// external member contract.
fn python_class_member_shadowed_bounded(
    python: &PythonAnalyzer,
    owner: &CodeUnit,
    member: &str,
) -> Option<bool> {
    let prepared = current_indexed_prepared(python, owner.source())?;
    let class = class_node_for_unit(python, &prepared, owner)?;
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let mut stack = vec![class];
    while let Some(node) = stack.pop() {
        if !session.scope_step() {
            return None;
        }
        if node != class && class_definition_node(node).is_some() {
            continue;
        }
        if writes_member_name(node, prepared.source(), member) {
            return Some(true);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    python
        .indexed_source_matches(owner.source(), prepared.source())
        .then_some(false)
}

fn python_class_hierarchy_member_unshadowed_bounded(
    python: &PythonAnalyzer,
    owner: &CodeUnit,
    member: &str,
) -> Option<bool> {
    let mut owners = vec![owner.clone()];
    owners.extend(python.get_ancestors(owner));
    for owner in owners {
        match python_class_member_shadowed_bounded(python, &owner, member) {
            Some(false) => {}
            Some(true) => return Some(false),
            None => return None,
        }
    }
    Some(true)
}

fn external_instance_method_present_on_owner(
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> bool {
    let matched = overlay.member_target_on_owner(owner_id, member);
    let [record] = matched.records.as_slice() else {
        return false;
    };
    matched.disposition
        == crate::analyzer::semantic_model::SemanticModelMemberTargetDisposition::Unique
        && record.language == Language::Python.config_label()
        && record.kind == SemanticModelSymbolKind::Method
        && !record.is_static()
        && record.has_receiver()
        && !record.provenance.ambiguous
        && record.provenance.completeness == SemanticModelCompleteness::Complete
}

fn complete_builtin_external_class(overlay: &SemanticModelOverlay, class: &ClassIdentity) -> bool {
    let ClassIdentity::External {
        qualified_name,
        symbol_id,
    } = class
    else {
        return false;
    };
    if !qualified_name.starts_with("builtins.") {
        return false;
    }
    let matched = overlay.symbols_with_id(symbol_id);
    let [record] = matched.records.as_slice() else {
        return false;
    };
    record.language == Language::Python.config_label()
        && record.owner_id.is_none()
        && record.kind == SemanticModelSymbolKind::Class
        && record.qualified_name == qualified_name.as_ref()
        && !record.provenance.ambiguous
        && record.provenance.completeness == SemanticModelCompleteness::Complete
}

/// A decorator can replace the class value even when its source declaration
/// has an ordinary metaclass. Only exact reviewed direct/factory contracts
/// establish that the declared identity survives every decorator application.
fn class_decorators_preserve_identity(
    workspace: &WorkspaceAnalyzer,
    python: &PythonAnalyzer,
    owner: &CodeUnit,
    prepared: &PreparedSyntaxTree,
    class: Node<'_>,
) -> Option<bool> {
    let Some(decorated) = class
        .parent()
        .filter(|node| node.kind() == "decorated_definition")
    else {
        return Some(true);
    };
    let snapshot = workspace.analyzer().active_semantic_model_snapshot()?;
    let overlay = snapshot.semantic_model_overlay()?;
    let active = snapshot.active_models();
    let scope = AnalyzerQueryScope::new(python);
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let support = PythonDefinitionProvider::new(python, &session);
    let mut cursor = decorated.walk();
    for decorator in decorated.named_children(&mut cursor) {
        if !session.scope_step() {
            return None;
        }
        if decorator.kind() != "decorator" {
            continue;
        }
        let mut decorator_cursor = decorator.walk();
        let mut expressions = decorator
            .named_children(&mut decorator_cursor)
            .filter(|node| !node.is_extra());
        let expression = expressions.next()?;
        if expressions.next().is_some() {
            return None;
        }
        let mut keywords = Vec::new();
        let callee = if expression.kind() == "call" {
            let arguments = expression.child_by_field_name("arguments")?;
            let mut names = HashSet::default();
            let mut argument_cursor = arguments.walk();
            for argument in arguments
                .named_children(&mut argument_cursor)
                .filter(|node| !node.is_extra())
            {
                if !session.scope_step() || argument.kind() != "keyword_argument" {
                    return None;
                }
                let name = argument
                    .child_by_field_name("name")?
                    .utf8_text(prepared.source().as_bytes())
                    .ok()?;
                let value = match argument.child_by_field_name("value")?.kind() {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                };
                if !names.insert(name) {
                    return None;
                }
                keywords.push((name, value));
            }
            expression.child_by_field_name("function")?
        } else {
            expression
        };
        let (module, member) = python_external_imported_symbol_bounded(
            &support,
            scope.token(),
            owner.source(),
            prepared.source(),
            prepared.tree().root_node(),
            callee,
        )?;
        let canonical = format!("{module}.{member}");
        let symbols = overlay.symbols_named(&canonical);
        let [symbol] = symbols.records.as_slice() else {
            return None;
        };
        if symbol.qualified_name != canonical
            || symbol.language != Language::Python.config_label()
            || symbol.kind != SemanticModelSymbolKind::Function
            || symbol.has_receiver()
            || symbol.provenance.ambiguous
            || !symbol.has_complete_callable_shape_evidence()
            || symbol.structured_signature().is_none()
        {
            return None;
        }
        let arity = if expression.kind() == "call" {
            u32::try_from(keywords.len()).ok()?
        } else {
            1
        };
        let matched = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
            Language::Python.config_label(),
            &module,
            &member,
            false,
            arity,
        ));
        if matched.disposition != SemanticModelMatchDisposition::Unique
            || matched.records.len() != 1
        {
            return None;
        }
        let selected = &matched.records[0];
        let provenance = selected.provenance(active);
        if provenance.ambiguous || provenance.completeness != SemanticModelCompleteness::Complete {
            return None;
        }
        let identity = selected.class_decorator_identity()?;
        if expression.kind() == "call" {
            let allowed = identity.factory_keywords.as_ref()?;
            if keywords.iter().any(|(name, value)| {
                !allowed
                    .iter()
                    .any(|keyword| keyword.name == *name && keyword.allowed_values.contains(value))
            }) {
                return None;
            }
        } else if !identity.direct {
            return None;
        }
    }
    (session.scope_step() && python.indexed_source_matches(owner.source(), prepared.source()))
        .then_some(true)
}

fn workspace_class_uses_ordinary_metaclass(
    workspace: &WorkspaceAnalyzer,
    python: &PythonAnalyzer,
    owner: &CodeUnit,
    overlay: Option<&SemanticModelOverlay>,
) -> bool {
    let Some(prepared) = current_indexed_prepared(python, owner.source()) else {
        return false;
    };
    let Some(class) = class_node_for_unit(python, &prepared, owner) else {
        return false;
    };
    if class.child_by_field_name("body").is_none() {
        return false;
    }
    if class_decorators_preserve_identity(workspace, python, owner, &prepared, class) != Some(true)
    {
        return false;
    }
    let Some(superclasses) = class.child_by_field_name("superclasses") else {
        return true;
    };
    let mut cursor = superclasses.walk();
    for base in superclasses.named_children(&mut cursor) {
        if base.kind() != "keyword_argument" {
            continue;
        }
        let Some(name) = base.child_by_field_name("name") else {
            return false;
        };
        let Ok(name) = name.utf8_text(prepared.source().as_bytes()) else {
            return false;
        };
        if name != "metaclass" {
            // Other class-header keyword arguments are also metaclass- or
            // class-construction behavior not represented by this proof.
            return false;
        }
        let Some(value) = base.child_by_field_name("value") else {
            return false;
        };
        let identity = match resolve_class_at_span(
            workspace,
            owner.source().clone(),
            span_for_node(value),
            &prepared,
        ) {
            ClassSeed::Class(identity) => identity,
            ClassSeed::Classes(_)
            | ClassSeed::ClassWithOpenBound(_)
            | ClassSeed::ClassesWithOpenBound(_)
            | ClassSeed::Unknown(_)
            | ClassSeed::NotApplicable => return false,
        };
        if identity.qualified_name() != "builtins.type"
            || overlay.is_none_or(|overlay| !complete_builtin_external_class(overlay, &identity))
        {
            return false;
        }
    }
    true
}

fn external_seed(
    overlay: Option<&SemanticModelOverlay>,
    name: &str,
    cache: &mut ExternalClassCache,
) -> ClassSeed {
    match external_class_identity(overlay, Language::Python, name, None, cache) {
        Some(identity) => ClassSeed::Class(identity),
        None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
    }
}

fn external_module_value_seed(
    overlay: &SemanticModelOverlay,
    module: &str,
    member: &str,
) -> Option<ClassSeed> {
    let qualified_name = format!("{module}.{member}");
    let matched = overlay.symbols_named(&qualified_name);
    if matched.disposition != SemanticModelOverlayDisposition::Unique {
        return Some(ClassSeed::Unknown(UnknownReason::AmbiguousCallee));
    }
    let [symbol] = matched.records.as_slice() else {
        return Some(ClassSeed::Unknown(UnknownReason::AmbiguousCallee));
    };
    if symbol.language != Language::Python.config_label()
        || symbol.kind != SemanticModelSymbolKind::Field
    {
        return None;
    }
    if symbol.provenance.ambiguous {
        return Some(ClassSeed::Unknown(UnknownReason::AmbiguousCallee));
    }
    if symbol.provenance.completeness != SemanticModelCompleteness::Complete {
        return Some(ClassSeed::Unknown(UnknownReason::PackIncomplete));
    }
    let Some(declared_type) = symbol.proxied_type.as_ref().or(symbol.value_type.as_ref()) else {
        return Some(ClassSeed::Unknown(UnknownReason::ExternalNotModeled));
    };
    let mut cache = ExternalClassCache::default();
    let identity = match declared_type {
        TypeRef::Named {
            name,
            arguments,
            nullable: false,
        } if arguments.is_empty() => {
            external_class_identity(Some(overlay), Language::Python, name, None, &mut cache)
        }
        TypeRef::Declared {
            id,
            arguments,
            nullable: false,
        } if arguments.is_empty() => {
            let target = overlay.symbols_with_id(id);
            if target.disposition != SemanticModelOverlayDisposition::Unique {
                return Some(ClassSeed::Unknown(UnknownReason::AmbiguousCallee));
            }
            let [target] = target.records.as_slice() else {
                return Some(ClassSeed::Unknown(UnknownReason::ExternalNotModeled));
            };
            external_class_identity(
                Some(overlay),
                Language::Python,
                &target.qualified_name,
                Some(id),
                &mut cache,
            )
        }
        _ => return Some(ClassSeed::Unknown(UnknownReason::ExternalNotModeled)),
    };
    Some(match identity {
        Some(identity) => ClassSeed::Class(identity),
        None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
    })
}

/// The module and member an import statement binds `reference` to.
///
/// A bare imported name and a namespaced path are the same question for the
/// import binder: `from abc import ABC` and `import abc` + `abc.ABC` both name
/// `abc.ABC`, and an external callee, decorator, or base is whatever the
/// binder's shadowing and uniqueness proofs say it is. The binder answers
/// nothing when a workspace declaration owns the name, so an activated model
/// never stands in for workspace code.
fn import_bound_external_symbol(
    python: &PythonAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
) -> Option<(String, String)> {
    let scope = AnalyzerQueryScope::new(python);
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let support = PythonDefinitionProvider::new(python, &session);
    python_external_imported_symbol_bounded(
        &support,
        scope.token(),
        file,
        prepared.source(),
        prepared.tree().root_node(),
        reference,
    )
}

fn imported_external_callable_binding(
    python: &PythonAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
) -> Option<(String, String)> {
    if let Some(binding) = import_bound_external_symbol(python, file, prepared, reference) {
        return Some(binding);
    }
    if reference.kind() != "identifier" {
        return None;
    }
    let member = reference.utf8_text(prepared.source().as_bytes()).ok()?;
    indexed_builtin_is_unshadowed(python, reference, prepared)
        .is_some_and(|unshadowed| unshadowed)
        .then(|| ("builtins".to_owned(), member.to_owned()))
}

/// Resolve an imported external function's return. An explicit exact class
/// set closes the result; a complete return annotation alone keeps its
/// ordinary open type bound. A typing.Any return stays an unknown value
/// because Any is not a runtime class.
fn imported_external_function_result_seed(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    expression: Node<'_>,
) -> Option<ClassSeed> {
    let python = python_analyzer(workspace);
    let (module, member) = imported_external_callable_binding(python, file, prepared, expression)?;
    let canonical = format!("{module}.{member}");
    let overlay = workspace.analyzer().semantic_model_overlay()?;
    let symbols = overlay.symbols_named(&canonical);
    let [symbol] = symbols.records.as_slice() else {
        return None;
    };
    if symbol.qualified_name != canonical
        || symbol.language != Language::Python.config_label()
        || symbol.kind != SemanticModelSymbolKind::Function
        || symbol.has_receiver()
        || symbol.provenance.ambiguous
        || (symbol.exact_return_classes.is_empty()
            && !symbol.has_complete_callable_shape_evidence())
    {
        return None;
    }
    let mut cache = ExternalClassCache::default();
    if !symbol.exact_return_classes.is_empty() {
        let classes = symbol
            .exact_return_classes
            .iter()
            .map(|class| match class {
                crate::analyzer::semantic_model::TypeRef::Named {
                    name,
                    nullable: false,
                    ..
                } => external_class_identity(
                    Some(&overlay),
                    Language::Python,
                    name,
                    None,
                    &mut cache,
                ),
                crate::analyzer::semantic_model::TypeRef::Declared {
                    id,
                    nullable: false,
                    ..
                } => external_class_identity(
                    Some(&overlay),
                    Language::Python,
                    "",
                    Some(id),
                    &mut cache,
                ),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        return Some(python_dynamic_any_seed(ClassSeed::classes(classes)));
    }
    let returns = symbol.structured_signature()?.returns.as_ref()?;
    if python_type_ref_contains_any(&overlay, returns) {
        return Some(ClassSeed::Unknown(UnknownReason::UncertainFlow));
    }
    let class = match returns {
        crate::analyzer::semantic_model::TypeRef::Named {
            name,
            nullable: false,
            ..
        } => external_class_identity(Some(&overlay), Language::Python, name, None, &mut cache),
        crate::analyzer::semantic_model::TypeRef::Declared {
            id,
            nullable: false,
            ..
        } => external_class_identity(Some(&overlay), Language::Python, "", Some(id), &mut cache),
        _ => None,
    }?;
    Some(python_dynamic_any_seed(ClassSeed::ClassWithOpenBound(
        class,
    )))
}

/// Whether a base spelling names a typing marker rather than a class that
/// contributes members.
///
/// `Generic` and `Protocol` exist to carry type parameters. Typeshed spells
/// `Generic` as a variable annotated `type[_Generic]` and `Protocol` as a
/// `_SpecialForm`, so neither resolves as a class at all, and a class that
/// names one would otherwise have a base nothing can resolve. The stub
/// producer already drops both when it records a hierarchy; this is the same
/// rule on the workspace side.
fn python_typing_marker_base(python: &PythonAnalyzer, owner: &CodeUnit, raw: &str) -> bool {
    let raw = raw.trim();
    let Some(prepared) = current_indexed_prepared(python, owner.source()) else {
        return false;
    };
    let Some(class) = class_node_for_unit(python, &prepared, owner) else {
        return false;
    };
    let Some(bases) = class.child_by_field_name("superclasses") else {
        return false;
    };
    let mut cursor = bases.walk();
    let Some(base) = bases
        .named_children(&mut cursor)
        .filter(|base| base.kind() != "keyword_argument")
        .map(python_base_origin_node)
        .find(|base| base.utf8_text(prepared.source().as_bytes()) == Ok(raw))
    else {
        return false;
    };
    let Some((module, member)) =
        import_bound_external_symbol(python, owner.source(), &prepared, base)
    else {
        return false;
    };
    matches!(
        format!("{module}.{member}").as_str(),
        "typing.Protocol"
            | "typing.Generic"
            | "typing_extensions.Protocol"
            | "typing_extensions.Generic"
    )
}

fn python_class_has_protocol_base(python: &PythonAnalyzer, owner: &CodeUnit) -> bool {
    let Some(prepared) = current_indexed_prepared(python, owner.source()) else {
        return true;
    };
    let Some(class) = class_node_for_unit(python, &prepared, owner) else {
        return true;
    };
    let Some(bases) = class.child_by_field_name("superclasses") else {
        return false;
    };
    let mut cursor = bases.walk();
    bases
        .named_children(&mut cursor)
        .filter(|base| base.kind() != "keyword_argument")
        .map(python_base_origin_node)
        .any(|base| {
            import_bound_external_symbol(python, owner.source(), &prepared, base).is_some_and(
                |(module, member)| {
                    matches!(
                        format!("{module}.{member}").as_str(),
                        "typing.Protocol" | "typing_extensions.Protocol"
                    )
                },
            )
        })
}

fn python_class_declares_abstract_members(
    python: &PythonAnalyzer,
    owner: &CodeUnit,
) -> Option<HashMap<String, bool>> {
    let prepared = current_indexed_prepared(python, owner.source())?;
    let class = class_node_for_unit(python, &prepared, owner)?;
    let body = class.child_by_field_name("body")?;
    let mut members = HashMap::default();
    let mut cursor = body.walk();
    for declaration in body.named_children(&mut cursor) {
        let (definition, decorated) = match declaration.kind() {
            "decorated_definition" => {
                let mut cursor = declaration.walk();
                let Some(definition) = declaration
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "function_definition")
                else {
                    continue;
                };
                (definition, Some(declaration))
            }
            "function_definition" => (declaration, None),
            _ => continue,
        };
        let Some(name) = definition
            .child_by_field_name("name")
            .and_then(|name| name.utf8_text(prepared.source().as_bytes()).ok())
        else {
            continue;
        };
        let is_abstract = decorated.is_some_and(|decorated| {
            let mut cursor = decorated.walk();
            decorated
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "decorator")
                .filter_map(|decorator| decorator.named_child(0))
                .any(|expression| {
                    let target = if expression.kind() == "call" {
                        expression
                            .child_by_field_name("function")
                            .unwrap_or(expression)
                    } else {
                        expression
                    };
                    import_bound_external_symbol(python, owner.source(), &prepared, target)
                        .is_some_and(|(module, member)| {
                            module == "abc"
                                && matches!(
                                    member.as_str(),
                                    "abstractmethod"
                                        | "abstractclassmethod"
                                        | "abstractstaticmethod"
                                        | "abstractproperty"
                                )
                        })
                })
        });
        members.insert(name.to_owned(), is_abstract);
    }
    Some(members)
}

fn python_class_hierarchy_has_abstract_members(python: &PythonAnalyzer, class: &CodeUnit) -> bool {
    let mut frontier = vec![class.clone()];
    let mut seen = HashSet::default();
    let mut nearest_members: HashMap<String, (usize, bool)> = HashMap::default();
    let mut distance = 0;
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for owner in frontier {
            if !seen.insert(owner.clone()) {
                continue;
            }
            let Some(declarations) = python_class_declares_abstract_members(python, &owner) else {
                return true;
            };
            for (name, is_abstract) in declarations {
                match nearest_members.entry(name) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert((distance, is_abstract));
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry)
                        if entry.get().0 == distance =>
                    {
                        entry.get_mut().1 |= is_abstract;
                    }
                    std::collections::hash_map::Entry::Occupied(_) => {}
                }
            }
            next.extend(python.get_direct_ancestors(&owner));
        }
        frontier = next;
        distance += 1;
    }
    nearest_members
        .values()
        .any(|(_, is_abstract)| *is_abstract)
}

fn external_hierarchy_has_protocol_or_abstract_members(
    workspace: &WorkspaceAnalyzer,
    ancestors: &[ClassIdentity],
) -> bool {
    let Some(overlay) = workspace.analyzer().semantic_model_overlay() else {
        return ancestors
            .iter()
            .any(|ancestor| matches!(ancestor, ClassIdentity::External { .. }));
    };
    for ancestor in ancestors {
        let ClassIdentity::External { symbol_id, .. } = ancestor else {
            continue;
        };
        let matched = overlay.symbols_with_id(symbol_id);
        let [symbol] = matched.records.as_slice() else {
            return true;
        };
        let surface = overlay.owner_surface(symbol);
        if !surface.gaps.is_empty()
            || surface.closure.iter().any(|owner| {
                matches!(
                    owner.qualified_name.as_str(),
                    "typing.Protocol" | "typing_extensions.Protocol"
                ) || owner.declaration_is_abstract()
                    || overlay
                        .members_of(&owner.id)
                        .records
                        .iter()
                        .any(|member| member.declaration_is_abstract())
            })
        {
            return true;
        }
    }
    false
}

fn declared_parameter_annotation_at_span(
    prepared: &PreparedSyntaxTree,
    span: SourceSpan,
) -> Option<(Node<'_>, Node<'_>)> {
    let mut node = node_at_span(prepared, span)?;
    while !matches!(node.kind(), "function_definition" | "lambda") {
        node = node.parent()?;
    }
    let layout = formal_parameter_slots_for_owner(Language::Python, node, prepared.source())?;
    let mut slots = layout.slots.iter().filter(|slot| {
        slot.declaration_range.start_byte <= span.start_byte() as usize
            && span.end_byte() as usize <= slot.declaration_range.end_byte
    });
    let slot = slots.next()?;
    if slots.next().is_some() {
        return None;
    }
    let declaration = node.named_descendant_for_byte_range(
        slot.declaration_range.start_byte,
        slot.declaration_range.end_byte,
    )?;
    let annotation = match declaration.kind() {
        "typed_parameter" | "typed_default_parameter" => declaration.child_by_field_name("type")?,
        _ => return None,
    };
    Some((node, annotation))
}

/// Whether this exact base expression is an unshadowed intrinsic builtin
/// root with no source declaration in the active workspace.
pub(super) fn python_intrinsic_base_is_unshadowed(
    python: &PythonAnalyzer,
    owner: &CodeUnit,
    raw: &str,
) -> bool {
    let name = raw.trim();
    if name != "object" && super::python_builtin_exception_name(name).is_none() {
        return false;
    }
    let Some(prepared) = current_indexed_prepared(python, owner.source()) else {
        return false;
    };
    let Some(class) = class_node_for_unit(python, &prepared, owner) else {
        return false;
    };
    let Some(bases) = class.child_by_field_name("superclasses") else {
        return false;
    };
    let mut cursor = bases.walk();
    let Some(base) = bases
        .named_children(&mut cursor)
        .filter(|base| base.kind() != "keyword_argument")
        .map(python_base_origin_node)
        .find(|base| base.utf8_text(prepared.source().as_bytes()) == Ok(name))
    else {
        return false;
    };
    base.kind() == "identifier"
        && base.utf8_text(prepared.source().as_bytes()) == Ok(name)
        && import_bound_external_symbol(python, owner.source(), &prepared, base).is_none()
        && indexed_builtin_is_unshadowed(python, base, &prepared) == Some(true)
}

/// Python supplies the default `object` behavior even when the active pack
/// omits the builtin's declaration.
fn python_default_object_base(python: &PythonAnalyzer, owner: &CodeUnit, raw: &str) -> bool {
    raw.trim() == "object" && python_intrinsic_base_is_unshadowed(python, owner, raw)
}

/// The active model's class for one canonical dotted name.
///
/// The name index admits aliases and simple-name postings, so a match is a
/// proof of this name only when the record's own qualified name is the name
/// asked for, or when the name is one of the record's exact exported aliases.
/// A terminal-name posting alone is not proof of a base.
fn exact_external_class_name(
    overlay: Option<&SemanticModelOverlay>,
    qualified_name: &str,
    cache: &mut ExternalClassCache,
) -> Option<ClassIdentity> {
    let identity = external_class_identity(overlay, Language::Python, qualified_name, None, cache)?;
    if identity.qualified_name() == qualified_name {
        return Some(identity);
    }
    let ClassIdentity::External { symbol_id, .. } = &identity else {
        unreachable!("external class lookup returns an external identity")
    };
    let matched = overlay?.symbols_with_id(symbol_id);
    let [record] = matched.records.as_slice() else {
        return None;
    };
    record
        .aliases
        .iter()
        .any(|alias| alias == qualified_name)
        .then_some(identity)
}

/// Raw supertypes retain source spelling, not a resolved import identity. A
/// base spelling therefore resolves only through one of the base expression's
/// own bindings: the import binder for a name an import statement owns, or
/// the builtin surface for an unshadowed builtin name. A bare name that the
/// binder proves is an imported symbol resolves to that dependency's class;
/// the active model must confirm the class, and a name the model does not
/// model stays unresolved rather than falling back to a spelling match.
fn exact_external_base(
    python: &PythonAnalyzer,
    owner: &CodeUnit,
    overlay: Option<&SemanticModelOverlay>,
    raw: &str,
    cache: &mut ExternalClassCache,
) -> Option<ClassIdentity> {
    let raw = raw.trim();
    let prepared = current_indexed_prepared(python, owner.source())?;
    let class = class_node_for_unit(python, &prepared, owner)?;
    let bases = class.child_by_field_name("superclasses")?;
    let mut cursor = bases.walk();
    // A raw spelling is the base's origin, so match against the same
    // reduction: `Mapping[str, int]` records and resolves as `Mapping`.
    let base = bases
        .named_children(&mut cursor)
        .filter(|base| base.kind() != "keyword_argument")
        .map(python_base_origin_node)
        .find(|base| base.utf8_text(prepared.source().as_bytes()) == Ok(raw))?;
    let identity = if base.kind() == "attribute" {
        let scope = AnalyzerQueryScope::new(python);
        let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
        let token = scope.token();
        let support = PythonDefinitionProvider::new(python, &session);
        let canonical = python_namespace_imported_class_name_bounded(
            &support,
            token,
            owner.source(),
            prepared.source(),
            prepared.tree().root_node(),
            base,
        )?;
        if canonical != raw {
            return None;
        }
        exact_external_class_name(overlay, &canonical, cache)?
    } else {
        // A plain name is not always a builtin: `from abc import ABC` binds a
        // dependency class that no workspace declaration resolves, and the
        // import binder is the same proof the namespaced branch uses. The
        // builtin spelling is the fallback for names no import owns, which is
        // also why a name both imported and builtin prefers the import.
        let imported = import_bound_external_symbol(python, owner.source(), &prepared, base)
            .and_then(|(module, member)| {
                exact_external_class_name(overlay, &format!("{module}.{member}"), cache)
            });
        match imported {
            Some(identity) => identity,
            None => {
                let ClassSeed::Class(identity) =
                    builtin_class_reference(python, overlay, base, &prepared, cache)?
                else {
                    return None;
                };
                identity
            }
        }
    };
    python
        .indexed_source_matches(owner.source(), prepared.source())
        .then_some(identity)
}

/// Whether Python attribute lookup may bypass a method already found on this
/// receiver class. A custom `__getattribute__` can replace any lookup. An
/// external hierarchy edge that does not resolve to one modeled declaration
/// remains risky; a partial member surface alone does not, because an override
/// is an explicit declaration in the modeled class body or its ancestors.
pub(crate) fn python_receiver_method_dispatch_may_be_bypassed(
    python: &PythonAnalyzer,
    receiver_class: &CodeUnit,
) -> bool {
    let workspace_ancestors = python.get_ancestors(receiver_class);
    if std::iter::once(receiver_class)
        .chain(workspace_ancestors.iter())
        .any(|owner| {
            python
                .direct_children(owner)
                .iter()
                .any(|child| child.terminal_name() == "__getattribute__")
        })
    {
        return true;
    }

    let overlay = python
        .active_semantic_model_snapshot()
        .and_then(|snapshot| snapshot.semantic_model_overlay().cloned());
    let mut external_cache = ExternalClassCache::default();
    let mut checked_external = HashSet::<Box<str>>::default();
    for owner in std::iter::once(receiver_class).chain(workspace_ancestors.iter()) {
        let direct = python.get_direct_ancestors(owner);
        for raw in python.inner.raw_supertypes_of(owner) {
            if direct
                .iter()
                .any(|ancestor| ancestor.terminal_name() == raw || ancestor.fq_name_str() == raw)
            {
                continue;
            }
            match exact_external_base(python, owner, overlay.as_deref(), &raw, &mut external_cache)
            {
                Some(ClassIdentity::External { symbol_id, .. }) => {
                    if checked_external.insert(symbol_id.clone())
                        && external_class_may_override_getattribute(overlay.as_deref(), &symbol_id)
                    {
                        return true;
                    }
                }
                Some(ClassIdentity::Workspace(_)) => {
                    unreachable!("external base resolution returns external classes")
                }
                None if python_default_object_base(python, owner, &raw) => {}
                None if python_typing_marker_base(python, owner, &raw) => {}
                None => return true,
            }
        }
    }
    false
}

/// Whether a modeled external base or one of its modeled ancestors declares
/// an instance lookup hook. Partial member surfaces do not hide an explicit
/// method declaration; unresolved or ambiguous hierarchy edges still do.
fn external_class_may_override_getattribute(
    overlay: Option<&SemanticModelOverlay>,
    symbol_id: &str,
) -> bool {
    let Some(overlay) = overlay else {
        return true;
    };
    let matched = overlay.symbols_with_id(symbol_id);
    let [owner] = matched.records.as_slice() else {
        return true;
    };
    if owner.qualified_name == "builtins.object" {
        return false;
    }
    let surface = overlay.owner_surface(owner);
    if surface
        .gaps
        .iter()
        .any(|gap| !matches!(gap, SemanticModelSurfaceGap::PartialType { .. }))
    {
        return true;
    }
    surface.closure.iter().any(|ancestor| {
        ancestor.qualified_name != "builtins.object"
            && overlay
                .members_of(&ancestor.id)
                .records
                .iter()
                .any(|member| member.name == "__getattribute__")
    })
}

/// Flatten the classes a guard names into one node per class.
///
/// `isinstance` accepts a tuple of classes and, since Python 3.10, a `|` union
/// of them. Both spell the same set. Returns false for a shape that is neither
/// a class reference nor a way of combining them, which leaves the guard
/// unresolved rather than half-read.
fn collect_guard_class_nodes<'tree>(node: Node<'tree>, nodes: &mut Vec<Node<'tree>>) -> bool {
    match node.kind() {
        "tuple" => {
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            children
                .into_iter()
                .all(|child| collect_guard_class_nodes(child, nodes))
        }
        "binary_operator" => {
            let Some(operator) = node.child_by_field_name("operator") else {
                return false;
            };
            if operator.kind() != "|" {
                return false;
            }
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return false;
            };
            collect_guard_class_nodes(left, nodes) && collect_guard_class_nodes(right, nodes)
        }
        _ => {
            nodes.push(node);
            true
        }
    }
}

/// The class one guard class expression names: a workspace class by its
/// declaration, or a bare unshadowed builtin name through the builtin table.
fn guard_class_identity(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    overlay: Option<&SemanticModelOverlay>,
    cache: &mut ExternalClassCache,
    class: Node<'_>,
) -> Result<ClassIdentity, UnknownReason> {
    let unmodeled = || UnknownReason::UnmodeledGuard {
        class: class
            .utf8_text(prepared.source().as_bytes())
            .expect("a class expression is within its prepared source")
            .into(),
    };
    match resolve_class_at_span(workspace, file.clone(), span_for_node(class), prepared) {
        ClassSeed::Class(identity) => Ok(identity),
        ClassSeed::Unknown(UnknownReason::SemanticBudget) => Err(UnknownReason::SemanticBudget),
        // A builtin name has no workspace declaration for the type lookup to
        // return, so `isinstance(value, dict)` resolves to nothing through that
        // route and is modeled here.
        ClassSeed::NotApplicable => {
            exact_builtin_class(python_analyzer(workspace), class, prepared, overlay, cache)
                .ok_or_else(unmodeled)
        }
        ClassSeed::Classes(_)
        | ClassSeed::ClassWithOpenBound(_)
        | ClassSeed::ClassesWithOpenBound(_)
        | ClassSeed::Unknown(_) => Err(unmodeled()),
    }
}

/// The builtin class a bare unshadowed builtin name denotes.
///
/// A builtin has no workspace declaration, so a type lookup answers nothing
/// for `dict` in `isinstance(value, dict)`. The name is only that class when
/// no lexical or module binding competes with it, which is the same proof a
/// builtin base spelling needs.
fn exact_builtin_class(
    python: &PythonAnalyzer,
    reference: Node<'_>,
    prepared: &PreparedSyntaxTree,
    overlay: Option<&SemanticModelOverlay>,
    cache: &mut ExternalClassCache,
) -> Option<ClassIdentity> {
    if reference.kind() != "identifier" {
        return None;
    }
    let name = reference.utf8_text(prepared.source().as_bytes()).ok()?;
    if !is_python_builtin_or_constant(name) {
        return None;
    }
    let identity = external_class_identity(overlay, Language::Python, name, None, cache)?;
    if identity.qualified_name() != format!("builtins.{name}") {
        return None;
    }
    indexed_builtin_is_unshadowed(python, reference, prepared)?.then_some(identity)
}

/// Completed lexical facts are independent of models and workspace bindings.
/// Exact source bytes and the reference position determine the answer. Keep
/// them for one query only; an interrupted bounded walk never supplies a fact.
#[derive(Default)]
struct PythonBuiltinShadowRequestMemo {
    answers: Mutex<HashMap<([u8; 32], SourceSpan), bool>>,
    #[cfg(test)]
    walks: std::sync::atomic::AtomicUsize,
}

impl PythonBuiltinShadowRequestMemo {
    fn unshadowed(
        &self,
        reference: Node<'_>,
        prepared: &PreparedSyntaxTree,
        session: &ResolutionSession,
    ) -> Option<bool> {
        if !session.scope_step() {
            return None;
        }
        let key = (prepared.source_sha256(), span_for_node(reference));
        if let Some(answer) = self
            .answers
            .lock()
            .expect("builtin shadow memo lock poisoned")
            .get(&key)
            .copied()
        {
            return Some(answer);
        }
        #[cfg(test)]
        self.walks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let answer = builtin_base_is_unshadowed_bounded(reference, prepared.source(), session)?;
        self.answers
            .lock()
            .expect("builtin shadow memo lock poisoned")
            .insert(key, answer);
        Some(answer)
    }
}

fn indexed_builtin_is_unshadowed(
    python: &PythonAnalyzer,
    reference: Node<'_>,
    prepared: &PreparedSyntaxTree,
) -> Option<bool> {
    let cancellation = python.inner.active_query_cancellation();
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, cancellation.as_ref());
    if let Some(memo) = python.active_query_request_memo::<PythonBuiltinShadowRequestMemo>() {
        memo.unshadowed(reference, prepared, &session)
    } else {
        builtin_base_is_unshadowed_bounded(reference, prepared.source(), &session)
    }
}

pub(super) fn builtin_base_is_unshadowed(reference: Node<'_>, source: &str) -> Option<bool> {
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    builtin_base_is_unshadowed_bounded(reference, source, &session)
}

fn builtin_base_is_unshadowed_bounded(
    reference: Node<'_>,
    source: &str,
    session: &ResolutionSession,
) -> Option<bool> {
    let name = reference.utf8_text(source.as_bytes()).ok()?;
    if python_comprehension_binds_name_at(name, reference, source)
        || python_type_parameter_binds_name_at(name, reference, source)
    {
        return Some(false);
    }
    let mut current = reference;
    let mut crossed_callable_body = false;
    while let Some(scope) = current.parent() {
        if !session.scope_step() {
            return None;
        }
        let body = scope.child_by_field_name("body");
        let inside_body = body.is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        });
        if inside_body && matches!(scope.kind(), "function_definition" | "lambda") {
            let inventory =
                python_lexical_scope_inventory_bounded(scope, source, || session.scope_step())?;
            if inventory.name_resolution_at(name, reference) != PythonLexicalNameResolution::Unbound
            {
                return Some(false);
            }
            crossed_callable_body = true;
        } else if (scope.kind() == "module"
            || (!crossed_callable_body && inside_body && scope.kind() == "class_definition"))
            && python_module_or_class_scope_binds_name_bounded(scope, name, source, || {
                session.scope_step()
            })?
        {
            return Some(false);
        }
        current = scope;
    }
    Some(true)
}

/// Whether an external class is `builtins.type` or derives from it.
///
/// Its instances are class objects, so their member surface is whatever class
/// each one is, not what this class declares.
fn external_class_derives_from_type(
    overlay: Option<&SemanticModelOverlay>,
    class: &ClassIdentity,
) -> bool {
    if class.qualified_name() == "builtins.type" {
        return true;
    }
    let ClassIdentity::External { symbol_id, .. } = class else {
        return false;
    };
    external_class_hierarchy(overlay, symbol_id)
        .ancestors
        .iter()
        .any(|ancestor| ancestor.qualified_name() == "builtins.type")
}

/// The modeled ancestry of an external class.
///
/// Without this every external class answered `unresolved_base`, so an
/// `isinstance(value, dict)` guard could never drop `builtins.list` and the
/// excluded classes survived into the narrowed arm. The active model publishes
/// the ancestry and says when it is incomplete, which is exactly the proof
/// `instance_relation` needs.
///
/// The descendant inventory stays unavailable and dynamic attributes stay
/// possible: a dependency's subclasses are not enumerable from a pack, and a
/// modeled surface is not evidence about attribute hooks. Consumers that prove
/// a closed member surface require both, so they are unaffected.
fn external_class_hierarchy(
    overlay: Option<&SemanticModelOverlay>,
    symbol_id: &str,
) -> ClassHierarchy {
    let Some(overlay) = overlay else {
        return ClassHierarchy::unknown();
    };
    let matched = overlay.symbols_with_id(symbol_id);
    let [symbol] = matched.records.as_slice() else {
        return ClassHierarchy::unknown();
    };
    let surface = overlay.owner_surface(symbol);
    let mut ancestors = surface
        .closure
        .iter()
        .filter(|record| record.id != symbol.id)
        .map(|record| ClassIdentity::External {
            qualified_name: record.qualified_name.clone().into_boxed_str(),
            symbol_id: record.id.clone().into_boxed_str(),
        })
        .collect::<Vec<_>>();
    ancestors.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
    ancestors.dedup();
    ClassHierarchy {
        ancestors,
        descendants: None,
        unresolved_base: !surface.proves_absence(),
        dynamic_attributes: true,
    }
}

/// Whether a call's callee reads a value rather than naming a class.
///
/// Calling a class constructs an instance of it; calling anything else runs
/// that value's `__call__` and produces a value this adapter cannot name. A
/// type lookup reports the same class for both shapes, so seeding a
/// constructed class needs the distinction made here. Only a proven value
/// rejects the seed: a callee neither proof decides keeps the lookup's answer.
fn callee_reads_a_value(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    span: SourceSpan,
) -> bool {
    let Some(callee) = node_at_span(prepared, span) else {
        return false;
    };
    match callee.kind() {
        "identifier" => identifier_reads_an_enclosing_local(callee, prepared.source()),
        "attribute" => {
            let python = python_analyzer(workspace);
            let scope = AnalyzerQueryScope::new(python);
            let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
            let support = PythonDefinitionProvider::new(python, &session);
            python_attribute_callee_reads_a_field_bounded(
                &support,
                scope.token(),
                file,
                prepared.source(),
                prepared.tree().root_node(),
                callee,
            ) == Some(true)
        }
        _ => false,
    }
}

/// Whether `reference` reads a name an enclosing callable binds locally.
///
/// A local or a parameter holds a value. A `global` or `nonlocal` declaration
/// names an outer binding, which a class declaration can still own, so neither
/// proves the callee is a value.
fn identifier_reads_an_enclosing_local(reference: Node<'_>, source: &str) -> bool {
    let Ok(name) = reference.utf8_text(source.as_bytes()) else {
        return false;
    };
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let mut current = reference;
    while let Some(scope) = current.parent() {
        if !session.scope_step() {
            return false;
        }
        let encloses = scope.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        });
        if encloses && matches!(scope.kind(), "function_definition" | "lambda") {
            let Some(inventory) =
                python_lexical_scope_inventory_bounded(scope, source, || session.scope_step())
            else {
                return false;
            };
            if inventory.name_resolution_at(name, reference) == PythonLexicalNameResolution::Local {
                return true;
            }
        }
        current = scope;
    }
    false
}

type PythonModuleBindingAnswers = HashMap<Box<str>, Option<PythonDirectScopeBindingKind>>;

/// Successful syntax-only answers retained for one active query. Exact source
/// bytes determine these bindings; workspace/model identities do not. A stopped
/// walk is never cached, and hits still check the current session for stopping.
#[derive(Default)]
struct PythonModuleBindingRequestMemo {
    bindings: Mutex<HashMap<[u8; 32], PythonModuleBindingAnswers>>,
}

fn resolve_module_binding(
    prepared: &PreparedSyntaxTree,
    name: &str,
    session: &ResolutionSession,
) -> Option<Option<PythonDirectScopeBindingKind>> {
    python_unambiguous_module_binding_bounded(
        prepared.tree().root_node(),
        prepared.source(),
        name,
        || session.scope_step(),
    )
}

impl PythonModuleBindingRequestMemo {
    fn binding(
        &self,
        prepared: &PreparedSyntaxTree,
        name: &str,
        session: &ResolutionSession,
    ) -> Option<Option<PythonDirectScopeBindingKind>> {
        if !session.scope_step() {
            return None;
        }
        let source = prepared.source_sha256();
        if let Some(binding) = self
            .bindings
            .lock()
            .expect("module binding memo lock poisoned")
            .get(&source)
            .and_then(|bindings| bindings.get(name))
            .copied()
        {
            return Some(binding);
        }
        let binding = resolve_module_binding(prepared, name, session)?;
        self.bindings
            .lock()
            .expect("module binding memo lock poisoned")
            .entry(source)
            .or_default()
            .insert(name.into(), binding);
        Some(binding)
    }
}

fn module_binding(
    workspace: &WorkspaceAnalyzer,
    prepared: &PreparedSyntaxTree,
    name: &str,
    session: &ResolutionSession,
) -> Option<Option<PythonDirectScopeBindingKind>> {
    if let Some(memo) =
        python_analyzer(workspace).active_query_request_memo::<PythonModuleBindingRequestMemo>()
    {
        memo.binding(prepared, name, session)
    } else {
        resolve_module_binding(prepared, name, session)
    }
}

/// The seed for a bare name that denotes a module-level declaration or import.
///
/// A name that denotes a class evaluates to the class object itself, not to an
/// instance of it, and a name that denotes a function evaluates to the function
/// object. Answering `NotApplicable` contributed no atom at all, so such a
/// value reaching a parameter let that parameter's class set close without it
/// and the absent-member policy proved a member absent on the classes that did
/// survive (issue #3282).
///
/// The class-set domain cannot name a class object's member surface -- its
/// metaclass's members plus the class's own class-level attributes -- which is
/// what `ClassObject` says. A function object's class is likewise not a class
/// this domain names, and no reason states that specifically, so it keeps the
/// unnamed-flow remainder. An import whose target neither the workspace nor the
/// active model names keeps that remainder too: what it binds is unknown, which
/// is not the same as binding nothing.
///
/// The name denotes that declaration only when this module binds it exactly
/// once and nothing between the reference and that binding rebinds it. A name
/// a closer binding holds is a value read rather than a seed site: the flow
/// engine already carries whatever atoms that value has. A `global`
/// declaration does not shadow, it names the module binding, so a read under
/// one is seeded like any other.
fn declaration_reference_seed(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
) -> ClassSeed {
    debug_assert_eq!(
        reference.kind(),
        "identifier",
        "a declaration reference seed reads a bare name"
    );
    let source = prepared.source();
    let Ok(name) = reference.utf8_text(source.as_bytes()) else {
        return ClassSeed::NotApplicable;
    };
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let binding = match module_binding(workspace, prepared, name, &session) {
        None => return ClassSeed::Unknown(UnknownReason::SemanticBudget),
        binding => binding,
    };
    match module_binding_reaches_reference(reference, name, source, &session) {
        None => return ClassSeed::Unknown(UnknownReason::SemanticBudget),
        // A closer binding holds the name, so this reference reads that local,
        // parameter or comprehension target rather than the module's. That is
        // an ordinary value read and not a seed site: whatever produced the
        // closer binding already supplies the value's atoms through dataflow,
        // and an atom added here would only turn an exact row partial.
        Some(false) => return ClassSeed::NotApplicable,
        Some(true) => {}
    }
    if matches!(
        binding,
        Some(Some(PythonDirectScopeBindingKind::Other)) | Some(None)
    ) {
        if !python_reference_in_deferred_scope(reference) {
            return ClassSeed::NotApplicable;
        }
        return module_global_initializer_seed(workspace, file, prepared, name, &session);
    }
    let Some(Some(
        binding @ (PythonDirectScopeBindingKind::ClassDeclaration
        | PythonDirectScopeBindingKind::FunctionDeclaration
        | PythonDirectScopeBindingKind::Import),
    )) = binding
    else {
        return ClassSeed::NotApplicable;
    };
    if binding == PythonDirectScopeBindingKind::FunctionDeclaration {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    if binding == PythonDirectScopeBindingKind::Import
        && import_binds_a_module(workspace, file, name)
    {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    match resolve_class_at_span(workspace, file.clone(), span_for_node(reference), prepared) {
        ClassSeed::Class(_)
        | ClassSeed::Classes(_)
        | ClassSeed::ClassWithOpenBound(_)
        | ClassSeed::ClassesWithOpenBound(_) => ClassSeed::Unknown(UnknownReason::ClassObject),
        ClassSeed::Unknown(reason) => ClassSeed::Unknown(reason),
        ClassSeed::NotApplicable
            if binding == PythonDirectScopeBindingKind::Import
                && imported_external_class(workspace, file, prepared, reference).is_some() =>
        {
            ClassSeed::Unknown(UnknownReason::ClassObject)
        }
        ClassSeed::NotApplicable => ClassSeed::Unknown(UnknownReason::UncertainFlow),
    }
}

fn python_reference_in_deferred_scope(reference: Node<'_>) -> bool {
    let mut current = reference;
    while let Some(scope) = current.parent() {
        if matches!(
            scope.kind(),
            "function_definition" | "lambda" | "class_definition"
        ) && scope.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        }) {
            return true;
        }
        current = scope;
    }
    false
}

fn module_global_initializer_seed(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    name: &str,
    session: &ResolutionSession,
) -> ClassSeed {
    let python = python_analyzer(workspace);
    let Some(facts) = python.module_global_source_facts(file, prepared, &|| session.scope_step())
    else {
        return ClassSeed::Unknown(UnknownReason::SemanticBudget);
    };
    if !facts.module_binds_name(name) {
        return ClassSeed::NotApplicable;
    }
    let Some(range) = facts.initializer_range(name) else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    if !python.cached_module_member_mutation_free(
        &brokk_bifrost_python::declarations::python_module_name(file),
        name,
        || {
            crate::analyzer::semantic::workspace_oracle::python_workspace_module_member_mutation_free(
                workspace.analyzer(),
                &brokk_bifrost_python::declarations::python_module_name(file),
                name,
                200_000,
                &|| session.scope_step(),
            )
        },
    ) {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    let Some(value) = prepared
        .tree()
        .root_node()
        .descendant_for_byte_range(range.start_byte, range.end_byte)
    else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    match resolve_class_at_span(workspace, file.clone(), span_for_node(value), prepared) {
        ClassSeed::Class(class) => ClassSeed::Class(class),
        ClassSeed::Unknown(reason) => ClassSeed::Unknown(reason),
        ClassSeed::NotApplicable
        | ClassSeed::Classes(_)
        | ClassSeed::ClassWithOpenBound(_)
        | ClassSeed::ClassesWithOpenBound(_) => ClassSeed::Unknown(UnknownReason::UncertainFlow),
    }
}

/// Whether the import that binds `name` binds a module object.
///
/// `import os`, `import pkg.child as alias`, and a `from pkg import child`
/// whose target is itself a module all record `ImportKind::Namespace`, and what
/// they bind is a module, which is never a class. Reading the binder's kind
/// settles that without the bounded type lookup and overlay read a class
/// reference needs. The saving is the point: `logging.getLogger` and
/// `os.path.join` put a namespace-bound base on a large share of the lines in a
/// real repository, and the binder is memoized per file while each lookup is
/// not.
fn import_binds_a_module(workspace: &WorkspaceAnalyzer, file: &ProjectFile, name: &str) -> bool {
    let python = python_analyzer(workspace);
    let scope = AnalyzerQueryScope::new(python);
    python
        .import_binder_of(scope.token(), file)
        .bindings
        .get(name)
        .is_some_and(|binding| binding.kind == ImportKind::Namespace)
}

/// The modeled external class an import-bound name denotes.
///
/// A dependency's class has no workspace declaration, so the type lookup in
/// [`resolve_class_at_span`] answers nothing for `JSONDecoder` in `from json
/// import JSONDecoder`. The import binder is what names the module and the
/// member the statement binds, and the active model is what says whether that
/// pair is a class; this is the route the adapter already uses for external
/// callees and bases.
fn imported_external_class(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
) -> Option<ClassIdentity> {
    let (module, member) =
        import_bound_external_symbol(python_analyzer(workspace), file, prepared, reference)?;
    external_class_identity(
        workspace.analyzer().semantic_model_overlay().as_deref(),
        Language::Python,
        &format!("{module}.{member}"),
        None,
        &mut ExternalClassCache::default(),
    )
}

/// Class candidates for a direct constructor call in a `with` manager.
///
/// Keep the source-resolution paths shared with the type-flow adapter: imports
/// first resolve through the import binder and active semantic-model overlay,
/// while workspace classes use the definition provider's scope and shadowing
/// rules. An imported external callable contributes its declared return class
/// or overload return set.
pub(crate) fn python_with_manager_call_classes(
    python: &PythonAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    callee: Node<'_>,
    overlay: Option<&SemanticModelOverlay>,
) -> Option<Vec<ClassIdentity>> {
    match python_module_external_class_alias_value(prepared, callee) {
        PythonModuleExternalClassAlias::Value(value) => {
            return imported_external_class_for_python(python, file, prepared, value, overlay)
                .map(|class| vec![class]);
        }
        PythonModuleExternalClassAlias::Unproved => return None,
        PythonModuleExternalClassAlias::NotFound => {}
    }
    if let Some(class) =
        imported_external_class_callee_for_python(python, file, prepared, callee, overlay)
    {
        return Some(vec![class]);
    }
    if let Some(classes) =
        imported_external_function_return_classes(python, file, prepared, callee, overlay)
    {
        return Some(classes);
    }

    let name = python_static_attribute_path(callee)?
        .into_iter()
        .map(|segment| segment.utf8_text(prepared.source().as_bytes()).ok())
        .collect::<Option<Vec<_>>>()?
        .join(".");
    python_workspace_class_candidate_named_for_python(python, file, prepared, callee, &name)
        .map(|class| vec![class])
}

enum PythonModuleExternalClassAlias<'tree> {
    NotFound,
    Unproved,
    Value(Node<'tree>),
}

/// Find a unique, direct module assignment such as
/// `threading.Lock = _thread.LockType`. The imported class on the right is the
/// constructor target, even when the external model does not name the assigned
/// attribute as an alias. Any other write to that attribute leaves it unknown.
fn python_module_external_class_alias_value<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    callee: Node<'tree>,
) -> PythonModuleExternalClassAlias<'tree> {
    let source = prepared.source();
    let Some(wanted_path) = python_static_attribute_path(callee).and_then(|path| {
        path.into_iter()
            .map(|segment| segment.utf8_text(source.as_bytes()).ok())
            .collect::<Option<Vec<_>>>()
    }) else {
        return PythonModuleExternalClassAlias::NotFound;
    };
    if wanted_path.len() < 2 {
        return PythonModuleExternalClassAlias::NotFound;
    }
    let root = prepared.tree().root_node();
    let mut value = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let target = match node.kind() {
            "assignment" | "augmented_assignment" | "for_statement" => {
                node.child_by_field_name("left")
            }
            "delete_statement" => node
                .child_by_field_name("left")
                .or_else(|| node.named_child(0)),
            "with_item" => node
                .child_by_field_name("value")
                .and_then(|value| (value.kind() == "as_pattern").then_some(value))
                .and_then(|pattern| pattern.child_by_field_name("alias")),
            _ => None,
        };
        if target
            .is_some_and(|target| python_target_writes_attribute_path(target, &wanted_path, source))
        {
            let direct_alias = node.kind() == "assignment"
                && target.is_some_and(|target| {
                    target.kind() == "attribute"
                        && python_static_attribute_path(target).is_some_and(|path| {
                            path.into_iter()
                                .map(|segment| segment.utf8_text(source.as_bytes()).ok())
                                .collect::<Option<Vec<_>>>()
                                .as_deref()
                                == Some(wanted_path.as_slice())
                        })
                })
                && node
                    .parent()
                    .is_some_and(|statement| statement.kind() == "expression_statement")
                && node.parent().and_then(|statement| statement.parent()) == Some(root);
            if !direct_alias || value.is_some() {
                return PythonModuleExternalClassAlias::Unproved;
            }
            let Some(initializer) = node.child_by_field_name("right") else {
                return PythonModuleExternalClassAlias::Unproved;
            };
            value = Some(initializer);
        }
        stack.extend(named_children(node));
    }
    value.map_or(
        PythonModuleExternalClassAlias::NotFound,
        PythonModuleExternalClassAlias::Value,
    )
}

fn python_target_writes_attribute_path(
    target: Node<'_>,
    wanted_path: &[&str],
    source: &str,
) -> bool {
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if node.kind() == "attribute"
            && python_static_attribute_path(node).is_some_and(|path| {
                path.into_iter()
                    .map(|segment| segment.utf8_text(source.as_bytes()).ok())
                    .collect::<Option<Vec<_>>>()
                    .as_deref()
                    == Some(wanted_path)
            })
        {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

pub(crate) fn python_with_manager_literal_class(
    prepared: &PreparedSyntaxTree,
    value: Node<'_>,
    overlay: Option<&SemanticModelOverlay>,
) -> Option<ClassIdentity> {
    let name = match value.kind() {
        "integer" => "builtins.int",
        "float" => "builtins.float",
        "string" | "concatenated_string" => python_string_literal_class(value, prepared),
        "true" | "false" => "builtins.bool",
        "none" => "types.NoneType",
        _ => return None,
    };
    external_class_identity(
        overlay,
        Language::Python,
        name,
        None,
        &mut ExternalClassCache::default(),
    )
}

/// Prove whether the effective `__exit__` of one exact class returns only
/// `None`. Workspace declarations use the shared Python C3 hierarchy provider;
/// external declarations use the semantic-model overlay's C3 lookup.
pub(crate) fn python_with_exit_returns_none(
    python: &PythonAnalyzer,
    class: &ClassIdentity,
    overlay: Option<&SemanticModelOverlay>,
) -> bool {
    match class {
        ClassIdentity::Workspace(owner) => {
            let Some(provider) = python.python_class_hierarchy_provider_for(owner) else {
                return false;
            };
            let members = provider.mro_members(owner, None);
            if members.hierarchy.outcome
                != crate::analyzer::usages::python_class_hierarchy::PythonHierarchyOutcome::Complete
            {
                return false;
            }
            let Some(member) = members
                .members
                .into_iter()
                .find(|member| member.name == "__exit__")
            else {
                return false;
            };
            workspace_exit_body_returns_none(python, &member.member)
        }
        ClassIdentity::External { symbol_id, .. } => {
            let Some(overlay) = overlay else {
                return false;
            };
            let Some(exit) = python_external_member_declaration(overlay, symbol_id, "__exit__")
            else {
                return false;
            };
            exit.structured_signature()
                .and_then(|signature| signature.returns.as_ref())
                .is_some_and(type_ref_is_none)
        }
    }
}

fn type_ref_is_none(reference: &TypeRef) -> bool {
    matches!(
        reference,
        TypeRef::Named {
            name,
            arguments,
            nullable,
        } if arguments.is_empty()
            && ((*name == "builtins.NoneType" && !*nullable)
                || (*name == "None" && *nullable))
    )
}

fn workspace_exit_body_returns_none(python: &PythonAnalyzer, method: &CodeUnit) -> bool {
    let Some(prepared) = current_indexed_prepared(python, method.source()) else {
        return false;
    };
    let Some(function) = python_function_node_for_unit(python, &prepared, method) else {
        return false;
    };
    if function.parent().is_some_and(|parent| {
        parent.kind() == "decorated_definition"
            && (0..parent.named_child_count())
                .any(|index| parent.named_child(index) == Some(function))
    }) {
        // A decorated `__exit__` may wrap or replace its return value.
        return false;
    }
    python_exit_body_has_no_value_return_or_yield(function, prepared.source())
}

fn python_exit_body_has_no_value_return_or_yield(function: Node<'_>, source: &str) -> bool {
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    if function
        .child_by_field_name("return_type")
        .is_some_and(|annotation| {
            !matches!(annotation.kind(), "none")
                && annotation.utf8_text(source.as_bytes()).ok() != Some("None")
        })
    {
        return false;
    }
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body
            && matches!(
                node.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        match node.kind() {
            "yield" => return false,
            "return_statement" => {
                let mut cursor = node.walk();
                if node
                    .named_children(&mut cursor)
                    .any(|value| value.kind() != "none")
                {
                    return false;
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    true
}

fn python_function_node_for_unit<'tree>(
    python: &PythonAnalyzer,
    prepared: &'tree PreparedSyntaxTree,
    unit: &CodeUnit,
) -> Option<Node<'tree>> {
    python.ranges(unit).into_iter().find_map(|range| {
        let node = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        let function = match node.kind() {
            "function_definition" => node,
            "decorated_definition" => {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "function_definition")?
            }
            _ => node
                .parent()
                .filter(|parent| parent.kind() == "function_definition")?,
        };
        (function
            .child_by_field_name("name")?
            .utf8_text(prepared.source().as_bytes())
            .ok()?
            == "__exit__")
            .then_some(function)
    })
}

/// Expand a callee source node to its complete dotted attribute path before
/// asking the import binder for an external class. Semantic call lowering can
/// anchor a module-qualified constructor at either the module identifier or
/// the final member, while the binder needs the whole `module.Class` node.
fn imported_external_class_callee(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    callee: Node<'_>,
) -> Option<ClassIdentity> {
    let python = python_analyzer(workspace);
    imported_external_class_callee_for_python(
        python,
        file,
        prepared,
        callee,
        workspace.analyzer().semantic_model_overlay().as_deref(),
    )
}

/// Whether the module-scope binding of `name` is what `reference` reads.
///
/// A closer binding defeats the proof: a local, a parameter, a `nonlocal` that
/// names an enclosing callable's binding, a comprehension target, a type
/// parameter, or a class body that binds the name -- the last only while no
/// callable body has been crossed, because a class scope is invisible to a
/// callable nested inside it.
///
/// A `global` declaration is the opposite: it says the module binding is
/// exactly what this reference reads, whatever any enclosing scope binds, so it
/// proves the question outright.
fn module_binding_reaches_reference(
    reference: Node<'_>,
    name: &str,
    source: &str,
    session: &ResolutionSession,
) -> Option<bool> {
    if python_comprehension_binds_name_at(name, reference, source)
        || python_type_parameter_binds_name_at(name, reference, source)
    {
        return Some(false);
    }
    let mut current = reference;
    let mut crossed_callable_body = false;
    while let Some(scope) = current.parent() {
        if !session.scope_step() {
            return None;
        }
        let inside_body = scope.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        });
        if inside_body && matches!(scope.kind(), "function_definition" | "lambda") {
            let inventory =
                python_lexical_scope_inventory_bounded(scope, source, || session.scope_step())?;
            match inventory.name_resolution_at(name, reference) {
                PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal => {
                    return Some(false);
                }
                PythonLexicalNameResolution::Global => return Some(true),
                PythonLexicalNameResolution::Unbound => {}
            }
            crossed_callable_body = true;
        } else if inside_body
            && !crossed_callable_body
            && scope.kind() == "class_definition"
            && python_module_or_class_scope_binds_name_bounded(scope, name, source, || {
                session.scope_step()
            })?
        {
            return Some(false);
        }
        current = scope;
    }
    Some(true)
}

/// The builtin class a Python string literal produces.
///
/// The grammar gives `"text"` and `b"text"` the same `string` kind and carries
/// the prefix on the literal's `string_start` token, so the opening token is
/// the only structure that separates `bytes` from `str`. A concatenation takes
/// its class from its first literal, which the grammar requires every part to
/// agree with.
fn python_string_literal_class(node: Node<'_>, prepared: &PreparedSyntaxTree) -> &'static str {
    let literal = if node.kind() == "concatenated_string" {
        let mut cursor = node.walk();
        match node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "string")
        {
            Some(first) => first,
            None => return "builtins.str",
        }
    } else {
        node
    };
    let mut cursor = literal.walk();
    let Some(start) = literal
        .named_children(&mut cursor)
        .find(|child| child.kind() == "string_start")
    else {
        return "builtins.str";
    };
    let Ok(prefix) = start.utf8_text(prepared.source().as_bytes()) else {
        return "builtins.str";
    };
    if prefix.contains('b') || prefix.contains('B') {
        "builtins.bytes"
    } else {
        "builtins.str"
    }
}

/// Python's implicit builtin namespace is a lexical binding source, even
/// when no workspace declaration exists for the referenced class.
fn builtin_class_reference(
    python: &PythonAnalyzer,
    overlay: Option<&SemanticModelOverlay>,
    reference: Node<'_>,
    prepared: &PreparedSyntaxTree,
    cache: &mut ExternalClassCache,
) -> Option<ClassSeed> {
    let source = prepared.source();
    if reference.kind() != "identifier" {
        return None;
    }
    let name = reference.utf8_text(source.as_bytes()).ok()?;
    if !is_python_builtin_or_constant(name) {
        return None;
    }
    match indexed_builtin_is_unshadowed(python, reference, prepared) {
        Some(false) => None,
        None => Some(ClassSeed::Unknown(UnknownReason::SemanticBudget)),
        Some(true) => {
            let qualified_name = format!("builtins.{name}");
            Some(
                match external_class_identity(
                    overlay,
                    Language::Python,
                    &qualified_name,
                    None,
                    cache,
                ) {
                    Some(identity) if identity.qualified_name() == qualified_name => {
                        ClassSeed::Class(identity)
                    }
                    Some(_) | None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
                },
            )
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PythonClassLookupKey {
    file: ProjectFile,
    source: [u8; 32],
    span: SourceSpan,
    language_content: crate::analyzer::semantic::StableDigest,
    project_generation: u64,
    semantic_overlay: Option<Box<str>>,
}

#[derive(Default)]
struct PythonClassLookupRequestMemo {
    answers: Mutex<HashMap<PythonClassLookupKey, (ClassSeed, Arc<crate::analyzer::ReadLedger>)>>,
    #[cfg(test)]
    lookups: std::sync::atomic::AtomicUsize,
}

/// Resolve the expression at `span` in `file` and interpret it as a class seed.
fn resolve_class_at_span(
    workspace: &WorkspaceAnalyzer,
    file: ProjectFile,
    span: SourceSpan,
    prepared: &PreparedSyntaxTree,
) -> ClassSeed {
    let indexed_source = prepared.source();
    if !workspace
        .analyzer()
        .indexed_source_matches(&file, indexed_source)
    {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    let python = python_analyzer(workspace);
    if python
        .inner
        .active_query_cancellation()
        .is_some_and(|token| token.is_cancelled())
    {
        return ClassSeed::Unknown(UnknownReason::SemanticBudget);
    }
    let Some(memo) = python.active_query_request_memo::<PythonClassLookupRequestMemo>() else {
        return resolve_indexed_class_at_span(workspace, file, span, prepared);
    };
    let key = PythonClassLookupKey {
        file: file.clone(),
        source: prepared.source_sha256(),
        span,
        language_content: python.inner.language_content_identity(),
        project_generation: workspace.analyzer().project().analysis_generation(),
        semantic_overlay: workspace
            .analyzer()
            .semantic_model_overlay()
            .map(|overlay| Box::from(overlay.active_model_set_hash())),
    };
    let cached = memo
        .answers
        .lock()
        .expect("class lookup memo lock poisoned")
        .get(&key)
        .cloned();
    if let Some((answer, reads)) = cached {
        crate::analyzer::replay_query_reads(workspace.analyzer(), &reads);
        return answer;
    }
    #[cfg(test)]
    memo.lookups
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (answer, reads) = crate::analyzer::capture_query_reads(workspace.analyzer(), || {
        resolve_indexed_class_at_span(workspace, file, span, prepared)
    });
    // A stopped lookup is not a completed answer. Later work must retain the
    // opportunity to resolve it, rather than inherit a prior exhausted walk.
    if answer != ClassSeed::Unknown(UnknownReason::SemanticBudget) {
        memo.answers
            .lock()
            .expect("class lookup memo lock poisoned")
            .insert(key, (answer.clone(), reads));
    }
    answer
}

fn resolve_indexed_class_at_span(
    workspace: &WorkspaceAnalyzer,
    file: ProjectFile,
    span: SourceSpan,
    prepared: &PreparedSyntaxTree,
) -> ClassSeed {
    let indexed_source = prepared.source();
    if let Some(reference) = node_at_span(prepared, span)
        && let Some(seed) = builtin_class_reference(
            python_analyzer(workspace),
            workspace.analyzer().semantic_model_overlay().as_deref(),
            reference,
            prepared,
            &mut ExternalClassCache::default(),
        )
    {
        return seed;
    }
    let range = analyzer_range_for_span(span);
    let Some(text) = indexed_source.get(range.start_byte..range.end_byte) else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    let outcome = resolve_type_at_reference_site_with_budget(
        workspace.analyzer(),
        &file,
        indexed_source,
        Some(prepared.tree()),
        ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: text.to_string(),
            focus_start_byte: range.start_byte,
            focus_end_byte: range.end_byte,
            range,
        },
        INTERACTIVE_TYPE_LOOKUP_BUDGET,
    );
    if !workspace
        .analyzer()
        .indexed_source_matches(&file, indexed_source)
    {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    match outcome.status {
        TypeLookupStatus::Unavailable => return ClassSeed::Unknown(UnknownReason::UncertainFlow),
        TypeLookupStatus::Incomplete | TypeLookupStatus::Cancelled => {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        }
        // The interactive receiver-resolution budget bounds analyzer-side
        // semantic work (scope and definition walks), not the dataflow
        // solver, so its exhaustion is a semantic-budget fact.
        TypeLookupStatus::ExceededBudget(_) => {
            return ClassSeed::Unknown(UnknownReason::SemanticBudget);
        }
        TypeLookupStatus::Ambiguous => {
            return ClassSeed::Unknown(UnknownReason::AmbiguousCallee);
        }
        TypeLookupStatus::Resolved
        | TypeLookupStatus::NoType
        | TypeLookupStatus::UnsupportedLanguage
        | TypeLookupStatus::InvalidLocation
        | TypeLookupStatus::NotFound => {}
    }
    class_seed_from_lookup_types(
        workspace.analyzer().semantic_model_overlay().as_deref(),
        Language::Python,
        &outcome.types,
    )
}

fn python_workspace_class_candidate(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
) -> Option<ClassIdentity> {
    let name = python_simple_type_identifier(reference, prepared.source())?;
    python_workspace_class_candidate_named(workspace, file, prepared, reference, &name)
}

fn python_workspace_class_candidate_named(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
    name: &str,
) -> Option<ClassIdentity> {
    let python = python_analyzer(workspace);
    python_workspace_class_candidate_named_for_python(python, file, prepared, reference, name)
}

fn python_workspace_class_candidate_named_for_python(
    python: &PythonAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
    name: &str,
) -> Option<ClassIdentity> {
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let scope = AnalyzerQueryScope::new(python);
    let support = PythonDefinitionProvider::new(python, &session);
    python_class_candidate_for_name(
        &support,
        scope.token(),
        file,
        prepared.source(),
        reference,
        name,
    )
    .or_else(|| {
        python_type_checking_imported_class_candidate(
            &support,
            scope.token(),
            file,
            prepared.source(),
            reference,
            name,
        )
    })
    .map(ClassIdentity::Workspace)
}

fn python_forward_module_class_candidate(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    name: &str,
) -> Option<ClassIdentity> {
    let python = python_analyzer(workspace);
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let support = PythonDefinitionProvider::new(python, &session);
    let mut candidates = support
        .file_identifier(file, name)
        .into_iter()
        .filter(CodeUnit::is_class);
    let candidate = candidates.next()?;
    if candidates.next().is_some()
        || python_unambiguous_module_class_binding_bounded(
            prepared.tree().root_node(),
            prepared.source(),
            name,
            || session.scope_step(),
        ) != Some(true)
    {
        return None;
    }
    Some(ClassIdentity::Workspace(candidate))
}

fn python_future_annotations_enabled(prepared: &PreparedSyntaxTree) -> bool {
    let root = prepared.tree().root_node();
    let mut cursor = root.walk();
    for statement in root
        .named_children(&mut cursor)
        .filter(|node| node.kind() == "future_import_statement")
    {
        let mut pending = vec![statement];
        while let Some(node) = pending.pop() {
            if node.named_child_count() == 0
                && node.utf8_text(prepared.source().as_bytes()).ok() == Some("annotations")
            {
                return true;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
    }
    false
}

impl PythonTypeFlowAdapter {
    fn guard_value_node<'tree>(
        &self,
        procedure: &ProcedureHandle,
        value: ValueId,
        prepared: &'tree PreparedSyntaxTree,
    ) -> Option<Node<'tree>> {
        let value = procedure.semantics().value(value)?;
        let mapping = procedure.semantics().source_mapping(value.source)?;
        if mapping.kind != SourceMappingKind::Exact {
            return None;
        }
        node_at_span(prepared, mapping.locator.anchor().span())
    }

    fn guard_classes(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: ValueId,
    ) -> Result<Vec<ClassIdentity>, UnknownReason> {
        let semantic_value = procedure
            .semantics()
            .value(value)
            .expect("a guard class value is retained");
        let mapping = procedure
            .semantics()
            .source_mapping(semantic_value.source)
            .expect("a guard class value has a source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return Err(UnknownReason::UncertainFlow);
        }
        let file =
            file_for_locator(workspace, &mapping.locator).ok_or(UnknownReason::UncertainFlow)?;
        let prepared = prepared_for_procedure(workspace, procedure, &file)?;
        let node = self
            .guard_value_node(procedure, value, &prepared)
            .ok_or(UnknownReason::UncertainFlow)?;
        let unmodeled = |class: Node<'_>| UnknownReason::UnmodeledGuard {
            class: class
                .utf8_text(prepared.source().as_bytes())
                .expect("a class expression is within its prepared source")
                .into(),
        };
        // A tuple and a PEP 604 `|` union spell the same set. A shape that is
        // neither is a guard this adapter does not model, which is what
        // `unmodeled` names.
        let mut nodes = Vec::new();
        if !collect_guard_class_nodes(node, &mut nodes) {
            return Err(unmodeled(node));
        }
        if nodes.is_empty() {
            return Err(unmodeled(node));
        }
        let overlay = workspace.analyzer().semantic_model_overlay();
        let mut cache = ExternalClassCache::default();
        nodes
            .into_iter()
            .map(|class| {
                guard_class_identity(
                    workspace,
                    &file,
                    &prepared,
                    overlay.as_deref(),
                    &mut cache,
                    class,
                )
            })
            .collect()
    }

    /// The class a predicate's target expression names, with the same proof an
    /// `isinstance` class needs. A target that names no such class is an error
    /// here, which the caller reports as an unmodeled target.
    pub(super) fn guard_class_expression(
        &self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        class: Node<'_>,
    ) -> Result<ClassIdentity, UnknownReason> {
        let overlay = workspace.analyzer().semantic_model_overlay();
        guard_class_identity(
            workspace,
            file,
            prepared,
            overlay.as_deref(),
            &mut ExternalClassCache::default(),
            class,
        )
    }

    pub(super) fn guard_classes_have_supported_instance_checks(
        &self,
        workspace: &WorkspaceAnalyzer,
        classes: &[ClassIdentity],
        overlay: Option<&SemanticModelOverlay>,
    ) -> bool {
        let python = python_analyzer(workspace);
        for class in classes {
            match class {
                ClassIdentity::External { .. } => {
                    if overlay
                        .is_none_or(|overlay| !complete_builtin_external_class(overlay, class))
                    {
                        return false;
                    }
                }
                ClassIdentity::Workspace(_) => {
                    let hierarchy = self.class_hierarchy(workspace, class);
                    if hierarchy.unresolved_base {
                        return false;
                    }
                    for ancestor in std::iter::once(class).chain(hierarchy.ancestors.iter()) {
                        match ancestor {
                            ClassIdentity::Workspace(owner) => {
                                if !workspace_class_uses_ordinary_metaclass(
                                    workspace, python, owner, overlay,
                                ) {
                                    return false;
                                }
                            }
                            ClassIdentity::External { .. } => {
                                if overlay.is_none_or(|overlay| {
                                    !complete_builtin_external_class(overlay, ancestor)
                                }) {
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
        }
        true
    }

    pub(super) fn instance_relation(
        &self,
        workspace: &WorkspaceAnalyzer,
        atom: &ClassIdentity,
        expected: &[ClassIdentity],
    ) -> Option<bool> {
        let hierarchy = self.class_hierarchy(workspace, atom);
        if expected
            .iter()
            .any(|class| class == atom || hierarchy.ancestors.contains(class))
        {
            return Some(true);
        }
        (!hierarchy.unresolved_base).then_some(false)
    }

    /// Whether a declared class states the runtime class of every value that
    /// satisfies it.
    ///
    /// Only a workspace class with an enumerated and empty descendant
    /// inventory does. An external class has no descendant inventory here, so
    /// a workspace subclass of it is not excluded.
    fn declared_class_is_closed(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
    ) -> bool {
        if !matches!(class, ClassIdentity::Workspace(_)) {
            return false;
        }
        let hierarchy = self.class_hierarchy(workspace, class);
        hierarchy.descendants.as_deref() == Some(&[])
            && !hierarchy.unresolved_base
            && !hierarchy.dynamic_attributes
    }

    fn annotation_class_seed(
        &self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        context: Node<'_>,
        annotation: Node<'_>,
    ) -> ClassSeed {
        let Some(annotation) = python_annotation_expression(annotation) else {
            return ClassSeed::NotApplicable;
        };
        let quoted_annotation = annotation;
        let deferred_annotation = if annotation.kind() == "string" {
            python_deferred_annotation_tree(annotation, prepared.source(), None)
        } else {
            None
        };
        let is_deferred_annotation = deferred_annotation.is_some();
        if annotation.kind() == "string" && deferred_annotation.is_none() {
            return ClassSeed::NotApplicable;
        }
        let deferred_content = deferred_annotation.as_ref().and_then(|_| {
            let mut cursor = quoted_annotation.walk();
            quoted_annotation
                .named_children(&mut cursor)
                .find(|content| content.kind() == "string_content")
        });
        let annotation = if let Some(tree) = deferred_annotation.as_ref() {
            let mut expression = tree.root_node();
            while !matches!(
                expression.kind(),
                "identifier" | "attribute" | "generic_type" | "subscript"
            ) {
                if expression.named_child_count() != 1 {
                    return ClassSeed::NotApplicable;
                }
                let Some(child) = expression.named_child(0) else {
                    return ClassSeed::NotApplicable;
                };
                expression = child;
            }
            expression
        } else {
            annotation
        };
        if !is_deferred_annotation
            && python_annotation_contains_any(workspace, file, prepared, annotation)
        {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        }
        let forward_reference_site = deferred_content
            .or_else(|| python_future_annotations_enabled(prepared).then_some(annotation));
        let forward_class_name = python_simple_type_identifier(annotation, prepared.source());
        if let Some(seed) =
            python_type_variable_bound_seed(workspace, file, prepared, context, annotation)
        {
            return seed;
        }
        if let Some(seed) =
            python_type_object_argument_bound_seed(workspace, file, prepared, context, annotation)
        {
            return seed;
        }
        if !matches!(
            annotation.kind(),
            "identifier" | "attribute" | "member_type" | "string_content"
        ) {
            return ClassSeed::NotApplicable;
        }
        let deferred_workspace_class = match (forward_reference_site, forward_class_name) {
            (Some(site), Some(name)) => {
                python_workspace_class_candidate_named(workspace, file, prepared, site, &name)
                    .or_else(|| {
                        python_forward_module_class_candidate(workspace, file, prepared, &name)
                    })
                    .and_then(|class| match class {
                        ClassIdentity::Workspace(unit) => Some(unit),
                        ClassIdentity::External { .. } => None,
                    })
            }
            _ => None,
        };
        let resolved = deferred_workspace_class
            .map(|unit| ClassSeed::Class(ClassIdentity::Workspace(unit)))
            .unwrap_or_else(|| {
                resolve_class_at_span(workspace, file.clone(), span_for_node(annotation), prepared)
            });
        match python_dynamic_any_seed(resolved) {
            ClassSeed::Class(class) if class.qualified_name() == "builtins.object" => {
                ClassSeed::ClassWithOpenBound(class)
            }
            ClassSeed::Class(class)
                if is_builtin_value_class(&class)
                    || self.declared_class_is_closed(workspace, &class) =>
            {
                ClassSeed::Class(class)
            }
            ClassSeed::Class(class) => ClassSeed::ClassWithOpenBound(class),
            seed => seed,
        }
    }

    fn iteration_element_class_seed(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        target: Node<'_>,
    ) -> ClassSeed {
        let Some(loop_statement) = target
            .parent()
            .filter(|node| node.kind() == "for_statement")
        else {
            return ClassSeed::NotApplicable;
        };
        if loop_statement.child_by_field_name("left") != Some(target) {
            return ClassSeed::NotApplicable;
        }
        let semantics = procedure.semantics();
        let Some(callable) = node_at_span(prepared, semantics.locator().anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        let Some(receiver_name) = python_first_parameter_name(callable, prepared.source()) else {
            return ClassSeed::NotApplicable;
        };
        let Some(iterable) = loop_statement.child_by_field_name("right") else {
            return ClassSeed::NotApplicable;
        };
        if iterable.kind() != "identifier"
            || iterable.utf8_text(prepared.source().as_bytes()).ok() != Some(receiver_name.as_str())
        {
            return ClassSeed::NotApplicable;
        }
        let Some(ClassIdentity::Workspace(owner)) = self.enclosing_class(workspace, procedure)
        else {
            return ClassSeed::NotApplicable;
        };
        let Some(class) = class_node_for_unit(python_analyzer(workspace), prepared, &owner) else {
            return ClassSeed::NotApplicable;
        };
        let Some(body) = class.child_by_field_name("body") else {
            return ClassSeed::NotApplicable;
        };
        let mut cursor = body.walk();
        let iterator = body.named_children(&mut cursor).find_map(|member| {
            let definition = if member.kind() == "decorated_definition" {
                let mut cursor = member.walk();
                member
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "function_definition")?
            } else {
                member
            };
            (definition.kind() == "function_definition"
                && definition
                    .child_by_field_name("name")
                    .and_then(|name| name.utf8_text(prepared.source().as_bytes()).ok())
                    == Some("__iter__"))
            .then_some(definition)
        });
        let Some(return_type) =
            iterator.and_then(|iterator| iterator.child_by_field_name("return_type"))
        else {
            return ClassSeed::NotApplicable;
        };
        let Some((iterator_type, _)) = python_first_generic_type_argument(return_type) else {
            return ClassSeed::NotApplicable;
        };
        let Some((module, member)) =
            import_bound_external_symbol(python_analyzer(workspace), file, prepared, iterator_type)
        else {
            return ClassSeed::NotApplicable;
        };
        if !matches!(
            (module.as_str(), member.as_str()),
            ("collections.abc", "Iterator") | ("typing", "Iterator")
        ) {
            return ClassSeed::NotApplicable;
        }
        let Some((_, element_type)) = python_first_generic_type_argument(return_type) else {
            return ClassSeed::NotApplicable;
        };
        self.annotation_class_seed(workspace, file, prepared, class, element_type)
    }

    fn workspace_member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        python: &PythonAnalyzer,
        unit: &CodeUnit,
        member: &str,
    ) -> MemberLookup {
        let ancestors = python.get_ancestors(unit);
        // A dynamic-attribute hook anywhere on the hierarchy means no static
        // member list is complete. A declared `__new__` says the same about
        // instance creation: it chooses what to return and may install
        // attributes on it, as caikit's `ApiFieldNames` singleton does with
        // `cls._instance.service_pb2_modules = []`.
        for owner in std::iter::once(unit).chain(ancestors.iter()) {
            if python.direct_children(owner).iter().any(|child| {
                matches!(
                    child.terminal_name(),
                    "__getattr__" | "__getattribute__" | "__new__"
                )
            }) {
                return MemberLookup::Unknown(UnknownReason::DynamicAttributes);
            }
        }
        // A raw base the hierarchy resolver did not enter must be answered by
        // the pack overlay or the member list is not known to be complete.
        let overlay = workspace.analyzer().semantic_model_overlay();
        let mut cache = ExternalClassCache::default();
        let mut external_bases = Vec::new();
        for owner in std::iter::once(unit).chain(ancestors.iter()) {
            let direct = python.get_direct_ancestors(owner);
            for raw in python.inner.raw_supertypes_of(owner) {
                let resolved = direct.iter().any(|ancestor| {
                    ancestor.terminal_name() == raw || ancestor.fq_name_str() == raw
                });
                if resolved {
                    continue;
                }
                match exact_external_base(python, owner, overlay.as_deref(), &raw, &mut cache) {
                    Some(identity) if !external_bases.contains(&identity) => {
                        external_bases.push(identity);
                    }
                    Some(_) => {}
                    None if python_typing_marker_base(python, owner, &raw) => {}
                    None => return MemberLookup::Unknown(UnknownReason::UnresolvedBase),
                }
            }
        }
        for owner in std::iter::once(unit).chain(ancestors.iter()) {
            if let Some(declaration) = python
                .direct_children(owner)
                .into_iter()
                .find(|child| child.terminal_name() == member)
            {
                return MemberLookup::Present(MemberLookupHit::new(
                    MemberDeclaration::Workspace(declaration),
                    CandidateCoverage::Exhaustive,
                ));
            }
        }
        for base in &external_bases {
            let ClassIdentity::External { symbol_id, .. } = base else {
                unreachable!("external_bases holds only external identities")
            };
            let Some(overlay) = overlay.as_deref() else {
                unreachable!("an external base resolved only through the overlay")
            };
            match external_member_lookup(overlay, symbol_id, member) {
                present @ MemberLookup::Present(_) => return present,
                MemberLookup::Unknown(reason) => return MemberLookup::Unknown(reason),
                MemberLookup::Absent => {}
                MemberLookup::DeclarationAbsent => {
                    unreachable!("external model lookup is declaration-complete or unknown")
                }
            }
        }
        // Every Python class inherits `object` whether or not it names a base,
        // so `__class__`, `__dict__`, `__hash__` and the rest of that surface
        // are declared by no workspace or named base and are still present.
        // `object` declares only dunders, which is a fact about the language
        // rather than about any model, so a plain name needs no lookup.
        if is_python_dunder(member) {
            let Some(overlay) = overlay.as_deref() else {
                return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
            };
            match object_member_lookup(overlay, &mut cache, member) {
                present @ MemberLookup::Present(_) => return present,
                MemberLookup::Unknown(reason) => return MemberLookup::Unknown(reason),
                MemberLookup::Absent | MemberLookup::DeclarationAbsent => {}
            }
        }
        // A class that installs members on its own instances at run time has no
        // bounded member list. `dynamic_field_writes` reports the same writes
        // per procedure for field slots; a member proof needs them per class.
        for owner in std::iter::once(unit).chain(ancestors.iter()) {
            if class_installs_dynamic_members(python, owner) {
                return MemberLookup::Unknown(UnknownReason::DynamicAttributes);
            }
        }
        // A class deriving from `type` has class objects for instances, and a
        // class object's members are the attributes of whatever class it is.
        // The metaclass declaration bounds only what the metaclass itself
        // adds, so `cls.protocol` inside a metaclass method is not absent.
        if external_bases
            .iter()
            .any(|base| external_class_derives_from_type(overlay.as_deref(), base))
        {
            return MemberLookup::Unknown(UnknownReason::ClassCreation);
        }
        // Class creation can install members the declaration does not show: a
        // metaclass writes them in its own `__init__`, another class-header
        // keyword configures the same machinery, and a class decorator can
        // return a different class outright. A class this proof does not cover
        // is not bounded by its declared body and its ancestors.
        for owner in std::iter::once(unit).chain(ancestors.iter()) {
            if !workspace_class_uses_ordinary_metaclass(
                workspace,
                python,
                owner,
                overlay.as_deref(),
            ) {
                return MemberLookup::Unknown(UnknownReason::ClassCreation);
            }
        }
        MemberLookup::DeclarationAbsent
    }
}

/// Whether a member name is one Python reserves for the language.
///
/// `object` declares only these, so a name outside the form cannot come from
/// the inherited object surface no matter what any model says.
fn is_python_dunder(member: &str) -> bool {
    member.len() > 4 && member.starts_with("__") && member.ends_with("__")
}

/// The `builtins.object` member surface, which every Python class inherits.
fn object_member_lookup(
    overlay: &SemanticModelOverlay,
    cache: &mut ExternalClassCache,
    member: &str,
) -> MemberLookup {
    let Some(ClassIdentity::External { symbol_id, .. }) = external_class_identity(
        Some(overlay),
        Language::Python,
        "builtins.object",
        None,
        cache,
    ) else {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    };
    external_member_lookup(overlay, &symbol_id, member)
}

fn is_builtin_value_class(class: &ClassIdentity) -> bool {
    matches!(
        class.qualified_name(),
        "types.NoneType"
            | "builtins.bool"
            | "builtins.int"
            | "builtins.float"
            | "builtins.str"
            | "builtins.bytes"
            | "builtins.list"
            | "builtins.tuple"
            | "builtins.dict"
            | "builtins.set"
            | "builtins.frozenset"
            | "builtins.object"
    )
}

/// A partial model can prove a direct positive member declaration even when
/// its class surface cannot prove absence. Use this only after a unique direct
/// constructor and stable local receiver have been established.
fn external_direct_member_lookup(
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> MemberLookup {
    let Some(symbol) = python_external_member_declaration(overlay, owner_id, member) else {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    };
    MemberLookup::Present(MemberLookupHit::new(
        MemberDeclaration::External(ExternalMemberDeclaration::new([Box::from(
            symbol.id.as_str(),
        )])),
        CandidateCoverage::Open,
    ))
}

/// Prove the external class still exposes its declared method by scanning the
/// current workspace for exact imported-class assignments and setattr calls.
fn external_class_member_mutation_free(
    workspace: &WorkspaceAnalyzer,
    class: &ClassIdentity,
    declaration: &ExternalMemberDeclaration,
    member: &str,
) -> bool {
    let ClassIdentity::External {
        qualified_name,
        symbol_id,
    } = class
    else {
        return false;
    };
    let Some(overlay) = workspace.analyzer().semantic_model_overlay() else {
        return false;
    };
    let mut class_ids = HashSet::from_iter([symbol_id.to_string()]);
    for member_id in declaration.symbol_ids() {
        let matched = overlay.symbols_with_id(member_id);
        let [member] = matched.records.as_slice() else {
            return false;
        };
        let Some(owner_id) = member.owner_id.as_deref() else {
            return false;
        };
        class_ids.insert(owner_id.to_owned());
    }
    let mut identity_groups = Vec::with_capacity(class_ids.len());
    for class_id in class_ids {
        let matched = overlay.symbols_with_id(&class_id);
        let [class_record] = matched.records.as_slice() else {
            return false;
        };
        if class_record.kind != SemanticModelSymbolKind::Class
            || class_record.language != Language::Python.config_label()
            || class_record.provenance.ambiguous
            || (class_id == symbol_id.as_ref()
                && class_record.qualified_name != qualified_name.as_ref())
        {
            return false;
        }
        let mut identities = Vec::with_capacity(class_record.aliases.len() + 1);
        identities.push(class_record.qualified_name.as_str());
        identities.extend(class_record.aliases.iter().map(String::as_str));
        identity_groups.push(identities);
    }
    python_analyzer(workspace).cached_class_member_mutation_free(&identity_groups, member, || {
        let Ok(files) = workspace.analyzer().project().all_files_shared() else {
            return false;
        };
        for file in files.iter() {
            if crate::analyzer::common::language_for_file(file) != Language::Python {
                continue;
            }
            let Ok(source) = file.read_to_string() else {
                return false;
            };
            let mut parser = tree_sitter::Parser::new();
            if parser
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .is_err()
            {
                return false;
            }
            let Some(tree) = parser.parse(&source, None) else {
                return false;
            };
            if tree.root_node().has_error() {
                return false;
            }
            for identities in &identity_groups {
                if brokk_bifrost_python::runtime_values::python_external_class_member_mutation(
                    tree.root_node(),
                    &source,
                    identities,
                    member,
                    65_536,
                )
                .is_some()
                {
                    return false;
                }
            }
        }
        true
    })
}

pub(crate) fn python_external_class_call_identity(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
) -> Option<ClassIdentity> {
    match PythonTypeFlowAdapter.constructed_class(workspace, procedure, call) {
        ClassSeed::Class(class @ ClassIdentity::External { .. }) => Some(class),
        ClassSeed::Class(_)
        | ClassSeed::ClassWithOpenBound(_)
        | ClassSeed::Classes(_)
        | ClassSeed::ClassesWithOpenBound(_)
        | ClassSeed::NotApplicable
        | ClassSeed::Unknown(_) => None,
    }
}

/// Find one exact effective Python member using the active pack's declared C3 order.
/// A direct member is already the first C3 candidate and needs complete
/// callable-shape evidence only. Inherited members use unique, unambiguous
/// class and base declarations from a complete C3 order.
pub(crate) fn python_external_member_declaration<'a>(
    overlay: &'a SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> Option<&'a SemanticModelSymbol> {
    let owner = exact_python_model_class(overlay, owner_id)?;
    if python_external_declares_member(overlay, owner_id, member) {
        if overlay
            .gapped_member_surface(&owner.qualified_name, member)
            .is_some()
            || overlay
                .gapped_member_surface(&owner.qualified_name, "__getattribute__")
                .is_some()
            || python_external_declares_member(overlay, owner_id, "__getattribute__")
        {
            return None;
        }
        let has_declared_bases = overlay
            .relations_from(owner_id)
            .records
            .iter()
            .any(|relation| relation.kind == "extends");
        if has_declared_bases {
            let mro = python_external_class_mro(overlay, owner_id)?;
            for class_id in mro.iter().skip(1) {
                let class = exact_python_model_class(overlay, class_id)?;
                if overlay
                    .gapped_member_surface(&class.qualified_name, "__getattribute__")
                    .is_some()
                    || (class.qualified_name != "builtins.object"
                        && python_external_declares_member(overlay, class_id, "__getattribute__"))
                {
                    return None;
                }
            }
        }
        return exact_python_method_declaration(overlay, owner_id, member);
    }

    let mro = python_external_class_mro(overlay, owner_id)?;
    for class_id in &mro {
        let class = exact_python_model_class(overlay, class_id)?;
        if overlay
            .gapped_member_surface(&class.qualified_name, member)
            .is_some()
            || overlay
                .gapped_member_surface(&class.qualified_name, "__getattribute__")
                .is_some()
            || overlay
                .gapped_member_surface(&class.qualified_name, "__getattr__")
                .is_some()
        {
            return None;
        }
    }
    let has_custom_getattribute = mro.iter().any(|class_id| {
        exact_python_model_class(overlay, class_id)
            .is_some_and(|class| class.qualified_name != "builtins.object")
            && python_external_declares_member(overlay, class_id, "__getattribute__")
    });
    if has_custom_getattribute {
        return None;
    }
    let declares_member = mro
        .iter()
        .any(|class_id| python_external_declares_member(overlay, class_id, member));
    let has_getattr = mro.iter().any(|class_id| {
        exact_python_model_class(overlay, class_id)
            .is_some_and(|class| class.qualified_name != "builtins.object")
            && python_external_declares_member(overlay, class_id, "__getattr__")
    });
    if has_getattr && !declares_member {
        return None;
    }
    if python_external_declares_member(overlay, owner_id, member) {
        return exact_python_method_declaration(overlay, owner_id, member);
    }
    for declaring_id in mro.into_iter().skip(1) {
        if python_external_declares_member(overlay, &declaring_id, member) {
            exact_python_model_class(overlay, &declaring_id)?;
            return exact_python_method_declaration(overlay, &declaring_id, member);
        }
    }
    None
}

fn imported_external_class_callee_for_python(
    python: &PythonAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    callee: Node<'_>,
    overlay: Option<&SemanticModelOverlay>,
) -> Option<ClassIdentity> {
    let mut expression = callee;
    let mut has_attribute_path = callee.kind() == "attribute";
    while let Some(parent) = expression.parent() {
        if parent.kind() != "attribute"
            || (parent.child_by_field_name("object") != Some(expression)
                && parent.child_by_field_name("attribute") != Some(expression))
        {
            break;
        }
        expression = parent;
        has_attribute_path = true;
    }
    has_attribute_path
        .then(|| imported_external_class_for_python(python, file, prepared, expression, overlay))
        .flatten()
}

fn imported_external_class_for_python(
    python: &PythonAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    reference: Node<'_>,
    overlay: Option<&SemanticModelOverlay>,
) -> Option<ClassIdentity> {
    let (module, member) = import_bound_external_symbol(python, file, prepared, reference)?;
    external_class_identity(
        overlay,
        Language::Python,
        &format!("{module}.{member}"),
        None,
        &mut ExternalClassCache::default(),
    )
}

fn imported_external_function_return_classes(
    python: &PythonAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    callee: Node<'_>,
    overlay: Option<&SemanticModelOverlay>,
) -> Option<Vec<ClassIdentity>> {
    let (module, member) = imported_external_callable_binding(python, file, prepared, callee)?;
    let overlay = overlay?;
    let qualified_name = format!("{module}.{member}");
    let matched = overlay.symbols_named(&qualified_name);
    if matched.records.is_empty() {
        return None;
    }

    let mut classes = Vec::new();
    for symbol in matched.records {
        if symbol.qualified_name != qualified_name && !symbol.aliases.contains(&qualified_name) {
            return None;
        }
        if symbol.language != Language::Python.config_label()
            || symbol.kind != SemanticModelSymbolKind::Function
            || symbol.owner_id.as_ref().is_some_and(|owner_id| {
                let owner = overlay.symbols_with_id(owner_id);
                !matches!(
                    owner.records.as_slice(),
                    [owner] if owner.kind == SemanticModelSymbolKind::Module
                )
            })
            || symbol.has_receiver()
            || symbol.provenance.ambiguous
            || (symbol.exact_return_classes.is_empty()
                && !symbol.has_complete_callable_shape_evidence())
        {
            return None;
        }
        let returned = if symbol.exact_return_classes.is_empty() {
            let reference = symbol.structured_signature()?.returns.as_ref()?;
            vec![reference]
        } else {
            symbol.exact_return_classes.iter().collect()
        };
        for reference in returned {
            let class = match reference {
                TypeRef::Named {
                    name,
                    nullable: false,
                    ..
                } => external_class_identity(
                    Some(overlay),
                    Language::Python,
                    name,
                    None,
                    &mut ExternalClassCache::default(),
                ),
                TypeRef::Declared {
                    id,
                    nullable: false,
                    ..
                } => external_class_identity(
                    Some(overlay),
                    Language::Python,
                    "",
                    Some(id),
                    &mut ExternalClassCache::default(),
                ),
                _ => None,
            }?;
            if class.qualified_name() == "typing.Any" || class.qualified_name() == "builtins.Any" {
                return None;
            }
            classes.push(class);
        }
    }
    classes.sort_by(|left, right| {
        left.qualified_name()
            .cmp(right.qualified_name())
            .then_with(|| format!("{left:?}").cmp(&format!("{right:?}")))
    });
    classes.dedup();
    (!classes.is_empty()).then_some(classes)
}

fn python_external_declares_member(
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> bool {
    overlay
        .members_of(owner_id)
        .records
        .into_iter()
        .any(|symbol| {
            symbol.owner_id.as_deref() == Some(owner_id)
                && symbol.name == member
                && symbol.language == Language::Python.config_label()
        })
}

fn exact_python_model_class<'a>(
    overlay: &'a SemanticModelOverlay,
    id: &str,
) -> Option<&'a SemanticModelSymbol> {
    let matched = overlay.symbols_with_id(id);
    let [symbol] = matched.records.as_slice() else {
        return None;
    };
    (symbol.id == id
        && symbol.language == Language::Python.config_label()
        && symbol.kind == SemanticModelSymbolKind::Class
        && !symbol.provenance.ambiguous)
        .then_some(*symbol)
}

fn exact_python_method_declaration<'a>(
    overlay: &'a SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> Option<&'a SemanticModelSymbol> {
    let mut records = overlay
        .members_of(owner_id)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.owner_id.as_deref() == Some(owner_id)
                && symbol.name == member
                && symbol.language == Language::Python.config_label()
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.id.cmp(&right.id));
    records.dedup_by(|left, right| left.id == right.id);
    let [symbol] = records.as_slice() else {
        return None;
    };
    (symbol.kind == SemanticModelSymbolKind::Method
        && symbol.has_receiver()
        && !symbol.provenance.ambiguous
        && symbol.has_complete_callable_shape_evidence()
        && symbol.structured_signature().is_some())
    .then_some(*symbol)
}

#[derive(Debug)]
struct PythonModelMroFrame {
    class_id: String,
    bases: Option<Vec<String>>,
    next_base: usize,
}

/// C3 linearization over a fully declared active Python model hierarchy.
/// Missing, ambiguous, partial, or unordered base evidence makes inheritance
/// unavailable; callers may still use a complete member declared on the class
/// itself.
fn python_external_class_mro(overlay: &SemanticModelOverlay, root_id: &str) -> Option<Vec<String>> {
    let mut linearizations = HashMap::<String, Vec<String>>::default();
    let mut visiting = HashSet::<String>::default();
    let mut stack = vec![PythonModelMroFrame {
        class_id: root_id.to_owned(),
        bases: None,
        next_base: 0,
    }];
    visiting.insert(root_id.to_owned());

    while !stack.is_empty() {
        let top = stack.len() - 1;
        if stack[top].bases.is_none() {
            let class_id = stack[top].class_id.clone();
            let class = exact_python_model_class(overlay, &class_id)?;
            if class.provenance.completeness != SemanticModelCompleteness::Complete {
                return None;
            }
            stack[top].bases = Some(python_external_direct_bases(overlay, class)?);
        }
        let bases = stack[top].bases.as_ref().expect("bases were initialized");
        if stack[top].next_base < bases.len() {
            let base = bases[stack[top].next_base].clone();
            stack[top].next_base += 1;
            if linearizations.contains_key(&base) {
                continue;
            }
            if !visiting.insert(base.clone()) {
                return None;
            }
            stack.push(PythonModelMroFrame {
                class_id: base,
                bases: None,
                next_base: 0,
            });
            continue;
        }

        let frame = stack.pop().expect("the MRO stack is nonempty");
        let bases = frame.bases.expect("bases were initialized");
        let mut sequences = bases
            .iter()
            .map(|base| linearizations.get(base).cloned())
            .collect::<Option<Vec<_>>>()?;
        sequences.push(bases.clone());
        let mut merged = Vec::new();
        loop {
            sequences.retain(|sequence| !sequence.is_empty());
            if sequences.is_empty() {
                break;
            }
            let candidate = sequences.iter().find_map(|sequence| {
                let head = sequence.first()?;
                (!sequences
                    .iter()
                    .any(|other| other.iter().skip(1).any(|tail| tail == head)))
                .then(|| head.clone())
            })?;
            merged.push(candidate.clone());
            for sequence in &mut sequences {
                if sequence.first() == Some(&candidate) {
                    sequence.remove(0);
                }
            }
        }
        let mut linearization = Vec::with_capacity(merged.len() + 1);
        linearization.push(frame.class_id.clone());
        linearization.extend(merged);
        visiting.remove(&frame.class_id);
        linearizations.insert(frame.class_id, linearization);
    }
    linearizations.remove(root_id)
}

fn python_external_direct_bases(
    overlay: &SemanticModelOverlay,
    class: &SemanticModelSymbol,
) -> Option<Vec<String>> {
    if class.provenance.completeness != SemanticModelCompleteness::Complete {
        return None;
    }
    if class.qualified_name == "builtins.object" {
        return Some(Vec::new());
    }
    let relations = overlay
        .relations_from(&class.id)
        .records
        .into_iter()
        .filter(|relation| relation.kind == "extends")
        .collect::<Vec<_>>();
    if relations.is_empty() {
        return Some(Vec::new());
    }
    let mut ordered = relations;
    if ordered.len() > 1
        && ordered
            .iter()
            .any(|relation| relation.declaration_ordinal.is_none())
    {
        return None;
    }
    ordered.sort_by_key(|relation| relation.declaration_ordinal.unwrap_or(0));
    if ordered
        .windows(2)
        .any(|pair| pair[0].declaration_ordinal == pair[1].declaration_ordinal)
        || ordered.iter().any(|relation| {
            relation.provenance.ambiguous
                || relation.provenance.completeness != SemanticModelCompleteness::Complete
        })
    {
        return None;
    }
    let mut bases = Vec::with_capacity(ordered.len());
    for relation in ordered {
        let by_id = overlay.symbols_with_id(&relation.to);
        let records = if by_id.records.is_empty() {
            if relation.to == "builtins.object" {
                continue;
            }
            overlay
                .symbols_named(&relation.to)
                .records
                .into_iter()
                .filter(|symbol| {
                    symbol.qualified_name == relation.to
                        || symbol.aliases.iter().any(|alias| alias == &relation.to)
                })
                .collect::<Vec<_>>()
        } else {
            by_id.records
        };
        if records.is_empty() && !relation.to.contains('.') {
            let module = class
                .locator_path
                .as_deref()
                .and_then(|path| {
                    super::external::python_module_name_from_relative(std::path::Path::new(path))
                })
                .or_else(|| {
                    class
                        .qualified_name
                        .rsplit_once('.')
                        .map(|(module, _)| module.to_owned())
                })?;
            let local_name = format!("{module}.{}", relation.to);
            if let Some(ClassIdentity::External { symbol_id, .. }) = external_class_identity(
                Some(overlay),
                Language::Python,
                &local_name,
                None,
                &mut ExternalClassCache::default(),
            ) {
                bases.push(symbol_id.into_string());
                continue;
            }
        }
        let [base] = records.as_slice() else {
            return None;
        };
        if base.language != Language::Python.config_label()
            || base.kind != SemanticModelSymbolKind::Class
            || base.provenance.ambiguous
            || base.provenance.completeness != SemanticModelCompleteness::Complete
        {
            return None;
        }
        bases.push(base.id.clone());
    }
    Some(bases)
}

fn python_exact_result_origin_classes(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    origin: &ConstructorResultOrigin,
) -> Option<Box<[ClassIdentity]>> {
    let semantics = procedure.semantics();
    match &origin.producer {
        crate::analyzer::semantic::ExactResultProducer::Call(call_id)
            if matches!(
                origin.source.kind,
                SourceSiteKind::ConstructorCall | SourceSiteKind::ExactCallResult
            ) =>
        {
            let calls = semantics
                .call_sites()
                .iter()
                .filter(|call| call.id == *call_id)
                .collect::<Vec<_>>();
            let [call] = calls.as_slice() else {
                return None;
            };
            let mapping = semantics.source_mapping(call.source)?;
            if mapping.kind != SourceMappingKind::Exact
                || mapping.locator.anchor().span() != origin.source.span
                || file_for_locator(workspace, &mapping.locator).as_ref()
                    != Some(&origin.source.file)
            {
                return None;
            }
            let results = call.normal_result_values().collect::<Vec<_>>();
            let [result] = results.as_slice() else {
                return None;
            };
            if *result != origin.result {
                return None;
            }
            if origin.source.kind == SourceSiteKind::ExactCallResult {
                PythonTypeFlowAdapter.exact_call_result_class(workspace, procedure, call)
            } else {
                match PythonTypeFlowAdapter.constructed_class(workspace, procedure, call) {
                    ClassSeed::Class(class) => Some(vec![class].into_boxed_slice()),
                    _ => None,
                }
            }
        }
        crate::analyzer::semantic::ExactResultProducer::MemoryLoad { point, location }
            if origin.source.kind == SourceSiteKind::ExactAccessResult =>
        {
            let rows = semantics
                .point(*point)?
                .events
                .iter()
                .filter_map(|event| {
                    let SemanticEffect::MemoryLoad {
                        location: found_location,
                        result,
                        ..
                    } = event.effect
                    else {
                        return None;
                    };
                    (found_location == *location && result == origin.result)
                        .then_some((event.source, found_location))
                })
                .collect::<Vec<_>>();
            let [(source, found_location)] = rows.as_slice() else {
                return None;
            };
            let mapping = semantics.source_mapping(*source)?;
            if mapping.kind != SourceMappingKind::Exact
                || mapping.locator.anchor().span() != origin.source.span
                || file_for_locator(workspace, &mapping.locator).as_ref()
                    != Some(&origin.source.file)
            {
                return None;
            }
            let location = semantics.memory_location(*found_location)?;
            match PythonTypeFlowAdapter.memory_load_result_class(
                workspace,
                procedure,
                location,
                origin.result,
            ) {
                ClassSeed::Class(class @ ClassIdentity::External { .. }) => {
                    Some(vec![class].into_boxed_slice())
                }
                ClassSeed::Classes(classes)
                    if classes
                        .iter()
                        .all(|class| matches!(class, ClassIdentity::External { .. })) =>
                {
                    Some(classes)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether the receiver's exact source mapping is a local identifier.
fn constructor_receiver_is_local_identifier(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    receiver: ValueId,
) -> bool {
    let semantics = procedure.semantics();
    let Some(receiver_value) = semantics.value(receiver) else {
        return false;
    };
    let Some(mapping) = semantics.source_mapping(receiver_value.source) else {
        return false;
    };
    if mapping.kind != SourceMappingKind::Exact {
        return false;
    }
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return false;
    };
    let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
        return false;
    };
    node_at_span(&prepared, mapping.locator.anchor().span())
        .is_some_and(|node| node.kind() == "identifier")
}

fn python_external_receiver_call_member(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
) -> Option<String> {
    let semantics = procedure.semantics();
    let callee = semantics.value(call.callee)?;
    let mapping = semantics.source_mapping(callee.source)?;
    if mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let file = file_for_locator(workspace, &mapping.locator)?;
    let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
    let node = node_at_span(&prepared, mapping.locator.anchor().span())?;
    if node.kind() != "attribute" {
        return None;
    }
    node.child_by_field_name("attribute")
        .and_then(|member| member.utf8_text(prepared.source().as_bytes()).ok())
        .map(str::to_owned)
}

/// Whether the constructor result reaches this call through one local
/// definition and direct receiver reads, without rebinding, aliasing, capture, or escape.
fn constructor_result_has_stable_local_receiver(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    receiver: ValueId,
    method_call: &SemanticCallSite,
    origin: &ConstructorResultOrigin,
) -> bool {
    macro_rules! reject {
        ($reason:literal) => {{
            return false;
        }};
    }
    if method_call.receiver != Some(receiver)
        || matches!(
            &origin.producer,
            crate::analyzer::semantic::ExactResultProducer::Call(call) if *call == method_call.id
        )
    {
        reject!("receiver/call identity mismatch");
    }
    if python_exact_result_origin_classes(workspace, procedure, origin).as_deref()
        != Some(origin.classes.as_ref())
    {
        reject!("result producer no longer proves the exact class");
    }
    if !constructor_receiver_is_local_identifier(workspace, procedure, receiver) {
        reject!("receiver is not a local identifier");
    }
    let semantics = procedure.semantics();
    let Some(method_source) = semantics.source_mapping(method_call.source) else {
        reject!("method call has no source mapping");
    };
    if method_source.kind != SourceMappingKind::Exact {
        reject!("method call mapping is inexact");
    }
    let method_start = usize::try_from(method_source.locator.anchor().span().start_byte())
        .expect("source byte offsets fit usize");
    let bindings = BindingOriginIndex::new(procedure);
    let Some(binding) = bindings.unique_binding_origin(receiver) else {
        reject!("receiver has no unique binding");
    };
    if !matches!(
        semantics.value(binding).map(|value| &value.kind),
        Some(SemanticValueKind::Local)
    ) || bindings.address_taken_binding_set().contains(&binding)
    {
        reject!("receiver binding is not a stable local");
    }

    if python_local_binding_deleted_before_call(workspace, procedure, receiver, method_start) {
        reject!("receiver binding is deleted before the call");
    }
    if python_local_special_attribute_access_before_call(
        workspace,
        procedure,
        receiver,
        method_start,
    ) {
        reject!("receiver __dict__ or __class__ is accessed");
    }

    let reaching_origin =
        python_unique_reaching_binding_assignment(procedure, binding, method_call);
    if reaching_origin != Some(origin.result) {
        reject!("reaching assignment differs from constructor result");
    }
    let mut receiver_reads = 0usize;
    for event in semantics
        .points()
        .iter()
        .flat_map(|point| point.events.iter())
    {
        match event.effect {
            SemanticEffect::ValueFlow { source, target, .. } if source == binding => {
                if !constructor_receiver_is_local_identifier(workspace, procedure, target) {
                    reject!("binding value flows to a nonlocal expression");
                }
                receiver_reads += 1;
            }
            SemanticEffect::ValueFlow { source, target, .. }
                if target == binding && source != origin.result =>
            {
                reject!("a different value flows into the receiver binding");
            }
            SemanticEffect::Assignment { target, value } if target != binding => {
                if bindings.unique_binding_origin(value) == Some(binding) {
                    reject!("receiver binding is copied into another assignment");
                }
            }
            SemanticEffect::MemoryStore {
                location, value, ..
            } => {
                if bindings.unique_binding_origin(value) == Some(binding) {
                    reject!("receiver binding is stored into memory");
                }
                let Some(location) = semantics.memory_location(location) else {
                    reject!("memory store has no classified location");
                };
                if matches!(
                    &location.kind,
                    MemoryLocationKind::Field { base, .. }
                        if bindings.unique_binding_origin(*base) == Some(binding)
                ) {
                    reject!("receiver binding is stored into an instance field");
                }
            }
            SemanticEffect::MemoryLoad { location, .. } => {
                let Some(location) = semantics.memory_location(location) else {
                    reject!("memory load has no classified location");
                };
                if let MemoryLocationKind::Field { base, member } = &location.kind
                    && bindings.unique_binding_origin(*base) == Some(binding)
                    && member
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        .is_some_and(|name| matches!(name, "__dict__" | "__class__"))
                {
                    reject!("receiver __dict__ or __class__ is accessed");
                }
            }
            SemanticEffect::AggregateInitializer { value, .. }
                if bindings.unique_binding_origin(value) == Some(binding) =>
            {
                reject!("receiver binding enters an aggregate");
            }
            SemanticEffect::ProcedureReturn { value: Some(value) }
            | SemanticEffect::Throw { value: Some(value) }
                if bindings.unique_binding_origin(value) == Some(binding) =>
            {
                reject!("receiver binding is returned or thrown");
            }
            _ => {}
        }
    }
    // Multiple direct reads preserve the same binding origin. Any read that
    // flows into another value was rejected above as an alias.
    if receiver_reads == 0 {
        reject!("no direct receiver reads were found");
    }
    for call in semantics.call_sites() {
        if call.id != method_call.id {
            let escapes_binding = call
                .arguments
                .iter()
                .map(|argument| argument.value)
                .any(|value| bindings.unique_binding_origin(value) == Some(binding))
                || (call.receiver.is_none()
                    && bindings.unique_binding_origin(call.callee) == Some(binding));
            if escapes_binding {
                reject!("receiver binding is passed as an argument or callee");
            }
            if call
                .receiver
                .is_some_and(|value| bindings.unique_binding_origin(value) == Some(binding))
            {
                let Some(mapping) = semantics.source_mapping(call.source) else {
                    reject!("receiver method call has no source mapping");
                };
                if mapping.kind != SourceMappingKind::Exact {
                    reject!("receiver method call has an inexact source mapping");
                }
                let earlier_start = usize::try_from(mapping.locator.anchor().span().start_byte())
                    .expect("source byte offsets fit usize");
                if earlier_start < method_start {
                    if python_unique_reaching_binding_assignment(procedure, binding, call)
                        != Some(origin.result)
                    {
                        reject!("earlier receiver call has a different reaching origin");
                    }
                    let Some(member_name) =
                        python_external_receiver_call_member(workspace, procedure, call)
                    else {
                        reject!("earlier receiver call has no exact member name");
                    };
                    if matches!(
                        member_name.as_str(),
                        "__setattr__" | "__delattr__" | "__setstate__" | "__init__"
                    ) {
                        reject!("earlier receiver call can mutate class state");
                    }
                    let Some(overlay) = workspace.analyzer().semantic_model_overlay() else {
                        reject!("active semantic model is unavailable");
                    };
                    for class in origin.classes.iter() {
                        let ClassIdentity::External { symbol_id, .. } = class else {
                            reject!("exact return origin contains a non-external class");
                        };
                        let Some(declaration) =
                            python_external_member_declaration(&overlay, symbol_id, &member_name)
                        else {
                            reject!("earlier receiver call is not a uniquely declared pack method");
                        };
                        if declaration.kind != SemanticModelSymbolKind::Method
                            || !declaration.has_receiver()
                            || !declaration.has_complete_callable_shape_evidence()
                            || declaration.structured_signature().is_none()
                            || !external_class_member_mutation_free(
                                workspace,
                                class,
                                &ExternalMemberDeclaration::new([Box::from(
                                    declaration.id.as_str(),
                                )]),
                                &member_name,
                            )
                        {
                            reject!(
                                "earlier receiver method is not closed by the pack declaration"
                            );
                        }
                    }
                }
            }
        } else if call.receiver != Some(receiver)
            || call
                .arguments
                .iter()
                .any(|argument| bindings.unique_binding_origin(argument.value) == Some(binding))
        {
            reject!("method call receiver or arguments differ from the proven binding");
        }
    }
    true
}

fn python_local_binding_deleted_before_call(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    receiver: ValueId,
    method_start: usize,
) -> bool {
    let semantics = procedure.semantics();
    let Some(value) = semantics.value(receiver) else {
        return true;
    };
    let Some(mapping) = semantics.source_mapping(value.source) else {
        return true;
    };
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return true;
    };
    let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
        return true;
    };
    let Some(receiver_node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
        return true;
    };
    let Some(scope) = python_enclosing_function(receiver_node) else {
        return true;
    };
    let receiver_name = match receiver_node.utf8_text(prepared.source().as_bytes()) {
        Ok(name) if receiver_node.kind() == "identifier" => name,
        _ => return true,
    };
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node != scope
            && matches!(
                node.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if matches!(node.kind(), "delete" | "delete_statement") && node.start_byte() < method_start
        {
            let mut names = vec![node];
            while let Some(candidate) = names.pop() {
                if candidate.kind() == "identifier"
                    && candidate.utf8_text(prepared.source().as_bytes()).ok() == Some(receiver_name)
                {
                    return true;
                }
                let mut cursor = candidate.walk();
                names.extend(candidate.named_children(&mut cursor));
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn python_local_special_attribute_access_before_call(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    receiver: ValueId,
    method_start: usize,
) -> bool {
    const MAX_SCOPE_NODES: usize = 65_536;

    let semantics = procedure.semantics();
    let Some(value) = semantics.value(receiver) else {
        return true;
    };
    let Some(mapping) = semantics.source_mapping(value.source) else {
        return true;
    };
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return true;
    };
    let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
        return true;
    };
    let Some(receiver_node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
        return true;
    };
    let Some(scope) = python_enclosing_function(receiver_node) else {
        return true;
    };
    let Ok(receiver_name) = receiver_node.utf8_text(prepared.source().as_bytes()) else {
        return true;
    };
    let Some(inventory) = python_lexical_scope_inventory_bounded(scope, prepared.source(), || true)
    else {
        return true;
    };
    let mut remaining = MAX_SCOPE_NODES;
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if remaining == 0 {
            return true;
        }
        remaining -= 1;
        if node != scope
            && matches!(
                node.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if node.kind() == "attribute" && node.start_byte() < method_start {
            let Some(object) = node.child_by_field_name("object") else {
                return true;
            };
            let Some(attribute) = node.child_by_field_name("attribute") else {
                return true;
            };
            if object.kind() == "identifier"
                && object.utf8_text(prepared.source().as_bytes()).ok() == Some(receiver_name)
                && !python_comprehension_binds_name_at(receiver_name, object, prepared.source())
                && inventory.name_resolution_at(receiver_name, object)
                    == PythonLexicalNameResolution::Local
                && attribute
                    .utf8_text(prepared.source().as_bytes())
                    .is_ok_and(|name| matches!(name, "__dict__" | "__class__"))
            {
                return true;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn python_enclosing_function(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda") {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn python_unique_reaching_binding_assignment(
    procedure: &ProcedureHandle,
    binding: ValueId,
    method_call: &SemanticCallSite,
) -> Option<ValueId> {
    let call_point = procedure.semantics().point(method_call.point)?;
    let invoke_index = call_point.events.iter().position(|event| {
        matches!(
            event.effect,
            SemanticEffect::Invoke { call_site } if call_site == method_call.id
        )
    })?;
    python_unique_reaching_binding_assignment_at(
        procedure,
        binding,
        method_call.point,
        invoke_index,
    )
}

fn python_unique_reaching_binding_assignment_at(
    procedure: &ProcedureHandle,
    binding: ValueId,
    use_point: ProgramPointId,
    use_event_index: usize,
) -> Option<ValueId> {
    const MAX_REACHING_SET_WORDS: usize = 65_536;

    let semantics = procedure.semantics();
    let point_count = semantics.points().len();
    let use_point_index = use_point.index();
    semantics.point(use_point)?;
    let mut assignments = Vec::<(usize, ValueId)>::new();
    let mut assignments_by_point = vec![Vec::<usize>::new(); point_count];
    for (point_index, point) in semantics.points().iter().enumerate() {
        for (event_index, event) in point.events.iter().enumerate() {
            if let SemanticEffect::Assignment { target, value } = event.effect
                && target == binding
            {
                let assignment_id = assignments.len() + 1;
                assignments.push((event_index, value));
                assignments_by_point[point_index].push(assignment_id);
            }
        }
    }
    let definition_count = assignments.len().saturating_add(1);
    let words = definition_count.div_ceil(64);
    if assignments.is_empty()
        || point_count
            .checked_mul(words)
            .is_none_or(|words| words > MAX_REACHING_SET_WORDS)
    {
        return None;
    }

    let mut facts = GenKillFacts::new(point_count, definition_count);
    for (point_index, point) in semantics.points().iter().enumerate() {
        let local = &assignments_by_point[point_index];
        if let Some(generated) = local.last().copied() {
            for killed in 0..definition_count {
                facts.record_killed(point_index, killed);
            }
            facts.record_generated(point_index, generated);
        } else if point.id == semantics.entry_point() {
            facts.record_generated(point_index, 0);
        }
    }

    let mut budget = CfgAlgorithmBudget::uniform(16_384);
    let cancellation = CancellationToken::new();
    let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
    let reaching =
        reaching_definitions(semantics, semantics.entry_point(), &facts, &mut request).ok()?;

    let same_point = assignments_by_point.get(use_point_index)?;
    let before_call = same_point
        .iter()
        .copied()
        .filter(|definition| assignments[*definition - 1].0 < use_event_index)
        .collect::<Vec<_>>();
    let reaching_here = if let Some(last) = before_call.last().copied() {
        vec![last]
    } else {
        reaching.reaching_in(use_point_index).collect::<Vec<_>>()
    };
    let [definition] = reaching_here.as_slice() else {
        return None;
    };
    (*definition > 0)
        .then(|| assignments.get(*definition - 1).map(|(_, value)| *value))
        .flatten()
}

fn python_exact_result_origin_for_value(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    result: ValueId,
) -> Option<ConstructorResultOrigin> {
    let semantics = procedure.semantics();
    let calls = semantics
        .call_sites()
        .iter()
        .filter(|call| call.normal_result_values().any(|value| value == result))
        .collect::<Vec<_>>();
    if let [call] = calls.as_slice() {
        let (classes, kind) = if let Some(classes) =
            PythonTypeFlowAdapter.exact_call_result_class(workspace, procedure, call)
        {
            (classes, SourceSiteKind::ExactCallResult)
        } else {
            let ClassSeed::Class(class @ ClassIdentity::External { .. }) =
                PythonTypeFlowAdapter.constructed_class(workspace, procedure, call)
            else {
                return None;
            };
            (
                vec![class].into_boxed_slice(),
                SourceSiteKind::ConstructorCall,
            )
        };
        let results = call.normal_result_values().collect::<Vec<_>>();
        let [only_result] = results.as_slice() else {
            return None;
        };
        if *only_result != result {
            return None;
        }
        let mapping = semantics.source_mapping(call.source)?;
        if mapping.kind != SourceMappingKind::Exact {
            return None;
        }
        let file = file_for_locator(workspace, &mapping.locator)?;
        return Some(ConstructorResultOrigin {
            classes,
            producer: crate::analyzer::semantic::ExactResultProducer::Call(call.id),
            result,
            source: SourceSite {
                file,
                span: mapping.locator.anchor().span(),
                kind,
            },
        });
    }
    if !calls.is_empty() {
        return None;
    }
    let loads = semantics
        .points()
        .iter()
        .flat_map(|point| {
            point
                .events
                .iter()
                .enumerate()
                .filter_map(move |(event_index, event)| {
                    let SemanticEffect::MemoryLoad {
                        location,
                        result: found,
                        ..
                    } = event.effect
                    else {
                        return None;
                    };
                    (found == result).then_some((point.id, event_index, location, event.source))
                })
        })
        .collect::<Vec<_>>();
    let [(point, _event_index, location, source)] = loads.as_slice() else {
        return None;
    };
    let mapping = semantics.source_mapping(*source)?;
    if mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let file = file_for_locator(workspace, &mapping.locator)?;
    let memory_location = semantics.memory_location(*location)?;
    let seed = PythonTypeFlowAdapter.memory_load_result_class(
        workspace,
        procedure,
        memory_location,
        result,
    );
    let classes = match seed {
        ClassSeed::Class(class @ ClassIdentity::External { .. }) => vec![class].into_boxed_slice(),
        ClassSeed::Classes(classes)
            if classes
                .iter()
                .all(|class| matches!(class, ClassIdentity::External { .. })) =>
        {
            classes
        }
        _ => return None,
    };
    let origin = ConstructorResultOrigin {
        classes,
        producer: crate::analyzer::semantic::ExactResultProducer::MemoryLoad {
            point: *point,
            location: *location,
        },
        result,
        source: SourceSite {
            file,
            span: mapping.locator.anchor().span(),
            kind: SourceSiteKind::ExactAccessResult,
        },
    };
    (python_exact_result_origin_classes(workspace, procedure, &origin).as_deref()
        == Some(origin.classes.as_ref()))
    .then_some(origin)
}

pub(crate) fn python_exact_external_receiver_identities(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    method_call: &SemanticCallSite,
) -> Option<Vec<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>> {
    let receiver = method_call.receiver?;
    if !constructor_receiver_is_local_identifier(workspace, procedure, receiver) {
        return None;
    }
    let semantics = procedure.semantics();
    let bindings = BindingOriginIndex::new(procedure);
    let binding = bindings.unique_binding_origin(receiver)?;
    if !matches!(
        semantics.value(binding).map(|value| &value.kind),
        Some(SemanticValueKind::Local)
    ) || bindings.address_taken_binding_set().contains(&binding)
    {
        return None;
    }
    let method_source = semantics.source_mapping(method_call.source)?;
    if method_source.kind != SourceMappingKind::Exact {
        return None;
    }
    let method_start = usize::try_from(method_source.locator.anchor().span().start_byte())
        .expect("source byte offsets fit usize");
    if python_local_binding_deleted_before_call(workspace, procedure, receiver, method_start) {
        return None;
    }
    let result = python_unique_reaching_binding_assignment(procedure, binding, method_call)?;
    let origin = python_exact_result_origin_for_value(workspace, procedure, result)?;
    if !constructor_result_has_stable_local_receiver(
        workspace,
        procedure,
        receiver,
        method_call,
        &origin,
    ) {
        return None;
    }

    let callee = semantics.value(method_call.callee)?;
    let callee_mapping = semantics.source_mapping(callee.source)?;
    if callee_mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let method_file = file_for_locator(workspace, &callee_mapping.locator)?;
    let prepared = prepared_for_procedure(workspace, procedure, &method_file).ok()?;
    let callee_node = node_at_span(&prepared, callee_mapping.locator.anchor().span())?;
    if callee_node.kind() != "attribute" {
        return None;
    }
    let member = callee_node
        .child_by_field_name("attribute")?
        .utf8_text(prepared.source().as_bytes())
        .ok()?;
    let overlay = workspace.analyzer().semantic_model_overlay()?;
    let mut identities = Vec::with_capacity(origin.classes.len());
    for class in origin.classes.iter() {
        let ClassIdentity::External { symbol_id, .. } = class else {
            return None;
        };
        let declaration = python_external_member_declaration(&overlay, symbol_id, member)?;
        if declaration.kind != SemanticModelSymbolKind::Method
            || !declaration.has_receiver()
            || !declaration.has_complete_callable_shape_evidence()
            || declaration.structured_signature().is_none()
            || !external_class_member_mutation_free(
                workspace,
                class,
                &ExternalMemberDeclaration::new([Box::from(declaration.id.as_str())]),
                member,
            )
        {
            return None;
        }
        let owner_id = declaration.owner_id.as_deref()?;
        let owners = overlay.symbols_with_id(owner_id);
        let [owner] = owners.records.as_slice() else {
            return None;
        };
        if owner.kind != SemanticModelSymbolKind::Class
            || owner.language != Language::Python.config_label()
            || owner.provenance.ambiguous
            || owner.provenance.pack_id != declaration.provenance.pack_id
        {
            return None;
        }
        identities.push(
            crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
                Language::Python,
                owner.qualified_name.clone(),
                member.to_owned(),
            ),
        );
    }
    identities.sort_unstable();
    identities.dedup();
    (!identities.is_empty()).then_some(identities)
}

/// A workspace class can close an exact instance method only when its own
/// declaration rules out inherited dispatch, custom construction, method
/// decorators, and access hooks. The caller also proves a stable local
/// receiver with no instance stores or escape, so an empty __slots__ is not
/// required to rule out per-instance method replacement.
fn workspace_instance_method_surface_is_closed(
    workspace: &WorkspaceAnalyzer,
    class: &ClassIdentity,
    member: &str,
    declaration: &CodeUnit,
) -> bool {
    let ClassIdentity::Workspace(owner) = class else {
        return false;
    };
    let python = python_analyzer(workspace);
    let Some(prepared) = current_indexed_prepared(python, owner.source()) else {
        return false;
    };
    let Some(class_node) = class_node_for_unit(python, &prepared, owner) else {
        return false;
    };
    if class_node.child_by_field_name("superclasses").is_some()
        || class_node
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
        || !workspace_class_uses_ordinary_metaclass(
            workspace,
            python,
            owner,
            workspace.analyzer().semantic_model_overlay().as_deref(),
        )
    {
        return false;
    }
    let Some(body) = class_node.child_by_field_name("body") else {
        return false;
    };
    let source = prepared.source();
    let mut empty_slots = 0usize;
    let mut method_declarations = 0usize;
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        match python_class_member_assignment(child, source, "__slots__") {
            ClassMemberAssignment::NotMember => {}
            ClassMemberAssignment::Value(value)
                if value.kind() == "tuple" && named_children(value).is_empty() =>
            {
                empty_slots += 1;
                if empty_slots > 1 {
                    return false;
                }
            }
            ClassMemberAssignment::AnnotationOnly
            | ClassMemberAssignment::Value(_)
            | ClassMemberAssignment::Unknown => return false,
        }
        if matches!(
            definition_name(child, source),
            Some("__new__" | "__init__" | "__getattribute__" | "__getattr__" | "__setattr__")
        ) || assignment_name(child, source) == Some(member)
        {
            return false;
        }
        if definition_name(child, source) == Some(member) {
            if child.kind() != "function_definition" {
                return false;
            }
            method_declarations += 1;
        }
    }
    empty_slots <= 1
        && method_declarations == 1
        && python
            .direct_children(owner)
            .iter()
            .any(|child| child == declaration && child.terminal_name() == member)
}

fn python_any_class(class: &ClassIdentity) -> bool {
    matches!(class, ClassIdentity::External { .. })
        && matches!(
            class.qualified_name(),
            "typing.Any" | "typing_extensions.Any"
        )
}

fn python_seed_contains_any(seed: &ClassSeed) -> bool {
    match seed {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => python_any_class(class),
        ClassSeed::Classes(classes) | ClassSeed::ClassesWithOpenBound(classes) => {
            classes.iter().any(python_any_class)
        }
        ClassSeed::Unknown(_) | ClassSeed::NotApplicable => false,
    }
}

fn python_dynamic_any_seed(seed: ClassSeed) -> ClassSeed {
    if python_seed_contains_any(&seed) {
        ClassSeed::Unknown(UnknownReason::UncertainFlow)
    } else {
        seed
    }
}

fn python_typing_union_or_optional(class: &ClassIdentity) -> bool {
    matches!(
        class.qualified_name(),
        "typing.Optional"
            | "typing.Union"
            | "typing_extensions.Optional"
            | "typing_extensions.Union"
    )
}

fn python_type_ref_contains_any(overlay: &SemanticModelOverlay, root: &TypeRef) -> bool {
    let mut pending = vec![root];
    let mut cache = ExternalClassCache::default();
    while let Some(reference) = pending.pop() {
        let (class, arguments) = match reference {
            TypeRef::Named {
                name, arguments, ..
            } => (
                external_class_identity(Some(overlay), Language::Python, name, None, &mut cache),
                arguments,
            ),
            TypeRef::Declared { id, arguments, .. } => (
                external_class_identity(Some(overlay), Language::Python, "", Some(id), &mut cache),
                arguments,
            ),
            _ => continue,
        };
        let Some(class) = class else {
            continue;
        };
        if python_any_class(&class) {
            return true;
        }
        if python_typing_union_or_optional(&class) {
            pending.extend(arguments);
        }
    }
    false
}

fn python_annotation_union_or_optional_base(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    base: Node<'_>,
) -> bool {
    let Some((module, member)) =
        import_bound_external_symbol(python_analyzer(workspace), file, prepared, base)
    else {
        return false;
    };
    matches!(
        (module.as_str(), member.as_str()),
        ("typing" | "typing_extensions", "Optional" | "Union")
    )
}

fn python_annotation_contains_any(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    annotation: Node<'_>,
) -> bool {
    let mut pending = vec![annotation];
    while let Some(annotation) = pending.pop() {
        let Some(annotation) = python_annotation_expression(annotation) else {
            continue;
        };
        match annotation.kind() {
            "identifier" | "attribute" | "member_type" => {
                let seed = resolve_class_at_span(
                    workspace,
                    file.clone(),
                    span_for_node(annotation),
                    prepared,
                );
                if python_seed_contains_any(&seed) {
                    return true;
                }
            }
            "union_type" => {
                let mut cursor = annotation.walk();
                pending.extend(annotation.named_children(&mut cursor));
            }
            "binary_operator" => {
                let is_union = annotation
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "|");
                if is_union {
                    pending.extend(
                        [
                            annotation.child_by_field_name("left"),
                            annotation.child_by_field_name("right"),
                        ]
                        .into_iter()
                        .flatten(),
                    );
                }
            }
            "subscript" | "generic_type" => {
                let Some((base, arguments)) = python_generic_type_arguments(annotation) else {
                    continue;
                };
                if python_annotation_union_or_optional_base(workspace, file, prepared, base) {
                    pending.extend(arguments);
                }
            }
            "parenthesized_expression" => {
                pending.extend(annotation.named_child(0));
            }
            _ => {}
        }
    }
    false
}

fn python_annotation_expression(mut node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "type" {
        node = node.named_child(0)?;
    }
    Some(node)
}

fn python_simple_type_identifier<'tree>(mut node: Node<'tree>, source: &str) -> Option<String> {
    while node.kind() == "type" {
        node = node.named_child(0)?;
    }
    (node.kind() == "identifier")
        .then(|| node.utf8_text(source.as_bytes()).ok().map(str::to_owned))
        .flatten()
}

fn python_type_parameter_declaration<'tree>(
    mut parameter: Node<'tree>,
    source: &str,
) -> Option<(String, Option<Node<'tree>>)> {
    while parameter.kind() == "type" {
        parameter = parameter.named_child(0)?;
    }
    if parameter.kind() == "constrained_type" {
        let mut cursor = parameter.walk();
        let mut children = parameter.named_children(&mut cursor);
        let name = python_simple_type_identifier(children.next()?, source)?;
        return Some((name, children.next()));
    }
    Some((python_simple_type_identifier(parameter, source)?, None))
}

/// `Some(None)` marks an unbounded PEP 695 parameter and shadows outer bounds.
fn python_type_parameter_bound<'tree>(
    context: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Option<Node<'tree>>> {
    let mut scope = Some(context);
    while let Some(node) = scope {
        if matches!(node.kind(), "class_definition" | "function_definition")
            && let Some(parameters) = node.child_by_field_name("type_parameters")
        {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if let Some((candidate, bound)) =
                    python_type_parameter_declaration(parameter, source)
                    && candidate == name
                {
                    return Some(bound);
                }
            }
        }
        scope = node.parent();
    }
    None
}

fn python_type_variable_bound_seed(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    context: Node<'_>,
    variable: Node<'_>,
) -> Option<ClassSeed> {
    let name = python_simple_type_identifier(variable, prepared.source())?;
    let bound = python_type_parameter_bound(context, &name, prepared.source())?;
    Some(match bound {
        Some(bound) => {
            let seed =
                resolve_class_at_span(workspace, file.clone(), span_for_node(bound), prepared);
            let seed = if matches!(
                &seed,
                ClassSeed::Class(_)
                    | ClassSeed::Classes(_)
                    | ClassSeed::ClassWithOpenBound(_)
                    | ClassSeed::ClassesWithOpenBound(_)
                    | ClassSeed::Unknown(UnknownReason::SemanticBudget)
            ) {
                seed
            } else {
                python_workspace_class_candidate(workspace, file, prepared, bound)
                    .map(ClassSeed::Class)
                    .unwrap_or(seed)
            };
            python_open_type_variable_seed(seed)
        }
        None => ClassSeed::NotApplicable,
    })
}

fn python_first_generic_type_argument(annotation: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let (base, mut arguments) = python_generic_type_arguments(annotation)?;
    Some((base, arguments.drain(..).next()?))
}

fn python_generic_type_arguments(annotation: Node<'_>) -> Option<(Node<'_>, Vec<Node<'_>>)> {
    let annotation = python_annotation_expression(annotation)?;
    match annotation.kind() {
        "generic_type" => {
            let mut cursor = annotation.walk();
            let mut children = annotation.named_children(&mut cursor);
            let base = children.next()?;
            let type_arguments = children.next()?;
            let mut cursor = type_arguments.walk();
            let arguments = type_arguments.named_children(&mut cursor).collect();
            Some((base, arguments))
        }
        "subscript" => {
            let base = annotation.child_by_field_name("value")?;
            let arguments = annotation.child_by_field_name("subscript")?;
            let arguments = if arguments.kind() == "tuple" {
                let mut cursor = arguments.walk();
                arguments.named_children(&mut cursor).collect()
            } else {
                vec![arguments]
            };
            Some((base, arguments))
        }
        _ => None,
    }
}

fn python_type_object_argument_bound_seed(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    context: Node<'_>,
    annotation: Node<'_>,
) -> Option<ClassSeed> {
    let (base, argument) = python_first_generic_type_argument(annotation)?;
    let base = match resolve_class_at_span(workspace, file.clone(), span_for_node(base), prepared) {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => class,
        _ => return None,
    };
    if base.qualified_name() != "builtins.type" {
        return None;
    }
    Some(
        python_type_variable_bound_seed(workspace, file, prepared, context, argument)
            .unwrap_or_else(|| {
                python_open_type_variable_seed(resolve_class_at_span(
                    workspace,
                    file.clone(),
                    span_for_node(argument),
                    prepared,
                ))
            }),
    )
}

fn python_open_type_variable_seed(seed: ClassSeed) -> ClassSeed {
    match python_dynamic_any_seed(seed) {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => {
            ClassSeed::ClassWithOpenBound(class)
        }
        ClassSeed::Classes(classes) | ClassSeed::ClassesWithOpenBound(classes) => {
            ClassSeed::classes_with_open_bound(classes.into_vec())
        }
        seed => seed,
    }
}

fn python_parameter_type_node<'tree>(
    callable: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let layout = formal_parameter_slots_for_owner(Language::Python, callable, source)?;
    let slot = layout
        .slots
        .iter()
        .find(|slot| slot.unique_name() == Some(name))?;
    let declaration = callable
        .named_descendant_for_byte_range(
            slot.declaration_range.start_byte,
            slot.declaration_range.end_byte,
        )
        .unwrap_or(callable);
    matches!(
        declaration.kind(),
        "typed_parameter" | "typed_default_parameter"
    )
    .then(|| declaration.child_by_field_name("type"))
    .flatten()
}

fn python_callable_binding_is_stable(callable: Node<'_>, name: &str, source: &str) -> bool {
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let Some(inventory) =
        python_lexical_scope_inventory_bounded(callable, source, || session.scope_step())
    else {
        return false;
    };
    if inventory
        .local_bindings()
        .any(|(binding, _)| binding == name)
    {
        return false;
    }
    let mut pending = vec![callable];
    while let Some(node) = pending.pop() {
        if !session.scope_step() {
            return false;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if node.kind() == "nonlocal_statement"
                && child.kind() == "identifier"
                && child.utf8_text(source.as_bytes()).ok() == Some(name)
            {
                return false;
            }
            if !session.scope_step() {
                return false;
            }
            pending.push(child);
        }
    }
    true
}

#[derive(Clone, Copy)]
enum PythonDynamicWriteReceiver<'tree> {
    Expression(Node<'tree>),
    ZeroArgSuper(Node<'tree>),
}

fn python_dynamic_write_receiver<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<PythonDynamicWriteReceiver<'tree>> {
    if node.kind() == "call" {
        let function = node.child_by_field_name("function")?;
        if function.kind() == "identifier"
            && function.utf8_text(source.as_bytes()).ok() == Some("delattr")
        {
            let arguments = node.child_by_field_name("arguments")?;
            let mut cursor = arguments.walk();
            return arguments
                .named_children(&mut cursor)
                .find(|argument| !argument.is_extra())
                .map(PythonDynamicWriteReceiver::Expression);
        }
        if setattr_write(node, source).is_some() {
            let arguments = node.child_by_field_name("arguments")?;
            let mut cursor = arguments.walk();
            return arguments
                .named_children(&mut cursor)
                .find(|argument| !argument.is_extra())
                .map(PythonDynamicWriteReceiver::Expression);
        }
        if function.kind() != "attribute" {
            return None;
        }
        let attribute = function.child_by_field_name("attribute")?;
        let member = attribute.utf8_text(source.as_bytes()).ok()?;
        let object = function.child_by_field_name("object")?;
        if member == "__setattr__" && python_zero_arg_super_shape(object, source) {
            return Some(PythonDynamicWriteReceiver::ZeroArgSuper(object));
        }
        if object.kind() == "attribute"
            && object
                .child_by_field_name("attribute")
                .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                == Some("__dict__")
        {
            return object
                .child_by_field_name("object")
                .map(PythonDynamicWriteReceiver::Expression);
        }
        if member == "__setattr__" {
            return Some(PythonDynamicWriteReceiver::Expression(object));
        }
    }
    if matches!(node.kind(), "assignment" | "augmented_assignment")
        && dictionary_write(node, source).is_some()
    {
        let receiver = node
            .child_by_field_name("left")
            .and_then(|left| left.child_by_field_name("value"))
            .and_then(|dictionary| dictionary.child_by_field_name("object"))?;
        return Some(PythonDynamicWriteReceiver::Expression(receiver));
    }
    None
}

fn python_zero_arg_super_shape(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "call"
        || node.child_by_field_name("function").is_none_or(|function| {
            function.kind() != "identifier"
                || function.utf8_text(source.as_bytes()).ok() != Some("super")
        })
    {
        return false;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .all(|argument| argument.is_extra())
}

fn python_zero_arg_super(
    workspace: &WorkspaceAnalyzer,
    call: Node<'_>,
    prepared: &PreparedSyntaxTree,
) -> bool {
    python_zero_arg_super_shape(call, prepared.source())
        && call
            .child_by_field_name("function")
            .is_some_and(|function| {
                indexed_builtin_is_unshadowed(python_analyzer(workspace), function, prepared)
                    == Some(true)
            })
}

fn python_dynamic_write_method_receiver_bound(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
    receiver: PythonDynamicWriteReceiver<'_>,
    method_has_receiver: bool,
    first_parameter: Option<&str>,
) -> Option<ClassIdentity> {
    match receiver {
        PythonDynamicWriteReceiver::ZeroArgSuper(call) => (method_has_receiver
            && python_zero_arg_super(workspace, call, prepared)
            && adapter.receiver_binding_is_stable(workspace, procedure))
        .then(|| adapter.enclosing_class(workspace, procedure))
        .flatten(),
        PythonDynamicWriteReceiver::Expression(expression)
            if expression.kind() == "identifier"
                && first_parameter == expression.utf8_text(prepared.source().as_bytes()).ok() =>
        {
            (adapter.receiver_binding_is_stable(workspace, procedure))
                .then(|| adapter.enclosing_class(workspace, procedure))
                .flatten()
        }
        PythonDynamicWriteReceiver::Expression(_) => None,
    }
}

fn python_dynamic_write_parameter_bound(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    callable: Node<'_>,
    receiver: PythonDynamicWriteReceiver<'_>,
) -> Option<ClassIdentity> {
    let PythonDynamicWriteReceiver::Expression(receiver) = receiver else {
        return None;
    };
    if receiver.kind() != "identifier" {
        return None;
    }
    let name = receiver.utf8_text(prepared.source().as_bytes()).ok()?;
    if !python_callable_binding_is_stable(callable, name, prepared.source()) {
        return None;
    }
    let annotation = python_parameter_type_node(callable, name, prepared.source())?;
    match adapter.annotation_class_seed(workspace, file, prepared, callable, annotation) {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => Some(class),
        _ => None,
    }
}

fn python_dynamic_write_receiver_field(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    callable: Node<'_>,
    prepared: &PreparedSyntaxTree,
    receiver: PythonDynamicWriteReceiver<'_>,
) -> Option<(ClassIdentity, Box<str>)> {
    let PythonDynamicWriteReceiver::Expression(receiver) = receiver else {
        return None;
    };
    if receiver.kind() != "attribute" {
        return None;
    }
    let semantics = procedure.semantics();
    let layout = formal_parameter_slots_for_owner(Language::Python, callable, prepared.source())?;
    let method_has_receiver =
        matches!(
            semantics.kind(),
            ProcedureKind::Method | ProcedureKind::Constructor
        ) && !matches!(layout.python_binding, Some(PythonMethodBinding::Static));
    let first_parameter =
        method_has_receiver.then(|| python_first_parameter_name(callable, prepared.source()))??;
    let object = receiver.child_by_field_name("object")?;
    if object.kind() != "identifier"
        || object.utf8_text(prepared.source().as_bytes()).ok() != Some(first_parameter.as_str())
        || !adapter.receiver_binding_is_stable(workspace, procedure)
    {
        return None;
    }
    let member = receiver
        .child_by_field_name("attribute")?
        .utf8_text(prepared.source().as_bytes())
        .ok()?;
    Some((
        adapter.enclosing_class(workspace, procedure)?,
        member.into(),
    ))
}

fn python_class_seed_bounds(seed: ClassSeed) -> Result<Vec<ClassIdentity>, UnknownReason> {
    match seed {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => Ok(vec![class]),
        ClassSeed::Classes(classes) | ClassSeed::ClassesWithOpenBound(classes) => {
            Ok(classes.into_vec())
        }
        ClassSeed::Unknown(reason) => Err(reason),
        ClassSeed::NotApplicable => Err(UnknownReason::UncertainFlow),
    }
}

fn python_field_store_value_bounds(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    span: SourceSpan,
    member: &str,
) -> Result<Option<Vec<ClassIdentity>>, UnknownReason> {
    let Some(value) = node_at_span(prepared, span) else {
        return Err(UnknownReason::UncertainFlow);
    };
    let mut ancestor = Some(value);
    let mut assignment = None;
    while let Some(node) = ancestor {
        if node.kind() == "assignment"
            && let Some(right) = node.child_by_field_name("right")
            && right.start_byte() <= value.start_byte()
            && value.end_byte() <= right.end_byte()
        {
            assignment = Some((node, right));
            break;
        }
        if matches!(node.kind(), "function_definition" | "class_definition") {
            break;
        }
        ancestor = node.parent();
    }
    let Some((assignment, right)) = assignment else {
        return Ok(None);
    };
    let Some(left) = assignment.child_by_field_name("left") else {
        return Err(UnknownReason::UncertainFlow);
    };
    let Some(left_member) = left
        .child_by_field_name("attribute")
        .and_then(|node| node.utf8_text(prepared.source().as_bytes()).ok())
    else {
        return Ok(None);
    };
    if left_member != member {
        return Ok(None);
    }
    let Some(callable) = enclosing_function_definition(assignment) else {
        return Err(UnknownReason::UncertainFlow);
    };
    let receiver = left.child_by_field_name("object");
    let first_parameter = python_first_parameter_name(callable, prepared.source());
    if receiver.is_none_or(|receiver| {
        receiver.kind() != "identifier"
            || first_parameter.as_deref() != receiver.utf8_text(prepared.source().as_bytes()).ok()
    }) {
        return Err(UnknownReason::UncertainFlow);
    }
    if runtime_created_type_expression(workspace, file, prepared, callable, right) {
        return Ok(Some(Vec::new()));
    }
    if let Some(name) = python_simple_type_identifier(right, prepared.source())
        && let Some(annotation) = python_parameter_type_node(callable, &name, prepared.source())
    {
        if !python_callable_binding_is_stable(callable, &name, prepared.source()) {
            return Err(UnknownReason::UncertainFlow);
        }
        let seed = adapter.annotation_class_seed(workspace, file, prepared, callable, annotation);
        return python_class_seed_bounds(seed).map(Some);
    }
    let seed = python_workspace_class_candidate(workspace, file, prepared, right)
        .map(ClassSeed::Class)
        .unwrap_or_else(|| {
            resolve_class_at_span(workspace, file.clone(), span_for_node(right), prepared)
        });
    python_class_seed_bounds(seed).map(Some)
}

fn python_dynamic_write_parameter_is_explicitly_unbounded(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    callable: Node<'_>,
    receiver: PythonDynamicWriteReceiver<'_>,
) -> bool {
    let PythonDynamicWriteReceiver::Expression(receiver) = receiver else {
        return false;
    };
    if receiver.kind() != "identifier" {
        return false;
    }
    let Some(name) = receiver.utf8_text(prepared.source().as_bytes()).ok() else {
        return false;
    };
    if !python_callable_binding_is_stable(callable, name, prepared.source()) {
        return false;
    }
    let Some(annotation) = python_parameter_type_node(callable, name, prepared.source()) else {
        return false;
    };
    let Some(annotation) = python_annotation_expression(annotation) else {
        return false;
    };
    if let Some(variable) = python_simple_type_identifier(annotation, prepared.source())
        && python_type_parameter_bound(callable, &variable, prepared.source()) == Some(None)
    {
        return true;
    }
    match resolve_class_at_span(workspace, file.clone(), span_for_node(annotation), prepared) {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => python_any_class(&class),
        ClassSeed::Classes(classes) | ClassSeed::ClassesWithOpenBound(classes) => {
            classes.iter().any(python_any_class)
        }
        ClassSeed::Unknown(_) | ClassSeed::NotApplicable => false,
    }
}

fn python_dynamic_write_iteration_element_bound(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    callable: Node<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    receiver: PythonDynamicWriteReceiver<'_>,
) -> Option<ClassIdentity> {
    let PythonDynamicWriteReceiver::Expression(receiver) = receiver else {
        return None;
    };
    let receiver_name = python_simple_type_identifier(receiver, prepared.source())?;
    let mut ancestor = receiver.parent();
    let mut target = None;
    while let Some(node) = ancestor {
        if node.kind() == "for_statement"
            && let Some(candidate) = node.child_by_field_name("left")
            && candidate.kind() == "identifier"
            && candidate.utf8_text(prepared.source().as_bytes()).ok()
                == Some(receiver_name.as_str())
        {
            target = Some(candidate);
            break;
        }
        if matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        ) && node.id() != callable.id()
        {
            break;
        }
        ancestor = node.parent();
    }
    let target = target?;
    if !python_iteration_target_binding_is_stable(
        callable,
        target,
        &receiver_name,
        receiver.start_byte(),
        prepared.source(),
    ) {
        return None;
    }
    let seed = adapter.iteration_element_class_seed(workspace, procedure, file, prepared, target);
    match seed {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => Some(class),
        _ => None,
    }
}

/// Keep the loop element bound only while its binder still names the current
/// receiver at the dynamic write. Other bindings before the write invalidate
/// the simple structural proof.
fn python_iteration_target_binding_is_stable(
    callable: Node<'_>,
    target: Node<'_>,
    receiver_name: &str,
    receiver_start: usize,
    source: &str,
) -> bool {
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let mut pending = vec![callable];
    while let Some(node) = pending.pop() {
        let nested_scope = node.id() != callable.id()
            && matches!(
                node.kind(),
                "function_definition" | "class_definition" | "lambda"
            );
        let can_bind = matches!(
            node.kind(),
            "assignment"
                | "augmented_assignment"
                | "type_alias_statement"
                | "named_expression"
                | "for_statement"
                | "delete_statement"
                | "as_pattern"
                | "except_clause"
                | "case_clause"
                | "import_statement"
                | "import_from_statement"
                | "function_definition"
                | "class_definition"
        );
        if can_bind
            && (!nested_scope || matches!(node.kind(), "function_definition" | "class_definition"))
        {
            let Some(bindings) =
                python_direct_scope_bindings_bounded(node, source, || session.scope_step())
            else {
                return false;
            };
            if bindings.iter().any(|binding| {
                binding.declaration.id() != target.id()
                    && binding.declaration.start_byte() < receiver_start
                    && binding.declaration.utf8_text(source.as_bytes()).ok() == Some(receiver_name)
            }) {
                return false;
            }
        }
        if nested_scope {
            continue;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    true
}

fn python_dynamic_write_stored_type_field_bound(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    procedure: &ProcedureHandle,
    callable: Node<'_>,
    receiver: PythonDynamicWriteReceiver<'_>,
) -> Option<ClassIdentity> {
    let PythonDynamicWriteReceiver::Expression(receiver) = receiver else {
        return None;
    };
    let semantics = procedure.semantics();
    let layout = formal_parameter_slots_for_owner(Language::Python, callable, prepared.source())?;
    let method_has_receiver =
        matches!(
            semantics.kind(),
            ProcedureKind::Method | ProcedureKind::Constructor
        ) && !matches!(layout.python_binding, Some(PythonMethodBinding::Static));
    if !method_has_receiver || receiver.kind() != "attribute" {
        return None;
    }
    let object = receiver.child_by_field_name("object")?;
    let first_parameter = python_first_parameter_name(callable, prepared.source())?;
    if object.kind() != "identifier"
        || object.utf8_text(prepared.source().as_bytes()).ok() != Some(first_parameter.as_str())
        || !adapter.receiver_binding_is_stable(workspace, procedure)
    {
        return None;
    }
    let field = receiver
        .child_by_field_name("attribute")?
        .utf8_text(prepared.source().as_bytes())
        .ok()?;
    let ClassIdentity::Workspace(owner) = adapter.enclosing_class(workspace, procedure)? else {
        return None;
    };
    let class = class_node_for_unit(python_analyzer(workspace), prepared, &owner)?;
    let (initializer, parameter) = python_stored_type_field_parameter(class, field, prepared)?;
    if !python_callable_binding_is_stable(initializer, &parameter, prepared.source()) {
        return None;
    }
    let annotation = python_parameter_type_node(initializer, &parameter, prepared.source())?;
    match adapter.annotation_class_seed(workspace, file, prepared, initializer, annotation) {
        ClassSeed::Class(class) | ClassSeed::ClassWithOpenBound(class) => Some(class),
        _ => None,
    }
}

fn python_stored_type_field_parameter<'tree>(
    class: Node<'tree>,
    field: &str,
    prepared: &PreparedSyntaxTree,
) -> Option<(Node<'tree>, String)> {
    let body = class.child_by_field_name("body")?;
    let source = prepared.source();
    let mut members = body.walk();
    let mut initializer = None;
    let mut parameter = None;
    for member in body.named_children(&mut members) {
        if assignment_name(member, source) == Some(field) {
            return None;
        }
        let definition = if member.kind() == "decorated_definition" {
            let mut cursor = member.walk();
            member
                .named_children(&mut cursor)
                .find(|child| child.kind() == "function_definition")?
        } else {
            member
        };
        if definition.kind() != "function_definition" {
            continue;
        }
        let method_name = definition_name(definition, source)?;
        let method_receiver = python_first_parameter_name(definition, source)?;
        let Some(method_body) = definition.child_by_field_name("body") else {
            continue;
        };
        let mut pending = vec![method_body];
        while let Some(node) = pending.pop() {
            if node.id() != method_body.id()
                && matches!(
                    node.kind(),
                    "function_definition" | "class_definition" | "lambda"
                )
            {
                continue;
            }
            if node.kind() == "augmented_assignment"
                && node
                    .child_by_field_name("left")
                    .and_then(|left| left.child_by_field_name("attribute"))
                    .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                    == Some(field)
            {
                return None;
            }
            if node.kind() == "assignment"
                && let Some(left) = node.child_by_field_name("left")
                && left.kind() == "attribute"
                && left
                    .child_by_field_name("attribute")
                    .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
                    == Some(field)
            {
                let object = left.child_by_field_name("object")?;
                let value = node.child_by_field_name("right")?;
                if method_name != "__init__"
                    || object.kind() != "identifier"
                    || object.utf8_text(source.as_bytes()).ok() != Some(method_receiver.as_str())
                    || initializer.is_some()
                    || value.kind() != "identifier"
                {
                    return None;
                }
                initializer = Some(definition);
                parameter = Some(value.utf8_text(source.as_bytes()).ok()?.to_owned());
            }
            if node.kind() == "call"
                && let Some(PythonDynamicWriteReceiver::Expression(receiver)) =
                    python_dynamic_write_receiver(node, source)
                && receiver.kind() == "identifier"
                && receiver.utf8_text(source.as_bytes()).ok() == Some(method_receiver.as_str())
                && let Some(write) = dynamic_call_write(node, source)
                && dynamic_member_name_affects(&write, field)
            {
                return None;
            }
            if node.kind() == "call"
                && matches!(
                    python_dynamic_write_receiver(node, source),
                    Some(PythonDynamicWriteReceiver::ZeroArgSuper(_))
                )
                && let Some(write) = dynamic_call_write(node, source)
                && dynamic_member_name_affects(&write, field)
            {
                return None;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
    }
    Some((initializer?, parameter?))
}

#[derive(Debug)]
enum PythonExactAccess {
    Attribute(Box<str>),
    Subscript,
}

struct PythonExactAccessStep {
    access: PythonExactAccess,
}

fn python_exact_value_class_at(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    mut value: ValueId,
    mut use_point: ProgramPointId,
    mut use_event_index: usize,
) -> Option<Box<[ClassIdentity]>> {
    const MAX_ORIGIN_STEPS: usize = 128;

    let semantics = procedure.semantics();
    let bindings = BindingOriginIndex::new(procedure);
    let mut visited = HashSet::default();
    let mut accesses = Vec::new();
    let mut origin_class = None;
    for _ in 0..MAX_ORIGIN_STEPS {
        if !visited.insert(value) {
            return None;
        }
        let calls = semantics
            .call_sites()
            .iter()
            .filter(|call| call.normal_result_values().any(|result| result == value))
            .collect::<Vec<_>>();
        if let [call] = calls.as_slice() {
            origin_class = PythonTypeFlowAdapter
                .exact_call_result_class(workspace, procedure, call)
                .or_else(|| {
                    match PythonTypeFlowAdapter.constructed_class(workspace, procedure, call) {
                        ClassSeed::Class(class @ ClassIdentity::External { .. }) => {
                            Some(vec![class].into_boxed_slice())
                        }
                        _ => None,
                    }
                });
            break;
        }
        if !calls.is_empty() {
            return None;
        }

        let loads = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point
                    .events
                    .iter()
                    .enumerate()
                    .filter_map(move |(event_index, event)| {
                        let SemanticEffect::MemoryLoad {
                            location, result, ..
                        } = event.effect
                        else {
                            return None;
                        };
                        (result == value).then_some((point.id, event_index, location, event.source))
                    })
            })
            .collect::<Vec<_>>();
        if let [(point, event_index, location, source)] = loads.as_slice() {
            let mapping = semantics.source_mapping(*source)?;
            if mapping.kind != SourceMappingKind::Exact {
                return None;
            }
            let file = file_for_locator(workspace, &mapping.locator)?;
            let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
            let node = node_at_span(&prepared, mapping.locator.anchor().span())?;
            let location_row = semantics.memory_location(*location)?;
            let (base, access, base_node) = match &location_row.kind {
                MemoryLocationKind::Field { base, .. }
                | MemoryLocationKind::Property { base, .. }
                    if node.kind() == "attribute" =>
                {
                    let attribute = node.child_by_field_name("attribute")?;
                    let object = node.child_by_field_name("object")?;
                    (
                        *base,
                        PythonExactAccess::Attribute(Box::from(
                            attribute.utf8_text(prepared.source().as_bytes()).ok()?,
                        )),
                        object,
                    )
                }
                MemoryLocationKind::Index { base, .. }
                | MemoryLocationKind::Property { base, .. }
                    if node.kind() == "subscript" =>
                {
                    let value_node = node.child_by_field_name("value")?;
                    node.child_by_field_name("subscript")?;
                    (*base, PythonExactAccess::Subscript, value_node)
                }
                _ => return None,
            };
            let base_value = semantics.value(base)?;
            let base_mapping = semantics.source_mapping(base_value.source)?;
            if base_mapping.kind != SourceMappingKind::Exact
                || file_for_locator(workspace, &base_mapping.locator).as_ref() != Some(&file)
                || base_mapping.locator.anchor().span() != span_for_node(base_node)
            {
                return None;
            }
            accesses.push(PythonExactAccessStep { access });
            value = base;
            use_point = *point;
            use_event_index = *event_index;
            continue;
        }
        if !loads.is_empty() {
            return None;
        }

        if !matches!(
            semantics.value(value).map(|value| &value.kind),
            Some(SemanticValueKind::Local | SemanticValueKind::Temporary)
        ) || !constructor_receiver_is_local_identifier(workspace, procedure, value)
        {
            return None;
        }
        let binding = bindings.unique_binding_origin(value)?;
        if !matches!(
            semantics.value(binding).map(|value| &value.kind),
            Some(SemanticValueKind::Local)
        ) {
            return None;
        }
        value = python_unique_reaching_binding_assignment_at(
            procedure,
            binding,
            use_point,
            use_event_index,
        )?;
    }
    let mut classes = origin_class?;
    for step in accesses.iter().rev() {
        let returned = classes
            .iter()
            .map(|class| python_exact_access_return_classes(workspace, class, &step.access))
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let ClassSeed::Classes(next) = ClassSeed::classes(returned) else {
            unreachable!("an exact access result has at least one runtime class")
        };
        classes = next;
    }
    Some(classes)
}

fn python_exact_access_return_classes(
    workspace: &WorkspaceAnalyzer,
    receiver_class: &ClassIdentity,
    access: &PythonExactAccess,
) -> Option<Box<[ClassIdentity]>> {
    let ClassIdentity::External { symbol_id, .. } = receiver_class else {
        return None;
    };
    let overlay = workspace.analyzer().semantic_model_overlay()?;
    let (member, declared_name) = match access {
        PythonExactAccess::Subscript => ("__getitem__", None),
        PythonExactAccess::Attribute(name) => {
            let declared = python_external_member_is_declared_in_mro(&overlay, symbol_id, name)?;
            if declared {
                return python_external_declared_property_return_classes(
                    workspace,
                    receiver_class,
                    &overlay,
                    symbol_id,
                    name,
                );
            }
            ("__getattr__", Some(name.as_ref()))
        }
    };
    let declaration = python_external_member_declaration(&overlay, symbol_id, member);
    let declaration = declaration?;
    let mutation_free = external_class_member_mutation_free(
        workspace,
        receiver_class,
        &ExternalMemberDeclaration::new([Box::from(declaration.id.as_str())]),
        declared_name.unwrap_or(member),
    );
    if declaration.exact_return_classes.is_empty() || !mutation_free {
        return None;
    }
    python_exact_return_classes(&overlay, declaration)
}

fn python_external_declared_property_return_classes(
    workspace: &WorkspaceAnalyzer,
    receiver_class: &ClassIdentity,
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> Option<Box<[ClassIdentity]>> {
    let mro = python_external_class_mro(overlay, owner_id)?;
    for class_id in mro {
        let class = exact_python_model_class(overlay, &class_id)?;
        if overlay
            .gapped_member_surface(&class.qualified_name, member)
            .is_some()
        {
            return None;
        }
        let mut records = overlay
            .members_of(&class_id)
            .records
            .into_iter()
            .filter(|symbol| {
                symbol.owner_id.as_deref() == Some(class_id.as_str())
                    && symbol.name == member
                    && symbol.language == Language::Python.config_label()
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            continue;
        }
        records.sort_by(|left, right| left.id.cmp(&right.id));
        records.dedup_by(|left, right| left.id == right.id);
        let [symbol] = records.as_slice() else {
            return None;
        };
        if symbol.kind != SemanticModelSymbolKind::Property {
            return None;
        }
        if symbol.exact_return_classes.is_empty()
            || !external_class_member_mutation_free(
                workspace,
                receiver_class,
                &ExternalMemberDeclaration::new([Box::from(symbol.id.as_str())]),
                member,
            )
        {
            return None;
        }
        return python_exact_return_classes(overlay, symbol);
    }
    None
}

fn python_external_member_is_declared_in_mro(
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> Option<bool> {
    let mro = python_external_class_mro(overlay, owner_id)?;
    for class_id in mro {
        let class = exact_python_model_class(overlay, &class_id)?;
        if overlay
            .gapped_member_surface(&class.qualified_name, member)
            .is_some()
        {
            return None;
        }
        if overlay
            .members_of(&class_id)
            .records
            .into_iter()
            .any(|symbol| {
                symbol.owner_id.as_deref() == Some(class_id.as_str())
                    && symbol.name == member
                    && symbol.language == Language::Python.config_label()
            })
        {
            return Some(true);
        }
    }
    Some(false)
}

fn python_exact_return_classes(
    overlay: &SemanticModelOverlay,
    symbol: &SemanticModelSymbol,
) -> Option<Box<[ClassIdentity]>> {
    if symbol.exact_return_classes.is_empty() || symbol.provenance.ambiguous {
        return None;
    }
    let mut cache = ExternalClassCache::default();
    let classes = symbol
        .exact_return_classes
        .iter()
        .map(|class| match class {
            TypeRef::Named {
                name,
                nullable: false,
                ..
            } => external_class_identity(Some(overlay), Language::Python, name, None, &mut cache),
            TypeRef::Declared {
                id,
                nullable: false,
                ..
            } => external_class_identity(Some(overlay), Language::Python, "", Some(id), &mut cache),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    // typing.Any is not a runtime class, so a claim that names it is not a
    // closed class set.
    if classes.iter().any(python_any_class) {
        return None;
    }
    let ClassSeed::Classes(classes) = ClassSeed::classes(classes) else {
        unreachable!("an exact return claim names at least one class")
    };
    Some(classes)
}

impl TypeFlowAdapter for PythonTypeFlowAdapter {
    fn language(&self) -> Language {
        Language::Python
    }

    fn semantics_version(&self) -> AdapterSemanticsVersion {
        // Keep cached class sets in step with program-point refinement,
        // guard remainders, scoped writes, open builtin call results, the
        // class-object remainder a declared or imported class reference
        // seeds, the classes a guard's true arm now proves about a
        // remainder, the arm-proven classes that now reach the guard's
        // reconvergence instead of ending there, and the class-body binding
        // a member name resolves to, the dependency class a bare
        // import-bound base denotes, the source root a by-name import
        // resolves its module in, and the module an absolute import written
        // against a source root below the project root names -- now only when
        // the workspace's own packaging declaration or package chain
        // establishes that root, so the class sets that used to come from a
        // bare tail match are no longer reported -- and now with a packaging
        // declaration of the project root counting as a declaration like any
        // other, so the shorter spellings it rules out no longer carry class
        // sets either -- and with a spelling below a declared root admitted
        // only when the package it starts from states that the repeated
        // directory is on its `__path__`, so a nested name a marker never
        // extends no longer carries the classes of the file it merely
        // resembles. The statement has to be one the interpreter runs and
        // keeps, so an append behind `if False:` or one a later `__path__`
        // assignment replaces no longer carries them either, and the
        // membership guard it hangs under has to be module-level, so a guard
        // inside an enclosing dead branch no longer carries them. Resolved
        // method returns lose certainty only for actual instance hooks or
        // unresolved modeled ancestry; partial member surfaces alone are safe
        // when no modeled __getattribute__ hook exists.
        // Variadic formals retain their tuple or dict container class instead
        // of taking the class of an element collected from a caller.
        // An annotation or modeled return containing typing.Any remains an
        // unknown value because Any is not a runtime class.
        // Conditional absent-member findings may use a declared parameter
        // only when its exact annotation proves one closed workspace class,
        // without workspace descendants, unresolved bases, dynamic hooks,
        // Protocol ancestry, or abstract members.
        AdapterSemanticsVersion::hash_bytes(
            "python-type-flow",
            b"python-type-flow-unmodeled-guards-scoped-dynamic-writes-dict-read-methods-bounded-receiver-scopes-subscripted-annotation-outer-class-class-object-reference-imports-unmodeled-predicate-type-is-guard-exact-binding-replacement-stable-receiver-entry-implicit-tuples-closed-native-members-sequence-initializers-module-binding-reuse-comprehension-scope-closed-sequence-loads-implicit-none-returns-returned-sequence-loads-arm-proven-classes-reach-joins-class-body-member-binding-import-bound-bases-importing-source-root-established-source-root-modules-declared-project-root-authority-package-path-extension-executed-typed-numeric-literals-partial-modeled-surface-hook-safety-variadic-container-classes-dynamic-write-name-sets-structured-dynamic-receiver-type-parameter-bounds-dynamic-type-write-bounds-nonescaping-nested-write-bounds-runtime-created-class-exclusion-loop-name-list-bounds-postponed-and-type-checking-annotation-bounds-field-slot-class-value-bounds-quoted-receiver-annotation-name-resolution-field-content-deletion-receivers-declared-parameter-conditional-closed-world-property-descriptor-field-slots-v77-external-module-value-types-exact-constructor-instance-dispatch-python-c3-class-member-replacement-scan-rql-inherited-external-member-exact-factory-and-access-return-class-sets-stable-local-multi-target-flow-dynamic-any-is-not-a-runtime-class-uncertain-constructor-call-shapes-once-bound-module-global-initializer-class-seeds",
        )
        .expect("adapter name is non-empty")
    }

    fn computed_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        let mapping = procedure
            .semantics()
            .source_mapping(value.source)
            .expect("a computed value retains a source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        };
        let name = match node.kind() {
            "call" => {
                let Some(function) = node.child_by_field_name("function") else {
                    return ClassSeed::Unknown(UnknownReason::UncertainFlow);
                };
                let is_builtin_str = function.kind() == "identifier"
                    && function.utf8_text(prepared.source().as_bytes()).ok() == Some("str")
                    && is_python_builtin_or_constant("str")
                    && indexed_builtin_is_unshadowed(
                        python_analyzer(workspace),
                        function,
                        &prepared,
                    ) == Some(true);
                if is_builtin_str {
                    "builtins.str"
                } else {
                    return ClassSeed::NotApplicable;
                }
            }
            "not_operator" => "builtins.bool",
            "string" | "concatenated_string" => python_string_literal_class(node, &prepared),
            "boolean_operator" | "binary_operator" | "unary_operator" => {
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            }
            _ => return ClassSeed::NotApplicable,
        };
        let mut cache = ExternalClassCache::default();
        external_seed(
            workspace.analyzer().semantic_model_overlay().as_deref(),
            name,
            &mut cache,
        )
    }

    fn retained_value_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        // Implicit scalars carry their value in IR. Their source anchors need
        // not name a literal: fallthrough None names the completed body.
        let implicit_class = match value.kind {
            SemanticValueKind::Null => Some("types.NoneType"),
            SemanticValueKind::UnsignedInteger(_) | SemanticValueKind::SignedInteger(_) => {
                Some("builtins.int")
            }
            SemanticValueKind::FloatingPoint { .. } => Some("builtins.float"),
            _ => None,
        };
        if let Some(name) = implicit_class {
            let mut cache = ExternalClassCache::default();
            return external_seed(
                workspace.analyzer().semantic_model_overlay().as_deref(),
                name,
                &mut cache,
            );
        }
        let mapping = procedure
            .semantics()
            .source_mapping(value.source)
            .expect("a retained value retains a source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::NotApplicable;
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        if let Some((module, member)) =
            import_bound_external_symbol(python_analyzer(workspace), &file, &prepared, node)
            && let Some(overlay) = workspace.analyzer().semantic_model_overlay()
            && let Some(seed) = external_module_value_seed(&overlay, &module, &member)
        {
            return seed;
        }
        if matches!(
            &value.kind,
            SemanticValueKind::LanguageDefined(kind)
                if kind.as_ref() == "python.unknown_iteration_element"
        ) {
            return self.iteration_element_class_seed(workspace, procedure, &file, &prepared, node);
        }
        if matches!(value.kind, SemanticValueKind::DefaultArgument { .. }) {
            // A saved default is not evaluated in the callee. In particular,
            // identifiers must not be interpreted as reads of its parameters
            // or locals, and container defaults are not fresh allocations.
            let literal = self.constant_class(workspace, procedure, value);
            if !matches!(literal, ClassSeed::NotApplicable) {
                return literal;
            }
            let container = match node.kind() {
                "list" => Some("builtins.list"),
                "dictionary" => Some("builtins.dict"),
                "tuple" => Some("builtins.tuple"),
                "set" => Some("builtins.set"),
                _ => None,
            };
            if let Some(name) = container {
                let mut cache = ExternalClassCache::default();
                return external_seed(
                    workspace.analyzer().semantic_model_overlay().as_deref(),
                    name,
                    &mut cache,
                );
            }
            if node.kind() == "call"
                && let Some(function) = node.child_by_field_name("function")
            {
                // A constructor's name must denote the same class at
                // definition time. Do not resolve a factory, a rebound name,
                // or a name captured from an enclosing callable as a class.
                let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
                if function.kind() != "identifier" {
                    return ClassSeed::Unknown(UnknownReason::UncertainFlow);
                }
                let Ok(name) = function.utf8_text(prepared.source().as_bytes()) else {
                    return ClassSeed::Unknown(UnknownReason::UncertainFlow);
                };
                if module_binding(workspace, &prepared, name, &session)
                    != Some(Some(PythonDirectScopeBindingKind::ClassDeclaration))
                {
                    return ClassSeed::Unknown(UnknownReason::UncertainFlow);
                }
                let mut ancestor = node.parent();
                let mut defining_callable_seen = false;
                while let Some(scope) = ancestor {
                    if !session.scope_step() {
                        return ClassSeed::Unknown(UnknownReason::SemanticBudget);
                    }
                    match scope.kind() {
                        "function_definition" | "lambda" if !defining_callable_seen => {
                            defining_callable_seen = true;
                        }
                        "function_definition" | "lambda" => {
                            let Some(inventory) = python_lexical_scope_inventory_bounded(
                                scope,
                                prepared.source(),
                                || session.scope_step(),
                            ) else {
                                return ClassSeed::Unknown(UnknownReason::SemanticBudget);
                            };
                            if !matches!(
                                inventory.name_resolution_at(name, node),
                                PythonLexicalNameResolution::Unbound
                            ) {
                                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
                            }
                        }
                        "class_definition"
                            if python_module_or_class_scope_binds_name_bounded(
                                scope,
                                name,
                                prepared.source(),
                                || session.scope_step(),
                            ) != Some(false) =>
                        {
                            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
                        }
                        _ => {}
                    }
                    ancestor = scope.parent();
                }
                let seed =
                    resolve_class_at_span(workspace, file, span_for_node(function), &prepared);
                if let ClassSeed::Class(class @ ClassIdentity::Workspace(owner)) = &seed {
                    let hierarchy = self.class_hierarchy(workspace, class);
                    let overlay = workspace.analyzer().semantic_model_overlay();
                    if !hierarchy.unresolved_base
                        && python_class_hierarchy_member_unshadowed_bounded(
                            python_analyzer(workspace),
                            owner,
                            "__class__",
                        ) == Some(true)
                        && self.guard_classes_have_supported_instance_checks(
                            workspace,
                            std::slice::from_ref(class),
                            overlay.as_deref(),
                        )
                        && matches!(
                            self.member_lookup(workspace, MemberAccessKind::Call, class, "__new__"),
                            MemberLookup::Absent | MemberLookup::DeclarationAbsent
                        )
                    {
                        return seed;
                    }
                }
            }
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        }
        match node.kind() {
            "string" | "concatenated_string" => {
                let mut cache = ExternalClassCache::default();
                external_seed(
                    workspace.analyzer().semantic_model_overlay().as_deref(),
                    "builtins.str",
                    &mut cache,
                )
            }
            "identifier" => declaration_reference_seed(workspace, &file, &prepared, node),
            _ => ClassSeed::NotApplicable,
        }
    }

    fn constructed_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        call: &SemanticCallSite,
    ) -> ClassSeed {
        let semantics = procedure.semantics();
        let callee = semantics
            .value(call.callee)
            .expect("a call site's callee value is retained");
        let mapping = semantics
            .source_mapping(callee.source)
            .expect("a callee value retains a source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::NotApplicable;
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let span = mapping.locator.anchor().span();
        let Some(callee_node) = node_at_span(&prepared, span) else {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        };
        let current_receiver_attribute_call = callee_node.kind() == "attribute"
            && python_attribute_callee_uses_self_or_cls_bounded(prepared.source(), callee_node);
        if current_receiver_attribute_call
            && python_attribute_callee_names_enclosing_nested_class_bounded(
                prepared.source(),
                callee_node,
            )
        {
            // A nested class reached through self/cls can be shadowed by
            // instance writes or subclass overrides.
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        }
        let seed = imported_external_class_callee(workspace, &file, &prepared, callee_node)
            .map(ClassSeed::Class)
            .unwrap_or_else(|| resolve_class_at_span(workspace, file.clone(), span, &prepared));
        if current_receiver_attribute_call {
            let python = python_analyzer(workspace);
            let scope = AnalyzerQueryScope::new(python);
            let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
            let support = PythonDefinitionProvider::new(python, &session);
            let callee_kind = python_attribute_callee_kind_bounded(
                &support,
                scope.token(),
                &file,
                prepared.source(),
                prepared.tree().root_node(),
                callee_node,
            );
            if callee_kind != Some(PythonAttributeCalleeKind::Function)
                && matches!(
                    &seed,
                    ClassSeed::Class(_)
                        | ClassSeed::Classes(_)
                        | ClassSeed::ClassWithOpenBound(_)
                        | ClassSeed::ClassesWithOpenBound(_)
                )
            {
                // An unresolved or class-like attribute call has no proof
                // against instance writes or subclass overrides.
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            }
        }
        // A broad type-at-reference query can be incomplete or ambiguous for
        // an imported package member even when the exact import binder and
        // active overlay identify this constructor's class. Recover only that
        // import-bound, unique external class; ambiguity in the import
        // binding or model still stays unknown.
        let seed = if matches!(
            &seed,
            ClassSeed::Unknown(UnknownReason::UncertainFlow | UnknownReason::AmbiguousCallee)
        ) && let Some(reference) = node_at_span(&prepared, span)
            && let Some(class) = imported_external_class(workspace, &file, &prepared, reference)
        {
            ClassSeed::Class(class)
        } else {
            seed
        };
        let seed = if matches!(&seed, ClassSeed::NotApplicable | ClassSeed::Unknown(_))
            && let Some(reference) = node_at_span(&prepared, span)
            && let Some(external_return_seed) =
                imported_external_function_result_seed(workspace, &file, &prepared, reference)
        {
            external_return_seed
        } else {
            seed
        };
        let unsupported_result = match &seed {
            ClassSeed::Class(ClassIdentity::External { qualified_name, .. }) => {
                Some(qualified_name.as_ref())
            }
            ClassSeed::Classes(classes) => classes.iter().find_map(|class| match class {
                ClassIdentity::External { qualified_name, .. }
                    if matches!(qualified_name.as_ref(), "builtins.type" | "builtins.super") =>
                {
                    Some(qualified_name.as_ref())
                }
                _ => None,
            }),
            _ => None,
        };
        if let Some(qualified_name) = unsupported_result {
            // Neither result has the instance member surface declared by the
            // builtin class itself.
            match qualified_name {
                // `type(value)` returns a class object, which is exactly what
                // `ClassObject` names.
                "builtins.type" => return ClassSeed::Unknown(UnknownReason::ClassObject),
                // `super()` returns a proxy bound to the enclosing class. It is
                // not a class object, so it keeps the unnamed-flow remainder.
                "builtins.super" => return ClassSeed::Unknown(UnknownReason::UncertainFlow),
                _ => {}
            }
        }
        if matches!(seed, ClassSeed::Class(_) | ClassSeed::Classes(_))
            && callee_reads_a_value(workspace, &file, &prepared, span)
        {
            return ClassSeed::NotApplicable;
        }
        seed
    }

    fn exact_call_result_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        call: &SemanticCallSite,
    ) -> Option<Box<[ClassIdentity]>> {
        let semantics = procedure.semantics();
        let callee = semantics.value(call.callee)?;
        let mapping = semantics.source_mapping(callee.source)?;
        if mapping.kind != SourceMappingKind::Exact {
            return None;
        }
        let file = file_for_locator(workspace, &mapping.locator)?;
        let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
        let reference = node_at_span(&prepared, mapping.locator.anchor().span())?;
        let ClassSeed::Classes(classes) =
            imported_external_function_result_seed(workspace, &file, &prepared, reference)?
        else {
            return None;
        };
        if classes
            .iter()
            .any(|class| matches!(class.qualified_name(), "builtins.type" | "builtins.super"))
        {
            return None;
        }
        Some(classes)
    }

    fn exact_result_receiver_is_stable(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        receiver: ValueId,
        call: &SemanticCallSite,
        origin: &ConstructorResultOrigin,
    ) -> bool {
        matches!(
            origin.source.kind,
            SourceSiteKind::ExactCallResult | SourceSiteKind::ExactAccessResult
        ) && python_exact_result_origin_classes(workspace, procedure, origin).as_deref()
            == Some(origin.classes.as_ref())
            && constructor_result_has_stable_local_receiver(
                workspace, procedure, receiver, call, origin,
            )
    }

    fn memory_load_result_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        location: &MemoryLocation,
        result: ValueId,
    ) -> ClassSeed {
        let loads = procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| {
                point
                    .events
                    .iter()
                    .enumerate()
                    .filter_map(move |(event_index, event)| {
                        matches!(
                            event.effect,
                            SemanticEffect::MemoryLoad {
                                location: found,
                                result: found_result,
                                ..
                            } if found == location.id && found_result == result
                        )
                        .then_some((point.id, event_index))
                    })
            })
            .collect::<Vec<_>>();
        let [(point, event_index)] = loads.as_slice() else {
            return ClassSeed::NotApplicable;
        };
        python_exact_value_class_at(workspace, procedure, result, *point, *event_index)
            .map_or(ClassSeed::NotApplicable, ClassSeed::Classes)
    }

    fn constant_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        let semantics = procedure.semantics();
        let mapping = semantics
            .source_mapping(value.source)
            .expect("a constant value retains a source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::NotApplicable;
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        let name = match node.kind() {
            "integer" => "builtins.int",
            "float" => "builtins.float",
            "string" | "concatenated_string" => python_string_literal_class(node, &prepared),
            "true" | "false" => "builtins.bool",
            "none" => "types.NoneType",
            _ => return ClassSeed::NotApplicable,
        };
        let mut cache = ExternalClassCache::default();
        external_seed(
            workspace.analyzer().semantic_model_overlay().as_deref(),
            name,
            &mut cache,
        )
    }

    fn allocation_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        allocation: &AllocationSite,
    ) -> ClassSeed {
        let semantics = procedure.semantics();
        // An allocation that shares its result with a call site is the
        // same-file `A()` shape; `constructed_class` answers for the call.
        let shared_with_call = semantics.call_sites().iter().any(|call| {
            call.result == Some(allocation.result)
                || call.normal_results.contains(&allocation.result)
        });
        if shared_with_call {
            return ClassSeed::NotApplicable;
        }
        // The entry point can belong to a surrounding expression (for example
        // parentheses). The allocated result retains the literal's own span.
        let result = semantics
            .value(allocation.result)
            .expect("an allocation has a live result");
        let mapping = semantics
            .source_mapping(result.source)
            .expect("an allocation result retains a source mapping");
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        let name = match node.kind() {
            "list" | "list_comprehension" => "builtins.list",
            "dictionary" | "dictionary_comprehension" => "builtins.dict",
            "set" | "set_comprehension" => "builtins.set",
            "tuple" | "expression_list" => "builtins.tuple",
            "generator_expression" => "typing.Generator",
            _ => return ClassSeed::NotApplicable,
        };
        let mut cache = ExternalClassCache::default();
        external_seed(
            workspace.analyzer().semantic_model_overlay().as_deref(),
            name,
            &mut cache,
        )
    }

    fn member_surface_is_closed(
        &self,
        _workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
    ) -> bool {
        matches!(class, ClassIdentity::External { .. }) && is_builtin_value_class(class)
    }

    fn receiver_binding_is_stable(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> bool {
        if !procedure
            .semantics()
            .values()
            .iter()
            .any(|value| matches!(value.kind, SemanticValueKind::Receiver { .. }))
        {
            return false;
        }
        let Some(file) = file_for_locator(workspace, procedure.semantics().locator()) else {
            return false;
        };
        let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
            return false;
        };
        let Some(callable) =
            node_at_span(&prepared, procedure.semantics().locator().anchor().span())
        else {
            return false;
        };
        if callable.has_error() {
            return false;
        }
        let Some(name) = python_first_parameter_name(callable, prepared.source()) else {
            return false;
        };
        let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
        let Some(inventory) =
            python_lexical_scope_inventory_bounded(callable, prepared.source(), || {
                session.scope_step()
            })
        else {
            return false;
        };
        // This inventory includes assignments in unsupported comprehensions,
        // including walrus targets that bind in the enclosing callable.
        if inventory
            .local_bindings()
            .any(|(binding, _)| binding == name)
        {
            return false;
        }
        // A nested callable can change the binding through nonlocal even
        // though the outer procedure has no assignment event of its own.
        let mut pending = vec![callable];
        while let Some(node) = pending.pop() {
            if !session.scope_step() {
                return false;
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if node.kind() == "nonlocal_statement"
                    && child.kind() == "identifier"
                    && child.utf8_text(prepared.source().as_bytes()).ok() == Some(name.as_str())
                {
                    return false;
                }
                if !session.scope_step() {
                    return false;
                }
                pending.push(child);
            }
        }
        true
    }

    fn declared_parameter_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        ordinal: u32,
    ) -> ClassSeed {
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(callable) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        let Some(layout) =
            formal_parameter_slots_for_owner(Language::Python, callable, prepared.source())
        else {
            return ClassSeed::NotApplicable;
        };
        // The lowering mints the receiver as a `Receiver` value and numbers
        // only the remaining slots, so a method's or constructor's parameter
        // ordinal N names slot N + 1.
        let first_slot_is_receiver =
            matches!(
                semantics.kind(),
                ProcedureKind::Method | ProcedureKind::Constructor
            ) && !matches!(layout.python_binding, Some(PythonMethodBinding::Static));
        let index = ordinal as usize + usize::from(first_slot_is_receiver);
        let Some(slot) = layout.slots.get(index) else {
            return ClassSeed::NotApplicable;
        };
        if let Some(variadic) = slot.variadic {
            let name = match variadic {
                FormalVariadicKind::Positional => "builtins.tuple",
                FormalVariadicKind::Keyword => "builtins.dict",
                FormalVariadicKind::Both => {
                    return ClassSeed::Unknown(UnknownReason::VariadicParameter);
                }
            };
            let mut cache = ExternalClassCache::default();
            return external_seed(
                workspace.analyzer().semantic_model_overlay().as_deref(),
                name,
                &mut cache,
            );
        }
        let declaration = callable
            .named_descendant_for_byte_range(
                slot.declaration_range.start_byte,
                slot.declaration_range.end_byte,
            )
            .unwrap_or(callable);
        let type_node = match declaration.kind() {
            "typed_parameter" | "typed_default_parameter" => {
                declaration.child_by_field_name("type")
            }
            _ => None,
        };
        let Some(type_node) = type_node else {
            return ClassSeed::NotApplicable;
        };
        self.annotation_class_seed(workspace, &file, &prepared, callable, type_node)
    }

    fn declared_parameter_conditional_origin_is_closed(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        origin: &SourceSite,
    ) -> bool {
        let ClassIdentity::Workspace(unit) = class else {
            return false;
        };
        if !self.declared_class_is_closed(workspace, class) {
            return false;
        }
        let python = python_analyzer(workspace);
        let mut hierarchy = vec![unit.clone()];
        hierarchy.extend(python.get_ancestors(unit));
        let class_hierarchy = self.class_hierarchy(workspace, class);
        if hierarchy
            .iter()
            .any(|owner| python_class_has_protocol_base(python, owner))
            || python_class_hierarchy_has_abstract_members(python, unit)
            || external_hierarchy_has_protocol_or_abstract_members(
                workspace,
                &class_hierarchy.ancestors,
            )
        {
            return false;
        }
        let Some(prepared) = current_indexed_prepared(python, &origin.file) else {
            return false;
        };
        let Some((context, annotation)) =
            declared_parameter_annotation_at_span(&prepared, origin.span)
        else {
            return false;
        };
        self.annotation_class_seed(workspace, &origin.file, &prepared, context, annotation)
            == ClassSeed::Class(class.clone())
    }

    fn closed_memory_loads(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<Vec<(ProgramPointId, ValueId)>, crate::analyzer::semantic::SemanticBudgetExceeded>
    {
        if !procedure
            .semantics()
            .memory_locations()
            .iter()
            .any(|location| matches!(location.kind, MemoryLocationKind::Index { .. }))
        {
            return Ok(Vec::new());
        }
        let Some(file) = file_for_locator(workspace, procedure.semantics().locator()) else {
            return Ok(Vec::new());
        };
        let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
            return Ok(Vec::new());
        };
        let Some(callable) =
            node_at_span(&prepared, procedure.semantics().locator().anchor().span())
        else {
            return Ok(Vec::new());
        };
        if callable.has_error() {
            return Ok(Vec::new());
        }
        let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
        let mut exceeded = None;
        let spans =
            super::semantic::closed_sequence_load_spans(callable, prepared.source(), || {
                if request.cancellation.is_cancelled() || !session.scope_step() {
                    return false;
                }
                match request
                    .budget
                    .charge(crate::analyzer::semantic::SemanticWork {
                        nested_entries: 1,
                        ..crate::analyzer::semantic::SemanticWork::default()
                    }) {
                    Ok(()) => true,
                    Err(error) => {
                        exceeded = Some(error);
                        false
                    }
                }
            });
        if let Some(error) = exceeded {
            return Err(error);
        }
        let Some(spans) = spans else {
            return Ok(Vec::new());
        };
        Ok(procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| point.events.iter().map(move |event| (point.id, event)))
            .filter_map(|(point, event)| {
                let SemanticEffect::MemoryLoad {
                    result, location, ..
                } = event.effect
                else {
                    return None;
                };
                let location = procedure
                    .semantics()
                    .memory_location(location)
                    .expect("a load location is live");
                if !matches!(location.kind, MemoryLocationKind::Index { .. }) {
                    return None;
                }
                let mapping = procedure
                    .semantics()
                    .source_mapping(event.source)
                    .expect("a load source is live");
                (mapping.kind == SourceMappingKind::Exact
                    && spans.contains(&mapping.locator.anchor().span()))
                .then_some((point, result))
            })
            .collect())
    }

    fn memory_load_is_closed_for_classes(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        location: &MemoryLocation,
        classes: &[ClassIdentity],
    ) -> bool {
        self.memory_load_supports_class_closure(location)
            && !classes.is_empty()
            && classes
                .iter()
                .all(|class| matches!(class.qualified_name(), "builtins.list" | "builtins.tuple"))
    }

    fn memory_load_supports_class_closure(&self, location: &MemoryLocation) -> bool {
        matches!(
            location.kind,
            MemoryLocationKind::Index {
                constant_index: Some(_),
                identity: IndexedLocationIdentity::Element,
                ..
            }
        )
    }

    fn accessed_member(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        site: MemberAccessQuery<'_>,
    ) -> Option<Box<str>> {
        let semantics = procedure.semantics();
        match site {
            MemberAccessQuery::Call(call) => {
                let callee = semantics
                    .value(call.callee)
                    .expect("a call site's callee value is retained");
                let mapping = semantics
                    .source_mapping(callee.source)
                    .expect("a callee value retains a source mapping");
                let file = file_for_locator(workspace, &mapping.locator)?;
                let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
                let node = node_at_span(&prepared, mapping.locator.anchor().span())?;
                if node.kind() != "attribute" {
                    return None;
                }
                let attribute = node.child_by_field_name("attribute")?;
                attribute
                    .utf8_text(prepared.source().as_bytes())
                    .ok()
                    .map(Box::from)
            }
            MemberAccessQuery::Load(location) => {
                let MemoryLocationKind::Field { member, .. } = &location.kind else {
                    return None;
                };
                let file = file_for_locator(workspace, member)?;
                let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
                node_text_at(&prepared, member.anchor().span())
            }
        }
    }

    fn member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        _kind: MemberAccessKind,
        class: &ClassIdentity,
        member: &str,
    ) -> MemberLookup {
        let python = python_analyzer(workspace);
        match class {
            ClassIdentity::Workspace(unit) => {
                self.workspace_member_lookup(workspace, python, unit, member)
            }
            ClassIdentity::External { symbol_id, .. } => {
                let Some(overlay) = workspace.analyzer().semantic_model_overlay() else {
                    return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
                };
                external_member_lookup(&overlay, symbol_id, member)
            }
        }
    }

    fn member_lookup_for_receiver(
        &self,
        workspace: &WorkspaceAnalyzer,
        query: MemberReceiverQuery<'_>,
    ) -> MemberLookup {
        let MemberReceiverQuery {
            procedure,
            receiver,
            call,
            constructor,
            class,
            member,
        } = query;
        let exact_local_instance = if let ConstructorResultEvidence::Unique(origin) = constructor {
            let constructed = python_exact_result_origin_classes(workspace, procedure, origin)
                .as_deref()
                == Some(origin.classes.as_ref())
                && origin.classes.contains(class);
            let same_class = origin.classes.contains(class);
            let exact_result_site = matches!(
                origin.source.kind,
                SourceSiteKind::ConstructorCall
                    | SourceSiteKind::ExactAccessResult
                    | SourceSiteKind::ExactCallResult
            );
            let stable_receiver = constructor_result_has_stable_local_receiver(
                workspace, procedure, receiver, call, origin,
            );
            constructed && same_class && exact_result_site && stable_receiver
        } else {
            false
        };
        let local_identifier_receiver =
            constructor_receiver_is_local_identifier(workspace, procedure, receiver);
        let mut lookup = self.member_lookup(workspace, MemberAccessKind::Call, class, member);
        if exact_local_instance
            && let ClassIdentity::External { symbol_id, .. } = class
            && let Some(overlay) = workspace.analyzer().semantic_model_overlay()
        {
            lookup = external_direct_member_lookup(&overlay, symbol_id, member);
        }
        let MemberLookup::Present(hit) = &mut lookup else {
            return lookup;
        };
        let exact_instance = if let ConstructorResultEvidence::Unique(_) = constructor {
            let closed = match &hit.declaration {
                // `exact_instance` already proves a unique direct instance
                // of this exact external class and a stable, non-escaping
                // local binding with no store to the accessed member. The
                // non-empty declaration came from the active semantic-model
                // overlay, so this closes only this call's receiver surface;
                // it does not make the pack's general override claim.
                MemberDeclaration::External(declaration) => {
                    let mutation_free =
                        external_class_member_mutation_free(workspace, class, declaration, member);
                    !declaration.symbol_ids().is_empty() && mutation_free
                }
                MemberDeclaration::Workspace(declaration) => {
                    workspace_instance_method_surface_is_closed(
                        workspace,
                        class,
                        member,
                        declaration,
                    )
                }
            };
            exact_local_instance && closed
        } else {
            false
        };
        if exact_instance {
            // The constructor-origin and binding checks above establish an
            // exact receiver for this call, including the no-instance-write
            // condition. They close only this receiver's dispatch surface.
            hit.dispatch_coverage = CandidateCoverage::Exhaustive;
        } else if hit.dispatch_coverage == CandidateCoverage::Exhaustive
            && match class {
                ClassIdentity::External { .. } => !is_builtin_value_class(class),
                // For workspace classes, alter the old class-only answer only
                // when an identifier receiver carries constructor evidence.
                // Inline calls such as Good().__init__() have no local binding
                // whose alias/rebind proof could improve dispatch.
                ClassIdentity::Workspace(_) => {
                    local_identifier_receiver
                        && !matches!(constructor, ConstructorResultEvidence::None)
                }
            }
        {
            // Non-builtin external-pack surfaces require the exact receiver
            // proof above. A workspace local that fails it remains open for
            // aliasing, rebinding, subclassing, or method replacement; other
            // workspace and builtin-value lookups keep their existing result.
            hit.dispatch_coverage = CandidateCoverage::Open;
        }
        lookup
    }

    fn enclosing_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Option<ClassIdentity> {
        enclosing_workspace_class(workspace, procedure).map(ClassIdentity::Workspace)
    }

    fn class_hierarchy(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
    ) -> ClassHierarchy {
        let unit = match class {
            ClassIdentity::Workspace(unit) => unit,
            ClassIdentity::External { symbol_id, .. } => {
                return external_class_hierarchy(
                    workspace.analyzer().semantic_model_overlay().as_deref(),
                    symbol_id,
                );
            }
        };
        let python = python_analyzer(workspace);
        let workspace_ancestors = python.get_ancestors(unit);
        let mut ancestors = workspace_ancestors
            .iter()
            .cloned()
            .map(ClassIdentity::Workspace)
            .collect::<Vec<_>>();
        let mut unresolved_base = false;
        let overlay = workspace.analyzer().semantic_model_overlay();
        let mut external_cache = ExternalClassCache::default();
        for owner in std::iter::once(unit).chain(workspace_ancestors.iter()) {
            let direct = python.get_direct_ancestors(owner);
            for raw in python.inner.raw_supertypes_of(owner) {
                if direct.iter().any(|ancestor| {
                    ancestor.terminal_name() == raw || ancestor.fq_name_str() == raw
                }) {
                    continue;
                }
                match exact_external_base(
                    python,
                    owner,
                    overlay.as_deref(),
                    &raw,
                    &mut external_cache,
                ) {
                    Some(identity) if !ancestors.contains(&identity) => ancestors.push(identity),
                    Some(_) => {}
                    None if python_typing_marker_base(python, owner, &raw) => {}
                    None => unresolved_base = true,
                }
            }
        }

        let mut descendants = Vec::new();
        let mut seen = HashSet::default();
        let mut pending = python
            .get_direct_descendants(unit)
            .into_iter()
            .collect::<Vec<_>>();
        while let Some(descendant) = pending.pop() {
            if !seen.insert(descendant.clone()) {
                continue;
            }
            pending.extend(python.get_direct_descendants(&descendant));
            descendants.push(ClassIdentity::Workspace(descendant));
        }

        let dynamic_attributes =
            std::iter::once(unit)
                .chain(workspace_ancestors.iter())
                .any(|owner| {
                    python.direct_children(owner).iter().any(|child| {
                        matches!(
                            child.terminal_name(),
                            "__getattr__" | "__getattribute__" | "__setattr__"
                        )
                    })
                });
        ancestors.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
        descendants.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
        ClassHierarchy {
            ancestors,
            descendants: Some(descendants),
            unresolved_base,
            dynamic_attributes,
        }
    }

    fn class_body_member_binding(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        member: &str,
    ) -> ClassBodyMemberBinding {
        let ClassIdentity::Workspace(unit) = class else {
            return ClassBodyMemberBinding::Unclassified;
        };
        let python = python_analyzer(workspace);
        let file = unit.source();
        let Some(prepared) = current_indexed_prepared(python, file) else {
            return ClassBodyMemberBinding::Unclassified;
        };
        let Some(class) = class_node_for_unit(python, &prepared, unit) else {
            return ClassBodyMemberBinding::Unclassified;
        };
        // A class decorator can return a different class, so this body does
        // not state what any member of the runtime class binds.
        if class
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
        {
            return ClassBodyMemberBinding::Unclassified;
        }
        let Some(body) = class.child_by_field_name("body") else {
            return ClassBodyMemberBinding::Unclassified;
        };
        let mut binding = ClassBodyMemberBinding::Unbound;
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            if assignment_name(child, prepared.source()) == Some(member) {
                return ClassBodyMemberBinding::Unclassified;
            }
            if definition_name(child, prepared.source()) == Some(member) {
                match child.kind() {
                    // A plain `def` binds the function the member lookup
                    // already names. Reading it through an instance yields
                    // that method, not a stored attribute value.
                    "function_definition" => binding = ClassBodyMemberBinding::Procedure,
                    // A decorator returns an arbitrary object, and a
                    // descriptor such as `property` runs user code on read.
                    "decorated_definition" => return ClassBodyMemberBinding::Unclassified,
                    _ => {}
                }
            }
        }
        binding
    }

    fn field_access_may_use_descriptor(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        member: &str,
    ) -> bool {
        let mro = python_descriptor_mro(workspace, class);
        mro.iter().any(|owner| match owner {
            ClassIdentity::Workspace(unit) => {
                python_workspace_member_may_be_descriptor(self, workspace, unit, member)
                    != DescriptorAnswer::No
            }
            ClassIdentity::External { .. } => {
                external_member_may_be_descriptor(self, workspace, owner, member)
                    != DescriptorAnswer::No
            }
        })
    }

    fn truthiness_is_pure(&self, workspace: &WorkspaceAnalyzer, class: &ClassIdentity) -> bool {
        if is_builtin_value_class(class) {
            return true;
        }
        let hierarchy = self.class_hierarchy(workspace, class);
        !hierarchy.unresolved_base
            && !hierarchy.dynamic_attributes
            && ["__bool__", "__len__"].iter().all(|member| {
                matches!(
                    self.member_lookup(workspace, MemberAccessKind::Load, class, member),
                    MemberLookup::Absent | MemberLookup::DeclarationAbsent
                )
            })
    }

    fn member_access_is_pure(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        member: &str,
    ) -> bool {
        is_builtin_value_class(class) || self.field_access_is_plain(workspace, class, member)
    }

    fn field_access_is_plain(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        member: &str,
    ) -> bool {
        let hierarchy = self.class_hierarchy(workspace, class);
        if hierarchy.unresolved_base || hierarchy.dynamic_attributes {
            return false;
        }
        let Some(descendants) = hierarchy.descendants.as_ref() else {
            return false;
        };
        std::iter::once(class)
            .chain(&hierarchy.ancestors)
            .chain(descendants)
            .all(|owner| {
                if owner.qualified_name() == "builtins.object" {
                    return true;
                }
                let owner_hierarchy = self.class_hierarchy(workspace, owner);
                !owner_hierarchy.unresolved_base
                    && !owner_hierarchy.dynamic_attributes
                    // Any class-level binding, including a plain method,
                    // makes the read go through the class rather than plain
                    // instance storage.
                    && matches!(
                        self.class_body_member_binding(workspace, owner, member),
                        ClassBodyMemberBinding::Unbound
                    )
            })
    }

    fn dynamic_write_receiver_bound(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        write_span: SourceSpan,
    ) -> Option<ClassIdentity> {
        let semantics = procedure.semantics();
        let file = file_for_locator(workspace, semantics.locator())?;
        let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
        let callable = node_at_span(&prepared, semantics.locator().anchor().span())?;
        let write = node_at_span(&prepared, write_span)?;
        let receiver = python_dynamic_write_receiver(write, prepared.source())?;
        let layout =
            formal_parameter_slots_for_owner(Language::Python, callable, prepared.source())?;
        let method_has_receiver =
            matches!(
                semantics.kind(),
                ProcedureKind::Method | ProcedureKind::Constructor
            ) && !matches!(layout.python_binding, Some(PythonMethodBinding::Static));
        let first_parameter = method_has_receiver
            .then(|| python_first_parameter_name(callable, prepared.source()))
            .flatten();

        let method_bound = python_dynamic_write_method_receiver_bound(
            self,
            workspace,
            procedure,
            &prepared,
            receiver,
            method_has_receiver,
            first_parameter.as_deref(),
        );
        let parameter_bound = python_dynamic_write_parameter_bound(
            self, workspace, &file, &prepared, callable, receiver,
        );
        let stored_bound = python_dynamic_write_stored_type_field_bound(
            self, workspace, &file, &prepared, procedure, callable, receiver,
        );
        let iteration_bound = python_dynamic_write_iteration_element_bound(
            self, workspace, procedure, callable, &file, &prepared, receiver,
        );
        method_bound
            .or(parameter_bound)
            .or(stored_bound)
            .or(iteration_bound)
    }

    fn dynamic_write_receiver_field(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        write_span: SourceSpan,
    ) -> Option<(ClassIdentity, Box<str>)> {
        let semantics = procedure.semantics();
        let file = file_for_locator(workspace, semantics.locator())?;
        let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
        let callable = node_at_span(&prepared, semantics.locator().anchor().span())?;
        let write = node_at_span(&prepared, write_span)?;
        let receiver = python_dynamic_write_receiver(write, prepared.source())?;
        python_dynamic_write_receiver_field(
            self, workspace, procedure, callable, &prepared, receiver,
        )
    }

    fn field_store_value_bounds(
        &self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        span: SourceSpan,
        member: &str,
    ) -> Result<Option<Vec<ClassIdentity>>, UnknownReason> {
        let python = python_analyzer(workspace);
        let prepared =
            current_indexed_prepared(python, file).ok_or(UnknownReason::UncertainFlow)?;
        python_field_store_value_bounds(self, workspace, file, &prepared, span, member)
    }

    fn dynamic_write_receiver_is_explicitly_unbounded(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        write_span: SourceSpan,
    ) -> bool {
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return false;
        };
        let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
            return false;
        };
        let Some(callable) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
            return false;
        };
        let Some(write) = node_at_span(&prepared, write_span) else {
            return false;
        };
        let Some(receiver) = python_dynamic_write_receiver(write, prepared.source()) else {
            return false;
        };
        python_dynamic_write_parameter_is_explicitly_unbounded(
            workspace, &file, &prepared, callable, receiver,
        )
    }

    fn dynamic_field_writes(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Vec<DynamicFieldWrite> {
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return vec![DynamicFieldWrite::Scoped {
                names: DynamicFieldNameSet::Any,
                receiver: None,
                span: semantics.locator().anchor().span(),
            }];
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(_) => {
                return vec![DynamicFieldWrite::Scoped {
                    names: DynamicFieldNameSet::Any,
                    receiver: None,
                    span: semantics.locator().anchor().span(),
                }];
            }
        };
        let Some(callable) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
            return vec![DynamicFieldWrite::Scoped {
                names: DynamicFieldNameSet::Any,
                receiver: None,
                span: semantics.locator().anchor().span(),
            }];
        };
        let root_id = callable.id();
        let mut writes = Vec::new();
        let mut stack = vec![callable];
        while let Some(node) = stack.pop() {
            if node.id() != root_id
                && matches!(
                    node.kind(),
                    "function_definition" | "class_definition" | "lambda"
                )
            {
                continue;
            }
            if let Some(write) = dynamic_call_write_for_field(workspace, &file, node, &prepared) {
                writes.push(scoped_dynamic_write(
                    workspace, procedure, node, write, &prepared,
                ));
            }
            if matches!(node.kind(), "assignment" | "augmented_assignment")
                && let Some(write) = dictionary_write_for_field(workspace, &file, node, &prepared)
            {
                writes.push(DynamicFieldWrite::Member("__dict__".into()));
                writes.push(scoped_dynamic_write(
                    workspace, procedure, node, write, &prepared,
                ));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        writes
    }

    fn dynamic_type_write_receiver_bounds(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        receiver: ValueId,
        write_span: SourceSpan,
    ) -> Result<Option<Vec<ClassIdentity>>, UnknownReason> {
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return Err(UnknownReason::UncertainFlow);
        };
        let prepared = prepared_for_procedure(workspace, procedure, &file)?;
        let Some(receiver_expression) =
            dynamic_write_receiver_expression(procedure, &prepared, receiver, write_span)
        else {
            return Ok(None);
        };
        let Some(scope) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
            return Err(UnknownReason::UncertainFlow);
        };
        Ok(
            runtime_created_type_expression(
                workspace,
                &file,
                &prepared,
                scope,
                receiver_expression,
            )
            .then(Vec::new),
        )
    }

    fn non_escaping_nested_write_receiver_bounds(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        receiver: ValueId,
        write_span: SourceSpan,
    ) -> Result<Option<Vec<ClassIdentity>>, UnknownReason> {
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return Err(UnknownReason::UncertainFlow);
        };
        let prepared = prepared_for_procedure(workspace, procedure, &file)?;
        let Some(receiver_expression) =
            dynamic_write_receiver_expression(procedure, &prepared, receiver, write_span)
        else {
            return Ok(None);
        };
        let Some(helper) = enclosing_function_definition(receiver_expression) else {
            return Ok(None);
        };
        let Some((positional_ordinal, parameter_name, keyword_only)) =
            nested_receiver_parameter(helper, receiver_expression, prepared.source())
        else {
            return Ok(None);
        };
        let Some(parent) = helper.parent() else {
            return Ok(None);
        };
        let Some(outer) = enclosing_function_definition(parent) else {
            return Ok(None);
        };
        let calls = nested_helper_direct_calls(outer, helper, prepared.source())?;
        let mut bounds = Vec::new();
        for call in calls {
            let argument = nested_helper_argument_expression(
                call,
                &parameter_name,
                positional_ordinal,
                keyword_only,
                prepared.source(),
            )?;
            for class in expression_dynamic_receiver_bounds(
                self, workspace, &file, &prepared, outer, argument,
            )? {
                if !bounds.contains(&class) {
                    bounds.push(class);
                }
            }
        }
        Ok(Some(bounds))
    }

    fn narrowing_verdicts(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        guard: &GuardFact,
        atoms: &[&ClassIdentity],
        member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
    ) -> Vec<NarrowingVerdict> {
        let unknown = || vec![NarrowingVerdict::Unknown; atoms.len()];
        let verdict = |holds| match holds {
            Some(true) => NarrowingVerdict::Keep,
            Some(false) => NarrowingVerdict::Drop,
            None => NarrowingVerdict::Unknown,
        };
        match guard.predicate {
            GuardPredicate::InstanceOf { classes, .. } => {
                let classes = match self.guard_classes(workspace, procedure, classes) {
                    Ok(classes) => classes,
                    Err(reason) => return vec![NarrowingVerdict::Incomplete(reason); atoms.len()],
                };
                let overlay = workspace.analyzer().semantic_model_overlay();
                for class in &classes {
                    if !self.guard_classes_have_supported_instance_checks(
                        workspace,
                        std::slice::from_ref(class),
                        overlay.as_deref(),
                    ) {
                        return vec![
                            NarrowingVerdict::Incomplete(UnknownReason::UnmodeledGuard {
                                class: class.qualified_name().into(),
                            });
                            atoms.len()
                        ];
                    }
                }
                atoms
                    .iter()
                    .map(
                        |atom| match self.instance_relation(workspace, atom, &classes) {
                            Some(holds) => verdict(Some(holds)),
                            None => NarrowingVerdict::Incomplete(UnknownReason::UnmodeledGuard {
                                class: classes
                                    .iter()
                                    .map(ClassIdentity::qualified_name)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                                    .into(),
                            }),
                        },
                    )
                    .collect()
            }
            // `None` is falsy, and nothing can make it truthy: `NoneType`
            // declares no `__bool__` and no `__len__`, and neither can be
            // added to it. A value a truth test proved truthy is therefore
            // not `None`. Nothing else follows, and the false arm -- which
            // the engine derives by reversing this one -- proves nothing at
            // all, because `0`, `""` and an empty container are falsy too.
            GuardPredicate::Truthy { .. } => atoms
                .iter()
                .map(|atom| {
                    if atom.qualified_name() == "types.NoneType" {
                        NarrowingVerdict::Drop
                    } else {
                        NarrowingVerdict::Unknown
                    }
                })
                .collect(),
            GuardPredicate::ExactClass {
                classes,
                exact_on_true,
                ..
            } => {
                let classes = match self.guard_classes(workspace, procedure, classes) {
                    Ok(classes) => classes,
                    Err(reason) => return vec![NarrowingVerdict::Incomplete(reason); atoms.len()],
                };
                // `type(value) is C` names the runtime class outright, so a
                // candidate needs no hierarchy: it either is one of the named
                // classes or it is not. The named classes must still be the
                // classes the source spells, which is the same proof
                // `isinstance` needs of them.
                let overlay = workspace.analyzer().semantic_model_overlay();
                for class in &classes {
                    if !self.guard_classes_have_supported_instance_checks(
                        workspace,
                        std::slice::from_ref(class),
                        overlay.as_deref(),
                    ) {
                        return vec![
                            NarrowingVerdict::Incomplete(UnknownReason::UnmodeledGuard {
                                class: class.qualified_name().into(),
                            });
                            atoms.len()
                        ];
                    }
                }
                atoms
                    .iter()
                    .map(|atom| verdict(Some(classes.contains(atom) == exact_on_true)))
                    .collect()
            }
            GuardPredicate::HasMember { member, .. } => {
                let Some(value) = procedure.semantics().value(member) else {
                    return unknown();
                };
                let Some(mapping) = procedure.semantics().source_mapping(value.source) else {
                    return unknown();
                };
                let Some(file) = file_for_locator(workspace, &mapping.locator) else {
                    return unknown();
                };
                let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
                    return unknown();
                };
                let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
                    return unknown();
                };
                let Some(member) = python_plain_string_literal(node, prepared.source()) else {
                    return unknown();
                };
                atoms
                    .iter()
                    .map(|atom| {
                        verdict(match member_lookup(atom, member) {
                            MemberLookup::Present(_) => Some(true),
                            MemberLookup::Absent => Some(false),
                            MemberLookup::Unknown(_) | MemberLookup::DeclarationAbsent => None,
                        })
                    })
                    .collect()
            }
            GuardPredicate::NullComparison { null_on_true } => atoms
                .iter()
                .map(|atom| {
                    verdict(Some(
                        (atom.qualified_name() == "types.NoneType") == null_on_true,
                    ))
                })
                .collect(),
            GuardPredicate::ConstantBoolean { .. }
            | GuardPredicate::ConstantEquality { .. }
            | GuardPredicate::OrderedIntegerComparison { .. }
            | GuardPredicate::OrderedFloatComparison { .. }
            | GuardPredicate::NanComparison { .. }
            | GuardPredicate::Opaque { .. } => unknown(),
        }
    }

    fn guard_proves_classes(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        guard: &GuardFact,
    ) -> ClassSeed {
        // Only a class predicate says what an unnamed value is. `hasattr`
        // proves one attribute, a truth test proves the value is not `None`,
        // and a null comparison proves only `NoneType`, which has no members
        // this domain would gain by naming.
        let (classes, names_the_runtime_class) = match guard.predicate {
            GuardPredicate::InstanceOf { classes, .. } => (classes, false),
            // `type(value) is C` names the runtime class on the true arm;
            // `type(value) is not C` states it on the false arm, so its true
            // arm proves nothing at all.
            GuardPredicate::ExactClass {
                classes,
                exact_on_true: true,
                ..
            } => (classes, true),
            GuardPredicate::ExactClass { .. }
            | GuardPredicate::ConstantBoolean { .. }
            | GuardPredicate::ConstantEquality { .. }
            | GuardPredicate::NullComparison { .. }
            | GuardPredicate::HasMember { .. }
            | GuardPredicate::Truthy { .. }
            | GuardPredicate::OrderedIntegerComparison { .. }
            | GuardPredicate::OrderedFloatComparison { .. }
            | GuardPredicate::NanComparison { .. }
            | GuardPredicate::Opaque { .. } => return ClassSeed::NotApplicable,
        };
        let Ok(classes) = self.guard_classes(workspace, procedure, classes) else {
            return ClassSeed::NotApplicable;
        };
        if classes.is_empty() {
            return ClassSeed::NotApplicable;
        }
        // The same proof `narrowing_verdicts` needs of a guard's operands:
        // the names must denote the classes the source spells before either
        // arm may act on them.
        let overlay = workspace.analyzer().semantic_model_overlay();
        if !self.guard_classes_have_supported_instance_checks(
            workspace,
            &classes,
            overlay.as_deref(),
        ) {
            return ClassSeed::NotApplicable;
        }
        // An exact-class test needs no hierarchy: the value is one of the
        // named classes or it is not. An `isinstance` a subclass also
        // satisfies leaves the member surface open, which is exactly what an
        // open bound records.
        if names_the_runtime_class
            || classes
                .iter()
                .all(|class| self.declared_class_is_closed(workspace, class))
        {
            ClassSeed::classes(classes)
        } else {
            ClassSeed::classes_with_open_bound(classes)
        }
    }

    /// Python names one actual argument in each of the two constrained call
    /// shapes: an ordinary method call whose return contract constrains an
    /// argument, and an ordinary one-argument predicate call whose result an
    /// opaque guard tests. Both take only direct positional arguments.
    fn refinement_subjects(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Vec<ValueId> {
        let semantics = procedure.semantics();
        let snapshot = workspace.analyzer().active_semantic_model_snapshot();
        let opaque_guard_subjects = semantics
            .guard_facts()
            .iter()
            .filter(|guard| matches!(guard.predicate, GuardPredicate::Opaque { .. }))
            .filter_map(|guard| guard.subject)
            .collect::<std::collections::HashSet<_>>();
        let mut subjects = Vec::new();
        for call in semantics.call_sites() {
            if !matches!(
                call.invocation_mode,
                crate::analyzer::semantic::CallInvocationMode::Ordinary
            ) {
                continue;
            }
            // `call_guard_narrowing` constrains a direct argument of a call an
            // opaque guard tests. `module.predicate(value)` carries a receiver
            // and is recognized too, so this is not restricted by receiver.
            if call
                .result
                .is_some_and(|result| opaque_guard_subjects.contains(&result))
            {
                subjects.extend(
                    call.arguments
                        .iter()
                        .filter(|argument| {
                            matches!(
                                argument.expansion,
                                crate::analyzer::semantic::CallArgumentExpansion::Direct(_)
                            )
                        })
                        .map(|argument| argument.value),
                );
            }
            if call.arguments.iter().any(|argument| {
                argument.keyword.is_some()
                    || !matches!(
                        argument.expansion,
                        crate::analyzer::semantic::CallArgumentExpansion::Direct(
                            crate::analyzer::semantic::ArgumentDomain::Positional
                        )
                    )
            }) {
                continue;
            }
            if call.receiver.is_some() {
                // Only a member a loaded semantic model refines can produce a
                // return contract, which is the first thing
                // `normal_return_type_constraints` establishes.
                let Some(snapshot) = snapshot.as_ref() else {
                    continue;
                };
                let (Ok(arity), Some(member)) = (
                    u32::try_from(call.arguments.len()),
                    self.accessed_member(workspace, procedure, MemberAccessQuery::Call(call)),
                ) else {
                    continue;
                };
                if snapshot
                    .active_models()
                    .has_normal_return_type_refinement_candidate(
                        Language::Python.config_label(),
                        &member,
                        true,
                        arity,
                    )
                {
                    subjects.extend(call.arguments.iter().map(|argument| argument.value));
                }
            }
        }
        subjects
    }

    fn call_guard_narrowing(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        guard: &GuardFact,
        atoms: &[&ClassIdentity],
        member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
    ) -> CallGuardOutcome {
        super::guard_summary::call_guard_narrowing(
            self,
            workspace,
            procedure,
            guard,
            atoms,
            member_lookup,
        )
    }

    fn normal_return_type_constraints(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        call: &SemanticCallSite,
    ) -> Vec<NormalReturnTypeConstraint> {
        if !matches!(
            call.invocation_mode,
            crate::analyzer::semantic::CallInvocationMode::Ordinary
        ) {
            return Vec::new();
        }
        let Some(receiver) = call.receiver else {
            return Vec::new();
        };
        let semantics = procedure.semantics();
        let Some(receiver_value) = semantics.value(receiver) else {
            return Vec::new();
        };
        if !matches!(&receiver_value.kind, SemanticValueKind::Temporary) {
            return Vec::new();
        }
        let Some(formal_receiver) = semantics.values().iter().find_map(|value| {
            matches!(value.kind, SemanticValueKind::Receiver { dispatch: true }).then_some(value.id)
        }) else {
            return Vec::new();
        };
        if receiver == formal_receiver {
            return Vec::new();
        }
        // The Python lowering represents `self.method(...)` with a temporary
        // receiver value. Its one canonical input is a Receiver flow from the
        // formal `self`; assignments or any other value flow into either the
        // temporary or the formal invalidate the exact receiver proof.
        let mut canonical_receiver_flows = 0usize;
        for event in semantics
            .points()
            .iter()
            .flat_map(|point| point.events.iter())
        {
            match &event.effect {
                SemanticEffect::Assignment { target, .. }
                    if *target == receiver || *target == formal_receiver =>
                {
                    return Vec::new();
                }
                SemanticEffect::ValueFlow { target, .. } if *target == formal_receiver => {
                    return Vec::new();
                }
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } if *target == receiver => {
                    if *source != formal_receiver || *kind != ValueFlowKind::Receiver {
                        return Vec::new();
                    }
                    canonical_receiver_flows += 1;
                }
                _ => {}
            }
        }
        if canonical_receiver_flows != 1 {
            return Vec::new();
        }
        if call.arguments.is_empty()
            || call.arguments.iter().any(|argument| {
                !matches!(
                    argument.expansion,
                    crate::analyzer::semantic::CallArgumentExpansion::Direct(
                        crate::analyzer::semantic::ArgumentDomain::Positional
                    )
                )
            })
        {
            return Vec::new();
        }
        let Some(callee_value) = semantics.value(call.callee) else {
            return Vec::new();
        };
        let Some(callee_mapping) = semantics.source_mapping(callee_value.source) else {
            return Vec::new();
        };
        if callee_mapping.kind != SourceMappingKind::Exact {
            return Vec::new();
        }
        let Some(file) = file_for_locator(workspace, &callee_mapping.locator) else {
            return Vec::new();
        };
        let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
            return Vec::new();
        };
        let Some(callee_node) = node_at_span(&prepared, callee_mapping.locator.anchor().span())
        else {
            return Vec::new();
        };
        if callee_node.kind() != "attribute" {
            return Vec::new();
        }
        let Some(receiver_node) = callee_node.child_by_field_name("object") else {
            return Vec::new();
        };
        let Some(receiver_mapping) = semantics
            .source_mapping(receiver_value.source)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
        else {
            return Vec::new();
        };
        let Some(receiver_site) = node_at_span(&prepared, receiver_mapping.locator.anchor().span())
        else {
            return Vec::new();
        };
        if receiver_site.start_byte() != receiver_node.start_byte()
            || receiver_site.end_byte() != receiver_node.end_byte()
        {
            return Vec::new();
        }
        let Some(member_node) = callee_node.child_by_field_name("attribute") else {
            return Vec::new();
        };
        let Ok(member) = member_node.utf8_text(prepared.source().as_bytes()) else {
            return Vec::new();
        };
        let Ok(arity) = u32::try_from(call.arguments.len()) else {
            return Vec::new();
        };
        let Some(snapshot) = workspace.analyzer().active_semantic_model_snapshot() else {
            return Vec::new();
        };
        let active = snapshot.active_models();
        if !active.has_normal_return_type_refinement_candidate(
            Language::Python.config_label(),
            member,
            true,
            arity,
        ) {
            return Vec::new();
        }
        let Some(ClassIdentity::Workspace(owner)) = self.enclosing_class(workspace, procedure)
        else {
            return Vec::new();
        };
        let hierarchy = self.class_hierarchy(workspace, &ClassIdentity::Workspace(owner.clone()));
        if hierarchy.unresolved_base
            || hierarchy.dynamic_attributes
            || hierarchy.descendants.as_deref() != Some(&[])
        {
            return Vec::new();
        }
        let python = python_analyzer(workspace);
        if python_class_hierarchy_member_unshadowed_bounded(python, &owner, member) != Some(true) {
            return Vec::new();
        }
        let workspace_owner = ClassIdentity::Workspace(owner.clone());
        let MemberLookup::Present(hit) =
            self.member_lookup(workspace, MemberAccessKind::Call, &workspace_owner, member)
        else {
            return Vec::new();
        };
        if hit.dispatch_coverage != CandidateCoverage::Exhaustive {
            return Vec::new();
        }
        let MemberDeclaration::External(declaration) = hit.declaration else {
            return Vec::new();
        };
        let [symbol_id] = declaration.symbol_ids() else {
            return Vec::new();
        };
        let Some(overlay) = snapshot.semantic_model_overlay() else {
            return Vec::new();
        };
        let symbol_match = overlay.symbols_with_id(symbol_id);
        let [symbol] = symbol_match.records.as_slice() else {
            return Vec::new();
        };
        if symbol.provenance.ambiguous
            || symbol.provenance.completeness != SemanticModelCompleteness::Complete
            || symbol.language != Language::Python.config_label()
            || symbol.kind != SemanticModelSymbolKind::Method
            || !symbol.has_receiver()
        {
            return Vec::new();
        }
        let Some(owner_id) = symbol.owner_id.as_deref() else {
            return Vec::new();
        };
        let owner_match = overlay.symbols_with_id(owner_id);
        let [modeled_owner] = owner_match.records.as_slice() else {
            return Vec::new();
        };
        if modeled_owner.provenance.ambiguous
            || modeled_owner.provenance.completeness != SemanticModelCompleteness::Complete
            || modeled_owner.language != Language::Python.config_label()
            || modeled_owner.kind != SemanticModelSymbolKind::Class
            || modeled_owner.owner_id.is_some()
        {
            return Vec::new();
        }
        let matched = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
            Language::Python.config_label(),
            &modeled_owner.qualified_name,
            &symbol.name,
            true,
            arity,
        ));
        if matched.disposition != SemanticModelMatchDisposition::Unique
            || matched.records.len() != 1
        {
            return Vec::new();
        }
        let selected = &matched.records[0];
        let provenance = selected.provenance(active);
        if provenance.ambiguous || provenance.completeness != SemanticModelCompleteness::Complete {
            return Vec::new();
        }
        let mut constraints = Vec::new();
        for refinement in selected.normal_return_type_refinements() {
            if refinement.required_receiver_members.iter().any(|required| {
                let required = required.as_ref();
                let MemberLookup::Present(required_hit) = self.member_lookup(
                    workspace,
                    MemberAccessKind::Call,
                    &workspace_owner,
                    required,
                ) else {
                    return true;
                };
                let MemberDeclaration::External(required_declaration) = required_hit.declaration
                else {
                    return true;
                };
                let expected = overlay.member_target_on_owner(modeled_owner.id.as_str(), required);
                let [expected] = expected.records.as_slice() else {
                    return true;
                };
                let [actual_id] = required_declaration.symbol_ids() else {
                    return true;
                };
                if required_hit.dispatch_coverage != CandidateCoverage::Exhaustive
                    || actual_id.as_ref() != expected.id.as_str()
                {
                    return true;
                }
                python_class_hierarchy_member_unshadowed_bounded(python, &owner, required)
                    != Some(true)
                    || !external_instance_method_present_on_owner(
                        overlay,
                        modeled_owner.id.as_str(),
                        required,
                    )
            }) {
                return Vec::new();
            }
            let subject = refinement.parameter_ordinal as usize;
            let class_parameter = refinement.class_parameter_ordinal as usize;
            if subject == class_parameter
                || subject >= call.arguments.len()
                || class_parameter >= call.arguments.len()
            {
                return Vec::new();
            }
            let Ok(classes) =
                self.guard_classes(workspace, procedure, call.arguments[class_parameter].value)
            else {
                return Vec::new();
            };
            if classes.is_empty() {
                return Vec::new();
            }
            if !self.guard_classes_have_supported_instance_checks(
                workspace,
                &classes,
                Some(overlay),
            ) {
                return Vec::new();
            }
            constraints.push(NormalReturnTypeConstraint {
                subject: call.arguments[subject].value,
                classes: classes.into_boxed_slice(),
                provenance: provenance.clone(),
            });
        }
        constraints
    }

    fn instance_of_verdict(
        &self,
        workspace: &WorkspaceAnalyzer,
        atom: &ClassIdentity,
        classes: &[ClassIdentity],
    ) -> NarrowingVerdict {
        match self.instance_relation(workspace, atom, classes) {
            Some(true) => NarrowingVerdict::Keep,
            Some(false) => NarrowingVerdict::Drop,
            None => NarrowingVerdict::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescriptorAnswer {
    No,
    Yes,
    Unknown,
}

fn python_descriptor_mro(
    workspace: &WorkspaceAnalyzer,
    class: &ClassIdentity,
) -> Vec<ClassIdentity> {
    let ClassIdentity::Workspace(unit) = class else {
        return vec![class.clone()];
    };
    let python = python_analyzer(workspace);
    let workspace_ancestors = python.get_ancestors(unit);
    let overlay = workspace.analyzer().semantic_model_overlay();
    let mut external_cache = ExternalClassCache::default();
    let mut mro = vec![class.clone()];
    mro.extend(
        workspace_ancestors
            .iter()
            .cloned()
            .map(ClassIdentity::Workspace),
    );
    for owner in std::iter::once(unit).chain(workspace_ancestors.iter()) {
        let direct = python.get_direct_ancestors(owner);
        for raw in python.inner.raw_supertypes_of(owner) {
            if direct
                .iter()
                .any(|ancestor| ancestor.terminal_name() == raw || ancestor.fq_name_str() == raw)
            {
                continue;
            }
            match exact_external_base(python, owner, overlay.as_deref(), &raw, &mut external_cache)
            {
                Some(identity) if !mro.contains(&identity) => mro.push(identity),
                Some(_) => {}
                None if python_typing_marker_base(python, owner, &raw) => {}
                // An unresolved base is not evidence that this member is a
                // descriptor. Keep checking the receiver and every resolved
                // ancestor; other hierarchy uncertainty remains represented
                // by the field-slot survey itself.
                None => {}
            }
        }
    }
    mro
}

#[derive(Clone, Copy)]
enum ClassMemberAssignment<'tree> {
    NotMember,
    AnnotationOnly,
    Value(Node<'tree>),
    Unknown,
}

fn python_class_member_assignment<'tree>(
    node: Node<'tree>,
    source: &str,
    member: &str,
) -> ClassMemberAssignment<'tree> {
    let node = if node.kind() == "expression_statement" {
        let Some(expression) = node.named_child(0) else {
            return ClassMemberAssignment::NotMember;
        };
        expression
    } else {
        node
    };
    if !matches!(
        node.kind(),
        "assignment" | "annotated_assignment" | "augmented_assignment"
    ) {
        return ClassMemberAssignment::NotMember;
    }
    let Some(left) = node.child_by_field_name("left") else {
        return ClassMemberAssignment::Unknown;
    };
    if left.kind() != "identifier" || left.utf8_text(source.as_bytes()).ok() != Some(member) {
        return ClassMemberAssignment::NotMember;
    }
    if node.kind() == "augmented_assignment" {
        return ClassMemberAssignment::Unknown;
    }
    let value = node
        .child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"));
    match (node.kind(), value) {
        ("annotated_assignment", None) => ClassMemberAssignment::AnnotationOnly,
        (_, Some(value)) => ClassMemberAssignment::Value(value),
        _ => ClassMemberAssignment::Unknown,
    }
}

fn python_workspace_member_may_be_descriptor(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    unit: &CodeUnit,
    member: &str,
) -> DescriptorAnswer {
    let python = python_analyzer(workspace);
    let Some(prepared) = current_indexed_prepared(python, unit.source()) else {
        return DescriptorAnswer::Unknown;
    };
    let Some(class) = class_node_for_unit(python, &prepared, unit) else {
        return DescriptorAnswer::Unknown;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return DescriptorAnswer::Unknown;
    };
    let mut unresolved = false;
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if definition_name(child, prepared.source()) == Some(member) {
            match child.kind() {
                "function_definition" => {}
                "decorated_definition" => {
                    let mut cursor = child.walk();
                    let function = child
                        .named_children(&mut cursor)
                        .find(|node| node.kind() == "function_definition");
                    if function.is_some_and(|function| {
                        python_function_has_property_decorator(function, prepared.source())
                    }) {
                        return DescriptorAnswer::Yes;
                    }
                    unresolved = true;
                }
                _ => unresolved = true,
            }
        }
        match python_class_member_assignment(child, prepared.source(), member) {
            ClassMemberAssignment::NotMember | ClassMemberAssignment::AnnotationOnly => {}
            ClassMemberAssignment::Unknown => unresolved = true,
            ClassMemberAssignment::Value(value) => {
                match python_value_may_be_descriptor(
                    adapter,
                    workspace,
                    unit.source().clone(),
                    &prepared,
                    value,
                ) {
                    DescriptorAnswer::No => {}
                    DescriptorAnswer::Yes => return DescriptorAnswer::Yes,
                    DescriptorAnswer::Unknown => unresolved = true,
                }
            }
        }
    }
    if unresolved {
        DescriptorAnswer::Unknown
    } else {
        DescriptorAnswer::No
    }
}

fn python_value_may_be_descriptor(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    file: ProjectFile,
    prepared: &PreparedSyntaxTree,
    value: Node<'_>,
) -> DescriptorAnswer {
    if value.kind() == "call" {
        let Some(function) = value.child_by_field_name("function") else {
            return DescriptorAnswer::Unknown;
        };
        return match resolved_class_bounds(resolve_class_at_span(
            workspace,
            file,
            span_for_node(function),
            prepared,
        )) {
            Some(classes) if !classes.is_empty() => {
                let mut unresolved = false;
                for class in classes {
                    match class_may_define_descriptor(adapter, workspace, &class) {
                        DescriptorAnswer::Yes => return DescriptorAnswer::Yes,
                        DescriptorAnswer::Unknown => unresolved = true,
                        DescriptorAnswer::No => {}
                    }
                }
                if unresolved {
                    DescriptorAnswer::Unknown
                } else {
                    DescriptorAnswer::No
                }
            }
            _ => DescriptorAnswer::Unknown,
        };
    }
    if matches!(
        value.kind(),
        "string"
            | "concatenated_string"
            | "integer"
            | "float"
            | "true"
            | "false"
            | "none"
            | "list"
            | "dictionary"
            | "set"
            | "tuple"
    ) {
        DescriptorAnswer::No
    } else {
        DescriptorAnswer::Unknown
    }
}

fn class_may_define_descriptor(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    class: &ClassIdentity,
) -> DescriptorAnswer {
    if let ClassIdentity::Workspace(unit) = class {
        let python = python_analyzer(workspace);
        let Some(prepared) = current_indexed_prepared(python, unit.source()) else {
            return DescriptorAnswer::Unknown;
        };
        let Some(class_node) = class_node_for_unit(python, &prepared, unit) else {
            return DescriptorAnswer::Unknown;
        };
        if class_node
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
        {
            return DescriptorAnswer::Unknown;
        }
    }
    let mut unresolved = false;
    for hook in ["__get__", "__set__"] {
        match adapter.member_lookup(workspace, MemberAccessKind::Load, class, hook) {
            MemberLookup::Present(_) => return DescriptorAnswer::Yes,
            MemberLookup::Absent | MemberLookup::DeclarationAbsent => {}
            MemberLookup::Unknown(_) => unresolved = true,
        }
    }
    if unresolved {
        DescriptorAnswer::Unknown
    } else {
        DescriptorAnswer::No
    }
}

fn external_member_may_be_descriptor(
    adapter: &PythonTypeFlowAdapter,
    workspace: &WorkspaceAnalyzer,
    class: &ClassIdentity,
    member: &str,
) -> DescriptorAnswer {
    match adapter.member_lookup(workspace, MemberAccessKind::Load, class, member) {
        MemberLookup::Present(_) | MemberLookup::Unknown(_) => DescriptorAnswer::Unknown,
        MemberLookup::Absent | MemberLookup::DeclarationAbsent => DescriptorAnswer::No,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PythonAnalyzer, PythonTypeFlowAdapter, prepared_for_procedure,
        workspace_class_uses_ordinary_metaclass,
    };
    use crate::analyzer::semantic::{
        CancellationToken, ClassIdentity, ClassSeed, DynamicFieldNameSet, DynamicFieldWrite,
        ProcedureKind, SemanticBudget, SemanticRequest, TypeFlowAdapter, UnknownReason,
    };
    use crate::analyzer::{AnalyzerConfig, CodeUnitIndex, Language, resolve_analyzer};
    use crate::inline_project::InlineTestProject;

    #[test]
    fn descriptor_setter_dynamic_write_retains_its_receiver() {
        let source = "from __future__ import annotations\nclass Observable:\n    def __set__(self, instance: HasEmitters, value):\n        setattr(instance, self.private_name, value)\nclass HasEmitters:\n    pass\n";
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("app.py");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Python semantic materialization succeeds")
            .available_value()
            .cloned()
            .expect("Python semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .filter_map(|procedure| artifact.procedure_handle(procedure.id()))
            .find(|procedure| {
                procedure
                    .semantics()
                    .locator()
                    .anchor()
                    .span()
                    .start()
                    .line()
                    == 2
            })
            .expect("fixture has the descriptor setter procedure");
        let writes = PythonTypeFlowAdapter.dynamic_field_writes(&workspace, &procedure);
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert!(
            matches!(
                writes.as_slice(),
                [DynamicFieldWrite::Scoped {
                    names: DynamicFieldNameSet::Any,
                    receiver: Some(_),
                    ..
                }]
            ),
            "the dynamic write keeps its unknown name and explicit instance receiver: {writes:?}"
        );
        let DynamicFieldWrite::Scoped { span, .. } = &writes[0] else {
            unreachable!();
        };
        let bound =
            PythonTypeFlowAdapter.dynamic_write_receiver_bound(&workspace, &procedure, *span);
        assert_eq!(
            bound.as_ref().map(ClassIdentity::qualified_name),
            Some("app.HasEmitters"),
            "the postponed annotation resolves to its forward-declared workspace class"
        );
    }

    #[test]
    fn generic_iteration_receiver_resolves_type_checking_import_bound() {
        let agent = "class Agent:\n    pass\n";
        let agentset = "from __future__ import annotations\nfrom collections.abc import Iterator\nfrom typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n    from mesa.agent import Agent\n\nclass AgentSet[A: Agent]:\n    def __iter__(self) -> Iterator[A]:\n        return iter(())\n\n    def set(self, name, value):\n        for agent in self:\n            setattr(agent, name, value)\n";
        let project = InlineTestProject::with_language(Language::Python)
            .file("mesa/__init__.py", "")
            .file("mesa/agent.py", agent)
            .file("mesa/agentset.py", agentset)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("mesa/agentset.py");
        let python = super::python_analyzer(&workspace);
        let prepared = super::current_indexed_prepared(python, &file).unwrap();
        let root = prepared.tree().root_node();
        let mut root_cursor = root.walk();
        let class = root
            .named_children(&mut root_cursor)
            .find(|node| {
                node.kind() == "class_definition"
                    && node
                        .child_by_field_name("name")
                        .and_then(|name| name.utf8_text(prepared.source().as_bytes()).ok())
                        == Some("AgentSet")
            })
            .unwrap();
        let type_parameter = class
            .child_by_field_name("type_parameters")
            .and_then(|parameters| parameters.named_child(0))
            .unwrap();
        let (_, bound) =
            super::python_type_parameter_declaration(type_parameter, prepared.source()).unwrap();
        let bound = bound.unwrap();
        let candidate =
            super::python_workspace_class_candidate(&workspace, &file, &prepared, bound);
        assert_eq!(
            candidate.as_ref().map(ClassIdentity::qualified_name),
            Some("mesa.agent.Agent"),
            "the TYPE_CHECKING import resolves the generic upper bound"
        );
        let iterator = class
            .child_by_field_name("body")
            .and_then(|body| {
                let mut cursor = body.walk();
                body.named_children(&mut cursor).find(|node| {
                    node.kind() == "function_definition"
                        && node
                            .child_by_field_name("name")
                            .and_then(|name| name.utf8_text(prepared.source().as_bytes()).ok())
                            == Some("__iter__")
                })
            })
            .unwrap();
        let return_type = iterator.child_by_field_name("return_type").unwrap();
        let (_, element_type) = super::python_first_generic_type_argument(return_type).unwrap();
        assert!(matches!(
            super::python_type_variable_bound_seed(
                &workspace,
                &file,
                &prepared,
                class,
                element_type
            ),
            Some(ClassSeed::ClassWithOpenBound(ClassIdentity::Workspace(ref class)))
                if class.fq_name_str() == "mesa.agent.Agent"
        ));
    }

    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#3531: Memoized builtin-shadow answers must follow exact prepared-source identity, module versus function scope, and local shadowing"
    )]
    fn builtin_shadow_memo_keeps_source_and_reference_identity() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("open.py", "pass         \nclass C(list):\n    pass\n")
            .file("shadowed.py", "list = object\nclass C(list):\n    pass\n")
            .file("scopes.py", "class Open(list):\n    pass\ndef f(list):\n    class Closed(list):\n        pass\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let python = super::python_analyzer(&workspace);
        let memo = super::PythonBuiltinShadowRequestMemo::default();
        for _ in 0..3 {
            for (file, expected) in [("open.py", true), ("shadowed.py", false)] {
                let prepared =
                    super::current_indexed_prepared(python, &project.file(file)).unwrap();
                let class = prepared.tree().root_node().named_child(1).unwrap();
                let base = class
                    .child_by_field_name("superclasses")
                    .unwrap()
                    .named_child(0)
                    .unwrap();
                let session =
                    super::ResolutionSession::bounded(super::INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
                assert_eq!(memo.unshadowed(base, &prepared, &session), Some(expected));
                assert_eq!(
                    super::builtin_base_is_unshadowed(base, prepared.source()),
                    Some(expected)
                );
            }
            let prepared =
                super::current_indexed_prepared(python, &project.file("scopes.py")).unwrap();
            let module = prepared.tree().root_node();
            let open = module.named_child(0).unwrap();
            let closed = module
                .named_child(1)
                .unwrap()
                .child_by_field_name("body")
                .unwrap()
                .named_child(0)
                .unwrap();
            for (class, expected) in [(open, true), (closed, false)] {
                let base = class
                    .child_by_field_name("superclasses")
                    .unwrap()
                    .named_child(0)
                    .unwrap();
                let session =
                    super::ResolutionSession::bounded(super::INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
                assert_eq!(memo.unshadowed(base, &prepared, &session), Some(expected));
                assert_eq!(
                    super::builtin_base_is_unshadowed(base, prepared.source()),
                    Some(expected)
                );
            }
        }
        assert_eq!(memo.walks.load(std::sync::atomic::Ordering::Relaxed), 4);
    }

    #[test]
    #[hardwon(
        "#3531: An exhausted or cancelled syntax walk must not poison the later funded memo answer"
    )]
    fn builtin_shadow_memo_retries_exhaustion_and_respects_cancellation() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "class C(list):\n    pass\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let prepared = super::current_indexed_prepared(
            super::python_analyzer(&workspace),
            &project.file("app.py"),
        )
        .unwrap();
        let base = prepared
            .tree()
            .root_node()
            .named_child(0)
            .unwrap()
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        let memo = super::PythonBuiltinShadowRequestMemo::default();
        let mut tiny = super::INTERACTIVE_TYPE_LOOKUP_BUDGET;
        tiny.max_scope_nodes = 1;
        assert_eq!(
            memo.unshadowed(
                base,
                &prepared,
                &super::ResolutionSession::bounded(tiny, None)
            ),
            None
        );
        let funded =
            || super::ResolutionSession::bounded(super::INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
        assert_eq!(memo.unshadowed(base, &prepared, &funded()), Some(true));
        assert_eq!(memo.unshadowed(base, &prepared, &funded()), Some(true));
        assert_eq!(memo.walks.load(std::sync::atomic::Ordering::Relaxed), 2);
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let stopped = super::ResolutionSession::bounded(
            super::INTERACTIVE_TYPE_LOOKUP_BUDGET,
            Some(&cancellation),
        );
        assert_eq!(memo.unshadowed(base, &prepared, &stopped), None);
        let fresh = super::PythonBuiltinShadowRequestMemo::default();
        assert_eq!(
            fresh.unshadowed(
                base,
                &prepared,
                &super::ResolutionSession::bounded(tiny, None)
            ),
            None
        );
    }

    #[test]
    #[hardwon(
        "#3531: A memo is reused within one analyzer query, discarded on cancellation, and recreated for the next query scope"
    )]
    fn builtin_shadow_answers_are_reused_only_inside_the_active_query() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "class C(list):\n    pass\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let python = super::python_analyzer(&workspace);
        let prepared = super::current_indexed_prepared(python, &project.file("app.py")).unwrap();
        let base = prepared
            .tree()
            .root_node()
            .named_child(0)
            .unwrap()
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        let cancellation = CancellationToken::default();
        let scope = crate::analyzer::AnalyzerQueryScope::with_cancellation(
            workspace.analyzer(),
            &cancellation,
        );
        let memo = python
            .active_query_request_memo::<super::PythonBuiltinShadowRequestMemo>()
            .unwrap();
        for _ in 0..8 {
            assert_eq!(
                super::indexed_builtin_is_unshadowed(python, base, &prepared),
                Some(true)
            );
        }
        assert_eq!(memo.walks.load(std::sync::atomic::Ordering::Relaxed), 1);
        cancellation.cancel();
        assert_eq!(
            super::indexed_builtin_is_unshadowed(python, base, &prepared),
            None
        );
        drop(scope);
        let fresh_cancellation = CancellationToken::default();
        let _fresh_scope = crate::analyzer::AnalyzerQueryScope::with_cancellation(
            workspace.analyzer(),
            &fresh_cancellation,
        );
        let fresh = python
            .active_query_request_memo::<super::PythonBuiltinShadowRequestMemo>()
            .unwrap();
        assert!(!std::sync::Arc::ptr_eq(&memo, &fresh));
        assert_eq!(
            super::indexed_builtin_is_unshadowed(python, base, &prepared),
            Some(true)
        );
        assert_eq!(fresh.walks.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn class_lookup_reuses_answer_and_dependency_reads_within_request() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("models.py", "class Widget:\n    pass\n")
            .file("app.py", "import models\nresult = models.Widget()\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("app.py");
        let python = super::python_analyzer(&workspace);
        let prepared = super::current_indexed_prepared(python, &file).unwrap();
        let assignment = prepared
            .tree()
            .root_node()
            .named_child(1)
            .unwrap()
            .named_child(0)
            .unwrap();
        let callee = assignment
            .child_by_field_name("right")
            .unwrap()
            .child_by_field_name("function")
            .unwrap();
        let span = super::span_for_node(callee);
        let cancellation = CancellationToken::default();
        let _scope = crate::analyzer::AnalyzerQueryScope::with_cancellation(
            workspace.analyzer(),
            &cancellation,
        );
        let memo = python
            .active_query_request_memo::<super::PythonClassLookupRequestMemo>()
            .unwrap();
        let resolve = || {
            crate::analyzer::capture_query_reads(workspace.analyzer(), || {
                super::resolve_class_at_span(&workspace, file.clone(), span, &prepared)
            })
        };
        let (cold, cold_reads) = resolve();
        assert!(
            matches!(&cold, ClassSeed::Class(class) if class.qualified_name() == "models.Widget")
        );
        assert!(
            !cold_reads.is_empty(),
            "resolved declaration must retain dependencies"
        );
        for _ in 0..8 {
            let (warm, warm_reads) = resolve();
            assert_eq!(warm, cold);
            assert_eq!(warm_reads.keys(), cold_reads.keys());
            assert_eq!(
                warm_reads.unattributed_reads(),
                cold_reads.unattributed_reads()
            );
        }
        assert_eq!(memo.lookups.load(std::sync::atomic::Ordering::Relaxed), 1);
        cancellation.cancel();
        assert_eq!(
            super::resolve_class_at_span(&workspace, file.clone(), span, &prepared),
            ClassSeed::Unknown(UnknownReason::SemanticBudget)
        );
        drop(_scope);
        let fresh = super::resolve_class_at_span(&workspace, file, span, &prepared);
        assert_eq!(fresh, cold, "a fresh uncached query is the answer oracle");
    }

    #[test]
    fn module_binding_reuse_preserves_budget_failure_and_exact_source_identity() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "class Target:\n    pass\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("app.py");
        let prepared = super::current_indexed_prepared(super::python_analyzer(&workspace), &file)
            .expect("indexed class snapshot");
        let memo = super::PythonModuleBindingRequestMemo::default();
        let session = |steps| {
            let mut limits = super::INTERACTIVE_TYPE_LOOKUP_BUDGET;
            limits.max_scope_nodes = steps;
            super::ResolutionSession::bounded(limits, None)
        };
        assert_eq!(memo.binding(&prepared, "Target", &session(1)), None);
        let class = Some(Some(super::PythonDirectScopeBindingKind::ClassDeclaration));
        assert_eq!(memo.binding(&prepared, "Target", &session(200_000)), class);
        assert_eq!(
            memo.binding(&prepared, "Target", &session(1)),
            class,
            "a successful prior lookup must avoid repeating its syntax walk"
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled = super::ResolutionSession::bounded(
            super::INTERACTIVE_TYPE_LOOKUP_BUDGET,
            Some(&cancellation),
        );
        assert_eq!(memo.binding(&prepared, "Target", &cancelled), None);
        assert_eq!(
            memo.binding(&prepared, "absent", &session(200_000)),
            Some(None)
        );
        assert_eq!(memo.binding(&prepared, "absent", &session(1)), Some(None));

        std::fs::write(file.abs_path(), "def Target():\n    pass\n").expect("replace fixture");
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let changed =
            super::current_indexed_prepared(super::python_analyzer(&changed_workspace), &file)
                .expect("indexed changed snapshot");
        assert_eq!(memo.binding(&changed, "Target", &session(1)), None);
        assert_eq!(
            memo.binding(&changed, "Target", &session(200_000)),
            Some(Some(
                super::PythonDirectScopeBindingKind::FunctionDeclaration
            ))
        );
        assert_eq!(memo.binding(&prepared, "Target", &session(1)), class);
    }

    #[test]
    fn prepared_syntax_validator_accepts_exact_content_and_rejects_changed_content() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "def target():\n    return 1\n")
            .build();
        let file = project.file("app.py");
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Python semantic materialization succeeds")
            .available_value()
            .cloned()
            .expect("Python semantic artifact is available");
        let procedure = artifact
            .procedures()
            .first()
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture has one procedure");

        let prepared = prepared_for_procedure(&workspace, &procedure, &file)
            .expect("unchanged syntax validates");
        let expected =
            crate::analyzer::semantic::ContentIdentity::hash_bytes(prepared.source().as_bytes());
        for _ in 0..100 {
            assert_eq!(&prepared.source_sha256(), expected.as_bytes());
            assert!(prepared_for_procedure(&workspace, &procedure, &file).is_ok());
        }

        std::fs::write(file.abs_path(), "def target():\n    return 2\n")
            .expect("change fixture content");
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let changed =
            super::current_indexed_prepared(super::python_analyzer(&changed_workspace), &file)
                .expect("changed snapshot is indexed");
        assert_ne!(prepared.source_sha256(), changed.source_sha256());
        assert_eq!(
            &changed.source_sha256(),
            crate::analyzer::semantic::ContentIdentity::hash_bytes(changed.source().as_bytes())
                .as_bytes(),
        );
        assert_eq!(
            prepared_for_procedure(&changed_workspace, &procedure, &file)
                .expect_err("changed content cannot validate an old artifact"),
            UnknownReason::UncertainFlow
        );
    }

    #[test]
    fn receiver_stability_accounts_for_comprehension_binding_scope() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "class Holder:\n    def stable(this):\n        data = [this for this in ()]\n        return this\n    def rebound(this):\n        data = [(this := x) for x in (1,)]\n        return this\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("method semantics materialize")
            .available_value()
            .cloned()
            .expect("method semantics are available");
        for (name, expected) in [("stable", true), ("rebound", false)] {
            let procedure = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("fixture declares the method");
            assert_eq!(
                PythonTypeFlowAdapter.receiver_binding_is_stable(&workspace, &procedure),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn native_member_closure_does_not_close_a_workspace_subclass() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "class Text(str):\n    pass\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer())
            .expect("workspace has the Python analyzer");
        let text = python
            .top_level_declarations(&project.file("app.py"))
            .into_iter()
            .find(|unit| unit.is_class())
            .expect("Text is declared");
        assert!(
            !PythonTypeFlowAdapter
                .member_surface_is_closed(&workspace, &ClassIdentity::Workspace(text))
        );
        assert!(PythonTypeFlowAdapter.member_surface_is_closed(
            &workspace,
            &ClassIdentity::External {
                qualified_name: "builtins.str".into(),
                symbol_id: "type.builtins-str".into(),
            }
        ));
    }

    #[test]
    fn shared_instance_guard_requires_identity_for_workspace_decorators() {
        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "app.py",
                "class Plain:\n    pass\n\nclass Actual:\n    pass\n\ndef replace(cls):\n    return Actual\n\n@replace\nclass Replaced:\n    def foo(self):\n        pass\n",
            )
            .build();
        let file = project.file("app.py");
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer())
            .expect("workspace has the Python analyzer");
        let class_named = |name: &str| {
            python
                .top_level_declarations(&file)
                .into_iter()
                .find(|unit| unit.is_class() && unit.short_name() == name)
                .unwrap_or_else(|| panic!("missing class declaration {name}"))
        };
        let adapter = PythonTypeFlowAdapter;

        let plain = ClassIdentity::Workspace(class_named("Plain"));
        assert!(
            adapter.guard_classes_have_supported_instance_checks(
                &workspace,
                std::slice::from_ref(&plain),
                None,
            ),
            "an undecorated ordinary workspace class remains a supported guard class",
        );

        let replaced = ClassIdentity::Workspace(class_named("Replaced"));
        assert!(
            !adapter.guard_classes_have_supported_instance_checks(
                &workspace,
                std::slice::from_ref(&replaced),
                None,
            ),
            "an unreviewed workspace decorator cannot establish class identity",
        );
        assert!(
            !workspace_class_uses_ordinary_metaclass(
                &workspace,
                python,
                match &replaced {
                    ClassIdentity::Workspace(owner) => owner,
                    ClassIdentity::External { .. } => unreachable!(),
                },
                None,
            ),
            "the shared guard and its class proof reject the replacing decorator",
        );
    }

    #[test]
    fn quoted_descriptor_setter_resolves_its_forward_receiver_class() {
        let source = "class Observable:\n    def __set__(self, instance: \"HasEmitters\", value):\n        setattr(instance, self.private_name, value)\nclass HasEmitters:\n    pass\n";
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("app.py");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Python semantic materialization succeeds")
            .available_value()
            .cloned()
            .expect("Python semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .filter_map(|procedure| artifact.procedure_handle(procedure.id()))
            .find(|procedure| {
                procedure
                    .semantics()
                    .locator()
                    .anchor()
                    .span()
                    .start()
                    .line()
                    == 1
            })
            .expect("fixture has the descriptor setter procedure");
        let writes = PythonTypeFlowAdapter.dynamic_field_writes(&workspace, &procedure);
        let [DynamicFieldWrite::Scoped { span, .. }] = writes.as_slice() else {
            panic!("the quoted descriptor keeps its explicit receiver: {writes:?}");
        };
        let bound =
            PythonTypeFlowAdapter.dynamic_write_receiver_bound(&workspace, &procedure, *span);
        assert_eq!(
            bound.as_ref().map(ClassIdentity::qualified_name),
            Some("app.HasEmitters"),
            "the quoted annotation resolves to its forward-declared workspace class"
        );
    }

    #[test]
    fn constructed_class_uses_whole_dotted_callee_and_rejects_namespace_rebinding() {
        for (consumer, expected) in [
            (
                "import models\ndef make():\n    return models.Widget()\n",
                Some("models.Widget"),
            ),
            (
                "import models\nclass Holder:\n    models = 0\n    def make(self):\n        return models.Widget()\n",
                Some("models.Widget"),
            ),
            (
                concat!(
                    "import models\n",
                    "models = object()\n",
                    "def make():\n",
                    "    return models.Widget()\n",
                ),
                None,
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Python)
                .file("models.py", "class Widget:\n    pass\n")
                .file("consumer.py", consumer)
                .build();
            let file = project.file("consumer.py");
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let artifact = workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Python semantic materialization succeeds")
                .available_value()
                .cloned()
                .expect("Python semantic artifact is available");
            let procedure = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    matches!(
                        procedure.kind(),
                        ProcedureKind::Function | ProcedureKind::Method
                    ) && !procedure.call_sites().is_empty()
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("fixture has one callable with a constructor call");
            let call = procedure
                .semantics()
                .call_sites()
                .first()
                .expect("fixture retains its call");
            let seed = PythonTypeFlowAdapter.constructed_class(&workspace, &procedure, call);
            match expected {
                Some(expected) => {
                    let ClassSeed::Class(class) = seed else {
                        panic!("dotted constructor did not produce an exact class: {seed:?}");
                    };
                    assert_eq!(class.qualified_name(), expected);
                }
                None => assert!(matches!(
                    seed,
                    ClassSeed::NotApplicable | ClassSeed::Unknown(_)
                )),
            }
        }
    }
}
