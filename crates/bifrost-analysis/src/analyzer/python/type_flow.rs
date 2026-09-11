//! Python class-set adapter: the per-language seeds and member lookup the
//! type-flow engine cannot derive from the language-neutral semantic IR.
//!
//! Every answer comes from structured sources: the semantic IR's exact source
//! mappings, the analyzer's prepared tree-sitter syntax, bounded direct-site type lookup
//! for callee and annotation resolution, the declaration index for class
//! members, and the active semantic-model overlay for external classes. No
//! source text is parsed or scanned here; reading a node's text at an
//! AST-provided span is structured access.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::{PreparedSyntaxSource, PreparedSyntaxTree};
use brokk_bifrost_python::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution, python_comprehension_binds_name_at,
    python_module_or_class_scope_binds_name_bounded, python_type_parameter_binds_name_at,
    python_unambiguous_module_binding_bounded, python_unambiguous_module_class_binding_bounded,
};
use brokk_bifrost_python::declarations::{python_base_origin_node, python_first_parameter_name};
use brokk_bifrost_python::diagnostics::is_python_builtin_or_constant;
use brokk_bifrost_python::syntax::python_plain_string_literal;
use tree_sitter::Node;

use super::PythonAnalyzer;
use super::lexical_scope::python_lexical_scope_inventory_bounded;
use crate::analyzer::lexical_definitions::{PythonMethodBinding, formal_parameter_slots_for_owner};
use crate::analyzer::semantic::type_flow::{
    ClassHierarchy, ClassIdentity, ClassSeed, DynamicFieldWrite, ExternalClassCache,
    MemberAccessKind, MemberAccessQuery, MemberDeclaration, MemberLookup, MemberLookupHit,
    NarrowingVerdict, NormalReturnTypeConstraint, TypeFlowAdapter, UnknownReason,
    analyzer_range_for_span, class_seed_from_lookup_types, external_class_identity,
    external_member_lookup, file_for_locator, source_span_for_node,
    validate_prepared_syntax_for_procedure,
};
use crate::analyzer::semantic::{
    AdapterSemanticsVersion, AllocationSite, CandidateCoverage, GuardFact, GuardPredicate,
    MemoryLocationKind, ProcedureHandle, ProcedureKind, SemanticCallSite, SemanticEffect,
    SemanticValue, SemanticValueKind, SourceMappingKind, SourceSpan, ValueFlowKind, ValueId,
};
use crate::analyzer::semantic_model::{
    ProcedureSummaryMemberKey, SemanticModelCompleteness, SemanticModelMatchDisposition,
    SemanticModelOverlay, SemanticModelSymbolKind, semantic_model_callable_family_id,
};
use crate::analyzer::usages::ImportKind;
use crate::analyzer::usages::get_definition::{
    PythonDefinitionProvider, ResolutionSession, python_attribute_callee_reads_a_field_bounded,
    python_external_imported_symbol_bounded, python_namespace_imported_class_name_bounded,
};
use crate::analyzer::usages::get_type::{
    TypeLookupStatus, resolve_type_at_reference_site_with_budget,
};
use crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, Language, ProjectFile, QueryScope,
    TypeHierarchyProvider, WorkspaceAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;
use crate::path_utils::rel_path_string;

/// The Python [`TypeFlowAdapter`]. Zero-sized: every method receives the
/// workspace it consults.
pub struct PythonTypeFlowAdapter;

/// One name-resolution cache, local to a single adapter call.
pub(super) fn python_analyzer(workspace: &WorkspaceAnalyzer) -> &PythonAnalyzer {
    resolve_analyzer::<PythonAnalyzer>(workspace.analyzer())
        .expect("PythonTypeFlowAdapter serves only workspaces that analyze Python")
}

fn overlay_of(workspace: &WorkspaceAnalyzer) -> Option<Arc<SemanticModelOverlay>> {
    workspace
        .analyzer()
        .active_semantic_model_snapshot()
        .and_then(|snapshot| snapshot.semantic_model_overlay().cloned())
}

pub(super) fn prepared_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let python = python_analyzer(workspace);
    let scope = AnalyzerQueryScope::new(python);
    let prepared = python
        .inner
        .prepared_syntax(scope.token(), file)
        .ok_or(UnknownReason::UncertainFlow)?;
    validate_prepared_syntax_for_procedure(workspace, procedure, file, prepared)
}

pub(super) fn current_indexed_prepared(
    python: &PythonAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    let scope = AnalyzerQueryScope::new(python);
    let prepared = python.inner.prepared_syntax(scope.token(), file)?;
    (matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_))
        && python.indexed_source_matches(file, prepared.source()))
    .then_some(prepared)
}

pub(super) fn node_at_span(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Node<'_>> {
    prepared
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
}

fn node_text_at(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Box<str>> {
    let node = node_at_span(prepared, span)?;
    node.utf8_text(prepared.source().as_bytes())
        .ok()
        .map(Box::from)
}

fn span_for_node(node: Node<'_>) -> SourceSpan {
    source_span_for_node(node)
}

fn range_for_span(span: SourceSpan) -> crate::analyzer::Range {
    analyzer_range_for_span(span)
}

fn enclosing_workspace_class(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
) -> Option<CodeUnit> {
    let locator = procedure.semantics().locator();
    let file = file_for_locator(workspace, locator)?;
    let mut unit = workspace
        .analyzer()
        .enclosing_code_unit(&file, &range_for_span(locator.anchor().span()))?;
    loop {
        if unit.is_class() {
            return Some(unit);
        }
        unit = workspace.analyzer().parent_of(&unit)?;
    }
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
        .is_some_and(|member| {
            matches!(
                member,
                "update" | "setdefault" | "pop" | "popitem" | "clear"
            )
        });
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
    Any,
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
                return match write {
                    DynamicMemberName::Any => true,
                    DynamicMemberName::Member(name) => name.as_ref() == member,
                };
            }
        }
    }
    match dynamic_call_write(node, source) {
        Some(DynamicMemberName::Any) => true,
        Some(DynamicMemberName::Member(name)) => name.as_ref() == member,
        None => false,
    }
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
    source: &str,
) -> DynamicFieldWrite {
    if let DynamicMemberName::Member(member) = name {
        return DynamicFieldWrite::Member(member);
    }
    let span = span_for_node(node);
    let semantics = procedure.semantics();
    let dictionary_owner = |dictionary: Node<'_>| {
        let attribute = dictionary.child_by_field_name("attribute")?;
        let member_span = span_for_node(attribute);
        semantics.memory_locations().iter().find_map(|location| {
            let MemoryLocationKind::Field { base, member } = &location.kind else {
                return None;
            };
            (member.anchor().span() == member_span).then_some(*base)
        })
    };
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
                                    overlay_of(workspace).as_deref(),
                                    object,
                                    source,
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
    DynamicFieldWrite::Any { receiver, span }
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
        // Overload declarations may share this exact callable identity. Every
        // declaration must agree; an alias posting alone is not exact binding.
        if semantic_model_callable_family_id(&symbols.records).is_none()
            || symbols.records.iter().any(|symbol| {
                symbol.qualified_name != canonical
                    || symbol.language != Language::Python.config_label()
                    || symbol.kind != SemanticModelSymbolKind::Function
                    || symbol.has_receiver()
                    || symbol.provenance.ambiguous
                    || symbol.provenance.completeness != SemanticModelCompleteness::Complete
            })
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
            ClassSeed::ClassWithOpenBound(_)
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
    let scope = AnalyzerQueryScope::new(python);
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let support = PythonDefinitionProvider::new(python, &session);
    let Some((module, member)) = python_external_imported_symbol_bounded(
        &support,
        scope.token(),
        owner.source(),
        prepared.source(),
        prepared.tree().root_node(),
        base,
    ) else {
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

/// Raw supertypes retain source spelling, not a resolved import identity. A
/// terminal-name overlay match such as `ABC` -> `abc.ABC` is therefore not a
/// proof of the base. A builtin spelling is accepted only after proving that
/// the actual base expression has no competing lexical or module binding.
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
        let identity = external_class_identity(overlay, Language::Python, &canonical, None, cache)?;
        if identity.qualified_name() != canonical {
            // Exact exported aliases name the same external declaration.
            // A terminal-name posting alone is not proof of this base.
            let ClassIdentity::External { symbol_id, .. } = &identity else {
                unreachable!("external class lookup returns an external identity")
            };
            let matched = overlay?.symbols_with_id(symbol_id);
            let [record] = matched.records.as_slice() else {
                return None;
            };
            if !record.aliases.iter().any(|alias| alias == &canonical) {
                return None;
            }
        }
        identity
    } else {
        let ClassSeed::Class(identity) =
            builtin_class_reference(overlay, base, prepared.source(), cache)?
        else {
            return None;
        };
        identity
    };
    python
        .indexed_source_matches(owner.source(), prepared.source())
        .then_some(identity)
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

/// The builtin class a bare unshadowed builtin name denotes.
///
/// A builtin has no workspace declaration, so a type lookup answers nothing
/// for `dict` in `isinstance(value, dict)`. The name is only that class when
/// no lexical or module binding competes with it, which is the same proof a
/// builtin base spelling needs.
fn exact_builtin_class(
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
    builtin_base_is_unshadowed(reference, prepared.source())?.then_some(identity)
}

pub(super) fn builtin_base_is_unshadowed(reference: Node<'_>, source: &str) -> Option<bool> {
    let name = reference.utf8_text(source.as_bytes()).ok()?;
    if python_comprehension_binds_name_at(name, reference, source)
        || python_type_parameter_binds_name_at(name, reference, source)
    {
        return Some(false);
    }
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
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
    let binding = match python_unambiguous_module_binding_bounded(
        prepared.tree().root_node(),
        source,
        name,
        || session.scope_step(),
    ) {
        None => return ClassSeed::Unknown(UnknownReason::SemanticBudget),
        Some(Some(
            binding @ (PythonDirectScopeBindingKind::ClassDeclaration
            | PythonDirectScopeBindingKind::FunctionDeclaration
            | PythonDirectScopeBindingKind::Import),
        )) => binding,
        Some(Some(PythonDirectScopeBindingKind::Other)) | Some(None) => {
            return ClassSeed::NotApplicable;
        }
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
    let python = python_analyzer(workspace);
    let scope = AnalyzerQueryScope::new(python);
    let session = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);
    let support = PythonDefinitionProvider::new(python, &session);
    let (module, member) = python_external_imported_symbol_bounded(
        &support,
        scope.token(),
        file,
        prepared.source(),
        prepared.tree().root_node(),
        reference,
    )?;
    external_class_identity(
        overlay_of(workspace).as_deref(),
        Language::Python,
        &format!("{module}.{member}"),
        None,
        &mut ExternalClassCache::default(),
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
    overlay: Option<&SemanticModelOverlay>,
    reference: Node<'_>,
    source: &str,
    cache: &mut ExternalClassCache,
) -> Option<ClassSeed> {
    if reference.kind() != "identifier" {
        return None;
    }
    let name = reference.utf8_text(source.as_bytes()).ok()?;
    if !is_python_builtin_or_constant(name) {
        return None;
    }
    match builtin_base_is_unshadowed(reference, source) {
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
    if let Some(reference) = node_at_span(prepared, span)
        && let Some(seed) = builtin_class_reference(
            overlay_of(workspace).as_deref(),
            reference,
            indexed_source,
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
        overlay_of(workspace).as_deref(),
        Language::Python,
        &outcome.types,
    )
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
        let overlay = overlay_of(workspace);
        let mut cache = ExternalClassCache::default();
        nodes
            .into_iter()
            .map(|class| {
                let span = span_for_node(class);
                match resolve_class_at_span(workspace, file.clone(), span, &prepared) {
                    ClassSeed::Class(class) => Ok(class),
                    ClassSeed::Unknown(UnknownReason::SemanticBudget) => {
                        Err(UnknownReason::SemanticBudget)
                    }
                    // A builtin name has no workspace declaration for the type
                    // lookup to return, so `isinstance(value, dict)` resolves
                    // to nothing through that route and is modeled here.
                    ClassSeed::NotApplicable => {
                        exact_builtin_class(class, &prepared, overlay.as_deref(), &mut cache)
                            .ok_or_else(|| unmodeled(class))
                    }
                    ClassSeed::ClassWithOpenBound(_)
                    | ClassSeed::ClassesWithOpenBound(_)
                    | ClassSeed::Unknown(_) => Err(unmodeled(class)),
                }
            })
            .collect()
    }

    fn guard_classes_have_supported_instance_checks(
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

    fn instance_relation(
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
        let overlay = overlay_of(workspace);
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

impl TypeFlowAdapter for PythonTypeFlowAdapter {
    fn language(&self) -> Language {
        Language::Python
    }

    fn semantics_version(&self) -> AdapterSemanticsVersion {
        // Keep cached class sets in step with program-point refinement,
        // guard remainders, scoped writes, open builtin call results, and the
        // class-object remainder a declared or imported class reference now
        // seeds.
        AdapterSemanticsVersion::hash_bytes(
            "python-type-flow",
            b"python-type-flow-unmodeled-guards-scoped-dynamic-writes-subscripted-annotation-outer-class-class-object-reference-imports-v35",
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
                    && builtin_base_is_unshadowed(function, prepared.source()) == Some(true);
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
        external_seed(overlay_of(workspace).as_deref(), name, &mut cache)
    }

    fn retained_value_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
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
                return external_seed(overlay_of(workspace).as_deref(), name, &mut cache);
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
                if python_unambiguous_module_class_binding_bounded(
                    prepared.tree().root_node(),
                    prepared.source(),
                    name,
                    || session.scope_step(),
                ) != Some(true)
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
                    let overlay = overlay_of(workspace);
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
                external_seed(overlay_of(workspace).as_deref(), "builtins.str", &mut cache)
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
        let seed = resolve_class_at_span(workspace, file.clone(), span, &prepared);
        if let ClassSeed::Class(ClassIdentity::External { qualified_name, .. }) = &seed {
            // Neither result has the instance member surface declared by the
            // builtin class itself.
            match qualified_name.as_ref() {
                // `type(value)` returns a class object, which is exactly what
                // `ClassObject` names.
                "builtins.type" => return ClassSeed::Unknown(UnknownReason::ClassObject),
                // `super()` returns a proxy bound to the enclosing class. It is
                // not a class object, so it keeps the unnamed-flow remainder.
                "builtins.super" => return ClassSeed::Unknown(UnknownReason::UncertainFlow),
                _ => {}
            }
        }
        if matches!(seed, ClassSeed::Class(_))
            && callee_reads_a_value(workspace, &file, &prepared, span)
        {
            return ClassSeed::NotApplicable;
        }
        seed
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
        external_seed(overlay_of(workspace).as_deref(), name, &mut cache)
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
        let mapping = semantics
            .source_mapping(allocation.source)
            .expect("an allocation retains a source mapping");
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
            "tuple" => "builtins.tuple",
            "generator_expression" => "typing.Generator",
            _ => return ClassSeed::NotApplicable,
        };
        let mut cache = ExternalClassCache::default();
        external_seed(overlay_of(workspace).as_deref(), name, &mut cache)
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
        // The grammar wraps the annotation in a `type` node; the expression
        // inside must be a bare or dotted name. Optional, unions, subscripts,
        // and quoted annotations declare no single class.
        let Some(type_node) = type_node else {
            return ClassSeed::NotApplicable;
        };
        let annotation = if type_node.kind() == "type" {
            let Some(inner) = type_node.named_child(0) else {
                return ClassSeed::NotApplicable;
            };
            inner
        } else {
            type_node
        };
        if !matches!(annotation.kind(), "identifier" | "attribute") {
            return ClassSeed::NotApplicable;
        }
        let seed = resolve_class_at_span(
            workspace,
            file,
            SourceSpan::new(
                crate::analyzer::semantic::SourcePosition::new(
                    annotation.start_byte() as u32,
                    annotation.start_position().row as u32,
                    annotation.start_position().column as u32,
                ),
                crate::analyzer::semantic::SourcePosition::new(
                    annotation.end_byte() as u32,
                    annotation.end_position().row as u32,
                    annotation.end_position().column as u32,
                ),
            )
            .expect("a tree-sitter node range is a valid source span"),
            &prepared,
        );
        // An annotation is an upper bound, not an identity: a caller may pass
        // any subclass, and a subclass declares members the annotated class
        // does not. Only a class nothing can extend states the runtime class.
        //
        // A builtin value class is the exception the model already makes
        // elsewhere: `str`, `int` and their siblings are subclassable in
        // principle, and treating an annotation naming one as exact is the
        // contract `builtin_class_reference` was added to serve. Widening them
        // here would make that resolution unusable.
        //
        // `object` is not one of them. Every class is an `object`, so the
        // annotation constrains nothing, and reading it as the exact class
        // would prove every member absent on any value a signature declares
        // that way -- which `__eq__(self, other: object)` does everywhere.
        let ClassSeed::Class(class) = seed else {
            return seed;
        };
        if class.qualified_name() == "builtins.object" {
            return ClassSeed::ClassWithOpenBound(class);
        }
        if is_builtin_value_class(&class) || self.declared_class_is_closed(workspace, &class) {
            ClassSeed::Class(class)
        } else {
            ClassSeed::ClassWithOpenBound(class)
        }
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
                let Some(overlay) = overlay_of(workspace) else {
                    return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
                };
                external_member_lookup(&overlay, symbol_id, member)
            }
        }
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
                return external_class_hierarchy(overlay_of(workspace).as_deref(), symbol_id);
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
        let overlay = overlay_of(workspace);
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

    fn field_slot_is_complete(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        member: &str,
    ) -> bool {
        let ClassIdentity::Workspace(unit) = class else {
            return false;
        };
        let python = python_analyzer(workspace);
        let file = unit.source();
        let Some(prepared) = current_indexed_prepared(python, file) else {
            return false;
        };
        let Some(class) = class_node_for_unit(python, &prepared, unit) else {
            return false;
        };
        if class
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
        {
            return false;
        }
        let Some(body) = class.child_by_field_name("body") else {
            return false;
        };
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            if assignment_name(child, prepared.source()) == Some(member) {
                return false;
            }
            if matches!(child.kind(), "function_definition" | "decorated_definition")
                && definition_name(child, prepared.source()) == Some(member)
            {
                return false;
            }
        }
        true
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
                    && self.field_slot_is_complete(workspace, owner, member)
            })
    }

    fn dynamic_field_writes(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Vec<DynamicFieldWrite> {
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return vec![DynamicFieldWrite::Any {
                receiver: None,
                span: semantics.locator().anchor().span(),
            }];
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(_) => {
                return vec![DynamicFieldWrite::Any {
                    receiver: None,
                    span: semantics.locator().anchor().span(),
                }];
            }
        };
        let Some(callable) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
            return vec![DynamicFieldWrite::Any {
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
            if let Some(write) = dynamic_call_write(node, prepared.source()) {
                writes.push(scoped_dynamic_write(
                    workspace,
                    procedure,
                    node,
                    write,
                    prepared.source(),
                ));
            }
            if matches!(node.kind(), "assignment" | "augmented_assignment")
                && let Some(write) = dictionary_write(node, prepared.source())
            {
                writes.push(DynamicFieldWrite::Member("__dict__".into()));
                writes.push(scoped_dynamic_write(
                    workspace,
                    procedure,
                    node,
                    write,
                    prepared.source(),
                ));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        writes
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
                let overlay = overlay_of(workspace);
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
                let overlay = overlay_of(workspace);
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
            | GuardPredicate::Opaque { .. } => unknown(),
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
            ) || call.arguments.iter().any(|argument| {
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
            } else if let [argument] = call.arguments.as_ref()
                && call
                    .result
                    .is_some_and(|result| opaque_guard_subjects.contains(&result))
            {
                subjects.push(argument.value);
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
    ) -> Option<(ValueId, Vec<NarrowingVerdict>)> {
        super::guard_summary::call_guard_narrowing(
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

#[cfg(test)]
mod tests {
    use super::{
        PythonAnalyzer, PythonTypeFlowAdapter, prepared_for_procedure,
        workspace_class_uses_ordinary_metaclass,
    };
    use crate::analyzer::semantic::{
        CancellationToken, ClassIdentity, ClassSeed, ProcedureKind, SemanticBudget,
        SemanticRequest, TypeFlowAdapter, UnknownReason,
    };
    use crate::analyzer::{AnalyzerConfig, CodeUnitIndex, Language, resolve_analyzer};
    use crate::inline_project::InlineTestProject;

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

        assert!(prepared_for_procedure(&workspace, &procedure, &file).is_ok());

        std::fs::write(file.abs_path(), "def target():\n    return 2\n")
            .expect("change fixture content");
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            prepared_for_procedure(&changed_workspace, &procedure, &file)
                .expect_err("changed content cannot validate an old artifact"),
            UnknownReason::UncertainFlow
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
                None => assert_eq!(seed, ClassSeed::NotApplicable),
            }
        }
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
}
