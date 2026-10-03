//! TypeScript receiver-owner and type-text property-owner resolution.
//!
//! `ts_resolve_type_text_to_property_owners` and the mutually recursive cluster
//! around it (`ts_expression_property_owners`, `ts_call_expression_callees`,
//! `ts_receiver_owner_candidates_at_byte_with_resolution`, and the
//! `TsReceiverResolution` recursion guard) answer one question: given a receiver
//! spelling or a type-text at a byte, which declarations own the properties it
//! exposes? The JS/TS usage graph (`js_ts_graph/{extractor,receiver_analysis}`)
//! and both definition routes ask it, so it lives beside the rest of the JS/TS
//! language logic rather than inside `usages/get_definition/js_ts.rs`, which the
//! graph would otherwise have to import (issue: the js_ts crate extraction,
//! Js-1b).
//!
//! Analyzer access is on [`JsTsSource`] wherever the cluster reaches a
//! JS/TS-only capability (the type-vs-value candidate spaces, which read
//! `is_type_alias`, and the import-candidate resolvers, which reach the
//! per-language usage index through the host's memo caches). The three helpers
//! that only read declaration ranges take `&dyn CodeUnitIndex` instead, so their
//! framework callers need no downcast at all.

use crate::imports::{
    resolve_js_ts_direct_import_candidates, resolve_js_ts_module_binding_candidates,
};
use crate::providers::JsTsSource;
use crate::source_facts::JsTsFileSourceFacts;
#[cfg(test)]
use crate::syntax::compute_import_binder as compute_jsts_import_binder;
use crate::syntax::{
    JsTsImportBinder, nested_type_identifier_parts, parse_js_ts_tree, slice,
    ts_type_wrapper_operand, ts_type_wrapper_type,
};
use crate::tsconfig::AliasResolver;
use crate::type_text::{
    jsts_type_space_candidates, jsts_unit_is_type_only, jsts_value_space_candidates,
    ts_clean_type_text,
};
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::js_ts_facts::{
    JsTsDeclarationFact, JsTsSourceTypeId, JsTsTypeShape,
};
use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome,
};
use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, Language, ProjectFile,
};
use brokk_bifrost_core::hash::HashSet;
use std::cell::{Cell, RefCell};
use tree_sitter::Node;

const MAX_TS_RECEIVER_RESOLUTION_DEPTH: usize = 64;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TsReceiverResolutionKey {
    scope_id: usize,
    receiver: String,
    byte: usize,
}

#[derive(Default)]
pub struct TsReceiverResolution {
    active: RefCell<HashSet<TsReceiverResolutionKey>>,
    depth: Cell<usize>,
}

struct TsReceiverResolutionGuard<'a> {
    resolution: &'a TsReceiverResolution,
    key: TsReceiverResolutionKey,
}

impl TsReceiverResolution {
    fn enter(&self, key: TsReceiverResolutionKey) -> Option<TsReceiverResolutionGuard<'_>> {
        let depth = self.depth.get();
        if depth >= MAX_TS_RECEIVER_RESOLUTION_DEPTH
            || !self.active.borrow_mut().insert(key.clone())
        {
            return None;
        }
        self.depth.set(depth + 1);
        Some(TsReceiverResolutionGuard {
            resolution: self,
            key,
        })
    }
}

impl Drop for TsReceiverResolutionGuard<'_> {
    fn drop(&mut self) {
        self.resolution.active.borrow_mut().remove(&self.key);
        self.resolution
            .depth
            .set(self.resolution.depth.get().saturating_sub(1));
    }
}

pub fn jsts_member_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    receiver_candidates: Vec<CodeUnit>,
    member: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for receiver in receiver_candidates {
        candidates.extend(support.fqn(&format!("{}.{}", receiver.fq_name(), member)));
    }
    if value_position {
        jsts_value_space_candidates(host, candidates)
    } else {
        jsts_type_space_candidates(host, candidates)
    }
}

pub fn ts_direct_object_literal_value(node: Node<'_>) -> Option<Node<'_>> {
    let node = ts_unwrap_expression(node)?;
    (node.kind() == "object").then_some(node)
}

/// The expression inside parentheses and `as`, `satisfies` and `<T>` type
/// assertions. `None` when a recovered wrapper has no operand.
pub fn ts_unwrap_expression(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        node = match node.kind() {
            "as_expression" | "satisfies_expression" | "type_assertion" => {
                ts_type_wrapper_operand(node)?
            }
            "parenthesized_expression" => {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| !child.is_extra())?
            }
            _ => return Some(node),
        };
    }
}

#[allow(clippy::too_many_arguments)]
pub fn ts_receiver_owner_candidates_at_byte(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
    byte: usize,
) -> Vec<CodeUnit> {
    ts_receiver_owner_candidates_at_byte_with_resolution(
        host,
        support,
        file,
        source,
        root,
        imports,
        aliases,
        receiver,
        byte,
        0,
        &TsReceiverResolution::default(),
    )
}

/// `depth` is the caller's accumulated budget in the mutually recursive owner
/// cluster, not a fresh count. Restarting it here would let a cycle that passes
/// through this hop run forever: the cluster's only per-turn progress is the
/// depth increment, and the `TsReceiverResolution` visited set cannot stand in
/// for it because a self-recursive function called from distinct byte offsets
/// produces a distinct key every turn (#2744).
#[allow(clippy::too_many_arguments)]
fn ts_receiver_owner_candidates_at_byte_with_resolution(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
    byte: usize,
    depth: usize,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    if receiver == "this"
        && let Some(owner) = jsts_enclosing_class(host, file, byte)
    {
        return vec![owner];
    }
    let Some(scope) = jsts_enclosing_function_scope(root, byte) else {
        return Vec::new();
    };
    let key = TsReceiverResolutionKey {
        scope_id: scope.id(),
        receiver: receiver.to_string(),
        byte,
    };
    let Some(_guard) = resolution.enter(key) else {
        return Vec::new();
    };

    // Keep an annotated parameter's owner in the same candidate set as every
    // visible write. If a write names a different owner, the combined set is
    // ambiguous rather than silently replacing the declared evidence with a
    // latest-write answer (#2495).
    let mut candidates = ts_receiver_owners_from_parameters(
        host, support, file, source, imports, aliases, scope, receiver,
    );
    if candidates.is_empty() {
        candidates.extend(ts_receiver_owners_from_contextual_callback(
            host, support, file, source, root, imports, aliases, scope, receiver, resolution,
        ));
    }
    candidates.extend(ts_receiver_owners_from_local_bindings(
        host, support, file, source, root, imports, aliases, scope, receiver, byte, depth,
        resolution,
    ));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn jsts_enclosing_class(
    unit_index: &dyn CodeUnitIndex,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    ClassRangeIndex::build(unit_index, file)
        .enclosing_unit(byte)
        .cloned()
}

pub fn jsts_enclosing_function_scope(root: Node<'_>, byte: usize) -> Option<Node<'_>> {
    let mut current = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if matches!(
            current.kind(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ) {
            return Some(current);
        }
        current = current.parent()?;
    }
}

/// Whether a simple receiver binding has a visible assignment before one use.
///
/// TypeScript annotations are structural, so an assignment can preserve the
/// declared type while changing the nominal owner. Annotation-only owner
/// recovery must yield to the structured write fold whenever such a write is
/// present (#2495).
pub fn ts_binding_is_assigned_before(
    scope: Node<'_>,
    source: &str,
    receiver: &str,
    before_byte: usize,
) -> bool {
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node.id() != scope.id()
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "abstract_class_declaration"
                    | "interface_declaration"
            )
        {
            continue;
        }
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && node_text_matches(left, source, receiver)
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_parameters(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
) -> Vec<CodeUnit> {
    let Some(parameters) = scope
        .child_by_field_name("parameters")
        .or_else(|| scope.child_by_field_name("parameter"))
    else {
        return Vec::new();
    };
    let mut owners = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !matches!(
            parameter.kind(),
            "required_parameter" | "optional_parameter"
        ) {
            continue;
        }
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        if parameter
            .child_by_field_name("name")
            .is_some_and(|name| node_text_matches(name, source, receiver))
        {
            owners.extend(
                ts_resolve_type_node_to_property_owner_outcome(
                    host,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    type_node,
                    0,
                    ReceiverAnalysisBudget::default(),
                )
                .values()
                .into_iter()
                .flatten()
                .cloned(),
            );
            continue;
        }
        if parameter
            .child_by_field_name("pattern")
            .is_some_and(|pattern| ts_object_pattern_binds(pattern, source, receiver))
        {
            let container_owners = ts_resolve_type_node_to_property_owner_outcome(
                host,
                support,
                file,
                source,
                imports,
                aliases,
                type_node,
                0,
                ReceiverAnalysisBudget::default(),
            )
            .values()
            .map(|values| values.to_vec())
            .unwrap_or_default();
            let fields = jsts_member_candidates(host, support, container_owners, receiver, true);
            for field in fields {
                owners.extend(ts_field_signature_type_owners(host, support, &field, 0));
            }
        }
    }
    owners
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_contextual_callback(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    let Some(callback_parameter_index) = ts_callback_parameter_index(scope, source, receiver)
    else {
        return Vec::new();
    };
    let Some((call, argument_index)) = ts_callback_argument_context(scope) else {
        return Vec::new();
    };
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    let callees = ts_call_expression_callees(
        host, support, file, source, root, imports, aliases, function, 0, resolution,
    );

    let mut owners = Vec::new();
    for callee in callees {
        owners.extend(ts_callback_parameter_owners_from_callee(
            host,
            support,
            &callee,
            argument_index,
            callback_parameter_index,
            0,
        ));
    }
    owners
}

fn ts_callback_parameter_index(scope: Node<'_>, source: &str, receiver: &str) -> Option<usize> {
    let parameters = scope
        .child_by_field_name("parameters")
        .or_else(|| scope.child_by_field_name("parameter"))?;
    if parameters.kind() == "identifier" {
        return node_text_matches(parameters, source, receiver).then_some(0);
    }
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| ts_parameter_name_node(parameter))
        .position(|name| node_text_matches(name, source, receiver))
}

pub fn ts_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => Some(parameter),
        "required_parameter" | "optional_parameter" => parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name")),
        _ => None,
    }
}

fn ts_callback_argument_context(scope: Node<'_>) -> Option<(Node<'_>, usize)> {
    let mut current = scope;
    while let Some(parent) = current.parent() {
        if parent.kind() == "arguments" {
            let mut cursor = parent.walk();
            let argument_index = parent
                .named_children(&mut cursor)
                .position(|child| child.id() == current.id())?;
            let call = parent
                .parent()
                .filter(|node| node.kind() == "call_expression")?;
            return Some((call, argument_index));
        }
        current = parent;
    }
    None
}

fn ts_callback_parameter_owners_from_callee(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    callee: &CodeUnit,
    argument_index: usize,
    callback_parameter_index: usize,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Some(facts) = host.source_facts(callee.source()) else {
        return Vec::new();
    };
    let mut owners = Vec::new();
    for declaration in source_declarations_for_unit(&facts, callee) {
        let Some(Some(mut callback_type)) = declaration
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.get(argument_index))
            .copied()
        else {
            continue;
        };
        while let JsTsTypeShape::Wrapped(child) = &facts.facts.types[callback_type.index()].shape {
            callback_type = *child;
        }
        let JsTsTypeShape::Function { parameters, .. } =
            &facts.facts.types[callback_type.index()].shape
        else {
            continue;
        };
        let Some(Some(parameter_type)) = parameters.get(callback_parameter_index).copied() else {
            continue;
        };
        owners.extend(
            ts_resolve_source_type_to_property_owner_outcome(
                host,
                support,
                callee.source(),
                &facts,
                parameter_type,
                depth + 1,
                ReceiverAnalysisBudget::default(),
            )
            .values()
            .map(|values| values.to_vec())
            .unwrap_or_default(),
        );
    }
    owners
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_local_bindings(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
    before_byte: usize,
    depth: usize,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = ReceiverOwnerWrites::Unseen;
    ts_collect_receiver_owners_from_bindings(
        host,
        support,
        file,
        source,
        root,
        imports,
        aliases,
        scope,
        scope.id(),
        receiver,
        before_byte,
        depth,
        &mut owners,
        resolution,
    );
    match owners {
        ReceiverOwnerWrites::Owners(owners) => owners,
        ReceiverOwnerWrites::Unseen
        | ReceiverOwnerWrites::Unknown
        | ReceiverOwnerWrites::Conflicted => Vec::new(),
    }
}

enum ReceiverOwnerWrites {
    Unseen,
    Owners(Vec<CodeUnit>),
    Unknown,
    Conflicted,
}

impl ReceiverOwnerWrites {
    fn record(&mut self, mut owners: Vec<CodeUnit>) {
        sort_units(&mut owners);
        owners.dedup();
        if owners.is_empty() {
            if !matches!(self, ReceiverOwnerWrites::Conflicted) {
                *self = ReceiverOwnerWrites::Unknown;
            }
            return;
        }
        match self {
            ReceiverOwnerWrites::Unseen => *self = ReceiverOwnerWrites::Owners(owners),
            ReceiverOwnerWrites::Owners(previous) if *previous == owners => {}
            ReceiverOwnerWrites::Owners(_) => *self = ReceiverOwnerWrites::Conflicted,
            ReceiverOwnerWrites::Unknown | ReceiverOwnerWrites::Conflicted => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_collect_receiver_owners_from_bindings(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    receiver: &str,
    before_byte: usize,
    depth: usize,
    out: &mut ReceiverOwnerWrites,
    resolution: &TsReceiverResolution,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "abstract_class_declaration"
                    | "interface_declaration"
            )
        {
            continue;
        }

        if node.kind() == "variable_declarator"
            && let Some(name) = node.child_by_field_name("name")
            && node_text_matches(name, source, receiver)
        {
            if let Some(value) = node.child_by_field_name("value") {
                let initialized = ts_expression_property_owners(
                    host,
                    support,
                    file,
                    source,
                    root,
                    imports,
                    aliases,
                    value,
                    depth + 1,
                    resolution,
                );
                // An annotation is a structural contract, not a second
                // nominal runtime owner. When an initializer exists, its
                // structured value evidence is authoritative; an unresolved
                // initializer remains Unknown instead of borrowing the
                // annotation's owner (#2495).
                out.record(initialized);
            } else if let Some(type_node) = node.child_by_field_name("type") {
                let annotated = match ts_resolve_type_node_to_property_owner_outcome(
                    host,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    type_node,
                    depth + 1,
                    ReceiverAnalysisBudget::default(),
                ) {
                    ReceiverAnalysisOutcome::Precise(values)
                    | ReceiverAnalysisOutcome::Ambiguous(values) => values,
                    ReceiverAnalysisOutcome::Unknown
                    | ReceiverAnalysisOutcome::Unsupported { .. }
                    | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                };
                out.record(annotated);
            }
        }

        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && matches!(left.kind(), "identifier" | "type_identifier")
            && node_text_matches(left, source, receiver)
        {
            let latest = node
                .child_by_field_name("right")
                .map(|value| {
                    ts_expression_property_owners(
                        host,
                        support,
                        file,
                        source,
                        root,
                        imports,
                        aliases,
                        value,
                        depth + 1,
                        resolution,
                    )
                })
                .unwrap_or_default();
            out.record(latest);
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_expression_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    expression: Node<'_>,
    depth: usize,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    match expression.kind() {
        "call_expression" => expression
            .child_by_field_name("function")
            .map(|function| {
                let callees = ts_call_expression_callees(
                    host,
                    support,
                    file,
                    source,
                    root,
                    imports,
                    aliases,
                    function,
                    depth + 1,
                    resolution,
                );
                ts_expand_call_return_property_owners_with_resolution(
                    host,
                    support,
                    callees,
                    depth + 1,
                    resolution,
                )
            })
            .unwrap_or_default(),
        "await_expression" => {
            let mut cursor = expression.walk();
            expression
                .named_children(&mut cursor)
                .next()
                .map(|child| {
                    ts_expression_property_owners(
                        host,
                        support,
                        file,
                        source,
                        root,
                        imports,
                        aliases,
                        child,
                        depth + 1,
                        resolution,
                    )
                })
                .unwrap_or_default()
        }
        "new_expression" => expression
            .child_by_field_name("constructor")
            .map(|constructor| {
                jsts_constructor_owner_candidates(
                    host,
                    support,
                    file,
                    Language::TypeScript,
                    source,
                    imports,
                    aliases,
                    constructor,
                    false,
                )
            })
            .unwrap_or_default(),
        "as_expression" | "satisfies_expression" | "type_assertion" => {
            ts_type_wrapper_type(expression)
                .map(|type_node| {
                    ts_resolve_type_node_to_property_owner_outcome(
                        host,
                        support,
                        file,
                        source,
                        imports,
                        aliases,
                        type_node,
                        depth + 1,
                        ReceiverAnalysisBudget::default(),
                    )
                    .values()
                    .map(|values| values.to_vec())
                    .unwrap_or_default()
                })
                .unwrap_or_else(|| {
                    ts_type_wrapper_operand(expression)
                        .map(|child| {
                            ts_expression_property_owners(
                                host,
                                support,
                                file,
                                source,
                                root,
                                imports,
                                aliases,
                                child,
                                depth + 1,
                                resolution,
                            )
                        })
                        .unwrap_or_default()
                })
        }
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn jsts_constructor_owner_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    constructor: Node<'_>,
    value_position: bool,
) -> Vec<CodeUnit> {
    let Some(name) = jsts_constructor_name(constructor, source) else {
        return Vec::new();
    };
    let mut candidates = resolve_js_ts_direct_import_candidates(
        host,
        support,
        language,
        file,
        imports,
        name,
        Some(aliases),
        value_position,
    )
    .unwrap_or_else(|| {
        if imports.binding(name).is_some() {
            Vec::new()
        } else {
            support.file_identifier(file, name)
        }
    });
    candidates.retain(|unit| unit.is_class());
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn jsts_constructor_name<'a>(constructor: Node<'_>, source: &'a str) -> Option<&'a str> {
    match constructor.kind() {
        "identifier" | "type_identifier" => source
            .get(constructor.start_byte()..constructor.end_byte())
            .map(str::trim)
            .filter(|name| !name.is_empty()),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn ts_call_expression_callees(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    function: Node<'_>,
    depth: usize,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    if function.kind() == "member_expression" {
        let Some(object) = function.child_by_field_name("object") else {
            return Vec::new();
        };
        let Some(property) = function
            .child_by_field_name("property")
            .and_then(|property| ts_call_reference_name(property, source))
        else {
            return Vec::new();
        };
        if let Some(namespace) = source
            .get(object.start_byte()..object.end_byte())
            .map(str::trim)
            .filter(|namespace| !namespace.is_empty())
            && let Some(binding) = imports.binding(namespace)
            && matches!(
                binding.kind,
                ImportKind::Namespace | ImportKind::CommonJsRequire
            )
        {
            return resolve_js_ts_module_binding_candidates(
                host,
                support,
                Language::TypeScript,
                file,
                &binding.module_specifier,
                &property,
                Some(aliases),
                true,
            );
        }
        let receiver_owners = ts_expression_receiver_owners(
            host,
            support,
            file,
            source,
            root,
            imports,
            aliases,
            object,
            depth + 1,
            resolution,
        );
        let callees = jsts_member_candidates(host, support, receiver_owners, &property, true);
        if !callees.is_empty() {
            return callees;
        }
        return Vec::new();
    }

    ts_call_reference_name(function, source)
        .map(|name| {
            ts_identifier_candidates(host, support, file, source, imports, aliases, &name, true)
        })
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn ts_expression_receiver_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    expression: Node<'_>,
    depth: usize,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    match expression.kind() {
        "identifier" | "property_identifier" | "this" => {
            let Some(receiver) = source
                .get(expression.start_byte()..expression.end_byte())
                .map(str::trim)
            else {
                return Vec::new();
            };
            ts_receiver_owner_candidates_at_byte_with_resolution(
                host,
                support,
                file,
                source,
                root,
                imports,
                aliases,
                receiver,
                expression.start_byte(),
                depth,
                resolution,
            )
        }
        _ => ts_expression_property_owners(
            host,
            support,
            file,
            source,
            root,
            imports,
            aliases,
            expression,
            depth + 1,
            resolution,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_identifier_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    jsts_identifier_candidates(
        host,
        support,
        Language::TypeScript,
        file,
        source,
        imports,
        aliases,
        name,
        value_position,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn jsts_identifier_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    language: Language,
    file: &ProjectFile,
    _source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = resolve_js_ts_direct_import_candidates(
        host,
        support,
        language,
        file,
        imports,
        name,
        Some(aliases),
        value_position,
    )
    .unwrap_or_else(|| {
        if imports.binding(name).is_some() {
            Vec::new()
        } else {
            support.file_identifier(file, name)
        }
    });
    if value_position {
        candidates = jsts_value_space_candidates(host, candidates);
    } else {
        candidates = jsts_type_space_candidates(host, candidates);
    }
    candidates
}

#[allow(clippy::too_many_arguments)]
pub fn ts_resolve_type_text_to_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    _source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    type_text: &str,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let type_text = ts_clean_type_text(type_text);
    if type_text.is_empty() {
        return Vec::new();
    }

    // Parse textual type fragments back into the TypeScript AST before
    // resolving them. The callers that only have text (for example type-alias
    // metadata) still get the same entry point, while unions and intersections
    // are handled by their actual syntax nodes instead of a leading-token
    // approximation.
    let synthetic_source = format!("type __BifrostType = {type_text};");
    let Some(tree) = parse_js_ts_tree(file, &synthetic_source, Language::TypeScript) else {
        return Vec::new();
    };
    let Some(type_node) = tree
        .root_node()
        .named_child(0)
        .and_then(|declaration| declaration.child_by_field_name("value"))
    else {
        return Vec::new();
    };
    ts_resolve_type_node_to_property_owner_outcome(
        host,
        support,
        file,
        &synthetic_source,
        imports,
        aliases,
        type_node,
        depth,
        ReceiverAnalysisBudget::default(),
    )
    .values()
    .map(|values| values.to_vec())
    .unwrap_or_default()
}

/// Resolve a TypeScript type node into the declarations that can own the
/// receiver's members. Every union/intersection arm is visited structurally.
/// An arm with no indexed owner contributes `Unknown`, so one resolved arm
/// plus one open arm remains ambiguous instead of becoming falsely precise.
/// Known non-object arms (`null`, `undefined`, and `never`) contribute no
/// receiver evidence and therefore do not make a nullable receiver open.
#[allow(clippy::too_many_arguments)]
pub fn ts_resolve_type_node_to_property_owner_outcome(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    type_node: Node<'_>,
    depth: usize,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    if depth > 8 {
        return ReceiverAnalysisOutcome::ExceededBudget {
            limit: "type_resolution_depth",
        };
    }

    let mut stack = vec![(type_node, depth)];
    let mut outcomes = Vec::new();
    while let Some((node, node_depth)) = stack.pop() {
        if node_depth > 8 {
            outcomes.push(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "type_resolution_depth",
            });
            continue;
        }

        match node.kind() {
            "type_annotation" | "parenthesized_type" | "readonly_type" => {
                let Some(child) = node.named_child(0) else {
                    outcomes.push(ReceiverAnalysisOutcome::Unknown);
                    continue;
                };
                stack.push((child, node_depth + 1));
            }
            "union_type" | "intersection_type" => {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                if children.is_empty() {
                    outcomes.push(ReceiverAnalysisOutcome::Unknown);
                } else {
                    for child in children.into_iter().rev() {
                        stack.push((child, node_depth + 1));
                    }
                }
            }
            "generic_type" => {
                let Some(name) = node.child_by_field_name("name") else {
                    outcomes.push(ReceiverAnalysisOutcome::Unknown);
                    continue;
                };
                let terminal =
                    type_identifier_terminal(name).map(|terminal| slice(terminal, source).trim());
                let is_inner_type_wrapper = terminal.is_some_and(|terminal| {
                    (name.kind() == "type_identifier"
                        && matches!(terminal, "Promise" | "ReturnType"))
                        || (name.kind() == "nested_type_identifier"
                            && matches!(terminal, "infer" | "Infer"))
                });
                if is_inner_type_wrapper {
                    let Some(argument) = node
                        .child_by_field_name("type_arguments")
                        .and_then(|arguments| arguments.named_child(0))
                    else {
                        outcomes.push(ReceiverAnalysisOutcome::Unknown);
                        continue;
                    };
                    stack.push((argument, node_depth + 1));
                } else {
                    outcomes.push(ts_resolve_named_type_node(
                        host, support, file, source, imports, aliases, name, node_depth, budget,
                    ));
                }
            }
            "type_query" => {
                let Some(target) = node.named_child(0) else {
                    outcomes.push(ReceiverAnalysisOutcome::Unknown);
                    continue;
                };
                let candidates = ts_named_type_candidates(
                    host, support, file, source, imports, aliases, target, true,
                );
                outcomes.push(ReceiverAnalysisOutcome::single_precise_or_ambiguous(
                    ts_expand_property_owners(host, support, candidates, node_depth + 1),
                    budget,
                ));
            }
            "type_identifier" | "nested_type_identifier" => {
                outcomes.push(ts_resolve_named_type_node(
                    host, support, file, source, imports, aliases, node, node_depth, budget,
                ));
            }
            "predefined_type" | "literal_type" if known_non_receiver_type(node, source) => {}
            _ => outcomes.push(ReceiverAnalysisOutcome::Unknown),
        }
    }

    ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
}

#[allow(clippy::too_many_arguments)]
fn ts_resolve_named_type_node(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    depth: usize,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let candidates =
        ts_named_type_candidates(host, support, file, source, imports, aliases, node, false);
    let owners = ts_expand_property_owners(host, support, candidates, depth + 1);
    ReceiverAnalysisOutcome::single_precise_or_ambiguous(owners, budget)
}

#[allow(clippy::too_many_arguments)]
pub fn ts_named_type_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut segments = Vec::new();
    let mut current = node;
    while let Some((module, name)) = nested_type_identifier_parts(current) {
        segments.push(name);
        current = module;
    }
    segments.push(current);
    segments.reverse();

    let segments = segments
        .into_iter()
        .map(|node| slice(node, source).trim().to_string())
        .collect::<Vec<_>>();
    ts_named_type_path_candidates(
        host,
        support,
        file,
        imports,
        aliases,
        &segments,
        value_position,
    )
}

#[allow(clippy::too_many_arguments)]
fn ts_named_type_path_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    segments: &[String],
    value_position: bool,
) -> Vec<CodeUnit> {
    let Some(root_name) = segments.first() else {
        return Vec::new();
    };
    let mut remaining = segments.iter().skip(1);
    let has_qualified_tail = remaining.len() != 0;
    let mut candidates = if let Some(binding) = imports.binding(root_name).filter(|binding| {
        matches!(
            binding.kind,
            ImportKind::Namespace | ImportKind::CommonJsRequire
        )
    }) {
        let Some(segment) = remaining.next() else {
            return Vec::new();
        };
        let member = segment.as_str();
        resolve_js_ts_module_binding_candidates(
            host,
            support,
            Language::TypeScript,
            file,
            &binding.module_specifier,
            member,
            Some(aliases),
            value_position,
        )
    } else if has_qualified_tail {
        // A namespace/module qualifier is neither purely a type nor purely a
        // value. Preserve its raw declaration candidates until the terminal
        // segment is selected, then let `jsts_member_candidates` apply the
        // requested namespace filtering to the declared type itself.
        support.file_identifier(file, root_name)
    } else {
        ts_identifier_candidates(
            host,
            support,
            file,
            "",
            imports,
            aliases,
            root_name,
            value_position,
        )
    };
    for segment in remaining {
        let member = segment.as_str();
        if member.is_empty() {
            return Vec::new();
        }
        candidates = jsts_member_candidates(host, support, candidates, member, value_position);
    }
    candidates
}

fn source_declarations_for_unit<'a>(
    facts: &'a JsTsFileSourceFacts,
    unit: &'a CodeUnit,
) -> impl Iterator<Item = &'a JsTsDeclarationFact> {
    facts.facts.declarations.iter().filter(|fact| {
        facts
            .declaration_units
            .get(&fact.declaration)
            .is_some_and(|units| units.contains(unit))
    })
}

/// Resolve already captured declaration type syntax without reparsing a
/// foreign file or synthesizing a type-alias source fragment.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ts_resolve_source_type_to_property_owner_outcome(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    facts: &JsTsFileSourceFacts,
    type_id: JsTsSourceTypeId,
    depth: usize,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let imports = JsTsImportBinder::from_source_facts(&facts.facts, &facts.imports, &facts.source);
    let aliases = host.alias_resolver().as_ref();
    let mut pending = vec![(type_id, depth, false)];
    let mut outcomes = Vec::new();
    while let Some((id, depth, value_position)) = pending.pop() {
        if depth > 8 {
            outcomes.push(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "type_resolution_depth",
            });
            continue;
        }
        match &facts.facts.types[id.index()].shape {
            JsTsTypeShape::Wrapped(child) => pending.push((*child, depth + 1, value_position)),
            JsTsTypeShape::Query(child) => pending.push((*child, depth + 1, true)),
            JsTsTypeShape::Union(children) | JsTsTypeShape::Intersection(children) => {
                if children.is_empty() {
                    outcomes.push(ReceiverAnalysisOutcome::Unknown);
                }
                pending.extend(
                    children
                        .iter()
                        .rev()
                        .map(|id| (*id, depth + 1, value_position)),
                );
            }
            JsTsTypeShape::Generic { base, arguments } => {
                let unwrap = match &facts.facts.types[base.index()].shape {
                    JsTsTypeShape::Named(path) => path.last().is_some_and(|terminal| {
                        (path.len() == 1 && matches!(terminal.as_str(), "Promise" | "ReturnType"))
                            || (path.len() > 1 && matches!(terminal.as_str(), "infer" | "Infer"))
                    }),
                    _ => false,
                };
                if unwrap {
                    if let Some(argument) = arguments.first() {
                        pending.push((*argument, depth + 1, value_position));
                    } else {
                        outcomes.push(ReceiverAnalysisOutcome::Unknown);
                    }
                } else {
                    pending.push((*base, depth, value_position));
                }
            }
            JsTsTypeShape::Named(path) => {
                let candidates = ts_named_type_path_candidates(
                    host,
                    support,
                    file,
                    &imports,
                    aliases,
                    path,
                    value_position,
                );
                let owners = ts_expand_property_owners(host, support, candidates, depth + 1);
                outcomes.push(ReceiverAnalysisOutcome::single_precise_or_ambiguous(
                    owners, budget,
                ));
            }
            JsTsTypeShape::NoReceiver => {}
            _ => outcomes.push(ReceiverAnalysisOutcome::Unknown),
        }
    }
    ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
}

fn known_non_receiver_type(node: Node<'_>, source: &str) -> bool {
    matches!(slice(node, source).trim(), "null" | "undefined" | "never")
}

fn type_identifier_terminal(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "type_identifier" => return Some(node),
            "nested_type_identifier" => node = nested_type_identifier_parts(node)?.1,
            _ => return None,
        }
    }
}

fn ts_expand_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    candidates: Vec<CodeUnit>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = Vec::new();
    for candidate in candidates {
        if jsts_unit_is_type_only(host, &candidate) {
            // The aliased type comes from the declaration's AST `value` field;
            // the signature string cannot be split at `=` without hitting a
            // type-parameter default (#2227).
            let Some(facts) = host.source_facts(candidate.source()) else {
                continue;
            };
            let expanded = source_declarations_for_unit(&facts, &candidate)
                .filter_map(|declaration| declaration.alias_type)
                .flat_map(|type_id| {
                    ts_resolve_source_type_to_property_owner_outcome(
                        host,
                        support,
                        candidate.source(),
                        &facts,
                        type_id,
                        depth + 1,
                        ReceiverAnalysisBudget::default(),
                    )
                    .values()
                    .map(|values| values.to_vec())
                    .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            if expanded.is_empty() {
                owners.push(candidate);
            } else {
                owners.extend(expanded);
            }
        } else if candidate.is_function() {
            owners.push(candidate.clone());
            owners.extend(ts_function_return_property_owners(
                host,
                support,
                &candidate,
                depth + 1,
            ));
        } else {
            owners.push(candidate);
        }
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

/// Entry point for a caller outside the recursive cluster, which starts a fresh
/// receiver resolution. A caller already inside the cluster must use
/// [`ts_expand_call_return_property_owners_with_resolution`] and pass its live
/// resolution instead (#2744).
pub fn ts_expand_call_return_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    callees: Vec<CodeUnit>,
    depth: usize,
) -> Vec<CodeUnit> {
    ts_expand_call_return_property_owners_with_resolution(
        host,
        support,
        callees,
        depth,
        &TsReceiverResolution::default(),
    )
}

fn ts_expand_call_return_property_owners_with_resolution(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    callees: Vec<CodeUnit>,
    depth: usize,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = Vec::new();
    for callee in callees.into_iter().filter(|callee| callee.is_function()) {
        if jsts_function_returns_direct_object_literal(host, &callee) {
            owners.push(callee.clone());
        }
        owners.extend(ts_function_return_property_owners_with_resolution(
            host,
            support,
            &callee,
            depth + 1,
            resolution,
        ));
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

fn jsts_function_returns_direct_object_literal(
    unit_index: &dyn CodeUnitIndex,
    function: &CodeUnit,
) -> bool {
    let Ok(source) = function.source().read_to_string() else {
        return false;
    };
    let language = brokk_bifrost_core::analyzer::common::language_for_file(function.source());
    let Some(tree) = parse_js_ts_tree(function.source(), &source, language) else {
        return false;
    };
    for indexed_node in ts_nodes_for_code_unit(unit_index, function, tree.root_node()) {
        let function_node = jsts_indexed_callable_node(indexed_node).unwrap_or(indexed_node);
        if function_node.kind() == "arrow_function"
            && function_node
                .child_by_field_name("body")
                .and_then(ts_direct_object_literal_value)
                .is_some()
        {
            return true;
        }
        let mut stack = vec![function_node];
        while let Some(node) = stack.pop() {
            if node.id() != function_node.id()
                && matches!(
                    node.kind(),
                    "function_declaration"
                        | "function_expression"
                        | "arrow_function"
                        | "method_definition"
                        | "class_declaration"
                        | "abstract_class_declaration"
                        | "interface_declaration"
                )
            {
                continue;
            }
            if node.kind() == "return_statement" {
                let mut cursor = node.walk();
                if node
                    .named_children(&mut cursor)
                    .next()
                    .and_then(ts_direct_object_literal_value)
                    .is_some()
                {
                    return true;
                }
                continue;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }
    false
}

/// The callable an indexed declaration node wraps.
///
/// A `function` declaration IS the callable; `const f = () => ...` indexes the
/// `lexical_declaration` that binds it, so every question about the callable --
/// its return type, its returns -- has to step through the declarator first.
pub(crate) fn jsts_indexed_callable_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(
            node.kind(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ) {
            return Some(node);
        }
        node = match node.kind() {
            "export_statement" => node.child_by_field_name("declaration")?,
            "lexical_declaration" | "variable_declaration" => {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "variable_declarator")?
            }
            "variable_declarator" => node.child_by_field_name("value")?,
            _ => return None,
        };
    }
}

/// Entry point for a caller outside the recursive cluster, which starts a fresh
/// receiver resolution. A caller already inside the cluster must use
/// [`ts_function_return_property_owners_with_resolution`] and pass its live
/// resolution instead (#2744).
pub fn ts_function_return_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    function: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    ts_function_return_property_owners_with_resolution(
        host,
        support,
        function,
        depth,
        &TsReceiverResolution::default(),
    )
}

fn ts_function_return_property_owners_with_resolution(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    function: &CodeUnit,
    depth: usize,
    resolution: &TsReceiverResolution,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Some(facts) = host.source_facts(function.source()) else {
        return Vec::new();
    };
    let mut owners = source_declarations_for_unit(&facts, function)
        .filter_map(|declaration| declaration.return_type)
        .flat_map(|type_id| {
            ts_resolve_source_type_to_property_owner_outcome(
                host,
                support,
                function.source(),
                &facts,
                type_id,
                depth + 1,
                ReceiverAnalysisBudget::default(),
            )
            .values()
            .map(|values| values.to_vec())
            .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    sort_units(&mut owners);
    owners.dedup();
    let Ok(source) = function.source().read_to_string() else {
        return owners;
    };
    let Some(tree) = parse_js_ts_tree(function.source(), &source, Language::TypeScript) else {
        return owners;
    };
    let imports = JsTsImportBinder::from_source_facts(&facts.facts, &facts.imports, &facts.source);
    // The analyzer's shared resolver, so this route reuses its warm config and
    // workspace-package memos instead of building cold ones per call.
    let aliases = host.alias_resolver().as_ref();
    for node in ts_nodes_for_code_unit(host, function, tree.root_node()) {
        ts_collect_return_property_owners(
            host,
            support,
            function.source(),
            &source,
            tree.root_node(),
            &imports,
            aliases,
            node,
            node.id(),
            depth + 1,
            resolution,
            &mut owners,
        );
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

pub fn ts_nodes_for_code_unit<'tree>(
    unit_index: &dyn CodeUnitIndex,
    unit: &CodeUnit,
    root: Node<'tree>,
) -> Vec<Node<'tree>> {
    let ranges = unit_index.ranges(unit);
    let mut nodes = Vec::new();
    for range in ranges {
        if let Some(node) = smallest_named_node_covering(root, range.start_byte, range.end_byte) {
            nodes.push(
                node.child_by_field_name("declaration")
                    .filter(|_| node.kind() == "export_statement")
                    .unwrap_or(node),
            );
        }
    }
    nodes
}

#[allow(clippy::too_many_arguments)]
fn ts_collect_return_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    depth: usize,
    // The caller's live resolution. Constructing a fresh one here would clear
    // both the visited-key set and the `MAX_TS_RECEIVER_RESOLUTION_DEPTH`
    // counter once per cycle turn, so neither guard could ever accumulate
    // (#2744).
    resolution: &TsReceiverResolution,
    out: &mut Vec<CodeUnit>,
) {
    if depth > 8 {
        return;
    }
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "abstract_class_declaration"
                    | "interface_declaration"
            )
        {
            continue;
        }
        if node.kind() == "return_statement" {
            let mut cursor = node.walk();
            if let Some(expression) = node.named_children(&mut cursor).next() {
                out.extend(ts_expression_property_owners(
                    host,
                    support,
                    file,
                    source,
                    root,
                    imports,
                    aliases,
                    expression,
                    depth + 1,
                    resolution,
                ));
            }
            continue;
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

fn ts_field_signature_type_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    field: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    let Some(facts) = host.source_facts(field.source()) else {
        return Vec::new();
    };
    source_declarations_for_unit(&facts, field)
        .filter_map(|declaration| declaration.member_type)
        .flat_map(|type_id| {
            ts_resolve_source_type_to_property_owner_outcome(
                host,
                support,
                field.source(),
                &facts,
                type_id,
                depth + 1,
                ReceiverAnalysisBudget::default(),
            )
            .values()
            .map(|values| values.to_vec())
            .unwrap_or_default()
        })
        .collect()
}

fn ts_object_pattern_binds(pattern: Node<'_>, source: &str, receiver: &str) -> bool {
    if pattern.kind() != "object_pattern" {
        return false;
    }
    let mut cursor = pattern.walk();
    pattern
        .named_children(&mut cursor)
        .any(|child| match child.kind() {
            "shorthand_property_identifier_pattern" => node_text_matches(child, source, receiver),
            "pair_pattern" => child
                .child_by_field_name("value")
                .is_some_and(|value| ts_pattern_binds_name(value, source, receiver)),
            _ => false,
        })
}

fn ts_pattern_binds_name(pattern: Node<'_>, source: &str, receiver: &str) -> bool {
    let mut current = Some(pattern);
    while let Some(pattern) = current {
        match pattern.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                return node_text_matches(pattern, source, receiver);
            }
            "assignment_pattern" => current = pattern.child_by_field_name("left"),
            _ => return false,
        }
    }
    false
}

pub fn node_text_matches(node: Node<'_>, source: &str, expected: &str) -> bool {
    source
        .get(node.start_byte()..node.end_byte())
        .is_some_and(|text| text.trim() == expected)
}

fn ts_call_reference_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" => source
            .get(node.start_byte()..node.end_byte())
            .map(|text| text.trim().to_string()),
        "member_expression" => node
            .child_by_field_name("property")
            .and_then(|property| ts_call_reference_name(property, source)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::capabilities::{
        ImportAnalysisProvider, TypeHierarchyProvider,
    };
    use brokk_bifrost_core::analyzer::model::{CodeUnitType, ImportInfo, Range};
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use brokk_bifrost_core::analyzer::query_token::QueryToken;
    use brokk_bifrost_core::hash::HashMap;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    /// A self-recursive function whose declared return type is a union of a
    /// generic-wrapped type and a plain one, and which calls itself from four
    /// distinct byte offsets. Two of those calls initialize a local binding
    /// whose member call (`.then`) sends the resolver back through
    /// `ts_receiver_owner_candidates_at_byte_with_resolution` for the same
    /// receiver, closing the owner cluster's mutual-recursion cycle (#2744).
    const RECURSIVE_UNION_SOURCE: &str = r#"
interface Wrapped<T> {
  then(handler: (value: T) => T): Wrapped<T>
}

function unroll(items: string[], acc: string, start: number): Wrapped<string> | string {
  if (start < 0) {
    return acc
  }

  const first = unroll(items, acc, 0)
  if (start === 0) {
    return first.then(next => unroll(items, next, 1))
  }

  const second = unroll(items, acc, start)
  return second.then(next => unroll(items, '', start))
}

export function caller(items: string[]): Wrapped<string> | string {
  const rolled = unroll(items, '', 0)
  return rolled.then(next => next)
}
"#;

    struct FakeJsTsSource {
        project: Arc<TestProject>,
        aliases: Arc<AliasResolver>,
        file: ProjectFile,
        source: String,
        declarations: Vec<(CodeUnit, Range)>,
        source_facts: Arc<JsTsFileSourceFacts>,
        source_facts_available: bool,
        source_inventory_complete: bool,
    }

    impl FakeJsTsSource {
        fn new(root: &std::path::Path, source: &str) -> Self {
            let file = ProjectFile::new(root, "unroll.ts");
            std::fs::write(file.abs_path(), source).expect("write fixture");
            let project = Arc::new(TestProject::new(root, Language::TypeScript));
            let aliases = Arc::new(AliasResolver::new(project.clone() as Arc<dyn Project>));

            // Index the two top-level functions by their declaration ranges,
            // exactly what `ts_nodes_for_code_unit` reads back.
            let tree = parse_js_ts_tree(&file, source, Language::TypeScript).expect("parse");
            let mut declarations = Vec::new();
            let root_node = tree.root_node();
            let mut stack = vec![root_node];
            while let Some(node) = stack.pop() {
                if node.kind() == "function_declaration"
                    && let Some(name) = node.child_by_field_name("name")
                {
                    let identifier = &source[name.start_byte()..name.end_byte()];
                    declarations.push((
                        CodeUnit::new(
                            file.clone(),
                            CodeUnitType::Function,
                            "",
                            identifier.to_string(),
                        ),
                        Range {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            start_line: node.start_position().row,
                            end_line: node.end_position().row,
                        },
                    ));
                }
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                stack.extend(children);
            }

            let parsed = crate::typescript::parse_typescript_file(&file, source, &tree);
            declarations.extend(
                parsed
                    .ranges
                    .iter()
                    .filter(|(unit, _)| !unit.is_function())
                    .flat_map(|(unit, ranges)| ranges.iter().map(|range| (unit.clone(), *range))),
            );
            let mut declaration_units: HashMap<_, Vec<_>> = HashMap::default();
            for (declaration, unit) in parsed.source_declaration_units {
                declaration_units.entry(declaration).or_default().push(unit);
            }
            let publication = parsed.source_facts.expect("primary source publication");
            let source_facts = Arc::new(JsTsFileSourceFacts {
                source: publication.occurrences,
                imports: publication.imports,
                facts: publication.js_ts.expect("JS/TS source family"),
                declaration_units,
            });
            Self {
                project,
                aliases,
                file,
                source: source.to_string(),
                declarations,
                source_facts,
                source_facts_available: true,
                source_inventory_complete: true,
            }
        }
    }

    impl CodeUnitIndex for FakeJsTsSource {
        fn project(&self) -> &dyn Project {
            self.project.as_ref()
        }

        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::TypeScript])
        }

        fn analyzed_files(&self) -> Vec<ProjectFile> {
            if self.source_facts_available {
                vec![self.file.clone()]
            } else {
                Vec::new()
            }
        }

        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(self.declarations.iter().map(|(unit, _)| unit.clone()))
        }

        fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
            self.declarations
                .iter()
                .filter(|(unit, _)| unit == code_unit)
                .map(|(_, range)| *range)
                .collect()
        }

        // The cycle under test never reaches these; a fake that answered them
        // would only add setup the regression does not exercise.
        fn search_definitions(&self, _pattern: &str, _case_sensitive: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }

        fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
            unimplemented!()
        }

        fn enclosing_code_unit_for_lines(
            &self,
            _file: &ProjectFile,
            _start_line: usize,
            _end_line: usize,
        ) -> Option<CodeUnit> {
            unimplemented!()
        }

        fn get_skeleton(&self, _code_unit: &CodeUnit) -> Option<String> {
            unimplemented!()
        }

        fn get_skeleton_header(&self, _code_unit: &CodeUnit) -> Option<String> {
            unimplemented!()
        }

        fn get_source(&self, _code_unit: &CodeUnit, _include_comments: bool) -> Option<String> {
            unimplemented!()
        }

        fn get_sources(&self, _code_unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
            unimplemented!()
        }
    }

    impl ImportAnalysisProvider for FakeJsTsSource {
        fn imported_code_units_of(
            &self,
            _file: &ProjectFile,
        ) -> Arc<brokk_bifrost_core::hash::HashSet<CodeUnit>> {
            Arc::new(brokk_bifrost_core::hash::HashSet::default())
        }

        fn referencing_files_of(
            &self,
            _file: &ProjectFile,
        ) -> brokk_bifrost_core::hash::HashSet<ProjectFile> {
            brokk_bifrost_core::hash::HashSet::default()
        }
    }

    impl TypeHierarchyProvider for FakeJsTsSource {
        fn get_direct_ancestors(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
            Vec::new()
        }

        fn get_direct_descendants(
            &self,
            _code_unit: &CodeUnit,
        ) -> brokk_bifrost_core::hash::HashSet<CodeUnit> {
            brokk_bifrost_core::hash::HashSet::default()
        }
    }

    impl JsTsSource for FakeJsTsSource {
        fn source_file_inventory(
            &self,
        ) -> brokk_bifrost_core::analyzer::query_batch::QueryBatch<ProjectFile> {
            let files = vec![self.file.clone()];
            if self.source_inventory_complete {
                brokk_bifrost_core::analyzer::query_batch::QueryBatch::complete(files, 1)
            } else {
                brokk_bifrost_core::analyzer::query_batch::QueryBatch::incomplete(files, 1)
            }
        }

        fn source_facts(&self, file: &ProjectFile) -> Option<Arc<JsTsFileSourceFacts>> {
            (self.source_facts_available && file == &self.file).then(|| self.source_facts.clone())
        }
        fn alias_resolver(&self) -> &Arc<AliasResolver> {
            &self.aliases
        }

        fn language(&self) -> Language {
            Language::TypeScript
        }

        fn all_files(&self) -> Vec<ProjectFile> {
            vec![self.file.clone()]
        }

        fn bulk_import_infos(
            &self,
            _files: &[ProjectFile],
        ) -> HashMap<ProjectFile, Vec<ImportInfo>> {
            HashMap::default()
        }

        fn raw_supertypes_of(&self, _code_unit: &CodeUnit) -> Vec<String> {
            Vec::new()
        }

        fn import_statements(&self, _file: &ProjectFile) -> Vec<String> {
            Vec::new()
        }

        fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
            source_declarations_for_unit(&self.source_facts, code_unit)
                .any(|declaration| declaration.alias_type.is_some())
        }

        fn raw_signatures(&self, _code_unit: &CodeUnit) -> Vec<String> {
            Vec::new()
        }

        fn with_usage_definitions(
            &self,
            _token: QueryToken<'_>,
            read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
        ) {
            read(self);
        }

        fn usage_index(
            &self,
            _cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> Option<Arc<crate::graph::resolver::JsTsUsageIndex>> {
            None
        }
    }

    impl BoundedDefinitionLookup for FakeJsTsSource {
        fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
            self.declarations
                .iter()
                .filter(|(unit, _)| unit.fq_name() == fqn)
                .map(|(unit, _)| unit.clone())
                .collect()
        }

        fn fqn_in_language(&self, fqn: &str, _language: Language) -> Vec<CodeUnit> {
            self.fqn(fqn)
        }

        fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
            if file != &self.file {
                return Vec::new();
            }
            self.declarations
                .iter()
                .filter(|(unit, _)| unit.identifier() == ident)
                .map(|(unit, _)| unit.clone())
                .collect()
        }

        fn package_exists(&self, _package: &str) -> bool {
            false
        }

        fn package_exists_in_language(&self, _package: &str, _language: Language) -> bool {
            false
        }

        fn fqn_exists(&self, fqn: &str) -> bool {
            !self.fqn(fqn).is_empty()
        }

        fn fqn_prefix_exists(&self, _prefix: &str) -> bool {
            false
        }

        fn fqn_direct_children(&self, _fqn: &str) -> Vec<CodeUnit> {
            Vec::new()
        }
    }

    #[test]
    fn usage_graph_requires_every_source_publication() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut host = FakeJsTsSource::new(root.path(), "");
        for parallel in [false, true] {
            assert!(
                crate::graph::resolver::build_jsts_usage_index(
                    &host,
                    host.aliases.as_ref(),
                    Language::TypeScript,
                    parallel
                )
                .is_some()
            );
        }
        host.source_facts_available = false;
        assert!(host.analyzed_files().is_empty());
        for parallel in [false, true] {
            assert!(
                crate::graph::resolver::build_jsts_usage_index(
                    &host,
                    host.aliases.as_ref(),
                    Language::TypeScript,
                    parallel
                )
                .is_none()
            );
        }
    }

    #[test]
    fn usage_graph_rejects_incomplete_source_inventory() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut host = FakeJsTsSource::new(root.path(), "");
        host.source_inventory_complete = false;
        for parallel in [false, true] {
            assert!(
                crate::graph::resolver::build_jsts_usage_index(
                    &host,
                    host.aliases.as_ref(),
                    Language::TypeScript,
                    parallel
                )
                .is_none()
            );
        }
    }

    #[test]
    fn declaration_types_resolve_after_source_file_is_removed() {
        let root = tempfile::tempdir().expect("tempdir");
        let host = FakeJsTsSource::new(
            root.path(),
            "interface Props { title: string } type Alias<T = string> = Props; function run(cb: (props: Alias) => void): Props { throw 0; }",
        );
        let run = host
            .declarations
            .iter()
            .find(|(unit, _)| unit.identifier() == "run")
            .expect("run")
            .0
            .clone();
        let props = host
            .declarations
            .iter()
            .find(|(unit, _)| unit.identifier() == "Props")
            .expect("Props")
            .0
            .clone();
        std::fs::remove_file(host.file.abs_path()).expect("remove declaring source");
        assert_eq!(
            ts_callback_parameter_owners_from_callee(&host, &host, &run, 0, 0, 0),
            vec![props.clone()]
        );
        let declaration = source_declarations_for_unit(&host.source_facts, &run)
            .next()
            .expect("source declaration");
        let outcome = ts_resolve_source_type_to_property_owner_outcome(
            &host,
            &host,
            &host.file,
            &host.source_facts,
            declaration.return_type.expect("return type"),
            0,
            ReceiverAnalysisBudget::default(),
        );
        assert_eq!(outcome.values(), Some([props].as_slice()));
    }

    /// Before #2744, the receiver-owner cluster reset both of its bounded
    /// recursion guards once per cycle turn: the accumulated `depth` budget was
    /// replaced with a literal `0` on the local-bindings hop, and
    /// `ts_collect_return_property_owners` built a fresh `TsReceiverResolution`,
    /// clearing both the visited-key set and the
    /// `MAX_TS_RECEIVER_RESOLUTION_DEPTH` counter. This fixture drove that cycle
    /// until the process aborted on a stack overflow, which no in-process
    /// harness could contain. Completing at all is the assertion.
    #[test]
    fn self_recursive_union_return_terminates() {
        let root = tempfile::tempdir().expect("tempdir");
        let host = FakeJsTsSource::new(root.path(), RECURSIVE_UNION_SOURCE);
        let tree = parse_js_ts_tree(&host.file, &host.source, Language::TypeScript).expect("parse");
        let imports = compute_jsts_import_binder(&host.source, &tree);

        // `rolled` is bound to the self-recursive call, so resolving its owner
        // enters the cluster the same way `resolve_one` does.
        let byte = host
            .source
            .find("return rolled.then")
            .expect("caller return site")
            + "return ".len();

        let owners = ts_receiver_owner_candidates_at_byte(
            &host,
            &host,
            &host.file,
            &host.source,
            tree.root_node(),
            &imports,
            host.aliases.as_ref(),
            "rolled",
            byte,
        );

        // The budgets bound the walk; the answer itself is whatever the bounded
        // walk reaches, so only termination is pinned here.
        assert!(owners.len() < 64, "unexpected owner explosion: {owners:?}");
    }
}
