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
use crate::syntax::compute_import_binder as compute_jsts_import_binder;
use crate::syntax::{JsTsImportBinder, parse_js_ts_tree};
use crate::tsconfig::AliasResolver;
use crate::type_text::{
    jsts_type_space_candidates, jsts_unit_is_type_only, jsts_value_space_candidates,
    ts_clean_type_text, ts_type_annotation_text,
};
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
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

pub fn ts_unwrap_expression(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "as_expression"
        | "satisfies_expression"
        | "type_assertion"
        | "parenthesized_expression" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| {
                    child.kind() != "type_annotation"
                        && child.kind() != "type_identifier"
                        && child.kind() != "predefined_type"
                })
                .and_then(ts_unwrap_expression)
        }
        _ => Some(node),
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
        &TsReceiverResolution::default(),
    )
}

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

    let mut candidates = ts_receiver_owners_from_parameters(
        host, support, file, source, imports, aliases, scope, receiver,
    );
    if candidates.is_empty() {
        candidates.extend(ts_receiver_owners_from_contextual_callback(
            host, support, file, source, imports, aliases, scope, receiver, resolution,
        ));
    }
    candidates.extend(ts_receiver_owners_from_local_bindings(
        host, support, file, source, imports, aliases, scope, receiver, byte, 0, resolution,
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
            owners.extend(ts_resolve_type_text_to_property_owners(
                host,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                0,
            ));
            continue;
        }
        if parameter
            .child_by_field_name("pattern")
            .is_some_and(|pattern| ts_object_pattern_binds(pattern, source, receiver))
        {
            let container_owners = ts_resolve_type_text_to_property_owners(
                host,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                0,
            );
            let fields = jsts_member_candidates(host, support, container_owners, receiver, true);
            for field in fields {
                owners.extend(ts_field_signature_type_owners(
                    host, support, file, source, imports, aliases, &field, 0,
                ));
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
        host, support, file, source, imports, aliases, function, 0, resolution,
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
    let Ok(source) = callee.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(callee.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(host.project().root().to_path_buf());
    let mut owners = Vec::new();
    for node in ts_nodes_for_code_unit(host, callee, tree.root_node()) {
        let Some(callback_type) = ts_function_parameter_type_text(node, &source, argument_index)
        else {
            continue;
        };
        let Some(parameter_type) =
            ts_callback_parameter_type_text(&callback_type, callback_parameter_index)
        else {
            continue;
        };
        owners.extend(ts_resolve_type_text_to_property_owners(
            host,
            support,
            callee.source(),
            &source,
            &imports,
            &aliases,
            &parameter_type,
            depth + 1,
        ));
    }
    owners
}

fn ts_function_parameter_type_text(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| {
            matches!(
                parameter.kind(),
                "required_parameter" | "optional_parameter"
            )
        })
        .nth(parameter_index)
        .and_then(|parameter| parameter.child_by_field_name("type"))
        .map(|type_node| ts_type_annotation_text(type_node, source))
}

fn ts_callback_parameter_type_text(callback_type: &str, parameter_index: usize) -> Option<String> {
    let callback_type = callback_type.trim();
    let open = callback_type.find('(')?;
    let close = ts_matching_close_delimiter(callback_type, open, '(', ')')?;
    let parameters = callback_type.get(open + 1..close)?;
    let parameter = ts_split_top_level_commas(parameters)
        .into_iter()
        .nth(parameter_index)?;
    let (_, type_text) = parameter.split_once(':')?;
    Some(ts_clean_type_text(type_text))
}

fn ts_matching_close_delimiter(
    text: &str,
    open_byte: usize,
    open_char: char,
    close_char: char,
) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_byte)
    {
        if ch == open_char {
            depth += 1;
        } else if ch == close_char {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn ts_split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in text.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if paren_depth == 0
                && angle_depth == 0
                && brace_depth == 0
                && bracket_depth == 0 =>
            {
                parts.push(text[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(text[start..].trim());
    parts
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_local_bindings(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
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
    let mut owners = Vec::new();
    ts_collect_receiver_owners_from_bindings(
        host,
        support,
        file,
        source,
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
    owners
}

#[allow(clippy::too_many_arguments)]
fn ts_collect_receiver_owners_from_bindings(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    receiver: &str,
    before_byte: usize,
    depth: usize,
    out: &mut Vec<CodeUnit>,
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
            let mut latest = Vec::new();
            if let Some(type_node) = node.child_by_field_name("type") {
                latest.extend(ts_resolve_type_text_to_property_owners(
                    host,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    ts_type_annotation_text(type_node, source).as_str(),
                    depth + 1,
                ));
            }
            if let Some(value) = node.child_by_field_name("value") {
                latest.extend(ts_expression_property_owners(
                    host,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    value,
                    depth + 1,
                    resolution,
                ));
            }
            out.clear();
            out.extend(latest);
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
                        imports,
                        aliases,
                        value,
                        depth + 1,
                        resolution,
                    )
                })
                .unwrap_or_default();
            out.clear();
            out.extend(latest);
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
                    imports,
                    aliases,
                    function,
                    depth + 1,
                    resolution,
                );
                ts_expand_call_return_property_owners(host, support, callees, depth + 1)
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
        "as_expression" | "satisfies_expression" | "type_assertion" => expression
            .child_by_field_name("type")
            .or_else(|| ts_assertion_type_child(expression))
            .map(|type_node| {
                ts_resolve_type_text_to_property_owners(
                    host,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    ts_type_annotation_text(type_node, source).as_str(),
                    depth + 1,
                )
            })
            .unwrap_or_else(|| {
                let mut cursor = expression.walk();
                expression
                    .named_children(&mut cursor)
                    .find(|child| child.kind() != "type_annotation")
                    .map(|child| {
                        ts_expression_property_owners(
                            host,
                            support,
                            file,
                            source,
                            imports,
                            aliases,
                            child,
                            depth + 1,
                            resolution,
                        )
                    })
                    .unwrap_or_default()
            }),
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
                root_node(expression),
                imports,
                aliases,
                receiver,
                expression.start_byte(),
                resolution,
            )
        }
        _ => ts_expression_property_owners(
            host,
            support,
            file,
            source,
            imports,
            aliases,
            expression,
            depth + 1,
            resolution,
        ),
    }
}

pub fn root_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
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
    source: &str,
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

    if let Some(name) = ts_typeof_target(&type_text) {
        let candidates =
            ts_identifier_candidates(host, support, file, source, imports, aliases, name, true);
        return ts_expand_property_owners(host, support, candidates, depth + 1);
    }

    if let Some(inner) = ts_generic_type_argument(&type_text, "ReturnType") {
        return ts_resolve_type_text_to_property_owners(
            host,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    if let Some(inner) = ts_generic_type_argument(&type_text, "Promise") {
        return ts_resolve_type_text_to_property_owners(
            host,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    if let Some(inner) = ts_schema_infer_argument(&type_text) {
        return ts_resolve_type_text_to_property_owners(
            host,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    let Some(name) = ts_leading_type_identifier(&type_text) else {
        return Vec::new();
    };
    let candidates =
        ts_identifier_candidates(host, support, file, source, imports, aliases, name, false);
    ts_expand_property_owners(host, support, candidates, depth + 1)
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
            let signatures = host.signatures(&candidate);
            let expanded = signatures
                .iter()
                .flat_map(|signature| {
                    ts_alias_rhs(signature)
                        .map(|rhs| {
                            ts_resolve_type_from_unit_context(
                                host,
                                support,
                                &candidate,
                                rhs,
                                depth + 1,
                            )
                        })
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

pub fn ts_expand_call_return_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    callees: Vec<CodeUnit>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = Vec::new();
    for callee in callees.into_iter().filter(|callee| callee.is_function()) {
        if jsts_function_returns_direct_object_literal(host, &callee) {
            owners.push(callee.clone());
        }
        owners.extend(ts_function_return_property_owners(
            host,
            support,
            &callee,
            depth + 1,
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

fn jsts_indexed_callable_node(mut node: Node<'_>) -> Option<Node<'_>> {
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

fn ts_resolve_type_from_unit_context(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    type_text: &str,
    depth: usize,
) -> Vec<CodeUnit> {
    let Ok(source) = unit.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(unit.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(host.project().root().to_path_buf());
    ts_resolve_type_text_to_property_owners(
        host,
        support,
        unit.source(),
        &source,
        &imports,
        &aliases,
        type_text,
        depth + 1,
    )
}

pub fn ts_function_return_property_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    function: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Ok(source) = function.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(function.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(host.project().root().to_path_buf());
    let mut owners = Vec::new();
    for node in ts_nodes_for_code_unit(host, function, tree.root_node()) {
        if let Some(type_text) = ts_function_return_type_text(node, &source) {
            owners.extend(ts_resolve_type_text_to_property_owners(
                host,
                support,
                function.source(),
                &source,
                &imports,
                &aliases,
                &type_text,
                depth + 1,
            ));
        }
        ts_collect_return_property_owners(
            host,
            support,
            function.source(),
            &source,
            &imports,
            &aliases,
            node,
            node.id(),
            depth + 1,
            &mut owners,
        );
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

fn ts_function_return_type_text(function: Node<'_>, source: &str) -> Option<String> {
    function
        .child_by_field_name("return_type")
        .map(|type_node| ts_type_annotation_text(type_node, source))
        .filter(|text| !text.is_empty())
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
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    depth: usize,
    out: &mut Vec<CodeUnit>,
) {
    if depth > 8 {
        return;
    }
    let resolution = TsReceiverResolution::default();
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
                    imports,
                    aliases,
                    expression,
                    depth + 1,
                    &resolution,
                ));
            }
            continue;
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_field_signature_type_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    field: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    let mut owners = Vec::new();
    for signature in host.signatures(field) {
        if let Some(type_text) = ts_field_type_text(&signature) {
            owners.extend(ts_resolve_type_text_to_property_owners(
                host,
                support,
                file,
                source,
                imports,
                aliases,
                type_text,
                depth + 1,
            ));
        }
    }
    owners
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

fn ts_field_type_text(signature: &str) -> Option<&str> {
    let (_, rhs) = signature.split_once(':')?;
    Some(
        rhs.split(['=', ','])
            .next()
            .unwrap_or(rhs)
            .trim()
            .trim_end_matches(';')
            .trim(),
    )
}

fn ts_alias_rhs(signature: &str) -> Option<&str> {
    let (_, rhs) = signature.split_once('=')?;
    Some(rhs.trim().trim_end_matches(';').trim())
}

fn ts_typeof_target(text: &str) -> Option<&str> {
    text.trim().strip_prefix("typeof").map(str::trim)
}

fn ts_generic_type_argument<'a>(text: &'a str, generic: &str) -> Option<&'a str> {
    let text = text.trim();
    let rest = text.strip_prefix(generic)?;
    let rest = rest.trim_start();
    let inner = rest.strip_prefix('<')?.strip_suffix('>')?;
    Some(inner.trim())
}

/// Recognizes a schema library's type-inference helper applied to a value, e.g. zod's
/// `z.infer<typeof Schema>` (and the `Infer` alias other libraries expose), so navigation can
/// follow the wrapped argument to the schema's shape. Matches the qualified `.infer`/`.Infer`
/// member-name convention regardless of the namespace alias, rather than the literal `z.infer`.
fn ts_schema_infer_argument(text: &str) -> Option<&str> {
    let text = text.trim();
    let open = text.find('<')?;
    let head = text[..open].trim();
    // `head` is a type-annotation qualifier chain (already sliced before any
    // generic argument list), so re-tokenizing it with the shared structured
    // splitter and taking the last segment reproduces `rsplit('.').next()`'s
    // terminal split exactly (TS/JS have no per-segment normalization
    // quirks, unlike Go/Rust/Cpp).
    let last =
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(Language::TypeScript, head)
            .pop()
            .unwrap_or_default();
    if !head.contains('.') || !(last == "infer" || last == "Infer") {
        return None;
    }
    let inner = text[open..].strip_prefix('<')?.strip_suffix('>')?;
    Some(inner.trim())
}

fn ts_leading_type_identifier(text: &str) -> Option<&str> {
    let text = text.trim();
    let end = text
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
        .unwrap_or(text.len());
    (end > 0).then_some(&text[..end])
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

fn ts_assertion_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "type_identifier"
                | "generic_type"
                | "type_arguments"
                | "object_type"
                | "predefined_type"
                | "union_type"
                | "intersection_type"
        )
    })
}
