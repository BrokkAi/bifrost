//! Whole-workspace inverted edge builder for Java.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Java node fqns are dotted and
//! package-qualified (`com.example.Service`, `com.example.Service.run`). Unlike
//! the import-binder languages, Java references resolve through type-name
//! resolution ([`JavaAnalyzer::resolve_type_name_in_file`], which honors imports,
//! the file's package, and on-demand hierarchy) plus a [`LocalInferenceEngine`]
//! that records every local/parameter/field's declared type so a method
//! invocation's receiver can be typed:
//!
//! - a `type_identifier`/`scoped_type_identifier` resolves to the type's fqn;
//! - `recv.method(..)` resolves `recv`'s type to `Owner`, giving `Owner.method`;
//! - `Type.method(..)` (static) resolves the type directly;
//! - a bare `method(..)` attributes to the enclosing class (`this`/inherited).
//!
//! Receivers that need field-access typing are not resolved — a recall gap, not
//! a wrong edge. Method-invocation receivers are typed from the callee's declared
//! return type, matching the same inference used when seeding locals.

use super::resolver::{
    constructor_method_reference_receiver, is_ignored_type_context, node_text,
    resolve_field_access_type, resolve_nested_type_for_owner, resolve_type_segments,
};
use super::return_type::{
    FileReturnCache, JavaReturnTypeContext, LexicalTypeResolution, METHOD_RECEIVER_CHAIN_LIMIT,
    METHOD_RECEIVER_CHAIN_LIMIT_NAME, MethodAnonymousReturnCache, MethodReturnCache,
    java_lexical_type_from_node, java_type_name_from_node, merge_receiver_type_outcomes,
    method_return_type_for_owner_fqn,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdgeBuildOutput, build_edge_output,
    build_file_declarations, build_file_declarations_from_state, classify_reference_node,
    parse_and_collect_with_declarations,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::sync::Mutex;
use tree_sitter::Node;

pub(super) fn build_java_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    files: &[ProjectFile],
    file_states: &HashMap<ProjectFile, FileState>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_java::LANGUAGE.into();
    let return_type_cache: MethodReturnCache = Mutex::new(HashMap::default());
    let anonymous_return_cache: MethodAnonymousReturnCache = Mutex::new(HashMap::default());
    let file_return_cache: FileReturnCache = Mutex::new(HashMap::default());
    build_edge_output(files, keep_file, |file| {
        let state = file_states.get(file);
        let declarations = state
            .map(build_file_declarations_from_state)
            .unwrap_or_else(|| build_file_declarations(analyzer, file));
        let class_ranges = state
            .map(ClassRangeIndex::build_from_state)
            .unwrap_or_else(|| ClassRangeIndex::build(analyzer, file));
        parse_and_collect_with_declarations(
            file,
            nodes,
            &language,
            declarations,
            |parsed, collector| {
                let mut ctx = JavaScan {
                    java,
                    analyzer,
                    file,
                    source: parsed.source.as_str(),
                    root: parsed.tree.root_node(),
                    class_ranges,
                    return_type_cache: &return_type_cache,
                    anonymous_return_cache: &anonymous_return_cache,
                    file_return_cache: &file_return_cache,
                    collector,
                };
                let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
                walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
            },
        )
    })
}

struct JavaScan<'a, 'b> {
    java: &'a JavaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'a>,
    class_ranges: ClassRangeIndex,
    return_type_cache: &'a MethodReturnCache,
    anonymous_return_cache: &'a MethodAnonymousReturnCache,
    file_return_cache: &'a FileReturnCache,
    collector: &'a mut EdgeCollector<'b>,
}

impl JavaScan<'_, '_> {
    /// Resolve the nominal identity carried by a structured type node to its fqn.
    fn resolve_type_fqn(&self, node: Node<'_>) -> Option<String> {
        self.resolve_type(node).map(|unit| unit.fq_name())
    }

    fn resolve_type(&self, node: Node<'_>) -> Option<CodeUnit> {
        if matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
            return resolve_type_segments(
                node,
                self.source,
                |candidate| self.resolve_non_nested_type(candidate),
                |owner, name| self.resolve_nested_type(owner, name),
            )
            .into_iter()
            .last()
            .map(|(resolved, _)| resolved);
        }
        self.resolve_non_nested_type(node)
    }

    fn resolve_non_nested_type(&self, node: Node<'_>) -> Option<CodeUnit> {
        match java_lexical_type_from_node(self.java, self.analyzer, self.file, self.source, node) {
            LexicalTypeResolution::Resolved(unit) => return Some(unit),
            LexicalTypeResolution::Blocked => return None,
            LexicalTypeResolution::NotFound => {}
        }
        let type_name = java_type_name_from_node(node, self.source)?;
        self.java.resolve_usage_type_name(self.file, &type_name)
    }

    fn resolve_nested_type(&self, owner: &CodeUnit, name: &str) -> Option<CodeUnit> {
        resolve_nested_type_for_owner(self.analyzer, owner, name)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector.record_kind(
            callee,
            classify_reference_node(node),
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.collector
            .record_unproven_name(name, node.start_byte(), node.end_byte());
    }
}

impl JavaReturnTypeContext for JavaScan<'_, '_> {
    fn java(&self) -> &JavaAnalyzer {
        self.java
    }

    fn file(&self) -> &ProjectFile {
        self.file
    }

    fn source(&self) -> &str {
        self.source
    }

    fn root(&self) -> Node<'_> {
        self.root
    }

    fn method_return_cache(&self) -> &MethodReturnCache {
        self.return_type_cache
    }

    fn method_anonymous_return_cache(&self) -> &MethodAnonymousReturnCache {
        self.anonymous_return_cache
    }

    fn file_return_cache(&self) -> &FileReturnCache {
        self.file_return_cache
    }
}

const SCOPE_NODES: &[&str] = &[
    "class_body",
    "method_declaration",
    "constructor_declaration",
    "compact_constructor_declaration",
    "block",
    "lambda_expression",
    "catch_clause",
    "enhanced_for_statement",
    "for_statement",
];

fn walk(node: Node<'_>, ctx: &mut JavaScan<'_, '_>, bindings: &mut LocalInferenceEngine<String>) {
    let mut state = (ctx, bindings);
    walk_tree_iterative(
        node,
        &mut state,
        |node, (ctx, bindings)| {
            if walk_enter(node, ctx, bindings) {
                TreeWalkAction::DescendWithExit
            } else {
                TreeWalkAction::Descend
            }
        },
        |(_, bindings)| bindings.exit_scope(),
    );
}

fn walk_enter(
    node: Node<'_>,
    ctx: &mut JavaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) -> bool {
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
        seed_declarations(node, ctx, bindings);
    } else {
        seed_inline_declarations(node, ctx, bindings);
    }

    record_reference(node, ctx, bindings);
    enters_scope
}

fn record_reference(
    node: Node<'_>,
    ctx: &mut JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        "object_creation_expression" => record_constructor_reference(node, ctx),
        // `new Foo()` and generics resolve via the type_identifier children, so
        // a scoped parent handles all of its semantic type segments (avoids
        // double counting while retaining outer-owner references).
        "type_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
            if node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "scoped_type_identifier" | "scoped_identifier"
                )
            }) || is_ignored_type_context(node)
            {
                return;
            }
            for (resolved, segment) in resolve_type_segments(
                node,
                ctx.source,
                |candidate| ctx.resolve_type(candidate),
                |owner, name| ctx.resolve_nested_type(owner, name),
            ) {
                ctx.record(resolved.fq_name(), segment);
            }
        }
        "method_invocation" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, ctx.source);
            if name.is_empty() {
                return;
            }
            // Same-owner (self/this receiver, implicit-this, or own-type static)
            // calls are excluded from proven usage-graph / dead-code inbound
            // edges, uniformly with Rust/C++/JS-TS (#1014 facet B). They are
            // recorded as unproven inbound rather than dropped, matching Rust: a
            // method reachable only through same-owner calls is reported as
            // inconclusive (its receivers could not be proven external), never
            // confidently dead.
            if method_invocation_receiver_is_same_owner(node, ctx, bindings) {
                ctx.record_unproven(name, name_node);
                return;
            }
            if let Some(owner) = method_owner_fqn(node, ctx, bindings) {
                ctx.record(format!("{owner}.{name}"), name_node);
            } else {
                ctx.record_unproven(name, name_node);
            }
        }
        "method_reference" => {
            if let Some(receiver) = constructor_method_reference_receiver(node) {
                record_constructor_reference_for_type(receiver, node, ctx);
                return;
            }
            let Some((receiver, member_node)) = method_reference_parts(node) else {
                return;
            };
            let member = node_text(member_node, ctx.source);
            if member.is_empty() {
                return;
            }
            if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings)
                && let Some(callee) = method_reference_callee(&owner, member, ctx)
            {
                ctx.record(callee, member_node);
            } else {
                ctx.record_unproven(member, member_node);
            }
        }
        "field_access" => {
            let Some(field_node) = node.child_by_field_name("field") else {
                return;
            };
            let field = node_text(field_node, ctx.source);
            let Some(object) = node.child_by_field_name("object") else {
                return;
            };
            if !field.is_empty()
                && let Some(owner) = receiver_type_fqn(object, ctx, bindings)
            {
                ctx.record(format!("{owner}.{field}"), field_node);
            } else if !field.is_empty() {
                ctx.record_unproven(field, field_node);
            }
        }
        _ => {}
    }
}

fn record_constructor_reference(node: Node<'_>, ctx: &mut JavaScan<'_, '_>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    record_constructor_reference_for_type(type_node, node, ctx);
}

fn record_constructor_reference_for_type(
    type_node: Node<'_>,
    reference_node: Node<'_>,
    ctx: &mut JavaScan<'_, '_>,
) {
    let Some(owner) = ctx.resolve_type(type_node) else {
        return;
    };
    ctx.record(owner.fq_name().to_string(), type_node);
    let constructor_fqn = format!("{}.{}", owner.fq_name(), owner.identifier());
    let declared = ctx
        .java
        .global_usage_definition_index()
        .by_fqn(&constructor_fqn)
        .iter()
        .any(|candidate| candidate.is_function() && !candidate.is_synthetic());
    if declared {
        ctx.record(constructor_fqn, reference_node);
    }
}

fn method_reference_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    let (member, rest) = children.split_last()?;
    let receiver = rest.last().copied()?;
    Some((receiver, *member))
}

fn method_reference_callee(
    owner_fq_name: &str,
    member: &str,
    ctx: &JavaScan<'_, '_>,
) -> Option<String> {
    let mut candidates = ctx
        .java
        .global_usage_definition_index()
        .by_fqn(&format!("{owner_fq_name}.{member}"))
        .iter()
        .filter(|unit| unit.is_function())
        .cloned()
        .collect::<Vec<_>>();
    let owner = ctx.java.definitions(owner_fq_name).next()?;
    let provider = ctx.java.type_hierarchy_provider()?;
    for ancestor in provider.get_ancestors(&owner) {
        candidates.extend(
            ctx.java
                .global_usage_definition_index()
                .by_fqn(&format!("{}.{}", ancestor.fq_name(), member))
                .iter()
                .filter(|unit| unit.is_function())
                .cloned(),
        );
    }
    candidates.sort();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates[0].fq_name())
}

/// Whether a method invocation's receiver is a same-owner receiver: an
/// unqualified (implicit-this) call, an explicit `this` receiver, or the owner
/// type itself for an own-type static call. A `super` receiver, or a call
/// through a differently-named variable/type, stays external (#1014 facet B).
fn method_invocation_receiver_is_same_owner(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    let Some(enclosing_owner) = ctx.class_ranges.enclosing(node.start_byte()) else {
        return false;
    };
    match node.child_by_field_name("object") {
        // Unqualified call: implicit-this on the current instance.
        None => true,
        Some(object) => match object.kind() {
            "this" => true,
            "super" => false,
            "identifier" | "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                let name = node_text(object, ctx.source);
                if !name.is_empty() && bindings.is_shadowed(name) {
                    return false;
                }
                // Own-type static call: the receiver resolves to the enclosing
                // class's own type.
                ctx.resolve_type_fqn(object)
                    .is_some_and(|receiver_fqn| receiver_fqn == enclosing_owner)
            }
            _ => false,
        },
    }
}

/// The fqn of the type that owns a method invocation: the receiver's type, or —
/// for an unqualified call — the enclosing class (`this`/inherited).
fn method_owner_fqn(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    method_owner_fqn_at_depth(node, ctx, bindings, 0)
}

fn method_owner_fqn_at_depth(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
    depth: usize,
) -> Option<String> {
    match node.child_by_field_name("object") {
        Some(object) => receiver_type_fqn_at_depth(object, ctx, bindings, depth + 1),
        None => ctx
            .class_ranges
            .enclosing(node.start_byte())
            .map(str::to_string),
    }
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_fqn(
    object: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    receiver_type_fqn_at_depth(object, ctx, bindings, 0)
}

fn receiver_type_fqn_at_depth(
    object: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
    depth: usize,
) -> Option<String> {
    match object.kind() {
        "identifier" => {
            let name = node_text(object, ctx.source);
            // A typed local resolves to its type; an untyped (shadowed) local is
            // known to be a value, so don't reinterpret its name as a static type.
            single_precise_binding(bindings, name).or_else(|| {
                (!bindings.is_shadowed(name))
                    .then(|| ctx.resolve_type_fqn(object))
                    .flatten()
            })
        }
        "this" | "super" => ctx
            .class_ranges
            .enclosing(object.start_byte())
            .map(str::to_string),
        "type_identifier" | "scoped_identifier" | "scoped_type_identifier" | "generic_type" => {
            ctx.resolve_type_fqn(object)
        }
        "field_access" => resolve_field_access_type(
            object,
            ctx.source,
            |base| {
                let name = node_text(base, ctx.source);
                if bindings.is_shadowed(name) {
                    Err(())
                } else {
                    Ok(ctx.resolve_type(base))
                }
            },
            |qualified| ctx.java.resolve_usage_type_name(ctx.file, qualified),
            |owner, name| ctx.resolve_nested_type(owner, name),
        )
        .map(|owner| owner.fq_name()),
        "object_creation_expression" => object
            .child_by_field_name("type")
            .and_then(|type_node| ctx.resolve_type_fqn(type_node)),
        "method_invocation" => match receiver_type_outcome_at_depth(object, ctx, bindings, depth) {
            ReceiverAnalysisOutcome::Precise(values) if values.len() == 1 => {
                values.into_iter().next()
            }
            ReceiverAnalysisOutcome::Precise(_)
            | ReceiverAnalysisOutcome::Ambiguous(_)
            | ReceiverAnalysisOutcome::Unsupported { .. }
            | ReceiverAnalysisOutcome::ExceededBudget { .. }
            | ReceiverAnalysisOutcome::Unknown => None,
        },
        _ => None,
    }
}

fn seed_declarations(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration" => {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for child in parameters.named_children(&mut cursor) {
                    if child.kind() == "formal_parameter" {
                        seed_typed_binding(child, ctx, bindings);
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                seed_typed_binding(parameter, ctx, bindings);
            }
        }
        "enhanced_for_statement" => {
            if let Some(name) = node.child_by_field_name("name") {
                bindings.declare_shadow(node_text(name, ctx.source).to_string());
            }
        }
        _ => {}
    }
}

fn seed_inline_declarations(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration" => {
            seed_variable_declaration(node, ctx, bindings)
        }
        "formal_parameter" => seed_typed_binding(node, ctx, bindings),
        _ => {}
    }
}

fn seed_variable_declaration(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let resolved_type = node
        .child_by_field_name("type")
        .and_then(|type_node| ctx.resolve_type_fqn(type_node));
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = child.child_by_field_name("name") else {
            continue;
        };
        let binding_name = node_text(name, ctx.source);
        if binding_name.is_empty() {
            continue;
        }
        if let Some(fqn) = resolved_type.as_ref() {
            bindings.seed_symbol(binding_name.to_string(), fqn.clone());
            continue;
        }
        match child
            .child_by_field_name("value")
            .map(|value| receiver_type_outcome(value, ctx, bindings))
        {
            Some(ReceiverAnalysisOutcome::Precise(values)) if values.len() == 1 => {
                bindings.seed_symbol(binding_name.to_string(), values[0].clone());
            }
            Some(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unsupported { .. }
                | ReceiverAnalysisOutcome::ExceededBudget { .. }
                | ReceiverAnalysisOutcome::Unknown,
            )
            | None => bindings.declare_shadow(binding_name.to_string()),
        }
    }
}

fn seed_typed_binding(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source);
    if binding_name.is_empty() {
        return;
    }
    match node
        .child_by_field_name("type")
        .and_then(|type_node| ctx.resolve_type_fqn(type_node))
    {
        Some(fqn) => bindings.seed_symbol(binding_name.to_string(), fqn),
        None => bindings.declare_shadow(binding_name.to_string()),
    }
}

fn single_precise_binding(bindings: &LocalInferenceEngine<String>, name: &str) -> Option<String> {
    let targets = bindings.resolve_symbol_ref(name)?.as_precise()?;
    (targets.len() == 1).then(|| targets.iter().next().expect("len checked").clone())
}

fn receiver_type_outcome(
    expression: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> ReceiverAnalysisOutcome<String> {
    receiver_type_outcome_at_depth(expression, ctx, bindings, 0)
}

fn receiver_type_outcome_at_depth(
    expression: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
    depth: usize,
) -> ReceiverAnalysisOutcome<String> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        return ReceiverAnalysisOutcome::ExceededBudget {
            limit: METHOD_RECEIVER_CHAIN_LIMIT_NAME,
        };
    }
    match expression.kind() {
        "object_creation_expression" => expression
            .child_by_field_name("type")
            .and_then(|type_node| ctx.resolve_type_fqn(type_node))
            .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown),
        "method_invocation" => {
            method_invocation_return_type_outcome(expression, ctx, bindings, depth)
        }
        "identifier" => {
            let name = node_text(expression, ctx.source);
            single_precise_binding(bindings, name)
                .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
                .unwrap_or(ReceiverAnalysisOutcome::Unknown)
        }
        "ternary_expression" | "conditional_expression" => {
            let outcomes: Vec<_> = ["consequence", "alternative"]
                .into_iter()
                .filter_map(|field| expression.child_by_field_name(field))
                .map(|branch| receiver_type_outcome_at_depth(branch, ctx, bindings, depth))
                .collect();
            merge_receiver_type_outcomes(outcomes)
        }
        "parenthesized_expression" => expression
            .named_child(0)
            .map(|child| receiver_type_outcome_at_depth(child, ctx, bindings, depth))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown),
        _ => ReceiverAnalysisOutcome::Unknown,
    }
}

fn method_invocation_return_type_outcome(
    invocation: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
    depth: usize,
) -> ReceiverAnalysisOutcome<String> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        return ReceiverAnalysisOutcome::ExceededBudget {
            limit: METHOD_RECEIVER_CHAIN_LIMIT_NAME,
        };
    }
    let Some(name_node) = invocation.child_by_field_name("name") else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    let name = node_text(name_node, ctx.source);
    if name.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    let Some(owner) = method_owner_fqn_at_depth(invocation, ctx, bindings, depth) else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    method_return_type_for_owner_fqn(&owner, name, argument_count(invocation), ctx)
}

fn argument_count(invocation: Node<'_>) -> usize {
    invocation
        .child_by_field_name("arguments")
        .map(|arguments| arguments.named_child_count())
        .unwrap_or(0)
}
