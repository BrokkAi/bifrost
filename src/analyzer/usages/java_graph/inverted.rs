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
//! Receivers that need return-type inference (method chains) or field-access
//! typing are not resolved — a recall gap, not a wrong edge. This mirrors the
//! receiver shapes the forward Java scan proves.

use super::resolver::{is_ignored_type_context, node_text};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, first_precise, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{IAnalyzer, JavaAnalyzer, ProjectFile};
use crate::hash::HashSet;
use tree_sitter::Node;

pub(super) fn build_java_edges<F>(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    files: &[ProjectFile],
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_java::LANGUAGE.into();
    build_edges(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let mut ctx = JavaScan {
                java,
                file,
                source: parsed.source.as_str(),
                class_ranges: ClassRangeIndex::build(analyzer, file),
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
        })
    })
}

struct JavaScan<'a, 'b> {
    java: &'a JavaAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

impl JavaScan<'_, '_> {
    /// Resolve a type node (stripping generics/arrays) to its fqn.
    fn resolve_type_fqn(&self, node: Node<'_>) -> Option<String> {
        let raw = node_text(node, self.source);
        let normalized = raw
            .split('<')
            .next()
            .unwrap_or(raw)
            .trim()
            .trim_end_matches("[]")
            .trim();
        if normalized.is_empty() {
            return None;
        }
        self.java
            .resolve_type_name_in_file(self.file, normalized)
            .map(|unit| unit.fq_name())
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

const SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "block",
    "lambda_expression",
    "catch_clause",
    "enhanced_for_statement",
    "for_statement",
];

fn walk(node: Node<'_>, ctx: &mut JavaScan<'_, '_>, bindings: &mut LocalInferenceEngine<String>) {
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
        seed_declarations(node, ctx, bindings);
    } else {
        seed_inline_declarations(node, ctx, bindings);
    }

    record_reference(node, ctx, bindings);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, ctx, bindings);
    }

    if enters_scope {
        bindings.exit_scope();
    }
}

fn record_reference(
    node: Node<'_>,
    ctx: &mut JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        // `new Foo()` and generics resolve via the type_identifier children, so
        // only the leaf type nodes are handled here (avoids double counting).
        "type_identifier" | "scoped_type_identifier" => {
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "scoped_type_identifier")
                || is_ignored_type_context(node)
            {
                return;
            }
            if let Some(fqn) = ctx.resolve_type_fqn(node) {
                ctx.record(fqn, node);
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
            if let Some(owner) = method_owner_fqn(node, ctx, bindings) {
                ctx.record(format!("{owner}.{name}"), name_node);
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
            }
        }
        _ => {}
    }
}

/// The fqn of the type that owns a method invocation: the receiver's type, or —
/// for an unqualified call — the enclosing class (`this`/inherited).
fn method_owner_fqn(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match node.child_by_field_name("object") {
        Some(object) => receiver_type_fqn(object, ctx, bindings),
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
    match object.kind() {
        "identifier" => {
            let name = node_text(object, ctx.source);
            // A typed local resolves to its type; an untyped (shadowed) local is
            // known to be a value, so don't reinterpret its name as a static type.
            first_precise(bindings, name).or_else(|| {
                (!bindings.is_shadowed(name))
                    .then(|| ctx.resolve_type_fqn(object))
                    .flatten()
            })
        }
        "this" | "super" => ctx
            .class_ranges
            .enclosing(object.start_byte())
            .map(str::to_string),
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            ctx.resolve_type_fqn(object)
        }
        _ => None,
    }
}

fn seed_declarations(
    node: Node<'_>,
    ctx: &JavaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" => {
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
        match resolved_type.as_ref() {
            Some(fqn) => bindings.seed_symbol(binding_name.to_string(), fqn.clone()),
            None => bindings.declare_shadow(binding_name.to_string()),
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
