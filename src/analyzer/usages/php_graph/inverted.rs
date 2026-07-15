//! Whole-workspace inverted edge builder for PHP.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. PHP node fqns are dotted and
//! namespace-qualified: a class is `App.Service`, a method/property/class-const is
//! `{class}.{member}` (`App.Service.run`), a free function is `{namespace}.{name}`
//! (`App.helper`), and a namespace-level constant carries a `_module_` segment
//! (`App._module_.LIMIT`). These match the forward scanner's resolve primitives
//! ([`resolve_php_type`], [`resolve_php_function`], [`resolve_php_constant`]), so
//! we reuse them directly.
//!
//! Reference resolution mirrors C#/Java: a type reference resolves through the
//! file's namespace + `use` aliases, and a [`LocalInferenceEngine`] seeded with
//! every typed parameter and `$x = new Foo()` local lets a method call's receiver
//! be typed:
//!
//! - a type reference (a `named_type` in param/return position, or a `new X`
//!   construction) resolves to the class fqn;
//! - a free `foo(..)` call resolves to the function fqn;
//! - a bare constant name resolves to the namespace constant fqn;
//! - `$obj->method(..)` resolves `$obj`'s type to `Owner`, giving `Owner.method`;
//! - `X::method(..)` (static) resolves the scope type directly, and
//!   `self`/`static`/`parent`/`$this` attribute to the enclosing class.
//!
//! The enclosing class is taken from a per-file class-range index (the analyzer's
//! own fqns), so `$this`/`self`/unqualified references attribute to the right
//! class without re-deriving the namespace. Type references in `extends`/
//! `implements`/cast position (bare `name`/`qualified_name`, not `named_type`),
//! and receivers that need return-type inference (method chains) or whose type we
//! cannot determine, are a recall gap — not a wrong edge.

use super::resolver::node_text;
use super::syntax::{
    assignment_parts, declared_callable_return_type_fq_name, declared_field_type_fq_name,
    is_local_scope, object_creation_type, seed_parameter_types, static_member_parts,
    variable_identifier,
};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdgeBuildOutput, build_edge_output, first_precise,
    parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{
    IAnalyzer, PhpAnalyzer, PhpFileContext, ProjectFile, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
use crate::hash::HashSet;
use tree_sitter::Node;

/// Build the whole PHP `caller -> callee` edge set in a single inverted pass over
/// the resolver-owned file set. `nodes`/`keep_file` mirror the Go builder.
pub(super) fn build_php_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    php: &PhpAnalyzer,
    files: &[ProjectFile],
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_php::LANGUAGE_PHP.into();
    build_edge_output(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let ctx = php.file_context_from_source(file, parsed.source.as_str());
            let mut scan = PhpScan {
                analyzer,
                php,
                ctx,
                source: parsed.source.as_str(),
                class_ranges: ClassRangeIndex::build(analyzer, file),
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut scan, &mut bindings);
        })
    })
}

struct PhpScan<'a, 'b> {
    analyzer: &'a dyn IAnalyzer,
    php: &'a PhpAnalyzer,
    ctx: PhpFileContext,
    source: &'a str,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

impl PhpScan<'_, '_> {
    fn resolve_type_fqn(&self, text: &str) -> Option<String> {
        resolve_php_type(text, &self.ctx)
    }

    /// The fqn of the smallest class declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

fn walk(node: Node<'_>, scan: &mut PhpScan<'_, '_>, bindings: &mut LocalInferenceEngine<String>) {
    let enters_scope = is_local_scope(node);
    if enters_scope {
        bindings.enter_scope();
        seed_parameters(node, scan, bindings);
    }
    seed_assignment(node, scan, bindings);
    record_reference(node, scan, bindings);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, scan, bindings);
    }

    if enters_scope {
        bindings.exit_scope();
    }
}

fn record_reference(
    node: Node<'_>,
    scan: &mut PhpScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        // `new X(..)`: resolve the type child to the class fqn. Recorded here (not
        // via the generic type-reference case below) so a construction counts once.
        "object_creation_expression" => {
            if let Some(type_node) = object_creation_type(node)
                && let Some(fqn) = scan.resolve_type_fqn(node_text(type_node, scan.source))
            {
                scan.record(fqn, type_node);
            }
        }
        // A type used in reference position: param/return type, `extends`/
        // `implements`, cast. `named_type` wraps the name in these contexts; the
        // `new X` type lives under `object_creation_expression` and is handled
        // above, so skip it here to avoid double counting.
        "named_type" => {
            if !is_in_object_creation(node)
                && let Some(fqn) = scan.resolve_type_fqn(node_text(node, scan.source))
            {
                scan.record(fqn, node);
            }
        }
        // Free function call: `foo(..)` where the function child is a name.
        "function_call_expression" => {
            if let Some(name_node) = node.child_by_field_name("function")
                && matches!(name_node.kind(), "name" | "qualified_name")
                && let Some(fqn) =
                    resolve_php_function(node_text(name_node, scan.source), &scan.ctx)
            {
                scan.record(fqn, name_node);
            }
        }
        // `X::method(..)` static call: resolve the scope to a class fqn.
        "scoped_call_expression" => {
            let Some((scope, name_node)) = static_member_parts(node) else {
                return;
            };
            let method = node_text(name_node, scan.source);
            if method.is_empty() {
                return;
            }
            if let Some(owner) = scope_class_fqn(scope, scan) {
                scan.record(format!("{owner}.{method}"), name_node);
            }
        }
        // `X::$property` static property access.
        "scoped_property_access_expression" => {
            let Some((scope, name_node)) = static_member_parts(node) else {
                return;
            };
            let property = variable_identifier(name_node, scan.source);
            if property.is_empty() {
                return;
            }
            if let Some(owner) = scope_class_fqn(scope, scan) {
                scan.record(format!("{owner}.{property}"), name_node);
            }
        }
        // `$obj->method(..)` instance call: type the receiver, giving `Owner.method`.
        "member_call_expression" => {
            let (Some(object), Some(name_node)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("name"),
            ) else {
                return;
            };
            let method = node_text(name_node, scan.source);
            if method.is_empty() {
                return;
            }
            if let Some(owner) = receiver_type_fqn(object, scan, bindings) {
                scan.record(format!("{owner}.{method}"), name_node);
            } else {
                scan.collector.record_unproven_name(
                    method,
                    name_node.start_byte(),
                    name_node.end_byte(),
                );
            }
        }
        // A bare constant name in reference position (`LIMIT`): not a call, not a
        // member, not a declaration. Resolves to the namespace constant fqn.
        "name" => {
            if is_bare_constant_reference(node)
                && let Some(fqn) = resolve_php_constant(node_text(node, scan.source), &scan.ctx)
            {
                scan.record(fqn, node);
            }
        }
        _ => {}
    }
}

/// The fqn of the class named by a static call's scope expression: an explicit
/// type, or `self`/`static`/`parent` → the enclosing class.
fn scope_class_fqn(scope: Node<'_>, scan: &PhpScan<'_, '_>) -> Option<String> {
    let text = node_text(scope, scan.source);
    match text {
        "self" | "static" | "parent" => {
            scan.enclosing_class(scope.start_byte()).map(str::to_string)
        }
        _ => scan.resolve_type_fqn(text),
    }
}

/// The fqn of an instance-call receiver's type. `$this` is the enclosing class; a
/// typed local/parameter resolves to its seeded type. Receivers we cannot type
/// (chained calls, untyped locals) are skipped — a recall gap, not a wrong edge.
fn receiver_type_fqn(
    object: Node<'_>,
    scan: &PhpScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match object.kind() {
        "variable_name" => {
            let name = variable_identifier(object, scan.source);
            if name == "this" {
                return scan
                    .enclosing_class(object.start_byte())
                    .map(str::to_string);
            }
            first_precise(bindings, name)
        }
        "object_creation_expression" => object_creation_type(object)
            .and_then(|type_node| scan.resolve_type_fqn(node_text(type_node, scan.source))),
        "parenthesized_expression" => object
            .named_child(0)
            .and_then(|inner| receiver_type_fqn(inner, scan, bindings)),
        "member_access_expression" => receiver_member_access_type_fqn(object, scan, bindings),
        _ => None,
    }
}

fn receiver_member_access_type_fqn(
    access: Node<'_>,
    scan: &PhpScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    let object = access.child_by_field_name("object")?;
    let name = access.child_by_field_name("name")?;
    let owner = receiver_type_fqn(object, scan, bindings)?;
    let member = node_text(name, scan.source);
    if member.is_empty() {
        return None;
    }
    let field_fqn = format!("{owner}.{member}");
    let field = scan
        .analyzer
        .definitions(&field_fqn)
        .find(|unit| unit.is_field())?;
    declared_field_type_fq_name(scan.php, scan.analyzer, &field)
}

/// Seed parameter types into the binding scope: a `simple_parameter` with a type
/// hint that resolves to a class fqn becomes a precise binding; an untyped
/// parameter is a shadow so its name is not later read as a static type.
fn seed_parameters(
    node: Node<'_>,
    scan: &PhpScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_parameter_types(node, scan.source, bindings, |raw| {
        scan.resolve_type_fqn(raw)
    });
}

/// Seed `$x = new Foo()` and `$x = factory()` locals into the binding scope when
/// the RHS has a structurally declared class result. Other assignments shadow the
/// name (so an untyped local is not later read as a static type).
fn seed_assignment(
    node: Node<'_>,
    scan: &mut PhpScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some((left, right)) = assignment_parts(node) else {
        return;
    };
    if left.kind() != "variable_name" {
        return;
    }
    let name = variable_identifier(left, scan.source);
    if name.is_empty() {
        return;
    }
    let resolved = assignment_receiver_type_fqn(right, scan);
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn assignment_receiver_type_fqn(right: Node<'_>, scan: &mut PhpScan<'_, '_>) -> Option<String> {
    match right.kind() {
        "object_creation_expression" => object_creation_type(right)
            .and_then(|type_node| scan.resolve_type_fqn(node_text(type_node, scan.source))),
        "function_call_expression" => {
            let function = right.child_by_field_name("function")?;
            if !matches!(function.kind(), "name" | "qualified_name") {
                return None;
            }
            let fqn = resolve_php_function(node_text(function, scan.source), &scan.ctx)?;
            declared_callable_return_type_fqn(scan, &fqn)
        }
        "scoped_call_expression" => {
            let scope = right.child_by_field_name("scope")?;
            let name = right.child_by_field_name("name")?;
            let method = node_text(name, scan.source);
            if method.is_empty() {
                return None;
            }
            let owner = scope_class_fqn(scope, scan)?;
            declared_callable_return_type_fqn(scan, &format!("{owner}.{method}"))
        }
        _ => None,
    }
}

fn declared_callable_return_type_fqn(scan: &PhpScan<'_, '_>, callable_fqn: &str) -> Option<String> {
    if let Some(return_type) = scan
        .analyzer
        .usage_facts_index()
        .callable_return_type(callable_fqn)
    {
        return Some(return_type.to_string());
    }
    let mut definitions = scan
        .php
        .definitions(callable_fqn)
        .filter(|unit| unit.is_function());
    let callable = definitions.next()?;
    if definitions.next().is_some() {
        return None;
    }
    declared_callable_return_type_fq_name(scan.php, scan.analyzer, &callable)
}

/// True when `node` is the type name inside a `new X(..)` expression (so the
/// generic type-reference case skips it to avoid double counting a construction).
fn is_in_object_creation(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "object_creation_expression")
}

/// True when a `name` node is a bare constant reference (not a call target, not a
/// member/scoped access name, not a declaration name).
fn is_bare_constant_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    !matches!(
        parent.kind(),
        "function_call_expression"
            | "member_access_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "class_constant_access_expression"
            | "named_type"
            | "object_creation_expression"
            | "function_definition"
            | "method_declaration"
            | "const_element"
            | "namespace_use_clause"
            | "namespace_definition"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "qualified_name"
            | "base_clause"
            | "class_interface_clause"
    )
}
