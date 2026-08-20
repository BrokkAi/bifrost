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

use super::JavaGraphSource;
use super::resolver::{
    constructor_method_reference_receiver, is_ignored_type_context, is_module_type_reference,
    is_non_type_module_reference, node_text, resolve_field_access_type,
    resolve_nested_type_for_owner, resolve_type_segments,
};
use super::return_type::{
    FileReturnCache, JavaReturnTypeContext, LexicalTypeResolution, METHOD_RECEIVER_CHAIN_LIMIT,
    METHOD_RECEIVER_CHAIN_LIMIT_NAME, MethodAnonymousReturnCache, MethodReturnCache,
    java_lexical_type_from_node, java_type_name_from_node, merge_receiver_type_outcomes,
    method_return_type_for_owner_fqn,
};
use crate::java::graph_support::{JavaSource, resolve_java_usage_type_name_in};
use crate::java::hierarchy::java_nearest_declaring_ancestors;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::tree_walk::{TreeWalkAction, walk_tree_iterative};
use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    ClassRangeIndex, FileEdgeScanInput, PerFileEdges, UsageReferenceKind, classify_reference_node,
};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use brokk_bifrost_core::analyzer::usages::same_owner::route_same_owner;
use tree_sitter::Node;

/// The three per-scan return-type caches the walk shares across files.
pub struct JavaEdgeScanCaches<'a> {
    pub method_return: &'a MethodReturnCache,
    pub method_anonymous_return: &'a MethodAnonymousReturnCache,
    pub file_return: &'a FileReturnCache,
}

/// The per-file half of the whole-workspace inverted pass.
///
/// The parallel fan-out, the on-demand parse, and the per-file declaration and
/// class-range indexes stay in `brokk-bifrost-analysis`: two of the three are
/// decoded from a persisted `FileState`, whose type is crate-private there.
/// This is everything downstream of them -- the walk that turns one parsed file
/// into its outbound edges.
pub fn scan_file(
    java: &dyn JavaSource,
    token: QueryToken<'_>,
    graph: &JavaGraphSource<'_>,
    file: &ProjectFile,
    input: &FileEdgeScanInput<'_>,
    class_ranges: ClassRangeIndex,
    caches: &JavaEdgeScanCaches<'_>,
) -> PerFileEdges {
    let mut ctx = JavaScan {
        java,
        graph,
        file,
        source: input.source,
        root: input.root(),
        class_ranges,
        return_type_cache: caches.method_return,
        anonymous_return_cache: caches.method_anonymous_return,
        file_return_cache: caches.file_return,
        input,
        edges: PerFileEdges::default(),
    };
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    walk(input.root(), token, &mut ctx, &mut bindings);
    ctx.edges
}

struct JavaScan<'a> {
    java: &'a dyn JavaSource,
    graph: &'a JavaGraphSource<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'a>,
    class_ranges: ClassRangeIndex,
    return_type_cache: &'a MethodReturnCache,
    anonymous_return_cache: &'a MethodAnonymousReturnCache,
    file_return_cache: &'a FileReturnCache,
    input: &'a FileEdgeScanInput<'a>,
    edges: PerFileEdges,
}

impl JavaScan<'_> {
    /// Resolve the nominal identity carried by a structured type node to its fqn.
    fn resolve_type_fqn(&self, token: QueryToken<'_>, node: Node<'_>) -> Option<String> {
        self.resolve_type(token, node).map(|unit| unit.fq_name())
    }

    fn resolve_type(&self, token: QueryToken<'_>, node: Node<'_>) -> Option<CodeUnit> {
        if matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
            return resolve_type_segments(
                node,
                self.source,
                |candidate| self.resolve_non_nested_type(token, candidate),
                |owner, name| self.resolve_nested_type(owner, name),
            )
            .into_iter()
            .last()
            .map(|(resolved, _)| resolved);
        }
        self.resolve_non_nested_type(token, node)
    }

    fn resolve_non_nested_type(&self, token: QueryToken<'_>, node: Node<'_>) -> Option<CodeUnit> {
        match java_lexical_type_from_node(
            self.java,
            token,
            self.graph,
            self.file,
            self.source,
            node,
        ) {
            LexicalTypeResolution::Resolved(unit) => return Some(unit),
            LexicalTypeResolution::Blocked => return None,
            LexicalTypeResolution::NotFound => {}
        }
        let type_name = java_type_name_from_node(node, self.source)?;
        self.resolve_realm_type_name(&type_name)
    }

    /// Resolve a spelled type name through Java's own import and package tiers,
    /// but against the *realm-aware* declaration index.
    ///
    /// `JavaAnalyzer::resolve_usage_type_name` resolves against the Java-only
    /// index, so a Java file naming a Kotlin or Scala class declared in the same
    /// workspace resolves to nothing and the reference is silently lost. Kotlin
    /// source could already resolve onto Java declarations; passing the merged
    /// index here is the return direction, and it is what makes a mixed
    /// Java/Kotlin workspace report call relationships both ways (#1239
    /// milestone 4). Java's visibility rules are unchanged — only the universe
    /// of declarations those rules search.
    fn resolve_realm_type_name(&self, type_name: &str) -> Option<CodeUnit> {
        self.graph.with_definitions(|definitions| {
            resolve_java_usage_type_name_in(
                self.java,
                self.graph.token,
                definitions,
                self.file,
                type_name,
            )
        })
    }

    fn resolve_nested_type(&self, owner: &CodeUnit, name: &str) -> Option<CodeUnit> {
        resolve_nested_type_for_owner(self.graph, owner, name)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        let kind = if is_module_type_reference(node) {
            UsageReferenceKind::Type
        } else {
            classify_reference_node(node)
        };
        let start = node.start_byte();
        let end = node.end_byte();
        if self.input.enclosing(start, end).is_some() {
            self.edges.record_kind(self.input, callee, kind, start, end);
        } else if is_module_type_reference(node) {
            self.edges.record_with_caller_kind(
                self.input,
                CodeUnit::file_scope(self.file.clone()).fq_name(),
                callee,
                kind,
                start,
                end,
            );
        }
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.edges
            .record_unproven_name(self.input, name, node.start_byte(), node.end_byte());
    }
}

impl JavaReturnTypeContext for JavaScan<'_> {
    fn java(&self) -> &dyn JavaSource {
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

fn walk(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut JavaScan<'_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut state = (ctx, bindings);
    walk_tree_iterative(
        node,
        &mut state,
        |node, (ctx, bindings)| {
            if walk_enter(node, token, ctx, bindings) {
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
    token: QueryToken<'_>,
    ctx: &mut JavaScan<'_>,
    bindings: &mut LocalInferenceEngine<String>,
) -> bool {
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
        seed_declarations(node, token, ctx, bindings);
    } else {
        seed_inline_declarations(node, token, ctx, bindings);
    }

    record_reference(node, token, ctx, bindings);
    enters_scope
}

fn record_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut JavaScan<'_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        "object_creation_expression" => record_constructor_reference(node, token, ctx),
        // `new Foo()` and generics resolve via the type_identifier children, so
        // a scoped parent handles all of its semantic type segments (avoids
        // double counting while retaining outer-owner references).
        "type_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
            if is_non_type_module_reference(node) {
                return;
            }
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
                |candidate| ctx.resolve_type(token, candidate),
                |owner, name| ctx.resolve_nested_type(owner, name),
            ) {
                ctx.record(resolved.fq_name(), segment);
            }
        }
        "identifier" if is_module_type_reference(node) => {
            for (resolved, segment) in resolve_type_segments(
                node,
                ctx.source,
                |candidate| ctx.resolve_type(token, candidate),
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
            let is_same_owner =
                method_invocation_receiver_is_same_owner(node, token, ctx, bindings);
            route_same_owner(
                ctx,
                is_same_owner,
                |ctx| ctx.record_unproven(name, name_node),
                |ctx| {
                    // The receiver's nominal type is where the *name* is
                    // written, not necessarily where the method is declared.
                    // Formatting `{receiver owner}.{name}` therefore named a
                    // type that declares nothing whenever the receiver inherits
                    // the method, and `record` drops a callee that is not a
                    // node -- so the call left the graph entirely (#2044:
                    // Guava's `ImmutableSupplier.get` and
                    // `ImmutableList.internalArray`).
                    match method_owner_fqn(node, token, ctx, bindings) {
                        Some(owner) => match method_callee(&owner, name, ctx) {
                            MethodCallee::Resolved(callee) => ctx.record(callee, name_node),
                            // No workspace declaration answers the name: the
                            // receiver's type is known, but the method comes
                            // from outside the workspace. Keeping the nominal
                            // callee is what it always was, and it names no
                            // node, so it invents nothing.
                            MethodCallee::Undeclared => {
                                ctx.record(format!("{owner}.{name}"), name_node)
                            }
                            MethodCallee::Ambiguous => ctx.record_unproven(name, name_node),
                        },
                        None => ctx.record_unproven(name, name_node),
                    }
                },
            );
        }
        "method_reference" => {
            if let Some(receiver) = constructor_method_reference_receiver(node) {
                record_constructor_reference_for_type(receiver, token, node, ctx);
                return;
            }
            let Some((receiver, member_node)) = method_reference_parts(node) else {
                return;
            };
            let member = node_text(member_node, ctx.source);
            if member.is_empty() {
                return;
            }
            // The same resolution as an invocation. A method reference names no
            // arguments, so it can only ever bind what the receiver's static
            // type provides -- exactly the question `method_callee` answers.
            // Unlike an invocation, a reference whose member no workspace
            // declaration answers stays unproven rather than nominal: there is
            // no receiver-typed call to attribute to an outside declaration.
            if let Some(owner) = receiver_type_fqn(receiver, token, ctx, bindings)
                && let MethodCallee::Resolved(callee) = method_callee(&owner, member, ctx)
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
                && let Some(owner) = receiver_type_fqn(object, token, ctx, bindings)
            {
                ctx.record(format!("{owner}.{field}"), field_node);
            } else if !field.is_empty() {
                ctx.record_unproven(field, field_node);
            }
        }
        _ => {}
    }
}

fn record_constructor_reference(node: Node<'_>, token: QueryToken<'_>, ctx: &mut JavaScan<'_>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    record_constructor_reference_for_type(type_node, token, node, ctx);
}

fn record_constructor_reference_for_type(
    type_node: Node<'_>,
    token: QueryToken<'_>,
    reference_node: Node<'_>,
    ctx: &mut JavaScan<'_>,
) {
    let Some(owner) = ctx.resolve_type(token, type_node) else {
        return;
    };
    ctx.record(owner.fq_name().to_string(), type_node);
    let constructor_fqn = format!("{}.{}", owner.fq_name(), owner.identifier());
    let declared = ctx.graph.with_definitions(|definitions| {
        definitions
            .fqn(&constructor_fqn)
            .iter()
            .any(|candidate| candidate.is_function() && !candidate.is_synthetic())
    });
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

/// Which declaration a member named on a receiver of a given static type
/// actually is -- the one seam both the invocation and the method-reference
/// arms resolve through.
enum MethodCallee {
    /// Exactly one declaration answers the member.
    Resolved(String),
    /// The receiver's own type declares nothing of that name and more than one
    /// supertype at the nearest declaring level does, so no owner can be
    /// chosen without guessing.
    Ambiguous,
    /// No declaration in this workspace answers the member. The receiver's
    /// type resolved; the method it names did not.
    Undeclared,
}

/// Java binds a member to the nearest declaration the receiver's static type
/// provides (JLS 15.12.2): the type's own declaration first, and only then the
/// one it inherits. The per-symbol inverse scan already applies exactly this
/// rule -- `receiver_type_matches_target` answers `Incompatible` as soon as the
/// receiver's own type declares a matching method -- so an override binds the
/// override, and the declaration it overrides keeps only its
/// override-declaration link, never the call.
///
/// Ancestors are compared by fully qualified name because that is the identity
/// an edge is keyed by. One declaration compiled into two source trees (Guava
/// ships `com.google.common.base.Supplier` under both `guava/` and
/// `android/guava/`) is one callee, not an ambiguity.
fn method_callee(owner_fq_name: &str, member: &str, ctx: &JavaScan<'_>) -> MethodCallee {
    ctx.graph.with_definitions(|index| {
        let declares = |scope: &str| {
            index
                .fqn(&format!("{scope}.{member}"))
                .iter()
                .any(CodeUnit::is_function)
        };
        if declares(owner_fq_name) {
            return MethodCallee::Resolved(format!("{owner_fq_name}.{member}"));
        }
        let (Some(owner), Some(provider)) = (
            ctx.graph.index.definitions(owner_fq_name).next(),
            ctx.graph.hierarchy,
        ) else {
            return MethodCallee::Undeclared;
        };
        let Some(declaring) = java_nearest_declaring_ancestors(
            ctx.graph.index,
            provider,
            &owner,
            |ancestor: &CodeUnit| declares(&ancestor.fq_name()),
        ) else {
            return MethodCallee::Undeclared;
        };
        let mut owners: Vec<String> = declaring.iter().map(CodeUnit::fq_name).collect();
        owners.sort();
        owners.dedup();
        match owners.len() {
            1 => MethodCallee::Resolved(format!("{}.{member}", owners[0])),
            _ => MethodCallee::Ambiguous,
        }
    })
}

/// Whether a method invocation's receiver is a same-owner receiver: an
/// unqualified (implicit-this) call, an explicit `this` receiver, or the owner
/// type itself for an own-type static call. A `super` receiver, or a call
/// through a differently-named variable/type, stays external (#1014 facet B).
fn method_invocation_receiver_is_same_owner(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
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
                ctx.resolve_type_fqn(token, object)
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
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    method_owner_fqn_at_depth(node, token, ctx, bindings, 0)
}

fn method_owner_fqn_at_depth(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
    bindings: &LocalInferenceEngine<String>,
    depth: usize,
) -> Option<String> {
    match node.child_by_field_name("object") {
        Some(object) => receiver_type_fqn_at_depth(object, token, ctx, bindings, depth + 1),
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
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    receiver_type_fqn_at_depth(object, token, ctx, bindings, 0)
}

fn receiver_type_fqn_at_depth(
    object: Node<'_>,
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
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
                    .then(|| ctx.resolve_type_fqn(token, object))
                    .flatten()
            })
        }
        "this" | "super" => ctx
            .class_ranges
            .enclosing(object.start_byte())
            .map(str::to_string),
        "type_identifier" | "scoped_identifier" | "scoped_type_identifier" | "generic_type" => {
            ctx.resolve_type_fqn(token, object)
        }
        "field_access" => resolve_field_access_type(
            object,
            ctx.source,
            |base| {
                let name = node_text(base, ctx.source);
                if bindings.is_shadowed(name) {
                    Err(())
                } else {
                    Ok(ctx.resolve_type(token, base))
                }
            },
            |qualified| ctx.resolve_realm_type_name(qualified),
            |owner, name| ctx.resolve_nested_type(owner, name),
        )
        .map(|owner| owner.fq_name()),
        "object_creation_expression" => object
            .child_by_field_name("type")
            .and_then(|type_node| ctx.resolve_type_fqn(token, type_node)),
        "method_invocation" => {
            match receiver_type_outcome_at_depth(object, token, ctx, bindings, depth) {
                ReceiverAnalysisOutcome::Precise(values) if values.len() == 1 => {
                    values.into_iter().next()
                }
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unsupported { .. }
                | ReceiverAnalysisOutcome::ExceededBudget { .. }
                | ReceiverAnalysisOutcome::Unknown => None,
            }
        }
        _ => None,
    }
}

fn seed_declarations(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration" => {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for child in parameters.named_children(&mut cursor) {
                    if child.kind() == "formal_parameter" {
                        seed_typed_binding(child, token, ctx, bindings);
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                seed_typed_binding(parameter, token, ctx, bindings);
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
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration" => {
            seed_variable_declaration(node, token, ctx, bindings)
        }
        "formal_parameter" => seed_typed_binding(node, token, ctx, bindings),
        _ => {}
    }
}

fn seed_variable_declaration(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let resolved_type = node
        .child_by_field_name("type")
        .and_then(|type_node| ctx.resolve_type_fqn(token, type_node));
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
            .map(|value| receiver_type_outcome(value, token, ctx, bindings))
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
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
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
        .and_then(|type_node| ctx.resolve_type_fqn(token, type_node))
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
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
    bindings: &LocalInferenceEngine<String>,
) -> ReceiverAnalysisOutcome<String> {
    receiver_type_outcome_at_depth(expression, token, ctx, bindings, 0)
}

fn receiver_type_outcome_at_depth(
    expression: Node<'_>,
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
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
            .and_then(|type_node| ctx.resolve_type_fqn(token, type_node))
            .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown),
        "method_invocation" => {
            method_invocation_return_type_outcome(expression, token, ctx, bindings, depth)
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
                .map(|branch| receiver_type_outcome_at_depth(branch, token, ctx, bindings, depth))
                .collect();
            merge_receiver_type_outcomes(outcomes)
        }
        "parenthesized_expression" => expression
            .named_child(0)
            .map(|child| receiver_type_outcome_at_depth(child, token, ctx, bindings, depth))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown),
        _ => ReceiverAnalysisOutcome::Unknown,
    }
}

fn method_invocation_return_type_outcome(
    invocation: Node<'_>,
    token: QueryToken<'_>,
    ctx: &JavaScan<'_>,
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
    let Some(owner) = method_owner_fqn_at_depth(invocation, token, ctx, bindings, depth) else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    method_return_type_for_owner_fqn(&owner, token, name, argument_count(invocation), ctx)
}

fn argument_count(invocation: Node<'_>) -> usize {
    invocation
        .child_by_field_name("arguments")
        .map(|arguments| arguments.named_child_count())
        .unwrap_or(0)
}
