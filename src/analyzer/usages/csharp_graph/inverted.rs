//! Whole-workspace inverted edge builder for C#.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Like Java, C# references resolve
//! through type-name resolution ([`CSharpAnalyzer::resolve_visible_type`], which
//! honors `using` directives and the file's namespace) plus a
//! [`LocalInferenceEngine`] seeded with every local/parameter's declared type so
//! a member access's receiver can be typed:
//!
//! - a type reference (`Foo x`, `new Foo()`, `List<Foo>`) resolves to the type;
//! - `recv.Member(..)` resolves `recv`'s type to `Owner`, giving `Owner.Member`;
//! - `Type.Member(..)` (static) resolves the type directly;
//! - a bare `Member(..)` attributes to the enclosing class.
//!
//! The enclosing class is taken from a per-file class-range index (the analyzer's
//! own fqns), so unqualified calls attribute to the right class without
//! re-deriving the namespace. Receivers needing return-type inference (method
//! chains) are an unhandled recall gap, not a wrong edge.

use super::extractor::{
    is_declaration_name, is_unqualified_method_group_argument, member_access_name,
    member_access_receiver,
};
use super::resolver::{
    UnqualifiedMethodGroupResolution, argument_count, class_unit_for_fq_name,
    extension_visibility_site_key, first_type_child, is_type_reference_node,
    method_return_type_fq_name_for_arity, nearest_member_candidates_for_owner, node_text,
    reference_type_text, resolve_type_fq_name_at, resolve_unqualified_method_group_for_owner,
    unqualified_member_has_local_binding, unqualified_member_has_structured_shadow,
    visible_extension_method_candidates,
};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, first_precise, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{
    CSharpAnalyzer, CSharpMemberName, CallableArity, CodeUnit, IAnalyzer, ProjectFile,
    csharp_attribute_type_names, csharp_callable_arity, csharp_member_name,
    csharp_unqualified_invocation_for_name,
};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

pub(super) fn build_csharp_edges<F>(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    files: &[ProjectFile],
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    build_edges(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let mut ctx = CsScan {
                analyzer,
                csharp,
                file,
                source: parsed.source.as_str(),
                class_ranges: ClassRangeIndex::build(analyzer, file),
                method_group_cache: HashMap::default(),
                member_cache: HashMap::default(),
                extension_cache: HashMap::default(),
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
        })
    })
}

struct CsScan<'a, 'b> {
    analyzer: &'a dyn IAnalyzer,
    csharp: &'a CSharpAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    class_ranges: ClassRangeIndex,
    method_group_cache: HashMap<(String, String), UnqualifiedMethodGroupResolution>,
    member_cache: HashMap<(String, String, Option<usize>), Vec<CachedMember>>,
    extension_cache: HashMap<ExtensionCacheKey, Vec<String>>,
    collector: &'a mut EdgeCollector<'b>,
}

type ExtensionCacheKey = (String, String, usize, Option<usize>, usize, usize);

struct CachedMember {
    fqn: String,
    callable_arity: Option<CallableArity>,
}

impl CsScan<'_, '_> {
    /// Resolve a type reference's text to its fqn via lexical scope, then visible types.
    fn resolve_type_fqn_at(&self, text: &str, node: Node<'_>) -> Option<String> {
        resolve_type_fq_name_at(
            self.csharp,
            self.file,
            &self.class_ranges,
            text,
            node,
            self.source,
        )
    }

    /// The fqn of the smallest class declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.collector
            .record_unproven_name(name, node.start_byte(), node.end_byte());
    }

    fn record_unproven_callee(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record_unproven(callee, node.start_byte(), node.end_byte());
    }

    fn record_nearest_member(
        &mut self,
        owner_fqn: &str,
        name: &str,
        node: Node<'_>,
        call_arity: Option<usize>,
        explicit_generic_arity: Option<usize>,
    ) {
        let key = (
            owner_fqn.to_string(),
            name.to_string(),
            explicit_generic_arity,
        );
        if !self.member_cache.contains_key(&key) {
            let candidates = class_unit_for_fq_name(self.csharp, owner_fqn)
                .map(|owner| {
                    nearest_member_candidates_for_owner(
                        self.analyzer,
                        self.csharp,
                        &owner,
                        name,
                        explicit_generic_arity,
                    )
                })
                .unwrap_or_default()
                .into_iter()
                .map(|candidate| CachedMember {
                    fqn: candidate.fq_name(),
                    callable_arity: candidate
                        .is_function()
                        .then(|| csharp_callable_arity(self.analyzer, &candidate)),
                })
                .collect();
            self.member_cache.insert(key.clone(), candidates);
        }
        let candidates = self
            .member_cache
            .get(&key)
            .expect("member cache entry was inserted");
        let callees = candidates
            .iter()
            .filter(|candidate| {
                !call_arity.is_some_and(|arity| {
                    candidate
                        .callable_arity
                        .is_some_and(|callable| !callable.accepts(arity))
                })
            })
            .map(|candidate| candidate.fqn.clone())
            .collect::<Vec<_>>();
        if !callees.is_empty() {
            for callee in callees {
                self.record(callee, node);
            }
            return;
        }

        let extension_callees = call_arity
            .map(|call_arity| {
                let (scope_start, scope_end) = extension_visibility_site_key(node);
                let extension_key = (
                    owner_fqn.to_string(),
                    name.to_string(),
                    call_arity,
                    explicit_generic_arity,
                    scope_start,
                    scope_end,
                );
                if !self.extension_cache.contains_key(&extension_key) {
                    let receiver_types = [owner_fqn.to_string()];
                    let mut extensions = visible_extension_method_candidates(
                        self.csharp,
                        self.analyzer,
                        self.file,
                        self.source,
                        node,
                        &receiver_types,
                        name,
                        Some(call_arity),
                        explicit_generic_arity,
                        false,
                    )
                    .into_iter()
                    .map(|extension| extension.fq_name())
                    .collect::<Vec<_>>();
                    extensions.sort();
                    extensions.dedup();
                    self.extension_cache
                        .insert(extension_key.clone(), extensions);
                }
                self.extension_cache
                    .get(&extension_key)
                    .expect("extension cache entry was inserted")
                    .clone()
            })
            .unwrap_or_default();
        if !extension_callees.is_empty() {
            for callee in extension_callees {
                self.record(callee, node);
            }
            return;
        }

        if candidates.is_empty() {
            if explicit_generic_arity.is_some() {
                self.record_unproven(name, node);
            } else {
                self.record(format!("{owner_fqn}.{name}"), node);
            }
        }
    }
}

const SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "block",
    "for_statement",
    "for_each_statement",
    "using_statement",
    "catch_clause",
];

fn walk(node: Node<'_>, ctx: &mut CsScan<'_, '_>, bindings: &mut LocalInferenceEngine<String>) {
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
    }
    seed_declaration(node, ctx, bindings);
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
    ctx: &mut CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        "attribute" => {
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            let names = csharp_attribute_type_names(name, ctx.source);
            for candidate in ctx
                .csharp
                .unambiguous_attribute_type_candidates(ctx.file, &names)
            {
                ctx.record(candidate.fq_name(), name);
            }
        }
        // A type reference (`Foo x`, `new Foo()`, generics) resolves to the type
        // node. `new Foo()`'s type child is itself a type reference, so it is
        // covered here without a separate object-creation case.
        "identifier" | "type" => {
            if node.kind() == "identifier"
                && let Some((invocation, explicit_generic_arity)) =
                    csharp_unqualified_invocation_for_name(node)
            {
                let name = node_text(node, ctx.source);
                if unqualified_member_has_local_binding(node, ctx.source, bindings)
                    || unqualified_member_has_structured_shadow(node, ctx.source)
                {
                    return;
                }
                if let Some(owner) = ctx.enclosing_class(node.start_byte()).map(str::to_string) {
                    let arity = argument_count(invocation, ctx.source);
                    ctx.record_nearest_member(
                        &owner,
                        name,
                        node,
                        Some(arity),
                        explicit_generic_arity,
                    );
                }
                return;
            }
            if is_declaration_name(node) || !is_type_reference_node(node) {
                // An unqualified `Member(..)` call attributes to the enclosing class.
                if is_unqualified_method_group_argument(node, ctx.source) {
                    let Some(owner_fqn) = ctx
                        .class_ranges
                        .enclosing(node.start_byte())
                        .map(str::to_string)
                    else {
                        return;
                    };
                    let name = node_text(node, ctx.source).to_string();
                    if unqualified_member_has_local_binding(node, ctx.source, bindings) {
                        return;
                    }
                    let key = (owner_fqn.clone(), name.clone());
                    let resolution = if let Some(cached) = ctx.method_group_cache.get(&key) {
                        cached.clone()
                    } else {
                        let Some(owner) = class_unit_for_fq_name(ctx.csharp, &owner_fqn) else {
                            return;
                        };
                        let resolution = resolve_unqualified_method_group_for_owner(
                            ctx.analyzer,
                            ctx.csharp,
                            &owner,
                            &name,
                        );
                        ctx.method_group_cache.insert(key, resolution.clone());
                        resolution
                    };
                    if matches!(&resolution, UnqualifiedMethodGroupResolution::NoMember)
                        || unqualified_member_has_structured_shadow(node, ctx.source)
                    {
                        return;
                    }
                    match resolution {
                        UnqualifiedMethodGroupResolution::Unique(candidate) => {
                            ctx.record(candidate.fq_name(), node);
                        }
                        UnqualifiedMethodGroupResolution::Ambiguous(candidates) => {
                            let mut callees = candidates
                                .into_iter()
                                .map(|candidate| candidate.fq_name())
                                .collect::<Vec<_>>();
                            callees.sort();
                            callees.dedup();
                            for callee in callees {
                                ctx.record_unproven_callee(callee, node);
                            }
                        }
                        UnqualifiedMethodGroupResolution::NoMember => {}
                    }
                }
                return;
            }
            let reference = reference_type_text(node, ctx.source);
            if let Some(fqn) = ctx.resolve_type_fqn_at(&reference, node) {
                ctx.record(fqn, node);
            }
        }
        "member_access_expression" => {
            let (Some(name_node), Some(receiver)) =
                (member_access_name(node), member_access_receiver(node))
            else {
                return;
            };
            let Some(name_shape) = csharp_member_name(name_node) else {
                return;
            };
            let name = node_text(name_shape.identifier, ctx.source);
            if name.is_empty() {
                return;
            }
            if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) {
                let call_arity = node.parent().and_then(|parent| {
                    (parent.kind() == "invocation_expression"
                        && parent.child_by_field_name("function") == Some(node))
                    .then(|| argument_count(parent, ctx.source))
                });
                ctx.record_nearest_member(
                    &owner,
                    name,
                    name_shape.identifier,
                    call_arity,
                    name_shape.explicit_generic_arity,
                );
            } else {
                ctx.record_unproven(name, name_shape.identifier);
            }
        }
        _ => {}
    }
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_fqn(
    receiver: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            // A typed local resolves to its type; otherwise the name may be a
            // static type, unless it is a known (shadowed) untyped local.
            first_precise(bindings, name).or_else(|| {
                (!bindings.is_shadowed(name))
                    .then(|| ctx.resolve_type_fqn_at(name, receiver))
                    .flatten()
            })
        }
        "this" | "base" => ctx
            .enclosing_class(receiver.start_byte())
            .map(str::to_string),
        "invocation_expression" => invocation_return_type_fqn(receiver, ctx, bindings),
        "qualified_name" | "generic_name" => {
            ctx.resolve_type_fqn_at(&reference_type_text(receiver, ctx.source), receiver)
        }
        _ => None,
    }
}

fn seed_declaration(
    node: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "parameter" => {
            let (Some(name), Some(type_node)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("type"),
            ) else {
                return;
            };
            seed_typed(
                name,
                ctx.resolve_type_fqn_at(&reference_type_text(type_node, ctx.source), type_node),
                ctx,
                bindings,
            );
        }
        "variable_declaration" => seed_variable_declaration(node, ctx, bindings),
        _ => {}
    }
}

fn seed_variable_declaration(
    node: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = reference_type_text(type_node, ctx.source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = child.child_by_field_name("name") else {
            continue;
        };
        // `var x = new Foo()` infers from the initializer; other `var` is unknown.
        let resolved = if type_text == "var" {
            object_created_type(child)
                .and_then(|type_node| {
                    ctx.resolve_type_fqn_at(&reference_type_text(type_node, ctx.source), type_node)
                })
                .or_else(|| var_initializer_type(child, ctx, bindings))
        } else {
            ctx.resolve_type_fqn_at(&type_text, type_node)
        };
        seed_typed(name, resolved, ctx, bindings);
    }
}

fn seed_typed(
    name: Node<'_>,
    resolved: Option<String>,
    ctx: &CsScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let binding_name = node_text(name, ctx.source);
    if binding_name.is_empty() {
        return;
    }
    match resolved {
        Some(fqn) => bindings.seed_symbol(binding_name.to_string(), fqn),
        None => bindings.declare_shadow(binding_name.to_string()),
    }
}

/// The type node of a `new Foo()` initializer reachable from a declarator.
fn object_created_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .or_else(|| first_type_child(node));
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(object_created_type)
}

fn var_initializer_type(
    declarator: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    let initializer = variable_declarator_initializer(declarator)?;
    expression_type_fqn(initializer, ctx, bindings)
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

fn expression_type_fqn(
    expression: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match expression.kind() {
        "object_creation_expression" => object_created_type(expression).and_then(|type_node| {
            ctx.resolve_type_fqn_at(&reference_type_text(type_node, ctx.source), type_node)
        }),
        "invocation_expression" => invocation_return_type_fqn(expression, ctx, bindings),
        "identifier" => {
            let name = node_text(expression, ctx.source);
            first_precise(bindings, name)
        }
        _ => None,
    }
}

fn invocation_return_type_fqn(
    invocation: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    let function = invocation.child_by_field_name("function")?;
    match function.kind() {
        "identifier" => {
            let name = node_text(function, ctx.source);
            let owner_fqn = ctx.enclosing_class(invocation.start_byte())?;
            let owner = class_unit_for_fq_name(ctx.csharp, owner_fqn)?;
            method_return_type_for_call(
                ctx,
                &owner,
                name,
                argument_count(invocation, ctx.source),
                None,
                None,
            )
        }
        "generic_name" => {
            let name = csharp_member_name(function)?;
            let type_arguments = resolved_type_arguments(name, ctx);
            let owner_fqn = ctx.enclosing_class(invocation.start_byte())?;
            let owner = class_unit_for_fq_name(ctx.csharp, owner_fqn)?;
            method_return_type_for_call(
                ctx,
                &owner,
                node_text(name.identifier, ctx.source),
                argument_count(invocation, ctx.source),
                name.explicit_generic_arity,
                type_arguments.as_deref(),
            )
        }
        "member_access_expression" => {
            let receiver = member_access_receiver(function)?;
            let name = csharp_member_name(member_access_name(function)?)?;
            let type_arguments = resolved_type_arguments(name, ctx);
            let owner_fqn = receiver_type_fqn(receiver, ctx, bindings)?;
            let owner = class_unit_for_fq_name(ctx.csharp, &owner_fqn)?;
            method_return_type_for_call(
                ctx,
                &owner,
                node_text(name.identifier, ctx.source),
                argument_count(invocation, ctx.source),
                name.explicit_generic_arity,
                type_arguments.as_deref(),
            )
        }
        _ => None,
    }
}

fn method_return_type_for_call(
    ctx: &CsScan<'_, '_>,
    owner: &CodeUnit,
    method_name: &str,
    arity: usize,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
) -> Option<String> {
    method_return_type_fq_name_for_arity(
        ctx.csharp,
        ctx.file,
        owner,
        method_name,
        Some(arity),
        explicit_generic_arity,
        explicit_type_arguments,
    )
}

fn resolved_type_arguments(
    name: CSharpMemberName<'_>,
    ctx: &CsScan<'_, '_>,
) -> Option<Vec<String>> {
    let arguments = name.type_arguments?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .map(|argument| {
            ctx.resolve_type_fqn_at(&reference_type_text(argument, ctx.source), argument)
        })
        .collect()
}
