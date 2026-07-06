use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::java_graph::hits;
use crate::analyzer::usages::java_graph::resolver::{
    TargetKind, TargetSpec, argument_list_arity, has_proven_static_import, infer_type_from_value,
    is_declaration_name, is_ignored_type_context, node_text, receiver_matches_target,
    resolve_type_from_node, same_owner_context, seed_class_binding,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{IAnalyzer, JavaAnalyzer, ProjectFile};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) saw_unproven_match: &'a mut bool,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) struct ScanCtx<'a> {
    pub(super) java: &'a JavaAnalyzer,
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) bindings: &'a mut LocalInferenceEngine<String>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) saw_unproven_match: &'a mut bool,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: HashMap<(usize, usize), hits::EnclosingContext>,
}

pub(super) fn scan_file(
    java: &JavaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);

    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    seed_class_binding(java, file, spec, &mut bindings);

    let mut ctx = ScanCtx {
        java,
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        bindings: &mut bindings,
        hits: state.hits,
        saw_unproven_match: state.saw_unproven_match,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let enters_scope = matches!(
        node.kind(),
        "method_declaration"
            | "constructor_declaration"
            | "block"
            | "lambda_expression"
            | "catch_clause"
            | "enhanced_for_statement"
            | "for_statement"
    );

    if enters_scope {
        ctx.bindings.enter_scope();
        seed_declarations(node, ctx);
    } else {
        seed_inline_declarations(node, ctx);
    }

    if node.kind() == "import_declaration" {
        maybe_record_import_hit(node, ctx);
    } else {
        maybe_record_hit(node, ctx);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }

    if enters_scope {
        ctx.bindings.exit_scope();
    }
}

fn seed_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" => {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for child in parameters.named_children(&mut cursor) {
                    if child.kind() == "formal_parameter" {
                        seed_typed_binding(child, ctx);
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                seed_typed_binding(parameter, ctx);
            }
        }
        "enhanced_for_statement" => {
            if let Some(name) = node.child_by_field_name("name") {
                ctx.bindings.declare_shadow(node_text(name, ctx.source));
            }
        }
        _ => {}
    }
}

fn seed_inline_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration" => seed_variable_declaration(node, ctx),
        "formal_parameter" => seed_typed_binding(node, ctx),
        _ => {}
    }
}

fn seed_variable_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let mut resolved_type = resolve_type_from_node(type_node, ctx);
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

        if resolved_type.is_none()
            && let Some(value) = child.child_by_field_name("value")
        {
            resolved_type = infer_type_from_value(value, ctx);
        }

        if let Some(resolved) = resolved_type.as_ref()
            && ctx
                .spec
                .accepted_owner_fq_names
                .contains(&resolved.fq_name())
        {
            ctx.bindings
                .seed_symbol(binding_name.to_string(), resolved.fq_name());
        } else {
            ctx.bindings.declare_shadow(binding_name.to_string());
        }
    }
}

fn seed_typed_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source);
    if binding_name.is_empty() {
        return;
    }
    let resolved = node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_type_from_node(type_node, ctx));
    if let Some(resolved) = resolved
        && ctx
            .spec
            .accepted_owner_fq_names
            .contains(&resolved.fq_name())
    {
        ctx.bindings
            .seed_symbol(binding_name.to_string(), resolved.fq_name());
    } else {
        ctx.bindings.declare_shadow(binding_name.to_string());
    }
}

fn maybe_record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match ctx.spec.kind {
        TargetKind::Type => maybe_record_type_hit(node, ctx),
        TargetKind::Constructor => maybe_record_constructor_hit(node, ctx),
        TargetKind::Method => maybe_record_method_hit(node, ctx),
        TargetKind::Field => maybe_record_field_hit(node, ctx),
    }
}

fn maybe_record_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "type_identifier" | "scoped_type_identifier" | "generic_type"
    ) {
        return;
    }
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "scoped_type_identifier")
    {
        return;
    }
    if is_ignored_type_context(node) {
        return;
    }
    let Some(resolved) = resolve_type_from_node(node, ctx) else {
        return;
    };
    if resolved != ctx.spec.owner {
        return;
    }
    hits::push_hit(node, ctx);
}

fn maybe_record_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.kind != TargetKind::Type {
        return;
    }
    walk_tree_iterative(
        node,
        ctx,
        |current, ctx| {
            if matches!(
                current.kind(),
                "type_identifier" | "scoped_type_identifier" | "scoped_identifier" | "identifier"
            ) && resolve_type_from_node(current, ctx)
                .is_some_and(|resolved| resolved == ctx.spec.owner)
            {
                hits::push_import_hit(current, ctx);
                return TreeWalkAction::Skip;
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn maybe_record_constructor_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "object_creation_expression" {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(resolved) = resolve_type_from_node(type_node, ctx) else {
        return;
    };
    if resolved != ctx.spec.owner {
        return;
    }
    if let Some(expected_arity) = ctx.spec.method_arity
        && argument_list_arity(node) != expected_arity
    {
        return;
    }
    hits::push_hit(node, ctx);
}

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "method_invocation" {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if let Some(expected_arity) = ctx.spec.method_arity
        && argument_list_arity(node) != expected_arity
    {
        return;
    }

    let receiver_matches = if let Some(object) = node.child_by_field_name("object") {
        receiver_matches_target(object, ctx)
    } else {
        same_owner_context(node, ctx) || has_proven_static_import(ctx)
    };

    if receiver_matches {
        hits::push_hit(name_node, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "field_access" {
        let Some(field_node) = node.child_by_field_name("field") else {
            return;
        };
        if node_text(field_node, ctx.source) != ctx.spec.member_name {
            return;
        }
        if let Some(object) = node.child_by_field_name("object") {
            if receiver_matches_target(object, ctx) {
                hits::push_hit(field_node, ctx);
            } else {
                *ctx.saw_unproven_match = true;
            }
        }
        return;
    }

    if node.kind() != "identifier" || node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if !is_declaration_name(node)
        && (same_owner_context(node, ctx) || has_proven_static_import(ctx))
    {
        hits::push_hit(node, ctx);
    }
}
