use crate::analyzer::java::structural::expression_name_node;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::ClassRangeIndex;
use crate::analyzer::usages::java_graph::hits;
use crate::analyzer::usages::java_graph::resolver::{
    TargetKind, TargetSpec, argument_list_arity, bare_field_context_matches_target,
    bare_method_context_matches_target, has_proven_static_import, infer_type_from_value,
    is_declaration_name, is_ignored_type_context, java_method_signatures_match,
    nested_type_for_owner, node_text, receiver_matches_target, resolve_non_nested_type_from_node,
    resolve_type_from_node, resolve_type_segments, same_owner_context, seed_class_binding,
};
use crate::analyzer::usages::java_graph::return_type::{FileReturnCache, MethodReturnCache};
use crate::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, ProjectFile};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use std::cell::RefCell;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub(super) type MethodCallReturnCacheKey = (String, String, usize);

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) struct ScanCtx<'a> {
    pub(super) java: &'a JavaAnalyzer,
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) root: Node<'a>,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) bindings: &'a mut LocalInferenceEngine<String>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) class_ranges: ClassRangeIndex,
    pub(super) method_call_return_cache:
        RefCell<HashMap<MethodCallReturnCacheKey, ReceiverAnalysisOutcome<String>>>,
    pub(super) method_return_cache: &'a MethodReturnCache,
    pub(super) file_return_cache: &'a FileReturnCache,
    pub(super) enclosing_cache: HashMap<(usize, usize), hits::EnclosingContext>,
    class_scope_depths: Vec<usize>,
}

pub(super) fn scan_file(
    java: &JavaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    method_return_cache: &MethodReturnCache,
    file_return_cache: &FileReturnCache,
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
        root: tree.root_node(),
        line_starts: &line_starts,
        spec,
        bindings: &mut bindings,
        hits: state.hits,
        unproven_hits: state.unproven_hits,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        class_ranges: ClassRangeIndex::build(analyzer, file),
        method_call_return_cache: RefCell::new(HashMap::default()),
        method_return_cache,
        file_return_cache,
        enclosing_cache: HashMap::default(),
        class_scope_depths: Vec::new(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let enters_class_scope = node.kind() == "class_body";
    let enters_scope = enters_class_scope
        || matches!(
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
        if enters_class_scope {
            ctx.class_scope_depths.push(ctx.bindings.scope_depth());
        }
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

    if enters_class_scope {
        ctx.class_scope_depths.pop();
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
    let mut resolved_type = (ctx.spec.kind != TargetKind::Type)
        .then(|| resolve_type_from_node(type_node, ctx))
        .flatten();
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

        if ctx.spec.kind != TargetKind::Type
            && resolved_type.is_none()
            && let Some(value) = child.child_by_field_name("value")
        {
            resolved_type = infer_type_from_value(value, ctx);
        }

        if ctx.spec.kind == TargetKind::Type {
            ctx.bindings.declare_shadow(binding_name.to_string());
        } else if let Some(resolved) = resolved_type.as_ref()
            && ctx
                .spec
                .receiver_owner_fq_names
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
    if ctx.spec.kind == TargetKind::Type {
        ctx.bindings.declare_shadow(binding_name.to_string());
        return;
    }
    let resolved = node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_type_from_node(type_node, ctx));
    if let Some(resolved) = resolved
        && ctx
            .spec
            .receiver_owner_fq_names
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
    if maybe_record_static_qualifier_type_hit(node, ctx) {
        return;
    }
    let Some(type_node) = type_reference_node(node) else {
        return;
    };
    // A scoped parent records each of its semantic type segments with exact
    // token ranges, so visiting a child separately would only duplicate it.
    if type_node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "scoped_type_identifier" | "scoped_identifier"
        )
    }) {
        return;
    }
    if is_ignored_type_context(type_node) {
        return;
    }
    for (resolved, segment) in resolve_type_segments(
        type_node,
        ctx.source,
        |candidate| resolve_non_nested_type_from_node(candidate, ctx),
        |owner, name| nested_type_for_owner(owner, name, ctx),
    ) {
        if resolved.fq_name() == ctx.spec.owner.fq_name() {
            hits::push_hit(segment, ctx);
        }
    }
}

fn maybe_record_static_qualifier_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    if node.kind() != "identifier" || !is_member_access_object(node) {
        return false;
    }
    let text = node_text(node, ctx.source);
    if text != ctx.spec.member_name {
        return false;
    }
    match ctx.bindings.resolve_symbol(text) {
        SymbolResolution::Precise(targets)
            if targets
                .iter()
                .any(|target| target == &ctx.spec.target.fq_name()) =>
        {
            hits::push_hit(node, ctx);
            true
        }
        SymbolResolution::Unknown if ctx.bindings.is_shadowed(text) => true,
        SymbolResolution::Unknown => {
            if resolve_type_from_node(node, ctx).is_some_and(|resolved| resolved == ctx.spec.target)
            {
                hits::push_hit(node, ctx);
            } else {
                hits::push_unproven_hit(node, ctx);
            }
            true
        }
        SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => true,
    }
}

fn is_member_access_object(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "method_invocation" | "field_access")
            && parent.child_by_field_name("object") == Some(node)
    })
}

fn maybe_record_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(path) = node.named_child(0) else {
        return;
    };
    match ctx.spec.kind {
        TargetKind::Type => {
            if node_text(path, ctx.source) == ctx.spec.owner.fq_name() {
                hits::push_import_hit(path, ctx);
                return;
            }
        }
        TargetKind::Field | TargetKind::Method => {
            if node_text(path, ctx.source)
                == format!("{}.{}", ctx.spec.owner.fq_name(), ctx.spec.member_name)
            {
                if let Some(member) = expression_name_node(path) {
                    hits::push_import_hit(member, ctx);
                } else {
                    hits::push_import_hit(path, ctx);
                }
                return;
            }
        }
        TargetKind::Constructor => return,
    }

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
            ) && type_terminal_name_matches(current, ctx)
                && resolve_type_from_node(current, ctx)
                    .is_some_and(|resolved| resolved.fq_name() == ctx.spec.owner.fq_name())
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
    if node.kind() == "object_creation_expression" {
        let Some(type_node) = node.child_by_field_name("type") else {
            return;
        };
        if !type_terminal_name_matches(type_node, ctx) {
            return;
        }
        let Some(resolved) = resolve_type_from_node(type_node, ctx) else {
            return;
        };
        if resolved.fq_name() != ctx.spec.owner.fq_name() {
            return;
        }
        if !callable_arity_matches_target(node, ctx) {
            return;
        }
        hits::push_hit(node, ctx);
    }
}

fn type_terminal_name_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    expression_name_node(node)
        .is_some_and(|name| node_text(name, ctx.source) == ctx.spec.member_name)
}

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if is_declaration_name(node) {
        maybe_record_method_declaration_hit(node, ctx);
        return;
    }
    if node.kind() == "method_reference" {
        maybe_record_method_reference_hit(node, ctx);
        return;
    }
    if node.kind() != "method_invocation" {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if !callable_arity_matches_target(node, ctx) {
        return;
    }

    let receiver_matches = if let Some(object) = node.child_by_field_name("object") {
        receiver_matches_target(object, ctx)
    } else {
        bare_method_context_matches_target(node, ctx) || has_proven_static_import(ctx)
    };

    if receiver_matches {
        hits::push_hit(name_node, ctx);
    } else {
        hits::push_unproven_hit(name_node, ctx);
    }
}

fn maybe_record_method_reference_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some((receiver, member)) = method_reference_parts(node) else {
        return;
    };
    if node_text(member, ctx.source) != ctx.spec.member_name {
        return;
    }
    match method_reference_target_resolution(receiver, ctx) {
        MethodReferenceTargetResolution::NotTarget => {}
        MethodReferenceTargetResolution::Proven => hits::push_hit(member, ctx),
        MethodReferenceTargetResolution::Unproven => hits::push_unproven_hit(member, ctx),
    }
}

enum MethodReferenceTargetResolution {
    NotTarget,
    Proven,
    Unproven,
}

fn method_reference_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    let (member, rest) = children.split_last()?;
    let receiver = rest.last().copied()?;
    Some((receiver, *member))
}

fn method_reference_target_resolution(
    receiver: Node<'_>,
    ctx: &mut ScanCtx<'_>,
) -> MethodReferenceTargetResolution {
    let owners = method_reference_owner_fq_names(receiver, ctx);
    let mut candidates = Vec::new();
    for owner in &owners {
        candidates.extend(method_reference_candidates_for_owner(owner, ctx));
    }
    let matching = candidates
        .iter()
        .filter(|candidate| {
            method_reference_candidate_has_target_owner(candidate, ctx)
                && java_method_signatures_match(ctx.java, &ctx.spec.target, candidate)
        })
        .count();
    if matching == 0 {
        return MethodReferenceTargetResolution::NotTarget;
    }
    if matching == 1 && candidates.len() == 1 && owners.len() == 1 {
        MethodReferenceTargetResolution::Proven
    } else {
        MethodReferenceTargetResolution::Unproven
    }
}

fn method_reference_candidate_has_target_owner(candidate: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    let fqn = candidate.fq_name();
    let Some((owner, _)) = fqn.rsplit_once('.') else {
        return false;
    };
    ctx.spec.declaration_owner_fq_names.contains(owner)
}

fn method_reference_owner_fq_names(receiver: Node<'_>, ctx: &mut ScanCtx<'_>) -> Vec<String> {
    match receiver.kind() {
        "this" | "super" => ctx
            .class_ranges
            .enclosing(receiver.start_byte())
            .map(|owner| vec![owner.to_string()])
            .unwrap_or_default(),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(receiver, ctx.source))
            .as_precise()
            .map(|targets| targets.iter().cloned().collect())
            .unwrap_or_else(|| {
                resolve_type_from_node(receiver, ctx)
                    .map(|unit| vec![unit.fq_name()])
                    .unwrap_or_default()
            }),
        _ => resolve_type_from_node(receiver, ctx)
            .map(|unit| vec![unit.fq_name()])
            .unwrap_or_default(),
    }
}

fn method_reference_candidates_for_owner(owner_fq_name: &str, ctx: &ScanCtx<'_>) -> Vec<CodeUnit> {
    let mut candidates = ctx
        .java
        .global_usage_definition_index()
        .by_fqn(&format!("{owner_fq_name}.{}", ctx.spec.member_name))
        .iter()
        .filter(|unit| unit.is_function())
        .cloned()
        .collect::<Vec<_>>();
    let Some(owner) = ctx.analyzer.definitions(owner_fq_name).next() else {
        return candidates;
    };
    let Some(provider) = ctx.analyzer.type_hierarchy_provider() else {
        return candidates;
    };
    for ancestor in provider.get_ancestors(&owner) {
        candidates.extend(
            ctx.java
                .global_usage_definition_index()
                .by_fqn(&format!("{}.{}", ancestor.fq_name(), ctx.spec.member_name))
                .iter()
                .filter(|unit| unit.is_function())
                .cloned(),
        );
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn maybe_record_method_declaration_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    let Some(declaration) = node.parent() else {
        return;
    };
    if declaration.kind() != "method_declaration" {
        return;
    }
    let context = hits::enclosing_context(declaration, ctx);
    let Some(enclosing) = context.enclosing.as_ref() else {
        return;
    };
    let Some(owner) = context.owner.as_ref() else {
        return;
    };
    if owner.fq_name() == ctx.spec.owner.fq_name() {
        return;
    }
    if !ctx
        .spec
        .declaration_owner_fq_names
        .contains(&owner.fq_name())
    {
        return;
    }
    if enclosing.is_function()
        && java_method_signatures_match(ctx.java, &ctx.spec.target, enclosing)
    {
        hits::push_override_declaration_hit(node, ctx);
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
                hits::push_unproven_hit(field_node, ctx);
            }
        }
        return;
    }

    if node.kind() != "identifier" || node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if is_declaration_name(node) {
        return;
    }
    let same_owner = same_owner_context(node, ctx);
    let shadowed = ctx.class_scope_depths.last().map_or_else(
        || ctx.bindings.is_shadowed(ctx.spec.member_name.as_str()),
        |depth| {
            if !same_owner {
                return ctx
                    .bindings
                    .is_shadowed_at_or_below_scope(*depth, ctx.spec.member_name.as_str());
            }
            ctx.bindings
                .is_shadowed_below_scope(*depth, ctx.spec.member_name.as_str())
        },
    );
    if !shadowed && (bare_field_context_matches_target(node, ctx) || has_proven_static_import(ctx))
    {
        hits::push_hit(node, ctx);
    }
}

fn type_reference_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => Some(node),
        "annotation" | "marker_annotation" => node.child_by_field_name("name"),
        _ => None,
    }
}

fn callable_arity_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(expected_arities) = ctx.spec.callable_arities.as_ref() else {
        return true;
    };
    let actual = argument_list_arity(node);
    expected_arities.iter().any(|arity| arity.accepts(actual))
}
