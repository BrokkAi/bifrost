use crate::analyzer::Range;
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::cpp_graph::extractor::{EnclosingContext, ScanCtx};
use crate::analyzer::usages::cpp_graph::resolver::{
    TargetKind, precise_parent_of, same_logical_symbol, visible_owner_from_member_name,
};
use crate::analyzer::usages::model::{UsageHitKind, UsageHitSurface};
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, UsageHitKind::Reference, false);
}

pub(super) fn push_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, UsageHitKind::Reference, true);
}

pub(super) fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, UsageHitKind::SelfReceiver, false);
}

pub(super) fn push_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, true, UsageHitKind::Definition, false);
}

pub(super) fn push_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_unproven_hit_with_kind(node, ctx, UsageHitKind::Reference);
}

pub(super) fn push_unproven_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_unproven_hit_with_kind(node, ctx, UsageHitKind::Definition);
}

fn push_unproven_hit_with_kind(node: Node<'_>, ctx: &mut ScanCtx<'_>, kind: UsageHitKind) {
    if is_inside_target_declaration(node, ctx) || is_member_field_own_declarator(node, ctx) {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    if ctx.target_group.contains(&enclosing) {
        return;
    }
    if enclosing == ctx.spec.target || same_logical_symbol(&enclosing, &ctx.spec.target) {
        return;
    }
    let hit = usage_hit(
        ctx.file,
        line_idx,
        start,
        end,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    );
    let hit = match kind {
        UsageHitKind::Reference => hit,
        UsageHitKind::Definition => hit.into_definition(),
        UsageHitKind::Import
        | UsageHitKind::Reexport
        | UsageHitKind::SelfReceiver
        | UsageHitKind::OverrideDeclaration => {
            unreachable!("unsupported unproven C++ hit emission kind: {kind:?}")
        }
    };
    ctx.unproven_hits.insert(hit.into_unproven());
}

fn push_hit_with_options(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    allow_logical_target_enclosing: bool,
    kind: UsageHitKind,
    allow_inside_target_declaration: bool,
) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    if (!allow_inside_target_declaration && is_inside_target_declaration(node, ctx))
        || is_member_field_own_declarator(node, ctx)
    {
        return;
    }
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    if ctx.target_group.contains(&enclosing) {
        return;
    }
    if enclosing == ctx.spec.target
        || (!allow_logical_target_enclosing && same_logical_symbol(&enclosing, &ctx.spec.target))
    {
        return;
    }
    let hit = usage_hit(
        ctx.file,
        line_idx,
        start,
        end,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    );
    let hit = match kind {
        UsageHitKind::Reference => hit,
        UsageHitKind::SelfReceiver => hit.into_self_receiver(),
        UsageHitKind::Definition => hit.into_definition(),
        UsageHitKind::Import | UsageHitKind::Reexport | UsageHitKind::OverrideDeclaration => {
            unreachable!("unsupported C++ hit emission kind: {kind:?}")
        }
    };
    ctx.hits.insert(hit);
    if kind.included_in(UsageHitSurface::ExternalUsages)
        && ctx
            .hits
            .iter()
            .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
            .count()
            > ctx.max_usages
    {
        *ctx.limit_exceeded = true;
    }
}

pub(super) fn enclosing_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> EnclosingContext {
    let key = (node.start_byte(), node.end_byte());
    if let Some(cached) = ctx.enclosing_cache.borrow().get(&key).cloned() {
        return cached;
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    let owner = enclosing.as_ref().and_then(|enclosing| {
        let cached = ctx.enclosing_owner_cache.borrow().get(enclosing).cloned();
        if let Some(cached) = cached {
            return cached;
        }
        let resolved = precise_parent_of(ctx.analyzer, enclosing)
            .or_else(|| visible_owner_from_member_name(ctx, enclosing));
        ctx.enclosing_owner_cache
            .borrow_mut()
            .insert(enclosing.clone(), resolved.clone());
        resolved
    });
    let context = EnclosingContext { enclosing, owner };
    ctx.enclosing_cache
        .borrow_mut()
        .insert(key, context.clone());
    context
}

fn is_inside_target_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    ctx.target_declaration_ranges
        .iter()
        .any(|range| node.start_byte() >= range.start_byte && node.end_byte() <= range.end_byte)
}

/// Returns whether `node` is on the declared-name path of a class field.
///
/// A `field_declaration` also owns default member initializers and, for method
/// declarations, parameter default values. Those subtrees contain genuine
/// references and must not be discarded with the declaration's own name.
pub(super) fn is_member_field_own_declarator(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if !matches!(ctx.spec.kind, TargetKind::MemberField) {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "field_declaration" {
            let mut cursor = parent.walk();
            return parent
                .children_by_field_name("declarator", &mut cursor)
                .any(|mut declarator| {
                    while let Some(inner) = declarator.child_by_field_name("declarator") {
                        declarator = inner;
                    }
                    node.start_byte() >= declarator.start_byte()
                        && node.end_byte() <= declarator.end_byte()
                });
        }
        if matches!(parent.kind(), "compound_statement" | "function_definition") {
            return false;
        }
        current = parent.parent();
    }
    false
}
