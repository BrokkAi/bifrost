use crate::analyzer::Range;
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::cpp_graph::extractor::{EnclosingContext, ScanCtx};
use crate::analyzer::usages::cpp_graph::resolver::{
    TargetKind, precise_parent_of, same_logical_symbol, visible_owner_from_member_name,
};
use crate::analyzer::usages::model::UsageHitSurface;
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, false, false);
}

pub(super) fn push_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, false, true);
}

pub(super) fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, true, false);
}

pub(super) fn push_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, true, false, false);
}

pub(super) fn push_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if is_inside_target_declaration(node, ctx) || is_member_field_declaration_context(node, ctx) {
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
    ctx.unproven_hits.insert(
        usage_hit(
            ctx.file,
            line_idx,
            start,
            end,
            enclosing,
            snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
        )
        .into_unproven(),
    );
}

fn push_hit_with_options(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    allow_logical_target_enclosing: bool,
    self_receiver: bool,
    allow_inside_target_declaration: bool,
) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    if (!allow_inside_target_declaration && is_inside_target_declaration(node, ctx))
        || is_member_field_declaration_context(node, ctx)
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
    ctx.hits.insert(if self_receiver {
        hit.into_self_receiver()
    } else {
        hit
    });
    if !self_receiver
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

pub(super) fn is_member_field_declaration_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if !matches!(ctx.spec.kind, TargetKind::MemberField) {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "field_declaration" {
            return true;
        }
        if matches!(parent.kind(), "compound_statement" | "function_definition") {
            return false;
        }
        current = parent.parent();
    }
    false
}
