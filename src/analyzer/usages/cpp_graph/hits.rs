use crate::analyzer::Range;
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::cpp_graph::extractor::{EnclosingContext, ScanCtx};
use crate::analyzer::usages::cpp_graph::resolver::{
    TargetKind, precise_parent_of, same_logical_symbol, visible_owner_from_member_name,
};
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, false);
}

pub(super) fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, false, true);
}

pub(super) fn push_definition_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit_with_options(node, ctx, true, false);
}

fn push_hit_with_options(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    allow_logical_target_enclosing: bool,
    self_receiver: bool,
) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    if is_inside_target_declaration(node, ctx) || is_member_field_declaration_context(node, ctx) {
        return;
    }
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
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
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

pub(super) fn enclosing_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> EnclosingContext {
    let key = (node.start_byte(), node.end_byte());
    if let Some(cached) = ctx.enclosing_cache.get(&key) {
        return cached.clone();
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    let owner = enclosing
        .as_ref()
        .and_then(|enclosing| precise_parent_of(ctx.analyzer, enclosing))
        .or_else(|| {
            enclosing
                .as_ref()
                .and_then(|enclosing| visible_owner_from_member_name(ctx, enclosing))
        });
    EnclosingContext { enclosing, owner }
}

fn is_inside_target_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.file != ctx.spec.target.source() {
        return false;
    }
    ctx.analyzer
        .ranges(&ctx.spec.target)
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
