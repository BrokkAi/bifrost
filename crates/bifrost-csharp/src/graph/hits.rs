use crate::graph::extractor::ScanCtx;
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::Range;
use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, external_usage_hit_count, reclassify_self_receiver_hit_at, usage_hit,
};
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_code_unit(node, ctx) else {
        return;
    };
    // A reference whose enclosing declaration is a *callable* target is a
    // recursive call (#1638): recorded, then classified `SelfReceiver`, so
    // editor find-references lists it while the external usage surface omits
    // it. For any other target the site is the declaration itself, not a use
    // of it, and stays dropped.
    if enclosing == ctx.spec.target && !ctx.spec.target.is_function() {
        return;
    }
    let recursive = enclosing == ctx.spec.target;
    ctx.hits.insert(usage_hit(
        ctx.file,
        line_idx,
        start,
        end,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    ));
    if recursive {
        reclassify_self_receiver_hit_at(ctx.hits, ctx.file, start, end);
    }
    refresh_usage_limit(ctx);
}

/// Push `node` as a same-owner `this`/own-type receiver hit (#1014 facet B):
/// excluded from the external usage surface, counted as a same-owner site.
/// Records the ordinary hit, then reclassifies it — the shared scan consumer, so
/// the record ceremony (span, enclosing, cap, self-definition guard) lives in
/// exactly one place.
pub(super) fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_self_receiver_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
    refresh_usage_limit(ctx);
}

fn refresh_usage_limit(ctx: &mut ScanCtx<'_>) {
    *ctx.limit_exceeded = external_usage_hit_count(ctx.hits) > ctx.max_usages;
}

pub(super) fn push_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let end = node.end_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_code_unit(node, ctx) else {
        return;
    };
    if enclosing == ctx.spec.target {
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

fn enclosing_code_unit(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> Option<CodeUnit> {
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
    let enclosing = ctx.graph.index.enclosing_code_unit(ctx.file, &range);
    ctx.enclosing_cache.insert(key, enclosing.clone());
    enclosing
}
