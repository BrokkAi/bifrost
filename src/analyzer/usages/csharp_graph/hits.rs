use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::csharp_graph::extractor::ScanCtx;
use crate::analyzer::{CodeUnit, Range};
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
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
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.hits.insert(usage_hit(
        ctx.file,
        line_idx,
        start,
        end,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

/// Push `node` as a same-owner `this`/own-type receiver hit (#1014 facet B):
/// excluded from the external usage surface, counted as a same-owner site.
pub(super) fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_code_unit(node, ctx) else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.hits.insert(
        usage_hit(
            ctx.file,
            line_idx,
            start,
            end,
            enclosing,
            snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
        )
        .into_self_receiver(),
    );
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
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
    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    ctx.enclosing_cache.insert(key, enclosing.clone());
    enclosing
}
