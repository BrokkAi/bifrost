use crate::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, reclassify_override_declaration_hit_at,
    usage_hit,
};
use crate::analyzer::usages::java_graph::extractor::ScanCtx;
use crate::analyzer::{CodeUnit, Range};
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

#[derive(Clone, Default)]
pub(super) struct EnclosingContext {
    pub(super) enclosing: Option<CodeUnit>,
    pub(super) owner: Option<CodeUnit>,
}

pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    *ctx.raw_match_count += 1;
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    let end = node.end_byte();
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

pub(super) fn push_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_import_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
}

pub(super) fn push_override_declaration_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_override_declaration_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
}

pub(super) fn push_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    let end = node.end_byte();
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

pub(super) fn enclosing_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> EnclosingContext {
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
    let owner = enclosing.as_ref().and_then(|enclosing| {
        let mut current = ctx.analyzer.parent_of(enclosing);
        while current.as_ref().is_some_and(|unit| unit.is_function()) {
            current = current
                .as_ref()
                .and_then(|unit| ctx.analyzer.parent_of(unit));
        }
        current
    });
    let resolved = EnclosingContext { enclosing, owner };
    ctx.enclosing_cache.insert(key, resolved.clone());
    resolved
}
