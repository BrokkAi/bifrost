use super::extractor::ScanCtx;
use crate::graph_hits::{HitRecorder, refresh_usage_limit};
use brokk_bifrost_core::analyzer::model::{CodeUnit, Range};
use brokk_bifrost_core::analyzer::usages::common::{
    reclassify_import_hit_at, reclassify_override_declaration_hit_at,
    reclassify_self_receiver_hit_at,
};
use brokk_bifrost_core::text_utils::find_line_index_for_offset;
use tree_sitter::Node;

#[derive(Clone, Default)]
pub struct EnclosingContext {
    pub enclosing: Option<CodeUnit>,
    pub owner: Option<CodeUnit>,
}

pub fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    *ctx.raw_match_count += 1;
    if *ctx.limit_exceeded {
        return;
    }
    let Some(enclosing) = enclosing_context(node, ctx).enclosing else {
        return;
    };
    HitRecorder::new(ctx.file, ctx.source, ctx.line_starts, &ctx.spec.target).record_proven(
        ctx.hits,
        ctx.max_usages,
        ctx.limit_exceeded,
        node,
        enclosing,
        &crate::JavaKnowledge,
    );
}

pub fn push_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_import_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
    refresh_usage_limit(ctx.hits, ctx.max_usages, ctx.limit_exceeded);
}

pub fn push_override_declaration_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_override_declaration_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
}

/// Record `node` as a same-owner self/this receiver hit (#1014 facet B): a call
/// whose receiver is the current instance (`this`, implicit-this) or the owner
/// type itself. Excluded from the external usage surface, counted as a
/// same-owner site.
pub fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_self_receiver_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
    refresh_usage_limit(ctx.hits, ctx.max_usages, ctx.limit_exceeded);
}

pub fn push_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let end = node.end_byte();
    let enclosing = enclosing_context(node, ctx).enclosing;
    HitRecorder::new(ctx.file, ctx.source, ctx.line_starts, &ctx.spec.target).record_unproven(
        ctx.unproven_hits,
        start,
        end,
        enclosing,
    );
}

pub fn enclosing_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> EnclosingContext {
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
    let enclosing = Some(
        ctx.graph
            .index
            .enclosing_code_unit(ctx.file, &range)
            .unwrap_or_else(|| CodeUnit::file_scope(ctx.file.clone())),
    );
    let owner = enclosing.as_ref().and_then(|enclosing| {
        let mut current = enclosing
            .is_class()
            .then(|| enclosing.clone())
            .or_else(|| ctx.graph.index.parent_of(enclosing));
        while current.as_ref().is_some_and(|unit| unit.is_function()) {
            current = current
                .as_ref()
                .and_then(|unit| ctx.graph.index.parent_of(unit));
        }
        current
    });
    let resolved = EnclosingContext { enclosing, owner };
    ctx.enclosing_cache.insert(key, resolved.clone());
    resolved
}
