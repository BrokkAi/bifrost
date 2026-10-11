use crate::graph::extractor::ScanCtx;
use brokk_bifrost_core::analyzer::usages::common::{
    insert_import_hit, insert_unproven_hit, reclassify_self_receiver_hit_at, usage_hit_for_node,
};
use tree_sitter::Node;

pub fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit);
    }
}

pub fn record_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let hit = build_hit(node, ctx);
    insert_unproven_hit(ctx.unproven_hits, hit);
}

/// Record `node` as a same-owner self/cls receiver hit (#1014 facet B): a
/// `self.member` / `cls.member` access whose receiver is the current instance /
/// own class. Excluded from the external usage surface, counted as a same-owner
/// site. Records the ordinary hit, then reclassifies it — the shared scan
/// consumer, so the record ceremony lives in exactly one place.
pub fn record_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    record_hit(node, ctx);
    reclassify_self_receiver_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
}

/// Record `node` as an `Import`-binding hit (the token that brings the symbol
/// into this file), which the IDE find-references surface includes but the
/// call-graph surfaces ignore.
pub fn record_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let hit = build_hit(node, ctx);
    insert_import_hit(ctx.hits, hit);
}

fn build_hit(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
) -> Option<brokk_bifrost_core::analyzer::usages::model::UsageHit> {
    usage_hit_for_node(node, ctx.file, ctx.source, ctx.line_starts, |range| {
        ctx.graph.index.enclosing_code_unit(ctx.file, range)
    })
}
