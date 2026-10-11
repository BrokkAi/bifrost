use crate::graph::extractor::ScanCtx;
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::usages::common::{
    insert_import_hit, insert_unproven_hit, usage_hit_for_node,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use tree_sitter::Node;

pub fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit);
    }
}

/// Record `node` as an `Import`-binding hit (the token that brings the symbol
/// into this file). The IDE find-references surface includes these; the
/// call-graph / relevance surfaces filter them out.
pub fn record_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let hit = build_hit(node, ctx);
    insert_import_hit(ctx.hits, hit);
}

/// Record `node` as a binding-only re-export. The token is useful to IDE
/// find-references and rename operations, but is omitted from the quieter
/// agent/search usage surface.
pub fn record_reexport_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit.into_reexport());
    }
}

/// Record `node` as a self/this receiver hit. IDE references include these; the
/// call-graph / relevance surfaces filter them out.
pub fn record_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit.into_self_receiver());
    }
}

/// Record an editor-visible link through an explicit declared TypeScript
/// contract without publishing it as an exact runtime usage.
pub fn record_declared_reference_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit.into_declared_reference());
    }
}

pub fn record_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let hit = build_hit(node, ctx);
    insert_unproven_hit(ctx.unproven_hits, hit);
}

fn build_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> Option<UsageHit> {
    usage_hit_for_node(node, ctx.file, ctx.source, ctx.line_starts, |range| {
        // Preserve the JS/TS file-scope attribution for hits without an indexed
        // enclosing declaration (#1785).
        Some(
            ctx.analyzer
                .enclosing_code_unit(ctx.file, range)
                .unwrap_or_else(|| CodeUnit::file_scope(ctx.file.clone())),
        )
    })
}
