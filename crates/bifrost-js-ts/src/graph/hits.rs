use crate::graph::extractor::ScanCtx;
use brokk_bifrost_core::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::{CodeUnit, Range};
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, trimmed_snippet_around_line};
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
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit.into_import());
    }
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

pub fn record_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.unproven_hits.insert(hit.into_unproven());
    }
}

fn build_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> Option<UsageHit> {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    if start_byte >= end_byte {
        return None;
    }

    let line_idx = find_line_index_for_offset(ctx.line_starts, start_byte);
    let snippet =
        trimmed_snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES);
    let range = Range {
        start_byte,
        end_byte,
        start_line: line_idx,
        end_line: line_idx,
    };

    // Every hit is attributed to the declaration that encloses it. When the
    // analyzer holds no declaration around this range -- it refused the file
    // (`is_unparseable_source`), or the file is outside what it indexed -- the
    // reference is still a real occurrence in a real file, so it is attributed
    // to that file's own scope instead of being discarded. `CodeUnit::file_scope`
    // is the same unit `ParsedFile::add_file_scope` and the store's hydration
    // synthesize for every file the analyzer *did* index, so the value is stable
    // across scans and dedups against the indexed answer rather than competing
    // with it (#1785).
    let enclosing = ctx
        .analyzer
        .enclosing_code_unit(ctx.file, &range)
        .unwrap_or_else(|| CodeUnit::file_scope(ctx.file.clone()));

    Some(usage_hit(
        ctx.file, line_idx, start_byte, end_byte, enclosing, snippet,
    ))
}
