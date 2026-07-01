use crate::analyzer::Range;
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::python_graph::extractor::ScanCtx;
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_line};
use tree_sitter::Node;

pub(super) fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit);
    }
}

/// Record `node` as an `Import`-binding hit (the token that brings the symbol
/// into this file), which the IDE find-references surface includes but the
/// call-graph surfaces ignore.
pub(super) fn record_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(hit) = build_hit(node, ctx) {
        ctx.hits.insert(hit.into_import());
    }
}

fn build_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> Option<crate::analyzer::usages::UsageHit> {
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

    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range)?;

    Some(usage_hit(
        ctx.file, line_idx, start_byte, end_byte, enclosing, snippet,
    ))
}
