use crate::analyzer::Range;
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::js_ts_graph::extractor::ScanCtx;
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_line};
use tree_sitter::Node;

pub(super) fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    if start_byte >= end_byte {
        return;
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

    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };

    ctx.hits.insert(usage_hit(
        ctx.file, line_idx, start_byte, end_byte, enclosing, snippet,
    ));
}
