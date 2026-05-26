use crate::analyzer::Range;
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::go_graph::extractor::ScanCtx;
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_range};
use tree_sitter::Node;

pub(super) fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let end = node.end_byte();
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(ctx.line_starts, start),
        end_line: find_line_index_for_offset(ctx.line_starts, end),
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.hits.insert(usage_hit(
        ctx.file,
        range.start_line,
        start,
        end,
        enclosing,
        trimmed_snippet_around_range(
            ctx.source,
            ctx.line_starts,
            start,
            end,
            SNIPPET_CONTEXT_LINES,
        ),
    ));
}
