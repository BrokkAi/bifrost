use crate::analyzer::Range;
use crate::analyzer::usages::common::{reclassify_import_hit_at, usage_hit};
use crate::analyzer::usages::scala_graph::extractor::ScanCtx;
use crate::text_utils::find_line_index_for_offset;
use tree_sitter::Node;

const SNIPPET_CONTEXT_LINES: usize = 1;

pub(super) fn add_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let cache_key = (range.start_byte, range.end_byte);
    let enclosing = if let Some(cached) = ctx.enclosing_cache.get(&cache_key) {
        cached.clone()
    } else {
        let resolved = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
        ctx.enclosing_cache.insert(cache_key, resolved.clone());
        resolved
    };
    let Some(enclosing) = enclosing else {
        return;
    };
    if enclosing == ctx.spec.target
        && range_within_any(ctx.analyzer.ranges(&ctx.spec.target), &range)
    {
        return;
    }
    let line = find_line_index_for_offset(ctx.line_starts, range.start_byte) + 1;
    ctx.hits.insert(usage_hit(
        ctx.file,
        line - 1,
        range.start_byte,
        range.end_byte,
        enclosing,
        snippet_around(ctx.source, ctx.line_starts, line),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

pub(super) fn add_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    add_hit(node, ctx);
    reclassify_import_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
}

fn range_within_any(ranges: &[Range], needle: &Range) -> bool {
    ranges
        .iter()
        .any(|range| range.start_byte <= needle.start_byte && needle.end_byte <= range.end_byte)
}

fn snippet_around(source: &str, line_starts: &[usize], one_based_line: usize) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let zero_based = one_based_line.saturating_sub(1);
    let start_line = zero_based.saturating_sub(SNIPPET_CONTEXT_LINES.saturating_sub(1));
    let end_line = (zero_based + SNIPPET_CONTEXT_LINES).min(line_starts.len());
    let start = *line_starts.get(start_line).unwrap_or(&0);
    let end = line_starts
        .get(end_line)
        .copied()
        .unwrap_or(source.len())
        .min(source.len());
    source[start..end].trim().to_string()
}
