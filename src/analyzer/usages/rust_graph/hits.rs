use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::rust_graph::extractor::ScanCtx;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_range};
use regex::Regex;
use std::collections::BTreeSet;
use tree_sitter::Node;

pub(super) fn record_module_qualified_hits(ctx: &mut ScanCtx<'_>) {
    for name in ctx.namespace_names {
        if ctx.shadowed_names.contains(name) {
            continue;
        }
        let pattern = format!(
            r"\b{}\s*::\s*{}\b",
            regex::escape(name),
            regex::escape(ctx.target_short)
        );
        let Ok(re) = Regex::new(&pattern) else {
            continue;
        };
        for matched in re.find_iter(ctx.source) {
            let matched_text = matched.as_str();
            let Some(local_offset) = matched_text.rfind(ctx.target_short) else {
                continue;
            };
            let start = matched.start() + local_offset;
            let end = start + ctx.target_short.len();
            if let Some(enclosing) =
                member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
            {
                push_member_hit(
                    ctx.file,
                    ctx.source,
                    ctx.line_starts,
                    start,
                    end,
                    enclosing,
                    ctx.hits,
                );
            }
        }
    }
}

pub(super) fn record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let end = node.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

pub(super) fn member_hit_enclosing(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    line_starts: &[usize],
    start: usize,
    end: usize,
) -> Option<CodeUnit> {
    analyzer.enclosing_code_unit(
        file,
        &Range {
            start_byte: start,
            end_byte: end,
            start_line: find_line_index_for_offset(line_starts, start),
            end_line: find_line_index_for_offset(line_starts, end),
        },
    )
}

pub(super) fn push_member_hit(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    let start_line = find_line_index_for_offset(line_starts, start);
    hits.insert(usage_hit(
        file,
        start_line,
        start,
        end,
        enclosing,
        trimmed_snippet_around_range(source, line_starts, start, end, SNIPPET_CONTEXT_LINES),
    ));
}
