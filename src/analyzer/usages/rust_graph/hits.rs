use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::rust_graph::extractor::ScanCtx;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_range};
use std::collections::BTreeSet;
use tree_sitter::Node;

pub(super) fn record_module_qualified_hits(root: Node<'_>, ctx: &mut ScanCtx<'_>) {
    record_module_qualified_hits_in(root, ctx);
}

fn record_module_qualified_hits_in(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
        record_scoped_identifier_hit(node, ctx);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        record_module_qualified_hits_in(child, ctx);
    }
}

fn record_scoped_identifier_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if node_text(name, ctx.source) != ctx.target_short {
        return;
    }
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    let path_text = node_text(path, ctx.source);
    if !ctx.namespace_names.contains(path_text) || ctx.shadowed_names.contains(path_text) {
        return;
    }

    let start = name.start_byte();
    let end = name.end_byte();
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

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
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
