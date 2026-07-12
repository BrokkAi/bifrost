use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, usage_hit};
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
    if ctx.target_is_module || ctx.target_is_class {
        record_scoped_target_segment_hit(node, ctx);
        return;
    }

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
    if !ctx.namespace_names.contains(path_text)
        || ctx.name_shadowed_at(path_text, path.start_byte())
    {
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

fn record_scoped_target_segment_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "use_declaration") {
        return;
    }
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let path_text = node_text(path, ctx.source);
    let name_text = node_text(name, ctx.source);
    if matches!(path.kind(), "identifier" | "type_identifier") {
        let resolved_root = ctx
            .refs
            .resolve_bare(path_text)
            .map(str::to_string)
            .or_else(|| ctx.rust.resolve_module_package(ctx.file, path_text));
        if resolved_root.as_deref() == Some(ctx.target_fqn) {
            record_target_segment(path, ctx);
        }
    }
    if !scoped_node_resolves_to_target(node, path_text, name_text, ctx) {
        return;
    }

    record_target_segment(name, ctx);
}

fn scoped_node_resolves_to_target(
    node: Node<'_>,
    path_text: &str,
    name_text: &str,
    ctx: &ScanCtx<'_>,
) -> bool {
    ctx.refs
        .resolve_scoped(path_text, name_text)
        .or_else(|| {
            ctx.rust
                .resolve_module_package(ctx.file, node_text(node, ctx.source))
        })
        .as_deref()
        == Some(ctx.target_fqn)
}

fn record_target_segment(segment: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = segment.start_byte();
    let end = segment.end_byte();
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

fn has_ancestor_kind(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
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

pub(super) fn record_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
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
    reclassify_import_hit_at(ctx.hits, ctx.file, start, end);
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
    push_member_hit_with_kind(
        file,
        source,
        line_starts,
        start,
        end,
        enclosing,
        hits,
        false,
    );
}

pub(super) fn push_unproven_member_hit(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    let start_line = find_line_index_for_offset(line_starts, start);
    hits.insert(
        usage_hit(
            file,
            start_line,
            start,
            end,
            enclosing,
            trimmed_snippet_around_range(source, line_starts, start, end, SNIPPET_CONTEXT_LINES),
        )
        .into_unproven(),
    );
}

pub(super) fn push_self_receiver_member_hit(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_member_hit_with_kind(file, source, line_starts, start, end, enclosing, hits, true);
}

#[allow(clippy::too_many_arguments)]
fn push_member_hit_with_kind(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    start: usize,
    end: usize,
    enclosing: CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
    self_receiver: bool,
) {
    let start_line = find_line_index_for_offset(line_starts, start);
    let hit = usage_hit(
        file,
        start_line,
        start,
        end,
        enclosing,
        trimmed_snippet_around_range(source, line_starts, start, end, SNIPPET_CONTEXT_LINES),
    );
    hits.insert(if self_receiver {
        hit.into_self_receiver()
    } else {
        hit
    });
}
