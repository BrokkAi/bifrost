use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, usage_hit};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::rust_graph::extractor::ScanCtx;
use crate::analyzer::usages::rust_graph::resolve_rust_path_fqn;
use crate::analyzer::usages::rust_graph::resolver::resolve_rust_token_tree_paths;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_range};
use std::collections::BTreeSet;
use tree_sitter::Node;

pub(super) fn record_module_qualified_hits(root: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                record_scoped_identifier_hit(node, ctx)
            }
            "token_tree" => record_token_tree_qualified_hits(node, ctx),
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn record_token_tree_qualified_hits(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "use_declaration") {
        return;
    }
    for segment in
        resolve_rust_token_tree_paths(ctx.rust, ctx.support, ctx.refs, ctx.file, ctx.source, node)
    {
        if segment.fqn == ctx.target_fqn {
            record_target_segment(segment.node, ctx);
        }
    }
}

fn record_scoped_identifier_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "use_declaration") {
        return;
    }
    if ctx.target_is_module || ctx.target_is_path_qualifier {
        record_scoped_target_segment_hit(node, ctx);
        return;
    }

    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if resolve_rust_path_fqn(ctx.rust, ctx.refs, ctx.file, node_text(node, ctx.source)).as_deref()
        != Some(ctx.target_fqn)
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
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let path_text = node_text(path, ctx.source);
    if matches!(path.kind(), "identifier" | "type_identifier") {
        let resolved_root = resolve_rust_path_fqn(ctx.rust, ctx.refs, ctx.file, path_text);
        let direct_binding_matches = ctx.matches_identifier(path_text, path.start_byte())
            && !ctx.name_shadowed_at(path_text, path.start_byte());
        if resolved_root.as_deref() == Some(ctx.target_fqn) || direct_binding_matches {
            record_target_segment(path, ctx);
        }
    }
    if ctx.matches_qualified_name(node_text(node, ctx.source))
        && scoped_path_binding_visible(node, ctx)
    {
        record_target_segment(name, ctx);
        return;
    }
    if !scoped_node_resolves_to_target(node, ctx) {
        return;
    }

    record_target_segment(name, ctx);
}

fn scoped_path_binding_visible(mut node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    while matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
        let Some(path) = node.child_by_field_name("path") else {
            break;
        };
        node = path;
    }
    let root = node_text(node, ctx.source);
    !root.is_empty() && !ctx.name_shadowed_at(root, node.start_byte())
}

fn scoped_node_resolves_to_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    resolve_rust_path_fqn(ctx.rust, ctx.refs, ctx.file, node_text(node, ctx.source)).as_deref()
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
