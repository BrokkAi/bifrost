use crate::analyzer::Range;
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::cpp_graph::extractor::{EnclosingContext, ScanCtx};
use crate::analyzer::usages::cpp_graph::resolver::{
    TargetKind, precise_parent_of, same_logical_symbol, visible_owner_from_member_name,
};
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

pub(super) fn push_text_hit(start: usize, end: usize, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded || ctx.file == ctx.spec.target.source() {
        return;
    }
    if !is_code_text_range(ctx, start, end) {
        return;
    }
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    if is_out_of_line_member_definition_line(ctx, line_idx, start) {
        return;
    }
    if ctx
        .hits
        .iter()
        .any(|hit| hit.file == *ctx.file && hit.line == line_idx + 1)
    {
        return;
    }
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: line_idx,
        end_line: find_line_index_for_offset(ctx.line_starts, end),
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };
    if enclosing == ctx.spec.target || same_logical_symbol(&enclosing, &ctx.spec.target) {
        return;
    }
    ctx.hits.insert(usage_hit(
        ctx.file,
        line_idx,
        start,
        end,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

fn is_code_text_range(ctx: &ScanCtx<'_>, start: usize, end: usize) -> bool {
    let Some(node) = ctx.root.descendant_for_byte_range(start, end) else {
        return false;
    };
    let mut current = Some(node);
    while let Some(node) = current {
        if matches!(
            node.kind(),
            "comment"
                | "raw_string_literal"
                | "string_literal"
                | "char_literal"
                | "preproc_call"
                | "preproc_def"
                | "preproc_function_def"
                | "preproc_arg"
        ) || node.kind().starts_with("preproc_")
        {
            return false;
        }
        current = node.parent();
    }
    true
}

fn is_out_of_line_member_definition_line(ctx: &ScanCtx<'_>, line_idx: usize, start: usize) -> bool {
    if !matches!(ctx.spec.kind, TargetKind::MemberField | TargetKind::Method) {
        return false;
    }
    let Some(owner_name) = ctx.spec.owner_cpp_name.as_deref() else {
        return false;
    };
    let line_start = ctx.line_starts[line_idx];
    let line_end = ctx
        .line_starts
        .get(line_idx + 1)
        .copied()
        .unwrap_or(ctx.source.len());
    let line = ctx.source[line_start..line_end].trim();
    let qualified = format!("{owner_name}::{}", ctx.spec.member_name);
    let Some(prefix) = line.split_once(&qualified).map(|(prefix, _)| prefix) else {
        return false;
    };
    !line.starts_with(&qualified) && !prefix.contains('=') && start >= line_start
}
pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    if is_inside_target_declaration(node, ctx) || is_member_field_declaration_context(node, ctx) {
        return;
    }
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    if enclosing == ctx.spec.target || same_logical_symbol(&enclosing, &ctx.spec.target) {
        return;
    }
    ctx.hits.insert(usage_hit(
        ctx.file,
        line_idx,
        start,
        end,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

pub(super) fn enclosing_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> EnclosingContext {
    let key = (node.start_byte(), node.end_byte());
    if let Some(cached) = ctx.enclosing_cache.get(&key) {
        return cached.clone();
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    let owner = enclosing
        .as_ref()
        .and_then(|enclosing| precise_parent_of(ctx.analyzer, enclosing))
        .or_else(|| {
            enclosing
                .as_ref()
                .and_then(|enclosing| visible_owner_from_member_name(ctx, enclosing))
        });
    EnclosingContext { enclosing, owner }
}

fn is_inside_target_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.file != ctx.spec.target.source() {
        return false;
    }
    ctx.analyzer
        .ranges(&ctx.spec.target)
        .iter()
        .any(|range| node.start_byte() >= range.start_byte && node.end_byte() <= range.end_byte)
}

pub(super) fn is_member_field_declaration_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if !matches!(ctx.spec.kind, TargetKind::MemberField) {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "field_declaration" {
            return true;
        }
        if matches!(parent.kind(), "compound_statement" | "function_definition") {
            return false;
        }
        current = parent.parent();
    }
    false
}
