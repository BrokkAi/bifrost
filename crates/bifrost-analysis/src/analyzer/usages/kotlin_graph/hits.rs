//! Recording a Kotlin reference as a usage hit, and attributing it to a caller.
//!
//! Every hit carries the declaration that encloses it, because "who uses this?"
//! is only useful if the answer says *from where*. Attribution goes through
//! `IAnalyzer::enclosing_code_unit`, cached per byte range because a single
//! reference is asked about several times while it is being classified.
//!
//! [`push_hit`] records a *proven* reference: one whose identity the scan
//! established. Milestone 2 of issue #1239 adds the other two channels the
//! cross-language contract defines -- unproven hits, for a reference that might
//! name the target but could not be proven, and same-owner hits, for a proven
//! reference whose receiver is the current instance (#1014 facet B). A type
//! reference is always one or the other of proven and absent: a written type
//! either resolves to the target or does not, with no receiver to be unsure
//! about.

use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, usage_hit};
use crate::analyzer::usages::kotlin_graph::extractor::ScanCtx;
use crate::analyzer::{CodeUnit, Range};
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

/// The declaration a reference sits inside.
#[derive(Clone, Default)]
pub(super) struct EnclosingContext {
    pub(super) enclosing: Option<CodeUnit>,
}

pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    *ctx.raw_match_count += 1;
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    // A reference inside the target's own body is not a usage of it. Types are
    // exempt: a class naming itself (a factory returning its own type, a
    // self-referential parameter) is a real reference.
    if enclosing == ctx.spec.target && !ctx.spec.target.is_class() {
        return;
    }
    ctx.hits.insert(usage_hit(
        ctx.file,
        line_idx,
        start,
        node.end_byte(),
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

pub(super) fn push_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_import_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
}

/// The declaration enclosing `node`.
pub(super) fn enclosing_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> EnclosingContext {
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
    let resolved = EnclosingContext { enclosing };
    ctx.enclosing_cache.insert(key, resolved.clone());
    resolved
}
