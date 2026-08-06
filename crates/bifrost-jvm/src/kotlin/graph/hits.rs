//! Recording a Kotlin reference as a usage hit, and attributing it to a caller.
//!
//! Every hit carries the declaration that encloses it, because "who uses this?"
//! is only useful if the answer says *from where*. Attribution goes through
//! `IAnalyzer::enclosing_code_unit`, cached per byte range because a single
//! reference is asked about several times while it is being classified.
//!
//! There are three channels, and keeping them apart is most of what "explicit"
//! means in this issue's acceptance criteria. [`push_hit`] records a *proven*
//! reference, one whose identity the scan established. [`push_unproven_hit`]
//! records a reference that might name the target but could not be proven.
//! [`push_self_receiver_hit`] records a proven reference whose receiver is the
//! current instance or the own type, which the cross-language contract of #1014
//! facet B excludes from the external usage surface.
//!
//! A *type* reference only ever lands in the first of the three: a written type
//! either resolves to the target or does not, with no receiver to be unsure
//! about. The other two exist for the callable and property arms.

use crate::kotlin::graph::extractor::ScanCtx;
use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, external_usage_hit_count, reclassify_import_hit_at,
    reclassify_override_declaration_hit_at, reclassify_self_receiver_hit_at, usage_hit,
};
use brokk_bifrost_core::analyzer::{CodeUnit, Range};
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

/// The declaration a reference sits inside.
#[derive(Clone, Default)]
pub struct EnclosingContext {
    pub enclosing: Option<CodeUnit>,
}

pub fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
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
    refresh_usage_limit(ctx);
}

pub fn push_import_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_import_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
    refresh_usage_limit(ctx);
}

/// Record a declaration that overrides the target as a reference to it.
pub fn push_override_declaration_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_override_declaration_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
}

/// Record `node` as a same-owner receiver hit (#1014 facet B): a reference whose
/// receiver is the current instance (`this`, implicit-`this`) or the own type
/// itself, as a companion access from inside the companion's class is.
///
/// It is recorded and *then* reclassified, so it is still counted and
/// inspectable as a same-owner site while being excluded from the external usage
/// surface. Without that exclusion every private helper called only from its own
/// class would look used. `super` is deliberately not routed here: a `super`
/// call names an ancestor's declaration from outside it.
pub fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_self_receiver_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
    refresh_usage_limit(ctx);
}

fn refresh_usage_limit(ctx: &mut ScanCtx<'_>) {
    *ctx.limit_exceeded = external_usage_hit_count(ctx.hits) > ctx.max_usages;
}

/// Record a reference that *might* name the target but could not be proven —
/// most often because the receiver's type could not be established.
///
/// This is the channel that keeps "we don't know" from collapsing into either
/// "yes" or "no". It is surfaced separately in the result and excluded from
/// proven-edge consumers, so a declaration reachable only through unproven
/// references reads as inconclusive rather than as confidently dead.
pub fn push_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let start = node.start_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.unproven_hits.insert(
        usage_hit(
            ctx.file,
            line_idx,
            start,
            node.end_byte(),
            enclosing,
            snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
        )
        .into_unproven(),
    );
}

/// The declaration enclosing `node`.
pub fn enclosing_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> EnclosingContext {
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
    let enclosing = ctx.graph.index.enclosing_code_unit(ctx.file, &range);
    let resolved = EnclosingContext { enclosing };
    ctx.enclosing_cache.insert(key, resolved.clone());
    resolved
}
