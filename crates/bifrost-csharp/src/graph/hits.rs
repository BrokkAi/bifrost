use crate::graph::extractor::ScanCtx;
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::Range;
use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, external_usage_hit_count, insert_unproven_hit,
    reclassify_self_receiver_hit_at, usage_hit,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, snippet_around_line};
use tree_sitter::Node;

pub(super) fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    // A derivation that admitted a declaration of unproven membership does
    // not prove this site.
    if ctx.membership.doubt() > ctx.site_doubt {
        push_unproven_hit(node, ctx);
        return;
    }
    // A site binds the target's identity only where this file's compilation
    // sees a declaration of it; a member only an invisible or unproven copy
    // declares is not proven by a resolved owner name.
    let target = ctx.spec.target.clone();
    let visibility = *ctx.target_visibility.get_or_insert_with(|| {
        crate::graph_support::identity_visibility(
            ctx.membership.unscoped(),
            ctx.file,
            &target.fq_name(),
            Some(&target),
            |candidate| {
                candidate.kind() == target.kind() && candidate.signature() == target.signature()
            },
        )
    });
    match visibility {
        Some(crate::graph_support::CSharpCompilationVisibility::Visible) => {}
        Some(crate::graph_support::CSharpCompilationVisibility::NotVisible) => return,
        Some(crate::graph_support::CSharpCompilationVisibility::Unresolved) | None => {
            push_unproven_hit(node, ctx);
            return;
        }
    }
    let Some(hit) = node_hit(node, ctx) else {
        return;
    };
    // A reference whose enclosing declaration is a *callable* target is a
    // recursive call (#1638): recorded, then classified `SelfReceiver`, so
    // editor find-references lists it while the external usage surface omits
    // it. For any other target the site is the declaration itself, not a use
    // of it, and stays dropped.
    if hit.enclosing == ctx.spec.target && !ctx.spec.target.is_function() {
        return;
    }
    let recursive = hit.enclosing == ctx.spec.target;
    let start = hit.range.start_byte;
    let end = hit.range.end_byte;
    ctx.hits.insert(hit.usage_hit(ctx));
    if recursive {
        reclassify_self_receiver_hit_at(ctx.hits, ctx.file, start, end);
    }
    refresh_usage_limit(ctx);
}

/// Push `node` as a same-owner `this`/own-type receiver hit (#1014 facet B):
/// excluded from the external usage surface, counted as a same-owner site.
/// Records the ordinary hit, then reclassifies it — the shared scan consumer, so
/// the record ceremony (span, enclosing, cap, self-definition guard) lives in
/// exactly one place.
pub(super) fn push_self_receiver_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    push_hit(node, ctx);
    reclassify_self_receiver_hit_at(ctx.hits, ctx.file, node.start_byte(), node.end_byte());
    refresh_usage_limit(ctx);
}

fn refresh_usage_limit(ctx: &mut ScanCtx<'_>) {
    *ctx.limit_exceeded = external_usage_hit_count(ctx.hits) > ctx.max_usages;
}

pub(super) fn push_unproven_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(hit) = node_hit(node, ctx) else {
        return;
    };
    if hit.enclosing == ctx.spec.target {
        return;
    }
    insert_unproven_hit(ctx.unproven_hits, Some(hit.usage_hit(ctx)));
}

struct NodeHit {
    range: Range,
    enclosing: CodeUnit,
}

impl NodeHit {
    fn usage_hit(&self, ctx: &ScanCtx<'_>) -> UsageHit {
        let line_idx = self.range.start_line;
        usage_hit(
            ctx.file,
            line_idx,
            self.range.start_byte,
            self.range.end_byte,
            self.enclosing.clone(),
            snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
        )
    }
}

fn node_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> Option<NodeHit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let key = (node.start_byte(), node.end_byte());
    let enclosing = if let Some(cached) = ctx.enclosing_cache.get(&key) {
        cached.clone()
    } else {
        let enclosing = ctx.graph.index.enclosing_code_unit(ctx.file, &range);
        ctx.enclosing_cache.insert(key, enclosing.clone());
        enclosing
    }?;
    Some(NodeHit { range, enclosing })
}
