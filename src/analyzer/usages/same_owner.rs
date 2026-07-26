//! Shared same-owner (self/this receiver) classification policy (#1014 facet B,
//! #1138).
//!
//! A *same-owner* reference is a call or member access whose receiver denotes the
//! enclosing instance or the own type: an implicit-this / bare call, an explicit
//! `this`/`self`, or an own-type static call (`Owner.staticMethod()` from within
//! `Owner`, `self::m()` / `static::m()` in PHP). A `super`/`parent`/`base`
//! receiver, or a call through a differently-named variable — even one of the
//! same type — is *not* same-owner: it stays external.
//!
//! The policy spine is uniform across languages; only the per-language *proof*
//! ("does this receiver denote the enclosing instance / own type in this
//! context") differs, because the own-type-static rule and the receiver grammar
//! are language-specific. That one boolean feeds two shared consumers:
//!
//! * **scan consumer** —
//!   [`reclassify_self_receiver_hit_at`](super::common::reclassify_self_receiver_hit_at):
//!   record the ordinary hit, then reclassify it as a same-owner site so it is
//!   excluded from the external usage surface (`scan_usages`) but still counted
//!   and inspectable as a same-owner site.
//! * **inverted consumer** — [`route_same_owner`]: a same-owner reference is
//!   recorded as UNPROVEN inbound (a real structural reference whose externality
//!   could not be proven) rather than a proven caller→callee edge. A declaration
//!   reachable only through same-owner calls therefore reads INCONCLUSIVE for
//!   dead-code — never confidently dead, and never confidently alive from the
//!   self-edge alone — uniformly across languages, matching Rust. This routing is
//!   the #1138 alignment, expressed once here and reused by every builder.

/// Route an inverted-edge reference under the same-owner policy.
///
/// When the per-language proof holds (`is_same_owner`), `on_same_owner` runs —
/// by contract it records the reference as *unproven* inbound (never a proven
/// edge). Otherwise `on_external` runs the language's own proven-vs-unproven
/// resolution. The builder context `ctx` is threaded through both arms so each
/// can hold `&mut` builder state without the two closures both capturing it.
pub(super) fn route_same_owner<C>(
    ctx: &mut C,
    is_same_owner: bool,
    on_same_owner: impl FnOnce(&mut C),
    on_external: impl FnOnce(&mut C),
) {
    if is_same_owner {
        on_same_owner(ctx);
    } else {
        on_external(ctx);
    }
}
