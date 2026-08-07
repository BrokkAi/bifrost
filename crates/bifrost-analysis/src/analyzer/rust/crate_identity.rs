//! The one place that turns a Rust crate path into an identity in the
//! activated semantic-model overlay, and a crate item into the overlay symbol
//! that proves it.
//!
//! Semantic diagnostics (`rust::diagnostics`) and the resolution trace's
//! boundary oracle (`usages::get_definition::trace`) must answer "which crate
//! is this, and does it publish this item" identically. Two parallel
//! implementations would agree only by accident, so both consume this
//! resolver: the `Unique`-disposition rule, the `language == "rust"` and
//! public-visibility filters, and the `::`-to-dotted translation all live here
//! once.
//!
//! # Why a source spelling is the lookup key
//!
//! A Cargo dependency renamed with `package = "..."` is published by
//! `rust::external`'s `add_cargo_dependency_aliases` as an *alias* on every
//! fact of the renamed crate, and the overlay indexes aliases alongside
//! qualified names. So `use registry_alias::Widget` looks up
//! `registry_alias.Widget` and hits, with no rename table on this side. By the
//! same token two versions of one crate mint the same version-free declaration
//! id, which makes the overlay report `Conflict`; [`RustOverlayCrates::unique_symbol`]
//! answers `None` there rather than picking a winner.
//!
//! Every method reads retained overlay state. None of them starts dependency
//! discovery, runs `cargo` or `rustdoc`, or reads `target/doc`.

use crate::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelOverlay, SemanticModelOverlayDisposition,
    SemanticModelSymbol, SemanticModelSymbolKind, Visibility,
};
use brokk_bifrost_rust::diagnostics::RustCrateSurface;

/// The activated overlay, read as a Cargo crate index.
#[derive(Clone, Copy)]
pub(crate) struct RustOverlayCrates<'a> {
    overlay: Option<&'a SemanticModelOverlay>,
}

impl<'a> RustOverlayCrates<'a> {
    pub(crate) fn new(overlay: Option<&'a SemanticModelOverlay>) -> Self {
        Self { overlay }
    }

    /// The name a Cargo API pack publishes for the path `segments` spells.
    ///
    /// Rust source separates path segments with `::` and a rustdoc-derived pack
    /// records them dotted, so this join is the translation between the two.
    /// The segments arrive from the parser's structured path fields; nothing
    /// here re-splits source text.
    pub(crate) fn pack_name(segments: &[String]) -> String {
        segments.join(".")
    }

    /// The unique symbol the overlay publishes under `qualified_name`.
    ///
    /// A name more than one activated pack claims is deliberately not unique:
    /// the overlay marks it `Conflict` and this returns `None`, so neither the
    /// trace nor a diagnostic picks an arbitrary winner between, say, two
    /// versions of the same crate.
    pub(crate) fn unique_symbol(&self, qualified_name: &str) -> Option<&'a SemanticModelSymbol> {
        let matched = self.overlay?.symbols_named(qualified_name);
        (matched.disposition == SemanticModelOverlayDisposition::Unique)
            .then(|| matched.records.first().copied())
            .flatten()
    }

    /// The unique symbol a Rust reference may resolve to: one visible, public
    /// Rust declaration.
    pub(crate) fn visible_symbol(&self, qualified_name: &str) -> Option<&'a SemanticModelSymbol> {
        let symbol = self.unique_symbol(qualified_name)?;
        (symbol.language == "rust" && symbol.visibility == Visibility::Public).then_some(symbol)
    }

    /// How completely the activated packs describe `crate_name`.
    ///
    /// A crate's own root module is published as a fact named exactly the crate
    /// name, and a Cargo rename aliases that fact too, so this answers for the
    /// spelling the source used.
    pub(crate) fn crate_surface(&self, crate_name: &str) -> RustCrateSurface {
        let Some(symbol) = self.unique_symbol(crate_name) else {
            return RustCrateSurface::Unpublished;
        };
        match symbol.provenance.completeness {
            SemanticModelCompleteness::Complete => RustCrateSurface::Complete,
            // The rustdoc producer records a pack partial whenever it emitted
            // any diagnostic: a glob or cross-crate re-export it could not
            // follow, a blanket impl it could not project, or -- see
            // `rust::external` -- a feature set that is not the one Cargo
            // resolves for this workspace. Any of those means a miss against
            // this surface is not proof.
            SemanticModelCompleteness::Partial => RustCrateSurface::Uncertain {
                detail: format!(
                    "the exact Cargo API pack for crate `{crate_name}` records an explicitly partial surface (an unfollowed re-export, an unprojected impl, or a feature set that is not the one the workspace resolves)"
                ),
            },
        }
    }

    /// Whether the packs publish the path `segments` spells as a visible,
    /// public Rust declaration.
    pub(crate) fn publishes_path(&self, segments: &[String]) -> bool {
        self.visible_symbol(&Self::pack_name(segments)).is_some()
    }

    /// Whether the packs publish `segments` as a module.
    ///
    /// Only a module's membership is enumerable from a rustdoc surface. A
    /// type's associated items are not: the producer skips blanket impls, and
    /// a trait bound or a `Deref` chain can supply a method that the type's
    /// own impls never mention, so a miss under a type owner is never proof.
    pub(crate) fn is_module_surface(&self, segments: &[String]) -> bool {
        self.visible_symbol(&Self::pack_name(segments))
            .is_some_and(|symbol| symbol.kind == SemanticModelSymbolKind::Module)
    }
}
