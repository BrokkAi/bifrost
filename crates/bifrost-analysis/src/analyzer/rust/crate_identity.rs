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
//! `rust::external`'s `apply_cargo_dependency_spellings` as an *alias* on every
//! fact of the renamed crate, and the overlay indexes aliases alongside
//! qualified names. So `use registry_alias::Widget` looks up
//! `registry_alias.Widget` and hits, with no rename table on this side. By the
//! same token two versions of one crate mint the same version-free declaration
//! id, which makes the overlay report `Conflict`; [`RustOverlayCrates::unique_symbol`]
//! answers `None` there rather than picking a winner.
//!
//! # Why the crate root gates every reference (#1795)
//!
//! A rename does not make the crate's own name a path this workspace can
//! write: once `widget` is renamed, Cargo and rustc both reject
//! `widget::Widget`. The pack nonetheless keeps that name on its facts,
//! because the rustdoc type paths it recorded are spelled with it -- a
//! signature naming `widget::Error`, a hierarchy target, an owner path.
//!
//! Those are two different roles for one string, and the producer separates
//! them at the crate root: it publishes the root module fact under exactly the
//! spellings the workspace can write, and leaves every inner fact under the
//! crate's own name. So a reference resolves here only when its leading
//! segment names a published crate root, which is the one place the two roles
//! can be told apart. A pack's own recorded paths keep resolving through
//! [`SemanticModelOverlay::symbols_named`]; a source reference spelling a
//! renamed-away crate root does not resolve at all, and the ladder above falls
//! through to the honest "this crate is not indexed" answer.
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
    fn visible_symbol(&self, qualified_name: &str) -> Option<&'a SemanticModelSymbol> {
        let symbol = self.unique_symbol(qualified_name)?;
        (symbol.language == "rust" && symbol.visibility == Visibility::Public).then_some(symbol)
    }

    /// Whether `symbol` is a crate root that `spelling` names.
    ///
    /// The overlay indexes a symbol under its terminal name as well as its
    /// qualified name, so a crate `widget` that contains a module
    /// `widget::widget` answers two records for the bare spelling `widget`.
    /// Only one of them is a crate root. Sharing a terminal name is therefore
    /// not enough: the spelling has to be what the pack publishes the module
    /// *as*, either its qualified name or an alias a rename added.
    fn names_crate_root(symbol: &SemanticModelSymbol, spelling: &str) -> bool {
        symbol.language == "rust"
            && symbol.kind == SemanticModelSymbolKind::Module
            && (symbol.qualified_name == spelling
                || symbol.aliases.iter().any(|alias| alias == spelling))
    }

    /// Whether the packs publish `root` as a crate root this workspace can
    /// write.
    ///
    /// This is the question [`Self::crate_surface`] asks before it grades a
    /// surface: a crate is reachable under exactly the spellings its pack
    /// publishes its root module under, which a Cargo rename replaces rather
    /// than extends. Several packs may answer -- two versions of one crate
    /// both publish a root -- and that does not make the spelling any less
    /// writable; [`Self::visible_symbol`] is where a name more than one pack
    /// claims stops resolving.
    fn publishes_crate_root(&self, root: &str) -> bool {
        self.overlay.is_some_and(|overlay| {
            overlay
                .symbols_named(root)
                .records
                .iter()
                .any(|symbol| Self::names_crate_root(symbol, root))
        })
    }

    /// The unique symbol a Rust *source reference* spelling `qualified_name`
    /// may resolve to.
    ///
    /// The leading dotted segment is the crate root the reference names.
    /// [`Self::pack_name`] mints these dotted names from the parser's
    /// structured path segments, so taking the leading one back off is that
    /// join's inverse; it happens here once, for every consumer, rather than
    /// in each of them.
    pub(crate) fn referenceable_symbol(
        &self,
        qualified_name: &str,
    ) -> Option<&'a SemanticModelSymbol> {
        let root = qualified_name.split('.').next()?;
        self.publishes_crate_root(root)
            .then(|| self.visible_symbol(qualified_name))
            .flatten()
    }

    /// How completely the activated packs describe `crate_name`.
    ///
    /// A crate's root module is published as a fact named exactly the spelling
    /// the workspace writes to reach it -- its own name, or the renamed one
    /// where Cargo renames it -- so this answers for the spelling the source
    /// used. A renamed-away name is unpublished as a crate root, which is what
    /// makes the ladder above report it unindexed rather than proving anything
    /// against it.
    pub(crate) fn crate_surface(&self, crate_name: &str) -> RustCrateSurface {
        let roots = self
            .overlay
            .map(|overlay| overlay.symbols_named(crate_name))
            .map(|matched| {
                matched
                    .records
                    .iter()
                    .filter(|symbol| Self::names_crate_root(symbol, crate_name))
                    .map(|symbol| symbol.provenance.completeness)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if roots.is_empty() {
            return RustCrateSurface::Unpublished;
        }
        // A grade claims something about one crate's whole API, so it has to be
        // the weakest claim any published root makes. Two versions of one crate
        // answer here together, and an item missing from the partial one is not
        // thereby missing from the crate.
        //
        // The rustdoc producer records a pack partial whenever it emitted any
        // diagnostic: a glob or cross-crate re-export it could not follow, a
        // blanket impl it could not project, or -- see `rust::external` -- a
        // feature set that is not the one Cargo resolves for this workspace.
        // Any of those means a miss against this surface is not proof.
        if roots.contains(&SemanticModelCompleteness::Partial) {
            return RustCrateSurface::Uncertain {
                detail: format!(
                    "the exact Cargo API pack for crate `{crate_name}` records an explicitly partial surface (an unfollowed re-export, an unprojected impl, or a feature set that is not the one the workspace resolves)"
                ),
            };
        }
        RustCrateSurface::Complete
    }

    /// Whether the packs publish the path `segments` spells as a visible,
    /// public Rust declaration this workspace can name.
    pub(crate) fn publishes_path(&self, segments: &[String]) -> bool {
        self.referenceable_symbol(&Self::pack_name(segments))
            .is_some()
    }

    /// Whether the packs publish `segments` as a module.
    ///
    /// Only a module's membership is enumerable from a rustdoc surface. A
    /// type's associated items are not: the producer skips blanket impls, and
    /// a trait bound or a `Deref` chain can supply a method that the type's
    /// own impls never mention, so a miss under a type owner is never proof.
    pub(crate) fn is_module_surface(&self, segments: &[String]) -> bool {
        self.referenceable_symbol(&Self::pack_name(segments))
            .is_some_and(|symbol| symbol.kind == SemanticModelSymbolKind::Module)
    }
}
