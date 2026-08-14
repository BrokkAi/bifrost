//! The one place that turns a Go import path into a package identity in the
//! activated semantic-model overlay, and a package member into the overlay
//! symbol that proves it.
//!
//! `get_definition` (`usages::get_definition::go`) and semantic diagnostics
//! (`go::diagnostics`) must answer "which package is this, and does it publish
//! this member" identically. Two parallel implementations would agree only by
//! accident, so both consume this resolver: the import-path lookup, the
//! `Unique`-disposition rule, the `language == "go"` and public-visibility
//! filters, and the two-name member candidate shape all live here once.
//!
//! Every method reads retained overlay state. None of them starts dependency
//! discovery, runs the Go toolchain, or touches a module cache.

use crate::analyzer::GO_MODULE_SCOPE_SEGMENT;
use crate::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelOverlay, SemanticModelOverlayDisposition,
    SemanticModelSymbol, Visibility,
};
use brokk_bifrost_go::diagnostics::GoPackageSurface;

/// The activated overlay, read as a Go package index.
#[derive(Clone, Copy)]
pub(crate) struct GoOverlayPackages<'a> {
    overlay: Option<&'a SemanticModelOverlay>,
}

impl<'a> GoOverlayPackages<'a> {
    pub(crate) fn new(overlay: Option<&'a SemanticModelOverlay>) -> Self {
        Self { overlay }
    }

    /// The two qualified names an exact Go API pack can publish `member` of
    /// `import_path` under: the canonical `<path>.<Name>` a type carries, and
    /// the `<path>.<module scope>.<Name>` a package-scope function, variable,
    /// or constant carries.
    ///
    /// Both consumers must search the same pair, otherwise a definition could
    /// resolve a package function that a diagnostic then calls absent.
    pub(crate) fn member_candidates(import_path: &str, member: &str) -> [String; 2] {
        [
            format!("{import_path}.{member}"),
            format!("{import_path}.{GO_MODULE_SCOPE_SEGMENT}.{member}"),
        ]
    }

    /// The unique symbol the overlay publishes under `qualified_name`.
    ///
    /// A name that more than one activated pack claims is deliberately not
    /// unique: the overlay marks it `Conflict` and this returns `None`, so
    /// neither navigation nor a diagnostic picks an arbitrary winner.
    pub(crate) fn unique_symbol(&self, qualified_name: &str) -> Option<&'a SemanticModelSymbol> {
        let matched = self.overlay?.symbols_named(qualified_name);
        (matched.disposition == SemanticModelOverlayDisposition::Unique)
            .then(|| matched.records.first().copied())
            .flatten()
    }

    /// The unique symbol a Go reference may resolve to: one visible, public Go
    /// declaration. A name several packs publish, or one whose only records
    /// are unexported, resolves to nothing.
    pub(crate) fn visible_symbol(&self, qualified_name: &str) -> Option<&'a SemanticModelSymbol> {
        let matched = self.overlay?.symbols_named(qualified_name);
        let mut visible =
            matched.records.iter().copied().filter(|symbol| {
                symbol.language == "go" && symbol.visibility == Visibility::Public
            });
        let first = visible.next()?;
        visible.next().is_none().then_some(first)
    }

    /// The `package` clause name an exact API pack records for `import_path`.
    ///
    /// The Go producer emits one module-kind symbol named exactly the import
    /// path whose first alias is the package clause name, which is how an
    /// unaliased `import "example.com/m/postgres"` of `package pg` binds `pg`
    /// rather than `postgres`.
    pub(crate) fn declared_package_name(&self, import_path: &str) -> Option<String> {
        self.unique_symbol(import_path)?.aliases.first().cloned()
    }

    /// How completely the activated packs describe `import_path`.
    pub(crate) fn package_surface(&self, import_path: &str) -> GoPackageSurface {
        let Some(symbol) = self.unique_symbol(import_path) else {
            return GoPackageSurface::Unpublished;
        };
        match symbol.provenance.completeness {
            SemanticModelCompleteness::Complete => GoPackageSurface::Complete,
            SemanticModelCompleteness::Partial => GoPackageSurface::Partial,
        }
    }

    /// Whether the packs publish `member` as a visible, public declaration of
    /// `import_path`, searching both names a Go pack can publish it under.
    pub(crate) fn publishes_member(&self, import_path: &str, member: &str) -> bool {
        Self::member_candidates(import_path, member)
            .iter()
            .any(|candidate| self.visible_symbol(candidate).is_some())
    }
}
