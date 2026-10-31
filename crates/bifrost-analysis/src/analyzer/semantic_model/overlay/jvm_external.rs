//! Model declaration classification shared by selected JVM store queries.

impl crate::analyzer::store::resolution_operation::SelectedModelAuthority
    for crate::analyzer::semantic_model::SemanticModelOverlay
{
    fn model_declared_types_named(
        &self,
        language: &str,
        names: &[&str],
    ) -> Result<
        std::sync::Arc<std::collections::HashSet<(String, String)>>,
        super::SemanticModelOverlayBuildError,
    > {
        self.model_declared_types_named(language, names)
    }

    fn active_models(&self) -> Option<std::sync::Arc<super::ResolvedActiveSemanticModels>> {
        self.active_models.clone()
    }

    fn model_selected_groups(
        &self,
        language: &str,
        reference: &super::TypeRef,
        selection: &super::ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Vec<Vec<super::SemanticModelSymbol>>, super::SemanticModelOverlayBuildError> {
        self.model_selected_groups(language, reference, selection, cancellation)
    }

    fn model_type_owner(
        &self,
        language: &str,
        nominal: &super::TypeRef,
        selection: &super::ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<
        super::ModelTypeOwnerAnswer<super::SemanticModelSymbol>,
        super::SemanticModelOverlayBuildError,
    > {
        self.model_type_owner(language, nominal, selection, cancellation)
    }

    fn model_member_declarations(
        &self,
        owner: &super::ModelSymbolRef,
        selection: &super::ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Option<super::ModelOwnerAnswer>, super::SemanticModelOverlayBuildError> {
        self.model_member_declarations(owner, selection, cancellation)
    }

    fn model_callable_results(
        &self,
        callable: &super::ModelSymbolRef,
        selection: &super::ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Option<Vec<Option<super::TypeRef>>>, super::SemanticModelOverlayBuildError> {
        self.model_callable_results(callable, selection, cancellation)
    }

    fn modeled_external_package_identity(
        &self,
        language: crate::analyzer::Language,
        import_path: &str,
    ) -> Option<crate::analyzer::languages::ModeledExternalPackageIdentity> {
        crate::analyzer::languages::language_support_for_hook(
            language,
            "modeled_external_package_identity",
        )
        .expect("selected import mount language must have registered support")
        .modeled_external_package_identity(self, import_path)
    }

    fn declares_jvm_type(&self, fqn: &str) -> bool {
        model_declares_external_type(self, fqn)
    }

    fn declared_jvm_owner(
        &self,
        fqn: &str,
    ) -> Option<crate::analyzer::resolution::ExternalOwnerIdentity> {
        model_declared_external_owner(self, fqn)
    }

    fn active_model_set_hash(&self) -> &str {
        self.active_model_set_hash()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum JvmExternalTypeKind {
    Class,
    Interface,
    Enum,
    Annotation,
    Record,
}

/// Whether the reviewed packs in `overlay` declare the external type `fqn`.
#[doc(hidden)]
pub fn model_declares_external_type(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    fqn: &str,
) -> bool {
    qualified_model_symbols(overlay, fqn)
        .iter()
        .any(|symbol| pack_type_kind(symbol.kind).is_some())
}

/// One unambiguous model provider for a declared type, independently of
/// whether that provider has a complete durable owner inventory.
#[doc(hidden)]
pub fn model_declared_external_owner(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    fqn: &str,
) -> Option<crate::analyzer::resolution::ExternalOwnerIdentity> {
    // The unselected view folds same-id owners across providers; moving the JVM
    // onto the selected composition is #7605's change, with its own identity.
    let symbols = qualified_model_symbols(overlay, fqn);
    match super::classify_model_type_owner(symbols.iter().map(|symbol| &**symbol), |kind| {
        pack_type_kind(kind).is_some()
    }) {
        super::ModelTypeOwnerAnswer::Unique { declaration, .. } => {
            Some(crate::analyzer::resolution::ExternalOwnerIdentity {
                provider_id: declaration.provenance.pack_digest.as_str().into(),
                owner_fqn: declaration.qualified_name.as_str().into(),
            })
        }
        super::ModelTypeOwnerAnswer::Ambiguous(_) | super::ModelTypeOwnerAnswer::Unknown { .. } => {
            None
        }
    }
}

#[doc(hidden)]
pub fn qualified_model_symbols(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    fqn: &str,
) -> Vec<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelSymbol>> {
    overlay
        .symbols_named(fqn)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.qualified_name == fqn || symbol.aliases.iter().any(|alias| alias == fqn)
        })
        .collect()
}

/// The JVM type shape an overlay symbol kind denotes, or `None` when the
/// symbol is not a type a JVM reference can name.
///
/// The overlay keeps the pack's declared kind, so this is the inverse of the
/// [`semantic_type_kind`] mapping the artifact producers use, narrowed to the
/// kinds that exist on a classpath. Members, macros and namespace scaffolds
/// are not type names; a Kotlin `typealias` is a source-level alias with no
/// class of its own.
#[doc(hidden)]
pub fn pack_type_kind(
    kind: crate::analyzer::semantic_model::SemanticModelSymbolKind,
) -> Option<JvmExternalTypeKind> {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind as Kind;

    match kind {
        Kind::Class | Kind::Struct => Some(JvmExternalTypeKind::Class),
        Kind::Interface | Kind::Trait => Some(JvmExternalTypeKind::Interface),
        Kind::Enum => Some(JvmExternalTypeKind::Enum),
        Kind::Annotation => Some(JvmExternalTypeKind::Annotation),
        Kind::Record => Some(JvmExternalTypeKind::Record),
        Kind::Delegate
        | Kind::Union
        | Kind::Module
        | Kind::TypeAlias
        | Kind::Constructor
        | Kind::Method
        | Kind::Function
        | Kind::Field
        | Kind::Property
        | Kind::Constant
        | Kind::Static
        | Kind::Macro
        | Kind::Event => None,
    }
}
