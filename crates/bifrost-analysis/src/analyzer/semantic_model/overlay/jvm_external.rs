//! Model declaration classification shared by selected JVM store queries.

impl crate::analyzer::store::resolution_operation::SelectedModelAuthority
    for crate::analyzer::semantic_model::SemanticModelOverlay
{
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
    let symbols = qualified_model_symbols(overlay, fqn);
    let mut types = symbols
        .into_iter()
        .filter(|symbol| pack_type_kind(symbol.kind).is_some());
    let first = types.next()?;
    if first.provenance.ambiguous
        || types.any(|symbol| {
            symbol.provenance.ambiguous
                || symbol.provenance.pack_digest != first.provenance.pack_digest
                || symbol.qualified_name != first.qualified_name
        })
    {
        return None;
    }
    Some(crate::analyzer::resolution::ExternalOwnerIdentity {
        provider_id: first.provenance.pack_digest.as_str().into(),
        owner_fqn: first.qualified_name.as_str().into(),
    })
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
