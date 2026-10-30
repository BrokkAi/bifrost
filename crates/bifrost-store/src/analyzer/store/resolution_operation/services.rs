//! Query-borrowed engine services used by selected resolution.

use std::sync::Arc;

use crate::analyzer::resolution::ExternalOwnerIdentity;
use crate::analyzer::resolution::registry_vocabulary::ModeledExternalPackageIdentity;
use crate::analyzer::semantic_model::TypeRef;
use crate::analyzer::semantic_model::overlay::{
    ModelOwnerAnswer, ModelProviderSelection, ModelSymbolRef, ModelTypeOwnerAnswer,
    SemanticModelOverlayBuildError, SemanticModelSymbol,
};
use crate::analyzer::store::active_models::ResolvedActiveSemanticModels;
use crate::analyzer::{CodeUnit, Language, ProjectFile};

pub trait SelectedAnalyzerServices: Send + Sync {
    fn declarations_named(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit>;
    fn external_inventory_providers(&self) -> Vec<String>;
    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>>;
    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>>;
}

pub trait SelectedModelAuthority {
    /// The activated set from which this authority was composed.
    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>>;

    /// Selected composed alias groups for an owner name or declaration ID.
    fn model_selected_groups(
        &self,
        language: &str,
        reference: &TypeRef,
        selection: &ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Vec<Vec<SemanticModelSymbol>>, SemanticModelOverlayBuildError>;

    /// The owner a nominal type reference names in the selected composition.
    fn model_type_owner(
        &self,
        language: &str,
        nominal: &TypeRef,
        selection: &ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<ModelTypeOwnerAnswer<SemanticModelSymbol>, SemanticModelOverlayBuildError>;

    /// SemanticModelOverlay is the single implementation of model member declarations.
    fn model_member_declarations(
        &self,
        owner: &ModelSymbolRef,
        selection: &ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Option<ModelOwnerAnswer>, SemanticModelOverlayBuildError>;
    /// SemanticModelOverlay is the single implementation of declared callable results.
    /// None is also returned for a selected callable without a structured
    /// signature, and for `returns: None` from a producer that does not
    /// conform to the returns contract (#7570); it does not mean the symbol
    /// is not a model callable.
    fn model_callable_results(
        &self,
        callable: &ModelSymbolRef,
        selection: &ModelProviderSelection,
        cancellation: &crate::CancellationToken,
    ) -> Result<Option<Vec<Option<TypeRef>>>, SemanticModelOverlayBuildError>;

    fn modeled_external_package_identity(
        &self,
        language: Language,
        import_path: &str,
    ) -> Option<ModeledExternalPackageIdentity>;
    fn declares_jvm_type(&self, fqn: &str) -> bool;
    fn declared_jvm_owner(&self, fqn: &str) -> Option<ExternalOwnerIdentity>;
    fn active_model_set_hash(&self) -> &str;
}

/// Selected declaration authority, before any intrinsic fallback. `None` is
/// absence; `Some(None)` is ambiguous authority and must stay open.
pub(in crate::analyzer::store) fn selected_jvm_declaration_owner(
    relations: &super::nominal_rules::ExternalOwnerRelations,
    connection: &rusqlite::Connection,
    authority: Option<&(dyn SelectedModelAuthority + Send + Sync)>,
    providers: &[String],
    fqn: &str,
) -> super::super::Result<Option<Option<ExternalOwnerIdentity>>> {
    use rusqlite::OptionalExtension;

    if let Some(authority) = authority {
        if let Some(owner) = authority.declared_jvm_owner(fqn) {
            return Ok(Some(Some(owner)));
        }
        if authority.declares_jvm_type(fqn) {
            return Ok(Some(None));
        }
    }
    if providers.is_empty() {
        return Ok(None);
    }
    let providers = serde_json::to_string(providers).expect("string provider identities serialize");
    // No aggregate row means absence; a NULL provider means ambiguity.
    let provider: Option<Option<String>> = connection
        .query_row(
            relations.declaration_owner,
            rusqlite::params![fqn, providers],
            |row| row.get(0),
        )
        .optional()?;
    Ok(provider.map(|provider| {
        provider.map(|provider| ExternalOwnerIdentity {
            provider_id: Arc::from(provider),
            owner_fqn: Arc::from(fqn),
        })
    }))
}
