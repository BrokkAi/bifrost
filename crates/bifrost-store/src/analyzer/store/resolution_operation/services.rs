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

/// Query-local import proof consumed only by the language's existing authority.
#[derive(Debug)]
pub struct SelectedExternalBindingRequest<'a> {
    pub file: &'a ProjectFile,
    pub language: Language,
    pub snapshot: &'a super::super::WorkspaceSnapshotId,
    pub selected: &'a super::PythonSelectedExternalImport,
    pub path: &'a [String],
}

#[derive(Debug)]
pub enum SelectedExternalBindingRead {
    Admitted(Box<SemanticModelSymbol>),
    Refused { code: &'static str, detail: String },
    Cancelled,
}
impl SelectedExternalBindingRead {
    pub fn unavailable() -> Self {
        Self::Refused {
            code: "selected_external_binding_unavailable",
            detail: "the selected language has no external binding authority".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationCertificate {
    Certified,
    Uncertified,
}

pub trait SelectedAnalyzerServices:
    brokk_bifrost_core::analyzer::memo_attribution::ReadReuseRefusal
{
    fn certify_selected_configuration(
        &self,
        _language: Language,
        _snapshot: &super::super::WorkspaceSnapshotId,
        _input_identity: &[u8; 32],
        _connection: &rusqlite::Connection,
    ) -> ConfigurationCertificate {
        ConfigurationCertificate::Uncertified
    }

    fn admit_selected_external_binding(
        &self,
        _request: &SelectedExternalBindingRequest<'_>,
        _cancellation: &crate::CancellationToken,
    ) -> SelectedExternalBindingRead {
        SelectedExternalBindingRead::unavailable()
    }

    fn declarations_named(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit>;
    fn verified_declaration(&self, expected: &CodeUnit) -> Option<CodeUnit>;
    fn external_inventory_providers(&self) -> Vec<String>;
    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>>;
    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>>;
    fn record_model_authority_read(&self, _hash: &str) {}
}

/// The store owns selected TEMP rows, while the engine owns read attribution.
/// Keep a preparation's receipt opaque until a later consumer replays it.
pub trait SelectedMacroFrontierReads: Send + Sync {
    fn capture(
        &self,
        prepare: &mut dyn FnMut() -> super::super::Result<super::SelectedResolutionStageOutcome>,
    ) -> (
        super::super::Result<super::SelectedResolutionStageOutcome>,
        Box<dyn std::any::Any + Send + Sync>,
    );

    fn replay(&self, receipt: &(dyn std::any::Any + Send + Sync));

    fn receipt_bytes(&self, receipt: &(dyn std::any::Any + Send + Sync)) -> usize;

    fn policy_unit_label(&self) -> Option<String>;
}

#[derive(Debug)]
pub enum ModelRuntimeBases {
    Agreed(Vec<TypeRef>),
    Unproven,
    Cancelled,
}

pub trait SelectedModelAuthority {
    /// The agreed ordered Python runtime bases for a selected class owner.
    fn python_runtime_bases(
        &self,
        _qualified_name: &str,
        _symbol_id: &str,
        _cancellation: &crate::CancellationToken,
    ) -> ModelRuntimeBases {
        ModelRuntimeBases::Unproven
    }

    /// Active-set declarations matching the caller's fixed simple-name vocabulary.
    fn model_declared_types_named(
        &self,
        language: &str,
        names: &[&str],
    ) -> Result<
        std::sync::Arc<std::collections::HashSet<(String, String)>>,
        SemanticModelOverlayBuildError,
    >;

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
