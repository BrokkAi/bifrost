//! Query-borrowed engine services used by selected resolution.

use std::sync::Arc;

use crate::analyzer::resolution::ExternalOwnerIdentity;
use crate::analyzer::resolution::registry_vocabulary::ModeledExternalPackageIdentity;
use crate::analyzer::store::active_models::ResolvedActiveSemanticModels;
use crate::analyzer::{CodeUnit, Language, ProjectFile};

pub trait SelectedAnalyzerServices: Send + Sync {
    fn declarations_named(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit>;
    fn external_inventory_providers(&self) -> Vec<String>;
    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>>;
    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>>;
}

pub trait SelectedModelAuthority {
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
    let provider: Option<Option<String>> = connection.query_row(
        "SELECT CASE WHEN count(*)=1 THEN min(provider_id) END FROM main.jvm_external_owners WHERE owner_fqn=?1 AND provider_id IN (SELECT value FROM json_each(?2)) HAVING count(*)>0",
        rusqlite::params![fqn, providers], |row| row.get(0)).optional()?;
    Ok(provider.map(|provider| {
        provider.map(|provider| ExternalOwnerIdentity {
            provider_id: Arc::from(provider),
            owner_fqn: Arc::from(fqn),
        })
    }))
}
