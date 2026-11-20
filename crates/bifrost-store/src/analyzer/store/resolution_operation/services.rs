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

/// Exact selected input behind a deterministic canonical parser span. This
/// certificate covers the whole file, not a digest of the returned span.
#[derive(Debug)]
pub struct SelectedSourceFileCertificate<'a> {
    pub file: &'a ProjectFile,
    pub oid: git2::Oid,
    pub parse_variant: brokk_bifrost_core::gitblob::ParseVariant,
    pub producer_epoch: &'a str,
}

pub trait SelectedAnalyzerServices:
    brokk_bifrost_core::analyzer::memo_attribution::ReadReuseRefusal
{
    /// Retain a separate File dependency outside declaration-candidate capture
    /// replacement. False refuses authority and retained read reuse.
    fn certify_selected_source_file(&self, _expected: &SelectedSourceFileCertificate<'_>) -> bool {
        self.refuse_read_reuse();
        false
    }

    fn selected_read_recorder(
        &self,
    ) -> Option<super::super::selected_read::SelectedReadRecorder<'_>>;
    fn record_selected_dependency(
        &self,
        dependency: &super::super::selected_read::SelectedDependency,
    ) -> super::super::Result<()>;

    /// Report failure even when this analyzer cannot issue recorded receipts.
    fn selected_read_failed(&self, _error: &super::super::StoreError, _cancelled: bool) {
        self.refuse_read_reuse();
    }

    /// The recorded-read route for selected typed sources. Demand the existing
    /// registered derivation on this exact inventory; its engine records the
    /// canonical Lookup identity and replays captured reads on memo hits.
    /// A service unable to certify it must refuse retained receipt reuse.
    fn record_selected_derivation(
        &self,
        _inventory: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
        _kind: crate::analyzer::semantic::derivation::DerivationKindId,
        _question: &crate::analyzer::semantic::derivation::DerivationQuestion,
    ) {
        self.refuse_read_reuse();
    }

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

    /// Record the complete canonical selected metadata answer without opening
    /// another reader. None is a proven absent declaration, not empty metadata.
    fn record_selected_signature_metadata(
        &self,
        _declaration: &CodeUnit,
        _metadata: Option<&[brokk_bifrost_core::analyzer::model::SignatureMetadata]>,
    ) {
        self.refuse_read_reuse();
    }

    /// Record one canonical source observation through the ordinary ledger.
    fn record_selected_receiver_proof(
        &self,
        _question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        _answer: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer,
    ) {
        self.refuse_read_reuse();
    }

    fn capture_selected_receiver_proof(
        &self,
        read: &mut dyn FnMut() -> super::super::Result<()>,
    ) -> (
        super::super::Result<()>,
        Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    ) {
        self.refuse_read_reuse();
        (read(), None)
    }

    fn replay_selected_receiver_proof(
        &self,
        _receipt: &(dyn std::any::Any + Send + Sync),
    ) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        self.refuse_read_reuse();
        None
    }

    fn declarations_named(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit>;
    fn verified_declaration(&self, expected: &CodeUnit) -> Option<CodeUnit>;
    /// Inventory providers visible to this operation. `models` is the
    /// operation's own model authority set: it gates request-owned providers,
    /// so the services never consult their analyzer snapshot for it.
    fn external_inventory_providers(&self, models: &ResolvedActiveSemanticModels) -> Vec<String>;
    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>>;
    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>>;
    fn record_model_family_open(
        &self,
        _open: crate::analyzer::semantic_model::runtime::FamilyOpen,
    ) {
    }
    /// The selected operation read this source file. A consumer that cannot
    /// name the file must record an unattributed read instead, never reuse.
    fn record_source_read(&self, _file: &ProjectFile) {}
    fn record_model_authority_read(&self, _hash: &str) {}
    /// Record the canonical selected inventory answer in this operation's
    /// enclosing read frame. A service without attribution cannot authorize it.
    fn record_selected_rust_inventory(
        &self,
        _kind: crate::analyzer::read_ledger::LookupKind,
        _question: crate::analyzer::read_ledger::LookupQuestion,
        _digest: crate::analyzer::semantic::ids::StableDigest,
    ) -> bool {
        self.refuse_read_reuse();
        false
    }
    fn record_rust_macro_invocations(
        &self,
        _question: crate::analyzer::read_ledger::LookupQuestion,
        _digest: crate::analyzer::semantic::ids::StableDigest,
    ) {
    }
}

/// The store owns selected TEMP rows, while the engine owns read attribution.
/// Keep a preparation's receipt opaque until a later consumer replays it.
pub trait SelectedMacroFrontierReads: Send + Sync {
    fn capture(
        &self,
        active_model_set_hash: Option<&str>,
        prepare: &mut dyn FnMut() -> super::super::Result<super::SelectedResolutionStageOutcome>,
    ) -> (
        super::super::Result<super::SelectedResolutionStageOutcome>,
        Box<dyn std::any::Any + Send + Sync>,
    );

    fn replay(&self, receipt: &(dyn std::any::Any + Send + Sync));

    fn receipt_bytes(&self, receipt: &(dyn std::any::Any + Send + Sync)) -> usize;

    /// The front's own capture must be complete independently of its consumer.
    fn receipt_is_reusable(
        &self,
        receipt: &(dyn std::any::Any + Send + Sync),
        active_model_set_hash: Option<&str>,
    ) -> bool;

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
    generation: i64,
) -> super::super::Result<Option<Option<ExternalOwnerIdentity>>> {
    selected_jvm_declaration_owner_with_memo_proof(
        relations, connection, authority, providers, fqn, generation,
    )
    .map(super::super::jvm_external_publication::JvmInventoryMemoValue::into_value)
}

pub(in crate::analyzer::store) fn selected_jvm_declaration_owner_with_memo_proof(
    relations: &super::nominal_rules::ExternalOwnerRelations,
    connection: &rusqlite::Connection,
    authority: Option<&(dyn SelectedModelAuthority + Send + Sync)>,
    providers: &[String],
    fqn: &str,
    generation: i64,
) -> super::super::Result<
    super::super::jvm_external_publication::JvmInventoryMemoValue<
        Option<Option<ExternalOwnerIdentity>>,
    >,
> {
    use super::super::jvm_external_publication::{JvmInventoryMemoProof, JvmInventoryMemoValue};
    if let Some(authority) = authority {
        if let Some(owner) = authority.declared_jvm_owner(fqn) {
            return Ok(JvmInventoryMemoValue::new(
                Some(Some(owner)),
                JvmInventoryMemoProof::Immutable,
            ));
        }
        if authority.declares_jvm_type(fqn) {
            return Ok(JvmInventoryMemoValue::new(
                Some(None),
                JvmInventoryMemoProof::Immutable,
            ));
        }
    }
    if providers.is_empty() {
        return Ok(JvmInventoryMemoValue::new(
            None,
            JvmInventoryMemoProof::Immutable,
        ));
    }
    let providers = serde_json::to_string(providers).expect("string provider identities serialize");
    // Inventory drift is unavailable, distinct from competing selected owners.
    let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_memo_sql(
        relations.declaration_owner,
        3,
        2,
        4,
    );
    let (provider, present, current, sealed): (Option<String>, Option<i64>, bool, bool) =
        connection.query_row(
            &guarded,
            rusqlite::params![
                fqn,
                providers,
                generation,
                super::super::jvm_external_publication::jvm_external_projection_identity()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    if !current {
        return Err(super::super::StoreError::stale_resolution(
            "JVM provider inventory changed during the request",
        ));
    }
    let provider = present.map(|_| provider);
    Ok(JvmInventoryMemoValue::new(
        provider.map(|provider| {
            provider.map(|provider| ExternalOwnerIdentity {
                provider_id: Arc::from(provider),
                owner_fqn: Arc::from(fqn),
            })
        }),
        JvmInventoryMemoProof::from_sealed(sealed, generation),
    ))
}

/// Direct reader fixtures: services that record nothing, so every selected
/// read refuses reuse and answers as it would without a ledger.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[derive(Default)]
pub struct UnrecordedSelectedServices;

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_core::analyzer::memo_attribution::ReadReuseRefusal
    for UnrecordedSelectedServices
{
    fn refuse_read_reuse(&self) {}
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedAnalyzerServices for UnrecordedSelectedServices {
    fn selected_read_recorder(
        &self,
    ) -> Option<super::super::selected_read::SelectedReadRecorder<'_>> {
        None
    }
    fn record_selected_dependency(
        &self,
        _dependency: &super::super::selected_read::SelectedDependency,
    ) -> super::super::Result<()> {
        Ok(())
    }
    fn declarations_named(&self, _file: &ProjectFile, _name: &str) -> Vec<CodeUnit> {
        Vec::new()
    }
    fn verified_declaration(&self, _expected: &CodeUnit) -> Option<CodeUnit> {
        None
    }
    fn external_inventory_providers(&self, _models: &ResolvedActiveSemanticModels) -> Vec<String> {
        Vec::new()
    }
    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>> {
        None
    }
    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>> {
        None
    }
}
