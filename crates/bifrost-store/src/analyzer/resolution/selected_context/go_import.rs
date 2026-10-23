//! Selected Go import bindings use the source file's lexical choice and actual
//! import definition. An absent package clause admits only an explicitly presumed name.

use super::*;
use crate::analyzer::resolution::{LoweredGoPackageImport, UnindexedExternalFrontier};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGoPackageImportKind;

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedGoImportBindingDescriptor {
    pub(super) source_fragment: BindingFragmentId,
    import: LoweredGoPackageImport,
    definition_node: BindingNodeId,
    lookup: SemanticId,
    completion: ResolutionCompletion,
    /// Present only for an unresolved provider's conventional default binder.
    /// This does not verify the provider's package clause.
    presumed_provider: Option<UnindexedExternalFrontier>,
}

impl SelectedGoImportBindingDescriptor {
    /// The selected reader supplies the exact definition node and a Package
    /// lookup for the sealed explicit alias or canonical provider package name.
    /// Blank imports cannot create a lexical binding.
    #[doc(hidden)]
    pub fn new(
        source_fragment: BindingFragmentId,
        import: &LoweredGoPackageImport,
        definition_node: BindingNodeId,
        lookup: SemanticId,
        completion: ResolutionCompletion,
    ) -> Self {
        assert_eq!(import.kind, ResolutionGoPackageImportKind::Named);
        assert!(lookup.shared_name_id().is_some());
        assert_ne!(definition_node, BindingNodeId::universal_root());
        assert!(!completion.contains_reason(ResolutionIncompleteReason::Cancelled));
        Self {
            source_fragment,
            import: *import,
            definition_node,
            lookup,
            completion,
            presumed_provider: None,
        }
    }

    pub(crate) fn with_presumed_provider(
        mut self,
        path: Arc<str>,
        provider_package_id: Option<i64>,
    ) -> Self {
        self.presumed_provider = Some(UnindexedExternalFrontier {
            provider_path: path,
            provider_package_id,
            member: None,
        });
        self
    }

    pub(crate) fn validate_content_authority(
        &self,
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        self.digest(identities, source, cancellation)?;
        Ok(())
    }

    fn digest(
        &self,
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<[u8; 32]> {
        let mut hash =
            CanonicalIdentityDescriptor::new(b"bifrost-selected-go-import-binding:v1", |key| {
                super::super::canonical_identity::selected_identity_content_digest(
                    identities,
                    source,
                    key,
                    cancellation,
                )
            });
        hash.field(
            "source",
            CanonicalIdentityPart::identity(self.source_fragment),
        )?;
        hash.field(
            "definition",
            CanonicalIdentityPart::identity(self.import.definition),
        )?;
        hash.field(
            "definition_node",
            CanonicalIdentityPart::identity(self.definition_node),
        )?;
        hash.field(
            "file_scope",
            CanonicalIdentityPart::identity(self.import.file_scope),
        )?;
        hash.field(
            "spelling_choice",
            CanonicalIdentityPart::identity(self.import.spelling_choice),
        )?;
        hash.field("lookup", CanonicalIdentityPart::identity(self.lookup))?;
        if let Some(provider) = &self.presumed_provider {
            hash.field(
                "presumed_provider",
                CanonicalIdentityPart::Label(&provider.provider_path),
            )?;
            if let Some(package) = provider.provider_package_id {
                hash.field(
                    "presumed_provider_package",
                    CanonicalIdentityPart::Content(&package.to_le_bytes()),
                )?;
            }
        }
        Ok(hash.finish())
    }

    pub(super) fn remap_shared_names(
        &mut self,
        remap: &mut impl FnMut(SemanticId) -> StoreResult<SemanticId>,
    ) -> StoreResult<()> {
        self.lookup = remap(self.lookup)?;
        Ok(())
    }

    pub(crate) fn shared_identities(&self) -> [ResolutionSemanticIdentity; 1] {
        [ResolutionSemanticIdentity::Shared(
            self.lookup.shared_name_id().expect("shared Package lookup"),
        )]
    }

    #[doc(hidden)]
    pub fn compile(
        &self,
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> StoreResult<Option<(CandidatePathIdentity, PartialPath)>> {
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(None);
        }
        if let Some(provider) = &self.presumed_provider {
            identities.record_presumed_go_import(self.import.definition, provider.clone());
        }
        Ok(Some((
            CandidatePathIdentity::new(
                self.source_fragment,
                identities.path(self.digest(identities, source, cancellation)?),
            ),
            PartialPath::new(
                EndpointSignature::new(
                    self.import.file_scope,
                    StackPattern::closed([self.lookup]),
                    StackPattern::closed([]),
                ),
                EndpointSignature::new(
                    self.definition_node,
                    StackPattern::closed([]),
                    StackPattern::closed([]),
                ),
                [PrecedenceStep {
                    tier: PrecedenceTier::LexicalBinding,
                    ordinal: 0,
                    semantic: self.import.spelling_choice,
                }],
                [WitnessStep::Node(self.definition_node)],
                self.completion.clone(),
            ),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::engine::PreloadedFragmentSource;
    use crate::analyzer::resolution::test_support::{fragment as fixture_fragment, node, semantic};

    use super::*;
}
