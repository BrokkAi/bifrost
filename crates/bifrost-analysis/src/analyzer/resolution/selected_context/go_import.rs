//! Selected Go import bindings use the source file's lexical choice and actual
//! import definition. An absent package clause admits only an explicitly presumed name.

use super::*;
use crate::analyzer::resolution::{LoweredGoPackageImport, UnindexedExternalFrontier};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGoPackageImportKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedGoImportBindingDescriptor {
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
    pub(crate) fn new(
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

    pub(crate) fn compile(
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

    #[test]
    fn selected_import_authority_survives_context_extensions_and_cancels_atomically() {
        let fragment = fixture_fragment("selected-go-import-source");
        let ordinal = SelectedResolutionMountOrdinal::new(fragment.ordinal());
        let lookup = |candidate| Ok((candidate == fragment).then_some((ordinal, Language::Go)));
        let identities = SelectedContextIdentities::new();
        let cancellation = CancellationToken::new();
        let binding = SelectedGoImportBindingDescriptor::new(
            fragment,
            &LoweredGoPackageImport {
                definition: semantic("selected-go-import-definition"),
                source_site: ResolutionSiteId::new(7),
                file_scope: node("selected-go-import-file-scope"),
                spelling_choice: semantic("selected-go-import-choice"),
                start_byte: 10,
                end_byte: 20,
                kind: ResolutionGoPackageImportKind::Named,
            },
            node("selected-go-import-definition-node"),
            SemanticId::shared_name(
                super::super::super::local_identity::test_shared_names().intern(
                    brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes(
                        b"bifrost-fixture-go-package-lookup:v1",
                        b"Package",
                    ),
                ),
            ),
            ResolutionCompletion::Complete,
        );
        let expected = binding
            .compile(
                &identities,
                &PreloadedFragmentSource::new([], []),
                &cancellation,
                &ResolutionSession::unbounded(),
            )
            .unwrap();
        let context = SelectedResolutionContextSet::new(identities.clone(), Vec::new(), 1, &lookup)
            .unwrap()
            .extend_go_import_bindings(vec![binding.clone()], &cancellation, &lookup)
            .unwrap()
            .unwrap();
        let root_bridge = SelectedRootBridgeDescriptor::for_test(
            fragment,
            Language::Go,
            ResolutionSiteId::new(7),
            ResolutionRootImportAnchor::Lexical,
            fragment,
            Language::Go,
            ResolutionScopeId::new(0),
            Vec::new(),
            ResolutionLookupSemanticRecipe::new(Language::Go, ResolutionNamespace::Type, "Item"),
            ResolutionLookupSemanticRecipe::new(Language::Go, ResolutionNamespace::Type, "Item"),
            ResolutionCompletion::Complete,
        );
        let extended = context
            .clone()
            .extend_root_bridges(vec![root_bridge], &cancellation, None, &lookup)
            .unwrap()
            .unwrap()
            .extend_package_bridges(Vec::new(), &cancellation, &lookup)
            .unwrap()
            .unwrap();
        let SelectedResolutionContextValidationOutcome::Ready(input) = extended
            .validate_exact_mounts(1, &lookup, &cancellation)
            .unwrap()
        else {
            panic!("live selected import context must validate");
        };
        let (_, _, _, _, assigned, _, imports) = input.into_parts();
        assert_eq!(imports.as_ref(), std::slice::from_ref(&binding));
        assert_eq!(
            imports[0]
                .compile(
                    &assigned,
                    &PreloadedFragmentSource::new([], []),
                    &cancellation,
                    &ResolutionSession::unbounded()
                )
                .unwrap(),
            expected
        );
        cancellation.cancel();
        assert!(
            context
                .extend_go_import_bindings(vec![binding], &cancellation, &lookup)
                .unwrap()
                .is_none()
        );
    }
}
