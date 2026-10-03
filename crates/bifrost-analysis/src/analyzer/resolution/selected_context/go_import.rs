//! Selected Go import bindings use the source file's lexical choice and actual
//! import definition. Package names come from selected context, never paths.

use super::*;
use crate::analyzer::resolution::LoweredGoPackageImport;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGoPackageImportKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedGoImportBindingDescriptor {
    pub(super) source_fragment: BindingFragmentId,
    import: LoweredGoPackageImport,
    definition_node: BindingNodeId,
    lookup: SemanticId,
    completion: ResolutionCompletion,
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
        }
    }

    fn digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"bifrost-selected-go-import-binding:v1");
        hash.field("source", &self.source_fragment.as_bytes());
        hash.field("definition", &self.import.definition.as_bytes());
        hash.field("definition_node", &self.definition_node.as_bytes());
        hash.field("file_scope", &self.import.file_scope.as_bytes());
        hash.field("spelling_choice", &self.import.spelling_choice.as_bytes());
        hash.field("lookup", &self.lookup.as_bytes());
        hash.finish()
    }

    pub(crate) fn shared_identities(&self) -> [ResolutionSemanticIdentity; 1] {
        [ResolutionSemanticIdentity::Shared(
            self.lookup.shared_name_id().expect("shared Package lookup"),
        )]
    }

    pub(crate) fn compile(
        &self,
        identities: &SelectedContextIdentities,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Option<(CandidatePathIdentity, PartialPath)> {
        if cancellation.is_cancelled() || !session.scope_step() {
            return None;
        }
        Some((
            CandidatePathIdentity::new(self.source_fragment, identities.path(self.digest())),
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
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_import_authority_survives_context_extensions_and_cancels_atomically() {
        let fragment = BindingFragmentId::at_ordinal(1);
        let ordinal = SelectedResolutionMountOrdinal::new(1);
        let lookup = |candidate| Ok((candidate == fragment).then_some((ordinal, Language::Go)));
        let identities = SelectedContextIdentities::new();
        let cancellation = CancellationToken::new();
        let binding = SelectedGoImportBindingDescriptor::new(
            fragment,
            &LoweredGoPackageImport {
                definition: SemanticId::local(1, 3),
                source_site: ResolutionSiteId::new(7),
                file_scope: BindingNodeId::local(1, 2),
                spelling_choice: SemanticId::local(1, 4),
                start_byte: 10,
                end_byte: 20,
                kind: ResolutionGoPackageImportKind::Named,
            },
            BindingNodeId::local(1, 3),
            SemanticId::shared_name(super::super::super::SharedNameId::interned(17)),
            ResolutionCompletion::Complete,
        );
        let expected = binding.compile(&identities, &cancellation, &ResolutionSession::unbounded());
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
            imports[0].compile(&assigned, &cancellation, &ResolutionSession::unbounded()),
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
