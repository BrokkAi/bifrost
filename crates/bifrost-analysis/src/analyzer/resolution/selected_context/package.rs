//! Selected package membership connects protected source stacks. It cannot
//! produce an external import/export bridge or bypass lexical scope choices.

use super::*;
use crate::analyzer::resolution::{LoweredPackageMember, LoweredPackageReference};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedPackageBridgeDescriptor {
    pub(super) source_fragment: BindingFragmentId,
    pub(super) target_fragment: BindingFragmentId,
    source_language: Language,
    target_language: Language,
    source_token: SemanticId,
    target_token: SemanticId,
    source_domain: SemanticId,
    source_lookup: SemanticId,
    target_domain: SemanticId,
    target_lookup: SemanticId,
    target_definition: Option<BindingNodeId>,
    route_identity: [u8; 32],
    precedence: Option<PrecedenceStep>,
    candidate_origin_rank: Option<u32>,
    jvm_evidence: Option<SelectedJvmBridgeEvidence>,
    completion: ResolutionCompletion,
}

impl SelectedPackageBridgeDescriptor {
    pub(crate) fn with_candidate_origin_rank(mut self, rank: Option<u32>) -> Self {
        self.candidate_origin_rank = rank;
        self
    }

    pub(super) fn matches_qualified_reference(
        &self,
        source_fragment: BindingFragmentId,
        source_token: SemanticId,
        source_lookups: &[SemanticId],
    ) -> bool {
        self.source_fragment == source_fragment
            && self.source_token == source_token
            && source_lookups.contains(&self.source_lookup)
    }

    pub(crate) fn qualified_root_reference_bridge(
        &self,
        source_token: SemanticId,
        anchor: ResolutionRootImportAnchor,
        anchor_semantic: SemanticId,
        route: &[ResolutionLookupSemanticRecipe],
        source_demand: &ResolutionLookupSemanticRecipe,
    ) -> Option<SelectedRootBridgeDescriptor> {
        let target_definition = self.target_definition?;
        assert_eq!(
            source_demand.identity_domain(),
            language_identity_domain(self.source_language)
        );
        if let Some(evidence) = self.jvm_evidence {
            assert_eq!(source_demand.namespace(), evidence.source_namespace);
        }
        let target_demand = ResolutionLookupSemanticRecipe::new(
            self.target_language,
            source_demand.namespace(),
            source_demand.spelling(),
        );
        let bridge = if let Some(evidence) = self.jvm_evidence {
            SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
                self.source_fragment,
                self.source_language,
                source_token,
                anchor,
                anchor_semantic,
                self.target_fragment,
                self.target_language,
                self.target_token,
                None,
                route.to_vec(),
                source_demand.clone(),
                target_demand,
                evidence,
                self.completion.clone(),
            )
        } else {
            SelectedRootBridgeDescriptor::from_selected_path_tokens(
                self.source_fragment,
                self.source_language,
                source_token,
                anchor,
                anchor_semantic,
                self.target_fragment,
                self.target_language,
                self.target_token,
                route.to_vec(),
                source_demand.clone(),
                target_demand,
                self.completion.clone(),
            )
        };
        Some(
            bridge
                .with_precedence(self.precedence)
                .with_selected_member_definition(target_definition),
        )
    }

    /// Both metadata rows must come from the operation's selected catalogs.
    /// Package identity and visibility are established by the language's SQL
    /// context reader before this constructor is called.
    pub(crate) fn new(
        source_fragment: BindingFragmentId,
        target_fragment: BindingFragmentId,
        language: Language,
        reference: &LoweredPackageReference,
        member: &LoweredPackageMember,
        completion: ResolutionCompletion,
    ) -> Self {
        assert_eq!(reference.domain, member.domain);
        assert_eq!(reference.lookup, member.lookup);
        assert_eq!(reference.namespace, member.namespace);
        assert!(reference.domain.shared_name_id().is_some());
        assert!(reference.lookup.shared_name_id().is_some());
        assert_ne!(language, Language::None);
        assert!(!completion.contains_reason(ResolutionIncompleteReason::Cancelled));
        Self {
            source_fragment,
            target_fragment,
            source_language: language,
            target_language: language,
            source_token: reference.token,
            target_token: member.token,
            source_domain: reference.domain,
            source_lookup: reference.lookup,
            target_domain: member.domain,
            target_lookup: member.lookup,
            target_definition: None,
            route_identity: [0; 32],
            precedence: None,
            candidate_origin_rank: None,
            jvm_evidence: None,
            completion,
        }
    }

    /// Connect package identities from distinct selected JVM languages only
    /// after the store reader has proved the structured package relation,
    /// exact target and source-root/dependency authority.
    /// The endpoint identities and bridge proof remain separate inputs so the
    /// constructor can validate each against its selected row.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_jvm(
        source_fragment: BindingFragmentId,
        target_fragment: BindingFragmentId,
        source_language: Language,
        target_language: Language,
        reference: &LoweredPackageReference,
        member: &LoweredPackageMember,
        evidence: SelectedJvmBridgeEvidence,
        completion: ResolutionCompletion,
    ) -> Self {
        assert!(matches!(
            source_language,
            Language::Java | Language::Kotlin | Language::Scala
        ));
        assert!(matches!(
            target_language,
            Language::Java | Language::Kotlin | Language::Scala
        ));
        assert_ne!(source_language, target_language);
        assert_eq!(reference.namespace, evidence.source_namespace);
        assert_eq!(member.namespace, evidence.target_namespace);
        assert_eq!(evidence.source_namespace, evidence.target_namespace);
        assert_eq!(member.definition, evidence.target_declaration);
        match evidence.provenance {
            SelectedJvmBridgeProvenance::StructuredPackageType {
                source_package,
                target_package,
            } => {
                assert_eq!(source_package, reference.domain);
                assert_eq!(target_package, member.domain);
            }
            SelectedJvmBridgeProvenance::AliasFact { .. } => {
                panic!("selected package bridge requires structured package identity")
            }
        }
        assert!(reference.domain.shared_name_id().is_some());
        assert!(reference.lookup.shared_name_id().is_some());
        assert!(member.domain.shared_name_id().is_some());
        assert!(member.lookup.shared_name_id().is_some());
        assert!(!completion.contains_reason(ResolutionIncompleteReason::Cancelled));
        if evidence.visibility == SelectedJvmBridgeVisibility::Open {
            assert!(matches!(&completion, ResolutionCompletion::Incomplete(_)));
        }
        Self {
            source_fragment,
            target_fragment,
            source_language,
            target_language,
            source_token: reference.token,
            target_token: member.token,
            source_domain: reference.domain,
            source_lookup: reference.lookup,
            target_domain: member.domain,
            target_lookup: member.lookup,
            target_definition: None,
            route_identity: [0; 32],
            precedence: None,
            candidate_origin_rank: None,
            jvm_evidence: Some(evidence),
            completion,
        }
    }

    /// Connect one selected import selector to a selected package member.
    /// The caller proves the package route and selector row before invoking
    /// this constructor; cross-language routes additionally carry the exact
    /// JVM target and visibility evidence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_jvm_import(
        source_fragment: BindingFragmentId,
        target_fragment: BindingFragmentId,
        source_language: Language,
        target_language: Language,
        reference: &LoweredPackageReference,
        member: &LoweredPackageMember,
        source_lookup: &ResolutionLookupSemanticRecipe,
        target_lookup: &ResolutionLookupSemanticRecipe,
        target_definition: BindingNodeId,
        route_identity: [u8; 32],
        precedence: Option<PrecedenceStep>,
        names: &dyn SharedNameInterner,
        evidence: Option<SelectedJvmBridgeEvidence>,
        completion: ResolutionCompletion,
    ) -> Self {
        assert!(matches!(
            source_language,
            Language::Java | Language::Kotlin | Language::Scala
        ));
        assert!(matches!(
            target_language,
            Language::Java | Language::Kotlin | Language::Scala
        ));
        assert_eq!(
            source_lookup.identity_domain(),
            language_identity_domain(source_language)
        );
        assert_eq!(
            target_lookup.identity_domain(),
            language_identity_domain(target_language)
        );
        assert_eq!(source_lookup.namespace(), target_lookup.namespace());
        assert_eq!(source_lookup.namespace(), reference.namespace);
        assert_eq!(target_lookup.namespace(), member.namespace);
        assert_eq!(source_lookup.spelling(), target_lookup.spelling());
        assert_eq!(reference.lookup, source_lookup.semantic(names));
        assert_eq!(member.lookup, target_lookup.semantic(names));
        if let Some(step) = precedence {
            assert_eq!(source_language, Language::Kotlin);
            assert_eq!(
                step.semantic,
                reference
                    .choice
                    .expect("selected Kotlin package choice is persisted")
            );
            assert_eq!(step.ordinal, 0);
            assert!(matches!(
                step.tier,
                PrecedenceTier::PackageOrModule | PrecedenceTier::DefaultImport
            ));
        }
        assert_eq!(
            source_language == target_language,
            evidence.is_none(),
            "a cross-language JVM import requires explicit bridge evidence"
        );
        assert!(reference.domain.shared_name_id().is_some());
        assert!(member.domain.shared_name_id().is_some());
        assert!(!completion.contains_reason(ResolutionIncompleteReason::Cancelled));
        if let Some(evidence) = evidence {
            assert_ne!(source_language, target_language);
            assert_eq!(evidence.source_namespace, source_lookup.namespace());
            assert_eq!(evidence.target_namespace, target_lookup.namespace());
            assert_eq!(evidence.target_declaration, member.definition);
            assert_eq!(evidence.target_definition, target_definition);
            assert_eq!(
                evidence.provenance,
                SelectedJvmBridgeProvenance::StructuredPackageType {
                    source_package: reference.domain,
                    target_package: member.domain,
                }
            );
            if evidence.visibility == SelectedJvmBridgeVisibility::Open {
                assert!(matches!(&completion, ResolutionCompletion::Incomplete(_)));
            }
        } else {
            assert_eq!(source_language, target_language);
            assert_eq!(reference.domain, member.domain);
        }
        Self {
            source_fragment,
            target_fragment,
            source_language,
            target_language,
            source_token: reference.token,
            target_token: member.token,
            source_domain: reference.domain,
            source_lookup: source_lookup.semantic(names),
            target_domain: member.domain,
            target_lookup: target_lookup.semantic(names),
            target_definition: Some(target_definition),
            route_identity,
            precedence,
            candidate_origin_rank: None,
            jvm_evidence: evidence,
            completion,
        }
    }

    /// Direct selected route to a member reached through an imported JVM
    /// singleton such as Scala's `Predef`. The relation is admitted only for
    /// one exact selected declaration and its typed owner route.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_jvm_selected_definition_import(
        source_fragment: BindingFragmentId,
        target_fragment: BindingFragmentId,
        source_language: Language,
        target_language: Language,
        reference: &LoweredPackageReference,
        source_lookup: &ResolutionLookupSemanticRecipe,
        target_declaration: SemanticId,
        target_definition: BindingNodeId,
        target_domain: SemanticId,
        target_lookup: &ResolutionLookupSemanticRecipe,
        route_identity: [u8; 32],
        names: &dyn SharedNameInterner,
        evidence: Option<SelectedJvmBridgeEvidence>,
        completion: ResolutionCompletion,
    ) -> Self {
        assert!(matches!(
            source_language,
            Language::Java | Language::Kotlin | Language::Scala
        ));
        assert!(matches!(
            target_language,
            Language::Java | Language::Kotlin | Language::Scala
        ));
        assert_eq!(
            source_lookup.identity_domain(),
            language_identity_domain(source_language)
        );
        assert_eq!(
            target_lookup.identity_domain(),
            language_identity_domain(target_language)
        );
        assert_eq!(source_lookup.namespace(), target_lookup.namespace());
        assert_eq!(source_lookup.namespace(), reference.namespace);
        assert_eq!(reference.lookup, source_lookup.semantic(names));
        assert_eq!(
            source_language == target_language,
            evidence.is_none(),
            "a cross-language singleton import requires explicit JVM evidence"
        );
        assert!(reference.domain.shared_name_id().is_some());
        assert!(target_domain.shared_name_id().is_some());
        assert!(!completion.contains_reason(ResolutionIncompleteReason::Cancelled));
        if let Some(evidence) = evidence {
            assert_eq!(evidence.source_namespace, source_lookup.namespace());
            assert_eq!(evidence.target_namespace, target_lookup.namespace());
            assert_eq!(evidence.target_declaration, target_declaration);
            assert_eq!(evidence.target_definition, target_definition);
            assert_eq!(
                evidence.provenance,
                SelectedJvmBridgeProvenance::StructuredPackageType {
                    source_package: reference.domain,
                    target_package: target_domain,
                }
            );
            if evidence.visibility == SelectedJvmBridgeVisibility::Open {
                assert!(matches!(&completion, ResolutionCompletion::Incomplete(_)));
            }
        } else {
            assert_eq!(reference.domain, target_domain);
        }
        Self {
            source_fragment,
            target_fragment,
            source_language,
            target_language,
            source_token: reference.token,
            target_token: target_declaration,
            source_domain: reference.domain,
            source_lookup: source_lookup.semantic(names),
            target_domain,
            target_lookup: target_lookup.semantic(names),
            target_definition: Some(target_definition),
            route_identity,
            precedence: None,
            candidate_origin_rank: None,
            jvm_evidence: evidence,
            completion,
        }
    }

    fn digest(
        &self,
        domain: &[u8],
        identities: &SelectedContextIdentities,
        source: &dyn BatchResolutionFragmentSource,
        cancellation: &CancellationToken,
    ) -> StoreResult<[u8; 32]> {
        let mut hash = CanonicalIdentityDescriptor::new(domain, |key| {
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
            "target",
            CanonicalIdentityPart::identity(self.target_fragment),
        )?;
        hash.field(
            "source_language",
            CanonicalIdentityPart::Label(self.source_language.config_label()),
        )?;
        hash.field(
            "target_language",
            CanonicalIdentityPart::Label(self.target_language.config_label()),
        )?;
        hash.field(
            "source_token",
            CanonicalIdentityPart::identity(self.source_token),
        )?;
        hash.field(
            "target_token",
            CanonicalIdentityPart::identity(self.target_token),
        )?;
        hash.field(
            "source_domain",
            CanonicalIdentityPart::identity(self.source_domain),
        )?;
        hash.field(
            "source_lookup",
            CanonicalIdentityPart::identity(self.source_lookup),
        )?;
        hash.field(
            "target_domain",
            CanonicalIdentityPart::identity(self.target_domain),
        )?;
        hash.field(
            "target_lookup",
            CanonicalIdentityPart::identity(self.target_lookup),
        )?;
        hash.field(
            "route_identity",
            CanonicalIdentityPart::Content(&self.route_identity),
        )?;
        if let Some(step) = self.precedence {
            hash.field(
                "precedence_tier",
                CanonicalIdentityPart::Label(step.tier.label()),
            )?;
            hash.field(
                "precedence_ordinal",
                CanonicalIdentityPart::Content(&step.ordinal.to_le_bytes()),
            )?;
            hash.field(
                "precedence_choice",
                CanonicalIdentityPart::identity(step.semantic),
            )?;
        }
        if let Some(rank) = self.candidate_origin_rank {
            hash.field(
                "candidate_origin_rank",
                CanonicalIdentityPart::Content(&rank.to_le_bytes()),
            )?;
        }
        if let Some(definition) = self.target_definition {
            hash.field(
                "target_definition",
                CanonicalIdentityPart::identity(definition),
            )?;
        }
        if let Some(evidence) = self.jvm_evidence {
            hash.field(
                "dependency_identity",
                CanonicalIdentityPart::Content(&evidence.dependency_identity),
            )?;
            hash.field(
                "target_declaration",
                CanonicalIdentityPart::identity(evidence.target_declaration),
            )?;
            hash.field(
                "target_definition",
                CanonicalIdentityPart::identity(evidence.target_definition),
            )?;
            hash.field(
                "source_namespace",
                CanonicalIdentityPart::Label(evidence.source_namespace.identity_label()),
            )?;
            hash.field(
                "target_namespace",
                CanonicalIdentityPart::Label(evidence.target_namespace.identity_label()),
            )?;
            hash.field(
                "visibility",
                CanonicalIdentityPart::Content(match evidence.visibility {
                    SelectedJvmBridgeVisibility::Public => b"public".as_slice(),
                    SelectedJvmBridgeVisibility::Protected => b"protected".as_slice(),
                    SelectedJvmBridgeVisibility::Package => b"package".as_slice(),
                    SelectedJvmBridgeVisibility::Open => b"open".as_slice(),
                }),
            )?;
            match evidence.provenance {
                SelectedJvmBridgeProvenance::StructuredPackageType {
                    source_package,
                    target_package,
                } => {
                    hash.field(
                        "provenance",
                        CanonicalIdentityPart::Content(b"structured_package_type"),
                    )?;
                    hash.field(
                        "source_package",
                        CanonicalIdentityPart::identity(source_package),
                    )?;
                    hash.field(
                        "target_package",
                        CanonicalIdentityPart::identity(target_package),
                    )?;
                }
                SelectedJvmBridgeProvenance::AliasFact { alias } => {
                    hash.field("provenance", CanonicalIdentityPart::Content(b"alias_fact"))?;
                    hash.field("alias", CanonicalIdentityPart::identity(alias))?;
                }
            }
        }
        Ok(hash.finish())
    }

    pub(crate) const fn source_language(&self) -> Language {
        self.source_language
    }

    pub(crate) const fn target_language(&self) -> Language {
        self.target_language
    }

    pub(super) fn remap_shared_names(
        &mut self,
        remap: &mut impl FnMut(SemanticId) -> StoreResult<SemanticId>,
    ) -> StoreResult<()> {
        self.source_domain = remap(self.source_domain)?;
        self.source_lookup = remap(self.source_lookup)?;
        self.target_domain = remap(self.target_domain)?;
        self.target_lookup = remap(self.target_lookup)?;
        Ok(())
    }

    pub(crate) fn shared_identities(&self) -> [ResolutionSemanticIdentity; 4] {
        [
            self.source_domain,
            self.source_lookup,
            self.target_domain,
            self.target_lookup,
        ]
        .map(|semantic| {
            ResolutionSemanticIdentity::Shared(
                semantic.shared_name_id().expect("shared package symbol"),
            )
        })
    }

    /// The bridge changes only the protected stack. Source paths own lexical
    /// precedence, namespace admission, target identity and omitted-binder gaps.
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
        let path = identities.path(self.digest(
            b"bifrost-selected-package-path:v1",
            identities,
            source,
            cancellation,
        )?);
        let tail = identities.stack_variable(self.digest(
            b"bifrost-selected-package-tail:v1",
            identities,
            source,
            cancellation,
        )?);
        let root = BindingNodeId::universal_root();
        let (end_node, export, witness) = if let Some(definition) = self.target_definition {
            (definition, Vec::new(), vec![WitnessStep::Node(definition)])
        } else {
            (
                BindingNodeId::universal_root(),
                vec![self.target_lookup, self.target_domain, self.target_token],
                Vec::new(),
            )
        };
        let mut precedence = self.precedence.into_iter().collect::<Vec<_>>();
        if let Some(rank) = self.candidate_origin_rank {
            precedence.push(PrecedenceStep {
                tier: PrecedenceTier::CandidateOriginRank,
                ordinal: rank,
                semantic: self
                    .precedence
                    .map_or(self.source_token, |step| step.semantic),
            });
        }
        Ok(Some((
            CandidatePathIdentity::new(self.source_fragment, path),
            PartialPath::new(
                EndpointSignature::new(
                    root,
                    StackPattern::open(
                        [self.source_domain, self.source_token, self.source_lookup],
                        tail,
                    ),
                    StackPattern::closed([]),
                ),
                EndpointSignature::new(
                    end_node,
                    StackPattern::open(export, tail),
                    StackPattern::closed([]),
                ),
                precedence,
                witness,
                self.completion.clone(),
            ),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::engine::PreloadedFragmentSource;

    use super::*;

    #[test]
    fn selected_kotlin_default_bridge_emits_its_default_import_tier() {
        let step = PrecedenceStep {
            tier: PrecedenceTier::DefaultImport,
            ordinal: 0,
            semantic: SemanticId::for_test(b"kotlin-default-import-choice"),
        };
        let bridge = SelectedPackageBridgeDescriptor {
            source_fragment: BindingFragmentId::for_test(b"kotlin-import-source"),
            target_fragment: BindingFragmentId::for_test(b"kotlin-import-target"),
            source_language: Language::Kotlin,
            target_language: Language::Kotlin,
            source_token: SemanticId::for_test(b"kotlin-source-token"),
            target_token: SemanticId::for_test(b"kotlin-target-token"),
            source_domain: SemanticId::for_test(b"kotlin-source-domain"),
            source_lookup: SemanticId::for_test(b"kotlin-source-lookup"),
            target_domain: SemanticId::for_test(b"kotlin-target-domain"),
            target_lookup: SemanticId::for_test(b"kotlin-target-lookup"),
            target_definition: Some(BindingNodeId::universal_root()),
            route_identity: [0; 32],
            precedence: Some(step),
            candidate_origin_rank: None,
            jvm_evidence: None,
            completion: ResolutionCompletion::Complete,
        };
        let compiled = bridge
            .compile(
                &SelectedContextIdentities::new(),
                &PreloadedFragmentSource::new([], []),
                &CancellationToken::default(),
                &ResolutionSession::unbounded(),
            )
            .unwrap()
            .expect("a live selected package bridge compiles");
        assert_eq!(compiled.1.precedence(), &[step]);
    }
}
