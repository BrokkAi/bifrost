//! JVM source contexts admitted only when a selected endpoint reaches them.
use super::demand::{
    ClosedForwardSource, ClosedRelations, DemandLanguage, DemandProvider, LanguageClosure,
    LanguageContextPreparation, LanguagePrefixInputs, LanguageRootDiscovery,
};
use super::jvm_context::{
    JvmImportContext, JvmImportContextGap, JvmRoutePublication, is_jvm_language,
    jvm_prefix_defers_member_selection,
};
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::{
    DemandMemberSelection, DemandMemberSelectionRequest, DemandSelectedOverlayBlueprint,
    EndpointSignature, FactResolutionAnswer, JvmImplicitRootProvider, LoweringGapOrigin,
    SelectedResolutionMountContext, language_implicit_root_providers,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

struct JvmSourceDemand {
    mount: SelectedResolutionMountOrdinal,
    qualified: Option<SelectedRootPathHalf>,
    qualified_completion: Option<ResolutionCompletion>,
    caller_scoped_source: Option<JvmCallerScopedSource>,
    caller_gap_reasons: Vec<ResolutionIncompleteReason>,
    import_qualifiers: Option<(SelectedRootPathHalf, Box<[SemanticId]>)>,
}

#[derive(Clone, Copy)]
enum JvmCallerScopedSource {
    Import {
        token: SemanticId,
        demand: SemanticId,
    },
    ImplicitRootReference {
        token: SemanticId,
        demand: SemanticId,
    },
}

struct JvmPreparedContext {
    blueprint: RefCell<Option<SelectedFactOperationBlueprint>>,
    scoped_gaps: RefCell<Option<Vec<JvmImportContextGap>>>,
}

struct JvmDemandLanguage<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    base: &'a dyn BatchResolutionFragmentSource,
    arena: &'a RefCell<ClosedRelations>,
    session: &'a ResolutionSession,
    cancellation: &'a CancellationToken,
    caller: SelectedResolutionMountOrdinal,
    caller_scoped_gaps: Option<Vec<JvmImportContextGap>>,
    selected_import_gap: Option<(SemanticId, SemanticId)>,
    imported_prefix_targets: HashMap<SemanticId, (BTreeSet<SemanticId>, ResolutionCompletion)>,
}

impl JvmDemandLanguage<'_, '_, '_> {
    fn scala_import_discharges(source: &JvmSourceDemand) -> DemandClosureDischarges {
        // Retire only this import's provisional inventory gaps. In particular,
        // never retire operation-owned hierarchy or applicability evidence.
        DemandClosureDischarges::exact(source.caller_gap_reasons.iter().filter_map(|reason| {
            match reason {
                ResolutionIncompleteReason::UnsupportedSemantic(reason) => Some(*reason),
                _ => None,
            }
        }))
    }

    fn publish_scala_import(
        &self,
        endpoint: &EndpointSignature,
        source: &JvmSourceDemand,
        bridges: Vec<SelectedRootBridgeDescriptor>,
        completion: ResolutionCompletion,
        discharges: DemandClosureDischarges,
    ) -> Result<LanguageClosure> {
        let mount = self
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?;
        let context = SelectedResolutionContextSet::new(
            self.operation.ready.context_identities.clone(),
            vec![SelectedResolutionMountContext::new(
                source.mount,
                mount.fragment(),
                Language::Scala,
                bridges,
                completion.clone(),
            )?],
            self.operation.mount_table().mount_count(),
            &selected_mount_lookup(self.operation.mount_table()),
        )?;
        let Some(blueprint) = self.register_context(context)? else {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        };
        let relation = DemandSelectedOverlayBlueprint::new(blueprint.context_token());
        let paths = self.operation.ready.lexical_source();
        let Some(candidates) = relation.added_candidate_paths(&paths, self.cancellation)? else {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        };
        self.arena.borrow_mut().publish_without_base(
            endpoint.clone(),
            relation,
            candidates,
            completion.clone(),
        );
        Ok(LanguageClosure {
            completion,
            closed: true,
            discharges: Some(discharges),
        })
    }

    fn close_unknown_scala_import(
        &self,
        endpoint: &EndpointSignature,
        source: &JvmSourceDemand,
        prefix_completion: &ResolutionCompletion,
    ) -> Result<LanguageClosure> {
        let (half, qualifiers) = source
            .import_qualifiers
            .as_ref()
            .expect("selected Scala import qualifier");
        let SelectedRootPathHalf::Import { token, .. } = half else {
            unreachable!("selected member import");
        };
        // A missing positioned reference is itself a structured source gap.
        // Its exact import token anchors the reason; no owner is fabricated.
        let owner_anchor = qualifiers.first().copied().unwrap_or(*token);
        let reason =
            self.operation
                .scala_import_owner_gap(half, owner_anchor, self.cancellation)?;
        let completion = prefix_completion.combine(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(reason),
        ]));
        self.publish_scala_import(
            endpoint,
            source,
            Vec::new(),
            completion,
            Self::scala_import_discharges(source),
        )
    }

    fn scala_import_member_request(
        &self,
        source: &JvmSourceDemand,
        values: &[ResolutionSlotValue],
    ) -> Result<Option<DemandMemberSelectionRequest>> {
        let (half, qualifiers) = source
            .import_qualifiers
            .as_ref()
            .expect("selected import qualifier");
        let SelectedRootPathHalf::Import {
            identity, demand, ..
        } = half
        else {
            unreachable!("selected member import");
        };
        let Some(recipes) =
            self.operation
                .jvm_lookup_recipes(identity.fragment(), [*demand], self.cancellation)?
        else {
            return Ok(None);
        };
        let recipe = recipes.first().expect("import demand recipe");
        if !matches!(
            recipe.namespace(),
            ResolutionNamespace::Type | ResolutionNamespace::Value | ResolutionNamespace::Callable
        ) {
            return Ok(None);
        }

        let member_namespace = if recipe.namespace() == ResolutionNamespace::Callable {
            ResolutionNamespace::Value
        } else {
            recipe.namespace()
        };
        let lookup = ResolutionLookupSemanticRecipe::new(
            Language::Scala,
            member_namespace,
            recipe.spelling(),
        )
        .semantic(&self.operation.ready.shared_names());
        Ok(Some(DemandMemberSelectionRequest {
            reference: *qualifiers
                .first()
                .expect("a selected owner has positioned inputs"),
            values: values.to_vec(),
            lookup,
            namespace: recipe.namespace(),
            language: Language::Scala,
        }))
    }

    fn close_scala_import(
        &self,
        endpoint: &EndpointSignature,
        source: &JvmSourceDemand,
        prefix_completion: &ResolutionCompletion,
        selection: &DemandMemberSelection,
    ) -> Result<LanguageClosure> {
        let (half, qualifiers) = source
            .import_qualifiers
            .as_ref()
            .expect("selected import qualifier");
        let mut completion = prefix_completion.combine(&selection.completion);
        let Some(publication) = self.operation.scala_selected_import_member_bridges(
            half,
            &selection.owners,
            &completion,
            self.cancellation,
        )?
        else {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        };
        if !publication.complete {
            let reason = self.operation.scala_import_owner_gap(
                half,
                *qualifiers
                    .first()
                    .expect("a selected owner has positioned inputs"),
                self.cancellation,
            )?;
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]));
        }
        self.publish_scala_import(
            endpoint,
            source,
            publication.bridges,
            completion,
            Self::scala_import_discharges(source),
        )
    }

    fn root_bridge_candidate(
        &self,
        bridge: &SelectedRootBridgeDescriptor,
    ) -> Result<CandidatePathIdentity> {
        bridge.candidate_identity(
            &self.operation.ready.context_identities,
            &self.operation.ready.lexical_source(),
            self.cancellation,
        )
    }

    fn source_demand(&self, endpoint: &EndpointSignature) -> Result<Option<JvmSourceDemand>> {
        let lexical = self.operation.ready.lexical_source();
        let symbols = endpoint.symbols().fixed();
        // Package source paths protect their domain, source token and lookup.
        // The local token is only a seek hint: selected package rows must prove
        // all three fields before it authorizes a file context.
        if endpoint.scopes().fixed().is_empty() && symbols.len() >= 3 {
            let token = symbols[1].symbol();
            let mount = match lexical.semantic_provenance(token, self.cancellation)? {
                Some(SelectedSemanticProvenance::FragmentLocal(provenance)) => {
                    Some(provenance.mount())
                }
                Some(SelectedSemanticProvenance::Stage(provenance)) => Some(provenance.mount()),
                Some(SelectedSemanticProvenance::Shared(_)) | None => None,
            };
            if let Some(mount) = mount {
                let record = self
                    .operation
                    .mount_table()
                    .mount_by_ordinal(mount.ordinal())?;
                if is_jvm_language(record.semantic_language()) {
                    let SelectedPackageRows::Ready(references) =
                        self.operation.selected_package_reference_for_token(
                            mount.ordinal(),
                            token,
                            self.cancellation,
                        )?
                    else {
                        return Ok(None);
                    };
                    for reference in references {
                        if self.cancellation.is_cancelled() || !self.session.scope_step() {
                            return Ok(None);
                        }
                        if reference.token == token
                            && reference.domain == symbols[0].symbol()
                            && reference.lookup == symbols[2].symbol()
                        {
                            let root_half = super::source_demand::root_source_half(
                                &self.operation.ready,
                                self.base,
                                endpoint,
                                None,
                                self.session,
                                self.cancellation,
                            )?;
                            if let Some(source) = root_half {
                                let owner_continues = matches!(
                                    &source.half,
                                    SelectedRootPathHalf::Reference {
                                        owner_continued: true,
                                        ..
                                    }
                                );
                                if owner_continues {
                                    return self.source_demand_from_root(source);
                                }
                            }
                            return Ok(Some(JvmSourceDemand {
                                mount: mount.ordinal(),
                                qualified: None,
                                qualified_completion: None,
                                caller_scoped_source: None,
                                caller_gap_reasons: Vec::new(),
                                import_qualifiers: None,
                            }));
                        }
                    }
                }
            }
        }

        let root_half = super::source_demand::root_source_half(
            &self.operation.ready,
            self.base,
            endpoint,
            None,
            self.session,
            self.cancellation,
        )?;
        match root_half {
            Some(source) => self.source_demand_from_root(source),
            None => Ok(None),
        }
    }

    fn source_demand_from_root(
        &self,
        source: super::source_demand::SelectedRootSource,
    ) -> Result<Option<JvmSourceDemand>> {
        let Some(mount) = self
            .operation
            .mount_table()
            .mount_for_fragment(source.key.fragment)?
            .filter(|mount| is_jvm_language(mount.semantic_language()))
        else {
            return Ok(None);
        };
        let source_language = mount.semantic_language();
        let import_qualifiers = if source_language == Language::Scala {
            self.operation
                .scala_import_qualifiers(&source.half, self.cancellation)?
                .map(|qualifiers| (source.half.clone(), qualifiers.into_boxed_slice()))
        } else {
            None
        };
        let caller_scoped_source = match &source.half {
            SelectedRootPathHalf::Import { token, demand, .. } => {
                Some(JvmCallerScopedSource::Import {
                    token: *token,
                    demand: *demand,
                })
            }
            SelectedRootPathHalf::Reference {
                token,
                demand,
                prefix_reference: None,
                owner_continued: false,
                anchor: ResolutionRootImportAnchor::Lexical,
                ..
            } if !language_implicit_root_providers(source_language).is_empty() => {
                Some(JvmCallerScopedSource::ImplicitRootReference {
                    token: *token,
                    demand: *demand,
                })
            }
            SelectedRootPathHalf::Reference { .. } | SelectedRootPathHalf::Export { .. } => None,
        };
        let qualified = match &source.half {
            SelectedRootPathHalf::Reference {
                prefix_reference,
                owner_continued,
                anchor,
                ..
            } => {
                prefix_reference.is_some()
                    || *owner_continued
                    || *anchor == ResolutionRootImportAnchor::Absolute
            }
            _ => false,
        };
        Ok(Some(JvmSourceDemand {
            mount: mount.ordinal(),
            qualified: qualified.then_some(source.half),
            qualified_completion: qualified.then_some(source.completion),
            caller_scoped_source,
            caller_gap_reasons: Vec::new(),
            import_qualifiers,
        }))
    }

    fn caller_scoped_gap_reasons(
        &mut self,
        source: &JvmSourceDemand,
    ) -> Result<Option<Vec<ResolutionIncompleteReason>>> {
        let Some(caller_source) = source.caller_scoped_source else {
            return Ok(Some(Vec::new()));
        };
        let (source_token, demand, implicit_root_reference) = match caller_source {
            JvmCallerScopedSource::Import { token, demand } => (token, demand, false),
            JvmCallerScopedSource::ImplicitRootReference { token, demand } => (token, demand, true),
        };
        if self.caller_scoped_gaps.is_none() {
            let language = self
                .operation
                .mount_table()
                .mount_by_ordinal(self.caller)?
                .semantic_language();
            let gaps = if !language_implicit_root_providers(language).is_empty()
                || (language == Language::Java && !implicit_root_reference)
            {
                let Some((_, gaps)) = self.file_context(self.caller)? else {
                    return Ok(None);
                };
                gaps
            } else {
                Vec::new()
            };
            self.caller_scoped_gaps = Some(gaps);
        }

        let source_mount = self
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?;
        let Some(mut recipes) = self.operation.jvm_lookup_recipes(
            source_mount.fragment(),
            [demand],
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let root_lookup = recipes
            .pop()
            .expect("a selected caller import demand has one lookup recipe");
        let language = source_mount.semantic_language();
        let scala_callable_value_alias = language_implicit_root_providers(language)
            .contains(&JvmImplicitRootProvider::ScalaPredef)
            && root_lookup.namespace() == ResolutionNamespace::Value;
        let reasons = self
            .caller_scoped_gaps
            .as_ref()
            .expect("caller import gaps were loaded")
            .iter()
            .filter(|gap| {
                if gap.source_token != source_token {
                    return false;
                }
                if self.selected_import_gap == Some((source_token, gap.reason)) {
                    return false;
                }
                gap.lookup == root_lookup
                    // A bare Scala `def` reference is read in the Value
                    // namespace, while its imported declaration is Callable.
                    // Keep that unresolved import open across this one token.
                    || (scala_callable_value_alias
                        && gap.lookup.namespace() == ResolutionNamespace::Callable
                        && root_lookup.spelling() == gap.lookup.spelling())
            })
            .filter_map(|gap| match gap.boundary_status {
                Some(status) => Some(ResolutionIncompleteReason::OpenBoundary {
                    semantic: gap.reason,
                    status,
                }),
                None if !implicit_root_reference => {
                    Some(ResolutionIncompleteReason::UnsupportedSemantic(gap.reason))
                }
                None => None,
            })
            .collect();
        Ok(Some(reasons))
    }
}

impl DemandLanguage for JvmDemandLanguage<'_, '_, '_> {
    type RootQuestion = JvmSourceDemand;
    type ContextKey = SelectedResolutionMountOrdinal;
    type ContextData = JvmPreparedContext;

    fn discover_root(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<Self::RootQuestion>> {
        self.operation
            .profile_jvm_read("discover_root", (self.caller, endpoint));
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguageRootDiscovery::Cancelled(cancelled_completion()));
        }
        if endpoint.node() != BindingNodeId::universal_root() {
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        if self.arena.borrow().endpoints.contains_key(endpoint) {
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        let source = self.source_demand(endpoint)?;
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(LanguageRootDiscovery::Cancelled(cancelled_completion()));
        }
        let Some(mut source) = source else {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        };
        let mut completion = ResolutionCompletion::Complete;
        if source.mount == self.caller && source.qualified.is_none() {
            let Some(reasons) = self.caller_scoped_gap_reasons(&source)? else {
                return Ok(LanguageRootDiscovery::Cancelled(cancelled_completion()));
            };
            if source.import_qualifiers.is_none() {
                self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            }
            if reasons.is_empty() && source.import_qualifiers.is_none() {
                return Ok(LanguageRootDiscovery::AlreadyReady {
                    completion: ResolutionCompletion::Complete,
                });
            }
            if !reasons.is_empty() {
                completion = ResolutionCompletion::incomplete(reasons.iter().copied());
            }
            source.caller_gap_reasons = reasons;
        }
        Ok(LanguageRootDiscovery::Ready {
            question: source,
            completion,
        })
    }

    fn context_key(&self, question: &Self::RootQuestion) -> Option<Self::ContextKey> {
        (question.mount != self.caller && question.qualified.is_none()).then_some(question.mount)
    }

    fn prepare_context(
        &mut self,
        key: &Self::ContextKey,
        question: &Self::RootQuestion,
    ) -> Result<LanguageContextPreparation<Self::ContextData>> {
        assert_eq!(*key, question.mount);
        assert!(question.qualified.is_none());
        if self.cancellation.is_cancelled() {
            return Ok(LanguageContextPreparation::Cancelled(cancelled_completion()));
        }
        Ok(LanguageContextPreparation::Ready {
            // Keep provider-file contexts lazy until the scheduler closes this
            // root. Registering them during discovery changes the candidate
            // source seen by other roots discovered in the same scheduler pass.
            data: JvmPreparedContext {
                blueprint: RefCell::new(None),
                scoped_gaps: RefCell::new(None),
            },
            completion: ResolutionCompletion::Complete,
        })
    }

    fn prefix_inputs(
        &mut self,
        question: &mut Self::RootQuestion,
        _context: Option<&Self::ContextData>,
    ) -> Result<LanguagePrefixInputs> {
        if self.cancellation.is_cancelled() {
            return Ok(LanguagePrefixInputs {
                references: Vec::new(),
                completion: cancelled_completion(),
            });
        }
        let references = if let Some((_, qualifiers)) = &question.import_qualifiers {
            qualifiers.to_vec()
        } else {
            question
                .qualified
                .as_ref()
                .and_then(|half| match half {
                    SelectedRootPathHalf::Reference {
                        prefix_reference, ..
                    } => *prefix_reference,
                    _ => unreachable!("qualified JVM reference"),
                })
                .into_iter()
                .collect()
        };
        Ok(LanguagePrefixInputs {
            references,
            completion: ResolutionCompletion::Complete,
        })
    }

    fn member_selection(
        &mut self,
        source: &Self::RootQuestion,
        _context: Option<&Self::ContextData>,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> Result<Option<DemandMemberSelectionRequest>> {
        let Some((_, qualifiers)) = &source.import_qualifiers else {
            return Ok(None);
        };
        let Some(values) = self.scala_import_projected_values(qualifiers, inputs) else {
            return Ok(None);
        };
        for value in values {
            if let ResolutionSlotValue::TypeObject(ty) = value
                && !self.operation.jvm_scala_object_definition(ty.identity())?
            {
                return Ok(None);
            }
        }
        self.scala_import_member_request(source, values)
    }

    fn close_selected_members(
        &mut self,
        endpoint: &EndpointSignature,
        source: &Self::RootQuestion,
        _context: Option<&Self::ContextData>,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
        selection: &DemandMemberSelection,
    ) -> Result<LanguageClosure> {
        let completion = inputs
            .iter()
            .fold(ResolutionCompletion::Complete, |completion, (_, answer)| {
                completion.combine(answer.completion())
            });
        self.close_scala_import(endpoint, source, &completion, selection)
    }

    fn close_root(
        &mut self,
        endpoint: &EndpointSignature,
        source: &Self::RootQuestion,
        context: Option<&Self::ContextData>,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> Result<LanguageClosure> {
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        }
        let mount = source.mount;
        let qualified = source.qualified.clone();
        let mut evidence = ResolutionCompletion::Complete;
        let mut discharges = None;
        let mut prefix_targets = None;
        let mut selected_import_prefix = false;
        let mut terminal_route_reasons = Vec::new();
        if let Some((import_half, qualifiers)) = &source.import_qualifiers {
            let completion = inputs
                .iter()
                .fold(ResolutionCompletion::Complete, |completion, (_, answer)| {
                    completion.combine(answer.completion())
                });
            if inputs.is_empty() {
                return self.close_unknown_scala_import(endpoint, source, &completion);
            }
            let mut nominal_type = false;
            if let Some(values) = self.scala_import_projected_values(qualifiers, inputs) {
                let mut stable_value = true;
                for value in values {
                    if let ResolutionSlotValue::TypeObject(ty) = value
                        && !self.operation.jvm_scala_object_definition(ty.identity())?
                    {
                        stable_value = false;
                        break;
                    }
                }
                if stable_value {
                    return self.close_unknown_scala_import(endpoint, source, &completion);
                }
                // A nominal class/model keeps its existing static-member
                // route only when every binding names those exact type owners.
                let owners = values
                    .iter()
                    .map(|value| value.ty().identity())
                    .collect::<BTreeSet<_>>();
                nominal_type = completion == ResolutionCompletion::Complete
                    && inputs.iter().all(|(_, answer)| {
                        answer
                            .binding()
                            .targets()
                            .iter()
                            .copied()
                            .collect::<BTreeSet<_>>()
                            == owners
                    });
                if !nominal_type {
                    return self.close_unknown_scala_import(endpoint, source, &completion);
                }
            }
            if !nominal_type {
                if inputs
                    .iter()
                    .any(|(_, answer)| !answer.binding().targets().is_empty())
                {
                    return self.close_unknown_scala_import(endpoint, source, &completion);
                }
                let fragment = match import_half {
                    SelectedRootPathHalf::Import { identity, .. } => identity.fragment(),
                    _ => unreachable!("Scala import half"),
                };
                for (_, answer) in inputs {
                    let Some(package) =
                        self.jvm_package_prefix_evidence(fragment, answer.completion())?
                    else {
                        return Ok(LanguageClosure {
                            completion: cancelled_completion(),
                            closed: false,
                            discharges: None,
                        });
                    };
                    if !matches!(package, JvmPackagePrefix::Witness(_)) {
                        return self.close_unknown_scala_import(endpoint, source, &completion);
                    }
                }
            }
            if mount == self.caller && source.caller_gap_reasons.is_empty() {
                self.arena.borrow_mut().base_ready.insert(endpoint.clone());
                return Ok(LanguageClosure {
                    completion,
                    closed: true,
                    discharges: None,
                });
            }
        }
        if mount == self.caller && qualified.is_none() {
            assert!(!source.caller_gap_reasons.is_empty());
            assert!(
                context.is_none(),
                "caller import gaps need no provider context"
            );
            assert!(
                inputs.is_empty() || source.import_qualifiers.is_some(),
                "caller import gaps have no prefixes"
            );
            let completion =
                ResolutionCompletion::incomplete(source.caller_gap_reasons.iter().copied());
            if source.import_qualifiers.is_some() {
                self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            }
            assert!(
                self.arena
                    .borrow_mut()
                    .endpoint_completions
                    .insert(endpoint.clone(), completion.clone())
                    .is_none()
            );
            let discharges = match source.caller_scoped_source {
                Some(JvmCallerScopedSource::Import { token, demand }) => {
                    let source_mount = self
                        .operation
                        .mount_table()
                        .mount_by_ordinal(source.mount)?;
                    let Some(mut recipes) = self.operation.jvm_lookup_recipes(
                        source_mount.fragment(),
                        [demand],
                        self.cancellation,
                    )?
                    else {
                        return Ok(LanguageClosure {
                            completion: cancelled_completion(),
                            closed: false,
                            discharges: None,
                        });
                    };
                    let root_lookup = recipes
                        .pop()
                        .expect("a selected caller import demand has one lookup recipe");
                    let identities = self
                        .caller_scoped_gaps
                        .as_ref()
                        .expect("caller import gaps were loaded")
                        .iter()
                        .filter(|gap| gap.source_token == token && gap.lookup == root_lookup)
                        .filter_map(|gap| gap.nominal_type_identity)
                        .collect::<Vec<_>>();
                    assert!(
                        identities.len() <= 1,
                        "one selected JVM import token has at most one unindexed nominal type"
                    );
                    identities.first().copied().map(|identity| {
                        DemandClosureDischarges::with_operation_local_placeholders([])
                            .with_selected_targets([identity])
                    })
                }
                Some(JvmCallerScopedSource::ImplicitRootReference { .. }) | None => None,
            };
            return Ok(LanguageClosure {
                completion,
                closed: true,
                discharges,
            });
        }
        let qualified_blueprint;
        let cached_blueprint;
        let blueprint = if let Some(half) = qualified {
            let SelectedRootPathHalf::Reference {
                identity,
                prefix_reference,
                owner_continued,
                source_reference,
                route,
                token,
                anchor,
                anchor_semantic,
                demand,
                ..
            } = &half
            else {
                unreachable!("qualified JVM reference");
            };
            let package_lookup = if let Some(prefix) = prefix_reference {
                assert_eq!(inputs.len(), 1, "one JVM lexical prefix");
                assert_eq!(inputs[0].0, *prefix);
                let answer = inputs[0].1;
                // A selected type-object prefix owns the whole qualified name.
                // Its existing typed member chain supplies any nested target.
                let has_prefix_target = !answer.binding().targets().is_empty();
                let mut type_prefix_targets = self.jvm_type_prefix_targets(
                    *prefix,
                    answer,
                    self.operation
                        .mount_table()
                        .mount_by_ordinal(source.mount)?
                        .semantic_language(),
                );
                let mut prefix_route_completion = ResolutionCompletion::Complete;
                if type_prefix_targets.is_none()
                    && !has_prefix_target
                    && let Some((imported_targets, import_completion)) =
                        self.imported_prefix_targets.get(prefix)
                    && !imported_targets.is_empty()
                {
                    type_prefix_targets = Some(imported_targets.iter().copied().collect());
                    prefix_route_completion = prefix_route_completion.combine(import_completion);
                }
                if let Some(type_targets) = type_prefix_targets {
                    selected_import_prefix = self.operation.mount_table().mount_by_ordinal(source.mount)?.semantic_language() == Language::Scala
                        && answer.site_metadata().is_some_and(|metadata| metadata.site_kind() ==
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ImportQualifierReference);
                    prefix_targets = Some(type_targets);
                    let language = self
                        .operation
                        .mount_table()
                        .mount_for_fragment(identity.fragment())?
                        .expect("selected source half has its mount")
                        .semantic_language();
                    evidence = answer.completion().combine(&prefix_route_completion);
                    if answer.completion() == &ResolutionCompletion::Complete {
                        if evidence == ResolutionCompletion::Complete {
                            discharges = Some(
                                DemandClosureDischarges::with_operation_local_placeholders([]),
                            );
                        }
                    } else {
                        let Some(prefix_evidence) = self.jvm_type_prefix_evidence(
                            language,
                            identity.fragment(),
                            *prefix,
                            prefix_targets
                                .as_ref()
                                .expect("selected type prefix targets were retained"),
                            answer,
                        )?
                        else {
                            return Ok(LanguageClosure {
                                completion: cancelled_completion(),
                                closed: false,
                                discharges: None,
                            });
                        };
                        match prefix_evidence {
                            JvmPackagePrefix::Witness(retired) => {
                                evidence = completion_without_unsupported_semantics(
                                    answer.completion(),
                                    &retired,
                                )
                                .combine(&prefix_route_completion);
                                discharges = Some(
                                    DemandClosureDischarges::with_operation_local_placeholders(
                                        retired.clone(),
                                    )
                                    .for_prefix(*prefix, retired, true),
                                );
                            }
                            JvmPackagePrefix::Retained(completion) => {
                                evidence = completion.combine(&prefix_route_completion);
                            }
                        }
                    }
                    if let Some(route_completion) = source.qualified_completion.as_ref() {
                        let Some((_, retired, _)) = self.jvm_root_reference_evidence(
                            language,
                            identity.fragment(),
                            *source_reference,
                            route_completion,
                        )?
                        else {
                            return Ok(LanguageClosure {
                                completion: cancelled_completion(),
                                closed: false,
                                discharges: None,
                            });
                        };
                        terminal_route_reasons = retired;
                        if jvm_prefix_defers_member_selection(language)
                            && evidence == ResolutionCompletion::Complete
                            && prefix_targets
                                .as_ref()
                                .is_some_and(|targets| targets.len() == 1)
                        {
                            // The proved prefix classifies the name even when
                            // member lookup still lacks hierarchy or signatures.
                            // Retire exactly its own ambiguity, not that lookup.
                            discharges
                                .get_or_insert_with(DemandClosureDischarges::default)
                                .merge(DemandClosureDischarges::exact(
                                    terminal_route_reasons.iter().copied(),
                                ));
                        }
                    }
                } else if has_prefix_target {
                    // A selected value shadows a package of the same name.
                    // Without a selected type-object projection its member
                    // owner is unknown, so leave the member route open.
                    evidence = answer.completion().clone();
                } else {
                    let Some(prefix_evidence) =
                        self.jvm_package_prefix_evidence(identity.fragment(), answer.completion())?
                    else {
                        return Ok(LanguageClosure {
                            completion: cancelled_completion(),
                            closed: false,
                            discharges: None,
                        });
                    };
                    match prefix_evidence {
                        JvmPackagePrefix::Witness(retired) => {
                            evidence = completion_without_unsupported_semantics(
                                answer.completion(),
                                &retired,
                            );
                            discharges = Some(
                                DemandClosureDischarges::with_operation_local_placeholders(
                                    retired.clone(),
                                )
                                .for_prefix(*prefix, retired, true),
                            );
                        }
                        JvmPackagePrefix::Retained(completion) => evidence = completion,
                    }
                }
                !has_prefix_target && prefix_targets.is_none()
            } else {
                assert!(matches!(
                    *anchor,
                    ResolutionRootImportAnchor::Absolute | ResolutionRootImportAnchor::Lexical
                ));
                assert!(
                    inputs.is_empty(),
                    "an unprefixed JVM root route has no lexical prefix"
                );
                let language = self
                    .operation
                    .mount_table()
                    .mount_for_fragment(identity.fragment())?
                    .expect("selected source half has its mount")
                    .semantic_language();
                if *anchor == ResolutionRootImportAnchor::Lexical && *owner_continued {
                    let route_completion = source
                        .qualified_completion
                        .as_ref()
                        .expect("a selected JVM root route retains its source completion");
                    if let Some((reference, retired, completion)) = self
                        .jvm_root_reference_evidence(
                            language,
                            identity.fragment(),
                            *source_reference,
                            route_completion,
                        )?
                    {
                        evidence = completion;
                        discharges = Some(
                            DemandClosureDischarges::with_operation_local_placeholders(
                                retired.clone(),
                            )
                            .for_prefix(reference, retired, true),
                        );
                    } else {
                        evidence = route_completion.clone();
                    }
                }
                true
            };
            let source_language = self
                .operation
                .mount_table()
                .mount_for_fragment(identity.fragment())?
                .expect("selected source half has its mount")
                .semantic_language();
            let lexical_import_head = if source_language == Language::Scala {
                let Some(head) = self
                    .operation
                    .jvm_lexical_import_qualifier(*source_reference, self.cancellation)?
                else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                head
            } else {
                false
            };
            let mut import_root_bridges = Vec::new();
            let mut existing_import_bridge_ids = BTreeSet::new();
            let mut has_import_route = false;
            let mut import_gap_reasons = Vec::new();
            if prefix_reference.is_none()
                && *anchor == ResolutionRootImportAnchor::Lexical
                && !language_implicit_root_providers(source_language).is_empty()
            {
                let Some(mut recipes) = self.operation.jvm_lookup_recipes(
                    identity.fragment(),
                    route.iter().copied().chain(std::iter::once(*demand)),
                    self.cancellation,
                )?
                else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                let source_demand = recipes.pop().expect("qualified root lookup demand");
                let Some((source_context, scoped_gaps)) = self.file_context(mount)? else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                let source_reference_semantic =
                    self.jvm_source_reference_semantic(*source_reference)?;
                let source_lookup = source_demand.semantic(&self.operation.ready.shared_names());
                let package_reference_tokens = if let Some(reference) = source_reference_semantic {
                    let SelectedPackageRows::Ready(references) = self
                        .operation
                        .selected_package_reference_for_site(mount, reference, self.cancellation)?
                    else {
                        return Ok(LanguageClosure {
                            completion: cancelled_completion(),
                            closed: false,
                            discharges: None,
                        });
                    };
                    references
                        .into_iter()
                        .filter(|package_reference| {
                            package_reference.reference == reference
                                && package_reference.lookup == source_lookup
                        })
                        .map(|package_reference| package_reference.token)
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let (root_bridges, package_bridges) = source_context.qualified_reference_bridges(
                    identity.fragment(),
                    &package_reference_tokens,
                    std::slice::from_ref(&source_demand),
                    &self.operation.ready.shared_names(),
                );
                has_import_route = !root_bridges.is_empty() || !package_bridges.is_empty();
                for bridge in &root_bridges {
                    existing_import_bridge_ids.insert(self.root_bridge_candidate(bridge)?);
                }
                for package_bridge in package_bridges {
                    if let Some(bridge) = package_bridge.qualified_root_reference_bridge(
                        *token,
                        *anchor,
                        *anchor_semantic,
                        &recipes,
                        &source_demand,
                    ) {
                        import_root_bridges.push(bridge);
                    }
                }
                if let Some(reference) = source_reference_semantic {
                    let prefix_bridges = root_bridges
                        .iter()
                        .chain(import_root_bridges.iter())
                        .filter(|bridge| {
                            matches!(
                                bridge.source_demand().namespace(),
                                ResolutionNamespace::Type
                                    | ResolutionNamespace::TypeOrValue
                                    | ResolutionNamespace::Value
                            )
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    let mut keyed = prefix_bridges
                        .into_iter()
                        .map(|bridge| Ok((self.root_bridge_candidate(&bridge)?, bridge)))
                        .collect::<Result<Vec<_>>>()?;
                    keyed.sort_unstable_by_key(|(candidate, _)| *candidate);
                    keyed.dedup_by_key(|(candidate, _)| *candidate);
                    let prefix_bridges = keyed
                        .into_iter()
                        .map(|(_, bridge)| bridge)
                        .collect::<Vec<_>>();
                    if !prefix_bridges.is_empty() {
                        let Some((targets, completion)) =
                            self.jvm_root_bridge_prefix_targets(prefix_bridges)?
                        else {
                            return Ok(LanguageClosure {
                                completion: cancelled_completion(),
                                closed: false,
                                discharges: None,
                            });
                        };
                        if !targets.is_empty() {
                            let entry = self
                                .imported_prefix_targets
                                .entry(reference)
                                .or_insert_with(|| {
                                    (BTreeSet::new(), ResolutionCompletion::Complete)
                                });
                            entry.0.extend(targets);
                            entry.1 = entry.1.combine(&completion);
                        }
                    }
                }
                if !import_root_bridges.is_empty() {
                    let existing = self.arena.borrow();
                    let mut retained = Vec::with_capacity(import_root_bridges.len());
                    for bridge in import_root_bridges {
                        let candidate = self.root_bridge_candidate(&bridge)?;
                        if !existing_import_bridge_ids.contains(&candidate)
                            && !existing.paths.contains_key(&candidate)
                        {
                            retained.push(bridge);
                        }
                    }
                    import_root_bridges = retained;
                }
                import_gap_reasons.extend(
                    scoped_gaps
                        .iter()
                        .filter(|gap| gap.lookup == source_demand)
                        .map(|gap| gap.reason),
                );
                if !import_gap_reasons.is_empty() {
                    evidence = evidence.combine(&ResolutionCompletion::incomplete(
                        import_gap_reasons
                            .iter()
                            .copied()
                            .map(ResolutionIncompleteReason::UnsupportedSemantic),
                    ));
                }
            }
            let publication = if package_lookup {
                let Some(publication) = self.operation.jvm_qualified_type_bridges(
                    &half,
                    &evidence,
                    self.cancellation,
                )?
                else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                publication
            } else if let Some(prefix_targets) = prefix_targets {
                let Some(publication) = self.operation.jvm_qualified_prefix_member_bridges(
                    &half,
                    &prefix_targets,
                    &evidence,
                    self.cancellation,
                )?
                else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                publication
            } else {
                JvmRoutePublication {
                    bridges: Vec::new(),
                    selected_targets: BTreeSet::new(),
                    complete: false,
                }
            };
            if publication.complete
                && !jvm_prefix_defers_member_selection(source_language)
                && (!has_import_route || !publication.selected_targets.is_empty())
                && !terminal_route_reasons.is_empty()
            {
                discharges
                    .get_or_insert_with(DemandClosureDischarges::default)
                    .merge(DemandClosureDischarges::with_operation_local_placeholders(
                        terminal_route_reasons,
                    ));
            }
            let existing = self.arena.borrow();
            let mut retained = Vec::with_capacity(import_root_bridges.len());
            for bridge in import_root_bridges {
                let candidate = self.root_bridge_candidate(&bridge)?;
                if !existing_import_bridge_ids.contains(&candidate)
                    && !existing.paths.contains_key(&candidate)
                {
                    retained.push(bridge);
                }
            }
            import_root_bridges = retained;
            let mut publication_bridges = Vec::with_capacity(publication.bridges.len());
            for bridge in publication.bridges {
                let candidate = self.root_bridge_candidate(&bridge)?;
                if !existing_import_bridge_ids.contains(&candidate)
                    && !existing.paths.contains_key(&candidate)
                {
                    publication_bridges.push(bridge);
                }
            }
            drop(existing);
            if publication.complete
                && !jvm_prefix_defers_member_selection(source_language)
                && !lexical_import_head
                && (!has_import_route || !publication.selected_targets.is_empty())
            {
                let selected = if publication.selected_targets.is_empty() {
                    DemandClosureDischarges::with_operation_local_placeholders([])
                        .with_authoritative_empty_result()
                } else {
                    DemandClosureDischarges::with_operation_local_placeholders([])
                        .with_selected_targets(publication.selected_targets)
                };
                discharges
                    .get_or_insert_with(DemandClosureDischarges::default)
                    .merge(selected);
            }
            // Caller import routes already live in the base graph. This
            // relation owns only qualified-reference bridges; the provider
            // read above prevents an empty package route from closing over
            // those existing candidates.
            let record = self.operation.mount_table().mount_by_ordinal(mount)?;
            let mut context = SelectedResolutionContextSet::new(
                self.operation.ready.context_identities.clone(),
                vec![SelectedResolutionMountContext::new(
                    mount,
                    record.fragment(),
                    source_language,
                    publication_bridges
                        .into_iter()
                        .chain(import_root_bridges)
                        .collect::<Vec<_>>(),
                    evidence.clone(),
                )?],
                self.operation.mount_table().mount_count(),
                &selected_mount_lookup(self.operation.mount_table()),
            )?;
            for reason in import_gap_reasons {
                context = context.with_context_owned_gap_identity(reason);
            }
            let Some(blueprint) = self.register_context(context)? else {
                return Ok(LanguageClosure {
                    completion: cancelled_completion(),
                    closed: false,
                    discharges: None,
                });
            };
            qualified_blueprint = blueprint;
            &qualified_blueprint
        } else {
            assert!(
                inputs.is_empty() || source.import_qualifiers.is_some(),
                "file context has no prefix"
            );
            assert_ne!(mount, self.caller, "caller file roots are already ready");
            let context = context.expect("demanded JVM file context was prepared");
            if context.blueprint.borrow().is_none() {
                let Some((file_context, scoped_gaps)) = self.file_context(mount)? else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                let file_context = scoped_gaps.iter().fold(file_context, |context, gap| {
                    context.with_context_owned_gap_identity(gap.reason)
                });
                let Some(blueprint) = self.register_context(file_context)? else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                *context.blueprint.borrow_mut() = Some(blueprint);
                *context.scoped_gaps.borrow_mut() = Some(scoped_gaps);
            }
            for gap in context
                .scoped_gaps
                .borrow()
                .as_ref()
                .expect("demanded JVM file context has scoped gap evidence")
            {
                let lookup = gap.lookup.semantic(&self.operation.ready.shared_names());
                if endpoint
                    .symbols()
                    .fixed()
                    .iter()
                    .any(|symbol| symbol.symbol() == lookup)
                {
                    let reason = gap.boundary_status.map_or(
                        ResolutionIncompleteReason::UnsupportedSemantic(gap.reason),
                        |status| ResolutionIncompleteReason::OpenBoundary {
                            semantic: gap.reason,
                            status,
                        },
                    );
                    evidence = evidence.combine(&ResolutionCompletion::incomplete([reason]));
                }
            }
            cached_blueprint = context.blueprint.borrow();
            cached_blueprint
                .as_ref()
                .expect("demanded JVM file context was registered")
        };
        let relation = DemandSelectedOverlayBlueprint::new(blueprint.context_token());
        let paths = self.operation.ready.lexical_source();
        let Some(candidates) = relation.added_candidate_paths(&paths, self.cancellation)? else {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        };
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        }
        if selected_import_prefix {
            // An exact lexical import qualifier owns its continuation. A
            // same-spelled root package/type is no longer an alternative.
            self.arena.borrow_mut().publish_without_base(
                endpoint.clone(),
                relation,
                candidates,
                evidence.clone(),
            );
        } else {
            self.arena
                .borrow_mut()
                .publish(endpoint.clone(), relation, candidates);
        }
        // Semantic coverage is carried by each compiled candidate, not attached
        // globally to unrelated roots reached later in this operation.
        Ok(LanguageClosure {
            completion: evidence,
            closed: true,
            discharges,
        })
    }
}

/// Evidence for how a qualified JVM prefix is interpreted.
#[derive(Debug)]
enum JvmPackagePrefix {
    /// The selected package or type interpretation is positive. Its lexical
    /// tail stopped only at caller-owned structural gaps or operation-local
    /// placeholders, which this closure can retire.
    Witness(Vec<SemanticId>),
    /// Some other reason (hierarchy, visibility, activation, a foreign
    /// fragment) keeps the type interpretation open, so the qualified route
    /// keeps the prefix completion.
    Retained(ResolutionCompletion),
}

fn completion_without_unsupported_semantics(
    completion: &ResolutionCompletion,
    retired: &[SemanticId],
) -> ResolutionCompletion {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return completion.clone();
    };
    let retired = retired.iter().copied().collect::<BTreeSet<_>>();
    let retained = reasons
        .iter()
        .filter(|reason| {
            !matches!(
                reason,
                ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                    if retired.contains(semantic)
            )
        })
        .copied()
        .collect::<Vec<_>>();
    if retained.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(retained)
    }
}

impl JvmDemandLanguage<'_, '_, '_> {
    fn jvm_source_reference_semantic(
        &self,
        source_reference: BindingNodeId,
    ) -> Result<Option<SemanticId>> {
        let classifications = self
            .operation
            .ready
            .lexical_source()
            .classify_endpoint_nodes(&[source_reference], self.cancellation)?;
        Ok(classifications
            .iter()
            .find(|classification| classification.node() == source_reference)
            .and_then(|classification| classification.reference()))
    }

    fn jvm_root_reference_evidence(
        &self,
        language: Language,
        fragment: BindingFragmentId,
        source_reference: BindingNodeId,
        completion: &ResolutionCompletion,
    ) -> Result<Option<(SemanticId, Vec<SemanticId>, ResolutionCompletion)>> {
        let classifications = self
            .operation
            .ready
            .lexical_source()
            .classify_endpoint_nodes(&[source_reference], self.cancellation)?;
        let Some(reference) = classifications
            .iter()
            .find(|classification| classification.node() == source_reference)
            .and_then(|classification| classification.reference())
        else {
            return Ok(None);
        };
        assert_eq!(
            reference.ordinal(),
            Some(fragment.ordinal()),
            "a selected Scala root reference belongs to its source fragment"
        );
        assert_eq!(
            reference.local_key(),
            source_reference.local_key(),
            "a selected Scala root reference keeps its source site identity"
        );
        let source_site = ResolutionSiteId::new(
            reference
                .local_key()
                .expect("a selected Scala reference has a local site"),
        );
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Ok(Some((reference, Vec::new(), completion.clone())));
        };
        let semantics = reasons
            .iter()
            .filter_map(|reason| match reason {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                    if !semantic.is_operation_local() =>
                {
                    Some(*semantic)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut provenance = Vec::new();
        for chunk in semantics
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH)
        {
            let outcome = self
                .operation
                .ready
                .typed_source()
                .visit_gap_reason_provenance_pages_for_reasons(
                    TypedFactRequest::new(chunk),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        provenance.extend_from_slice(page);
                        Ok(true)
                    }),
                )?;
            if !outcome.is_exhausted() || self.cancellation.is_cancelled() {
                return Ok(None);
            }
        }
        let mut retired = Vec::new();
        for semantic in semantics {
            let matching = provenance
                .iter()
                .filter(|row| row.reason() == semantic)
                .collect::<Vec<_>>();
            let [row] = matching.as_slice() else {
                continue;
            };
            if row.fragment() == fragment
                && row.source_site() == source_site
                && crate::analyzer::resolution::jvm_terminal_type_gap_origin_is_safe(
                    language,
                    row.fragment(),
                    row.source_site(),
                    row.origin(),
                    reference,
                )
            {
                retired.push(semantic);
            }
        }
        Ok(Some((
            reference,
            retired.clone(),
            completion_without_unsupported_semantics(completion, &retired),
        )))
    }

    fn jvm_type_prefix_targets(
        &self,
        reference: SemanticId,
        answer: &FactResolutionAnswer,
        language: Language,
    ) -> Option<Vec<SemanticId>> {
        let values = self.jvm_prefix_projected_values(reference, answer, language)?;
        let scala = language == Language::Scala;
        let type_targets = values
            .iter()
            .map(|value| value.ty().identity())
            .collect::<BTreeSet<_>>();
        let binding_targets = answer
            .binding()
            .targets()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        (scala || type_targets == binding_targets).then(|| type_targets.into_iter().collect())
    }

    fn scala_import_projected_values<'answer>(
        &self,
        qualifiers: &[SemanticId],
        inputs: &[(SemanticId, &'answer FactResolutionAnswer)],
    ) -> Option<&'answer [ResolutionSlotValue]> {
        assert_eq!(
            qualifiers.len(),
            inputs.len(),
            "all qualifier views finish: {qualifiers:?}, {inputs:?}"
        );
        let (&qualifier, &(_, answer)) = qualifiers.first().zip(inputs.first())?;
        assert_eq!(inputs[0].0, qualifier);
        let values = self.jvm_prefix_projected_values(qualifier, answer, Language::Scala)?;
        let owner = values.first()?.ty().identity();
        if values.iter().any(|value| value.ty().identity() != owner) {
            return None;
        }
        for (&qualifier, &(reference, answer)) in qualifiers.iter().zip(inputs).skip(1) {
            assert_eq!(reference, qualifier);
            if self.jvm_prefix_projected_values(qualifier, answer, Language::Scala)? != values {
                return None;
            }
        }
        Some(values)
    }

    fn jvm_prefix_projected_values<'answer>(
        &self,
        reference: SemanticId,
        answer: &'answer FactResolutionAnswer,
        language: Language,
    ) -> Option<&'answer [ResolutionSlotValue]> {
        let mut projections = answer.projections().iter().filter(|projection| {
            projection.reference() == reference && (
                matches!(projection.kind(),
                    brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetTypeOrDeclaredValueType
                    | brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetTypeIdentity)
                || (language == Language::Scala && projection.kind() ==
                    brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetDeclaredValueType)
            )
        });
        let projection = projections.next()?;
        if projections.next().is_some() {
            return None;
        }
        let frontier = answer
            .projected_frontiers()
            .iter()
            .find(|frontier| frontier.slot() == projection.output_slot())?;
        let values = frontier.possible_values();
        let scala = language == Language::Scala;
        if values.is_empty()
            || values.iter().any(|value| {
                value.ty().indirection() != 0
                    || (!scala && !matches!(value, ResolutionSlotValue::TypeObject(_)))
            })
        {
            return None;
        }
        Some(values)
    }

    /// A selected JVM type prefix can retire only its own unsupported
    /// receiver and compilation-unit placement gaps, and its own qualified-name
    /// ambiguity where the language ranks a lexical type above a package. A
    /// typed projection or an exact selected import bridge must establish the
    /// prefix's type targets before those gaps can be retired.
    fn jvm_type_prefix_evidence(
        &self,
        language: Language,
        caller: BindingFragmentId,
        reference: SemanticId,
        selected_type_targets: &[SemanticId],
        answer: &FactResolutionAnswer,
    ) -> Result<Option<JvmPackagePrefix>> {
        if selected_type_targets.is_empty() {
            return Ok(Some(JvmPackagePrefix::Retained(
                answer.completion().clone(),
            )));
        }

        let ResolutionCompletion::Incomplete(reasons) = answer.completion() else {
            unreachable!("the complete type-prefix path is handled before provenance lookup")
        };
        let mut semantics = Vec::new();
        for reason in reasons.iter() {
            let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
                return Ok(Some(JvmPackagePrefix::Retained(
                    answer.completion().clone(),
                )));
            };
            semantics.push(*semantic);
        }
        if semantics.is_empty() {
            return Ok(Some(JvmPackagePrefix::Retained(
                answer.completion().clone(),
            )));
        }

        let mut provenance = Vec::new();
        for chunk in semantics.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let outcome = self
                .operation
                .ready
                .typed_source()
                .visit_gap_reason_provenance_pages_for_reasons(
                    TypedFactRequest::new(chunk),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        provenance.extend_from_slice(page);
                        Ok(true)
                    }),
                )?;
            if !outcome.is_exhausted() {
                return Ok(None);
            }
        }
        let mut retired = BTreeSet::new();
        for row in &provenance {
            if row.fragment() != caller
                || !crate::analyzer::resolution::jvm_type_prefix_gap_origin_is_safe(
                    language,
                    row.fragment(),
                    row.source_site(),
                    row.origin(),
                    reference,
                )
                || !retired.insert(row.reason())
            {
                return Ok(Some(JvmPackagePrefix::Retained(
                    answer.completion().clone(),
                )));
            }
        }
        if provenance.len() != retired.len()
            || semantics
                .iter()
                .any(|semantic| !retired.contains(semantic) && !semantic.is_operation_local())
        {
            return Ok(Some(JvmPackagePrefix::Retained(
                answer.completion().clone(),
            )));
        }
        Ok(Some(JvmPackagePrefix::Witness(semantics)))
    }

    /// The owners an import hands to the head of a qualified name.
    ///
    /// A bridge under a Type or TypeOrValue demand names a type, or a term the
    /// head's members are selected from. A bridge under a Value demand names a
    /// term, and only a term that owns a member scope (a Scala object, package
    /// object or companion) can own the terminal: a val's members come from
    /// its type through the typed projection, never from the import.
    fn jvm_root_bridge_prefix_targets(
        &self,
        bridges: Vec<SelectedRootBridgeDescriptor>,
    ) -> Result<Option<(BTreeSet<SemanticId>, ResolutionCompletion)>> {
        let (terms, types): (Vec<_>, Vec<_>) = bridges
            .into_iter()
            .partition(|bridge| bridge.source_demand().namespace() == ResolutionNamespace::Value);
        let Some((mut targets, mut completion)) = self.jvm_root_bridge_targets(&types)? else {
            return Ok(None);
        };
        let Some((term_targets, term_completion)) = self.jvm_root_bridge_targets(&terms)? else {
            return Ok(None);
        };
        let Some(scope_owners) = self.jvm_member_scope_owners(&term_targets)? else {
            return Ok(None);
        };
        if !scope_owners.is_empty() {
            targets.extend(scope_owners);
            completion = completion.combine(&term_completion);
        }
        Ok(Some((targets, completion)))
    }

    /// The definitions among `definitions` that own a persisted member scope.
    fn jvm_member_scope_owners(
        &self,
        definitions: &BTreeSet<SemanticId>,
    ) -> Result<Option<BTreeSet<SemanticId>>> {
        let definitions = definitions.iter().copied().collect::<Vec<_>>();
        let mut owners = BTreeSet::new();
        for chunk in definitions.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let outcome = self
                .operation
                .ready
                .typed_source()
                .visit_member_scope_pages_for_definitions(
                    TypedFactRequest::new(chunk),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        owners.extend(page.iter().map(|row| row.row().definition()));
                        Ok(true)
                    }),
                )?;
            if !outcome.is_exhausted() || self.cancellation.is_cancelled() {
                return Ok(None);
            }
        }
        Ok(Some(owners))
    }

    fn jvm_root_bridge_targets(
        &self,
        bridges: &[SelectedRootBridgeDescriptor],
    ) -> Result<Option<(BTreeSet<SemanticId>, ResolutionCompletion)>> {
        let mut definition_fragments = BTreeMap::new();
        let mut completion = ResolutionCompletion::Complete;
        for bridge in bridges {
            completion = completion.combine(bridge.completion());
            let Some(definition) = bridge.target_definition() else {
                return Ok(Some((BTreeSet::new(), completion)));
            };
            if let Some(previous) =
                definition_fragments.insert(definition, bridge.target_fragment())
            {
                assert_eq!(previous, bridge.target_fragment());
            }
        }
        let definitions = definition_fragments.keys().copied().collect::<Vec<_>>();
        if definitions.is_empty() {
            return Ok(Some((BTreeSet::new(), completion)));
        }
        let classifications = self
            .operation
            .ready
            .lexical_source()
            .classify_endpoint_nodes(&definitions, self.cancellation)?;
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut targets = BTreeSet::new();
        for definition in definitions {
            let Some(semantic) = classifications
                .iter()
                .find(|classification| classification.node() == definition)
                .and_then(|classification| classification.definition())
            else {
                return Err(StoreError::corrupt(
                    "selected JVM import prefix target lacks a definition identity",
                ));
            };
            assert_eq!(
                semantic.ordinal(),
                Some(definition_fragments[&definition].ordinal()),
                "selected JVM import prefix target remains in its selected target fragment"
            );
            targets.insert(semantic);
        }
        Ok(Some((targets, completion)))
    }
}

impl JvmDemandLanguage<'_, '_, '_> {
    /// Decision recorded in the JVM rollout plan (2026-09-29).
    fn jvm_package_prefix_evidence(
        &self,
        caller: BindingFragmentId,
        completion: &ResolutionCompletion,
    ) -> Result<Option<JvmPackagePrefix>> {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Ok(Some(JvmPackagePrefix::Witness(Vec::new())));
        };
        let mut semantics = Vec::new();
        for reason in reasons.iter() {
            let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
                return Ok(Some(JvmPackagePrefix::Retained(completion.clone())));
            };
            semantics.push(*semantic);
        }
        let mut provenance = Vec::new();
        for chunk in semantics.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let outcome = self
                .operation
                .ready
                .typed_source()
                .visit_gap_reason_provenance_pages_for_reasons(
                    TypedFactRequest::new(chunk),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        provenance.extend_from_slice(page);
                        Ok(true)
                    }),
                )?;
            if !outcome.is_exhausted() {
                return Ok(None);
            }
        }
        let owned_reasons = provenance
            .iter()
            .filter(|row| {
                row.fragment() == caller
                    && matches!(
                        row.origin(),
                        LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedPlacementBoundary
                                | ResolutionGapKind::AmbiguousQualifiedType
                        )
                    )
            })
            .map(|row| row.reason())
            .collect::<HashSet<_>>();
        let package_witness = provenance.len() == owned_reasons.len()
            && semantics
                .iter()
                .all(|semantic| owned_reasons.contains(semantic) || semantic.is_operation_local());
        Ok(Some(if package_witness {
            JvmPackagePrefix::Witness(semantics)
        } else {
            JvmPackagePrefix::Retained(completion.clone())
        }))
    }
}

/// Whether a forward point query in this source language runs with the JVM
/// demand provider, which admits the provider files its qualified routes and
/// package members reach. Kotlin's producer publishes the qualified routes
/// required by this path.
pub(super) fn jvm_demand_storage_language(storage_language: &str) -> bool {
    matches!(storage_language, "java" | "kotlin" | "scala")
}

impl SelectedResolutionOperation<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_jvm_forward_operation<T>(
        &self,
        caller_language: &str,
        blueprint: &SelectedFactOperationBlueprint,
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        caller_path: &str,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        selected_import_gap: Option<(SemanticId, SemanticId)>,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let caller = self
            .mount_table()
            .mount_for_path(caller_language, caller_path)?
            .expect("located JVM reference has a selected caller mount");
        assert!(matches!(
            caller.semantic_language(),
            Language::Java | Language::Kotlin | Language::Scala
        ));
        let caller = caller.ordinal();
        self.profile_jvm_read(
            "demand_provider",
            (caller_language, caller_path, selected_import_gap),
        );
        let paths = self.ready.lexical_source();
        let base = blueprint.path_fragment_source(lexical, &paths, None);
        let arena = RefCell::new(ClosedRelations::default());
        let source = ClosedForwardSource::new(&base, &paths, &arena, session);
        let provider = DemandProvider::new(JvmDemandLanguage {
            operation: self,
            base: lexical,
            arena: &arena,
            session,
            cancellation,
            caller,
            caller_scoped_gaps: None,
            selected_import_gap,
            imported_prefix_targets: HashMap::default(),
        });
        blueprint.with_demand_operation(
            &source,
            &paths,
            lexical,
            typed,
            provider,
            cancellation,
            session,
            run,
        )
    }
}

impl JvmDemandLanguage<'_, '_, '_> {
    fn file_context(
        &self,
        mount: SelectedResolutionMountOrdinal,
    ) -> Result<Option<(SelectedResolutionContextSet, Vec<JvmImportContextGap>)>> {
        self.operation
            .profile_jvm_read("demand_file_context", mount);
        let record = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount)?;
        assert!(is_jvm_language(record.semantic_language()));
        match self.operation.jvm_import_context(
            record.semantic_language(),
            record.persisted_relative_path(),
            self.cancellation,
        )? {
            JvmImportContext::Ready {
                context,
                scoped_gaps,
                ..
            } => Ok(Some((*context, scoped_gaps))),
            JvmImportContext::Cancelled => Ok(None),
            JvmImportContext::Unavailable => Err(StoreError::new(
                "selected JVM provider context became unavailable".to_owned(),
            )),
        }
    }

    fn register_context(
        &self,
        context: SelectedResolutionContextSet,
    ) -> Result<Option<SelectedFactOperationBlueprint>> {
        let SelectedResolutionContextValidationOutcome::Ready(context) = context
            .validate_exact_mounts_in_session(
                self.operation.mount_table().mount_count(),
                &selected_mount_lookup(self.operation.mount_table()),
                self.cancellation,
                self.session,
            )?
        else {
            return Ok(None);
        };
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = self
            .operation
            .ready
            .collect_blueprint_in_session(context, self.cancellation, self.session)?
        else {
            return Ok(None);
        };
        if matches!(
            self.operation.ready.register_context_in_session(
                &blueprint,
                self.cancellation,
                self.session,
            )?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Ok(None);
        }
        Ok(Some(blueprint))
    }
}
