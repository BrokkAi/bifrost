//! Go qualified-import bridges admitted only when a root endpoint asks for
//! its positioned lexical prefix.
use super::demand::{
    ClosedForwardSource, ClosedRelations, DemandLanguage, DemandProvider, LanguageClosure,
    LanguageContextPreparation, LanguagePrefixInputs, LanguageRootDiscovery,
};
use super::go_named::{
    GoDemandContext, GoPreparedImportContext, GoPreparedImportContextOutcome,
    NAMED_IMPORT_TARGET_MOUNTS,
};
use super::*;
use crate::analyzer::resolution::{
    DemandRootUnavailableReason, DemandSelectedOverlayBlueprint, EndpointSignature,
    LoweringGapOrigin, SelectedResolutionMountContext, SelectedRootBridgeDescriptor,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

#[derive(Clone)]
struct GoSourceDemand {
    mount: SelectedResolutionMountOrdinal,
    root_semantic: SemanticId,
    source_role: Option<String>,
    qualified: Option<SelectedRootPathHalf>,
    prefix_answer: Option<FactResolutionAnswer>,
}

struct GoPreparedDemandContext {
    blueprint: SelectedFactOperationBlueprint,
    demand: GoDemandContext,
    completion: ResolutionCompletion,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GoRemoteRootExpansion {
    FollowDemandedMounts,
    CallerContextOnly,
}

pub(super) struct GoForwardOperationContext<'a> {
    pub(super) blueprint: &'a SelectedFactOperationBlueprint,
    pub(super) demand: GoDemandContext,
    pub(super) caller_path: &'a str,
    pub(super) lexical: &'a dyn BatchResolutionFragmentSource,
    pub(super) typed: &'a dyn SelectedTypedFactSource,
    pub(super) cancellation: &'a CancellationToken,
    pub(super) session: &'a ResolutionSession,
}

struct GoDemandLanguage<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    base: &'a dyn BatchResolutionFragmentSource,
    arena: &'a RefCell<ClosedRelations>,
    session: &'a ResolutionSession,
    cancellation: &'a CancellationToken,
    demand: GoDemandContext,
    caller: SelectedResolutionMountOrdinal,
    remote_root_expansion: GoRemoteRootExpansion,
    package_mounts: HashMap<i64, Vec<SelectedResolutionMountOrdinal>>,
    export_index:
        HashMap<SelectedResolutionMountOrdinal, HashMap<SemanticId, Vec<SelectedRootPathHalf>>>,
    source_roles: HashMap<SelectedResolutionMountOrdinal, String>,
    base_context_mounts: HashSet<SelectedResolutionMountOrdinal>,
    prepared_root_source_halves:
        HashMap<EndpointSignature, Option<super::source_demand::SelectedRootSource>>,
}

impl GoDemandLanguage<'_, '_, '_> {
    fn source_role_for_mount(
        &mut self,
        mount: SelectedResolutionMountOrdinal,
    ) -> Result<Option<String>> {
        if mount == self.caller {
            return Ok(None);
        }
        if let Some(role) = self.source_roles.get(&mount) {
            return Ok(Some(role.clone()));
        }
        let role = self.operation.go_source_role_for_mount(
            self.demand.context_id,
            mount,
            self.cancellation,
        )?;
        if let Some(role) = &role {
            self.source_roles.insert(mount, role.clone());
        }
        Ok(role)
    }

    fn has_package_reference(
        &mut self,
        mount: SelectedResolutionMountOrdinal,
        token: SemanticId,
        domain: SemanticId,
        lookup: SemanticId,
    ) -> Result<bool> {
        Ok(matches!(
            self.operation.has_package_reference(
                mount,
                token,
                domain,
                lookup,
                self.cancellation
            )?,
            super::package_context::SelectedPackageRows::Ready(true)
        ))
    }

    /// The mounts that can hold the source half of a universal-root endpoint:
    /// the packages that import its first symbol and the mount that published
    /// it. `None` when no demanded or publishing mount is known: the endpoint
    /// then has no source half to discover, and reading every selected mount
    /// for one would make a request cost scale with the workspace's file count.
    fn root_source_mounts(
        &self,
        endpoint: &EndpointSignature,
    ) -> Result<Option<Vec<SelectedResolutionMountOrdinal>>> {
        let Some(root_semantic) = endpoint
            .symbols()
            .fixed()
            .first()
            .map(|symbol| symbol.symbol())
        else {
            return Ok(None);
        };
        let mut source_mounts = self
            .demand
            .import_packages
            .keys()
            .filter_map(|(mount, semantic)| (*semantic == root_semantic).then_some(*mount))
            .collect::<Vec<_>>();
        let lexical = self.operation.ready.lexical_source();
        match lexical.semantic_provenance(root_semantic, self.cancellation)? {
            Some(SelectedSemanticProvenance::FragmentLocal(provenance)) => {
                source_mounts.push(provenance.mount().ordinal());
            }
            Some(SelectedSemanticProvenance::Stage(provenance)) => {
                source_mounts.push(provenance.mount().ordinal());
            }
            Some(SelectedSemanticProvenance::Shared(_)) | None => {}
        }
        source_mounts.sort_unstable();
        source_mounts.dedup();
        Ok((!source_mounts.is_empty()).then_some(source_mounts))
    }

    fn source_demand(&mut self, endpoint: &EndpointSignature) -> Result<Option<GoSourceDemand>> {
        if endpoint.node() == BindingNodeId::universal_root()
            && endpoint.symbols().fixed().is_empty()
        {
            // Go source-demand discovery needs the root symbol below. An
            // empty root endpoint cannot identify a Go source half, so do not
            // scan every universal-root path to reach the same `None` result.
            return Ok(None);
        }
        let lexical = self.operation.ready.lexical_source();
        let root_source = match self.prepared_root_source_halves.remove(endpoint) {
            Some(prepared) => prepared,
            None => {
                let mounts = self.root_source_mount_scope(std::slice::from_ref(endpoint))?;
                super::source_demand::root_source_half(
                    &self.operation.ready,
                    self.base,
                    endpoint,
                    mounts.as_deref(),
                    self.session,
                    self.cancellation,
                )?
            }
        };
        if let Some(source) = root_source
            && let Some(mount) = self
                .operation
                .mount_table()
                .mount_for_fragment(source.key.fragment)?
                .filter(|mount| mount.semantic_language() == Language::Go)
            && let SelectedRootPathHalf::Reference {
                prefix_reference, ..
            } = &source.half
        {
            let is_qualified = prefix_reference.is_some();
            let source_role = self.source_role_for_mount(mount.ordinal())?;
            let root_semantic = endpoint
                .symbols()
                .fixed()
                .first()
                .expect("a Go reference root has a symbol")
                .symbol();
            return Ok(Some(GoSourceDemand {
                mount: mount.ordinal(),
                root_semantic,
                source_role,
                qualified: is_qualified.then_some(source.half),
                prefix_answer: None,
            }));
        }

        let symbols = endpoint.symbols().fixed();
        // Same-package bridges carry the source reference token, package
        // domain, and lookup as their three-symbol route. Verify all three
        // against the mount's selected package-reference rows before opening
        // that file's import context, as the JVM provider does.
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
                let mount = mount.ordinal();
                let record = self.operation.mount_table().mount_by_ordinal(mount)?;
                if record.semantic_language() == Language::Go
                    && self.has_package_reference(
                        mount,
                        token,
                        symbols[0].symbol(),
                        symbols[2].symbol(),
                    )?
                {
                    let source_role = self.source_role_for_mount(mount)?;
                    let root_semantic = endpoint
                        .symbols()
                        .fixed()
                        .first()
                        .expect("a Go same-package root has a symbol")
                        .symbol();
                    return Ok(Some(GoSourceDemand {
                        mount,
                        root_semantic,
                        source_role,
                        qualified: None,
                        prefix_answer: None,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Resolve a remote file's one-segment Go prefix in that file's context.
    /// The scheduler's base context belongs to the queried file, so it cannot
    /// answer an import name owned by a newly reached file until that file's
    /// prepared context is installed here.
    fn resolve_prefix_in_file_context(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        prefix: SemanticId,
    ) -> Result<Option<FactResolutionAnswer>> {
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(None);
        }
        let persisted_lexical = self.operation.ready.lexical_source();
        let typed = self.operation.ready.typed_source();
        let mut answer = None;
        blueprint.with_forward_operation_in_session(
            self.base,
            &persisted_lexical,
            &typed,
            self.cancellation,
            self.session,
            |operation| {
                answer = Some(operation.resolve_reference_with_metrics(
                    prefix,
                    &mut ResolutionBatchMetrics::default(),
                )?);
                Ok(())
            },
        )?;
        Ok(answer)
    }

    fn publish_context(
        &self,
        endpoint: &EndpointSignature,
        blueprint: &SelectedFactOperationBlueprint,
    ) -> Result<Option<()>> {
        let relation = DemandSelectedOverlayBlueprint::new(blueprint.context_token());
        let paths = self.operation.ready.lexical_source();
        let Some(candidates) = relation.added_candidate_paths(&paths, self.cancellation)? else {
            return Ok(None);
        };
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(None);
        }
        self.arena
            .borrow_mut()
            .publish(endpoint.clone(), relation, candidates);
        Ok(Some(()))
    }

    fn package_provider_mounts(
        &mut self,
        package: i64,
    ) -> Result<Option<Vec<SelectedResolutionMountOrdinal>>> {
        if let Some(mounts) = self.package_mounts.get(&package) {
            return Ok(Some(mounts.clone()));
        }
        let connection = self.operation.ready.inventory.connection();
        let mut statement = connection.prepare_cached(NAMED_IMPORT_TARGET_MOUNTS)?;
        let mut rows = statement.query(rusqlite::params![self.demand.context_id, package])?;
        let mut mounts = Vec::new();
        while let Some(row) = rows.next()? {
            if self.cancellation.is_cancelled() || !self.session.scope_step() {
                return Ok(None);
            }
            mounts.push(SelectedResolutionMountOrdinal::new(row.get(0)?));
        }
        self.package_mounts.insert(package, mounts.clone());
        Ok(Some(mounts))
    }

    fn root_source_mount_scope(
        &mut self,
        endpoints: &[EndpointSignature],
    ) -> Result<Option<Vec<SelectedResolutionMountOrdinal>>> {
        if self.remote_root_expansion != GoRemoteRootExpansion::CallerContextOnly
            || !endpoints.iter().any(|endpoint| {
                endpoint.node() == BindingNodeId::universal_root()
                    && endpoint.scopes().fixed().is_empty()
            })
        {
            return Ok(None);
        }

        let mut mounts = self.base_context_mounts.clone();
        mounts.insert(self.caller);
        let packages = self
            .demand
            .import_packages
            .iter()
            .filter_map(|((source, _), package)| mounts.contains(source).then_some(*package))
            .collect::<HashSet<_>>();
        for package in packages {
            let Some(providers) = self.package_provider_mounts(package)? else {
                break;
            };
            mounts.extend(providers);
        }
        let mut mounts = mounts.into_iter().collect::<Vec<_>>();
        mounts.sort_unstable_by_key(|mount| mount.get());
        Ok(Some(mounts))
    }

    fn export_halves(
        &mut self,
        mount: SelectedResolutionMountOrdinal,
        demand: SemanticId,
    ) -> Result<Option<Vec<SelectedRootPathHalf>>> {
        if !self.export_index.contains_key(&mount) {
            let lexical = self.operation.ready.lexical_source();
            let identities = self.operation.ready.context_identities.clone();
            let mut by_demand = HashMap::<SemanticId, Vec<SelectedRootPathHalf>>::default();
            let mut stopped = false;
            let outcome = visit_selected_root_export_half_pages(
                &identities,
                &lexical,
                &lexical,
                Some(&[mount]),
                self.cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    for half in page {
                        if !self.session.scope_step() {
                            stopped = true;
                            return Ok(false);
                        }
                        let SelectedRootPathHalf::Export { demand, .. } = half else {
                            unreachable!("export-only visitor")
                        };
                        by_demand.entry(*demand).or_default().push((*half).clone());
                    }
                    Ok(true)
                }),
            )?;
            if stopped || !outcome.is_exhausted() {
                return Ok(None);
            }
            self.export_index.insert(mount, by_demand);
        }
        Ok(Some(
            self.export_index
                .get(&mount)
                .expect("Go provider export index was inserted")
                .get(&demand)
                .cloned()
                .unwrap_or_default(),
        ))
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
        Ok(Some(blueprint))
    }

    fn go_import_prefix_discharges(
        &self,
        caller: BindingFragmentId,
        completion: &ResolutionCompletion,
        import_bindings: &HashSet<SemanticId>,
    ) -> Result<Option<Vec<SemanticId>>> {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Ok(Some(Vec::new()));
        };
        let semantics = reasons
            .iter()
            .map(|reason| match reason {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic) => Some(*semantic),
                _ => None,
            })
            .collect::<Option<Vec<_>>>();
        let Some(semantics) = semantics else {
            return Ok(Some(Vec::new()));
        };
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
        // The one-segment TypeOrValue prefix evaluator can mint operation-local
        // placeholders for its type/value interpretation of a package name.
        // A complete import binding proves that interpretation is a package.
        Ok(Some(
            if provenance.len() == owned_reasons.len()
                && semantics.iter().all(|semantic| {
                    import_bindings.contains(semantic)
                        || semantic.is_operation_local()
                        || owned_reasons.contains(semantic)
                })
            {
                semantics
            } else {
                Vec::new()
            },
        ))
    }
}

impl DemandLanguage for GoDemandLanguage<'_, '_, '_> {
    type RootQuestion = GoSourceDemand;
    type ContextKey = (SelectedResolutionMountOrdinal, String);
    type ContextData = GoPreparedDemandContext;

    fn discover_root(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<Self::RootQuestion>> {
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
        let Some(source) = source else {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        };
        if source.mount == self.caller && source.qualified.is_none() {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        if source.mount != self.caller
            && source.qualified.is_none()
            && self.base_context_mounts.contains(&source.mount)
        {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        if source.mount != self.caller
            && self.remote_root_expansion == GoRemoteRootExpansion::CallerContextOnly
            && !self.base_context_mounts.contains(&source.mount)
        {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        if source.mount != self.caller && source.source_role.is_none() {
            return Ok(LanguageRootDiscovery::Unavailable {
                reason: DemandRootUnavailableReason::IncompletePreparation,
                completion: ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(source.root_semantic),
                ]),
            });
        }
        Ok(LanguageRootDiscovery::Ready {
            question: source,
            completion: ResolutionCompletion::Complete,
        })
    }

    fn prepare_root_discoveries(&mut self, endpoints: &[EndpointSignature]) -> Result<()> {
        self.prepared_root_source_halves.clear();
        if endpoints.is_empty() {
            return Ok(());
        }
        // Reverse confirmation has a finite caller context: its selected
        // caller mounts and their imported Go package mounts. Forward demand
        // can admit more packages as roots are discovered, so it has no
        // bounded mount set to pass to the root visit.
        let mounts = self.root_source_mount_scope(endpoints)?;
        let halves = super::source_demand::root_source_halves_in_mounts(
            &self.operation.ready,
            self.base,
            endpoints,
            mounts.as_deref(),
            self.session,
            self.cancellation,
        )?;
        assert_eq!(halves.len(), endpoints.len());
        self.prepared_root_source_halves
            .extend(endpoints.iter().cloned().zip(halves));
        Ok(())
    }

    fn supports_batched_root_discoveries(&self) -> bool {
        true
    }

    fn context_key(&self, question: &Self::RootQuestion) -> Option<Self::ContextKey> {
        if question.mount == self.caller {
            return None;
        }
        question
            .source_role
            .as_ref()
            .map(|role| (question.mount, role.clone()))
    }

    fn prepare_context(
        &mut self,
        key: &Self::ContextKey,
        question: &Self::RootQuestion,
    ) -> Result<LanguageContextPreparation<Self::ContextData>> {
        assert_eq!(question.mount, key.0);
        assert_eq!(question.source_role.as_deref(), Some(key.1.as_str()));
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguageContextPreparation::Cancelled(cancelled_completion()));
        }
        let record = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(key.0)?;
        let prepared = match self.operation.go_file_import_context_with_role(
            self.demand.context_id,
            record.persisted_relative_path(),
            &key.1,
            self.cancellation,
        )? {
            GoPreparedImportContextOutcome::Ready(prepared) => *prepared,
            GoPreparedImportContextOutcome::Unavailable => {
                return Ok(LanguageContextPreparation::Unavailable(
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(question.root_semantic),
                    ]),
                ));
            }
            GoPreparedImportContextOutcome::Cancelled => {
                return Ok(LanguageContextPreparation::Cancelled(cancelled_completion()));
            }
        };
        let GoPreparedImportContext {
            context, demand, ..
        } = prepared;
        let completion = context.inventory_completion().clone();
        assert_eq!(
            demand.context_completions.get(&key.0),
            Some(&completion),
            "one prepared Go file context has one matching completion"
        );
        let Some(blueprint) = self.register_context(context)? else {
            return Ok(LanguageContextPreparation::Cancelled(cancelled_completion()));
        };
        // Go attaches inventory completion only to roots whose binding uses
        // that file's package/import context. The adapter decides that after
        // resolving a qualified prefix.
        Ok(LanguageContextPreparation::Ready {
            data: GoPreparedDemandContext {
                blueprint,
                demand,
                completion,
            },
            completion: ResolutionCompletion::Complete,
        })
    }

    fn prefix_inputs(
        &mut self,
        question: &mut Self::RootQuestion,
        context: Option<&Self::ContextData>,
    ) -> Result<LanguagePrefixInputs> {
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguagePrefixInputs {
                references: Vec::new(),
                completion: cancelled_completion(),
            });
        }
        let Some(half) = question.qualified.as_ref() else {
            return Ok(LanguagePrefixInputs {
                references: Vec::new(),
                completion: context.map_or_else(
                    || ResolutionCompletion::Complete,
                    |context| context.completion.clone(),
                ),
            });
        };
        let SelectedRootPathHalf::Reference {
            prefix_reference: Some(prefix),
            route,
            ..
        } = half
        else {
            unreachable!("Go qualified demand has a positioned reference")
        };
        assert!(
            route.is_empty(),
            "Go package qualifier has exactly one prefix segment"
        );
        let Some(context) = context else {
            assert_eq!(
                question.mount, self.caller,
                "a remote qualified root must have its own prepared context"
            );
            return Ok(LanguagePrefixInputs {
                references: vec![*prefix],
                completion: ResolutionCompletion::Complete,
            });
        };
        let Some(answer) = self.resolve_prefix_in_file_context(&context.blueprint, *prefix)? else {
            return Ok(LanguagePrefixInputs {
                references: Vec::new(),
                completion: cancelled_completion(),
            });
        };
        if answer
            .completion()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(LanguagePrefixInputs {
                references: Vec::new(),
                completion: answer.completion().clone(),
            });
        }
        let import_witness = answer.binding().targets().iter().any(|target| {
            context
                .demand
                .import_packages
                .contains_key(&(question.mount, *target))
        });
        question.prefix_answer = Some(answer);
        Ok(LanguagePrefixInputs {
            references: Vec::new(),
            completion: if import_witness {
                context.completion.clone()
            } else {
                ResolutionCompletion::Complete
            },
        })
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
        let Some(half) = source.qualified.as_ref() else {
            assert_ne!(
                source.mount, self.caller,
                "the caller's non-qualified roots are already in its prepared context"
            );
            assert!(inputs.is_empty(), "a file-context root has no prefix");
            let Some(context) = context else {
                return Ok(LanguageClosure {
                    completion: ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(source.root_semantic),
                    ]),
                    closed: true,
                    discharges: None,
                });
            };
            if self
                .publish_context(endpoint, &context.blueprint)?
                .is_none()
            {
                return Ok(LanguageClosure {
                    completion: cancelled_completion(),
                    closed: false,
                    discharges: None,
                });
            }
            return Ok(LanguageClosure {
                completion: context.completion.clone(),
                closed: true,
                discharges: None,
            });
        };
        let SelectedRootPathHalf::Reference {
            identity,
            prefix_reference: Some(prefix),
            token,
            anchor,
            anchor_semantic,
            demand,
            route,
            ..
        } = half
        else {
            unreachable!("Go demand contains a positioned qualified reference")
        };
        assert!(
            route.is_empty(),
            "Go package qualifier has exactly one prefix segment"
        );
        let answer = if let Some(answer) = source.prefix_answer.as_ref() {
            assert!(
                inputs.is_empty(),
                "pre-resolved Go prefix has no scheduler input"
            );
            answer
        } else {
            assert_eq!(inputs.len(), 1, "one Go lexical prefix");
            assert_eq!(inputs[0].0, *prefix);
            inputs[0].1
        };
        if source.mount != self.caller && context.is_none() {
            return Ok(LanguageClosure {
                completion: ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(source.root_semantic),
                ]),
                closed: true,
                discharges: None,
            });
        }
        assert_eq!(
            answer
                .site_metadata()
                .expect("positioned Go prefix metadata")
                .namespace(),
            ResolutionNamespace::TypeOrValue
        );
        let binding_completion = answer.binding().completion();
        let import_packages = context
            .map(|context| &context.demand.import_packages)
            .unwrap_or(&self.demand.import_packages);
        let package_targets = answer
            .binding()
            .targets()
            .iter()
            .filter_map(|target| {
                import_packages
                    .get(&(source.mount, *target))
                    .map(|package| (*target, *package))
            })
            .collect::<Vec<_>>();
        let context_completion = context
            .map(|context| context.completion.clone())
            .or_else(|| self.demand.context_completions.get(&source.mount).cloned())
            .expect("Go qualified source has a prepared context completion");
        let SelectedLookupRecipeReadOutcome::Ready(recipes) = self
            .operation
            .ready
            .lexical_source()
            .lookup_semantic_recipes(
                &[SelectedLookupRecipeRequest {
                    fragment: identity.fragment(),
                    semantic: *demand,
                }],
                self.cancellation,
                Some(self.session),
            )?
        else {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        };
        let recipe = recipes
            .into_iter()
            .next()
            .flatten()
            .ok_or_else(|| StoreError::corrupt("Go qualified demand lacks lookup recipe"))?;
        let mut bridges = Vec::new();
        let mut import_witness = false;
        let mut import_bindings = HashSet::default();
        let mut demanded_exports = Vec::new();
        for (target, package) in package_targets {
            if self.cancellation.is_cancelled() || !self.session.scope_step() {
                return Ok(LanguageClosure {
                    completion: cancelled_completion(),
                    closed: false,
                    discharges: None,
                });
            }
            import_witness = true;
            import_bindings.insert(target);
            let Some(provider_mounts) = self.package_provider_mounts(package)? else {
                return Ok(LanguageClosure {
                    completion: cancelled_completion(),
                    closed: false,
                    discharges: None,
                });
            };
            for provider_mount in provider_mounts {
                if self.cancellation.is_cancelled() || !self.session.scope_step() {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                }
                let Some(exports) = self.export_halves(provider_mount, *demand)? else {
                    return Ok(LanguageClosure {
                        completion: cancelled_completion(),
                        closed: false,
                        discharges: None,
                    });
                };
                if !exports.is_empty() && self.source_role_for_mount(provider_mount)?.is_none() {
                    if self.cancellation.is_cancelled() {
                        return Ok(LanguageClosure {
                            completion: cancelled_completion(),
                            closed: false,
                            discharges: None,
                        });
                    }
                    return Ok(LanguageClosure {
                        completion: ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(*demand),
                        ]),
                        closed: true,
                        discharges: None,
                    });
                }
                demanded_exports.extend(exports);
            }
        }
        let mut discharges = None;
        if import_witness && binding_completion == &ResolutionCompletion::Complete {
            // Only a complete import binding proves that a qualified prefix is
            // a package and can retire its source-owned placeholder reasons.
            let Some(retired) = self.go_import_prefix_discharges(
                identity.fragment(),
                answer.completion(),
                &import_bindings,
            )?
            else {
                return Ok(LanguageClosure {
                    completion: cancelled_completion(),
                    closed: false,
                    discharges: None,
                });
            };
            discharges = Some(DemandClosureDischarges::exact(retired));
        } else if !import_witness {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(LanguageClosure {
                completion: binding_completion.clone(),
                closed: true,
                discharges: None,
            });
        }
        if demanded_exports.is_empty() {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(LanguageClosure {
                completion: binding_completion.clone(),
                closed: true,
                discharges,
            });
        }
        let evidence = binding_completion.combine(&context_completion);
        for export in demanded_exports {
            let SelectedRootPathHalf::Export {
                identity: target,
                token: export_token,
                ..
            } = &export
            else {
                unreachable!("Go provider index contains exports")
            };
            bridges.push(
                SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                    identity.fragment(),
                    Language::Go,
                    *token,
                    *anchor,
                    *anchor_semantic,
                    target.fragment(),
                    Language::Go,
                    *export_token,
                    *prefix,
                    Vec::new(),
                    recipe.clone(),
                    recipe.clone(),
                    evidence.clone(),
                )
                .with_selected_export(&self.operation.ready.shared_names(), &export),
            );
        }
        // Publish only the qualified bridges introduced by this root. The
        // admitted file context remains the base source for its own references.
        let source_mount = self
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?;
        assert_eq!(source_mount.fragment(), identity.fragment());
        let selected_context = SelectedResolutionContextSet::new(
            self.operation.ready.context_identities.clone(),
            vec![SelectedResolutionMountContext::new(
                source.mount,
                source_mount.fragment(),
                Language::Go,
                bridges,
                evidence.clone(),
            )?],
            self.operation.mount_table().mount_count(),
            &selected_mount_lookup(self.operation.mount_table()),
        )?;
        let Some(blueprint) = self.register_context(selected_context)? else {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        };
        if self.publish_context(endpoint, &blueprint)?.is_none() {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        }
        Ok(LanguageClosure {
            completion: evidence,
            closed: true,
            discharges,
        })
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn stage_go_reference_batches(
        &self,
        context: GoForwardOperationContext<'_>,
        maximum_batch_size: usize,
        stager: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary> {
        let caller_mount = self
            .mount_table()
            .mount_for_path("go", context.caller_path)?
            .expect("selected Go batch caller has a source mount")
            .ordinal();
        if context.demand.needs_demand_provider_for(caller_mount) {
            self.with_go_forward_operation(context, None, |operation| {
                operation.stage_all_reference_batches(maximum_batch_size, stager)
            })
        } else {
            let persisted_lexical = self.ready.lexical_source();
            context.blueprint.with_forward_operation_in_session(
                context.lexical,
                &persisted_lexical,
                context.typed,
                context.cancellation,
                context.session,
                |operation| operation.stage_all_reference_batches(maximum_batch_size, stager),
            )
        }
    }

    pub(super) fn with_go_forward_operation<T>(
        &self,
        context: GoForwardOperationContext<'_>,
        artifacts: Option<&mut crate::analyzer::resolution::ForwardCandidateArtifactCache>,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_go_forward_operation_inner(
            context,
            artifacts,
            GoRemoteRootExpansion::FollowDemandedMounts,
            run,
        )
    }

    pub(super) fn with_go_reverse_confirmation_operation<T>(
        &self,
        context: GoForwardOperationContext<'_>,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_go_forward_operation_inner(
            context,
            None,
            GoRemoteRootExpansion::CallerContextOnly,
            run,
        )
    }

    fn with_go_forward_operation_inner<T>(
        &self,
        context: GoForwardOperationContext<'_>,
        artifacts: Option<&mut crate::analyzer::resolution::ForwardCandidateArtifactCache>,
        remote_root_expansion: GoRemoteRootExpansion,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let caller = self
            .mount_table()
            .mount_for_path("go", context.caller_path)?
            .expect("located Go reference has a selected caller mount");
        assert_eq!(caller.semantic_language(), Language::Go);
        let paths = self.ready.lexical_source();
        let base =
            context
                .blueprint
                .path_fragment_source(context.lexical, &paths, Some(context.session));
        let arena = RefCell::new(ClosedRelations::default());
        let source = ClosedForwardSource::new(&base, &paths, &arena, context.session);
        let base_context_mounts = context.demand.context_completions.keys().copied().collect();
        let provider = DemandProvider::new(GoDemandLanguage {
            operation: self,
            base: context.lexical,
            arena: &arena,
            session: context.session,
            cancellation: context.cancellation,
            demand: context.demand,
            caller: caller.ordinal(),
            remote_root_expansion,
            package_mounts: HashMap::default(),
            export_index: HashMap::default(),
            source_roles: HashMap::default(),
            base_context_mounts,
            prepared_root_source_halves: HashMap::default(),
        });
        if let Some(artifacts) = artifacts {
            context.blueprint.with_demand_operation_using_artifacts(
                &source,
                &paths,
                context.lexical,
                context.typed,
                provider,
                context.cancellation,
                context.session,
                artifacts,
                run,
            )
        } else {
            context.blueprint.with_demand_operation(
                &source,
                &paths,
                context.lexical,
                context.typed,
                provider,
                context.cancellation,
                context.session,
                run,
            )
        }
    }
}
