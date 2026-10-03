//! Java source contexts admitted only when a selected endpoint reaches them.
use super::jvm_context::JavaImportContext;
use super::package_context::SelectedPackageRows;
use super::rust_demand::relations::{ClosedForwardSource, ClosedRelations};
use super::*;
use crate::analyzer::resolution::{
    DemandRootDiscovery, DemandRootPlan, DemandRootProvider, DemandSelectedOverlayBlueprint,
    EndpointSignature, FactResolutionAnswer, LoweringGapOrigin, SelectedContextPathFragmentSource,
    SelectedResolutionMountContext,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

struct JavaSourceDemand {
    mount: SelectedResolutionMountOrdinal,
    qualified: Option<SelectedRootPathHalf>,
}

struct JavaProvider<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    base: &'a dyn BatchResolutionFragmentSource,
    arena: &'a RefCell<ClosedRelations>,
    session: &'a ResolutionSession,
    cancellation: &'a CancellationToken,
    caller: SelectedResolutionMountOrdinal,
    // All of these rows and registrations belong to this one query.
    contexts: HashMap<SelectedResolutionMountOrdinal, SelectedFactOperationBlueprint>,
    pending: HashMap<EndpointSignature, JavaSourceDemand>,
    /// Qualified closures whose prefix question this provider answered, with
    /// the prefix placeholder reasons that answer retired.
    discharges: HashMap<EndpointSignature, Vec<SemanticId>>,
}

impl JavaProvider<'_, '_, '_> {
    fn source_demand(&self, endpoint: &EndpointSignature) -> Result<Option<JavaSourceDemand>> {
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
                if record.semantic_language() == Language::Java {
                    let SelectedPackageRows::Ready(references) = self
                        .operation
                        .selected_package_references(mount.ordinal(), self.cancellation)?
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
                            return Ok(Some(JavaSourceDemand {
                                mount: mount.ordinal(),
                                qualified: None,
                            }));
                        }
                    }
                }
            }
        }

        let Some((source, half)) = super::source_demand::root_source_half(
            &self.operation.ready,
            self.base,
            endpoint,
            self.session,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        Ok(self
            .operation
            .mount_table()
            .mount_for_fragment(source.fragment)?
            .filter(|mount| mount.semantic_language() == Language::Java)
            .map(|mount| JavaSourceDemand {
                mount: mount.ordinal(),
                qualified: matches!(
                    &half,
                    SelectedRootPathHalf::Reference {
                        prefix_reference: Some(_),
                        ..
                    } | SelectedRootPathHalf::Reference {
                        anchor: ResolutionRootImportAnchor::Absolute,
                        prefix_reference: None,
                        ..
                    }
                )
                .then_some(half),
            }))
    }
}

impl DemandRootProvider for JavaProvider<'_, '_, '_> {
    fn discover(&mut self, endpoint: &EndpointSignature) -> Result<DemandRootDiscovery> {
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(DemandRootDiscovery::Cancelled(cancelled_completion()));
        }
        if endpoint.node() != BindingNodeId::universal_root() {
            return Ok(DemandRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        if self.arena.borrow().endpoints.contains_key(endpoint) {
            return Ok(DemandRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        let source = self.source_demand(endpoint)?;
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(DemandRootDiscovery::Cancelled(cancelled_completion()));
        }
        let Some(source) =
            source.filter(|source| source.mount != self.caller || source.qualified.is_some())
        else {
            self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            return Ok(DemandRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        };
        let prefixes = source
            .qualified
            .as_ref()
            .and_then(|half| match half {
                SelectedRootPathHalf::Reference {
                    prefix_reference, ..
                } => *prefix_reference,
                _ => unreachable!("qualified reference"),
            })
            .into_iter()
            .collect();
        self.pending.insert(endpoint.clone(), source);
        Ok(DemandRootDiscovery::Ready(DemandRootPlan {
            prefixes,
            completion: ResolutionCompletion::Complete,
        }))
    }

    fn close(
        &mut self,
        endpoint: &EndpointSignature,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> Result<ResolutionCompletion> {
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(cancelled_completion());
        }
        let source = self
            .pending
            .get(endpoint)
            .expect("Java endpoint was discovered");
        let mount = source.mount;
        let qualified = source.qualified.clone();
        let mut evidence = ResolutionCompletion::Complete;
        let qualified_blueprint;
        let blueprint = if let Some(half) = qualified {
            let SelectedRootPathHalf::Reference {
                identity,
                prefix_reference,
                anchor,
                ..
            } = &half
            else {
                unreachable!("qualified Java reference");
            };
            let package_lookup = if let Some(prefix) = prefix_reference {
                assert_eq!(inputs.len(), 1, "one Java lexical prefix");
                assert_eq!(inputs[0].0, *prefix);
                let answer = inputs[0].1;
                // A lexical Type interpretation owns the whole qualified name.
                // Its existing typed member chain supplies any nested target.
                let type_interpretation = !answer.binding().targets().is_empty();
                if type_interpretation {
                    evidence = answer.completion().clone();
                    if evidence == ResolutionCompletion::Complete {
                        self.discharges.insert(endpoint.clone(), Vec::new());
                    }
                } else {
                    let Some(prefix) = self
                        .java_package_prefix_evidence(identity.fragment(), answer.completion())?
                    else {
                        return Ok(cancelled_completion());
                    };
                    match prefix {
                        JavaPackagePrefix::Witness(retired) => {
                            self.discharges.insert(endpoint.clone(), retired);
                        }
                        JavaPackagePrefix::Retained(completion) => evidence = completion,
                    }
                }
                !type_interpretation
            } else {
                assert_eq!(*anchor, ResolutionRootImportAnchor::Absolute);
                assert!(
                    inputs.is_empty(),
                    "absolute Java route has no lexical prefix"
                );
                true
            };
            let bridges = if package_lookup {
                let Some(bridges) = self.operation.java_qualified_type_bridges(
                    &half,
                    &evidence,
                    self.cancellation,
                )?
                else {
                    return Ok(cancelled_completion());
                };
                bridges
            } else {
                Vec::new()
            };
            // Prefix evaluation already admits any provider-file imports it
            // needs. This relation owns only the new reference bridges; adding
            // the whole file context would collide with caller base paths.
            let record = self.operation.mount_table().mount_by_ordinal(mount)?;
            let context = SelectedResolutionContextSet::new(
                self.operation.ready.context_identities.clone(),
                vec![SelectedResolutionMountContext::new(
                    mount,
                    record.fragment(),
                    Language::Java,
                    bridges,
                    evidence.clone(),
                )?],
                self.operation.mount_table().mount_count(),
                &selected_mount_lookup(self.operation.mount_table()),
            )?;
            let Some(blueprint) = self.register_context(context)? else {
                return Ok(cancelled_completion());
            };
            qualified_blueprint = blueprint;
            &qualified_blueprint
        } else {
            assert!(inputs.is_empty(), "file context has no prefix");
            if !self.contexts.contains_key(&mount) {
                let Some(context) = self.file_context(mount)? else {
                    return Ok(cancelled_completion());
                };
                let Some(blueprint) = self.register_context(context)? else {
                    return Ok(cancelled_completion());
                };
                self.contexts.insert(mount, blueprint);
            }
            &self.contexts[&mount]
        };
        let relation = DemandSelectedOverlayBlueprint::new(blueprint.context_token());
        let paths = self.operation.ready.lexical_source();
        let Some(candidates) = relation.added_candidate_paths(&paths, self.cancellation)? else {
            return Ok(cancelled_completion());
        };
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(cancelled_completion());
        }
        self.arena
            .borrow_mut()
            .publish(endpoint.clone(), relation, candidates);
        // Semantic coverage is carried by each compiled candidate, not attached
        // globally to unrelated roots reached later in this operation.
        Ok(evidence)
    }

    fn resolved_closure_discharges(&self, endpoint: &EndpointSignature) -> Option<Vec<SemanticId>> {
        self.discharges.get(endpoint).cloned()
    }
}

/// How a qualified prefix that binds no type within the enumerated source is
/// read (JLS 6.5.2).
enum JavaPackagePrefix {
    /// The prefix is a package name. Its lexical tail stopped only at this
    /// compilation unit's placement boundary and at the ambiguity of the
    /// qualified name itself; those placeholder reasons are retired and the
    /// package interpretation carries its own positive witness, exactly as a
    /// single-type import does.
    Witness(Vec<SemanticId>),
    /// Some other reason (hierarchy, visibility, activation, a foreign
    /// fragment) keeps the type interpretation open, so the qualified route
    /// keeps the prefix completion.
    Retained(ResolutionCompletion),
}

impl JavaProvider<'_, '_, '_> {
    /// Decision recorded in the Java rollout plan (2026-09-29).
    fn java_package_prefix_evidence(
        &self,
        caller: BindingFragmentId,
        completion: &ResolutionCompletion,
    ) -> Result<Option<JavaPackagePrefix>> {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Ok(Some(JavaPackagePrefix::Witness(Vec::new())));
        };
        let mut semantics = Vec::new();
        for reason in reasons.iter() {
            let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
                return Ok(Some(JavaPackagePrefix::Retained(completion.clone())));
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
                .all(|semantic| owned_reasons.contains(semantic));
        Ok(Some(if package_witness {
            JavaPackagePrefix::Witness(semantics)
        } else {
            JavaPackagePrefix::Retained(completion.clone())
        }))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_java_forward_operation<T>(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        caller_path: &str,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let caller = self
            .mount_table()
            .mount_for_path("java", caller_path)?
            .expect("located Java reference has a selected caller mount")
            .ordinal();
        let paths = self.ready.lexical_source();
        let base = SelectedContextPathFragmentSource::new(
            lexical,
            &paths,
            blueprint.context_token(),
            None,
        );
        let arena = RefCell::new(ClosedRelations::default());
        let source = ClosedForwardSource::new(&base, &paths, &arena, session);
        let provider = JavaProvider {
            operation: self,
            base: lexical,
            arena: &arena,
            session,
            cancellation,
            caller,
            contexts: HashMap::default(),
            pending: HashMap::default(),
            discharges: HashMap::default(),
        };
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

impl JavaProvider<'_, '_, '_> {
    fn file_context(
        &self,
        mount: SelectedResolutionMountOrdinal,
    ) -> Result<Option<SelectedResolutionContextSet>> {
        let record = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount)?;
        match self
            .operation
            .java_import_context(record.persisted_relative_path(), self.cancellation)?
        {
            JavaImportContext::Ready { context, .. } => Ok(Some(*context)),
            JavaImportContext::Cancelled => Ok(None),
            JavaImportContext::Unavailable => Err(StoreError::new(
                "selected Java provider context became unavailable".to_owned(),
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
