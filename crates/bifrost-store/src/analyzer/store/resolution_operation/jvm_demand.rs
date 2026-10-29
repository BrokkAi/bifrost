//! JVM source contexts admitted only when a selected endpoint reaches them.
use super::demand::{
    ClosedForwardSource, ClosedRelations, LanguageContextPreparation, LanguageRootDiscovery,
};
use super::demand_closure::{BaseEligibility, ClosureWitness, Read};
use super::imports::SelectedImportRouteKind;
use super::jvm_context::{
    JvmImportContext, JvmImportContextGap, jvm_prefix_defers_member_selection,
};
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::DemandReferenceKey;
use crate::analyzer::resolution::DemandRelationKey;
use crate::analyzer::resolution::{
    BindingOrigin, DemandMemberSelection, DemandMemberSelectionRequest,
    DemandSelectedOverlayBlueprint, EndpointSignature, FactResolutionAnswer,
    JvmImplicitRootProvider, LoweringGapOrigin, SelectedResolutionMountContext,
    binding_origin_rank, language_implicit_root_providers,
    language_implicit_root_providers_in_namespace,
};
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, ResolutionGapKind, ResolutionRootImportKind,
};

pub(in crate::analyzer) fn jvm_root_import_origin(
    language: Language,
    kind: ResolutionRootImportKind,
) -> BindingOrigin {
    nominal_rules::nominal_language_rules(language)
        .expect("caller belongs to a nominal family")
        .root_import_origin(kind)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct JvmBindingPrecedence {
    // Match shared path precedence: binding origin before lexical depth.
    pub(super) rank: u32,
    depth: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct JvmImportBinding {
    pub(super) reference: SemanticId,
    pub(super) token: SemanticId,
    pub(super) precedence: JvmBindingPrecedence,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Internal lowering references publish no authored metadata. Every JVM
    /// precedence scan must establish the published kind before a lexical read.
    fn jvm_authored_reference_local_path_evidence(
        &self,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<crate::analyzer::resolution::ReferenceLocalPathEvidence>> {
        let lexical = self.ready.lexical_source();
        let Some(seed) = lexical.reference_seed(ResolutionQuery::new(reference), cancellation)?
        else {
            return Ok(None);
        };
        if !seed
            .site_metadata()
            .is_some_and(|metadata| metadata.site_kind() != ResolutionSiteKind::SyntheticReference)
        {
            return Ok(None);
        }
        lexical.reference_local_path_evidence(reference, cancellation)
    }

    /// Match import binders against the existing lexical path evidence. The
    /// reader already walked these scopes; JVM code only supplies import rules.
    pub(super) fn jvm_import_bindings_for_lookup(
        &self,
        mount: SelectedResolutionMountOrdinal,
        lookup: &ResolutionLookupSemanticRecipe,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<JvmImportBinding>>> {
        let record = self.ready.inventory.mount_record_by_ordinal(mount)?;
        let connection = self.ready.inventory.connection();
        let lexical = self.ready.lexical_source();
        let names = self.ready.shared_names();
        let lookup_semantic = lookup.semantic(&names);
        let mut binders = Vec::new();
        let outcome = crate::analyzer::resolution::visit_selected_root_import_half_pages(
            &self.ready.context_identities,
            &lexical,
            &lexical,
            Some(&[mount]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                for half in page {
                    let SelectedRootPathHalf::Import {
                        token,
                        demand,
                        source_scope_head,
                        activation,
                        ..
                    } = half
                    else {
                        continue;
                    };
                    // The half's demand is the lookup bound in the importing
                    // scope, including for wildcard imports. The owner route
                    // is separate; another demand through that same wildcard
                    // is not a competing binder for this name or namespace.
                    if *demand != lookup_semantic {
                        continue;
                    }
                    let Some(metadata) = self.jvm_import_token_metadata(
                        record.blob_id(),
                        mount,
                        *token,
                        cancellation,
                    )?
                    else {
                        return Ok(false);
                    };
                    let selector = &metadata.selector;
                    let route = &metadata.route;
                    let wildcard = selector
                        .as_ref()
                        .is_some_and(|selector| selector.source_name.is_none())
                        || route.as_ref().is_some_and(|route| {
                            matches!(
                                route.kind,
                                SelectedImportRouteKind::TypeOnDemand
                                    | SelectedImportRouteKind::StaticOnDemand
                            )
                        });
                    let origin = jvm_root_import_origin(
                        record.semantic_language(),
                        if wildcard {
                            ResolutionRootImportKind::Glob
                        } else {
                            ResolutionRootImportKind::Named
                        },
                    );
                    let rank = binding_origin_rank(record.semantic_language(), origin);
                    if let Some(rank) = rank {
                        binders.push((*token, *source_scope_head, *activation, rank));
                    }
                }
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() || cancellation.is_cancelled() {
            return Ok(None);
        }
        binders.sort_unstable();
        binders.dedup();
        // SyntheticReference publishes no site kind or authored metadata.
        // Only published, lowered sites can enter the lexical metadata reader.
        let mut statement = connection.prepare_cached(
            "SELECT DISTINCT semantic.semantic_key
             FROM main.resolution_identities AS lookup
             CROSS JOIN main.resolution_paths AS path
               ON path.blob_id=?1 AND path.end_lead_identity=lookup.id
             JOIN main.resolution_node_catalog AS node
               ON node.blob_id=path.blob_id AND node.local_key=path.start_node
             JOIN main.resolution_semantic_sites AS semantic
               ON semantic.blob_id=node.blob_id AND semantic.semantic_key=node.semantic_local_key
              AND semantic.semantic_role='reference'
             JOIN main.resolution_sites AS authored
               ON authored.blob_id=semantic.blob_id AND authored.site=semantic.source_site
              AND authored.site_kind IS NOT NULL
             WHERE lookup.identity_digest=?2",
        )?;
        let references = statement.query_map(
            rusqlite::params![record.blob_id(), lookup.name_digest().as_slice()],
            |row| row.get::<_, u32>(0),
        )?;
        let mut result = Vec::new();
        for reference in references {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let reference = SemanticId::local(mount.get(), reference?);
            let Some(evidence) =
                self.jvm_authored_reference_local_path_evidence(reference, cancellation)?
            else {
                continue;
            };
            if !evidence.metadata().unqualified()
                || !evidence.local_bindings_certified()
                || !evidence.local_definitions().is_empty()
            {
                continue;
            }
            for &(token, scope, activation, rank) in &binders {
                if activation.is_some_and(|start| evidence.metadata().start_byte() < start as usize)
                {
                    continue;
                }
                if let Some(depth) = evidence
                    .lexical_scopes()
                    .iter()
                    .filter(|(node, _)| *node == scope)
                    .map(|(_, depth)| *depth)
                    .min()
                {
                    result.push(JvmImportBinding {
                        reference,
                        token,
                        precedence: JvmBindingPrecedence { depth, rank },
                    });
                }
            }
        }
        result
            .sort_unstable_by_key(|binding| (binding.reference, binding.precedence, binding.token));
        result.dedup_by_key(|binding| (binding.reference, binding.precedence, binding.token));
        self.profile_jvm_read("import_bound_references", (lookup, &result));
        Ok(Some(result))
    }
}

fn jvm_implicit_provider_gap(language: Language, gap: &JvmImportContextGap) -> bool {
    language_implicit_root_providers(language)
        .iter()
        .any(|provider| match provider {
            JvmImplicitRootProvider::Package(package) => {
                gap.kind == "jvm-default-import-package-open"
                    && gap.owner.as_deref() == Some(*package)
            }
            JvmImplicitRootProvider::ScalaPredef => gap.kind == "scala-predef-route-open",
        })
}

struct JvmSourceDemand {
    mount: SelectedResolutionMountOrdinal,
    lookup: SemanticId,
    qualified: Option<SelectedRootPathHalf>,
    qualified_completion: Option<ResolutionCompletion>,
    caller_scoped_source: Option<JvmCallerScopedSource>,
    caller_gap_reasons: Vec<ResolutionIncompleteReason>,
    caller_discharged_provider_reasons: BTreeSet<SemanticId>,
    caller_positive_binding_providers: BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    import_qualifiers: Option<(SelectedRootPathHalf, Box<[SemanticId]>)>,
}

impl JvmSourceDemand {
    #[cfg(any(test, feature = "test-support"))]
    fn route_kind(&self) -> &'static str {
        if self.import_qualifiers.is_some() {
            return "scala-import-qualifiers";
        }
        match self.qualified.as_ref() {
            Some(SelectedRootPathHalf::Reference {
                prefix_reference: Some(_),
                ..
            }) => "positioned-prefix",
            Some(SelectedRootPathHalf::Reference {
                owner_continued: true,
                ..
            }) => "owner-continuation",
            Some(SelectedRootPathHalf::Reference {
                anchor: ResolutionRootImportAnchor::Absolute,
                ..
            }) => "absolute-package",
            Some(_) => "lexical-qualified",
            None => match self.caller_scoped_source {
                Some(JvmCallerScopedSource::Import { .. }) => "import-context",
                Some(JvmCallerScopedSource::ImplicitRootReference { .. }) => "unqualified-context",
                None => "provider-context",
            },
        }
    }
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct JvmPreparedNameKey {
    lookup: SemanticId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct JvmCallerContextKey {
    name: String,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

type JvmContextDelta = (
    DemandSelectedOverlayBlueprint,
    Vec<(CandidatePathIdentity, PartialPath)>,
);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct JvmProviderRegistrationKey {
    mount: SelectedResolutionMountOrdinal,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type JvmContextRegistrationMemo =
    super::context_preparation::ContextRegistrationMemo<JvmProviderRegistrationKey>;

struct JvmPreparedNameContext {
    blueprint: SelectedFactOperationBlueprint,
    scoped_gaps: Vec<JvmImportContextGap>,
}

struct JvmPreparedContext {
    contexts: RefCell<HashMap<JvmPreparedNameKey, JvmPreparedNameContext>>,
}

enum JvmPendingRegistration {
    Caller(JvmCallerContextKey),
    Provider(JvmPreparedNameKey, Vec<JvmImportContextGap>),
}

// Keep prepared contexts inline; registered publications need no payload.
#[allow(clippy::large_enum_variant)]
enum JvmNamePublication {
    Prepared(SelectedResolutionContextSet),
    Registered,
}

enum JvmNameContextKey {
    Caller(JvmCallerContextKey),
    Provider {
        context: super::demand_closure::ContextId,
        name: JvmPreparedNameKey,
    },
}

struct JvmDemandState<'a, 'store, 'input> {
    rules: &'static dyn nominal_rules::NominalLanguageRules,
    family: &'static dyn nominal_rules::NominalPackageRules,
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    base: &'a dyn BatchResolutionFragmentSource,
    initial: crate::analyzer::resolution::SelectedContextPathToken,
    arena: &'a RefCell<ClosedRelations>,
    session: &'a ResolutionSession,
    cancellation: &'a CancellationToken,
    caller: SelectedResolutionMountOrdinal,
    // Whole-file consumers supply their existing import proof. A point
    // context may admit additional names, but must not reopen that proof.
    whole_file_import_gaps: Option<&'a [JvmImportContextGap]>,
    caller_scoped_gaps: Option<Vec<JvmImportContextGap>>,
    caller_context_lookups: HashSet<(String, (u64, u64))>,
    caller_registered_contexts: HashMap<JvmCallerContextKey, SelectedFactOperationBlueprint>,
    import_bindings: RefCell<
        HashMap<
            (
                SelectedResolutionMountOrdinal,
                ResolutionLookupSemanticRecipe,
            ),
            Vec<JvmImportBinding>,
        >,
    >,
    selected_import_gap: Option<(SemanticId, SemanticId)>,
    pending_registration: Option<JvmPendingRegistration>,
}

impl JvmDemandState<'_, '_, '_> {
    fn jvm_import_bindings_for_lookup(
        &self,
        mount: SelectedResolutionMountOrdinal,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Option<Vec<JvmImportBinding>>> {
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        let key = (mount, lookup.clone());
        if let Some(bindings) = self.import_bindings.borrow().get(&key) {
            return Ok(Some(bindings.clone()));
        }
        let Some(bindings) =
            self.operation
                .jvm_import_bindings_for_lookup(mount, lookup, self.cancellation)?
        else {
            return Ok(None);
        };
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        self.import_bindings
            .borrow_mut()
            .insert(key, bindings.clone());
        Ok(Some(bindings))
    }

    fn context_key(&self, question: &JvmSourceDemand) -> Option<SelectedResolutionMountOrdinal> {
        (question.mount != self.caller && question.qualified.is_none()).then_some(question.mount)
    }

    fn prepare_context(
        &mut self,
        key: &SelectedResolutionMountOrdinal,
        question: &JvmSourceDemand,
    ) -> Result<LanguageContextPreparation<JvmPreparedContext>> {
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
                contexts: RefCell::new(HashMap::default()),
            },
            completion: ResolutionCompletion::Complete,
        })
    }

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
            policy: &crate::analyzer::resolution::DEFAULT_HIERARCHY_POLICY,
            order: Some(crate::analyzer::resolution::HierarchyOrderRequest {
                policy: &super::jvm_hierarchy_order::JVM_DECLARED_ORDER,
                start_after: None,
            }),
            reference: *qualifiers
                .first()
                .expect("a selected owner has positioned inputs"),
            values: values.to_vec(),
            lookup,
            namespace: recipe.namespace(),
            language: Language::Scala,
        }))
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
                if self.family.admits(record.semantic_language()) {
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
                            // This selected package reference proves the local
                            // source token's mount. Other mounts cannot carry a
                            // source half for that exact token.
                            let root_half = super::source_demand::root_source_half(
                                &self.operation.ready,
                                self.base,
                                endpoint,
                                Some(&[mount.ordinal()]),
                                self.session,
                                self.cancellation,
                            )?;
                            if let Some(source) = root_half {
                                let qualified = matches!(
                                    &source.half,
                                    SelectedRootPathHalf::Reference {
                                        prefix_reference: Some(_),
                                        ..
                                    } | SelectedRootPathHalf::Reference {
                                        owner_continued: true,
                                        ..
                                    } | SelectedRootPathHalf::Reference {
                                        anchor: ResolutionRootImportAnchor::Absolute,
                                        ..
                                    }
                                );
                                if qualified {
                                    return self.source_demand_from_root(source);
                                }
                            }
                            // A package reference still depends on its caller's
                            // import inventories when it has no owner continuation.
                            let caller_scoped_source =
                                (!language_implicit_root_providers_in_namespace(
                                    record.semantic_language(),
                                    reference.namespace,
                                )
                                .is_empty())
                                .then_some(JvmCallerScopedSource::ImplicitRootReference {
                                    token: reference.token,
                                    demand: reference.lookup,
                                });
                            return Ok(Some(JvmSourceDemand {
                                mount: mount.ordinal(),
                                lookup: reference.lookup,
                                qualified: None,
                                qualified_completion: None,
                                caller_scoped_source,
                                caller_gap_reasons: Vec::new(),
                                caller_discharged_provider_reasons: BTreeSet::new(),
                                caller_positive_binding_providers: BTreeMap::new(),
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
            .filter(|mount| self.family.admits(mount.semantic_language()))
        else {
            return Ok(None);
        };
        let source_language = mount.semantic_language();
        let import_qualifiers = if nominal_rules::nominal_language_rules(source_language)
            .expect("source belongs to a nominal family")
            .lexical_import_anchors()
            .contains(&ResolutionRootImportAnchor::Lexical)
        {
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
        let lookup = match &source.half {
            SelectedRootPathHalf::Import { demand, .. }
            | SelectedRootPathHalf::Reference { demand, .. } => *demand,
            SelectedRootPathHalf::Export { .. } => {
                unreachable!("a demanded root has a source lookup")
            }
        };
        Ok(Some(JvmSourceDemand {
            mount: mount.ordinal(),
            lookup,
            qualified: qualified.then_some(source.half),
            qualified_completion: qualified.then_some(source.completion),
            caller_scoped_source,
            caller_gap_reasons: Vec::new(),
            caller_discharged_provider_reasons: BTreeSet::new(),
            caller_positive_binding_providers: BTreeMap::new(),
            import_qualifiers,
        }))
    }

    fn caller_import_gaps(&self) -> &[JvmImportContextGap] {
        self.whole_file_import_gaps.unwrap_or_else(|| {
            self.caller_scoped_gaps
                .as_deref()
                .expect("caller import gaps were loaded")
        })
    }

    // Compare providers only after an actual binding with complete inventory
    // has been proved. An empty provider set never shadows an unavailable one.
    fn complete_binding_origin_rank(
        &self,
        context: &SelectedResolutionContextSet,
        source: &JvmSourceDemand,
        tokens: &[SemanticId],
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Option<JvmBindingPrecedence>> {
        use crate::analyzer::resolution::TypedFactPageVisitor;
        let mount = self
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?;
        let (roots, packages) = context.qualified_reference_bridges(
            mount.fragment(),
            tokens,
            std::slice::from_ref(lookup),
            &self.operation.ready.shared_names(),
        );
        self.operation.profile_jvm_read(
            "binding_precedence_inputs",
            (lookup, tokens, &roots, &packages),
        );
        let Some(import_bindings) = self.jvm_import_bindings_for_lookup(source.mount, lookup)?
        else {
            return Ok(None);
        };
        let mut rank = None;
        // Read the selected reference/declaration packages, including staged
        // source, rather than infer a provider from a spelling or a file path.
        let mut references = Vec::new();
        let mut package_depth = u32::MAX;
        for &token in tokens {
            let SelectedPackageRows::Ready(rows) = self
                .operation
                .selected_package_reference_for_token(source.mount, token, self.cancellation)?
            else {
                return Ok(None);
            };
            for row in rows {
                let Some(evidence) = self
                    .operation
                    .jvm_authored_reference_local_path_evidence(row.reference, self.cancellation)?
                else {
                    continue;
                };
                package_depth = package_depth.min(
                    evidence
                        .lexical_scopes()
                        .iter()
                        .filter(|(node, _)| *node == row.root_scope)
                        .map(|(_, depth)| *depth)
                        .min()
                        .unwrap_or(u32::MAX),
                );
                references.push(row.reference);
            }
        }
        references.sort_unstable();
        references.dedup();
        for binding in &import_bindings {
            let selected_reference = references.contains(&binding.reference)
                || matches!(source.caller_scoped_source, Some(JvmCallerScopedSource::Import { token, .. }) if token == binding.token);
            if selected_reference
                && self
                    .operation
                    .ready
                    .context_identities
                    .jvm_external_provider_type_identity_for_reference(
                        crate::analyzer::resolution::ExternalOwnerLanguage::Jvm,
                        binding.reference,
                    )
                    .and_then(|identity| {
                        self.operation
                            .ready
                            .context_identities
                            .external_owner_identity(identity)
                    })
                    .is_some()
            {
                rank = rank.into_iter().chain(Some(binding.precedence)).min();
            }
        }
        for bridge in &roots {
            if bridge.binding_origin_rank().is_none() {
                continue;
            }
            for binding in import_bindings.iter().filter(|binding| {
                binding.token == bridge.source_import_token()
                    && references.contains(&binding.reference)
            }) {
                rank = rank.into_iter().chain(Some(binding.precedence)).min();
            }
        }
        let package_bindings = packages.iter().filter(|bridge| {
            matches!(
                lookup.namespace(),
                ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
            ) || *bridge.completion() == ResolutionCompletion::Complete
        });
        rank = rank
            .into_iter()
            .chain(
                package_bindings
                    .clone()
                    .filter_map(|bridge| bridge.binding_origin_rank())
                    .map(|rank| JvmBindingPrecedence {
                        depth: package_depth,
                        rank,
                    }),
            )
            .min();
        let mut definitions = package_bindings
            .filter_map(|bridge| bridge.binding_definition())
            .collect::<Vec<_>>();
        definitions.sort_unstable();
        definitions.dedup();
        if !references.is_empty() && !definitions.is_empty() {
            let mut semantics = references.clone();
            for nodes in definitions.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                semantics.extend(
                    self.operation
                        .ready
                        .lexical_source()
                        .classify_endpoint_nodes(nodes, self.cancellation)?
                        .into_iter()
                        .filter_map(|row| row.definition()),
                );
            }
            semantics.sort_unstable();
            semantics.dedup();
            let mut endpoints = Vec::new();
            for semantics in semantics.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                let Some(rows) = self
                    .operation
                    .ready
                    .typed_source()
                    .jvm_access_endpoints(semantics, self.cancellation)?
                else {
                    return Ok(None);
                };
                endpoints.extend(rows);
            }
            self.operation.profile_jvm_read(
                "binding_precedence_packages",
                (&references, &definitions, &endpoints),
            );
            let source_packages = endpoints
                .iter()
                .filter(|row| references.contains(&row.semantic))
                .map(|row| &row.package)
                .collect::<Vec<_>>();
            for target in endpoints
                .iter()
                .filter(|row| !references.contains(&row.semantic))
            {
                let language = mount.semantic_language();
                let same_package = source_packages
                    .iter()
                    .any(|package| **package == target.package);
                let default_package = target.package.as_ref().is_some_and(|package| {
                    language_implicit_root_providers(language).iter().any(|provider| {
                        matches!(provider, JvmImplicitRootProvider::Package(name) if *name == package)
                    })
                });
                let package_rank = if same_package {
                    binding_origin_rank(language, BindingOrigin::SamePackage).or_else(|| {
                        binding_origin_rank(language, BindingOrigin::OtherCompilationUnitPackage)
                    })
                } else if default_package {
                    binding_origin_rank(language, BindingOrigin::DefaultImport)
                } else {
                    None
                };
                rank = rank
                    .into_iter()
                    .chain(package_rank.map(|rank| JvmBindingPrecedence {
                        depth: package_depth,
                        rank,
                    }))
                    .min();
            }
        }
        let semantic = lookup.semantic(&self.operation.ready.shared_names());
        let SelectedPackageRows::Ready(members) = self.operation.jvm_package_members_for_lookup(
            source.mount,
            semantic,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        if !members.is_empty() {
            let local = binding_origin_rank(
                mount.semantic_language(),
                BindingOrigin::SameCompilationUnitPackage,
            );
            rank = rank
                .into_iter()
                .chain(local.map(|rank| JvmBindingPrecedence {
                    depth: package_depth,
                    rank,
                }))
                .min();
        }
        let typed = self.operation.ready.typed_source();
        let mut qualifier_slots = Vec::new();
        for chunk in references.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let read = typed.visit_binding_projection_pages_for_references(
                TypedFactRequest::new(chunk),
                self.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    qualifier_slots.extend(page.iter().map(|row| row.row().output_slot()));
                    Ok(true)
                }),
            )?;
            if !read.is_exhausted() || read.evidence() != &ResolutionCompletion::Complete {
                return Ok(rank);
            }
        }
        qualifier_slots.sort_unstable();
        qualifier_slots.dedup();
        let mut type_qualifier = false;
        for chunk in qualifier_slots.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let read = typed.visit_qualified_route_pages_for_qualifier_slots(
                TypedFactRequest::new(chunk),
                self.cancellation,
                &mut TypedFactPageVisitor::new(&mut |page| {
                    type_qualifier |= page.iter().any(|route| {
                        matches!(
                            route.row().namespace(),
                            ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
                        )
                    });
                    Ok(true)
                }),
            )?;
            if !read.is_exhausted() || read.evidence() != &ResolutionCompletion::Complete {
                return Ok(rank);
            }
        }
        if type_qualifier
            && matches!(
                lookup.namespace(),
                ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
            )
            && let Some(origin_rank) =
                binding_origin_rank(mount.semantic_language(), BindingOrigin::RootPackage)
        {
            let package_present: bool = self.operation.ready.inventory.connection().query_row(
                self.family.package_prefix_presence_sql(),
                [lookup.spelling()],
                |row| row.get(0),
            )?;
            if package_present {
                // A qualified package prefix is a positive binding in the
                // workspace root, outside lexical scopes and before implicit imports.
                rank = rank
                    .into_iter()
                    .chain(Some(JvmBindingPrecedence {
                        depth: u32::MAX - 1,
                        rank: origin_rank,
                    }))
                    .min();
            }
        }
        Ok(rank)
    }

    fn complete_external_type_receiver(&self, reference: SemanticId) -> Result<bool> {
        use crate::analyzer::resolution::{TypedFactPageVisitor, TypedFactRequest};
        use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;
        let typed = self.operation.ready.typed_source();
        let mut qualifier_slots = Vec::new();
        let routes = typed.visit_qualified_route_pages_for_references(
            TypedFactRequest::new(&[reference]),
            self.cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                qualifier_slots.extend(page.iter().map(|route| route.row().qualifier_slot()));
                Ok(true)
            }),
        )?;
        qualifier_slots.sort_unstable();
        qualifier_slots.dedup();
        self.operation.profile_jvm_read(
            "binding_receiver_routes",
            (reference, &qualifier_slots, &routes),
        );
        if !routes.is_exhausted()
            || routes.evidence() != &ResolutionCompletion::Complete
            || qualifier_slots.len() != 1
        {
            return Ok(false);
        }
        let mut receivers = Vec::new();
        let projections = typed.visit_binding_projection_pages_for_outputs(
            TypedFactRequest::new(&qualifier_slots),
            self.cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                receivers.extend(
                    page.iter()
                        .filter(|row| {
                            matches!(
                                row.row().kind(),
                                BindingProjectionKind::TargetTypeIdentity
                                    | BindingProjectionKind::TargetNominalTypeIdentity
                                    | BindingProjectionKind::TargetTypeOrDeclaredValueType
                            )
                        })
                        .map(|row| row.row().reference()),
                );
                Ok(true)
            }),
        )?;
        receivers.sort_unstable();
        receivers.dedup();
        self.operation.profile_jvm_read(
            "binding_receiver_projections",
            (reference, &receivers, &projections),
        );
        if !projections.is_exhausted()
            || projections.evidence() != &ResolutionCompletion::Complete
            || receivers.len() != 1
        {
            return Ok(false);
        }
        let receiver = receivers[0];
        let Some(local) = self
            .operation
            .jvm_authored_reference_local_path_evidence(receiver, self.cancellation)?
        else {
            return Ok(false);
        };
        if !local.local_definitions().is_empty() {
            return Ok(false);
        }
        let identities = &self.operation.ready.context_identities;
        self.operation.profile_jvm_read(
            "binding_receiver_identity",
            (
                reference,
                receiver,
                identities.jvm_external_provider_type_identity_for_reference(
                    crate::analyzer::resolution::ExternalOwnerLanguage::Jvm,
                    receiver,
                ),
            ),
        );
        let Some(owner) = identities.jvm_external_provider_type_identity_for_reference(
            crate::analyzer::resolution::ExternalOwnerLanguage::Jvm,
            receiver,
        ) else {
            return Ok(false);
        };
        if identities.external_owner_identity(owner).is_none() {
            return Ok(false);
        }
        let mut complete = false;
        let scope = typed.visit_member_scope_pages_for_definitions(
            TypedFactRequest::new(&[owner]),
            self.cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                complete |= page.iter().any(|row| {
                    row.row().external_coverage().is_some_and(|coverage| {
                        // A flattened name closure cannot prove the absence of
                        // a runtime singleton or companion declaration.
                        !coverage.member_names_only
                            && coverage.callables_complete
                            && coverage.values_complete
                            && coverage.types_complete
                            && coverage.supertypes_complete
                    })
                });
                Ok(true)
            }),
        )?;
        let mut runtime_type_value = false;
        let members = typed.visit_member_owner_pages_for_owners(
            TypedFactRequest::new(&[owner]),
            self.cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                runtime_type_value |= page.iter().any(|row| matches!(
                    row.row().kind(),
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::NestedType
                        | brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::Field
                ));
                Ok(true)
            }),
        )?;
        // The external inventory, not an empty source-only companion read,
        // proves there is no runtime singleton/companion receiver here.
        let result = complete
            && scope.is_exhausted()
            && scope.evidence() == &ResolutionCompletion::Complete
            && !runtime_type_value
            && members.is_exhausted()
            && members.evidence() == &ResolutionCompletion::Complete;
        self.operation.profile_jvm_read(
            "binding_precedence_type_receiver",
            (reference, receiver, owner, result),
        );
        Ok(result)
    }

    fn discharged_provider_reasons(
        &self,
        mount: SelectedResolutionMountOrdinal,
        gaps: &[JvmImportContextGap],
        lookup: &ResolutionLookupSemanticRecipe,
        source_tokens: &[SemanticId],
        binding_rank: Option<JvmBindingPrecedence>,
    ) -> Result<BTreeSet<SemanticId>> {
        let language = self
            .operation
            .mount_table()
            .mount_by_ordinal(mount)?
            .semantic_language();
        // A complete name inventory proves this exact provider cannot supply
        // an absent spelling, even without a binding. A present spelling can
        // still be discharged below by a stronger positive binding; inventory
        // presence does not override the language's binding-origin ranks.
        let mut completed_provider_reasons = gaps
            .iter()
            .filter_map(|gap| {
                if !jvm_implicit_provider_gap(language, gap) {
                    return None;
                }
                let provider = gap.owner.as_deref()?;
                if gap.boundary_status
                    == Some(crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed)
                    && brokk_bifrost_jvm::intrinsics::default_provider_excludes_name(
                        language,
                        provider,
                        gap.lookup.spelling(),
                    )
                {
                    return Some(gap.reason);
                }
                let entry = crate::analyzer::resolution::universe_lookup(
                    language,
                    gap.lookup.namespace(),
                    gap.lookup.spelling(),
                )?;
                let (provider, _) = entry.identity_spelling.rsplit_once('.')?;
                (jvm_implicit_provider_gap(language, gap) && gap.owner.as_deref() == Some(provider))
                    .then_some(gap.reason)
            })
            .collect::<BTreeSet<_>>();
        let lexical = self.operation.ready.lexical_source();
        let type_alternatives = gaps
            .iter()
            .filter(|gap| {
                jvm_implicit_provider_gap(language, gap)
                    && matches!(
                        gap.lookup.namespace(),
                        ResolutionNamespace::Type
                            | ResolutionNamespace::Callable
                            | ResolutionNamespace::Value
                    )
            })
            .filter_map(|gap| gap.source_reference)
            .collect::<BTreeSet<_>>();
        for reference in type_alternatives {
            let Some(seed) =
                lexical.reference_seed(ResolutionQuery::new(reference), self.cancellation)?
            else {
                continue;
            };
            // A qualified call can search imported extension callables, but its
            // type alternative belongs to the receiver, not to global imports.
            if seed.site_metadata().is_some_and(|metadata| {
                !metadata.unqualified() && metadata.namespace() == ResolutionNamespace::Callable
            }) {
                let type_receiver = self.complete_external_type_receiver(reference)?;
                completed_provider_reasons.extend(
                    gaps.iter()
                        .filter(|gap| {
                            gap.source_reference == Some(reference)
                                && jvm_implicit_provider_gap(language, gap)
                                && (gap.lookup.namespace() == ResolutionNamespace::Type
                                    || type_receiver)
                        })
                        .map(|gap| gap.reason),
                );
                if type_receiver {
                    let member_lookups = gaps
                        .iter()
                        .filter(|gap| gap.source_reference == Some(reference))
                        .map(|gap| gap.lookup.spelling())
                        .collect::<BTreeSet<_>>();
                    for gap in gaps.iter().filter(|gap| {
                        gap.source_reference.is_none()
                            && member_lookups.contains(gap.lookup.spelling())
                            && !jvm_implicit_provider_gap(language, gap)
                    }) {
                        let Some(bindings) =
                            self.jvm_import_bindings_for_lookup(mount, &gap.lookup)?
                        else {
                            return Ok(BTreeSet::new());
                        };
                        // This closed receiver's member is not a name bound by
                        // that import. Its package frontier cannot supply it.
                        if !bindings
                            .iter()
                            .any(|binding| binding.token == gap.source_token)
                        {
                            completed_provider_reasons.insert(gap.reason);
                        }
                    }
                }
            }
        }
        let Some(binding_rank) = binding_rank else {
            return Ok(completed_provider_reasons);
        };
        let mut source_references = BTreeSet::new();
        for &token in source_tokens {
            let SelectedPackageRows::Ready(rows) = self
                .operation
                .selected_package_reference_for_token(mount, token, self.cancellation)?
            else {
                return Ok(BTreeSet::new());
            };
            source_references.extend(rows.into_iter().map(|row| row.reference));
        }
        let mut import_bindings = HashMap::default();
        for gap in gaps
            .iter()
            .filter(|gap| !jvm_implicit_provider_gap(language, gap))
        {
            if import_bindings.contains_key(&gap.lookup) {
                continue;
            }
            let Some(bindings) = self.jvm_import_bindings_for_lookup(mount, &gap.lookup)? else {
                return Ok(BTreeSet::new());
            };
            import_bindings.insert(gap.lookup.clone(), bindings);
        }
        Ok(gaps
            .iter()
            .filter(|gap| gap.lookup.spelling() == lookup.spelling())
            .filter(|gap| {
                gap.source_reference.map_or_else(
                    || source_tokens.contains(&gap.source_token),
                    |reference| source_references.contains(&reference),
                )
            })
            .filter_map(|gap| {
                let provider_rank = if jvm_implicit_provider_gap(language, gap) {
                    binding_origin_rank(language, BindingOrigin::DefaultImport).map(|rank| {
                        JvmBindingPrecedence {
                            depth: u32::MAX,
                            rank,
                        }
                    })
                } else {
                    import_bindings
                        .get(&gap.lookup)
                        .into_iter()
                        .flatten()
                        .filter(|binding| {
                            binding.token == gap.source_token
                                && gap
                                    .source_reference
                                    .is_none_or(|reference| reference == binding.reference)
                        })
                        .map(|binding| binding.precedence)
                        .min()
                };
                // Provider inventories at the same origin rank remain open:
                // lexical depth cannot prove absence from a split package.
                provider_rank
                    .filter(|rank| binding_rank.rank < rank.rank)
                    .map(|_| gap.reason)
            })
            .chain(completed_provider_reasons)
            .collect())
    }

    fn caller_scoped_gap_reasons(
        &mut self,
        source: &mut JvmSourceDemand,
    ) -> Result<Option<Vec<ResolutionIncompleteReason>>> {
        let Some(caller_source) = source.caller_scoped_source else {
            return Ok(Some(Vec::new()));
        };
        let (source_token, demand, implicit_root_reference) = match caller_source {
            JvmCallerScopedSource::Import { token, demand } => (token, demand, false),
            JvmCallerScopedSource::ImplicitRootReference { token, demand } => (token, demand, true),
        };

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
        let Some((context, context_gaps)) =
            self.file_context(self.caller, root_lookup.spelling())?
        else {
            return Ok(None);
        };
        let binding_rank = if context_gaps.is_empty() {
            None
        } else {
            self.complete_binding_origin_rank(&context, source, &[source_token], &root_lookup)?
        };
        let shadowed = self.discharged_provider_reasons(
            self.caller,
            &context_gaps,
            &root_lookup,
            &[source_token],
            binding_rank,
        )?;
        // A local candidate is not a successful binding yet: constructor and
        // receiver refinement can still reject it. Keep its provider evidence
        // open until the shared final-answer phase sees this exact target.
        let language = source_mount.semantic_language();
        if let (Some(local_rank), Some(default_rank)) = (
            binding_origin_rank(language, BindingOrigin::LocalOrInherited),
            binding_origin_rank(language, BindingOrigin::DefaultImport),
        ) && local_rank < default_rank
        {
            let SelectedPackageRows::Ready(rows) =
                self.operation.selected_package_reference_for_token(
                    source.mount,
                    source_token,
                    self.cancellation,
                )?
            else {
                return Ok(None);
            };
            // A package-demand token is shared by references with the same
            // lookup. Context gaps retain only a representative reference, so
            // match the token's full selected reference set, not that one site.
            // The proof still applies only if the final answer selects the
            // exact local target below.
            let source_references = rows
                .iter()
                .map(|row| row.reference)
                .collect::<BTreeSet<_>>();
            for row in rows {
                let Some(local) = self
                    .operation
                    .jvm_authored_reference_local_path_evidence(row.reference, self.cancellation)?
                else {
                    continue;
                };
                if local.local_bindings_certified()
                    && let [target] = local.local_definitions()
                {
                    source
                        .caller_positive_binding_providers
                        .entry(*target)
                        .or_default()
                        .extend(
                            context_gaps
                                .iter()
                                .filter(|gap| {
                                    gap.lookup.spelling() == root_lookup.spelling()
                                        && gap.source_reference.is_some_and(|reference| {
                                            source_references.contains(&reference)
                                        })
                                        && jvm_implicit_provider_gap(language, gap)
                                })
                                .map(|gap| gap.reason),
                        );
                }
            }
        }
        source.caller_discharged_provider_reasons = shadowed.clone();
        self.operation.profile_jvm_read(
            "binding_precedence_result",
            (
                &root_lookup,
                source_token,
                binding_rank,
                &context_gaps,
                &shadowed,
            ),
        );
        let context_key = (
            root_lookup.spelling().to_owned(),
            self.operation.ready.inventory.staged_read_epoch(),
        );
        if self.whole_file_import_gaps.is_none()
            && !self.caller_context_lookups.contains(&context_key)
        {
            let language = self
                .operation
                .mount_table()
                .mount_by_ordinal(self.caller)?
                .semantic_language();
            let gaps = if !language_implicit_root_providers(language).is_empty()
                || (self.rules.has_context_import_inventory() && !implicit_root_reference)
            {
                context_gaps
            } else {
                Vec::new()
            };
            let accumulated = self.caller_scoped_gaps.get_or_insert_with(Vec::new);
            accumulated.extend(gaps);
            accumulated.sort_by(|left, right| {
                (&left.lookup, left.reason).cmp(&(&right.lookup, right.reason))
            });
            accumulated.dedup();
            self.caller_context_lookups.insert(context_key);
        }

        let language = source_mount.semantic_language();
        let scala_callable_value_alias = language_implicit_root_providers(language)
            .contains(&JvmImplicitRootProvider::ScalaPredef)
            && root_lookup.namespace() == ResolutionNamespace::Value;
        let reasons = self
            .caller_import_gaps()
            .iter()
            .filter(|gap| {
                if shadowed.contains(&gap.reason) {
                    return false;
                }
                if gap.kind == "jvm-default-import-package-open"
                    && language_implicit_root_providers_in_namespace(
                        language,
                        gap.lookup.namespace(),
                    )
                    .is_empty()
                {
                    return false;
                }
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

/// Evidence for how a qualified JVM prefix is interpreted.
#[derive(Clone, Debug)]
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

impl JvmDemandState<'_, '_, '_> {
    fn discover_source(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<JvmSourceDemand>> {
        if endpoint.node() != BindingNodeId::universal_root() {
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        if self
            .arena
            .borrow()
            .endpoints
            .contains_key(&DemandRelationKey::caller(endpoint.clone()))
        {
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        }
        let source = self.source_demand(endpoint)?;
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(LanguageRootDiscovery::Cancelled(cancelled_completion()));
        }
        let Some(mut source) = source else {
            self.arena
                .borrow_mut()
                .base_ready
                .insert(DemandRelationKey::caller(endpoint.clone()));
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            });
        };
        let mut completion = ResolutionCompletion::Complete;
        if source.mount == self.caller && source.qualified.is_none() {
            let Some(reasons) = self.caller_scoped_gap_reasons(&mut source)? else {
                return Ok(LanguageRootDiscovery::Cancelled(cancelled_completion()));
            };
            if source.import_qualifiers.is_none() {
                self.arena
                    .borrow_mut()
                    .base_ready
                    .insert(DemandRelationKey::caller(endpoint.clone()));
            }
            if self.whole_file_import_gaps.is_some()
                && reasons.is_empty()
                && source.import_qualifiers.is_none()
            {
                return Ok(LanguageRootDiscovery::AlreadyReady {
                    completion: ResolutionCompletion::Complete,
                });
            }
            // Point contexts still need other caller names even when there is
            // no gap; discover them for closure-time delta publication.
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

    fn selected_member_request(
        &self,
        source: &JvmSourceDemand,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<DemandMemberSelectionRequest>> {
        (|| -> Result<Option<DemandMemberSelectionRequest>> {
            let Some((_, qualifiers)) = &source.import_qualifiers else {
                return Ok(None);
            };
            let Some(values) = self.scala_import_projected_values(qualifiers, inputs) else {
                return Ok(None);
            };
            for value in values {
                if let ResolutionSlotValue::TypeObject(ty, _) = value
                    && !self.operation.jvm_scala_object_definition(ty.identity())?
                {
                    return Ok(None);
                }
            }
            self.scala_import_member_request(source, values)
        })()
    }

    fn caller_gap_completion(source: &JvmSourceDemand) -> ResolutionCompletion {
        if source.caller_gap_reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete(source.caller_gap_reasons.iter().copied())
        }
    }

    fn caller_gap_witness(source: &JvmSourceDemand) -> ClosureWitness {
        ClosureWitness {
            discharged_provider_reasons: source.caller_discharged_provider_reasons.clone(),
            positive_binding_providers: source.caller_positive_binding_providers.clone(),
        }
    }

    fn caller_gap_authority(
        &self,
        source: &JvmSourceDemand,
    ) -> Result<Read<Option<DemandClosureDischarges>>> {
        let mut discharges = match source.caller_scoped_source {
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
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                let root_lookup = recipes
                    .pop()
                    .expect("a selected caller import demand has one lookup recipe");
                let identities = self
                    .caller_import_gaps()
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
        if !source.caller_discharged_provider_reasons.is_empty() {
            discharges
                .get_or_insert_with(DemandClosureDischarges::default)
                .merge(
                    DemandClosureDischarges::default().with_discharged_provider_reasons(
                        source.caller_discharged_provider_reasons.iter().copied(),
                    ),
                );
        }
        if !source.caller_positive_binding_providers.is_empty() {
            discharges
                .get_or_insert_with(DemandClosureDischarges::default)
                .positive_binding_providers = source.caller_positive_binding_providers.clone();
        }
        Ok(Read::ready(discharges))
    }

    fn caller_name_context(
        &mut self,
        source: &JvmSourceDemand,
    ) -> Result<Option<(JvmCallerContextKey, JvmNamePublication)>> {
        let mount = source.mount;
        let caller_mount = self.operation.mount_table().mount_by_ordinal(mount)?;
        let Some(mut recipes) = self.operation.jvm_lookup_recipes(
            caller_mount.fragment(),
            [source.lookup],
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let recipe = recipes.pop().expect("one caller root lookup");
        let key = JvmCallerContextKey {
            name: recipe.spelling().to_owned(),
            scope: self.operation.ready.inventory.scope_identity(),
            stage_epoch: self.operation.ready.inventory.staged_read_epoch(),
        };
        let publication = if self.caller_registered_contexts.contains_key(&key) {
            JvmNamePublication::Registered
        } else {
            let Some((context, _)) = self.file_context(mount, recipe.spelling())? else {
                return Ok(None);
            };
            self.pending_registration = Some(JvmPendingRegistration::Caller(key.clone()));
            JvmNamePublication::Prepared(context)
        };
        Ok(Some((key, publication)))
    }

    fn provider_name_context(
        &mut self,
        endpoint: &EndpointSignature,
        source: &JvmSourceDemand,
        context: &JvmPreparedContext,
    ) -> Result<Option<(JvmPreparedNameKey, JvmNamePublication, ResolutionCompletion)>> {
        let mount = source.mount;
        let source_mount = self.operation.mount_table().mount_by_ordinal(mount)?;
        let lookup = source.lookup;
        let mut evidence = ResolutionCompletion::Complete;
        let key = JvmPreparedNameKey {
            lookup,
            scope: self.operation.ready.inventory.scope_identity(),
            stage_epoch: self.operation.ready.inventory.staged_read_epoch(),
        };
        let cached = context.contexts.borrow();
        let (preparation, scoped_gaps) = if let Some(cached) = cached.get(&key) {
            (JvmNamePublication::Registered, cached.scoped_gaps.clone())
        } else {
            let Some(mut recipes) = self.operation.jvm_lookup_recipes(
                source_mount.fragment(),
                [lookup],
                self.cancellation,
            )?
            else {
                return Ok(None);
            };
            let recipe = recipes.pop().expect("one demanded file lookup");
            let Some((file_context, scoped_gaps)) = self.file_context(mount, recipe.spelling())?
            else {
                return Ok(None);
            };
            let file_context = scoped_gaps.iter().fold(file_context, |context, gap| {
                context.with_context_owned_gap_identity(gap.reason)
            });
            self.pending_registration =
                Some(JvmPendingRegistration::Provider(key, scoped_gaps.clone()));
            (JvmNamePublication::Prepared(file_context), scoped_gaps)
        };
        for gap in scoped_gaps {
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
        Ok(Some((key, preparation, evidence)))
    }

    fn remember_registration(
        &mut self,
        context: Option<&JvmPreparedContext>,
        blueprint: &SelectedFactOperationBlueprint,
    ) {
        match self.pending_registration.take() {
            Some(JvmPendingRegistration::Caller(key)) => {
                self.caller_registered_contexts
                    .insert(key, blueprint.clone());
            }
            Some(JvmPendingRegistration::Provider(key, scoped_gaps)) => {
                context
                    .expect("provider context was prepared")
                    .contexts
                    .borrow_mut()
                    .insert(
                        key,
                        JvmPreparedNameContext {
                            blueprint: blueprint.clone(),
                            scoped_gaps,
                        },
                    );
            }
            None => {}
        }
    }
}

impl JvmDemandState<'_, '_, '_> {
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
        let mut observed = completion.clone();
        let mut type_references = BTreeSet::from([reference]);
        if jvm_prefix_defers_member_selection(language) {
            // A selected qualified type proves the package/type alternatives
            // along its structured qualifier chain, even though those gaps
            // are also copied onto the terminal's typed frontier.
            let typed = self.operation.ready.typed_source();
            let mut pending = vec![reference];
            let mut slots = BTreeSet::new();
            while let Some(current) = pending.pop() {
                let mut qualifiers = Vec::new();
                let mut current_slots = Vec::new();
                let read = typed.visit_binding_projection_pages_for_references(
                    TypedFactRequest::new(&[current]),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        current_slots.extend(
                            page.iter()
                                .map(|row| row.row())
                                .filter(|row| {
                                    matches!(
                                        row.kind(),
                                        BindingProjectionKind::TargetTypeIdentity
                                            | BindingProjectionKind::TargetNominalTypeIdentity
                                    )
                                })
                                .map(|row| row.output_slot()),
                        );
                        Ok(true)
                    }),
                )?;
                if !read.is_exhausted() || read.evidence() != &ResolutionCompletion::Complete {
                    return Ok(None);
                }
                if current_slots.is_empty() {
                    continue;
                }
                slots.extend(current_slots);
                let read = typed.visit_qualified_route_pages_for_references(
                    TypedFactRequest::new(&[current]),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        qualifiers.extend(page.iter().map(|row| row.row().qualifier_slot()));
                        Ok(true)
                    }),
                )?;
                if !read.is_exhausted() || read.evidence() != &ResolutionCompletion::Complete {
                    return Ok(None);
                }
                qualifiers.sort_unstable();
                qualifiers.dedup();
                for chunk in qualifiers.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                    let read = typed.visit_binding_projection_pages_for_outputs(
                        TypedFactRequest::new(chunk),
                        self.cancellation,
                        &mut FactPageVisitor::new(&mut |page| {
                            for row in page {
                                let row = row.row();
                                if matches!(
                                    row.kind(),
                                    BindingProjectionKind::TargetTypeIdentity
                                        | BindingProjectionKind::TargetNominalTypeIdentity
                                ) && type_references.insert(row.reference())
                                {
                                    pending.push(row.reference());
                                }
                            }
                            Ok(true)
                        }),
                    )?;
                    if !read.is_exhausted() || read.evidence() != &ResolutionCompletion::Complete {
                        return Ok(None);
                    }
                }
                if self.cancellation.is_cancelled() {
                    return Ok(None);
                }
            }
            let slots = slots.into_iter().collect::<Vec<_>>();
            for chunk in slots.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                let read = typed.visit_type_frontier_completion_pages(
                    TypedFactRequest::new(chunk),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        for row in page {
                            observed = observed.combine(row.completion());
                        }
                        Ok(true)
                    }),
                )?;
                if !read.is_exhausted() || read.evidence() != &ResolutionCompletion::Complete {
                    return Ok(None);
                }
            }
        }
        let ResolutionCompletion::Incomplete(reasons) = &observed else {
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
                && ((row.source_site() != source_site
                    && jvm_prefix_defers_member_selection(language)
                    && row.origin()
                        == LoweringGapOrigin::Extracted(ResolutionGapKind::AmbiguousQualifiedType)
                    && type_references.contains(
                        &crate::analyzer::resolution::fact_lowering::site_semantic(
                            fragment,
                            row.source_site(),
                        ),
                    ))
                    || (row.source_site() == source_site
                        && crate::analyzer::resolution::jvm_terminal_type_gap_origin_is_safe(
                            language,
                            row.fragment(),
                            row.source_site(),
                            row.origin(),
                            reference,
                        )))
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
        let rules = nominal_rules::nominal_language_rules(language)
            .expect("caller belongs to a nominal family");
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
        (rules.has_projected_value_qualifiers() || type_targets == binding_targets)
            .then(|| type_targets.into_iter().collect())
    }

    fn scala_import_projected_values<'answer>(
        &self,
        qualifiers: &[SemanticId],
        inputs: &[(DemandReferenceKey, &'answer FactResolutionAnswer)],
    ) -> Option<&'answer [ResolutionSlotValue]> {
        assert_eq!(
            qualifiers.len(),
            inputs.len(),
            "all qualifier views finish: {qualifiers:?}, {inputs:?}"
        );
        let (&qualifier, &(_, answer)) = qualifiers.first().zip(inputs.first())?;
        assert_eq!(inputs[0].0, DemandReferenceKey::caller(qualifier));
        let values = self.jvm_prefix_projected_values(qualifier, answer, Language::Scala)?;
        let owner = values.first()?.ty().identity();
        if values.iter().any(|value| value.ty().identity() != owner) {
            return None;
        }
        for (&qualifier, &(reference, answer)) in qualifiers.iter().zip(inputs).skip(1) {
            assert_eq!(reference, DemandReferenceKey::caller(qualifier));
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
        let rules = nominal_rules::nominal_language_rules(language)
            .expect("caller belongs to a nominal family");
        let mut projections = answer.projections().iter().filter(|projection| {
            projection.reference() == reference
                && rules
                    .qualifier_projection_kinds()
                    .contains(&projection.kind())
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
        if values.is_empty()
            || values.iter().any(|value| {
                value.ty().indirection() != 0
                    || (!rules.has_projected_value_qualifiers()
                        && !matches!(value, ResolutionSlotValue::TypeObject(_, _)))
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
        completion: &ResolutionCompletion,
    ) -> Result<Option<JvmPackagePrefix>> {
        if selected_type_targets.is_empty() {
            return Ok(Some(JvmPackagePrefix::Retained(completion.clone())));
        }

        let ResolutionCompletion::Incomplete(reasons) = completion else {
            unreachable!("the complete type-prefix path is handled before provenance lookup")
        };
        let mut semantics = Vec::new();
        for reason in reasons.iter() {
            let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
                return Ok(Some(JvmPackagePrefix::Retained(completion.clone())));
            };
            semantics.push(*semantic);
        }
        if semantics.is_empty() {
            return Ok(Some(JvmPackagePrefix::Retained(completion.clone())));
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
                return Ok(Some(JvmPackagePrefix::Retained(completion.clone())));
            }
        }
        if provenance.len() != retired.len()
            || semantics
                .iter()
                .any(|semantic| !retired.contains(semantic) && !semantic.is_operation_local())
        {
            return Ok(Some(JvmPackagePrefix::Retained(completion.clone())));
        }
        Ok(Some(JvmPackagePrefix::Witness(semantics)))
    }
}

impl JvmDemandState<'_, '_, '_> {
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

/// Inputs for one caller file's shared JVM forward operation.
#[doc(hidden)]
pub struct JvmForwardOperationContext<'a> {
    pub storage_language: &'a str,
    pub blueprint: &'a SelectedFactOperationBlueprint,
    pub caller_path: &'a str,
    pub import_gaps: &'a [JvmImportContextGap],
    pub lexical: &'a dyn BatchResolutionFragmentSource,
    pub typed: &'a dyn SelectedTypedFactSource,
    pub cancellation: &'a CancellationToken,
    pub session: &'a ResolutionSession,
}

impl SelectedResolutionOperation<'_, '_> {
    #[doc(hidden)]
    pub fn stage_jvm_reference_batches(
        &self,
        context: JvmForwardOperationContext<'_>,
        maximum_batch_size: usize,
        sink: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary> {
        self.with_jvm_forward_operation(
            context.storage_language,
            context.blueprint,
            context.lexical,
            context.typed,
            context.caller_path,
            Some(context.import_gaps),
            context.cancellation,
            context.session,
            None,
            |operation| operation.stage_all_reference_batches(maximum_batch_size, sink),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_jvm_forward_operation<T>(
        &self,
        caller_language: &str,
        blueprint: &SelectedFactOperationBlueprint,
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        caller_path: &str,
        whole_file_import_gaps: Option<&[JvmImportContextGap]>,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        selected_import_gap: Option<(SemanticId, SemanticId)>,
        run: impl FnOnce(&mut crate::analyzer::resolution::FactResolutionOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let caller = self
            .mount_table()
            .mount_for_path(caller_language, caller_path)?
            .expect("located JVM reference has a selected caller mount");
        let rules = nominal_rules::nominal_language_rules(caller.semantic_language())
            .expect("caller belongs to a nominal family");
        let family = rules.family();
        let caller = caller.ordinal();
        self.profile_jvm_read(
            "demand_provider",
            (caller_language, caller_path, selected_import_gap),
        );
        let paths = self.ready.lexical_source();
        let base = blueprint.path_fragment_source(lexical, &paths, None);
        let arena = RefCell::new(ClosedRelations::default());
        let source = ClosedForwardSource::new(
            &base,
            &paths,
            &arena,
            session,
            crate::analyzer::resolution::CALLER_ENVIRONMENT,
        );
        let language = JvmDemandState {
            rules,
            family,
            operation: self,
            base: lexical,
            initial: blueprint.context_token(),
            arena: &arena,
            session,
            cancellation,
            caller,
            whole_file_import_gaps,
            caller_scoped_gaps: None,
            caller_context_lookups: HashSet::default(),
            caller_registered_contexts: HashMap::default(),
            import_bindings: RefCell::default(),
            selected_import_gap,
            pending_registration: None,
        };
        self.with_shared_forward_operation(
            JvmRules::new(language),
            &arena,
            &paths,
            &source,
            blueprint,
            lexical,
            typed,
            Some(&self.jvm_context_blueprints),
            cancellation,
            session,
            None,
            run,
        )
    }
}

impl JvmDemandState<'_, '_, '_> {
    fn file_context(
        &self,
        mount: SelectedResolutionMountOrdinal,
        lookup: &str,
    ) -> Result<Option<(SelectedResolutionContextSet, Vec<JvmImportContextGap>)>> {
        self.operation
            .profile_jvm_read("demand_file_context", mount);
        let record = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount)?;
        assert!(self.family.admits(record.semantic_language()));
        match self.operation.jvm_import_context_for_name(
            record.semantic_language(),
            record.persisted_relative_path(),
            lookup,
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

    fn context_delta(
        &self,
        token: crate::analyzer::resolution::SelectedContextPathToken,
    ) -> Result<Option<JvmContextDelta>> {
        let paths = self.operation.ready.lexical_source();
        let Some((_, candidates)) =
            DemandSelectedOverlayBlueprint::delta(token, &paths, self.initial, self.cancellation)?
        else {
            return Ok(None);
        };
        let Some(delta) = super::super::resolution_stage::SelectedResolutionStage::new(
            &self.operation.ready.inventory,
        )
        .publish_context_delta(token, self.initial, self.cancellation)?
        else {
            return Ok(None);
        };
        Ok(Some((
            DemandSelectedOverlayBlueprint::new(delta),
            candidates,
        )))
    }

    fn register_context(
        &self,
        mount: SelectedResolutionMountOrdinal,
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
        self.operation.ready.publish_prepared_context(
            context,
            self.cancellation,
            self.session,
            Some(&self.operation.jvm_context_blueprints),
            |blueprint| {
                let key = JvmProviderRegistrationKey {
                    mount,
                    scope: self.operation.ready.inventory.scope_identity(),
                    stage_epoch: self.operation.ready.inventory.staged_read_epoch(),
                };
                self.operation
                    .jvm_context_registrations
                    .borrow_mut()
                    .register(key, blueprint, |cells| {
                        self.operation.ready.register_context_cells_in_session(
                            blueprint,
                            cells,
                            self.cancellation,
                            self.session,
                        )
                    })
            },
        )
    }
}

// Discovery and provider preparation retain their existing authority. Source
// member continuations and production closure use the shared scheduler.
struct JvmRules<'a, 'store, 'input> {
    state: JvmDemandState<'a, 'store, 'input>,
    sources: HashMap<EndpointSignature, JvmSourceDemand>,
    contexts: Vec<SelectedResolutionMountOrdinal>,
    prepared: HashMap<super::demand_closure::ContextId, JvmPreparedContext>,
    provider_roots: HashMap<EndpointSignature, Read<Option<DemandClosureDischarges>>>,
    source_roots: HashMap<EndpointSignature, JvmSourceState>,
    prefix_evidence: RefCell<HashMap<DemandReferenceKey, JvmPackagePrefix>>,
}

impl<'a, 'store, 'input> JvmRules<'a, 'store, 'input> {
    fn new(state: JvmDemandState<'a, 'store, 'input>) -> Self {
        Self {
            state,
            sources: HashMap::default(),
            contexts: Vec::new(),
            prepared: HashMap::default(),
            provider_roots: HashMap::default(),
            source_roots: HashMap::default(),
            prefix_evidence: RefCell::new(HashMap::default()),
        }
    }
}

impl<'store, 'input> super::demand_closure::DemandRules for JvmRules<'_, 'store, 'input> {
    type Placement = ();
    type Target = JvmSourceTarget;
    type Member = ();
    type Provider = SemanticId;
    type MemberRow = crate::analyzer::resolution::LoweredMemberOwnerProperty;
    type PlacementObservations = crate::analyzer::store::resolution_operation::demand_closure::CollectedPlacementObservations;
    type Rank = JvmBindingPrecedence;
    type Half<'b>
        = JvmHalfRows<'b, 'store, 'input>
    where
        Self: 'b;
    type PreparationKey = JvmNameContextKey;
    type Certificate = ();

    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        _: bool,
    ) -> Result<Read<super::demand_closure::EndpointAdmission>> {
        use super::demand_closure::{Admission, ContextId, EndpointAdmission, RootFrame};
        self.state
            .operation
            .profile_jvm_read("discover_root", (self.state.caller, endpoint));
        // Reuse the existing discovery and JVM reason minting. Its outer
        // scope-step is supplied once by SharedDemand, not charged again here.
        Ok(match self.state.discover_source(endpoint)? {
            LanguageRootDiscovery::Ready {
                question,
                completion,
            } => {
                let halves = question
                    .import_qualifiers
                    .as_ref()
                    .map(|(half, _)| vec![half.clone()])
                    .or_else(|| question.qualified.as_ref().map(|half| vec![half.clone()]))
                    .unwrap_or_default();
                let key = self.state.context_key(&question).map(|mount| {
                    let index = self
                        .contexts
                        .iter()
                        .position(|existing| *existing == mount)
                        .unwrap_or_else(|| {
                            self.contexts.push(mount);
                            self.contexts.len() - 1
                        });
                    ContextId(index)
                });
                let frame = RootFrame {
                    endpoint: endpoint.clone(),
                    sources: Box::new([]),
                    halves,
                    context: key,
                    operands: Box::new([]),
                    resolved_prefixes: Vec::new(),
                    completion: completion.clone(),
                };
                // A cancelled preparation may retry discovery in this request.
                self.sources.insert(endpoint.clone(), question);
                Read::ready(EndpointAdmission::Context(Admission::SourceOwned(frame)))
            }
            LanguageRootDiscovery::AlreadyReady { completion } => {
                Read::ready(EndpointAdmission::Ready(completion))
            }
            LanguageRootDiscovery::Unavailable { reason, completion } => {
                Read::Unavailable { reason, completion }
            }
            LanguageRootDiscovery::Cancelled(completion) => Read::Cancelled(completion),
        })
    }
    fn describe_source(
        &mut self,
        _: &EndpointSignature,
        _: Option<super::source_demand::SourceDemandKey>,
        _: Vec<SelectedRootPathHalf>,
        _: ResolutionCompletion,
    ) -> Result<Read<super::demand_closure::Admission>> {
        unreachable!("JVM admission retains its structured discovered question")
    }
    fn derive_context(
        &mut self,
        key: super::demand_closure::ContextId,
        frame: &super::demand_closure::RootFrame,
    ) -> Result<Read<Option<SelectedResolutionContextSet>>> {
        let source = &self.sources[&frame.endpoint];
        Ok(match self.state.prepare_context(&self.contexts[key.0], source)? {
            LanguageContextPreparation::Ready { data, completion } => {
                assert!(self.prepared.insert(key, data).is_none());
                Read::Ready { value: None, completion }
            }
            LanguageContextPreparation::Cancelled(completion) => Read::Cancelled(completion),
            LanguageContextPreparation::Unavailable(completion) => Read::Unavailable {
                reason: crate::analyzer::resolution::DemandRootUnavailableReason::IncompletePreparation, completion },
        })
    }
    fn resolve_prefix_operands(
        &mut self,
        _: &mut super::demand_closure::RootFrame,
        _: Option<&SelectedResolutionContextSet>,
    ) -> Result<Read<Vec<super::demand_closure::ResolvedPrefixOperand>>> {
        if self.state.cancellation.is_cancelled() {
            Ok(Read::Cancelled(cancelled_completion()))
        } else {
            Ok(Read::ready(Vec::new()))
        }
    }
    fn prefix_operands(
        &self,
        frame: &super::demand_closure::RootFrame,
        caller: super::demand_closure::EnvironmentId,
    ) -> Vec<super::demand_closure::PrefixOperand> {
        use super::demand_closure::{HalfId, PrefixOperand};
        let source = &self.sources[&frame.endpoint];
        let Some((_, references)) = &source.import_qualifiers else {
            return super::demand_closure::default_prefix_operands(frame, caller);
        };
        references
            .iter()
            .map(|&reference| PrefixOperand {
                key: DemandReferenceKey {
                    reference,
                    environment: caller,
                },
                source_halves: Box::new([HalfId(0)]),
            })
            .collect()
    }
    fn half_rows<'b>(
        &'b self,
        source: &'b super::demand_closure::SourceHalf,
        frame: &'b super::demand_closure::RootFrame,
        _: &'b crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        _: &'b dyn super::demand_closure::HalfSource,
        _: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<Self::Half<'b>>> {
        assert!(
            self.source_roots.contains_key(&frame.endpoint),
            "only admitted source roots enter source rows"
        );
        let state = self
            .source_roots
            .get(&frame.endpoint)
            .expect("source state retained across waits");
        Ok(Some(JvmHalfRows {
            rules: self,
            source,
            state,
            language: state.reader.language,
        }))
    }
    fn bridge_material(
        &self,
        frame: &super::demand_closure::RootFrame,
        _: &SelectedRootPathHalf,
        export: &SelectedRootPathHalf,
        _: &ResolutionLookupSemanticRecipe,
        _: Language,
    ) -> Result<super::demand_closure::BridgeMaterial> {
        let SelectedRootPathHalf::Export {
            identity,
            token,
            demand,
            definition,
            ..
        } = export
        else {
            unreachable!("canonical export material");
        };
        let key = super::demand_closure::ExportAuthority {
            fragment: identity.fragment(),
            token: *token,
            demand: *demand,
            definition: *definition,
        };
        Ok(self.source_roots[&frame.endpoint]
            .material
            .borrow()
            .get(&key)
            .expect("selected package export retains access material")
            .clone())
    }
    fn provider_preparation(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<super::demand_closure::ProviderPreparation<Self::PreparationKey>>> {
        // Position typed owners before any source traversal. The retained
        // projection and completion are owned facts; resumes never reread them.
        let source = &self.sources[&frame.endpoint];
        let language = self
            .state
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?
            .semantic_language();
        let source_half = source
            .qualified
            .as_ref()
            .or_else(|| source.import_qualifiers.as_ref().map(|(half, _)| half));
        let mut reader = source_half
            .map(|half| self.state.operation.jvm_source_reader_context(half))
            .transpose()?;
        if let Some(origin) = nominal_rules::nominal_language_rules(language)
            .expect("caller belongs to a nominal family")
            .lexical_import_head_origin()
            && let Some(SelectedRootPathHalf::Reference {
                source_reference, ..
            }) = &source.qualified
        {
            let Some(import_head) = self
                .state
                .operation
                .jvm_lexical_import_qualifier(*source_reference, self.state.cancellation)?
            else {
                return Ok(Some(
                    super::demand_closure::ProviderPreparation::Unavailable(cancelled_completion()),
                ));
            };
            if import_head {
                reader
                    .as_mut()
                    .expect("source reader prepared")
                    .package_origin_rank = binding_origin_rank(language, origin);
            }
        }
        let member_start =
            if let Some(request) = self.state.selected_member_request(source, inputs)? {
                Some(JvmSourceStart::Members {
                    reference: request.reference,
                    values: request.values,
                })
            } else if let Some((_, qualifiers)) = &source.import_qualifiers {
                if let Some(values) = self.state.scala_import_projected_values(qualifiers, inputs) {
                    let owners = values
                        .iter()
                        .map(|value| value.ty().identity())
                        .collect::<BTreeSet<_>>();
                    if inputs.iter().all(|(_, answer)| {
                        answer.completion() == &ResolutionCompletion::Complete
                            && answer
                                .binding()
                                .targets()
                                .iter()
                                .copied()
                                .collect::<BTreeSet<_>>()
                                == owners
                    }) {
                        self.state
                            .scala_import_member_request(source, values)?
                            .map(|request| JvmSourceStart::Members {
                                reference: request.reference,
                                values: request.values,
                            })
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else if let Some(SelectedRootPathHalf::Reference {
                prefix_reference: Some(prefix),
                ..
            }) = &source.qualified
            {
                assert_eq!(inputs.len(), 1, "one positioned JVM prefix");
                assert_eq!(inputs[0].0, DemandReferenceKey::caller(*prefix));
                self.state
                    .jvm_type_prefix_targets(*prefix, inputs[0].1, language)
                    .filter(|owners| !owners.is_empty())
                    .map(|_| JvmSourceStart::Members {
                        reference: *prefix,
                        values: self
                            .state
                            .jvm_prefix_projected_values(*prefix, inputs[0].1, language)
                            .expect("validated owner projection retains its exact values")
                            .to_vec(),
                    })
            } else {
                None
            };
        let terminal_evidence = if let Some(SelectedRootPathHalf::Reference {
            identity,
            source_reference,
            prefix_reference,
            owner_continued,
            anchor,
            ..
        }) = &source.qualified
            && (member_start.is_some()
                || (jvm_prefix_defers_member_selection(language) && prefix_reference.is_some())
                || (prefix_reference.is_none()
                    && *owner_continued
                    && *anchor == ResolutionRootImportAnchor::Lexical))
        {
            let observed = source
                .qualified_completion
                .as_ref()
                .expect("qualified source keeps terminal evidence");
            self.state.jvm_root_reference_evidence(
                language,
                identity.fragment(),
                *source_reference,
                observed,
            )?
        } else {
            None
        };
        let terminal_reasons = terminal_evidence
            .as_ref()
            .map(|(_, retired, _)| retired.clone())
            .unwrap_or_default();
        if let Some(start) = member_start {
            let mut completion = ResolutionCompletion::combine_all_with_poll(
                inputs.iter().map(|(_, answer)| answer.completion()),
                &mut || self.state.cancellation.is_cancelled(),
            )
            .unwrap_or_else(cancelled_completion);
            let mut discharges = if source.import_qualifiers.is_some() {
                JvmDemandState::scala_import_discharges(source)
            } else {
                DemandClosureDischarges::default()
            };
            if let Some(SelectedRootPathHalf::Reference {
                prefix_reference: Some(prefix),
                ..
            }) = &source.qualified
                && let JvmPackagePrefix::Witness(retired) = self
                    .prefix_evidence
                    .borrow()
                    .get(&DemandReferenceKey::caller(*prefix))
                    .expect("prefix normalization precedes source preparation")
            {
                completion = completion_without_unsupported_semantics(&completion, retired);
                discharges.merge(
                    DemandClosureDischarges::with_operation_local_placeholders(retired.clone())
                        .for_prefix(*prefix, retired.clone(), true),
                );
            }
            self.source_roots.insert(
                frame.endpoint.clone(),
                JvmSourceState::new(
                    start,
                    completion,
                    discharges,
                    reader.expect("source reader prepared"),
                    terminal_reasons,
                ),
            );
            return Ok(None);
        }
        // Every qualified source half enters the shared route frontier. A
        // selected value with no type projection retains an unresolved start;
        // it cannot be reinterpreted as a package of the same spelling.
        if let Some(SelectedRootPathHalf::Reference {
            prefix_reference,
            owner_continued,
            anchor,
            ..
        }) = &source.qualified
        {
            let mut completion = ResolutionCompletion::combine_all_with_poll(
                inputs.iter().map(|(_, answer)| answer.completion()),
                &mut || self.state.cancellation.is_cancelled(),
            )
            .unwrap_or_else(cancelled_completion);
            let mut discharges = DemandClosureDischarges::default();
            let start = if let Some(prefix) = prefix_reference {
                let answer = inputs[0].1;
                if !answer.binding().targets().is_empty() {
                    JvmSourceStart::Unresolved(Some(*prefix))
                } else {
                    if let JvmPackagePrefix::Witness(retired) = self
                        .prefix_evidence
                        .borrow()
                        .get(&DemandReferenceKey::caller(*prefix))
                        .expect("prefix normalization precedes source preparation")
                    {
                        completion = completion_without_unsupported_semantics(&completion, retired);
                        discharges = DemandClosureDischarges::with_operation_local_placeholders(
                            retired.clone(),
                        )
                        .for_prefix(*prefix, retired.clone(), true);
                    }
                    JvmSourceStart::PositionedPackage(*prefix)
                }
            } else {
                if *owner_continued && *anchor == ResolutionRootImportAnchor::Lexical {
                    let observed = source
                        .qualified_completion
                        .as_ref()
                        .expect("owner head retains its source completion");
                    if let Some((reference, retired, normalized)) = terminal_evidence {
                        completion = normalized;
                        discharges.merge(
                            DemandClosureDischarges::with_operation_local_placeholders(
                                retired.clone(),
                            )
                            .for_prefix(reference, retired, true),
                        );
                    } else {
                        completion = observed.clone();
                    }
                }
                JvmSourceStart::Absolute
            };
            let mut state = JvmSourceState::new(
                start,
                completion,
                discharges,
                reader.expect("source reader prepared"),
                terminal_reasons,
            );
            if matches!(state.start, JvmSourceStart::Unresolved(_)) {
                state.authority.get_mut().complete = false;
            }
            self.source_roots.insert(frame.endpoint.clone(), state);
            return Ok(None);
        }
        if let Some((half, qualifiers)) = &source.import_qualifiers {
            let SelectedRootPathHalf::Import { token, .. } = half else {
                unreachable!("Scala selected import");
            };
            let completion = ResolutionCompletion::combine_all_with_poll(
                inputs.iter().map(|(_, answer)| answer.completion()),
                &mut || self.state.cancellation.is_cancelled(),
            )
            .unwrap_or_else(cancelled_completion);
            // A proved package import still owns a source half. Publish its
            // selected named bindings instead of retaining a name-limited base.
            if !inputs.is_empty()
                && inputs.iter().all(|(key, answer)| {
                    answer.binding().targets().is_empty()
                        && matches!(
                            self.prefix_evidence.borrow().get(key),
                            Some(JvmPackagePrefix::Witness(_))
                        )
                })
            {
                let Some(mut recipes) = self.state.operation.jvm_lookup_recipes(
                    self.state
                        .operation
                        .mount_table()
                        .mount_by_ordinal(source.mount)?
                        .fragment(),
                    [source.lookup],
                    self.state.cancellation,
                )?
                else {
                    return Ok(Some(
                        super::demand_closure::ProviderPreparation::Unavailable(
                            cancelled_completion(),
                        ),
                    ));
                };
                let lookup = recipes.pop().expect("one import lookup");
                let Some((mut context, gaps)) =
                    self.state.file_context(source.mount, lookup.spelling())?
                else {
                    return Ok(Some(
                        super::demand_closure::ProviderPreparation::Unavailable(
                            cancelled_completion(),
                        ),
                    ));
                };
                let mut completion = completion;
                let mut discharges = JvmDemandState::scala_import_discharges(source);
                for (key, _) in inputs {
                    if let Some(JvmPackagePrefix::Witness(retired)) =
                        self.prefix_evidence.borrow().get(key)
                    {
                        completion = completion_without_unsupported_semantics(&completion, retired);
                        discharges.merge(
                            DemandClosureDischarges::with_operation_local_placeholders(
                                retired.clone(),
                            )
                            .for_prefix(
                                key.reference,
                                retired.clone(),
                                true,
                            ),
                        );
                    }
                }
                for gap in gaps {
                    context = context.with_context_owned_gap_identity(gap.reason);
                    if gap.lookup == lookup {
                        completion = completion.combine(&ResolutionCompletion::incomplete([gap
                            .boundary_status
                            .map_or(
                                ResolutionIncompleteReason::UnsupportedSemantic(gap.reason),
                                |status| ResolutionIncompleteReason::OpenBoundary {
                                    semantic: gap.reason,
                                    status,
                                },
                            )]));
                    }
                }
                let bindings: Vec<_> = context
                    .root_bridges()
                    .iter()
                    .filter(|bridge| {
                        bridge.source_fragment().ordinal() == source.mount.get()
                            && bridge.source_import_token() == *token
                            && bridge.source_demand() == &lookup
                    })
                    .cloned()
                    .collect();
                for bridge in &bindings {
                    completion = completion.combine(bridge.completion());
                }
                let mut state = JvmSourceState::new(
                    JvmSourceStart::NamedImport,
                    completion,
                    discharges,
                    reader.expect("import reader prepared"),
                    terminal_reasons,
                );
                state.named_import = Some(JvmNamedImport {
                    context: context.without_root_bridges(),
                    bindings,
                });
                self.source_roots.insert(frame.endpoint.clone(), state);
                return Ok(None);
            }
            let reason = self.state.operation.scala_import_owner_gap(
                half,
                qualifiers.first().copied().unwrap_or(*token),
                self.state.cancellation,
            )?;
            let mut state = JvmSourceState::new(
                JvmSourceStart::Unresolved(None),
                completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ])),
                JvmDemandState::scala_import_discharges(source),
                reader.expect("import reader prepared"),
                terminal_reasons,
            );
            state.authority.get_mut().complete = false;
            self.source_roots.insert(frame.endpoint.clone(), state);
            return Ok(None);
        }
        assert!(
            frame.halves.is_empty(),
            "provider-only roots have no source half"
        );
        assert!(
            inputs.is_empty(),
            "provider-only roots have no prefix inputs"
        );
        self.state.pending_registration = None;
        self.provider_roots.insert(
            frame.endpoint.clone(),
            Read::Cancelled(cancelled_completion()),
        );
        if source.mount == self.state.caller && self.state.whole_file_import_gaps.is_some() {
            let Read::Ready {
                value: discharges, ..
            } = self.state.caller_gap_authority(source)?
            else {
                return Ok(Some(
                    super::demand_closure::ProviderPreparation::Unavailable(cancelled_completion()),
                ));
            };
            self.provider_roots
                .insert(frame.endpoint.clone(), Read::ready(discharges));
            let completion = JvmDemandState::caller_gap_completion(source);
            return Ok(Some(
                super::demand_closure::ProviderPreparation::RetainBase {
                    completion: completion.clone(),
                    endpoint_completion: Some(completion),
                },
            ));
        }
        let (key, publication, gaps, discharges, endpoint_completion) = if source.mount
            == self.state.caller
        {
            let Some((key, publication)) = self.state.caller_name_context(source)? else {
                return Ok(Some(
                    super::demand_closure::ProviderPreparation::Unavailable(cancelled_completion()),
                ));
            };
            let Read::Ready {
                value: discharges, ..
            } = self.state.caller_gap_authority(source)?
            else {
                return Ok(Some(
                    super::demand_closure::ProviderPreparation::Unavailable(cancelled_completion()),
                ));
            };
            let completion = JvmDemandState::caller_gap_completion(source);
            (
                JvmNameContextKey::Caller(key),
                publication,
                completion.clone(),
                discharges,
                Some(completion),
            )
        } else {
            let context_id = frame.context.expect("provider file has a prepared context");
            let context = &self.prepared[&context_id];
            let Some((name, publication, completion)) =
                self.state
                    .provider_name_context(&frame.endpoint, source, context)?
            else {
                return Ok(Some(
                    super::demand_closure::ProviderPreparation::Unavailable(cancelled_completion()),
                ));
            };
            (
                JvmNameContextKey::Provider {
                    context: context_id,
                    name,
                },
                publication,
                completion,
                None,
                None,
            )
        };
        // Route-specific completion belongs to this prepared source. Inventory
        // completion stays on the blueprint returned by prepared_publication.
        let completion = gaps;
        if let JvmNamePublication::Prepared(contexts) = publication {
            let Some(blueprint) = self.state.register_context(source.mount, contexts)? else {
                return Ok(Some(
                    super::demand_closure::ProviderPreparation::Unavailable(cancelled_completion()),
                ));
            };
            self.state.remember_registration(
                frame
                    .context
                    .and_then(|context| self.prepared.get(&context)),
                &blueprint,
            );
        }
        self.provider_roots
            .insert(frame.endpoint.clone(), Read::ready(discharges));
        Ok(Some(super::demand_closure::ProviderPreparation::Prepared {
            key,
            completion,
            endpoint_completion,
        }))
    }

    fn prepared_publication(&self, key: &Self::PreparationKey) -> SelectedFactOperationBlueprint {
        match key {
            JvmNameContextKey::Caller(key) => self.state.caller_registered_contexts[key].clone(),
            JvmNameContextKey::Provider { context, name } => {
                self.prepared[context].contexts.borrow()[name]
                    .blueprint
                    .clone()
            }
        }
    }

    fn publication_context(
        &self,
        frame: &super::demand_closure::RootFrame,
        ready: &ReadySelectedResolution<'_, '_>,
        inventory: &ResolutionCompletion,
    ) -> Result<SelectedResolutionContextSet> {
        let source = &self.sources[&frame.endpoint];
        let mount = self
            .state
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?;
        let context = SelectedResolutionContextSet::new(
            ready.context_identities.clone(),
            vec![SelectedResolutionMountContext::new(
                source.mount,
                mount.fragment(),
                mount.semantic_language(),
                Vec::new(),
                inventory.clone(),
            )?],
            self.state.operation.mount_table().mount_count(),
            &selected_mount_lookup(self.state.operation.mount_table()),
        )?;
        let Some(named) = self
            .source_roots
            .get(&frame.endpoint)
            .and_then(|state| state.named_import.as_ref())
        else {
            return Ok(context);
        };
        match context.clone().merge(
            named.context.clone(),
            self.state.cancellation,
            &selected_mount_lookup(self.state.operation.mount_table()),
        )? {
            Some(merged) => Ok(merged),
            None => {
                // Publication validates cancellation before installing rows.
                // Keep its inventory evidence valid even on the cancelled path.
                debug_assert!(self.state.cancellation.is_cancelled());
                Ok(context)
            }
        }
    }
    fn closure_witness(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        _: &super::demand_closure::PrefixAnswers<'_>,
        _: Option<&DemandMemberSelection>,
    ) -> Result<Read<ClosureWitness>> {
        if let Some(Read::Cancelled(completion)) = self.provider_roots.get(&frame.endpoint) {
            return Ok(Read::Cancelled(completion.clone()));
        }
        Ok(Read::ready(JvmDemandState::caller_gap_witness(
            &self.sources[&frame.endpoint],
        )))
    }

    fn closure_policy(
        &self,
        frame: &super::demand_closure::RootFrame,
        facts: &super::demand_closure::ClosureFacts<'_>,
    ) -> Result<Read<super::demand_closure::ClosurePolicy>> {
        if self.source_roots.contains_key(&frame.endpoint) {
            let state = &self.source_roots[&frame.endpoint];
            let mut member_completion = ResolutionCompletion::Complete;
            if !facts.visit_member_reads(
                &mut || self.state.cancellation.is_cancelled(),
                &mut |read| {
                    member_completion = member_completion.combine(&read.completion);
                    Ok(())
                },
            )? {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            let member_completion = completion_without_unsupported_semantics(
                &member_completion,
                &state.terminal_reasons,
            );
            if member_completion != ResolutionCompletion::Complete
                && self.sources[&frame.endpoint].import_qualifiers.is_some()
            {
                return Ok(Read::Unavailable {
                    reason: crate::analyzer::resolution::DemandRootUnavailableReason::IncompletePreparation,
                    completion: member_completion,
                });
            }
            // An open member inventory is a closed, incomplete root, not a
            // failed preparation. Publish its evidence without claiming absence.
            let authority = state.authority.borrow();
            // The start's prefix is a location, not discharge authority.
            // Only the selected-answer proof retained in state.discharges can
            // authorize retiring its provisional or operation-local reasons.
            let mut exact = DemandClosureDischarges::default();
            let [half] = facts.halves else {
                unreachable!("a JVM source root owns one half");
            };
            // An empty member inventory from another file cannot certify the
            // qualified route's absence.
            let mut empty_authority = true;
            if half.selected_targets.is_empty()
                && let JvmSourceStart::Members { values, .. } = &state.start
            {
                for value in values {
                    empty_authority &= self
                        .state
                        .operation
                        .jvm_source_owner_is_in_caller_file(&state.reader, value.ty().identity())?;
                }
            }
            let complete = authority.complete
                && empty_authority
                && member_completion == ResolutionCompletion::Complete
                && completion_without_unsupported_semantics(
                    &state.completion,
                    &state.terminal_reasons,
                ) == ResolutionCompletion::Complete;
            // A proved Java prefix classifies the qualified name even when
            // its member hierarchy is open. Retire only that name's own gap
            // before publishing the route.
            if jvm_prefix_defers_member_selection(state.reader.language)
                && matches!(&state.start, JvmSourceStart::Members { values, .. } if values.len() == 1)
                && state.completion == ResolutionCompletion::Complete
            {
                exact.merge(DemandClosureDischarges::exact(
                    state.terminal_reasons.iter().copied(),
                ));
            }
            // A declaration-backed external package route settles Java's
            // package-or-type alternative without claiming source navigation
            // targets or closing its member inventory.
            if complete && let Some(owner) = authority.external_nominal {
                // Carry the positive declaration identity through the existing
                // selected-route channel. A boolean nominal marker cannot
                // authorize retiring gaps on an answer without source targets.
                exact.merge(
                    DemandClosureDischarges::exact(state.terminal_reasons.iter().copied())
                        .with_selected_targets([owner]),
                );
            }
            // Java's name classification leaves terminal target and absence
            // authority to typed member resolution.
            if complete && !jvm_prefix_defers_member_selection(state.reader.language) {
                if authority.prefix.is_none() {
                    exact = DemandClosureDischarges::with_operation_local_placeholders([]);
                }
                exact.merge(DemandClosureDischarges::with_operation_local_placeholders(
                    state.terminal_reasons.iter().copied(),
                ));
                exact = if half.selected_targets.is_empty() {
                    exact.with_authoritative_empty_result()
                } else {
                    exact.with_selected_targets(half.selected_targets.clone())
                };
            }
            exact.merge(state.discharges.clone());
            let preserve_discharges = complete || exact != DemandClosureDischarges::default();
            let mut policy = super::demand_closure::ClosurePolicy::new(
                member_completion,
                // Named import publication is a delta against the initial
                // context. Keep identical canonical base bindings that the
                // delta deliberately omits, alongside newly published rows.
                if self.sources[&frame.endpoint].import_qualifiers.is_some()
                    && state.named_import.is_none()
                {
                    BaseEligibility::Exclude
                } else {
                    BaseEligibility::Retain
                },
                exact,
                Box::new([]),
            );
            if preserve_discharges {
                policy.preserve_discharge_record();
            }
            return Ok(Read::ready(policy));
        }
        let Read::Ready {
            value: discharges, ..
        } = self
            .provider_roots
            .get(&frame.endpoint)
            .expect("prepared provider authority")
        else {
            unreachable!("the closure witness rejects cancelled preparation");
        };
        let mut exact = discharges.clone().unwrap_or_default();
        exact.discharged_provider_reasons = facts.witness.discharged_provider_reasons.clone();
        exact.positive_binding_providers = facts.witness.positive_binding_providers.clone();
        let mut policy = super::demand_closure::ClosurePolicy::new(
            ResolutionCompletion::Complete,
            BaseEligibility::Retain,
            exact,
            Box::new([]),
        );
        if discharges.is_some() {
            policy.preserve_discharge_record();
        }
        Ok(Read::ready(policy))
    }
    fn prefix_completion(
        &self,
        prefix: super::demand_closure::PrefixCompletionInput<'_>,
    ) -> Result<Option<ResolutionCompletion>> {
        if prefix.raw == &ResolutionCompletion::Complete
            && prefix.selected.completion() == &ResolutionCompletion::Complete
        {
            self.prefix_evidence
                .borrow_mut()
                .insert(prefix.key, JvmPackagePrefix::Witness(Vec::new()));
            return Ok(Some(ResolutionCompletion::Complete));
        }
        let reference = prefix.key.reference;
        let Some(ordinal) = reference.ordinal() else {
            self.prefix_evidence.borrow_mut().insert(
                prefix.key,
                JvmPackagePrefix::Retained(prefix.selected.completion().clone()),
            );
            return Ok(Some(prefix.raw.clone()));
        };
        let mount = self
            .state
            .operation
            .mount_table()
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let owners = self
            .state
            .jvm_type_prefix_targets(reference, prefix.selected, mount.semantic_language())
            .filter(|owners| !owners.is_empty());
        let normalize = |completion: &ResolutionCompletion| -> Result<Option<JvmPackagePrefix>> {
            if completion == &ResolutionCompletion::Complete {
                return Ok(Some(JvmPackagePrefix::Witness(Vec::new())));
            }
            if let Some(owners) = &owners {
                self.state.jvm_type_prefix_evidence(
                    mount.semantic_language(),
                    mount.fragment(),
                    reference,
                    owners,
                    completion,
                )
            } else if prefix.selected.binding().targets().is_empty() {
                self.state
                    .jvm_package_prefix_evidence(mount.fragment(), completion)
            } else {
                Ok(Some(JvmPackagePrefix::Retained(completion.clone())))
            }
        };
        let Some(raw_evidence) = normalize(prefix.raw)? else {
            return Ok(None);
        };
        // The shared driver normalizes only this reference's raw reasons.
        // Discharge authority still depends on the whole selected answer,
        // including foreign inventory gaps.
        let selected_evidence = if prefix.raw == prefix.selected.completion() {
            raw_evidence.clone()
        } else {
            let Some(evidence) = normalize(prefix.selected.completion())? else {
                return Ok(None);
            };
            evidence
        };
        let completion = match raw_evidence {
            JvmPackagePrefix::Witness(retired) => {
                completion_without_unsupported_semantics(prefix.raw, &retired)
            }
            JvmPackagePrefix::Retained(completion) => completion,
        };
        self.prefix_evidence
            .borrow_mut()
            .insert(prefix.key, selected_evidence);
        Ok(Some(completion))
    }
    fn register_publication(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        ready: &ReadySelectedResolution<'_, '_>,
        registration: &SelectedFactOperationBlueprint,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
    ) -> Result<ContextRegistrationOutcome> {
        let source = &self.sources[&frame.endpoint];
        let key = JvmProviderRegistrationKey {
            mount: source.mount,
            scope: self.state.operation.ready.inventory.scope_identity(),
            stage_epoch: self.state.operation.ready.inventory.staged_read_epoch(),
        };
        let result = self
            .state
            .operation
            .jvm_context_registrations
            .borrow_mut()
            .register(key, registration, |cells| {
                ready.register_context_cells_in_session(registration, cells, cancellation, session)
            })?;
        if !matches!(result, ContextRegistrationOutcome::Cancelled) {
            self.state.remember_registration(
                frame.context.and_then(|key| self.prepared.get(&key)),
                registration,
            );
        }
        Ok(result)
    }
    fn publication_delta(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        registration: &SelectedFactOperationBlueprint,
        _: &dyn crate::analyzer::resolution::SelectedContextPathSource,
        _: &CancellationToken,
    ) -> Result<Read<super::demand_closure::PublicationDelta>> {
        let delta = self.state.context_delta(registration.context_token())?;
        let source = &self.sources[&frame.endpoint];
        if delta.is_some()
            && (source.mount != self.state.caller || source.qualified.is_some())
            && !super::demand_closure::closer_step(
                self.state.session,
                self.state.cancellation,
                super::demand_closure::CloserWork::CompletionPacking,
            )
        {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        Ok(match delta {
            Some((relation, paths)) => {
                Read::ready(super::demand_closure::PublicationDelta { relation, paths })
            }
            None => Read::Cancelled(cancelled_completion()),
        })
    }
}

// Shared-only real-producer fixture and lifecycle support.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod shared_contract;

#[derive(Default)]
struct JvmSourceAuthority {
    complete: bool,
    prefix: Option<SemanticId>,
    external_nominal: Option<SemanticId>,
}

struct JvmNamedImport {
    context: SelectedResolutionContextSet,
    bindings: Vec<crate::analyzer::resolution::SelectedRootBridgeDescriptor>,
}

#[derive(Clone)]
enum JvmSourceTarget {
    Route(super::demand_closure::RouteLocation),
    Import(usize),
}

struct JvmSourceState {
    reader: super::jvm_context::JvmSourceReaderContext,
    named_import: Option<JvmNamedImport>,
    start: JvmSourceStart,
    completion: ResolutionCompletion,
    discharges: DemandClosureDischarges,
    terminal_reasons: Vec<SemanticId>,
    authority: RefCell<JvmSourceAuthority>,
    material: RefCell<
        HashMap<super::demand_closure::ExportAuthority, super::demand_closure::BridgeMaterial>,
    >,
    observations: RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
}
impl JvmSourceState {
    fn new(
        start: JvmSourceStart,
        completion: ResolutionCompletion,
        discharges: DemandClosureDischarges,
        reader: super::jvm_context::JvmSourceReaderContext,
        terminal_reasons: Vec<SemanticId>,
    ) -> Self {
        let prefix = start.prefix();
        Self {
            reader,
            named_import: None,
            start,
            completion,
            discharges,
            terminal_reasons,
            authority: RefCell::new(JvmSourceAuthority {
                complete: true,
                prefix,
                external_nominal: None,
            }),
            material: RefCell::new(HashMap::default()),
            observations: RefCell::new(Vec::new()),
        }
    }
}

#[derive(Clone)]
enum JvmSourceStart {
    Absolute,
    NamedImport,
    PositionedPackage(SemanticId),
    Members {
        reference: SemanticId,
        values: Vec<ResolutionSlotValue>,
    },
    Unresolved(Option<SemanticId>),
}
impl JvmSourceStart {
    fn prefix(&self) -> Option<SemanticId> {
        match self {
            Self::Absolute | Self::NamedImport => None,
            Self::Unresolved(prefix) => *prefix,
            Self::PositionedPackage(reference) | Self::Members { reference, .. } => {
                Some(*reference)
            }
        }
    }
}

// Cheap source view reconstructed from owned inputs after each scheduler wait.
struct JvmHalfRows<'a, 'store, 'input> {
    rules: &'a JvmRules<'a, 'store, 'input>,
    source: &'a super::demand_closure::SourceHalf,
    language: Language,
    state: &'a JvmSourceState,
}

impl JvmHalfRows<'_, '_, '_> {
    fn import_material(
        &self,
        bridge: &crate::analyzer::resolution::SelectedRootBridgeDescriptor,
    ) -> Result<super::demand_closure::BridgeMaterial> {
        let context = &self
            .state
            .named_import
            .as_ref()
            .expect("named import binding")
            .context;
        Ok(super::demand_closure::BridgeMaterial {
            source_language: bridge.source_language(),
            target_language: bridge.target_language(),
            precedence: bridge.precedence(),
            candidate_origin_rank: bridge.candidate_origin_rank(),
            target_definition: bridge.target_definition(),
            cross_language_evidence: bridge.jvm_evidence(),
            callable_import: bridge
                .callable_import_boundary(
                    &context.identity_space(),
                    &self.rules.state.operation.ready.lexical_source(),
                    self.rules.state.cancellation,
                )?
                .map(|_| bridge.source_import_token()),
        })
    }
    fn owner_request(
        &self,
        location: &super::demand_closure::RouteLocation,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Option<DemandMemberSelectionRequest> {
        let super::demand_closure::RouteLocation::Owner { definition, .. } = location else {
            return None;
        };
        Some(self.selection_request(
            self.source.prefix.unwrap_or(self.source.token),
            vec![ResolutionSlotValue::type_object(
                crate::analyzer::resolution::ResolutionTypeRef::new(*definition, 0),
            )],
            lookup,
        ))
    }
    // A Scala qualifier in a type path can be a singleton term or a nested
    // type. Value member selection includes Scala's declared NestedType alias.
    fn qualifier_lookup(
        &self,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> ResolutionLookupSemanticRecipe {
        let rules = nominal_rules::nominal_language_rules(self.language)
            .expect("caller belongs to a nominal family");
        let namespace = rules.qualifier_namespace(lookup.namespace());
        if namespace == lookup.namespace() {
            lookup.clone()
        } else {
            ResolutionLookupSemanticRecipe::new(rules.language(), namespace, lookup.spelling())
        }
    }

    fn selection_request(
        &self,
        reference: SemanticId,
        values: Vec<ResolutionSlotValue>,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> DemandMemberSelectionRequest {
        let namespace = nominal_rules::nominal_language_rules(self.language)
            .expect("caller belongs to a nominal family")
            .selection_namespace(lookup.namespace());
        DemandMemberSelectionRequest {
            policy: &crate::analyzer::resolution::DEFAULT_HIERARCHY_POLICY,
            order: Some(crate::analyzer::resolution::HierarchyOrderRequest {
                policy: &super::jvm_hierarchy_order::JVM_DECLARED_ORDER,
                start_after: None,
            }),
            reference,
            values,
            lookup: ResolutionLookupSemanticRecipe::new(
                self.language,
                namespace,
                lookup.spelling(),
            )
            .semantic(&self.rules.state.operation.ready.shared_names()),
            namespace: lookup.namespace(),
            language: self.language,
        }
    }
}

impl super::demand_closure::RouteRules<super::demand_closure::ClosureTag>
    for JvmHalfRows<'_, '_, '_>
{
    fn member_request(
        &self,
        cursor: &super::demand_closure::WalkCursor<super::demand_closure::ClosureTag>,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Read<Option<DemandMemberSelectionRequest>>> {
        Ok(Read::ready(self.owner_request(
            &cursor.location,
            &self.qualifier_lookup(lookup),
        )))
    }
    fn root_starts(
        &self,
        cursor: &super::demand_closure::WalkCursor<super::demand_closure::ClosureTag>,
        _: &mut ResolutionCompletion,
    ) -> Result<super::demand_closure::RouteStarts> {
        Ok(super::demand_closure::RouteStarts {
            locations: vec![cursor.location.clone()],
            consumed: 0,
        })
    }
    fn route_tier(
        &self,
        cursor: &super::demand_closure::WalkCursor<super::demand_closure::ClosureTag>,
        segment: &ResolutionLookupSemanticRecipe,
        tier: usize,
    ) -> Result<Option<super::demand_closure::RouteEdgeTier>> {
        if tier != 0 {
            return Ok(None);
        }
        let super::demand_closure::RouteLocation::Container { unit, container } = &cursor.location
        else {
            unreachable!("owner routes yield a member request before route tiers");
        };
        if segment.namespace() != ResolutionNamespace::Package {
            let Some(rows) = self.rules.state.operation.jvm_pure_package_exports(
                self.source,
                segment,
                container,
                &self.state.reader,
                &self.state.completion,
                self.rules.state.cancellation,
            )?
            else {
                return Ok(None);
            };
            self.state
                .observations
                .borrow_mut()
                .extend(rows.observations);
            if !rows.exports.is_empty() || rows.external_owner.is_some() {
                self.state.authority.borrow_mut().complete &= rows.complete;
                return Ok(Some(super::demand_closure::RouteEdgeTier {
                    edges: rows
                        .exports
                        .into_iter()
                        .map(|row| row.declaration)
                        .chain(rows.external_owner)
                        .map(|definition| super::demand_closure::RouteLocation::Owner {
                            definition,
                            scope: None,
                        })
                        .collect(),
                    ..Default::default()
                }));
            }
        }
        let package = if container.is_empty() {
            segment.spelling().to_owned()
        } else {
            format!("{container}.{}", segment.spelling())
        };
        Ok(Some(super::demand_closure::RouteEdgeTier {
            edges: vec![super::demand_closure::RouteLocation::Container {
                unit: *unit,
                container: package,
            }],
            ..Default::default()
        }))
    }
    fn dead_end(
        &self,
        _: &super::demand_closure::WalkCursor<super::demand_closure::ClosureTag>,
        _: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        Ok(ResolutionCompletion::Complete)
    }
}
impl super::demand_closure::HalfRules for JvmHalfRows<'_, '_, '_> {
    type MemberRow = crate::analyzer::resolution::LoweredMemberOwnerProperty;
    type Rank = JvmBindingPrecedence;
    type Provider = SemanticId;
    type LexicalTiers =
        std::iter::Empty<super::demand_closure::LexicalStartTier<Self::Rank, Self::Provider>>;
    type Placement = ();
    type Target = JvmSourceTarget;
    type Member = ();
    fn source_import_targets(&self, _: &()) -> Result<Read<Option<Vec<Self::Target>>>> {
        Ok(Read::ready(self.state.named_import.as_ref().map(|named| {
            named
                .bindings
                .iter()
                .enumerate()
                .filter(|(_, bridge)| bridge.target_definition().is_some())
                .map(|(index, _)| JvmSourceTarget::Import(index))
                .collect()
        })))
    }
    fn proven_targets(
        &self,
        _: &(),
        target: &Self::Target,
        _: &ResolutionCompletion,
    ) -> Result<Read<Vec<super::demand_closure::ProvenTarget>>> {
        let JvmSourceTarget::Import(index) = target else {
            return Ok(Read::ready(Vec::new()));
        };
        let bridge = &self
            .state
            .named_import
            .as_ref()
            .expect("named import target")
            .bindings[*index];
        if !bridge.is_member_target() {
            return Ok(Read::ready(Vec::new()));
        }
        Ok(Read::ready(vec![super::demand_closure::ProvenTarget {
            target: super::demand_closure::SelectedMemberTarget {
                fragment: bridge.target_fragment(),
                token: bridge.target_export_token(),
                definition: bridge
                    .target_definition()
                    .expect("selected import definition"),
                lookup: bridge.target_demand().clone(),
                completion: bridge.completion().clone(),
            },
            material: self.import_material(bridge)?,
        }]))
    }
    fn source_endpoint_completion(
        &self,
        _: &super::demand_closure::SourceHalf,
        endpoint: &EndpointSignature,
        _: &ReadySelectedResolution<'_, '_>,
    ) -> Option<ResolutionCompletion> {
        self.state.named_import.as_ref()?;
        let source = &self.rules.sources[endpoint];
        (!source.caller_gap_reasons.is_empty())
            .then(|| JvmDemandState::caller_gap_completion(source))
    }
    fn initial_completion(&self) -> ResolutionCompletion {
        self.state.completion.clone()
    }
    fn provider_observations(
        &self,
    ) -> Result<Read<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>> {
        let mut observations = std::mem::take(&mut *self.state.observations.borrow_mut());
        observations.append(&mut *self.state.reader.observations.borrow_mut());
        Ok(Read::ready(observations))
    }
    fn terminal_member_request(
        &self,
        _: &(),
        target: &super::demand_closure::SourceTargetContext<'_, Self::Rank>,
    ) -> Result<Read<Option<DemandMemberSelectionRequest>>> {
        Ok(Read::ready(
            self.owner_request(&target.cursor.location, target.lookup),
        ))
    }
    fn member_rows(
        &self,
        _: &(),
        route: &super::demand_closure::MemberRouteContext<'_, Self::Rank>,
        owner: SemanticId,
    ) -> Result<Read<Vec<Self::MemberRow>>> {
        let Some(read) = self.rules.state.operation.jvm_source_member_rows(
            owner,
            route,
            self.source.token,
            self.rules.state.cancellation,
        )?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        let completion = read.observation.completion.clone();
        self.state.authority.borrow_mut().complete &= read.observation.inventory_complete
            == Some(true)
            && completion == ResolutionCompletion::Complete;
        self.state.observations.borrow_mut().push(read.observation);
        Ok(Read::Ready {
            value: read.rows,
            completion,
        })
    }
    fn member_target(
        &self,
        _: &(),
        route: &super::demand_closure::MemberRouteContext<'_, Self::Rank>,
        row: &Self::MemberRow,
    ) -> Result<Read<Option<super::demand_closure::SelectedMemberRouteTarget>>> {
        let target = self.rules.state.operation.jvm_source_member_target(
            self.source,
            &self.state.reader,
            route,
            row,
            self.rules.state.cancellation,
        )?;
        if let Read::Ready { completion, .. } = &target {
            let mut authority = self.state.authority.borrow_mut();
            authority.complete &=
                completion_without_unsupported_semantics(completion, &self.state.terminal_reasons)
                    == ResolutionCompletion::Complete;
        }
        Ok(target)
    }
    fn language(&self) -> Language {
        self.language
    }
    fn placements(&mut self) -> Vec<()> {
        vec![()]
    }
    fn placement(
        &self,
        _: &(),
        tag: super::demand_closure::ClosureTag,
    ) -> Option<super::demand_closure::PlacementFacts<Self::Target>> {
        Some(super::demand_closure::PlacementFacts {
            tag,
            completion: ResolutionCompletion::Complete,
            targets: Vec::new(),
            members: Vec::new(),
        })
    }
    fn root_starts(
        &mut self,
        _: &(),
        facts: &mut super::demand_closure::PlacementFacts<Self::Target>,
    ) -> Result<Vec<super::demand_closure::PlacementStart<(), Self::Rank>>> {
        use super::demand_closure::{PlacementStart, RouteLocation, WalkCursor};
        if let JvmSourceStart::Members { reference, values } = &self.state.start {
            // The selected lexical prefix consumes the first route segment;
            // any remaining segments still belong to the shared route driver.
            let consumed = if self.source.is_import {
                // Import qualifier views already select the complete owner.
                self.source.route.len()
            } else {
                usize::from(!self.source.route.is_empty())
            };
            let (position, lookup) = if let Some(segment) = self.source.route.get(consumed) {
                (super::demand_closure::MemberRoutePosition::Segment, segment)
            } else {
                (
                    super::demand_closure::MemberRoutePosition::Terminal,
                    &self.source.demand,
                )
            };
            let lookup = if position == super::demand_closure::MemberRoutePosition::Segment {
                self.qualifier_lookup(lookup)
            } else {
                lookup.clone()
            };
            return Ok(vec![PlacementStart::MemberRequest {
                position,
                cursor: WalkCursor {
                    tag: facts.tag,
                    location: RouteLocation::Owner {
                        definition: values
                            .first()
                            .expect("selected owner projection is nonempty")
                            .ty()
                            .identity(),
                        scope: None,
                    },
                    consumed_prefix_segments: consumed,
                    start_step: consumed,
                    namespace: self.source.demand.namespace(),
                },
                request: self.selection_request(*reference, values.clone(), &lookup),
                anchor: self.source.anchor,
                rank: None,
                scope: None,
            }]);
        }
        if matches!(self.state.start, JvmSourceStart::Unresolved(_)) {
            return Ok(Vec::new());
        }
        let (package, consumed) =
            if matches!(self.state.start, JvmSourceStart::PositionedPackage(_)) {
                // The positioned prefix was already classified as a package. Do
                // not search root exports for an unrelated type of that spelling.
                (
                    self.source
                        .route
                        .first()
                        .expect("positioned package has a route prefix")
                        .spelling(),
                    1,
                )
            } else if self.source.route.is_empty() {
                let Some(package) = nominal_rules::nominal_language_rules(self.language)
                    .expect("caller belongs to a nominal family")
                    .empty_route_package(self.state.reader.package.as_deref())
                else {
                    self.state.authority.borrow_mut().complete = false;
                    return Ok(Vec::new());
                };
                (package, 0)
            } else {
                ("", 0)
            };
        Ok(vec![PlacementStart::Route {
            cursor: WalkCursor {
                tag: facts.tag,
                location: RouteLocation::Container {
                    unit: 0,
                    container: package.to_owned(),
                },
                consumed_prefix_segments: consumed,
                start_step: consumed,
                namespace: self.source.demand.namespace(),
            },
            anchor: self.source.anchor,
            // Package-only starts carry no proven binding origin.
            rank: None,
            scope: None,
        }])
    }
    fn route_rules<'a>(
        &'a self,
        _: &'a (),
        _: ResolutionRootImportAnchor,
        _: &'a [ResolutionLookupSemanticRecipe],
    ) -> impl super::demand_closure::RouteRules<super::demand_closure::ClosureTag> + 'a {
        self
    }
    fn route_target(
        &self,
        location: super::demand_closure::RouteLocation,
        _: Option<&Self::Rank>,
        _: Option<ResolutionScopeId>,
    ) -> Self::Target {
        JvmSourceTarget::Route(location)
    }
    fn target_location(&self, target: &Self::Target) -> super::demand_closure::RouteLocation {
        match target {
            JvmSourceTarget::Route(location) => location.clone(),
            JvmSourceTarget::Import(index) => {
                let bridge = &self
                    .state
                    .named_import
                    .as_ref()
                    .expect("named import target")
                    .bindings[*index];
                let definition = bridge
                    .target_definition()
                    .expect("selected import definition");
                super::demand_closure::RouteLocation::Owner {
                    definition: SemanticId::local(
                        definition.ordinal().expect("mounted import definition"),
                        definition.local_key().expect("local import definition"),
                    ),
                    scope: None,
                }
            }
        }
    }
    fn exports(
        &self,
        _: &(),
        target: Self::Target,
        completion: &ResolutionCompletion,
    ) -> Result<Option<super::demand_closure::ExportHydration>> {
        if let JvmSourceTarget::Import(index) = target {
            let bridge = &self
                .state
                .named_import
                .as_ref()
                .expect("named import target")
                .bindings[index];
            if bridge.is_member_target() {
                return Ok(Some(super::demand_closure::ExportHydration {
                    exports: Vec::new(),
                    blockers: Vec::new(),
                    unstaged: ResolutionCompletion::Complete,
                    coverage: Default::default(),
                }));
            }
            let Some(inventory) = self.rules.state.operation.jvm_root_exports(
                SelectedResolutionMountOrdinal::new(bridge.target_fragment().ordinal()),
                self.rules.state.cancellation,
            )?
            else {
                return Ok(None);
            };
            if !inventory.outcome.is_exhausted() {
                return Ok(None);
            }
            let export = inventory.halves.iter().find(|half| matches!(half,
                SelectedRootPathHalf::Export { token, definition, demand, .. }
                if *token == bridge.target_export_token()
                    && Some(*definition) == bridge.target_definition()
                    && *demand == bridge.target_demand().semantic(&self.rules.state.operation.ready.shared_names())
            )).expect("named import retains its canonical export").clone();
            let SelectedRootPathHalf::Export {
                identity,
                token,
                demand,
                definition,
                ..
            } = &export
            else {
                unreachable!("canonical export");
            };
            self.state.material.borrow_mut().insert(
                super::demand_closure::ExportAuthority {
                    fragment: identity.fragment(),
                    token: *token,
                    demand: *demand,
                    definition: *definition,
                },
                self.import_material(bridge)?,
            );
            return Ok(Some(super::demand_closure::ExportHydration {
                exports: vec![(
                    export,
                    bridge.target_demand().clone(),
                    bridge.completion().clone(),
                )],
                blockers: Vec::new(),
                unstaged: ResolutionCompletion::Complete,
                coverage: Default::default(),
            }));
        }
        let JvmSourceTarget::Route(super::demand_closure::RouteLocation::Container {
            container,
            ..
        }) = target
        else {
            panic!("pure package target reached member boundary");
        };
        let Some(rows) = self.rules.state.operation.jvm_pure_package_exports(
            self.source,
            &self.source.demand,
            &container,
            &self.state.reader,
            completion,
            self.rules.state.cancellation,
        )?
        else {
            return Ok(None);
        };
        self.state
            .observations
            .borrow_mut()
            .extend(rows.observations);
        let mut authority = self.state.authority.borrow_mut();
        authority.complete &= rows.complete;
        if let Some(owner) = rows.external_owner {
            assert!(
                authority
                    .external_nominal
                    .is_none_or(|selected| selected == owner),
                "one qualified package route selects one external type identity"
            );
            authority.external_nominal = Some(owner);
        }
        let mut exports = Vec::new();
        for row in rows.exports {
            let SelectedRootPathHalf::Export {
                identity,
                token,
                demand,
                definition,
                ..
            } = &row.export
            else {
                unreachable!("package reader returns exports");
            };
            self.state.material.borrow_mut().insert(
                super::demand_closure::ExportAuthority {
                    fragment: identity.fragment(),
                    token: *token,
                    demand: *demand,
                    definition: *definition,
                },
                row.material,
            );
            exports.push((row.export, row.lookup, row.completion));
        }
        Ok(Some(super::demand_closure::ExportHydration {
            exports,
            blockers: Vec::new(),
            unstaged: ResolutionCompletion::Complete,
            coverage: Default::default(),
        }))
    }
    fn empty_target(&self, _: &(), _: &Self::Target) -> Result<ResolutionCompletion> {
        Ok(ResolutionCompletion::Complete)
    }
}
