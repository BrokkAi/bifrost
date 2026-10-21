//! JVM source contexts admitted only when a selected endpoint reaches them.
use super::demand::{
    ClosedForwardSource, ClosedRelations, DemandLanguage, DemandProvider, LanguageClosure,
    LanguageContextPreparation, LanguagePrefixInputs, LanguageRootDiscovery,
};
use super::demand_closure::{
    BaseEligibility, ClosureWitness, Read, RouteDisposition, StagedClosure, StagedPreparation,
};
use super::jvm_context::{
    JvmImportContext, JvmImportContextGap, JvmRoutePublication, is_jvm_language,
    jvm_prefix_defers_member_selection,
};
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::DemandReferenceKey;
use crate::analyzer::resolution::DemandRelationKey;
use crate::analyzer::resolution::{
    BindingOrigin, DemandMemberSelection, DemandMemberSelectionOutcome,
    DemandMemberSelectionRequest, DemandSelectedOverlayBlueprint, EndpointSignature,
    FactResolutionAnswer, JvmImplicitRootProvider, LoweringGapOrigin,
    SelectedResolutionMountContext, binding_origin_rank, language_implicit_root_providers,
    language_implicit_root_providers_in_namespace,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct JvmBindingPrecedence {
    // Match shared path precedence: binding origin before lexical depth.
    rank: u32,
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
                    let selector = super::jvm_context::selected_jvm_import_selector(
                        connection,
                        record.blob_id(),
                        *token,
                    )?;
                    let route = super::jvm_context::selected_import_route(
                        connection,
                        record.blob_id(),
                        mount,
                        *token,
                    )?;
                    let wildcard = selector
                        .as_ref()
                        .is_some_and(|selector| selector.source_name.is_none())
                        || route.as_ref().is_some_and(|route| {
                            matches!(route.kind.as_str(), "type_on_demand" | "static_on_demand")
                        });
                    // The half's demand is the lookup bound in the importing
                    // scope, including for wildcard imports. The owner route
                    // is separate; another demand through that same wildcard
                    // is not a competing binder for this name or namespace.
                    if *demand != lookup_semantic {
                        continue;
                    }
                    let origin = if wildcard {
                        match record.semantic_language() {
                            Language::Kotlin => BindingOrigin::StarImport,
                            Language::Java => BindingOrigin::OnDemandImport,
                            _ => BindingOrigin::WildcardImport,
                        }
                    } else if record.semantic_language() == Language::Java {
                        BindingOrigin::SingleTypeImport
                    } else {
                        BindingOrigin::ExplicitImport
                    };
                    let rank = binding_origin_rank(record.semantic_language(), origin);
                    if let Some(rank) = rank {
                        binders.push((*token, *source_scope_head, *activation, rank));
                    }
                }
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
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

#[cfg_attr(test, derive(Clone))]
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

#[derive(PartialEq, Eq, Hash)]
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

struct JvmDemandLanguage<'a, 'store, 'input> {
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
    selected_import_gap: Option<(SemanticId, SemanticId)>,
    imported_prefix_targets: HashMap<SemanticId, (BTreeSet<SemanticId>, ResolutionCompletion)>,
    pending_registration: Option<JvmPendingRegistration>,
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

    fn stage_scala_import(
        &self,
        source: &JvmSourceDemand,
        bridges: Vec<SelectedRootBridgeDescriptor>,
        completion: ResolutionCompletion,
        discharges: DemandClosureDischarges,
    ) -> Result<Read<StagedClosure>> {
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
        let mut staged = Self::staged_base(completion.clone(), Some(discharges));
        staged.disposition = RouteDisposition::Publish;
        staged.base = BaseEligibility::Exclude;
        staged.endpoint_completion = Some(completion);
        staged.preparation = Some(StagedPreparation::Prepared(context));
        self.stage_descriptor_material(&mut staged);
        Ok(Read::ready(staged))
    }

    fn stage_unknown_scala_import(
        &self,
        source: &JvmSourceDemand,
        prefix_completion: &ResolutionCompletion,
    ) -> Result<Read<StagedClosure>> {
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
        self.stage_scala_import(
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

    fn stage_scala_import_members(
        &self,
        source: &JvmSourceDemand,
        prefix_completion: &ResolutionCompletion,
        selection: &DemandMemberSelection,
    ) -> Result<Read<StagedClosure>> {
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
            return Ok(Read::Cancelled(cancelled_completion()));
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
        self.stage_scala_import(
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
        let Some(import_bindings) = self.operation.jvm_import_bindings_for_lookup(
            source.mount,
            lookup,
            self.cancellation,
        )?
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
                    .jvm_external_provider_type_identity_for_reference(binding.reference)
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
                "SELECT EXISTS(
                   SELECT 1 FROM main.workspace_file_package_rows AS package INDEXED BY idx_workspace_file_package_rows_name
                   JOIN temp.selected_resolution_mounts AS mounted ON mounted.file_version_id=package.file_version_id
                   JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id AND meta.is_complete=1
                   WHERE mounted.storage_language IN ('java','kotlin','scala')
                     AND (package.package_name=?1 OR (package.package_name>=?1||'.' AND package.package_name<?1||'/'))
                   UNION ALL
                   SELECT 1 FROM temp.selected_resolution_mounts AS mounted
                   JOIN main.blob_meta AS meta ON meta.blob_id=mounted.blob_id AND meta.is_complete=1
                   WHERE mounted.file_version_id IS NULL AND mounted.storage_language IN ('java','kotlin','scala')
                     AND (meta.content_package=?1 OR (meta.content_package>=?1||'.' AND meta.content_package<?1||'/'))
                 )", [lookup.spelling()], |row| row.get(0),
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
                identities.jvm_external_provider_type_identity_for_reference(receiver),
            ),
        );
        let Some(owner) = identities.jvm_external_provider_type_identity_for_reference(receiver)
        else {
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
                        coverage.callables_complete
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
                        let Some(bindings) = self.operation.jvm_import_bindings_for_lookup(
                            mount,
                            &gap.lookup,
                            self.cancellation,
                        )?
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
            let Some(bindings) = self.operation.jvm_import_bindings_for_lookup(
                mount,
                &gap.lookup,
                self.cancellation,
            )?
            else {
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
                || (language == Language::Java && !implicit_root_reference)
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
        self.discover_source(endpoint)
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
                contexts: RefCell::new(HashMap::default()),
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
            references: references
                .into_iter()
                .map(DemandReferenceKey::caller)
                .collect(),
            completion: ResolutionCompletion::Complete,
        })
    }

    fn member_selection(
        &mut self,
        source: &Self::RootQuestion,
        _context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<DemandMemberSelectionOutcome> {
        let request = self.selected_member_request(source, inputs)?;
        Ok(DemandMemberSelectionOutcome::Ready {
            request,
            completion: ResolutionCompletion::Complete,
        })
    }

    fn close_selected_members(
        &mut self,
        endpoint: &EndpointSignature,
        source: &Self::RootQuestion,
        _context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        selection: &DemandMemberSelection,
    ) -> Result<LanguageClosure> {
        let completion = inputs
            .iter()
            .fold(ResolutionCompletion::Complete, |completion, (_, answer)| {
                completion.combine(answer.completion())
            });
        let staged = self.stage_scala_import_members(source, &completion, selection)?;
        self.publish_staged(endpoint, source, None, staged)
    }

    fn close_root(
        &mut self,
        endpoint: &EndpointSignature,
        source: &Self::RootQuestion,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<LanguageClosure> {
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguageClosure {
                completion: cancelled_completion(),
                closed: false,
                discharges: None,
            });
        }
        let staged = self.stage_root(endpoint, source, context, inputs)?;
        self.publish_staged(endpoint, source, context, staged)
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
                if let ResolutionSlotValue::TypeObject(ty) = value
                    && !self.operation.jvm_scala_object_definition(ty.identity())?
                {
                    return Ok(None);
                }
            }
            self.scala_import_member_request(source, values)
        })()
    }

    fn stage_descriptor_material(&self, staged: &mut StagedClosure) {
        use super::demand_closure::{ExportAuthority, TargetAuthority};
        if let Some(StagedPreparation::Prepared(context)) = &staged.preparation {
            staged.bridges = context.root_bridges().to_vec();
        }
        staged.targets = staged
            .bridges
            .iter()
            .filter_map(|bridge| {
                let definition = bridge.target_definition()?;
                let fragment = bridge.target_fragment();
                let token = bridge.target_export_token();
                let demand = bridge
                    .target_demand()
                    .semantic(&self.operation.ready.shared_names());
                Some(if bridge.is_member_target() {
                    TargetAuthority::Member {
                        fragment,
                        token,
                        demand,
                        definition,
                    }
                } else {
                    TargetAuthority::Export(ExportAuthority {
                        fragment,
                        token,
                        demand,
                        definition,
                    })
                })
            })
            .collect();
    }

    fn staged_base(
        completion: ResolutionCompletion,
        discharges: Option<DemandClosureDischarges>,
    ) -> StagedClosure {
        let witness = ClosureWitness {
            discharged_provider_reasons: discharges
                .as_ref()
                .map(|proof| proof.discharged_provider_reasons.clone())
                .unwrap_or_default(),
            positive_binding_providers: discharges
                .as_ref()
                .map(|proof| proof.positive_binding_providers.clone())
                .unwrap_or_default(),
        };
        StagedClosure {
            disposition: RouteDisposition::RetainBase,
            base: BaseEligibility::Retain,
            completion,
            members: None,
            targets: Vec::new(),
            bridges: Vec::new(),
            witness,
            discharges,
            preparation: None,
            endpoint_completion: None,
        }
    }

    // J2 replaces the private lexical/precedence decisions; J3 replaces the
    // private provider/member closure. This stage never registers or publishes.
    fn stage_root(
        &mut self,
        endpoint: &EndpointSignature,
        source: &JvmSourceDemand,
        context: Option<&JvmPreparedContext>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Read<StagedClosure>> {
        self.pending_registration = None;
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
                return self.stage_unknown_scala_import(source, &completion);
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
                    return self.stage_unknown_scala_import(source, &completion);
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
                    return self.stage_unknown_scala_import(source, &completion);
                }
            }
            if !nominal_type {
                if inputs
                    .iter()
                    .any(|(_, answer)| !answer.binding().targets().is_empty())
                {
                    return self.stage_unknown_scala_import(source, &completion);
                }
                let fragment = match import_half {
                    SelectedRootPathHalf::Import { identity, .. } => identity.fragment(),
                    _ => unreachable!("Scala import half"),
                };
                for (_, answer) in inputs {
                    let Some(package) =
                        self.jvm_package_prefix_evidence(fragment, answer.completion())?
                    else {
                        return Ok(Read::Cancelled(cancelled_completion()));
                    };
                    if !matches!(package, JvmPackagePrefix::Witness(_)) {
                        return self.stage_unknown_scala_import(source, &completion);
                    }
                }
            }
            if mount == self.caller && source.caller_gap_reasons.is_empty() {
                return Ok(Read::ready(Self::staged_base(completion, None)));
            }
        }
        if mount == self.caller && qualified.is_none() {
            assert!(
                context.is_none(),
                "caller import gaps need no provider context"
            );
            assert!(
                inputs.is_empty() || source.import_qualifiers.is_some(),
                "caller import gaps have no prefixes"
            );
            let preparation =
                if source.import_qualifiers.is_none() && self.whole_file_import_gaps.is_none() {
                    let caller_mount = self.operation.mount_table().mount_by_ordinal(mount)?;
                    let Some(mut recipes) = self.operation.jvm_lookup_recipes(
                        caller_mount.fragment(),
                        [source.lookup],
                        self.cancellation,
                    )?
                    else {
                        return Ok(Read::Cancelled(cancelled_completion()));
                    };
                    let recipe = recipes.pop().expect("one caller root lookup");
                    let key = JvmCallerContextKey {
                        name: recipe.spelling().to_owned(),
                        scope: self.operation.ready.inventory.scope_identity(),
                        stage_epoch: self.operation.ready.inventory.staged_read_epoch(),
                    };
                    Some(
                        if let Some(blueprint) = self.caller_registered_contexts.get(&key) {
                            StagedPreparation::Registered(blueprint.clone())
                        } else {
                            let Some((context, _)) = self.file_context(mount, recipe.spelling())?
                            else {
                                return Ok(Read::Cancelled(cancelled_completion()));
                            };
                            self.pending_registration = Some(JvmPendingRegistration::Caller(key));
                            StagedPreparation::Prepared(context)
                        },
                    )
                } else {
                    None
                };
            let completion = if source.caller_gap_reasons.is_empty() {
                ResolutionCompletion::Complete
            } else {
                ResolutionCompletion::incomplete(source.caller_gap_reasons.iter().copied())
            };
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
            let mut staged = Self::staged_base(completion.clone(), discharges);
            staged.endpoint_completion = Some(completion);
            staged.preparation = preparation;
            if staged.preparation.is_some() {
                staged.disposition = RouteDisposition::Publish;
            }
            staged.witness = ClosureWitness {
                discharged_provider_reasons: source.caller_discharged_provider_reasons.clone(),
                positive_binding_providers: source.caller_positive_binding_providers.clone(),
            };
            self.stage_descriptor_material(&mut staged);
            return Ok(Read::ready(staged));
        }
        let preparation = if let Some(half) = qualified {
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
                assert_eq!(inputs[0].0, DemandReferenceKey::caller(*prefix));
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
                            return Ok(Read::Cancelled(cancelled_completion()));
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
                            return Ok(Read::Cancelled(cancelled_completion()));
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
                        return Ok(Read::Cancelled(cancelled_completion()));
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
                    return Ok(Read::Cancelled(cancelled_completion()));
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
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                let source_demand = recipes.pop().expect("qualified root lookup demand");
                let Some((source_context, scoped_gaps)) =
                    self.file_context(mount, source_demand.spelling())?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                let source_reference_semantic =
                    self.jvm_source_reference_semantic(*source_reference)?;
                let source_lookup = source_demand.semantic(&self.operation.ready.shared_names());
                let package_reference_tokens = if let Some(reference) = source_reference_semantic {
                    let SelectedPackageRows::Ready(references) = self
                        .operation
                        .selected_package_reference_for_site(mount, reference, self.cancellation)?
                    else {
                        return Ok(Read::Cancelled(cancelled_completion()));
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
                            return Ok(Read::Cancelled(cancelled_completion()));
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
                let binding_rank = self.complete_binding_origin_rank(
                    &source_context,
                    source,
                    &package_reference_tokens,
                    &source_demand,
                )?;
                let shadowed = self.discharged_provider_reasons(
                    mount,
                    &scoped_gaps,
                    &source_demand,
                    &package_reference_tokens,
                    binding_rank,
                )?;
                if !shadowed.is_empty() {
                    discharges
                        .get_or_insert_with(DemandClosureDischarges::default)
                        .merge(
                            DemandClosureDischarges::default()
                                .with_discharged_provider_reasons(shadowed.iter().copied()),
                        );
                }
                import_gap_reasons.extend(
                    scoped_gaps
                        .iter()
                        .filter(|gap| {
                            gap.lookup == source_demand
                                && !shadowed.contains(&gap.reason)
                                && (gap.kind != "jvm-default-import-package-open"
                                    || !language_implicit_root_providers_in_namespace(
                                        source_language,
                                        gap.lookup.namespace(),
                                    )
                                    .is_empty())
                        })
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
                    return Ok(Read::Cancelled(cancelled_completion()));
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
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                publication
            } else {
                JvmRoutePublication {
                    bridges: Vec::new(),
                    selected_targets: BTreeSet::new(),
                    complete: false,
                }
            };
            // The publication owns its route placeholders, but cannot erase
            // an unavailable provider's independently scoped inventory reason.
            let authority_evidence =
                completion_without_unsupported_semantics(&evidence, &terminal_route_reasons);
            self.operation.profile_jvm_read(
                "binding_precedence_authority",
                (
                    &half,
                    &publication.selected_targets,
                    publication.complete,
                    &evidence,
                    &authority_evidence,
                    &terminal_route_reasons,
                ),
            );
            // An exhausted route cannot prove absence or retire placeholders
            // while a candidate provider still has an incomplete inventory.
            if publication.complete
                && authority_evidence == ResolutionCompletion::Complete
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
                && authority_evidence == ResolutionCompletion::Complete
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
            StagedPreparation::Prepared(context)
        } else {
            assert!(
                inputs.is_empty() || source.import_qualifiers.is_some(),
                "file context has no prefix"
            );
            assert_ne!(mount, self.caller, "caller file roots are already ready");
            let context = context.expect("demanded JVM file context was prepared");
            let source_mount = self.operation.mount_table().mount_by_ordinal(mount)?;
            let lookup = source.lookup;
            let key = JvmPreparedNameKey {
                lookup,
                scope: self.operation.ready.inventory.scope_identity(),
                stage_epoch: self.operation.ready.inventory.staged_read_epoch(),
            };
            let cached = context.contexts.borrow();
            let (preparation, scoped_gaps) = if let Some(cached) = cached.get(&key) {
                (
                    StagedPreparation::Registered(cached.blueprint.clone()),
                    cached.scoped_gaps.clone(),
                )
            } else {
                let Some(mut recipes) = self.operation.jvm_lookup_recipes(
                    source_mount.fragment(),
                    [lookup],
                    self.cancellation,
                )?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                let recipe = recipes.pop().expect("one demanded file lookup");
                let Some((file_context, scoped_gaps)) =
                    self.file_context(mount, recipe.spelling())?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                let file_context = scoped_gaps.iter().fold(file_context, |context, gap| {
                    context.with_context_owned_gap_identity(gap.reason)
                });
                self.pending_registration =
                    Some(JvmPendingRegistration::Provider(key, scoped_gaps.clone()));
                (StagedPreparation::Prepared(file_context), scoped_gaps)
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
            preparation
        };
        let mut staged = Self::staged_base(evidence, discharges);
        staged.disposition = RouteDisposition::Publish;
        staged.preparation = Some(preparation);
        if selected_import_prefix {
            staged.base = BaseEligibility::Exclude;
            staged.endpoint_completion = Some(staged.completion.clone());
        }
        self.stage_descriptor_material(&mut staged);
        Ok(Read::ready(staged))
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

    // J4 retires this production fallback. SharedDemand never calls it.
    fn publish_staged(
        &mut self,
        endpoint: &EndpointSignature,
        source: &JvmSourceDemand,
        context: Option<&JvmPreparedContext>,
        staged: Read<StagedClosure>,
    ) -> Result<LanguageClosure> {
        let mut staged = match staged {
            Read::Ready { value, .. } => value,
            Read::Cancelled(completion) | Read::Unavailable { completion, .. } => {
                return Ok(LanguageClosure {
                    completion,
                    closed: false,
                    discharges: None,
                });
            }
        };
        if let Some(preparation) = staged.preparation.take() {
            let blueprint = match preparation {
                StagedPreparation::Registered(blueprint) => blueprint,
                StagedPreparation::Prepared(contexts) => {
                    let Some(blueprint) = self.register_context(source.mount, contexts)? else {
                        return Ok(LanguageClosure {
                            completion: cancelled_completion(),
                            closed: false,
                            discharges: None,
                        });
                    };
                    self.remember_registration(context, &blueprint);
                    blueprint
                }
            };
            let selected_import =
                source.import_qualifiers.is_some() && staged.base == BaseEligibility::Exclude;
            let delta = if selected_import {
                let relation = DemandSelectedOverlayBlueprint::new(blueprint.context_token());
                let paths = self.operation.ready.lexical_source();
                relation
                    .added_candidate_paths(&paths, self.cancellation)?
                    .map(|paths| (relation, paths))
            } else {
                self.context_delta(blueprint.context_token())?
            };
            let Some((relation, paths)) = delta else {
                return Ok(LanguageClosure {
                    completion: cancelled_completion(),
                    closed: false,
                    discharges: None,
                });
            };
            if !selected_import
                && (source.mount != self.caller || source.qualified.is_some())
                && (self.cancellation.is_cancelled() || !self.session.scope_step())
            {
                return Ok(LanguageClosure {
                    completion: cancelled_completion(),
                    closed: false,
                    discharges: None,
                });
            }
            self.arena.borrow_mut().publish(
                DemandRelationKey::caller(endpoint.clone()),
                relation,
                paths,
            );
        } else {
            self.arena
                .borrow_mut()
                .base_ready
                .insert(DemandRelationKey::caller(endpoint.clone()));
        }
        let key = DemandRelationKey::caller(endpoint.clone());
        let mut arena = self.arena.borrow_mut();
        if staged.base == BaseEligibility::Exclude {
            assert!(arena.excluded_base.insert(key.clone()));
        }
        if let Some(completion) = staged.endpoint_completion {
            assert!(arena.endpoint_completions.insert(key, completion).is_none());
        }
        Ok(LanguageClosure {
            completion: staged.completion,
            closed: true,
            discharges: staged.discharges,
        })
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
        let source = ClosedForwardSource::new(
            &base,
            &paths,
            &arena,
            session,
            crate::analyzer::resolution::CALLER_ENVIRONMENT,
        );
        let provider = DemandProvider::new(JvmDemandLanguage {
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
            selected_import_gap,
            imported_prefix_targets: HashMap::default(),
            pending_registration: None,
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
        lookup: &str,
    ) -> Result<Option<(SelectedResolutionContextSet, Vec<JvmImportContextGap>)>> {
        self.operation
            .profile_jvm_read("demand_file_context", mount);
        let record = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount)?;
        assert!(is_jvm_language(record.semantic_language()));
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
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = self
            .operation
            .collect_jvm_blueprint_in_session(context, self.cancellation, self.session)?
        else {
            return Ok(None);
        };
        let key = JvmProviderRegistrationKey {
            mount,
            scope: self.operation.ready.inventory.scope_identity(),
            stage_epoch: self.operation.ready.inventory.staged_read_epoch(),
        };
        if matches!(
            self.operation
                .jvm_context_registrations
                .borrow_mut()
                .register(key, &blueprint, |cells| self
                    .operation
                    .ready
                    .register_context_cells_in_session(
                        &blueprint,
                        cells,
                        self.cancellation,
                        self.session,
                    ),)?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Ok(None);
        }
        Ok(Some(blueprint))
    }
}

// J1 owns discovery and preparation. J2 replaces private lexical decisions;
// J3 replaces Closed provider/member staging; J4 switches production dispatch.
#[allow(dead_code)]
struct JvmRules<'a, 'store, 'input> {
    language: JvmDemandLanguage<'a, 'store, 'input>,
    sources: HashMap<EndpointSignature, JvmSourceDemand>,
    contexts: Vec<SelectedResolutionMountOrdinal>,
    prepared: HashMap<super::demand_closure::ContextId, JvmPreparedContext>,
    policy: Option<(BaseEligibility, Option<DemandClosureDischarges>)>,
    witness: ClosureWitness,
    member_bridges: Vec<SelectedRootBridgeDescriptor>,
}

#[allow(dead_code)]
impl<'a, 'store, 'input> JvmRules<'a, 'store, 'input> {
    fn new(language: JvmDemandLanguage<'a, 'store, 'input>) -> Self {
        Self {
            language,
            sources: HashMap::default(),
            contexts: Vec::new(),
            prepared: HashMap::default(),
            policy: None,
            witness: ClosureWitness::default(),
            member_bridges: Vec::new(),
        }
    }
}

impl DemandLanguage for JvmRules<'_, '_, '_> {
    type RootQuestion = super::demand_closure::RootFrame;
    type ContextKey = super::demand_closure::ContextId;
    type ContextData = Option<SelectedResolutionContextSet>;
    fn discover_root(
        &mut self,
        _: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<Self::RootQuestion>> {
        unreachable!("JvmRules discovery is executed by SharedDemand")
    }
    // JVM discovery is scalar today. J2 may introduce keyed batching later.
    fn supports_batched_root_discoveries(&self) -> bool {
        false
    }
    fn context_key(&self, frame: &Self::RootQuestion) -> Option<Self::ContextKey> {
        super::demand_closure::DemandRules::context_identity(self, frame)
    }
    fn prepare_context(
        &mut self,
        _: &Self::ContextKey,
        _: &Self::RootQuestion,
    ) -> Result<LanguageContextPreparation<Self::ContextData>> {
        unreachable!("SharedDemand derives JVM contexts")
    }
    fn prefix_inputs(
        &mut self,
        _: &mut Self::RootQuestion,
        _: Option<&Self::ContextData>,
    ) -> Result<LanguagePrefixInputs> {
        unreachable!("SharedDemand positions JVM prefixes")
    }
    fn close_root(
        &mut self,
        _: &EndpointSignature,
        _: &Self::RootQuestion,
        _: Option<&Self::ContextData>,
        _: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<LanguageClosure> {
        unreachable!("SharedDemand publishes JVM stages")
    }
}

impl super::demand_closure::DemandRules for JvmRules<'_, '_, '_> {
    type Half<'b>
        = super::demand_closure::EmptyHalf
    where
        Self: 'b;
    type PreparationKey = ();
    type Certificate = ();

    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        _: bool,
    ) -> Result<Read<super::demand_closure::EndpointAdmission>> {
        use super::demand_closure::{Admission, ContextId, EndpointAdmission, RootFrame};
        self.language
            .operation
            .profile_jvm_read("discover_root", (self.language.caller, endpoint));
        // Reuse the existing discovery and JVM reason minting. Its outer
        // scope-step is supplied once by SharedDemand, not charged again here.
        Ok(match self.language.discover_source(endpoint)? {
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
                let key = self.language.context_key(&question).map(|mount| {
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
    fn context_identity(
        &self,
        frame: &super::demand_closure::RootFrame,
    ) -> Option<super::demand_closure::ContextId> {
        frame.context
    }
    fn derive_context(
        &mut self,
        key: super::demand_closure::ContextId,
        frame: &super::demand_closure::RootFrame,
    ) -> Result<Read<Option<SelectedResolutionContextSet>>> {
        let source = &self.sources[&frame.endpoint];
        Ok(match self.language.prepare_context(&self.contexts[key.0], source)? {
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
        if self.language.cancellation.is_cancelled() {
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
        let references = source
            .import_qualifiers
            .as_ref()
            .map(|(_, refs)| refs.to_vec())
            .unwrap_or_else(|| {
                source
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
            });
        references
            .into_iter()
            .map(|reference| PrefixOperand {
                key: DemandReferenceKey {
                    reference,
                    environment: caller,
                },
                source_halves: Box::new([HalfId(0)]),
            })
            .collect()
    }
    fn provider_preparation(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<super::demand_closure::ProviderPreparation<Self::PreparationKey>>> {
        // J2/J3 replace the private lexical/provider/member closure decisions.
        // This computes inputs only; registration and publication stay shared.
        self.member_bridges.clear();
        let source = &self.sources[&frame.endpoint];
        let context = frame.context.and_then(|key| self.prepared.get(&key));
        let staged = self
            .language
            .stage_root(&frame.endpoint, source, context, inputs)?;
        if let Read::Ready { value, .. } = &staged {
            self.witness = ClosureWitness {
                discharged_provider_reasons: value.witness.discharged_provider_reasons.clone(),
                positive_binding_providers: value.witness.positive_binding_providers.clone(),
            };
            self.policy = Some((value.base, value.discharges.clone()));
        }
        Ok(Some(super::demand_closure::ProviderPreparation::Closed(
            staged,
        )))
    }
    fn member_request(
        &self,
        frame: &super::demand_closure::RootFrame,
        answers: &super::demand_closure::PrefixAnswers<'_>,
    ) -> Result<Read<Option<DemandMemberSelectionRequest>>> {
        // J3 replaces the private member applicability decisions. The shared
        // scheduler already owns hierarchy dependencies and their lifecycle.
        let source = &self.sources[&frame.endpoint];
        let inputs = answers
            .entries
            .iter()
            .map(|entry| (entry.key, entry.answer))
            .collect::<Vec<_>>();
        let request = self.language.selected_member_request(source, &inputs)?;
        Ok(Read::ready(request))
    }
    fn selected_member_targets(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        selection: &DemandMemberSelection,
    ) -> Result<Read<Vec<super::demand_closure::SelectedMemberTarget>>> {
        // J3 replaces this private member-proof projection; no hierarchy walk
        // or provider completeness is reconstructed by this adapter.
        let source = &self.sources[&frame.endpoint];
        let (half, qualifiers) = source.import_qualifiers.as_ref().expect("selected import");
        let Some(publication) = self
            .language
            .operation
            .scala_selected_import_member_bridges(
                half,
                &selection.owners,
                &selection.completion,
                self.language.cancellation,
            )?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        #[cfg(test)]
        for bridge in &publication.bridges {
            bridge.assert_distinct_target_kinds_for_test(
                &self.language.operation.ready.context_identities,
                &self.language.operation.ready.lexical_source(),
                self.language.cancellation,
            );
        }
        let completion = if publication.complete {
            selection.completion.clone()
        } else {
            let reason = self.language.operation.scala_import_owner_gap(
                half,
                *qualifiers.first().expect("selected import has a qualifier"),
                self.language.cancellation,
            )?;
            selection
                .completion
                .combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]))
        };
        let targets = publication
            .bridges
            .iter()
            .map(|bridge| super::demand_closure::SelectedMemberTarget {
                fragment: bridge.target_fragment(),
                token: bridge.target_export_token(),
                definition: bridge
                    .target_definition()
                    .expect("private member proof has a definition"),
                lookup: bridge.target_demand().clone(),
                completion: bridge.completion().clone(),
            })
            .collect();
        self.policy = Some((
            BaseEligibility::Exclude,
            Some(JvmDemandLanguage::scala_import_discharges(source)),
        ));
        self.witness = ClosureWitness {
            discharged_provider_reasons: source.caller_discharged_provider_reasons.clone(),
            positive_binding_providers: source.caller_positive_binding_providers.clone(),
        };
        self.member_bridges = publication.bridges;
        Ok(Read::Ready {
            value: targets,
            completion,
        })
    }
    fn member_bridge_material(
        &self,
        _: &super::demand_closure::RootFrame,
        _: &SelectedRootPathHalf,
        target: &super::demand_closure::SelectedMemberTarget,
        _: Language,
    ) -> Result<super::demand_closure::BridgeMaterial> {
        let bridge = self
            .member_bridges
            .iter()
            .find(|bridge| {
                bridge.target_fragment() == target.fragment
                    && bridge.target_export_token() == target.token
                    && bridge.target_definition() == Some(target.definition)
            })
            .expect("selected target has its exact private descriptor material");
        Ok(super::demand_closure::BridgeMaterial {
            source_language: bridge.source_language(),
            target_language: bridge.target_language(),
            precedence: bridge.precedence(),
            candidate_origin_rank: bridge.candidate_origin_rank(),
            target_definition: bridge.target_definition(),
            cross_language_evidence: bridge.jvm_evidence(),
        })
    }
    fn publication_context(
        &self,
        frame: &super::demand_closure::RootFrame,
        ready: &ReadySelectedResolution<'_, '_>,
        inventory: &ResolutionCompletion,
    ) -> Result<SelectedResolutionContextSet> {
        let source = &self.sources[&frame.endpoint];
        let mount = self
            .language
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?;
        SelectedResolutionContextSet::new(
            ready.context_identities.clone(),
            vec![SelectedResolutionMountContext::new(
                source.mount,
                mount.fragment(),
                mount.semantic_language(),
                Vec::new(),
                inventory.clone(),
            )?],
            self.language.operation.mount_table().mount_count(),
            &selected_mount_lookup(self.language.operation.mount_table()),
        )
    }
    fn closure_witness(
        &mut self,
        _: &super::demand_closure::RootFrame,
        _: &super::demand_closure::PrefixAnswers<'_>,
        _: Option<&DemandMemberSelection>,
    ) -> Result<Read<ClosureWitness>> {
        Ok(Read::ready(ClosureWitness {
            discharged_provider_reasons: self.witness.discharged_provider_reasons.clone(),
            positive_binding_providers: self.witness.positive_binding_providers.clone(),
        }))
    }
    fn closure_policy(
        &self,
        _: &super::demand_closure::RootFrame,
        facts: &super::demand_closure::ClosureFacts<'_>,
    ) -> Result<Read<super::demand_closure::ClosurePolicy>> {
        let (base, discharges) = self.policy.as_ref().expect("closed stage supplies policy");
        let mut exact = discharges.clone().unwrap_or_default();
        exact.discharged_provider_reasons = facts.witness.discharged_provider_reasons.clone();
        exact.positive_binding_providers = facts.witness.positive_binding_providers.clone();
        let mut policy = super::demand_closure::ClosurePolicy::new(
            ResolutionCompletion::Complete,
            *base,
            exact,
            Box::new([]),
        );
        if discharges.is_some() {
            policy.preserve_discharge_record();
        }
        Ok(Read::ready(policy))
    }
    fn compile_publication(
        &mut self,
        _: &super::demand_closure::RootFrame,
        _: &ReadySelectedResolution<'_, '_>,
        contexts: crate::analyzer::resolution::SelectedResolutionContextInputs,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
    ) -> Result<SelectedFactOperationBlueprintConstruction> {
        #[cfg(test)]
        if !self.member_bridges.is_empty() {
            assert_eq!(
                contexts.root_bridges_for_test(),
                self.member_bridges.as_slice(),
                "shared member descriptors preserve private material exactly"
            );
        }
        self.language
            .operation
            .collect_jvm_blueprint_in_session(contexts, cancellation, session)
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
            scope: self.language.operation.ready.inventory.scope_identity(),
            stage_epoch: self.language.operation.ready.inventory.staged_read_epoch(),
        };
        let result = self
            .language
            .operation
            .jvm_context_registrations
            .borrow_mut()
            .register(key, registration, |cells| {
                ready.register_context_cells_in_session(registration, cells, cancellation, session)
            })?;
        if !matches!(result, ContextRegistrationOutcome::Cancelled) {
            self.language.remember_registration(
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
        let delta = self.language.context_delta(registration.context_token())?;
        let source = &self.sources[&frame.endpoint];
        if delta.is_some()
            && (source.mount != self.language.caller || source.qualified.is_some())
            && !super::demand_closure::closer_step(
                self.language.session,
                self.language.cancellation,
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

// Test-only JVM consumer of the shared contracts. Production dispatch stays above.
#[cfg(test)]
pub(super) mod shared_contract {
    use super::super::demand_closure::*;
    use super::*;
    use crate::analyzer::resolution::{
        DemandMemberSelectionOutcome, DemandRelationKey, DemandRootDiscovery, DemandRootProvider,
    };
    use std::cell::Cell;

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct Observation {
        pub owners: Vec<SemanticId>,
        pub completion: ResolutionCompletion,
    }
    pub(crate) struct Report {
        pub observation: Observation,
        pub published: bool,
        pub dependencies: usize,
    }

    struct Observed<'a, P> {
        inner: P,
        selections: &'a RefCell<Vec<Observation>>,
        dependencies: Option<(&'a EndpointSignature, &'a Cell<usize>)>,
    }
    impl<P: DemandRootProvider> DemandRootProvider for Observed<'_, P> {
        fn discover(&mut self, endpoint: &DemandRelationKey) -> Result<DemandRootDiscovery> {
            if let Some((root, count)) = self.dependencies
                && endpoint.endpoint != *root
            {
                count.set(count.get() + 1);
            }
            self.inner.discover(endpoint)
        }
        fn close(
            &mut self,
            endpoint: &DemandRelationKey,
            inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<ResolutionCompletion> {
            self.inner.close(endpoint, inputs)
        }
        fn close_with_member_completion(
            &mut self,
            endpoint: &DemandRelationKey,
            inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
            member_completion: &ResolutionCompletion,
        ) -> Result<ResolutionCompletion> {
            self.inner
                .close_with_member_completion(endpoint, inputs, member_completion)
        }
        fn member_selection(
            &mut self,
            endpoint: &DemandRelationKey,
            inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<DemandMemberSelectionOutcome> {
            self.inner.member_selection(endpoint, inputs)
        }
        fn close_selected_members(
            &mut self,
            endpoint: &DemandRelationKey,
            inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
            selection: &DemandMemberSelection,
        ) -> Result<ResolutionCompletion> {
            self.selections.borrow_mut().push(Observation {
                owners: selection.owners.clone(),
                completion: selection.completion.clone(),
            });
            self.inner
                .close_selected_members(endpoint, inputs, selection)
        }
        fn resolved_closure_discharges(
            &self,
            endpoint: &DemandRelationKey,
        ) -> Option<DemandClosureDischarges> {
            self.inner.resolved_closure_discharges(endpoint)
        }
    }

    struct Environment<'a, 'store, 'input> {
        operation: &'a SelectedResolutionOperation<'store, 'input>,
        base: &'a dyn BatchResolutionFragmentSource,
        initial: crate::analyzer::resolution::SelectedContextPathToken,
        session: &'a ResolutionSession,
        cancellation: &'a CancellationToken,
        caller: SelectedResolutionMountOrdinal,
    }
    impl<'a, 'store, 'input> Environment<'a, 'store, 'input> {
        fn language(
            &self,
            arena: &'a RefCell<ClosedRelations>,
        ) -> JvmDemandLanguage<'a, 'store, 'input> {
            JvmDemandLanguage {
                operation: self.operation,
                base: self.base,
                initial: self.initial,
                arena,
                session: self.session,
                cancellation: self.cancellation,
                caller: self.caller,
                whole_file_import_gaps: None,
                caller_scoped_gaps: None,
                caller_context_lookups: HashSet::default(),
                caller_registered_contexts: HashMap::default(),
                selected_import_gap: None,
                imported_prefix_targets: HashMap::default(),
                pending_registration: None,
            }
        }
    }

    // Force the same selected import through the actual private JVM callbacks;
    // ordinary dependencies continue to use its production provider.
    struct Reference<'a, 'store, 'input> {
        language: JvmDemandLanguage<'a, 'store, 'input>,
        root: EndpointSignature,
        source: Option<JvmSourceDemand>,
    }
    impl DemandLanguage for Reference<'_, '_, '_> {
        type RootQuestion = JvmSourceDemand;
        type ContextKey = SelectedResolutionMountOrdinal;
        type ContextData = JvmPreparedContext;
        fn discover_root(
            &mut self,
            endpoint: &EndpointSignature,
        ) -> Result<LanguageRootDiscovery<Self::RootQuestion>> {
            if *endpoint == self.root {
                Ok(LanguageRootDiscovery::Ready {
                    question: self.source.take().expect("one root discovery"),
                    completion: ResolutionCompletion::Complete,
                })
            } else {
                self.language.discover_root(endpoint)
            }
        }
        fn context_key(&self, source: &Self::RootQuestion) -> Option<Self::ContextKey> {
            self.language.context_key(source)
        }
        fn prepare_context(
            &mut self,
            key: &Self::ContextKey,
            source: &Self::RootQuestion,
        ) -> Result<LanguageContextPreparation<Self::ContextData>> {
            self.language.prepare_context(key, source)
        }
        fn prefix_inputs(
            &mut self,
            source: &mut Self::RootQuestion,
            context: Option<&Self::ContextData>,
        ) -> Result<LanguagePrefixInputs> {
            self.language.prefix_inputs(source, context)
        }
        fn member_selection(
            &mut self,
            source: &Self::RootQuestion,
            context: Option<&Self::ContextData>,
            inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<DemandMemberSelectionOutcome> {
            self.language.member_selection(source, context, inputs)
        }
        fn close_selected_members(
            &mut self,
            endpoint: &EndpointSignature,
            source: &Self::RootQuestion,
            context: Option<&Self::ContextData>,
            inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
            selection: &DemandMemberSelection,
        ) -> Result<LanguageClosure> {
            self.language
                .close_selected_members(endpoint, source, context, inputs, selection)
        }
        fn close_root(
            &mut self,
            endpoint: &EndpointSignature,
            source: &Self::RootQuestion,
            context: Option<&Self::ContextData>,
            inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<LanguageClosure> {
            self.language.close_root(endpoint, source, context, inputs)
        }
    }

    pub(crate) fn run(
        operation: &SelectedResolutionOperation<'_, '_>,
        caller_path: &str,
        lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
        cancellation: &CancellationToken,
    ) -> Report {
        let session = ResolutionSession::unbounded();
        let JvmImportContext::Ready { context, .. } = operation
            .jvm_import_context(Language::Scala, caller_path, cancellation)
            .unwrap()
        else {
            panic!("Scala context ready")
        };
        let SelectedResolutionContextValidationOutcome::Ready(context) = (*context)
            .validate_exact_mounts_in_session(
                operation.mount_table().mount_count(),
                &selected_mount_lookup(operation.mount_table()),
                cancellation,
                &session,
            )
            .unwrap()
        else {
            panic!("validated context")
        };
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
            .collect_jvm_blueprint_in_session(context, cancellation, &session)
            .unwrap()
        else {
            panic!("compiled context")
        };
        let lexical = operation.ready.lexical_source();
        let typed = operation.ready.typed_source();
        let caller = operation
            .mount_table()
            .mount_for_path("scala", caller_path)
            .unwrap()
            .unwrap()
            .ordinal();
        let environment = Environment {
            operation,
            base: &lexical,
            initial: blueprint.context_token(),
            session: &session,
            cancellation,
            caller,
        };
        let trial_arena = RefCell::new(ClosedRelations::default());
        let reference_arena = RefCell::new(ClosedRelations::default());
        let language = environment.language(&trial_arena);
        let (endpoint, source) = lowered
            .lexical()
            .paths()
            .iter()
            .filter_map(|(_, path)| {
                if path.end().node() != BindingNodeId::universal_root() {
                    return None;
                }
                let endpoint = path.end().clone();
                let source = language.source_demand(&endpoint).unwrap()?;
                let (half, _) = source.import_qualifiers.as_ref()?;
                let SelectedRootPathHalf::Import {
                    identity, demand, ..
                } = half
                else {
                    return None;
                };
                let recipes = operation
                    .jvm_lookup_recipes(identity.fragment(), [*demand], cancellation)
                    .unwrap()
                    .unwrap();
                (recipes[0].spelling() == "selected").then_some((endpoint, source))
            })
            .next()
            .expect("authored selected-member import");
        let target = *source
            .import_qualifiers
            .as_ref()
            .unwrap()
            .1
            .first()
            .unwrap();
        let dependencies = Cell::new(0);
        let observed_trial = RefCell::new(Vec::new());
        let observed_reference = RefCell::new(Vec::new());
        let base = blueprint.path_fragment_source(&lexical, &lexical, None);
        let closed =
            ClosedForwardSource::new(&base, &lexical, &trial_arena, &session, CALLER_ENVIRONMENT);
        let rules = JvmRules::new(language);
        let mut trial = Observed {
            inner: DemandProvider::new(SharedDemand {
                rules,
                arena: &trial_arena,
                paths: &lexical,
                ready: &operation.ready,
                base: &lexical,
                session: &session,
                cancellation,
                completion: &ResolutionCompletion::Complete,
            }),
            selections: &observed_trial,
            dependencies: Some((&endpoint, &dependencies)),
        };
        let trial_completion = blueprint
            .with_forward_operation_for_test(
                &closed,
                &lexical,
                &lexical,
                &typed,
                cancellation,
                &session,
                |fact| fact.prepare_relation_for_test(&endpoint, target, &mut trial),
            )
            .unwrap();
        if trial_arena
            .borrow()
            .registrations
            .contains_key(&DemandRelationKey::caller(endpoint.clone()))
        {
            let registrations = trial_arena.borrow().registrations.len();
            let repeated = blueprint
                .with_forward_operation_for_test(
                    &closed,
                    &lexical,
                    &lexical,
                    &typed,
                    cancellation,
                    &session,
                    |fact| fact.prepare_relation_for_test(&endpoint, target, &mut trial),
                )
                .unwrap();
            assert_eq!(
                repeated, trial_completion,
                "positive memo retains exact completion"
            );
            assert_eq!(
                trial_arena.borrow().registrations.len(),
                registrations,
                "positive memo does not register again"
            );
        }
        let published = trial_arena
            .borrow()
            .registrations
            .contains_key(&DemandRelationKey::caller(endpoint.clone()));
        let reference_closed = ClosedForwardSource::new(
            &base,
            &lexical,
            &reference_arena,
            &session,
            CALLER_ENVIRONMENT,
        );
        let mut reference = Observed {
            inner: DemandProvider::new(Reference {
                language: environment.language(&reference_arena),
                root: endpoint.clone(),
                source: Some(source),
            }),
            selections: &observed_reference,
            dependencies: None,
        };
        blueprint
            .with_forward_operation_for_test(
                &reference_closed,
                &lexical,
                &lexical,
                &typed,
                cancellation,
                &session,
                |fact| fact.prepare_relation_for_test(&endpoint, target, &mut reference),
            )
            .unwrap();
        let mut trials = observed_trial.borrow_mut();
        let references = observed_reference.borrow();
        assert_eq!(trials.len(), 1, "shared member phase executes once");
        assert_eq!(
            references.len(),
            1,
            "independent private JVM member phase executes once"
        );
        assert_eq!(
            trials[0].owners, references[0].owners,
            "declaring owners match private closer"
        );
        assert_eq!(
            trials[0].completion, references[0].completion,
            "aggregate completion matches private closer"
        );
        let reasons = |completion: &ResolutionCompletion| match completion {
            ResolutionCompletion::Complete => BTreeSet::new(),
            ResolutionCompletion::Incomplete(reasons) => {
                reasons.iter().copied().collect::<BTreeSet<_>>()
            }
        };
        assert!(
            reasons(&trials[0].completion).is_subset(&reasons(&trial_completion)),
            "shared result retains every ancestor reason"
        );
        Report {
            observation: trials.pop().unwrap(),
            published,
            dependencies: dependencies.get(),
        }
    }
    pub(crate) fn run_discovered(
        operation: &SelectedResolutionOperation<'_, '_>,
        language: Language,
        storage: &str,
        caller_path: &str,
        lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
        cancellation: &CancellationToken,
    ) {
        let session = ResolutionSession::unbounded();
        let JvmImportContext::Ready { context, .. } = operation
            .jvm_import_context(language, caller_path, cancellation)
            .unwrap()
        else {
            panic!("consumer context is ready")
        };
        let SelectedResolutionContextValidationOutcome::Ready(context) = (*context)
            .validate_exact_mounts_in_session(
                operation.mount_table().mount_count(),
                &selected_mount_lookup(operation.mount_table()),
                cancellation,
                &session,
            )
            .unwrap()
        else {
            panic!("consumer context validates")
        };
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
            .collect_jvm_blueprint_in_session(context, cancellation, &session)
            .unwrap()
        else {
            panic!("consumer blueprint compiles")
        };
        let lexical = operation.ready.lexical_source();
        let caller = operation
            .mount_table()
            .mount_for_path(storage, caller_path)
            .unwrap()
            .unwrap()
            .ordinal();
        let environment = Environment {
            operation,
            base: &lexical,
            initial: blueprint.context_token(),
            session: &session,
            cancellation,
            caller,
        };
        let trial_arena = RefCell::new(ClosedRelations::default());
        let private_arena = RefCell::new(ClosedRelations::default());
        let probe = environment.language(&trial_arena);
        let endpoints = lowered
            .lexical()
            .paths()
            .iter()
            .filter_map(|(_, path)| {
                let endpoint = path.end();
                if endpoint.node() != BindingNodeId::universal_root() {
                    return None;
                }
                let source = probe.source_demand(endpoint).unwrap()?;
                if source.qualified.is_some()
                    || source.import_qualifiers.is_some()
                    || !matches!(
                        source.caller_scoped_source,
                        Some(JvmCallerScopedSource::ImplicitRootReference { .. })
                    )
                {
                    return None;
                }
                let mount = operation
                    .mount_table()
                    .mount_by_ordinal(source.mount)
                    .unwrap();
                let recipes = operation
                    .jvm_lookup_recipes(mount.fragment(), [source.lookup], cancellation)
                    .unwrap()?;
                (recipes[0].spelling() == "List"
                    && recipes[0].namespace() == ResolutionNamespace::Type)
                    .then_some(DemandRelationKey::caller(endpoint.clone()))
            })
            .collect::<Vec<_>>();
        assert!(
            !endpoints.is_empty(),
            "local reference has a discovered root"
        );
        let endpoint = &endpoints[0];
        let mut trial = DemandProvider::new(SharedDemand {
            rules: JvmRules::new(environment.language(&trial_arena)),
            arena: &trial_arena,
            paths: &lexical,
            ready: &operation.ready,
            base: &lexical,
            session: &session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        });
        let mut private = DemandProvider::new(environment.language(&private_arena));
        let trial_plan = trial.discover(endpoint).unwrap();
        let private_plan = private.discover(endpoint).unwrap();
        let DemandRootDiscovery::Ready(trial_plan) = trial_plan else {
            panic!("shared discovered root is ready")
        };
        let DemandRootDiscovery::Ready(private_plan) = private_plan else {
            panic!("private discovered root is ready")
        };
        assert_eq!(trial_plan.completion, private_plan.completion);
        assert!(trial_plan.prefixes.is_empty() && private_plan.prefixes.is_empty());
        let trial_completion = trial.close(endpoint, &[]).unwrap();
        let private_completion = private.close(endpoint, &[]).unwrap();
        assert_eq!(
            trial_completion, private_completion,
            "staged closure completion"
        );
        let actual = trial
            .resolved_closure_discharges(endpoint)
            .expect("shared carries provider proof");
        let expected = private
            .resolved_closure_discharges(endpoint)
            .expect("private carries provider proof");
        assert_eq!(
            actual.discharged_provider_reasons,
            expected.discharged_provider_reasons
        );
        assert_eq!(
            actual.positive_binding_providers,
            expected.positive_binding_providers
        );
        eprintln!("J1 witness {language:?}: actual={actual:?} private={expected:?}");
        assert!(
            !actual.positive_binding_providers.is_empty(),
            "D proof must transport real conditional provider authority"
        );
        assert!(
            actual
                .positive_binding_providers
                .values()
                .any(|reasons| !reasons.is_empty()),
            "D proof is nonempty"
        );
        assert_eq!(
            trial_arena.borrow().paths,
            private_arena.borrow().paths,
            "exact delta cells"
        );
        assert_eq!(
            trial_arena.borrow().endpoint_completions,
            private_arena.borrow().endpoint_completions
        );
        let publications = trial_arena.borrow().endpoints.len();
        let completions = trial_arena.borrow().endpoint_completions.len();
        assert_eq!(publications, 1, "one publication");
        assert_eq!(completions, 1, "one explicit endpoint completion");
        assert_eq!(trial.close(endpoint, &[]).unwrap(), trial_completion);
        assert_eq!(trial_arena.borrow().endpoints.len(), publications);
        assert_eq!(trial_arena.borrow().endpoint_completions.len(), completions);
        eprintln!(
            "J1 {language:?}: discharged={:?} conditional={:?}; publications={publications} completions={completions}",
            actual.discharged_provider_reasons, actual.positive_binding_providers
        );
    }
}
