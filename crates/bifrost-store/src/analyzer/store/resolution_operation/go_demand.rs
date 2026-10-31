//! Go qualified-import bridges admitted only when a root endpoint asks for
//! its positioned lexical prefix.

use super::demand::{ClosedForwardSource, ClosedRelations, LanguageContextPreparation};
#[cfg(any(test, feature = "test-support"))]
use super::demand::{DemandProvider, LanguageRootDiscovery};
use super::go_named::{
    GoDemandContext, GoPreparedImportContext, GoPreparedImportContextOutcome,
    NAMED_IMPORT_TARGET_MOUNTS,
};
use super::*;
use crate::analyzer::resolution::DemandReferenceKey;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::DemandRelationKey;
use crate::analyzer::resolution::{
    DemandRootUnavailableReason, EndpointSignature, LoweringGapOrigin,
    SelectedResolutionMountContext,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

/// A provider owns registration independently of the name currently demanded.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct GoProviderRegistrationKey {
    context_id: i64,
    mount: SelectedResolutionMountOrdinal,
    source_role: String,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) type GoContextRegistrationMemo =
    super::context_preparation::ContextRegistrationMemo<GoProviderRegistrationKey>;

#[derive(Clone)]
struct GoSourceDemand {
    mount: SelectedResolutionMountOrdinal,
    root_semantic: SemanticId,
    source_role: Option<String>,
    qualified: Option<SelectedRootPathHalf>,
}

struct GoPreparedDemandContext {
    preparation: super::go_named::GoPreparedContextKey,
    blueprint: SelectedFactOperationBlueprint,
    demand: GoDemandContext,
    completion: ResolutionCompletion,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GoRemoteRootExpansion {
    FollowDemandedMounts,
    CallerContextOnly,
}

#[doc(hidden)]
pub struct GoForwardOperationContext<'a> {
    #[doc(hidden)]
    pub blueprint: &'a SelectedFactOperationBlueprint,
    #[doc(hidden)]
    pub demand: GoDemandContext,
    #[doc(hidden)]
    pub caller_path: &'a str,
    #[doc(hidden)]
    pub lexical: &'a dyn BatchResolutionFragmentSource,
    #[doc(hidden)]
    pub typed: &'a dyn SelectedTypedFactSource,
    #[doc(hidden)]
    pub cancellation: &'a CancellationToken,
    #[doc(hidden)]
    pub session: &'a ResolutionSession,
}

struct GoSourceRoleEntry {
    role: String,
    preparation_proof: Option<(super::go_named::GoPreparedContextKey, bool)>,
}

struct GoDemandState<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    base: &'a dyn BatchResolutionFragmentSource,
    arena: &'a RefCell<ClosedRelations>,
    session: &'a ResolutionSession,
    cancellation: &'a CancellationToken,
    demand: GoDemandContext,
    caller: SelectedResolutionMountOrdinal,
    remote_root_expansion: GoRemoteRootExpansion,
    package_mounts: HashMap<i64, Vec<SelectedResolutionMountOrdinal>>,
    package_inventories: HashSet<i64>,
    export_index:
        HashMap<SelectedResolutionMountOrdinal, HashMap<SemanticId, Vec<SelectedRootPathHalf>>>,
    source_roles: HashMap<SelectedResolutionMountOrdinal, GoSourceRoleEntry>,
    base_context_mounts: HashSet<SelectedResolutionMountOrdinal>,
    #[cfg(any(test, feature = "test-support"))]
    prepared_root_source_halves:
        HashMap<EndpointSignature, Option<super::source_demand::SelectedRootSource>>,
}

impl<'store, 'input> GoDemandState<'_, 'store, 'input> {
    fn prepare_file_context(
        &mut self,
        key: &(SelectedResolutionMountOrdinal, String),
        question: &GoSourceDemand,
    ) -> Result<LanguageContextPreparation<GoPreparedDemandContext>> {
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
        let preparation = self.operation.go_file_preparation_key(
            self.demand.context_id,
            key.0,
            record.persisted_relative_path(),
            &key.1,
        );
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
        let Some(blueprint) = self.prepare_context_blueprint(context, key.0, &key.1)? else {
            return Ok(LanguageContextPreparation::Cancelled(cancelled_completion()));
        };
        self.operation
            .go_prepared_contexts
            .update(&preparation, |prepared| {
                prepared.blueprint = Some(std::sync::Arc::new(blueprint.clone()));
            });
        // Go attaches inventory completion only to roots whose binding uses
        // that file's package/import context. The adapter decides that after
        // resolving a qualified prefix.
        Ok(LanguageContextPreparation::Ready {
            data: GoPreparedDemandContext {
                preparation,
                blueprint,
                demand,
                completion,
            },
            completion: ResolutionCompletion::Complete,
        })
    }

    fn source_role_for_mount(
        &mut self,
        mount: SelectedResolutionMountOrdinal,
    ) -> Result<Option<String>> {
        if mount == self.caller {
            return Ok(None);
        }
        if let Some(entry) = self.source_roles.get(&mount) {
            return Ok(Some(entry.role.clone()));
        }
        // An ignored row identifies a point caller's production package, but
        // does not authorize remote source admission or a root certificate.
        let role = self
            .operation
            .go_source_role_for_mount(self.demand.context_id, mount, self.cancellation)?
            .filter(|role| role != "ignored");
        if let Some(role) = &role {
            self.source_roles.insert(
                mount,
                GoSourceRoleEntry {
                    role: role.clone(),
                    preparation_proof: None,
                },
            );
        }
        Ok(role)
    }

    fn source_context_is_proven(
        &mut self,
        mount: SelectedResolutionMountOrdinal,
        role: &str,
    ) -> Result<Option<bool>> {
        let record = self
            .operation
            .ready
            .inventory
            .mount_record_by_ordinal(mount)?;
        let key = self.operation.go_file_preparation_key(
            self.demand.context_id,
            mount,
            record.persisted_relative_path(),
            role,
        );
        if let Some((authority, proven)) = &self
            .source_roles
            .get(&mount)
            .expect("preparation follows selected source-role discovery")
            .preparation_proof
            && authority == &key
        {
            return Ok(Some(*proven));
        }
        let Some(selection) = self
            .operation
            .go_context_selection(self.demand.context_id, role)?
        else {
            return Ok(Some(false));
        };
        let connection = self.operation.ready.inventory.connection();
        let Some(members) =
            super::super::resolution_typed::go_members::package_member_sources_in_context(
                connection,
                selection.identity.revision,
                mount,
                selection.identity.context_id,
                self.operation
                    .ready
                    .go_active_package
                    .get()
                    .map(|(_, package, role)| (package, role)),
                record.persisted_relative_path(),
                self.cancellation,
            )?
        else {
            return Ok(None);
        };
        // Only the package of the operation's own sources has a frontier in
        // its base context. A context prepared for an uncertain sibling there
        // would close that frontier as certain, so it needs the full placement
        // proof. A foreign package reached through an import has no base paths
        // to retain: refusing its context withholds every reference that
        // routes through it, such as a member promoted through a struct
        // declared in a build-constrained file. Its prepared context carries
        // its own inventory completion onto the import route instead.
        let shares_base_package = members.iter().flatten().any(|member| {
            let member = SelectedResolutionMountOrdinal::new(
                member
                    .ordinal()
                    .expect("a mounted package member has an ordinal"),
            );
            member == self.caller || self.base_context_mounts.contains(&member)
        });
        let proven = if members.is_empty() || shares_base_package {
            let Some(proven) =
                super::super::resolution_typed::go_members::package_placement_is_proven(
                    connection,
                    &selection.identity,
                    &members,
                    self.cancellation,
                )?
            else {
                return Ok(None);
            };
            proven
        } else {
            true
        };
        self.source_roles
            .get_mut(&mount)
            .expect("selected source-role entry remains live")
            .preparation_proof = Some((key, proven));
        Ok(Some(proven))
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

    fn package_source_demand(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<Option<GoSourceDemand>> {
        let lexical = self.operation.ready.lexical_source();
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

    fn prepare_context_blueprint(
        &self,
        context: SelectedResolutionContextSet,
        mount: SelectedResolutionMountOrdinal,
        source_role: &str,
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
            None,
            |blueprint| self.register_blueprint(blueprint, mount, source_role),
        )
    }

    fn register_blueprint(
        &self,
        blueprint: &SelectedFactOperationBlueprint,
        mount: SelectedResolutionMountOrdinal,
        source_role: &str,
    ) -> Result<ContextRegistrationOutcome> {
        let key = GoProviderRegistrationKey {
            context_id: self.demand.context_id,
            mount,
            source_role: source_role.to_owned(),
            scope: self.operation.ready.inventory.scope_identity(),
            stage_epoch: self.operation.ready.inventory.staged_read_epoch(),
        };
        let outcome = self
            .operation
            .go_context_registrations
            .borrow_mut()
            .register(key, blueprint, |cells| {
                let outcome = self.operation.ready.register_context_cells_in_session(
                    blueprint,
                    cells,
                    self.cancellation,
                    self.session,
                )?;
                Ok(outcome)
            })?;
        Ok(outcome)
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

/// Go's discovery, package and evidence rules for the shared closer.
struct GoRules<'a, 'request, 'store, 'input> {
    language: &'a mut GoDemandState<'request, 'store, 'input>,
    contexts: Vec<(SelectedResolutionMountOrdinal, String)>,
    preparation: Option<super::go_named::GoPreparedContextKey>,
    prepared: HashMap<super::demand_closure::ContextId, GoPreparedDemandContext>,
}

impl GoRules<'_, '_, '_, '_> {
    fn source(&self, frame: &super::demand_closure::RootFrame) -> Result<GoSourceDemand> {
        let qualified = frame.halves.first().cloned();
        let mount = if let Some(SelectedRootPathHalf::Reference { identity, .. }) = &qualified {
            self.language
                .operation
                .mount_table()
                .mount_for_fragment(identity.fragment())?
                .expect("a positioned Go source has a selected mount")
                .ordinal()
        } else {
            self.contexts[frame
                .context
                .expect("a context-only root has a certified source")
                .0]
                .0
        };
        Ok(GoSourceDemand {
            mount,
            root_semantic: frame
                .endpoint
                .symbols()
                .fixed()
                .first()
                .expect("Go source root symbol")
                .symbol(),
            source_role: frame.context.map(|key| self.contexts[key.0].1.clone()),
            qualified,
        })
    }

    fn prefix_answer<'a>(
        &self,
        frame: &'a super::demand_closure::RootFrame,
        half: super::demand_closure::HalfId,
        answers: &super::demand_closure::PrefixAnswers<'a>,
    ) -> &'a FactResolutionAnswer {
        if let Some(resolved) = frame
            .resolved_prefixes
            .iter()
            .find(|resolved| resolved.operand.source_halves.contains(&half))
        {
            return &resolved.answer;
        }
        let operand = frame
            .operands
            .iter()
            .find(|operand| operand.source_halves.contains(&half))
            .expect("every Go qualified half has a prefix operand");
        answers
            .entries
            .iter()
            .find(|entry| entry.key == operand.key)
            .expect("caller prefix operands form an exact answer bijection")
            .answer
    }

    /// Go's remote-environment prefix hook. A Go prefix can name a package
    /// in a remote source environment (a module cache or vendor tree,
    /// prepared as an overlay), and the nested evaluator resolves it inside
    /// that environment's prepared context. The shared scheduler evaluates
    /// prefixes only in the caller's environment. Moving remote environments
    /// into it needs a stable owner outside the request for dynamically
    /// prepared overlays, which the shared code does not have, so this stays
    /// a Go hook until a second language needs remote environments (#5658).
    /// The nested evaluator keeps its existing source envelope. No remote task
    /// is scheduled and no caller answer with substituted metadata is built.
    fn resolve_go_remote_environment_prefixes(
        &mut self,
        frame: &mut super::demand_closure::RootFrame,
    ) -> Result<super::demand_closure::Read<Vec<super::demand_closure::ResolvedPrefixOperand>>>
    {
        use super::demand_closure::{HalfId, PrefixOperand, Read, ResolvedPrefixOperand};
        if self.language.cancellation.is_cancelled() || !self.language.session.scope_step() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        let Some(context) = frame.context.and_then(|key| self.prepared.get(&key)) else {
            return Ok(Read::ready(Vec::new()));
        };
        if frame.halves.is_empty() {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: context.completion.clone(),
            });
        }
        let mut resolved = Vec::<ResolvedPrefixOperand>::new();
        let mut completion = ResolutionCompletion::Complete;
        for (index, half) in frame.halves.iter().enumerate() {
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
            let key = DemandReferenceKey::caller(*prefix);
            if let Some(existing) = resolved
                .iter_mut()
                .find(|resolved| resolved.operand.key == key)
            {
                let mut halves = existing.operand.source_halves.to_vec();
                halves.push(HalfId(index));
                existing.operand.source_halves = halves.into_boxed_slice();
                continue;
            }
            let Some(answer) = self
                .language
                .resolve_prefix_in_file_context(&context.blueprint, *prefix)?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            if answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
            {
                return Ok(Read::Cancelled(answer.completion().clone()));
            }
            // A remote file's context completion becomes visible precisely
            // when this original binding witnesses its import package.
            let mount = self.contexts[frame.context.unwrap().0].0;
            if answer.binding().targets().iter().any(|target| {
                context
                    .demand
                    .import_packages
                    .contains_key(&(mount, *target))
            }) {
                completion = completion.combine(&context.completion);
            }
            resolved.push(ResolvedPrefixOperand {
                operand: PrefixOperand {
                    key,
                    source_halves: Box::new([HalfId(index)]),
                },
                answer,
            });
        }
        Ok(Read::Ready {
            value: resolved,
            completion,
        })
    }

    fn certify(
        &mut self,
        endpoint: &EndpointSignature,
        source: GoSourceDemand,
        halves: Vec<SelectedRootPathHalf>,
    ) -> Result<super::demand_closure::Read<super::demand_closure::Admission>> {
        use super::demand_closure::{
            Admission, BaseEligibility, ContextId, Read, RootFrame, RootSource,
        };
        let language = &self.language;
        if source.mount == language.caller && source.qualified.is_none()
            || source.mount != language.caller
                && (source.qualified.is_none()
                    && language.base_context_mounts.contains(&source.mount)
                    || language.remote_root_expansion == GoRemoteRootExpansion::CallerContextOnly
                        && !language.base_context_mounts.contains(&source.mount))
        {
            return Ok(Read::ready(Admission::BaseOwned {
                completion: ResolutionCompletion::Complete,
                base: BaseEligibility::Retain,
            }));
        }
        if source.mount != language.caller && source.source_role.is_none() {
            return Ok(Read::ready(Admission::Unavailable {
                reason: DemandRootUnavailableReason::IncompletePreparation,
                completion: ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(source.root_semantic),
                ]),
            }));
        }
        if let Some(role) = &source.source_role {
            let Some(proven) = self.language.source_context_is_proven(source.mount, role)? else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            if !proven {
                // The selected source still owns its partial base paths. A new
                // context must not close its uncertain package frontier.
                return Ok(Read::ready(Admission::BaseOwned {
                    completion: ResolutionCompletion::Complete,
                    base: BaseEligibility::Retain,
                }));
            }
        }
        let context = source.source_role.map(|role| {
            let key = (source.mount, role);
            let index = self
                .contexts
                .iter()
                .position(|previous| previous == &key)
                .unwrap_or_else(|| {
                    self.contexts.push(key);
                    self.contexts.len() - 1
                });
            ContextId(index)
        });
        let mut frame = if let Some(half) = &source.qualified {
            let SelectedRootPathHalf::Reference {
                identity,
                token,
                demand,
                ..
            } = half
            else {
                unreachable!("Go qualified roots have reference halves")
            };
            RootFrame::positioned(
                endpoint,
                super::source_demand::SourceDemandKey {
                    fragment: identity.fragment(),
                    token: *token,
                    demand: *demand,
                },
                halves,
            )
        } else {
            RootFrame {
                query_obligations: crate::analyzer::resolution::QueryObligations::empty(),
                endpoint: endpoint.clone(),
                sources: Box::new([RootSource::Context(
                    context.expect("a remote context has a certified role"),
                )]),
                halves: Vec::new(),
                context: None,
                operands: Box::new([]),
                resolved_prefixes: Vec::new(),
                completion: ResolutionCompletion::Complete,
            }
        };
        frame.context = context;
        Ok(Read::ready(Admission::SourceOwned(frame)))
    }
}

struct GoPublicationCertificate<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    inventory: super::go_context::GoPackageInventoryState,
}
impl super::demand_closure::PublicationCertificate for GoPublicationCertificate<'_, '_, '_> {
    fn publish(self) {
        self.operation
            .record_go_package_inventory_state(&self.inventory);
    }
}

impl<'request, 'store, 'input> super::demand_closure::DemandRules
    for GoRules<'_, 'request, 'store, 'input>
{
    type Placement = ();
    type Target = ();
    type Member = ();
    type Provider = ();
    type MemberRow = ();
    type PlacementObservations =
        crate::analyzer::store::resolution_operation::demand_closure::EmptyPlacementObservations;
    type Rank = ();
    type Half<'a>
        = super::demand_closure::EmptyHalf
    where
        Self: 'a;
    type PreparationKey = super::go_named::GoPreparedContextKey;
    type Certificate = GoPublicationCertificate<'request, 'store, 'input>;

    fn prepared_publication(&self, key: &Self::PreparationKey) -> SelectedFactOperationBlueprint {
        self.language
            .operation
            .go_prepared_contexts
            .get(key)
            .expect("a promised ready Go preparation remains in its request memo")
            .blueprint
            .expect("Go preparation already validated its publication blueprint")
            .as_ref()
            .clone()
    }

    fn closure_policy(
        &self,
        frame: &super::demand_closure::RootFrame,
        facts: &super::demand_closure::ClosureFacts<'_>,
    ) -> Result<super::demand_closure::Read<super::demand_closure::ClosurePolicy>> {
        use super::demand_closure::{BaseEligibility, ClosurePolicy, Read};
        let mut discharges = None;
        for half in facts.halves {
            let answer = self.prefix_answer(frame, half.half, &facts.prefixes);
            let source = self.source(frame)?;
            let demand = self
                .prepared
                .get(
                    &frame
                        .context
                        .unwrap_or(super::demand_closure::ContextId(usize::MAX)),
                )
                .map(|prepared| &prepared.demand)
                .unwrap_or(&self.language.demand);
            let bindings: HashSet<_> = answer
                .binding()
                .targets()
                .iter()
                .filter(|target| {
                    demand
                        .import_packages
                        .contains_key(&(source.mount, **target))
                })
                .copied()
                .collect();
            if !bindings.is_empty()
                && answer.binding().completion() == &ResolutionCompletion::Complete
            {
                let SelectedRootPathHalf::Reference { identity, .. } = &frame.halves[half.half.0]
                else {
                    unreachable!("Go package prefix belongs to a reference")
                };
                let Some(retired) = self.language.go_import_prefix_discharges(
                    identity.fragment(),
                    answer.completion(),
                    &bindings,
                )?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                // Go has one positioned source. Exact provenance comes from the
                // original answer, including operation-local prefix placeholders.
                assert_eq!(facts.halves.len(), 1);
                discharges = Some(DemandClosureDischarges::exact(retired));
            }
        }
        let preserve_record = discharges.is_some();
        let mut policy = ClosurePolicy::new(
            ResolutionCompletion::Complete,
            BaseEligibility::Retain,
            discharges.unwrap_or_default(),
            Box::new([]),
        );
        if preserve_record {
            policy.preserve_discharge_record();
        }
        Ok(Read::ready(policy))
    }

    fn raw_prefix_completion(&self, answer: &FactResolutionAnswer) -> ResolutionCompletion {
        answer.binding().completion().clone()
    }

    fn derive_context(
        &mut self,
        key: super::demand_closure::ContextId,
        frame: &super::demand_closure::RootFrame,
    ) -> Result<super::demand_closure::Read<Option<SelectedResolutionContextSet>>> {
        use super::demand_closure::Read;
        let source = self.source(frame)?;
        let context_key = self.contexts[key.0].clone();
        match self.language.prepare_file_context(&context_key, &source)? {
            LanguageContextPreparation::Ready { data, completion } => {
                self.prepared.insert(key, data);
                Ok(Read::Ready {
                    value: None,
                    completion,
                })
            }
            LanguageContextPreparation::Unavailable(completion) => Ok(Read::Unavailable {
                reason: DemandRootUnavailableReason::IncompletePreparation,
                completion,
            }),
            LanguageContextPreparation::Cancelled(completion) => Ok(Read::Cancelled(completion)),
        }
    }

    fn resolve_prefix_operands(
        &mut self,
        frame: &mut super::demand_closure::RootFrame,
        _context: Option<&SelectedResolutionContextSet>,
    ) -> Result<super::demand_closure::Read<Vec<super::demand_closure::ResolvedPrefixOperand>>>
    {
        self.resolve_go_remote_environment_prefixes(frame)
    }

    fn publication_context(
        &self,
        frame: &super::demand_closure::RootFrame,
        ready: &ReadySelectedResolution<'_, '_>,
        inventory: &ResolutionCompletion,
    ) -> Result<SelectedResolutionContextSet> {
        let source = self.source(frame)?;
        let mount = self
            .language
            .operation
            .mount_table()
            .mount_by_ordinal(source.mount)?;
        let SelectedRootPathHalf::Reference { identity, .. } = &frame.halves[0] else {
            unreachable!("a Go bridge starts at its positioned reference")
        };
        assert_eq!(mount.fragment(), identity.fragment());
        SelectedResolutionContextSet::new(
            ready.context_identities.clone(),
            vec![SelectedResolutionMountContext::new(
                source.mount,
                mount.fragment(),
                Language::Go,
                Vec::new(),
                inventory.clone(),
            )?],
            self.language.operation.mount_table().mount_count(),
            &selected_mount_lookup(self.language.operation.mount_table()),
        )
    }

    fn register_publication(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        _ready: &ReadySelectedResolution<'_, '_>,
        registration: &SelectedFactOperationBlueprint,
        _session: &ResolutionSession,
        _cancellation: &CancellationToken,
    ) -> Result<ContextRegistrationOutcome> {
        let source = self.source(frame)?;
        let role = self.language.operation.go_source_role_for_mount(
            self.language.demand.context_id,
            source.mount,
            self.language.cancellation,
        )?;
        if self.language.cancellation.is_cancelled() {
            return Ok(ContextRegistrationOutcome::Cancelled);
        }
        self.language.register_blueprint(
            registration,
            source.mount,
            &role.expect("an admitted Go exporting source has a selected role"),
        )
    }

    fn publication(
        &self,
        key: Option<&Self::PreparationKey>,
        registration: SelectedFactOperationBlueprint,
    ) -> super::demand_closure::PublicationMaterial<Self::Certificate> {
        let Some(key) = key else {
            return super::demand_closure::PublicationMaterial {
                registration,
                certificate: None,
            };
        };
        let prepared = self
            .language
            .operation
            .go_prepared_contexts
            .get(key)
            .expect("a promised ready Go preparation remains in its request memo");
        super::demand_closure::PublicationMaterial {
            registration: prepared
                .blueprint
                .expect("Go preparation already validated its publication blueprint")
                .as_ref()
                .clone(),
            certificate: Some(GoPublicationCertificate {
                operation: self.language.operation,
                inventory: prepared.package_inventory,
            }),
        }
    }

    fn provider_preparation(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<super::demand_closure::ProviderPreparation<Self::PreparationKey>>> {
        use super::demand_closure::ProviderPreparation;
        let source = self.source(frame)?;
        let prepared = frame.context.and_then(|key| self.prepared.get(&key));
        if frame.halves.is_empty() {
            assert!(inputs.is_empty(), "a file context has no prefix");
            let preparation = self
                .preparation
                .clone()
                .or_else(|| prepared.map(|prepared| prepared.preparation.clone()));
            let Some(preparation) = preparation else {
                return Ok(Some(ProviderPreparation::Unavailable(
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(source.root_semantic),
                    ]),
                )));
            };
            let value = self
                .language
                .operation
                .go_prepared_contexts
                .get(&preparation)
                .expect("a promised ready Go preparation remains in its request memo");
            return Ok(Some(ProviderPreparation::Prepared {
                completion: value.context.inventory_completion().clone(),
                key: preparation,
                endpoint_completion: None,
            }));
        }
        if source.mount != self.language.caller && prepared.is_none() {
            return Ok(Some(ProviderPreparation::Unavailable(
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(source.root_semantic),
                ]),
            )));
        }
        Ok(Some(ProviderPreparation::Rows {
            mount: source.mount,
        }))
    }

    fn provider_rows(
        &mut self,
        frame: &super::demand_closure::RootFrame,
        half_id: super::demand_closure::HalfId,
        source_mount: SelectedResolutionMountOrdinal,
        answers: &super::demand_closure::PrefixAnswers<'_>,
    ) -> Result<super::demand_closure::Read<super::demand_closure::ProviderRows>> {
        use super::demand_closure::{ProviderRows, Read};
        let prepared = frame.context.and_then(|key| self.prepared.get(&key));
        let half = &frame.halves[half_id.0];
        let SelectedRootPathHalf::Reference {
            identity,
            source_reference,
            prefix_reference: Some(_),
            demand,
            route: segments,
            ..
        } = half
        else {
            unreachable!("a Go qualified demand is a positioned reference")
        };
        assert!(
            segments.is_empty(),
            "Go package qualifier has one prefix segment"
        );
        let answer = self.prefix_answer(frame, half_id, answers);
        assert_eq!(
            answer
                .site_metadata()
                .expect("positioned Go prefix metadata")
                .namespace(),
            ResolutionNamespace::TypeOrValue
        );
        let packages = prepared
            .map(|prepared| &prepared.demand.import_packages)
            .unwrap_or(&self.language.demand.import_packages);
        let package_targets: Vec<_> = answer
            .binding()
            .targets()
            .iter()
            .filter_map(|target| {
                packages
                    .get(&(source_mount, *target))
                    .map(|package| (*target, *package))
            })
            .collect();
        let binding = answer.binding().completion().clone();
        let context_completion = prepared
            .map(|prepared| prepared.completion.clone())
            .or_else(|| {
                self.language
                    .demand
                    .context_completions
                    .get(&source_mount)
                    .cloned()
            })
            .expect("Go qualified source has a prepared context completion");
        let Some(recipe) = super::demand_closure::export_recipe(
            &self.language.operation.ready,
            identity.fragment(),
            *demand,
            self.language.cancellation,
            self.language.session,
        )?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        // An incomplete import may still identify one modeled nominal owner.
        // Preserve its open completion; only the owner identity joins the same
        // native receiver walk used for a confirmed import.
        let mut endpoint_completion = None;
        let mut selected_owner = None;
        if frame.halves.len() == 1
            && recipe.namespace() == ResolutionNamespace::Type
            && matches!(&binding, ResolutionCompletion::Incomplete(reasons)
                if reasons.iter().all(|reason| matches!(reason,
                    ResolutionIncompleteReason::UnsupportedSemantic(id)
                        if self.language.operation.ready.context_identities.named_reason(*id)
                            .is_some_and(|(name, _)| name == super::GO_IMPORT_INCOMPLETE))))
            && answer.binding().targets().len() == 1
            // A source-backed import must keep its source owner, even when
            // its import inventory is incomplete. GoTool provenance is only
            // admitted by import authority for providers without source.
            && (package_targets.is_empty()
                || prepared
                    .map(|prepared| &prepared.demand.modeled_imports)
                    .unwrap_or(&self.language.demand.modeled_imports)
                    .get(&(source_mount, answer.binding().targets()[0]))
                    .is_some_and(|provider| matches!(&provider.provenance,
                        super::go_named::GoExternalPackageProvenance::GoTool { .. })))
        {
            let paths = answer
                .projected_frontiers()
                .iter()
                .flat_map(|state| state.unindexed_external())
                .filter(|frontier| frontier.member.is_none())
                .map(|frontier| &frontier.provider_path)
                .collect::<BTreeSet<_>>();
            if let Some(path) = paths.iter().next().filter(|_| paths.len() == 1)
                && let Some(authority) = self.language.operation.ready.model_authority()
                && let Some(models) = authority.active_models()
            {
                use crate::analyzer::semantic_model::TypeRef;
                use crate::analyzer::semantic_model::overlay::ModelTypeOwnerAnswer;
                let nominal = TypeRef::Named {
                    name: format!("{}.{}", path, recipe.spelling()),
                    arguments: Vec::new(),
                    nullable: false,
                };
                let selected = authority.model_type_owner(
                    "go",
                    &nominal,
                    &models.model_provider_selection(),
                    self.language.cancellation,
                );
                if self.language.cancellation.is_cancelled() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                if let ModelTypeOwnerAnswer::Unique { owner, declaration } =
                    selected.map_err(|error| {
                        StoreError::new(format!("Go incomplete-import model owner: {error:?}"))
                    })?
                {
                    selected_owner = Some((owner, declaration));
                }
            }
        }
        // Package provenance identifies its confirming authority, not its type
        // provider. Models select their pack; GoTool uses all active Go packs.
        // Only a unique Type terminal establishes nominal identity.
        if recipe.namespace() == ResolutionNamespace::Type
            && answer.binding().completion() == &ResolutionCompletion::Complete
            && let [binder] = answer.binding().targets()
            && let Some(provider) = prepared
                .map(|prepared| &prepared.demand.modeled_imports)
                .unwrap_or(&self.language.demand.modeled_imports)
                .get(&(source_mount, *binder))
            // GoTool package rows retain durable package IDs even without
            // indexed source. The import authority admits this tag only when
            // the selected provider has no source declarations.
            && (package_targets.is_empty() || matches!(&provider.provenance,
                super::go_named::GoExternalPackageProvenance::GoTool { .. }))
            && let Some(models) = self
                .language
                .operation
                .ready
                .model_authority()
                .and_then(|authority| authority.active_models())
            && let Some(authority) = self.language.operation.ready.model_authority()
        {
            use crate::analyzer::semantic_model::TypeRef;
            use crate::analyzer::semantic_model::overlay::{
                ModelProvider, ModelProviderSelection, ModelTypeOwnerAnswer,
            };

            let providers = models
                .shards()
                .iter()
                .filter(|shard| {
                    crate::analyzer::LanguageDialect::Standard(Language::Go)
                        .accepts_semantic_pack_language(&shard.manifest.language)
                })
                .filter(|shard| match &provider.provenance {
                    super::go_named::GoExternalPackageProvenance::SemanticModel {
                        pack_id,
                        pack_digest,
                        ..
                    } => {
                        shard.manifest.pack_id == *pack_id
                            && shard.manifest.semantic_sha256 == *pack_digest
                    }
                    super::go_named::GoExternalPackageProvenance::GoTool { .. } => true,
                })
                .map(|shard| ModelProvider {
                    pack_id: shard.manifest.pack_id.clone(),
                    pack_version: shard.manifest.version.clone(),
                    pack_digest: shard.manifest.semantic_sha256.clone(),
                })
                .collect::<BTreeSet<_>>();
            if !providers.is_empty()
                && (matches!(
                    &provider.provenance,
                    super::go_named::GoExternalPackageProvenance::GoTool { .. }
                ) || providers.len() == 1)
            {
                let selection = ModelProviderSelection::new(providers);
                let nominal = TypeRef::Named {
                    name: format!("{}.{}", provider.import_path, recipe.spelling()),
                    arguments: Vec::new(),
                    nullable: false,
                };
                let selected = authority.model_type_owner(
                    "go",
                    &nominal,
                    &selection,
                    self.language.cancellation,
                );
                if self.language.cancellation.is_cancelled() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                let selected = selected
                    .map_err(|error| StoreError::new(format!("Go model type owner: {error:?}")))?;
                if let ModelTypeOwnerAnswer::Unique { owner, declaration } = selected {
                    selected_owner = Some((owner, declaration));
                }
            }
        }
        if let Some((owner, declaration)) = selected_owner
            && let [binder] = answer.binding().targets()
        {
            use crate::analyzer::resolution::{
                ExternalOwnerIdentity, ExternalOwnerLanguage, TypedFactPageVisitor,
                TypedFactRequest,
            };
            use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;
            let lexical = self.language.operation.ready.lexical_source();
            let classifications = lexical
                .classify_endpoint_nodes(&[*source_reference], self.language.cancellation)?;
            if self.language.cancellation.is_cancelled() {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            let reference = classifications
                .iter()
                .find(|classification| classification.node() == *source_reference)
                .and_then(|classification| classification.reference())
                .ok_or_else(|| StoreError::corrupt(format!(
                    "qualified Go reference {source_reference:?} has no semantic identity: {classifications:?}"
                )))?;
            let mut slots = Vec::new();
            let read = self
                .language
                .operation
                .ready
                .typed_source()
                .visit_binding_projection_pages_for_references(
                    TypedFactRequest::new(&[reference]),
                    self.language.cancellation,
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        slots.extend(
                            page.iter()
                                .filter(|row| {
                                    matches!(
                                        row.row().kind(),
                                        BindingProjectionKind::TargetTypeIdentity
                                            | BindingProjectionKind::TargetNominalTypeIdentity
                                    )
                                })
                                .map(|row| row.row().output_slot()),
                        );
                        Ok(true)
                    }),
                )?;
            if read.is_cancelled() || self.language.cancellation.is_cancelled() {
                return Ok(Read::Cancelled(read.evidence().clone()));
            }
            if read.is_exhausted()
                && read.evidence() == &ResolutionCompletion::Complete
                && !slots.is_empty()
            {
                let identities = &self.language.operation.ready.context_identities;
                let external = identities.external_owner_semantic_for_language(
                    ExternalOwnerLanguage::Go,
                    &ExternalOwnerIdentity {
                        provider_id: Arc::from(owner.provider.pack_digest),
                        owner_fqn: Arc::from(declaration.qualified_name),
                    },
                    &self.language.operation.ready.shared_names(),
                );
                // Retaining the base must retain this import's keyed gap as
                // well as its stable nominal identity. Complete imports do
                // not add an endpoint receipt.
                if binding != ResolutionCompletion::Complete {
                    endpoint_completion = Some(binding.clone());
                }
                for slot in slots {
                    identities.record_jvm_external_provider_type_identity(
                        ExternalOwnerLanguage::Go,
                        reference,
                        slot,
                        external,
                        *binder,
                    );
                }
            }
        }
        let witness = !package_targets.is_empty();
        let mut exports = Vec::new();
        for (_, package) in package_targets {
            if self.language.cancellation.is_cancelled() || !self.language.session.scope_step() {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            let Some(mounts) = self.language.package_provider_mounts(package)? else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            for mount in mounts {
                if self.language.cancellation.is_cancelled() || !self.language.session.scope_step()
                {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                let Some(rows) = self.language.export_halves(mount, *demand)? else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                if !rows.is_empty() && self.language.source_role_for_mount(mount)?.is_none() {
                    if self.language.cancellation.is_cancelled() {
                        return Ok(Read::Cancelled(cancelled_completion()));
                    }
                    return Ok(Read::Unavailable {
                        reason: DemandRootUnavailableReason::MissingSourceProvenance,
                        completion: ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(*demand),
                        ]),
                    });
                }
                if !rows.is_empty() && !self.language.package_inventories.contains(&package) {
                    let record = self
                        .language
                        .operation
                        .ready
                        .inventory
                        .mount_record_by_ordinal(mount)?;
                    let Some(selected) = self
                        .language
                        .operation
                        .go_package_inventory_for_selected_package(
                            self.language.demand.context_id,
                            package,
                            &record,
                            self.language.cancellation,
                        )?
                    else {
                        return Ok(Read::Cancelled(cancelled_completion()));
                    };
                    self.language
                        .operation
                        .record_go_package_inventory_state(&selected.inventory);
                    assert!(self.language.package_inventories.insert(package));
                }
                exports.extend(rows);
            }
        }
        let completion = if exports.is_empty() {
            binding.clone()
        } else {
            binding.combine(&context_completion)
        };
        Ok(Read::ready(ProviderRows {
            endpoint_completion,
            language: Language::Go,
            exports,
            recipe,
            binding,
            context_completion,
            witness,
            completion,
        }))
    }

    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        retained_completion: Option<&ResolutionCompletion>,
    ) -> Result<super::demand_closure::Read<super::demand_closure::EndpointAdmission>> {
        use super::demand_closure::{EndpointAdmission, Read};
        let language = &self.language;
        if let Some(completion) = retained_completion {
            return Ok(Read::ready(EndpointAdmission::Ready(completion.clone())));
        }
        let local = endpoint.node() != BindingNodeId::universal_root()
            && endpoint.node().ordinal().is_none_or(|ordinal| {
                let mount = SelectedResolutionMountOrdinal::new(ordinal);
                mount == language.caller
                    || language.base_context_mounts.contains(&mount)
                    || language.remote_root_expansion == GoRemoteRootExpansion::CallerContextOnly
            });
        if local {
            return Ok(Read::ready(EndpointAdmission::Ready(
                ResolutionCompletion::Complete,
            )));
        }
        if endpoint.node() == BindingNodeId::universal_root()
            && endpoint.symbols().fixed().is_empty()
        {
            return Ok(Read::ready(EndpointAdmission::Context(
                super::demand_closure::Admission::BaseOwned {
                    completion: ResolutionCompletion::Complete,
                    base: super::demand_closure::BaseEligibility::Retain,
                },
            )));
        }
        Ok(Read::ready(EndpointAdmission::Discover))
    }

    fn discovery_scope(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<super::demand_closure::SourceScope> {
        use super::demand_closure::SourceScope;
        let Some(mut mounts) = self
            .language
            .root_source_mount_scope(std::slice::from_ref(endpoint))?
        else {
            return Ok(SourceScope::DemandedMounts);
        };
        // External tests are separate selected units in the same package
        // directory. A reverse bound includes both roles without conflating
        // their context identities or inferring a package from its spelling.
        let connection = self.language.operation.ready.inventory.connection();
        let mut statement = connection.prepare_cached(&GO_INTERVAL_DISCOVERY_SCOPE_0_SQL)?;
        // Add role peers only for the admitted base contexts.
        let encoded = serde_json::json!(
            self.language
                .base_context_mounts
                .iter()
                .chain(std::iter::once(&self.language.caller))
                .map(|mount| mount.get())
                .collect::<Vec<_>>()
        )
        .to_string();
        let mut rows =
            statement.query(rusqlite::params![self.language.demand.context_id, encoded])?;
        while let Some(row) = rows.next()? {
            if self.language.cancellation.is_cancelled() || !self.language.session.scope_step() {
                return Ok(SourceScope::Cancelled(cancelled_completion()));
            }
            mounts.push(SelectedResolutionMountOrdinal::new(row.get(0)?));
        }
        mounts.sort_unstable();
        mounts.dedup();
        Ok(SourceScope::Mounts(mounts.into_boxed_slice()))
    }

    fn describe_source(
        &mut self,
        endpoint: &EndpointSignature,
        _source: Option<super::source_demand::SourceDemandKey>,
        halves: Vec<SelectedRootPathHalf>,
        _completion: ResolutionCompletion,
    ) -> Result<super::demand_closure::Read<super::demand_closure::Admission>> {
        use super::demand_closure::{Admission, BaseEligibility, Read};
        if endpoint.node() != BindingNodeId::universal_root() {
            // A mounted endpoint proves the file, but selected import and role
            // rows must still certify its context. This read does not evaluate.
            let mount = SelectedResolutionMountOrdinal::new(
                endpoint
                    .node()
                    .ordinal()
                    .expect("unmounted endpoints were admitted without discovery"),
            );
            let language = &mut self.language;
            let record = language.operation.mount_table().mount_by_ordinal(mount)?;
            if record.semantic_language() == Language::Go {
                let local_key = endpoint.node().local_key().expect("mounted file scope key");
                let imports: bool = language.operation.ready.inventory.connection().query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM temp.selected_resolution_mounts mounted
                       JOIN main.resolution_go_package_imports imports ON imports.blob_id=mounted.blob_id
                       WHERE mounted.mount_ordinal=?1 AND imports.file_scope_key=?2 AND imports.kind='named'
                       UNION ALL
                       SELECT 1 FROM temp.selected_resolution_stage_go_package_imports
                       WHERE host_ordinal=?1 AND file_scope_key=?3 AND kind='named')",
                    rusqlite::params![mount.get(), local_key, crate::analyzer::store::resolution_stage::codec::encode_node(endpoint.node())], |row| row.get(0),
                )?;
                if let Some(symbol) = endpoint.symbols().fixed().first().filter(|_| imports) {
                    let source_role = language.source_role_for_mount(mount)?;
                    return self.certify(
                        endpoint,
                        GoSourceDemand {
                            mount,
                            root_semantic: symbol.symbol(),
                            source_role,
                            qualified: None,
                        },
                        Vec::new(),
                    );
                }
            }
        } else {
            for half in &halves {
                if let SelectedRootPathHalf::Reference {
                    identity,
                    prefix_reference,
                    ..
                } = half
                    && let Some(mount) = self
                        .language
                        .operation
                        .mount_table()
                        .mount_for_fragment(identity.fragment())?
                        .filter(|mount| mount.semantic_language() == Language::Go)
                {
                    let source_role = self.language.source_role_for_mount(mount.ordinal())?;
                    let source = GoSourceDemand {
                        mount: mount.ordinal(),
                        root_semantic: endpoint
                            .symbols()
                            .fixed()
                            .first()
                            .expect("Go root symbol")
                            .symbol(),
                        source_role,
                        qualified: prefix_reference.is_some().then(|| half.clone()),
                    };
                    return self.certify(endpoint, source, halves);
                }
            }
            if let Some(source) = self.language.package_source_demand(endpoint)? {
                return self.certify(endpoint, source, Vec::new());
            }
        }
        Ok(Read::ready(Admission::BaseOwned {
            completion: ResolutionCompletion::Complete,
            base: BaseEligibility::Retain,
        }))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    #[doc(hidden)]
    pub fn stage_go_reference_batches(
        &self,
        context: GoForwardOperationContext<'_>,
        maximum_batch_size: usize,
        stager: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary> {
        self.with_go_forward_operation(context, None, |operation| {
            operation.stage_all_reference_batches(maximum_batch_size, stager)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn assert_go_settled_readmission_for_test(
        &self,
        demand: GoDemandContext,
        caller_path: &str,
    ) -> Result<()> {
        use super::demand::{DemandLanguage, LanguageClosure};
        use super::demand_closure::{SharedDemand, discover_root};
        use crate::analyzer::resolution::{ResolutionIncompleteReason, StackPattern};
        let cancellation = CancellationToken::new();
        let session = ResolutionSession::unbounded();
        let arena = RefCell::new(ClosedRelations::default());
        let paths = self.ready.lexical_source();
        let caller = self
            .mount_table()
            .mount_for_path("go", caller_path)?
            .unwrap()
            .ordinal();
        let reason = self.ready.context_identities.named_semantic(
            CanonicalHasher::new(b"7868-go-settled-readmission").finish(),
            "7868-go-settled-readmission",
            "unavailable Go root",
        );
        let completion =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )]);
        let endpoint = EndpointSignature::new(
            BindingNodeId::universal_root(),
            StackPattern::closed([]),
            StackPattern::closed([]),
        );
        let mut language = GoDemandState {
            operation: self,
            base: &paths,
            arena: &arena,
            session: &session,
            cancellation: &cancellation,
            demand,
            caller,
            remote_root_expansion: GoRemoteRootExpansion::CallerContextOnly,
            package_mounts: HashMap::default(),
            package_inventories: HashSet::default(),
            export_index: HashMap::default(),
            source_roles: HashMap::default(),
            base_context_mounts: HashSet::default(),
            prepared_root_source_halves: HashMap::default(),
        };
        let mut shared = SharedDemand {
            source_closures: HashMap::default(),
            rules: GoRules {
                language: &mut language,
                contexts: Vec::new(),
                preparation: None,
                prepared: HashMap::default(),
            },
            arena: &arena,
            paths: &paths,
            ready: &self.ready,
            projection_memo: None,
            base: &paths,
            session: &session,
            cancellation: &cancellation,
            completion: &ResolutionCompletion::Complete,
        };
        shared.finalize_closure(&endpoint, LanguageClosure::settled(completion.clone()))?;
        assert_eq!(
            arena
                .borrow()
                .registered_endpoint(&endpoint)
                .unwrap()
                .completion,
            completion
        );
        let LanguageRootDiscovery::AlreadyReady {
            completion: admitted,
        } = discover_root(&mut shared, &endpoint)?
        else {
            panic!("settled endpoint is readable")
        };
        assert_eq!(
            admitted, completion,
            "Go readmission retains settled reasons"
        );
        Ok(())
    }

    #[doc(hidden)]
    pub fn with_go_forward_operation<T>(
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
        let source = ClosedForwardSource::new(
            &base,
            &paths,
            &arena,
            context.session,
            crate::analyzer::resolution::CALLER_ENVIRONMENT,
        )
        .with_package_inventory_rows(
            &self.ready.go_package_inventory_complete,
            &self.ready.go_package_inventory_fragments,
        );
        let caller_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(caller.ordinal())?;
        let caller_version = super::go_context::go_placement_file_version(
            self.ready.inventory.connection(),
            &caller_record,
        )?
        .expect("a prepared Go caller has a selected placement");
        let caller_role = self.go_source_role_for_mount(
            context.demand.context_id,
            caller.ordinal(),
            context.cancellation,
        )?;
        let caller_package = if let Some(role) = caller_role {
            let selected_role = match role.as_str() {
                "go" => Some("go"),
                "test" => Some("test"),
                "xtest" => Some("xtest"),
                "ignored" => None,
                _ => unreachable!("a prepared caller has a selected Go source role: {role}"),
            };
            Some((
                self.go_selected_package_id(context.demand.context_id, caller_version, &role)?
                    .expect("a prepared Go caller has one selected package variant"),
                selected_role,
            ))
        } else {
            assert!(
                context.cancellation.is_cancelled(),
                "a prepared Go caller has a selected source role"
            );
            None
        };
        struct ActivePackageGuard<'a> {
            slot: &'a std::cell::Cell<Option<(i64, i64, Option<&'static str>)>>,
            previous: Option<(i64, i64, Option<&'static str>)>,
        }
        impl Drop for ActivePackageGuard<'_> {
            fn drop(&mut self) {
                self.slot.set(self.previous);
            }
        }
        let _active_package = ActivePackageGuard {
            slot: &self.ready.go_active_package,
            previous: self.ready.go_active_package.replace(
                caller_package.map(|(package, role)| (context.demand.context_id, package, role)),
            ),
        };
        let base_context_mounts = context.demand.context_completions.keys().copied().collect();
        let mut language = GoDemandState {
            operation: self,
            base: context.lexical,
            arena: &arena,
            session: context.session,
            cancellation: context.cancellation,
            demand: context.demand,
            caller: caller.ordinal(),
            remote_root_expansion,
            package_mounts: HashMap::default(),
            package_inventories: HashSet::default(),
            export_index: HashMap::default(),
            source_roles: HashMap::default(),
            base_context_mounts,
            #[cfg(any(test, feature = "test-support"))]
            prepared_root_source_halves: HashMap::default(),
        };
        self.with_shared_forward_operation(
            GoRules {
                language: &mut language,
                contexts: Vec::new(),
                preparation: None,
                prepared: HashMap::default(),
            },
            &arena,
            &paths,
            &source,
            context.blueprint,
            context.lexical,
            context.typed,
            None,
            context.cancellation,
            context.session,
            artifacts,
            run,
        )
    }
}

pub(crate) static GO_INTERVAL_DISCOVERY_SCOPE_0_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"WITH directories AS (
               SELECT DISTINCT package.provider_directory
               FROM temp.selected_resolution_mounts mounted
               JOIN ({}) source USING(file_version_id)
               JOIN main.go_package_instances package
                 ON package.context_id=source.context_id AND package.package_id=source.package_id
               WHERE source.context_id=?1 AND mounted.mount_ordinal IN (SELECT value FROM json_each(?2))
             )
             SELECT DISTINCT mounted.mount_ordinal
             FROM directories
             JOIN main.go_package_instances package USING(provider_directory)
             JOIN temp.selected_go_context_source_files source
               ON source.context_id=package.context_id AND source.package_id=package.package_id
             JOIN temp.selected_resolution_mounts mounted USING(file_version_id)
             JOIN temp.selected_resolution_scope_mounts selected USING(mount_ordinal)
             WHERE package.context_id=?1 AND source.source_role IN ('go','xtest')"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });
