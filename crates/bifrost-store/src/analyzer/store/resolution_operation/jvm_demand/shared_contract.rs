use super::super::demand::{DemandLanguage, LanguageClosure, LanguagePrefixInputs};
use super::super::demand_closure::*;
use super::*;
use crate::analyzer::resolution::{
    DemandMemberSelectionOutcome, DemandRelationKey, DemandRootDiscovery, DemandRootProvider,
};
use std::cell::Cell;

thread_local! {
    static GOLDEN: RefCell<Option<(std::path::PathBuf, String, Vec<String>)>> = const { RefCell::new(None) };
}

pub fn start_golden(directory: std::path::PathBuf) {
    GOLDEN.with_borrow_mut(|slot| {
        assert!(slot.is_none());
        *slot = Some((directory, String::new(), Vec::new()));
    });
}

pub fn finish_golden() -> String {
    let (_, _, mut rows) = GOLDEN.with_borrow_mut(|slot| slot.take().unwrap());
    assert!(
        !rows.is_empty(),
        "a JVM golden family must exercise real closure"
    );
    rows.sort();
    rows.join("\n")
}

pub fn golden_scenario(name: &str, run: impl FnOnce()) {
    GOLDEN.with_borrow_mut(|slot| {
        if let Some((_, scenario, _)) = slot {
            *scenario = name.to_owned();
        }
    });
    run();
}

pub fn golden_source(path: &str, source: &str) -> String {
    GOLDEN.with_borrow(|slot| {
        let Some((directory, _, _)) = slot else {
            return source.to_owned();
        };
        // Content-address each source so looped fixtures keep both variants.
        let digest = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
            .unwrap()
            .to_string();
        let file = directory.join("sources").join(&digest[..16]).join(path);
        if std::env::var_os("BIFROST_BLESS").is_some_and(|v| v == "1") {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, source).unwrap();
        }
        std::fs::read_to_string(&file).unwrap_or_else(|error| panic!("{}: {error}", file.display()))
    })
}

fn golden_value(text: String, operation: &SelectedResolutionOperation<'_, '_>) -> String {
    use crate::analyzer::resolution::{SharedNameId, SharedNameInterner};
    let names = operation.ready.shared_names();
    let pattern = regex::Regex::new(r"SemanticId\(([0-9]+)\)").unwrap();
    pattern
        .replace_all(&text, |captures: &regex::Captures<'_>| {
            let raw: u64 = captures[1].parse().unwrap();
            let base = SemanticId::shared_name(SharedNameId::interned(0)).get();
            let Some(ordinal) = raw
                .checked_sub(base)
                .and_then(|value| u32::try_from(value).ok())
            else {
                return captures[0].to_owned();
            };
            let name = if ordinal < SharedNameId::PER_REQUEST_BASE {
                SharedNameId::interned(i64::from(ordinal))
            } else {
                SharedNameId::per_request(ordinal - SharedNameId::PER_REQUEST_BASE)
            };
            assert_eq!(SemanticId::shared_name(name).get(), raw);
            let digest = names.digest_for_id(name).unwrap_or_else(|| {
                assert!(
                    name.is_interned(),
                    "a request-local shared name has a recorded digest"
                );
                operation
                    .ready
                    .inventory
                    .connection()
                    .query_row(
                        "SELECT identity_digest FROM main.resolution_identities WHERE id=?1",
                        [i64::from(name.get())],
                        |row| row.get::<_, [u8; 32]>(0),
                    )
                    .expect("an observed persisted lookup identity has a digest")
            });
            let digest = digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("SemanticId(shared:{digest})")
        })
        .into_owned()
}

fn golden_values(
    values: impl IntoIterator<Item = impl std::fmt::Debug>,
    operation: &SelectedResolutionOperation<'_, '_>,
) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(|value| golden_value(format!("{value:?}"), operation))
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn golden_observation(
    kind: &str,
    value: impl std::fmt::Debug,
    arena: &RefCell<ClosedRelations>,
    operation: &SelectedResolutionOperation<'_, '_>,
) {
    GOLDEN.with_borrow_mut(|slot| {
        if let Some((_, scenario, rows)) = slot {
            let arena = arena.borrow();
            let value = golden_value(format!("{value:?}"), operation);
            rows.push(format!("=== {scenario} / {kind} ===\n{value}\npaths={:?}\nendpoint_completions={:?}\nexcluded_base={:?}\nbase_ready={:?}\n",
                golden_values(arena.paths.iter().map(|(identity, path)| (identity.fragment(), path)), operation),
                golden_values(&arena.endpoint_completions, operation),
                golden_values(&arena.excluded_base, operation),
                golden_values(&arena.base_ready, operation)));
        }
    });
}

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct Observation {
    pub owners: Vec<SemanticId>,
    pub completion: ResolutionCompletion,
}
#[doc(hidden)]
pub struct Report {
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
    fn cancel_close(&mut self, endpoint: &DemandRelationKey) {
        self.inner.cancel_close(endpoint);
    }
    fn poll_close(
        &mut self,
        endpoint: &DemandRelationKey,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        initial_members: Option<&DemandMemberSelection>,
        member_completion: &ResolutionCompletion,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<crate::analyzer::resolution::CloseProgress<ResolutionCompletion>> {
        if let Some(selection) = initial_members {
            self.selections.borrow_mut().push(Observation {
                owners: selection.owners.clone(),
                completion: selection.completion.clone(),
            });
        }
        if let crate::analyzer::resolution::CloseResume::Members { selection, .. } = &resume {
            self.selections.borrow_mut().push(Observation {
                owners: selection.owners.clone(),
                completion: selection.completion.clone(),
            });
        }
        self.inner.poll_close(
            endpoint,
            inputs,
            initial_members,
            member_completion,
            provenance,
            resume,
        )
    }
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
    fn discharged_provider_reasons(
        &self,
        endpoint: &DemandRelationKey,
    ) -> Option<&BTreeSet<SemanticId>> {
        self.inner.discharged_provider_reasons(endpoint)
    }
    fn retain_member_provider_reasons(
        &mut self,
        endpoint: &DemandRelationKey,
        reasons: &BTreeSet<SemanticId>,
    ) {
        self.inner.retain_member_provider_reasons(endpoint, reasons);
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
    fn language(&self, arena: &'a RefCell<ClosedRelations>) -> JvmDemandState<'a, 'store, 'input> {
        JvmDemandState {
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
            import_bindings: RefCell::default(),
            selected_import_gap: None,
            pending_registration: None,
        }
    }
}

fn context(
    operation: &SelectedResolutionOperation<'_, '_>,
    language: Language,
    storage: &str,
    caller_path: &str,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> (
    SelectedFactOperationBlueprint,
    SelectedResolutionMountOrdinal,
) {
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
            session,
        )
        .unwrap()
    else {
        panic!("consumer context validates")
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
        .ready
        .collect_blueprint_in_session(context, cancellation, session)
        .unwrap()
    else {
        panic!("consumer blueprint compiles")
    };
    let caller = operation
        .mount_table()
        .mount_for_path(storage, caller_path)
        .unwrap()
        .unwrap()
        .ordinal();
    (blueprint, caller)
}

// Exercise real producer endpoints through shared publication against the
// saved reference, including another caller's provider-file context.
#[doc(hidden)]
pub fn run_provider_only(
    operation: &SelectedResolutionOperation<'_, '_>,
    language: Language,
    storage: &str,
    caller_path: &str,
    lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
) {
    let session = ResolutionSession::unbounded();
    let (blueprint, caller) = context(
        operation,
        language,
        storage,
        caller_path,
        cancellation,
        &session,
    );
    let lexical = operation.ready.lexical_source();
    let environment = Environment {
        operation,
        base: &lexical,
        initial: blueprint.context_token(),
        session: &session,
        cancellation,
        caller,
    };
    let probe_arena = RefCell::new(ClosedRelations::default());
    let probe = environment.language(&probe_arena);
    let mut seen = HashSet::default();
    for (_, path) in lowered.lexical().paths() {
        let endpoint = path.end();
        if endpoint.node() != BindingNodeId::universal_root() || !seen.insert(endpoint.clone()) {
            continue;
        }
        let Some(source) = probe.source_demand(endpoint).unwrap() else {
            continue;
        };
        if source.qualified.is_some() || source.import_qualifiers.is_some() {
            continue;
        }
        let candidate_arena = RefCell::new(ClosedRelations::default());

        let mut candidate = DemandProvider::new(SharedDemand {
            source_closures: HashMap::default(),
            rules: JvmRules::new(environment.language(&candidate_arena)),
            arena: &candidate_arena,
            paths: &lexical,
            ready: &operation.ready,
            projection_memo: Some(&operation.jvm_context_blueprints),
            base: &lexical,
            session: &session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        });

        let key = DemandRelationKey::caller(endpoint.clone());
        let DemandRootDiscovery::Ready(actual_plan) = candidate.discover(&key).unwrap() else {
            panic!("shared provider-only root is ready");
        };

        assert!(actual_plan.prefixes.is_empty());

        candidate.close(&key, &[]).unwrap();
        golden_observation(
            "provider",
            (&key, candidate.resolved_closure_discharges(&key)),
            &candidate_arena,
            operation,
        );
        let actual = candidate_arena.borrow();

        eprintln!(
            "J3_PROVIDER_CERT route={} role={} endpoints={}",
            source.route_kind(),
            if source.mount == caller {
                "caller"
            } else {
                "provider-file"
            },
            actual.endpoints.len()
        );
    }
    assert!(
        !seen.is_empty(),
        "the producer supplies real root endpoints"
    );
}

pub struct SourceSweepObservation {
    pub answer: Box<crate::analyzer::resolution::FactResolutionAnswer>,
    pub foreign_access_reasons: BTreeSet<SemanticId>,
}

// Resolve real producer references and preserve the full shared answer.
pub fn run_source_sweep(
    operation: &SelectedResolutionOperation<'_, '_>,
    language: Language,
    caller_path: &str,
    lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
    source_facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    name: &str,
) -> Vec<SourceSweepObservation> {
    let session = ResolutionSession::unbounded();
    // Production point contexts are prepared for the requested name.
    // A whole-file context can conceal a missing prefix preparation.
    let JvmImportContext::Ready { context, .. } = operation
        .jvm_import_context_for_name(language, caller_path, name, cancellation)
        .unwrap()
    else {
        panic!("point context is ready")
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
        panic!("point context validates")
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
        .ready
        .collect_blueprint_in_session(context, cancellation, &session)
        .unwrap()
    else {
        panic!("point blueprint compiles")
    };
    let caller = operation
        .mount_table()
        .mount_for_path(language.config_label(), caller_path)
        .unwrap()
        .unwrap()
        .ordinal();
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let environment = Environment {
        operation,
        base: &lexical,
        initial: blueprint.context_token(),
        session: &session,
        cancellation,
        caller,
    };
    let references = source_facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role
                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole::Reference
                && source_facts.names[identifier.name.index()].spelling == name
        })
        .map(|identifier| {
            crate::analyzer::resolution::mounted_site_semantic(
                lowered.lexical().fragment(), identifier.site,
            )
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !references.is_empty(),
        "producer supplies source-route references"
    );
    let mut observations = Vec::new();
    for reference in references {
        let actual_arena = RefCell::new(ClosedRelations::default());

        let base = blueprint.path_fragment_source(&lexical, &lexical, None);
        let actual_source =
            ClosedForwardSource::new(&base, &lexical, &actual_arena, &session, CALLER_ENVIRONMENT);

        let mut actual = DemandProvider::new(SharedDemand {
            source_closures: HashMap::default(),
            rules: JvmRules::new(environment.language(&actual_arena)),
            arena: &actual_arena,
            paths: &lexical,
            ready: &operation.ready,
            projection_memo: Some(&operation.jvm_context_blueprints),
            base: &lexical,
            session: &session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        });

        let observed = blueprint
            .with_forward_operation_for_test(
                &actual_source,
                &lexical,
                &lexical,
                &typed,
                cancellation,
                &session,
                |fact| fact.resolve_reference_by_demand(reference, &mut actual),
            )
            .unwrap();

        let ready = |result| match result {
            crate::analyzer::resolution::FactDemandResolution::Ready(answer) => answer,
            crate::analyzer::resolution::FactDemandResolution::Cancelled(completion) => {
                panic!("unbounded parity reference stopped: {completion:?}")
            }
        };
        let observed = ready(observed);
        let reasons = match observed.completion() {
            ResolutionCompletion::Complete => Vec::new(),
            ResolutionCompletion::Incomplete(reasons) => reasons
                .iter()
                .filter_map(|reason| match reason {
                    ResolutionIncompleteReason::UnsupportedSemantic(id) => Some(*id),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        };
        let mut foreign_access_reasons = BTreeSet::new();
        let outcome = typed
            .visit_gap_reason_provenance_pages_for_reasons(
                TypedFactRequest::new(&reasons),
                cancellation,
                &mut FactPageVisitor::new(&mut |rows| {
                    for row in rows {
                        if row.fragment() != lowered.lexical().fragment()
                            && row.origin()
                                == LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnsupportedVisibility,
                                )
                        {
                            foreign_access_reasons.insert(row.reason());
                        }
                    }
                    Ok(true)
                }),
            )
            .unwrap();
        assert!(outcome.is_exhausted());
        golden_observation(
            "source",
            (&reference, &observed, &foreign_access_reasons),
            &actual_arena,
            operation,
        );
        observations.push(SourceSweepObservation {
            answer: observed,
            foreign_access_reasons,
        });
    }
    observations
}

pub fn run_terminal_descent(
    operation: &SelectedResolutionOperation<'_, '_>,
    caller_path: &str,
    name: &str,
    lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
) {
    let session = ResolutionSession::unbounded();
    let (blueprint, caller) = context(
        operation,
        Language::Scala,
        "scala",
        caller_path,
        cancellation,
        &session,
    );
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let environment = Environment {
        operation,
        base: &lexical,
        initial: blueprint.context_token(),
        session: &session,
        cancellation,
        caller,
    };
    let candidate_arena = RefCell::new(ClosedRelations::default());

    let probe = environment.language(&candidate_arena);
    let (endpoint, prefix) = lowered
        .lexical()
        .paths()
        .iter()
        .filter_map(|(_, path)| {
            if path.end().node() != BindingNodeId::universal_root() {
                return None;
            }
            let source = probe.source_demand(path.end()).unwrap()?;
            let SelectedRootPathHalf::Reference {
                identity,
                prefix_reference,
                source_reference,
                demand,
                ..
            } = source.qualified?
            else {
                return None;
            };
            let recipe = operation
                .jvm_lookup_recipes(identity.fragment(), [demand], cancellation)
                .unwrap()
                .unwrap()
                .pop()
                .unwrap();
            (recipe.namespace() == ResolutionNamespace::Type && recipe.spelling() == name).then(
                || {
                    let reference = prefix_reference
                        .or_else(|| {
                            probe
                                .jvm_source_reference_semantic(source_reference)
                                .unwrap()
                        })
                        .expect("qualified source has a reference");
                    (path.end().clone(), reference)
                },
            )
        })
        .next()
        .expect("qualified Scala Type reference");
    let key = DemandRelationKey::caller(endpoint.clone());
    let base = blueprint.path_fragment_source(&lexical, &lexical, None);
    let candidate_source = ClosedForwardSource::new(
        &base,
        &lexical,
        &candidate_arena,
        &session,
        CALLER_ENVIRONMENT,
    );

    let selections = RefCell::new(Vec::new());
    let mut candidate = Observed {
        selections: &selections,
        dependencies: None,
        inner: DemandProvider::new(SharedDemand {
            source_closures: HashMap::default(),
            rules: JvmRules::new(environment.language(&candidate_arena)),
            arena: &candidate_arena,
            paths: &lexical,
            ready: &operation.ready,
            projection_memo: Some(&operation.jvm_context_blueprints),
            base: &lexical,
            session: &session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        }),
    };

    let actual = blueprint
        .with_forward_operation_for_test(
            &candidate_source,
            &lexical,
            &lexical,
            &typed,
            cancellation,
            &session,
            |fact| fact.prepare_relation_for_test(&endpoint, prefix, &mut candidate),
        )
        .unwrap();

    let actual_authority = candidate.resolved_closure_discharges(&key);
    golden_observation(
        "singleton",
        (&name, &actual, &actual_authority, &*selections.borrow()),
        &candidate_arena,
        operation,
    );
}

#[doc(hidden)]
pub fn run(
    operation: &SelectedResolutionOperation<'_, '_>,
    caller_path: &str,
    lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
) -> Report {
    let session = ResolutionSession::unbounded();
    let (blueprint, caller) = context(
        operation,
        Language::Scala,
        "scala",
        caller_path,
        cancellation,
        &session,
    );
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let environment = Environment {
        operation,
        base: &lexical,
        initial: blueprint.context_token(),
        session: &session,
        cancellation,
        caller,
    };
    let trial_arena = RefCell::new(ClosedRelations::default());

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

    let base = blueprint.path_fragment_source(&lexical, &lexical, None);
    let closed =
        ClosedForwardSource::new(&base, &lexical, &trial_arena, &session, CALLER_ENVIRONMENT);
    let rules = JvmRules::new(language);
    let mut trial = Observed {
        inner: DemandProvider::new(SharedDemand {
            source_closures: HashMap::default(),
            rules,
            arena: &trial_arena,
            paths: &lexical,
            ready: &operation.ready,
            projection_memo: Some(&operation.jvm_context_blueprints),
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

    let mut trials = observed_trial.borrow_mut();

    assert_eq!(trials.len(), 1, "shared member phase executes once");

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
    golden_observation(
        "member",
        (
            &trial_completion,
            &*trials,
            trial.resolved_closure_discharges(&DemandRelationKey::caller(endpoint.clone())),
        ),
        &trial_arena,
        operation,
    );
    Report {
        observation: trials.pop().unwrap(),
        published,
        dependencies: dependencies.get(),
    }
}
#[doc(hidden)]
pub fn run_discovered(
    operation: &SelectedResolutionOperation<'_, '_>,
    language: Language,
    storage: &str,
    caller_path: &str,
    lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
) {
    run_provider_only(
        operation,
        language,
        storage,
        caller_path,
        lowered,
        cancellation,
    );
    let session = ResolutionSession::unbounded();
    let (blueprint, caller) = context(
        operation,
        language,
        storage,
        caller_path,
        cancellation,
        &session,
    );
    let lexical = operation.ready.lexical_source();
    let environment = Environment {
        operation,
        base: &lexical,
        initial: blueprint.context_token(),
        session: &session,
        cancellation,
        caller,
    };
    let trial_arena = RefCell::new(ClosedRelations::default());

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
            (recipes[0].spelling() == "List" && recipes[0].namespace() == ResolutionNamespace::Type)
                .then_some(DemandRelationKey::caller(endpoint.clone()))
        })
        .collect::<Vec<_>>();
    assert!(
        !endpoints.is_empty(),
        "local reference has a discovered root"
    );
    // Probe every retained absolute source half from this real parser fixture.
    // The normal provider classifies before walking; no failed trial falls back.
    for (_, path) in lowered.lexical().paths() {
        let endpoint = path.end();
        if endpoint.node() != BindingNodeId::universal_root() {
            continue;
        }
        let Some(source) = probe.source_demand(endpoint).unwrap() else {
            continue;
        };
        let Some(SelectedRootPathHalf::Reference {
            anchor: ResolutionRootImportAnchor::Absolute,
            prefix_reference: None,
            route,
            ..
        }) = source.qualified.as_ref()
        else {
            continue;
        };
        let mut recipes = operation
            .jvm_lookup_recipes(
                operation
                    .mount_table()
                    .mount_by_ordinal(source.mount)
                    .unwrap()
                    .fragment(),
                route.iter().copied().chain([source.lookup]),
                cancellation,
            )
            .unwrap()
            .unwrap();
        let demand = recipes.pop().expect("one terminal recipe");
        if !matches!(
            demand.namespace(),
            ResolutionNamespace::Type | ResolutionNamespace::Value
        ) {
            continue;
        }
        if !recipes
            .iter()
            .all(|recipe| recipe.namespace() == ResolutionNamespace::Package)
        {
            continue;
        }
        let candidate_arena = RefCell::new(ClosedRelations::default());

        let mut candidate = DemandProvider::new(SharedDemand {
            source_closures: HashMap::default(),
            rules: JvmRules::new(environment.language(&candidate_arena)),
            arena: &candidate_arena,
            paths: &lexical,
            ready: &operation.ready,
            projection_memo: Some(&operation.jvm_context_blueprints),
            base: &lexical,
            session: &session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        });

        let key = DemandRelationKey::caller(endpoint.clone());
        assert!(matches!(
            candidate.discover(&key).unwrap(),
            DemandRootDiscovery::Ready(_)
        ));

        let before = crate::analyzer::resolution::seam_profile::SHARED_CLOSER_STEPS.get();
        let actual = candidate.close(&key, &[]).unwrap();
        let middle = crate::analyzer::resolution::seam_profile::SHARED_CLOSER_STEPS.get();
        golden_observation("absolute", (&key, &actual), &candidate_arena, operation);

        let actual_work: [usize; super::super::demand_closure::CLOSER_WORK_KINDS] =
            std::array::from_fn(|i| middle[i] - before[i]);

        // Keep the independently measured source-work category contract.
        let expected_work = match demand.spelling() {
            "List" => [
                0, 0, 0, 4, 0, 1, 1, 0, 0, 3, 0, 1, 1, 1, 1, 1, 2, 0, 0, 0, 1, 0, 0, 2, 0,
            ],
            "Missing" => [
                0, 0, 0, 3, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            spelling => panic!("unrecognized source work fixture: {spelling}"),
        };
        assert_eq!(actual_work, expected_work, "JVM source category pin");
    }
    let endpoint = &endpoints[0];
    let mut trial = DemandProvider::new(SharedDemand {
        source_closures: HashMap::default(),
        rules: JvmRules::new(environment.language(&trial_arena)),
        arena: &trial_arena,
        paths: &lexical,
        ready: &operation.ready,
        projection_memo: Some(&operation.jvm_context_blueprints),
        base: &lexical,
        session: &session,
        cancellation,
        completion: &ResolutionCompletion::Complete,
    });

    let trial_plan = trial.discover(endpoint).unwrap();

    let DemandRootDiscovery::Ready(trial_plan) = trial_plan else {
        panic!("shared discovered root is ready")
    };

    assert!(trial_plan.prefixes.is_empty());
    let trial_completion = trial.close(endpoint, &[]).unwrap();

    let actual = trial
        .resolved_closure_discharges(endpoint)
        .expect("shared carries provider proof");

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

    golden_observation(
        "witness",
        (&trial_completion, &actual),
        &trial_arena,
        operation,
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
// The JVM fixture harness observes the real shared language at its existing
// poll boundary. Fault callbacks only cancel or fail a real outstanding wait.
#[derive(Debug, PartialEq, Eq)]
struct OrderAggregate {
    owners: Vec<SemanticId>,
    completion: ResolutionCompletion,
    providers: Vec<(
        crate::analyzer::resolution::HierarchyProviderKey,
        crate::analyzer::resolution::HierarchyProviderVisit,
        ResolutionCompletion,
        Option<bool>,
    )>,
}
#[derive(Debug, Default)]
struct OrderTrace {
    aggregates: Vec<OrderAggregate>,
    orders: Vec<(bool, Vec<SemanticId>)>,
    waiters: HashMap<EndpointSignature, crate::analyzer::resolution::CloseContinuationId>,
    slots: usize,
    yields: usize,
    resumes: usize,
    cancellations: usize,
}
impl OrderTrace {
    fn selection(
        &mut self,
        selection: &DemandMemberSelection,
        view: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
    ) -> Result<()> {
        let mut providers = Vec::new();
        assert!(view.visit(selection.provenance, &mut || false, &mut |row| {
            providers.push((
                row.provider.clone(),
                row.visit,
                row.completion.clone(),
                row.inventory_complete,
            ));
            Ok(())
        })?);
        self.aggregates.push(OrderAggregate {
            owners: selection.owners.clone(),
            completion: selection.completion.clone(),
            providers,
        });
        if let Some(id) = selection.order {
            let status = view.order_status(id);
            assert_eq!(status.completion, &ResolutionCompletion::Complete);
            let mut owners = Vec::new();
            assert!(view.visit_order(id, &mut || false, &mut |row| {
                owners.push(row.owner);
                Ok(())
            })?);
            self.orders.push((status.complete, owners));
        }
        Ok(())
    }
    fn assert_drained(&self) {
        assert_eq!(
            self.slots, 0,
            "actual shared source slots are gone: {self:?}"
        );
        assert!(
            self.waiters.is_empty(),
            "outstanding source member waiters are gone: {self:?}"
        );
    }
}
struct OrderLanguage<'a, 'store, 'input> {
    inner: SharedDemand<'a, 'store, 'input, JvmRules<'a, 'store, 'input>>,
    trace: &'a RefCell<OrderTrace>,
    order: Option<crate::analyzer::resolution::HierarchyOrderRequest>,
    at_yield: fn(&CancellationToken),
    at_resume: fn() -> Result<()>,
}
impl DemandLanguage for OrderLanguage<'_, '_, '_> {
    type RootQuestion = RootFrame;
    type ContextKey = ContextId;
    type ContextData = Option<SelectedResolutionContextSet>;
    fn discover_root(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<RootFrame>> {
        self.inner.discover_root(endpoint)
    }
    fn context_key(&self, question: &RootFrame) -> Option<ContextId> {
        self.inner.context_key(question)
    }
    fn prepare_context(
        &mut self,
        key: &ContextId,
        question: &RootFrame,
    ) -> Result<LanguageContextPreparation<Self::ContextData>> {
        self.inner.prepare_context(key, question)
    }
    fn prefix_inputs(
        &mut self,
        question: &mut RootFrame,
        context: Option<&Self::ContextData>,
    ) -> Result<LanguagePrefixInputs> {
        self.inner.prefix_inputs(question, context)
    }
    fn member_selection(
        &mut self,
        question: &RootFrame,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<DemandMemberSelectionOutcome> {
        let mut outcome = self.inner.member_selection(question, context, inputs)?;
        if let DemandMemberSelectionOutcome::Ready {
            request: Some(request),
            ..
        } = &mut outcome
        {
            request.order = self.order;
        }
        Ok(outcome)
    }
    fn close_root(
        &mut self,
        endpoint: &EndpointSignature,
        question: &RootFrame,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<LanguageClosure> {
        self.inner.close_root(endpoint, question, context, inputs)
    }
    fn close_selected_members(
        &mut self,
        endpoint: &EndpointSignature,
        question: &RootFrame,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        selection: &DemandMemberSelection,
    ) -> Result<LanguageClosure> {
        self.inner
            .close_selected_members(endpoint, question, context, inputs, selection)
    }
    fn cancel_close_root(&mut self, endpoint: &EndpointSignature) {
        self.inner.cancel_close_root(endpoint);
        let mut trace = self.trace.borrow_mut();
        trace.waiters.remove(endpoint);
        trace.slots = self.inner.source_closures.len();
        trace.cancellations += 1;
    }
    fn poll_close_root(
        &mut self,
        endpoint: &EndpointSignature,
        question: &RootFrame,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        initial_members: Option<&DemandMemberSelection>,
        member_completion: &ResolutionCompletion,
        view: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<crate::analyzer::resolution::CloseProgress<LanguageClosure>> {
        use crate::analyzer::resolution::{CloseProgress, CloseResume};
        if let CloseResume::Members {
            continuation,
            selection,
        } = &resume
        {
            (self.at_resume)()?;
            let mut trace = self.trace.borrow_mut();
            assert_eq!(trace.waiters.remove(endpoint), Some(*continuation));
            trace.resumes += 1;
            trace.selection(selection, view)?;
        }
        if let Some(selection) = initial_members {
            self.trace.borrow_mut().selection(selection, view)?;
        }
        let mut progress = self.inner.poll_close_root(
            endpoint,
            question,
            context,
            inputs,
            initial_members,
            member_completion,
            view,
            resume,
        )?;
        let mut trace = self.trace.borrow_mut();
        trace.slots = self.inner.source_closures.len();
        if let CloseProgress::Members {
            continuation,
            request,
            ..
        } = &mut progress
        {
            request.order = self.order;
            assert!(
                trace.slots > 0,
                "a real JVM source cursor owns the yielded reply"
            );
            assert!(
                trace
                    .waiters
                    .insert(endpoint.clone(), *continuation)
                    .is_none()
            );
            trace.yields += 1;
            (self.at_yield)(self.inner.cancellation);
        }
        Ok(progress)
    }
}
struct OrderAttempt {
    completion: Result<ResolutionCompletion>,
    trace: OrderTrace,
    discharges: Option<DemandClosureDischarges>,
    order_work: usize,
    scope: usize,
}
#[allow(clippy::too_many_arguments)]
fn order_attempt(
    operation: &SelectedResolutionOperation<'_, '_>,
    caller_path: &str,
    lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
    order: Option<crate::analyzer::resolution::HierarchyOrderRequest>,
    at_yield: fn(&CancellationToken),
    at_resume: fn() -> Result<()>,
) -> OrderAttempt {
    let (blueprint, caller) = context(
        operation,
        Language::Scala,
        "scala",
        caller_path,
        cancellation,
        session,
    );
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let arena = RefCell::new(ClosedRelations::default());
    let environment = Environment {
        operation,
        base: &lexical,
        initial: blueprint.context_token(),
        session,
        cancellation,
        caller,
    };
    let probe = environment.language(&arena);
    let (endpoint, target) = lowered
        .lexical()
        .paths()
        .iter()
        .filter_map(|(_, path)| {
            if path.end().node() != BindingNodeId::universal_root() {
                return None;
            }
            let source = probe.source_demand(path.end()).unwrap()?;
            let (
                SelectedRootPathHalf::Import {
                    identity, demand, ..
                },
                qualifiers,
            ) = source.import_qualifiers.as_ref()?
            else {
                return None;
            };
            let recipes = operation
                .jvm_lookup_recipes(identity.fragment(), [*demand], cancellation)
                .unwrap()
                .unwrap();
            (recipes[0].spelling() == "selected").then_some((path.end().clone(), qualifiers[0]))
        })
        .next()
        .expect("fixture has a real selected member import");
    let trace = RefCell::new(OrderTrace::default());
    let mut provider = DemandProvider::new(OrderLanguage {
        inner: SharedDemand {
            source_closures: HashMap::default(),
            rules: JvmRules::new(environment.language(&arena)),
            arena: &arena,
            paths: &lexical,
            ready: &operation.ready,
            projection_memo: Some(&operation.jvm_context_blueprints),
            base: &lexical,
            session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        },
        trace: &trace,
        order,
        at_yield,
        at_resume,
    });
    let base = blueprint.path_fragment_source(&lexical, &lexical, None);
    let closed = ClosedForwardSource::new(&base, &lexical, &arena, session, CALLER_ENVIRONMENT);
    let before = crate::analyzer::resolution::seam_profile::SHARED_CLOSER_STEPS.get();
    let completion = blueprint.with_forward_operation_for_test(
        &closed,
        &lexical,
        &lexical,
        &typed,
        cancellation,
        session,
        |fact| fact.prepare_relation_for_test(&endpoint, target, &mut provider),
    );
    let after = crate::analyzer::resolution::seam_profile::SHARED_CLOSER_STEPS.get();
    let discharges = provider.resolved_closure_discharges(&DemandRelationKey::caller(endpoint));
    drop(provider);
    let trace = trace.into_inner();
    trace.assert_drained();
    OrderAttempt {
        completion,
        trace,
        discharges,
        order_work: after[CloserWork::HierarchyOrder as usize]
            - before[CloserWork::HierarchyOrder as usize],
        scope: session.finish(()).work().scope_nodes,
    }
}
// Test runner, not a provider constructor: callers retain no native state.
#[doc(hidden)]
pub fn run_order_contract(
    operation: &SelectedResolutionOperation<'_, '_>,
    caller_path: &str,
    lowered: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
) -> (usize, bool, Vec<(bool, Vec<SemanticId>)>) {
    use crate::analyzer::resolution::{HierarchyOrderRequest, HierarchyProviderVisit};
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    let request = Some(HierarchyOrderRequest {
        policy: &super::super::jvm_hierarchy_order::JVM_DECLARED_ORDER,
        start_after: None,
    });
    let plain = order_attempt(
        operation,
        caller_path,
        lowered,
        &ResolutionSession::unbounded(),
        &CancellationToken::new(),
        None,
        |_| {},
        || Ok(()),
    );
    let ordered = order_attempt(
        operation,
        caller_path,
        lowered,
        &ResolutionSession::unbounded(),
        &CancellationToken::new(),
        request,
        |_| {},
        || Ok(()),
    );
    assert_eq!(
        plain.completion.as_ref().unwrap(),
        ordered.completion.as_ref().unwrap()
    );
    assert_eq!(
        plain.trace.aggregates, ordered.trace.aggregates,
        "ordered visitation preserves exact owners, completion and provider-qualified reasons"
    );
    assert!(
        ordered.trace.yields > 0 && ordered.trace.resumes > 0,
        "real Members yield then resume: {:?}",
        ordered.trace
    );
    let boundary = ordered
        .trace
        .aggregates
        .iter()
        .flat_map(|row| &row.providers)
        .any(|row| row.1 == HierarchyProviderVisit::NotSearched);
    let cancellation = CancellationToken::new();
    let cancelled = order_attempt(
        operation,
        caller_path,
        lowered,
        &ResolutionSession::unbounded(),
        &cancellation,
        request,
        CancellationToken::cancel,
        || Ok(()),
    );
    assert!(cancelled.trace.yields > 0 && cancelled.trace.cancellations > 0);
    assert!(
        cancelled
            .completion
            .unwrap()
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    );
    assert!(cancelled.discharges.is_none());
    let terminal = order_attempt(
        operation,
        caller_path,
        lowered,
        &ResolutionSession::unbounded(),
        &CancellationToken::new(),
        request,
        |_| {},
        || {
            Err(crate::analyzer::store::StoreError::new(
                "JVM source resume terminal fault",
            ))
        },
    );
    assert!(terminal.completion.is_err());
    assert!(terminal.trace.yields > 0 && terminal.trace.cancellations > 0);
    assert!(terminal.discharges.is_none());
    let cap = ResolutionSession::bounded(
        ReceiverAnalysisBudget {
            max_targets: usize::MAX,
            max_summary_expansions: usize::MAX,
            max_resolution_rounds: usize::MAX,
            max_scope_nodes: usize::MAX,
            max_hierarchy_order_steps: 0,
            ..ReceiverAnalysisBudget::default()
        },
        None,
    );
    let exhausted = order_attempt(
        operation,
        caller_path,
        lowered,
        &cap,
        &CancellationToken::new(),
        request,
        |_| {},
        || Ok(()),
    );
    assert_eq!(
        plain.completion.as_ref().unwrap(),
        exhausted.completion.as_ref().unwrap()
    );
    assert_eq!(plain.trace.aggregates, exhausted.trace.aggregates);
    assert_eq!(exhausted.order_work, 0);
    assert_eq!(exhausted.trace.orders.len(), ordered.trace.orders.len());
    for (capped, normal) in exhausted.trace.orders.iter().zip(&ordered.trace.orders) {
        if !capped.0 && !capped.1.is_empty() {
            assert_eq!(
                capped, normal,
                "an uncharged NotSearched leaf is unchanged, not a cap discharge"
            );
        }
    }
    if ordered.order_work > 0 {
        assert!(
            exhausted
                .trace
                .orders
                .iter()
                .any(|(complete, owners)| !*complete && owners.is_empty()),
            "cap exhaustion retains no provisional ordered discharge: {:?}",
            exhausted.trace.orders
        );
    }

    // A finite aggregate allowance equal to the completed unordered cost
    // must remain complete even when optional ordering consumes its own cap.
    let finite_plain = ResolutionSession::bounded(
        ReceiverAnalysisBudget {
            max_targets: usize::MAX,
            max_summary_expansions: usize::MAX,
            max_resolution_rounds: usize::MAX,
            max_scope_nodes: usize::MAX,
            max_hierarchy_order_steps: 0,
            ..ReceiverAnalysisBudget::default()
        },
        None,
    );
    let measured = order_attempt(
        operation,
        caller_path,
        lowered,
        &finite_plain,
        &CancellationToken::new(),
        None,
        |_| {},
        || Ok(()),
    );
    let finite_ordered = ResolutionSession::bounded(
        ReceiverAnalysisBudget {
            max_targets: usize::MAX,
            max_summary_expansions: usize::MAX,
            max_resolution_rounds: usize::MAX,
            max_scope_nodes: measured.scope,
            max_hierarchy_order_steps: 0,
            ..ReceiverAnalysisBudget::default()
        },
        None,
    );
    let stopped_order = order_attempt(
        operation,
        caller_path,
        lowered,
        &finite_ordered,
        &CancellationToken::new(),
        request,
        |_| {},
        || Ok(()),
    );
    assert_eq!(
        measured.completion.unwrap(),
        stopped_order.completion.unwrap()
    );
    assert_eq!(measured.trace.aggregates, stopped_order.trace.aggregates);
    assert!(matches!(
        finite_ordered.finish(()),
        brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Complete { .. }
    ));
    GOLDEN.with_borrow_mut(|slot| {
        if let Some((_, scenario, rows)) = slot {
            rows.push(format!(
                "=== {scenario} / order ===\nwork={} boundary={boundary} trace={:?}\n",
                ordered.order_work, ordered.trace
            ));
        }
    });
    (ordered.order_work, boundary, ordered.trace.orders)
}
