use super::*;
use crate::analyzer::store::WorkspacePackageFileRow;
use crate::analyzer::store::resolution_operation::java_reverse_rows::{
    JvmReverseCandidateOutcome, JvmReverseConfirmed,
};

const JAVA_ROOT_CONSUMER_PATH: &str = "src/use/Use.java";
const JAVA_ROOT_PROVIDER_PATH: &str = "src/dep/Target.java";
const JAVA_ROOT_DECOY_PATH: &str = "src/decoy/Target.java";
const JAVA_ROOT_SOURCES: [(&str, &str); 3] = [
    (
        JAVA_ROOT_CONSUMER_PATH,
        "package use; import dep.Target; class Use { Target field; }",
    ),
    (
        JAVA_ROOT_PROVIDER_PATH,
        "package dep; public class Target {}",
    ),
    (
        JAVA_ROOT_DECOY_PATH,
        "package decoy; public class Target {}",
    ),
];

struct JavaRootResolutionOperationFixture {
    store: AnalyzerStore,
    project_root: tempfile::TempDir,
    project: MutableGenerationProject,
    workspace_id: WorkspaceId,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    source_rows: Vec<WorkspaceFileRow>,
    package_rows: Vec<crate::analyzer::store::WorkspacePackageFileRow>,
    configuration: Vec<crate::analyzer::store::WorkspaceConfigurationInput>,
    consumer_path: String,
    consumer_facts: FileResolutionFacts,
    provider_facts: FileResolutionFacts,
    decoy_facts: FileResolutionFacts,
}

impl JavaRootResolutionOperationFixture {
    fn new() -> Self {
        Self::with_consumer(JAVA_ROOT_SOURCES[0].1)
    }

    fn with_consumer(consumer: &str) -> Self {
        Self::with_layout(
            consumer,
            [
                JAVA_ROOT_CONSUMER_PATH,
                JAVA_ROOT_PROVIDER_PATH,
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        )
    }

    fn with_layout(consumer: &str, paths: [&str; 3], configuration: &[(&str, &str)]) -> Self {
        Self::with_source_texts(
            [consumer, JAVA_ROOT_SOURCES[1].1, JAVA_ROOT_SOURCES[2].1],
            paths,
            configuration,
        )
    }

    fn with_source_texts(
        sources: [&str; 3],
        paths: [&str; 3],
        configuration: &[(&str, &str)],
    ) -> Self {
        let configuration = configuration
            .iter()
            .map(|(path, source)| {
                crate::analyzer::store::WorkspaceConfigurationInput::new(
                    (*path).to_owned(),
                    source.as_bytes().to_vec().into_boxed_slice(),
                )
            })
            .collect::<Vec<_>>();
        // A mutable-generation project and a persistent store share this root
        // so the fixture can exercise selected publication and database reopen.
        let project_root = tempfile::tempdir().unwrap();
        let project = MutableGenerationProject::new(project_root.path(), Language::Java);
        let store = AnalyzerStore::open_persistent(&project_root.path().join("store.db")).unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "java-root-operation-v1")
            .unwrap();
        store
            .ensure_resolution_producer_epoch("java", Language::Java)
            .unwrap();
        let mut source_rows = Vec::new();
        let mut package_rows = Vec::new();
        let mut facts = Vec::new();
        let mut prepared = Vec::new();
        for (path, source) in paths.into_iter().zip(sources) {
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            let (state, file_facts) =
                parsed_operation_state(project_root.path(), path, source, &JavaAdapter);
            package_rows.push(crate::analyzer::store::WorkspacePackageFileRow {
                package_name: state.package_name.clone(),
                rel_path: path.to_owned(),
            });
            prepared.push(
                AnalyzerStore::prepare_parsed_blob(oid, "java", generation, &JavaAdapter, state)
                    .unwrap(),
            );
            source_rows.push(WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid: oid,
            });
            facts.push(file_facts);
        }
        let (outcomes, _) = store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 3);
        assert!(
            outcomes.iter().all(|outcome| outcome.error.is_none()),
            "{outcomes:?}"
        );
        let workspace_id = WorkspaceId(
            "7575757575757575757575757575757575757575757575757575757575757575".to_owned(),
        );
        let snapshot = store
            .sync_workspace_inputs_for_workspace(
                &workspace_id,
                "java",
                generation,
                &source_rows,
                &[],
                &[],
                &package_rows,
                &[],
                &[],
                &configuration,
                &[],
            )
            .unwrap();
        store.reconcile_jvm_package_context(&snapshot).unwrap();
        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert("java".to_owned(), snapshot);
        let [consumer_facts, provider_facts, decoy_facts]: [FileResolutionFacts; 3] =
            facts.try_into().unwrap();
        Self {
            store,
            project_root,
            project,
            workspace_id,
            snapshots,
            languages: vec![SelectedResolutionLanguage::new("java", Language::Java)],
            source_rows,
            package_rows,
            configuration,
            consumer_path: paths[0].to_owned(),
            consumer_facts,
            provider_facts,
            decoy_facts,
        }
    }

    fn reopen(mut self) -> Self {
        let database = self.project_root.path().join("store.db");
        drop(self.store);
        self.store = AnalyzerStore::open_persistent(&database).unwrap();
        self
    }

    fn open(
        &self,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperationOpenOutcome<'_, '_> {
        self.store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &self.project,
                    &self.workspace_id,
                    &self.snapshots,
                    &self.languages,
                    &[],
                ),
                cancellation,
            )
            .unwrap()
    }

    fn open_ready(&self, cancellation: &CancellationToken) -> SelectedResolutionOperation<'_, '_> {
        match self.open(cancellation) {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            _ => panic!("complete Java operation must open Ready"),
        }
    }

    fn contexts_for(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
    ) -> SelectedResolutionContextSet {
        match operation
            .java_import_context(&self.consumer_path, &CancellationToken::new())
            .unwrap()
        {
            super::super::jvm_context::JavaImportContext::Ready { context, .. } => *context,
            _ => panic!("published Java selected source context must be ready"),
        }
    }
}

fn assert_java_root_parity(fixture: &JavaRootResolutionOperationFixture) -> bool {
    let cancellation = CancellationToken::default();
    let mounted = fixture.open_ready(&cancellation);
    assert_eq!(mounted.mounts().unwrap().len(), 3);
    let mounts = mounted.mounts().unwrap().to_vec();
    let preload_context = fixture.contexts_for(&mounted);

    let artifact_for = |path: &str, facts: &FileResolutionFacts| {
        let mount = mounts
            .iter()
            .find(|mount| mount.persisted_relative_path() == path)
            .unwrap_or_else(|| panic!("missing selected Java mount {path:?}"));
        let artifact = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            mount.fragment(),
            &mounted.ready.shared_names(),
            Language::Java,
            facts,
        );
        crate::analyzer::resolution::record_fixture_selected_identity_catalog(
            artifact.identities(),
            mounted
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())
                .unwrap()
                .fragment_digest()
                .as_bytes(),
        );
        artifact
    };
    let consumer = artifact_for(JAVA_ROOT_CONSUMER_PATH, &fixture.consumer_facts);
    let provider = artifact_for(JAVA_ROOT_PROVIDER_PATH, &fixture.provider_facts);
    let decoy = artifact_for(JAVA_ROOT_DECOY_PATH, &fixture.decoy_facts);
    let reference_site = site_for_identifier(
        &fixture.consumer_facts,
        "Target",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let provider_site = site_for_identifier(
        &fixture.provider_facts,
        "Target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Type,
    );
    let decoy_site = site_for_identifier(
        &fixture.decoy_facts,
        "Target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Type,
    );
    let reference = semantic_at(&consumer, reference_site, LoweredSemanticRole::Reference);
    let provider_definition =
        semantic_at(&provider, provider_site, LoweredSemanticRole::Definition);
    let decoy_definition = semantic_at(&decoy, decoy_site, LoweredSemanticRole::Definition);

    let mut preload = PreloadedFactResolutionService::from_lowered_fragments(
        [
            consumer.lexical().clone(),
            provider.lexical().clone(),
            decoy.lexical().clone(),
        ],
        [
            consumer.typed().clone(),
            provider.typed().clone(),
            decoy.typed().clone(),
        ],
    );
    // Independent in-memory ownership oracle from lowered AST facts. Package
    // identity comes from this fixture's authored package rows, not access SQL.
    let mut endpoints = Vec::new();
    let mut declarations = Vec::new();
    for (index, (path, artifact)) in [
        (JAVA_ROOT_CONSUMER_PATH, &consumer),
        (JAVA_ROOT_PROVIDER_PATH, &provider),
        (JAVA_ROOT_DECOY_PATH, &decoy),
    ]
    .into_iter()
    .enumerate()
    {
        let package = fixture
            .package_rows
            .iter()
            .find(|row| row.rel_path == path)
            .map(|row| row.package_name.clone());
        // These oracle fixtures author classes only; an interface would need
        // its own flag before this oracle could describe it.
        let source_path = &fixture.source_rows[index].rel_path;
        let text = std::fs::read_to_string(fixture.project_root.path().join(source_path))
            .expect("read Java oracle fixture source");
        assert!(!text.contains("interface"), "{source_path}: {text}");
        declarations.extend(artifact.typed().member_scopes().iter().map(|row| {
            crate::analyzer::resolution::JavaInheritanceDeclaration {
                definition: row.definition(),
                name: String::new(),
                package: package.clone(),
                kind: crate::analyzer::resolution::JavaInheritanceDeclarationKind::Type {
                    is_interface: false,
                    is_singleton: false,
                },
            }
        }));
        let parents = artifact
            .typed()
            .member_owners()
            .iter()
            .map(|row| (row.definition(), row.owner_definition()))
            .collect::<HashMap<_, _>>();
        let types = artifact
            .typed()
            .member_scopes()
            .iter()
            .map(|row| row.definition())
            .collect::<HashSet<_>>();
        for row in artifact.lexical().semantics() {
            let mut owner = if row.role() == LoweredSemanticRole::Definition {
                Some(row.semantic())
            } else {
                row.reference_owner().flatten()
            };
            let mut seen = HashSet::default();
            while let Some(current) = owner {
                assert!(seen.insert(current), "fixture ownership is acyclic");
                let Some(parent) = parents.get(&current) else {
                    break;
                };
                owner = Some(*parent);
            }
            endpoints.push(crate::analyzer::resolution::JavaAccessEndpoint {
                semantic: row.semantic(),
                package: package.clone(),
                outermost_type: owner.filter(|owner| types.contains(owner)),
            });
        }
    }
    preload.set_java_access_endpoints(endpoints);
    preload.set_java_inheritance_metadata(declarations);
    let SelectedResolutionContextValidationOutcome::Ready(preload_context) = preload_context
        .validate_exact_mounts(mounts.len(), &mount_lookup(&mounts), &cancellation)
        .expect("validate preloaded Java root context")
    else {
        panic!("uncancelled preloaded Java root context must validate")
    };
    let preload_blueprint =
        crate::analyzer::resolution::SelectedContextTestOracle::collect_context(
            preload_context,
            &mounted.ready.shared_names(),
            &cancellation,
        )
        .expect("compile independent preloaded Java root context oracle");
    drop(mounted);
    let expected_point = preload_blueprint
        .resolve_reference(&preload, &preload, reference, &cancellation)
        .expect("preloaded cross-package Java point resolution");
    assert!(
        expected_point
            .binding()
            .targets()
            .contains(&provider_definition)
    );
    assert!(
        !expected_point
            .binding()
            .targets()
            .contains(&decoy_definition)
    );
    assert!(matches!(
        expected_point.completion(),
        ResolutionCompletion::Incomplete(_)
    ));

    let point_locator = SelectedSemanticLocator::new(
        "java",
        JAVA_ROOT_CONSUMER_PATH,
        reference_site,
        LoweredSemanticRole::Reference,
    );
    let point_operation = fixture.open_ready(&cancellation);
    let point_context = fixture.contexts_for(&point_operation);
    let mut point_metrics = SelectedResolutionContextMetrics;
    let point = point_operation
        .resolve_reference(
            point_context,
            &point_locator,
            &cancellation,
            &mut point_metrics,
        )
        .expect("persisted cross-package Java point resolution");
    assert_empty_context_metrics(&point_metrics);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(point)) = point
    else {
        panic!("persisted cross-package Java point must return a native found answer")
    };
    assert_eq!(point.site_metadata(), expected_point.site_metadata());
    assert_eq!(point.reference_owner(), expected_point.reference_owner());
    assert_eq!(
        point.callable_receiver_origin(),
        expected_point.callable_receiver_origin()
    );
    assert_eq!(
        point.callable_receiver_dispositions(),
        expected_point.callable_receiver_dispositions()
    );
    assert_eq!(
        point.callable_candidate_applicability(),
        expected_point.callable_candidate_applicability()
    );
    assert_eq!(point.member_owners(), expected_point.member_owners());
    assert_eq!(
        point.observed_type_identity(),
        expected_point.observed_type_identity()
    );
    assert_eq!(
        point.type_bound_receiver(),
        expected_point.type_bound_receiver()
    );
    assert_eq!(
        point.binding().targets(),
        expected_point.binding().targets()
    );
    assert_eq!(
        point.binding().witnesses(),
        expected_point.binding().witnesses()
    );
    let implicit_project = fixture.configuration.is_empty();
    let mut completion_improved = false;
    completion_improved |= assert_java_import_route_proof_delta(
        point.binding().completion(),
        expected_point.binding().completion(),
        reference,
        implicit_project,
    );
    assert_eq!(point.projections(), expected_point.projections());
    assert_eq!(
        point.projected_frontiers().len(),
        expected_point.projected_frontiers().len()
    );
    for (actual, expected) in point
        .projected_frontiers()
        .iter()
        .zip(expected_point.projected_frontiers())
    {
        assert_eq!(actual.slot(), expected.slot());
        assert_eq!(actual.possible_values(), expected.possible_values());
        completion_improved |= assert_java_import_route_proof_delta(
            actual.completion(),
            expected.completion(),
            reference,
            implicit_project,
        );
    }
    completion_improved |= assert_java_import_route_proof_delta(
        point.completion(),
        expected_point.completion(),
        reference,
        implicit_project,
    );

    let expected_reverse = preload_blueprint
        .references_to(
            &preload,
            &preload,
            2,
            provider_definition,
            &cancellation,
            &mut FactReverseResolutionMetrics::default(),
        )
        .expect("preloaded cross-package Java reverse resolution");
    assert!(expected_reverse.references().contains(&reference));
    assert!(matches!(
        expected_reverse.completion(),
        ResolutionCompletion::Incomplete(_)
    ));
    let definition_locator = SelectedSemanticLocator::new(
        "java",
        JAVA_ROOT_PROVIDER_PATH,
        provider_site,
        LoweredSemanticRole::Definition,
    );
    let reverse_operation = fixture.open_ready(&cancellation);
    let reverse_context = fixture.contexts_for(&reverse_operation);
    let mut context_metrics = SelectedResolutionContextMetrics;
    let mut reverse_metrics = FactReverseResolutionMetrics::default();
    let reverse = reverse_operation
        .references_to_selected_definition(
            reverse_context,
            2,
            &definition_locator,
            &cancellation,
            &mut context_metrics,
            &mut reverse_metrics,
        )
        .expect("persisted cross-package Java reverse resolution");
    assert_empty_context_metrics(&context_metrics);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(reverse)) =
        reverse
    else {
        panic!("persisted cross-package Java reverse must return a native found answer")
    };
    assert_eq!(reverse.references(), expected_reverse.references());
    assert_eq!(reverse.answer().witnesses(), expected_reverse.witnesses());
    completion_improved |= assert_java_import_route_proof_delta(
        reverse.completion(),
        expected_reverse.completion(),
        reference,
        implicit_project,
    );
    assert!(reverse.references().contains(&reference));
    completion_improved
}

fn assert_java_import_route_proof_delta(
    actual: &ResolutionCompletion,
    expected: &ResolutionCompletion,
    source_reference: SemanticId,
    implicit_project: bool,
) -> bool {
    if implicit_project
        && matches!(actual, ResolutionCompletion::Complete)
        && matches!(expected, ResolutionCompletion::Incomplete(_))
    {
        return true;
    }
    let (ResolutionCompletion::Incomplete(actual), ResolutionCompletion::Incomplete(expected)) =
        (actual, expected)
    else {
        panic!(
            "selected Java route changed completion outside an implicit project: actual {actual:?}, expected {expected:?}"
        )
    };
    assert!(
        actual.iter().all(|reason| expected.contains(reason)),
        "persisted Java route proof must only discharge oracle evidence: actual {actual:?}, expected {expected:?}"
    );
    let removed = expected
        .iter()
        .filter(|reason| !actual.contains(reason))
        .collect::<Vec<_>>();
    assert!(
        removed.len() <= 1,
        "only one import-site gap may be discharged"
    );
    let Some(removed) = removed.first() else {
        return false;
    };
    assert!(matches!(
        **removed,
        ResolutionIncompleteReason::UnsupportedSemantic(site)
            if site.ordinal() == source_reference.ordinal()
    ));
    true
}

#[test]
fn selected_java_root_context_matches_preload_reopens_and_excludes_decoy() {
    let fixture = JavaRootResolutionOperationFixture::new();
    assert!(assert_java_root_parity(&fixture));
    let fixture = fixture.reopen();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        fixture.open(&cancelled),
        SelectedResolutionOperationOpenOutcome::Cancelled
    ));
    assert!(assert_java_root_parity(&fixture));
}

#[test]
fn selected_java_provider_withdrawal_invalidates_old_context_and_keeps_import_open() {
    let mut fixture = JavaRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let old_context = fixture.contexts_for(&operation);
    drop(operation);
    fixture
        .source_rows
        .retain(|row| row.rel_path != JAVA_ROOT_PROVIDER_PATH);
    let snapshot = fixture
        .store
        .sync_workspace_inputs_for_workspace(
            &fixture.workspace_id,
            "java",
            fixture.snapshots["java"].generation,
            &fixture.source_rows,
            &[],
            &[],
            &fixture
                .package_rows
                .iter()
                .filter(|row| row.rel_path != JAVA_ROOT_PROVIDER_PATH)
                .cloned()
                .collect::<Vec<_>>(),
            &[],
            &[],
            &fixture.configuration,
            &[],
        )
        .unwrap();
    fixture
        .store
        .reconcile_jvm_package_context(&snapshot)
        .unwrap();
    fixture.snapshots.insert("java".to_owned(), snapshot);
    let operation = fixture.open_ready(&cancellation);
    let mounts = operation.mounts().unwrap();
    assert_eq!(mounts.len(), 2);
    assert!(
        old_context
            .validate_exact_mounts(mounts.len(), &mount_lookup(mounts), &cancellation)
            .is_err()
    );
    let context = fixture.contexts_for(&operation);
    let site = site_for_identifier(
        &fixture.consumer_facts,
        "Target",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let answer = operation
        .resolve_reference(
            context,
            &SelectedSemanticLocator::new(
                "java",
                JAVA_ROOT_CONSUMER_PATH,
                site,
                LoweredSemanticRole::Reference,
            ),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
        answer
    else {
        panic!("selected Java reference remains located after provider withdrawal");
    };
    assert!(answer.binding().targets().is_empty());
    assert!(matches!(
        answer.completion(),
        ResolutionCompletion::Incomplete(_)
    ));
}

#[test]
fn selected_java_explicit_type_import_beats_on_demand_in_either_order() {
    for source in [
        "package use; import dep.Target; import decoy.*; class Use { Target field; }",
        "package use; import decoy.*; import dep.Target; class Use { Target field; }",
    ] {
        let fixture = JavaRootResolutionOperationFixture::with_consumer(source);
        assert!(assert_java_root_parity(&fixture));
    }
}

#[test]
fn selected_java_nested_type_shadows_explicit_and_on_demand_imports() {
    let fixture = JavaRootResolutionOperationFixture::with_consumer(
        "package use; import dep.Target; import decoy.*; class Use { static class Target {} Target field; }",
    );
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let context = fixture.contexts_for(&operation);
    let source_mount = operation
        .mounts()
        .unwrap()
        .iter()
        .find(|mount| mount.persisted_relative_path() == JAVA_ROOT_CONSUMER_PATH)
        .unwrap();
    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        source_mount.fragment(),
        crate::analyzer::resolution::test_shared_names(),
        Language::Java,
        &fixture.consumer_facts,
    );
    let declaration = site_for_identifier(
        &fixture.consumer_facts,
        "Target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Type,
    );
    let expected = semantic_at(&lowered, declaration, LoweredSemanticRole::Definition);
    let reference = site_for_identifier(
        &fixture.consumer_facts,
        "Target",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let answer = operation
        .resolve_reference(
            context,
            &SelectedSemanticLocator::new(
                "java",
                JAVA_ROOT_CONSUMER_PATH,
                reference,
                LoweredSemanticRole::Reference,
            ),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
        answer
    else {
        panic!("selected Java field type reference must be located");
    };
    assert_eq!(answer.binding().targets(), &[expected]);
}

#[test]
fn selected_java_import_token_provenance_survives_remount() {
    use crate::analyzer::resolution::lower_resolution_facts_for_selection;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportRouteKind;

    let source = "package use; import dep.Target; import decoy.*; import static util.Holder.Target; import static util.Holder.*; class Use { Target field; Other other; }";
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file(JAVA_ROOT_CONSUMER_PATH, source)
        .build();
    let (_, facts) = parsed_operation_state(
        fixture.root(),
        JAVA_ROOT_CONSUMER_PATH,
        source,
        &JavaAdapter,
    );
    let first_fragment = BindingFragmentId::for_test(b"java-import-source");
    let second_fragment = BindingFragmentId::for_test(b"java-import-remount");
    let lowered = lower_resolution_facts_for_selection(
        first_fragment,
        crate::analyzer::resolution::test_shared_names(),
        Language::Java,
        &facts,
    );
    let provenance = &lowered.common().root_import_provenance;
    assert_eq!(
        provenance
            .iter()
            .map(|row| row.kind)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ResolutionImportRouteKind::SingleType,
            ResolutionImportRouteKind::TypeOnDemand,
            ResolutionImportRouteKind::SingleStatic,
            ResolutionImportRouteKind::StaticOnDemand
        ])
    );
    for row in provenance {
        let route = facts
            .import_routes
            .iter()
            .find(|route| route.site == row.source_site)
            .unwrap();
        let site = facts
            .sites
            .iter()
            .find(|site| site.id == row.source_site)
            .unwrap();
        assert_eq!(row.kind, route.kind);
        assert_eq!(
            (row.start_byte, row.end_byte),
            (site.start_byte, site.end_byte)
        );
        assert!(
            lowered.lexical().paths().iter().any(|(_, path)| path
                .end()
                .symbols()
                .fixed()
                .iter()
                .any(|symbol| symbol.symbol() == row.token)),
            "provenance must annotate an actual root import token: {row:?}"
        );
    }
    let remounted = lowered
        .remount(second_fragment, &CancellationToken::new())
        .unwrap();
    let oracle = lower_resolution_facts_for_selection(
        second_fragment,
        crate::analyzer::resolution::test_shared_names(),
        Language::Java,
        &facts,
    );
    assert_eq!(remounted.common(), oracle.common());
    assert_eq!(remounted.lexical(), oracle.lexical());
    assert_eq!(remounted.identities(), oracle.identities());
}

fn assert_java_provider_visibility(fixture: &JavaRootResolutionOperationFixture, visible: bool) {
    assert_java_definition_visibility(
        fixture,
        &fixture.provider_facts,
        &fixture.source_rows[1].rel_path,
        visible,
    );
}

fn assert_java_definition_visibility(
    fixture: &JavaRootResolutionOperationFixture,
    facts: &FileResolutionFacts,
    path: &str,
    visible: bool,
) -> ResolutionCompletion {
    assert_java_named_definition_visibility(
        fixture,
        facts,
        path,
        "Target",
        ResolutionNamespace::Type,
        visible,
    )
}

fn assert_java_named_definition_visibility(
    fixture: &JavaRootResolutionOperationFixture,
    facts: &FileResolutionFacts,
    path: &str,
    name: &str,
    namespace: ResolutionNamespace,
    visible: bool,
) -> ResolutionCompletion {
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let context = fixture.contexts_for(&operation);
    let provider = operation
        .mount_table()
        .mount_for_path("java", path)
        .unwrap()
        .unwrap();
    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        provider.fragment(),
        crate::analyzer::resolution::test_shared_names(),
        Language::Java,
        facts,
    );
    let definition = semantic_at(
        &lowered,
        site_for_identifier(
            facts,
            name,
            ResolutionIdentifierRole::Declaration,
            namespace,
        ),
        LoweredSemanticRole::Definition,
    );
    let reference = try_site_for_identifier(
        &fixture.consumer_facts,
        name,
        ResolutionIdentifierRole::Reference,
        namespace,
    )
    .or_else(|| {
        (namespace == ResolutionNamespace::Value)
            .then(|| {
                try_site_for_identifier(
                    &fixture.consumer_facts,
                    name,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                )
            })
            .flatten()
    })
    .unwrap_or_else(|| panic!("fixture identifier Reference {namespace:?} {name:?}"));
    let answer = operation
        .resolve_reference(
            context,
            &SelectedSemanticLocator::new(
                "java",
                &fixture.consumer_path,
                reference,
                LoweredSemanticRole::Reference,
            ),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
        answer
    else {
        panic!("source-owned Java type reference must remain located");
    };
    assert_eq!(
        answer.binding().targets().contains(&definition),
        visible,
        "{answer:?}"
    );
    answer.completion().clone()
}

#[test]
fn selected_java_known_source_witness_keeps_open_inventory_separate() {
    const POM: &str = "<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version></project>";
    for configuration in [vec![("pom.xml", POM)], Vec::new()] {
        let fixture = JavaRootResolutionOperationFixture::with_layout(
            JAVA_ROOT_SOURCES[0].1,
            [
                "src/main/java/use/Use.java",
                "src/main/java/dep/Target.java",
                "src/main/java/decoy/Target.java",
            ],
            &configuration,
        );
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let context = fixture.contexts_for(&operation);
        assert_ne!(
            context.inventory_completion(),
            &ResolutionCompletion::Complete
        );
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "Target",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        let answer = operation
            .resolve_reference(
                context,
                &SelectedSemanticLocator::new(
                    "java",
                    &fixture.consumer_path,
                    reference,
                    LoweredSemanticRole::Reference,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            answer
        else {
            panic!("source-owned Java reference must remain located");
        };
        let [target] = answer.binding().targets() else {
            panic!("{answer:?}");
        };
        let witnesses = answer
            .binding()
            .witnesses()
            .iter()
            .filter(|witness| witness.target() == *target)
            .collect::<Vec<_>>();
        assert!(!witnesses.is_empty(), "{answer:?}");
        assert!(
            witnesses
                .iter()
                .any(|witness| witness.completion() == &ResolutionCompletion::Complete),
            "a known Java source target is visible through Maven membership or the implicit project: {answer:?}",
        );
    }
}

#[test]
fn selected_java_source_root_access_rejects_only_proven_main_to_test() {
    const POM: &str = "<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version></project>";
    for (caller, provider, visible) in [
        (
            "src/main/java/use/Use.java",
            "src/test/java/dep/Target.java",
            false,
        ),
        (
            "src/test/java/use/Use.java",
            "src/main/java/dep/Target.java",
            true,
        ),
    ] {
        let fixture = JavaRootResolutionOperationFixture::with_layout(
            JAVA_ROOT_SOURCES[0].1,
            [caller, provider, "src/main/java/decoy/Target.java"],
            &[("pom.xml", POM)],
        );
        assert_java_provider_visibility(&fixture, visible);
    }
    let custom = JavaRootResolutionOperationFixture::with_layout(
        JAVA_ROOT_SOURCES[0].1,
        [
            "src/main/java/use/Use.java",
            "src/test/java/dep/Target.java",
            "src/main/java/decoy/Target.java",
        ],
        &[(
            "pom.xml",
            "<project><groupId>example</groupId><artifactId>app</artifactId><build><sourceDirectory>custom</sourceDirectory></build></project>",
        )],
    );
    assert_java_provider_visibility(&custom, true);
    let ambiguous = JavaRootResolutionOperationFixture::with_layout(
        JAVA_ROOT_SOURCES[0].1,
        [
            "src/main/java/use/Use.java",
            "src/main/nested/src/test/java/dep/Target.java",
            "src/main/java/decoy/Target.java",
        ],
        &[("pom.xml", POM), ("src/main/nested/pom.xml", POM)],
    );
    assert_java_provider_visibility(&ambiguous, true);
}

#[test]
fn selected_java_static_import_cannot_borrow_type_import_authority() {
    let fixture = JavaRootResolutionOperationFixture::with_consumer(
        "package use; import static dep.Target; class Use { Target field; }",
    );
    assert_java_provider_visibility(&fixture, false);
}

#[test]
fn selected_java_package_candidates_seek_published_package_index() {
    use crate::analyzer::store::planner_statistics::pinned_plans::{pinned, plan_rows};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    let fixture = JavaRootResolutionOperationFixture::with_layout(
        JAVA_ROOT_SOURCES[0].1,
        [
            "src/main/java/use/Use.java",
            "src/main/java/dep/Target.java",
            "src/main/java/decoy/Target.java",
        ],
        &[(
            "pom.xml",
            "<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version></project>",
        )],
    );
    for statistics in PlannerStatisticsState::BOTH {
        fixture
            .store
            .conn
            .execute(move |connection| statistics.install(connection));
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let rows = plan_rows(
            operation.ready.inventory.connection(),
            &pinned("jvm_native_import_target_mounts"),
        )
        .unwrap();
        assert!(
            rows.iter()
                .any(|row| row.contains("idx_workspace_file_package_rows_name")
                    && row.contains("package_name=?")),
            "{statistics:?}: {rows:?}"
        );
        assert!(
            rows.iter()
                .any(|row| row.contains("SEARCH mounted") && row.contains("file_version_id=?")),
            "{statistics:?}: {rows:?}"
        );
        let connection = operation.ready.inventory.connection();
        let context: i64 = connection
            .query_row("SELECT context_id FROM jvm_context_revisions", [], |row| {
                row.get(0)
            })
            .unwrap();
        let version = |path: &str| {
            connection.query_row(
            "SELECT file_version_id FROM temp.selected_resolution_mounts WHERE storage_language='java' AND persisted_relative_path=?1",
            [path], |row| row.get::<_,i64>(0)).unwrap()
        };
        let mut access_query = pinned("jvm_native_source_access");
        access_query.params = vec![
            rusqlite::types::Value::Integer(context),
            rusqlite::types::Value::Integer(version(&fixture.consumer_path)),
            rusqlite::types::Value::Text(fixture.consumer_path.clone()),
            rusqlite::types::Value::Integer(version(&fixture.source_rows[1].rel_path)),
            rusqlite::types::Value::Text(fixture.source_rows[1].rel_path.clone()),
        ];
        let access_rows = plan_rows(connection, &access_query).unwrap();
        assert!(
            access_rows
                .iter()
                .any(|row| row.contains("idx_jvm_source_root_files_source")),
            "{statistics:?}: {access_rows:?}"
        );
        for forbidden in ["SCAN f", "SCAN m", "AUTOMATIC", "TEMP B-TREE"] {
            assert!(
                !access_rows.iter().any(|row| row.contains(forbidden)),
                "{statistics:?}: {access_rows:?}"
            );
        }
        for forbidden in [
            "SCAN mounted",
            "SCAN package",
            "AUTOMATIC",
            "TEMP B-TREE",
            "CO-ROUTINE",
        ] {
            assert!(
                !rows.iter().any(|row| row.contains(forbidden)),
                "{statistics:?}: {rows:?}"
            );
        }
    }
}

#[test]
fn selected_java_direct_dependency_access_requires_exact_coordinates_and_scope() {
    const TARGET_POM: &str = "<project><groupId>example</groupId><artifactId>provider</artifactId><version>2</version></project>";
    for (role, scope, version, expected) in [
        ("main", "compile", "2", "known"),
        ("main", "provided", "2", "known"),
        ("test", "test", "2", "known"),
        ("main", "test", "2", "unknown"),
        ("main", "compile", "3", "unknown"),
    ] {
        let caller = format!("consumer/src/{role}/java/use/Use.java");
        let consumer_pom = format!(
            "<project><groupId>example</groupId><artifactId>consumer</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>provider</artifactId><version>{version}</version><scope>{scope}</scope><optional>true</optional></dependency></dependencies></project>"
        );
        let fixture = JavaRootResolutionOperationFixture::with_layout(
            JAVA_ROOT_SOURCES[0].1,
            [
                &caller,
                "provider/src/main/java/dep/Target.java",
                "decoy/Target.java",
            ],
            &[
                ("consumer/pom.xml", &consumer_pom),
                ("provider/pom.xml", TARGET_POM),
            ],
        );
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let connection = operation.ready.inventory.connection();
        let context: i64 = connection
            .query_row("SELECT context_id FROM jvm_context_revisions", [], |row| {
                row.get(0)
            })
            .unwrap();
        let file = |path: &str| {
            connection.query_row(
            "SELECT file_version_id FROM temp.selected_resolution_mounts WHERE storage_language='java' AND persisted_relative_path=?1",
            [path], |row| row.get::<_,i64>(0)).unwrap()
        };
        let access: String = connection
            .query_row(
                super::super::jvm_context::SOURCE_ACCESS,
                params![
                    context,
                    file(&caller),
                    caller,
                    file("provider/src/main/java/dep/Target.java"),
                    "provider/src/main/java/dep/Target.java"
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            access, expected,
            "role={role}, scope={scope}, version={version}"
        );
        drop(operation);
        // Unknown classpath membership retains a partial source candidate;
        // this positive direct declaration never certifies a closed classpath.
        assert_java_provider_visibility(&fixture, true);
    }
}

#[test]
fn java_import_context_checks_actual_declaration_visibility() {
    for (consumer, visible) in [
        (
            "package use; import dep.Target; class Use { Target field; }",
            false,
        ),
        (
            "package dep; import dep.Target; class Use { Target field; }",
            true,
        ),
        (
            "package use; import dep.*; class Use { Target field; }",
            false,
        ),
    ] {
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                consumer,
                "package dep; class Target {}",
                JAVA_ROOT_SOURCES[2].1,
            ],
            [
                JAVA_ROOT_CONSUMER_PATH,
                JAVA_ROOT_PROVIDER_PATH,
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        assert_java_provider_visibility(&fixture, visible);
    }
}

#[test]
fn selected_java_same_package_types_preserve_import_precedence() {
    let fields = (0..20)
        .map(|index| format!("Target field{index};"))
        .collect::<Vec<_>>()
        .join(" ");
    for (imports, same_package_wins) in [
        ("", true),
        ("import dep.*;", true),
        ("import dep.Target;", false),
    ] {
        let consumer = format!("package use; {imports} class Use {{ {fields} }}");
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                &consumer,
                "package use; class Target {}",
                "package dep; public class Target {}",
            ],
            [
                JAVA_ROOT_CONSUMER_PATH,
                "src/use/Target.java",
                "src/dep/Target.java",
            ],
            &[],
        );
        assert_java_provider_visibility(&fixture, same_package_wins);
        assert_java_definition_visibility(
            &fixture,
            &fixture.decoy_facts,
            &fixture.source_rows[2].rel_path,
            !same_package_wins,
        );
    }
}

#[test]
fn selected_package_metadata_reads_are_scoped_and_indexed() {
    use super::super::package_context::SelectedPackageRows;
    use crate::analyzer::resolution::SharedNameInterner;
    use crate::analyzer::store::planner_statistics::pinned_plans::{pinned, plan_rows};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    let target_fields = (0..20)
        .map(|index| format!(" Target target{index};"))
        .collect::<String>();
    let mut consumer = format!("package use; class Use {{{target_fields}");
    let mut provider = String::from("package use; class Target {}");
    for index in 0..128 {
        consumer.push_str(&format!(" Name{index} field{index};"));
        provider.push_str(&format!(" class Name{index} {{}}"));
    }
    consumer.push('}');
    let fixture = JavaRootResolutionOperationFixture::with_source_texts(
        [&consumer, &provider, JAVA_ROOT_SOURCES[2].1],
        [
            JAVA_ROOT_CONSUMER_PATH,
            JAVA_ROOT_PROVIDER_PATH,
            JAVA_ROOT_DECOY_PATH,
        ],
        &[],
    );
    for statistics in PlannerStatisticsState::BOTH {
        fixture
            .store
            .conn
            .execute(move |connection| statistics.install(connection));
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let caller = operation
            .mount_table()
            .mount_for_path("java", JAVA_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let target = operation
            .mount_table()
            .mount_for_path("java", JAVA_ROOT_PROVIDER_PATH)
            .unwrap()
            .unwrap();
        let SelectedPackageRows::Ready(references) = operation
            .selected_package_references(caller.ordinal(), &cancellation)
            .unwrap()
        else {
            panic!("not cancelled");
        };
        assert_eq!(references.len(), 148);
        let source = site_for_identifier(
            &fixture.consumer_facts,
            "Target",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        let reference = references
            .iter()
            .find(|reference| reference.source_site == source)
            .unwrap();
        let same_lookup = references
            .iter()
            .filter(|candidate| candidate.lookup == reference.lookup)
            .collect::<Vec<_>>();
        assert_eq!(same_lookup.len(), 20);
        assert!(
            same_lookup
                .iter()
                .all(|candidate| candidate.token == reference.token)
        );
        let SelectedPackageRows::Ready(members) = operation
            .selected_package_members_for_lookup(target.ordinal(), reference.lookup, &cancellation)
            .unwrap()
        else {
            panic!("not cancelled");
        };
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0].source_site,
            site_for_identifier(
                &fixture.provider_facts,
                "Target",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type
            )
        );
        // Populate the stage with the ordinary reader's complete result. The
        // two readers use different coordinate domains and SQL joins; equality
        // is a round-trip law, not a second invocation of one implementation.
        let mut all_members = BTreeSet::new();
        for reference in &references {
            let SelectedPackageRows::Ready(rows) = operation
                .selected_package_members_for_lookup(
                    target.ordinal(),
                    reference.lookup,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("not cancelled");
            };
            all_members.extend(rows);
        }
        use crate::analyzer::store::resolution_stage::codec::{encode_node, encode_semantic};
        operation.ready.inventory.with_owned_temp_write(|connection| {
            for (ordinal, marker) in [(caller.ordinal(), 1_u8), (target.ordinal(), 2_u8)] {
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)", params![ordinal.get(), [marker; 32].as_slice(), [marker; 32].as_slice()])?;
                let producer = connection.last_insert_rowid();
                if ordinal == caller.ordinal() {
                    for row in &references {
                        connection.execute("INSERT INTO temp.selected_resolution_stage_package_references(host_ordinal,producer_id,token_key,domain_shared,reference_key,choice_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![ordinal.get(),producer,encode_semantic(row.token),row.domain.shared_name_id().unwrap().get(),encode_semantic(row.reference),encode_semantic(row.choice.expect("package choice is lowered")),row.source_site.get(),encode_node(row.root_scope),row.namespace.label(),row.lookup.shared_name_id().unwrap().get()])?;
                    }
                } else {
                    for row in &all_members {
                        connection.execute("INSERT INTO temp.selected_resolution_stage_package_members(host_ordinal,producer_id,token_key,domain_shared,definition_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![ordinal.get(),producer,encode_semantic(row.token),row.domain.shared_name_id().unwrap().get(),encode_semantic(row.definition),row.source_site.get(),encode_node(row.root_scope),row.namespace.label(),row.lookup.shared_name_id().unwrap().get()])?;
                    }
                }
            }
            Ok(())
        }).unwrap();
        let SelectedPackageRows::Ready(staged_references) = operation
            .selected_package_references(caller.ordinal(), &cancellation)
            .unwrap()
        else {
            panic!("not cancelled");
        };
        assert_eq!(staged_references, references);
        let SelectedPackageRows::Ready(staged_members) = operation
            .selected_package_members_for_lookup(target.ordinal(), reference.lookup, &cancellation)
            .unwrap()
        else {
            panic!("not cancelled");
        };
        assert_eq!(staged_members, members);
        let stored = operation
            .ready
            .shared_names()
            .to_persisted(reference.lookup.shared_name_id().unwrap())
            .unwrap()
            .get();
        for (name, ordinal, lookup) in [
            ("native_package_references", caller.ordinal(), None),
            ("native_stage_package_references", caller.ordinal(), None),
            ("native_package_members", target.ordinal(), Some(stored)),
            (
                "native_stage_package_members",
                target.ordinal(),
                Some(reference.lookup.shared_name_id().unwrap().get()),
            ),
        ] {
            let mut query = pinned(name);
            query.params = vec![rusqlite::types::Value::Integer(i64::from(ordinal.get()))];
            if let Some(lookup) = lookup {
                query
                    .params
                    .push(rusqlite::types::Value::Integer(i64::from(lookup)));
            }
            let rows = plan_rows(operation.ready.inventory.connection(), &query).unwrap();
            for forbidden in ["SCAN p", "SCAN candidate", "AUTOMATIC", "TEMP B-TREE"] {
                assert!(
                    !rows.iter().any(|row| row.contains(forbidden)),
                    "{name} {statistics:?}: {rows:?}"
                );
            }
        }
        // Changing the staged lookup must suppress the old ordinary name,
        // while retaining the same definition under its new staged name.
        let replacement = references
            .iter()
            .find(|row| row.lookup != reference.lookup)
            .unwrap()
            .lookup;
        operation.ready.inventory.with_owned_temp_write(|connection| {
            connection.execute("UPDATE temp.selected_resolution_stage_package_members SET lookup_shared=?1 WHERE definition_key=?2 AND host_ordinal=?3", params![replacement.shared_name_id().unwrap().get(), encode_semantic(members[0].definition), target.ordinal().get()])?;
            Ok(())
        }).unwrap();
        let SelectedPackageRows::Ready(old_name) = operation
            .selected_package_members_for_lookup(target.ordinal(), reference.lookup, &cancellation)
            .unwrap()
        else {
            panic!("not cancelled");
        };
        assert!(
            old_name.is_empty(),
            "stage rename must withdraw ordinary lookup: {old_name:?}"
        );
        let SelectedPackageRows::Ready(new_name) = operation
            .selected_package_members_for_lookup(target.ordinal(), replacement, &cancellation)
            .unwrap()
        else {
            panic!("not cancelled");
        };
        assert!(
            new_name
                .iter()
                .any(|row| row.definition == members[0].definition)
        );
        cancellation.cancel();
        assert!(matches!(
            operation
                .selected_package_references(caller.ordinal(), &cancellation)
                .unwrap(),
            SelectedPackageRows::Cancelled
        ));
        assert!(matches!(
            operation
                .selected_package_members_for_lookup(
                    target.ordinal(),
                    reference.lookup,
                    &cancellation
                )
                .unwrap(),
            SelectedPackageRows::Cancelled
        ));
    }
}

#[test]
fn selected_java_missing_explicit_import_does_not_fall_through_to_package_peer() {
    let fixture = JavaRootResolutionOperationFixture::with_source_texts(
        [
            "package use; import missing.Target; class Use { Target field; }",
            "package use; class Target {}",
            JAVA_ROOT_SOURCES[2].1,
        ],
        [
            JAVA_ROOT_CONSUMER_PATH,
            JAVA_ROOT_PROVIDER_PATH,
            JAVA_ROOT_DECOY_PATH,
        ],
        &[],
    );
    assert_java_provider_visibility(&fixture, false);
    assert_java_definition_visibility(
        &fixture,
        &fixture.decoy_facts,
        &fixture.source_rows[2].rel_path,
        false,
    );
}

#[test]
fn selected_java_nested_type_imports_follow_owner_chains_and_visibility() {
    for (consumer, provider, visible) in [
        (
            "package use; import dep.Outer.Target; class Use { Target field; }",
            "package dep; public class Outer { public static class Target {} }",
            true,
        ),
        (
            "package use; import dep.Outer.*; class Use { Target field; }",
            "package dep; public class Outer { public class Target {} }",
            true,
        ),
        (
            "package use; import dep.Outer.Inner.Target; class Use { Target field; }",
            "package dep; public class Outer { public static class Inner { public static class Target {} } }",
            true,
        ),
        (
            "package use; import dep.Wrong.Target; class Use { Target field; }",
            "package dep; public class Outer { public static class Target {} }",
            false,
        ),
        (
            "package use; import dep.Outer.Target; class Use { Target field; }",
            "package dep; public class Outer { private static class Target {} }",
            false,
        ),
        (
            "package use; import dep.Outer.Target; class Use { Target field; }",
            "package dep; class Outer { public static class Target {} }",
            false,
        ),
        (
            "package use; import dep.Outer.Inner.Target; class Use { Target field; }",
            "package dep; public class Outer { private static class Inner { public static class Target {} } }",
            false,
        ),
    ] {
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [consumer, provider, JAVA_ROOT_SOURCES[2].1],
            [
                JAVA_ROOT_CONSUMER_PATH,
                "src/dep/Outer.java",
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        assert_java_provider_visibility(&fixture, visible);
    }
}

#[test]
fn selected_java_static_imports_require_static_access_and_preserve_namespace() {
    for (consumer, provider, namespace, visible) in [
        (
            "package use; import static dep.Outer.Target; class Use { int field = Target; }",
            "package dep; public class Outer { public static int Target; }",
            ResolutionNamespace::Value,
            true,
        ),
        (
            "package use; import static dep.Outer.*; class Use { int field = Target; }",
            "package dep; public class Outer { public static int Target; }",
            ResolutionNamespace::Value,
            true,
        ),
        (
            "package use; import static dep.Outer.Target; class Use { int field = Target; }",
            "package dep; public class Outer { public int Target; }",
            ResolutionNamespace::Value,
            false,
        ),
        (
            "package use; import static dep.Outer.Target; class Use { int field = Target; }",
            "package dep; public class Outer { private static int Target; }",
            ResolutionNamespace::Value,
            false,
        ),
        (
            "package use; import static dep.Outer.Target; class Use { int field = Target(); }",
            "package dep; public class Outer { public static int Target() { return 1; } }",
            ResolutionNamespace::Callable,
            true,
        ),
        (
            "package use; import static dep.Outer.*; class Use { int field = Target(); }",
            "package dep; public class Outer { public static int Target() { return 1; } }",
            ResolutionNamespace::Callable,
            true,
        ),
        (
            "package use; import static dep.Outer.Target; class Use { int field = Target(); }",
            "package dep; public class Outer { public int Target() { return 1; } }",
            ResolutionNamespace::Callable,
            false,
        ),
        (
            "package use; import static dep.Outer.Target; class Use { Target field; }",
            "package dep; public class Outer { public static class Target {} }",
            ResolutionNamespace::Type,
            true,
        ),
        (
            "package use; import static dep.Outer.Target; class Use { Target field; }",
            "package dep; public class Outer { public class Target {} }",
            ResolutionNamespace::Type,
            false,
        ),
    ] {
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [consumer, provider, JAVA_ROOT_SOURCES[2].1],
            [
                JAVA_ROOT_CONSUMER_PATH,
                "src/dep/Outer.java",
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        assert_java_named_definition_visibility(
            &fixture,
            &fixture.provider_facts,
            &fixture.source_rows[1].rel_path,
            "Target",
            namespace,
            visible,
        );
    }
}

#[test]
fn selected_java_static_type_import_precedence_preserves_value_namespace() {
    for (consumer, provider, imported_type) in [
        (
            "package use; import static dep.Outer.Target; class Use { Target field; }",
            "package dep; public class Outer { public static class Target {} }",
            true,
        ),
        (
            "package use; import static dep.Outer.*; class Use { Target field; }",
            "package dep; public class Outer { public static class Target {} }",
            false,
        ),
    ] {
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [consumer, provider, "package use; public class Target {}"],
            [
                JAVA_ROOT_CONSUMER_PATH,
                "src/dep/Outer.java",
                "src/use/Target.java",
            ],
            &[],
        );
        assert_java_provider_visibility(&fixture, imported_type);
        assert_java_definition_visibility(
            &fixture,
            &fixture.decoy_facts,
            "src/use/Target.java",
            !imported_type,
        );
    }
    let fixture = JavaRootResolutionOperationFixture::with_source_texts(
        [
            "package use; import static dep.Outer.Target; class Use { Target field; int value = Target; }",
            "package dep; public class Outer { public static int Target; }",
            "package use; public class Target {}",
        ],
        [
            JAVA_ROOT_CONSUMER_PATH,
            "src/dep/Outer.java",
            "src/use/Target.java",
        ],
        &[],
    );
    assert_java_definition_visibility(&fixture, &fixture.decoy_facts, "src/use/Target.java", true);
    assert_java_named_definition_visibility(
        &fixture,
        &fixture.provider_facts,
        "src/dep/Outer.java",
        "Target",
        ResolutionNamespace::Value,
        true,
    );
}

#[test]
fn selected_java_import_access_rejects_protected_members_across_packages() {
    for (declaration, use_body, namespace) in [
        (
            "protected static class Target {}",
            "Target field;",
            ResolutionNamespace::Type,
        ),
        (
            "protected static int Target;",
            "int field = Target;",
            ResolutionNamespace::Value,
        ),
        (
            "protected static int Target() { return 1; }",
            "int field = Target();",
            ResolutionNamespace::Callable,
        ),
    ] {
        for package in ["use", "dep"] {
            let consumer = format!(
                "package {package}; import static dep.Outer.Target; class Use {{ {use_body} }}"
            );
            let provider = format!("package dep; public class Outer {{ {declaration} }}");
            let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                [&consumer, &provider, JAVA_ROOT_SOURCES[2].1],
                [
                    JAVA_ROOT_CONSUMER_PATH,
                    "src/dep/Outer.java",
                    JAVA_ROOT_DECOY_PATH,
                ],
                &[],
            );
            assert_java_named_definition_visibility(
                &fixture,
                &fixture.provider_facts,
                "src/dep/Outer.java",
                "Target",
                namespace,
                package == "dep",
            );
        }
    }
}

#[test]
fn selected_java_reverse_confirms_an_imported_scala_reference() {
    use crate::analyzer::scala::ScalaAdapter;

    let project_root = tempfile::tempdir().unwrap();
    let store = AnalyzerStore::open_persistent(&project_root.path().join("store.db")).unwrap();
    let project = MutableGenerationProject::new(project_root.path(), Language::Java);
    let workspace_id =
        WorkspaceId("8585858585858585858585858585858585858585858585858585858585858585".to_owned());
    let java_path = "src/main/java/model/Visible.java";
    let java_source = "package model; public class Visible {}\n";
    let scala_path = "src/main/scala/client/Use.scala";
    let scala_source =
        "package client\nimport model.Visible\nclass Use { val value: Visible = new Visible() }\n";
    let (java_state, _) =
        super::parsed_operation_state(project_root.path(), java_path, java_source, &JavaAdapter);
    let (scala_state, scala_facts) =
        super::parsed_operation_state(project_root.path(), scala_path, scala_source, &ScalaAdapter);
    let java_generation = store
        .ensure_language_epoch_value("java", "selected-jvm-reverse-context-v1")
        .unwrap();
    let scala_generation = store
        .ensure_language_epoch_value("scala", "selected-jvm-reverse-context-v1")
        .unwrap();
    store
        .ensure_resolution_producer_epoch("java", Language::Java)
        .unwrap();
    store
        .ensure_resolution_producer_epoch("scala", Language::Scala)
        .unwrap();
    let java_oid = Oid::hash_object(ObjectType::Blob, java_source.as_bytes()).unwrap();
    let scala_oid = Oid::hash_object(ObjectType::Blob, scala_source.as_bytes()).unwrap();
    let prepared = vec![
        AnalyzerStore::prepare_parsed_blob(
            java_oid,
            "java",
            java_generation,
            &JavaAdapter,
            java_state.clone(),
        )
        .unwrap(),
        AnalyzerStore::prepare_parsed_blob(
            scala_oid,
            "scala",
            scala_generation,
            &ScalaAdapter,
            scala_state.clone(),
        )
        .unwrap(),
    ];
    let (outcomes, _) = store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
    assert!(
        outcomes.iter().all(|outcome| outcome.error.is_none()),
        "{outcomes:?}"
    );
    let configuration = [WorkspaceConfigurationInput::new(
        "pom.xml".to_owned(),
        b"<project><groupId>test</groupId><artifactId>mixed-jvm</artifactId><version>1</version></project>"
            .to_vec()
            .into_boxed_slice(),
    )];
    let java_snapshot = store
        .sync_workspace_inputs_for_workspace(
            &workspace_id,
            "java",
            java_generation,
            &[WorkspaceFileRow {
                rel_path: java_path.to_owned(),
                blob_oid: java_oid,
            }],
            &[],
            &[],
            &[WorkspacePackageFileRow {
                package_name: java_state.package_name.clone(),
                rel_path: java_path.to_owned(),
            }],
            &[],
            &[],
            &configuration,
            &[],
        )
        .unwrap();
    let scala_snapshot = store
        .sync_workspace_inputs_for_workspace(
            &workspace_id,
            "scala",
            scala_generation,
            &[WorkspaceFileRow {
                rel_path: scala_path.to_owned(),
                blob_oid: scala_oid,
            }],
            &[],
            &[],
            &[WorkspacePackageFileRow {
                package_name: scala_state.package_name.clone(),
                rel_path: scala_path.to_owned(),
            }],
            &[],
            &[],
            &configuration,
            &[],
        )
        .unwrap();
    let mut snapshots = WorkspaceSnapshots::default();
    snapshots.insert("java".to_owned(), java_snapshot);
    snapshots.insert("scala".to_owned(), scala_snapshot);
    store.reconcile_jvm_package_contexts(&snapshots).unwrap();
    let languages = vec![
        SelectedResolutionLanguage::new("java", Language::Java),
        SelectedResolutionLanguage::new("scala", Language::Scala),
    ];
    let cancellation = CancellationToken::new();
    let operation = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                &project,
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            ),
            &cancellation,
        )
        .unwrap();
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = operation else {
        panic!("complete Java/Scala selection must open Ready");
    };
    let target = java_state
        .declarations
        .iter()
        .find(|unit| unit.short_name() == "Visible")
        .cloned()
        .expect("Java target declaration");
    let reference_site = scala_facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Type
                && scala_facts.names[identifier.name.index()].spelling == "Visible"
        })
        .max_by_key(|identifier| scala_facts.sites[identifier.site.index()].start_byte)
        .expect("Scala usage reference")
        .site;
    let candidates = operation
        .jvm_reverse_candidate_sites(&target, &cancellation)
        .unwrap();
    let JvmReverseCandidateOutcome::Ready(candidates) = candidates else {
        panic!("selected JVM candidate inventory must be ready");
    };
    assert!(
        candidates.candidates.iter().any(|candidate| {
            candidate.locator.storage_language() == "scala"
                && candidate.locator.relative_path() == scala_path
                && candidate.locator.source_site() == Some(reference_site)
        }),
        "the Scala usage reference must enter the shared JVM candidate set: {candidates:#?}"
    );
    let confirmed = operation
        .confirm_jvm_reverse_candidates(
            candidates,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(confirmed) = confirmed else {
        panic!("selected JVM confirmation must produce a native result");
    };
    let scala_bindings = confirmed
        .references
        .iter()
        .filter(|reference| {
            reference.locator.storage_language() == "scala"
                && reference.locator.relative_path() == scala_path
        })
        .map(|reference| {
            (
                reference.locator.source_site(),
                reference.answer.binding().targets().to_vec(),
                reference.answer.binding().completion().clone(),
                reference.answer.reference_owner(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        scala_bindings
            .iter()
            .any(|(_, targets, _, _)| targets.contains(&confirmed.target)),
        "the Scala file's own language context must confirm Java target {:?}: {scala_bindings:#?}",
        confirmed.target
    );
}

fn selected_java_reverse_for_qualified_peer_reference<A: LanguageAdapter>(
    peer_language: Language,
    peer_storage_language: &str,
    peer_path: &str,
    peer_source: &str,
    adapter: &A,
) -> (JvmReverseConfirmed, ResolutionSiteId) {
    let project_root = tempfile::tempdir().unwrap();
    let store = AnalyzerStore::open_persistent(&project_root.path().join("store.db")).unwrap();
    let project = MutableGenerationProject::new(project_root.path(), Language::Java);
    let workspace_id =
        WorkspaceId("8585858585858585858585858585858585858585858585858585858585858585".to_owned());
    let java_path = "src/main/java/model/Visible.java";
    let java_source = "package model; public class Visible {}\n";
    let (java_state, _) =
        super::parsed_operation_state(project_root.path(), java_path, java_source, &JavaAdapter);
    let (peer_state, peer_facts) =
        super::parsed_operation_state(project_root.path(), peer_path, peer_source, adapter);
    let reference_site = site_for_identifier(
        &peer_facts,
        "Visible",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let java_generation = store
        .ensure_language_epoch_value("java", "selected-jvm-reverse-context-v1")
        .unwrap();
    let peer_generation = store
        .ensure_language_epoch_value(peer_storage_language, "selected-jvm-reverse-context-v1")
        .unwrap();
    store
        .ensure_resolution_producer_epoch("java", Language::Java)
        .unwrap();
    store
        .ensure_resolution_producer_epoch(peer_storage_language, peer_language)
        .unwrap();
    let java_oid = Oid::hash_object(ObjectType::Blob, java_source.as_bytes()).unwrap();
    let peer_oid = Oid::hash_object(ObjectType::Blob, peer_source.as_bytes()).unwrap();
    let prepared = vec![
        AnalyzerStore::prepare_parsed_blob(
            java_oid,
            "java",
            java_generation,
            &JavaAdapter,
            java_state.clone(),
        )
        .unwrap(),
        AnalyzerStore::prepare_parsed_blob(
            peer_oid,
            peer_storage_language,
            peer_generation,
            adapter,
            peer_state.clone(),
        )
        .unwrap(),
    ];
    let (outcomes, _) = store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
    assert!(
        outcomes.iter().all(|outcome| outcome.error.is_none()),
        "{outcomes:?}"
    );
    let configuration = [WorkspaceConfigurationInput::new(
        "pom.xml".to_owned(),
        b"<project><groupId>test</groupId><artifactId>mixed-jvm</artifactId><version>1</version></project>"
            .to_vec()
            .into_boxed_slice(),
    )];
    let java_snapshot = store
        .sync_workspace_inputs_for_workspace(
            &workspace_id,
            "java",
            java_generation,
            &[WorkspaceFileRow {
                rel_path: java_path.to_owned(),
                blob_oid: java_oid,
            }],
            &[],
            &[],
            &[WorkspacePackageFileRow {
                package_name: java_state.package_name.clone(),
                rel_path: java_path.to_owned(),
            }],
            &[],
            &[],
            &configuration,
            &[],
        )
        .unwrap();
    let peer_snapshot = store
        .sync_workspace_inputs_for_workspace(
            &workspace_id,
            peer_storage_language,
            peer_generation,
            &[WorkspaceFileRow {
                rel_path: peer_path.to_owned(),
                blob_oid: peer_oid,
            }],
            &[],
            &[],
            &[WorkspacePackageFileRow {
                package_name: peer_state.package_name.clone(),
                rel_path: peer_path.to_owned(),
            }],
            &[],
            &[],
            &configuration,
            &[],
        )
        .unwrap();
    let mut snapshots = WorkspaceSnapshots::default();
    snapshots.insert("java".to_owned(), java_snapshot);
    snapshots.insert(peer_storage_language.to_owned(), peer_snapshot);
    store.reconcile_jvm_package_contexts(&snapshots).unwrap();
    let languages = vec![
        SelectedResolutionLanguage::new("java", Language::Java),
        SelectedResolutionLanguage::new(peer_storage_language, peer_language),
    ];
    let cancellation = CancellationToken::new();
    let operation = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                &project,
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            ),
            &cancellation,
        )
        .unwrap();
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = operation else {
        panic!("complete Java/peer selection must open Ready");
    };
    let target = java_state
        .declarations
        .iter()
        .find(|unit| unit.short_name() == "Visible")
        .cloned()
        .expect("Java target declaration");
    let candidates = operation
        .jvm_reverse_candidate_sites(&target, &cancellation)
        .unwrap();
    let JvmReverseCandidateOutcome::Ready(candidates) = candidates else {
        panic!("selected JVM candidate inventory must be ready");
    };
    assert!(
        candidates.candidates.iter().any(|candidate| {
            candidate.locator.storage_language() == peer_storage_language
                && candidate.locator.relative_path() == peer_path
                && candidate.locator.source_site() == Some(reference_site)
        }),
        "the qualified peer reference must enter the shared JVM candidate set: {candidates:#?}"
    );
    let confirmed = operation
        .confirm_jvm_reverse_candidates(
            candidates,
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(confirmed) = confirmed else {
        panic!("selected JVM confirmation must produce a native result");
    };
    (confirmed, reference_site)
}

#[test]
fn selected_java_reverse_confirms_a_qualified_scala_reference() {
    use crate::analyzer::scala::ScalaAdapter;

    let (confirmed, reference_site) = selected_java_reverse_for_qualified_peer_reference(
        Language::Scala,
        "scala",
        "src/main/scala/client/Use.scala",
        "package client\nclass Use { val value: model.Visible = new model.Visible() }\n",
        &ScalaAdapter,
    );
    assert!(
        confirmed.peer_language_inventory_open,
        "selected Scala sources keep Java reverse enumeration incomplete even when a qualified site is omitted"
    );
    let binding = confirmed
        .references
        .iter()
        .find(|reference| {
            reference.locator.storage_language() == "scala"
                && reference.locator.source_site() == Some(reference_site)
        })
        .expect("qualified Scala reference remains in reverse confirmation");
    assert!(
        binding
            .answer
            .binding()
            .targets()
            .contains(&confirmed.target),
        "the selected package row and type export must confirm the Java type: {:?}",
        binding.answer.binding()
    );
}

#[test]
fn selected_java_reverse_confirms_a_qualified_kotlin_reference() {
    use crate::analyzer::kotlin::KotlinAdapter;

    let (confirmed, reference_site) = selected_java_reverse_for_qualified_peer_reference(
        Language::Kotlin,
        "kotlin",
        "src/main/kotlin/client/Use.kt",
        "package client\nclass Use { val value: model.Visible = model.Visible() }\n",
        &KotlinAdapter,
    );
    let binding = confirmed
        .references
        .iter()
        .find(|reference| {
            reference.locator.storage_language() == "kotlin"
                && reference.locator.source_site() == Some(reference_site)
        })
        .expect("qualified Kotlin reference remains in reverse confirmation");
    assert!(
        binding
            .answer
            .binding()
            .targets()
            .contains(&confirmed.target),
        "the selected package row and type export must confirm the Java type: {:?}",
        binding.answer.binding()
    );
}

#[test]
fn selected_java_reverse_keeps_an_omitted_qualified_scala_site_incomplete() {
    use crate::analyzer::scala::ScalaAdapter;

    let (confirmed, reference_site) = selected_java_reverse_for_qualified_peer_reference(
        Language::Scala,
        "scala",
        "src/main/scala/client/Use.scala",
        "package client\nclass Use { val missing: absent.Visible = null }\n",
        &ScalaAdapter,
    );
    assert!(
        confirmed.peer_language_inventory_open,
        "an omitted qualified Scala site must keep Java reverse enumeration incomplete"
    );
    let confirmed_reference_targets = confirmed
        .references
        .iter()
        .map(|reference| (&reference.locator, reference.answer.binding().targets()))
        .collect::<Vec<_>>();
    assert!(
        confirmed.references.iter().all(|reference| {
            reference.locator.storage_language() != "scala"
                || reference.locator.source_site() != Some(reference_site)
                || !reference
                    .answer
                    .binding()
                    .targets()
                    .contains(&confirmed.target)
        }),
        "absent package evidence must not bind by spelling: {:#?}",
        confirmed_reference_targets
    );
}

#[test]
fn selected_java_inheritance_metadata_uses_indexed_source_rows_and_honors_cancellation() {
    use super::super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
    use crate::analyzer::resolution::JavaInheritanceDeclarationKind;
    use crate::analyzer::structural::resolution::DeclaredVisibility;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    let mut source = String::from("package use; class Use {");
    for ordinal in 0..513 {
        source.push_str(&format!("public void method{ordinal}() {{}}\n"));
    }
    source.push('}');
    for statistics in PlannerStatisticsState::BOTH {
        let fixture = JavaRootResolutionOperationFixture::with_consumer(&source);
        fixture
            .store
            .conn
            .execute(move |connection| statistics.install(connection));
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let mount = operation
            .mount_table()
            .mount_for_path("java", JAVA_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            mount.fragment(),
            &operation.ready.shared_names(),
            Language::Java,
            &fixture.consumer_facts,
        );
        let definitions = lowered
            .lexical()
            .semantics()
            .iter()
            .filter(|row| row.role() == LoweredSemanticRole::Definition)
            .map(|row| row.semantic())
            .collect::<Vec<_>>();
        assert_eq!(definitions.len(), 515);
        let typed = operation.ready.typed_source();
        for count in [1, 256, 515] {
            let rows = typed
                .java_inheritance_declarations(&definitions[..count], &cancellation)
                .unwrap()
                .expect("live selected metadata");
            assert_eq!(rows.len(), count);
            for row in &rows {
                assert_eq!(row.package.as_deref(), Some("use"));
                match row.kind {
                    JavaInheritanceDeclarationKind::Type { is_interface, .. } => {
                        assert!(!is_interface)
                    }
                    JavaInheritanceDeclarationKind::Method {
                        is_abstract,
                        is_static,
                        visibility,
                    } => {
                        assert_eq!(is_abstract, Some(false));
                        assert!(!is_static);
                        assert_eq!(visibility, DeclaredVisibility::Public);
                    }
                }
            }
            let endpoints = typed
                .java_access_endpoints(&definitions[..count], &cancellation)
                .unwrap()
                .expect("live Java access metadata");
            assert_eq!(endpoints.len(), count);
            let roots = endpoints
                .iter()
                .map(|row| {
                    assert_eq!(row.package.as_deref(), Some("use"));
                    row.outermost_type
                        .expect("method and type share an outer type")
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(roots.len(), 1);
            let access_plan = explain_pin(
                operation.ready.inventory.connection(),
                &pinned("java_access_endpoints"),
            );
            for alias in [
                "mount", "interior", "site", "semantic", "meta", "parent", "scope",
            ] {
                assert!(
                    access_plan
                        .iter()
                        .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                    "Java access must seek {alias} with {statistics}: {access_plan:#?}"
                );
            }
            let plan = explain_pin(
                operation.ready.inventory.connection(),
                &pinned("java_inheritance_declarations"),
            );
            for alias in [
                "mount", "interior", "source", "semantic", "bridge", "link", "units", "meta",
            ] {
                assert!(
                    plan.iter()
                        .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                    "selected metadata must seek {alias} with {statistics}: {plan:#?}"
                );
            }
            let synthetic_plan = explain_pin(
                operation.ready.inventory.connection(),
                &pinned("java_synthetic_type_bodies"),
            );
            for alias in [
                "mount", "interior", "semantic", "scope", "source", "meta", "bridge",
            ] {
                assert!(
                    synthetic_plan
                        .iter()
                        .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                    "synthetic Java type bodies must seek {alias} with {statistics}: {synthetic_plan:#?}"
                );
            }
            assert!(
                synthetic_plan
                    .iter()
                    .all(|detail| !detail.contains("AUTOMATIC")
                        && !detail.contains("TEMP B-TREE")
                        && !detail.contains("CO-ROUTINE")
                        && (!detail.starts_with("SCAN ") || detail == "SCAN request")),
                "{statistics}: {synthetic_plan:#?}"
            );
            // The canonical metadata view checks agreement of source
            // visibility values for one indexed unit. Its DISTINCT set is
            // bounded by the visibility enum; it does not sort workspace rows.
            assert!(
                plan.iter().all(|detail| !detail.contains("AUTOMATIC")
                    && (!detail.contains("TEMP B-TREE")
                        || detail == "USE TEMP B-TREE FOR count(DISTINCT)")
                    && !detail.contains("CO-ROUTINE")
                    && (!detail.starts_with("SCAN ") || detail == "SCAN request")),
                "{statistics}: {plan:#?}"
            );
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            typed
                .java_inheritance_declarations(&definitions, &cancelled)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            typed
                .java_inheritance_declarations(&definitions, &cancellation)
                .unwrap()
                .unwrap()
                .len(),
            515
        );
    }
}
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "2954b247d759: a reference that sits in no declaration is stored with owner -1, which the JVM access endpoint read rejected as an out-of-range integer (Scala precedence census G4)"
)]
fn selected_jvm_access_endpoints_read_a_reference_that_sits_in_no_declaration() {
    let fixture = JavaRootResolutionOperationFixture::new();
    // `resolution_sites.owner` is -1 for a reference in no declaration. Scala
    // stores that for an import selector; no Java construct produces it, so
    // the stored row is set directly.
    fixture.store.conn.execute(|connection| {
        connection
            .execute("UPDATE resolution_sites SET owner=-1 WHERE role=0", [])
            .unwrap()
    });
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mount = operation
        .mount_table()
        .mount_for_path("java", JAVA_ROOT_CONSUMER_PATH)
        .unwrap()
        .unwrap();
    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        mount.fragment(),
        &operation.ready.shared_names(),
        Language::Java,
        &fixture.consumer_facts,
    );
    let references = lowered
        .lexical()
        .semantics()
        .iter()
        .filter(|row| row.role() == LoweredSemanticRole::Reference)
        .map(|row| row.semantic())
        .collect::<Vec<_>>();
    assert!(!references.is_empty());
    let endpoints = operation
        .ready
        .typed_source()
        .jvm_access_endpoints(&references, &cancellation)
        .unwrap()
        .expect("live JVM access metadata");
    assert_eq!(endpoints.len(), references.len());
    for endpoint in endpoints {
        assert_eq!(endpoint.enclosing_templates, Vec::new(), "{endpoint:?}");
        assert_eq!(endpoint.outermost_type, None, "{endpoint:?}");
    }
}

#[test]
fn selected_java_same_package_access_keeps_exact_main_test_direction() {
    let pom =
        "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>";
    for (consumer_path, provider_path, visible) in [
        (
            "src/main/java/use/Use.java",
            "src/test/java/use/Target.java",
            false,
        ),
        (
            "src/test/java/use/Use.java",
            "src/main/java/use/Target.java",
            true,
        ),
    ] {
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "package use; class Use { Target field; }",
                "package use; class Target {}",
                JAVA_ROOT_SOURCES[2].1,
            ],
            [consumer_path, provider_path, JAVA_ROOT_DECOY_PATH],
            &[("pom.xml", pom)],
        );
        assert_java_provider_visibility(&fixture, visible);
    }
}

#[test]
fn selected_java_same_package_parity_reopens_and_keeps_lexical_shadowing() {
    let fixture = JavaRootResolutionOperationFixture::with_source_texts(
        [
            "package use; class Use { Target field; }",
            "package use; class Target {}",
            JAVA_ROOT_SOURCES[2].1,
        ],
        [
            JAVA_ROOT_CONSUMER_PATH,
            JAVA_ROOT_PROVIDER_PATH,
            JAVA_ROOT_DECOY_PATH,
        ],
        &[],
    );
    assert_java_root_parity(&fixture);
    assert_java_root_parity(&fixture.reopen());
    let fixture = JavaRootResolutionOperationFixture::with_source_texts(
        [
            "package use; class Use { class Target {} Target field; }",
            "package use; class Target {}",
            JAVA_ROOT_SOURCES[2].1,
        ],
        [
            JAVA_ROOT_CONSUMER_PATH,
            JAVA_ROOT_PROVIDER_PATH,
            JAVA_ROOT_DECOY_PATH,
        ],
        &[],
    );
    assert_java_provider_visibility(&fixture, false);
    assert_eq!(
        assert_java_definition_visibility(
            &fixture,
            &fixture.consumer_facts,
            &fixture.consumer_path,
            true,
        ),
        ResolutionCompletion::Complete,
        "lexical nested type plus proven same-package access closes this lookup"
    );
    let default = JavaRootResolutionOperationFixture::with_source_texts(
        [
            "class Use { Target field; }",
            "class Target {}",
            JAVA_ROOT_SOURCES[2].1,
        ],
        [
            JAVA_ROOT_CONSUMER_PATH,
            JAVA_ROOT_PROVIDER_PATH,
            JAVA_ROOT_DECOY_PATH,
        ],
        &[],
    );
    assert_java_provider_visibility(&default, true);
}
