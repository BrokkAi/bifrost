#[cfg(test)]
pub(crate) mod jvm_extraction_tests {

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    use brokk_bifrost_analysis::analyzer::store_bridge::parsed_blob::AnalyzerStoreEngineExt;

    use std::sync::Arc;

    use std::collections::BTreeSet;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::JAVA_ROOT_CONSUMER_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::JAVA_ROOT_PROVIDER_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::JAVA_ROOT_SOURCES;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use crate::engine_tests::jvm_adapter_more_analyzer_store_resolution_operation_java_tests_root::jvm_extraction_tests::JavaRootResolutionOperationFixture;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::MutableGenerationProject as MutableGenerationProject;

    use git2::ObjectType;

    use git2::Oid;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

    use brokk_bifrost_analysis::analyzer::store::workspace_inputs::WorkspaceConfigurationInput;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

    use brokk_bifrost_analysis::analyzer::resolution::engine::cancelled_completion;

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state as parsed_operation_state;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::site_for_identifier as site_for_identifier;

    use brokk_bifrost_analysis::analyzer::store::WorkspacePackageFileRow;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_reverse_rows::JvmReverseCandidateOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_reverse_rows::JvmReverseConfirmed;

    #[test]
    fn selected_java_import_token_provenance_survives_remount() {
        use brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection;
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
            brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
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
            brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            Language::Java,
            &facts,
        );
        assert_eq!(remounted.common(), oracle.common());
        assert_eq!(remounted.lexical(), oracle.lexical());
        assert_eq!(remounted.identities(), oracle.identities());
    }
    #[test]
    fn selected_java_reverse_confirms_an_imported_scala_reference() {
        use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

        let project_root = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_persistent(&project_root.path().join("store.db")).unwrap();
        let project = MutableGenerationProject::new(project_root.path(), Language::Java);
        let workspace_id = WorkspaceId(
            "8585858585858585858585858585858585858585858585858585858585858585".to_owned(),
        );
        let java_path = "src/main/java/model/Visible.java";
        let java_source = "package model; public class Visible {}\n";
        let scala_path = "src/main/scala/client/Use.scala";
        let scala_source = "package client\nimport model.Visible\nclass Use { val value: Visible = new Visible() }\n";
        let (java_state, _) =
        brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state(project_root.path(), java_path, java_source, &JavaAdapter);
        let (scala_state, scala_facts) =
        brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state(project_root.path(), scala_path, scala_source, &ScalaAdapter);
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
        let before_nomination = operation.ready.inventory.read_change_stamp().unwrap();
        let candidates = operation
            .jvm_reverse_candidate_sites(&target, &cancellation)
            .unwrap();
        assert_eq!(
            operation.ready.inventory.read_change_stamp().unwrap(),
            before_nomination,
            "private reverse request keys must not invalidate selected authority",
        );
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
    #[test]
    fn selected_java_reverse_confirms_a_qualified_scala_reference() {
        use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

        let (confirmed, reference_site) = selected_java_reverse_for_qualified_peer_reference(
            Language::Scala,
            "scala",
            "src/main/scala/client/Use.scala",
            "package client\nclass Use { val value: model.Visible = new model.Visible() }\n",
            &ScalaAdapter,
            |_| {},
            |_, _| {},
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
        use brokk_bifrost_jvm_analysis::analyzer::kotlin::adapter::KotlinAdapter;

        let (confirmed, reference_site) = selected_java_reverse_for_qualified_peer_reference(
            Language::Kotlin,
            "kotlin",
            "src/main/kotlin/client/Use.kt",
            "package client\nclass Use { val value: model.Visible = model.Visible() }\n",
            &KotlinAdapter,
            |_| {},
            |_, _| {},
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
    #[hardwon("#5796: incomplete caller inventory lost its target-level evidence obligation")]
    fn selected_java_reverse_keeps_an_omitted_qualified_scala_site_incomplete() {
        use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

        let (confirmed, reference_site) = selected_java_reverse_for_qualified_peer_reference(
            Language::Scala,
            "scala",
            "src/main/scala/client/Use.scala",
            "package client\nclass Use { val missing: absent.Visible = null }\n",
            &ScalaAdapter,
            |_| {},
            |_, _| {},
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
    fn selected_java_reverse_missing_scala_package_object_is_an_error() {
        let (confirmed, site) = selected_java_reverse_for_qualified_peer_reference(
            Language::Scala,
            "scala",
            "src/main/scala/client/package.scala",
            "package object client { val value: model.Visible = new model.Visible() }\n",
            &brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter,
            |state| {
                assert!(!state.source_declaration_units.is_empty());
                state.source_declaration_metadata.clear();
                state.source_declaration_units.clear();
            },
            |_, _| {},
        );
        let reference = confirmed
            .references
            .into_iter()
            .find(|reference| {
                reference.locator.storage_language() == "scala"
                    && reference.locator.source_site() == Some(site)
            })
            .expect("the semantic reference survives missing native owner rows");
        assert!(
            reference
                .answer
                .binding()
                .targets()
                .contains(&confirmed.target)
        );
        assert!(matches!(
        reference.owner,
        brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseEnclosingUnit::MissingSource
    ));
        assert!(reference.owner.into_unit().is_err());
    }
    #[test]
    fn selected_java_reverse_keeps_a_known_absent_owner() {
        let (confirmed, site) = selected_java_reverse_for_qualified_peer_reference(
            Language::Scala,
            "scala",
            "src/main/scala/client/Use.scala",
            "package client\nclass Use { val value: model.Visible = new model.Visible() }\n",
            &brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter,
            |_| {},
            |store, oid| {
                let oid = oid.to_owned();
                store.conn.execute(move |connection| {
                connection.execute(
                    "UPDATE resolution_sites SET owner=-1 WHERE role=0 AND blob_id IN (SELECT id FROM blobs WHERE blob_oid=?1)",
                    [oid],
                )
            }).unwrap();
            },
        );
        let reference = confirmed
            .references
            .into_iter()
            .find(|reference| {
                reference.locator.storage_language() == "scala"
                    && reference.locator.source_site() == Some(site)
            })
            .expect("the known-no-owner reference survives confirmation");
        assert!(
            reference
                .answer
                .binding()
                .targets()
                .contains(&confirmed.target)
        );
        assert!(matches!(
        reference.owner,
        brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseEnclosingUnit::NoEnclosingUnit
    ));
        assert!(reference.owner.into_unit().unwrap().is_none());
    }
    #[test]
    fn selected_jvm_reverse_cancellation_wrappers_leave_retry_answers_unchanged() {
        let fixture = JavaRootResolutionOperationFixture::new();
        let (provider, _) = brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state(
        fixture.project_root.path(),
        JAVA_ROOT_PROVIDER_PATH,
        JAVA_ROOT_SOURCES[1].1,
        &JavaAdapter,
    );
        let target = provider
            .declarations
            .iter()
            .find(|unit| unit.short_name() == "Target" && unit.is_class())
            .expect("the public reverse target");
        let query = |cancellation: &CancellationToken| {
            let admission = CancellationToken::new();
            let operation = fixture.open_ready(&admission);
            let JvmReverseCandidateOutcome::Ready(candidates) = operation
                .jvm_reverse_candidate_sites(target, &admission)
                .unwrap()
            else {
                panic!("the candidate inventory is available before cancellation")
            };
            operation
                .confirm_jvm_reverse_candidates(
                    candidates,
                    cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap()
        };
        let render = |confirmed: &JvmReverseConfirmed| {
            let mut rows = confirmed
            .references
            .iter()
            .map(|reference| {
                let owner = match &reference.owner {
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseEnclosingUnit::Unit(unit) => unit.fq_name(),
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseEnclosingUnit::NoEnclosingUnit => {
                        "<no enclosing unit>".into()
                    }
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseEnclosingUnit::MissingSource => {
                        "<missing source>".into()
                    }
                };
                format!(
                    "{:?} target={} alternatives={} binding={:?} full={:?} owner={owner}",
                    reference.locator,
                    reference
                        .answer
                        .binding()
                        .targets()
                        .contains(&confirmed.target),
                    reference.answer.binding().targets().len(),
                    reference.answer.binding().completion(),
                    reference.answer.completion(),
                )
            })
            .collect::<Vec<_>>();
            rows.sort();
            (confirmed.completion.clone(), rows)
        };
        let SelectedResolutionOperationOutcome::Native(baseline) = query(&CancellationToken::new())
        else {
            panic!("the unbounded reverse request completes")
        };
        let baseline = render(&baseline);
        let mut cancelled = 0;
        // Deterministic token wrappers exercise early and late lifecycle checks,
        // including the forward callback, without depending on wall-clock timing.
        for checks in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096] {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            match query(&cancellation) {
                SelectedResolutionOperationOutcome::Cancelled(completion) => {
                    cancelled += 1;
                    assert_eq!(completion.combine(&cancelled_completion()), completion);
                }
                SelectedResolutionOperationOutcome::Native(answer) => {
                    assert_eq!(render(&answer), baseline)
                }
                _ => panic!("a cancellation wrapper changed the reverse outcome"),
            }
            let SelectedResolutionOperationOutcome::Native(retry) =
                query(&CancellationToken::new())
            else {
                panic!("cancellation must not leak staged state into the retry")
            };
            assert_eq!(
                render(&retry),
                baseline,
                "retry after cancellation limit {checks}"
            );
        }
        assert!(
            cancelled > 0,
            "the wrappers must actually observe cancellation"
        );
    }
    fn selected_java_reverse_for_qualified_peer_reference<A: LanguageAdapter>(
        peer_language: Language,
        peer_storage_language: &str,
        peer_path: &str,
        peer_source: &str,
        adapter: &A,
        prepare_peer: impl FnOnce(&mut FileState),
        before_confirm: impl FnOnce(&AnalyzerStore, &str),
    ) -> (JvmReverseConfirmed, ResolutionSiteId) {
        let project_root = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_persistent(&project_root.path().join("store.db")).unwrap();
        let project = MutableGenerationProject::new(project_root.path(), Language::Java);
        let workspace_id = WorkspaceId(
            "8585858585858585858585858585858585858585858585858585858585858585".to_owned(),
        );
        let java_path = "src/main/java/model/Visible.java";
        let java_source = "package model; public class Visible {}\n";
        let (java_state, _) =
        brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state(project_root.path(), java_path, java_source, &JavaAdapter);
        let (mut peer_state, peer_facts) =
        brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state(project_root.path(), peer_path, peer_source, adapter);
        let reference_site = site_for_identifier(
            &peer_facts,
            "Visible",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        // Keep a caller-owned inventory gap distinct from the Java target. The
        // legacy target-level reduction must also retain its Inventory attribution.
        Arc::get_mut(&mut peer_state)
            .expect("the fixture still owns its peer state exclusively")
            .resolution_facts
            .add_reference_enumeration_gap(reference_site, ResolutionGapKind::UnsupportedRoute);
        prepare_peer(Arc::get_mut(&mut peer_state).expect("the fixture owns its peer state"));
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

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseEvidenceOrigin;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::reverse::ReverseSubject;
        let target_inventory =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                candidates.target.semantic,
            )]);
        let obligations = candidates
            .evidence
            .enumeration
            .obligations
            .iter()
            .filter(|obligation| {
                *obligation.subject() == ReverseSubject::Target(candidates.target.semantic)
                    && matches!(obligation.origin, ReverseEvidenceOrigin::Inventory)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            obligations.len(),
            1,
            "the synthesized inventory obligation must remain distinct from the peer boundary"
        );
        for obligation in obligations {
            assert_eq!(obligation.completion, target_inventory);
        }
        assert_eq!(
            candidates
                .evidence
                .enumeration
                .obligations
                .iter()
                .filter(|obligation| {
                    matches!(obligation.origin, ReverseEvidenceOrigin::InventoryBoundary)
                })
                .count(),
            usize::from(candidates.peer_language_inventory_open),
        );
        let ledger_completion = candidates
            .evidence
            .enumeration
            .completion_for(|obligation| {
                !matches!(obligation.origin, ReverseEvidenceOrigin::InventoryBoundary)
            })
            .combine(&candidates.evidence.binding.completion())
            .combine(&candidates.evidence.metadata.completion());
        assert_eq!(
            ledger_completion, candidates.completion,
            "the candidate ledger must retain every legacy inventory reason"
        );
        assert!(
            candidates.candidates.iter().any(|candidate| {
                candidate.locator.storage_language() == peer_storage_language
                    && candidate.locator.relative_path() == peer_path
                    && candidate.locator.source_site() == Some(reference_site)
            }),
            "the qualified peer reference must enter the shared JVM candidate set: {candidates:#?}"
        );
        before_confirm(&store, &peer_oid.to_string());
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

    use brokk_bifrost_analysis::analyzer::resolution::LoweredSemanticRole;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::shared_contract;
    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;
    use std::collections::HashSet;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::semantic_at;
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_shared_jvm_consumer<A: LanguageAdapter>(
        store: &AnalyzerStore,
        root: &std::path::Path,
        workspace: &WorkspaceId,
        path: &str,
        source: &str,
        storage: &str,
        language: Language,
        adapter: &A,
        configuration: &[WorkspaceConfigurationInput],
    ) -> (
        brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
        FileResolutionFacts,
    ) {
        let source = shared_contract::golden_source(path, source);
        let source = source.as_str();
        let generation = store
            .ensure_language_epoch_value(storage, "j0-private-member-consumer-v1")
            .unwrap();
        store
            .ensure_resolution_producer_epoch(storage, language)
            .unwrap();
        let (state, facts) = parsed_operation_state(root, path, source, adapter);
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let package = state.package_name.clone();
        let prepared =
            AnalyzerStore::prepare_parsed_blob(oid, storage, generation, adapter, state).unwrap();
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
        assert!(
            outcomes.iter().all(|outcome| outcome.error.is_none()),
            "{outcomes:?}"
        );
        let snapshot = store
            .sync_workspace_inputs_for_workspace(
                workspace,
                storage,
                generation,
                &[WorkspaceFileRow {
                    rel_path: path.to_owned(),
                    blob_oid: oid,
                }],
                &[],
                &[],
                &[WorkspacePackageFileRow {
                    package_name: package,
                    rel_path: path.to_owned(),
                }],
                &[],
                &[],
                configuration,
                &[],
                &[],
            )
            .unwrap();
        (snapshot, facts)
    }

    // J3 declared-order fixtures. Keep this block independent of the terminal
    // module-descent fixture while the parallel hook lane finishes that case.
    #[test]
    #[hardwon(
        "#5658: JVM ordered discharge must retain aggregate evidence and clean up source waits"
    )]
    pub(crate) fn shared_closer_jvm_order_real_source_lifecycle_and_boundaries() {
        use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;
        let consumer_path = "src/main/scala/use/Use.scala";
        let cases = [
            "class Base { val selected = 1 }\nobject Child extends Base",
            "class Base extends Missing { val selected = 1 }\nobject Child extends Base",
            "object Child { val other = 1 }",
            "trait Root\ntrait Left extends Root\ntrait Right extends Root\nobject Child extends Left with Right",
        ];
        let mut boundaries = Vec::new();
        let mut work = Vec::new();
        for (index, declarations) in cases.into_iter().enumerate() {
            let consumer_source = format!(
                "package use\n{declarations}\nimport Child.selected\nobject Use {{ val answer = selected }}\n"
            );
            let root = tempfile::tempdir().unwrap();
            let store = AnalyzerStore::open_persistent(&root.path().join("store.db")).unwrap();
            let project = MutableGenerationProject::new(root.path(), Language::Scala);
            let workspace = WorkspaceId(
                "2929292929292929292929292929292929292929292929292929292929292929".to_owned(),
            );
            let configuration = [WorkspaceConfigurationInput::new("pom.xml".to_owned(), b"<project><groupId>test</groupId><artifactId>j3-order</artifactId><version>1</version></project>".to_vec().into_boxed_slice())];
            let (scala, facts) = publish_shared_jvm_consumer(
                &store,
                root.path(),
                &workspace,
                consumer_path,
                &consumer_source,
                "scala",
                Language::Scala,
                &ScalaAdapter,
                &configuration,
            );
            let mut snapshots = WorkspaceSnapshots::default();
            snapshots.insert("scala".to_owned(), scala);
            store.reconcile_jvm_package_contexts(&snapshots).unwrap();
            let languages = [SelectedResolutionLanguage::new("scala", Language::Scala)];
            let cancellation = CancellationToken::new();
            let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
                .open_selected_resolution_operation(
                    SelectedResolutionOperationInput::new(
                        &project,
                        &workspace,
                        &snapshots,
                        &languages,
                        &[],
                    ),
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("the real Scala order fixture opens");
            };
            let mount = operation
                .mounts()
                .unwrap()
                .iter()
                .find(|mount| mount.persisted_relative_path() == consumer_path)
                .unwrap();
            let lowered =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    mount.fragment(),
                    &operation.ready.shared_names(),
                    Language::Scala,
                    &facts,
                );
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::record_selected(
                lowered.identities(),
                operation
                    .ready
                    .inventory
                    .mount_record_by_ordinal(mount.ordinal())
                    .unwrap()
                    .fragment_digest()
                    .as_bytes(),
            );
            let (order_work, boundary, selections) =
                shared_contract::run_order_contract(&operation, consumer_path, &lowered);
            assert!(
                !selections.is_empty(),
                "the real JVM member selection retains an order outcome"
            );
            if index == 2 {
                assert!(
                    selections
                        .iter()
                        .any(|(complete, owners)| *complete && owners.len() == 1),
                    "the fully searched no-base owner finishes Done: {selections:?}"
                );
            }
            if index == 3 {
                let expected = ["Child", "Left", "Right", "Root"].map(|name| {
                    let namespace = if name == "Child" {
                        ResolutionNamespace::Value
                    } else {
                        ResolutionNamespace::Type
                    };
                    semantic_at(
                        &lowered,
                        site_for_identifier(
                            &facts,
                            name,
                            ResolutionIdentifierRole::Declaration,
                            namespace,
                        ),
                        LoweredSemanticRole::Definition,
                    )
                });
                assert!(
                    selections
                        .iter()
                        .any(|(complete, owners)| *complete
                            && owners.as_slice() == expected.as_slice()),
                    "the fully searched diamond preserves declared heads and delays its shared ancestor: expected={expected:?}, actual={selections:?}"
                );
                for (_, owners) in &selections {
                    assert_eq!(
                        owners.iter().collect::<HashSet<_>>().len(),
                        owners.len(),
                        "shared diamond ancestors occur once"
                    );
                }
            }
            eprintln!(
                "J3_ORDER fixture={index} work={order_work} not_searched={boundary} outcomes={selections:?}"
            );

            work.push(order_work);
            boundaries.push(boundary);
        }
        assert!(
            boundaries[1],
            "the Missing ancestor must retain a genuine NotSearched boundary: {boundaries:?}"
        );
        assert!(
            work[0] > 0,
            "an inherited member exercises declared order: {work:?}"
        );
        assert_eq!(
            work[2], 0,
            "a no-base owner finishes without any HierarchyOrder charge"
        );
    }
    /// A foreign on-disk anchor fails one lookup rather than panicking the server.
    #[test]
    fn persisted_module_anchor_without_language_policy_is_corrupt() {
        use brokk_bifrost_analysis::analyzer::resolution::SelectedSemanticLocator;
        use brokk_bifrost_analysis::analyzer::store::StoreErrorKind;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::LocatedSemantic;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::project_native_definition_units;
        use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

        let source = "class A {}";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("A.java", source)
            .build();
        let root = fixture.root();
        let database = root.join("store.db");
        let store = AnalyzerStore::open_persistent(&database).unwrap();
        let project = MutableGenerationProject::new(root, Language::Java);
        let workspace =
            WorkspaceId("3939393939393939393939393939393939393939393939393939393939393939".into());
        let path = "A.java";
        let (snapshot, facts) = publish_shared_jvm_consumer(
            &store,
            root,
            &workspace,
            path,
            source,
            "java",
            Language::Java,
            &JavaAdapter,
            &[],
        );
        // Simulate a foreign producer writing a valid anchor shape for a frontend
        // whose declarations must have absolute identities.
        let changed = rusqlite::Connection::open(&database).unwrap().execute(
            "UPDATE code_units SET fq_anchor_kind='own_module',fq_anchor_pop=0 WHERE short_name='A'", [],
        ).unwrap();
        assert_eq!(changed, 1, "the persisted class row was changed");
        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert("java".into(), snapshot);
        let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
        let cancellation = CancellationToken::new();
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &project,
                    &workspace,
                    &snapshots,
                    &languages,
                    &[],
                ),
                &cancellation,
            )
            .unwrap()
        else {
            panic!("selected fixture opens")
        };
        // Java publishes both a type and its constructor at the class name.
        // Select the type's own producer site rather than the shared name range.
        let site = site_for_identifier(
            &facts,
            "A",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        );
        let locator =
            SelectedSemanticLocator::new("java", path, site, LoweredSemanticRole::Definition);
        let LocatedSemantic::Found(definition) = operation
            .ready
            .lookup_locator(&operation.ready.lexical_source(), &locator, &cancellation)
            .unwrap()
        else {
            panic!("class type declaration was selected")
        };
        let error = match project_native_definition_units(
            &operation.ready,
            &[definition],
            &cancellation,
            &ResolutionSession::unbounded(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("Java cannot project a persisted module anchor"),
        };
        assert_eq!(error.kind, StoreErrorKind::Corrupt);
        assert!(error.to_string().contains("unsupported package anchor"));
    }
}
