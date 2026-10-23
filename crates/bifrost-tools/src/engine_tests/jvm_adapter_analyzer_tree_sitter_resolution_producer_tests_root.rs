#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_analysis::CodeUnitIndex;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::resolution_producer_tests::JavaInteriorSnapshot;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchStats;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::tree_sitter_resolution_producer_tests_go_support::go_extraction_support_0::assert_native_overlay_publication as assert_native_overlay_publication;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::tree_sitter_resolution_producer_tests_go_support::go_extraction_support_0::assert_native_unit_projection as assert_native_unit_projection;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::tree_sitter_resolution_producer_tests_go_support::go_extraction_support_0::native_type_projection as native_type_projection;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::resolution_producer_tests::rust_root_test_support::parse_progress_counter as parse_progress_counter;

    #[cfg(test)]
    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
    #[cfg(test)]
    use git2::ObjectType;
    #[cfg(test)]
    use git2::Oid;
    #[cfg(test)]
    use std::collections::BTreeMap;
    #[cfg(test)]
    use std::collections::BTreeSet;
    #[cfg(test)]
    use std::sync::Arc;
    #[cfg(test)]
    use std::sync::atomic::Ordering;

    #[cfg(test)]
    use crate::inline_project::InlineTestProject;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerBuildTierAccess;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::i_analyzer::InformationTier;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::Language;

    #[cfg(test)]
    #[test]
    fn producer_analyzes_each_cold_file_once_is_warm_zero_and_file_local_after_change() {
        const MODEL: &str = "package demo; class Model { int value; }\n";
        const CHANGED_MODEL: &str = "package demo; class Model { int value; } class Added {}\n";
        const HELPER: &str = "package demo; class Helper {}\n";
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("src/Model.java", MODEL)
            .file("src/Helper.java", HELPER)
            .build();
        let project = fixture.project_dyn();
        let mut cold_context =
            ephemeral_store_context(project.as_ref()).expect("ephemeral context");
        let store = Arc::clone(&cold_context.store);
        let cold_tiers = Arc::new(AnalyzerBuildTierAccess::new_active());
        cold_context.build_tier_access = Arc::clone(&cold_tiers);
        let (cold_parses, cold_progress) = parse_progress_counter();
        let cold = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            cold_context,
            Some(cold_progress),
        )
        .expect("cold analyzer");
        assert_eq!(cold_parses.load(Ordering::Relaxed), 2);
        assert_eq!(cold.state.persistence_stats.committed_blobs, 2);
        assert_eq!(cold.state.persistence_stats.committed_fragments, 2);
        assert_eq!(cold_tiers.tier_access_count(InformationTier::Syntax), 2);
        assert_eq!(cold_tiers.tier_access_count(InformationTier::UsageGraph), 0);
        let cold_names = declaration_names(&cold);
        let cold_interiors = java_interior_snapshots(&cold);
        assert_eq!(
            cold_interiors
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["src/Helper.java", "src/Model.java"]
        );
        assert_eq!(
            cold_interiors["src/Helper.java"].blob_oid,
            Oid::hash_object(ObjectType::Blob, HELPER.as_bytes()).expect("helper OID")
        );
        assert_eq!(
            cold_interiors["src/Model.java"].blob_oid,
            Oid::hash_object(ObjectType::Blob, MODEL.as_bytes()).expect("model OID")
        );
        for interior in cold_interiors.values() {
            assert!(interior.semantic_sites > 0);
            assert!(interior.path_endpoint_headers > 0);
        }
        let cold_transactions = store.parsed_blob_transaction_starts_for_test();

        let mut warm_context = cold.store_context.clone();
        let warm_tiers = Arc::new(AnalyzerBuildTierAccess::new_active());
        warm_context.build_tier_access = Arc::clone(&warm_tiers);
        let (warm_parses, warm_progress) = parse_progress_counter();
        let warm = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            warm_context,
            Some(warm_progress),
        )
        .expect("warm analyzer");
        assert_eq!(warm_parses.load(Ordering::Relaxed), 0);
        assert_eq!(warm.state.persistence_stats, PersistBatchStats::default());
        assert_eq!(
            store.parsed_blob_transaction_starts_for_test(),
            cold_transactions
        );
        assert_eq!(declaration_names(&warm), cold_names);
        assert_eq!(java_interior_snapshots(&warm), cold_interiors);
        assert_eq!(warm_tiers.tier_access_count(InformationTier::Syntax), 0);
        assert_eq!(warm_tiers.tier_access_count(InformationTier::UsageGraph), 0);

        fixture
            .file("src/Model.java")
            .write(CHANGED_MODEL)
            .expect("update Java source");
        let mut incremental_context = warm.store_context.clone();
        let incremental_tiers = Arc::new(AnalyzerBuildTierAccess::new_active());
        incremental_context.build_tier_access = Arc::clone(&incremental_tiers);
        let (incremental_parses, incremental_progress) = parse_progress_counter();
        let incremental = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            incremental_context,
            Some(incremental_progress),
        )
        .expect("incremental analyzer");
        assert_eq!(incremental_parses.load(Ordering::Relaxed), 1);
        assert_eq!(incremental.state.persistence_stats.committed_blobs, 1);
        assert_eq!(incremental.state.persistence_stats.committed_fragments, 1);
        assert_eq!(
            store.parsed_blob_transaction_starts_for_test(),
            cold_transactions + 1
        );
        assert_eq!(
            incremental_tiers.tier_access_count(InformationTier::Syntax),
            1
        );
        assert_eq!(
            incremental_tiers.tier_access_count(InformationTier::UsageGraph),
            0
        );
        let incremental_interiors = java_interior_snapshots(&incremental);
        assert_eq!(incremental_interiors.len(), 2);
        assert_eq!(
            incremental_interiors["src/Helper.java"],
            cold_interiors["src/Helper.java"]
        );
        let changed = &incremental_interiors["src/Model.java"];
        assert_eq!(
            changed.blob_oid,
            Oid::hash_object(ObjectType::Blob, CHANGED_MODEL.as_bytes())
                .expect("changed model OID")
        );
        assert_ne!(
            changed.interior_digest,
            cold_interiors["src/Model.java"].interior_digest
        );
        assert!(
            changed.semantic_sites > cold_interiors["src/Model.java"].semantic_sites,
            "the added top-level type must add a declaration site"
        );
        assert!(
            changed.path_endpoint_headers > cold_interiors["src/Model.java"].path_endpoint_headers,
            "the added top-level type must add lexical and root-export paths"
        );

        let fresh = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        assert_eq!(declaration_names(&incremental), declaration_names(&fresh));
    }
    #[cfg(test)]
    #[test]
    fn hydrated_java_overlays_publish_same_and_changed_native_content() {
        let original =
            "class Sample { static void original() {} static void caller() { original(); } }";
        assert_native_overlay_publication(
            JavaAdapter,
            "Sample.java",
            original,
            original,
            "original",
            "original",
        );
        assert_native_overlay_publication(
            JavaAdapter,
            "Sample.java",
            original,
            "class Sample { static void changed() {} static void caller() { changed(); } }",
            "changed",
            "changed",
        );
    }
    #[cfg(test)]
    #[test]
    fn hydrated_scala_overlays_keep_extractor_roles_after_eviction() {
        use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

        let disk = "object Pick { def unapply(x: Any): Any = x }; object Use { def run(x: Any) = x match { case Pick(a) => a } }";
        for (source, target) in [
            (disk, "unapply"),
            (
                "object Pick { def unapplySeq(x: Any): Any = x }; object Use { def run(x: Any) = x match { case Pick(a, b) => a } }",
                "unapplySeq",
            ),
            (
                "object Pick { def unapply(x: Any): Any = x; def unapplySeq(x: Any): Any = x }; object Use { def run(x: Any) = x match { case Pick(a) => a } }",
                "unapply",
            ),
            (
                "object Pick { def unapply(x: Any): Any = x; def unapplySeq(x: Any): Any = x }; object Use { def run(x: Any) = x match { case Pick(rest*) => rest } }",
                "unapplySeq",
            ),
        ] {
            assert_native_overlay_publication(
                ScalaAdapter,
                "Use.scala",
                disk,
                source,
                "Pick",
                target,
            );
        }
    }
    #[cfg(test)]
    #[test]
    fn java_overlay_packages_follow_selected_caller_and_provider_content() {
        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JavaImportContext;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        const OLD_CALLER: &str = "package oldpkg; class Use { Target field; }";
        const NEW_CALLER: &str = "package newpkg; class Use { Target field; }";
        const OLD_PROVIDER: &str = "package oldpkg; class Target {}";
        const NEW_PROVIDER: &str = "package newpkg; class Target {}";
        for (caller, provider, provider_overlay, expected) in [
            (NEW_CALLER, OLD_PROVIDER, None, 0),
            (NEW_CALLER, NEW_PROVIDER, None, 1),
            (OLD_CALLER, OLD_PROVIDER, Some(NEW_PROVIDER), 0),
            (NEW_CALLER, OLD_PROVIDER, Some(NEW_PROVIDER), 1),
        ] {
            let fixture = InlineTestProject::with_language(Language::Java)
                .file("Use.java", OLD_CALLER)
                .file("Target.java", provider)
                .build();
            let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            assert!(overlay.set(fixture.file("Use.java").abs_path(), caller.to_owned()));
            if let Some(source) = provider_overlay {
                assert!(overlay.set(fixture.file("Target.java").abs_path(), source.to_owned()));
            }
            let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
            let caller_state = analyzer
                .fetch_file_state(&fixture.file("Use.java"))
                .unwrap();
            analyzer
                .fetch_file_state(&fixture.file("Target.java"))
                .unwrap();
            let facts = &caller_state.resolution_facts;
            let name = facts
                .names
                .iter()
                .find(|name| name.spelling == "Target")
                .unwrap()
                .id;
            let site = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.name == name
                        && identifier.role == ResolutionIdentifierRole::Reference
                })
                .unwrap()
                .site;
            let cancellation = CancellationToken::new();
            let snapshots = analyzer.selected_workspace_snapshots();
            let SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            } = analyzer
                .selected_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
                .unwrap()
            else {
                panic!("Java source overlay publication must be ready");
            };
            let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
            let input = SelectedResolutionOperationInput::new(
                analyzer.project(),
                analyzer.workspace_id(),
                snapshots.as_ref(),
                &languages,
                &masks,
            )
            .with_content_mounts(content_mounts);
            let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
                .analyzer_store()
                .open_selected_resolution_operation(input, &cancellation)
                .unwrap()
            else {
                panic!("Java overlay operation must open");
            };
            let JavaImportContext::Ready { context, .. } = operation
                .java_import_context("Use.java", &cancellation)
                .unwrap()
            else {
                panic!("selected Java overlay packages must compose");
            };
            let result = operation
                .resolve_reference(
                    *context,
                    &SelectedSemanticLocator::new(
                        "java",
                        "Use.java",
                        site,
                        LoweredSemanticRole::Reference,
                    ),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) = result
            else {
                panic!("Java overlay type reference must be located");
            };
            assert_eq!(
                answer.binding().targets().len(),
                expected,
                "caller={caller:?}, provider={provider:?}, provider_overlay={provider_overlay:?}, answer={answer:?}"
            );
            assert_eq!(
                std::fs::read_to_string(fixture.file("Use.java").abs_path()).unwrap(),
                OLD_CALLER
            );
            assert_eq!(
                std::fs::read_to_string(fixture.file("Target.java").abs_path()).unwrap(),
                provider
            );
        }
    }
    #[cfg(test)]
    #[test]
    fn java_native_definition_projection_matches_parser_identity() {
        let source = "package example; class Sample { static void target() {} static void caller() { target(); } }";
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("Sample.java", source)
            .build();
        assert_native_unit_projection(&fixture, JavaAdapter, "Sample.java", source, || {});
    }
    #[cfg(test)]
    #[test]
    fn native_java_types_project_intrinsic_descriptors_from_selected_rows() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes;
        let java = "class Use { int f(int target) { return target; } }";
        let java_fixture = InlineTestProject::with_language(Language::Java)
            .file("Use.java", java)
            .build();
        let answer = native_type_projection(&java_fixture, JavaAdapter, "Use.java", java);
        {
            let SelectedNativeTypes::Ready {
                nominal, intrinsic, ..
            } = answer.value_types
            else {
                panic!("primitive type must project without a parser unit");
            };
            assert!(nominal.is_empty());
            assert_eq!(
                intrinsic.len(),
                1,
                "{:?}: {:?}",
                answer.named_reasons,
                answer.answer
            );
            assert_eq!(intrinsic[0].spelling(), "int");
            assert!(answer.answer.projected_frontiers().iter().any(|frontier| {
                frontier
                    .possible_values()
                    .iter()
                    .any(|value| value.ty().identity() == intrinsic[0].identity())
            }));
        }
    }
    #[cfg(test)]
    fn declaration_names(analyzer: &TreeSitterAnalyzer<JavaAdapter>) -> BTreeSet<String> {
        analyzer
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect()
    }
    #[cfg(test)]
    fn java_interior_snapshots(
        analyzer: &TreeSitterAnalyzer<JavaAdapter>,
    ) -> BTreeMap<String, JavaInteriorSnapshot> {
        let snapshots = analyzer.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
        let ready = match analyzer
            .store_context
            .store
            .open_selected_resolution_mount_inventory(
                &analyzer.store_context.workspace_id,
                snapshots.as_ref(),
                &languages,
                &[],
                &CancellationToken::default(),
            )
            .expect("open persisted Java resolution inventory")
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            SelectedResolutionMountInventoryOutcome::Unavailable(reason) => {
                panic!("published Java resolution inventory unavailable: {reason:?}")
            }
            SelectedResolutionMountInventoryOutcome::Cancelled => {
                panic!("uncancelled Java resolution inventory was cancelled")
            }
            SelectedResolutionMountInventoryOutcome::Stale(reason) => {
                panic!("newly captured Java resolution inventory was stale: {reason:?}")
            }
        };
        ready
            .mounts()
            .unwrap()
            .iter()
            .map(|mount| {
                (
                    mount.persisted_relative_path().to_owned(),
                    JavaInteriorSnapshot {
                        blob_oid: mount.blob_oid(),
                        interior_digest: mount.interior_digest(),
                        semantic_sites: mount.manifest_counts().semantic_sites(),
                        path_endpoint_headers: mount.manifest_counts().path_endpoint_headers(),
                    },
                )
            })
            .collect()
    }
}
