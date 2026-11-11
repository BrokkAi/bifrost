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

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#8741: an absent implicit JVM source root must skip reference resolution"
)]
fn jvm_direct_supertype_reference_bindings_preserve_alternatives() {
    jvm_supertype_reference_admission_probe("c/Child.java");
}

#[test]
fn jvm_direct_supertype_reference_admits_candidate_file_imports() {
    jvm_supertype_reference_admission_probe("a/Base.java");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#8741: an open selected root package inventory was completed as intrinsic"
)]
fn implicit_root_stays_open_with_selected_package_gap_in_both_orders() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::resolution::{
        BatchResolutionFragmentSource, JvmSelectedRootPresence, LoweredSemanticRole,
        SelectedFactOperationBlueprintConstruction, SelectedResolutionContextValidationOutcome,
        SelectedSemanticLocator,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
    for presence_first in [true, false] {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file(
                "java/lang/Broken.java",
                "package java.lang; class Broken {}",
            )
            .file("p/Child.java", "package p; class Child {}")
            .build();
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        let state = analyzer
            .fetch_file_state(&fixture.file("p/Child.java"))
            .unwrap();
        analyzer
            .fetch_file_state(&fixture.file("java/lang/Broken.java"))
            .unwrap();
        // The selected java.lang mount has an open persisted package-member
        // inventory before the operation opens; no stage epoch changes later.
        analyzer.analyzer_store().conn.execute_fixture(|connection| {
            let inserted = connection.execute(
                "INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) SELECT interior.blob_id,930001,0,2 FROM resolution_fragment_interiors AS interior JOIN blob_meta AS meta ON meta.blob_id=interior.blob_id WHERE interior.lang='java' AND meta.content_package='java.lang'",
                [],
            ).unwrap();
            assert_eq!(inserted, 1);
            connection.execute(
                "INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) SELECT interior.blob_id,2,0,0,930001,930001 FROM resolution_fragment_interiors AS interior JOIN blob_meta AS meta ON meta.blob_id=interior.blob_id WHERE interior.lang='java' AND meta.content_package='java.lang'",
                [],
            ).unwrap();
        });
        let cancellation = CancellationToken::new();
        let snapshots = analyzer.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("open operation")
        };
        let lexical = operation.ready.lexical_source();
        if presence_first {
            assert_eq!(
                lexical
                    .jvm_selected_root_presence("java.lang.Object", &cancellation)
                    .unwrap(),
                JvmSelectedRootPresence::NotReady
            );
        }
        let jvm_context::JvmImportContext::Ready {
            context,
            scoped_gaps: gaps,
            ..
        } = operation
            .java_import_context("p/Child.java", &cancellation)
            .unwrap()
        else {
            panic!("import context")
        };
        if !presence_first {
            assert_eq!(
                lexical
                    .jvm_selected_root_presence("java.lang.Object", &cancellation)
                    .unwrap(),
                JvmSelectedRootPresence::NotReady
            );
        }
        let SelectedResolutionContextValidationOutcome::Ready(context) = operation
            .prepare_context(*context, &cancellation, &SelectedResolutionContextMetrics)
            .unwrap()
        else {
            panic!("validate context")
        };
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
            .ready
            .collect_blueprint(context, &cancellation)
            .unwrap()
        else {
            panic!("blueprint")
        };
        let typed = operation.ready.typed_source();
        let session = ResolutionSession::unbounded();
        operation.with_jvm_hierarchy_query(JvmForwardOperationContext {
            storage_language: "java", blueprint: &blueprint, caller_path: "p/Child.java",
            import_gaps: &gaps, lexical: &lexical, typed: &typed,
            cancellation: &cancellation, session: &session,
        }, |query| {
            let implicit = state.resolution_facts.supertypes.iter()
                .find(|parent| parent.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind::ImplicitSuperclass)
                .expect("Child has an implicit Object parent");
            let locator = SelectedSemanticLocator::new("java", "p/Child.java", implicit.subtype, LoweredSemanticRole::Definition);
            let LocatedSemantic::Found(definition) = operation.ready.lookup_locator(&lexical, &locator, &cancellation)?
            else { panic!("locate Child") };
            let answer = query.jvm_direct_supertype_answer(definition)?;
            assert_eq!(answer.parents.len(), 1, "{answer:?}");
            assert!(matches!(answer.parents[0].completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Incomplete(_)), "{presence_first}: {answer:?}");
            Ok(())
        }).unwrap();
    }
}

fn jvm_supertype_reference_admission_probe(caller_path: &str) {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::resolution::{
        LoweredSemanticRole, SelectedFactOperationBlueprintConstruction,
        SelectedResolutionContextValidationOutcome, SelectedSemanticLocator,
        SelectedTypedFactSource, TypedFactPageVisitor, TypedFactRequest,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("a/Base.java", "package a; public class Base {}")
        .file("b/Base.java", "package b; public class Base {}")
        .file("c/Child.java", "package c; import a.*; import b.*; class Child extends Base {} class D extends a.Base {}")
        .file("d/Other.java", "package d; import a.Base; class Other extends Base {}")
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    for path in ["a/Base.java", "b/Base.java", "c/Child.java", "d/Other.java"] {
        analyzer.fetch_file_state(&fixture.file(path)).unwrap();
    }
    let state = analyzer
        .fetch_file_state(&fixture.file("c/Child.java"))
        .unwrap();
    let cancellation = CancellationToken::new();
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &[],
    );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("open operation")
    };
    let jvm_context::JvmImportContext::Ready {
        context,
        scoped_gaps: gaps,
        ..
    } = operation
        .java_import_context(caller_path, &cancellation)
        .unwrap()
    else {
        panic!("import context")
    };
    let SelectedResolutionContextValidationOutcome::Ready(context) = operation
        .prepare_context(*context, &cancellation, &SelectedResolutionContextMetrics)
        .unwrap()
    else {
        panic!("validate context")
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
        .ready
        .collect_blueprint(context, &cancellation)
        .unwrap()
    else {
        panic!("blueprint")
    };
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let session = ResolutionSession::unbounded();
    operation
        .with_jvm_hierarchy_query(
            JvmForwardOperationContext {
                storage_language: "java",
                blueprint: &blueprint,
                caller_path,
                import_gaps: &gaps,
                lexical: &lexical,
                typed: &typed,
                cancellation: &cancellation,
                session: &session,
            },
            |query| {
                for (ordinal, expected) in [(0, 2), (1, 1), (1, 1)] {
                    let site = state.resolution_facts.supertypes[ordinal].subtype;
                    let locator = SelectedSemanticLocator::new(
                        "java",
                        "c/Child.java",
                        site,
                        LoweredSemanticRole::Definition,
                    );
                    let LocatedSemantic::Found(definition) =
                        operation
                            .ready
                            .lookup_locator(&lexical, &locator, &cancellation)?
                    else {
                        panic!("locate definition")
                    };
                    let answer = query.jvm_direct_supertype_answer(definition)?;
                    assert_eq!(answer.parents.len(), 1, "{answer:?}");
                    assert_eq!(answer.parents[0].targets.len(), expected, "{answer:?}");
                    let mut candidates = Vec::new();
                    let outcome = typed.visit_supertype_pages_for_definitions(
                        TypedFactRequest::new(&[definition]), &cancellation,
                        &mut TypedFactPageVisitor::new(&mut |page| {
                            candidates.extend(page.iter().map(|selected| selected.row().clone()));
                            Ok(true)
                        }),
                    )?;
                    assert!(outcome.is_exhausted());
                    for target in &answer.parents[0].targets {
                        let reverse = query.jvm_direct_descendant_answer(*target, &candidates, outcome.evidence().clone())?;
                        assert!(reverse.open.is_empty(), "{reverse:?}");
                        if expected > 1 {
                            assert!(reverse.edges.is_empty(), "{reverse:?}");
                            assert_eq!(reverse.ambiguous, vec![definition]);
                        } else {
                            assert_eq!(reverse.edges, vec![definition]);
                            assert!(reverse.ambiguous.is_empty(), "{reverse:?}");
                        }
                    }

                    // #8290 must remain a witness of the shared engine, even
                    // when the hierarchy projection reuses its first result.
                    let uncached = query.resolve_reference_uncached_for_test(answer.parents[0].reference)?;
                    assert_eq!(*uncached.binding().completion(), brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete, "uncached binding: {uncached:?}");
                    assert_eq!(answer.parents[0].completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete, "repeated parent binding must stay closed: {answer:?}");
                }
                let base_state = analyzer.fetch_file_state(&fixture.file("a/Base.java")).unwrap();
                let implicit = base_state.resolution_facts.supertypes.iter()
                    .find(|parent| parent.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind::ImplicitSuperclass)
                    .expect("Base has an implicit Object parent");
                let locator = SelectedSemanticLocator::new(
                    "java", "a/Base.java", implicit.subtype, LoweredSemanticRole::Definition,
                );
                let LocatedSemantic::Found(base_definition) = operation.ready.lookup_locator(&lexical, &locator, &cancellation)? else {
                    panic!("locate Base definition");
                };
                let before = query.resolved_reference_count_for_test();
                let implicit_answer = query.jvm_direct_supertype_answer(base_definition)?;
                assert_eq!(implicit_answer.parents.len(), 1, "{implicit_answer:?}");
                assert_eq!(implicit_answer.parents[0].targets.len(), 1, "{implicit_answer:?}");
                assert_eq!(implicit_answer.parents[0].completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete, "{implicit_answer:?}");
                assert_eq!(query.resolved_reference_count_for_test(), before,
                    "an absent root takes the intrinsic edge without resolving a reference");
                let other = analyzer.fetch_file_state(&fixture.file("d/Other.java")).unwrap();
                let locator = SelectedSemanticLocator::new(
                    "java", "d/Other.java", other.resolution_facts.supertypes[0].subtype,
                    LoweredSemanticRole::Definition,
                );
                let LocatedSemantic::Found(definition) = operation.ready.lookup_locator(&lexical, &locator, &cancellation)? else {
                    panic!("locate second candidate");
                };
                let answer = query.jvm_direct_supertype_answer(definition)?;
                assert_eq!(answer.parents[0].targets.len(), 1, "second candidate must use its own explicit import: {answer:?}");
                assert_eq!(answer.parents[0].completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete, "{answer:?}");
                let profile = brokk_bifrost_core::cache_db::sql_profile::request_scope("7027_r4_descendants");
                let walk = operation.jvm_descendant_walk(query, answer.parents[0].targets[0], "Base", Language::Java, &cancellation, &session)?;
                drop(profile);
                brokk_bifrost_core::cache_db::sql_profile::flush();
                assert_eq!(walk.rounds, 1);
                assert_eq!(walk.answer.edges.len(), 2, "{:?}", walk.answer);
                assert_eq!(walk.answer.ambiguous.len(), 1, "{:?}", walk.answer);
                assert!(walk.answer.open.is_empty(), "{:?}", walk.answer);
                Ok(())
            },
        )
        .unwrap();
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9195: shared selected JVM hierarchy stopped at a Kotlin source typealias"
)]
fn kotlin_source_alias_parent_closes_in_selected_native_hierarchy() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::resolution::{
        LoweredSemanticRole, SelectedFactOperationBlueprintConstruction,
        SelectedResolutionContextValidationOutcome, SelectedSemanticLocator,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_direct_supertypes::JvmHierarchyReadReceipts;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_jvm_analysis::analyzer::kotlin::adapter::KotlinAdapter;

    let fixture = InlineTestProject::with_language(Language::Kotlin)
        .file("lib/Base.kt", "package lib\nopen class Base\n")
        .file(
            "app/Alias.kt",
            "package app\nimport lib.Base\ntypealias AliasToBase = Base\n",
        )
        .file("app/Child.kt", "package app\nclass X : AliasToBase()\n")
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), KotlinAdapter);
    let base_state = analyzer
        .fetch_file_state(&fixture.file("lib/Base.kt"))
        .unwrap();
    let child_state = analyzer
        .fetch_file_state(&fixture.file("app/Child.kt"))
        .unwrap();
    let cancellation = CancellationToken::new();
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("kotlin", Language::Kotlin)];
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &[],
    );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("open selected Kotlin operation")
    };
    let jvm_context::JvmImportContext::Ready {
        context,
        scoped_gaps: gaps,
        ..
    } = operation
        .jvm_import_context(Language::Kotlin, "app/Child.kt", &cancellation)
        .unwrap()
    else {
        panic!("Kotlin import context")
    };
    let SelectedResolutionContextValidationOutcome::Ready(context) = operation
        .prepare_context(*context, &cancellation, &SelectedResolutionContextMetrics)
        .unwrap()
    else {
        panic!("validate Kotlin context")
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
        .ready
        .collect_blueprint(context, &cancellation)
        .unwrap()
    else {
        panic!("Kotlin blueprint")
    };
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let locate = |path, site| {
        let locator =
            SelectedSemanticLocator::new("kotlin", path, site, LoweredSemanticRole::Definition);
        let LocatedSemantic::Found(id) = operation
            .ready
            .lookup_locator(&lexical, &locator, &cancellation)
            .unwrap()
        else {
            panic!("locate {path}")
        };
        id
    };
    let child = locate(
        "app/Child.kt",
        child_state.resolution_facts.supertypes[0].subtype,
    );
    let base = locate(
        "lib/Base.kt",
        base_state.resolution_facts.supertypes[0].subtype,
    );
    let session = ResolutionSession::unbounded();
    let SelectedNativeDefinitions::Ready(definitions) = operation
        .selected_hierarchy_definition_units(&[base], &cancellation, &session)
        .unwrap()
    else {
        panic!("selected Kotlin source Base is hydratable")
    };
    assert!(
        matches!(&definitions[..], [(id, SelectedNativeDefinition::Unit(unit))]
        if *id == base && unit.fq_name() == "lib.Base")
    );
    #[derive(Default)]
    struct CountingReceipts {
        captured: usize,
        replayed: usize,
    }
    impl JvmHierarchyReadReceipts for CountingReceipts {
        type Receipt = ();
        fn capture<T>(&mut self, read: impl FnOnce() -> T) -> (T, ()) {
            self.captured += 1;
            (read(), ())
        }
        fn replay(&mut self, _: &()) {
            self.replayed += 1;
        }
    }
    let mut receipts = CountingReceipts::default();
    operation
        .with_jvm_hierarchy_query_receipts(
            JvmForwardOperationContext {
                storage_language: "kotlin",
                blueprint: &blueprint,
                caller_path: "app/Child.kt",
                import_gaps: &gaps,
                lexical: &lexical,
                typed: &typed,
                cancellation: &cancellation,
                session: &session,
            },
            &mut receipts,
            |query| {
                let answer = query.jvm_direct_supertype_answer(child)?;
                assert_eq!(answer.parents.len(), 1, "{answer:?}");
                let parent = &answer.parents[0];
                let binding = query.resolve_reference_uncached_for_test(parent.reference)?;
                assert_eq!(binding.binding().targets().len(), 1, "{binding:?}");
                assert_ne!(
                    binding.binding().targets()[0],
                    base,
                    "binding API retains the alias"
                );
                assert_eq!(
                    parent.targets,
                    vec![base],
                    "selected alias RHS resolves in its declaration context: {answer:?}"
                );
                assert_eq!(
                    parent.completion,
                    brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete,
                    "{answer:?}"
                );
                let repeated = query.jvm_direct_supertype_answer(child)?;
                assert_eq!(repeated.parents[0].targets, vec![base]);
                Ok(())
            },
        )
        .unwrap();
    assert!(
        receipts.captured > 0 && receipts.replayed > 0,
        "selected alias reads must be captured and replayed: {} / {}",
        receipts.captured,
        receipts.replayed
    );
    let budget = brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
        max_scope_nodes: 1,
        ..Default::default()
    };
    let limited = ResolutionSession::bounded(budget, Some(&cancellation));
    operation.with_jvm_hierarchy_query(JvmForwardOperationContext {
        storage_language: "kotlin", blueprint: &blueprint, caller_path: "app/Child.kt",
        import_gaps: &gaps, lexical: &lexical, typed: &typed,
        cancellation: &cancellation, session: &limited,
    }, |query| {
        let cut = query.jvm_direct_supertype_answer(child)?;
        assert!(cut.parents.iter().all(|parent|
            parent.completion != brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete),
            "a stopped alias chain cannot certify a parent: {cut:?}");
        Ok(())
    }).unwrap();
}

#[test]
fn jvm_descendant_alias_worklist() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::resolution::{
        LoweredSemanticRole, SelectedFactOperationBlueprintConstruction,
        SelectedResolutionContextValidationOutcome, SelectedSemanticLocator,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;
    let fixture = InlineTestProject::with_language(Language::Scala)
        .file("a/Base.scala", "package a; class Base")
        .file(
            "c/Alias.scala",
            "package c; object Aliases { type B = a.Base }",
        )
        .file(
            "d/Child.scala",
            "package d; import c.Aliases.B; class E extends B",
        )
        .file(
            "e/Renamed.scala",
            "package e; import a.{Base => R}; class C extends R",
        )
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), ScalaAdapter);
    for path in [
        "a/Base.scala",
        "c/Alias.scala",
        "d/Child.scala",
        "e/Renamed.scala",
    ] {
        analyzer.fetch_file_state(&fixture.file(path)).unwrap();
    }
    let state = analyzer
        .fetch_file_state(&fixture.file("a/Base.scala"))
        .unwrap();
    // #8367 removes synthetic parent rows. Locate the declaration through
    // its own structured identifier rather than through a parent edge.
    let base = state.resolution_facts.identifiers.iter().find(|identifier| {
        identifier.role == brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole::Declaration
            && identifier.namespace == brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type
            && state.resolution_facts.names[identifier.name.index()].spelling == "Base"
    }).expect("fixture Base declaration").site;
    let caller_path = "a/Base.scala";
    let cancellation = CancellationToken::new();
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("scala", Language::Scala)];
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &[],
    );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("open operation")
    };
    let jvm_context::JvmImportContext::Ready {
        context,
        scoped_gaps: gaps,
        ..
    } = operation
        .jvm_import_context(Language::Scala, caller_path, &cancellation)
        .unwrap()
    else {
        panic!("import context")
    };
    let SelectedResolutionContextValidationOutcome::Ready(context) = operation
        .prepare_context(*context, &cancellation, &SelectedResolutionContextMetrics)
        .unwrap()
    else {
        panic!("validate context")
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
        .ready
        .collect_blueprint(context, &cancellation)
        .unwrap()
    else {
        panic!("blueprint")
    };
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let session = ResolutionSession::unbounded();
    operation
        .with_jvm_hierarchy_query(
            JvmForwardOperationContext {
                storage_language: "scala",
                blueprint: &blueprint,
                caller_path,
                import_gaps: &gaps,
                lexical: &lexical,
                typed: &typed,
                cancellation: &cancellation,
                session: &session,
            },
            |query| {
                let locator = SelectedSemanticLocator::new(
                    "scala",
                    caller_path,
                    base,
                    LoweredSemanticRole::Definition,
                );
                let LocatedSemantic::Found(target) =
                    operation
                        .ready
                        .lookup_locator(&lexical, &locator, &cancellation)?
                else {
                    panic!("locate Base");
                };
                let walk = operation.jvm_descendant_walk(
                    query,
                    target,
                    "Base",
                    Language::Scala,
                    &cancellation,
                    &session,
                )?;
                // #8367 removes #8261's synthetic AnyRef row; #8427 binds it.
                // Either a closed answer or an open answer naming exactly that
                // implicit parent is valid. Openness itself is not the contract.
                let aliases = analyzer.fetch_file_state(&fixture.file("c/Alias.scala")).unwrap();
                let mut implicit = Vec::new();
                for parent in &aliases.resolution_facts.supertypes {
                    if parent.kind != brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind::ImplicitSuperclass { continue; }
                    let locator = SelectedSemanticLocator::new("scala", "c/Alias.scala", parent.supertype_reference, LoweredSemanticRole::Reference);
                    if let LocatedSemantic::Found(reference) = operation.ready.lookup_locator(&lexical, &locator, &cancellation)? { implicit.push(reference); }
                }
                assert!(walk.answer.open.iter().all(|reference| implicit.contains(reference)), "{:?}", walk.answer);
                assert_eq!(walk.rounds, 2);
                assert_eq!(walk.answer.edges.len(), 2, "{:?}", walk.answer);
                assert!(walk.answer.ambiguous.is_empty(), "{:?}", walk.answer);
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn jvm_descendant_r4_profile() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::resolution::{
        LoweredSemanticRole, SelectedFactOperationBlueprintConstruction,
        SelectedResolutionContextValidationOutcome, SelectedSemanticLocator,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
    // The java-native-ancestors golden sources, inlined: a public engine test
    // cannot include the private root-test fixtures.
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("a/Base.java", "package a;\npublic class Base { public void run() {} }\n")
        .file("b/Base.java", "package b;\npublic class Base { public void run() {} }\n")
        .file("c/Child.java", "package c;\nimport a.*;\nimport b.*;\npublic class Child extends Base { public void run() {} }\nclass D extends a.Base { public void run() {} }\nclass Unresolved extends Missing {}\n")
        .file("c/Partial.java", "// Test-only hierarchy completeness fixture for #7027 S2c.\npackage c;\ninterface Known {}\nclass Partial extends Missing implements Known {}\n")
        .file("e/Unseen.java", "// Test-only reverse hierarchy fixture for #7027 S3.\npackage e;\nclass Unseen extends Base { public void run() {} }\n")
        .build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    for path in [
        "a/Base.java",
        "b/Base.java",
        "c/Child.java",
        "c/Partial.java",
        "e/Unseen.java",
    ] {
        analyzer.fetch_file_state(&fixture.file(path)).unwrap();
    }
    let state = analyzer
        .fetch_file_state(&fixture.file("c/Child.java"))
        .unwrap();
    let caller_path = "c/Child.java";
    let cancellation = CancellationToken::new();
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &[],
    );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("open operation")
    };
    let jvm_context::JvmImportContext::Ready {
        context,
        scoped_gaps: gaps,
        ..
    } = operation
        .jvm_import_context(Language::Java, caller_path, &cancellation)
        .unwrap()
    else {
        panic!("import context")
    };
    let SelectedResolutionContextValidationOutcome::Ready(context) = operation
        .prepare_context(*context, &cancellation, &SelectedResolutionContextMetrics)
        .unwrap()
    else {
        panic!("validate context")
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
        .ready
        .collect_blueprint(context, &cancellation)
        .unwrap()
    else {
        panic!("blueprint")
    };
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let session = ResolutionSession::unbounded();
    operation
        .with_jvm_hierarchy_query(
            JvmForwardOperationContext {
                storage_language: "java",
                blueprint: &blueprint,
                caller_path,
                import_gaps: &gaps,
                lexical: &lexical,
                typed: &typed,
                cancellation: &cancellation,
                session: &session,
            },
            |query| {
                let locator = SelectedSemanticLocator::new(
                    "java",
                    caller_path,
                    state.resolution_facts.supertypes[1].subtype,
                    LoweredSemanticRole::Definition,
                );
                let LocatedSemantic::Found(child) =
                    operation
                        .ready
                        .lookup_locator(&lexical, &locator, &cancellation)?
                else {
                    panic!("locate D");
                };
                let target = query.jvm_direct_supertype_answer(child)?.parents[0].targets[0];
                let profile =
                    brokk_bifrost_core::cache_db::sql_profile::request_scope("7027_r4_round");
                let walk = operation.jvm_descendant_walk(
                    query,
                    target,
                    "Base",
                    Language::Java,
                    &cancellation,
                    &session,
                )?;
                drop(profile);
                brokk_bifrost_core::cache_db::sql_profile::flush();
                for max_scope_nodes in [1, 3] {
                    // One step cuts membership; three steps reach hydration
                    // and cut there. Neither cut promises a surviving subset.
                    let budget = brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget { max_scope_nodes, ..Default::default() };
                    let limited = ResolutionSession::bounded(budget, Some(&cancellation));
                    let cut = operation.jvm_descendant_walk(query, target, "Base", Language::Java, &cancellation, &limited)?;
                    assert!(cut.answer.open_reasons.iter().any(|reason| matches!(reason, brokk_bifrost_core::analyzer::capabilities::HierarchyOpenReason::MemberFamily(brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason::HierarchyTruncated))), "{:?}", cut.answer);
                }
                assert_eq!(walk.rounds, 1);
                assert_eq!(walk.answer.edges, vec![child]);
                assert_eq!(walk.answer.ambiguous.len(), 1, "{:?}", walk.answer);
                assert!(!walk.answer.open.is_empty(), "{:?}", walk.answer);
                Ok(())
            },
        )
        .unwrap();
}

struct ScalaAliasWalkObservation {
    targets: Vec<brokk_bifrost_analysis::analyzer::resolution::SemanticId>,
    completion: brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion,
    replayed: usize,
    scope_nodes: usize,
}

fn selected_scala_alias_walk(
    aliases: &str,
    other_files: &[(&str, &str)],
    max_scope_nodes: Option<usize>,
) -> ScalaAliasWalkObservation {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::resolution::{
        LoweredSemanticRole, SelectedFactOperationBlueprintConstruction,
        SelectedResolutionContextValidationOutcome, SelectedSemanticLocator,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_direct_supertypes::JvmHierarchyReadReceipts;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

    let mut project = InlineTestProject::with_language(Language::Scala)
        .file("app/Aliases.scala", aliases)
        .file("app/Child.scala", "package app\nclass Child extends A0\n");
    for (path, source) in other_files {
        project = project.file(*path, *source);
    }
    let fixture = project.build();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), ScalaAdapter);
    analyzer
        .fetch_file_state(&fixture.file("app/Aliases.scala"))
        .unwrap();
    for (path, _) in other_files {
        analyzer.fetch_file_state(&fixture.file(*path)).unwrap();
    }
    let child_state = analyzer
        .fetch_file_state(&fixture.file("app/Child.scala"))
        .unwrap();
    let cancellation = CancellationToken::new();
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("scala", Language::Scala)];
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &[],
    );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("open selected Scala operation")
    };
    let jvm_context::JvmImportContext::Ready {
        context,
        scoped_gaps: gaps,
        ..
    } = operation
        .jvm_import_context(Language::Scala, "app/Child.scala", &cancellation)
        .unwrap()
    else {
        panic!("Scala import context")
    };
    let SelectedResolutionContextValidationOutcome::Ready(context) = operation
        .prepare_context(*context, &cancellation, &SelectedResolutionContextMetrics)
        .unwrap()
    else {
        panic!("validate Scala context")
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
        .ready
        .collect_blueprint(context, &cancellation)
        .unwrap()
    else {
        panic!("Scala blueprint")
    };
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let locator = SelectedSemanticLocator::new(
        "scala",
        "app/Child.scala",
        child_state
            .resolution_facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole::Declaration
                    && identifier.namespace == brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type
                    && child_state.resolution_facts.names[identifier.name.index()].spelling == "Child"
            })
            .expect("fixture Child declaration")
            .site,
        LoweredSemanticRole::Definition,
    );
    let LocatedSemantic::Found(child) = operation
        .ready
        .lookup_locator(&lexical, &locator, &cancellation)
        .unwrap()
    else {
        panic!("locate Scala child")
    };
    let session = max_scope_nodes.map_or_else(ResolutionSession::unbounded, |max_scope_nodes| {
        ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes,
                ..Default::default()
            },
            Some(&cancellation),
        )
    });
    #[derive(Default)]
    struct CountingReceipts {
        replayed: usize,
    }
    impl JvmHierarchyReadReceipts for CountingReceipts {
        type Receipt = ();
        fn capture<T>(&mut self, read: impl FnOnce() -> T) -> (T, ()) {
            (read(), ())
        }
        fn replay(&mut self, _: &()) {
            self.replayed += 1;
        }
    }
    let mut receipts = CountingReceipts::default();
    let (targets, completion) = operation
        .with_jvm_hierarchy_query_receipts(
            JvmForwardOperationContext {
                storage_language: "scala",
                blueprint: &blueprint,
                caller_path: "app/Child.scala",
                import_gaps: &gaps,
                lexical: &lexical,
                typed: &typed,
                cancellation: &cancellation,
                session: &session,
            },
            &mut receipts,
            |query| {
                let answer = query.jvm_direct_supertype_answer(child)?;
                assert_eq!(answer.parents.len(), 1, "{answer:?}");
                let parent = answer.parents.into_iter().next().unwrap();
                Ok((parent.targets, parent.completion))
            },
        )
        .unwrap();
    let work = session.finish(()).work();
    ScalaAliasWalkObservation {
        targets,
        completion,
        replayed: receipts.replayed,
        scope_nodes: work.scope_nodes,
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9195: alias-parent walk re-expanded reconverging aliases per path and skipped budget debit on cached steps"
)]
fn scala_selected_alias_dag_expands_linearly() {
    let mut aliases = String::from("package app\n");
    let mut files = Vec::new();
    for level in 0..8 {
        aliases.push_str(&format!("import left{level}.*\nimport right{level}.*\n"));
        files.push((
            format!("left{level}/B.scala"),
            format!("package left{level}\ntype B{level} = app.A{}\n", level + 1),
        ));
        files.push((
            format!("right{level}/B.scala"),
            format!("package right{level}\ntype B{level} = app.A{}\n", level + 1),
        ));
    }
    for level in 0..8 {
        aliases.push_str(&format!("type A{level} = B{level}\n"));
    }
    aliases.push_str("type A8 = lib.Base\n");
    files.push((
        "lib/Base.scala".to_owned(),
        "package lib\nclass Base\n".to_owned(),
    ));
    let borrowed = files
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    let observation = selected_scala_alias_walk(&aliases, &borrowed, None);
    assert_eq!(observation.targets.len(), 1, "{:?}", observation.targets);
    assert!(
        observation.replayed < 150,
        "replayed {} reads for 25 aliases",
        observation.replayed
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9195: alias-parent walk re-expanded reconverging aliases per path and skipped budget debit on cached steps"
)]
fn scala_selected_alias_fanout_charges_and_stays_open() {
    let aliases = "package app\nimport one.*\nimport two.*\ntype A0 = Base\n";
    let files = [
        ("one/Base.scala", "package one\nclass Base\n"),
        ("two/Base.scala", "package two\nclass Base\n"),
    ];
    let full = selected_scala_alias_walk(aliases, &files, Some(10_000));
    assert_eq!(full.targets.len(), 2, "{:?}", full.targets);
    assert!(
        !matches!(&full.completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().any(|reason| matches!(reason, brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::ReceiverBudgetExhausted(_)))),
        "{:?}",
        full.completion
    );
    let single = selected_scala_alias_walk(
        "package app\nimport one.*\ntype A0 = Base\n",
        &files[..1],
        Some(10_000),
    );
    assert!(
        full.scope_nodes > single.scope_nodes,
        "fanout {} <= single {}",
        full.scope_nodes,
        single.scope_nodes
    );
    let cut = selected_scala_alias_walk(aliases, &files, Some(full.scope_nodes - 1));
    assert_ne!(
        cut.completion,
        brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete
    );
    assert!(
        matches!(&cut.completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().any(|reason| matches!(reason, brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::ReceiverBudgetExhausted(_)))),
        "{:?}",
        cut.completion
    );
    assert_eq!(cut.scope_nodes, full.scope_nodes - 1);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#9195: alias-parent walk re-expanded reconverging aliases per path and skipped budget debit on cached steps"
)]
fn scala_selected_alias_budget_cut_is_deterministic() {
    let aliases = "package app\nimport one.*\nimport two.*\ntype A0 = Base\n";
    let files = [
        ("one/Base.scala", "package one\nclass Base\n"),
        ("two/Base.scala", "package two\nclass Base\n"),
    ];
    let full = selected_scala_alias_walk(aliases, &files, Some(10_000));
    assert!(
        !matches!(&full.completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().any(|reason| matches!(reason, brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::ReceiverBudgetExhausted(_)))),
        "{:?}",
        full.completion
    );
    let budget = full.scope_nodes - 1;
    let first = selected_scala_alias_walk(aliases, &files, Some(budget));
    let second = selected_scala_alias_walk(aliases, &files, Some(budget));
    assert_ne!(
        first.completion,
        brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Complete
    );
    assert!(
        matches!(&first.completion, brokk_bifrost_analysis::analyzer::resolution::ResolutionCompletion::Incomplete(reasons)
            if reasons.iter().any(|reason| matches!(reason, brokk_bifrost_analysis::analyzer::resolution::ResolutionIncompleteReason::ReceiverBudgetExhausted(_)))),
        "{:?}",
        first.completion
    );
    assert_eq!(first.targets, second.targets);
    assert_eq!(first.completion, second.completion);
    assert_eq!(first.scope_nodes, second.scope_nodes);
}
