#[cfg(test)]
mod ruby_extraction_tests {
    use brokk_bifrost_analysis::{CodeUnitIndex, IAnalyzer};

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use std::sync::Arc;

    use std::sync::atomic::AtomicUsize;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgressPhase;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::model::Language;

    use git2::ObjectType;

    use git2::Oid;

    use std::sync::atomic::Ordering;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_store;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::source_admission_test_support::table;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::source_admission_test_support::table_with_items;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

    use brokk_bifrost_cpp_analysis::analyzer::cpp::source_storage::CanonicalCppSourceFacts;

    use brokk_bifrost_analysis::inline_project::InlineTestProject;
    use brokk_bifrost_test_macros::hardwon;
    const TRANSITION_CHILD_ROOT: &str = "BIFROST_5408_TRANSITION_CHILD_ROOT";

    const TRANSITION_CHILD_DB: &str = "BIFROST_5408_TRANSITION_CHILD_DB";

    const TRANSITION_CHILD_OUTPUT: &str = "BIFROST_5408_TRANSITION_CHILD_OUTPUT";

    fn persisted_policy_stage(
        root: &std::path::Path,
        database: &std::path::Path,
        stage: &str,
        setting: Option<&str>,
    ) -> serde_json::Value {
        let output_path = root.join(format!("{stage}.json"));
        let qualified = concat!(
            module_path!(),
            "::numeric_data_admission_persisted_policy_transitions"
        );
        let test_name = qualified
            .split_once("::")
            .expect("test module has crate prefix")
            .1;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env(TRANSITION_CHILD_ROOT, root)
            .env(TRANSITION_CHILD_DB, database)
            .env(TRANSITION_CHILD_OUTPUT, &output_path)
            .env_remove("BIFROST_MAX_LINE_LENGTH");
        if let Some(setting) = setting {
            command.env("BIFROST_MAX_LINE_LENGTH", setting);
        }
        let output = command.output().expect("run isolated admission stage");
        assert!(
            output.status.success(),
            "stage {stage}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // An incorrectly filtered child must fail here rather than pass with zero tests.
        serde_json::from_slice(
            &std::fs::read(output_path).expect("selected child wrote observation"),
        )
        .unwrap()
    }

    fn observe_persisted_policy_child(root: std::path::PathBuf) {
        use serde_json::json;
        use std::collections::BTreeMap;
        let database = std::env::var_os(TRANSITION_CHILD_DB).expect("child database");
        let output = std::env::var_os(TRANSITION_CHILD_OUTPUT).expect("child output");
        let project: Arc<dyn Project> = Arc::new(
            brokk_bifrost_core::analyzer::project::TestProject::new(&root, Language::Cpp),
        );
        let store = AnalyzerStore::open_persistent(std::path::Path::new(&database)).unwrap();
        let context = store_context_from_store(project.as_ref(), store, false);
        let parses = Arc::new(AtomicUsize::new(0));
        let progress_parses = Arc::clone(&parses);
        let analyzer: TreeSitterAnalyzer<CppAdapter> =
            TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                Arc::clone(&project),
                CppAdapter,
                AnalyzerConfig::default(),
                context,
                Some(Arc::new(move |event| {
                    if event.phase == BuildProgressPhase::Parse {
                        progress_parses.fetch_add(1, Ordering::Relaxed);
                    }
                })),
            )
            .unwrap();
        let unit_names = |units: Vec<CodeUnit>| {
            let mut names: Vec<_> = units
                .into_iter()
                .map(|unit| {
                    (
                        brokk_bifrost_core::path_utils::rel_path_string(unit.source()),
                        unit.short_name().to_owned(),
                    )
                })
                .collect();
            names.sort();
            names
        };
        let mut summary = BTreeMap::new();
        let mut canonical = BTreeMap::new();
        let mut incomplete = BTreeMap::new();
        let mut published = BTreeMap::new();
        for (path, language) in [("data.h", "cpp"), ("data.c", "cpp:c")] {
            let file = ProjectFile::new(root.clone(), path);
            // Summary first: this was the unguarded persisted reuse reported in review.
            summary.insert(
                path,
                analyzer
                    .summary_file_projection(&file)
                    .map(|projection| unit_names(projection.declarations.clone())),
            );
            let scope = AnalyzerQueryScope::new(&analyzer);
            let facts =
                analyzer.canonical_cpp_source_facts(&file, language, &moka::sync::Cache::new(1));
            canonical.insert(path, facts.is_some());
            let reason = match scope.read_completion() {
                Ok(()) => {
                    assert!(facts.is_some());
                    None
                }
                Err(QueryReadIncomplete::StructureUnavailable(unavailable)) => {
                    assert_eq!(unavailable, file);
                    assert!(facts.is_none());
                    Some("StructureUnavailable".to_owned())
                }
                Err(QueryReadIncomplete::SemanticEvidenceUnavailable(reason)) => {
                    assert!(facts.is_none());
                    Some(reason.into_string())
                }
                Err(other) => panic!("unexpected admission read failure: {other:?}"),
            };
            assert!(scope.store_error().is_none());
            incomplete.insert(path, reason);
            let source = project.read_source(&file).unwrap();
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            published.insert(
                path,
                analyzer
                    .store_context
                    .store
                    .contains_parsed_blob(oid, language)
                    .unwrap(),
            );
        }
        // Exercise ordinary SQL-backed consumers, without a new per-reader guard.
        let all = unit_names(analyzer.all_declarations().collect());
        let primary_ranges = unit_names(
            analyzer
                .all_declarations_with_primary_ranges()
                .into_iter()
                .map(|(unit, _)| unit)
                .collect(),
        );
        let mounted = analyzer
            .workspace_declarations_with_primary_ranges(&CancellationToken::new())
            .map(|units| unit_names(units.into_iter().map(|(unit, _)| unit).collect()));
        let generations: BTreeMap<_, _> = analyzer
            .store_context
            .generations
            .iter()
            .map(|(language, generation)| (language.clone(), generation.get()))
            .collect();
        let observation = json!({
            "consumers": {"summary": summary, "canonical": canonical, "incomplete": incomplete,
                "published": published, "all": all, "primary_ranges": primary_ranges, "mounted": mounted},
            "generations": generations,
            "producer_parse_events": parses.load(Ordering::Relaxed),
            "content_identity": analyzer.language_content_identity().as_bytes().to_vec(),
            "read_epoch": brokk_bifrost_analysis::analyzer::read_verification::analysis_epoch_digest().as_bytes().to_vec(),
        });
        std::fs::write(
            std::path::Path::new(&output),
            serde_json::to_vec_pretty(&observation).unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[hardwon(
        "#5408: persisted summaries and bulk declarations reused a blob admitted under another policy"
    )]
    fn numeric_data_admission_persisted_policy_transitions() {
        if let Some(root) = std::env::var_os(TRANSITION_CHILD_ROOT) {
            observe_persisted_policy_child(root.into());
            return;
        }
        for oversized in [false, true] {
            let source = table_with_items(if oversized { 4200 } else { 1400 });
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("data.h", &source)
                .file("data.c", &source)
                .file("healthy.cpp", "int retained() { return 1; }\n")
                .build();
            let database = fixture.root().join("same-store.db");
            let initial_setting = if oversized { Some("0") } else { None };
            let strict_setting = if oversized { None } else { Some("16000") };
            let admitted =
                persisted_policy_stage(fixture.root(), &database, "admitted", initial_setting);
            let warm = persisted_policy_stage(fixture.root(), &database, "warm", initial_setting);
            assert_eq!(admitted["consumers"], warm["consumers"]);
            assert_eq!(admitted["generations"], warm["generations"]);
            assert_eq!(warm["producer_parse_events"], 0);
            for path in ["data.h", "data.c"] {
                assert_eq!(admitted["consumers"]["canonical"][path], true);
                assert_eq!(admitted["consumers"]["published"][path], true);
                assert!(
                    admitted["consumers"]["summary"][path]
                        .as_array()
                        .is_some_and(|units| units.iter().any(|unit| unit[1] == "sibling"))
                );
            }
            let strict =
                persisted_policy_stage(fixture.root(), &database, "strict", strict_setting);
            let fresh = persisted_policy_stage(
                fixture.root(),
                &fixture.root().join("fresh-strict.db"),
                "fresh-strict",
                strict_setting,
            );
            assert_eq!(
                strict["consumers"], fresh["consumers"],
                "reopened strict store must agree with fresh strict control"
            );
            assert_eq!(strict["read_epoch"], fresh["read_epoch"]);
            assert_ne!(admitted["content_identity"], strict["content_identity"]);
            assert_ne!(admitted["read_epoch"], strict["read_epoch"]);
            for language in ["cpp", "cpp:c"] {
                assert_ne!(
                    admitted["generations"][language],
                    strict["generations"][language]
                );
            }
            for path in ["data.h", "data.c"] {
                assert!(strict["consumers"]["summary"][path].is_null());
                assert_eq!(strict["consumers"]["canonical"][path], false);
                assert_eq!(strict["consumers"]["published"][path], false);
                if oversized {
                    assert!(
                        strict["consumers"]["incomplete"][path]
                            .as_str()
                            .is_some_and(|reason| reason.contains("ExcludedNodes")
                                && reason.contains("8192"))
                    );
                } else {
                    assert_eq!(
                        strict["consumers"]["incomplete"][path],
                        "StructureUnavailable"
                    );
                }
            }
            assert!(
                strict["consumers"]["all"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|unit| unit[0] == "healthy.cpp" && unit[1] == "retained")
            );
            // Restore valid default input. For the zero->default case the policy
            // stays default and only the blob changes; a refusal must not poison it.
            if oversized {
                for path in ["data.h", "data.c"] {
                    fixture.file(path).write(table()).unwrap();
                }
            }
            let restored =
                persisted_policy_stage(fixture.root(), &database, "restored-default", None);
            let restored_warm =
                persisted_policy_stage(fixture.root(), &database, "restored-warm", None);
            if oversized {
                assert_eq!(
                    strict["generations"], restored["generations"],
                    "source repair under the same default policy must not rotate the epoch"
                );
            } else {
                for language in ["cpp", "cpp:c"] {
                    assert_ne!(
                        strict["generations"][language],
                        restored["generations"][language]
                    );
                }
            }
            assert_eq!(restored["consumers"], restored_warm["consumers"]);
            assert_eq!(restored["generations"], restored_warm["generations"]);
            assert_eq!(restored_warm["producer_parse_events"], 0);
            for path in ["data.h", "data.c"] {
                assert_eq!(restored["consumers"]["canonical"][path], true);
                assert_eq!(restored["consumers"]["published"][path], true);
                assert!(restored["consumers"]["summary"][path].is_array());
            }
        }
    }
}
