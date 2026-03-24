use brokk_analyzer::{
    AnalyzerConfig, IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile,
    TestProject, TypeHierarchyProvider,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap()
}

fn fixture_analyzer(config: AnalyzerConfig) -> JavaAnalyzer {
    JavaAnalyzer::from_project_with_config(TestProject::new(fixture_root(), Language::Java), config)
}

fn temp_analyzer(
    files: &[(&str, &str)],
    config: AnalyzerConfig,
) -> (tempfile::TempDir, JavaAnalyzer) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    for (path, contents) in files {
        ProjectFile::new(root.clone(), path)
            .write(contents)
            .unwrap();
    }

    let analyzer =
        JavaAnalyzer::from_project_with_config(TestProject::new(root, Language::Java), config);
    (temp, analyzer)
}

#[test]
fn parallel_build_matches_sequential_build_observables() {
    let sequential = fixture_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        memo_cache_budget_bytes: Some(1024 * 1024),
    });
    let parallel = fixture_analyzer(AnalyzerConfig {
        parallelism: Some(4),
        memo_cache_budget_bytes: Some(1024 * 1024),
    });

    assert_eq!(
        sequential.get_all_declarations(),
        parallel.get_all_declarations()
    );

    for fq_name in ["A", "D", "UsePackaged", "ServiceImpl", "EnumClass"] {
        let left = sequential
            .get_definitions(fq_name)
            .into_iter()
            .next()
            .unwrap();
        let right = parallel
            .get_definitions(fq_name)
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(
            sequential.get_direct_children(&left),
            parallel.get_direct_children(&right)
        );
        assert_eq!(sequential.ranges_of(&left), parallel.ranges_of(&right));
        assert_eq!(
            sequential.get_skeleton(&left),
            parallel.get_skeleton(&right)
        );
    }

    let use_packaged = ProjectFile::new(fixture_root(), "UsePackaged.java");
    assert_eq!(
        sequential.imported_code_units_of(&use_packaged),
        parallel.imported_code_units_of(&use_packaged)
    );
    assert_eq!(
        sequential.search_definitions("service", true),
        parallel.search_definitions("service", true)
    );
}

#[test]
fn small_budget_memo_caches_do_not_change_update_results() {
    let config = AnalyzerConfig {
        parallelism: Some(4),
        memo_cache_budget_bytes: Some(256),
    };
    let (_temp, analyzer) = temp_analyzer(
        &[
            ("pkg/Base.java", "package pkg; public class Base {}"),
            (
                "pkg/Derived.java",
                "package pkg; public class Derived extends Base {}",
            ),
            (
                "consumer/Consumer.java",
                "package consumer; import pkg.*; public class Consumer { private Derived derived; private Base base; }",
            ),
        ],
        config.clone(),
    );
    let mut analyzer = analyzer;

    let consumer = analyzer
        .get_definitions("consumer.Consumer")
        .into_iter()
        .next()
        .unwrap();
    let base = analyzer
        .get_definitions("pkg.Base")
        .into_iter()
        .next()
        .unwrap();
    let derived = analyzer
        .get_definitions("pkg.Derived")
        .into_iter()
        .next()
        .unwrap();

    for _ in 0..3 {
        let _ = analyzer.imported_code_units_of(consumer.source());
        let _ = analyzer.referencing_files_of(base.source());
        let _ = analyzer.relevant_imports_for(&consumer);
        let _ = analyzer.get_direct_ancestors(&derived);
        let _ = analyzer.get_direct_descendants(&base);
    }

    let derived_file =
        ProjectFile::new(analyzer.project().root().to_path_buf(), "pkg/Derived.java");
    derived_file
        .write(
            "package pkg; public class Derived extends Base { public int extra() { return 1; } }",
        )
        .unwrap();

    analyzer = analyzer.update(&BTreeSet::from([derived_file]));
    let refreshed = JavaAnalyzer::from_project_with_config(
        TestProject::new(analyzer.project().root().to_path_buf(), Language::Java),
        config,
    );

    assert_eq!(
        analyzer.get_all_declarations(),
        refreshed.get_all_declarations()
    );

    let updated_consumer = analyzer
        .get_definitions("consumer.Consumer")
        .into_iter()
        .next()
        .unwrap();
    let refreshed_consumer = refreshed
        .get_definitions("consumer.Consumer")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        analyzer.imported_code_units_of(updated_consumer.source()),
        refreshed.imported_code_units_of(refreshed_consumer.source())
    );
    assert_eq!(
        analyzer.relevant_imports_for(&updated_consumer),
        refreshed.relevant_imports_for(&refreshed_consumer)
    );

    let updated_base = analyzer
        .get_definitions("pkg.Base")
        .into_iter()
        .next()
        .unwrap();
    let refreshed_base = refreshed
        .get_definitions("pkg.Base")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        analyzer.get_direct_descendants(&updated_base),
        refreshed.get_direct_descendants(&refreshed_base)
    );
    assert!(!analyzer.get_definitions("pkg.Derived.extra").is_empty());
}
