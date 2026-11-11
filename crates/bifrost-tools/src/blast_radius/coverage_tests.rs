use super::*;
use brokk_bifrost_analysis::test_support::commit_all;
use brokk_bifrost_core::test_support::write_file as write;
use git2::Repository;

fn fixture() -> (tempfile::TempDir, Repository) {
    let temp = tempfile::tempdir().expect("temporary repository");
    write(
        temp.path(),
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    write(temp.path(), "src/lib.rs", "pub mod changed;\n");
    write(
        temp.path(),
        "src/changed.rs",
        "pub fn value() -> i32 { 1 }\n",
    );
    let repo = Repository::init(temp.path()).expect("initialize repository");
    (temp, repo)
}

#[test]
fn scope_defaults_and_limits_preserve_reached_file_count() {
    let (temp, repo) = fixture();
    let root = temp.path();
    for index in 0..101 {
        write(
            root,
            &format!("tests/case_{index}.rs"),
            "use fixture::changed::value;\n#[test]\nfn checks_value() { assert_eq!(value(), 1); }\n",
        );
    }
    commit_all(&repo, "base");
    write(root, "src/changed.rs", "pub fn value() -> i32 { 2 }\n");
    let target = commit_all(&repo, "target");
    let request: BlastRadiusParams = serde_json::from_str("{}").expect("JSON request");
    assert_eq!(100, request.max_scopes);
    assert_eq!(100, BlastRadiusParams::default().max_scopes);
    let error = BlastRadiusParams {
        max_scopes: 0,
        ..request
    }
    .validate()
    .expect_err("zero is invalid");
    assert!(error.contains("1") && error.contains("1000"), "{error}");
    let result = blast_radius_at_root(
        root,
        None,
        BlastRadiusParams {
            target: Some(target.to_string()),
            ..BlastRadiusParams::default()
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("blast radius");
    assert_eq!(101, result.analysis.reached_test_file_count, "{result:#?}");
    assert!(result.test_scopes.len() <= 100, "{result:#?}");
    let one_scope = blast_radius_at_root(
        root,
        None,
        BlastRadiusParams {
            target: Some(target.to_string()),
            max_scopes: 1,
            ..BlastRadiusParams::default()
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("coalesced blast radius");
    assert_eq!(1, one_scope.test_scopes.len());
    assert_eq!(101, one_scope.analysis.reached_test_file_count);
    assert!(
        one_scope
            .render_text(RenderOptions::default())
            .contains("Test files reached through structured file dependencies: 101")
    );
}

#[test]
fn changed_and_missing_functions_render_distinct_outcomes() {
    let (temp, repo) = fixture();
    let root = temp.path();
    write(
        root,
        "src/changed.rs",
        "pub fn value() -> i32 { 1 }\npub fn removed() -> i32 { 1 }\n",
    );
    write(
        root,
        "tests/value.rs",
        "use fixture::changed::value;\n#[test]\nfn checks_value() { assert_eq!(value(), 1); }\n",
    );
    commit_all(&repo, "base");
    write(
        root,
        "src/changed.rs",
        "pub fn value() -> i32 { 2 }\npub fn uncovered() -> i32 { 2 }\n",
    );
    let target = commit_all(&repo, "target");
    let blast = blast_radius_at_root(
        root,
        None,
        BlastRadiusParams {
            target: Some(target.to_string()),
            ..BlastRadiusParams::default()
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("blast radius");
    let removed = blast
        .changed_callables
        .iter()
        .find(|change| {
            change
                .before
                .as_ref()
                .is_some_and(|symbol| symbol.name == "removed")
        })
        .expect("deleted callable");
    assert!(
        removed.changes.contains(&CallableChangeTag::Deleted),
        "{removed:#?}"
    );
    let missing = missing_tests_at_root(
        root,
        None,
        MissingTestsParams {
            base: None,
            target: Some(target.to_string()),
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("missing tests");
    assert_eq!(1, missing.analysis.reached_function_count, "{missing:#?}");
    assert_eq!(1, missing.analysis.missing_function_count, "{missing:#?}");
    assert_eq!(
        0, missing.analysis.indeterminate_function_count,
        "{missing:#?}"
    );
    assert!(
        missing
            .render_text(RenderOptions::default())
            .contains("1 reached, 1 missing, 0 indeterminate")
    );
}

#[test]
fn external_test_and_production_caller_reach_changed_function() {
    let (temp, repo) = fixture();
    let root = temp.path();
    write(
        root,
        "src/changed.rs",
        "pub fn value() -> i32 { 1 }\npub fn wrapper() -> i32 { value() }\n",
    );
    write(
        root,
        "tests/value.rs",
        "use fixture::changed::value;\n#[test]\nfn checks_value() { assert_eq!(value(), 1); }\n",
    );
    commit_all(&repo, "base");
    write(
        root,
        "src/changed.rs",
        "pub fn value() -> i32 { 2 }\npub fn wrapper() -> i32 { value() }\n",
    );
    let target = commit_all(&repo, "target");
    let result = missing_tests_at_root(
        root,
        None,
        MissingTestsParams {
            base: None,
            target: Some(target.to_string()),
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("missing tests");
    assert_eq!(1, result.analysis.candidate_function_count, "{result:#?}");
    assert_eq!(1, result.analysis.reached_function_count, "{result:#?}");
    assert_eq!(0, result.analysis.missing_function_count, "{result:#?}");
}

#[test]
fn incomplete_blast_radius_text_names_the_reason() {
    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_core::analyzer::project::FilesystemProject;
    use std::sync::Arc;

    let (temp, repo) = fixture();
    let root = temp.path();
    commit_all(&repo, "base");
    write(
        root,
        "src/changed.rs",
        "pub fn value() -> i32 { 2 }\n#[test]\nfn checks_value() { assert_eq!(value(), 2); }\n",
    );
    let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
        .expect("workspace analyzer");
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let result = blast_radius_at_root(
        root,
        Some(workspace.analyzer()),
        BlastRadiusParams::default(),
        &DiffAnalysisOptions::default(),
        &cancellation,
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("partial blast radius");
    assert!(
        result
            .analysis
            .incomplete_reasons
            .contains(&BlastRadiusIncompleteReason::TargetGraphCancelled),
        "{result:#?}"
    );
    assert!(
        result
            .render_text(RenderOptions::default())
            .contains("TargetGraphCancelled")
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "e64771ef37bf: same-file test calls were classified as lacking an enclosing declaration"
)]
fn same_file_test_call_reaches_changed_function() {
    let (temp, repo) = fixture();
    let root = temp.path();
    write(
        root,
        "src/changed.rs",
        "pub fn value() -> i32 { 1 }\npub fn wrapper() -> i32 { value() }\n#[test]\nfn checks_value() { assert_eq!(value(), 1); }\n",
    );
    commit_all(&repo, "base");
    write(
        root,
        "src/changed.rs",
        "pub fn value() -> i32 { 2 }\npub fn wrapper() -> i32 { value() }\n#[test]\nfn checks_value() { assert_eq!(value(), 2); }\n",
    );
    let target = commit_all(&repo, "target");
    let result = missing_tests_at_root(
        root,
        None,
        MissingTestsParams {
            base: None,
            target: Some(target.to_string()),
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("missing tests");
    assert_eq!(1, result.analysis.candidate_function_count, "{result:#?}");
    assert_eq!(1, result.analysis.reached_function_count, "{result:#?}");
    assert_eq!(0, result.analysis.missing_function_count, "{result:#?}");
    assert_eq!(
        0, result.analysis.indeterminate_function_count,
        "{result:#?}"
    );
}

#[test]
fn renamed_dependency_combines_old_and_new_test_distances() {
    let temp = tempfile::tempdir().expect("temporary repository");
    let root = temp.path();
    write(root, "src/a.py", "def value():\n    return 1\n");
    write(
        root,
        "src/b.py",
        "from src.a import value\ndef wrapped():\n    return value()\n",
    );
    write(
        root,
        "tests/test_service.py",
        "from src.b import wrapped\ndef test_value():\n    assert wrapped() == 1\n",
    );
    let repo = Repository::init(root).expect("initialize repository");
    commit_all(&repo, "base");
    std::fs::rename(root.join("src/a.py"), root.join("src/c.py")).expect("rename dependency");
    write(
        root,
        "src/b.py",
        "from src.c import value\ndef wrapped():\n    return value()\n",
    );
    write(
        root,
        "tests/test_service.py",
        "from src.c import value\nfrom src.b import wrapped\ndef test_value():\n    assert value() == wrapped()\n",
    );
    let target = commit_all(&repo, "target");
    let result = blast_radius_at_root(
        root,
        None,
        BlastRadiusParams {
            target: Some(target.to_string()),
            ..BlastRadiusParams::default()
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("blast radius");
    let scope = result
        .test_scopes
        .iter()
        .find(|scope| scope.path == "tests/test_service.py")
        .expect("test scope");
    assert_eq!(0, scope.minimum_dependency_distance, "{result:#?}");
    assert_eq!(2, scope.maximum_dependency_distance, "{result:#?}");
}

#[test]
fn deleted_rust_dependency_keeps_old_side_test_recovery_when_python_is_added() {
    let (temp, repo) = fixture();
    let root = temp.path();
    write(root, "src/lib.rs", "pub mod old;\n");
    write(root, "src/old.rs", "pub fn value() -> i32 { 1 }\n");
    write(
        root,
        "tests/value.rs",
        "use fixture::old::value;\n#[test]\nfn checks_value() { assert_eq!(value(), 1); }\n",
    );
    commit_all(&repo, "base");
    std::fs::remove_file(root.join("src/old.rs")).expect("delete Rust dependency");
    write(root, "src/new.py", "def value():\n    return 1\n");
    let target = commit_all(&repo, "target");
    let result = blast_radius_at_root(
        root,
        None,
        BlastRadiusParams {
            target: Some(target.to_string()),
            ..BlastRadiusParams::default()
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("blast radius");
    assert!(
        result
            .test_scopes
            .iter()
            .any(|scope| scope.path == "tests/value.rs"),
        "{result:#?}"
    );
}

#[test]
fn nested_directory_scope_collapse_counts_each_reached_test_once() {
    let temp = tempfile::tempdir().expect("temporary repository");
    let root = temp.path();
    write(root, "src/value.py", "def value():\n    return 1\n");
    for path in [
        "tests/a/test_one.py",
        "tests/a/test_two.py",
        "tests/b/test_three.py",
    ] {
        write(
            root,
            path,
            "from src.value import value\ndef test_value():\n    assert value() == 1\n",
        );
    }
    let repo = Repository::init(root).expect("initialize repository");
    commit_all(&repo, "base");
    write(root, "src/value.py", "def value():\n    return 2\n");
    let target = commit_all(&repo, "target");
    let result = blast_radius_at_root(
        root,
        None,
        BlastRadiusParams {
            target: Some(target.to_string()),
            max_scopes: 1,
            ..BlastRadiusParams::default()
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("blast radius");
    assert_eq!(3, result.analysis.reached_test_file_count, "{result:#?}");
    assert_eq!(1, result.test_scopes.len(), "{result:#?}");
    assert_eq!(
        3,
        result
            .test_scopes
            .iter()
            .map(|scope| scope.reached_file_count)
            .sum::<usize>(),
        "{result:#?}"
    );
}

#[test]
fn usable_incomplete_graph_keeps_proven_test_reachability_and_reasons() {
    let temp = tempfile::tempdir().expect("temporary repository");
    let root = temp.path();
    write(
        root,
        "A/A.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
    );
    write(
        root,
        "B/B.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
    );
    write(root, "A/GlobalUsings.cs", "global using Shared;\n");
    write(
        root,
        "A/Shared.cs",
        "namespace Shared;\npublic class Value {\n public int Get() => 1;\n public int Never() => 1;\n}\n",
    );
    write(
        root,
        "A/ProjectATest.cs",
        "public class ProjectATest { [Fact] public void Runs() { new Value().Get(); } }\n",
    );
    write(root, "B/Other.cs", "public class Other { }\n");
    let repo = Repository::init(root).expect("initialize repository");
    commit_all(&repo, "base");
    write(
        root,
        "A/Shared.cs",
        "namespace Shared;\npublic class Value {\n public int Get() => 2;\n public int Never() => 2;\n}\n",
    );
    let target = commit_all(&repo, "target");
    let result = missing_tests_at_root(
        root,
        None,
        MissingTestsParams {
            base: None,
            target: Some(target.to_string()),
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("missing tests");
    assert_eq!(
        FileGraphCompletion::Incomplete,
        result.analysis.file_graph_completion,
        "{result:#?}"
    );
    assert_eq!(1, result.analysis.reached_function_count, "{result:#?}");
    assert_eq!(
        1, result.analysis.indeterminate_function_count,
        "{result:#?}"
    );
    assert_eq!(0, result.analysis.missing_function_count, "{result:#?}");
    assert!(
        result
            .render_text(RenderOptions::default())
            .contains("incomplete: [CompilationScopeUnresolved]"),
        "{result:#?}"
    );
}

#[test]
fn changed_outer_function_resolves_when_nested_function_shares_its_end_line() {
    let temp = tempfile::tempdir().expect("temporary repository");
    let root = temp.path();
    write(
        root,
        "src/value.py",
        "def outer():\n    def inner():\n        return 1\n",
    );
    write(
        root,
        "tests/test_value.py",
        "from src.value import outer\ndef test_outer():\n    outer()\n",
    );
    let repo = Repository::init(root).expect("initialize repository");
    commit_all(&repo, "base");
    write(
        root,
        "src/value.py",
        "def outer():\n    def inner():\n        return 2\n",
    );
    let target = commit_all(&repo, "target");
    let result = missing_tests_at_root(
        root,
        None,
        MissingTestsParams {
            base: None,
            target: Some(target.to_string()),
        },
        &DiffAnalysisOptions::default(),
        &CancellationToken::default(),
        &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
    )
    .expect("missing tests");
    // The changed outer function resolves to its full span and is classified,
    // not indeterminate. The native Python resolver links `from src.value
    // import outer` in test_outer, so the candidate is reached.
    assert_eq!(1, result.analysis.candidate_function_count, "{result:#?}");
    assert_eq!(1, result.analysis.reached_function_count, "{result:#?}");
    assert_eq!(0, result.analysis.missing_function_count, "{result:#?}");
    assert_eq!(
        0, result.analysis.indeterminate_function_count,
        "{result:#?}"
    );
}
