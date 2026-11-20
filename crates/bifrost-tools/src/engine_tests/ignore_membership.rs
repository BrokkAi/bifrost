use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::multi_analyzer::{MultiAnalyzer, resolve_analyzer};
use brokk_bifrost_analysis::analyzer::read_verification::{UpdateDeltaEvent, capture_update_delta};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogOptions, DependencyPackLimits, SemanticModelActivationRequest,
    SemanticModelRuntimeLimits, SemanticPackCatalog,
};
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
    TreeSitterAnalyzer, full_update_count_for_test, membership_scan_count_for_test,
    store_context_from_store,
};
use brokk_bifrost_analysis::analyzer::workspace::{
    DependencyPackEcosystem, DependencyPackWorkspaceContext, WorkspaceAnalyzer,
};
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::{
    FilesystemProject, IgnoreTestEnvironment, Project, WorkspaceFileListingCache,
    age_ignore_test_inputs,
};
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::path_normalization::NormalizePath;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use brokk_bifrost_python_analysis::analyzer::python::PythonAdapter;
use brokk_bifrost_test_macros::hardwon;
use std::collections::BTreeSet;
use std::sync::Arc;

struct Fixture {
    _env: brokk_bifrost_core::analyzer::project::IgnoreTestEnvironment,
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
    cache: Arc<WorkspaceFileListingCache>,
    project: Arc<dyn Project>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_files(&[])
    }

    fn with_files(files: &[(&str, &str)]) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let env = brokk_bifrost_core::analyzer::project::IgnoreTestEnvironment::new(
            &temp.path().join("home"),
        );
        let root = temp.path().join("source");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap().normalize();
        git2::Repository::init(&root).unwrap();
        std::fs::write(root.join("keep.py"), "def retained():\n    return 1\n").unwrap();
        std::fs::write(
            root.join("hidden.py"),
            "def disappearing():\n    return 2\n",
        )
        .unwrap();
        std::fs::write(root.join("first.rb"), "class FirstLanguage\nend\n").unwrap();
        std::fs::write(root.join(".bifrostignore"), "").unwrap();
        std::fs::write(root.join(".gitignore"), "").unwrap();
        for (path, source) in files {
            ProjectFile::new(root.clone(), *path).write(source).unwrap();
        }
        // Ignore receipt capture requires old input and parent timestamps.
        // ctime cannot be backdated; establish a quiet capture window.
        brokk_bifrost_core::analyzer::project::age_ignore_test_inputs(&root);
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project =
            Arc::new(FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap());
        assert_eq!(
            root.as_path(),
            project.root(),
            "fixture and project must use the same normalized root for counter lookups"
        );
        Self {
            _env: env,
            _temp: temp,
            root,
            cache,
            project,
        }
    }

    fn build(&self) -> WorkspaceAnalyzer {
        WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&self.project),
            AnalyzerConfig::default(),
        )
        .unwrap()
    }

    fn changes(&self, paths: &[&str]) -> BTreeSet<ProjectFile> {
        paths
            .iter()
            .map(|path| ProjectFile::new(self.root.clone(), *path))
            .collect()
    }

    fn fresh(&self) -> WorkspaceAnalyzer {
        let project = Arc::new(FilesystemProject::new(&self.root).unwrap());
        WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap()
    }
}

fn rendered(analyzer: &dyn IAnalyzer) -> String {
    serde_json::to_string_pretty(&crate::searchtools::search_symbols(
        analyzer,
        crate::searchtools::SearchSymbolsParams {
            patterns: vec![".*".to_owned()],
            include_tests: true,
            limit: 100,
        },
    ))
    .unwrap()
}

#[test]
fn ignore_membership_workspace_hide_reveal_and_reported_hidden_path() {
    let fixture = Fixture::new();
    let mut current = fixture.build();
    assert!(rendered(current.analyzer()).contains("disappearing"));
    for (rules, reported) in [
        ("hidden.py\n", vec![".bifrostignore"]),
        ("", vec![".bifrostignore"]),
        ("hidden.py\n", vec![".bifrostignore", "hidden.py"]),
        ("", vec![".bifrostignore"]),
        ("first.rb\n", vec![".gitignore"]),
        ("", vec![".gitignore"]),
    ] {
        let ignore = if reported.contains(&".gitignore") {
            ".gitignore"
        } else {
            ".bifrostignore"
        };
        std::fs::write(fixture.root.join(ignore), rules).unwrap();
        let before = full_update_count_for_test(&fixture.root);
        let walks = fixture.cache.walk_count();
        current = current.update(&fixture.changes(&reported));
        assert_eq!(
            fixture.cache.walk_count(),
            walks + 1,
            "a rebuild must reuse NEW without enumerating again"
        );
        assert!(full_update_count_for_test(&fixture.root) > before);
        assert_eq!(
            rendered(current.analyzer()),
            rendered(fixture.fresh().analyzer()),
            "{ignore} {rules:?}"
        );
    }
}

#[test]
fn ignore_membership_direct_multi_hide_reveal() {
    let fixture = Fixture::new();
    let workspace = fixture.build();
    let mut current = resolve_analyzer::<MultiAnalyzer>(workspace.analyzer())
        .unwrap()
        .clone();
    for rules in ["hidden.py\nfirst.rb\n", ""] {
        std::fs::write(fixture.root.join(".gitignore"), rules).unwrap();
        current = current.update(&fixture.changes(&[".gitignore"]));
        assert_eq!(rendered(&current), rendered(fixture.fresh().analyzer()));
    }
}

#[test]
fn ignore_membership_direct_tree_sitter_hide_reveal() {
    let fixture = Fixture::new();
    let mut current = TreeSitterAnalyzer::new_with_config(
        Arc::clone(&fixture.project),
        PythonAdapter::default(),
        AnalyzerConfig::default(),
    );
    for rules in ["hidden.py\n", ""] {
        std::fs::write(fixture.root.join(".bifrostignore"), rules).unwrap();
        current = current.update(&fixture.changes(&[".bifrostignore"]));
        let fresh = TreeSitterAnalyzer::new_with_config(
            Arc::new(FilesystemProject::new(&fixture.root).unwrap()),
            PythonAdapter::default(),
            AnalyzerConfig::default(),
        );
        assert_eq!(rendered(&current), rendered(&fresh));
    }
}

#[test]
fn ignore_membership_core_excludes_file_hide_reveal() {
    let fixture = Fixture::new();
    let rules = fixture._temp.path().join("global-ignore");
    std::fs::write(&rules, "").unwrap();
    git2::Repository::open(&fixture.root)
        .unwrap()
        .config()
        .unwrap()
        .set_str("core.excludesFile", rules.to_str().unwrap())
        .unwrap();
    fixture.project.invalidate_cached_file_listing();
    brokk_bifrost_core::analyzer::project::age_ignore_test_inputs(&fixture.root);
    let mut current = fixture.build();
    for contents in ["hidden.py\nfirst.rb\n", ""] {
        std::fs::write(&rules, contents).unwrap();
        current = current.update(&BTreeSet::new());
        assert_eq!(
            rendered(current.analyzer()),
            rendered(fixture.fresh().analyzer())
        );
    }
}

#[test]
fn ignore_membership_reported_content_create_delete_stay_incremental() {
    let fixture = Fixture::new();
    let mut current = fixture.build();
    let rebuilds = full_update_count_for_test(&fixture.root);
    let walks = fixture.cache.walk_count();
    std::fs::write(
        fixture.root.join("keep.py"),
        "def changed():\n    return 3\n",
    )
    .unwrap();
    current = current.update(&fixture.changes(&["keep.py"]));
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    assert_eq!(fixture.cache.walk_count(), walks);
    std::fs::write(fixture.root.join("added.py"), "def added():\n    pass\n").unwrap();
    current = current.update(&fixture.changes(&["added.py"]));
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    assert_eq!(fixture.cache.walk_count(), walks);
    std::fs::remove_file(fixture.root.join("added.py")).unwrap();
    current = current.update(&fixture.changes(&["added.py"]));
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    assert_eq!(fixture.cache.walk_count(), walks);
    assert_eq!(
        rendered(current.analyzer()),
        rendered(fixture.fresh().analyzer())
    );
}

#[test]
#[hardwon("#12752: an update naming an ignored existing file indexed it")]
fn ignore_membership_named_ignored_existing_file_is_not_indexed() {
    let fixture = Fixture::new();
    let mut current = fixture.build();
    // One update that edits the rule and names the file it hides.
    std::fs::write(fixture.root.join(".bifrostignore"), "hidden.py\n").unwrap();
    current = current.update(&fixture.changes(&[".bifrostignore", "hidden.py"]));
    assert_eq!(
        rendered(current.analyzer()),
        rendered(fixture.fresh().analyzer())
    );
    // The file is outside the selection before and after: naming it again
    // must not parse or index it, and must not rebuild.
    std::fs::write(
        fixture.root.join("hidden.py"),
        "def edited_while_ignored():\n    return 3\n",
    )
    .unwrap();
    let rebuilds = full_update_count_for_test(&fixture.root);
    current = current.update(&fixture.changes(&["hidden.py"]));
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    let answer = rendered(current.analyzer());
    assert!(!answer.contains("edited_while_ignored"), "{answer}");
    assert_eq!(answer, rendered(fixture.fresh().analyzer()));
}

/// The update's delta covers the one reported path and the one folded path:
/// every admission requests exactly two paths.
fn assert_delta_covers_two_paths(events: &[UpdateDeltaEvent], certified: bool) {
    assert!(
        events.iter().any(|event| matches!(
            event,
            UpdateDeltaEvent::Decision { certified: decided, .. } if *decided == certified
        )),
        "{events:?}"
    );
    let admissions = events
        .iter()
        .filter_map(|event| match event {
            UpdateDeltaEvent::Admission { requested, .. } => Some(*requested),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !admissions.is_empty() && admissions.iter().all(|requested| *requested == 2),
        "{events:?}"
    );
}

#[test]
#[hardwon(
    "#12752: an unreported addition rebuilt the workspace and dropped the published semantic overlay"
)]
fn ignore_membership_unreported_additions_and_removals_stay_incremental() {
    let fixture = Fixture::new();
    // A cached listing changes only through reported events, so an unreported
    // addition needs a project that lists the directory afresh.
    let mut current = fixture.fresh();
    // Dependency evidence makes the update decide whether its delta is certified.
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let cancellation = CancellationToken::default();
    let activation = SemanticModelActivationRequest {
        host_activation:
            brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        approximate_standard_libraries: Vec::new(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let discovery = current.activate_dependency_packs(
        &AnalyzerConfig::default(),
        &[DependencyPackEcosystem::Python],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    assert!(discovery.complete(), "{discovery:#?}");
    let rebuilds = full_update_count_for_test(&fixture.root);
    std::fs::write(fixture.root.join("added.py"), "def added():\n    pass\n").unwrap();
    std::fs::write(
        fixture.root.join("keep.py"),
        "def changed():\n    return 3\n",
    )
    .unwrap();
    // The uncached update lists afresh, and a listing taken inside the racy
    // window is unconfirmed (it refuses certified deltas), so age the writes.
    age_ignore_test_inputs(&fixture.root);
    let (updated, events) = capture_update_delta(|| current.update(&fixture.changes(&["keep.py"])));
    current = updated;
    assert_delta_covers_two_paths(&events, true);
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    assert_eq!(
        rendered(current.analyzer()),
        rendered(fixture.fresh().analyzer())
    );
    // A folded removal reaches the certified delta like a folded addition.
    std::fs::remove_file(fixture.root.join("added.py")).unwrap();
    age_ignore_test_inputs(&fixture.root);
    let (updated, events) = capture_update_delta(|| current.update(&fixture.changes(&["keep.py"])));
    current = updated;
    assert_delta_covers_two_paths(&events, true);
    // The same deletion, reported, reaches the same decision.
    std::fs::write(fixture.root.join("added.py"), "def added():\n    pass\n").unwrap();
    age_ignore_test_inputs(&fixture.root);
    current = current.update(&fixture.changes(&["keep.py", "added.py"]));
    std::fs::remove_file(fixture.root.join("added.py")).unwrap();
    age_ignore_test_inputs(&fixture.root);
    let (updated, events) =
        capture_update_delta(|| current.update(&fixture.changes(&["keep.py", "added.py"])));
    current = updated;
    assert_delta_covers_two_paths(&events, true);
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    // An unreported new file that the ignore rules exclude is not indexed.
    std::fs::write(fixture.root.join(".bifrostignore"), "ignored_new.py\n").unwrap();
    current = current.update(&fixture.changes(&[".bifrostignore"]));
    let rebuilds = full_update_count_for_test(&fixture.root);
    std::fs::write(
        fixture.root.join("ignored_new.py"),
        "def sneaky():\n    pass\n",
    )
    .unwrap();
    current = current.update(&fixture.changes(&["keep.py"]));
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    assert!(!rendered(current.analyzer()).contains("sneaky"));
    std::fs::remove_file(fixture.root.join("ignored_new.py")).unwrap();
    current = current.update(&fixture.changes(&["keep.py"]));
    assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
    assert_eq!(
        rendered(current.analyzer()),
        rendered(fixture.fresh().analyzer())
    );
}

#[test]
#[hardwon("#12752: a named ignored configuration input was dropped from the update")]
fn ignore_membership_named_ignored_configuration_input_still_updates() {
    let fixture = Fixture::with_files(&[
        (
            "setup.py",
            "from setuptools import setup\nsetup(packages=['pkg'], package_dir={'': 'src'})\n",
        ),
        ("src/pkg/model.py", "class Widget:\n    pass\n"),
        (".bifrostignore", "setup.py\n"),
    ]);
    let current = fixture.build();
    let names = |analyzer: &dyn IAnalyzer| {
        let mut names = ["pkg.model.Widget", "src.pkg.model.Widget"]
            .map(|name| (name, analyzer.get_definitions(name).len()))
            .to_vec();
        names.sort();
        names
    };
    assert_eq!(
        names(current.analyzer()),
        [("pkg.model.Widget", 1), ("src.pkg.model.Widget", 0)]
    );
    // setup.py is outside the selection but Python still reads it by path.
    std::fs::write(
        fixture.root.join("setup.py"),
        "from setuptools import setup\nsetup()\n",
    )
    .unwrap();
    let updated = current.update(&fixture.changes(&["setup.py"]));
    let fresh = fixture.fresh();
    assert_eq!(names(updated.analyzer()), names(fresh.analyzer()));
    assert_eq!(
        names(updated.analyzer()),
        [("pkg.model.Widget", 0), ("src.pkg.model.Widget", 1)]
    );
}

/// The configuration bytes the store retains for the Rust workspace snapshot.
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
)]
fn rust_configuration_rows(workspace: &WorkspaceAnalyzer) -> Vec<String> {
    let conn = workspace
        .store()
        .expect("the workspace has a store")
        .read_conn()
        .unwrap();
    conn.prepare(
        "SELECT v.rel_path || ': ' || CAST(s.source_bytes AS TEXT) \
         FROM workspace_file_versions v \
         JOIN workspace_input_sources s ON s.content_oid = v.blob_oid \
         WHERE v.lang = 'rust' AND v.input_kind = 'configuration' AND v.valid_until IS NULL \
         ORDER BY 1",
    )
    .unwrap()
    .query_map([], |row| row.get::<_, String>(0))
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

#[test]
#[hardwon(
    "#12752: an ignored Cargo-included configuration input was dropped by the outer membership filter"
)]
fn ignore_membership_ignored_cargo_included_input_still_updates() {
    assert_ignored_cargo_included_input_updates("flags.rs");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12752: a Cargo-included non-.rs configuration file was not routed to the Rust delegate"
)]
fn ignore_membership_ignored_cargo_included_toml_input_still_updates() {
    assert_ignored_cargo_included_input_updates("flags.toml");
}

fn assert_ignored_cargo_included_input_updates(name: &str) {
    let included_path = format!(".cargo/{name}");
    let include = format!("include = ['{name}']\n");
    let ignore = format!("{included_path}\n");
    let fixture = Fixture::with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("src/lib.rs", "pub fn example() {}\n"),
        (".cargo/config.toml", &include),
        (
            included_path.as_str(),
            "[build]\ntarget = 'x86_64-unknown-linux-gnu'\n",
        ),
        (".bifrostignore", &ignore),
    ]);
    let current = fixture.build();
    let direct = resolve_analyzer::<MultiAnalyzer>(current.analyzer())
        .unwrap()
        .clone();
    let before = rust_configuration_rows(&current);
    assert!(
        before
            .iter()
            .any(|row| row.contains("x86_64-unknown-linux-gnu")),
        "the ignored included file is part of the captured configuration: {before:?}"
    );
    // Cargo selected the ignored file as configuration, regardless of its extension.
    std::fs::write(
        fixture.root.join(&included_path),
        "[build]\ntarget = 'aarch64-unknown-linux-gnu'\n",
    )
    .unwrap();
    let changes = fixture.changes(&[included_path.as_str()]);
    let expected = rust_configuration_rows(&fixture.fresh());
    let direct = WorkspaceAnalyzer::Multi(Box::new(direct.update(&changes)));
    assert_eq!(
        rust_configuration_rows(&direct),
        expected,
        "direct multi update"
    );
    let updated = current.update(&changes);
    let after = rust_configuration_rows(&updated);
    assert_eq!(after, expected);
    assert!(
        after
            .iter()
            .any(|row| row.contains("aarch64-unknown-linux-gnu")),
        "{after:?}"
    );
}

fn rendered_composer_lookup(analyzer: &dyn IAnalyzer) -> String {
    use crate::searchtools::scan_usages::{
        ScanUsagesExecutionContext, scan_usages_by_reference_with_context,
    };
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_core::cancellation::CancellationToken;
    let scope = AnalyzerQueryScope::new(analyzer);
    // A small real query budget exposes Composer's supplemental resolution
    // scope without creating thousands of otherwise irrelevant fixture files.
    let context = ScanUsagesExecutionContext::with_limits(
        CancellationToken::default(),
        2,
        2,
        1_000_000,
        1000,
    );
    let result = scan_usages_by_reference_with_context(
        analyzer,
        scope.token(),
        crate::searchtools::ScanUsagesByReferenceParams {
            symbols: vec!["App.Domain.Service.run".to_owned()],
            include_tests: true,
            paths: None,
            include_same_owner: true,
        },
        &context,
    );
    serde_json::to_string_pretty(&result).unwrap()
}

#[test]
fn ignore_membership_composer_hide_reveal_rebuilds_wrappers() {
    let mut files = vec![
        (
            "composer.json".to_owned(),
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#.to_owned(),
        ),
        (
            "src/Domain/Service.php".to_owned(),
            "<?php\nnamespace App\\Domain;\nclass Service { public function run(): void {} }\n"
                .to_owned(),
        ),
    ];
    for index in 0..6 {
        files.push((
            format!("src/Widget{index}.php"),
            format!("<?php\nnamespace App;\nclass Widget{index} {{}}\n"),
        ));
    }
    let files = files
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    let fixture = Fixture::with_files(&files);
    let mut current = fixture.build();
    let visible = rendered_composer_lookup(current.analyzer());
    assert!(visible.contains("\"resolved\": 1"), "{visible}");
    for rules in ["composer.json\n", ""] {
        // Composer is also readable explicitly when ignored. Vary its bytes
        // while changing membership, reporting only the ignore edit, so a
        // wrapper that carries the old autoload state cannot pass parity.
        let manifest = if rules.is_empty() { files[0].1 } else { "{}" };
        std::fs::write(fixture.root.join("composer.json"), manifest).unwrap();
        std::fs::write(fixture.root.join(".gitignore"), rules).unwrap();
        let before = full_update_count_for_test(&fixture.root);
        current = current.update(&fixture.changes(&[".gitignore"]));
        assert!(full_update_count_for_test(&fixture.root) > before);
        let answer = rendered_composer_lookup(current.analyzer());
        assert_eq!(answer, rendered_composer_lookup(fixture.fresh().analyzer()));
        if rules.is_empty() {
            assert_eq!(answer, visible);
        } else {
            assert_ne!(
                answer, visible,
                "the rendered query must depend on Composer's autoload scope"
            );
        }
    }
}

#[test]
fn ignore_membership_large_workspace_point_updates_do_not_observe_full_selection() {
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_selection_observation_count_for_test;
    // The assertions count full-selection observations, walks and full
    // updates, which do not scale with the file count. Each fresh comparison
    // analyzes every filler file, so a few hundred keep CI time bounded.
    let files = (0..200)
        .map(|index| {
            (
                format!("filler_{index:04}.py"),
                format!("def filler_{index:04}():\n    pass\n"),
            )
        })
        .collect::<Vec<_>>();
    let files = files
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<Vec<_>>();
    let fixture = Fixture::with_files(&files);
    let mut current = fixture.build();
    let walks = fixture.cache.walk_count();
    let rebuilds = full_update_count_for_test(&fixture.root);
    let answer = |analyzer: &dyn IAnalyzer| {
        let result = crate::searchtools::search_symbols(
            analyzer,
            crate::searchtools::SearchSymbolsParams {
                patterns: vec!["latency_probe|incremental_added|disappearing".to_owned()],
                include_tests: true,
                limit: 100,
            },
        );
        assert!(
            result.total_files > 0,
            "the product query must select real symbols"
        );
        serde_json::to_string_pretty(&result).unwrap()
    };
    for (path, source) in [
        ("keep.py", "def latency_probe():\n    return 2\n"),
        ("probe.py", "def incremental_added():\n    pass\n"),
    ] {
        std::fs::write(fixture.root.join(path), source).unwrap();
        let observations = full_selection_observation_count_for_test(&fixture.root);
        current = current.update(&fixture.changes(&[path]));
        assert_eq!(
            full_selection_observation_count_for_test(&fixture.root),
            observations,
            "a reported point update must not observe the full selection"
        );
        assert_eq!(fixture.cache.walk_count(), walks);
        assert_eq!(full_update_count_for_test(&fixture.root), rebuilds);
        assert_eq!(
            answer(current.analyzer()),
            answer(fixture.fresh().analyzer())
        );
    }
    let observations = full_selection_observation_count_for_test(&fixture.root);
    std::fs::write(
        fixture.root.join(".bifrostignore"),
        "probe.py\nfiller_0000.py\n",
    )
    .unwrap();
    current = current.update(&fixture.changes(&[".bifrostignore"]));
    assert!(full_selection_observation_count_for_test(&fixture.root) > observations);
    assert!(full_update_count_for_test(&fixture.root) > rebuilds);
    assert_eq!(fixture.cache.walk_count(), walks + 1);
    assert_eq!(
        answer(current.analyzer()),
        answer(fixture.fresh().analyzer())
    );
}

#[test]
fn ignore_membership_point_changes_from_another_generation_require_full_observation() {
    let fixture = Fixture::new();
    let original = fixture.build();
    let walks = fixture.cache.walk_count();
    std::fs::write(fixture.root.join("Added.java"), "class BranchAdded {}\n").unwrap();
    let other = original.update(&fixture.changes(&["Added.java"]));
    assert!(rendered(other.analyzer()).contains("BranchAdded"));
    assert_eq!(fixture.cache.walk_count(), walks);
    std::fs::write(
        fixture.root.join("keep.py"),
        "def latest_branch():\n    pass\n",
    )
    .unwrap();
    let updated = original.update(&fixture.changes(&["keep.py"]));
    assert_eq!(
        rendered(updated.analyzer()),
        rendered(fixture.fresh().analyzer())
    );
}

#[cfg(unix)]
#[test]
fn ignore_membership_first_and_last_language_file_change_omission_identity() {
    let fixture = Fixture::new();
    // A file symlink with no extension is adopted only while C++ is present.
    std::os::unix::fs::symlink(fixture.root.join("keep.py"), fixture.root.join("adopted")).unwrap();
    fixture.project.invalidate_cached_file_listing();
    brokk_bifrost_core::analyzer::project::age_ignore_test_inputs(&fixture.root);
    let mut current = fixture.build();
    let identity = |workspace: &WorkspaceAnalyzer| {
        resolve_analyzer::<brokk_bifrost_python_analysis::analyzer::python::PythonAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap()
        .workspace_content_identity()
        .unwrap()
    };
    let before = identity(&current);
    let walks = fixture.cache.walk_count();
    std::fs::write(fixture.root.join("first.cpp"), "int first;\n").unwrap();
    current = current.update(&fixture.changes(&["first.cpp"]));
    let added = identity(&current);
    assert_ne!(
        before, added,
        "the first C++ file makes the omission hide source"
    );
    assert_eq!(fixture.cache.walk_count(), walks);
    assert_eq!(added, identity(&fixture.fresh()));
    std::fs::remove_file(fixture.root.join("first.cpp")).unwrap();
    current = current.update(&fixture.changes(&["first.cpp"]));
    assert_eq!(identity(&current), before);
    assert_eq!(identity(&current), identity(&fixture.fresh()));
    assert_eq!(fixture.cache.walk_count(), walks);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12752: an ignored compile_commands.json edit was dropped by the membership filter"
)]
fn ignore_membership_ignored_cpp_compile_commands_still_updates() {
    use brokk_bifrost_cpp::graph_support::CppSource;
    use brokk_bifrost_cpp_analysis::analyzer::cpp::CppAnalyzer;

    let before_database = r#"[{"directory":".","file":"probe.cpp","arguments":["clang++","-DBEFORE","-c","probe.cpp"]}]"#;
    let after_database = r#"[{"directory":".","file":"probe.cpp","arguments":["clang++","-DAFTER","-c","probe.cpp"]}]"#;
    let fixture = Fixture::with_files(&[
        ("probe.cpp", "int probe() { return 1; }\n"),
        ("compile_commands.json", before_database),
        (".gitignore", "compile_commands.json\n"),
    ]);
    let current = fixture.build();
    let direct = resolve_analyzer::<MultiAnalyzer>(current.analyzer())
        .unwrap()
        .clone();
    let file = ProjectFile::new(&fixture.root, "probe.cpp");
    let contexts = |analyzer: &dyn IAnalyzer| {
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer).unwrap();
        CppSource::compile_contexts_for(cpp, &file).to_vec()
    };
    // Warm the compile database before editing the ignored metadata file.
    let before = contexts(current.analyzer());
    assert_eq!(before.len(), 1);
    assert!(before[0].defined_macros.contains("BEFORE"));
    assert_eq!(contexts(&direct), before);
    std::fs::write(fixture.root.join("compile_commands.json"), after_database).unwrap();
    let changes = fixture.changes(&["compile_commands.json"]);
    let expected = contexts(fixture.fresh().analyzer());
    assert_eq!(expected.len(), 1);
    assert!(expected[0].defined_macros.contains("AFTER"));
    let updated = current.update(&changes);
    assert_eq!(contexts(updated.analyzer()), expected);
    assert_eq!(contexts(&direct.update(&changes)), expected);
}

#[test]
#[hardwon(
    "#13077: update_paths naming an ignored existing file indexed it, so incremental differed from cold"
)]
fn ignore_membership_named_ignored_existing_file_is_not_indexed_in_store() {
    let fixture = InlineTestProject::new()
        .file("Left.java", "class Left {}")
        .file("Right.java", "class Right {}")
        .file(".bifrostignore", "Right.java\n")
        .with_git()
        .build();
    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
    let mut current =
        WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
    let fresh = || {
        WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(FilesystemProject::new(fixture.root()).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap()
    };
    fixture
        .file(".bifrostignore")
        .write("Right.java\n")
        .unwrap();
    current = current.update(&BTreeSet::from([
        fixture.file(".bifrostignore"),
        fixture.file("Right.java"),
    ]));
    assert_eq!(rendered(current.analyzer()), rendered(fresh().analyzer()));
    fixture
        .file("Right.java")
        .write("class EditedWhileIgnored {}")
        .unwrap();
    let rebuilds = full_update_count_for_test(fixture.root());
    current = current.update(&BTreeSet::from([fixture.file("Right.java")]));
    assert_eq!(full_update_count_for_test(fixture.root()), rebuilds);
    assert_eq!(rendered(current.analyzer()), rendered(fresh().analyzer()));
}

#[test]
#[hardwon("#13077: an indexed ignored path survived in live paths and persisted workspace rows")]
fn ignore_membership_polluted_store_converges_on_update_and_restart() {
    let fixture = InlineTestProject::new()
        .file("Left.java", "class Left {}")
        .file("Right.java", "class Right {}")
        .file(".bifrostignore", "")
        .with_git()
        .build();
    let database = tempfile::tempdir().unwrap();
    let db = database.path().join("store.sqlite");
    let build = || {
        let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
        let store = AnalyzerStore::open_persistent(&db).unwrap();
        let context = store_context_from_store(project.as_ref(), store, false);
        TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap()
    };
    let mut current = build();
    let active_right_versions = |analyzer: &TreeSitterAnalyzer<JavaAdapter>| {
        analyzer.analyzer_store().conn.execute(|connection| {
            connection
                .query_row(
                    "SELECT count(*) FROM workspace_file_versions
                 WHERE rel_path = 'Right.java' AND input_kind = 'source'
                   AND valid_until IS NULL",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
        })
    };
    assert!(active_right_versions(&current) > 0);
    // Seed the old bug's persisted and live state: Right is indexed, while
    // selection now excludes it. The generation listing includes both paths
    // because .bifrostignore filters source selection after enumeration.
    fixture
        .file(".bifrostignore")
        .write("Right.java\n")
        .unwrap();
    assert!(rendered(&current).contains("Right"));
    // An unrelated update must also repair the polluted generation.
    current = current.update(&BTreeSet::from([fixture.file("Left.java")]));
    assert_eq!(active_right_versions(&current), 0);
    let cold = build();
    assert!(!rendered(&cold).contains("Right"));
    assert_eq!(rendered(&current), rendered(&cold));
    drop(cold);
    drop(current);
    assert!(!rendered(&build()).contains("Right"));

    // A polluted ignored source can disappear without a watcher removal.
    // Its next unrelated update retires it without rebuilding the workspace.
    fixture.file(".bifrostignore").write("").unwrap();
    let mut current = build();
    assert!(rendered(&current).contains("Right"));
    fixture
        .file(".bifrostignore")
        .write("Right.java\n")
        .unwrap();
    std::fs::remove_file(fixture.file("Right.java").abs_path()).unwrap();
    let rebuilds = full_update_count_for_test(fixture.root());
    current = current.update(&BTreeSet::from([fixture.file("Left.java")]));
    assert_eq!(full_update_count_for_test(fixture.root()), rebuilds);
    assert_eq!(active_right_versions(&current), 0);
    assert_eq!(rendered(&current), rendered(&build()));
}

#[test]
fn ignore_membership_named_excluded_configuration_is_still_processed() {
    use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
    let fixture = InlineTestProject::new()
        .file("Left.java", "class Left {}")
        .file("build.gradle.kts", "// initial configuration\n")
        .file(".bifrostignore", "build.gradle.kts\n")
        .with_git()
        .build();
    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
    let mut current =
        TreeSitterAnalyzer::new_with_config(project, JavaAdapter, AnalyzerConfig::default());
    let file = fixture.file("build.gradle.kts");
    let source = "// edited configuration\n";
    file.write(source).unwrap();
    current = current.update(&BTreeSet::from([file.clone()]));
    let inputs = current.selected_configuration_input_blobs().unwrap();
    assert!(
        inputs.contains(&(
            file,
            git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes(),).unwrap()
        )),
        "{inputs:?}"
    );
}

#[test]
#[hardwon("#13077: ordinary verified saves rebuilt selection and scanned every indexed source")]
fn ignore_membership_verified_saves_skip_scan_and_rule_edits_match_cold() {
    let fixture = InlineTestProject::new()
        .file("source/Left.java", "class Left {}")
        .file("source/Right.java", "class Right {}")
        .file("source/.bifrostignore", "")
        .with_git()
        .build();
    let _environment = IgnoreTestEnvironment::new(&fixture.root().join("home"));
    let root = fixture.root().join("source").canonicalize().unwrap();
    // Only the fixture's owned parent is aged. Never age the shared /tmp.
    age_ignore_test_inputs(&root);
    let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::with_cached_listing(&root, Arc::clone(&cache)).unwrap());
    let build = || {
        WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), AnalyzerConfig::default())
            .unwrap()
    };
    let fresh = || {
        WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(FilesystemProject::new(&root).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap()
    };
    let file = |name: &str| ProjectFile::new(&root, name);
    let mut current = build();
    let scans = membership_scan_count_for_test(project.root());
    file("Left.java")
        .write("class Left { int changed; }")
        .unwrap();
    current = current.update(&BTreeSet::from([file("Left.java")]));
    assert_eq!(
        membership_scan_count_for_test(project.root()),
        scans,
        "an ordinary verified save must not scan workspace membership"
    );
    assert_eq!(rendered(current.analyzer()), rendered(fresh().analyzer()));

    // The owner must notice an ignore edit even when no rule path was named.
    file(".bifrostignore").write("Right.java\n").unwrap();
    let rebuilds = full_update_count_for_test(project.root());
    current = current.update(&BTreeSet::from([file("Left.java")]));
    // The outer membership decision sees the rule change and rebuilds before
    // the delegate's receipt-recovery scan can run, so the observable proof of
    // reselection is the rebuild, not the delegate scan counter.
    assert!(full_update_count_for_test(project.root()) > rebuilds);
    assert_eq!(rendered(current.analyzer()), rendered(fresh().analyzer()));
    assert!(!rendered(current.analyzer()).contains("Right"));

    // A reported rule edit takes the same owner-controlled receipt path.
    file(".bifrostignore").write("").unwrap();
    project.invalidate_cached_file_listing();
    current = build();
    assert!(rendered(current.analyzer()).contains("Right"));
    file(".bifrostignore").write("Right.java\n").unwrap();
    let rebuilds = full_update_count_for_test(project.root());
    current = current.update(&BTreeSet::from([file(".bifrostignore")]));
    // As above: the outer membership decision rebuilds for the rule change.
    assert!(full_update_count_for_test(project.root()) > rebuilds);
    assert_eq!(rendered(current.analyzer()), rendered(fresh().analyzer()));

    // Naming an unchanged recorded rule input still invalidates its owner.
    age_ignore_test_inputs(&root);
    project.invalidate_cached_file_listing();
    current = build();
    let walks = cache.walk_count();
    current = current.update(&BTreeSet::from([file(".bifrostignore")]));
    assert!(cache.walk_count() > walks);
    assert_eq!(rendered(current.analyzer()), rendered(fresh().analyzer()));

    // A completed no-withdrawal check advances the receipt anchor, so the
    // next ordinary save does not repeat that workspace scan.
    let scans = membership_scan_count_for_test(project.root());
    file("Left.java")
        .write("class Left { int changed_again; }")
        .unwrap();
    current = current.update(&BTreeSet::from([file("Left.java")]));
    assert_eq!(membership_scan_count_for_test(project.root()), scans);
    assert_eq!(rendered(current.analyzer()), rendered(fresh().analyzer()));
}
