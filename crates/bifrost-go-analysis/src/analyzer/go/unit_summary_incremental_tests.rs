//! SQLite/Rust boundary differential for bulk summary admission.
use super::*;
use brokk_bifrost_analysis::analyzer::store::{
    AnalyzerStore,
    go_package_context::source_inventory_profile,
    go_unit_summaries::{GoUnitSummaries, RetainedGoUnitSummaries},
    unit_summaries::UnitSummaryReconciliation,
};
use brokk_bifrost_core::analyzer::project::TestProject;
use std::cell::RefCell;

type ReportCounts = (usize, usize, usize);

thread_local! {
    static REPORTS: RefCell<Option<Vec<ReportCounts>>> = const { RefCell::new(None) };
    static DISCOVERY_REPORTS: RefCell<Option<Vec<ReportCounts>>> = const { RefCell::new(None) };
}
pub(super) fn record(report: &UnitSummaryReconciliation) {
    REPORTS.with(|reports| {
        if let Some(reports) = reports.borrow_mut().as_mut() {
            assert!(report.failed.is_empty(), "{report:?}");
            reports.push((report.units, report.admitted, report.statements));
        }
    });
}
pub(super) fn record_discovered(report: &UnitSummaryReconciliation) {
    DISCOVERY_REPORTS.with(|reports| {
        if let Some(reports) = reports.borrow_mut().as_mut() {
            assert!(report.failed.is_empty(), "{report:?}");
            reports.push((report.units, report.admitted, report.statements));
        }
    });
}

fn clear_reports() {
    REPORTS.with(|reports| *reports.borrow_mut() = Some(Vec::new()));
}
fn report() -> ReportCounts {
    REPORTS.with(|reports| {
        let reports = reports.replace(None).expect("capture enabled");
        assert_eq!(reports.len(), 1, "one source reconciliation: {reports:?}");
        reports[0]
    })
}

fn retained(go: &GoAnalyzer, store: &AnalyzerStore) -> UnitSummaryReconciliation {
    let snapshot = go.selected_snapshot_for_test().unwrap();
    let context = store
        .go_context_for_reconciliation(&snapshot, &source_inventory_profile())
        .unwrap()
        .unwrap();
    store
        .reconcile_unit_summaries(
            &snapshot,
            RetainedGoUnitSummaries(GoUnitSummaries {
                context_id: context.context_id,
                profile: source_inventory_profile(),
            }),
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        )
        .unwrap()
}

// Read the persisted consumer relation, including completion/output digest, then
// exercise the analyzer's public declaration lookup against the same selection.
fn rendered(go: &GoAnalyzer) -> String {
    rendered_profile(go, source_inventory_profile())
}
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: test assertion over persisted consumer rows"
)]
fn rendered_profile(go: &GoAnalyzer, profile: [u8; 32]) -> String {
    let snapshot = go.selected_snapshot_for_test().unwrap();
    let conn = go.inner.analyzer_store().read_conn().unwrap();
    let mut query = conn
        .prepare(
            "SELECT hex(versions.unit_key),hex(summaries.output_digest),
         summaries.publication_state
       FROM resolution_unit_summary_versions versions
       JOIN resolution_unit_summaries summaries USING(summary_id)
       WHERE versions.workspace_id=?1 AND versions.lang='go' AND versions.generation=?2
         AND versions.profile_digest=?3 AND versions.valid_until IS NULL
       ORDER BY versions.unit_key",
        )
        .unwrap();
    let rows = query
        .query_map(
            rusqlite::params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                profile
            ],
            |row| {
                Ok(format!(
                    "{} {} {}",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?
                ))
            },
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let mut result = rows.join("\n");
    for name in [
        "example.test/sliced/a.Base",
        "example.test/sliced/a.Target",
        "example.test/sliced/b.Alias",
        "example.test/sliced/c.Top",
    ] {
        let mut definitions = go
            .get_definitions(name)
            .into_iter()
            .map(|unit| unit.fq_name().to_owned())
            .collect::<Vec<_>>();
        definitions.sort();
        result.push_str(&format!("\n{name}: {definitions:?}"));
    }
    result
}

#[test]
fn go_summary_bulk_admission_matches_scratch_for_edit_family() {
    let source = tempfile::tempdir().unwrap();
    let root = source.path();
    for (path, text) in [
        ("go.mod", "module example.test/sliced\n\ngo 1.22\n"),
        ("go.sum", ""),
        ("notes.rs", "fn unrelated() { let value = 1; }\n"),
        (
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 1 }\n",
        ),
        (
            "b/b.go",
            "package b\nimport \"example.test/sliced/a\"\ntype Alias = a.Base\n",
        ),
        (
            "c/c.go",
            "package c\nimport \"example.test/sliced/b\"\ntype Top = b.Alias\n",
        ),
        ("d/d.go", "package d\nfunc Other() {}\n"),
    ] {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let cache = tempfile::tempdir().unwrap();
    let path = cache.path().join("store.db");
    let store = Arc::new(AnalyzerStore::open_persistent(&path).unwrap());
    *store.crate_statement_counter.lock().unwrap() = Some(Arc::default());
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Go));
    let context =
        brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_shared_store(
            project.as_ref(),
            Arc::clone(&store),
            false,
        );
    let mut go = GoAnalyzer::new_with_config_store_context(
        Arc::clone(&project),
        Default::default(),
        context,
        None,
    )
    .unwrap();
    assert_eq!(retained(&go, &store).admitted, 0);
    for (class, path, text, admitted) in [
        (
            "unrelated",
            "notes.rs",
            "fn unrelated() { let value = 2; }\n",
            0,
        ),
        // A body edit with an equal resolution surface admits zero units.
        (
            "equal-surface body",
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 2 }\n",
            0,
        ),
        (
            "surface",
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 2 }\nfunc Added() {}\n",
            2,
        ),
        (
            "go.mod",
            "go.mod",
            "module example.test/sliced\n\ngo 1.23\n",
            4,
        ),
        (
            "go.sum",
            "go.sum",
            "example.test/dependency v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            4,
        ),
    ] {
        clear_reports();
        std::fs::write(root.join(path), text).unwrap();
        go = IAnalyzer::update_with_listing(
            &go,
            &BTreeSet::from([ProjectFile::new(root.to_path_buf(), path)]),
            None,
        );
        let (units, actual, sql) = report();
        assert_eq!(units, 4, "{class}");
        assert_eq!(actual, admitted, "{class}: sql={sql}");
        let fresh = GoAnalyzer::new(Arc::new(TestProject::new(root, Language::Go)));
        assert_eq!(
            rendered(&go),
            rendered(&fresh),
            "{class}: incremental differs from scratch"
        );
        eprintln!("13517 {class}: units={units} admitted={actual} sql={sql}");
    }
    // Another independently opened handle both writes and validates these rows.
    let other = AnalyzerStore::open_persistent(&path).unwrap();
    let snapshot = go.selected_snapshot_for_test().unwrap();
    let context = other
        .go_context_for_reconciliation(&snapshot, &source_inventory_profile())
        .unwrap()
        .unwrap();
    other
        .conn
        .execute(|conn| {
            let _fixture =
                brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute_batch(
        "DELETE FROM resolution_unit_summary_versions; DELETE FROM resolution_unit_summaries;"
    )
        })
        .unwrap();
    let written = other
        .reconcile_unit_summaries(
            &snapshot,
            GoUnitSummaries {
                context_id: context.context_id,
                profile: source_inventory_profile(),
            },
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(
        written.derived, 4,
        "the independent handle must actually write: {written:?}"
    );
    let validated = retained(&go, &store);
    eprintln!(
        "13517 other writer: units={} admitted={} sql={}",
        validated.units, validated.admitted, validated.statements
    );
    assert_eq!(validated.admitted, 0, "{validated:?}");
    assert!(validated.failed.is_empty(), "{validated:?}");
    assert_eq!(
        rendered(&go),
        rendered(&GoAnalyzer::new(Arc::new(TestProject::new(
            root,
            Language::Go
        ))))
    );
}

#[expect(
    clippy::disallowed_methods,
    reason = "#12820: test fixture selects the blob to repair"
)]
fn repair_surface(go: &GoAnalyzer, root: &std::path::Path) {
    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
    let store = go.inner.analyzer_store();
    let snapshot = go.selected_snapshot_for_test().unwrap();
    let oid: String = store
        .read_conn()
        .unwrap()
        .query_row(
            "SELECT blob_oid FROM workspace_file_versions WHERE workspace_id=?1 AND lang='go'
           AND generation=?2 AND rel_path='a/a.go' AND valid_until IS NULL",
            rusqlite::params![snapshot.workspace_id.as_str(), snapshot.generation.get()],
            |row| row.get(0),
        )
        .unwrap();
    let key = brokk_bifrost_core::gitblob::BlobKey::unvaried(oid.parse().unwrap(), "go");
    // Parse the repaired adapter output in the same module/package directory;
    // this .txt is not selected as a Go source. Selected bytes/OID never change.
    let replacement = ProjectFile::new(root, "a/repaired-facts.txt");
    std::fs::write(
        replacement.abs_path(),
        "package a\ntype Base struct { Value string }\nfunc Target() int { return 1 }\nfunc Repaired() {}\n",
    )
    .unwrap();
    store.mark_parsed_blob_incomplete_for_test(&key);
    let prepared = AnalyzerStore::prepare_parsed_blob(
        &key,
        snapshot.generation,
        &adapter::GoAdapter,
        Arc::new(parse_state(&adapter::GoAdapter, &replacement)),
    )
    .unwrap();
    store.repair_prepared_blob(prepared).unwrap();
}

#[test]
fn go_summary_bulk_admission_rechecks_same_oid_surface_repair() {
    let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/sliced\n\ngo 1.22\n")
        .file(
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 1 }\n",
        )
        .file(
            "b/b.go",
            "package b\nimport \"example.test/sliced/a\"\ntype Alias = a.Base\n",
        )
        .build();
    let go = GoAnalyzer::new(project.project_dyn());
    *go.inner
        .analyzer_store()
        .crate_statement_counter
        .lock()
        .unwrap() = Some(Arc::default());
    let original = std::fs::read(project.file("a/a.go").abs_path()).unwrap();
    assert_eq!(retained(&go, go.inner.analyzer_store()).admitted, 0);
    repair_surface(&go, project.root());
    assert_eq!(
        std::fs::read(project.file("a/a.go").abs_path()).unwrap(),
        original
    );
    let report = retained(&go, go.inner.analyzer_store());
    eprintln!(
        "13517 same-OID repair: units={} admitted={} sql={}",
        report.units, report.admitted, report.statements
    );
    assert!(
        report.admitted > 0,
        "surface repair must enter per-unit validation: {report:?}"
    );
    assert!(report.failed.is_empty(), "{report:?}");
    let fresh = GoAnalyzer::new(project.project_dyn());
    repair_surface(&fresh, project.root());
    let full_context = fresh
        .inner
        .analyzer_store()
        .go_context_for_reconciliation(
            &fresh.selected_snapshot_for_test().unwrap(),
            &source_inventory_profile(),
        )
        .unwrap()
        .unwrap();
    fresh
        .inner
        .analyzer_store()
        .reconcile_unit_summaries(
            &fresh.selected_snapshot_for_test().unwrap(),
            GoUnitSummaries {
                context_id: full_context.context_id,
                profile: source_inventory_profile(),
            },
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(rendered(&go), rendered(&fresh));
}

#[test]
fn go_summary_discovery_output_change_forces_full_reconciliation() {
    use brokk_bifrost_analysis::analyzer::store::go_package_context::{
        GoContextPublicationOutcome, GoInputObservationOutcome, profile_digest,
    };
    let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/sliced\n\ngo 1.22\n")
        .file("notes.txt", "before\n")
        .file(
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 1 }\n",
        )
        .file(
            "b/b.go",
            "package b\nimport \"example.test/sliced/a\"\ntype Alias = a.Base\n",
        )
        .build();
    let initial = GoAnalyzer::new(project.project_dyn());
    let go = IAnalyzer::update_with_listing(
        &initial,
        &BTreeSet::from([project.file("notes.txt")]),
        None,
    );
    *go.inner
        .analyzer_store()
        .crate_statement_counter
        .lock()
        .unwrap() = Some(Arc::default());
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    let discovered = dependency_discovery::discover_go_packages(
        &Default::default(),
        go.inner.project(),
        &Default::default(),
        Some(&cancellation),
    );
    let Some(mut canonical) = discovered.canonical else {
        assert!(
            std::process::Command::new("go")
                .arg("version")
                .output()
                .is_err(),
            "{discovered:?}"
        );
        return;
    };
    canonical.domain = brokk_bifrost_go::package_discovery::go_discovery_domains(
        project.root(),
        &[(
            "go.mod".into(),
            std::fs::read_to_string(project.root().join("go.mod")).unwrap(),
        )],
    )
    .unwrap()
    .pop()
    .unwrap();
    let module_cache = tempfile::tempdir().unwrap();
    let mut provider = canonical.packages[0].clone();
    provider.import_path = "example.test/cache/provider".into();
    provider.name = "provider".into();
    provider.dir = module_cache.path().to_path_buf();
    provider.go_files.clear();
    provider.cgo_files.clear();
    provider.ignored_go_files.clear();
    provider.test_go_files.clear();
    provider.x_test_go_files.clear();
    provider.imports.clear();
    provider.module = Some(brokk_bifrost_go::package_discovery::GoModule {
        path: "example.test/cache".into(),
        version: "v1.0.0".into(),
        sum: "first-cache-output".into(),
        dir: module_cache.path().to_path_buf(),
        main: false,
        go_mod: Default::default(),
        replace: None,
    });
    canonical.packages.push(provider);
    let publish =
        |go: &GoAnalyzer, discovery: brokk_bifrost_go::package_discovery::GoPackageDiscovery| {
            let store = go.inner.analyzer_store();
            let snapshot = go.selected_snapshot_for_test().unwrap();
            let GoInputObservationOutcome::Ready(observation) = store
                .observe_go_context_inputs(&snapshot, go.inner.project(), &cancellation)
                .unwrap()
            else {
                panic!("selected observation")
            };
            let profile = profile_digest(&discovery);
            let GoContextPublicationOutcome::Published(identity) = store
                .publish_go_package_context(
                    snapshot.clone(),
                    project.root().to_path_buf(),
                    None,
                    &observation,
                    &observation,
                    discovery,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("published discovery")
            };
            assert!(go.activate_native_context_profile(&snapshot, profile));
            (identity, profile)
        };
    let (before, profile) = publish(&go, canonical.clone());
    let snapshot = go.selected_snapshot_for_test().unwrap();
    let initial = go
        .reconcile_discovered_unit_summaries(
            go.inner.analyzer_store(),
            &snapshot,
            before.context_id,
            profile,
            None,
            &cancellation,
        )
        .unwrap();
    assert_eq!(initial.admitted, 2, "{initial:?}");
    // The domain pass that ran the full reconciliation above consumes the
    // analyzer's pending full-pass bit (a new analyzer starts with it set).
    go.requires_full_summary_reconciliation
        .store(false, std::sync::atomic::Ordering::Release);
    let same = go
        .reconcile_discovered_unit_summaries(
            go.inner.analyzer_store(),
            &snapshot,
            before.context_id,
            profile,
            Some(before.context_id),
            &cancellation,
        )
        .unwrap();
    assert_eq!(same.admitted, 0, "{same:?}");
    // The selected workspace bytes did not change; fresh external cache output did.
    canonical
        .packages
        .last_mut()
        .unwrap()
        .module
        .as_mut()
        .unwrap()
        .sum = "second-cache-output".into();
    let (after, after_profile) = publish(&go, canonical.clone());
    assert_eq!(profile, after_profile);
    assert_ne!(before.context_id, after.context_id);
    let changed = go
        .reconcile_discovered_unit_summaries(
            go.inner.analyzer_store(),
            &snapshot,
            after.context_id,
            profile,
            Some(before.context_id),
            &cancellation,
        )
        .unwrap();
    assert_eq!(changed.admitted, 2, "{changed:?}");
    eprintln!(
        "13517 discovery output: units={} admitted={} sql={}",
        changed.units, changed.admitted, changed.statements
    );
    let fresh = GoAnalyzer::new(project.project_dyn());
    let (fresh_context, _) = publish(&fresh, canonical);
    fresh
        .reconcile_discovered_unit_summaries(
            fresh.inner.analyzer_store(),
            &fresh.selected_snapshot_for_test().unwrap(),
            fresh_context.context_id,
            profile,
            None,
            &cancellation,
        )
        .unwrap();
    assert_eq!(
        rendered_profile(&go, profile),
        rendered_profile(&fresh, profile)
    );
}

#[test]
fn go_summary_bulk_admission_survives_an_unrelated_workspace_update() {
    use super::dependency_packs::{GoReconciliationTrigger, reconcile_selected_go_domains};
    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    if std::process::Command::new("go")
        .arg("version")
        .output()
        .is_err()
    {
        return;
    }
    let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/sliced\n\ngo 1.22\n")
        .file("notes.txt", "before\n")
        .file(
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 1 }\n",
        )
        .build();
    let config = AnalyzerConfig::default();
    let workspace = WorkspaceAnalyzer::build_ephemeral_for_languages_footgun(
        project.project_dyn(),
        config.clone(),
        &BTreeSet::from([Language::Go]),
    )
    .unwrap();
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    let warm = |workspace: &WorkspaceAnalyzer| {
        let outcome = reconcile_selected_go_domains(
            workspace,
            &config,
            &Default::default(),
            &cancellation,
            GoReconciliationTrigger::DependencyActivation,
        )
        .unwrap();
        assert!(!outcome.cancelled, "{outcome:?}");
    };
    warm(&workspace);
    std::fs::write(project.file("notes.txt").abs_path(), "after\n").unwrap();
    let updated = workspace.update(&BTreeSet::from([project.file("notes.txt")]));
    DISCOVERY_REPORTS.with(|reports| *reports.borrow_mut() = Some(Vec::new()));
    warm(&updated);
    let reports = DISCOVERY_REPORTS.with(|reports| reports.replace(None).unwrap());
    assert!(
        !reports.is_empty(),
        "fresh discovery must reconcile a selected Go domain"
    );
    assert!(
        reports.iter().all(|(_, admitted, _)| *admitted == 0),
        "unrelated workspace edit: {reports:?}"
    );
    let fresh = WorkspaceAnalyzer::build_ephemeral_for_languages_footgun(
        project.project_dyn(),
        config.clone(),
        &BTreeSet::from([Language::Go]),
    )
    .unwrap();
    warm(&fresh);
    let current = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<GoAnalyzer>(
        updated.analyzer(),
    )
    .unwrap();
    let scratch = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<GoAnalyzer>(
        fresh.analyzer(),
    )
    .unwrap();
    assert_eq!(rendered(current), rendered(scratch));
}

const FAMILY_BASE: &[(&str, &str)] = &[
    ("go.mod", "module example.test/sliced\n\ngo 1.22\n"),
    (
        "a/a.go",
        "package a\ntype Base struct { Value int }\nfunc Target() int { return 1 }\n",
    ),
    (
        "b/b.go",
        "package b\nimport \"example.test/sliced/a\"\ntype Alias = a.Base\n",
    ),
    (
        "c/c.go",
        "package c\nimport \"example.test/sliced/b\"\ntype Top = b.Alias\n",
    ),
    ("d/d.go", "package d\nfunc Other() {}\n"),
];

/// Apply one edit (None deletes) to a warm Go project, reconcile it through
/// the retained path, and compare with a from-scratch analyzer. Returns the
/// number of units and the number admitted to per-unit work.
fn edit_matches_scratch(
    initial: &[(&str, &str)],
    edits: &[(&str, Option<&str>)],
    class: &str,
) -> (usize, usize) {
    let source = tempfile::tempdir().unwrap();
    let root = source.path();
    for (path, text) in initial {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let cache = tempfile::tempdir().unwrap();
    let store = Arc::new(AnalyzerStore::open_persistent(&cache.path().join("store.db")).unwrap());
    *store.crate_statement_counter.lock().unwrap() = Some(Arc::default());
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Go));
    let context =
        brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_shared_store(
            project.as_ref(),
            Arc::clone(&store),
            false,
        );
    let go = GoAnalyzer::new_with_config_store_context(
        Arc::clone(&project),
        Default::default(),
        context,
        None,
    )
    .unwrap();
    assert_eq!(retained(&go, &store).admitted, 0, "{class}: warm pass");
    clear_reports();
    let mut changed = BTreeSet::new();
    for (path, text) in edits {
        match text {
            Some(text) => {
                let target = root.join(path);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(target, text).unwrap();
            }
            None => std::fs::remove_file(root.join(path)).unwrap(),
        }
        changed.insert(ProjectFile::new(root.to_path_buf(), *path));
    }
    let go = IAnalyzer::update_with_listing(&go, &changed, None);
    let (units, admitted, _) = report();
    let fresh = GoAnalyzer::new(Arc::new(TestProject::new(root, Language::Go)));
    assert_eq!(
        rendered(&go),
        rendered(&fresh),
        "{class}: incremental differs from scratch"
    );
    eprintln!("13517 {class}: units={units} admitted={admitted}");
    (units, admitted)
}

fn with_file<'a>(
    base: &[(&'a str, &'a str)],
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    base.iter().chain(extra).copied().collect()
}

#[test]
fn go_summary_bulk_admission_admits_member_set_changes() {
    let (units, admitted) = edit_matches_scratch(
        FAMILY_BASE,
        &[("a/extra.go", Some("package a\nfunc Extra() {}\n"))],
        "member added",
    );
    // A membership change republishes the whole inventory, so every unit is
    // admitted to a full pass.
    assert_eq!((units, admitted), (4, 4), "member added");
    let initial = with_file(
        FAMILY_BASE,
        &[("a/extra.go", "package a\nfunc Extra() {}\n")],
    );
    let (units, admitted) =
        edit_matches_scratch(&initial, &[("a/extra.go", None)], "member deleted");
    assert_eq!((units, admitted), (4, 4), "member deleted");
}

#[test]
fn go_summary_bulk_admission_admits_source_role_change() {
    let initial = with_file(
        FAMILY_BASE,
        &[("a/a_test.go", "package a\nfunc TestSame() {}\n")],
    );
    // Same path, test -> xtest.
    let (units, admitted) = edit_matches_scratch(
        &initial,
        &[("a/a_test.go", Some("package a_test\nfunc TestSame() {}\n"))],
        "source role",
    );
    assert_eq!((units, admitted), (5, 5), "source role");
}

#[test]
fn go_summary_bulk_admission_admits_consumer_of_deleted_dependency() {
    let (_, admitted) =
        edit_matches_scratch(FAMILY_BASE, &[("b/b.go", None)], "deleted dependency");
    assert!(admitted >= 1, "deleted dependency: admitted {admitted}");
    // The package stays imported but loses every selected file.
    let (units, admitted) = edit_matches_scratch(
        FAMILY_BASE,
        &[(
            "b/b.go",
            Some(
                "//go:build ignore\n\npackage b\nimport \"example.test/sliced/a\"\ntype Alias = a.Base\n",
            ),
        )],
        "dependency without selected files",
    );
    assert_eq!((units, admitted), (4, 4), "unselected dependency");
}

#[test]
fn go_summary_bulk_admission_propagates_dependency_output_change() {
    // The consumer's directory sorts before its dependency's.
    let initial = [
        ("go.mod", "module example.test/sliced\n\ngo 1.22\n"),
        ("z/z.go", "package z\ntype Base struct { Value int }\n"),
        (
            "a/a.go",
            "package a\nimport \"example.test/sliced/z\"\ntype Alias = z.Base\n",
        ),
        (
            "m/m.go",
            "package m\nimport \"example.test/sliced/a\"\ntype Top = a.Alias\n",
        ),
    ];
    let (units, admitted) = edit_matches_scratch(
        &initial,
        &[(
            "z/z.go",
            Some(
                "package z\ntype Base struct { Value string }\nfunc New() Base { return Base{} }\n",
            ),
        )],
        "dependency output",
    );
    // z changed and a consumes z; m reads a's unchanged output and is not admitted.
    assert_eq!((units, admitted), (3, 2), "dependency output");
}

#[expect(
    clippy::disallowed_methods,
    reason = "#13517: test assertion over persisted dependency rows"
)]
#[test]
fn go_summary_bulk_admission_rechecks_external_provider_digest() {
    use brokk_bifrost_analysis::analyzer::store::go_package_context::{
        GoContextPublicationOutcome, GoInputObservationOutcome, profile_digest,
    };
    let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/sliced\n\ngo 1.22\n")
        .file(
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 1 }\n",
        )
        .file(
            "b/b.go",
            "package b\nimport \"example.test/sliced/a\"\ntype Alias = a.Base\n",
        )
        .build();
    let go = GoAnalyzer::new(project.project_dyn());
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
    let discovered = dependency_discovery::discover_go_packages(
        &Default::default(),
        go.inner.project(),
        &Default::default(),
        Some(&cancellation),
    );
    let mut canonical = discovered
        .canonical
        .expect("the go tool is installed in the test environment");
    canonical.domain = brokk_bifrost_go::package_discovery::go_discovery_domains(
        project.root(),
        &[(
            "go.mod".into(),
            std::fs::read_to_string(project.root().join("go.mod")).unwrap(),
        )],
    )
    .unwrap()
    .pop()
    .unwrap();
    let module_cache = tempfile::tempdir().unwrap();
    let mut provider = canonical.packages[0].clone();
    provider.import_path = "example.test/cache/provider".into();
    provider.name = "provider".into();
    provider.dir = module_cache.path().to_path_buf();
    provider.go_files.clear();
    provider.cgo_files.clear();
    provider.ignored_go_files.clear();
    provider.test_go_files.clear();
    provider.x_test_go_files.clear();
    provider.imports.clear();
    provider.module = Some(brokk_bifrost_go::package_discovery::GoModule {
        path: "example.test/cache".into(),
        version: "v1.0.0".into(),
        sum: "first-cache-output".into(),
        dir: module_cache.path().to_path_buf(),
        main: false,
        go_mod: Default::default(),
        replace: None,
    });
    for package in &mut canonical.packages {
        if package.import_path == "example.test/sliced/b" {
            package.imports.push("example.test/cache/provider".into());
        }
    }
    canonical.packages.push(provider);
    let publish =
        |go: &GoAnalyzer, discovery: brokk_bifrost_go::package_discovery::GoPackageDiscovery| {
            let store = go.inner.analyzer_store();
            let snapshot = go.selected_snapshot_for_test().unwrap();
            let GoInputObservationOutcome::Ready(observation) = store
                .observe_go_context_inputs(&snapshot, go.inner.project(), &cancellation)
                .unwrap()
            else {
                panic!("selected observation")
            };
            let profile = profile_digest(&discovery);
            let GoContextPublicationOutcome::Published(identity) = store
                .publish_go_package_context(
                    snapshot,
                    project.root().to_path_buf(),
                    None,
                    &observation,
                    &observation,
                    discovery,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("published discovery")
            };
            (identity, profile)
        };
    let store = go.inner.analyzer_store();
    let snapshot = go.selected_snapshot_for_test().unwrap();
    let (before, profile) = publish(&go, canonical.clone());
    store
        .reconcile_unit_summaries(
            &snapshot,
            GoUnitSummaries {
                context_id: before.context_id,
                profile,
            },
            &cancellation,
        )
        .unwrap();
    let external: i64 = store
        .read_conn()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM resolution_unit_summary_dependencies WHERE boundary='external'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        external > 0,
        "the fixture must record an external dependency"
    );
    // Another handle's summaries stay valid under the same context and profile.
    let retained_with = |context_id: i64| {
        store
            .reconcile_unit_summaries(
                &snapshot,
                RetainedGoUnitSummaries(GoUnitSummaries {
                    context_id,
                    profile,
                }),
                &cancellation,
            )
            .unwrap()
    };
    assert_eq!(retained_with(before.context_id).admitted, 0);
    // The module-cache output moves; the package and import names do not.
    canonical
        .packages
        .last_mut()
        .unwrap()
        .module
        .as_mut()
        .unwrap()
        .sum = "second-cache-output".into();
    let (after, after_profile) = publish(&go, canonical.clone());
    assert_eq!(profile, after_profile);
    let report = retained_with(after.context_id);
    // Only b imports the provider; a must stay out of per-unit validation.
    assert_eq!(report.admitted, 1, "{report:?}");
    let fresh = GoAnalyzer::new(project.project_dyn());
    let (fresh_context, _) = publish(&fresh, canonical);
    fresh
        .inner
        .analyzer_store()
        .reconcile_unit_summaries(
            &fresh.selected_snapshot_for_test().unwrap(),
            GoUnitSummaries {
                context_id: fresh_context.context_id,
                profile,
            },
            &cancellation,
        )
        .unwrap();
    assert_eq!(
        rendered_profile(&go, profile),
        rendered_profile(&fresh, profile)
    );
}

#[test]
fn go_summary_bulk_admission_rechecks_recorded_member_set_and_role() {
    let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/sliced\n\ngo 1.22\n")
        .file(
            "a/a.go",
            "package a\ntype Base struct { Value int }\nfunc Target() int { return 1 }\n",
        )
        .file(
            "b/b.go",
            "package b\nimport \"example.test/sliced/a\"\ntype Alias = a.Base\n",
        )
        .file("d/d.go", "package d\nfunc Other() {}\n")
        .build();
    for (class, rewrite) in [
        (
            "recorded member missing",
            "DELETE FROM resolution_unit_summary_members WHERE rel_path='a/a.go'",
        ),
        (
            "recorded role differs",
            "UPDATE resolution_unit_summary_members SET source_role='test' WHERE rel_path='a/a.go'",
        ),
    ] {
        let go = GoAnalyzer::new(project.project_dyn());
        let store = go.inner.analyzer_store();
        assert_eq!(retained(&go, store).admitted, 0, "{class}: warm");
        store
            .conn
            .execute(move |conn| {
                let _fixture =
                    brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
                conn.execute(rewrite, [])
            })
            .unwrap();
        let report = retained(&go, store);
        assert!(report.failed.is_empty(), "{class}: {report:?}");
        // Only a's summary disagrees with the selected members; b and d do not.
        assert_eq!(
            (report.units, report.admitted),
            (3, 1),
            "{class}: {report:?}"
        );
        let fresh = GoAnalyzer::new(project.project_dyn());
        assert_eq!(rendered(&go), rendered(&fresh), "{class}");
    }
}

#[test]
fn go_pending_full_reconciliation_survives_unrelated_edits() {
    use std::sync::atomic::Ordering::{Acquire, Release};
    let project = crate::inline_project::InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/sliced\n\ngo 1.22\n")
        .file("notes.txt", "before\n")
        .file("a/a.go", "package a\nfunc Target() int { return 1 }\n")
        .build();
    let go = GoAnalyzer::new(project.project_dyn());
    assert!(go.requires_full_summary_reconciliation.load(Acquire));
    let edit = BTreeSet::from([project.file("notes.txt")]);
    let updated = IAnalyzer::update_with_listing(&go, &edit, None);
    assert!(
        updated.requires_full_summary_reconciliation.load(Acquire),
        "an edit without Go configuration must not drop a pending full pass"
    );
    updated
        .requires_full_summary_reconciliation
        .store(false, Release);
    let later = IAnalyzer::update_with_listing(&updated, &edit, None);
    assert!(!later.requires_full_summary_reconciliation.load(Acquire));
}
