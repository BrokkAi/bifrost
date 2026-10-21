use super::*;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::PythonSummaryObservation;
use brokk_bifrost_core::analyzer::project::{OverlayProject, TestProject};
use std::path::PathBuf;
use std::time::Instant;

fn profile() -> PythonSummaryProfile {
    PythonSummaryProfile {
        authority: PythonSummaryAuthority::SuppliedAnalysis,
        observation: PythonSummaryObservation::Runtime,
        roots: vec![PathBuf::from("src")],
        ordered: true,
        target_digest: [0; 32],
    }
}
fn stage(environment: &PythonNativeEnvironment, fixture: &BuiltInlineTestProject, revision: i64) {
    environment.begin(revision).unwrap();
    let project = fixture.project_dyn();
    for file in project.analyzable_files(Language::Python).unwrap() {
        let source = project.read_source(&file).unwrap();
        environment
            .stage_source(project.clone(), &file, &source, revision)
            .unwrap();
    }
}
fn build(
    environment: &PythonNativeEnvironment,
    fixture: &BuiltInlineTestProject,
    revision: i64,
) -> String {
    stage(environment, fixture, revision);
    let receipt = environment
        .reconcile(revision, &CancellationToken::default())
        .unwrap();
    assert!(receipt.failed.is_empty(), "{receipt:?}");
    environment.render(revision).unwrap()
}

#[test]
fn python_environment_profiles_reopen_withdraw_cancel_and_shuffle() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("src/pkg/__init__.py", "from .model import Widget\n")
        .file("src/pkg/model.py", "class Widget: pass\n_private = 1\n")
        .file("src/user.py", "from pkg.model import Widget\n")
        .build();
    let database = fixture.root().join("environment.db");
    let environment = PythonNativeEnvironment::open(&database, profile()).unwrap();
    let initial = build(&environment, &fixture, 1);
    assert!(
        initial.contains("pkg.model | module | selected"),
        "{initial}"
    );
    stage(&environment, &fixture, 1);
    let warm = environment
        .reconcile(1, &CancellationToken::default())
        .unwrap();
    assert_eq!(warm.unchanged, 1, "{warm:?}");
    let mut typing = profile();
    typing.observation = PythonSummaryObservation::Typing;
    let other = PythonNativeEnvironment::open(&database, typing.clone()).unwrap();
    let typing_render = build(&other, &fixture, 1);
    assert!(typing_render.starts_with("authority=supplied_analysis observation=typing"));
    assert_eq!(
        environment.render(1).unwrap(),
        initial,
        "other profile cannot replace runtime"
    );
    drop(other);
    drop(environment);
    let environment = PythonNativeEnvironment::open(&database, profile()).unwrap();
    assert_eq!(
        environment.render(1).unwrap(),
        initial,
        "reopen needs no TEMP metadata"
    );
    // Cancellation after real input publication must preserve the old revision
    // and clear every language staging relation; no partial summary is visible.
    stage(&environment, &fixture, 2);
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    assert!(environment.reconcile(2, &cancelled).unwrap().cancelled);
    assert_eq!(environment.render(1).unwrap(), initial);
    environment.publication.store.conn.execute(|conn| {
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM temp.py_env_files", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
    });
    build(&environment, &fixture, 2);
    environment.begin(3).unwrap();
    let withdrawal = environment
        .reconcile(3, &CancellationToken::default())
        .unwrap();
    assert!(withdrawal.failed.is_empty(), "{withdrawal:?}");
    assert_eq!(
        environment.render(3).unwrap(),
        "no live Python environment\n"
    );
    assert_eq!(environment.render(1).unwrap(), initial);
    let other = PythonNativeEnvironment::open(&database, typing).unwrap();
    assert_eq!(
        other.render(1).unwrap(),
        typing_render,
        "withdrawal is profile-local"
    );

    let shuffled =
        PythonNativeEnvironment::open(&fixture.root().join("shuffled.db"), profile()).unwrap();
    shuffled.begin(1).unwrap();
    let project = fixture.project_dyn();
    for file in project
        .analyzable_files(Language::Python)
        .unwrap()
        .into_iter()
        .rev()
    {
        let source = project.read_source(&file).unwrap();
        shuffled
            .stage_source(project.clone(), &file, &source, 1)
            .unwrap();
    }
    let receipt = shuffled
        .reconcile(1, &CancellationToken::default())
        .unwrap();
    assert!(receipt.failed.is_empty(), "{receipt:?}");
    assert_eq!(
        shuffled.render(1).unwrap(),
        initial,
        "allocation/enumeration order must not select providers"
    );
}

#[test]
fn python_environment_snapshot_root_and_marker_edits_match_fresh() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file(
            "pyproject.toml",
            "[tool.setuptools.packages.find]\nwhere = ['source']\n",
        )
        .file("source/pkg/model.py", "class Widget: pass\n")
        .file("source/app.py", "from pkg.model import Widget\n")
        .build();
    let workspace = PythonSummaryProfile {
        authority: PythonSummaryAuthority::Workspace,
        roots: Vec::new(),
        ordered: false,
        ..profile()
    };
    let environment =
        PythonNativeEnvironment::open(&fixture.root().join("edits.db"), workspace.clone()).unwrap();
    let first = build(&environment, &fixture, 1);
    assert!(first.contains("pkg.model | module | selected"), "{first}");
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(
        fixture.root().join("pyproject.toml"),
        "[tool.setuptools.packages.find]\nwhere = ['.']\n".into()
    ));
    let selected: Arc<dyn Project> = Arc::new(overlay.snapshot());
    for (revision, project) in [(2, selected.clone()), (3, fixture.project_dyn())] {
        environment.begin(revision).unwrap();
        for file in project.analyzable_files(Language::Python).unwrap() {
            environment
                .stage_source(
                    project.clone(),
                    &file,
                    &project.read_source(&file).unwrap(),
                    revision,
                )
                .unwrap();
        }
        let receipt = environment
            .reconcile(revision, &CancellationToken::default())
            .unwrap();
        assert!(receipt.failed.is_empty(), "{receipt:?}");
    }
    assert_eq!(environment.render(1).unwrap(), first);
    assert_eq!(environment.render(3).unwrap(), first);
    assert!(
        environment
            .render(2)
            .unwrap()
            .contains("source.pkg.model | module")
    );
    let fresh = PythonNativeEnvironment::open(&fixture.root().join("fresh.db"), workspace).unwrap();
    fresh.begin(2).unwrap();
    for file in selected.analyzable_files(Language::Python).unwrap() {
        fresh
            .stage_source(
                selected.clone(),
                &file,
                &selected.read_source(&file).unwrap(),
                2,
            )
            .unwrap();
    }
    assert!(
        fresh
            .reconcile(2, &CancellationToken::default())
            .unwrap()
            .failed
            .is_empty()
    );
    assert_eq!(fresh.render(2).unwrap(), environment.render(2).unwrap());
}

#[test]
fn python_environment_setup_root_and_marker_lifecycle() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("setup.py", "from setuptools import setup as configure\nconfigure(packages=['pkg'], package_dir={'': 'source'})\n")
        .file("source/pkg/model.py", "x = 1\n")
        .build();
    let selected = PythonSummaryProfile {
        authority: PythonSummaryAuthority::Workspace,
        roots: Vec::new(),
        ordered: false,
        ..profile()
    };
    let environment =
        PythonNativeEnvironment::open(&fixture.root().join("markers.db"), selected).unwrap();
    let initial = build(&environment, &fixture, 1);
    assert!(
        initial.contains("pkg.model | module | selected"),
        "{initial}"
    );
    assert!(initial.contains("pkg | namespace | selected"), "{initial}");
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(
        fixture.root().join("source/pkg/__init__.py"),
        "x = 2\n".into()
    ));
    let project: Arc<dyn Project> = Arc::new(overlay.snapshot());
    environment.begin(2).unwrap();
    for file in project.analyzable_files(Language::Python).unwrap() {
        environment
            .stage_source(
                project.clone(),
                &file,
                &project.read_source(&file).unwrap(),
                2,
            )
            .unwrap();
    }
    let receipt = environment
        .reconcile(2, &CancellationToken::default())
        .unwrap();
    assert!(receipt.failed.is_empty(), "{receipt:?}");
    let marked = environment.render(2).unwrap();
    assert!(marked.contains("pkg | package | selected"), "{marked}");
    assert!(marked.contains("pkg | namespace | shadowed"), "{marked}");
    assert_eq!(environment.render(1).unwrap(), initial);
    assert_eq!(
        build(&environment, &fixture, 3),
        initial,
        "removed marker must restore the namespace"
    );
}

#[test]
fn python_environment_failed_publication_rolls_back() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("src/a.py", "x = 1\n")
        .build();
    let environment =
        PythonNativeEnvironment::open(&fixture.root().join("failure.db"), profile()).unwrap();
    stage(&environment, &fixture, 1);
    environment.publication.store.conn.execute(|conn| conn.execute_batch("CREATE TRIGGER refuse_python_summary BEFORE INSERT ON python_unit_summary_roots BEGIN SELECT RAISE(ABORT,'injected summary publication failure'); END;")).unwrap();
    assert!(
        environment
            .reconcile(1, &CancellationToken::default())
            .is_err()
    );
    assert_eq!(
        environment.render(1).unwrap(),
        "no live Python environment\n"
    );
    environment.publication.store.conn.execute(|conn| {
        let summaries: i64 = conn
            .query_row(
                "SELECT count(*) FROM resolution_unit_summaries WHERE lang='python'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(summaries, 0);
        conn.execute_batch("DROP TRIGGER refuse_python_summary")
            .unwrap();
    });
    assert!(build(&environment, &fixture, 1).contains("a | module | selected"));
}

#[test]
fn python_environment_concurrent_profiles_are_independent() {
    let fixture = Arc::new(
        InlineTestProject::with_language(Language::Python)
            .file("src/a.py", "x = 1\n")
            .build(),
    );
    let database = fixture.root().join("concurrent.db");
    std::thread::scope(|scope| {
        let runtime = scope.spawn(|| {
            let environment = PythonNativeEnvironment::open(&database, profile()).unwrap();
            build(&environment, &fixture, 1)
        });
        let typing = scope.spawn(|| {
            let mut selected = profile();
            selected.observation = PythonSummaryObservation::Typing;
            let environment = PythonNativeEnvironment::open(&database, selected).unwrap();
            build(&environment, &fixture, 1)
        });
        assert!(runtime.join().unwrap().contains("observation=runtime"));
        assert!(typing.join().unwrap().contains("observation=typing"));
    });
    assert!(
        PythonNativeEnvironment::open(&database, profile())
            .unwrap()
            .render(1)
            .unwrap()
            .contains("observation=runtime")
    );
}

/// A receipt, deliberately not a timing gate. Inputs are supplied by the lane
/// runner so ordinary tests never scan a checkout or discover an interpreter.
#[test]
#[ignore = "requires BIFROST_PYTHON_ENV_ROOT and BIFROST_PYTHON_ENV_FILES"]
fn measure_python_environment_reconcile() {
    let root =
        PathBuf::from(std::env::var_os("BIFROST_PYTHON_ENV_ROOT").expect("selected corpus root"));
    let manifest = std::fs::read_to_string(
        std::env::var_os("BIFROST_PYTHON_ENV_FILES").expect("selected file manifest"),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut selected = profile();
    selected.roots = vec![PathBuf::new()];
    let environment =
        PythonNativeEnvironment::open(&directory.path().join("corpus.db"), selected).unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Python));
    let first = manifest.lines().next().expect("nonempty corpus");
    for revision in [1, 2] {
        environment.begin(revision).unwrap();
        let started = Instant::now();
        let mut files = 0;
        for relative in manifest.lines() {
            let file = ProjectFile::new(&root, relative);
            let mut source = project.read_source(&file).unwrap();
            if revision == 2 && relative == first {
                source.push_str("\n# native environment receipt edit\n");
            }
            environment
                .stage_source(project.clone(), &file, &source, revision)
                .unwrap();
            files += 1;
        }
        let staging = started.elapsed();
        let receipt = environment
            .reconcile(revision, &CancellationToken::default())
            .unwrap();
        assert!(receipt.failed.is_empty(), "{receipt:?}");
        println!(
            "PYTHON_ENV_RECEIPT root={} files={files} revision={revision} input_seconds={} reconcile={receipt:?}",
            root.display(),
            staging.as_secs_f64()
        );
        assert!(
            receipt.statements > 0,
            "measurement must count actual SQL statements"
        );
    }
}
