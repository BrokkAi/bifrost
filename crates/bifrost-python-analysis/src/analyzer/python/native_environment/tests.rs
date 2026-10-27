use super::*;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::{
    PythonSummaryAuthority, PythonSummaryObservation,
};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
use brokk_bifrost_core::analyzer::project::{OverlayProject, TestProject};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

fn profile() -> PythonSummaryProfile {
    PythonSummaryProfile {
        authority: PythonSummaryAuthority::SuppliedAnalysis,
        observation: PythonSummaryObservation::Runtime,
        roots: vec![PathBuf::from("src")],
        ordered: true,
        target_digest: [0; 32],
        python_version: None,
    }
}
fn workspace_profile() -> PythonSummaryProfile {
    PythonSummaryProfile {
        authority: PythonSummaryAuthority::Workspace,
        roots: Vec::new(),
        ordered: false,
        ..profile()
    }
}
fn build(environment: &PythonNativeEnvironment, fixture: &BuiltInlineTestProject) -> (i64, String) {
    let revision = environment.publish_project(fixture.project_dyn()).unwrap();
    let receipt = environment
        .reconcile(revision, &CancellationToken::default())
        .unwrap();
    assert!(receipt.failed.is_empty(), "{receipt:?}");
    (revision, environment.render(revision).unwrap())
}

#[test]
fn python_environment_profiles_reopen_withdraw_cancel_and_shuffle() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("src/pkg/__init__.py", "from .model import Widget\n")
        .file("src/pkg/model.py", "class Widget: pass\n_private = 1\n")
        .file("src/user.py", "from pkg.model import Widget\n")
        .build();
    let database = fixture.root().join("environment.db");
    let environment = PythonNativeEnvironment::open(&database, fixture.root(), profile()).unwrap();
    let (first, initial) = build(&environment, &fixture);
    assert!(
        initial.contains("pkg.model | module | selected"),
        "{initial}"
    );
    let warm = environment
        .reconcile(first, &CancellationToken::default())
        .unwrap();
    assert_eq!(warm.unchanged, 1, "{warm:?}");
    let mut typing = profile();
    typing.observation = PythonSummaryObservation::Typing;
    let other = PythonNativeEnvironment::open(&database, fixture.root(), typing.clone()).unwrap();
    let (typing_revision, typing_render) = build(&other, &fixture);
    assert_eq!(typing_revision, first);
    assert!(typing_render.starts_with("authority=supplied_analysis observation=typing"));
    assert_eq!(environment.render(first).unwrap(), initial);
    drop(other);
    drop(environment);
    let environment = PythonNativeEnvironment::open(&database, fixture.root(), profile()).unwrap();
    assert_eq!(
        environment.render(first).unwrap(),
        initial,
        "reopen needs no TEMP metadata"
    );
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(
        fixture.root().join("src/pkg/model.py"),
        "class Widget: pass\n# edit\n".into()
    ));
    let revision = environment
        .publish_project(Arc::new(overlay.snapshot()))
        .unwrap();
    assert!(revision > first);
    // Cancel while the first file is being placed, after the stream reached it.
    let cancelled = CancellationToken::default();
    let cancel_at_root = cancelled.clone();
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reached_root = reached.clone();
    let root = python_environment_root(fixture.root().to_owned());
    let mut snapshot = environment.publication.snapshot.clone();
    snapshot.revision = revision;
    let receipt = environment
        .publication
        .store
        .reconcile_python_environment(
            &snapshot,
            workspace_profile(),
            move |path, inputs| {
                reached_root.store(true, std::sync::atomic::Ordering::SeqCst);
                cancel_at_root.cancel();
                root(path, inputs)
            },
            &cancelled,
        )
        .unwrap();
    assert!(receipt.cancelled, "{receipt:?}");
    assert!(
        reached.load(std::sync::atomic::Ordering::SeqCst),
        "selected file placement ran"
    );
    assert_eq!(environment.render(first).unwrap(), initial);
    environment.publication.store.conn.execute(move |conn| {
        let staged: i64 = conn
            .query_row("SELECT count(*) FROM temp.py_env_files", [], |r| r.get(0))
            .unwrap();
        assert_eq!(staged, 0);
        let published: i64 = conn
            .query_row(
                "SELECT count(*) FROM resolution_unit_summary_versions WHERE valid_from=?1",
                [revision],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            published, 0,
            "cancellation must not publish a partial summary"
        );
    });
    let edited = environment
        .reconcile(revision, &CancellationToken::default())
        .unwrap();
    assert_eq!(edited.derived, 1, "{edited:?}");
    let empty = environment
        .publish_sources(fixture.project_dyn(), &BTreeSet::new())
        .unwrap();
    let withdrawal = environment
        .reconcile(empty, &CancellationToken::default())
        .unwrap();
    assert!(withdrawal.failed.is_empty(), "{withdrawal:?}");
    assert_eq!(
        environment.render(empty).unwrap(),
        "no live Python environment\n"
    );
    assert_eq!(environment.render(first).unwrap(), initial);
    let other = PythonNativeEnvironment::open(&database, fixture.root(), typing).unwrap();
    assert_eq!(
        other.render(first).unwrap(),
        typing_render,
        "withdrawal is profile-local"
    );
    let shuffled = PythonNativeEnvironment::open(
        &fixture.root().join("shuffled.db"),
        fixture.root(),
        profile(),
    )
    .unwrap();
    let (shuffled_revision, shuffled_render) = build(&shuffled, &fixture);
    assert_eq!(
        shuffled_render, initial,
        "allocation order must not select providers"
    );
    assert_eq!(
        shuffled
            .reconcile(shuffled_revision, &CancellationToken::default())
            .unwrap()
            .unchanged,
        1
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
    let environment = PythonNativeEnvironment::open(
        &fixture.root().join("edits.db"),
        fixture.root(),
        workspace_profile(),
    )
    .unwrap();
    let first = environment.publish_project(fixture.project_dyn()).unwrap();
    // Publish B before deriving A: A's roots must still read its own exact bytes.
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(
        fixture.root().join("pyproject.toml"),
        "[tool.setuptools.packages.find]\nwhere = ['.']\n".into()
    ));
    let selected: Arc<dyn Project> = Arc::new(overlay.snapshot());
    let second = environment.publish_project(selected.clone()).unwrap();
    assert!(second > first);
    // Make every source/configuration read fail on disk. Reconcile has no Project.
    for path in ["pyproject.toml", "source/pkg/model.py", "source/app.py"] {
        std::fs::remove_file(fixture.root().join(path)).unwrap();
    }
    let derived = environment
        .reconcile(first, &CancellationToken::default())
        .unwrap();
    assert_eq!(derived.derived, 1, "nonempty SQL-only derive: {derived:?}");
    let initial = environment.render(first).unwrap();
    assert!(
        initial.contains("pkg.model | module | selected"),
        "{initial}"
    );
    let warm = environment
        .reconcile(first, &CancellationToken::default())
        .unwrap();
    assert_eq!(warm.unchanged, 1, "nonempty SQL-only reuse: {warm:?}");
    assert!(
        environment
            .reconcile(second, &CancellationToken::default())
            .unwrap()
            .failed
            .is_empty()
    );
    let changed = environment.render(second).unwrap();
    assert!(changed.contains("source.pkg.model | module"), "{changed}");
    assert_eq!(environment.render(first).unwrap(), initial);
}

#[test]
fn python_environment_setup_root_and_marker_lifecycle() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("setup.py", "from setuptools import setup as configure\nconfigure(packages=['pkg'], package_dir={'': 'source'})\n")
        .file("source/pkg/model.py", "x = 1\n")
        .build();
    let environment = PythonNativeEnvironment::open(
        &fixture.root().join("markers.db"),
        fixture.root(),
        workspace_profile(),
    )
    .unwrap();
    let (first, initial) = build(&environment, &fixture);
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
    let second = environment.publish_project(project.clone()).unwrap();
    assert!(
        environment
            .reconcile(second, &CancellationToken::default())
            .unwrap()
            .failed
            .is_empty()
    );
    let marked = environment.render(second).unwrap();
    assert!(marked.contains("pkg | package | selected"), "{marked}");
    assert!(marked.contains("pkg | namespace | shadowed"), "{marked}");
    assert_eq!(environment.render(first).unwrap(), initial);
    let fresh = PythonNativeEnvironment::open(
        &fixture.root().join("fresh.db"),
        fixture.root(),
        workspace_profile(),
    )
    .unwrap();
    let fresh_revision = fresh.publish_project(project).unwrap();
    assert!(
        fresh
            .reconcile(fresh_revision, &CancellationToken::default())
            .unwrap()
            .failed
            .is_empty()
    );
    assert_eq!(fresh.render(fresh_revision).unwrap(), marked);
    assert_eq!(
        build(&environment, &fixture).1,
        initial,
        "removed marker restores namespace"
    );
}

#[test]
fn python_environment_failed_publication_rolls_back() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("src/a.py", "x = 1\n")
        .build();
    let environment = PythonNativeEnvironment::open(
        &fixture.root().join("failure.db"),
        fixture.root(),
        profile(),
    )
    .unwrap();
    let revision = environment.publish_project(fixture.project_dyn()).unwrap();
    environment.publication.store.conn.execute(|conn| conn.execute_batch("CREATE TRIGGER refuse_python_summary BEFORE INSERT ON python_unit_summary_roots BEGIN SELECT RAISE(ABORT,'injected summary publication failure'); END;")).unwrap();
    assert!(
        environment
            .reconcile(revision, &CancellationToken::default())
            .is_err()
    );
    assert_eq!(
        environment.render(revision).unwrap(),
        "no live Python environment\n"
    );
    environment.publication.store.conn.execute(move |conn| {
        let summaries: i64 = conn
            .query_row(
                "SELECT count(*) FROM resolution_unit_summaries WHERE lang='python'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(summaries, 0);
        conn.execute_batch("DROP TRIGGER refuse_python_summary")
            .unwrap();
    });
    assert!(
        build(&environment, &fixture)
            .1
            .contains("a | module | selected")
    );
}

#[test]
fn python_environment_selected_configuration_requires_retained_bytes() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file(
            "pyproject.toml",
            "[tool.setuptools.packages.find]\nwhere = ['src']\n",
        )
        .file("src/a.py", "x = 1\n")
        .build();
    let environment = PythonNativeEnvironment::open(
        &fixture.root().join("missing.db"),
        fixture.root(),
        workspace_profile(),
    )
    .unwrap();
    let revision = environment.publish_project(fixture.project_dyn()).unwrap();
    environment
        .publication
        .store
        .conn
        .execute(|conn| conn.execute("DELETE FROM workspace_input_sources", []))
        .unwrap();
    let error = environment
        .reconcile(revision, &CancellationToken::default())
        .unwrap_err();
    assert!(error.is_missing_required_source_facts(), "{error}");
    assert!(error.to_string().contains("pyproject.toml"), "{error}");
    assert_eq!(
        environment.render(revision).unwrap(),
        "no live Python environment\n"
    );
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
            let environment =
                PythonNativeEnvironment::open(&database, fixture.root(), profile()).unwrap();
            build(&environment, &fixture).1
        });
        let typing = scope.spawn(|| {
            let mut selected = profile();
            selected.observation = PythonSummaryObservation::Typing;
            let environment =
                PythonNativeEnvironment::open(&database, fixture.root(), selected).unwrap();
            build(&environment, &fixture).1
        });
        assert!(runtime.join().unwrap().contains("observation=runtime"));
        assert!(typing.join().unwrap().contains("observation=typing"));
    });
}

/// A receipt, deliberately not a timing gate. Never scans a checkout by default.
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
        PythonNativeEnvironment::open_scoped(&directory.path().join("corpus.db"), &root, selected)
            .unwrap();
    let base: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Python));
    let files: BTreeSet<_> = manifest
        .lines()
        .map(|relative| ProjectFile::new(&root, relative))
        .collect();
    let first = files.first().expect("nonempty corpus");
    let overlay = Arc::new(OverlayProject::new(base.clone()));
    assert!(overlay.set(
        first.abs_path(),
        format!(
            "{}\n# native environment receipt edit\n",
            base.read_source(first).unwrap()
        )
    ));
    for project in [base, Arc::new(overlay.snapshot()) as Arc<dyn Project>] {
        let started = Instant::now();
        let revision = environment.publish_sources(project, &files).unwrap();
        let publication = started.elapsed();
        let receipt = environment
            .reconcile(revision, &CancellationToken::default())
            .unwrap();
        assert!(receipt.failed.is_empty(), "{receipt:?}");
        println!(
            "PYTHON_ENV_RECEIPT root={} files={} revision={revision} input_seconds={} reconcile={receipt:?}",
            root.display(),
            files.len(),
            publication.as_secs_f64()
        );
        assert!(
            receipt.statements > 0,
            "actual SQL statements must be counted"
        );
    }
}

use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon(
    "#2053: retained event commits must exclude the current RHS and preserve conditional rebinding arms"
)]
fn module_rebindings_retained_temporal_selection() {
    let source = "def convert(value):\n    return value\nconvert = decorate(convert)\nafter = convert(1)\nif enabled:\n    convert = native\nelse:\n    convert = fallback\nfinal = convert\n";
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("src/timeline.py", source)
        .build();
    let database = fixture.root().join("bindings.db");
    let environment = PythonNativeEnvironment::open(
        &database,
        fixture.root(),
        PythonSummaryProfile {
            authority: PythonSummaryAuthority::SuppliedAnalysis,
            observation: PythonSummaryObservation::Runtime,
            roots: vec![PathBuf::from("src")],
            ordered: true,
            target_digest: [0; 32],
            python_version: None,
        },
    )
    .unwrap();
    let revision = environment.publish_project(fixture.project_dyn()).unwrap();
    let receipt = environment
        .reconcile(revision, &CancellationToken::default())
        .unwrap();
    assert!(receipt.failed.is_empty(), "{receipt:?}");
    let rhs = source.find("decorate(convert)").unwrap() + "decorate(".len();
    let after = source.find("convert(1)").unwrap();
    let final_read = source.rfind("convert").unwrap();
    let rhs_trace = environment
        .temporal_binding_trace(revision, "src/timeline.py", rhs, "convert")
        .unwrap();
    let after_trace = environment
        .temporal_binding_trace(revision, "src/timeline.py", after, "convert")
        .unwrap();
    let final_trace = environment
        .temporal_binding_trace(revision, "src/timeline.py", final_read, "convert")
        .unwrap();
    let function = format!("Function@{}:", source.find("def convert").unwrap());
    let assignment = format!("Assign@{}:", source.find("convert = decorate").unwrap());
    let native = format!("Assign@{}:", source.find("convert = native").unwrap());
    let fallback = format!("Assign@{}:", source.find("convert = fallback").unwrap());
    assert!(rhs_trace.contains(&function), "{rhs_trace}");
    assert!(
        !rhs_trace.contains(&assignment),
        "uncommitted write: {rhs_trace}"
    );
    assert!(after_trace.contains(&assignment), "{after_trace}");
    assert!(
        !after_trace.contains(&function),
        "shadowed declaration: {after_trace}"
    );
    assert!(
        final_trace.contains(&native) && final_trace.contains(&fallback),
        "{final_trace}"
    );
    assert!(
        !final_trace.contains(&assignment),
        "exhaustive arms: {final_trace}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6108: cold bulk publication skipped Python native binding rows"
)]
fn python_trial_cold_index_publishes_scoped_blobs() {
    const CHILD: &str = "BIFROST_PYTHON_COLD_INDEX_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for trial in [false, true] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "analyzer::python::native_environment::tests::python_trial_cold_index_publishes_scoped_blobs",
                "--nocapture",
            ]).env(CHILD, "1").env_remove("BIFROST_TRIAL_NATIVE_PYTHON");
            if trial {
                // Presence, including an empty value, selects the trial.
                command.env("BIFROST_TRIAL_NATIVE_PYTHON", "");
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "trial={trial}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "the selected child test must run: trial={trial}: {output:?}",
            );
        }
        return;
    }
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_store;
    // The project is authored inline: this crate is open core, and the root
    // `tests/` tree is private and absent from the projected public workspace.
    let fixture = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/__init__.py",
            "from .model import Widget\n__all__ = [\"Widget\"]\n",
        )
        .file("pkg/model.py", "class Widget: pass\nx = 1\n")
        .file(
            "api.py",
            "from pkg import model\nfrom pkg.model import Widget\nimport absent.provider as unknown\n",
        )
        .file("reexport.py", "from pkg import *\n")
        .build();
    let project = fixture.project_dyn();
    let expected = project.analyzable_files(Language::Python).unwrap().len();
    assert!(
        expected > 1,
        "the cold index must visit multiple Python files"
    );
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("cold.db");
    let store = AnalyzerStore::open_persistent(&database).unwrap();
    let context = store_context_from_store(project.as_ref(), store, false);
    let store = context.store.clone();
    let _analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        project,
        PythonAdapter::default(),
        Default::default(),
        context,
        None,
    )
    .unwrap();
    let sql = store.read_conn().unwrap();
    let indexed: usize = sql
        .query_row(
            "SELECT count(*) FROM blobs WHERE lang='python'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(indexed, expected, "prove the cold indexing path ran");
    let published: usize = sql.query_row(
        "SELECT count(*) FROM python_binding_source source JOIN blobs ON blobs.id=source.blob_id WHERE blobs.lang='python'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(
        published,
        if super::super::trial_native_python_selected() {
            expected
        } else {
            0
        }
    );
}
