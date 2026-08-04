//! Analyzer-level persistence behavior for the blob-keyed SQLite store.

use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::analyzer::{BuildProgressEvent, BuildProgressPhase, store::analyzer_db_path};
use brokk_bifrost::{
    AnalyzerConfig, IAnalyzer, Language, Project, ProjectFile, PythonAnalyzer, TestProject,
    WorkspaceAnalyzer,
};
use git2::{IndexAddOption, Repository, Signature};
use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, Once};

/// Keep this process's opportunistic analyzer-store GC permanently out of the
/// picture (see `AnalyzerGcCoordinator::schedule`).
///
/// A brand-new `cache_state` row starts with `last_gc_at = 0`, so a store's
/// very first `build_persisted*` call always finds GC "due" (`gc_due_tx`:
/// `now - 0 >= GC_MIN_INTERVAL_SECS` is trivially true) and spawns a real
/// background sweep against the *same* SQLite file this test file's `cold`
/// build just wrote and its `warm` build immediately reopens. Under light
/// load the sweep finishes microseconds later, long before the warm build
/// touches the store, so the race is invisible. Under heavy box load
/// (parallel `cargo build`, an oversubscribed CPU) the sweep can still be
/// mid-transaction when the warm build's connection opens, and lock
/// contention on that shared file perturbs the "warm" build/query into doing
/// structured work — a re-parse, extra candidate hydration — that the
/// `warm_*` family asserts never happens (issue #1099). GC readiness is not
/// under test anywhere in this file, so raise the interval once, for the
/// whole process, instead of threading a guard through every test. The
/// returned `GcIntervalGuard` wraps a `MutexGuard` (see `GcTuningGuard`) that
/// is not `Send`, so it cannot live in a `static`; `mem::forget` it instead
/// to hold the override (and the internal tuning lock) for the rest of the
/// process, which is safe because nothing else in this binary calls
/// `set_tuning_for_test`.
fn disable_opportunistic_gc_for_test() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let guard = brokk_bifrost::analyzer::store::gc::set_min_interval_secs_for_test(i64::MAX);
        std::mem::forget(guard);
    });
}

fn build_persisted(project: Arc<dyn Project>, config: AnalyzerConfig) -> WorkspaceAnalyzer {
    disable_opportunistic_gc_for_test();
    WorkspaceAnalyzer::build_persisted(project, config).expect("persisted analyzer should build")
}

fn build_persisted_with_progress<F>(
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    progress: F,
) -> WorkspaceAnalyzer
where
    F: Fn(BuildProgressEvent) + Send + Sync + 'static,
{
    disable_opportunistic_gc_for_test();
    WorkspaceAnalyzer::build_persisted_with_progress(project, config, progress)
        .expect("persisted analyzer should build")
}

fn write_file(root: &Path, rel: &str, body: &str) {
    let abs = root.join(rel);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(abs, body).unwrap();
}

fn init_git_repo(root: &Path) -> Repository {
    let repo = Repository::init(root).unwrap();
    let mut config = repo.config().unwrap();
    config.set_str("user.name", "Bifrost Test").unwrap();
    config.set_str("user.email", "bifrost@example.com").unwrap();
    repo
}

fn commit_all(repo: &Repository, message: &str) {
    let mut index = repo.index().unwrap();
    // Persisted analyzers keep their SQLite database under `.bifrost/cache`. A later
    // fixture commit must not race those live database files into the Git
    // index; only the workspace sources are part of the test repository.
    let mut skip_analyzer_cache = |path: &Path, _matched_pathspec: &[u8]| {
        i32::from(path.starts_with(Path::new(".bifrost/cache")))
    };
    index
        .add_all(
            ["*"],
            IndexAddOption::DEFAULT,
            Some(&mut skip_analyzer_cache),
        )
        .unwrap();
    index.write().unwrap();
    let tree_oid = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_oid).unwrap();
    let sig = Signature::now("Bifrost Test", "bifrost@example.com").unwrap();
    let parents = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok())
        .into_iter()
        .collect::<Vec<_>>();
    let parent_refs = parents.iter().collect::<Vec<_>>();
    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
        .unwrap();
}

fn python_project(root: &Path) -> Arc<dyn Project> {
    Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ))
}

fn language_python_project(root: &Path, language: Language) -> Arc<dyn Project> {
    Arc::new(TestProject::with_languages(
        root.canonicalize().unwrap(),
        BTreeSet::from([language, Language::Python]),
    ))
}

fn parsed_file_count(events: &[BuildProgressEvent]) -> usize {
    events
        .iter()
        .filter(|event| event.phase == BuildProgressPhase::Parse)
        .filter(|event| event.file.is_some())
        .count()
}

#[test]
fn persisted_build_reports_cache_open_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "example.py", "def example():\n    return 1\n");
    init_git_repo(root);
    fs::write(root.join(".bifrost"), "not a directory").unwrap();
    let project = python_project(root);

    let error = match WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default()) {
        Ok(_) => panic!("persisted build unexpectedly fell back to an in-memory store"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("opening the persisted analyzer store"),
        "missing persisted-store context: {message}"
    );
    assert!(
        message.contains(".bifrost") || message.contains("bifrost_cache.db"),
        "missing failed cache path: {message}"
    );
}

fn assert_warm_multilanguage_definition_query(
    project: Arc<dyn Project>,
    query: brokk_bifrost::searchtools::DefinitionReferenceQuery,
    expected_fqn: &str,
) {
    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    let analyzer = warm.analyzer();
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
    analyzer
        .test_hooks()
        .reset_global_usage_definition_index_build_count_for_test();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_candidate_hydration_count_for_test();
    analyzer
        .test_hooks()
        .reset_workspace_path_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_scala_project_types_build_count_for_test();
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    assert!(
        analyzer.test_hooks().candidate_hydration_count_for_test() < 32,
        "forward lookup hydrated the unrelated generated-file set"
    );
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );

    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![query],
        },
    );

    assert_eq!(result.results[0].status, "resolved");
    assert_eq!(
        result.results[0].definitions[0].fqn.as_deref(),
        Some(expected_fqn)
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    assert!(
        analyzer.test_hooks().candidate_hydration_count_for_test() < 32,
        "forward lookup hydrated the unrelated generated-file set"
    );
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );
}

fn assert_warm_multilanguage_type_query(
    project: Arc<dyn Project>,
    query: brokk_bifrost::searchtools::TypeReferenceQuery,
    expected_fqn: &str,
) {
    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    let analyzer = warm.analyzer();
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
    analyzer
        .test_hooks()
        .reset_global_usage_definition_index_build_count_for_test();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_candidate_hydration_count_for_test();
    analyzer
        .test_hooks()
        .reset_workspace_path_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_scala_project_types_build_count_for_test();

    let result = brokk_bifrost::searchtools::get_type_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetTypeParams {
            references: vec![query],
        },
    );

    assert_eq!(result.results[0].status, "resolved");
    assert_eq!(result.results[0].types[0].fqn, expected_fqn);
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    let hydration_count = analyzer.test_hooks().candidate_hydration_count_for_test();
    assert!(
        hydration_count < 32,
        "type lookup hydrated the unrelated generated-file set: {hydration_count} hydrations ({} full, {} bulk)",
        analyzer
            .test_hooks()
            .full_candidate_hydration_count_for_test(),
        analyzer
            .test_hooks()
            .bulk_candidate_hydration_count_for_test()
    );
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );
}

fn assert_warm_multilanguage_no_definition_query(
    project: Arc<dyn Project>,
    query: brokk_bifrost::searchtools::DefinitionReferenceQuery,
) {
    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    let analyzer = warm.analyzer();
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
    analyzer
        .test_hooks()
        .reset_global_usage_definition_index_build_count_for_test();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_candidate_hydration_count_for_test();
    analyzer
        .test_hooks()
        .reset_workspace_path_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_scala_project_types_build_count_for_test();

    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![query],
        },
    );

    assert_eq!(result.results[0].status, "no_definition");
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    assert!(analyzer.test_hooks().candidate_hydration_count_for_test() < 32);
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );
}

fn write_unrelated_generated_files(root: &Path, extension: &str, body: &str) {
    for index in 0..32 {
        write_file(
            root,
            &format!("generated/unrelated_{index}.{extension}"),
            body,
        );
    }
}

fn declaration_names(analyzer: &dyn IAnalyzer) -> BTreeSet<String> {
    analyzer
        .all_declarations()
        .map(|unit| unit.fq_name())
        .collect()
}

#[test]
fn warm_multilanguage_go_definition_query_does_not_build_full_definition_index() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "go.mod", "module example.com/app\n");
    write_file(
        root,
        "main.go",
        "package main\n\nimport \"example.com/app/generated/client\"\n\nfunc Run() { api.Helper() }\n",
    );
    write_file(
        root,
        "generated/client/client.go",
        "package api\n\nfunc Helper() {}\n",
    );
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Go),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "main.go".to_string(),
            line: Some(5),
            column: Some(18),
        },
        "example.com/app/generated/client.Helper",
    );
}

#[test]
fn warm_multilanguage_csharp_definition_query_does_not_build_full_definition_index() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "Lib/Service.cs",
        "namespace Lib { public class Service { public void Run() {} } }\n",
    );
    let caller = "using Lib;\nnamespace App { public class Controller { public void Handle() { var service = new Service(); service.Run(); } } }\n";
    write_file(root, "App/Controller.cs", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let call_line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::CSharp),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "App/Controller.cs".to_string(),
            line: Some(2),
            column: Some(call_line.find("Run").unwrap() + 1),
        },
        "Lib.Service.Run",
    );
}

#[test]
fn warm_csharp_inherited_member_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "Lib/Types.cs",
        "namespace Lib { public class Base { public void Run() {} } public class Child : Base {} }\n",
    );
    let caller = "using Lib;\nnamespace App { public class Controller { public void Handle(Child child) { child.Run(); } } }\n";
    write_file(root, "App/Controller.cs", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "cs",
        "namespace Generated { public class Unrelated {} }\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::CSharp),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "App/Controller.cs".to_string(),
            line: Some(2),
            column: Some(line.find("Run").unwrap() + 1),
        },
        "Lib.Base.Run",
    );
}

#[test]
fn warm_csharp_global_using_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "GlobalUsings.cs", "global using Lib;\n");
    write_file(
        root,
        "Lib/Service.cs",
        "namespace Lib { public class Service { public void Run() {} } }\n",
    );
    let caller = "namespace App { public class Controller { public void Handle(Service service) { service.Run(); } } }\n";
    write_file(root, "App/Controller.cs", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "cs",
        "namespace Generated { public class Unrelated {} }\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::CSharp),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "App/Controller.cs".to_string(),
            line: Some(1),
            column: Some(caller.find("Run").unwrap() + 1),
        },
        "Lib.Service.Run",
    );
}

#[test]
fn warm_csharp_factory_return_receiver_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "Lib/Services.cs",
        "namespace Lib { public class Service { public void Run() {} } public class Factory { public Service Create() { return new Service(); } } }\n",
    );
    let caller = "using Lib;\nnamespace App { public class Controller { public void Handle(Factory factory) { factory.Create().Run(); } } }\n";
    write_file(root, "App/Controller.cs", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "cs",
        "namespace Generated { public class Unrelated {} }\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::CSharp),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "App/Controller.cs".to_string(),
            line: Some(2),
            column: Some(line.rfind("Run").unwrap() + 1),
        },
        "Lib.Service.Run",
    );
}

/// The structured `FqName` segments (interned `(kind, text)` pairs) persisted
/// to `code_units.fq_segments` in M3 must survive a close/reopen byte-for-byte:
/// a cache-loaded unit's segments — KIND and TEXT — must equal the
/// freshly-extracted unit's. The fixture deliberately includes the two
/// spelling-hard languages: C++ (a `::`-headed namespace `Package` chain) and
/// Scala (a `Companion` object whose name carries a trailing `$`). Because the
/// warm build re-parses nothing (`parsed_file_count == 0`), its units are purely
/// cache-loaded, so equality proves the round-trip and not a re-extraction. The
/// The structured column is authoritative during hydration, so this also proves
/// that the display projections are derived from the restored identity.
#[test]
fn warm_fq_segments_survive_store_roundtrip_across_languages() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "widget.cpp",
        r#"
namespace ns {
namespace inner {
class Widget {
public:
    int compute();
};
int Widget::compute() { return 1; }
}
}
"#,
    );
    write_file(
        root,
        "Registry.scala",
        r#"
package demo

object Registry {
  def create(): Int = 1
}

class Registry {
  def use(): Int = 2
}
"#,
    );
    write_file(
        root,
        "mod.py",
        "class Holder:\n    def value(self):\n        return 1\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "fq segment roundtrip fixture");
    let canonical_root = root.canonicalize().unwrap();
    let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
        canonical_root.clone(),
        BTreeSet::from([Language::Cpp, Language::Scala, Language::Python]),
    ));
    let files: Vec<ProjectFile> = ["widget.cpp", "Registry.scala", "mod.py"]
        .iter()
        .map(|rel| ProjectFile::new(canonical_root.clone(), *rel))
        .collect();

    // Cold build extracts + persists; the per-file FileState it serves carries
    // the freshly-interned `fq` on every declaration.
    let cold = build_persisted(project.clone(), AnalyzerConfig::default());
    let fresh_segments = fq_segments_by_name(cold.analyzer(), &files);
    drop(cold);

    // Warm build reopens from cache and must not re-parse a single file.
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(
        parsed_file_count(&warm_events.lock().unwrap()),
        0,
        "warm build must serve purely from cache so segment equality proves a round-trip"
    );
    let loaded_segments = fq_segments_by_name(warm.analyzer(), &files);

    assert_eq!(
        loaded_segments, fresh_segments,
        "cache-loaded fq segments (kind AND text) must equal the freshly-extracted ones"
    );

    // Prove the two spelling-hard cases are actually present and structured, not
    // silently empty (which would make the equality above vacuous for them).
    assert_eq!(
        loaded_segments.get("ns::inner.Widget.compute"),
        Some(&vec![
            ("Package".to_string(), "ns".to_string()),
            ("Package".to_string(), "inner".to_string()),
            ("Type".to_string(), "Widget".to_string()),
            ("Member".to_string(), "compute".to_string()),
        ]),
        "cpp `::`-headed namespace chain must round-trip as Package/Type/Member segments; \
         got {loaded_segments:#?}"
    );
    assert_eq!(
        loaded_segments.get("demo.Registry$.create"),
        Some(&vec![
            ("Package".to_string(), "demo".to_string()),
            ("Companion".to_string(), "Registry".to_string()),
            ("Member".to_string(), "create".to_string()),
        ]),
        "scala companion object must round-trip as a Companion segment; got {loaded_segments:#?}"
    );
}

/// Map each file's declarations (drawn from the per-file FileState, which is the
/// path M3 wired `fq` through on load — as opposed to the string-keyed
/// `get_all_declarations` candidate-row path, which stays string-based for M4)
/// to their structured segment `(kind_name, text)` pairs. Skips units whose `fq`
/// is empty (synthetic file-scope units). Keyed by `fq_name()` so a
/// freshly-extracted map and a cache-loaded map compare directly.
fn fq_segments_by_name(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
) -> std::collections::BTreeMap<String, Vec<(String, String)>> {
    let mut out = std::collections::BTreeMap::new();
    for file in files {
        for unit in analyzer.get_declarations(file) {
            let segments: Vec<(String, String)> = unit
                .fq_segments_debug()
                .into_iter()
                .map(|(kind, text)| (kind.to_string(), text))
                .collect();
            if !segments.is_empty() {
                out.insert(unit.fq_name(), segments);
            }
        }
    }
    out
}

/// Issue #1345: a warm workspace must not lose the Kotlin return types and
/// extension receivers a cold build published.
///
/// Losing them would be worse than never publishing them, because the consumers
/// that read the published fact treat its absence as "the source wrote no type"
/// — so a warm build would silently answer receiver-chain and extension-
/// conformance questions differently from a cold one.
#[test]
fn warm_kotlin_return_type_and_extension_receiver_metadata_survive_store_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "src/Library.kt",
        r#"package lib

class Book(val title: String) {
    fun describe(): String = title
}

fun Book.stamp(): Book = this

fun untyped() = 1
"#,
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "kotlin signature metadata");
    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Kotlin,
    ));

    let cold = build_persisted(project.clone(), AnalyzerConfig::default());
    let cold_facts = kotlin_signature_facts(&cold);
    drop(cold);
    let warm = build_persisted(project, AnalyzerConfig::default());
    let warm_facts = kotlin_signature_facts(&warm);

    assert_eq!(
        cold_facts.get("lib.stamp"),
        Some(&(Some("Book".to_string()), Some("Book".to_string()))),
        "cold build must publish the extension's return type and receiver: \
         {cold_facts:#?}"
    );
    assert_eq!(
        cold_facts.get("lib.Book.describe"),
        Some(&(Some("String".to_string()), None))
    );
    assert_eq!(cold_facts.get("lib.untyped"), Some(&(None, None)));
    assert_eq!(
        warm_facts, cold_facts,
        "a warm build must report exactly what the cold build published"
    );
}

/// Written return type and extension receiver of every Kotlin callable and
/// property in the workspace, by fully-qualified name.
fn kotlin_signature_facts(
    workspace: &WorkspaceAnalyzer,
) -> BTreeMap<String, (Option<String>, Option<String>)> {
    let analyzer = workspace.analyzer();
    let mut out = BTreeMap::new();
    for unit in analyzer.get_all_declarations() {
        if unit.is_class() {
            continue;
        }
        let Some(metadata) = analyzer.signature_metadata(&unit).into_iter().next() else {
            continue;
        };
        out.insert(
            unit.fq_name(),
            (
                metadata.return_type_text().map(str::to_string),
                metadata.extension_receiver_type().map(str::to_string),
            ),
        );
    }
    out
}

#[test]
fn warm_csharp_unconstrained_extension_receiver_metadata_survives_store_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "Extensions.cs",
        r#"
namespace Demo;

public interface IMarked {}

public static class Extensions
{
    public static T Echo<T>(this T value) => value;
    public static T Restricted<T>(this T value) where T : IMarked => value;
}
"#,
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "generic extension metadata");
    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::CSharp,
    ));

    let cold = build_persisted(project.clone(), AnalyzerConfig::default());
    drop(cold);
    let warm = build_persisted(project, AnalyzerConfig::default());
    let declarations = warm.analyzer().get_all_declarations();

    for (name, expected_unconstrained) in [("Echo", true), ("Restricted", false)] {
        let extension = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == name
                    && warm
                        .analyzer()
                        .parent_of(unit)
                        .is_some_and(|owner| owner.fq_name() == "Demo.Extensions")
            })
            .unwrap_or_else(|| panic!("missing warm Demo.Extensions.{name}: {declarations:#?}"));
        let metadata = warm
            .analyzer()
            .signature_metadata(extension)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing warm signature metadata for {name}"));
        assert_eq!(
            metadata.extension_receiver_is_unconstrained_type_parameter(),
            expected_unconstrained,
            "{name}: {metadata:#?}"
        );
    }
}

#[test]
fn warm_multilanguage_rust_definition_query_does_not_build_full_definition_index() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let value_source = "pub struct Number;\n\npub enum Value {\n    Number(Number),\n}\n\npub fn classify(value: Value) {\n    match value {\n        Value::Number(_) => {}\n    }\n}\n";
    write_file(root, "src/value/mod.rs", value_source);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let (reference_line_index, reference_line) = value_source
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("Value::Number"))
        .unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Rust),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "src/value/mod.rs".to_string(),
            line: Some(reference_line_index + 1),
            column: Some(reference_line.find("Number").unwrap() + 1),
        },
        "value.Value.Number",
    );
}

#[test]
fn warm_multilanguage_csharp_type_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "Models/Widget.cs",
        "namespace Models { public class Widget {} }\n",
    );
    let caller = "using Models;\nnamespace App { public class UseWidget { public void Render(Widget input) { input.ToString(); } } }\n";
    write_file(root, "App/UseWidget.cs", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "cs",
        "namespace Generated { public class Unrelated {} }\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_type_query(
        language_python_project(root, Language::CSharp),
        brokk_bifrost::searchtools::TypeReferenceQuery {
            path: "App/UseWidget.cs".to_string(),
            line: Some(2),
            column: Some(line.find("input.ToString").unwrap() + 1),
        },
        "Models.Widget",
    );
}

#[test]
fn warm_multilanguage_go_type_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "go.mod", "module example.com/app\n");
    write_file(
        root,
        "store/store.go",
        "package store\ntype Client struct{}\n",
    );
    let caller = "package main\nimport \"example.com/app/store\"\nfunc Run() {\n    var client store.Client\n    _ = client\n}\n";
    write_file(root, "main.go", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "go", "package generated\ntype Unrelated struct{}\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(4).unwrap();
    assert_warm_multilanguage_type_query(
        language_python_project(root, Language::Go),
        brokk_bifrost::searchtools::TypeReferenceQuery {
            path: "main.go".to_string(),
            line: Some(5),
            column: Some(line.find("client").unwrap() + 1),
        },
        "example.com/app/store.Client",
    );
}

#[test]
fn warm_multilanguage_java_type_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "models/Widget.java",
        "package models; public class Widget {}\n",
    );
    let caller = "package app;\nimport models.Widget;\npublic class UseWidget { public void render(Widget input) { Widget local = input; local.toString(); } }\n";
    write_file(root, "app/UseWidget.java", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "java", "package generated; class Unrelated {}\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(2).unwrap();
    assert_warm_multilanguage_type_query(
        language_python_project(root, Language::Java),
        brokk_bifrost::searchtools::TypeReferenceQuery {
            path: "app/UseWidget.java".to_string(),
            line: Some(3),
            column: Some(line.find("local.toString").unwrap() + 1),
        },
        "models.Widget",
    );
}

#[test]
fn warm_multilanguage_typescript_type_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "model.ts", "export class Widget {}\n");
    let caller = "import * as Models from './model';\nconst value: Models.Widget = new Models.Widget();\nvalue;\n";
    write_file(root, "app.ts", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "ts", "export class Unrelated {}\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(2).unwrap();
    assert_warm_multilanguage_type_query(
        language_python_project(root, Language::TypeScript),
        brokk_bifrost::searchtools::TypeReferenceQuery {
            path: "app.ts".to_string(),
            line: Some(3),
            column: Some(line.find("value").unwrap() + 1),
        },
        "Widget",
    );
}

#[test]
fn warm_multilanguage_javascript_type_query_stays_bounded_when_unsupported() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "app.js",
        "const value = new Widget();\nclass Widget {}\n",
    );
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "js", "export class Unrelated {}\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = language_python_project(root, Language::JavaScript);
    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    let analyzer = warm.analyzer();
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
    analyzer
        .test_hooks()
        .reset_global_usage_definition_index_build_count_for_test();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_candidate_hydration_count_for_test();
    analyzer
        .test_hooks()
        .reset_workspace_path_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_scala_project_types_build_count_for_test();

    let result = brokk_bifrost::searchtools::get_type_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetTypeParams {
            references: vec![brokk_bifrost::searchtools::TypeReferenceQuery {
                path: "app.js".to_string(),
                line: Some(1),
                column: Some("const ".len() + 1),
            }],
        },
    );

    assert_eq!(result.results[0].status, "no_type");
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    assert!(
        analyzer.test_hooks().candidate_hydration_count_for_test() < 32,
        "type lookup hydrated the unrelated generated-file set"
    );
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );
}

#[test]
fn warm_multilanguage_rust_type_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "model.rs", "pub struct Widget;\n");
    let caller = "mod model;\nuse crate::model::Widget;\npub fn render(input: Widget) {\n    let _ = input;\n}\n";
    write_file(root, "lib.rs", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "rs", "pub struct Unrelated;\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(3).unwrap();
    assert_warm_multilanguage_type_query(
        language_python_project(root, Language::Rust),
        brokk_bifrost::searchtools::TypeReferenceQuery {
            path: "lib.rs".to_string(),
            line: Some(4),
            column: Some(line.find("input").unwrap() + 1),
        },
        "Widget",
    );
}

#[test]
fn warm_multilanguage_cpp_include_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "target.h",
        "namespace ns { class Service { public: void run(); }; }\n",
    );
    write_file(
        root,
        "target.cpp",
        "#include \"target.h\"\nvoid ns::Service::run() {}\n",
    );
    let caller = "#include \"target.h\"\nvoid handle(ns::Service service) { service.run(); }\n";
    write_file(root, "app.cpp", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "cpp", "namespace generated { class Unrelated {}; }\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Cpp),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app.cpp".to_string(),
            line: Some(2),
            column: Some(line.find("run").unwrap() + 1),
        },
        "ns.Service.run",
    );
}

#[test]
fn warm_cpp_template_alias_unit_round_trips_with_namespace_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "canonical.h",
        "namespace jni_zero { template <typename T> class ScopedJavaGlobalRef {}; }\n",
    );
    write_file(
        root,
        "aliases.h",
        r#"#include "canonical.h"
namespace base::android {
template <typename T = int>
using ScopedJavaGlobalRef = jni_zero::ScopedJavaGlobalRef<T>;
}
"#,
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = language_python_project(root, Language::Cpp);

    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(
        parsed_file_count(&warm_events.lock().unwrap()),
        0,
        "warm build must hydrate the alias unit from the analyzer store"
    );
    let analyzer = warm.analyzer();
    let aliases = analyzer.get_definitions("base::android.ScopedJavaGlobalRef");
    assert_eq!(aliases.len(), 1, "persisted alias units: {aliases:#?}");
    let alias = &aliases[0];
    assert_eq!(alias.package_name(), "base::android");
    assert_eq!(alias.identifier(), "ScopedJavaGlobalRef");
    assert!(!alias.is_synthetic());
    assert!(
        analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(alias)),
        "hydrated unit must retain persisted type-alias classification"
    );
    assert_eq!(
        analyzer.get_source(alias, false).as_deref(),
        Some("using ScopedJavaGlobalRef = jni_zero::ScopedJavaGlobalRef<T>;")
    );
}

#[test]
fn warm_cpp_partial_specialization_dispatch_matches_cold_analysis() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "choice.h",
        r#"namespace persist {
template <typename T, typename U = T*> class choice {
 public: int pick() const { return 1; }
};
template <typename T> class choice<T, T*> {
 public: long pick() const { return 2; }
};
}
"#,
    );
    let caller =
        "#include \"choice.h\"\nlong call(persist::choice<int> value) { return value.pick(); }\n";
    write_file(root, "app.cpp", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = language_python_project(root, Language::Cpp);
    let line = caller.lines().nth(1).unwrap();
    let query = brokk_bifrost::searchtools::DefinitionReferenceQuery {
        path: "app.cpp".to_string(),
        line: Some(2),
        column: Some(line.find("pick").unwrap() + 1),
    };

    let cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let cold_result = brokk_bifrost::searchtools::get_definitions_by_location(
        cold.analyzer(),
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![query.clone()],
        },
    );
    assert_eq!(cold_result.results[0].status, "resolved");
    assert_eq!(
        cold_result.results[0].definitions[0].fqn.as_deref(),
        Some("persist.choice<T, T*>.pick")
    );
    drop(cold);

    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(
        parsed_file_count(&warm_events.lock().unwrap()),
        0,
        "warm build must hydrate template metadata without reparsing"
    );
    let warm_result = brokk_bifrost::searchtools::get_definitions_by_location(
        warm.analyzer(),
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![query],
        },
    );
    assert_eq!(warm_result.results[0].status, cold_result.results[0].status);
    assert_eq!(
        warm_result.results[0]
            .definitions
            .iter()
            .map(|definition| definition.fqn.as_deref())
            .collect::<Vec<_>>(),
        cold_result.results[0]
            .definitions
            .iter()
            .map(|definition| definition.fqn.as_deref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn warm_cpp_template_alias_specialization_dispatch_matches_cold_analysis() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "choice.h",
        r#"namespace persist {
struct Special {};
struct Shared {};
template <typename T, typename Tag> class choice {};
template <typename T> class choice<T, Shared> {};
template <> class choice<Special, Shared> {};
template <typename T> using selected = choice<T, Shared>;
}
"#,
    );
    let caller =
        "#include \"choice.h\"\nusing persist::Special;\npersist::selected<Special> value;\n";
    write_file(root, "app.cpp", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = language_python_project(root, Language::Cpp);
    let line = caller.lines().nth(2).unwrap();
    let query = brokk_bifrost::searchtools::DefinitionReferenceQuery {
        path: "app.cpp".to_string(),
        line: Some(3),
        column: Some(line.find("selected").unwrap() + 1),
    };

    let cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let cold_result = brokk_bifrost::searchtools::get_definitions_by_location(
        cold.analyzer(),
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![query.clone()],
        },
    );
    assert_eq!(cold_result.results[0].status, "resolved");
    assert_eq!(
        cold_result.results[0].definitions[0].fqn.as_deref(),
        Some("persist.choice<Special, Shared>")
    );
    drop(cold);

    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(
        parsed_file_count(&warm_events.lock().unwrap()),
        0,
        "warm build must hydrate template-alias metadata without reparsing"
    );
    let warm_result = brokk_bifrost::searchtools::get_definitions_by_location(
        warm.analyzer(),
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![query],
        },
    );
    assert_eq!(warm_result.results[0].status, cold_result.results[0].status);
    assert_eq!(
        warm_result.results[0]
            .definitions
            .iter()
            .map(|definition| definition.fqn.as_deref())
            .collect::<Vec<_>>(),
        cold_result.results[0]
            .definitions
            .iter()
            .map(|definition| definition.fqn.as_deref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn warm_multilanguage_java_imported_receiver_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "pkg/Target.java",
        "package pkg; public class Target { public void run() {} }\n",
    );
    let caller = "package app;\nimport pkg.Target;\npublic class UseTarget { public void call(Target target) { target.run(); } }\n";
    write_file(root, "app/UseTarget.java", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "java",
        "package generated; class Unrelated { void ignored() {} }\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(2).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Java),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/UseTarget.java".to_string(),
            line: Some(3),
            column: Some(line.find("run").unwrap() + 1),
        },
        "pkg.Target.run",
    );
}

#[test]
fn warm_java_inherited_member_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "pkg/Types.java",
        "package pkg; class Base { public void run() {} } public class Child extends Base {}\n",
    );
    let caller = "package app;\nimport pkg.Child;\npublic class UseChild { public void call(Child child) { child.run(); } }\n";
    write_file(root, "app/UseChild.java", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "java",
        "package generated; class Unrelated { void ignored() {} }\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(2).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Java),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/UseChild.java".to_string(),
            line: Some(3),
            column: Some(line.find("run").unwrap() + 1),
        },
        "pkg.Base.run",
    );
}

#[test]
fn warm_multilanguage_php_typed_receiver_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "src/Service.php",
        "<?php\nnamespace App;\nclass Service { public function run(): void {} }\n",
    );
    let caller = "<?php\nnamespace App;\nclass Controller {\n    public function handle(Service $service): void {\n        $service->run();\n    }\n}\n";
    write_file(root, "src/Controller.php", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "php",
        "<?php\nnamespace Generated;\nclass Unrelated {}\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(4).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Php),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "src/Controller.php".to_string(),
            line: Some(5),
            column: Some(line.find("run").unwrap() + 1),
        },
        "App.Service.run",
    );
}

#[test]
fn warm_multilanguage_ruby_require_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "app/user.rb", "class User\nend\n");
    let caller = "require_relative \"user\"\n\nclass App\n  def run\n    User\n  end\nend\n";
    write_file(root, "app/main.rb", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "rb", "class Unrelated\nend\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(4).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Ruby),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/main.rb".to_string(),
            line: Some(5),
            column: Some(line.find("User").unwrap() + 1),
        },
        "User",
    );
}

#[test]
fn warm_ruby_inherited_receiver_query_uses_owner_scoped_facts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let caller = "class User\n  def audit\n  end\nend\n\nclass Admin < User\nend\n\nclass App\n  def run\n    Admin.new.audit\n  end\nend\n";
    write_file(root, "app.rb", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "rb", "class Unrelated\n  def ignored\n  end\nend\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(10).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Ruby),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app.rb".to_string(),
            line: Some(11),
            column: Some(line.find("audit").unwrap() + 1),
        },
        "User.audit",
    );
}

#[test]
fn warm_ruby_mixin_receiver_query_uses_persisted_owner_facts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let caller = "module Auditable\n  def audit\n  end\nend\n\nclass Admin\n  include Auditable\nend\n\nclass App\n  def run\n    Admin.new.audit\n  end\nend\n";
    write_file(root, "app.rb", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "rb", "module Unrelated\nend\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(11).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Ruby),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app.rb".to_string(),
            line: Some(12),
            column: Some(line.find("audit").unwrap() + 1),
        },
        "Auditable.audit",
    );
}

#[test]
fn warm_scala_inherited_member_query_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "app/Model.scala",
        "package app\nclass Base { def value: Int = 1 }\nclass Child extends Base\nobject Child { def value: Int = 2 }\n",
    );
    let caller = "package app\nclass Controller { def run(child: Child): Int = child.value }\n";
    write_file(root, "app/Controller.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(
        root,
        "scala",
        "package generated\nclass Unrelated { def ignored: Int = 0 }\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Scala),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/Controller.scala".to_string(),
            line: Some(2),
            column: Some(line.find("value").unwrap() + 1),
        },
        "app.Base.value",
    );
}

#[test]
fn warm_scala_wildcard_imported_supertype_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "lib/Base.scala",
        "package lib\nclass Base { def value: Int = 1 }\n",
    );
    write_file(
        root,
        "app/Child.scala",
        "package app\nimport lib.*\nclass Child extends Base\n",
    );
    let caller = "package app\nclass Controller { def run(child: Child): Int = child.value }\n";
    write_file(root, "app/Controller.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass Unrelated\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Scala),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/Controller.scala".to_string(),
            line: Some(2),
            column: Some(line.find("value").unwrap() + 1),
        },
        "lib.Base.value",
    );
}

#[test]
fn warm_scala_nested_supertype_uses_structured_persisted_path() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "app/Model.scala",
        "package app\nobject Outer { trait Base { def value: Int = 1 } }\nclass Child extends Outer.Base\n",
    );
    let caller = "package app\nclass Controller { def run(child: Child): Int = child.value }\n";
    write_file(root, "app/Controller.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass Unrelated\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Scala),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/Controller.scala".to_string(),
            line: Some(2),
            column: Some(line.find("value").unwrap() + 1),
        },
        "app.Outer$.Base.value",
    );
}

#[test]
fn warm_scala_missing_explicit_import_blocks_same_package_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "app/Child.scala",
        "package app\nclass Child { def local: Int = 1 }\n",
    );
    let caller = "package app\nimport missing.Child\nclass Controller { def run(child: Child): Int = child.local }\n";
    write_file(root, "app/Controller.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass Unrelated\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(2).unwrap();
    assert_warm_multilanguage_no_definition_query(
        language_python_project(root, Language::Scala),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/Controller.scala".to_string(),
            line: Some(3),
            column: Some(line.find("local").unwrap() + 1),
        },
    );
}

#[test]
fn warm_scala_factory_return_receiver_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "example/Service.scala",
        "package example\nclass Repository\nclass Service(repository: Repository) { def execute(name: String): String = name.trim }\nobject Service { def build(repository: Repository): Service = new Service(repository) }\n",
    );
    let caller = "package example\nobject Consumer { def run(repository: Repository): String = { val service = Service.build(repository); service.execute(\" Ada \") } }\n";
    write_file(root, "example/Consumer.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass Unrelated\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(1).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Scala),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "example/Consumer.scala".to_string(),
            line: Some(2),
            column: Some(line.find("execute").unwrap() + 1),
        },
        "example.Service.execute",
    );
}

#[test]
fn warm_scala_extension_receiver_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "app/Syntax.scala",
        "package app\nobject Syntax:\n  extension (value: String)\n    def slug: String = value.toLowerCase\n",
    );
    let caller =
        "package app\nobject App:\n  import app.Syntax.*\n  val slugged = \"Hello World\".slug\n";
    write_file(root, "app/App.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass Unrelated\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let line = caller.lines().nth(3).unwrap();
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::Scala),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app/App.scala".to_string(),
            line: Some(4),
            column: Some(line.find(".slug").unwrap() + 2),
        },
        "app.Syntax$.slug",
    );
}

#[test]
fn scala_dirty_owner_overlay_supplies_live_ancestor_facts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "lib/Base.scala",
        "package lib\nclass Base { def oldValue: Int = 1 }\n",
    );
    write_file(
        root,
        "app/Child.scala",
        "package app\nimport lib.Base\nclass Child extends Base\n",
    );
    let caller =
        "package app\nclass Controller { def run(child: Child): Int = child.replacement }\n";
    write_file(root, "app/Controller.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass Unrelated\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "initial owner");
    let project = language_python_project(root, Language::Scala);
    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());

    write_file(
        root,
        "lib/Base.scala",
        "package lib\nclass Base { def replacement: Int = 2 }\n",
    );
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(parsed_file_count(&events.lock().unwrap()), 1);
    let analyzer = warm.analyzer();
    analyzer
        .test_hooks()
        .reset_global_usage_definition_index_build_count_for_test();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_candidate_hydration_count_for_test();
    analyzer
        .test_hooks()
        .reset_workspace_path_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_scala_project_types_build_count_for_test();
    let line = caller.lines().nth(1).unwrap();
    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "app/Controller.scala".to_string(),
                line: Some(2),
                column: Some(line.find("replacement").unwrap() + 1),
            }],
        },
    );
    assert_eq!(result.results[0].status, "resolved");
    assert_eq!(
        result.results[0].definitions[0].fqn.as_deref(),
        Some("lib.Base.replacement")
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    assert!(analyzer.test_hooks().candidate_hydration_count_for_test() < 32);
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );
}

#[test]
fn scala_stale_owner_blob_is_excluded_from_ancestor_facts() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "lib/Base.scala",
        "package lib\nclass Base { def oldValue: Int = 1 }\n",
    );
    write_file(
        root,
        "app/Child.scala",
        "package app\nimport lib.Base\nclass Child extends Base\n",
    );
    let caller = "package app\nclass Controller { def run(child: Child): Int = child.replacement + child.oldValue }\n";
    write_file(root, "app/Controller.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass Unrelated\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "initial owner");
    let project = language_python_project(root, Language::Scala);
    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());

    write_file(
        root,
        "lib/Base.scala",
        "package lib\nclass Base { def replacement: Int = 2 }\n",
    );
    commit_all(&repo, "replace owner blob");
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(parsed_file_count(&events.lock().unwrap()), 1);
    let analyzer = warm.analyzer();
    analyzer
        .test_hooks()
        .reset_global_usage_definition_index_build_count_for_test();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_workspace_path_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_scala_project_types_build_count_for_test();
    let line = caller.lines().nth(1).unwrap();
    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![
                brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "app/Controller.scala".to_string(),
                    line: Some(2),
                    column: Some(line.find("replacement").unwrap() + 1),
                },
                brokk_bifrost::searchtools::DefinitionReferenceQuery {
                    path: "app/Controller.scala".to_string(),
                    line: Some(2),
                    column: Some(line.find("oldValue").unwrap() + 1),
                },
            ],
        },
    );
    assert_eq!(result.results[0].status, "resolved");
    assert_eq!(
        result.results[0].definitions[0].fqn.as_deref(),
        Some("lib.Base.replacement")
    );
    assert_eq!(result.results[1].status, "no_definition");
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );
}

#[test]
fn warm_scala_class_and_singleton_type_batch_is_candidate_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "app/Settings.scala",
        "package app\nclass Settings { def value: Int = 0 }\nobject Settings { def value: Int = 1 }\n",
    );
    let caller = "package app\nclass Controller { def run(plain: Settings, singleton: Settings.type): Int = plain.value + singleton.value }\n";
    write_file(root, "app/Controller.scala", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "scala", "package generated\nclass UnrelatedType\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = language_python_project(root, Language::Scala);
    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    let analyzer = warm.analyzer();
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
    analyzer
        .test_hooks()
        .reset_global_usage_definition_index_build_count_for_test();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_candidate_hydration_count_for_test();
    analyzer
        .test_hooks()
        .reset_workspace_path_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_scala_project_types_build_count_for_test();

    let line = caller.lines().nth(1).unwrap();
    let result = brokk_bifrost::searchtools::get_type_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetTypeParams {
            references: vec![
                brokk_bifrost::searchtools::TypeReferenceQuery {
                    path: "app/Controller.scala".to_string(),
                    line: Some(2),
                    column: Some(line.find("plain.value").unwrap() + 1),
                },
                brokk_bifrost::searchtools::TypeReferenceQuery {
                    path: "app/Controller.scala".to_string(),
                    line: Some(2),
                    column: Some(line.find("singleton.value").unwrap() + 1),
                },
            ],
        },
    );

    assert_eq!(result.results[0].status, "resolved");
    assert_eq!(result.results[0].types[0].fqn, "app.Settings");
    assert_eq!(result.results[1].status, "resolved");
    assert_eq!(result.results[1].types[0].fqn, "app.Settings$");
    assert_eq!(
        analyzer
            .test_hooks()
            .global_usage_definition_index_build_count_for_test(),
        0
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0
    );
    assert!(
        analyzer.test_hooks().candidate_hydration_count_for_test() < 32,
        "type lookup hydrated the unrelated generated-file set"
    );
    assert_eq!(
        analyzer.test_hooks().workspace_path_scan_count_for_test(),
        0
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .scala_project_types_build_count_for_test(),
        0
    );
}

#[test]
fn warm_typescript_path_module_query_does_not_scan_live_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "util.ts", "export function helper() {}\n");
    let caller = "import { helper } from \"./util\";\nhelper();\n";
    write_file(root, "app.ts", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "ts", "export const ignored = 1;\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::TypeScript),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app.ts".to_string(),
            line: Some(2),
            column: Some(1),
        },
        "helper",
    );
}

#[test]
fn warm_javascript_path_module_query_does_not_scan_live_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "components.js",
        "export class Greeter { greet() {} }\nexport function createGreeter() { return new Greeter(); }\n",
    );
    let caller = "import { createGreeter } from \"./components.js\";\nconst greeter = createGreeter();\ngreeter.greet();\n";
    write_file(root, "app.js", caller);
    write_file(root, "other.py", "def unrelated():\n    return 1\n");
    write_unrelated_generated_files(root, "js", "export const ignored = 1;\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    assert_warm_multilanguage_definition_query(
        language_python_project(root, Language::JavaScript),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app.js".to_string(),
            line: Some(3),
            column: Some("greeter.".len() + 1),
        },
        "Greeter.greet",
    );
}

#[test]
fn warm_python_path_module_query_does_not_scan_live_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "pkg/util.py", "def helper():\n    pass\n");
    let caller = "import pkg.util as util\n\ndef run():\n    util.helper()\n";
    write_file(root, "app.py", caller);
    write_unrelated_generated_files(root, "py", "def ignored():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    assert_warm_multilanguage_definition_query(
        python_project(root),
        brokk_bifrost::searchtools::DefinitionReferenceQuery {
            path: "app.py".to_string(),
            line: Some(4),
            column: Some("    util.".len() + 1),
        },
        "pkg.util.helper",
    );
}

#[test]
fn csharp_package_existence_ignores_stale_complete_blobs() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, ".gitignore", ".bifrost/cache/\n");
    write_file(
        root,
        "Types.cs",
        "namespace Removed { public class OldType {} }\n",
    );
    let caller =
        "using Removed;\nnamespace App { public class Controller { private Missing value; } }\n";
    write_file(root, "Controller.cs", caller);
    let repo = init_git_repo(root);
    commit_all(&repo, "initial namespace");
    let project = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::CSharp,
    ));

    let _cold = build_persisted(project.clone(), AnalyzerConfig::default());
    write_file(
        root,
        "Types.cs",
        "namespace Replacement { public class NewType {} }\n",
    );
    commit_all(&repo, "replace namespace");
    let warm = build_persisted(project, AnalyzerConfig::default());

    let type_line = caller.lines().nth(1).unwrap();
    let result = brokk_bifrost::searchtools::get_definitions_by_location(
        warm.analyzer(),
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "Controller.cs".to_string(),
                line: Some(2),
                column: Some(type_line.find("Missing").unwrap() + 1),
            }],
        },
    );

    assert_eq!(
        result.results[0].status, "unresolvable_import_boundary",
        "the stale Removed namespace blob must not count as live"
    );
}

#[test]
fn git_blob_store_warm_build_hydrates_without_reparse() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "alpha.py", "class Alpha:\n    pass\n");
    write_file(root, "beta.py", "def beta():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);

    let cold_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cold = build_persisted_with_progress(Arc::clone(&project), AnalyzerConfig::default(), {
        let events = Arc::clone(&cold_events);
        move |event| events.lock().unwrap().push(event)
    });
    let cold_names = declaration_names(cold.analyzer());
    assert!(cold_names.contains("alpha.Alpha"));
    assert!(cold_names.contains("beta.beta"));
    assert_eq!(parsed_file_count(&cold_events.lock().unwrap()), 2);

    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(cold_names, declaration_names(warm.analyzer()));
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
}

#[test]
fn dirty_file_reconcile_parses_only_changed_blob() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "alpha.py", "class Alpha:\n    pass\n");
    write_file(root, "beta.py", "def beta():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);

    let _ = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    write_file(root, "alpha.py", "class Renamed:\n    pass\n");

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rebuilt = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    });
    let names = declaration_names(rebuilt.analyzer());
    assert!(names.contains("alpha.Renamed"));
    assert!(!names.contains("alpha.Alpha"));
    assert!(names.contains("beta.beta"));
    assert_eq!(parsed_file_count(&events.lock().unwrap()), 1);
}

#[test]
fn corrupt_persisted_blob_is_reparsed_and_repaired() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "alpha.py", "class Alpha:\n    pass\n");
    write_file(root, "beta.py", "def beta():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let alpha_oid = repo
        .head()
        .unwrap()
        .peel_to_commit()
        .unwrap()
        .tree()
        .unwrap()
        .get_path(Path::new("alpha.py"))
        .unwrap()
        .id()
        .to_string();
    let project = python_project(root);

    let cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    drop(cold);

    let cache = Connection::open(analyzer_db_path(root)).unwrap();
    cache
        .execute(
            "DELETE FROM code_units WHERE blob_oid = ?1 AND lang = 'python'",
            [alpha_oid],
        )
        .unwrap();
    drop(cache);

    let repair_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let repaired =
        build_persisted_with_progress(Arc::clone(&project), AnalyzerConfig::default(), {
            let events = Arc::clone(&repair_events);
            move |event| events.lock().unwrap().push(event)
        });
    let names = declaration_names(repaired.analyzer());
    assert!(names.contains("alpha.Alpha"));
    assert!(names.contains("beta.beta"));
    assert_eq!(
        parsed_file_count(&repair_events.lock().unwrap()),
        1,
        "only the quarantined blob should be reparsed"
    );
    drop(repaired);

    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert!(declaration_names(warm.analyzer()).contains("alpha.Alpha"));
    assert_eq!(
        parsed_file_count(&warm_events.lock().unwrap()),
        0,
        "the repaired blob should hydrate normally on the following build"
    );
}

#[test]
fn deleted_file_is_removed_from_live_results() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "alpha.py", "class Alpha:\n    pass\n");
    write_file(root, "beta.py", "def beta():\n    return 1\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);

    let _ = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    fs::remove_file(root.join("beta.py")).unwrap();

    let rebuilt = build_persisted(project, AnalyzerConfig::default());
    let names = declaration_names(rebuilt.analyzer());
    assert!(names.contains("alpha.Alpha"));
    assert!(!names.contains("beta.beta"));
}

#[test]
fn plain_build_reparses_while_persisted_build_hydrates_parse_errors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(root, "broken.py", "def x():\n    return 1)\n");
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    let project = python_project(root);
    let file = ProjectFile::new(root.canonicalize().unwrap(), "broken.py");

    let plain_first = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        !plain_first
            .analyzer()
            .parse_errors(&file)
            .expect("plain build should freshly parse errors")
            .is_empty()
    );

    let plain_second = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        !plain_second
            .analyzer()
            .parse_errors(&file)
            .expect("second plain build should freshly parse errors")
            .is_empty()
    );

    let cold_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let persisted_first =
        build_persisted_with_progress(Arc::clone(&project), AnalyzerConfig::default(), {
            let events = Arc::clone(&cold_events);
            move |event| events.lock().unwrap().push(event)
        });
    assert!(
        !persisted_first
            .analyzer()
            .parse_errors(&file)
            .expect("cold persisted build should freshly parse errors")
            .is_empty()
    );
    assert_eq!(parsed_file_count(&cold_events.lock().unwrap()), 1);

    let warm_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let persisted_second = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert!(
        persisted_second.analyzer().parse_errors(&file).is_none(),
        "warm persisted build must hydrate and leave parse_errors unknown"
    );
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);
}

#[test]
fn update_repopulates_parse_errors_for_delta_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write_file(&root, "evolving.py", "def x():\n    return 1)\n");
    let project = python_project(&root);
    let file = ProjectFile::new(root, "evolving.py");

    let analyzer = PythonAnalyzer::new(Arc::clone(&project));
    assert!(!analyzer.parse_errors(&file).unwrap().is_empty());

    file.write("def x():\n    return 1\n").unwrap();
    let mut changed = BTreeSet::new();
    changed.insert(file.clone());
    let updated = analyzer.update(&changed);
    assert_eq!(updated.parse_errors(&file), Some(Vec::new()));
}

/// Issue #1102: per-declaration test-region taint must survive a store
/// round-trip. A cold build computes taint live and persists it; a warm build
/// reopens the store and must hydrate identical taint (`code_units.in_test_region`
/// -> `FileState::test_region_units`). Both surfaces must agree that the
/// production function is untainted and the inline `#[cfg(test)]` symbols are
/// tainted.
#[test]
fn persisted_rust_test_region_taint_survives_store_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "widget.rs",
        r#"pub fn make_widget() -> u32 {
    7
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
"#,
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let taint_by_short_name = |analyzer: &dyn IAnalyzer| {
        analyzer
            .all_declarations()
            .filter(|unit| !unit.is_synthetic())
            .map(|unit| {
                (
                    unit.short_name().to_string(),
                    analyzer.in_test_region(&unit),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };

    // Cold build: taint computed from live extraction, then persisted.
    let cold = build_persisted(
        language_python_project(root, Language::Rust),
        AnalyzerConfig::default(),
    );
    let cold_taint = taint_by_short_name(cold.analyzer());
    drop(cold);

    // Warm build: reopen the store; taint is hydrated from the persisted column.
    let warm = build_persisted(
        language_python_project(root, Language::Rust),
        AnalyzerConfig::default(),
    );
    let warm_taint = taint_by_short_name(warm.analyzer());

    assert_eq!(
        cold_taint, warm_taint,
        "live-extraction and warm-store taint must agree"
    );
    assert_eq!(
        warm_taint.get("make_widget"),
        Some(&false),
        "production fn untainted: {warm_taint:?}"
    );
    assert_eq!(
        warm_taint.get("tests"),
        Some(&true),
        "cfg(test) module tainted: {warm_taint:?}"
    );
    assert_eq!(
        warm_taint.get("tests.it_works"),
        Some(&true),
        "inline test fn tainted: {warm_taint:?}"
    );
}

/// Issue #1195: `LanguageAdapter::storage_language_key_for_file`'s default
/// impl used to ignore its `file` argument and always answer with the
/// *adapter's own* language key, so the cross-adapter guard in
/// `paths_for_row`/`resolve_candidate_rows_limited` (which exists precisely
/// to keep one language's persisted rows from being served for another
/// language's files that share a git blob oid) never actually discriminated.
///
/// This fixture byte-for-byte mirrors the real exposure found in this very
/// repo (`git ls-tree` shows `src/analyzer/python/cache.rs` and
/// `src/analyzer/ruby/cache.rs` share a blob oid): a Python file and a Ruby
/// file with identical content, so git dedups them to one blob. The `.rb`
/// twin is not valid Ruby -- that's irrelevant; the only thing under test is
/// whether Python's own persisted row for the shared blob also hydrates as
/// the Ruby-named path when Python resolves candidates for that blob oid.
/// Before the fix it did (the guard always matched), attaching Python's
/// package/short_name conventions to a file Python's adapter never analyzed.
#[test]
fn cross_language_blob_sharing_does_not_leak_rows_across_adapters() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let shared_body = "class Widget:\n    def value(self):\n        return 1\n";
    write_file(root, "pkg/widget.py", shared_body);
    write_file(root, "pkg/widget.rb", shared_body);
    let repo = init_git_repo(root);
    commit_all(&repo, "shared blob across python and ruby");

    // Confirm the fixture actually reproduces the exposure: both paths must
    // resolve to the same git blob, or this test proves nothing.
    let python_oid =
        git2::Oid::hash_file(git2::ObjectType::Blob, root.join("pkg").join("widget.py")).unwrap();
    let ruby_oid =
        git2::Oid::hash_file(git2::ObjectType::Blob, root.join("pkg").join("widget.rb")).unwrap();
    assert_eq!(
        python_oid, ruby_oid,
        "fixture must share a git blob oid across languages to exercise the guard"
    );

    let analyzer = build_persisted(
        language_python_project(root, Language::Ruby),
        AnalyzerConfig::default(),
    );
    let workspace = analyzer.analyzer();

    let hits: Vec<_> = workspace.definitions("pkg.widget.Widget.value").collect();
    let hit_paths: Vec<_> = hits
        .iter()
        .map(|unit| unit.source().rel_path().to_path_buf())
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "python's persisted row for the shared blob must not ALSO hydrate as \
         the byte-identical ruby file: got paths {hit_paths:?}"
    );
    assert_eq!(hit_paths[0], Path::new("pkg/widget.py"));
}

/// Positive control for the #1195 fix: identical content shared across two
/// paths WITHIN the same language is an intentional, pre-existing dedup path
/// (git dedups identical blobs; `code_units.fq_segments` persists only the
/// content-stable tail and composes it with each live path's structured package
/// prefix on load -- see `encode_unit_fq_segments`). The
/// #1195 fix must not disturb this: both live paths sharing the one
/// persisted row must still resolve, each under its own path-derived fqn.
#[test]
fn same_language_blob_sharing_still_serves_both_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let shared_body = "class Widget:\n    def value(self):\n        return 1\n";
    write_file(root, "pkg_a/widget.py", shared_body);
    write_file(root, "pkg_b/widget.py", shared_body);
    let repo = init_git_repo(root);
    commit_all(&repo, "shared blob within python");

    let analyzer = build_persisted(python_project(root), AnalyzerConfig::default());
    let workspace = analyzer.analyzer();

    let a_hits: Vec<_> = workspace.definitions("pkg_a.widget.Widget.value").collect();
    let b_hits: Vec<_> = workspace.definitions("pkg_b.widget.Widget.value").collect();

    assert_eq!(
        a_hits.len(),
        1,
        "pkg_a's path-qualified fqn must resolve from the shared blob's row"
    );
    assert_eq!(a_hits[0].source().rel_path(), Path::new("pkg_a/widget.py"));

    assert_eq!(
        b_hits.len(),
        1,
        "pkg_b's path-qualified fqn must resolve from the shared blob's row"
    );
    assert_eq!(b_hits[0].source().rel_path(), Path::new("pkg_b/widget.py"));
}

/// A language analyzer handed a file OUTSIDE its own language set must answer
/// with no state — never parse the foreign file as its own language.
/// Multi-analyzer fan-outs (`ImportAnalysisProvider::referencing_files_of`)
/// legitimately ask every provider about arbitrary files; before the #1189
/// fix the file-state funnel would tree-sitter-parse the foreign source with
/// the adapter's own grammar (a rust probe parsed a C++ header, error-recovery
/// produced a class-like, and the FqName round-trip assert killed the MCP
/// process), and after #1195's per-file storage keys it would instead index a
/// foreign key absent from the adapter's generation map and panic. The funnel
/// now refuses: no panic, no declarations, for both never-seen and
/// post-build-warm states.
#[test]
fn foreign_language_file_yields_no_state_instead_of_a_foreign_parse() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        "pkg/widget.py",
        "class Widget:\n    def value(self):\n        return 1\n",
    );
    // The real #1189 shape: a C++ header whose `enum class` error-recovers
    // into a declaration under a foreign grammar.
    write_file(
        root,
        "native/advanced_features.h",
        "enum class BlendMode {\n    Normal,\n    Multiply,\n};\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "python beside a cpp header");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ));
    let analyzer = PythonAnalyzer::new(Arc::clone(&project));
    let header = ProjectFile::new(root.canonicalize().unwrap(), "native/advanced_features.h");

    assert!(
        analyzer.declarations(&header).is_empty(),
        "a python analyzer must not produce declarations for a C++ header"
    );
    // Same answer once the workspace is fully built (warm caches, populated
    // generation map) — the state the #1189 crash needed.
    let workspace = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        workspace.analyzer().declarations(&header).is_empty(),
        "a warm workspace must not serve foreign-language declarations either"
    );
}

#[test]
fn hidden_python_path_module_fq_reopens_warm_without_reparse() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write_file(
        root,
        ".github/download-models-weights.py",
        "def fetch():\n    return 1\n",
    );
    let repo = init_git_repo(root);
    commit_all(&repo, "hidden python path module");
    let project = python_project(root);

    let _cold = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    let warm_events = Arc::new(Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(parsed_file_count(&warm_events.lock().unwrap()), 0);

    let analyzer = warm.analyzer();
    let module_hits: Vec<_> = analyzer
        .definitions(".github.download-models-weights")
        .collect();
    assert!(
        module_hits.iter().any(|unit| unit.is_module()),
        "warm reopen must synthesize the hidden-path module unit: {module_hits:#?}"
    );

    let function_hits: Vec<_> = analyzer
        .definitions(".github.download-models-weights.fetch")
        .collect();
    assert_eq!(
        function_hits.len(),
        1,
        "warm reopen must preserve the hidden-path function fq: {function_hits:#?}"
    );
    assert_eq!(
        function_hits[0].source().rel_path(),
        Path::new(".github/download-models-weights.py")
    );
}

mod common;
use common::InlineTestProject;

fn parsed_language_file_count(events: &[BuildProgressEvent], language: Language) -> usize {
    events
        .iter()
        .filter(|event| event.phase == BuildProgressPhase::Parse)
        .filter(|event| event.language == language)
        .filter(|event| event.file.is_some())
        .count()
}

const KOTLIN_SERVICE_KT: &str = "package app\n\nclass Service(val id: Int) {\n    fun serve(): Int = id\n\n    companion object {\n        fun default(): Service = Service(0)\n    }\n}\n";
const KOTLIN_UTIL_KT: &str =
    "package app\n\nfun helper(count: Int = 1): Int = count\n\ntypealias Ids = List<Int>\n";

#[test]
fn kotlin_persisted_build_hydrates_without_reparse_and_restores_declarations() {
    let built = InlineTestProject::with_language(Language::Kotlin)
        .file("src/Service.kt", KOTLIN_SERVICE_KT)
        .file("src/Util.kt", KOTLIN_UTIL_KT)
        .build();
    let repo = init_git_repo(built.root());
    commit_all(&repo, "init");
    let project = built.project_dyn();

    let cold_events = Arc::new(Mutex::new(Vec::new()));
    let cold = build_persisted_with_progress(Arc::clone(&project), AnalyzerConfig::default(), {
        let events = Arc::clone(&cold_events);
        move |event| events.lock().unwrap().push(event)
    });
    let cold_names = declaration_names(cold.analyzer());
    for expected in [
        "app.Service",
        "app.Service.Service",
        "app.Service.id",
        "app.Service.serve",
        "app.Service.Companion",
        "app.Service.Companion.default",
        "app.helper",
        "app.Ids",
    ] {
        assert!(cold_names.contains(expected), "missing {expected}");
    }
    assert_eq!(
        parsed_language_file_count(&cold_events.lock().unwrap(), Language::Kotlin),
        2
    );
    let cold_service = cold.analyzer().get_definitions("app.Service");
    let cold_signature = cold.analyzer().signatures(&cold_service[0]);
    drop(cold);

    let warm_events = Arc::new(Mutex::new(Vec::new()));
    let warm = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&warm_events);
        move |event| events.lock().unwrap().push(event)
    });
    assert_eq!(cold_names, declaration_names(warm.analyzer()));
    assert_eq!(
        parsed_language_file_count(&warm_events.lock().unwrap(), Language::Kotlin),
        0,
        "warm rebuild must hydrate Kotlin state without reparsing"
    );
    let warm_service = warm.analyzer().get_definitions("app.Service");
    assert_eq!(
        warm.analyzer().signatures(&warm_service[0]),
        cold_signature,
        "signatures must survive the store round-trip"
    );
}

#[test]
fn kotlin_dirty_file_reconcile_parses_only_changed_blob() {
    let built = InlineTestProject::with_language(Language::Kotlin)
        .file("src/Service.kt", KOTLIN_SERVICE_KT)
        .file("src/Util.kt", KOTLIN_UTIL_KT)
        .build();
    let repo = init_git_repo(built.root());
    commit_all(&repo, "init");
    let project = built.project_dyn();

    let _ = build_persisted(Arc::clone(&project), AnalyzerConfig::default());
    write_file(
        built.root(),
        "src/Util.kt",
        "package app\n\nfun renamedHelper(count: Int = 1): Int = count\n",
    );

    let events = Arc::new(Mutex::new(Vec::new()));
    let rebuilt = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    });
    let names = declaration_names(rebuilt.analyzer());
    assert!(names.contains("app.renamedHelper"));
    assert!(!names.contains("app.helper"));
    assert!(names.contains("app.Service.serve"));
    assert_eq!(
        parsed_language_file_count(&events.lock().unwrap(), Language::Kotlin),
        1,
        "only the edited Kotlin file may reparse"
    );
}

#[test]
fn kotlin_epoch_bump_invalidates_kotlin_rows_but_not_java_rows() {
    // Mixed-language epoch scoping: a Kotlin analysis-epoch change must force
    // Kotlin re-analysis while the Java analyzer keeps hydrating warm.
    let built = InlineTestProject::new()
        .file("src/Service.kt", KOTLIN_SERVICE_KT)
        .file(
            "src/Client.java",
            "package app;\n\nclass Client {\n    int use() { return 1; }\n}\n",
        )
        .build();
    assert_eq!(
        built.languages(),
        BTreeSet::from([Language::Java, Language::Kotlin])
    );
    let repo = init_git_repo(built.root());
    commit_all(&repo, "init");
    let project = built.project_dyn();

    let _ = build_persisted(Arc::clone(&project), AnalyzerConfig::default());

    let store = brokk_bifrost::analyzer::store::AnalyzerStore::open_persistent(&analyzer_db_path(
        built.root(),
    ))
    .expect("open persisted analyzer store");
    store
        .ensure_language_epoch_value("kotlin", "kotlin-epoch-invalidation-test")
        .expect("bump kotlin epoch");
    drop(store);

    let events = Arc::new(Mutex::new(Vec::new()));
    let rebuilt = build_persisted_with_progress(project, AnalyzerConfig::default(), {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    });
    let names = declaration_names(rebuilt.analyzer());
    assert!(names.contains("app.Service.serve"));
    assert!(names.contains("app.Client"));
    let events = events.lock().unwrap();
    assert_eq!(
        parsed_language_file_count(&events, Language::Kotlin),
        1,
        "a stale Kotlin epoch must force Kotlin re-analysis"
    );
    assert_eq!(
        parsed_language_file_count(&events, Language::Java),
        0,
        "the Java epoch is untouched, so Java must hydrate warm"
    );
}
