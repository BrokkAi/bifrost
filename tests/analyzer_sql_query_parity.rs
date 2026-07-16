mod common;

use brokk_bifrost::analyzer::BuildProgressPhase;
use brokk_bifrost::{
    AnalyzerConfig, CodeUnit, IAnalyzer, JavaAnalyzer, JavascriptAnalyzer, Language, Project,
    ProjectFile, PythonAnalyzer, TestProject, TypescriptAnalyzer, WorkspaceAnalyzer,
};
use common::InlineTestProject;
use git2::{IndexAddOption, Repository, Signature};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn unit_keys(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<(String, String, String)> {
    units
        .into_iter()
        .map(|unit| {
            let rel_path = unit
                .source()
                .rel_path()
                .to_string_lossy()
                .replace('\\', "/");
            (rel_path, unit.fq_name(), format!("{:?}", unit.kind()))
        })
        .collect()
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
    index.add_all(["*"], IndexAddOption::DEFAULT, None).unwrap();
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

#[test]
fn java_sql_workspace_queries_return_expected_units() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Service.java",
            r#"
package pkg;
class Service {
  int count;
  void greet() {}
}
"#,
        )
        .file(
            "Other.java",
            r#"
package pkg;
class Other {
  void call() {}
}
"#,
        )
        .build();
    let analyzer = JavaAnalyzer::new(project.project_dyn());

    assert_eq!(
        unit_keys(analyzer.get_definitions("pkg.Service")),
        BTreeSet::from([(
            "Service.java".to_string(),
            "pkg.Service".to_string(),
            "Class".to_string()
        )])
    );
    assert_eq!(
        unit_keys(analyzer.search_definitions("greet", true)),
        BTreeSet::from([(
            "Service.java".to_string(),
            "pkg.Service.greet".to_string(),
            "Function".to_string()
        )])
    );
    assert_eq!(
        unit_keys(analyzer.autocomplete_definitions("greet")),
        BTreeSet::from([(
            "Service.java".to_string(),
            "pkg.Service.greet".to_string(),
            "Function".to_string()
        )])
    );
    let declarations = unit_keys(analyzer.get_all_declarations());
    for expected in [
        ("Service.java", "pkg.Service", "Class"),
        ("Service.java", "pkg.Service.count", "Field"),
        ("Service.java", "pkg.Service.greet", "Function"),
        ("Other.java", "pkg.Other", "Class"),
        ("Other.java", "pkg.Other.call", "Function"),
    ] {
        assert!(
            declarations.contains(&(
                expected.0.to_string(),
                expected.1.to_string(),
                expected.2.to_string()
            )),
            "missing {expected:?} from {declarations:?}"
        );
    }
}

#[test]
fn python_same_blob_at_two_paths_expands_to_distinct_live_units() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("left")).unwrap();
    std::fs::create_dir_all(root.join("right")).unwrap();
    let source = "class Shared:\n    pass\n";
    std::fs::write(root.join("left/shared.py"), source).unwrap();
    std::fs::write(root.join("right/shared.py"), source).unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ));
    let analyzer = PythonAnalyzer::new(project);
    let hits = unit_keys(analyzer.search_definitions("Shared", true));

    assert!(
        hits.iter()
            .any(|(path, fqn, _)| path == "left/shared.py" && fqn == "left.shared.Shared")
    );
    assert!(
        hits.iter()
            .any(|(path, fqn, _)| path == "right/shared.py" && fqn == "right.shared.Shared")
    );
}

#[test]
fn same_blob_ts_and_tsx_are_separate_store_entries() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let source = "export const value = 1;\n";
    std::fs::write(root.join("plain.ts"), source).unwrap();
    std::fs::write(root.join("component.tsx"), source).unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::TypeScript,
    ));
    let parsed = Arc::new(AtomicUsize::new(0));
    let parsed_events = Arc::clone(&parsed);
    let analyzer = WorkspaceAnalyzer::build_persisted_with_progress(
        project,
        AnalyzerConfig::default(),
        move |event| {
            if event.language == Language::TypeScript
                && event.phase == BuildProgressPhase::Parse
                && event.file.is_some()
            {
                parsed_events.fetch_add(1, Ordering::Relaxed);
            }
        },
    )
    .expect("persisted analyzer should build");

    assert_eq!(
        parsed.load(Ordering::Relaxed),
        2,
        "same blob content must be parsed separately for TS and TSX grammars"
    );

    let hits = unit_keys(analyzer.analyzer().search_definitions("value", true));
    assert!(hits.iter().any(|(path, _, _)| path == "plain.ts"));
    assert!(hits.iter().any(|(path, _, _)| path == "component.tsx"));
}

#[test]
fn python_untracked_overlay_is_live_for_sql_workspace_queries() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("tracked.py"), "class Tracked:\n    pass\n").unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");
    std::fs::write(root.join("untracked.py"), "class Fresh:\n    pass\n").unwrap();

    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ));
    let analyzer = PythonAnalyzer::new(project);
    let hits = unit_keys(analyzer.search_definitions("Fresh", true));

    assert!(
        hits.iter()
            .any(|(path, fqn, _)| path == "untracked.py" && fqn == "untracked.Fresh")
    );
}

#[test]
fn python_store_only_symbol_is_found_from_live_store() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("tracked.py"), "class Tracked:\n    pass\n").unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ));
    let analyzer = PythonAnalyzer::new(project);
    std::fs::write(root.join("store_only.py"), "class StoreOnly:\n    pass\n").unwrap();
    let file = ProjectFile::new(root.canonicalize().unwrap(), "store_only.py");
    analyzer
        .write_live_file_to_store_for_test(&file)
        .expect("store-only blob write");
    let definitions = unit_keys(analyzer.get_definitions("store_only.StoreOnly"));
    assert!(definitions.iter().any(|(path, fqn, kind)| {
        path == "store_only.py" && fqn == "store_only.StoreOnly" && kind == "Class"
    }));
    let search = unit_keys(analyzer.search_definitions("StoreOnly", true));
    assert!(
        search
            .iter()
            .any(|(path, fqn, _)| { path == "store_only.py" && fqn == "store_only.StoreOnly" })
    );
}

#[test]
fn non_git_live_map_makes_store_only_file_visible_to_workspace_queries() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("tracked.py", "class Tracked:\n    pass\n")
        .build();
    let analyzer = PythonAnalyzer::new(project.project_dyn());
    let file = ProjectFile::new(project.root().to_path_buf(), "fresh.py");
    file.write("class Fresh:\n    pass\n").unwrap();
    analyzer
        .write_live_file_to_store_for_test(&file)
        .expect("non-git store-only blob write");

    let hits = unit_keys(analyzer.search_definitions("Fresh", true));
    assert!(
        hits.iter()
            .any(|(path, fqn, _)| path == "fresh.py" && fqn == "fresh.Fresh")
    );
}

#[test]
fn global_usage_definition_index_includes_store_only_live_units() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("tracked.py", "class Tracked:\n    pass\n")
        .build();
    let analyzer = PythonAnalyzer::new(project.project_dyn());
    let file = ProjectFile::new(project.root().to_path_buf(), "store_only.py");
    file.write("class StoreOnly:\n    pass\n").unwrap();
    analyzer
        .write_live_file_to_store_for_test(&file)
        .expect("store-only blob write");
    let support = analyzer.global_usage_definition_index();
    assert!(
        support
            .fqn_for_test("store_only.StoreOnly")
            .iter()
            .any(|unit| unit.source() == &file && unit.identifier() == "StoreOnly"),
        "definition lookup index must be derived from store/live rows"
    );
    assert!(
        support
            .file_identifier_for_test(&file, "StoreOnly")
            .iter()
            .any(|unit| unit.fq_name() == "store_only.StoreOnly")
    );
}

#[test]
fn synthetic_module_units_are_sourced_from_live_store_hydration() {
    let py = InlineTestProject::with_language(Language::Python)
        .file("pkg/mod.py", "import os\nclass Thing:\n    pass\n")
        .build();
    let py_analyzer = PythonAnalyzer::new(py.project_dyn());
    assert!(
        unit_keys(py_analyzer.search_definitions("pkg.mod", true))
            .iter()
            .any(|(path, fqn, kind)| path == "pkg/mod.py" && fqn == "pkg.mod" && kind == "Module")
    );

    let js = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "module.js",
            "import value from './dep.js';\nexport const answer = value;\n",
        )
        .file("dep.js", "export default 42;\n")
        .build();
    let js_analyzer = JavascriptAnalyzer::new(js.project_dyn());
    assert!(
        unit_keys(js_analyzer.search_definitions("module.js", true))
            .iter()
            .any(|(path, fqn, kind)| path == "module.js" && fqn == "module.js" && kind == "Module")
    );

    let ts = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "module.ts",
            "import value from './dep';\nexport const answer = value;\n",
        )
        .file("dep.ts", "export default 42;\n")
        .build();
    let ts_analyzer = TypescriptAnalyzer::new(ts.project_dyn());
    assert!(
        unit_keys(ts_analyzer.search_definitions("module.ts", true))
            .iter()
            .any(|(path, fqn, kind)| path == "module.ts" && fqn == "module.ts" && kind == "Module")
    );
}

#[test]
fn synthetic_module_definition_and_search_do_not_hydrate_workspace() {
    let mut builder = InlineTestProject::with_language(Language::TypeScript).file(
        "entry.ts",
        "import { value } from './dep0';\nexport const answer = value;\n",
    );
    for index in 0..19 {
        builder = builder.file(
            format!("dep{index}.ts"),
            format!("export const value{index} = {index};\n"),
        );
    }
    let project = builder.build();
    let analyzer = TypescriptAnalyzer::new(project.project_dyn());

    analyzer.reset_full_hydration_count_for_test();
    let search_hits = unit_keys(analyzer.search_definitions("entry.ts", true));
    assert!(
        search_hits.iter().any(|(path, fqn, kind)| {
            path == "entry.ts" && fqn == "entry.ts" && kind == "Module"
        }),
        "search_definitions should still include the synthesized module"
    );
    assert_eq!(
        analyzer.full_hydration_count_for_test(),
        0,
        "search_definitions must not fully hydrate workspace files"
    );

    analyzer.reset_full_hydration_count_for_test();
    let definition_hits = unit_keys(analyzer.get_definitions("entry.ts"));
    assert!(
        definition_hits.iter().any(|(path, fqn, kind)| {
            path == "entry.ts" && fqn == "entry.ts" && kind == "Module"
        }),
        "definitions should still include the synthesized module"
    );
    assert_eq!(
        analyzer.full_hydration_count_for_test(),
        0,
        "definitions must not fully hydrate workspace files"
    );
}

#[test]
fn stale_snapshot_path_is_not_reported_after_file_edit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(root.join("mod.py"), "class Before:\n    pass\n").unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let project = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ));
    let analyzer = PythonAnalyzer::new(project);
    assert!(!analyzer.search_definitions("Before", true).is_empty());

    std::fs::write(root.join("mod.py"), "class After:\n    pass\n").unwrap();
    let stale_hits = analyzer.search_definitions("Before", true);
    assert!(
        stale_hits.is_empty(),
        "stale path result should be omitted after edit: {stale_hits:?}"
    );
}

#[test]
fn git_file_scoped_reads_return_expected_java_data() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(
        root.join("Service.java"),
        r#"
package pkg;
import java.util.List;
class Service {
  int count;
  void greet() {}
}
"#,
    )
    .unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let project = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Java,
    ));
    let analyzer = JavaAnalyzer::new(project);
    let file = ProjectFile::new(root.canonicalize().unwrap(), "Service.java");

    assert_java_file_scoped_reads(&analyzer, &file);
}

#[test]
fn non_git_file_scoped_reads_return_expected_python_data() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            "import os\nclass Service:\n    def greet(self):\n        return os.getcwd()\n",
        )
        .build();
    let analyzer = PythonAnalyzer::new(project.project_dyn());
    let file = ProjectFile::new(project.root().to_path_buf(), "service.py");

    assert_python_file_scoped_reads(&analyzer, &file);
}

#[test]
fn dirty_file_scoped_reads_use_live_worktree_content() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::write(
        root.join("service.py"),
        "class Old:\n    def run(self):\n        return 1\n",
    )
    .unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let project: Arc<dyn Project> = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ));
    let analyzer = PythonAnalyzer::new(Arc::clone(&project));
    std::fs::write(
        root.join("service.py"),
        "class Dirty:\n    def run(self):\n        return 2\n",
    )
    .unwrap();
    let file = ProjectFile::new(root.canonicalize().unwrap(), "service.py");

    let dirty_class = analyzer
        .declarations(&file)
        .into_iter()
        .find(|unit| unit.fq_name() == "service.Dirty")
        .expect("dirty class should be parsed on demand");
    assert_eq!(
        analyzer.get_source(&dirty_class, false).unwrap(),
        "class Dirty:\n    def run(self):\n        return 2"
    );

    let fresh = PythonAnalyzer::new(project);
    let fresh_class = fresh
        .declarations(&file)
        .into_iter()
        .find(|unit| unit.fq_name() == "service.Dirty")
        .expect("fresh class");
    assert_eq!(analyzer.ranges(&dirty_class), fresh.ranges(&fresh_class));
    assert_eq!(
        analyzer.get_skeleton(&dirty_class),
        fresh.get_skeleton(&fresh_class)
    );
}

#[test]
fn same_blob_two_paths_have_path_distinct_file_scoped_units() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("left")).unwrap();
    std::fs::create_dir_all(root.join("right")).unwrap();
    let source = "class Shared:\n    def run(self):\n        return 1\n";
    std::fs::write(root.join("left/shared.py"), source).unwrap();
    std::fs::write(root.join("right/shared.py"), source).unwrap();
    let repo = init_git_repo(root);
    commit_all(&repo, "init");

    let project = Arc::new(TestProject::new(
        root.canonicalize().unwrap(),
        Language::Python,
    ));
    let analyzer = PythonAnalyzer::new(project);
    let left = ProjectFile::new(root.canonicalize().unwrap(), "left/shared.py");
    let right = ProjectFile::new(root.canonicalize().unwrap(), "right/shared.py");

    let left_class = analyzer
        .declarations(&left)
        .into_iter()
        .find(|unit| unit.fq_name() == "left.shared.Shared")
        .expect("left shared class");
    let right_class = analyzer
        .declarations(&right)
        .into_iter()
        .find(|unit| unit.fq_name() == "right.shared.Shared")
        .expect("right shared class");

    assert_eq!(left_class.package_name(), "left.shared");
    assert_eq!(right_class.package_name(), "right.shared");
    assert_eq!(
        analyzer.get_skeleton(&left_class),
        Some("class Shared:\n  def run(self): ...".to_string())
    );
    assert_eq!(
        analyzer.get_skeleton(&left_class),
        analyzer.get_skeleton(&right_class)
    );
}

fn assert_java_file_scoped_reads(analyzer: &JavaAnalyzer, file: &ProjectFile) {
    assert_eq!(
        unit_keys(analyzer.top_level_declarations(file)),
        BTreeSet::from([
            (
                "Service.java".to_string(),
                "pkg".to_string(),
                "Module".to_string()
            ),
            (
                "Service.java".to_string(),
                "pkg.Service".to_string(),
                "Class".to_string()
            )
        ])
    );
    let declarations = unit_keys(analyzer.declarations(file));
    for expected in [
        ("Service.java", "pkg.Service", "Class"),
        ("Service.java", "pkg.Service.count", "Field"),
        ("Service.java", "pkg.Service.greet", "Function"),
    ] {
        assert!(
            declarations.contains(&(
                expected.0.to_string(),
                expected.1.to_string(),
                expected.2.to_string()
            )),
            "missing {expected:?} from {declarations:?}"
        );
    }
    assert_eq!(
        analyzer.import_statements(file),
        vec!["import java.util.List;".to_string()]
    );
    let class = analyzer
        .declarations(file)
        .into_iter()
        .find(|unit| unit.fq_name() == "pkg.Service")
        .expect("class");
    assert_eq!(
        unit_keys(analyzer.direct_children(&class)),
        BTreeSet::from([
            (
                "Service.java".to_string(),
                "pkg.Service.count".to_string(),
                "Field".to_string()
            ),
            (
                "Service.java".to_string(),
                "pkg.Service.greet".to_string(),
                "Function".to_string()
            )
        ])
    );
    assert!(!analyzer.ranges(&class).is_empty());
    assert_eq!(
        analyzer.get_source(&class, false),
        Some("class Service {\n  int count;\n  void greet() {}\n}".to_string())
    );
    assert_eq!(
        analyzer.get_skeleton(&class),
        Some("class Service {\n  int count;\n  void greet()\n}".to_string())
    );
}

fn assert_python_file_scoped_reads(analyzer: &PythonAnalyzer, file: &ProjectFile) {
    assert_eq!(
        unit_keys(analyzer.top_level_declarations(file)),
        BTreeSet::from([
            (
                "service.py".to_string(),
                "service".to_string(),
                "Module".to_string()
            ),
            (
                "service.py".to_string(),
                "service.Service".to_string(),
                "Class".to_string()
            ),
            (
                "service.py".to_string(),
                "service.Service.greet".to_string(),
                "Function".to_string()
            )
        ])
    );
    let declarations = unit_keys(analyzer.declarations(file));
    for expected in [
        ("service.py", "service.Service", "Class"),
        ("service.py", "service.Service.greet", "Function"),
        ("service.py", "service", "Module"),
    ] {
        assert!(
            declarations.contains(&(
                expected.0.to_string(),
                expected.1.to_string(),
                expected.2.to_string()
            )),
            "missing {expected:?} from {declarations:?}"
        );
    }
    assert_eq!(
        analyzer.import_statements(file),
        vec!["import os".to_string()]
    );
    let class = analyzer
        .declarations(file)
        .into_iter()
        .find(|unit| unit.fq_name() == "service.Service")
        .expect("class");
    assert_eq!(
        unit_keys(analyzer.direct_children(&class)),
        BTreeSet::from([(
            "service.py".to_string(),
            "service.Service.greet".to_string(),
            "Function".to_string()
        )])
    );
    assert!(!analyzer.ranges(&class).is_empty());
    assert_eq!(
        analyzer.get_source(&class, false),
        Some("class Service:\n    def greet(self):\n        return os.getcwd()".to_string())
    );
    assert_eq!(
        analyzer.get_skeleton(&class),
        Some("class Service:\n  def greet(self): ...".to_string())
    );
}
