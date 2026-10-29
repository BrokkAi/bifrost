use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
    BoundedFileCache, BulkFileStateSource, ByteBoundedStore, FileStateCacheKey, LanguageAdapter,
    TreeSitterAnalyzer, store_context_from_store,
};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType, Language, ProjectFile};
use brokk_bifrost_core::analyzer::project::{Project, TestProject};
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use brokk_bifrost_python_analysis::analyzer::python::PythonAdapter;
use brokk_bifrost_test_macros::hardwon;
use std::sync::Arc;

fn project(language: Language, files: &[(&str, &str)]) -> (tempfile::TempDir, Arc<dyn Project>) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for (name, source) in files {
        ProjectFile::new(root.clone(), *name).write(source).unwrap();
    }
    let project = Arc::new(TestProject::new(root, language));
    (temp, project)
}

fn persisted<A: LanguageAdapter>(project: Arc<dyn Project>, adapter: A) -> TreeSitterAnalyzer<A> {
    let store = AnalyzerStore::open_persistent(&project.root().join("analyzer.db")).unwrap();
    let context = store_context_from_store(project.as_ref(), store, false);
    TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        project,
        adapter,
        AnalyzerConfig::default(),
        context,
        None,
    )
    .unwrap()
}

#[test]
#[hardwon("021f40d89b72: included source exceeded the byte cap after omitted-source hydration")]
fn query_hydration_recharges_replacements_against_the_byte_cap() {
    let source = format!(
        "class Large {{\n{}void run() {{}}\n}}\n",
        "// retained source bytes\n".repeat(600)
    );
    let (_temp, project) = project(Language::Java, &[("Large.java", &source)]);
    let analyzer = persisted(Arc::clone(&project), JavaAdapter);
    let file = ProjectFile::new(project.root().to_path_buf(), "Large.java");
    let omitted = analyzer.bulk_file_states([file.clone()], BulkFileStateSource::Omit);
    let included = analyzer.bulk_file_states([file.clone()], BulkFileStateSource::Include);
    let small = omitted[&file].estimated_retained_bytes();
    let large = included[&file].estimated_retained_bytes();
    assert!(
        large > small,
        "source inclusion must increase retained weight: {small}, {large}"
    );
    let _scope = AnalyzerQueryScope::new(&analyzer);
    let states = Arc::clone(&analyzer.query_read_cache_lock().file_states);
    states.write().unwrap().max_bytes = small;
    analyzer.bulk_file_states_for_query([file.clone()], BulkFileStateSource::Omit);
    let snapshot = analyzer.query_file_state_snapshot.load_full().unwrap();
    assert_eq!(snapshot.len(), 1);
    assert!(
        snapshot
            .values()
            .all(|state| state.estimated_retained_bytes() <= small)
    );
    drop(snapshot);
    analyzer.bulk_file_states_for_query([file.clone()], BulkFileStateSource::Include);
    let snapshot = analyzer.query_file_state_snapshot.load_full().unwrap();
    assert!(
        snapshot
            .values()
            .all(|state| state.estimated_retained_bytes() <= small)
    );
    assert!(snapshot.is_empty());
    drop(snapshot);
    analyzer.bulk_file_states_for_query([file], BulkFileStateSource::Omit);
    assert_eq!(
        analyzer
            .query_file_state_snapshot
            .load_full()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn signature_storage_is_charged_before_admitting_a_unit_slice() {
    let (_temp, project) = project(Language::Java, &[]);
    let file = ProjectFile::new(project.root().to_path_buf(), "A.java");
    let large = CodeUnit::with_signature(
        file.clone(),
        CodeUnitType::Function,
        "",
        "large",
        Some("x".repeat(8192)),
        false,
    );
    let small = CodeUnit::with_signature(
        file,
        CodeUnitType::Function,
        "",
        "small",
        Some("()".to_owned()),
        false,
    );
    let mut store = ByteBoundedStore::<u8, Arc<[CodeUnit]>>::new(4096);
    store.retain(0, Arc::from([small.clone()]));
    store.retain(1, Arc::from([large]));
    assert!(store.get(&1).is_none());
    assert_eq!(store.get(&0).unwrap().as_ref(), &[small]);
}

#[test]
fn file_cache_evicts_untouched_oldest_entries() {
    use brokk_bifrost_analysis::analyzer::source_admission::SourceAdmissionPolicy;
    let key = |name: &str| FileStateCacheKey {
        oid: git2::Oid::zero(),
        rel_path: name.into(),
        admission_policy: SourceAdmissionPolicy::current(),
    };
    let mut cache = BoundedFileCache::new(2);
    for value in 0..4 {
        cache.insert(key(&value.to_string()), Arc::new(value));
        assert!(cache.len() <= 2);
    }
    assert!(cache.get(&key("0")).is_none());
    assert!(cache.get(&key("1")).is_none());
    assert_eq!(*cache.get(&key("2")).unwrap(), 2);
    assert_eq!(*cache.get(&key("3")).unwrap(), 3);
}

#[test]
fn package_children_do_not_claim_a_bounded_file_local_answer() {
    let (_temp, project) = project(
        Language::Java,
        &[
            ("A.java", "package demo; class A { void run() {} }\n"),
            ("B.java", "package demo; class B {}\n"),
        ],
    );
    let analyzer = persisted(Arc::clone(&project), JavaAdapter);
    drop(analyzer);
    let analyzer = persisted(project, JavaAdapter);
    let units = analyzer.get_all_declarations();
    let package = units
        .iter()
        .find(|unit| unit.is_module() && unit.fq_name() == "demo")
        .unwrap();
    let mut children = analyzer
        .direct_children(package)
        .iter()
        .map(CodeUnit::fq_name)
        .collect::<Vec<_>>();
    children.sort();
    assert_eq!(children, ["demo.A", "demo.B"]);
    for limit in [0, 1, 20] {
        let page = analyzer.direct_children_limited(package, limit);
        assert!(!page.complete, "Java packages span files: {page:?}");
        assert!(page.rows.is_empty());
    }
    let class = units
        .iter()
        .find(|unit| unit.fq_name() == "demo.A")
        .unwrap();
    let page = analyzer.direct_children_limited(class, 20);
    assert!(page.complete);
    assert!(page.rows.iter().any(|unit| unit.identifier() == "run"));
}

#[test]
fn cold_default_package_namespace_respects_the_inspection_budget() {
    let (_temp, project) = project(Language::Java, &[("A.java", "class A { void run() {} }\n")]);
    drop(persisted(Arc::clone(&project), JavaAdapter));
    let analyzer = persisted(Arc::clone(&project), JavaAdapter);
    let file = ProjectFile::new(project.root().to_path_buf(), "A.java");
    for limit in [0, 1, 2, 20] {
        let result = analyzer.file_namespace_hint_limited(&file, limit);
        assert!(result.inspected <= limit, "{result:?}");
        if limit < 3 {
            assert!(result.rows.is_empty(), "{result:?}");
            assert!(!result.complete, "{result:?}");
        } else {
            assert_eq!(result.rows, [""], "{result:?}");
            assert!(result.complete, "{result:?}");
        }
        if limit == 1 {
            assert_eq!(result.inspected, 1);
            assert!(!result.complete);
        }
    }
}

#[test]
fn stale_path_module_batches_report_unavailable_instead_of_absence() {
    let (_temp, project) = project(
        Language::Python,
        &[
            ("alpha.py", "class Alpha: pass\n"),
            ("beta.py", "class Beta: pass\n"),
        ],
    );
    let analyzer = persisted(Arc::clone(&project), PythonAdapter::default());
    let names = vec!["alpha".to_owned(), "beta".to_owned()];
    let before = analyzer.forward_path_module_fqns_batch(&names);
    assert!(
        before
            .iter()
            .all(|row| row.as_ref().is_some_and(|units| !units.is_empty())),
        "{before:?}"
    );
    analyzer
        .analyzer_store()
        .ensure_language_epoch_value("python", "retired-path-module-generation")
        .unwrap();
    assert_eq!(
        analyzer.forward_path_module_fqns_batch(&names),
        [None, None]
    );
    for name in &names {
        assert!(analyzer.forward_path_module_fqn(name).is_none());
    }
    drop(analyzer);
    let reopened = persisted(project, PythonAdapter::default());
    assert!(
        reopened
            .forward_path_module_fqns_batch(&names)
            .iter()
            .all(|row| row.as_ref().is_some_and(|units| !units.is_empty()))
    );
}

#[test]
fn python_hierarchy_modules_have_one_fact_per_file() {
    let (_temp, project) = project(
        Language::Python,
        &[
            ("pkg/__init__.py", "from .alpha import Alpha\n"),
            ("pkg/alpha.py", "class Alpha: pass\n"),
            ("pkg/beta.py", "class Beta: pass\n"),
        ],
    );
    let repo = track(project.as_ref());
    let check = |analyzer: &TreeSitterAnalyzer<PythonAdapter>| {
        for kind in [CodeUnitType::Module, CodeUnitType::Class] {
            let facts = analyzer.hierarchy_declaration_facts_by_kind(kind).unwrap();
            let names = facts
                .iter()
                .map(|fact| fact.declaration.fq_name())
                .collect::<Vec<_>>();
            let unique = names.iter().collect::<std::collections::BTreeSet<_>>();
            assert_eq!(names.len(), unique.len(), "{names:?}");
            let mut inventory = facts
                .iter()
                .map(|fact| {
                    (
                        fact.declaration.fq_name(),
                        fact.declaration.source().clone(),
                    )
                })
                .collect::<Vec<_>>();
            inventory.sort();
            let expected = if kind == CodeUnitType::Module {
                vec![
                    ("pkg", "pkg/__init__.py"),
                    ("pkg.alpha", "pkg/alpha.py"),
                    ("pkg.beta", "pkg/beta.py"),
                ]
            } else {
                vec![
                    ("pkg.alpha.Alpha", "pkg/alpha.py"),
                    ("pkg.beta.Beta", "pkg/beta.py"),
                ]
            };
            assert_eq!(
                inventory,
                expected
                    .into_iter()
                    .map(|(name, path)| (name.to_owned(), ProjectFile::new(project.root(), path)))
                    .collect::<Vec<_>>()
            );
        }
    };
    for _ in 0..2 {
        check(&persisted(Arc::clone(&project), PythonAdapter::default()));
    }
    let analyzer = persisted(Arc::clone(&project), PythonAdapter::default());
    let file = ProjectFile::new(project.root().to_path_buf(), "pkg/alpha.py");
    file.write("class Alpha:\n    def added(self): pass\n")
        .unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_path(std::path::Path::new("pkg/alpha.py"))
        .unwrap();
    index.write().unwrap();
    fail_publication(&analyzer);
    let updated = analyzer.update(&std::collections::BTreeSet::from([file]));
    assert!(!updated.state.dirty_snapshot().is_empty());
    check(&updated);
}

#[test]
fn declaration_syntax_uses_the_nearest_enclosing_type() {
    let (_temp, project) = project(
        Language::Java,
        &[(
            "Types.java",
            "enum E { ONE; class Inner { void nested() {} } void outer() {} }\ninterface I { class Inner { void nested() {} } void outer(); }\nclass Plain { void plain() {} }\nrecord Value(int count) { void value() {} }\n",
        )],
    );
    let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
    for (name, expected) in [
        ("E.Inner.nested", "class_declaration"),
        ("I.Inner.nested", "class_declaration"),
        ("E.outer", "enum_declaration"),
        ("I.outer", "interface_declaration"),
        ("Plain.plain", "class_declaration"),
        ("Value.value", "record_declaration"),
    ] {
        let unit = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == name)
            .unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(
            analyzer.declaration_syntax_kind(&unit),
            Some(expected),
            "{name}"
        );
    }
}

#[test]
fn exact_source_admission_includes_the_byte_limit_boundary() {
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
        BoundedParse, source_admission_test_support::parse,
    };
    let adapter = PythonAdapter::default();
    let source = "def cafe(): return 'caf\u{e9}'";
    let (_temp, project) = project(Language::Python, &[("cafe.py", source)]);
    let file = ProjectFile::new(project.root().to_path_buf(), "cafe.py");
    let adapter = adapter.for_project(project).unwrap();
    for limit in [source.len() - 1, source.len(), source.len() + 1] {
        let outcome = parse(&adapter, source, Some(&limit.to_string()));
        if limit < source.len() {
            assert!(matches!(outcome, BoundedParse::Refused(_)));
        } else {
            let BoundedParse::Complete(tree) = outcome else {
                panic!("exact boundary refused")
            };
            assert!(!tree.root_node().has_error());
            assert_eq!(tree.root_node().end_byte(), source.len());
            let parsed = adapter.parse_file(&file, source, &tree);
            assert!(
                parsed
                    .top_level_declarations
                    .iter()
                    .any(|unit| unit.identifier() == "cafe")
            );
        }
    }
}

fn fail_publication<A: LanguageAdapter>(analyzer: &TreeSitterAnalyzer<A>) {
    analyzer.analyzer_store().conn.execute(|connection| connection.execute_batch(
        "CREATE TEMP TRIGGER refuse_publication BEFORE INSERT ON blobs BEGIN SELECT RAISE(FAIL, 'retain edited source'); END;"
    ).unwrap());
}

fn track(project: &dyn Project) -> git2::Repository {
    let repo = brokk_bifrost_core::gitblob::test_repo::init_repo(project.root());
    brokk_bifrost_core::gitblob::test_repo::commit_all(&repo, "source inventory");
    repo
}

#[test]
fn dirty_exact_names_and_members_match_the_edited_inventory() {
    use brokk_bifrost_csharp_analysis::analyzer::csharp::adapter::CSharpAdapter;
    use std::collections::BTreeSet;
    let (_temp, project) = project(
        Language::CSharp,
        &[
            ("A.cs", "partial class Owner { void member(int n) {} }\n"),
            (
                "B.cs",
                "partial class Owner { void member(String n) {} } class Other {}\n",
            ),
        ],
    );
    let repo = track(project.as_ref());
    let analyzer = persisted(Arc::clone(&project), CSharpAdapter);
    let file = ProjectFile::new(project.root().to_path_buf(), "A.cs");
    file.write("partial class Owner { void member(double n) {} void added() {} }\n")
        .unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("A.cs")).unwrap();
    index.write().unwrap();
    fail_publication(&analyzer);
    let updated = analyzer.update(&BTreeSet::from([file]));
    assert!(!updated.state.dirty_snapshot().is_empty());
    let fresh = TreeSitterAnalyzer::new(Arc::clone(&project), CSharpAdapter);
    for name in ["Owner", "Other", "Owner.member", "Owner.added", "Missing"] {
        for normalized in [false, true] {
            let actual = updated
                .try_lookup_declarations_by_persisted_fqn(name, normalized)
                .unwrap();
            let expected = fresh
                .try_lookup_declarations_by_persisted_fqn(name, normalized)
                .unwrap();
            assert_eq!(actual, expected, "{name} normalized={normalized}");
            assert!(actual.iter().all(|unit| unit.fq_name() == name));
            assert_eq!(
                actual.len(),
                match name {
                    "Owner" | "Owner.member" => 2,
                    "Missing" => 0,
                    _ => 1,
                }
            );
        }
    }
    let members = updated.lookup_members_for_owner_name("Owner", "member");
    assert_eq!(members.len(), 2, "{members:?}");
    assert_eq!(
        members,
        fresh.lookup_members_for_owner_name("Owner", "member")
    );
    assert!(
        updated
            .lookup_members_for_owner_name("Owner", "missing")
            .is_empty()
    );
}

#[test]
fn dirty_assignment_members_match_fresh_javascript_navigation() {
    use brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter;
    use std::collections::BTreeSet;
    let (_temp, project) = project(
        Language::JavaScript,
        &[(
            "object.js",
            "function holder() { let obj = {}; obj.old = function() {}; return obj; }\n",
        )],
    );
    let repo = track(project.as_ref());
    let analyzer = persisted(Arc::clone(&project), JavascriptAdapter);
    let file = ProjectFile::new(project.root().to_path_buf(), "object.js");
    file.write("function holder() { let obj = {}; obj.member = function() {}; obj.nested = {}; obj.nested.child = function() {}; return obj; }\n").unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("object.js")).unwrap();
    index.write().unwrap();
    fail_publication(&analyzer);
    let updated = analyzer.update(&BTreeSet::from([file]));
    assert!(!updated.state.dirty_snapshot().is_empty());
    let fresh = TreeSitterAnalyzer::new(project, JavascriptAdapter);
    for name in ["holder", "member", "child", "old"] {
        let expected = fresh.lookup_declarations_by_identifier(name);
        assert_eq!(
            updated.lookup_declarations_by_identifier(name),
            expected,
            "{name}"
        );
        if name != "old" {
            assert!(!expected.is_empty(), "fixture must expose {name}");
        } else {
            assert!(expected.is_empty());
        }
        let limited =
            updated.lookup_non_module_declarations_by_identifier_limited(name, 100, || true);
        assert!(limited.complete, "{name}: {limited:?}");
        assert_eq!(
            limited.rows.into_iter().collect::<BTreeSet<_>>(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn literal_symbol_search_quotes_stars_but_keeps_explicit_wildcards() {
    use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;
    let (_temp, project) = project(
        Language::Scala,
        &[(
            "Names.scala",
            "object Names { def `Star*Name`(): Unit = (); def StarName(): Unit = (); def `Dot.Name`(): Unit = () }\n",
        )],
    );
    let analyzer = TreeSitterAnalyzer::new(project, ScalaAdapter);
    for (pattern, expected) in [
        ("*", vec!["Names$.`Star*Name`"]),
        ("Star*Name", vec!["Names$.`Star*Name`"]),
        ("Dot.Name", vec!["Names$.`Dot.Name`"]),
    ] {
        let found = analyzer.search_definitions(pattern, true);
        let names = found.iter().map(CodeUnit::fq_name).collect::<Vec<_>>();
        assert_eq!(names, expected, "{pattern}");
        assert_eq!(
            found,
            analyzer.search_definitions(&format!(".*?{}.*?", regex::escape(pattern)), false)
        );
    }
    assert!(analyzer.search_definitions(".*", true).len() >= 4);
}

#[test]
fn shared_content_does_not_project_c_declarations_into_cpp() {
    use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
    let (_temp, project) = project(
        Language::Cpp,
        &[
            (
                "twin.c",
                "struct Outer { struct Inner { int value; } inner; };\nstruct Shared {};\n",
            ),
            (
                "twin.cpp",
                "struct Outer { struct Inner { int value; } inner; };\nstruct Shared {};\n",
            ),
        ],
    );
    drop(persisted(Arc::clone(&project), CppAdapter));
    let analyzer = persisted(project, CppAdapter);
    for name in ["Inner", "Shared"] {
        let unlimited = analyzer.lookup_declarations_by_identifier(name);
        let limited = analyzer.lookup_declarations_by_identifier_limited(name, 100, || true);
        assert!(limited.complete);
        assert_eq!(
            limited
                .rows
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            unlimited,
            "{name}"
        );
        let mut paths = unlimited
            .iter()
            .map(|unit| unit.source().rel_path().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(paths, ["twin.c", "twin.cpp"]);
        assert!(unlimited.iter().all(CodeUnit::is_class));
        if name == "Inner" {
            for unit in &unlimited {
                assert_eq!(
                    unit.fq_name().contains("Outer"),
                    unit.source().rel_path().extension().unwrap() == "cpp"
                );
            }
        }
    }
}

#[test]
fn disabled_automatic_gc_preserves_due_accounting_through_drop() {
    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    let _tuning = brokk_bifrost_core::cache_gc::set_tuning_for_test(1, 0);
    let (_temp, project) = project(
        Language::Java,
        &[
            ("A.java", "class A {}\n"),
            (".gitignore", ".bifrost/cache/\n"),
        ],
    );
    let _repo = track(project.as_ref());
    let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
        Arc::clone(&project),
        AnalyzerConfig::default(),
    )
    .unwrap();
    let db = workspace.persisted_store_path().unwrap();
    drop(workspace);
    brokk_bifrost_core::cache_gc::set_accounting_for_test(&db, 0, 0).unwrap();
    drop(
        WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            Arc::clone(&project),
            AnalyzerConfig::default(),
        )
        .unwrap(),
    );
    assert_eq!(
        brokk_bifrost_core::cache_gc::gc_accounting_for_test(&db).unwrap(),
        (0, 0)
    );
    drop(WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default()).unwrap());
    let (time, blobs) = brokk_bifrost_core::cache_gc::gc_accounting_for_test(&db).unwrap();
    assert!(
        time > 0 && blobs > 0,
        "enabled GC must have run: {:?}",
        (time, blobs)
    );
}

#[test]
fn overlay_package_type_queries_exclude_fields_and_methods() {
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    use brokk_bifrost_core::analyzer::{
        DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
        RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
        RelationalName,
    };
    let (_temp, base) = project(
        Language::Java,
        &[
            ("A.java", "package demo; class A {}\n"),
            ("B.java", "package demo; class B {}\n"),
        ],
    );
    let overlay = Arc::new(OverlayProject::new(base));
    let analyzer = TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, JavaAdapter);
    let file = ProjectFile::new(overlay.root().to_path_buf(), "A.java");
    assert!(overlay.set(
        file.abs_path(),
        "package demo; class A { int field; void method() {} }\n".to_owned()
    ));
    let updated = analyzer.update(&std::collections::BTreeSet::from([file]));
    let owner = updated
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.fq_name() == "demo.A")
        .unwrap();
    let request = RelationalDefinitionRequest {
        ordinal: 0,
        language_scope: DefinitionLanguageScope::Language(Language::Java),
        name: RelationalName::stable(owner.package_fq()),
        query: RelationalDefinitionQuery::PackageTypesInPackage,
    };
    let outcome = RelationalDefinitionLookup::batch(
        &updated,
        &[request],
        &brokk_bifrost_analysis::CancellationToken::new(),
    );
    let RelationalBatchOutcome::Complete(rows) = outcome else {
        panic!("{outcome:?}")
    };
    let RelationalDefinitionValue::Definitions(units) = &rows[0].value else {
        panic!("wrong shape")
    };
    let mut names = units.iter().map(CodeUnit::fq_name).collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["demo.A", "demo.B"]);
    assert!(units.iter().all(CodeUnit::is_class));
}

#[test]
fn dirty_cpp_overloads_follow_the_earliest_prototype() {
    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    let (_temp, project) = project(Language::Cpp, &[("order.hpp", "void f(char);\n")]);
    let repo = track(project.as_ref());
    let analyzer = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
        Arc::clone(&project),
        AnalyzerConfig::default(),
    )
    .unwrap();
    analyzer.store().unwrap().conn.execute(|connection| connection.execute_batch(
        "CREATE TEMP TRIGGER refuse_order_publication BEFORE INSERT ON blobs BEGIN SELECT RAISE(FAIL, 'retain prototype ranges'); END;"
    ).unwrap());
    let file = ProjectFile::new(project.root().to_path_buf(), "order.hpp");
    file.write("void f(int);\nvoid f(double);\nvoid f(int);\nvoid f(double) {}\nvoid f(int) {}\n")
        .unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("order.hpp")).unwrap();
    index.write().unwrap();
    let updated = analyzer.update(&std::collections::BTreeSet::from([file]));
    let units = updated.analyzer().definitions("f").collect::<Vec<_>>();
    assert_eq!(units.len(), 2, "{units:?}");
    assert!(units[0].signature().unwrap().contains("int"), "{units:?}");
    assert!(
        units[1].signature().unwrap().contains("double"),
        "{units:?}"
    );
    let ranges = updated.analyzer().ranges(&units[0]);
    assert!(
        ranges.len() >= 2,
        "the repeated int prototype must retain multiple ranges: {ranges:?}"
    );
}
