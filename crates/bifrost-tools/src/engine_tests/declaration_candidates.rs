use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType, Language, ProjectFile};
use brokk_bifrost_core::analyzer::project::{OverlayProject, Project, TestProject};
use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;
use brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter;
use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;
use std::collections::BTreeSet;
use std::sync::Arc;

fn java_analyzer(files: &[(&str, &str)]) -> (tempfile::TempDir, TreeSitterAnalyzer<JavaAdapter>) {
    let temp = tempfile::tempdir().expect("temporary project");
    let root = temp.path().canonicalize().expect("canonical project root");
    for (path, source) in files {
        let file = ProjectFile::new(root.clone(), path);
        if let Some(parent) = file.abs_path().parent() {
            std::fs::create_dir_all(parent).expect("source directory");
        }
        file.write(source).expect("write Java source");
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
    (temp, TreeSitterAnalyzer::new(project, JavaAdapter))
}

fn go_analyzer(files: &[(&str, &str)]) -> (tempfile::TempDir, TreeSitterAnalyzer<GoAdapter>) {
    let temp = tempfile::tempdir().expect("temporary project");
    let root = temp.path().canonicalize().expect("canonical project root");
    for (path, source) in files {
        let file = ProjectFile::new(root.clone(), path);
        if let Some(parent) = file.abs_path().parent() {
            std::fs::create_dir_all(parent).expect("source directory");
        }
        file.write(source).expect("write Go source");
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Go));
    (temp, TreeSitterAnalyzer::new(project, GoAdapter))
}

fn python_analyzer(
    files: &[(&str, &str)],
) -> (tempfile::TempDir, TreeSitterAnalyzer<PythonAdapter>) {
    let temp = tempfile::tempdir().expect("temporary project");
    let root = temp.path().canonicalize().expect("canonical project root");
    for (path, source) in files {
        let file = ProjectFile::new(root.clone(), path);
        if let Some(parent) = file.abs_path().parent() {
            std::fs::create_dir_all(parent).expect("source directory");
        }
        file.write(source).expect("write Python source");
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
    (
        temp,
        TreeSitterAnalyzer::new(project, PythonAdapter::default()),
    )
}

fn rust_analyzer(files: &[(&str, &str)]) -> (tempfile::TempDir, TreeSitterAnalyzer<RustAdapter>) {
    let temp = tempfile::tempdir().expect("temporary project");
    let root = temp.path().canonicalize().expect("canonical project root");
    for (path, source) in files {
        let file = ProjectFile::new(root.clone(), path);
        if let Some(parent) = file.abs_path().parent() {
            std::fs::create_dir_all(parent).expect("source directory");
        }
        file.write(source).expect("write Rust source");
    }
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
    (temp, TreeSitterAnalyzer::new(project, RustAdapter))
}

fn named(units: &[CodeUnit], kind: CodeUnitType, name: &str) -> Vec<CodeUnit> {
    units
        .iter()
        .filter(|unit| unit.kind() == kind && unit.identifier() == name)
        .cloned()
        .collect()
}

#[test]
fn persisted_and_updated_declarations_match_the_live_workspace() {
    let (temp, analyzer) = java_analyzer(&[
        (
            "A.java",
            "package demo; class Alpha extends Base { class Nested {} }\n",
        ),
        ("Base.java", "package demo; class Base {}\n"),
        ("B.java", "package demo; class Beta {}\n"),
    ]);
    let before = analyzer.get_all_declarations();
    assert_eq!(named(&before, CodeUnitType::Class, "Nested").len(), 1);

    let package_classes = analyzer.class_declarations_in_package("demo");
    let package_names = package_classes
        .iter()
        .filter(|unit| unit.is_class())
        .map(CodeUnit::identifier)
        .collect::<Vec<_>>();
    assert_eq!(package_names, ["Alpha", "Beta", "Base"]);

    let ranged_before = analyzer.all_declarations_with_primary_ranges();
    assert!(
        ranged_before
            .iter()
            .any(|(unit, range)| { unit.identifier() == "Alpha" && range.is_some() })
    );

    let root = temp.path().canonicalize().expect("canonical project root");
    let changed = ProjectFile::new(root, "A.java");
    let same_content_overlay = Arc::new(OverlayProject::new(Arc::clone(&analyzer.project)));
    assert!(same_content_overlay.set(
        changed.abs_path(),
        "package demo; // same declaration identity, new blob\nclass Alpha extends Base { class Nested {} }\n".to_string()
    ));
    let same_content_request =
        analyzer.clone_with_project(Arc::new(same_content_overlay.snapshot()));
    let same_content_classes = same_content_request.class_declarations_in_package("demo");
    let unique_content_classes = same_content_classes.iter().collect::<BTreeSet<_>>();
    assert_eq!(
        same_content_classes.len(),
        unique_content_classes.len(),
        "persisted and overlay package projections must deduplicate: {same_content_classes:?}"
    );

    let overlay = Arc::new(OverlayProject::new(Arc::clone(&analyzer.project)));
    assert!(overlay.set(changed.abs_path(), "package demo;\n".to_string()));
    let request = analyzer.clone_with_project(Arc::new(overlay.snapshot()));
    assert!(request.workspace_declaration_identities_authoritative());
    let overlaid = request.get_all_declarations();
    assert!(
        named(&overlaid, CodeUnitType::Class, "Alpha").is_empty(),
        "{overlaid:?}"
    );
    assert!(
        named(&overlaid, CodeUnitType::Class, "Nested").is_empty(),
        "{overlaid:?}"
    );
    let ranged_overlay = request.all_declarations_with_primary_ranges();
    assert!(
        !ranged_overlay
            .iter()
            .any(|(unit, _)| unit.identifier() == "Alpha"),
        "stale persisted declarations must be shadowed: {ranged_overlay:?}"
    );
    assert!(
        !ranged_overlay
            .iter()
            .any(|(unit, _)| unit.source() == &changed && unit.is_class())
    );

    changed
        .write("package demo; class Renamed extends Base { class Nested {} }\n")
        .expect("replace source");
    let updated = analyzer.update(&BTreeSet::from([changed]));
    let after = updated.get_all_declarations();
    assert!(
        named(&after, CodeUnitType::Class, "Alpha").is_empty(),
        "{after:?}"
    );
    assert_eq!(named(&after, CodeUnitType::Class, "Renamed").len(), 1);
    assert_eq!(named(&after, CodeUnitType::Class, "Nested").len(), 1);
    let ranged_after = updated.all_declarations_with_primary_ranges();
    assert!(
        ranged_after
            .iter()
            .any(|(unit, range)| { unit.identifier() == "Renamed" && range.is_some() })
    );
}

#[test]
fn hierarchy_rows_retain_and_hydrate_persisted_supertypes() {
    let (_temp, analyzer) = java_analyzer(&[
        (
            "Child.java",
            "package demo; import java.io.Serializable; class Child extends Base implements Serializable {}\n",
        ),
        ("Base.java", "package demo; class Base {}\n"),
    ]);
    let (hierarchy_rows, hierarchy_reads) = capture_query_reads(&analyzer, || {
        analyzer.hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
    });
    assert!(
        hierarchy_reads.keys().contains(&analyzer.scope_read_key()),
        "hierarchy query must record its workspace-scope dependency: {:?}",
        hierarchy_reads.keys()
    );
    let mut rows = hierarchy_rows.expect("complete hierarchy query");
    assert!(
        rows.iter()
            .any(|row| row.declaration.identifier() == "Child")
    );
    let (hydrated, reads) = capture_query_reads(&analyzer, || {
        analyzer.hydrate_hierarchy_declaration_facts(&mut rows)
    });
    hydrated.expect("hydrate hierarchy facts");
    assert!(
        reads.keys().contains(&analyzer.scope_read_key()),
        "hierarchy hydration must record its workspace-scope dependency: {:?}",
        reads.keys()
    );
    let child = rows
        .iter()
        .find(|row| row.declaration.identifier() == "Child")
        .expect("child hierarchy row");
    assert!(
        child
            .raw_supertypes
            .iter()
            .any(|name| name.contains("Base"))
    );
    assert!(
        child
            .raw_supertypes
            .iter()
            .any(|name| name.contains("Serializable"))
    );
}

#[test]
fn hierarchy_query_on_rekeyed_go_overlay_is_an_explicit_empty_result() {
    let (_temp, analyzer) = go_analyzer(&[
        ("go.mod", "module example.com/original\n\ngo 1.24\n"),
        ("main.go", "package main\ntype Parent struct{}\n"),
    ]);
    let overlay = Arc::new(OverlayProject::new(Arc::clone(&analyzer.project)));
    assert!(overlay.set(
        analyzer.project.root().join("go.mod"),
        "module example.com/rekeyed\n\ngo 1.24\n".to_string()
    ));
    let request = analyzer.clone_with_project(Arc::new(overlay.snapshot()));
    assert!(!request.workspace_declaration_identities_authoritative());
    assert!(matches!(
        request.hierarchy_declaration_facts_by_kind(CodeUnitType::Class),
        Some(rows) if rows.is_empty()
    ));
}

#[test]
fn bounded_non_module_identifier_lookup_excludes_path_module_units() {
    let (_temp, analyzer) = python_analyzer(&[(
        "service.py",
        "def service():\n    return 1\n\nclass Service:\n    pass\n",
    )]);
    let _ = analyzer.get_all_declarations();
    assert!(analyzer.workspace_declaration_identities_authoritative());
    let result =
        analyzer.lookup_non_module_declarations_by_identifier_limited("service", 16, || true);
    assert!(result.complete, "{result:?}");
    assert!(
        result.rows.iter().any(|unit| unit.is_function()),
        "expected the real declaration: {:?}",
        result.rows
    );
    assert!(
        result.rows.iter().all(|unit| !unit.is_module()),
        "{:?}",
        result.rows
    );
}

#[test]
fn declaration_candidates_are_unique_and_ranges_keep_source_order() {
    let source = "package demo; class Widget { int first; } class Widget { int second; }\n";
    let (_temp, analyzer) = java_analyzer(&[("Widget.java", source)]);
    let all = analyzer.get_all_declarations();
    let widgets = named(&all, CodeUnitType::Class, "Widget");
    assert_eq!(widgets.len(), 1, "{widgets:?}");
    let widget = &widgets[0];

    let definitions = analyzer.get_definitions(&widget.fq_name());
    assert_eq!(definitions.iter().filter(|unit| unit == &widget).count(), 1);
    let ranges = analyzer.location_ranges(widget);
    assert!(ranges.len() >= 2, "expected both source sites: {ranges:?}");
    assert!(
        ranges
            .windows(2)
            .all(|pair| pair[0].start_byte < pair[1].start_byte)
    );

    let short_name_candidates = analyzer.lookup_candidates_by_short_name("Widget");
    assert!(
        short_name_candidates.contains(widget),
        "{short_name_candidates:?}"
    );
    assert_eq!(
        short_name_candidates
            .iter()
            .filter(|unit| *unit == widget)
            .count(),
        1
    );

    let (_nested_temp, nested_analyzer) = java_analyzer(&[(
        "Outer.java",
        "package demo; class Outer { class Inner {} }\n",
    )]);
    let nested_units = nested_analyzer.get_all_declarations();
    let inner = named(&nested_units, CodeUnitType::Class, "Inner")
        .into_iter()
        .next()
        .expect("fixture declares Outer.Inner");
    assert_ne!(inner.short_name(), inner.identifier());
    assert!(
        nested_analyzer
            .lookup_candidates_by_short_name(inner.short_name())
            .contains(&inner)
    );
}

#[test]
fn duplicate_impl_children_sort_by_their_first_source_range() {
    let (_temp, analyzer) = rust_analyzer(&[(
        "lib.rs",
        "pub struct Widget;\nimpl Widget { fn alpha() {} fn beta() {} }\nimpl Widget { fn beta() {} fn alpha() {} }\n",
    )]);
    let widget = named(
        &analyzer.get_all_declarations(),
        CodeUnitType::Class,
        "Widget",
    )
    .into_iter()
    .next()
    .expect("fixture declares Widget");
    let children = analyzer.direct_children_limited(&widget, 32);
    assert!(children.complete, "{children:?}");
    let names = children
        .rows
        .iter()
        .filter(|unit| unit.is_function())
        .map(CodeUnit::identifier)
        .collect::<Vec<_>>();
    assert_eq!(names, ["alpha", "beta"]);
}

#[test]
fn java_nested_member_lookup_accepts_binary_owner_spelling() {
    let (_temp, initial) = java_analyzer(&[(
        "Outer.java",
        "package demo; public class Outer { public static class Inner { public void member() {} } }\n",
    )]);
    initial
        .store_context
        .store
        .conn
        .execute(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER reject_nested_member_blob
                 BEFORE INSERT ON blobs
                 BEGIN SELECT RAISE(ABORT, 'retain nested member for lookup'); END;",
            )?;
            Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
        })
        .expect("install temporary publication failure");
    let file = ProjectFile::new(initial.project.root().to_path_buf(), "Outer.java");
    file.write("package demo; // edited source\npublic class Outer { public static class Inner { public void member() {} } }\n")
        .expect("edit Java source");
    let analyzer = initial.update(&BTreeSet::from([file]));
    let declarations = analyzer.get_all_declarations();
    assert!(
        declarations
            .iter()
            .any(|unit| unit.identifier() == "member"),
        "fixture contains the nested member: {declarations:?}"
    );

    let members = analyzer.lookup_members_for_owner_name("demo.Outer$Inner", "member");
    assert_eq!(
        members.len(),
        1,
        "binary nested-owner spelling must resolve its declared member: {members:?}; declarations: {declarations:?}"
    );
    let member = members.iter().next().unwrap();
    assert_eq!(member.identifier(), "member");
    assert!(member.fq_name().contains("Outer"), "{member:?}");
}
