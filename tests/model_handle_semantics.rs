use brokk_analyzer::{
    CodeUnit, CodeUnitType, ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile,
    TestProject,
};
use std::cmp::Ordering;
use std::collections::{BTreeSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
        .canonicalize()
        .unwrap()
}

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn project_file_equality_ordering_and_hash_are_semantic() {
    let left = ProjectFile::new(root(), "A.java");
    let same = ProjectFile::new(root(), "./A.java");
    let right = ProjectFile::new(root(), "B.java");

    assert_eq!(left, same);
    assert_eq!(hash_value(&left), hash_value(&same));
    assert!(left < right);
}

#[test]
fn code_unit_equality_ordering_and_hash_are_semantic() {
    let file = ProjectFile::new(root(), "A.java");
    let left = CodeUnit::with_signature(
        file.clone(),
        CodeUnitType::Function,
        "pkg",
        "A.method",
        Some("void method()".to_string()),
        false,
    );
    let same = CodeUnit::with_signature(
        ProjectFile::new(root(), "A.java"),
        CodeUnitType::Function,
        "pkg",
        "A.method",
        Some("void method()".to_string()),
        false,
    );
    let different_signature = CodeUnit::with_signature(
        file,
        CodeUnitType::Function,
        "pkg",
        "A.method",
        Some("int method()".to_string()),
        false,
    );

    assert_eq!(left, same);
    assert_eq!(hash_value(&left), hash_value(&same));
    assert_ne!(left, different_signature);

    let mut set = BTreeSet::new();
    set.insert(left.clone());
    set.insert(same);
    set.insert(different_signature.clone());
    assert_eq!(set.len(), 2);
    assert_eq!(left.cmp(&different_signature), Ordering::Greater);
}

#[test]
fn java_wildcard_imports_resolve_from_package_index() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "pkg/Base.java")
        .write("package pkg; public class Base {}")
        .unwrap();
    ProjectFile::new(root.clone(), "pkg/Derived.java")
        .write("package pkg; public class Derived {}")
        .unwrap();
    ProjectFile::new(root.clone(), "consumer/Use.java")
        .write("package consumer; import pkg.*; public class Use { Base base; Derived derived; }")
        .unwrap();

    let analyzer = JavaAnalyzer::from_project(TestProject::new(root.clone(), Language::Java));
    let imports = analyzer.imported_code_units_of(&ProjectFile::new(root, "consumer/Use.java"));
    let names: BTreeSet<_> = imports
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();

    assert_eq!(
        names,
        BTreeSet::from(["pkg.Base".to_string(), "pkg.Derived".to_string()])
    );
}
