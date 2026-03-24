use brokk_analyzer::{
    AnalyzerDelegate, IAnalyzer, ImportAnalysisProvider, Language, MultiAnalyzer, Project,
    ProjectFile, RustAnalyzer, TestProject,
};
use std::collections::BTreeMap;
use tempfile::tempdir;

fn rust_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Rust)
}

#[test]
fn rust_discovers_modules_impl_targets_and_members() {
    let project = rust_project(&[(
        "lib.rs",
        r#"
        mod utils {
            pub fn helper() -> i32 {
                42
            }
        }

        pub struct Point {
            pub x: i32,
            pub y: i32,
        }

        impl Point {
            pub fn new(x: i32, y: i32) -> Self {
                Self { x, y }
            }

            pub const ID: i32 = 1;
        }

        pub trait Drawable {
            fn draw(&self);
        }

        pub enum Color {
            Red,
            Green,
            Blue,
        }

        pub fn distance(a: &Point, b: &Point) -> f64 {
            0.0
        }
        "#,
    )]);
    let analyzer = RustAnalyzer::from_project(project);

    assert!(!analyzer.get_definitions("utils").is_empty());
    assert!(!analyzer.get_definitions("utils.helper").is_empty());
    assert!(!analyzer.get_definitions("Point").is_empty());
    assert!(!analyzer.get_definitions("Point.new").is_empty());
    assert!(!analyzer.get_definitions("Point.ID").is_empty());
    assert!(!analyzer.get_definitions("Drawable").is_empty());
    assert!(!analyzer.get_definitions("Color").is_empty());
    assert!(!analyzer.get_definitions("distance").is_empty());

    let point = analyzer
        .get_definitions("Point")
        .into_iter()
        .next()
        .unwrap();
    let point_skeleton = analyzer.get_skeleton(&point).unwrap();
    assert!(point_skeleton.contains("pub x: i32"));
    assert!(point_skeleton.contains("pub y: i32"));

    let id = analyzer
        .get_definitions("Point.ID")
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        "pub const ID: i32 = 1;",
        analyzer.get_skeleton(&id).unwrap()
    );
}

#[test]
fn rust_extracts_impl_target_names_for_wrapped_types() {
    let project = rust_project(&[(
        "lib.rs",
        r#"
        pub trait Demo {
            fn act(&self);
        }

        impl<T> Demo for &T {
            fn act(&self) {}
        }

        impl<T> Demo for &Vec<Box<T>> {
            fn act(&self) {}
        }

        impl<T> Demo for *const T {
            fn act(&self) {}
        }

        impl<T> Demo for [T] {
            fn act(&self) {}
        }
        "#,
    )]);
    let analyzer = RustAnalyzer::from_project(project);

    assert!(!analyzer.get_definitions("T.act").is_empty());
    assert!(!analyzer.get_definitions("Vec.act").is_empty());
}

#[test]
fn rust_imports_aliases_and_test_detection_match_expected_behaviors() {
    let project = rust_project(&[
        ("src/my_module.rs", "pub struct MyStruct;\n"),
        (
            "src/main.rs",
            r#"
            use crate::my_module::MyStruct;
            use crate::my_module::MyStruct as AliasStruct;
            use std::io::{self, Read, Write};

            #[cfg(test)]
            mod tests {
                #[test]
                fn it_works() {
                    let _s = AliasStruct;
                    let _ = MyStruct;
                }
            }
            "#,
        ),
    ]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    let main_file = ProjectFile::new(project.root().to_path_buf(), "src/main.rs");

    let imports = analyzer.import_statements_of(&main_file);
    assert!(imports.contains(&"use crate::my_module::MyStruct;".to_string()));
    assert!(imports.contains(&"use crate::my_module::MyStruct as AliasStruct;".to_string()));
    assert!(imports.contains(&"use std::io;".to_string()));
    assert!(imports.contains(&"use std::io::Read;".to_string()));
    assert!(imports.contains(&"use std::io::Write;".to_string()));

    let imported = analyzer.imported_code_units_of(&main_file);
    assert!(
        imported
            .iter()
            .any(|code_unit| code_unit.identifier() == "MyStruct")
    );
    assert!(analyzer.contains_tests(&main_file));

    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Rust,
        AnalyzerDelegate::Rust(analyzer.clone()),
    )]));
    assert!(multi.contains_tests(&main_file));
}

#[test]
fn rust_type_aliases_are_marked() {
    let project = rust_project(&[(
        "src/main.rs",
        r#"
        type MyResult<T> = Result<T, Error>;
        struct MyStruct;
        fn my_func() {}
        "#,
    )]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "src/main.rs");
    let declarations = analyzer.get_declarations(&file);

    let alias = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "MyResult")
        .unwrap();
    let structure = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "MyStruct")
        .unwrap();
    let function = declarations
        .iter()
        .find(|code_unit| code_unit.identifier() == "my_func")
        .unwrap();

    assert!(analyzer.is_type_alias(alias));
    assert!(!analyzer.is_type_alias(structure));
    assert!(!analyzer.is_type_alias(function));
    assert!(
        analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(alias))
    );
}

#[test]
fn rust_updates_add_and_remove_definitions() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "lib.rs");
    file.write("pub fn foo() -> i32 { 1 }\n").unwrap();

    let project = TestProject::new(root, Language::Rust);
    let analyzer = RustAnalyzer::from_project(project);
    assert!(!analyzer.get_definitions("foo").is_empty());
    assert!(analyzer.get_definitions("bar").is_empty());

    file.write(
        r#"
        pub fn foo() -> i32 { 1 }
        pub fn bar() -> i32 { 2 }
        "#,
    )
    .unwrap();

    let updated = analyzer.update(&std::collections::BTreeSet::from([file.clone()]));
    assert!(!updated.get_definitions("bar").is_empty());

    std::fs::remove_file(file.abs_path()).unwrap();
    let refreshed = updated.update_all();
    assert!(refreshed.get_definitions("foo").is_empty());
    assert!(refreshed.get_definitions("bar").is_empty());
}
