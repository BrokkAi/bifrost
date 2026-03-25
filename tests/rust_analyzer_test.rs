use brokk_analyzer::{
    CodeUnit, IAnalyzer, Language, Project, ProjectFile, RustAnalyzer, TestProject,
};
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

fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

#[test]
fn test_module_class_and_function_code_units() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
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
    )]));

    assert!(!analyzer.get_definitions("utils").is_empty());
    assert!(!analyzer.get_definitions("Point").is_empty());
    assert!(!analyzer.get_definitions("Drawable").is_empty());
    assert!(!analyzer.get_definitions("Color").is_empty());
    assert!(!analyzer.get_definitions("distance").is_empty());
    assert!(!analyzer.get_definitions("Point.new").is_empty());
    assert!(!analyzer.get_definitions("utils.helper").is_empty());
}

#[test]
fn test_impl_target_extraction_variants() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "lib.rs",
        r#"
        pub struct MyStruct;

        pub trait MyTrait {
            fn do_something(&self);
        }

        impl MyTrait for MyStruct {
            fn do_something(&self) {}
        }

        impl<T> MyTrait for &T {
            fn do_something(&self) {}
        }

        mod ast {
            pub struct StringLike<'a> {
                value: &'a str,
            }
        }

        pub trait StringLikeExtensions {
            fn is_empty(&self) -> bool;
        }

        impl<'a> StringLikeExtensions for ast::StringLike<'a> {
            fn is_empty(&self) -> bool {
                false
            }
        }

        impl<T> MyTrait for &Vec<Box<T>> {
            fn do_something(&self) {}
        }

        pub trait Deref {
            fn deref(&self);
        }

        impl<T> Deref for *const T {
            fn deref(&self) {}
        }

        impl<T> Deref for *mut T {
            fn deref(&self) {}
        }

        pub trait SliceTrait {
            fn len(&self) -> usize;
        }

        impl<T> SliceTrait for [T] {
            fn len(&self) -> usize { 0 }
        }
        "#,
    )]));

    assert!(!analyzer.get_definitions("MyStruct").is_empty());
    assert!(!analyzer.get_definitions("MyStruct.do_something").is_empty());
    assert!(!analyzer.get_definitions("T.do_something").is_empty());
    assert!(!analyzer.get_definitions("StringLike").is_empty());
    assert!(!analyzer.get_definitions("StringLike.is_empty").is_empty());
    assert!(!analyzer.get_definitions("Vec.do_something").is_empty());
    assert!(!analyzer.get_definitions("T.deref").is_empty());
    assert!(!analyzer.get_definitions("T.len").is_empty());
}

#[test]
fn test_impl_for_self_type() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "lib.rs",
        r#"
        pub struct Counter {
            value: i32,
        }

        impl Counter {
            pub fn new() -> Self {
                Self { value: 0 }
            }

            pub fn increment(&mut self) -> &mut Self {
                self.value += 1;
                self
            }
        }

        pub trait Builder {
            fn build(self) -> Self;
        }

        impl Builder for Counter {
            fn build(self) -> Self {
                self
            }
        }
        "#,
    )]));

    assert!(!analyzer.get_definitions("Counter").is_empty());
    assert!(!analyzer.get_definitions("Counter.new").is_empty());
    assert!(!analyzer.get_definitions("Counter.increment").is_empty());
    assert!(!analyzer.get_definitions("Counter.build").is_empty());
}

#[test]
fn test_nested_modules_with_test_function() {
    let project = rust_project(&[(
        "nested_test.rs",
        r#"
        mod outer {
            mod inner {
                #[test]
                fn my_test() {
                    assert!(true);
                }
            }

            pub fn outer_helper() -> i32 {
                42
            }
        }

        pub fn top_level() {}
        "#,
    )]);
    let analyzer = RustAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "nested_test.rs");

    assert!(!analyzer.get_definitions("outer").is_empty());
    assert!(!analyzer.get_definitions("outer.inner").is_empty());
    assert!(!analyzer.get_definitions("outer.inner.my_test").is_empty());
    assert!(!analyzer.get_definitions("outer.outer_helper").is_empty());
    assert!(!analyzer.get_definitions("top_level").is_empty());
    assert!(analyzer.contains_tests(&file));
}

#[test]
fn test_field_skeletons() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "lib.rs",
        r#"
        pub struct Point {
            pub x: i32,
            y: i32,
        }

        pub const ORIGIN: i32 = 0;
        static COUNT: i32 = 1;

        pub enum E {
            A,
            B(u32),
            C { x: i32 },
        }

        impl Point {
            pub const ID: i32 = 1;
        }
        "#,
    )]));

    let point = definition(&analyzer, "Point");
    let point_skeleton = analyzer.get_skeleton(&point).unwrap();
    assert!(point_skeleton.contains("pub x: i32"));
    assert!(point_skeleton.contains("y: i32"));

    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "_module_.ORIGIN"))
            .unwrap()
            .contains("pub const ORIGIN: i32 = 0")
    );
    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "_module_.COUNT"))
            .unwrap()
            .contains("static COUNT: i32 = 1")
    );

    let enum_skeleton = analyzer.get_skeleton(&definition(&analyzer, "E")).unwrap();
    assert!(enum_skeleton.contains("enum E"));
    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "E.A"))
            .unwrap()
            .contains("A")
    );
    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "E.B"))
            .unwrap()
            .contains("B")
    );
    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "E.B"))
            .unwrap()
            .contains("u32")
    );
    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "E.C"))
            .unwrap()
            .contains("C")
    );
    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "E.C"))
            .unwrap()
            .contains("x: i32")
    );
    assert!(
        analyzer
            .get_skeleton(&definition(&analyzer, "Point.ID"))
            .unwrap()
            .contains("pub const ID: i32 = 1;")
    );
}
