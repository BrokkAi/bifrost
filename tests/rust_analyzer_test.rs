use brokk_bifrost::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, Project, ProjectFile, RustAnalyzer, TestProject,
};
use tempfile::tempdir;

mod common;
use common::InlineTestProject;

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
fn rust_identifier_collection_handles_deep_valid_type_on_small_stack() {
    let depth = 1_024;
    let mut source = String::from("struct Wrap<T>(T);\nstruct Leaf;\ntype Deep = ");
    source.push_str(&"Wrap<".repeat(depth));
    source.push_str("Leaf");
    source.push_str(&">".repeat(depth));
    source.push_str(";\n");

    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "struct Marker;\n")
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let identifiers = std::thread::Builder::new()
        .name("deep-rust-identifier-collection".to_string())
        .stack_size(256 * 1024)
        .spawn(move || analyzer.extract_type_identifiers(&source))
        .expect("spawn deep Rust identifier collector")
        .join()
        .expect("deep Rust identifier collector must not overflow");

    assert!(identifiers.contains("Deep"));
    assert!(identifiers.contains("Wrap"));
    assert!(identifiers.contains("Leaf"));
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
    assert!(analyzer.get_definitions("T").is_empty());
    assert!(!analyzer.get_definitions("T.do_something").is_empty());
    assert!(analyzer.get_definitions("StringLike").is_empty());
    assert!(!analyzer.get_definitions("ast.StringLike").is_empty());
    assert!(
        !analyzer
            .get_definitions("ast.StringLike.is_empty")
            .is_empty()
    );
    assert!(analyzer.get_definitions("Vec").is_empty());
    assert!(!analyzer.get_definitions("Vec.do_something").is_empty());
    assert!(!analyzer.get_definitions("T.deref").is_empty());
    assert!(!analyzer.get_definitions("T.len").is_empty());
}

#[test]
fn rust_impl_members_use_real_owner_identity_without_publishing_phantom_types() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/model.rs",
            r#"
pub struct Writer;
"#,
        )
        .file(
            "src/local.rs",
            r#"
pub struct Option;
"#,
        )
        .file(
            "src/impls.rs",
            r#"
// Impl owner members stay indexed without nominal stand-ins.
use crate::model::Writer;
use crate::model as m;
use std::option::Option;

trait LocalTrait {
    fn act(&self);
    fn act_s(&self);
    fn act_f(&self);
    fn act_t(&self);
}

impl Writer {
    fn write(&self) {}
}

impl LocalTrait for m::Writer {
    fn act(&self) {}
}

impl LocalTrait for Option<u8> {
    fn act(&self) {}
}

impl<S> LocalTrait for S {
    fn act_s(&self) {}
}

impl<F> LocalTrait for F {
    fn act_f(&self) {}
}

impl<T> LocalTrait for T {
    fn act_t(&self) {}
}

impl LocalTrait for Self {
    fn act(&self) {}
}
"#,
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let writer = definition(&analyzer, "model.Writer");
    assert_eq!(writer.source().rel_path().to_string_lossy(), "src/model.rs");
    let writer_method = definition(&analyzer, "model.Writer.write");
    assert_eq!(
        writer_method.source().rel_path().to_string_lossy(),
        "src/impls.rs"
    );
    let namespace_writer_method = definition(&analyzer, "model.Writer.act");
    assert_eq!(
        namespace_writer_method
            .source()
            .rel_path()
            .to_string_lossy(),
        "src/impls.rs"
    );

    assert!(analyzer.get_definitions("impls.Writer").is_empty());
    assert!(analyzer.get_definitions("impls.m.Writer").is_empty());
    assert!(analyzer.get_definitions("m.Writer.act").is_empty());
    assert!(analyzer.get_definitions("impls.Option").is_empty());
    assert!(analyzer.get_definitions("impls.S").is_empty());
    assert!(analyzer.get_definitions("impls.F").is_empty());
    assert!(analyzer.get_definitions("impls.T").is_empty());
    assert!(analyzer.get_definitions("impls.Self").is_empty());
    assert!(analyzer.get_definitions("std.option.Option").is_empty());

    assert!(!analyzer.get_definitions("std.option.Option.act").is_empty());
    assert!(!analyzer.get_definitions("impls.S.act_s").is_empty());
    assert!(!analyzer.get_definitions("impls.F.act_f").is_empty());
    assert!(!analyzer.get_definitions("impls.T.act_t").is_empty());
    assert!(!analyzer.get_definitions("impls.Self.act").is_empty());
    assert!(analyzer.get_definitions("local.Option.act").is_empty());
    assert_eq!(analyzer.get_definitions("local.Option").len(), 1);
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
fn test_wrapped_macro_rules_declaration_is_indexed_as_macro() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/macros/join.rs",
            r#"
macro_rules! doc {
    ($join:item) => { $join };
}

#[cfg(doc)]
doc! {macro_rules! join {
    ($(biased;)? $($future:expr),*) => { unimplemented!() }
}}

#[cfg(not(doc))]
doc! {macro_rules! join {
    ( $($e:expr),+ $(,)? ) => {{
        let _ = ($($e),+);
    }};
}}
"#,
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let file = project.file("src/macros/join.rs");

    let declarations = analyzer.get_declarations(&file);
    let join = declarations
        .iter()
        .find(|unit| unit.identifier() == "join")
        .unwrap_or_else(|| panic!("missing join macro in {declarations:#?}"));
    assert_eq!(CodeUnitType::Macro, join.kind());
    assert_eq!("macros.join.join", join.fq_name());
    assert_eq!(2, analyzer.ranges(join).len());
    assert_eq!(
        1,
        analyzer
            .get_top_level_declarations(&file)
            .iter()
            .filter(|unit| unit.fq_name() == "macros.join.join")
            .count()
    );
}

#[test]
fn test_inert_macro_rules_tokens_are_not_indexed_as_macros() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/macros/inert.rs",
            r#"
macro_rules! drop_tokens {
    ($item:item) => {};
}

drop_tokens! { macro_rules! fake {
    () => {};
}}

stringify! { macro_rules! also_fake {
    () => {};
}}
"#,
        )
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let file = project.file("src/macros/inert.rs");

    let declarations = analyzer.get_declarations(&file);
    assert!(
        declarations
            .iter()
            .all(|unit| unit.identifier() != "fake" && unit.identifier() != "also_fake"),
        "{declarations:#?}"
    );
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

#[test]
fn test_signature_metadata_keeps_rust_pattern_parameters() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "lib.rs",
        r#"
        pub fn consume((left, right): (i32, i32), _: bool) -> i32 {
            left + right
        }
        "#,
    )]));
    let function = definition(&analyzer, "consume");
    let metadata = analyzer
        .signature_metadata(&function)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing signature metadata for {}", function.fq_name()));
    let labels: Vec<_> = metadata
        .parameters()
        .iter()
        .map(|parameter| &metadata.label()[parameter.start_byte()..parameter.end_byte()])
        .collect();
    assert_eq!(vec!["(left, right)", "_"], labels);
}
