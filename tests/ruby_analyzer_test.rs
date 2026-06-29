// Declaration extraction for the Ruby analyzer.
// Covers ISC-3 (declarations + types), ISC-3b (`class << self`),
// ISC-4 (class reopening), ISC-9 (nested namespaces), ISC-11 (graceful parse).

mod common;

use brokk_bifrost::{CodeUnit, IAnalyzer, ProjectFile, RubyAnalyzer, TestProject};
use common::InlineTestProject;
use std::collections::BTreeSet;

fn analyzer() -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-ruby").unwrap(),
        brokk_bifrost::Language::Ruby,
    ))
}

fn file(analyzer: &RubyAnalyzer, rel: &str) -> ProjectFile {
    ProjectFile::new(analyzer.project().root().to_path_buf(), rel)
}

fn declarations(analyzer: &RubyAnalyzer, rel: &str) -> BTreeSet<CodeUnit> {
    analyzer.get_declarations(&file(analyzer, rel))
}

fn find<'a>(decls: &'a BTreeSet<CodeUnit>, identifier: &str) -> &'a CodeUnit {
    decls
        .iter()
        .find(|cu| cu.identifier() == identifier)
        .unwrap_or_else(|| panic!("no declaration with identifier {identifier:?}"))
}

#[test]
fn extracts_classes_methods_and_inheritance() {
    let analyzer = analyzer();
    let decls = declarations(&analyzer, "inheritance/simple.rb");

    let animal = find(&decls, "Animal");
    assert!(animal.is_class());
    assert_eq!(animal.fq_name(), "Animal");

    let dog = find(&decls, "Dog");
    assert!(dog.is_class());

    // Both classes define `speak`; identifiers resolve to the method name.
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_function() && cu.identifier() == "speak")
    );
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_function() && cu.identifier() == "initialize")
    );
}

#[test]
fn nested_namespaces_build_qualified_names() {
    let analyzer = analyzer();
    let decls = declarations(&analyzer, "namespaced.rb");

    let gamma = find(&decls, "Gamma");
    assert!(gamma.is_class());
    // module Alpha; module Beta; class Gamma -> Alpha$Beta$Gamma
    assert_eq!(gamma.fq_name(), "Alpha$Beta$Gamma");

    let hello = decls
        .iter()
        .find(|cu| cu.is_function() && cu.identifier() == "hello")
        .expect("hello method");
    assert_eq!(hello.fq_name(), "Alpha$Beta$Gamma.hello");

    // class-level constant is a field
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_field() && cu.identifier() == "GREETING")
    );
    // `def self.build` singleton method is captured
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_function() && cu.identifier() == "build")
    );
}

#[test]
fn captures_attr_macros_and_constants() {
    let analyzer = analyzer();
    let decls = declarations(&analyzer, "accessors.rb");

    for accessor in ["balance", "owner", "pin"] {
        assert!(
            decls
                .iter()
                .any(|cu| cu.is_field() && cu.identifier() == accessor),
            "missing attr field {accessor:?}",
        );
    }
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_field() && cu.identifier() == "MAX_BALANCE")
    );
}

#[test]
fn singleton_class_methods_attach_to_enclosing_type() {
    let analyzer = analyzer();
    let decls = declarations(&analyzer, "singleton.rb");

    // `def self.default`, `class << self; def configure`, and `def log`
    for method in ["default", "configure", "log"] {
        assert!(
            decls
                .iter()
                .any(|cu| cu.is_function() && cu.identifier() == method),
            "missing method {method:?}",
        );
    }
}

#[test]
fn modules_are_modules() {
    let analyzer = analyzer();
    let decls = declarations(&analyzer, "inheritance/mixins.rb");
    let walkable = find(&decls, "Walkable");
    assert!(walkable.is_module());
}

#[test]
fn class_reopening_merges_across_files() {
    let analyzer = analyzer();
    // Same `Config` fq_name declared in two files; definitions returns both
    // method fragments.
    let methods: BTreeSet<String> = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|cu| cu.is_function())
        .filter(|cu| cu.fq_name().starts_with("Config."))
        .map(|cu| cu.identifier().to_string())
        .collect();
    assert!(methods.contains("initial_setting"), "got {methods:?}");
    assert!(methods.contains("added_later"), "got {methods:?}");

    let config_defs = analyzer.get_definitions("Config");
    assert!(
        config_defs.len() >= 2,
        "expected Config defined in >=2 files, got {}",
        config_defs.len()
    );
}

#[test]
fn syntax_error_file_does_not_panic() {
    let analyzer = analyzer();
    // Should analyze without panicking and surface parse errors.
    let _ = declarations(&analyzer, "syntax_error.rb");
    let errors = analyzer.parse_errors(&file(&analyzer, "syntax_error.rb"));
    assert!(errors.is_some());
}

#[test]
fn empty_file_yields_no_declarations() {
    let analyzer = analyzer();
    assert!(declarations(&analyzer, "empty.rb").is_empty());
}

#[test]
fn deeply_nested_input_does_not_overflow_the_stack() {
    // The visitor must walk arbitrarily deep nesting without native recursion
    // overflowing the stack (analyzers must never crash on malformed input).
    // ~5000 deep comfortably exceeds the recursion depth that overflowed the
    // previous implementation on a default test-thread stack.
    let depth = 5_000;
    let mut source = String::new();
    for level in 0..depth {
        source.push_str(&format!("module M{level}\n"));
    }
    source.push_str("end\n".repeat(depth).as_str());

    let built = InlineTestProject::with_language(brokk_bifrost::Language::Ruby)
        .file("deep.rb", source)
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());
    // Completing analysis without aborting the process is the assertion.
    let _ = analyzer.get_all_declarations();
}

#[test]
fn records_method_signature_parameter_metadata() {
    let built = InlineTestProject::with_language(brokk_bifrost::Language::Ruby)
        .file(
            "service.rb",
            r#"class Service
  def configure(left, right = default_value, *rest, key:, **opts, &block)
  end
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());
    let method = analyzer
        .get_definitions("Service.configure")
        .into_iter()
        .next()
        .expect("configure definition");
    let metadata = analyzer.signature_metadata(&method);

    assert_eq!(metadata.len(), 1, "metadata: {metadata:?}");
    let label = metadata[0].label();
    assert!(label.contains("def configure"), "label: {label}");
    let parameter_labels: Vec<&str> = metadata[0]
        .parameters()
        .iter()
        .map(|parameter| {
            let start = parameter.start_byte();
            let end = parameter.end_byte();
            assert_eq!(
                &label[start..end],
                parameter.label(),
                "bad offset for {parameter:?} in {label}"
            );
            parameter.label()
        })
        .collect();

    assert_eq!(
        parameter_labels,
        vec!["left", "right", "rest", "key", "opts", "block"]
    );
}
