// Declaration extraction for the Ruby analyzer.
// Covers ISC-3 (declarations + types), ISC-3b (`class << self`),
// ISC-4 (class reopening), ISC-9 (nested namespaces), ISC-11 (graceful parse).

mod common;

use brokk_bifrost::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, Language, ProjectFile, RubyAnalyzer, TestProject,
    TypeHierarchyProvider,
};
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

fn all_identifiers(analyzer: &RubyAnalyzer) -> BTreeSet<String> {
    analyzer
        .get_all_declarations()
        .into_iter()
        .map(|cu| cu.identifier().to_string())
        .collect()
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

    for accessor in ["@balance", "@owner", "@pin"] {
        assert!(
            decls
                .iter()
                .any(|cu| cu.is_field() && cu.identifier() == accessor),
            "missing attr backing field {accessor:?}",
        );
    }
    for accessor in ["balance", "owner", "pin="] {
        assert!(
            decls
                .iter()
                .any(|cu| cu.is_function() && cu.identifier() == accessor),
            "missing attr reader method {accessor:?}",
        );
    }
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_field() && cu.identifier() == "MAX_BALANCE")
    );
}

#[test]
fn ignores_dynamic_attr_and_alias_method_names() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "dynamic_accessors.rb",
            r#"class Account
  ATTR_NAME = :owner
  alias_name = :label

  attr_reader ATTR_NAME
  alias_method alias_name, :owner
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let decls = declarations(&analyzer, "dynamic_accessors.rb");

    assert!(
        decls
            .iter()
            .all(|cu| !(cu.is_function() && cu.identifier() == "ATTR_NAME")),
        "dynamic attr_reader name should not become a method declaration"
    );
    assert!(
        decls
            .iter()
            .all(|cu| !(cu.is_function() && cu.identifier() == "alias_name")),
        "dynamic alias_method name should not become a method declaration"
    );
}

#[test]
fn indexes_ruby_variable_fields_by_scope() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "invoice.rb",
            r#"class Invoice
  @last_build = nil
  @@sequence = 0

  def initialize
    @status = "draft"
  end

  def status
    @status
  end

  def self.build
    @last_build = new
    @@sequence += 1
  end

  def self.last_build
    @last_build
  end
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());

    let instance = analyzer.get_definitions("Invoice.@status");
    assert_eq!(1, instance.len(), "{instance:?}");
    assert!(instance[0].is_field());
    assert_eq!(instance[0].identifier(), "@status");

    let class_variable = analyzer.get_definitions("Invoice.@@sequence");
    assert_eq!(1, class_variable.len(), "{class_variable:?}");
    assert!(class_variable[0].is_field());
    assert_eq!(class_variable[0].identifier(), "@@sequence");

    let singleton = analyzer.get_definitions("Invoice.$singleton.@last_build");
    assert_eq!(1, singleton.len(), "{singleton:?}");
    assert!(singleton[0].is_field());
    assert_eq!(singleton[0].identifier(), "@last_build");
}

#[test]
fn indexes_ruby_variable_fields_from_compound_assignment() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "invoice.rb",
            r#"class Invoice
  def status
    @status ||= "draft"
  end

  def self.build
    @@sequence += 1
  end
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());

    let instance = analyzer.get_definitions("Invoice.@status");
    assert_eq!(1, instance.len(), "{instance:?}");
    assert!(instance[0].is_field());

    let class_variable = analyzer.get_definitions("Invoice.@@sequence");
    assert_eq!(1, class_variable.len(), "{class_variable:?}");
    assert!(class_variable[0].is_field());
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
fn explicit_update_removes_stale_declarations_after_file_edit() {
    let built = InlineTestProject::with_language(brokk_bifrost::Language::Ruby)
        .file(
            "app/service.rb",
            r#"
class LegacyService
  def old_call
  end
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());
    let service = built.file("app/service.rb");

    assert!(all_identifiers(&analyzer).contains("LegacyService"));
    assert!(all_identifiers(&analyzer).contains("old_call"));

    service
        .write(
            r#"
class CurrentService
  def new_call
  end
end
"#,
        )
        .unwrap();
    let updated = analyzer.update(&BTreeSet::from([service.clone()]));
    let identifiers = all_identifiers(&updated);

    assert!(!identifiers.contains("LegacyService"), "{identifiers:?}");
    assert!(!identifiers.contains("old_call"), "{identifiers:?}");
    assert!(identifiers.contains("CurrentService"), "{identifiers:?}");
    assert!(identifiers.contains("new_call"), "{identifiers:?}");
}

#[test]
fn update_all_rebuilds_ruby_declarations_imports_and_hierarchy_from_disk() {
    let built = InlineTestProject::with_language(brokk_bifrost::Language::Ruby)
        .file("lib/base.rb", "class Base\nend\n")
        .file("lib/auditable.rb", "module Auditable\nend\n")
        .file(
            "app/service.rb",
            r#"
require_relative "../lib/base"
require_relative "../lib/auditable"

class Service < Base
  include Auditable

  def call
  end
end
"#,
        )
        .build();
    let analyzer = RubyAnalyzer::new(built.project_dyn());
    let service_file = built.file("app/service.rb");

    let service = analyzer
        .get_definitions("Service")
        .into_iter()
        .next()
        .expect("initial Service declaration");
    let initial_ancestors: BTreeSet<_> = analyzer
        .get_direct_ancestors(&service)
        .iter()
        .map(|unit| unit.identifier().to_string())
        .collect();
    assert!(initial_ancestors.contains("Base"), "{initial_ancestors:?}");
    assert!(
        analyzer
            .imported_code_units_of(&service_file)
            .iter()
            .any(|unit| unit.identifier() == "Auditable")
    );

    built
        .file("lib/new_base.rb")
        .write("class NewBase\nend\n")
        .unwrap();
    service_file
        .write(
            r#"
require_relative "../lib/new_base"

class Service < NewBase
  def refreshed
  end
end
"#,
        )
        .unwrap();
    std::fs::remove_file(built.file("lib/base.rb").abs_path()).unwrap();
    std::fs::remove_file(built.file("lib/auditable.rb").abs_path()).unwrap();

    let updated = analyzer.update_all();
    let identifiers = all_identifiers(&updated);
    assert!(!identifiers.contains("Base"), "{identifiers:?}");
    assert!(!identifiers.contains("Auditable"), "{identifiers:?}");
    assert!(identifiers.contains("NewBase"), "{identifiers:?}");
    assert!(identifiers.contains("refreshed"), "{identifiers:?}");

    let service = updated
        .get_definitions("Service")
        .into_iter()
        .next()
        .expect("updated Service declaration");
    let updated_ancestors: BTreeSet<_> = updated
        .get_direct_ancestors(&service)
        .iter()
        .map(|unit| unit.identifier().to_string())
        .collect();
    assert!(
        updated_ancestors.contains("NewBase"),
        "{updated_ancestors:?}"
    );
    assert!(
        updated
            .imported_code_units_of(&service_file)
            .iter()
            .any(|unit| unit.identifier() == "NewBase")
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
