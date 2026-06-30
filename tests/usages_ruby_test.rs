// Ruby usage discovery via `RubyUsageGraphStrategy`. Ruby's dynamic dispatch
// only permits precise graph hits when parser/analyzer facts prove the receiver
// or constant target. These tests pin structured Ruby usage discovery.

mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{
    CandidateFileProvider, FuzzyResult, ImportGraphCandidateProvider, UsageFinder,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ProjectFile, RubyAnalyzer, TestProject};
use common::{InlineTestProject, ruby_analyzer_with_files};

fn analyzer() -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(
        std::fs::canonicalize("tests/fixtures/usage-graph-ruby").unwrap(),
        brokk_bifrost::Language::Ruby,
    ))
}

fn definition(analyzer: &RubyAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn hit_enclosing_ids(analyzer: &RubyAnalyzer, fq_name: &str) -> Vec<String> {
    let target = definition(analyzer, fq_name);
    analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed")
        .iter()
        .map(|hit| hit.enclosing.identifier().to_string())
        .collect()
}

fn hit_source_lines(
    hits: &std::collections::BTreeSet<brokk_bifrost::usages::UsageHit>,
) -> Vec<String> {
    hits.iter()
        .map(|hit| {
            let source = std::fs::read_to_string(hit.file.abs_path()).expect("read hit file");
            source
                .lines()
                .nth(hit.line - 1)
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .collect()
}

fn hit_texts(hits: &std::collections::BTreeSet<brokk_bifrost::usages::UsageHit>) -> Vec<String> {
    hits.iter()
        .map(|hit| {
            let source = std::fs::read_to_string(hit.file.abs_path()).expect("read hit file");
            source
                .get(hit.start_offset..hit.end_offset)
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

struct FixedCandidateProvider {
    files: HashSet<ProjectFile>,
}

impl CandidateFileProvider for FixedCandidateProvider {
    fn find_candidates(
        &self,
        _target: &CodeUnit,
        _analyzer: &dyn IAnalyzer,
    ) -> HashSet<ProjectFile> {
        self.files.clone()
    }
}

#[test]
fn finds_cross_file_method_usage() {
    let analyzer = analyzer();
    let target = definition(&analyzer, "Greeter.greet");

    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    // The only call site is App#run in app.rb.
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "run"),
        "expected Greeter#greet usage inside App#run, got {:?}",
        hits.iter()
            .map(|h| h.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn finds_method_usage_through_a_mixin() {
    let analyzer = analyzer();
    // `log` is defined on module Loggable and called inside Service (which
    // includes Loggable). Name-based resolution finds both call sites.
    let target = definition(&analyzer, "Loggable.log");

    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let enclosing: Vec<String> = hits
        .iter()
        .map(|h| h.enclosing.identifier().to_string())
        .collect();
    assert!(enclosing.iter().any(|id| id == "work"), "got {enclosing:?}");
    assert!(
        enclosing.iter().any(|id| id == "retry_work"),
        "got {enclosing:?}"
    );
}

#[test]
fn does_not_report_the_declaration_as_a_usage() {
    let analyzer = analyzer();
    let target = definition(&analyzer, "Greeter.greet");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    // The `def greet` declaration itself must not be counted as a usage.
    assert!(hits.iter().all(|hit| hit.enclosing.identifier() != "greet"));
}

#[test]
fn import_graph_candidates_include_indirect_ruby_require_importers() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "app/services/user_service"

class App
  def run
    User.build
  end
end
"#,
        ),
        (
            "app/services/user_service.rb",
            r#"
require "app/models/user"

class UserService
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        ),
    ]);
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 100, 100);
    assert!(
        query.candidate_files.contains(&ProjectFile::new(
            project.root().to_path_buf(),
            "app/main.rb"
        )),
        "expected indirect importer to be an import-graph candidate, got {:?}",
        query.candidate_files
    );
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "run"),
        "expected User.build usage inside App#run, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn resolves_constant_usages_through_project_local_require_visibility() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "app/models/user"

class App
  def run
    User
  end
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
end
"#,
        ),
        (
            "app/other.rb",
            r#"
class Other
  def run
    User
  end
end
"#,
        ),
    ]);

    let target = definition(&analyzer, "User");
    let provider = FixedCandidateProvider {
        files: [project.file("app/main.rb"), project.file("app/other.rb")]
            .into_iter()
            .collect(),
    };
    let hits = UsageFinder::new()
        .query_with_provider(&analyzer, &[target], Some(&provider), 100, 100)
        .result
        .into_either()
        .expect("usage lookup should succeed");
    let enclosing: Vec<String> = hits.iter().map(|hit| hit.enclosing.fq_name()).collect();

    assert!(
        enclosing.iter().any(|name| name == "App.run"),
        "{enclosing:?}"
    );
    assert!(
        enclosing.iter().all(|name| name != "Other.run"),
        "{enclosing:?}"
    );
}

#[test]
fn resolves_relative_qualified_constants_through_lexical_namespace() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/models.rb",
        r#"
module A
  module B
    class C
    end
  end

  class App
    def run
      B::C
    end
  end
end

module Other
  module B
    class C
    end
  end
end
"#,
    )]);

    let target = definition(&analyzer, "A$B$C");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let enclosing: Vec<String> = hits.iter().map(|hit| hit.enclosing.fq_name()).collect();

    assert!(
        enclosing.iter().any(|name| name == "A$App.run"),
        "{enclosing:?}"
    );
}

#[test]
fn reports_terminal_class_segment_for_required_qualified_construction() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/report.rb",
            r#"
require_relative "../lib/billing/invoice"

module Reports
  class InvoiceReport
    def render
      invoice = Billing::Invoice.build
    end
  end
end
"#,
        ),
        (
            "lib/billing/invoice.rb",
            r#"
module Billing
  class Invoice
    def self.build
      new
    end
  end
end
"#,
        ),
    ]);

    let target = definition(&analyzer, "Billing$Invoice");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(
        lines
            .iter()
            .any(|line| line == "invoice = Billing::Invoice.build"),
        "{lines:?}"
    );
    assert!(texts.iter().any(|text| text == "Invoice"), "{texts:?}");
    assert!(
        !texts.iter().any(|text| text == "Billing::Invoice"),
        "{texts:?}"
    );
}

#[test]
fn reports_terminal_nested_constant_segment_from_lexical_namespace() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "lib/billing/invoice.rb",
            r#"
require_relative "money"

module Billing
  class Invoice
    DEFAULT_CURRENCY = Money::Currency.new("USD")
  end
end
"#,
        ),
        (
            "lib/billing/money.rb",
            r#"
module Billing
  module Money
    class Currency
    end
  end
end
"#,
        ),
    ]);

    let target = definition(&analyzer, "Billing$Money$Currency");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(
        lines
            .iter()
            .any(|line| line == "DEFAULT_CURRENCY = Money::Currency.new(\"USD\")"),
        "{lines:?}"
    );
    assert!(texts.iter().any(|text| text == "Currency"), "{texts:?}");
    assert!(
        !texts.iter().any(|text| text == "Money::Currency"),
        "{texts:?}"
    );
}

#[test]
fn resolves_namespaced_class_constant_field_usages() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/report.rb",
            r#"require_relative "../lib/billing/invoice"

module Reports
  class InvoiceReport
    def render
      Billing::Invoice::DEFAULT_CURRENCY
      Other::Invoice::DEFAULT_CURRENCY
    end
  end
end
"#,
        ),
        (
            "lib/billing/invoice.rb",
            r#"module Billing
  class Invoice
    DEFAULT_CURRENCY = Money::Currency.new("USD")
  end
end
"#,
        ),
        (
            "lib/other/invoice.rb",
            r#"module Other
  class Invoice
    DEFAULT_CURRENCY = "EUR"
  end
end
"#,
        ),
    ]);

    let target = definition(&analyzer, "Billing$Invoice.DEFAULT_CURRENCY");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(
        lines
            .iter()
            .any(|line| line == "Billing::Invoice::DEFAULT_CURRENCY"),
        "{lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line == "Other::Invoice::DEFAULT_CURRENCY"),
        "{lines:?}"
    );
    assert!(
        texts.iter().any(|text| text == "DEFAULT_CURRENCY"),
        "{texts:?}"
    );
    assert!(
        !texts
            .iter()
            .any(|text| text == "Billing::Invoice::DEFAULT_CURRENCY"),
        "{texts:?}"
    );
}

#[test]
fn resolves_absolute_namespaced_class_constant_field_usages() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/report.rb",
        r#"module Billing
  class Invoice
    DEFAULT_CURRENCY = "USD"
  end
end

module Reports
  module Billing
    class Invoice
      DEFAULT_CURRENCY = "ZAR"
    end
  end

  class InvoiceReport
    def render
      ::Billing::Invoice::DEFAULT_CURRENCY
    end
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Billing$Invoice.DEFAULT_CURRENCY");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(
        lines
            .iter()
            .any(|line| line == "::Billing::Invoice::DEFAULT_CURRENCY"),
        "{lines:?}"
    );
}

#[test]
fn resolves_ruby_instance_variable_field_usages() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "lib/billing/invoice.rb",
        r#"class Invoice
  def initialize
    @status = "draft"
  end

  def status
    @status
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Invoice.@status");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(lines.iter().any(|line| line == "@status"), "{lines:?}");
    assert!(texts.iter().all(|text| text == "@status"), "{texts:?}");
}

#[test]
fn resolves_ruby_class_variable_field_usages() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "lib/billing/invoice.rb",
        r#"class Invoice
  @@sequence = 0

  def self.build
    @@sequence += 1
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Invoice.@@sequence");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(
        lines.iter().any(|line| line == "@@sequence += 1"),
        "{lines:?}"
    );
    assert!(texts.iter().all(|text| text == "@@sequence"), "{texts:?}");
}

#[test]
fn resolves_ruby_class_instance_variable_field_usages() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "lib/billing/invoice.rb",
        r#"class Invoice
  @last_build = nil

  def self.build
    @last_build = new
  end

  def self.last_build
    @last_build
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Invoice.$singleton.@last_build");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(
        lines.iter().any(|line| line == "@last_build = new"),
        "{lines:?}"
    );
    assert!(lines.iter().any(|line| line == "@last_build"), "{lines:?}");
    assert!(texts.iter().all(|text| text == "@last_build"), "{texts:?}");
}

#[test]
fn indexes_absolute_namespaced_constant_assignment_as_top_level_field() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/report.rb",
        r#"module Billing
  class Invoice
  end
end

module Reports
  ::Billing::Invoice::DEFAULT_CURRENCY = "USD"
end
"#,
    )]);

    let definitions = analyzer.get_definitions("Billing$Invoice.DEFAULT_CURRENCY");

    assert_eq!(1, definitions.len(), "{definitions:?}");
}

#[test]
fn reports_superclass_reference_before_entering_declared_class_scope() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "lib/billing/invoice.rb",
        r#"
module Billing
  class Record
  end

  class Invoice < Record
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Billing$Record");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(
        lines.iter().any(|line| line == "class Invoice < Record"),
        "{lines:?}"
    );
    assert!(texts.iter().any(|text| text == "Record"), "{texts:?}");
}

#[test]
fn resolves_explicit_receiver_from_local_construction_without_same_name_false_positives() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  def save
  end
end

class Account
  def save
  end
end

class App
  def run
    user = User.new
    user.save

    account = Account.new
    account.save
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User.save");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let snippets: Vec<String> = hits.iter().map(|hit| hit.snippet.clone()).collect();

    assert!(snippets.iter().any(|snippet| snippet.contains("user.save")));
    assert!(
        !snippets
            .iter()
            .any(|snippet| snippet.contains("account.save"))
    );
}

#[test]
fn reports_class_constant_usages_when_constant_is_call_receiver() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  def self.find
  end
end

class App
  def run
    User.find
    User.new
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(lines.iter().any(|line| line == "User.find"), "{lines:?}");
    assert!(lines.iter().any(|line| line == "User.new"), "{lines:?}");
}

#[test]
fn resolves_bare_calls_through_enclosing_class_and_superclass() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/service.rb",
        r#"
class BaseService
  def audit
  end
end

class UserService < BaseService
  def run
    audit
  end
end
"#,
    )]);

    let enclosing = hit_enclosing_ids(&analyzer, "BaseService.audit");
    assert!(enclosing.iter().any(|id| id == "run"), "{enclosing:?}");
}

#[test]
fn ruby_usage_resolves_top_level_bare_method_call() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/report.rb",
        r#"
module Reports
  class InvoiceReport
    def render
      normalize_total(19)
    end
  end
end

def render_shadow(normalize_total)
  normalize_total
end

def normalize_total(value = 0)
  value.round
end
"#,
    )]);

    let target = definition(&analyzer, "normalize_total");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let enclosing: Vec<String> = hits.iter().map(|hit| hit.enclosing.fq_name()).collect();

    assert!(
        lines.iter().any(|line| line == "normalize_total(19)"),
        "{lines:?}"
    );
    assert!(
        !enclosing.iter().any(|name| name == "normalize_total"),
        "{enclosing:?}"
    );
    assert!(
        !enclosing.iter().any(|name| name == "render_shadow"),
        "{enclosing:?}"
    );
}

#[test]
fn resolves_bare_calls_inside_singleton_class_as_class_method_calls() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  class << self
    def run
      build
      self.build
    end

    def build
    end
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User.build");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(lines.iter().any(|line| line == "build"), "{lines:?}");
    assert!(lines.iter().any(|line| line == "self.build"), "{lines:?}");
}

#[test]
fn distinguishes_include_and_extend_receiver_polarity() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
module Findable
  def find
  end
end

module Auditable
  def audit
  end
end

class User
  extend Findable
  include Auditable
end

class App
  def run
    User.find
    User.new.audit
    User.audit
    User.new.find
  end
end
"#,
    )]);

    let find = definition(&analyzer, "Findable.find");
    let find_hits = analyzer
        .find_usages(&[find])
        .into_either()
        .expect("find lookup should succeed");
    let find_lines = hit_source_lines(&find_hits);
    assert!(find_lines.iter().any(|line| line == "User.find"));
    assert!(
        !find_lines.iter().any(|line| line == "User.new.find"),
        "{find_lines:?}"
    );

    let audit = definition(&analyzer, "Auditable.audit");
    let audit_hits = analyzer
        .find_usages(&[audit])
        .into_either()
        .expect("audit lookup should succeed");
    let audit_lines = hit_source_lines(&audit_hits);
    assert!(audit_lines.iter().any(|line| line == "User.new.audit"));
    assert!(
        !audit_lines.iter().any(|line| line == "User.audit"),
        "{audit_lines:?}"
    );
}

#[test]
fn resolves_build_receiver_include_and_prepend_usage_precedence() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/report.rb",
            r#"require_relative "../lib/billing/invoice"

module Reports
  class InvoiceReport
    def render
      invoice = Billing::Invoice.build
      invoice.audit
      invoice.total_label
    end
  end
end
"#,
        ),
        (
            "lib/billing/invoice.rb",
            r#"module Billing
  module Auditable
    def audit
    end
  end

  module Formatting
    def total_label
    end
  end

  class Invoice
    include Auditable
    prepend Formatting

    def total_label
    end

    def self.build
      @last_build = Invoice.new
    end
  end
end
"#,
        ),
    ]);

    let audit = definition(&analyzer, "Billing$Auditable.audit");
    let audit_hits = analyzer
        .find_usages(&[audit])
        .into_either()
        .expect("audit lookup should succeed");
    let audit_lines = hit_source_lines(&audit_hits);
    assert!(
        audit_lines.iter().any(|line| line == "invoice.audit"),
        "{audit_lines:?}"
    );

    let formatting = definition(&analyzer, "Billing$Formatting.total_label");
    let formatting_hits = analyzer
        .find_usages(&[formatting])
        .into_either()
        .expect("formatting lookup should succeed");
    let formatting_lines = hit_source_lines(&formatting_hits);
    assert!(
        formatting_lines
            .iter()
            .any(|line| line == "invoice.total_label"),
        "{formatting_lines:?}"
    );

    let invoice_total_label = definition(&analyzer, "Billing$Invoice.total_label");
    let invoice_hits = analyzer
        .find_usages(&[invoice_total_label])
        .into_either()
        .expect("shadowed class method lookup should succeed");
    let invoice_lines = hit_source_lines(&invoice_hits);
    assert!(
        !invoice_lines
            .iter()
            .any(|line| line == "invoice.total_label"),
        "{invoice_lines:?}"
    );
}

#[test]
fn resolves_inherited_self_new_factory_receiver_usage() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app.rb",
        r#"module Auditable
  def audit
  end
end

class Base
  def self.build
    self.new
  end
end

class Child < Base
  include Auditable
end

class App
  def run
    Child.build.audit
  end
end
"#,
    )]);

    let audit = definition(&analyzer, "Auditable.audit");
    let hits = analyzer
        .find_usages(&[audit])
        .into_either()
        .expect("audit lookup should succeed");
    let lines = hit_source_lines(&hits);
    assert!(
        lines.iter().any(|line| line == "Child.build.audit"),
        "{lines:?}"
    );
}

#[test]
fn recursive_factory_receiver_fails_closed_for_usages() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app.rb",
        r#"class Thing
  def self.build
    Thing.build.new
  end

  def audit
  end
end

class App
  def run
    Thing.build.audit
  end
end
"#,
    )]);

    let audit = definition(&analyzer, "Thing.audit");
    let query = UsageFinder::new().query(&analyzer, &[audit], 100, 100);
    assert!(
        matches!(query.result, FuzzyResult::Failure { .. }),
        "recursive factory inference should not invent a hit: {:?}",
        query.result
    );
}

#[test]
fn resolves_multi_argument_mixin_usage_precedence() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app.rb",
        r#"module A
  def audit
  end

  def label
  end
end

module B
  def audit
  end

  def label
  end
end

class Included
  include A, B
end

class Prepended
  prepend A, B

  def label
  end
end

class App
  def run
    Included.new.audit
    Prepended.new.label
  end
end
"#,
    )]);

    let a_audit = definition(&analyzer, "A.audit");
    let a_audit_hits = analyzer
        .find_usages(&[a_audit])
        .into_either()
        .expect("A.audit lookup should succeed");
    let a_audit_lines = hit_source_lines(&a_audit_hits);
    assert!(
        a_audit_lines
            .iter()
            .any(|line| line == "Included.new.audit"),
        "{a_audit_lines:?}"
    );

    let b_audit = definition(&analyzer, "B.audit");
    let b_audit_hits = analyzer
        .find_usages(&[b_audit])
        .into_either()
        .expect("B.audit lookup should succeed");
    let b_audit_lines = hit_source_lines(&b_audit_hits);
    assert!(
        !b_audit_lines
            .iter()
            .any(|line| line == "Included.new.audit"),
        "{b_audit_lines:?}"
    );

    let a_label = definition(&analyzer, "A.label");
    let a_label_hits = analyzer
        .find_usages(&[a_label])
        .into_either()
        .expect("A.label lookup should succeed");
    let a_label_lines = hit_source_lines(&a_label_hits);
    assert!(
        a_label_lines
            .iter()
            .any(|line| line == "Prepended.new.label"),
        "{a_label_lines:?}"
    );
}

#[test]
fn reports_unsafe_inference_for_only_dynamic_or_untyped_same_name_calls() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  def save
  end
end

class App
  def run(obj)
    obj.save
    send(:save)
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User.save");
    let query = UsageFinder::new().query(&analyzer, &[target], 100, 100);
    let diagnostic = query.graph_failure.expect("graph failure diagnostic");

    assert_eq!("RubyUsageGraphStrategy", diagnostic.strategy);
    assert_eq!("unsafe_inference", diagnostic.reason_kind);
    assert!(
        matches!(query.result, FuzzyResult::Failure { .. }),
        "expected failure, got {:?}",
        query.result
    );
}

#[test]
fn ruby_usage_graph_includes_rails_autoload_consumers() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "Gemfile",
            r#"source "https://rubygems.org"

gem "rails"
"#,
        ),
        (
            "app/controllers/users_controller.rb",
            r#"
class UsersController
  def show
    User.build
  end
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        ),
    ]);
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 100, 100);
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "show"),
        "expected User.build usage inside UsersController#show, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn zeitwerk_candidates_are_filtered_before_usage_file_cap() {
    let mut builder = InlineTestProject::with_language(Language::Ruby)
        .file(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"rails\"\n",
        )
        .file(
            "app/controllers/users_controller.rb",
            r#"
class UsersController
  def show
    User.build
  end
end
"#,
        )
        .file(
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        );
    for index in 0..40 {
        builder = builder.file(
            format!("app/services/noise_{index}.rb"),
            format!(
                r#"
class Noise{index}
  def call
    :ok
  end
end
"#
            ),
        );
    }
    let project = builder.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 2, 100);
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "show"),
        "expected User.build usage inside UsersController#show despite many irrelevant Zeitwerk files, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn zeitwerk_usage_candidates_include_non_app_ruby_consumers() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "Gemfile",
            r#"source "https://rubygems.org"

gem "rails"
"#,
        ),
        (
            "spec/models/user_spec.rb",
            r#"
class UserSpec
  def verifies_build
    User.build
  end
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        ),
    ]);
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 2, 100);
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter()
            .any(|hit| hit.enclosing.source() == &project.file("spec/models/user_spec.rb")),
        "expected User.build usage in spec/models/user_spec.rb, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn zeitwerk_structured_candidates_do_not_evict_precise_importers() {
    let mut builder = InlineTestProject::with_language(Language::Ruby)
        .file(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"rails\"\n",
        )
        .file(
            "app/controllers/users_controller.rb",
            r#"
require "app/models/user"

class UsersController
  def show
    User.call
  end
end
"#,
        )
        .file(
            "app/models/user.rb",
            r#"
class User
  def self.call
    new
  end
end
"#,
        );
    for index in 0..40 {
        builder = builder.file(
            format!("app/services/noise_{index}.rb"),
            format!(
                r#"
class Noise{index}
  def call
    :ok
  end
end
"#
            ),
        );
    }
    let project = builder.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let target = definition(&analyzer, "User.call");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 2, 100);
    assert!(
        query
            .candidate_files
            .contains(&project.file("app/controllers/users_controller.rb")),
        "explicit require importer should remain in capped provider candidates, got {:?}",
        query.candidate_files
    );
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "show"),
        "expected User.call usage inside UsersController#show despite noisy call methods, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}
