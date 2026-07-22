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
fn resolves_autoload_symbol_and_cross_file_constant_usages() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "lib/shop.rb",
            r#"
module Shop
  autoload :Discount, "shop/discount"
end
"#,
        ),
        (
            "lib/shop/discount.rb",
            r#"
module Shop
  class Discount
  end
end
"#,
        ),
        (
            "app/catalog.rb",
            r#"
class Catalog
  def run
    Shop::Discount.default
  end
end
"#,
        ),
    ]);

    let target = definition(&analyzer, "Shop$Discount");
    let provider = FixedCandidateProvider {
        files: [
            project.file("lib/shop.rb"),
            project.file("app/catalog.rb"),
            project.file("lib/shop/discount.rb"),
        ]
        .into_iter()
        .collect(),
    };
    let hits = UsageFinder::new()
        .query_with_provider(&analyzer, &[target], Some(&provider), 100, 100)
        .result
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert!(
        lines
            .iter()
            .any(|line| line == r#"autoload :Discount, "shop/discount""#),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line == "Shop::Discount.default"),
        "{lines:?}"
    );
    assert!(texts.iter().all(|text| text == "Discount"), "{texts:?}");
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
fn resolves_class_receiver_calls_to_singleton_class_methods() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/product.rb",
        r#"
class Product
  class << self
    def from_sku(sku)
      new(sku)
    end
  end
end

class OtherProduct
  def from_sku(sku)
  end
end

class Catalog
  def run
    Product.from_sku("sku-1")
    OtherProduct.new.from_sku("sku-2")
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Product.from_sku");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(
        lines
            .iter()
            .any(|line| line == r#"Product.from_sku("sku-1")"#),
        "{lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line == r#"OtherProduct.new.from_sku("sku-2")"#),
        "{lines:?}"
    );
}

#[test]
fn resolves_module_function_class_receiver_usages() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/pricing.rb",
        r#"
module Pricing
  module_function

  def tax_rate(region)
    0.1
  end
end

class Region
  def tax_rate(region)
  end
end

class Checkout
  def run
    Pricing.tax_rate("EU")
    Region.new.tax_rate("EU")
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Pricing.tax_rate");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(
        lines.iter().any(|line| line == r#"Pricing.tax_rate("EU")"#),
        "{lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line == r#"Region.new.tax_rate("EU")"#),
        "{lines:?}"
    );
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
fn resolves_public_send_symbol_dispatch_with_receiver_aware_mixin_lookup() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/report.rb",
        r#"
module Billing
  module Auditable
    def audit
    end
  end

  class Invoice
    include Auditable
  end

  class Other
    def audit
    end
  end
end

class Report
  def run
    invoice = Billing::Invoice.new
    invoice.public_send(:audit)
    invoice.public_send(:"audit")

    other = Billing::Other.new
    other.public_send(:audit)
    invoice.public_send(:missing, :audit)
  end
end
"#,
    )]);

    let target = definition(&analyzer, "Billing$Auditable.audit");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("audit lookup should succeed");
    let lines = hit_source_lines(&hits);
    let texts = hit_texts(&hits);

    assert_eq!(2, hits.len(), "expected two precise hits, got {lines:?}");
    assert!(
        lines
            .iter()
            .any(|line| line == "invoice.public_send(:audit)"),
        "{lines:?}"
    );
    assert_eq!(vec!["audit".to_string(), "audit".to_string()], texts);
}

#[test]
fn public_send_with_explicit_receiver_returns_unproven_not_top_level_hit() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/report.rb",
        r#"
class User
end

class Report
  def run
    user = User.new
    user.public_send(:save)
  end
end

def save
end
"#,
    )]);

    let target = definition(&analyzer, "save");
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 100, 100);

    assert!(
        query.graph_failure.is_none(),
        "unproven explicit receiver should not be a graph failure: {:?}",
        query.graph_failure
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!(
            "expected success with unproven sites, got {:?}",
            query.result
        );
    };
    assert!(
        hits_by_overload.values().all(|hits| hits.is_empty()),
        "explicit public_send receiver must not resolve through top-level fallback: {hits_by_overload:#?}"
    );
    assert_eq!(Some(&1), unproven_total_by_overload.get(&target));
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
fn resolves_bare_new_singleton_factory_receiver_usage() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "lib/precision/base.rb",
            r#"module Precision
  class Base
    def execute
    end

    def self.build
      new
    end
  end
end
"#,
        ),
        (
            "lib/precision/factory.rb",
            r#"require_relative "base"

module Precision
  def self.build
    Base.new
  end
end
"#,
        ),
        (
            "app/run.rb",
            r#"require_relative "../lib/precision/factory"

service = Precision.build
service.execute

second = Precision::Base.build
second.execute
"#,
        ),
    ]);

    let execute = definition(&analyzer, "Precision$Base.execute");
    let hits = analyzer
        .find_usages(&[execute])
        .into_either()
        .expect("Precision::Base#execute lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(
        lines.iter().any(|line| line == "service.execute"),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line == "second.execute"),
        "bare new in a singleton factory should preserve the invocation owner: {lines:?}"
    );
}

#[test]
fn bare_new_factory_inference_respects_bindings_defaults_setters_and_overrides() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "factory.rb",
        r#"
class Other
  def execute; end
end

class Service
  def execute; end

  def self.from_parameter(new)
    new
  end

  def self.from_assignment
    new = Other.new
    new
  end

  def self.from_operator_assignment
    new ||= Other.new
    new
  end

  def self.from_default(value = new)
    new
  end

  def self.from_setter
    new.value = 1
    new
  end
end

class Overridden
  def execute; end

  def self.new
    Other.new
  end

  def self.build
    new
  end
end

Service.from_parameter(Other.new).execute
Service.from_assignment.execute
Service.from_operator_assignment.execute
Service.from_default.execute
Service.from_setter.execute
Overridden.build.execute
"#,
    )]);

    let service_execute = definition(&analyzer, "Service.execute");
    let service_hits = analyzer
        .find_usages(&[service_execute])
        .into_either()
        .expect("Service#execute lookup should succeed");
    let service_lines = hit_source_lines(&service_hits);
    assert_eq!(
        vec![
            "Service.from_default.execute".to_string(),
            "Service.from_setter.execute".to_string(),
        ],
        service_lines,
        "only non-binding uses of new should preserve the Service owner"
    );

    let overridden_execute = definition(&analyzer, "Overridden.execute");
    let overridden_hits = analyzer
        .find_usages(&[overridden_execute])
        .into_either()
        .expect("Overridden#execute lookup should succeed");
    assert!(
        overridden_hits.is_empty(),
        "an overridden singleton new must not be treated as allocation of its invocation owner"
    );

    let other_execute = definition(&analyzer, "Other.execute");
    let other_lines = hit_source_lines(
        &analyzer
            .find_usages(&[other_execute])
            .into_either()
            .expect("Other#execute lookup should succeed"),
    );
    assert!(
        other_lines
            .iter()
            .any(|line| line == "Overridden.build.execute"),
        "the overridden new return should flow through the factory chain: {other_lines:?}"
    );
}

#[test]
fn recursive_factory_receiver_returns_unproven_without_inventing_hit() {
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
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&audit), 100, 100);
    assert!(
        query.graph_failure.is_none(),
        "unproven recursive factory receiver should not be a graph failure: {:?}",
        query.graph_failure
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!(
            "expected success with unproven sites, got {:?}",
            query.result
        );
    };
    assert!(
        hits_by_overload.values().all(|hits| hits.is_empty()),
        "recursive factory inference should not invent a proven hit: {hits_by_overload:#?}"
    );
    assert_eq!(Some(&1), unproven_total_by_overload.get(&audit));
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app.rb",
        r#"class Service
  def self.build
    Service.new
  end

  def run
  end
end

class Other
  def run
  end
end

class App
  def via_factory
    service = Service.build
    service.run
  end
end
"#,
    )]);

    let service_run = definition(&analyzer, "Service.run");
    let service_hits = analyzer
        .find_usages(&[service_run])
        .into_either()
        .expect("Service.run lookup should succeed");
    let service_lines = hit_source_lines(&service_hits);
    assert!(
        service_lines.iter().any(|line| line == "service.run"),
        "{service_lines:?}"
    );

    let other_run = definition(&analyzer, "Other.run");
    let other_query = UsageFinder::new().query(&analyzer, &[other_run], 100, 100);
    if let Ok(other_hits) = other_query.result.into_either() {
        let other_lines = hit_source_lines(&other_hits);
        assert!(
            !other_lines.iter().any(|line| line == "service.run"),
            "factory receiver must not fall back to same-name Other.run: {other_lines:?}"
        );
    }
}

#[test]
fn ambiguous_factory_receiver_emits_no_partial_edge() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app.rb",
        r#"class Service
  def run
  end
end

class Other
  def run
  end
end

class Factory
  def self.build(flag)
    if flag
      Service.new
    else
      Other.new
    end
  end
end

class App
  def run(flag)
    service = Factory.build(flag)
    service.run
  end
end
"#,
    )]);

    for target_fqn in ["Service.run", "Other.run"] {
        let target = definition(&analyzer, target_fqn);
        let query = UsageFinder::new().query(&analyzer, &[target], 100, 100);
        if let Ok(hits) = query.result.into_either() {
            let lines = hit_source_lines(&hits);
            assert!(
                !lines.iter().any(|line| line == "service.run"),
                "ambiguous factory receiver must not emit partial {target_fqn} hit: {lines:?}"
            );
        }
    }
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
fn reports_unproven_sites_for_only_dynamic_or_untyped_same_name_calls() {
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
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 100, 100);

    assert!(
        query.graph_failure.is_none(),
        "unproven Ruby calls should not be a graph failure: {:?}",
        query.graph_failure
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!(
            "expected success with unproven sites, got {:?}",
            query.result
        );
    };
    assert!(hits_by_overload.values().all(|hits| hits.is_empty()));
    assert_eq!(Some(&2), unproven_total_by_overload.get(&target));
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
fn finds_attr_reader_and_alias_method_usages_through_inferred_receiver() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "lib/shop/product.rb",
            r#"
class Product
  attr_reader :name
  alias_method :label, :name

  def self.featured
    new("featured")
  end

  def initialize(name)
    @name = name
  end

  def summary
    label
  end
end
"#,
        ),
        (
            "app/catalog.rb",
            r#"
require "lib/shop/product"

product = Product.featured
product.name
product.label
"#,
        ),
    ]);

    let name_target = analyzer
        .get_definitions("Product.name")
        .into_iter()
        .find(|unit| unit.is_function())
        .expect("missing attr_reader method declaration");
    let name_hits = analyzer
        .find_usages(&[name_target])
        .into_either()
        .expect("attr_reader usage lookup should succeed");
    let name_lines = hit_source_lines(&name_hits);
    assert!(
        name_lines.iter().any(|line| line == "product.name"),
        "expected Product#name external usage, got {name_lines:?}"
    );

    let label_target = definition(&analyzer, "Product.label");
    let label_hits = analyzer
        .find_usages(&[label_target])
        .into_either()
        .expect("alias_method usage lookup should succeed");
    let label_lines = hit_source_lines(&label_hits);
    assert!(
        label_lines.iter().any(|line| line == "label"),
        "expected Product#label internal usage, got {label_lines:?}"
    );
    assert!(
        label_lines.iter().any(|line| line == "product.label"),
        "expected Product#label external usage, got {label_lines:?}"
    );
}

#[test]
fn finds_namespaced_attr_reader_usage_from_alias_target_and_inferred_receiver() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "lib/shop/product.rb",
            r#"
module Shop
  class Product
    attr_reader :name

    def initialize(name)
      @name = name
    end

    alias_method :label, :name

    def summary
      label
    end

    def self.featured
      new("featured")
    end
  end
end
"#,
        ),
        (
            "app/catalog.rb",
            r#"
require "lib/shop/product"

product = Shop::Product.featured
product.name
product.label
"#,
        ),
    ]);

    let name_target = definition(&analyzer, "Shop$Product.name");
    let name_hits = analyzer
        .find_usages(&[name_target])
        .into_either()
        .expect("namespaced attr_reader usage lookup should succeed");
    let name_lines = hit_source_lines(&name_hits);
    let name_texts = hit_texts(&name_hits);
    assert!(
        name_lines
            .iter()
            .any(|line| line == "alias_method :label, :name"),
        "expected alias_method target argument usage, got {name_lines:?}"
    );
    assert!(
        name_lines.iter().any(|line| line == "product.name"),
        "expected namespaced Product#name external usage, got {name_lines:?}"
    );
    assert!(
        name_texts.iter().all(|text| text == "name"),
        "expected exact name tokens, got {name_texts:?}"
    );
}

#[test]
fn finds_singleton_attr_reader_and_alias_method_usages_without_instance_false_positive() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app.rb",
        r#"
class Product
  class << self
    attr_reader :version
    alias_method :label, :version
  end
end

Product.version
Product.label
Product.new.version
"#,
    )]);

    let version_target = analyzer
        .get_definitions("Product.version")
        .into_iter()
        .find(|unit| unit.is_function())
        .expect("missing singleton attr_reader method declaration");
    let version_hits = analyzer
        .find_usages(&[version_target])
        .into_either()
        .expect("singleton attr_reader usage lookup should succeed");
    let version_lines = hit_source_lines(&version_hits);
    assert!(
        version_lines.iter().any(|line| line == "Product.version"),
        "expected Product.version usage, got {version_lines:?}"
    );
    assert!(
        version_lines
            .iter()
            .all(|line| line != "Product.new.version"),
        "singleton attr_reader must not resolve through instance receiver: {version_lines:?}"
    );

    let label_target = definition(&analyzer, "Product.label");
    let label_hits = analyzer
        .find_usages(&[label_target])
        .into_either()
        .expect("singleton alias_method usage lookup should succeed");
    let label_lines = hit_source_lines(&label_hits);
    assert!(
        label_lines.iter().any(|line| line == "Product.label"),
        "expected Product.label usage, got {label_lines:?}"
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
