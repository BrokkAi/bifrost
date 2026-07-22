mod common;

use brokk_bifrost::{AnalyzerConfig, Language, SearchToolsService, WorkspaceAnalyzer};
use common::{
    CSHARP_NESTED_PARTIAL_MAPPER, InlineTestProject, call_search_tool_json,
    csharp_nested_partial_cacheinfo_project,
};
use serde_json::{Value, json};

fn lookup(root: &std::path::Path, args: &str) -> Value {
    call_search_tool_json(root, "get_definitions_by_location", args)
}

fn lookup_declaration(root: &std::path::Path, args: &str) -> Value {
    call_search_tool_json(root, "get_declarations_by_location", args)
}

fn lookup_declaration_with_definition_key(root: &std::path::Path, args: &str) -> Value {
    let mut value = lookup_declaration(root, args);
    for result in value["results"].as_array_mut().into_iter().flatten() {
        if let Some(declarations) = result
            .as_object_mut()
            .and_then(|object| object.remove("declarations"))
        {
            result["definitions"] = declarations;
        }
    }
    value
}

fn lookup_reference(root: &std::path::Path, args: &str) -> Value {
    call_search_tool_json(root, "get_definitions_by_reference", args)
}

fn lookup_type(root: &std::path::Path, args: &str) -> Value {
    call_search_tool_json(root, "get_type_by_location", args)
}

fn column_of(line: &str, needle: &str) -> usize {
    line.find(needle).expect("needle in line") + 1
}

fn character_column_of(line: &str, needle: &str) -> usize {
    line[..line.find(needle).expect("needle in line")]
        .chars()
        .count()
        + 1
}

fn location_reference(path: &str, source: &str, start: usize) -> String {
    json!({"references": [location_query(path, source, start)]}).to_string()
}

fn location_query(path: &str, source: &str, start: usize) -> Value {
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    json!({"path": path, "line": line, "column": column})
}

#[test]
fn typescript_jsx_attribute_resolves_local_component_props_owner_exactly() {
    let source = r#"
interface LocalProps { label: string }
interface OtherProps { label: string }
function Local(_props: LocalProps) { return null }
function Other(_props: OtherProps) { return null }
export function View() {
  return <><Local label="local" /><Other label="other" /><External label="external" /></>
}
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("view.tsx", source)
        .build();

    for (marker, expected) in [
        ("label=\"local\"", "LocalProps.label"),
        ("label=\"other\"", "OtherProps.label"),
    ] {
        let start = source.find(marker).expect("attribute marker");
        let value = lookup(
            project.root(),
            &location_reference("view.tsx", source, start),
        );
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{value}"
        );
    }

    let external = source
        .find("label=\"external\"")
        .expect("external attribute");
    let value = lookup(
        project.root(),
        &location_reference("view.tsx", source, external),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_jsx_attribute_resolves_imported_component_props_owner() {
    let source = r#"
import { Child } from './child'
export function View() { return <Child title="hello" /> }
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "child.tsx",
            "export interface ChildProps { title: string }\nexport const Child: React.FC<ChildProps> = (_props) => null\n",
        )
        .file("view.tsx", source)
        .build();
    let start = source.find("title=\"hello\"").expect("attribute");
    let value = lookup(
        project.root(),
        &location_reference("view.tsx", source, start),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "ChildProps.title",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["path"], "child.tsx",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_constant_reference_to_class() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"class User
end

class App
  def run
    User
  end
end
"#,
        )
        .build();

    let line = "    User";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":6,"column":{}}}]}}"#,
            column_of(line, "User")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "User", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User", "{value}");
}

#[test]
fn ruby_get_definition_resolves_same_class_bare_method_call() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"class User
  def run
    audit
  end

  def audit
  end
end
"#,
        )
        .build();

    let line = "    audit";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":3,"column":{}}}]}}"#,
            column_of(line, "audit")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User.audit", "{value}");
}

#[test]
fn ruby_get_definition_resolves_attr_reader_and_alias_method_calls() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
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
        )
        .file(
            "app/catalog.rb",
            r#"
require "lib/shop/product"

product = Product.featured
product.name
product.label
"#,
        )
        .build();

    let name_line = "product.name";
    let name_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/catalog.rb","line":5,"column":{}}}]}}"#,
            column_of(name_line, "name")
        ),
    );
    assert_eq!(
        name_value["results"][0]["status"], "resolved",
        "{name_value}"
    );
    assert_eq!(
        name_value["results"][0]["definitions"][0]["fqn"], "Product.name",
        "{name_value}"
    );
    assert_eq!(
        name_value["results"][0]["definitions"][0]["kind"], "function",
        "{name_value}"
    );

    let label_line = "product.label";
    let label_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/catalog.rb","line":6,"column":{}}}]}}"#,
            column_of(label_line, "label")
        ),
    );
    assert_eq!(
        label_value["results"][0]["status"], "resolved",
        "{label_value}"
    );
    assert_eq!(
        label_value["results"][0]["definitions"][0]["fqn"], "Product.label",
        "{label_value}"
    );
}

#[test]
fn ruby_get_definition_resolves_singleton_attr_reader_and_alias_method_calls() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
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
        )
        .build();

    let version_line = "Product.version";
    let version_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":9,"column":{}}}]}}"#,
            column_of(version_line, "version")
        ),
    );
    assert_eq!(
        version_value["results"][0]["status"], "resolved",
        "{version_value}"
    );
    assert_eq!(
        version_value["results"][0]["definitions"][0]["fqn"], "Product.version",
        "{version_value}"
    );

    let label_line = "Product.label";
    let label_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":10,"column":{}}}]}}"#,
            column_of(label_line, "label")
        ),
    );
    assert_eq!(
        label_value["results"][0]["status"], "resolved",
        "{label_value}"
    );
    assert_eq!(
        label_value["results"][0]["definitions"][0]["fqn"], "Product.label",
        "{label_value}"
    );

    let instance_line = "Product.new.version";
    let instance_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":11,"column":{}}}]}}"#,
            column_of(instance_line, "version")
        ),
    );
    assert_eq!(
        instance_value["results"][0]["status"], "no_definition",
        "{instance_value}"
    );
}

#[test]
fn ruby_get_definition_does_not_index_dynamic_attr_or_alias_names() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"
class Product
  ATTR_NAME = :name
  alias_name = :label

  attr_reader ATTR_NAME
  alias_method alias_name, :name
end

product = Product.new
product.ATTR_NAME
product.alias_name
"#,
        )
        .build();

    let attr_line = "product.ATTR_NAME";
    let attr_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":11,"column":{}}}]}}"#,
            column_of(attr_line, "ATTR_NAME")
        ),
    );
    assert_eq!(
        attr_value["results"][0]["status"], "no_definition",
        "{attr_value}"
    );

    let alias_line = "product.alias_name";
    let alias_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":12,"column":{}}}]}}"#,
            column_of(alias_line, "alias_name")
        ),
    );
    assert_eq!(
        alias_value["results"][0]["status"], "no_definition",
        "{alias_value}"
    );
}

#[test]
fn ruby_get_definition_resolves_top_level_bare_method_call() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/report.rb",
            r#"module Reports
  class InvoiceReport
    def render
      normalize_total(19)
    end
  end
end

def normalize_total(value)
  value.round
end
"#,
        )
        .build();

    let line = "      normalize_total(19)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/report.rb","line":4,"column":{}}}]}}"#,
            column_of(line, "normalize_total")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "normalize_total",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_shadowing_parameter_itself() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/report.rb",
            r#"def render(normalize_total)
  normalize_total
end

def normalize_total
end
"#,
        )
        .build();

    let line = "  normalize_total";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/report.rb","line":2,"column":{}}}]}}"#,
            column_of(line, "normalize_total")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["name"], "normalize_total",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "parameter", "{value}");
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn ruby_get_definition_resolves_explicit_class_receiver_call() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"class User
  def self.find
  end
end

class App
  def run
    User.find
  end
end
"#,
        )
        .build();

    let line = "    User.find";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":8,"column":{}}}]}}"#,
            column_of(line, "find")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User.find", "{value}");
}

#[test]
fn ruby_get_definition_resolves_autoload_symbol_to_constant() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/shop.rb",
            r#"module Shop
  class Discount
  end

  autoload :Discount, "shop/discount"
end
"#,
        )
        .build();

    let line = r#"  autoload :Discount, "shop/discount""#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib/shop.rb","line":5,"column":{}}}]}}"#,
            column_of(line, "Discount")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Shop$Discount", "{value}");
    assert_eq!(result["definitions"][0]["path"], "lib/shop.rb", "{value}");
}

#[test]
fn ruby_get_definition_resolves_cross_file_autoload_constant_path() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "lib/shop.rb",
            r#"module Shop
  autoload :Discount, "shop/discount"
end
"#,
        )
        .file(
            "lib/shop/discount.rb",
            r#"module Shop
  class Discount
    def self.default
    end
  end
end
"#,
        )
        .file(
            "app/catalog.rb",
            r#"class Catalog
  def run
    Shop::Discount.default
  end
end
"#,
        )
        .build();

    let line = "    Shop::Discount.default";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/catalog.rb","line":3,"column":{}}}]}}"#,
            column_of(line, "Discount")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Shop$Discount", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "lib/shop/discount.rb",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_module_function_class_receiver_call() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/pricing.rb",
            r#"module Pricing
  module_function

  def tax_rate(region)
    0.1
  end
end

class Checkout
  def run
    Pricing.tax_rate("EU")
  end
end
"#,
        )
        .build();

    let line = r#"    Pricing.tax_rate("EU")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/pricing.rb","line":11,"column":{}}}]}}"#,
            column_of(line, "tax_rate")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Pricing.tax_rate",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_mixin_methods_by_receiver_polarity() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"module Findable
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
  end
end
"#,
        )
        .build();

    let find_line = "    User.find";
    let find_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":18,"column":{}}}]}}"#,
            column_of(find_line, "find")
        ),
    );
    let find_result = &find_value["results"][0];
    assert_eq!(find_result["status"], "resolved", "{find_value}");
    assert_eq!(
        find_result["definitions"][0]["fqn"], "Findable.find",
        "{find_value}"
    );

    let audit_line = "    User.new.audit";
    let audit_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":19,"column":{}}}]}}"#,
            column_of(audit_line, "audit")
        ),
    );
    let audit_result = &audit_value["results"][0];
    assert_eq!(audit_result["status"], "resolved", "{audit_value}");
    assert_eq!(
        audit_result["definitions"][0]["fqn"], "Auditable.audit",
        "{audit_value}"
    );
}

#[test]
fn ruby_get_definition_resolves_build_receiver_include_and_prepend_methods() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
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
        )
        .file(
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
        )
        .build();

    let audit_line = "      invoice.audit";
    let audit_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/report.rb","line":7,"column":{}}}]}}"#,
            column_of(audit_line, "audit")
        ),
    );
    let audit_result = &audit_value["results"][0];
    assert_eq!(audit_result["status"], "resolved", "{audit_value}");
    assert_eq!(
        audit_result["definitions"][0]["fqn"], "Billing$Auditable.audit",
        "{audit_value}"
    );

    let total_label_line = "      invoice.total_label";
    let total_label_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/report.rb","line":8,"column":{}}}]}}"#,
            column_of(total_label_line, "total_label")
        ),
    );
    let total_label_result = &total_label_value["results"][0];
    assert_eq!(
        total_label_result["status"], "resolved",
        "{total_label_value}"
    );
    assert_eq!(
        total_label_result["definitions"][0]["fqn"], "Billing$Formatting.total_label",
        "{total_label_value}"
    );
}

#[test]
fn ruby_get_definition_resolves_inherited_self_new_factory_receiver() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
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
        )
        .build();

    let line = "    Child.build.audit";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":18,"column":{}}}]}}"#,
            column_of(line, "audit")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Auditable.audit",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_factory_cycle_fails_closed() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"class Thing
  def self.build
    Thing.build.new
  end
end

class App
  def run
    Thing.build.audit
  end
end
"#,
        )
        .build();

    let line = "    Thing.build.audit";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":9,"column":{}}}]}}"#,
            column_of(line, "audit")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
}

#[test]
fn ruby_get_definition_respects_multi_argument_mixin_precedence() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
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
        )
        .build();

    let audit_line = "    Included.new.audit";
    let audit_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":30,"column":{}}}]}}"#,
            column_of(audit_line, "audit")
        ),
    );
    let audit_result = &audit_value["results"][0];
    assert_eq!(audit_result["status"], "resolved", "{audit_value}");
    assert_eq!(
        audit_result["definitions"][0]["fqn"], "A.audit",
        "{audit_value}"
    );

    let label_line = "    Prepended.new.label";
    let label_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":31,"column":{}}}]}}"#,
            column_of(label_line, "label")
        ),
    );
    let label_result = &label_value["results"][0];
    assert_eq!(label_result["status"], "resolved", "{label_value}");
    assert_eq!(
        label_result["definitions"][0]["fqn"], "A.label",
        "{label_value}"
    );
}

#[test]
fn ruby_get_definition_resolves_constant_through_project_local_require() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/main.rb",
            r#"require_relative "user"

class App
  def run
    User
  end
end
"#,
        )
        .file(
            "app/user.rb",
            r#"class User
end
"#,
        )
        .build();

    let line = "    User";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/main.rb","line":5,"column":{}}}]}}"#,
            column_of(line, "User")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User", "{value}");
    assert_eq!(result["definitions"][0]["path"], "app/user.rb", "{value}");
}

#[test]
fn ruby_get_definition_resolves_superclass_method_from_constructed_receiver() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"class User
  def audit
  end
end

class Admin < User
end

class App
  def run
    Admin.new.audit
  end
end
"#,
        )
        .build();

    let line = "    Admin.new.audit";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":11,"column":{}}}]}}"#,
            column_of(line, "audit")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User.audit", "{value}");
}

#[test]
fn ruby_get_definition_prefers_direct_method_over_mixin_method() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"module Auditable
  def audit
  end
end

class User
  include Auditable

  def audit
  end
end

class App
  def run
    User.new.audit
  end
end
"#,
        )
        .build();

    let line = "    User.new.audit";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":15,"column":{}}}]}}"#,
            column_of(line, "audit")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User.audit", "{value}");
}

#[test]
fn ruby_get_definition_reports_dynamic_dispatch_without_guessing() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"class User
  def audit
  end

  def run
    send(:audit)
  end
end
"#,
        )
        .build();

    let line = "    send(:audit)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":6,"column":{}}}]}}"#,
            column_of(line, "send")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "unsupported_ruby_dynamic_dispatch",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_project_defined_send_without_symbol_dispatch() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"class User
  def run
    send
  end

  def send
  end
end
"#,
        )
        .build();

    let line = "    send";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rb","line":3,"column":{}}}]}}"#,
            column_of(line, "send")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User.send", "{value}");
}

#[test]
fn ruby_get_definition_resolves_zeitwerk_visible_constant() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("Gemfile", "gem \"rails\"\n")
        .file(
            "app/models/report_builder.rb",
            r#"class ReportBuilder
end
"#,
        )
        .file(
            "app/controllers/reports_controller.rb",
            r#"class ReportsController
  def show
    ReportBuilder
  end
end
"#,
        )
        .build();

    let line = "    ReportBuilder";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/controllers/reports_controller.rb","line":3,"column":{}}}]}}"#,
            column_of(line, "ReportBuilder")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ReportBuilder", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "app/models/report_builder.rb",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_namespaced_class_constant_field() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
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
        )
        .file(
            "lib/billing/invoice.rb",
            r#"module Billing
  class Invoice
    DEFAULT_CURRENCY = Money::Currency.new("USD")
  end
end
"#,
        )
        .file(
            "lib/other/invoice.rb",
            r#"module Other
  class Invoice
    DEFAULT_CURRENCY = "EUR"
  end
end
"#,
        )
        .build();

    let line = "      Billing::Invoice::DEFAULT_CURRENCY";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/report.rb","line":6,"column":{}}}]}}"#,
            column_of(line, "DEFAULT_CURRENCY")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Billing$Invoice.DEFAULT_CURRENCY",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "lib/billing/invoice.rb",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_absolute_namespaced_class_constant_field() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
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
        )
        .build();

    let line = "      ::Billing::Invoice::DEFAULT_CURRENCY";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/report.rb","line":16,"column":{}}}]}}"#,
            column_of(line, "DEFAULT_CURRENCY")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Billing$Invoice.DEFAULT_CURRENCY",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_owner_segments_in_scoped_constant_assignment() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app/report.rb",
            r#"module Billing
  class Invoice
  end
end

Billing::Invoice::DEFAULT_CURRENCY = "USD"
"#,
        )
        .build();

    let line = "Billing::Invoice::DEFAULT_CURRENCY = \"USD\"";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/report.rb","line":6,"column":{}}}]}}"#,
            column_of(line, "Invoice")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Billing$Invoice",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_instance_variable_field() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "invoice.rb",
            r#"class Invoice
  def initialize
    @status = "draft"
  end

  def status
    @status
  end
end
"#,
        )
        .build();

    let line = "    @status";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"invoice.rb","line":7,"column":{}}}]}}"#,
            column_of(line, "@status")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "@status", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Invoice.@status",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_class_variable_field() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "invoice.rb",
            r#"class Invoice
  @@sequence = 0

  def self.build
    @@sequence += 1
  end
end
"#,
        )
        .build();

    let line = "    @@sequence += 1";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"invoice.rb","line":5,"column":{}}}]}}"#,
            column_of(line, "@@sequence")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "@@sequence", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Invoice.@@sequence",
        "{value}"
    );
}

#[test]
fn ruby_get_definition_resolves_class_instance_variable_field() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "invoice.rb",
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
        )
        .build();

    let line = "    @last_build";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"invoice.rb","line":9,"column":{}}}]}}"#,
            column_of(line, "@last_build")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "@last_build", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Invoice.$singleton.@last_build",
        "{value}"
    );

    let line = "    @last_build = new";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"invoice.rb","line":5,"column":{}}}]}}"#,
            column_of(line, "@last_build")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "@last_build", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Invoice.$singleton.@last_build",
        "{value}"
    );
}

#[test]
fn rust_named_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::format_value;

pub fn run() {
    format_value();
}
"#,
        )
        .file(
            "util.rs",
            r#"
pub fn format_value() {}
"#,
        )
        .build();

    let line = "    format_value();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "format_value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "format_value", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "format_value", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_imported_turbofish_function_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::leaf;

pub fn run() {
    leaf::<u8>();
}
"#,
        )
        .file("util.rs", "pub fn leaf<T>() {}\n")
        .build();

    let line = "    leaf::<u8>();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "leaf")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "leaf", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "leaf", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_generic_method_call_prefers_method_over_same_named_field() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod model;
use crate::model::Worker;

pub fn run(worker: Worker) {
    worker.make::<u8>();
}
"#,
        )
        .file(
            "model.rs",
            r#"
pub struct Worker {
    pub make: usize,
}

impl Worker {
    pub fn make<T>(&self) {}
}
"#,
        )
        .build();

    let line = "    worker.make::<u8>();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "make")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "worker.make", "{value}");
    assert_eq!(
        result["definitions"].as_array().expect("definitions").len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "Worker.make", "{value}");
    assert_eq!(result["definitions"][0]["path"], "model.rs", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "function", "{value}");
}

#[test]
fn rust_definition_lookup_ignores_other_language_normalized_fqn_collisions() {
    let rust_source = "pub struct Widget;\n\nimpl Widget {\n    pub fn build() -> Self {\n        Self\n    }\n}\n";
    let project = InlineTestProject::new()
        .file("src/shared/mod.rs", rust_source)
        .file(
            "src/shared/Widget.scala",
            "package shared\nobject Widget { def create(): Widget.type = this }\n",
        )
        .build();
    let (reference_line_index, reference_line) = rust_source
        .lines()
        .enumerate()
        .find(|(_, line)| line.trim() == "Self")
        .unwrap();

    let value = lookup(
        project.root(),
        &json!({
            "references": [{
                "path": "src/shared/mod.rs",
                "line": reference_line_index + 1,
                "column": column_of(reference_line, "Self")
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "shared.Widget", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "src/shared/mod.rs",
        "{value}"
    );
}

#[test]
fn rust_grouped_use_prefix_resolves_to_module_declaration() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub mod workflow;

use workflow::{Job, Named};

pub fn run(job: Job) -> String {
    job.name().to_string()
}
"#,
        )
        .file(
            "src/workflow.rs",
            r#"
pub struct Job;

pub trait Named {
    fn name(&self) -> &str;
}
"#,
        )
        .build();

    let line = "use workflow::{Job, Named};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":4,"column":{}}}]}}"#,
            column_of(line, "workflow")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "workflow::", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "workflow", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/lib.rs", "{value}");
}

#[test]
fn rust_trait_impl_items_resolve_to_trait_declarations() {
    let source = r#"
pub trait Runner {
    type Output;

    fn run() -> Self::Output {
        String::new()
    }
}

pub struct LocalRunner;

impl Runner for LocalRunner {
    type Output = String;
}

pub fn run_via_trait() -> String {
    LocalRunner::run()
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    let call_line = "    LocalRunner::run()";
    let method = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":17,"column":{}}}]}}"#,
            column_of(call_line, "run")
        ),
    );
    assert_eq!(method["results"][0]["status"], "resolved", "{method}");
    assert_eq!(
        method["results"][0]["definitions"][0]["fqn"], "Runner.run",
        "{method}"
    );

    let assoc_line = "    type Output = String;";
    let assoc = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":13,"column":{}}}]}}"#,
            column_of(assoc_line, "Output")
        ),
    );
    assert_eq!(assoc["results"][0]["status"], "resolved", "{assoc}");
    assert_eq!(
        assoc["results"][0]["definitions"][0]["fqn"], "Runner.Output",
        "{assoc}"
    );
}

#[test]
fn rust_associated_type_navigation_distinguishes_contract_and_implementation() {
    let source = r#"
pub trait Runner {
    type Output;
}

pub struct LocalRunner;

impl Runner for LocalRunner {
    type Output = String;
}

pub type Selected = <LocalRunner as Runner>::Output;
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    let impl_item = source.find("type Output =").expect("impl associated type") + 5;
    let args = location_reference("src/lib.rs", source, impl_item);
    let declaration = lookup_declaration(project.root(), &args);
    assert_eq!(declaration["results"][0]["operation"], "declaration");
    assert_eq!(
        declaration["results"][0]["status"], "resolved",
        "{declaration}"
    );
    assert_eq!(
        declaration["results"][0]["declarations"][0]["fqn"], "Runner.Output",
        "{declaration}"
    );

    let definition = lookup(project.root(), &args);
    assert_eq!(definition["results"][0]["operation"], "definition");
    assert_eq!(
        definition["results"][0]["status"], "resolved",
        "{definition}"
    );
    assert_eq!(
        definition["results"][0]["definitions"][0]["fqn"], "LocalRunner.Output",
        "{definition}"
    );

    let qualified = source.rfind("Output;").expect("qualified associated type");
    let definition = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, qualified),
    );
    assert_eq!(
        definition["results"][0]["status"], "resolved",
        "{definition}"
    );
    assert_eq!(
        definition["results"][0]["definitions"][0]["fqn"], "LocalRunner.Output",
        "{definition}"
    );
}

#[test]
fn java_declaration_navigation_uses_interface_receiver_contract() {
    let source = r#"
interface Runner { void run(); }
class LocalRunner implements Runner { public void run() {} }
class App { void invoke(Runner runner) { runner.run(); } }
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("App.java", source)
        .build();
    let call = source.rfind("run();").expect("interface-typed call");
    let value = lookup_declaration(
        project.root(),
        &location_reference("App.java", source, call),
    );
    assert_eq!(value["results"][0]["operation"], "declaration");
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["declarations"][0]["fqn"], "Runner.run",
        "{value}"
    );
}

#[test]
fn rust_associated_path_type_segment_resolves_imported_sibling_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/main.rs", common::RUST_ASSOCIATED_PATH_MAIN)
        .file("src/state.rs", common::RUST_ASSOCIATED_PATH_STATE)
        .build();

    let line = "    app_with_state(AppState::with_environment(repositories, environment))";
    let type_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/main.rs","line":16,"column":{}}}]}}"#,
            column_of(line, "AppState")
        ),
    );

    let type_result = &type_value["results"][0];
    assert_eq!(type_result["status"], "resolved", "{type_value}");
    assert_eq!(
        type_result["reference"]["target"], "AppState::with_environment",
        "{type_value}"
    );
    assert_eq!(
        type_result["definitions"][0]["path"], "src/state.rs",
        "{type_value}"
    );
    assert_eq!(
        type_result["definitions"][0]["fqn"], "state.AppState",
        "{type_value}"
    );

    let method_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/main.rs","line":16,"column":{}}}]}}"#,
            column_of(line, "with_environment")
        ),
    );

    let method_result = &method_value["results"][0];
    assert_eq!(method_result["status"], "resolved", "{method_value}");
    assert_eq!(
        method_result["definitions"][0]["fqn"], "state.AppState.with_environment",
        "{method_value}"
    );
    assert_eq!(
        method_result["definitions"][0]["path"], "src/state.rs",
        "{method_value}"
    );

    let line = "    let _ = state::AppState::with_environment(Repositories, Environment);";
    let scoped_type_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/main.rs","line":15,"column":{}}}]}}"#,
            column_of(line, "AppState")
        ),
    );

    let scoped_type_result = &scoped_type_value["results"][0];
    assert_eq!(
        scoped_type_result["status"], "resolved",
        "{scoped_type_value}"
    );
    assert_eq!(
        scoped_type_result["definitions"][0]["fqn"], "state.AppState",
        "{scoped_type_value}"
    );
}

#[test]
fn rust_type_lookup_resolves_explicit_local_binding_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod model;
use crate::model::Widget;

pub fn run() {
    let value: Widget = Widget {};
    let _ = value;
}
"#,
        )
        .file("model.rs", "pub struct Widget;\n")
        .build();

    let line = "    let _ = value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "value", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.rs",
        "{value}"
    );
}

#[test]
fn rust_type_lookup_resolves_explicit_parameter_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod model;
use crate::model::Widget;

pub fn render(input: Widget) {
    let _ = input;
}
"#,
        )
        .file("model.rs", "pub struct Widget;\n")
        .build();

    let line = "    let _ = input;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "input")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.rs",
        "{value}"
    );
}

#[test]
fn rust_type_lookup_resolves_member_receiver_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod model;
use crate::model::Widget;

pub fn render(input: Widget) {
    let _ = input.name;
}
"#,
        )
        .file(
            "model.rs",
            r#"
pub struct Widget {
    pub name: String,
}
"#,
        )
        .build();

    let line = "    let _ = input.name;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "input")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.rs",
        "{value}"
    );
}

#[test]
fn rust_type_lookup_resolves_member_field_type_from_known_receiver() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod model;
use crate::model::{Label, Widget};

pub fn render(input: Widget) {
    let _ = input.label;
}
"#,
        )
        .file(
            "model.rs",
            r#"
pub struct Label;

pub struct Widget {
    pub label: Label,
}
"#,
        )
        .build();

    let line = "    let _ = input.label;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "label")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Label", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.rs",
        "{value}"
    );
}

#[test]
fn rust_type_lookup_reports_no_type_for_untyped_local() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub fn render() {
    let value = 1;
    let _ = value;
}
"#,
        )
        .build();

    let line = "    let _ = value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":4,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(result["reference"]["target"], "value", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "no_explicit_type",
        "{value}"
    );
}

#[test]
fn rust_type_lookup_resolves_struct_literal_expression_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod model;
use crate::model::Widget;

pub fn run() {
    let _ = Widget {};
}
"#,
        )
        .file("model.rs", "pub struct Widget;\n")
        .build();

    let line = "    let _ = Widget {};";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "Widget")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.rs",
        "{value}"
    );
}

#[test]
fn rust_type_lookup_resolves_function_call_return_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod model;
use crate::model::Widget;

fn make_widget() -> Widget {
    Widget {}
}

pub fn run() {
    let _ = make_widget();
}
"#,
        )
        .file("model.rs", "pub struct Widget;\n")
        .build();

    let line = "    let _ = make_widget();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":10,"column":{}}}]}}"#,
            column_of(line, "make_widget")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.rs",
        "{value}"
    );
}

#[test]
fn rust_type_lookup_keeps_type_alias_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub struct Widget;
pub type Alias = Widget;

pub fn run() {
    let value: Alias = Widget;
    let _ = value;
}
"#,
        )
        .build();

    let line = "    let _ = value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Alias", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["kind"], "field",
        "{value}"
    );
}

#[test]
fn ts_type_lookup_resolves_local_variable_annotation() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "const value: Widget = new Widget();\nclass Widget {}\n",
        )
        .build();

    let value = lookup_type(
        project.root(),
        r#"{"references":[{"path":"app.ts","line":1,"column":7}]}"#,
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "value", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "app.ts",
        "{value}"
    );
}

#[test]
fn ts_type_lookup_resolves_imported_type_annotation() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("model.ts", "export interface Widget {}\n")
        .file(
            "app.ts",
            "import { Widget } from './model';\nconst value: Widget = {};\nvalue;\n",
        )
        .build();

    let line = "value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.ts",
        "{value}"
    );
}

#[test]
fn ts_type_lookup_resolves_parameter_and_return_annotations() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "class Widget {}\nfunction render(input: Widget): Widget { return input; }\nrender(new Widget());\n",
        )
        .build();

    for (line_no, line, name) in [
        (
            2,
            "function render(input: Widget): Widget { return input; }",
            "input",
        ),
        (3, "render(new Widget());", "render"),
    ] {
        let value = lookup_type(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"app.ts","line":{line_no},"column":{}}}]}}"#,
                column_of(line, name)
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
        assert_eq!(
            result["types"][0]["definitions"][0]["path"], "app.ts",
            "{value}"
        );
    }
}

#[test]
fn ts_type_lookup_resolves_member_receiver_type() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "class Widget { label(): string { return ''; } }\nconst value: Widget = new Widget();\nvalue.label();\n",
        )
        .build();

    let line = "value.label();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "app.ts",
        "{value}"
    );
}

#[test]
fn typescript_factory_receiver_member_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            "export class Service { run() {} }\nexport class Other { run() {} }\nexport function makeService() { return new Service(); }\nexport function caller() {\n  const service = makeService();\n  service.run();\n}\n",
        )
        .build();

    let line = "  service.run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Service.run", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.ts", "{value}");
}

#[test]
fn typescript_interface_typed_parameter_property_resolves_to_declaration() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "api.ts",
            "export interface User {\n  id: string;\n  name: string;\n}\n",
        )
        .file(
            "app.ts",
            "import { User } from './api';\nfunction show(user: User) {\n  return user.name;\n}\n",
        )
        .build();

    let line = "  return user.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":3,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User.name", "{value}");
    assert_eq!(result["definitions"][0]["path"], "api.ts", "{value}");
}

#[test]
fn typescript_type_alias_typed_parameter_property_resolves_to_declaration() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "components.tsx",
            r#"
export type User = {
  id: string;
  name: string;
};
"#,
        )
        .file(
            "app.tsx",
            "import { type User } from './components';\ndeclare const user: User;\nconst label = user.name;\n",
        )
        .build();

    let line = "const label = user.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.tsx","line":3,"column":{}}}]}}"#,
            column_of(line, ".name") + 1
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "components.tsx.User.name",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "components.tsx",
        "{value}"
    );
}

#[test]
fn typescript_type_alias_typed_parameter_member_resolves_to_declaration() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "components.tsx",
            r#"
export type User = {
  id: string;
  name: string;
};

export function formatName(user: User): string {
  return user.name.trim();
}
"#,
        )
        .build();

    let line = "  return user.name.trim();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"components.tsx","line":8,"column":{}}}]}}"#,
            column_of(line, ".name") + 1
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "components.tsx.User.name",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "components.tsx",
        "{value}"
    );
}

#[test]
fn typescript_declared_return_object_key_resolves_to_interface_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "api.ts",
            "export interface User {\n  id: string;\n  name: string;\n}\nexport class ApiClient {\n  makeUser(): User {\n    return { id: '', name: this.baseUrl };\n  }\n}\n",
        )
        .build();

    let line = "    return { id: '', name: this.baseUrl };";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"api.ts","line":7,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "User.name", "{value}");
    assert_eq!(result["definitions"][0]["path"], "api.ts", "{value}");
}

#[test]
fn typescript_static_method_call_resolves_to_static_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "api.ts",
            r#"
export class ApiClient {
  static create(baseUrl: string): ApiClient {
    return new ApiClient(baseUrl);
  }
  constructor(readonly baseUrl: string) {}
}

export function boot() {
  return ApiClient.create("/api");
}
"#,
        )
        .build();

    let line = "  return ApiClient.create(\"/api\");";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"api.ts","line":10,"column":{}}}]}}"#,
            column_of(line, "create")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ApiClient.create$static",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "api.ts", "{value}");
}

#[test]
fn typescript_imported_static_member_keeps_receiver_file_identity() {
    let app = r#"
import { KibanaServices as SecurityServices } from "./security/services";
import CasesServices from "./cases/services";

export function boot() {
  SecurityServices.get();
  CasesServices.get();
}
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "security/services.ts",
            "export class KibanaServices { static get() {} }\n",
        )
        .file(
            "cases/services.ts",
            "export default class KibanaServices { static get() {} }\n",
        )
        .file("app.ts", app)
        .build();

    for (receiver, expected_path) in [
        ("SecurityServices", "security/services.ts"),
        ("CasesServices", "cases/services.ts"),
    ] {
        let start = app.find(&format!("{receiver}.get")).expect("static call") + receiver.len() + 1;
        let value = lookup(project.root(), &location_reference("app.ts", app, start));
        let result = &value["results"][0];

        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().unwrap().len(),
            1,
            "{value}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"], "KibanaServices.get$static",
            "{value}"
        );
        assert_eq!(result["definitions"][0]["path"], expected_path, "{value}");
    }
}

#[test]
fn typescript_parameter_shadow_blocks_outer_factory_receiver_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            "export class Service { run() {} }\nexport class Other { run() {} }\nexport function makeService() { return new Service(); }\nconst service = makeService();\nexport function caller(service: Other) {\n  service.run();\n}\n",
        )
        .build();

    let line = "  service.run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Other.run", "{value}");
    assert!(
        value.to_string().find("Service.run").is_none(),
        "parameter receiver must not resolve through the outer Service factory: {value}"
    );
}

#[test]
fn ts_function_local_use_does_not_leak_to_sibling_function_type_lookup() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "class Widget {}\nfunction first(value: Widget) { return value; }\nfunction second() { const value = 1; return value; }\n",
        )
        .build();

    let line = "function second() { const value = 1; return value; }";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":3,"column":{}}}]}}"#,
            column_of(line, "value;")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "no_explicit_type",
        "{value}"
    );
}

#[test]
fn ts_block_local_use_does_not_leak_to_outer_type_lookup() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "class Widget {}\nfunction run(ok: boolean) {\n  if (ok) { const value: Widget = new Widget(); }\n  return value;\n}\n",
        )
        .build();

    let line = "  return value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":4,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "no_explicit_type",
        "{value}"
    );
}

#[test]
fn ts_nested_function_can_use_outer_typed_binding_for_type_lookup() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "class Widget {}\nfunction outer(value: Widget) {\n  function inner() {\n    return value;\n  }\n}\n",
        )
        .build();

    let line = "    return value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":4,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
}

#[test]
fn ts_type_lookup_resolves_destructured_parameter_property_type() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "class Widget {}\nfunction render({ value }: { value: Widget }) {\n  return value;\n}\n",
        )
        .build();

    let line = "  return value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
}

#[test]
fn ts_type_lookup_resolves_namespace_imported_type_annotation() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("model.ts", "export class Widget {}\n")
        .file(
            "app.ts",
            "import * as Models from './model';\nconst value: Models.Widget = new Models.Widget();\nvalue;\n",
        )
        .build();

    let line = "value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "model.ts",
        "{value}"
    );
}

#[test]
fn ts_type_lookup_resolves_return_type_annotation_wrapper() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            "class Widget {}\nfunction makeWidget(): Widget { return new Widget(); }\nconst value: ReturnType<typeof makeWidget> = makeWidget();\nvalue;\n",
        )
        .build();

    let line = "value;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":4,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Widget", "{value}");
}

#[test]
fn javascript_type_lookup_reports_no_declared_type() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", "const value = new Widget();\nclass Widget {}\n")
        .build();

    let value = lookup_type(
        project.root(),
        r#"{"references":[{"path":"app.js","line":1,"column":7}]}"#,
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(result["reference"]["target"], "value", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "javascript_declared_type_unsupported",
        "{value}"
    );
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("type diagnostic");
    assert!(
        message.contains("Requested location: app.js:1:7"),
        "{message}"
    );
    assert!(
        message.contains("> 1 | const value = new Widget();"),
        "{message}"
    );
    assert!(
        message.contains("^ requested line 1, column 7"),
        "{message}"
    );
    assert!(message.contains("retry get_type_by_location"), "{message}");
}

#[test]
fn type_lookup_reports_invalid_location_before_language_diagnostics() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", "const value = new Widget();\nclass Widget {}\n")
        .build();

    let value = lookup_type(
        project.root(),
        r#"{"references":[{"path":"app.js","line":99,"column":1}]}"#,
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "invalid_location", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "invalid_location",
        "{value}"
    );
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("invalid-location diagnostic");
    assert!(
        message.contains("Requested location: app.js:99:1"),
        "{message}"
    );
    assert!(message.contains("  2 | class Widget {}"), "{message}");
    assert!(
        message.contains("> 99 | [requested line is after the last source line]"),
        "{message}"
    );
}

#[test]
fn go_type_lookup_resolves_imported_explicit_local_type() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "store/store.go",
            r#"
package store

type Client struct{}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "example.com/app/store"

func Run() {
    var client store.Client
    _ = client
}
"#,
        )
        .build();

    let line = "    _ = client";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":8,"column":{}}}]}}"#,
            column_of(line, "client")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["types"][0]["fqn"], "example.com/app/store.Client",
        "{value}"
    );
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "store/store.go",
        "{value}"
    );
}

#[test]
fn java_type_lookup_resolves_imported_explicit_local_type() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "models/Widget.java",
            "package models; public class Widget {}\n",
        )
        .file(
            "app/UseWidget.java",
            r#"
package app;

import models.Widget;

public class UseWidget {
    public void render(Widget input) {
        Widget local = input;
        local.toString();
    }
}
"#,
        )
        .build();

    let line = "        local.toString();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseWidget.java","line":9,"column":{}}}]}}"#,
            column_of(line, "local")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "models.Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "models/Widget.java",
        "{value}"
    );
}

#[test]
fn java_type_lookup_reports_no_type_for_inferred_local() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "models/Widget.java",
            "package models; public class Widget {}\n",
        )
        .file(
            "app/UseWidget.java",
            r#"
package app;

import models.Widget;

public class UseWidget {
    public void render() {
        var local = new Widget();
        local.toString();
    }
}
"#,
        )
        .build();

    let line = "        local.toString();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseWidget.java","line":9,"column":{}}}]}}"#,
            column_of(line, "local")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "no_explicit_type",
        "{value}"
    );
}

#[test]
fn java_type_lookup_does_not_leak_sibling_method_local_type() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "models/Label.java",
            "package models; public class Label {}\n",
        )
        .file(
            "models/Widget.java",
            "package models; public class Widget {}\n",
        )
        .file(
            "app/UseWidget.java",
            r#"
package app;

import models.Label;
import models.Widget;

public class UseWidget {
    private Label value;

    public void seed() {
        Widget value = new Widget();
        value.toString();
    }

    public void render() {
        value.toString();
    }
}
"#,
        )
        .build();

    let line = "        value.toString();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseWidget.java","line":16,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "models.Label", "{value}");
}

#[test]
fn java_type_lookup_resolves_explicit_method_return_type() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "models/Widget.java",
            "package models; public class Widget {}\n",
        )
        .file(
            "app/UseWidget.java",
            r#"
package app;

import models.Widget;

public class UseWidget {
    public Widget create() {
        return new Widget();
    }
}
"#,
        )
        .build();

    let line = "    public Widget create() {";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseWidget.java","line":7,"column":{}}}]}}"#,
            column_of(line, "Widget")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "models.Widget", "{value}");
}

#[test]
fn java_type_lookup_reports_no_type_for_method_declaration_name() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "models/Widget.java",
            "package models; public class Widget {}\n",
        )
        .file(
            "app/UseWidget.java",
            r#"
package app;

import models.Widget;

public class UseWidget {
    public Widget create() {
        return new Widget();
    }
}
"#,
        )
        .build();

    let line = "    public Widget create() {";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseWidget.java","line":7,"column":{}}}]}}"#,
            column_of(line, "create")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "inappropriate_symbol_context",
        "{value}"
    );
}

#[test]
fn java_type_lookup_bare_local_named_type_does_not_become_default_package_class() {
    let source = r#"
package app;

import models.Widget;

public class UseWidget {
    public Widget render() {
        Widget type = new Widget();
        return type;
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("type.java", "public class type {}\n")
        .file(
            "models/Widget.java",
            "package models; public class Widget {}\n",
        )
        .file("app/UseWidget.java", source)
        .build();

    let value = lookup_type(
        project.root(),
        &location_reference(
            "app/UseWidget.java",
            source,
            source.rfind("type;").expect("bare local expression"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "models.Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "models/Widget.java",
        "{value}"
    );
}

#[test]
fn csharp_type_lookup_resolves_using_explicit_parameter_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Models/Widget.cs",
            "namespace Models { public class Widget {} }\n",
        )
        .file(
            "App/UseWidget.cs",
            r#"
using Models;

namespace App {
    public class UseWidget {
        public void Render(Widget input) {
            input.ToString();
        }
    }
}
"#,
        )
        .build();

    let line = "            input.ToString();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/UseWidget.cs","line":7,"column":{}}}]}}"#,
            column_of(line, "input")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Models.Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "Models/Widget.cs",
        "{value}"
    );
}

#[test]
fn csharp_attribute_shorthand_type_lookup_prefers_imported_attribute_suffix() {
    let source = r#"
using System.Management.Automation;

namespace Demo.Runtime.PowerShell {
    internal class Parameter { }

    [Parameter]
    public sealed class ExportProxyCmdlet { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "Automation/ParameterAttribute.cs",
            "namespace System.Management.Automation { public class ParameterAttribute : System.Attribute { } }\n",
        )
        .file("Generated/ExportProxyCmdlet.cs", source)
        .build();

    let attribute = source.find("Parameter]").expect("attribute shorthand");
    let value = lookup_type(
        project.root(),
        &location_reference("Generated/ExportProxyCmdlet.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["types"][0]["fqn"], "System.Management.Automation.ParameterAttribute",
        "{value}"
    );
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "Automation/ParameterAttribute.cs",
        "{value}"
    );
}

#[test]
fn csharp_type_lookup_preserves_ambiguous_visible_type_candidates() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("A/Widget.cs", "namespace A { public class Widget {} }\n")
        .file("B/Widget.cs", "namespace B { public class Widget {} }\n")
        .file(
            "App/UseWidget.cs",
            r#"
using A;
using B;

namespace App {
    public class UseWidget {
        public void Render(Widget input) {
            input.ToString();
        }
    }
}
"#,
        )
        .build();

    let line = "            input.ToString();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/UseWidget.cs","line":8,"column":{}}}]}}"#,
            column_of(line, "input")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    let definitions = result["types"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    assert_eq!(definitions.len(), 2, "{value}");
}

#[test]
fn csharp_type_lookup_selects_same_fqn_candidate_by_generic_arity() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Models/Box.cs",
            "namespace Models { public class Box {} }\n",
        )
        .file(
            "Models/GenericBox.cs",
            "namespace Models { public class Box<T> {} }\n",
        )
        .file(
            "App/UseBox.cs",
            r#"
using Models;

namespace App {
    public class UseBox {
        public void Render(Box<int> input) {
            input.ToString();
        }
    }
}

"#,
        )
        .build();

    let line = "            input.ToString();";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/UseBox.cs","line":7,"column":{}}}]}}"#,
            column_of(line, "input")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    let definitions = result["types"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    assert_eq!(definitions.len(), 1, "{value}");
    assert_eq!(definitions[0]["path"], "Models/GenericBox.cs", "{value}");
}

#[test]
fn csharp_type_lookup_does_not_normalize_an_exact_arity_miss() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "N/GenericBox.cs",
            "namespace N { public class Box<T> {} }\n",
        )
        .file(
            "Imported/Box.cs",
            "namespace Imported { public class Box {} }\n",
        )
        .file(
            "N/UseBox.cs",
            "using Imported;\nnamespace N { public class UseBox { public void Read(Box input) { input.ToString(); } } }\n",
        )
        .build();
    let line =
        "namespace N { public class UseBox { public void Read(Box input) { input.ToString(); } } }";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"N/UseBox.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "input.ToString")
        ),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["types"][0]["fqn"], "Imported.Box",
        "{value}"
    );
}

#[test]
fn csharp_global_qualified_simple_type_bypasses_current_namespace() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Box.cs", "public class Box {}\n")
        .file(
            "N/Box.cs",
            "namespace N { public class Box<T> {} }\n",
        )
        .file(
            "N/UseBox.cs",
            "namespace N { public class UseBox { public void Read(global::Box input) { input.ToString(); } } }\n",
        )
        .build();
    let line = "namespace N { public class UseBox { public void Read(global::Box input) { input.ToString(); } } }";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"N/UseBox.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "input.ToString")
        ),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(value["results"][0]["types"][0]["fqn"], "Box", "{value}");
}

#[test]
fn csharp_dotted_type_lookup_allows_imported_nested_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Imported/ImportedOwner.cs",
            "namespace Imported { public class ImportedOwner { public class Nested { } } }\n",
        )
        .file(
            "App/Consumer.cs",
            "using Imported;\nnamespace App { public class Consumer { public void Read(ImportedOwner.Nested input) { input.ToString(); } } }\n",
        )
        .build();
    let line = "namespace App { public class Consumer { public void Read(ImportedOwner.Nested input) { input.ToString(); } } }";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "input.ToString")
        ),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["types"][0]["fqn"], "Imported.ImportedOwner$Nested",
        "{value}"
    );
}

#[test]
fn csharp_dotted_type_lookup_does_not_import_child_namespace() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Imported/System/String.cs",
            "namespace Imported.System { public class String { } }\n",
        )
        .file(
            "System/String.cs",
            "namespace System { public class String { } }\n",
        )
        .file(
            "App/Consumer.cs",
            "using Imported;\nnamespace App { public class Consumer { public void Read(System.String input) { input.ToString(); } } }\n",
        )
        .build();
    let line = "namespace App { public class Consumer { public void Read(System.String input) { input.ToString(); } } }";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "input.ToString")
        ),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["types"][0]["fqn"], "System.String",
        "{value}"
    );
}

#[test]
fn csharp_type_lookup_preserves_partial_declaration_locations() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "src/Handlers.cs",
            r#"namespace Demo;

public partial class EventRecord
{
    public string Name { get; set; }
}
"#,
        )
        .file(
            "src/Consumers.cs",
            r#"namespace Demo;

public partial class EventRecord
{
    public string Label()
    {
        return Name;
    }
}

public sealed class Consumer
{
    public string Render(EventRecord record)
    {
        return record.Name;
    }
}
"#,
        )
        .build();

    let line = "        return record.Name;";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Consumers.cs","line":15,"column":{}}}]}}"#,
            column_of(line, "record")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "Demo.EventRecord", "{value}");
    let definitions = result["types"][0]["definitions"]
        .as_array()
        .expect("definitions array");
    assert_eq!(definitions.len(), 2, "{value}");
    assert!(
        definitions
            .iter()
            .any(|definition| definition["path"] == "src/Handlers.cs"),
        "{value}"
    );
    assert!(
        definitions
            .iter()
            .any(|definition| definition["path"] == "src/Consumers.cs"),
        "{value}"
    );
}

#[test]
fn csharp_type_lookup_reports_no_type_for_method_declaration_name() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Models/Widget.cs",
            "namespace Models { public class Widget {} }\n",
        )
        .file(
            "App/UseWidget.cs",
            r#"
using Models;

namespace App {
    public class UseWidget {
        public Widget Create() {
            return new Widget();
        }
    }
}
"#,
        )
        .build();

    let line = "        public Widget Create() {";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/UseWidget.cs","line":6,"column":{}}}]}}"#,
            column_of(line, "Create")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "inappropriate_symbol_context",
        "{value}"
    );
}

#[test]
fn scala_type_lookup_resolves_imported_explicit_val_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("models/Widget.scala", "package models\nclass Widget\n")
        .file(
            "app/UseWidget.scala",
            r#"
package app

import models.Widget

class UseWidget {
  def render(input: Widget): Unit = {
    val local: Widget = input
    local.toString
  }
}
"#,
        )
        .build();

    let line = "    local.toString";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseWidget.scala","line":9,"column":{}}}]}}"#,
            column_of(line, "local")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["types"][0]["fqn"], "models.Widget", "{value}");
    assert_eq!(
        result["types"][0]["definitions"][0]["path"], "models/Widget.scala",
        "{value}"
    );
}

#[test]
fn scala_type_lookup_reports_no_type_for_function_declaration_name() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("models/Widget.scala", "package models\nclass Widget\n")
        .file(
            "app/UseWidget.scala",
            r#"
package app

import models.Widget

class UseWidget {
  def create(): Widget = new Widget
}
"#,
        )
        .build();

    let line = "  def create(): Widget = new Widget";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseWidget.scala","line":7,"column":{}}}]}}"#,
            column_of(line, "create")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "inappropriate_symbol_context",
        "{value}"
    );
}

#[test]
fn go_type_lookup_resolves_short_var_composite_literals() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Client struct{}

func Run() {
    value := Client{}
    _ = value
    pointer := &Client{}
    _ = pointer
}
"#,
        )
        .build();

    for (line_no, line, name) in [
        (8, "    _ = value", "value"),
        (10, "    _ = pointer", "pointer"),
    ] {
        let value = lookup_type(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"main.go","line":{line_no},"column":{}}}]}}"#,
                column_of(line, name)
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["types"][0]["fqn"], "example.com/app.Client",
            "{value}"
        );
    }
}

#[test]
fn go_type_lookup_resolves_composite_literal_expression_type() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Client struct{}

func Run() {
    _ = Client{}
}
"#,
        )
        .build();

    let line = "    _ = Client{}";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Client")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["types"][0]["fqn"], "example.com/app.Client",
        "{value}"
    );
}

#[test]
fn go_type_lookup_resolves_function_call_return_type() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Client struct{}

func NewClient() Client {
    return Client{}
}

func Run() {
    _ = NewClient()
}
"#,
        )
        .build();

    let line = "    _ = NewClient()";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":11,"column":{}}}]}}"#,
            column_of(line, "NewClient")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["types"][0]["fqn"], "example.com/app.Client",
        "{value}"
    );
}

#[test]
fn go_type_lookup_resolves_parameters_and_receivers() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Client struct{}

func Use(client Client) {
    _ = client
}

func (client Client) Run() {
    _ = client
}
"#,
        )
        .build();

    for (line_no, line) in [(7, "    _ = client"), (11, "    _ = client")] {
        let value = lookup_type(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"main.go","line":{line_no},"column":{}}}]}}"#,
                column_of(line, "client")
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["types"][0]["fqn"], "example.com/app.Client",
            "{value}"
        );
    }
}

#[test]
fn go_type_lookup_resolves_selector_receiver_and_field_type() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Profile struct{}

type Client struct {
    Profile Profile
}

func Run(client Client) {
    _ = client.Profile
}
"#,
        )
        .build();

    let line = "    _ = client.Profile";
    let receiver_value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":11,"column":{}}}]}}"#,
            column_of(line, "client")
        ),
    );
    let receiver_result = &receiver_value["results"][0];
    assert_eq!(receiver_result["status"], "resolved", "{receiver_value}");
    assert_eq!(
        receiver_result["types"][0]["fqn"], "example.com/app.Client",
        "{receiver_value}"
    );

    let field_value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":11,"column":{}}}]}}"#,
            column_of(line, "Profile")
        ),
    );
    let field_result = &field_value["results"][0];
    assert_eq!(field_result["status"], "resolved", "{field_value}");
    assert_eq!(
        field_result["types"][0]["fqn"], "example.com/app.Profile",
        "{field_value}"
    );
}

#[test]
fn go_type_lookup_reports_interface_method_owner() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Runner interface {
    Run() error
}
"#,
        )
        .build();

    let line = "    Run() error";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":5,"column":{}}}]}}"#,
            column_of(line, "Run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["types"][0]["fqn"], "example.com/app.Runner",
        "{value}"
    );
    assert_eq!(
        result["diagnostics"][0]["kind"], "go_interface_method_owner",
        "{value}"
    );
}

#[test]
fn go_type_lookup_reports_no_type_for_unsupported_inference() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

func external() any { return nil }

func Run() {
    value := external()
    _ = value
}
"#,
        )
        .build();

    let line = "    _ = value";
    let value = lookup_type(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":8,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_type", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "go_no_supported_type",
        "{value}"
    );
}

#[test]
fn type_lookup_rejects_oversized_batches() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub struct Widget;\n")
        .build();

    let references = (0..101)
        .map(|_| r#"{"path":"lib.rs","line":1,"column":12}"#)
        .collect::<Vec<_>>()
        .join(",");
    let value = lookup_type(
        project.root(),
        &format!(r#"{{"references":[{references}]}}"#),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "invalid_location", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "too_many_references",
        "{value}"
    );
}

#[test]
fn definition_lookup_rejects_oversized_batches() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub struct Widget;\n")
        .build();

    let references = (0..101)
        .map(|_| r#"{"path":"lib.rs","line":1,"column":12}"#)
        .collect::<Vec<_>>()
        .join(",");
    let value = lookup(
        project.root(),
        &format!(r#"{{"references":[{references}]}}"#),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "invalid_location", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "too_many_references",
        "{value}"
    );
}

#[test]
fn rust_grouped_crate_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod env;\n")
        .file("src/env.rs", "pub fn env_init() {}\n")
        .file(
            "src/bin/app.rs",
            r#"
use app::{
    env::{env_init},
};

fn main() {
    env_init();
}
"#,
        )
        .build();

    let line = "    env_init();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/bin/app.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "env_init")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/env.rs", "{value}");
}

#[test]
fn rust_glob_import_resolves_public_export_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "mod service;\n")
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Foo", "{value}");
}

#[test]
fn rust_function_local_dependency_glob_beats_same_named_crate_module_for_scoped_owner() {
    let source = r#"
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_task() {
        use tokio_test::*;

        let mut task = task::spawn();
        let _ = &mut task;
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"tokio\", \"tokio-test\"]\nresolver = \"2\"\n\n[patch.crates-io]\ntokio-test = { path = \"tokio-test\" }\n",
        )
        .file(
            "tokio-test/Cargo.toml",
            "[package]\nname = \"tokio-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("tokio-test/src/lib.rs", "pub mod task;\n")
        .file("tokio-test/src/task.rs", "pub fn spawn() {}\n")
        .file(
            "tokio/Cargo.toml",
            "[package]\nname = \"tokio\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dev-dependencies]\ntokio-test = \"0.1.0\"\n",
        )
        .file("tokio/src/lib.rs", "pub mod task;\n")
        .file("tokio/src/task/mod.rs", "pub mod coop;\n")
        .file("tokio/src/task/coop/mod.rs", source)
        .build();

    let start = source.find("task::spawn").expect("scoped task reference");
    let value = lookup(
        project.root(),
        &location_reference("tokio/src/task/coop/mod.rs", source, start),
    );
    let result = &value["results"][0];

    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "tokio-test/src/lib.rs",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "tokio-test.src.task",
        "{value}"
    );
}

#[test]
fn rust_current_module_item_beats_glob_import_for_scoped_owner() {
    let source = r#"
mod imported {
    pub mod task {
        pub fn spawn() {}
    }
}
use imported::*;

mod task {
    pub fn spawn() {}
}

fn run() {
    task::spawn();
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("main.rs", source)
        .build();

    let start = source.find("task::spawn").expect("scoped task reference");
    let value = lookup(
        project.root(),
        &location_reference("main.rs", source, start),
    );
    let result = &value["results"][0];

    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "task", "{value}");
}

#[test]
fn rust_bare_name_does_not_cross_independent_cargo_example_targets() {
    let source = "fn use_it(_: Args) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"examples\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", "pub fn library() {}\n")
        .file("examples/a.rs", source)
        .file("examples/b.rs", "struct Args;\n")
        .build();

    let start = source.find("Args").expect("bare type reference");
    let value = lookup(
        project.root(),
        &location_reference("examples/a.rs", source, start),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_path_module_reference_keeps_the_current_example_declaration_identity() {
    let first = r#"
#[path = "shared.rs"]
mod shared;

fn run() {
    shared::exercise();
}
"#;
    let second = r#"
#[path = "shared.rs"]
mod shared;

fn run() {
    shared::exercise();
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"examples\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", "pub fn library() {}\n")
        .file("examples/first.rs", first)
        .file("examples/second.rs", second)
        .file("examples/shared.rs", "pub fn exercise() {}\n")
        .build();

    let start = first.find("shared::exercise").expect("module reference");
    let value = lookup(
        project.root(),
        &location_reference("examples/first.rs", first, start),
    );
    let result = &value["results"][0];

    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "examples.shared",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "examples/first.rs",
        "{value}"
    );
}

#[test]
fn rust_glob_import_does_not_resolve_private_name() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "struct Hidden;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let _ = Hidden {};
}
"#,
        )
        .build();

    let line = "    let _ = Hidden {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "Hidden")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_glob_reexport_resolves_to_original_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file("index.rs", "pub use crate::service::*;\n")
        .file(
            "main.rs",
            r#"
mod service;
mod index;
use crate::index::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_local_binding_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let Foo = ();
    let _ = Foo;
}
"#,
        )
        .build();

    let line = "    let _ = Foo;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_explicit_import_takes_precedence_over_glob_import() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "main.rs",
            r#"
mod private_mod {
    pub struct Foo;
}
mod public_mod {
    pub struct Foo;
}
use crate::private_mod::Foo;
use crate::public_mod::*;

fn run() {
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":12,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "private_mod.Foo",
        "{value}"
    );
}

#[test]
fn rust_struct_pattern_type_name_does_not_shadow_glob_import() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo { pub value: i32 }\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn input() -> Foo {
    todo!()
}

fn run() {
    let Foo { value } = input();
}
"#,
        )
        .build();

    let line = "    let Foo { value } = input();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":10,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_local_item_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    struct Foo;
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_let_binding_does_not_shadow_own_initializer() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let Foo = Foo {};
}
"#,
        )
        .build();

    let line = "    let Foo = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "= Foo") + 2
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_inner_block_binding_does_not_shadow_after_block() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    {
        let Foo = ();
    }
    let _ = Foo {};
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_later_local_item_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

fn run() {
    let _ = Foo {};
    struct Foo;
}
"#,
        )
        .build();

    let line = "    let _ = Foo {};";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_tuple_struct_pattern_binding_shadows_glob_imported_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("service.rs", "pub struct Foo;\n")
        .file(
            "main.rs",
            r#"
mod service;
use crate::service::*;

struct Pair<T>(T);

fn input() -> Pair<()> {
    todo!()
}

fn run() {
    let Pair(Foo) = input();
    let _ = Foo;
}
"#,
        )
        .build();

    let line = "    let _ = Foo;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.rs","line":13,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_if_let_binding_scope_and_constructor_owner_by_location() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
struct Some(i32);

fn range() {}
fn input() -> Some { todo!() }

fn demo() {
    if let Some(range) = input() {
        let _inside = range;
    } else {
        let _else = range;
    }
    let _after = range;
}

"#,
        )
        .build();

    for (line, text, needle, expected_status) in [
        (
            8,
            "    if let Some(range) = input() {",
            "range",
            "no_definition",
        ),
        (9, "        let _inside = range;", "range", "no_definition"),
        (11, "        let _else = range;", "range", "resolved"),
        (13, "    let _after = range;", "range", "resolved"),
    ] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"lib.rs","line":{line},"column":{}}}]}}"#,
                column_of(text, needle)
            ),
        );
        assert_eq!(
            value["results"][0]["status"], expected_status,
            "line {line}: {value}"
        );
        if expected_status == "resolved" {
            assert_eq!(value["results"][0]["definitions"][0]["fqn"], "range");
        } else {
            assert_eq!(
                value["results"][0]["diagnostics"][0]["kind"], "local_binding",
                "line {line}: {value}"
            );
        }
    }

    let constructor = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":8,"column":{}}}]}}"#,
            column_of("    if let Some(range) = input() {", "Some")
        ),
    );
    assert_eq!(
        constructor["results"][0]["status"], "resolved",
        "{constructor}"
    );
    assert_eq!(
        constructor["results"][0]["definitions"][0]["fqn"], "Some",
        "{constructor}"
    );
}

#[test]
fn rust_scoped_if_let_variant_is_not_a_local_pattern_binding() {
    let source = r#"
enum Foo { Bar }
fn input() -> Foo { Foo::Bar }
fn demo() {
    if let Foo::Bar = input() {}
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();
    let reference = source.rfind("Foo::Bar").expect("if-let variant") + "Foo::".len();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", source, reference),
    );

    assert_ne!(
        value["results"][0]["diagnostics"][0]["kind"], "local_binding",
        "a scoped pattern path is not a local binding: {value}"
    );
}

#[test]
fn rust_while_let_binding_scope_by_reference() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
fn item() {}
fn next() -> Option<i32> { todo!() }

fn demo() {
    while let Some(item) = next() {
        let _while_body = item;
        break;
    }
    let _while_after = item;
}
"#,
        )
        .build();

    for (context, target, expected_status) in [
        ("while let Some(item) = next() {", "item", "no_definition"),
        ("let _while_body = item;", "item", "no_definition"),
        ("let _while_after = item;", "item", "resolved"),
    ] {
        let value = lookup_reference(
            project.root(),
            &json!({
                "references": [{
                    "symbol": "demo",
                    "context": context,
                    "target": target
                }]
            })
            .to_string(),
        );
        assert_eq!(
            value["results"][0]["status"], expected_status,
            "{context}: {value}"
        );
        if expected_status == "resolved" {
            assert_eq!(value["results"][0]["definitions"][0]["fqn"], "item");
        } else {
            assert_eq!(
                value["results"][0]["diagnostics"][0]["kind"], "local_binding",
                "{context}: {value}"
            );
        }
    }
}

#[test]
fn rust_let_chain_bindings_are_visible_in_order() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
fn first() {}
fn second() {}
fn input(_: fn()) -> Option<Option<i32>> { todo!() }

fn demo() {
    if let Some(first) = input(second)
        && let Some(second) = first
        && second > 0
    {
        let _chain_body = (first, second);
    }
    let _chain_after = (first, second);
}
"#,
        )
        .build();

    for (context, target, expected_status) in [
        ("&& let Some(second) = first", "second", "no_definition"),
        ("&& let Some(second) = first", "first", "no_definition"),
        ("&& second > 0", "second", "no_definition"),
        (
            "let _chain_body = (first, second);",
            "first",
            "no_definition",
        ),
        ("let _chain_after = (first, second);", "first", "resolved"),
    ] {
        let value = lookup_reference(
            project.root(),
            &json!({
                "references": [{
                    "symbol": "demo",
                    "context": context,
                    "target": target
                }]
            })
            .to_string(),
        );
        assert_eq!(
            value["results"][0]["status"], expected_status,
            "{context}: {value}"
        );
        if expected_status == "no_definition" {
            assert_eq!(
                value["results"][0]["diagnostics"][0]["kind"], "local_binding",
                "{context}: {value}"
            );
        }
    }

    let source = project
        .file("lib.rs")
        .read_to_string()
        .expect("read inline Rust source");
    let early_second = source.find("input(second)").expect("first let value") + "input(".len();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", &source, early_second),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(value["results"][0]["definitions"][0]["fqn"], "second");
}

#[test]
fn rust_reference_context_resolves_target_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::helper;

pub fn run() {
    let value = helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "let value = helper();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert!(
        result.as_object().unwrap().get("reference").is_none(),
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_prelude_some_does_not_resolve_sibling_module_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod custom {
    pub struct Some(pub u8);
}

fn demo(value: Option<u8>) {
    if let Some(inner) = value {
        let _ = inner;
    }
}
"#,
        )
        .build();

    let line = "    if let Some(inner) = value {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "Some")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_type_namespace_does_not_resolve_same_file_enum_variant() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
enum Binding {
    String(&'static str),
}

fn demo(value: Option<String>) {
    let _ = value;
}
"#,
        )
        .build();

    let line = "fn demo(value: Option<String>) {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "String")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_same_module_custom_constructor_still_resolves() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
struct Some(u8);

fn demo() -> Some {
    Some(1)
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "demo",
                "context": "Some(1)",
                "target": "Some"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Some", "{value}");
}

#[test]
fn rust_explicit_unresolved_import_does_not_fall_back_to_variant() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
use missing_crate::Pattern;

enum Position {
    Pattern,
}

fn demo(_: Pattern) {}
"#,
        )
        .build();

    let line = "fn demo(_: Pattern) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":8,"column":{}}}]}}"#,
            column_of(line, "Pattern")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn rust_workspace_import_beats_same_file_value_namespace() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"matcher\", \"core\"]\nresolver = \"2\"\n",
        )
        .file(
            "matcher/Cargo.toml",
            "[package]\nname = \"matcher\"\nversion = \"0.1.0\"\n",
        )
        .file("matcher/src/lib.rs", "pub struct Pattern;\n")
        .file(
            "core/Cargo.toml",
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\n[dependencies]\nmatcher = { path = \"../matcher\" }\n",
        )
        .file(
            "core/src/lib.rs",
            r#"
use matcher::Pattern;

enum Position {
    Pattern,
}

fn demo(_: Pattern) {}
"#,
        )
        .build();

    let line = "fn demo(_: Pattern) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"core/src/lib.rs","line":8,"column":{}}}]}}"#,
            column_of(line, "Pattern")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "matcher/src/lib.rs",
        "{value}"
    );
}

#[test]
fn rust_focused_use_paths_resolve_exact_cargo_targets_without_flat_collisions() {
    let app_source = r#"
struct Commands {
    Auth: usize,
    path: usize,
}

fn imports() {
    use grit_util::{error::GritResult, auth::{Auth, Other}};
    use std::{path::PathBuf};
}
"#;
    let project = InlineTestProject::new()
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"grit-util\"]\nresolver = \"2\"\n",
        )
        .file(
            "grit-util/Cargo.toml",
            "[package]\nname = \"grit-util\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "grit-util/src/lib.rs",
            "pub mod auth;\npub mod error;\n",
        )
        .file(
            "grit-util/src/auth.rs",
            "pub struct Auth;\npub struct Other;\n",
        )
        .file("grit-util/src/error.rs", "pub struct GritResult;\n")
        .file(
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ngrit-util = { path = \"../grit-util\" }\n",
        )
        .file("app/src/lib.rs", app_source)
        .file("foreign.cpp", "struct error {};\n")
        .build();

    for (needle, expected_fqn, expected_path) in [
        (
            "error::GritResult",
            "grit-util.src.error",
            "grit-util/src/lib.rs",
        ),
        (
            "Auth, Other",
            "grit-util.src.auth.Auth",
            "grit-util/src/auth.rs",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference(
                "app/src/lib.rs",
                app_source,
                app_source.find(needle).unwrap(),
            ),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{needle}: {value}");
        assert_eq!(result["definitions"][0]["fqn"], expected_fqn, "{value}");
        assert_eq!(result["definitions"][0]["path"], expected_path, "{value}");
    }

    let value = lookup(
        project.root(),
        &location_reference(
            "app/src/lib.rs",
            app_source,
            app_source.find("path::PathBuf").unwrap(),
        ),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "imports",
                "context": "    use grit_util::{error::GritResult, auth::{Auth, Other}};",
                "target": "error"
            }]
        })
        .to_string(),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "grit-util.src.error",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "grit-util/src/lib.rs",
        "{value}"
    );
}

#[test]
fn rust_focused_reexport_module_segment_does_not_collapse_to_terminal_function() {
    let source = "mod copy;\npub use self::copy::copy;\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"focused-use\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", source)
        .file("src/copy.rs", "pub fn copy() {}\n")
        .build();
    let focused = source
        .find("copy::copy")
        .expect("nonterminal module segment");

    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, focused),
    );
    let result = &value["results"][0];

    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "module", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/lib.rs", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "copy", "{value}");
}

#[test]
fn rust_cargo_dependency_kinds_scope_public_forward_resolution() {
    let library = r#"
fn normal(_: normal_dep::Shared) {}

#[cfg(test)]
mod tests {
    fn development(_: dev_dep::Shared) {}
}

fn invalid_build(_: build_dep::Shared) {}
"#;
    let example = "fn development(_: dev_dep::Shared) {}\n";
    let build_script =
        "fn build_only(_: build_dep::Shared) {}\nfn invalid_normal(_: normal_dep::Shared) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"normal\", \"development\", \"build-dep\"]\nresolver = \"2\"\n",
        )
        .file(
            "normal/Cargo.toml",
            "[package]\nname = \"normal-package\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("normal/src/lib.rs", "pub struct Shared;\n")
        .file(
            "development/Cargo.toml",
            "[package]\nname = \"development-package\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("development/src/lib.rs", "pub struct Shared;\n")
        .file(
            "build-dep/Cargo.toml",
            "[package]\nname = \"build-package\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("build-dep/src/lib.rs", "pub struct Shared;\n")
        .file(
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nnormal_dep = { package = \"normal-package\", path = \"../normal\" }\n\n[dev-dependencies]\ndev_dep = { package = \"development-package\", path = \"../development\" }\n\n[build-dependencies]\nbuild_dep = { package = \"build-package\", path = \"../build-dep\" }\n",
        )
        .file("app/src/lib.rs", library)
        .file("app/examples/demo.rs", example)
        .file("app/build.rs", build_script)
        .build();

    for (path, source, needle, expected_path) in [
        (
            "app/src/lib.rs",
            library,
            "normal_dep::Shared",
            "normal/src/lib.rs",
        ),
        (
            "app/src/lib.rs",
            library,
            "dev_dep::Shared",
            "development/src/lib.rs",
        ),
        (
            "app/examples/demo.rs",
            example,
            "dev_dep::Shared",
            "development/src/lib.rs",
        ),
        (
            "app/build.rs",
            build_script,
            "build_dep::Shared",
            "build-dep/src/lib.rs",
        ),
    ] {
        let start = source.find(needle).expect("reference") + needle.find("Shared").unwrap();
        let value = lookup(project.root(), &location_reference(path, source, start));
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["path"], expected_path,
            "{value}"
        );
    }

    for (path, source, needle) in [
        ("app/src/lib.rs", library, "build_dep::Shared"),
        ("app/build.rs", build_script, "normal_dep::Shared"),
    ] {
        let start =
            source.find(needle).expect("invalid reference") + needle.find("Shared").unwrap();
        let value = lookup(project.root(), &location_reference(path, source, start));
        assert_ne!(value["results"][0]["status"], "resolved", "{value}");
        assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
    }
}

#[test]
fn rust_definition_fallback_respects_reference_roles_and_local_bindings() {
    let source = r#"
macro_rules! local_macro { () => {} }

trait Values { type Item; }
trait Borrowed<'a> {}
trait Serializer { type Error; }

mod errors { pub struct Error; }
use errors::Error;
use std::sync::atomic::Ordering::*;

struct LocalSerializer;
impl Serializer for LocalSerializer { type Error = Error; }

struct Acquire { marker: usize }

struct Decoy {
    write: usize,
    Item: usize,
    writer: usize,
    root: usize,
}

impl Decoy {
    fn write(&self) {}
    fn root(&self) {}
}

fn helper() {}

fn exercise<T, W>(root: Decoy)
where
    T: Values<Item = W>,
    W: for<'writer> Borrowed<'writer>,
{
    write!("external macro");
    local_macro!();
    let Item = 1;
    let _ = Item;
    let _ = Acquire;
    let produced = &root;
    let _ = produced.root;
    let _ = root.root;
    root.write();
    helper();
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();

    for marker in [
        "write!(\"external macro\")",
        "T: Values",
        "writer> Borrowed",
        "let _ = Item",
        "let _ = Acquire",
        "produced.root",
    ] {
        let start = source.find(marker).expect("reference marker");
        let value = lookup(project.root(), &location_reference("lib.rs", source, start));
        assert_eq!(
            value["results"][0]["status"], "no_definition",
            "{marker}: {value}"
        );
    }

    for (marker, expected_fqn, expected_kind) in [
        ("local_macro!", "local_macro", "macro"),
        ("Item = W", "Values.Item", "field"),
        ("helper();", "helper", "function"),
    ] {
        let start = source.find(marker).expect("reference marker");
        let value = lookup(project.root(), &location_reference("lib.rs", source, start));
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{marker}: {value}");
        assert_eq!(
            result["definitions"][0]["fqn"], expected_fqn,
            "{marker}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["kind"], expected_kind,
            "{marker}: {value}"
        );
    }

    let receiver = source.find("root.root").expect("explicit receiver");
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", source, receiver),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "root", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "parameter", "{value}");
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");

    let method = source.rfind("root.write").expect("method call") + "root.".len();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", source, method),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Decoy.write", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "function", "{value}");

    let imported_type = source.find("= Error;").expect("associated type value") + "= ".len();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", source, imported_type),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "errors.Error", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "class", "{value}");
}

#[test]
fn rust_bare_values_inside_impl_prefer_module_constants_over_associated_constants() {
    let source = r#"
const START_FIELD: &str = "start";
const END_FIELD: &str = "end";
const VALUE_FIELD: &str = "value";

struct Spanned;

trait Deserialize {
    fn bare() -> [&'static str; 3];
}

impl Spanned {
    const START_FIELD: &str = "associated start";
    const END_FIELD: &str = "associated end";
    const VALUE_FIELD: &str = "associated value";
    fn qualified() -> [&'static str; 3] {
        [Self::START_FIELD, Self::END_FIELD, Self::VALUE_FIELD]
    }
}

impl Deserialize for Spanned {
    fn bare() -> [&'static str; 3] {
        [START_FIELD, END_FIELD, VALUE_FIELD]
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    let bare_body = source
        .find("[START_FIELD, END_FIELD, VALUE_FIELD]")
        .expect("bare constant array");
    for name in ["START_FIELD", "END_FIELD", "VALUE_FIELD"] {
        let bare = bare_body
            + source[bare_body..]
                .find(name)
                .expect("bare module constant reference");
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, bare),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{name}: {value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{name}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"],
            format!("_module_.{name}"),
            "{name}: {value}"
        );
        assert_eq!(result["definitions"][0]["kind"], "field", "{name}: {value}");

        let qualified = source
            .find(&format!("Self::{name}"))
            .expect("qualified associated constant reference")
            + "Self::".len();
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, qualified),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "Self::{name}: {value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "Self::{name}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"],
            format!("Spanned.{name}"),
            "Self::{name}: {value}"
        );
    }
}

#[test]
fn rust_child_module_scoped_root_rejects_parent_sibling_for_extern_prelude_name() {
    let source = r#"
mod toml_edit {
    pub fn local() {}
}

mod child {
    fn external() {
        toml_edit::de::from_str();
    }

    fn explicitly_local() {
        use crate::toml_edit;
        toml_edit::local();
    }
}

fn parent_local() {
    toml_edit::local();
}
"#;
    let legacy = r#"
mod toml_edit {
    pub fn local() {}
}

mod child {
    fn unresolved_without_extern_crate() {
        toml_edit::de::from_str();
    }
}
"#;
    let legacy_explicit = r#"
extern crate toml_edit;

mod child {
    fn external() {
        toml_edit::de::from_str();
    }
}
"#;
    let legacy_alias = r#"
extern crate toml_edit as edit;

mod child {
    fn external() {
        edit::de::from_str();
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"legacy\", \"legacy-explicit\", \"legacy-alias\", \"toml-edit\"]\nresolver = \"2\"\n",
        )
        .file(
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntoml_edit = { path = \"../toml-edit\" }\n",
        )
        .file("app/src/lib.rs", source)
        .file(
            "legacy/Cargo.toml",
            "[package]\nname = \"legacy\"\nversion = \"0.1.0\"\nedition = \"2015\"\n\n[dependencies]\ntoml_edit = { path = \"../toml-edit\" }\n",
        )
        .file("legacy/src/lib.rs", legacy)
        .file(
            "legacy-explicit/Cargo.toml",
            "[package]\nname = \"legacy_explicit\"\nversion = \"0.1.0\"\nedition = \"2015\"\n\n[dependencies]\ntoml_edit = { path = \"../toml-edit\" }\n",
        )
        .file("legacy-explicit/src/lib.rs", legacy_explicit)
        .file(
            "legacy-alias/Cargo.toml",
            "[package]\nname = \"legacy_alias\"\nversion = \"0.1.0\"\nedition = \"2015\"\n\n[dependencies]\ntoml_edit = { path = \"../toml-edit\" }\n",
        )
        .file("legacy-alias/src/lib.rs", legacy_alias)
        .file(
            "toml-edit/Cargo.toml",
            "[package]\nname = \"toml_edit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("toml-edit/src/lib.rs", "pub mod de;\n")
        .file("toml-edit/src/de.rs", "pub fn from_str() {}\n")
        .build();

    let external = source
        .find("toml_edit::de::from_str")
        .expect("extern-prelude qualifier");
    let value = lookup(
        project.root(),
        &location_reference("app/src/lib.rs", source, external),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");

    for marker in ["toml_edit::local();\n    }\n}", "toml_edit::local();\n}"] {
        let local = source.find(marker).expect("local module qualifier");
        let value = lookup(
            project.root(),
            &location_reference("app/src/lib.rs", source, local),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["path"], "app/src/lib.rs",
            "{value}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"], "app.src.toml_edit",
            "{value}"
        );
    }

    let legacy_root = legacy
        .find("toml_edit::de::from_str")
        .expect("Rust 2015 bare dependency root");
    let value = lookup(
        project.root(),
        &location_reference("legacy/src/lib.rs", legacy, legacy_root),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");

    let legacy_explicit_root = legacy_explicit
        .find("toml_edit::de::from_str")
        .expect("explicit Rust 2015 extern crate root");
    let value = lookup(
        project.root(),
        &location_reference(
            "legacy-explicit/src/lib.rs",
            legacy_explicit,
            legacy_explicit_root,
        ),
    );
    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );

    let legacy_alias_root = legacy_alias
        .find("edit::de::from_str")
        .expect("aliased Rust 2015 extern crate root");
    let value = lookup(
        project.root(),
        &location_reference("legacy-alias/src/lib.rs", legacy_alias, legacy_alias_root),
    );
    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn rust_same_fqn_expansion_preserves_type_namespace_for_local_module_paths() {
    let source = r#"
mod types {
    pub struct Item {
        pub value: usize,
    }

    #[allow(non_snake_case)]
    pub fn Item() {}
}

fn consume(_: types::Item) {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"namespace-expansion\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", source)
        .build();

    let item = source.rfind("types::Item").expect("scoped type reference") + "types::".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, item),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "types.Item", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "class", "{value}");
}

#[test]
fn rust_member_calls_do_not_fall_back_to_same_named_fields() {
    let source = r#"
struct Builder {
    enable_io: bool,
}

impl Builder {
    fn configure(&mut self) {
        self.enable_io();
        let _enabled = self.enable_io;
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    let call = source.find("self.enable_io();").expect("field-shaped call") + "self.".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, call),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");

    let access = source.rfind("self.enable_io;").expect("field access") + "self.".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, access),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Builder.enable_io",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["kind"], "field",
        "{value}"
    );
}

#[test]
fn rust_shorthand_pattern_binding_does_not_fall_back_to_same_named_callable() {
    let source = r#"
enum Inner {
    Alternative { is_shutdown: bool },
}

impl Inner {
    fn is_shutdown(&self) -> bool { true }
}

fn inspect(inner: Inner) {
    match inner {
        Inner::Alternative { is_shutdown, .. } => {
            let _value = is_shutdown;
        }
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    for marker in ["{ is_shutdown, ..", "= is_shutdown;"] {
        let start = source.find(marker).expect("pattern binding marker")
            + marker.find("is_shutdown").expect("binding name in marker");
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, start),
        );
        assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
        assert_eq!(
            value["results"][0]["diagnostics"][0]["kind"], "local_binding",
            "{value}"
        );
    }
}

#[test]
fn rust_impl_type_owner_prefers_the_local_struct_over_same_named_module_alias() {
    let buffer = r#"
pub struct Table;
pub trait Display {}
impl Display for Table {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub mod table; pub mod document;\n")
        .file("src/table.rs", "pub type Table = ();\n")
        .file("src/document.rs", "pub mod buffer;\n")
        .file("src/document/buffer.rs", buffer)
        .build();

    let owner = buffer.rfind("Table").expect("impl type owner");
    let value = lookup(
        project.root(),
        &location_reference("src/document/buffer.rs", buffer, owner),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "document.buffer.Table",
        "a local type declaration must beat an unrelated same-named module alias: {value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["kind"], "class",
        "{value}"
    );
}

#[test]
fn rust_explicit_type_import_beats_same_named_enclosing_type() {
    let source = r#"
mod tracing_core {
    pub trait Subscriber {}
}

pub struct Subscriber;

pub fn use_local(_: Subscriber) {}

mod format {
    use crate::tracing_core::Subscriber;

    pub trait FormatEvent<S>
    where
        S: Subscriber,
    {}
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    let imported = source.rfind("S: Subscriber").expect("imported type use") + "S: ".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, imported),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "tracing_core.Subscriber",
        "{value}"
    );

    let enclosing = source.find("_: Subscriber").unwrap() + "_: ".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, enclosing),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Subscriber",
        "{value}"
    );
}

#[test]
fn rust_self_in_impl_of_scoped_type_alias_resolves_physical_owner() {
    let main = r#"
use comrak::options;

enum ListStyle {
    Plus,
}

impl From<ListStyle> for options::ListStyleType {
    fn from(style: ListStyle) -> Self {
        match style {
            ListStyle::Plus => Self::Plus,
        }
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"comrak\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod parser;
pub use parser::options;

#[deprecated]
pub type ListStyleType = parser::options::ListStyleType;
"#,
        )
        .file("src/parser/mod.rs", "pub mod options;\n")
        .file(
            "src/parser/options.rs",
            r#"
pub enum ListStyleType {
    Dash,
    Plus,
    Star,
}
"#,
        )
        .file("src/main.rs", main)
        .build();

    for (start, expected_fqn, expected_kind) in [
        (
            main.find("-> Self").expect("bare Self return type") + "-> ".len(),
            "parser.options.ListStyleType",
            "class",
        ),
        (
            main.find("Self::Plus").expect("associated owner"),
            "parser.options.ListStyleType",
            "class",
        ),
        (
            main.find("Self::Plus").expect("associated item") + "Self::".len(),
            "parser.options.ListStyleType.Plus",
            "field",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("src/main.rs", main, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().expect("definitions").len(),
            1,
            "{value}"
        );
        assert_eq!(result["definitions"][0]["fqn"], expected_fqn, "{value}");
        assert_eq!(
            result["definitions"][0]["path"], "src/parser/options.rs",
            "{value}"
        );
        assert_eq!(result["definitions"][0]["kind"], expected_kind, "{value}");
    }
}

#[test]
fn rust_scoped_factory_call_preserves_owner_during_receiver_inference() {
    let source = r#"
struct AContext {
    span: usize,
}

impl AContext {
    fn parse() -> Result<Self, ()> { todo!() }

    fn exercise() -> Result<(), ()> {
        let root = ZFactory::parse()?;
        root.span();
        Ok(())
    }

    fn unresolved() -> Result<(), ()> {
        let root = MissingFactory::parse()?;
        root.span();
        Ok(())
    }
}

struct Wrapped;
impl Wrapped {
    fn span(&self) {}
}

struct ZFactory;
impl ZFactory {
    fn parse() -> Result<Wrapped, ()> { todo!() }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();

    let proven = source.find("root.span();").expect("proven method") + "root.".len();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", source, proven),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Wrapped.span", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "function", "{value}");

    let unresolved = source.rfind("root.span();").expect("unresolved method") + "root.".len();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", source, unresolved),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_scoped_owner_resolution_preserves_namespace_and_canonical_identity() {
    let source = r#"
mod format {
    pub struct Format;
}
fn format() {}

enum Markdown {
    Markdown,
}

struct Collisions {
    std: usize,
    manifest: usize,
}

fn manifest() {}
mod manifest {
    pub struct Manifest;
}

fn exercise() {
    let _ = format::Format;
    let _ = Markdown::Markdown;
    let _: manifest::Manifest;
    let _: std::path::PathBuf;
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .file("src/leaf.rs", "pub struct Error;\n")
        .file(
            "src/barrel.rs",
            "pub use crate::leaf::Error;\npub trait Serializer { type Error; }\npub struct LocalSerializer;\nimpl Serializer for LocalSerializer { type Error = Error; }\n",
        )
        .file(
            "src/consumer.rs",
            "use crate::barrel::Error;\npub fn consume(_: Error) {}\n",
        )
        .file("src/errors.rs", "pub struct Error;\n")
        .file(
            "src/parent/mod.rs",
            "use crate::errors::Error;\npub trait Serializer { type Error; }\npub struct LocalSerializer;\nimpl Serializer for LocalSerializer { type Error = Error; }\npub mod child;\n",
        )
        .file(
            "src/parent/child.rs",
            "use super::Error;\npub fn consume(_: Error) {}\n",
        )
        .file(
            "src/outer/mod.rs",
            "mod error;\npub use error::Error;\npub mod middle;\n",
        )
        .file("src/outer/error.rs", "pub struct Error;\n")
        .file(
            "src/outer/middle/mod.rs",
            "use super::Error;\npub mod child;\n",
        )
        .file(
            "src/outer/middle/child.rs",
            "use super::Error;\npub fn consume(_: Error) {}\n",
        )
        .build();

    for (marker, expected_fqn, expected_kind) in [
        ("format::Format", "format", "module"),
        ("Markdown::Markdown", "Markdown", "class"),
        ("manifest::Manifest", "manifest", "module"),
    ] {
        let start = source.find(marker).expect("owner marker");
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{marker}: {value}");
        assert_eq!(
            result["definitions"][0]["fqn"], expected_fqn,
            "{marker}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["kind"], expected_kind,
            "{marker}: {value}"
        );
    }

    let external = source.find("std::path::PathBuf").expect("external owner");
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, external),
    );
    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );

    let consumer = project
        .file("src/consumer.rs")
        .read_to_string()
        .expect("consumer source");
    let error = consumer.rfind("Error").expect("imported type use");
    let value = lookup(
        project.root(),
        &location_reference("src/consumer.rs", &consumer, error),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "leaf.Error", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/leaf.rs", "{value}");

    let child = project
        .file("src/parent/child.rs")
        .read_to_string()
        .expect("child source");
    let error = child.rfind("Error").expect("parent import use");
    let value = lookup(
        project.root(),
        &location_reference("src/parent/child.rs", &child, error),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "errors.Error", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/errors.rs", "{value}");

    let nested_child = project
        .file("src/outer/middle/child.rs")
        .read_to_string()
        .expect("nested child source");
    let error = nested_child
        .rfind("Error")
        .expect("nested parent import use");
    let value = lookup(
        project.root(),
        &location_reference("src/outer/middle/child.rs", &nested_child, error),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "outer.error.Error",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/outer/error.rs",
        "{value}"
    );
}

#[test]
fn rust_enclosing_inline_module_name_does_not_shadow_extern_prelude_root() {
    let source = r#"
mod serde_json {
    fn exercise(value: &str) {
        let _ = serde_json::to_string_pretty(value);
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let external = source
        .find("serde_json::to_string_pretty")
        .expect("extern-prelude root");
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, external),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn rust_self_scoped_path_keeps_independent_example_target_identity() {
    let first = r#"
trait Service { type Future; fn call() -> Self::Future; }
struct Svc;
impl Service for Svc {
    type Future = ();
    fn call() -> Self::Future { () }
}
"#;
    let second = r#"
trait Service { type Future; fn call() -> Self::Future; }
struct Svc;
impl Service for Svc {
    type Future = ();
    fn call() -> Self::Future { () }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"examples\"]\nresolver = \"2\"\n",
        )
        .file(
            "examples/Cargo.toml",
            "[package]\nname = \"examples\"\nversion = \"0.1.0\"\n\n[[example]]\nname = \"first\"\npath = \"examples/first.rs\"\n\n[[example]]\nname = \"second\"\npath = \"examples/second.rs\"\n",
        )
        .file("examples/src/lib.rs", "pub fn library_marker() {}\n")
        .file("examples/examples/first.rs", first)
        .file("examples/examples/second.rs", second)
        .build();
    let reference = first.rfind("Self::Future").expect("Self associated type");

    for (start, fqn, kind) in [
        (reference, "examples.examples.Svc", "class"),
        (
            reference + "Self::".len(),
            "examples.examples.Svc.Future",
            "field",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("examples/examples/first.rs", first, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().expect("definitions").len(),
            1,
            "{value}"
        );
        assert_eq!(result["definitions"][0]["fqn"], fqn, "{value}");
        assert_eq!(
            result["definitions"][0]["path"], "examples/examples/first.rs",
            "{value}"
        );
        assert_eq!(result["definitions"][0]["kind"], kind, "{value}");
    }
}

#[test]
fn rust_struct_field_access_resolves_from_parameters_and_result_locals() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
struct BridgeContext {
    settings: SettingsStore,
}

struct SettingsStore {
    path: String,
}

struct RolloutRewrite {
    session_meta_count: usize,
}

fn build() -> anyhow::Result<RolloutRewrite> {
    todo!()
}

fn run(ctx: BridgeContext) -> anyhow::Result<()> {
    let rewrite = build()?;
    let _ = ctx.settings.path;
    let _ = rewrite.session_meta_count;
    Ok(())
}
"#,
        )
        .build();

    let settings_line = "    let _ = ctx.settings.path;";
    let settings = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":20,"column":{}}}]}}"#,
            column_of(settings_line, "settings")
        ),
    );
    assert_eq!(settings["results"][0]["status"], "resolved", "{settings}");
    assert_eq!(
        settings["results"][0]["definitions"][0]["fqn"], "BridgeContext.settings",
        "{settings}"
    );

    let session_line = "    let _ = rewrite.session_meta_count;";
    let session_meta_count = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":21,"column":{}}}]}}"#,
            column_of(session_line, "session_meta_count")
        ),
    );
    assert_eq!(
        session_meta_count["results"][0]["status"], "resolved",
        "{session_meta_count}"
    );
    assert_eq!(
        session_meta_count["results"][0]["definitions"][0]["fqn"],
        "RolloutRewrite.session_meta_count",
        "{session_meta_count}"
    );
}

#[test]
fn rust_struct_literal_field_labels_resolve_exact_owner_and_declarations_do_not() {
    let source = r#"
struct Wanted { same: usize, only: usize }
struct Decoy { same: usize, only: usize }

impl Wanted {
    fn build(same: usize) -> Self {
        Self { same, only: 1 }
    }
}

fn decoy() -> Decoy { Decoy { same: 2, only: 3 } }
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();

    for (start, expected) in [
        (source.find("same, only: 1").unwrap(), "Wanted.same"),
        (source.find("only: 1").unwrap(), "Wanted.only"),
        (source.find("same: 2").unwrap(), "Decoy.same"),
    ] {
        let value = lookup(project.root(), &location_reference("lib.rs", source, start));
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{value}"
        );
    }

    let declaration = source.find("same: usize").unwrap();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", source, declaration),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "Wanted.build",
                "context": "        Self { same, only: 1 }",
                "target": "same"
            }]
        })
        .to_string(),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Wanted.same",
        "{value}"
    );
}

#[test]
fn rust_struct_field_access_ignores_shadowing_binding_after_inner_scope() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
struct Outer {
    name: String,
}

struct Inner {
    name: String,
}

fn run(value: Outer) {
    {
        let value: Inner = todo!();
        let _ = value.name;
    }
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":15,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Outer.name",
        "{value}"
    );
}

#[test]
fn rust_unimported_inline_module_type_does_not_guess_same_file_identifier() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_function_local_use_does_not_leak_to_sibling_function_type_lookup() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

fn other() {
    use crate::hidden::Hidden;
}

fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":13,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_parent_module_use_does_not_leak_into_inline_child_module() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

use crate::hidden::Hidden;

mod child {
    fn run(value: Hidden) {
        let _ = value.name;
    }
}
"#,
        )
        .build();

    let line = "        let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":12,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_function_local_use_does_not_leak_through_resolve_bare_for_crate_root_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub struct Actual {
    pub name: String,
}

fn other() {
    use crate::Actual as Hidden;
}

fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":11,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_inline_module_local_type_resolves_inside_same_module_scope() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod child {
    struct Local {
        name: String,
    }

    fn run(value: Local) {
        let _ = value.name;
    }
}
"#,
        )
        .build();

    let line = "        let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":8,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "child.Local.name",
        "{value}"
    );
}

#[test]
fn rust_inline_module_local_type_resolves_before_later_declaration() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod child {
    fn run(value: Local) {
        let _ = value.name;
    }

    struct Local {
        name: String,
    }
}
"#,
        )
        .build();

    let line = "        let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":4,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "child.Local.name",
        "{value}"
    );
}

#[test]
fn rust_later_module_use_resolves_earlier_same_module_reference() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden {
    pub struct Hidden {
        pub name: String,
    }
}

fn run(value: Hidden) {
    let _ = value.name;
}

use crate::hidden::Hidden;
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "hidden.Hidden.name",
        "{value}"
    );
}

#[test]
fn rust_struct_field_access_resolves_from_option_expect_locals() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod pricing;\npub mod route;\npub use route::RouteCheapnessEstimate;\n")
        .file("src/route.rs", "pub struct RouteCheapnessEstimate {\n    pub input_price_per_mtok_micros: Option<u64>,\n}\n")
        .file(
            "src/pricing.rs",
            r#"
use crate::{RouteCheapnessEstimate};

pub fn pricing() -> Option<RouteCheapnessEstimate> {
    todo!()
}

fn run() {
    let fast = pricing().expect("priced model");
    let _ = fast.input_price_per_mtok_micros;
}
"#,
        )
        .build();

    let line = "    let _ = fast.input_price_per_mtok_micros;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/pricing.rs","line":10,"column":{}}}]}}"#,
            column_of(line, "input_price_per_mtok_micros")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "route.RouteCheapnessEstimate.input_price_per_mtok_micros",
        "{value}"
    );
}

#[test]
fn rust_struct_field_access_resolves_from_macro_token_trees() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
macro_rules! object {
    ($($tt:tt)*) => {};
}

pub struct LlmModel {
    pub name: String,
}

pub struct ModelFit {
    pub model: LlmModel,
}

fn fit_to_json(fit: &ModelFit) {
    object!({
        "name": fit.model.name,
        "ollama_name": helper(&fit.model.name),
    });
}
"#,
        )
        .build();

    let line = r#"        "ollama_name": helper(&fit.model.name),"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":17,"column":{}}}]}}"#,
            column_of(line, "model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ModelFit.model", "{value}");
}

#[test]
fn rust_dotted_method_chain_resolves_inside_macro_token_trees() {
    let source = r#"
macro_rules! render { ($($tt:tt)*) => {}; }

pub struct AlertType;
impl AlertType { pub fn default_title(&self) -> &'static str { "Alert" } }
pub struct OtherAlertType;
impl OtherAlertType { pub fn default_title(&self) -> &'static str { "Other" } }
pub struct NodeAlert { pub alert_type: AlertType }
pub struct OtherAlert { pub alert_type: OtherAlertType }

fn format(alert: &NodeAlert, other: &OtherAlert) {
    render!(alert.alert_type.default_title());
    render!(other.alert_type.default_title());
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    for (expression, expected) in [
        ("alert.alert_type.default_title", "AlertType.default_title"),
        (
            "other.alert_type.default_title",
            "OtherAlertType.default_title",
        ),
    ] {
        let start = source.find(expression).expect("macro member chain")
            + expression.rfind('.').expect("terminal member")
            + 1;
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, start),
        );
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{value}"
        );
    }
}

#[test]
fn rust_qualified_macro_path_focus_resolves_each_exact_segment() {
    let source = r#"
pub struct EventInfo;
impl EventInfo { pub fn default() -> Self { Self } }

fn run() {
    let _ = vec![EventInfo::default(), EventInfo::default()];
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", source)
        .build();
    let expression = "EventInfo::default()";
    let first = source.find(expression).expect("first macro path");

    for (offset, expected) in [
        (first, "EventInfo"),
        (first + "EventInfo::".len(), "EventInfo.default"),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("lib.rs", source, offset),
        );
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{value}"
        );
    }
}

#[test]
fn rust_macro_token_tree_declaration_names_are_not_forward_references() {
    let source = r#"
macro_rules! cfg_aio { ($($item:item)*) => { $($item)* }; }

const AIO: usize = 0b0100;
struct Interest(usize);

impl Interest {
    cfg_aio! {
        pub const AIO: Interest = Interest(AIO);
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();

    let declaration = source.find("pub const AIO").expect("macro declaration") + "pub const ".len();
    let declaration_result = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, declaration),
    );
    assert_eq!(
        declaration_result["results"][0]["status"], "no_definition",
        "a token-tree declaration name is not a forward reference: {declaration_result}"
    );

    let initializer = source
        .find("Interest(AIO)")
        .expect("macro initializer reference")
        + "Interest(".len();
    let initializer_result = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, initializer),
    );
    assert_eq!(
        initializer_result["results"][0]["status"], "resolved",
        "the same-name initializer remains a genuine reference: {initializer_result}"
    );
    assert_eq!(
        initializer_result["results"][0]["definitions"][0]["fqn"], "_module_.AIO",
        "{initializer_result}"
    );
}

#[test]
fn rust_struct_field_access_resolves_imported_parameter_types() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod display;
pub mod fit;
pub mod models;
"#,
        )
        .file(
            "src/fit.rs",
            r#"
use crate::models::LlmModel;

pub struct ModelFit {
    pub model: LlmModel,
}
"#,
        )
        .file(
            "src/models.rs",
            r#"
pub struct LlmModel {
    pub name: String,
}
"#,
        )
        .file(
            "src/display.rs",
            r#"
use crate::fit::ModelFit;

fn fit_to_json(fit: &ModelFit) {
    let _ = &fit.model.name;
}
"#,
        )
        .build();

    let line = "    let _ = &fit.model.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/display.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "fit.ModelFit.model",
        "{value}"
    );
}

#[test]
fn rust_get_definition_resolves_field_type_from_ast_node() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod models;

use models::MemoryRepository;

pub struct Service {
    repository: MemoryRepository,
}
"#,
        )
        .file("src/models.rs", "pub struct MemoryRepository;\n")
        .build();

    let line = "    repository: MemoryRepository,";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":7,"column":{}}}]}}"#,
            column_of(line, "MemoryRepository")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "models.MemoryRepository",
        "{value}"
    );
}

#[test]
fn rust_get_definition_resolves_function_return_type_from_ast_node() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod models;

use models::MemoryRepository;

pub fn build() -> MemoryRepository {
    MemoryRepository
}
"#,
        )
        .file("src/models.rs", "pub struct MemoryRepository;\n")
        .build();

    let line = "pub fn build() -> MemoryRepository {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "MemoryRepository")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "models.MemoryRepository",
        "{value}"
    );
}

#[test]
fn rust_field_access_unwraps_wrapped_type_nodes() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod models;

use models::{Error, MemoryRepository};

pub struct Service {
    maybe: Option<&'static MemoryRepository>,
    result: Result<MemoryRepository, Error>,
}

pub fn build() -> anyhow::Result<MemoryRepository> {
    MemoryRepository { name: String::new() }
}

pub fn run(service: Service) {
    let _ = service.maybe.unwrap().name;
    let _ = service.result.unwrap().name;
    let _ = build().unwrap().name;
}
"#,
        )
        .file(
            "src/models.rs",
            r#"
pub struct Error;

pub struct MemoryRepository {
    pub name: String,
}
"#,
        )
        .build();

    for (line_number, line) in [
        (16, "    let _ = service.maybe.unwrap().name;"),
        (17, "    let _ = service.result.unwrap().name;"),
        (18, "    let _ = build().unwrap().name;"),
    ] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"src/lib.rs","line":{line_number},"column":{}}}]}}"#,
                column_of(line, "name")
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "models.MemoryRepository.name",
            "{value}"
        );
    }
}

#[test]
fn rust_field_access_does_not_unwrap_result_error_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod models;

use models::Error;

pub fn fallible() -> Result<(), Error> {
    Ok(())
}

pub fn run() {
    let _ = fallible().unwrap().message;
}
"#,
        )
        .file(
            "src/models.rs",
            r#"
pub struct Error {
    pub message: String,
}
"#,
        )
        .build();

    let line = "    let _ = fallible().unwrap().message;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":11,"column":{}}}]}}"#,
            column_of(line, "message")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_struct_field_access_resolves_borrowed_self_field() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub struct Provider {
    model: String,
}

pub struct Other {
    model: String,
}

impl Provider {
    fn model(&self) -> String {
        String::new()
    }

    fn run(&self) {
        let _ = Arc::clone(&self.model);
    }
}
"#,
        )
        .build();

    let line = "        let _ = Arc::clone(&self.model);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":16,"column":{}}}]}}"#,
            column_of(line, "model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Provider.model", "{value}");
}

#[test]
fn go_selector_chain_resolves_promoted_embedded_fields_and_range_elements() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "types/types.go",
            r#"
package types

type Category struct {
    ID string
}

type ScanResult struct {
    Category Category
}
"#,
        )
        .file(
            "tui/model.go",
            r#"
package tui

import "example.com/app/types"

type dataState struct {
    results []*types.ScanResult
}

type selectionState struct {
    selected map[string]bool
}

type Model struct {
    dataState
    selectionState
}

func (m *Model) Handle() {
    for _, r := range m.results {
        if m.selected[r.Category.ID] {
            _ = r
        }
    }
    r := m.results[0]
    _ = r.Category.ID
}
"#,
        )
        .build();

    let selected_line = "        if m.selected[r.Category.ID] {";
    let selected = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tui/model.go","line":21,"column":{}}}]}}"#,
            column_of(selected_line, "selected")
        ),
    );
    assert_eq!(selected["results"][0]["status"], "resolved", "{selected}");
    assert_eq!(
        selected["results"][0]["definitions"][0]["fqn"],
        "example.com/app/tui.selectionState.selected",
        "{selected}"
    );

    let id = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tui/model.go","line":21,"column":{}}}]}}"#,
            column_of(selected_line, "ID")
        ),
    );
    assert_eq!(id["results"][0]["status"], "resolved", "{id}");
    assert_eq!(
        id["results"][0]["definitions"][0]["fqn"], "example.com/app/types.Category.ID",
        "{id}"
    );

    let indexed_line = "    _ = r.Category.ID";
    let indexed_id = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tui/model.go","line":26,"column":{}}}]}}"#,
            column_of(indexed_line, "ID")
        ),
    );
    assert_eq!(
        indexed_id["results"][0]["status"], "resolved",
        "{indexed_id}"
    );
    assert_eq!(
        indexed_id["results"][0]["definitions"][0]["fqn"], "example.com/app/types.Category.ID",
        "{indexed_id}"
    );
}

#[test]
fn go_imported_factory_result_resolves_promoted_embedded_members() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/parity\n\ngo 1.22\n")
        .file(
            "pkg/service/service.go",
            r#"
package service

type AuditLog struct {
    Last string
}

func (a *AuditLog) Record(message string) string {
    a.Last = message
    return a.Last
}

type Worker struct {
    *AuditLog
}

func NewWorker() *Worker {
    return &Worker{AuditLog: &AuditLog{}}
}
"#,
        )
        .file(
            "cmd/app/main.go",
            r#"
package main

import svc "example.com/parity/pkg/service"

func main() {
    worker := svc.NewWorker()
    worker.Record("start")
    _ = worker.Last
}
"#,
        )
        .build();

    let method_line = r#"    worker.Record("start")"#;
    let method = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"cmd/app/main.go","line":8,"column":{}}}]}}"#,
            column_of(method_line, "Record")
        ),
    );
    assert_eq!(method["results"][0]["status"], "resolved", "{method}");
    assert_eq!(
        method["results"][0]["definitions"][0]["fqn"],
        "example.com/parity/pkg/service.AuditLog.Record",
        "{method}"
    );

    let field_line = "    _ = worker.Last";
    let field = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"cmd/app/main.go","line":9,"column":{}}}]}}"#,
            column_of(field_line, "Last")
        ),
    );
    assert_eq!(field["results"][0]["status"], "resolved", "{field}");
    assert_eq!(
        field["results"][0]["definitions"][0]["fqn"],
        "example.com/parity/pkg/service.AuditLog.Last",
        "{field}"
    );
}

#[test]
fn go_imported_package_var_resolves_inside_longer_selector_chain() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "pkg/assets/assets.go",
            r#"
package assets

type FS struct{}

var Rewrites FS
"#,
        )
        .file(
            "service/rewrite.go",
            r#"
package service

import "example.com/app/pkg/assets"

func run() {
    _, _ = assets.Rewrites.ReadFile("rewrite/default.conf")
}
"#,
        )
        .build();

    let line = r#"    _, _ = assets.Rewrites.ReadFile("rewrite/default.conf")"#;
    let rewrites = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service/rewrite.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Rewrites")
        ),
    );
    assert_eq!(rewrites["results"][0]["status"], "resolved", "{rewrites}");
    assert_eq!(
        rewrites["results"][0]["definitions"][0]["fqn"],
        "example.com/app/pkg/assets._module_.Rewrites",
        "{rewrites}"
    );

    let read_file = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service/rewrite.go","line":7,"column":{}}}]}}"#,
            column_of(line, "ReadFile")
        ),
    );
    assert_eq!(
        read_file["results"][0]["status"], "no_definition",
        "{read_file}"
    );
}

#[test]
fn python_class_and_instance_attributes_resolve_to_definitions() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "util.py",
            r#"
class ModelParser:
    @staticmethod
    def from_model(path):
        return ModelParser()
"#,
        )
        .file(
            "main.py",
            r#"
from util import ModelParser

class DataType:
    FLOAT = object()

class Service:
    def __init__(self, memory):
        self.memory = memory

    def run(self):
        return self.memory

def class_attr():
    return DataType.FLOAT

def imported_static():
    return ModelParser.from_model("model.xml")
"#,
        )
        .build();

    let class_attr = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "class_attr",
                "context": "return DataType.FLOAT",
                "target": "FLOAT"
            }]
        })
        .to_string(),
    );
    assert_eq!(
        class_attr["results"][0]["status"], "resolved",
        "{class_attr}"
    );
    assert_eq!(
        class_attr["results"][0]["definitions"][0]["fqn"], "main.DataType.FLOAT",
        "{class_attr}"
    );

    let instance_attr = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "Service.run",
                "context": "return self.memory",
                "target": "memory"
            }]
        })
        .to_string(),
    );
    assert_eq!(
        instance_attr["results"][0]["status"], "resolved",
        "{instance_attr}"
    );
    assert_eq!(
        instance_attr["results"][0]["definitions"][0]["fqn"], "main.Service.memory",
        "{instance_attr}"
    );

    let imported_static = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "imported_static",
                "context": "return ModelParser.from_model(\"model.xml\")",
                "target": "from_model"
            }]
        })
        .to_string(),
    );
    assert_eq!(
        imported_static["results"][0]["status"], "resolved",
        "{imported_static}"
    );
    assert_eq!(
        imported_static["results"][0]["definitions"][0]["fqn"], "util.ModelParser.from_model",
        "{imported_static}"
    );
}

#[test]
fn python_property_getter_resolves_on_module_level_receiver() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "m.py",
            r#"
class User:
    @property
    def normalized_name(self) -> str:
        return "guest"

user = User()
user.normalized_name
"#,
        )
        .build();

    let line = "user.normalized_name";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"m.py","line":8,"column":{}}}]}}"#,
            column_of(line, "normalized_name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "m.User.normalized_name",
        "{value}"
    );
}

#[test]
fn python_nested_function_self_assignment_does_not_create_outer_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    def configure(self):
        def inner():
            self.shadow = 1

    def read(self):
        return self.shadow
"#,
        )
        .build();

    let line = "        return self.shadow";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.py","line":8,"column":{}}}]}}"#,
            column_of(line, "shadow")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_nested_class_self_assignment_does_not_create_outer_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    def configure(self):
        class Inner:
            def run(self):
                self.shadow = 1

    def read(self):
        return self.shadow
"#,
        )
        .build();

    let line = "        return self.shadow";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.py","line":9,"column":{}}}]}}"#,
            column_of(line, "shadow")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_reference_context_collapses_repeated_targets_with_same_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::helper;

pub fn run() {
    helper(); helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "helper(); helper();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_reference_context_reports_ambiguous_when_targets_resolve_differently() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;

fn helper() {}

pub fn run() {
    crate::util::helper(); helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "crate::util::helper(); helper();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_reference_target",
        "{value}"
    );
}

#[test]
fn rust_crate_scoped_macro_resolves_from_nested_crate_root() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "printf/src/lib.rs",
            r#"
#[macro_export]
macro_rules! sprintf {
    ($fmt:expr) => { $fmt };
}

#[cfg(test)]
mod tests;
"#,
        )
        .file(
            "printf/src/tests.rs",
            r#"
pub fn test_crate_macros() {
    let target = crate::sprintf!("noargs1");
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "printf.src.tests.test_crate_macros",
                "context": "let target = crate::sprintf!(\"noargs1\");",
                "target": "sprintf"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "printf.src.sprintf",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "printf/src/lib.rs",
        "{value}"
    );
}

#[test]
fn rust_struct_field_access_does_not_unwrap_option_without_syntax() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod pricing;\npub mod route;\npub use route::RouteCheapnessEstimate;\n")
        .file("src/route.rs", "pub struct RouteCheapnessEstimate {\n    pub input_price_per_mtok_micros: Option<u64>,\n}\n")
        .file(
            "src/pricing.rs",
            r#"
use crate::{RouteCheapnessEstimate};

pub fn pricing() -> Option<RouteCheapnessEstimate> {
    todo!()
}

fn run() {
    let maybe = pricing();
    let _ = maybe.input_price_per_mtok_micros;
}
"#,
        )
        .build();

    let line = "    let _ = maybe.input_price_per_mtok_micros;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/pricing.rs","line":10,"column":{}}}]}}"#,
            column_of(line, "input_price_per_mtok_micros")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "mod service;\nmod app;\n")
        .file(
            "service.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) {}
}
"#,
        )
        .file(
            "app.rs",
            r#"
use crate::service::Service;

pub fn run(service: Service) {
    service.execute();
}
"#,
        )
        .build();

    let line = "    service.execute();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "execute")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Service.execute",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "service.rs", "{value}");
}

#[test]
fn rust_typed_receiver_method_resolves_src_module_definition() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
pub mod service;

pub use service::{MemoryRepository, Service, build_service};

pub fn run_demo() -> String {
    let repository = MemoryRepository::default();
    let service = build_service(repository);
    service.execute(" Grace ")
}
"#,
        )
        .file(
            "src/service.rs",
            r#"
#[derive(Default)]
pub struct MemoryRepository;

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(self, name: &str) -> String {
        name.trim().to_string()
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
"#,
        )
        .build();

    let line = r#"    service.execute(" Grace ")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "execute")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "service.Service.execute",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/service.rs",
        "{value}"
    );
}

#[test]
fn rust_unproven_receiver_method_does_not_guess_same_named_method() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) {}
}

pub fn run(service: ()) {
    service.execute();
}
"#,
        )
        .build();

    let line = "    service.execute();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":9,"column":{}}}]}}"#,
            column_of(line, "execute")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_crate_scoped_macro_resolves_inside_inline_module() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            r#"
pub mod inner {
    macro_rules! helper {
        () => {};
    }

    pub fn caller() {
        crate::inner::helper!();
    }
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "inner.caller",
                "context": "crate::inner::helper!();",
                "target": "helper"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "inner.helper", "{value}");

    let line = "        crate::inner::helper!();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":8,"column":{}}}]}}"#,
            column_of(line, "crate")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "no_indexed_definition",
        "{value}"
    );
}

#[test]
fn rust_nonterminal_scoped_focus_does_not_retry_terminal_or_flat_names() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "use std::fmt;\nuse std::path;\nstruct Commands;\nstruct PathBuf;\nimpl fmt::Display for Commands {\n    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result { Ok(()) }\n}\nfn consume(_: path::PathBuf) {}\nmod local { pub struct Item; }\nfn indexed(_: local::Item) {}\n",
        )
        .build();

    for (line, source_line, focus) in [
        (5, "impl fmt::Display for Commands {", "fmt"),
        (8, "fn consume(_: path::PathBuf) {}", "path"),
    ] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"lib.rs","line":{line},"column":{}}}]}}"#,
                column_of(source_line, focus)
            ),
        );
        let result = &value["results"][0];
        assert_eq!(
            result["status"], "unresolvable_import_boundary",
            "focused {focus}: {value}"
        );
        assert!(result["definitions"][0].is_null(), "{value}");
    }

    let terminal_line = "fn indexed(_: local::Item) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":10,"column":{}}}]}}"#,
            column_of(terminal_line, "Item")
        ),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "local.Item", "{value}");
}

#[test]
fn rust_scoped_path_focus_preserves_owner_and_terminal_roles() {
    let source = r#"
mod primary;
mod unrelated;
use crate::{primary::{AnalysisLog}};
enum MatchResult { AnalysisLog(AnalysisLog) }

fn consume() {
    let _ = vec![MatchResult::AnalysisLog(AnalysisLog::floating_error())];
    let _ = vec![unrelated::AnalysisLog::floating_error()];
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .file(
            "src/primary.rs",
            "pub struct AnalysisLog;\nimpl AnalysisLog { pub fn floating_error() {} }\n",
        )
        .file(
            "src/unrelated.rs",
            "pub struct AnalysisLog;\nimpl AnalysisLog { pub fn floating_error() {} }\n",
        )
        .build();
    let primary = "(AnalysisLog::floating_error())]";
    let owner_start = source.find("AnalysisLog::floating_error").unwrap();
    let terminal_start = owner_start + "AnalysisLog::".len();

    for (start, expected) in [
        (owner_start, "primary.AnalysisLog"),
        (terminal_start, "primary.AnalysisLog.floating_error"),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }

    let unrelated_owner = source
        .find("unrelated::AnalysisLog::floating_error")
        .unwrap()
        + "unrelated::".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", source, unrelated_owner),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "unrelated.AnalysisLog",
        "{value}"
    );

    for (target, expected) in [
        ("AnalysisLog", "primary.AnalysisLog"),
        ("floating_error", "primary.AnalysisLog.floating_error"),
    ] {
        let value = lookup_reference(
            project.root(),
            &json!({
                "references": [{
                    "symbol": "consume",
                    "context": primary,
                    "target": target
                }]
            })
            .to_string(),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn rust_focused_prefix_candidates_stay_within_rust() {
    let rust_source = r#"struct IndexedOwner;
impl IndexedOwner {
    fn new() -> Self { Self }
}

fn demo() {
    let _external = String::new();
    let _indexed = IndexedOwner::new();
}
"#;
    let cpp_source = r#"struct String {};
String make_string() { return String{}; }
"#;
    let project = InlineTestProject::new()
        .file("lib.rs", rust_source)
        .file("foreign.cpp", cpp_source)
        .build();

    let cpp_use = cpp_source.find("String make_string").unwrap();
    let value = lookup(
        project.root(),
        &location_reference("foreign.cpp", cpp_source, cpp_use),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "String", "{value}");
    assert_eq!(result["definitions"][0]["path"], "foreign.cpp", "{value}");

    let string_use = rust_source.find("String::new()").unwrap();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", rust_source, string_use),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "demo",
                "context": "let _external = String::new();",
                "target": "String"
            }]
        })
        .to_string(),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");

    let indexed_use = rust_source.find("IndexedOwner::new()").unwrap();
    let value = lookup(
        project.root(),
        &location_reference("lib.rs", rust_source, indexed_use),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "IndexedOwner", "{value}");
    assert_eq!(result["definitions"][0]["path"], "lib.rs", "{value}");
}

#[test]
fn line_column_uses_character_columns_not_byte_offsets() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;
use crate::util::helper;

pub fn run() {
    let café = helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let line = "    let café = helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            character_column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["reference"]["target"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.rs", "{value}");
}

#[test]
fn rust_external_crate_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub fn run() {
    serde::Serialize::serialize;
}
"#,
        )
        .build();

    let line = "    serde::Serialize::serialize;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":3,"column":{}}}]}}"#,
            column_of(line, "Serialize")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    assert!(result["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_unresolved_scoped_path_does_not_guess_by_leaf_name() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;

pub fn run() {
    crate::missing::helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let line = "    crate::missing::helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_root_super_path_does_not_resolve_to_crate_root_item() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub fn helper() {}

pub fn run() {
    super::helper();
}
"#,
        )
        .build();

    let line = "    super::helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_too_many_super_segments_do_not_resolve_to_crate_root_item() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
pub fn helper() {}

pub mod child {
    pub fn run() {
        super::super::helper();
    }
}
"#,
        )
        .build();

    let line = "        super::super::helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_unimported_bare_name_does_not_guess_workspace_identifier() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            r#"
mod util;

pub fn run() {
    helper();
}
"#,
        )
        .file("util.rs", "pub fn helper() {}\n")
        .build();

    let line = "    helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_unimported_parameter_type_does_not_guess_workspace_identifier() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            r#"
mod hidden;

pub fn run(value: Hidden) {
    let _ = value.name;
}
"#,
        )
        .file(
            "src/hidden.rs",
            r#"
pub struct Hidden {
    pub name: String,
}
"#,
        )
        .build();

    let line = "    let _ = value.name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/lib.rs","line":5,"column":{}}}]}}"#,
            column_of(line, "name")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn rust_reference_inside_test_file_resolves_without_include_tests_flag() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "tests/helper.rs",
            r##"
fn helper() {}

#[test]
pub fn run() {
    helper();
}
"##,
        )
        .build();

    let line = "    helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/helper.rs","line":6,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["path"], "tests/helper.rs",
        "{value}"
    );
}

#[test]
fn rust_cargo_example_targets_keep_same_named_types_physically_scoped() {
    let left = r#"
struct Shared;

fn consume(_: crate::Shared) {}
fn imported(_: demo::Shared) {}
fn library(_: demo::LibraryOnly) {}
"#;
    let right = r#"
pub struct Shared;

fn consume(_: crate::Shared) {}
fn imported(_: demo::Shared) {}
fn library(_: demo::LibraryOnly) {}
"#;
    let build = r#"
struct Shared;

fn consume(_: crate::Shared) {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            "pub struct Shared;\npub struct LibraryOnly;\n",
        )
        .file("examples/left.rs", left)
        .file("examples/right.rs", right)
        .file("build.rs", build)
        .build();

    for (path, source) in [
        ("examples/left.rs", left),
        ("examples/right.rs", right),
        ("build.rs", build),
    ] {
        let start = source.find("crate::Shared").expect("Shared reference") + "crate::".len();
        let value = lookup(project.root(), &location_reference(path, source, start));
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
        assert_eq!(result["definitions"][0]["path"], path, "{value}");

        if path == "build.rs" {
            continue;
        }

        let imported_start =
            source.find("demo::Shared").expect("imported reference") + "demo::".len();
        let value = lookup(
            project.root(),
            &location_reference(path, source, imported_start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["path"], "src/lib.rs", "{value}");

        let library_start =
            source.find("demo::LibraryOnly").expect("library reference") + "demo::".len();
        let value = lookup(
            project.root(),
            &location_reference(path, source, library_start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
        assert_eq!(result["definitions"][0]["path"], "src/lib.rs", "{value}");
    }
}

#[test]
fn rust_cargo_bench_targets_scope_bare_macro_arguments_to_the_physical_root() {
    let left = r#"
const NUM_ENTRIES: usize = 10;

mod parser {
    use crate::NUM_ENTRIES;

    #[divan::bench(args = NUM_ENTRIES)]
    fn bench() {}
}

mod edit {
    use crate::NUM_ENTRIES;

    #[divan::bench(args = NUM_ENTRIES)]
    fn bench() {}
}
"#;
    let right = r#"
const NUM_ENTRIES: usize = 20;

mod parser {
    use crate::NUM_ENTRIES;

    #[divan::bench(args = NUM_ENTRIES)]
    fn bench() {}
}

mod edit {
    use crate::NUM_ENTRIES;

    #[divan::bench(args = NUM_ENTRIES)]
    fn bench() {}
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("benches/left.rs", left)
        .file("benches/right.rs", right)
        .build();

    for (path, source) in [("benches/left.rs", left), ("benches/right.rs", right)] {
        for (start, _) in source.match_indices("NUM_ENTRIES").skip(1) {
            let value = lookup(project.root(), &location_reference(path, source, start));
            let result = &value["results"][0];
            assert_eq!(result["status"], "resolved", "{value}");
            assert_eq!(
                result["definitions"].as_array().map(Vec::len),
                Some(1),
                "{value}"
            );
            assert_eq!(result["definitions"][0]["path"], path, "{value}");
            assert_eq!(result["definitions"][0]["kind"], "field", "{value}");
            assert_eq!(
                result["definitions"][0]["fqn"], "benches._module_.NUM_ENTRIES",
                "{value}"
            );
        }
    }
}

#[test]
fn rust_cargo_example_targets_scope_local_module_paths_to_the_physical_root() {
    let source = r#"
mod yak_shave {
    pub fn shave_all() {}
}

fn run() {
    yak_shave::shave_all();
}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("examples/compact.rs", source)
        .file("examples/source_locations.rs", source)
        .build();

    for path in ["examples/compact.rs", "examples/source_locations.rs"] {
        let start = source.rfind("yak_shave").expect("module reference");
        let value = lookup(project.root(), &location_reference(path, source, start));
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
        assert_eq!(result["definitions"][0]["path"], path, "{value}");
        assert_eq!(result["definitions"][0]["kind"], "module", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "examples.yak_shave",
            "{value}"
        );
    }
}

#[test]
fn rust_binary_only_explicit_targets_infer_paths_and_isolate_same_named_types() {
    let left = "struct Shared;\nfn consume(_: crate::Shared) {}\n";
    let right = "struct Shared;\nfn consume(_: crate::Shared) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nautolib = false\nautobins = false\n\n[[bin]]\nname = \"left\"\n\n[[bin]]\nname = \"right\"\n",
        )
        .file("src/bin/left.rs", left)
        .file("src/bin/right.rs", right)
        .build();

    for (path, source) in [("src/bin/left.rs", left), ("src/bin/right.rs", right)] {
        let start = source.find("crate::Shared").expect("Shared reference") + "crate::".len();
        let value = lookup(project.root(), &location_reference(path, source, start));
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
        assert_eq!(result["definitions"][0]["path"], path, "{value}");
    }
}

#[test]
fn rust_direct_crate_root_recovery_rejects_nested_declarations() {
    let source = r#"
mod nested {
    pub struct NestedType;
}

struct Host;
impl Host {
    fn method_only() {}
}

fn invalid_type(_: crate::NestedType) {}
fn invalid_method(_: crate::method_only) {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", source)
        .build();

    for name in ["NestedType", "method_only"] {
        let needle = format!("crate::{name}");
        let start = source.find(&needle).expect("crate-root reference") + "crate::".len();
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "no_definition", "{name}: {value}");
        assert!(result["definitions"][0].is_null(), "{name}: {value}");
    }
}

#[test]
fn rust_direct_crate_root_reference_resolves_root_reexport() {
    let root = "mod nested;\npub use nested::NestedType;\nfn consume(_: crate::NestedType) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", root)
        .file("src/nested.rs", "pub struct NestedType;\n")
        .build();

    let start = root
        .find("crate::NestedType")
        .expect("crate-root reference")
        + "crate::".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", root, start),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "src/nested.rs", "{value}");
}

#[test]
fn rust_explicit_dependency_route_wins_over_same_fqn_local_targets() {
    let consumer =
        "struct Shared;\nfn external(_: dep::Shared) {}\nfn local(_: crate::Shared) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = [\"dep\", \"app\"]\nresolver = \"2\"\n",
        )
        .file(
            "dep/Cargo.toml",
            "[package]\nname = \"dep\"\nversion = \"0.1.0\"\n",
        )
        .file("dep/src/lib.rs", "pub struct Shared;\n")
        .file(
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ndep = { path = \"../dep\" }\n",
        )
        .file("app/src/lib.rs", "pub struct Shared;\n")
        .file("app/examples/consumer.rs", consumer)
        .build();

    for (needle, prefix, expected) in [
        ("dep::Shared", "dep::", "dep/src/lib.rs"),
        ("crate::Shared", "crate::", "app/examples/consumer.rs"),
    ] {
        let start = consumer.find(needle).expect("reference") + prefix.len();
        let value = lookup(
            project.root(),
            &location_reference("app/examples/consumer.rs", consumer, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
        assert_eq!(result["definitions"][0]["path"], expected, "{value}");
    }
}

#[test]
fn rust_passthrough_macros_follow_their_physical_cargo_target() {
    let left = r#"
macro_rules! configure { (mod $name:ident;) => {} }
configure! { mod hidden; }
fn invalid(_: crate::Hidden) {}
"#;
    let right = r#"
macro_rules! configure { ($($item:item)*) => { $($item)* }; }
configure! { mod generated; }
fn valid(_: crate::generated::Visible) {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nautolib = false\nautobins = false\n\n[[bin]]\nname = \"left\"\n\n[[bin]]\nname = \"right\"\n",
        )
        .file("src/bin/left.rs", left)
        .file("src/bin/right.rs", right)
        .file("src/bin/hidden.rs", "pub struct Hidden;\n")
        .file("src/bin/generated.rs", "pub struct Visible;\n")
        .build();

    let invalid_start = left.find("crate::Hidden").expect("invalid reference") + "crate::".len();
    let value = lookup(
        project.root(),
        &location_reference("src/bin/left.rs", left, invalid_start),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn rust_passthrough_macro_routes_reject_mixed_rules_and_scoped_name_collisions() {
    let source = r#"
early! { mod early_module; }
macro_rules! early { ($($item:item)*) => { $($item)* }; }
macro_rules! mixed {
    (mod $name:ident;) => {};
    ($($item:item)*) => { $($item)* };
}
macro_rules! dependency_wrapper { ($($item:item)*) => { $($item)* }; }

mixed! { mod swallowed; }
dependency::dependency_wrapper! { mod scoped; }

fn invalid_mixed(_: crate::Swallowed) {}
fn invalid_scoped(_: crate::Scoped) {}
fn invalid_early(_: crate::Early) {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", source)
        .file("src/swallowed.rs", "pub struct Swallowed;\n")
        .file("src/scoped.rs", "pub struct Scoped;\n")
        .file("src/early_module.rs", "pub struct Early;\n")
        .build();

    for name in ["Swallowed", "Scoped", "Early"] {
        let needle = format!("crate::{name}");
        let start = source.find(&needle).expect("invalid reference") + "crate::".len();
        let value = lookup(
            project.root(),
            &location_reference("src/lib.rs", source, start),
        );
        assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
        assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
    }
}

#[test]
fn rust_passthrough_macro_target_provenance_reaches_nested_generated_modules() {
    let root = r#"
#[macro_use]
mod macros;
cfg_items! { mod first; }
fn valid(_: crate::first::second::Nested) {}
"#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", root)
        .file("src/macros/mod.rs", "#[macro_use]\nmod cfg;\n")
        .file(
            "src/macros/cfg.rs",
            "macro_rules! cfg_items { ($($item:item)*) => { $($item)* }; }\n",
        )
        .file("src/first.rs", "cfg_items! { pub mod second; }\n")
        .file("src/first/second.rs", "pub struct Nested;\n")
        .build();

    let start = root
        .find("crate::first::second::Nested")
        .expect("nested reference")
        + "crate::first::second::".len();
    let value = lookup(
        project.root(),
        &location_reference("src/lib.rs", root, start),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["path"], "src/first/second.rs",
        "{value}"
    );
}

#[test]
fn rust_private_sibling_macro_does_not_authorize_same_target_invocations() {
    let consumer = r#"
cfg_items! { mod hidden; }
fn invalid(_: self::hidden::Hidden) {}
"#;
    let before = "too_late! { mod generated; }\nfn invalid(_: self::generated::Generated) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "mod private_macros;\nmod consumer;\nmod before;\nmacro_rules! too_late { ($($item:item)*) => { $($item)* }; }\n",
        )
        .file(
            "src/private_macros.rs",
            "macro_rules! cfg_items { ($($item:item)*) => { $($item)* }; }\n",
        )
        .file("src/consumer.rs", consumer)
        .file("src/consumer/hidden.rs", "pub struct Hidden;\n")
        .file("src/before.rs", before)
        .file("src/before/generated.rs", "pub struct Generated;\n")
        .build();

    let start = consumer
        .find("self::hidden::Hidden")
        .expect("private sibling reference")
        + "self::hidden::".len();
    let value = lookup(
        project.root(),
        &location_reference("src/consumer.rs", consumer, start),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");

    let start = before
        .find("self::generated::Generated")
        .expect("early child reference")
        + "self::generated::".len();
    let value = lookup(
        project.root(),
        &location_reference("src/before.rs", before, start),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn legacy_byte_range_is_rejected_without_exposing_byte_guidance() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("lib.rs", "pub fn helper() { let café = 1; }\n")
        .build();

    let source = std::fs::read_to_string(project.root().join("lib.rs")).expect("source");
    let start = source.find('é').expect("non-ascii byte");
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"lib.rs","start_byte":{},"end_byte":{}}}]}}"#,
            start + 1,
            start + 2
        ),
    );

    assert_eq!(value["results"][0]["status"], "invalid_location", "{value}");
    assert!(!value.to_string().contains("byte"), "{value}");
}

#[test]
fn typescript_named_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("util.ts", "export function helper() {}\n")
        .file(
            "app.ts",
            r#"
import { helper } from "./util";

export function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.ts", "{value}");
}

#[test]
fn typescript_value_reference_prefers_const_over_same_named_interface() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export interface Widget {
  value: string;
}
export const Widget = makeWidget();

export function run() {
  consume(Widget);
}
"#,
        )
        .build();

    let line = "  consume(Widget);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":8,"column":{}}}]}}"#,
            column_of(line, "Widget")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "field", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 5, "{value}");
}

#[test]
fn typescript_type_reference_prefers_interface_over_same_named_const() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export interface Widget {
  value: string;
}
export const Widget = makeWidget();

export function run(value: Widget) {
  return value;
}
"#,
        )
        .build();

    let line = "export function run(value: Widget) {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(line, "Widget")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "class", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 2, "{value}");
}

#[test]
fn typescript_reference_context_resolves_type_alias_union_member() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export type ClientOptionsWithUrl = {
  accelerateUrl: string
}

export type ClientOptionsWithAdapter = {
  adapter: unknown
}

export type ClientOptions = ClientOptionsWithUrl | ClientOptionsWithAdapter
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "ClientOptions",
                "context": "export type ClientOptions = ClientOptionsWithUrl | ClientOptionsWithAdapter",
                "target": "ClientOptionsWithUrl"
            }]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "app.ts.ClientOptionsWithUrl",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["start_line"], 2,
        "{value}"
    );
}

#[test]
fn typescript_path_alias_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "~/*": ["src/*"] } } }"#,
        )
        .file("src/util.ts", "export function helper() {}\n")
        .file(
            "app.ts",
            r#"
import { helper } from "~/util";

export function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "src/util.ts", "{value}");
}

#[test]
fn typescript_js_extension_import_resolves_to_ts_source() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("util.ts", "export function helper() {}\n")
        .file(
            "app.ts",
            r#"
import { helper } from "./util.js";

export function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "helper", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.ts", "{value}");
}

#[test]
fn typescript_path_alias_import_resolves_through_star_barrel() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@renderer/*": ["src/renderer/*"] } } }"#,
        )
        .file("src/renderer/utils/index.ts", "export * from \"./naming\";\n")
        .file(
            "src/renderer/utils/naming.ts",
            "export function isEmoji(value: string): boolean { return value.length > 0; }\n",
        )
        .file(
            "src/renderer/components/UserPopup.tsx",
            r#"
import { isEmoji } from "@renderer/utils";

export function render(avatar: string) {
  return isEmoji(avatar);
}
"#,
        )
        .build();

    let line = "  return isEmoji(avatar);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/renderer/components/UserPopup.tsx","line":5,"column":{}}}]}}"#,
            column_of(line, "isEmoji")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "isEmoji", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "src/renderer/utils/naming.ts",
        "{value}"
    );
}

#[test]
fn typescript_imported_object_literal_property_resolves_through_star_barrel() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@renderer/*": ["src/renderer/*"] } } }"#,
        )
        .file(
            "src/renderer/primitives/index.ts",
            "export * from \"./classNames\";\n",
        )
        .file(
            "src/renderer/primitives/classNames.ts",
            r#"
export const providerListClasses = {
  itemEnabledDot: 'dot',
  itemLabel: 'label'
} as const
"#,
        )
        .file(
            "src/renderer/components/ProviderListItem.tsx",
            r#"
import { providerListClasses } from "@renderer/primitives";

export function render() {
  return providerListClasses.itemEnabledDot;
}
"#,
        )
        .build();

    let line = "  return providerListClasses.itemEnabledDot;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/renderer/components/ProviderListItem.tsx","line":5,"column":{}}}]}}"#,
            column_of(line, "itemEnabledDot")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "providerListClasses.itemEnabledDot",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/renderer/primitives/classNames.ts",
        "{value}"
    );
}

#[test]
fn typescript_destructured_typed_parameter_member_resolves_to_schema_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "provider.ts",
            r#"
export const ProviderSchema = z.object({
  isEnabled: z.boolean(),
})
export type Provider = z.infer<typeof ProviderSchema>
"#,
        )
        .file(
            "app.ts",
            r#"
import type { Provider } from './provider'

interface Props {
  provider: Provider
}

export function Item({ provider }: Props) {
  return provider.isEnabled
}
"#,
        )
        .build();

    let line = "  return provider.isEnabled";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":9,"column":{}}}]}}"#,
            column_of(line, "isEnabled")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ProviderSchema.isEnabled",
        "{value}"
    );
}

#[test]
fn typescript_call_initialized_local_member_resolves_to_returned_object_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "build.ts",
            r#"
export const getBuildConfig = () => {
  return {
    visionModels: '',
  }
}

export type BuildConfig = ReturnType<typeof getBuildConfig>
"#,
        )
        .file(
            "client.ts",
            r#"
import { BuildConfig, getBuildConfig } from './build'

export function getClientConfig() {
  if (window) {
    return JSON.parse('{}') as BuildConfig
  }
  return getBuildConfig()
}
"#,
        )
        .file(
            "app.ts",
            r#"
import { getClientConfig } from './client'

export function isVisionModel() {
  const clientConfig = getClientConfig()
  return clientConfig.visionModels
}
"#,
        )
        .build();

    let line = "  return clientConfig.visionModels";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "visionModels")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "getBuildConfig.visionModels",
        "{value}"
    );
}

#[test]
fn typescript_new_initialized_local_method_resolves_to_class_member() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "greeter.ts",
            r#"
export class Greeter {
  greet(): string {
    return 'hello'
  }
}
"#,
        )
        .file(
            "app.ts",
            r#"
import { Greeter } from './greeter'

export function run() {
  const greeter = new Greeter()
  return greeter.greet()
}
"#,
        )
        .build();

    let line = "  return greeter.greet()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "greet()")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Greeter.greet", "{value}");
    assert_eq!(result["definitions"][0]["path"], "greeter.ts", "{value}");
}

#[test]
fn typescript_reassigned_new_initialized_local_method_does_not_guess() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
class Greeter {
  greet(): string {
    return 'hello'
  }
}

declare function dynamicValue(): unknown

export function run() {
  let greeter = new Greeter()
  greeter = dynamicValue()
  return greeter.greet()
}
"#,
        )
        .build();

    let line = "  return greeter.greet()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":13,"column":{}}}]}}"#,
            column_of(line, "greet()")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_cyclic_local_receiver_inference_terminates_without_unrelated_owner() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
class Unrelated {
  make(): Unrelated { return this }
  run(): void {}
}

export function start() {
  const service = service.make()
  service.run()
}
"#,
        )
        .build();

    let source = project.file("app.ts").read_to_string().expect("app source");
    let reference_start = source.rfind("run()").expect("receiver call");
    let value = lookup(
        project.root(),
        &location_reference("app.ts", &source, reference_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert!(result["definitions"].is_null(), "{value}");
}

#[test]
fn typescript_contextual_callback_receiver_cycle_terminates_without_unrelated_owner() {
    let source = r#"
class Unrelated {
  withChild(callback: (child: Unrelated) => void): void {}
  run(): void {}
}

export function start() {
  const child = child.withChild((child) => child.run())
}
"#;
    let reference_start = source.rfind("run()").expect("callback receiver call");
    let args = location_reference("app.ts", source, reference_start);
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", source)
        .build();

    let value = lookup(project.root(), &args);

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert!(result["definitions"].is_null(), "{value}");
}

#[test]
fn typescript_deep_acyclic_receiver_chain_stops_at_semantic_budget() {
    const DEPTH: usize = 4_000;
    let mut source = String::from(
        r#"
class Service {
  make(): Service { return this }
  run(): void {}
}

export function start() {
  const value4000 = new Service()
"#,
    );
    for index in (0..DEPTH).rev() {
        source.push_str(&format!(
            "  const value{index} = value{}.make()\n",
            index + 1
        ));
    }
    source.push_str("  value0.run()\n}\n");
    let reference_start = source.rfind("run()").expect("receiver call");
    let args = location_reference("app.ts", &source, reference_start);
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", source)
        .build();

    let value = lookup(project.root(), &args);

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert!(result["definitions"].is_null(), "{value}");
}

#[test]
fn typescript_deep_acyclic_receiver_lookup_is_stack_safe() {
    const DEPTH: usize = 4_000;
    let mut source = String::from(
        r#"
class Service {
  run(): void {}
}

export function start() {
"#,
    );
    for _ in 0..DEPTH {
        source.push_str("  if (true) {\n");
    }
    source.push_str("  const service = new Service()\n  service.run()\n");
    for _ in 0..DEPTH {
        source.push_str("  }\n");
    }
    source.push_str("}\n");
    let reference_start = source.rfind("run()").expect("receiver call");
    let args = location_reference("app.ts", &source, reference_start);
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", source)
        .build();

    let value = lookup(project.root(), &args);

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Service.run", "{value}");
}

#[test]
fn typescript_contextual_callback_parameter_members_resolve() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "utils.ts",
            r#"
export class Response {
  setPage(): void {}
}

export class Context {
  newPage(): Page { return new Page() }
}

export class Page {
  pptrPage = ''
}

export function withContext(cb: (response: Response, context: Context) => void): void {}
"#,
        )
        .file(
            "app.ts",
            r#"
import { withContext } from './utils.js'

export function run() {
  withContext((response, context) => {
    context.newPage()
    response.setPage()
  })
}
"#,
        )
        .build();

    let context_line = "    context.newPage()";
    let context_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":6,"column":{}}}]}}"#,
            column_of(context_line, "newPage")
        ),
    );

    let context_result = &context_value["results"][0];
    assert_eq!(context_result["status"], "resolved", "{context_value}");
    assert_eq!(
        context_result["definitions"][0]["fqn"], "Context.newPage",
        "{context_value}"
    );

    let response_line = "    response.setPage()";
    let response_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(response_line, "setPage")
        ),
    );

    let response_result = &response_value["results"][0];
    assert_eq!(response_result["status"], "resolved", "{response_value}");
    assert_eq!(
        response_result["definitions"][0]["fqn"], "Response.setPage",
        "{response_value}"
    );
}

#[test]
fn typescript_member_call_contextual_callback_parameter_members_resolve() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "utils.ts",
            r#"
export class Context {
  newPage(): Page { return new Page() }
}

export class Page {}

export function withContext(cb: (context: Context) => void): void {}
"#,
        )
        .file(
            "app.ts",
            r#"
import * as utils from './utils.js'

export function run() {
  utils.withContext(context => {
    context.newPage()
  })
}
"#,
        )
        .build();

    let line = "    context.newPage()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "newPage")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Context.newPage",
        "{value}"
    );
}

#[test]
fn typescript_awaited_member_call_initialized_local_resolves_to_return_type_member() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "utils.ts",
            r#"
export class Context {
  newPage(): Promise<Page> { return Promise.resolve(new Page()) }
}

export class Page {
  pptrPage = ''
}

export function withContext(cb: (context: Context) => Promise<void>): void {}
"#,
        )
        .file(
            "app.ts",
            r#"
import { withContext } from './utils.js'

export function run() {
  withContext(async context => {
    const page = await context.newPage()
    page.pptrPage
  })
}
"#,
        )
        .build();

    let line = "    page.pptrPage";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(line, "pptrPage")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Page.pptrPage", "{value}");
}

#[test]
fn typescript_call_initialized_exported_object_member_resolves_to_argument_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tool.ts",
            r#"
export function defineTool<T>(definition: T): T {
  return {
    ...definition,
    pageScoped: true,
  } as T
}

export const listTools = defineTool({
  handler(): void {},
})
"#,
        )
        .file(
            "app.ts",
            r#"
import { listTools } from './tool.js'

export function run() {
  listTools.handler()
}
"#,
        )
        .build();

    let line = "  listTools.handler()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "handler")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "listTools.handler",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["start_line"], 10, "{value}");
}

#[test]
fn typescript_call_argument_object_member_requires_shape_preserving_callee() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tool.ts",
            r#"
export function log(definition: { handler(): void }): void {}

export const listTools = log({
  handler(): void {},
})
"#,
        )
        .file(
            "app.ts",
            r#"
import { listTools } from './tool.js'

export function run() {
  listTools.handler()
}
"#,
        )
        .build();

    let line = "  listTools.handler()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "handler")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_window_member_resolves_to_ambient_window_interface_property() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export {}

declare global {
  interface Window {
    __dtmcp?: {
      toolGroups?: string[]
    }
  }
}

export function run() {
  if (window.__dtmcp) {}
}
"#,
        )
        .build();

    let line = "  if (window.__dtmcp) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":13,"column":{}}}]}}"#,
            column_of(line, "__dtmcp")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Window.__dtmcp", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 6, "{value}");
}

#[test]
fn typescript_window_member_ignores_non_ambient_local_window_class() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
class Window {
  other(): void {}
}

export function run() {
  window.other()
}
"#,
        )
        .build();

    let line = "  window.other()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":7,"column":{}}}]}}"#,
            column_of(line, "other")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn javascript_destructured_commonjs_require_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "util.js",
            "function helper() {}\nexports.helper = helper;\n",
        )
        .file(
            "app.js",
            r#"
const { helper } = require("./util");

function run() {
  helper();
}
"#,
        )
        .build();

    let line = "  helper();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":5,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "util.js", "{value}");
}

#[test]
fn javascript_commonjs_factory_returned_object_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "lib.js",
            r#"
function makeToolbox() {
  return {
    format(value) {
      return value.label;
    },
  };
}

module.exports = { makeToolbox };
"#,
        )
        .file(
            "app.js",
            r#"
const { makeToolbox } = require("./lib");

function run(widget) {
  const toolbox = makeToolbox();
  return toolbox.format(widget);
}
"#,
        )
        .build();

    let line = "  return toolbox.format(widget);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":6,"column":{}}}]}}"#,
            column_of(line, "format")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "makeToolbox.format",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "lib.js", "{value}");
}

#[test]
fn javascript_commonjs_host_module_does_not_resolve_to_exported_module_property() {
    let commonjs_source = r#"module.exports = {
  module: { rules: [] },
};
"#;
    let consumer_source = "const config = require('./webpack.config');\nconfig.module.rules;\n";
    let local_source = "const module = { exports: null };\nmodule.exports = {};\nmodule;\n";
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("webpack.config.js", commonjs_source)
        .file("consumer.js", consumer_source)
        .file("local.js", local_source)
        .build();

    let host = lookup(
        project.root(),
        &location_reference("webpack.config.js", commonjs_source, 0),
    );
    assert_eq!(host["results"][0]["status"], "no_definition", "{host}");
    assert_eq!(
        host["results"][0]["diagnostics"][0]["kind"], "commonjs_host_binding",
        "{host}"
    );

    let property = lookup(
        project.root(),
        &location_reference(
            "consumer.js",
            consumer_source,
            consumer_source.find("module.rules").expect("module use"),
        ),
    );
    assert_eq!(property["results"][0]["status"], "resolved", "{property}");
    assert_eq!(
        property["results"][0]["definitions"][0]["fqn"], "module",
        "{property}"
    );
    assert_eq!(
        property["results"][0]["definitions"][0]["path"], "webpack.config.js",
        "{property}"
    );

    for local_reference in [
        local_source
            .find("module.exports")
            .expect("local member use"),
        local_source.rfind("module;").expect("local bare use"),
    ] {
        let local = lookup(
            project.root(),
            &location_reference("local.js", local_source, local_reference),
        );
        assert_eq!(local["results"][0]["status"], "resolved", "{local}");
        assert_eq!(
            local["results"][0]["definitions"][0]["path"], "local.js",
            "{local}"
        );
        assert_eq!(
            local["results"][0]["definitions"][0]["start_line"], 1,
            "{local}"
        );
    }
}

#[test]
fn javascript_same_file_object_literal_property_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
const classes = {
  enabled: 'dot'
};

function render() {
  return classes.enabled;
}
"#,
        )
        .build();

    let line = "  return classes.enabled;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "enabled")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.js.classes.enabled",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_local_bindings_and_named_roles_block_indexed_fallback() {
    let source = r#"
const aliases = { c: 1 };
const bench = { start() {} };

function deref(c) {
  const path = c;
  return aliases[c] + c + path;
}

class ArboristNode {
  path;
  constructor(path) { this.path = path; }
}

function createConnection() {}
const options = { createConnection: deref };

class WithGetter { get value() { return 1; } }

const FieldBehavior = {};
(function(FieldBehavior) { return FieldBehavior; })(FieldBehavior);

bench.start();
"#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", source)
        .build();

    for start in [
        source.find("deref(c)").unwrap() + "deref(".len(),
        source.find("aliases[c]").unwrap() + "aliases[".len(),
        source.find("+ c +").unwrap() + 2,
        source.find("constructor(path)").unwrap() + "constructor(".len(),
        source.find("= path;").unwrap() + 2,
        source.find("return FieldBehavior;").unwrap() + "return ".len(),
    ] {
        let value = lookup(project.root(), &location_reference("app.js", source, start));
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert!(
            value["results"][0]["definitions"][0].get("fqn").is_none(),
            "{value}"
        );
    }

    for start in [
        source.find("+ path;").unwrap() + 2,
        source.find("  path;\n").unwrap() + 2,
        source.find("{ createConnection:").unwrap() + 2,
        source.find("get value()").unwrap() + "get ".len(),
    ] {
        let value = lookup(project.root(), &location_reference("app.js", source, start));
        assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    }

    let bench = lookup(
        project.root(),
        &location_reference("app.js", source, source.find("bench.start").unwrap()),
    );
    assert_eq!(bench["results"][0]["status"], "resolved", "{bench}");
    assert_eq!(
        bench["results"][0]["definitions"][0]["fqn"], "app.js.bench",
        "{bench}"
    );
}

#[test]
fn javascript_bare_function_beats_same_named_member() {
    let source = r#"const holder = {};
holder.foo = undefined;
function foo() {}
foo();
"#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", source)
        .build();
    let call = source.rfind("foo();").expect("bare foo call");
    let value = lookup(project.root(), &location_reference("app.js", source, call));

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "foo", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_recovered_top_level_function_never_resolves_unrelated_member() {
    let source = r#"var __v_0 = [1, 2, 3];
__v_0.foo = undefined;
function foo() {}
%OptimizeFunctionOnNextCall(foo);
foo();
"#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("recovered.js", source)
        .build();
    let call = source.rfind("foo();").expect("recovered bare foo call");
    let value = lookup(
        project.root(),
        &location_reference("recovered.js", source, call),
    );

    let result = &value["results"][0];
    if result["status"] == "resolved" {
        assert_eq!(result["definitions"][0]["fqn"], "foo", "{value}");
    } else {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert!(result["definitions"].is_null(), "{value}");
    }
}

#[test]
fn javascript_hoisted_declarations_block_member_fallback() {
    let source = r#"member.pause = function() {};
member.generator = function() {};
member.LocalClass = function() {};
member.unrelated = function() {};

function outer() {
  pause();
  generator();
  LocalClass;
  function pause() {}
  function* generator() {}
  class LocalClass {}
}

member.pause();
unrelated();
"#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", source)
        .build();

    for marker in ["  pause();", "  generator();", "  LocalClass;"] {
        let start = source.find(marker).expect("nested declaration reference") + 2;
        let value = lookup(project.root(), &location_reference("app.js", source, start));
        let result = &value["results"][0];
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(result["diagnostics"][0]["kind"], "local_binding", "{value}");
    }

    let qualified = source.rfind("member.pause").expect("qualified member call");
    let value = lookup(
        project.root(),
        &location_reference("app.js", source, qualified + "member.".len()),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "member.pause", "{value}");

    let unrelated = source.rfind("unrelated();").expect("bare unrelated call");
    let value = lookup(
        project.root(),
        &location_reference("app.js", source, unrelated),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn javascript_bare_import_and_browser_global_resolution_remain_exact() {
    let app = r#"import { helper } from "./util.js";
window.Promise = function Promise() {};

function imported() { helper(); }
function globalRead() { return Promise.resolve(); }
function shadowed(Promise) { return Promise; }
"#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("util.js", "export function helper() {}\n")
        .file("app.js", app)
        .build();

    let helper = app.find("helper();").expect("imported helper call");
    let value = lookup(project.root(), &location_reference("app.js", app, helper));
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "helper",
        "{value}"
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["path"], "util.js",
        "{value}"
    );

    let promise = app.find("Promise.resolve").expect("bare global Promise");
    let value = lookup(project.root(), &location_reference("app.js", app, promise));
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "window.Promise",
        "{value}"
    );

    let shadow = app.rfind("return Promise").expect("shadowed Promise read") + "return ".len();
    let value = lookup(project.root(), &location_reference("app.js", app, shadow));
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert!(
        value["results"][0]["definitions"][0].get("fqn").is_none(),
        "{value}"
    );
}

#[test]
fn typescript_local_bindings_and_uncontextual_object_keys_block_indexed_fallback() {
    let source = r#"
class Record { value = 1 }
function createConnection() {}
function run(value: number) {
  const local = value;
  return value + local;
}
const options = { createConnection: run };
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", source)
        .build();

    for start in [
        source.find("run(value:").unwrap() + "run(".len(),
        source.find("= value;").unwrap() + 2,
        source.find("return value").unwrap() + "return ".len(),
    ] {
        let value = lookup(project.root(), &location_reference("app.ts", source, start));
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["name"], "value",
            "{value}"
        );
        assert!(
            value["results"][0]["definitions"][0].get("fqn").is_none(),
            "{value}"
        );
    }

    for start in [
        source.find("Record { value").unwrap() + "Record { ".len(),
        source.find("+ local;").unwrap() + 2,
        source.find("{ createConnection:").unwrap() + 2,
    ] {
        let value = lookup(project.root(), &location_reference("app.ts", source, start));
        assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    }
}

#[test]
fn typescript_for_of_bindings_block_same_named_indexed_fields() {
    let source = r#"
class SortItem {
  field = "indexed";
  key = "indexed";
  config = "indexed";
  uid = "indexed";
  source = "indexed";
}

function consume(...values: unknown[]) {}

function render(entries: unknown[], fallback: string) {
  for (const field of entries) {
    consume(field);
  }
  for (const [key, config] of entries) {
    consume("array", key, config);
  }
  for (const { key, config } of entries) {
    consume("object", key, config);
  }
  for (const { uid, source: { config = fallback }, ...source } of entries) {
    consume("nested", uid, config, source);
  }
}
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", source)
        .build();

    for (marker, identifiers) in [
        ("consume(field)", &["field"][..]),
        ("consume(\"array\", key, config)", &["key", "config"][..]),
        ("consume(\"object\", key, config)", &["key", "config"][..]),
        (
            "consume(\"nested\", uid, config, source)",
            &["uid", "config", "source"][..],
        ),
    ] {
        let line_start = source.find(marker).expect("loop-body marker");
        for identifier in identifiers {
            let start = line_start + marker.find(identifier).expect("identifier in marker");
            let value = lookup(project.root(), &location_reference("app.ts", source, start));
            let result = &value["results"][0];
            assert_eq!(result["status"], "no_definition", "{value}");
            assert!(result["definitions"].is_null(), "{value}");
            assert_eq!(result["diagnostics"][0]["kind"], "local_binding", "{value}");
        }
    }

    let fallback = source
        .find("config = fallback")
        .expect("default initializer")
        + "config = ".len();
    let value = lookup(
        project.root(),
        &location_reference("app.ts", source, fallback),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "fallback", "{value}");
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn javascript_member_assignment_function_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
const utils = {};
utils.typeConverter = function (value) {
  return value;
};

function render() {
  return utils.typeConverter(1);
}
"#,
        )
        .build();

    let line = "  return utils.typeConverter(1);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":8,"column":{}}}]}}"#,
            column_of(line, "typeConverter")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "utils.typeConverter",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "function", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_new_initialized_local_method_resolves_to_class_member() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
class Greeter {
  greet() {
    return 'hello';
  }
}

function run() {
  const greeter = new Greeter();
  return greeter.greet();
}
"#,
        )
        .build();

    let line = "  return greeter.greet();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":10,"column":{}}}]}}"#,
            column_of(line, "greet()")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Greeter.greet", "{value}");
}

#[test]
fn javascript_imported_factory_receiver_method_resolves_to_class_member() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "components.js",
            r#"
export class Greeter {
  greet(user) {
    return user.name;
  }
}

export function createGreeter() {
  return new Greeter();
}
"#,
        )
        .file(
            "app.js",
            r#"
import { createGreeter } from "./components.js";

const greeter = createGreeter();
const message = greeter.greet({ name: "Ada" });
"#,
        )
        .build();

    let line = r#"const message = greeter.greet({ name: "Ada" });"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":5,"column":{}}}]}}"#,
            column_of(line, "greet(")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Greeter.greet", "{value}");
    assert_eq!(result["definitions"][0]["path"], "components.js", "{value}");
}

#[test]
fn javascript_object_literal_method_receiver_resolves_to_method_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "library.js",
            r#"
class Task {
  finish() {
    return helpers.formatTask(this);
  }
}

const helpers = {
  formatTask(task) {
    return task.label;
  },
};

exports.helpers = helpers;
"#,
        )
        .file(
            "consumer.js",
            r#"
const { helpers } = require("./library");

helpers.formatTask({ label: "direct" });
"#,
        )
        .build();

    let library_line = "    return helpers.formatTask(this);";
    let library_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"library.js","line":4,"column":{}}}]}}"#,
            column_of(library_line, "formatTask")
        ),
    );
    let library_result = &library_value["results"][0];
    assert_eq!(library_result["status"], "resolved", "{library_value}");
    assert_eq!(
        library_result["definitions"][0]["fqn"], "helpers.formatTask",
        "{library_value}"
    );

    let consumer_line = r#"helpers.formatTask({ label: "direct" });"#;
    let consumer_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"consumer.js","line":4,"column":{}}}]}}"#,
            column_of(consumer_line, "formatTask")
        ),
    );
    let consumer_result = &consumer_value["results"][0];
    assert_eq!(consumer_result["status"], "resolved", "{consumer_value}");
    assert_eq!(
        consumer_result["definitions"][0]["fqn"], "helpers.formatTask",
        "{consumer_value}"
    );
}

#[test]
fn javascript_this_property_resolves_to_constructor_assignment() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "components.js",
            r#"
export class Greeter {
  constructor(title) {
    this.title = title;
  }

  greet(user) {
    return `${this.title}, ${user.name}`;
  }
}
"#,
        )
        .build();

    let line = "    return `${this.title}, ${user.name}`;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"components.js","line":8,"column":{}}}]}}"#,
            column_of(line, "title")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Greeter.title", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 4, "{value}");
}

#[test]
fn javascript_this_property_in_exported_class_resolves_to_constructor_assignment() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "components.js",
            r#"
export const DEFAULT_TITLE = "Welcome";

export class Greeter {
  constructor(title = DEFAULT_TITLE) {
    this.title = title;
  }

  greet(user) {
    return `${this.title}, ${formatName(user)}`;
  }
}

export function formatName(user) {
  return user.name.trim();
}
"#,
        )
        .build();

    let line = "    return `${this.title}, ${formatName(user)}`;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"components.js","line":10,"column":{},"symbol":"title"}}]}}"#,
            column_of(line, "title")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Greeter.title", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 6, "{value}");
}

#[test]
fn javascript_member_assignment_object_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
const alasql = {};
alasql.options = {
  csvStringToNumber: true
};

function render() {
  return alasql.options.csvStringToNumber;
}
"#,
        )
        .build();

    let line = "  return alasql.options.csvStringToNumber;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":8,"column":{}}}]}}"#,
            column_of(line, "options")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "alasql.options", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "field", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_cross_file_member_assignment_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "defs.js",
            r#"
const alasql = {};
alasql.options = {
  csvStringToNumber: true
};
"#,
        )
        .file(
            "use.js",
            r#"
function render() {
  return alasql.options.csvStringToNumber;
}
"#,
        )
        .build();

    let line = "  return alasql.options.csvStringToNumber;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"use.js","line":3,"column":{}}}]}}"#,
            column_of(line, "options")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "alasql.options", "{value}");
    assert_eq!(result["definitions"][0]["path"], "defs.js", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_local_member_assignment_resolves_later_member_use() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function compile(query) {
  query.windowaggrs = [];
  if (query.windowaggrs && query.windowaggrs.length > 0) {
    return query.windowaggrs;
  }
}
"#,
        )
        .build();

    let line = "  if (query.windowaggrs && query.windowaggrs.length > 0) {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":4,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "query.windowaggrs",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn javascript_local_member_assignment_does_not_cross_function_scope() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function compile(query) {
  query.windowaggrs = [];
}

function render(query) {
  return query.windowaggrs;
}
"#,
        )
        .build();

    let line = "  return query.windowaggrs;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn javascript_unparenthesized_arrow_parameter_blocks_project_wide_member_fallback() {
    let consumer = r#"
const inspect = data => data.originalPlacement;
const inspectParenthesized = (data) => data.originalPlacement;

const inspectLocal = data => {
  data.localPlacement = data.placement;
  return data.localPlacement;
};
"#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "generated.js",
            r#"
function update(data) {
  data.originalPlacement = data.placement;
}
"#,
        )
        .file("consumer.js", consumer)
        .build();

    let unrelated_reads: Vec<_> = consumer
        .match_indices("data.originalPlacement")
        .map(|(start, _)| start)
        .collect();
    assert_eq!(unrelated_reads.len(), 2);
    for unrelated_read in unrelated_reads {
        let value = lookup(
            project.root(),
            &location_reference("consumer.js", consumer, unrelated_read + "data.".len()),
        );
        assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    }

    let local_read = consumer
        .rfind("data.localPlacement")
        .expect("same-arrow local property read");
    let value = lookup(
        project.root(),
        &location_reference("consumer.js", consumer, local_read + "data.".len()),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "consumer.js", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 6, "{value}");
}

#[test]
fn javascript_block_shadowed_member_assignment_does_not_resolve_outer_receiver() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function render(query, cond) {
  if (cond) {
    let query = {};
    query.windowaggrs = [];
  }
  return query.windowaggrs;
}
"#,
        )
        .build();

    let line = "  return query.windowaggrs;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn javascript_var_receiver_assignment_remains_function_scoped_across_blocks() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
function render(cond) {
  if (cond) {
    var query = {};
    query.windowaggrs = [];
  }
  return query.windowaggrs;
}
"#,
        )
        .build();

    let line = "  return query.windowaggrs;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":7,"column":{}}}]}}"#,
            column_of(line, "windowaggrs")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "query.windowaggrs",
        "{value}"
    );
}

#[test]
fn javascript_member_expression_receiver_focus_resolves_receiver_definition() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "app.js",
            r#"
var re_aggrWithExpression = /^(SUM|MAX)$/;

function accepts(value) {
  return re_aggrWithExpression.test(value);
}
"#,
        )
        .build();

    let line = "  return re_aggrWithExpression.test(value);";
    let receiver_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":5,"column":{}}}]}}"#,
            column_of(line, "re_aggrWithExpression")
        ),
    );

    let result = &receiver_value["results"][0];
    assert_eq!(result["status"], "resolved", "{receiver_value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.js.re_aggrWithExpression",
        "{receiver_value}"
    );
    assert_eq!(
        result["definitions"][0]["start_line"], 2,
        "{receiver_value}"
    );

    let property_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.js","line":5,"column":{}}}]}}"#,
            column_of(line, "test")
        ),
    );
    assert_eq!(
        property_value["results"][0]["status"], "no_definition",
        "{property_value}"
    );
}

#[test]
fn javascript_unknown_receiver_member_does_not_guess_same_file_function() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export function method() {}

export function run(obj: any) {
  obj.method();
}
"#,
        )
        .build();

    let line = "  obj.method();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "method")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_unknown_global_members_do_not_guess_project_definitions() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/app.ts",
            r#"
export function run() {
  console.error("boom");
  return process.argv;
}
"#,
        )
        .file(
            "mocks/globals.ts",
            r#"
export const console = {
  error(message: string) {}
};

export const process = {
  argv: ["--mock"]
};
"#,
        )
        .build();

    for (line_number, line, member) in [
        (3, "  console.error(\"boom\");", "error"),
        (4, "  return process.argv;", "argv"),
    ] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"src/app.ts","line":{line_number},"column":{}}}]}}"#,
                column_of(line, member)
            ),
        );

        assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    }
}

#[test]
fn typescript_cross_file_ambient_namespace_resolves_to_global_declaration() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "globals.d.ts",
            r#"
declare namespace ThirdPartyLib {
  interface LibOptions {
    enabled: boolean
  }
}
"#,
        )
        .file(
            "app.ts",
            r#"
export const options: ThirdPartyLib.LibOptions = { enabled: true }
"#,
        )
        .build();

    let line = "export const options: ThirdPartyLib.LibOptions = { enabled: true }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":2,"column":{}}}]}}"#,
            column_of(line, "LibOptions")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "ThirdPartyLib.LibOptions",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "globals.d.ts", "{value}");
}

#[test]
fn typescript_cross_file_umd_namespace_resolves_to_global_declaration() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "globals.d.ts",
            r#"
export as namespace ThirdPartyLib;
export = ThirdPartyLib;

declare namespace ThirdPartyLib {
  interface LibOptions {
    enabled: boolean
  }
}
"#,
        )
        .file(
            "app.ts",
            r#"
let options: ThirdPartyLib.LibOptions;
"#,
        )
        .build();

    let line = "let options: ThirdPartyLib.LibOptions;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":2,"column":{}}}]}}"#,
            column_of(line, "LibOptions")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ThirdPartyLib.LibOptions",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "globals.d.ts", "{value}");
}

#[test]
fn typescript_cross_file_exported_namespace_requires_an_import() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "library.ts",
            r#"
export namespace ThirdPartyLib {
  export interface LibOptions {
    enabled: boolean
  }
}
"#,
        )
        .file(
            "app.ts",
            r#"
export const options: ThirdPartyLib.LibOptions = { enabled: true }
"#,
        )
        .build();

    let line = "export const options: ThirdPartyLib.LibOptions = { enabled: true }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":2,"column":{}}}]}}"#,
            column_of(line, "LibOptions")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_this_member_uses_exact_enclosing_class_with_duplicate_names() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "z/current.ts",
            r#"
export class ErrorBoundary {
  state = { failed: false };

  render() {
    return this.state.failed;
  }
}
"#,
        )
        .file(
            "a/other.ts",
            r#"
export class ErrorBoundary {
  state = { failed: true };
}
"#,
        )
        .build();

    let line = "    return this.state.failed;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"z/current.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "state")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "z/current.ts", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 3, "{value}");
}

#[test]
fn typescript_this_member_does_not_use_same_named_class_from_another_file() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "z/current.ts",
            r#"
export class ErrorBoundary {
  constructor() {
    this.state = { failed: false };
  }

  render() {
    return this.state.failed;
  }
}
"#,
        )
        .file(
            "a/other.ts",
            r#"
export class ErrorBoundary {
  state = { failed: true };
}
"#,
        )
        .build();

    let line = "    return this.state.failed;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"z/current.ts","line":8,"column":{}}}]}}"#,
            column_of(line, "state")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn typescript_this_member_resolves_to_enclosing_class_method() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "context.ts",
            r#"
export class Context {
  private loadResource(url: string): string {
    return url
  }

  constructor() {
    const loader = (url: string) => this.loadResource(url)
  }
}
"#,
        )
        .build();

    let line = "    const loader = (url: string) => this.loadResource(url)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"context.ts","line":8,"column":{}}}]}}"#,
            column_of(line, "loadResource")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Context.loadResource",
        "{value}"
    );
}

#[test]
fn typescript_this_member_resolves_to_enclosing_class_method_body() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "context.ts",
            r#"
export class Context {
  private validatePath(path: string): void {}

  async loadResource(path: string): Promise<string> {
    this.validatePath(path)
    return path
  }
}
"#,
        )
        .build();

    let line = "    this.validatePath(path)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"context.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "validatePath")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Context.validatePath",
        "{value}"
    );
}

#[test]
fn typescript_package_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
import { useMemo } from "react";

export function run() {
  useMemo();
}
"#,
        )
        .build();

    let line = "  useMemo();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":5,"column":{}}}]}}"#,
            column_of(line, "useMemo")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
    let message = value["results"][0]["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(message.contains("outside the indexed workspace"), "{value}");
    assert!(message.contains("partial workspace"), "{value}");
}

#[test]
fn typescript_workspace_module_external_reexport_reports_boundary() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/core.ts",
            r#"
import { exec } from "./vendor-core.js";

export class ProcessPromise {
  run() {
    return exec({});
  }
}
"#,
        )
        .file("src/vendor-core.ts", "export { exec } from 'zurk/spawn';\n")
        .build();

    let line = "    return exec({});";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/core.ts","line":6,"column":{}}}]}}"#,
            column_of(line, "exec")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(message.contains("src/vendor-core.ts"), "{value}");
    assert!(message.contains("zurk/spawn"), "{value}");
    assert!(message.contains("outside the indexed workspace"), "{value}");
}

#[test]
fn go_import_selector_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import "example.com/app/sub"

func Run() {
    sub.Helper()
}
"#,
        )
        .file(
            "sub/sub.go",
            r#"
package sub

func Helper() {}
"#,
        )
        .build();

    let line = "    sub.Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/sub.Helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "sub/sub.go", "{value}");
}

#[test]
fn go_bare_names_respect_interface_parameters_and_package_scope() {
    let source = r#"
package app

type nodeManaged struct {
    nodeName string
}

type errArrayElem struct {
    error
}

type DesiredStateOfWorld interface {
    AddNode(nodeName string)
}

var ordinary = 1

func marshal() error {
    return nil
}

func use() int {
    return ordinary
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file("main.go", source)
        .build();

    let interface_parameter = source
        .find("nodeName string)")
        .expect("interface parameter declaration");
    let value = lookup(
        project.root(),
        &location_reference("main.go", source, interface_parameter),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "nodeName", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "parameter", "{value}");
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");

    let builtin_error = source.find("marshal() error").expect("return type") + "marshal() ".len();
    let value = lookup(
        project.root(),
        &location_reference("main.go", source, builtin_error),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0].get("definitions").is_none(), "{value}");

    let ordinary_reference = source.rfind("ordinary").expect("ordinary reference");
    let value = lookup(
        project.root(),
        &location_reference("main.go", source, ordinary_reference),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app._module_.ordinary",
        "{value}"
    );
}

#[test]
fn go_keyed_composite_labels_resolve_from_exact_struct_owner() {
    let source = r#"
package main

import (
    "example.com/app/model"
    main "example.com/dependency/endpoints"
)

type Local struct {
    LocalField string
}

type MissingFieldOwner struct {
    Other string
}

type Distractor struct {
    Shared string
}

type KeyCollision struct {
    LocalMapKey string
}

type Options struct {
    ResolvedRegion string
}

type Outside struct {
    Field string
}

const LocalMapKey = "local"

var localValue = Local{LocalField: "local"}
var importedValue = model.Imported{ImportedOnly: "imported"}
var sliceValues = []Local{{LocalField: "slice"}}
var arrayValues = [1]model.Imported{{ImportedOnly: "array"}}
var nestedArrays = [1][1]model.Imported{{{ImportedOnly: "nested-array"}}}
var mapValues = map[string]model.Imported{"value": {ImportedOnly: "map"}}
var vendoredAliasCollision = main.Options{ResolvedRegion: "imported-vendor"}
var unresolvedQualifiedOwner = main.Outside{Field: "must not fall back to local Outside.Field"}
var invalidOwner = MissingFieldOwner{Shared: "must not guess Distractor.Shared"}
var keyedMap = map[string]int{LocalMapKey: 1}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file("main.go", source)
        .file(
            "model/model.go",
            r#"
package model

type Imported struct {
    ImportedOnly string
}
"#,
        )
        .file(
            "vendor/example.com/dependency/endpoints/endpoints.go",
            r#"
package endpoints

type Options struct {
    ResolvedRegion string
}
"#,
        )
        .build();

    for (marker, focus, expected_fqn, expected_path) in [
        (
            "Local{LocalField: \"local\"}",
            "LocalField",
            "example.com/app.Local.LocalField",
            "main.go",
        ),
        (
            "model.Imported{ImportedOnly: \"imported\"}",
            "ImportedOnly",
            "example.com/app/model.Imported.ImportedOnly",
            "model/model.go",
        ),
        (
            "[]Local{{LocalField: \"slice\"}}",
            "LocalField",
            "example.com/app.Local.LocalField",
            "main.go",
        ),
        (
            "[1]model.Imported{{ImportedOnly: \"array\"}}",
            "ImportedOnly",
            "example.com/app/model.Imported.ImportedOnly",
            "model/model.go",
        ),
        (
            "[1][1]model.Imported{{{ImportedOnly: \"nested-array\"}}}",
            "ImportedOnly",
            "example.com/app/model.Imported.ImportedOnly",
            "model/model.go",
        ),
        (
            "{\"value\": {ImportedOnly: \"map\"}}",
            "ImportedOnly",
            "example.com/app/model.Imported.ImportedOnly",
            "model/model.go",
        ),
        (
            "main.Options{ResolvedRegion: \"imported-vendor\"}",
            "ResolvedRegion",
            "example.com/app/vendor/example.com/dependency/endpoints.Options.ResolvedRegion",
            "vendor/example.com/dependency/endpoints/endpoints.go",
        ),
    ] {
        let marker_start = source.find(marker).expect("composite marker");
        let focus_start = marker_start + marker.find(focus).expect("focus in marker");
        let value = lookup(
            project.root(),
            &location_reference("main.go", source, focus_start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{marker}: {value}");
        assert_eq!(
            result["definitions"][0]["fqn"], expected_fqn,
            "{marker}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["path"], expected_path,
            "{marker}: {value}"
        );
    }

    let invalid_marker = "MissingFieldOwner{Shared:";
    let invalid_start = source.find(invalid_marker).expect("invalid owner marker")
        + invalid_marker.find("Shared").expect("invalid owner focus");
    let value = lookup(
        project.root(),
        &location_reference("main.go", source, invalid_start),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");

    let unresolved_marker = "main.Outside{Field:";
    let unresolved_start = source
        .find(unresolved_marker)
        .expect("unresolved qualified owner marker")
        + unresolved_marker
            .find("Field")
            .expect("unresolved qualified owner focus");
    let value = lookup(
        project.root(),
        &location_reference("main.go", source, unresolved_start),
    );
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");

    let map_marker = "map[string]int{LocalMapKey:";
    let map_start = source.find(map_marker).expect("map-key marker")
        + map_marker.find("LocalMapKey").expect("map-key focus");
    let value = lookup(
        project.root(),
        &location_reference("main.go", source, map_start),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "example.com/app._module_.LocalMapKey",
        "{value}"
    );
}

#[test]
fn go_import_selector_prefers_nearest_visible_vendor() {
    let source = r#"
package tool

import dep "example.com/dependency/endpoints"

var value = dep.Options{Selected: "nearest"}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file("cmd/tool/main.go", source)
        .file(
            "vendor/example.com/dependency/endpoints/endpoints.go",
            r#"
package endpoints

type Options struct {
    Selected string
}
"#,
        )
        .file(
            "cmd/tool/vendor/example.com/dependency/endpoints/endpoints.go",
            r#"
package endpoints

type Options struct {
    Selected string
}
"#,
        )
        .build();

    let selected = source.find("Selected:").expect("composite field label");
    let value = lookup(
        project.root(),
        &location_reference("cmd/tool/main.go", source, selected),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"],
        "example.com/app/cmd/tool/vendor/example.com/dependency/endpoints.Options.Selected",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"],
        "cmd/tool/vendor/example.com/dependency/endpoints/endpoints.go",
        "{value}"
    );
}

#[test]
fn go_import_selector_resolves_package_var_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import "errors"
import "example.com/app/store"

func Run(err error) bool {
    return errors.Is(err, store.ErrDuplicate)
}
"#,
        )
        .file(
            "store/errors.go",
            r#"
package store

import "errors"

var ErrDuplicate = errors.New("duplicate")
"#,
        )
        .build();

    let line = "    return errors.Is(err, store.ErrDuplicate)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":8,"column":{}}}]}}"#,
            column_of(line, "ErrDuplicate")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/store._module_.ErrDuplicate",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "store/errors.go",
        "{value}"
    );
}

#[test]
fn go_external_import_selector_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "fmt/fmt.go",
            r#"
package fmt

func Println(value string) {}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "fmt"

func Run() {
    fmt.Println("hello")
}
"#,
        )
        .build();

    let line = r#"    fmt.Println("hello")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Println")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn go_external_dot_import_reference_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import . "fmt"

func Run() {
    Println("hello")
}
"#,
        )
        .build();

    let line = r#"    Println("hello")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Println")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn go_dot_import_resolves_unqualified_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import . "example.com/app/sub"

func Run() {
    Helper()
}
"#,
        )
        .file(
            "sub/sub.go",
            r#"
package sub

func Helper() {}
"#,
        )
        .build();

    let line = "    Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/sub.Helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "sub/sub.go", "{value}");
}

#[test]
fn go_receiver_field_chain_resolves_qualified_field_type() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "store/store.go",
            r#"
package store

type Client struct{}

func (c Client) Ping() {}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "example.com/app/store"

type Env struct { Client store.Client }
type Server struct { Env Env }

func (s Server) Run() {
    s.Env.Client.Ping()
}
"#,
        )
        .build();

    let line = "    s.Env.Client.Ping()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":10,"column":{}}}]}}"#,
            column_of(line, "Ping")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/store.Client.Ping",
        "{value}"
    );
}

#[test]
fn go_package_qualified_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "request/nginx.go",
            r#"
package request

type NginxRewriteReq struct {
    WebsiteID uint
    Name string
}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "example.com/app/request"

func GetRewriteConfig(req request.NginxRewriteReq) {
    if req.Name == "current" {
    }
}
"#,
        )
        .build();

    let line = "    if req.Name == \"current\" {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app/request.NginxRewriteReq.Name",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "request/nginx.go",
        "{value}"
    );
}

#[test]
fn go_imported_local_receiver_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "store/store.go",
            r#"
package store

type Client struct {
    Name string
}
"#,
        )
        .file(
            "main.go",
            r#"
package main

import "example.com/app/store"

func Run() {
    var typed store.Client
    _ = typed.Name

    inferred := store.Client{}
    _ = inferred.Name
}
"#,
        )
        .build();

    for (line_no, line) in [(8, "    _ = typed.Name"), (11, "    _ = inferred.Name")] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"main.go","line":{line_no},"column":{}}}]}}"#,
                column_of(line, "Name")
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "example.com/app/store.Client.Name",
            "{value}"
        );
        assert_eq!(
            result["definitions"][0]["path"], "store/store.go",
            "{value}"
        );
    }
}

#[test]
fn go_unresolved_inner_local_receiver_does_not_fall_back_to_outer_binding() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Client struct {
    Name string
}

func Run() {
    client := Client{}
    {
        client := missing()
        _ = client.Name
    }
}
"#,
        )
        .build();

    let line = "        _ = client.Name";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":12,"column":{}}}]}}"#,
            column_of(line, "Name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
}

#[test]
fn go_local_pointer_struct_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type PublishOptions struct {
    Fix bool
}

func NewCmdPublish() {
    opts := &PublishOptions{}
    use(&opts.Fix)
    if opts.Fix {
    }
}

func use(v *bool) {}
"#,
        )
        .build();

    let pointer_line = "    use(&opts.Fix)";
    let pointer_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":10,"column":{}}}]}}"#,
            column_of(pointer_line, "Fix")
        ),
    );
    let pointer_result = &pointer_value["results"][0];
    assert_eq!(pointer_result["status"], "resolved", "{pointer_value}");
    assert_eq!(
        pointer_result["definitions"][0]["fqn"], "example.com/app.PublishOptions.Fix",
        "{pointer_value}"
    );

    let field_line = "    if opts.Fix {";
    let field_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":11,"column":{}}}]}}"#,
            column_of(field_line, "Fix")
        ),
    );
    let field_result = &field_value["results"][0];
    assert_eq!(field_result["status"], "resolved", "{field_value}");
    assert_eq!(
        field_result["definitions"][0]["fqn"], "example.com/app.PublishOptions.Fix",
        "{field_value}"
    );
}

#[test]
fn go_receiver_focus_resolves_to_receiver_parameter() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "buf.go",
            r#"
package app

type Buf struct {
    buffer []byte
}

func (br *Buf) Reset() {
    if br.buffer == nil {
    }
}
"#,
        )
        .build();

    let line = "    if br.buffer == nil {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"buf.go","line":9,"column":{}}}]}}"#,
            column_of(line, "br.buffer")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "br", "{value}");
    assert_eq!(
        result["definitions"][0]["kind"], "receiver_parameter",
        "{value}"
    );
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn go_duplicate_promoted_fields_are_ambiguous() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Left struct {
    ID string
}

type Right struct {
    ID string
}

type Model struct {
    Left
    Right
}

func run(model Model) {
    _ = model.ID
}
"#,
        )
        .build();

    let line = "    _ = model.ID";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":18,"column":{}}}]}}"#,
            column_of(line, "ID")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_definition",
        "{value}"
    );
}

#[test]
fn go_local_alias_to_receiver_field_resolves_field_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "resolver.go",
            r#"
package resolver

type status struct {
    disabledGroups []string
}

type BlockingResolver struct {
    status *status
}

func (r *BlockingResolver) setDisabledGroups(groups []string) {
    s := r.status
    s.disabledGroups = groups
}
"#,
        )
        .build();

    let line = "    s.disabledGroups = groups";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"resolver.go","line":14,"column":{}}}]}}"#,
            column_of(line, "disabledGroups")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.status.disabledGroups",
        "{value}"
    );
}

#[test]
fn go_range_element_struct_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "resolver.go",
            r#"
package resolver

type scheduledGroup struct {
    group string
}

func disable(groups []scheduledGroup) {
    for _, sg := range groups {
        if sg.group == "" {
        }
    }
}
"#,
        )
        .build();

    let line = "        if sg.group == \"\" {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"resolver.go","line":10,"column":{}}}]}}"#,
            column_of(line, "group")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.scheduledGroup.group",
        "{value}"
    );
}

#[test]
fn go_range_element_can_shadow_the_iterable_receiver_without_recursive_inference() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "history.go",
            r#"
package history

type History struct {
    Revision string
}

func visit(history []History) {
    for _, history := range history {
        _ = history.Revision
    }
}
"#,
        )
        .build();

    let line = "        _ = history.Revision";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"history.go","line":10,"column":{}}}]}}"#,
            column_of(line, "Revision")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.History.Revision",
        "{value}"
    );
}

#[test]
fn go_range_element_from_method_return_resolves_field_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "resolver.go",
            r#"
package resolver

type scheduledGroup struct {
    group string
}

type Resolver struct{}

func (r *Resolver) collectGroups() []scheduledGroup {
    return nil
}

func (r *Resolver) disable() {
    groups := r.collectGroups()
    for _, sg := range groups {
        if sg.group == "" {
        }
    }
}
"#,
        )
        .build();

    let line = "        if sg.group == \"\" {";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"resolver.go","line":17,"column":{}}}]}}"#,
            column_of(line, "group")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.scheduledGroup.group",
        "{value}"
    );
}

#[test]
fn go_receiver_chain_focus_resolves_to_receiver_parameter() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "buf.go",
            r#"
package app

import "sync"

type Buf struct {
    rw sync.RWMutex
}

func (br *Buf) Lock() {
    br.rw.Lock()
}
"#,
        )
        .build();

    let line = "    br.rw.Lock()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"buf.go","line":11,"column":{}}}]}}"#,
            column_of(line, "br.rw.Lock")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "br", "{value}");
    assert_eq!(
        result["definitions"][0]["kind"], "receiver_parameter",
        "{value}"
    );
    assert!(
        result["diagnostics"].as_array().unwrap().is_empty(),
        "{value}"
    );
}

#[test]
fn go_selector_focus_resolves_only_the_structured_prefix() {
    let source = r#"
package main

import cfg "example.com/app/config"

type Command struct {
    Options cfg.Options
}

func (c *Command) run() {
    _ = c.Options.KeepUserTurns
}

func shadow() {
    cfg := Command{}
    _ = cfg.Options.KeepUserTurns
}

var _ cfg.Options
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "config/config.go",
            r#"
package config

type Options struct {
    KeepUserTurns bool
}
"#,
        )
        .file("main.go", source)
        .build();

    let chain = source
        .find("c.Options.KeepUserTurns")
        .expect("receiver chain");
    let receiver = lookup(
        project.root(),
        &location_reference("main.go", source, chain),
    );
    let result = &receiver["results"][0];
    assert_eq!(result["status"], "resolved", "{receiver}");
    assert_eq!(result["definitions"][0]["name"], "c", "{receiver}");
    assert_eq!(
        result["definitions"][0]["kind"], "receiver_parameter",
        "{receiver}"
    );

    for (offset, expected) in [
        ("c.".len(), "example.com/app.Command.Options"),
        (
            "c.Options.".len(),
            "example.com/app/config.Options.KeepUserTurns",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("main.go", source, chain + offset),
        );
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{value}"
        );
    }

    let shadowed = source
        .find("cfg.Options.KeepUserTurns")
        .expect("shadowed local chain");
    for (offset, expected) in [
        ("cfg.".len(), "example.com/app.Command.Options"),
        (
            "cfg.Options.".len(),
            "example.com/app/config.Options.KeepUserTurns",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("main.go", source, shadowed + offset),
        );
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{value}"
        );
    }

    let alias_start = source.rfind("cfg.Options").expect("package alias chain");
    let alias = lookup(
        project.root(),
        &location_reference("main.go", source, alias_start),
    );
    assert_eq!(
        alias["results"][0]["status"], "unresolvable_import_boundary",
        "{alias}"
    );

    let package_type = lookup(
        project.root(),
        &location_reference("main.go", source, alias_start + "cfg.".len()),
    );
    assert_eq!(
        package_type["results"][0]["status"], "resolved",
        "{package_type}"
    );
    assert_eq!(
        package_type["results"][0]["definitions"][0]["fqn"], "example.com/app/config.Options",
        "{package_type}"
    );
}

#[test]
fn go_selector_focus_preserves_ambiguous_intermediate_members() {
    let source = r#"
package main

type Leaf struct { ID string }
type Left struct { Leaf }
type Right struct { Leaf }
type Model struct {
    Left
    Right
}

func inspect(model Model) {
    _ = model.Leaf.ID
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file("main.go", source)
        .build();
    let chain = source.find("model.Leaf.ID").expect("ambiguous chain");

    for offset in ["model.".len(), "model.Leaf.".len()] {
        let value = lookup(
            project.root(),
            &location_reference("main.go", source, chain + offset),
        );
        assert_eq!(value["results"][0]["status"], "ambiguous", "{value}");
        assert_eq!(
            value["results"][0]["diagnostics"][0]["kind"], "ambiguous_definition",
            "{value}"
        );
    }
}

#[test]
fn go_receiver_chain_with_missing_terminal_still_honors_receiver_focus() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "buf.go",
            r#"
package app

import "sync"

type Buf struct {
    rw sync.RWMutex
}

func (br *Buf) Lock() {
    br.rw.Missing()
}
"#,
        )
        .build();

    let line = "    br.rw.Missing()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"buf.go","line":11,"column":{}}}]}}"#,
            column_of(line, "br.rw.Missing")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "br", "{value}");
    assert_eq!(
        result["definitions"][0]["kind"], "receiver_parameter",
        "{value}"
    );
    assert!(
        result["diagnostics"].as_array().unwrap().is_empty(),
        "{value}"
    );
}

#[test]
fn go_explicit_outer_field_shadows_promoted_field() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Base struct {
    ID string
}

type Service struct {
    Base
    ID int
}

func use(s Service) {
    _ = s.ID
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "use",
                "context": "_ = s.ID",
                "target": "ID"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.Service.ID",
        "{value}"
    );
}

#[test]
fn go_shallower_promoted_field_wins_over_deeper_field() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type C struct {
    ID string
}

type B struct {
    C
}

type A struct {
    ID string
}

type Service struct {
    A
    B
}

func use(s Service) {
    _ = s.ID
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "use",
                "context": "_ = s.ID",
                "target": "ID"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.com/app.A.ID",
        "{value}"
    );
}

#[test]
fn go_shared_promoted_field_paths_are_ambiguous() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type Shared struct {
    ID string
}

type Left struct {
    Shared
}

type Right struct {
    Shared
}

type Model struct {
    Left
    Right
}

func use(model Model) {
    _ = model.ID
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "use",
                "context": "_ = model.ID",
                "target": "ID"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_definition",
        "{value}"
    );
}

#[test]
fn go_named_same_name_field_does_not_promote_nested_field() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

type NamedBase struct {
    Hidden string
}

type Wrapper struct {
    NamedBase NamedBase
}

func use(wrapper Wrapper) {
    _ = wrapper.Hidden
}
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "use",
                "context": "_ = wrapper.Hidden",
                "target": "Hidden"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
}

#[test]
fn go_parameter_binding_resolves_instead_of_dot_imported_definition() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

import . "example.com/app/sub"

func Run(Helper func()) {
    Helper()
}
"#,
        )
        .file(
            "sub/sub.go",
            r#"
package sub

func Helper() {}
"#,
        )
        .build();

    let line = "    Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "Helper", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "parameter", "{value}");
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn go_unresolved_selector_does_not_fall_back_to_package_leaf() {
    let project = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/app\n")
        .file(
            "main.go",
            r#"
package main

func Helper() {}

func Run() {
    other.Helper()
}
"#,
        )
        .build();

    let line = "    other.Helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"main.go","line":7,"column":{}}}]}}"#,
            column_of(line, "Helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0]["definitions"][0].is_null(), "{value}");
}

#[test]
fn java_imported_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("pkg/Target.java", "package pkg; public class Target {}\n")
        .file(
            "app/UseTarget.java",
            r#"
package app;

import pkg.Target;

public class UseTarget {
    private Target target;
}
"#,
        )
        .build();

    let line = "    private Target target;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseTarget.java","line":7,"column":{}}}]}}"#,
            column_of(line, "Target")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.Target", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "pkg/Target.java",
        "{value}"
    );
}

#[test]
fn java_static_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Target.java",
            "package pkg; public class Target { public static void run() {} }\n",
        )
        .file(
            "app/UseTarget.java",
            r#"
package app;

import static pkg.Target.run;

public class UseTarget {
    public void call() {
        run();
    }
}
"#,
        )
        .build();

    let line = "        run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseTarget.java","line":8,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.Target.run", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "pkg/Target.java",
        "{value}"
    );
}

#[test]
fn java_enclosing_fields_shadow_static_wildcard_imports() {
    let source = r#"
package app;

import static pkg.ImportedFields.*;

public class Consumer extends pkg.Base {
    int collision;

    int read() {
        return collision + inheritedCollision + importedOnly;
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/ImportedFields.java",
            r#"
package pkg;

public class ImportedFields {
    public static int collision;
    public static int inheritedCollision;
    public static int importedOnly;
}
"#,
        )
        .file(
            "pkg/Base.java",
            "package pkg; public class Base { protected int inheritedCollision; }\n",
        )
        .file("app/Consumer.java", source)
        .build();

    for (name, expected) in [
        ("collision", "app.Consumer.collision"),
        ("inheritedCollision", "pkg.Base.inheritedCollision"),
        ("importedOnly", "pkg.ImportedFields.importedOnly"),
    ] {
        let start = source.rfind(name).expect("bare field reference");
        let value = lookup(
            project.root(),
            &location_reference("app/Consumer.java", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{name}: {value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{name}: {value}");
        assert_eq!(result["definitions"][0]["kind"], "field", "{name}: {value}");
    }
}

#[test]
fn java_enclosing_end_field_ignores_locals_from_earlier_sibling_methods() {
    let source = r#"
package com.alibaba.fastjson2;

import static com.alibaba.fastjson2.JSONReaderUTF8.*;

final class JSONReaderJSONB {
    final int end = 10;

    int earlierSibling() {
        int end = 1;
        return end; // same-method-local
    }

    int parameterShadow(int end) {
        return end; // same-method-parameter
    }

    int blockShadow() {
        {
            int end = 2;
            return end; // active-block-local
        }
    }

    int afterBlock() {
        {
            int end = 3;
        }
        return end; // field-after-block
    }

    int targetWitness() {
        return end; // field-after-sibling-local
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/alibaba/fastjson2/JSONReaderUTF8.java",
            r#"
package com.alibaba.fastjson2;

public class JSONReaderUTF8 {
    public static int end;
}
"#,
        )
        .file("com/alibaba/fastjson2/JSONReaderJSONB.java", source)
        .build();

    for marker in [
        "end; // field-after-sibling-local",
        "end; // field-after-block",
    ] {
        let start = source.find(marker).expect("enclosing end witness");
        let value = lookup(
            project.root(),
            &location_reference("com/alibaba/fastjson2/JSONReaderJSONB.java", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{marker}: {value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "com.alibaba.fastjson2.JSONReaderJSONB.end",
            "{marker}: {value}"
        );
    }

    for marker in ["end; // same-method-local", "end; // active-block-local"] {
        let start = source.find(marker).expect("lexical shadow witness");
        let value = lookup(
            project.root(),
            &location_reference("com/alibaba/fastjson2/JSONReaderJSONB.java", source, start),
        );
        assert_eq!(
            value["results"][0]["status"], "no_definition",
            "the active lexical binding must shadow both fields: {marker}: {value}"
        );
    }

    let parameter = source
        .find("end; // same-method-parameter")
        .expect("parameter shadow witness");
    let value = lookup(
        project.root(),
        &location_reference(
            "com/alibaba/fastjson2/JSONReaderJSONB.java",
            source,
            parameter,
        ),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["kind"], "parameter",
        "the parameter must shadow both enclosing and imported fields: {value}"
    );
}

#[test]
fn java_enclosing_instance_type_field_ignores_constructor_and_sibling_parameters() {
    let source = r#"
package com.alibaba.fastjson2.reader;

import static com.alibaba.fastjson2.reader.ObjectReaderImplMap.*;

public class ObjectReaderImplMapMultiValueType {
    final Class instanceType;

    public ObjectReaderImplMapMultiValueType(Class mapType) {
        Class instanceType = mapType;
        this.instanceType = instanceType;
    }

    int earlierSibling(Class instanceType) {
        return instanceType.hashCode();
    }

    Class createInstance() {
        return instanceType; // retained-instanceType-witness
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/alibaba/fastjson2/reader/ObjectReaderImplMap.java",
            r#"
package com.alibaba.fastjson2.reader;

public class ObjectReaderImplMap {
    public Class instanceType;
}
"#,
        )
        .file(
            "com/alibaba/fastjson2/reader/ObjectReaderImplMapMultiValueType.java",
            source,
        )
        .build();

    let start = source
        .find("instanceType; // retained-instanceType-witness")
        .expect("retained instanceType witness");
    let value = lookup(
        project.root(),
        &location_reference(
            "com/alibaba/fastjson2/reader/ObjectReaderImplMapMultiValueType.java",
            source,
            start,
        ),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"],
        "com.alibaba.fastjson2.reader.ObjectReaderImplMapMultiValueType.instanceType",
        "{value}"
    );
}

#[test]
fn java_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Target.java",
            "package pkg; public class Target { public void run() {} }\n",
        )
        .file(
            "app/UseTarget.java",
            r#"
package app;

import pkg.Target;

public class UseTarget {
    public void call(Target target) {
        target.run();
    }
}
"#,
        )
        .build();

    let line = "        target.run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseTarget.java","line":8,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.Target.run", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "pkg/Target.java",
        "{value}"
    );
}

#[test]
fn java_try_resource_receiver_shadows_same_named_imported_type() {
    let source = r#"
package app;

import other.Indexer;

public class SentenceSourceIndexer implements AutoCloseable {
    private Indexer indexer;

    public void execute() throws Exception {
        try (SentenceSourceIndexer indexer = new SentenceSourceIndexer()) {
            indexer.run(); // resource-receiver
        }
        indexer.run(); // field-receiver-after-try
    }

    public void run() {}
    public void close() {}
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "other/Indexer.java",
            "package other; public class Indexer { public void run() {} }\n",
        )
        .file("app/SentenceSourceIndexer.java", source)
        .build();

    for (marker, expected) in [
        (
            "indexer.run(); // resource-receiver",
            "app.SentenceSourceIndexer.run",
        ),
        (
            "indexer.run(); // field-receiver-after-try",
            "other.Indexer.run",
        ),
    ] {
        let start = source.find(marker).expect("receiver marker") + marker.find("run").unwrap();
        let value = lookup(
            project.root(),
            &location_reference("app/SentenceSourceIndexer.java", source, start),
        );
        assert_eq!(
            value["results"][0]["status"], "resolved",
            "{marker}: {value}"
        );
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{marker}: {value}"
        );
    }
}

#[test]
fn java_lombok_data_getter_resolves_to_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final String name;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    String run(Person person) {
        return person.getName();
    }
}
"#,
        )
        .build();

    let line = "        return person.getName();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "getName")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Person.name",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "field", "{value}");
}

#[test]
fn java_lombok_data_boolean_getter_resolves_is_accessor_to_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final boolean ready;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    boolean run(Person person) {
        return person.isReady();
    }
}
"#,
        )
        .build();

    let line = "        return person.isReady();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "isReady")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Person.ready",
        "{value}"
    );
}

#[test]
fn java_lombok_data_is_getter_requires_boolean_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final String ready;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    boolean run(Person person) {
        return person.isReady();
    }
}
"#,
        )
        .build();

    let line = "        return person.isReady();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "isReady")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_missing_getter_without_lombok_does_not_guess_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

public class Person {
    private final String name;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    String run(Person person) {
        return person.getName();
    }
}
"#,
        )
        .build();

    let line = "        return person.getName();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "getName")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_lombok_accessor_name_field_access_does_not_resolve_backing_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Person.java",
            r#"
package app;

import lombok.Data;

@Data
public class Person {
    private final String name;
}
"#,
        )
        .file(
            "app/UsePerson.java",
            r#"
package app;

public class UsePerson {
    Object run(Person person) {
        return person.getName;
    }
}
"#,
        )
        .build();

    let line = "        return person.getName;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UsePerson.java","line":6,"column":{}}}]}}"#,
            column_of(line, "getName")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_lambda_receiver_focus_resolves_to_lambda_parameter() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Container.java",
            r#"
package app;
import java.util.ArrayList;
import java.util.NavigableMap;
import java.util.TreeMap;

class Location {
    public final String signature;
    Location(String signature) {
        this.signature = signature;
    }
}

class Container {
    public transient NavigableMap<String, ArrayList<Location>> methodMembers = new TreeMap<>();
}
"#,
        )
        .file(
            "Action.java",
            r#"
package app;

class Action {
    private final Container container = new Container();
    void run(Location method) {
        container.methodMembers.values().forEach(methods -> methods.forEach(ignored -> {
            methods.stream().filter(location -> location.signature.equals(method.signature)).forEach(location -> {});
        }));
    }
}
"#,
        )
        .build();

    let line = "            methods.stream().filter(location -> location.signature.equals(method.signature)).forEach(location -> {});";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Action.java","line":8,"column":{}}}]}}"#,
            column_of(line, "location.signature")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "location", "{value}");
    assert_eq!(
        result["definitions"][0]["kind"], "lambda_parameter",
        "{value}"
    );
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn java_method_token_on_external_field_receiver_does_not_return_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Action.java",
            r#"
package app;

class Location {
    public final String signature = "";
}

class Action {
    void run(Location location) {
        location.signature.equals("");
    }
}
"#,
        )
        .build();

    let line = "        location.signature.equals(\"\");";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Action.java","line":10,"column":{}}}]}}"#,
            column_of(line, "equals")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_untyped_lambda_receiver_still_resolves_to_its_parameter() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "Action.java",
            r#"
package app;

interface Consumer<T> { void accept(T value); }

class Location {
    public final String signature = "";
}

class CustomBox<T> {
    void forEach(Consumer<T> consumer) {}
}

class Action {
    void run(CustomBox<Location> box) {
        box.forEach(location -> location.signature.equals(""));
    }
}
"#,
        )
        .build();

    let line = "        box.forEach(location -> location.signature.equals(\"\"));";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Action.java","line":16,"column":{}}}]}}"#,
            column_of(line, "location.signature")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "location", "{value}");
    assert_eq!(
        result["definitions"][0]["kind"], "lambda_parameter",
        "{value}"
    );
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn java_new_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/google/gson/GsonBuilder.java",
            "package com.google.gson; public class GsonBuilder { public GsonBuilder enableComplexMapKeySerialization() { return this; } }\n",
        )
        .file(
            "app/UseGson.java",
            r#"
package app;

import com.google.gson.GsonBuilder;

public class UseGson {
    public void call() {
        new GsonBuilder().enableComplexMapKeySerialization();
    }
}
"#,
        )
        .build();

    let line = "        new GsonBuilder().enableComplexMapKeySerialization();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseGson.java","line":8,"column":{}}}]}}"#,
            column_of(line, "enableComplexMapKeySerialization")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"],
        "com.google.gson.GsonBuilder.enableComplexMapKeySerialization",
        "{value}"
    );
}

#[test]
fn java_nested_type_constructor_resolves_from_enclosing_context() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "org/asynchttpclient/channel/ChannelPoolPartitioning.java",
            r#"
package org.asynchttpclient.channel;

public interface ChannelPoolPartitioning {
    enum PerHostChannelPoolPartitioning implements ChannelPoolPartitioning {
        INSTANCE;

        public Object getPartitionKey() {
            return new PartitionKey();
        }
    }

    class PartitionKey {
    }
}
"#,
        )
        .build();

    let line = "            return new PartitionKey();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"org/asynchttpclient/channel/ChannelPoolPartitioning.java","line":9,"column":{}}}]}}"#,
            column_of(line, "PartitionKey")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"],
        "org.asynchttpclient.channel.ChannelPoolPartitioning.PartitionKey",
        "{value}"
    );
}

#[test]
fn java_explicit_constructor_call_resolves_to_constructor_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "example/Service.java",
            r#"
package example;

public class Service {
    public Service(String name) {}
}
"#,
        )
        .file(
            "example/Consumer.java",
            r#"
package example;

public class Consumer {
    public void run() {
        new Service("job");
    }
}
"#,
        )
        .build();

    let line = "        new Service(\"job\");";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"example/Consumer.java","line":6,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Service.Service",
        "{value}"
    );
}

#[test]
fn java_static_method_receiver_resolves_imported_type_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Util.java",
            "package pkg; public class Util { public static String format(String value) { return value; } }\n",
        )
        .file(
            "app/UseUtil.java",
            r#"
package app;

import pkg.Util;

public class UseUtil {
    public String call(String value) {
        return Util.format(value);
    }
}
"#,
        )
        .build();

    let line = "        return Util.format(value);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseUtil.java","line":8,"column":{}}}]}}"#,
            column_of(line, "format")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.Util.format",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/Util.java", "{value}");
}

#[test]
fn java_method_reference_resolves_to_receiver_type_member() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/GuardianState.java",
            "package app; public class GuardianState { public boolean isFailed() { return false; } }\n",
        )
        .file(
            "app/UseGuardian.java",
            r#"
package app;

import java.util.stream.Stream;

public class UseGuardian {
    public long count(Stream<GuardianState> states) {
        return states.filter(GuardianState::isFailed).count();
    }
}
"#,
        )
        .build();

    let line = "        return states.filter(GuardianState::isFailed).count();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseGuardian.java","line":8,"column":{}}}]}}"#,
            column_of(line, "isFailed")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.GuardianState.isFailed",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "app/GuardianState.java",
        "{value}"
    );
}

#[test]
fn java_static_method_receiver_resolves_inherited_member_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/BaseUtil.java",
            "package pkg; public class BaseUtil { public static boolean isEmpty(String value) { return value.isEmpty(); } }\n",
        )
        .file(
            "pkg/StrUtil.java",
            "package pkg; public class StrUtil extends BaseUtil {}\n",
        )
        .file(
            "app/UseUtil.java",
            r#"
package app;

import pkg.StrUtil;

public class UseUtil {
    public boolean call(String value) {
        return StrUtil.isEmpty(value);
    }
}
"#,
        )
        .build();

    let line = "        return StrUtil.isEmpty(value);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseUtil.java","line":8,"column":{}}}]}}"#,
            column_of(line, "isEmpty")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.BaseUtil.isEmpty",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "pkg/BaseUtil.java",
        "{value}"
    );
}

#[test]
fn java_unqualified_inherited_method_call_filters_out_wrong_arity_override() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/intellij/ui/SimpleTextAttributes.java",
            "package com.intellij.ui; public class SimpleTextAttributes { public static final SimpleTextAttributes GRAY_ATTRIBUTES = new SimpleTextAttributes(); }\n",
        )
        .file(
            "com/intellij/ui/SimpleColoredComponent.java",
            "package com.intellij.ui; public class SimpleColoredComponent { public void append(String text, SimpleTextAttributes attributes) {} public void appendMany(String text, SimpleTextAttributes... attributes) {} }\n",
        )
        .file(
            "com/intellij/ui/ColoredListCellRenderer.java",
            "package com.intellij.ui; public class ColoredListCellRenderer extends SimpleColoredComponent { public void append(String text, SimpleTextAttributes attributes, boolean isMainText) {} public void appendMany(String text) {} }\n",
        )
        .file(
            "com/intellij/lang/RegExpInspectionConfigurationCellRenderer.java",
            r#"
package com.intellij.lang;

import com.intellij.ui.ColoredListCellRenderer;
import com.intellij.ui.SimpleTextAttributes;

public class RegExpInspectionConfigurationCellRenderer extends ColoredListCellRenderer {
    public void render() {
        append("'", SimpleTextAttributes.GRAY_ATTRIBUTES);
        appendMany("'", SimpleTextAttributes.GRAY_ATTRIBUTES, SimpleTextAttributes.GRAY_ATTRIBUTES);
    }
}
"#,
        )
        .build();

    let line = "        append(\"'\", SimpleTextAttributes.GRAY_ATTRIBUTES);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"com/intellij/lang/RegExpInspectionConfigurationCellRenderer.java","line":9,"column":{}}}]}}"#,
            column_of(line, "append")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "com.intellij.ui.SimpleColoredComponent.append",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(String, SimpleTextAttributes)",
        "{value}"
    );

    let varargs_line = "        appendMany(\"'\", SimpleTextAttributes.GRAY_ATTRIBUTES, SimpleTextAttributes.GRAY_ATTRIBUTES);";
    let varargs_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"com/intellij/lang/RegExpInspectionConfigurationCellRenderer.java","line":10,"column":{}}}]}}"#,
            column_of(varargs_line, "appendMany")
        ),
    );
    let varargs_result = &varargs_value["results"][0];
    assert_eq!(varargs_result["status"], "resolved", "{varargs_value}");
    assert_eq!(
        varargs_result["definitions"][0]["fqn"],
        "com.intellij.ui.SimpleColoredComponent.appendMany",
        "{varargs_value}"
    );
    assert_eq!(
        varargs_result["definitions"][0]["signature"], "(String, SimpleTextAttributes[])",
        "{varargs_value}"
    );
}

#[test]
fn java_unqualified_inherited_method_call_with_only_external_base_match_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/JBList.java",
            r#"
package pkg;

public class JBList extends ExternalBaseList {
    public void repaint(long tm, int x, int y, int width, int height) {}

    public void setBusy(boolean busy) {
        Runnable callback = () -> {
            if (busy) {
                repaint();
            }
        };
        callback.run();
    }
}
"#,
        )
        .build();

    let line = "                repaint();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"pkg/JBList.java","line":10,"column":{}}}]}}"#,
            column_of(line, "repaint")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_bare_inherited_field_lookup_does_not_return_same_named_methods() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/GridBag.java",
            "package pkg; public class GridBag { protected int insets = 7; }\n",
        )
        .file(
            "pkg/FormBuilder.java",
            r#"
package pkg;

public class FormBuilder extends GridBag {
    int readInsets() {
        return insets;
    }

    void insets() {}

    void callInsets() {
        insets();
    }
}
"#,
        )
        .build();

    let field_line = "        return insets;";
    let field_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"pkg/FormBuilder.java","line":6,"column":{}}}]}}"#,
            column_of(field_line, "insets")
        ),
    );

    let field_result = &field_value["results"][0];
    assert_eq!(field_result["status"], "resolved", "{field_value}");
    assert_eq!(
        field_result["definitions"][0]["fqn"], "pkg.GridBag.insets",
        "{field_value}"
    );
    assert_eq!(
        field_result["definitions"][0]["kind"], "field",
        "{field_value}"
    );

    let call_line = "        insets();";
    let call_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"pkg/FormBuilder.java","line":12,"column":{}}}]}}"#,
            column_of(call_line, "insets")
        ),
    );

    let call_result = &call_value["results"][0];
    assert_eq!(call_result["status"], "resolved", "{call_value}");
    assert_eq!(
        call_result["definitions"][0]["fqn"], "pkg.FormBuilder.insets",
        "{call_value}"
    );
    assert_eq!(
        call_result["definitions"][0]["kind"], "function",
        "{call_value}"
    );
}

#[test]
fn java_unqualified_method_call_keeps_matching_local_overload() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/BaseRenderer.java",
            "package pkg; public class BaseRenderer { public void append(String text, String attrs) {} }\n",
        )
        .file(
            "pkg/ChildRenderer.java",
            r#"
package pkg;

public class ChildRenderer extends BaseRenderer {
    public void append(String text, String attrs, boolean primary) {}

    public void render() {
        append("value", "gray", true);
    }
}
"#,
        )
        .build();

    let line = "        append(\"value\", \"gray\", true);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"pkg/ChildRenderer.java","line":8,"column":{}}}]}}"#,
            column_of(line, "append")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.ChildRenderer.append",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(String, String, boolean)",
        "{value}"
    );
}

#[test]
fn java_static_method_receiver_prefers_nearest_declaring_type() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/BaseUtil.java",
            "package pkg; public class BaseUtil { public static String label() { return \"base\"; } }\n",
        )
        .file(
            "pkg/StrUtil.java",
            "package pkg; public class StrUtil extends BaseUtil { public static String label() { return \"child\"; } }\n",
        )
        .file(
            "app/UseUtil.java",
            r#"
package app;

import pkg.StrUtil;

public class UseUtil {
    public String call() {
        return StrUtil.label();
    }
}
"#,
        )
        .build();

    let line = "        return StrUtil.label();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseUtil.java","line":8,"column":{}}}]}}"#,
            column_of(line, "label")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.StrUtil.label",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "pkg/StrUtil.java",
        "{value}"
    );
}

#[test]
fn java_this_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Holder.java",
            r#"
package app;

public class Holder {
    private int value;

    public int read() {
        return this.value;
    }
}
"#,
        )
        .build();

    let line = "        return this.value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Holder.java","line":8,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Holder.value",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "app/Holder.java",
        "{value}"
    );
}

#[test]
fn java_workspace_wildcard_missing_type_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("pkg/Present.java", "package pkg; public class Present {}\n")
        .file(
            "app/UseMissing.java",
            r#"
package app;

import pkg.*;

public class UseMissing {
    private MissingType value;
}
"#,
        )
        .build();

    let line = "    private MissingType value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseMissing.java","line":7,"column":{}}}]}}"#,
            column_of(line, "MissingType")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn java_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/UseList.java",
            r#"
package app;

import java.util.List;

public class UseList {
    private List<String> values;
}
"#,
        )
        .build();

    let line = "    private List<String> values;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseList.java","line":7,"column":{}}}]}}"#,
            column_of(line, "List")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
    let message = value["results"][0]["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(message.contains("outside the indexed workspace"), "{value}");
    assert!(message.contains("partial workspace"), "{value}");
}

#[test]
fn java_packaged_external_import_does_not_fall_back_to_default_package_type() {
    let source = r#"
package app;

import java.util.HashMap;

public class UseMap {
    public Object build() {
        return new HashMap();
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("HashMap.java", "public class HashMap {}\n")
        .file("app/UseMap.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/UseMap.java",
            source,
            source.find("HashMap()").expect("constructor type"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(message.contains("outside the indexed workspace"), "{value}");
}

#[test]
fn java_explicit_import_beats_same_named_same_package_type() {
    let imported_source = r#"
package app;

import target.Channel;

public interface ImportedHandler {
    void connected(Channel channel);
}
"#;
    let same_package_source = r#"
package app;

public interface LocalHandler {
    void connected(Channel channel);
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "target/Channel.java",
            "package target; public interface Channel {}\n",
        )
        .file(
            "app/Channel.java",
            "package app; public interface Channel {}\n",
        )
        .file("app/ImportedHandler.java", imported_source)
        .file("app/LocalHandler.java", same_package_source)
        .build();

    let imported = lookup(
        project.root(),
        &location_reference(
            "app/ImportedHandler.java",
            imported_source,
            imported_source
                .find("Channel channel")
                .expect("imported type"),
        ),
    );
    assert_eq!(imported["results"][0]["status"], "resolved", "{imported}");
    assert_eq!(
        imported["results"][0]["definitions"][0]["fqn"], "target.Channel",
        "an explicit single-type import must constrain the simple name before same-package lookup: {imported}"
    );

    let local = lookup(
        project.root(),
        &location_reference(
            "app/LocalHandler.java",
            same_package_source,
            same_package_source
                .find("Channel channel")
                .expect("same-package type"),
        ),
    );
    assert_eq!(local["results"][0]["status"], "resolved", "{local}");
    assert_eq!(
        local["results"][0]["definitions"][0]["fqn"], "app.Channel",
        "without an explicit import the same-package type must remain visible: {local}"
    );
}

#[test]
fn java_missing_explicit_import_does_not_fall_back_to_same_package_type() {
    let source = r#"
package app;

import missing.Channel;

public interface Handler {
    void connected(Channel channel);
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Channel.java",
            "package app; public interface Channel {}\n",
        )
        .file("app/Handler.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/Handler.java",
            source,
            source.find("Channel channel").expect("imported type"),
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "a matched explicit import must block same-package fallback even when its target is outside the workspace: {value}"
    );
}

#[test]
fn java_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/UseLocal.java",
            r#"
package app;

public class UseLocal {
    public void run() {
        int value = 1;
        value++;
    }
}
"#,
        )
        .build();

    let line = "        value++;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/UseLocal.java","line":7,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn php_imported_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nuse App\\Service;\nclass Controller {\n    public function handle(Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Service", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "src/Service.php",
        "{value}"
    );
}

#[test]
fn php_instanceof_imported_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Mapping/Accessors/ReadonlyAccessor.php",
            "<?php\nnamespace App\\Mapping\\Accessors;\nclass ReadonlyAccessor {}\n",
        )
        .file(
            "src/UnitOfWork.php",
            "<?php\nnamespace App;\nuse App\\Mapping\\Accessors\\ReadonlyAccessor;\nclass UnitOfWork {\n    public function reset(mixed $accessor): void {\n        if (! $accessor instanceof ReadonlyAccessor) {}\n    }\n}\n",
        )
        .build();

    let line = "        if (! $accessor instanceof ReadonlyAccessor) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/UnitOfWork.php","line":6,"column":{}}}]}}"#,
            line.find("ReadonlyAccessor").expect("ReadonlyAccessor") + 1
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Mapping.Accessors.ReadonlyAccessor",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Mapping/Accessors/ReadonlyAccessor.php",
        "{value}"
    );
}

#[test]
fn php_function_alias_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/helpers.php",
            "<?php\nnamespace App;\nfunction render_view(): void {}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nuse function App\\render_view;\nclass Controller {\n    public function handle(): void {\n        render_view();\n    }\n}\n",
        )
        .build();

    let line = "        render_view();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":6,"column":{}}}]}}"#,
            column_of(line, "render_view")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.render_view",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/helpers.php",
        "{value}"
    );
}

#[test]
fn php_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(Service $service): void {\n        $service->run();\n    }\n}\n",
        )
        .build();

    let line = "        $service->run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Service.run",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Service.php",
        "{value}"
    );
}

#[test]
fn php_typed_nullsafe_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(Service $service): void {\n        $service?->run();\n    }\n}\n",
        )
        .build();

    let line = "        $service?->run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Service.run",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Service.php",
        "{value}"
    );
}

#[test]
fn php_nullsafe_property_access_and_chained_call_resolve_to_definitions() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/Holder.php",
            "<?php\nnamespace App;\nclass Holder {\n    public Service $service;\n}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(Holder $holder): void {\n        $holder?->service?->run();\n    }\n}\n",
        )
        .build();

    let line = "        $holder?->service?->run();";
    let property_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "service")
        ),
    );
    let property_result = &property_value["results"][0];
    assert_eq!(property_result["status"], "resolved", "{property_value}");
    assert_eq!(
        property_result["definitions"][0]["fqn"], "App.Holder.service",
        "{property_value}"
    );
    assert_eq!(
        property_result["definitions"][0]["path"], "src/Holder.php",
        "{property_value}"
    );

    let method_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );
    let method_result = &method_value["results"][0];
    assert_eq!(method_result["status"], "resolved", "{method_value}");
    assert_eq!(
        method_result["definitions"][0]["fqn"], "App.Service.run",
        "{method_value}"
    );
    assert_eq!(
        method_result["definitions"][0]["path"], "src/Service.php",
        "{method_value}"
    );
}

#[test]
fn php_nullsafe_method_return_chain_resolves_to_definitions() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/Holder.php",
            "<?php\nnamespace App;\nclass Holder {\n    public function service(): ?Service { return new Service(); }\n}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(Holder $holder): void {\n        $holder?->service()?->run();\n    }\n}\n",
        )
        .build();

    let line = "        $holder?->service()?->run();";
    for (name, expected_fqn, expected_path) in [
        ("service", "App.Holder.service", "src/Holder.php"),
        ("run", "App.Service.run", "src/Service.php"),
    ] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
                column_of(line, name)
            ),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected_fqn, "{value}");
        assert_eq!(result["definitions"][0]["path"], expected_path, "{value}");
    }
}

#[test]
fn php_trait_method_resolves_through_using_class() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Support/LogsEvents.php",
            "<?php\nnamespace App\\Support;\ntrait LogsEvents {\n    public function record(string $message): string { return $message; }\n}\n",
        )
        .file(
            "src/Support/AuditsEvents.php",
            "<?php\nnamespace App\\Support;\ntrait AuditsEvents {\n    public function audit(string $message): string { return $message; }\n}\n",
        )
        .file(
            "src/Service/EmailNotifier.php",
            "<?php\nnamespace App\\Service;\nuse App\\Support\\LogsEvents;\nuse App\\Support\\AuditsEvents;\nclass EmailNotifier {\n    use LogsEvents, AuditsEvents;\n    public function notify(string $message): void {\n        $this->record($message);\n        $this->audit($message);\n    }\n}\n",
        )
        .file(
            "src/Other/OtherNotifier.php",
            "<?php\nnamespace App\\Other;\nclass OtherNotifier {\n    public function record(string $message): string { return $message; }\n}\n",
        )
        .file(
            "src/Consumer.php",
            "<?php\nnamespace App;\nuse App\\Service\\EmailNotifier;\nuse App\\Other\\OtherNotifier;\n$mailer = new EmailNotifier();\n$mailer->record(\"logged\");\n$other = new OtherNotifier();\n$other->record(\"unrelated\");\n",
        )
        .build();

    let internal_line = "        $this->record($message);";
    let internal = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Service/EmailNotifier.php","line":8,"column":{}}}]}}"#,
            column_of(internal_line, "record")
        ),
    );
    let result = &internal["results"][0];
    assert_eq!(result["status"], "resolved", "{internal}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Support.LogsEvents.record",
        "{internal}"
    );

    let external_line = "$mailer->record(\"logged\");";
    let external = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Consumer.php","line":6,"column":{}}}]}}"#,
            column_of(external_line, "record")
        ),
    );
    let result = &external["results"][0];
    assert_eq!(result["status"], "resolved", "{external}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Support.LogsEvents.record",
        "{external}"
    );

    let audit_line = "        $this->audit($message);";
    let audit = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Service/EmailNotifier.php","line":9,"column":{}}}]}}"#,
            column_of(audit_line, "audit")
        ),
    );
    let result = &audit["results"][0];
    assert_eq!(result["status"], "resolved", "{audit}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Support.AuditsEvents.audit",
        "{audit}"
    );

    let unrelated_line = "$other->record(\"unrelated\");";
    let unrelated = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Consumer.php","line":8,"column":{}}}]}}"#,
            column_of(unrelated_line, "record")
        ),
    );
    let result = &unrelated["results"][0];
    assert_eq!(result["status"], "resolved", "{unrelated}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Other.OtherNotifier.record",
        "{unrelated}"
    );
}

#[test]
fn php_interface_implementation_method_declaration_resolves_to_interface_method() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Contracts/Notifier.php",
            "<?php\nnamespace App\\Contracts;\ninterface Notifier {\n    public function notify(string $message): void;\n}\n",
        )
        .file(
            "src/Service/EmailNotifier.php",
            "<?php\nnamespace App\\Service;\nuse App\\Contracts\\Notifier;\nclass EmailNotifier implements Notifier {\n    public function notify(string $message): void {}\n}\n",
        )
        .build();

    let line = "    public function notify(string $message): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Service/EmailNotifier.php","line":5,"column":{}}}]}}"#,
            column_of(line, "notify")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Contracts.Notifier.notify",
        "{value}"
    );
}

#[test]
fn php_repository_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Repository.php",
            "<?php\nnamespace App;\nclass Repository {\n    public function save(string $value): void {}\n}\n",
        )
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {\n    public function handle(Repository $repository): void {\n        $repository->save('value');\n    }\n}\n",
        )
        .build();

    let line = "        $repository->save('value');";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Service.php","line":5,"column":{}}}]}}"#,
            column_of(line, "save")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Repository.save",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Repository.php",
        "{value}"
    );
}

#[test]
fn php_fully_qualified_type_resolves_from_final_segment() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {}\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(\\App\\Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(\\App\\Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":4,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Service", "{value}");
}

#[test]
fn php_composer_psr4_type_resolves_to_project_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{
  "autoload": {
    "psr-4": {
      "App\\": "src/"
    }
  }
}
"#,
        )
        .file(
            "src/Service.php",
            "<?php\nnamespace App;\nclass Service {}\n",
        )
        .file(
            "tests/Controller.php",
            "<?php\nnamespace Tests;\nclass Controller {\n    public function handle(\\App\\Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(\\App\\Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/Controller.php","line":4,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Service", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "src/Service.php",
        "{value}"
    );
}

#[test]
fn php_parent_static_call_resolves_to_parent_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/BaseController.php",
            "<?php\nnamespace App;\nclass BaseController {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/ChildController.php",
            "<?php\nnamespace App;\nclass ChildController extends BaseController {\n    public function run(): void {}\n    public function call(): void {\n        parent::run();\n    }\n}\n",
        )
        .build();

    let line = "        parent::run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/ChildController.php","line":6,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.BaseController.run",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/BaseController.php",
        "{value}"
    );
}

#[test]
fn php_parent_constructor_resolves_to_nearest_inherited_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/GrandBase.php",
            "<?php\nnamespace App;\nclass GrandBase {\n    public function __construct() {}\n}\n",
        )
        .file(
            "src/BaseController.php",
            "<?php\nnamespace App;\nclass BaseController extends GrandBase {}\n",
        )
        .file(
            "src/ChildController.php",
            "<?php\nnamespace App;\nclass ChildController extends BaseController {\n    public function call(): void {\n        parent::__construct();\n    }\n}\n",
        )
        .build();

    let line = "        parent::__construct();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/ChildController.php","line":5,"column":{}}}]}}"#,
            column_of(line, "__construct")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.GrandBase.__construct",
        "{value}"
    );
}

#[test]
fn php_late_static_constructor_resolves_to_enclosing_class() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Base.php",
            "<?php\nnamespace App;\nclass Base {\n    public function __construct() {}\n    public static function create(): Base { return new static(); }\n}\n",
        )
        .build();

    let line = "    public static function create(): Base { return new static(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Base.php","line":5,"column":{}}}]}}"#,
            column_of(line, "static();")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Base", "{value}");
}

#[test]
fn php_inherited_member_resolves_parent_with_multiline_extends() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/BaseController.php",
            "<?php\nnamespace App;\nclass BaseController {\n    public function run(): void {}\n}\n",
        )
        .file(
            "src/ChildController.php",
            "<?php\nnamespace App;\nclass ChildController extends\n    BaseController {\n    public function call(): void {\n        parent::run();\n    }\n}\n",
        )
        .build();

    let line = "        parent::run();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/ChildController.php","line":6,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.BaseController.run",
        "{value}"
    );
}

#[test]
fn php_self_class_constant_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/SchemaTool.php",
            "<?php\nnamespace App;\nclass SchemaTool {\n    private const KNOWN_COLUMN_OPTIONS = [];\n    public function gather(): void {\n        $options = self::KNOWN_COLUMN_OPTIONS;\n    }\n}\n",
        )
        .build();

    let line = "        $options = self::KNOWN_COLUMN_OPTIONS;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/SchemaTool.php","line":6,"column":{}}}]}}"#,
            column_of(line, "KNOWN_COLUMN_OPTIONS")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.SchemaTool.KNOWN_COLUMN_OPTIONS",
        "{value}"
    );
}

#[test]
fn php_aliased_static_property_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Service/EmailNotifier.php",
            "<?php\nnamespace App\\Service;\nclass EmailNotifier {\n    public static int $sent = 0;\n    public static function create(): self { return new self(); }\n}\n",
        )
        .file(
            "src/Consumer.php",
            "<?php\nnamespace App;\nuse App\\Service\\EmailNotifier as Mailer;\n$mailer = Mailer::create();\n$count = Mailer::$sent;\n",
        )
        .build();

    let line = "$count = Mailer::$sent;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Consumer.php","line":5,"column":{}}}]}}"#,
            column_of(line, "sent")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Service.EmailNotifier.sent",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Service/EmailNotifier.php",
        "{value}"
    );
}

#[test]
fn php_static_factory_result_receiver_resolves_instance_method() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Service/EmailNotifier.php",
            "<?php\nnamespace App\\Service;\nclass EmailNotifier {\n    public static function create(): self { return new self(); }\n    public function notify(string $message): void {}\n}\n",
        )
        .file(
            "src/Consumer.php",
            "<?php\nnamespace App;\nuse App\\Service\\EmailNotifier as Mailer;\n$mailer = Mailer::create();\n$mailer->notify('hello');\n",
        )
        .build();

    let line = "$mailer->notify('hello');";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Consumer.php","line":5,"column":{}}}]}}"#,
            column_of(line, "notify")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Service.EmailNotifier.notify",
        "{value}"
    );
}

#[test]
fn php_enum_cases_resolve_as_static_members() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "app/Permissions/Permission.php",
            r#"
<?php

namespace App\Permissions;

enum Permission: string
{
    case PageUpdate = 'page-update';
    case PageView = 'page-view';
}
"#,
        )
        .file(
            "app/Uploads/AttachmentController.php",
            r#"
<?php

namespace App\Uploads;

use App\Permissions\Permission;

class AttachmentController
{
    public function update(): void
    {
        $this->check(Permission::PageView);
    }
}
"#,
        )
        .build();

    let line = "        $this->check(Permission::PageView);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Uploads/AttachmentController.php","line":12,"column":{}}}]}}"#,
            column_of(line, "PageView")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Permissions.Permission.PageView",
        "{value}"
    );
}

#[test]
fn php_promoted_constructor_properties_resolve_as_instance_members() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "app/Queries/PageQueries.php",
            r#"
<?php

namespace App\Queries;

class PageQueries
{
}
"#,
        )
        .file(
            "app/Uploads/AttachmentController.php",
            r#"
<?php

namespace App\Uploads;

use App\Queries\PageQueries;

class AttachmentController
{
    public function __construct(
        protected PageQueries $pageQueries,
    ) {
    }

    public function attachLink(): void
    {
        $page = $this->pageQueries;
    }
}
"#,
        )
        .build();

    let line = "        $page = $this->pageQueries;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Uploads/AttachmentController.php","line":17,"column":{}}}]}}"#,
            column_of(line, "pageQueries")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Uploads.AttachmentController.pageQueries",
        "{value}"
    );
}

#[test]
fn php_promoted_property_receiver_resolves_member_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Service.php",
            r#"
<?php

namespace App;

class Repository
{
    public function save(string $value): string
    {
        return $value;
    }
}

class Service
{
    public function __construct(private Repository $repository)
    {
    }

    public function execute(string $name): string
    {
        return $this->repository->save($name);
    }
}
"#,
        )
        .build();

    let line = "        return $this->repository->save($name);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Service.php","line":22,"column":{}}}]}}"#,
            column_of(line, "save")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Repository.save",
        "{value}"
    );
}

#[test]
fn php_prefix_only_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Controller/Controller.php",
            "<?php\nnamespace Vendor\\Package\\Controller;\nclass Controller {}\n",
        )
        .file(
            "src/App.php",
            "<?php\nnamespace App;\nuse Vendor\\Package\\Service;\nclass App {\n    public function handle(Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/App.php","line":5,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn php_external_type_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nuse Vendor\\Package\\Service;\nclass Controller {\n    public function handle(Service $service): void {}\n}\n",
        )
        .build();

    let line = "    public function handle(Service $service): void {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn php_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller {\n    public function handle(): void {\n        $value = 1;\n        $value++;\n    }\n}\n",
        )
        .build();

    let line = "        $value++;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Controller.php","line":5,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_from_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "from pkg.util import helper\n\ndef run():\n    helper()\n",
        )
        .build();

    let line = "    helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.util.helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_builtin_call_does_not_resolve_to_same_class_method() {
    let source = concat!(
        "class Operations:\n",
        "    def list(self):\n",
        "        pass\n",
        "\n",
        "    def run(self, args):\n",
        "        return list(args)\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("operations.py", source)
        .build();
    let reference = source.rfind("list(args)").expect("built-in list call");

    let value = lookup(
        project.root(),
        &location_reference("operations.py", source, reference),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_class_body_bare_member_resolves_to_sibling_method() {
    let source = concat!(
        "class Operations:\n",
        "    def list(self):\n",
        "        pass\n",
        "\n",
        "    alias = list\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("operations.py", source)
        .build();
    let reference = source.rfind("list").expect("class-body method reference");

    let value = lookup(
        project.root(),
        &location_reference("operations.py", source, reference),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "operations.Operations.list",
        "{value}"
    );
}

#[test]
fn python_module_rebinding_replaces_earlier_import_for_forward_lookup() {
    let consumer = concat!(
        "from service import TOKEN\n",
        "TOKEN = object()\n",
        "value = TOKEN\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", "TOKEN = object()\n")
        .file("consumer.py", consumer)
        .build();
    let reference = consumer.rfind("TOKEN").expect("post-rebind use");

    let value = lookup(
        project.root(),
        &location_reference("consumer.py", consumer, reference),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "consumer.TOKEN",
        "{value}"
    );
}

#[test]
fn python_reference_before_later_import_does_not_see_future_binding() {
    let consumer = concat!("value = TOKEN\n", "from service import TOKEN\n");
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", "TOKEN = object()\n")
        .file("consumer.py", consumer)
        .build();
    let reference = consumer.find("TOKEN").expect("pre-import reference");

    let value = lookup(
        project.root(),
        &location_reference("consumer.py", consumer, reference),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_conditional_module_rebinding_preserves_both_forward_candidates() {
    let consumer = concat!(
        "try:\n",
        "    from service import TOKEN as selected\n",
        "except ImportError:\n",
        "    selected = object()\n",
        "value = selected\n",
    );
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", "TOKEN = object()\n")
        .file("consumer.py", consumer)
        .build();
    let reference = consumer.rfind("selected").expect("joined binding use");

    let value = lookup(
        project.root(),
        &location_reference("consumer.py", consumer, reference),
    );
    let mut definitions: Vec<&str> = value["results"][0]["definitions"]
        .as_array()
        .expect("definitions array")
        .iter()
        .filter_map(|definition| definition["fqn"].as_str())
        .collect();
    definitions.sort_unstable();

    assert_eq!(
        definitions,
        vec!["consumer.selected", "service.TOKEN"],
        "{value}"
    );
}

#[test]
fn python_reexported_function_call_resolves_to_original_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/example/service.py", "def build_service():\n    pass\n")
        .file(
            "src/example/__init__.py",
            "from .service import build_service\n",
        )
        .file(
            "tests/test_service.py",
            "from example import build_service\n\ndef test_service():\n    build_service()\n",
        )
        .build();

    let line = "    build_service()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/test_service.py","line":4,"column":{}}}]}}"#,
            column_of(line, "build_service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.service.build_service",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/example/service.py",
        "{value}"
    );
}

#[test]
fn python_reexported_class_alias_resolves_static_members_and_name_range() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/shop/models.py",
            "from dataclasses import dataclass\n@dataclass\nclass User:\n    @classmethod\n    def guest(cls) -> \"User\":\n        return cls(\"guest\")\n    @staticmethod\n    def format_name(name: str) -> str:\n        return name.title()\n",
        )
        .file("src/shop/__init__.py", "from .models import User as Account\n")
        .file(
            "tests/test_models.py",
            "from shop import Account\nuser = Account.guest()\nAccount.format_name(\"ada\")\n",
        )
        .build();

    let guest_line = "user = Account.guest()";
    let guest = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/test_models.py","line":2,"column":{}}}]}}"#,
            column_of(guest_line, "guest")
        ),
    );
    let guest_result = &guest["results"][0];
    assert_eq!(guest_result["status"], "resolved", "{guest}");
    assert_eq!(
        guest_result["definitions"][0]["fqn"], "shop.models.User.guest",
        "{guest}"
    );

    let format_line = "Account.format_name(\"ada\")";
    let format_name = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/test_models.py","line":3,"column":{}}}]}}"#,
            column_of(format_line, "format_name")
        ),
    );
    let format_result = &format_name["results"][0];
    assert_eq!(format_result["status"], "resolved", "{format_name}");
    assert_eq!(
        format_result["definitions"][0]["fqn"], "shop.models.User.format_name",
        "{format_name}"
    );

    let account = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/test_models.py","line":2,"column":{}}}]}}"#,
            column_of(guest_line, "Account")
        ),
    );
    let account_result = &account["results"][0];
    assert_eq!(account_result["status"], "resolved", "{account}");
    assert_eq!(
        account_result["definitions"][0]["fqn"], "shop.models.User",
        "{account}"
    );
    assert_eq!(
        account_result["definitions"][0]["start_line"], 3,
        "{account}"
    );
}

#[test]
fn python_imported_factory_return_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/example/service.py",
            r#"
class Service:
    def execute(self, name):
        return name

def build_service():
    return Service()
"#,
        )
        .file(
            "src/example/__init__.py",
            "from .service import Service, build_service\n",
        )
        .file(
            "tests/test_service.py",
            r#"
from example import Service, build_service

def test_service_execution():
    service = build_service()
    service.execute(" Ada ")
"#,
        )
        .build();

    let line = r#"    service.execute(" Ada ")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/test_service.py","line":6,"column":{}}}]}}"#,
            column_of(line, "execute")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.service.Service.execute",
        "{value}"
    );
}

#[test]
fn python_reexported_classmethod_factory_return_property_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/shop/models.py",
            r#"
class User:
    @property
    def normalized_name(self) -> str:
        return self.name.lower()

    @classmethod
    def guest(cls) -> "User":
        return cls("guest")
"#,
        )
        .file(
            "src/shop/__init__.py",
            "from .models import User as Account\n",
        )
        .file(
            "tests/test_models.py",
            "from shop import Account\nuser = Account.guest()\nuser.normalized_name\n",
        )
        .build();

    let line = "user.normalized_name";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"tests/test_models.py","line":3,"column":{}}}]}}"#,
            column_of(line, "normalized_name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "shop.models.User.normalized_name",
        "{value}"
    );
}

#[test]
fn python_namespace_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "import pkg.util as util\n\ndef run():\n    util.helper()\n",
        )
        .build();

    let line = "    util.helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.util.helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_attribute_object_resolves_to_namespace_not_member() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "import pkg.util as util\n\ndef run():\n    util.helper()\n",
        )
        .build();

    let line = "    util.helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "util")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "pkg.util", "{value}");
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_plain_dotted_import_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/util.py", "def helper():\n    pass\n")
        .file(
            "app.py",
            "import pkg.util\n\ndef run():\n    pkg.util.helper()\n",
        )
        .build();

    let line = "    pkg.util.helper()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "pkg.util.helper",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "pkg/util.py", "{value}");
}

#[test]
fn python_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            "class Service:\n    def run(self):\n        pass\n",
        )
        .file(
            "app.py",
            "from service import Service\n\ndef handle(service: Service):\n    service.run()\n",
        )
        .build();

    let line = "    service.run()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "service.Service.run",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "service.py", "{value}");
}

#[test]
fn python_definition_batch_resolves_typed_imported_receivers() {
    let source = "from service import Service\n\ndef handle(service: Service):\n    service.run()\n    service.stop()\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            "class Service:\n    def run(self):\n        pass\n\n    def stop(self):\n        pass\n",
        )
        .file("app.py", source)
        .build();

    let references = ["run", "stop"]
        .into_iter()
        .map(|needle| {
            let start = source.rfind(needle).expect("receiver member in source");
            let single: Value = serde_json::from_str(&location_reference("app.py", source, start))
                .expect("single location reference");
            single["references"][0].clone()
        })
        .collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({"references": references}).to_string(),
    );

    assert_eq!(
        value["results"].as_array().map(Vec::len),
        Some(2),
        "{value}"
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "service.Service.run",
        "{value}"
    );
    assert_eq!(value["results"][1]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][1]["definitions"][0]["fqn"], "service.Service.stop",
        "{value}"
    );
}

#[test]
fn python_typed_receiver_inherited_method_resolves_to_base_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            "class Base:\n    def run(self):\n        pass\n\nclass Child(Base):\n    pass\n",
        )
        .file(
            "app.py",
            "from service import Child\n\ndef handle(service: Child):\n    service.run()\n",
        )
        .build();

    let line = "    service.run()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "service.Base.run",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "service.py", "{value}");
}

#[test]
fn python_self_attribute_read_prefers_init_assignment_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    def __init__(self):
        self.repository = None

    def save(self, repository):
        self.repository = repository

    def current(self):
        return self.repository
"#,
        )
        .build();

    let line = "        return self.repository";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service.py","line":10,"column":{}}}]}}"#,
            column_of(line, "repository")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "service.Service.repository",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["start_line"], 4, "{value}");
}

#[test]
fn python_unimported_receiver_annotation_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "other.py",
            "class Service:\n    def run(self):\n        pass\n",
        )
        .file(
            "app.py",
            "def handle(service: Service):\n    service.run()\n",
        )
        .build();

    let line = "    service.run()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            "import requests\n\ndef run():\n    requests.get()\n",
        )
        .build();

    let line = "    requests.get()";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":4,"column":{}}}]}}"#,
            column_of(line, "get")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn python_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "def run():\n    value = 1\n    value\n")
        .build();

    let line = "    value";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.py","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_using_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service {} }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { private Service service; } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { private Service service; } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Service", "{value}");
    assert_eq!(
        result["definitions"][0]["path"], "Lib/Service.cs",
        "{value}"
    );
}

#[test]
fn csharp_attribute_shorthand_definition_prefers_imported_attribute_suffix() {
    let source = r#"
using System.Management.Automation;

namespace Demo.Runtime.PowerShell {
    internal class Parameter { }

    [Parameter]
    public sealed class ExportProxyCmdlet { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "Automation/ParameterAttribute.cs",
            "namespace System.Management.Automation { public class ParameterAttribute : System.Attribute { } }\n",
        )
        .file("Generated/ExportProxyCmdlet.cs", source)
        .build();

    let attribute = source.find("Parameter]").expect("attribute shorthand");
    let value = lookup(
        project.root(),
        &location_reference("Generated/ExportProxyCmdlet.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "System.Management.Automation.ParameterAttribute",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "Automation/ParameterAttribute.cs",
        "{value}"
    );
}

#[test]
fn csharp_attribute_shorthand_rejects_explicit_object_base_exact_candidate() {
    let source = r#"
using System.Management.Automation;

namespace Demo.Runtime.PowerShell {
    internal class Parameter : object { }

    [Parameter]
    public sealed class ExportProxyCmdlet { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "Automation/ParameterAttribute.cs",
            "namespace System.Management.Automation { public class ParameterAttribute : System.Attribute { } }\n",
        )
        .file("Generated/ExportProxyCmdlet.cs", source)
        .build();

    let attribute = source.find("Parameter]").expect("attribute shorthand");
    let value = lookup(
        project.root(),
        &location_reference("Generated/ExportProxyCmdlet.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "System.Management.Automation.ParameterAttribute",
        "an explicit object base proves the exact Parameter is not an attribute: {value}"
    );
}

#[test]
fn csharp_attribute_shorthand_rejects_explicit_object_base_with_unresolved_interface() {
    let source = r#"
using System.Management.Automation;
using External.Contracts;

namespace Demo.Runtime.PowerShell {
    internal class Parameter : object, IExternalInterface { }

    [Parameter]
    public sealed class ExportProxyCmdlet { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "Automation/ParameterAttribute.cs",
            "namespace System.Management.Automation { public class ParameterAttribute : System.Attribute { } }\n",
        )
        .file("Generated/ExportProxyCmdlet.cs", source)
        .build();

    let attribute = source.find("Parameter]").expect("attribute shorthand");
    let value = lookup(
        project.root(),
        &location_reference("Generated/ExportProxyCmdlet.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "System.Management.Automation.ParameterAttribute",
        "the explicit object base decisively proves the exact Parameter is not an attribute even when another base is unresolved: {value}"
    );
}

#[test]
fn csharp_attribute_shorthand_external_suffix_reports_boundary() {
    let source = r#"
using System.Management.Automation;

namespace Demo.Runtime.PowerShell {
    internal class Parameter { }

    [Parameter(Mandatory = true)]
    public sealed class ExportProxyCmdlet { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Generated/ExportProxyCmdlet.cs", source)
        .build();

    let attribute = source
        .find("Parameter(Mandatory")
        .expect("production-shaped attribute shorthand");
    let value = lookup(
        project.root(),
        &location_reference("Generated/ExportProxyCmdlet.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    assert!(
        result["definitions"]
            .as_array()
            .is_none_or(|definitions| definitions
                .iter()
                .all(|definition| { definition["fqn"] != "Demo.Runtime.PowerShell.Parameter" })),
        "an external ParameterAttribute boundary must never resolve the local non-attribute Parameter: {value}"
    );
}

#[test]
fn csharp_attribute_shorthand_with_two_valid_forms_is_ambiguous() {
    let source = r#"
namespace Demo {
    public class Marker : System.Attribute { }
    public class MarkerAttribute : System.Attribute { }

    [Marker]
    public sealed class Consumer { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file("Consumer.cs", source)
        .build();

    let attribute = source.find("Marker]").expect("ambiguous attribute");
    let value = lookup(
        project.root(),
        &location_reference("Consumer.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    let mut fqns = result["definitions"]
        .as_array()
        .expect("ambiguous definitions")
        .iter()
        .map(|definition| definition["fqn"].as_str().expect("definition fqn"))
        .collect::<Vec<_>>();
    fqns.sort_unstable();
    assert_eq!(fqns, ["Demo.Marker", "Demo.MarkerAttribute"], "{value}");
}

#[test]
fn csharp_attribute_two_successful_alias_spellings_to_same_type_resolve_once() {
    let source = r#"
using Marker = Attributes.SharedAttribute;
using MarkerAttribute = Attributes.SharedAttribute;

namespace Demo {
    [Marker]
    public sealed class Consumer { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "Attributes/SharedAttribute.cs",
            "namespace Attributes { public class SharedAttribute : System.Attribute { } }\n",
        )
        .file("Consumer.cs", source)
        .build();

    let attribute = source.find("Marker]").expect("aliased attribute");
    let value = lookup(
        project.root(),
        &location_reference("Consumer.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert!(
        result["definitions"]
            .as_array()
            .is_some_and(|definitions| definitions
                .iter()
                .any(|definition| definition["fqn"] == "Attributes.SharedAttribute")),
        "{value}"
    );

    let value = lookup_type(
        project.root(),
        &location_reference("Consumer.cs", source, attribute),
    );
    let result = &value["results"][0];
    assert_eq!(
        result["status"], "ambiguous",
        "type lookup must preserve ambiguity between both successful attribute-name spellings even when they name the same logical type: {value}"
    );
}

#[test]
fn csharp_attribute_partial_base_preserves_all_definition_locations() {
    let source = r#"
using Demo.Attributes;

namespace Demo {
    [Marker]
    public sealed class Consumer { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "Attributes/MarkerAttribute.First.cs",
            "namespace Demo.Attributes { public partial class MarkerAttribute { } }\n",
        )
        .file(
            "Attributes/MarkerAttribute.Second.cs",
            "namespace Demo.Attributes { public partial class MarkerAttribute : System.Attribute { } }\n",
        )
        .file("Consumer.cs", source)
        .build();

    let attribute = source.find("Marker]").expect("partial attribute");
    let value = lookup(
        project.root(),
        &location_reference("Consumer.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    let mut paths = result["definitions"]
        .as_array()
        .expect("partial attribute definitions")
        .iter()
        .map(|definition| definition["path"].as_str().expect("definition path"))
        .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "Attributes/MarkerAttribute.First.cs",
            "Attributes/MarkerAttribute.Second.cs"
        ],
        "{value}"
    );
}

#[test]
fn csharp_attribute_shorthand_discards_ambiguous_exact_lookup_before_suffix() {
    let source = r#"
using ExactAttribute;
using ExactNonAttribute;
using Suffixed;

namespace Demo {
    [Marker]
    public sealed class Consumer { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "ExactAttribute/Marker.cs",
            "namespace ExactAttribute { public class Marker : System.Attribute { } }\n",
        )
        .file(
            "ExactNonAttribute/Marker.cs",
            "namespace ExactNonAttribute { public class Marker { } }\n",
        )
        .file(
            "Suffixed/MarkerAttribute.cs",
            "namespace Suffixed { public class MarkerAttribute : System.Attribute { } }\n",
        )
        .file("Consumer.cs", source)
        .build();

    let attribute = source.find("Marker]").expect("attribute shorthand");
    let value = lookup(
        project.root(),
        &location_reference("Consumer.cs", source, attribute),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Suffixed.MarkerAttribute",
        "an ambiguous exact type-name lookup is suppressed before attribute ancestry is considered: {value}"
    );
}

#[test]
fn csharp_attribute_namespace_alias_external_suffix_reports_boundary() {
    let source = r#"
using PS = System.Management.Automation;

namespace Demo {
    [PS::Parameter]
    public sealed class ExportProxyCmdlet { }
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Generated/ExportProxyCmdlet.cs", source)
        .build();

    let attribute = source
        .find("Parameter]")
        .expect("namespace-alias attribute shorthand");
    let value = lookup(
        project.root(),
        &location_reference("Generated/ExportProxyCmdlet.cs", source, attribute),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn csharp_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public void Run() {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Service service) { service.Run(); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Service service) { service.Run(); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.Run",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "Lib/Service.cs",
        "{value}"
    );
}

#[test]
fn csharp_conditional_member_resolves_typed_parenthesized_cast_and_field_receivers() {
    let source = r#"using Lib;
namespace App;
public class Controller {
    private readonly Service _service = new();
    public void FromParameter(Service service) => service?.Run();
    public void FromParenthesized(Service service) => ((service))?.Run(1);
    public void FromCast(object raw) => ((Service)raw)?.Run<string>(1, 2);
    public void FromField() => _service?.Run();
    public void FromConditionalProperty(Service service) => service?.Child?.Run();
    public void FromConditionalReturn(Service service) => service?.GetChild()?.Run();
    public void FromAs(object raw) => (raw as Service)?.Run();
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            r#"namespace Lib;
public class Service {
    public void Run() {}
    public void Run(int value) {}
    public void Run<T>(int first, int second) {}
    public Service Child => this;
    public Service GetChild() => this;
}
"#,
        )
        .file("App/Controller.cs", source)
        .build();

    for (needle, expected_signature) in [
        ("service?.Run()", "()"),
        ("((service))?.Run(1)", "(int)"),
        ("((Service)raw)?.Run<string>(1, 2)", "`1(int, int)"),
        ("_service?.Run()", "()"),
        ("service?.Child?.Run()", "()"),
        ("service?.GetChild()?.Run()", "()"),
        ("(raw as Service)?.Run()", "()"),
    ] {
        let member_offset = source.find(needle).expect("conditional access")
            + needle.find("Run").expect("conditional member name");
        let value = lookup(
            project.root(),
            &location_reference("App/Controller.cs", source, member_offset),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{needle}: {value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{needle}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"], "Lib.Service.Run",
            "{needle}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["signature"], expected_signature,
            "{needle}: {value}"
        );
    }
}

#[test]
fn csharp_object_cast_conditional_member_does_not_fall_back_to_enclosing_override() {
    let source = r#"namespace Example;
public partial class Model {
    private string _value = "";
    public string Serialize() => (((object)_value)?.ToString());
    public string Format() => (((object)_value)?.Format());
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Model.Json.cs", source)
        .file(
            "Model.PowerShell.cs",
            r#"namespace Example;
public partial class Model {
    public override string ToString() => "model";
}
"#,
        )
        .file(
            "Extensions.cs",
            r#"namespace Example;
public static class Extensions {
    public static string ToString(this Model value) => "extension";
    public static string Format(this object value) => "extension";
}
"#,
        )
        .build();
    let start = source.find("ToString").expect("conditional member name");
    let value = lookup(
        project.root(),
        &location_reference("Model.Json.cs", source, start),
    );

    assert_eq!(
        value["results"][0]["status"], "no_definition",
        "the explicit object cast targets external System.Object.ToString, not the containing model override: {value}"
    );

    let format_start = source.find("?.Format").expect("conditional extension") + 2;
    let value = lookup(
        project.root(),
        &location_reference("Model.Json.cs", source, format_start),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Example.Extensions.Format",
        "the explicit object cast should retain the matching builtin extension receiver: {value}"
    );
}

#[test]
fn csharp_nested_owner_member_does_not_merge_dotted_owner_collision() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Nested.cs",
            "namespace N { public class Outer { public class Inner { public void Target() {} public void Run() { Target(); } } } }\n",
        )
        .file(
            "Dotted.cs",
            "namespace N.Outer { public class Inner { public void Target(int value) {} } }\n",
        )
        .build();

    let line = "namespace N { public class Outer { public class Inner { public void Target() {} public void Run() { Target(); } } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Nested.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Target();")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "N.Outer$Inner.Target",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "Nested.cs", "{value}");
}

#[test]
fn csharp_visible_enum_member_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Modes.cs",
            "namespace Lib { public enum Mode { Read, Write } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Read")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Mode.Read", "{value}");
    assert_eq!(result["definitions"][0]["path"], "Lib/Modes.cs", "{value}");
}

#[test]
fn csharp_visible_enum_receiver_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Modes.cs",
            "namespace Lib { public enum Mode { Read, Write } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle() { var mode = Mode.Read; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Mode")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Mode", "{value}");
    assert_eq!(result["definitions"][0]["path"], "Lib/Modes.cs", "{value}");
}

#[test]
fn csharp_enum_declaration_name_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Modes.cs",
            "namespace Lib { public enum Mode { Read, Write } }\n",
        )
        .build();

    let line = "namespace Lib { public enum Mode { Read, Write } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Lib/Modes.cs","line":1,"column":{}}},{{"path":"Lib/Modes.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Mode"),
            column_of(line, "Read")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert_eq!(value["results"][1]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_same_namespace_static_property_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/App.cs",
            "namespace App { public partial class App { public static ResourceDictionary ResourceDictionary { get; private set; } } public class ResourceDictionary {} }\n",
        )
        .file(
            "App/Bootstrapper.cs",
            "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }\n",
        )
        .build();

    let line = "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Bootstrapper.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "ResourceDictionary")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.App.ResourceDictionary",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "App/App.cs", "{value}");
}

#[test]
fn csharp_same_namespace_static_receiver_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/App.cs",
            "namespace App { public partial class App { public static ResourceDictionary ResourceDictionary { get; private set; } } public class ResourceDictionary {} }\n",
        )
        .file(
            "App/Bootstrapper.cs",
            "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }\n",
        )
        .build();

    let line = "namespace App { public class Bootstrapper { public void Start() { var value = App.ResourceDictionary; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Bootstrapper.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "App.ResourceDictionary")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.App", "{value}");
    assert_eq!(result["definitions"][0]["path"], "App/App.cs", "{value}");
}

#[test]
fn csharp_reference_context_resolves_unqualified_static_field() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "NzbDrone.Core/Organizer/FileNameBuilder.cs",
            r#"using System.Text.RegularExpressions;

namespace NzbDrone.Core.Organizer;

public sealed class FileNameBuilder
{
    private static readonly Regex TitleRegex = new Regex("[^a-z]+");

    public string BuildFileName(string title)
    {
        return TitleRegex.Replace(title, "");
    }
}
"#,
        )
        .build();

    let args = json!({
        "references": [{
            "symbol": "NzbDrone.Core.Organizer.FileNameBuilder.BuildFileName",
            "context": "        return TitleRegex.Replace(title, \"\");",
            "target": "TitleRegex"
        }]
    })
    .to_string();
    let value = lookup_reference(project.root(), &args);

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "NzbDrone.Core.Organizer.FileNameBuilder.TitleRegex",
        "{value}"
    );
}

#[test]
fn csharp_type_reference_beats_same_named_member_and_local() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/Service.cs",
            "namespace App { public class Service {} }\n",
        )
        .file(
            "App/Controller.cs",
            r#"namespace App;

public class Controller
{
    private int Service;

    public void Handle()
    {
        var Service = 1;
        Service value;
    }
}
"#,
        )
        .build();

    let line = "        Service value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":10,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Service", "{value}");
}

#[test]
fn csharp_instance_member_receiver_resolves_from_enclosing_property_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/List.cs",
            "namespace App { public class List<T> { public class Node<T> { public T Data { get; set; } } private Node<T> lastNode { get; set; } public T Last() { return lastNode.Data; } } }\n",
        )
        .build();

    let line = "namespace App { public class List<T> { public class Node<T> { public T Data { get; set; } } private Node<T> lastNode { get; set; } public T Last() { return lastNode.Data; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/List.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Data;")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.List`1$Node`1.Data",
        "{value}"
    );
}

#[test]
fn csharp_partial_property_receiver_resolves_to_declaration() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "src/Handlers.cs",
            r#"namespace Demo;

public partial class EventRecord
{
    public string Name { get; set; }

    public EventRecord(string name)
    {
        Name = name;
    }
}
"#,
        )
        .file(
            "src/Consumers.cs",
            r#"namespace Demo;

public partial class EventRecord
{
    public string Label()
    {
        return Name;
    }
}

public sealed class Consumer
{
    public string Render(EventRecord record)
    {
        return record.Name;
    }
}
"#,
        )
        .build();

    let line = "        return record.Name;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/Consumers.cs","line":15,"column":{}}}]}}"#,
            column_of(line, "Name")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Demo.EventRecord.Name",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "src/Handlers.cs",
        "{value}"
    );
}

#[test]
fn csharp_var_initialized_from_instance_member_seeds_receiver_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/List.cs",
            "namespace App { public class List<T> { public class Node<T> { public Node<T> Next { get; set; } public T Data { get; set; } } private Node<T> firstNode { get; set; } public T Get() { var currentNode = firstNode; currentNode = currentNode.Next; return currentNode.Data; } } }\n",
        )
        .build();

    let line = "namespace App { public class List<T> { public class Node<T> { public Node<T> Next { get; set; } public T Data { get; set; } } private Node<T> firstNode { get; set; } public T Get() { var currentNode = firstNode; currentNode = currentNode.Next; return currentNode.Data; } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/List.cs","line":1,"column":{}}},{{"path":"App/List.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Next;"),
            column_of(line, "Data;")
        ),
    );

    for result in value["results"].as_array().unwrap() {
        assert_eq!(result["status"], "resolved", "{value}");
    }
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "App.List`1$Node`1.Next",
        "{value}"
    );
    assert_eq!(
        value["results"][1]["definitions"][0]["fqn"], "App.List`1$Node`1.Data",
        "{value}"
    );
}

#[test]
fn csharp_extension_method_resolves_from_visible_namespace() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Dapper/SqlMapper.cs",
            "namespace Dapper { public static class SqlMapper { public static T QueryFirst<T>(this IDbConnection cnn, string sql, object? param = null) => default!; public static dynamic QueryFirst(this IDbConnection cnn, string sql) => default!; } }\n",
        )
        .file(
            "App/Repo.cs",
            "using Dapper;\nusing System.Data;\nnamespace App { class Repo { public int Load(IDbConnection connection) { return connection.QueryFirst<int>(\"select 1\"); } } }\n",
        )
        .build();

    let line = "namespace App { class Repo { public int Load(IDbConnection connection) { return connection.QueryFirst<int>(\"select 1\"); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Repo.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "QueryFirst")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Dapper.SqlMapper.QueryFirst",
        "{value}"
    );
}

#[test]
fn csharp_extension_candidates_require_structured_external_receiver_evidence() {
    let source = r#"using System;
namespace ClosedXML.Excel;

internal static class TypeExtensions {
    public static string Describe(this Type type) => "type";
    public static Type GetUnderlyingType(this Type type) => type;

    public static bool IsNullable(Type type) =>
        Nullable.GetUnderlyingType(type) != null;

    public static string DescribeLocal(Type type) {
        Type local = type;
        return local.Describe();
    }
}

internal static class UriExtensions {
    public static string Describe(this Uri uri) => "uri";
}

internal static class Consumer {
    public static string DescribeType(Type type) => type.Describe();
    public static string DescribeUri(Uri uri) => uri.Describe();
    public static string Unknown() => mystery.Describe();
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("ClosedXML/Extensions/TypeExtensions.cs", source)
        .build();

    let sites = [
        ("Nullable.GetUnderlyingType", "Nullable."),
        ("local.Describe()", "local."),
        ("type.Describe()", "type."),
        ("uri.Describe()", "uri."),
        ("mystery.Describe()", "mystery."),
    ];
    let references = sites
        .into_iter()
        .map(|(needle, receiver)| {
            let offset = source.find(needle).expect("reference site") + receiver.len();
            location_query("ClosedXML/Extensions/TypeExtensions.cs", source, offset)
        })
        .collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({ "references": references }).to_string(),
    );

    for index in [0, 4] {
        assert_ne!(
            value["results"][index]["status"], "resolved",
            "an untyped receiver must not borrow a visible extension owner: {value}"
        );
        assert!(
            value["results"][index]["definitions"]
                .as_array()
                .is_none_or(Vec::is_empty),
            "an untyped receiver must not produce a local definition: {value}"
        );
    }

    for index in [1, 2] {
        assert_eq!(value["results"][index]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][index]["definitions"][0]["fqn"],
            "ClosedXML.Excel.TypeExtensions.Describe",
            "declared Type evidence must select only the Type extension: {value}"
        );
    }
    assert_eq!(value["results"][3]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][3]["definitions"][0]["fqn"], "ClosedXML.Excel.UriExtensions.Describe",
        "declared Uri evidence must select only the Uri extension: {value}"
    );
}

#[test]
fn csharp_inapplicable_direct_member_yields_to_matching_extension() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/IListener.cs",
            "namespace Demo { public interface IListener { void Signal(string id, int token, object data); } }\n",
        )
        .file(
            "Demo/ListenerExtensions.cs",
            "namespace Demo { public static class ListenerExtensions { public static void Signal(this IListener listener, string id) {} } }\n",
        )
        .file(
            "App/Consumer.cs",
            "using static Demo.ListenerExtensions;\nnamespace App { public sealed class Consumer { public void Run(Demo.IListener listener) { listener.Signal(\"ready\"); } } }\n",
        )
        .build();

    let line = "namespace App { public sealed class Consumer { public void Run(Demo.IListener listener) { listener.Signal(\"ready\"); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "Demo.ListenerExtensions.Signal",
        "an inapplicable direct member must not block a matching extension: {value}"
    );
}

#[test]
fn csharp_static_using_resolves_short_target_in_enclosing_namespace() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Types.cs",
            r#"namespace Demo {
    using static ListenerExtensions;
    public interface IListener { void Signal(string id, int token, object data); }
    public static class ListenerExtensions {
        public static void Signal(this IListener listener, string id) {}
    }
    public sealed class Consumer {
        public void Run(IListener listener) { listener.Signal("ready"); }
    }
}
"#,
        )
        .build();

    let line = "        public void Run(IListener listener) { listener.Signal(\"ready\"); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Demo/Types.cs","line":8,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Demo.ListenerExtensions.Signal",
        "a short static-using target must resolve in its enclosing namespace: {value}"
    );
}

#[test]
fn csharp_global_static_using_applies_across_files() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/IListener.cs",
            "namespace Demo { public interface IListener { void Signal(string id, int token, object data); } }\n",
        )
        .file(
            "Demo/ListenerExtensions.cs",
            "namespace Demo { public static class ListenerExtensions { public static void Signal(this IListener listener, string id) {} } }\n",
        )
        .file(
            "GlobalUsings.cs",
            "global using static Demo.ListenerExtensions;\n",
        )
        .file(
            "App/Consumer.cs",
            "namespace App { public sealed class Consumer { public void Run(Demo.IListener listener) { listener.Signal(\"ready\"); } } }\n",
        )
        .build();

    let line = "namespace App { public sealed class Consumer { public void Run(Demo.IListener listener) { listener.Signal(\"ready\"); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Demo.ListenerExtensions.Signal",
        "a global static using must make extensions visible in other files: {value}"
    );
}

#[test]
fn csharp_inapplicable_direct_member_rejects_unrelated_extension_receiver() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Listener.cs",
            "namespace Demo { public sealed class Listener { public void Signal(string id, int token, object data) {} } }\n",
        )
        .file(
            "Visible/Extensions.cs",
            "namespace Visible { public static class Extensions { public static void Signal(this string value, string id) {} } }\n",
        )
        .file(
            "App/Consumer.cs",
            "using Demo;\nusing Visible;\nnamespace App { public sealed class Consumer { public void Run(Listener listener) { listener.Signal(\"ready\"); } } }\n",
        )
        .build();

    let line = "namespace App { public sealed class Consumer { public void Run(Listener listener) { listener.Signal(\"ready\"); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Demo.Listener.Signal",
        "an extension with an incompatible known receiver must not replace the legacy direct fallback: {value}"
    );
}

#[test]
fn csharp_callable_applicability_filters_without_guessing_overload_rank() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Listener.cs",
            r#"namespace Demo {
    public sealed class Listener {
        public void Signal(string id) {}
        public void Run() {}
        public void Run(int count = 0) {}
        public void Pack(string head) {}
        public void Pack(string head, params object[] tail) {}
        public void Pick(string head, object tail) {}
        public void Pick(string head, params object[] tail) {}
    }
    public static class ListenerExtensions {
        public static void Signal(this Listener listener, string id) {}
    }
}
"#,
        )
        .file(
            "App/Consumer.cs",
            r#"using Demo;
namespace App {
    public sealed class Consumer {
        public void Execute(Listener listener) {
            listener.Signal("ready");
            listener.Run();
            listener.Run(1);
            listener.Pack("head");
            listener.Pack("head", 1, 2);
            listener.Pick("head", "tail");
        }
    }
}
"#,
        )
        .build();

    let references = [
        (5, "            listener.Signal(\"ready\");", "Signal"),
        (6, "            listener.Run();", "Run"),
        (7, "            listener.Run(1);", "Run"),
        (8, "            listener.Pack(\"head\");", "Pack"),
        (9, "            listener.Pack(\"head\", 1, 2);", "Pack"),
        (10, "            listener.Pick(\"head\", \"tail\");", "Pick"),
    ]
    .into_iter()
    .map(|(line, source, name)| {
        format!(
            r#"{{"path":"App/Consumer.cs","line":{line},"column":{}}}"#,
            column_of(source, name)
        )
    })
    .collect::<Vec<_>>()
    .join(",");
    let value = lookup(
        project.root(),
        &format!(r#"{{"references":[{references}]}}"#),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(6, results.len(), "{value}");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "Demo.Listener.Signal",
        "an applicable direct member must retain precedence: {value}"
    );
    let signatures = results
        .iter()
        .map(|result| {
            let mut signatures = result["definitions"]
                .as_array()
                .expect("definitions")
                .iter()
                .map(|definition| {
                    definition["signature"]
                        .as_str()
                        .expect("definition signature")
                })
                .collect::<Vec<_>>();
            signatures.sort_unstable();
            signatures
        })
        .collect::<Vec<_>>();
    assert_eq!(
        signatures,
        vec![
            vec!["(string)"],
            vec!["()", "(int)"],
            vec!["(int)"],
            vec!["(string)", "(string, object[])"],
            vec!["(string, object[])"],
            vec!["(string, object)", "(string, object[])"],
        ],
        "arity must reject impossible overloads without guessing between overlapping applicable ranges: {value}"
    );
}

#[test]
fn csharp_extension_lookup_uses_visibility_indexes_without_unrelated_hydration() {
    let mut project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Visible/Extensions.cs",
            "namespace Visible { public static class Extensions { public static int Convert(this string value) => 0; public static int Convert(this string value, int radix) => 0; public static int Convert(string value, int radix, bool ordinary) => 0; } }\n",
        )
        .file(
            "Hidden/Extensions.cs",
            "namespace Hidden { public static class Extensions { public static int Convert(this string value, int radix) => 1; } }\n",
        )
        .file(
            "App/Runner.cs",
            "using static Visible.Extensions;\nnamespace App { public class Runner { public int Run(string value) { return value.Convert(10); } } }\n",
        );
    for index in 0..256 {
        project = project.file(
            format!("Noise{index}/Extensions.cs"),
            format!(
                "namespace Noise{index} {{ public static class Extensions {{ public static int Convert(this string value, int radix) => {index}; }} }}\n"
            ),
        );
    }
    let project = project.build();
    let analyzer = brokk_bifrost::CSharpAnalyzer::new(project.project_dyn());
    let extension_file = project.file("Visible/Extensions.cs");
    let extension = brokk_bifrost::IAnalyzer::declarations(&analyzer, &extension_file)
        .into_iter()
        .find(|unit| unit.fq_name() == "Visible.Extensions.Convert")
        .expect("visible extension declaration");
    let owner = brokk_bifrost::IAnalyzer::parent_of(&analyzer, &extension)
        .expect("extension method structural owner");
    assert_eq!(owner.fq_name(), "Visible.Extensions");
    analyzer.reset_full_declaration_scan_count_for_test();
    analyzer.reset_full_hydration_count_for_test();
    let line = "namespace App { public class Runner { public int Run(string value) { return value.Convert(10); } } }";

    let value = brokk_bifrost::searchtools::get_definitions_by_location(
        &analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "App/Runner.cs".to_string(),
                line: Some(2),
                column: Some(column_of(line, "Convert")),
            }],
        },
    );

    let result = &value.results[0];
    assert_eq!(result.status, "resolved");
    assert_eq!(
        result.definitions.len(),
        1,
        "only the visible extension overload should match"
    );
    assert_eq!(
        result.definitions[0].fqn.as_deref(),
        Some("Visible.Extensions.Convert")
    );
    assert_eq!(
        result.definitions[0].signature.as_deref(),
        Some("(string, int)")
    );
    assert_eq!(
        analyzer.full_declaration_scan_count_for_test(),
        0,
        "extension lookup must use persisted visibility indexes"
    );
    assert!(
        analyzer.full_hydration_count_for_test() <= 2,
        "extension lookup may hydrate the consumer and visible declaration, but not unrelated same-name files"
    );
}

#[test]
fn csharp_fully_qualified_property_receiver_prefers_applicable_direct_member() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Module.cs",
            r#"namespace Demo {
    public sealed class Module {
        public static Module Instance { get; } = new Module();
        public void Signal(int a, int b, int c, int d, int e, int f, int g, int h, int i) {}
    }
}
"#,
        )
        .file(
            "Demo/Extensions.cs",
            r#"namespace Demo.Runtime {
    public static class Extensions {
        public static void Signal(this Demo.Module module, int value) {}
        public static void Signal(this Demo.Module module, string value) {}
    }
}
"#,
        )
        .file(
            "App/Consumer.cs",
            r#"using static Demo.Runtime.Extensions;
namespace App {
    public sealed class Consumer {
        public void Run() { Demo.Module.Instance.Signal(1, 2, 3, 4, 5, 6, 7, 8, 9); }
    }
}
"#,
        )
        .build();

    let line =
        "        public void Run() { Demo.Module.Instance.Signal(1, 2, 3, 4, 5, 6, 7, 8, 9); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":4,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "inapplicable extensions must not replace the direct property receiver member: {value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "Demo.Module.Signal");
    assert_eq!(
        result["definitions"][0]["signature"],
        "(int, int, int, int, int, int, int, int, int)"
    );
}

#[test]
fn csharp_dotted_value_receiver_precedes_same_spelled_type_path() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Types.cs",
            r#"namespace Demo {
    public sealed class Module { public void Signal(int first, int second) {} }
    public sealed class DirectTarget { public void Signal(string value) {} }
    public sealed class Holder { public DirectTarget Module { get; } = new DirectTarget(); }
}
"#,
        )
        .file(
            "App/Consumer.cs",
            r#"namespace App {
    public sealed class Consumer {
        public void Run(Demo.Holder Demo) { Demo.Module.Signal("value"); }
    }
}
"#,
        )
        .build();

    let line = "        public void Run(Demo.Holder Demo) { Demo.Module.Signal(\"value\"); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["definitions"][0]["fqn"], "Demo.DirectTarget.Signal",
        "a typed value must shadow the same-spelled namespace/type path: {value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "(string)");
}

#[test]
fn csharp_unresolved_dotted_value_shadow_does_not_become_type_path() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Module.cs",
            "namespace Demo { public sealed class Module { public static void Signal() {} } }\n",
        )
        .file(
            "App/Consumer.cs",
            r#"namespace App {
    public sealed class Consumer {
        public void Run(dynamic Demo) { Demo.Module.Signal(); }
    }
}
"#,
        )
        .build();

    let line = "        public void Run(dynamic Demo) { Demo.Module.Signal(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert!(result["definitions"].as_array().is_none_or(Vec::is_empty));
}

#[test]
fn csharp_dotted_receiver_uses_nearest_hidden_property_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Types.cs",
            r#"namespace Demo {
    public sealed class BaseRoute { public void Signal(int value) {} }
    public sealed class DerivedRoute { public void Signal(string value) {} }
    public class Base { public Demo.BaseRoute Route { get; } }
    public sealed class Derived : Base { public Demo.DerivedRoute Route { get; } }
}
"#,
        )
        .file(
            "App/Consumer.cs",
            r#"namespace App {
    public sealed class Consumer {
        public void Run(Demo.Derived derived) { derived.Route.Signal("value"); }
    }
}
"#,
        )
        .build();

    let line = "        public void Run(Demo.Derived derived) { derived.Route.Signal(\"value\"); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["definitions"][0]["fqn"], "Demo.DerivedRoute.Signal",
        "a hidden property must stop lookup before the base property: {value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "(string)");
}

#[test]
fn csharp_unresolved_hidden_property_blocks_base_property_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo/Types.cs",
            r#"namespace Demo {
    public sealed class BaseRoute { public void Signal(string value) {} }
    public class Base { public Demo.BaseRoute Route { get; } }
    public sealed class Derived : Base { public ExternalRoute Route { get; } }
}
"#,
        )
        .file(
            "App/Consumer.cs",
            r#"namespace App {
    public sealed class Consumer {
        public void Run(Demo.Derived derived) { derived.Route.Signal("value"); }
    }
}
"#,
        )
        .build();

    let line = "        public void Run(Demo.Derived derived) { derived.Route.Signal(\"value\"); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Consumer.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "Signal")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert!(result["definitions"].as_array().is_none_or(Vec::is_empty));
}

#[test]
fn csharp_typed_receiver_method_filters_overloads_by_call_arity() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public void GetFilePaths(string path) {} public void GetFilePaths(string path, bool clearCache) {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache) { service.GetFilePaths(folder, clearCache); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache) { service.GetFilePaths(folder, clearCache); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "GetFilePaths")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.GetFilePaths",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(string, bool)",
        "{value}"
    );
}

#[test]
fn csharp_explicit_constructor_call_resolves_to_constructor_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public Service(string name) {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle() { var service = new Service(\"job\"); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle() { var service = new Service(\"job\"); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.Service",
        "{value}"
    );
}

#[test]
fn csharp_partial_nested_constructor_resolves_after_persisted_startup() {
    let project = csharp_nested_partial_cacheinfo_project().build();
    let service = SearchToolsService::new_manual_for_project(project.project_dyn())
        .expect("build persisted C# search tools service");
    let constructor = CSHARP_NESTED_PARTIAL_MAPPER
        .find("new CacheInfo")
        .expect("nested constructor call")
        + "new ".len();
    let payload = service
        .call_tool_json(
            "get_definitions_by_location",
            &location_reference("Mapper.cs", CSHARP_NESTED_PARTIAL_MAPPER, constructor),
        )
        .expect("resolve nested constructor type");
    let value: Value = serde_json::from_str(&payload).expect("valid get_definition response");

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Dapper.SqlMapper$CacheInfo",
        "{value}"
    );
}

#[test]
fn csharp_generic_constructor_coexists_with_same_named_nongeneric_type() {
    let source = r#"namespace Lib {
public class Response {}
public class Error {}
public class RestException {
    public RestException(Response response) {}
    public RestException(Response response, Error body) {}
}
public partial class RestException<T> {
    public RestException(Response response, T body) {}
}
public partial class RestException<T> {
    public T Body { get; }
}
}
"#;
    let consumer = r#"using Lib;
namespace App {
public class Runner {
    public void Run(Response response, Error error) {
        var failure = new RestException<Error>(response, error);
        var body = failure.Body;
    }
}
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Lib/RestException.cs", source)
        .file(
            "Other/RestException.cs",
            "namespace Other { public class RestException<T> { public RestException(T body) {} } }\n",
        )
        .file("App/Runner.cs", consumer)
        .build();
    let start = consumer.find("RestException<Error>").expect("constructor");

    let value = lookup(
        project.root(),
        &location_reference("App/Runner.cs", consumer, start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.RestException`1.RestException",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(Response, T)",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "Lib/RestException.cs",
        "{value}"
    );

    let body = consumer.find("failure.Body").expect("partial member") + "failure.".len();
    let value = lookup(
        project.root(),
        &location_reference("App/Runner.cs", consumer, body),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Lib.RestException`1.Body",
        "{value}"
    );
}

#[test]
fn csharp_nongeneric_static_receiver_beats_same_named_generic_type() {
    let source = r#"namespace Demo;

[System.Runtime.CompilerServices.CollectionBuilder(
    typeof(ImmutableEquatableArray),
    nameof(ImmutableEquatableArray.Create))]
public sealed class ImmutableEquatableArray<T>
{
    public ImmutableEquatableArray(T value) {}
}

public static class ImmutableEquatableArray
{
    public static ImmutableEquatableArray<T> Create<T>(T value) => new(value);
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("ImmutableEquatableArray.cs", source)
        .build();
    let receiver = source
        .find("ImmutableEquatableArray.Create")
        .expect("nameof receiver");
    for (start, expected_fqn) in [
        (receiver, "Demo.ImmutableEquatableArray"),
        (
            receiver + "ImmutableEquatableArray.".len(),
            "Demo.ImmutableEquatableArray.Create",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("ImmutableEquatableArray.cs", source, start),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().unwrap().len(),
            1,
            "{value}"
        );
        assert_eq!(result["definitions"][0]["fqn"], expected_fqn, "{value}");
    }
}

#[test]
fn csharp_typed_receiver_method_wrong_arity_returns_overload_definitions() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Service.cs",
            "namespace Lib { public class Service { public void GetFilePaths(string path) {} public void GetFilePaths(string path, bool clearCache) {} } }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache, int depth) { service.GetFilePaths(folder, clearCache, depth); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Service service, string folder, bool clearCache, int depth) { service.GetFilePaths(folder, clearCache, depth); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "GetFilePaths")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        2,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "Lib.Service.GetFilePaths",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "(string)", "{value}");
    assert_eq!(
        result["definitions"][1]["signature"], "(string, bool)",
        "{value}"
    );
}

#[test]
fn csharp_generic_supertype_selects_arity_exact_base() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Types.cs",
            "namespace Lib { public class Base { public void Pick(int value) {} } public class Base<T> { public void Pick(T value) {} } public class Child : Base<string> {} public class GlobalChild : global::Lib.Base<string> {} }\n",
        )
        .file(
            "Other/AliasedChild.cs",
            "using L = Lib;\nnamespace Other { public class AliasedChild : L::Base<string> {} }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib; using Other;\nnamespace App { public class Controller { public void Handle(Child child, GlobalChild globalChild, AliasedChild aliasedChild) { child.Pick(\"value\"); globalChild.Pick(\"value\"); aliasedChild.Pick(\"value\"); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Child child, GlobalChild globalChild, AliasedChild aliasedChild) { child.Pick(\"value\"); globalChild.Pick(\"value\"); aliasedChild.Pick(\"value\"); } } }";
    for marker in ["child.Pick", "globalChild.Pick", "aliasedChild.Pick"] {
        let value = lookup(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
                column_of(line, marker) + marker.find("Pick").unwrap()
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"].as_array().unwrap().len(),
            1,
            "{value}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"], "Lib.Base`1.Pick",
            "{value}"
        );
    }
}

#[test]
fn csharp_generic_object_initializer_and_new_receiver_keep_owner_arity() {
    let source = r#"namespace Lib {
public class Box {
    public int Value { get; set; }
    public int Read() => Value;
}
public class Box<T> {
    public T Value { get; set; }
    public T Read() => Value;
}
}
"#;
    let consumer = r#"using Lib;
namespace App {
public class Runner {
    public void Run() {
        var initialized = new Box<string> { Value = "text" };
        var read = new Box<string>().Read();
        var globalRead = new global::Lib.Box<string>().Read();
    }
}
}
"#;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Lib/Boxes.cs", source)
        .file("App/Runner.cs", consumer)
        .build();

    for (marker, offset, expected) in [
        ("Value =", 0, "Lib.Box`1.Value"),
        (
            "new Box<string>().Read",
            "new Box<string>().".len(),
            "Lib.Box`1.Read",
        ),
        (
            "new global::Lib.Box<string>().Read",
            "new global::Lib.Box<string>().".len(),
            "Lib.Box`1.Read",
        ),
    ] {
        let start = consumer.find(marker).expect("reference marker") + offset;
        let value = lookup(
            project.root(),
            &location_reference("App/Runner.cs", consumer, start),
        );
        assert_eq!(value["results"][0]["status"], "resolved", "{value}");
        assert_eq!(
            value["results"][0]["definitions"][0]["fqn"], expected,
            "{value}"
        );
    }
}

#[test]
fn csharp_inherited_member_prefers_nearest_declaring_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Types.cs",
            "namespace Lib { public class Grand { public void Run() {} } public class Base : Grand { public new void Run() {} } public class Child : Base {} }\n",
        )
        .file(
            "App/Controller.cs",
            "using Lib;\nnamespace App { public class Controller { public void Handle(Child child) { child.Run(); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Handle(Child child) { child.Run(); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Lib.Base.Run", "{value}");
}

#[test]
fn csharp_partial_class_inherits_member_before_same_named_visible_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Terminal.Gui/View.cs",
            r#"namespace Terminal.Gui {
    public class View {
        public Input.KeyBindings KeyBindings { get; } = new();
    }

    public partial class TreeView : View { }
}
"#,
        )
        .file(
            "Terminal.Gui/Input/KeyBindings.cs",
            r#"namespace Terminal.Gui.Input {
    public sealed class KeyBindings {
        public bool TryGet(int key) => false;
    }
}
"#,
        )
        .file(
            "Terminal.Gui/TreeView.Navigation.cs",
            r#"using Terminal.Gui.Input;

namespace Terminal.Gui {
    public partial class TreeView {
        public bool Navigate(int key) => KeyBindings.TryGet(key);
    }
}
"#,
        )
        .build();

    let line = "        public bool Navigate(int key) => KeyBindings.TryGet(key);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"Terminal.Gui/TreeView.Navigation.cs","line":5,"column":{}}}]}}"#,
            column_of(line, "KeyBindings")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Terminal.Gui.View.KeyBindings",
        "an inherited value member must precede a same-named visible type: {value}"
    );
}

#[test]
fn csharp_this_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/Controller.cs",
            "namespace App { public class Controller { public void Run() {} public void Handle() { this.Run(); } } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { public void Run() {} public void Handle() { this.Run(); } } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Run();")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "App.Controller.Run",
        "{value}"
    );
}

#[test]
fn csharp_external_using_reports_boundary() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/Controller.cs",
            "using External;\nnamespace App { public class Controller { private Service service; } }\n",
        )
        .build();

    let line = "namespace App { public class Controller { private Service service; } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App/Controller.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn csharp_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "class App { void Run() { var value = 1; value++; } }\n",
        )
        .build();

    let line = "class App { void Run() { var value = 1; value++; } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "value++")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_delegate_parameter_resolves_to_lexical_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "using System;\nclass App { void Run() {} void Handle(Action Run) { Run(); } }\n",
        )
        .build();

    let line = "class App { void Run() {} void Handle(Action Run) { Run(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Run();")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "Run", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "parameter", "{value}");
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn csharp_local_function_shadow_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "class App { void Run() {} void Handle() { void Run() {} Run(); } }\n",
        )
        .build();

    let line = "class App { void Run() {} void Handle() { void Run() {} Run(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Run();")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_parameter_declaration_name_resolves_to_itself() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "class App { string Name { get; set; } void Run(string Name) { } }\n",
        )
        .build();

    let line = "class App { string Name { get; set; } void Run(string Name) { } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Name) {")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["name"], "Name", "{value}");
    assert_eq!(result["definitions"][0]["kind"], "parameter", "{value}");
    assert!(result["definitions"][0].get("fqn").is_none(), "{value}");
}

#[test]
fn csharp_local_function_declaration_name_does_not_resolve_to_member() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "class App { void Name() {} void Run() { void Name() {} } }\n",
        )
        .build();

    let line = "class App { void Name() {} void Run() { void Name() {} } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":1,"column":{}}}]}}"#,
            column_of(line, "Name() {} }")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_ambiguous_using_type_returns_ambiguous() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("A/Service.cs", "namespace A { public class Service {} }\n")
        .file("B/Service.cs", "namespace B { public class Service {} }\n")
        .file(
            "App.cs",
            "using A;\nusing B;\nclass App { private Service service; }\n",
        )
        .build();

    let line = "class App { private Service service; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":3,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(value["results"][0]["status"], "ambiguous", "{value}");
    let mut fqns = value["results"][0]["definitions"]
        .as_array()
        .expect("definitions array")
        .iter()
        .map(|definition| definition["fqn"].as_str().expect("definition fqn"))
        .collect::<Vec<_>>();
    fqns.sort_unstable();
    assert_eq!(fqns, ["A.Service", "B.Service"], "{value}");
}

#[test]
fn csharp_alias_external_using_reports_boundary() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "using Svc = External.Service;\nclass App { private Svc service; }\n",
        )
        .build();

    let line = "class App { private Svc service; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Svc")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn csharp_static_external_using_reports_boundary() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            "using static External.Helpers;\nclass App { void Handle() { Help(); } }\n",
        )
        .build();

    let line = "class App { void Handle() { Help(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.cs","line":2,"column":{}}}]}}"#,
            column_of(line, "Help")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn cpp_included_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("target.h", "namespace ns { class Service {}; }\n")
        .file("app.cpp", "#include \"target.h\"\nns::Service service;\n")
        .build();

    let line = "ns::Service service;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service", "{value}");
    assert_eq!(result["definitions"][0]["path"], "target.h", "{value}");
}

#[test]
fn cpp_exact_fqn_candidate_ordering_does_not_hydrate_hidden_duplicate_files() {
    const HIDDEN_DUPLICATES: usize = 16;
    const EXACT_CANDIDATES: usize = HIDDEN_DUPLICATES + 1;
    let mut builder = InlineTestProject::with_language(Language::Cpp)
        .file("z_visible.h", "namespace demo { struct Shared {}; }\n")
        .file(
            "consumer.cpp",
            "#include \"z_visible.h\"\ndemo::Shared value;\n",
        );
    for index in 0..HIDDEN_DUPLICATES {
        builder = builder.file(
            format!("a_hidden_{index:02}.h"),
            "\nnamespace demo { struct Shared {}; }\n",
        );
    }
    let project = builder.build();
    let repository =
        git2::Repository::init(project.root()).expect("git repository for persisted warm analyzer");
    let mut index = repository.index().expect("git index");
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .expect("stage inline fixture");
    let tree_id = index.write_tree().expect("fixture tree");
    let tree = repository.find_tree(tree_id).expect("fixture tree object");
    let signature =
        git2::Signature::now("Bifrost Test", "bifrost@example.invalid").expect("fixture signature");
    repository
        .commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
        .expect("fixture commit");

    let cold_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted analyzer should build");
    drop(cold_workspace);
    let warm_workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted analyzer should reopen");
    let analyzer = warm_workspace.analyzer();

    analyzer.reset_candidate_hydration_count_for_test();
    let definitions = analyzer.definitions("demo.Shared").collect::<Vec<_>>();
    let candidate_hydrations = analyzer.candidate_hydration_count_for_test();

    let actual_paths = definitions
        .iter()
        .map(|unit| {
            unit.source()
                .rel_path()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();
    let mut expected_paths = vec!["z_visible.h".to_string()];
    expected_paths.extend((0..HIDDEN_DUPLICATES).map(|index| format!("a_hidden_{index:02}.h")));
    assert_eq!(
        actual_paths, expected_paths,
        "definition ordering must keep first source position ahead of path tie-breaking"
    );
    assert_eq!(
        definitions.len(),
        EXACT_CANDIDATES,
        "the narrow FQN query retains every distinct exact candidate"
    );
    // Keep the public semantic result covered, but only after capturing the
    // narrow FQN query's hydration count so rendering cannot affect it.
    let line = "demo::Shared value;";
    let value = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: vec![brokk_bifrost::searchtools::DefinitionReferenceQuery {
                path: "consumer.cpp".to_string(),
                line: Some(2),
                column: Some(column_of(line, "Shared")),
            }],
        },
    );
    let result = &value.results[0];
    assert_eq!(result.status, "ambiguous", "lookup result: {result:#?}");
    assert_eq!(
        result.definitions.len(),
        EXACT_CANDIDATES,
        "lookup result: {result:#?}"
    );
    let actual_result_paths = result
        .definitions
        .iter()
        .map(|definition| definition.path.clone())
        .collect::<Vec<_>>();
    let mut expected_result_paths = (0..HIDDEN_DUPLICATES)
        .map(|index| format!("a_hidden_{index:02}.h"))
        .collect::<Vec<_>>();
    expected_result_paths.push("z_visible.h".to_string());
    assert_eq!(
        actual_result_paths, expected_result_paths,
        "rendered duplicate definitions retain their stable path ordering"
    );
    assert_eq!(
        candidate_hydrations, 0,
        "resolving persisted candidate rows and sorting them should not hydrate complete candidate file states; observed {candidate_hydrations} candidate hydrations"
    );
}

#[test]
fn cpp_unrelated_qualified_names_do_not_resolve_to_visible_nested_type() {
    const UNRELATED_ALIAS_TARGET: &str = "base::internal.circular_deque_const_iterator";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "base/containers/circular_deque.h",
            "namespace base { namespace internal { template <typename T> class circular_deque_const_iterator {}; template <typename T> class circular_deque_iterator { using base = circular_deque_const_iterator<T>; }; } class RealType {}; }\n",
        )
        .file(
            "consumer.cc",
            "#include \"base/containers/circular_deque.h\"\nvoid exercise() {\n  base::android::AttachCurrentThread();\n  base::BindOnce();\n  base::TimeDelta elapsed;\n  base::RealType real;\n}\n",
        )
        .build();
    let source = project.file("consumer.cc").read_to_string().unwrap();
    let lines = source.lines().collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({
            "references": [
                {"path": "consumer.cc", "line": 3, "column": column_of(lines[2], "base")},
                {"path": "consumer.cc", "line": 4, "column": column_of(lines[3], "base")},
                {"path": "consumer.cc", "line": 5, "column": column_of(lines[4], "base")},
                {"path": "consumer.cc", "line": 6, "column": column_of(lines[5], "RealType")},
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[3]["status"], "resolved", "{value}");
    assert_eq!(
        results[3]["definitions"][0]["fqn"], "base.RealType",
        "{value}"
    );
    let unrelated_targets = results[..3]
        .iter()
        .flat_map(|result| {
            result["definitions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|definition| definition["fqn"].as_str())
        })
        .collect::<Vec<_>>();
    let unrelated_alias_target_count = unrelated_targets
        .iter()
        .filter(|fqn| **fqn == UNRELATED_ALIAS_TARGET)
        .count();
    assert_eq!(
        unrelated_alias_target_count, 0,
        "unrelated qualified references resolved through the nested `using base` alias: {unrelated_targets:?}"
    );
    assert!(unrelated_targets.is_empty(), "{unrelated_targets:?}");
}

#[test]
fn cpp_repeated_qualifier_alias_checks_bound_candidate_hydration() {
    const REFERENCE_COUNT: usize = 32;
    let mut consumer =
        "#include \"base/containers/circular_deque.h\"\nvoid exercise() {\n".to_string();
    for _ in 0..REFERENCE_COUNT {
        consumer.push_str("  base::BindOnce();\n");
    }
    consumer.push_str("}\n");
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "base/containers/circular_deque.h",
            "namespace base { namespace internal { template <typename T> class circular_deque_const_iterator {}; template <typename T> class circular_deque_iterator { using base = circular_deque_const_iterator<T>; }; } }\n",
        )
        .file("consumer.cc", consumer)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    analyzer.reset_candidate_hydration_count_for_test();
    let value = brokk_bifrost::searchtools::get_definitions_by_location(
        analyzer,
        brokk_bifrost::searchtools::GetDefinitionParams {
            references: (0..REFERENCE_COUNT)
                .map(
                    |index| brokk_bifrost::searchtools::DefinitionReferenceQuery {
                        path: "consumer.cc".to_string(),
                        line: Some(index + 3),
                        column: Some(3),
                    },
                )
                .collect(),
        },
    );

    assert_eq!(value.results.len(), REFERENCE_COUNT, "{value:#?}");
    assert!(
        value
            .results
            .iter()
            .all(|result| result.status == "no_definition" && result.definitions.is_empty()),
        "{value:#?}"
    );
    let hydrations = analyzer.candidate_hydration_count_for_test();
    assert!(
        hydrations <= 2,
        "repeated focused qualifiers should reuse the batch source/tree cache; observed {hydrations} candidate hydrations for {REFERENCE_COUNT} references"
    );
}

#[test]
fn cpp_type_qualifier_focus_follows_its_structural_prefix() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            "namespace ns { struct Outer { struct Inner { static void member(); }; using Alias = Inner; static void member(); }; } namespace unrelated { struct Outer {}; }\n",
        )
        .file(
            "consumer.cc",
            "#include \"types.h\"\nnamespace ns { void exercise() {\n  Outer::member();\n  Outer::Inner::member();\n  Outer::Alias::member();\n} }\n",
        )
        .build();
    let source = project.file("consumer.cc").read_to_string().unwrap();
    let lines = source.lines().collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({
            "references": [
                {"path": "consumer.cc", "line": 3, "column": column_of(lines[2], "Outer")},
                {"path": "consumer.cc", "line": 4, "column": column_of(lines[3], "Inner")},
                {"path": "consumer.cc", "line": 5, "column": column_of(lines[4], "Alias")},
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    let resolved_fqns = results
        .iter()
        .map(|result| {
            assert_eq!(result["status"], "resolved", "{value}");
            result["definitions"][0]["fqn"]
                .as_str()
                .expect("resolved FQN")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        resolved_fqns,
        ["ns.Outer", "ns.Outer$Inner", "ns.Outer$Inner"],
        "{value}"
    );
}

#[test]
fn cpp_type_qualifier_focus_searches_enclosing_namespace_prefixes() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            "namespace a { struct Outer { struct Inner { static void member(); }; static void member(); }; } namespace unrelated { struct Outer {}; }\n",
        )
        .file(
            "consumer.cc",
            "#include \"types.h\"\nnamespace a { namespace b { void exercise() {\n  Outer::member();\n  Outer::Inner::member();\n} } }\n",
        )
        .build();
    let source = project.file("consumer.cc").read_to_string().unwrap();
    let lines = source.lines().collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({
            "references": [
                {"path": "consumer.cc", "line": 3, "column": column_of(lines[2], "Outer")},
                {"path": "consumer.cc", "line": 4, "column": column_of(lines[3], "Inner")},
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    let resolved_fqns = results
        .iter()
        .map(|result| {
            assert_eq!(result["status"], "resolved", "{value}");
            result["definitions"][0]["fqn"]
                .as_str()
                .expect("resolved FQN")
        })
        .collect::<Vec<_>>();
    assert_eq!(resolved_fqns, ["a.Outer", "a.Outer$Inner"], "{value}");
}

#[test]
fn cpp_type_qualifier_focus_stops_at_the_nearest_nonempty_scope() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            "struct Outer { static void member(); }; namespace ns { struct Outer { static void member(); }; } namespace a { struct Outer { static void member(); }; namespace b { struct Outer { static void member(); }; } }\n",
        )
        .file(
            "consumer.cc",
            "#include \"types.h\"\nnamespace ns { void first() {\n  Outer::member();\n} }\nnamespace a { namespace b { void second() {\n  Outer::member();\n} } }\n",
        )
        .build();
    let source = project.file("consumer.cc").read_to_string().unwrap();
    let lines = source.lines().collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({
            "references": [
                {"path": "consumer.cc", "line": 3, "column": column_of(lines[2], "Outer")},
                {"path": "consumer.cc", "line": 6, "column": column_of(lines[5], "Outer")},
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    let fqns = results
        .iter()
        .map(|result| {
            assert_eq!(result["status"], "resolved", "{value}");
            assert_eq!(
                result["definitions"].as_array().map(Vec::len),
                Some(1),
                "nearest nonempty scope must shadow outer declarations: {value}"
            );
            result["definitions"][0]["fqn"]
                .as_str()
                .expect("resolved FQN")
        })
        .collect::<Vec<_>>();
    assert_eq!(fqns, ["ns.Outer", "a::b.Outer"], "{value}");
}

#[test]
fn cpp_type_qualifier_focus_prefers_the_enclosing_class_scope() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            "struct Inner { static void member(); }; struct Outer { struct Inner { static void member(); }; void exercise() { Inner::member(); } };\n",
        )
        .build();
    let line = "struct Inner { static void member(); }; struct Outer { struct Inner { static void member(); }; void exercise() { Inner::member(); } };";
    let value = lookup(
        project.root(),
        &json!({
            "references": [{
                "path": "types.h",
                "line": 1,
                "column": column_of(line, "Inner::member()")
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "enclosing class member must shadow the global type: {value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "Outer$Inner", "{value}");
}

#[test]
fn cpp_leading_global_type_qualifier_focus_is_global_only() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            "struct Outer { static void member(); }; namespace ns { struct Outer { static void member(); }; }\n",
        )
        .file(
            "consumer.cc",
            "#include \"types.h\"\nnamespace ns { void exercise() {\n  ::Outer::member();\n} }\n",
        )
        .build();
    let line = "  ::Outer::member();";
    let value = lookup(
        project.root(),
        &json!({
            "references": [{
                "path": "consumer.cc",
                "line": 3,
                "column": column_of(line, "Outer")
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "leading global qualifier must exclude the lexical namespace: {value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "Outer", "{value}");
}

#[test]
fn cpp_template_type_qualifier_focus_uses_structured_type_names() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.h",
            "template <typename T> struct Outer { struct Inner { static void member(); }; static void member(); };\n",
        )
        .file(
            "consumer.cc",
            "#include \"types.h\"\nvoid exercise() {\n  Outer<int>::member();\n  Outer<int>::Inner::member();\n}\n",
        )
        .build();
    let source = project.file("consumer.cc").read_to_string().unwrap();
    let lines = source.lines().collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({
            "references": [
                {"path": "consumer.cc", "line": 3, "column": column_of(lines[2], "Outer")},
                {"path": "consumer.cc", "line": 4, "column": column_of(lines[3], "Inner")},
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    let resolved_fqns = results
        .iter()
        .map(|result| {
            assert_eq!(result["status"], "resolved", "{value}");
            result["definitions"][0]["fqn"]
                .as_str()
                .expect("resolved FQN")
        })
        .collect::<Vec<_>>();
    assert_eq!(resolved_fqns, ["Outer", "Outer$Inner"], "{value}");
}

#[test]
fn cpp_scoped_template_alias_reference_preserves_specialization_arguments() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "choice.h",
            r#"namespace persist {
struct Special {};
struct Shared {};
template <typename T, typename Tag> class choice {};
template <typename T> class choice<T, Shared> {};
template <> class choice<Special, Shared> {};
template <typename T> using selected = choice<T, Shared>;
}
"#,
        )
        .file(
            "consumer.cc",
            "#include \"choice.h\"\nusing persist::Special;\npersist::selected<Special> value;\n",
        )
        .build();
    let line = "persist::selected<Special> value;";
    let value = lookup(
        project.root(),
        &json!({
            "references": [{
                "path": "consumer.cc",
                "line": 3,
                "column": column_of(line, "selected")
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "the explicit specialization must outrank the partial specialization: {value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "persist.choice<Special, Shared>",
        "{value}"
    );
}

#[test]
fn cpp_constructor_call_resolves_to_header_constructor_declaration() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            "namespace example { class Repository {}; class Service { public: explicit Service(Repository& repository); }; }\n",
        )
        .file(
            "service.cpp",
            "#include \"service.h\"\nnamespace example { Service::Service(Repository& repository) {} Service build_service(Repository& repository) { return Service(repository); } }\n",
        )
        .build();

    let line = "namespace example { Service::Service(Repository& repository) {} Service build_service(Repository& repository) { return Service(repository); } }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"service.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service(repository)")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Service.Service",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["path"], "service.h", "{value}");
}

#[test]
fn cpp_braced_constructor_call_resolves_to_matching_constructor_declaration() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Target { public: Target(); explicit Target(int value); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nnamespace ns { Target make() { return Target{1}; } }\n",
        )
        .build();

    let line = "namespace ns { Target make() { return Target{1}; } }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Target{1}")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Target.Target",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "(int)", "{value}");
    assert_eq!(result["definitions"][0]["path"], "target.h", "{value}");
}

#[test]
fn cpp_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Service { public: void run(); }; }\n",
        )
        .file(
            "target.cpp",
            "#include \"target.h\"\nnamespace ns { void Service::run() {} }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle(ns::Service service) { service.run(); }\n",
        )
        .build();

    let line = "void handle(ns::Service service) { service.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service.run", "{value}");
}

#[test]
fn cpp_navigation_distinguishes_header_declaration_and_source_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            "namespace ns { class Service { public: void run(); }; }\n",
        )
        .file(
            "service.cpp",
            "#include \"service.h\"\nnamespace ns { void Service::run() {} }\n",
        )
        .file(
            "app.cpp",
            "#include \"service.h\"\nvoid invoke(ns::Service& service) { service.run(); }\n",
        )
        .build();
    let source = "#include \"service.h\"\nvoid invoke(ns::Service& service) { service.run(); }\n";
    let call = source.rfind("run").expect("method call");
    let args = location_reference("app.cpp", source, call);

    let declaration = lookup_declaration(project.root(), &args);
    assert_eq!(declaration["results"][0]["operation"], "declaration");
    assert_eq!(
        declaration["results"][0]["status"], "resolved",
        "{declaration}"
    );
    assert_eq!(
        declaration["results"][0]["declarations"][0]["path"], "service.h",
        "{declaration}"
    );

    let definition = lookup(project.root(), &args);
    assert_eq!(definition["results"][0]["operation"], "definition");
    assert_eq!(
        definition["results"][0]["status"], "resolved",
        "{definition}"
    );
    assert_eq!(
        definition["results"][0]["definitions"][0]["path"], "service.cpp",
        "{definition}"
    );
}

#[test]
fn cpp_navigation_distinguishes_same_file_declaration_and_definition_ranges() {
    let source = "void run(); void run() {}\nvoid invoke() { run(); }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", source)
        .build();
    let call = source.rfind("run").expect("function call");
    let args = location_reference("app.cpp", source, call);

    let declaration = lookup_declaration(project.root(), &args);
    assert_eq!(
        declaration["results"][0]["status"], "resolved",
        "{declaration}"
    );
    assert_eq!(
        declaration["results"][0]["declarations"][0]["start_line"], 1,
        "{declaration}"
    );
    assert_eq!(
        declaration["results"][0]["declarations"][0]["start_column"], 6,
        "{declaration}"
    );
    assert_eq!(
        declaration["results"][0]["declarations"][0]["end_column"], 9,
        "{declaration}"
    );

    let definition = lookup(project.root(), &args);
    assert_eq!(
        definition["results"][0]["status"], "resolved",
        "{definition}"
    );
    assert_eq!(
        definition["results"][0]["definitions"][0]["start_line"], 1,
        "{definition}"
    );
    assert_eq!(
        definition["results"][0]["definitions"][0]["start_column"], 18,
        "{definition}"
    );
    assert_eq!(
        definition["results"][0]["definitions"][0]["end_column"], 21,
        "{definition}"
    );
}

#[test]
fn cpp_navigation_keeps_general_symbol_ranges_definition_oriented() {
    let source = "void run();\nvoid run() {}\nvoid invoke() { run(); }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", source)
        .build();

    let locations = call_search_tool_json(
        project.root(),
        "get_symbol_locations",
        r#"{"symbols":["run"]}"#,
    );
    assert_eq!(locations["locations"][0]["start_line"], 2, "{locations}");

    let by_reference = lookup_reference(
        project.root(),
        r#"{"references":[{"symbol":"invoke","context":"void invoke() { run(); }","target":"run"}]}"#,
    );
    assert_eq!(
        by_reference["results"][0]["definitions"][0]["start_line"], 2,
        "{by_reference}"
    );
}

#[test]
fn cpp_declaration_navigation_keeps_all_physical_prototypes_before_filtering() {
    let header = "void run();\n";
    let implementation = "#include \"service.h\"\nvoid run();\nvoid run() {}\n";
    let caller = "#include \"service.h\"\nvoid invoke() { run(); }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("service.h", header)
        .file("service.cpp", implementation)
        .file("app.cpp", caller)
        .build();
    let call = caller.rfind("run").expect("function call");

    let declaration =
        lookup_declaration(project.root(), &location_reference("app.cpp", caller, call));
    assert_eq!(
        declaration["results"][0]["status"], "ambiguous",
        "{declaration}"
    );
    let targets = declaration["results"][0]["declarations"]
        .as_array()
        .expect("declaration targets");
    assert_eq!(targets.len(), 2, "{declaration}");
    assert!(targets.iter().any(|target| target["path"] == "service.h"));
    assert!(
        targets
            .iter()
            .any(|target| { target["path"] == "service.cpp" && target["start_line"] == 2 })
    );
}

#[test]
fn cpp_navigation_retains_declarations_that_follow_definitions() {
    let function_source = "void run() {}\nvoid run();\nvoid invoke() { run(); }\n";
    let function_project = InlineTestProject::with_language(Language::Cpp)
        .file("function.cpp", function_source)
        .build();
    let function_call = function_source.rfind("run").expect("function call");
    let function_args = location_reference("function.cpp", function_source, function_call);
    let declaration = lookup_declaration(function_project.root(), &function_args);
    let definition = lookup(function_project.root(), &function_args);
    assert_eq!(
        declaration["results"][0]["declarations"][0]["start_line"],
        2
    );
    assert_eq!(definition["results"][0]["definitions"][0]["start_line"], 1);

    let type_source = "struct Item {};\nstruct Item;\nItem make();\n";
    let type_project = InlineTestProject::with_language(Language::Cpp)
        .file("type.cpp", type_source)
        .build();
    let type_reference = type_source.rfind("Item").expect("type reference");
    let type_args = location_reference("type.cpp", type_source, type_reference);
    let declaration = lookup_declaration(type_project.root(), &type_args);
    let definition = lookup(type_project.root(), &type_args);
    assert_eq!(
        declaration["results"][0]["declarations"][0]["start_line"],
        2
    );
    assert_eq!(definition["results"][0]["definitions"][0]["start_line"], 1);
}

#[test]
fn cpp_navigation_bounds_repeated_physical_targets() {
    let mut source = "void run();\n".repeat(300);
    source.push_str("void invoke() { run(); }\n");
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("generated.cpp", &source)
        .build();
    let call = source.rfind("run").expect("function call");
    let result = lookup_declaration(
        project.root(),
        &location_reference("generated.cpp", &source, call),
    );

    assert_eq!(result["results"][0]["status"], "ambiguous", "{result}");
    assert_eq!(
        result["results"][0]["declarations"]
            .as_array()
            .map(Vec::len),
        Some(256),
        "{result}"
    );
    assert!(
        result["results"][0]["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| diagnostics
                .iter()
                .any(|diagnostic| diagnostic["kind"] == "navigation_targets_truncated")),
        "{result}"
    );
}

#[test]
fn cpp_navigation_bounds_repeated_targets_across_a_batch() {
    let mut source = "void run();\n".repeat(300);
    source.push_str("void invoke() { run(); }\n");
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("generated.cpp", &source)
        .build();
    let call = source.rfind("run").expect("function call");
    let prefix = &source[..call];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let references = (0..5)
        .map(|_| json!({"path": "generated.cpp", "line": line, "column": column}))
        .collect::<Vec<_>>();
    let result = lookup_declaration(
        project.root(),
        &json!({"references": references}).to_string(),
    );

    let results = result["results"].as_array().expect("batch results");
    assert_eq!(results.len(), 5, "{result}");
    assert_eq!(
        results
            .iter()
            .map(|item| item["declarations"].as_array().map_or(0, Vec::len))
            .sum::<usize>(),
        1020,
        "{result}"
    );
    assert!(results.iter().all(|item| {
        item["diagnostics"].as_array().is_some_and(|diagnostics| {
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic["kind"] == "navigation_targets_truncated")
        })
    }));
}

#[test]
fn cpp_overload_ambiguity_does_not_claim_an_unproven_link_unit() {
    let target = "namespace ns { class Net { public: int load(); int load(int value); }; int Net::load() { return 0; } int Net::load(int value) { return value; } }\n";
    let caller = "#include \"target.h\"\nvoid invoke(ns::Net& net) { net.load(1, 2); }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("target.h", target)
        .file("app.cpp", caller)
        .build();
    let call = caller.rfind("load").expect("method call");
    let result = lookup(project.root(), &location_reference("app.cpp", caller, call));

    assert_eq!(result["results"][0]["status"], "ambiguous", "{result}");
    assert_eq!(
        result["results"][0]["definitions"].as_array().map(Vec::len),
        Some(2),
        "{result}"
    );
    assert!(
        result["results"][0]["diagnostics"]
            .as_array()
            .is_none_or(|diagnostics| diagnostics
                .iter()
                .all(|diagnostic| diagnostic["kind"] != "unproven_cpp_link_unit")),
        "{result}"
    );
}

#[test]
fn cpp_definition_navigation_keeps_multiple_bodies_ambiguous() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("service.h", "void run();\n")
        .file("first.cpp", "#include \"service.h\"\nvoid run() {}\n")
        .file("second.cpp", "#include \"service.h\"\nvoid run() {}\n")
        .file(
            "app.cpp",
            "#include \"service.h\"\nvoid invoke() { run(); }\n",
        )
        .build();
    let source = "#include \"service.h\"\nvoid invoke() { run(); }\n";
    let call = source.rfind("run").expect("function call");
    let value = lookup(project.root(), &location_reference("app.cpp", source, call));
    assert_eq!(value["results"][0]["operation"], "definition");
    assert_eq!(value["results"][0]["status"], "ambiguous", "{value}");
    assert_eq!(
        value["results"][0]["definitions"].as_array().map(Vec::len),
        Some(2),
        "{value}"
    );
    assert!(
        value["results"][0]["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| diagnostics
                .iter()
                .any(|diagnostic| { diagnostic["kind"] == "unproven_cpp_link_unit" })),
        "{value}"
    );
}

#[test]
fn cpp_definition_navigation_keeps_same_file_bodies_ambiguous() {
    let source = "void run() {}\nvoid run() {}\nvoid invoke() { run(); }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", source)
        .build();
    let call = source.rfind("run").expect("function call");
    let value = lookup(project.root(), &location_reference("app.cpp", source, call));

    assert_eq!(value["results"][0]["status"], "ambiguous", "{value}");
    assert_eq!(
        value["results"][0]["definitions"].as_array().map(Vec::len),
        Some(2),
        "{value}"
    );
    assert!(
        value["results"][0]["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| diagnostics
                .iter()
                .any(|diagnostic| diagnostic["kind"] == "unproven_cpp_link_unit")),
        "{value}"
    );
}

#[test]
fn cpp_definition_navigation_does_not_fall_back_to_a_prototype() {
    let source = "void run();\nvoid invoke() { run(); }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", source)
        .build();
    let call = source.rfind("run").expect("function call");
    let value = lookup(project.root(), &location_reference("app.cpp", source, call));

    assert_eq!(value["results"][0]["operation"], "definition");
    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(value["results"][0].get("definitions").is_none(), "{value}");
}

#[test]
fn cpp_typed_receiver_method_filters_overloads_by_call_arity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class Net { public: int load_model(); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr); }\n",
        )
        .build();

    let line = "void handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr); }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(DataReader &)",
        "{value}"
    );
}

#[test]
fn cpp_typed_receiver_method_wrong_arity_returns_overload_definitions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class Net { public: int load_model(); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr, dr); }\n",
        )
        .build();

    let line = "void handle(ns::Net& net, const ns::DataReader& dr) { net.load_model(dr, dr); }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        2,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["signature"], "()", "{value}");
    assert_eq!(
        result["definitions"][1]["signature"], "(DataReader &)",
        "{value}"
    );

    let definition = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );
    let result = &definition["results"][0];
    assert_eq!(result["status"], "no_definition", "{definition}");
    assert!(
        result["diagnostics"]
            .as_array()
            .is_none_or(|diagnostics| diagnostics
                .iter()
                .all(|diagnostic| diagnostic["kind"] != "ambiguous_definition")),
        "{definition}"
    );
}

#[test]
fn cpp_typed_receiver_method_filters_overloads_by_argument_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class DataReaderFromMemory : public DataReader {}; class Net { public: int load_model(const char* path); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nclass DataReaderFromMemoryCopy : public DataReaderFromMemory {};\nvoid bind(Net& net, DataReaderFromMemoryCopy& dr) { net.load_model(dr); }\n",
        )
        .build();

    let line = "void bind(Net& net, DataReaderFromMemoryCopy& dr) { net.load_model(dr); }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":4,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(DataReader &)",
        "{value}"
    );
}

#[test]
fn cpp_same_arity_free_function_overloads_filter_by_argument_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/parity.h",
            r#"#pragma once
#include <string>
namespace parity {
struct AuditSink {
    std::string last;
    void record(const std::string& value);
};
class BaseHandler {
public:
    virtual ~BaseHandler() = default;
    virtual std::string handle(const std::string& name) = 0;
};
class ConsoleHandler : public BaseHandler {
public:
    explicit ConsoleHandler(AuditSink& sink);
    std::string handle(const std::string& name) override;
private:
    AuditSink& sink_;
};
std::string format(const std::string& value);
std::string format(int value);
} // namespace parity
"#,
        )
        .file(
            "src/parity.cpp",
            r#"#include "parity.h"
namespace parity {
void AuditSink::record(const std::string& value) { last = value; }
ConsoleHandler::ConsoleHandler(AuditSink& sink) : sink_(sink) {}
std::string ConsoleHandler::handle(const std::string& name) {
    sink_.record(name);
    return name;
}
std::string format(const std::string& value) { return "s:" + value; }
std::string format(int value) { return "i:" + std::to_string(value); }
} // namespace parity
"#,
        )
        .file(
            "src/main.cpp",
            r#"#include "parity.h"
namespace app {
std::string run() {
    parity::AuditSink sink;
    parity::ConsoleHandler handler(sink);
    parity::BaseHandler& base = handler;
    auto first = base.handle("Ada");
    auto formatted = parity::format(first);
    auto number = parity::format(7);
    return formatted + number;
}
} // namespace app
"#,
        )
        .build();

    let first_line = "    auto formatted = parity::format(first);";
    let first_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/main.cpp","line":8,"column":{}}}]}}"#,
            column_of(first_line, "format(first)")
        ),
    );
    assert_cpp_format_overload_definitions(&first_value, "string");

    let int_line = "    auto number = parity::format(7);";
    let int_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/main.cpp","line":9,"column":{}}}]}}"#,
            column_of(int_line, "format(7)")
        ),
    );
    assert_cpp_format_overload_definitions(&int_value, "int");
}

fn assert_cpp_format_overload_definitions(value: &Value, expected_signature_fragment: &str) {
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    let definitions = result["definitions"].as_array().unwrap();
    assert_eq!(definitions.len(), 1, "{value}");
    assert_eq!(definitions[0]["path"], "src/parity.cpp", "{value}");
    assert!(
        definitions.iter().all(|definition| {
            definition["fqn"] == "parity.format"
                && definition["signature"]
                    .as_str()
                    .is_some_and(|signature| signature.contains(expected_signature_fragment))
        }),
        "{value}"
    );
}

#[test]
fn cpp_typed_receiver_method_wrong_argument_type_returns_overload_definitions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class DataReader {}; class Other {}; class Net { public: int load_model(const char* path); int load_model(const DataReader& dr); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nvoid bind(Net& net, Other& other) { net.load_model(other); }\n",
        )
        .build();

    let line = "void bind(Net& net, Other& other) { net.load_model(other); }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "load_model")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        2,
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Net.load_model",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["signature"], "(DataReader &)",
        "{value}"
    );
    assert_eq!(result["definitions"][1]["signature"], "(char *)", "{value}");
}

#[test]
fn cpp_typed_receiver_method_filters_pointer_overload_by_argument_indirection() {
    // A pointer argument must select the `Widget*` overload over the `Widget`
    // value overload. This is the case the old workspace-pointer escape hatch
    // bailed on (returning both); indirection-aware matching resolves it.
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Widget {}; class Sink { public: int accept(Widget w); int accept(Widget* w); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nvoid bind(Sink& sink, Widget* wp) { sink.accept(wp); }\n",
        )
        .build();

    let line = "void bind(Sink& sink, Widget* wp) { sink.accept(wp); }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "accept")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "ns.Sink.accept", "{value}");
    assert_eq!(
        result["definitions"][0]["signature"], "(Widget *)",
        "{value}"
    );
}

#[test]
fn cpp_typed_receiver_method_filters_value_overload_by_argument_indirection() {
    // The mirror of the pointer case: a value argument must select the `Widget`
    // overload over the `Widget*` overload.
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Widget {}; class Sink { public: int accept(Widget w); int accept(Widget* w); }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nusing namespace ns;\nvoid bind(Sink& sink, Widget w) { sink.accept(w); }\n",
        )
        .build();

    let line = "void bind(Sink& sink, Widget w) { sink.accept(w); }";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "accept")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["fqn"], "ns.Sink.accept", "{value}");
    assert_eq!(result["definitions"][0]["signature"], "(Widget)", "{value}");
}

#[test]
fn cpp_chained_struct_field_receiver_resolves_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("bstr.h", "struct bstr { int len; };\n")
        .file(
            "app.c",
            "#include \"bstr.h\"\nstruct tmp_buffers { struct bstr write_console_buf; };\nint read_len(struct tmp_buffers *buffers) { return buffers->write_console_buf.len; }\n",
        )
        .build();

    let line =
        "int read_len(struct tmp_buffers *buffers) { return buffers->write_console_buf.len; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.c","line":3,"column":{}}}]}}"#,
            line.rfind("len").expect("field in line") + 1
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "bstr.len", "{value}");
}

#[test]
fn cpp_typedef_struct_value_parameter_resolves_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/lib/raw.h",
            r#"
#ifndef LIB_RAW_H
#define LIB_RAW_H
#ifdef __cplusplus
extern "C" {
#endif
typedef struct RawData { unsigned char * data; unsigned long size; } RawData;
#ifdef __cplusplus
}
#endif
#endif
"#,
        )
        .file(
            "apps/shared/raw_reader.h",
            "#include \"lib/raw.h\"\nint read_len(const RawData raw);\n",
        )
        .file(
            "apps/shared/app.c",
            "#include \"raw_reader.h\"\nint read_len(const RawData raw) { return raw.size; }\n",
        )
        .build();

    let line = "int read_len(const RawData raw) { return raw.size; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"apps/shared/app.c","line":2,"column":{}}}]}}"#,
            column_of(line, "size")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "RawData.size", "{value}");
}

#[test]
fn cpp_local_type_uses_class_body_over_forward_declaration() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class DeepImage;
class Image {
public:
    void resize();
};
class DeepImage : public Image {
public:
    void level();
};
void run() {
    DeepImage img;
    img.resize();
    img.level();
}
"#,
        )
        .build();

    let resize = "    img.resize();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":13,"column":{}}},{{"path":"app.cpp","line":14,"column":{}}}]}}"#,
            column_of(resize, "resize"),
            column_of("    img.level();", "level")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Image.resize",
        "{value}"
    );
    assert_eq!(value["results"][1]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][1]["definitions"][0]["fqn"], "DeepImage.level",
        "{value}"
    );
}

#[test]
fn cpp_elaborated_return_type_function_is_not_recovered_as_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class RawData {};
class RawData make() {
    return RawData{};
}
void consume(make *ptr) {}
"#,
        )
        .build();

    let line = "void consume(make *ptr) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "make")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
}

#[test]
fn cpp_multi_declarator_local_declaration_reuses_shared_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
struct RawData {
    void use();
};
void run() {
    RawData first, second;
    second.use();
}
"#,
        )
        .build();

    let line = "    second.use();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":7,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "RawData.use", "{value}");
}

#[test]
fn cpp_secondary_local_declarator_is_not_an_indexed_field_reference() {
    let source = r#"
typedef unsigned long size_t;
struct Record {
    int j;
};
int read(Record *record) {
    size_t i, j;
    j = i;
    return record->j;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.c", source)
        .build();

    let declaration = source.find("i, j;").expect("multi-declarator local") + 3;
    let local_use = source.find("    j = i;").expect("local value use") + 4;
    let field_use = source.rfind("record->j").expect("qualified field use") + "record->".len();
    let value = lookup(
        project.root(),
        &json!({
            "references": [
                location_query("app.c", source, declaration),
                location_query("app.c", source, local_use),
                location_query("app.c", source, field_use),
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "no_definition", "{value}");
    assert_eq!(
        results[0]["diagnostics"][0]["kind"], "declaration_or_import_site",
        "{value}"
    );
    assert_eq!(results[1]["status"], "no_definition", "{value}");
    assert_eq!(
        results[1]["diagnostics"][0]["kind"], "local_variable_reference",
        "{value}"
    );
    assert_eq!(results[2]["status"], "resolved", "{value}");
    assert_eq!(results[2]["definitions"][0]["fqn"], "Record.j", "{value}");
}

#[test]
fn cpp_typedef_alias_declarator_is_not_a_type_reference() {
    let source = r#"
typedef struct Scope Scope;
struct Scope {
    int value;
};
Scope *identity(Scope *scope) {
    return scope;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.c", source)
        .build();

    let alias = source.find("Scope Scope;").expect("typedef alias") + "Scope ".len();
    let type_use = source.find("Scope *identity").expect("typedef type use");
    let value = lookup(
        project.root(),
        &json!({
            "references": [
                location_query("app.c", source, alias),
                location_query("app.c", source, type_use),
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "no_definition", "{value}");
    assert_eq!(
        results[0]["diagnostics"][0]["kind"], "declaration_or_import_site",
        "{value}"
    );
    assert_eq!(results[1]["status"], "resolved", "{value}");
    assert_eq!(results[1]["definitions"][0]["fqn"], "Scope", "{value}");
}

#[test]
fn cpp_export_macro_class_body_seeds_local_receiver_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API
#define NS_ENTER namespace Project {
#define NS_EXIT }
NS_ENTER
class Image {
public:
    void resize();
};
class API DeepImage : public Image {
public:
    void level();
};
NS_EXIT
void run() {
    DeepImage img;
    img.resize();
    img.level();
}
"#,
        )
        .build();

    let value = lookup_declaration_with_definition_key(
        project.root(),
        r#"{"references":[{"path":"app.cpp","line":17,"column":9},{"path":"app.cpp","line":18,"column":9}]}"#,
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Image.resize",
        "{value}"
    );
    assert_eq!(value["results"][1]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][1]["definitions"][0]["fqn"], "DeepImage.level",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_local_type_seeds_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData raw;
    raw.use();
}
"#,
        )
        .build();

    let line = "    raw.use();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_function_like_macro_decorated_local_type_seeds_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API_ATTR(x)

struct RawData {
    void use();
};

void run() {
    API_ATTR(foo) RawData raw;
    raw.use();
}
"#,
        )
        .build();

    let line = "    raw.use();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_multi_declarator_reuses_shared_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData first, second;
    second.use();
}
"#,
        )
        .build();

    let line = "    second.use();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_multi_declarator_keeps_pointer_depth_per_declarator() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData *first, second;
    second.use();
}
"#,
        )
        .build();

    let line = "    second.use();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_macro_decorated_multi_declarator_preserves_pointer_depth_on_later_pointer() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API

struct RawData {
    void use();
};

void run() {
    API RawData first, *second;
    second->use();
}
"#,
        )
        .build();

    let line = "    second->use();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "use")
        ),
    );

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "RawData.use",
        "{value}"
    );
}

#[test]
fn cpp_local_function_declaration_does_not_seed_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "class Widget { public: void run(); };\nWidget make(int);\nvoid handle() { make.run(); }\n",
        )
        .build();

    let line = "void handle() { make.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_local_function_declaration_with_builtin_pointer_does_not_seed_receiver_binding() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "class Widget { public: void run(); };\nWidget make(const unsigned char* mem);\nvoid handle() { make.run(); }\n",
        )
        .build();

    let line = "void handle() { make.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_workspace_angle_include_receiver_method_resolves_to_definition() {
    let header = "#define API\nnamespace ns { class API Service { public: void run(); }; }\n";
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/target.h", header)
        .file(
            "target.cpp",
            "#include \"include/target.h\"\nnamespace ns { void Service::run() {} }\n",
        )
        .file(
            "src/app.cpp",
            "#include <target.h>\nusing namespace ns;\nvoid handle(Service& service) { service.run(); }\n",
        )
        .build();

    let line = "void handle(Service& service) { service.run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service.run", "{value}");
}

#[test]
fn cpp_workspace_angle_include_missing_type_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("target.h", "namespace ns { class Service {}; }\n")
        .file(
            "src/app.cpp",
            "#include <target.h>\nusing namespace ns;\nMissingType value;\n",
        )
        .build();

    let line = "MissingType value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"src/app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "MissingType")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_export_macro_class_recovery_handles_header_variants() {
    let cases = [
        (
            "final class",
            "#define API\nnamespace ns { class API Service final { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "single macro with base",
            "#define API_EXPORT\nnamespace ns { class Base {}; class API_EXPORT Service : public Base { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "function-like export macro",
            "#define API(component)\nnamespace ns { class API(foo) Service { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "function-like component export macro",
            "#define COMPONENT_EXPORT(component)\nnamespace ns { class COMPONENT_EXPORT(URL) Service { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "multiple macros",
            "#define DLL_PUBLIC\n#define API\nnamespace ns { class DLL_PUBLIC API Service { public: void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "struct macro",
            "#define API\nnamespace ns { struct API Service { void run(); }; }\n",
            "ns.Service.run",
        ),
        (
            "function-like namespace macro",
            "#define NS_ENTER(name) namespace name {\n#define NS_EXIT }\n#define API\nNS_ENTER(ns)\nclass API Service { public: void run(); };\nNS_EXIT\n",
            "Service.run",
        ),
    ];

    for (name, header, expected_fqn) in cases {
        let project = InlineTestProject::with_language(Language::Cpp)
            .file("include/target.h", header)
            .file(
                "target.cpp",
                "#include \"include/target.h\"\nnamespace ns { void Service::run() {} }\n",
            )
            .file(
                "src/app.cpp",
                "#include <target.h>\nusing namespace ns;\nvoid handle(Service& service) { service.run(); }\n",
            )
            .build();

        let line = "void handle(Service& service) { service.run(); }";
        let value = lookup_declaration_with_definition_key(
            project.root(),
            &format!(
                r#"{{"references":[{{"path":"src/app.cpp","line":3,"column":{}}}]}}"#,
                column_of(line, "run")
            ),
        );

        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{name}: {value}");
        assert_eq!(
            result["definitions"][0]["fqn"], expected_fqn,
            "{name}: {value}"
        );
    }
}

#[test]
fn cpp_relative_namespace_call_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "namespace ns { namespace detail { void helper() {} } void run() { detail::helper(); } }\n",
        )
        .build();

    let line =
        "namespace ns { namespace detail { void helper() {} } void run() { detail::helper(); } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":1,"column":{}}}]}}"#,
            column_of(line, "helper();")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns::detail.helper",
        "{value}"
    );
}

#[test]
fn cpp_flattened_macro_namespace_forward_declaration_activates_qualified_definition() {
    let base_header = r#"
#define FMT_API
FMT_API void vformat_to(int& out, int format, int args, int locale = {});
}  // namespace detail, flattened after an earlier macro-shaped parse error
void run() {
    int out = 0;
    detail::vformat_to(out, 0, 0, 0);
}
#include "format-inl.h"
"#;
    let format_inline = r#"
#define FMT_FUNC
namespace detail {
FMT_FUNC void vformat_to(int& out, int format, int args, int locale) {}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("base.h", base_header)
        .file("format-inl.h", format_inline)
        .build();

    let line = "    detail::vformat_to(out, 0, 0, 0);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"base.h","line":7,"column":{}}}]}}"#,
            column_of(line, "vformat_to")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "detail.vformat_to",
        "{value}"
    );
    assert!(
        result["definitions"]
            .as_array()
            .is_some_and(|definitions| definitions
                .iter()
                .any(|definition| definition["path"] == "format-inl.h")),
        "{value}"
    );
}

#[test]
fn cpp_global_macro_forward_declaration_does_not_activate_later_namespace_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
#define API
API void helper(int value);
void run() { detail::helper(1); }
namespace detail { void helper(int value) {} }
"#,
        )
        .build();

    let line = "void run() { detail::helper(1); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":4,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_range_for_pointer_binding_resolves_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "graph.h",
            r#"
namespace ns {
class Operator { public: int params; };
class Graph { public: Operator* ops; };
}
"#,
        )
        .file(
            "app.cpp",
            r#"
#include "graph.h"
using namespace ns;
void run(Graph& graph) {
    for (Operator* op : graph.ops) {
        op->params = 1;
    }
}
"#,
        )
        .build();

    let line = "        op->params = 1;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "params")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Operator.params",
        "{value}"
    );
}

#[test]
fn cpp_external_include_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            "#include <external/service.h>\nService service;\n",
        )
        .build();

    let line = "Service service;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn cpp_extensionless_angle_include_with_unrelated_basename_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("vendor/vector", "namespace local { class NotStd {}; }\n")
        .file("app.cpp", "#include <vector>\nstd::Vector values;\n")
        .build();

    let line = "std::Vector values;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Vector")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn cpp_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", "void run() { int value = 1; value++; }\n")
        .build();

    let line = "void run() { int value = 1; value++; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":1,"column":{}}}]}}"#,
            column_of(line, "value++")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_same_file_global_value_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.c",
            "static const int global_value = 1;\nint run() { return global_value; }\n",
        )
        .build();

    let line = "int run() { return global_value; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.c","line":2,"column":{}}}]}}"#,
            column_of(line, "global_value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "app.c", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 1, "{value}");
}

#[test]
fn cpp_bare_enum_enumerator_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
enum Mode { Ready, Done };
Mode current() { return Ready; }
"#,
        )
        .build();

    let line = "Mode current() { return Ready; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "Ready")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Mode.Ready", "{value}");
}

#[test]
fn cpp_scoped_enum_enumerator_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
enum class PowerSaveLevel { LOW_POWER, PERFORMANCE };
PowerSaveLevel current() { return PowerSaveLevel::PERFORMANCE; }
"#,
        )
        .build();

    let line = "PowerSaveLevel current() { return PowerSaveLevel::PERFORMANCE; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "PERFORMANCE")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "PowerSaveLevel.PERFORMANCE",
        "{value}"
    );
}

#[test]
fn cpp_bare_member_field_resolves_in_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Parser {
    int fp_;
    void run() {
        if (!fp_) {}
    }
};
"#,
        )
        .build();

    let line = "        if (!fp_) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Parser.fp_", "{value}");
}

#[test]
fn cpp_bare_member_field_resolves_in_out_of_line_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "parser.h",
            r#"
namespace ns {
class Parser {
    int fp_;
    void run();
};
}
"#,
        )
        .file(
            "parser.cpp",
            r#"
#include "parser.h"
namespace ns {
void Parser::run() {
    if (!*fp_) {}
}
}
"#,
        )
        .build();

    let line = "    if (!*fp_) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"parser.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Parser.fp_", "{value}");
}

#[test]
fn cpp_member_field_receiver_resolves_in_out_of_line_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "parser.h",
            r#"
namespace ns {
class Logger {
public:
    bool atErrorLimit() const;
};
class Parser {
    Logger& log_;
    void run();
};
}
"#,
        )
        .file(
            "parser.cpp",
            r#"
#include "parser.h"
namespace ns {
void Parser::run() {
    if (log_.atErrorLimit()) {}
}
}
"#,
        )
        .build();

    let line = "    if (log_.atErrorLimit()) {}";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"parser.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "atErrorLimit")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Logger.atErrorLimit",
        "{value}"
    );
}

#[test]
fn cpp_out_of_line_method_prefers_lexical_namespace_owner() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "global.h",
            r#"
class Parser {
public:
    bool wrong();
};
"#,
        )
        .file(
            "parser.h",
            r#"
namespace ns {
class Parser {
public:
    bool right();
    bool run();
};
}
"#,
        )
        .file(
            "parser.cpp",
            r#"
#include "global.h"
#include "parser.h"
namespace ns {
bool Parser::run() {
    return this->right();
}
}
"#,
        )
        .build();

    let line = "    return this->right();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"parser.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "right")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Parser.right",
        "{value}"
    );
}

#[test]
fn cpp_this_receiver_resolves_in_out_of_line_method_body() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "visitor.h",
            r#"
namespace ns {
class Visitor {
public:
    bool traverse();
    bool run();
};
}
"#,
        )
        .file(
            "visitor.cpp",
            r#"
#include "visitor.h"
namespace ns {
bool Visitor::run() {
    return this->traverse();
}
}
"#,
        )
        .build();

    let line = "    return this->traverse();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"visitor.cpp","line":5,"column":{}}}]}}"#,
            column_of(line, "traverse")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns.Visitor.traverse",
        "{value}"
    );
}

#[test]
fn cpp_relative_qualified_parameter_type_resolves_arrow_member() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "ast.h",
            r#"
namespace ns {
namespace ast {
class TernaryOperator {
public:
    bool condition() const;
};
}
}
"#,
        )
        .file(
            "visitor.h",
            r#"
#include "ast.h"
namespace ns {
namespace codegen {
class Visitor {
public:
    bool run(const ast::TernaryOperator* tern);
};
}
}
"#,
        )
        .file(
            "visitor.cpp",
            r#"
#include "visitor.h"
namespace ns {
namespace codegen {
bool Visitor::run(const ast::TernaryOperator* tern) {
    return tern->condition();
}
}
}
"#,
        )
        .build();

    let line = "    return tern->condition();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"visitor.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "condition")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "ns::ast.TernaryOperator.condition",
        "{value}"
    );
}

#[test]
fn cpp_relative_qualified_type_does_not_match_unrelated_suffix_namespace() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            r#"
namespace foo {
namespace bar {
class T {
public:
    bool wrong() const;
};
}
}
"#,
        )
        .file(
            "visitor.cpp",
            r#"
#include "target.h"
namespace ns {
namespace codegen {
bool run(const bar::T* value) {
    return value->wrong();
}
}
}
"#,
        )
        .build();

    let line = "    return value->wrong();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"visitor.cpp","line":6,"column":{}}}]}}"#,
            column_of(line, "wrong")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_bare_member_field_resolves_from_base_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Base {
protected:
    int fp_;
};
class Parser : public Base {
    void run() {
        if (!fp_) {}
    }
};
"#,
        )
        .build();

    let line = "        if (!fp_) {}";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":8,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Base.fp_", "{value}");
}

#[test]
fn cpp_bare_member_call_prefers_current_class_override() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Base {
public:
    virtual void close(bool send = true) = 0;
};
class Parser : public Base {
public:
    void close(bool send = true) override;
    void run() {
        close(false);
    }
};
void Parser::close(bool send) {}
"#,
        )
        .build();

    let line = "        close(false);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":10,"column":{}}}]}}"#,
            column_of(line, "close")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Parser.close", "{value}");
}

#[test]
fn cpp_bare_identifier_does_not_resolve_unrelated_member_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class File { int fp_; };
int run() { return fp_; }
"#,
        )
        .build();

    let line = "int run() { return fp_; }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":3,"column":{}}}]}}"#,
            column_of(line, "fp_")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_static_const_struct_value_resolves_in_initializer() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.c",
            r#"
typedef struct AVClass AVClass;
typedef struct StreamOps StreamOps;

struct AVClass {
    const char *class_name;
};

struct StreamOps {
    const AVClass *priv_class;
};

static const AVClass curl_avio_class = {
    .class_name = "stream",
};

static const StreamOps stream_ops = {
    .priv_class = &curl_avio_class,
};
"#,
        )
        .build();

    let line = "    .priv_class = &curl_avio_class,";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.c","line":18,"column":{}}}]}}"#,
            column_of(line, "curl_avio_class")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["path"], "app.c", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 13, "{value}");
}

#[test]
fn cpp_out_of_line_definition_name_is_not_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.cpp",
            "namespace ns { class Service { public: void run(); }; void Service::run() {} }\n",
        )
        .build();

    let line = "namespace ns { class Service { public: void run(); }; void Service::run() {} }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"target.cpp","line":1,"column":{}}}]}}"#,
            column_of(line, "run() {}")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_type_reference_does_not_resolve_to_same_named_function() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("api.h", "namespace ns { void Service(); }\n")
        .file("app.cpp", "#include \"api.h\"\nns::Service service;\n")
        .build();

    let line = "ns::Service service;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_qualified_call_does_not_cross_unrelated_namespace() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "api.h",
            "namespace ns { namespace detail { void helper() {} } }\n",
        )
        .file(
            "app.cpp",
            "#include \"api.h\"\nvoid run() { detail::helper(); }\n",
        )
        .build();

    let line = "void run() { detail::helper(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "helper")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_auto_new_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "target.h",
            "namespace ns { class Service { public: void run() {} }; }\n",
        )
        .file(
            "app.cpp",
            "#include \"target.h\"\nvoid handle() { auto service = new ns::Service(); service->run(); }\n",
        )
        .build();

    let line = "void handle() { auto service = new ns::Service(); service->run(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "ns.Service.run", "{value}");
}

#[test]
fn cpp_auto_static_call_receiver_method_resolves_to_return_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
class Board {
public:
    static Board& GetInstance();
    void SetPowerSaveLevel();
};
void run() {
    auto& board = Board::GetInstance();
    board.SetPowerSaveLevel();
}
"#,
        )
        .build();

    let line = "    board.SetPowerSaveLevel();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":9,"column":{}}}]}}"#,
            column_of(line, "SetPowerSaveLevel")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "Board.SetPowerSaveLevel",
        "{value}"
    );
}

#[test]
fn cpp_alias_pointer_receiver_resolves_underlying_type_member() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
template <class T> class shared_ptr {
public:
    T* operator->();
};
class InterfaceElement {
public:
    void getActiveOutputs();
};
class NodeDef : public InterfaceElement {};
using NodeDefPtr = shared_ptr<NodeDef>;
void run(NodeDefPtr nodeDef) {
    nodeDef->getActiveOutputs();
}
"#,
        )
        .build();

    let line = "    nodeDef->getActiveOutputs();";
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":13,"column":{}}}]}}"#,
            column_of(line, "getActiveOutputs")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "InterfaceElement.getActiveOutputs",
        "{value}"
    );
}

#[test]
fn cpp_template_alias_dot_receiver_does_not_unwrap_to_first_argument() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "app.cpp",
            r#"
template <class T> class vector {
public:
    int size();
};
class Node {
public:
    void visit();
};
using NodeVector = vector<Node>;
void run(NodeVector nodes) {
    nodes.visit();
}
"#,
        )
        .build();

    let line = "    nodes.visit();";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":12,"column":{}}}]}}"#,
            column_of(line, "visit")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_unqualified_typo_with_angle_include_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", "#include <vector>\nvoid run() { typo(); }\n")
        .build();

    let line = "void run() { typo(); }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.cpp","line":2,"column":{}}}]}}"#,
            column_of(line, "typo")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn cpp_explicit_qualified_lookup_preserves_scope_and_symbol_kind() {
    let api = r#"
namespace proton {
template<class K, class V> class map {};
template<class T> class outer {
public:
    template<class U> class nested {};
};
class error {};
class connection { public: int error() const; };
namespace nested { class item {}; }
}
namespace sibling { class item {}; }
"#;
    let source = r#"
#include "api.hpp"
#include <map>
std::map<int, int>* external_map;
proton::error make_error() { return proton::error(); }
proton::nested::item nested_item;
::proton::nested::item global_nested_item;
proton::outer<int>::nested<long> nested_template_item;
sibling::item sibling_item;
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("api.hpp", api)
        .file("app.cpp", source)
        .build();

    let starts = [
        source.find("map<int").expect("std map terminal"),
        source
            .rfind("error();")
            .expect("qualified error constructor"),
        source.find("item nested_item").expect("nested item"),
        source
            .find("item global_nested_item")
            .expect("global nested item"),
        source.find("nested<long>").expect("nested templated type"),
        source.find("item sibling_item").expect("sibling item"),
    ];
    let value = lookup(
        project.root(),
        &json!({
            "references": starts
                .into_iter()
                .map(|start| location_query("app.cpp", source, start))
                .collect::<Vec<_>>()
        })
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");

    assert!(
        matches!(
            results[0]["status"].as_str(),
            Some("no_definition" | "unresolvable_import_boundary")
        ),
        "{value}"
    );
    assert_eq!(results[1]["status"], "resolved", "{value}");
    assert_eq!(
        results[1]["definitions"][0]["fqn"], "proton.error",
        "{value}"
    );
    assert_eq!(results[1]["definitions"][0]["path"], "api.hpp", "{value}");
    for (result, expected) in results[2..].iter().zip([
        "proton::nested.item",
        "proton::nested.item",
        "proton.outer$nested",
        "sibling.item",
    ]) {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn cpp_qpid_qualified_template_and_macro_class_shapes_resolve_exact_types() {
    let api = r#"
#define PN_CPP_CLASS_EXTERN
namespace std {
template<class K, class T> class map {};
class runtime_error {};
class string {};
}
namespace proton {
template<class K, class T> class map : public std::map<K, T> {
  using std::map<K,T>::map;
};
struct
PN_CPP_CLASS_EXTERN error : public std::runtime_error {
    explicit error(const std::string&);
    ~error() throw();
};
class connection { public: int error() const; };
}
"#;
    let source = r#"
#include "api.hpp"
void stop() { throw proton::error("container is stopping"); }
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("api.hpp", api)
        .file("app.cpp", source)
        .build();
    let using_start = api
        .find("using std::map<K,T>")
        .map(|start| start + "using std::".len())
        .expect("inherited constructor template qualifier");
    let error_start = source
        .find("error(\"")
        .expect("qualified error constructor");
    let value = lookup(
        project.root(),
        &json!({"references": [
            location_query("api.hpp", api, using_start),
            location_query("app.cpp", source, error_start),
        ]})
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(results[0]["definitions"][0]["fqn"], "std.map", "{value}");
    assert_eq!(results[1]["status"], "resolved", "{value}");
    assert_eq!(
        results[1]["definitions"][0]["fqn"], "proton.error",
        "{value}"
    );
    assert_eq!(results[1]["definitions"][0]["kind"], "class", "{value}");
}

#[test]
fn cpp_bare_call_prefers_callable_role_over_same_named_nested_type() {
    let source = r#"
class message {
    struct impl { impl(int); };
    impl& impl() const;
public:
    void body() { impl(); this->impl(); impl(1); }
};
class unrelated { public: void impl(int); };
class widget { public: widget(); };
void local_shadow() { auto impl = []() {}; impl(); }
void construct() { widget(); }
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("app.cpp", source)
        .build();

    let starts = [
        source.find("impl(); this").expect("bare member call"),
        source
            .find("this->impl")
            .map(|start| start + "this->".len())
            .expect("explicit this member call"),
        source.find("impl(1)").expect("wrong-arity member call"),
        source.rfind("impl();").expect("local callable shadow"),
        source.rfind("widget();").expect("constructor control"),
    ];
    let value = lookup_declaration_with_definition_key(
        project.root(),
        &json!({
            "references": starts
                .into_iter()
                .map(|start| location_query("app.cpp", source, start))
                .collect::<Vec<_>>()
        })
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");

    for result in &results[..2] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], "message.impl", "{value}");
        assert_eq!(result["definitions"][0]["kind"], "function", "{value}");
    }
    assert_eq!(results[2]["status"], "no_declaration", "{value}");
    assert_eq!(results[3]["status"], "no_declaration", "{value}");
    assert_eq!(results[4]["status"], "resolved", "{value}");
    assert_eq!(
        results[4]["definitions"][0]["fqn"], "widget.widget",
        "{value}"
    );

    let definition_references = [starts[0], starts[1], starts[4]]
        .into_iter()
        .map(|start| location_query("app.cpp", source, start))
        .collect::<Vec<_>>();
    let definition_value = lookup(
        project.root(),
        &json!({"references": definition_references}).to_string(),
    );
    for result in definition_value["results"]
        .as_array()
        .expect("definition results")
    {
        assert_eq!(result["status"], "no_definition", "{definition_value}");
    }
}

#[test]
fn cpp_out_of_line_bare_member_call_prefers_callable_over_nested_type() {
    let forward = r#"namespace proton { class message; }"#;
    let header = r#"
#define PN_CPP_CLASS_EXTERN
namespace proton {
class
PN_CPP_CLASS_EXTERN message {
    struct impl;
    struct impl& impl() const;
public:
    void body(int);
};
}
"#;
    let source = r#"
#include "fwd.hpp"
#include "message.hpp"
namespace proton {
struct message::impl {};
struct message::impl& message::impl() const { static struct impl value; return value; }
void message::body(int x) { impl(); }
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("fwd.hpp", forward)
        .file("tracing_private.hpp", forward)
        .file("message.hpp", header)
        .file("message.cpp", source)
        .build();
    let start = source
        .rfind("impl();")
        .expect("bare out-of-line member call");
    let value = lookup(
        project.root(),
        &json!({"references": [location_query("message.cpp", source, start)]}).to_string(),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "proton.message.impl",
        "{value}"
    );
    assert_eq!(result["definitions"][0]["kind"], "function", "{value}");
}

#[test]
fn cpp_macro_decorated_out_of_line_owner_prefers_canonical_included_class() {
    let api = r#"
#define API
namespace proton {
class
API endpoint {
public:
    ~endpoint();
    void before();
    void touch();
};
class
API connection : public endpoint { int endpoint; };
class
API link : public endpoint { int endpoint; };
}
"#;
    let unrelated = r#"
#define API
namespace unrelated { class
API endpoint { public: ~endpoint(); void touch(); }; }
"#;
    let shadow = r#"
#define API
namespace proton { class
API endpoint { public: ~endpoint(); void before(); void touch(); }; }
"#;
    let source = r#"
namespace proton { void endpoint::before() {} }
#include "api.hpp"
namespace proton {
endpoint::~endpoint() = default;
void endpoint::touch() {}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("api.hpp", api)
        .file("unrelated.hpp", unrelated)
        .file("shadow.hpp", shadow)
        .file("endpoint.cpp", source)
        .build();

    let starts = [
        source
            .find("endpoint::before")
            .expect("owner before include"),
        source.find("endpoint::~").expect("destructor owner"),
        source
            .find("endpoint::~endpoint")
            .map(|start| start + "endpoint::~".len())
            .expect("terminal destructor type name"),
        source.find("endpoint::touch").expect("method owner"),
    ];
    let value = lookup(
        project.root(),
        &json!({
            "references": starts
                .into_iter()
                .map(|start| location_query("endpoint.cpp", source, start))
                .collect::<Vec<_>>()
        })
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "no_definition", "{value}");
    for result in &results[1..] {
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "proton.endpoint",
            "{value}"
        );
        assert_eq!(result["definitions"][0]["path"], "api.hpp", "{value}");
        assert_eq!(
            result["definitions"].as_array().map(Vec::len),
            Some(1),
            "{value}"
        );
    }
}

#[test]
fn cpp_local_and_self_values_do_not_fall_through_to_workspace_homonyms() {
    let first = r#"
class duplicate {
    int state_;
public:
    duplicate(int value) : state_(value) {}
    void reset() { state_ = 0; }
};
"#;
    let second = r#"
class duplicate {
    int state_;
public:
    duplicate(int value) : state_(value) {}
};
"#;
    let source = r#"
namespace proton { class url {}; }
class sender { public: sender(int, int, int); };
void consume(int);
void accept(proton::url);
void run(int container, int url, int address) {
    sender send(container, url, address);
    consume(url);
    accept(proton::url{});
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("first.cpp", first)
        .file("second.cpp", second)
        .file("app.cpp", source)
        .build();

    let first_starts = [
        first.find("state_(value)").expect("constructor field"),
        first.rfind("state_ =").expect("member write"),
    ];
    let first_value = lookup(
        project.root(),
        &json!({
            "references": first_starts
                .into_iter()
                .map(|start| location_query("first.cpp", first, start))
                .collect::<Vec<_>>()
        })
        .to_string(),
    );
    for result in first_value["results"]
        .as_array()
        .expect("definition results")
    {
        assert_eq!(result["status"], "resolved", "{first_value}");
        assert_eq!(
            result["definitions"][0]["fqn"], "duplicate.state_",
            "{first_value}"
        );
        assert_eq!(
            result["definitions"][0]["path"], "first.cpp",
            "{first_value}"
        );
    }

    let local_starts = [
        source.find("url, address").expect("constructor argument"),
        source.rfind("url);").expect("ordinary local argument"),
        source.rfind("url{}").expect("qualified type construction"),
    ];
    let local_value = lookup(
        project.root(),
        &json!({
            "references": local_starts
                .into_iter()
                .map(|start| location_query("app.cpp", source, start))
                .collect::<Vec<_>>()
        })
        .to_string(),
    );
    let local_results = local_value["results"]
        .as_array()
        .expect("definition results");
    assert_eq!(local_results[0]["status"], "no_definition", "{local_value}");
    assert_eq!(local_results[1]["status"], "resolved", "{local_value}");
    assert_eq!(
        local_results[1]["definitions"][0]["kind"], "parameter",
        "{local_value}"
    );
    assert_eq!(
        local_results[1]["definitions"][0]["path"], "app.cpp",
        "{local_value}"
    );
    assert_eq!(local_results[2]["status"], "resolved", "{local_value}");
    assert_eq!(
        local_results[2]["definitions"][0]["fqn"], "proton.url",
        "{local_value}"
    );
}

#[test]
fn scala_same_package_type_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Service.scala", "package app\nclass Service\n")
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val service: Service = new Service }\n",
        )
        .build();

    let line = "class Controller { val service: Service = new Service }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Service", "{value}");
}

#[test]
fn scala_imported_type_prefers_plain_class_over_companion_object_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("lib/Foo.scala", "package lib\nclass Foo\nobject Foo\n")
        .file(
            "app/Consumer.scala",
            "package app\nimport lib.Foo\nclass Consumer { val value: Foo = new Foo() }\n",
        )
        .build();

    let line = "class Consumer { val value: Foo = new Foo() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Consumer.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "Foo")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "lib.Foo", "{value}");
}

#[test]
fn scala_self_type_resolves_to_same_file_declaration() {
    // chisel's IgnoreSeqInBundle shape (issue #1058): a self-type reference
    // must resolve to a same-file, same-package declaration — not fall
    // through to the import-boundary heuristic.
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Mixins.scala",
            "package app\n\ntrait IgnoreSeqInBundle {\n  this: Bundle =>\n  def ignoreSeq: Boolean = true\n}\n\nabstract class Bundle\n",
        )
        .build();

    let line = "  this: Bundle =>";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Mixins.scala","line":4,"column":{}}}]}}"#,
            column_of(line, "Bundle")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Bundle", "{value}");
}

#[test]
fn scala_self_type_resolves_when_declaration_follows_a_closed_package_block() {
    // chisel Aggregate.scala shape (issue #1058): a closed nested
    // `package experimental { }` block, then a top-level declaration.
    // The declaration belongs to the file's outer package; indexing it
    // under the closed block's package makes every reference to it fail.
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Mixins.scala",
            "package app\n\ntrait IgnoreSeqInBundle {\n  this: Bundle =>\n  def ignoreSeq: Boolean = true\n}\n\npackage experimental {\n  class Foo\n}\n\nabstract class Bundle\n",
        )
        .build();

    let line = "  this: Bundle =>";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Mixins.scala","line":4,"column":{}}}]}}"#,
            column_of(line, "Bundle")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Bundle", "{value}");
}

#[test]
fn scala_self_type_resolves_despite_cross_build_twin_declarations() {
    // The chisel Aggregate.scala layout: identical package/fq names in
    // parallel cross-build source trees.
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "core/src/main/scala/app/Mixins.scala",
            "package app\n\ntrait IgnoreSeqInBundle {\n  this: Bundle =>\n  def ignoreSeq: Boolean = true\n}\n\nabstract class Bundle\n",
        )
        .file(
            "core/src/main/scala-2/app/Mixins.scala",
            "package app\n\ntrait IgnoreSeqInBundle {\n  this: Bundle =>\n  def ignoreSeq: Boolean = true\n}\n\nabstract class Bundle\n",
        )
        .build();

    let line = "  this: Bundle =>";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"core/src/main/scala/app/Mixins.scala","line":4,"column":{}}}]}}"#,
            column_of(line, "Bundle")
        ),
    );

    let result = &value["results"][0];
    // Identical fq names across cross-build trees correctly report
    // ambiguity with both variants offered.
    assert_eq!(result["status"], "ambiguous", "{value}");
    let paths: Vec<&str> = result["definitions"]
        .as_array()
        .expect("definitions")
        .iter()
        .filter_map(|definition| definition["path"].as_str())
        .collect();
    assert_eq!(paths.len(), 2, "{value}");
}

#[test]
fn scala_constructor_call_resolves_to_primary_constructor_identity() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Service.scala",
            "package app\nclass Repository\nclass Service(repository: Repository)\nobject Service {\n  def build(repository: Repository): Service = new Service(repository)\n}\n",
        )
        .build();

    let line = "  def build(repository: Repository): Service = new Service(repository)";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Service.scala","line":5,"column":{}}}]}}"#,
            column_of(line, "Service(repository)")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Service.Service",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "app/Service.scala",
        "{value}"
    );
}

#[test]
fn scala_object_apply_call_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Factory.scala",
            "package app\nclass Service\nobject Factory { def apply(): Service = new Service }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val service = Factory() }\n",
        )
        .build();

    let line = "class Controller { val service = Factory() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Factory")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Factory$.apply",
        "{value}"
    );
}

#[test]
fn scala_bare_calls_do_not_confuse_universal_construction_with_instance_apply_or_object() {
    let source = r#"package app

class FunType(prefix: String) {
  def apply(index: Int): String = prefix
}

final class PcConvertToNamedLambdaParameters(driver: String, params: Int)
object PcConvertToNamedLambdaParameters { val codeActionId = "convert" }

sealed abstract class Chunk[+A] {
  def apply(index: Int): A
}
object Chunk

object Consumer {
  val funType = FunType("Function")
  val conversion = PcConvertToNamedLambdaParameters("driver", 1)
  val header = Chunk("package", "app")
  val options = Chunk("--driver", "local")
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Calls.scala", source)
        .build();
    let references = [
        "FunType(\"Function\")",
        "PcConvertToNamedLambdaParameters(\"driver\", 1)",
        "Chunk(\"package\", \"app\")",
        "Chunk(\"--driver\", \"local\")",
    ]
    .into_iter()
    .map(|needle| {
        let start = source.find(needle).expect("bare call");
        let prefix = &source[..start];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = prefix
            .rsplit_once('\n')
            .map_or(prefix, |(_, current)| current)
            .chars()
            .count()
            + 1;
        format!(r#"{{"path":"app/Calls.scala","line":{line},"column":{column}}}"#)
    })
    .collect::<Vec<_>>()
    .join(",");
    let value = lookup(
        project.root(),
        &format!(r#"{{"references":[{references}]}}"#),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "app.FunType.FunType",
        "{value}"
    );
    assert_eq!(results[1]["status"], "resolved", "{value}");
    assert_eq!(
        results[1]["definitions"][0]["fqn"],
        "app.PcConvertToNamedLambdaParameters.PcConvertToNamedLambdaParameters",
        "{value}"
    );
    for result in &results[2..] {
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "no_applicable_scala_callable",
            "{value}"
        );
    }
}

#[test]
fn scala_uppercase_local_call_shadows_same_package_object_apply() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Factory.scala",
            "package app\nclass Service\nobject Factory { def apply(): Service = new Service }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(): Service = { val Factory = () => new Service; Factory() } }\n",
        )
        .build();

    let line =
        "class Controller { def run(): Service = { val Factory = () => new Service; Factory() } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Factory() }")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_companion_method_call_resolves_from_type_receiver() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Service.scala",
            "package example\nclass Repository\nclass Service(repository: Repository)\nobject Service { def build(repository: Repository): Service = new Service(repository) }\n",
        )
        .file(
            "example/Consumer.scala",
            "package example\nobject Consumer { def run(repository: Repository): Service = Service.build(repository) }\n",
        )
        .build();

    let line =
        "object Consumer { def run(repository: Repository): Service = Service.build(repository) }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"example/Consumer.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "build")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Service$.build",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "example/Service.scala",
        "{value}"
    );
}

#[test]
fn scala_object_apply_call_resolves_from_constructor_like_reference() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Factory.scala",
            "package app\nclass Service\nobject Factory { def apply(): Service = new Service }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val service = Factory() }\n",
        )
        .build();

    let line = "class Controller { val service = Factory() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Factory")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Factory$.apply",
        "{value}"
    );
}

#[test]
fn scala_renamed_member_import_resolves_to_member_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/ConsoleRenderer.scala",
            r#"
package app

class ConsoleRenderer {
  def render(value: String): String = value
}

object ConsoleRenderer {
  def default: ConsoleRenderer = new ConsoleRenderer
}
"#,
        )
        .file(
            "app/App.scala",
            r#"
package app

object App:
  import app.ConsoleRenderer.{default => renderer}
  val direct = renderer.render("ok")
"#,
        )
        .build();

    let app_source = r#"
package app

object App:
  import app.ConsoleRenderer.{default => renderer}
  val direct = renderer.render("ok")
"#;
    let renderer_start = app_source.find("renderer.render").expect("renderer token");
    let value = lookup(
        project.root(),
        &location_reference("app/App.scala", app_source, renderer_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.ConsoleRenderer$.default",
        "{value}"
    );

    let render_start = app_source.find("render(\"ok\")").expect("render token");
    let value = lookup(
        project.root(),
        &location_reference("app/App.scala", app_source, render_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.ConsoleRenderer.render",
        "{value}"
    );
}

#[test]
fn scala_member_import_alias_does_not_shadow_its_own_qualifier() {
    let source = r#"
package app

class Renderer { def render(value: String): String = value }
object Factory { def default: Renderer = new Renderer }

object App:
  import Factory.{default => Factory}
  val direct = Factory.render("ok")
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/App.scala", source)
        .build();

    for (start, expected) in [
        (
            source.rfind("Factory.render").expect("import alias"),
            "app.Factory$.default",
        ),
        (
            source.rfind("render(\"ok\")").expect("receiver member"),
            "app.Renderer.render",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("app/App.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_imported_factory_return_type_uses_factory_scope() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "api/Renderer.scala",
            r#"
package api

class Renderer {
  def render(value: String): String = value
}
"#,
        )
        .file(
            "app/Renderer.scala",
            r#"
package app

class Renderer {
  def render(value: String): String = value.trim
}

object Factory {
  def default: Renderer = new Renderer
}
"#,
        )
        .file(
            "app/App.scala",
            r#"
package app

object App:
  import Factory.{default => renderer}
  val direct = renderer.render("ok")
"#,
        )
        .build();

    let app_source = r#"
package app

object App:
  import Factory.{default => renderer}
  val direct = renderer.render("ok")
"#;
    let render_start = app_source.find("render(\"ok\")").expect("render token");
    let value = lookup(
        project.root(),
        &location_reference("app/App.scala", app_source, render_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Renderer.render",
        "{value}"
    );
}

#[test]
fn scala_receiver_binding_seed_is_bounded_across_repeated_companion_factories() {
    let mut source = String::from(
        r#"
package app

class Symbol {
  def entered: Symbol = this
}

object Routes {
  def make(): Symbol = new Symbol
}

object Definitions {
  def newCompleteClassSymbol(): Symbol = new Symbol
"#,
    );
    for index in 0..64 {
        source.push_str(&format!("  val route{index} = Routes.make()\n"));
    }
    source.push_str(
        r#"  val cls = newCompleteClassSymbol()
  val selected = cls.entered
}
"#,
    );

    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Definitions.scala", source.clone())
        .build();
    let entered_start = source.find("cls.entered").expect("member selection") + "cls.".len();
    let started = std::time::Instant::now();
    let value = lookup(
        project.root(),
        &location_reference("app/Definitions.scala", &source, entered_start),
    );

    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "Scala receiver binding reconstruction exceeded its bounded regression budget: {value}"
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Symbol.entered",
        "{value}"
    );
}

#[test]
fn scala_factory_result_binding_shadows_visible_singleton_receiver() {
    let source = r#"
package app

class Symbol {
  def entered: Int = 1
}

object Factory {
  def entered: String = "singleton"
}

object Definitions {
  def build(): Symbol = new Symbol
  def run(): Int = {
    val Factory = build()
    Factory.entered
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Definitions.scala", source)
        .build();
    let entered_start =
        source.find("Factory.entered").expect("member selection") + "Factory.".len();
    let value = lookup(
        project.root(),
        &location_reference("app/Definitions.scala", source, entered_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Symbol.entered",
        "{value}"
    );
}

#[test]
fn scala_extension_method_call_resolves_to_extension_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Syntax.scala",
            r#"
package app

object Syntax:
  extension (value: String)
    def slug: String = value.toLowerCase
"#,
        )
        .file(
            "app/App.scala",
            r#"
package app

object App:
  import app.Syntax.*
  val slugged = "Hello World".slug
"#,
        )
        .build();

    let app_source = r#"
package app

object App:
  import app.Syntax.*
  val slugged = "Hello World".slug
"#;
    let slug_start = app_source.find(".slug").expect("slug token") + 1;
    let value = lookup(
        project.root(),
        &location_reference("app/App.scala", app_source, slug_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Syntax$.slug",
        "{value}"
    );
}

#[test]
fn scala_relative_wildcard_extension_method_call_resolves_to_extension_definition() {
    let source = r#"
package example

object Syntax:
  extension (value: String)
    def slug: String =
      value.toLowerCase.replace(" ", "-")

object App:
  import Syntax.*
  val slugged = "Hello World".slug
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("src/main/scala/example/Workflow.scala", source)
        .build();

    let slug_start = source.find(".slug").expect("slug token") + 1;
    let value = lookup(
        project.root(),
        &location_reference("src/main/scala/example/Workflow.scala", source, slug_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Syntax$.slug",
        "{value}"
    );
}

#[test]
fn scala_direct_member_beats_visible_extension_method() {
    let source = r#"
package app

final case class User(slug: String)

object Syntax:
  extension (u: User)
    def slug: String = "extension"

object Workflow:
  import Syntax.*
  def run(u: User): String = u.slug
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Workflow.scala", source)
        .build();

    let slug_start = source.find("u.slug").expect("slug call") + "u.".len();
    let value = lookup(
        project.root(),
        &location_reference("app/Workflow.scala", source, slug_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.User.slug", "{value}");
}

#[test]
fn scala_extension_receiver_type_mismatch_returns_no_definition() {
    let source = r#"
package app

object Syntax:
  extension (s: String)
    def slug: String = s.toLowerCase

object Workflow:
  import Syntax.*
  def run(i: Int): String = i.slug
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Workflow.scala", source)
        .build();

    let slug_start = source.find("i.slug").expect("slug call") + "i.".len();
    let value = lookup(
        project.root(),
        &location_reference("app/Workflow.scala", source, slug_start),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_extension_receiver_type_resolves_in_extension_declaration_context() {
    let syntax_source = r#"
package ext

final case class User(name: String)

object Syntax:
  extension (u: User)
    def slug: String = u.name.toLowerCase
"#;
    let app_source = r#"
package app

final case class User(name: String)

object Workflow:
  import ext.Syntax.*
  def run(u: User): String = u.slug
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("ext/Syntax.scala", syntax_source)
        .file("app/Workflow.scala", app_source)
        .build();

    let slug_start = app_source.find("u.slug").expect("slug call") + "u.".len();
    let value = lookup(
        project.root(),
        &location_reference("app/Workflow.scala", app_source, slug_start),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_extension_call_wins_when_direct_member_arity_does_not_apply() {
    let source = r#"
package app

final case class User(name: String):
  def slug(): String = name

object Syntax:
  extension (u: User)
    def slug(i: Int): String = u.name + i.toString

object Workflow:
  import Syntax.*
  def run(u: User): String = u.slug(1)
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Workflow.scala", source)
        .build();

    let slug_start = source.find("u.slug").expect("slug call") + "u.".len();
    let value = lookup(
        project.root(),
        &location_reference("app/Workflow.scala", source, slug_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Syntax$.slug",
        "{value}"
    );
}

#[test]
fn scala_ambiguous_extension_methods_return_candidate_definitions() {
    let source = r#"
package app

object SyntaxA:
  extension (s: String)
    def slug: String = s.toLowerCase

object SyntaxB:
  extension (s: String)
    def slug: String = s.reverse

object Workflow:
  import SyntaxA.*
  import SyntaxB.*
  def run(s: String): String = s.slug
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Workflow.scala", source)
        .build();

    let slug_start = source.find("s.slug").expect("slug call") + "s.".len();
    let value = lookup(
        project.root(),
        &location_reference("app/Workflow.scala", source, slug_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "ambiguous", "{value}");
    let definitions = result["definitions"].as_array().expect("definitions array");
    let fqns: Vec<_> = definitions
        .iter()
        .map(|definition| definition["fqn"].as_str().expect("definition fqn"))
        .collect();
    assert!(fqns.contains(&"app.SyntaxA$.slug"), "{value}");
    assert!(fqns.contains(&"app.SyntaxB$.slug"), "{value}");
    assert!(
        definitions.iter().all(|definition| definition["signature"]
            .as_str()
            .is_some_and(|signature| signature.starts_with("extension (s: String) def slug"))),
        "{value}"
    );
}

#[test]
fn scala_unqualified_inherited_helper_call_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "api/RestHelper.scala",
            "package api\ntrait RestHelper { protected def collectResourceDocs(values: Seq[Int]): Seq[Int] = values }\n",
        )
        .file(
            "api/v2/Api.scala",
            r#"
package api.v2

import api.RestHelper

object Api extends RestHelper {
  def allResourceDocs: Seq[Int] = collectResourceDocs(Seq(1))
}
"#,
        )
        .build();

    let line = "  def allResourceDocs: Seq[Int] = collectResourceDocs(Seq(1))";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"api/v2/Api.scala","line":7,"column":{}}}]}}"#,
            column_of(line, "collectResourceDocs")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "api.RestHelper.collectResourceDocs",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "api/RestHelper.scala",
        "{value}"
    );
}

#[test]
fn scala_trait_default_method_resolves_through_concrete_receiver() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\ntrait Logging { def info(msg: String): Unit = () }\nclass Service extends Logging\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(service: Service): Unit = service.info(\"started\") }\n",
        )
        .build();

    let line = "class Controller { def run(service: Service): Unit = service.info(\"started\") }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "info")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Logging.info",
        "{value}"
    );
}

#[test]
fn scala_trait_val_resolves_through_concrete_receiver() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\ntrait Identified { val id: String = \"x\" }\nclass Service extends Identified\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(service: Service): String = service.id }\n",
        )
        .build();

    let line = "class Controller { def run(service: Service): String = service.id }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "id")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Identified.id",
        "{value}"
    );
}

#[test]
fn scala_trait_method_override_prefers_concrete_receiver_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\ntrait Logging { def info(msg: String): Unit = () }\nclass Service extends Logging { override def info(msg: String): Unit = () }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(service: Service): Unit = service.info(\"started\") }\n",
        )
        .build();

    let line = "class Controller { def run(service: Service): Unit = service.info(\"started\") }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "info")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Service.info",
        "{value}"
    );
}

#[test]
fn scala_trait_method_overridden_by_val_prefers_concrete_receiver_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\ntrait Identified { def id: String = \"base\" }\nclass Service extends Identified { override val id: String = \"service\" }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(service: Service): String = service.id }\n",
        )
        .build();

    let line = "class Controller { def run(service: Service): String = service.id }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "id")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Service.id", "{value}");
}

#[test]
fn scala_instance_member_prefers_inherited_member_over_companion_object() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nclass Base { def value: Int = 1 }\nclass Child extends Base\nobject Child { def value: Int = 2 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(child: Child): Int = child.value }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Base.value", "{value}");
}

#[test]
fn scala_source_ancestor_fallback_uses_matching_owner_not_first_simple_name() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            r#"
package app

class Wrong
object Outer {
  class Child extends Wrong
}
class Base { def value: Int = 1 }
class Child extends Base
"#,
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(child: Child): Int = child.value }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Base.value", "{value}");
}

#[test]
fn scala_imported_type_annotation_beats_same_package_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nclass Child { def local: Int = 0 }\n",
        )
        .file(
            "other/Model.scala",
            "package other\nclass Child { def value: Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nimport other.Child\nclass Controller { def run(child: Child): Int = child.value }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "other.Child.value",
        "{value}"
    );
}

#[test]
fn scala_missing_imported_type_annotation_does_not_fall_back_to_same_package_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nclass Child { def local: Int = 0 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nimport external.Child\nclass Controller { def run(child: Child): Int = child.local }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.local }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "local")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_ambiguous_wildcard_type_does_not_fall_back_to_same_package_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nclass Child { def local: Int = 0 }\n",
        )
        .file(
            "one/Model.scala",
            "package one\nclass Child { def first: Int = 1 }\n",
        )
        .file(
            "two/Model.scala",
            "package two\nclass Child { def second: Int = 2 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nimport one.*\nimport two.*\nclass Controller { def run(child: Child): Int = child.local }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.local }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":4,"column":{}}}]}}"#,
            column_of(line, "local")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_qualified_nested_supertype_preserves_the_complete_lookup_path() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            "package app\nobject Outer { trait Base { def value: Int = 1 } }\nclass Child extends Outer.Base\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(child: Child): Int = child.value }\n",
        )
        .build();

    let line = "class Controller { def run(child: Child): Int = child.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Outer$.Base.value",
        "{value}"
    );
}

#[test]
fn scala_nested_class_ancestor_does_not_leak_to_outer_owner() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            r#"
package app

class Base { def value: Int = 1 }
class Outer {
  class Inner extends Base
}
"#,
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def run(outer: Outer): Int = outer.value }\n",
        )
        .build();

    let line = "class Controller { def run(outer: Outer): Int = outer.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_unqualified_member_call_beats_same_named_object_apply() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Factory.scala",
            "package app\nclass Service\nobject Factory { def apply(): Service = new Service }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def Factory(): Int = 1; def run(): Int = Factory() }\n",
        )
        .build();

    let line = "class Controller { def Factory(): Int = 1; def run(): Int = Factory() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Factory() }")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Controller.Factory",
        "{value}"
    );
}

#[test]
fn scala_typed_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Service.scala",
            "package app\nclass Service { def run(): Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def handle(service: Service): Int = service.run() }\n",
        )
        .build();

    let line = "class Controller { def handle(service: Service): Int = service.run() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "run")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Service.run",
        "{value}"
    );
}

#[test]
fn scala_postfix_operator_method_resolves_to_definition() {
    let controller = "package app\nclass Controller { def handle(box: Box): Boolean = box ! }\n";
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Box.scala",
            "package app\nclass Box { def ! : Boolean = true }\n",
        )
        .file("app/Controller.scala", controller)
        .build();

    let start = controller.find('!').expect("operator");
    let value = lookup(
        project.root(),
        &location_reference("app/Controller.scala", controller, start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Box.!", "{value}");
}

#[test]
fn scala_generic_and_curried_member_calls_resolve_to_definitions() {
    let source = r#"
package app

class Service {
  def generic[A](value: Int): Int = value
  def curried(value: Int)(label: String): Int = value
}

object Controller {
  def run(service: Service): Int =
    service.generic[String](1) + service.curried(2)("two")
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Calls.scala", source)
        .build();

    for (needle, expected) in [
        ("generic[String]", "app.Service.generic"),
        ("curried(2)", "app.Service.curried"),
    ] {
        let start = source.find(needle).expect("Scala call");
        let value = lookup(
            project.root(),
            &location_reference("app/Calls.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_unapplied_generic_function_resolves_to_definition() {
    let source = r#"
package app

object GenericRefs {
  def generic[A](value: A): A = value
  val reference = generic[Int]
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/GenericRefs.scala", source)
        .build();
    let start = source.rfind("generic[Int]").expect("generic reference");
    let value = lookup(
        project.root(),
        &location_reference("app/GenericRefs.scala", source, start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.GenericRefs$.generic",
        "{value}"
    );
}

#[test]
fn scala_wrapped_type_references_resolve_structured_targets() {
    let source = r#"
package app

class Target
class Parent(value: Int)
class Child extends Parent(1)
class Outer { class Inner }
class Uses {
  val annotated: Target @unchecked = ???
  val projected: Outer#Inner = ???
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/WrappedTypes.scala", source)
        .build();

    for (start, expected) in [
        (
            source.find("Target @unchecked").expect("annotated type"),
            "app.Target",
        ),
        (
            source.find("Parent(1)").expect("applied constructor type"),
            "app.Parent",
        ),
        (
            source.find("Outer#Inner").expect("projected type") + "Outer#".len(),
            "app.Outer.Inner",
        ),
    ] {
        let value = lookup(
            project.root(),
            &location_reference("app/WrappedTypes.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_trailing_block_argument_forms_have_one_top_level_argument() {
    let source = r#"
package app

class Service {
  def braced(value: => Int): Int = value
  def partial(value: PartialFunction[Int, Int]): Int = 1
  def colon(value: => Int): Int = value
  def first(): Int = 1
  def second(): Int = 2

  def run(): Int = {
    val a = braced { first(); second() }
    val b = partial { case 0 => 0; case other => other }
    val c = colon:
      first()
      second()
    a + b + c
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/BlockArguments.scala", source)
        .build();

    for (needle, expected) in [
        ("braced {", "app.Service.braced"),
        ("partial {", "app.Service.partial"),
        ("colon:", "app.Service.colon"),
    ] {
        let start = source.rfind(needle).expect("block argument call");
        let value = lookup(
            project.root(),
            &location_reference("app/BlockArguments.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_direct_application_chain_rejects_more_lists_than_the_declaration() {
    let source = r#"
package app

class Service {
  def single(value: Int): Int = value
}

object Controller {
  def run(service: Service): Int = service.single(1)("extra")
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Calls.scala", source)
        .build();
    let start = source.find("single(1)").expect("Scala call");
    let value = lookup(
        project.root(),
        &location_reference("app/Calls.scala", source, start),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_generic_and_curried_new_calls_resolve_to_primary_constructors() {
    let source = r#"
package app

class Box[A](value: Int)
class Curried(value: Int)(label: String)

object Controller {
  val box = new Box[String](1)
  val curried = new Curried(2)("two")
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Constructors.scala", source)
        .build();

    for (needle, expected) in [
        ("Box[String]", "app.Box.Box"),
        ("Curried(2)", "app.Curried.Curried"),
    ] {
        let start = source.find(needle).expect("Scala constructor");
        let value = lookup(
            project.root(),
            &location_reference("app/Constructors.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }
}

#[test]
fn scala_constructor_application_chain_rejects_extra_argument_lists() {
    let source = r#"
package app

class Single(value: Int)

object Controller {
  val invalid = new Single(1)("extra")
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/InvalidConstructor.scala", source)
        .build();
    let start = source.find("Single(1)").expect("Scala constructor call");
    let value = lookup(
        project.root(),
        &location_reference("app/InvalidConstructor.scala", source, start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "scala_constructor_arity_mismatch",
        "{value}"
    );
}

#[test]
fn scala_parameterless_primary_and_secondary_constructors_share_valid_shapes() {
    let source = r#"
package app

class Multi {
  def this(value: Int) = this()
}
class MethodOnly {
  def MethodOnly(value: Int): Int = value
}

object Controller {
  val zero = new Multi
  val one = new Multi(1)
  val ordinary = new MethodOnly
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/ConstructorAlternatives.scala", source)
        .build();

    for (needle, expected) in [
        ("new Multi\n", "app.Multi"),
        ("new Multi(1)", "app.Multi.Multi"),
    ] {
        let start = source.find(needle).expect("constructor call") + "new ".len();
        let value = lookup(
            project.root(),
            &location_reference("app/ConstructorAlternatives.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }

    let start = source
        .find("new MethodOnly")
        .expect("ordinary method owner")
        + "new ".len();
    let value = lookup(
        project.root(),
        &location_reference("app/ConstructorAlternatives.scala", source, start),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.MethodOnly", "{value}");
}

#[test]
fn scala_infix_dispatch_uses_left_receiver_for_ordinary_operators() {
    let source = r#"
package app

class Right
class Left {
  def combine(right: Right): Int = 1
}

object Controller {
  def run(left: Left, right: Right): Int = left combine right
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Infix.scala", source)
        .build();
    let start = source.rfind("combine").expect("infix call");
    let value = lookup(
        project.root(),
        &location_reference("app/Infix.scala", source, start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Left.combine",
        "{value}"
    );
}

#[test]
fn scala_colon_infix_dispatch_uses_the_right_receiver() {
    let source = r#"
package app

class Head {
  def ::(tail: Tail): Int = 1
}
class Tail {
  def ::(head: Head): Int = 2
}

object Controller {
  def run(head: Head, tail: Tail): Int = head :: tail
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Colon.scala", source)
        .build();
    let start = source.rfind("::").expect("right-associative infix call");
    let value = lookup(
        project.root(),
        &location_reference("app/Colon.scala", source, start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Tail.::", "{value}");
}

#[test]
fn scala_compound_infix_dispatch_fails_closed_without_precedence_reconstruction() {
    let source = r#"
package app

class A { def +(right: B): A = this }
class B { def *(right: C): B = this }
class C

object Controller {
  def run(a: A, b: B, c: C) = a + b * c
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Compound.scala", source)
        .build();
    let start = source.rfind('*').expect("compound infix call");
    let value = lookup(
        project.root(),
        &location_reference("app/Compound.scala", source, start),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert!(
        value["results"][0]["diagnostics"][0]["message"]
            .as_str()
            .is_some_and(|message| message.contains("precedence-aware receiver reconstruction")),
        "{value}"
    );
}

#[test]
fn scala_service_execute_receiver_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Service.scala",
            "package app\nclass Service { def execute(): Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def handle(service: Service): Int = service.execute() }\n",
        )
        .build();

    let line = "class Controller { def handle(service: Service): Int = service.execute() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "execute")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Service.execute",
        "{value}"
    );
}

#[test]
fn scala_factory_returned_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Service.scala",
            r#"
package example

class Repository

class Service(repository: Repository) {
  def execute(name: String): String = name.trim
}

object Service {
  def build(repository: Repository): Service = new Service(repository)
}
"#,
        )
        .file(
            "example/Consumer.scala",
            r#"
package example

object Consumer {
  def run(): String = {
    val repository = new Repository()
    val service = Service.build(repository)
    service.execute(" Ada ")
  }
}
"#,
        )
        .build();

    let line = r#"    service.execute(" Ada ")"#;
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"example/Consumer.scala","line":8,"column":{}}}]}}"#,
            column_of(line, "execute")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Service.execute",
        "{value}"
    );
}

#[test]
fn scala_generic_constructor_receiver_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Scoreboard.scala",
            "package app\nclass ScoreboardInOrder[T] { def checkEmptiness(): Unit = {} }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { def handle(): Unit = { val sco = ScoreboardInOrder[String](); sco.checkEmptiness() } }\n",
        )
        .build();

    let line = "class Controller { def handle(): Unit = { val sco = ScoreboardInOrder[String](); sco.checkEmptiness() } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "checkEmptiness")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.ScoreboardInOrder.checkEmptiness",
        "{value}"
    );
}

#[test]
fn scala_constructor_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Context.scala",
            "package app\nclass Registry\nclass Context(val registry: Registry)\n",
        )
        .file(
            "app/Grouped.scala",
            "package app\nclass Grouped(context: Context) { val value = context.registry }\n",
        )
        .build();

    let line = "class Grouped(context: Context) { val value = context.registry }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Grouped.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Context.registry",
        "{value}"
    );
}

#[test]
fn scala_unqualified_owner_field_read_after_write_resolves_to_definition() {
    let service_source = r#"
package example

class Repository {
  var last: String = ""

  def save(value: String): String = {
    last = value.trim
    last
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("example/Service.scala", service_source)
        .build();
    let read_start = service_source
        .find("    last\n")
        .expect("unqualified field read")
        + "    ".len();
    let value = lookup(
        project.root(),
        &location_reference("example/Service.scala", service_source, read_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.Repository.last",
        "{value}"
    );
}

#[test]
fn scala_unqualified_owner_method_call_resolves_to_definition() {
    let source = r#"
package example

object App {
  def target(value: Int): Int = value
  val result = target(1)
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("example/App.scala", source)
        .build();
    let call_start = source.find("target(1)").expect("unqualified method call");
    let value = lookup(
        project.root(),
        &location_reference("example/App.scala", source, call_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "example.App$.target",
        "{value}"
    );
}

#[test]
fn scala_local_receiver_shadows_constructor_parameter_fallback() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Context.scala",
            "package app\nclass Registry\nclass Context(val registry: Registry)\n",
        )
        .file(
            "app/Grouped.scala",
            "package app\nclass Grouped(context: Context) { def run(): Any = { val context = null; context.registry } }\n",
        )
        .build();

    let line = "class Grouped(context: Context) { def run(): Any = { val context = null; context.registry } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Grouped.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_modified_case_class_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Context.scala",
            "package app\nclass Registry\nfinal case class Context(registry: Registry)\n",
        )
        .file(
            "app/Grouped.scala",
            "package app\nclass Grouped(context: Context) { val value = context.registry }\n",
        )
        .build();

    let line = "class Grouped(context: Context) { val value = context.registry }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Grouped.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Context.registry",
        "{value}"
    );
}

#[test]
fn scala_multiline_private_constructor_parameter_field_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/StreamContext.scala",
            "package app\nclass Registry\nprivate[app] class StreamContext(\n  val registry: Registry\n)\n",
        )
        .file(
            "app/TimeGrouped.scala",
            "package app\nprivate[app] class TimeGrouped(\n  context: StreamContext,\n  host: String\n) {\n  val value = context.registry\n}\n",
        )
        .build();

    let line = "  val value = context.registry";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/TimeGrouped.scala","line":6,"column":{}}}]}}"#,
            column_of(line, "registry")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.StreamContext.registry",
        "{value}"
    );
}

#[test]
fn scala_object_receiver_method_resolves_to_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/DataSources.scala",
            "package app\nclass DataSource\nobject DataSources { def of(source: DataSource): Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val value = DataSources.of(new DataSource) }\n",
        )
        .build();

    let line = "class Controller { val value = DataSources.of(new DataSource) }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "of")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.DataSources$.of",
        "{value}"
    );
}

#[test]
fn scala_singleton_typed_receiver_method_prefers_object_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Settings.scala",
            "package app\nclass Settings { def value: Int = 0 }\nobject Settings { def value: Int = 1 }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nclass Controller { val settings: Settings.type = Settings; val actual = settings.value }\n",
        )
        .build();

    let line =
        "class Controller { val settings: Settings.type = Settings; val actual = settings.value }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Settings$.value",
        "{value}"
    );
}

#[test]
fn scala_stable_identifier_object_val_resolves_in_case_pattern() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "common/ApiVersion.scala",
            "package common\ntrait ApiVersion\nobject ApiVersion { val v2_1_0 = new ApiVersion {} }\n",
        )
        .file(
            "app/Controller.scala",
            "package app\nimport common.ApiVersion\nclass Controller { def docs(version: ApiVersion): Int = version match { case ApiVersion.v2_1_0 => 1; case _ => 0 } }\n",
        )
        .build();

    let line = "class Controller { def docs(version: ApiVersion): Int = version match { case ApiVersion.v2_1_0 => 1; case _ => 0 } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "v2_1_0")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "common.ApiVersion$.v2_1_0",
        "{value}"
    );
}

#[test]
fn scala_stable_identifier_pattern_prefers_nested_object_term_over_same_named_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "lib/Maybe.scala",
            "package lib\nsealed trait Maybe\nobject Maybe { sealed abstract class Absent; case object Absent extends Absent }\n",
        )
        .file(
            "app/Consumer.scala",
            "package app\nimport lib.Maybe\nobject Consumer { def empty(value: Maybe): Boolean = value match { case Maybe.Absent => true; case _ => false } }\nobject QualifiedConsumer { def empty(value: Maybe): Boolean = value match { case lib.Maybe.Absent => true; case _ => false } }\nobject TypeConsumer { val absent: Maybe.Absent = ??? }\n",
        )
        .file(
            "app/Decoy.scala",
            "package app\nobject Maybe { sealed abstract class Absent; case object Absent extends Absent }\n",
        )
        .build();

    let line = "object Consumer { def empty(value: Maybe): Boolean = value match { case Maybe.Absent => true; case _ => false } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Consumer.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "Absent")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "lib.Maybe$.Absent$",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "lib/Maybe.scala",
        "{value}"
    );

    let qualified_line = "object QualifiedConsumer { def empty(value: Maybe): Boolean = value match { case lib.Maybe.Absent => true; case _ => false } }";
    let qualified_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Consumer.scala","line":4,"column":{}}}]}}"#,
            column_of(qualified_line, "Absent")
        ),
    );
    assert_eq!(
        qualified_value["results"][0]["definitions"][0]["fqn"], "lib.Maybe$.Absent$",
        "{qualified_value}"
    );

    let type_line = "object TypeConsumer { val absent: Maybe.Absent = ??? }";
    let type_value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Consumer.scala","line":5,"column":{}}}]}}"#,
            column_of(type_line, "Absent")
        ),
    );
    assert_eq!(
        type_value["results"][0]["status"], "resolved",
        "{type_value}"
    );
    assert_eq!(
        type_value["results"][0]["definitions"][0]["fqn"], "lib.Maybe$.Absent",
        "{type_value}"
    );
}

#[test]
fn scala_stable_identifier_pattern_honors_package_and_local_term_owners() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Definitions.scala",
            "package app\nsealed trait State\nobject State { sealed abstract class Empty; case object Empty extends Empty }\nclass LocalMaybe { val Absent: Int = 1 }\nobject Maybe { case object Absent }\n",
        )
        .file(
            "app/Consumer.scala",
            "package app\nobject Consumer {\n  def packageTerm(value: State): Boolean = value match { case State.Empty => true; case _ => false }\n  def localTerm(Maybe: LocalMaybe, value: Int): Boolean = value match { case Maybe.Absent => true; case _ => false }\n}\n",
        )
        .build();

    let package_line = "  def packageTerm(value: State): Boolean = value match { case State.Empty => true; case _ => false }";
    let local_line = "  def localTerm(Maybe: LocalMaybe, value: Int): Boolean = value match { case Maybe.Absent => true; case _ => false }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Consumer.scala","line":3,"column":{}}},{{"path":"app/Consumer.scala","line":4,"column":{}}}]}}"#,
            column_of(package_line, "Empty"),
            column_of(local_line, "Absent")
        ),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "app.State$.Empty$",
        "{value}"
    );
    assert_eq!(results[1]["status"], "resolved", "{value}");
    assert_eq!(
        results[1]["definitions"][0]["fqn"], "app.LocalMaybe.Absent",
        "{value}"
    );
}

#[test]
fn scala_external_import_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Controller.scala",
            "package app\nimport external.Service\nclass Controller { val service: Service = ??? }\n",
        )
        .build();

    let line = "class Controller { val service: Service = ??? }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn scala_external_constructor_call_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Controller.scala",
            "package app\nimport external.Service\nclass Controller { val service = Service() }\n",
        )
        .build();

    let line = "class Controller { val service = Service() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "Service")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn scala_external_imported_function_call_reports_boundary() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Controller.scala",
            "package app\nimport external.Helpers.make\nclass Controller { val service = make() }\n",
        )
        .build();

    let line = "class Controller { val service = make() }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/Controller.scala","line":3,"column":{}}}]}}"#,
            column_of(line, "make")
        ),
    );

    assert_eq!(
        value["results"][0]["status"], "unresolvable_import_boundary",
        "{value}"
    );
}

#[test]
fn scala_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "App.scala",
            "object App { def run(): Int = { val value = 1; value } }\n",
        )
        .build();

    let line = "object App { def run(): Int = { val value = 1; value } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"App.scala","line":1,"column":{}}}]}}"#,
            column_of(line, "value }")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("definition diagnostic");
    assert!(
        message.contains("Requested location: App.scala:1:"),
        "{message}"
    );
    assert!(message.contains("> 1 | object App"), "{message}");
    assert!(message.contains("^ requested line 1, column"), "{message}");
    assert!(
        message.contains("retry get_definitions_by_location"),
        "{message}"
    );
}

#[test]
fn scala_uppercase_local_value_shadows_workspace_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Service.scala", "package app\nclass Service\n")
        .file(
            "app/App.scala",
            "package app\nobject App { def run(): Int = { val Service = 1; Service } }\n",
        )
        .build();

    let line = "object App { def run(): Int = { val Service = 1; Service } }";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app/App.scala","line":2,"column":{}}}]}}"#,
            column_of(line, "Service }")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_staticmethod_first_parameter_does_not_create_instance_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    @staticmethod
    def configure(obj):
        obj.shadow = 1

    def run(self):
        return self.shadow
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "Service.run",
                "context": "return self.shadow",
                "target": "shadow"
            }]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn python_classmethod_first_parameter_does_not_create_instance_field() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            r#"
class Service:
    @classmethod
    def configure(cls):
        cls.shadow = 1

    def run(self):
        return self.shadow
"#,
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "Service.run",
                "context": "return self.shadow",
                "target": "shadow"
            }]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn valid_local_value_returns_no_definition() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "app.ts",
            r#"
export function run() {
  const value = 1;
  value;
}
"#,
        )
        .build();

    let line = "  value;";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"app.ts","line":4,"column":{}}}]}}"#,
            column_of(line, "value")
        ),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn unsupported_language_returns_structured_status() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("notes.txt", "helper\n")
        .build();

    let value = lookup(
        project.root(),
        r#"{"references":[{"path":"notes.txt","line":1,"column":1}]}"#,
    );

    assert_eq!(
        value["results"][0]["status"], "unsupported_language",
        "{value}"
    );
    assert!(value["results"][0]["reference"].is_null(), "{value}");
}

#[test]
fn php_bare_function_does_not_resolve_same_named_javascript_declaration() {
    let project = InlineTestProject::new()
        .file("builtin.php", "<?php\n$result = count($items);\n")
        .file(
            "helper.js",
            "function count(items) { return items.length; }\n",
        )
        .build();
    let line = "$result = count($items);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"builtin.php","line":2,"column":{}}}]}}"#,
            column_of(line, "count")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    assert!(result["definitions"].is_null(), "{value}");
}

#[test]
fn php_bare_function_prefers_same_language_declaration_over_javascript_collision() {
    let project = InlineTestProject::new()
        .file("api.php", "<?php\nfunction count($items) { return 1; }\n")
        .file("use.php", "<?php\n$result = count($items);\n")
        .file(
            "helper.js",
            "function count(items) { return items.length; }\n",
        )
        .build();
    let line = "$result = count($items);";
    let value = lookup(
        project.root(),
        &format!(
            r#"{{"references":[{{"path":"use.php","line":2,"column":{}}}]}}"#,
            column_of(line, "count")
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"].as_array().unwrap().len(),
        1,
        "{value}"
    );
    assert_eq!(result["definitions"][0]["language"], "php", "{value}");
    assert_eq!(result["definitions"][0]["path"], "api.php", "{value}");
}

#[test]
fn scala_type_reference_keeps_supported_java_definition_resolution() {
    let source = concat!(
        "package app\n",
        "object Use { ",
        "val explicit = new Greeter(1); ",
        "val wrongExplicit = new Greeter(); ",
        "val implicitZero = new ImplicitGreeter(); ",
        "val wrongImplicit = new ImplicitGreeter(1); ",
        "val sameNamedMethod = new MethodOnly(); ",
        "val wrongSameNamedMethod = new MethodOnly(1); ",
        "val record = new Pair(1, 2); ",
        "val auxiliaryRecord = new Pair(1); ",
        "val wrongRecord = new Pair(); ",
        "val emptyVarargsRecord = new Batch(\"p\"); ",
        "val populatedVarargsRecord = new Batch(\"p\", \"a\", \"b\"); ",
        "val wrongVarargsRecord = new Batch(); ",
        "val compactRecord = new Compact(1); ",
        "val wrongCompactRecord = new Compact() ",
        "}\n",
    );
    let project = InlineTestProject::new()
        .file(
            "app/Greeter.java",
            "package app; public class Greeter { public Greeter(int value) {} }\n",
        )
        .file(
            "app/ImplicitGreeter.java",
            "package app; public class ImplicitGreeter {}\n",
        )
        .file(
            "app/MethodOnly.java",
            "package app; public class MethodOnly { public void MethodOnly(int value) {} }\n",
        )
        .file(
            "app/Pair.java",
            "package app; public record Pair(int left, int right) { public Pair(int left) { this(left, 0); } }\n",
        )
        .file(
            "app/Batch.java",
            "package app; public record Batch(String prefix, String... values) {}\n",
        )
        .file(
            "app/Compact.java",
            "package app; public record Compact(int value) { public Compact { if (value < 0) throw new IllegalArgumentException(); } }\n",
        )
        .file("app/Use.scala", source)
        .build();

    for (needle, expected) in [
        ("new Greeter(1)", "app.Greeter.Greeter"),
        ("new ImplicitGreeter()", "app.ImplicitGreeter"),
        ("new MethodOnly()", "app.MethodOnly"),
        ("new Pair(1, 2)", "app.Pair"),
        ("new Pair(1)", "app.Pair.Pair"),
        ("new Batch(\"p\")", "app.Batch"),
        ("new Batch(\"p\", \"a\", \"b\")", "app.Batch"),
        ("new Compact(1)", "app.Compact.Compact"),
    ] {
        let start = source.find(needle).expect("valid Java construction") + "new ".len();
        let value = lookup(
            project.root(),
            &location_reference("app/Use.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "resolved", "{value}");
        assert_eq!(result["definitions"][0]["language"], "java", "{value}");
        assert_eq!(result["definitions"][0]["fqn"], expected, "{value}");
    }

    for needle in [
        "new Greeter()",
        "new ImplicitGreeter(1)",
        "new MethodOnly(1)",
        "new Pair()",
        "new Batch()",
        "new Compact()",
    ] {
        let start = source.find(needle).expect("invalid Java construction") + "new ".len();
        let value = lookup(
            project.root(),
            &location_reference("app/Use.scala", source, start),
        );
        let result = &value["results"][0];
        assert_eq!(result["status"], "no_definition", "{value}");
        assert_eq!(
            result["diagnostics"][0]["kind"], "no_applicable_scala_constructor",
            "{value}"
        );
    }
}

#[test]
fn php_reference_context_resolves_static_qualifier_to_class() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Types.php",
            "<?php\nnamespace App;\nclass Types { public const JSON = 'json'; }\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller { public function handle(): string { return Types::JSON; } }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "App.Controller.handle",
                "context": "return Types::JSON;",
                "target": "Types"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Types", "{value}");
}

#[test]
fn php_reference_context_resolves_static_member_to_constant() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "composer.json",
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
        )
        .file(
            "src/Types.php",
            "<?php\nnamespace App;\nclass Types { public const JSON = 'json'; }\n",
        )
        .file(
            "src/Controller.php",
            "<?php\nnamespace App;\nclass Controller { public function handle(): string { return Types::JSON; } }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "App.Controller.handle",
                "context": "return Types::JSON;",
                "target": "JSON"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Types.JSON", "{value}");
}

#[test]
fn java_reference_context_resolves_field_access_qualifier_to_class() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Types.java",
            "package app; public class Types { public static String JSON = \"json\"; }\n",
        )
        .file(
            "app/UseTypes.java",
            "package app; public class UseTypes { public Object run() { return Types.JSON; } }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "app.UseTypes.run",
                "context": "return Types.JSON;",
                "target": "Types"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Types", "{value}");
}

#[test]
fn java_reference_context_resolves_field_access_member_to_field() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Types.java",
            "package app; public class Types { public static String JSON = \"json\"; }\n",
        )
        .file(
            "app/UseTypes.java",
            "package app; public class UseTypes { public Object run() { return Types.JSON; } }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "app.UseTypes.run",
                "context": "return Types.JSON;",
                "target": "JSON"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Types.JSON", "{value}");
}

#[test]
fn java_definition_lookup_honors_each_focused_selector_segment() {
    let source = r#"
package app;

public class Consumer {
    Types value;

    void run() {
        Types.get();
        java.util.function.Supplier<Types> reference = Types::get;
        java.util.function.Function<Argument, Types> generic = Types::<Argument>create;
        java.util.function.Supplier<Types> constructor = Types::new;
        Types.Nested.create();
        value.nested.create();
        new Types.Nested();
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "app/Types.java",
            r#"
package app;

public class Types {
    public Types() {}
    public static Types get() { return new Types(); }
    public static <T> Types create(T value) { return new Types(); }
    public Nested nested = new Nested();

    public static class Nested {
        public Nested() {}
        public static void create() {}
    }
}
"#,
        )
        .file(
            "app/Argument.java",
            "package app; public class Argument {}\n",
        )
        .file("app/Consumer.java", source)
        .build();

    let cases = [
        ("Types.get();", "Types", "app.Types"),
        ("Types.get();", "get", "app.Types.get"),
        ("Types::get", "Types", "app.Types"),
        ("Types::get", "get", "app.Types.get"),
        ("Types::<Argument>create", "Types", "app.Types"),
        ("Types::<Argument>create", "Argument", "app.Argument"),
        ("Types::<Argument>create", "create", "app.Types.create"),
        ("Types::new", "Types", "app.Types"),
        ("Types::new", "new", "app.Types.Types"),
        ("Types.Nested.create();", "Types", "app.Types"),
        ("Types.Nested.create();", "Nested", "app.Types.Nested"),
        (
            "Types.Nested.create();",
            "create",
            "app.Types.Nested.create",
        ),
        ("value.nested.create();", "value", "app.Consumer.value"),
        ("value.nested.create();", "nested", "app.Types.nested"),
        (
            "value.nested.create();",
            "create",
            "app.Types.Nested.create",
        ),
        ("new Types.Nested();", "Types", "app.Types"),
        ("new Types.Nested();", "Nested", "app.Types.Nested.Nested"),
    ];
    let references = cases
        .iter()
        .map(|(marker, focus, _)| {
            let marker_start = source.find(marker).expect("case marker");
            let start = marker_start + marker.find(focus).expect("focus in marker");
            serde_json::from_str::<Value>(&location_reference("app/Consumer.java", source, start))
                .expect("location reference JSON")["references"][0]
                .clone()
        })
        .collect::<Vec<_>>();
    let value = lookup(
        project.root(),
        &json!({ "references": references }).to_string(),
    );

    for (index, (marker, focus, expected)) in cases.iter().enumerate() {
        let result = &value["results"][index];
        assert_eq!(
            result["status"], "resolved",
            "{marker} focus {focus}: {value}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"], *expected,
            "{marker} focus {focus}: {value}"
        );
    }
}

#[test]
fn java_nested_type_beats_imported_nested_type_in_constructor_context() {
    let source = r#"
package app;

import pkg.Symbol.Visitor;

public class Enclosing {
    static class Visitor {}

    class Runner {
        Visitor current = new Visitor();
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Symbol.java",
            "package pkg; public class Symbol { public static class Visitor {} }\n",
        )
        .file("app/Enclosing.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/Enclosing.java",
            source,
            source.rfind("new Visitor()").expect("nested constructor"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Enclosing.Visitor",
        "{value}"
    );
    assert_eq!(
        result["definitions"][0]["path"], "app/Enclosing.java",
        "{value}"
    );
}

#[test]
fn java_nested_type_beats_imported_nested_type_in_parameter_context() {
    let source = r#"
package app;

import pkg.Symbol.Visitor;

public class Enclosing {
    static class Visitor {}

    void accept(Visitor visitor) {}
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "pkg/Symbol.java",
            "package pkg; public class Symbol { public static class Visitor {} }\n",
        )
        .file("app/Enclosing.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/Enclosing.java",
            source,
            source.find("Visitor visitor").expect("parameter type"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Enclosing.Visitor",
        "{value}"
    );
}

#[test]
fn java_terminal_token_in_scoped_source_type_resolves_whole_type() {
    let source = r#"
package app;

public class Outer {
    public static class Inner {}
}

class UseInner {
    private app.Outer.Inner value;
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("app/Outer.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/Outer.java",
            source,
            source.rfind("Inner value").expect("scoped terminal type"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Outer.Inner",
        "{value}"
    );
}

#[test]
fn java_terminal_token_in_fully_qualified_external_type_stays_on_boundary() {
    let source = r#"
package app;

public class EvaluateInstancesRequest {
    static class Builder {}

    private com.google.cloud.aiplatform.v1.ExactMatchInput.Builder builder;
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("app/EvaluateInstancesRequest.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/EvaluateInstancesRequest.java",
            source,
            source.rfind("Builder builder").expect("fq terminal type"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(message.contains("ExactMatchInput.Builder"), "{value}");
}

#[test]
fn java_terminal_token_in_scoped_external_type_does_not_fall_back_to_same_package() {
    let source = r#"
package app;

public class UseValue {
    private com.google.protobuf.Value payload;
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("app/Value.java", "package app; public class Value {}\n")
        .file("app/UseValue.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/UseValue.java",
            source,
            source
                .rfind("Value payload")
                .expect("scoped external terminal"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "unresolvable_import_boundary", "{value}");
    let message = result["diagnostics"][0]["message"]
        .as_str()
        .expect("diagnostic message");
    assert!(message.contains("com.google.protobuf.Value"), "{value}");
}

#[test]
fn java_terminal_token_in_missing_workspace_type_is_not_an_import_boundary() {
    let source = r#"
package app;

public class UseMissing {
    private app.Missing payload;
}
"#;
    let project = InlineTestProject::with_language(Language::Java)
        .file("app/Known.java", "package app; public class Known {}\n")
        .file("app/UseMissing.java", source)
        .build();

    let value = lookup(
        project.root(),
        &location_reference(
            "app/UseMissing.java",
            source,
            source.find("Missing payload").expect("missing scoped type"),
        ),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "no_definition", "{value}");
    assert_eq!(
        result["diagnostics"][0]["kind"], "no_indexed_definition",
        "{value}"
    );
}

#[test]
fn cpp_reference_context_resolves_qualified_scope_to_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("types.h", "struct Types { static const int JSON = 1; };\n")
        .file(
            "app.cpp",
            "#include \"types.h\"\nint run() { return Types::JSON; }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "return Types::JSON;",
                "target": "Types"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Types", "{value}");
}

#[test]
fn cpp_reference_context_resolves_qualified_name_to_static_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("types.h", "struct Types { static const int JSON = 1; };\n")
        .file(
            "app.cpp",
            "#include \"types.h\"\nint run() { return Types::JSON; }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "return Types::JSON;",
                "target": "JSON"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Types.JSON", "{value}");
}

#[test]
fn rust_reference_context_resolves_path_qualifier_to_type() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "lib.rs",
            "pub struct Types; impl Types { pub const JSON: i32 = 1; } pub fn run() -> i32 { Types::JSON }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "Types::JSON",
                "target": "Types"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "Types", "{value}");
}

#[test]
fn csharp_reference_context_resolves_member_access_qualifier_to_class() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App/Types.cs",
            "namespace App { public class Types { public static string JSON = \"json\"; } public class UseTypes { public object Run() { return Types.JSON; } } }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "App.UseTypes.Run",
                "context": "return Types.JSON;",
                "target": "Types"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "App.Types", "{value}");
}

#[test]
fn python_reference_context_resolves_attribute_qualifier_to_class() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            "class Types:\n    JSON = 'json'\n\ndef run():\n    return Types.JSON\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "run",
                "context": "return Types.JSON",
                "target": "Types"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Types", "{value}");
    assert_eq!(result["definitions"][0]["start_line"], 1, "{value}");
    assert_eq!(result["definitions"][0]["start_column"], 7, "{value}");
    assert_eq!(result["definitions"][0]["end_line"], 1, "{value}");
    assert_eq!(result["definitions"][0]["end_column"], 12, "{value}");
}

#[test]
fn navigation_and_type_candidates_expose_exact_same_line_unicode_ranges() {
    let source = "class Først {} class Widget {}\nconst value: Widget = new Widget();\nvalue;\n";
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", source)
        .build();
    let reference = source.find("new Widget").unwrap() + "new ".len();
    let expected_start = source.lines().next().unwrap().find("Widget").unwrap();
    let expected_column = source.lines().next().unwrap()[..expected_start]
        .chars()
        .count()
        + 1;
    let expected_end_column = expected_column + "Widget".chars().count();

    let definition = lookup(
        project.root(),
        &location_reference("app.ts", source, reference),
    );
    let declaration = lookup_declaration(
        project.root(),
        &location_reference("app.ts", source, reference),
    );
    for candidate in [
        &definition["results"][0]["definitions"][0],
        &declaration["results"][0]["declarations"][0],
    ] {
        assert_eq!(candidate["start_line"], 1, "candidate: {candidate}");
        assert_eq!(
            candidate["start_column"], expected_column,
            "candidate: {candidate}"
        );
        assert_eq!(candidate["end_line"], 1, "candidate: {candidate}");
        assert_eq!(
            candidate["end_column"], expected_end_column,
            "candidate: {candidate}"
        );
    }

    let type_lookup = lookup_type(
        project.root(),
        &location_reference("app.ts", source, source.rfind("value").unwrap()),
    );
    let type_definition = &type_lookup["results"][0]["types"][0]["definitions"][0];
    assert_eq!(type_definition["start_line"], 1, "{type_lookup}");
    assert_eq!(
        type_definition["start_column"], expected_column,
        "{type_lookup}"
    );
    assert_eq!(type_definition["end_line"], 1, "{type_lookup}");
    assert_eq!(
        type_definition["end_column"], expected_end_column,
        "{type_lookup}"
    );
}

#[test]
fn scala_reference_context_resolves_select_qualifier_to_object() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Types.scala",
            "package app\nobject Types { val JSON: String = \"json\" }\nclass UseTypes { def run: String = Types.JSON }\n",
        )
        .build();

    let value = lookup_reference(
        project.root(),
        &json!({
            "references": [{
                "symbol": "app.UseTypes.run",
                "context": "Types.JSON",
                "target": "Types"
            }]
        })
        .to_string(),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["fqn"], "app.Types$", "{value}");
}

#[test]
fn rust_parameter_definition_by_location_has_local_candidate_contract() {
    let source =
        "fn mono_family(cfg: &config::Config) -> String {\n    cfg.font.mono_family.clone()\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file("main.rs", source)
        .build();
    let reference = source.find("cfg.font").expect("body parameter reference");

    let value = lookup(
        project.root(),
        &location_reference("main.rs", source, reference),
    );
    let result = &value["results"][0];
    let definition = &result["definitions"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(definition["name"], "cfg", "{value}");
    assert!(definition.get("fqn").is_none(), "{value}");
    assert_eq!(definition["kind"], "parameter", "{value}");
    assert_eq!(definition["signature"], "cfg: &config::Config", "{value}");
    assert_eq!(definition["path"], "main.rs", "{value}");
    assert_eq!(definition["start_line"], 1, "{value}");
    assert_eq!(definition["start_column"], 16, "{value}");
    assert_eq!(definition["end_line"], 1, "{value}");
    assert_eq!(definition["end_column"], 19, "{value}");
}

#[test]
fn javascript_destructured_parameter_definition_reports_binding_leaf() {
    let source = "function render({ label, nested: { value } }) {\n  return value;\n}\n";
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("render.js", source)
        .build();
    let reference = source.rfind("value").expect("body parameter reference");

    let value = lookup(
        project.root(),
        &location_reference("render.js", source, reference),
    );
    let result = &value["results"][0];
    let definition = &result["definitions"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(definition["name"], "value", "{value}");
    assert!(definition.get("fqn").is_none(), "{value}");
    assert_eq!(definition["kind"], "parameter", "{value}");
    assert_eq!(
        definition["signature"], "{ label, nested: { value } }",
        "{value}"
    );
    assert_eq!(definition["start_line"], 1, "{value}");
}

#[test]
fn scala_qualified_java_constructor_does_not_fall_back_to_scala_simple_name_owner() {
    let scala_source = r#"
package app

class Builder {
  def append(value: String): Builder = this
}

object Consumer {
  val built = new javaish.Builder().append("java")
}
"#;
    let project = InlineTestProject::new()
        .file(
            "javaish/Builder.java",
            "package javaish; public class Builder { public Builder append(String value) { return this; } }\n",
        )
        .file("app/Consumer.scala", scala_source)
        .build();
    let append_start = scala_source.find(".append").expect("qualified Java append") + 1;
    let value = lookup(
        project.root(),
        &location_reference("app/Consumer.scala", scala_source, append_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(result["definitions"][0]["language"], "java", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "javaish.Builder.append",
        "{value}"
    );
}

#[test]
fn scala_qualified_unindexed_java_constructor_does_not_use_scala_simple_name_member() {
    let source = r#"
package app

class StringBuilder {
  def append(value: String): StringBuilder = this
}
object Consumer {
  val built = new java.lang.StringBuilder().append("java")
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Consumer.scala", source)
        .build();
    let append_start = source.find(".append").expect("qualified append") + 1;
    let value = lookup(
        project.root(),
        &location_reference("app/Consumer.scala", source, append_start),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_owner_does_not_borrow_member_from_same_fqn_java_declaration() {
    let source = r#"
package shared

class Builder

object Consumer {
  val built = new Builder().append("wrong-language")
}
"#;
    let project = InlineTestProject::new()
        .file(
            "java/shared/Builder.java",
            "package shared; public class Builder { public Builder append(String value) { return this; } }\n",
        )
        .file("scala/shared/Consumer.scala", source)
        .build();
    let append_start = source.find(".append").expect("same-FQN append") + 1;
    let value = lookup(
        project.root(),
        &location_reference("scala/shared/Consumer.scala", source, append_start),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn scala_nested_class_companion_term_beats_constructor_member_identity() {
    let source = r#"
package app

object Outer {
  class Entry {
    def companion: Entry.type = Entry
  }
  object Entry
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Outer.scala", source)
        .build();
    let entry_start = source.find("= Entry").expect("companion term") + "= ".len();
    let value = lookup(
        project.root(),
        &location_reference("app/Outer.scala", source, entry_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Outer$.Entry$",
        "{value}"
    );
    assert_ne!(
        result["definitions"][0]["fqn"], "app.Outer$.Entry.Entry",
        "the class constructor must not win the term-namespace lookup: {value}"
    );
}

#[test]
fn scala_nested_singleton_type_reference_keeps_term_namespace_identity() {
    let source = r#"
package app

object Outer {
  class Entry
  object Entry
  val companion: Entry.type = Entry
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Outer.scala", source)
        .build();
    let entry_start = source.find("Entry.type").expect("singleton type");
    let value = lookup(
        project.root(),
        &location_reference("app/Outer.scala", source, entry_start),
    );

    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Outer$.Entry$",
        "{value}"
    );
}
