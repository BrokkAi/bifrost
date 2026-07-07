mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge, usage_graph_at};
use serde_json::Value;

fn ruby_usage_graph() -> Value {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "app.rb",
            r#"
class Service
  def initialize
  end

  def run
    1
  end

  def unused
    0
  end
end

class Other
  def run
    2
  end
end

module Helpers
  def normalize
    "ok"
  end
  module_function :normalize
end

class Consumer
  def via_instance
    service = Service.new
    service.run
  end

  def via_constructor
    Service.new
  end

  def via_module
    Helpers.normalize
  end

  def local
    3
  end

  def calls_local
    local
  end

  def wrong_receiver
    other = Other.new
    other.run
  end
end
"#,
        )
        .build();
    usage_graph_at(project.root(), "{}")
}

#[test]
fn resolves_locally_typed_instance_and_bare_self_calls() {
    let value = ruby_usage_graph();

    assert!(
        has_edge(&value, "Consumer.via_instance", "Service.run"),
        "expected via_instance -> Service.run: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Consumer.calls_local", "Consumer.local"),
        "expected calls_local -> Consumer.local: {}",
        value["edges"]
    );
}

#[test]
fn resolves_constructor_and_module_function_calls() {
    let value = ruby_usage_graph();

    assert!(
        has_edge(&value, "Consumer.via_constructor", "Service.initialize"),
        "expected via_constructor -> Service.initialize: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Consumer.via_module", "Helpers.normalize"),
        "expected via_module -> Helpers.normalize: {}",
        value["edges"]
    );
}

#[test]
fn constant_references_edge_to_the_type_node() {
    let value = ruby_usage_graph();

    assert!(
        has_edge(&value, "Consumer.via_instance", "Service"),
        "expected via_instance -> Service: {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = ruby_usage_graph();

    assert!(
        !has_edge(&value, "Consumer.wrong_receiver", "Service.run"),
        "wrong_receiver must not edge to Service.run: {}",
        value["edges"]
    );
}

#[test]
fn unused_method_has_no_incoming_edges() {
    let value = ruby_usage_graph();

    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["to"].as_str() == Some("Service.unused")),
        "unused method must have no incoming edges: {}",
        value["edges"]
    );
}

#[test]
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&ruby_usage_graph());
}
