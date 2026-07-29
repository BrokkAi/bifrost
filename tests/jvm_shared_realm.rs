//! Behaviour tests for the shared JVM realm (issue #1237).
//!
//! Java, Scala, and Kotlin compile to one classpath, so Bifrost models them as
//! one dependency universe and one usage-candidate universe. These tests pin
//! what that membership does and does not mean: one candidate space, but never
//! a collapsed source-language identity.

mod common;

use common::InlineTestProject;
use common::usage_graph::usage_graph_at;
use serde_json::Value;

const JAVA_API: &str = "package app;\n\
     \n\
     public interface Api {\n\
         String describe();\n\
     }\n";

const SCALA_SERVICE: &str = "package app\n\
     \n\
     trait Service {\n\
       def run(): String\n\
     }\n";

const KOTLIN_IMPL: &str = "package app\n\
     \n\
     class Impl {\n\
         fun help(): String = \"help\"\n\
     }\n";

fn mixed_jvm_graph() -> (common::BuiltInlineTestProject, Value) {
    let built = InlineTestProject::new()
        .file("src/app/Api.java", JAVA_API)
        .file("src/app/Service.scala", SCALA_SERVICE)
        .file("src/app/Impl.kt", KOTLIN_IMPL)
        .build();
    let graph = usage_graph_at(built.root(), "{}");
    (built, graph)
}

fn node_language(graph: &Value, fqn: &str) -> Option<String> {
    graph["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .find(|node| node["fqn"].as_str() == Some(fqn))
        .and_then(|node| node["language"].as_str())
        .map(str::to_string)
}

#[test]
fn every_jvm_language_contributes_nodes_to_the_shared_realm() {
    let (_built, graph) = mixed_jvm_graph();

    for fqn in ["app.Api", "app.Service", "app.Impl"] {
        assert!(
            node_language(&graph, fqn).is_some(),
            "expected a node for {fqn} in {}",
            serde_json::to_string_pretty(&graph["nodes"]).unwrap()
        );
    }
}

#[test]
fn shared_realm_membership_keeps_each_node_source_language() {
    let (_built, graph) = mixed_jvm_graph();

    assert_eq!(node_language(&graph, "app.Api").as_deref(), Some("java"));
    assert_eq!(
        node_language(&graph, "app.Service").as_deref(),
        Some("scala")
    );
    assert_eq!(node_language(&graph, "app.Impl").as_deref(), Some("kotlin"));
}

#[test]
fn kotlin_realm_identities_stay_source_level() {
    let built = InlineTestProject::new()
        .file("src/app/Api.java", JAVA_API)
        .file(
            "src/app/Catalog.kt",
            "package app\n\
             \n\
             object Catalog {\n\
                 fun register(): Int = 1\n\
             }\n\
             \n\
             fun topLevel(): Int = 2\n",
        )
        .build();
    let graph = usage_graph_at(built.root(), "{}");

    let kotlin_fqns: Vec<&str> = graph["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .filter(|node| node["language"].as_str() == Some("kotlin"))
        .map(|node| node["fqn"].as_str().expect("node fqn"))
        .collect();

    assert!(
        kotlin_fqns.contains(&"app.Catalog"),
        "missing app.Catalog in {kotlin_fqns:?}"
    );
    assert!(
        kotlin_fqns.contains(&"app.topLevel"),
        "a top-level Kotlin function is named by its source identity, never \
         through the generated `CatalogKt` facade: {kotlin_fqns:?}"
    );
    assert!(
        kotlin_fqns
            .iter()
            .all(|fqn| !fqn.contains('$') && !fqn.contains("Kt.")),
        "no compiler-generated JVM name may appear in a realm identity: {kotlin_fqns:?}"
    );
}

#[test]
fn java_only_workspace_still_reports_java_nodes_and_edges() {
    // Merging Java and Scala into one realm must not change what a
    // single-language JVM workspace reports.
    let built = InlineTestProject::new()
        .file(
            "src/app/Greeter.java",
            "package app;\n\
             \n\
             public class Greeter {\n\
                 public String greet() { return \"hi\"; }\n\
             }\n",
        )
        .file(
            "src/app/Caller.java",
            "package app;\n\
             \n\
             public class Caller {\n\
                 public String call() { return new Greeter().greet(); }\n\
             }\n",
        )
        .build();
    let graph = usage_graph_at(built.root(), "{}");

    assert_eq!(
        node_language(&graph, "app.Greeter").as_deref(),
        Some("java")
    );
    assert!(
        common::usage_graph::has_edge(&graph, "app.Caller.call", "app.Greeter.greet"),
        "the existing Java call edge must survive the realm merge: {}",
        serde_json::to_string_pretty(&graph["edges"]).unwrap()
    );
    common::usage_graph::assert_every_edge_endpoint_is_a_node(&graph);
}
