//! Behaviour tests for the shared JVM realm (issue #1237).
//!
//! Java, Scala, and Kotlin compile to one classpath, so Bifrost models them as
//! one dependency universe and one usage-candidate universe. These tests pin
//! what that membership does and does not mean: one candidate space, but never
//! a collapsed source-language identity.

use crate::common::InlineTestProject;
use crate::common::usage_graph::usage_graph_at;
use brokk_bifrost::CodeUnitIndex;
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

fn mixed_jvm_graph() -> (crate::common::BuiltInlineTestProject, Value) {
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
        crate::common::usage_graph::has_edge(&graph, "app.Caller.call", "app.Greeter.greet"),
        "the existing Java call edge must survive the realm merge: {}",
        serde_json::to_string_pretty(&graph["edges"]).unwrap()
    );
    crate::common::usage_graph::assert_every_edge_endpoint_is_a_node(&graph);
}

// ---------------------------------------------------------------------------
// Cross-language source resolution
// ---------------------------------------------------------------------------

use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, ImportAnalysisProvider, JavaAnalyzer, KotlinAnalyzer, Language,
    MultiAnalyzer, ScalaAnalyzer, TypeHierarchyProvider,
};
use std::collections::BTreeMap;

/// A multi-language analyzer over an inline workspace, with one delegate per
/// JVM language the fixture actually uses.
fn jvm_workspace(files: &[(&str, &str)]) -> (crate::common::BuiltInlineTestProject, MultiAnalyzer) {
    let mut project = InlineTestProject::new();
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();

    let mut delegates = BTreeMap::new();
    for language in built.languages() {
        let delegate = match language {
            Language::Java => AnalyzerDelegate::Java(JavaAnalyzer::new(built.project_dyn())),
            Language::Scala => AnalyzerDelegate::Scala(ScalaAnalyzer::new(built.project_dyn())),
            Language::Kotlin => AnalyzerDelegate::Kotlin(KotlinAnalyzer::new(built.project_dyn())),
            other => panic!("unexpected language in JVM fixture: {other:?}"),
        };
        delegates.insert(language, delegate);
    }
    (built, MultiAnalyzer::new(delegates))
}

fn definition(analyzer: &MultiAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .find(CodeUnit::is_class)
        .unwrap_or_else(|| panic!("no class declaration named {fq_name}"))
}

fn sorted_fq_names(units: &[CodeUnit]) -> Vec<String> {
    let mut names: Vec<String> = units.iter().map(CodeUnit::fq_name).collect();
    names.sort();
    names
}

#[test]
fn kotlin_class_implementing_a_java_interface_resolves_the_java_declaration() {
    let (_built, analyzer) = jvm_workspace(&[
        ("src/app/Api.java", JAVA_API),
        (
            "src/app/Impl.kt",
            "package app\n\
             \n\
             class Impl : Api {\n\
                 override fun describe(): String = \"impl\"\n\
             }\n",
        ),
    ]);
    let impl_unit = definition(&analyzer, "app.Impl");
    assert_eq!(
        sorted_fq_names(&analyzer.get_direct_ancestors(&impl_unit)),
        vec!["app.Api".to_string()],
        "the JVM realm lets a Kotlin class name a Java interface declared next \
         door with no import"
    );
}

#[test]
fn kotlin_class_extending_a_scala_trait_resolves_the_scala_declaration() {
    let (_built, analyzer) = jvm_workspace(&[
        ("src/lib/Service.scala", "package lib\n\ntrait Service\n"),
        (
            "src/app/Impl.kt",
            "package app\n\nimport lib.Service\n\nclass Impl : Service\n",
        ),
    ]);
    let impl_unit = definition(&analyzer, "app.Impl");
    assert_eq!(
        sorted_fq_names(&analyzer.get_direct_ancestors(&impl_unit)),
        vec!["lib.Service".to_string()]
    );
}

#[test]
fn kotlin_imports_resolve_java_and_scala_declarations() {
    let (built, analyzer) = jvm_workspace(&[
        (
            "src/lib/Api.java",
            "package lib;\n\npublic interface Api {}\n",
        ),
        ("src/lib/Service.scala", "package lib\n\ntrait Service\n"),
        (
            "src/app/App.kt",
            "package app\n\
             \n\
             import lib.Api\n\
             import lib.Service\n\
             \n\
             class App\n",
        ),
    ]);
    let mut imported: Vec<String> = analyzer
        .imported_code_units_of(&built.file("src/app/App.kt"))
        .iter()
        .map(CodeUnit::fq_name)
        .collect();
    imported.sort();
    assert_eq!(
        imported,
        vec!["lib.Api".to_string(), "lib.Service".to_string()]
    );
}

#[test]
fn java_interface_descendants_include_its_kotlin_implementors() {
    let (_built, analyzer) = jvm_workspace(&[
        ("src/app/Api.java", JAVA_API),
        (
            "src/app/JavaImpl.java",
            "package app;\n\
             \n\
             public class JavaImpl implements Api {\n\
                 public String describe() { return \"java\"; }\n\
             }\n",
        ),
        (
            "src/app/KotlinImpl.kt",
            "package app\n\
             \n\
             class KotlinImpl : Api {\n\
                 override fun describe(): String = \"kotlin\"\n\
             }\n",
        ),
    ]);
    let api = definition(&analyzer, "app.Api");
    let mut descendants: Vec<String> = analyzer
        .get_direct_descendants(&api)
        .iter()
        .map(CodeUnit::fq_name)
        .collect();
    descendants.sort();
    assert_eq!(
        descendants,
        vec!["app.JavaImpl".to_string(), "app.KotlinImpl".to_string()],
        "a Java interface's implementors span the realm, not just its own language"
    );
}

#[test]
fn kotlin_only_workspace_resolves_exactly_as_before() {
    // A realm of one adds nothing, and must take nothing away.
    let (_built, analyzer) = jvm_workspace(&[(
        "src/app/Types.kt",
        "package app\n\nopen class Base\n\nclass Child : Base()\n",
    )]);
    let child = definition(&analyzer, "app.Child");
    assert_eq!(
        sorted_fq_names(&analyzer.get_direct_ancestors(&child)),
        vec!["app.Base".to_string()]
    );
}

#[test]
fn lone_kotlin_workspace_handle_resolves_without_realm_widening() {
    // A single-language workspace is served by a MultiAnalyzer holding one
    // delegate. Realm widening needs Kotlin plus another JVM language, so this
    // workspace must resolve exactly what the bare KotlinAnalyzer resolved: its
    // own declarations, and nothing out of the Java sibling it does not analyze.
    let built = InlineTestProject::with_language(Language::Kotlin)
        .file(
            "src/app/Types.kt",
            "package app\n\
             \n\
             open class Base\n\
             \n\
             class Child : Base()\n\
             \n\
             class Impl : Api\n",
        )
        .file("src/app/Api.java", JAVA_API)
        .build();
    let workspace = built.workspace_analyzer(brokk_bifrost::AnalyzerConfig::default());
    assert!(matches!(
        workspace,
        brokk_bifrost::WorkspaceAnalyzer::Multi(_)
    ));
    let analyzer = workspace.analyzer();
    assert_eq!(
        std::collections::BTreeSet::from([Language::Kotlin]),
        analyzer.languages()
    );
    let hierarchy = analyzer
        .type_hierarchy_provider()
        .expect("a Kotlin workspace answers type-hierarchy queries");
    let class_named = |fq_name: &str| {
        analyzer
            .get_definitions(fq_name)
            .into_iter()
            .find(CodeUnit::is_class)
            .unwrap_or_else(|| panic!("no class declaration named {fq_name}"))
    };

    assert_eq!(
        sorted_fq_names(&hierarchy.get_direct_ancestors(&class_named("app.Child"))),
        vec!["app.Base".to_string()],
        "routing a lone Kotlin delegate through MultiAnalyzer keeps Kotlin's own \
         hierarchy intact"
    );
    assert!(
        hierarchy
            .get_direct_ancestors(&class_named("app.Impl"))
            .is_empty(),
        "a Java declaration in an unanalyzed sibling file is outside this \
         workspace's realm of one"
    );
}

#[test]
fn a_java_name_the_kotlin_file_cannot_see_stays_unresolved() {
    let (_built, analyzer) = jvm_workspace(&[
        (
            "src/other/Hidden.java",
            "package other;\n\npublic interface Hidden {}\n",
        ),
        ("src/app/Impl.kt", "package app\n\nclass Impl : Hidden\n"),
    ]);
    let impl_unit = definition(&analyzer, "app.Impl");
    assert!(
        analyzer.get_direct_ancestors(&impl_unit).is_empty(),
        "sharing a realm widens the declaration universe, not Kotlin's own \
         visibility rules: a different package still needs an import"
    );
}

// ---------------------------------------------------------------------------
// Cross-language usage: Kotlin and its JVM neighbours (issue #1239, milestone 4)
// ---------------------------------------------------------------------------

use crate::common::search_tools::call_tool;
use crate::common::usage_graph::has_edge;

const XLANG_JAVA_GREETER: &str = "package lib;\n\
     \n\
     public class JavaGreeter {\n\
         public String greet() { return \"java\"; }\n\
     }\n";

const XLANG_SCALA_GREETER: &str = "package lib\n\
     \n\
     class ScalaGreeter {\n\
       def greet(): String = \"scala\"\n\
     }\n";

const XLANG_KOTLIN_GREETER: &str = "package lib\n\
     \n\
     class KotlinGreeter {\n\
     \n\
         fun greet(): String {\n\
             return \"kotlin\"\n\
         }\n\
     }\n";

const XLANG_KOTLIN_CALLER: &str = "package app\n\
     \n\
     import lib.JavaGreeter\n\
     import lib.ScalaGreeter\n\
     \n\
     class KotlinCaller {\n\
     \n\
         fun callJava(): String {\n\
             val greeter = JavaGreeter()\n\
             return greeter.greet()\n\
         }\n\
     \n\
         fun callScala(): String {\n\
             val greeter = ScalaGreeter()\n\
             return greeter.greet()\n\
         }\n\
     }\n";

const XLANG_JAVA_CALLER: &str = "package app;\n\
     \n\
     import lib.KotlinGreeter;\n\
     \n\
     public class JavaCaller {\n\
         public String callKotlin() { return new KotlinGreeter().greet(); }\n\
     }\n";

const XLANG_SCALA_CALLER: &str = "package app\n\
     \n\
     import lib.KotlinGreeter\n\
     \n\
     class ScalaCaller {\n\
       def callKotlin(): String = new KotlinGreeter().greet()\n\
     }\n";

fn mixed_caller_workspace() -> crate::common::BuiltInlineTestProject {
    InlineTestProject::new()
        .file("src/lib/JavaGreeter.java", XLANG_JAVA_GREETER)
        .file("src/lib/ScalaGreeter.scala", XLANG_SCALA_GREETER)
        .file("src/lib/KotlinGreeter.kt", XLANG_KOTLIN_GREETER)
        .file("src/app/KotlinCaller.kt", XLANG_KOTLIN_CALLER)
        .file("src/app/JavaCaller.java", XLANG_JAVA_CALLER)
        .file("src/app/ScalaCaller.scala", XLANG_SCALA_CALLER)
        .build()
}

/// Every file path carrying a proven `scan_usages` hit for `symbol`.
fn usage_hit_paths(project: &crate::common::BuiltInlineTestProject, symbol: &str) -> Vec<String> {
    let scan = call_tool(
        project,
        "scan_usages_by_reference",
        &serde_json::json!({ "symbols": [symbol], "include_tests": true }).to_string(),
    );
    scan["results"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|entry| entry["files"].as_array().into_iter().flatten())
        .filter_map(|file| file["path"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn kotlin_source_contributes_edges_onto_java_and_scala_declarations() {
    let built = mixed_caller_workspace();
    let graph = usage_graph_at(built.root(), "{}");
    let edges = || serde_json::to_string_pretty(&graph["edges"]).unwrap();

    // Kotlin -> Java, both the construction and the call.
    assert!(
        has_edge(&graph, "app.KotlinCaller.callJava", "lib.JavaGreeter"),
        "missing Kotlin -> Java type edge: {}",
        edges()
    );
    assert!(
        has_edge(&graph, "app.KotlinCaller.callJava", "lib.JavaGreeter.greet"),
        "missing Kotlin -> Java call edge: {}",
        edges()
    );
    // Kotlin -> Scala.
    assert!(
        has_edge(&graph, "app.KotlinCaller.callScala", "lib.ScalaGreeter"),
        "missing Kotlin -> Scala type edge: {}",
        edges()
    );
    assert!(
        has_edge(
            &graph,
            "app.KotlinCaller.callScala",
            "lib.ScalaGreeter.greet"
        ),
        "missing Kotlin -> Scala call edge: {}",
        edges()
    );
}

#[test]
fn java_source_contributes_edges_onto_kotlin_declarations() {
    let built = mixed_caller_workspace();
    let graph = usage_graph_at(built.root(), "{}");
    let edges = || serde_json::to_string_pretty(&graph["edges"]).unwrap();

    // The return direction. Before this, Java's builder resolved names against
    // the Java-only declaration index, so `new KotlinGreeter()` resolved to
    // nothing and both references were silently lost.
    assert!(
        has_edge(&graph, "app.JavaCaller.callKotlin", "lib.KotlinGreeter"),
        "missing Java -> Kotlin type edge: {}",
        edges()
    );
    assert!(
        has_edge(
            &graph,
            "app.JavaCaller.callKotlin",
            "lib.KotlinGreeter.greet"
        ),
        "missing Java -> Kotlin call edge: {}",
        edges()
    );
    crate::common::usage_graph::assert_every_edge_endpoint_is_a_node(&graph);
}

#[test]
fn scan_usages_for_a_kotlin_class_reports_java_and_scala_call_sites() {
    let built = mixed_caller_workspace();
    let paths = usage_hit_paths(&built, "lib.KotlinGreeter");
    assert!(
        paths.iter().any(|path| path.ends_with("JavaCaller.java")),
        "a Kotlin class's Java call sites must be reported: {paths:?}"
    );
    assert!(
        paths.iter().any(|path| path.ends_with("ScalaCaller.scala")),
        "a Kotlin class's Scala call sites must be reported: {paths:?}"
    );
}

#[test]
fn scan_usages_for_a_java_class_reports_kotlin_call_sites() {
    let built = mixed_caller_workspace();
    let paths = usage_hit_paths(&built, "lib.JavaGreeter");
    assert!(
        paths.iter().any(|path| path.ends_with("KotlinCaller.kt")),
        "a Java class's Kotlin call sites must be reported: {paths:?}"
    );
}

#[test]
fn scan_usages_for_a_scala_class_reports_kotlin_call_sites() {
    let built = mixed_caller_workspace();
    let paths = usage_hit_paths(&built, "lib.ScalaGreeter");
    assert!(
        paths.iter().any(|path| path.ends_with("KotlinCaller.kt")),
        "a Scala class's Kotlin call sites must be reported: {paths:?}"
    );
}
