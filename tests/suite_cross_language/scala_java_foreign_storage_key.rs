//! #1805: the Scala forward resolver asks its own analyzer about Java units.
//!
//! `ForwardScalaNameResolver::resolve_candidate_tier` looks an owner-path
//! candidate up with `fqn_in_language(exact, Language::Java)` on purpose, then
//! filters the hits through `scala_unit_matches_owner_kind`, whose
//! `TypeNamespace` arm consults `ScalaAnalyzer::is_type_alias`. A Java-file
//! `CodeUnit` therefore reaches the Scala analyzer's per-file store query,
//! whose storage key is the FILE's language ("java") and so is absent from the
//! Scala adapter's `generations` map. Indexing that map directly panicked with
//! "no entry found for key" (the scala FIRD census died this way on zio,
//! metals and midonet).

use crate::common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

const JAVA_CONFIG: &str = r#"package pkg;

public class Config {
    public static final int Level = 1;

    public static int level() {
        return Level;
    }
}
"#;

/// The default-package Scala file makes the owner path `pkg` fall through to
/// the root-namespace tier, where the only workspace declaration named `pkg`
/// is the Java file's package module unit -- a non-class unit, so the
/// `TypeNamespace` arm reaches `is_type_alias` with a Java-file `CodeUnit`.
const SCALA_MAIN: &str = r#"object Main {
  val x: pkg.Config = null
}
"#;

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
fn scala_type_reference_into_java_package_resolves_instead_of_panicking() {
    let project = InlineTestProject::new()
        .file("pkg/Config.java", JAVA_CONFIG)
        .file("Main.scala", SCALA_MAIN)
        .build();
    let start = SCALA_MAIN
        .find("Config = null")
        .expect("the Java type reference");
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({"references": [location_query("Main.scala", SCALA_MAIN, start)]}).to_string(),
    );
    let result = &value["results"][0];
    assert_eq!(result["status"], "resolved", "{value}");
    let definitions = result["definitions"].as_array().expect("definitions array");
    assert!(
        definitions.iter().any(|definition| {
            definition["path"] == "pkg/Config.java" && definition["fqn"] == "pkg.Config"
        }),
        "the Scala type reference must resolve into the Java file: {value}"
    );
}

/// The same foreign unit asked directly, which is what every other per-file
/// query seam on the analyzer would have done with it: a Java declaration is
/// never one of the Scala analyzer's type aliases, and asking must not panic.
#[test]
fn scala_analyzer_reports_java_units_as_non_aliases() {
    use brokk_bifrost::analyzer::resolve_analyzer;
    use brokk_bifrost::{AnalyzerConfig, ScalaAnalyzer};

    let project = InlineTestProject::new()
        .file("pkg/Config.java", JAVA_CONFIG)
        .file("Main.scala", SCALA_MAIN)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let java_units = analyzer.declarations(&project.file("pkg/Config.java"));
    assert!(!java_units.is_empty(), "the Java file must declare units");
    let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)
        .expect("a mixed workspace exposes the Scala analyzer");
    for unit in &java_units {
        assert!(
            !scala.is_type_alias(unit),
            "`{}` lives in a Java file and cannot be a Scala type alias",
            unit.fq_name()
        );
    }
}
