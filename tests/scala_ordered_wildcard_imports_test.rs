mod common;

use brokk_bifrost::{ImportAnalysisProvider, Language, ScalaAnalyzer};
use common::{InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

fn location_at(path: &str, source: &str, needle: &str) -> Value {
    let start = source.rfind(needle).expect("reference text");
    location_at_offset(path, source, start)
}

fn location_at_offset(path: &str, source: &str, start: usize) -> Value {
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current)| current)
        .chars()
        .count()
        + 1;
    json!({"path": path, "line": line, "column": column})
}

#[test]
fn sibling_package_scopes_keep_import_context_for_forward_and_candidate_routing() {
    let consumer = r#"package outer {
  import core.*
  object Consumer { val target = Target() }
}
package other {
  import core.*
  object Consumer { val target = Target() }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "outer/core/Target.scala",
            "package outer.core\nobject Target { def apply(): Int = 1 }\n",
        )
        .file(
            "other/core/Target.scala",
            "package other.core\nobject Target { def apply(): Int = 2 }\n",
        )
        .file("Scopes.scala", consumer)
        .build();
    let first = consumer.find("Target").expect("outer target");
    let second = consumer.rfind("Target").expect("other target");
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_at_offset("Scopes.scala", consumer, first),
                location_at_offset("Scopes.scala", consumer, second),
            ]
        })
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "outer.core.Target$.apply",
        "{value}"
    );
    assert_eq!(
        results[1]["definitions"][0]["fqn"], "other.core.Target$.apply",
        "{value}"
    );

    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let source = project.file("Scopes.scala");
    let imports = analyzer.import_info_of(&source);
    assert!(analyzer.could_import_file(
        &source,
        &imports,
        &project.file("outer/core/Target.scala")
    ));
    assert!(analyzer.could_import_file(
        &source,
        &imports,
        &project.file("other/core/Target.scala")
    ));
}

#[test]
fn package_alias_candidate_routing_selects_relative_namespace_and_descendants() {
    let consumer = r#"package app
import api.{v1 => selected}
object Consumer {
  val direct: selected.Target = null
  val nested: selected.deep.Nested = null
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/api/v1/Target.scala",
            "package app.api.v1\nclass Target\n",
        )
        .file(
            "app/api/V1.scala",
            "package app.api\nobject v1 { class ObjectSide }\n",
        )
        .file(
            "app/api/v1/deep/Nested.scala",
            "package app.api.v1.deep\nclass Nested\n",
        )
        .file("api/v1/Target.scala", "package api.v1\nclass Target\n")
        .file("app/Consumer.scala", consumer)
        .build();

    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let source = project.file("app/Consumer.scala");
    let singleton = project.file("app/api/V1.scala");
    let nested = project.file("app/api/v1/deep/Nested.scala");
    let imports = analyzer.import_info_of(&source);
    assert!(analyzer.could_import_file(
        &source,
        &imports,
        &project.file("app/api/v1/Target.scala")
    ));
    assert!(analyzer.could_import_file(&source, &imports, &singleton));
    assert!(analyzer.could_import_file(&source, &imports, &nested));
    assert!(!analyzer.could_import_file(&source, &imports, &project.file("api/v1/Target.scala")));
    let imported = analyzer.imported_code_units_of(&source);
    assert!(
        imported.iter().any(|unit| unit.source() == &singleton),
        "same-tier singleton declarations should remain reverse-import candidates"
    );
    assert!(
        imported.iter().any(|unit| unit.source() == &nested),
        "package aliases should import descendant package declarations for reverse routing"
    );
    assert!(
        analyzer.referencing_files_of(&singleton).contains(&source),
        "same-tier singleton declarations should retain the importer"
    );
    assert!(
        analyzer.referencing_files_of(&nested).contains(&source),
        "descendant package declarations should retain the package-alias importer"
    );
}

#[test]
fn template_body_chained_wildcards_retain_enclosing_package_context() {
    let consumer = r#"package dotty.tools
package dotc

object Consumer {
  import core.*
  import Annotations.*
  val annotation = Annotation(1)
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "dotty/tools/dotc/core/Annotations.scala",
            r#"package dotty.tools.dotc.core
object Annotations {
  object Annotation { def apply(value: Int): Int = value }
}
"#,
        )
        .file("dotty/tools/dotc/Consumer.scala", consumer)
        .build();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [location_at(
                "dotty/tools/dotc/Consumer.scala",
                consumer,
                "Annotation",
            )]
        })
        .to_string(),
    );
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"],
        "dotty.tools.dotc.core.Annotations$.Annotation$.apply",
        "{value}"
    );
}

#[test]
fn sibling_object_imports_in_one_package_keep_forward_scope_identity() {
    let consumer = r#"package app
object First {
  import x.*
  val target = Target()
}
object Second {
  import y.*
  val target = Target()
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "x/Target.scala",
            "package x\nobject Target { def apply(): Int = 1 }\n",
        )
        .file(
            "y/Target.scala",
            "package y\nobject Target { def apply(): Int = 2 }\n",
        )
        .file("app/Consumer.scala", consumer)
        .build();
    let first = consumer.find("Target").expect("first target");
    let second = consumer.rfind("Target").expect("second target");
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_at_offset("app/Consumer.scala", consumer, first),
                location_at_offset("app/Consumer.scala", consumer, second),
            ]
        })
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "x.Target$.apply",
        "{value}"
    );
    assert_eq!(
        results[1]["definitions"][0]["fqn"], "y.Target$.apply",
        "{value}"
    );

    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let source = project.file("app/Consumer.scala");
    let imports = analyzer.import_info_of(&source);
    assert!(analyzer.could_import_file(&source, &imports, &project.file("x/Target.scala")));
    assert!(analyzer.could_import_file(&source, &imports, &project.file("y/Target.scala")));
}

#[test]
fn imports_only_bind_references_after_their_declaration_in_the_same_scope() {
    let consumer = r#"package app
object Consumer {
  val beforeWildcard = Target()
  val beforeAlias = Later()
  import x.*
  import y.Target as Later
  val afterWildcard = Target()
  val afterAlias = Later()
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "x/Target.scala",
            "package x\nobject Target { def apply(): Int = 1 }\n",
        )
        .file(
            "y/Target.scala",
            "package y\nobject Target { def apply(): Int = 2 }\n",
        )
        .file("app/Consumer.scala", consumer)
        .build();
    let target_positions = consumer
        .match_indices("Target")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let later_positions = consumer
        .match_indices("Later")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_at_offset("app/Consumer.scala", consumer, target_positions[0]),
                location_at_offset("app/Consumer.scala", consumer, later_positions[0]),
                location_at_offset("app/Consumer.scala", consumer, target_positions[2]),
                location_at_offset("app/Consumer.scala", consumer, later_positions[2]),
            ]
        })
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    assert_ne!(results[0]["status"], "resolved", "{value}");
    assert_ne!(results[1]["status"], "resolved", "{value}");
    assert_eq!(
        results[2]["definitions"][0]["fqn"], "x.Target$.apply",
        "{value}"
    );
    assert_eq!(
        results[3]["definitions"][0]["fqn"], "y.Target$.apply",
        "{value}"
    );
}

#[test]
fn sibling_object_supertypes_use_the_import_scope_of_each_declaration() {
    let consumer = r#"package app
object First {
  import x.Base
  final class Child extends Base
  val value = new Child().leftOnly()
}
object Second {
  import y.Base
  final class Child extends Base
  val value = new Child().rightOnly()
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "x/Base.scala",
            "package x\nclass Base { def leftOnly(): Int = 1 }\n",
        )
        .file(
            "y/Base.scala",
            "package y\nclass Base { def rightOnly(): Int = 2 }\n",
        )
        .file("app/Consumer.scala", consumer)
        .build();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_at("app/Consumer.scala", consumer, "leftOnly"),
                location_at("app/Consumer.scala", consumer, "rightOnly"),
            ]
        })
        .to_string(),
    );
    let results = value["results"].as_array().expect("definition results");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "x.Base.leftOnly",
        "{value}"
    );
    assert_eq!(
        results[1]["definitions"][0]["fqn"], "y.Base.rightOnly",
        "{value}"
    );
}

#[test]
fn chained_relative_wildcards_use_lexical_package_prefixes_for_binding_and_candidates() {
    let consumer = r#"package dotty.tools
package dotc
package typer

import core.*
import Annotations.*

object Consumer { val annotation = Annotation(1) }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "dotty/tools/dotc/core/Annotations.scala",
            r#"package dotty.tools.dotc.core
object Annotations {
  object Annotation { def apply(value: Int): Int = value }
}
"#,
        )
        .file("dotty/tools/dotc/typer/Consumer.scala", consumer)
        .build();

    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [location_at(
                "dotty/tools/dotc/typer/Consumer.scala",
                consumer,
                "Annotation",
            )]
        })
        .to_string(),
    );
    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"],
        "dotty.tools.dotc.core.Annotations$.Annotation$.apply",
        "{value}"
    );

    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let source = project.file("dotty/tools/dotc/typer/Consumer.scala");
    let target = project.file("dotty/tools/dotc/core/Annotations.scala");
    let imports = analyzer.import_info_of(&source);
    assert!(analyzer.could_import_file(&source, &imports, &target));
}

#[test]
fn dual_chained_singleton_roots_remain_ambiguous() {
    let consumer = r#"package app
import a.*
import b.*
import Shared.*
object Consumer { val target = Target() }
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "a/Shared.scala",
            "package a\nobject Shared { object Target { def apply(): Int = 1 } }\n",
        )
        .file(
            "b/Shared.scala",
            "package b\nobject Shared { object Target { def apply(): Int = 2 } }\n",
        )
        .file("app/Consumer.scala", consumer)
        .build();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [location_at("app/Consumer.scala", consumer, "Target")]
        })
        .to_string(),
    );

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
    assert_eq!(
        value["results"][0]["diagnostics"][0]["kind"], "ambiguous_scala_wildcard_import",
        "{value}"
    );
}

#[test]
fn absolute_wildcard_owner_and_explicit_alias_keep_import_precedence() {
    let consumer = r#"package app
import a.Shared.*
import b.Target as Chosen
object Consumer {
  val wildcard = Target()
  val aliased = Chosen()
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "a/Shared.scala",
            "package a\nobject Shared { object Target { def apply(): Int = 1 } }\n",
        )
        .file(
            "b/Target.scala",
            "package b\nobject Target { def apply(): Int = 2 }\n",
        )
        .file("app/Consumer.scala", consumer)
        .build();
    let value = call_search_tool_json(
        project.root(),
        "get_definitions_by_location",
        &json!({
            "references": [
                location_at("app/Consumer.scala", consumer, "Target"),
                location_at("app/Consumer.scala", consumer, "Chosen"),
            ]
        })
        .to_string(),
    );

    let results = value["results"].as_array().expect("definition results");
    assert_eq!(results[0]["status"], "resolved", "{value}");
    assert_eq!(
        results[0]["definitions"][0]["fqn"], "a.Shared$.Target$.apply",
        "{value}"
    );
    assert_eq!(results[1]["status"], "resolved", "{value}");
    assert_eq!(
        results[1]["definitions"][0]["fqn"], "b.Target$.apply",
        "{value}"
    );

    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let source = project.file("app/Consumer.scala");
    let imports = analyzer.import_info_of(&source);
    assert!(analyzer.could_import_file(&source, &imports, &project.file("a/Shared.scala")));
    assert!(analyzer.could_import_file(&source, &imports, &project.file("b/Target.scala")));
}
