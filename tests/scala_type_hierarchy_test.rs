mod common;

use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ScalaAnalyzer, TypeHierarchyProvider};
use common::{BuiltInlineTestProject, InlineTestProject};
use std::collections::BTreeSet;

fn scala_analyzer_with_files(files: &[(&str, &str)]) -> (BuiltInlineTestProject, ScalaAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Scala);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &ScalaAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn fq_names(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<String> {
    units.into_iter().map(|unit| unit.fq_name()).collect()
}

#[test]
fn scala_class_extends_resolves_direct_ancestor() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
class Base
class Child extends Base
"#,
    )]);

    let child = definition(&analyzer, "app.Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["app.Base".to_string()])
    );
}

#[test]
fn scala_class_extends_class_with_trait_parent() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
class Base
trait Runnable
class Worker extends Base with Runnable
"#,
    )]);

    let worker = definition(&analyzer, "app.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["app.Base".to_string(), "app.Runnable".to_string()])
    );
}

#[test]
fn scala_trait_extends_trait_parent() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
trait Parent
trait Child extends Parent
"#,
    )]);

    let child = definition(&analyzer, "app.Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["app.Parent".to_string()])
    );
}

#[test]
fn scala_class_resolves_multiple_mixed_in_traits_and_transitive_trait_parent() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
class Base
trait Traceable
trait Audited extends Traceable
trait Logged
trait Metered
class Worker extends Base with Audited with Logged with Metered
"#,
    )]);

    let worker = definition(&analyzer, "app.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from([
            "app.Audited".to_string(),
            "app.Base".to_string(),
            "app.Logged".to_string(),
            "app.Metered".to_string(),
        ])
    );
    assert_eq!(
        fq_names(analyzer.get_ancestors(&worker)),
        BTreeSet::from([
            "app.Audited".to_string(),
            "app.Base".to_string(),
            "app.Logged".to_string(),
            "app.Metered".to_string(),
            "app.Traceable".to_string(),
        ])
    );
}

#[test]
fn scala_object_resolves_trait_parents() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
trait Runnable
trait Logged
object Worker extends Runnable with Logged
"#,
    )]);

    let worker = definition(&analyzer, "app.Worker$");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["app.Logged".to_string(), "app.Runnable".to_string()])
    );
}

#[test]
fn scala_hierarchy_resolves_imported_parent_symbols() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "lib/Types.scala",
            r#"
package lib
class Base
trait Runnable
"#,
        ),
        (
            "app/Worker.scala",
            r#"
package app
import lib.Base as ParentBase
import lib._
class Worker extends ParentBase with Runnable
"#,
        ),
    ]);

    let worker = definition(&analyzer, "app.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["lib.Base".to_string(), "lib.Runnable".to_string()])
    );
}

#[test]
fn scala_generic_parent_does_not_treat_type_argument_as_parent() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
class Box[A]
class Payload
class Child extends Box[Payload]
"#,
    )]);

    let child = definition(&analyzer, "app.Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["app.Box".to_string()])
    );
}

#[test]
fn scala_unresolved_parent_is_ignored() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
class Child extends Missing
"#,
    )]);

    let child = definition(&analyzer, "app.Child");
    assert!(analyzer.get_direct_ancestors(&child).is_empty());
}

#[test]
fn scala_direct_descendants_are_not_transitive() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
class Base
class Child extends Base
class Grandchild extends Child
"#,
    )]);

    let base = definition(&analyzer, "app.Base");
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        BTreeSet::from(["app.Child".to_string()])
    );
}
