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
fn scala_recorded_supertypes_drive_mixed_class_and_trait_descendants() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "Types.scala",
        r#"
package app
class Base
trait Runnable
trait Audited extends Runnable
class Worker extends Base with Audited
"#,
    )]);

    let worker = definition(&analyzer, "app.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["app.Audited".to_string(), "app.Base".to_string()])
    );

    let audited = definition(&analyzer, "app.Audited");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&audited)),
        BTreeSet::from(["app.Runnable".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&audited)),
        BTreeSet::from(["app.Worker".to_string()])
    );

    let runnable = definition(&analyzer, "app.Runnable");
    assert_eq!(
        fq_names(analyzer.get_descendants(&runnable)),
        BTreeSet::from(["app.Audited".to_string(), "app.Worker".to_string()])
    );
}

#[test]
fn scala_descendant_index_batches_file_hierarchy_facts_and_preserves_visibility() {
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
            "alias/Children.scala",
            r#"
package alias
import lib.Base as Parent
import lib.Runnable
class First extends Parent with Runnable
class Second extends Parent
class Third extends Parent
"#,
        ),
        (
            "wild/Child.scala",
            r#"
package wild
import lib._
class WildcardChild extends Base with Runnable
"#,
        ),
        (
            "same/Types.scala",
            r#"
package same
class Peer
class SamePackageChild extends Peer
"#,
        ),
        (
            "companion/Types.scala",
            r#"
package companion
class Foo
object Foo { trait Base }
class Child extends Foo.Base
"#,
        ),
    ]);
    let base = definition(&analyzer, "lib.Base");
    let runnable = definition(&analyzer, "lib.Runnable");
    let peer = definition(&analyzer, "same.Peer");
    let first = definition(&analyzer, "alias.First");
    let companion_base = definition(&analyzer, "companion.Foo$.Base");
    let companion_child = definition(&analyzer, "companion.Child");

    analyzer.reset_full_hydration_count_for_test();

    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        BTreeSet::from([
            "alias.First".to_string(),
            "alias.Second".to_string(),
            "alias.Third".to_string(),
            "wild.WildcardChild".to_string(),
        ])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&runnable)),
        BTreeSet::from(["alias.First".to_string(), "wild.WildcardChild".to_string(),])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&peer)),
        BTreeSet::from(["same.SamePackageChild".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&first)),
        BTreeSet::from(["lib.Base".to_string(), "lib.Runnable".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&companion_base)),
        BTreeSet::from(["companion.Child".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&companion_child)),
        BTreeSet::from(["companion.Foo$.Base".to_string()])
    );
    assert_eq!(
        analyzer.full_hydration_count_for_test(),
        0,
        "descendant construction must not point-hydrate once per declaration"
    );
    assert_eq!(
        analyzer.bulk_hydration_count_for_test(),
        5,
        "descendant construction should project each Scala file once"
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
