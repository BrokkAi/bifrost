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
fn scala_sequential_package_clauses_resolve_constructor_applied_generic_parent() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "impl/Base.scala",
            r#"
package scala.collection.convert
package impl
abstract class IndexedStepperBase[Sub, Semi <: Sub](protected var i0: Int)
"#,
        ),
        (
            "impl/Child.scala",
            r#"
package scala.collection.convert
package impl
trait AnyStepper[A]
class ObjectArrayStepper[A](start: Int)
  extends IndexedStepperBase[AnyStepper[A], ObjectArrayStepper[A]](start)
    with AnyStepper[A]
"#,
        ),
    ]);

    let child = definition(
        &analyzer,
        "scala.collection.convert.impl.ObjectArrayStepper",
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from([
            "scala.collection.convert.impl.AnyStepper".to_string(),
            "scala.collection.convert.impl.IndexedStepperBase".to_string(),
        ])
    );

    let base = definition(
        &analyzer,
        "scala.collection.convert.impl.IndexedStepperBase",
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        BTreeSet::from(["scala.collection.convert.impl.ObjectArrayStepper".to_string()])
    );
}

#[test]
fn scala_hierarchy_preserves_sequential_enclosing_package_context_source_free() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "collection/Factory.scala",
            r#"package scala.collection
trait StrictOptimizedSeqFactory[Coll]
"#,
        ),
        (
            "mutable/ListBuffer.scala",
            r#"package scala.collection
package mutable
class ListBuffer extends StrictOptimizedSeqFactory[ListBuffer]
"#,
        ),
        (
            "mutable/DottedListBuffer.scala",
            r#"package scala.collection.mutable
class DottedListBuffer extends StrictOptimizedSeqFactory[DottedListBuffer]
"#,
        ),
    ]);
    let factory = definition(&analyzer, "scala.collection.StrictOptimizedSeqFactory");
    let sequential = definition(&analyzer, "scala.collection.mutable.ListBuffer");
    let dotted = definition(&analyzer, "scala.collection.mutable.DottedListBuffer");

    analyzer.reset_full_hydration_count_for_test();
    analyzer.reset_scala_project_types_build_count_for_test();
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&factory)),
        BTreeSet::from(["scala.collection.mutable.ListBuffer".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&sequential)),
        BTreeSet::from(["scala.collection.StrictOptimizedSeqFactory".to_string()])
    );
    assert!(
        analyzer.get_direct_ancestors(&dotted).is_empty(),
        "a single dotted package must not expose its parent package for unqualified lookup"
    );
    assert_eq!(
        analyzer.full_hydration_count_for_test(),
        0,
        "source-free hierarchy construction must retain zero point hydration"
    );
    assert_eq!(
        analyzer.bulk_hydration_count_for_test(),
        3,
        "source-free hierarchy construction must project each file exactly once"
    );
    assert_eq!(
        analyzer.scala_project_types_build_count_for_test(),
        1,
        "hierarchy construction must retain one shared project-types snapshot"
    );
}

#[test]
fn scala_hierarchy_qualified_package_roots_follow_import_and_ambiguity_precedence() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "scala/CollectionObject.scala",
            r#"package scala
object collection { trait BitSetOps }
"#,
        ),
        (
            "scala/collection/BitSetOps.scala",
            r#"package scala.collection
trait BitSetOps
"#,
        ),
        (
            "extras/Syntax.scala",
            r#"package extras
object Syntax { val unrelated: Int = 1 }
"#,
        ),
        (
            "scala/collection/immutable/BitSet.scala",
            r#"package scala
package collection
package immutable
import extras.Syntax.*
class BitSet extends collection.BitSetOps
"#,
        ),
        (
            "imported/Collection.scala",
            r#"package imported
object collection { trait BitSetOps }
"#,
        ),
        (
            "scala/collection/immutable/ImportedBitSet.scala",
            r#"package scala
package collection
package immutable
import imported.collection
class ImportedBitSet extends collection.BitSetOps
"#,
        ),
        (
            "collision/Collection.scala",
            r#"package collision
object collection { trait BitSetOps }
"#,
        ),
        (
            "collision/collection/BitSetOps.scala",
            r#"package collision.collection
trait BitSetOps
"#,
        ),
        (
            "scala/collection/immutable/AmbiguousBitSet.scala",
            r#"package scala
package collection
package immutable
import collision.collection
class AmbiguousBitSet extends collection.BitSetOps
"#,
        ),
    ]);

    let bit_set = definition(&analyzer, "scala.collection.immutable.BitSet");
    let imported = definition(&analyzer, "scala.collection.immutable.ImportedBitSet");
    let ambiguous = definition(&analyzer, "scala.collection.immutable.AmbiguousBitSet");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&bit_set)),
        BTreeSet::from(["scala.collection.BitSetOps".to_string()]),
        "the enclosing package root must beat the implicit scala.collection singleton and survive an unrelated wildcard import"
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&imported)),
        BTreeSet::from(["imported.collection$.BitSetOps".to_string()]),
        "an explicit import must remain above enclosing package roots"
    );
    assert!(
        analyzer.get_direct_ancestors(&ambiguous).is_empty(),
        "an imported package/singleton collision must fail closed"
    );
}

#[test]
fn scala_hierarchy_qualified_package_root_rejects_duplicate_physical_terminals() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "collection/First.scala",
            "package scala.collection\ntrait BitSetOps\n",
        ),
        (
            "collection/Second.scala",
            "package scala.collection\ntrait BitSetOps\n",
        ),
        (
            "immutable/BitSet.scala",
            r#"package scala
package collection
package immutable
class BitSet extends collection.BitSetOps
"#,
        ),
    ]);
    let bit_set = definition(&analyzer, "scala.collection.immutable.BitSet");
    assert!(
        analyzer.get_direct_ancestors(&bit_set).is_empty(),
        "duplicate physical package terminals must fail closed"
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
            "root/api/Types.scala",
            r#"
package root.api
class PackageBase
"#,
        ),
        (
            "alias/Children.scala",
            r#"
package alias
import lib.Base as Parent
import lib.Runnable
import root.{api => classic}
class First extends Parent with Runnable
class Second extends Parent
class Third extends Parent
class PackageAliasChild extends classic.PackageBase
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
object Bases { trait StableBase }
import Bases.*
class StableWildcardChild extends StableBase
"#,
        ),
    ]);
    let base = definition(&analyzer, "lib.Base");
    let runnable = definition(&analyzer, "lib.Runnable");
    let peer = definition(&analyzer, "same.Peer");
    let package_base = definition(&analyzer, "root.api.PackageBase");
    let package_alias_child = definition(&analyzer, "alias.PackageAliasChild");
    let first = definition(&analyzer, "alias.First");
    let companion_base = definition(&analyzer, "companion.Foo$.Base");
    let companion_child = definition(&analyzer, "companion.Child");
    let stable_base = definition(&analyzer, "companion.Bases$.StableBase");
    let stable_wildcard_child = definition(&analyzer, "companion.StableWildcardChild");

    analyzer.reset_full_hydration_count_for_test();
    analyzer.reset_scala_project_types_build_count_for_test();

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
        fq_names(analyzer.get_direct_descendants(&package_base)),
        BTreeSet::from(["alias.PackageAliasChild".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&package_alias_child)),
        BTreeSet::from(["root.api.PackageBase".to_string()])
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
        fq_names(analyzer.get_direct_descendants(&stable_base)),
        BTreeSet::from(["companion.StableWildcardChild".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&stable_wildcard_child)),
        BTreeSet::from(["companion.Bases$.StableBase".to_string()])
    );
    assert_eq!(
        analyzer.full_hydration_count_for_test(),
        0,
        "descendant construction must not point-hydrate once per declaration"
    );
    assert_eq!(
        analyzer.bulk_hydration_count_for_test(),
        6,
        "descendant construction should project each Scala file once"
    );
    assert_eq!(
        analyzer.scala_project_types_build_count_for_test(),
        1,
        "descendant construction and ancestor queries must share one project-types snapshot"
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
fn scala_hierarchy_wildcards_use_ordered_owner_tiers_and_reject_namespace_collisions() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        ("Bases/Global.scala", "package Bases\ntrait SelectedBase\n"),
        (
            "relative/Bases.scala",
            "package relative\nobject Bases { trait SelectedBase }\n",
        ),
        (
            "relative/Child.scala",
            r#"package relative
import Bases.*
class RelativeChild extends SelectedBase
"#,
        ),
        (
            "collision/Bases.scala",
            "package collision\nobject Bases { trait ClashingBase }\n",
        ),
        (
            "collision/Bases/Types.scala",
            "package collision.Bases\ntrait ClashingBase\n",
        ),
        (
            "collision/Child.scala",
            r#"package collision
import Bases.*
class CollisionChild extends ClashingBase
"#,
        ),
        (
            "explicit/Api.scala",
            "package explicit\nobject Api { trait ExplicitBase }\n",
        ),
        (
            "explicit/Api/Types.scala",
            "package explicit.Api\ntrait ExplicitBase\n",
        ),
        (
            "consumer/Child.scala",
            r#"package consumer
import explicit.{Api => mixed}
class ExplicitCollisionChild extends mixed.ExplicitBase
"#,
        ),
    ]);

    let relative_child = definition(&analyzer, "relative.RelativeChild");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&relative_child)),
        BTreeSet::from(["relative.Bases$.SelectedBase".to_string()]),
        "the relative singleton tier must win before the global package tier"
    );

    for child in [
        "collision.CollisionChild",
        "consumer.ExplicitCollisionChild",
    ] {
        let child = definition(&analyzer, child);
        assert!(
            analyzer.get_direct_ancestors(&child).is_empty(),
            "same-tier package/singleton imports must fail closed for {}",
            child.fq_name()
        );
    }
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
